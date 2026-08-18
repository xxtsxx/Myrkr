; =============================================================================
; ramlog.asm - the in-RAM action log the GUI's log viewer reads.
; -----------------------------------------------------------------------------
;   rlog_begin()                      - discard the old log, start capturing
;   rlog_append(rcx = UTF-8, edx=len) - append bytes verbatim (no-op until armed)
;   rlog_flatten(rcx = *ptr, rdx = *len) -> eax = 0 none / 1 whole / 2 partial
;   rlog_wipe()                       - stop capturing, release + wipe everything
;
; This is NOT log.asm.  That one appends a single outcome line per command to a
; file on disk, is off by default, and is a user-facing audit trail.  This one
; keeps every byte the tool printed during ONE operation, in memory only, so the
; window can show the full story of what just happened.  Nothing here touches
; the disk and nothing survives the process.
;
; UNCAPPED, by decision: a user who asks what happened to 40,000 files gets the
; answer for all 40,000.  The only ceiling is the machine's, and hitting it is
; reported (rlog_flatten returns 2) rather than silently trimming the tail -
; a log that quietly stops is worse than one that says where it stopped.
;
; ---- why chunks, and not one growable block --------------------------------
; The bytes arrive on the WORKER thread (every print_a inside a crypto run) and
; are read on the UI thread when the viewer opens, which can happen while the
; job is still going.  A single block that doubles in size would free the old
; block out from under a reader mid-copy - a use-after-free reachable by
; clicking at the wrong moment, on memory that holds the user's file paths.
;
; So nothing is ever freed while capturing.  Chunks are allocated forward, never
; moved, and the only published length (g_rl_total) is advanced AFTER the bytes
; behind it are written.  A reader therefore always sees a valid prefix: it may
; miss the last few bytes of a message, it can never read a byte that is not
; there.  That is the whole synchronisation story - no lock, and no lock needed.
;
; Chunks come from mem_alloc/mem_free, so releasing one wipes it (VirtualAlloc
; pages, zeroed on the way out).  A whole chunk is wiped even when only part of
; it was used.
; =============================================================================

include macros.inc

extern mem_alloc:proc
extern mem_free:proc
extern log_stamp:proc                   ; log.asm: "YYYY-MM-DD HH:MM:SS"
extern log_result_text:proc             ; log.asm: exit code -> one sentence

RL_CHUNK    equ 65536               ; bytes per chunk
RL_SLOTS    equ 4096                ; chunk pointers -> 256 MiB before OOM
RL_NAME_MAX equ 4096                ; bound on an unterminated entry name
RL_CUR_MAX  equ 512                 ; the "currently processing" line, UTF-8

.const
CSTR rl_tag_add, "  added     "
CSTR rl_tag_ext, "  extracted "
rl_crlf     db 13,10
; The closing block.  A log that someone pastes into a mail has to say WHEN, and
; has to end with the answer rather than making the reader scroll for it.
CSTR rl_fin_1,     13,10,"  finished "
CSTR rl_fin_2,     13,10,"  "
CSTR rl_fin_3,     " added, "
CSTR rl_fin_4,     " extracted",13,10,"  "
CSTR rl_cancelled, "cancelled at your request"

.data
g_rl_on     dd 0                    ; 1 once the GUI has armed capture
g_rl_oom    dd 0                    ; 1 once an allocation failed: log incomplete
g_rl_count  dq 0                    ; chunks allocated
g_rl_used   dq 0                    ; bytes used in the LAST chunk
g_rl_total  dq 0                    ; bytes appended - the published length
; Counted HERE and not by the GUI, so the closing summary counts the lines this
; log actually contains.  A number arrived at separately can disagree with the
; list under it, and then the reader has to decide which one is lying.
public g_rl_nadd, g_rl_next         ; the progress window shows these live
g_rl_nadd   dq 0                    ; entries logged as added
g_rl_next   dq 0                    ; entries logged as extracted

.data?
align 16
g_rl_chunks dq RL_SLOTS dup (?)     ; chunk pointers, index 0..g_rl_count-1
g_rl_stamp  db 24 dup (?)           ; log_stamp's 19 chars
g_rl_num    db 24 dup (?)           ; one decimal count
; The entry being worked on, for the progress window's "currently processing"
; line.  Published from HERE because this is the one place that already sees
; every name: progress.asm counts bytes per positional INPUT and has never known
; which file it is inside.  Written on the worker, read on the UI thread - the
; length lands AFTER the bytes, so a reader gets a short name rather than a name
; half replaced by the next one.
public g_rl_curname, g_rl_curlen
g_rl_curname db RL_CUR_MAX dup (?)
g_rl_curlen  dd ?

.code

; =============================================================================
; rlog_drop() - release every chunk (wiping it) and reset the counters.
; Internal: callers use rlog_begin or rlog_wipe, which differ only in whether
; capture is left on.
; =============================================================================
rlog_drop proc frame
    FRAME_PROLOG 48
    ; [rbp-16] = chunk index
    mov     qword ptr [rbp-16], 0
rd_loop:
    mov     rax, qword ptr [rbp-16]
    cmp     rax, qword ptr [g_rl_count]
    jae     rd_done
    lea     r10, [g_rl_chunks]
    mov     rcx, qword ptr [r10+rax*8]
    xIFT rcx
        mov     rdx, RL_CHUNK               ; whole chunk, not just the used part
        call    mem_free                    ; wipes, then releases
        mov     rax, qword ptr [rbp-16]
        lea     r10, [g_rl_chunks]
        mov     qword ptr [r10+rax*8], 0
    xENDIF
    inc     qword ptr [rbp-16]
    jmp     rd_loop
rd_done:
    mov     qword ptr [g_rl_count], 0
    mov     qword ptr [g_rl_used], 0
    mov     qword ptr [g_rl_total], 0
    mov     qword ptr [g_rl_nadd], 0
    mov     qword ptr [g_rl_next], 0
    mov     dword ptr [g_rl_oom], 0
    FRAME_EPILOG
    ret
rlog_drop endp

; =============================================================================
; rlog_begin() - throw away the previous operation's log and start a new one.
; Called by the GUI on the UI thread before a worker starts, which is also what
; arms capture: a CLI run never calls it, so the CLI keeps nothing in memory.
; =============================================================================
public rlog_begin
rlog_begin proc frame
    FRAME_PROLOG 48
    call    rlog_drop
    mov     dword ptr [g_rl_on], 1
    FRAME_EPILOG
    ret
rlog_begin endp

; =============================================================================
; rlog_wipe() - stop capturing and release everything.  Window teardown.
; =============================================================================
public rlog_wipe
rlog_wipe proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_rl_on], 0          ; before the drop, not after
    call    rlog_drop
    FRAME_EPILOG
    ret
rlog_wipe endp

; =============================================================================
; rlog_grow() -> eax = 1 got a chunk / 0 out of memory (g_rl_oom set)
; =============================================================================
rlog_grow proc frame
    FRAME_PROLOG 48
    mov     rax, qword ptr [g_rl_count]
    cmp     rax, RL_SLOTS
    jae     rg_fail
    mov     rcx, RL_CHUNK
    call    mem_alloc
    test    rax, rax
    jz      rg_fail
    mov     r10, qword ptr [g_rl_count]
    lea     r11, [g_rl_chunks]
    mov     qword ptr [r11+r10*8], rax      ; the pointer lands BEFORE the count
    mov     qword ptr [g_rl_used], 0
    inc     qword ptr [g_rl_count]
    mov     eax, 1
    FRAME_EPILOG
    ret
rg_fail:
    mov     dword ptr [g_rl_oom], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
rlog_grow endp

; =============================================================================
; rlog_append(rcx = UTF-8 bytes, edx = length)
;
; Worker thread.  Splits across chunk boundaries; on an allocation failure it
; keeps what already fits and marks the log incomplete rather than failing the
; operation - nobody's encrypt should die because its narration ran out of room.
; Must never print anything itself: this sits underneath print_a.
; =============================================================================
public rlog_append
rlog_append proc frame
    FRAME_PROLOG 64
    ; [rbp-16] = src cursor   [rbp-24] = bytes left   [rbp-32] = bytes this pass
    cmp     dword ptr [g_rl_on], 0
    je      ra_ret
    test    rcx, rcx
    jz      ra_ret
    mov     eax, edx                        ; zero-extend the length
    test    rax, rax
    jz      ra_ret
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rax
ra_loop:
    cmp     qword ptr [rbp-24], 0
    je      ra_ret
    mov     rax, qword ptr [g_rl_count]
    test    rax, rax
    jz      ra_grow                         ; nothing allocated yet
    mov     rax, qword ptr [g_rl_used]
    cmp     rax, RL_CHUNK
    jb      ra_have
ra_grow:
    call    rlog_grow
    test    eax, eax
    jz      ra_ret                          ; out of memory: keep what is there
ra_have:
    ; n = min(bytes left, room in the current chunk); both are >= 1 here
    mov     rax, RL_CHUNK
    sub     rax, qword ptr [g_rl_used]
    mov     r10, qword ptr [rbp-24]
    cmp     r10, rax
    jbe     @F
    mov     r10, rax
@@:
    mov     qword ptr [rbp-32], r10
    mov     rax, qword ptr [g_rl_count]
    dec     rax
    lea     r11, [g_rl_chunks]
    mov     r11, qword ptr [r11+rax*8]
    add     r11, qword ptr [g_rl_used]      ; dst
    mov     r8, qword ptr [rbp-16]          ; src
    xor     r9, r9
ra_cpy:
    mov     al, byte ptr [r8+r9]
    mov     byte ptr [r11+r9], al
    inc     r9
    cmp     r9, qword ptr [rbp-32]
    jb      ra_cpy
    mov     r10, qword ptr [rbp-32]
    add     qword ptr [g_rl_used], r10
    add     qword ptr [rbp-16], r10
    sub     qword ptr [rbp-24], r10
    ; Published LAST, after the bytes it covers are in place, so a reader on the
    ; UI thread sees a shorter log rather than uninitialised memory.
    add     qword ptr [g_rl_total], r10
    jmp     ra_loop
ra_ret:
    FRAME_EPILOG
    ret
rlog_append endp

; =============================================================================
; rlog_added(rcx = UTF-8 name, edx = length or 0 for NUL-terminated)
; rlog_extracted(rcx = UTF-8 name, edx = length or 0 for NUL-terminated)
;
; One line per entry, which is the difference between a log that says "zipped
; 913 file(s)" and one that says WHICH 913.  The summary was all the tee could
; ever produce: the crypto paths print outcomes, and no outcome names the files
; it covers.
;
; These ARE calls into pack.asm / zip.asm / unzip.asm, which the earlier design
; ruled out.  That ruling assumed the tee would carry enough detail and it does
; not - the name only exists at the moment the entry is written, and nothing
; downstream can recover it without re-deriving a list and calling it a record.
; A derived list would claim files were written that were never observed being
; written, which is exactly the failure the rest of this file is built to avoid.
;
; The cost to the CLI is one compare against g_rl_on per entry, because nothing
; but the GUI ever arms this.  No formatting, no allocation, no output.
;
; Length 0 means "NUL-terminated": two of the four call sites have an explicit
; length and two have a C string, and making them agree at the call site would
; have meant a strlen at each of the latter anyway.
; =============================================================================
public rlog_added
rlog_added proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_rl_on], 0
    je      ra2_ret                          ; the CLI stops here, per entry
    inc     qword ptr [g_rl_nadd]
    lea     r8, [rl_tag_add]
    mov     r9d, rl_tag_add_len
    call    rlog_tagged
ra2_ret:
    FRAME_EPILOG
    ret
rlog_added endp

public rlog_extracted
rlog_extracted proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_rl_on], 0
    je      rx2_ret
    inc     qword ptr [g_rl_next]
    lea     r8, [rl_tag_ext]
    mov     r9d, rl_tag_ext_len
    call    rlog_tagged
rx2_ret:
    FRAME_EPILOG
    ret
rlog_extracted endp

; -----------------------------------------------------------------------------
; rl_num(rax = value) -> rcx = ptr, edx = length.  Decimal, unpadded.  Leaf.
; log.asm's log_putn is fixed-width and zero-pads, which reads as "0913 added".
; -----------------------------------------------------------------------------
rl_num proc
    lea     r10, [g_rl_num + 24]
    mov     r11, 10
    xor     r8d, r8d
rn_loop:
    xor     edx, edx
    div     r11
    add     dl, '0'
    dec     r10
    mov     byte ptr [r10], dl
    inc     r8d
    test    rax, rax
    jnz     rn_loop
    mov     rcx, r10
    mov     edx, r8d
    ret
rl_num endp

; =============================================================================
; rlog_finish(ecx = exit code, edx = 1 if the user cancelled)
;
; Closes the log with when it ended, how much it covered, and how it went - so a
; log pasted into a mail carries its own date, and ends with the answer instead
; of making the reader scroll for it.
;
; The counts come from this file's own tallies, so the summary describes the
; lines directly above it rather than a number reached some other way.  The
; sentence comes from log.asm's log_result_text, which is the same mapping the
; on-disk audit log uses - one exit code should not become two different English
; sentences in one product.
;
; Cancelled is not an exit code and is passed separately: the crypto layer
; reports it as a failure so its rollback runs, and telling the user their own
; decision "failed" is the wrong word for the right event.
; =============================================================================
public rlog_finish
rlog_finish proc frame
    FRAME_PROLOG 64
    ; [rbp-16] exit code   [rbp-24] cancelled
    cmp     dword ptr [g_rl_on], 0
    je      rf2_ret
    mov     dword ptr [rbp-16], ecx
    mov     dword ptr [rbp-24], edx
    lea     rcx, [rl_fin_1]
    mov     edx, rl_fin_1_len
    call    rlog_append
    lea     rcx, [g_rl_stamp]
    call    log_stamp
    lea     rcx, [g_rl_stamp]
    mov     edx, 19
    call    rlog_append
    lea     rcx, [rl_fin_2]
    mov     edx, rl_fin_2_len
    call    rlog_append
    mov     rax, qword ptr [g_rl_nadd]
    call    rl_num                           ; -> rcx, edx: already the arguments
    call    rlog_append
    lea     rcx, [rl_fin_3]
    mov     edx, rl_fin_3_len
    call    rlog_append
    mov     rax, qword ptr [g_rl_next]
    call    rl_num
    call    rlog_append
    lea     rcx, [rl_fin_4]
    mov     edx, rl_fin_4_len
    call    rlog_append
    cmp     dword ptr [rbp-24], 0
    je      rf2_code
    lea     rcx, [rl_cancelled]
    mov     edx, rl_cancelled_len
    jmp     rf2_say
rf2_code:
    mov     ecx, dword ptr [rbp-16]
    call    log_result_text                  ; -> rax = text, edx = length
    mov     rcx, rax
rf2_say:
    call    rlog_append
    lea     rcx, [rl_crlf]
    mov     edx, 2
    call    rlog_append
rf2_ret:
    FRAME_EPILOG
    ret
rlog_finish endp

; -----------------------------------------------------------------------------
; rlog_tagged(rcx = name, edx = len or 0, r8 = tag, r9d = tag len) - internal.
; -----------------------------------------------------------------------------
rlog_tagged proc frame
    FRAME_PROLOG 64
    ; [rbp-16] name  [rbp-24] len  [rbp-32] tag  [rbp-40] tag len
    cmp     dword ptr [g_rl_on], 0
    je      rt_ret                          ; not armed: this is the whole cost
    test    rcx, rcx
    jz      rt_ret
    mov     qword ptr [rbp-16], rcx
    mov     dword ptr [rbp-24], edx
    mov     qword ptr [rbp-32], r8
    mov     dword ptr [rbp-40], r9d
    cmp     dword ptr [rbp-24], 0
    jne     rt_have
    ; measure it, bounded: a name that is not terminated inside the buffer it
    ; came from is a corrupt container, and this must not walk out of it
    xor     eax, eax
rt_scan:
    cmp     eax, RL_NAME_MAX
    jae     rt_scanned
    cmp     byte ptr [rcx+rax], 0
    je      rt_scanned
    inc     eax
    jmp     rt_scan
rt_scanned:
    mov     dword ptr [rbp-24], eax
    test    eax, eax
    jz      rt_ret                          ; empty name: nothing worth a line
rt_have:
    ; publish it as the current entry before writing the line, so the progress
    ; window is naming what is being worked on rather than what was finished
    mov     dword ptr [g_rl_curlen], 0       ; invalidate while the bytes move
    mov     r8, qword ptr [rbp-16]
    mov     r9d, dword ptr [rbp-24]
    cmp     r9d, RL_CUR_MAX
    jbe     @F
    mov     r9d, RL_CUR_MAX                  ; a long path shows its head
@@:
    xor     r10d, r10d
    lea     r11, [g_rl_curname]              ; through a register: a RIP-relative
                                             ; operand cannot carry an index
rt_cur:
    cmp     r10d, r9d
    jae     rt_curd
    mov     al, byte ptr [r8+r10]
    mov     byte ptr [r11+r10], al
    inc     r10d
    jmp     rt_cur
rt_curd:
    mov     dword ptr [g_rl_curlen], r9d     ; length LAST, as ever
    mov     rcx, qword ptr [rbp-32]
    mov     edx, dword ptr [rbp-40]
    call    rlog_append
    mov     rcx, qword ptr [rbp-16]
    mov     edx, dword ptr [rbp-24]
    call    rlog_append
    lea     rcx, [rl_crlf]
    mov     edx, 2
    call    rlog_append
rt_ret:
    FRAME_EPILOG
    ret
rlog_tagged endp

; =============================================================================
; rlog_flatten(rcx = *out ptr, rdx = *out len) -> eax
;       0 = nothing logged (or the copy could not be allocated)
;       1 = the whole log
;       2 = the log, but an append was dropped earlier - it is incomplete
;
; UI thread.  Returns ONE contiguous UTF-8 block, which is what both the viewer
; and the clipboard want.  The caller owns it and releases it with
; mem_free(ptr, len) - len is the allocation size, so the wipe covers all of it.
;
; g_rl_total is read once, up front, and is the authority: chunks are never
; freed while capturing, so every byte it covers is already written and still
; mapped even if the worker appends more during the copy.
; =============================================================================
public rlog_flatten
rlog_flatten proc frame
    FRAME_PROLOG 80
    ; [rbp-16]=*ptr [rbp-24]=*len [rbp-32]=total [rbp-40]=dst [rbp-48]=index
    ; [rbp-56]=left [rbp-64]=base
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rcx], 0
    mov     qword ptr [rdx], 0
    mov     rax, qword ptr [g_rl_total]
    mov     qword ptr [rbp-32], rax
    test    rax, rax
    jz      rf_none
    mov     rcx, rax
    call    mem_alloc
    test    rax, rax
    jz      rf_none
    mov     qword ptr [rbp-40], rax
    mov     qword ptr [rbp-64], rax
    mov     qword ptr [rbp-48], 0
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-56], rax
rf_chunk:
    cmp     qword ptr [rbp-56], 0
    je      rf_done
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [g_rl_count]
    jae     rf_done                         ; cannot happen; the tail stays zero
    lea     r11, [g_rl_chunks]
    mov     r8, qword ptr [r11+rax*8]
    test    r8, r8
    jz      rf_done
    mov     r10, RL_CHUNK
    cmp     qword ptr [rbp-56], r10
    jae     @F
    mov     r10, qword ptr [rbp-56]
@@:
    mov     r11, qword ptr [rbp-40]
    xor     r9, r9
rf_cpy:
    mov     al, byte ptr [r8+r9]
    mov     byte ptr [r11+r9], al
    inc     r9
    cmp     r9, r10
    jb      rf_cpy
    add     qword ptr [rbp-40], r10
    sub     qword ptr [rbp-56], r10
    inc     qword ptr [rbp-48]
    jmp     rf_chunk
rf_done:
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [rcx], rax
    mov     rcx, qword ptr [rbp-24]
    mov     rax, qword ptr [rbp-32]         ; the allocation size, so the
    mov     qword ptr [rcx], rax            ; caller's mem_free wipes all of it
    mov     eax, 1
    cmp     dword ptr [g_rl_oom], 0
    je      @F
    mov     eax, 2
@@:
    FRAME_EPILOG
    ret
rf_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
rlog_flatten endp

end
