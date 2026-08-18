; =============================================================================
; volume.asm - splitting one container across several files
; -----------------------------------------------------------------------------
; A volume set is the ordinary container byte stream cut into pieces.  It is NOT
; a unit of encryption: the crypto runs exactly as it does for a single file and
; the cuts are made underneath it, so concatenating the slices reproduces the
; container byte for byte.  See docs/VOLUMES.md for why, and manifest.md for the
; constraint that forced it - a GCM tag covers a whole stream, so per-entry
; random access survives only if volumes slice the ciphertext run rather than
; becoming the streams.
;
; Consequences worth stating, because they are the point:
;   - no new nonce, key or AAD exists here.  A volume set has exactly the
;     integrity properties a single container has, because it IS one.
;   - the volume header is plaintext addressing BELOW the ciphertext.  Tampering
;     with it cannot forge anything; the worst it achieves is a misassembled
;     stream, and a misassembled stream fails a tag.
;   - the index needs no change: entry extents are already logical offsets from
;     HDR_BYTES, so an extent means the same thing across one file or nine.
;
;   vol_begin(rcx = wide output path, rdx = bytes per part) -> eax 0 ok
;   vol_write(rcx = buf, rdx = len)                          -> eax 0 ok
;   vol_finish()                                             -> eax 0 ok
;
; A limit of ZERO means "do not split": no volume header is written and the
; output keeps the shape it has always had - not the same BYTES, since the salt
; and set_id are fresh per container and no two encrypts ever match.  That makes
; the layer safe to sit in the write path before the reader exists.
; =============================================================================

include macros.inc

extern file_open_write:proc
extern file_write_all:proc
extern file_close:proc
extern file_delete:proc
extern file_seek:proc
extern file_open_read:proc
extern file_read_at:proc
extern get_file_size:proc
extern file_open_rw:proc
extern file_truncate:proc
extern file_rename:proc
externdef g_pkhdr:byte              ; pack.asm owns it; set_id is copied from it

INVALID         equ -1                  ; INVALID_HANDLE_VALUE, mirrored from
                                        ; cmd.asm/estream.asm - constcheck holds
                                        ; the three spellings to one value

.data?
g_vol_hout   dq ?                       ; handle of the part being written
g_vol_limit  dq ?                       ; bytes per part, 0 = do not split
g_vol_part   dd ?                       ; 1-based part number being written
g_vol_fill   dq ?                       ; slice bytes in the current part
g_vol_hdr    db VOL_HDR_BYTES dup (?)   ; the part header being written
g_vol_base   dw VOL_PATH_CHARS dup (?)  ; output path with any .mrk trimmed
g_vol_path   dw VOL_PATH_CHARS dup (?)  ; the current part's full path
g_vol_split  dd ?                       ; 1 once a limit made us split: the
                                        ; output is under its FINAL name, not a
                                        ; temp (stays set after vol_settle)
g_vs_parts   db VOL_MAX_PARTS*VOL_PART_STRIDE dup (?)  ; the open set
g_vs_hdr     db VOL_HDR_BYTES dup (?)   ; the part header being validated
g_vs_setid   db 12 dup (?)              ; part 1's set_id, the membership proof
g_vs_count   dd ?                       ; parts in the open set
g_vs_total   dq ?                       ; logical bytes across the whole set
g_vs_refs    dd ?                       ; open sets share one table; last close wins
g_vs_on      dd ?                       ; 1 while a SET is open for reading
g_vol_on     dd ?                       ; 1 between vol_begin and vol_finish
g_vol_toomany dd ?                      ; 1 if a write hit VOL_MAX_PARTS
g_vol_plain  dw VOL_PATH_CHARS dup (?)  ; the name the output would have had
                                        ; with no split - see vol_settle
g_vol_shift  db VOL_SHIFT_CHUNK dup (?) ; buffer for the header strip

.code

; =============================================================================
; vol_name(rcx = 1-based part number) - build g_vol_path from g_vol_base.
;
; <base>.partNNN.mrk, and .mrk LAST so file association keeps working on every
; part: double-clicking part 7 has to open Myrkr the same way part 1 does.  That
; is the RAR convention rather than 7-Zip's archive.7z.001, chosen for exactly
; that reason.
;
; Three digits to 999 and four beyond, up to VOL_MAX_PARTS.  The padding is
; cosmetic - a set is assembled from the part numbers inside the headers, never
; from a lexical sort of file names - but the WIDTH is not: see below for what
; a digit place that overflows produced.
; =============================================================================
vol_name proc
    mov     r8d, ecx                        ; part number
    lea     r10, [g_vol_base]
    lea     r11, [g_vol_path]
    xor     r9, r9
vn_copy:
    mov     ax, word ptr [r10+r9*2]
    test    ax, ax
    jz      vn_suffix
    mov     word ptr [r11+r9*2], ax
    inc     r9
    cmp     r9, VOL_PATH_CHARS - 16         ; room for ".partNNN.mrk" + NUL
    jb      vn_copy
vn_suffix:
    mov     word ptr [r11+r9*2], '.'
    inc     r9
    mov     word ptr [r11+r9*2], 'p'
    inc     r9
    mov     word ptr [r11+r9*2], 'a'
    inc     r9
    mov     word ptr [r11+r9*2], 'r'
    inc     r9
    mov     word ptr [r11+r9*2], 't'
    inc     r9
    ; Three digits to 999, FOUR beyond - not "three digits and let the hundreds
    ; place overflow", which is what stood here and was wrong in the worst way.
    ; 'add eax, "0"' on a hundreds digit of 10 gives ':', and a Windows path with
    ; a colon in it is not a file name, it is an alternate data stream: parts
    ; 1000-1099 were created as hidden streams on a zero-length file called
    ; "<base>.part", and 1100+ came out as "<base>.part;NN.mrk". Encrypt reported
    ; success, and the set even round-tripped locally, because the reader
    ; generates the same broken name and follows the writer into the same stream.
    ; It survives only until the folder is copied anywhere at all: streams do not
    ; travel to FAT, to a zip, to a share, or through most backup tools. Splitting
    ; exists precisely so the pieces can be MOVED.
    ;
    ; Reachable with the smallest offered split (100 MB) on any input past
    ; ~100 GB - and the report that started the volume work was a 587 GB folder.
    ;
    ; Sets of 999 parts or fewer keep exactly the names they always had.
    mov     eax, r8d
    cmp     eax, 1000
    jb      vn_hundreds
    xor     edx, edx
    mov     ecx, 1000
    div     ecx                             ; eax = thousands, edx = remainder
    add     eax, '0'
    mov     word ptr [r11+r9*2], ax
    inc     r9
    mov     eax, edx
vn_hundreds:
    xor     edx, edx
    mov     ecx, 100
    div     ecx                             ; eax = hundreds, edx = remainder
    add     eax, '0'
    mov     word ptr [r11+r9*2], ax
    inc     r9
    mov     eax, edx
    xor     edx, edx
    mov     ecx, 10
    div     ecx
    add     eax, '0'
    mov     word ptr [r11+r9*2], ax
    inc     r9
    add     edx, '0'
    mov     word ptr [r11+r9*2], dx
    inc     r9
    mov     word ptr [r11+r9*2], '.'
    inc     r9
    mov     word ptr [r11+r9*2], 'm'
    inc     r9
    mov     word ptr [r11+r9*2], 'r'
    inc     r9
    mov     word ptr [r11+r9*2], 'k'
    inc     r9
    mov     word ptr [r11+r9*2], 0
    ret
vol_name endp

; =============================================================================
; vol_open_part(rcx = part number, rdx = final flag) -> eax 0 ok / EXIT_IO
; Opens the part and writes its header.  Only ever called when splitting.
; =============================================================================
vol_open_part proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-40], ecx         ; part number
    mov     dword ptr [rbp-48], edx         ; flags
    call    vol_name                        ; rcx is still the part number
    lea     rcx, [g_vol_path]
    call    file_open_write
    cmp     rax, INVALID
    je      vop_io
    mov     qword ptr [g_vol_hout], rax
    ; ---- header -----------------------------------------------------------
    lea     r10, [g_vol_hdr]
    mov     dword ptr [r10+VOLH_magic], VOL_MAGIC
    mov     dword ptr [r10+VOLH_version], VOL_VERSION
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r10+VOLH_part], eax
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [r10+VOLH_flags], eax
    mov     dword ptr [r10+VOLH_reserved], 0
    ; set_id, verbatim from the container header.  This is the membership proof:
    ; it is 12 CSPRNG bytes drawn per container and already inside the header's
    ; AAD, so a part claiming another set's id still fails that container's tag.
    lea     r11, [g_pkhdr]
    add     r11, CONTAINER_SETID_OFF
    xor     r9, r9
vop_sid:
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+VOLH_setid+r9], al
    inc     r9
    cmp     r9, 12
    jb      vop_sid
    mov     rcx, qword ptr [g_vol_hout]
    lea     rdx, [g_vol_hdr]
    mov     r8, VOL_HDR_BYTES
    call    file_write_all
    test    eax, eax
    jnz     vop_io
    mov     qword ptr [g_vol_fill], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
vop_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
vol_open_part endp

; =============================================================================
; vol_begin(rcx = wide output path, rdx = bytes per part) -> eax 0 ok / EXIT_IO
;
; With a limit of 0 this opens the output exactly as the writer always did, and
; every byte handed to vol_write goes straight to it.
; =============================================================================
public vol_begin, g_vol_limit, g_vol_hout, g_vol_split, g_vol_toomany
vol_begin proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [g_vol_limit], rdx
    mov     dword ptr [g_vol_part], 1
    mov     qword ptr [g_vol_fill], 0
    mov     dword ptr [g_vol_split], 0
    mov     dword ptr [g_vol_toomany], 0
    mov     dword ptr [g_vol_on], 1
    mov     qword ptr [g_vol_hout], INVALID
    ; keep the path for part naming even when we do not split - cheap, and it
    ; means vol_name never depends on when the limit was set.  The UNTRIMMED
    ; copy is kept too: it is the name the output would have had if nothing had
    ; been split, and vol_settle renames a one-part set back to it.
    mov     r10, qword ptr [rbp-16]
    lea     r11, [g_vol_plain]
    xor     r9, r9
vb_pcopy:
    mov     ax, word ptr [r10+r9*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      vb_pcopied
    inc     r9
    cmp     r9, VOL_PATH_CHARS - 1
    jb      vb_pcopy
    mov     word ptr [r11+r9*2], 0
vb_pcopied:
    mov     r10, qword ptr [rbp-16]
    lea     r11, [g_vol_base]
    xor     r9, r9
vb_copy:
    mov     ax, word ptr [r10+r9*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      vb_copied
    inc     r9
    cmp     r9, VOL_PATH_CHARS - 1
    jb      vb_copy
    mov     word ptr [r11+r9*2], 0
vb_copied:
    ; Trim one trailing ".mrk" so a set of "folder.mrk" is folder.part001.mrk
    ; rather than folder.mrk.part001.mrk.  r9 is the length; the case fold is
    ; there because the caller's path is whatever the user typed.
    cmp     r9, 4
    jb      vb_trimmed
    mov     ax, word ptr [r11+r9*2-8]
    cmp     ax, '.'
    jne     vb_trimmed
    mov     ax, word ptr [r11+r9*2-6]
    or      ax, 20h
    cmp     ax, 'm'
    jne     vb_trimmed
    mov     ax, word ptr [r11+r9*2-4]
    or      ax, 20h
    cmp     ax, 'r'
    jne     vb_trimmed
    mov     ax, word ptr [r11+r9*2-2]
    or      ax, 20h
    cmp     ax, 'k'
    jne     vb_trimmed
    sub     r9, 4
    mov     word ptr [r11+r9*2], 0
vb_trimmed:
    cmp     qword ptr [g_vol_limit], 0
    jne     vb_split
    ; ---- no split: one file, no volume header, the usual container shape ---
    mov     rcx, qword ptr [rbp-16]
    call    file_open_write
    cmp     rax, INVALID
    je      vb_io
    mov     qword ptr [g_vol_hout], rax
    xor     eax, eax
    FRAME_EPILOG
    ret
vb_split:
    mov     dword ptr [g_vol_split], 1
    mov     ecx, 1
    xor     edx, edx                        ; not final; the last part says so
    call    vol_open_part
    FRAME_EPILOG
    ret
vb_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
vol_begin endp

; =============================================================================
; vol_write(rcx = buf, rdx = len) -> eax 0 ok / EXIT_IO
;
; Rolls to the next part when the current one is full.  The cut lands wherever
; the limit falls - mid-entry, mid-tag, anywhere - because a slice carries no
; meaning of its own.  That is the whole design: the pieces are bytes, and only
; the concatenation is a container.
; =============================================================================
public vol_write
vol_write proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx         ; cursor
    mov     qword ptr [rbp-24], rdx         ; remaining
vw_loop:
    cmp     qword ptr [rbp-24], 0
    je      vw_ok
    cmp     qword ptr [g_vol_limit], 0
    je      vw_all                          ; not splitting: one write, one file
    ; room left in this part
    mov     rax, qword ptr [g_vol_limit]
    sub     rax, qword ptr [g_vol_fill]
    jnz     vw_have
    ; full: close it and open the next
    mov     rcx, qword ptr [g_vol_hout]
    call    file_close
    mov     qword ptr [g_vol_hout], INVALID
    inc     dword ptr [g_vol_part]
    ; The writer stops where the READER stops.  vs_assemble refuses a set with
    ; more than VOL_MAX_PARTS members, and nothing here used to know that, so a
    ; small enough limit on a large enough input produced a set that encrypt
    ; called a success and decrypt could never open again.  Refusing at the same
    ; number means the two halves cannot disagree.
    ;
    ; It refuses mid-write because how many parts there will be is not knowable
    ; at vol_begin - the input is compressed and archived on the way past. The
    ; part left open never gets VOLF_FINAL, so the half-written set is refused on
    ; read as a missing tail rather than extracting short.
    cmp     dword ptr [g_vol_part], VOL_MAX_PARTS
    ja      vw_toomany
    mov     ecx, dword ptr [g_vol_part]
    xor     edx, edx
    call    vol_open_part
    test    eax, eax
    jnz     vw_ret
    mov     rax, qword ptr [g_vol_limit]
vw_have:
    cmp     rax, qword ptr [rbp-24]
    jbe     vw_chunk
    mov     rax, qword ptr [rbp-24]
vw_chunk:
    mov     qword ptr [rbp-32], rax         ; this write
    mov     rcx, qword ptr [g_vol_hout]
    mov     rdx, qword ptr [rbp-16]
    mov     r8, qword ptr [rbp-32]
    call    file_write_all
    test    eax, eax
    jnz     vw_io
    mov     rax, qword ptr [rbp-32]
    add     qword ptr [g_vol_fill], rax
    add     qword ptr [rbp-16], rax
    sub     qword ptr [rbp-24], rax
    jmp     vw_loop
vw_all:
    mov     rcx, qword ptr [g_vol_hout]
    mov     rdx, qword ptr [rbp-16]
    mov     r8, qword ptr [rbp-24]
    call    file_write_all
    test    eax, eax
    jnz     vw_io
    mov     qword ptr [rbp-24], 0
    jmp     vw_loop
vw_ok:
    xor     eax, eax
vw_ret:
    FRAME_EPILOG
    ret
vw_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
vw_toomany:
    ; Its own flag, so the caller can say WHICH refusal this is.  "Could not
    ; write" would send the user looking at the disk, and the answer is a larger
    ; part size - the same lesson as the split-container add message in 1.0.60.
    mov     dword ptr [g_vol_toomany], 1
    mov     eax, EXIT_UNSUPPORTED
    FRAME_EPILOG
    ret
vol_write endp

; =============================================================================
; ---------------------------- THE READ SIDE ----------------------------------
;
; A set is opened by being handed ANY of its parts: the reader strips the
; ".partNNN.mrk" tail, walks 001 upward until a part is missing, and holds them
; all open.  All of them, because reads are random access - an entry's extent
; can land in any part, and a set assembled once is cheaper than reopening.
;
; What is checked, and why each check exists rather than being assumed:
;   - magic and version, so a file that merely ends in .partNNN.mrk is refused
;     rather than read as addressing;
;   - set_id equal to part 1's, which is the membership proof v4 reserved the
;     field for - it catches parts of two different sets sharing a folder;
;   - part numbers contiguous from 1, so a hole is a refusal;
;   - VOLF_FINAL on the last part and no earlier one, so a MISSING TAIL is
;     caught.  Without it, a set whose last part had not been copied yet would
;     open, list, and extract a short archive without complaint - which is
;     exactly the failure 1.0.51 was about, and it is not being reintroduced
;     through a different door.
;
; None of this is security: the container's own tags are. It is addressing, and
; every one of these refusals is a case where addressing would otherwise be
; silently wrong.
; =============================================================================

; =============================================================================
; vs_hdr_check(rcx = part index 0-based, rdx = expected part number)
;   -> eax 0 ok / EXIT_CORRUPT
; The header of the part whose handle is already in the table is in g_vs_hdr.
; =============================================================================
vs_hdr_check proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx
    mov     dword ptr [rbp-32], edx
    lea     r10, [g_vs_hdr]
    cmp     dword ptr [r10+VOLH_magic], VOL_MAGIC
    jne     vhc_bad
    cmp     dword ptr [r10+VOLH_version], VOL_VERSION
    jne     vhc_bad
    mov     eax, dword ptr [rbp-32]
    cmp     dword ptr [r10+VOLH_part], eax
    jne     vhc_bad                         ; out of order or a hole
    ; set_id: part 1 defines it, every later part must match
    ; through a register: a RIP-relative operand cannot carry an index register,
    ; which is an ADDR32 relocation error at link time rather than an assembly one
    lea     rdx, [g_vs_setid]
    cmp     dword ptr [rbp-24], 0
    jne     vhc_cmpid
    xor     r9, r9
vhc_take:
    mov     al, byte ptr [r10+VOLH_setid+r9]
    mov     byte ptr [rdx+r9], al
    inc     r9
    cmp     r9, 12
    jb      vhc_take
    jmp     vhc_ok
vhc_cmpid:
    xor     r9, r9
vhc_cmp:
    mov     al, byte ptr [r10+VOLH_setid+r9]
    cmp     al, byte ptr [rdx+r9]
    jne     vhc_bad
    inc     r9
    cmp     r9, 12
    jb      vhc_cmp
vhc_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
vhc_bad:
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
vs_hdr_check endp

; =============================================================================
; vset_open(rcx = wide path) -> rax = handle, or INVALID
;
; Returns the handle the caller should keep using.  For a plain container that
; is simply the opened file and nothing else happens - g_vs_on stays 0 and every
; vol_get/vol_size below is a straight pass-through, which is what keeps the
; single-file path exactly as it was.
; =============================================================================
public vset_open
vset_open proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rcx
    ; ---- already open?  Join it rather than reassembling ---------------------
    ; estream opens one stream PER ENTRY and keeps them all open at once - that
    ; is what drag-out is - so a second vset_open must not tear down the set the
    ; first one built, and a vset_close from one stream must not close the parts
    ; the others are still reading.  The set is refcounted: the last release
    ; closes it.
    ;
    ; The part table is read-only once assembled and file_read_at takes an
    ; explicit offset, so sharing it across streams needs no further locking -
    ; there is no cursor to race over.
    cmp     dword ptr [g_vs_on], 0
    je      vso_fresh
    inc     dword ptr [g_vs_refs]
    lea     r10, [g_vs_parts]
    mov     rax, qword ptr [r10+VOLP_handle]
    FRAME_EPILOG
    ret
vso_fresh:
    mov     dword ptr [g_vs_on], 0
    mov     dword ptr [g_vs_count], 0
    mov     qword ptr [g_vs_total], 0
    mov     rcx, qword ptr [rbp-16]
    call    file_open_read
    cmp     rax, INVALID
    je      vso_no
    mov     qword ptr [rbp-24], rax
    ; ---- is it a part, or a container? -------------------------------------
    mov     rcx, rax
    xor     rdx, rdx
    lea     r8, [g_vs_hdr]
    mov     r9, VOL_HDR_BYTES
    call    file_read_at
    test    eax, eax
    jnz     vso_plain                       ; too short to be a part: not one
    lea     r10, [g_vs_hdr]
    cmp     dword ptr [r10+VOLH_magic], VOL_MAGIC
    jne     vso_plain
    ; ---- a part.  Close it and assemble the set from part 1 ----------------
    mov     rcx, qword ptr [rbp-24]
    call    file_close
    mov     rcx, qword ptr [rbp-16]
    call    vs_base_from_part
    test    eax, eax
    jnz     vso_no                          ; not named like a member
    call    vs_assemble
    test    eax, eax
    jnz     vso_no
    mov     dword ptr [g_vs_on], 1
    mov     dword ptr [g_vs_refs], 1
    ; the handle handed back is part 1's, so a caller that closes it without
    ; going through vset_close still releases something real
    lea     r10, [g_vs_parts]
    mov     rax, qword ptr [r10+VOLP_handle]
    FRAME_EPILOG
    ret
vso_plain:
    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
vso_no:
    mov     rax, INVALID
    FRAME_EPILOG
    ret
vset_open endp

; =============================================================================
; vol_part_suffix(rcx = wide path, rdx = length in chars with ".mrk" already
;                 removed) -> rax = the length with a ".partNNN" also removed,
;                 or rdx unchanged when there is none.
;
; Returns the LENGTH rather than the amount to subtract, so a caller keeping its
; running length in r8 does not have to protect it from this proc's scratch.
;
; TWO callers derive an output name from a container name and each had its own
; ".mrk" strip: derive_output_name (cmd.asm) and build_output (gui.asm). Fixing
; only the first left the right-drag - which goes through the second - still
; writing boot.wim.part001, reported after the first fix shipped. So the rule
; lives here once and both call it.
;
; Matched as a SHAPE - dot, "part", then three digits or four - not by searching
; for the text, so report.partial.mrk or notes.partABC.mrk keeps its name.
; =============================================================================
public vol_part_suffix
vol_part_suffix proc
    mov     rax, rdx                         ; unchanged unless the shape matches
    mov     r11, 8                           ; ".partNNN"
vps_try:
    cmp     rdx, r11
    jb      vps_wider
    mov     r10, rdx
    sub     r10, r11
    lea     r10, [rcx+r10*2]                 ; -> the candidate ".part..."
    cmp     word ptr [r10+0], '.'
    jne     vps_wider
    mov     r8w, word ptr [r10+2]
    or      r8w, 20h
    cmp     r8w, 'p'
    jne     vps_wider
    mov     r8w, word ptr [r10+4]
    or      r8w, 20h
    cmp     r8w, 'a'
    jne     vps_wider
    mov     r8w, word ptr [r10+6]
    or      r8w, 20h
    cmp     r8w, 'r'
    jne     vps_wider
    mov     r8w, word ptr [r10+8]
    or      r8w, 20h
    cmp     r8w, 't'
    jne     vps_wider
    xor     r9, r9
vps_dig:
    movzx   r8d, word ptr [r10+10+r9*2]
    cmp     r8d, '0'
    jb      vps_wider
    cmp     r8d, '9'
    ja      vps_wider
    inc     r9
    mov     r8, r11
    sub     r8, 5                            ; digits in this candidate
    cmp     r9, r8
    jb      vps_dig
    sub     rax, r11
    ret
vps_wider:
    ; Three digits, then four.  vol_name grows to four past part 999, and a
    ; fixed-width match left boot.wim.part1000 keeping "part1000" in the name it
    ; decrypted to - the same leak the three-digit case was fixed for.
    cmp     r11, 8
    jne     vps_ret
    mov     r11, 9                           ; ".partNNNN"
    jmp     vps_try
vps_ret:
    ret
vol_part_suffix endp

; =============================================================================
; vol_is_set(rcx = wide path) -> eax = 1 if that file is a member of a set
;
; For the EDIT paths, which must refuse.  Adding to or deleting from a set means
; rewriting the index through a plain handle and sliding survivors down over a
; hole; done to a set that would write past the end of whichever part happened to
; be last and destroy the container it was editing.  Reading a set is supported;
; editing one is not, and the difference has to be checked before anything is
; written rather than discovered half way through.
;
; Deliberately a cheap magic test on the file itself rather than a full
; vset_open: the caller is about to refuse, so assembling the set to prove what
; is already known would be work done only to throw away - and it would fail for
; a set with a missing part, turning "cannot edit a set" into "corrupt", which is
; a worse answer to the same question.
; =============================================================================
public vol_is_set
vol_is_set proc frame
    FRAME_PROLOG 64
    call    file_open_read
    cmp     rax, INVALID
    je      vis_no
    mov     qword ptr [rbp-16], rax
    mov     rcx, rax
    xor     rdx, rdx
    lea     r8, [g_vs_hdr]
    mov     r9, VOL_HDR_BYTES
    call    file_read_at
    mov     dword ptr [rbp-24], eax
    mov     rcx, qword ptr [rbp-16]
    call    file_close
    cmp     dword ptr [rbp-24], 0
    jne     vis_no
    lea     r10, [g_vs_hdr]
    cmp     dword ptr [r10+VOLH_magic], VOL_MAGIC
    jne     vis_no
    mov     eax, 1
    FRAME_EPILOG
    ret
vis_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
vol_is_set endp

; =============================================================================
; vs_base_from_part(rcx = a member's path) -> eax 0 ok, g_vol_base = the base
; Strips exactly ".partNNN.mrk".  A member that has been renamed cannot have its
; siblings found, and saying so beats guessing.
; =============================================================================
vs_base_from_part proc
    mov     r10, rcx
    xor     r9, r9
vbp_len:
    cmp     word ptr [r10+r9*2], 0
    je      vbp_have
    inc     r9
    cmp     r9, VOL_PATH_CHARS - 1
    jb      vbp_len
vbp_have:
    ; Try the three-digit tail, then the four-digit one.  vol_name emits four
    ; digits past part 999, so a member of a large set is ".partNNNN.mrk" and a
    ; fixed 12-character strip would cut in the wrong place - it would take the
    ; leading digit for part of the base name and then look for siblings of a set
    ; that does not exist.  Handing over part 1000 of a set has to work as well as
    ; handing over part 1.
    mov     r8, VOL_SUFFIX_CHARS
vbp_try:
    cmp     r9, r8
    jbe     vbp_widen
    mov     rdx, r9
    sub     rdx, r8                         ; -> the '.' of ".part...mrk"
    cmp     word ptr [r10+rdx*2], '.'
    jne     vbp_widen
    cmp     word ptr [r10+rdx*2+2], 'p'
    jne     vbp_widen
    cmp     word ptr [r10+rdx*2+4], 'a'
    jne     vbp_widen
    cmp     word ptr [r10+rdx*2+6], 'r'
    jne     vbp_widen
    cmp     word ptr [r10+rdx*2+8], 't'
    je      vbp_match
vbp_widen:
    cmp     r8, VOL_SUFFIX_CHARS
    jne     vbp_bad                         ; both widths tried
    mov     r8, VOL_SUFFIX_CHARS + 1        ; ".partNNNN.mrk"
    jmp     vbp_try
vbp_match:
    mov     r9, rdx
    lea     r11, [g_vol_base]
    xor     rax, rax
vbp_copy:
    cmp     rax, r9
    jae     vbp_done
    mov     dx, word ptr [r10+rax*2]
    mov     word ptr [r11+rax*2], dx
    inc     rax
    jmp     vbp_copy
vbp_done:
    mov     word ptr [r11+rax*2], 0
    xor     eax, eax
    ret
vbp_bad:
    mov     eax, 1
    ret
vs_base_from_part endp

; =============================================================================
; vs_assemble() -> eax 0 ok / EXIT_CORRUPT | EXIT_IO
; Opens part 1 upward until one is missing, validating as it goes.
; =============================================================================
vs_assemble proc frame
    FRAME_PROLOG 96
    xor     r9d, r9d
    mov     dword ptr [rbp-24], r9d         ; index
    mov     qword ptr [g_vs_total], 0
vsa_next:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, VOL_MAX_PARTS
    jae     vsa_toomany
    lea     ecx, [eax+1]                    ; 1-based part number
    mov     dword ptr [rbp-32], ecx
    call    vol_name
    lea     rcx, [g_vol_path]
    call    file_open_read
    cmp     rax, INVALID
    je      vsa_end                         ; no more parts
    mov     qword ptr [rbp-40], rax
    ; header
    mov     rcx, rax
    xor     rdx, rdx
    lea     r8, [g_vs_hdr]
    mov     r9, VOL_HDR_BYTES
    call    file_read_at
    test    eax, eax
    jnz     vsa_io
    mov     ecx, dword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    vs_hdr_check
    test    eax, eax
    jnz     vsa_corrupt
    ; size -> slice length
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rbp-48]
    call    get_file_size
    test    eax, eax
    jnz     vsa_io
    mov     rax, qword ptr [rbp-48]
    cmp     rax, VOL_HDR_BYTES
    jb      vsa_corrupt
    sub     rax, VOL_HDR_BYTES
    ; record it
    mov     r10d, dword ptr [rbp-24]
    imul    r10, r10, VOL_PART_STRIDE
    lea     r11, [g_vs_parts]
    add     r11, r10
    mov     rdx, qword ptr [rbp-40]
    mov     qword ptr [r11+VOLP_handle], rdx
    mov     rdx, qword ptr [g_vs_total]
    mov     qword ptr [r11+VOLP_start], rdx
    mov     qword ptr [r11+VOLP_len], rax
    add     qword ptr [g_vs_total], rax
    inc     dword ptr [rbp-24]
    ; was that the final part?
    lea     r10, [g_vs_hdr]
    test    dword ptr [r10+VOLH_flags], VOLF_FINAL
    jz      vsa_next
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_vs_count], eax
    xor     eax, eax
    FRAME_EPILOG
    ret
vsa_end:
    ; ran out of parts without ever seeing the final flag: the tail is missing.
    ; Refusing here is the whole point of the flag.
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
vsa_toomany:
vsa_corrupt:
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
vsa_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
vs_assemble endp

; =============================================================================
; vol_size(rcx = handle, rdx = *size) -> eax 0 ok / EXIT_IO
; The LOGICAL size: what the container would be as one file.
; =============================================================================
public vol_size
vol_size proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_vs_on], 0
    je      vsz_plain
    mov     rax, qword ptr [g_vs_total]
    mov     qword ptr [rdx], rax
    xor     eax, eax
    FRAME_EPILOG
    ret
vsz_plain:
    call    get_file_size
    FRAME_EPILOG
    ret
vol_size endp

; =============================================================================
; vol_get(rcx = handle, rdx = logical offset, r8 = buf, r9 = len)
;   -> eax 0 ok / EXIT_IO
; Spans parts.  A read that crosses a cut is the normal case, not an edge one:
; the cut lands wherever the size limit fell.
; =============================================================================
public vol_get
vol_get proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rcx         ; handle (plain path only)
    mov     qword ptr [rbp-24], rdx         ; logical offset
    mov     qword ptr [rbp-32], r8          ; buf
    mov     qword ptr [rbp-40], r9          ; remaining
    cmp     dword ptr [g_vs_on], 0
    jne     vg_set
    call    file_read_at                    ; arguments are still in place
    FRAME_EPILOG
    ret
vg_set:
    cmp     qword ptr [rbp-40], 0
    je      vg_ok
    ; find the part holding this offset
    xor     r9d, r9d
vg_find:
    cmp     r9d, dword ptr [g_vs_count]
    jae     vg_range
    mov     r10, r9
    imul    r10, r10, VOL_PART_STRIDE
    lea     r11, [g_vs_parts]
    add     r11, r10
    mov     rax, qword ptr [r11+VOLP_start]
    cmp     qword ptr [rbp-24], rax
    jb      vg_nextpart
    add     rax, qword ptr [r11+VOLP_len]
    cmp     qword ptr [rbp-24], rax
    jb      vg_have
vg_nextpart:
    inc     r9d
    jmp     vg_find
vg_have:
    ; bytes available in this part from the offset
    mov     rax, qword ptr [r11+VOLP_start]
    add     rax, qword ptr [r11+VOLP_len]
    sub     rax, qword ptr [rbp-24]         ; available
    cmp     rax, qword ptr [rbp-40]
    jbe     vg_chunk
    mov     rax, qword ptr [rbp-40]
vg_chunk:
    mov     qword ptr [rbp-48], rax         ; this read
    ; physical offset = VOL_HDR_BYTES + (logical - part start)
    mov     rdx, qword ptr [rbp-24]
    sub     rdx, qword ptr [r11+VOLP_start]
    add     rdx, VOL_HDR_BYTES
    mov     rcx, qword ptr [r11+VOLP_handle]
    mov     r8, qword ptr [rbp-32]
    mov     r9, qword ptr [rbp-48]
    call    file_read_at
    test    eax, eax
    jnz     vg_io
    mov     rax, qword ptr [rbp-48]
    add     qword ptr [rbp-24], rax
    add     qword ptr [rbp-32], rax
    sub     qword ptr [rbp-40], rax
    jmp     vg_set
vg_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
vg_range:
vg_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
vol_get endp

; =============================================================================
; vset_close(rcx = handle) - closes the whole set, or the one plain file.
; =============================================================================
public vset_close
vset_close proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    cmp     dword ptr [g_vs_on], 0
    je      vsc_plain
    ; the last release closes the parts; the others just let go
    dec     dword ptr [g_vs_refs]
    cmp     dword ptr [g_vs_refs], 0
    jg      vsc_ret
    xor     r9d, r9d
    mov     dword ptr [rbp-24], r9d
vsc_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_vs_count]
    jae     vsc_done
    mov     r10, rax
    imul    r10, r10, VOL_PART_STRIDE
    lea     r11, [g_vs_parts]
    add     r11, r10
    mov     rcx, qword ptr [r11+VOLP_handle]
    call    file_close
    inc     dword ptr [rbp-24]
    jmp     vsc_loop
vsc_done:
    mov     dword ptr [g_vs_on], 0
    mov     dword ptr [g_vs_count], 0
    mov     dword ptr [g_vs_refs], 0
vsc_ret:
    FRAME_EPILOG
    ret
vsc_plain:
    mov     rcx, qword ptr [rbp-16]
    call    file_close
    FRAME_EPILOG
    ret
vset_close endp

; =============================================================================
; vol_discard() - delete every part of a set that failed part way through.
;
; do_pack deletes its partial output on ANY failure, so that a run that did not
; finish leaves nothing behind pretending to be a container.  For a split set
; that delete hit the un-split output path, which does not exist, and the parts
; stayed - a failed encrypt at the 4096-part ceiling left 4096 files, and an I/O
; failure or a cancellation half way left however many it had written.  None of
; them are openable (the last one never got VOLF_FINAL), so what they were was
; unusable files the user had to identify and remove by hand.
;
; Deletes 1..g_vol_part, the ones this run created.  It cannot touch an unrelated
; set: the names come from the base path this run was given.
; =============================================================================
public vol_discard
vol_discard proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_vol_split], 0
    je      vd_ret                          ; never split: nothing of ours to undo
    cmp     qword ptr [g_vol_hout], INVALID
    je      @F
    mov     rcx, qword ptr [g_vol_hout]
    call    file_close
    mov     qword ptr [g_vol_hout], INVALID
@@:
    mov     dword ptr [rbp-24], 1
vd_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_vol_part]
    ja      vd_done
    mov     ecx, eax
    call    vol_name
    lea     rcx, [g_vol_path]
    call    file_delete
    inc     dword ptr [rbp-24]
    jmp     vd_loop
vd_done:
    mov     dword ptr [g_vol_split], 0      ; done once, whoever asks
    mov     dword ptr [g_vol_on], 0
vd_ret:
    xor     eax, eax
    FRAME_EPILOG
    ret
vol_discard endp

; =============================================================================
; vol_put(rcx = handle, rdx = buf, r8 = len) -> eax 0 ok / EXIT_IO
;
; For code shared between the fresh pack and the in-place edit paths - idx_write
; is the only such proc.  A fresh pack's index has to go through the rolling
; sink or it would land past the end of the last part; an add or a delete is
; rewriting one existing file in place and must not.
;
; Dispatching on "is a volume write in progress" keeps that decision in one
; place.  The alternative, passing a flag down through idx_write, puts the same
; question at every call site and gets it wrong at the one added later.
; =============================================================================
public vol_put
vol_put proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    cmp     dword ptr [g_vol_on], 0
    je      vp_plain
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    vol_write
    FRAME_EPILOG
    ret
vp_plain:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    file_write_all
    FRAME_EPILOG
    ret
vol_put endp

; =============================================================================
; vol_settle() -> eax 0 ok / EXIT_IO
;
; A SET OF ONE IS NOT A SET.
;
; With a split size set, a container that fitted in one part was still written
; as <base>.part001.mrk with a volume header on the front - so a 50 MB output
; under a 100 MB limit was named like a member of a set, refused edits like a
; set, and told the user nothing about why.  The size that WOULD have needed
; splitting is not a property of the file that came out.
;
; do_pack skips the split entirely when its pre-flight says the container will
; fit, so this path is only reached when that estimate was wrong in the safe
; direction - the estimate is a store-mode upper bound and compression can only
; shrink what actually gets written.  Which is also why the copy below is cheap
; when it happens: the file is small precisely because it compressed.
;
; The strip is IN PLACE - read at k+32, write at k - rather than a copy to a
; second file.  A copy would need as much free space again, and failing for want
; of room AFTER a successful encrypt is a worse outcome than the naming was.
; =============================================================================
vol_settle proc frame
    FRAME_PROLOG 96
    cmp     dword ptr [g_vol_split], 0
    je      vst_ok                          ; never split: nothing to undo
    cmp     dword ptr [g_vol_part], 1
    jne     vst_ok                          ; a real set: leave it alone
    mov     ecx, 1
    call    vol_name                        ; g_vol_path = <base>.part001.mrk
    lea     rcx, [g_vol_path]
    call    file_open_rw
    cmp     rax, INVALID
    je      vst_io
    mov     qword ptr [rbp-16], rax         ; handle
    mov     rcx, rax
    lea     rdx, [rbp-24]
    call    get_file_size
    test    eax, eax
    jnz     vst_close_io
    mov     rax, qword ptr [rbp-24]
    cmp     rax, VOL_HDR_BYTES
    jbe     vst_close_io                    ; header and nothing else
    sub     rax, VOL_HDR_BYTES
    mov     qword ptr [rbp-32], rax         ; bytes to move
    mov     qword ptr [rbp-40], 0           ; destination cursor
vst_loop:
    mov     rax, qword ptr [rbp-32]
    test    rax, rax
    jz      vst_trunc
    cmp     rax, VOL_SHIFT_CHUNK
    jbe     @F
    mov     rax, VOL_SHIFT_CHUNK
@@:
    mov     qword ptr [rbp-48], rax         ; this chunk
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-40]
    add     rdx, VOL_HDR_BYTES              ; source is 32 further on
    lea     r8, [g_vol_shift]
    mov     r9, qword ptr [rbp-48]
    call    file_read_at
    test    eax, eax
    jnz     vst_close_io
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-40]
    call    file_seek
    test    eax, eax
    jnz     vst_close_io
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [g_vol_shift]
    mov     r8, qword ptr [rbp-48]
    call    file_write_all
    test    eax, eax
    jnz     vst_close_io
    mov     rax, qword ptr [rbp-48]
    add     qword ptr [rbp-40], rax
    sub     qword ptr [rbp-32], rax
    jmp     vst_loop
vst_trunc:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-40]
    call    file_truncate
    test    eax, eax
    jnz     vst_close_io
    mov     rcx, qword ptr [rbp-16]
    call    file_close
    mov     qword ptr [rbp-16], INVALID
    ; ...and back to the name it would have had all along.
    lea     rcx, [g_vol_path]
    lea     rdx, [g_vol_plain]
    call    file_rename
    test    eax, eax
    jnz     vst_io
    ; g_vol_split STAYS SET.  Its one reader asks "was the output written
    ; straight to its final name, rather than to a temp that still has to be
    ; renamed?" - and that is true of a promoted part exactly as it is of a real
    ; set.  Clearing it here sent do_pack down the temp-rename path for a temp
    ; that a split run never created, so a perfectly good container came out
    ; alongside "error: I/O failure".
vst_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
vst_close_io:
    mov     rcx, qword ptr [rbp-16]
    call    file_close
vst_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
vol_settle endp

; =============================================================================
; vol_finish() -> eax 0 ok / EXIT_IO
;
; Marks the last part final and closes it.  The flag is written by REOPENING the
; part header rather than being known in advance, because how many parts there
; will be is not knowable when part 1 is written and patching part 1 afterwards
; would mean returning to media that may already have been swapped out.
;
; A reader therefore requires parts 1..N contiguous with the final flag on N: a
; missing tail is a missing flag rather than a silently short archive.  After
; 1.0.51 that distinction is not a theoretical one.
; =============================================================================
public vol_finish
vol_finish proc frame
    FRAME_PROLOG 64
    cmp     qword ptr [g_vol_hout], INVALID
    je      vf_ok
    cmp     dword ptr [g_vol_split], 0
    je      vf_close                        ; single file: nothing to mark
    ; the header is still in g_vol_hdr for this part - set final and rewrite it
    lea     r10, [g_vol_hdr]
    mov     eax, dword ptr [r10+VOLH_flags]
    or      eax, VOLF_FINAL
    mov     dword ptr [r10+VOLH_flags], eax
    mov     rcx, qword ptr [g_vol_hout]
    xor     rdx, rdx
    call    file_seek
    test    eax, eax
    jnz     vf_io
    mov     rcx, qword ptr [g_vol_hout]
    lea     rdx, [g_vol_hdr]
    mov     r8, VOL_HDR_BYTES
    call    file_write_all
    test    eax, eax
    jnz     vf_io
vf_close:
    mov     dword ptr [g_vol_on], 0
    mov     rcx, qword ptr [g_vol_hout]
    call    file_close
    mov     qword ptr [g_vol_hout], INVALID
    ; One part is not a set: put it back under its plain name.  Here rather than
    ; at the caller so every path that finishes a write gets it.
    call    vol_settle
    FRAME_EPILOG
    ret
vf_ok:
    mov     dword ptr [g_vol_on], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
vf_io:
    mov     dword ptr [g_vol_on], 0
    mov     rcx, qword ptr [g_vol_hout]
    call    file_close
    mov     qword ptr [g_vol_hout], INVALID
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
vol_finish endp

end
