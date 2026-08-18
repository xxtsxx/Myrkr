; =============================================================================
; progress.asm - in-place console progress bar for long streaming operations
; -----------------------------------------------------------------------------
;   progress_begin(rcx = total bytes, rdx = label ptr, r8d = label len)
;   progress_add(rcx = delta bytes processed)
;   progress_done()
;
; Renders a carriage-return-updated line to STDERR:
;     <label>  [########----------------]  62%   5734 / 9248 MiB
; Throttled to repaint only when the integer percentage changes (<=101 paints).
; Output goes to STDERR so STDOUT stays clean for piping, and is fully
; SUPPRESSED when STDERR is not an interactive console (GetConsoleMode fails) -
; so redirecting output to a file never embeds bar/CR spam.
; =============================================================================

include macros.inc

extern GetStdHandle:proc
extern GetConsoleMode:proc
extern WriteFile:proc
extern GetTickCount64:proc              ; the rate/eta clock (ms since boot)
externdef g_hstderr:qword               ; console.asm: the REAL stderr (test override)
ifdef TEST_IO
extern GetEnvironmentVariableW:proc     ; MYRKR_DBG_PROGRESS, see progress_begin
endif

STD_ERROR_HANDLE    equ -12
BARW                equ 24              ; bar width in characters

.data?
public g_prog_total, g_prog_done, g_prog_abort
public g_cur_input, g_file_done, g_file_total
public g_prog_startms, g_prog_label, g_prog_lablen
g_prog_total    dq ?
g_prog_done     dq ?
; The rate/eta clock starts at the FIRST BYTE, not at progress_begin: key
; derivation runs between the two (up to seconds, longer under a policy that
; raises the cost), and folding that idle head into the average would make the
; first minute's rate a lie in exactly the direction that misleads - too slow,
; so the ETA reads long and then collapses.  0 = no byte seen yet.
g_prog_startms  dq ?
g_prog_lastms   dq ?                    ; last console repaint (time throttle)
; ---- per-input progress (GUI listview per-file bars) ------------------------
; g_cur_input = index (0..15) of the positional currently being streamed into
; the output; g_file_done/g_file_total accumulate per-input byte counts so the
; GUI can render a progress bar per file.  Set by the pack/encrypt path; polled
; (read-only) by the GUI timer.  Harmless/unused on the CLI and decrypt paths.
g_cur_input     dq ?
g_file_done     dq MAX_ARGS dup (?)     ; one slot per positional input
g_file_total    dq MAX_ARGS dup (?)
g_prog_h        dq ?                    ; cached STDERR handle
g_prog_active   dd ?                    ; 1 = console, render; 0 = suppress
g_prog_abort    dd ?                    ; set by progress_abort() (GUI Cancel)
g_prog_lastpct  dd ?                    ; last painted percent (-1 = none yet)
g_prog_mode     dd ?                    ; GetConsoleMode out (unused value)
g_prog_written  dd ?                    ; WriteFile out (unused value)
g_prog_lablen   dd ?
g_prog_label    dq ?
pr_tmp          db 24 dup (?)           ; scratch for decimal conversion
g_prog_buf      db 200 dup (?)          ; assembled render line

.const
pr_open     db "  ["
pr_open_len  equ $ - pr_open
pr_close    db "] "
pr_close_len equ $ - pr_close
pr_pct      db "%  "
pr_pct_len   equ $ - pr_pct
pr_sep      db " / "
pr_sep_len   equ $ - pr_sep
pr_unit     db " MiB     "
pr_unit_len  equ $ - pr_unit
pr_crlf     db 13, 10
pr_rate     db "  "
pr_rate_len  equ $ - pr_rate
pr_mbs      db " MB/s  eta "
pr_mbs_len   equ $ - pr_mbs
pr_colon    db ":"
pr_pad4     db "    "
pr_pad4_len  equ $ - pr_pad4
ifdef TEST_IO
even
w_dbg_prog  dw 'M','Y','R','K','R','_','D','B','G','_','P','R','O','G','R','E','S','S',0
endif

.code

; ---------------------------------------------------------------------------
; pr_copy - append ecx bytes from [r8] to the cursor r11 (leaf).
; Clobbers rax, r9; advances r11.
; ---------------------------------------------------------------------------
pr_copy proc
    test    ecx, ecx
    jz      prc_d
    xor     r9d, r9d
prc_l:
    mov     al, byte ptr [r8+r9]
    mov     byte ptr [r11+r9], al
    inc     r9d
    cmp     r9d, ecx
    jb      prc_l
    add     r11, r9
prc_d:
    ret
pr_copy endp

; ---------------------------------------------------------------------------
; pr_dec - append unsigned decimal of rax to the cursor r11 (leaf).
; Clobbers rax, rdx, r8, r9, r10; advances r11.
; ---------------------------------------------------------------------------
pr_dec proc
    lea     r9, [pr_tmp+24]
    mov     r8, 10
prd_l:
    xor     edx, edx
    div     r8                          ; rax/10, rdx = digit
    add     dl, '0'
    dec     r9
    mov     byte ptr [r9], dl
    test    rax, rax
    jnz     prd_l
    lea     r10, [pr_tmp+24]
prd_c:
    mov     al, byte ptr [r9]
    mov     byte ptr [r11], al
    inc     r11
    inc     r9
    cmp     r9, r10
    jb      prd_c
    ret
pr_dec endp

; ---------------------------------------------------------------------------
; pr_dec2 - append rax as exactly two digits, zero-padded (leaf, mirrors
; pr_dec).  For the mm and ss of an eta, where "1:2:3" reads as nonsense.
; ---------------------------------------------------------------------------
pr_dec2 proc
    mov     r10, rax
    mov     rax, r10
    xor     edx, edx
    mov     r9, 10
    div     r9                          ; rax = tens, rdx = ones
    add     al, '0'
    mov     byte ptr [r11], al
    inc     r11
    add     dl, '0'
    mov     byte ptr [r11], dl
    inc     r11
    ret
pr_dec2 endp

; ---------------------------------------------------------------------------
; prog_render - paint the current state (only called while active).
; ---------------------------------------------------------------------------
prog_render proc frame
    FRAME_PROLOG 64                      ; shadow + 5th-arg slot for WriteFile,
                                         ; plus [rbp-16] cursor / [rbp-24] rate
                                         ; held across the helper calls
    lea     r11, [g_prog_buf]
    mov     byte ptr [r11], 13          ; CR -> overwrite line in place
    inc     r11
    mov     byte ptr [r11], ' '
    inc     r11
    mov     byte ptr [r11], ' '
    inc     r11
    ; label
    mov     r8, qword ptr [g_prog_label]
    mov     ecx, dword ptr [g_prog_lablen]
    call    pr_copy
    ; "  ["
    lea     r8, [pr_open]
    mov     ecx, pr_open_len
    call    pr_copy
    ; bar: filled = pct*BARW/100
    mov     eax, dword ptr [g_prog_lastpct]
    imul    eax, eax, BARW
    xor     edx, edx
    mov     ecx, 100
    div     ecx                         ; eax = filled count
    mov     r9d, eax
    xor     ecx, ecx
prr_f:
    cmp     ecx, r9d
    jae     prr_fe
    mov     byte ptr [r11], '#'
    inc     r11
    inc     ecx
    jmp     prr_f
prr_fe:
    mov     ecx, r9d
prr_e:
    cmp     ecx, BARW
    jae     prr_ee
    mov     byte ptr [r11], '-'
    inc     r11
    inc     ecx
    jmp     prr_e
prr_ee:
    ; "] "
    lea     r8, [pr_close]
    mov     ecx, pr_close_len
    call    pr_copy
    ; percent
    mov     eax, dword ptr [g_prog_lastpct]
    call    pr_dec
    lea     r8, [pr_pct]
    mov     ecx, pr_pct_len
    call    pr_copy
    ; done MiB
    mov     rax, qword ptr [g_prog_done]
    shr     rax, 20
    call    pr_dec
    lea     r8, [pr_sep]
    mov     ecx, pr_sep_len
    call    pr_copy
    ; total MiB
    mov     rax, qword ptr [g_prog_total]
    shr     rax, 20
    call    pr_dec
    lea     r8, [pr_unit]
    mov     ecx, pr_unit_len
    call    pr_copy
    ; ---- rate and eta, once there is a second of signal ---------------------
    ; "  345.6 MB/s  eta 12:34" (h:mm:ss past an hour).  Padded with spaces at
    ; the end so a line that SHRINKS - fewer rate digits, an hour boundary -
    ; cannot leave the previous paint's tail on screen.
    mov     qword ptr [rbp-16], r11     ; cursor survives the calls below
    call    prog_speed_x10
    test    rax, rax
    jz      prr_norate
    mov     qword ptr [rbp-24], rax
    mov     r11, qword ptr [rbp-16]
    lea     r8, [pr_rate]
    mov     ecx, pr_rate_len
    call    pr_copy
    mov     rax, qword ptr [rbp-24]
    xor     edx, edx
    mov     rcx, 10
    div     rcx                         ; rax = whole MB/s, rdx = tenth
    mov     qword ptr [rbp-24], rdx     ; IN THE FRAME: pr_dec clobbers r9/r10,
                                        ; and holding a remainder in either is
                                        ; the clobber class this session has
                                        ; now hit three times
    call    pr_dec
    mov     byte ptr [r11], '.'
    inc     r11
    mov     rax, qword ptr [rbp-24]
    add     al, '0'
    mov     byte ptr [r11], al
    inc     r11
    lea     r8, [pr_mbs]
    mov     ecx, pr_mbs_len
    call    pr_copy
    mov     qword ptr [rbp-16], r11
    call    prog_eta_s
    mov     r11, qword ptr [rbp-16]
    cmp     rax, -1
    je      prr_pad                     ; rate known but eta not: leave it off
    ; h:mm:ss, hours only when there are any
    xor     edx, edx
    mov     rcx, 3600
    div     rcx                         ; rax = h, rdx = m*60+s
    mov     qword ptr [rbp-24], rdx     ; the frame again, same reason as above
    test    rax, rax
    jz      prr_msec
    call    pr_dec
    lea     r8, [pr_colon]
    mov     ecx, 1
    call    pr_copy
    mov     rax, qword ptr [rbp-24]
    xor     edx, edx
    mov     rcx, 60
    div     rcx
    mov     qword ptr [rbp-24], rdx
    call    pr_dec2                     ; minutes zero-padded under an hour count
    jmp     prr_secs
prr_msec:
    mov     rax, qword ptr [rbp-24]
    xor     edx, edx
    mov     rcx, 60
    div     rcx
    mov     qword ptr [rbp-24], rdx
    call    pr_dec                      ; bare minutes: "4:07", not "04:07"
prr_secs:
    lea     r8, [pr_colon]
    mov     ecx, 1
    call    pr_copy
    mov     rax, qword ptr [rbp-24]
    call    pr_dec2
prr_pad:
    lea     r8, [pr_pad4]
    mov     ecx, pr_pad4_len
    call    pr_copy
    jmp     prr_write
prr_norate:
    mov     r11, qword ptr [rbp-16]
prr_write:
    ; WriteFile(stderr, buf, len, &written, NULL)
    mov     r10, r11
    lea     rax, [g_prog_buf]
    sub     r10, rax                    ; r10 = length
    WINCALL WriteFile, qword ptr [g_prog_h], addr g_prog_buf, r10d, addr g_prog_written, 0
    FRAME_EPILOG
    ret
prog_render endp

; =============================================================================
public progress_begin
progress_begin proc frame
    FRAME_PROLOG 32
    mov     qword ptr [g_prog_total], rcx
    mov     qword ptr [g_prog_label], rdx
    mov     dword ptr [g_prog_lablen], r8d
    mov     qword ptr [g_prog_done], 0
    mov     dword ptr [g_prog_abort], 0
    ; reset the per-input counters (totals are filled by the caller afterwards)
    mov     qword ptr [g_cur_input], 0
    xor     r10, r10
pb_zero_files:
    lea     r11, [g_file_done]
    mov     qword ptr [r11+r10*8], 0
    inc     r10
    cmp     r10, MAX_ARGS
    jb      pb_zero_files
    mov     dword ptr [g_prog_lastpct], -1
    mov     dword ptr [g_prog_active], 0
    mov     qword ptr [g_prog_startms], 0
    mov     qword ptr [g_prog_lastms], 0
    WINCALL GetStdHandle, STD_ERROR_HANDLE
    mov     qword ptr [g_prog_h], rax
ifdef TEST_IO
    ; THE OVERRIDE WINS FIRST, console or not.  The bar aims at the console by
    ; design - the hybrid binary's AttachConsole replaces the std handles, so
    ; with a parent terminal the bar stays visible there even when the user
    ; redirects 2> to a file, which keeps the file clean AND the bar on screen.
    ; It also makes the bar invisible to everything that captures stderr, in
    ; both directions: a harness console makes GetConsoleMode SUCCEED and the
    ; frames go to a screen nobody reads.  So a test build with
    ; MYRKR_DBG_PROGRESS set renders into g_hstderr - con_init's captured REAL
    ; stderr - where a 2> file collects the CR-separated frames.  Release
    ; builds have no override in either direction.
    WINCALL GetEnvironmentVariableW, addr w_dbg_prog, addr g_prog_mode, 2
    test    eax, eax
    jz      pb_noforce
    mov     rax, qword ptr [g_hstderr]
    test    rax, rax
    jz      pb_noforce
    mov     qword ptr [g_prog_h], rax
    jmp     pb_console
pb_noforce:
endif
    mov     rcx, qword ptr [g_prog_h]
    WINCALL GetConsoleMode, rcx, addr g_prog_mode   ; 0 if not a console
    test    eax, eax
    jz      pb_done
pb_console:
    mov     dword ptr [g_prog_active], 1
    mov     dword ptr [g_prog_lastpct], 0
    call    prog_render                 ; paint initial 0%
pb_done:
    FRAME_EPILOG
    ret
progress_begin endp

; =============================================================================
; Returns eax = abort flag (1 if progress_abort was called, e.g. GUI Cancel).
; g_prog_done is ALWAYS updated (even when not rendering to a console) so a GUI
; can poll it; only the on-screen repaint is gated by g_prog_active.
public progress_add
progress_add proc frame
    FRAME_PROLOG 48
    ; [rbp-16] = now (ms)
    add     qword ptr [g_prog_done], rcx
    ; attribute these bytes to the current input (for GUI per-file bars)
    mov     r10, qword ptr [g_cur_input]
    cmp     r10, MAX_ARGS
    jae     pa_nofile
    lea     r11, [g_file_done]
    add     qword ptr [r11+r10*8], rcx
pa_nofile:
    ; The rate/eta clock starts HERE, at the first byte - before the console
    ; gate, because the GUI (whose stderr is no console) reads the same clock
    ; through prog_speed_x10 / prog_eta_s.
    WINCALL GetTickCount64
    mov     qword ptr [rbp-16], rax
    cmp     qword ptr [g_prog_startms], 0
    jne     pa_clocked
    cmp     qword ptr [g_prog_done], 0
    je      pa_clocked
    mov     qword ptr [g_prog_startms], rax
pa_clocked:
    cmp     dword ptr [g_prog_active], 0
    je      pa_ret                      ; not a console -> track only, no repaint
    mov     rax, qword ptr [g_prog_total]
    test    rax, rax
    jz      pa_full
    mov     rax, qword ptr [g_prog_done]
    mov     r8, 100
    mul     r8                          ; rdx:rax = done*100 (fits 64 to ~160 PB)
    mov     r8, qword ptr [g_prog_total]
    xor     edx, edx
    div     r8                          ; rax = percent
    jmp     pa_clamp
pa_full:
    mov     eax, 100
pa_clamp:
    cmp     eax, 100
    jbe     @F
    mov     eax, 100
@@:
    cmp     eax, dword ptr [g_prog_lastpct]
    jne     pa_paint                    ; the percent moved
    ; It did not - but at 4 GiB per percent a 155 GB job repaints every few
    ; seconds AT BEST, and an eta that does not tick reads as a hang.  Repaint
    ; on time as well: once a second, only while the rate line is showing
    ; (before the first measurable second there is nothing new to draw).
    cmp     qword ptr [g_prog_startms], 0
    je      pa_ret
    mov     rax, qword ptr [rbp-16]
    sub     rax, qword ptr [g_prog_lastms]
    cmp     rax, 1000
    jb      pa_ret
    mov     eax, dword ptr [g_prog_lastpct]
pa_paint:
    mov     dword ptr [g_prog_lastpct], eax
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [g_prog_lastms], rax
    call    prog_render
pa_ret:
    mov     eax, dword ptr [g_prog_abort]
    FRAME_EPILOG
    ret
progress_add endp

; =============================================================================
; prog_speed_x10 -> rax = cumulative average rate, tenths of a decimal MB/s.
;                   0 = not measurable yet (no byte, or under a second in).
;
; Cumulative, deliberately: a windowed rate is livelier and noisier, and an eta
; derived from a noisy rate swings by minutes on a disk hiccup.  The average
; starts at the first byte (see g_prog_startms), so the KDF's head does not
; drag it down.  MB/s = bytes / (1000 * ms); x10 = bytes / (100 * ms).
; =============================================================================
public prog_speed_x10
prog_speed_x10 proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_prog_startms], 0
    je      psx_none
    cmp     qword ptr [g_prog_done], 0
    je      psx_none
    WINCALL GetTickCount64
    sub     rax, qword ptr [g_prog_startms]
    cmp     rax, 1000
    jb      psx_none                    ; under a second: numbers are noise
    imul    rcx, rax, 100               ; 100 * elapsed_ms; no overflow this era
    mov     rax, qword ptr [g_prog_done]
    xor     edx, edx
    div     rcx
    FRAME_EPILOG
    ret
psx_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
prog_speed_x10 endp

; =============================================================================
; prog_eta_s -> rax = whole seconds remaining at the average rate, capped at
;               359999 (99:59:59); -1 = not computable yet; 0 = done.
;
; eta_ms = remaining * elapsed / done.  The product needs 128 bits for a large
; job (155 GB remaining x an hour of ms is past 2^64), which is exactly what
; MUL leaves in rdx:rax and DIV consumes - so the wide multiply costs nothing.
; DIV faults if the quotient cannot fit 64 bits (rdx >= divisor going in);
; that means an eta past anything displayable, so it is the CAP, not a fault.
; =============================================================================
public prog_eta_s
prog_eta_s proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_prog_startms], 0
    je      pes_none
    mov     rcx, qword ptr [g_prog_done]
    test    rcx, rcx
    jz      pes_none
    mov     rax, qword ptr [g_prog_total]
    sub     rax, rcx
    ja      pes_left
    xor     eax, eax                    ; done >= total: nothing remains
    FRAME_EPILOG
    ret
pes_left:
    mov     qword ptr [rbp-16], rax     ; remaining
    WINCALL GetTickCount64
    sub     rax, qword ptr [g_prog_startms]
    cmp     rax, 1000
    jb      pes_none
    mov     rcx, rax                    ; elapsed ms
    mov     rax, qword ptr [rbp-16]
    mul     rcx                         ; rdx:rax = remaining * elapsed_ms
    mov     rcx, qword ptr [g_prog_done]
    cmp     rdx, rcx
    jae     pes_cap                     ; quotient would not fit: beyond display
    div     rcx                         ; rax = eta ms
    add     rax, 999                    ; CEILING, not floor: a job with 300 MB
                                        ; left at half a gigabyte a second is
                                        ; sub-second, and "eta 0:00" on a bar
                                        ; that is still moving reads as a bug.
                                        ; 0:01 is never a lie for a running job.
    mov     rcx, 1000
    xor     edx, edx
    div     rcx                         ; rax = eta s
    mov     rcx, 359999
    cmp     rax, rcx
    jbe     @F
pes_cap:
    mov     rax, 359999                 ; 99:59:59 - the display's ceiling
@@:
    FRAME_EPILOG
    ret
pes_none:
    mov     rax, -1
    FRAME_EPILOG
    ret
prog_eta_s endp

; progress_abort() - request cooperative cancellation; the next progress_add
; in the streaming loop returns nonzero and the loop bails (deleting its temp).
; Raw leaf (no FRAME_PROLOG): callable from the GUI thread without touching the
; process-global software shadow stack that the worker thread is using.
public progress_abort
progress_abort proc
    mov     dword ptr [g_prog_abort], 1
    ret
progress_abort endp

; =============================================================================
public progress_done
progress_done proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_prog_active], 0
    je      pd_done
    mov     dword ptr [g_prog_active], 0
    mov     rcx, qword ptr [g_prog_h]
    lea     rdx, [pr_crlf]
    mov     r8d, 2
    lea     r9, [g_prog_written]
    mov     qword ptr [rsp+32], 0
    call    WriteFile                   ; move cursor off the bar line
pd_done:
    FRAME_EPILOG
    ret
progress_done endp

end
