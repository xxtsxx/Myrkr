; =============================================================================
; secdesk.asm - private ("secure") desktop primitives for password entry
; -----------------------------------------------------------------------------
; The password is typed on a desktop of our own rather than the interactive one,
; so that code running on the user's normal desktop cannot observe or drive it.
;
; WHAT THIS DEFENDS, precisely - the boundary is narrower than "secure desktop"
; sounds and is worth stating where the code is:
;
;   * Window discovery and message injection.  FindWindow, EnumWindows,
;     SendMessage and friends are DESKTOP-SCOPED: a thread only sees windows on
;     its own desktop.  A script on the interactive desktop cannot locate the
;     prompt, cannot WM_SETTEXT a password into it, and cannot post a click to
;     its OK button.  That is the property this exists for - it is precisely how
;     the GUI could be driven headlessly before.
;   * Keyboard and screen hooks.  SetWindowsHookEx is likewise desktop-scoped,
;     so a keylogger installed on the interactive desktop sees nothing typed
;     here.  The same goes for screen capture and shared-screen meetings.
;
; WHAT IT DOES NOT DEFEND:
;
;   * A same-user attacker who can call SetThreadDesktop.  The desktop is owned
;     by this user, so any DACL that lets US use it lets THEM use it - a
;     restrictive ACL is not available here.  UAC's desktop is protected because
;     it belongs to Winlogon/SYSTEM, a context a user-mode process cannot claim.
;     What raises the cost is the environment: reaching another desktop needs
;     direct API calls, which a WDAC policy with Constrained Language Mode does
;     not let a script host make.  The control is real in that estate and weaker
;     outside it - see manifest section 14.
;   * Anything with kernel or administrator privilege.
;
; A window must be created on the desktop its thread is attached to, and
; SetThreadDesktop fails for a thread that already owns windows or hooks - so
; the prompt runs on a dedicated thread that attaches itself before creating
; anything.  The GUI's own thread never leaves the interactive desktop.
; =============================================================================

include macros.inc

extern CreateDesktopW:proc
extern OpenDesktopW:proc
extern CloseDesktop:proc
extern SetThreadDesktop:proc
extern GetThreadDesktop:proc
extern OpenInputDesktop:proc
extern SwitchDesktop:proc
extern SetUserObjectSecurity:proc
extern CreateWindowExW:proc
extern DestroyWindow:proc
extern GetCurrentThreadId:proc
extern CreateThread:proc
extern WaitForSingleObject:proc
extern Sleep:proc
extern OpenProcessToken:proc
extern GetTokenInformation:proc
extern InitializeAcl:proc
extern AddAccessAllowedAce:proc
extern InitializeSecurityDescriptor:proc
extern SetSecurityDescriptorDacl:proc
extern SetSecurityDescriptorControl:proc
extern CloseHandle:proc
extern rng_fill:proc
extern secure_zero:proc
extern sstk_thread_init:proc
extern sstk_thread_free:proc
ifdef DBG_TRACE
extern print_a:proc
endif

GENERIC_ALL             equ 10000000h
DESKTOP_MAXALLOWED_     equ 02000000h   ; MAXIMUM_ALLOWED
DESKTOP_CREATE_ACCESS_  equ 000601FFh   ; READ_CONTROL | WRITE_DAC | DESKTOP_ALL(01FFh)
DESKTOP_USER_STRIPPED_  equ 00020146h   ; READ_CONTROL | SWITCH | ENUM | CREATEMENU | CREATEWINDOW
                                        ; (strips READOBJECTS, WRITEOBJECTS, HOOKCONTROL, JOURNAL*)
ACL_REVISION_           equ 2
SD_REVISION_            equ 1
SE_DACL_PROTECTED_      equ 1000h
SECDESK_TRIES_          equ 6
SECDESK_WAIT_           equ 40          ; ms between SwitchDesktop retries

.const
align 4
sd_dacl_si      dd 4                                                ; DACL_SECURITY_INFORMATION (by pointer)
sid_local_sys   db 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0              ; S-1-5-18 (NT AUTHORITY\SYSTEM)
sid_dwm_grp     db 1, 2, 0, 0, 0, 0, 0, 5, 90, 0, 0, 0, 0, 0, 0, 0  ; S-1-5-90-0 (Window Manager\DWM-*)
sid_umfd_grp    db 1, 2, 0, 0, 0, 0, 0, 5, 96, 0, 0, 0, 0, 0, 0, 0  ; S-1-5-96-0 (Font Driver Host\UMFD-*)
sd_hex          db "0123456789abcdef"
WSTR w_desk_def,  <Default>
WSTR w_sd_static, <STATIC>
even
w_sd_empty      dw 0

.data?
public g_sd_prev_input                  ; hardening.asm's crash containment reads it
align 8
g_sd_prev_input  dq ?                   ; input desktop that was active before us
g_sd_prev_thread dq ?                   ; calling thread's desktop before us
g_sd_kat_h       dq ?                   ; secdesk_selftest worker target HDESK
g_sd_tokbuf      dq 16 dup (?)          ; TOKEN_USER scratch (128 bytes, 8-aligned)
g_sd_acl         dq 32 dup (?)          ; explicit protected ACL (256 bytes, 8-aligned)
g_sd_sd          dq 5 dup (?)           ; SECURITY_DESCRIPTOR (40 bytes; MUST be 8-aligned
                                        ;   or NtSetSecurityObject fails with ERROR_NOACCESS)
g_sd_kat_ok      dd ?                   ; secdesk_selftest worker result
align 2
g_sd_name        dw 40 dup (?)          ; "Myrkr-" + 32 hex chars + NUL

.code

ifdef DBG_TRACE
prn_sd macro msg
    lea     rcx, [msg]
    mov     edx, msg&_len
    call    print_a
endm
endif

; =============================================================================
; secdesk_open -> rax = HDESK, or 0 if a private desktop cannot be created and
; locked down.
;
; Hardening (ported from Vordr VDR-12 / VDR2-12):
;   1. Per-invocation 128-bit CSPRNG name ("Myrkr-<32 hex>") prevents pre-squat.
;   2. Opens with DESKTOP_CREATE_ACCESS_ (preserving full handle rights for our
;      own process), then applies an explicit SE_DACL_PROTECTED DACL granting
;      SYSTEM GENERIC_ALL and TokenUser ONLY 0x00020146 — stripping
;      DESKTOP_HOOKCONTROL, DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS, and
;      DESKTOP_JOURNALRECORD/PLAYBACK so a peer process running as the same UID
;      cannot OpenDesktopW to hook keystrokes or read/inject window messages
;      without first calling SetUserObjectSecurity(WRITE_DAC).
;   3. Fails closed (closes desktop and returns 0) if RNG or DACL setup fails.
; =============================================================================
public secdesk_open
secdesk_open proc frame
    FRAME_PROLOG 112
    ; [rbp-24]=hDesk [rbp-32]=hToken [rbp-40]=cbRet/cbSid [rbp-64..rbp-49]=rand(16)

    lea     rcx, [rbp-64]
    mov     edx, 16
    call    rng_fill
    test    eax, eax
    jz      sdo_fail

    ; Format "Myrkr-" + 32 lowercase hex wide chars into g_sd_name
    lea     r10, [g_sd_name]
    mov     word ptr [r10+0],  'M'
    mov     word ptr [r10+2],  'y'
    mov     word ptr [r10+4],  'r'
    mov     word ptr [r10+6],  'k'
    mov     word ptr [r10+8],  'r'
    mov     word ptr [r10+10], '-'
    lea     r11, [r10+12]
    lea     r8,  [sd_hex]
    xor     ecx, ecx
sdo_hex:
    movzx   eax, byte ptr [rbp+rcx-64]
    mov     edx, eax
    shr     eax, 4
    and     edx, 0Fh
    movzx   eax, byte ptr [r8+rax]
    mov     word ptr [r11], ax
    movzx   edx, byte ptr [r8+rdx]
    mov     word ptr [r11+2], dx
    add     r11, 4
    inc     ecx
    cmp     ecx, 16
    jb      sdo_hex
    mov     word ptr [r11], 0

    lea     rcx, [rbp-64]
    mov     edx, 16
    call    secure_zero

    WINCALL CreateDesktopW, addr g_sd_name, 0, 0, 0, DESKTOP_CREATE_ACCESS_, 0
    test    rax, rax
    jz      sdo_fail
    mov     qword ptr [rbp-24], rax

    ; Query TokenUser SID
    mov     qword ptr [rbp-32], 0
    WINCALL OpenProcessToken, -1, 8, addr rbp-32    ; GetCurrentProcess()=-1, TOKEN_QUERY=8
    test    eax, eax
    jz      sdo_close_fail
    mov     dword ptr [rbp-40], 0
    WINCALL GetTokenInformation, qword ptr [rbp-32], 1, addr g_sd_tokbuf, 128, addr rbp-40
    mov     dword ptr [rbp-44], eax
    WINCALL CloseHandle, qword ptr [rbp-32]
    cmp     dword ptr [rbp-44], 0
    je      sdo_close_fail

    ; Build protected explicit DACL:
    ;   - TokenUser stripped (0x00020146: no HOOKCONTROL / READOBJECTS / WRITEOBJECTS / JOURNAL*)
    ;   - LocalSystem (S-1-5-18): GENERIC_ALL
    ;   - Window Manager group (S-1-5-90-0): GENERIC_ALL (DWM desktop composition)
    ;   - Font Driver Host group (S-1-5-96-0): GENERIC_ALL (UMFD font rasterization)
    WINCALL InitializeAcl, addr g_sd_acl, 256, ACL_REVISION_
    test    eax, eax
    jz      sdo_close_fail
    mov     r9, qword ptr [g_sd_tokbuf]             ; TOKEN_USER.User.Sid
    test    r9, r9
    jz      sdo_close_fail
    WINCALL AddAccessAllowedAce, addr g_sd_acl, ACL_REVISION_, DESKTOP_USER_STRIPPED_, r9
    test    eax, eax
    jz      sdo_close_fail
    WINCALL AddAccessAllowedAce, addr g_sd_acl, ACL_REVISION_, GENERIC_ALL, addr sid_local_sys
    test    eax, eax
    jz      sdo_close_fail
    WINCALL AddAccessAllowedAce, addr g_sd_acl, ACL_REVISION_, GENERIC_ALL, addr sid_dwm_grp
    test    eax, eax
    jz      sdo_close_fail
    WINCALL AddAccessAllowedAce, addr g_sd_acl, ACL_REVISION_, GENERIC_ALL, addr sid_umfd_grp
    test    eax, eax
    jz      sdo_close_fail

    WINCALL InitializeSecurityDescriptor, addr g_sd_sd, SD_REVISION_
    test    eax, eax
    jz      sdo_close_fail
    WINCALL SetSecurityDescriptorDacl, addr g_sd_sd, 1, addr g_sd_acl, 0
    test    eax, eax
    jz      sdo_close_fail
    WINCALL SetSecurityDescriptorControl, addr g_sd_sd, SE_DACL_PROTECTED_, SE_DACL_PROTECTED_
    test    eax, eax
    jz      sdo_close_fail

    WINCALL SetUserObjectSecurity, qword ptr [rbp-24], addr sd_dacl_si, addr g_sd_sd
    test    eax, eax
    jz      sdo_close_fail

    mov     rax, qword ptr [rbp-24]
    jmp     sdo_done

sdo_close_fail:
    WINCALL CloseDesktop, qword ptr [rbp-24]
sdo_fail:
    xor     eax, eax
sdo_done:
    FRAME_EPILOG
    ret
secdesk_open endp

; =============================================================================
; secdesk_enter(rcx = HDESK) -> eax = 1 ok, 0 failed.
;
; MUST be called on the thread that will create the prompt window, and before it
; creates any window: SetThreadDesktop fails once a thread owns one.  Saves both
; the thread's previous desktop and the previously active INPUT desktop so
; secdesk_leave can put the user back where they were.  Never switches away if
; OpenInputDesktop returned 0 (no handle to return to).
; =============================================================================
public secdesk_enter
secdesk_enter proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    ; remember what was on screen before we take over (MAXIMUM_ALLOWED so an
    ; elevated/filtered token lacking WRITE_DAC on Default still opens cleanly)
    WINCALL OpenInputDesktop, 0, 0, DESKTOP_MAXALLOWED_
    mov     qword ptr [g_sd_prev_input], rax
    test    rax, rax
    jz      sde_fail
    WINCALL GetCurrentThreadId
    WINCALL GetThreadDesktop, eax
    mov     qword ptr [g_sd_prev_thread], rax
    ; attach this thread, then put the private desktop on screen (with retry)
    WINCALL SetThreadDesktop, qword ptr [rbp-24]
    test    eax, eax
    jz      sde_close_prev
    mov     dword ptr [rbp-32], 0
sde_sw_loop:
    WINCALL SwitchDesktop, qword ptr [rbp-24]
    test    eax, eax
    jnz     sde_ok
    inc     dword ptr [rbp-32]
    cmp     dword ptr [rbp-32], SECDESK_TRIES_
    jae     sde_unset
    WINCALL Sleep, SECDESK_WAIT_
    jmp     sde_sw_loop
sde_ok:
    mov     eax, 1
    jmp     sde_done
sde_unset:
    ; the switch failed after retries; detach and close saved input desktop
    WINCALL SetThreadDesktop, qword ptr [g_sd_prev_thread]
    mov     qword ptr [g_sd_prev_thread], 0
sde_close_prev:
    WINCALL CloseDesktop, qword ptr [g_sd_prev_input]
    mov     qword ptr [g_sd_prev_input], 0
sde_fail:
    xor     eax, eax
sde_done:
    FRAME_EPILOG
    ret
secdesk_enter endp

; =============================================================================
; secdesk_leave - put the user back on the desktop they came from.
; Retries transient SwitchDesktop contention and falls back to "Default" by name
; if the saved handle cannot be switched to, matching Vordr's secdesk_restore.
; =============================================================================
public secdesk_leave
secdesk_leave proc frame
    FRAME_PROLOG 80
    mov     dword ptr [rbp-24], 0
sdl_sw_loop:
    cmp     qword ptr [g_sd_prev_input], 0
    je      sdl_thread
    WINCALL SwitchDesktop, qword ptr [g_sd_prev_input]
    test    eax, eax
    jnz     sdl_close_prev
    inc     dword ptr [rbp-24]
    cmp     dword ptr [rbp-24], SECDESK_TRIES_
    jae     sdl_byname
    WINCALL Sleep, SECDESK_WAIT_
    jmp     sdl_sw_loop
sdl_byname:
    WINCALL OpenDesktopW, addr w_desk_def, 0, 0, DESKTOP_MAXALLOWED_
    test    rax, rax
    jz      sdl_close_prev
    mov     qword ptr [rbp-32], rax
    WINCALL SwitchDesktop, rax
    WINCALL CloseDesktop, qword ptr [rbp-32]
sdl_close_prev:
    WINCALL CloseDesktop, qword ptr [g_sd_prev_input]
    mov     qword ptr [g_sd_prev_input], 0
sdl_thread:
    cmp     qword ptr [g_sd_prev_thread], 0
    je      sdl_done
    WINCALL SetThreadDesktop, qword ptr [g_sd_prev_thread]
    mov     qword ptr [g_sd_prev_thread], 0
sdl_done:
    FRAME_EPILOG
    ret
secdesk_leave endp

; =============================================================================
; secdesk_close(rcx = HDESK) - release the private desktop.
; The desktop object dies once no thread is attached and no window remains on
; it, so this must follow secdesk_leave and the prompt window's destruction.
; =============================================================================
public secdesk_close
secdesk_close proc frame
    FRAME_PROLOG 48
    test    rcx, rcx
    jz      sdc_done
    WINCALL CloseDesktop, rcx
sdc_done:
    FRAME_EPILOG
    ret
secdesk_close endp

; =============================================================================
; secdesk_selftest -> eax = 1 pass, 0 fail.
; Live non-flickering KAT run by `myrkr selftest`:
;   - Skips gracefully (returns 1) in non-interactive service sessions where
;     OpenInputDesktop returns 0.
;   - Calls secdesk_open (CreateDesktopW + SetUserObjectSecurity protected DACL).
;   - Verifies OpenDesktopW(g_sd_name, DESKTOP_HOOKCONTROL=8) and
;     OpenDesktopW(g_sd_name, DESKTOP_READOBJECTS=1) are both denied (0).
;   - Attaches a fresh worker thread via SetThreadDesktop (without SwitchDesktop,
;     so zero screen flash), creates and destroys a window on the private desktop,
;     detaches, and closes the desktop.
; =============================================================================
sd_kat_thread proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 128
    mov     dword ptr [g_sd_kat_ok], 0
    call    sstk_thread_init
    WINCALL GetCurrentThreadId
    WINCALL GetThreadDesktop, eax
    mov     qword ptr [rbp-16], rax
    WINCALL SetThreadDesktop, qword ptr [g_sd_kat_h]
    test    eax, eax
    jz      skt_done
    WINCALL CreateWindowExW, 0, addr w_sd_static, addr w_sd_empty, 0, 0, 0, 8, 8, 0, 0, 0, 0
    test    rax, rax
    jz      skt_restore
    WINCALL DestroyWindow, rax
    mov     dword ptr [g_sd_kat_ok], 1
skt_restore:
    cmp     qword ptr [rbp-16], 0
    je      skt_done
    WINCALL SetThreadDesktop, qword ptr [rbp-16]
skt_done:
    call    sstk_thread_free
    xor     eax, eax
    mov     rsp, rbp
    pop     rbp
    ret
sd_kat_thread endp

public secdesk_selftest
secdesk_selftest proc frame
    FRAME_PROLOG 80
    WINCALL OpenInputDesktop, 0, 0, DESKTOP_MAXALLOWED_
    test    rax, rax
    jz      sds_skip                        ; headless service session -> skip
    WINCALL CloseDesktop, rax

    call    secdesk_open
    test    rax, rax
    jz      sds_fail
    mov     qword ptr [g_sd_kat_h], rax

    ; Peer hook / object-read probes by desktop name MUST be refused by our DACL
    WINCALL OpenDesktopW, addr g_sd_name, 0, 0, 8       ; DESKTOP_HOOKCONTROL
    test    rax, rax
    jnz     sds_leaked_desk
    WINCALL OpenDesktopW, addr g_sd_name, 0, 0, 1       ; DESKTOP_READOBJECTS
    test    rax, rax
    jnz     sds_leaked_desk

    WINCALL CreateThread, 0, 0, addr sd_kat_thread, 0, 0, 0
    test    rax, rax
    jz      sds_close_fail
    mov     qword ptr [rbp-24], rax
    WINCALL WaitForSingleObject, rax, 5000
    WINCALL CloseHandle, qword ptr [rbp-24]

    mov     rcx, qword ptr [g_sd_kat_h]
    mov     qword ptr [g_sd_kat_h], 0
    call    secdesk_close
    mov     eax, dword ptr [g_sd_kat_ok]
    jmp     sds_ret

sds_leaked_desk:
    WINCALL CloseDesktop, rax
sds_close_fail:
    mov     rcx, qword ptr [g_sd_kat_h]
    mov     qword ptr [g_sd_kat_h], 0
    call    secdesk_close
sds_fail:
    xor     eax, eax
    jmp     sds_ret
sds_skip:
    mov     eax, 1
sds_ret:
    FRAME_EPILOG
    ret
secdesk_selftest endp

ifdef DBG_TRACE
; =============================================================================
; `myrkr secdesk` (debug builds only) - smoke-test the primitives above.
;
; This is the only consumer until the prompt window lands, and it exists because
; the failure modes here are environmental, not logical: SetThreadDesktop refuses
; a thread that owns windows, SwitchDesktop refuses without the right access, and
; neither shows up at build time.  Exercising the whole cycle on a worker thread
; is the same shape the real prompt will use.
;
; It DOES switch the visible desktop for about a second - the screen goes to an
; empty desktop and comes back.  That is the feature working.
; =============================================================================
.const
CSTR m_sd_open,   "secdesk: CreateDesktopW ok",13,10
CSTR m_sd_noopen, "secdesk: FAILED to create the private desktop",13,10
CSTR m_sd_enter,  "secdesk: thread attached + switched ok (1s)",13,10
CSTR m_sd_noent,  "secdesk: FAILED to attach/switch",13,10
CSTR m_sd_back,   "secdesk: returned to the original desktop",13,10

.data?
g_sd_test_h  dq ?                   ; desktop under test
g_sd_test_rc dd ?                   ; worker result

.code
; worker: attach to the private desktop, show it briefly, come back.
sd_test_thread proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     dword ptr [g_sd_test_rc], 0
    call    sstk_thread_init
    test    eax, eax
    jz      sdt_out
    mov     rcx, qword ptr [g_sd_test_h]
    call    secdesk_enter
    test    eax, eax
    jz      sdt_fail
    WINCALL Sleep, 1000
    call    secdesk_leave
    mov     dword ptr [g_sd_test_rc], 1
sdt_fail:
    call    sstk_thread_free
sdt_out:
    xor     eax, eax
    add     rsp, 48
    pop     rbp
    ret
sd_test_thread endp

LANDING_PAD                              ; dispatch reaches handlers via CALL_GUARDED
public cmd_secdesk
cmd_secdesk proc frame
    FRAME_PROLOG 64
    call    secdesk_open
    mov     qword ptr [g_sd_test_h], rax
    test    rax, rax
    jnz     @F
    prn_sd  m_sd_noopen
    mov     eax, EXIT_IO
    jmp     sdcmd_done
@@:
    prn_sd  m_sd_open
    ; the switch must happen on a thread that owns no windows
    WINCALL CreateThread, 0, 0, addr sd_test_thread, 0, 0, 0
    mov     qword ptr [rbp-24], rax
    test    rax, rax
    jz      sdcmd_ioerr
    WINCALL WaitForSingleObject, qword ptr [rbp-24], 10000
    WINCALL CloseHandle, qword ptr [rbp-24]
    cmp     dword ptr [g_sd_test_rc], 0
    je      sdcmd_noent
    prn_sd  m_sd_enter
    prn_sd  m_sd_back
    mov     rcx, qword ptr [g_sd_test_h]
    call    secdesk_close
    xor     eax, eax
    jmp     sdcmd_done
sdcmd_noent:
    prn_sd  m_sd_noent
sdcmd_ioerr:
    mov     rcx, qword ptr [g_sd_test_h]
    call    secdesk_close
    mov     eax, EXIT_IO
sdcmd_done:
    FRAME_EPILOG
    ret
cmd_secdesk endp
endif ; DBG_TRACE

end
