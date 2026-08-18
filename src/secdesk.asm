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
extern CloseDesktop:proc
extern SetThreadDesktop:proc
extern GetThreadDesktop:proc
extern OpenInputDesktop:proc
extern SwitchDesktop:proc
extern GetCurrentThreadId:proc
ifdef DBG_TRACE
extern CreateThread:proc
extern WaitForSingleObject:proc
extern CloseHandle:proc
extern Sleep:proc
extern print_a:proc
endif

GENERIC_ALL         equ 10000000h

.const
; A fixed name is fine: CreateDesktopW opens the existing one if a desktop of
; this name is already present in the window station, and only this process ever
; switches to it.
WSTR wsd_name, <Myrkr-Secure>

.data?
g_sd_prev_input dq ?                ; input desktop that was active before us
g_sd_prev_thread dq ?               ; calling thread's desktop before us

.code

ifdef DBG_TRACE
prn_sd macro msg
    lea     rcx, [msg]
    mov     edx, msg&_len
    call    print_a
endm
endif

; =============================================================================
; secdesk_open -> rax = HDESK, or 0 if a private desktop cannot be created.
; The caller decides what a failure means; nothing here falls back silently,
; because a silent fallback to the interactive desktop is the whole control
; quietly turning itself off.
; =============================================================================
public secdesk_open
secdesk_open proc frame
    FRAME_PROLOG 64
    ; CreateDesktopW(name, NULL device, NULL devmode, flags 0, GENERIC_ALL, NULL sa)
    ;
    ; flags is 0 rather than DF_ALLOWOTHERACCOUNTHOOK (1): that flag would let
    ; processes of OTHER accounts install hooks on this desktop, which is the
    ; opposite of the point.
    ;
    ; The security attributes are NULL, so the desktop gets the default DACL for
    ; this token.  That is deliberate and not an oversight - see the header: an
    ; ACL cannot separate us from a same-user attacker, so there is nothing
    ; useful to write here, and inventing one would suggest a boundary that does
    ; not exist.
    WINCALL CreateDesktopW, addr wsd_name, 0, 0, 0, GENERIC_ALL, 0
    FRAME_EPILOG
    ret
secdesk_open endp

; =============================================================================
; secdesk_enter(rcx = HDESK) -> eax = 1 ok, 0 failed.
;
; MUST be called on the thread that will create the prompt window, and before it
; creates any window: SetThreadDesktop fails once a thread owns one.  Saves both
; the thread's previous desktop and the previously active INPUT desktop so
; secdesk_leave can put the user back where they were.
; =============================================================================
public secdesk_enter
secdesk_enter proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    ; remember what was on screen before we take over
    WINCALL OpenInputDesktop, 0, 0, GENERIC_ALL
    mov     qword ptr [g_sd_prev_input], rax
    WINCALL GetCurrentThreadId
    WINCALL GetThreadDesktop, eax
    mov     qword ptr [g_sd_prev_thread], rax
    ; attach this thread, then put the private desktop on screen
    WINCALL SetThreadDesktop, qword ptr [rbp-24]
    test    eax, eax
    jz      sde_fail
    WINCALL SwitchDesktop, qword ptr [rbp-24]
    test    eax, eax
    jz      sde_unset
    mov     eax, 1
    jmp     sde_done
sde_unset:
    ; the switch failed but the thread is attached; put it back so the caller is
    ; not left on a desktop it cannot draw on
    WINCALL SetThreadDesktop, qword ptr [g_sd_prev_thread]
sde_fail:
    xor     eax, eax
sde_done:
    FRAME_EPILOG
    ret
secdesk_enter endp

; =============================================================================
; secdesk_leave - put the user back on the desktop they came from.
; Safe to call whether or not secdesk_enter succeeded.
; =============================================================================
public secdesk_leave
secdesk_leave proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_sd_prev_input], 0
    je      sdl_thread
    WINCALL SwitchDesktop, qword ptr [g_sd_prev_input]
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
    mov     rcx, qword ptr [g_sd_test_h]
    call    secdesk_enter
    test    eax, eax
    jz      sdt_fail
    WINCALL Sleep, 1000
    call    secdesk_leave
    mov     dword ptr [g_sd_test_rc], 1
sdt_fail:
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
