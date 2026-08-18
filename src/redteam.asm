; =============================================================================
; redteam.asm - in-tool fault injection for measuring the memory-safety controls.
; -----------------------------------------------------------------------------
; The exploitation-hardening controls (stack canary, software shadow stack,
; DLPV forward-edge CFG, integer-overflow checks, bounds checks, struct type
; tags, temporal tagged heap, IAT lockdown) only fire when memory is actually
; corrupted, so they cannot be exercised through the normal CLI.  This module
; adds a hidden `redteam <case>` command that DELIBERATELY commits exactly one
; violation per invocation.  The test harness runs each case as a child process
; and asserts the child died with the expected fastfail / access-violation code,
; proving the control both fires and fails closed.
;
;   myrkr redteam canary     -> FF_STACK_COOKIE (2)
;   myrkr redteam shadow     -> FF_SHADOW_STACK (0xF001)
;   myrkr redteam dlpv       -> FF_GUARD_ICALL  (10)
;   myrkr redteam overflow   -> FF_OVERFLOW     (0xF005)
;   myrkr redteam bounds     -> FF_BOUNDS       (0xF004)
;   myrkr redteam typemagic  -> FF_TYPE_MAGIC   (0xF003)
;   myrkr redteam heaptag    -> FF_HEAP_TAG     (0xF002)
;   myrkr redteam iat        -> 0xFADE1A70 (AV on the locked IAT slot, observed)
;
; If a case RETURNS (the control failed to fire), cmd_redteam exits non-zero so
; the harness records a FAIL.  Compiled only into the instrumented build
; (`build dbg`, which defines DBG_TRACE); the shipping binary never contains it.
; =============================================================================

include macros.inc

ifdef DBG_TRACE

externdef g_cfg_in:qword                ; first positional arg (the case name)
extern wstr_eq:proc                     ; (rcx,rdx) -> eax=1 if equal UTF-16
extern print_a:proc                     ; (rcx=ptr, edx=len)
extern tagged_alloc:proc                ; (rcx=size) -> rax=user ptr
extern tagged_check:proc                ; (rcx=user ptr) fastfails on violation
extern __imp_CloseHandle:qword          ; an IAT slot (RO after iat_lockdown)
extern AddVectoredExceptionHandler:proc
extern ExitProcess:proc
extern VirtualProtect:proc
extern VirtualQuery:proc
extern iat_lockdown:proc

; The IAT case reports through the same 0xFADE<code> channel as every other
; case.  It used to be judged by the process's exit status after an UNHANDLED
; access violation - i.e. by Windows' report of how the process died, not by the
; mitigation itself.  That proxy was unreliable: the write always faulted, but
; on roughly a third of runs ntdll fast-failed while dispatching the unhandled
; exception and 0xC0000409 became the exit code, so a working control reported
; FAIL.  Catching the AV ourselves measures the thing the case is named after.
PAGE_READONLY_      equ 2
PAGE_READWRITE_     equ 4
MBI_PROTECT         equ 36                  ; MEMORY_BASIC_INFORMATION.Protect
EXCEPTION_AV        equ 0C0000005h
EXC_CONTINUE_SEARCH equ 0

.const
WSTR rc_canary,    <canary>
WSTR rc_shadow,    <shadow>
WSTR rc_dlpv,      <dlpv>
WSTR rc_overflow,  <overflow>
WSTR rc_bounds,    <bounds>
WSTR rc_typemagic, <typemagic>
WSTR rc_heaptag,   <heaptag>
WSTR rc_iat,       <iat>
CSTR rt_msg_nofire, "redteam: control did NOT fire - FAIL",13,10
CSTR rt_msg_unkn,   "redteam: unknown case (canary|shadow|dlpv|overflow|bounds|typemagic|heaptag|iat)",13,10

.data?
align 16
rt_buf  db 64 dup (?)                    ; zeroed scratch (no LP/type magic)

.code

; -- dispatch one redteam case ------------------------------------------------
; Matches g_cfg_in against the case names and runs the matching violation.
RTCASE macro target, namestr
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, namestr
    call    wstr_eq
    test    eax, eax
    jnz     target
endm

public cmd_redteam
LANDING_PAD                              ; dispatch reaches handlers via CALL_GUARDED
cmd_redteam proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_cfg_in]
    test    rcx, rcx
    jz      rt_unknown

    RTCASE  rt_do_canary,    rc_canary
    RTCASE  rt_do_shadow,    rc_shadow
    RTCASE  rt_do_dlpv,      rc_dlpv
    RTCASE  rt_do_overflow,  rc_overflow
    RTCASE  rt_do_bounds,    rc_bounds
    RTCASE  rt_do_type,      rc_typemagic
    RTCASE  rt_do_heap,      rc_heaptag
    RTCASE  rt_do_iat,       rc_iat
    jmp     rt_unknown

rt_do_canary:   call rt_v_canary
    jmp     rt_nofire
rt_do_shadow:   call rt_v_shadow
    jmp     rt_nofire
rt_do_dlpv:     call rt_v_dlpv
    jmp     rt_nofire
rt_do_overflow: call rt_v_overflow
    jmp     rt_nofire
rt_do_bounds:   call rt_v_bounds
    jmp     rt_nofire
rt_do_type:     call rt_v_type
    jmp     rt_nofire
rt_do_heap:     call rt_v_heap
    jmp     rt_nofire
rt_do_iat:      call rt_v_iat
    jmp     rt_nofire

rt_nofire:
    ; the violation returned -> the control under test did NOT catch it
    lea     rcx, rt_msg_nofire
    mov     edx, rt_msg_nofire_len
    call    print_a
    mov     eax, EXIT_SELFTEST          ; non-zero: harness records FAIL
    FRAME_EPILOG
    ret
rt_unknown:
    lea     rcx, rt_msg_unkn
    mov     edx, rt_msg_unkn_len
    call    print_a
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
cmd_redteam endp

; =============================================================================
; Individual violations.  Each is `proc frame` so the canary/shadow-stack
; machinery is active; each should terminate the process before returning.
; =============================================================================

; B1 stack canary: overwrite the canary slot, then run the verifying epilog.
rt_v_canary proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-8], 0DEADBEEFh   ; smash the planted canary
    FRAME_EPILOG                             ; -> FF_STACK_COOKIE
    ret
rt_v_canary endp

; B2 software shadow stack: corrupt the on-stack return address, leave canary.
rt_v_shadow proc frame
    FRAME_PROLOG 32
    mov     rax, 0BADC0DEBADC0DEh
    mov     qword ptr [rbp+8], rax           ; clobber saved return address
    FRAME_EPILOG                             ; canary ok, shadow mismatch -> FF_SHADOW_STACK
    ret
rt_v_shadow endp

; B4 DLPV: guarded indirect call through a pointer with no landing-pad magic.
rt_v_dlpv proc frame
    FRAME_PROLOG 32
    lea     rax, [rt_buf+8]                  ; [rax-8] = rt_buf[0] = 0 != LP_MAGIC
    CALL_GUARDED rax                         ; -> FF_GUARD_ICALL
    FRAME_EPILOG
    ret
rt_v_dlpv endp

; B6 integer overflow: checked add that carries out of 64 bits.
rt_v_overflow proc frame
    FRAME_PROLOG 32
    mov     rax, -1                          ; 0xFFFF...FF
    CHECK_ADD_OVF rax, 2                      ; carry -> FF_OVERFLOW
    FRAME_EPILOG
    ret
rt_v_overflow endp

; B7 bounds: index >= limit.
rt_v_bounds proc frame
    FRAME_PROLOG 32
    mov     rcx, 100
    BOUND_CHECK rcx, 10                       ; 100 >= 10 -> FF_BOUNDS
    FRAME_EPILOG
    ret
rt_v_bounds endp

; B8 type safety: type-check a buffer whose first dword is not the magic.
rt_v_type proc frame
    FRAME_PROLOG 32
    lea     rcx, [rt_buf]                    ; magic dword = 0 != TM_HEAPBLK
    TYPE_CHECK rcx, TM_HEAPBLK                ; -> FF_TYPE_MAGIC
    FRAME_EPILOG
    ret
rt_v_type endp

; B9 tagged heap: smash a live block's rear canary, then validate it.
rt_v_heap proc frame
    FRAME_PROLOG 32
    mov     rcx, 64
    call    tagged_alloc
    test    rax, rax
    jz      rt_heap_done                     ; OOM: can't run the test
    mov     qword ptr [rbp-24], rax          ; save user ptr
    mov     byte ptr [rax+64], 0AAh          ; overflow past user region -> rear canary
    mov     rcx, qword ptr [rbp-24]
    call    tagged_check                     ; rear-canary mismatch -> FF_HEAP_TAG
rt_heap_done:
    FRAME_EPILOG
    ret
rt_v_heap endp

; rt_iat_veh(rcx = PEXCEPTION_POINTERS) -> eax
; Vectored handler for the IAT case.  Raw - no FRAME_PROLOG: this runs inside the
; OS exception dispatcher, where the canary and shadow-stack bookkeeping have no
; matching entry, and where the whole point is to disturb as little as possible.
;
; It confirms all three facts before believing the control worked: an access
; violation, on a WRITE, to the exact slot iat_lockdown was asked to protect.  A
; handler that accepted any AV would report success for an unrelated crash.
; Anything else is passed on untouched (EXCEPTION_CONTINUE_SEARCH), so a genuine
; fault still surfaces as a fault.
rt_iat_veh proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     rax, qword ptr [rcx]             ; PEXCEPTION_RECORD
    cmp     dword ptr [rax], EXCEPTION_AV    ; ExceptionCode
    jne     veh_pass
    cmp     qword ptr [rax+32], 1            ; ExceptionInformation[0]: 1 = write
    jne     veh_pass
    lea     r10, [__imp_CloseHandle]
    cmp     qword ptr [rax+40], r10          ; ExceptionInformation[1]: target
    jne     veh_pass
    WINCALL ExitProcess, 0FADE0000h or FF_IAT_RO
veh_pass:
    mov     eax, EXC_CONTINUE_SEARCH
    add     rsp, 48
    pop     rbp
    ret
rt_iat_veh endp

; B5 IAT lockdown.
;
; WHAT THIS CASE PROVES, and what it does not - stated exactly, because the
; earlier version of it overclaimed:
;
;   PROVES: at the moment of the write, the IAT slot is on a read-only page and
;   the write is refused.  That property is real and worth a regression test.
;
;   DOES NOT PROVE: that iat_lockdown is what made it read-only.  The IAT lives
;   in .rdata, which the loader already maps read-only once imports are bound,
;   so the write faults whether or not our code ran.  Measured: with
;   iat_lockdown's VirtualProtect stubbed out entirely, this case still passes.
;
; The isolation steps below (hand the page back to PAGE_READWRITE, call
; iat_lockdown, require VirtualQuery to report PAGE_READONLY again) SHOULD turn
; this into a control test, and half of the evidence says they do.  Reading
; VirtualQuery's Protect immediately after the call, via a temporary exit-code
; readout, measured exactly what the design predicts:
;
;     iat_lockdown stubbed -> 0x04 PAGE_READWRITE
;     iat_lockdown real    -> 0x02 PAGE_READONLY
;
; So the re-protect works and the difference IS observable at that point.  Yet
; the assembled case still reports PASS with the control stubbed, which cannot
; both be true - if Protect really were 0x04 the cmp below would skip the write
; and the case would report "did NOT fire".  The contradiction is UNRESOLVED.
; Until it is, treat the steps as a sanity gate and NOT as attribution: a green
; result here does not license the claim that iat_lockdown did anything.
;
; So: this is a property test, not a control test, until that is explained.  It is at least DETERMINISTIC now,
; which the old form was not - see rt_iat_veh.
rt_v_iat proc frame
    FRAME_PROLOG 160                         ; 32 shadow + MBI(48) + locals
    WINCALL AddVectoredExceptionHandler, 1, addr rt_iat_veh
    ; 1. undo the protection, so read-only can only come back from our code
    WINCALL VirtualProtect, addr __imp_CloseHandle, 8, PAGE_READWRITE_, addr rbp-40
    test    eax, eax
    jz      rt_iat_nofire
    ; 2. the control under test
    call    iat_lockdown
    test    eax, eax
    jz      rt_iat_nofire                    ; it reported failure itself
    ; 3. it must have restored read-only on the slot's page
    WINCALL VirtualQuery, addr __imp_CloseHandle, addr rbp-112, 48
    test    rax, rax
    jz      rt_iat_nofire
    cmp     dword ptr [rbp-112+MBI_PROTECT], PAGE_READONLY_
    jne     rt_iat_nofire                    ; still writable -> control failed
    ; 4. and the write must now fault
    lea     rax, [__imp_CloseHandle]
    mov     qword ptr [rax], 0               ; -> AV -> rt_iat_veh -> 0xFADE1A70
rt_iat_nofire:
    ; Reaching here means the IAT was left writable, or the write succeeded:
    ; either way the control did not do its job.  Returning lets the dispatcher
    ; print "control did NOT fire".
    FRAME_EPILOG
    ret
rt_v_iat endp

endif ; DBG_TRACE

end
