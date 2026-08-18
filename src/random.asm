; =============================================================================
; random.asm - CSPRNG
; -----------------------------------------------------------------------------
; rng_fill(rcx = buffer, edx = length) -> eax = 1 ok, 0 failure
;
; Primary source : BCryptGenRandom(NULL, buf, len, USE_SYSTEM_PREFERRED_RNG)
; Defense in depth: if the CPU supports RDSEED, every 8-byte lane is XOR-mixed
; with hardware entropy.  Mixing can only add entropy, never remove it.
; Policy        : if the OS RNG fails we FAIL - we never fall back to a
;                 weaker source for key material.
; =============================================================================

include macros.inc

extern BCryptGenRandom:proc

BCRYPT_USE_SYSTEM_PREFERRED_RNG equ 2

.code

public rng_fill
rng_fill proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] buffer, [rbp-32] length

    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx

    ; ---- primary: OS CSPRNG -------------------------------------------------
    ; BCryptGenRandom(hAlgorithm=NULL, pbBuffer, cbBuffer, dwFlags)
    WINCALL BCryptGenRandom, 0, rcx, edx, BCRYPT_USE_SYSTEM_PREFERRED_RNG
    test    eax, eax                    ; NTSTATUS: 0 = STATUS_SUCCESS
    jnz     rf_fail

    ; ---- defense in depth: XOR-mix RDSEED if available ----------------------
    test    dword ptr [g_cpu_features], CPUF_RDSEED
    jz      rf_ok
    mov     r10, qword ptr [rbp-24]     ; cursor
    mov     r11d, dword ptr [rbp-32]    ; remaining bytes
rf_mix_loop:
    cmp     r11d, 8
    jb      rf_ok                       ; tail < 8 bytes: already random, done
    mov     eax, 16                     ; retry budget per lane
rf_retry:
    rdseed  rcx
    jc      rf_have_seed
    dec     eax
    jnz     rf_retry
    jmp     rf_ok                       ; RDSEED starved: keep OS bytes, still ok
rf_have_seed:
    xor     qword ptr [r10], rcx
    add     r10, 8
    sub     r11d, 8
    jmp     rf_mix_loop

rf_ok:
    mov     eax, 1
    jmp     rf_done
rf_fail:
    xor     eax, eax
rf_done:
    FRAME_EPILOG
    ret
rng_fill endp

end
