; =============================================================================
; ripemd160.asm - ISO/IEC 10118-3 RIPEMD-160 (TrueCrypt & VeraCrypt legacy KDF)
; -----------------------------------------------------------------------------
;   rmd160_init   (rcx = ctx)
;   rmd160_update (rcx = ctx, rdx = data, r8 = len)
;   rmd160_final  (rcx = ctx, rdx = out20)
; =============================================================================

include macros.inc

extern secure_zero:proc

RMD160_CTX struct
    state   dd 5 dup (?)                ; H0..H4 (LE32)
    buflen  dd ?                        ; buffered bytes (0..63)
    total   dq ?                        ; total bytes processed
    buf     db 64 dup (?)               ; partial block
RMD160_CTX ends

R160_CTX_SIZE   equ sizeof RMD160_CTX

.const
r160_rl label byte
    db  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
    db  7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8
    db  3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12
    db  1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2
    db  4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13

r160_rr label byte
    db  5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12
    db  6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2
    db 15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13
    db  8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14
    db 12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11

r160_sl label byte
    db 11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8
    db  7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12
    db 11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5
    db 11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12
    db  9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6

r160_sr label byte
    db  8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6
    db  9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11
    db  9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5
    db 15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8
    db  8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11

.code

; =============================================================================
; rmd160_init(rcx = ctx)
; =============================================================================
LANDING_PAD
public rmd160_init
rmd160_init proc
    mov     dword ptr [rcx].RMD160_CTX.state,    067452301h
    mov     dword ptr [rcx].RMD160_CTX.state+4,  0EFCDAB89h
    mov     dword ptr [rcx].RMD160_CTX.state+8,  098BADCFEh
    mov     dword ptr [rcx].RMD160_CTX.state+12, 010325476h
    mov     dword ptr [rcx].RMD160_CTX.state+16, 0C3D2E1F0h
    mov     dword ptr [rcx].RMD160_CTX.buflen, 0
    mov     qword ptr [rcx].RMD160_CTX.total, 0
    ret
rmd160_init endp

; =============================================================================
; rmd160_compress(rcx = state_ptr, rdx = block64)
; =============================================================================
rmd160_compress proc frame
    FRAME_PROLOG 208
    ; [rbp-16..64] = r12..r15, rbx, rsi, rdi
    ; [rsp+32..95]  = X[0..15] (64B)
    ; [rsp+96..115] = left result a1..e1 (20B)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; state_ptr

    movdqu  xmm0, xmmword ptr [rdx]
    movdqu  xmm1, xmmword ptr [rdx+16]
    movdqu  xmm2, xmmword ptr [rdx+32]
    movdqu  xmm3, xmmword ptr [rdx+48]
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm1
    movdqu  xmmword ptr [rsp+64], xmm2
    movdqu  xmmword ptr [rsp+80], xmm3

    ; ---- Left line (80 steps): r8d=a, r9d=b, r10d=c, r11d=d, r12d=e ----------
    mov     r8d,  dword ptr [rsi]
    mov     r9d,  dword ptr [rsi+4]
    mov     r10d, dword ptr [rsi+8]
    mov     r11d, dword ptr [rsi+12]
    mov     r12d, dword ptr [rsi+16]

    lea     r13, [r160_rl]
    lea     r14, [r160_sl]
    xor     ebx, ebx
r1c_left:
    cmp     ebx, 16
    jb      r1c_lf0
    cmp     ebx, 32
    jb      r1c_lf1
    cmp     ebx, 48
    jb      r1c_lf2
    cmp     ebx, 64
    jb      r1c_lf3
    ; J(b,c,d) = b ^ (c | ~d) + 0xA953FD4E
    mov     eax, r11d
    not     eax
    or      eax, r10d
    xor     eax, r9d
    add     eax, 0A953FD4Eh
    jmp     r1c_lstep
r1c_lf0:
    ; F(b,c,d) = b ^ c ^ d + 0
    mov     eax, r9d
    xor     eax, r10d
    xor     eax, r11d
    jmp     r1c_lstep
r1c_lf1:
    ; G(b,c,d) = (b & c) | (~b & d) + 0x5A827999
    mov     eax, r9d
    and     eax, r10d
    mov     edx, r9d
    not     edx
    and     edx, r11d
    or      eax, edx
    add     eax, 05A827999h
    jmp     r1c_lstep
r1c_lf2:
    ; H(b,c,d) = (b | ~c) ^ d + 0x6ED9EBA1
    mov     eax, r10d
    not     eax
    or      eax, r9d
    xor     eax, r11d
    add     eax, 06ED9EBA1h
    jmp     r1c_lstep
r1c_lf3:
    ; I(b,c,d) = (b & d) | (c & ~d) + 0x8F1BBCDC
    mov     eax, r9d
    and     eax, r11d
    mov     edx, r11d
    not     edx
    and     edx, r10d
    or      eax, edx
    add     eax, 08F1BBCDCh

r1c_lstep:
    movzx   edi, byte ptr [r13+rbx]
    add     eax, r8d
    add     eax, dword ptr [rsp+32+rdi*4]
    movzx   ecx, byte ptr [r14+rbx]
    rol     eax, cl
    add     eax, r12d

    mov     r8d,  r12d
    mov     r12d, r11d
    rol     r10d, 10
    mov     r11d, r10d
    mov     r10d, r9d
    mov     r9d,  eax

    inc     ebx
    cmp     ebx, 80
    jb      r1c_left

    mov     dword ptr [rsp+96],  r8d        ; a1
    mov     dword ptr [rsp+100], r9d        ; b1
    mov     dword ptr [rsp+104], r10d       ; c1
    mov     dword ptr [rsp+108], r11d       ; d1
    mov     dword ptr [rsp+112], r12d       ; e1

    ; ---- Right line (80 steps): r8d=a2, r9d=b2, r10d=c2, r11d=d2, r12d=e2 ----
    mov     r8d,  dword ptr [rsi]
    mov     r9d,  dword ptr [rsi+4]
    mov     r10d, dword ptr [rsi+8]
    mov     r11d, dword ptr [rsi+12]
    mov     r12d, dword ptr [rsi+16]

    lea     r13, [r160_rr]
    lea     r14, [r160_sr]
    xor     ebx, ebx
r1c_right:
    cmp     ebx, 16
    jb      r1c_rf0
    cmp     ebx, 32
    jb      r1c_rf1
    cmp     ebx, 48
    jb      r1c_rf2
    cmp     ebx, 64
    jb      r1c_rf3
    ; F(b,c,d) = b ^ c ^ d + 0
    mov     eax, r9d
    xor     eax, r10d
    xor     eax, r11d
    jmp     r1c_rstep
r1c_rf0:
    ; J(b,c,d) = b ^ (c | ~d) + 0x50A28BE6
    mov     eax, r11d
    not     eax
    or      eax, r10d
    xor     eax, r9d
    add     eax, 050A28BE6h
    jmp     r1c_rstep
r1c_rf1:
    ; I(b,c,d) = (b & d) | (c & ~d) + 0x5C4DD124
    mov     eax, r9d
    and     eax, r11d
    mov     edx, r11d
    not     edx
    and     edx, r10d
    or      eax, edx
    add     eax, 05C4DD124h
    jmp     r1c_rstep
r1c_rf2:
    ; H(b,c,d) = (b | ~c) ^ d + 0x6D703EF3
    mov     eax, r10d
    not     eax
    or      eax, r9d
    xor     eax, r11d
    add     eax, 06D703EF3h
    jmp     r1c_rstep
r1c_rf3:
    ; G(b,c,d) = (b & c) | (~b & d) + 0x7A6D76E9
    mov     eax, r9d
    and     eax, r10d
    mov     edx, r9d
    not     edx
    and     edx, r11d
    or      eax, edx
    add     eax, 07A6D76E9h

r1c_rstep:
    movzx   edi, byte ptr [r13+rbx]
    add     eax, r8d
    add     eax, dword ptr [rsp+32+rdi*4]
    movzx   ecx, byte ptr [r14+rbx]
    rol     eax, cl
    add     eax, r12d

    mov     r8d,  r12d
    mov     r12d, r11d
    rol     r10d, 10
    mov     r11d, r10d
    mov     r10d, r9d
    mov     r9d,  eax

    inc     ebx
    cmp     ebx, 80
    jb      r1c_right

    ; Combine:
    ;   t        = state[1] + c1 + d2
    ;   state[1] = state[2] + d1 + e2
    ;   state[2] = state[3] + e1 + a2
    ;   state[3] = state[4] + a1 + b2
    ;   state[4] = state[0] + b1 + c2
    ;   state[0] = t
    mov     eax, dword ptr [rsi+4]
    add     eax, dword ptr [rsp+104]        ; + c1
    add     eax, r11d                       ; + d2

    mov     ecx, dword ptr [rsi+8]
    add     ecx, dword ptr [rsp+108]        ; + d1
    add     ecx, r12d                       ; + e2
    mov     dword ptr [rsi+4], ecx

    mov     ecx, dword ptr [rsi+12]
    add     ecx, dword ptr [rsp+112]        ; + e1
    add     ecx, r8d                        ; + a2
    mov     dword ptr [rsi+8], ecx

    mov     ecx, dword ptr [rsi+16]
    add     ecx, dword ptr [rsp+96]         ; + a1
    add     ecx, r9d                        ; + b2
    mov     dword ptr [rsi+12], ecx

    mov     ecx, dword ptr [rsi]
    add     ecx, dword ptr [rsp+100]        ; + b1
    add     ecx, r10d                       ; + c2
    mov     dword ptr [rsi+16], ecx

    mov     dword ptr [rsi], eax

    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm0
    movdqu  xmmword ptr [rsp+64], xmm0
    movdqu  xmmword ptr [rsp+80], xmm0
    movdqu  xmmword ptr [rsp+96], xmm0
    mov     dword ptr [rsp+112], 0

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
rmd160_compress endp

; =============================================================================
; rmd160_update(rcx = ctx, rdx = data, r8 = len)
; =============================================================================
LANDING_PAD
public rmd160_update
rmd160_update proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    test    r8, r8
    jz      r1u_done

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; data
    mov     rdi, r8                         ; len
    add     qword ptr [rbx].RMD160_CTX.total, rdi

    mov     ecx, dword ptr [rbx].RMD160_CTX.buflen
    test    ecx, ecx
    jz      r1u_blocks

    mov     eax, 64
    sub     eax, ecx
    cmp     rdi, rax
    jb      r1u_tail

    lea     r9, [rbx].RMD160_CTX.buf
    add     r9, rcx
    mov     ecx, eax
r1u_fill:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     ecx
    jnz     r1u_fill

    sub     rdi, rax
    mov     dword ptr [rbx].RMD160_CTX.buflen, 0
    lea     rcx, [rbx].RMD160_CTX.state
    lea     rdx, [rbx].RMD160_CTX.buf
    call    rmd160_compress

r1u_blocks:
    cmp     rdi, 64
    jb      r1u_tail
    lea     rcx, [rbx].RMD160_CTX.state
    mov     rdx, rsi
    call    rmd160_compress
    add     rsi, 64
    sub     rdi, 64
    jmp     r1u_blocks

r1u_tail:
    test    rdi, rdi
    jz      r1u_done
    mov     ecx, dword ptr [rbx].RMD160_CTX.buflen
    lea     r9, [rbx].RMD160_CTX.buf
    add     r9, rcx
    add     ecx, edi
    mov     dword ptr [rbx].RMD160_CTX.buflen, ecx
r1u_copy:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     rdi
    jnz     r1u_copy

r1u_done:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
rmd160_update endp

; =============================================================================
; rmd160_final(rcx = ctx, rdx = out20)
; =============================================================================
LANDING_PAD
public rmd160_final
rmd160_final proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; out20

    mov     rax, qword ptr [rbx].RMD160_CTX.total
    shl     rax, 3                          ; LE64 bit length
    mov     qword ptr [rbp-40], rax

    mov     edi, dword ptr [rbx].RMD160_CTX.buflen
    lea     r9, [rbx].RMD160_CTX.buf
    mov     byte ptr [r9+rdi], 080h
    inc     edi
    cmp     edi, 56
    jbe     r1f_pad_56

r1f_pad_64:
    cmp     edi, 64
    jae     r1f_comp_extra
    mov     byte ptr [r9+rdi], 0
    inc     edi
    jmp     r1f_pad_64

r1f_comp_extra:
    lea     rcx, [rbx].RMD160_CTX.state
    lea     rdx, [rbx].RMD160_CTX.buf
    call    rmd160_compress
    xor     edi, edi

r1f_pad_56:
    lea     r9, [rbx].RMD160_CTX.buf
r1f_zloop:
    cmp     edi, 56
    jae     r1f_store_len
    mov     byte ptr [r9+rdi], 0
    inc     edi
    jmp     r1f_zloop

r1f_store_len:
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r9+56], rax
    lea     rcx, [rbx].RMD160_CTX.state
    lea     rdx, [rbx].RMD160_CTX.buf
    call    rmd160_compress

    ; Emit 20 bytes (5 LE32 words)
    movdqu  xmm0, xmmword ptr [rbx].RMD160_CTX.state
    movdqu  xmmword ptr [rsi], xmm0
    mov     eax, dword ptr [rbx].RMD160_CTX.state+16
    mov     dword ptr [rsi+16], eax
    pxor    xmm0, xmm0
    mov     qword ptr [rbp-40], 0

    mov     rcx, rbx
    mov     rdx, R160_CTX_SIZE
    call    secure_zero

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
rmd160_final endp

end
