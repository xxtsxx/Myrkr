; =============================================================================
; blake2s.asm - RFC 7693 BLAKE2s-256 (unkeyed 32-byte digest for VeraCrypt KDF)
; -----------------------------------------------------------------------------
;   blake2s_init   (rcx = ctx)
;   blake2s_update (rcx = ctx, rdx = data, r8 = len)
;   blake2s_final  (rcx = ctx, rdx = out32)
; =============================================================================

include macros.inc

extern secure_zero:proc

BLAKE2S_CTX struct
    h       dd 8 dup (?)                ; chaining state
    t       dd 2 dup (?)                ; 64-bit byte counter
    f       dd 2 dup (?)                ; finalization flags
    buf     db 64 dup (?)               ; block buffer
    buflen  dd ?                        ; buffered bytes (0..64)
    pad     dd ?
BLAKE2S_CTX ends

B2S_CTX_SIZE    equ sizeof BLAKE2S_CTX

.const
align 4
b2s_iv label dword
    dd 06A09E667h, 0BB67AE85h, 03C6EF372h, 0A54FF53Ah
    dd 0510E527Fh, 09B05688Ch, 01F83D9ABh, 05BE0CD19h

b2s_sigma label byte
    db  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
    db 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3
    db 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4
    db  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8
    db  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13
    db  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9
    db 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11
    db 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10
    db  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5
    db 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0

.code

; Quarter-round macro on v[0..15] at [rsp+32] using m[0..15] at [rsp+96],
; sigma row pointer in r9. Uses volatile regs eax, ecx, edx, r8d, r10d, r11d.
B2S_G macro a, b, c, d, sx, sy
    movzx   r10d, byte ptr [r9+sx]
    movzx   r11d, byte ptr [r9+sy]
    mov     eax, dword ptr [rsp+32+a*4]
    mov     ecx, dword ptr [rsp+32+b*4]
    mov     edx, dword ptr [rsp+32+c*4]
    mov     r8d, dword ptr [rsp+32+d*4]

    add     eax, ecx
    add     eax, dword ptr [rsp+96+r10*4]
    xor     r8d, eax
    ror     r8d, 16
    add     edx, r8d
    xor     ecx, edx
    ror     ecx, 12

    add     eax, ecx
    add     eax, dword ptr [rsp+96+r11*4]
    xor     r8d, eax
    ror     r8d, 8
    add     edx, r8d
    xor     ecx, edx
    ror     ecx, 7

    mov     dword ptr [rsp+32+a*4], eax
    mov     dword ptr [rsp+32+b*4], ecx
    mov     dword ptr [rsp+32+c*4], edx
    mov     dword ptr [rsp+32+d*4], r8d
endm

; =============================================================================
; blake2s_init(rcx = ctx)
; =============================================================================
LANDING_PAD
public blake2s_init
blake2s_init proc
    movdqu  xmm0, xmmword ptr [b2s_iv]
    movdqu  xmm1, xmmword ptr [b2s_iv+16]
    movdqu  xmmword ptr [rcx].BLAKE2S_CTX.h, xmm0
    movdqu  xmmword ptr [rcx].BLAKE2S_CTX.h+16, xmm1
    ; param block P[0] = 0x01010020 (fanout=1, depth=1, digest_length=32)
    xor     dword ptr [rcx].BLAKE2S_CTX.h, 001010020h
    mov     qword ptr [rcx].BLAKE2S_CTX.t, 0
    mov     qword ptr [rcx].BLAKE2S_CTX.f, 0
    mov     dword ptr [rcx].BLAKE2S_CTX.buflen, 0
    mov     dword ptr [rcx].BLAKE2S_CTX.pad, 0
    ret
blake2s_init endp

; =============================================================================
; blake2s_compress(rcx = ctx, rdx = block64)
; =============================================================================
blake2s_compress proc frame
    FRAME_PROLOG 240
    ; [rbp-16] = rbx, [rbp-24] = rsi
    ; [rsp+32..95]  = v[0..15]
    ; [rsp+96..159] = m[0..15]
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi

    mov     rbx, rcx                        ; ctx

    ; Copy m[0..15]
    movdqu  xmm0, xmmword ptr [rdx]
    movdqu  xmm1, xmmword ptr [rdx+16]
    movdqu  xmm2, xmmword ptr [rdx+32]
    movdqu  xmm3, xmmword ptr [rdx+48]
    movdqu  xmmword ptr [rsp+96], xmm0
    movdqu  xmmword ptr [rsp+112], xmm1
    movdqu  xmmword ptr [rsp+128], xmm2
    movdqu  xmmword ptr [rsp+144], xmm3

    ; Initialize v[0..7] = h[0..7], v[8..15] = IV[0..7] ^ (0,0,0,0,t0,t1,f0,f1)
    movdqu  xmm0, xmmword ptr [rbx].BLAKE2S_CTX.h
    movdqu  xmm1, xmmword ptr [rbx].BLAKE2S_CTX.h+16
    movdqu  xmm2, xmmword ptr [b2s_iv]
    movdqu  xmm3, xmmword ptr [b2s_iv+16]
    movdqu  xmm4, xmmword ptr [rbx].BLAKE2S_CTX.t   ; t[0], t[1], f[0], f[1]
    pxor    xmm3, xmm4
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm1
    movdqu  xmmword ptr [rsp+64], xmm2
    movdqu  xmmword ptr [rsp+80], xmm3

    lea     r9, [b2s_sigma]
    xor     esi, esi
b2s_round:
    B2S_G   0,  4,  8, 12,  0,  1
    B2S_G   1,  5,  9, 13,  2,  3
    B2S_G   2,  6, 10, 14,  4,  5
    B2S_G   3,  7, 11, 15,  6,  7
    B2S_G   0,  5, 10, 15,  8,  9
    B2S_G   1,  6, 11, 12, 10, 11
    B2S_G   2,  7,  8, 13, 12, 13
    B2S_G   3,  4,  9, 14, 14, 15
    add     r9, 16
    inc     esi
    cmp     esi, 10
    jb      b2s_round

    ; h[i] ^= v[i] ^ v[i+8]
    movdqu  xmm0, xmmword ptr [rbx].BLAKE2S_CTX.h
    movdqu  xmm1, xmmword ptr [rbx].BLAKE2S_CTX.h+16
    movdqu  xmm2, xmmword ptr [rsp+32]
    movdqu  xmm3, xmmword ptr [rsp+48]
    movdqu  xmm4, xmmword ptr [rsp+64]
    movdqu  xmm5, xmmword ptr [rsp+80]
    pxor    xmm0, xmm2
    pxor    xmm0, xmm4
    pxor    xmm1, xmm3
    pxor    xmm1, xmm5
    movdqu  xmmword ptr [rbx].BLAKE2S_CTX.h, xmm0
    movdqu  xmmword ptr [rbx].BLAKE2S_CTX.h+16, xmm1

    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm0
    movdqu  xmmword ptr [rsp+64], xmm0
    movdqu  xmmword ptr [rsp+80], xmm0
    movdqu  xmmword ptr [rsp+96], xmm0
    movdqu  xmmword ptr [rsp+112], xmm0
    movdqu  xmmword ptr [rsp+128], xmm0
    movdqu  xmmword ptr [rsp+144], xmm0

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
blake2s_compress endp

; =============================================================================
; blake2s_update(rcx = ctx, rdx = data, r8 = len)
; Preserves >= 1 buffered byte whenever len > 0 so finalization marks the last block.
; =============================================================================
LANDING_PAD
public blake2s_update
blake2s_update proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    test    r8, r8
    jz      b2u_done

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; data
    mov     rdi, r8                         ; inlen

    mov     ecx, dword ptr [rbx].BLAKE2S_CTX.buflen
    mov     eax, 64
    sub     eax, ecx                        ; fill = 64 - left
    cmp     rdi, rax
    jbe     b2u_tail                        ; strictly '>' required!

    ; Top up buf to 64 bytes and compress
    test    eax, eax
    jz      b2u_flush_buf
    lea     r9, [rbx].BLAKE2S_CTX.buf
    add     r9, rcx
    mov     ecx, eax
b2u_fill:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     ecx
    jnz     b2u_fill
    sub     rdi, rax

b2u_flush_buf:
    mov     dword ptr [rbx].BLAKE2S_CTX.buflen, 0
    add     dword ptr [rbx].BLAKE2S_CTX.t, 64
    adc     dword ptr [rbx].BLAKE2S_CTX.t+4, 0
    mov     rcx, rbx
    lea     rdx, [rbx].BLAKE2S_CTX.buf
    call    blake2s_compress

b2u_blocks:
    cmp     rdi, 64
    jbe     b2u_tail                        ; strictly '>' required!
    add     dword ptr [rbx].BLAKE2S_CTX.t, 64
    adc     dword ptr [rbx].BLAKE2S_CTX.t+4, 0
    mov     rcx, rbx
    mov     rdx, rsi
    call    blake2s_compress
    add     rsi, 64
    sub     rdi, 64
    jmp     b2u_blocks

b2u_tail:
    mov     ecx, dword ptr [rbx].BLAKE2S_CTX.buflen
    lea     r9, [rbx].BLAKE2S_CTX.buf
    add     r9, rcx
    add     ecx, edi
    mov     dword ptr [rbx].BLAKE2S_CTX.buflen, ecx
b2u_copy:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     rdi
    jnz     b2u_copy

b2u_done:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
blake2s_update endp

; =============================================================================
; blake2s_final(rcx = ctx, rdx = out32)
; =============================================================================
LANDING_PAD
public blake2s_final
blake2s_final proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; out32

    mov     eax, dword ptr [rbx].BLAKE2S_CTX.buflen
    add     dword ptr [rbx].BLAKE2S_CTX.t, eax
    adc     dword ptr [rbx].BLAKE2S_CTX.t+4, 0
    mov     dword ptr [rbx].BLAKE2S_CTX.f, 0FFFFFFFFh

    lea     r9, [rbx].BLAKE2S_CTX.buf
b2f_zpad:
    cmp     eax, 64
    jae     b2f_comp
    mov     byte ptr [r9+rax], 0
    inc     eax
    jmp     b2f_zpad

b2f_comp:
    mov     rcx, rbx
    lea     rdx, [rbx].BLAKE2S_CTX.buf
    call    blake2s_compress

    movdqu  xmm0, xmmword ptr [rbx].BLAKE2S_CTX.h
    movdqu  xmm1, xmmword ptr [rbx].BLAKE2S_CTX.h+16
    movdqu  xmmword ptr [rsi], xmm0
    movdqu  xmmword ptr [rsi+16], xmm1
    pxor    xmm0, xmm0
    pxor    xmm1, xmm1

    mov     rcx, rbx
    mov     rdx, B2S_CTX_SIZE
    call    secure_zero

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
blake2s_final endp

end
