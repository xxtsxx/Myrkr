; =============================================================================
; sha512.asm - FIPS 180-4 SHA-512 (constant-time software implementation)
; -----------------------------------------------------------------------------
;   sha512_init   (rcx = ctx)
;   sha512_update (rcx = ctx, rdx = data, r8 = len)
;   sha512_final  (rcx = ctx, rdx = out64)
; =============================================================================

include macros.inc

extern secure_zero:proc

SHA512_CTX struct
    state       dq 8 dup (?)            ; H0..H7 (native 64-bit words)
    buf         db 128 dup (?)          ; partial 128-byte block
    buflen      dq ?                    ; buffered byte count (0..127)
    total_lo    dq ?                    ; total message bytes (low 64)
    total_hi    dq ?                    ; total message bytes (high 64)
SHA512_CTX ends

S512_CTX_SIZE   equ sizeof SHA512_CTX

.const
align 8
s512_iv label qword
    dq 06a09e667f3bcc908h, 0bb67ae8584caa73bh, 03c6ef372fe94f82bh, 0a54ff53a5f1d36f1h
    dq 0510e527fade682d1h, 09b05688c2b3e6c1fh, 01f83d9abfb41bd6bh, 05be0cd19137e2179h

align 8
s512_k label qword
    dq 0428a2f98d728ae22h, 07137449123ef65cdh, 0b5c0fbcfec4d3b2fh, 0e9b5dba58189dbbch
    dq 03956c25bf348b538h, 059f111f1b605d019h, 0923f82a4af194f9bh, 0ab1c5ed5da6d8118h
    dq 0d807aa98a3030242h, 012835b0145706fbeh, 0243185be4ee4b28ch, 0550c7dc3d5ffb4e2h
    dq 072be5d74f27b896fh, 080deb1fe3b1696b1h, 09bdc06a725c71235h, 0c19bf174cf692694h
    dq 0e49b69c19ef14ad2h, 0efbe4786384f25e3h, 00fc19dc68b8cd5b5h, 0240ca1cc77ac9c65h
    dq 02de92c6f592b0275h, 04a7484aa6ea6e483h, 05cb0a9dcbd41fbd4h, 076f988da831153b5h
    dq 0983e5152ee66dfabh, 0a831c66d2db43210h, 0b00327c898fb213fh, 0bf597fc7beef0ee4h
    dq 0c6e00bf33da88fc2h, 0d5a79147930aa725h, 006ca6351e003826fh, 0142929670a0e6e70h
    dq 027b70a8546d22ffch, 02e1b21385c26c926h, 04d2c6dfc5ac42aedh, 053380d139d95b3dfh
    dq 0650a73548baf63deh, 0766a0abb3c77b2a8h, 081c2c92e47edaee6h, 092722c851482353bh
    dq 0a2bfe8a14cf10364h, 0a81a664bbc423001h, 0c24b8b70d0f89791h, 0c76c51a30654be30h
    dq 0d192e819d6ef5218h, 0d69906245565a910h, 0f40e35855771202ah, 0106aa07032bbd1b8h
    dq 019a4c116b8d2d0c8h, 01e376c085141ab53h, 02748774cdf8eeb99h, 034b0bcb5e19b48a8h
    dq 0391c0cb3c5c95a63h, 04ed8aa4ae3418acbh, 05b9cca4f7763e373h, 0682e6ff3d6b2b8a3h
    dq 0748f82ee5defb2fch, 078a5636f43172f60h, 084c87814a1f0ab72h, 08cc702081a6439ech
    dq 090befffa23631e28h, 0a4506cebde82bde9h, 0bef9a3f7b2c67915h, 0c67178f2e372532bh
    dq 0ca273eceea26619ch, 0d186b8c721c0c207h, 0eada7dd6cde0eb1eh, 0f57d4f7fee6ed178h
    dq 006f067aa72176fbah, 00a637dc5a2c898a6h, 0113f9804bef90daeh, 01b710b35131c471bh
    dq 028db77f523047d84h, 032caab7b40c72493h, 03c9ebe0a15c9bebch, 0431d67c49c100d4ch
    dq 04cc5d4becb3e42b6h, 0597f299cfc657e2ah, 05fcb6fab3ad6faech, 06c44198c4a475817h

.code

; =============================================================================
; sha512_init(rcx = ctx)
; =============================================================================
LANDING_PAD
public sha512_init
sha512_init proc
    movdqu  xmm0, xmmword ptr [s512_iv]
    movdqu  xmm1, xmmword ptr [s512_iv+16]
    movdqu  xmm2, xmmword ptr [s512_iv+32]
    movdqu  xmm3, xmmword ptr [s512_iv+48]
    movdqu  xmmword ptr [rcx].SHA512_CTX.state, xmm0
    movdqu  xmmword ptr [rcx].SHA512_CTX.state+16, xmm1
    movdqu  xmmword ptr [rcx].SHA512_CTX.state+32, xmm2
    movdqu  xmmword ptr [rcx].SHA512_CTX.state+48, xmm3
    mov     qword ptr [rcx].SHA512_CTX.buflen, 0
    mov     qword ptr [rcx].SHA512_CTX.total_lo, 0
    mov     qword ptr [rcx].SHA512_CTX.total_hi, 0
    ret
sha512_init endp

; =============================================================================
; sha512_compress(rcx = state_ptr, rdx = block_ptr)
; Compresses a single 128-byte block into state[0..7].
; =============================================================================
sha512_compress proc frame
    FRAME_PROLOG 800
    ; [rbp-16..64] = r12..r15, rbx, rsi, rdi
    ; [rsp+32 .. rsp+671] = W[0..79] (640 bytes)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; state_ptr

    ; W[0..15] big-endian load
    xor     ecx, ecx
s5c_w0:
    mov     rax, qword ptr [rdx+rcx*8]
    bswap   rax
    mov     qword ptr [rsp+32+rcx*8], rax
    inc     ecx
    cmp     ecx, 16
    jb      s5c_w0

    ; W[16..79]
s5c_wext:
    ; s0(W[i-15]) = ROR(1) ^ ROR(8) ^ SHR(7)
    mov     rax, qword ptr [rsp+32+rcx*8-120]
    mov     r8, rax
    mov     r9, rax
    ror     rax, 1
    ror     r8, 8
    shr     r9, 7
    xor     rax, r8
    xor     rax, r9

    ; s1(W[i-2]) = ROR(19) ^ ROR(61) ^ SHR(6)
    mov     r10, qword ptr [rsp+32+rcx*8-16]
    mov     r8, r10
    mov     r9, r10
    ror     r10, 19
    ror     r8, 61
    shr     r9, 6
    xor     r10, r8
    xor     r10, r9

    add     rax, qword ptr [rsp+32+rcx*8-128]   ; + W[i-16]
    add     rax, qword ptr [rsp+32+rcx*8-56]    ; + W[i-7]
    add     rax, r10
    mov     qword ptr [rsp+32+rcx*8], rax
    inc     ecx
    cmp     ecx, 80
    jb      s5c_wext

    ; Load a..h into r8..r15
    mov     r8,  qword ptr [rsi]
    mov     r9,  qword ptr [rsi+8]
    mov     r10, qword ptr [rsi+16]
    mov     r11, qword ptr [rsi+24]
    mov     r12, qword ptr [rsi+32]
    mov     r13, qword ptr [rsi+40]
    mov     r14, qword ptr [rsi+48]
    mov     r15, qword ptr [rsi+56]

    lea     rdi, [s512_k]
    xor     ebx, ebx
s5c_rnd:
    ; Sigma1(e=r12) = ROR(14) ^ ROR(18) ^ ROR(41) -> rax
    mov     rax, r12
    mov     rcx, r12
    mov     rdx, r12
    ror     rax, 14
    ror     rcx, 18
    ror     rdx, 41
    xor     rax, rcx
    xor     rax, rdx

    ; Ch(e=r12, f=r13, g=r14) = (e & f) ^ (~e & g) -> rcx
    mov     rcx, r12
    and     rcx, r13
    mov     rdx, r12
    not     rdx
    and     rdx, r14
    xor     rcx, rdx

    ; T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i] -> rax
    add     rax, rcx
    add     rax, r15
    add     rax, qword ptr [rdi+rbx*8]
    add     rax, qword ptr [rsp+32+rbx*8]

    ; Sigma0(a=r8) = ROR(28) ^ ROR(34) ^ ROR(39) -> rcx
    mov     rcx, r8
    mov     rdx, r8
    ror     rcx, 28
    ror     rdx, 34
    xor     rcx, rdx
    mov     rdx, r8
    ror     rdx, 39
    xor     rcx, rdx

    ; d_new = d + T1; rax = T1 + Sigma0(a)
    add     r11, rax
    add     rax, rcx

    ; Maj(a=r8, b=r9, c=r10) = ((a | b) & c) | (a & b) -> rcx
    mov     rcx, r8
    or      rcx, r9
    and     rcx, r10
    mov     rdx, r8
    and     rdx, r9
    or      rcx, rdx
    add     rax, rcx                        ; T1 + T2

    mov     r15, r14
    mov     r14, r13
    mov     r13, r12
    mov     r12, r11
    mov     r11, r10
    mov     r10, r9
    mov     r9,  r8
    mov     r8,  rax

    inc     ebx
    cmp     ebx, 80
    jb      s5c_rnd

    add     qword ptr [rsi],    r8
    add     qword ptr [rsi+8],  r9
    add     qword ptr [rsi+16], r10
    add     qword ptr [rsi+24], r11
    add     qword ptr [rsi+32], r12
    add     qword ptr [rsi+40], r13
    add     qword ptr [rsi+48], r14
    add     qword ptr [rsi+56], r15

    ; Wipe W[0..79]
    xor     eax, eax
    xor     ecx, ecx
s5c_wipe:
    mov     qword ptr [rsp+32+rcx*8], rax
    inc     ecx
    cmp     ecx, 80
    jb      s5c_wipe

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
sha512_compress endp

; =============================================================================
; sha512_update(rcx = ctx, rdx = data, r8 = len)
; =============================================================================
LANDING_PAD
public sha512_update
sha512_update proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    test    r8, r8
    jz      s5u_done

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; data
    mov     rdi, r8                         ; len

    add     qword ptr [rbx].SHA512_CTX.total_lo, rdi
    adc     qword ptr [rbx].SHA512_CTX.total_hi, 0

    mov     rcx, qword ptr [rbx].SHA512_CTX.buflen
    test    rcx, rcx
    jz      s5u_blocks

    mov     rax, 128
    sub     rax, rcx                        ; space left in buf
    cmp     rdi, rax
    jb      s5u_tail

    ; Fill partial buffer to 128 bytes and compress
    lea     r9, [rbx].SHA512_CTX.buf
    add     r9, rcx
    mov     rcx, rax
s5u_fill:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     rcx
    jnz     s5u_fill

    sub     rdi, rax
    mov     qword ptr [rbx].SHA512_CTX.buflen, 0
    lea     rcx, [rbx].SHA512_CTX.state
    lea     rdx, [rbx].SHA512_CTX.buf
    call    sha512_compress

s5u_blocks:
    cmp     rdi, 128
    jb      s5u_tail
    lea     rcx, [rbx].SHA512_CTX.state
    mov     rdx, rsi
    call    sha512_compress
    add     rsi, 128
    sub     rdi, 128
    jmp     s5u_blocks

s5u_tail:
    test    rdi, rdi
    jz      s5u_done
    mov     rcx, qword ptr [rbx].SHA512_CTX.buflen
    lea     r9, [rbx].SHA512_CTX.buf
    add     r9, rcx
    add     rcx, rdi
    mov     qword ptr [rbx].SHA512_CTX.buflen, rcx
s5u_copy:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     rdi
    jnz     s5u_copy

s5u_done:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
sha512_update endp

; =============================================================================
; sha512_final(rcx = ctx, rdx = out64)
; =============================================================================
LANDING_PAD
public sha512_final
sha512_final proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; out64

    ; 128-bit bit count = total * 8, big-endian
    mov     rax, qword ptr [rbx].SHA512_CTX.total_lo
    mov     rdx, qword ptr [rbx].SHA512_CTX.total_hi
    shld    rdx, rax, 3
    shl     rax, 3
    bswap   rdx
    bswap   rax
    mov     qword ptr [rbp-40], rdx         ; hi_be
    mov     qword ptr [rbp-48], rax         ; lo_be

    mov     rdi, qword ptr [rbx].SHA512_CTX.buflen
    lea     r9, [rbx].SHA512_CTX.buf
    mov     byte ptr [r9+rdi], 080h
    inc     rdi
    cmp     rdi, 112
    jbe     s5f_pad_len

s5f_pad_128:
    cmp     rdi, 128
    jae     s5f_comp_extra
    mov     byte ptr [r9+rdi], 0
    inc     rdi
    jmp     s5f_pad_128

s5f_comp_extra:
    lea     rcx, [rbx].SHA512_CTX.state
    lea     rdx, [rbx].SHA512_CTX.buf
    call    sha512_compress
    xor     edi, edi

s5f_pad_len:
    lea     r9, [rbx].SHA512_CTX.buf
s5f_zloop:
    cmp     rdi, 112
    jae     s5f_store_len
    mov     byte ptr [r9+rdi], 0
    inc     rdi
    jmp     s5f_zloop

s5f_store_len:
    mov     rdx, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [r9+112], rdx
    mov     qword ptr [r9+120], rax
    lea     rcx, [rbx].SHA512_CTX.state
    lea     rdx, [rbx].SHA512_CTX.buf
    call    sha512_compress

    ; Emit 64-byte big-endian digest
    xor     ecx, ecx
s5f_out:
    mov     rax, qword ptr [rbx+rcx*8]
    bswap   rax
    mov     qword ptr [rsi+rcx*8], rax
    inc     ecx
    cmp     ecx, 8
    jb      s5f_out

    mov     qword ptr [rbp-40], 0
    mov     qword ptr [rbp-48], 0
    mov     rcx, rbx
    mov     rdx, S512_CTX_SIZE
    call    secure_zero

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
sha512_final endp

end
