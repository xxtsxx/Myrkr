; =============================================================================
; sha256.asm - SHA-256 using the SHA-NI instruction set extension
; -----------------------------------------------------------------------------
;   sha256_init   (rcx = ctx)
;   sha256_update (rcx = ctx, rdx = data, r8 = len)
;   sha256_final  (rcx = ctx, rdx = out32)
;   sha256_hash   (rcx = data, rdx = len, r8 = out32)   one-shot
;
; Compression follows the public-domain Intel SHA-NI pattern.  Note the HW
; constraint: SHA256RNDS2 takes the message words from the IMPLICIT xmm0, so
; xmm0 is reserved for the per-round message and must not hold state.
; Register map inside the compressor:
;   xmm0 = MSG (implicit operand)     xmm1 = STATE0 (ABEF)
;   xmm2 = STATE1 (CDGH)              xmm3..6 = TMSG0..3 (schedule)
;   xmm7 = byte-swap mask             xmm8/9 = state save   xmm10 = TMP
; Constant-time: no secret-dependent branches or memory indices.
; =============================================================================

include macros.inc

extern secure_zero:proc

SHA256_CTX struct
    state   dd 8 dup (?)            ; H0..H7
    buf     db 64 dup (?)           ; partial block
    buflen  dd ?                    ; bytes buffered (0..63)
    total   dq ?                    ; total message length in bytes
SHA256_CTX ends
public SHA256_CTX_SIZE
SHA256_CTX_SIZE equ sizeof SHA256_CTX

.const
align 16
k256 dd 0428a2f98h,071374491h,0b5c0fbcfh,0e9b5dba5h,03956c25bh,059f111f1h,0923f82a4h,0ab1c5ed5h
     dd 0d807aa98h,012835b01h,0243185beh,0550c7dc3h,072be5d74h,080deb1feh,09bdc06a7h,0c19bf174h
     dd 0e49b69c1h,0efbe4786h,00fc19dc6h,0240ca1cch,02de92c6fh,04a7484aah,05cb0a9dch,076f988dah
     dd 0983e5152h,0a831c66dh,0b00327c8h,0bf597fc7h,0c6e00bf3h,0d5a79147h,006ca6351h,014292967h
     dd 027b70a85h,02e1b2138h,04d2c6dfch,053380d13h,0650a7354h,0766a0abbh,081c2c92eh,092722c85h
     dd 0a2bfe8a1h,0a81a664bh,0c24b8b70h,0c76c51a3h,0d192e819h,0d6990624h,0f40e3585h,0106aa070h
     dd 019a4c116h,01e376c08h,02748774ch,034b0bcb5h,0391c0cb3h,04ed8aa4ah,05b9cca4fh,0682e6ff3h
     dd 0748f82eeh,078a5636fh,084c87814h,08cc70208h,090befffah,0a4506cebh,0bef9a3f7h,0c67178f2h
align 16
shuf_mask db 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
align 16
init_h dd 06a09e667h,0bb67ae85h,03c6ef372h,0a54ff53ah,0510e527fh,09b05688ch,01f83d9abh,05be0cd19h

.code

; ---------------------------------------------------------------------------
; RGROUP M, Koff - process 4 SHA rounds using message quad M and K[Koff..].
; Reserves xmm0 as the message register (SHA256RNDS2 implicit operand).
; ---------------------------------------------------------------------------
RGROUP macro M, Koff
    movdqa  xmm0, M
    paddd   xmm0, xmmword ptr [k256+Koff]
    sha256rnds2 xmm2, xmm1, xmm0            ; STATE1 = rnds2(STATE1,STATE0,MSG)
    pshufd  xmm0, xmm0, 0Eh
    sha256rnds2 xmm1, xmm2, xmm0            ; STATE0 = rnds2(STATE0,STATE1,MSG)
endm

; ---------------------------------------------------------------------------
; SGROUP Koff - derive the next message quad (W[r..r+3]) into xmm10 from the
; sliding window xmm3..xmm6 (M0..M3), run its 4 rounds, then rotate the window.
; Canonical 3-step schedule:  N = msg1(M0,M1); N += alignr(M3,M2,4); N = msg2(N,M3)
; xmm7 holds the byte-swap MASK across the whole block, so xmm0 is the temp.
; ---------------------------------------------------------------------------
SGROUP macro Koff
    movdqa  xmm10, xmm3                     ; M0
    sha256msg1 xmm10, xmm4                  ; msg1(M0,M1)
    movdqa  xmm0, xmm6                      ; M3
    palignr xmm0, xmm5, 4                   ; alignr(M3,M2,4)
    paddd   xmm10, xmm0
    sha256msg2 xmm10, xmm6                  ; N = W[r..r+3]
    RGROUP xmm10, Koff
    movdqa  xmm3, xmm4                      ; rotate window: M0=M1,M1=M2,M2=M3,M3=N
    movdqa  xmm4, xmm5
    movdqa  xmm5, xmm6
    movdqa  xmm6, xmm10
endm

; =============================================================================
; sha256_init(rcx = ctx)
; =============================================================================
public sha256_init
sha256_init proc
    movdqu  xmm0, xmmword ptr [init_h]
    movdqu  xmmword ptr [rcx].SHA256_CTX.state, xmm0
    movdqu  xmm0, xmmword ptr [init_h+16]
    movdqu  xmmword ptr [rcx].SHA256_CTX.state+16, xmm0
    mov     dword ptr [rcx].SHA256_CTX.buflen, 0
    mov     qword ptr [rcx].SHA256_CTX.total, 0
    ret
sha256_init endp

; =============================================================================
; sha256_compress_sw(rcx = state ptr, rdx = blocks ptr, r8 = block count)
; Software FIPS 180-4 SHA-256 fallback for pre-SHA-NI CPUs (e.g. Skylake).
; =============================================================================
public sha256_compress_sw
sha256_compress_sw proc frame
    FRAME_PROLOG 416
    ; [rbp-16]=r12 [rbp-24]=r13 [rbp-32]=r14 [rbp-40]=r15
    ; [rbp-48]=rbx [rbp-56]=rsi [rbp-64]=rdi
    ; [rsp+32 .. rsp+287] = W[0..63] (256 bytes)
    ; [rsp+288 .. rsp+319] = a..h (32 bytes)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    test    r8, r8
    jz      scsw_out

    mov     r12, rcx                         ; state ptr
    mov     r13, rdx                         ; blocks ptr
    mov     r14, r8                          ; block count

scsw_blk:
    ; W[0..15] = big-endian dwords of [r13]
    xor     r10d, r10d
scsw_w0:
    mov     eax, dword ptr [r13+r10*4]
    bswap   eax
    mov     dword ptr [rsp+32+r10*4], eax
    inc     r10d
    cmp     r10d, 16
    jb      scsw_w0

    ; W[16..63]
    mov     r10d, 16
scsw_wexp:
    ; s0 = ROR(W[t-15],7) ^ ROR(W[t-15],18) ^ (W[t-15] >> 3)
    mov     eax, dword ptr [rsp+32+r10*4-60]
    mov     ecx, eax
    mov     edx, eax
    ror     eax, 7
    ror     ecx, 18
    shr     edx, 3
    xor     eax, ecx
    xor     eax, edx                         ; eax = s0
    ; s1 = ROR(W[t-2],17) ^ ROR(W[t-2],19) ^ (W[t-2] >> 10)
    mov     ebx, dword ptr [rsp+32+r10*4-8]
    mov     ecx, ebx
    mov     edx, ebx
    ror     ebx, 17
    ror     ecx, 19
    shr     edx, 10
    xor     ebx, ecx
    xor     ebx, edx                         ; ebx = s1
    add     eax, ebx
    add     eax, dword ptr [rsp+32+r10*4-64] ; + W[t-16]
    add     eax, dword ptr [rsp+32+r10*4-28] ; + W[t-7]
    mov     dword ptr [rsp+32+r10*4], eax
    inc     r10d
    cmp     r10d, 64
    jb      scsw_wexp

    ; a..h = state[0..7]
    mov     eax, dword ptr [r12+0]
    mov     dword ptr [rsp+288], eax         ; a
    mov     eax, dword ptr [r12+4]
    mov     dword ptr [rsp+292], eax         ; b
    mov     eax, dword ptr [r12+8]
    mov     dword ptr [rsp+296], eax         ; c
    mov     eax, dword ptr [r12+12]
    mov     dword ptr [rsp+300], eax         ; d
    mov     eax, dword ptr [r12+16]
    mov     dword ptr [rsp+304], eax         ; e
    mov     eax, dword ptr [r12+20]
    mov     dword ptr [rsp+308], eax         ; f
    mov     eax, dword ptr [r12+24]
    mov     dword ptr [rsp+312], eax         ; g
    mov     eax, dword ptr [r12+28]
    mov     dword ptr [rsp+316], eax         ; h

    lea     r15, [k256]
    xor     r10d, r10d
scsw_rnd:
    ; S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25)
    mov     eax, dword ptr [rsp+304]         ; e
    mov     ecx, eax
    mov     edx, eax
    ror     eax, 6
    ror     ecx, 11
    ror     edx, 25
    xor     eax, ecx
    xor     eax, edx                         ; eax = S1
    ; ch = (e & f) ^ (~e & g)
    mov     ecx, dword ptr [rsp+304]         ; e
    mov     edx, ecx
    and     ecx, dword ptr [rsp+308]         ; e & f
    not     edx
    and     edx, dword ptr [rsp+312]         ; ~e & g
    xor     ecx, edx                         ; ecx = ch
    ; temp1 (esi) = h + S1 + ch + k256[t] + W[t]
    mov     esi, dword ptr [rsp+316]         ; h
    add     esi, eax
    add     esi, ecx
    add     esi, dword ptr [r15+r10*4]
    add     esi, dword ptr [rsp+32+r10*4]

    ; S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22)
    mov     eax, dword ptr [rsp+288]         ; a
    mov     ecx, eax
    mov     edx, eax
    ror     eax, 2
    ror     ecx, 13
    ror     edx, 22
    xor     eax, ecx
    xor     eax, edx                         ; eax = S0
    ; maj = (a & b) ^ (a & c) ^ (b & c)
    mov     ebx, dword ptr [rsp+288]         ; a
    mov     ecx, dword ptr [rsp+292]         ; b
    mov     edx, dword ptr [rsp+296]         ; c
    mov     edi, ebx
    and     edi, ecx                         ; a & b
    and     ebx, edx                         ; a & c
    and     ecx, edx                         ; b & c
    xor     edi, ebx
    xor     edi, ecx                         ; edi = maj
    add     edi, eax                         ; edi = temp2

    ; shift working registers
    mov     eax, dword ptr [rsp+312]         ; g
    mov     dword ptr [rsp+316], eax         ; h = g
    mov     eax, dword ptr [rsp+308]         ; f
    mov     dword ptr [rsp+312], eax         ; g = f
    mov     eax, dword ptr [rsp+304]         ; e
    mov     dword ptr [rsp+308], eax         ; f = e
    mov     eax, dword ptr [rsp+300]         ; d
    add     eax, esi                         ; d + temp1
    mov     dword ptr [rsp+304], eax         ; e = d + temp1
    mov     eax, dword ptr [rsp+296]         ; c
    mov     dword ptr [rsp+300], eax         ; d = c
    mov     eax, dword ptr [rsp+292]         ; b
    mov     dword ptr [rsp+296], eax         ; c = b
    mov     eax, dword ptr [rsp+288]         ; a
    mov     dword ptr [rsp+292], eax         ; b = a
    add     esi, edi                         ; temp1 + temp2
    mov     dword ptr [rsp+288], esi         ; a = temp1 + temp2

    inc     r10d
    cmp     r10d, 64
    jb      scsw_rnd

    ; state[0..7] += a..h
    mov     eax, dword ptr [rsp+288]
    add     dword ptr [r12+0], eax
    mov     eax, dword ptr [rsp+292]
    add     dword ptr [r12+4], eax
    mov     eax, dword ptr [rsp+296]
    add     dword ptr [r12+8], eax
    mov     eax, dword ptr [rsp+300]
    add     dword ptr [r12+12], eax
    mov     eax, dword ptr [rsp+304]
    add     dword ptr [r12+16], eax
    mov     eax, dword ptr [rsp+308]
    add     dword ptr [r12+20], eax
    mov     eax, dword ptr [rsp+312]
    add     dword ptr [r12+24], eax
    mov     eax, dword ptr [rsp+316]
    add     dword ptr [r12+28], eax

    add     r13, 64
    dec     r14
    jnz     scsw_blk

    lea     rcx, [rsp+32]
    mov     edx, 288
    call    secure_zero

scsw_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
sha256_compress_sw endp

; =============================================================================
; sha256_compress(rcx = state ptr, rdx = blocks ptr, r8 = block count)
; Leaf; saves nonvolatile xmm6..xmm10 per the Win64 ABI (falls back to
; sha256_compress_sw when SHA-NI is unavailable).
; =============================================================================
sha256_compress proc frame
    sub     rsp, 16*5
    .allocstack 80
    movdqu  xmmword ptr [rsp+0],  xmm6
    .savexmm128 xmm6, 0
    movdqu  xmmword ptr [rsp+16], xmm7
    .savexmm128 xmm7, 16
    movdqu  xmmword ptr [rsp+32], xmm8
    .savexmm128 xmm8, 32
    movdqu  xmmword ptr [rsp+48], xmm9
    .savexmm128 xmm9, 48
    movdqu  xmmword ptr [rsp+64], xmm10
    .savexmm128 xmm10, 64
    .endprolog

    test    r8, r8
    jz      sc_done
    test    dword ptr [g_cpu_features], CPUF_SHANI
    jz      sc_fallback

    ; load + arrange state: xmm1=STATE0(ABEF), xmm2=STATE1(CDGH)
    movdqu  xmm1, xmmword ptr [rcx]          ; DCBA
    movdqu  xmm2, xmmword ptr [rcx+16]       ; HGFE
    movdqa  xmm7, xmmword ptr [shuf_mask]
    pshufd  xmm1, xmm1, 0B1h                 ; CDAB
    pshufd  xmm2, xmm2, 01Bh                 ; EFGH
    movdqa  xmm10, xmm1                      ; CDAB
    palignr xmm1, xmm2, 8                    ; ABEF -> STATE0
    pblendw xmm2, xmm10, 0F0h               ; CDGH -> STATE1

sc_block:
    movdqa  xmm8, xmm1                       ; ABEF_SAVE
    movdqa  xmm9, xmm2                       ; CDGH_SAVE

    ; load + byte-swap the four message quads (window M0..M3 = xmm3..xmm6)
    movdqu  xmm3, xmmword ptr [rdx+0]
    pshufb  xmm3, xmm7
    movdqu  xmm4, xmmword ptr [rdx+16]
    pshufb  xmm4, xmm7
    movdqu  xmm5, xmmword ptr [rdx+32]
    pshufb  xmm5, xmm7
    movdqu  xmm6, xmmword ptr [rdx+48]
    pshufb  xmm6, xmm7

    ; rounds 0-15 (message words already available)
    RGROUP xmm3, 0
    RGROUP xmm4, 16
    RGROUP xmm5, 32
    RGROUP xmm6, 48

    ; rounds 16-63 (derive each quad, run rounds, slide the window)
    SGROUP 64
    SGROUP 80
    SGROUP 96
    SGROUP 112
    SGROUP 128
    SGROUP 144
    SGROUP 160
    SGROUP 176
    SGROUP 192
    SGROUP 208
    SGROUP 224
    SGROUP 240

    ; feed-forward
    paddd   xmm1, xmm8
    paddd   xmm2, xmm9

    add     rdx, 64
    dec     r8
    jnz     sc_block

    ; store state back: inverse arrangement
    pshufd  xmm1, xmm1, 01Bh                 ; FEBA
    pshufd  xmm2, xmm2, 0B1h                 ; DCHG
    movdqa  xmm10, xmm1
    pblendw xmm1, xmm2, 0F0h                ; DCBA
    palignr xmm2, xmm10, 8                   ; HGFE
    movdqu  xmmword ptr [rcx], xmm1
    movdqu  xmmword ptr [rcx+16], xmm2
    pxor    xmm0, xmm0
    pxor    xmm1, xmm1
    pxor    xmm2, xmm2
    pxor    xmm3, xmm3
    pxor    xmm4, xmm4
    pxor    xmm5, xmm5

sc_done:
    movdqu  xmm6,  xmmword ptr [rsp+0]
    movdqu  xmm7,  xmmword ptr [rsp+16]
    movdqu  xmm8,  xmmword ptr [rsp+32]
    movdqu  xmm9,  xmmword ptr [rsp+48]
    movdqu  xmm10, xmmword ptr [rsp+64]
    add     rsp, 16*5
    ret
sc_fallback:
    movdqu  xmm6,  xmmword ptr [rsp+0]
    movdqu  xmm7,  xmmword ptr [rsp+16]
    movdqu  xmm8,  xmmword ptr [rsp+32]
    movdqu  xmm9,  xmmword ptr [rsp+48]
    movdqu  xmm10, xmmword ptr [rsp+64]
    add     rsp, 16*5
    jmp     sha256_compress_sw
sha256_compress endp

; =============================================================================
; sha256_update(rcx = ctx, rdx = data, r8 = len)
; =============================================================================
public sha256_update
sha256_update proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=ctx [rbp-32]=data [rbp-40]=len
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8

    ; total += len
    mov     rax, qword ptr [rbp-40]
    add     qword ptr [rcx].SHA256_CTX.total, rax

    ; --- if buffer holds a partial block, top it up byte-by-byte ------------
    mov     r9d, dword ptr [rcx].SHA256_CTX.buflen
    test    r9d, r9d
    jz      su_bulk
su_fillbuf:
    mov     rcx, qword ptr [rbp-24]
    mov     r9d, dword ptr [rcx].SHA256_CTX.buflen
    cmp     r9d, 64                         ; full buffer -> always flush first
    je      su_flushbuf
    cmp     qword ptr [rbp-40], 0           ; input exhausted?
    je      su_done
    jmp     su_addbyte
su_flushbuf:
    lea     rdx, [rcx].SHA256_CTX.buf
    lea     rcx, [rcx].SHA256_CTX.state
    mov     r8, 1
    call    sha256_compress
    mov     rcx, qword ptr [rbp-24]
    mov     dword ptr [rcx].SHA256_CTX.buflen, 0
    jmp     su_bulk
su_addbyte:
    mov     rax, qword ptr [rbp-32]
    mov     r10b, byte ptr [rax]
    lea     r11, [rcx].SHA256_CTX.buf
    mov     byte ptr [r11+r9], r10b
    inc     r9d
    mov     dword ptr [rcx].SHA256_CTX.buflen, r9d
    inc     qword ptr [rbp-32]
    dec     qword ptr [rbp-40]
    jmp     su_fillbuf

su_bulk:
    ; process whole 64-byte blocks directly from input
    mov     rcx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-40]
    shr     r8, 6                            ; full blocks
    test    r8, r8
    jz      su_tail
    mov     rdx, qword ptr [rbp-32]
    lea     rcx, [rcx].SHA256_CTX.state
    call    sha256_compress
    mov     r8, qword ptr [rbp-40]
    and     r8, -64                          ; bytes consumed
    add     qword ptr [rbp-32], r8
    mov     rax, qword ptr [rbp-40]
    and     rax, 63
    mov     qword ptr [rbp-40], rax

su_tail:
    ; copy remaining (<64) bytes into buf
    mov     rcx, qword ptr [rbp-24]
    mov     r9, qword ptr [rbp-40]
    test    r9, r9
    jz      su_done
    lea     r11, [rcx].SHA256_CTX.buf
    mov     rax, qword ptr [rbp-32]
    xor     r10d, r10d
su_copy:
    mov     r8b, byte ptr [rax+r10]
    mov     byte ptr [r11+r10], r8b
    inc     r10
    cmp     r10, r9
    jb      su_copy
    mov     dword ptr [rcx].SHA256_CTX.buflen, r10d
su_done:
    FRAME_EPILOG
    ret
sha256_update endp

; =============================================================================
; sha256_final(rcx = ctx, rdx = out32) - pad and emit big-endian digest
; =============================================================================
public sha256_final
sha256_final proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx

    ; bit length (big-endian) BEFORE padding
    mov     rax, qword ptr [rcx].SHA256_CTX.total
    shl     rax, 3                            ; bytes -> bits
    bswap   rax
    mov     qword ptr [rbp-40], rax           ; be64 length

    ; append 0x80
    mov     r9d, dword ptr [rcx].SHA256_CTX.buflen
    lea     r11, [rcx].SHA256_CTX.buf
    mov     byte ptr [r11+r9], 080h
    inc     r9d
    ; if no room for 8-byte length, pad block and compress
    cmp     r9d, 56
    jbe     sf_pad_zeros
    ; zero-fill to 64, compress, then start fresh block
sf_fill_to_64:
    cmp     r9d, 64
    jae     sf_compress_partial
    mov     byte ptr [r11+r9], 0
    inc     r9d
    jmp     sf_fill_to_64
sf_compress_partial:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rcx].SHA256_CTX.buf
    lea     rcx, [rcx].SHA256_CTX.state
    mov     r8, 1
    call    sha256_compress
    mov     rcx, qword ptr [rbp-24]
    lea     r11, [rcx].SHA256_CTX.buf
    xor     r9d, r9d
sf_pad_zeros:
    ; zero-fill up to byte 56
    mov     rcx, qword ptr [rbp-24]
    lea     r11, [rcx].SHA256_CTX.buf
sf_zloop:
    cmp     r9d, 56
    jae     sf_putlen
    mov     byte ptr [r11+r9], 0
    inc     r9d
    jmp     sf_zloop
sf_putlen:
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r11+56], rax
    lea     rdx, [rcx].SHA256_CTX.buf
    lea     rcx, [rcx].SHA256_CTX.state
    mov     r8, 1
    call    sha256_compress

    ; output 32 bytes: state words are native (LE); digest is big-endian, so
    ; byte-swap each 32-bit word on the way out.
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    movdqa  xmm1, xmmword ptr [shuf_mask]
    movdqu  xmm0, xmmword ptr [rcx].SHA256_CTX.state
    pshufb  xmm0, xmm1
    movdqu  xmmword ptr [rdx], xmm0
    movdqu  xmm0, xmmword ptr [rcx].SHA256_CTX.state+16
    pshufb  xmm0, xmm1
    movdqu  xmmword ptr [rdx+16], xmm0

    ; wipe context (contains message-derived state) + local bitlen + xmm0
    mov     qword ptr [rbp-40], 0
    pxor    xmm0, xmm0
    lea     rcx, [rcx].SHA256_CTX.state
    mov     rdx, SHA256_CTX_SIZE
    call    secure_zero
    FRAME_EPILOG
    ret
sha256_final endp

; =============================================================================
; sha256_hash(rcx = data, rdx = len, r8 = out32) - one-shot convenience
; =============================================================================
public sha256_hash
sha256_hash proc frame
    FRAME_PROLOG 64 + SHA256_CTX_SIZE
    ; ctx on stack at [rbp - (16+SHA256_CTX_SIZE) .. ]; use [rsp+32] region
    mov     qword ptr [rbp-24], rdx          ; len
    mov     qword ptr [rbp-32], r8           ; out
    mov     qword ptr [rbp-40], rcx          ; data
    lea     rcx, [rsp+32]                     ; ctx
    mov     qword ptr [rbp-48], rcx
    call    sha256_init
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-40]
    mov     r8,  qword ptr [rbp-24]
    call    sha256_update
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-32]
    call    sha256_final
    FRAME_EPILOG
    ret
sha256_hash endp

end
