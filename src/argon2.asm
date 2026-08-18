; =============================================================================
; argon2.asm - Argon2id (RFC 9106)
; -----------------------------------------------------------------------------
;   argon2id_hash(rcx = ARGON2REQ*) -> eax = 0 ok, 1 alloc failure
;
; Transcribed from a sandbox implementation validated against the RFC 9106
; Argon2id test vector.  Scalar 64-bit compression (fBlaMka + BLAKE2 P).
; The large memory arena is VirtualAlloc'd, wiped, and freed.
; =============================================================================

include macros.inc

extern blake2b_init:proc
extern blake2b_update:proc
extern blake2b_final:proc
extern blake2b_long:proc
extern secure_zero:proc
extern VirtualAlloc:proc
extern VirtualFree:proc

MEM_COMMIT      equ 1000h
MEM_RESERVE     equ 2000h
MEM_RELEASE     equ 8000h
PAGE_READWRITE  equ 04h

.const
align 16
rot24_mask  db 3,4,5,6,7,0,1,2, 11,12,13,14,15,8,9,10
rot16_mask  db 2,3,4,5,6,7,0,1, 10,11,12,13,14,15,8,9
align 16
rot24_mask256 db 3,4,5,6,7,0,1,2,11,12,13,14,15,8,9,10, 3,4,5,6,7,0,1,2,11,12,13,14,15,8,9,10
rot16_mask256 db 2,3,4,5,6,7,0,1,10,11,12,13,14,15,8,9, 2,3,4,5,6,7,0,1,10,11,12,13,14,15,8,9

.code

ARGON2REQ struct
    t_cost      dd ?
    m_cost      dd ?            ; KiB
    lanes       dd ?            ; parallelism p
    outlen      dd ?
    version     dd ?            ; 0x13
    atype       dd ?            ; 2 = argon2id
    pwd         dq ?
    pwdlen      dd ?
    saltlen     dd ?
    salt        dq ?
    secret      dq ?
    secretlen   dd ?
    adlen       dd ?
    ad          dq ?
    outp        dq ?
ARGON2REQ ends

.code

; ---------------------------------------------------------------------------
; GBM a,b,c,d - Argon2 GB mix on 16 qwords based at rsi.  fBlaMka variant.
; fBlaMka(x,y) = x + y + 2*(lo32(x)*lo32(y)).  temps rax,r8,r9,r10,r11.
; ---------------------------------------------------------------------------
GBM macro a,b,c,d
    ; a = fBlaMka(a,b)
    mov     rax, qword ptr [rsi+a*8]
    mov     r8,  qword ptr [rsi+b*8]
    mov     r10d, eax
    mov     r11d, r8d
    imul    r10, r11
    add     rax, r8
    lea     rax, [rax + r10*2]
    mov     qword ptr [rsi+a*8], rax
    ; d = rotr(d^a,32)
    mov     r9,  qword ptr [rsi+d*8]
    xor     r9, rax
    ror     r9, 32
    mov     qword ptr [rsi+d*8], r9
    ; c = fBlaMka(c,d)
    mov     rax, qword ptr [rsi+c*8]
    mov     r10d, eax
    mov     r11d, r9d
    imul    r10, r11
    add     rax, r9
    lea     rax, [rax + r10*2]
    mov     qword ptr [rsi+c*8], rax
    ; b = rotr(b^c,24)
    mov     r8,  qword ptr [rsi+b*8]
    xor     r8, rax
    ror     r8, 24
    mov     qword ptr [rsi+b*8], r8
    ; a = fBlaMka(a,b)
    mov     rax, qword ptr [rsi+a*8]
    mov     r10d, eax
    mov     r11d, r8d
    imul    r10, r11
    add     rax, r8
    lea     rax, [rax + r10*2]
    mov     qword ptr [rsi+a*8], rax
    ; d = rotr(d^a,16)
    mov     r9,  qword ptr [rsi+d*8]
    xor     r9, rax
    ror     r9, 16
    mov     qword ptr [rsi+d*8], r9
    ; c = fBlaMka(c,d)
    mov     rax, qword ptr [rsi+c*8]
    mov     r10d, eax
    mov     r11d, r9d
    imul    r10, r11
    add     rax, r9
    lea     rax, [rax + r10*2]
    mov     qword ptr [rsi+c*8], rax
    ; b = rotr(b^c,63)
    mov     r8,  qword ptr [rsi+b*8]
    xor     r8, rax
    ror     r8, 63
    mov     qword ptr [rsi+b*8], r8
endm

; =============================================================================
; argon2_p(rcx = ptr to 16 contiguous qwords) - BLAKE2 P permutation
; Leaf; uses rsi (saved).
; =============================================================================
argon2_p proc
    push    rsi
    mov     rsi, rcx
    GBM 0,4,8,12
    GBM 1,5,9,13
    GBM 2,6,10,14
    GBM 3,7,11,15
    GBM 0,5,10,15
    GBM 1,6,11,12
    GBM 2,7,8,13
    GBM 3,4,9,14
    pop     rsi
    ret
argon2_p endp

; =============================================================================
; argon2_compress(rcx = dst, rdx = X, r8 = Y, r9 = with_xor)
; dst = (with_xor ? dst : 0) ^ ( P_col(P_row(X^Y)) ^ (X^Y) )
; =============================================================================
RB   equ 32          ; Rbuf  (1024)
QB   equ 1056        ; Qbuf  (1024)
TB   equ 2080        ; Tbuf  (128) column scratch
S12  equ 2208
S13  equ 2216
S14  equ 2224
S15  equ 2232
argon2_compress_scalar proc frame
    FRAME_PROLOG 2304
    ; locals: [rbp-24]=dst [rbp-32]=with_xor ; buffers at rsp+RB/QB/TB
    mov     qword ptr [rsp+S12], r12
    mov     qword ptr [rsp+S13], r13
    mov     qword ptr [rsp+S14], r14
    mov     qword ptr [rsp+S15], r15
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], r9

    ; R = X ^ Y -> Rbuf ; Qbuf = R   (1024 bytes = 64 * 16-byte)
    lea     r10, [rsp+RB]
    lea     r11, [rsp+QB]
    xor     eax, eax
ac_xor:
    movdqu  xmm0, xmmword ptr [rdx+rax]
    movdqu  xmm1, xmmword ptr [r8+rax]
    pxor    xmm0, xmm1
    movdqu  xmmword ptr [r10+rax], xmm0
    movdqu  xmmword ptr [r11+rax], xmm0
    add     rax, 16
    cmp     rax, 1024
    jb      ac_xor

    ; row passes: P over each 128-byte row
    xor     r12d, r12d
ac_row:
    lea     rcx, [rsp+QB]
    mov     rax, r12
    shl     rax, 7                       ; *128
    add     rcx, rax
    call    argon2_p
    inc     r12d
    cmp     r12d, 8
    jb      ac_row

    ; column passes: gather column c into Tbuf, P, scatter back
    xor     r12d, r12d                   ; c
ac_col:
    ; gather: Tbuf[2r]=Qbuf[r*16+c*2], Tbuf[2r+1]=Qbuf[r*16+c*2+1]
    xor     r13d, r13d                   ; r
ac_gather:
    mov     rax, r13
    shl     rax, 4                       ; r*16 (qwords)
    mov     r14, r12
    add     r14, r14                     ; c*2
    add     rax, r14                     ; r*16 + c*2 (qword index)
    lea     r10, [rsp+QB]
    movdqu  xmm0, xmmword ptr [r10+rax*8] ; two qwords (r,c)
    mov     r11, r13
    add     r11, r11                     ; 2r
    lea     r15, [rsp+TB]
    movdqu  xmmword ptr [r15+r11*8], xmm0
    inc     r13d
    cmp     r13d, 8
    jb      ac_gather

    lea     rcx, [rsp+TB]
    call    argon2_p

    ; scatter back
    xor     r13d, r13d
ac_scatter:
    mov     r11, r13
    add     r11, r11
    lea     r15, [rsp+TB]
    movdqu  xmm0, xmmword ptr [r15+r11*8]
    mov     rax, r13
    shl     rax, 4
    mov     r14, r12
    add     r14, r14
    add     rax, r14
    lea     r10, [rsp+QB]
    movdqu  xmmword ptr [r10+rax*8], xmm0
    inc     r13d
    cmp     r13d, 8
    jb      ac_scatter

    inc     r12d
    cmp     r12d, 8
    jb      ac_col

    ; finalize: Z = Qbuf ^ Rbuf ; dst = with_xor? dst^Z : Z
    mov     rcx, qword ptr [rbp-24]      ; dst
    lea     r10, [rsp+QB]
    lea     r11, [rsp+RB]
    xor     eax, eax
ac_fin:
    movdqu  xmm0, xmmword ptr [r10+rax]
    movdqu  xmm1, xmmword ptr [r11+rax]
    pxor    xmm0, xmm1                    ; Z
    cmp     qword ptr [rbp-32], 0
    je      ac_store
    movdqu  xmm1, xmmword ptr [rcx+rax]
    pxor    xmm0, xmm1
ac_store:
    movdqu  xmmword ptr [rcx+rax], xmm0
    add     rax, 16
    cmp     rax, 1024
    jb      ac_fin

    mov     r12, qword ptr [rsp+S12]
    mov     r13, qword ptr [rsp+S13]
    mov     r14, qword ptr [rsp+S14]
    mov     r15, qword ptr [rsp+S15]
    FRAME_EPILOG
    ret
argon2_compress_scalar endp

; =============================================================================
; argon2_compress(rcx=dst, rdx=X, r8=Y, r9=with_xor) - dispatcher
; Selects the fastest available compression: AVX2 > SSE2/SSSE3 > scalar.
; =============================================================================
public argon2_compress
argon2_compress proc
    test    dword ptr [g_cpu_features], CPUF_AVX2
    jnz     argon2_compress_avx2
    test    dword ptr [g_cpu_features], CPUF_SSE41
    jnz     argon2_compress_sse2
    jmp     argon2_compress_scalar
argon2_compress endp

; =============================================================================
; argon2_compress_sse2 - SSE2/SSSE3 BLAMKA (validated vs scalar KAT)
; rcx=dst, rdx=X, r8=Y, r9=with_xor
; -----------------------------------------------------------------------------
; fBlaMka(d,s): d = d + s + 2*(lo32(d)*lo32(s))     temp xmm10
; rotr32 = pshufd 0B1h ; rotr24/16 = pshufb masks ; rotr63 = shift/or
; Block kept in stack buffers: SR (R = X^Y, preserved), SS (working state).
; =============================================================================
SR   equ 32          ; R buffer (1024)
WSS  equ 1056        ; working state (1024)
SX6  equ 2080        ; xmm6..xmm11 save area (96)

FBLA macro d, s
    movdqa  xmm10, d
    pmuludq xmm10, s
    paddq   xmm10, xmm10
    paddq   d, s
    paddq   d, xmm10
endm

ROT63 macro r
    movdqa  xmm10, r
    psrlq   xmm10, 63
    paddq   r, r
    por     r, xmm10
endm

; one BLAKE2 round over xmm0..7 = A0,A1,B0,B1,C0,C1,D0,D1
SROUND macro
    ; --- G1 ---
    FBLA    xmm0, xmm2
    FBLA    xmm1, xmm3
    pxor    xmm6, xmm0
    pxor    xmm7, xmm1
    pshufd  xmm6, xmm6, 0B1h
    pshufd  xmm7, xmm7, 0B1h
    FBLA    xmm4, xmm6
    FBLA    xmm5, xmm7
    pxor    xmm2, xmm4
    pxor    xmm3, xmm5
    pshufb  xmm2, xmm8
    pshufb  xmm3, xmm8
    ; --- G2 ---
    FBLA    xmm0, xmm2
    FBLA    xmm1, xmm3
    pxor    xmm6, xmm0
    pxor    xmm7, xmm1
    pshufb  xmm6, xmm9
    pshufb  xmm7, xmm9
    FBLA    xmm4, xmm6
    FBLA    xmm5, xmm7
    pxor    xmm2, xmm4
    pxor    xmm3, xmm5
    ROT63   xmm2
    ROT63   xmm3
    ; --- DIAGONALIZE ---
    movdqa  xmm10, xmm3
    palignr xmm10, xmm2, 8                  ; alignr(B1,B0,8)
    movdqa  xmm11, xmm2
    palignr xmm11, xmm3, 8                  ; alignr(B0,B1,8)
    movdqa  xmm2, xmm10
    movdqa  xmm3, xmm11
    movdqa  xmm10, xmm4                      ; swap C0,C1
    movdqa  xmm4, xmm5
    movdqa  xmm5, xmm10
    movdqa  xmm10, xmm7
    palignr xmm10, xmm6, 8                  ; alignr(D1,D0,8)
    movdqa  xmm11, xmm6
    palignr xmm11, xmm7, 8                  ; alignr(D0,D1,8)
    movdqa  xmm6, xmm11                      ; D0 = t1
    movdqa  xmm7, xmm10                      ; D1 = t0
    ; --- G1 ---
    FBLA    xmm0, xmm2
    FBLA    xmm1, xmm3
    pxor    xmm6, xmm0
    pxor    xmm7, xmm1
    pshufd  xmm6, xmm6, 0B1h
    pshufd  xmm7, xmm7, 0B1h
    FBLA    xmm4, xmm6
    FBLA    xmm5, xmm7
    pxor    xmm2, xmm4
    pxor    xmm3, xmm5
    pshufb  xmm2, xmm8
    pshufb  xmm3, xmm8
    ; --- G2 ---
    FBLA    xmm0, xmm2
    FBLA    xmm1, xmm3
    pxor    xmm6, xmm0
    pxor    xmm7, xmm1
    pshufb  xmm6, xmm9
    pshufb  xmm7, xmm9
    FBLA    xmm4, xmm6
    FBLA    xmm5, xmm7
    pxor    xmm2, xmm4
    pxor    xmm3, xmm5
    ROT63   xmm2
    ROT63   xmm3
    ; --- UNDIAGONALIZE ---
    movdqa  xmm10, xmm2
    palignr xmm10, xmm3, 8                  ; alignr(B0,B1,8)
    movdqa  xmm11, xmm3
    palignr xmm11, xmm2, 8                  ; alignr(B1,B0,8)
    movdqa  xmm2, xmm10
    movdqa  xmm3, xmm11
    movdqa  xmm10, xmm4
    movdqa  xmm4, xmm5
    movdqa  xmm5, xmm10
    movdqa  xmm10, xmm6
    palignr xmm10, xmm7, 8                  ; alignr(D0,D1,8)
    movdqa  xmm11, xmm7
    palignr xmm11, xmm6, 8                  ; alignr(D1,D0,8)
    movdqa  xmm6, xmm11                      ; D0 = t1
    movdqa  xmm7, xmm10                      ; D1 = t0
endm

; DO_SROUND base(reg), stride(imm): load 8 regs, round, store
DO_SROUND macro basereg, st
    movdqu  xmm0, xmmword ptr [basereg + 0*st]
    movdqu  xmm1, xmmword ptr [basereg + 1*st]
    movdqu  xmm2, xmmword ptr [basereg + 2*st]
    movdqu  xmm3, xmmword ptr [basereg + 3*st]
    movdqu  xmm4, xmmword ptr [basereg + 4*st]
    movdqu  xmm5, xmmword ptr [basereg + 5*st]
    movdqu  xmm6, xmmword ptr [basereg + 6*st]
    movdqu  xmm7, xmmword ptr [basereg + 7*st]
    SROUND
    movdqu  xmmword ptr [basereg + 0*st], xmm0
    movdqu  xmmword ptr [basereg + 1*st], xmm1
    movdqu  xmmword ptr [basereg + 2*st], xmm2
    movdqu  xmmword ptr [basereg + 3*st], xmm3
    movdqu  xmmword ptr [basereg + 4*st], xmm4
    movdqu  xmmword ptr [basereg + 5*st], xmm5
    movdqu  xmmword ptr [basereg + 6*st], xmm6
    movdqu  xmmword ptr [basereg + 7*st], xmm7
endm

argon2_compress_sse2 proc frame
    FRAME_PROLOG 2240
    mov     qword ptr [rbp-24], rcx         ; dst
    mov     qword ptr [rbp-32], r9          ; with_xor
    ; save xmm6..xmm11
    lea     r11, [rsp+SX6]
    movdqu  xmmword ptr [r11+0],  xmm6
    movdqu  xmmword ptr [r11+16], xmm7
    movdqu  xmmword ptr [r11+32], xmm8
    movdqu  xmmword ptr [r11+48], xmm9
    movdqu  xmmword ptr [r11+64], xmm10
    movdqu  xmmword ptr [r11+80], xmm11

    movdqa  xmm8, xmmword ptr [rot24_mask]
    movdqa  xmm9, xmmword ptr [rot16_mask]

    ; R = X ^ Y -> SR ; SS = R
    lea     r10, [rsp+SR]
    lea     r11, [rsp+WSS]
    xor     eax, eax
cs_xor:
    movdqu  xmm0, xmmword ptr [rdx+rax]
    movdqu  xmm1, xmmword ptr [r8+rax]
    pxor    xmm0, xmm1
    movdqu  xmmword ptr [r10+rax], xmm0
    movdqu  xmmword ptr [r11+rax], xmm0
    add     rax, 16
    cmp     rax, 1024
    jb      cs_xor

    ; 8 row rounds (contiguous 128-byte rows)
    xor     r9d, r9d
cs_row:
    lea     rcx, [rsp+WSS]
    mov     rax, r9
    shl     rax, 7
    add     rcx, rax
    DO_SROUND rcx, 16
    inc     r9d
    cmp     r9d, 8
    jb      cs_row

    ; 8 column rounds (stride 128)
    xor     r9d, r9d
cs_col:
    lea     rcx, [rsp+WSS]
    mov     rax, r9
    shl     rax, 4
    add     rcx, rax
    DO_SROUND rcx, 128
    inc     r9d
    cmp     r9d, 8
    jb      cs_col

    ; out = SS ^ SR ; with_xor: dst ^= that
    mov     rcx, qword ptr [rbp-24]
    lea     r10, [rsp+WSS]
    lea     r11, [rsp+SR]
    xor     eax, eax
cs_fin:
    movdqu  xmm0, xmmword ptr [r10+rax]
    movdqu  xmm1, xmmword ptr [r11+rax]
    pxor    xmm0, xmm1
    cmp     qword ptr [rbp-32], 0
    je      cs_store
    movdqu  xmm1, xmmword ptr [rcx+rax]
    pxor    xmm0, xmm1
cs_store:
    movdqu  xmmword ptr [rcx+rax], xmm0
    add     rax, 16
    cmp     rax, 1024
    jb      cs_fin

    lea     r11, [rsp+SX6]
    movdqu  xmm6,  xmmword ptr [r11+0]
    movdqu  xmm7,  xmmword ptr [r11+16]
    movdqu  xmm8,  xmmword ptr [r11+32]
    movdqu  xmm9,  xmmword ptr [r11+48]
    movdqu  xmm10, xmmword ptr [r11+64]
    movdqu  xmm11, xmmword ptr [r11+80]
    FRAME_EPILOG
    ret
argon2_compress_sse2 endp

; =============================================================================
; argon2_compress_avx2 - AVX2 BLAMKA (4-way, validated vs scalar KAT)
; rcx=dst, rdx=X, r8=Y, r9=with_xor
; ymm0..7 = A0,A1,B0,B1,C0,C1,D0,D1 ; ymm8/9 = rot masks ; ymm10..12 temps
; =============================================================================
AR    equ 32          ; R buffer (1024)
AW    equ 1056        ; working state (1024)
AX6   equ 2080        ; xmm6..xmm12 save (112)

VFBLA macro d, s
    vpmuludq ymm10, d, s
    vpaddq  ymm10, ymm10, ymm10
    vpaddq  d, d, s
    vpaddq  d, d, ymm10
endm
VROT63 macro r
    vpsrlq  ymm10, r, 63
    vpaddq  r, r, r
    vpor    r, r, ymm10
endm
AVX_G1 macro
    VFBLA   ymm0, ymm2
    VFBLA   ymm1, ymm3
    vpxor   ymm6, ymm6, ymm0
    vpxor   ymm7, ymm7, ymm1
    vpshufd ymm6, ymm6, 0B1h
    vpshufd ymm7, ymm7, 0B1h
    VFBLA   ymm4, ymm6
    VFBLA   ymm5, ymm7
    vpxor   ymm2, ymm2, ymm4
    vpxor   ymm3, ymm3, ymm5
    vpshufb ymm2, ymm2, ymm8
    vpshufb ymm3, ymm3, ymm8
endm
AVX_G2 macro
    VFBLA   ymm0, ymm2
    VFBLA   ymm1, ymm3
    vpxor   ymm6, ymm6, ymm0
    vpxor   ymm7, ymm7, ymm1
    vpshufb ymm6, ymm6, ymm9
    vpshufb ymm7, ymm7, ymm9
    VFBLA   ymm4, ymm6
    VFBLA   ymm5, ymm7
    vpxor   ymm2, ymm2, ymm4
    vpxor   ymm3, ymm3, ymm5
    VROT63  ymm2
    VROT63  ymm3
endm
; ROUND1 diagonalize: per-register vpermq
AVXROUND1 macro
    AVX_G1
    AVX_G2
    vpermq  ymm2, ymm2, 039h
    vpermq  ymm4, ymm4, 04Eh
    vpermq  ymm6, ymm6, 093h
    vpermq  ymm3, ymm3, 039h
    vpermq  ymm5, ymm5, 04Eh
    vpermq  ymm7, ymm7, 093h
    AVX_G1
    AVX_G2
    vpermq  ymm2, ymm2, 093h
    vpermq  ymm4, ymm4, 04Eh
    vpermq  ymm6, ymm6, 039h
    vpermq  ymm3, ymm3, 093h
    vpermq  ymm5, ymm5, 04Eh
    vpermq  ymm7, ymm7, 039h
endm
; ROUND2 diagonalize: blend + permute pairs
AVXROUND2 macro
    AVX_G1
    AVX_G2
    vpblendd ymm10, ymm2, ymm3, 0CCh
    vpblendd ymm11, ymm2, ymm3, 033h
    vpermq  ymm3, ymm10, 0B1h
    vpermq  ymm2, ymm11, 0B1h
    vmovdqa ymm12, ymm4
    vmovdqa ymm4, ymm5
    vmovdqa ymm5, ymm12
    vpblendd ymm10, ymm6, ymm7, 0CCh
    vpblendd ymm11, ymm6, ymm7, 033h
    vpermq  ymm6, ymm10, 0B1h
    vpermq  ymm7, ymm11, 0B1h
    AVX_G1
    AVX_G2
    vpblendd ymm10, ymm2, ymm3, 0CCh
    vpblendd ymm11, ymm2, ymm3, 033h
    vpermq  ymm2, ymm10, 0B1h
    vpermq  ymm3, ymm11, 0B1h
    vmovdqa ymm12, ymm4
    vmovdqa ymm4, ymm5
    vmovdqa ymm5, ymm12
    vpblendd ymm10, ymm6, ymm7, 033h
    vpblendd ymm11, ymm6, ymm7, 0CCh
    vpermq  ymm6, ymm10, 0B1h
    vpermq  ymm7, ymm11, 0B1h
endm
; load 8 ymm for a round from base with the offset list, run body, store back
DO_AVX macro basereg, o1,o2,o3,o4,o5,o6,o7, body
    vmovdqu ymm0, ymmword ptr [basereg + 0]
    vmovdqu ymm1, ymmword ptr [basereg + o1]
    vmovdqu ymm2, ymmword ptr [basereg + o2]
    vmovdqu ymm3, ymmword ptr [basereg + o3]
    vmovdqu ymm4, ymmword ptr [basereg + o4]
    vmovdqu ymm5, ymmword ptr [basereg + o5]
    vmovdqu ymm6, ymmword ptr [basereg + o6]
    vmovdqu ymm7, ymmword ptr [basereg + o7]
    body
    vmovdqu ymmword ptr [basereg + 0],  ymm0
    vmovdqu ymmword ptr [basereg + o1], ymm1
    vmovdqu ymmword ptr [basereg + o2], ymm2
    vmovdqu ymmword ptr [basereg + o3], ymm3
    vmovdqu ymmword ptr [basereg + o4], ymm4
    vmovdqu ymmword ptr [basereg + o5], ymm5
    vmovdqu ymmword ptr [basereg + o6], ymm6
    vmovdqu ymmword ptr [basereg + o7], ymm7
endm

argon2_compress_avx2 proc frame
    FRAME_PROLOG 2240
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], r9
    lea     r11, [rsp+AX6]
    movdqu  xmmword ptr [r11+0],  xmm6
    movdqu  xmmword ptr [r11+16], xmm7
    movdqu  xmmword ptr [r11+32], xmm8
    movdqu  xmmword ptr [r11+48], xmm9
    movdqu  xmmword ptr [r11+64], xmm10
    movdqu  xmmword ptr [r11+80], xmm11
    movdqu  xmmword ptr [r11+96], xmm12

    vmovdqu ymm8, ymmword ptr [rot24_mask256]
    vmovdqu ymm9, ymmword ptr [rot16_mask256]

    ; R = X ^ Y -> AR ; working = R
    lea     r10, [rsp+AR]
    lea     r11, [rsp+AW]
    xor     eax, eax
av_xor:
    vmovdqu ymm0, ymmword ptr [rdx+rax]
    vpxor   ymm0, ymm0, ymmword ptr [r8+rax]
    vmovdqu ymmword ptr [r10+rax], ymm0
    vmovdqu ymmword ptr [r11+rax], ymm0
    add     rax, 32
    cmp     rax, 1024
    jb      av_xor

    ; 4 row rounds (ROUND1): base = W + 256*i, offsets {128,32,160,64,192,96,224}
    lea     rcx, [rsp+AW]
    DO_AVX rcx, 128,32,160,64,192,96,224, AVXROUND1
    lea     rcx, [rsp+AW+256]
    DO_AVX rcx, 128,32,160,64,192,96,224, AVXROUND1
    lea     rcx, [rsp+AW+512]
    DO_AVX rcx, 128,32,160,64,192,96,224, AVXROUND1
    lea     rcx, [rsp+AW+768]
    DO_AVX rcx, 128,32,160,64,192,96,224, AVXROUND1

    ; 4 column rounds (ROUND2): base = W + 32*i, offsets {128,256,384,512,640,768,896}
    lea     rcx, [rsp+AW]
    DO_AVX rcx, 128,256,384,512,640,768,896, AVXROUND2
    lea     rcx, [rsp+AW+32]
    DO_AVX rcx, 128,256,384,512,640,768,896, AVXROUND2
    lea     rcx, [rsp+AW+64]
    DO_AVX rcx, 128,256,384,512,640,768,896, AVXROUND2
    lea     rcx, [rsp+AW+96]
    DO_AVX rcx, 128,256,384,512,640,768,896, AVXROUND2

    ; out = W ^ R ; with_xor: dst ^= that
    mov     rcx, qword ptr [rbp-24]
    lea     r10, [rsp+AW]
    lea     r11, [rsp+AR]
    xor     eax, eax
av_fin:
    vmovdqu ymm0, ymmword ptr [r10+rax]
    vpxor   ymm0, ymm0, ymmword ptr [r11+rax]
    cmp     qword ptr [rbp-32], 0
    je      av_store
    vpxor   ymm0, ymm0, ymmword ptr [rcx+rax]
av_store:
    vmovdqu ymmword ptr [rcx+rax], ymm0
    add     rax, 32
    cmp     rax, 1024
    jb      av_fin

    vzeroupper
    lea     r11, [rsp+AX6]
    movdqu  xmm6,  xmmword ptr [r11+0]
    movdqu  xmm7,  xmmword ptr [r11+16]
    movdqu  xmm8,  xmmword ptr [r11+32]
    movdqu  xmm9,  xmmword ptr [r11+48]
    movdqu  xmm10, xmmword ptr [r11+64]
    movdqu  xmm11, xmmword ptr [r11+80]
    movdqu  xmm12, xmmword ptr [r11+96]
    FRAME_EPILOG
    ret
argon2_compress_avx2 endp

; =============================================================================
; Driver state (single-threaded program -> globals keep the code clean and
; RIP-relative; the arena itself is VirtualAlloc'd).
; =============================================================================
.data
g_arena   dq 0
g_p       dq 0
g_t       dq 0
g_mb      dq 0            ; m_prime (blocks)
g_q       dq 0            ; columns per lane
g_seg     dq 0            ; segment length
g_type    dq 0
g_pass    dq 0
g_slice   dq 0
g_lane    dq 0
g_idx     dq 0
g_actr    dq 0            ; address counter (data-independent)
g_col     dq 0
g_prevcol dq 0
g_reflane dq 0
g_refidx  dq 0

.data?
align 16
g_b2bctx  db 256 dup (?)
g_hbuf    db 80 dup (?)   ; H0(64) || LE32(blk) || LE32(lane)
g_le4     db 8 dup (?)
align 16
g_inp     db 1024 dup (?)
g_addr    db 1024 dup (?)
g_zero    db 1024 dup (?) ; stays zero (BSS, never written)

.code

externdef blake2b_init:proc
externdef blake2b_update:proc
externdef blake2b_final:proc
ifdef DBG_TRACE
extern print_hex:proc
extern print_a:proc
.const
a2_nl db 13,10
.code
endif

; =============================================================================
; a2_blkptr(rcx = lane, rdx = col) -> rax = pointer to that 1024-byte block
; =============================================================================
a2_blkptr proc
    mov     rax, rcx
    imul    rax, qword ptr [g_q]
    add     rax, rdx
    shl     rax, 10
    add     rax, qword ptr [g_arena]
    ret
a2_blkptr endp

; ---------------------------------------------------------------------------
; UPD32 - blake2b_update(ctx=g_b2bctx, &g_le4, 4) with a 32-bit value in eax
; ---------------------------------------------------------------------------
UPD32 macro
    lea     r11, [g_le4]
    mov     dword ptr [r11], eax
    lea     rcx, [g_b2bctx]
    lea     rdx, [g_le4]
    mov     r8, 4
    call    blake2b_update
endm

; =============================================================================
; argon2id_hash(rcx = ARGON2REQ*) -> eax = 0 ok, 1 alloc failure
; =============================================================================
public argon2id_hash
argon2id_hash proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx     ; req

    ; ---- read params -------------------------------------------------------
    mov     eax, dword ptr [rcx].ARGON2REQ.lanes
    mov     qword ptr [g_p], rax
    mov     eax, dword ptr [rcx].ARGON2REQ.t_cost
    mov     qword ptr [g_t], rax
    mov     eax, dword ptr [rcx].ARGON2REQ.atype
    mov     qword ptr [g_type], rax

    ; ---- H0 = BLAKE2b-512 of the parameter encoding ------------------------
    lea     rcx, [g_b2bctx]
    mov     edx, 64
    call    blake2b_init
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.lanes
    UPD32                                    ; p
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.outlen
    UPD32                                    ; outlen
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.m_cost
    UPD32                                    ; m
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.t_cost
    UPD32                                    ; t
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.version
    UPD32                                    ; version
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.atype
    UPD32                                    ; type
    ; pwdlen, pwd
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.pwdlen
    UPD32
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rcx].ARGON2REQ.pwd
    mov     r8d, dword ptr [rcx].ARGON2REQ.pwdlen
    lea     rcx, [g_b2bctx]
    call    blake2b_update
    ; saltlen, salt
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.saltlen
    UPD32
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rcx].ARGON2REQ.salt
    mov     r8d, dword ptr [rcx].ARGON2REQ.saltlen
    lea     rcx, [g_b2bctx]
    call    blake2b_update
    ; secretlen, secret
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.secretlen
    UPD32
    mov     rcx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rcx].ARGON2REQ.secretlen
    test    r8d, r8d
    jz      a2_no_secret
    mov     rdx, qword ptr [rcx].ARGON2REQ.secret
    lea     rcx, [g_b2bctx]
    call    blake2b_update
a2_no_secret:
    ; adlen, ad
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.adlen
    UPD32
    mov     rcx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rcx].ARGON2REQ.adlen
    test    r8d, r8d
    jz      a2_no_ad
    mov     rdx, qword ptr [rcx].ARGON2REQ.ad
    lea     rcx, [g_b2bctx]
    call    blake2b_update
a2_no_ad:
    lea     rcx, [g_b2bctx]
    lea     rdx, [g_hbuf]                    ; H0 -> first 64 bytes of hbuf
    call    blake2b_final
ifdef DBG_TRACE
    lea     rcx, [g_hbuf]
    mov     edx, 8
    call    print_hex
    lea     rcx, [a2_nl]
    mov     edx, 2
    call    print_a
endif

    ; ---- geometry: m_prime, q, seg ----------------------------------------
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx].ARGON2REQ.m_cost
    mov     r8, qword ptr [g_p]
    shl     r8, 2                            ; 4p
    xor     rdx, rdx
    div     r8                               ; rax = m/(4p)
    mul     r8                               ; rax = floor(m/4p)*4p = m_prime
    mov     qword ptr [g_mb], rax
    xor     rdx, rdx
    div     qword ptr [g_p]                  ; q = m_prime/p
    mov     qword ptr [g_q], rax
    shr     rax, 2                           ; seg = q/4
    mov     qword ptr [g_seg], rax

    ; ---- allocate arena = m_prime * 1024 ----------------------------------
    mov     rax, qword ptr [g_mb]
    shl     rax, 10
    xor     rcx, rcx
    mov     rdx, rax
    mov     r8d, MEM_RESERVE or MEM_COMMIT
    mov     r9d, PAGE_READWRITE
    call    VirtualAlloc
    test    rax, rax
    jz      a2_fail
    mov     qword ptr [g_arena], rax

    ; ---- initial blocks B[i][0], B[i][1] ----------------------------------
    mov     qword ptr [g_lane], 0
a2_init_lane:
    mov     rax, qword ptr [g_lane]
    cmp     rax, qword ptr [g_p]
    jae     a2_fill
    ; block 0
    lea     r11, [g_hbuf]
    mov     dword ptr [r11+64], 0
    mov     eax, dword ptr [g_lane]
    mov     dword ptr [r11+68], eax
    mov     rcx, qword ptr [g_lane]
    xor     rdx, rdx
    call    a2_blkptr
    mov     rcx, rax
    mov     edx, 1024
    lea     r8, [g_hbuf]
    mov     r9, 72
    call    blake2b_long
    ; block 1
    lea     r11, [g_hbuf]
    mov     dword ptr [r11+64], 1
    mov     eax, dword ptr [g_lane]
    mov     dword ptr [r11+68], eax
    mov     rcx, qword ptr [g_lane]
    mov     rdx, 1
    call    a2_blkptr
    mov     rcx, rax
    mov     edx, 1024
    lea     r8, [g_hbuf]
    mov     r9, 72
    call    blake2b_long
    inc     qword ptr [g_lane]
    jmp     a2_init_lane

    ; =====================================================================
    ; fill loop
    ; =====================================================================
a2_fill:
ifdef DBG_TRACE
    mov     rcx, qword ptr [g_arena]
    mov     edx, 8
    call    print_hex
    lea     rcx, [a2_nl]
    mov     edx, 2
    call    print_a
    cmp     qword ptr [g_p], 2          ; B[1][0] only exists when p >= 2
    jb      a2_dbg_skip_b10
    mov     rcx, qword ptr [g_arena]
    mov     rax, qword ptr [g_q]
    shl     rax, 10
    add     rcx, rax
    mov     edx, 8
    call    print_hex
    lea     rcx, [a2_nl]
    mov     edx, 2
    call    print_a
a2_dbg_skip_b10:
endif
    mov     qword ptr [g_pass], 0
a2_pass:
    mov     rax, qword ptr [g_pass]
    cmp     rax, qword ptr [g_t]
    jae     a2_finalize
    mov     qword ptr [g_slice], 0
a2_slice:
    cmp     qword ptr [g_slice], 4
    jae     a2_pass_next
    mov     qword ptr [g_lane], 0
a2_lane:
    mov     rax, qword ptr [g_lane]
    cmp     rax, qword ptr [g_p]
    jae     a2_slice_next

    ; data-independent addressing?  (argon2id: type==2 && pass==0 && slice<2)
    mov     qword ptr [g_actr], 0
    cmp     qword ptr [g_type], 2
    jne     a2_setup_done
    cmp     qword ptr [g_pass], 0
    jne     a2_setup_done
    cmp     qword ptr [g_slice], 2
    jae     a2_setup_done
    ; set up inp block for address generation
    lea     rcx, [g_inp]
    mov     rdx, 1024
    call    secure_zero
    lea     r11, [g_inp]
    mov     rax, qword ptr [g_pass]
    mov     qword ptr [r11+0], rax
    mov     rax, qword ptr [g_lane]
    mov     qword ptr [r11+8], rax
    mov     rax, qword ptr [g_slice]
    mov     qword ptr [r11+16], rax
    mov     rax, qword ptr [g_mb]
    mov     qword ptr [r11+24], rax
    mov     rax, qword ptr [g_t]
    mov     qword ptr [r11+32], rax
    mov     rax, qword ptr [g_type]
    mov     qword ptr [r11+40], rax
    mov     qword ptr [r11+48], 0            ; v[6] counter
a2_setup_done:

    ; start index in segment
    mov     qword ptr [g_idx], 0
    cmp     qword ptr [g_pass], 0
    jne     a2_idx_loop
    cmp     qword ptr [g_slice], 0
    jne     a2_idx_loop
    mov     qword ptr [g_idx], 2

a2_idx_loop:
    mov     rax, qword ptr [g_idx]
    cmp     rax, qword ptr [g_seg]
    jae     a2_lane_next

    ; col = slice*seg + idx ; prevcol = (col==0)? q-1 : col-1
    mov     rax, qword ptr [g_slice]
    imul    rax, qword ptr [g_seg]
    add     rax, qword ptr [g_idx]
    mov     qword ptr [g_col], rax
    test    rax, rax
    jnz     a2_pc_norm
    mov     rax, qword ptr [g_q]
    dec     rax
    mov     qword ptr [g_prevcol], rax
    jmp     a2_pc_done
a2_pc_norm:
    dec     rax
    mov     qword ptr [g_prevcol], rax
a2_pc_done:

    ; ---- pseudo-random rnd into r15 ----------------------------------------
    cmp     qword ptr [g_type], 2
    jne     a2_rnd_dep
    cmp     qword ptr [g_pass], 0
    jne     a2_rnd_dep
    cmp     qword ptr [g_slice], 2
    jae     a2_rnd_dep
    ; data-independent: regenerate addr block every 128 values
    mov     rax, qword ptr [g_actr]
    and     rax, 127
    jnz     a2_addr_use
    lea     r11, [g_inp]
    inc     qword ptr [r11+48]              ; inp.v[6]++
    lea     rcx, [g_addr]
    lea     rdx, [g_zero]
    lea     r8, [g_inp]
    xor     r9d, r9d
    call    argon2_compress
    lea     rcx, [g_addr]
    lea     rdx, [g_zero]
    lea     r8, [g_addr]
    xor     r9d, r9d
    call    argon2_compress
a2_addr_use:
    mov     rax, qword ptr [g_actr]
    and     rax, 127
    lea     r11, [g_addr]
    mov     r15, qword ptr [r11+rax*8]
    inc     qword ptr [g_actr]
    jmp     a2_have_rnd
a2_rnd_dep:
    mov     rcx, qword ptr [g_lane]
    mov     rdx, qword ptr [g_prevcol]
    call    a2_blkptr
    mov     r15, qword ptr [rax]
a2_have_rnd:

    ; ---- reference lane ----------------------------------------------------
    ; refLane = (pass==0 && slice==0) ? lane : (J2 % p)
    mov     rax, qword ptr [g_pass]
    or      rax, qword ptr [g_slice]
    jnz     a2_rl_mod
    mov     rax, qword ptr [g_lane]
    mov     qword ptr [g_reflane], rax
    jmp     a2_rl_done
a2_rl_mod:
    mov     rax, r15
    shr     rax, 32                          ; J2
    xor     rdx, rdx
    div     qword ptr [g_p]
    mov     qword ptr [g_reflane], rdx
a2_rl_done:

    ; ---- reference area (r11) ----------------------------------------------
    mov     r10, qword ptr [g_reflane]
    cmp     qword ptr [g_pass], 0
    jne     a2_area_passN
    cmp     qword ptr [g_slice], 0
    jne     a2_area_p0sN
    ; pass0 slice0: area = col-1
    mov     r11, qword ptr [g_col]
    dec     r11
    jmp     a2_area_done
a2_area_p0sN:
    mov     rax, qword ptr [g_slice]
    imul    rax, qword ptr [g_seg]           ; s*seg
    cmp     r10, qword ptr [g_lane]
    jne     a2_area_p0_oth
    add     rax, qword ptr [g_idx]
    dec     rax
    mov     r11, rax
    jmp     a2_area_done
a2_area_p0_oth:
    cmp     qword ptr [g_idx], 0
    jne     a2_area_done_mov1
    dec     rax
a2_area_done_mov1:
    mov     r11, rax
    jmp     a2_area_done
a2_area_passN:
    mov     rax, qword ptr [g_q]
    sub     rax, qword ptr [g_seg]           ; q-seg
    cmp     r10, qword ptr [g_lane]
    jne     a2_area_pN_oth
    add     rax, qword ptr [g_idx]
    dec     rax
    mov     r11, rax
    jmp     a2_area_done
a2_area_pN_oth:
    cmp     qword ptr [g_idx], 0
    jne     a2_area_done_mov2
    dec     rax
a2_area_done_mov2:
    mov     r11, rax
a2_area_done:

    ; ---- z = area-1 - ((area * ((J1^2)>>32)) >> 32) ------------------------
    mov     eax, r15d                        ; J1 = low32(rnd), zero-extended
    imul    rax, rax                         ; J1^2 (fits 64)
    shr     rax, 32                          ; x
    imul    rax, r11                         ; area * x
    shr     rax, 32                          ; y
    mov     rdx, r11
    dec     rdx
    sub     rdx, rax                         ; z (in rdx)

    ; ---- startpos = (pass!=0 && slice!=3) ? (slice+1)*seg : 0 --------------
    xor     r8, r8
    cmp     qword ptr [g_pass], 0
    je      a2_ri_have
    cmp     qword ptr [g_slice], 3
    je      a2_ri_have
    mov     rax, qword ptr [g_slice]
    inc     rax
    imul    rax, qword ptr [g_seg]
    mov     r8, rax
a2_ri_have:
    ; refIndex = (startpos + z) % q
    add     r8, rdx
    mov     rax, r8
    xor     rdx, rdx
    div     qword ptr [g_q]
    mov     qword ptr [g_refidx], rdx

    ; ---- compress: cur = G(prev, ref), with_xor = (pass != 0) -------------
    mov     rcx, qword ptr [g_reflane]
    mov     rdx, qword ptr [g_refidx]
    call    a2_blkptr
    mov     r12, rax                         ; ref ptr
    mov     rcx, qword ptr [g_lane]
    mov     rdx, qword ptr [g_prevcol]
    call    a2_blkptr
    mov     r13, rax                         ; prev ptr
    mov     rcx, qword ptr [g_lane]
    mov     rdx, qword ptr [g_col]
    call    a2_blkptr                        ; cur ptr in rax
    mov     rcx, rax                         ; dst = cur
    mov     rdx, r13                         ; X = prev
    mov     r8, r12                          ; Y = ref
    xor     r9d, r9d
    cmp     qword ptr [g_pass], 0
    je      a2_comp
    mov     r9d, 1                           ; with_xor on later passes
a2_comp:
    call    argon2_compress
ifdef DBG_TRACE
    jmp     a2_dbg_skip                 ; per-block fill dump disabled (noisy)
    cmp     qword ptr [g_pass], 0
    jne     a2_dbg_skip
    cmp     qword ptr [g_lane], 0
    jne     a2_dbg_skip
    lea     rcx, [g_reflane]            ; refLane
    mov     edx, 8
    call    print_hex
    lea     rcx, [a2_nl]
    mov     edx, 2
    call    print_a
    lea     rcx, [g_refidx]             ; refIdx
    mov     edx, 8
    call    print_hex
    lea     rcx, [a2_nl]
    mov     edx, 2
    call    print_a
    mov     rcx, qword ptr [g_lane]
    mov     rdx, qword ptr [g_col]
    call    a2_blkptr
    mov     rcx, rax
    mov     edx, 8
    call    print_hex
    lea     rcx, [a2_nl]
    mov     edx, 2
    call    print_a
a2_dbg_skip:
endif

    inc     qword ptr [g_idx]
    jmp     a2_idx_loop

a2_lane_next:
    inc     qword ptr [g_lane]
    jmp     a2_lane
a2_slice_next:
    inc     qword ptr [g_slice]
    jmp     a2_slice
a2_pass_next:
    inc     qword ptr [g_pass]
    jmp     a2_pass

    ; =====================================================================
    ; finalize: C = XOR of last column of every lane ; out = H'(C)
    ; =====================================================================
a2_finalize:
    ; accumulate into B[0][q-1] (reuse as C)
    mov     rcx, 0
    mov     rdx, qword ptr [g_q]
    dec     rdx
    call    a2_blkptr
    mov     r13, rax                         ; C ptr = lane0 last block
    mov     qword ptr [g_lane], 1
a2_fin_lane:
    mov     rax, qword ptr [g_lane]
    cmp     rax, qword ptr [g_p]
    jae     a2_emit
    mov     rcx, qword ptr [g_lane]
    mov     rdx, qword ptr [g_q]
    dec     rdx
    call    a2_blkptr                        ; lane i last block
    ; C ^= block (1024 bytes)
    xor     r9d, r9d
a2_fin_xor:
    movdqu  xmm0, xmmword ptr [r13+r9]
    movdqu  xmm1, xmmword ptr [rax+r9]
    pxor    xmm0, xmm1
    movdqu  xmmword ptr [r13+r9], xmm0
    add     r9, 16
    cmp     r9, 1024
    jb      a2_fin_xor
    inc     qword ptr [g_lane]
    jmp     a2_fin_lane

a2_emit:
ifdef DBG_TRACE
    mov     rcx, r13
    mov     edx, 8
    call    print_hex
    lea     rcx, [a2_nl]
    mov     edx, 2
    call    print_a
endif
    ; out = H'(outlen, C)
    mov     rcx, qword ptr [rbp-24]
    mov     rcx, qword ptr [rcx].ARGON2REQ.outp
    mov     r9, qword ptr [rbp-24]
    mov     edx, dword ptr [r9].ARGON2REQ.outlen
    mov     r8, r13                          ; C (1024 bytes)
    mov     r9, 1024
    call    blake2b_long

    ; H0 is key-equivalent - the whole derivation is deterministic from it and
    ; the public parameters - so it dies here rather than sitting in .data?
    ; until the process ends.  a2_fail wipes it too: H0 exists there as well.
    lea     rcx, [g_hbuf]
    mov     rdx, 80
    call    secure_zero
    ; wipe + free arena
    mov     rcx, qword ptr [g_arena]
    mov     rdx, qword ptr [g_mb]
    shl     rdx, 10
    call    secure_zero
    mov     rcx, qword ptr [g_arena]
    xor     edx, edx
    mov     r8d, MEM_RELEASE
    call    VirtualFree

    xor     eax, eax
    FRAME_EPILOG
    ret
a2_fail:
    lea     rcx, [g_hbuf]
    mov     rdx, 80
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret
argon2id_hash endp

end
