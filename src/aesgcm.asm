; =============================================================================
; aesgcm.asm - AES-256-GCM using AES-NI + PCLMULQDQ
; -----------------------------------------------------------------------------
;   gcm_seal(rcx = GCMREQ*)  -> writes ciphertext + 16-byte tag
;   gcm_open(rcx = GCMREQ*)  -> eax = 0 if tag valid (plaintext written), 1 else
;
; One-shot over in-memory buffers.  Instruction sequences are transcribed from
; sandbox-validated intrinsics (FIPS-197 AES-256 vector + NIST SP800-38D GCM).
; GHASH runs in the byte-reflected domain: H and Y are stored byte-swapped and
; the canonical shift-based reduction is used (no secret-dependent branches).
; =============================================================================

include macros.inc

extern ct_memcmp:proc
extern secure_zero:proc

; Request block shared by seal/open
GCMREQ struct
    key     dq ?            ; -> 32-byte key
    iv      dq ?            ; -> 12-byte nonce
    aad     dq ?            ; -> additional authenticated data
    aadlen  dq ?
    inp     dq ?            ; -> plaintext (seal) / ciphertext (open)
    inlen   dq ?
    outp    dq ?            ; -> ciphertext (seal) / plaintext (open)
    tag     dq ?            ; -> 16-byte tag (out for seal, in for open)
GCMREQ ends

.const
align 16
bswap_mask db 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0

.code

; =============================================================================
; aes256_expand(rcx = key ptr, rdx = round-key out, 15*16 bytes)
; Leaf.  Uses xmm0..xmm4 (volatile).
; =============================================================================
; helper macro: a ^= a<<4bytes (thrice), then a ^= t ; result in xmm3, store
EXP_CORE macro srcreg
    movdqa  xmm3, srcreg
    movdqa  xmm4, xmm3
    pslldq  xmm4, 4
    pxor    xmm3, xmm4
    movdqa  xmm4, xmm3
    pslldq  xmm4, 4
    pxor    xmm3, xmm4
    movdqa  xmm4, xmm3
    pslldq  xmm4, 4
    pxor    xmm3, xmm4
    pxor    xmm3, xmm2
endm

EXPA macro rcon                         ; updates k0 (xmm0) from k1 (xmm1)
    aeskeygenassist xmm2, xmm1, rcon
    pshufd  xmm2, xmm2, 0FFh
    EXP_CORE xmm0
    movdqa  xmm0, xmm3
endm

EXPB macro                              ; updates k1 (xmm1) from k0 (xmm0)
    aeskeygenassist xmm2, xmm0, 0
    pshufd  xmm2, xmm2, 0AAh
    EXP_CORE xmm1
    movdqa  xmm1, xmm3
endm

public aes256_expand
aes256_expand proc
    movdqu  xmm0, xmmword ptr [rcx]          ; k0
    movdqu  xmm1, xmmword ptr [rcx+16]       ; k1
    movdqu  xmmword ptr [rdx+0],  xmm0
    movdqu  xmmword ptr [rdx+16], xmm1
    EXPA 01h
    movdqu  xmmword ptr [rdx+32], xmm0
    EXPB
    movdqu  xmmword ptr [rdx+48], xmm1
    EXPA 02h
    movdqu  xmmword ptr [rdx+64], xmm0
    EXPB
    movdqu  xmmword ptr [rdx+80], xmm1
    EXPA 04h
    movdqu  xmmword ptr [rdx+96], xmm0
    EXPB
    movdqu  xmmword ptr [rdx+112], xmm1
    EXPA 08h
    movdqu  xmmword ptr [rdx+128], xmm0
    EXPB
    movdqu  xmmword ptr [rdx+144], xmm1
    EXPA 10h
    movdqu  xmmword ptr [rdx+160], xmm0
    EXPB
    movdqu  xmmword ptr [rdx+176], xmm1
    EXPA 20h
    movdqu  xmmword ptr [rdx+192], xmm0
    EXPB
    movdqu  xmmword ptr [rdx+208], xmm1
    EXPA 40h
    movdqu  xmmword ptr [rdx+224], xmm0
    ret
aes256_expand endp

; ---------------------------------------------------------------------------
; AES_ENC reg, rkbase, ktmp - encrypt 128-bit block in 'reg' with 15 round
; keys at [rkbase].  ktmp is a scratch xmm.
; ---------------------------------------------------------------------------
AES_ENC macro reg, rkbase, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+0]
    pxor    reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+16]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+32]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+48]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+64]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+80]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+96]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+112]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+128]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+144]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+160]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+176]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+192]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+208]
    aesenc  reg, ktmp
    movdqu  ktmp, xmmword ptr [rkbase+224]
    aesenclast reg, ktmp
endm

; =============================================================================
; gf_mul(xmm1 = Y, xmm2 = H) -> xmm1 = Y*H in GF(2^128), reflected domain.
; Canonical Intel shift-reduction.  Clobbers xmm3..xmm9 (caller saves those).
; Implemented as a macro so the GHASH loop stays register-resident.
; =============================================================================
GF_MUL macro
    ; t3=clmul(a,b,00) t4=clmul(a,b,10) t5=clmul(a,b,01) t6=clmul(a,b,11)
    movdqa      xmm3, xmm1
    pclmulqdq   xmm3, xmm2, 000h
    movdqa      xmm4, xmm1
    pclmulqdq   xmm4, xmm2, 010h
    movdqa      xmm5, xmm1
    pclmulqdq   xmm5, xmm2, 001h
    movdqa      xmm6, xmm1
    pclmulqdq   xmm6, xmm2, 011h
    pxor        xmm4, xmm5
    movdqa      xmm5, xmm4
    pslldq      xmm5, 8
    psrldq      xmm4, 8
    pxor        xmm3, xmm5              ; xmm3 = lo (t3)
    pxor        xmm6, xmm4              ; xmm6 = hi (t6)
    ; reduce: <<1 reflection then mod
    movdqa      xmm7, xmm3
    psrld       xmm7, 31
    movdqa      xmm8, xmm6
    psrld       xmm8, 31
    pslld       xmm3, 1
    pslld       xmm6, 1
    movdqa      xmm9, xmm7
    psrldq      xmm9, 12
    pslldq      xmm8, 4
    pslldq      xmm7, 4
    por         xmm3, xmm7
    por         xmm6, xmm8
    por         xmm6, xmm9
    movdqa      xmm7, xmm3
    pslld       xmm7, 31
    movdqa      xmm8, xmm3
    pslld       xmm8, 30
    movdqa      xmm9, xmm3
    pslld       xmm9, 25
    pxor        xmm7, xmm8
    pxor        xmm7, xmm9
    movdqa      xmm8, xmm7
    psrldq      xmm8, 4
    pslldq      xmm7, 12
    pxor        xmm3, xmm7
    movdqa      xmm5, xmm3
    psrld       xmm5, 1
    movdqa      xmm4, xmm3
    psrld       xmm4, 2
    movdqa      xmm7, xmm3
    psrld       xmm7, 7
    pxor        xmm5, xmm4
    pxor        xmm5, xmm7
    pxor        xmm5, xmm8
    pxor        xmm3, xmm5
    pxor        xmm6, xmm3
    movdqa      xmm1, xmm6              ; Y = result
endm

; ---------------------------------------------------------------------------
; CTR_INC base - increment the big-endian 32-bit counter at [base+12]
; ---------------------------------------------------------------------------
CTR_INC macro base
    mov     eax, dword ptr [base+12]
    bswap   eax
    inc     eax
    bswap   eax
    mov     dword ptr [base+12], eax
endm


; =============================================================================
; Streaming GCM context (caller-allocated).  Field offsets:
; =============================================================================
GC_RK   equ 0            ; 240  round keys
GC_H    equ 240          ; 16   hash subkey (reflected)
GC_Y    equ 256          ; 16   GHASH accumulator (reflected)
GC_J0   equ 272          ; 16   pre-counter block
GC_CTR  equ 288          ; 16   running counter
GC_AADN equ 304          ; 8    total AAD bytes
GC_PTN  equ 312          ; 8    total data bytes
GC_MODE equ 320          ; 8    0 = seal, 1 = open
public GCM_CTX_SIZE
GCM_CTX_SIZE equ 336

; ---------------------------------------------------------------------------
; GHASH one 16-byte block at [memreg] into xmm1 (Y); H in xmm2, mask in xmm14
; ---------------------------------------------------------------------------
GHASH_MEM macro memreg
    movdqu  xmm0, xmmword ptr [memreg]
    pshufb  xmm0, xmm14
    pxor    xmm1, xmm0
    GF_MUL
endm

; =============================================================================
; gcm_init(rcx = ctx, rdx = key, r8 = iv, r9 = mode)
; rsp layout: [rsp+32]=xmm14 save [rsp+48]=ctx [rsp+56]=iv [rsp+64]=mode
; =============================================================================
public gcm_init
gcm_init proc frame
    FRAME_PROLOG 80
    movdqu  xmmword ptr [rsp+32], xmm14
    mov     qword ptr [rsp+48], rcx
    mov     qword ptr [rsp+56], r8
    mov     qword ptr [rsp+64], r9

    mov     rcx, rdx                    ; key
    mov     rax, qword ptr [rsp+48]
    lea     rdx, [rax+GC_RK]
    call    aes256_expand

    mov     rax, qword ptr [rsp+48]
    mov     r9, qword ptr [rsp+64]
    mov     qword ptr [rax+GC_MODE], r9

    movdqu  xmm14, xmmword ptr [bswap_mask]
    pxor    xmm0, xmm0
    lea     r10, [rax+GC_RK]
    AES_ENC xmm0, r10, xmm5
    pshufb  xmm0, xmm14
    mov     rax, qword ptr [rsp+48]
    movdqu  xmmword ptr [rax+GC_H], xmm0

    mov     r8, qword ptr [rsp+56]       ; iv
    mov     ecx, dword ptr [r8+0]
    mov     dword ptr [rax+GC_J0+0], ecx
    mov     ecx, dword ptr [r8+4]
    mov     dword ptr [rax+GC_J0+4], ecx
    mov     ecx, dword ptr [r8+8]
    mov     dword ptr [rax+GC_J0+8], ecx
    mov     dword ptr [rax+GC_J0+12], 01000000h
    movdqu  xmm0, xmmword ptr [rax+GC_J0]
    movdqu  xmmword ptr [rax+GC_CTR], xmm0

    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rax+GC_Y], xmm0
    mov     qword ptr [rax+GC_AADN], 0
    mov     qword ptr [rax+GC_PTN], 0

    movdqu  xmm14, xmmword ptr [rsp+32]
    FRAME_EPILOG
    ret
gcm_init endp

; =============================================================================
; gcm_aad(rcx = ctx, rdx = aad, r8 = len)
; rsp layout: [rsp+32..111]=xmm6,7,8,9,14  [rsp+112]=tail(16)  [rsp+128]=ctx
; =============================================================================
public gcm_aad
gcm_aad proc frame
    FRAME_PROLOG 144
    movdqu  xmmword ptr [rsp+32],  xmm6
    movdqu  xmmword ptr [rsp+48],  xmm7
    movdqu  xmmword ptr [rsp+64],  xmm8
    movdqu  xmmword ptr [rsp+80],  xmm9
    movdqu  xmmword ptr [rsp+96],  xmm14
    mov     qword ptr [rsp+128], rcx

    movdqu  xmm1, xmmword ptr [rcx+GC_Y]
    movdqu  xmm2, xmmword ptr [rcx+GC_H]
    movdqu  xmm14, xmmword ptr [bswap_mask]
    add     qword ptr [rcx+GC_AADN], r8

    mov     r10, rdx
    mov     r11, r8
ga_loop:
    cmp     r11, 16
    jb      ga_tail
    GHASH_MEM r10
    add     r10, 16
    sub     r11, 16
    jmp     ga_loop
ga_tail:
    test    r11, r11
    jz      ga_done
    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+112], xmm0
    xor     r9d, r9d
ga_tcopy:
    mov     al, byte ptr [r10+r9]
    mov     byte ptr [rsp+112+r9], al
    inc     r9
    cmp     r9, r11
    jb      ga_tcopy
    lea     r10, [rsp+112]
    GHASH_MEM r10
ga_done:
    mov     rax, qword ptr [rsp+128]
    movdqu  xmmword ptr [rax+GC_Y], xmm1

    movdqu  xmm6,  xmmword ptr [rsp+32]
    movdqu  xmm7,  xmmword ptr [rsp+48]
    movdqu  xmm8,  xmmword ptr [rsp+64]
    movdqu  xmm9,  xmmword ptr [rsp+80]
    movdqu  xmm14, xmmword ptr [rsp+96]
    FRAME_EPILOG
    ret
gcm_aad endp

; =============================================================================
; gcm_crypt(rcx = ctx, rdx = in, r8 = out, r9 = len)
; rsp layout: [rsp+32..111]=xmm6,7,8,9,14  [rsp+112..143]=r12,13,14,15
;             [rsp+144]=tail(16)
; ctx=r12 in=r13 out=r14 remaining=r15.  Only final call may be len%16!=0.
; =============================================================================
public gcm_crypt
gcm_crypt proc frame
    FRAME_PROLOG 192
    movdqu  xmmword ptr [rsp+32],  xmm6
    movdqu  xmmword ptr [rsp+48],  xmm7
    movdqu  xmmword ptr [rsp+64],  xmm8
    movdqu  xmmword ptr [rsp+80],  xmm9
    movdqu  xmmword ptr [rsp+96],  xmm14
    mov     qword ptr [rsp+112], r12
    mov     qword ptr [rsp+120], r13
    mov     qword ptr [rsp+128], r14
    mov     qword ptr [rsp+136], r15

    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8
    mov     r15, r9
    add     qword ptr [r12+GC_PTN], r9

    movdqu  xmm1, xmmword ptr [r12+GC_Y]
    movdqu  xmm2, xmmword ptr [r12+GC_H]
    movdqu  xmm14, xmmword ptr [bswap_mask]

gx_loop:
    cmp     r15, 16
    jb      gx_tail
    movdqu  xmm6, xmmword ptr [r13]
    lea     r10, [r12+GC_CTR]
    CTR_INC r10
    movdqu  xmm0, xmmword ptr [r12+GC_CTR]
    lea     r10, [r12+GC_RK]
    AES_ENC xmm0, r10, xmm5
    pxor    xmm0, xmm6
    movdqu  xmmword ptr [r14], xmm0
    cmp     qword ptr [r12+GC_MODE], 0
    jne     gx_open_gh
    pshufb  xmm0, xmm14
    pxor    xmm1, xmm0
    jmp     gx_gh_mul
gx_open_gh:
    pshufb  xmm6, xmm14
    pxor    xmm1, xmm6
gx_gh_mul:
    GF_MUL
    add     r13, 16
    add     r14, 16
    sub     r15, 16
    jmp     gx_loop

gx_tail:
    test    r15, r15
    jz      gx_done
    ; keystream for the partial block -> [rsp+144]
    lea     r10, [r12+GC_CTR]
    CTR_INC r10
    movdqu  xmm0, xmmword ptr [r12+GC_CTR]
    lea     r10, [r12+GC_RK]
    AES_ENC xmm0, r10, xmm5
    movdqu  xmmword ptr [rsp+144], xmm0
    ; zero the GHASH (ciphertext) buffer
    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+160], xmm0
    ; build output AND the zero-padded ciphertext, reading input before it is
    ; overwritten (safe even when in == out).
    xor     r9d, r9d
gx_tbuild:
    movzx   eax, byte ptr [r13+r9]              ; input byte
    mov     r8b, byte ptr [rsp+144+r9]          ; keystream byte
    cmp     qword ptr [r12+GC_MODE], 0
    jne     gx_tb_open
    ; seal: ct = in ^ ks ; ghash ct ; out = ct
    xor     al, r8b
    mov     byte ptr [rsp+160+r9], al
    mov     byte ptr [r14+r9], al
    jmp     gx_tb_next
gx_tb_open:
    ; open: ct = in (capture for ghash) ; out = in ^ ks
    mov     byte ptr [rsp+160+r9], al
    xor     al, r8b
    mov     byte ptr [r14+r9], al
gx_tb_next:
    inc     r9
    cmp     r9, r15
    jb      gx_tbuild
    lea     r10, [rsp+160]
    GHASH_MEM r10
gx_done:
    movdqu  xmmword ptr [r12+GC_Y], xmm1

    movdqu  xmm6,  xmmword ptr [rsp+32]
    movdqu  xmm7,  xmmword ptr [rsp+48]
    movdqu  xmm8,  xmmword ptr [rsp+64]
    movdqu  xmm9,  xmmword ptr [rsp+80]
    movdqu  xmm14, xmmword ptr [rsp+96]
    mov     r12, qword ptr [rsp+112]
    mov     r13, qword ptr [rsp+120]
    mov     r14, qword ptr [rsp+128]
    mov     r15, qword ptr [rsp+136]
    FRAME_EPILOG
    ret
gcm_crypt endp

; =============================================================================
; gcm_final(rcx = ctx, rdx = tag out 16 bytes)
; rsp layout: [rsp+32..111]=xmm6,7,8,9,14  [rsp+112]=lenblk(16)
;             [rsp+128]=ctx  [rsp+136]=tag
; =============================================================================
public gcm_final
gcm_final proc frame
    FRAME_PROLOG 160
    movdqu  xmmword ptr [rsp+32],  xmm6
    movdqu  xmmword ptr [rsp+48],  xmm7
    movdqu  xmmword ptr [rsp+64],  xmm8
    movdqu  xmmword ptr [rsp+80],  xmm9
    movdqu  xmmword ptr [rsp+96],  xmm14
    mov     qword ptr [rsp+128], rcx
    mov     qword ptr [rsp+136], rdx

    movdqu  xmm1, xmmword ptr [rcx+GC_Y]
    movdqu  xmm2, xmmword ptr [rcx+GC_H]
    movdqu  xmm14, xmmword ptr [bswap_mask]

    mov     rax, qword ptr [rcx+GC_AADN]
    shl     rax, 3
    bswap   rax
    mov     qword ptr [rsp+112], rax
    mov     rax, qword ptr [rcx+GC_PTN]
    shl     rax, 3
    bswap   rax
    mov     qword ptr [rsp+120], rax
    lea     r10, [rsp+112]
    GHASH_MEM r10

    movdqa  xmm0, xmm1
    pshufb  xmm0, xmm14
    mov     rcx, qword ptr [rsp+128]
    movdqu  xmm5, xmmword ptr [rcx+GC_J0]
    lea     r10, [rcx+GC_RK]
    AES_ENC xmm5, r10, xmm6
    pxor    xmm0, xmm5
    mov     rdx, qword ptr [rsp+136]
    movdqu  xmmword ptr [rdx], xmm0

    movdqu  xmm6,  xmmword ptr [rsp+32]
    movdqu  xmm7,  xmmword ptr [rsp+48]
    movdqu  xmm8,  xmmword ptr [rsp+64]
    movdqu  xmm9,  xmmword ptr [rsp+80]
    movdqu  xmm14, xmmword ptr [rsp+96]
    FRAME_EPILOG
    ret
gcm_final endp

; =============================================================================
; gcm_seal(rcx = GCMREQ*) -> eax = 0   (one-shot wrapper)
; =============================================================================
public gcm_seal
gcm_seal proc frame
    FRAME_PROLOG 64 + GCM_CTX_SIZE
    mov     qword ptr [rbp-24], rcx
    lea     rax, [rsp+32]
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10].GCMREQ.key
    mov     r8,  qword ptr [r10].GCMREQ.iv
    xor     r9, r9
    call    gcm_init
    mov     rcx, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10].GCMREQ.aad
    mov     r8,  qword ptr [r10].GCMREQ.aadlen
    call    gcm_aad
    mov     rcx, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10].GCMREQ.inp
    mov     r8,  qword ptr [r10].GCMREQ.outp
    mov     r9,  qword ptr [r10].GCMREQ.inlen
    call    gcm_crypt
    mov     rcx, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10].GCMREQ.tag
    call    gcm_final
    ; the ctx holds the full expanded key schedule, on the (pageable) stack -
    ; it does not outlive the call
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, GCM_CTX_SIZE
    call    secure_zero
    xor     eax, eax
    FRAME_EPILOG
    ret
gcm_seal endp

; =============================================================================
; gcm_open(rcx = GCMREQ*) -> eax = 0 if tag valid, 1 otherwise
; =============================================================================
public gcm_open
gcm_open proc frame
    FRAME_PROLOG 64 + GCM_CTX_SIZE + 16
    mov     qword ptr [rbp-24], rcx
    lea     rax, [rsp+32]
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10].GCMREQ.key
    mov     r8,  qword ptr [r10].GCMREQ.iv
    mov     r9, 1
    call    gcm_init
    mov     rcx, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10].GCMREQ.aad
    mov     r8,  qword ptr [r10].GCMREQ.aadlen
    call    gcm_aad
    mov     rcx, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10].GCMREQ.inp
    mov     r8,  qword ptr [r10].GCMREQ.outp
    mov     r9,  qword ptr [r10].GCMREQ.inlen
    call    gcm_crypt
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [rsp+32+GCM_CTX_SIZE]
    call    gcm_final
    lea     rcx, [rsp+32+GCM_CTX_SIZE]
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10].GCMREQ.tag
    mov     r8, 16
    call    ct_memcmp
    ; wipe the ctx (round keys) AND the computed tag behind it, preserving the
    ; compare result - they are contiguous, so one call covers both
    mov     dword ptr [rbp-40], eax
    lea     rcx, [rsp+32]
    mov     rdx, GCM_CTX_SIZE + 16
    call    secure_zero
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
gcm_open endp

; =============================================================================
; Variable-key-size AES (128/192/256) for the WinZip-AES ZIP extractor.
; -----------------------------------------------------------------------------
; The GCM path above uses the dedicated AES-NI aes256_expand + AES_ENC.  WinZip
; AES, however, can use 128- or 192-bit keys too, so the unzip path computes the
; key schedule in software (FIPS-197, S-box based) - producing the SAME round-key
; byte layout the AES-NI `aesenc` instruction consumes - and runs the rounds with
; AES-NI via a round count.  This keeps one code path for all three key sizes.
; =============================================================================
.const
align 16
aes_sbox \
 db 063h,07ch,077h,07bh,0f2h,06bh,06fh,0c5h,030h,001h,067h,02bh,0feh,0d7h,0abh,076h
 db 0cah,082h,0c9h,07dh,0fah,059h,047h,0f0h,0adh,0d4h,0a2h,0afh,09ch,0a4h,072h,0c0h
 db 0b7h,0fdh,093h,026h,036h,03fh,0f7h,0cch,034h,0a5h,0e5h,0f1h,071h,0d8h,031h,015h
 db 004h,0c7h,023h,0c3h,018h,096h,005h,09ah,007h,012h,080h,0e2h,0ebh,027h,0b2h,075h
 db 009h,083h,02ch,01ah,01bh,06eh,05ah,0a0h,052h,03bh,0d6h,0b3h,029h,0e3h,02fh,084h
 db 053h,0d1h,000h,0edh,020h,0fch,0b1h,05bh,06ah,0cbh,0beh,039h,04ah,04ch,058h,0cfh
 db 0d0h,0efh,0aah,0fbh,043h,04dh,033h,085h,045h,0f9h,002h,07fh,050h,03ch,09fh,0a8h
 db 051h,0a3h,040h,08fh,092h,09dh,038h,0f5h,0bch,0b6h,0dah,021h,010h,0ffh,0f3h,0d2h
 db 0cdh,00ch,013h,0ech,05fh,097h,044h,017h,0c4h,0a7h,07eh,03dh,064h,05dh,019h,073h
 db 060h,081h,04fh,0dch,022h,02ah,090h,088h,046h,0eeh,0b8h,014h,0deh,05eh,00bh,0dbh
 db 0e0h,032h,03ah,00ah,049h,006h,024h,05ch,0c2h,0d3h,0ach,062h,091h,095h,0e4h,079h
 db 0e7h,0c8h,037h,06dh,08dh,0d5h,04eh,0a9h,06ch,056h,0f4h,0eah,065h,07ah,0aeh,008h
 db 0bah,078h,025h,02eh,01ch,0a6h,0b4h,0c6h,0e8h,0ddh,074h,01fh,04bh,0bdh,08bh,08ah
 db 070h,03eh,0b5h,066h,048h,003h,0f6h,00eh,061h,035h,057h,0b9h,086h,0c1h,01dh,09eh
 db 0e1h,0f8h,098h,011h,069h,0d9h,08eh,094h,09bh,01eh,087h,0e9h,0ceh,055h,028h,0dfh
 db 08ch,0a1h,089h,00dh,0bfh,0e6h,042h,068h,041h,099h,02dh,00fh,0b0h,054h,0bbh,016h

.code

; SUBWORD - eax = SubWord(eax) via aes_sbox.  Clobbers edx, r9, r10d.
; (loads the S-box base RIP-relative; a [label+reg] form would force an
; absolute fixup that fails to link under high-entropy ASLR.)
SUBWORD macro
    lea     r9, [aes_sbox]
    movzx   r10d, al
    movzx   r10d, byte ptr [r9+r10]
    mov     edx, eax
    shr     edx, 8
    movzx   edx, dl
    movzx   edx, byte ptr [r9+rdx]
    shl     edx, 8
    or      r10d, edx
    mov     edx, eax
    shr     edx, 16
    movzx   edx, dl
    movzx   edx, byte ptr [r9+rdx]
    shl     edx, 16
    or      r10d, edx
    mov     edx, eax
    shr     edx, 24
    movzx   edx, dl
    movzx   edx, byte ptr [r9+rdx]
    shl     edx, 24
    or      r10d, edx
    mov     eax, r10d
endm

; =============================================================================
; aes_expand_key(rcx=key, rdx=keylen{16,24,32}, r8=rkout) -> eax = Nr (10/12/14)
; FIPS-197 key schedule.  rkout receives (Nr+1)*16 bytes.
; =============================================================================
public aes_expand_key
aes_expand_key proc frame
    FRAME_PROLOG 48
    ; [rbp-24]=rkout [rbp-32]=Nk [rbp-40]=totalwords [rbp-48]=rcon
    mov     qword ptr [rbp-24], r8
    mov     r9, rdx
    shr     r9, 2                            ; Nk
    mov     qword ptr [rbp-32], r9
    xor     r10, r10
aek_cpy:
    mov     al, byte ptr [rcx+r10]
    mov     byte ptr [r8+r10], al
    inc     r10
    cmp     r10, rdx
    jb      aek_cpy
    mov     rax, r9
    add     rax, 7
    shl     rax, 2                           ; totalwords = 4*(Nk+7)
    mov     qword ptr [rbp-40], rax
    mov     dword ptr [rbp-48], 1            ; rcon
    mov     r11, r9                          ; i = Nk
aek_loop:
    cmp     r11, qword ptr [rbp-40]
    jae     aek_done
    mov     r9, qword ptr [rbp-32]           ; Nk
    mov     rax, r11
    xor     rdx, rdx
    div     r9                               ; rdx = i mod Nk
    mov     r8, qword ptr [rbp-24]
    mov     eax, dword ptr [r8+r11*4-4]      ; temp = w[i-1]
    test    rdx, rdx
    jnz     aek_chk4
    ror     eax, 8                           ; RotWord
    SUBWORD
    mov     edx, dword ptr [rbp-48]          ; rcon (low byte)
    xor     al, dl
    mov     edx, dword ptr [rbp-48]          ; rcon = xtime(rcon)
    mov     ecx, edx
    shl     edx, 1
    test    ecx, 80h
    jz      @F
    xor     edx, 1Bh
@@:
    and     edx, 0FFh
    mov     dword ptr [rbp-48], edx
    jmp     aek_xor
aek_chk4:
    cmp     r9, 6                            ; Nk > 6 (AES-256) only
    jbe     aek_xor
    cmp     rdx, 4
    jne     aek_xor
    SUBWORD
aek_xor:
    mov     r8, qword ptr [rbp-24]
    mov     r9, qword ptr [rbp-32]
    mov     ecx, eax                         ; temp
    mov     rax, r11
    sub     rax, r9                          ; i-Nk
    mov     edx, dword ptr [r8+rax*4]        ; w[i-Nk]
    xor     edx, ecx
    mov     dword ptr [r8+r11*4], edx
    inc     r11
    jmp     aek_loop
aek_done:
    mov     rax, qword ptr [rbp-32]
    add     rax, 6                           ; Nr = Nk + 6
    FRAME_EPILOG
    ret
aes_expand_key endp

; =============================================================================
; aes_ecb_block(rcx=rk, rdx=io16, r8=Nr) - encrypt one block in place (AES-NI).
; =============================================================================
public aes_ecb_block
aes_ecb_block proc frame
    FRAME_PROLOG 32
    movdqu  xmm0, xmmword ptr [rdx]
    movdqu  xmm1, xmmword ptr [rcx]
    pxor    xmm0, xmm1                       ; round 0 (whitening)
    mov     rax, 1
aeb_round:
    cmp     rax, r8
    jae     aeb_last
    mov     r10, rax
    shl     r10, 4
    movdqu  xmm1, xmmword ptr [rcx+r10]
    aesenc  xmm0, xmm1
    inc     rax
    jmp     aeb_round
aeb_last:
    mov     r10, r8
    shl     r10, 4
    movdqu  xmm1, xmmword ptr [rcx+r10]
    aesenclast xmm0, xmm1
    movdqu  xmmword ptr [rdx], xmm0
    FRAME_EPILOG
    ret
aes_ecb_block endp

; =============================================================================
; aes_ctr_xor(rcx=rk, rdx=data, r8=len, r9=ctr16, [rbp+48]=Nr)
; -----------------------------------------------------------------------------
; WinZip-AES CTR mode: the 16-byte counter (caller-initialised to zero) is
; incremented as a LITTLE-ENDIAN 128-bit integer BEFORE each block, AES-encrypted
; (Nr-round AES, any key size) to form the keystream, and XORed over the data in
; place.  The first block thus uses counter value 1.  Decrypt = encrypt (XOR).
; =============================================================================
public aes_ctr_xor
aes_ctr_xor proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=rk [rbp-32]=data [rbp-40]=len [rbp-48]=ctr [rbp-56]=Nr
    ; keystream scratch at [rbp-80..rbp-65]
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-56], rax
acx_loop:
    cmp     qword ptr [rbp-40], 0
    je      acx_done
    mov     r9, qword ptr [rbp-48]
    xor     r10d, r10d
acx_inc:
    inc     byte ptr [r9+r10]
    jnz     acx_incd
    inc     r10d
    cmp     r10d, 16
    jb      acx_inc
acx_incd:
    movdqu  xmm0, xmmword ptr [r9]
    movdqu  xmmword ptr [rbp-80], xmm0       ; scratch = counter
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rbp-80]
    mov     r8, qword ptr [rbp-56]
    call    aes_ecb_block                    ; scratch = keystream
    mov     rax, qword ptr [rbp-40]          ; len
    cmp     rax, 16
    jb      acx_part
    mov     rdx, qword ptr [rbp-32]
    movdqu  xmm0, xmmword ptr [rbp-80]
    movdqu  xmm1, xmmword ptr [rdx]
    pxor    xmm1, xmm0
    movdqu  xmmword ptr [rdx], xmm1
    add     qword ptr [rbp-32], 16
    sub     qword ptr [rbp-40], 16
    jmp     acx_loop
acx_part:
    mov     rdx, qword ptr [rbp-32]
    xor     r11, r11
acx_pb:
    cmp     r11, rax
    jae     acx_done
    mov     r10b, byte ptr [rbp-80+r11]
    xor     byte ptr [rdx+r11], r10b
    inc     r11
    jmp     acx_pb
acx_done:
    FRAME_EPILOG
    ret
aes_ctr_xor endp

end
