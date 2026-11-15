; =============================================================================
; aesxts.asm - AES-256 (AES-NI) + Unified 15-Mode IEEE P1619 XTS Engine
; -----------------------------------------------------------------------------
;   aes256_xts_set_key (rcx = key32, rdx = ks480)
;   aes256_enc_block   (rcx = ks480, rdx = blk16)
;   aes256_dec_block   (rcx = ks480, rdx = blk16)
;   xts_mode_key_size  (ecx = modeId) -> eax = 32 * cipherCount
;   xts_init           (ecx = modeId, rdx = priKey, r8 = secKey, r9 = xtsCtx)
;   xts_encrypt        (rcx = xtsCtx, rdx = buf, r8 = byteLen, r9 = startUnit)
;   xts_decrypt        (rcx = xtsCtx, rdx = buf, r8 = byteLen, r9 = startUnit)
;
; XTS_CTX layout (25,552 bytes, 16-byte aligned):
;   [0     .. 15]     header: dd modeId, dd count, db c0, c1, c2, pad[5]
;   [16    .. 12783]  ksPrimary[3 * 4256]
;   [12784 .. 25551]  ksSecondary[3 * 4256]
; =============================================================================

include macros.inc

extern aes256_expand:proc
extern serpent_set_key:proc
extern serpent_enc_block:proc
extern serpent_dec_block:proc
extern twofish_set_key:proc
extern twofish_enc_block:proc
extern twofish_dec_block:proc
extern camellia_set_key:proc
extern camellia_enc_block:proc
extern camellia_dec_block:proc
extern kuznyechik_set_key:proc
extern kuznyechik_enc_block:proc
extern kuznyechik_dec_block:proc

XTS_KS_STRIDE       equ 4256
XTS_SEC_OFFSET      equ (16 + 3 * XTS_KS_STRIDE)

; Cipher IDs
XTS_CIPH_AES        equ 0
XTS_CIPH_SERPENT    equ 1
XTS_CIPH_TWOFISH    equ 2
XTS_CIPH_CAMELLIA   equ 3
XTS_CIPH_KUZNYECHIK equ 4

.const
align 8
; Cipher dispatch table: 5 * 24 bytes { set_key, enc_block, dec_block }
xts_cipher_vtbl label qword
    dq aes256_xts_set_key, aes256_enc_block,     aes256_dec_block
    dq serpent_set_key,    serpent_enc_block,    serpent_dec_block
    dq twofish_set_key,    twofish_enc_block,    twofish_dec_block
    dq camellia_set_key,   camellia_enc_block,   camellia_dec_block
    dq kuznyechik_set_key, kuznyechik_enc_block, kuznyechik_dec_block

; 15 VeraCrypt / TrueCrypt XTS modes (4 bytes each: count, c0, c1, c2)
; Order of c0..c2 matches VeraCrypt EncryptionAlgorithm.cpp Ciphers[] push_back order!
;   0: AES                      1: Serpent                  2: Twofish
;   3: Camellia                 4: Kuznyechik               5: AESTwofish
;   6: AESTwofishSerpent        7: SerpentAES               8: SerpentTwofishAES
;   9: TwofishSerpent          10: CamelliaKuznyechik      11: KuznyechikTwofish
;  12: CamelliaSerpent         13: KuznyechikAES           14: KuznyechikSerpentCamellia
align 4
xts_mode_tbl label byte
    db 1, XTS_CIPH_AES,        0,                0                  ; 0: AES
    db 1, XTS_CIPH_SERPENT,    0,                0                  ; 1: Serpent
    db 1, XTS_CIPH_TWOFISH,    0,                0                  ; 2: Twofish
    db 1, XTS_CIPH_CAMELLIA,   0,                0                  ; 3: Camellia
    db 1, XTS_CIPH_KUZNYECHIK, 0,                0                  ; 4: Kuznyechik
    db 2, XTS_CIPH_TWOFISH,    XTS_CIPH_AES,     0                  ; 5: AESTwofish
    db 3, XTS_CIPH_SERPENT,    XTS_CIPH_TWOFISH, XTS_CIPH_AES       ; 6: AESTwofishSerpent
    db 2, XTS_CIPH_AES,        XTS_CIPH_SERPENT, 0                  ; 7: SerpentAES
    db 3, XTS_CIPH_AES,        XTS_CIPH_TWOFISH, XTS_CIPH_SERPENT   ; 8: SerpentTwofishAES
    db 2, XTS_CIPH_SERPENT,    XTS_CIPH_TWOFISH, 0                  ; 9: TwofishSerpent
    db 2, XTS_CIPH_KUZNYECHIK, XTS_CIPH_CAMELLIA,0                  ; 10: CamelliaKuznyechik
    db 2, XTS_CIPH_TWOFISH,    XTS_CIPH_KUZNYECHIK, 0               ; 11: KuznyechikTwofish
    db 2, XTS_CIPH_SERPENT,    XTS_CIPH_CAMELLIA,0                  ; 12: CamelliaSerpent
    db 2, XTS_CIPH_AES,        XTS_CIPH_KUZNYECHIK, 0               ; 13: KuznyechikAES
    db 3, XTS_CIPH_CAMELLIA,   XTS_CIPH_SERPENT, XTS_CIPH_KUZNYECHIK; 14: KuznyechikSerpentCamellia

.code

; =============================================================================
; aes256_xts_set_key(rcx = key32, rdx = ks480)
; Populates encryption round keys at [rdx+0..239] and InvMixColumns decryption
; round keys at [rdx+240..479].
; =============================================================================
LANDING_PAD
public aes256_xts_set_key
aes256_xts_set_key proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rdx

    call    aes256_expand

    movdqu  xmm0, xmmword ptr [rbx+224]     ; dk[0] = ek[14]
    movdqu  xmmword ptr [rbx+240], xmm0

    aesimc  xmm0, xmmword ptr [rbx+208]
    movdqu  xmmword ptr [rbx+256], xmm0
    aesimc  xmm0, xmmword ptr [rbx+192]
    movdqu  xmmword ptr [rbx+272], xmm0
    aesimc  xmm0, xmmword ptr [rbx+176]
    movdqu  xmmword ptr [rbx+288], xmm0
    aesimc  xmm0, xmmword ptr [rbx+160]
    movdqu  xmmword ptr [rbx+304], xmm0
    aesimc  xmm0, xmmword ptr [rbx+144]
    movdqu  xmmword ptr [rbx+320], xmm0
    aesimc  xmm0, xmmword ptr [rbx+128]
    movdqu  xmmword ptr [rbx+336], xmm0
    aesimc  xmm0, xmmword ptr [rbx+112]
    movdqu  xmmword ptr [rbx+352], xmm0
    aesimc  xmm0, xmmword ptr [rbx+96]
    movdqu  xmmword ptr [rbx+368], xmm0
    aesimc  xmm0, xmmword ptr [rbx+80]
    movdqu  xmmword ptr [rbx+384], xmm0
    aesimc  xmm0, xmmword ptr [rbx+64]
    movdqu  xmmword ptr [rbx+400], xmm0
    aesimc  xmm0, xmmword ptr [rbx+48]
    movdqu  xmmword ptr [rbx+416], xmm0
    aesimc  xmm0, xmmword ptr [rbx+32]
    movdqu  xmmword ptr [rbx+432], xmm0
    aesimc  xmm0, xmmword ptr [rbx+16]
    movdqu  xmmword ptr [rbx+448], xmm0

    movdqu  xmm0, xmmword ptr [rbx]         ; dk[14] = ek[0]
    movdqu  xmmword ptr [rbx+464], xmm0
    pxor    xmm0, xmm0

    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
aes256_xts_set_key endp

; =============================================================================
; aes256_enc_block(rcx = ks480, rdx = blk16)
; =============================================================================
LANDING_PAD
public aes256_enc_block
aes256_enc_block proc
    movdqu      xmm0, xmmword ptr [rdx]
    movdqu      xmm1, xmmword ptr [rcx]
    pxor        xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+16]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+32]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+48]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+64]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+80]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+96]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+112]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+128]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+144]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+160]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+176]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+192]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+208]
    aesenc      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+224]
    aesenclast  xmm0, xmm1
    movdqu      xmmword ptr [rdx], xmm0
    pxor        xmm0, xmm0
    pxor        xmm1, xmm1
    ret
aes256_enc_block endp

; =============================================================================
; aes256_dec_block(rcx = ks480, rdx = blk16)
; =============================================================================
LANDING_PAD
public aes256_dec_block
aes256_dec_block proc
    movdqu      xmm0, xmmword ptr [rdx]
    movdqu      xmm1, xmmword ptr [rcx+240]
    pxor        xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+256]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+272]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+288]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+304]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+320]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+336]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+352]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+368]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+384]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+400]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+416]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+432]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+448]
    aesdec      xmm0, xmm1
    movdqu      xmm1, xmmword ptr [rcx+464]
    aesdeclast  xmm0, xmm1
    movdqu      xmmword ptr [rdx], xmm0
    pxor        xmm0, xmm0
    pxor        xmm1, xmm1
    ret
aes256_dec_block endp

; =============================================================================
; xts_mode_key_size(ecx = modeId) -> eax = 32 * count (32, 64, or 96)
; =============================================================================
public xts_mode_key_size
xts_mode_key_size proc
    BOUND_CHECK rcx, 15
    lea     r8, [xts_mode_tbl]
    movzx   eax, byte ptr [r8+rcx*4]
    shl     eax, 5
    ret
xts_mode_key_size endp

; =============================================================================
; xts_init(ecx = modeId, rdx = priKey, r8 = secKey, r9 = xtsCtx)
; =============================================================================
public xts_init
xts_init proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    BOUND_CHECK rcx, 15
    mov     r12, rdx                        ; priKey
    mov     r13, r8                         ; secKey
    mov     r14, r9                         ; xtsCtx

    lea     rax, [xts_mode_tbl]
    movzx   r15d, byte ptr [rax+rcx*4]      ; cipher count (1..3)
    mov     dword ptr [r14], ecx            ; modeId
    mov     dword ptr [r14+4], r15d         ; count
    mov     edx, dword ptr [rax+rcx*4]
    shr     edx, 8
    mov     dword ptr [r14+8], edx          ; c0, c1, c2, 0
    mov     dword ptr [r14+12], 0

    lea     rsi, [xts_cipher_vtbl]
    xor     ebx, ebx                        ; idx = 0..count-1
xi_loop:
    movzx   edi, byte ptr [r14+8+rbx]       ; cipherId
    imul    edi, edi, 24                    ; vtbl byte offset
    mov     rax, qword ptr [rsi+rdi]        ; set_key fn (note: serpent/twofish/camellia/kuz set_key also get LANDING_PAD!)

    ; Primary cipher idx
    mov     ecx, ebx
    shl     ecx, 5                          ; idx * 32
    add     rcx, r12
    imul    edx, ebx, XTS_KS_STRIDE
    lea     rdx, [r14+16+rdx]
    CALL_GUARDED rax

    ; Secondary cipher idx
    movzx   edi, byte ptr [r14+8+rbx]
    imul    edi, edi, 24
    mov     rax, qword ptr [rsi+rdi]
    mov     ecx, ebx
    shl     ecx, 5
    add     rcx, r13
    imul    edx, ebx, XTS_KS_STRIDE
    lea     rdx, [r14+XTS_SEC_OFFSET+rdx]
    CALL_GUARDED rax

    inc     ebx
    cmp     ebx, r15d
    jb      xi_loop

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
xts_init endp

; =============================================================================
; xts_single_pass(rcx = ksPri, rdx = ksSec, r8 = buf, r9 = byteLen,
;                 [rbp+48] = startUnit, [rbp+56] = blockFn, [rbp+64] = secEncFn)
; Internal helper: runs XTS over byteLen bytes (multiple of 16; up to 32 blocks
; = 512 bytes per XTS data unit) for one cipher.
; =============================================================================
xts_single_pass proc frame
    FRAME_PROLOG 96
    ; [rbp-16..64] = r12..r15, rbx, rsi, rdi
    ; [rsp+32..47] = 16-byte tweak
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    shr     r9, 4                           ; remaining 16-byte blocks
    jz      xsp_done

    mov     r12, rcx                        ; ksPri
    mov     r13, rdx                        ; ksSec
    mov     rsi, r8                         ; buf
    mov     r14, r9                         ; remBlocks
    mov     r15, qword ptr [rbp+48]         ; unitNo

xsp_unit:
    ; Encrypt LE128(unitNo) with secondary cipher
    mov     qword ptr [rsp+32], r15
    mov     qword ptr [rsp+40], 0
    mov     rcx, r13
    lea     rdx, [rsp+32]
    mov     rax, qword ptr [rbp+64]         ; secEncFn
    CALL_GUARDED rax

    mov     ebx, 32                         ; max 32 * 16 = 512 bytes per unit
    cmp     r14, 32
    jae     xsp_cnt_ok
    mov     ebx, r14d
xsp_cnt_ok:
    sub     r14, rbx
    mov     rdi, qword ptr [rbp+56]         ; blockFn (enc or dec)
xsp_blk:
    mov     rax, qword ptr [rsp+32]
    mov     rdx, qword ptr [rsp+40]
    xor     qword ptr [rsi],   rax
    xor     qword ptr [rsi+8], rdx

    mov     rcx, r12
    mov     rdx, rsi
    CALL_GUARDED rdi

    mov     rax, qword ptr [rsp+32]
    mov     rdx, qword ptr [rsp+40]
    xor     qword ptr [rsi],   rax
    xor     qword ptr [rsi+8], rdx

    ; Constant-time GF(2^128) tweak multiply by x (modulus x^128 + x^7 + x^2 + x + 1)
    mov     rcx, rdx
    shr     rcx, 63
    imul    ecx, ecx, 087h
    shld    rdx, rax, 1
    shl     rax, 1
    xor     rax, rcx
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], rdx

    add     rsi, 16
    dec     ebx
    jnz     xsp_blk

    inc     r15
    test    r14, r14
    jnz     xsp_unit

    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0

xsp_done:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
xts_single_pass endp

; =============================================================================
; xts_encrypt(rcx = xtsCtx, rdx = buf, r8 = unitCount, r9 = startUnit)
; Forward cascade: cipher[0], cipher[1], ..., cipher[count-1]
; =============================================================================
public xts_encrypt
xts_encrypt proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi

    mov     r12, rcx                        ; xtsCtx
    mov     r13, rdx                        ; buf
    mov     r14, r8                         ; unitCount
    mov     r15, r9                         ; startUnit

    mov     esi, dword ptr [r12+4]          ; count
    BOUND_CHECK rsi, 4
    test    esi, esi
    jz      xe_done

    xor     ebx, ebx
xe_loop:
    movzx   eax, byte ptr [r12+8+rbx]       ; cipherId
    imul    eax, eax, 24
    lea     rcx, [xts_cipher_vtbl]
    mov     r10, qword ptr [rcx+rax+8]      ; enc_block

    imul    eax, ebx, XTS_KS_STRIDE
    lea     rcx, [r12+16+rax]               ; ksPri
    lea     rdx, [r12+XTS_SEC_OFFSET+rax]   ; ksSec
    mov     r8,  r13
    mov     r9,  r14
    mov     qword ptr [rsp+32], r15
    mov     qword ptr [rsp+40], r10         ; blockFn = enc_block
    mov     qword ptr [rsp+48], r10         ; secEncFn = enc_block
    call    xts_single_pass

    inc     ebx
    cmp     ebx, esi
    jb      xe_loop

xe_done:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
xts_encrypt endp

; =============================================================================
; xts_decrypt(rcx = xtsCtx, rdx = buf, r8 = unitCount, r9 = startUnit)
; Reverse cascade: cipher[count-1] down to cipher[0]
; =============================================================================
public xts_decrypt
xts_decrypt proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx

    mov     r12, rcx                        ; xtsCtx
    mov     r13, rdx                        ; buf
    mov     r14, r8                         ; unitCount
    mov     r15, r9                         ; startUnit

    mov     ebx, dword ptr [r12+4]          ; count
    BOUND_CHECK rbx, 4
    test    ebx, ebx
    jz      xd_done

xd_loop:
    dec     ebx
    movzx   eax, byte ptr [r12+8+rbx]       ; cipherId
    imul    eax, eax, 24
    lea     rcx, [xts_cipher_vtbl]
    mov     r10, qword ptr [rcx+rax+16]     ; dec_block
    mov     r11, qword ptr [rcx+rax+8]      ; secEncFn = enc_block!

    imul    eax, ebx, XTS_KS_STRIDE
    lea     rcx, [r12+16+rax]               ; ksPri
    lea     rdx, [r12+XTS_SEC_OFFSET+rax]   ; ksSec
    mov     r8,  r13
    mov     r9,  r14
    mov     qword ptr [rsp+32], r15
    mov     qword ptr [rsp+40], r10         ; blockFn = dec_block
    mov     qword ptr [rsp+48], r11         ; secEncFn = enc_block
    call    xts_single_pass

    test    ebx, ebx
    jnz     xd_loop

xd_done:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
xts_decrypt endp

end
