; =============================================================================
; camellia.asm - RFC 3713 Camellia-256 (128-bit block, 256-bit key)
; -----------------------------------------------------------------------------
;   camellia_set_key   (rcx = key32, rdx = ks272)
;   camellia_enc_block (rcx = ks272, rdx = blk16)
;   camellia_dec_block (rcx = ks272, rdx = blk16)
; =============================================================================

include macros.inc

.const
align 8
cam_KS label qword
    dq 0A09E667F3BCC908Bh, 0B67AE8584CAA73B2h, 0C6EF372FE94F82BEh, 054FF53A5F1D36F1Ch
    dq 010E527FADE682D1Dh, 0B05688C2B3E6C1FDh

align 8
cam_masks label qword
    dq 00101010001000001h, 00001010101010000h, 00100010100010100h, 00101000100000101h
    dq 00001010100010101h, 00100010101000101h, 00101000101010001h, 00101010001010100h

cam_sbox1 label byte
    db 070h, 082h, 02Ch, 0ECh, 0B3h, 027h, 0C0h, 0E5h, 0E4h, 085h, 057h, 035h, 0EAh, 00Ch, 0AEh, 041h
    db 023h, 0EFh, 06Bh, 093h, 045h, 019h, 0A5h, 021h, 0EDh, 00Eh, 04Fh, 04Eh, 01Dh, 065h, 092h, 0BDh
    db 086h, 0B8h, 0AFh, 08Fh, 07Ch, 0EBh, 01Fh, 0CEh, 03Eh, 030h, 0DCh, 05Fh, 05Eh, 0C5h, 00Bh, 01Ah
    db 0A6h, 0E1h, 039h, 0CAh, 0D5h, 047h, 05Dh, 03Dh, 0D9h, 001h, 05Ah, 0D6h, 051h, 056h, 06Ch, 04Dh
    db 08Bh, 00Dh, 09Ah, 066h, 0FBh, 0CCh, 0B0h, 02Dh, 074h, 012h, 02Bh, 020h, 0F0h, 0B1h, 084h, 099h
    db 0DFh, 04Ch, 0CBh, 0C2h, 034h, 07Eh, 076h, 005h, 06Dh, 0B7h, 0A9h, 031h, 0D1h, 017h, 004h, 0D7h
    db 014h, 058h, 03Ah, 061h, 0DEh, 01Bh, 011h, 01Ch, 032h, 00Fh, 09Ch, 016h, 053h, 018h, 0F2h, 022h
    db 0FEh, 044h, 0CFh, 0B2h, 0C3h, 0B5h, 07Ah, 091h, 024h, 008h, 0E8h, 0A8h, 060h, 0FCh, 069h, 050h
    db 0AAh, 0D0h, 0A0h, 07Dh, 0A1h, 089h, 062h, 097h, 054h, 05Bh, 01Eh, 095h, 0E0h, 0FFh, 064h, 0D2h
    db 010h, 0C4h, 000h, 048h, 0A3h, 0F7h, 075h, 0DBh, 08Ah, 003h, 0E6h, 0DAh, 009h, 03Fh, 0DDh, 094h
    db 087h, 05Ch, 083h, 002h, 0CDh, 04Ah, 090h, 033h, 073h, 067h, 0F6h, 0F3h, 09Dh, 07Fh, 0BFh, 0E2h
    db 052h, 09Bh, 0D8h, 026h, 0C8h, 037h, 0C6h, 03Bh, 081h, 096h, 06Fh, 04Bh, 013h, 0BEh, 063h, 02Eh
    db 0E9h, 079h, 0A7h, 08Ch, 09Fh, 06Eh, 0BCh, 08Eh, 029h, 0F5h, 0F9h, 0B6h, 02Fh, 0FDh, 0B4h, 059h
    db 078h, 098h, 006h, 06Ah, 0E7h, 046h, 071h, 0BAh, 0D4h, 025h, 0ABh, 042h, 088h, 0A2h, 08Dh, 0FAh
    db 072h, 007h, 0B9h, 055h, 0F8h, 0EEh, 0ACh, 00Ah, 036h, 049h, 02Ah, 068h, 03Ch, 038h, 0F1h, 0A4h
    db 040h, 028h, 0D3h, 07Bh, 0BBh, 0C9h, 043h, 0C1h, 015h, 0E3h, 0ADh, 0F4h, 077h, 0C7h, 080h, 09Eh

.data?
align 8
cam_S       dq 2048 dup (?)             ; S[8][256]
cam_ready   dd ?

.code

; =============================================================================
; camellia_init_tables()
; =============================================================================
camellia_init_tables proc
    lea     r8, [cam_sbox1]
    lea     r9, [cam_masks]
    lea     r10, [cam_S]
    xor     ecx, ecx
cit_loop:
    movzx   eax, byte ptr [r8+rcx]          ; s1 = sbox1[x]
    mov     edx, eax
    rol     dl, 1                           ; s2 = rotl8(s1, 1)
    mov     r11d, eax
    ror     r11b, 1                         ; s3 = rotl8(s1, 7)

    ; Store S[0], S[1], S[2], S[4], S[5], S[7]
    push    rax
    imul    rax, qword ptr [r9]
    mov     qword ptr [r10+rcx*8], rax
    pop     rax

    push    rdx
    imul    rdx, qword ptr [r9+8]
    mov     qword ptr [r10+rcx*8+2048], rdx
    pop     rdx

    push    r11
    imul    r11, qword ptr [r9+16]
    mov     qword ptr [r10+rcx*8+4096], r11
    pop     r11

    imul    rdx, qword ptr [r9+32]
    mov     qword ptr [r10+rcx*8+8192], rdx

    imul    r11, qword ptr [r9+40]
    mov     qword ptr [r10+rcx*8+10240], r11

    imul    rax, qword ptr [r9+56]
    mov     qword ptr [r10+rcx*8+14336], rax

    ; s4 = sbox1[rotl8(x, 1)] -> S[3], S[6]
    mov     edx, ecx
    rol     dl, 1
    movzx   eax, byte ptr [r8+rdx]
    mov     rdx, rax
    imul    rax, qword ptr [r9+24]
    mov     qword ptr [r10+rcx*8+6144], rax
    imul    rdx, qword ptr [r9+48]
    mov     qword ptr [r10+rcx*8+12288], rdx

    inc     ecx
    cmp     ecx, 256
    jb      cit_loop

    mov     dword ptr [cam_ready], 1
    ret
camellia_init_tables endp

; =============================================================================
; cam_F(rcx = x, rdx = k) -> rax = F(x, k)
; Leaf. Clobbers rax, rcx, rdx, r8, r9.
; =============================================================================
cam_F proc
    xor     rcx, rdx
    lea     r8, [cam_S]
    movzx   edx, cl
    mov     rax, qword ptr [r8+14336+rdx*8]
    shr     rcx, 8
    movzx   edx, cl
    xor     rax, qword ptr [r8+12288+rdx*8]
    shr     rcx, 8
    movzx   edx, cl
    xor     rax, qword ptr [r8+10240+rdx*8]
    shr     rcx, 8
    movzx   edx, cl
    xor     rax, qword ptr [r8+8192+rdx*8]
    shr     rcx, 8
    movzx   edx, cl
    xor     rax, qword ptr [r8+6144+rdx*8]
    shr     rcx, 8
    movzx   edx, cl
    xor     rax, qword ptr [r8+4096+rdx*8]
    shr     rcx, 8
    movzx   edx, cl
    xor     rax, qword ptr [r8+2048+rdx*8]
    shr     rcx, 8
    xor     rax, qword ptr [r8+rcx*8]
    ret
cam_F endp

; =============================================================================
; cam_FL(rcx = x, rdx = k) -> rax
; =============================================================================
cam_FL proc
    mov     r8, rcx
    shr     r8, 32                          ; xl
    mov     eax, ecx                        ; xr
    mov     r9, rdx
    shr     r9, 32                          ; kl
    ; yr = rotl32(xl & kl, 1) ^ xr
    mov     ecx, r8d
    and     ecx, r9d
    rol     ecx, 1
    xor     ecx, eax                        ; ecx = yr
    ; yl = (yr | kr) ^ xl
    mov     eax, ecx
    or      eax, edx                        ; edx = kr
    xor     eax, r8d                        ; eax = yl
    shl     rax, 32
    or      rax, rcx
    ret
cam_FL endp

; =============================================================================
; cam_FL1(rcx = y, rdx = k) -> rax
; =============================================================================
cam_FL1 proc
    mov     r8, rcx
    shr     r8, 32                          ; yl
    mov     eax, ecx                        ; yr
    mov     r9, rdx
    shr     r9, 32                          ; kl
    ; xl = (yr | kr) ^ yl
    mov     ecx, eax
    or      ecx, edx                        ; edx = kr
    xor     ecx, r8d                        ; ecx = xl
    ; xr = rotl32(xl & kl, 1) ^ yr
    mov     edx, ecx
    and     edx, r9d
    rol     edx, 1
    xor     edx, eax                        ; edx = xr
    shl     rcx, 32
    or      rcx, rdx
    mov     rax, rcx
    ret
cam_FL1 endp

; Emit rotl128l(L, R, cnt) -> dst_l, rotl128r(L, R, cnt) -> dst_r (uses rax, rdx)
CAM_ROTL128 macro Lreg, Rreg, cnt, dstL, dstR
    mov     rax, Lreg
    mov     rdx, Rreg
    shld    rax, Rreg, cnt
    shld    rdx, Lreg, cnt
    mov     dstL, rax
    mov     dstR, rdx
endm

; =============================================================================
; camellia_set_key(rcx = key32, rdx = ks272)
; =============================================================================
LANDING_PAD
public camellia_set_key
camellia_set_key proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; key32
    mov     rdi, rdx                        ; ks272

    cmp     dword ptr [cam_ready], 0
    jne     csk_go
    call    camellia_init_tables

csk_go:
    mov     r12, qword ptr [rsi]
    mov     r13, qword ptr [rsi+8]
    mov     r14, qword ptr [rsi+16]
    mov     r15, qword ptr [rsi+24]
    bswap   r12                             ; kll
    bswap   r13                             ; klr
    bswap   r14                             ; krl
    bswap   r15                             ; krr

    lea     rbx, [cam_KS]

    ; kal = kll ^ krl, kar = klr ^ krr
    mov     rax, r12
    xor     rax, r14                        ; kal
    mov     rcx, r13
    xor     rcx, r15                        ; kar
    mov     qword ptr [rbp-72], rax         ; lp = kal
    mov     qword ptr [rbp-80], rcx         ; kar

    mov     rcx, rax
    mov     rdx, qword ptr [rbx]            ; KS[0]
    call    cam_F
    xor     rax, qword ptr [rbp-80]         ; kal = kar ^ F(kal, KS[0])
    mov     qword ptr [rbp-80], rax         ; kar = kal
    mov     rcx, rax
    mov     rdx, qword ptr [rbx+8]          ; KS[1]
    call    cam_F
    xor     rax, qword ptr [rbp-72]         ; kal = lp ^ F(kal, KS[1])
    xor     rax, r12                        ; kal ^= kll
    mov     rcx, qword ptr [rbp-80]
    xor     rcx, r13                        ; kar ^= klr

    mov     qword ptr [rbp-72], rax         ; lp = kal
    mov     qword ptr [rbp-80], rcx         ; kar
    mov     rcx, rax
    mov     rdx, qword ptr [rbx+16]         ; KS[2]
    call    cam_F
    xor     rax, qword ptr [rbp-80]         ; kal = kar ^ F(kal, KS[2])
    mov     qword ptr [rbp-80], rax         ; kar = kal
    mov     rcx, rax
    mov     rdx, qword ptr [rbx+24]         ; KS[3]
    call    cam_F
    xor     rax, qword ptr [rbp-72]         ; final kal
    mov     qword ptr [rbp-72], rax         ; [rbp-72] = kal, [rbp-80] = kar

    ; kbl = kal ^ krl, kbr = kar ^ krr
    xor     rax, r14                        ; kbl
    mov     rcx, qword ptr [rbp-80]
    xor     rcx, r15                        ; kbr
    mov     rsi, rax                        ; lp = kbl
    mov     qword ptr [rbp-88], rcx         ; kbr

    mov     rcx, rax
    mov     rdx, qword ptr [rbx+32]         ; KS[4]
    call    cam_F
    xor     rax, qword ptr [rbp-88]         ; kbl = kbr ^ F(kbl, KS[4])
    mov     rbx, rax                        ; kbr = kbl
    mov     rcx, rax
    mov     rdx, qword ptr [cam_KS+40]      ; KS[5]
    call    cam_F
    xor     rsi, rax                        ; rsi = kbl, rbx = kbr

    ; Populate ks[0..33]
    mov     qword ptr [rdi],    r12         ; ks[0] = kll
    mov     qword ptr [rdi+8],  r13         ; ks[1] = klr
    mov     qword ptr [rdi+16], rsi         ; ks[2] = kbl
    mov     qword ptr [rdi+24], rbx         ; ks[3] = kbr

    CAM_ROTL128 r14, r15, 15, qword ptr [rdi+32],  qword ptr [rdi+40]   ; ks[4..5] (kr, 15)
    mov     r8, qword ptr [rbp-72]          ; kal
    mov     r9, qword ptr [rbp-80]          ; kar
    CAM_ROTL128 r8,  r9,  15, qword ptr [rdi+48],  qword ptr [rdi+56]   ; ks[6..7] (ka, 15)
    CAM_ROTL128 r14, r15, 30, qword ptr [rdi+64],  qword ptr [rdi+72]   ; ks[8..9] (kr, 30)
    CAM_ROTL128 rsi, rbx, 30, qword ptr [rdi+80],  qword ptr [rdi+88]   ; ks[10..11] (kb, 30)
    CAM_ROTL128 r12, r13, 45, qword ptr [rdi+96],  qword ptr [rdi+104]  ; ks[12..13] (kl, 45)
    CAM_ROTL128 r8,  r9,  45, qword ptr [rdi+112], qword ptr [rdi+120]  ; ks[14..15] (ka, 45)
    CAM_ROTL128 r12, r13, 60, qword ptr [rdi+128], qword ptr [rdi+136]  ; ks[16..17] (kl, 60)
    CAM_ROTL128 r14, r15, 60, qword ptr [rdi+144], qword ptr [rdi+152]  ; ks[18..19] (kr, 60)
    CAM_ROTL128 rsi, rbx, 60, qword ptr [rdi+160], qword ptr [rdi+168]  ; ks[20..21] (kb, 60)

    ; Note: for shifts >= 64 (77 = 64+13, 94 = 64+30, 111 = 64+47), Camellia.c uses rotl128r/rotl128l swapped!
    CAM_ROTL128 r12, r13, 13, qword ptr [rdi+184], qword ptr [rdi+176]  ; ks[22]=r, ks[23]=l
    CAM_ROTL128 r8,  r9,  13, qword ptr [rdi+200], qword ptr [rdi+192]  ; ks[24]=r, ks[25]=l
    mov     rax, qword ptr [rdi+72]
    mov     rdx, qword ptr [rdi+64]
    mov     qword ptr [rdi+208], rax        ; ks[26] = ks[9]
    mov     qword ptr [rdi+216], rdx        ; ks[27] = ks[8]
    CAM_ROTL128 r8,  r9,  30, qword ptr [rdi+232], qword ptr [rdi+224]  ; ks[28]=r, ks[29]=l
    CAM_ROTL128 r12, r13, 47, qword ptr [rdi+248], qword ptr [rdi+240]  ; ks[30]=r, ks[31]=l
    CAM_ROTL128 rsi, rbx, 47, qword ptr [rdi+264], qword ptr [rdi+256]  ; ks[32]=r, ks[33]=l

    mov     qword ptr [rbp-72], 0
    mov     qword ptr [rbp-80], 0
    mov     qword ptr [rbp-88], 0

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
camellia_set_key endp

; 6-round Camellia Feistel block on (r12=L, r13=R) using ks at [rbx + koff .. koff+40]
; Each 2-round Feistel pair computes: R ^= F(L, k_even); L ^= F(R, k_odd),
; leaving (L2, R2) directly in (r12, r13) with zero swaps.
CAM_R6 macro koff
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+koff]
    call    cam_F
    xor     r13, rax

    mov     rcx, r13
    mov     rdx, qword ptr [rbx+koff+8]
    call    cam_F
    xor     r12, rax

    mov     rcx, r12
    mov     rdx, qword ptr [rbx+koff+16]
    call    cam_F
    xor     r13, rax

    mov     rcx, r13
    mov     rdx, qword ptr [rbx+koff+24]
    call    cam_F
    xor     r12, rax

    mov     rcx, r12
    mov     rdx, qword ptr [rbx+koff+32]
    call    cam_F
    xor     r13, rax

    mov     rcx, r13
    mov     rdx, qword ptr [rbx+koff+40]
    call    cam_F
    xor     r12, rax
endm

; =============================================================================
; camellia_enc_block(rcx = ks272, rdx = blk16)
; =============================================================================
LANDING_PAD
public camellia_enc_block
camellia_enc_block proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], rbx
    mov     qword ptr [rbp-48], rsi

    mov     rbx, rcx                        ; ks
    mov     rsi, rdx                        ; blk16

    mov     r12, qword ptr [rsi]
    mov     r13, qword ptr [rsi+8]
    bswap   r12
    bswap   r13
    xor     r12, qword ptr [rbx]            ; l = be64(in[0..7]) ^ ks[0]
    xor     r13, qword ptr [rbx+8]          ; r = be64(in[8..15]) ^ ks[1]

    CAM_R6  16                              ; ks[2..7]
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+64]         ; ks[8]
    call    cam_FL
    mov     r12, rax
    mov     rcx, r13
    mov     rdx, qword ptr [rbx+72]         ; ks[9]
    call    cam_FL1
    mov     r13, rax

    CAM_R6  80                              ; ks[10..15]
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+128]        ; ks[16]
    call    cam_FL
    mov     r12, rax
    mov     rcx, r13
    mov     rdx, qword ptr [rbx+136]        ; ks[17]
    call    cam_FL1
    mov     r13, rax

    CAM_R6  144                             ; ks[18..23]
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+192]        ; ks[24]
    call    cam_FL
    mov     r12, rax
    mov     rcx, r13
    mov     rdx, qword ptr [rbx+200]        ; ks[25]
    call    cam_FL1
    mov     r13, rax

    CAM_R6  208                             ; ks[26..31]
    xor     r13, qword ptr [rbx+256]        ; r ^= ks[32]
    xor     r12, qword ptr [rbx+264]        ; l ^= ks[33]
    bswap   r13
    bswap   r12
    mov     qword ptr [rsi],   r13
    mov     qword ptr [rsi+8], r12

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     rbx, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
camellia_enc_block endp

; =============================================================================
; camellia_dec_block(rcx = ks272, rdx = blk16)
; Note: Camellia decryption is identical to Camellia encryption with reversed
; round keys: kw3..4 -> ks[32..33], k24..1 -> ks[31..2], kl6..1 -> ks[24,25,16,17,8,9]
; with FL on active half using ks[25]/ks[17]/ks[9] and FL1 on passive half using ks[24]/ks[16]/ks[8]!
; =============================================================================
LANDING_PAD
public camellia_dec_block
camellia_dec_block proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], rbx
    mov     qword ptr [rbp-48], rsi

    mov     rbx, rcx
    mov     rsi, rdx

    ; Let r12 = r = be64(in[0..7]) ^ ks[32], r13 = l = be64(in[8..15]) ^ ks[33]
    ; Trace Camellia.c:1770-1820:
    ;   step 1 (ks[31]): rp=r(r12); r = l(r13) ^ F(r, ks[31]); -> new r=r12, rp=r14
    ;   step 2 (ks[30]): l = r(r12); r = rp(r14) ^ F(r, ks[30]); -> after step 2: r is in r13, l is in r12!
    ;Wait: in CAM_DR6 above, step 2 set r13 = rp ^ F(r12, k-8), leaving r12 = l and r13 = r!
    ; Better: keep r12 = active half (r in Camellia.c), r13 = passive half (l in Camellia.c) explicitly!
    mov     r12, qword ptr [rsi]
    mov     r13, qword ptr [rsi+8]
    bswap   r12
    bswap   r13
    xor     r12, qword ptr [rbx+256]        ; r = be64(in[0..7]) ^ ks[32]
    xor     r13, qword ptr [rbx+264]        ; l = be64(in[8..15]) ^ ks[33]

    ; Block 1: ks[31..26] (offsets 248 down to 208)
    mov     r14d, 248
cdb_b1:
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+r14]
    call    cam_F
    xor     rax, r13                        ; new_r = l ^ F(r, k)
    mov     r13, r12                        ; new_l = old_r
    mov     r12, rax
    sub     r14d, 8
    cmp     r14d, 208
    jge     cdb_b1

    ; l = FL1(l, ks[24]), r = FL(r, ks[25])
    mov     rcx, r13
    mov     rdx, qword ptr [rbx+192]        ; ks[24]
    call    cam_FL1
    mov     r13, rax
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+200]        ; ks[25]
    call    cam_FL
    mov     r12, rax

    ; Block 2: ks[23..18] (offsets 184 down to 144)
    mov     r14d, 184
cdb_b2:
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+r14]
    call    cam_F
    xor     rax, r13
    mov     r13, r12
    mov     r12, rax
    sub     r14d, 8
    cmp     r14d, 144
    jge     cdb_b2

    ; l = FL1(l, ks[16]), r = FL(r, ks[17])
    mov     rcx, r13
    mov     rdx, qword ptr [rbx+128]        ; ks[16]
    call    cam_FL1
    mov     r13, rax
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+136]        ; ks[17]
    call    cam_FL
    mov     r12, rax

    ; Block 3: ks[15..10] (offsets 120 down to 80)
    mov     r14d, 120
cdb_b3:
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+r14]
    call    cam_F
    xor     rax, r13
    mov     r13, r12
    mov     r12, rax
    sub     r14d, 8
    cmp     r14d, 80
    jge     cdb_b3

    ; l = FL1(l, ks[8]), r = FL(r, ks[9])
    mov     rcx, r13
    mov     rdx, qword ptr [rbx+64]         ; ks[8]
    call    cam_FL1
    mov     r13, rax
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+72]         ; ks[9]
    call    cam_FL
    mov     r12, rax

    ; Block 4: ks[7..2] (offsets 56 down to 16)
    mov     r14d, 56
cdb_b4:
    mov     rcx, r12
    mov     rdx, qword ptr [rbx+r14]
    call    cam_F
    xor     rax, r13
    mov     r13, r12
    mov     r12, rax
    sub     r14d, 8
    cmp     r14d, 16
    jge     cdb_b4

    ; Final: l ^= ks[0], r ^= ks[1], store be64(out, l), be64(out+8, r)
    xor     r13, qword ptr [rbx]
    xor     r12, qword ptr [rbx+8]
    bswap   r13
    bswap   r12
    mov     qword ptr [rsi],   r13
    mov     qword ptr [rsi+8], r12

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     rbx, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
camellia_dec_block endp

end
