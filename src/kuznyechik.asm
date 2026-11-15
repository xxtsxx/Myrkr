; =============================================================================
; kuznyechik.asm - GOST R 34.12-2015 Kuznyechik (128-bit block, 256-bit key)
; -----------------------------------------------------------------------------
;   kuznyechik_set_key   (rcx = key32, rdx = ks320)
;   kuznyechik_enc_block (rcx = ks320, rdx = blk16)
;   kuznyechik_dec_block (rcx = ks320, rdx = blk16)
; =============================================================================

include macros.inc

.const
kuz_S label byte
    db 0FCh, 0EEh, 0DDh, 011h, 0CFh, 06Eh, 031h, 016h, 0FBh, 0C4h, 0FAh, 0DAh, 023h, 0C5h, 004h, 04Dh
    db 0E9h, 077h, 0F0h, 0DBh, 093h, 02Eh, 099h, 0BAh, 017h, 036h, 0F1h, 0BBh, 014h, 0CDh, 05Fh, 0C1h
    db 0F9h, 018h, 065h, 05Ah, 0E2h, 05Ch, 0EFh, 021h, 081h, 01Ch, 03Ch, 042h, 08Bh, 001h, 08Eh, 04Fh
    db 005h, 084h, 002h, 0AEh, 0E3h, 06Ah, 08Fh, 0A0h, 006h, 00Bh, 0EDh, 098h, 07Fh, 0D4h, 0D3h, 01Fh
    db 0EBh, 034h, 02Ch, 051h, 0EAh, 0C8h, 048h, 0ABh, 0F2h, 02Ah, 068h, 0A2h, 0FDh, 03Ah, 0CEh, 0CCh
    db 0B5h, 070h, 00Eh, 056h, 008h, 00Ch, 076h, 012h, 0BFh, 072h, 013h, 047h, 09Ch, 0B7h, 05Dh, 087h
    db 015h, 0A1h, 096h, 029h, 010h, 07Bh, 09Ah, 0C7h, 0F3h, 091h, 078h, 06Fh, 09Dh, 09Eh, 0B2h, 0B1h
    db 032h, 075h, 019h, 03Dh, 0FFh, 035h, 08Ah, 07Eh, 06Dh, 054h, 0C6h, 080h, 0C3h, 0BDh, 00Dh, 057h
    db 0DFh, 0F5h, 024h, 0A9h, 03Eh, 0A8h, 043h, 0C9h, 0D7h, 079h, 0D6h, 0F6h, 07Ch, 022h, 0B9h, 003h
    db 0E0h, 00Fh, 0ECh, 0DEh, 07Ah, 094h, 0B0h, 0BCh, 0DCh, 0E8h, 028h, 050h, 04Eh, 033h, 00Ah, 04Ah
    db 0A7h, 097h, 060h, 073h, 01Eh, 000h, 062h, 044h, 01Ah, 0B8h, 038h, 082h, 064h, 09Fh, 026h, 041h
    db 0ADh, 045h, 046h, 092h, 027h, 05Eh, 055h, 02Fh, 08Ch, 0A3h, 0A5h, 07Dh, 069h, 0D5h, 095h, 03Bh
    db 007h, 058h, 0B3h, 040h, 086h, 0ACh, 01Dh, 0F7h, 030h, 037h, 06Bh, 0E4h, 088h, 0D9h, 0E7h, 089h
    db 0E1h, 01Bh, 083h, 049h, 04Ch, 03Fh, 0F8h, 0FEh, 08Dh, 053h, 0AAh, 090h, 0CAh, 0D8h, 085h, 061h
    db 020h, 071h, 067h, 0A4h, 02Dh, 02Bh, 009h, 05Bh, 0CBh, 09Bh, 025h, 0D0h, 0BEh, 0E5h, 06Ch, 052h
    db 059h, 0A6h, 074h, 0D2h, 0E6h, 0F4h, 0B4h, 0C0h, 0D1h, 066h, 0AFh, 0C2h, 039h, 04Bh, 063h, 0B6h

kuz_IS label byte
    db 0A5h, 02Dh, 032h, 08Fh, 00Eh, 030h, 038h, 0C0h, 054h, 0E6h, 09Eh, 039h, 055h, 07Eh, 052h, 091h
    db 064h, 003h, 057h, 05Ah, 01Ch, 060h, 007h, 018h, 021h, 072h, 0A8h, 0D1h, 029h, 0C6h, 0A4h, 03Fh
    db 0E0h, 027h, 08Dh, 00Ch, 082h, 0EAh, 0AEh, 0B4h, 09Ah, 063h, 049h, 0E5h, 042h, 0E4h, 015h, 0B7h
    db 0C8h, 006h, 070h, 09Dh, 041h, 075h, 019h, 0C9h, 0AAh, 0FCh, 04Dh, 0BFh, 02Ah, 073h, 084h, 0D5h
    db 0C3h, 0AFh, 02Bh, 086h, 0A7h, 0B1h, 0B2h, 05Bh, 046h, 0D3h, 09Fh, 0FDh, 0D4h, 00Fh, 09Ch, 02Fh
    db 09Bh, 043h, 0EFh, 0D9h, 079h, 0B6h, 053h, 07Fh, 0C1h, 0F0h, 023h, 0E7h, 025h, 05Eh, 0B5h, 01Eh
    db 0A2h, 0DFh, 0A6h, 0FEh, 0ACh, 022h, 0F9h, 0E2h, 04Ah, 0BCh, 035h, 0CAh, 0EEh, 078h, 005h, 06Bh
    db 051h, 0E1h, 059h, 0A3h, 0F2h, 071h, 056h, 011h, 06Ah, 089h, 094h, 065h, 08Ch, 0BBh, 077h, 03Ch
    db 07Bh, 028h, 0ABh, 0D2h, 031h, 0DEh, 0C4h, 05Fh, 0CCh, 0CFh, 076h, 02Ch, 0B8h, 0D8h, 02Eh, 036h
    db 0DBh, 069h, 0B3h, 014h, 095h, 0BEh, 062h, 0A1h, 03Bh, 016h, 066h, 0E9h, 05Ch, 06Ch, 06Dh, 0ADh
    db 037h, 061h, 04Bh, 0B9h, 0E3h, 0BAh, 0F1h, 0A0h, 085h, 083h, 0DAh, 047h, 0C5h, 0B0h, 033h, 0FAh
    db 096h, 06Fh, 06Eh, 0C2h, 0F6h, 050h, 0FFh, 05Dh, 0A9h, 08Eh, 017h, 01Bh, 097h, 07Dh, 0ECh, 058h
    db 0F7h, 01Fh, 0FBh, 07Ch, 009h, 00Dh, 07Ah, 067h, 045h, 087h, 0DCh, 0E8h, 04Fh, 01Dh, 04Eh, 004h
    db 0EBh, 0F8h, 0F3h, 03Eh, 03Dh, 0BDh, 08Ah, 088h, 0DDh, 0CDh, 00Bh, 013h, 098h, 002h, 093h, 080h
    db 090h, 0D0h, 024h, 034h, 0CBh, 0EDh, 0F4h, 0CEh, 099h, 010h, 044h, 040h, 092h, 03Ah, 001h, 026h
    db 012h, 01Ah, 048h, 068h, 0F5h, 081h, 08Bh, 0C7h, 0D6h, 020h, 00Ah, 008h, 000h, 04Ch, 0D7h, 074h

; Coefficients for a[0..15] in l(a): a[0]*148 ^ a[1]*32 ^ ... ^ a[14]*148 ^ a[15]*1
kuz_lvec label byte
    db 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1

.data?
align 16
kuz_T       dq 8192 dup (?)             ; T[16][256][2]
align 16
kuz_IT      dq 8192 dup (?)             ; IT[16][256][2]
align 16
kuz_C       dq 64 dup (?)               ; C[32][2]
kuz_ready   dd ?

.code

; =============================================================================
; kuz_l_eval(rcx = buf16) -> al = l(buf16) in GF(2^8, 0x1C3)
; Leaf. Clobbers eax, edx, r8, r9, r10, r11.
; =============================================================================
kuz_l_eval proc
    lea     r8, [kuz_lvec]
    xor     r9d, r9d                        ; acc = 0
    xor     r10d, r10d                      ; idx = 0..15
kle_byte:
    movzx   eax, byte ptr [rcx+r10]         ; x
    movzx   edx, byte ptr [r8+r10]          ; y
    mov     r11d, 8
kle_bit:
    test    dl, 1
    jz      kle_noxor
    xor     r9d, eax
kle_noxor:
    add     eax, eax
    test    eax, 0100h
    jz      kle_nored
    xor     eax, 01C3h
kle_nored:
    shr     edx, 1
    dec     r11d
    jnz     kle_bit

    inc     r10d
    cmp     r10d, 16
    jb      kle_byte

    mov     eax, r9d
    ret
kuz_l_eval endp

; =============================================================================
; kuz_apply_L(rcx = buf16) - applies L = R^16 in-place
; =============================================================================
kuz_apply_L proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     rbx, rcx
    mov     esi, 16
kal_step:
    mov     rcx, rbx
    call    kuz_l_eval
    ; Shift right bytes: buf[15]=buf[14]..buf[1]=buf[0], buf[0]=al
    mov     edx, 15
kal_shift:
    mov     r8b, byte ptr [rbx+rdx-1]
    mov     byte ptr [rbx+rdx], r8b
    dec     edx
    jnz     kal_shift
    mov     byte ptr [rbx], al
    dec     esi
    jnz     kal_step

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
kuz_apply_L endp

; =============================================================================
; kuz_apply_IL(rcx = buf16) - applies IL = IR^16 in-place
; =============================================================================
kuz_apply_IL proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     rbx, rcx
    mov     esi, 16
kail_step:
    movzx   eax, byte ptr [rbx]             ; save val[0]
    xor     edx, edx
kail_shift:
    mov     r8b, byte ptr [rbx+rdx+1]
    mov     byte ptr [rbx+rdx], r8b
    inc     edx
    cmp     edx, 15
    jb      kail_shift
    mov     byte ptr [rbx+15], al
    mov     rcx, rbx
    call    kuz_l_eval
    mov     byte ptr [rbx+15], al
    dec     esi
    jnz     kail_step

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
kuz_apply_IL endp

; =============================================================================
; kuznyechik_init_tables()
; =============================================================================
kuznyechik_init_tables proc frame
    FRAME_PROLOG 96
    ; [rbp-16..48] = r12..r14, rbx, rsi, rdi (use [rbp-16..56])
    ; [rsp+32..47] = 16-byte scratch v
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], rbx
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    ; 1. T[16][256][2]
    lea     r12, [kuz_S]
    lea     rdi, [kuz_T]
    xor     ebx, ebx                        ; i = 0..15
kit_ti:
    xor     esi, esi                        ; j = 0..255
kit_tj:
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0
    movzx   eax, byte ptr [r12+rsi]
    mov     byte ptr [rsp+32+rbx], al
    lea     rcx, [rsp+32]
    call    kuz_apply_L
    mov     rax, qword ptr [rsp+32]
    mov     rdx, qword ptr [rsp+40]
    mov     qword ptr [rdi], rax
    mov     qword ptr [rdi+8], rdx
    add     rdi, 16
    inc     esi
    cmp     esi, 256
    jb      kit_tj
    inc     ebx
    cmp     ebx, 16
    jb      kit_ti

    ; 2. IT[16][256][2]
    lea     r12, [kuz_IS]
    lea     rdi, [kuz_IT]
    xor     ebx, ebx
kit_iti:
    xor     esi, esi
kit_itj:
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0
    movzx   eax, byte ptr [r12+rsi]
    mov     byte ptr [rsp+32+rbx], al
    lea     rcx, [rsp+32]
    call    kuz_apply_IL
    mov     rax, qword ptr [rsp+32]
    mov     rdx, qword ptr [rsp+40]
    mov     qword ptr [rdi], rax
    mov     qword ptr [rdi+8], rdx
    add     rdi, 16
    inc     esi
    cmp     esi, 256
    jb      kit_itj
    inc     ebx
    cmp     ebx, 16
    jb      kit_iti

    ; 3. C[32][2] (idx = 0..31 -> v.cc[15] = idx + 1)
    lea     rdi, [kuz_C]
    mov     ebx, 1
kit_c:
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0
    mov     byte ptr [rsp+47], bl
    lea     rcx, [rsp+32]
    call    kuz_apply_L
    mov     rax, qword ptr [rsp+32]
    mov     rdx, qword ptr [rsp+40]
    mov     qword ptr [rdi], rax
    mov     qword ptr [rdi+8], rdx
    add     rdi, 16
    inc     ebx
    cmp     ebx, 32
    jbe     kit_c

    mov     dword ptr [kuz_ready], 1

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     rbx, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
kuznyechik_init_tables endp

; =============================================================================
; Helper: kuz_LS(rcx = x1, rdx = x2) -> rax = t1, rdx = t2
; Leaf. Clobbers rax, rcx, rdx, r8, r9, r10, r11.
; =============================================================================
kuz_LS proc
    lea     r8, [kuz_T]
    xor     r9d, r9d                        ; t1
    xor     r10d, r10d                      ; t2

    ; Process 8 bytes of x1 (rcx) across T[0..7]
    mov     r11d, 8
kls_1:
    movzx   eax, cl
    shl     eax, 4                          ; j * 16
    xor     r9,  qword ptr [r8+rax]
    xor     r10, qword ptr [r8+rax+8]
    shr     rcx, 8
    add     r8,  4096                       ; next table T[i] (256 * 16)
    dec     r11d
    jnz     kls_1

    ; Process 8 bytes of x2 (rdx) across T[8..15]
    mov     r11d, 8
kls_2:
    movzx   eax, dl
    shl     eax, 4
    xor     r9,  qword ptr [r8+rax]
    xor     r10, qword ptr [r8+rax+8]
    shr     rdx, 8
    add     r8,  4096
    dec     r11d
    jnz     kls_2

    mov     rax, r9
    mov     rdx, r10
    ret
kuz_LS endp

; =============================================================================
; Helper: kuz_ILS(rcx = x1, rdx = x2) -> rax = t1, rdx = t2
; Leaf. Clobbers rax, rcx, rdx, r8, r9, r10, r11.
; =============================================================================
kuz_ILS proc
    lea     r8, [kuz_IT]
    xor     r9d, r9d
    xor     r10d, r10d

    mov     r11d, 8
kils_1:
    movzx   eax, cl
    shl     eax, 4
    xor     r9,  qword ptr [r8+rax]
    xor     r10, qword ptr [r8+rax+8]
    shr     rcx, 8
    add     r8,  4096
    dec     r11d
    jnz     kils_1

    mov     r11d, 8
kils_2:
    movzx   eax, dl
    shl     eax, 4
    xor     r9,  qword ptr [r8+rax]
    xor     r10, qword ptr [r8+rax+8]
    shr     rdx, 8
    add     r8,  4096
    dec     r11d
    jnz     kils_2

    mov     rax, r9
    mov     rdx, r10
    ret
kuz_ILS endp

; =============================================================================
; Helper: kuz_ILSS(rcx = x1, rdx = x2) -> rax = t1, rdx = t2
; Applies S-box then IT[0..15]. Leaf.
; =============================================================================
kuz_ILSS proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-16], rbx
    lea     rbx, [kuz_S]
    lea     r8,  [kuz_IT]
    xor     r9d, r9d
    xor     r10d, r10d

    mov     r11d, 8
kilss_1:
    movzx   eax, cl
    movzx   eax, byte ptr [rbx+rax]
    shl     eax, 4
    xor     r9,  qword ptr [r8+rax]
    xor     r10, qword ptr [r8+rax+8]
    shr     rcx, 8
    add     r8,  4096
    dec     r11d
    jnz     kilss_1

    mov     r11d, 8
kilss_2:
    movzx   eax, dl
    movzx   eax, byte ptr [rbx+rax]
    shl     eax, 4
    xor     r9,  qword ptr [r8+rax]
    xor     r10, qword ptr [r8+rax+8]
    shr     rdx, 8
    add     r8,  4096
    dec     r11d
    jnz     kilss_2

    mov     rax, r9
    mov     rdx, r10
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
kuz_ILSS endp

; =============================================================================
; kuznyechik_set_key(rcx = key32, rdx = ks320)
; ks layout: rke[0..19] (160B) followed by rkd[0..19] (160B)
; =============================================================================
LANDING_PAD
public kuznyechik_set_key
kuznyechik_set_key proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; key32
    mov     rdi, rdx                        ; ks320

    cmp     dword ptr [kuz_ready], 0
    jne     ksk_expand
    call    kuznyechik_init_tables

ksk_expand:
    mov     r12, qword ptr [rsi]            ; k00
    mov     r13, qword ptr [rsi+8]          ; k01
    mov     r14, qword ptr [rsi+16]         ; k10
    mov     r15, qword ptr [rsi+24]         ; k11

    mov     qword ptr [rdi],    r12
    mov     qword ptr [rdi+8],  r13
    mov     qword ptr [rdi+16], r14
    mov     qword ptr [rdi+24], r15

    lea     rbx, [kuz_C]
    xor     esi, esi                        ; round idx 0..31
ksk_fk:
    ; Feistel step: (k00,k01,k10,k11) -> (LS(k00^C[i][0], k01^C[i][1]) ^ (k10,k11), k00, k01)
    mov     rcx, r12
    mov     rdx, r13
    xor     rcx, qword ptr [rbx+rsi*8]      ; note: rsi steps by 2 qwords below!
    xor     rdx, qword ptr [rbx+rsi*8+8]
    call    kuz_LS
    xor     rax, r14
    xor     rdx, r15
    mov     r14, r12
    mov     r15, r13
    mov     r12, rax
    mov     r13, rdx

    add     esi, 2                          ; 2 qwords per C entry (total 64 qwords)
    mov     eax, esi
    and     eax, 15                         ; every 8 rounds (16 qwords), emit 4 round-key qwords
    jnz     ksk_fk

    ; Store rke[4..7], [8..11], [12..15], [16..19] at offset (esi*2)
    mov     eax, esi
    add     eax, eax                        ; 16 -> 32, 32 -> 64, 48 -> 96, 64 -> 128
    mov     qword ptr [rdi+rax],    r12
    mov     qword ptr [rdi+rax+8],  r13
    mov     qword ptr [rdi+rax+16], r14
    mov     qword ptr [rdi+rax+24], r15
    cmp     esi, 64
    jb      ksk_fk

    ; Build rkd[0..19] at [rdi+160..319]
    mov     rax, qword ptr [rdi]
    mov     rdx, qword ptr [rdi+8]
    mov     qword ptr [rdi+160], rax
    mov     qword ptr [rdi+168], rdx

    mov     esi, 1
ksk_rkd:
    mov     eax, esi
    shl     eax, 4
    mov     rcx, qword ptr [rdi+rax]
    mov     rdx, qword ptr [rdi+rax+8]
    call    kuz_ILSS
    mov     ecx, esi
    shl     ecx, 4
    mov     qword ptr [rdi+160+rcx],   rax
    mov     qword ptr [rdi+160+rcx+8], rdx
    inc     esi
    cmp     esi, 10
    jb      ksk_rkd

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
kuznyechik_set_key endp

; =============================================================================
; kuznyechik_enc_block(rcx = ks320, rdx = blk16)
; =============================================================================
LANDING_PAD
public kuznyechik_enc_block
kuznyechik_enc_block proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    mov     rbx, rcx                        ; ks
    mov     rsi, rdx                        ; blk16

    mov     rax, qword ptr [rsi]
    mov     rdx, qword ptr [rsi+8]
    xor     edi, edi
keb_rnd:
    xor     rax, qword ptr [rbx+rdi]
    xor     rdx, qword ptr [rbx+rdi+8]
    mov     rcx, rax
    call    kuz_LS
    add     edi, 16
    cmp     edi, 144                        ; 9 rounds (0..8 * 16)
    jb      keb_rnd

    xor     rax, qword ptr [rbx+144]
    xor     rdx, qword ptr [rbx+152]
    mov     qword ptr [rsi],   rax
    mov     qword ptr [rsi+8], rdx

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
kuznyechik_enc_block endp

; =============================================================================
; kuznyechik_dec_block(rcx = ks320, rdx = blk16)
; =============================================================================
LANDING_PAD
public kuznyechik_dec_block
kuznyechik_dec_block proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    mov     rbx, rcx                        ; ks
    mov     rsi, rdx                        ; blk16

    mov     rcx, qword ptr [rsi]
    mov     rdx, qword ptr [rsi+8]
    call    kuz_ILSS

    mov     edi, 144                        ; rkd[18..19] down to rkd[4..5]
kdb_rnd:
    xor     rax, qword ptr [rbx+160+rdi]
    xor     rdx, qword ptr [rbx+160+rdi+8]
    mov     rcx, rax
    call    kuz_ILS
    sub     edi, 16
    cmp     edi, 16
    ja      kdb_rnd

    ; Final round: xor rkd[2..3], apply IS bytewise, xor rkd[0..1]
    xor     rax, qword ptr [rbx+176]
    xor     rdx, qword ptr [rbx+184]
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], rdx

    lea     r8, [kuz_IS]
    xor     ecx, ecx
kdb_is:
    movzx   eax, byte ptr [rsp+32+rcx]
    movzx   eax, byte ptr [r8+rax]
    mov     byte ptr [rsp+32+rcx], al
    inc     ecx
    cmp     ecx, 16
    jb      kdb_is

    mov     rax, qword ptr [rsp+32]
    mov     rdx, qword ptr [rsp+40]
    xor     rax, qword ptr [rbx+160]
    xor     rdx, qword ptr [rbx+168]
    mov     qword ptr [rsi],   rax
    mov     qword ptr [rsi+8], rdx

    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
kuznyechik_dec_block endp

end
