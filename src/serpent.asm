; =============================================================================
; serpent.asm - Serpent-256 bitsliced block cipher (128-bit block, 256-bit key)
; -----------------------------------------------------------------------------
;   serpent_set_key   (rcx = key32, rdx = ks560)
;   serpent_enc_block (rcx = ks560, rdx = blk16)
;   serpent_dec_block (rcx = ks560, rdx = blk16)
;
; Key schedule layout (560 bytes = 140 dwords):
;   W[0..7]    pre-key words (wiped after schedule expansion)
;   W[8..139]  33 * 4 subkey words (round_key[0..131] at ks + 32)
;
; Bitsliced S-box expressions from Dag Arne Osvik ("Speeding Up Serpent"),
; matching VeraCrypt / TrueCrypt SerpentFast_sbox.h.
; Registers in block state: B0=r8d, B1=r9d, B2=r10d, B3=r11d, scratch B4=eax.
; =============================================================================

include macros.inc

; -----------------------------------------------------------------------------
; Forward S-boxes (B0=r8d, B1=r9d, B2=r10d, B3=r11d, B4=eax)
; -----------------------------------------------------------------------------
SRP_E1 macro
    xor     r11d, r8d
    mov     eax,  r9d
    and     r9d,  r11d
    xor     eax,  r10d
    xor     r9d,  r8d
    or      r8d,  r11d
    xor     r8d,  eax
    xor     eax,  r11d
    xor     r11d, r10d
    or      r10d, r9d
    xor     r10d, eax
    not     eax
    or      eax,  r9d
    xor     r9d,  r11d
    xor     r9d,  eax
    or      r11d, r8d
    xor     r9d,  r11d
    xor     eax,  r11d
    mov     r11d, r8d
    mov     r8d,  r9d
    mov     r9d,  eax
endm

SRP_E2 macro
    not     r8d
    not     r10d
    mov     eax,  r8d
    and     r8d,  r9d
    xor     r10d, r8d
    or      r8d,  r11d
    xor     r11d, r10d
    xor     r9d,  r8d
    xor     r8d,  eax
    or      eax,  r9d
    xor     r9d,  r11d
    or      r10d, r8d
    and     r10d, eax
    xor     r8d,  r9d
    and     r9d,  r10d
    xor     r9d,  r8d
    and     r8d,  r10d
    xor     eax,  r8d
    mov     r8d,  r10d
    mov     r10d, r11d
    mov     r11d, r9d
    mov     r9d,  eax
endm

SRP_E3 macro
    mov     eax,  r8d
    and     r8d,  r10d
    xor     r8d,  r11d
    xor     r10d, r9d
    xor     r10d, r8d
    or      r11d, eax
    xor     r11d, r9d
    xor     eax,  r10d
    mov     r9d,  r11d
    or      r11d, eax
    xor     r11d, r8d
    and     r8d,  r9d
    xor     eax,  r8d
    xor     r9d,  r11d
    xor     r9d,  eax
    mov     r8d,  r10d
    mov     r10d, r9d
    mov     r9d,  r11d
    not     eax
    mov     r11d, eax
endm

SRP_E4 macro
    mov     eax,  r8d
    or      r8d,  r11d
    xor     r11d, r9d
    and     r9d,  eax
    xor     eax,  r10d
    xor     r10d, r11d
    and     r11d, r8d
    or      eax,  r9d
    xor     r11d, eax
    xor     r8d,  r9d
    and     eax,  r8d
    xor     r9d,  r11d
    xor     eax,  r10d
    or      r9d,  r8d
    xor     r9d,  r10d
    xor     r8d,  r11d
    mov     r10d, r9d
    or      r9d,  r11d
    xor     r8d,  r9d
    mov     r9d,  r10d
    mov     r10d, r11d
    mov     r11d, eax
endm

SRP_E5 macro
    xor     r9d,  r11d
    not     r11d
    xor     r10d, r11d
    xor     r11d, r8d
    mov     eax,  r9d
    and     r9d,  r11d
    xor     r9d,  r10d
    xor     eax,  r11d
    xor     r8d,  eax
    and     r10d, eax
    xor     r10d, r8d
    and     r8d,  r9d
    xor     r11d, r8d
    or      eax,  r9d
    xor     eax,  r8d
    or      r8d,  r11d
    xor     r8d,  r10d
    and     r10d, r11d
    not     r8d
    xor     eax,  r10d
    mov     r10d, r8d
    mov     r8d,  r9d
    mov     r9d,  eax
endm

SRP_E6 macro
    xor     r8d,  r9d
    xor     r9d,  r11d
    not     r11d
    mov     eax,  r9d
    and     r9d,  r8d
    xor     r10d, r11d
    xor     r9d,  r10d
    or      r10d, eax
    xor     eax,  r11d
    and     r11d, r9d
    xor     r11d, r8d
    xor     eax,  r9d
    xor     eax,  r10d
    xor     r10d, r8d
    and     r8d,  r11d
    not     r10d
    xor     r8d,  eax
    or      eax,  r11d
    xor     eax,  r10d
    mov     r10d, r8d
    mov     r8d,  r9d
    mov     r9d,  r11d
    mov     r11d, eax
endm

SRP_E7 macro
    not     r10d
    mov     eax,  r11d
    and     r11d, r8d
    xor     r8d,  eax
    xor     r11d, r10d
    or      r10d, eax
    xor     r9d,  r11d
    xor     r10d, r8d
    or      r8d,  r9d
    xor     r10d, r9d
    xor     eax,  r8d
    or      r8d,  r11d
    xor     r8d,  r10d
    xor     eax,  r11d
    xor     eax,  r8d
    not     r11d
    and     r10d, eax
    xor     r11d, r10d
    mov     r10d, eax
endm

SRP_E8 macro
    mov     eax,  r9d
    or      r9d,  r10d
    xor     r9d,  r11d
    xor     eax,  r10d
    xor     r10d, r9d
    or      r11d, eax
    and     r11d, r8d
    xor     eax,  r10d
    xor     r11d, r9d
    or      r9d,  eax
    xor     r9d,  r8d
    or      r8d,  eax
    xor     r8d,  r10d
    xor     r9d,  eax
    xor     r10d, r9d
    and     r9d,  r8d
    xor     r9d,  eax
    not     r10d
    or      r10d, r8d
    xor     eax,  r10d
    mov     r10d, r9d
    mov     r9d,  r11d
    mov     r11d, r8d
    mov     r8d,  eax
endm

; -----------------------------------------------------------------------------
; Inverse S-boxes (B0=r8d, B1=r9d, B2=r10d, B3=r11d, B4=eax)
; -----------------------------------------------------------------------------
SRP_D1 macro
    not     r10d
    mov     eax,  r9d
    or      r9d,  r8d
    not     eax
    xor     r9d,  r10d
    or      r10d, eax
    xor     r9d,  r11d
    xor     r8d,  eax
    xor     r10d, r8d
    and     r8d,  r11d
    xor     eax,  r8d
    or      r8d,  r9d
    xor     r8d,  r10d
    xor     r11d, eax
    xor     r10d, r9d
    xor     r11d, r8d
    xor     r11d, r9d
    and     r10d, r11d
    xor     eax,  r10d
    mov     r10d, r9d
    mov     r9d,  eax
endm

SRP_D2 macro
    mov     eax,  r9d
    xor     r9d,  r11d
    and     r11d, r9d
    xor     eax,  r10d
    xor     r11d, r8d
    or      r8d,  r9d
    xor     r10d, r11d
    xor     r8d,  eax
    or      r8d,  r10d
    xor     r9d,  r11d
    xor     r8d,  r9d
    or      r9d,  r11d
    xor     r9d,  r8d
    not     eax
    xor     eax,  r9d
    or      r9d,  r8d
    xor     r9d,  r8d
    or      r9d,  eax
    xor     r11d, r9d
    mov     r9d,  r8d
    mov     r8d,  eax
    mov     eax,  r10d
    mov     r10d, r11d
    mov     r11d, eax
endm

SRP_D3 macro
    xor     r10d, r11d
    xor     r11d, r8d
    mov     eax,  r11d
    and     r11d, r10d
    xor     r11d, r9d
    or      r9d,  r10d
    xor     r9d,  eax
    and     eax,  r11d
    xor     r10d, r11d
    and     eax,  r8d
    xor     eax,  r10d
    and     r10d, r9d
    or      r10d, r8d
    not     r11d
    xor     r10d, r11d
    xor     r8d,  r11d
    and     r8d,  r9d
    xor     r11d, eax
    xor     r11d, r8d
    mov     r8d,  r9d
    mov     r9d,  eax
endm

SRP_D4 macro
    mov     eax,  r10d
    xor     r10d, r9d
    xor     r8d,  r10d
    and     eax,  r10d
    xor     eax,  r8d
    and     r8d,  r9d
    xor     r9d,  r11d
    or      r11d, eax
    xor     r10d, r11d
    xor     r8d,  r11d
    xor     r9d,  eax
    and     r11d, r10d
    xor     r11d, r9d
    xor     r9d,  r8d
    or      r9d,  r10d
    xor     r8d,  r11d
    xor     r9d,  eax
    xor     r8d,  r9d
    mov     eax,  r8d
    mov     r8d,  r10d
    mov     r10d, r11d
    mov     r11d, eax
endm

SRP_D5 macro
    mov     eax,  r10d
    and     r10d, r11d
    xor     r10d, r9d
    or      r9d,  r11d
    and     r9d,  r8d
    xor     eax,  r10d
    xor     eax,  r9d
    and     r9d,  r10d
    not     r8d
    xor     r11d, eax
    xor     r9d,  r11d
    and     r11d, r8d
    xor     r11d, r10d
    xor     r8d,  r9d
    and     r10d, r8d
    xor     r11d, r8d
    xor     r10d, eax
    or      r10d, r11d
    xor     r11d, r8d
    xor     r10d, r9d
    mov     r9d,  r11d
    mov     r11d, eax
endm

SRP_D6 macro
    not     r9d
    mov     eax,  r11d
    xor     r10d, r9d
    or      r11d, r8d
    xor     r11d, r10d
    or      r10d, r9d
    and     r10d, r8d
    xor     eax,  r11d
    xor     r10d, eax
    or      eax,  r8d
    xor     eax,  r9d
    and     r9d,  r10d
    xor     r9d,  r11d
    xor     eax,  r10d
    and     r11d, eax
    xor     eax,  r9d
    xor     r11d, eax
    not     eax
    xor     r11d, r8d
    mov     r8d,  r9d
    mov     r9d,  eax
    mov     eax,  r11d
    mov     r11d, r10d
    mov     r10d, eax
endm

SRP_D7 macro
    xor     r8d,  r10d
    mov     eax,  r10d
    and     r10d, r8d
    xor     eax,  r11d
    not     r10d
    xor     r11d, r9d
    xor     r10d, r11d
    or      eax,  r8d
    xor     r8d,  r10d
    xor     r11d, eax
    xor     eax,  r9d
    and     r9d,  r11d
    xor     r9d,  r8d
    xor     r8d,  r11d
    or      r8d,  r10d
    xor     r11d, r9d
    xor     eax,  r8d
    mov     r8d,  r9d
    mov     r9d,  r10d
    mov     r10d, eax
endm

SRP_D8 macro
    mov     eax,  r10d
    xor     r10d, r8d
    and     r8d,  r11d
    or      eax,  r11d
    not     r10d
    xor     r11d, r9d
    or      r9d,  r8d
    xor     r8d,  r10d
    and     r10d, eax
    and     r11d, eax
    xor     r9d,  r10d
    xor     r10d, r8d
    or      r8d,  r10d
    xor     eax,  r9d
    xor     r8d,  r11d
    xor     r11d, eax
    or      eax,  r8d
    xor     r11d, r10d
    xor     eax,  r10d
    mov     r10d, r9d
    mov     r9d,  r8d
    mov     r8d,  r11d
    mov     r11d, eax
endm

; -----------------------------------------------------------------------------
; Linear / Inverse Linear Transforms & Round Key XOR (ks base in rcx)
; -----------------------------------------------------------------------------
SRP_TRANS macro
    rol     r8d,  13
    rol     r10d, 3
    xor     r9d,  r8d
    xor     r9d,  r10d
    mov     eax,  r8d
    shl     eax,  3
    xor     r11d, r10d
    xor     r11d, eax
    rol     r9d,  1
    rol     r11d, 7
    xor     r8d,  r9d
    xor     r8d,  r11d
    mov     eax,  r9d
    shl     eax,  7
    xor     r10d, r11d
    xor     r10d, eax
    rol     r8d,  5
    rol     r10d, 22
endm

SRP_ITRANS macro
    ror     r10d, 22
    ror     r8d,  5
    mov     eax,  r9d
    shl     eax,  7
    xor     r10d, r11d
    xor     r10d, eax
    xor     r8d,  r9d
    xor     r8d,  r11d
    ror     r11d, 7
    ror     r9d,  1
    mov     eax,  r8d
    shl     eax,  3
    xor     r11d, r10d
    xor     r11d, eax
    xor     r9d,  r8d
    xor     r9d,  r10d
    ror     r10d, 3
    ror     r8d,  13
endm

; round_key starts at ks + 32 -> round r is at ks + 32 + 16*r
SRP_KXOR macro r
    xor     r8d,  dword ptr [rcx + 32 + 16*r]
    xor     r9d,  dword ptr [rcx + 36 + 16*r]
    xor     r10d, dword ptr [rcx + 40 + 16*r]
    xor     r11d, dword ptr [rcx + 44 + 16*r]
endm

SRP_KS_BOX macro sbox, boff
    mov     r8d,  dword ptr [rdx + boff]
    mov     r9d,  dword ptr [rdx + boff + 4]
    mov     r10d, dword ptr [rdx + boff + 8]
    mov     r11d, dword ptr [rdx + boff + 12]
    sbox
    mov     dword ptr [rdx + boff],      r8d
    mov     dword ptr [rdx + boff + 4],  r9d
    mov     dword ptr [rdx + boff + 8],  r10d
    mov     dword ptr [rdx + boff + 12], r11d
endm

.code

; =============================================================================
; serpent_set_key(rcx = key32, rdx = ks560)
; Leaf. Uses only volatile registers (rax, rcx, rdx, r8..r11).
; =============================================================================
LANDING_PAD
public serpent_set_key
serpent_set_key proc
    ; Load W[0..7] from key32 (little-endian)
    mov     rax, qword ptr [rcx]
    mov     qword ptr [rdx], rax
    mov     rax, qword ptr [rcx+8]
    mov     qword ptr [rdx+8], rax
    mov     rax, qword ptr [rcx+16]
    mov     qword ptr [rdx+16], rax
    mov     rax, qword ptr [rcx+24]
    mov     qword ptr [rdx+24], rax

    ; Expand W[8..139]
    mov     ecx, 8
ssk_exp:
    mov     eax, dword ptr [rdx + rcx*4 - 32]
    xor     eax, dword ptr [rdx + rcx*4 - 20]
    xor     eax, dword ptr [rdx + rcx*4 - 12]
    xor     eax, dword ptr [rdx + rcx*4 - 4]
    xor     eax, 09E3779B9h
    lea     r8d, [ecx - 8]
    xor     eax, r8d
    rol     eax, 11
    mov     dword ptr [rdx + rcx*4], eax
    inc     ecx
    cmp     ecx, 140
    jb      ssk_exp

    ; Apply S-boxes to W[8..139] (byte offsets 32..544)
    SRP_KS_BOX SRP_E4, 32
    SRP_KS_BOX SRP_E3, 48
    SRP_KS_BOX SRP_E2, 64
    SRP_KS_BOX SRP_E1, 80
    SRP_KS_BOX SRP_E8, 96
    SRP_KS_BOX SRP_E7, 112
    SRP_KS_BOX SRP_E6, 128
    SRP_KS_BOX SRP_E5, 144

    SRP_KS_BOX SRP_E4, 160
    SRP_KS_BOX SRP_E3, 176
    SRP_KS_BOX SRP_E2, 192
    SRP_KS_BOX SRP_E1, 208
    SRP_KS_BOX SRP_E8, 224
    SRP_KS_BOX SRP_E7, 240
    SRP_KS_BOX SRP_E6, 256
    SRP_KS_BOX SRP_E5, 272

    SRP_KS_BOX SRP_E4, 288
    SRP_KS_BOX SRP_E3, 304
    SRP_KS_BOX SRP_E2, 320
    SRP_KS_BOX SRP_E1, 336
    SRP_KS_BOX SRP_E8, 352
    SRP_KS_BOX SRP_E7, 368
    SRP_KS_BOX SRP_E6, 384
    SRP_KS_BOX SRP_E5, 400

    SRP_KS_BOX SRP_E4, 416
    SRP_KS_BOX SRP_E3, 432
    SRP_KS_BOX SRP_E2, 448
    SRP_KS_BOX SRP_E1, 464
    SRP_KS_BOX SRP_E8, 480
    SRP_KS_BOX SRP_E7, 496
    SRP_KS_BOX SRP_E6, 512
    SRP_KS_BOX SRP_E5, 528

    SRP_KS_BOX SRP_E4, 544

    ; Wipe raw key words W[0..7] inside ks
    xor     eax, eax
    mov     qword ptr [rdx],    rax
    mov     qword ptr [rdx+8],  rax
    mov     qword ptr [rdx+16], rax
    mov     qword ptr [rdx+24], rax
    xor     r8d,  r8d
    xor     r9d,  r9d
    xor     r10d, r10d
    xor     r11d, r11d
    ret
serpent_set_key endp

; =============================================================================
; serpent_enc_block(rcx = ks560, rdx = blk16)
; Leaf. Uses only volatile registers (rax, rcx, rdx, r8..r11).
; =============================================================================
LANDING_PAD
public serpent_enc_block
serpent_enc_block proc
    mov     r8d,  dword ptr [rdx]
    mov     r9d,  dword ptr [rdx+4]
    mov     r10d, dword ptr [rdx+8]
    mov     r11d, dword ptr [rdx+12]

    SRP_KXOR 0
    SRP_E1
    SRP_TRANS
    SRP_KXOR 1
    SRP_E2
    SRP_TRANS
    SRP_KXOR 2
    SRP_E3
    SRP_TRANS
    SRP_KXOR 3
    SRP_E4
    SRP_TRANS
    SRP_KXOR 4
    SRP_E5
    SRP_TRANS
    SRP_KXOR 5
    SRP_E6
    SRP_TRANS
    SRP_KXOR 6
    SRP_E7
    SRP_TRANS
    SRP_KXOR 7
    SRP_E8
    SRP_TRANS

    SRP_KXOR 8
    SRP_E1
    SRP_TRANS
    SRP_KXOR 9
    SRP_E2
    SRP_TRANS
    SRP_KXOR 10
    SRP_E3
    SRP_TRANS
    SRP_KXOR 11
    SRP_E4
    SRP_TRANS
    SRP_KXOR 12
    SRP_E5
    SRP_TRANS
    SRP_KXOR 13
    SRP_E6
    SRP_TRANS
    SRP_KXOR 14
    SRP_E7
    SRP_TRANS
    SRP_KXOR 15
    SRP_E8
    SRP_TRANS

    SRP_KXOR 16
    SRP_E1
    SRP_TRANS
    SRP_KXOR 17
    SRP_E2
    SRP_TRANS
    SRP_KXOR 18
    SRP_E3
    SRP_TRANS
    SRP_KXOR 19
    SRP_E4
    SRP_TRANS
    SRP_KXOR 20
    SRP_E5
    SRP_TRANS
    SRP_KXOR 21
    SRP_E6
    SRP_TRANS
    SRP_KXOR 22
    SRP_E7
    SRP_TRANS
    SRP_KXOR 23
    SRP_E8
    SRP_TRANS

    SRP_KXOR 24
    SRP_E1
    SRP_TRANS
    SRP_KXOR 25
    SRP_E2
    SRP_TRANS
    SRP_KXOR 26
    SRP_E3
    SRP_TRANS
    SRP_KXOR 27
    SRP_E4
    SRP_TRANS
    SRP_KXOR 28
    SRP_E5
    SRP_TRANS
    SRP_KXOR 29
    SRP_E6
    SRP_TRANS
    SRP_KXOR 30
    SRP_E7
    SRP_TRANS
    SRP_KXOR 31
    SRP_E8
    SRP_KXOR 32

    mov     dword ptr [rdx],    r8d
    mov     dword ptr [rdx+4],  r9d
    mov     dword ptr [rdx+8],  r10d
    mov     dword ptr [rdx+12], r11d
    xor     eax,  eax
    xor     r8d,  r8d
    xor     r9d,  r9d
    xor     r10d, r10d
    xor     r11d, r11d
    ret
serpent_enc_block endp

; =============================================================================
; serpent_dec_block(rcx = ks560, rdx = blk16)
; Leaf. Uses only volatile registers (rax, rcx, rdx, r8..r11).
; =============================================================================
LANDING_PAD
public serpent_dec_block
serpent_dec_block proc
    mov     r8d,  dword ptr [rdx]
    mov     r9d,  dword ptr [rdx+4]
    mov     r10d, dword ptr [rdx+8]
    mov     r11d, dword ptr [rdx+12]

    SRP_KXOR 32
    SRP_D8
    SRP_KXOR 31
    SRP_ITRANS
    SRP_D7
    SRP_KXOR 30
    SRP_ITRANS
    SRP_D6
    SRP_KXOR 29
    SRP_ITRANS
    SRP_D5
    SRP_KXOR 28
    SRP_ITRANS
    SRP_D4
    SRP_KXOR 27
    SRP_ITRANS
    SRP_D3
    SRP_KXOR 26
    SRP_ITRANS
    SRP_D2
    SRP_KXOR 25
    SRP_ITRANS
    SRP_D1
    SRP_KXOR 24

    SRP_ITRANS
    SRP_D8
    SRP_KXOR 23
    SRP_ITRANS
    SRP_D7
    SRP_KXOR 22
    SRP_ITRANS
    SRP_D6
    SRP_KXOR 21
    SRP_ITRANS
    SRP_D5
    SRP_KXOR 20
    SRP_ITRANS
    SRP_D4
    SRP_KXOR 19
    SRP_ITRANS
    SRP_D3
    SRP_KXOR 18
    SRP_ITRANS
    SRP_D2
    SRP_KXOR 17
    SRP_ITRANS
    SRP_D1
    SRP_KXOR 16

    SRP_ITRANS
    SRP_D8
    SRP_KXOR 15
    SRP_ITRANS
    SRP_D7
    SRP_KXOR 14
    SRP_ITRANS
    SRP_D6
    SRP_KXOR 13
    SRP_ITRANS
    SRP_D5
    SRP_KXOR 12
    SRP_ITRANS
    SRP_D4
    SRP_KXOR 11
    SRP_ITRANS
    SRP_D3
    SRP_KXOR 10
    SRP_ITRANS
    SRP_D2
    SRP_KXOR 9
    SRP_ITRANS
    SRP_D1
    SRP_KXOR 8

    SRP_ITRANS
    SRP_D8
    SRP_KXOR 7
    SRP_ITRANS
    SRP_D7
    SRP_KXOR 6
    SRP_ITRANS
    SRP_D6
    SRP_KXOR 5
    SRP_ITRANS
    SRP_D5
    SRP_KXOR 4
    SRP_ITRANS
    SRP_D4
    SRP_KXOR 3
    SRP_ITRANS
    SRP_D3
    SRP_KXOR 2
    SRP_ITRANS
    SRP_D2
    SRP_KXOR 1
    SRP_ITRANS
    SRP_D1
    SRP_KXOR 0

    mov     dword ptr [rdx],    r8d
    mov     dword ptr [rdx+4],  r9d
    mov     dword ptr [rdx+8],  r10d
    mov     dword ptr [rdx+12], r11d
    xor     eax,  eax
    xor     r8d,  r8d
    xor     r9d,  r9d
    xor     r10d, r10d
    xor     r11d, r11d
    ret
serpent_dec_block endp

end
