; =============================================================================
; twofish.asm - Twofish-256 block cipher (128-bit block, 256-bit key)
; -----------------------------------------------------------------------------
;   twofish_set_key   (rcx = key32, rdx = ks4256)
;   twofish_enc_block (rcx = ks4256, rdx = blk16)
;   twofish_dec_block (rcx = ks4256, rdx = blk16)
;
; Key schedule layout (4256 bytes):
;   [0   .. 159]  l_key[40]     (40 dwords)
;   [160 .. 4255] mk_tab[4*256] (interleaved: mk_tab[c + 4*i], 1024 dwords)
; =============================================================================

include macros.inc

.const
tf_ror4 label byte
    db 0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15

tf_ashx label byte
    db 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7

tf_tab5b label byte
    db 0, 05Ah, 0B4h, 0EEh

tf_tabef label byte
    db 0, 0EEh, 0B4h, 05Ah

; qt[n=0..1][sub=0..3][16]: 2 * 64 = 128 bytes
; n=0: qt0[0], qt1[0], qt2[0], qt3[0]
; n=1: qt0[1], qt1[1], qt2[1], qt3[1]
tf_qt label byte
    ; n = 0
    db  8,  1,  7, 13,  6, 15,  3,  2,  0, 11,  5,  9, 14, 12, 10,  4   ; qt0[0]
    db 14, 12, 11,  8,  1,  2,  3,  5, 15,  4, 10,  6,  7,  0,  9, 13   ; qt1[0]
    db 11, 10,  5, 14,  6, 13,  9,  0, 12,  8, 15,  3,  2,  4,  7,  1   ; qt2[0]
    db 13,  7, 15,  4,  1,  2,  6, 14,  9, 11,  3,  0,  8,  5, 12, 10   ; qt3[0]
    ; n = 1
    db  2,  8, 11, 13, 15,  7,  6, 14,  3,  1,  9,  4,  0, 10, 12,  5   ; qt0[1]
    db  1, 14,  2, 11,  4, 12,  3,  7,  6, 13, 10,  5, 15,  9,  0,  8   ; qt1[1]
    db  4, 12,  7,  5,  1,  6,  9, 10,  0, 14, 13,  8,  2, 11,  3, 15   ; qt2[1]
    db 11,  9,  5,  1, 12,  3, 13, 14,  6,  4,  7, 15,  2,  0,  8, 10   ; qt3[1]

.data?
tf_qtab     db 512 dup (?)              ; q_tab[2][256]
align 4
tf_mtab     dd 1024 dup (?)             ; m_tab[4][256]
tf_ready    dd ?

.code

; =============================================================================
; tf_qp(ecx = n (0..1), edx = x (0..255)) -> al = qp(n, x)
; Leaf. Clobbers eax, ecx, edx, r8, r9, r10, r11.
; =============================================================================
tf_qp proc
    shl     ecx, 6                          ; n * 64
    lea     r8, [tf_qt]
    add     r8, rcx                         ; &tf_qt[n][0]
    lea     r9, [tf_ror4]
    lea     r10, [tf_ashx]

    mov     eax, edx
    shr     eax, 4                          ; a0 = x >> 4
    and     edx, 15                         ; b0 = x & 15

    mov     ecx, eax
    xor     ecx, edx                        ; a1 = a0 ^ b0
    movzx   r11d, byte ptr [r9+rdx]
    movzx   eax, byte ptr [r10+rax]
    xor     r11d, eax                       ; b1 = ror4[b0] ^ ashx[a0]

    movzx   eax, byte ptr [r8+rcx]          ; a2 = qt0[n][a1]
    movzx   edx, byte ptr [r8+16+r11]       ; b2 = qt1[n][b1]

    mov     ecx, eax
    xor     ecx, edx                        ; a3 = a2 ^ b2
    movzx   r11d, byte ptr [r9+rdx]
    movzx   eax, byte ptr [r10+rax]
    xor     r11d, eax                       ; b3 = ror4[b2] ^ ashx[a2]

    movzx   eax, byte ptr [r8+32+rcx]       ; a4 = qt2[n][a3]
    movzx   edx, byte ptr [r8+48+r11]       ; b4 = qt3[n][b3]
    shl     edx, 4
    or      eax, edx
    ret
tf_qp endp

; =============================================================================
; twofish_init_tables() - generates tf_qtab[2][256] and tf_mtab[4][256]
; =============================================================================
twofish_init_tables proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    lea     rdi, [tf_qtab]
    xor     ebx, ebx
tfit_q:
    xor     ecx, ecx
    mov     edx, ebx
    call    tf_qp
    mov     byte ptr [rdi+rbx], al
    mov     ecx, 1
    mov     edx, ebx
    call    tf_qp
    mov     byte ptr [rdi+256+rbx], al
    inc     ebx
    cmp     ebx, 256
    jb      tfit_q

    ; Generate m_tab[4][256]
    lea     rsi, [tf_mtab]
    lea     r8,  [tf_tab5b]
    lea     r9,  [tf_tabef]
    xor     ebx, ebx
tfit_m:
    ; --- q(1, i) -> m_tab[0][i], m_tab[2][i] ---
    movzx   eax, byte ptr [rdi+256+rbx]     ; f01 = q(1, i)
    mov     ecx, eax
    shr     ecx, 2
    xor     ecx, eax
    mov     edx, eax
    and     edx, 3
    movzx   r10d, byte ptr [r8+rdx]
    xor     ecx, r10d                       ; ecx = f5b

    mov     r11d, eax
    shr     r11d, 1
    mov     r10d, eax
    shr     r10d, 2
    xor     r11d, eax
    xor     r11d, r10d
    movzx   r10d, byte ptr [r9+rdx]
    xor     r11d, r10d                      ; r11d = fef

    ; m_tab[0][i] = f01 | (f5b << 8) | (fef << 16) | (fef << 24)
    mov     edx, r11d
    shl     edx, 8
    or      edx, r11d
    shl     edx, 8
    or      edx, ecx
    shl     edx, 8
    or      edx, eax
    mov     dword ptr [rsi+rbx*4], edx

    ; m_tab[2][i] = f5b | (fef << 8) | (f01 << 16) | (fef << 24)
    mov     edx, r11d
    shl     edx, 8
    or      edx, eax
    shl     edx, 8
    or      edx, r11d
    shl     edx, 8
    or      edx, ecx
    mov     dword ptr [rsi+2048+rbx*4], edx

    ; --- q(0, i) -> m_tab[1][i], m_tab[3][i] ---
    movzx   eax, byte ptr [rdi+rbx]         ; f01 = q(0, i)
    mov     ecx, eax
    shr     ecx, 2
    xor     ecx, eax
    mov     edx, eax
    and     edx, 3
    movzx   r10d, byte ptr [r8+rdx]
    xor     ecx, r10d                       ; ecx = f5b

    mov     r11d, eax
    shr     r11d, 1
    mov     r10d, eax
    shr     r10d, 2
    xor     r11d, eax
    xor     r11d, r10d
    movzx   r10d, byte ptr [r9+rdx]
    xor     r11d, r10d                      ; r11d = fef

    ; m_tab[1][i] = fef | (fef << 8) | (f5b << 16) | (f01 << 24)
    mov     edx, eax
    shl     edx, 8
    or      edx, ecx
    shl     edx, 8
    or      edx, r11d
    shl     edx, 8
    or      edx, r11d
    mov     dword ptr [rsi+1024+rbx*4], edx

    ; m_tab[3][i] = f5b | (f01 << 8) | (fef << 16) | (f5b << 24)
    mov     edx, ecx
    shl     edx, 8
    or      edx, r11d
    shl     edx, 8
    or      edx, eax
    shl     edx, 8
    or      edx, ecx
    mov     dword ptr [rsi+3072+rbx*4], edx

    inc     ebx
    cmp     ebx, 256
    jb      tfit_m

    mov     dword ptr [tf_ready], 1

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
twofish_init_tables endp

; =============================================================================
; tf_mds_rem(ecx = p0, edx = p1) -> eax = mds_rem(p0, p1)
; =============================================================================
tf_mds_rem proc
    mov     r8d, 8
tmr_loop:
    mov     eax, edx
    shr     eax, 24                         ; t = p1 >> 24
    shl     edx, 8
    mov     r9d, ecx
    shr     r9d, 24
    or      edx, r9d                        ; p1 = (p1 << 8) | (p0 >> 24)
    shl     ecx, 8                          ; p0 <<= 8

    mov     r9d, eax
    add     r9d, r9d                        ; u = t << 1
    test    eax, 080h
    jz      tmr_no1
    xor     r9d, 014Dh
tmr_no1:
    mov     r10d, r9d
    shl     r10d, 16
    xor     r10d, eax
    xor     edx, r10d                       ; p1 ^= t ^ (u << 16)

    mov     r10d, eax
    shr     r10d, 1
    xor     r9d, r10d                       ; u ^= (t >> 1)
    test    eax, 1
    jz      tmr_no2
    xor     r9d, (014Dh shr 1)
tmr_no2:
    mov     r10d, r9d
    shl     r10d, 24
    mov     r11d, r9d
    shl     r11d, 8
    or      r10d, r11d
    xor     edx, r10d                       ; p1 ^= (u << 24) | (u << 8)

    dec     r8d
    jnz     tmr_loop

    mov     eax, edx
    ret
tf_mds_rem endp

; =============================================================================
; tf_h_fun(ecx = x, rdx = key4_ptr) -> eax = h_fun(x, key[0..3])
; Leaf. Uses tf_qtab and tf_mtab.
; =============================================================================
tf_h_fun proc
    lea     r8, [tf_qtab]
    lea     r9, [tf_mtab]

    ; Extract bytes b0..b3 from ecx
    movzx   eax, cl                         ; b0
    shr     ecx, 8
    movzx   r10d, cl                        ; b1
    shr     ecx, 8
    movzx   r11d, cl                        ; b2
    shr     ecx, 8                          ; ecx = b3

    ; Stage 4 (key[3] at [rdx+12])
    movzx   eax,  byte ptr [r8+256+rax]     ; q(1, b0)
    xor     al,   byte ptr [rdx+12]
    movzx   r10d, byte ptr [r8+r10]         ; q(0, b1)
    xor     r10b, byte ptr [rdx+13]
    movzx   r11d, byte ptr [r8+r11]         ; q(0, b2)
    xor     r11b, byte ptr [rdx+14]
    movzx   ecx,  byte ptr [r8+256+rcx]     ; q(1, b3)
    xor     cl,   byte ptr [rdx+15]

    ; Stage 3 (key[2] at [rdx+8])
    movzx   eax,  byte ptr [r8+256+rax]     ; q(1, b0)
    xor     al,   byte ptr [rdx+8]
    movzx   r10d, byte ptr [r8+256+r10]     ; q(1, b1)
    xor     r10b, byte ptr [rdx+9]
    movzx   r11d, byte ptr [r8+r11]         ; q(0, b2)
    xor     r11b, byte ptr [rdx+10]
    movzx   ecx,  byte ptr [r8+rcx]         ; q(0, b3)
    xor     cl,   byte ptr [rdx+11]

    ; Stage 2 & 1 (key[1] at [rdx+4], key[0] at [rdx+0])
    movzx   eax,  byte ptr [r8+rax]         ; q(0, b0)
    xor     al,   byte ptr [rdx+4]
    movzx   eax,  byte ptr [r8+rax]         ; q(0, ...)
    xor     al,   byte ptr [rdx]

    movzx   r10d, byte ptr [r8+256+r10]     ; q(1, b1)
    xor     r10b, byte ptr [rdx+5]
    movzx   r10d, byte ptr [r8+r10]         ; q(0, ...)
    xor     r10b, byte ptr [rdx+1]

    movzx   r11d, byte ptr [r8+r11]         ; q(0, b2)
    xor     r11b, byte ptr [rdx+6]
    movzx   r11d, byte ptr [r8+256+r11]     ; q(1, ...)
    xor     r11b, byte ptr [rdx+2]

    movzx   ecx,  byte ptr [r8+256+rcx]     ; q(1, b3)
    xor     cl,   byte ptr [rdx+7]
    movzx   ecx,  byte ptr [r8+256+rcx]     ; q(1, ...)
    xor     cl,   byte ptr [rdx+3]

    ; MDS lookup
    mov     eax, dword ptr [r9+rax*4]
    xor     eax, dword ptr [r9+1024+r10*4]
    xor     eax, dword ptr [r9+2048+r11*4]
    xor     eax, dword ptr [r9+3072+rcx*4]
    ret
tf_h_fun endp

; =============================================================================
; twofish_set_key(rcx = key32, rdx = ks4256)
; =============================================================================
LANDING_PAD
public twofish_set_key
twofish_set_key proc frame
    FRAME_PROLOG 128
    ; [rbp-16..48] = r12..r13, rbx, rsi, rdi
    ; [rsp+32..47] = me_key[4]
    ; [rsp+48..63] = mo_key[4]
    ; [rsp+64..79] = s_key[4]
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], rbx
    mov     qword ptr [rbp-40], rsi
    mov     qword ptr [rbp-48], rdi

    mov     rsi, rcx                        ; key32
    mov     rdi, rdx                        ; ks4256

    cmp     dword ptr [tf_ready], 0
    jne     tsk_go
    call    twofish_init_tables

tsk_go:
    xor     ebx, ebx                        ; i = 0..3
tsk_skey:
    mov     ecx, dword ptr [rsi+rbx*8]      ; a = in_key[2*i]
    mov     edx, dword ptr [rsi+rbx*8+4]    ; b = in_key[2*i+1]
    mov     dword ptr [rsp+32+rbx*4], ecx   ; me_key[i]
    mov     dword ptr [rsp+48+rbx*4], edx   ; mo_key[i]
    call    tf_mds_rem
    mov     ecx, 3
    sub     ecx, ebx
    mov     dword ptr [rsp+64+rcx*4], eax   ; s_key[3-i]
    inc     ebx
    cmp     ebx, 4
    jb      tsk_skey

    ; l_key[0..39]
    xor     ebx, ebx                        ; i = 0..38 step 2
tsk_lkey:
    imul    ecx, ebx, 001010101h
    lea     rdx, [rsp+32]                   ; me_key
    call    tf_h_fun
    mov     r12d, eax                       ; a

    lea     ecx, [ebx+1]
    imul    ecx, ecx, 001010101h
    lea     rdx, [rsp+48]                   ; mo_key
    call    tf_h_fun
    rol     eax, 8                          ; b = rotl(h_fun(b, mo_key), 8)

    lea     ecx, [r12d+eax]
    mov     dword ptr [rdi+rbx*4], ecx      ; l_key[i] = a + b
    add     ecx, eax                        ; a + 2*b
    rol     ecx, 9
    mov     dword ptr [rdi+rbx*4+4], ecx    ; l_key[i+1]

    add     ebx, 2
    cmp     ebx, 40
    jb      tsk_lkey

    ; gen_mk_tab: mk_tab[0..3 + 4*x] at [rdi + 160 + x*16]
    lea     r12, [tf_qtab]
    lea     r13, [tf_mtab]
    xor     ebx, ebx                        ; x = 0..255
tsk_mkt:
    ; q40(x)
    movzx   eax, byte ptr [r12+256+rbx]     ; q(1, x)
    xor     al,  byte ptr [rsp+64+12]       ; ^ byte(s_key[3], 0)
    movzx   eax, byte ptr [r12+256+rax]     ; q(1, .)
    xor     al,  byte ptr [rsp+64+8]        ; ^ byte(s_key[2], 0)
    movzx   eax, byte ptr [r12+rax]         ; q(0, .)
    xor     al,  byte ptr [rsp+64+4]        ; ^ byte(s_key[1], 0)
    movzx   eax, byte ptr [r12+rax]         ; q(0, .)
    xor     al,  byte ptr [rsp+64]          ; ^ byte(s_key[0], 0)
    mov     ecx, dword ptr [r13+rax*4]      ; mds(0, q40)

    ; q41(x)
    movzx   eax, byte ptr [r12+rbx]         ; q(0, x)
    xor     al,  byte ptr [rsp+64+13]       ; ^ byte(s_key[3], 1)
    movzx   eax, byte ptr [r12+256+rax]     ; q(1, .)
    xor     al,  byte ptr [rsp+64+9]        ; ^ byte(s_key[2], 1)
    movzx   eax, byte ptr [r12+256+rax]     ; q(1, .)
    xor     al,  byte ptr [rsp+64+5]        ; ^ byte(s_key[1], 1)
    movzx   eax, byte ptr [r12+rax]         ; q(0, .)
    xor     al,  byte ptr [rsp+64+1]        ; ^ byte(s_key[0], 1)
    mov     edx, dword ptr [r13+1024+rax*4] ; mds(1, q41)

    ; q42(x)
    movzx   eax, byte ptr [r12+rbx]         ; q(0, x)
    xor     al,  byte ptr [rsp+64+14]       ; ^ byte(s_key[3], 2)
    movzx   eax, byte ptr [r12+rax]         ; q(0, .)
    xor     al,  byte ptr [rsp+64+10]       ; ^ byte(s_key[2], 2)
    movzx   eax, byte ptr [r12+rax]         ; q(0, .)
    xor     al,  byte ptr [rsp+64+6]        ; ^ byte(s_key[1], 2)
    movzx   eax, byte ptr [r12+256+rax]     ; q(1, .)
    xor     al,  byte ptr [rsp+64+2]        ; ^ byte(s_key[0], 2)
    mov     r8d, dword ptr [r13+2048+rax*4] ; mds(2, q42)

    ; q43(x)
    movzx   eax, byte ptr [r12+256+rbx]     ; q(1, x)
    xor     al,  byte ptr [rsp+64+15]       ; ^ byte(s_key[3], 3)
    movzx   eax, byte ptr [r12+rax]         ; q(0, .)
    xor     al,  byte ptr [rsp+64+11]       ; ^ byte(s_key[2], 3)
    movzx   eax, byte ptr [r12+256+rax]     ; q(1, .)
    xor     al,  byte ptr [rsp+64+7]        ; ^ byte(s_key[1], 3)
    movzx   eax, byte ptr [r12+256+rax]     ; q(1, .)
    xor     al,  byte ptr [rsp+64+3]        ; ^ byte(s_key[0], 3)
    mov     r9d, dword ptr [r13+3072+rax*4] ; mds(3, q43)

    mov     eax, ebx
    shl     eax, 4
    mov     dword ptr [rdi+160+rax],    ecx
    mov     dword ptr [rdi+160+rax+4],  edx
    mov     dword ptr [rdi+160+rax+8],  r8d
    mov     dword ptr [rdi+160+rax+12], r9d

    inc     ebx
    cmp     ebx, 256
    jb      tsk_mkt

    ; Wipe me_key, mo_key, s_key on stack
    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm0
    movdqu  xmmword ptr [rsp+64], xmm0

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     rbx, qword ptr [rbp-32]
    mov     rsi, qword ptr [rbp-40]
    mov     rdi, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
twofish_set_key endp

; Compute g0(src32) -> out0, g1(src32_1) -> out1 using mk_tab at [rbx+160]
; Clobbers eax, ecx, edx.
TF_G0 macro src32, dst32
    mov     ecx, src32
    movzx   eax, cl
    shl     eax, 4
    mov     dst32, dword ptr [rbx+160+rax]
    shr     ecx, 8
    movzx   eax, cl
    shl     eax, 4
    xor     dst32, dword ptr [rbx+164+rax]
    shr     ecx, 8
    movzx   eax, cl
    shl     eax, 4
    xor     dst32, dword ptr [rbx+168+rax]
    shr     ecx, 8
    shl     ecx, 4
    xor     dst32, dword ptr [rbx+172+rcx]
endm

TF_G1 macro src32, dst32
    mov     ecx, src32
    movzx   eax, cl
    shl     eax, 4
    mov     dst32, dword ptr [rbx+164+rax]
    shr     ecx, 8
    movzx   eax, cl
    shl     eax, 4
    xor     dst32, dword ptr [rbx+168+rax]
    shr     ecx, 8
    movzx   eax, cl
    shl     eax, 4
    xor     dst32, dword ptr [rbx+172+rax]
    shr     ecx, 8
    shl     ecx, 4
    xor     dst32, dword ptr [rbx+160+rcx]
endm

; =============================================================================
; twofish_enc_block(rcx = ks4256, rdx = blk16)
; =============================================================================
LANDING_PAD
public twofish_enc_block
twofish_enc_block proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12

    mov     rbx, rcx                        ; ks
    mov     rsi, rdx                        ; blk16
    mov     r8d,  dword ptr [rsi]
    mov     r9d,  dword ptr [rsi+4]
    mov     r10d, dword ptr [rsi+8]
    mov     r11d, dword ptr [rsi+12]
    xor     r8d,  dword ptr [rbx]
    xor     r9d,  dword ptr [rbx+4]
    xor     r10d, dword ptr [rbx+8]
    xor     r11d, dword ptr [rbx+12]

    mov     edi, 32                         ; byte offset into l_key (8*4 .. 39*4)
teb_loop:
    TF_G0   r8d,  r12d                      ; t0
    TF_G1   r9d,  edx                       ; t1
    lea     eax,  [r12d + edx]
    add     eax,  dword ptr [rbx+rdi]       ; + l_key[4*i + 8]
    xor     r10d, eax
    ror     r10d, 1

    rol     r11d, 1
    lea     eax,  [r12d + edx*2]
    add     eax,  dword ptr [rbx+rdi+4]     ; + l_key[4*i + 9]
    xor     r11d, eax

    TF_G0   r10d, r12d                      ; t0
    TF_G1   r11d, edx                       ; t1
    lea     eax,  [r12d + edx]
    add     eax,  dword ptr [rbx+rdi+8]     ; + l_key[4*i + 10]
    xor     r8d,  eax
    ror     r8d,  1

    rol     r9d,  1
    lea     eax,  [r12d + edx*2]
    add     eax,  dword ptr [rbx+rdi+12]    ; + l_key[4*i + 11]
    xor     r9d,  eax

    add     edi, 16
    cmp     edi, 160
    jb      teb_loop

    xor     r10d, dword ptr [rbx+16]
    xor     r11d, dword ptr [rbx+20]
    xor     r8d,  dword ptr [rbx+24]
    xor     r9d,  dword ptr [rbx+28]
    mov     dword ptr [rsi],    r10d
    mov     dword ptr [rsi+4],  r11d
    mov     dword ptr [rsi+8],  r8d
    mov     dword ptr [rsi+12], r9d

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    mov     r12, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
twofish_enc_block endp

; =============================================================================
; twofish_dec_block(rcx = ks4256, rdx = blk16)
; =============================================================================
LANDING_PAD
public twofish_dec_block
twofish_dec_block proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12

    mov     rbx, rcx                        ; ks
    mov     rsi, rdx                        ; blk16
    mov     r8d,  dword ptr [rsi]
    mov     r9d,  dword ptr [rsi+4]
    mov     r10d, dword ptr [rsi+8]
    mov     r11d, dword ptr [rsi+12]
    xor     r8d,  dword ptr [rbx+16]
    xor     r9d,  dword ptr [rbx+20]
    xor     r10d, dword ptr [rbx+24]
    xor     r11d, dword ptr [rbx+28]

    mov     edi, 144                        ; byte offset (4*7 + 8)*4 = 144 down to 32
tdb_loop:
    TF_G0   r8d,  r12d                      ; t0
    TF_G1   r9d,  edx                       ; t1
    rol     r10d, 1
    lea     eax,  [r12d + edx]
    add     eax,  dword ptr [rbx+rdi+8]     ; + l_key[4*i + 10]
    xor     r10d, eax

    lea     eax,  [r12d + edx*2]
    add     eax,  dword ptr [rbx+rdi+12]    ; + l_key[4*i + 11]
    xor     r11d, eax
    ror     r11d, 1

    TF_G0   r10d, r12d                      ; t0
    TF_G1   r11d, edx                       ; t1
    rol     r8d,  1
    lea     eax,  [r12d + edx]
    add     eax,  dword ptr [rbx+rdi]       ; + l_key[4*i + 8]
    xor     r8d,  eax

    lea     eax,  [r12d + edx*2]
    add     eax,  dword ptr [rbx+rdi+4]     ; + l_key[4*i + 9]
    xor     r9d,  eax
    ror     r9d,  1

    sub     edi, 16
    cmp     edi, 32
    jae     tdb_loop

    xor     r10d, dword ptr [rbx]
    xor     r11d, dword ptr [rbx+4]
    xor     r8d,  dword ptr [rbx+8]
    xor     r9d,  dword ptr [rbx+12]
    mov     dword ptr [rsi],    r10d
    mov     dword ptr [rsi+4],  r11d
    mov     dword ptr [rsi+8],  r8d
    mov     dword ptr [rsi+12], r9d

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    mov     r12, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
twofish_dec_block endp

end
