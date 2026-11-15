; =============================================================================
; whirlpool.asm - ISO/IEC 10118-3 Whirlpool v3.0 (512-bit hash)
; -----------------------------------------------------------------------------
;   whirlpool_init   (rcx = ctx)
;   whirlpool_update (rcx = ctx, rdx = data, r8 = len)
;   whirlpool_final  (rcx = ctx, rdx = out64)
; =============================================================================

include macros.inc

extern secure_zero:proc

WHIRLPOOL_CTX struct
    state       dq 8 dup (?)            ; chaining state (native BE64 words)
    buf         db 64 dup (?)           ; partial block
    buflen      dd ?                    ; buffered bytes (0..63)
    pad         dd ?
    total_lo    dq ?                    ; total bytes processed (low 64)
    total_hi    dq ?                    ; total bytes processed (high 64)
WHIRLPOOL_CTX ends

WP_CTX_SIZE     equ sizeof WHIRLPOOL_CTX

.const
wp_sbox label byte
    db 018h, 023h, 0C6h, 0E8h, 087h, 0B8h, 001h, 04Fh, 036h, 0A6h, 0D2h, 0F5h, 079h, 06Fh, 091h, 052h
    db 060h, 0BCh, 09Bh, 08Eh, 0A3h, 00Ch, 07Bh, 035h, 01Dh, 0E0h, 0D7h, 0C2h, 02Eh, 04Bh, 0FEh, 057h
    db 015h, 077h, 037h, 0E5h, 09Fh, 0F0h, 04Ah, 0DAh, 058h, 0C9h, 029h, 00Ah, 0B1h, 0A0h, 06Bh, 085h
    db 0BDh, 05Dh, 010h, 0F4h, 0CBh, 03Eh, 005h, 067h, 0E4h, 027h, 041h, 08Bh, 0A7h, 07Dh, 095h, 0D8h
    db 0FBh, 0EEh, 07Ch, 066h, 0DDh, 017h, 047h, 09Eh, 0CAh, 02Dh, 0BFh, 007h, 0ADh, 05Ah, 083h, 033h
    db 063h, 002h, 0AAh, 071h, 0C8h, 019h, 049h, 0D9h, 0F2h, 0E3h, 05Bh, 088h, 09Ah, 026h, 032h, 0B0h
    db 0E9h, 00Fh, 0D5h, 080h, 0BEh, 0CDh, 034h, 048h, 0FFh, 07Ah, 090h, 05Fh, 020h, 068h, 01Ah, 0AEh
    db 0B4h, 054h, 093h, 022h, 064h, 0F1h, 073h, 012h, 040h, 008h, 0C3h, 0ECh, 0DBh, 0A1h, 08Dh, 03Dh
    db 097h, 000h, 0CFh, 02Bh, 076h, 082h, 0D6h, 01Bh, 0B5h, 0AFh, 06Ah, 050h, 045h, 0F3h, 030h, 0EFh
    db 03Fh, 055h, 0A2h, 0EAh, 065h, 0BAh, 02Fh, 0C0h, 0DEh, 01Ch, 0FDh, 04Dh, 092h, 075h, 006h, 08Ah
    db 0B2h, 0E6h, 00Eh, 01Fh, 062h, 0D4h, 0A8h, 096h, 0F9h, 0C5h, 025h, 059h, 084h, 072h, 039h, 04Ch
    db 05Eh, 078h, 038h, 08Ch, 0D1h, 0A5h, 0E2h, 061h, 0B3h, 021h, 09Ch, 01Eh, 043h, 0C7h, 0FCh, 004h
    db 051h, 099h, 06Dh, 00Dh, 0FAh, 0DFh, 07Eh, 024h, 03Bh, 0ABh, 0CEh, 011h, 08Fh, 04Eh, 0B7h, 0EBh
    db 03Ch, 081h, 094h, 0F7h, 0B9h, 013h, 02Ch, 0D3h, 0E7h, 06Eh, 0C4h, 003h, 056h, 044h, 07Fh, 0A9h
    db 02Ah, 0BBh, 0C1h, 053h, 0DCh, 00Bh, 09Dh, 06Ch, 031h, 074h, 0F6h, 046h, 0ACh, 089h, 014h, 0E1h
    db 016h, 03Ah, 069h, 009h, 070h, 0B6h, 0D0h, 0EDh, 0CCh, 042h, 098h, 0A4h, 028h, 05Ch, 0F8h, 086h

.data?
align 8
wp_C        dq 2058 dup (?)             ; C[0..7][0..255] + RC[0..9]
wp_ready    dd ?

.code

; xtime in GF(2^8) modulo 0x11d: input/output in reg8 (with zeroed upper bits in reg32)
WP_XTIME macro reg32, tmp32
    mov     tmp32, reg32
    add     reg32, reg32
    shr     tmp32, 7
    imul    tmp32, 01Dh
    xor     reg32, tmp32
    and     reg32, 0FFh
endm

; =============================================================================
; whirlpool_init_tables() - builds wp_C[8*256 + 10] idempotently
; =============================================================================
whirlpool_init_tables proc
    lea     r8, [wp_sbox]
    lea     r9, [wp_C]
    xor     ecx, ecx
wpit_loop:
    movzx   eax, byte ptr [r8+rcx]          ; s
    mov     edx, eax                        ; s2 = 2*s
    WP_XTIME edx, r10d
    mov     r11d, edx                       ; s4 = 4*s
    WP_XTIME r11d, r10d

    ; Pack c0 = (s<<56)|(s<<48)|(s4<<40)|(s<<32)|(s8<<24)|(s5<<16)|(s2<<8)|s9
    mov     r10, rax
    shl     r10, 8
    or      r10, rax                        ; s, s
    shl     r10, 8
    or      r10, r11                        ; s4
    shl     r10, 8
    or      r10, rax                        ; s

    ; Compute s8 in r11d, s5 = s4 ^ s
    push    rcx
    mov     ecx, r11d
    xor     ecx, eax                        ; ecx = s5
    WP_XTIME r11d, eax                      ; r11d = s8 (clobbers eax; reload s below)
    pop     rax                             ; rax = x
    push    rax
    movzx   eax, byte ptr [r8+rax]          ; eax = s

    shl     r10, 8
    or      r10, r11                        ; s8
    shl     r10, 8
    or      r10, rcx                        ; s5
    shl     r10, 8
    or      r10, rdx                        ; s2
    xor     r11d, eax                       ; s9 = s8 ^ s
    shl     r10, 8
    or      r10, r11                        ; c0 complete in r10!
    pop     rcx                             ; rcx = x

    ; Store ror(c0, 8*k) into wp_C[k*256 + x] for k = 0..7
    mov     qword ptr [r9+rcx*8],       r10
    ror     r10, 8
    mov     qword ptr [r9+rcx*8+2048],  r10
    ror     r10, 8
    mov     qword ptr [r9+rcx*8+4096],  r10
    ror     r10, 8
    mov     qword ptr [r9+rcx*8+6144],  r10
    ror     r10, 8
    mov     qword ptr [r9+rcx*8+8192],  r10
    ror     r10, 8
    mov     qword ptr [r9+rcx*8+10240], r10
    ror     r10, 8
    mov     qword ptr [r9+rcx*8+12288], r10
    ror     r10, 8
    mov     qword ptr [r9+rcx*8+14336], r10

    inc     ecx
    cmp     ecx, 256
    jb      wpit_loop

    ; RC[0..9] at wp_C[2048..2057]
    xor     ecx, ecx
wpit_rc:
    mov     rax, qword ptr [r8+rcx*8]
    bswap   rax
    mov     qword ptr [r9+16384+rcx*8], rax
    inc     ecx
    cmp     ecx, 10
    jb      wpit_rc

    mov     dword ptr [wp_ready], 1
    ret
whirlpool_init_tables endp

; =============================================================================
; whirlpool_init(rcx = ctx)
; =============================================================================
LANDING_PAD
public whirlpool_init
whirlpool_init proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rcx

    cmp     dword ptr [wp_ready], 0
    jne     wpi_zero
    call    whirlpool_init_tables

wpi_zero:
    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rbx].WHIRLPOOL_CTX.state,    xmm0
    movdqu  xmmword ptr [rbx].WHIRLPOOL_CTX.state+16, xmm0
    movdqu  xmmword ptr [rbx].WHIRLPOOL_CTX.state+32, xmm0
    movdqu  xmmword ptr [rbx].WHIRLPOOL_CTX.state+48, xmm0
    mov     dword ptr [rbx].WHIRLPOOL_CTX.buflen, 0
    mov     dword ptr [rbx].WHIRLPOOL_CTX.pad, 0
    mov     qword ptr [rbx].WHIRLPOOL_CTX.total_lo, 0
    mov     qword ptr [rbx].WHIRLPOOL_CTX.total_hi, 0

    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
whirlpool_init endp

; =============================================================================
; whirlpool_compress(rcx = state_ptr, rdx = raw_block64)
; =============================================================================
whirlpool_compress proc frame
    FRAME_PROLOG 368
    ; [rbp-16..56] = r12..r14, rbx, rsi, rdi
    ; [rsp+32..95]   = blk_be[0..7]
    ; [rsp+96..159]  = K[0..7]
    ; [rsp+160..223] = S[0..7]
    ; [rsp+224..287] = L[0..7]
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], rbx
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    mov     rsi, rcx                        ; state_ptr
    lea     rdi, [wp_C]

    ; Initialize blk_be, K = digest, S = digest ^ blk_be
    xor     ecx, ecx
wpc_init:
    mov     rax, qword ptr [rdx+rcx*8]
    bswap   rax
    mov     qword ptr [rsp+32+rcx*8], rax
    mov     r8,  qword ptr [rsi+rcx*8]
    mov     qword ptr [rsp+96+rcx*8], r8
    xor     r8,  rax
    mov     qword ptr [rsp+160+rcx*8], r8
    inc     ecx
    cmp     ecx, 8
    jb      wpc_init

    xor     r12d, r12d                      ; round r = 0..9
wpc_round:
    ; Step 1: L[i] from K + RC[r] (for i == 0)
    xor     r13d, r13d                      ; i = 0..7
wpc_k_row:
    xor     rax, rax
    test    r13d, r13d
    jnz     wpc_k_cols
    mov     rax, qword ptr [rdi+16384+r12*8]
wpc_k_cols:
    xor     ecx, ecx                        ; c = 0..7
    mov     r14, rdi                        ; &wp_C[c*256]
wpc_k_col:
    mov     edx, r13d
    sub     edx, ecx
    and     edx, 7                          ; (i - c) & 7
    mov     ebx, 7
    sub     ebx, ecx                        ; byte index (7 - c) in LE qword
    lea     ebx, [ebx + edx*8]
    movzx   edx, byte ptr [rsp+96+rbx]
    xor     rax, qword ptr [r14+rdx*8]
    add     r14, 2048
    inc     ecx
    cmp     ecx, 8
    jb      wpc_k_col

    mov     qword ptr [rsp+224+r13*8], rax
    inc     r13d
    cmp     r13d, 8
    jb      wpc_k_row

    ; Step 2: K[i] = L[i]; L[i] ^= round(S)
    xor     r13d, r13d
wpc_s_row:
    mov     rax, qword ptr [rsp+224+r13*8]
    mov     qword ptr [rsp+96+r13*8], rax   ; K[i] = L[i]
    xor     ecx, ecx
    mov     r14, rdi
wpc_s_col:
    mov     edx, r13d
    sub     edx, ecx
    and     edx, 7
    mov     ebx, 7
    sub     ebx, ecx
    lea     ebx, [ebx + edx*8]
    movzx   edx, byte ptr [rsp+160+rbx]
    xor     rax, qword ptr [r14+rdx*8]
    add     r14, 2048
    inc     ecx
    cmp     ecx, 8
    jb      wpc_s_col

    mov     qword ptr [rsp+224+r13*8], rax
    inc     r13d
    cmp     r13d, 8
    jb      wpc_s_row

    ; S = L
    movdqu  xmm0, xmmword ptr [rsp+224]
    movdqu  xmm1, xmmword ptr [rsp+240]
    movdqu  xmm2, xmmword ptr [rsp+256]
    movdqu  xmm3, xmmword ptr [rsp+272]
    movdqu  xmmword ptr [rsp+160], xmm0
    movdqu  xmmword ptr [rsp+176], xmm1
    movdqu  xmmword ptr [rsp+192], xmm2
    movdqu  xmmword ptr [rsp+208], xmm3

    inc     r12d
    cmp     r12d, 10
    jb      wpc_round

    ; Miyaguchi-Preneel: digest[i] ^= L[i] ^ blk_be[i]
    xor     ecx, ecx
wpc_fin:
    mov     rax, qword ptr [rsp+224+rcx*8]
    xor     rax, qword ptr [rsp+32+rcx*8]
    xor     qword ptr [rsi+rcx*8], rax
    inc     ecx
    cmp     ecx, 8
    jb      wpc_fin

    ; Wipe stack scratch (256 bytes at [rsp+32..287])
    xor     eax, eax
    xor     ecx, ecx
wpc_wipe:
    mov     qword ptr [rsp+32+rcx*8], rax
    inc     ecx
    cmp     ecx, 32
    jb      wpc_wipe

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     rbx, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
whirlpool_compress endp

; =============================================================================
; whirlpool_update(rcx = ctx, rdx = data, r8 = len)
; =============================================================================
LANDING_PAD
public whirlpool_update
whirlpool_update proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    test    r8, r8
    jz      wpu_done

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; data
    mov     rdi, r8                         ; len

    add     qword ptr [rbx].WHIRLPOOL_CTX.total_lo, rdi
    adc     qword ptr [rbx].WHIRLPOOL_CTX.total_hi, 0

    mov     ecx, dword ptr [rbx].WHIRLPOOL_CTX.buflen
    test    ecx, ecx
    jz      wpu_blocks

    mov     eax, 64
    sub     eax, ecx
    cmp     rdi, rax
    jb      wpu_tail

    lea     r9, [rbx].WHIRLPOOL_CTX.buf
    add     r9, rcx
    mov     ecx, eax
wpu_fill:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     ecx
    jnz     wpu_fill

    sub     rdi, rax
    mov     dword ptr [rbx].WHIRLPOOL_CTX.buflen, 0
    lea     rcx, [rbx].WHIRLPOOL_CTX.state
    lea     rdx, [rbx].WHIRLPOOL_CTX.buf
    call    whirlpool_compress

wpu_blocks:
    cmp     rdi, 64
    jb      wpu_tail
    lea     rcx, [rbx].WHIRLPOOL_CTX.state
    mov     rdx, rsi
    call    whirlpool_compress
    add     rsi, 64
    sub     rdi, 64
    jmp     wpu_blocks

wpu_tail:
    test    rdi, rdi
    jz      wpu_done
    mov     ecx, dword ptr [rbx].WHIRLPOOL_CTX.buflen
    lea     r9, [rbx].WHIRLPOOL_CTX.buf
    add     r9, rcx
    add     ecx, edi
    mov     dword ptr [rbx].WHIRLPOOL_CTX.buflen, ecx
wpu_copy:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     rdi
    jnz     wpu_copy

wpu_done:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
whirlpool_update endp

; =============================================================================
; whirlpool_final(rcx = ctx, rdx = out64)
; =============================================================================
LANDING_PAD
public whirlpool_final
whirlpool_final proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; out64

    mov     rax, qword ptr [rbx].WHIRLPOOL_CTX.total_lo
    mov     rdx, qword ptr [rbx].WHIRLPOOL_CTX.total_hi
    shld    rdx, rax, 3
    shl     rax, 3
    bswap   rdx
    bswap   rax
    mov     qword ptr [rbp-40], rdx         ; hi_be
    mov     qword ptr [rbp-48], rax         ; lo_be

    mov     edi, dword ptr [rbx].WHIRLPOOL_CTX.buflen
    lea     r9, [rbx].WHIRLPOOL_CTX.buf
    mov     byte ptr [r9+rdi], 080h
    inc     edi
    cmp     edi, 32
    jbe     wpf_pad_48

wpf_pad_64:
    cmp     edi, 64
    jae     wpf_comp_extra
    mov     byte ptr [r9+rdi], 0
    inc     edi
    jmp     wpf_pad_64

wpf_comp_extra:
    lea     rcx, [rbx].WHIRLPOOL_CTX.state
    lea     rdx, [rbx].WHIRLPOOL_CTX.buf
    call    whirlpool_compress
    xor     edi, edi

wpf_pad_48:
    lea     r9, [rbx].WHIRLPOOL_CTX.buf
wpf_zloop:
    cmp     edi, 48
    jae     wpf_store_len
    mov     byte ptr [r9+rdi], 0
    inc     edi
    jmp     wpf_zloop

wpf_store_len:
    mov     rdx, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [r9+48], rdx
    mov     qword ptr [r9+56], rax
    lea     rcx, [rbx].WHIRLPOOL_CTX.state
    lea     rdx, [rbx].WHIRLPOOL_CTX.buf
    call    whirlpool_compress

    xor     ecx, ecx
wpf_out:
    mov     rax, qword ptr [rbx+rcx*8]
    bswap   rax
    mov     qword ptr [rsi+rcx*8], rax
    inc     ecx
    cmp     ecx, 8
    jb      wpf_out

    mov     qword ptr [rbp-40], 0
    mov     qword ptr [rbp-48], 0
    mov     rcx, rbx
    mov     rdx, WP_CTX_SIZE
    call    secure_zero

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
whirlpool_final endp

end
