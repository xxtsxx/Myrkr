; =============================================================================
; streebog.asm - GOST R 34.11-2012 Streebog-512 (VeraCrypt KDF compatible)
; -----------------------------------------------------------------------------
;   streebog_init   (rcx = ctx)
;   streebog_update (rcx = ctx, rdx = data, r8 = len)
;   streebog_final  (rcx = ctx, rdx = out64)
; =============================================================================

include macros.inc

extern secure_zero:proc

STREEBOG_CTX struct
    h       dq 8 dup (?)                ; 512-bit chaining state
    N       dq 8 dup (?)                ; 512-bit bit counter
    Sigma   dq 8 dup (?)                ; 512-bit message checksum
    buf     db 64 dup (?)               ; partial block
    bufsize dq ?                        ; buffered bytes (0..63)
STREEBOG_CTX ends

SBG_CTX_SIZE    equ sizeof STREEBOG_CTX

.const
sbg_Pi label byte
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

align 8
sbg_A label qword
    dq 0641C314B2B8EE083h, 0C83862965601DD1Bh, 08D70C431AC02A736h, 007E095624504536Ch
    dq 00EDD37C48A08A6D8h, 01CA76E95091051ADh, 03853DC371220A247h, 070A6A56E2440598Eh
    dq 0A48B474F9EF5DC18h, 0550B8E9E21F7A530h, 0AA16012142F35760h, 0492C024284FBAEC0h
    dq 09258048415EB419Dh, 039B008152ACB8227h, 0727D102A548B194Eh, 0E4FA2054A80B329Ch
    dq 0F97D86D98A327728h, 0EFFA11AF0964EE50h, 0C3E9224312C8C1A0h, 09BCF4486248D9F5Dh
    dq 02B838811480723BAh, 0561B0D22900E4669h, 0AC361A443D1C8CD2h, 0456C34887A3805B9h
    dq 05B068C651810A89Eh, 0B60C05CA30204D21h, 071180A8960409A42h, 0E230140FC0802984h
    dq 0D960281E9D1D5215h, 0AFC0503C273AA42Ah, 0439DA0784E745554h, 086275DF09CE8AAA8h
    dq 00321658CBA93C138h, 00642CA05693B9F70h, 00C84890AD27623E0h, 018150F14B9EC46DDh
    dq 0302A1E286FC58CA7h, 060543C50DE970553h, 0C0A878A0A1330AA6h, 09D4DF05D5F661451h
    dq 0ACCC9CA9328A8950h, 04585254F64090FA0h, 08A174A9EC8121E5Dh, 0092E94218D243CBAh
    dq 0125C354207487869h, 024B86A840E90F0D2h, 0486DD4151C3DFDB9h, 090DAB52A387AE76Fh
    dq 046B60F011A83988Eh, 08C711E02341B2D01h, 005E23C0468365A02h, 00AD97808D06CB404h
    dq 014AFF010BDD87508h, 02843FD2067ADEA10h, 05086E740CE47C920h, 0A011D380818E8F40h
    dq 083478B07B2468764h, 01B8E0B0E798C13C8h, 03601161CF205268Dh, 06C022C38F90A4C07h
    dq 0D8045870EF14980Eh, 0AD08B0E0C3282D1Ch, 047107DDD9B505A38h, 08E20FAA72BA0B470h

align 8
sbg_C label qword
    dq 0DD806559F2A64507h, 005767436CC744D23h, 0A2422A08A460D315h, 04B7CE09192676901h
    dq 0714EB88D7585C4FCh, 02F6A76432E45D016h, 0EBCB2F81C0657C1Fh, 0B1085BDA1ECADAE9h
    dq 0E679047021B19BB7h, 055DDA21BD7CBCD56h, 05CB561C2DB0AA7CAh, 09AB5176B12D69958h
    dq 061D55E0F16B50131h, 0F3FEEA720A232B98h, 04FE39D460F70B5D7h, 06FA3B58AA99D2F1Ah
    dq 0991E96F50ABA0AB2h, 0C2B6F443867ADB31h, 0C1C93A376062DB09h, 0D3E20FE490359EB1h
    dq 0F2EA7514B1297B7Bh, 006F15E5F529C1F8Bh, 00A39FC286A3D8435h, 0F574DCAC2BCE2FC7h
    dq 0220CBEBC84E3D12Eh, 03453EAA193E837F1h, 0D8B71333935203BEh, 0A9D72C82ED03D675h
    dq 09D721CAD685E353Fh, 0488E857E335C3C7Dh, 0F948E1A05D71E4DDh, 0EF1FDFB3E81566D2h
    dq 0601758FD7C6CFE57h, 07A56A27EA9EA63F5h, 0DFFF00B723271A16h, 0BFCD1747253AF5A3h
    dq 0359E35D7800FFFBDh, 07F151C1F1686104Ah, 09A3F410C6CA92363h, 04BEA6BACAD474799h
    dq 0FA68407A46647D6Eh, 0BF71C57236904F35h, 00AF21F66C2BEC6B6h, 0CFFAA6B71C9AB7B4h
    dq 0187F9AB49AF08EC6h, 02D66C4F95142A46Ch, 06FA4C33B7A3039C0h, 0AE4FAEAE1D3AD3D9h
    dq 08886564D3A14D493h, 03517454CA23C4AF3h, 006476983284A0504h, 00992ABC52D822C37h
    dq 0D3473E33197A93C9h, 0399EC6C7E6BF87C9h, 051AC86FEBF240954h, 0F4C70E16EEAAC5ECh
    dq 0A47F0DD4BF02E71Eh, 036ACC2355951A8D9h, 069D18D2BD1A5C42Fh, 0F4892BCB929B0690h
    dq 089B4443B4DDBC49Ah, 04EB7F8719C36DE1Eh, 003E7AA020C6E4141h, 09B1F5B424D93C9A7h
    dq 07261445183235ADBh, 00E38DC92CB1F2A60h, 07B2B8A9AA6079C54h, 0800A440BDBB2CEB1h
    dq 03CD955B7E00D0984h, 03A7D3A1B25894224h, 0944C9AD8EC165FDEh, 0378F5A541631229Bh
    dq 074B4C7FB98459CEDh, 03698FAD1153BB6C3h, 07A1E6C303B7652F4h, 09FE76702AF69334Bh
    dq 01FFFE18A1B336103h, 08941E71CFF8A78DBh, 0382AE548B2E4F3F3h, 0ABBEDEA680056F52h
    dq 06BCAA4CD81F32D1Bh, 0DEA2594AC06FD85Dh, 0EFBACD1D7D476E98h, 08A1D71EFEA48B9CAh
    dq 02001802114846679h, 0D8FA6BBBEBAB0761h, 03002C6CD635AFE94h, 07BCD9ED0EFC889FBh
    dq 048BC924AF11BD720h, 0FAF417D5D9B21B99h, 0E71DA4AA88E12852h, 05D80EF9D1891CC86h
    dq 0F82012D430219F9Bh, 0CDA43C32BCDF1D77h, 0D21380B00449B17Ah, 0378EE767F11631BAh

.data?
align 8
sbg_Ax      dq 2048 dup (?)             ; Ax[8][256]
sbg_ready   dd ?

.code

; =============================================================================
; streebog_init_tables()
; =============================================================================
streebog_init_tables proc
    lea     r8,  [sbg_Pi]
    lea     r9,  [sbg_A]
    lea     r10, [sbg_Ax]
    xor     ecx, ecx                        ; k = 0..7
sit_k:
    xor     edx, edx                        ; x = 0..255
sit_x:
    movzx   r11d, byte ptr [r8+rdx]         ; pval = Pi[x]
    xor     rax, rax
    test    r11d, 1
    jz      sit_b1
    xor     rax, qword ptr [r9]
sit_b1:
    test    r11d, 2
    jz      sit_b2
    xor     rax, qword ptr [r9+8]
sit_b2:
    test    r11d, 4
    jz      sit_b3
    xor     rax, qword ptr [r9+16]
sit_b3:
    test    r11d, 8
    jz      sit_b4
    xor     rax, qword ptr [r9+24]
sit_b4:
    test    r11d, 16
    jz      sit_b5
    xor     rax, qword ptr [r9+32]
sit_b5:
    test    r11d, 32
    jz      sit_b6
    xor     rax, qword ptr [r9+40]
sit_b6:
    test    r11d, 64
    jz      sit_b7
    xor     rax, qword ptr [r9+48]
sit_b7:
    test    r11d, 128
    jz      sit_store
    xor     rax, qword ptr [r9+56]
sit_store:
    mov     qword ptr [r10+rdx*8], rax
    inc     edx
    cmp     edx, 256
    jb      sit_x

    add     r9,  64                         ; next 8 basis qwords
    add     r10, 2048                       ; next Ax[k] row
    inc     ecx
    cmp     ecx, 8
    jb      sit_k

    mov     dword ptr [sbg_ready], 1
    ret
streebog_init_tables endp

; =============================================================================
; sbg_xlps(rcx = x_ptr, rdx = y_ptr, r8 = out_ptr)
; Safe when out_ptr aliases x_ptr or y_ptr.
; =============================================================================
sbg_xlps proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi

    ; Stage r[0..7] = x[0..7] ^ y[0..7] at [rsp+32..95]
    movdqu  xmm0, xmmword ptr [rcx]
    movdqu  xmm1, xmmword ptr [rcx+16]
    movdqu  xmm2, xmmword ptr [rcx+32]
    movdqu  xmm3, xmmword ptr [rcx+48]
    movdqu  xmm4, xmmword ptr [rdx]
    movdqu  xmm5, xmmword ptr [rdx+16]
    pxor    xmm0, xmm4
    pxor    xmm1, xmm5
    movdqu  xmm4, xmmword ptr [rdx+32]
    movdqu  xmm5, xmmword ptr [rdx+48]
    pxor    xmm2, xmm4
    pxor    xmm3, xmm5
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm1
    movdqu  xmmword ptr [rsp+64], xmm2
    movdqu  xmmword ptr [rsp+80], xmm3

    lea     r9, [sbg_Ax]
    xor     ecx, ecx                        ; j = 0..7
sxl_j:
    xor     rax, rax
    xor     edx, edx                        ; k = 0..7
    mov     rsi, r9
sxl_k:
    lea     ebx, [ecx + edx*8]
    movzx   ebx, byte ptr [rsp+32+rbx]
    xor     rax, qword ptr [rsi+rbx*8]
    add     rsi, 2048
    inc     edx
    cmp     edx, 8
    jb      sxl_k

    mov     qword ptr [r8+rcx*8], rax
    inc     ecx
    cmp     ecx, 8
    jb      sxl_j

    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm0
    movdqu  xmmword ptr [rsp+64], xmm0
    movdqu  xmmword ptr [rsp+80], xmm0

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
sbg_xlps endp

; =============================================================================
; sbg_g(rcx = h_ptr, rdx = N_ptr, r8 = m_ptr)
; Updates h[0..7] in-place.
; =============================================================================
sbg_g proc frame
    FRAME_PROLOG 208
    ; [rbp-16..48] = r12..r14, rbx
    ; [rsp+32..95]  = Ki[8]
    ; [rsp+96..159] = data[8]
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], rbx

    mov     r12, rcx                        ; h_ptr
    mov     r13, r8                         ; m_ptr

    ; Ki = XLPS(h, N)
    lea     r8, [rsp+32]
    call    sbg_xlps

    ; data = XLPS(Ki, m)
    lea     rcx, [rsp+32]
    mov     rdx, r13
    lea     r8,  [rsp+96]
    call    sbg_xlps

    ; 11 rounds: Ki = XLPS(Ki, C[i]); data = XLPS(Ki, data)
    lea     r14, [sbg_C]
    xor     ebx, ebx
sg_rnd:
    lea     rcx, [rsp+32]
    mov     rdx, r14
    lea     r8,  [rsp+32]
    call    sbg_xlps

    lea     rcx, [rsp+32]
    lea     rdx, [rsp+96]
    lea     r8,  [rsp+96]
    call    sbg_xlps

    add     r14, 64
    inc     ebx
    cmp     ebx, 11
    jb      sg_rnd

    ; Ki = XLPS(Ki, C[11])
    lea     rcx, [rsp+32]
    mov     rdx, r14
    lea     r8,  [rsp+32]
    call    sbg_xlps

    ; h[k] = Ki[k] ^ data[k] ^ h[k] ^ m[k]
    xor     ecx, ecx
sg_xor:
    mov     rax, qword ptr [rsp+32+rcx*8]
    xor     rax, qword ptr [rsp+96+rcx*8]
    xor     rax, qword ptr [r13+rcx*8]
    xor     qword ptr [r12+rcx*8], rax
    inc     ecx
    cmp     ecx, 8
    jb      sg_xor

    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm0
    movdqu  xmmword ptr [rsp+64], xmm0
    movdqu  xmmword ptr [rsp+80], xmm0
    movdqu  xmmword ptr [rsp+96], xmm0
    movdqu  xmmword ptr [rsp+112], xmm0
    movdqu  xmmword ptr [rsp+128], xmm0
    movdqu  xmmword ptr [rsp+144], xmm0

    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     rbx, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
sbg_g endp

; =============================================================================
; sbg_add512(rcx = dst_x, rdx = src_y)
; Exact VeraCrypt Streebog.c add512 (retaining carry-drop compatibility):
;   tmp = x[i] + y[i]; OF = (tmp < x[i]); tmp += CF; CF = OF; x[i] = tmp;
; =============================================================================
sbg_add512 proc
    xor     r8d, r8d                        ; CF = 0
    xor     r9d, r9d                        ; i = 0..7
sa5_loop:
    mov     rax, qword ptr [rcx+r9*8]
    add     rax, qword ptr [rdx+r9*8]
    setc    r10b                            ; OF = (tmp < x[i])
    movzx   r10d, r10b
    add     rax, r8                         ; tmp += CF
    mov     r8d, r10d                       ; CF = OF
    mov     qword ptr [rcx+r9*8], rax
    inc     r9d
    cmp     r9d, 8
    jb      sa5_loop
    ret
sbg_add512 endp

; =============================================================================
; sbg_stage2(rcx = ctx, rdx = block64)
; =============================================================================
sbg_stage2 proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; block64

    lea     rcx, [rbx].STREEBOG_CTX.h
    lea     rdx, [rbx].STREEBOG_CTX.N
    mov     r8,  rsi
    call    sbg_g

    ; buffer512 = { 512, 0..0 } at [rsp+32..95]
    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm0
    movdqu  xmmword ptr [rsp+64], xmm0
    movdqu  xmmword ptr [rsp+80], xmm0
    mov     qword ptr [rsp+32], 512

    lea     rcx, [rbx].STREEBOG_CTX.N
    lea     rdx, [rsp+32]
    call    sbg_add512

    lea     rcx, [rbx].STREEBOG_CTX.Sigma
    mov     rdx, rsi
    call    sbg_add512

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
sbg_stage2 endp

; =============================================================================
; streebog_init(rcx = ctx)
; =============================================================================
LANDING_PAD
public streebog_init
streebog_init proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rcx

    cmp     dword ptr [sbg_ready], 0
    jne     sbi_zero
    call    streebog_init_tables

sbi_zero:
    mov     rcx, rbx
    mov     rdx, SBG_CTX_SIZE
    call    secure_zero

    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
streebog_init endp

; =============================================================================
; streebog_update(rcx = ctx, rdx = data, r8 = len)
; =============================================================================
LANDING_PAD
public streebog_update
streebog_update proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    test    r8, r8
    jz      sbu_done

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; data
    mov     rdi, r8                         ; len

sbu_fast:
    cmp     rdi, 64
    jb      sbu_loop
    cmp     qword ptr [rbx].STREEBOG_CTX.bufsize, 0
    jne     sbu_loop
    mov     rcx, rbx
    mov     rdx, rsi
    call    sbg_stage2
    add     rsi, 64
    sub     rdi, 64
    jmp     sbu_fast

sbu_loop:
    test    rdi, rdi
    jz      sbu_done
    mov     rcx, qword ptr [rbx].STREEBOG_CTX.bufsize
    mov     rax, 64
    sub     rax, rcx                        ; chunksize = 64 - bufsize
    cmp     rax, rdi
    jbe     sbu_copy_go
    mov     rax, rdi
sbu_copy_go:
    lea     r9, [rbx].STREEBOG_CTX.buf
    add     r9, rcx
    add     rcx, rax
    mov     qword ptr [rbx].STREEBOG_CTX.bufsize, rcx
    sub     rdi, rax
sbu_copy:
    mov     r8b, byte ptr [rsi]
    mov     byte ptr [r9], r8b
    inc     rsi
    inc     r9
    dec     rax
    jnz     sbu_copy

    cmp     qword ptr [rbx].STREEBOG_CTX.bufsize, 64
    jb      sbu_loop
    mov     rcx, rbx
    lea     rdx, [rbx].STREEBOG_CTX.buf
    call    sbg_stage2
    mov     qword ptr [rbx].STREEBOG_CTX.bufsize, 0
    jmp     sbu_loop

sbu_done:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
streebog_update endp

; =============================================================================
; streebog_final(rcx = ctx, rdx = out64)
; =============================================================================
LANDING_PAD
public streebog_final
streebog_final proc frame
    FRAME_PROLOG 192
    ; [rbp-16..24] = rbx, rsi
    ; [rsp+32..95]  = len_block[8]
    ; [rsp+96..159] = zero_block[8]
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi

    mov     rbx, rcx                        ; ctx
    mov     rsi, rdx                        ; out64

    pxor    xmm0, xmm0
    movdqu  xmmword ptr [rsp+32], xmm0
    movdqu  xmmword ptr [rsp+48], xmm0
    movdqu  xmmword ptr [rsp+64], xmm0
    movdqu  xmmword ptr [rsp+80], xmm0
    movdqu  xmmword ptr [rsp+96], xmm0
    movdqu  xmmword ptr [rsp+112], xmm0
    movdqu  xmmword ptr [rsp+128], xmm0
    movdqu  xmmword ptr [rsp+144], xmm0

    mov     rax, qword ptr [rbx].STREEBOG_CTX.bufsize
    mov     rcx, rax
    shl     rcx, 3
    mov     qword ptr [rsp+32], rcx         ; len_block[0] = bufsize * 8

    ; Pad: zero buf[bufsize..63], then buf[bufsize] = 0x01
    lea     r9, [rbx].STREEBOG_CTX.buf
    mov     rcx, rax
sbf_zpad:
    cmp     rcx, 64
    jae     sbf_set01
    mov     byte ptr [r9+rcx], 0
    inc     rcx
    jmp     sbf_zpad
sbf_set01:
    mov     byte ptr [r9+rax], 001h

    lea     rcx, [rbx].STREEBOG_CTX.h
    lea     rdx, [rbx].STREEBOG_CTX.N
    lea     r8,  [rbx].STREEBOG_CTX.buf
    call    sbg_g

    lea     rcx, [rbx].STREEBOG_CTX.N
    lea     rdx, [rsp+32]
    call    sbg_add512

    lea     rcx, [rbx].STREEBOG_CTX.Sigma
    lea     rdx, [rbx].STREEBOG_CTX.buf
    call    sbg_add512

    lea     rcx, [rbx].STREEBOG_CTX.h
    lea     rdx, [rsp+96]                   ; buffer0
    lea     r8,  [rbx].STREEBOG_CTX.N
    call    sbg_g

    lea     rcx, [rbx].STREEBOG_CTX.h
    lea     rdx, [rsp+96]                   ; buffer0
    lea     r8,  [rbx].STREEBOG_CTX.Sigma
    call    sbg_g

    movdqu  xmm0, xmmword ptr [rbx].STREEBOG_CTX.h
    movdqu  xmm1, xmmword ptr [rbx].STREEBOG_CTX.h+16
    movdqu  xmm2, xmmword ptr [rbx].STREEBOG_CTX.h+32
    movdqu  xmm3, xmmword ptr [rbx].STREEBOG_CTX.h+48
    movdqu  xmmword ptr [rsi],    xmm0
    movdqu  xmmword ptr [rsi+16], xmm1
    movdqu  xmmword ptr [rsi+32], xmm2
    movdqu  xmmword ptr [rsi+48], xmm3
    pxor    xmm0, xmm0
    pxor    xmm1, xmm1
    pxor    xmm2, xmm2
    pxor    xmm3, xmm3
    mov     qword ptr [rsp+32], 0

    mov     rcx, rbx
    mov     rdx, SBG_CTX_SIZE
    call    secure_zero

    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
streebog_final endp

end
