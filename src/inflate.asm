; =============================================================================
; inflate.asm - raw DEFLATE (RFC 1951) decompressor.
; -----------------------------------------------------------------------------
; A direct port of the structure of Mark Adler's puff.c (public domain): a
; simple, auditable per-bit canonical-Huffman decoder with a 32 KiB LZ77 window
; realised directly in the caller's output buffer.  Used to inflate ZIP entries
; (compression method 8) after WinZip-AES decryption.  Decompression only ever
; runs on data that already passed HMAC authentication.
;
;   inflate(rcx=src, rdx=srclen, r8=dst, r9=dstcap, [rbp+48]=*outlen) -> eax
;       eax = 0 success (and *outlen = bytes produced); nonzero = failure.
;
; State is global (single-threaded worker).  No dynamic allocation.
; =============================================================================

include macros.inc

.const
lens_tab  dw 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
lext_tab  dw 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
dists_tab dw 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769
          dw 1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
dext_tab  dw 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
clc_order db 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15

.data?
inf_in      dq ?
inf_inlen   dq ?
inf_incnt   dq ?
inf_out     dq ?
inf_outlen  dq ?
inf_outcnt  dq ?
inf_bitbuf  dd ?
inf_bitcnt  dd ?
inf_err     dd ?
lc_count    dw 16  dup (?)
lc_symbol   dw 288 dup (?)
dc_count    dw 16  dup (?)
dc_symbol   dw 32  dup (?)
inf_lengths db 320 dup (?)

.code

; =============================================================================
; inf_bits(rcx = need) -> eax  (raw leaf; clobbers rax,rcx,rdx,r8,r9,r10,r11)
; LSB-first bit reader.  On input underflow sets inf_err=2 and returns 0.
; =============================================================================
inf_bits proc
    mov     r8d, ecx                         ; need
    mov     eax, dword ptr [inf_bitbuf]      ; val
ib_fill:
    mov     r9d, dword ptr [inf_bitcnt]
    cmp     r9d, r8d
    jae     ib_have
    mov     r11, qword ptr [inf_incnt]
    cmp     r11, qword ptr [inf_inlen]
    jae     ib_under
    mov     r10, qword ptr [inf_in]
    movzx   edx, byte ptr [r10+r11]
    mov     ecx, r9d                         ; cl = bitcnt
    shl     edx, cl
    or      eax, edx
    inc     r11
    mov     qword ptr [inf_incnt], r11
    add     r9d, 8
    mov     dword ptr [inf_bitcnt], r9d
    jmp     ib_fill
ib_have:
    mov     r9d, dword ptr [inf_bitcnt]
    sub     r9d, r8d
    mov     dword ptr [inf_bitcnt], r9d
    mov     ecx, r8d                         ; cl = need
    mov     edx, eax
    shr     edx, cl
    mov     dword ptr [inf_bitbuf], edx
    mov     r9d, 1
    shl     r9d, cl
    dec     r9d                              ; mask = (1<<need)-1
    and     eax, r9d
    ret
ib_under:
    mov     dword ptr [inf_err], 2
    xor     eax, eax
    ret
inf_bits endp

; =============================================================================
; inf_decode(rcx = count base, rdx = symbol base) -> eax symbol (or negative)
; Per-bit canonical Huffman decode.  Raw; keeps loop state on its own stack.
; =============================================================================
inf_decode proc
    sub     rsp, 72
    mov     qword ptr [rsp+32], rcx          ; count base
    mov     qword ptr [rsp+40], rdx          ; symbol base
    mov     dword ptr [rsp+48], 1            ; len
    mov     dword ptr [rsp+52], 0            ; code
    mov     dword ptr [rsp+56], 0            ; first
    mov     dword ptr [rsp+60], 0            ; index
id_loop:
    mov     ecx, 1
    call    inf_bits
    cmp     dword ptr [inf_err], 0
    jne     id_err
    mov     edx, dword ptr [rsp+52]          ; code
    or      edx, eax                         ; code |= bit
    mov     rcx, qword ptr [rsp+32]
    mov     r8d, dword ptr [rsp+48]          ; len
    movzx   r9d, word ptr [rcx+r8*2]         ; count[len]
    mov     r10d, edx
    sub     r10d, r9d                         ; code - count
    cmp     r10d, dword ptr [rsp+56]
    jl      id_found                          ; (code-count) < first
    mov     r11d, dword ptr [rsp+60]
    add     r11d, r9d
    mov     dword ptr [rsp+60], r11d          ; index += count
    mov     r10d, dword ptr [rsp+56]
    add     r10d, r9d
    shl     r10d, 1
    mov     dword ptr [rsp+56], r10d          ; first = (first+count)<<1
    shl     edx, 1
    mov     dword ptr [rsp+52], edx           ; code <<= 1
    inc     dword ptr [rsp+48]                ; len++
    cmp     dword ptr [rsp+48], 15
    jbe     id_loop
    mov     eax, -10
    add     rsp, 72
    ret
id_found:
    mov     rcx, qword ptr [rsp+40]           ; symbol base
    mov     r10d, edx
    sub     r10d, dword ptr [rsp+56]          ; code - first
    add     r10d, dword ptr [rsp+60]          ; + index
    movzx   eax, word ptr [rcx+r10*2]
    add     rsp, 72
    ret
id_err:
    mov     eax, -1
    add     rsp, 72
    ret
inf_decode endp

; =============================================================================
; inf_construct(rcx=count, rdx=symbol, r8=lengths, r9=n) -> eax
;   0 = complete code; <0 = over-subscribed (error); >0 = incomplete (left)
; =============================================================================
inf_construct proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=count [rbp-32]=symbol [rbp-40]=lengths [rbp-48]=n [rbp-56]=left
    ; offs[16] at [rbp-96]
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    ; zero count[0..15]
    xor     r10, r10
ic_zc:
    mov     word ptr [rcx+r10*2], 0
    inc     r10
    cmp     r10, 16
    jb      ic_zc
    ; count occurrences of each length
    xor     r10, r10
ic_cc:
    cmp     r10, qword ptr [rbp-48]
    jae     ic_ccd
    mov     r11, qword ptr [rbp-40]
    movzx   eax, byte ptr [r11+r10]
    mov     r11, qword ptr [rbp-24]
    inc     word ptr [r11+rax*2]
    inc     r10
    jmp     ic_cc
ic_ccd:
    ; all-zero?  count[0]==n -> complete (no codes)
    mov     r11, qword ptr [rbp-24]
    movzx   eax, word ptr [r11]
    cmp     rax, qword ptr [rbp-48]
    jne     ic_chk
    xor     eax, eax
    FRAME_EPILOG
    ret
ic_chk:
    mov     r9d, 1                            ; left
    mov     r8d, 1                            ; len
ic_left:
    shl     r9d, 1
    mov     r11, qword ptr [rbp-24]
    movzx   eax, word ptr [r11+r8*2]
    sub     r9d, eax
    js      ic_over
    inc     r8d
    cmp     r8d, 15
    jbe     ic_left
    mov     dword ptr [rbp-56], r9d           ; left (>=0)
    ; offs[1]=0; offs[len+1]=offs[len]+count[len]
    lea     r10, [rbp-96]
    mov     word ptr [r10+2], 0
    mov     r8d, 1
ic_offs:
    cmp     r8d, 15
    jae     ic_place
    mov     r11, qword ptr [rbp-24]
    movzx   eax, word ptr [r11+r8*2]
    movzx   edx, word ptr [r10+r8*2]
    add     eax, edx
    mov     word ptr [r10+r8*2+2], ax
    inc     r8d
    jmp     ic_offs
ic_place:
    xor     r10, r10
ic_pl:
    cmp     r10, qword ptr [rbp-48]
    jae     ic_pld
    mov     r11, qword ptr [rbp-40]
    movzx   eax, byte ptr [r11+r10]           ; len
    test    eax, eax
    jz      ic_pln
    lea     r11, [rbp-96]
    movzx   edx, word ptr [r11+rax*2]          ; offs[len]
    mov     r9, qword ptr [rbp-32]
    mov     word ptr [r9+rdx*2], r10w          ; symbol[offs[len]] = symbol
    inc     word ptr [r11+rax*2]
ic_pln:
    inc     r10
    jmp     ic_pl
ic_pld:
    mov     eax, dword ptr [rbp-56]            ; return left
    FRAME_EPILOG
    ret
ic_over:
    mov     eax, r9d                           ; negative
    FRAME_EPILOG
    ret
inf_construct endp

; =============================================================================
; inf_codes - decode the body of one block using lc_/dc_ tables.
; =============================================================================
inf_codes proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=lensym [rbp-32]=len [rbp-40]=dist
ico_loop:
    lea     rcx, [lc_count]
    lea     rdx, [lc_symbol]
    call    inf_decode
    cmp     eax, 0
    jl      ico_err
    cmp     eax, 256
    je      ico_done
    jl      ico_lit
    ; length symbol
    sub     eax, 257
    cmp     eax, 29
    jae     ico_err
    cdqe
    lea     r10, [lens_tab]
    movzx   r8d, word ptr [r10+rax*2]
    mov     dword ptr [rbp-32], r8d
    lea     r10, [lext_tab]
    movzx   ecx, word ptr [r10+rax*2]
    call    inf_bits
    add     eax, dword ptr [rbp-32]
    mov     dword ptr [rbp-32], eax            ; len
    ; distance symbol
    lea     rcx, [dc_count]
    lea     rdx, [dc_symbol]
    call    inf_decode
    cmp     eax, 0
    jl      ico_err
    cmp     eax, 30
    jae     ico_err
    cdqe
    lea     r10, [dists_tab]
    movzx   r8d, word ptr [r10+rax*2]
    mov     dword ptr [rbp-40], r8d
    lea     r10, [dext_tab]
    movzx   ecx, word ptr [r10+rax*2]
    call    inf_bits
    add     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-40], eax            ; dist
    ; dist must not exceed bytes produced
    mov     edx, dword ptr [rbp-40]
    cmp     rdx, qword ptr [inf_outcnt]
    ja      ico_err
    mov     r8d, dword ptr [rbp-32]            ; len counter
    mov     r9, qword ptr [inf_out]
ico_copy:
    mov     rax, qword ptr [inf_outcnt]
    cmp     rax, qword ptr [inf_outlen]
    jae     ico_full
    mov     edx, dword ptr [rbp-40]            ; dist
    mov     r10, rax
    sub     r10, rdx                           ; outcnt - dist
    mov     dl, byte ptr [r9+r10]
    mov     byte ptr [r9+rax], dl
    inc     rax
    mov     qword ptr [inf_outcnt], rax
    dec     r8d
    jnz     ico_copy
    jmp     ico_loop
ico_lit:
    mov     r10, qword ptr [inf_outcnt]
    cmp     r10, qword ptr [inf_outlen]
    jae     ico_full
    mov     r9, qword ptr [inf_out]
    mov     byte ptr [r9+r10], al
    inc     r10
    mov     qword ptr [inf_outcnt], r10
    jmp     ico_loop
ico_done:
    xor     eax, eax
    FRAME_EPILOG
    ret
ico_full:
    mov     eax, 1
    FRAME_EPILOG
    ret
ico_err:
    mov     eax, -1
    FRAME_EPILOG
    ret
inf_codes endp

; =============================================================================
; inf_stored - copy a stored (BTYPE=00) block.
; =============================================================================
inf_stored proc frame
    FRAME_PROLOG 48
    ; [rbp-24]=len
    mov     dword ptr [inf_bitbuf], 0          ; discard to byte boundary
    mov     dword ptr [inf_bitcnt], 0
    mov     rax, qword ptr [inf_incnt]
    add     rax, 4
    cmp     rax, qword ptr [inf_inlen]
    ja      ist_err2
    mov     r8, qword ptr [inf_in]
    mov     r9, qword ptr [inf_incnt]
    movzx   eax, byte ptr [r8+r9]
    movzx   edx, byte ptr [r8+r9+1]
    shl     edx, 8
    or      eax, edx                           ; len
    movzx   edx, byte ptr [r8+r9+2]
    movzx   ecx, byte ptr [r8+r9+3]
    shl     ecx, 8
    or      edx, ecx                           ; nlen
    mov     r10d, eax
    not     r10d
    and     r10d, 0FFFFh
    cmp     r10d, edx
    jne     ist_errc
    add     r9, 4
    mov     qword ptr [inf_incnt], r9
    mov     qword ptr [rbp-24], rax            ; len
    mov     r10, r9
    add     r10, rax
    cmp     r10, qword ptr [inf_inlen]
    ja      ist_err2
    mov     r11, qword ptr [rbp-24]
    test    r11, r11
    jz      ist_done
ist_cpy:
    mov     rax, qword ptr [inf_outcnt]
    cmp     rax, qword ptr [inf_outlen]
    jae     ist_full
    mov     r8, qword ptr [inf_in]
    mov     r9, qword ptr [inf_incnt]
    mov     dl, byte ptr [r8+r9]
    mov     r8, qword ptr [inf_out]
    mov     byte ptr [r8+rax], dl
    inc     rax
    mov     qword ptr [inf_outcnt], rax
    inc     qword ptr [inf_incnt]
    dec     r11
    jnz     ist_cpy
ist_done:
    xor     eax, eax
    FRAME_EPILOG
    ret
ist_err2:
    mov     eax, 2
    FRAME_EPILOG
    ret
ist_errc:
    mov     eax, -2
    FRAME_EPILOG
    ret
ist_full:
    mov     eax, 1
    FRAME_EPILOG
    ret
inf_stored endp

; =============================================================================
; inf_fixed - build fixed Huffman tables and decode the block.
; =============================================================================
inf_fixed proc frame
    FRAME_PROLOG 48
    lea     r8, [inf_lengths]
    xor     r9, r9
ifx1:
    mov     byte ptr [r8+r9], 8
    inc     r9
    cmp     r9, 144
    jb      ifx1
ifx2:
    mov     byte ptr [r8+r9], 9
    inc     r9
    cmp     r9, 256
    jb      ifx2
ifx3:
    mov     byte ptr [r8+r9], 7
    inc     r9
    cmp     r9, 280
    jb      ifx3
ifx4:
    mov     byte ptr [r8+r9], 8
    inc     r9
    cmp     r9, 288
    jb      ifx4
    lea     rcx, [lc_count]
    lea     rdx, [lc_symbol]
    lea     r8, [inf_lengths]
    mov     r9, 288
    call    inf_construct
    lea     r8, [inf_lengths]
    xor     r9, r9
ifx5:
    mov     byte ptr [r8+r9], 5
    inc     r9
    cmp     r9, 30
    jb      ifx5
    lea     rcx, [dc_count]
    lea     rdx, [dc_symbol]
    lea     r8, [inf_lengths]
    mov     r9, 30
    call    inf_construct
    call    inf_codes
    FRAME_EPILOG
    ret
inf_fixed endp

; =============================================================================
; inf_dynamic - read dynamic Huffman headers, build tables, decode the block.
; =============================================================================
inf_dynamic proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=nlen [rbp-32]=ndist [rbp-40]=ncode [rbp-48]=index
    ; [rbp-56]=count [rbp-64]=replen
    mov     ecx, 5                            ; HLIT  (5 bits)
    call    inf_bits
    add     eax, 257
    mov     dword ptr [rbp-24], eax
    mov     ecx, 5                            ; HDIST (5 bits)
    call    inf_bits
    add     eax, 1
    mov     dword ptr [rbp-32], eax
    mov     ecx, 4                            ; HCLEN (4 bits)
    call    inf_bits
    add     eax, 4
    mov     dword ptr [rbp-40], eax
    cmp     dword ptr [rbp-24], 286
    ja      idy_err
    cmp     dword ptr [rbp-32], 30
    ja      idy_err
    ; zero lengths[0..18]
    lea     r8, [inf_lengths]
    xor     r9, r9
idy_z:
    mov     byte ptr [r8+r9], 0
    inc     r9
    cmp     r9, 19
    jb      idy_z
    ; read code-length code lengths in clc_order
    xor     r10, r10
idy_cl:
    cmp     r10d, dword ptr [rbp-40]
    jae     idy_clbuild
    mov     qword ptr [rbp-48], r10
    mov     ecx, 3
    call    inf_bits
    mov     r10, qword ptr [rbp-48]
    lea     r11, [clc_order]
    movzx   edx, byte ptr [r11+r10]
    lea     r11, [inf_lengths]
    mov     byte ptr [r11+rdx], al
    inc     r10
    jmp     idy_cl
idy_clbuild:
    lea     rcx, [lc_count]
    lea     rdx, [lc_symbol]
    lea     r8, [inf_lengths]
    mov     r9, 19
    call    inf_construct
    test    eax, eax
    jnz     idy_err                            ; code-length code must be complete
    mov     dword ptr [rbp-48], 0              ; index = 0
idy_read:
    mov     eax, dword ptr [rbp-24]
    add     eax, dword ptr [rbp-32]
    cmp     dword ptr [rbp-48], eax
    jae     idy_built
    lea     rcx, [lc_count]
    lea     rdx, [lc_symbol]
    call    inf_decode
    cmp     eax, 0
    jl      idy_err
    cmp     eax, 16
    jl      idy_lit
    je      idy_rep16
    cmp     eax, 17
    je      idy_rep17
    ; symbol 18: repeat zero 11..138
    mov     ecx, 7
    call    inf_bits
    add     eax, 11
    mov     dword ptr [rbp-56], eax
    mov     dword ptr [rbp-64], 0
    jmp     idy_fill
idy_rep17:
    mov     ecx, 3
    call    inf_bits
    add     eax, 3
    mov     dword ptr [rbp-56], eax
    mov     dword ptr [rbp-64], 0
    jmp     idy_fill
idy_rep16:
    mov     r10d, dword ptr [rbp-48]
    test    r10d, r10d
    jz      idy_err
    lea     r11, [inf_lengths]
    movzx   eax, byte ptr [r11+r10-1]
    mov     dword ptr [rbp-64], eax            ; replen = lengths[index-1]
    mov     ecx, 2
    call    inf_bits
    add     eax, 3
    mov     dword ptr [rbp-56], eax
    jmp     idy_fill
idy_lit:
    mov     r10d, dword ptr [rbp-48]
    lea     r11, [inf_lengths]
    mov     byte ptr [r11+r10], al
    inc     dword ptr [rbp-48]
    jmp     idy_read
idy_fill:
    mov     eax, dword ptr [rbp-48]
    add     eax, dword ptr [rbp-56]
    mov     edx, dword ptr [rbp-24]
    add     edx, dword ptr [rbp-32]
    cmp     eax, edx
    ja      idy_err
idy_fl:
    cmp     dword ptr [rbp-56], 0
    je      idy_read
    mov     r10d, dword ptr [rbp-48]
    lea     r11, [inf_lengths]
    mov     eax, dword ptr [rbp-64]
    mov     byte ptr [r11+r10], al
    inc     dword ptr [rbp-48]
    dec     dword ptr [rbp-56]
    jmp     idy_fl
idy_built:
    lea     r11, [inf_lengths]
    movzx   eax, byte ptr [r11+256]
    test    eax, eax
    jz      idy_err                            ; need an end-of-block code
    lea     rcx, [lc_count]
    lea     rdx, [lc_symbol]
    lea     r8, [inf_lengths]
    mov     r9d, dword ptr [rbp-24]
    call    inf_construct
    test    eax, eax
    jz      idy_dist
    js      idy_err
    ; incomplete lit/len code: only valid if nlen == count[0]+count[1]
    lea     r11, [lc_count]
    movzx   edx, word ptr [r11]
    movzx   r8d, word ptr [r11+2]
    add     edx, r8d
    cmp     edx, dword ptr [rbp-24]
    jne     idy_err
idy_dist:
    lea     rcx, [dc_count]
    lea     rdx, [dc_symbol]
    lea     r8, [inf_lengths]
    mov     r9d, dword ptr [rbp-24]
    add     r8, r9                             ; lengths + nlen
    mov     r9d, dword ptr [rbp-32]
    call    inf_construct
    test    eax, eax
    jz      idy_codes
    js      idy_err
    lea     r11, [dc_count]
    movzx   edx, word ptr [r11]
    movzx   r8d, word ptr [r11+2]
    add     edx, r8d
    cmp     edx, dword ptr [rbp-32]
    jne     idy_err
idy_codes:
    call    inf_codes
    FRAME_EPILOG
    ret
idy_err:
    mov     eax, -3
    FRAME_EPILOG
    ret
inf_dynamic endp

; =============================================================================
; inflate(rcx=src, rdx=srclen, r8=dst, r9=dstcap, [rbp+48]=*outlen) -> eax
; =============================================================================
public inflate
inflate proc frame
    FRAME_PROLOG 48
    ; [rbp-24]=outlen ptr [rbp-32]=last
    mov     qword ptr [inf_in], rcx
    mov     qword ptr [inf_inlen], rdx
    mov     qword ptr [inf_incnt], 0
    mov     qword ptr [inf_out], r8
    mov     qword ptr [inf_outlen], r9
    mov     qword ptr [inf_outcnt], 0
    mov     dword ptr [inf_bitbuf], 0
    mov     dword ptr [inf_bitcnt], 0
    mov     dword ptr [inf_err], 0
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-24], rax
inf_blk:
    mov     ecx, 1
    call    inf_bits
    mov     dword ptr [rbp-32], eax            ; last
    mov     ecx, 2
    call    inf_bits
    cmp     dword ptr [inf_err], 0
    jne     inf_failerr
    cmp     eax, 0
    je      inf_st
    cmp     eax, 1
    je      inf_fx
    cmp     eax, 2
    je      inf_dy
    mov     eax, -1
    jmp     inf_ret
inf_st:
    call    inf_stored
    jmp     inf_chk
inf_fx:
    call    inf_fixed
    jmp     inf_chk
inf_dy:
    call    inf_dynamic
inf_chk:
    test    eax, eax
    jnz     inf_ret                            ; nonzero -> error/full, stop
    cmp     dword ptr [inf_err], 0
    jne     inf_failerr
    cmp     dword ptr [rbp-32], 0
    je      inf_blk                            ; not last -> next block
    xor     eax, eax                           ; success
inf_ret:
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [inf_outcnt]
    mov     qword ptr [r10], r11
    FRAME_EPILOG
    ret
inf_failerr:
    mov     eax, 2
    jmp     inf_ret
inflate endp

end
