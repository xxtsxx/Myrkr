; =============================================================================
; deflate.asm - raw DEFLATE (RFC 1951) ENCODER.
; -----------------------------------------------------------------------------
; Produces a standard raw-DEFLATE bitstream that any inflate (ours, zlib,
; 7-Zip, ...) decodes - so `zip` can write compressed (method 8) entries.
;
; Design: the input is processed in independent 32 KiB chunks, each emitted as
; one fixed-Huffman block (BTYPE=01) with LZ77 back-references found via a
; hash-chain matcher (matches stay within the current chunk, so no sliding
; window is needed).  The last chunk's block carries BFINAL=1.  Fixed Huffman
; (not dynamic) keeps the encoder compact; the caller (zip.asm) falls back to
; STORE for any entry this fails to shrink, so incompressible data never grows.
;
;   deflate_buf(rcx=src, rdx=srclen, r8=dst, r9=dstcap) -> rax
;       rax = compressed length, or -1 if it would exceed dstcap (incompressible)
; =============================================================================

include macros.inc

DBLOCK      equ 32768
HASHMASK    equ 7FFFh
HASHSIZE    equ 8000h
MAXCHAIN    equ 128
MINMATCH    equ 3
MAXMATCH    equ 258
NIL         equ 0FFFFh

.const
df_lens   dw 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
df_lext   dw 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
df_dists  dw 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769
          dw 1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
df_dext   dw 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13

.data?
df_ready    dd ?
df_fcode    dw 288 dup (?)         ; fixed lit/len codes (bit-reversed for LSB-first)
df_flen     db 288 dup (?)
df_dcode    dw 30 dup (?)          ; fixed distance codes (5-bit, reversed)
df_dst      dq ?
df_dstpos   dq ?
df_dstcap   dq ?
df_overflow dd ?
df_bitbuf   dd ?
df_bitcnt   dd ?
df_base     dq ?
df_clen     dq ?
align 16
df_head     dw HASHSIZE dup (?)
df_prev     dw DBLOCK dup (?)

.code

; reverse the low cl bits of eax -> eax
REVBITS macro
    local r
    push    rcx
    xor     edx, edx
r:
    shr     eax, 1
    rcl     edx, 1
    dec     ecx
    jnz     r
    mov     eax, edx
    pop     rcx
endm

; =============================================================================
; deflate_init - build the fixed-Huffman code tables (idempotent).
; =============================================================================
deflate_init proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [df_ready], 0
    jne     di_done
    xor     r9, r9                           ; sym
di_lit:
    cmp     r9, 288
    jae     di_dist
    ; determine code + length for fixed lit/len symbol r9
    cmp     r9, 144
    jae     @F
    mov     eax, 30h
    add     eax, r9d                         ; 8-bit, 0x30+sym
    mov     ecx, 8
    jmp     di_emit
@@:
    cmp     r9, 256
    jae     @F
    mov     eax, 190h
    lea     edx, [r9-144]
    add     eax, edx                         ; 9-bit, 0x190+(sym-144)
    mov     ecx, 9
    jmp     di_emit
@@:
    cmp     r9, 280
    jae     @F
    lea     eax, [r9-256]                    ; 7-bit, sym-256
    mov     ecx, 7
    jmp     di_emit
@@:
    lea     eax, [r9-280]
    add     eax, 0C0h                        ; 8-bit, 0xC0+(sym-280)
    mov     ecx, 8
di_emit:
    mov     r8d, ecx                         ; len
    REVBITS                                  ; eax = reversed code (cl bits)
    lea     r10, [df_fcode]
    mov     word ptr [r10+r9*2], ax
    lea     r10, [df_flen]
    mov     byte ptr [r10+r9], r8b
    inc     r9
    jmp     di_lit
di_dist:
    xor     r9, r9
di_dl:
    cmp     r9, 30
    jae     di_fin
    mov     eax, r9d                         ; distance code = sym, 5 bits
    mov     ecx, 5
    REVBITS
    lea     r10, [df_dcode]
    mov     word ptr [r10+r9*2], ax
    inc     r9
    jmp     di_dl
di_fin:
    mov     dword ptr [df_ready], 1
di_done:
    FRAME_EPILOG
    ret
deflate_init endp

; put_bits(rcx=value, rdx=nbits) - append bits LSB-first to the output (raw).
put_bits proc
    mov     r9d, ecx
    mov     eax, dword ptr [df_bitcnt]
    mov     ecx, eax
    shl     r9d, cl
    or      dword ptr [df_bitbuf], r9d
    add     eax, edx
pb_emit:
    cmp     eax, 8
    jb      pb_done
    mov     r11, qword ptr [df_dstpos]
    cmp     r11, qword ptr [df_dstcap]
    jae     pb_over
    mov     r8d, dword ptr [df_bitbuf]
    mov     r10, qword ptr [df_dst]
    mov     byte ptr [r10+r11], r8b
    inc     r11
    mov     qword ptr [df_dstpos], r11
    shr     dword ptr [df_bitbuf], 8
    sub     eax, 8
    jmp     pb_emit
pb_over:
    mov     dword ptr [df_overflow], 1
    mov     dword ptr [df_bitcnt], 0
    ret
pb_done:
    mov     dword ptr [df_bitcnt], eax
    ret
put_bits endp

; put_huff(rcx=symbol) - emit a fixed lit/len Huffman code.
put_huff proc
    sub     rsp, 40
    lea     r10, [df_flen]
    movzx   edx, byte ptr [r10+rcx]
    lea     r10, [df_fcode]
    movzx   ecx, word ptr [r10+rcx*2]
    call    put_bits
    add     rsp, 40
    ret
put_huff endp

; put_length(rcx=length 3..258) - emit length symbol + extra bits.
put_length proc
    sub     rsp, 40
    mov     qword ptr [rsp+8], rcx           ; save length
    ; find largest i with df_lens[i] <= length
    lea     r10, [df_lens]
    xor     r8, r8                           ; i
    xor     r9, r9                           ; best i
pl_scan:
    cmp     r8, 29
    jae     pl_have
    movzx   eax, word ptr [r10+r8*2]
    cmp     rax, rcx
    ja      pl_have
    mov     r9, r8
    inc     r8
    jmp     pl_scan
pl_have:
    ; symbol = 257 + r9 ; emit it
    lea     rcx, [r9+257]
    mov     qword ptr [rsp+16], r9
    call    put_huff
    ; extra bits = length - df_lens[i], count df_lext[i]
    mov     r9, qword ptr [rsp+16]
    lea     r10, [df_lens]
    movzx   eax, word ptr [r10+r9*2]
    mov     rcx, qword ptr [rsp+8]
    sub     rcx, rax                         ; extra value
    lea     r10, [df_lext]
    movzx   rdx, word ptr [r10+r9*2]
    test    edx, edx
    jz      pl_done
    call    put_bits
pl_done:
    add     rsp, 40
    ret
put_length endp

; put_dist(rcx=distance 1..32768) - emit distance code + extra bits.
put_dist proc
    sub     rsp, 40
    mov     qword ptr [rsp+8], rcx
    lea     r10, [df_dists]
    xor     r8, r8
    xor     r9, r9
pd_scan:
    cmp     r8, 30
    jae     pd_have
    movzx   eax, word ptr [r10+r8*2]
    cmp     rax, rcx
    ja      pd_have
    mov     r9, r8
    inc     r8
    jmp     pd_scan
pd_have:
    mov     qword ptr [rsp+16], r9
    lea     r10, [df_dcode]
    movzx   ecx, word ptr [r10+r9*2]         ; 5-bit reversed code
    mov     rdx, 5
    call    put_bits
    mov     r9, qword ptr [rsp+16]
    lea     r10, [df_dists]
    movzx   eax, word ptr [r10+r9*2]
    mov     rcx, qword ptr [rsp+8]
    sub     rcx, rax
    lea     r10, [df_dext]
    movzx   rdx, word ptr [r10+r9*2]
    test    edx, edx
    jz      pd_done
    call    put_bits
pd_done:
    add     rsp, 40
    ret
put_dist endp

; matchlen(rcx=ptrA, rdx=ptrB, r8=maxlen) -> rax
matchlen proc
    xor     rax, rax
ml_l:
    cmp     rax, r8
    jae     ml_d
    mov     r10b, byte ptr [rcx+rax]
    cmp     r10b, byte ptr [rdx+rax]
    jne     ml_d
    inc     rax
    jmp     ml_l
ml_d:
    ret
matchlen endp

; =============================================================================
; deflate_chunk - encode df_base[0..df_clen) as one fixed-Huffman block.
;   rcx = is_last (0/1)
; =============================================================================
deflate_chunk proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=p [rbp-32]=best_len [rbp-40]=best_dist
    ; reset hash heads to NIL
    lea     r10, [df_head]
    xor     r9, r9
dc_zh:
    mov     word ptr [r10+r9*2], NIL
    inc     r9
    cmp     r9, HASHSIZE
    jb      dc_zh
    ; block header: BFINAL (is_last), BTYPE=01 (fixed)
    mov     rdx, 1
    call    put_bits                         ; rcx = is_last
    mov     rcx, 1
    mov     rdx, 2
    call    put_bits
    mov     qword ptr [rbp-24], 0
dc_loop:
    cmp     dword ptr [df_overflow], 0
    jne     dc_done
    mov     rax, qword ptr [rbp-24]          ; p
    cmp     rax, qword ptr [df_clen]
    jae     dc_eob
    ; can we hash 3 bytes?
    mov     rdx, rax
    add     rdx, 3
    cmp     rdx, qword ptr [df_clen]
    ja      dc_literal
    ; h = hash(base+p)
    mov     r11, qword ptr [df_base]
    movzx   eax, byte ptr [r11+rax]
    shl     eax, 10
    mov     rcx, qword ptr [rbp-24]
    movzx   edx, byte ptr [r11+rcx+1]
    shl     edx, 5
    xor     eax, edx
    movzx   edx, byte ptr [r11+rcx+2]
    xor     eax, edx
    and     eax, HASHMASK                    ; eax = h
    ; search the chain
    mov     qword ptr [rbp-32], 0            ; best_len
    lea     r10, [df_head]
    movzx   r8d, word ptr [r10+rax*2]        ; cand
    mov     r9d, MAXCHAIN
dc_chain:
    cmp     r8d, NIL
    je      dc_chaindone
    test    r9d, r9d
    jz      dc_chaindone
    ; maxlen = min(258, clen - p)
    mov     rcx, qword ptr [df_clen]
    sub     rcx, qword ptr [rbp-24]
    cmp     rcx, MAXMATCH
    jbe     @F
    mov     rcx, MAXMATCH
@@:
    mov     r11, qword ptr [df_base]
    mov     rdx, r11
    add     rdx, qword ptr [rbp-24]          ; ptrB = base + p
    add     r11, r8                          ; ptrA = base + cand
    mov     qword ptr [rbp-48], r8           ; save cand
    mov     qword ptr [rbp-56], r9           ; save chain
    mov     rcx, r11                         ; wait: matchlen(rcx=ptrA, rdx=ptrB, r8=maxlen)
    ; recompute maxlen into r8
    mov     r8, qword ptr [df_clen]
    sub     r8, qword ptr [rbp-24]
    cmp     r8, MAXMATCH
    jbe     @F
    mov     r8, MAXMATCH
@@:
    call    matchlen                         ; rax = match length
    mov     r8, qword ptr [rbp-48]
    mov     r9, qword ptr [rbp-56]
    cmp     rax, qword ptr [rbp-32]
    jbe     dc_next
    mov     qword ptr [rbp-32], rax          ; best_len
    mov     rcx, qword ptr [rbp-24]
    sub     rcx, r8
    mov     qword ptr [rbp-40], rcx          ; best_dist = p - cand
    cmp     rax, MAXMATCH
    jae     dc_chaindone
dc_next:
    lea     r10, [df_prev]
    movzx   r8d, word ptr [r10+r8*2]         ; cand = prev[cand]
    dec     r9d
    jmp     dc_chain
dc_chaindone:
    ; insert p: prev[p] = head[h]; head[h] = p   (recompute h)
    mov     r11, qword ptr [df_base]
    mov     rcx, qword ptr [rbp-24]
    movzx   eax, byte ptr [r11+rcx]
    shl     eax, 10
    movzx   edx, byte ptr [r11+rcx+1]
    shl     edx, 5
    xor     eax, edx
    movzx   edx, byte ptr [r11+rcx+2]
    xor     eax, edx
    and     eax, HASHMASK
    lea     r10, [df_head]
    movzx   r8d, word ptr [r10+rax*2]
    lea     r11, [df_prev]
    mov     word ptr [r11+rcx*2], r8w
    mov     word ptr [r10+rax*2], cx
    ; match or literal?
    cmp     qword ptr [rbp-32], MINMATCH
    jb      dc_literal
    ; emit match
    mov     rcx, qword ptr [rbp-32]
    call    put_length
    mov     rcx, qword ptr [rbp-40]
    call    put_dist
    ; insert positions p+1 .. p+best_len-1
    mov     rax, qword ptr [rbp-24]
    inc     rax
    mov     qword ptr [rbp-64], rax          ; j
    mov     rax, qword ptr [rbp-24]
    add     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-72], rax          ; end = p + best_len
dc_ins:
    mov     rax, qword ptr [rbp-64]
    cmp     rax, qword ptr [rbp-72]
    jae     dc_insdone
    mov     rdx, rax
    add     rdx, 3
    cmp     rdx, qword ptr [df_clen]
    ja      dc_insdone
    mov     r11, qword ptr [df_base]
    movzx   eax, byte ptr [r11+rax]
    mov     rcx, qword ptr [rbp-64]
    shl     eax, 10
    movzx   edx, byte ptr [r11+rcx+1]
    shl     edx, 5
    xor     eax, edx
    movzx   edx, byte ptr [r11+rcx+2]
    xor     eax, edx
    and     eax, HASHMASK
    lea     r10, [df_head]
    movzx   r8d, word ptr [r10+rax*2]
    lea     r11, [df_prev]
    mov     word ptr [r11+rcx*2], r8w
    mov     word ptr [r10+rax*2], cx
    inc     qword ptr [rbp-64]
    jmp     dc_ins
dc_insdone:
    mov     rax, qword ptr [rbp-24]
    add     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-24], rax          ; p += best_len
    jmp     dc_loop
dc_literal:
    mov     r11, qword ptr [df_base]
    mov     rax, qword ptr [rbp-24]
    movzx   ecx, byte ptr [r11+rax]
    call    put_huff
    inc     qword ptr [rbp-24]
    jmp     dc_loop
dc_eob:
    mov     rcx, 256
    call    put_huff
dc_done:
    FRAME_EPILOG
    ret
deflate_chunk endp

; =============================================================================
; deflate_buf(rcx=src, rdx=srclen, r8=dst, r9=dstcap) -> rax (len or -1)
; =============================================================================
public deflate_buf
deflate_buf proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=src [rbp-32]=srclen [rbp-40]=off
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [df_dst], r8
    mov     qword ptr [df_dstcap], r9
    mov     qword ptr [df_dstpos], 0
    mov     dword ptr [df_overflow], 0
    mov     dword ptr [df_bitbuf], 0
    mov     dword ptr [df_bitcnt], 0
    call    deflate_init
    mov     qword ptr [rbp-40], 0
db_loop:
    cmp     dword ptr [df_overflow], 0
    jne     db_over
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [rbp-32]
    jae     db_flush
    ; chunk: base = src+off, len = min(DBLOCK, srclen-off)
    mov     r10, qword ptr [rbp-24]
    add     r10, rax
    mov     qword ptr [df_base], r10
    mov     r11, qword ptr [rbp-32]
    sub     r11, rax                         ; remaining
    cmp     r11, DBLOCK
    jbe     @F
    mov     r11, DBLOCK
@@:
    mov     qword ptr [df_clen], r11
    add     rax, r11
    mov     qword ptr [rbp-40], rax          ; off += chunklen
    ; is_last = (off >= srclen)
    xor     ecx, ecx
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [rbp-32]
    jb      @F
    mov     ecx, 1
@@:
    call    deflate_chunk
    jmp     db_loop
db_flush:
    ; flush remaining bits (pad to a byte boundary with zeros)
    cmp     dword ptr [df_bitcnt], 0
    je      db_done
    mov     rcx, 0
    mov     rdx, 8
    sub     edx, dword ptr [df_bitcnt]
    call    put_bits
db_done:
    cmp     dword ptr [df_overflow], 0
    jne     db_over
    mov     rax, qword ptr [df_dstpos]
    FRAME_EPILOG
    ret
db_over:
    mov     rax, -1
    FRAME_EPILOG
    ret
deflate_buf endp

end
