; =============================================================================
; blake2b.asm - BLAKE2b (RFC 7693), scalar 64-bit implementation
; -----------------------------------------------------------------------------
;   blake2b_init  (rcx = ctx, edx = outlen 1..64)
;   blake2b_update(rcx = ctx, rdx = data, r8 = len)
;   blake2b_final (rcx = ctx, rdx = out)
;   blake2b_hash  (rcx = data, rdx = len, r8 = out, r9 = outlen)   one-shot
;   blake2b_long  (rcx = out, edx = outlen, r8 = in, r9 = inlen)   Argon2 H'
;
; No secret-dependent branching.  Used by Argon2id (this is not a hot path:
; the Argon2 memory fill has its own compression in argon2.asm).
; =============================================================================

include macros.inc

extern secure_zero:proc

BLAKE2B_CTX struct
    h       dq 8 dup (?)
    t       dq 2 dup (?)
    buf     db 128 dup (?)
    buflen  dd ?
    outlen  dd ?
BLAKE2B_CTX ends
public BLAKE2B_CTX_SIZE
BLAKE2B_CTX_SIZE equ sizeof BLAKE2B_CTX

.const
align 16
b2b_iv  dq 06a09e667f3bcc908h, 0bb67ae8584caa73bh, 03c6ef372fe94f82bh, 0a54ff53a5f1d36f1h
        dq 0510e527fade682d1h, 09b05688c2b3e6c1fh, 01f83d9abfb41bd6bh, 05be0cd19137e2179h

.code

; ---------------------------------------------------------------------------
; BG a,b,c,d,sx,sy - one BLAKE2 G mix on v[] (base r13) with message m[] (r14)
; indices a..d into v (words), sx/sy into m.  temps rax, r10, r11.
; ---------------------------------------------------------------------------
BG macro a,b,c,d,sx,sy
    mov     rax, qword ptr [r13+a*8]
    add     rax, qword ptr [r13+b*8]
    add     rax, qword ptr [r14+sx*8]
    mov     qword ptr [r13+a*8], rax
    mov     r10, qword ptr [r13+d*8]
    xor     r10, rax
    ror     r10, 32
    mov     qword ptr [r13+d*8], r10
    mov     r11, qword ptr [r13+c*8]
    add     r11, r10
    mov     qword ptr [r13+c*8], r11
    mov     r10, qword ptr [r13+b*8]
    xor     r10, r11
    ror     r10, 24
    mov     qword ptr [r13+b*8], r10
    mov     rax, qword ptr [r13+a*8]
    add     rax, r10
    add     rax, qword ptr [r14+sy*8]
    mov     qword ptr [r13+a*8], rax
    mov     r10, qword ptr [r13+d*8]
    xor     r10, rax
    ror     r10, 16
    mov     qword ptr [r13+d*8], r10
    mov     r11, qword ptr [r13+c*8]
    add     r11, r10
    mov     qword ptr [r13+c*8], r11
    mov     r10, qword ptr [r13+b*8]
    xor     r10, r11
    ror     r10, 63
    mov     qword ptr [r13+b*8], r10
endm

; feed-forward helper: h[idx] ^= v[idx] ^ v[idx+8]   (r13=v base, rcx=ctx)
FF macro idx
    mov     rax, qword ptr [r13 + idx*8]
    xor     rax, qword ptr [r13 + (idx+8)*8]
    xor     qword ptr [rcx].BLAKE2B_CTX.h + idx*8, rax
endm

ROUND macro s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15
    BG 0,4,8,12,  s0,s1
    BG 1,5,9,13,  s2,s3
    BG 2,6,10,14, s4,s5
    BG 3,7,11,15, s6,s7
    BG 0,5,10,15, s8,s9
    BG 1,6,11,12, s10,s11
    BG 2,7,8,13,  s12,s13
    BG 3,4,9,14,  s14,s15
endm

; =============================================================================
; blake2b_init(rcx = ctx, edx = outlen)
; =============================================================================
public blake2b_init
blake2b_init proc
    ; h = IV
    movdqu  xmm0, xmmword ptr [b2b_iv+0]
    movdqu  xmmword ptr [rcx].BLAKE2B_CTX.h+0, xmm0
    movdqu  xmm0, xmmword ptr [b2b_iv+16]
    movdqu  xmmword ptr [rcx].BLAKE2B_CTX.h+16, xmm0
    movdqu  xmm0, xmmword ptr [b2b_iv+32]
    movdqu  xmmword ptr [rcx].BLAKE2B_CTX.h+32, xmm0
    movdqu  xmm0, xmmword ptr [b2b_iv+48]
    movdqu  xmmword ptr [rcx].BLAKE2B_CTX.h+48, xmm0
    ; h[0] ^= 0x01010000 | outlen   (fanout=1, depth=1, no key)
    mov     eax, edx
    and     eax, 0FFh
    or      eax, 001010000h
    mov     r11d, eax                    ; zero-extends into r11
    xor     qword ptr [rcx].BLAKE2B_CTX.h, r11
    ; t = 0, buflen = 0, outlen
    mov     qword ptr [rcx].BLAKE2B_CTX.t+0, 0
    mov     qword ptr [rcx].BLAKE2B_CTX.t+8, 0
    mov     dword ptr [rcx].BLAKE2B_CTX.buflen, 0
    mov     dword ptr [rcx].BLAKE2B_CTX.outlen, edx
    ret
blake2b_init endp

; =============================================================================
; blake2b_compress(rcx = ctx, rdx = block ptr, r8 = lastflag 0|~0)
; =============================================================================
VBUF equ 32
blake2b_compress proc frame
    FRAME_PROLOG VBUF + 128 + 32
    ; locals: [rbp-16]=r13save [rbp-24]=r14save ; v at [rsp+VBUF]
    mov     qword ptr [rbp-16], r13
    mov     qword ptr [rbp-24], r14

    lea     r13, [rsp+VBUF]              ; v base
    mov     r14, rdx                    ; m base = block

    ; v[0..7] = h[0..7]
    movdqu  xmm0, xmmword ptr [rcx].BLAKE2B_CTX.h+0
    movdqu  xmmword ptr [r13+0], xmm0
    movdqu  xmm0, xmmword ptr [rcx].BLAKE2B_CTX.h+16
    movdqu  xmmword ptr [r13+16], xmm0
    movdqu  xmm0, xmmword ptr [rcx].BLAKE2B_CTX.h+32
    movdqu  xmmword ptr [r13+32], xmm0
    movdqu  xmm0, xmmword ptr [rcx].BLAKE2B_CTX.h+48
    movdqu  xmmword ptr [r13+48], xmm0
    ; v[8..15] = IV
    movdqu  xmm0, xmmword ptr [b2b_iv+0]
    movdqu  xmmword ptr [r13+64], xmm0
    movdqu  xmm0, xmmword ptr [b2b_iv+16]
    movdqu  xmmword ptr [r13+80], xmm0
    movdqu  xmm0, xmmword ptr [b2b_iv+32]
    movdqu  xmmword ptr [r13+96], xmm0
    movdqu  xmm0, xmmword ptr [b2b_iv+48]
    movdqu  xmmword ptr [r13+112], xmm0
    ; v[12] ^= t0 ; v[13] ^= t1 ; v[14] ^= last
    mov     rax, qword ptr [rcx].BLAKE2B_CTX.t+0
    xor     qword ptr [r13+96], rax
    mov     rax, qword ptr [rcx].BLAKE2B_CTX.t+8
    xor     qword ptr [r13+104], rax
    xor     qword ptr [r13+112], r8

    ; save ctx ptr across rounds (rcx is volatile but we don't call anything)
    mov     qword ptr [rbp-32], rcx

    ROUND  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    ROUND  14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3
    ROUND  11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4
    ROUND  7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8
    ROUND  9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13
    ROUND  2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9
    ROUND  12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11
    ROUND  13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10
    ROUND  6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5
    ROUND  10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0
    ROUND  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    ROUND  14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3

    ; feed-forward: h[i] ^= v[i] ^ v[i+8]  (unrolled)
    mov     rcx, qword ptr [rbp-32]
    FF 0
    FF 1
    FF 2
    FF 3
    FF 4
    FF 5
    FF 6
    FF 7

    mov     r13, qword ptr [rbp-16]
    mov     r14, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
blake2b_compress endp

; =============================================================================
; blake2b_update(rcx = ctx, rdx = data, r8 = len)
; =============================================================================
public blake2b_update
blake2b_update proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx     ; ctx
    mov     qword ptr [rbp-32], rdx     ; data
    mov     qword ptr [rbp-40], r8      ; len
bu_loop:
    cmp     qword ptr [rbp-40], 0
    je      bu_done
    mov     rcx, qword ptr [rbp-24]
    mov     r9d, dword ptr [rcx].BLAKE2B_CTX.buflen
    cmp     r9d, 128
    jne     bu_addbyte
    ; buffer full and more data remains -> compress (t += 128), reset
    add     qword ptr [rcx].BLAKE2B_CTX.t+0, 128
    adc     qword ptr [rcx].BLAKE2B_CTX.t+8, 0
    lea     rdx, [rcx].BLAKE2B_CTX.buf
    xor     r8, r8
    call    blake2b_compress
    mov     rcx, qword ptr [rbp-24]
    mov     dword ptr [rcx].BLAKE2B_CTX.buflen, 0
    jmp     bu_loop
bu_addbyte:
    mov     rax, qword ptr [rbp-32]
    mov     r10b, byte ptr [rax]
    lea     r11, [rcx].BLAKE2B_CTX.buf
    mov     byte ptr [r11+r9], r10b
    inc     r9d
    mov     dword ptr [rcx].BLAKE2B_CTX.buflen, r9d
    inc     qword ptr [rbp-32]
    dec     qword ptr [rbp-40]
    jmp     bu_loop
bu_done:
    FRAME_EPILOG
    ret
blake2b_update endp

; =============================================================================
; blake2b_final(rcx = ctx, rdx = out)
; =============================================================================
public blake2b_final
blake2b_final proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx

    ; t += buflen
    mov     r9d, dword ptr [rcx].BLAKE2B_CTX.buflen
    mov     eax, r9d
    add     qword ptr [rcx].BLAKE2B_CTX.t+0, rax
    adc     qword ptr [rcx].BLAKE2B_CTX.t+8, 0
    ; zero-pad buf from buflen..127
    lea     r11, [rcx].BLAKE2B_CTX.buf
bf_pad:
    cmp     r9d, 128
    jae     bf_compress
    mov     byte ptr [r11+r9], 0
    inc     r9d
    jmp     bf_pad
bf_compress:
    lea     rdx, [rcx].BLAKE2B_CTX.buf
    mov     r8, -1                       ; last block flag = all ones
    call    blake2b_compress

    ; output outlen bytes of h (little-endian, native)
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8d, dword ptr [rcx].BLAKE2B_CTX.outlen
    lea     r10, [rcx].BLAKE2B_CTX.h
    xor     r9d, r9d
bf_copy:
    cmp     r9d, r8d
    jae     bf_wipe
    mov     al, byte ptr [r10+r9]
    mov     byte ptr [rdx+r9], al
    inc     r9d
    jmp     bf_copy
bf_wipe:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, BLAKE2B_CTX_SIZE
    call    secure_zero
    FRAME_EPILOG
    ret
blake2b_final endp

; =============================================================================
; blake2b_hash(rcx = data, rdx = len, r8 = out, r9 = outlen) - one-shot
; =============================================================================
public blake2b_hash
blake2b_hash proc frame
    FRAME_PROLOG 96 + BLAKE2B_CTX_SIZE
    mov     qword ptr [rbp-24], rcx     ; data
    mov     qword ptr [rbp-32], rdx     ; len
    mov     qword ptr [rbp-40], r8      ; out
    mov     qword ptr [rbp-48], r9      ; outlen
    lea     rcx, [rsp+32]               ; ctx
    mov     qword ptr [rbp-56], rcx
    mov     edx, r9d
    call    blake2b_init
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-24]
    mov     r8,  qword ptr [rbp-32]
    call    blake2b_update
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-40]
    call    blake2b_final
    FRAME_EPILOG
    ret
blake2b_hash endp

; =============================================================================
; blake2b_long(rcx = out, edx = outlen, r8 = in, r9 = inlen)
; Argon2's H' variable-length hash (RFC 9106 section 3.2).
;   outlen <= 64 : H( LE32(outlen) || in )  truncated to outlen
;   outlen  > 64 : V0 = H64( LE32(outlen) || in ); out[0..31] = V0[0..31];
;                  Vi = H64(Vi-1); emit 32 bytes each until <=64 left;
;                  final = H(remaining bytes)(Vlast)
; =============================================================================
public blake2b_long
blake2b_long proc frame
    FRAME_PROLOG 160 + BLAKE2B_CTX_SIZE + 64
    ; locals:
    ;  [rbp-24] out  [rbp-32] outlen  [rbp-40] in  [rbp-48] inlen
    ;  [rbp-56] ctx ptr  [rbp-64] pos  [rbp-72] remaining
    ;  ctx at [rsp+32], Vbuf (64) at [rsp+32+CTX]
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    lea     rax, [rsp+32]
    mov     qword ptr [rbp-56], rax
    lea     rax, [rsp+32+BLAKE2B_CTX_SIZE]
    mov     qword ptr [rbp-80], rax      ; Vbuf

    ; store LE32(outlen) into the high 4 bytes of a scratch (use [rbp-88])
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [rbp-88], eax      ; little-endian 4-byte length prefix

    cmp     dword ptr [rbp-32], 64
    ja      bl_long

    ; ---- short path: H(outlen)( LE32(outlen) || in ) -----------------------
    mov     rcx, qword ptr [rbp-56]
    mov     edx, dword ptr [rbp-32]
    call    blake2b_init
    mov     rcx, qword ptr [rbp-56]
    lea     rdx, [rbp-88]
    mov     r8, 4
    call    blake2b_update
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-40]
    mov     r8,  qword ptr [rbp-48]
    call    blake2b_update
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-24]
    call    blake2b_final
    jmp     bl_done

bl_long:
    ; ---- V0 = H64( LE32(outlen) || in ) ------------------------------------
    mov     rcx, qword ptr [rbp-56]
    mov     edx, 64
    call    blake2b_init
    mov     rcx, qword ptr [rbp-56]
    lea     rdx, [rbp-88]
    mov     r8, 4
    call    blake2b_update
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-40]
    mov     r8,  qword ptr [rbp-48]
    call    blake2b_update
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-80]      ; -> Vbuf
    call    blake2b_final

    ; out[0..31] = V[0..31]
    mov     r10, qword ptr [rbp-80]      ; V
    mov     r11, qword ptr [rbp-24]      ; out
    movdqu  xmm0, xmmword ptr [r10]
    movdqu  xmmword ptr [r11], xmm0
    movdqu  xmm0, xmmword ptr [r10+16]
    movdqu  xmmword ptr [r11+16], xmm0
    mov     qword ptr [rbp-64], 32       ; pos
    mov     rax, qword ptr [rbp-32]
    sub     rax, 32
    mov     qword ptr [rbp-72], rax      ; remaining

bl_loop:
    cmp     qword ptr [rbp-72], 64
    jbe     bl_tail
    ; V = H64(V)
    mov     rcx, qword ptr [rbp-80]
    mov     rdx, 64
    mov     r8,  qword ptr [rbp-80]
    mov     r9,  64
    call    blake2b_hash
    ; out[pos..pos+31] = V[0..31]
    mov     r10, qword ptr [rbp-80]
    mov     r11, qword ptr [rbp-24]
    add     r11, qword ptr [rbp-64]
    movdqu  xmm0, xmmword ptr [r10]
    movdqu  xmmword ptr [r11], xmm0
    movdqu  xmm0, xmmword ptr [r10+16]
    movdqu  xmmword ptr [r11+16], xmm0
    add     qword ptr [rbp-64], 32
    sub     qword ptr [rbp-72], 32
    jmp     bl_loop

bl_tail:
    ; final = H(remaining)(V)  -> out[pos..]
    mov     rcx, qword ptr [rbp-80]      ; in = V
    mov     rdx, 64
    mov     r8,  qword ptr [rbp-24]
    add     r8,  qword ptr [rbp-64]      ; out + pos
    mov     r9,  qword ptr [rbp-72]      ; remaining
    call    blake2b_hash

bl_done:
    FRAME_EPILOG
    ret
blake2b_long endp

end
