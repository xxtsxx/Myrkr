; =============================================================================
; sha1.asm - SHA-1, HMAC-SHA1, PBKDF2-HMAC-SHA1 (software).
; -----------------------------------------------------------------------------
; Used ONLY by the encrypted-ZIP (WinZip AES) extractor for key derivation and
; entry authentication.  SHA-1 is broken for collision resistance but is fine in
; the HMAC/PBKDF2 construction WinZip AES specifies; we implement exactly that.
;
;   sha1_init(rcx=ctx)
;   sha1_update(rcx=ctx, rdx=data, r8=len)
;   sha1_final(rcx=ctx, rdx=out20)
;   hmac_sha1(rcx=key, rdx=keylen, r8=msg, r9=msglen, [rbp+48]=out20)
;   pbkdf2_hmac_sha1(rcx=pw, rdx=pwlen, r8=salt, r9=saltlen,
;                    [rbp+48]=iters, [rbp+56]=out, [rbp+64]=dklen)
;
; ctx is SHA1_CTX_SIZE bytes supplied by the caller.
; =============================================================================

include macros.inc

; SHA1_CTX_SIZE now lives in macros.inc so the ZIP paths can size their context
; buffers from the same constant this module's layout defines.

; ---------------------------------------------------------------------------
; SHA1_ROUND - one round given f in r8d and k in edx.  a..e are the locals at
; [rbp-324..rbp-340]; r11 = moving W pointer (advanced by 4).  Uses eax, ecx.
; ---------------------------------------------------------------------------
SHA1_ROUND macro
    mov     eax, dword ptr [rbp-340]        ; a
    rol     eax, 5
    add     eax, r8d                        ; + f
    add     eax, edx                        ; + k
    add     eax, dword ptr [rbp-356]        ; + e
    add     eax, dword ptr [r11]            ; + W[t]
    mov     ecx, dword ptr [rbp-352]        ; d
    mov     dword ptr [rbp-356], ecx        ; e = d
    mov     ecx, dword ptr [rbp-348]        ; c
    mov     dword ptr [rbp-352], ecx        ; d = c
    mov     ecx, dword ptr [rbp-344]        ; b
    rol     ecx, 30
    mov     dword ptr [rbp-348], ecx        ; c = rol30(b)
    mov     ecx, dword ptr [rbp-340]        ; a
    mov     dword ptr [rbp-344], ecx        ; b = a
    mov     dword ptr [rbp-340], eax        ; a = temp
    add     r11, 4
endm

.code

; =============================================================================
; sha1_block(rcx=ctx, rdx=block64) - one 64-byte compression (internal).
; =============================================================================
sha1_block proc frame
    FRAME_PROLOG 416
    ; locals (kept clear of the canary at [rbp-8]):
    ;   W=[rbp-336]  a=[rbp-340] b=[rbp-344] c=[rbp-348] d=[rbp-352]
    ;   e=[rbp-356]  ctxsv=[rbp-368]
    mov     qword ptr [rbp-368], rcx
    ; W[0..15] = big-endian dwords of block
    lea     r9, [rbp-336]
    xor     r10d, r10d
sb_load:
    mov     eax, dword ptr [rdx+r10*4]
    bswap   eax
    mov     dword ptr [r9+r10*4], eax
    inc     r10d
    cmp     r10d, 16
    jb      sb_load
    ; W[16..79]
    mov     r10d, 16
sb_exp:
    mov     eax, dword ptr [r9+r10*4-12]    ; W[t-3]
    xor     eax, dword ptr [r9+r10*4-32]    ; W[t-8]
    xor     eax, dword ptr [r9+r10*4-56]    ; W[t-14]
    xor     eax, dword ptr [r9+r10*4-64]    ; W[t-16]
    rol     eax, 1
    mov     dword ptr [r9+r10*4], eax
    inc     r10d
    cmp     r10d, 80
    jb      sb_exp
    ; a..e = h0..h4
    mov     rcx, qword ptr [rbp-368]
    mov     eax, dword ptr [rcx+0]
    mov     dword ptr [rbp-340], eax
    mov     eax, dword ptr [rcx+4]
    mov     dword ptr [rbp-344], eax
    mov     eax, dword ptr [rcx+8]
    mov     dword ptr [rbp-348], eax
    mov     eax, dword ptr [rcx+12]
    mov     dword ptr [rbp-352], eax
    mov     eax, dword ptr [rcx+16]
    mov     dword ptr [rbp-356], eax
    lea     r11, [rbp-336]                  ; wptr -> W[0]
    ; ---- rounds 0..19: f=(b&c)|(~b&d), k=5A827999 ----
    mov     r10d, 20
sb_r1:
    mov     r8d, dword ptr [rbp-344]        ; b
    and     r8d, dword ptr [rbp-348]        ; b&c
    mov     eax, dword ptr [rbp-344]
    not     eax
    and     eax, dword ptr [rbp-352]        ; ~b&d
    or      r8d, eax
    mov     edx, 5A827999h
    SHA1_ROUND
    dec     r10d
    jnz     sb_r1
    ; ---- rounds 20..39: f=b^c^d, k=6ED9EBA1 ----
    mov     r10d, 20
sb_r2:
    mov     r8d, dword ptr [rbp-344]
    xor     r8d, dword ptr [rbp-348]
    xor     r8d, dword ptr [rbp-352]
    mov     edx, 6ED9EBA1h
    SHA1_ROUND
    dec     r10d
    jnz     sb_r2
    ; ---- rounds 40..59: f=(b&c)|(b&d)|(c&d), k=8F1BBCDC ----
    mov     r10d, 20
sb_r3:
    mov     r8d, dword ptr [rbp-344]
    and     r8d, dword ptr [rbp-348]        ; b&c
    mov     eax, dword ptr [rbp-344]
    and     eax, dword ptr [rbp-352]        ; b&d
    or      r8d, eax
    mov     eax, dword ptr [rbp-348]
    and     eax, dword ptr [rbp-352]        ; c&d
    or      r8d, eax
    mov     edx, 8F1BBCDCh
    SHA1_ROUND
    dec     r10d
    jnz     sb_r3
    ; ---- rounds 60..79: f=b^c^d, k=CA62C1D6 ----
    mov     r10d, 20
sb_r4:
    mov     r8d, dword ptr [rbp-344]
    xor     r8d, dword ptr [rbp-348]
    xor     r8d, dword ptr [rbp-352]
    mov     edx, 0CA62C1D6h
    SHA1_ROUND
    dec     r10d
    jnz     sb_r4
    ; h += a..e
    mov     rcx, qword ptr [rbp-368]
    mov     eax, dword ptr [rbp-340]
    add     dword ptr [rcx+0], eax
    mov     eax, dword ptr [rbp-344]
    add     dword ptr [rcx+4], eax
    mov     eax, dword ptr [rbp-348]
    add     dword ptr [rcx+8], eax
    mov     eax, dword ptr [rbp-352]
    add     dword ptr [rcx+12], eax
    mov     eax, dword ptr [rbp-356]
    add     dword ptr [rcx+16], eax
    FRAME_EPILOG
    ret
sha1_block endp

public sha1_init
sha1_init proc
    mov     dword ptr [rcx+0],  67452301h
    mov     dword ptr [rcx+4],  0EFCDAB89h
    mov     dword ptr [rcx+8],  98BADCFEh
    mov     dword ptr [rcx+12], 10325476h
    mov     dword ptr [rcx+16], 0C3D2E1F0h
    mov     dword ptr [rcx+20], 0            ; buflen
    mov     qword ptr [rcx+24], 0            ; msglen
    ret
sha1_init endp

; sha1_update(rcx=ctx, rdx=data, r8=len)
public sha1_update
sha1_update proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=ctx [rbp-32]=data [rbp-40]=len
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    add     qword ptr [rcx+24], r8           ; msglen += len
su_loop:
    cmp     qword ptr [rbp-40], 0
    je      su_done
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx+20]          ; buflen
    mov     r9d, 64
    sub     r9d, eax                         ; take = 64 - buflen
    mov     r8, qword ptr [rbp-40]
    cmp     r8, r9
    cmovb   r9, r8                           ; take = min(take, len)  (r9 small)
    ; copy r9 bytes data -> buffer+buflen
    lea     r10, [rcx+32]
    add     r10, rax                         ; dst = buffer + buflen
    mov     r11, qword ptr [rbp-32]          ; src
    xor     r8, r8
su_cpy:
    mov     dl, byte ptr [r11+r8]
    mov     byte ptr [r10+r8], dl
    inc     r8
    cmp     r8, r9
    jb      su_cpy
    add     eax, r9d                         ; buflen += take
    mov     dword ptr [rcx+20], eax
    add     qword ptr [rbp-32], r9           ; data += take
    sub     qword ptr [rbp-40], r9           ; len -= take
    cmp     eax, 64
    jne     su_loop
    ; full block
    lea     rdx, [rcx+32]
    call    sha1_block
    mov     rcx, qword ptr [rbp-24]
    mov     dword ptr [rcx+20], 0            ; buflen = 0
    jmp     su_loop
su_done:
    FRAME_EPILOG
    ret
sha1_update endp

; sha1_final(rcx=ctx, rdx=out20)
public sha1_final
sha1_final proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx          ; ctx
    mov     qword ptr [rbp-32], rdx          ; out
    ; bitlen = msglen*8
    mov     rax, qword ptr [rcx+24]
    shl     rax, 3
    mov     qword ptr [rbp-40], rax
    ; append 0x80
    mov     eax, dword ptr [rcx+20]          ; buflen
    lea     r10, [rcx+32]
    mov     byte ptr [r10+rax], 80h
    inc     eax                              ; buflen++
    ; if buflen > 56: zero to 64, block, buflen=0
    cmp     eax, 56
    jbe     sf_zero56
sf_fill64:
    cmp     eax, 64
    jae     sf_blk1
    mov     byte ptr [r10+rax], 0
    inc     eax
    jmp     sf_fill64
sf_blk1:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rcx+32]
    call    sha1_block
    mov     rcx, qword ptr [rbp-24]
    lea     r10, [rcx+32]
    xor     eax, eax
sf_zero56:
    cmp     eax, 56
    jae     sf_len
    mov     byte ptr [r10+rax], 0
    inc     eax
    jmp     sf_zero56
sf_len:
    ; write bitlen big-endian into buffer[56..63]
    mov     rax, qword ptr [rbp-40]
    bswap   rax
    mov     qword ptr [r10+56], rax
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rcx+32]
    call    sha1_block
    ; output h0..h4 big-endian
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    xor     r9d, r9d
sf_out:
    mov     eax, dword ptr [rcx+r9*4]
    bswap   eax
    mov     dword ptr [rdx+r9*4], eax
    inc     r9d
    cmp     r9d, 5
    jb      sf_out
    FRAME_EPILOG
    ret
sha1_final endp

; sha1_hash(rcx=data, rdx=len, r8=out20) - one-shot
public sha1_hash
sha1_hash proc frame
    FRAME_PROLOG 176
    ; ctx=[rbp-112] (clear of canary)  [rbp-120]=out [rbp-128]=data [rbp-136]=len
    mov     qword ptr [rbp-120], r8
    mov     qword ptr [rbp-128], rcx
    mov     qword ptr [rbp-136], rdx
    lea     rcx, [rbp-112]
    call    sha1_init
    lea     rcx, [rbp-112]
    mov     rdx, qword ptr [rbp-128]
    mov     r8, qword ptr [rbp-136]
    call    sha1_update
    lea     rcx, [rbp-112]
    mov     rdx, qword ptr [rbp-120]
    call    sha1_final
    FRAME_EPILOG
    ret
sha1_hash endp

; =============================================================================
; hmac_sha1(rcx=key, rdx=keylen, r8=msg, r9=msglen, [rbp+48]=out20)
; =============================================================================
public hmac_sha1
hmac_sha1 proc frame
    FRAME_PROLOG 384
    ; [rbp-24]=msg [rbp-32]=msglen [rbp-40]=out
    ; k_ipad=[rbp-128] (64)  k_opad=[rbp-192] (64)  ctx=[rbp-288] (96)
    ; inner=[rbp-312] (20)   keyhash=[rbp-260]? -> reuse inner region carefully
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-40], rax
    ; if keylen > 64: key = sha1(key); keylen = 20  (hash into k_ipad first 20)
    cmp     rdx, 64
    jbe     hm_short
    ; sha1(key) -> [rbp-128]
    lea     r10, [rbp-288]
    mov     qword ptr [rbp-48], rcx          ; save key/len
    mov     qword ptr [rbp-56], rdx
    mov     rcx, r10
    call    sha1_init
    lea     rcx, [rbp-288]
    mov     rdx, qword ptr [rbp-48]
    mov     r8, qword ptr [rbp-56]
    call    sha1_update
    lea     rcx, [rbp-288]
    lea     rdx, [rbp-128]                   ; hashed key into start of ipad area
    call    sha1_final
    lea     rcx, [rbp-128]                   ; key = hashed
    mov     rdx, 20
    jmp     hm_pads
hm_short:
    ; key stays in rcx, keylen in rdx
hm_pads:
    ; build k_ipad / k_opad: first keylen bytes = key^pad, rest = pad
    mov     qword ptr [rbp-48], rcx          ; key ptr (may be rbp-128)
    mov     qword ptr [rbp-56], rdx          ; keylen
    xor     r9, r9
hm_pad_loop:
    cmp     r9, 64
    jae     hm_pad_done
    xor     eax, eax                         ; key byte (0 past keylen)
    cmp     r9, qword ptr [rbp-56]
    jae     hm_pad_zero
    mov     r10, qword ptr [rbp-48]
    movzx   eax, byte ptr [r10+r9]
hm_pad_zero:
    mov     edx, eax
    xor     edx, 36h
    mov     byte ptr [rbp-128+r9], dl        ; need r9 indexing; use base reg
    xor     eax, 5Ch
    mov     byte ptr [rbp-192+r9], al
    inc     r9
    jmp     hm_pad_loop
hm_pad_done:
    ; inner = sha1(k_ipad || msg)
    lea     rcx, [rbp-288]
    call    sha1_init
    lea     rcx, [rbp-288]
    lea     rdx, [rbp-128]
    mov     r8, 64
    call    sha1_update
    lea     rcx, [rbp-288]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    sha1_update
    lea     rcx, [rbp-288]
    lea     rdx, [rbp-312]                   ; inner digest (20)
    call    sha1_final
    ; out = sha1(k_opad || inner)
    lea     rcx, [rbp-288]
    call    sha1_init
    lea     rcx, [rbp-288]
    lea     rdx, [rbp-192]
    mov     r8, 64
    call    sha1_update
    lea     rcx, [rbp-288]
    lea     rdx, [rbp-312]
    mov     r8, 20
    call    sha1_update
    lea     rcx, [rbp-288]
    mov     rdx, qword ptr [rbp-40]          ; out
    call    sha1_final
    FRAME_EPILOG
    ret
hmac_sha1 endp

; =============================================================================
; pbkdf2_hmac_sha1(rcx=pw, rdx=pwlen, r8=salt, r9=saltlen,
;                  [rbp+48]=iters, [rbp+56]=out, [rbp+64]=dklen)
; =============================================================================
public pbkdf2_hmac_sha1
pbkdf2_hmac_sha1 proc frame
    FRAME_PROLOG 256
    ; [rbp-24]=pw [rbp-32]=pwlen [rbp-40]=salt [rbp-48]=saltlen
    ; [rbp-56]=iters [rbp-64]=out [rbp-72]=dklen
    ; [rbp-80]=blockidx [rbp-88]=outpos [rbp-96]=j
    ; saltbuf=[rbp-160] (salt up to 64 + 4 byte index)  T=[rbp-184](20) U=[rbp-208](20)
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-56], rax
    mov     rax, qword ptr [rbp+56]
    mov     qword ptr [rbp-64], rax
    mov     rax, qword ptr [rbp+64]
    mov     qword ptr [rbp-72], rax
    mov     qword ptr [rbp-88], 0            ; outpos
    mov     dword ptr [rbp-80], 1            ; blockidx (1-based)
pk_block:
    mov     rax, qword ptr [rbp-88]
    cmp     rax, qword ptr [rbp-72]
    jae     pk_done
    ; saltbuf = salt || INT_BE(blockidx)
    mov     r8, qword ptr [rbp-48]           ; saltlen
    mov     r11, qword ptr [rbp-40]          ; salt
    xor     r9, r9
pk_scpy:
    cmp     r9, r8
    jae     pk_sidx
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [rbp-160+r9], al
    inc     r9
    jmp     pk_scpy
pk_sidx:
    mov     eax, dword ptr [rbp-80]
    bswap   eax
    mov     dword ptr [rbp-160+r9], eax      ; append 4-byte BE index
    add     r8, 4                            ; salt||idx length
    mov     qword ptr [rbp-96], r8           ; stash msglen for U1
    ; U1 = HMAC(pw, salt||idx) -> T ; U = U1
    lea     rcx, [rbp-184]                   ; out=T
    mov     qword ptr [rsp+32], rcx
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [rbp-160]
    mov     r9, qword ptr [rbp-96]
    call    hmac_sha1
    ; copy T -> U
    xor     r9, r9
pk_t2u:
    mov     eax, dword ptr [rbp-184+r9]
    mov     dword ptr [rbp-208+r9], eax
    add     r9, 4
    cmp     r9, 20
    jb      pk_t2u
    ; iterate j = 2..iters: U = HMAC(pw, U); T ^= U
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [rbp-96], rax          ; j counter = iters
    dec     qword ptr [rbp-96]
pk_iter:
    cmp     qword ptr [rbp-96], 0
    je      pk_emit
    lea     rcx, [rbp-208]                   ; out = U (in place)
    mov     qword ptr [rsp+32], rcx
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [rbp-208]
    mov     r9, 20
    call    hmac_sha1
    xor     r9, r9
pk_xor:
    mov     eax, dword ptr [rbp-208+r9]
    xor     dword ptr [rbp-184+r9], eax      ; T ^= U
    add     r9, 4
    cmp     r9, 20
    jb      pk_xor
    dec     qword ptr [rbp-96]
    jmp     pk_iter
pk_emit:
    ; copy up to 20 bytes of T into out at outpos (clamp to dklen)
    mov     r10, qword ptr [rbp-64]          ; out
    add     r10, qword ptr [rbp-88]          ; + outpos
    mov     r8, qword ptr [rbp-72]
    sub     r8, qword ptr [rbp-88]           ; remaining
    cmp     r8, 20
    jbe     @F
    mov     r8, 20
@@:
    xor     r9, r9
pk_ecpy:
    cmp     r9, r8
    jae     pk_enext
    mov     al, byte ptr [rbp-184+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    jmp     pk_ecpy
pk_enext:
    add     qword ptr [rbp-88], r8           ; outpos += copied
    inc     dword ptr [rbp-80]               ; blockidx++
    jmp     pk_block
pk_done:
    FRAME_EPILOG
    ret
pbkdf2_hmac_sha1 endp

end
