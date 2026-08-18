; =============================================================================
; crc32.asm - IEEE CRC-32 (reflected, poly 0xEDB88320), table-driven.
; -----------------------------------------------------------------------------
; The ZIP format authenticates each entry's uncompressed data with this CRC.
; Note: the SSE4.2 `crc32` instruction computes CRC-32C (Castagnoli), a DIFFERENT
; polynomial, so it cannot be used here - this is the classic zlib/PKZIP CRC.
;
;   crc32_update(rcx = crc, rdx = buf, r8 = len) -> eax = crc
;
; Matches zlib's crc32(): pass 0 as the initial crc; the running value returned
; can be fed back in as `crc` to continue over multiple chunks.  The proc folds
; the standard pre/post inversion (^0xFFFFFFFF) in internally, so a 0-length
; call returns its input unchanged.  The 256-entry table is built once, lazily.
; =============================================================================

include macros.inc

.data?
g_crc_table db 256*4 dup (?)
g_crc_ready dd ?

.code

public crc32_update
crc32_update proc frame
    FRAME_PROLOG 32
    ; rcx=crc rdx=buf r8=len
    ; ---- build the reflected CRC-32 table once (guarded) -------------------
    cmp     dword ptr [g_crc_ready], 0
    jne     cu_ready
    lea     r10, [g_crc_table]
    xor     r9d, r9d                     ; n = 0..255
cu_bn:
    mov     eax, r9d                     ; c = n
    mov     r11d, 8                      ; 8 shifts
cu_bk:
    test    eax, 1
    jz      cu_bnoxor
    shr     eax, 1
    xor     eax, 0EDB88320h
    jmp     cu_bnext
cu_bnoxor:
    shr     eax, 1
cu_bnext:
    dec     r11d
    jnz     cu_bk
    mov     dword ptr [r10+r9*4], eax
    inc     r9d
    cmp     r9d, 256
    jb      cu_bn
    mov     dword ptr [g_crc_ready], 1
cu_ready:
    mov     eax, ecx                     ; c = crc
    not     eax                          ; c ^= 0xFFFFFFFF
    test    r8, r8
    jz      cu_fin
    lea     r10, [g_crc_table]
    xor     r9, r9                       ; i
cu_loop:
    movzx   r11d, byte ptr [rdx+r9]      ; buf[i]
    xor     r11d, eax                    ; (c ^ byte) & 0xFF
    movzx   r11d, r11b
    mov     r11d, dword ptr [r10+r11*4]  ; table[...]
    shr     eax, 8
    xor     eax, r11d                    ; c = table[...] ^ (c>>8)
    inc     r9
    cmp     r9, r8
    jb      cu_loop
cu_fin:
    not     eax                          ; c ^= 0xFFFFFFFF
    FRAME_EPILOG
    ret
crc32_update endp

end
