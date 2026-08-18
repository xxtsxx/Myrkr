; =============================================================================
; archive.asm - minimal ustar (POSIX tar) header builder
; -----------------------------------------------------------------------------
; The pack driver (pack.asm) streams tar through the GCM layer.  Here we only
; BUILD the 512-byte ustar headers (validated against GNU tar).  Nothing here
; reads one back any more - see the note where the parser used to be.
;
;   tar_octal(rcx = field ptr, edx = field len, r8 = value)
;   tar_build_header(rcx = hdr512, rdx = name(utf8z), r8 = prefix(utf8z|0),
;                    r9 = size, [rsp+40] = typeflag char)
; =============================================================================

include macros.inc

extern secure_zero:proc

TAR_BLOCK   equ 512

.data?

.code

; =============================================================================
; tar_octal(rcx = field, edx = len, r8 = value)
; Writes zero-padded octal into field[0..len-2], field[len-1] = 0.
; =============================================================================
; Values that fit in (len-1) octal digits are written as zero-padded octal,
; exactly as classic ustar.  Larger values (e.g. a >8 GiB file size in the
; 12-byte size field) use the GNU base-256 extension: the high bit of the
; first byte is set (0x80) and the remaining bytes hold the big-endian binary
; magnitude.  Only the size field can realistically overflow.
public tar_octal
tar_octal proc
    mov     r11, rcx                    ; field ptr (preserved across proc)
    movsxd  r10, edx                    ; field len
    ; threshold = 2^(3*(len-1)) - 1, only meaningful while 3*(len-1) < 64
    mov     rax, r10
    dec     rax
    lea     rax, [rax+rax*2]            ; 3*(len-1)
    cmp     rax, 64
    jae     to_dooctal                  ; can't overflow a 64-bit value
    mov     rcx, rax                    ; shift count -> cl
    mov     r9, 1
    shl     r9, cl
    dec     r9                          ; max octal-representable value
    cmp     r8, r9
    ja      to_base256
to_dooctal:
    lea     r9, [r11+r10-1]
    mov     byte ptr [r9], 0            ; NUL terminator
    dec     r9                          ; last digit position
    mov     rax, r8                     ; value
    mov     rcx, 8
to_loop:
    cmp     r9, r11
    jb      to_done
    xor     rdx, rdx
    div     rcx                         ; rax/8, rdx = digit
    add     dl, '0'
    mov     byte ptr [r9], dl
    dec     r9
    jmp     to_loop
to_done:
    ret
to_base256:
    mov     byte ptr [r11], 80h         ; GNU base-256 flag in first byte
    lea     r9, [r11+r10-1]             ; last byte (LSB)
    mov     rax, r8                     ; value
to_b256:
    cmp     r9, r11                     ; stop before overwriting flag byte
    jbe     to_done
    mov     byte ptr [r9], al
    shr     rax, 8
    dec     r9
    jmp     to_b256
tar_octal endp

; =============================================================================
; tar_build_header(rcx = hdr512, rdx = name, r8 = prefix|0, r9 = size,
;                  [rsp+40] = typeflag)
; =============================================================================
public tar_build_header
tar_build_header proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=hdr [rbp-32]=name [rbp-40]=prefix [rbp-48]=size [rbp-56]=type
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     rax, qword ptr [rbp+48]     ; 5th arg (typeflag) at [rbp+48]
    mov     qword ptr [rbp-56], rax

    ; zero the 512-byte header
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, TAR_BLOCK
    call    secure_zero

    ; name -> [hdr+0], up to 100 bytes
    mov     rdx, qword ptr [rbp-24]     ; hdr
    mov     rcx, qword ptr [rbp-32]     ; name
    mov     r8d, 100
    call    copy_bounded
    ; prefix -> [hdr+345], up to 155 (if non-null)
    cmp     qword ptr [rbp-40], 0
    je      bh_noprefix
    mov     rdx, qword ptr [rbp-24]
    add     rdx, 345
    mov     rcx, qword ptr [rbp-40]
    mov     r8d, 155
    call    copy_bounded
bh_noprefix:
    mov     r11, qword ptr [rbp-24]     ; hdr base (kept in r11)
    ; mode: dir 0755 else 0644
    lea     rcx, [r11+100]
    mov     edx, 8
    mov     r8, 420                     ; 0644 octal (file mode)
    cmp     qword ptr [rbp-56], '5'
    jne     @F
    mov     r8, 493                     ; 0755 octal (dir mode)
@@:
    call    tar_octal
    ; uid/gid/mtime = 0
    mov     r11, qword ptr [rbp-24]
    lea     rcx, [r11+108]
    mov     edx, 8
    xor     r8, r8
    call    tar_octal
    mov     r11, qword ptr [rbp-24]
    lea     rcx, [r11+116]
    mov     edx, 8
    xor     r8, r8
    call    tar_octal
    mov     r11, qword ptr [rbp-24]
    lea     rcx, [r11+136]
    mov     edx, 12
    xor     r8, r8
    call    tar_octal
    ; size: 0 for dir, else size
    mov     r11, qword ptr [rbp-24]
    lea     rcx, [r11+124]
    mov     edx, 12
    mov     r8, qword ptr [rbp-48]
    cmp     qword ptr [rbp-56], '5'
    jne     @F
    xor     r8, r8
@@:
    call    tar_octal
    ; typeflag
    mov     r11, qword ptr [rbp-24]
    mov     rax, qword ptr [rbp-56]
    mov     byte ptr [r11+156], al
    ; magic "ustar\0" + version "00"
    mov     byte ptr [r11+257], 'u'
    mov     byte ptr [r11+258], 's'
    mov     byte ptr [r11+259], 't'
    mov     byte ptr [r11+260], 'a'
    mov     byte ptr [r11+261], 'r'
    mov     byte ptr [r11+262], 0
    mov     byte ptr [r11+263], '0'
    mov     byte ptr [r11+264], '0'

    ; checksum: chksum field = 8 spaces, sum all bytes, write 6 octal + NUL + space
    mov     r11, qword ptr [rbp-24]
    mov     ecx, 8
    lea     r10, [r11+148]
cs_spaces:
    mov     byte ptr [r10], ' '
    inc     r10
    dec     ecx
    jnz     cs_spaces
    xor     eax, eax                    ; sum
    xor     r10d, r10d
cs_sum:
    movzx   edx, byte ptr [r11+r10]
    add     eax, edx
    inc     r10d
    cmp     r10d, TAR_BLOCK
    jb      cs_sum
    ; write sum as 6-digit octal at [148], then NUL at [154], space at [155]
    lea     rcx, [r11+148]
    mov     edx, 7                      ; 6 digits + NUL
    mov     r8, rax
    call    tar_octal
    mov     r11, qword ptr [rbp-24]
    mov     byte ptr [r11+155], ' '
    FRAME_EPILOG
    ret
tar_build_header endp

; ---------------------------------------------------------------------------
; copy_bounded(rcx = src(utf8z), rdx = dst, r8d = max) - copy up to max bytes
; or until NUL (NUL not copied; field stays zero-padded).
; ---------------------------------------------------------------------------
copy_bounded proc
    xor     r9d, r9d
cb_loop:
    cmp     r9d, r8d
    jae     cb_done
    mov     al, byte ptr [rcx+r9]
    test    al, al
    jz      cb_done
    mov     byte ptr [rdx+r9], al
    inc     r9d
    jmp     cb_loop
cb_done:
    ret
copy_bounded endp

; =============================================================================
; tar_parse_header AND parse_octal LIVED HERE.
;
; They read a 512-byte ustar header back: the size (octal, or GNU base-256 when
; the high bit is set), the type byte, and the entry path reassembled from the
; prefix and name fields.  Extraction needed all three because it walked the tar
; stream sequentially and the header was the only description it had.
;
; It does not walk it any more (docs/V5_WORK.md, step A2).  The inventory records
; the name, the size and a directory flag for every entry, with its own tag over
; the lot, so unpack_entry skips the 512 bytes without reading them - and a
; parser that no longer runs on attacker-supplied bytes is one that can never be
; wrong about them.  This tree still WRITES ustar headers, which is why the
; builder above stays: a container's payload is a tar stream that other tools
; can read.
; =============================================================================

end
