; =============================================================================
; zip.asm - create WinZip AES-256 encrypted ZIP archives.
; -----------------------------------------------------------------------------
; INTEROP FEATURE (not the hardened .mrk path).  Produces standard .zip files
; whose entries are encrypted with WinZip AES-256 (AE-2), readable by 7-Zip,
; WinRAR, WinZip and our own `unzip`.  This deliberately trades away the .mrk
; container's Argon2id KDF and key-committing AES-GCM for compatibility with the
; tools recipients actually have.  Per entry:
;
;   fresh random 16-byte salt
;   key = PBKDF2-HMAC-SHA1(password, salt, 1000, 66) -> aesKey/macKey/pwVerify
;   data = DEFLATE(plaintext) if it shrinks, else the plaintext (STORED)
;   ciphertext = AES-256-CTR(aesKey, data)
;   entry = salt(16) || pwVerify(2) || ciphertext || HMAC-SHA1(macKey,ct)[0..9]
;
; AE-2 => the ZIP CRC-32 field is 0.  Compression uses our DEFLATE encoder
; (deflate.asm) for entries up to DEFLATE_MAX held in memory; larger entries and
; incompressible data are stored.  Files are walked recursively; entry names are
; the input-relative paths ('/'-separated).  ZIP64 is emitted automatically for
; entries/offsets >= 4 GiB or >= 65535 entries.  Empty directories are not kept.
;
;   do_zip -> eax exit code
; =============================================================================

include macros.inc

extern normalize_path:proc
extern make_temp_path:proc
extern disk_has_space:proc
extern input_size:proc
extern zip_read_cd:proc
extern zip_check_password:proc
extern add_prefix_copy:proc
extern pfx_select:proc
extern sanitize_name:proc
externdef g_add_prefixlen:qword
extern file_open_rw:proc
extern file_seek:proc
extern file_truncate:proc
externdef g_prog_abort:dword
externdef g_cfg_in:qword
externdef g_cdbuf:qword
externdef g_cdsize:qword
externdef g_cdcount:qword
externdef g_uz_size:qword
externdef g_uz_hin:qword
extern file_open_write:proc
extern file_open_read:proc
extern file_write_all:proc
extern file_read_exact:proc
extern file_read_at:proc
extern crc32_update:proc
extern file_close:proc
extern file_rename:proc
extern file_delete:proc
extern get_file_size:proc
extern read_file:proc
extern mem_free:proc
extern rng_fill:proc
extern pbkdf2_hmac_sha1:proc
extern sha1_init:proc
extern sha1_update:proc
extern sha1_final:proc
extern aes_expand_key:proc
extern aes_ctr_xor:proc
extern deflate_buf:proc
extern mem_alloc:proc
extern check_password_policy:proc
extern print_policy_error:proc
extern progress_begin:proc
extern progress_add:proc
extern rlog_added:proc                  ; ramlog.asm: one line per entry
extern progress_done:proc
extern print_a:proc
extern print_u64:proc
extern print_wz:proc
extern secure_zero:proc

extern GetFileAttributesW:proc
extern FindFirstFileW:proc
extern FindNextFileW:proc
extern FindClose:proc
extern WideCharToMultiByte:proc

externdef g_cfg_out:qword
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_positionals:qword
externdef g_poscount:qword
externdef g_cur_input:qword
externdef g_file_total:qword             ; per-positional total bytes (GUI per-file bars)
externdef g_temppath:word

INVALID         equ -1
CP_UTF8         equ 65001
CHUNK           equ 100000h
FILE_ATTR_DIR   equ 10h
FIND_CFILENAME  equ 44
SIG_LOCAL       equ 04034B50h
SIG_CDIR        equ 02014B50h
SIG_EOCD        equ 06054B50h
SIG_Z64EOCD     equ 06064B50h
SIG_Z64LOC      equ 07064B50h
                                ; the local SHA1CTX equ is gone: SHA1_CTX_SIZE
                                ; (macros.inc) is owned by sha1.asm's layout
DEFLATE_MAX     equ 8000000h    ; 128 MiB: larger entries are stored (memory bound)
ZIP64_SENT      equ 0FFFFFFFFh  ; the 0xFFFFFFFF "value is in the ZIP64 extra" sentinel
ZIP64_TRIG      equ 0FFFFFFFFh  ; a 32-bit size/offset field at this value -> ZIP64
ZIP64_CNT       equ 0FFFFh      ; entry count at this value -> ZIP64 EOCD

; ZTRIG lhs - compare a 64-bit size/offset (lhs) against the 4 GiB ZIP64 trigger.
; A bare `cmp r/m64, 0FFFFFFFFh` sign-extends the immediate to 0xFFFFFFFFFFFFFFFF,
; so it never fires for real >= 4 GiB values; load the constant zero-extended into
; r11 first.  Sets flags for the following jb/jae.  Clobbers r11.
ZTRIG macro lhs
    mov     r11d, ZIP64_TRIG
    cmp     lhs, r11
endm

.const
zip_aesx      db 001h,099h,007h,000h,002h,000h,'A','E',003h,000h,000h ; AES extra (AE-2, AES-256, store)
zip_aesx_defl db 001h,099h,007h,000h,002h,000h,'A','E',003h,008h,000h ; AES extra (real method = deflate)
CSTR lbl_zip,     "zipping"
CSTR m_zip_done,  "zipped "
CSTR m_zip_done2, " file(s) -> "
CSTR m_nl,        13,10
CSTR e_zip_noout, "myrkr: zip requires -o OUTPUT.zip",13,10
CSTR e_zadd_chk,    "error: cannot check the password against this archive - refusing to append (see docs/ARCHIVE_APPEND.md)",13,10
CSTR e_zadd_open,   "error: cannot read that zip archive",13,10
CSTR e_zadd_usage,  "usage: myrkr zipadd ARCHIVE.zip FILE [FILE...] [-p PASSWORD]",13,10
CSTR e_zadd_pw,     "error: that password does not open the entries already in this archive",13,10
CSTR m_zadd_done,   "zipadd: OK",13,10
CSTR e_zip_io,    "myrkr: I/O error writing the archive",13,10
CSTR e_zip_space, "myrkr: not enough free disk space for the archive",13,10

.data?
g_zip_hout  dq ?
g_zip_cout  dq ?
g_zipoff    dq ?
g_zip_cdsize dq ?
g_zip_cdoff dq ?
g_zip_z64off dq ?
g_zip_count dq ?
g_ziperr    dq ?
zip_out_np  dw 8000h dup (?)
zip_tempc   dw 8010h dup (?)
g_zwalk     dw 8000h dup (?)
g_zwalklen  dq ?
g_zrel      db 4096 dup (?)
g_zrellen   dq ?
g_zchildu8  db 1024 dup (?)
zip_salt    db 16 dup (?)
zip_keys    db 72 dup (?)
zip_rk      db 240 dup (?)
zip_ctr     db 16 dup (?)
zip_ipad    db 64 dup (?)
zip_opad    db 64 dup (?)
zip_sctx    db SHA1_CTX_SIZE dup (?)
zip_inner   db 20 dup (?)
zip_mac     db 20 dup (?)
zip_fhdr    db 64 dup (?)
zip_chdr    db 64 dup (?)
zip_eocd    db 32 dup (?)
zip_extrabuf db 64 dup (?)      ; ZIP64 extra (<=28) + AES extra (11)
zip_z64rec  db 96 dup (?)       ; ZIP64 EOCD record (56) + locator (20)
align 16
zip_chunk   db CHUNK dup (?)

.code

; zw(rcx=ptr, rdx=len) - write to the main temp + advance g_zipoff (sticky err)
zw proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_ziperr], 0
    jne     zw_ret
    mov     qword ptr [rbp-24], rdx
    mov     r8, rdx
    mov     rdx, rcx
    mov     rcx, qword ptr [g_zip_hout]
    call    file_write_all
    test    eax, eax
    jz      zw_ok
    mov     qword ptr [g_ziperr], EXIT_IO
    jmp     zw_ret
zw_ok:
    mov     rax, qword ptr [rbp-24]
    add     qword ptr [g_zipoff], rax
zw_ret:
    FRAME_EPILOG
    ret
zw endp

; cw(rcx=ptr, rdx=len) - write to the central-dir temp + advance g_zip_cdsize
cw proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_ziperr], 0
    jne     cw_ret
    mov     qword ptr [rbp-24], rdx
    mov     r8, rdx
    mov     rdx, rcx
    mov     rcx, qword ptr [g_zip_cout]
    call    file_write_all
    test    eax, eax
    jz      cw_ok
    mov     qword ptr [g_ziperr], EXIT_IO
    jmp     cw_ret
cw_ok:
    mov     rax, qword ptr [rbp-24]
    add     qword ptr [g_zip_cdsize], rax
cw_ret:
    FRAME_EPILOG
    ret
cw endp

; =============================================================================
; zip_put_zip64(rcx=dst, rdx=mask, r8=usize, r9=csize, [rsp+40]=localoff)
; Build a ZIP64 extra field (0x0001).  mask bit0=usize, bit1=csize, bit2=offset
; (in that fixed order).  -> rax = total bytes written (4-byte header + body).
; =============================================================================
zip_put_zip64 proc
    mov     word ptr [rcx], 0001h
    lea     r10, [rcx+4]
    test    rdx, 1
    jz      z64_1
    mov     qword ptr [r10], r8
    add     r10, 8
z64_1:
    test    rdx, 2
    jz      z64_2
    mov     qword ptr [r10], r9
    add     r10, 8
z64_2:
    test    rdx, 4
    jz      z64_3
    mov     rax, qword ptr [rsp+40]
    mov     qword ptr [r10], rax
    add     r10, 8
z64_3:
    mov     rax, r10
    sub     rax, rcx
    sub     rax, 4
    mov     word ptr [rcx+2], ax            ; body size
    add     rax, 4
    ret
zip_put_zip64 endp

; =============================================================================
; zip_emit_file - emit one encrypted entry for g_zwalk (full path) / g_zrel
; (UTF-8 relative name, g_zrellen).  Sticky errors set g_ziperr.
; =============================================================================
zip_emit_file proc frame
    FRAME_PROLOG 320
    ; [rbp-24]=hin [rbp-32]=usize [rbp-40]=csize [rbp-48]=localoff [rbp-56]=namelen
    ; [rbp-64/72]=stream remaining/chunk  [rbp-80]=realmethod [rbp-88]=datalen
    ; [rbp-96]=databuf [rbp-104]=filebuf [rbp-112]=defbuf [rbp-120]=inmem
    ; [rbp-128]=aesxptr [rbp-136]=u32 [rbp-144]=c32 [rbp-152]=o32
    ; [rbp-160]=extralen [rbp-168]=verneed
    mov     qword ptr [rbp-24], INVALID
    mov     qword ptr [rbp-104], 0
    mov     qword ptr [rbp-112], 0
    mov     rax, qword ptr [g_zrellen]
    mov     qword ptr [rbp-56], rax
    lea     rcx, [g_zwalk]
    call    file_open_read
    cmp     rax, INVALID
    je      zef_err
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    lea     rdx, [rbp-32]
    call    get_file_size
    test    eax, eax
    jnz     zef_err
    mov     rax, qword ptr [rbp-32]
    ; ---- choose STORE vs DEFLATE (in-memory for entries up to DEFLATE_MAX) ---
    mov     qword ptr [rbp-80], 0            ; realmethod = store
    mov     qword ptr [rbp-88], rax          ; datalen = usize
    mov     qword ptr [rbp-96], 0            ; databuf
    mov     qword ptr [rbp-120], 0           ; inmem
    test    rax, rax
    jz      zef_inmem_set                    ; empty file -> in-memory, no data
    cmp     rax, DEFLATE_MAX
    ja      zef_sizes                        ; large -> stream as store
    mov     rcx, rax
    call    mem_alloc
    test    rax, rax
    jz      zef_sizes                        ; OOM -> streaming store
    mov     qword ptr [rbp-104], rax
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, rax
    mov     r8, qword ptr [rbp-32]
    call    file_read_exact
    test    eax, eax
    jnz     zef_err
    mov     r10, qword ptr [rbp-104]
    mov     qword ptr [rbp-96], r10          ; databuf = filebuf (store default)
    mov     rcx, qword ptr [rbp-32]
    call    mem_alloc
    test    rax, rax
    jz      zef_inmem_set                    ; no defbuf -> store filebuf
    mov     qword ptr [rbp-112], rax
    mov     rcx, qword ptr [rbp-104]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-112]
    mov     r9, qword ptr [rbp-32]
    call    deflate_buf
    cmp     rax, -1
    je      zef_inmem_set                    ; incompressible -> store
    cmp     rax, qword ptr [rbp-32]
    jae     zef_inmem_set                    ; didn't shrink -> store
    mov     qword ptr [rbp-80], 8            ; realmethod = deflate
    mov     qword ptr [rbp-88], rax          ; datalen = dsize
    mov     r10, qword ptr [rbp-112]
    mov     qword ptr [rbp-96], r10          ; databuf = defbuf
zef_inmem_set:
    mov     qword ptr [rbp-120], 1           ; inmem
zef_sizes:
    mov     rax, qword ptr [rbp-88]
    cmp     dword ptr [g_cfg_passlen], 0     ; AES wraps data in salt(16)+verify(2)+mac(10)
    je      @F
    add     rax, 28                          ; csize = datalen + 28
@@:
    mov     qword ptr [rbp-40], rax
    lea     rax, [zip_aesx]                  ; AES extra: store or deflate
    cmp     qword ptr [rbp-80], 0
    je      @F
    lea     rax, [zip_aesx_defl]
@@:
    mov     qword ptr [rbp-128], rax
    ; per-entry crypto material - only when a password is set
    mov     dword ptr [rbp-176], 0           ; crc-32 accumulator (plain entries)
    cmp     dword ptr [g_cfg_passlen], 0
    je      zef_plain_crc                    ; no password -> compute a real CRC-32
    ; fresh salt + per-entry key
    lea     rcx, [zip_salt]
    mov     edx, 16
    call    rng_fill
    test    eax, eax
    jz      zef_err
    mov     qword ptr [rsp+32], 1000
    lea     rax, [zip_keys]
    mov     qword ptr [rsp+40], rax
    mov     qword ptr [rsp+48], 66
    lea     rcx, [g_cfg_pass]
    mov     edx, dword ptr [g_cfg_passlen]
    lea     r8, [zip_salt]
    mov     r9, 16
    call    pbkdf2_hmac_sha1
    lea     rcx, [zip_keys]                  ; expand aesKey -> zip_rk (Nr=14)
    mov     rdx, 32
    lea     r8, [zip_rk]
    call    aes_expand_key
    jmp     zef_crc_done
zef_plain_crc:
    ; unencrypted entry: ZIP authenticates with a real CRC-32 of the *uncompressed*
    ; data.  In-memory entries CRC their loaded buffer; a large streamed-store entry
    ; pre-scans the file (positioned reads), then rewinds to 0 for the write loop.
    cmp     qword ptr [rbp-32], 0            ; empty file -> crc stays 0
    je      zef_crc_done
    cmp     qword ptr [rbp-120], 0           ; in-memory?
    je      zef_crc_scan
    xor     ecx, ecx
    mov     rdx, qword ptr [rbp-104]         ; filebuf (uncompressed)
    mov     r8, qword ptr [rbp-32]           ; usize
    call    crc32_update
    mov     dword ptr [rbp-176], eax
    jmp     zef_crc_done
zef_crc_scan:
    mov     qword ptr [rbp-192], 0           ; scan offset
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-200], rax         ; scan remaining
zef_crc_sl:
    cmp     qword ptr [rbp-200], 0
    je      zef_crc_rewind
    mov     r8, qword ptr [rbp-200]
    cmp     r8, CHUNK
    jbe     @F
    mov     r8, CHUNK
@@:
    mov     qword ptr [rbp-184], r8          ; this chunk length
    mov     rcx, qword ptr [rbp-24]          ; handle
    mov     rdx, qword ptr [rbp-192]         ; offset
    lea     r8, [zip_chunk]
    mov     r9, qword ptr [rbp-184]
    call    file_read_at
    test    eax, eax
    jnz     zef_err
    mov     ecx, dword ptr [rbp-176]         ; running crc
    lea     rdx, [zip_chunk]
    mov     r8, qword ptr [rbp-184]
    call    crc32_update
    mov     dword ptr [rbp-176], eax
    mov     rax, qword ptr [rbp-184]
    add     qword ptr [rbp-192], rax
    sub     qword ptr [rbp-200], rax
    jmp     zef_crc_sl
zef_crc_rewind:
    mov     rcx, qword ptr [rbp-24]          ; rewind to start for the write loop
    xor     rdx, rdx
    lea     r8, [zip_chunk]
    xor     r9, r9
    call    file_read_at
    ; Checked, like every other read here.  This one is a zero-length read whose
    ; only purpose is the seek inside file_read_at, and the payload loop below
    ; reads from the CURRENT file pointer (file_read_exact, not file_read_at) -
    ; so if the seek fails the entry is written from wherever the CRC scan left
    ; the pointer.  That is a wrong zip that reports success, not a failure.
    test    eax, eax
    jnz     zef_err
zef_crc_done:
    ; local header offset
    mov     rax, qword ptr [g_zipoff]
    mov     qword ptr [rbp-48], rax
    ; ---- ZIP64: 32-bit field values (sentinel when >= 4 GiB) + version -------
    mov     dword ptr [rbp-168], 20
    mov     rax, qword ptr [rbp-32]
    ZTRIG   rax
    jb      @F
    mov     dword ptr [rbp-168], 45
    mov     rax, ZIP64_SENT
@@:
    mov     qword ptr [rbp-136], rax         ; u32
    mov     rax, qword ptr [rbp-40]
    ZTRIG   rax
    jb      @F
    mov     dword ptr [rbp-168], 45
    mov     rax, ZIP64_SENT
@@:
    mov     qword ptr [rbp-144], rax         ; c32
    mov     rax, qword ptr [rbp-48]
    ZTRIG   rax
    jb      @F
    mov     dword ptr [rbp-168], 45
    mov     rax, ZIP64_SENT
@@:
    mov     qword ptr [rbp-152], rax         ; o32
    ; ---- build local extra: ZIP64(usize,csize) then AES ---------------------
    xor     edx, edx
    ZTRIG   qword ptr [rbp-32]
    jb      @F
    or      edx, 1
@@:
    ZTRIG   qword ptr [rbp-40]
    jb      @F
    or      edx, 2
@@:
    mov     qword ptr [rbp-160], 0
    test    edx, edx
    jz      zef_lx_aes
    lea     rcx, [zip_extrabuf]
    mov     r8, qword ptr [rbp-32]
    mov     r9, qword ptr [rbp-40]
    mov     qword ptr [rsp+32], 0
    call    zip_put_zip64
    mov     qword ptr [rbp-160], rax
zef_lx_aes:
    cmp     dword ptr [g_cfg_passlen], 0     ; plain entries carry no AES extra field
    je      zef_lx_done
    mov     r11, qword ptr [rbp-160]
    lea     r10, [zip_extrabuf]
    add     r10, r11
    mov     r8, qword ptr [rbp-128]
    xor     r9, r9
zef_lx_cp:
    mov     al, byte ptr [r8+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    cmp     r9, 11
    jb      zef_lx_cp
    add     qword ptr [rbp-160], 11          ; extralen = zip64 + 11
zef_lx_done:
    ; ---- build + write local file header -----------------------------------
    lea     r10, [zip_fhdr]
    mov     dword ptr [r10+0], SIG_LOCAL
    mov     eax, dword ptr [rbp-168]
    mov     word ptr [r10+4], ax             ; version needed
    cmp     dword ptr [g_cfg_passlen], 0
    je      zef_lh_plain
    mov     word ptr [r10+6], 0801h          ; encrypted + UTF-8 name
    mov     word ptr [r10+8], 99             ; method = AES
    mov     dword ptr [r10+14], 0            ; crc-32 = 0 (AE-2)
    jmp     zef_lh_common
zef_lh_plain:
    mov     word ptr [r10+6], 0800h          ; UTF-8 name, not encrypted
    mov     eax, dword ptr [rbp-80]          ; method = store (0) / deflate (8)
    mov     word ptr [r10+8], ax
    mov     eax, dword ptr [rbp-176]         ; real crc-32 of the uncompressed data
    mov     dword ptr [r10+14], eax
zef_lh_common:
    mov     word ptr [r10+10], 0
    mov     word ptr [r10+12], 0021h
    mov     eax, dword ptr [rbp-144]
    mov     dword ptr [r10+18], eax          ; csize (or sentinel)
    mov     eax, dword ptr [rbp-136]
    mov     dword ptr [r10+22], eax          ; usize (or sentinel)
    mov     eax, dword ptr [rbp-56]
    mov     word ptr [r10+26], ax            ; name len
    mov     eax, dword ptr [rbp-160]
    mov     word ptr [r10+28], ax            ; extra len
    lea     rcx, [zip_fhdr]
    mov     rdx, 30
    call    zw
    lea     rcx, [g_zrel]
    mov     rdx, qword ptr [rbp-56]
    call    zw
    lea     rcx, [zip_extrabuf]
    mov     rdx, qword ptr [rbp-160]
    call    zw
    ; encrypted entries: emit salt + pw-verify and prime the HMAC + AES counter
    cmp     dword ptr [g_cfg_passlen], 0
    je      zef_data
    ; salt + password-verification value
    lea     rcx, [zip_salt]
    mov     rdx, 16
    call    zw
    lea     rcx, [zip_keys+64]
    mov     rdx, 2
    call    zw
    ; ---- HMAC ipad/opad from macKey (zip_keys[32..63]) ----------------------
    lea     r8, [zip_keys+32]                ; macKey (RIP-relative bases; a
    lea     r10, [zip_ipad]                  ; [label+reg] form would force an
    lea     r11, [zip_opad]                  ; absolute fixup that won't link)
    xor     r9, r9
zef_pad:
    cmp     r9, 64
    jae     zef_padd
    xor     eax, eax
    cmp     r9, 32
    jae     @F
    movzx   eax, byte ptr [r8+r9]
@@:
    mov     edx, eax
    xor     edx, 36h
    mov     byte ptr [r10+r9], dl
    xor     eax, 5Ch
    mov     byte ptr [r11+r9], al
    inc     r9
    jmp     zef_pad
zef_padd:
    lea     rcx, [zip_sctx]
    call    sha1_init
    lea     rcx, [zip_sctx]
    lea     rdx, [zip_ipad]
    mov     r8, 64
    call    sha1_update
    lea     rcx, [zip_ctr]
    mov     rdx, 16
    call    secure_zero
zef_data:
    ; ---- data: in-memory (store/deflate buffer) or streamed (large store) ---
    cmp     qword ptr [rbp-120], 0
    je      zef_stream
    cmp     qword ptr [rbp-88], 0
    je      zef_fin                          ; empty entry: no data
    cmp     dword ptr [g_cfg_passlen], 0
    je      zef_inmem_plain
    mov     qword ptr [rsp+32], 14
    lea     rcx, [zip_rk]
    mov     rdx, qword ptr [rbp-96]
    mov     r8, qword ptr [rbp-88]
    lea     r9, [zip_ctr]
    call    aes_ctr_xor
    lea     rcx, [zip_sctx]
    mov     rdx, qword ptr [rbp-96]
    mov     r8, qword ptr [rbp-88]
    call    sha1_update
    mov     rcx, qword ptr [rbp-96]
    mov     rdx, qword ptr [rbp-88]
    call    zw
    mov     rcx, qword ptr [rbp-32]          ; progress by uncompressed size
    call    progress_add
    jmp     zef_fin
zef_inmem_plain:
    ; plain: write the stored/deflated bytes verbatim (CRC already computed)
    mov     rcx, qword ptr [rbp-96]
    mov     rdx, qword ptr [rbp-88]
    call    zw
    mov     rcx, qword ptr [rbp-32]
    call    progress_add
    jmp     zef_fin
zef_stream:
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-64], rax
    xWHILE qword ptr [rbp-64], ne, 0         ; while plaintext remains
        mov     r8, qword ptr [rbp-64]
        xIF r8, a, CHUNK
            mov     r8, CHUNK
        xENDIF
        mov     qword ptr [rbp-72], r8
        mov     rcx, qword ptr [rbp-24]
        lea     rdx, [zip_chunk]
        call    file_read_exact
        test    eax, eax
        jnz     zef_err
        cmp     dword ptr [g_cfg_passlen], 0   ; plain: stream the chunk verbatim
        je      zef_str_wr
        mov     qword ptr [rsp+32], 14       ; Nr
        lea     rcx, [zip_rk]
        lea     rdx, [zip_chunk]
        mov     r8, qword ptr [rbp-72]
        lea     r9, [zip_ctr]
        call    aes_ctr_xor
        lea     rcx, [zip_sctx]
        lea     rdx, [zip_chunk]
        mov     r8, qword ptr [rbp-72]
        call    sha1_update
zef_str_wr:
        lea     rcx, [zip_chunk]
        mov     rdx, qword ptr [rbp-72]
        call    zw
        cmp     qword ptr [g_ziperr], 0
        jne     zef_ret
        mov     rcx, qword ptr [rbp-72]
        call    progress_add
        mov     rax, qword ptr [rbp-72]
        sub     qword ptr [rbp-64], rax
    xENDW
zef_fin:
    cmp     dword ptr [g_cfg_passlen], 0     ; plain entries carry no trailing MAC
    je      zef_close
    lea     rcx, [zip_sctx]
    lea     rdx, [zip_inner]
    call    sha1_final
    lea     rcx, [zip_sctx]
    call    sha1_init
    lea     rcx, [zip_sctx]
    lea     rdx, [zip_opad]
    mov     r8, 64
    call    sha1_update
    lea     rcx, [zip_sctx]
    lea     rdx, [zip_inner]
    mov     r8, 20
    call    sha1_update
    lea     rcx, [zip_sctx]
    lea     rdx, [zip_mac]
    call    sha1_final
    lea     rcx, [zip_mac]
    mov     rdx, 10
    call    zw
zef_close:
    mov     rcx, qword ptr [rbp-24]
    call    file_close
    mov     qword ptr [rbp-24], INVALID
    ; ---- central directory record ------------------------------------------
    ; build central extra: ZIP64(usize,csize,offset) then AES
    xor     edx, edx
    ZTRIG   qword ptr [rbp-32]
    jb      @F
    or      edx, 1
@@:
    ZTRIG   qword ptr [rbp-40]
    jb      @F
    or      edx, 2
@@:
    ZTRIG   qword ptr [rbp-48]
    jb      @F
    or      edx, 4
@@:
    mov     qword ptr [rbp-160], 0
    test    edx, edx
    jz      zef_cx_aes
    lea     rcx, [zip_extrabuf]
    mov     r8, qword ptr [rbp-32]
    mov     r9, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [rsp+32], rax
    call    zip_put_zip64
    mov     qword ptr [rbp-160], rax
zef_cx_aes:
    cmp     dword ptr [g_cfg_passlen], 0     ; plain entries carry no AES extra field
    je      zef_cx_done
    mov     r11, qword ptr [rbp-160]
    lea     r10, [zip_extrabuf]
    add     r10, r11
    mov     r8, qword ptr [rbp-128]
    xor     r9, r9
zef_cx_cp:
    mov     al, byte ptr [r8+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    cmp     r9, 11
    jb      zef_cx_cp
    add     qword ptr [rbp-160], 11
zef_cx_done:
    lea     r10, [zip_chdr]
    mov     dword ptr [r10+0], SIG_CDIR
    mov     word ptr [r10+4], 002Dh          ; version made by (4.5)
    mov     eax, dword ptr [rbp-168]
    mov     word ptr [r10+6], ax             ; version needed
    cmp     dword ptr [g_cfg_passlen], 0
    je      zef_ch_plain
    mov     word ptr [r10+8], 0801h
    mov     word ptr [r10+10], 99
    mov     dword ptr [r10+16], 0            ; crc-32 = 0
    jmp     zef_ch_common
zef_ch_plain:
    mov     word ptr [r10+8], 0800h          ; UTF-8 name, not encrypted
    mov     eax, dword ptr [rbp-80]          ; method = store (0) / deflate (8)
    mov     word ptr [r10+10], ax
    mov     eax, dword ptr [rbp-176]         ; real crc-32
    mov     dword ptr [r10+16], eax
zef_ch_common:
    mov     word ptr [r10+12], 0
    mov     word ptr [r10+14], 0021h
    mov     eax, dword ptr [rbp-144]
    mov     dword ptr [r10+20], eax          ; csize (or sentinel)
    mov     eax, dword ptr [rbp-136]
    mov     dword ptr [r10+24], eax          ; usize (or sentinel)
    mov     eax, dword ptr [rbp-56]
    mov     word ptr [r10+28], ax            ; name len
    mov     eax, dword ptr [rbp-160]
    mov     word ptr [r10+30], ax            ; extra len
    mov     word ptr [r10+32], 0             ; comment len
    mov     word ptr [r10+34], 0             ; disk start
    mov     word ptr [r10+36], 0             ; internal attrs
    mov     dword ptr [r10+38], 20h          ; external attrs (archive)
    mov     eax, dword ptr [rbp-152]
    mov     dword ptr [r10+42], eax          ; local header offset (or sentinel)
    lea     rcx, [zip_chdr]
    mov     rdx, 46
    call    cw
    lea     rcx, [g_zrel]
    mov     rdx, qword ptr [rbp-56]
    call    cw
    lea     rcx, [zip_extrabuf]
    mov     rdx, qword ptr [rbp-160]
    call    cw
    inc     qword ptr [g_zip_count]
    ; One line in the window's action log per entry.  Beside the count, and for
    ; the same reason: the central-directory record is written, so this entry is
    ; in the archive.  Nothing above this point is committed.  No-op in the CLI.
    lea     rcx, [g_zrel]
    mov     edx, dword ptr [rbp-56]
    call    rlog_added
zef_ret:
    mov     rcx, qword ptr [rbp-24]
    call    file_close
    mov     rcx, qword ptr [rbp-104]         ; free filebuf if allocated
    test    rcx, rcx
    jz      @F
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
@@:
    mov     rcx, qword ptr [rbp-112]         ; free defbuf if allocated
    test    rcx, rcx
    jz      @F
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
@@:
    FRAME_EPILOG
    ret
zef_err:
    mov     qword ptr [g_ziperr], EXIT_IO
    jmp     zef_ret
zip_emit_file endp

; =============================================================================
; zip_node - recurse g_zwalk (full path) / g_zrel (rel name); emit each file.
; =============================================================================
zip_node proc frame
    FRAME_PROLOG 720
    ; finddata at [rsp+64]; [rbp-24]=hfind [rbp-32]=walklen [rbp-40]=rellen
    WINCALL GetFileAttributesW, addr g_zwalk
    cmp     eax, -1
    je      zn_err
    test    eax, FILE_ATTR_DIR
    jz      zn_isfile
    mov     rax, qword ptr [g_zwalklen]
    lea     r10, [g_zwalk]
    mov     word ptr [r10+rax*2], 5Ch
    mov     word ptr [r10+rax*2+2], '*'
    mov     word ptr [r10+rax*2+4], 0
    WINCALL FindFirstFileW, addr g_zwalk, addr rsp+64
    mov     r11, qword ptr [g_zwalklen]
    lea     r10, [g_zwalk]
    mov     word ptr [r10+r11*2], 0
    cmp     rax, -1
    je      zn_ret
    mov     qword ptr [rbp-24], rax
zn_child:
    lea     r10, [rsp+64+FIND_CFILENAME]
    movzx   eax, word ptr [r10]
    cmp     ax, '.'
    jne     zn_do
    movzx   edx, word ptr [r10+2]
    test    dx, dx
    jz      zn_next
    cmp     dx, '.'
    jne     zn_do
    movzx   edx, word ptr [r10+4]
    test    dx, dx
    jz      zn_next
zn_do:
    mov     rax, qword ptr [g_zwalklen]
    mov     qword ptr [rbp-32], rax
    mov     rax, qword ptr [g_zrellen]
    mov     qword ptr [rbp-40], rax
    mov     rax, qword ptr [g_zwalklen]
    lea     r10, [g_zwalk]
    mov     word ptr [r10+rax*2], 5Ch
    inc     rax
    lea     r11, [rsp+64+FIND_CFILENAME]
    xor     r9, r9
zn_wc:
    mov     dx, word ptr [r11+r9*2]
    test    dx, dx
    jz      zn_wcd
    mov     word ptr [r10+rax*2], dx
    inc     rax
    inc     r9
    cmp     rax, 7F00h
    jb      zn_wc
zn_wcd:
    mov     word ptr [r10+rax*2], 0
    mov     qword ptr [g_zwalklen], rax
    WINCALL WideCharToMultiByte, CP_UTF8, 0, addr rsp+64+FIND_CFILENAME, -1, addr g_zchildu8, 1024, 0, 0
    mov     rax, qword ptr [g_zrellen]
    lea     r10, [g_zrel]
    mov     byte ptr [r10+rax], '/'
    inc     rax
    lea     r11, [g_zchildu8]
    xor     r9, r9
zn_rc:
    mov     dl, byte ptr [r11+r9]
    test    dl, dl
    jz      zn_rcd
    mov     byte ptr [r10+rax], dl
    inc     rax
    inc     r9
    cmp     rax, 4000
    jb      zn_rc
zn_rcd:
    mov     byte ptr [r10+rax], 0
    mov     qword ptr [g_zrellen], rax
    call    zip_node
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [g_zwalklen], rax
    lea     r10, [g_zwalk]
    mov     word ptr [r10+rax*2], 0
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_zrellen], rax
    lea     r10, [g_zrel]
    mov     byte ptr [r10+rax], 0
    cmp     qword ptr [g_ziperr], 0
    jne     zn_findclose
zn_next:
    WINCALL FindNextFileW, qword ptr [rbp-24], addr rsp+64
    test    eax, eax
    jnz     zn_child
zn_findclose:
    WINCALL FindClose, qword ptr [rbp-24]
zn_ret:
    FRAME_EPILOG
    ret
zn_isfile:
    call    zip_emit_file
    FRAME_EPILOG
    ret
zn_err:
    mov     qword ptr [g_ziperr], EXIT_IO
    FRAME_EPILOG
    ret
zip_node endp

; zip_input_top(rcx = positional path) - seed g_zwalk/g_zrel then zip_node
zip_input_top proc frame
    FRAME_PROLOG 96
    lea     r10, [g_zwalk]
    xor     r9, r9
zit_c:
    mov     ax, word ptr [rcx+r9*2]
    mov     word ptr [r10+r9*2], ax
    test    ax, ax
    jz      zit_cd
    inc     r9
    cmp     r9, 7F00h
    jb      zit_c
zit_cd:
    mov     qword ptr [g_zwalklen], r9
    xor     r8, r8
    xor     r9, r9
zit_scan:
    movzx   eax, word ptr [r10+r9*2]
    test    eax, eax
    jz      zit_sd
    cmp     eax, 5Ch
    je      zit_sep
    cmp     eax, 2Fh
    jne     zit_sa
zit_sep:
    lea     r8, [r9+1]
zit_sa:
    inc     r9
    jmp     zit_scan
zit_sd:
    lea     rax, [g_zwalk]
    lea     r8, [rax+r8*2]              ; leaf ptr (src)
    mov     qword ptr [rbp-16], r8
    ; Same rule as pack_input_top, deliberately in the same shape: destination
    ; first, leaf after it, children inherit it from g_zrel.
    lea     rcx, [g_zrel]
    call    add_prefix_copy
    mov     r11, rax
    lea     r10, [g_zrel]
    add     r10, r11
    mov     r8, qword ptr [rbp-16]
    neg     r11
    add     r11, 4096
    WINCALL WideCharToMultiByte, CP_UTF8, 0, r8, -1, r10, r11d, 0, 0
    test    eax, eax
    jz      zit_err
    dec     eax
    add     rax, qword ptr [g_add_prefixlen]
    mov     qword ptr [g_zrellen], rax
    cmp     qword ptr [g_add_prefixlen], 0
    je      zit_go
    lea     rcx, [g_zrel]
    call    sanitize_name
    test    eax, eax
    jnz     zit_unsafe
zit_go:
    call    zip_node
    FRAME_EPILOG
    ret
zit_unsafe:
    mov     qword ptr [g_ziperr], EXIT_CORRUPT
    FRAME_EPILOG
    ret
zit_err:
    mov     qword ptr [g_ziperr], EXIT_IO
    FRAME_EPILOG
    ret
zip_input_top endp

; =============================================================================
; do_zip -> eax exit code
; =============================================================================
public do_zip
; =============================================================================
; zip_finish -> eax 0 / EXIT_IO.  Close the central-directory temp, append it at
; the current offset, then write the ZIP64 records and the EOCD.
;
; Shared by do_zip and do_zip_add.  Everything it needs is already in the
; writer's globals - g_zipoff says where the directory lands, g_zip_count and
; g_zip_cdsize describe it - so appending to an archive differs from building
; one only in what those held when the walk started.
;
; The EOCD goes LAST, and for an append that is what makes an interrupted add
; harmless: until this record lands, the archive's original EOCD is still the
; last one in the file and still points at a directory that has not been
; touched, so a reader scanning back from the end finds the archive exactly as
; it was.
;
; locals (frame 96): cdbuf[-40] cdbufsize[-48]
; =============================================================================
zip_finish proc frame
    FRAME_PROLOG 96
    mov     rcx, qword ptr [g_zip_cout]
    call    file_close
    mov     qword ptr [g_zip_cout], INVALID
    mov     rax, qword ptr [g_zipoff]
    mov     qword ptr [g_zip_cdoff], rax
    lea     rcx, [zip_tempc]
    lea     rdx, [rbp-40]
    lea     r8, [rbp-48]
    call    read_file
    test    eax, eax
    jnz     zf_io
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-48]
    call    zw
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
    cmp     qword ptr [g_ziperr], 0
    jne     zf_io
    ; ---- ZIP64 EOCD record + locator when count/offset/size overflow --------
    cmp     qword ptr [g_zip_count], ZIP64_CNT
    jae     zf_need64
    ZTRIG   qword ptr [g_zip_cdoff]
    jae     zf_need64
    ZTRIG   qword ptr [g_zip_cdsize]
    jb      zf_eocd
zf_need64:
    mov     rax, qword ptr [g_zipoff]
    mov     qword ptr [g_zip_z64off], rax
    lea     r10, [zip_z64rec]
    mov     dword ptr [r10+0], SIG_Z64EOCD
    mov     qword ptr [r10+4], 44            ; size of the rest of this record
    mov     word ptr [r10+12], 002Dh         ; version made by (4.5)
    mov     word ptr [r10+14], 002Dh         ; version needed
    mov     dword ptr [r10+16], 0            ; this disk
    mov     dword ptr [r10+20], 0            ; disk with cd start
    mov     rax, qword ptr [g_zip_count]
    mov     qword ptr [r10+24], rax          ; entries on this disk
    mov     qword ptr [r10+32], rax          ; total entries
    mov     rax, qword ptr [g_zip_cdsize]
    mov     qword ptr [r10+40], rax          ; cd size
    mov     rax, qword ptr [g_zip_cdoff]
    mov     qword ptr [r10+48], rax          ; cd offset
    mov     dword ptr [r10+56], SIG_Z64LOC   ; --- locator ---
    mov     dword ptr [r10+60], 0            ; disk with zip64 eocd
    mov     rax, qword ptr [g_zip_z64off]
    mov     qword ptr [r10+64], rax          ; zip64 eocd offset
    mov     dword ptr [r10+72], 1            ; total disks
    lea     rcx, [zip_z64rec]
    mov     rdx, 76
    call    zw
    cmp     qword ptr [g_ziperr], 0
    jne     zf_io
zf_eocd:
    ; EOCD (sentinels where ZIP64 applies)
    lea     r10, [zip_eocd]
    mov     dword ptr [r10+0], SIG_EOCD
    mov     word ptr [r10+4], 0
    mov     word ptr [r10+6], 0
    mov     rax, qword ptr [g_zip_count]
    cmp     rax, 0FFFFh
    jb      @F
    mov     eax, 0FFFFh
@@:
    mov     word ptr [r10+8], ax
    mov     word ptr [r10+10], ax
    mov     rax, qword ptr [g_zip_cdsize]
    ZTRIG   rax
    jb      @F
    mov     eax, ZIP64_SENT
@@:
    mov     dword ptr [r10+12], eax
    mov     rax, qword ptr [g_zip_cdoff]
    ZTRIG   rax
    jb      @F
    mov     eax, ZIP64_SENT
@@:
    mov     dword ptr [r10+16], eax
    mov     word ptr [r10+20], 0
    lea     rcx, [zip_eocd]
    mov     rdx, 22
    call    zw
    cmp     qword ptr [g_ziperr], 0
    jne     zf_io
    xor     eax, eax
    FRAME_EPILOG
    ret
zf_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
zip_finish endp

; =============================================================================
; do_zip_add -> eax exit code.  Append positionals[1..] to the zip named by
; positionals[0], in place.
;
; The new entries and the new directory are written AFTER the archive's existing
; EOCD, and the new EOCD is the last thing written.  A reader locates the
; directory by scanning back from the end of the file for an EOCD, so until that
; final write it still finds the ORIGINAL one, pointing at the ORIGINAL
; directory, which has not been touched - an interrupted add leaves a readable
; archive holding exactly what it held before.  The old directory and EOCD stay
; behind as dead bytes in the middle, a few hundred per add, which no reader
; looks at.
;
; That is the opposite trade from the .mrk path, which has no way to avoid a
; window where the container has no valid trailer.  A zip can be appended to
; safely because its directory is found from the end rather than required to be
; at it.
;
; The existing directory records are copied verbatim into the new one: nothing
; moved, so not one local-header offset needs patching.
;
; locals (frame 96): index[-24] size0[-32] code[-56]
; =============================================================================
public do_zip_add
do_zip_add proc frame
    FRAME_PROLOG 96
    mov     qword ptr [g_zip_hout], INVALID
    mov     qword ptr [g_zip_cout], INVALID
    mov     qword ptr [g_ziperr], 0
    cmp     qword ptr [g_poscount], 2
    jb      dza_usage
    ; ---- read the directory we are extending -------------------------------
    ; The path goes in rcx: zip_read_cd takes it from its caller, as do_unzip
    ; and zip_delete_marked both do.  Passing nothing left it normalising
    ; whatever rcx happened to hold, and the failure came back as a bare exit
    ; code with nothing printed - the verb exited 2 in silence.  Both halves of
    ; that are fixed here.
    mov     rcx, qword ptr [g_cfg_in]
    call    zip_read_cd
    test    eax, eax
    jz      dza_cdok
    lea     rcx, [e_zadd_open]
    mov     edx, e_zadd_open_len
    call    print_a
    jmp     dza_ret0
dza_cdok:
    ; ---- and refuse a password the archive disagrees with ------------------
    cmp     dword ptr [g_cfg_passlen], 0
    je      dza_pwok                         ; adding unencrypted
    call    zip_check_password
    test    eax, eax
    jz      dza_pwok
    cmp     eax, EXIT_AUTH
    je      dza_pwbad
    ; Anything else from the check is a defect in the check, not a verdict on
    ; the password - and it must not exit silently, which is how the missing
    ; rcx above hid for a whole test round.  Refusing is still the right
    ; outcome: nothing has been written and the archive is untouched.
    mov     dword ptr [rbp-56], eax          ; print_a returns into eax
    lea     rcx, [e_zadd_chk]
    mov     edx, e_zadd_chk_len
    call    print_a
    mov     eax, dword ptr [rbp-56]
    jmp     dza_close_in
dza_pwbad:
    lea     rcx, [e_zadd_pw]
    mov     edx, e_zadd_pw_len
    call    print_a
    mov     eax, EXIT_AUTH
    jmp     dza_close_in
dza_pwok:
    mov     rax, qword ptr [g_uz_size]
    mov     qword ptr [rbp-32], rax
    mov     rcx, qword ptr [g_uz_hin]
    call    file_close
    mov     qword ptr [g_uz_hin], INVALID
    ; ---- open for writing and aim the writer at the end --------------------
    lea     rcx, [g_positionals]
    mov     rcx, qword ptr [rcx]
    lea     rdx, [zip_out_np]
    call    normalize_path
    test    eax, eax
    jnz     dza_io0
    lea     rcx, [zip_out_np]
    call    make_temp_path
    call    zip_build_cdtemp
    lea     rcx, [zip_out_np]
    call    file_open_rw
    cmp     rax, INVALID
    je      dza_io0
    mov     qword ptr [g_zip_hout], rax
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-32]
    call    file_seek
    test    eax, eax
    jnz     dza_io
    lea     rcx, [zip_tempc]
    call    file_open_write
    cmp     rax, INVALID
    je      dza_io
    mov     qword ptr [g_zip_cout], rax
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [g_zipoff], rax        ; local offsets carry on from here
    mov     qword ptr [g_zip_cdsize], 0
    mov     qword ptr [g_zip_count], 0
    ; the existing records go into the new directory first, unchanged
    mov     rcx, qword ptr [g_cdbuf]
    mov     rdx, qword ptr [g_cdsize]
    call    cw
    cmp     qword ptr [g_ziperr], 0
    jne     dza_io
    mov     rax, qword ptr [g_cdcount]
    mov     qword ptr [g_zip_count], rax
    ; ---- progress: total the inputs being ADDED, not the archive ------------
    ; positionals[0] is the archive and is not being read, so sum_inputs (which
    ; walks the whole array) would inflate the total by the archive's own size
    ; and leave the bar short of the end.
    mov     qword ptr [rbp-64], 0
    mov     qword ptr [rbp-40], 1
dza_sum:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_poscount]
    jae     dza_sumd
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    call    input_size
    add     qword ptr [rbp-64], rax
    inc     qword ptr [rbp-40]
    jmp     dza_sum
dza_sumd:
    mov     rcx, qword ptr [rbp-64]
    lea     rdx, [lbl_zip]
    mov     r8d, lbl_zip_len
    call    progress_begin
    ; ---- walk the new inputs, exactly as do_zip walks its own --------------
    mov     qword ptr [rbp-24], 1            ; [0] is the archive itself
dza_loop:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     dza_walked
    mov     qword ptr [g_cur_input], rax
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    call    zip_input_top
    cmp     qword ptr [g_ziperr], 0
    jne     dza_io
    ; Between inputs, where the rollback still restores the archive byte for
    ; byte - the whole reason the append starts past the old EOCD.
    cmp     dword ptr [g_prog_abort], 0
    jne     dza_cancelled
    inc     qword ptr [rbp-24]
    jmp     dza_loop
dza_walked:
    call    zip_finish
    test    eax, eax
    jnz     dza_io
    mov     rcx, qword ptr [g_zip_hout]
    call    file_close
    mov     qword ptr [g_zip_hout], INVALID
    lea     rcx, [zip_tempc]
    call    file_delete
    call    progress_done
    lea     rcx, [m_zadd_done]
    mov     edx, m_zadd_done_len
    call    print_a
    xor     eax, eax
    jmp     dza_done
dza_cancelled:
    call    progress_done
    mov     eax, EXIT_CANCELLED
    jmp     dza_done
dza_usage:
    lea     rcx, [e_zadd_usage]
    mov     edx, e_zadd_usage_len
    call    print_a
    mov     eax, EXIT_USAGE
    jmp     dza_ret0
dza_io:
    lea     rcx, [e_zip_io]
    mov     edx, e_zip_io_len
    call    print_a
    mov     eax, EXIT_IO
    jmp     dza_done
dza_io0:
    lea     rcx, [e_zip_io]
    mov     edx, e_zip_io_len
    call    print_a
    mov     eax, EXIT_IO
    jmp     dza_done
dza_close_in:
    mov     dword ptr [rbp-56], eax
    cmp     qword ptr [g_uz_hin], INVALID
    je      @F
    mov     rcx, qword ptr [g_uz_hin]
    call    file_close
    mov     qword ptr [g_uz_hin], INVALID
@@:
    mov     eax, dword ptr [rbp-56]
    jmp     dza_ret0
dza_done:
    mov     dword ptr [rbp-56], eax
    mov     rcx, qword ptr [g_zip_cout]
    call    file_close
    mov     qword ptr [g_zip_cout], INVALID
    lea     rcx, [zip_tempc]
    call    file_delete
    cmp     dword ptr [rbp-56], 0
    je      @F
    ; Put the length back.  Nothing at or below it was written, so the archive
    ; is the one we opened - the whole reason the append starts past the EOCD.
    cmp     qword ptr [g_zip_hout], INVALID
    je      @F
    mov     rcx, qword ptr [g_zip_hout]
    mov     rdx, qword ptr [rbp-32]
    call    file_truncate
@@:
    mov     rcx, qword ptr [g_zip_hout]
    call    file_close
    mov     qword ptr [g_zip_hout], INVALID
    mov     eax, dword ptr [rbp-56]
dza_ret0:
    call    zip_wipe_keys                    ; preserves eax; see the proc
    FRAME_EPILOG
    ret
do_zip_add endp

; =============================================================================
; zip_wipe_keys - the writer's copy of unzip.asm's uz_wipe_keys, for the same
; reason: PBKDF2 output, round keys, HMAC pads and keyed SHA-1 state are
; derived from the master password and were living in .data? until process
; exit.  Raw prologue: callers arrive with the exit code in eax and
; FRAME_PROLOG plants the canary through rax.
; =============================================================================
zip_wipe_keys proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    lea     rcx, [zip_keys]
    mov     rdx, 72
    call    secure_zero
    lea     rcx, [zip_rk]
    mov     rdx, 240
    call    secure_zero
    lea     rcx, [zip_ipad]
    mov     rdx, 64
    call    secure_zero
    lea     rcx, [zip_opad]
    mov     rdx, 64
    call    secure_zero
    lea     rcx, [zip_sctx]
    mov     rdx, SHA1_CTX_SIZE
    call    secure_zero
    add     rsp, 48
    pop     rbp
    ret
zip_wipe_keys endp

do_zip proc frame
    FRAME_PROLOG 96
    mov     qword ptr [g_add_prefixlen], 0   ; a fresh zip has no folder to land in
    ; [rbp-24]=index [rbp-32]=total [rbp-40]=cdbuf [rbp-48]=cdbufsize [rbp-56]=code
    mov     qword ptr [g_zip_hout], INVALID
    mov     qword ptr [g_zip_cout], INVALID
    mov     qword ptr [g_ziperr], 0
    cmp     qword ptr [g_cfg_out], 0
    jne     dz_haveout
    lea     rcx, [e_zip_noout]
    mov     edx, e_zip_noout_len
    call    print_a
    mov     eax, EXIT_USAGE
    jmp     dz_ret0
dz_haveout:
    cmp     dword ptr [g_cfg_passlen], 0
    je      dz_polok                         ; no password -> unencrypted zip (no policy)
    call    check_password_policy
    test    eax, eax
    jz      dz_polok
    call    print_policy_error
    mov     eax, EXIT_USAGE
    jmp     dz_ret0
dz_polok:
    mov     rcx, qword ptr [g_cfg_out]
    lea     rdx, [zip_out_np]
    call    normalize_path
    test    eax, eax
    jnz     dz_io0
    ; sum input sizes (progress + disk pre-flight)
    mov     qword ptr [rbp-32], 0
    mov     qword ptr [rbp-24], 0
dz_sum:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     dz_sumd
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    call    input_size
    add     qword ptr [rbp-32], rax
    ; record this input's size for the GUI per-file progress bar
    mov     r9, qword ptr [rbp-24]
    cmp     r9, MAX_ARGS
    jae     dz_sum_nofile
    lea     r11, [g_file_total]
    mov     qword ptr [r11+r9*8], rax
dz_sum_nofile:
    inc     qword ptr [rbp-24]
    jmp     dz_sum
dz_sumd:
    lea     rcx, [zip_out_np]
    mov     rdx, qword ptr [rbp-32]
    add     rdx, DISK_MARGIN
    call    disk_has_space
    cmp     eax, 1
    je      dz_nospace
    ; temp files: main = OUTPUT.tmp ; cd = OUTPUT.tmp + 'c'
    lea     rcx, [zip_out_np]
    call    make_temp_path
    call    zip_build_cdtemp
    lea     rcx, [g_temppath]
    call    file_open_write
    cmp     rax, INVALID
    je      dz_io0
    mov     qword ptr [g_zip_hout], rax
    lea     rcx, [zip_tempc]
    call    file_open_write
    cmp     rax, INVALID
    je      dz_io
    mov     qword ptr [g_zip_cout], rax
    mov     qword ptr [g_zipoff], 0
    mov     qword ptr [g_zip_cdsize], 0
    mov     qword ptr [g_zip_count], 0
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [lbl_zip]
    mov     r8d, lbl_zip_len
    call    progress_begin
    ; walk inputs
    mov     qword ptr [rbp-24], 0
dz_loop:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     dz_walkdone
    mov     qword ptr [g_cur_input], rax
    mov     rcx, rax                        ; where this input lands
    call    pfx_select
    mov     rax, qword ptr [rbp-24]
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    call    zip_input_top
    cmp     qword ptr [g_ziperr], 0
    jne     dz_emitfail
    inc     qword ptr [rbp-24]
    jmp     dz_loop
dz_walkdone:
    ; the directory, the ZIP64 records and the EOCD - shared with do_zip_add
    call    zip_finish
    test    eax, eax
    jnz     dz_io
    mov     rcx, qword ptr [g_zip_hout]
    call    file_close
    mov     qword ptr [g_zip_hout], INVALID
    lea     rcx, [g_temppath]
    lea     rdx, [zip_out_np]
    call    file_rename
    test    eax, eax
    jnz     dz_io
    lea     rcx, [zip_tempc]
    call    file_delete
    call    progress_done
    lea     rcx, [m_zip_done]
    mov     edx, m_zip_done_len
    call    print_a
    mov     rcx, qword ptr [g_zip_count]
    call    print_u64
    lea     rcx, [m_zip_done2]
    mov     edx, m_zip_done2_len
    call    print_a
    mov     rcx, qword ptr [g_cfg_out]
    call    print_wz
    lea     rcx, [m_nl]
    mov     edx, 2
    call    print_a
    xor     eax, eax
    jmp     dz_done
dz_emitfail:
    call    progress_done
    jmp     dz_io
dz_nospace:
    lea     rcx, [e_zip_space]
    mov     edx, e_zip_space_len
    call    print_a
    mov     eax, EXIT_NOSPACE
    jmp     dz_ret0
dz_io:
    call    progress_done
dz_io0:
    lea     rcx, [e_zip_io]
    mov     edx, e_zip_io_len
    call    print_a
    mov     eax, EXIT_IO
dz_done:
    mov     dword ptr [rbp-56], eax
    mov     rcx, qword ptr [g_zip_cout]
    call    file_close
    mov     rcx, qword ptr [g_zip_hout]
    call    file_close
    cmp     dword ptr [rbp-56], 0
    je      dz_okret
    lea     rcx, [g_temppath]
    call    file_delete
    lea     rcx, [zip_tempc]
    call    file_delete
dz_okret:
    mov     eax, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
dz_ret0:
    FRAME_EPILOG
    ret
do_zip endp

; zip_build_cdtemp - zip_tempc = g_temppath + 'c'
zip_build_cdtemp proc
    lea     r10, [g_temppath]
    lea     r11, [zip_tempc]
    xor     r9, r9
zbc_c:
    mov     ax, word ptr [r10+r9*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      zbc_d
    inc     r9
    cmp     r9, 7FF0h
    jb      zbc_c
zbc_d:
    mov     word ptr [r11+r9*2], 'c'
    inc     r9
    mov     word ptr [r11+r9*2], 0
    ret
zip_build_cdtemp endp

end
