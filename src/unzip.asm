; =============================================================================
; unzip.asm - encrypted-ZIP (WinZip AES) extractor, STREAMING.
; -----------------------------------------------------------------------------
; Extracts standard ZIP archives whose entries are encrypted with WinZip AES
; (AES-128/192/256; method 99, AES extra 0x9901, AE-1/AE-2), as produced by
; 7-Zip / WinRAR / WinZip.  Per entry:
;
;   key = PBKDF2-HMAC-SHA1(password, salt, 1000, 2*K+2)
;         -> aesKey[K] || macKey[K] || pwVerify[2]
;   verify pwVerify, then HMAC-SHA1(macKey, ciphertext)[0..9] == auth tag
;         (encrypt-then-MAC: authenticate BEFORE trusting plaintext)
;   plaintext = AES-CTR(aesKey, ciphertext)
;   data      = plaintext (stored) or inflate(plaintext) (deflate)
;
; Memory is BOUNDED, independent of archive size: only the central directory is
; held in memory (cap CD_CAP); the archive is read via positioned reads
; (file_read_at).  STORED entries stream the ciphertext in CHUNK pieces through
; AES-CTR + a streaming HMAC into OUTPUT.part, then verify the tag and rename
; (temp-then-rename, so unauthenticated plaintext is never exposed as the real
; output).  DEFLATE entries are held in memory up to DEFLATE_RD_CAP (our inflate
; is whole-buffer); larger ones are refused with a clear message.  ZIP64 is
; supported.  Unencrypted store/deflate entries are extracted as a convenience;
; legacy ZipCrypto is refused.  Names are sanitised (no absolute/drive/.. paths).
;
;   do_unzip -> eax exit code
; =============================================================================

include macros.inc

extern normalize_path:proc
extern mem_free:proc
extern mem_alloc:proc
extern file_open_read:proc
extern file_open_write:proc
extern file_open_rw:proc
extern file_seek:proc
extern rng_fill:proc
extern file_write_all:proc
extern file_read_exact:proc
extern file_read_at:proc
extern file_close:proc
extern file_rename:proc
extern file_delete:proc
extern get_file_size:proc
extern sanitize_name:proc
extern create_parents:proc
extern build_extract_path:proc
extern pbkdf2_hmac_sha1:proc
extern hmac_sha1:proc
extern sha1_init:proc
extern sha1_update:proc
extern sha1_final:proc
extern aes_expand_key:proc
extern aes_ctr_xor:proc
extern inflate:proc
extern crc32_update:proc
extern ct_memcmp:proc
extern print_a:proc
extern print_u64:proc
extern secure_zero:proc
extern progress_begin:proc
extern progress_add:proc
extern rlog_extracted:proc              ; ramlog.asm: one line per entry
extern progress_done:proc

extern CreateDirectoryW:proc
extern FlushFileBuffers:proc
extern MultiByteToWideChar:proc
extern idx_find:proc
extern idx_buf_ensure:proc                ; pack.asm: allocates the inventory buffer
extern idx_buf_commit:proc                ; pack.asm: makes that much of it writable
extern pick_has:proc
externdef g_pick_active:dword

externdef g_idxptr:qword
externdef g_idxlen:qword
externdef g_idxcount:qword
externdef g_idxflags:qword
externdef g_cfg_in:qword
externdef g_cfg_out:qword
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_namew:word
externdef g_extw:word
externdef g_outdir_np:word

INVALID         equ -1
CP_UTF8         equ 65001
CHUNK           equ 100000h     ; 1 MiB streaming buffer
CD_CAP          equ 10000000h   ; 256 MiB central-directory cap (~3M entries)
DEFLATE_RD_CAP  equ 20000000h   ; 512 MiB: larger deflate entries are refused
TAILSIZE        equ 66000       ; >= 22 + 65535 comment + zip64 locator
SIG_EOCD        equ 06054B50h
SIG_CDIR        equ 02014B50h
SIG_LOCAL       equ 04034B50h
SIG_Z64EOCD     equ 06064B50h
SIG_Z64LOC      equ 07064B50h
ZD_NAME_MAX     equ 4096        ; longest entry name zip_delete_marked will judge
MEMSINK         equ -2          ; the "handle" uz_sink_open returns in memory mode

.const
CSTR e_uz_badzip, "myrkr: not a valid ZIP archive",13,10
CSTR e_uz_io,     "myrkr: I/O error reading the archive",13,10
CSTR e_uz_oom,    "myrkr: out of memory",13,10
CSTR e_uz_auth,   "myrkr: wrong password or tampered entry",13,10
CSTR e_uz_unsup,  "myrkr: unsupported entry (only WinZip AES + store/deflate)",13,10
CSTR e_uz_zcrypto,"myrkr: legacy ZipCrypto entries are not supported",13,10
CSTR e_uz_name,   "myrkr: unsafe entry name rejected",13,10
CSTR e_uz_corrupt,"myrkr: corrupt ZIP structure",13,10
CSTR e_uz_big,    "myrkr: deflate entry too large to extract (use 7-Zip/WinRAR)",13,10
CSTR e_uz_needpw, "myrkr: this archive is encrypted; supply a password with -p",13,10
CSTR m_uz_done,   "extracted "
CSTR m_uz_done2,  " file(s)",13,10
CSTR lbl_unzip,   "extracting"
w_ext_zip   dw '.','z','i','p',0
w_ext_part  dw '.','p','a','r','t',0
w_ext_tmp   dw '.','m','r','k','t','m','p',0

.data?
g_uz_hin    dq ?
g_uz_size   dq ?
g_cdbuf     dq ?
g_cdsize    dq ?
g_cdcount   dq ?            ; central-directory entry count
g_cdoff     dq ?            ; where that directory starts in the file
g_uz_mem    dq ?            ; non-zero = extract into memory here, not to a file
g_uz_memcap dq ?            ; how much room that buffer has
g_uz_memlen dq ?            ; how much of it extract_zip_entry has filled
uz_in_np    dw 8000h dup (?)
uz_dflt     dw 8000h dup (?)
uz_partpath dw 8010h dup (?)
uz_name8    db 4096 dup (?)
uz_tail     db TAILSIZE dup (?)
uz_lhbuf    db 64  dup (?)
uz_saltbuf  db 32  dup (?)
zcp_lochdr  db 32  dup (?)      ; a local header, for the password check
uz_keys     db 72  dup (?)
uz_rk       db 240 dup (?)
uz_ctr      db 16  dup (?)
uz_ipad     db 64  dup (?)
uz_opad     db 64  dup (?)
uz_sctx     db SHA1_CTX_SIZE dup (?)
uz_inner    db 20  dup (?)
uz_mac      db 20  dup (?)
uz_tag      db 16  dup (?)
uz_count    dq ?
uz_aesver   dq ?
uz_strength dq ?
uz_realm    dq ?
uz_aesfound dq ?
uz_tmppath  dw 8010h dup (?)        ; the rewrite's destination, until it is renamed
zd_name8    db ZD_NAME_MAX dup (?)  ; one entry name, normalised, for the lookup
zd_eocd     db 22 dup (?)           ; the end-of-central-directory record we write
align 16
uz_chunk    db CHUNK dup (?)

.code

; =============================================================================
; uz_find_aes(rcx = extra ptr, rdx = extra len) - scan for the AES extra (0x9901)
; -> sets uz_aesfound/uz_aesver/uz_strength/uz_realm
; =============================================================================
uz_find_aes proc frame
    FRAME_PROLOG 48
    mov     qword ptr [uz_aesfound], 0
    xor     r9, r9
ufa_loop:
    mov     r10, r9
    add     r10, 4
    cmp     r10, rdx
    ja      ufa_done
    movzx   eax, word ptr [rcx+r9]
    movzx   r11d, word ptr [rcx+r9+2]
    cmp     eax, 9901h
    jne     ufa_next
    ; the body read below needs 7 more bytes; a truncated record must not
    ; hand back whatever happens to sit past the extra field
    lea     r10, [r9+11]
    cmp     r10, rdx
    ja      ufa_done
    movzx   eax, word ptr [rcx+r9+4]
    mov     qword ptr [uz_aesver], rax
    movzx   eax, byte ptr [rcx+r9+8]
    mov     qword ptr [uz_strength], rax
    movzx   eax, word ptr [rcx+r9+9]
    mov     qword ptr [uz_realm], rax
    mov     qword ptr [uz_aesfound], 1
    jmp     ufa_done
ufa_next:
    add     r9, 4
    add     r9, r11
    jmp     ufa_loop
ufa_done:
    FRAME_EPILOG
    ret
uz_find_aes endp

; =============================================================================
; uz_wipe_keys - the password-derived material this module leaves in globals:
; the PBKDF2 output, the expanded round keys, the HMAC pads and the keyed
; SHA-1 state.  Re-derived per archive; they die with the operation.  Raw
; prologue on purpose: the exit funnels call this with the exit code already
; in eax, and FRAME_PROLOG plants the canary through rax.
; =============================================================================
uz_wipe_keys proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    lea     rcx, [uz_keys]
    mov     rdx, 72
    call    secure_zero
    lea     rcx, [uz_rk]
    mov     rdx, 240
    call    secure_zero
    lea     rcx, [uz_ipad]
    mov     rdx, 64
    call    secure_zero
    lea     rcx, [uz_opad]
    mov     rdx, 64
    call    secure_zero
    lea     rcx, [uz_sctx]
    mov     rdx, SHA1_CTX_SIZE
    call    secure_zero
    add     rsp, 48
    pop     rbp
    ret
uz_wipe_keys endp

; helper: UTF-8 uz_name8 -> UTF-16 g_namew.  -> eax 0 ok / 1 fail
eze_make_wide proc frame
    FRAME_PROLOG 48
    WINCALL MultiByteToWideChar, CP_UTF8, 0, addr uz_name8, -1, addr g_namew, 4096
    test    eax, eax
    jz      emw_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
emw_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
eze_make_wide endp

; uz_build_part - uz_partpath = g_extw + ".part"
uz_build_part proc
    lea     r10, [g_extw]
    lea     r11, [uz_partpath]
    xor     r9, r9
ubp_c:
    mov     ax, word ptr [r10+r9*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      ubp_d
    inc     r9
    cmp     r9, 7FF0h
    jb      ubp_c
ubp_d:
    lea     r10, [w_ext_part]
    xor     r8, r8
ubp_e:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      ubp_done
    inc     r9
    inc     r8
    jmp     ubp_e
ubp_done:
    ret
uz_build_part endp

; =============================================================================
; The memory sink.
;
; extract_zip_entry is the ONLY WinZip-AES reader in this program and it is
; going to stay the only one, so a drag-out that needs an entry's bytes in
; memory diverts this reader rather than growing a second.  Setting g_uz_mem
; redirects the three places it produces output; everything before them - the
; key derivation, the HMAC, the CTR, the CRC, the ZIP64 fixups - is untouched
; and unaware.
;
; The safety argument is the one temp-then-rename already makes.  Nothing is
; handed to the caller until the entry has passed its tag: eze_aes_store still
; verifies AFTER the last chunk, and on failure zip_entry_to_mem frees the
; buffer with the wipe on.  The buffer IS the .part file.
;
; Note what does NOT protect these bytes: the HMAC covers ciphertext and the
; CRC is taken before the sink, so a copy bug here is caught by nothing and
; would hand the shell the wrong bytes.  That is why the copy below is a plain
; byte loop with one bound - there is no tail case to get wrong.
; =============================================================================

; uz_mem_take(rcx = ptr, rdx = len) -> eax 0 / EXIT_IO if it would not fit
uz_mem_take proc
    mov     rax, qword ptr [g_uz_memlen]
    add     rax, rdx
    jc      umt_full                        ; length overflow is a refusal too
    cmp     rax, qword ptr [g_uz_memcap]
    ja      umt_full
    mov     r10, qword ptr [g_uz_mem]
    add     r10, qword ptr [g_uz_memlen]
    xor     r9, r9
umt_copy:
    cmp     r9, rdx
    jae     umt_done
    mov     r8b, byte ptr [rcx+r9]
    mov     byte ptr [r10+r9], r8b
    inc     r9
    jmp     umt_copy
umt_done:
    mov     qword ptr [g_uz_memlen], rax
    xor     eax, eax
    ret
umt_full:
    mov     eax, EXIT_IO
    ret
uz_mem_take endp

; uz_sink_open(rcx = wide path to open) -> rax = handle / MEMSINK / INVALID
uz_sink_open proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_uz_mem], 0
    je      uso_file
    mov     qword ptr [g_uz_memlen], 0
    mov     rax, MEMSINK
    FRAME_EPILOG
    ret
uso_file:
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [g_extw]
    call    create_parents
    mov     rcx, qword ptr [rbp-24]
    call    file_open_write
    FRAME_EPILOG
    ret
uz_sink_open endp

; uz_sink_write(rcx = handle, rdx = ptr, r8 = len) -> eax 0 / EXIT_IO
uz_sink_write proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_uz_mem], 0
    je      usw_file
    mov     rcx, rdx
    mov     rdx, r8
    call    uz_mem_take
    FRAME_EPILOG
    ret
usw_file:
    call    file_write_all
    FRAME_EPILOG
    ret
uz_sink_write endp

; uz_sink_close(rcx = handle) - tolerates INVALID and MEMSINK, so every exit
; path can call it without first working out which kind of sink was open.
uz_sink_close proc frame
    FRAME_PROLOG 48
    cmp     rcx, INVALID
    je      usc_ret
    cmp     rcx, MEMSINK
    je      usc_ret
    call    file_close
usc_ret:
    FRAME_EPILOG
    ret
uz_sink_close endp

; uz_sink_discard(rcx = handle) - close and throw the partial output away.  In
; memory mode there is no .part on disk to delete, and deleting one anyway
; would remove a leftover from some earlier real extraction.
uz_sink_discard proc frame
    FRAME_PROLOG 48
    call    uz_sink_close
    cmp     qword ptr [g_uz_mem], 0
    jne     usd_ret
    lea     rcx, [uz_partpath]
    call    file_delete
usd_ret:
    FRAME_EPILOG
    ret
uz_sink_discard endp

; uz_write_file(rcx=ptr, rdx=len) - write a buffer to g_extw (creating dirs).
uz_write_file proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_uz_mem], 0
    je      uw_file
    mov     qword ptr [g_uz_memlen], 0
    call    uz_mem_take
    FRAME_EPILOG
    ret
uw_file:
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], INVALID
    lea     rcx, [g_extw]
    call    create_parents
    lea     rcx, [g_extw]
    call    file_open_write
    cmp     rax, INVALID
    je      uw_io
    mov     qword ptr [rbp-40], rax
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    file_write_all
    test    eax, eax
    jnz     uw_io
    mov     rcx, qword ptr [rbp-40]
    call    file_close
    xor     eax, eax
    FRAME_EPILOG
    ret
uw_io:
    mov     rcx, qword ptr [rbp-40]
    call    file_close
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
uz_write_file endp

; =============================================================================
; extract_zip_entry(rcx = central-dir header pointer in g_cdbuf) -> eax 0 / code
; =============================================================================
; =============================================================================
; uz_entry_done - one entry is out, whole and verified.  Counts it, and gives the
; window's action log its line.
;
; A proc and not three copies of two instructions: extract_zip_entry has THREE
; output paths (AES-stored via a .part rename, plain stored, and deflate), each
; ending in the same "that one is done" moment, and the next one added would
; have been the one that forgot the line.  The count was already duplicated
; three ways; this stops the pair drifting apart.
;
; Called only where the entry is COMMITTED - after the authentication tag or the
; CRC has been checked and the bytes are on disk.  A name logged from anywhere
; earlier would be claiming an extraction that had not happened yet.
; =============================================================================
uz_entry_done proc frame
    FRAME_PROLOG 48
    inc     qword ptr [uz_count]
    lea     rcx, [uz_name8]
    xor     edx, edx                         ; NUL-terminated: measure it there
    call    rlog_extracted
    FRAME_EPILOG
    ret
uz_entry_done endp

extract_zip_entry proc frame
    FRAME_PROLOG 320
    ; [rbp-24]=chptr [rbp-32]=csize [rbp-40]=usize [rbp-48]=lho [rbp-56]=ctlen
    ; [rbp-64]=method [rbp-72]=flag [rbp-80]=crc_exp [rbp-88]=effmethod [rbp-96]=nlen
    ; [rbp-104]=keylen [rbp-112]=saltlen [rbp-120]=Nr [rbp-128]=dataoff
    ; [rbp-136]=hpart [rbp-144]=remaining [rbp-152]=outbuf [rbp-160]=defin
    ; [rbp-168]=crc_run [rbp-176]=needcrc [rbp-184]=retcode [rbp-192]=chunklen
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-136], INVALID
    mov     qword ptr [rbp-152], 0
    mov     qword ptr [rbp-160], 0
    movzx   eax, word ptr [rcx+8]
    mov     qword ptr [rbp-72], rax          ; flag
    movzx   eax, word ptr [rcx+10]
    mov     qword ptr [rbp-64], rax          ; method
    mov     eax, dword ptr [rcx+16]
    mov     qword ptr [rbp-80], rax          ; crc-32
    mov     eax, dword ptr [rcx+20]
    mov     qword ptr [rbp-32], rax          ; csize
    mov     eax, dword ptr [rcx+24]
    mov     qword ptr [rbp-40], rax          ; usize
    movzx   eax, word ptr [rcx+28]
    mov     qword ptr [rbp-96], rax          ; name len
    movzx   r8d, word ptr [rcx+30]           ; extra len
    mov     eax, dword ptr [rcx+42]
    mov     qword ptr [rbp-48], rax          ; local header offset
    ; ---- the name AND the extra must lie inside the buffer that was read -----
    ; The caller (do_unzip's walk) bounds the fixed 46 bytes, but not these two
    ; lengths - and the extra pointer below is ch+46+nlen, read by uz_find_aes
    ; and the ZIP64 loop with no further check.  A corrupted CD filename-length
    ; (the field at +28) then aims that pointer past g_cdbuf.  zip_to_index and
    ; zip_check_password already bound exactly this (`ch+46+nlen <= g_cdsize`);
    ; the extract path did not, and a malformed zip read off the end of the
    ; central directory - a crash the release build only escaped by heap luck.
    ; Extra is included because it is dereferenced too; a read, but still OOB.
    mov     r11, rcx
    add     r11, 46
    add     r11, qword ptr [rbp-96]          ; ch+46+nlen
    add     r11, r8                          ; + extralen = end of this record
    mov     r10, qword ptr [g_cdbuf]
    add     r10, qword ptr [g_cdsize]        ; one past the directory buffer
    cmp     r11, r10
    ja      eze_corrupt
    ; ---- AES + ZIP64 extra fixups ------------------------------------------
    mov     r11, rcx
    add     r11, 46
    add     r11, qword ptr [rbp-96]          ; extra ptr = ch+46+nlen
    mov     qword ptr [rbp-200], r11
    mov     qword ptr [rbp-208], r8          ; extra len
    mov     rcx, r11
    mov     rdx, r8
    call    uz_find_aes
    mov     rcx, qword ptr [rbp-200]
    mov     rdx, qword ptr [rbp-208]
    xor     r9, r9
z64_loop:
    mov     r10, r9
    add     r10, 4
    cmp     r10, rdx
    ja      z64_done
    movzx   eax, word ptr [rcx+r9]
    movzx   r8d, word ptr [rcx+r9+2]
    cmp     eax, 1
    jne     z64_next
    lea     r11, [rcx+r9+4]
    xor     r8, r8
    cmp     dword ptr [rbp-40], 0FFFFFFFFh
    jne     @F
    mov     rax, qword ptr [r11+r8]
    mov     qword ptr [rbp-40], rax
    add     r8, 8
@@:
    cmp     dword ptr [rbp-32], 0FFFFFFFFh
    jne     @F
    mov     rax, qword ptr [r11+r8]
    mov     qword ptr [rbp-32], rax
    add     r8, 8
@@:
    cmp     dword ptr [rbp-48], 0FFFFFFFFh
    jne     z64_done
    mov     rax, qword ptr [r11+r8]
    mov     qword ptr [rbp-48], rax
    jmp     z64_done
z64_next:
    add     r9, 4
    add     r9, r8
    jmp     z64_loop
z64_done:
    ; ---- copy entry name (UTF-8) -> uz_name8 -------------------------------
    mov     r10, qword ptr [rbp-24]
    add     r10, 46
    mov     r8, qword ptr [rbp-96]
    cmp     r8, 4094
    jbe     @F
    mov     r8, 4094
@@:
    lea     r11, [uz_name8]
    xor     r9, r9
ne_cpy:
    cmp     r9, r8
    jae     ne_cpd
    mov     al, byte ptr [r10+r9]
    mov     byte ptr [r11+r9], al
    inc     r9
    jmp     ne_cpy
ne_cpd:
    mov     byte ptr [r11+r9], 0
    test    r9, r9
    jz      eze_skip
    cmp     byte ptr [r11+r9-1], '/'
    jne     eze_file
    ; ---- directory entry ---------------------------------------------------
    lea     rcx, [uz_name8]
    call    sanitize_name
    test    eax, eax
    jnz     eze_unsafe
    call    eze_make_wide
    test    eax, eax
    jnz     eze_corrupt
    call    build_extract_path
    cmp     qword ptr [g_uz_mem], 0     ; a folder has no bytes to hand back, and
    jne     eze_skip                    ; making one on disk is not what was asked
    lea     rcx, [g_extw]
    call    create_parents
    WINCALL CreateDirectoryW, addr g_extw, 0
    xor     eax, eax
    jmp     eze_ret
eze_file:
    lea     rcx, [uz_name8]
    call    sanitize_name
    test    eax, eax
    jnz     eze_unsafe
    call    eze_make_wide
    test    eax, eax
    jnz     eze_corrupt
    call    build_extract_path
    ; ---- read the local header to find the data offset ---------------------
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-48]          ; lho
    lea     r8, [uz_lhbuf]
    mov     r9, 30
    call    file_read_at
    test    eax, eax
    jnz     eze_io
    lea     r10, [uz_lhbuf]
    cmp     dword ptr [r10], SIG_LOCAL
    jne     eze_corrupt
    movzx   r8d, word ptr [r10+26]           ; local name len
    movzx   r9d, word ptr [r10+28]           ; local extra len
    mov     rax, qword ptr [rbp-48]
    add     rax, 30
    add     rax, r8
    add     rax, r9
    mov     qword ptr [rbp-128], rax         ; data offset
    ; ---- compute CRC-need (AE-1 or unencrypted) ----------------------------
    mov     qword ptr [rbp-176], 0
    mov     rax, qword ptr [rbp-64]
    cmp     rax, 99
    jne     ezf_needcrc                      ; unencrypted -> real CRC
    cmp     qword ptr [uz_aesver], 1
    jne     ezf_crcdone                      ; AE-2: CRC field is 0
ezf_needcrc:
    mov     qword ptr [rbp-176], 1
ezf_crcdone:
    mov     qword ptr [rbp-168], 0           ; crc running = 0
    ; ---- dispatch ----------------------------------------------------------
    mov     rax, qword ptr [rbp-64]
    cmp     rax, 99
    je      eze_aes
    ; unencrypted entry
    mov     rax, qword ptr [rbp-72]
    test    rax, 1
    jnz     eze_zcrypto
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [rbp-88], rax          ; effmethod = method
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-56], rax          ; ctlen = csize (no crypto overhead)
    ; data starts at dataoff; no salt, no key
    cmp     qword ptr [rbp-88], 0
    je      eze_plain_store
    jmp     eze_deflate                      ; unencrypted deflate
eze_aes:
    cmp     qword ptr [uz_aesfound], 0
    je      eze_unsup
    cmp     dword ptr [g_cfg_passlen], 0     ; encrypted entry but no password
    je      eze_needpw
    mov     rax, qword ptr [uz_strength]
    cmp     rax, 1
    jb      eze_unsup
    cmp     rax, 3
    ja      eze_unsup
    inc     rax
    shl     rax, 3                           ; keylen = 8*(strength+1)
    mov     qword ptr [rbp-104], rax
    shr     rax, 1
    mov     qword ptr [rbp-112], rax         ; saltlen
    mov     rax, qword ptr [uz_realm]
    mov     qword ptr [rbp-88], rax          ; effmethod
    ; ctlen = csize - saltlen - 2 - 10
    mov     rax, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-112]
    add     rdx, 12
    cmp     rax, rdx
    jb      eze_corrupt
    sub     rax, rdx
    mov     qword ptr [rbp-56], rax          ; ctlen
    ; read salt + pwVerify from the data offset
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-128]
    lea     r8, [uz_saltbuf]
    mov     r9, qword ptr [rbp-112]
    add     r9, 2
    call    file_read_at
    test    eax, eax
    jnz     eze_io
    ; derive key
    mov     rax, qword ptr [rbp-104]
    add     rax, rax
    add     rax, 2
    mov     qword ptr [rsp+32], 1000
    lea     rdx, [uz_keys]
    mov     qword ptr [rsp+40], rdx
    mov     qword ptr [rsp+48], rax
    lea     rcx, [g_cfg_pass]
    mov     edx, dword ptr [g_cfg_passlen]
    lea     r8, [uz_saltbuf]
    mov     r9, qword ptr [rbp-112]
    call    pbkdf2_hmac_sha1
    ; pwVerify: uz_keys[2K] == uz_saltbuf[saltlen]
    mov     rax, qword ptr [rbp-104]
    add     rax, rax
    lea     rcx, [uz_keys]
    add     rcx, rax
    lea     rdx, [uz_saltbuf]
    add     rdx, qword ptr [rbp-112]
    mov     r8, 2
    call    ct_memcmp
    test    eax, eax
    jnz     eze_auth
    ; expand AES key
    lea     rcx, [uz_keys]
    mov     rdx, qword ptr [rbp-104]
    lea     r8, [uz_rk]
    call    aes_expand_key
    mov     qword ptr [rbp-120], rax         ; Nr
    ; dispatch on real method
    cmp     qword ptr [rbp-88], 0
    je      eze_aes_store
    cmp     qword ptr [rbp-88], 8
    jne     eze_unsup
    jmp     eze_deflate
; =============================================================================
; eze_aes_store - stream the AES-stored ciphertext: HMAC + CTR + CRC into
; OUTPUT.part, verify the tag, then rename.  (file pointer is at ct start.)
; =============================================================================
eze_aes_store:
    ; build ipad/opad from macKey (uz_keys[keylen .. 2K-1])
    lea     r8, [uz_keys]
    add     r8, qword ptr [rbp-104]          ; macKey
    lea     r10, [uz_ipad]
    lea     r11, [uz_opad]
    xor     r9, r9
eas_pad:
    cmp     r9, 64
    jae     eas_padd
    xor     eax, eax
    cmp     r9, qword ptr [rbp-104]
    jae     @F
    movzx   eax, byte ptr [r8+r9]
@@:
    mov     edx, eax
    xor     edx, 36h
    mov     byte ptr [r10+r9], dl
    xor     eax, 5Ch
    mov     byte ptr [r11+r9], al
    inc     r9
    jmp     eas_pad
eas_padd:
    lea     rcx, [uz_sctx]
    call    sha1_init
    lea     rcx, [uz_sctx]
    lea     rdx, [uz_ipad]
    mov     r8, 64
    call    sha1_update
    lea     rcx, [uz_ctr]
    mov     rdx, 16
    call    secure_zero
    ; open OUTPUT.part
    call    uz_build_part
    lea     rcx, [uz_partpath]
    call    uz_sink_open
    cmp     rax, INVALID
    je      eze_io
    mov     qword ptr [rbp-136], rax
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [rbp-144], rax         ; remaining = ctlen
    xWHILE qword ptr [rbp-144], ne, 0        ; while ciphertext remains
        mov     r8, qword ptr [rbp-144]
        xIF r8, a, CHUNK
            mov     r8, CHUNK
        xENDIF
        mov     qword ptr [rbp-192], r8
        mov     rcx, qword ptr [g_uz_hin]
        lea     rdx, [uz_chunk]
        call    file_read_exact              ; ciphertext chunk (sequential)
        test    eax, eax
        jnz     eze_io_part
        lea     rcx, [uz_sctx]               ; HMAC over ciphertext
        lea     rdx, [uz_chunk]
        mov     r8, qword ptr [rbp-192]
        call    sha1_update
        mov     rax, qword ptr [rbp-120]     ; AES-CTR decrypt in place
        mov     qword ptr [rsp+32], rax
        lea     rcx, [uz_rk]
        lea     rdx, [uz_chunk]
        mov     r8, qword ptr [rbp-192]
        lea     r9, [uz_ctr]
        call    aes_ctr_xor
        xIF qword ptr [rbp-176], ne, 0       ; CRC over plaintext (AE-1)
            mov     rcx, qword ptr [rbp-168]
            lea     rdx, [uz_chunk]
            mov     r8, qword ptr [rbp-192]
            call    crc32_update
            mov     qword ptr [rbp-168], rax
        xENDIF
        mov     rcx, qword ptr [rbp-136]
        lea     rdx, [uz_chunk]
        mov     r8, qword ptr [rbp-192]
        call    uz_sink_write
        test    eax, eax
        jnz     eze_io_part
        mov     rcx, qword ptr [rbp-192]     ; report bytes to the progress bar
        call    progress_add
        mov     rax, qword ptr [rbp-192]
        sub     qword ptr [rbp-144], rax
    xENDW
eas_fin:
    ; read 10-byte auth tag (sequential), finalise HMAC
    mov     rcx, qword ptr [g_uz_hin]
    lea     rdx, [uz_tag]
    mov     r8, 10
    call    file_read_exact
    test    eax, eax
    jnz     eze_io_part
    lea     rcx, [uz_sctx]
    lea     rdx, [uz_inner]
    call    sha1_final
    lea     rcx, [uz_sctx]
    call    sha1_init
    lea     rcx, [uz_sctx]
    lea     rdx, [uz_opad]
    mov     r8, 64
    call    sha1_update
    lea     rcx, [uz_sctx]
    lea     rdx, [uz_inner]
    mov     r8, 20
    call    sha1_update
    lea     rcx, [uz_sctx]
    lea     rdx, [uz_mac]
    call    sha1_final
    lea     rcx, [uz_mac]
    lea     rdx, [uz_tag]
    mov     r8, 10
    call    ct_memcmp
    test    eax, eax
    jnz     eze_auth_part
    ; optional CRC (AE-1)
    cmp     qword ptr [rbp-176], 0
    je      eas_ok
    mov     eax, dword ptr [rbp-168]
    cmp     eax, dword ptr [rbp-80]
    jne     eze_auth_part
eas_ok:
    ; close part, rename into place.  The tag passed, so in memory mode the
    ; buffer becomes the caller's the same way the .part becomes the output.
    mov     rcx, qword ptr [rbp-136]
    call    uz_sink_close
    mov     qword ptr [rbp-136], INVALID
    cmp     qword ptr [g_uz_mem], 0
    jne     eas_counted
    lea     rcx, [uz_partpath]
    lea     rdx, [g_extw]
    call    file_rename
    test    eax, eax
    jnz     eze_io
eas_counted:
    call    uz_entry_done
    xor     eax, eax
    jmp     eze_ret
; =============================================================================
; eze_plain_store - stream an UNENCRYPTED stored entry (copy + optional CRC).
; =============================================================================
eze_plain_store:
    mov     qword ptr [rbp-168], 0
    mov     rcx, qword ptr [g_uz_hin]        ; seek to data
    mov     rdx, qword ptr [rbp-128]
    lea     r8, [uz_chunk]
    xor     r9, r9
    call    file_read_at                     ; 0-length positioned read = seek
    test    eax, eax
    jnz     eze_io
    lea     rcx, [g_extw]
    call    uz_sink_open
    cmp     rax, INVALID
    je      eze_io
    mov     qword ptr [rbp-136], rax
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [rbp-144], rax
    xWHILE qword ptr [rbp-144], ne, 0        ; while stored data remains
        mov     r8, qword ptr [rbp-144]
        xIF r8, a, CHUNK
            mov     r8, CHUNK
        xENDIF
        mov     qword ptr [rbp-192], r8
        mov     rcx, qword ptr [g_uz_hin]
        lea     rdx, [uz_chunk]
        call    file_read_exact
        test    eax, eax
        jnz     eze_io_part2
        xIF qword ptr [rbp-176], ne, 0       ; CRC over the stored bytes
            mov     rcx, qword ptr [rbp-168]
            lea     rdx, [uz_chunk]
            mov     r8, qword ptr [rbp-192]
            call    crc32_update
            mov     qword ptr [rbp-168], rax
        xENDIF
        mov     rcx, qword ptr [rbp-136]
        lea     rdx, [uz_chunk]
        mov     r8, qword ptr [rbp-192]
        call    uz_sink_write
        test    eax, eax
        jnz     eze_io_part2
        mov     rcx, qword ptr [rbp-192]     ; report bytes to the progress bar
        call    progress_add
        mov     rax, qword ptr [rbp-192]
        sub     qword ptr [rbp-144], rax
    xENDW
eps_fin:
    mov     rcx, qword ptr [rbp-136]
    call    uz_sink_close
    mov     qword ptr [rbp-136], INVALID
    cmp     qword ptr [rbp-176], 0
    je      eps_ok
    mov     eax, dword ptr [rbp-168]
    cmp     eax, dword ptr [rbp-80]
    jne     eze_corrupt
eps_ok:
    call    uz_entry_done
    xor     eax, eax
    jmp     eze_ret
; =============================================================================
; eze_deflate - buffered deflate path (AES or unencrypted).  [rbp-88]=8.
; For AES the file pointer is at ct start; for unencrypted, seek to dataoff.
; =============================================================================
eze_deflate:
    cmp     qword ptr [rbp-40], DEFLATE_RD_CAP
    ja      eze_toobig
    ; allocate the compressed-data buffer (ctlen) and read it
    mov     rcx, qword ptr [rbp-56]
    test    rcx, rcx
    jnz     @F
    mov     rcx, 1
@@:
    call    mem_alloc
    test    rax, rax
    jz      eze_oom
    mov     qword ptr [rbp-160], rax         ; defin
    mov     rax, qword ptr [rbp-64]
    cmp     rax, 99
    je      ed_readaes
    ; unencrypted: positioned read from dataoff
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-128]
    mov     r8, qword ptr [rbp-160]
    mov     r9, qword ptr [rbp-56]
    call    file_read_at
    test    eax, eax
    jnz     eze_io
    jmp     ed_inflate
ed_readaes:
    ; sequential read of ciphertext (file pointer at ct start), then tag
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-160]
    mov     r8, qword ptr [rbp-56]
    call    file_read_exact
    test    eax, eax
    jnz     eze_io
    mov     rcx, qword ptr [g_uz_hin]
    lea     rdx, [uz_tag]
    mov     r8, 10
    call    file_read_exact
    test    eax, eax
    jnz     eze_io
    ; HMAC over ciphertext (one-shot), verify BEFORE decrypt
    lea     rax, [uz_mac]
    mov     qword ptr [rsp+32], rax
    lea     rcx, [uz_keys]
    add     rcx, qword ptr [rbp-104]
    mov     rdx, qword ptr [rbp-104]
    mov     r8, qword ptr [rbp-160]
    mov     r9, qword ptr [rbp-56]
    call    hmac_sha1
    lea     rcx, [uz_mac]
    lea     rdx, [uz_tag]
    mov     r8, 10
    call    ct_memcmp
    test    eax, eax
    jnz     eze_auth
    ; decrypt in place
    lea     rcx, [uz_ctr]
    mov     rdx, 16
    call    secure_zero
    mov     rax, qword ptr [rbp-120]
    mov     qword ptr [rsp+32], rax
    lea     rcx, [uz_rk]
    mov     rdx, qword ptr [rbp-160]
    mov     r8, qword ptr [rbp-56]
    lea     r9, [uz_ctr]
    call    aes_ctr_xor
ed_inflate:
    ; allocate output (usize) and inflate
    mov     rcx, qword ptr [rbp-40]
    test    rcx, rcx
    jnz     @F
    mov     rcx, 1
@@:
    call    mem_alloc
    test    rax, rax
    jz      eze_oom
    mov     qword ptr [rbp-152], rax         ; outbuf
    lea     r10, [rbp-216]
    mov     qword ptr [rsp+32], r10          ; &outlen
    mov     rcx, qword ptr [rbp-160]
    mov     rdx, qword ptr [rbp-56]
    mov     r8, qword ptr [rbp-152]
    mov     r9, qword ptr [rbp-40]
    call    inflate
    test    eax, eax
    jnz     eze_corrupt
    ; CRC over decompressed data (if needed)
    cmp     qword ptr [rbp-176], 0
    je      ed_write
    xor     ecx, ecx
    mov     rdx, qword ptr [rbp-152]
    mov     r8, qword ptr [rbp-216]
    call    crc32_update
    cmp     eax, dword ptr [rbp-80]
    jne     eze_corrupt
ed_write:
    mov     rcx, qword ptr [rbp-152]
    mov     rdx, qword ptr [rbp-216]
    call    uz_write_file
    test    eax, eax
    jnz     eze_io
    mov     rcx, qword ptr [rbp-216]         ; report the inflated bytes
    call    progress_add
    call    uz_entry_done
    xor     eax, eax
    jmp     eze_ret
; -------------------------------------------------------------------------
eze_skip:
    xor     eax, eax
    jmp     eze_ret
eze_unsafe:
    lea     rcx, [e_uz_name]
    mov     edx, e_uz_name_len
    call    print_a
    mov     eax, EXIT_CORRUPT
    jmp     eze_ret
eze_zcrypto:
    lea     rcx, [e_uz_zcrypto]
    mov     edx, e_uz_zcrypto_len
    call    print_a
    mov     eax, EXIT_CORRUPT
    jmp     eze_ret
eze_unsup:
    lea     rcx, [e_uz_unsup]
    mov     edx, e_uz_unsup_len
    call    print_a
    mov     eax, EXIT_CORRUPT
    jmp     eze_ret
eze_toobig:
    lea     rcx, [e_uz_big]
    mov     edx, e_uz_big_len
    call    print_a
    mov     eax, EXIT_CORRUPT
    jmp     eze_ret
eze_needpw:
    lea     rcx, [e_uz_needpw]
    mov     edx, e_uz_needpw_len
    call    print_a
    mov     eax, EXIT_USAGE
    jmp     eze_ret
eze_auth_part:
    mov     rcx, qword ptr [rbp-136]
    call    uz_sink_discard
    mov     qword ptr [rbp-136], INVALID
eze_auth:
    lea     rcx, [e_uz_auth]
    mov     edx, e_uz_auth_len
    call    print_a
    mov     eax, EXIT_AUTH
    jmp     eze_ret
eze_corrupt:
    lea     rcx, [e_uz_corrupt]
    mov     edx, e_uz_corrupt_len
    call    print_a
    mov     eax, EXIT_CORRUPT
    jmp     eze_ret
eze_oom:
    lea     rcx, [e_uz_oom]
    mov     edx, e_uz_oom_len
    call    print_a
    mov     eax, EXIT_OOM
    jmp     eze_ret
eze_io_part:
    mov     rcx, qword ptr [rbp-136]
    call    uz_sink_discard
    mov     qword ptr [rbp-136], INVALID
    jmp     eze_io
eze_io_part2:
    mov     rcx, qword ptr [rbp-136]
    call    uz_sink_close
    mov     qword ptr [rbp-136], INVALID
eze_io:
    lea     rcx, [e_uz_io]
    mov     edx, e_uz_io_len
    call    print_a
    mov     eax, EXIT_IO
eze_ret:
    mov     qword ptr [rbp-184], rax
    mov     rcx, qword ptr [rbp-136]         ; close any open output sink
    call    uz_sink_close
    cmp     qword ptr [rbp-152], 0           ; free deflate output buffer
    je      @F
    mov     rcx, qword ptr [rbp-152]
    mov     rdx, qword ptr [rbp-40]
    call    mem_free
@@:
    cmp     qword ptr [rbp-160], 0           ; free deflate input buffer
    je      @F
    mov     rcx, qword ptr [rbp-160]
    mov     rdx, qword ptr [rbp-56]
    call    mem_free
@@:
    mov     rax, qword ptr [rbp-184]
    FRAME_EPILOG
    ret
extract_zip_entry endp

; =============================================================================
; zip_is_encrypted(rcx = wide path) -> eax: 1 = the archive has encrypted
;   entries, 0 = none are encrypted, -1 = could not determine (the caller
;   should assume encrypted and prompt for a password).
;
; Walks the central directory via positioned reads.  An entry counts as
; encrypted if its method is 99 (WinZip AES) or its general-purpose bit 0
; (the ZIP "encrypted" flag) is set.  Directory and plain entries are never
; encrypted, so an all-plain archive returns 0 and the GUI can skip the
; password field.  Self-contained: opens/closes its own handle, uses
; uz_tail/uz_lhbuf as scratch, allocates nothing.
; =============================================================================
public zip_is_encrypted
zip_is_encrypted proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=hin [rbp-32]=size [rbp-40]=tailsize [rbp-48]=count
    ; [rbp-56]=cdoff [rbp-64]=choff [rbp-72]=i/result [rbp-80]=eocdrel
    mov     qword ptr [rbp-24], INVALID
    call    file_open_read                   ; rcx = path
    cmp     rax, INVALID
    je      zie_unknown
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    lea     rdx, [rbp-32]
    call    get_file_size
    test    eax, eax
    jnz     zie_unknown
    mov     rax, qword ptr [rbp-32]
    cmp     rax, 22
    jb      zie_unknown
    ; ---- read the tail and find the EOCD -----------------------------------
    mov     r8, TAILSIZE
    cmp     rax, r8
    jbe     @F
    mov     rax, r8
@@:
    mov     qword ptr [rbp-40], rax          ; tailsize
    mov     rcx, qword ptr [rbp-32]
    sub     rcx, rax                          ; tailoff
    mov     rdx, rcx
    mov     rcx, qword ptr [rbp-24]
    lea     r8, [uz_tail]
    mov     r9, qword ptr [rbp-40]
    call    file_read_at
    test    eax, eax
    jnz     zie_unknown
    mov     rax, qword ptr [rbp-40]
    sub     rax, 22
zie_scan:
    lea     r10, [uz_tail]
    cmp     dword ptr [r10+rax], SIG_EOCD
    je      zie_eocd
    test    rax, rax
    jz      zie_unknown
    dec     rax
    jmp     zie_scan
zie_eocd:
    mov     qword ptr [rbp-80], rax          ; eocdrel
    lea     r10, [uz_tail]
    add     r10, rax
    movzx   ecx, word ptr [r10+10]
    mov     qword ptr [rbp-48], rcx          ; count
    mov     ecx, dword ptr [r10+16]
    mov     qword ptr [rbp-56], rcx          ; cdoff
    ; ---- ZIP64? ------------------------------------------------------------
    cmp     qword ptr [rbp-48], 0FFFFh
    je      zie_z64
    cmp     dword ptr [rbp-56], 0FFFFFFFFh
    jne     zie_walk
zie_z64:
    mov     rax, qword ptr [rbp-80]
    cmp     rax, 20
    jb      zie_unknown
    sub     rax, 20
    lea     r10, [uz_tail]
    add     r10, rax
    cmp     dword ptr [r10], SIG_Z64LOC
    jne     zie_unknown
    mov     rdx, qword ptr [r10+8]            ; zip64 eocd offset
    cmp     rdx, qword ptr [rbp-32]
    jae     zie_unknown
    mov     rcx, qword ptr [rbp-24]
    lea     r8, [uz_lhbuf]
    mov     r9, 56
    call    file_read_at
    test    eax, eax
    jnz     zie_unknown
    lea     r10, [uz_lhbuf]
    cmp     dword ptr [r10], SIG_Z64EOCD
    jne     zie_unknown
    mov     rcx, qword ptr [r10+32]
    mov     qword ptr [rbp-48], rcx          ; count
    mov     rcx, qword ptr [r10+48]
    mov     qword ptr [rbp-56], rcx          ; cdoff
zie_walk:
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [rbp-64], rax          ; choff
    mov     qword ptr [rbp-72], 0            ; i
zie_loop:
    mov     rax, qword ptr [rbp-72]
    cmp     rax, qword ptr [rbp-48]
    jae     zie_plain                        ; walked all entries: none encrypted
    mov     rax, qword ptr [rbp-64]
    add     rax, 46
    cmp     rax, qword ptr [rbp-32]
    ja      zie_unknown
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-64]
    lea     r8, [uz_lhbuf]
    mov     r9, 46
    call    file_read_at
    test    eax, eax
    jnz     zie_unknown
    lea     r10, [uz_lhbuf]
    cmp     dword ptr [r10], SIG_CDIR
    jne     zie_unknown
    movzx   eax, word ptr [r10+10]           ; method
    cmp     eax, 99
    je      zie_enc
    movzx   eax, word ptr [r10+8]            ; general-purpose flag
    test    eax, 1
    jnz     zie_enc
    movzx   eax, word ptr [r10+28]           ; nlen
    movzx   ecx, word ptr [r10+30]           ; elen
    movzx   edx, word ptr [r10+32]           ; clen
    mov     r11, qword ptr [rbp-64]
    add     r11, 46
    add     r11, rax
    add     r11, rcx
    add     r11, rdx
    mov     qword ptr [rbp-64], r11
    inc     qword ptr [rbp-72]
    jmp     zie_loop
zie_enc:
    mov     dword ptr [rbp-72], 1
    jmp     zie_close
zie_plain:
    mov     dword ptr [rbp-72], 0
    jmp     zie_close
zie_unknown:
    mov     dword ptr [rbp-72], -1
zie_close:
    cmp     qword ptr [rbp-24], INVALID
    je      @F
    mov     rcx, qword ptr [rbp-24]
    call    file_close
@@:
    mov     eax, dword ptr [rbp-72]
    FRAME_EPILOG
    ret
zip_is_encrypted endp

; =============================================================================
; uz_entry_usize(rcx = central-dir header ptr) -> rax = uncompressed size,
; resolving the ZIP64 (0x0001) extra when the 32-bit field holds the
; 0xFFFFFFFF sentinel.  Leaf (clobbers volatiles only); used to pre-sum the
; progress total.
; =============================================================================
uz_entry_usize proc
    mov     eax, dword ptr [rcx+24]          ; usize (zero-extended to rax)
    cmp     eax, 0FFFFFFFFh
    jne     ueu_done
    movzx   r8d, word ptr [rcx+28]           ; nlen
    movzx   r9d, word ptr [rcx+30]           ; elen
    lea     r10, [rcx+46]
    add     r10, r8                          ; extra-field ptr = ch+46+nlen
    xor     r11, r11                         ; cursor into the extra field
ueu_loop:
    mov     rdx, r11
    add     rdx, 4
    cmp     rdx, r9                          ; room for a 4-byte field header?
    ja      ueu_zero
    movzx   eax, word ptr [r10+r11]          ; field id
    movzx   edx, word ptr [r10+r11+2]        ; field data size
    cmp     eax, 1                           ; 0x0001 = ZIP64 extended info
    je      ueu_found
    add     r11, 4
    add     r11, rdx
    jmp     ueu_loop
ueu_found:
    mov     rax, r11
    add     rax, 12                          ; need 4 header + 8 usize bytes
    cmp     rax, r9
    ja      ueu_zero
    mov     rax, qword ptr [r10+r11+4]        ; usize is the first ZIP64 field
    ret
ueu_zero:
    xor     eax, eax
ueu_done:
    ret
uz_entry_usize endp

; =============================================================================
; do_unzip -> eax exit code
; =============================================================================
; =============================================================================
; uz_entry_picked(rcx = central-dir header) -> eax = 1 extract it, 0 skip.
;
; Only meaningful while g_pick_active is set; with no selection in force every
; entry is taken, so a stale mark can never quietly narrow a full extract.
;
; The name is normalised the way zip_to_index normalised it - backslashes to
; '/', a trailing separator dropped - because the pick was recorded against THAT
; spelling and a lookup against any other would silently match nothing, which
; here means silently extracting nothing.
; =============================================================================
uz_entry_picked proc frame
    FRAME_PROLOG 64
    cmp     dword ptr [g_pick_active], 0
    je      uep_yes
    mov     qword ptr [rbp-16], rcx
    movzx   eax, word ptr [rcx+28]
    mov     qword ptr [rbp-24], rax
    lea     r10, [rcx+46]
    mov     qword ptr [rbp-32], r10
    mov     r11, qword ptr [rbp-24]
    xor     r9, r9
uep_sep:
    cmp     r9, r11
    jae     uep_sepdone
    cmp     byte ptr [r10+r9], 5Ch
    jne     uep_sepn
    mov     byte ptr [r10+r9], 2Fh
uep_sepn:
    inc     r9
    jmp     uep_sep
uep_sepdone:
    mov     rax, qword ptr [rbp-24]
    test    rax, rax
    jz      uep_no
    mov     r10, qword ptr [rbp-32]
    cmp     byte ptr [r10+rax-1], 2Fh
    jne     uep_look
    dec     qword ptr [rbp-24]
uep_look:
    cmp     qword ptr [rbp-24], 0
    je      uep_no
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    pick_has
    test    eax, eax
    jz      uep_no
uep_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
uep_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
uz_entry_picked endp

; =============================================================================
; zidx_add_unique(rcx = utf8 name, rdx = length, r8 = size, r9d = flags)
; Append an inventory entry unless one of that name is already there.
; =============================================================================
zidx_add_unique proc frame
    FRAME_PROLOG 96
    ; [rbp-16]=name [rbp-24]=len [rbp-32]=size [rbp-40]=flags
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    mov     dword ptr [rbp-40], r9d
    call    idx_find                          ; rcx/rdx are still the arguments
    cmp     rax, 0
    jge     zau_ret                           ; already listed
    ; The buffer is allocated on demand, and a zip listing is one of the three
    ; places that writes into it - see idx_buf_ensure (pack.asm).  Out of memory
    ; reports the same way running out of room does: the listing says it is
    ; short rather than going quiet about it.
    call    idx_buf_ensure
    test    eax, eax
    jz      zau_haveb
    or      qword ptr [g_idxflags], IDXF_TRUNCATED
    jmp     zau_ret
zau_haveb:
    mov     r10, qword ptr [rbp-24]
    add     r10, IDXE_FIXED
    add     r10, qword ptr [g_idxlen]
    ; IDX_MAX_BYTES, not idx_cap: this is the ZIP listing path, and being short
    ; here sets IDXF_TRUNCATED rather than failing the operation - different
    ; semantics from .mrk, so it keeps the buffer's own hard limit.
    cmp     r10, IDX_MAX_BYTES
    ja      zau_short
    ; commit the bytes this entry will occupy; out of memory reports the same
    ; way running out of room does
    mov     rcx, r10
    call    idx_buf_commit
    test    eax, eax
    jz      zau_room
zau_short:
    ; Say so rather than stopping quietly: a listing that is short and does not
    ; admit it is the same class of failure as a delete that leaves data behind.
    or      qword ptr [g_idxflags], IDXF_TRUNCATED
    jmp     zau_ret
zau_room:
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [g_idxlen]
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+IDXE_size], rax
    ; A zip is never removed from in place, so there is no extent to record.
    ; The container view hides Remove for one, which is what keeps these zeros
    ; from ever being acted on.
    mov     qword ptr [r10+IDXE_offset], 0
    mov     qword ptr [r10+IDXE_stored], 0
    mov     qword ptr [r10+IDXE_ordinal], 0
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r10+IDXE_flags], eax
    mov     rax, qword ptr [rbp-24]
    mov     dword ptr [r10+IDXE_namelen], eax
    mov     r11, qword ptr [rbp-16]
    xor     r9, r9
zau_copy:
    cmp     r9, qword ptr [rbp-24]
    jae     zau_copied
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+IDXE_name+r9], al
    inc     r9
    jmp     zau_copy
zau_copied:
    mov     rax, qword ptr [rbp-24]
    add     rax, IDXE_FIXED
    add     qword ptr [g_idxlen], rax
    inc     qword ptr [g_idxcount]
zau_ret:
    FRAME_EPILOG
    ret
zidx_add_unique endp

; =============================================================================
; zidx_parents(rcx = utf8 name, rdx = length) - make sure every folder above
; this name exists as an entry of its own.
; =============================================================================
zidx_parents proc frame
    FRAME_PROLOG 96
    ; [rbp-16]=name [rbp-24]=len [rbp-32]=k
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], 0
zp_loop:
    mov     rax, qword ptr [rbp-32]
    cmp     rax, qword ptr [rbp-24]
    jae     zp_done
    mov     r10, qword ptr [rbp-16]
    cmp     byte ptr [r10+rax], 2Fh           ; '/'
    jne     zp_next
    test    rax, rax
    jz      zp_next                           ; a leading '/' names nothing
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, rax
    xor     r8, r8
    mov     r9d, IDXEF_DIR
    call    zidx_add_unique
zp_next:
    inc     qword ptr [rbp-32]
    jmp     zp_loop
zp_done:
    FRAME_EPILOG
    ret
zidx_parents endp

; =============================================================================
; zip_to_index -> eax = 0, or EXIT_IO / EXIT_CORRUPT / EXIT_OOM.
;
; Build the in-memory inventory from a zip central directory, in the SAME shape
; idx_read produces for a .mrk.  That shape is the point: rows_from_index, the
; expand/collapse rule, the row display and the summary all already work against
; it, so browsing an archive costs no second listing path in the GUI.
;
; No password is asked for and none is needed.  WinZip-AES encrypts entry DATA,
; not the central directory, so an archive names and sizes are readable by
; anyone holding the file - a fact about the format, not a choice made here.
; Asking for a password to show what is already unprotected would be theatre,
; and would imply the names had been secret.  A .mrk is the other way round: its
; inventory sits behind the same key as its payload, so nothing can be shown
; until the password has been given.
;
; ZIPS OFTEN CARRY NO DIRECTORY ENTRIES AT ALL.  Only file records are required,
; so "a/b/c.txt" can be the only trace of a and of a/b.  Built from the entries
; alone the tree would have no folder rows, every file would sit behind
; ancestors that do not exist, and the window would come up EMPTY on a perfectly
; good archive.  Missing parents are synthesised; that is what zidx_parents is.
;
; Names are taken as the raw central-directory bytes, exactly as
; extract_zip_entry reads them.  A name shown differently from the name
; extracted would be worse than either convention on its own.
;
; locals (frame 128): choff[-24] i[-32] namelen[-40] nameptr[-48] usize[-56]
;   flags[-64] code[-80]
; =============================================================================
public zip_to_index
zip_to_index proc frame
    FRAME_PROLOG 128
    mov     rcx, qword ptr [g_cfg_in]
    call    zip_read_cd
    test    eax, eax
    jnz     zti_ret
    mov     qword ptr [g_idxlen], 0
    mov     qword ptr [g_idxcount], 0
    mov     qword ptr [g_idxflags], 0
    mov     qword ptr [rbp-24], 0
    mov     qword ptr [rbp-32], 0
zti_loop:
    mov     rax, qword ptr [rbp-32]
    cmp     rax, qword ptr [g_cdcount]
    jae     zti_done
    mov     rax, qword ptr [rbp-24]
    add     rax, 46
    cmp     rax, qword ptr [g_cdsize]
    ja      zti_done
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-24]
    cmp     dword ptr [rcx], SIG_CDIR
    jne     zti_done
    movzx   eax, word ptr [rcx+28]            ; name length
    mov     qword ptr [rbp-40], rax
    ; the name has to lie inside the buffer that was read
    mov     r11, qword ptr [rbp-24]
    add     r11, 46
    add     r11, rax
    cmp     r11, qword ptr [g_cdsize]
    ja      zti_done
    lea     r10, [rcx+46]
    mov     qword ptr [rbp-48], r10
    call    uz_entry_usize                    ; rcx is still the CD header
    mov     qword ptr [rbp-56], rax
    ; ---- '\' is a separator here too ----------------------------------------
    ; The spec says names use '/', and plenty of Windows tools write '\' anyway -
    ; .NET's ZipFile.CreateFromDirectory does, on the framework this was tested
    ; against.  build_extract_path passes a backslash straight through into the
    ; output path and create_parents makes the folder, so the EXTRACTOR already
    ; treats it as a separator.  Listing it as a literal character would show one
    ; flat row for something that comes out as a folder - the browser and the
    ; extractor disagreeing about the same archive.
    ;
    ; A backslash is a legal filename character on POSIX, so this does mangle a
    ; name that meant it literally.  That case cannot be extracted on Windows
    ; either, and matching what the extractor does is worth more than being
    ; right about a file that cannot be written.
    ;
    ; In place, in our own copy of the central directory, which is freed at the
    ; end of this proc.
    mov     r10, qword ptr [rbp-48]
    mov     r11, qword ptr [rbp-40]
    xor     r9, r9
zti_sep:
    cmp     r9, r11
    jae     zti_sepdone
    cmp     byte ptr [r10+r9], 5Ch
    jne     zti_sepnext
    mov     byte ptr [r10+r9], 2Fh
zti_sepnext:
    inc     r9
    jmp     zti_sep
zti_sepdone:
    ; a trailing '/' is what marks a directory in a zip
    mov     dword ptr [rbp-64], 0
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      zti_step                          ; nameless: nothing to list
    cmp     byte ptr [r10+rax-1], 2Fh
    jne     zti_named
    dec     qword ptr [rbp-40]
    mov     dword ptr [rbp-64], IDXEF_DIR
    mov     qword ptr [rbp-56], 0
zti_named:
    cmp     qword ptr [rbp-40], 0
    je      zti_step
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-40]
    call    zidx_parents
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-56]
    mov     r9d, dword ptr [rbp-64]
    call    zidx_add_unique
zti_step:
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-24]
    movzx   eax, word ptr [rcx+28]
    movzx   r8d, word ptr [rcx+30]
    movzx   r9d, word ptr [rcx+32]
    mov     r11, qword ptr [rbp-24]
    add     r11, 46
    add     r11, rax
    add     r11, r8
    add     r11, r9
    mov     qword ptr [rbp-24], r11
    inc     qword ptr [rbp-32]
    jmp     zti_loop
zti_done:
    xor     eax, eax
zti_ret:
    ; the listing is in memory now, so nothing here needs the archive open; an
    ; extract that follows opens it again for itself
    mov     dword ptr [rbp-80], eax
    cmp     qword ptr [g_cdbuf], 0
    je      @F
    mov     rcx, qword ptr [g_cdbuf]
    mov     rdx, qword ptr [g_cdsize]
    call    mem_free
    mov     qword ptr [g_cdbuf], 0
@@:
    cmp     qword ptr [g_uz_hin], INVALID
    je      @F
    mov     rcx, qword ptr [g_uz_hin]
    call    file_close
    mov     qword ptr [g_uz_hin], INVALID
@@:
    mov     eax, dword ptr [rbp-80]
    FRAME_EPILOG
    ret
zip_to_index endp

; =============================================================================
; zip_entry_to_mem(rcx = wide archive path, rdx = utf8 name, r8 = name len,
;                  r9 = *out, a two-qword area receiving { ptr, len })
;   -> eax 0, or EXIT_IO / EXIT_CORRUPT / EXIT_AUTH / EXIT_OOM / EXIT_USAGE
;
; One named entry, extracted into a buffer the caller then owns and releases
; with mem_free(ptr, len).  This is what a drag-out of a zip row is built on;
; docs/DRAG_OUT.md §7 says why a zip entry is materialised while a .mrk entry
; is streamed.
;
; The archive is a PARAMETER and not g_cfg_in for the reason entry_stream_open's
; key is: the drag object holds its own copy of the container path, taken when
; the drag began, and the globals the GUI was using may have moved on by the
; time a target asks for the bytes.
;
; The name is matched against the spelling zip_to_index LISTED, not the one the
; archive stores: backslashes folded to '/', a trailing separator dropped.  The
; row being dragged came from that listing, so matching anything else would
; silently find nothing - and a drag that silently finds nothing is a copy that
; quietly loses a file.  Same argument as uz_entry_picked.
;
; zip_to_index frees g_cdbuf and closes g_uz_hin when it finishes, so there is
; no central directory left over to reuse and this reads its own.  It also
; means this must not run while a listing is in flight; it is called from the
; STA thread that owns the container view, which is what makes that true.
; =============================================================================
public zip_entry_to_mem
zip_entry_to_mem proc frame
    FRAME_PROLOG 160
    ; [rbp-16]=name [rbp-24]=len [rbp-32]=out
    ; [rbp-48]=cursor [rbp-56]=index [rbp-64]=nlen [rbp-72]=nptr
    ; [rbp-80]=buf [rbp-88]=cap [rbp-96]=rc [rbp-104]=chptr
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    mov     qword ptr [r9], 0
    mov     qword ptr [r9+8], 0
    mov     qword ptr [rbp-80], 0
    cmp     r8, 0
    je      zem_corrupt_raw
    call    zip_read_cd
    test    eax, eax
    jnz     zem_ret_raw                       ; it cleaned up after itself
    mov     qword ptr [rbp-48], 0
    mov     qword ptr [rbp-56], 0
zem_loop:
    mov     rax, qword ptr [rbp-56]
    cmp     rax, qword ptr [g_cdcount]
    jae     zem_notfound
    mov     rax, qword ptr [rbp-48]
    add     rax, 46
    cmp     rax, qword ptr [g_cdsize]
    ja      zem_notfound
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-48]
    cmp     dword ptr [rcx], SIG_CDIR
    jne     zem_notfound
    mov     qword ptr [rbp-104], rcx
    movzx   eax, word ptr [rcx+28]            ; name length
    mov     qword ptr [rbp-64], rax
    mov     r11, qword ptr [rbp-48]           ; the name has to lie inside the buffer
    add     r11, 46
    add     r11, rax
    cmp     r11, qword ptr [g_cdsize]
    ja      zem_notfound
    lea     r10, [rcx+46]
    mov     qword ptr [rbp-72], r10
    ; ---- normalise the way the listing did (in our own copy) ----------------
    mov     r11, qword ptr [rbp-64]
    xor     r9, r9
zem_sep:
    cmp     r9, r11
    jae     zem_sepd
    cmp     byte ptr [r10+r9], 5Ch
    jne     zem_sepn
    mov     byte ptr [r10+r9], 2Fh
zem_sepn:
    inc     r9
    jmp     zem_sep
zem_sepd:
    mov     rax, qword ptr [rbp-64]
    test    rax, rax
    jz      zem_step
    mov     r10, qword ptr [rbp-72]
    cmp     byte ptr [r10+rax-1], 2Fh
    jne     zem_cmp
    dec     qword ptr [rbp-64]
zem_cmp:
    mov     rax, qword ptr [rbp-64]
    cmp     rax, qword ptr [rbp-24]
    jne     zem_step
    mov     r10, qword ptr [rbp-72]
    mov     r11, qword ptr [rbp-16]
    xor     r9, r9
zem_bc:
    cmp     r9, rax
    jae     zem_found
    mov     r8b, byte ptr [r10+r9]
    cmp     r8b, byte ptr [r11+r9]
    jne     zem_step
    inc     r9
    jmp     zem_bc
zem_step:
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-48]
    movzx   eax, word ptr [rcx+28]
    movzx   r8d, word ptr [rcx+30]
    movzx   r9d, word ptr [rcx+32]
    mov     r11, qword ptr [rbp-48]
    add     r11, 46
    add     r11, rax
    add     r11, r8
    add     r11, r9
    mov     qword ptr [rbp-48], r11
    inc     qword ptr [rbp-56]
    jmp     zem_loop
zem_found:
    ; ---- size the buffer from the entry's declared uncompressed size --------
    ; The cap is that size and nothing larger, so an archive that declares one
    ; length and delivers another is REFUSED by uz_mem_take rather than
    ; overflowing.  A zip that lies about a size is exactly the input this has
    ; to survive.
    mov     rcx, qword ptr [rbp-104]
    call    uz_entry_usize
    mov     qword ptr [rbp-88], rax
    mov     rcx, rax
    call    mem_alloc                         ; mem_alloc already floors 0 at 1
    test    rax, rax
    jz      zem_oom
    mov     qword ptr [rbp-80], rax
    mov     qword ptr [g_uz_mem], rax
    mov     rax, qword ptr [rbp-88]
    mov     qword ptr [g_uz_memcap], rax
    mov     qword ptr [g_uz_memlen], 0
    mov     rcx, qword ptr [rbp-104]
    call    extract_zip_entry
    mov     qword ptr [rbp-96], rax
    mov     qword ptr [g_uz_mem], 0           ; back to writing files
    cmp     qword ptr [rbp-96], 0
    jne     zem_failbuf
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-80]
    mov     qword ptr [r10], rax
    mov     rax, qword ptr [g_uz_memlen]
    mov     qword ptr [r10+8], rax
    xor     eax, eax
    jmp     zem_ret
zem_failbuf:
    ; The tag did not pass, or the read broke part way.  What is in there is
    ; unauthenticated plaintext, so it goes back wiped and the caller is told
    ; nothing - the buffer is the .part file, and this is deleting it.
    mov     rcx, qword ptr [rbp-80]
    mov     rdx, qword ptr [rbp-88]
    call    mem_free
    mov     qword ptr [rbp-80], 0
    mov     rax, qword ptr [rbp-96]
    jmp     zem_ret
zem_notfound:
    mov     eax, EXIT_CORRUPT
    jmp     zem_ret
zem_oom:
    mov     eax, EXIT_OOM
zem_ret:
    mov     dword ptr [rbp-112], eax
    cmp     qword ptr [g_cdbuf], 0
    je      @F
    mov     rcx, qword ptr [g_cdbuf]
    mov     rdx, qword ptr [g_cdsize]
    call    mem_free
    mov     qword ptr [g_cdbuf], 0
@@:
    cmp     qword ptr [g_uz_hin], INVALID
    je      @F
    mov     rcx, qword ptr [g_uz_hin]
    call    file_close
    mov     qword ptr [g_uz_hin], INVALID
@@:
    mov     eax, dword ptr [rbp-112]
    FRAME_EPILOG
    ret
zem_corrupt_raw:
    mov     eax, EXIT_CORRUPT
zem_ret_raw:
    FRAME_EPILOG
    ret
zip_entry_to_mem endp

; =============================================================================
; zip_read_cd(rcx = wide path) -> eax = 0, or EXIT_IO / EXIT_CORRUPT / EXIT_OOM.
;
; Opens the archive, finds the end-of-central-directory record (ZIP64 included)
; and reads the whole central directory into g_cdbuf.  On success the CALLER
; owns the open handle in g_uz_hin and the buffer in g_cdbuf/g_cdsize, and the
; entry count is in g_cdcount.
;
; On FAILURE it leaves nothing open: the handle is closed and the buffer freed
; before it returns.  Every caller happens to clean up unconditionally anyway,
; so this changes no behaviour today - it removes the requirement that they all
; keep doing so, which was a contract stated only for the success path.
;
; Factored out of do_unzip so that LISTING an archive and EXTRACTING one find
; their entries through the same code.  A second EOCD scan written for the
; browser would be a second place to get ZIP64 wrong, and the two would come to
; disagree only on the archives that are hardest to test.
;
; It reports nothing: the caller owns the message, which is why do_unzip's
; wording is unchanged.
;
; locals (frame 128): tailsize[-24] eocdrel[-32] cdoff[-40] cdsize[-48]
; =============================================================================
public zip_read_cd
public g_cdbuf, g_cdsize, g_cdcount, g_cdoff, g_uz_size, g_uz_hin
public zip_check_password
zip_read_cd proc frame
    FRAME_PROLOG 128
    mov     qword ptr [g_uz_hin], INVALID
    mov     qword ptr [g_cdbuf], 0
    mov     qword ptr [g_cdcount], 0
    lea     rdx, [uz_in_np]
    call    normalize_path
    test    eax, eax
    jnz     zrc_io
    lea     rcx, [uz_in_np]
    call    file_open_read
    cmp     rax, INVALID
    je      zrc_io
    mov     qword ptr [g_uz_hin], rax
    mov     rcx, rax
    lea     rdx, [g_uz_size]
    call    get_file_size
    test    eax, eax
    jnz     zrc_io
    mov     rax, qword ptr [g_uz_size]
    cmp     rax, 22
    jb      zrc_bad
    ; ---- read the tail and find the EOCD -----------------------------------
    mov     r8, TAILSIZE
    cmp     rax, r8
    jbe     @F
    mov     rax, r8
@@:
    mov     qword ptr [rbp-24], rax          ; tailsize
    mov     rcx, qword ptr [g_uz_size]
    sub     rcx, rax
    mov     rdx, rcx
    mov     rcx, qword ptr [g_uz_hin]
    lea     r8, [uz_tail]
    mov     r9, qword ptr [rbp-24]
    call    file_read_at
    test    eax, eax
    jnz     zrc_io
    mov     rax, qword ptr [rbp-24]
    sub     rax, 22                           ; scan start (rel)
zrc_scan:
    lea     r10, [uz_tail]
    cmp     dword ptr [r10+rax], SIG_EOCD
    je      zrc_eocd
    test    rax, rax
    jz      zrc_bad
    dec     rax
    jmp     zrc_scan
zrc_eocd:
    mov     qword ptr [rbp-32], rax          ; eocdrel
    lea     r10, [uz_tail]
    add     r10, rax
    movzx   ecx, word ptr [r10+10]
    mov     qword ptr [g_cdcount], rcx
    mov     ecx, dword ptr [r10+16]
    mov     qword ptr [rbp-40], rcx          ; cdoff
    mov     ecx, dword ptr [r10+12]
    mov     qword ptr [rbp-48], rcx          ; cdsize
    ; ---- ZIP64? ------------------------------------------------------------
    cmp     qword ptr [g_cdcount], 0FFFFh
    je      zrc_z64
    cmp     dword ptr [rbp-40], 0FFFFFFFFh
    jne     zrc_have
zrc_z64:
    mov     rax, qword ptr [rbp-32]
    cmp     rax, 20
    jb      zrc_bad
    sub     rax, 20
    lea     r10, [uz_tail]
    add     r10, rax
    cmp     dword ptr [r10], SIG_Z64LOC
    jne     zrc_bad
    mov     rdx, qword ptr [r10+8]            ; zip64 eocd offset
    cmp     rdx, qword ptr [g_uz_size]
    jae     zrc_bad
    mov     rcx, qword ptr [g_uz_hin]
    lea     r8, [uz_lhbuf]
    mov     r9, 56
    call    file_read_at
    test    eax, eax
    jnz     zrc_io
    lea     r10, [uz_lhbuf]
    cmp     dword ptr [r10], SIG_Z64EOCD
    jne     zrc_bad
    mov     rcx, qword ptr [r10+32]
    mov     qword ptr [g_cdcount], rcx
    mov     rcx, qword ptr [r10+48]
    mov     qword ptr [rbp-40], rcx
    mov     rcx, qword ptr [r10+40]
    mov     qword ptr [rbp-48], rcx
zrc_have:
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_cdoff], rax
    ; ---- read the central directory into memory (cap-bounded) --------------
    mov     rax, qword ptr [rbp-48]
    cmp     rax, CD_CAP
    ja      zrc_bad
    mov     rcx, rax
    test    rcx, rcx
    jnz     @F
    mov     rcx, 1
@@:
    call    mem_alloc
    test    rax, rax
    jz      zrc_oom
    mov     qword ptr [g_cdbuf], rax
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [g_cdsize], rax
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [g_cdbuf]
    mov     r9, qword ptr [rbp-48]
    call    file_read_at
    test    eax, eax
    jnz     zrc_io
    xor     eax, eax
    FRAME_EPILOG
    ret
zrc_io:
    mov     eax, EXIT_IO
    jmp     zrc_fail
zrc_bad:
    mov     eax, EXIT_CORRUPT
    jmp     zrc_fail
zrc_oom:
    mov     eax, EXIT_OOM
zrc_fail:
    ; a path that returns nothing hands back nothing to own
    mov     dword ptr [rbp-56], eax
    cmp     qword ptr [g_cdbuf], 0
    je      @F
    mov     rcx, qword ptr [g_cdbuf]
    mov     rdx, qword ptr [g_cdsize]
    call    mem_free
    mov     qword ptr [g_cdbuf], 0
@@:
    cmp     qword ptr [g_uz_hin], INVALID
    je      @F
    mov     rcx, qword ptr [g_uz_hin]
    call    file_close
    mov     qword ptr [g_uz_hin], INVALID
@@:
    mov     eax, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
zip_read_cd endp


; =============================================================================
; zip_check_password -> eax 0 / EXIT_AUTH / EXIT_IO / EXIT_CORRUPT
;
; Does the password in g_cfg_pass open the entries this archive ALREADY holds?
;
; It has to be asked before a single byte is appended.  Every WinZip-AES entry
; carries its own salt and derives its own key, so adding under a mistyped
; password does not fail - it produces an archive whose old entries open and
; whose new ones do not, with nothing anywhere saying why.  That is the failure
; this exists to prevent.
;
; Checked against the first encrypted entry, using the same 2-byte password
; verifier extract_zip_entry checks: PBKDF2-HMAC-SHA1 over the entry's salt,
; 1000 iterations, and the two bytes that follow the derived keys.  An archive
; with no encrypted entry has nothing to disagree with, so the new entries
; simply set the password for themselves.
;
; Requires zip_read_cd to have run: g_cdbuf/g_cdsize hold the directory and
; g_uz_hin is the open archive.
;
; locals (frame 160): cursor[-16] localoff[-24] dataoff[-32] keylen[-40]
;   saltlen[-48] namelen[-56] extralen[-64]
;
; 160, not 96: pbkdf2_hmac_sha1 takes SEVEN arguments, so its outgoing area is
; 32 bytes of shadow plus three stack slots - 56 bytes - and at 96 that area sat
; exactly on saltlen, namelen and extralen.  The verifier comparison after the
; call reads saltlen, so it would have compared against the wrong offset.
; =============================================================================
zip_check_password proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-16], 0
zcp_next:
    mov     rcx, qword ptr [rbp-16]
    call    zd_record                        ; validates rather than trusting
    test    rax, rax
    jz      zcp_none                         ; walked off the end: nothing to check
    mov     r10, qword ptr [g_cdbuf]
    add     r10, qword ptr [rbp-16]
    movzx   eax, word ptr [r10+8]            ; general-purpose flag
    test    eax, 1
    jz      zcp_step                         ; not encrypted, try the next one
    ; the AES extra lives after the name in this record
    movzx   r8d, word ptr [r10+28]           ; namelen
    movzx   r9d, word ptr [r10+30]           ; extralen
    ; A 32-BIT load, not a qword read masked down.  `and rax, 0FFFFFFFFh`
    ; assembles as AND r64, imm32, and an imm32 is SIGN-extended - so the mask
    ; is 0FFFFFFFFFFFFFFFFh and does nothing at all.  The qword at +42 carries
    ; the first four bytes of the entry NAME in its high half, so the offset
    ; came out astronomically large and the read failed.  Writing to eax
    ; zero-extends into rax, which is what was wanted.
    mov     eax, dword ptr [r10+42]
    mov     qword ptr [rbp-24], rax          ; local header offset
    lea     rcx, [r10+46]
    add     rcx, r8
    mov     rdx, r9
    call    uz_find_aes
    cmp     qword ptr [uz_aesfound], 0
    je      zcp_step                         ; encrypted but not WinZip-AES
    mov     rax, qword ptr [uz_strength]
    cmp     rax, 1
    jb      zcp_corrupt
    cmp     rax, 3
    ja      zcp_corrupt
    inc     rax
    shl     rax, 3
    mov     qword ptr [rbp-40], rax          ; keylen  = 8*(strength+1)
    shr     rax, 1
    mov     qword ptr [rbp-48], rax          ; saltlen = keylen/2
    ; the data offset is only knowable from the LOCAL header - its name and
    ; extra lengths need not match the directory's
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-24]
    lea     r8, [zcp_lochdr]
    mov     r9, 30
    call    file_read_at
    test    eax, eax
    jnz     zcp_io
    lea     r10, [zcp_lochdr]
    movzx   eax, word ptr [r10+26]
    mov     qword ptr [rbp-56], rax
    movzx   eax, word ptr [r10+28]
    mov     qword ptr [rbp-64], rax
    mov     rax, qword ptr [rbp-24]
    add     rax, 30
    add     rax, qword ptr [rbp-56]
    add     rax, qword ptr [rbp-64]
    mov     qword ptr [rbp-32], rax          ; salt starts here
    ; salt + the 2 verifier bytes
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [uz_saltbuf]
    mov     r9, qword ptr [rbp-48]
    add     r9, 2
    call    file_read_at
    test    eax, eax
    jnz     zcp_io
    mov     rax, qword ptr [rbp-40]
    add     rax, rax
    add     rax, 2                           ; 2K+2 bytes out of the KDF
    mov     qword ptr [rsp+32], 1000
    lea     rdx, [uz_keys]
    mov     qword ptr [rsp+40], rdx
    mov     qword ptr [rsp+48], rax
    lea     rcx, [g_cfg_pass]
    mov     edx, dword ptr [g_cfg_passlen]
    lea     r8, [uz_saltbuf]
    mov     r9, qword ptr [rbp-48]
    call    pbkdf2_hmac_sha1
    mov     rax, qword ptr [rbp-40]
    add     rax, rax
    lea     rcx, [uz_keys]
    add     rcx, rax                         ; derived verifier
    lea     rdx, [uz_saltbuf]
    add     rdx, qword ptr [rbp-48]          ; stored verifier
    mov     r8, 2
    call    ct_memcmp
    test    eax, eax
    jnz     zcp_auth
    xor     eax, eax
    jmp     zcp_ret
zcp_step:
    mov     rcx, qword ptr [rbp-16]
    call    zd_record
    add     qword ptr [rbp-16], rax
    jmp     zcp_next
zcp_none:
    xor     eax, eax
    jmp     zcp_ret
zcp_auth:
    mov     eax, EXIT_AUTH
    jmp     zcp_ret
zcp_corrupt:
    mov     eax, EXIT_CORRUPT
    jmp     zcp_ret
zcp_io:
    mov     eax, EXIT_IO
zcp_ret:
    call    uz_wipe_keys                     ; preserves eax; see the proc
    FRAME_EPILOG
    ret
zip_check_password endp

; =============================================================================
; zd_record(rcx = offset into the central directory) -> rax = that record's
; whole length, or 0 if there is no valid record at that offset.  Leaf.
;
; EVERY pass calls this rather than trusting the survey pass to have walked the
; same ground.  It does walk the same ground - the arithmetic is identical and
; nothing between the passes alters a length - but "pass one already checked it"
; is an invariant living in a comment, and a pass added later, or reordered,
; would break it silently and walk off the end of the buffer.  Three compares
; per record is not a price worth arguing about.
; =============================================================================
zd_record proc
    mov     rax, rcx
    add     rax, 46
    cmp     rax, qword ptr [g_cdsize]
    ja      zdr_no
    mov     r10, qword ptr [g_cdbuf]
    add     r10, rcx
    cmp     dword ptr [r10], SIG_CDIR
    jne     zdr_no
    movzx   eax, word ptr [r10+28]           ; name
    movzx   r11d, word ptr [r10+30]          ; extra
    add     eax, r11d
    movzx   r11d, word ptr [r10+32]          ; comment
    add     eax, r11d
    add     eax, 46
    mov     r11, rcx
    add     r11, rax
    cmp     r11, qword ptr [g_cdsize]
    ja      zdr_no
    ret
zdr_no:
    xor     eax, eax
    ret
zd_record endp

; =============================================================================
; uz_entry_dropped(rcx = central-directory header) -> eax = 1 remove it, 0 keep.
;
; The answer comes from the SAME inventory the window was drawn from:
; container_mark_selected set IDXEF_DROPPED on the entries under the selected
; rows, including everything below a selected folder, and this looks the name up
; there.  Anything the lookup does not find is KEPT.  That default is the point:
; a delete decided by a failed string match is the one mistake this cannot make,
; and an entry wrongly kept is visible while an entry wrongly destroyed is not.
;
; The name is normalised the way zip_to_index normalised it - backslashes to
; '/', a trailing separator dropped - because the mark was recorded against THAT
; spelling and a lookup against any other silently matches nothing.
;
; Into a scratch buffer, NOT in place as uz_entry_picked does it: the
; central-directory record is copied verbatim into the rewritten archive, and a
; name normalised in our copy would be written out no longer matching the local
; header it belongs to.
; =============================================================================
uz_entry_dropped proc frame
    FRAME_PROLOG 64
    ; [rbp-16] = name length, as it is being trimmed
    movzx   eax, word ptr [rcx+28]
    test    rax, rax
    jz      ued_keep
    cmp     rax, ZD_NAME_MAX
    ja      ued_keep                         ; longer than we can normalise
    mov     qword ptr [rbp-16], rax
    lea     r10, [rcx+46]
    lea     r11, [zd_name8]
    xor     r9, r9
ued_copy:
    cmp     r9, qword ptr [rbp-16]
    jae     ued_copied
    mov     al, byte ptr [r10+r9]
    cmp     al, 5Ch
    jne     @F
    mov     al, 2Fh
@@:
    mov     byte ptr [r11+r9], al
    inc     r9
    jmp     ued_copy
ued_copied:
    mov     rax, qword ptr [rbp-16]
    lea     r11, [zd_name8]
    cmp     byte ptr [r11+rax-1], 2Fh
    jne     ued_look
    dec     qword ptr [rbp-16]               ; a directory record's trailing '/'
    jz      ued_keep
ued_look:
    lea     rcx, [zd_name8]
    mov     rdx, qword ptr [rbp-16]
    call    idx_find
    cmp     rax, 0
    jl      ued_keep                         ; not in the inventory: keep it
    mov     r10, qword ptr [g_idxptr]
    add     r10, rax
    mov     eax, dword ptr [r10+IDXE_flags]
    test    eax, IDXEF_DROPPED
    jz      ued_keep
    mov     eax, 1
    FRAME_EPILOG
    ret
ued_keep:
    xor     eax, eax
    FRAME_EPILOG
    ret
uz_entry_dropped endp

; =============================================================================
; zd_wipe_run(rcx = handle, rdx = byte count) -> eax = 0 / EXIT_IO.
; Write random over `count` bytes from the handle's current position.
;
; RANDOM, never zeros, for the reason do_remove_marked gives: a run of zeros
; advertises exactly where something used to be and how big it was, where random
; is indistinguishable from the compressed and encrypted bytes around it.
; =============================================================================
zd_wipe_run proc frame
    FRAME_PROLOG 64
    ; [rbp-16]=handle [rbp-24]=left [rbp-32]=this chunk
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
zwr_next:
    cmp     qword ptr [rbp-24], 0
    je      zwr_ok
    mov     r8, qword ptr [rbp-24]
    cmp     r8, CHUNK
    jbe     @F
    mov     r8, CHUNK
@@:
    mov     qword ptr [rbp-32], r8
    lea     rcx, [uz_chunk]
    mov     edx, dword ptr [rbp-32]
    call    rng_fill
    test    eax, eax
    jz      zwr_io                           ; no random, no wipe - say so
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [uz_chunk]
    mov     r8, qword ptr [rbp-32]
    call    file_write_all
    test    eax, eax
    jnz     zwr_io
    mov     rax, qword ptr [rbp-32]
    sub     qword ptr [rbp-24], rax
    jmp     zwr_next
zwr_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
zwr_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
zd_wipe_run endp

; =============================================================================
; zip_delete_marked -> eax = 0, or EXIT_IO / EXIT_CORRUPT / EXIT_UNSUPPORTED /
; EXIT_PARTIAL.  Removes the entries marked IDXEF_DROPPED from the archive named
; by g_cfg_in.
;
; A zip cannot be edited the way a container can.  A .mrk records where every
; entry's ciphertext lies, so removing one is an overwrite in place and a slide
; of what follows; a zip's entries are reachable only by walking, every offset in
; its directory describes the OLD layout, and there is no per-entry extent to
; overwrite that the format itself would then still agree with.  So the archive
; is rebuilt, and the order of the three steps is the whole design:
;
;   1. WRITE the new archive beside the old one, under a temporary name.  The
;      original is untouched throughout, so every failure up to the end of this
;      step costs a temp file and nothing else - and that is most of the failures,
;      because it is where all the work is.
;
;      Survivors are copied as RAW BYTES: local header, extra fields, compressed
;      data.  A WinZip-AES entry carries its own salt, password verifier and
;      authentication tag inside those bytes, so it still decrypts under the same
;      password afterwards.  Nothing is decrypted to move it and the password is
;      not needed to do any of this - which also means a wrong password cannot
;      corrupt an archive this rewrote.
;
;   2. OVERWRITE the old file with random where the removed entries lay, and over
;      its central directory.  THIS is what makes the removal a removal.
;      Deleting the file alone unlinks it and leaves every removed entry's
;      ciphertext in freed blocks, still decryptable by whoever knows the
;      password - which is precisely the thing the user asked to be rid of, and
;      exactly the leak that in-place removal was built to avoid for containers.
;
;      Only the removed entries and the directory are overwritten, not the whole
;      file.  The survivors' bytes are not a secret being destroyed: by this
;      point they are in the new archive, unchanged, and writing over them would
;      buy nothing for a second full pass over the file.  The directory IS
;      overwritten because it names everything, including what was just removed -
;      a name is the disclosure that survives when the data does not.
;
;      The writes are FLUSHED before the handle closes.  Deleting a file discards
;      its dirty pages, so an unflushed overwrite followed by a delete can reach
;      the disk never: the wipe would have been a no-op that looked like a wipe,
;      and the failure is invisible from here.
;
;      What this cannot promise is the filesystem's own copies - a snapshot, a
;      journal, a flash translation layer that wrote the block elsewhere.  Same
;      caveat as removal from a container, and it is a property of the medium.
;
;   3. DELETE the old file, then rename the new one into its place.
;
; WHAT IT REFUSES, rather than guessing at.  An entry with general-purpose bit 3
; has its sizes only AFTER its data, so a byte copy cannot know where the entry
; ends without decoding it; ZIP64 offsets and multi-disk records do not fit the
; directory this writes; and a record whose signature is not where the directory
; says stops the whole thing.  Any of those and the archive is left exactly as it
; was.  Refusing to rewrite an archive is an inconvenience; rewriting one wrongly
; destroys it.  Myrkr's own zips carry none of these.
;
; locals (frame 176): hout[-16] hrw[-24] choff[-32] i[-40] outpos[-48]
;   cdofs[-56] cdsize[-64] kept[-72] lofs[-80] left[-88] chunk[-96] src[-104]
;   code[-112] reclen[-120] csize[-128] hdr[-136] keeptmp[-144]
; =============================================================================
public zip_delete_marked
zip_delete_marked proc frame
    FRAME_PROLOG 176
    mov     qword ptr [rbp-16], INVALID
    mov     qword ptr [rbp-24], INVALID
    mov     qword ptr [rbp-48], 0
    mov     qword ptr [rbp-72], 0
    mov     dword ptr [rbp-144], 0
    mov     word ptr [uz_tmppath], 0         ; nothing to clean up yet
    mov     rcx, qword ptr [g_cfg_in]
    call    zip_read_cd
    test    eax, eax
    jnz     zd_out

; ---- pass one: is this an archive we are willing to rewrite at all? ---------
; Every refusal is decided here, before a byte is written anywhere, so a refusal
; costs the user nothing but the answer.
    mov     qword ptr [rbp-32], 0
    mov     qword ptr [rbp-40], 0
zd_s_loop:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_cdcount]
    jae     zd_s_done
    mov     rcx, qword ptr [rbp-32]
    call    zd_record
    test    rax, rax
    jz      zd_corrupt
    mov     qword ptr [rbp-120], rax
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-32]
    movzx   eax, word ptr [rcx+8]            ; general-purpose flags
    test    eax, 8                           ; bit 3: sizes follow the data
    jnz     zd_unsup
    movzx   eax, word ptr [rcx+34]           ; disk this entry starts on
    test    eax, eax
    jnz     zd_unsup
    cmp     dword ptr [rcx+20], 0FFFFFFFFh   ; compressed size in a ZIP64 extra
    je      zd_unsup
    cmp     dword ptr [rcx+42], 0FFFFFFFFh   ; local offset in a ZIP64 extra
    je      zd_unsup
    call    uz_entry_dropped
    test    eax, eax
    jnz     zd_s_step
    inc     qword ptr [rbp-72]
zd_s_step:
    mov     rax, qword ptr [rbp-32]
    add     rax, qword ptr [rbp-120]
    mov     qword ptr [rbp-32], rax
    inc     qword ptr [rbp-40]
    jmp     zd_s_loop
zd_s_done:
    cmp     qword ptr [rbp-72], 0FFFFh       ; more survivors than an EOCD counts
    ja      zd_unsup

; ---- the destination name: the archive's, with a suffix --------------------
    lea     r10, [uz_in_np]
    lea     r11, [uz_tmppath]
    xor     r9, r9
zd_tp:
    cmp     r9, 8000h
    jae     zd_unsup                         ; no room left for the suffix
    mov     ax, word ptr [r10+r9*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      zd_tpdone
    inc     r9
    jmp     zd_tp
zd_tpdone:
    lea     r10, [w_ext_tmp]
    xor     rax, rax
zd_ts:
    mov     dx, word ptr [r10+rax*2]
    mov     word ptr [r11+r9*2], dx
    inc     r9
    inc     rax
    test    dx, dx
    jnz     zd_ts
    lea     rcx, [uz_tmppath]
    call    file_open_write
    cmp     rax, INVALID
    je      zd_io
    mov     qword ptr [rbp-16], rax

; ---- pass two: copy the survivors, byte for byte ---------------------------
    mov     qword ptr [rbp-32], 0
    mov     qword ptr [rbp-40], 0
zd_c_loop:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_cdcount]
    jae     zd_c_done
    mov     rcx, qword ptr [rbp-32]
    call    zd_record
    test    rax, rax
    jz      zd_corrupt
    mov     qword ptr [rbp-120], rax
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-32]
    mov     qword ptr [rbp-136], rcx
    call    uz_entry_dropped
    test    eax, eax
    jnz     zd_c_step                        ; removed: it is simply not copied
    mov     rcx, qword ptr [rbp-136]
    mov     eax, dword ptr [rcx+42]
    mov     qword ptr [rbp-80], rax          ; where it lies in the old file
    mov     eax, dword ptr [rcx+20]
    mov     qword ptr [rbp-128], rax         ; compressed size
    ; The local header's name and extra lengths are its own - the directory's
    ; copies are allowed to differ, and the bytes to copy are bounded by these.
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-80]
    lea     r8, [uz_lhbuf]
    mov     r9, 30
    call    file_read_at
    test    eax, eax
    jnz     zd_io
    lea     r10, [uz_lhbuf]
    cmp     dword ptr [r10], SIG_LOCAL
    jne     zd_corrupt
    mov     rax, qword ptr [rbp-128]
    movzx   r11d, word ptr [r10+26]
    add     rax, r11
    movzx   r11d, word ptr [r10+28]
    add     rax, r11
    add     rax, 30
    mov     qword ptr [rbp-88], rax
    mov     rax, qword ptr [rbp-80]
    add     rax, qword ptr [rbp-88]
    cmp     rax, qword ptr [g_uz_size]
    ja      zd_corrupt                       ; the entry runs off the end
    ; its new home, recorded in our copy of the directory before it moves
    mov     rax, qword ptr [rbp-48]
    ; via a register: as an immediate 0FFFFFFFFh sign-extends to -1 and the
    ; unsigned `ja` can never take - the guard was dead and a rewrite crossing
    ; 4 GiB truncated this value into the dword field below instead of refusing
    mov     r10d, 0FFFFFFFFh
    cmp     rax, r10
    ja      zd_unsup
    mov     rcx, qword ptr [rbp-136]
    mov     dword ptr [rcx+42], eax
    mov     rax, qword ptr [rbp-80]
    mov     qword ptr [rbp-104], rax
zd_c_chunk:
    cmp     qword ptr [rbp-88], 0
    je      zd_c_step
    mov     r8, qword ptr [rbp-88]
    cmp     r8, CHUNK
    jbe     @F
    mov     r8, CHUNK
@@:
    mov     qword ptr [rbp-96], r8
    mov     rcx, qword ptr [g_uz_hin]
    mov     rdx, qword ptr [rbp-104]
    lea     r8, [uz_chunk]
    mov     r9, qword ptr [rbp-96]
    call    file_read_at
    test    eax, eax
    jnz     zd_io
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [uz_chunk]
    mov     r8, qword ptr [rbp-96]
    call    file_write_all
    test    eax, eax
    jnz     zd_io
    mov     rax, qword ptr [rbp-96]
    add     qword ptr [rbp-104], rax
    add     qword ptr [rbp-48], rax
    sub     qword ptr [rbp-88], rax
    jmp     zd_c_chunk
zd_c_step:
    mov     rax, qword ptr [rbp-32]
    add     rax, qword ptr [rbp-120]
    mov     qword ptr [rbp-32], rax
    inc     qword ptr [rbp-40]
    jmp     zd_c_loop
zd_c_done:

; ---- pass three: the new central directory, then the EOCD ------------------
    mov     rax, qword ptr [rbp-48]
    ; via a register: as an immediate 0FFFFFFFFh sign-extends to -1 and the
    ; unsigned `ja` can never take - the guard was dead and a rewrite crossing
    ; 4 GiB truncated this value into the dword field below instead of refusing
    mov     r10d, 0FFFFFFFFh
    cmp     rax, r10
    ja      zd_unsup
    mov     qword ptr [rbp-56], rax
    mov     qword ptr [rbp-64], 0
    mov     qword ptr [rbp-32], 0
    mov     qword ptr [rbp-40], 0
zd_d_loop:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_cdcount]
    jae     zd_d_done
    mov     rcx, qword ptr [rbp-32]
    call    zd_record
    test    rax, rax
    jz      zd_corrupt
    mov     qword ptr [rbp-120], rax
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-32]
    mov     qword ptr [rbp-136], rcx
    call    uz_entry_dropped
    test    eax, eax
    jnz     zd_d_step
    ; verbatim, except for the local offset pass two patched in place
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-136]
    mov     r8, qword ptr [rbp-120]
    call    file_write_all
    test    eax, eax
    jnz     zd_io
    mov     rax, qword ptr [rbp-120]
    add     qword ptr [rbp-64], rax
    add     qword ptr [rbp-48], rax
zd_d_step:
    mov     rax, qword ptr [rbp-32]
    add     rax, qword ptr [rbp-120]
    mov     qword ptr [rbp-32], rax
    inc     qword ptr [rbp-40]
    jmp     zd_d_loop
zd_d_done:
    mov     rax, qword ptr [rbp-64]
    ; via a register: as an immediate 0FFFFFFFFh sign-extends to -1 and the
    ; unsigned `ja` can never take - the guard was dead and a rewrite crossing
    ; 4 GiB truncated this value into the dword field below instead of refusing
    mov     r10d, 0FFFFFFFFh
    cmp     rax, r10
    ja      zd_unsup
    lea     r10, [zd_eocd]
    mov     dword ptr [r10], SIG_EOCD
    mov     word ptr [r10+4], 0              ; this disk
    mov     word ptr [r10+6], 0              ; the disk the directory starts on
    mov     eax, dword ptr [rbp-72]          ; survivors, bounded to 0xFFFF above
    mov     word ptr [r10+8], ax
    mov     word ptr [r10+10], ax
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [r10+12], eax          ; directory size
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [r10+16], eax          ; directory offset
    mov     word ptr [r10+20], 0             ; no archive comment
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [zd_eocd]
    mov     r8, 22
    call    file_write_all
    test    eax, eax
    jnz     zd_io
    mov     rcx, qword ptr [rbp-16]
    call    file_close
    mov     qword ptr [rbp-16], INVALID
    mov     rcx, qword ptr [g_uz_hin]
    call    file_close
    mov     qword ptr [g_uz_hin], INVALID

; ---- pass four: make the old file's removed entries unreadable -------------
; From here the temp file is the archive, so it is never cleaned up on the way
; out even when something below fails.
    mov     dword ptr [rbp-144], 1
    lea     rcx, [uz_in_np]
    call    file_open_rw
    cmp     rax, INVALID
    je      zd_io
    mov     qword ptr [rbp-24], rax
    mov     qword ptr [rbp-32], 0
    mov     qword ptr [rbp-40], 0
zd_w_loop:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_cdcount]
    jae     zd_w_done
    mov     rcx, qword ptr [rbp-32]
    call    zd_record
    test    rax, rax
    jz      zd_corrupt
    mov     qword ptr [rbp-120], rax
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-32]
    mov     qword ptr [rbp-136], rcx
    call    uz_entry_dropped
    test    eax, eax
    jz      zd_w_step                        ; a survivor: its bytes are not a secret
    mov     rcx, qword ptr [rbp-136]
    mov     eax, dword ptr [rcx+42]
    mov     qword ptr [rbp-80], rax
    mov     eax, dword ptr [rcx+20]
    mov     qword ptr [rbp-128], rax
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-80]
    lea     r8, [uz_lhbuf]
    mov     r9, 30
    call    file_read_at
    test    eax, eax
    jnz     zd_io
    lea     r10, [uz_lhbuf]
    cmp     dword ptr [r10], SIG_LOCAL
    jne     zd_w_step                        ; nothing here we can size: leave it
    mov     rax, qword ptr [rbp-128]
    movzx   r11d, word ptr [r10+26]
    add     rax, r11
    movzx   r11d, word ptr [r10+28]
    add     rax, r11
    add     rax, 30                          ; the header goes too: it holds the name
    mov     qword ptr [rbp-88], rax
    mov     rax, qword ptr [rbp-80]
    add     rax, qword ptr [rbp-88]
    cmp     rax, qword ptr [g_uz_size]
    ja      zd_w_step
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-80]
    call    file_seek
    test    eax, eax
    jnz     zd_io
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-88]
    call    zd_wipe_run
    test    eax, eax
    jnz     zd_io
zd_w_step:
    mov     rax, qword ptr [rbp-32]
    add     rax, qword ptr [rbp-120]
    mov     qword ptr [rbp-32], rax
    inc     qword ptr [rbp-40]
    jmp     zd_w_loop
zd_w_done:
    ; and the directory itself, through to the end of the file: it names every
    ; entry that was just removed, and a name outlives the data it pointed at
    mov     rax, qword ptr [g_cdoff]
    cmp     rax, qword ptr [g_uz_size]
    jae     zd_flush
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, rax
    call    file_seek
    test    eax, eax
    jnz     zd_io
    mov     rax, qword ptr [g_uz_size]
    sub     rax, qword ptr [g_cdoff]
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, rax
    call    zd_wipe_run
    test    eax, eax
    jnz     zd_io
zd_flush:
    ; before the delete, not after: a delete drops the dirty pages this wrote
    WINCALL FlushFileBuffers, qword ptr [rbp-24]
    mov     rcx, qword ptr [rbp-24]
    call    file_close
    mov     qword ptr [rbp-24], INVALID

; ---- and finally the swap ---------------------------------------------------
    lea     rcx, [uz_in_np]
    call    file_delete
    lea     rcx, [uz_tmppath]
    lea     rdx, [uz_in_np]
    call    file_rename
    test    eax, eax
    jnz     zd_partial
    xor     eax, eax
    jmp     zd_out
zd_partial:
    mov     eax, EXIT_PARTIAL
    jmp     zd_out
zd_corrupt:
    mov     eax, EXIT_CORRUPT
    jmp     zd_out
zd_unsup:
    mov     eax, EXIT_UNSUPPORTED
    jmp     zd_out
zd_io:
    mov     eax, EXIT_IO
zd_out:
    mov     dword ptr [rbp-112], eax
    cmp     qword ptr [rbp-16], INVALID
    je      @F
    mov     rcx, qword ptr [rbp-16]
    call    file_close
    mov     qword ptr [rbp-16], INVALID
@@:
    cmp     qword ptr [rbp-24], INVALID
    je      @F
    mov     rcx, qword ptr [rbp-24]
    call    file_close
    mov     qword ptr [rbp-24], INVALID
@@:
    cmp     qword ptr [g_uz_hin], INVALID
    je      @F
    mov     rcx, qword ptr [g_uz_hin]
    call    file_close
    mov     qword ptr [g_uz_hin], INVALID
@@:
    cmp     qword ptr [g_cdbuf], 0
    je      @F
    mov     rcx, qword ptr [g_cdbuf]
    mov     rdx, qword ptr [g_cdsize]
    call    mem_free
    mov     qword ptr [g_cdbuf], 0
@@:
    ; A half-written temp file is not left lying about - unless it is by now the
    ; only copy of the archive, in which case removing it is the data loss the
    ; whole ordering exists to prevent.
    cmp     dword ptr [rbp-144], 0
    jne     @F
    cmp     dword ptr [rbp-112], 0
    je      @F
    cmp     word ptr [uz_tmppath], 0
    je      @F
    lea     rcx, [uz_tmppath]
    call    file_delete
@@:
    mov     eax, dword ptr [rbp-112]
    FRAME_EPILOG
    ret
zip_delete_marked endp

; =============================================================================
; do_unzip -> eax exit code
; =============================================================================
public do_unzip
do_unzip proc frame
    FRAME_PROLOG 128
    ; [rbp-32]=count [rbp-40]=code [rbp-72]=i [rbp-80]=choff [rbp-88]=total
    mov     qword ptr [uz_count], 0
    mov     rcx, qword ptr [g_cfg_in]
    call    zip_read_cd
    test    eax, eax
    jz      du_cdok
    cmp     eax, EXIT_CORRUPT
    je      du_badzip
    cmp     eax, EXIT_OOM
    je      du_oom
    jmp     du_ioerr
du_cdok:
    mov     rax, qword ptr [g_cdcount]
    mov     qword ptr [rbp-32], rax
    ; ---- output directory --------------------------------------------------
    cmp     qword ptr [g_cfg_out], 0
    jne     du_outset
    call    uz_default_out
    lea     rcx, [uz_dflt]
    jmp     du_outnorm
du_outset:
    mov     rcx, qword ptr [g_cfg_out]
du_outnorm:
    lea     rdx, [g_outdir_np]
    call    normalize_path
    test    eax, eax
    jnz     du_ioerr
    WINCALL CreateDirectoryW, addr g_outdir_np, 0
    ; ---- progress: sum uncompressed sizes for the operation total ----------
    mov     qword ptr [rbp-88], 0            ; total usize
    mov     qword ptr [rbp-80], 0            ; choff
    mov     qword ptr [rbp-72], 0            ; i
du_sumloop:
    mov     rax, qword ptr [rbp-72]
    cmp     rax, qword ptr [rbp-32]
    jae     du_sumdone
    mov     rax, qword ptr [rbp-80]
    add     rax, 46
    cmp     rax, qword ptr [g_cdsize]
    ja      du_sumdone
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-80]
    cmp     dword ptr [rcx], SIG_CDIR
    jne     du_sumdone
    call    uz_entry_picked                  ; skipped entries are not progress
    test    eax, eax
    jz      du_sumnext
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-80]
    call    uz_entry_usize                   ; rax = ZIP64-resolved usize
    add     qword ptr [rbp-88], rax
du_sumnext:
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-80]
    movzx   eax, word ptr [rcx+28]
    movzx   r8d, word ptr [rcx+30]
    movzx   r9d, word ptr [rcx+32]
    mov     r11, qword ptr [rbp-80]
    add     r11, 46
    add     r11, rax
    add     r11, r8
    add     r11, r9
    mov     qword ptr [rbp-80], r11
    inc     qword ptr [rbp-72]
    jmp     du_sumloop
du_sumdone:
    mov     rcx, qword ptr [rbp-88]
    lea     rdx, [lbl_unzip]
    mov     r8d, lbl_unzip_len
    call    progress_begin
    ; ---- walk the central directory ----------------------------------------
    mov     qword ptr [rbp-80], 0            ; choff
    mov     qword ptr [rbp-72], 0            ; i
du_eloop:
    mov     rax, qword ptr [rbp-72]
    cmp     rax, qword ptr [rbp-32]
    jae     du_ok
    mov     rax, qword ptr [rbp-80]
    add     rax, 46
    cmp     rax, qword ptr [g_cdsize]
    ja      du_badzip
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-80]
    cmp     dword ptr [rcx], SIG_CDIR
    jne     du_badzip
    call    uz_entry_picked
    test    eax, eax
    jz      du_eskip
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-80]
    call    extract_zip_entry
    test    eax, eax
    jnz     du_entryfail
du_eskip:
    mov     rcx, qword ptr [g_cdbuf]
    add     rcx, qword ptr [rbp-80]
    movzx   eax, word ptr [rcx+28]
    movzx   r8d, word ptr [rcx+30]
    movzx   r9d, word ptr [rcx+32]
    mov     r11, qword ptr [rbp-80]
    add     r11, 46
    add     r11, rax
    add     r11, r8
    add     r11, r9
    mov     qword ptr [rbp-80], r11
    inc     qword ptr [rbp-72]
    jmp     du_eloop
du_ok:
    call    progress_done                    ; finalise the console progress line
    lea     rcx, [m_uz_done]
    mov     edx, m_uz_done_len
    call    print_a
    mov     rcx, qword ptr [uz_count]
    call    print_u64
    lea     rcx, [m_uz_done2]
    mov     edx, m_uz_done2_len
    call    print_a
    xor     eax, eax
    jmp     du_done
du_entryfail:
    jmp     du_done                          ; entry already printed its error
du_badzip:
    lea     rcx, [e_uz_badzip]
    mov     edx, e_uz_badzip_len
    call    print_a
    mov     eax, EXIT_CORRUPT
    jmp     du_done
du_oom:
    lea     rcx, [e_uz_oom]
    mov     edx, e_uz_oom_len
    call    print_a
    mov     eax, EXIT_OOM
    jmp     du_done
du_ioerr:
    lea     rcx, [e_uz_io]
    mov     edx, e_uz_io_len
    call    print_a
    mov     eax, EXIT_IO
du_done:
    mov     dword ptr [rbp-40], eax
    call    uz_wipe_keys                     ; preserves eax; see the proc
    cmp     qword ptr [g_cdbuf], 0
    je      @F
    mov     rcx, qword ptr [g_cdbuf]
    mov     rdx, qword ptr [g_cdsize]
    call    mem_free
    mov     qword ptr [g_cdbuf], 0
@@:
    cmp     qword ptr [g_uz_hin], INVALID
    je      @F
    mov     rcx, qword ptr [g_uz_hin]
    call    file_close
    mov     qword ptr [g_uz_hin], INVALID
@@:
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
do_unzip endp

; =============================================================================
; uz_default_out - uz_dflt = g_cfg_in with a trailing ".zip" removed (case-
; insensitive); if no such suffix, uz_dflt = g_cfg_in + "_files".
; =============================================================================
uz_default_out proc frame
    FRAME_PROLOG 48
    mov     rcx, qword ptr [g_cfg_in]
    xor     rax, rax
udo_len:
    cmp     word ptr [rcx+rax*2], 0
    je      udo_lend
    inc     rax
    jmp     udo_len
udo_lend:
    mov     qword ptr [rbp-24], rax
    lea     r11, [uz_dflt]
    xor     r9, r9
udo_cpy:
    cmp     r9, rax
    jae     udo_cpd
    mov     dx, word ptr [rcx+r9*2]
    mov     word ptr [r11+r9*2], dx
    inc     r9
    jmp     udo_cpy
udo_cpd:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, 4
    jb      udo_append
    mov     rcx, qword ptr [g_cfg_in]
    lea     r8, [rcx+rax*2-8]
    lea     r10, [w_ext_zip]
    xor     r9, r9
udo_cmp:
    movzx   ecx, word ptr [r8+r9*2]
    movzx   edx, word ptr [r10+r9*2]
    cmp     ecx, 'A'
    jb      @F
    cmp     ecx, 'Z'
    ja      @F
    add     ecx, 20h
@@:
    cmp     ecx, edx
    jne     udo_append
    inc     r9
    cmp     r9, 4
    jb      udo_cmp
    mov     rax, qword ptr [rbp-24]
    sub     rax, 4
    lea     r11, [uz_dflt]
    mov     word ptr [r11+rax*2], 0
    FRAME_EPILOG
    ret
udo_append:
    mov     rax, qword ptr [rbp-24]
    lea     r11, [uz_dflt]
    mov     word ptr [r11+rax*2], '_'
    mov     word ptr [r11+rax*2+2], 'f'
    mov     word ptr [r11+rax*2+4], 'i'
    mov     word ptr [r11+rax*2+6], 'l'
    mov     word ptr [r11+rax*2+8], 'e'
    mov     word ptr [r11+rax*2+10], 's'
    mov     word ptr [r11+rax*2+12], 0
    FRAME_EPILOG
    ret
uz_default_out endp

end
