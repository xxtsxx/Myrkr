; =============================================================================
; cmd.asm - encrypt / decrypt / verify / hash / bench (streaming, chunked)
; -----------------------------------------------------------------------------
; encrypt/decrypt stream the file in 1 MiB chunks through the streaming GCM
; context, so memory use is O(chunk) not O(file).  Output is written to
; OUTPUT.tmp and atomically renamed on success; on any failure (including a
; decrypt authentication failure) the temp file is deleted.
;
; Container: [64-byte header | ciphertext | 16-byte tag]  (header = GCM AAD)
; =============================================================================

include macros.inc

extern file_open_read:proc
extern file_open_write:proc
extern get_file_size:proc
extern file_read_exact:proc
extern file_write_all:proc
extern file_close:proc
extern file_rename:proc
extern file_delete:proc
extern rng_fill:proc
extern argon2id_hash:proc
extern gcm_init:proc
extern gcm_aad:proc
extern gcm_crypt:proc
extern gcm_final:proc
extern sha256_init:proc
extern sha256_update:proc
extern sha256_final:proc
extern ct_memcmp:proc
extern secure_zero:proc
extern print_a:proc
extern print_err:proc
extern hdr_bad_version:proc     ; pack.asm: one wording for a version mismatch
extern hdr_version_ok:proc      ; pack.asm: the only place the version is judged
extern print_hex:proc
extern print_wz:proc
extern print_u64:proc
extern print_u64e:proc
extern QueryPerformanceCounter:proc
extern QueryPerformanceFrequency:proc
extern GetFullPathNameW:proc
extern GetFileAttributesW:proc
extern FindFirstFileW:proc
extern FindNextFileW:proc
extern FindClose:proc
extern WideCharToMultiByte:proc
extern disk_has_space:proc
extern do_pack:proc
extern do_unpack:proc
extern vset_open:proc                    ; volume.asm: a container may be a set
extern vset_close:proc
extern vol_get:proc
extern vol_size:proc
extern vol_part_suffix:proc
extern idx_tail:proc
extern idx_auth:proc
extern entry_stream_open:proc
extern progress_begin:proc
extern progress_add:proc
extern progress_done:proc

externdef g_cfg_in:qword
externdef g_cfg_out:qword
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_cfg_t:dword
externdef g_cfg_m:dword
externdef g_cfg_pwminlen:dword
externdef g_cfg_pwminclasses:dword
externdef g_positionals:qword
externdef g_poscount:qword
externdef g_bare:dword                   ; do_pack/do_unpack mode: 1 = single-file
externdef g_peek_compress:dword          ; compression byte sampled by peek_archive
externdef g_verify_only:dword            ; pack.asm: do_unpack authenticates only
externdef g_cur_input:qword              ; per-file progress (single-file = input 0)
externdef g_file_total:qword

FILE_ATTR_DIR   equ 10h

ARGON2REQ struct
    t_cost      dd ?
    m_cost      dd ?
    lanes       dd ?
    outlen      dd ?
    version     dd ?
    atype       dd ?
    pwd         dq ?
    pwdlen      dd ?
    saltlen     dd ?
    salt        dq ?
    secret      dq ?
    secretlen   dd ?
    adlen       dd ?
    ad          dq ?
    outp        dq ?
ARGON2REQ ends

ARGON2_VERSION  equ 13h
ARGON2_TYPE_ID  equ 2
                                     ; KEY_LEN now lives in macros.inc: secmem.asm
                                     ; locks g_key and needs the same constant
GCTX_SIZE       equ 336
CHUNK           equ 100000h          ; 1 MiB
INVALID         equ -1
FILE_ATTR_DIR   equ 10h
FIND_CFILENAME  equ 44               ; offset of cFileName in WIN32_FIND_DATAW
CP_UTF8         equ 65001
externdef g_cfg_json:dword
externdef g_hstdout:qword

.const
CSTR msg_dec_ok,     "decrypted -> "
CSTR msg_verify_ok,  "verify: OK (authentic)",13,10
CSTR msg_nl,         13,10
CSTR msg_two_sp,     "  "
CSTR e_io,           "error: I/O failure (cannot open/read/write file)",13,10
CSTR e_corrupt,      "error: not a valid Myrkr container (bad magic/version/size)",13,10
CSTR e_auth,         "error: authentication failed - wrong password or corrupted file",13,10
CSTR e_oom,          "error: out of memory",13,10
CSTR e_params,       "error: container has out-of-range KDF parameters",13,10
; open_common handles single-file containers only.  Both callers now route
; archives elsewhere (decrypt -> do_unpack, verify -> do_unpack in verify-only
; mode), so this fires only if a container's archive flag disagrees with what
; peek_archive read from the same byte - i.e. never, short of a bug.  It named
; 'unpack', a verb removed when pack/unpack were folded into encrypt/decrypt,
; so it advised a command that does not exist.
CSTR e_isarchive,    "error: internal - archive container reached the single-file path",13,10
CSTR e_nospace,      "error: not enough free disk space on the output drive",13,10
CSTR e_noout,        "error: no output specified (use -o OUTPUT)",13,10
CSTR e_pw1,          "error: password does not meet policy. required: at least "
CSTR e_pw2,          " characters and at least "
CSTR e_pw3,          " of 4 classes (uppercase, lowercase, digit, symbol).",13,10
CSTR e_pw4,          "       adjust with --min-len / --min-classes, or bypass with --no-policy.",13,10
CSTR bench_pre,      "argon2id calibration (current -m/-t): "
CSTR bench_post,     " ms per derivation",13,10
CSTR lbl_decrypt,    "decrypting"
CSTR lbl_verify,     "verifying"
CSTR lbl_hash,       "hashing"
; JSON pieces for `hash --json` (newline = LF; valid JSON whitespace)
CSTR js_open,     "["
CSTR js_comma,    ","
CSTR js_rec_pre,  10,"  {",22h,"sha256",22h,":",22h     ; \n  {"sha256":"
CSTR js_rec_mid,  22h,",",22h,"path",22h,":",22h          ; ","path":"
CSTR js_rec_post, 22h,"}"                                 ; "}
CSTR js_close,    10,"]",13,10                            ; \n]\r\n
WSTR w_ext_agcm,     <.mrk>
WSTR w_ext_dec,      <.dec>

.data?
public g_key, g_temppath, g_out_np
align 16
g_key       db 32 dup (?)
g_hdr       db HDR_BYTES dup (?)     ; 80: param block (64) + KCV (16)
g_tag       db 16 dup (?)            ; computed tag
g_tag2      db 16 dup (?)            ; stored tag (decrypt)
g_digest    db 32 dup (?)
public g_gctx                           ; secmem locks it; see secmem_init
g_gctx      db GCTX_SIZE dup (?)
g_shactx    db 256 dup (?)
g_kcvctx    db 256 dup (?)           ; SHA-256 ctx for the key-check value
g_kcvdig    db 32 dup (?)            ; SHA-256(key) digest
g_kcvchk    db 16 dup (?)            ; recomputed KCV (decrypt compare)
align 16
g_in_np     dw 8000h dup (?)        ; \\?\-normalized input path
g_out_np    dw 8000h dup (?)        ; \\?\-normalized output path
g_fullbuf   dw 8000h dup (?)        ; GetFullPathNameW scratch
g_temppath  dw 8010h dup (?)        ; normalized output + ".tmp"
g_derived_out dw 8010h dup (?)      ; decrypt: output name derived from input
g_chunk     db CHUNK dup (?)
; ---- folder-hash recursion state (do_hash) --------------------------------
align 16
hg_walk     dw 8000h dup (?)        ; UTF-16 full path during the tree walk
hg_walklen  dq ?
hg_rel      db 4096 dup (?)         ; UTF-8 path relative to the root folder
hg_rellen   dq ?
hg_child    db 1024 dup (?)         ; UTF-8 child name (one level)
hg_jbuf     db 32768 dup (?)        ; JSON-escaped path scratch
g_hasherr   dd ?                    ; first IO error encountered in the walk
g_hash_first dd ?                   ; JSON: 0 until the first record is emitted

.code

prn macro msg
    lea     rcx, [msg]
    mov     edx, msg&_len
    call    print_err
endm
prn_a macro msg
    lea     rcx, [msg]
    mov     edx, msg&_len
    call    print_a
endm

; =============================================================================
; derive_key(rcx = salt ptr, edx = t_cost, r8d = m_cost_kib) -> eax 0/EXIT_OOM
; =============================================================================
public derive_key
derive_key proc frame
    FRAME_PROLOG 32 + (sizeof ARGON2REQ) + 32
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [rbp-40], r8d
    lea     r10, [rsp+32]
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r10].ARGON2REQ.t_cost, eax
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r10].ARGON2REQ.m_cost, eax
    mov     dword ptr [r10].ARGON2REQ.lanes, 1
    mov     dword ptr [r10].ARGON2REQ.outlen, KEY_LEN
    mov     dword ptr [r10].ARGON2REQ.version, ARGON2_VERSION
    mov     dword ptr [r10].ARGON2REQ.atype, ARGON2_TYPE_ID
    lea     rax, [g_cfg_pass]
    mov     qword ptr [r10].ARGON2REQ.pwd, rax
    mov     eax, dword ptr [g_cfg_passlen]
    mov     dword ptr [r10].ARGON2REQ.pwdlen, eax
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10].ARGON2REQ.salt, rax
    mov     dword ptr [r10].ARGON2REQ.saltlen, 32
    mov     qword ptr [r10].ARGON2REQ.secret, 0
    mov     dword ptr [r10].ARGON2REQ.secretlen, 0
    mov     qword ptr [r10].ARGON2REQ.ad, 0
    mov     dword ptr [r10].ARGON2REQ.adlen, 0
    lea     rax, [g_key]
    mov     qword ptr [r10].ARGON2REQ.outp, rax
    lea     rcx, [rsp+32]
    call    argon2id_hash
    test    eax, eax
    jz      dk_ok
    mov     eax, EXIT_OOM
    jmp     dk_done
dk_ok:
    xor     eax, eax
dk_done:
    FRAME_EPILOG
    ret
derive_key endp

; =============================================================================
; make_temp_path(rcx = wide src) -> g_temppath = src || ".tmp"
; =============================================================================
public make_temp_path
make_temp_path proc
    lea     r10, [g_temppath]
    xor     r9d, r9d
mtp_copy:
    movzx   eax, word ptr [rcx+r9*2]
    mov     word ptr [r10+r9*2], ax
    test    eax, eax
    jz      mtp_suffix
    inc     r9d
    cmp     r9d, 8000
    jb      mtp_copy
mtp_suffix:
    mov     word ptr [r10+r9*2], '.'
    inc     r9d
    mov     word ptr [r10+r9*2], 't'
    inc     r9d
    mov     word ptr [r10+r9*2], 'm'
    inc     r9d
    mov     word ptr [r10+r9*2], 'p'
    inc     r9d
    mov     word ptr [r10+r9*2], 0
    ret
make_temp_path endp

; =============================================================================
; wstr_copy_conv(rcx = src, rdx = dst) - copy NUL-terminated UTF-16, mapping
; '/' -> '\' (required before a \\?\ prefix, which disables normalization).
; =============================================================================
wstr_copy_conv proc
    xor     r9d, r9d
wcc_loop:
    movzx   eax, word ptr [rcx+r9*2]
    cmp     eax, 2Fh                    ; '/'
    jne     @F
    mov     eax, 5Ch                    ; '\'
@@:
    mov     word ptr [rdx+r9*2], ax
    test    eax, eax
    jz      wcc_done
    inc     r9d
    cmp     r9d, 7FF0h
    jb      wcc_loop
    mov     word ptr [rdx+r9*2], 0      ; bounded truncation
wcc_done:
    ret
wstr_copy_conv endp

; =============================================================================
; normalize_path(rcx = src, rdx = dst) -> eax 0 / EXIT_IO
; Produces an extended-length "\\?\" path so Windows allows up to 32,767 chars.
;   already "\\?\"        -> copied as-is
;   UNC "\\server\..."    -> "\\?\UNC\server\..."
;   drive "X:\..."/"X:/..."-> "\\?\X:\..."
;   relative              -> GetFullPathNameW first, then prefixed
; =============================================================================
public normalize_path
normalize_path proc frame
    FRAME_PROLOG 64                     ; 64 (alloc 80), not 48: the local at
                                        ; [rbp-40] otherwise sat in
                                        ; GetFullPathNameW's 32-byte home space,
                                        ; which a Win32 callee may save registers
                                        ; into
    mov     qword ptr [rbp-24], rcx     ; src
    mov     qword ptr [rbp-32], rdx     ; dst

    ; rule 1: already "\\?\"
    cmp     word ptr [rcx+0], 5Ch
    jne     np_notpre
    cmp     word ptr [rcx+2], 5Ch
    jne     np_notpre
    cmp     word ptr [rcx+4], 3Fh
    jne     np_notpre
    cmp     word ptr [rcx+6], 5Ch
    jne     np_notpre
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    wstr_copy_conv
    xor     eax, eax
    jmp     np_done

np_notpre:
    ; UNC absolute "\\"
    mov     rcx, qword ptr [rbp-24]
    cmp     word ptr [rcx+0], 5Ch
    jne     np_chkdrive
    cmp     word ptr [rcx+2], 5Ch
    jne     np_chkdrive
    mov     rax, rcx
    jmp     np_haveabs
np_chkdrive:
    ; drive absolute "X:\" or "X:/"
    cmp     word ptr [rcx+2], 3Ah       ; ':'
    jne     np_rel
    movzx   eax, word ptr [rcx+4]
    cmp     eax, 5Ch
    je      np_drv_ok
    cmp     eax, 2Fh
    jne     np_rel
np_drv_ok:
    mov     rax, rcx
    jmp     np_haveabs
np_rel:
    ; relative -> resolve to absolute
    WINCALL GetFullPathNameW, qword ptr [rbp-24], 8000h, addr g_fullbuf, 0
    test    eax, eax
    jz      np_io
    lea     rax, [g_fullbuf]

np_haveabs:
    mov     qword ptr [rbp-40], rax     ; base (absolute)
    mov     r10, rax
    mov     rdx, qword ptr [rbp-32]     ; dst
    cmp     word ptr [r10+0], 5Ch       ; UNC?
    jne     np_pfx_drive
    cmp     word ptr [r10+2], 5Ch
    jne     np_pfx_drive
    ; "\\?\UNC\" + (base + 2 chars)
    mov     word ptr [rdx+0],  5Ch
    mov     word ptr [rdx+2],  5Ch
    mov     word ptr [rdx+4],  3Fh
    mov     word ptr [rdx+6],  5Ch
    mov     word ptr [rdx+8],  55h      ; U
    mov     word ptr [rdx+10], 4Eh      ; N
    mov     word ptr [rdx+12], 43h      ; C
    mov     word ptr [rdx+14], 5Ch
    mov     rcx, qword ptr [rbp-40]
    add     rcx, 4                       ; skip leading "\\"
    lea     rdx, [rdx+16]
    call    wstr_copy_conv
    xor     eax, eax
    jmp     np_done
np_pfx_drive:
    mov     rdx, qword ptr [rbp-32]
    mov     word ptr [rdx+0], 5Ch
    mov     word ptr [rdx+2], 5Ch
    mov     word ptr [rdx+4], 3Fh
    mov     word ptr [rdx+6], 5Ch
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rdx+8]
    call    wstr_copy_conv
    xor     eax, eax
    jmp     np_done
np_io:
    mov     eax, EXIT_IO
np_done:
    FRAME_EPILOG
    ret
normalize_path endp

; =============================================================================
; check_password_policy() -> eax: 0 ok, 1 too short, 2 too few classes
; Counts UTF-8 code points (length) and distinct character classes of
; g_cfg_pass against g_cfg_pwminlen / g_cfg_pwminclasses.
; =============================================================================
; =============================================================================
; print_policy_error - print the password-policy requirement to stderr
; =============================================================================
public print_policy_error
print_policy_error proc frame
    FRAME_PROLOG 32
    prn     e_pw1
    mov     ecx, dword ptr [g_cfg_pwminlen]
    call    print_u64e
    prn     e_pw2
    mov     ecx, dword ptr [g_cfg_pwminclasses]
    call    print_u64e
    prn     e_pw3
    prn     e_pw4
    FRAME_EPILOG
    ret
print_policy_error endp

public check_password_policy
check_password_policy proc
    lea     r9, [g_cfg_pass]
    mov     ecx, dword ptr [g_cfg_passlen]
    xor     r10d, r10d                  ; code-point count
    xor     r11d, r11d                  ; class mask (1=U 2=L 4=D 8=S)
    xor     r8d, r8d
cpp_loop:
    cmp     r8d, ecx
    jae     cpp_eval
    movzx   eax, byte ptr [r9+r8]
    mov     edx, eax                    ; count code points: (b & 0xC0) != 0x80
    and     edx, 0C0h
    cmp     edx, 80h
    je      cpp_noinc
    inc     r10d
cpp_noinc:
    cmp     eax, 'A'
    jb      cpp_lo
    cmp     eax, 'Z'
    ja      cpp_lo
    or      r11d, 1
    jmp     cpp_next
cpp_lo:
    cmp     eax, 'a'
    jb      cpp_di
    cmp     eax, 'z'
    ja      cpp_di
    or      r11d, 2
    jmp     cpp_next
cpp_di:
    cmp     eax, '0'
    jb      cpp_sy
    cmp     eax, '9'
    ja      cpp_sy
    or      r11d, 4
    jmp     cpp_next
cpp_sy:
    or      r11d, 8
cpp_next:
    inc     r8d
    jmp     cpp_loop
cpp_eval:
    mov     eax, dword ptr [g_cfg_pwminlen]
    cmp     r10d, eax
    jb      cpp_short
    xor     eax, eax                    ; popcount of the 4-bit class mask
    test    r11d, 1
    jz      @F
    inc     eax
@@: test    r11d, 2
    jz      @F
    inc     eax
@@: test    r11d, 4
    jz      @F
    inc     eax
@@: test    r11d, 8
    jz      @F
    inc     eax
@@: cmp     eax, dword ptr [g_cfg_pwminclasses]
    jb      cpp_few
    xor     eax, eax
    ret
cpp_short:
    mov     eax, 1
    ret
cpp_few:
    mov     eax, 2
    ret
check_password_policy endp

; =============================================================================
; compute_kcv(rcx = dst) - dst[0..KCV_LEN-1] = SHA-256(g_key)[0..KCV_LEN-1].
; A key-check value: stored in the container so a wrong password is rejected
; right after key derivation, and the scheme becomes key-committing.
; =============================================================================
public compute_kcv
compute_kcv proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx     ; dst
    lea     rcx, [g_kcvctx]
    call    sha256_init
    lea     rcx, [g_kcvctx]
    lea     rdx, [g_key]
    mov     r8, KEY_LEN
    call    sha256_update
    lea     rcx, [g_kcvctx]
    lea     rdx, [g_kcvdig]
    call    sha256_final
    mov     rcx, qword ptr [rbp-24]
    lea     r10, [g_kcvdig]
    xor     r9, r9
ck_cpy:
    mov     al, byte ptr [r10+r9]
    mov     byte ptr [rcx+r9], al
    inc     r9
    cmp     r9, KCV_LEN
    jb      ck_cpy
    FRAME_EPILOG
    ret
compute_kcv endp

; =============================================================================
; do_encrypt -> eax exit code
; =============================================================================
public do_encrypt
do_encrypt proc frame
    FRAME_PROLOG 64
    ; ---- require an output (-o) --------------------------------------------
    cmp     qword ptr [g_cfg_out], 0
    jne     de_haveout
    prn     e_noout
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
de_haveout:
    ; ---- mode: a single regular-file input is a single-file (bare) container;
    ;      multiple inputs or a single directory are archived.  Both delegate to
    ;      do_pack, which applies the size-based compression default and streams
    ;      through the hardened pack path.  g_bare selects tar vs. no-tar. -------
    mov     dword ptr [g_bare], 0
    cmp     qword ptr [g_poscount], 1
    jne     de_pack
    lea     r11, [g_positionals]
    WINCALL GetFileAttributesW, qword ptr [r11+0]
    cmp     eax, -1
    je      de_setbare                  ; unreadable -> try single (clear error)
    test    eax, FILE_ATTR_DIR
    jz      de_setbare
    jmp     de_pack
de_setbare:
    mov     dword ptr [g_bare], 1
de_pack:
    call    do_pack
    FRAME_EPILOG
    ret
do_encrypt endp

; =============================================================================
; open_common(ecx = write flag: 1 decrypt, 0 verify) -> eax exit code
; =============================================================================
open_common proc frame
    FRAME_PROLOG 144                 ; 144, not 112: the logical cursor at
                                     ; [rbp-88] would sit in the outgoing
                                     ; shadow space at 112
    ; [rbp-24]=hin [rbp-32]=hout [rbp-40]=insize [rbp-48]=remaining
    ; [rbp-56]=chunklen [rbp-64]=code [rbp-72]=writeflag [rbp-80]=inventory bytes
    mov     dword ptr [rbp-72], ecx
    mov     qword ptr [rbp-24], INVALID
    mov     qword ptr [rbp-32], INVALID
    mov     word ptr [g_temppath], 0

    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_in_np]
    call    normalize_path
    test    eax, eax
    jnz     oc_io
    ; Through the volume layer, like every other container read.  This path
    ; handles STORED single-file containers, and a stored one that was split
    ; failed here with "not a valid Myrkr container" while a compressed one
    ; worked - because a compressed single-file container routes to do_unpack,
    ; which was already volume-aware, and only the stored one comes here.
    ; Found by following the pattern in docs/VOLUMES.md section 8 rather than by
    ; being reported.
    lea     rcx, [g_in_np]
    call    vset_open
    cmp     rax, INVALID
    je      oc_io
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    lea     rdx, [rbp-40]
    call    vol_size
    test    eax, eax
    jnz     oc_io
    cmp     qword ptr [rbp-40], CONTAINER_MIN_SIZE
    jb      oc_corrupt

    ; read + validate header.  idx_tail also measures the inventory the v3
    ; container carries after its payload tag, and leaves the file pointer at
    ; HDR_BYTES - where the streaming below starts.
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [g_hdr]
    call    idx_tail
    cmp     rax, 0
    jl      oc_corrupt
    mov     qword ptr [rbp-80], rax
    lea     r10, [g_hdr]
    cmp     dword ptr [r10+0], HDR_MAGIC
    jne     oc_corrupt
    mov     rcx, r10
    call    hdr_version_ok
    test    eax, eax
    jz      oc_version
    lea     r10, [g_hdr]
    cmp     byte ptr [r10+CONTAINER_HDR.lanes], 1        ; lanes
    jne     oc_corrupt
    cmp     byte ptr [r10+CONTAINER_HDR.archive], 0        ; archive flag -> use 'unpack'
    jne     oc_isarchive
    mov     eax, dword ptr [r10+8]
    cmp     eax, ARGON2_MIN_T
    jb      oc_params
    cmp     eax, ARGON2_MAX_T
    ja      oc_params
    mov     eax, dword ptr [r10+12]
    cmp     eax, ARGON2_MIN_M_KIB
    jb      oc_params
    cmp     eax, ARGON2_MAX_M_KIB
    ja      oc_params

    ; ctlen = insize - header - tag - inventory
    mov     rax, qword ptr [rbp-40]
    sub     rax, CONTAINER_MIN_SIZE
    sub     rax, qword ptr [rbp-80]
    mov     qword ptr [rbp-48], rax

    lea     rcx, [g_hdr+20]
    mov     edx, dword ptr [g_hdr+8]
    mov     r8d, dword ptr [g_hdr+12]
    call    derive_key
    test    eax, eax
    jnz     oc_oom

    ; key-check: SHA-256(key)[0..15] must match header[64..79], else wrong
    ; password -> fail fast (before streaming any data, no temp file created)
    lea     rcx, [g_kcvchk]
    call    compute_kcv
    lea     rcx, [g_kcvchk]
    lea     rdx, [g_hdr+KCV_OFFSET]
    mov     r8, KCV_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     oc_auth

    ; A single-file container is one entry, ordinal zero, framed exactly like an
    ; archive's entries - so its stream is opened the same way: counter nonce,
    ; and the ordinal bound into the AAD.  The header's old nonce field is no
    ; longer read; nonces are positions now, not stored values.
    lea     rcx, [g_gctx]
    lea     rdx, [g_hdr]
    xor     r8, r8                       ; ordinal 0
    mov     r9, 1                        ; decrypt
    lea     rax, [g_key]
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0        ; segment 0 - a single-file container is
                                 ; one entry, and B4 is what splits one
    call    entry_stream_open

    ; open output temp (decrypt only)
    cmp     dword ptr [rbp-72], 0
    je      oc_stream
    mov     rcx, qword ptr [g_cfg_out]
    lea     rdx, [g_out_np]
    call    normalize_path
    test    eax, eax
    jnz     oc_io
    ; pre-flight: the plaintext (a temp file < the input size) must fit
    lea     rcx, [g_out_np]
    mov     rdx, qword ptr [rbp-40]      ; input size (>= output)
    add     rdx, DISK_MARGIN
    call    disk_has_space
    cmp     eax, 1
    je      oc_nospace
    lea     rcx, [g_out_np]
    call    make_temp_path
    lea     rcx, [g_temppath]
    call    file_open_write
    cmp     rax, INVALID
    je      oc_io
    mov     qword ptr [rbp-32], rax

oc_stream:
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [rbp-48], rax      ; remaining = ctlen (already)
    lea     rdx, [lbl_verify]            ; label: verify unless write (decrypt)
    mov     r8d, lbl_verify_len
    cmp     dword ptr [rbp-72], 0
    je      @F
    lea     rdx, [lbl_decrypt]
    mov     r8d, lbl_decrypt_len
@@:
    mov     rcx, qword ptr [rbp-48]      ; total = ciphertext length
    call    progress_begin
    ; A LOGICAL cursor rather than the handle's file position: across a part
    ; boundary a file position means nothing.  idx_tail left the pointer at
    ; HDR_BYTES, which is where the ciphertext starts, so that is where this
    ; starts too.
    mov     qword ptr [rbp-88], HDR_BYTES
oc_loop:
    cmp     qword ptr [rbp-48], 0
    je      oc_tagcheck
    mov     r8, qword ptr [rbp-48]
    cmp     r8, CHUNK
    jbe     @F
    mov     r8, CHUNK
@@:
    mov     qword ptr [rbp-56], r8
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-88]
    lea     r8, [g_chunk]
    mov     r9, qword ptr [rbp-56]
    call    vol_get
    test    eax, eax
    jnz     oc_io
    mov     rax, qword ptr [rbp-56]
    add     qword ptr [rbp-88], rax
    lea     rcx, [g_gctx]
    lea     rdx, [g_chunk]
    lea     r8, [g_chunk]
    mov     r9, qword ptr [rbp-56]
    call    gcm_crypt
    cmp     dword ptr [rbp-72], 0
    je      oc_skipwrite
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [g_chunk]
    mov     r8, qword ptr [rbp-56]
    call    file_write_all
    test    eax, eax
    jnz     oc_io
oc_skipwrite:
    mov     rcx, qword ptr [rbp-56]
    call    progress_add
    test    eax, eax
    jnz     oc_io                        ; cancel requested -> drop temp
    mov     rax, qword ptr [rbp-56]
    sub     qword ptr [rbp-48], rax
    jmp     oc_loop

oc_tagcheck:
    call    progress_done
    ; read stored tag, compute, constant-time compare
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-88]      ; the cursor is at the tag
    lea     r8, [g_tag2]
    mov     r9, 16
    call    vol_get
    test    eax, eax
    jnz     oc_io
    lea     rcx, [g_gctx]
    lea     rdx, [g_tag]
    call    gcm_final
    lea     rcx, [g_tag]
    lea     rdx, [g_tag2]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     oc_auth
    ; ... and the inventory, which this path never reads but which is still part
    ; of the container: a byte changed inside it must fail like any other.
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-80]
    call    idx_auth
    test    eax, eax
    jz      oc_idxok
    cmp     eax, EXIT_AUTH
    je      oc_auth
    jmp     oc_io
oc_idxok:

    ; authentic
    cmp     dword ptr [rbp-72], 0
    je      oc_verify_ok
    ; decrypt: close, rename temp -> out
    mov     rcx, qword ptr [rbp-24]
    call    vset_close
    mov     qword ptr [rbp-24], INVALID
    mov     rcx, qword ptr [rbp-32]
    call    file_close
    mov     qword ptr [rbp-32], INVALID
    lea     rcx, [g_temppath]
    lea     rdx, [g_out_np]
    call    file_rename
    test    eax, eax
    jnz     oc_io
    prn_a   msg_dec_ok
    mov     rcx, qword ptr [g_cfg_out]
    call    print_wz
    lea     rcx, [msg_nl]
    mov     edx, 2
    call    print_a
    xor     eax, eax
    jmp     oc_done
oc_verify_ok:
    prn_a   msg_verify_ok
    xor     eax, eax
    jmp     oc_done

oc_auth:
    prn     e_auth
    mov     eax, EXIT_AUTH
    jmp     oc_done
oc_version:
    lea     r10, [g_hdr]
    mov     ecx, dword ptr [r10+4]
    call    hdr_bad_version
    mov     eax, EXIT_UNSUPPORTED
    jmp     oc_done
oc_corrupt:
    prn     e_corrupt
    mov     eax, EXIT_CORRUPT
    jmp     oc_done
oc_isarchive:
    prn     e_isarchive
    mov     eax, EXIT_CORRUPT
    jmp     oc_done
oc_params:
    prn     e_params
    mov     eax, EXIT_CORRUPT
    jmp     oc_done
oc_oom:
    prn     e_oom
    mov     eax, EXIT_OOM
    jmp     oc_done
oc_nospace:
    prn     e_nospace
    mov     eax, EXIT_NOSPACE
    jmp     oc_done
oc_io:
    call    progress_done
    prn     e_io
    mov     eax, EXIT_IO
oc_done:
    mov     dword ptr [rbp-64], eax
    lea     rcx, [g_key]
    mov     rdx, KEY_LEN
    call    secure_zero
    mov     rcx, qword ptr [rbp-24]
    call    vset_close
    mov     rcx, qword ptr [rbp-32]
    call    file_close
    ; on any failure with a temp open, delete it
    cmp     dword ptr [rbp-64], 0
    je      oc_ret
    cmp     dword ptr [rbp-72], 0
    je      oc_ret
    lea     rcx, [g_temppath]
    call    file_delete
oc_ret:
    mov     eax, dword ptr [rbp-64]
    FRAME_EPILOG
    ret
open_common endp

; =============================================================================
; peek_archive -> eax: 0 = single-file container, 1 = archive, 2 = unknown
; Reads just the header to classify; the real open re-reads and validates.
; =============================================================================
peek_archive proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], INVALID
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_in_np]
    call    normalize_path
    test    eax, eax
    jnz     pk_unknown
    ; THROUGH THE VOLUME LAYER, like every other container read.  This proc runs
    ; BEFORE do_unpack and decides archive-vs-single from the header; opening the
    ; file directly meant a volume set was inspected raw, so the first four bytes
    ; were MVOL rather than MYRK and decrypt reported "not a valid Myrkr
    ; container" without do_unpack ever being reached.  Every read of a container
    ; has to address the logical stream, not just the ones inside do_unpack.
    lea     rcx, [g_in_np]
    call    vset_open
    cmp     rax, INVALID
    je      pk_unknown
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    xor     rdx, rdx
    lea     r8, [g_hdr]
    mov     r9, HDR_BYTES
    call    vol_get
    test    eax, eax
    jnz     pk_close_unknown
    lea     r10, [g_hdr]
    cmp     dword ptr [r10+0], HDR_MAGIC
    jne     pk_close_unknown
    ; The silent one: hdr_version_ok prints nothing, which is what this path
    ; needs - it answers "is this one of ours?" about a file the user has only
    ; hovered over, and an error on screen for that would be absurd.
    mov     rcx, r10
    call    hdr_version_ok
    test    eax, eax
    jz      pk_close_unknown
    lea     r10, [g_hdr]
    movzx   eax, byte ptr [r10+CONTAINER_HDR.compressed]       ; compression byte
    mov     dword ptr [g_peek_compress], eax
    movzx   eax, byte ptr [r10+CONTAINER_HDR.archive]       ; archive flag
    mov     qword ptr [rbp-32], rax
    mov     rcx, qword ptr [rbp-24]
    call    vset_close
    mov     rax, qword ptr [rbp-32]
    cmp     rax, 1
    je      pk_archive
    xor     eax, eax
    jmp     pk_done
pk_archive:
    mov     eax, 1
    jmp     pk_done
pk_close_unknown:
    mov     rcx, qword ptr [rbp-24]
    call    vset_close
pk_unknown:
    mov     eax, 2
pk_done:
    FRAME_EPILOG
    ret
peek_archive endp

; =============================================================================
; derive_output_name - if no -o was given, build a default output from the
; input: strip a trailing ".mrk" (case-insensitive), else append ".dec".
; Used as the output file (single) or folder (archive) on decrypt.
; =============================================================================
derive_output_name proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_cfg_out], 0
    jne     dn_done
    mov     rcx, qword ptr [g_cfg_in]
    xor     rax, rax
dn_len:
    cmp     word ptr [rcx+rax*2], 0
    je      dn_lend
    inc     rax
    jmp     dn_len
dn_lend:
    mov     r10, rax                     ; len
    cmp     r10, 4
    jb      dn_append
    mov     r11, qword ptr [g_cfg_in]
    lea     r11, [r11+r10*2-8]           ; -> in[len-4]
    lea     r8, [w_ext_agcm]
    xor     r9, r9
dn_cmp:
    movzx   eax, word ptr [r11+r9*2]
    movzx   edx, word ptr [r8+r9*2]
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 20h
@@:
    cmp     edx, 'A'
    jb      @F
    cmp     edx, 'Z'
    ja      @F
    add     edx, 20h
@@:
    cmp     eax, edx
    jne     dn_append
    inc     r9
    cmp     r9, 4
    jb      dn_cmp
    ; matched ".mrk": copy in[0..len-4]
    mov     r8, r10
    sub     r8, 4
    ; ...and a ".partNNN" in front of it.  Shared with build_output rather
    ; than written twice: fixing only this one left the right-drag path still
    ; producing boot.wim.part001.
    mov     rcx, qword ptr [g_cfg_in]
    mov     rdx, r8
    call    vol_part_suffix
    mov     r8, rax
    mov     rcx, qword ptr [g_cfg_in]
    lea     r11, [g_derived_out]
    xor     r9, r9
dn_copy:
    cmp     r9, r8
    jae     dn_copyd
    mov     ax, word ptr [rcx+r9*2]
    mov     word ptr [r11+r9*2], ax
    inc     r9
    jmp     dn_copy
dn_copyd:
    mov     word ptr [r11+r9*2], 0
    jmp     dn_set
dn_append:
    mov     rcx, qword ptr [g_cfg_in]
    lea     r11, [g_derived_out]
    xor     r9, r9
dn_acopy:
    mov     ax, word ptr [rcx+r9*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      dn_aapp
    inc     r9
    jmp     dn_acopy
dn_aapp:
    lea     r8, [w_ext_dec]
    xor     edx, edx
dn_acp2:
    mov     ax, word ptr [r8+rdx*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      dn_set
    inc     r9
    inc     edx
    jmp     dn_acp2
dn_set:
    lea     rax, [g_derived_out]
    mov     qword ptr [g_cfg_out], rax
dn_done:
    FRAME_EPILOG
    ret
derive_output_name endp

; =============================================================================
; derive_output_dir - default destination for an ARCHIVE decrypt with no -o.
;
; An archive already carries its own top level inside the tar, so the
; destination is the folder the container SITS IN, not a new folder named after
; it.  Naming one produced Code\Code\... - the tar's Code/ nested inside a Code/
; we invented.  An explicit -o is untouched and still means "extract into this".
;
; "C:\a\Code.mrk" -> "C:\a"      "\\srv\sh\Code.mrk" -> "\\srv\sh"
; "sub\Code.mrk"  -> "sub"       "Code.mrk"          -> "."
; "C:\Code.mrk"   -> "C:\"       (a bare "C:" is drive-RELATIVE, not the root)
; =============================================================================
derive_output_dir proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_cfg_out], 0
    jne     ddir_done
    mov     rcx, qword ptr [g_cfg_in]
    lea     r11, [g_derived_out]
    xor     r9, r9
    mov     r10, -1                      ; index of the last separator seen
ddir_copy:
    mov     ax, word ptr [rcx+r9*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      ddir_cut
    cmp     ax, 5Ch                      ; '\'
    je      ddir_mark
    cmp     ax, 2Fh                      ; '/'
    jne     ddir_next
ddir_mark:
    mov     r10, r9
ddir_next:
    inc     r9
    jmp     ddir_copy
ddir_cut:
    cmp     r10, 0
    jl      ddir_cwd                     ; no separator at all -> "."
    mov     word ptr [r11+r10*2], 0      ; cut the path at the separator
    ; "C:\Code.mrk" would leave "C:", which names the drive's CURRENT directory
    ; rather than its root - put the separator back for that one shape.
    cmp     r10, 2
    jne     ddir_set
    cmp     word ptr [r11+2], 3Ah        ; ':'
    jne     ddir_set
    mov     word ptr [r11+4], 5Ch
    mov     word ptr [r11+6], 0
    jmp     ddir_set
ddir_cwd:
    mov     word ptr [r11+0], 2Eh        ; '.'
    mov     word ptr [r11+2], 0
ddir_set:
    lea     rax, [g_derived_out]
    mov     qword ptr [g_cfg_out], rax
ddir_done:
    FRAME_EPILOG
    ret
derive_output_dir endp

; =============================================================================
; do_decrypt - classify the container; archive -> extract, else single-file.
; =============================================================================
public do_decrypt
do_decrypt proc frame
    FRAME_PROLOG 32
    call    peek_archive
    cmp     eax, 1
    je      dd_archive
    cmp     eax, 2
    je      dd_single_raw                ; unknown -> let open_common surface it
    ; EVERY single-file container goes through do_unpack, compressed or not.
    ; open_common's only remaining job is the branch above: reporting that an
    ; UNRECOGNISED file is not a container, which is a verdict it is still
    ; perfectly able to reach.
    ;
    ; open_common cannot read a v6 one.  A compressed single file was already
    ; routed away from it, so the breakage only showed for a STORED one - turn
    ; Compress off in the window, encrypt one file, and the container it wrote
    ; could not be decrypted. It reported "authentication failed - wrong password
    ; or corrupted file" about a container that is perfectly sound, which is the
    ; worst possible wording for the one case where it is not true.
    ;
    ; Pre-existing, and not a volume regression: reproduced at 1.0.51, before any
    ; of the volume work existed. Found while checking whether a SPLIT stored
    ; container decrypted - it did not, and neither did an unsplit one.
    jmp     dd_bare
dd_single_raw:
    call    derive_output_name           ; default output file if no -o
    mov     ecx, 1
    call    open_common
    FRAME_EPILOG
    ret
dd_bare:
    mov     dword ptr [g_bare], 1
    call    derive_output_name           ; default output file if no -o
    call    do_unpack
    FRAME_EPILOG
    ret
dd_archive:
    mov     dword ptr [g_bare], 0
    call    derive_output_dir            ; no -o -> extract into the container's folder
    call    do_unpack
    FRAME_EPILOG
    ret
do_decrypt endp

; =============================================================================
; do_verify - authenticate a container and write nothing.
;
; Archives used to be refused here ("use 'unpack' instead" - a verb that has not
; existed since pack/unpack were folded into encrypt/decrypt).  They are not
; refused now: do_unpack already performs exactly what verify means, and running
; it with g_verify_only set streams the whole ciphertext through GCM, checks the
; tag, and skips the temp file entirely.  For an archive that is strictly better
; than decrypt-then-discard - it is the one path that authenticates without ever
; putting plaintext on disk (manifest section 14.3).
; =============================================================================
public do_verify
do_verify proc frame
    FRAME_PROLOG 32
    call    peek_archive
    cmp     eax, 1
    jne     dv_single
    mov     dword ptr [g_bare], 0
    mov     dword ptr [g_verify_only], 1
    call    do_unpack
    mov     dword ptr [g_verify_only], 0
    test    eax, eax
    jnz     dv_done
    prn     msg_verify_ok
    xor     eax, eax
    jmp     dv_done
dv_single:
    ; A single-file container verifies through do_unpack too, for the same reason
    ; decrypt does: open_common cannot read a v6 one, so verify was reporting
    ; EXIT_AUTH - "authentication failed - wrong password or corrupted file" -
    ; for EVERY single-file container, including ones that decrypt perfectly. An
    ; integrity check calling a sound archive corrupt is exactly backwards.
    ;
    ; 1.0.53 recorded this as needing a second fix, on the strength of a test run
    ; while three other changes were in flight. That was wrong: this routing is
    ; the whole fix, and the archive path had been doing it correctly all along.
    ;
    ; g_verify_only makes do_unpack build no temp file, so nothing is written and
    ; no plaintext touches the disk - the one path that authenticates without
    ; producing anything (manifest 14.3).
    mov     dword ptr [g_bare], 1
    mov     dword ptr [g_verify_only], 1
    call    do_unpack
    mov     dword ptr [g_verify_only], 0
    test    eax, eax
    jnz     dv_done
    prn     msg_verify_ok
    xor     eax, eax
dv_done:
    FRAME_EPILOG
    ret
do_verify endp

; =============================================================================
; hash_stream(rcx = wide full path, rdx = showprog) -> eax = 0 ok / EXIT_IO
; Streams SHA-256 of one file into g_digest.  showprog!=0 draws a progress bar
; (used for the single-file case; folder mode passes 0 to stay quiet).
; =============================================================================
hash_stream proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=hin [rbp-32]=remaining [rbp-40]=chunklen [rbp-48]=showprog [rbp-56]=code
    mov     qword ptr [rbp-24], INVALID
    mov     qword ptr [rbp-48], rdx
    call    file_open_read              ; rcx = path
    cmp     rax, INVALID
    je      hs_io
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    lea     rdx, [rbp-32]
    call    get_file_size
    test    eax, eax
    jnz     hs_io
    lea     rcx, [g_shactx]
    call    sha256_init
    cmp     qword ptr [rbp-48], 0
    je      hs_loop
    mov     rcx, qword ptr [rbp-32]      ; total = file size
    lea     rdx, [lbl_hash]
    mov     r8d, lbl_hash_len
    call    progress_begin
hs_loop:
    cmp     qword ptr [rbp-32], 0
    je      hs_fin
    mov     r8, qword ptr [rbp-32]
    cmp     r8, CHUNK
    jbe     @F
    mov     r8, CHUNK
@@:
    mov     qword ptr [rbp-40], r8
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_chunk]
    call    file_read_exact
    test    eax, eax
    jnz     hs_io
    lea     rcx, [g_shactx]
    lea     rdx, [g_chunk]
    mov     r8, qword ptr [rbp-40]
    call    sha256_update
    cmp     qword ptr [rbp-48], 0
    je      hs_adv
    mov     rcx, qword ptr [rbp-40]
    call    progress_add
    test    eax, eax
    jnz     hs_io                        ; cancel requested
hs_adv:
    mov     rax, qword ptr [rbp-40]
    sub     qword ptr [rbp-32], rax
    jmp     hs_loop
hs_fin:
    cmp     qword ptr [rbp-48], 0
    je      @F
    call    progress_done
@@:
    lea     rcx, [g_shactx]
    lea     rdx, [g_digest]
    call    sha256_final
    xor     eax, eax
    jmp     hs_done
hs_io:
    cmp     qword ptr [rbp-48], 0
    je      @F
    call    progress_done
@@:
    mov     eax, EXIT_IO
hs_done:
    mov     dword ptr [rbp-56], eax
    cmp     qword ptr [rbp-24], INVALID
    je      hs_noclose
    mov     rcx, qword ptr [rbp-24]
    call    file_close
hs_noclose:
    mov     eax, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
hash_stream endp

; =============================================================================
; json_puts_escaped(rcx = ptr, rdx = len) - write a JSON-escaped UTF-8 string
; to stdout.  Escapes ", \ and control chars (< 0x20); UTF-8 bytes pass through.
; =============================================================================
json_puts_escaped proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=src [rbp-32]=len [rbp-40]=i [rbp-48]=outlen
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    xor     eax, eax
    mov     qword ptr [rbp-40], rax
    mov     qword ptr [rbp-48], rax
jpe_loop:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [rbp-32]
    jae     jpe_flush
    mov     r10, qword ptr [rbp-24]
    movzx   ecx, byte ptr [r10+rax]     ; current byte
    mov     r11, qword ptr [rbp-48]     ; outlen
    lea     r8, [hg_jbuf]
    cmp     cl, 22h                     ; '"'
    je      jpe_quote
    cmp     cl, 5Ch                     ; '\'
    je      jpe_bslash
    cmp     cl, 20h
    jb      jpe_ctrl
    mov     byte ptr [r8+r11], cl
    inc     r11
    jmp     jpe_adv
jpe_quote:
    mov     byte ptr [r8+r11], 5Ch
    mov     byte ptr [r8+r11+1], 22h
    add     r11, 2
    jmp     jpe_adv
jpe_bslash:
    mov     byte ptr [r8+r11], 5Ch
    mov     byte ptr [r8+r11+1], 5Ch
    add     r11, 2
    jmp     jpe_adv
jpe_ctrl:
    mov     byte ptr [r8+r11], 5Ch
    mov     byte ptr [r8+r11+1], 'u'
    mov     byte ptr [r8+r11+2], '0'
    mov     byte ptr [r8+r11+3], '0'
    mov     edx, ecx
    shr     edx, 4
    and     edx, 0Fh
    cmp     dl, 10
    jb      @F
    add     dl, 'a'-10-'0'
@@:
    add     dl, '0'
    mov     byte ptr [r8+r11+4], dl
    mov     edx, ecx
    and     edx, 0Fh
    cmp     dl, 10
    jb      @F
    add     dl, 'a'-10-'0'
@@:
    add     dl, '0'
    mov     byte ptr [r8+r11+5], dl
    add     r11, 6
jpe_adv:
    mov     qword ptr [rbp-48], r11
    inc     qword ptr [rbp-40]
    jmp     jpe_loop
jpe_flush:
    lea     rcx, [hg_jbuf]
    mov     edx, dword ptr [rbp-48]
    call    print_a
    FRAME_EPILOG
    ret
json_puts_escaped endp

; =============================================================================
; emit_record - print the current g_digest + hg_rel (len hg_rellen) as one
; text line ("<hex>  <relpath>") or one JSON object, per g_cfg_json.
; =============================================================================
emit_record proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_cfg_json], 0
    jne     er_json
    lea     rcx, [g_digest]
    mov     edx, 32
    call    print_hex
    prn_a   msg_two_sp
    lea     rcx, [hg_rel]
    mov     edx, dword ptr [hg_rellen]
    call    print_a
    lea     rcx, [msg_nl]
    mov     edx, 2
    call    print_a
    jmp     er_done
er_json:
    cmp     dword ptr [g_hash_first], 0
    je      er_first
    prn_a   js_comma
    jmp     er_pre
er_first:
    mov     dword ptr [g_hash_first], 1
er_pre:
    prn_a   js_rec_pre
    lea     rcx, [g_digest]
    mov     edx, 32
    call    print_hex
    prn_a   js_rec_mid
    lea     rcx, [hg_rel]
    mov     rdx, qword ptr [hg_rellen]
    call    json_puts_escaped
    prn_a   js_rec_post
er_done:
    FRAME_EPILOG
    ret
emit_record endp

; =============================================================================
; hash_node - recursively hash everything under hg_walk (full path), emitting
; each file as g_digest + hg_rel (path relative to the root folder).  Mirrors
; pack_node, but seeds hg_rel empty so the root folder name is not prefixed,
; and emits a hash record per file instead of a tar entry.  First IO error is
; latched into g_hasherr and aborts the walk.
; =============================================================================
hash_node proc frame
    FRAME_PROLOG 720
    ; finddata at [rsp+64] (592 bytes); [rbp-24]=hfind [rbp-32]=walklen [rbp-40]=rellen
    WINCALL GetFileAttributesW, addr hg_walk
    cmp     eax, -1
    je      hn_err
    test    eax, FILE_ATTR_DIR
    jz      hn_isfile
    ; ---- directory: append "\*" and enumerate ----
    mov     rax, qword ptr [hg_walklen]
    lea     r10, [hg_walk]
    mov     word ptr [r10+rax*2], 5Ch
    mov     word ptr [r10+rax*2+2], '*'
    mov     word ptr [r10+rax*2+4], 0
    WINCALL FindFirstFileW, addr hg_walk, addr rsp+64
    mov     r11, qword ptr [hg_walklen]
    lea     r10, [hg_walk]
    mov     word ptr [r10+r11*2], 0     ; restore (strip "\*")
    cmp     rax, -1
    je      hn_ret                      ; empty / unreadable dir: nothing to emit
    mov     qword ptr [rbp-24], rax
hn_child:
    ; skip "." and ".."
    lea     r10, [rsp+64+FIND_CFILENAME]
    movzx   eax, word ptr [r10]
    cmp     ax, '.'
    jne     hn_dochild
    movzx   edx, word ptr [r10+2]
    test    dx, dx
    jz      hn_next
    cmp     dx, '.'
    jne     hn_dochild
    movzx   edx, word ptr [r10+4]
    test    dx, dx
    jz      hn_next
hn_dochild:
    mov     rax, qword ptr [hg_walklen]
    mov     qword ptr [rbp-32], rax
    mov     rax, qword ptr [hg_rellen]
    mov     qword ptr [rbp-40], rax
    ; hg_walk += "\" + childW
    mov     rax, qword ptr [hg_walklen]
    lea     r10, [hg_walk]
    mov     word ptr [r10+rax*2], 5Ch
    inc     rax
    lea     r11, [rsp+64+FIND_CFILENAME]
    xor     r9, r9
hn_wcpy:
    mov     dx, word ptr [r11+r9*2]
    test    dx, dx
    jz      hn_wcpyd
    mov     word ptr [r10+rax*2], dx
    inc     rax
    inc     r9
    cmp     rax, 7F00h
    jb      hn_wcpy
hn_wcpyd:
    mov     word ptr [r10+rax*2], 0
    mov     qword ptr [hg_walklen], rax
    ; child UTF-16 -> hg_child (UTF-8)
    WINCALL WideCharToMultiByte, CP_UTF8, 0, addr rsp+64+FIND_CFILENAME, -1, addr hg_child, 1024, 0, 0
    ; hg_rel += ("/" if non-empty) + hg_child
    mov     rax, qword ptr [hg_rellen]
    lea     r10, [hg_rel]
    test    rax, rax
    jz      hn_nosep
    mov     byte ptr [r10+rax], '/'
    inc     rax
hn_nosep:
    lea     r11, [hg_child]
    xor     r9, r9
hn_rcpy:
    mov     dl, byte ptr [r11+r9]
    test    dl, dl
    jz      hn_rcpyd
    mov     byte ptr [r10+rax], dl
    inc     rax
    inc     r9
    cmp     rax, 4000
    jb      hn_rcpy
hn_rcpyd:
    mov     byte ptr [r10+rax], 0
    mov     qword ptr [hg_rellen], rax
    call    hash_node
    ; restore lengths + terminators
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [hg_walklen], rax
    lea     r10, [hg_walk]
    mov     word ptr [r10+rax*2], 0
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [hg_rellen], rax
    lea     r10, [hg_rel]
    mov     byte ptr [r10+rax], 0
    cmp     dword ptr [g_hasherr], 0
    jne     hn_findclose
hn_next:
    WINCALL FindNextFileW, qword ptr [rbp-24], addr rsp+64
    test    eax, eax
    jnz     hn_child
hn_findclose:
    WINCALL FindClose, qword ptr [rbp-24]
hn_ret:
    FRAME_EPILOG
    ret
hn_isfile:
    lea     rcx, [hg_walk]
    xor     edx, edx                    ; folder mode: no per-file progress bar
    call    hash_stream
    test    eax, eax
    jnz     hn_err
    call    emit_record
    FRAME_EPILOG
    ret
hn_err:
    mov     dword ptr [g_hasherr], EXIT_IO
    FRAME_EPILOG
    ret
hash_node endp

; =============================================================================
; do_hash - SHA-256 of the input.  A single file prints "<hex>  <path>" (its
; original argument path); a folder is walked recursively and each file is
; printed as "<hex>  <relative-path-from-the-folder>".  --json emits a JSON
; array of {"sha256","path"} objects instead.  Order follows the filesystem
; enumeration; the first unreadable file aborts with EXIT_IO.
; =============================================================================
public do_hash
do_hash proc frame
    FRAME_PROLOG 112                    ; 112 (alloc 128), not 64: the 8-arg
                                        ; WideCharToMultiByte spills to [rsp+64],
                                        ; which reached the local at [rbp-56]
    ; [rbp-32]=code [rbp-40]=-o handle (INVALID=none) [rbp-48]=saved stdout [rbp-56]=attrs
    mov     dword ptr [g_hasherr], 0
    mov     dword ptr [g_hash_first], 0
    mov     qword ptr [rbp-40], INVALID
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_in_np]
    call    normalize_path
    test    eax, eax
    jnz     dh_io
    WINCALL GetFileAttributesW, addr g_in_np
    cmp     eax, -1
    je      dh_io
    mov     dword ptr [rbp-56], eax     ; save attributes across the -o open
    ; ---- optional "-o FILE": redirect this command's stdout to the file ------
    mov     rcx, qword ptr [g_cfg_out]
    test    rcx, rcx
    jz      dh_branch
    lea     rdx, [g_out_np]
    call    normalize_path
    test    eax, eax
    jnz     dh_io
    lea     rcx, [g_out_np]
    call    file_open_write
    cmp     rax, INVALID
    je      dh_io
    mov     qword ptr [rbp-40], rax
    mov     rcx, qword ptr [g_hstdout]
    mov     qword ptr [rbp-48], rcx     ; remember the real stdout
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_hstdout], rax  ; print_a/print_hex/print_wz now write the file
dh_branch:
    mov     eax, dword ptr [rbp-56]
    test    eax, FILE_ATTR_DIR
    jnz     dh_dir

    ; ---------------- single file ----------------
    cmp     dword ptr [g_cfg_json], 0
    jne     dh_file_json
    lea     rcx, [g_in_np]
    mov     edx, 1                      ; show progress
    call    hash_stream
    test    eax, eax
    jnz     dh_io
    lea     rcx, [g_digest]
    mov     edx, 32
    call    print_hex
    prn_a   msg_two_sp
    mov     rcx, qword ptr [g_cfg_in]
    call    print_wz
    lea     rcx, [msg_nl]
    mov     edx, 2
    call    print_a
    xor     eax, eax
    jmp     dh_done
dh_file_json:
    lea     rcx, [g_in_np]
    xor     edx, edx                    ; no progress: keep stdout valid JSON
    call    hash_stream
    test    eax, eax
    jnz     dh_io
    ; path = the original argument (UTF-8) into hg_rel
    WINCALL WideCharToMultiByte, CP_UTF8, 0, qword ptr [g_cfg_in], -1, addr hg_rel, 4096, 0, 0
    test    eax, eax
    jz      dh_io
    dec     eax                         ; drop the NUL from the count
    mov     ecx, eax                    ; zero-extend into the qword length
    mov     qword ptr [hg_rellen], rcx
    prn_a   js_open
    call    emit_record
    prn_a   js_close
    xor     eax, eax
    jmp     dh_done

    ; ---------------- folder ----------------
dh_dir:
    ; seed hg_walk from the normalized root; hg_rel = "" (root-relative)
    lea     r10, [g_in_np]
    lea     r11, [hg_walk]
    xor     r9, r9
dh_seed:
    mov     ax, word ptr [r10+r9*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      dh_seedd
    inc     r9
    cmp     r9, 7F00h
    jb      dh_seed
dh_seedd:
    mov     qword ptr [hg_walklen], r9
    mov     qword ptr [hg_rellen], 0
    mov     byte ptr [hg_rel], 0
    cmp     dword ptr [g_cfg_json], 0
    je      dh_walk
    prn_a   js_open
dh_walk:
    call    hash_node
    cmp     dword ptr [g_cfg_json], 0
    je      @F
    prn_a   js_close
@@:
    mov     eax, dword ptr [g_hasherr]
    test    eax, eax
    jz      dh_ok
    prn     e_io
    jmp     dh_done                     ; eax = EXIT_IO
dh_ok:
    xor     eax, eax
    jmp     dh_done
dh_io:
    prn     e_io
    mov     eax, EXIT_IO
dh_done:
    mov     dword ptr [rbp-32], eax
    ; restore stdout + close the -o file if one was opened
    cmp     qword ptr [rbp-40], INVALID
    je      dh_ret
    mov     rcx, qword ptr [rbp-48]
    mov     qword ptr [g_hstdout], rcx
    mov     rcx, qword ptr [rbp-40]
    call    file_close
dh_ret:
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
do_hash endp

; =============================================================================
; do_bench - time one Argon2id derivation at current -m/-t and report ms
; =============================================================================
public do_bench
do_bench proc frame
    FRAME_PROLOG 96 + 64
    lea     rcx, [rsp+32]
    mov     edx, 32
    call    rng_fill
    WINCALL QueryPerformanceFrequency, addr rbp-40
    WINCALL QueryPerformanceCounter, addr rbp-48
    lea     rcx, [rsp+32]
    mov     edx, dword ptr [g_cfg_t]
    mov     r8d, dword ptr [g_cfg_m]
    call    derive_key
    WINCALL QueryPerformanceCounter, addr rbp-56
    mov     rax, qword ptr [rbp-56]
    sub     rax, qword ptr [rbp-48]
    imul    rax, 1000
    xor     rdx, rdx
    div     qword ptr [rbp-40]
    mov     qword ptr [rbp-64], rax
    prn_a   bench_pre
    mov     rcx, qword ptr [rbp-64]
    call    print_u64
    prn_a   bench_post
    lea     rcx, [g_key]
    mov     rdx, KEY_LEN
    call    secure_zero
    xor     eax, eax
    FRAME_EPILOG
    ret
do_bench endp

end
