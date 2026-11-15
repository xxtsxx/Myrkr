; =============================================================================
; tcvc.asm - TrueCrypt 7.1a & VeraCrypt Read-Only Volume Container Engine
; -----------------------------------------------------------------------------
;   pbkdf2_hmac_ex         (ecx=hashId, rdx=pw, r8d=pwLen, r9=salt,
;                           [rbp+48]=saltLen, [rbp+56]=iters,
;                           [rbp+64]=outPtr, [rbp+72]=outLen) -> eax (0=ok,1=abort)
;   tcvc_mix_pool_chunk    (rcx=buf, edx=len, r8=state12, r9d=poolSize)
;   tcvc_apply_keyfiles    (rcx=pw, edx=pwLen, r8=kfArrW, r9d=kfCount,
;                           [rbp+48]=volPathW) -> eax = EXIT_*
;   tcvc_unlock_header_buf (rcx=rawHdr512, rdx=pw, r8d=pwLen, r9d=pim) -> eax = EXIT_*
;   tcvc_open              (rcx=volPathW, rdx=pw, r8d=pwLen, r9=kfArrW,
;                           [rbp+48]=kfCount) -> eax = EXIT_*
;   tcvc_open_mem          (rcx=memPtr, rdx=memSize, r8=pw, r9d=pwLen,
;                           [rbp+48]=pim) -> eax = EXIT_*
;   tcvc_read_bytes        (rcx=volOff, rdx=dstBuf, r8=byteLen) -> eax = EXIT_*
;   tcvc_close             ()
; =============================================================================

include macros.inc

extern sha512_init:proc
extern sha512_update:proc
extern sha512_final:proc
extern sha256_init:proc
extern sha256_update:proc
extern sha256_final:proc
extern blake2s_init:proc
extern blake2s_update:proc
extern blake2s_final:proc
extern whirlpool_init:proc
extern whirlpool_update:proc
extern whirlpool_final:proc
extern streebog_init:proc
extern streebog_update:proc
extern streebog_final:proc
extern rmd160_init:proc
extern rmd160_update:proc
extern rmd160_final:proc
extern argon2id_hash:proc

extern xts_mode_key_size:proc
extern xts_init:proc
extern xts_decrypt:proc
extern crc32_update:proc
externdef g_crc_table:byte

extern secure_zero:proc
extern mem_alloc:proc
extern mem_free:proc
extern normalize_path:proc
extern file_path_allowed:proc
extern file_leaf_surrogate:proc
extern file_validate_handle:proc
extern file_open_new:proc
extern file_write_all:proc
extern file_close:proc
extern file_delete:proc
extern disk_has_space:proc
extern sstk_thread_init:proc
extern sstk_thread_free:proc
extern idx_buf_ensure:proc
extern idx_buf_commit:proc
extern idx_find:proc
extern entry_path:proc
extern idx_extract_bytes:proc
extern extract_guard_reset:proc
extern extract_guard:proc
extern make_temp_sibling:proc
extern commit_temp:proc
extern pick_has:proc
extern progress_begin:proc
extern progress_add:proc
extern progress_done:proc
extern rlog_extracted:proc
extern print_a:proc
extern print_err:proc
extern print_u64:proc
extern fat_probe:proc
extern fat_enum:proc
extern fat_extract_entry:proc
extern exfat_probe:proc
extern exfat_enum:proc
extern exfat_extract_entry:proc
extern ntfs_probe:proc
extern ntfs_enum:proc
extern ntfs_extract_entry:proc
extern ext_probe:proc
extern ext_enum:proc
extern ext_extract_entry:proc
extern hfsplus_probe:proc
extern hfsplus_enum:proc
extern hfsplus_extract_entry:proc

externdef g_idxptr:qword
externdef g_idxlen:qword
externdef g_idxcount:qword
externdef g_idxflags:qword
externdef g_pick_active:dword
externdef g_outdir_np:word
externdef g_extw:word
externdef g_extmp:word
externdef g_unpack_link:dword
externdef g_cfg_in:qword
externdef g_cfg_out:qword
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword

extern CreateFileW:proc
extern CreateDirectoryW:proc
extern ReadFile:proc
extern GetFileSizeEx:proc
extern SetFilePointerEx:proc
extern SetFileTime:proc
extern CloseHandle:proc
extern GetFileAttributesW:proc
extern FindFirstFileW:proc
extern FindNextFileW:proc
extern FindClose:proc
extern CompareStringOrdinal:proc
extern VirtualAlloc:proc
extern VirtualFree:proc
extern CreateThread:proc
extern WaitForMultipleObjects:proc

; -----------------------------------------------------------------------------
; Module-private constants (TCVC_* prefix prevents cross-module collisions)
; -----------------------------------------------------------------------------
; Hash / KDF IDs: 0=SHA512, 1=SHA256, 2=BLAKE2S, 3=WHIRLPOOL, 4=STREEBOG, 5=RIPEMD160, 6=ARGON2ID
TCVC_HASH_SHA512        equ 0
TCVC_HASH_WHIRLPOOL     equ 3
TCVC_HASH_RIPEMD160     equ 5
TCVC_KDF_ARGON2ID       equ 6

; Layout inside g_tcvc_sec (TCVC_SEC_SIZE = 26512 bytes, VirtualLock'd):
TCVC_OFF_XTS            equ 0           ; 25552 bytes: active volume XTS_CTX
TCVC_OFF_PW             equ 25552       ; 128 bytes: mixed password
TCVC_OFF_POOL           equ 25680       ; 128 bytes: keyfile pool
TCVC_OFF_DK             equ 25808       ; 192 bytes: KDF derived header key
TCVC_OFF_HDR            equ 26000       ; 448 bytes: decrypted header [64..511]
TCVC_OFF_SALT           equ 26448       ; 64 bytes: raw header salt [0..63]

TCVC_MAGIC_VERA         equ 041524556h  ; "VERA" LE32
TCVC_MAGIC_TRUE         equ 045555254h  ; "TRUE" LE32

TCVC_CACHE_BYTES        equ 65536       ; 64 KiB decrypted sector cache
TCVC_KF_MAX_READ        equ 1048576     ; 1 MiB per keyfile
TCVC_MAX_PASS           equ 128         ; VeraCrypt max password length

TCVC_GEN_READ           equ 80000000h
TCVC_GEN_READ_WATTR     equ 80000100h   ; GENERIC_READ | FILE_WRITE_ATTRIBUTES
TCVC_SHARE_READ         equ 1
TCVC_SHARE_RW           equ 3
TCVC_OPEN_EXISTING      equ 3
TCVC_INV_ATTR           equ 0FFFFFFFFh
TCVC_ATTR_HIDDEN        equ 2
TCVC_ATTR_DIR           equ 10h
TCVC_ATTR_REPARSE       equ 400h
TCVC_REPARSE_SURR       equ 20000000h
TCVC_CSTR_EQUAL         equ 2
TCVC_MEM_COMMIT_RES     equ 3000h
TCVC_MEM_RELEASE        equ 8000h
TCVC_PAGE_RW            equ 04h
TCVC_INFINITE           equ 0FFFFFFFFh

; Per-worker slot in transient VirtualAlloc unlock arena (6 workers * 26624 = 159744)
;   [0     .. 25551]  worker XTS_CTX (25552 bytes, 16-aligned)
;   [25552 .. 25743]  worker dk[192]
;   [25744 .. 26191]  worker hdr_try[448]
;   [26192 .. 26239]  job params:
;                       +0  dd hashId
;                       +4  dd iterations
;                       +8  dd reqVera     (1 = VERA, 0 = TRUE)
;                       +12 dd matchedMode (-1 or 0..14)
;                       +16 dd errCode     (0 or EXIT_UNSUPPORTED / EXIT_CORRUPT)
;                       +20 dd slotIdx
;                       +24 dq encHdr448Ptr
;                       +32 dq pwPtr
;                       +40 dd pwLen
;                       +44 dd pad
TCVC_SLOT_BYTES         equ 26624
TCVC_ARENA_BYTES        equ (6 * TCVC_SLOT_BYTES)
TCVC_SLOT_DK            equ 25552
TCVC_SLOT_HDR           equ 25744
TCVC_SLOT_JOB           equ 26192

.const
align 8
; Hash vtable: 6 * 32 bytes
;   +0  dq init_fn
;   +8  dq update_fn
;   +16 dq final_fn
;   +24 dw blockSize, digestSize, ctxSize, 0
tcvc_hash_vtbl label qword
    dq sha512_init,    sha512_update,    sha512_final
    dw 128, 64, 216, 0
    dq sha256_init,    sha256_update,    sha256_final
    dw 64,  32, 112, 0
    dq blake2s_init,   blake2s_update,   blake2s_final
    dw 64,  32, 120, 0
    dq whirlpool_init, whirlpool_update, whirlpool_final
    dw 64,  64, 152, 0
    dq streebog_init,  streebog_update,  streebog_final
    dw 64,  64, 264, 0
    dq rmd160_init,    rmd160_update,    rmd160_final
    dw 64,  20,  96, 0

align 4
; TrueCrypt 7.1a fast-path table: { hashId, iterations }
tcvc_tc_kdfs label dword
    dd TCVC_HASH_RIPEMD160, 2000
    dd TCVC_HASH_SHA512,    1000
    dd TCVC_HASH_WHIRLPOOL, 1000
    dd TCVC_HASH_RIPEMD160, 1000

; VeraCrypt default (PIM=0) PBKDF2 iterations indexed by hashId 0..5
tcvc_vc_def_iters label dword
    dd 500000                               ; SHA-512
    dd 500000                               ; SHA-256
    dd 500000                               ; BLAKE2s-256
    dd 500000                               ; Whirlpool
    dd 500000                               ; Streebog-512
    dd 655331                               ; RIPEMD-160

CSTR lbl_tcvc_ext,     "extracting"
CSTR msg_tcvc_done1,   "extracted "
CSTR msg_tcvc_done2,   " file(s)",13,10
CSTR msg_tcvc_ver_ok,  "verified: OK",13,10
CSTR e_tcvc_auth,      "error: authentication failed - wrong password/keyfile or not a TrueCrypt/VeraCrypt volume",13,10
CSTR e_tcvc_corrupt,   "error: corrupt or truncated TrueCrypt/VeraCrypt volume or filesystem",13,10
CSTR e_tcvc_unsup,     "error: unsupported volume parameters or unrecognised filesystem",13,10
CSTR e_tcvc_io,        "error: I/O failure",13,10
CSTR e_tcvc_oom,       "error: out of memory",13,10
CSTR e_tcvc_nospace,   "error: not enough free disk space",13,10
CSTR e_tcvc_idxfull,   "error: too many entries for one container - the inventory is full.",13,10

align 2
WSTR ws_tc_fmt_tc,     <TrueCrypt>
WSTR ws_tc_fmt_vc,     <VeraCrypt>
ws_tc_sep              dw ' ', 00B7h, ' ', 0
WSTR ws_tc_ro,         <Read-Only (XTS)>
WSTR ws_tc_unk,        <?>

WSTR ws_tc_m0,         <AES-256>
WSTR ws_tc_m1,         <Serpent>
WSTR ws_tc_m2,         <Twofish>
WSTR ws_tc_m3,         <Camellia>
WSTR ws_tc_m4,         <Kuznyechik>
WSTR ws_tc_m5,         <AES-Twofish>
WSTR ws_tc_m6,         <AES-Twofish-Serpent>
WSTR ws_tc_m7,         <Serpent-AES>
WSTR ws_tc_m8,         <Serpent-Twofish-AES>
WSTR ws_tc_m9,         <Twofish-Serpent>
WSTR ws_tc_m10,        <Camellia-Kuznyechik>
WSTR ws_tc_m11,        <Kuznyechik-Twofish>
WSTR ws_tc_m12,        <Camellia-Serpent>
WSTR ws_tc_m13,        <Kuznyechik-AES>
WSTR ws_tc_m14,        <Kuznyechik-Serpent-Camellia>

WSTR ws_tc_k0,         <SHA-512>
WSTR ws_tc_k1,         <SHA-256>
WSTR ws_tc_k2,         <BLAKE2s>
WSTR ws_tc_k3,         <Whirlpool>
WSTR ws_tc_k4,         <Streebog>
WSTR ws_tc_k5,         <RIPEMD-160>
WSTR ws_tc_k6,         <Argon2id>

WSTR ws_tc_f1,         <FAT12>
WSTR ws_tc_f2,         <FAT16>
WSTR ws_tc_f3,         <FAT32>
WSTR ws_tc_f4,         <exFAT>
WSTR ws_tc_f5,         <NTFS>
WSTR ws_tc_f6,         <ext2/3/4>
WSTR ws_tc_f7,         <HFS+>

align 8
tcvc_mode_names label qword
    dq ws_tc_m0,  ws_tc_m1,  ws_tc_m2,  ws_tc_m3,  ws_tc_m4
    dq ws_tc_m5,  ws_tc_m6,  ws_tc_m7,  ws_tc_m8,  ws_tc_m9
    dq ws_tc_m10, ws_tc_m11, ws_tc_m12, ws_tc_m13, ws_tc_m14

tcvc_kdf_names label qword
    dq ws_tc_k0, ws_tc_k1, ws_tc_k2, ws_tc_k3, ws_tc_k4, ws_tc_k5, ws_tc_k6

tcvc_fs_names label qword
    dq ws_tc_unk, ws_tc_f1, ws_tc_f2, ws_tc_f3, ws_tc_f4, ws_tc_f5, ws_tc_f6, ws_tc_f7

.data?
align 16
public g_tcvc_sec
g_tcvc_sec          db TCVC_SEC_SIZE dup (?)

align 8
public g_tcvc_data_size
public g_tcvc_sec_size
public g_tcvc_is_vera
public g_tcvc_mode_id
public g_tcvc_kdf_id
public g_tcvc_open_flag
public g_tcvc_fs_id
public g_kf_paths
public g_kf_count

g_kf_paths          dq MAX_KEYFILES dup (?)
g_tcvc_hfile        dq ?
g_tcvc_mem_ptr      dq ?
g_tcvc_host_size    dq ?
g_tcvc_data_off     dq ?
g_tcvc_data_size    dq ?
g_tcvc_cache_ptr    dq ?
g_tcvc_cache_base   dq ?
g_tcvc_hout         dq ?
g_tcvc_mem          dq ?
g_tcvc_memcap       dq ?
g_tcvc_memlen       dq ?
g_tcvc_fcount       dq ?

g_kf_count          dd ?
g_tcvc_fs_id        dd ?
g_tcvc_sec_size     dd ?
g_tcvc_is_vera      dd ?
g_tcvc_mode_id      dd ?
g_tcvc_kdf_id       dd ?
g_tcvc_open_flag    dd ?
g_tcvc_cache_len    dd ?
g_tcvc_pw_len       dd ?
g_tcvc_tables_ready dd ?
g_tcvc_abort        dd ?
g_tcvc_win_slot     dd ?

align 8
g_tcvc_wfd          db 600 dup (?)          ; WIN32_FIND_DATAW (592 bytes)
align 2
g_tcvc_path1        dw (MAX_PATH_CHARS + 16) dup (?)
g_tcvc_path2        dw (MAX_PATH_CHARS + 16) dup (?)
g_tcvc_vol_np       dw (MAX_PATH_CHARS + 16) dup (?)
g_tcvc_dflt_out     dw (MAX_PATH_CHARS + 16) dup (?)
align 16
g_tcvc_idxname      db 4096 dup (?)

.code

; =============================================================================
; tcvc_ensure_tables() - pre-warms all lazy lookup tables on the calling thread
; before worker threads are spawned so parallel workers never race on init.
; =============================================================================
tcvc_ensure_tables proc frame
    FRAME_PROLOG 368
    ; [rsp+32..303] = 272-byte dummy ctx / key buffer
    cmp     dword ptr [g_tcvc_tables_ready], 0
    jne     tet_done

    ; Zero [rsp+32..127] for dummy 32-byte key
    lea     rcx, [rsp+32]
    mov     edx, 96
    call    secure_zero

    ; 1. CRC-32 table
    xor     ecx, ecx
    lea     rdx, [rsp+32]
    xor     r8d, r8d
    call    crc32_update

    ; 2. Whirlpool & Streebog tables
    lea     rcx, [rsp+32]
    call    whirlpool_init
    lea     rcx, [rsp+32]
    call    streebog_init

    ; 3. Twofish (mode 2), Camellia (mode 3), Kuznyechik (mode 4) tables
    mov     ecx, 2
    lea     rdx, [rsp+32]
    lea     r8,  [rsp+64]
    lea     r9,  [g_tcvc_sec]
    call    xts_init

    mov     ecx, 3
    lea     rdx, [rsp+32]
    lea     r8,  [rsp+64]
    lea     r9,  [g_tcvc_sec]
    call    xts_init

    mov     ecx, 4
    lea     rdx, [rsp+32]
    lea     r8,  [rsp+64]
    lea     r9,  [g_tcvc_sec]
    call    xts_init

    lea     rcx, [g_tcvc_sec]
    mov     edx, 25552
    call    secure_zero
    lea     rcx, [rsp+32]
    mov     edx, 272
    call    secure_zero

    mov     dword ptr [g_tcvc_tables_ready], 1
tet_done:
    FRAME_EPILOG
    ret
tcvc_ensure_tables endp

; =============================================================================
; pbkdf2_hmac_ex(ecx = hashId, rdx = pwPtr, r8d = pwLen, r9 = saltPtr,
;                [rbp+48] = saltLen, [rbp+56] = iterations,
;                [rbp+64] = outPtr,  [rbp+72] = outLen)
;   -> eax = 0 ok, 1 aborted via g_tcvc_abort
; Stack-only state: safe for concurrent execution across worker threads.
; =============================================================================
public pbkdf2_hmac_ex
pbkdf2_hmac_ex proc frame
    ; Stack layout (FRAME_PROLOG 1488 -> alloc 1504):
    ;   [rbp-16..64]     saved r12..r15, rbx, rsi, rdi
    ;   [rbp-72]         vtbl entry ptr
    ;   [rbp-80]         saltPtr
    ;   [rbp-88]         outPtr
    ;   [rbp-96]         blockSize (dd at -96), digestSize (dd at -92)
    ;   [rbp-104]        ctxSize   (dd at -104), blockIdx  (dd at -100)
    ;   [rbp-112]        remOut    (dd at -112), saltLen   (dd at -108)
    ;   [rbp-120]        iters     (dd at -120), retCode   (dd at -116)
    ;   [rsp+32  .. 303] innerCtx  (272B)
    ;   [rsp+304 .. 575] outerCtx  (272B)
    ;   [rsp+576 .. 847] workCtx   (272B)
    ;   [rsp+848 .. 975] padBuf    (128B: ipad/opad/hashedKey)
    ;   [rsp+976 ..1039] keyHash   (64B)
    ;   [rsp+1040..1183] kBuf      (144B: salt(<=128) || BE32(i), or digest(<=64))
    ;   [rsp+1184..1247] uBuf      (64B: XOR accumulator)
    FRAME_PROLOG 1488
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    BOUND_CHECK rcx, 6
    shl     ecx, 5
    lea     rax, [tcvc_hash_vtbl]
    add     rax, rcx
    mov     qword ptr [rbp-72], rax         ; vtbl ptr

    mov     r12, rdx                        ; pwPtr
    mov     r13d, r8d                       ; pwLen
    mov     qword ptr [rbp-80], r9          ; saltPtr

    mov     ecx, dword ptr [rbp+48]         ; saltLen
    cmp     ecx, 128
    ja      pbk_abort_early
    mov     dword ptr [rbp-108], ecx

    mov     ecx, dword ptr [rbp+56]         ; iterations
    test    ecx, ecx
    jz      pbk_abort_early
    mov     dword ptr [rbp-120], ecx

    mov     rcx, qword ptr [rbp+64]         ; outPtr
    mov     qword ptr [rbp-88], rcx
    mov     ecx, dword ptr [rbp+72]         ; outLen
    mov     dword ptr [rbp-112], ecx
    mov     dword ptr [rbp-116], 0          ; retCode = 0

    movzx   ecx, word ptr [rax+24]          ; blockSize
    mov     dword ptr [rbp-96], ecx
    movzx   edx, word ptr [rax+26]          ; digestSize
    mov     dword ptr [rbp-92], edx
    movzx   ecx, word ptr [rax+28]          ; ctxSize
    mov     dword ptr [rbp-104], ecx

    ; If pwLen > blockSize, hash password first into keyHash [rsp+976]
    cmp     r13d, dword ptr [rbp-96]
    jbe     pbk_key_ready

    lea     rcx, [rsp+576]
    mov     r14, qword ptr [rax]            ; init_fn
    CALL_GUARDED r14

    lea     rcx, [rsp+576]
    mov     rdx, r12
    mov     r8d, r13d
    mov     rax, qword ptr [rbp-72]
    mov     r14, qword ptr [rax+8]          ; update_fn
    CALL_GUARDED r14

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+976]
    mov     rax, qword ptr [rbp-72]
    mov     r14, qword ptr [rax+16]         ; final_fn
    CALL_GUARDED r14

    lea     r12, [rsp+976]
    mov     r13d, dword ptr [rbp-92]        ; pwLen = digestSize

pbk_key_ready:
    ; Build ipad in [rsp+848] and precompute innerCtx [rsp+32]
    mov     ebx, dword ptr [rbp-96]         ; blockSize
    xor     ecx, ecx
pbk_ipad_lp:
    mov     al, 036h
    cmp     ecx, r13d
    jae     pbk_ipad_st
    xor     al, byte ptr [r12+rcx]
pbk_ipad_st:
    mov     byte ptr [rsp+848+rcx], al
    inc     ecx
    cmp     ecx, ebx
    jb      pbk_ipad_lp

    lea     rcx, [rsp+32]
    mov     rax, qword ptr [rbp-72]
    mov     r14, qword ptr [rax]            ; init_fn
    CALL_GUARDED r14

    lea     rcx, [rsp+32]
    lea     rdx, [rsp+848]
    mov     r8d, ebx
    mov     rax, qword ptr [rbp-72]
    mov     r14, qword ptr [rax+8]          ; update_fn
    CALL_GUARDED r14

    ; Build opad in [rsp+848] and precompute outerCtx [rsp+304]
    xor     ecx, ecx
pbk_opad_lp:
    mov     al, 05Ch
    cmp     ecx, r13d
    jae     pbk_opad_st
    xor     al, byte ptr [r12+rcx]
pbk_opad_st:
    mov     byte ptr [rsp+848+rcx], al
    inc     ecx
    cmp     ecx, ebx
    jb      pbk_opad_lp

    lea     rcx, [rsp+304]
    mov     rax, qword ptr [rbp-72]
    mov     r14, qword ptr [rax]            ; init_fn
    CALL_GUARDED r14

    lea     rcx, [rsp+304]
    lea     rdx, [rsp+848]
    mov     r8d, ebx
    mov     rax, qword ptr [rbp-72]
    mov     r14, qword ptr [rax+8]          ; update_fn
    CALL_GUARDED r14

    ; Cache update_fn in r14, final_fn in r15
    mov     rax, qword ptr [rbp-72]
    mov     r14, qword ptr [rax+8]          ; update_fn
    mov     r15, qword ptr [rax+16]         ; final_fn
    mov     dword ptr [rbp-100], 1          ; blockIdx = 1

pbk_blk_loop:
    cmp     dword ptr [rbp-112], 0
    je      pbk_wipe

    ; ---- Iteration 1: HMAC(salt || BE32(blockIdx)) --------------------------
    lea     rdi, [rsp+1040]                 ; kBuf
    mov     rsi, qword ptr [rbp-80]         ; saltPtr
    mov     ecx, dword ptr [rbp-108]        ; saltLen
    rep     movsb
    mov     eax, dword ptr [rbp-100]
    bswap   eax
    mov     dword ptr [rdi], eax

    ; Copy innerCtx -> workCtx
    lea     rdi, [rsp+576]
    lea     rsi, [rsp+32]
    mov     ecx, dword ptr [rbp-104]
    rep     movsb

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+1040]
    mov     r8d, dword ptr [rbp-108]
    add     r8d, 4
    CALL_GUARDED r14

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+1040]
    CALL_GUARDED r15

    ; Copy outerCtx -> workCtx
    lea     rdi, [rsp+576]
    lea     rsi, [rsp+304]
    mov     ecx, dword ptr [rbp-104]
    rep     movsb

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+1040]
    mov     r8d, dword ptr [rbp-92]         ; digestSize
    CALL_GUARDED r14

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+1040]
    CALL_GUARDED r15

    ; uBuf = U_1
    lea     rdi, [rsp+1184]
    lea     rsi, [rsp+1040]
    mov     ecx, dword ptr [rbp-92]
    rep     movsb

    ; ---- Remaining iterations 2 .. iters ------------------------------------
    mov     ebx, dword ptr [rbp-120]
    dec     ebx
    jz      pbk_blk_emit

pbk_iter_loop:
    test    ebx, 1023
    jnz     pbk_no_abort
    cmp     dword ptr [g_tcvc_abort], 0
    jne     pbk_aborted
pbk_no_abort:
    ; Copy innerCtx -> workCtx
    lea     rdi, [rsp+576]
    lea     rsi, [rsp+32]
    mov     ecx, dword ptr [rbp-104]
    rep     movsb

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+1040]
    mov     r8d, dword ptr [rbp-92]
    CALL_GUARDED r14

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+1040]
    CALL_GUARDED r15

    ; Copy outerCtx -> workCtx
    lea     rdi, [rsp+576]
    lea     rsi, [rsp+304]
    mov     ecx, dword ptr [rbp-104]
    rep     movsb

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+1040]
    mov     r8d, dword ptr [rbp-92]
    CALL_GUARDED r14

    lea     rcx, [rsp+576]
    lea     rdx, [rsp+1040]
    CALL_GUARDED r15

    ; XOR kBuf into uBuf (8 bytes at a time for 32/64B, 4 bytes for 20B)
    mov     ecx, dword ptr [rbp-92]
    shr     ecx, 2                          ; dwords (5, 8, or 16)
    xor     edx, edx
pbk_xor_lp:
    mov     eax, dword ptr [rsp+1040+rdx*4]
    xor     dword ptr [rsp+1184+rdx*4], eax
    inc     edx
    cmp     edx, ecx
    jb      pbk_xor_lp

    dec     ebx
    jnz     pbk_iter_loop

pbk_blk_emit:
    mov     ecx, dword ptr [rbp-92]         ; digestSize
    cmp     ecx, dword ptr [rbp-112]
    jbe     pbk_copy_len_ok
    mov     ecx, dword ptr [rbp-112]
pbk_copy_len_ok:
    mov     rdi, qword ptr [rbp-88]
    lea     rsi, [rsp+1184]
    mov     edx, ecx
    rep     movsb
    mov     qword ptr [rbp-88], rdi
    sub     dword ptr [rbp-112], edx
    inc     dword ptr [rbp-100]
    jmp     pbk_blk_loop

pbk_abort_early:
pbk_aborted:
    mov     dword ptr [rbp-116], 1

pbk_wipe:
    lea     rcx, [rsp+32]
    mov     edx, 1216                       ; wipe innerCtx..uBuf (32..1247)
    call    secure_zero

    mov     eax, dword ptr [rbp-116]
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
pbkdf2_hmac_ex endp

; =============================================================================
; tcvc_mix_pool_chunk(rcx = buf, edx = len, r8 = state12, r9d = poolSize)
; Mixes up to (1 MiB - totalRead) bytes into g_tcvc_sec + TCVC_OFF_POOL using
; TrueCrypt/VeraCrypt rolling CRC-32 pool addition (Keyfiles.c:189-203).
; state12 layout: [0]=crc (init 0xFFFFFFFF), [4]=writePos, [8]=totalRead.
; =============================================================================
public tcvc_mix_pool_chunk
tcvc_mix_pool_chunk proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    mov     rsi, rcx                        ; buf
    mov     ebx, edx                        ; len
    mov     rdi, r8                         ; state12

    ; Ensure g_crc_table is initialized
    cmp     dword ptr [g_tcvc_tables_ready], 0
    jne     tmpc_tbl_ok
    mov     dword ptr [rbp-40], r9d
    xor     ecx, ecx
    mov     rdx, rsi
    xor     r8d, r8d
    call    crc32_update
    mov     r9d, dword ptr [rbp-40]
tmpc_tbl_ok:

    test    ebx, ebx
    jz      tmpc_done

    lea     r10, [g_crc_table]
    lea     r11, [g_tcvc_sec + TCVC_OFF_POOL]
    mov     eax, dword ptr [rdi]            ; crc
    mov     ecx, dword ptr [rdi+4]          ; writePos
    mov     edx, dword ptr [rdi+8]          ; totalRead

tmpc_loop:
    cmp     edx, TCVC_KF_MAX_READ
    jae     tmpc_save

    movzx   r8d, byte ptr [rsi]
    inc     rsi
    xor     r8d, eax
    movzx   r8d, r8b
    shr     eax, 8
    xor     eax, dword ptr [r10+r8*4]       ; crc = UPDC32(byte, crc)

    ; keyPool[writePos..+3] += BE32(crc) bytes, wrapping at poolSize (64 or 128, multiple of 4)
    mov     r8d, eax
    shr     r8d, 24
    add     byte ptr [r11+rcx], r8b
    mov     r8d, eax
    shr     r8d, 16
    add     byte ptr [r11+rcx+1], r8b
    mov     r8d, eax
    shr     r8d, 8
    add     byte ptr [r11+rcx+2], r8b
    add     byte ptr [r11+rcx+3], al

    add     ecx, 4
    cmp     ecx, r9d
    jb      tmpc_nw
    xor     ecx, ecx
tmpc_nw:
    inc     edx
    dec     ebx
    jnz     tmpc_loop

tmpc_save:
    mov     dword ptr [rdi],   eax
    mov     dword ptr [rdi+4], ecx
    mov     dword ptr [rdi+8], edx

tmpc_done:
    xor     eax, eax
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
tcvc_mix_pool_chunk endp

; =============================================================================
; tcvc_mix_one_keyfile(rcx = kfPathW, edx = poolSize, r8 = scratch64k) -> eax = EXIT_*
; =============================================================================
tcvc_mix_one_keyfile proc frame
    FRAME_PROLOG 144
    ; [rbp-16..48] = r12, r13, rbx, rsi, rdi
    ; [rbp-64..-53] = state12 { crc, writePos, totalRead }
    ; [rbp-72..-65] = FILETIME { 0xFFFFFFFF, 0xFFFFFFFF }
    ; [rbp-80]      = bytesRead (dd)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], rbx
    mov     qword ptr [rbp-40], rsi
    mov     qword ptr [rbp-48], rdi

    mov     rsi, rcx                        ; kfPathW
    mov     r12d, edx                       ; poolSize
    mov     r13, r8                         ; scratch64k

    call    file_path_allowed
    test    eax, eax
    jz      tmok_io_err
    mov     rcx, rsi
    call    file_leaf_surrogate
    test    eax, eax
    jnz     tmok_io_err

    ; Try opening with FILE_WRITE_ATTRIBUTES to suppress LastAccessTime updates
    WINCALL CreateFileW, rsi, TCVC_GEN_READ_WATTR, TCVC_SHARE_RW, 0, TCVC_OPEN_EXISTING, 0, 0
    cmp     rax, -1
    je      tmok_open_ro
    mov     rbx, rax
    mov     dword ptr [rbp-72], 0FFFFFFFFh
    mov     dword ptr [rbp-68], 0FFFFFFFFh
    WINCALL SetFileTime, rbx, 0, addr rbp-72, 0
    jmp     tmok_opened

tmok_open_ro:
    WINCALL CreateFileW, rsi, TCVC_GEN_READ, TCVC_SHARE_RW, 0, TCVC_OPEN_EXISTING, 0, 0
    cmp     rax, -1
    je      tmok_io_err
    mov     rbx, rax

tmok_opened:
    mov     rcx, rbx
    call    file_validate_handle
    test    eax, eax
    jz      tmok_close_err

    mov     dword ptr [rbp-64], 0FFFFFFFFh  ; crc = 0xFFFFFFFF
    mov     dword ptr [rbp-60], 0           ; writePos = 0
    mov     dword ptr [rbp-56], 0           ; totalRead = 0

tmok_rd_lp:
    cmp     dword ptr [rbp-56], TCVC_KF_MAX_READ
    jae     tmok_rd_done

    mov     dword ptr [rbp-80], 0
    WINCALL ReadFile, rbx, r13, 65536, addr rbp-80, 0
    test    eax, eax
    jz      tmok_close_err

    mov     edx, dword ptr [rbp-80]
    test    edx, edx
    jz      tmok_rd_done

    mov     rcx, r13
    lea     r8,  [rbp-64]
    mov     r9d, r12d
    call    tcvc_mix_pool_chunk
    jmp     tmok_rd_lp

tmok_rd_done:
    ; Empty (0-byte) keyfile is rejected by TrueCrypt/VeraCrypt (Keyfiles.c:210)
    cmp     dword ptr [rbp-56], 0
    je      tmok_close_err

    WINCALL CloseHandle, rbx
    xor     eax, eax                        ; EXIT_OK
    jmp     tmok_out

tmok_close_err:
    WINCALL CloseHandle, rbx
tmok_io_err:
    mov     eax, EXIT_IO

tmok_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     rbx, qword ptr [rbp-32]
    mov     rsi, qword ptr [rbp-40]
    mov     rdi, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
tcvc_mix_one_keyfile endp

; =============================================================================
; tcvc_apply_keyfiles(rcx = pwPtr, edx = pwLen, r8 = kfArrW, r9d = kfCount,
;                     [rbp+48] = volPathW) -> eax = EXIT_*
; Writes mixed password into g_tcvc_sec + TCVC_OFF_PW and length into g_tcvc_pw_len.
; =============================================================================
public tcvc_apply_keyfiles
tcvc_apply_keyfiles proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     r12, rcx                        ; pwPtr
    mov     r13d, edx                       ; pwLen
    mov     r14, r8                         ; kfArrW
    mov     r15d, r9d                       ; kfCount

    cmp     r13d, TCVC_MAX_PASS
    ja      tak_auth_err

    ; Wipe pw_mixed and kf_pool
    lea     rcx, [g_tcvc_sec + TCVC_OFF_PW]
    mov     edx, 256
    call    secure_zero

    ; Copy raw password into pw_mixed
    test    r13d, r13d
    jz      tak_chk_kf
    lea     rdi, [g_tcvc_sec + TCVC_OFF_PW]
    mov     rsi, r12
    mov     ecx, r13d
    rep     movsb

tak_chk_kf:
    mov     dword ptr [g_tcvc_pw_len], r13d
    test    r15d, r15d
    jz      tak_ok_nokf

    ; Determine poolSize: <= 64 -> 64, > 64 -> 128
    mov     ebx, 64
    cmp     r13d, 64
    jbe     tak_pool_sz
    mov     ebx, 128
tak_pool_sz:
    mov     dword ptr [rbp-72], ebx         ; poolSize

    mov     ecx, 65536
    call    mem_alloc
    test    rax, rax
    jz      tak_oom
    mov     qword ptr [rbp-80], rax         ; scratch64k

    xor     edi, edi                        ; kf index = 0..kfCount-1
tak_kf_loop:
    cmp     edi, r15d
    jae     tak_mix_final

    mov     rsi, qword ptr [r14 + rdi*8]    ; kfPathW
    test    rsi, rsi
    jz      tak_io_free

    mov     rcx, rsi
    lea     rdx, [g_tcvc_path1]
    call    normalize_path
    test    eax, eax
    jnz     tak_io_free
    lea     rsi, [g_tcvc_path1]

    mov     rcx, rsi
    call    file_path_allowed
    test    eax, eax
    jz      tak_io_free
    mov     rcx, rsi
    call    file_leaf_surrogate
    test    eax, eax
    jnz     tak_io_free

    WINCALL GetFileAttributesW, rsi
    cmp     eax, TCVC_INV_ATTR
    je      tak_io_free
    test    eax, TCVC_ATTR_DIR
    jz      tak_single_file

    ; ---- Directory keyfile path: non-recursive, skip hidden & container ------
    ; g_tcvc_path1 already holds canonicalized path; strip trailing slashes, append "\*.*"
    lea     rdx, [g_tcvc_path1]
    xor     ecx, ecx
tak_cp_dir:
    cmp     word ptr [rdx + rcx*2], 0
    je      tak_dir_copied
    inc     ecx
    cmp     ecx, MAX_PATH_CHARS - 8
    jae     tak_io_free
    jmp     tak_cp_dir

tak_dir_copied:
    test    ecx, ecx
    jz      tak_io_free
tak_trim_sl:
    test    ecx, ecx
    jz      tak_trim_done
    mov     ax, word ptr [rdx + rcx*2 - 2]
    cmp     ax, 5Ch
    je      tak_do_trim
    cmp     ax, '/'
    jne     tak_trim_done
tak_do_trim:
    dec     ecx
    jmp     tak_trim_sl

tak_trim_done:
    mov     dword ptr [rbp-84], ecx         ; baseDirChars
    mov     word ptr [rdx + rcx*2],     5Ch ; '\'
    mov     word ptr [rdx + rcx*2 + 2], '*'
    mov     word ptr [rdx + rcx*2 + 4], '.'
    mov     word ptr [rdx + rcx*2 + 6], '*'
    mov     word ptr [rdx + rcx*2 + 8], 0

    WINCALL FindFirstFileW, addr g_tcvc_path1, addr g_tcvc_wfd
    cmp     rax, -1
    je      tak_io_free
    mov     qword ptr [rbp-96], rax         ; hFind
    mov     dword ptr [rbp-88], 0           ; dirFileCount = 0

tak_find_lp:
    mov     eax, dword ptr [g_tcvc_wfd]     ; dwFileAttributes
    test    eax, TCVC_ATTR_DIR
    jnz     tak_find_next                   ; skip '.' / '..' / subdirectories
    test    eax, TCVC_ATTR_HIDDEN
    jnz     tak_find_next                   ; skip hidden files (Keyfiles.c:349)
    test    eax, TCVC_ATTR_REPARSE
    jz      tak_build_sub
    test    dword ptr [g_tcvc_wfd + 36], TCVC_REPARSE_SURR
    jnz     tak_find_next

tak_build_sub:
    ; Build "<dir>\<cFileName>" in g_tcvc_path2
    lea     rdx, [g_tcvc_path2]
    lea     rsi, [g_tcvc_path1]
    mov     ecx, dword ptr [rbp-84]
    xor     r8d, r8d
tak_cp_base:
    cmp     r8d, ecx
    jae     tak_base_done
    mov     ax, word ptr [rsi + r8*2]
    mov     word ptr [rdx + r8*2], ax
    inc     r8d
    jmp     tak_cp_base
tak_base_done:
    mov     word ptr [rdx + r8*2], 5Ch
    inc     r8d
    lea     rsi, [g_tcvc_wfd + 44]          ; cFileName offset in WIN32_FIND_DATAW
    xor     r9d, r9d
tak_cp_leaf:
    mov     ax, word ptr [rsi + r9*2]
    mov     word ptr [rdx + r8*2], ax
    test    ax, ax
    jz      tak_sub_ready
    inc     r8d
    inc     r9d
    cmp     r8d, MAX_PATH_CHARS
    jae     tak_find_err
    jmp     tak_cp_leaf

tak_sub_ready:
    ; Skip if child equals volPathW (Keyfiles.c:356)
    mov     rcx, qword ptr [rbp+48]
    test    rcx, rcx
    jz      tak_do_sub
    WINCALL CompareStringOrdinal, rcx, -1, addr g_tcvc_path2, -1, 1
    cmp     eax, TCVC_CSTR_EQUAL
    je      tak_find_next

tak_do_sub:
    lea     rcx, [g_tcvc_path2]
    mov     edx, dword ptr [rbp-72]
    mov     r8,  qword ptr [rbp-80]
    call    tcvc_mix_one_keyfile
    test    eax, eax
    jnz     tak_find_err
    inc     dword ptr [rbp-88]

tak_find_next:
    WINCALL FindNextFileW, qword ptr [rbp-96], addr g_tcvc_wfd
    test    eax, eax
    jnz     tak_find_lp

    WINCALL FindClose, qword ptr [rbp-96]
    cmp     dword ptr [rbp-88], 0
    je      tak_io_free                     ; empty keyfile folder -> error
    jmp     tak_kf_next

tak_find_err:
    WINCALL FindClose, qword ptr [rbp-96]
    jmp     tak_io_free

tak_single_file:
    mov     rcx, rsi
    mov     edx, dword ptr [rbp-72]
    mov     r8,  qword ptr [rbp-80]
    call    tcvc_mix_one_keyfile
    test    eax, eax
    jnz     tak_io_free

tak_kf_next:
    inc     edi
    jmp     tak_kf_loop

tak_mix_final:
    mov     rcx, qword ptr [rbp-80]
    mov     edx, 65536
    call    mem_free

    ; Mix kf_pool[0..poolSize-1] into pw_mixed[0..poolSize-1]
    mov     ebx, dword ptr [rbp-72]         ; poolSize
    lea     rsi, [g_tcvc_sec + TCVC_OFF_POOL]
    lea     rdi, [g_tcvc_sec + TCVC_OFF_PW]
    xor     ecx, ecx
tak_add_lp:
    mov     al, byte ptr [rsi+rcx]
    add     byte ptr [rdi+rcx], al
    inc     ecx
    cmp     ecx, ebx
    jb      tak_add_lp

    cmp     r13d, ebx
    jae     tak_len_set
    mov     dword ptr [g_tcvc_pw_len], ebx
tak_len_set:
    lea     rcx, [g_tcvc_sec + TCVC_OFF_POOL]
    mov     edx, 128
    call    secure_zero

tak_ok_nokf:
    ; Empty password with 0 keyfiles is rejected
    cmp     dword ptr [g_tcvc_pw_len], 0
    je      tak_auth_err
    xor     eax, eax                        ; EXIT_OK
    jmp     tak_out

tak_io_free:
    mov     rcx, qword ptr [rbp-80]
    mov     edx, 65536
    call    mem_free
    lea     rcx, [g_tcvc_sec + TCVC_OFF_PW]
    mov     edx, 256
    call    secure_zero
    mov     eax, EXIT_IO
    jmp     tak_out

tak_oom:
    mov     eax, EXIT_OOM
    jmp     tak_out

tak_auth_err:
    mov     eax, EXIT_AUTH

tak_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
tcvc_apply_keyfiles endp

; =============================================================================
; tcvc_try_modes(rcx = dk192, rdx = encHdr448, r8 = xtsScratch, r9 = hdrOut448,
;                [rbp+48] = reqVera, [rbp+56] = outErrPtr)
;   -> eax = matched modeId (0..14), or -1 if none matched.
;      If magic+CRC matched an unsupported/corrupt header, writes EXIT_* to *outErrPtr.
; =============================================================================
tcvc_try_modes proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     r12, rcx                        ; dk192
    mov     r13, rdx                        ; encHdr448
    mov     r14, r8                         ; xtsScratch
    mov     r15, r9                         ; hdrOut448

    mov     rax, qword ptr [rbp+56]
    mov     dword ptr [rax], 0              ; *outErrPtr = 0

    xor     ebx, ebx                        ; modeId = 0..14
ttm_loop:
    mov     ecx, ebx
    call    xts_mode_key_size               ; eax = 32, 64, or 96
    mov     ecx, ebx
    mov     rdx, r12                        ; priKey = dk + 0
    lea     r8,  [r12 + rax]                ; secKey = dk + keyBytes
    mov     r9,  r14
    call    xts_init

    ; Copy 448-byte ciphertext into hdrOut448 and XTS-decrypt with unit 0
    mov     rdi, r15
    mov     rsi, r13
    mov     ecx, 448 / 8
    rep     movsq

    mov     rcx, r14
    mov     rdx, r15
    mov     r8d, 448
    xor     r9d, r9d
    call    xts_decrypt

    ; 1. Check 4-byte magic ("VERA" or "TRUE") matching reqVera
    mov     eax, TCVC_MAGIC_VERA
    cmp     dword ptr [rbp+48], 0
    jne     ttm_cmp_magic
    mov     eax, TCVC_MAGIC_TRUE
ttm_cmp_magic:
    cmp     dword ptr [r15], eax
    jne     ttm_next

    ; 2. Verify VolumeKeyAreaCrc32 (BE32 at +8 == CRC32(hdr[192..447], 256))
    xor     ecx, ecx
    lea     rdx, [r15 + 192]
    mov     r8d, 256
    call    crc32_update
    mov     edx, dword ptr [r15 + 8]
    bswap   edx
    cmp     eax, edx
    jne     ttm_next

    ; 3. Read HeaderVersion (BE16 at +4)
    movzx   esi, word ptr [r15 + 4]
    rol     si,  8
    cmp     esi, 4
    jb      ttm_ver_range

    ; Verify HeaderCrc32 (BE32 at +188 == CRC32(hdr[0..187], 188))
    xor     ecx, ecx
    mov     rdx, r15
    mov     r8d, 188
    call    crc32_update
    mov     edx, dword ptr [r15 + 188]
    bswap   edx
    cmp     eax, edx
    jne     ttm_next

ttm_ver_range:
    ; Authenticated TC/VC header! Check structural support (v3..v5 XTS, normal volume)
    cmp     esi, 3
    jb      ttm_unsup
    cmp     esi, 5
    ja      ttm_unsup

    ; HiddenVolumeDataSize (BE64 at +28) must be 0
    cmp     qword ptr [r15 + 28], 0
    jne     ttm_unsup

    ; Flags (BE32 at +60, valid for v4+): reject system-encryption bit 0
    cmp     esi, 4
    jb      ttm_sec_chk
    mov     eax, dword ptr [r15 + 60]
    bswap   eax
    test    eax, 1
    jnz     ttm_unsup

ttm_sec_chk:
    ; SectorSize: v5+ at +64, else 512; must be power-of-two in 512..4096
    mov     eax, 512
    cmp     esi, 5
    jb      ttm_sec_val
    mov     eax, dword ptr [r15 + 64]
    bswap   eax
ttm_sec_val:
    cmp     eax, 512
    jb      ttm_corrupt
    cmp     eax, 4096
    ja      ttm_corrupt
    lea     ecx, [eax - 1]
    test    eax, ecx
    jnz     ttm_corrupt

    ; Check host bounds if g_tcvc_host_size != 0
    mov     rcx, qword ptr [g_tcvc_host_size]
    test    rcx, rcx
    jz      ttm_hit

    mov     rax, qword ptr [r15 + 36]       ; VolumeDataSize
    bswap   rax
    mov     rdx, qword ptr [r15 + 44]       ; EncryptedAreaStart
    bswap   rdx
    test    rax, rax
    jnz     ttm_chk_align
    test    rdx, rdx
    jnz     ttm_corrupt
    ; Legacy V1 layout fallback: start=512, size=hostSize-512
    cmp     rcx, 1024
    jb      ttm_corrupt
    mov     edx, 512
    mov     rax, rcx
    sub     rax, 512
ttm_chk_align:
    cmp     rdx, 512
    jb      ttm_corrupt
    test    edx, 511
    jnz     ttm_corrupt
    cmp     rax, 512
    jb      ttm_corrupt
    test    eax, 511
    jnz     ttm_corrupt
    add     rdx, rax
    jc      ttm_corrupt
    cmp     rdx, rcx
    ja      ttm_corrupt

ttm_hit:
    mov     eax, ebx                        ; matched modeId!
    jmp     ttm_out

ttm_unsup:
    mov     rax, qword ptr [rbp+56]
    mov     dword ptr [rax], EXIT_UNSUPPORTED
    mov     eax, -1
    jmp     ttm_out

ttm_corrupt:
    mov     rax, qword ptr [rbp+56]
    mov     dword ptr [rax], EXIT_CORRUPT
    mov     eax, -1
    jmp     ttm_out

ttm_next:
    inc     ebx
    cmp     ebx, 15
    jb      ttm_loop

    mov     eax, -1

ttm_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
tcvc_try_modes endp

; =============================================================================
; tcvc_kdf_worker_body(rcx = slotBase)
; Framed body run inside worker thread after sstk_thread_init.
; =============================================================================
tcvc_kdf_worker_body proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rcx                        ; slotBase

    mov     dword ptr [rbx + TCVC_SLOT_JOB + 12], -1
    mov     dword ptr [rbx + TCVC_SLOT_JOB + 16], 0

    mov     ecx, dword ptr [rbx + TCVC_SLOT_JOB + 0]    ; hashId
    mov     rdx, qword ptr [rbx + TCVC_SLOT_JOB + 32]   ; pwPtr
    mov     r8d, dword ptr [rbx + TCVC_SLOT_JOB + 40]   ; pwLen
    lea     r9,  [g_tcvc_sec + TCVC_OFF_SALT]
    mov     qword ptr [rsp+32], 64                      ; saltLen
    mov     eax, dword ptr [rbx + TCVC_SLOT_JOB + 4]    ; iterations
    mov     qword ptr [rsp+40], rax
    lea     rax, [rbx + TCVC_SLOT_DK]
    mov     qword ptr [rsp+48], rax                     ; outPtr
    mov     qword ptr [rsp+56], 192                     ; outLen
    call    pbkdf2_hmac_ex
    test    eax, eax
    jnz     tkwb_done

    cmp     dword ptr [g_tcvc_abort], 0
    jne     tkwb_done

    lea     rcx, [rbx + TCVC_SLOT_DK]
    mov     rdx, qword ptr [rbx + TCVC_SLOT_JOB + 24]   ; encHdr448Ptr
    mov     r8,  rbx                                    ; xtsScratch at slotBase+0
    lea     r9,  [rbx + TCVC_SLOT_HDR]                  ; hdrOut448
    mov     eax, dword ptr [rbx + TCVC_SLOT_JOB + 8]    ; reqVera
    mov     qword ptr [rsp+32], rax
    lea     rax, [rbx + TCVC_SLOT_JOB + 16]             ; &errCode
    mov     qword ptr [rsp+40], rax
    call    tcvc_try_modes
    cmp     eax, -1
    je      tkwb_chk_err

    ; Matched! Signal all other workers to abort immediately
    mov     dword ptr [rbx + TCVC_SLOT_JOB + 12], eax
    mov     ecx, dword ptr [rbx + TCVC_SLOT_JOB + 20]   ; slotIdx
    mov     eax, -1
    lock cmpxchg dword ptr [g_tcvc_win_slot], ecx
    mov     eax, 1
    xchg    dword ptr [g_tcvc_abort], eax
    jmp     tkwb_done

tkwb_chk_err:
    cmp     dword ptr [rbx + TCVC_SLOT_JOB + 16], 0
    je      tkwb_done
    mov     eax, 1
    xchg    dword ptr [g_tcvc_abort], eax

tkwb_done:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
tcvc_kdf_worker_body endp

; =============================================================================
; tcvc_kdf_worker(rcx = slotBase) - OS thread entry point (MUST use raw frame!)
; =============================================================================
tcvc_kdf_worker proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rcx
    call    sstk_thread_init
    test    eax, eax
    jz      tkw_out
    mov     rcx, rbx
    call    tcvc_kdf_worker_body
    call    sstk_thread_free
tkw_out:
    mov     rbx, qword ptr [rbp-16]
    xor     eax, eax
    add     rsp, 64
    pop     rbp
    ret
tcvc_kdf_worker endp

; =============================================================================
; tcvc_commit_header(ecx = modeId, edx = kdfId, r8d = isVera) -> eax = EXIT_*
; Extracts geometry and initializes active DataAreaKey XTS schedule from
; g_tcvc_sec + TCVC_OFF_HDR (448 bytes).
; =============================================================================
tcvc_commit_header proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi

    mov     ebx, ecx                        ; modeId
    mov     dword ptr [g_tcvc_mode_id], ecx
    mov     dword ptr [g_tcvc_kdf_id],  edx
    mov     dword ptr [g_tcvc_is_vera], r8d

    lea     rsi, [g_tcvc_sec + TCVC_OFF_HDR]
    movzx   ecx, word ptr [rsi + 4]
    rol     cx,  8                          ; headerVersion

    mov     eax, 512
    cmp     ecx, 5
    jb      tch_sec_ok
    mov     eax, dword ptr [rsi + 64]
    bswap   eax
tch_sec_ok:
    mov     dword ptr [g_tcvc_sec_size], eax

    mov     rax, qword ptr [rsi + 36]       ; VolumeDataSize
    bswap   rax
    mov     rdx, qword ptr [rsi + 44]       ; EncryptedAreaStart
    bswap   rdx
    mov     r8,  qword ptr [rsi + 52]       ; EncryptedAreaLength
    bswap   r8

    test    rax, rax
    jnz     tch_v2
    test    rdx, rdx
    jnz     tch_corrupt
    mov     edx, 512
    mov     rax, qword ptr [g_tcvc_host_size]
    sub     rax, 512
    mov     r8,  rax
tch_v2:
    cmp     r8, rax
    jb      tch_unsup                       ; partial in-place encryption

    mov     qword ptr [g_tcvc_data_off],  rdx
    mov     qword ptr [g_tcvc_data_size], rax

    ; Initialize active volume XTS_CTX at g_tcvc_sec + TCVC_OFF_XTS
    mov     ecx, ebx
    call    xts_mode_key_size
    mov     ecx, ebx
    lea     rdx, [rsi + 192]                ; primary master key(s)
    lea     r8,  [rsi + 192 + rax]          ; secondary master key(s)
    lea     r9,  [g_tcvc_sec + TCVC_OFF_XTS]
    call    xts_init

    ; Wipe transient KDF output, salt, and decrypted header (keep active XTS_CTX & pw)
    lea     rcx, [g_tcvc_sec + TCVC_OFF_DK]
    mov     edx, 192 + 448 + 64
    call    secure_zero

    xor     eax, eax                        ; EXIT_OK
    jmp     tch_out

tch_unsup:
    mov     eax, EXIT_UNSUPPORTED
    jmp     tch_out
tch_corrupt:
    mov     eax, EXIT_CORRUPT
tch_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
tcvc_commit_header endp

; =============================================================================
; tcvc_unlock_header_buf(rcx = rawHdr512, rdx = pwPtr, r8d = pwLen, r9d = pim)
;   -> eax = EXIT_OK / EXIT_AUTH / EXIT_UNSUPPORTED / EXIT_CORRUPT / EXIT_OOM
; =============================================================================
public tcvc_unlock_header_buf
tcvc_unlock_header_buf proc frame
    FRAME_PROLOG 256
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-72]       errCode (dd), threadCount (dd at -68)
    ; [rbp-80]       arenaPtr
    ; [rbp-128..-81] hThreads[6] (6 * 8 = 48 bytes)
    ; [rsp+64..159]  ARGON2REQ (96 bytes; outgoing args use [rsp+0..55])
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     r12, rcx                        ; rawHdr512
    mov     r13, rdx                        ; pwPtr
    mov     r14d, r8d                       ; pwLen
    mov     r15d, r9d                       ; pim

    call    tcvc_ensure_tables

    ; Copy 64-byte salt into g_tcvc_sec + TCVC_OFF_SALT
    lea     rdi, [g_tcvc_sec + TCVC_OFF_SALT]
    mov     rsi, r12
    mov     ecx, 64 / 8
    rep     movsq

    mov     dword ptr [g_tcvc_abort], 0
    mov     dword ptr [g_tcvc_win_slot], -1
    mov     dword ptr [rbp-72], 0

    ; ---- Phase 1: Fast-path TrueCrypt 7.1a (only when pim == 0) -------------
    test    r15d, r15d
    jnz     tuh_vc_pbkdf2

    xor     ebx, ebx                        ; tc kdf idx 0..3
tuh_tc_lp:
    lea     rsi, [tcvc_tc_kdfs]
    mov     ecx, dword ptr [rsi + rbx*8]    ; hashId
    mov     edi, ecx
    mov     eax, dword ptr [rsi + rbx*8 + 4]; iterations

    mov     rdx, r13
    mov     r8d, r14d
    lea     r9,  [g_tcvc_sec + TCVC_OFF_SALT]
    mov     qword ptr [rsp+32], 64
    mov     qword ptr [rsp+40], rax
    lea     rax, [g_tcvc_sec + TCVC_OFF_DK]
    mov     qword ptr [rsp+48], rax
    mov     qword ptr [rsp+56], 192
    call    pbkdf2_hmac_ex

    lea     rcx, [g_tcvc_sec + TCVC_OFF_DK]
    lea     rdx, [r12 + 64]
    lea     r8,  [g_tcvc_sec + TCVC_OFF_XTS]
    lea     r9,  [g_tcvc_sec + TCVC_OFF_HDR]
    mov     qword ptr [rsp+32], 0           ; reqVera = 0 ("TRUE")
    lea     rax, [rbp-72]
    mov     qword ptr [rsp+40], rax
    call    tcvc_try_modes
    cmp     eax, -1
    jne     tuh_tc_hit

    cmp     dword ptr [rbp-72], 0
    jne     tuh_ret_err

    inc     ebx
    cmp     ebx, 4
    jb      tuh_tc_lp
    jmp     tuh_vc_pbkdf2

tuh_tc_hit:
    mov     ecx, eax                        ; modeId
    mov     edx, edi                        ; kdfId
    xor     r8d, r8d                        ; isVera = 0
    call    tcvc_commit_header
    jmp     tuh_out

    ; ---- Phase 2: Parallel 6-thread VeraCrypt PBKDF2-HMAC -------------------
tuh_vc_pbkdf2:
    WINCALL VirtualAlloc, 0, TCVC_ARENA_BYTES, TCVC_MEM_COMMIT_RES, TCVC_PAGE_RW
    test    rax, rax
    jz      tuh_oom
    mov     qword ptr [rbp-80], rax         ; arenaPtr
    mov     dword ptr [rbp-68], 0           ; spawned threads

    xor     ebx, ebx                        ; slotIdx = 0..5 (hashId 0..5)
tuh_spawn_lp:
    imul    eax, ebx, TCVC_SLOT_BYTES
    add     rax, qword ptr [rbp-80]
    mov     rsi, rax                        ; slotBase

    ; Compute iterations: pim == 0 -> tcvc_vc_def_iters[ebx], else 15000 + pim * 1000
    lea     rcx, [tcvc_vc_def_iters]
    mov     edx, dword ptr [rcx + rbx*4]
    test    r15d, r15d
    jz      tuh_iters_ok
    imul    edx, r15d, 1000
    add     edx, 15000
tuh_iters_ok:
    mov     dword ptr [rsi + TCVC_SLOT_JOB + 0],  ebx   ; hashId
    mov     dword ptr [rsi + TCVC_SLOT_JOB + 4],  edx   ; iterations
    mov     dword ptr [rsi + TCVC_SLOT_JOB + 8],  1     ; reqVera = 1
    mov     dword ptr [rsi + TCVC_SLOT_JOB + 12], -1
    mov     dword ptr [rsi + TCVC_SLOT_JOB + 16], 0
    mov     dword ptr [rsi + TCVC_SLOT_JOB + 20], ebx   ; slotIdx
    lea     rax, [r12 + 64]
    mov     qword ptr [rsi + TCVC_SLOT_JOB + 24], rax   ; encHdr448Ptr
    mov     qword ptr [rsi + TCVC_SLOT_JOB + 32], r13   ; pwPtr
    mov     dword ptr [rsi + TCVC_SLOT_JOB + 40], r14d  ; pwLen

    WINCALL CreateThread, 0, 0, addr tcvc_kdf_worker, rsi, 0, 0
    test    rax, rax
    jz      tuh_sync_fallback
    mov     ecx, dword ptr [rbp-68]
    mov     qword ptr [rbp-128 + rcx*8], rax
    inc     dword ptr [rbp-68]
    jmp     tuh_spawn_next

tuh_sync_fallback:
    ; If CreateThread fails under resource pressure, run slot synchronously
    mov     rcx, rsi
    call    tcvc_kdf_worker_body

tuh_spawn_next:
    inc     ebx
    cmp     ebx, 6
    jb      tuh_spawn_lp

    mov     ecx, dword ptr [rbp-68]
    test    ecx, ecx
    jz      tuh_joined
    WINCALL WaitForMultipleObjects, ecx, addr rbp-128, 1, TCVC_INFINITE

    xor     ebx, ebx
tuh_close_th:
    cmp     ebx, dword ptr [rbp-68]
    jae     tuh_joined
    WINCALL CloseHandle, qword ptr [rbp-128 + rbx*8]
    inc     ebx
    jmp     tuh_close_th

tuh_joined:
    mov     dword ptr [g_tcvc_abort], 0

    ; Check if any slot matched
    mov     ebx, dword ptr [g_tcvc_win_slot]
    cmp     ebx, -1
    je      tuh_chk_slot_errs

    imul    eax, ebx, TCVC_SLOT_BYTES
    add     rax, qword ptr [rbp-80]
    mov     rsi, rax
    mov     r15d, dword ptr [rsi + TCVC_SLOT_JOB + 12]  ; matchedMode

    ; Copy winning decrypted header into g_tcvc_sec + TCVC_OFF_HDR
    lea     rdi, [g_tcvc_sec + TCVC_OFF_HDR]
    lea     rsi, [rsi + TCVC_SLOT_HDR]
    mov     ecx, 448 / 8
    rep     movsq

    ; Wipe and free arena
    mov     rcx, qword ptr [rbp-80]
    mov     edx, TCVC_ARENA_BYTES
    call    secure_zero
    WINCALL VirtualFree, qword ptr [rbp-80], 0, TCVC_MEM_RELEASE

    mov     ecx, r15d                       ; modeId
    mov     edx, ebx                        ; kdfId (hashId 0..5)
    mov     r8d, 1                          ; isVera = 1
    call    tcvc_commit_header
    jmp     tuh_out

tuh_chk_slot_errs:
    xor     ebx, ebx
tuh_err_scan:
    imul    eax, ebx, TCVC_SLOT_BYTES
    add     rax, qword ptr [rbp-80]
    mov     ecx, dword ptr [rax + TCVC_SLOT_JOB + 16]
    test    ecx, ecx
    jnz     tuh_slot_err_found
    inc     ebx
    cmp     ebx, 6
    jb      tuh_err_scan

    ; Wipe and free PBKDF2 arena before Argon2id phase
    mov     rcx, qword ptr [rbp-80]
    mov     edx, TCVC_ARENA_BYTES
    call    secure_zero
    WINCALL VirtualFree, qword ptr [rbp-80], 0, TCVC_MEM_RELEASE
    jmp     tuh_argon2

tuh_slot_err_found:
    mov     dword ptr [rbp-72], ecx
    mov     rcx, qword ptr [rbp-80]
    mov     edx, TCVC_ARENA_BYTES
    call    secure_zero
    WINCALL VirtualFree, qword ptr [rbp-80], 0, TCVC_MEM_RELEASE
    jmp     tuh_ret_err

    ; ---- Phase 3: VeraCrypt Argon2id (Pkcs5.c:get_argon2_params) ------------
tuh_argon2:
    mov     ebx, r15d                       ; pim
    test    ebx, ebx
    jnz     tuh_a2_pim_ok
    mov     ebx, 12                         ; default VC Argon2id PIM = 12
tuh_a2_pim_ok:
    ; m_cost_mib = min(64 + (pim - 1) * 32, 1024); m_cost_kib = m_cost_mib * 1024
    lea     eax, [ebx - 1]
    shl     eax, 5
    add     eax, 64
    cmp     eax, 1024
    jbe     tuh_a2_m_ok
    mov     eax, 1024
tuh_a2_m_ok:
    shl     eax, 10                         ; KiB
    mov     edi, eax                        ; m_cost

    ; t_cost = (pim <= 31) ? 3 + (pim - 1) / 3 : 13 + (pim - 31)
    cmp     ebx, 31
    ja      tuh_a2_t_hi
    lea     eax, [ebx - 1]
    xor     edx, edx
    mov     ecx, 3
    div     ecx
    add     eax, 3
    jmp     tuh_a2_t_ok
tuh_a2_t_hi:
    lea     eax, [ebx - 18]                 ; 13 + pim - 31 = pim - 18
tuh_a2_t_ok:
    mov     esi, eax                        ; t_cost

    ; Populate ARGON2REQ at [rsp+64]
    lea     rcx, [rsp+64]
    mov     edx, sizeof ARGON2REQ
    call    secure_zero

    mov     dword ptr [rsp+64 + ARGON2REQ.t_cost],  esi
    mov     dword ptr [rsp+64 + ARGON2REQ.m_cost],  edi
    mov     dword ptr [rsp+64 + ARGON2REQ.lanes],   1
    mov     dword ptr [rsp+64 + ARGON2REQ.outlen],  192
    mov     dword ptr [rsp+64 + ARGON2REQ.version], 013h
    mov     dword ptr [rsp+64 + ARGON2REQ.atype],   2
    mov     qword ptr [rsp+64 + ARGON2REQ.pwd],     r13
    mov     dword ptr [rsp+64 + ARGON2REQ.pwdlen],  r14d
    mov     dword ptr [rsp+64 + ARGON2REQ.saltlen], 64
    lea     rax, [g_tcvc_sec + TCVC_OFF_SALT]
    mov     qword ptr [rsp+64 + ARGON2REQ.salt],    rax
    lea     rax, [g_tcvc_sec + TCVC_OFF_DK]
    mov     qword ptr [rsp+64 + ARGON2REQ.outp],    rax
    mov     dword ptr [rsp+64 + ARGON2REQ.flags],   0

    lea     rcx, [rsp+64]
    call    argon2id_hash
    mov     ebx, eax
    lea     rcx, [rsp+64]
    mov     edx, sizeof ARGON2REQ
    call    secure_zero
    test    ebx, ebx
    jnz     tuh_oom

    lea     rcx, [g_tcvc_sec + TCVC_OFF_DK]
    lea     rdx, [r12 + 64]
    lea     r8,  [g_tcvc_sec + TCVC_OFF_XTS]
    lea     r9,  [g_tcvc_sec + TCVC_OFF_HDR]
    mov     qword ptr [rsp+32], 1           ; reqVera = 1
    lea     rax, [rbp-72]
    mov     qword ptr [rsp+40], rax
    call    tcvc_try_modes
    cmp     eax, -1
    je      tuh_no_match

    mov     ecx, eax                        ; modeId
    mov     edx, TCVC_KDF_ARGON2ID
    mov     r8d, 1                          ; isVera = 1
    call    tcvc_commit_header
    jmp     tuh_out

tuh_no_match:
    lea     rcx, [g_tcvc_sec + TCVC_OFF_XTS]
    mov     edx, 25552
    call    secure_zero
    lea     rcx, [g_tcvc_sec + TCVC_OFF_DK]
    mov     edx, 192 + 448 + 64
    call    secure_zero
    cmp     dword ptr [rbp-72], 0
    jne     tuh_ret_err
    mov     eax, EXIT_AUTH
    jmp     tuh_out

tuh_oom:
    mov     eax, EXIT_OOM
    jmp     tuh_out

tuh_ret_err:
    lea     rcx, [g_tcvc_sec + TCVC_OFF_XTS]
    mov     edx, 25552
    call    secure_zero
    lea     rcx, [g_tcvc_sec + TCVC_OFF_DK]
    mov     edx, 192 + 448 + 64
    call    secure_zero
    mov     eax, dword ptr [rbp-72]

tuh_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
tcvc_unlock_header_buf endp

; =============================================================================
; tcvc_raw_read(rcx = hostOffset, rdx = dstBuf, r8d = byteLen) -> eax = EXIT_*
; =============================================================================
tcvc_raw_read proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    mov     rax, qword ptr [g_tcvc_mem_ptr]
    test    rax, rax
    jz      trr_disk

    ; In-memory container backing
    mov     r9, rcx
    mov     ebx, r8d
    add     r9, rbx
    jc      trr_io_err
    cmp     r9, qword ptr [g_tcvc_host_size]
    ja      trr_io_err
    lea     rsi, [rax + rcx]
    mov     rdi, rdx
    mov     ecx, ebx
    rep     movsb
    xor     eax, eax
    jmp     trr_out

trr_disk:
    mov     rsi, rdx                        ; dstBuf
    mov     ebx, r8d                        ; byteLen
    WINCALL SetFilePointerEx, qword ptr [g_tcvc_hfile], rcx, 0, 0
    test    eax, eax
    jz      trr_io_err

    mov     dword ptr [rbp-40], 0
    WINCALL ReadFile, qword ptr [g_tcvc_hfile], rsi, ebx, addr rbp-40, 0
    test    eax, eax
    jz      trr_io_err
    cmp     dword ptr [rbp-40], ebx
    jne     trr_io_err
    xor     eax, eax
    jmp     trr_out

trr_io_err:
    mov     eax, EXIT_IO

trr_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
tcvc_raw_read endp

; =============================================================================
; tcvc_close() - wipes all secrets, frees sector cache, closes container handle
; =============================================================================
public tcvc_close
tcvc_close proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_tcvc_cache_ptr]
    test    rcx, rcx
    jz      tcc_nocache
    mov     edx, TCVC_CACHE_BYTES
    call    mem_free
    mov     qword ptr [g_tcvc_cache_ptr], 0
tcc_nocache:
    mov     qword ptr [g_tcvc_cache_base], -1
    mov     dword ptr [g_tcvc_cache_len], 0

    mov     rcx, qword ptr [g_tcvc_hfile]
    test    rcx, rcx
    jz      tcc_nofile
    cmp     rcx, -1
    je      tcc_nofile
    WINCALL CloseHandle, rcx
tcc_nofile:
    mov     qword ptr [g_tcvc_hfile], -1
    mov     qword ptr [g_tcvc_mem_ptr], 0
    mov     qword ptr [g_tcvc_host_size], 0
    mov     qword ptr [g_tcvc_data_off], 0
    mov     qword ptr [g_tcvc_data_size], 0
    mov     dword ptr [g_tcvc_open_flag], 0
    mov     dword ptr [g_tcvc_fs_id], 0

    lea     rcx, [g_tcvc_sec]
    mov     edx, TCVC_SEC_SIZE
    call    secure_zero

    FRAME_EPILOG
    ret
tcvc_close endp

; =============================================================================
; tcvc_open(rcx = volPathW, rdx = pwPtr, r8d = pwLen, r9 = kfArrW,
;           [rbp+48] = kfCount) -> eax = EXIT_*
; =============================================================================
public tcvc_open
tcvc_open proc frame
    FRAME_PROLOG 624
    ; [rbp-16..48]   saved r12..r14, rbx, rsi
    ; [rbp-56]       fileSize (dq)
    ; [rsp+48..559]  rawHdr512 (512 bytes)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], rbx
    mov     qword ptr [rbp-48], rsi

    mov     r12, rcx                        ; volPathW
    mov     r13, rdx                        ; pwPtr
    mov     r14d, r8d                       ; pwLen
    mov     rbx, r9                         ; kfArrW
    mov     esi, dword ptr [rbp+48]         ; kfCount

    call    tcvc_close

    test    r12, r12
    jz      tco_io_err
    mov     rcx, r12
    lea     rdx, [g_tcvc_vol_np]
    call    normalize_path
    test    eax, eax
    jnz     tco_io_err
    lea     r12, [g_tcvc_vol_np]

    mov     rcx, r12
    call    file_path_allowed
    test    eax, eax
    jz      tco_io_err
    mov     rcx, r12
    call    file_leaf_surrogate
    test    eax, eax
    jnz     tco_io_err

    ; Strictly read-only container open (GENERIC_READ, FILE_SHARE_READ)
    WINCALL CreateFileW, r12, TCVC_GEN_READ, TCVC_SHARE_READ, 0, TCVC_OPEN_EXISTING, 0, 0
    cmp     rax, -1
    je      tco_io_err
    mov     qword ptr [g_tcvc_hfile], rax

    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      tco_fail_io

    mov     qword ptr [rbp-56], 0
    WINCALL GetFileSizeEx, qword ptr [g_tcvc_hfile], addr rbp-56
    test    eax, eax
    jz      tco_fail_io

    mov     rax, qword ptr [rbp-56]
    cmp     rax, 1024
    jb      tco_fail_corrupt
    test    eax, 511
    jnz     tco_fail_corrupt
    mov     qword ptr [g_tcvc_host_size], rax

    ; Apply keyfiles (if any) + password into g_tcvc_sec + TCVC_OFF_PW
    mov     rcx, r13
    mov     edx, r14d
    mov     r8,  rbx
    mov     r9d, esi
    mov     qword ptr [rsp+32], r12         ; volPathW
    call    tcvc_apply_keyfiles
    test    eax, eax
    jnz     tco_fail_code

    ; Read primary 512-byte header at offset 0
    xor     ecx, ecx
    lea     rdx, [rsp+48]
    mov     r8d, 512
    call    tcvc_raw_read
    test    eax, eax
    jnz     tco_fail_code

    lea     rcx, [rsp+48]
    lea     rdx, [g_tcvc_sec + TCVC_OFF_PW]
    mov     r8d, dword ptr [g_tcvc_pw_len]
    xor     r9d, r9d                        ; pim = 0
    call    tcvc_unlock_header_buf
    test    eax, eax
    jz      tco_unlocked

    ; Automatic backup header fallback at hostSize - 131072 if primary failed
    cmp     eax, EXIT_AUTH
    jne     tco_fail_code
    mov     rcx, qword ptr [g_tcvc_host_size]
    cmp     rcx, 262144
    jb      tco_fail_auth

    sub     rcx, 131072
    lea     rdx, [rsp+48]
    mov     r8d, 512
    call    tcvc_raw_read
    test    eax, eax
    jnz     tco_fail_auth

    lea     rcx, [rsp+48]
    lea     rdx, [g_tcvc_sec + TCVC_OFF_PW]
    mov     r8d, dword ptr [g_tcvc_pw_len]
    xor     r9d, r9d
    call    tcvc_unlock_header_buf
    test    eax, eax
    jnz     tco_fail_code

tco_unlocked:
    ; Wipe mixed password & stack header copy now that volume XTS_CTX is active
    lea     rcx, [g_tcvc_sec + TCVC_OFF_PW]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [rsp+48]
    mov     edx, 512
    call    secure_zero

    mov     ecx, TCVC_CACHE_BYTES
    call    mem_alloc
    test    rax, rax
    jz      tco_fail_oom
    mov     qword ptr [g_tcvc_cache_ptr], rax
    mov     qword ptr [g_tcvc_cache_base], -1
    mov     dword ptr [g_tcvc_cache_len], 0
    mov     dword ptr [g_tcvc_open_flag], 1

    xor     eax, eax                        ; EXIT_OK
    jmp     tco_out

tco_fail_oom:
    mov     ebx, EXIT_OOM
    jmp     tco_cleanup
tco_fail_auth:
    mov     ebx, EXIT_AUTH
    jmp     tco_cleanup
tco_fail_corrupt:
    mov     ebx, EXIT_CORRUPT
    jmp     tco_cleanup
tco_fail_io:
    mov     ebx, EXIT_IO
    jmp     tco_cleanup
tco_fail_code:
    mov     ebx, eax
tco_cleanup:
    lea     rcx, [rsp+48]
    mov     edx, 512
    call    secure_zero
    call    tcvc_close
    mov     eax, ebx
    jmp     tco_out

tco_io_err:
    mov     eax, EXIT_IO

tco_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     rbx, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
tcvc_open endp

; =============================================================================
; tcvc_open_mem(rcx = memPtr, rdx = memSize, r8 = pwPtr, r9d = pwLen,
;               [rbp+48] = pim) -> eax = EXIT_*
; In-memory container open (used by selftest KATs and fuzz harnesses).
; =============================================================================
public tcvc_open_mem
tcvc_open_mem proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx

    mov     r12, rcx                        ; memPtr
    mov     r13, rdx                        ; memSize
    mov     r14, r8                         ; pwPtr
    mov     r15d, r9d                       ; pwLen
    mov     ebx, dword ptr [rbp+48]         ; pim

    call    tcvc_close

    test    r12, r12
    jz      tcom_corrupt
    cmp     r13, 1024
    jb      tcom_corrupt
    test    r13d, 511
    jnz     tcom_corrupt

    mov     qword ptr [g_tcvc_hfile], -1
    mov     qword ptr [g_tcvc_mem_ptr], r12
    mov     qword ptr [g_tcvc_host_size], r13

    ; Primary header at memPtr + 0
    mov     rcx, r12
    mov     rdx, r14
    mov     r8d, r15d
    mov     r9d, ebx
    call    tcvc_unlock_header_buf
    test    eax, eax
    jz      tcom_unlocked

    cmp     eax, EXIT_AUTH
    jne     tcom_fail_code
    cmp     r13, 262144
    jb      tcom_fail_code

    ; Backup header at memPtr + memSize - 131072
    lea     rcx, [r12 + r13 - 131072]
    mov     rdx, r14
    mov     r8d, r15d
    mov     r9d, ebx
    call    tcvc_unlock_header_buf
    test    eax, eax
    jnz     tcom_fail_code

tcom_unlocked:
    mov     ecx, TCVC_CACHE_BYTES
    call    mem_alloc
    test    rax, rax
    jz      tcom_oom
    mov     qword ptr [g_tcvc_cache_ptr], rax
    mov     qword ptr [g_tcvc_cache_base], -1
    mov     dword ptr [g_tcvc_cache_len], 0
    mov     dword ptr [g_tcvc_open_flag], 1
    xor     eax, eax
    jmp     tcom_out

tcom_oom:
    mov     ebx, EXIT_OOM
    jmp     tcom_clean
tcom_corrupt:
    mov     ebx, EXIT_CORRUPT
    jmp     tcom_clean
tcom_fail_code:
    mov     ebx, eax
tcom_clean:
    call    tcvc_close
    mov     eax, ebx

tcom_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
tcvc_open_mem endp

; =============================================================================
; tcvc_read_bytes(rcx = volOffset, rdx = dstBuf, r8 = byteLen) -> eax = EXIT_*
; Reads arbitrary byte ranges from the unlocked volume via 64 KiB sector cache.
; =============================================================================
public tcvc_read_bytes
tcvc_read_bytes proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    cmp     dword ptr [g_tcvc_open_flag], 0
    je      trb_corrupt

    test    r8, r8
    jz      trb_ok

    ; Overflow-safe bounds check: volOffset + byteLen <= g_tcvc_data_size
    mov     rax, rcx
    add     rax, r8
    jc      trb_corrupt
    cmp     rax, qword ptr [g_tcvc_data_size]
    ja      trb_corrupt

    mov     r12, rcx                        ; curVolOff
    mov     r13, rdx                        ; curDst
    mov     r14, r8                         ; remBytes

trb_loop:
    test    r14, r14
    jz      trb_ok

    mov     r15, r12
    and     r15, -65536                     ; chunkBase (64 KiB aligned)
    cmp     r15, qword ptr [g_tcvc_cache_base]
    je      trb_hit

    ; Cache miss: load min(dataSize - chunkBase, 65536) and XTS-decrypt
    mov     rbx, qword ptr [g_tcvc_data_size]
    sub     rbx, r15
    cmp     rbx, TCVC_CACHE_BYTES
    jbe     trb_len_ok
    mov     ebx, TCVC_CACHE_BYTES
trb_len_ok:
    mov     rcx, qword ptr [g_tcvc_data_off]
    add     rcx, r15                        ; hostOffset
    mov     rdx, qword ptr [g_tcvc_cache_ptr]
    mov     r8d, ebx
    call    tcvc_raw_read
    test    eax, eax
    jnz     trb_io_miss

    mov     r9,  qword ptr [g_tcvc_data_off]
    add     r9,  r15
    shr     r9,  9                          ; startUnit = hostOffset / 512
    lea     rcx, [g_tcvc_sec + TCVC_OFF_XTS]
    mov     rdx, qword ptr [g_tcvc_cache_ptr]
    mov     r8d, ebx
    call    xts_decrypt

    mov     qword ptr [g_tcvc_cache_base], r15
    mov     dword ptr [g_tcvc_cache_len],  ebx

trb_hit:
    mov     eax, r12d
    and     eax, 0FFFFh                     ; inChunkOff
    mov     ecx, dword ptr [g_tcvc_cache_len]
    sub     ecx, eax                        ; availInChunk
    cmp     r14, rcx
    jae     trb_cpy_sz
    mov     ecx, r14d
trb_cpy_sz:
    mov     rsi, qword ptr [g_tcvc_cache_ptr]
    add     rsi, rax
    mov     rdi, r13
    mov     edx, ecx
    rep     movsb

    add     r12, rdx
    add     r13, rdx
    sub     r14, rdx
    jmp     trb_loop

trb_io_miss:
    mov     qword ptr [g_tcvc_cache_base], -1
    mov     eax, EXIT_IO
    jmp     trb_out

trb_corrupt:
    mov     eax, EXIT_CORRUPT
    jmp     trb_out

trb_ok:
    xor     eax, eax

trb_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
tcvc_read_bytes endp

; =============================================================================
; is_tcvc_path(rcx = widePath) -> eax: 1 if .tc/.hc (and not .mrk/.zip magic), 0 else
; =============================================================================
public is_tcvc_path
is_tcvc_path proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx

    test    rcx, rcx
    jz      itp_no

    xor     r8d, r8d
itp_len:
    cmp     r8d, MAX_PATH_CHARS
    jae     itp_no
    cmp     word ptr [rcx + r8*2], 0
    je      itp_len_ok
    inc     r8d
    jmp     itp_len

itp_len_ok:
    cmp     r8d, 3
    jb      itp_no
    cmp     word ptr [rcx + r8*2 - 6], '.'
    jne     itp_no

    movzx   eax, word ptr [rcx + r8*2 - 4]
    cmp     eax, 'A'
    jb      itp_c1
    cmp     eax, 'Z'
    ja      itp_c1
    add     eax, 20h
itp_c1:
    cmp     eax, 't'
    je      itp_c2
    cmp     eax, 'h'
    jne     itp_no

itp_c2:
    movzx   eax, word ptr [rcx + r8*2 - 2]
    cmp     eax, 'A'
    jb      itp_c3
    cmp     eax, 'Z'
    ja      itp_c3
    add     eax, 20h
itp_c3:
    cmp     eax, 'c'
    jne     itp_no

    ; Peek first 4 bytes to exclude misnamed Myrkr ("MYRK"/"MVOL") or ZIP files
    WINCALL CreateFileW, rcx, TCVC_GEN_READ, TCVC_SHARE_RW, 0, TCVC_OPEN_EXISTING, 0, 0
    cmp     rax, -1
    je      itp_yes                         ; let tcvc_open surface EXIT_IO cleanly
    mov     rbx, rax
    mov     dword ptr [rbp-24], 0
    mov     dword ptr [rbp-32], 0
    WINCALL ReadFile, rbx, addr rbp-32, 4, addr rbp-24, 0
    WINCALL CloseHandle, rbx
    cmp     dword ptr [rbp-24], 4
    jb      itp_yes

    mov     eax, dword ptr [rbp-32]
    cmp     eax, HDR_MAGIC                  ; "MYRK"
    je      itp_no
    cmp     eax, VOL_MAGIC                  ; "MVOL"
    je      itp_no
    cmp     eax, 04034B50h                  ; PK\x03\x04
    je      itp_no
    cmp     eax, 06054B50h                  ; PK\x05\x06
    je      itp_no
    cmp     eax, 08074B50h                  ; PK\x07\x08
    je      itp_no

itp_yes:
    mov     eax, 1
    jmp     itp_out

itp_no:
    xor     eax, eax

itp_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
is_tcvc_path endp

; =============================================================================
; tcvc_idx_put(rcx = normName, edx = normLen, r8 = size, r9d = flags,
;              [rbp+48] = meta0, [rbp+56] = meta1, [rbp+64] = meta2) -> eax = EXIT_*
; =============================================================================
tcvc_idx_put proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    mov     r12, rcx                        ; normName
    mov     r13d, edx                       ; normLen
    mov     r14, r8                         ; size
    mov     r15d, r9d                       ; flags

    mov     rcx, r12
    mov     edx, r13d
    call    idx_find
    cmp     rax, 0
    jge     tip_ok                          ; already in index

    call    idx_buf_ensure
    test    eax, eax
    jnz     tip_oom

    mov     edx, r13d
    add     rdx, IDXE_FIXED
    add     rdx, qword ptr [g_idxlen]
    cmp     rdx, IDX_MAX_BYTES
    ja      tip_oom

    mov     rcx, rdx
    call    idx_buf_commit
    test    eax, eax
    jnz     tip_oom

    mov     rdi, qword ptr [g_idxptr]
    add     rdi, qword ptr [g_idxlen]

    mov     qword ptr [rdi + IDXE_size],    r14
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rdi + IDXE_offset],  rax
    mov     rax, qword ptr [rbp+56]
    mov     qword ptr [rdi + IDXE_stored],  rax
    mov     rax, qword ptr [rbp+64]
    mov     qword ptr [rdi + IDXE_ordinal], rax
    mov     dword ptr [rdi + IDXE_flags],   r15d
    mov     dword ptr [rdi + IDXE_namelen], r13d

    lea     rdi, [rdi + IDXE_name]
    mov     rsi, r12
    mov     ecx, r13d
    rep     movsb

    mov     eax, r13d
    add     rax, IDXE_FIXED
    add     qword ptr [g_idxlen], rax
    inc     qword ptr [g_idxcount]

tip_ok:
    xor     eax, eax
    jmp     tip_out

tip_oom:
    mov     eax, EXIT_OOM

tip_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
tcvc_idx_put endp

; =============================================================================
; tcvc_idx_parents(rcx = normName, edx = normLen) -> eax = EXIT_*
; Ensures every ancestor directory exists in g_idxptr for GUI tree view.
; =============================================================================
tcvc_idx_parents proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], rbx

    mov     r12, rcx
    mov     r13d, edx
    xor     ebx, ebx

tipa_lp:
    cmp     ebx, r13d
    jae     tipa_ok
    cmp     byte ptr [r12 + rbx], '/'
    jne     tipa_next
    test    ebx, ebx
    jz      tipa_next

    mov     rcx, r12
    mov     edx, ebx
    xor     r8d, r8d
    mov     r9d, IDXEF_DIR
    mov     qword ptr [rsp+32], 0
    mov     qword ptr [rsp+40], 0
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_put
    test    eax, eax
    jnz     tipa_out

tipa_next:
    inc     ebx
    jmp     tipa_lp

tipa_ok:
    xor     eax, eax

tipa_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     rbx, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
tcvc_idx_parents endp

; =============================================================================
; tcvc_idx_add(rcx = nameUtf8, edx = nameLen, r8 = size, r9d = flags,
;              [rbp+48] = meta0, [rbp+56] = meta1, [rbp+64] = meta2) -> eax = EXIT_*
; =============================================================================
public tcvc_idx_add
tcvc_idx_add proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    test    rcx, rcx
    jz      tia_corrupt
    test    edx, edx
    jz      tia_corrupt
    cmp     edx, ENTRY_NAME_MAX
    ja      tia_corrupt

    mov     r14, r8                         ; size
    mov     r15d, r9d                       ; flags

    ; Copy into g_tcvc_idxname normalizing '\' -> '/' and rejecting embedded NULs
    lea     rdi, [g_tcvc_idxname]
    xor     eax, eax
tia_norm:
    movzx   r8d, byte ptr [rcx + rax]
    test    r8d, r8d
    jz      tia_corrupt
    cmp     r8b, 5Ch                        ; '\'
    jne     tia_st
    mov     r8b, '/'
tia_st:
    mov     byte ptr [rdi + rax], r8b
    inc     eax
    cmp     eax, edx
    jb      tia_norm

    ; Trim trailing '/'
tia_trim:
    test    eax, eax
    jz      tia_corrupt
    cmp     byte ptr [rdi + rax - 1], '/'
    jne     tia_trimmed
    dec     eax
    jmp     tia_trim

tia_trimmed:
    mov     r13d, eax                       ; normLen
    mov     byte ptr [rdi + rax], 0

    ; Synthesize missing parent directories
    lea     rcx, [g_tcvc_idxname]
    mov     edx, r13d
    call    tcvc_idx_parents
    test    eax, eax
    jnz     tia_out

    ; Emit the entry itself
    lea     rcx, [g_tcvc_idxname]
    mov     edx, r13d
    mov     r8,  r14
    mov     r9d, r15d
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rsp+32], rax
    mov     rax, qword ptr [rbp+56]
    mov     qword ptr [rsp+40], rax
    mov     rax, qword ptr [rbp+64]
    mov     qword ptr [rsp+48], rax
    call    tcvc_idx_put
    jmp     tia_out

tia_corrupt:
    mov     eax, EXIT_CORRUPT

tia_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
tcvc_idx_add endp

; =============================================================================
; tcvc_sink_write(rcx = buf, edx = len) -> eax = EXIT_*
; =============================================================================
public tcvc_sink_write
tcvc_sink_write proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    test    edx, edx
    jz      tsw_ok

    mov     rsi, rcx
    mov     ebx, edx

    mov     rdi, qword ptr [g_tcvc_mem]
    test    rdi, rdi
    jz      tsw_disk

    ; In-memory extraction sink (used by estream virtual drag-out)
    mov     rax, qword ptr [g_tcvc_memlen]
    add     rax, rbx
    jc      tsw_corrupt
    cmp     rax, qword ptr [g_tcvc_memcap]
    ja      tsw_corrupt
    add     rdi, qword ptr [g_tcvc_memlen]
    mov     ecx, ebx
    rep     movsb
    mov     qword ptr [g_tcvc_memlen], rax
    jmp     tsw_ok

tsw_disk:
    mov     rcx, qword ptr [g_tcvc_hout]
    mov     rdx, rsi
    mov     r8d, ebx
    call    file_write_all
    test    eax, eax
    jnz     tsw_io

    mov     ecx, ebx
    call    progress_add
    test    eax, eax
    jnz     tsw_cancel

tsw_ok:
    xor     eax, eax
    jmp     tsw_out

tsw_cancel:
    mov     eax, EXIT_CANCELLED
    jmp     tsw_out
tsw_corrupt:
    mov     eax, EXIT_CORRUPT
    jmp     tsw_out
tsw_io:
    mov     eax, EXIT_IO

tsw_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
tcvc_sink_write endp

; =============================================================================
; tcvc_probe_fs() -> eax = EXIT_* (populates g_tcvc_fs_id on EXIT_OK)
; =============================================================================
public tcvc_probe_fs
tcvc_probe_fs proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx
    mov     dword ptr [g_tcvc_fs_id], 0
    xor     ebx, ebx                        ; sawCorrupt = 0

    call    exfat_probe
    cmp     eax, 0
    jg      tpf_found
    je      tpf_try_ntfs
    mov     ebx, 1

tpf_try_ntfs:
    call    ntfs_probe
    cmp     eax, 0
    jg      tpf_found
    je      tpf_try_ext
    mov     ebx, 1

tpf_try_ext:
    call    ext_probe
    cmp     eax, 0
    jg      tpf_found
    je      tpf_try_hfs
    mov     ebx, 1

tpf_try_hfs:
    call    hfsplus_probe
    cmp     eax, 0
    jg      tpf_found
    je      tpf_try_fat
    mov     ebx, 1

tpf_try_fat:
    call    fat_probe
    cmp     eax, 0
    jg      tpf_found
    je      tpf_done_none
    mov     ebx, 1

tpf_done_none:
    test    ebx, ebx
    jnz     tpf_corrupt
    mov     eax, EXIT_UNSUPPORTED
    jmp     tpf_out

tpf_found:
    mov     dword ptr [g_tcvc_fs_id], eax
    xor     eax, eax
    jmp     tpf_out

tpf_corrupt:
    mov     eax, EXIT_CORRUPT

tpf_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
tcvc_probe_fs endp

; =============================================================================
; tcvc_to_index() -> eax = EXIT_*
; Probes the unlocked volume's filesystem and populates g_idxptr.
; =============================================================================
public tcvc_to_index
tcvc_to_index proc frame
    FRAME_PROLOG 48
    call    idx_buf_ensure
    test    eax, eax
    jz      tti_buf_ok
    mov     eax, EXIT_OOM
    jmp     tti_out

tti_buf_ok:
    mov     qword ptr [g_idxlen], 0
    mov     qword ptr [g_idxcount], 0
    mov     qword ptr [g_idxflags], 0

    call    tcvc_probe_fs
    test    eax, eax
    jnz     tti_out

    mov     eax, dword ptr [g_tcvc_fs_id]
    cmp     eax, TCVC_FS_EXFAT
    je      tti_exfat
    cmp     eax, TCVC_FS_NTFS
    je      tti_ntfs
    cmp     eax, TCVC_FS_EXT
    je      tti_ext
    cmp     eax, TCVC_FS_HFSPLUS
    je      tti_hfs
    cmp     eax, TCVC_FS_FAT12
    jb      tti_unsup
    cmp     eax, TCVC_FS_FAT32
    jbe     tti_fat

tti_unsup:
    mov     eax, EXIT_UNSUPPORTED
    jmp     tti_out

tti_fat:
    call    fat_enum
    jmp     tti_out

tti_exfat:
    call    exfat_enum
    jmp     tti_out

tti_ntfs:
    call    ntfs_enum
    jmp     tti_out

tti_ext:
    call    ext_enum
    jmp     tti_out

tti_hfs:
    call    hfsplus_enum

tti_out:
    FRAME_EPILOG
    ret
tcvc_to_index endp

; =============================================================================
; tcvc_extract_entry(rcx = idxEntPtr) -> eax = EXIT_*
; Sanitizes path via entry_path, guards against junctions/symlinks via
; extract_guard, writes to random temp sibling, and commits atomically.
; =============================================================================
public tcvc_extract_entry
tcvc_extract_entry proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], rbx

    mov     r12, rcx                        ; idxEntPtr
    mov     qword ptr [g_tcvc_mem], 0
    mov     qword ptr [g_tcvc_memcap], 0
    mov     qword ptr [g_tcvc_memlen], 0
    mov     qword ptr [g_tcvc_hout], -1

    call    entry_path
    test    eax, eax
    jz      tee_path_ok
    mov     eax, EXIT_CORRUPT               ; entry_path already printed diagnostic
    jmp     tee_out

tee_path_ok:
    test    dword ptr [r12 + IDXE_flags], IDXEF_DIR
    jz      tee_file

    ; Directory entry
    lea     rcx, [g_extw]
    call    extract_guard
    test    eax, eax
    jnz     tee_link
    WINCALL CreateDirectoryW, addr g_extw, 0
    xor     eax, eax
    jmp     tee_out

tee_file:
    lea     rcx, [g_extw]
    call    extract_guard
    test    eax, eax
    jnz     tee_link

    lea     rcx, [g_extw]
    lea     rdx, [g_extmp]
    call    make_temp_sibling
    test    eax, eax
    jnz     tee_io

    lea     rcx, [g_extmp]
    call    file_open_new
    cmp     rax, -1
    je      tee_io
    mov     qword ptr [g_tcvc_hout], rax

    mov     rcx, r12
    mov     eax, dword ptr [g_tcvc_fs_id]
    cmp     eax, TCVC_FS_EXFAT
    je      tee_fs_exfat
    cmp     eax, TCVC_FS_NTFS
    je      tee_fs_ntfs
    cmp     eax, TCVC_FS_EXT
    je      tee_fs_ext
    cmp     eax, TCVC_FS_HFSPLUS
    je      tee_fs_hfs
    cmp     eax, TCVC_FS_FAT12
    jb      tee_fs_unsup
    cmp     eax, TCVC_FS_FAT32
    ja      tee_fs_unsup
    call    fat_extract_entry
    jmp     tee_fs_done

tee_fs_exfat:
    call    exfat_extract_entry
    jmp     tee_fs_done

tee_fs_ntfs:
    call    ntfs_extract_entry
    jmp     tee_fs_done

tee_fs_ext:
    call    ext_extract_entry
    jmp     tee_fs_done

tee_fs_hfs:
    call    hfsplus_extract_entry
    jmp     tee_fs_done

tee_fs_unsup:
    mov     eax, EXIT_UNSUPPORTED

tee_fs_done:
    mov     ebx, eax
    mov     rcx, qword ptr [g_tcvc_hout]
    call    file_close
    mov     qword ptr [g_tcvc_hout], -1

    test    ebx, ebx
    jnz     tee_discard_tmp

    lea     rcx, [g_extmp]
    lea     rdx, [g_extw]
    call    commit_temp
    test    eax, eax
    jnz     tee_commit_err

    lea     rcx, [r12 + IDXE_name]
    mov     edx, dword ptr [r12 + IDXE_namelen]
    call    rlog_extracted
    inc     qword ptr [g_tcvc_fcount]
    xor     eax, eax
    jmp     tee_out

tee_commit_err:
    mov     ebx, eax
tee_discard_tmp:
    lea     rcx, [g_extmp]
    call    file_delete
    mov     eax, ebx
    jmp     tee_out

tee_link:
    mov     eax, EXIT_UNSUPPORTED
    jmp     tee_out

tee_io:
    cmp     dword ptr [g_unpack_link], 0
    jne     tee_link
    mov     eax, EXIT_IO

tee_out:
    mov     r12, qword ptr [rbp-16]
    mov     rbx, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
tcvc_extract_entry endp

; =============================================================================
; tcvc_default_out() - g_tcvc_dflt_out = g_cfg_in minus trailing .tc/.hc, else + "_files"
; =============================================================================
tcvc_default_out proc frame
    FRAME_PROLOG 48
    mov     rcx, qword ptr [g_cfg_in]
    lea     r11, [g_tcvc_dflt_out]
    xor     r8d, r8d
tdo_cp:
    mov     ax, word ptr [rcx + r8*2]
    mov     word ptr [r11 + r8*2], ax
    test    ax, ax
    jz      tdo_copied
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS - 8
    jb      tdo_cp

tdo_copied:
    cmp     r8d, 3
    jbe     tdo_append                        ; e.g. ".tc" alone -> append "_files"
    cmp     word ptr [r11 + r8*2 - 6], '.'
    jne     tdo_append

    movzx   eax, word ptr [r11 + r8*2 - 4]
    cmp     eax, 'A'
    jb      tdo_c1
    cmp     eax, 'Z'
    ja      tdo_c1
    add     eax, 20h
tdo_c1:
    cmp     eax, 't'
    je      tdo_c2
    cmp     eax, 'h'
    jne     tdo_append
tdo_c2:
    movzx   eax, word ptr [r11 + r8*2 - 2]
    cmp     eax, 'A'
    jb      tdo_c3
    cmp     eax, 'Z'
    ja      tdo_c3
    add     eax, 20h
tdo_c3:
    cmp     eax, 'c'
    jne     tdo_append

    sub     r8d, 3
    mov     word ptr [r11 + r8*2], 0
    jmp     tdo_done

tdo_append:
    mov     word ptr [r11 + r8*2],      '_'
    mov     word ptr [r11 + r8*2 + 2],  'f'
    mov     word ptr [r11 + r8*2 + 4],  'i'
    mov     word ptr [r11 + r8*2 + 6],  'l'
    mov     word ptr [r11 + r8*2 + 8],  'e'
    mov     word ptr [r11 + r8*2 + 10], 's'
    mov     word ptr [r11 + r8*2 + 12], 0

tdo_done:
    FRAME_EPILOG
    ret
tcvc_default_out endp

; =============================================================================
; tcvc_extract_all() -> eax = EXIT_*
; Extracts all (or g_pick_active-selected) entries from g_idxptr to g_cfg_out.
; =============================================================================
public tcvc_extract_all
tcvc_extract_all proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], rbx

    mov     qword ptr [g_tcvc_fcount], 0
    call    extract_guard_reset

    call    idx_extract_bytes
    mov     r14, rax                        ; totalBytes

    mov     rcx, qword ptr [g_cfg_out]
    test    rcx, rcx
    jnz     tea_norm_out
    call    tcvc_default_out
    lea     rcx, [g_tcvc_dflt_out]
tea_norm_out:
    lea     rdx, [g_outdir_np]
    call    normalize_path
    test    eax, eax
    jnz     tea_io

    lea     rcx, [g_outdir_np]
    mov     rdx, r14
    add     rdx, DISK_MARGIN
    call    disk_has_space
    cmp     eax, 1
    je      tea_nospace

    WINCALL CreateDirectoryW, addr g_outdir_np, 0

    mov     rcx, r14
    lea     rdx, [lbl_tcvc_ext]
    mov     r8d, lbl_tcvc_ext_len
    call    progress_begin

    xor     r12d, r12d                      ; cursor into g_idxptr
    mov     r13, qword ptr [g_idxcount]     ; entries remaining

tea_loop:
    test    r13, r13
    jz      tea_done

    mov     rax, r12
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      tea_corrupt

    mov     rbx, qword ptr [g_idxptr]
    add     rbx, r12
    mov     ecx, dword ptr [rbx + IDXE_namelen]
    add     rax, rcx
    cmp     rax, qword ptr [g_idxlen]
    ja      tea_corrupt
    mov     r14, rax                        ; next cursor

    cmp     dword ptr [g_pick_active], 0
    je      tea_do_ent
    lea     rcx, [rbx + IDXE_name]
    mov     edx, dword ptr [rbx + IDXE_namelen]
    call    pick_has
    test    eax, eax
    jz      tea_next

tea_do_ent:
    mov     rcx, rbx
    call    tcvc_extract_entry
    test    eax, eax
    jnz     tea_out

tea_next:
    mov     r12, r14
    dec     r13
    jmp     tea_loop

tea_done:
    call    progress_done
    xor     eax, eax
    jmp     tea_out

tea_nospace:
    mov     eax, EXIT_NOSPACE
    jmp     tea_out
tea_corrupt:
    mov     eax, EXIT_CORRUPT
    jmp     tea_out
tea_io:
    mov     eax, EXIT_IO

tea_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     rbx, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
tcvc_extract_all endp

; =============================================================================
; tcvc_report_err(ecx = exitCode) - prints CLI error message for exitCode
; =============================================================================
tcvc_report_err proc frame
    FRAME_PROLOG 48
    cmp     ecx, EXIT_AUTH
    je      tre_auth
    cmp     ecx, EXIT_CORRUPT
    je      tre_corrupt
    cmp     ecx, EXIT_UNSUPPORTED
    je      tre_unsup
    cmp     ecx, EXIT_NOSPACE
    je      tre_nospace
    cmp     ecx, EXIT_OOM
    je      tre_oom
    cmp     ecx, EXIT_CANCELLED
    je      tre_done

    lea     rcx, [e_tcvc_io]
    mov     edx, e_tcvc_io_len
    call    print_err
    jmp     tre_done

tre_auth:
    lea     rcx, [e_tcvc_auth]
    mov     edx, e_tcvc_auth_len
    call    print_err
    jmp     tre_done
tre_corrupt:
    lea     rcx, [e_tcvc_corrupt]
    mov     edx, e_tcvc_corrupt_len
    call    print_err
    jmp     tre_done
tre_unsup:
    cmp     dword ptr [g_unpack_link], 0
    jne     tre_done                        ; report_link already printed
    lea     rcx, [e_tcvc_unsup]
    mov     edx, e_tcvc_unsup_len
    call    print_err
    jmp     tre_done
tre_nospace:
    lea     rcx, [e_tcvc_nospace]
    mov     edx, e_tcvc_nospace_len
    call    print_err
    jmp     tre_done
tre_oom:
    cmp     qword ptr [g_idxlen], IDX_MAX_BYTES - 4160
    jb      tre_oom_mem
    lea     rcx, [e_tcvc_idxfull]
    mov     edx, e_tcvc_idxfull_len
    call    print_err
    jmp     tre_done
tre_oom_mem:
    lea     rcx, [e_tcvc_oom]
    mov     edx, e_tcvc_oom_len
    call    print_err

tre_done:
    FRAME_EPILOG
    ret
tcvc_report_err endp

; =============================================================================
; do_tcvc_decrypt() -> eax = EXIT_*
; =============================================================================
public do_tcvc_decrypt
do_tcvc_decrypt proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx

    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_cfg_pass]
    mov     r8d, dword ptr [g_cfg_passlen]
    lea     r9,  [g_kf_paths]
    mov     eax, dword ptr [g_kf_count]
    mov     qword ptr [rsp+32], rax
    call    tcvc_open
    test    eax, eax
    jnz     dtd_err

    call    tcvc_to_index
    test    eax, eax
    jnz     dtd_err_close

    call    tcvc_extract_all
    test    eax, eax
    jnz     dtd_err_close

    call    tcvc_close

    lea     rcx, [msg_tcvc_done1]
    mov     edx, msg_tcvc_done1_len
    call    print_a
    mov     rcx, qword ptr [g_tcvc_fcount]
    call    print_u64
    lea     rcx, [msg_tcvc_done2]
    mov     edx, msg_tcvc_done2_len
    call    print_a
    xor     eax, eax
    jmp     dtd_out

dtd_err_close:
    mov     ebx, eax
    call    tcvc_close
    mov     eax, ebx
dtd_err:
    mov     ebx, eax
    mov     ecx, ebx
    call    tcvc_report_err
    mov     eax, ebx

dtd_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
do_tcvc_decrypt endp

; =============================================================================
; do_tcvc_verify() -> eax = EXIT_*
; =============================================================================
public do_tcvc_verify
do_tcvc_verify proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx

    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_cfg_pass]
    mov     r8d, dword ptr [g_cfg_passlen]
    lea     r9,  [g_kf_paths]
    mov     eax, dword ptr [g_kf_count]
    mov     qword ptr [rsp+32], rax
    call    tcvc_open
    test    eax, eax
    jnz     dtv_err

    call    tcvc_to_index
    mov     ebx, eax
    call    tcvc_close
    test    ebx, ebx
    jnz     dtv_err_ebx

    lea     rcx, [msg_tcvc_ver_ok]
    mov     edx, msg_tcvc_ver_ok_len
    call    print_a
    xor     eax, eax
    jmp     dtv_out

dtv_err:
    mov     ebx, eax
dtv_err_ebx:
    mov     ecx, ebx
    call    tcvc_report_err
    mov     eax, ebx

dtv_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
do_tcvc_verify endp

; =============================================================================
; do_tcvc_list_idx() -> eax = EXIT_*
; Opens the TC/VC volume, enumerates into g_idxptr, and closes the volume so
; pack.asm:do_list can render g_idxptr with its buffered formatter.
; =============================================================================
public do_tcvc_list_idx
do_tcvc_list_idx proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx

    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_cfg_pass]
    mov     r8d, dword ptr [g_cfg_passlen]
    lea     r9,  [g_kf_paths]
    mov     eax, dword ptr [g_kf_count]
    mov     qword ptr [rsp+32], rax
    call    tcvc_open
    test    eax, eax
    jnz     dtl_err

    call    tcvc_to_index
    mov     ebx, eax
    call    tcvc_close
    test    ebx, ebx
    jnz     dtl_err_ebx
    xor     eax, eax
    jmp     dtl_out

dtl_err:
    mov     ebx, eax
dtl_err_ebx:
    mov     ecx, ebx
    call    tcvc_report_err
    mov     eax, ebx

dtl_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
do_tcvc_list_idx endp

; =============================================================================
; tcvc_is_open() -> eax = 1 if an unlocked TC/VC volume is currently open
; =============================================================================
public tcvc_is_open
tcvc_is_open proc
    mov     eax, dword ptr [g_tcvc_open_flag]
    ret
tcvc_is_open endp

; =============================================================================
; tcvc_wcat(rcx = dstBase, edx = curPos, r8d = maxPos, r9 = srcWide) -> eax = newPos
; =============================================================================
tcvc_wcat proc
    mov     eax, edx
twc_loop:
    cmp     eax, r8d
    jae     twc_done
    movzx   r10d, word ptr [r9]
    test    r10d, r10d
    jz      twc_done
    mov     word ptr [rcx + rax*2], r10w
    inc     eax
    add     r9, 2
    jmp     twc_loop
twc_done:
    mov     word ptr [rcx + rax*2], 0
    ret
tcvc_wcat endp

; =============================================================================
; tcvc_format_status(rcx = wideDst, edx = capChars)
; Writes "<TrueCrypt|VeraCrypt> · <Cipher> · <KDF> · <FS> · Read-Only (XTS)"
; =============================================================================
public tcvc_format_status
tcvc_format_status proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13

    test    rcx, rcx
    jz      tfs_out
    cmp     edx, 2
    jb      tfs_out

    mov     rbx, rcx                        ; dstBase
    lea     r12d, [edx - 1]                 ; maxPos (reserve NUL)
    xor     r13d, r13d                      ; curPos = 0
    mov     word ptr [rbx], 0

    ; 1. Container format
    lea     r9, [ws_tc_fmt_tc]
    cmp     dword ptr [g_tcvc_is_vera], 0
    je      tfs_fmt
    lea     r9, [ws_tc_fmt_vc]
tfs_fmt:
    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    call    tcvc_wcat
    mov     r13d, eax

    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    lea     r9, [ws_tc_sep]
    call    tcvc_wcat
    mov     r13d, eax

    ; 2. XTS cipher / cascade
    lea     r9, [ws_tc_unk]
    mov     eax, dword ptr [g_tcvc_mode_id]
    cmp     eax, 15
    jae     tfs_mode
    lea     rcx, [tcvc_mode_names]
    mov     r9, qword ptr [rcx + rax*8]
tfs_mode:
    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    call    tcvc_wcat
    mov     r13d, eax

    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    lea     r9, [ws_tc_sep]
    call    tcvc_wcat
    mov     r13d, eax

    ; 3. Header KDF
    lea     r9, [ws_tc_unk]
    mov     eax, dword ptr [g_tcvc_kdf_id]
    cmp     eax, 7
    jae     tfs_kdf
    lea     rcx, [tcvc_kdf_names]
    mov     r9, qword ptr [rcx + rax*8]
tfs_kdf:
    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    call    tcvc_wcat
    mov     r13d, eax

    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    lea     r9, [ws_tc_sep]
    call    tcvc_wcat
    mov     r13d, eax

    ; 4. Filesystem
    lea     r9, [ws_tc_unk]
    mov     eax, dword ptr [g_tcvc_fs_id]
    cmp     eax, 8
    jae     tfs_fs
    lea     rcx, [tcvc_fs_names]
    mov     r9, qword ptr [rcx + rax*8]
tfs_fs:
    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    call    tcvc_wcat
    mov     r13d, eax

    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    lea     r9, [ws_tc_sep]
    call    tcvc_wcat
    mov     r13d, eax

    ; 5. Read-Only (XTS) notice
    mov     rcx, rbx
    mov     edx, r13d
    mov     r8d, r12d
    lea     r9, [ws_tc_ro]
    call    tcvc_wcat

tfs_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
tcvc_format_status endp

; =============================================================================
; tcvc_entry_to_mem(rcx = idxEntFixedPtr, rdx = outPtrLen16) -> eax = EXIT_*
; Extracts a single file entry into a mem_alloc'd buffer for virtual drag-out.
; =============================================================================
public tcvc_entry_to_mem
tcvc_entry_to_mem proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14

    mov     r12, rcx                        ; idxEntFixedPtr
    mov     r13, rdx                        ; outPtrLen16
    mov     qword ptr [r13], 0
    mov     qword ptr [r13 + 8], 0

    cmp     dword ptr [g_tcvc_open_flag], 0
    je      tem_io

    test    dword ptr [r12 + IDXE_flags], IDXEF_DIR
    jnz     tem_zero

    mov     r14, qword ptr [r12 + IDXE_size]
    test    r14, r14
    jz      tem_zero
    cmp     r14, 20000000h                  ; 512 MiB cap for in-RAM drag stream
    ja      tem_oom

    mov     rcx, r14
    call    mem_alloc
    test    rax, rax
    jz      tem_oom
    mov     rbx, rax                        ; allocated buffer

    mov     qword ptr [g_tcvc_mem], rbx
    mov     qword ptr [g_tcvc_memcap], r14
    mov     qword ptr [g_tcvc_memlen], 0
    mov     qword ptr [g_tcvc_hout], -1

    mov     rcx, r12
    mov     eax, dword ptr [g_tcvc_fs_id]
    cmp     eax, TCVC_FS_EXFAT
    je      tem_exfat
    cmp     eax, TCVC_FS_NTFS
    je      tem_ntfs
    cmp     eax, TCVC_FS_EXT
    je      tem_ext
    cmp     eax, TCVC_FS_HFSPLUS
    je      tem_hfs
    cmp     eax, TCVC_FS_FAT12
    jb      tem_unsup_free
    cmp     eax, TCVC_FS_FAT32
    jbe     tem_fat
    jmp     tem_unsup_free

tem_fat:
    call    fat_extract_entry
    jmp     tem_done_fs
tem_exfat:
    call    exfat_extract_entry
    jmp     tem_done_fs
tem_ntfs:
    call    ntfs_extract_entry
    jmp     tem_done_fs
tem_ext:
    call    ext_extract_entry
    jmp     tem_done_fs
tem_hfs:
    call    hfsplus_extract_entry

tem_done_fs:
    mov     qword ptr [g_tcvc_mem], 0
    mov     qword ptr [g_tcvc_memcap], 0
    test    eax, eax
    jnz     tem_err_free

    mov     rcx, qword ptr [g_tcvc_memlen]
    cmp     rcx, r14
    jne     tem_corrupt_free

    mov     qword ptr [r13], rbx
    mov     qword ptr [r13 + 8], r14
    xor     eax, eax
    jmp     tem_out

tem_unsup_free:
    mov     qword ptr [g_tcvc_mem], 0
    mov     qword ptr [g_tcvc_memcap], 0
    mov     eax, EXIT_UNSUPPORTED
    jmp     tem_err_free
tem_corrupt_free:
    mov     eax, EXIT_CORRUPT
tem_err_free:
    mov     dword ptr [rbp-48], eax
    mov     rcx, rbx
    mov     rdx, r14
    call    mem_free
    mov     eax, dword ptr [rbp-48]
    jmp     tem_out

tem_zero:
    xor     eax, eax
    jmp     tem_out
tem_oom:
    mov     eax, EXIT_OOM
    jmp     tem_out
tem_io:
    mov     eax, EXIT_IO

tem_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
tcvc_entry_to_mem endp

; =============================================================================
; do_tcvc_gui_extract() -> eax = EXIT_*
; Extracts entries to g_cfg_out on the GUI worker thread.
; If the volume is already open (container browser), reuses it and leaves it
; open; otherwise (--to right-drag) opens, indexes, extracts, and closes.
; =============================================================================
public do_tcvc_gui_extract
do_tcvc_gui_extract proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx

    cmp     dword ptr [g_tcvc_open_flag], 0
    je      dtge_cold

    call    tcvc_extract_all
    mov     ebx, eax
    jmp     dtge_done

dtge_cold:
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_cfg_pass]
    mov     r8d, dword ptr [g_cfg_passlen]
    lea     r9,  [g_kf_paths]
    mov     eax, dword ptr [g_kf_count]
    mov     qword ptr [rsp+32], rax
    call    tcvc_open
    mov     ebx, eax
    test    ebx, ebx
    jnz     dtge_done

    call    tcvc_to_index
    mov     ebx, eax
    test    ebx, ebx
    jnz     dtge_close

    call    tcvc_extract_all
    mov     ebx, eax

dtge_close:
    call    tcvc_close

dtge_done:
    test    ebx, ebx
    jnz     dtge_rep_err
    lea     rcx, [msg_tcvc_done1]
    mov     edx, msg_tcvc_done1_len
    call    print_a
    mov     rcx, qword ptr [g_tcvc_fcount]
    call    print_u64
    lea     rcx, [msg_tcvc_done2]
    mov     edx, msg_tcvc_done2_len
    call    print_a
    jmp     dtge_ret
dtge_rep_err:
    mov     ecx, ebx
    call    tcvc_report_err
dtge_ret:
    mov     eax, ebx
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
do_tcvc_gui_extract endp

end
