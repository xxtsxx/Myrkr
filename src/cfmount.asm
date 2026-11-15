; =============================================================================
; cfmount.asm - User-Mode Drive Mounting via Windows Cloud Files API
; -----------------------------------------------------------------------------
; Mounts unlocked native Myrkr (.mrk) archives Read/Write by default and
; TrueCrypt/VeraCrypt (.tc/.hc) or fallback .mrk containers Read-Only as
; standard session-scoped Windows drive letters (Z: downward) with zero
; elevation and zero kernel driver installation:
;   1. Creates an isolated sync-root directory under %LOCALAPPDATA%\Myrkr\Mounts
;      (marked FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, without EFS so Windows never
;      nags to back up an EFS certificate) plus an exclusive DELETE_ON_CLOSE
;      lockfile so concurrent Myrkr windows never disturb live mounts while
;      crashed mounts are swept on next startup.
;   2. Registers the sync root via cldapi.dll (loaded dynamically from System32)
;      and populates placeholders carrying a self-contained 48-byte FileIdentity
;      ([8B CSPRNG session magic] || [40B INDEX_ENTRY header]).
;   3. Serves on-demand FetchData callbacks in 256 KiB chunks under an SRWLock,
;      authenticating .mrk GCM tags fail-closed before returning plaintext and
;      streaming .tc/.hc ranges with early stop via tcvc_read_range.
;   4. Automatically dehydrates untouched placeholders back to 0 on-disk bytes
;      upon NOTIFY_FILE_CLOSE_COMPLETION, LRU file switch, and unmount, while
;      Read/Write .mrk mounts lazily stage mutations into a compliant format-v9
;      <stem>.delta.mrk sidecar for atomic ReplaceFileW merge on dismount.
; =============================================================================

include macros.inc

extern LoadLibraryExW:proc
extern GetProcAddress:proc
extern AcquireSRWLockExclusive:proc
extern ReleaseSRWLockExclusive:proc
extern VirtualAlloc:proc
extern VirtualFree:proc
extern GetEnvironmentVariableW:proc
extern GetTempPathW:proc
extern GetSystemTimeAsFileTime:proc
extern CreateDirectoryW:proc
extern RemoveDirectoryW:proc
extern CreateFileW:proc
extern ReadFile:proc
extern WriteFile:proc
extern FlushFileBuffers:proc
extern GetFileSizeEx:proc
extern MoveFileExW:proc
extern CloseHandle:proc
extern DeleteFileW:proc
extern GetFileAttributesW:proc
extern SetFileAttributesW:proc
extern GetCompressedFileSizeW:proc
extern FindFirstFileW:proc
extern FindNextFileW:proc
extern FindClose:proc
extern MultiByteToWideChar:proc
extern WideCharToMultiByte:proc
extern CompareStringOrdinal:proc
extern GetLogicalDrives:proc
extern DefineDosDeviceW:proc
extern QueryDosDeviceW:proc
extern TrySubmitThreadpoolCallback:proc
extern CreateEventW:proc
extern ResetEvent:proc
extern SetEvent:proc
extern CreateThread:proc
extern WaitForSingleObject:proc
extern WaitForMultipleObjects:proc
extern ReadDirectoryChangesW:proc
extern GetOverlappedResult:proc
extern CancelIoEx:proc
extern PostMessageW:proc
extern Sleep:proc
extern DecryptFileW:proc
extern SHChangeNotify:proc
extern ShellExecuteW:proc

extern rng_fill:proc
extern secure_zero:proc
extern mem_alloc:proc
extern mem_free:proc
extern sstk_thread_init:proc
extern sstk_thread_free:proc
extern sanitize_name:proc
extern create_parents:proc
extern tcvc_read_range:proc
extern argon2id_hash:proc
extern sha256_hash:proc
extern gcm_init:proc
extern gcm_aad:proc
extern gcm_crypt:proc
extern gcm_final:proc
extern tar_build_header:proc
extern entry_stream_open:proc
extern nonce_set:proc
extern delta_path_for:proc
extern es_new:proc
extern es_bind:proc
extern es_cur_pos:proc
extern es_code:proc
extern es_destroy:proc
extern ES_Read:proc
extern ES_Seek:proc

externdef g_sstk_tls:dword
externdef g_key:byte
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_pkhdr:byte
externdef g_hwnd:qword
externdef g_idxptr:qword
externdef g_idxlen:qword
externdef g_idxcount:qword

; -----------------------------------------------------------------------------
; Module-private constants (CFM_* prefix avoids cross-module collisions)
; -----------------------------------------------------------------------------
CFM_LOAD_SYS32          equ 0800h       ; LOAD_LIBRARY_SEARCH_SYSTEM32
CFM_MEM_COMMIT_RES      equ 3000h       ; MEM_COMMIT | MEM_RESERVE
CFM_MEM_RELEASE         equ 8000h       ; MEM_RELEASE
CFM_PAGE_RW             equ 04h         ; PAGE_READWRITE
CFM_CP_UTF8             equ 65001
CFM_MB_ERR_INV          equ 8           ; MB_ERR_INVALID_CHARS
CFM_CSTR_EQUAL          equ 2
CFM_GENERIC_RW          equ 0C0000000h  ; GENERIC_READ | GENERIC_WRITE
CFM_GENERIC_WRITE       equ 40000000h
CFM_CREATE_ALWAYS       equ 2
CFM_OPEN_EXISTING       equ 3
CFM_ATTR_READONLY       equ 1
CFM_ATTR_DIR            equ 10h
CFM_ATTR_NORMAL         equ 80h
CFM_ATTR_REPARSE        equ 400h
CFM_ATTR_NOT_INDEXED    equ 2000h       ; FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
CFM_ATTR_ENCRYPTED      equ 4000h       ; FILE_ATTRIBUTE_ENCRYPTED
CFM_INV_ATTR            equ 0FFFFFFFFh
CFM_FLAG_DEL_CLOSE      equ 04000000h   ; FILE_FLAG_DELETE_ON_CLOSE
CFM_REPARSE_SURR        equ 20000000h   ; IsReparseTagNameSurrogate bit
CFM_DDD_REMOVE          equ 2           ; DDD_REMOVE_DEFINITION
CFM_DDD_EXACT_MATCH     equ 4           ; DDD_EXACT_MATCH_ON_REMOVE
CFM_SHCNE_DRIVEADD      equ 0100h
CFM_SHCNE_DRIVEREMOVED  equ 0080h
CFM_SHCNF_PATHW         equ 0005h
CFM_SW_SHOWNORMAL       equ 1

CFM_CHUNK_BYTES         equ 40000h      ; 256 KiB transfer chunk (64 * 4096)
CFM_TC_CACHE_MAX        equ 400000h     ; 4 MiB 1-entry RAM cache for TC/VC
CFM_MRK_CACHE_MAX       equ 1000000h    ; 16 MiB pre-authenticated cache for .mrk
CFM_WIPE_BUF_BYTES      equ 10000h      ; 64 KiB zero buffer for hydrated wipe
CFM_WIPE_CAP_BYTES      equ 40000000h   ; 1 GiB max wipe per file
CFM_TREE_ALLOC_BYTES    equ 11000h      ; 68 KiB per-level FindFirstFile scratch
CFM_MAX_DEPTH           equ 64

CFM_REG_FLAGS           equ 6           ; DISABLE_ON_DEMAND_POPULATION_ON_ROOT(2) | MARK_IN_SYNC_ON_ROOT(4)
CFM_CONNECT_FLAGS       equ 0Eh         ; REQUIRE_PROCESS_INFO(2) | REQUIRE_FULL_FILE_PATH(4) | BLOCK_SELF_IMPLICIT_HYDRATION(8)
CFM_POP_ALWAYS_FULL     equ 3           ; CF_POPULATION_POLICY_ALWAYS_FULL
CFM_INSYNC_RW           equ 80000100h   ; PRESERVE_INSYNC_FOR_SYNC_ENGINE | TRACK_FILE_LAST_WRITE_TIME
CFM_PCI_MARK_INSYNC     equ 2           ; CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
CFM_DEHYD_BG            equ 1           ; CF_DEHYDRATE_FLAG_BACKGROUND
CFM_STATUS_UNSUCCESSFUL equ 0C0000001h
CFM_STATUS_CHECKSUM_ERR equ 0C0000242h
CFM_MEM_RESERVE         equ 2000h
CFM_MEM_COMMIT          equ 1000h
CFM_BASE_SEEN           equ 80000000h   ; transient mark bit on g_cf_base_idx entries
CFM_MOVE_REPLACE_WT     equ 9           ; MOVEFILE_REPLACE_EXISTING(1) | MOVEFILE_WRITE_THROUGH(8)
CFM_NOTIFY_FILTER       equ 17Fh        ; FILE_NAME|DIR_NAME|ATTR|SIZE|LAST_WRITE|CREATION|SECURITY
CFM_WAIT_TIMEOUT        equ 102h
CFM_WM_DELTASYNC        equ 8006h       ; WM_APP + 6 notification to GUI window
CFM_GENERIC_READ        equ 80000000h
CFM_FILE_READ_ATTR      equ 80h
CFM_FILE_LIST_DIR       equ 1
CFM_SHARE_ALL           equ 7           ; FILE_SHARE_READ | WRITE | DELETE
CFM_FLAG_BACKUP         equ 02000000h   ; FILE_FLAG_BACKUP_SEMANTICS
CFM_FLAG_OV_BACKUP      equ 42000000h   ; FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS
CFM_DIFF_SCRATCH        equ 30000h      ; 192 KiB per-level walk scratch
CFM_SYNC_WORK_BYTES     equ 40000h      ; 256 KiB delta writer working page
CFM_REC_ARENA_CAP       equ 10000000h   ; 256 MiB delta item arena cap
CFM_MAN_ARENA_CAP       equ 4000000h    ; 64 MiB manifest arena cap
CFM_IDX_ARENA_CAP       equ 10000000h   ; 256 MiB delta index arena cap

CFM_DW_HOUT             equ 0
CFM_DW_PAYOFF           equ 8
CFM_DW_ENTOFF           equ 16
CFM_DW_ORD              equ 24
CFM_DW_SEGFILL          equ 32
CFM_DW_SINKBUF          equ 40
CFM_DW_SINKFILL         equ 48
CFM_DW_SEGIDX           equ 56
CFM_DW_ERR              equ 60
CFM_DW_HDR              equ 64
CFM_DW_TAG              equ 144
CFM_DW_BYTES            equ 160

.const
align 2
w_cf_empty              dw 0
WSTR w_cf_cldapi,       <cldapi.dll>
WSTR w_cf_localapp,     <LOCALAPPDATA>
WSTR w_cf_sub_myrkr,    <\Myrkr>
WSTR w_cf_sub_mounts,   <\Mounts>
WSTR w_cf_lock_ext,     <.lock>
WSTR w_cf_star,         <\*>
WSTR w_cf_prov_name,    <Myrkr>
WSTR w_cf_prov_ver,     <1.0>
WSTR w_cf_explore,      <explore>
WSTR w_cf_explorer_exe, <explorer.exe>
WSTR w_cf_dllhost_exe,  <dllhost.exe>
WSTR w_cf_search_exe,   <SearchProtocolHost.exe>
WSTR w_cf_rtbroker_exe, <RuntimeBroker.exe>
WSTR w_cf_recycle,      <$RECYCLE.BIN>
WSTR w_cf_svi,          <System Volume Information>
WSTR w_cf_delta_mf,     <.myrkr-delta>

a_CfRegisterSyncRoot    db "CfRegisterSyncRoot", 0
a_CfUnregisterSyncRoot  db "CfUnregisterSyncRoot", 0
a_CfConnectSyncRoot     db "CfConnectSyncRoot", 0
a_CfDisconnectSyncRoot  db "CfDisconnectSyncRoot", 0
a_CfCreatePlaceholders  db "CfCreatePlaceholders", 0
a_CfExecute             db "CfExecute", 0
a_CfOpenFileWithOplock  db "CfOpenFileWithOplock", 0
a_CfGetWin32Handle      db "CfGetWin32HandleFromProtectedHandle", 0
a_CfCloseHandle         db "CfCloseHandle", 0
a_CfDehydrate           db "CfDehydratePlaceholder", 0
a_CfGetPlaceholderInfo  db "CfGetPlaceholderInfo", 0
a_CfHydratePlaceholder  db "CfHydratePlaceholder", 0
a_cf_hex                db "0123456789abcdef"
a_cf_mf_name            db ".myrkr-delta", 0
a_cf_mf_hdr1            db "myrkr-delta-v1", 10, "base-id: "
a_cf_mf_del             db "del: "

align 8
; CF_SYNC_POLICIES (24 bytes) - Read-Only mounts (.tc/.hc & R/O .mrk)
cf_sync_policies label byte
    dd 24                               ; StructSize
    dw 0                                ; CF_HYDRATION_POLICY_PARTIAL
    dw 6                                ; STREAMING_ALLOWED(2) | AUTO_DEHYDRATION_ALLOWED(4)
    dw CFM_POP_ALWAYS_FULL              ; CF_POPULATION_POLICY_ALWAYS_FULL (3)
    dw 0                                ; Population.Modifier
    dd 0                                ; CF_INSYNC_POLICY_NONE
    dd 0                                ; CF_HARDLINK_POLICY_NONE
    dd 0                                ; CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT

align 8
; CF_SYNC_POLICIES (24 bytes) - Read/Write .mrk mounts
; Note: STREAMING_ALLOWED(2) MUST NOT be set on R/W mounts.  With streaming
; allowed, cldflt.sys may satisfy TRANSFER_DATA without persisting blocks on
; disk, leaving unhydrated placeholders unable to complete in-place WriteFile.
cf_sync_policies_rw label byte
    dd 24                               ; StructSize
    dw 2                                ; CF_HYDRATION_POLICY_FULL
    dw 4                                ; AUTO_DEHYDRATION_ALLOWED(4) (no STREAMING_ALLOWED)
    dw CFM_POP_ALWAYS_FULL              ; CF_POPULATION_POLICY_ALWAYS_FULL (3)
    dw 0                                ; Population.Modifier
    dd CFM_INSYNC_RW                    ; PRESERVE_INSYNC_FOR_SYNC_ENGINE | TRACK_FILE_LAST_WRITE_TIME
    dd 0                                ; CF_HARDLINK_POLICY_NONE
    dd 0                                ; CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT

; Fixed Myrkr Cloud-Files ProviderId GUID {4D59524B-5243-4653-9A71-8E31D42C0F19}
cf_provider_guid label byte
    dd 4D59524Bh
    dw 5243h, 4653h
    db 9Ah, 71h, 8Eh, 31h, 0D4h, 2Ch, 0Fh, 19h

align 8
; CF_CALLBACK_REGISTRATION[4] (64 bytes)
; Note: Type 5 (NOTIFY_FILE_OPEN_COMPLETION) MUST NOT be registered because
; cldflt.sys blocks external opens unless ACK_OPEN is issued.
cf_callback_table label qword
    dd 0, 0                             ; CF_CALLBACK_TYPE_FETCH_DATA = 0
    dq cf_cb_fetch_data
    dd 2, 0                             ; CF_CALLBACK_TYPE_CANCEL_FETCH_DATA = 2
    dq cf_cb_cancel_fetch
    dd 6, 0                             ; CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION = 6
    dq cf_cb_close_completion
    dd 0FFFFFFFFh, 0                    ; CF_CALLBACK_TYPE_NONE
    dq 0

.data?
align 16
public g_cf_mrk_key
public g_cf_delta_key
public g_cf_pass
public g_cf_dctx
g_cf_mrk_key            db KEY_LEN dup (?)
g_cf_delta_key          db KEY_LEN dup (?)
g_cf_pass               db (MAX_PASSWORD_BYTES + 1) dup (?)
align 16
g_cf_dctx               db 336 dup (?)
g_cf_zeros512           db 512 dup (?)

align 8
g_cf_lock               dq ?            ; SRWLOCK (0-initialized = SRWLOCK_INIT)
g_cf_delta_lock         dq ?            ; SRWLOCK serializing delta sidecar builds
g_cf_hcldapi            dq ?
pfn_CfRegisterSyncRoot  dq ?
pfn_CfUnregisterSyncRoot dq ?
pfn_CfConnectSyncRoot   dq ?
pfn_CfDisconnectSyncRoot dq ?
pfn_CfCreatePlaceholders dq ?
pfn_CfExecute           dq ?
pfn_CfOpenFileWithOplock dq ?
pfn_CfGetWin32Handle    dq ?
pfn_CfCloseHandle       dq ?
pfn_CfDehydrate         dq ?
pfn_CfGetPlaceholderInfo dq ?
pfn_CfHydratePlaceholder dq ?

g_cf_conn_key           dq ?
g_cf_session_magic      dq ?
g_cf_mount_ft           dq ?
g_cf_hlock              dq ?
g_cf_xfer_buf           dq ?
g_cf_esctx              dq ?
g_cf_mrk_ord            dq ?
g_cf_mrk_off            dq ?

; R/W .mrk snapshot & watcher state
g_cf_base_hdr           db HDR_BYTES dup (?)
align 8
g_cf_base_idx           dq ?
g_cf_base_idxlen        dq ?
g_cf_base_idxcnt        dq ?
g_cf_synced_fp          dq ?
g_cf_stop_evt           dq ?
g_cf_wake_evt           dq ?
g_cf_watch_th           dq ?

; 1-entry decrypted RAM cache (shared for TC/VC <= 4 MiB and .mrk <= 16 MiB)
g_cf_ent_buf            dq ?
g_cf_ent_size           dq ?
g_cf_ent_hdr            db IDXE_FIXED dup (?)

g_cf_id_buf             db 48 dup (?)
g_cf_pci                db 88 dup (?)

g_cf_api_state          dd ?            ; 0 = unprobed, 1 = ok, -1 = unavailable
g_cf_mounted            dd ?            ; 1 = active mount
g_cf_unmounting         dd ?            ; 1 = tearing down (reject callbacks)
g_cf_is_tcvc            dd ?            ; 1 = TC/VC, 0 = .mrk
g_cf_is_rw              dd ?            ; 1 = Read/Write .mrk mount, 0 = Read-Only
g_cf_dirty              dd ?            ; 1 = <stem>.delta.mrk exists on disk
g_cf_commit_state       dd ?            ; 0 = clean, 1 = synced, 2 = needs final sync
g_cf_passlen            dd ?            ; UTF-8 length of g_cf_pass
g_cf_letter             dd ?            ; 'D'..'Z' or 0
g_cf_mrk_bound          dd ?            ; 1 = g_cf_esctx currently bound
g_cf_ent_kind           dd ?            ; 0 = empty, 1 = .mrk, 2 = TC/VC
g_cf_dehyd_inflight     dd ?            ; atomic count of threadpool dehydrations

align 2
g_cf_drv_colon          dw 4 dup (?)    ; "Z:", 0
g_cf_drv_slash          dw 4 dup (?)    ; "Z:\", 0
g_cf_base_w             dw MAX_PATH_CHARS dup (?)
g_cf_root_w             dw MAX_PATH_CHARS dup (?)
g_cf_lock_w             dw MAX_PATH_CHARS dup (?)
g_cf_delta_w            dw MAX_PATH_CHARS dup (?)
g_cf_dtmp_w             dw MAX_PATH_CHARS dup (?)
g_cf_path_w             dw MAX_PATH_CHARS dup (?)
g_cf_last_hyd_w         dw MAX_PATH_CHARS dup (?)
g_cf_cur_hyd_w          dw MAX_PATH_CHARS dup (?)
g_cf_last_dir_w         dw MAX_PATH_CHARS dup (?)
g_cf_rel_w              dw 4112 dup (?)
g_cf_u8name             db 4112 dup (?)

.code

; =============================================================================
; cfmount_lock / cfmount_unlock - exclusive SRWLock serializing FetchData and
; container state access.
; =============================================================================
public cfmount_lock
cfmount_lock proc frame
    FRAME_PROLOG 32
    WINCALL AcquireSRWLockExclusive, addr g_cf_lock
    FRAME_EPILOG
    ret
cfmount_lock endp

public cfmount_unlock
cfmount_unlock proc frame
    FRAME_PROLOG 32
    WINCALL ReleaseSRWLockExclusive, addr g_cf_lock
    FRAME_EPILOG
    ret
cfmount_unlock endp

; =============================================================================
; cfmount_is_mounted() -> eax = 1 if mounted, else 0
; cfmount_letter()     -> eax = 'D'..'Z' if mounted, else 0
; =============================================================================
public cfmount_is_mounted
cfmount_is_mounted proc
    mov     eax, dword ptr [g_cf_mounted]
    ret
cfmount_is_mounted endp

public cfmount_letter
cfmount_letter proc
    xor     eax, eax
    cmp     dword ptr [g_cf_mounted], 0
    je      @F
    mov     eax, dword ptr [g_cf_letter]
@@:
    ret
cfmount_letter endp

public cfmount_is_rw
cfmount_is_rw proc
    xor     eax, eax
    cmp     dword ptr [g_cf_mounted], 0
    je      @F
    mov     eax, dword ptr [g_cf_is_rw]
@@:
    ret
cfmount_is_rw endp

public cfmount_is_dirty
cfmount_is_dirty proc
    xor     eax, eax
    cmp     dword ptr [g_cf_mounted], 0
    je      @F
    mov     eax, dword ptr [g_cf_dirty]
@@:
    ret
cfmount_is_dirty endp

; =============================================================================
; cf_init_procs() -> eax = 1 if cldapi.dll loaded & resolved, else 0
; =============================================================================
cf_init_procs proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx

    mov     eax, dword ptr [g_cf_api_state]
    cmp     eax, 1
    je      cip_ok
    cmp     eax, -1
    je      cip_fail

    WINCALL LoadLibraryExW, addr w_cf_cldapi, 0, CFM_LOAD_SYS32
    test    rax, rax
    jz      cip_mark_fail
    mov     rbx, rax
    mov     qword ptr [g_cf_hcldapi], rax

    WINCALL GetProcAddress, rbx, addr a_CfRegisterSyncRoot
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfRegisterSyncRoot], rax

    WINCALL GetProcAddress, rbx, addr a_CfUnregisterSyncRoot
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfUnregisterSyncRoot], rax

    WINCALL GetProcAddress, rbx, addr a_CfConnectSyncRoot
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfConnectSyncRoot], rax

    WINCALL GetProcAddress, rbx, addr a_CfDisconnectSyncRoot
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfDisconnectSyncRoot], rax

    WINCALL GetProcAddress, rbx, addr a_CfCreatePlaceholders
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfCreatePlaceholders], rax

    WINCALL GetProcAddress, rbx, addr a_CfExecute
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfExecute], rax

    WINCALL GetProcAddress, rbx, addr a_CfOpenFileWithOplock
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfOpenFileWithOplock], rax

    WINCALL GetProcAddress, rbx, addr a_CfGetWin32Handle
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfGetWin32Handle], rax

    WINCALL GetProcAddress, rbx, addr a_CfCloseHandle
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfCloseHandle], rax

    WINCALL GetProcAddress, rbx, addr a_CfDehydrate
    test    rax, rax
    jz      cip_mark_fail
    mov     qword ptr [pfn_CfDehydrate], rax

    ; Optional R/W placeholder inspection & explicit hydration procs
    WINCALL GetProcAddress, rbx, addr a_CfGetPlaceholderInfo
    mov     qword ptr [pfn_CfGetPlaceholderInfo], rax
    WINCALL GetProcAddress, rbx, addr a_CfHydratePlaceholder
    mov     qword ptr [pfn_CfHydratePlaceholder], rax

    mov     dword ptr [g_cf_api_state], 1
cip_ok:
    mov     eax, 1
    jmp     cip_out

cip_mark_fail:
    mov     dword ptr [g_cf_api_state], -1
cip_fail:
    xor     eax, eax

cip_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
cf_init_procs endp

; =============================================================================
; cf_wcopy_cat(rcx = dstW, edx = capChars, r8 = src1W, r9 = src2W_or_0)
;   -> eax = 1 ok, 0 overflow/bad
; =============================================================================
cf_wcopy_cat proc
    test    rcx, rcx
    jz      cwcc_fail
    cmp     edx, 2
    jb      cwcc_fail
    test    r8, r8
    jz      cwcc_fail

    dec     edx                             ; max chars before NUL
    xor     r10d, r10d                      ; write pos

cwcc_s1:
    mov     ax, word ptr [r8]
    test    ax, ax
    jz      cwcc_s2_chk
    cmp     r10d, edx
    jae     cwcc_fail_zero
    mov     word ptr [rcx + r10*2], ax
    inc     r10d
    add     r8, 2
    jmp     cwcc_s1

cwcc_s2_chk:
    test    r9, r9
    jz      cwcc_done
cwcc_s2:
    mov     ax, word ptr [r9]
    test    ax, ax
    jz      cwcc_done
    cmp     r10d, edx
    jae     cwcc_fail_zero
    mov     word ptr [rcx + r10*2], ax
    inc     r10d
    add     r9, 2
    jmp     cwcc_s2

cwcc_done:
    mov     word ptr [rcx + r10*2], 0
    mov     eax, 1
    ret

cwcc_fail_zero:
    mov     word ptr [rcx], 0
cwcc_fail:
    xor     eax, eax
    ret
cf_wcopy_cat endp

; =============================================================================
; cf_free_ent_cache() - wipes and frees the 1-entry RAM cache (caller holds lock)
; =============================================================================
cf_free_ent_cache proc frame
    FRAME_PROLOG 48
    mov     rcx, qword ptr [g_cf_ent_buf]
    test    rcx, rcx
    jz      cfec_done
    mov     rdx, qword ptr [g_cf_ent_size]
    test    rdx, rdx
    jnz     @F
    mov     edx, 1
@@:
    call    mem_free
    mov     qword ptr [g_cf_ent_buf], 0
    mov     qword ptr [g_cf_ent_size], 0
    mov     dword ptr [g_cf_ent_kind], 0
    lea     rcx, [g_cf_ent_hdr]
    mov     edx, IDXE_FIXED
    call    secure_zero
cfec_done:
    FRAME_EPILOG
    ret
cf_free_ent_cache endp

; =============================================================================
; cf_match_ent_cache(rcx = idxEntFixed40Ptr, edx = kind) -> eax = 1 hit, 0 miss
; =============================================================================
cf_match_ent_cache proc
    xor     eax, eax
    cmp     qword ptr [g_cf_ent_buf], 0
    je      cmec_ret
    cmp     dword ptr [g_cf_ent_kind], edx
    jne     cmec_ret
    lea     r10, [g_cf_ent_hdr]
    mov     r11, qword ptr [rcx + IDXE_size]
    cmp     r11, qword ptr [r10 + IDXE_size]
    jne     cmec_ret
    mov     r11, qword ptr [rcx + IDXE_offset]
    cmp     r11, qword ptr [r10 + IDXE_offset]
    jne     cmec_ret
    mov     r11, qword ptr [rcx + IDXE_stored]
    cmp     r11, qword ptr [r10 + IDXE_stored]
    jne     cmec_ret
    mov     r11, qword ptr [rcx + IDXE_ordinal]
    cmp     r11, qword ptr [r10 + IDXE_ordinal]
    jne     cmec_ret
    mov     r11d, dword ptr [rcx + IDXE_flags]
    cmp     r11d, dword ptr [r10 + IDXE_flags]
    jne     cmec_ret
    mov     eax, 1
cmec_ret:
    ret
cf_match_ent_cache endp

; =============================================================================
; cf_dehydrate_one(rcx = fullPathW, edx = allowRetry) -> eax = 1 ok, 0 fail
; =============================================================================
cf_dehydrate_one proc frame
    FRAME_PROLOG 240
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13

    mov     rbx, rcx                        ; fullPathW
    mov     r13d, edx                       ; allowRetry (1 on async worker, 0 on unmount)
    xor     r12d, r12d                      ; attempt = 0

cdo_try:
    mov     qword ptr [rbp-40], 0           ; protectedHandle = 0
    mov     r10, qword ptr [pfn_CfOpenFileWithOplock]
    test    r10, r10
    jz      cdo_fail
    WINCALL r10, rbx, 0, addr rbp-40
    test    eax, eax
    js      cdo_retry_chk

    mov     r10, qword ptr [pfn_CfGetWin32Handle]
    WINCALL r10, qword ptr [rbp-40]
    mov     qword ptr [rbp-48], rax         ; win32Handle

    ; On R/W mounts, never dehydrate modified or non-in-sync files
    cmp     dword ptr [g_cf_is_rw], 0
    je      cdo_do_dehyd
    mov     r10, qword ptr [pfn_CfGetPlaceholderInfo]
    test    r10, r10
    jz      cdo_skip_dirty
    mov     dword ptr [rbp-56], 0           ; retLen
    WINCALL r10, qword ptr [rbp-48], 1, addr rbp-192, 128, addr rbp-56
    test    eax, eax
    js      cdo_skip_dirty
    cmp     dword ptr [rbp-192 + 36], 1     ; InSyncState == CF_IN_SYNC_STATE_IN_SYNC
    jne     cdo_skip_dirty
    cmp     qword ptr [rbp-192 + 16], 0     ; ModifiedDataSize == 0
    jne     cdo_skip_dirty

cdo_do_dehyd:
    mov     r10, qword ptr [pfn_CfDehydrate]
    WINCALL r10, qword ptr [rbp-48], 0, -1, CFM_DEHYD_BG, 0
    mov     dword ptr [rbp-52], eax         ; hr

    mov     r10, qword ptr [pfn_CfCloseHandle]
    WINCALL r10, qword ptr [rbp-40]

    cmp     dword ptr [rbp-52], 0
    jge     cdo_ok
    jmp     cdo_retry_chk

cdo_skip_dirty:
    mov     r10, qword ptr [pfn_CfCloseHandle]
    WINCALL r10, qword ptr [rbp-40]
    jmp     cdo_fail

cdo_retry_chk:
    test    r13d, r13d
    jz      cdo_fail
    test    r12d, r12d
    jnz     cdo_fail
    cmp     dword ptr [g_cf_unmounting], 0
    jne     cdo_fail
    inc     r12d
    WINCALL Sleep, 40
    cmp     dword ptr [g_cf_unmounting], 0
    jne     cdo_fail
    jmp     cdo_try

cdo_ok:
    mov     eax, 1
    jmp     cdo_out

cdo_fail:
    xor     eax, eax

cdo_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
cf_dehydrate_one endp

; =============================================================================
; cf_dehydrate_tp_cb(rcx = Instance, rdx = pageW) - OS threadpool callback
; =============================================================================
cf_dehydrate_tp_cb proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rbx
    mov     qword ptr [rbp-16], rdx

    xor     ebx, ebx
    mov     eax, dword ptr [g_sstk_tls]
    test    eax, eax
    jz      cdtp_run
    dec     eax
    mov     r10, gs:[rax*8 + TEB_TLS_SLOTS]
    test    r10, r10
    jnz     cdtp_run
    call    sstk_thread_init
    mov     ebx, eax

cdtp_run:
    cmp     dword ptr [g_cf_unmounting], 0
    jne     cdtp_free
    mov     rcx, qword ptr [rbp-16]
    mov     edx, 1
    call    cf_dehydrate_one

cdtp_free:
    WINCALL VirtualFree, qword ptr [rbp-16], 0, CFM_MEM_RELEASE
    lock dec dword ptr [g_cf_dehyd_inflight]

    test    ebx, ebx
    jz      cdtp_done
    call    sstk_thread_free

cdtp_done:
    mov     rbx, qword ptr [rbp-8]
    mov     rsp, rbp
    pop     rbp
    ret
cf_dehydrate_tp_cb endp

; =============================================================================
; cf_queue_dehydrate(rcx = str1W, rdx = str2W_or_0)
; Queues asynchronous placeholder dehydration on the Win32 threadpool.
; =============================================================================
cf_queue_dehydrate proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13

    cmp     dword ptr [g_cf_unmounting], 0
    jne     cqd_out

    mov     r12, rcx
    mov     r13, rdx
    WINCALL VirtualAlloc, 0, 10000h, CFM_MEM_COMMIT_RES, CFM_PAGE_RW
    test    rax, rax
    jz      cqd_out
    mov     rbx, rax

    mov     rcx, rbx
    mov     edx, MAX_PATH_CHARS
    mov     r8,  r12
    mov     r9,  r13
    call    cf_wcopy_cat
    test    eax, eax
    jz      cqd_free_page

    lock inc dword ptr [g_cf_dehyd_inflight]
    WINCALL TrySubmitThreadpoolCallback, addr cf_dehydrate_tp_cb, rbx, 0
    test    eax, eax
    jnz     cqd_out

    lock dec dword ptr [g_cf_dehyd_inflight]
cqd_free_page:
    WINCALL VirtualFree, rbx, 0, CFM_MEM_RELEASE

cqd_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
cf_queue_dehydrate endp

; =============================================================================
; cf_is_shell_prober(rcx = CallbackInfo) -> eax = 1 if Explorer/thumbnail/search
; background prober, else 0.
; Suppressing immediate CfDehydratePlaceholder on Windows Shell metadata/icon
; probes prevents ReadDirectoryChangesW FILE_ACTION_MODIFIED refresh storms in
; File Explorer; hydrated clusters are excluded from content indexing and are
; zero-wiped and deleted on unmount.
; =============================================================================
cf_is_shell_prober proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx

    test    rcx, rcx
    jz      cisp_no
    mov     rax, qword ptr [rcx + 136]      ; ProcessInfo (CF_PROCESS_INFO*)
    test    rax, rax
    jz      cisp_no
    mov     rcx, qword ptr [rax + 8]        ; ImagePath (PCWSTR)
    test    rcx, rcx
    jz      cisp_no

    mov     rbx, rcx                        ; leafPtr = ImagePath
cisp_scan:
    movzx   eax, word ptr [rcx]
    test    eax, eax
    jz      cisp_chk
    add     rcx, 2
    cmp     eax, '\'
    jne     cisp_scan
    mov     rbx, rcx                        ; character after '\'
    jmp     cisp_scan

cisp_chk:
    WINCALL CompareStringOrdinal, rbx, -1, addr w_cf_explorer_exe, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cisp_yes
    WINCALL CompareStringOrdinal, rbx, -1, addr w_cf_dllhost_exe, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cisp_yes
    WINCALL CompareStringOrdinal, rbx, -1, addr w_cf_search_exe, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cisp_yes
    WINCALL CompareStringOrdinal, rbx, -1, addr w_cf_rtbroker_exe, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cisp_yes

cisp_no:
    xor     eax, eax
    jmp     cisp_out
cisp_yes:
    mov     eax, 1
cisp_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
cf_is_shell_prober endp

; =============================================================================
; cf_cb_cancel_fetch(rcx = CallbackInfo, rdx = CallbackParameters)
; Required by CfConnectSyncRoot whenever FETCH_DATA is registered.
; =============================================================================
cf_cb_cancel_fetch proc
    ret
cf_cb_cancel_fetch endp

; =============================================================================
; cf_cb_close_completion(rcx = CallbackInfo, rdx = CallbackParameters)
; Fires asynchronously when an external reader closes its handle on a placeholder.
; =============================================================================
cf_cb_close_completion proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rbx
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx

    cmp     dword ptr [g_cf_unmounting], 0
    jne     cccc_ret
    test    rcx, rcx
    jz      cccc_ret
    test    rdx, rdx
    jz      cccc_ret

    xor     ebx, ebx
    mov     eax, dword ptr [g_sstk_tls]
    test    eax, eax
    jz      cccc_run
    dec     eax
    mov     r10, gs:[rax*8 + TEB_TLS_SLOTS]
    test    r10, r10
    jnz     cccc_run
    call    sstk_thread_init
    mov     ebx, eax

cccc_run:
    ; Signal R/W watcher when any handle closes on the sync root
    cmp     dword ptr [g_cf_is_rw], 0
    je      @F
    mov     rcx, qword ptr [g_cf_wake_evt]
    test    rcx, rcx
    jz      @F
    WINCALL SetEvent, rcx
@@:
    mov     rax, qword ptr [rbp-24]
    test    dword ptr [rax + 8], 1          ; CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED
    jnz     cccc_free_sstk

    mov     rax, qword ptr [rbp-16]
    cmp     qword ptr [rax + 32], 0         ; VolumeDosName
    je      cccc_free_sstk
    cmp     qword ptr [rax + 104], 0        ; NormalizedPath
    je      cccc_free_sstk

    mov     rcx, rax
    call    cf_is_shell_prober
    test    eax, eax
    jnz     cccc_free_sstk

    mov     rax, qword ptr [rbp-16]
    mov     rcx, qword ptr [rax + 32]       ; VolumeDosName (e.g. "C:")
    mov     rdx, qword ptr [rax + 104]      ; NormalizedPath (e.g. "\Users\...")
    call    cf_queue_dehydrate

cccc_free_sstk:
    test    ebx, ebx
    jz      cccc_ret
    call    sstk_thread_free

cccc_ret:
    mov     rbx, qword ptr [rbp-8]
    mov     rsp, rbp
    pop     rbp
    ret
cf_cb_close_completion endp

; =============================================================================
; cf_load_mrk_cache(rcx = idxEntFixed40Ptr, rdx = fileSize) -> eax = 0 ok, -1 err
; Pre-reads and GCM-authenticates an entire .mrk entry (<= 16 MiB) into RAM
; BEFORE any byte is transferred to cldflt.sys.  Caller holds cfmount_lock.
; =============================================================================
cf_load_mrk_cache proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    mov     r12, rcx                        ; idxEntFixed40Ptr
    mov     r13, rdx                        ; fileSize

    cmp     qword ptr [g_cf_esctx], 0
    je      clmc_err

    call    cf_free_ent_cache
    mov     dword ptr [g_cf_mrk_bound], 0

    mov     rcx, r13
    test    rcx, rcx
    jnz     @F
    mov     ecx, 1
@@:
    call    mem_alloc
    test    rax, rax
    jz      clmc_err
    mov     rbx, rax                        ; buf

    mov     rcx, qword ptr [g_cf_esctx]
    mov     rdx, r12
    lea     r8,  [g_cf_mrk_key]
    call    es_bind
    test    eax, eax
    jnz     clmc_free_err

    xor     r14d, r14d                      ; got = 0
clmc_loop:
    cmp     r14, r13
    jae     clmc_verify_eof

    mov     r8, r13
    sub     r8, r14
    cmp     r8, 100000h                     ; 1 MiB max per ES_Read
    jbe     @F
    mov     r8d, 100000h
@@:
    mov     dword ptr [rbp-64], 0           ; cbRead = 0
    mov     rcx, qword ptr [g_cf_esctx]
    lea     rdx, [rbx + r14]
    lea     r9,  [rbp-64]
    call    ES_Read
    test    eax, eax
    js      clmc_free_err
    mov     rcx, qword ptr [g_cf_esctx]
    call    es_code
    test    eax, eax
    jnz     clmc_free_err
    mov     eax, dword ptr [rbp-64]
    test    eax, eax
    jz      clmc_free_err
    add     r14, rax
    jmp     clmc_loop

clmc_verify_eof:
    ; Trigger erd_end -> es_drain so AES-GCM tag is verified BEFORE returning
    mov     dword ptr [rbp-64], 0
    mov     rcx, qword ptr [g_cf_esctx]
    lea     rdx, [rbp-60]
    mov     r8d, 1
    lea     r9,  [rbp-64]
    call    ES_Read
    test    eax, eax
    js      clmc_free_err
    mov     rcx, qword ptr [g_cf_esctx]
    call    es_code
    test    eax, eax
    jnz     clmc_free_err

    mov     qword ptr [g_cf_ent_buf], rbx
    mov     qword ptr [g_cf_ent_size], r13
    mov     dword ptr [g_cf_ent_kind], 1
    mov     rsi, r12
    lea     rdi, [g_cf_ent_hdr]
    mov     ecx, IDXE_FIXED
    rep     movsb
    xor     eax, eax
    jmp     clmc_out

clmc_free_err:
    mov     rcx, rbx
    mov     rdx, r13
    test    rdx, rdx
    jnz     @F
    mov     edx, 1
@@:
    call    mem_free
clmc_err:
    mov     eax, -1

clmc_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
cf_load_mrk_cache endp

; =============================================================================
; cf_load_tcvc_cache(rcx = idxEntFixed40Ptr, rdx = fileSize) -> eax = 0 ok, -1 err
; Caller holds cfmount_lock.
; =============================================================================
cf_load_tcvc_cache proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], rsi
    mov     qword ptr [rbp-48], rdi

    mov     r12, rcx
    mov     r13, rdx

    call    cf_free_ent_cache

    mov     rcx, r13
    call    mem_alloc
    test    rax, rax
    jz      cltc_err
    mov     rbx, rax

    mov     rcx, r12
    xor     edx, edx
    mov     r8,  rbx
    mov     r9,  r13
    call    tcvc_read_range
    cmp     rax, r13
    jne     cltc_free_err

    mov     qword ptr [g_cf_ent_buf], rbx
    mov     qword ptr [g_cf_ent_size], r13
    mov     dword ptr [g_cf_ent_kind], 2
    mov     rsi, r12
    lea     rdi, [g_cf_ent_hdr]
    mov     ecx, IDXE_FIXED
    rep     movsb
    xor     eax, eax
    jmp     cltc_out

cltc_free_err:
    mov     rcx, rbx
    mov     rdx, r13
    call    mem_free
cltc_err:
    mov     eax, -1

cltc_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     rsi, qword ptr [rbp-40]
    mov     rdi, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
cf_load_tcvc_cache endp

; =============================================================================
; cf_read_mrk_stream(rcx = idxEntFixed40Ptr, rdx = curOff, r8 = dstBuf,
;                    r9 = chunkLen, [rbp+48] = fileSize) -> eax = 0 ok, -1 err
; Streaming fallback for large (> 16 MiB) .mrk entries.  Caller holds lock.
; =============================================================================
cf_read_mrk_stream proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], r15

    mov     r12, rcx                        ; idxEntFixed40Ptr
    mov     r13, rdx                        ; curOff
    mov     r14, r8                         ; dstBuf
    mov     r15, r9                         ; chunkLen

    mov     rcx, qword ptr [g_cf_esctx]
    test    rcx, rcx
    jz      crms_err

    cmp     dword ptr [g_cf_mrk_bound], 0
    je      crms_rebind
    mov     rax, qword ptr [r12 + IDXE_ordinal]
    cmp     rax, qword ptr [g_cf_mrk_ord]
    jne     crms_rebind
    mov     rax, qword ptr [r12 + IDXE_offset]
    cmp     rax, qword ptr [g_cf_mrk_off]
    jne     crms_rebind
    call    es_cur_pos
    cmp     r13, rax
    jae     crms_seek_fwd

crms_rebind:
    mov     dword ptr [g_cf_mrk_bound], 0
    mov     rcx, qword ptr [g_cf_esctx]
    mov     rdx, r12
    lea     r8,  [g_cf_mrk_key]
    call    es_bind
    test    eax, eax
    jnz     crms_err
    mov     rax, qword ptr [r12 + IDXE_ordinal]
    mov     qword ptr [g_cf_mrk_ord], rax
    mov     rax, qword ptr [r12 + IDXE_offset]
    mov     qword ptr [g_cf_mrk_off], rax
    mov     dword ptr [g_cf_mrk_bound], 1

crms_seek_fwd:
    mov     rcx, qword ptr [g_cf_esctx]
    call    es_cur_pos
    cmp     rax, r13
    je      crms_read
    mov     rcx, qword ptr [g_cf_esctx]
    mov     rdx, r13
    xor     r8d, r8d                        ; STREAM_SEEK_SET
    xor     r9d, r9d
    call    ES_Seek
    test    eax, eax
    js      crms_drop_err

crms_read:
    xor     ebx, ebx                        ; got = 0
crms_loop:
    cmp     rbx, r15
    jae     crms_chk_eof
    mov     r8, r15
    sub     r8, rbx
    mov     dword ptr [rbp-56], 0           ; cbRead = 0
    mov     rcx, qword ptr [g_cf_esctx]
    lea     rdx, [r14 + rbx]
    lea     r9,  [rbp-56]
    call    ES_Read
    test    eax, eax
    js      crms_drop_err
    mov     rcx, qword ptr [g_cf_esctx]
    call    es_code
    test    eax, eax
    jnz     crms_drop_err
    mov     eax, dword ptr [rbp-56]
    test    eax, eax
    jz      crms_drop_err
    add     rbx, rax
    jmp     crms_loop

crms_chk_eof:
    mov     rax, r13
    add     rax, r15
    cmp     rax, qword ptr [rbp+48]
    jb      crms_ok

    ; At EOF: drain & verify final segment's AES-GCM tag before returning
    mov     dword ptr [rbp-56], 0
    mov     rcx, qword ptr [g_cf_esctx]
    lea     rdx, [rbp-52]
    mov     r8d, 1
    lea     r9,  [rbp-56]
    call    ES_Read
    test    eax, eax
    js      crms_drop_err
    mov     rcx, qword ptr [g_cf_esctx]
    call    es_code
    test    eax, eax
    jnz     crms_drop_err

crms_ok:
    xor     eax, eax
    jmp     crms_out

crms_drop_err:
    mov     dword ptr [g_cf_mrk_bound], 0
crms_err:
    mov     eax, -1

crms_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     r15, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
cf_read_mrk_stream endp

; =============================================================================
; cf_send_transfer(rcx = cbInfo, edx = ntStatus, r8 = bufPtr, r9 = off,
;                  [rbp+48] = len) -> eax = HRESULT
; =============================================================================
cf_send_transfer proc frame
    FRAME_PROLOG 144
    ; [rbp-64 .. -17]  = CF_OPERATION_INFO (48 bytes)
    ; [rbp-104 .. -65] = CF_OPERATION_PARAMETERS (40 bytes)
    mov     qword ptr [rbp-64], 0
    mov     dword ptr [rbp-64], 48          ; StructSize = 48
    mov     dword ptr [rbp-60], 0           ; CF_OPERATION_TYPE_TRANSFER_DATA = 0
    mov     rax, qword ptr [rcx + 8]        ; ConnectionKey
    mov     qword ptr [rbp-56], rax
    mov     rax, qword ptr [rcx + 112]      ; TransferKey
    mov     qword ptr [rbp-48], rax
    mov     qword ptr [rbp-40], 0           ; CorrelationVector
    mov     qword ptr [rbp-32], 0           ; SyncStatus
    mov     rax, qword ptr [rcx + 144]      ; RequestKey
    mov     qword ptr [rbp-24], rax

    mov     dword ptr [rbp-104], 40         ; ParamSize = 40
    mov     dword ptr [rbp-100], 0          ; pad
    mov     dword ptr [rbp-96], 0           ; TransferData.Flags = 0
    mov     dword ptr [rbp-92], edx         ; CompletionStatus (NTSTATUS)
    mov     qword ptr [rbp-88], r8          ; Buffer
    mov     qword ptr [rbp-80], r9          ; Offset
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-72], rax         ; Length

    mov     r10, qword ptr [pfn_CfExecute]
    WINCALL r10, addr rbp-64, addr rbp-104
    FRAME_EPILOG
    ret
cf_send_transfer endp

; =============================================================================
; cf_fetch_body(rcx = CallbackInfo, rdx = CallbackParameters)
; =============================================================================
cf_fetch_body proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], r15
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    test    rcx, rcx
    jz      cfb_out
    test    rdx, rdx
    jz      cfb_out

    mov     r12, rcx                        ; cbInfo
    mov     r13, rdx                        ; cbParams

    cmp     dword ptr [g_cf_unmounting], 0
    jne     cfb_fail_unavail

    cmp     dword ptr [r12 + 96], 48        ; FileIdentityLength == 48
    jne     cfb_fail_unavail
    mov     rbx, qword ptr [r12 + 88]       ; FileIdentity
    test    rbx, rbx
    jz      cfb_fail_unavail
    mov     rax, qword ptr [rbx]
    cmp     rax, qword ptr [g_cf_session_magic]
    jne     cfb_fail_unavail

    add     rbx, 8                          ; rbx -> 40-byte INDEX_ENTRY fixed header
    mov     rax, qword ptr [rbx + IDXE_size]
    mov     qword ptr [rbp-72], rax         ; fileSize

    ; Opportunistic LRU dehydration when switching to a different placeholder
    ; (skipped for Explorer/thumbnail shell probers to avoid USN refresh loops)
    mov     rcx, r12
    call    cf_is_shell_prober
    test    eax, eax
    jnz     cfb_skip_lru

    call    cfmount_lock
    mov     r8,  qword ptr [r12 + 32]       ; VolumeDosName
    mov     r9,  qword ptr [r12 + 104]      ; NormalizedPath
    test    r8,  r8
    jz      cfb_lru_done
    test    r9,  r9
    jz      cfb_lru_done
    lea     rcx, [g_cf_cur_hyd_w]
    mov     edx, MAX_PATH_CHARS
    call    cf_wcopy_cat
    test    eax, eax
    jz      cfb_lru_done
    cmp     word ptr [g_cf_last_hyd_w], 0
    je      cfb_lru_save
    WINCALL CompareStringOrdinal, addr g_cf_last_hyd_w, -1, addr g_cf_cur_hyd_w, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cfb_lru_done
    lea     rcx, [g_cf_last_hyd_w]
    xor     edx, edx
    call    cf_queue_dehydrate
cfb_lru_save:
    lea     rcx, [g_cf_last_hyd_w]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_cur_hyd_w]
    xor     r9d, r9d
    call    cf_wcopy_cat
cfb_lru_done:
    call    cfmount_unlock
cfb_skip_lru:

    ; Compute 4096-aligned [curOff, endOff) clamped to fileSize (handling CF_EOF = -1)
    mov     rcx, qword ptr [rbp-72]         ; fileSize
    mov     r14, qword ptr [r13 + 16]       ; RequiredFileOffset
    cmp     r14, rcx
    ja      cfb_fail_unavail
    mov     rax, qword ptr [r13 + 24]       ; RequiredLength
    test    rax, rax
    js      cfb_clamp_eof                   ; CF_EOF (-1) -> hydrate through fileSize
    add     rax, r14                        ; reqEnd
    jc      cfb_clamp_eof                   ; overflow -> clamp to fileSize
    cmp     rax, rcx
    jbe     @F
cfb_clamp_eof:
    mov     rax, rcx
@@:
    and     r14, -4096                      ; curOff = align_down(reqOff, 4096)
    cmp     rax, rcx
    je      cfb_end_ready
    add     rax, 4095
    and     rax, -4096                      ; align_up(endOff, 4096)
    cmp     rax, rcx
    jbe     cfb_end_ready
    mov     rax, rcx
cfb_end_ready:
    mov     r15, rax                        ; endOff

    ; Zero-length transfer edge case (e.g. 0-byte file)
    cmp     r14, r15
    jb      cfb_chunk_loop

    call    cfmount_lock
    cmp     dword ptr [g_cf_is_tcvc], 0
    jne     cfb_zero_xfer
    cmp     qword ptr [rbp-72], 0
    jne     cfb_zero_xfer
    mov     rcx, rbx
    xor     edx, edx
    call    cf_load_mrk_cache
    test    eax, eax
    js      cfb_unlock_csum_zero
cfb_zero_xfer:
    WINCALL cf_send_transfer, r12, 0, qword ptr [g_cf_xfer_buf], r14, 0
    call    cfmount_unlock
    jmp     cfb_out

cfb_unlock_csum_zero:
    call    cfmount_unlock
    jmp     cfb_fail_csum

cfb_chunk_loop:
    cmp     r14, r15
    jae     cfb_out
    cmp     dword ptr [g_cf_unmounting], 0
    jne     cfb_fail_rem_unavail

    mov     rax, r15
    sub     rax, r14
    cmp     rax, CFM_CHUNK_BYTES
    jbe     @F
    mov     eax, CFM_CHUNK_BYTES
@@:
    mov     qword ptr [rbp-80], rax         ; chunkLen

    call    cfmount_lock
    cmp     dword ptr [g_cf_unmounting], 0
    jne     cfb_unlock_unavail
    cmp     qword ptr [g_cf_xfer_buf], 0
    je      cfb_unlock_unavail

    cmp     dword ptr [g_cf_is_tcvc], 0
    jne     cfb_do_tcvc

    ; ---- Native .mrk entry ----
    mov     rdx, qword ptr [rbp-72]         ; fileSize
    cmp     rdx, CFM_MRK_CACHE_MAX
    ja      cfb_mrk_large

    mov     rcx, rbx
    mov     edx, 1
    call    cf_match_ent_cache
    test    eax, eax
    jnz     cfb_copy_cached

    mov     rcx, rbx
    mov     rdx, qword ptr [rbp-72]
    call    cf_load_mrk_cache
    test    eax, eax
    js      cfb_unlock_csum
    jmp     cfb_copy_cached

cfb_mrk_large:
    WINCALL cf_read_mrk_stream, rbx, r14, qword ptr [g_cf_xfer_buf], \
            qword ptr [rbp-80], qword ptr [rbp-72]
    test    eax, eax
    js      cfb_unlock_csum
    jmp     cfb_xfer_chunk

    ; ---- TrueCrypt / VeraCrypt entry ----
cfb_do_tcvc:
    mov     rdx, qword ptr [rbp-72]         ; fileSize
    cmp     rdx, CFM_TC_CACHE_MAX
    ja      cfb_tcvc_large

    mov     rcx, rbx
    mov     edx, 2
    call    cf_match_ent_cache
    test    eax, eax
    jnz     cfb_copy_cached

    mov     rcx, rbx
    mov     rdx, qword ptr [rbp-72]
    call    cf_load_tcvc_cache
    test    eax, eax
    js      cfb_unlock_csum

cfb_copy_cached:
    mov     rsi, qword ptr [g_cf_ent_buf]
    add     rsi, r14
    mov     rdi, qword ptr [g_cf_xfer_buf]
    mov     rcx, qword ptr [rbp-80]
    rep     movsb
    jmp     cfb_xfer_chunk

cfb_tcvc_large:
    mov     rcx, rbx
    mov     rdx, r14
    mov     r8,  qword ptr [g_cf_xfer_buf]
    mov     r9,  qword ptr [rbp-80]
    call    tcvc_read_range
    cmp     rax, qword ptr [rbp-80]
    jne     cfb_unlock_csum

cfb_xfer_chunk:
    WINCALL cf_send_transfer, r12, 0, qword ptr [g_cf_xfer_buf], r14, qword ptr [rbp-80]
    mov     dword ptr [rbp-88], eax         ; hr
    mov     rcx, qword ptr [g_cf_xfer_buf]
    mov     rdx, qword ptr [rbp-80]
    call    secure_zero
    call    cfmount_unlock

    cmp     dword ptr [rbp-88], 0
    jl      cfb_out                         ; cancelled / aborted by kernel

    add     r14, qword ptr [rbp-80]
    jmp     cfb_chunk_loop

cfb_unlock_csum:
    call    cfmount_unlock
cfb_fail_csum:
    mov     rax, r15
    sub     rax, r14
    jbe     cfb_fail_csum_raw
    WINCALL cf_send_transfer, r12, CFM_STATUS_CHECKSUM_ERR, 0, r14, rax
    jmp     cfb_out
cfb_fail_csum_raw:
    WINCALL cf_send_transfer, r12, CFM_STATUS_CHECKSUM_ERR, 0, \
            qword ptr [r13 + 16], qword ptr [r13 + 24]
    jmp     cfb_out

cfb_unlock_unavail:
    call    cfmount_unlock
cfb_fail_rem_unavail:
    mov     rax, r15
    sub     rax, r14
    jbe     cfb_fail_unavail
    WINCALL cf_send_transfer, r12, CFM_STATUS_UNSUCCESSFUL, 0, r14, rax
    jmp     cfb_out

cfb_fail_unavail:
    WINCALL cf_send_transfer, r12, CFM_STATUS_UNSUCCESSFUL, 0, \
            qword ptr [r13 + 16], qword ptr [r13 + 24]

cfb_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     r15, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
cf_fetch_body endp

; =============================================================================
; cf_cb_fetch_data(rcx = CallbackInfo, rdx = CallbackParameters)
; Raw OS threadpool entry wrapper ensuring per-thread software shadow stack.
; =============================================================================
cf_cb_fetch_data proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rbx
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx

    xor     ebx, ebx
    mov     eax, dword ptr [g_sstk_tls]
    test    eax, eax
    jz      ccfd_run
    dec     eax
    mov     r10, gs:[rax*8 + TEB_TLS_SLOTS]
    test    r10, r10
    jnz     ccfd_run
    call    sstk_thread_init
    mov     ebx, eax

ccfd_run:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    call    cf_fetch_body

    test    ebx, ebx
    jz      ccfd_done
    call    sstk_thread_free

ccfd_done:
    mov     rbx, qword ptr [rbp-8]
    mov     rsp, rbp
    pop     rbp
    ret
cf_cb_fetch_data endp

; =============================================================================
; cf_wipe_file(rcx = filePathW, rdx = zeroBuf64K)
; If GetCompressedFileSizeW reports non-zero allocated disk bytes on a
; hydrated file, overwrites them with zeros before deletion.
; =============================================================================
cf_wipe_file proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13

    mov     rbx, rcx                        ; filePathW
    mov     r12, rdx                        ; zeroBuf64K

    mov     dword ptr [rbp-40], 0           ; hiSize = 0
    WINCALL GetCompressedFileSizeW, rbx, addr rbp-40
    cmp     eax, 0FFFFFFFFh
    jne     cwf_have_sz
    cmp     dword ptr [rbp-40], 0
    je      cwf_done
cwf_have_sz:
    mov     edx, dword ptr [rbp-40]
    shl     rdx, 32
    mov     eax, eax
    or      rax, rdx                        ; allocBytes
    test    rax, rax
    jz      cwf_done
    cmp     rax, CFM_WIPE_CAP_BYTES
    jbe     @F
    mov     rax, CFM_WIPE_CAP_BYTES
@@:
    mov     r13, rax                        ; bytesToWipe

    WINCALL CreateFileW, rbx, CFM_GENERIC_WRITE, 3, 0, CFM_OPEN_EXISTING, 0, 0
    cmp     rax, -1
    je      cwf_done
    mov     qword ptr [rbp-48], rax         ; hFile

cwf_loop:
    test    r13, r13
    jz      cwf_close
    mov     r8, r13
    cmp     r8, CFM_WIPE_BUF_BYTES
    jbe     @F
    mov     r8d, CFM_WIPE_BUF_BYTES
@@:
    mov     dword ptr [rbp-52], 0
    WINCALL WriteFile, qword ptr [rbp-48], r12, r8d, addr rbp-52, 0
    test    eax, eax
    jz      cwf_close
    mov     eax, dword ptr [rbp-52]
    test    eax, eax
    jz      cwf_close
    sub     r13, rax
    jmp     cwf_loop

cwf_close:
    WINCALL CloseHandle, qword ptr [rbp-48]

cwf_done:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
cf_wipe_file endp

; =============================================================================
; cf_rm_tree_rec(rcx = dirPathW, edx = depth, r8 = zeroBuf64K)
; Bounded-depth directory remover that strips READONLY, refuses to follow
; name-surrogate junctions/symlinks, zero-wipes any hydrated clusters, and
; removes the directory.
; =============================================================================
cf_rm_tree_rec proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], r15

    cmp     edx, CFM_MAX_DEPTH
    jae     crtr_out

    mov     r12, rcx                        ; dirPathW
    mov     r13d, edx                       ; depth
    mov     r14, r8                         ; zeroBuf64K

    ; Scratch block: [0..599] = WIN32_FIND_DATAW, [608..66143] = childPathW
    WINCALL VirtualAlloc, 0, CFM_TREE_ALLOC_BYTES, CFM_MEM_COMMIT_RES, CFM_PAGE_RW
    test    rax, rax
    jz      crtr_rmdir
    mov     rbx, rax

    lea     rcx, [rbx + 608]
    mov     edx, MAX_PATH_CHARS
    mov     r8,  r12
    lea     r9,  [w_cf_star]
    call    cf_wcopy_cat
    test    eax, eax
    jz      crtr_free

    WINCALL FindFirstFileW, addr rbx+608, rbx
    cmp     rax, -1
    je      crtr_free
    mov     r15, rax                        ; hFind

crtr_next:
    ; cFileName sits at offset 44 in WIN32_FIND_DATAW
    cmp     word ptr [rbx + 44], '.'
    jne     crtr_build_child
    cmp     word ptr [rbx + 46], 0
    je      crtr_step
    cmp     word ptr [rbx + 46], '.'
    jne     crtr_build_child
    cmp     word ptr [rbx + 48], 0
    je      crtr_step

crtr_build_child:
    ; childPathW = dirPathW + "\" + cFileName
    lea     rcx, [rbx + 608]
    mov     edx, MAX_PATH_CHARS
    mov     r8,  r12
    lea     r9,  [w_cf_star]                ; "\*" -> replace trailing '*' below
    call    cf_wcopy_cat
    test    eax, eax
    jz      crtr_step

    ; Overwrite trailing '*' with cFileName
    lea     rcx, [rbx + 608]
    xor     eax, eax
@@:
    cmp     word ptr [rcx + rax*2], 0
    je      @F
    inc     eax
    jmp     @B
@@:
    dec     eax                             ; index of '*'
    lea     rcx, [rcx + rax*2]
    mov     edx, MAX_PATH_CHARS
    sub     edx, eax
    lea     r8,  [rbx + 44]
    xor     r9d, r9d
    call    cf_wcopy_cat
    test    eax, eax
    jz      crtr_step

    WINCALL SetFileAttributesW, addr rbx+608, CFM_ATTR_NORMAL

    mov     eax, dword ptr [rbx]            ; dwFileAttributes
    test    eax, CFM_ATTR_DIR
    jz      crtr_file

    ; Directory: do NOT recurse into name-surrogate reparse points (junction/symlink)
    test    eax, CFM_ATTR_REPARSE
    jz      crtr_recurse
    test    dword ptr [rbx + 36], CFM_REPARSE_SURR ; dwReserved0
    jnz     crtr_rmdir_child

crtr_recurse:
    lea     rcx, [rbx + 608]
    lea     edx, [r13d + 1]
    mov     r8,  r14
    call    cf_rm_tree_rec
    jmp     crtr_step

crtr_rmdir_child:
    WINCALL RemoveDirectoryW, addr rbx+608
    jmp     crtr_step

crtr_file:
    test    r14, r14
    jz      crtr_delfile
    lea     rcx, [rbx + 608]
    mov     rdx, r14
    call    cf_wipe_file
crtr_delfile:
    WINCALL DeleteFileW, addr rbx+608

crtr_step:
    WINCALL FindNextFileW, r15, rbx
    test    eax, eax
    jnz     crtr_next

    WINCALL FindClose, r15

crtr_free:
    WINCALL VirtualFree, rbx, 0, CFM_MEM_RELEASE

crtr_rmdir:
    WINCALL SetFileAttributesW, r12, CFM_ATTR_NORMAL
    WINCALL RemoveDirectoryW, r12

crtr_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     r15, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
cf_rm_tree_rec endp

; =============================================================================
; cf_wipe_and_rm_tree(rcx = dirPathW)
; =============================================================================
cf_wipe_and_rm_tree proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12

    mov     r12, rcx
    WINCALL VirtualAlloc, 0, CFM_WIPE_BUF_BYTES, CFM_MEM_COMMIT_RES, CFM_PAGE_RW
    mov     rbx, rax                        ; zeroBuf64K (0 if OOM: delete still runs)

    mov     rcx, r12
    xor     edx, edx
    mov     r8,  rbx
    call    cf_rm_tree_rec

    test    rbx, rbx
    jz      cwrt_out
    WINCALL VirtualFree, rbx, 0, CFM_MEM_RELEASE

cwrt_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
cf_wipe_and_rm_tree endp

; =============================================================================
; cf_get_mounts_base(ecx = createDirs) -> eax = 1 ok (g_cf_base_w filled), 0 fail
; Resolves "%LOCALAPPDATA%\Myrkr\Mounts" (or "%TEMP%\Myrkr\Mounts" fallback).
; =============================================================================
cf_get_mounts_base proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     ebx, ecx

    WINCALL GetEnvironmentVariableW, addr w_cf_localapp, addr g_cf_base_w, <MAX_PATH_CHARS - 64>
    test    eax, eax
    jz      cgmb_temp
    cmp     eax, MAX_PATH_CHARS - 64
    jb      cgmb_strip_slash

cgmb_temp:
    WINCALL GetTempPathW, <MAX_PATH_CHARS - 64>, addr g_cf_base_w
    test    eax, eax
    jz      cgmb_fail
    cmp     eax, MAX_PATH_CHARS - 64
    jae     cgmb_fail

cgmb_strip_slash:
    lea     rcx, [g_cf_base_w]
    cmp     word ptr [rcx + rax*2 - 2], '\'
    jne     @F
    dec     eax
    mov     word ptr [rcx + rax*2], 0
@@:
    lea     rcx, [g_cf_path_w]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_base_w]
    lea     r9,  [w_cf_sub_myrkr]
    call    cf_wcopy_cat
    test    eax, eax
    jz      cgmb_fail

    test    ebx, ebx
    jz      @F
    WINCALL CreateDirectoryW, addr g_cf_path_w, 0
@@:
    lea     rcx, [g_cf_base_w]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_path_w]
    lea     r9,  [w_cf_sub_mounts]
    call    cf_wcopy_cat
    test    eax, eax
    jz      cgmb_fail

    test    ebx, ebx
    jz      cgmb_chk_unenc
    WINCALL CreateDirectoryW, addr g_cf_base_w, 0
cgmb_chk_unenc:
    WINCALL GetFileAttributesW, addr g_cf_base_w
    cmp     eax, CFM_INV_ATTR
    je      cgmb_ok
    mov     dword ptr [rbp-24], eax
    test    eax, CFM_ATTR_ENCRYPTED
    jz      @F
    WINCALL DecryptFileW, addr g_cf_base_w, 0
    and     dword ptr [rbp-24], not CFM_ATTR_ENCRYPTED
@@:
    test    ebx, ebx
    jz      cgmb_ok
    mov     eax, dword ptr [rbp-24]
    test    eax, CFM_ATTR_NOT_INDEXED
    jnz     cgmb_ok
    or      eax, CFM_ATTR_NOT_INDEXED
    WINCALL SetFileAttributesW, addr g_cf_base_w, eax

cgmb_ok:
    mov     eax, 1
    jmp     cgmb_out

cgmb_fail:
    xor     eax, eax

cgmb_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
cf_get_mounts_base endp

; =============================================================================
; cfmount_sweep_stale()
; Cleans up orphaned sync-root directories under %LOCALAPPDATA%\Myrkr\Mounts
; whose exclusive .lock file is no longer held by a live Myrkr process.
; =============================================================================
public cfmount_sweep_stale
cfmount_sweep_stale proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13

    call    cf_init_procs                   ; best-effort: unregister if cldapi present

    xor     ecx, ecx                        ; do not create if absent
    call    cf_get_mounts_base
    test    eax, eax
    jz      css_out

    WINCALL GetFileAttributesW, addr g_cf_base_w
    cmp     eax, CFM_INV_ATTR
    je      css_out

    WINCALL VirtualAlloc, 0, CFM_TREE_ALLOC_BYTES, CFM_MEM_COMMIT_RES, CFM_PAGE_RW
    test    rax, rax
    jz      css_out
    mov     rbx, rax                        ; [0..599]=WFD, [608..]=itemPathW

    lea     rcx, [rbx + 608]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_base_w]
    lea     r9,  [w_cf_star]
    call    cf_wcopy_cat
    test    eax, eax
    jz      css_free

    WINCALL FindFirstFileW, addr rbx+608, rbx
    cmp     rax, -1
    je      css_drv_sweep
    mov     r12, rax                        ; hFind

css_loop:
    test    dword ptr [rbx], CFM_ATTR_DIR
    jz      css_next
    cmp     word ptr [rbx + 44], '.'
    je      css_next

    ; Build itemPathW = g_cf_base_w + "\" + cFileName
    lea     rcx, [rbx + 608]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_base_w]
    lea     r9,  [w_cf_star]
    call    cf_wcopy_cat
    test    eax, eax
    jz      css_next

    lea     rcx, [rbx + 608]
    xor     eax, eax
@@:
    cmp     word ptr [rcx + rax*2], 0
    je      @F
    inc     eax
    jmp     @B
@@:
    dec     eax
    lea     rcx, [rcx + rax*2]
    mov     edx, MAX_PATH_CHARS
    sub     edx, eax
    lea     r8,  [rbx + 44]
    xor     r9d, r9d
    call    cf_wcopy_cat
    test    eax, eax
    jz      css_next

    ; Check lockfile "<itemPathW>.lock": if present & exclusively held, skip!
    lea     rcx, [g_cf_lock_w]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [rbx + 608]
    lea     r9,  [w_cf_lock_ext]
    call    cf_wcopy_cat
    test    eax, eax
    jz      css_next

    WINCALL GetFileAttributesW, addr g_cf_lock_w
    cmp     eax, CFM_INV_ATTR
    je      css_reap                        ; lockfile absent -> dead session

    WINCALL CreateFileW, addr g_cf_lock_w, CFM_GENERIC_RW, 0, 0, CFM_OPEN_EXISTING, 0, 0
    cmp     rax, -1
    je      css_next                        ; sharing violation -> live Myrkr owns it!
    WINCALL CloseHandle, rax
    WINCALL DeleteFileW, addr g_cf_lock_w

css_reap:
    mov     r10, qword ptr [pfn_CfUnregisterSyncRoot]
    test    r10, r10
    jz      @F
    WINCALL r10, addr rbx+608
@@:
    lea     rcx, [rbx + 608]
    call    cf_wipe_and_rm_tree

css_next:
    WINCALL FindNextFileW, r12, rbx
    test    eax, eax
    jnz     css_loop

    WINCALL FindClose, r12

css_drv_sweep:
    ; Also unmap any orphaned session drive letter (D:..Z:) pointing to a
    ; dead %LOCALAPPDATA%\Myrkr\Mounts\<id> directory that no longer exists.
    lea     rcx, [g_cf_base_w]
    xor     r13d, r13d
@@:
    cmp     word ptr [rcx + r13*2], 0
    je      @F
    inc     r13d
    jmp     @B
@@:
    test    r13d, r13d
    jz      css_free

    mov     r12d, 'D'
css_drv_lp:
    mov     word ptr [rbx + 0], r12w
    mov     word ptr [rbx + 2], ':'
    mov     word ptr [rbx + 4], 0
    mov     word ptr [rbx + 8], r12w
    mov     word ptr [rbx + 10], ':'
    mov     word ptr [rbx + 12], '\'
    mov     word ptr [rbx + 14], 0

    WINCALL QueryDosDeviceW, rbx, addr rbx+608, MAX_PATH_CHARS
    test    eax, eax
    jz      css_drv_next

    cmp     word ptr [rbx + 608], '\'
    jne     css_drv_next
    cmp     word ptr [rbx + 610], '?'
    jne     css_drv_next
    cmp     word ptr [rbx + 612], '?'
    jne     css_drv_next
    cmp     word ptr [rbx + 614], '\'
    jne     css_drv_next

    WINCALL CompareStringOrdinal, addr rbx+616, r13d, addr g_cf_base_w, r13d, 1
    cmp     eax, CFM_CSTR_EQUAL
    jne     css_drv_next
    cmp     word ptr [rbx + 616 + r13*2], '\'
    jne     css_drv_next

    WINCALL GetFileAttributesW, addr rbx+616
    cmp     eax, CFM_INV_ATTR
    jne     css_drv_next                    ; directory still alive -> leave mounted

    WINCALL DefineDosDeviceW, <CFM_DDD_REMOVE or CFM_DDD_EXACT_MATCH>, rbx, addr rbx+616
    WINCALL SHChangeNotify, CFM_SHCNE_DRIVEREMOVED, CFM_SHCNF_PATHW, addr rbx+8, 0

css_drv_next:
    inc     r12d
    cmp     r12d, 'Z'
    jbe     css_drv_lp

css_free:
    WINCALL VirtualFree, rbx, 0, CFM_MEM_RELEASE

css_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
cfmount_sweep_stale endp

; =============================================================================
; cf_populate_placeholders() -> eax = 1 ok, 0 fail
; Walks g_idxptr (g_idxcount entries), validates each entry path with
; sanitize_name, creates directories, and populates read-only placeholders.
; =============================================================================
cf_populate_placeholders proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    WINCALL GetSystemTimeAsFileTime, addr g_cf_mount_ft
    mov     word ptr [g_cf_last_dir_w], 0

    xor     r12d, r12d                      ; byte cursor in g_idxptr
    mov     r13, qword ptr [g_idxcount]     ; entries remaining

cpp_loop:
    test    r13, r13
    jz      cpp_ok

    mov     rax, r12
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      cpp_fail

    mov     rbx, qword ptr [g_idxptr]
    add     rbx, r12                        ; rbx -> INDEX_ENTRY
    mov     ecx, dword ptr [rbx + IDXE_namelen]
    add     rax, rcx
    cmp     rax, qword ptr [g_idxlen]
    ja      cpp_fail
    mov     r14, rax                        ; next cursor

    test    dword ptr [rbx + IDXE_flags], IDXEF_DROPPED
    jnz     cpp_next

    ; Copy UTF-8 name, strip trailing slash, reject embedded NULs, sanitize
    test    ecx, ecx
    jz      cpp_next
    cmp     ecx, ENTRY_NAME_MAX
    ja      cpp_next

    lea     rsi, [rbx + IDXE_name]
    lea     rdi, [g_cf_u8name]
    mov     r8, rdi                         ; RIP-relative base for indexed access
    mov     edx, ecx                        ; save namelen
    rep     movsb
    mov     ecx, edx

cpp_trim_sep:
    test    ecx, ecx
    jz      cpp_next
    movzx   eax, byte ptr [r8 + rcx - 1]
    cmp     eax, '/'
    je      cpp_do_trim
    cmp     eax, '\'
    jne     cpp_trimmed
cpp_do_trim:
    dec     ecx
    jmp     cpp_trim_sep

cpp_trimmed:
    cmp     ecx, 1
    jne     @F
    cmp     byte ptr [r8], '.'
    je      cpp_next
@@:
    mov     byte ptr [r8 + rcx], 0

    ; Reject embedded NUL bytes prior to trailing NUL
    xor     eax, eax
cpp_nul_chk:
    cmp     eax, ecx
    jae     cpp_nul_ok
    cmp     byte ptr [r8 + rax], 0
    je      cpp_next
    inc     eax
    jmp     cpp_nul_chk

cpp_nul_ok:
    mov     dword ptr [rbp-64], ecx         ; trimmed u8 len
    lea     rcx, [g_cf_u8name]
    call    sanitize_name
    test    eax, eax
    jnz     cpp_next

    WINCALL MultiByteToWideChar, CFM_CP_UTF8, CFM_MB_ERR_INV, addr g_cf_u8name, \
            dword ptr [rbp-64], addr g_cf_rel_w, 4100
    test    eax, eax
    jle     cpp_next

    ; Prepend leading '\' in g_cf_path_w build: convert '/' -> '\' in g_cf_rel_w
    lea     rcx, [g_cf_rel_w]
    mov     word ptr [rcx + rax*2], 0
    xor     edx, edx
cpp_slash_lp:
    cmp     edx, eax
    jae     cpp_rel_ready
    cmp     word ptr [rcx + rdx*2], '/'
    jne     @F
    mov     word ptr [rcx + rdx*2], '\'
@@:
    inc     edx
    jmp     cpp_slash_lp

cpp_rel_ready:
    ; g_cf_path_w = g_cf_root_w + "\" + g_cf_rel_w
    lea     rcx, [g_cf_path_w]
    mov     edx, MAX_PATH_CHARS - 16
    lea     r8,  [g_cf_root_w]
    lea     r9,  [w_cf_star]                ; "\*" -> overwrite '*' with g_cf_rel_w
    call    cf_wcopy_cat
    test    eax, eax
    jz      cpp_next

    lea     rcx, [g_cf_path_w]
    xor     eax, eax
@@:
    cmp     word ptr [rcx + rax*2], 0
    je      @F
    inc     eax
    jmp     @B
@@:
    dec     eax
    lea     rcx, [rcx + rax*2]
    mov     edx, MAX_PATH_CHARS - 16
    sub     edx, eax
    lea     r8,  [g_cf_rel_w]
    xor     r9d, r9d
    call    cf_wcopy_cat
    test    eax, eax
    jz      cpp_next

    test    dword ptr [rbx + IDXE_flags], IDXEF_DIR
    jz      cpp_file
    lea     rcx, [g_cf_path_w]
    call    create_parents
    WINCALL CreateDirectoryW, addr g_cf_path_w, 0
    lea     rcx, [g_cf_last_dir_w]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_path_w]
    xor     r9d, r9d
    call    cf_wcopy_cat
    jmp     cpp_next

cpp_file:
    ; Split g_cf_path_w at its final '\' into parentDirW and leafNameW
    lea     rcx, [g_cf_path_w]
    xor     edx, edx                        ; scan index
    xor     r8d, r8d                        ; lastSlashIdx
cpp_find_sep:
    movzx   eax, word ptr [rcx + rdx*2]
    test    eax, eax
    jz      cpp_split
    cmp     eax, '\'
    jne     @F
    mov     r8d, edx
@@:
    inc     edx
    jmp     cpp_find_sep

cpp_split:
    test    r8d, r8d
    jz      cpp_next
    lea     rsi, [rcx + r8*2]               ; ptr to final '\'
    mov     word ptr [rsi], 0               ; split parentDirW
    lea     rdi, [rsi + 2]                  ; leafNameW
    mov     qword ptr [rbp-64], rsi         ; save slash ptr
    mov     qword ptr [rbp-72], rdi         ; save leafNameW

    ; Avoid redundant parent CreateDirectoryW syscalls across sibling files
    cmp     word ptr [g_cf_last_dir_w], 0
    je      cpp_mk_parent
    WINCALL CompareStringOrdinal, addr g_cf_path_w, -1, addr g_cf_last_dir_w, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cpp_parent_ok
cpp_mk_parent:
    mov     rsi, qword ptr [rbp-64]
    mov     word ptr [rsi], '\'
    lea     rcx, [g_cf_path_w]
    call    create_parents
    mov     rsi, qword ptr [rbp-64]
    mov     word ptr [rsi], 0
    lea     rcx, [g_cf_last_dir_w]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_path_w]
    xor     r9d, r9d
    call    cf_wcopy_cat
cpp_parent_ok:

    ; 48-byte FileIdentity = [8B session magic] + [40B INDEX_ENTRY header]
    mov     rax, qword ptr [g_cf_session_magic]
    mov     qword ptr [g_cf_id_buf], rax
    mov     rsi, rbx
    lea     rdi, [g_cf_id_buf + 8]
    mov     ecx, IDXE_FIXED
    rep     movsb

    ; Zero and populate CF_PLACEHOLDER_CREATE_INFO (88 bytes)
    lea     rcx, [g_cf_pci]
    mov     edx, 88
    call    secure_zero

    mov     rax, qword ptr [rbp-72]         ; RelativeFileName (leaf)
    mov     qword ptr [g_cf_pci + 0], rax
    mov     rax, qword ptr [g_cf_mount_ft]
    mov     qword ptr [g_cf_pci + 8], rax   ; CreationTime
    mov     qword ptr [g_cf_pci + 16], rax  ; LastAccessTime
    mov     qword ptr [g_cf_pci + 24], rax  ; LastWriteTime
    mov     qword ptr [g_cf_pci + 32], rax  ; ChangeTime
    mov     eax, CFM_ATTR_READONLY
    cmp     dword ptr [g_cf_is_rw], 0
    je      @F
    mov     eax, CFM_ATTR_NORMAL
@@:
    mov     dword ptr [g_cf_pci + 40], eax
    mov     rax, qword ptr [rbx + IDXE_size]
    mov     qword ptr [g_cf_pci + 48], rax  ; FileSize
    lea     rax, [g_cf_id_buf]
    mov     qword ptr [g_cf_pci + 56], rax  ; FileIdentity
    mov     dword ptr [g_cf_pci + 64], 48   ; FileIdentityLength
    mov     dword ptr [g_cf_pci + 68], CFM_PCI_MARK_INSYNC

    mov     dword ptr [rbp-80], 0           ; entriesProcessed (disjoint from [rbp-64])
    mov     r10, qword ptr [pfn_CfCreatePlaceholders]
    WINCALL r10, addr g_cf_path_w, addr g_cf_pci, 1, 0, addr rbp-80

    mov     rsi, qword ptr [rbp-64]
    mov     word ptr [rsi], '\'

cpp_next:
    mov     r12, r14
    dec     r13
    jmp     cpp_loop

cpp_ok:
    mov     eax, 1
    jmp     cpp_out

cpp_fail:
    xor     eax, eax

cpp_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
cf_populate_placeholders endp

; =============================================================================
; cf_wjoin_bs(rcx = dstW, edx = capChars, r8 = dirW, r9 = leafW)
;   -> eax = char length written (excluding NUL), or 0 on overflow/invalid
;   If dirW is empty (dirW[0] == 0), copies leafW directly; else dirW + "\" + leafW.
; =============================================================================
cf_wjoin_bs proc
    test    rcx, rcx
    jz      cwjb_fail
    cmp     edx, 2
    jb      cwjb_fail
    test    r8, r8
    jz      cwjb_fail
    test    r9, r9
    jz      cwjb_fail

    dec     edx                             ; max chars before NUL
    xor     r10d, r10d                      ; write pos

    cmp     word ptr [r8], 0
    je      cwjb_leaf

cwjb_dir:
    mov     ax, word ptr [r8]
    test    ax, ax
    jz      cwjb_sep
    cmp     r10d, edx
    jae     cwjb_zero
    mov     word ptr [rcx + r10*2], ax
    inc     r10d
    add     r8, 2
    jmp     cwjb_dir

cwjb_sep:
    cmp     r10d, edx
    jae     cwjb_zero
    mov     word ptr [rcx + r10*2], '\'
    inc     r10d

cwjb_leaf:
    mov     ax, word ptr [r9]
    test    ax, ax
    jz      cwjb_done
    cmp     r10d, edx
    jae     cwjb_zero
    mov     word ptr [rcx + r10*2], ax
    inc     r10d
    add     r9, 2
    jmp     cwjb_leaf

cwjb_done:
    mov     word ptr [rcx + r10*2], 0
    mov     eax, r10d
    ret

cwjb_zero:
    mov     word ptr [rcx], 0
cwjb_fail:
    xor     eax, eax
    ret
cf_wjoin_bs endp

; =============================================================================
; cf_write_all(rcx = hFile, rdx = bufPtr, r8 = byteLen) -> eax = 0 ok, -1 err
; =============================================================================
cf_write_all proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13

    mov     rbx, rcx                        ; hFile
    mov     r12, rdx                        ; bufPtr
    mov     r13, r8                         ; remLen

cwa_lp:
    test    r13, r13
    jz      cwa_ok
    mov     rax, r13
    cmp     rax, 100000h                    ; 1 MiB chunk max per WriteFile
    jbe     @F
    mov     eax, 100000h
@@:
    mov     dword ptr [rbp-48], eax         ; chunkDword
    mov     dword ptr [rbp-40], 0           ; writtenDword
    WINCALL WriteFile, rbx, r12, dword ptr [rbp-48], addr rbp-40, 0
    test    eax, eax
    jz      cwa_err
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-48]
    jne     cwa_err
    add     r12, rax
    sub     r13, rax
    jmp     cwa_lp

cwa_ok:
    xor     eax, eax
    jmp     cwa_out
cwa_err:
    mov     eax, -1
cwa_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
cf_write_all endp

; =============================================================================
; cf_arena_init(rcx = arena32Ptr, rdx = capBytes) -> eax = 1 ok, 0 fail
;   +0 base, +8 len, +16 commit, +24 cap
; =============================================================================
cf_arena_init proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12

    mov     rbx, rcx
    mov     r12, rdx
    mov     qword ptr [rbx + 0], 0
    mov     qword ptr [rbx + 8], 0
    mov     qword ptr [rbx + 16], 0
    mov     qword ptr [rbx + 24], 0

    WINCALL VirtualAlloc, 0, r12, CFM_MEM_RESERVE, CFM_PAGE_RW
    test    rax, rax
    jz      cai_fail
    mov     qword ptr [rbx + 0], rax
    mov     qword ptr [rbx + 24], r12
    mov     eax, 1
    jmp     cai_out

cai_fail:
    xor     eax, eax
cai_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
cf_arena_init endp

; =============================================================================
; cf_arena_alloc(rcx = arena32Ptr, rdx = addBytes) -> rax = writePtr or 0
; =============================================================================
cf_arena_alloc proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14

    mov     rbx, rcx
    mov     r12, qword ptr [rbx + 8]        ; oldLen
    mov     r13, r12
    add     r13, rdx                        ; newLen
    jc      caa_fail
    cmp     r13, qword ptr [rbx + 24]       ; cap
    ja      caa_fail

    cmp     r13, qword ptr [rbx + 16]       ; commit
    jbe     caa_have

    ; Commit in 1 MiB increments up to cap
    mov     r14, r13
    add     r14, 0FFFFFh
    and     r14, NOT 0FFFFFh
    cmp     r14, qword ptr [rbx + 24]
    jbe     @F
    mov     r14, qword ptr [rbx + 24]
@@:
    WINCALL VirtualAlloc, qword ptr [rbx + 0], r14, CFM_MEM_COMMIT, CFM_PAGE_RW
    test    rax, rax
    jz      caa_fail
    mov     qword ptr [rbx + 16], r14

caa_have:
    mov     rax, qword ptr [rbx + 0]
    add     rax, r12
    mov     qword ptr [rbx + 8], r13
    jmp     caa_out

caa_fail:
    xor     eax, eax
caa_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
cf_arena_alloc endp

; =============================================================================
; cf_arena_free(rcx = arena32Ptr)
; =============================================================================
cf_arena_free proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rcx

    mov     rcx, qword ptr [rbx + 0]
    test    rcx, rcx
    jz      caf_zero
    mov     rdx, qword ptr [rbx + 16]
    test    rdx, rdx
    jz      @F
    call    secure_zero
@@:
    WINCALL VirtualFree, qword ptr [rbx + 0], 0, CFM_MEM_RELEASE

caf_zero:
    mov     qword ptr [rbx + 0], 0
    mov     qword ptr [rbx + 8], 0
    mov     qword ptr [rbx + 16], 0
    mov     qword ptr [rbx + 24], 0
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
cf_arena_free endp

; =============================================================================
; cf_fnv_mix(rcx = h64, rdx = bufPtr, r8 = byteLen) -> rax = newH64
; =============================================================================
cf_fnv_mix proc
    mov     rax, rcx
    mov     r10, 100000001B3h
cfm_lp:
    test    r8, r8
    jz      cfm_done
    movzx   r9d, byte ptr [rdx]
    xor     rax, r9
    imul    rax, r10
    inc     rdx
    dec     r8
    jmp     cfm_lp
cfm_done:
    ret
cf_fnv_mix endp

; =============================================================================
; cf_split_ustar(rcx = u8Path, rdx = u8Len, r8 = outName104, r9 = outPrefix160)
;   -> eax = 0 ok, 1 invalid (thread-safe mirror of pack.asm split_name)
; =============================================================================
cf_split_ustar proc
    cmp     rdx, ENTRY_NAME_MAX + 1
    ja      csu_invalid
    cmp     rdx, 100
    ja      csu_split
    xor     r10, r10
csu_c1:
    cmp     r10, rdx
    jae     csu_c1d
    mov     al, byte ptr [rcx + r10]
    mov     byte ptr [r8 + r10], al
    inc     r10
    jmp     csu_c1
csu_c1d:
    mov     byte ptr [r8 + r10], 0
    mov     byte ptr [r9], 0
    xor     eax, eax
    ret

csu_split:
    mov     r10, rdx
    sub     r10, 101
csu_scan:
    cmp     r10, 155
    ja      csu_toolong
    cmp     r10, rdx
    jae     csu_toolong
    movzx   eax, byte ptr [rcx + r10]
    cmp     al, '/'
    je      csu_found
    cmp     al, '\'
    je      csu_found
    inc     r10
    jmp     csu_scan

csu_found:
    mov     rax, rdx
    dec     rax
    sub     rax, r10
    cmp     rax, 100
    ja      csu_toolong
    xor     r11, r11
csu_pc:
    cmp     r11, r10
    jae     csu_pcd
    mov     al, byte ptr [rcx + r11]
    mov     byte ptr [r9 + r11], al
    inc     r11
    jmp     csu_pc
csu_pcd:
    mov     byte ptr [r9 + r11], 0
    lea     rcx, [rcx + r10 + 1]
    xor     r11, r11
csu_nc:
    mov     al, byte ptr [rcx + r11]
    test    al, al
    jz      csu_ncd
    mov     byte ptr [r8 + r11], al
    inc     r11
    cmp     r11, 100
    jb      csu_nc
csu_ncd:
    mov     byte ptr [r8 + r11], 0
    xor     eax, eax
    ret

csu_toolong:
    mov     byte ptr [r8], '@'
    mov     byte ptr [r8 + 1], 0
    mov     byte ptr [r9], 0
    xor     eax, eax
    ret

csu_invalid:
    mov     eax, 1
    ret
cf_split_ustar endp

; =============================================================================
; cf_dw_begin / cf_dw_flush_sink / cf_dw_feed / cf_dw_end / cf_dw_idx_add
; Self-contained format-v9 segmented AES-GCM entry writer for <stem>.delta.mrk.
; =============================================================================
cf_dw_begin proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rcx

    mov     rax, qword ptr [rbx + CFM_DW_PAYOFF]
    mov     qword ptr [rbx + CFM_DW_ENTOFF], rax
    mov     qword ptr [rbx + CFM_DW_SEGFILL], 0
    mov     qword ptr [rbx + CFM_DW_SINKFILL], 0
    mov     dword ptr [rbx + CFM_DW_SEGIDX], 0

    lea     r10, [rbx + CFM_DW_HDR]
    mov     r11, qword ptr [rbx + CFM_DW_ORD]
    WINCALL entry_stream_open, addr g_cf_dctx, r10, r11, 0, addr g_cf_delta_key, 0

    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
cf_dw_begin endp

cf_dw_flush_sink proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     rbx, rcx

    cmp     dword ptr [rbx + CFM_DW_ERR], 0
    jne     cdfs_err
    mov     r12, qword ptr [rbx + CFM_DW_SINKFILL]
    test    r12, r12
    jz      cdfs_ok

    ; Roll 4 GiB segment lazily only when full and more plaintext is arriving
    mov     rax, 100000000h
    cmp     qword ptr [rbx + CFM_DW_SEGFILL], rax
    jb      cdfs_enc

    lea     r10, [rbx + CFM_DW_TAG]
    WINCALL gcm_final, addr g_cf_dctx, r10
    mov     rcx, qword ptr [rbx + CFM_DW_HOUT]
    lea     rdx, [rbx + CFM_DW_TAG]
    mov     r8d, GCM_TAG_LEN
    call    cf_write_all
    test    eax, eax
    jnz     cdfs_set_err
    add     qword ptr [rbx + CFM_DW_PAYOFF], GCM_TAG_LEN
    inc     dword ptr [rbx + CFM_DW_SEGIDX]
    lea     r10, [rbx + CFM_DW_HDR]
    mov     r11, qword ptr [rbx + CFM_DW_ORD]
    WINCALL entry_stream_open, addr g_cf_dctx, r10, r11, 0, addr g_cf_delta_key, dword ptr [rbx + CFM_DW_SEGIDX]
    mov     qword ptr [rbx + CFM_DW_SEGFILL], 0

cdfs_enc:
    mov     r10, qword ptr [rbx + CFM_DW_SINKBUF]
    WINCALL gcm_crypt, addr g_cf_dctx, r10, r10, r12

    mov     rcx, qword ptr [rbx + CFM_DW_HOUT]
    mov     rdx, qword ptr [rbx + CFM_DW_SINKBUF]
    mov     r8,  r12
    call    cf_write_all
    test    eax, eax
    jnz     cdfs_set_err

    add     qword ptr [rbx + CFM_DW_PAYOFF], r12
    add     qword ptr [rbx + CFM_DW_SEGFILL], r12
    mov     qword ptr [rbx + CFM_DW_SINKFILL], 0

cdfs_ok:
    xor     eax, eax
    jmp     cdfs_out

cdfs_set_err:
    mov     dword ptr [rbx + CFM_DW_ERR], -1
cdfs_err:
    mov     eax, -1
cdfs_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
cf_dw_flush_sink endp

cf_dw_feed proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], rsi
    mov     qword ptr [rbp-48], rdi

    mov     rbx, rcx                        ; dwPtr
    mov     r12, rdx                        ; srcPtr
    mov     r13, r8                         ; remLen

cdfd_lp:
    cmp     dword ptr [rbx + CFM_DW_ERR], 0
    jne     cdfd_err
    test    r13, r13
    jz      cdfd_ok

    mov     rax, 10000h                     ; 64 KiB sink capacity
    sub     rax, qword ptr [rbx + CFM_DW_SINKFILL]
    cmp     rax, r13
    jbe     @F
    mov     rax, r13
@@:
    mov     rdi, qword ptr [rbx + CFM_DW_SINKBUF]
    add     rdi, qword ptr [rbx + CFM_DW_SINKFILL]
    mov     rsi, r12
    mov     rcx, rax
    rep     movsb

    add     qword ptr [rbx + CFM_DW_SINKFILL], rax
    add     r12, rax
    sub     r13, rax

    cmp     qword ptr [rbx + CFM_DW_SINKFILL], 10000h
    jne     cdfd_lp
    mov     rcx, rbx
    call    cf_dw_flush_sink
    test    eax, eax
    jz      cdfd_lp
    jmp     cdfd_err

cdfd_ok:
    xor     eax, eax
    jmp     cdfd_out
cdfd_err:
    mov     eax, -1
cdfd_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     rsi, qword ptr [rbp-40]
    mov     rdi, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
cf_dw_feed endp

cf_dw_end proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rcx

    call    cf_dw_flush_sink
    test    eax, eax
    jnz     cdwe_err

    lea     r10, [rbx + CFM_DW_TAG]
    WINCALL gcm_final, addr g_cf_dctx, r10

    mov     rcx, qword ptr [rbx + CFM_DW_HOUT]
    lea     rdx, [rbx + CFM_DW_TAG]
    mov     r8d, GCM_TAG_LEN
    call    cf_write_all
    test    eax, eax
    jnz     cdwe_set_err

    add     qword ptr [rbx + CFM_DW_PAYOFF], GCM_TAG_LEN
    inc     qword ptr [rbx + CFM_DW_ORD]
    xor     eax, eax
    jmp     cdwe_out

cdwe_set_err:
    mov     dword ptr [rbx + CFM_DW_ERR], -1
cdwe_err:
    mov     eax, -1
cdwe_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
cf_dw_end endp

; cf_dw_idx_add(rcx = idxArenaPtr, rdx = dwPtr, r8 = contentSize, r9d = flags,
;               [rbp+48] = u8NamePtr, [rbp+56] = u8NameLen) -> eax = 0 ok, -1 err
cf_dw_idx_add proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    mov     rbx, rdx                        ; dwPtr
    mov     r12, r8                         ; contentSize
    mov     r13d, r9d                       ; flags
    mov     rsi, qword ptr [rbp+48]         ; u8NamePtr
    mov     r14d, dword ptr [rbp+56]        ; u8NameLen

    lea     rdx, [r14 + IDXE_FIXED]
    call    cf_arena_alloc
    test    rax, rax
    jz      cdia_err

    mov     qword ptr [rax + IDXE_size], r12
    mov     rcx, qword ptr [rbx + CFM_DW_ENTOFF]
    mov     qword ptr [rax + IDXE_offset], rcx
    mov     rdx, qword ptr [rbx + CFM_DW_PAYOFF]
    sub     rdx, rcx
    mov     qword ptr [rax + IDXE_stored], rdx
    mov     rcx, qword ptr [rbx + CFM_DW_ORD]
    dec     rcx
    mov     qword ptr [rax + IDXE_ordinal], rcx
    mov     dword ptr [rax + IDXE_flags], r13d
    mov     dword ptr [rax + IDXE_namelen], r14d

    lea     rdi, [rax + IDXE_name]
    mov     ecx, r14d
    rep     movsb
    xor     eax, eax
    jmp     cdia_out

cdia_err:
    mov     eax, -1
cdia_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
cf_dw_idx_add endp

; =============================================================================
; cf_is_root_skip_w(rcx = leafW) -> eax = 1 skip, 0 keep
; Skips Windows volume metadata folders and .myrkr-delta at root depth 0.
; =============================================================================
cf_is_root_skip_w proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rcx

    WINCALL CompareStringOrdinal, rbx, -1, addr w_cf_recycle, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cirs_yes
    WINCALL CompareStringOrdinal, rbx, -1, addr w_cf_svi, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cirs_yes
    WINCALL CompareStringOrdinal, rbx, -1, addr w_cf_delta_mf, -1, 1
    cmp     eax, CFM_CSTR_EQUAL
    je      cirs_yes

    xor     eax, eax
    jmp     cirs_out
cirs_yes:
    mov     eax, 1
cirs_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
cf_is_root_skip_w endp

; =============================================================================
; cf_find_base_info(rcx = u8Name, edx = u8Len, r8d = mode) -> rax:
;   mode = 0: exact non-dir match -> returns last matching entryPtr or 0
;   mode = 1: exact non-dir match -> marks CFM_BASE_SEEN on all matches & returns last
;   mode = 2: dir lookup -> returns bitmask:
;             bit 0 (1) = exact IDXEF_DIR match (marked CFM_BASE_SEEN)
;             bit 1 (2) = prefix match (some entry starts with u8Name + '/')
; =============================================================================
cf_find_base_info proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    xor     rax, rax                        ; result (ptr or mask)
    mov     r9, qword ptr [g_cf_base_idx]
    test    r9, r9
    jz      cfbi_out
    mov     r10, r9
    add     r10, qword ptr [g_cf_base_idxlen]
    mov     r11, qword ptr [g_cf_base_idxcnt]

cfbi_lp:
    test    r11, r11
    jz      cfbi_out
    lea     rbx, [r9 + IDXE_FIXED]
    cmp     rbx, r10
    ja      cfbi_out
    mov     ebx, dword ptr [r9 + IDXE_namelen]
    lea     rdi, [r9 + IDXE_FIXED + rbx]
    cmp     rdi, r10
    ja      cfbi_out

    cmp     r8d, 2
    je      cfbi_dir_mode

    ; File modes (0 / 1): require non-dir and exact namelen == edx
    test    dword ptr [r9 + IDXE_flags], IDXEF_DIR
    jnz     cfbi_next
    cmp     ebx, edx
    jne     cfbi_next
    xor     edi, edi
cfbi_fcmp:
    cmp     edi, edx
    jae     cfbi_fmatch
    mov     sil, byte ptr [rcx + rdi]
    cmp     sil, byte ptr [r9 + IDXE_name + rdi]
    jne     cfbi_next
    inc     edi
    jmp     cfbi_fcmp
cfbi_fmatch:
    mov     rax, r9
    cmp     r8d, 1
    jne     cfbi_next
    or      dword ptr [r9 + IDXE_flags], CFM_BASE_SEEN
    jmp     cfbi_next

cfbi_dir_mode:
    cmp     ebx, edx
    jb      cfbi_next
    jne     cfbi_chk_pfx
    ; Exact length: check IDXEF_DIR
    test    dword ptr [r9 + IDXE_flags], IDXEF_DIR
    jz      cfbi_next
    xor     edi, edi
cfbi_dcmp1:
    cmp     edi, edx
    jae     cfbi_dmatch_exact
    mov     sil, byte ptr [rcx + rdi]
    cmp     sil, byte ptr [r9 + IDXE_name + rdi]
    jne     cfbi_next
    inc     edi
    jmp     cfbi_dcmp1
cfbi_dmatch_exact:
    or      dword ptr [r9 + IDXE_flags], CFM_BASE_SEEN
    or      eax, 1
    jmp     cfbi_next

cfbi_chk_pfx:
    cmp     byte ptr [r9 + IDXE_name + rdx], '/'
    jne     cfbi_next
    xor     edi, edi
cfbi_dcmp2:
    cmp     edi, edx
    jae     cfbi_dmatch_pfx
    mov     sil, byte ptr [rcx + rdi]
    cmp     sil, byte ptr [r9 + IDXE_name + rdi]
    jne     cfbi_next
    inc     edi
    jmp     cfbi_dcmp2
cfbi_dmatch_pfx:
    or      eax, 2

cfbi_next:
    mov     ebx, dword ptr [r9 + IDXE_namelen]
    lea     r9, [r9 + IDXE_FIXED + rbx]
    dec     r11
    jmp     cfbi_lp

cfbi_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
cf_find_base_info endp
; =============================================================================
; cf_diff_add_item(rcx = diffCtxPtr, edx = kind, r8 = fileSize, r9 = wfdMtime,
;                  [rbp+48] = u8Ptr, [rbp+56] = u8Len,
;                  [rbp+64] = wRelPtr, [rbp+72] = wRelChars,
;                  [rbp+80] = baseHdr40Or0) -> eax = 0 ok, -1 err
; =============================================================================
cf_diff_add_item proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], r15
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rbx, rcx                        ; diffCtxPtr
    mov     r12d, edx                       ; kind (0=dir, 1=local file, 2=moved base)
    mov     r13, r8                         ; fileSize
    mov     r14, r9                         ; wfdMtime

    ; Mix 24-byte item descriptor + u8Name (+ baseHdr if kind==2) into fp64
    mov     dword ptr [rbp-96], r12d
    mov     eax, dword ptr [rbp+56]
    mov     dword ptr [rbp-92], eax
    mov     qword ptr [rbp-88], r13
    mov     qword ptr [rbp-80], r14
    mov     rcx, qword ptr [rbx + 64]
    lea     rdx, [rbp-96]
    mov     r8d, 24
    call    cf_fnv_mix
    mov     rcx, rax
    mov     rdx, qword ptr [rbp+48]
    mov     r8d, dword ptr [rbp+56]
    call    cf_fnv_mix
    cmp     r12d, 2
    jne     @F
    mov     rdx, qword ptr [rbp+80]
    test    rdx, rdx
    jz      @F
    mov     rcx, rax
    mov     r8d, IDXE_FIXED
    call    cf_fnv_mix
@@:
    mov     qword ptr [rbx + 64], rax

    ; Compute 8-byte aligned record size:
    ;   64 + ((u8Len + 2) & ~1) + (wRelChars + 1)*2, rounded to 8
    mov     eax, dword ptr [rbp+56]         ; u8Len
    add     eax, 2
    and     eax, NOT 1
    mov     r15d, eax                       ; aligned u8 block bytes
    mov     ecx, dword ptr [rbp+72]         ; wRelChars
    inc     ecx
    shl     ecx, 1                          ; wRel byte length incl NUL
    lea     edx, [r15d + ecx + 64 + 7]
    and     edx, NOT 7                      ; recBytes
    mov     dword ptr [rbp-72], edx

    lea     rcx, [rbx + 0]                  ; recArena
    mov     edx, dword ptr [rbp-72]
    call    cf_arena_alloc
    test    rax, rax
    jz      cdai_err
    mov     rdi, rax                        ; recPtr

    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [rdi + 0], eax        ; recBytes
    mov     dword ptr [rdi + 4], r12d       ; kind
    mov     qword ptr [rdi + 8], r13        ; fileSize
    mov     eax, dword ptr [rbp+56]
    mov     dword ptr [rdi + 16], eax       ; u8Len
    mov     eax, dword ptr [rbp+72]
    mov     dword ptr [rdi + 20], eax       ; wRelChars

    ; Populate or zero 40-byte baseHdr at [rdi + 24]
    mov     rsi, qword ptr [rbp+80]
    test    rsi, rsi
    jz      cdai_zero_hdr
    mov     r10, rdi
    lea     rdi, [r10 + 24]
    mov     ecx, IDXE_FIXED
    rep     movsb
    mov     rdi, r10
    jmp     cdai_copy_u8

cdai_zero_hdr:
    xor     eax, eax
    mov     qword ptr [rdi + 24], rax
    mov     qword ptr [rdi + 32], rax
    mov     qword ptr [rdi + 40], rax
    mov     qword ptr [rdi + 48], rax
    mov     qword ptr [rdi + 56], rax

cdai_copy_u8:
    mov     r10, rdi
    lea     rdi, [r10 + 64]
    mov     rsi, qword ptr [rbp+48]
    mov     ecx, dword ptr [rbp+56]
    rep     movsb
    mov     byte ptr [rdi], 0

    lea     rdi, [r10 + 64 + r15]
    mov     rsi, qword ptr [rbp+64]
    mov     ecx, dword ptr [rbp+72]
    shl     ecx, 1
    rep     movsb
    mov     word ptr [rdi], 0

    inc     dword ptr [rbx + 72]            ; itemCount++
    xor     eax, eax
    jmp     cdai_out

cdai_err:
    mov     dword ptr [rbx + 80], -1
    mov     eax, -1

cdai_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     r15, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
cf_diff_add_item endp

; =============================================================================
; cf_diff_walk_rec(rcx = diffCtxPtr, rdx = dirFullW, r8 = dirRelW, r9d = depth)
;   -> eax = direct child count (>= 0), or -1 on error
; =============================================================================
cf_diff_walk_rec proc frame
    FRAME_PROLOG 208
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], r15
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     r12, rcx                        ; diffCtxPtr
    mov     r13, rdx                        ; dirFullW
    mov     r14, r8                         ; dirRelW
    mov     dword ptr [rbp-72], r9d         ; depth
    mov     dword ptr [rbp-68], 0           ; childCount = 0

    cmp     dword ptr [r12 + 80], 0
    jne     cdwr_err_early
    cmp     r9d, CFM_MAX_DEPTH
    jae     cdwr_zero_early

    WINCALL VirtualAlloc, 0, CFM_DIFF_SCRATCH, CFM_MEM_COMMIT_RES, CFM_PAGE_RW
    test    rax, rax
    jz      cdwr_oom
    mov     rbx, rax
    ; scratch layout:
    ;   [rbx + 0 .. 591]         = WIN32_FIND_DATAW
    ;   [rbx + 608 .. 735]       = CF_PLACEHOLDER_STANDARD_INFO (128 B)
    ;   [rbx + 768]              = retLen (dd)
    ;   [rbx + 1024 .. 66559]    = childFullW (MAX_PATH_CHARS dw)
    ;   [rbx + 66560 .. 132095]  = childRelW  (MAX_PATH_CHARS dw)
    ;   [rbx + 132096 .. 140287] = childU8    (8192 B)

    lea     rcx, [rbx + 1024]
    mov     edx, MAX_PATH_CHARS
    mov     r8,  r13
    lea     r9,  [w_cf_star]
    call    cf_wcopy_cat
    test    eax, eax
    jz      cdwr_free_ok

    lea     rcx, [rbx + 1024]
    WINCALL FindFirstFileW, rcx, rbx
    cmp     rax, -1
    je      cdwr_free_ok
    mov     r15, rax                        ; hFind

cdwr_entry:
    ; Skip "." and ".."
    cmp     word ptr [rbx + 44], '.'
    jne     cdwr_chk_root
    cmp     word ptr [rbx + 46], 0
    je      cdwr_step
    cmp     word ptr [rbx + 46], '.'
    jne     cdwr_chk_root
    cmp     word ptr [rbx + 48], 0
    je      cdwr_step

cdwr_chk_root:
    cmp     dword ptr [rbp-72], 0
    jne     cdwr_chk_reparse
    lea     rcx, [rbx + 44]
    call    cf_is_root_skip_w
    test    eax, eax
    jnz     cdwr_step

cdwr_chk_reparse:
    ; Skip symlinks / junctions (name-surrogate reparse points), NOT cloud placeholders
    mov     eax, dword ptr [rbx]
    test    eax, CFM_ATTR_REPARSE
    jz      cdwr_count_child
    test    dword ptr [rbx + 36], CFM_REPARSE_SURR
    jnz     cdwr_step

cdwr_count_child:
    inc     dword ptr [rbp-68]              ; childCount++

    ; Build childFullW = dirFullW + "\" + cFileName
    lea     rcx, [rbx + 1024]
    mov     edx, MAX_PATH_CHARS
    mov     r8,  r13
    lea     r9,  [rbx + 44]
    call    cf_wjoin_bs
    test    eax, eax
    jz      cdwr_step

    ; Build childRelW = (dirRelW ? dirRelW + "\" : "") + cFileName
    lea     rcx, [rbx + 66560]
    mov     edx, MAX_PATH_CHARS
    mov     r8,  r14
    lea     r9,  [rbx + 44]
    call    cf_wjoin_bs
    test    eax, eax
    jz      cdwr_step
    mov     dword ptr [rbp-80], eax         ; wRelChars

    ; Convert childRelW -> UTF-8 in childU8 with '/' separators
    lea     r10, [rbx + 66560]
    lea     r11, [rbx + 132096]
    WINCALL WideCharToMultiByte, CFM_CP_UTF8, 0, r10, dword ptr [rbp-80], \
            r11, ENTRY_NAME_MAX, 0, 0
    test    eax, eax
    jle     cdwr_step
    mov     dword ptr [rbp-76], eax         ; u8Len
    lea     rcx, [rbx + 132096]
    mov     byte ptr [rcx + rax], 0
    xor     edx, edx
cdwr_norm_sep:
    cmp     edx, eax
    jae     cdwr_san
    cmp     byte ptr [rcx + rdx], '\'
    jne     @F
    mov     byte ptr [rcx + rdx], '/'
@@:
    inc     edx
    jmp     cdwr_norm_sep

cdwr_san:
    lea     rcx, [rbx + 132096]
    call    sanitize_name
    test    eax, eax
    jnz     cdwr_step

    test    dword ptr [rbx], CFM_ATTR_DIR
    jz      cdwr_is_file

    ; ---- Directory node ----
    lea     rcx, [rbx + 132096]
    mov     edx, dword ptr [rbp-76]
    mov     r8d, 2
    call    cf_find_base_info
    mov     qword ptr [rbp-112], rax        ; baseDirMask

    mov     rcx, r12
    lea     rdx, [rbx + 1024]
    lea     r8,  [rbx + 66560]
    mov     r9d, dword ptr [rbp-72]
    inc     r9d
    call    cf_diff_walk_rec
    test    eax, eax
    js      cdwr_close_err

    ; Skip emitting directory if already explicit IDXEF_DIR in base, OR if an
    ; implicit parent folder in base that still contains >= 1 child on disk.
    mov     rcx, qword ptr [rbp-112]
    test    ecx, 1
    jnz     cdwr_step
    test    ecx, 2
    jz      cdwr_emit_dir
    test    eax, eax
    jnz     cdwr_step

cdwr_emit_dir:
    lea     rsi, [rbx + 132096]
    mov     edi, dword ptr [rbp-76]
    lea     r10, [rbx + 66560]
    mov     r11d, dword ptr [rbp-80]
    WINCALL cf_diff_add_item, r12, 0, 0, 0, rsi, rdi, r10, r11, 0
    test    eax, eax
    js      cdwr_close_err
    jmp     cdwr_step

cdwr_is_file:
    ; ---- File node ----
    mov     eax, dword ptr [rbx + 28]       ; nFileSizeHigh
    shl     rax, 32
    mov     ecx, dword ptr [rbx + 32]       ; nFileSizeLow
    or      rax, rcx
    mov     qword ptr [rbp-88], rax         ; wfdSize
    mov     rax, qword ptr [rbx + 20]       ; ftLastWriteTime
    mov     qword ptr [rbp-96], rax         ; wfdMtime

    ; Inspect Cloud Files placeholder metadata without triggering hydration
    lea     r10, [rbx + 1024]
    WINCALL CreateFileW, r10, CFM_FILE_READ_ATTR, CFM_SHARE_ALL, 0, \
            CFM_OPEN_EXISTING, CFM_FLAG_BACKUP, 0
    cmp     rax, -1
    je      cdwr_file_local
    mov     qword ptr [rbp-104], rax        ; hAttr

    lea     rcx, [rbx + 608]
    mov     edx, 128
    call    secure_zero
    mov     dword ptr [rbx + 768], 0
    mov     r10, qword ptr [pfn_CfGetPlaceholderInfo]
    test    r10, r10
    jz      cdwr_close_attr_local
    lea     rsi, [rbx + 608]
    lea     rdi, [rbx + 768]
    WINCALL r10, qword ptr [rbp-104], 1, rsi, 128, rdi
    mov     esi, eax
    WINCALL CloseHandle, qword ptr [rbp-104]
    test    esi, esi
    js      cdwr_file_local

    ; Check untouched session placeholder invariants:
    ;   FileIdentityLength == 48, magic == g_cf_session_magic,
    ;   InSyncState == 1, ModifiedDataSize == 0, wfdSize == IDXE_size
    cmp     dword ptr [rbx + 608 + 56], 48
    jne     cdwr_file_local
    mov     rax, qword ptr [rbx + 608 + 60]
    cmp     rax, qword ptr [g_cf_session_magic]
    jne     cdwr_file_local
    cmp     dword ptr [rbx + 608 + 36], 1
    jne     cdwr_file_local
    cmp     qword ptr [rbx + 608 + 16], 0
    jne     cdwr_file_local
    mov     rax, qword ptr [rbx + 608 + 68 + IDXE_size]
    cmp     rax, qword ptr [rbp-88]
    jne     cdwr_file_local

    ; Clean placeholder from this mount session: check if still at original path
    lea     rcx, [rbx + 132096]
    mov     edx, dword ptr [rbp-76]
    xor     r8d, r8d
    call    cf_find_base_info
    test    rax, rax
    jz      cdwr_file_moved
    mov     rcx, qword ptr [rax + IDXE_ordinal]
    cmp     rcx, qword ptr [rbx + 608 + 68 + IDXE_ordinal]
    jne     cdwr_file_moved_over

    ; Case 0: Untouched base file at its original path -> mark seen & skip
    lea     rcx, [rbx + 132096]
    mov     edx, dword ptr [rbp-76]
    mov     r8d, 1
    call    cf_find_base_info
    jmp     cdwr_step

cdwr_file_moved_over:
    ; Clean placeholder renamed/moved onto an existing base file path -> mark target seen
    lea     rcx, [rbx + 132096]
    mov     edx, dword ptr [rbp-76]
    mov     r8d, 1
    call    cf_find_base_info

cdwr_file_moved:
    ; Case 2: Renamed/moved clean base placeholder -> stream from g_cf_esctx
    lea     rsi, [rbx + 132096]
    mov     edi, dword ptr [rbp-76]
    lea     r10, [rbx + 66560]
    mov     r11d, dword ptr [rbp-80]
    lea     rax, [rbx + 608 + 68]
    mov     qword ptr [rbp-112], rax
    WINCALL cf_diff_add_item, r12, 2, qword ptr [rbp-88], qword ptr [rbp-96], \
            rsi, rdi, r10, r11, qword ptr [rbp-112]
    test    eax, eax
    js      cdwr_close_err
    jmp     cdwr_step

cdwr_close_attr_local:
    WINCALL CloseHandle, qword ptr [rbp-104]

cdwr_file_local:
    ; Case 1: Modified placeholder or newly created local file
    lea     rcx, [rbx + 132096]
    mov     edx, dword ptr [rbp-76]
    mov     r8d, 1
    call    cf_find_base_info

    lea     rsi, [rbx + 132096]
    mov     edi, dword ptr [rbp-76]
    lea     r10, [rbx + 66560]
    mov     r11d, dword ptr [rbp-80]
    WINCALL cf_diff_add_item, r12, 1, qword ptr [rbp-88], qword ptr [rbp-96], \
            rsi, rdi, r10, r11, 0
    test    eax, eax
    js      cdwr_close_err

cdwr_step:
    WINCALL FindNextFileW, r15, rbx
    test    eax, eax
    jnz     cdwr_entry

    WINCALL FindClose, r15
cdwr_free_ok:
    WINCALL VirtualFree, rbx, 0, CFM_MEM_RELEASE
    mov     eax, dword ptr [rbp-68]
    jmp     cdwr_out

cdwr_close_err:
    WINCALL FindClose, r15
    WINCALL VirtualFree, rbx, 0, CFM_MEM_RELEASE
    mov     eax, -1
    jmp     cdwr_out

cdwr_oom:
    mov     dword ptr [r12 + 80], -1
cdwr_err_early:
    mov     eax, -1
    jmp     cdwr_out

cdwr_zero_early:
    xor     eax, eax

cdwr_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     r15, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
cf_diff_walk_rec endp

; =============================================================================
; cf_collect_diff(rcx = diffCtxPtr) -> eax = 0 ok, -1 err
; Populates diffCtx (88 bytes):
;   +0  recArena (32)
;   +32 manArena (32)
;   +64 fp64 (8)
;   +72 itemCount (4)
;   +76 delCount (4)
;   +80 err (4)
; Caller must call cf_arena_free on diffCtx+0 and diffCtx+32 when done.
; =============================================================================
cf_collect_diff proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    mov     rbx, rcx                        ; diffCtxPtr
    mov     rcx, rbx
    mov     edx, 88
    call    secure_zero

    mov     rax, 0CBF29CE484222325h         ; FNV-1a 64-bit offset basis
    mov     qword ptr [rbx + 64], rax

    lea     rcx, [rbx + 0]
    mov     edx, CFM_REC_ARENA_CAP
    call    cf_arena_init
    test    eax, eax
    jz      ccd_err

    lea     rcx, [rbx + 32]
    mov     edx, CFM_MAN_ARENA_CAP
    call    cf_arena_init
    test    eax, eax
    jz      ccd_err

    ; Clear CFM_BASE_SEEN across g_cf_base_idx
    mov     r12, qword ptr [g_cf_base_idx]
    mov     r13, r12
    add     r13, qword ptr [g_cf_base_idxlen]
    mov     r14, qword ptr [g_cf_base_idxcnt]
ccd_clr_lp:
    test    r14, r14
    jz      ccd_hdr
    lea     rax, [r12 + IDXE_FIXED]
    cmp     rax, r13
    ja      ccd_hdr
    mov     eax, dword ptr [r12 + IDXE_namelen]
    lea     rcx, [r12 + IDXE_FIXED + rax]
    cmp     rcx, r13
    ja      ccd_hdr
    and     dword ptr [r12 + IDXE_flags], 7FFFFFFFh
    mov     r12, rcx
    dec     r14
    jmp     ccd_clr_lp

ccd_hdr:
    ; Emit 49-byte .myrkr-delta header: "myrkr-delta-v1\nbase-id: <24hex>\n"
    lea     rcx, [rbx + 32]
    mov     edx, 49
    call    cf_arena_alloc
    test    rax, rax
    jz      ccd_err
    mov     rdi, rax
    lea     rsi, [a_cf_mf_hdr1]
    mov     ecx, 24
    rep     movsb

    lea     rsi, [g_cf_base_hdr + CONTAINER_HDR.set_id]
    lea     r10, [a_cf_hex]
    mov     ecx, 12
ccd_id_hex:
    movzx   eax, byte ptr [rsi]
    mov     edx, eax
    shr     eax, 4
    and     edx, 0Fh
    movzx   eax, byte ptr [r10 + rax]
    mov     byte ptr [rdi], al
    movzx   edx, byte ptr [r10 + rdx]
    mov     byte ptr [rdi + 1], dl
    inc     rsi
    add     rdi, 2
    dec     ecx
    jnz     ccd_id_hex
    mov     byte ptr [rdi], 10              ; '\n'

    ; Walk sync-root tree
    mov     rcx, rbx
    lea     rdx, [g_cf_root_w]
    lea     r8,  [w_cf_empty]
    xor     r9d, r9d
    call    cf_diff_walk_rec
    test    eax, eax
    js      ccd_err
    cmp     dword ptr [rbx + 80], 0
    jne     ccd_err

    ; Append "del: <utf8>\n" lines for any base entries not marked CFM_BASE_SEEN
    mov     r12, qword ptr [g_cf_base_idx]
    mov     r13, r12
    add     r13, qword ptr [g_cf_base_idxlen]
    mov     r14, qword ptr [g_cf_base_idxcnt]
ccd_del_lp:
    test    r14, r14
    jz      ccd_ok
    lea     rax, [r12 + IDXE_FIXED]
    cmp     rax, r13
    ja      ccd_ok
    mov     eax, dword ptr [r12 + IDXE_namelen]
    lea     rcx, [r12 + IDXE_FIXED + rax]
    cmp     rcx, r13
    ja      ccd_ok

    test    dword ptr [r12 + IDXE_flags], CFM_BASE_SEEN
    jnz     ccd_del_next

    lea     rcx, [rbx + 32]
    lea     edx, [eax + 6]                  ; "del: " (5) + namelen + '\n' (1)
    call    cf_arena_alloc
    test    rax, rax
    jz      ccd_err
    mov     rdi, rax
    mov     qword ptr [rbp-64], rax         ; lineStart

    lea     rsi, [a_cf_mf_del]
    mov     ecx, 5
    rep     movsb
    lea     rsi, [r12 + IDXE_name]
    mov     ecx, dword ptr [r12 + IDXE_namelen]
    rep     movsb
    mov     byte ptr [rdi], 10              ; '\n'

    mov     rcx, qword ptr [rbx + 64]
    mov     rdx, qword ptr [rbp-64]
    mov     r8d, dword ptr [r12 + IDXE_namelen]
    add     r8d, 6
    call    cf_fnv_mix
    mov     qword ptr [rbx + 64], rax
    inc     dword ptr [rbx + 76]            ; delCount++

ccd_del_next:
    mov     eax, dword ptr [r12 + IDXE_namelen]
    lea     r12, [r12 + IDXE_FIXED + rax]
    dec     r14
    jmp     ccd_del_lp

ccd_ok:
    xor     eax, eax
    jmp     ccd_out

ccd_err:
    mov     dword ptr [rbx + 80], -1
    mov     eax, -1

ccd_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
cf_collect_diff endp

; =============================================================================
; cf_sync_delta_once(ecx = isFinal) -> eax:
;   0  = already synced / clean (no disk write needed)
;   1  = wrote or removed <stem>.delta.mrk on disk
;   2  = background pass deferred (a modified file is still locked by an app)
;  -1  = I/O or OOM error
; =============================================================================
cf_sync_delta_once proc frame
    FRAME_PROLOG 800
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], r15
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     dword ptr [rbp-72], ecx         ; isFinal
    mov     dword ptr [rbp-68], -1          ; retCode
    mov     qword ptr [rbp-80], -1          ; hOut
    mov     qword ptr [rbp-88], -1          ; hIn
    xor     ebx, ebx                        ; workBuf = 0

    WINCALL AcquireSRWLockExclusive, addr g_cf_delta_lock

    cmp     dword ptr [g_cf_is_rw], 0
    je      csdo_ret_zero

    ; Zero idxArena so cleanup is always safe
    lea     rcx, [rbp-240]
    mov     edx, 32
    call    secure_zero

    lea     rcx, [rbp-208]                  ; diffCtx
    call    cf_collect_diff
    test    eax, eax
    js      csdo_cleanup

    ; Check if sync root matches base .mrk with zero changes
    mov     eax, dword ptr [rbp-208 + 72]   ; itemCount
    or      eax, dword ptr [rbp-208 + 76]   ; delCount
    jnz     csdo_has_diff

    cmp     dword ptr [g_cf_dirty], 0
    je      csdo_ret_zero
    WINCALL DeleteFileW, addr g_cf_delta_w
    mov     dword ptr [g_cf_dirty], 0
    mov     qword ptr [g_cf_synced_fp], 0
    mov     dword ptr [rbp-68], 1
    jmp     csdo_cleanup

csdo_has_diff:
    ; Skip redundant Argon2id + rewrite if on-disk .delta.mrk already matches fp64
    cmp     dword ptr [g_cf_dirty], 0
    je      csdo_alloc_work
    mov     rax, qword ptr [rbp-208 + 64]
    cmp     rax, qword ptr [g_cf_synced_fp]
    jne     csdo_alloc_work
    WINCALL GetFileAttributesW, addr g_cf_delta_w
    cmp     eax, CFM_INV_ATTR
    jne     csdo_ret_zero

csdo_alloc_work:
    WINCALL VirtualAlloc, 0, CFM_SYNC_WORK_BYTES, CFM_MEM_COMMIT_RES, CFM_PAGE_RW
    test    rax, rax
    jz      csdo_cleanup
    mov     rbx, rax
    ; workBuf layout (256 KiB):
    ;   [rbx + 0 .. 65535]       = sinkBuf64K
    ;   [rbx + 65536 .. 131071]  = readBuf64K
    ;   [rbx + 131072 .. 196607] = fullPathW (MAX_PATH_CHARS dw)
    ;   [rbx + 196608 .. 197119] = tarHdr512
    ;   [rbx + 197120 .. 197247] = nameBuf128
    ;   [rbx + 197248 .. 197439] = prefixBuf192
    ;   [rbx + 197440 .. 201599] = dirSlashBuf (4160 B)
    ;   [rbx + 201600 .. 201727] = stdInfo128  (128 B)
    ;   [rbx + 201728]           = retLen      (dd)

    ; Pre-flight lock probe on modified/local files (kind == 1) before Argon2id
    mov     r12, qword ptr [rbp-208 + 0]    ; recArena.base
    mov     r13, r12
    add     r13, qword ptr [rbp-208 + 8]    ; recArena.end
csdo_probe_lp:
    cmp     r12, r13
    jae     csdo_probe_ok
    cmp     dword ptr [r12 + 4], 1          ; kind == 1?
    jne     csdo_probe_next

    mov     eax, dword ptr [r12 + 16]
    add     eax, 2
    and     eax, NOT 1
    lea     r9, [r12 + 64 + rax]            ; wRel
    lea     rcx, [rbx + 131072]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_root_w]
    call    cf_wjoin_bs
    test    eax, eax
    jz      csdo_cleanup

    xor     r14d, r14d                      ; retry counter
csdo_probe_open:
    lea     r10, [rbx + 131072]
    WINCALL CreateFileW, r10, CFM_GENERIC_READ, CFM_SHARE_ALL, 0, \
            CFM_OPEN_EXISTING, CFM_ATTR_NORMAL, 0
    cmp     rax, -1
    jne     csdo_probe_close
    cmp     dword ptr [rbp-72], 0           ; isFinal?
    je      csdo_defer_locked
    inc     r14d
    cmp     r14d, 6
    jae     csdo_cleanup
    WINCALL Sleep, 50
    jmp     csdo_probe_open

csdo_probe_close:
    WINCALL CloseHandle, rax

csdo_probe_next:
    mov     eax, dword ptr [r12 + 0]
    add     r12, rax
    jmp     csdo_probe_lp

csdo_defer_locked:
    mov     dword ptr [rbp-68], 2
    jmp     csdo_cleanup

csdo_probe_ok:
    ; Initialize idxArena
    lea     rcx, [rbp-240]
    mov     edx, CFM_IDX_ARENA_CAP
    call    cf_arena_init
    test    eax, eax
    jz      csdo_cleanup

    ; Build 80-byte format-v9 header in CF_DWSTATE ([rbp-400 + CFM_DW_HDR])
    lea     rcx, [rbp-400]
    mov     edx, CFM_DW_BYTES
    call    secure_zero

    lea     r14, [rbp-400 + CFM_DW_HDR]
    mov     dword ptr [r14 + 0], HDR_MAGIC
    mov     dword ptr [r14 + 4], HDR_VERSION
    mov     eax, dword ptr [g_cf_base_hdr + CONTAINER_HDR.t_cost]
    cmp     eax, ARGON2_MIN_T
    jae     @F
    mov     eax, ARGON2_DEF_T
@@:
    mov     dword ptr [r14 + 8], eax
    mov     eax, dword ptr [g_cf_base_hdr + CONTAINER_HDR.m_cost_kib]
    cmp     eax, ARGON2_MIN_M_KIB
    jae     @F
    mov     eax, ARGON2_DEF_M_KIB
@@:
    mov     dword ptr [r14 + 12], eax
    mov     byte ptr [r14 + 16], 1          ; lanes = 1
    mov     byte ptr [r14 + 17], 1          ; archive = 1
    mov     byte ptr [r14 + 18], 0          ; compressed = 0
    mov     byte ptr [r14 + 19], SEG_SHIFT_DEFAULT

    lea     rcx, [r14 + 20]                 ; 32B salt + 12B set_id = 44 random bytes
    mov     edx, 44
    call    rng_fill
    test    eax, eax
    jz      csdo_cleanup

    ; Derive g_cf_delta_key via Argon2id (RFC 9106 standard for v9)
    lea     rcx, [rbp-496]
    mov     edx, sizeof ARGON2REQ
    call    secure_zero

    mov     eax, dword ptr [r14 + 8]
    mov     dword ptr [rbp-496 + ARGON2REQ.t_cost], eax
    mov     eax, dword ptr [r14 + 12]
    mov     dword ptr [rbp-496 + ARGON2REQ.m_cost], eax
    mov     dword ptr [rbp-496 + ARGON2REQ.lanes], 1
    mov     dword ptr [rbp-496 + ARGON2REQ.outlen], KEY_LEN
    mov     dword ptr [rbp-496 + ARGON2REQ.version], 13h
    mov     dword ptr [rbp-496 + ARGON2REQ.atype], 2
    lea     rax, [g_cf_pass]
    mov     qword ptr [rbp-496 + ARGON2REQ.pwd], rax
    mov     eax, dword ptr [g_cf_passlen]
    mov     dword ptr [rbp-496 + ARGON2REQ.pwdlen], eax
    mov     dword ptr [rbp-496 + ARGON2REQ.saltlen], 32
    lea     rax, [r14 + 20]
    mov     qword ptr [rbp-496 + ARGON2REQ.salt], rax
    lea     rax, [g_cf_delta_key]
    mov     qword ptr [rbp-496 + ARGON2REQ.outp], rax
    mov     dword ptr [rbp-496 + ARGON2REQ.flags], 0

    lea     rcx, [rbp-496]
    call    argon2id_hash
    test    eax, eax
    jnz     csdo_cleanup

    ; Fill 16-byte KCV = SHA-256(g_cf_delta_key)[0..15]
    lea     rcx, [g_cf_delta_key]
    mov     edx, KEY_LEN
    lea     r8,  [rbp-528]
    call    sha256_hash
    lea     rsi, [rbp-528]
    lea     rdi, [r14 + KCV_OFFSET]
    mov     ecx, KCV_LEN
    rep     movsb
    lea     rcx, [rbp-528]
    mov     edx, 32
    call    secure_zero

    ; Build sibling temp path "<g_cf_delta_w>.<16hex>.tmp" in g_cf_dtmp_w
    lea     rcx, [rbp-528]
    mov     edx, 8
    call    rng_fill
    test    eax, eax
    jz      csdo_cleanup

    lea     rcx, [g_cf_dtmp_w]
    mov     edx, MAX_PATH_CHARS - 32
    lea     r8,  [g_cf_delta_w]
    xor     r9d, r9d
    call    cf_wcopy_cat
    test    eax, eax
    jz      csdo_cleanup

    lea     rdi, [g_cf_dtmp_w]
    xor     ecx, ecx
@@:
    cmp     word ptr [rdi + rcx*2], 0
    je      @F
    inc     ecx
    jmp     @B
@@:
    lea     rdi, [rdi + rcx*2]
    mov     word ptr [rdi], '.'
    add     rdi, 2
    lea     rsi, [rbp-528]
    lea     r10, [a_cf_hex]
    mov     ecx, 8
csdo_tmp_hex:
    movzx   eax, byte ptr [rsi]
    mov     edx, eax
    shr     eax, 4
    and     edx, 0Fh
    movzx   eax, byte ptr [r10 + rax]
    mov     word ptr [rdi], ax
    movzx   edx, byte ptr [r10 + rdx]
    mov     word ptr [rdi + 2], dx
    inc     rsi
    add     rdi, 4
    dec     ecx
    jnz     csdo_tmp_hex
    mov     word ptr [rdi + 0], '.'
    mov     word ptr [rdi + 2], 't'
    mov     word ptr [rdi + 4], 'm'
    mov     word ptr [rdi + 6], 'p'
    mov     word ptr [rdi + 8], 0

    WINCALL CreateFileW, addr g_cf_dtmp_w, CFM_GENERIC_WRITE, 0, 0, \
            CFM_CREATE_ALWAYS, CFM_ATTR_NORMAL, 0
    cmp     rax, -1
    je      csdo_cleanup
    mov     qword ptr [rbp-80], rax         ; hOut
    mov     qword ptr [rbp-400 + CFM_DW_HOUT], rax
    mov     qword ptr [rbp-400 + CFM_DW_SINKBUF], rbx

    ; Write 80-byte container header
    mov     rcx, rax
    lea     rdx, [rbp-400 + CFM_DW_HDR]
    mov     r8d, HDR_BYTES
    call    cf_write_all
    test    eax, eax
    jnz     csdo_abort_tmp

    ; ---- Entry 0: .myrkr-delta manifest ----
    lea     rcx, [a_cf_mf_name]
    mov     edx, 12
    lea     r8,  [rbx + 197120]
    lea     r9,  [rbx + 197248]
    call    cf_split_ustar

    mov     r15, qword ptr [rbp-208 + 40]   ; manArena.len
    lea     r10, [rbx + 196608]             ; tarHdr512
    lea     r11, [rbx + 197120]             ; nameBuf
    lea     rsi, [rbx + 197248]             ; prefixBuf
    WINCALL tar_build_header, r10, r11, rsi, r15, '0'

    lea     rcx, [rbp-400]
    call    cf_dw_begin
    lea     rcx, [rbp-400]
    lea     rdx, [rbx + 196608]
    mov     r8d, 512
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp

    lea     rcx, [rbp-400]
    mov     rdx, qword ptr [rbp-208 + 32]   ; manArena.base
    mov     r8,  r15
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp

    mov     rax, r15
    and     eax, 511
    mov     r8d, 512
    sub     r8d, eax
    and     r8d, 511
    jz      @F
    lea     rcx, [rbp-400]
    lea     rdx, [g_cf_zeros512]
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp
@@:
    lea     rcx, [rbp-400]
    call    cf_dw_end
    test    eax, eax
    jnz     csdo_abort_tmp

    lea     r10, [rbp-240]
    lea     r11, [rbp-400]
    WINCALL cf_dw_idx_add, r10, r11, r15, 0, addr a_cf_mf_name, 12
    test    eax, eax
    jnz     csdo_abort_tmp

    ; ---- Emit all DELTA_ITEM records in recArena ----
    mov     r12, qword ptr [rbp-208 + 0]    ; recArena.base
    mov     r13, r12
    add     r13, qword ptr [rbp-208 + 8]    ; recArena.end

csdo_item_lp:
    cmp     r12, r13
    jae     csdo_seal_idx

    mov     eax, dword ptr [r12 + 4]        ; kind
    cmp     eax, 0
    je      csdo_emit_dir
    cmp     eax, 1
    je      csdo_emit_local
    jmp     csdo_emit_moved

csdo_emit_dir:
    ; Directory entry: ustar header carries name + '/', index carries bare name
    mov     ecx, dword ptr [r12 + 16]       ; u8Len
    lea     rsi, [r12 + 64]
    lea     rdi, [rbx + 197440]             ; dirSlashBuf
    rep     movsb
    mov     byte ptr [rdi], '/'
    mov     byte ptr [rdi + 1], 0

    lea     rcx, [rbx + 197440]
    mov     edx, dword ptr [r12 + 16]
    inc     edx
    lea     r8,  [rbx + 197120]
    lea     r9,  [rbx + 197248]
    call    cf_split_ustar
    test    eax, eax
    jnz     csdo_abort_tmp

    lea     r10, [rbx + 196608]
    lea     r11, [rbx + 197120]
    lea     rsi, [rbx + 197248]
    WINCALL tar_build_header, r10, r11, rsi, 0, '5'

    lea     rcx, [rbp-400]
    call    cf_dw_begin
    lea     rcx, [rbp-400]
    lea     rdx, [rbx + 196608]
    mov     r8d, 512
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp
    lea     rcx, [rbp-400]
    call    cf_dw_end
    test    eax, eax
    jnz     csdo_abort_tmp

    lea     r10, [rbp-240]
    lea     r11, [rbp-400]
    lea     rsi, [r12 + 64]
    mov     edi, dword ptr [r12 + 16]
    WINCALL cf_dw_idx_add, r10, r11, 0, IDXEF_DIR, rsi, rdi
    test    eax, eax
    jnz     csdo_abort_tmp
    jmp     csdo_item_next

csdo_emit_local:
    ; Modified placeholder or newly created local file on disk
    mov     eax, dword ptr [r12 + 16]
    add     eax, 2
    and     eax, NOT 1
    lea     r9, [r12 + 64 + rax]            ; wRel
    lea     rcx, [rbx + 131072]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_root_w]
    call    cf_wjoin_bs
    test    eax, eax
    jz      csdo_abort_tmp

    lea     r10, [rbx + 131072]
    WINCALL CreateFileW, r10, CFM_GENERIC_READ, CFM_SHARE_ALL, 0, \
            CFM_OPEN_EXISTING, CFM_ATTR_NORMAL, 0
    cmp     rax, -1
    jne     csdo_have_hin
    ; If transient file vanished/locked during background pass, retry cleanly
    cmp     dword ptr [rbp-72], 0
    jne     csdo_abort_tmp
    mov     dword ptr [rbp-68], 2
    jmp     csdo_abort_tmp_keep_rc

csdo_have_hin:
    mov     qword ptr [rbp-88], rax         ; hIn
    mov     qword ptr [rbp-96], 0
    WINCALL GetFileSizeEx, rax, addr rbp-96
    test    eax, eax
    jz      csdo_abort_tmp

    ; Hydrate any unhydrated ranges on partially-modified placeholders first
    mov     r15, qword ptr [rbp-96]         ; actualSize
    test    r15, r15
    jz      csdo_local_hdr
    mov     r10, qword ptr [pfn_CfGetPlaceholderInfo]
    test    r10, r10
    jz      csdo_local_hdr
    lea     rcx, [rbx + 201600]
    mov     edx, 128
    call    secure_zero
    mov     dword ptr [rbx + 201728], 0
    lea     rsi, [rbx + 201600]
    lea     rdi, [rbx + 201728]
    mov     r10, qword ptr [pfn_CfGetPlaceholderInfo]
    WINCALL r10, qword ptr [rbp-88], 1, rsi, 128, rdi
    test    eax, eax
    js      csdo_local_hdr                  ; ordinary non-placeholder local file
    cmp     qword ptr [rbx + 201600 + 0], r15 ; OnDiskDataSize >= actualSize?
    jae     csdo_local_hdr
    mov     r10, qword ptr [pfn_CfHydratePlaceholder]
    test    r10, r10
    jz      csdo_abort_tmp
    WINCALL r10, qword ptr [rbp-88], 0, -1, 0, 0
    test    eax, eax
    js      csdo_abort_tmp

csdo_local_hdr:
    lea     rcx, [r12 + 64]
    mov     edx, dword ptr [r12 + 16]
    lea     r8,  [rbx + 197120]
    lea     r9,  [rbx + 197248]
    call    cf_split_ustar
    test    eax, eax
    jnz     csdo_abort_tmp

    lea     r10, [rbx + 196608]
    lea     r11, [rbx + 197120]
    lea     rsi, [rbx + 197248]
    WINCALL tar_build_header, r10, r11, rsi, r15, '0'

    lea     rcx, [rbp-400]
    call    cf_dw_begin
    lea     rcx, [rbp-400]
    lea     rdx, [rbx + 196608]
    mov     r8d, 512
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp

    mov     qword ptr [rbp-104], r15        ; remBytes
csdo_local_rd:
    mov     rax, qword ptr [rbp-104]
    test    rax, rax
    jz      csdo_local_pad
    cmp     rax, 10000h
    jbe     @F
    mov     eax, 10000h
@@:
    mov     r14d, eax                       ; chunk
    mov     dword ptr [rbp-120], 0
    lea     r10, [rbx + 65536]
    WINCALL ReadFile, qword ptr [rbp-88], r10, r14d, addr rbp-120, 0
    test    eax, eax
    jz      csdo_abort_tmp
    mov     eax, dword ptr [rbp-120]
    test    eax, eax
    jz      csdo_abort_tmp
    lea     rcx, [rbp-400]
    lea     rdx, [rbx + 65536]
    mov     r8d, eax
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp
    mov     eax, dword ptr [rbp-120]
    sub     qword ptr [rbp-104], rax
    jmp     csdo_local_rd

csdo_local_pad:
    WINCALL CloseHandle, qword ptr [rbp-88]
    mov     qword ptr [rbp-88], -1

    mov     rax, r15
    and     eax, 511
    mov     r8d, 512
    sub     r8d, eax
    and     r8d, 511
    jz      @F
    lea     rcx, [rbp-400]
    lea     rdx, [g_cf_zeros512]
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp
@@:
    lea     rcx, [rbp-400]
    call    cf_dw_end
    test    eax, eax
    jnz     csdo_abort_tmp

    lea     r10, [rbp-240]
    lea     r11, [rbp-400]
    lea     rsi, [r12 + 64]
    mov     edi, dword ptr [r12 + 16]
    WINCALL cf_dw_idx_add, r10, r11, r15, 0, rsi, rdi
    test    eax, eax
    jnz     csdo_abort_tmp
    jmp     csdo_item_next

csdo_emit_moved:
    ; Renamed/moved clean placeholder: stream plaintext directly from g_cf_esctx
    mov     r15, qword ptr [r12 + 8]        ; fileSize
    lea     rcx, [r12 + 64]
    mov     edx, dword ptr [r12 + 16]
    lea     r8,  [rbx + 197120]
    lea     r9,  [rbx + 197248]
    call    cf_split_ustar
    test    eax, eax
    jnz     csdo_abort_tmp

    lea     r10, [rbx + 196608]
    lea     r11, [rbx + 197120]
    lea     rsi, [rbx + 197248]
    WINCALL tar_build_header, r10, r11, rsi, r15, '0'

    lea     rcx, [rbp-400]
    call    cf_dw_begin
    lea     rcx, [rbp-400]
    lea     rdx, [rbx + 196608]
    mov     r8d, 512
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp

    mov     qword ptr [rbp-112], 0          ; readOff = 0
csdo_moved_rd:
    mov     rax, r15
    sub     rax, qword ptr [rbp-112]
    jz      csdo_moved_pad
    cmp     rax, 10000h
    jbe     @F
    mov     eax, 10000h
@@:
    mov     r14d, eax                       ; chunk

    call    cfmount_lock
    mov     rcx, qword ptr [g_cf_esctx]
    test    rcx, rcx
    jz      csdo_moved_unlock_err

    ; Bind & seek g_cf_esctx if needed
    cmp     dword ptr [g_cf_mrk_bound], 0
    je      csdo_moved_bind
    mov     rax, qword ptr [r12 + 24 + IDXE_ordinal]
    cmp     rax, qword ptr [g_cf_mrk_ord]
    jne     csdo_moved_bind
    mov     rax, qword ptr [r12 + 24 + IDXE_offset]
    cmp     rax, qword ptr [g_cf_mrk_off]
    jne     csdo_moved_bind
    mov     rcx, qword ptr [g_cf_esctx]
    call    es_cur_pos
    cmp     rax, qword ptr [rbp-112]
    je      csdo_moved_do_read

csdo_moved_bind:
    mov     dword ptr [g_cf_mrk_bound], 0
    mov     rcx, qword ptr [g_cf_esctx]
    lea     rdx, [r12 + 24]
    lea     r8,  [g_cf_mrk_key]
    call    es_bind
    test    eax, eax
    jnz     csdo_moved_unlock_err
    mov     rax, qword ptr [r12 + 24 + IDXE_ordinal]
    mov     qword ptr [g_cf_mrk_ord], rax
    mov     rax, qword ptr [r12 + 24 + IDXE_offset]
    mov     qword ptr [g_cf_mrk_off], rax
    mov     dword ptr [g_cf_mrk_bound], 1
    cmp     qword ptr [rbp-112], 0
    je      csdo_moved_do_read
    WINCALL ES_Seek, qword ptr [g_cf_esctx], qword ptr [rbp-112], 0, 0
    test    eax, eax
    js      csdo_moved_unlock_err

csdo_moved_do_read:
    mov     dword ptr [rbp-120], 0
    lea     r10, [rbx + 65536]
    WINCALL ES_Read, qword ptr [g_cf_esctx], r10, r14d, addr rbp-120
    mov     esi, eax
    mov     rcx, qword ptr [g_cf_esctx]
    call    es_code
    mov     edi, eax
    call    cfmount_unlock

    test    esi, esi
    js      csdo_abort_tmp
    test    edi, edi
    jnz     csdo_abort_tmp
    cmp     dword ptr [rbp-120], r14d
    jne     csdo_abort_tmp

    lea     rcx, [rbp-400]
    lea     rdx, [rbx + 65536]
    mov     r8d, r14d
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp
    add     qword ptr [rbp-112], r14
    jmp     csdo_moved_rd

csdo_moved_unlock_err:
    mov     dword ptr [g_cf_mrk_bound], 0
    call    cfmount_unlock
    jmp     csdo_abort_tmp

csdo_moved_pad:
    mov     rax, r15
    and     eax, 511
    mov     r8d, 512
    sub     r8d, eax
    and     r8d, 511
    jz      @F
    lea     rcx, [rbp-400]
    lea     rdx, [g_cf_zeros512]
    call    cf_dw_feed
    test    eax, eax
    jnz     csdo_abort_tmp
@@:
    lea     rcx, [rbp-400]
    call    cf_dw_end
    test    eax, eax
    jnz     csdo_abort_tmp

    lea     r10, [rbp-240]
    lea     r11, [rbp-400]
    lea     rsi, [r12 + 64]
    mov     edi, dword ptr [r12 + 16]
    WINCALL cf_dw_idx_add, r10, r11, r15, 0, rsi, rdi
    test    eax, eax
    jnz     csdo_abort_tmp

csdo_item_next:
    mov     eax, dword ptr [r12 + 0]
    add     r12, rax
    jmp     csdo_item_lp

csdo_seal_idx:
    ; ---- Encrypt & append inventory, tag, and 32-byte trailer ----
    mov     dword ptr [rbp-560 + IDXT_flags], 0
    mov     eax, dword ptr [rbp-208 + 72]   ; itemCount
    inc     eax                             ; +1 for .myrkr-delta
    mov     dword ptr [rbp-560 + IDXT_count], eax
    mov     rax, qword ptr [rbp-240 + 8]    ; idxArena.len
    mov     qword ptr [rbp-560 + IDXT_len], rax
    mov     dword ptr [rbp-560 + IDXT_magic], IDX_MAGIC
    mov     dword ptr [rbp-560 + IDXT_rev], 0
    mov     rax, qword ptr [rbp-400 + CFM_DW_ORD]
    mov     qword ptr [rbp-560 + IDXT_next], rax

    mov     rcx, IDX_NONCE_BASE
    lea     rdx, [rbp-688]
    xor     r8d, r8d
    call    nonce_set

    lea     rsi, [rbp-400 + CFM_DW_HDR]
    lea     rdi, [rbp-672]
    mov     ecx, HDR_BYTES
    rep     movsb
    lea     rsi, [rbp-560]
    mov     ecx, IDX_TRAILER_BYTES
    rep     movsb

    lea     r10, [rbp-688]
    WINCALL gcm_init, addr g_cf_dctx, addr g_cf_delta_key, r10, 0
    lea     r10, [rbp-672]
    WINCALL gcm_aad, addr g_cf_dctx, r10, IDX_AAD_BYTES

    mov     r14, qword ptr [rbp-240 + 8]    ; idxArena.len
    test    r14, r14
    jz      csdo_idx_tag
    mov     r10, qword ptr [rbp-240 + 0]    ; idxArena.base
    WINCALL gcm_crypt, addr g_cf_dctx, r10, r10, r14

csdo_idx_tag:
    lea     r10, [rbp-704]
    WINCALL gcm_final, addr g_cf_dctx, r10

    test    r14, r14
    jz      @F
    mov     rcx, qword ptr [rbp-80]
    mov     rdx, qword ptr [rbp-240 + 0]
    mov     r8,  r14
    call    cf_write_all
    test    eax, eax
    jnz     csdo_abort_tmp
@@:
    mov     rcx, qword ptr [rbp-80]
    lea     rdx, [rbp-704]
    mov     r8d, GCM_TAG_LEN
    call    cf_write_all
    test    eax, eax
    jnz     csdo_abort_tmp

    mov     rcx, qword ptr [rbp-80]
    lea     rdx, [rbp-560]
    mov     r8d, IDX_TRAILER_BYTES
    call    cf_write_all
    test    eax, eax
    jnz     csdo_abort_tmp

    WINCALL FlushFileBuffers, qword ptr [rbp-80]
    test    eax, eax
    jz      csdo_abort_tmp

    WINCALL CloseHandle, qword ptr [rbp-80]
    mov     qword ptr [rbp-80], -1

    WINCALL MoveFileExW, addr g_cf_dtmp_w, addr g_cf_delta_w, CFM_MOVE_REPLACE_WT
    test    eax, eax
    jz      csdo_del_tmp_err

    WINCALL SetFileAttributesW, addr g_cf_delta_w, CFM_ATTR_NORMAL
    mov     rax, qword ptr [rbp-208 + 64]
    mov     qword ptr [g_cf_synced_fp], rax
    mov     dword ptr [g_cf_dirty], 1
    mov     dword ptr [rbp-68], 1
    jmp     csdo_cleanup

csdo_abort_tmp:
    mov     dword ptr [rbp-68], -1
csdo_abort_tmp_keep_rc:
    cmp     qword ptr [rbp-88], -1
    je      @F
    WINCALL CloseHandle, qword ptr [rbp-88]
    mov     qword ptr [rbp-88], -1
@@:
    cmp     qword ptr [rbp-80], -1
    je      csdo_del_tmp_only
    WINCALL CloseHandle, qword ptr [rbp-80]
    mov     qword ptr [rbp-80], -1
csdo_del_tmp_only:
    WINCALL DeleteFileW, addr g_cf_dtmp_w
    jmp     csdo_cleanup

csdo_del_tmp_err:
    mov     dword ptr [rbp-68], -1
    WINCALL DeleteFileW, addr g_cf_dtmp_w
    jmp     csdo_cleanup

csdo_ret_zero:
    mov     dword ptr [rbp-68], 0

csdo_cleanup:
    cmp     qword ptr [rbp-88], -1
    je      @F
    WINCALL CloseHandle, qword ptr [rbp-88]
@@:
    cmp     qword ptr [rbp-80], -1
    je      @F
    WINCALL CloseHandle, qword ptr [rbp-80]
@@:
    lea     rcx, [rbp-240]
    call    cf_arena_free
    lea     rcx, [rbp-208 + 0]
    call    cf_arena_free
    lea     rcx, [rbp-208 + 32]
    call    cf_arena_free

    lea     rcx, [g_cf_delta_key]
    mov     edx, KEY_LEN
    call    secure_zero
    lea     rcx, [g_cf_dctx]
    mov     edx, 336
    call    secure_zero

    test    rbx, rbx
    jz      @F
    mov     rcx, rbx
    mov     edx, CFM_SYNC_WORK_BYTES
    call    secure_zero
    WINCALL VirtualFree, rbx, 0, CFM_MEM_RELEASE
@@:
    WINCALL ReleaseSRWLockExclusive, addr g_cf_delta_lock
    mov     eax, dword ptr [rbp-68]

    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     r15, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
cf_sync_delta_once endp

; =============================================================================
; cf_watch_body / cf_watch_thread / cf_stop_watcher
; Recursive ReadDirectoryChangesW + close-completion watcher for R/W .mrk mounts.
; =============================================================================
cf_watch_body proc frame
    FRAME_PROLOG 224
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], r15

    xor     ebx, ebx                        ; chgBuf = 0
    mov     r12, -1                         ; hDir = INVALID
    xor     r13d, r13d                      ; hOvEvt = 0
    mov     r14d, 0FFFFFFFFh                ; waitMs = INFINITE
    xor     r15d, r15d                      ; bit0 = rdcArmed, bit1 = pendingSync

    WINCALL CreateFileW, addr g_cf_root_w, CFM_FILE_LIST_DIR, CFM_SHARE_ALL, 0, \
            CFM_OPEN_EXISTING, CFM_FLAG_OV_BACKUP, 0
    cmp     rax, -1
    je      cwb_out
    mov     r12, rax

    WINCALL CreateEventW, 0, 1, 0, 0
    test    rax, rax
    jz      cwb_close_dir
    mov     r13, rax

    WINCALL VirtualAlloc, 0, 10000h, CFM_MEM_COMMIT_RES, CFM_PAGE_RW
    test    rax, rax
    jz      cwb_close_evt
    mov     rbx, rax

cwb_loop:
    WINCALL WaitForSingleObject, qword ptr [g_cf_stop_evt], 0
    test    eax, eax
    jz      cwb_cleanup

    test    r15d, 1                         ; rdcArmed?
    jnz     cwb_wait

    lea     rcx, [rbp-80]
    mov     edx, 32
    call    secure_zero
    mov     qword ptr [rbp-80 + 24], r13    ; ov.hEvent
    WINCALL ResetEvent, r13
    mov     dword ptr [rbp-120], 0
    lea     r10, [rbp-120]
    lea     r11, [rbp-80]
    WINCALL ReadDirectoryChangesW, r12, rbx, 10000h, 1, CFM_NOTIFY_FILTER, r10, r11, 0
    test    eax, eax
    jz      cwb_wait
    or      r15d, 1                         ; rdcArmed = 1

cwb_wait:
    mov     rax, qword ptr [g_cf_stop_evt]
    mov     qword ptr [rbp-112], rax
    mov     rax, qword ptr [g_cf_wake_evt]
    mov     qword ptr [rbp-104], rax
    mov     qword ptr [rbp-96], r13
    mov     ecx, 2
    test    r15d, 1
    jz      @F
    mov     ecx, 3
@@:
    lea     r10, [rbp-112]
    WINCALL WaitForMultipleObjects, rcx, r10, 0, r14d
    test    eax, eax                        ; 0 = g_cf_stop_evt
    jz      cwb_cleanup
    cmp     eax, 1                          ; 1 = g_cf_wake_evt
    je      cwb_woken
    cmp     eax, 2                          ; 2 = hOvEvt (ReadDirectoryChangesW)
    je      cwb_rdc_done
    cmp     eax, CFM_WAIT_TIMEOUT
    je      cwb_timeout
    jmp     cwb_cleanup

cwb_woken:
    WINCALL ResetEvent, qword ptr [g_cf_wake_evt]
    or      r15d, 2                         ; pendingSync = 1
    mov     r14d, 1000                      ; 1.0 s settle debounce
    jmp     cwb_loop

cwb_rdc_done:
    mov     dword ptr [rbp-120], 0
    lea     r10, [rbp-80]
    lea     r11, [rbp-120]
    WINCALL GetOverlappedResult, r12, r10, r11, 0
    and     r15d, NOT 1                     ; rdcArmed = 0
    or      r15d, 2                         ; pendingSync = 1
    mov     r14d, 1000                      ; 1.0 s settle debounce
    jmp     cwb_loop

cwb_timeout:
    cmp     dword ptr [g_cf_unmounting], 0
    jne     cwb_cleanup
    WINCALL WaitForSingleObject, qword ptr [g_cf_stop_evt], 0
    test    eax, eax
    jz      cwb_cleanup

    xor     ecx, ecx
    call    cf_sync_delta_once
    cmp     eax, 2
    je      cwb_retry_locked

    and     r15d, NOT 2                     ; pendingSync = 0
    mov     r14d, 0FFFFFFFFh                ; INFINITE
    cmp     eax, 1
    jne     cwb_loop
    mov     rcx, qword ptr [g_hwnd]
    test    rcx, rcx
    jz      cwb_loop
    WINCALL PostMessageW, rcx, CFM_WM_DELTASYNC, 0, 0
    jmp     cwb_loop

cwb_retry_locked:
    mov     r14d, 500
    jmp     cwb_loop

cwb_cleanup:
    test    r15d, 1
    jz      @F
    lea     r10, [rbp-80]
    WINCALL CancelIoEx, r12, r10
    mov     dword ptr [rbp-120], 0
    lea     r10, [rbp-80]
    lea     r11, [rbp-120]
    WINCALL GetOverlappedResult, r12, r10, r11, 1
@@:
    WINCALL VirtualFree, rbx, 0, CFM_MEM_RELEASE
cwb_close_evt:
    WINCALL CloseHandle, r13
cwb_close_dir:
    WINCALL CloseHandle, r12

cwb_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     r15, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
cf_watch_body endp

cf_watch_thread proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rbx

    xor     ebx, ebx
    mov     eax, dword ptr [g_sstk_tls]
    test    eax, eax
    jz      cwt_run
    dec     eax
    mov     r10, gs:[rax*8 + TEB_TLS_SLOTS]
    test    r10, r10
    jnz     cwt_run
    call    sstk_thread_init
    mov     ebx, eax

cwt_run:
    call    cf_watch_body
    test    ebx, ebx
    jz      cwt_done
    call    sstk_thread_free

cwt_done:
    xor     eax, eax
    mov     rbx, qword ptr [rbp-8]
    mov     rsp, rbp
    pop     rbp
    ret
cf_watch_thread endp

cf_stop_watcher proc frame
    FRAME_PROLOG 64
    mov     rcx, qword ptr [g_cf_stop_evt]
    test    rcx, rcx
    jz      @F
    WINCALL SetEvent, rcx
@@:
    mov     rcx, qword ptr [g_cf_watch_th]
    test    rcx, rcx
    jz      @F
    WINCALL WaitForSingleObject, rcx, 0FFFFFFFFh
    WINCALL CloseHandle, qword ptr [g_cf_watch_th]
    mov     qword ptr [g_cf_watch_th], 0
@@:
    mov     rcx, qword ptr [g_cf_stop_evt]
    test    rcx, rcx
    jz      @F
    WINCALL CloseHandle, rcx
    mov     qword ptr [g_cf_stop_evt], 0
@@:
    mov     rcx, qword ptr [g_cf_wake_evt]
    test    rcx, rcx
    jz      @F
    WINCALL CloseHandle, rcx
    mov     qword ptr [g_cf_wake_evt], 0
@@:
    FRAME_EPILOG
    ret
cf_stop_watcher endp

; =============================================================================
; cfmount_prepare_commit() -> eax:
;   0 = clean or Read-Only mount (already unmounted & cleaned up)
;   1 = R/W mount has unmerged changes (drive letter unmapped, watcher stopped;
;       caller should run cfmount_finish_commit + merge_delta_mrk under UI busy)
; =============================================================================
public cfmount_prepare_commit
cfmount_prepare_commit proc frame
    FRAME_PROLOG 176
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12

    mov     dword ptr [g_cf_commit_state], 0
    cmp     dword ptr [g_cf_mounted], 0
    je      cmpc_zero
    cmp     dword ptr [g_cf_is_rw], 0
    jne     cmpc_rw
    call    cfmount_unmount
    jmp     cmpc_zero

cmpc_rw:
    ; Unmap drive letter first so external processes cannot start new writes
    cmp     dword ptr [g_cf_letter], 0
    je      @F
    WINCALL DefineDosDeviceW, <CFM_DDD_REMOVE or CFM_DDD_EXACT_MATCH>, addr g_cf_drv_colon, addr g_cf_root_w
    WINCALL SHChangeNotify, CFM_SHCNE_DRIVEREMOVED, CFM_SHCNF_PATHW, addr g_cf_drv_slash, 0
    mov     dword ptr [g_cf_letter], 0
@@:
    call    cf_stop_watcher

    WINCALL AcquireSRWLockExclusive, addr g_cf_delta_lock
    lea     rcx, [rbp-128]                  ; diffCtx (88 B)
    call    cf_collect_diff
    mov     ebx, eax                        ; diffErr
    mov     r12, qword ptr [rbp-128 + 64]   ; fp64
    mov     eax, dword ptr [rbp-128 + 72]   ; itemCount
    or      eax, dword ptr [rbp-128 + 76]   ; delCount
    mov     dword ptr [rbp-32], eax         ; hasChanges

    lea     rcx, [rbp-128 + 0]
    call    cf_arena_free
    lea     rcx, [rbp-128 + 32]
    call    cf_arena_free
    WINCALL ReleaseSRWLockExclusive, addr g_cf_delta_lock

    test    ebx, ebx
    js      cmpc_need_sync
    cmp     dword ptr [rbp-32], 0
    jne     cmpc_dirty

    ; Zero net changes on Z: -> remove any reverted .delta.mrk & fast-unmount
    cmp     dword ptr [g_cf_dirty], 0
    je      @F
    WINCALL DeleteFileW, addr g_cf_delta_w
    mov     dword ptr [g_cf_dirty], 0
@@:
    cmp     dword ptr [g_cfg_passlen], 0
    jne     @F
    mov     eax, dword ptr [g_cf_passlen]
    test    eax, eax
    jz      @F
    mov     dword ptr [g_cfg_passlen], eax
    lea     r8, [g_cf_pass]
    lea     r9, [g_cfg_pass]
    xor     edx, edx
cmpc_cp_pw:
    mov     al, byte ptr [r8 + rdx]
    mov     byte ptr [r9 + rdx], al
    inc     edx
    cmp     edx, MAX_PASSWORD_BYTES + 1
    jb      cmpc_cp_pw
@@:
    call    cfmount_unmount
    jmp     cmpc_zero

cmpc_dirty:
    cmp     dword ptr [g_cf_dirty], 0
    je      cmpc_need_sync
    cmp     r12, qword ptr [g_cf_synced_fp]
    jne     cmpc_need_sync
    WINCALL GetFileAttributesW, addr g_cf_delta_w
    cmp     eax, CFM_INV_ATTR
    je      cmpc_need_sync

    mov     dword ptr [g_cf_commit_state], 1
    mov     eax, 1
    jmp     cmpc_out

cmpc_need_sync:
    mov     dword ptr [g_cf_commit_state], 2
    mov     eax, 1
    jmp     cmpc_out

cmpc_zero:
    xor     eax, eax

cmpc_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
cfmount_prepare_commit endp

; =============================================================================
; cfmount_finish_commit(rcx = outDeltaPathW, edx = capChars) -> eax:
;   0  = <stem>.delta.mrk flushed on disk, mount torn down, g_cfg_pass ready
;  -1  = failed to write <stem>.delta.mrk (mount still torn down cleanly)
; =============================================================================
public cfmount_finish_commit
cfmount_finish_commit proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    lea     r8, [g_cf_delta_w]
    xor     r9d, r9d
    call    cf_wcopy_cat
    test    eax, eax
    jz      cmfc_err_unmount

    cmp     dword ptr [g_cf_commit_state], 2
    jne     cmfc_restore_pw
    mov     ecx, 1
    call    cf_sync_delta_once
    test    eax, eax
    js      cmfc_err_unmount

cmfc_restore_pw:
    ; Ensure g_cfg_pass holds the session password (od_restore may have wiped it)
    mov     eax, dword ptr [g_cf_passlen]
    test    eax, eax
    jz      cmfc_unmount
    mov     dword ptr [g_cfg_passlen], eax
    lea     rsi, [g_cf_pass]
    lea     rdi, [g_cfg_pass]
    mov     ecx, MAX_PASSWORD_BYTES + 1
    rep     movsb

cmfc_unmount:
    call    cfmount_unmount
    xor     eax, eax
    jmp     cmfc_out

cmfc_err_unmount:
    call    cfmount_unmount
    mov     eax, -1

cmfc_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
cfmount_finish_commit endp

; =============================================================================
; cfmount_mount(rcx = containerPathW, edx = modeFlags) -> eax = 'D'..'Z' or 0
;   modeFlags bit 0 (1): 1 = TrueCrypt/VeraCrypt, 0 = native .mrk
;   modeFlags bit 1 (2): 1 = mount Read/Write (.mrk with <stem>.delta.mrk sidecar)
; =============================================================================
public cfmount_mount
cfmount_mount proc frame
    FRAME_PROLOG 208
    ; [rbp-16]=rbx, [rbp-24]=r12, [rbp-32]=r13, [rbp-40]=r14, [rbp-48]=rsi, [rbp-56]=rdi
    ; [rbp-136 .. -65] = CF_SYNC_REGISTRATION (72 bytes)
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], r14
    mov     qword ptr [rbp-48], rsi
    mov     qword ptr [rbp-56], rdi

    mov     r12, rcx                        ; containerPathW
    mov     r14d, edx                       ; modeFlags
    mov     r13d, edx
    and     r13d, 1                         ; isTcvc

    call    cfmount_unmount

    call    cf_init_procs
    test    eax, eax
    jz      cmm_fail

    mov     ecx, 1                          ; create %LOCALAPPDATA%\Myrkr\Mounts
    call    cf_get_mounts_base
    test    eax, eax
    jz      cmm_fail

    ; Pick highest free drive letter 'Z' down to 'D' before allocating resources
    WINCALL GetLogicalDrives
    test    eax, eax
    jz      cmm_fail
    mov     edx, eax
    mov     ebx, 'Z'
cmm_pick_drv:
    mov     ecx, ebx
    sub     ecx, 'A'
    bt      edx, ecx
    jnc     cmm_have_drv
    dec     ebx
    cmp     ebx, 'D'
    jae     cmm_pick_drv
    jmp     cmm_fail

cmm_have_drv:
    ; Generate 8-byte random session magic and format 16-hex-char folder name
    lea     rcx, [g_cf_session_magic]
    mov     edx, 8
    call    rng_fill
    test    eax, eax
    jz      cmm_fail

    ; Build "\0123456789abcdef" in g_cf_rel_w
    lea     rdi, [g_cf_rel_w]
    mov     word ptr [rdi], '\'
    add     rdi, 2
    lea     rsi, [g_cf_session_magic]
    lea     r10, [a_cf_hex]
    mov     ecx, 8
cmm_hex_lp:
    movzx   eax, byte ptr [rsi]
    mov     edx, eax
    shr     eax, 4
    and     edx, 0Fh
    movzx   eax, byte ptr [r10 + rax]
    mov     word ptr [rdi], ax
    movzx   edx, byte ptr [r10 + rdx]
    mov     word ptr [rdi + 2], dx
    inc     rsi
    add     rdi, 4
    dec     ecx
    jnz     cmm_hex_lp
    mov     word ptr [rdi], 0

    lea     rcx, [g_cf_root_w]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_base_w]
    lea     r9,  [g_cf_rel_w]
    call    cf_wcopy_cat
    test    eax, eax
    jz      cmm_fail

    lea     rcx, [g_cf_lock_w]
    mov     edx, MAX_PATH_CHARS
    lea     r8,  [g_cf_root_w]
    lea     r9,  [w_cf_lock_ext]
    call    cf_wcopy_cat
    test    eax, eax
    jz      cmm_fail

    ; Acquire exclusive DELETE_ON_CLOSE session lockfile
    WINCALL CreateFileW, addr g_cf_lock_w, CFM_GENERIC_RW, 0, 0, \
            CFM_CREATE_ALWAYS, CFM_FLAG_DEL_CLOSE, 0
    cmp     rax, -1
    je      cmm_fail
    mov     qword ptr [g_cf_hlock], rax

    WINCALL CreateDirectoryW, addr g_cf_root_w, 0
    test    eax, eax
    jz      cmm_fail_lock
    WINCALL SetFileAttributesW, addr g_cf_root_w, CFM_ATTR_NOT_INDEXED

    ; Allocate 256 KiB transfer buffer
    WINCALL VirtualAlloc, 0, CFM_CHUNK_BYTES, CFM_MEM_COMMIT_RES, CFM_PAGE_RW
    test    rax, rax
    jz      cmm_fail_dir
    mov     qword ptr [g_cf_xfer_buf], rax

    ; Prepare container backend state (.mrk vs .tc/.hc)
    mov     dword ptr [g_cf_is_tcvc], r13d
    mov     dword ptr [g_cf_is_rw], 0
    mov     dword ptr [g_cf_dirty], 0
    mov     dword ptr [g_cf_commit_state], 0
    mov     qword ptr [g_cf_synced_fp], 0
    mov     dword ptr [g_cf_mrk_bound], 0
    mov     qword ptr [g_cf_esctx], 0
    test    r13d, r13d
    jnz     cmm_reg_sync

    ; Native .mrk: copy 32-byte container key and open private estream context
    lea     rsi, [g_key]
    lea     rdi, [g_cf_mrk_key]
    mov     ecx, KEY_LEN
    rep     movsb

    mov     rcx, r12
    call    es_new
    test    rax, rax
    jz      cmm_fail_backend
    mov     qword ptr [g_cf_esctx], rax

    ; Enable R/W overlay when requested and supported
    test    r14d, 2
    jz      cmm_reg_sync
    cmp     qword ptr [pfn_CfGetPlaceholderInfo], 0
    je      cmm_reg_sync
    cmp     qword ptr [pfn_CfHydratePlaceholder], 0
    je      cmm_reg_sync
    cmp     dword ptr [g_cfg_passlen], 0
    je      cmm_reg_sync
    cmp     qword ptr [g_idxptr], 0
    je      cmm_reg_sync

    mov     rcx, r12
    lea     rdx, [g_cf_delta_w]
    mov     r8d, MAX_PATH_CHARS
    call    delta_path_for
    test    eax, eax
    jz      cmm_reg_sync

    ; Snapshot base header, password, and base inventory
    lea     rsi, [g_pkhdr]
    lea     rdi, [g_cf_base_hdr]
    mov     ecx, HDR_BYTES
    rep     movsb

    mov     eax, dword ptr [g_cfg_passlen]
    mov     dword ptr [g_cf_passlen], eax
    lea     rsi, [g_cfg_pass]
    lea     rdi, [g_cf_pass]
    mov     ecx, MAX_PASSWORD_BYTES + 1
    rep     movsb

    mov     rcx, qword ptr [g_idxlen]
    cmp     rcx, 16
    jae     @F
    mov     ecx, 16
@@:
    call    mem_alloc
    test    rax, rax
    jz      cmm_reg_sync
    mov     qword ptr [g_cf_base_idx], rax
    mov     rcx, qword ptr [g_idxlen]
    mov     qword ptr [g_cf_base_idxlen], rcx
    mov     rdx, qword ptr [g_idxcount]
    mov     qword ptr [g_cf_base_idxcnt], rdx
    mov     rdi, rax
    mov     rsi, qword ptr [g_idxptr]
    rep     movsb

    ; Strip transient in-memory bits from snapshot flags (retain only IDXEF_DIR)
    mov     rsi, qword ptr [g_cf_base_idx]
    mov     rdi, rsi
    add     rdi, qword ptr [g_cf_base_idxlen]
    mov     rcx, qword ptr [g_cf_base_idxcnt]
cmm_clean_idx:
    test    rcx, rcx
    jz      cmm_rw_ready
    lea     rax, [rsi + IDXE_FIXED]
    cmp     rax, rdi
    ja      cmm_rw_ready
    mov     eax, dword ptr [rsi + IDXE_namelen]
    lea     rdx, [rsi + IDXE_FIXED + rax]
    cmp     rdx, rdi
    ja      cmm_rw_ready
    and     dword ptr [rsi + IDXE_flags], IDXEF_DIR
    mov     rsi, rdx
    dec     rcx
    jmp     cmm_clean_idx

cmm_rw_ready:
    mov     dword ptr [g_cf_is_rw], 1

cmm_reg_sync:
    mov     dword ptr [g_cf_unmounting], 0
    mov     word ptr [g_cf_last_hyd_w], 0

    ; Build CF_SYNC_REGISTRATION (72 bytes at [rbp-136 .. -65])
    lea     rcx, [rbp-136]
    mov     edx, 72
    call    secure_zero
    mov     dword ptr [rbp-136 + 0], 72
    lea     rax, [w_cf_prov_name]
    mov     qword ptr [rbp-136 + 8], rax
    lea     rax, [w_cf_prov_ver]
    mov     qword ptr [rbp-136 + 16], rax
    lea     rax, [g_cf_session_magic]
    mov     qword ptr [rbp-136 + 24], rax
    mov     dword ptr [rbp-136 + 32], 8
    lea     rsi, [cf_provider_guid]
    lea     rdi, [rbp-136 + 52]
    mov     ecx, 16
    rep     movsb

    lea     r11, [cf_sync_policies]
    cmp     dword ptr [g_cf_is_rw], 0
    je      @F
    lea     r11, [cf_sync_policies_rw]
@@:
    lea     rsi, [rbp-136]
    mov     r10, qword ptr [pfn_CfRegisterSyncRoot]
    WINCALL r10, addr g_cf_root_w, rsi, r11, CFM_REG_FLAGS
    test    eax, eax
    js      cmm_fail_backend

    mov     qword ptr [g_cf_conn_key], 0
    mov     r10, qword ptr [pfn_CfConnectSyncRoot]
    WINCALL r10, addr g_cf_root_w, addr cf_callback_table, 0, \
            CFM_CONNECT_FLAGS, addr g_cf_conn_key
    test    eax, eax
    js      cmm_fail_unreg

    call    cf_populate_placeholders
    test    eax, eax
    jz      cmm_fail_disconn

    ; Map session drive letter (re-probing downward if another app took ebx)
cmm_map_loop:
    mov     word ptr [g_cf_drv_colon + 0], bx
    mov     word ptr [g_cf_drv_colon + 2], ':'
    mov     word ptr [g_cf_drv_colon + 4], 0

    mov     word ptr [g_cf_drv_slash + 0], bx
    mov     word ptr [g_cf_drv_slash + 2], ':'
    mov     word ptr [g_cf_drv_slash + 4], '\'
    mov     word ptr [g_cf_drv_slash + 6], 0

    WINCALL DefineDosDeviceW, 0, addr g_cf_drv_colon, addr g_cf_root_w
    test    eax, eax
    jnz     cmm_mapped

    dec     ebx
    cmp     ebx, 'D'
    jb      cmm_fail_disconn
    WINCALL GetLogicalDrives
    mov     ecx, ebx
    sub     ecx, 'A'
    bt      eax, ecx
    jc      cmm_next_drv
    jmp     cmm_map_loop
cmm_next_drv:
    dec     ebx
    cmp     ebx, 'D'
    jae     cmm_map_loop
    jmp     cmm_fail_disconn

cmm_mapped:
    mov     dword ptr [g_cf_letter], ebx
    mov     dword ptr [g_cf_mounted], 1

    ; Start background directory watcher for R/W .mrk mounts
    cmp     dword ptr [g_cf_is_rw], 0
    je      cmm_notify
    WINCALL CreateEventW, 0, 1, 0, 0
    mov     qword ptr [g_cf_stop_evt], rax
    WINCALL CreateEventW, 0, 1, 0, 0
    mov     qword ptr [g_cf_wake_evt], rax
    cmp     qword ptr [g_cf_stop_evt], 0
    je      cmm_notify
    cmp     qword ptr [g_cf_wake_evt], 0
    je      cmm_notify
    WINCALL CreateThread, 0, 0, addr cf_watch_thread, 0, 0, 0
    mov     qword ptr [g_cf_watch_th], rax

cmm_notify:
    WINCALL SHChangeNotify, CFM_SHCNE_DRIVEADD, CFM_SHCNF_PATHW, addr g_cf_drv_slash, 0
    mov     eax, ebx
    jmp     cmm_out

cmm_fail_disconn:
    mov     dword ptr [g_cf_unmounting], 1
    mov     r10, qword ptr [pfn_CfDisconnectSyncRoot]
    WINCALL r10, qword ptr [g_cf_conn_key]
    mov     qword ptr [g_cf_conn_key], 0
cmm_fail_unreg:
    mov     r10, qword ptr [pfn_CfUnregisterSyncRoot]
    WINCALL r10, addr g_cf_root_w
cmm_fail_backend:
    mov     rcx, qword ptr [g_cf_base_idx]
    test    rcx, rcx
    jz      @F
    mov     rdx, qword ptr [g_cf_base_idxlen]
    cmp     rdx, 16
    jae     cmm_fb_idx_sz
    mov     edx, 16
cmm_fb_idx_sz:
    call    mem_free
    mov     qword ptr [g_cf_base_idx], 0
    mov     qword ptr [g_cf_base_idxlen], 0
    mov     qword ptr [g_cf_base_idxcnt], 0
@@:
    lea     rcx, [g_cf_base_hdr]
    mov     edx, HDR_BYTES
    call    secure_zero
    lea     rcx, [g_cf_pass]
    mov     edx, MAX_PASSWORD_BYTES + 1
    call    secure_zero
    mov     dword ptr [g_cf_passlen], 0
    mov     dword ptr [g_cf_is_rw], 0

    mov     rcx, qword ptr [g_cf_esctx]
    test    rcx, rcx
    jz      @F
    call    es_destroy
    mov     qword ptr [g_cf_esctx], 0
@@:
    lea     rcx, [g_cf_mrk_key]
    mov     edx, KEY_LEN
    call    secure_zero
    mov     rcx, qword ptr [g_cf_xfer_buf]
    test    rcx, rcx
    jz      cmm_fail_dir
    WINCALL VirtualFree, rcx, 0, CFM_MEM_RELEASE
    mov     qword ptr [g_cf_xfer_buf], 0
cmm_fail_dir:
    lea     rcx, [g_cf_root_w]
    call    cf_wipe_and_rm_tree
cmm_fail_lock:
    mov     rcx, qword ptr [g_cf_hlock]
    cmp     rcx, -1
    je      @F
    test    rcx, rcx
    jz      @F
    WINCALL CloseHandle, rcx
@@:
    mov     qword ptr [g_cf_hlock], 0
cmm_fail:
    xor     eax, eax

cmm_out:
    mov     rbx, qword ptr [rbp-16]
    mov     r12, qword ptr [rbp-24]
    mov     r13, qword ptr [rbp-32]
    mov     r14, qword ptr [rbp-40]
    mov     rsi, qword ptr [rbp-48]
    mov     rdi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
cfmount_mount endp

; =============================================================================
; cfmount_unmount()
; =============================================================================
public cfmount_unmount
cfmount_unmount proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_cf_mounted], 0
    je      cmu_out

    ; Stop R/W directory watcher before setting unmounting state
    call    cf_stop_watcher

    ; Best-effort synchronous dehydration of last accessed file before disconnect
    cmp     word ptr [g_cf_last_hyd_w], 0
    je      @F
    lea     rcx, [g_cf_last_hyd_w]
    xor     edx, edx
    call    cf_dehydrate_one
    mov     word ptr [g_cf_last_hyd_w], 0
@@:
    mov     dword ptr [g_cf_unmounting], 1
    mov     dword ptr [g_cf_mounted], 0

    ; Remove session DOS drive mapping and notify shell (if still mapped)
    cmp     dword ptr [g_cf_letter], 0
    je      @F
    WINCALL DefineDosDeviceW, <CFM_DDD_REMOVE or CFM_DDD_EXACT_MATCH>, addr g_cf_drv_colon, addr g_cf_root_w
    WINCALL SHChangeNotify, CFM_SHCNE_DRIVEREMOVED, CFM_SHCNF_PATHW, addr g_cf_drv_slash, 0
    mov     dword ptr [g_cf_letter], 0
@@:
    ; Disconnect callbacks and unregister sync root
    mov     r10, qword ptr [pfn_CfDisconnectSyncRoot]
    test    r10, r10
    jz      @F
    WINCALL r10, qword ptr [g_cf_conn_key]
@@:
    mov     qword ptr [g_cf_conn_key], 0

    mov     r10, qword ptr [pfn_CfUnregisterSyncRoot]
    test    r10, r10
    jz      @F
    WINCALL r10, addr g_cf_root_w
@@:
    ; Drain any in-flight threadpool dehydration callbacks
cmu_wait_tp:
    cmp     dword ptr [g_cf_dehyd_inflight], 0
    je      cmu_tp_drained
    WINCALL Sleep, 5
    jmp     cmu_wait_tp

cmu_tp_drained:
    call    cfmount_lock

    call    cf_free_ent_cache

    mov     rcx, qword ptr [g_cf_esctx]
    test    rcx, rcx
    jz      @F
    call    es_destroy
    mov     qword ptr [g_cf_esctx], 0
@@:
    mov     dword ptr [g_cf_mrk_bound], 0

    mov     rcx, qword ptr [g_cf_base_idx]
    test    rcx, rcx
    jz      @F
    mov     rdx, qword ptr [g_cf_base_idxlen]
    cmp     rdx, 16
    jae     cmu_bidx_sz
    mov     edx, 16
cmu_bidx_sz:
    call    mem_free
    mov     qword ptr [g_cf_base_idx], 0
    mov     qword ptr [g_cf_base_idxlen], 0
    mov     qword ptr [g_cf_base_idxcnt], 0
@@:
    lea     rcx, [g_cf_base_hdr]
    mov     edx, HDR_BYTES
    call    secure_zero
    lea     rcx, [g_cf_pass]
    mov     edx, MAX_PASSWORD_BYTES + 1
    call    secure_zero
    lea     rcx, [g_cf_delta_key]
    mov     edx, KEY_LEN
    call    secure_zero
    lea     rcx, [g_cf_dctx]
    mov     edx, 336
    call    secure_zero
    mov     dword ptr [g_cf_passlen], 0
    mov     dword ptr [g_cf_is_rw], 0
    mov     dword ptr [g_cf_dirty], 0
    mov     dword ptr [g_cf_commit_state], 0
    mov     qword ptr [g_cf_synced_fp], 0

    lea     rcx, [g_cf_mrk_key]
    mov     edx, KEY_LEN
    call    secure_zero
    lea     rcx, [g_cf_session_magic]
    mov     edx, 8
    call    secure_zero

    mov     rcx, qword ptr [g_cf_xfer_buf]
    test    rcx, rcx
    jz      @F
    mov     edx, CFM_CHUNK_BYTES
    call    secure_zero
    WINCALL VirtualFree, qword ptr [g_cf_xfer_buf], 0, CFM_MEM_RELEASE
    mov     qword ptr [g_cf_xfer_buf], 0
@@:
    call    cfmount_unlock

    ; Wipe any remaining hydrated clusters and remove sync-root directory tree
    cmp     word ptr [g_cf_root_w], 0
    je      @F
    lea     rcx, [g_cf_root_w]
    call    cf_wipe_and_rm_tree
    mov     word ptr [g_cf_root_w], 0
@@:
    ; Release DELETE_ON_CLOSE session lockfile last
    mov     rcx, qword ptr [g_cf_hlock]
    test    rcx, rcx
    jz      @F
    cmp     rcx, -1
    je      @F
    WINCALL CloseHandle, rcx
@@:
    mov     qword ptr [g_cf_hlock], 0

cmu_out:
    FRAME_EPILOG
    ret
cfmount_unmount endp

; =============================================================================
; cfmount_unmount_if_tcvc() - safety hook called by tcvc_close
; =============================================================================
public cfmount_unmount_if_tcvc
cfmount_unmount_if_tcvc proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_cf_mounted], 0
    je      @F
    cmp     dword ptr [g_cf_is_tcvc], 0
    je      @F
    call    cfmount_unmount
@@:
    FRAME_EPILOG
    ret
cfmount_unmount_if_tcvc endp

; =============================================================================
; cfmount_open_explorer() - opens mounted "<Letter>:\" in File Explorer
; =============================================================================
public cfmount_open_explorer
cfmount_open_explorer proc frame
    FRAME_PROLOG 64
    cmp     dword ptr [g_cf_mounted], 0
    je      cmoe_out
    WINCALL ShellExecuteW, 0, addr w_cf_explore, addr g_cf_drv_slash, 0, 0, CFM_SW_SHOWNORMAL
cmoe_out:
    FRAME_EPILOG
    ret
cfmount_open_explorer endp

end
