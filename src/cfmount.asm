; =============================================================================
; cfmount.asm - User-Mode Read-Only Drive Mounting via Windows Cloud Files API
; -----------------------------------------------------------------------------
; Mounts unlocked TrueCrypt/VeraCrypt (.tc/.hc) and native Myrkr (.mrk)
; containers as standard session-scoped Windows drive letters (Z: downward)
; with zero elevation and zero kernel driver installation:
;   1. Creates an isolated sync-root directory under %LOCALAPPDATA%\Myrkr\Mounts
;      (marked FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, without EFS so Windows never
;      nags to back up an EFS certificate) plus
;      an exclusive DELETE_ON_CLOSE lockfile so concurrent Myrkr windows never
;      disturb live mounts while crashed mounts are swept on next startup.
;   2. Registers the sync root via cldapi.dll (loaded dynamically from System32)
;      and populates read-only placeholders carrying a self-contained 48-byte
;      FileIdentity ([8B CSPRNG session magic] || [40B INDEX_ENTRY header]).
;   3. Serves on-demand FetchData callbacks in 256 KiB chunks under an SRWLock,
;      authenticating .mrk GCM tags fail-closed before returning plaintext and
;      streaming .tc/.hc ranges with early stop via tcvc_read_range.
;   4. Automatically dehydrates placeholders back to 0 on-disk bytes upon
;      NOTIFY_FILE_CLOSE_COMPLETION, LRU file switch, and unmount.
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
extern WriteFile:proc
extern CloseHandle:proc
extern DeleteFileW:proc
extern GetFileAttributesW:proc
extern SetFileAttributesW:proc
extern GetCompressedFileSizeW:proc
extern FindFirstFileW:proc
extern FindNextFileW:proc
extern FindClose:proc
extern MultiByteToWideChar:proc
extern CompareStringOrdinal:proc
extern GetLogicalDrives:proc
extern DefineDosDeviceW:proc
extern QueryDosDeviceW:proc
extern TrySubmitThreadpoolCallback:proc
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
extern es_new:proc
extern es_bind:proc
extern es_cur_pos:proc
extern es_code:proc
extern es_destroy:proc
extern ES_Read:proc
extern ES_Seek:proc

externdef g_sstk_tls:dword
externdef g_key:byte
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
CFM_PCI_MARK_INSYNC     equ 2           ; CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
CFM_DEHYD_BG            equ 1           ; CF_DEHYDRATE_FLAG_BACKGROUND
CFM_STATUS_UNSUCCESSFUL equ 0C0000001h
CFM_STATUS_CHECKSUM_ERR equ 0C0000242h

.const
align 2
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
a_cf_hex                db "0123456789abcdef"

align 8
; CF_SYNC_POLICIES (24 bytes)
; Population MUST be CF_POPULATION_POLICY_ALWAYS_FULL (3), NOT FULL (2):
; FULL (2) causes cldflt.sys to block FindFirstFile / Explorer directory
; enumeration waiting for CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, whereas
; ALWAYS_FULL (3) tells cldflt.sys the entire tree is already populated locally.
cf_sync_policies label byte
    dd 24                               ; StructSize
    dw 0                                ; CF_HYDRATION_POLICY_PARTIAL
    dw 6                                ; STREAMING_ALLOWED(2) | AUTO_DEHYDRATION_ALLOWED(4)
    dw CFM_POP_ALWAYS_FULL              ; CF_POPULATION_POLICY_ALWAYS_FULL (3)
    dw 0                                ; Population.Modifier
    dd 0                                ; CF_INSYNC_POLICY_NONE
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
g_cf_mrk_key            db KEY_LEN dup (?)

align 8
g_cf_lock               dq ?            ; SRWLOCK (0-initialized = SRWLOCK_INIT)
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

g_cf_conn_key           dq ?
g_cf_session_magic      dq ?
g_cf_mount_ft           dq ?
g_cf_hlock              dq ?
g_cf_xfer_buf           dq ?
g_cf_esctx              dq ?
g_cf_mrk_ord            dq ?
g_cf_mrk_off            dq ?

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
    FRAME_PROLOG 96
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

    mov     r10, qword ptr [pfn_CfDehydrate]
    WINCALL r10, qword ptr [rbp-48], 0, -1, CFM_DEHYD_BG, 0
    mov     dword ptr [rbp-52], eax         ; hr

    mov     r10, qword ptr [pfn_CfCloseHandle]
    WINCALL r10, qword ptr [rbp-40]

    cmp     dword ptr [rbp-52], 0
    jge     cdo_ok

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
    test    dword ptr [rdx + 8], 1          ; CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED
    jnz     cccc_ret
    cmp     qword ptr [rcx + 32], 0         ; VolumeDosName
    je      cccc_ret
    cmp     qword ptr [rcx + 104], 0        ; NormalizedPath
    je      cccc_ret

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
    mov     rcx, qword ptr [rbp-16]
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

    ; Compute 4096-aligned [curOff, endOff) clamped to fileSize
    mov     r14, qword ptr [r13 + 16]       ; RequiredFileOffset
    mov     rax, qword ptr [r13 + 24]       ; RequiredLength
    add     rax, r14                        ; reqEnd
    jc      cfb_fail_unavail
    and     r14, -4096                      ; curOff = align_down(reqOff, 4096)

    mov     rcx, qword ptr [rbp-72]         ; fileSize
    cmp     rax, rcx
    jbe     @F
    mov     rax, rcx
@@:
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
    mov     dword ptr [g_cf_pci + 40], CFM_ATTR_READONLY
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
; cfmount_mount(rcx = containerPathW, edx = isTcvc) -> eax = 'D'..'Z' or 0
; =============================================================================
public cfmount_mount
cfmount_mount proc frame
    FRAME_PROLOG 176
    ; [rbp-16]=rbx, [rbp-24]=r12, [rbp-32]=r13, [rbp-40]=rsi, [rbp-48]=rdi
    ; [rbp-128 .. -57] = CF_SYNC_REGISTRATION (72 bytes)
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], r12
    mov     qword ptr [rbp-32], r13
    mov     qword ptr [rbp-40], rsi
    mov     qword ptr [rbp-48], rdi

    mov     r12, rcx                        ; containerPathW
    mov     r13d, edx                       ; isTcvc

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

cmm_reg_sync:
    mov     dword ptr [g_cf_unmounting], 0
    mov     word ptr [g_cf_last_hyd_w], 0

    ; Build CF_SYNC_REGISTRATION (72 bytes at [rbp-128 .. -57])
    lea     rcx, [rbp-128]
    mov     edx, 72
    call    secure_zero
    mov     dword ptr [rbp-128 + 0], 72
    lea     rax, [w_cf_prov_name]
    mov     qword ptr [rbp-128 + 8], rax
    lea     rax, [w_cf_prov_ver]
    mov     qword ptr [rbp-128 + 16], rax
    lea     rax, [g_cf_session_magic]
    mov     qword ptr [rbp-128 + 24], rax
    mov     dword ptr [rbp-128 + 32], 8
    lea     rsi, [cf_provider_guid]
    lea     rdi, [rbp-128 + 52]
    mov     ecx, 16
    rep     movsb

    mov     r10, qword ptr [pfn_CfRegisterSyncRoot]
    WINCALL r10, addr g_cf_root_w, addr rbp-128, addr cf_sync_policies, CFM_REG_FLAGS
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
    mov     rsi, qword ptr [rbp-40]
    mov     rdi, qword ptr [rbp-48]
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

    ; Remove session DOS drive mapping and notify shell
    WINCALL DefineDosDeviceW, <CFM_DDD_REMOVE or CFM_DDD_EXACT_MATCH>, addr g_cf_drv_colon, addr g_cf_root_w
    WINCALL SHChangeNotify, CFM_SHCNE_DRIVEREMOVED, CFM_SHCNF_PATHW, addr g_cf_drv_slash, 0
    mov     dword ptr [g_cf_letter], 0

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
