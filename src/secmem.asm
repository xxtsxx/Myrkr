; =============================================================================
; secmem.asm - locked (non-pageable) secret memory
; -----------------------------------------------------------------------------
; Every buffer that ever holds the master password or a derived key is pinned
; with VirtualLock, so the kernel may not write it to the pagefile or into a
; hibernation image.  Wiping alone is not enough: secure_zero clears the live
; copy, but a page evicted to disk *before* the wipe leaves a copy the process
; can no longer reach, and that copy outlives the process.
;
; Ported from Vordr, where the same buffers are locked and the audit lives in
; docs/SECRETS.md.
;
; Registered here:
;   g_cfg_pass  (main.asm) - the master password, UTF-8, MAX_PASSWORD_BYTES+1
;   g_key       (cmd.asm)  - the Argon2id-derived 32-byte file key
;
; NOT covered, deliberately:
;   * The Argon2 arena (default 512 MiB).  It holds key-derivation state, but a
;     half-gigabyte lock is far beyond any sane working-set quota, and failing
;     the lock would take the whole feature down with it.  argon2.asm already
;     secure_zero's the arena before releasing it.
;   * GCM round keys in TRANSIENT cipher contexts: the estream objects (heap,
;     wiped by tagged_free) and the one-shot gcm_seal/gcm_open stack frames
;     (wiped before return).  The two GLOBAL contexts - g_pkctx, g_gctx - ARE
;     registered below, since they persist between operations.
;
; Failure policy: locking is defense in depth, not a correctness requirement.
; If VirtualLock fails even after growing the working set, the flag returned by
; secmem_locked drops to 0 and the operation continues.  Refusing to run would
; mean a quota setting could stop someone decrypting their own data, which
; trades a real availability loss for a speculative confidentiality gain.  This
; is the one place the project's fail-closed rule is deliberately not applied,
; so it is stated rather than buried.
; =============================================================================

include macros.inc

extern VirtualLock:proc
extern VirtualUnlock:proc
extern GetCurrentProcess:proc
extern GetProcessWorkingSetSize:proc
extern SetProcessWorkingSetSize:proc
extern secure_zero:proc

externdef g_cfg_pass:byte
externdef g_key:byte
externdef g_passw:word                  ; gui.asm: wide password as typed
externdef g_confirmw:word               ; gui.asm: wide confirm field
externdef g_pkctx:byte                  ; pack.asm: streaming GCM ctx (round keys)
externdef g_gctx:byte                   ; cmd.asm: single-file GCM ctx (round keys)

SECMEM_MAX      equ 8              ; registered regions (2 used; room to grow)
; Slack added to the working set when a lock is refused for quota.  One lock is
; at most a couple of pages, but the quota is granted in whole pages and the
; process needs headroom for its own pages too.
SECMEM_WS_SLACK equ 1048576        ; 1 MiB

.data?
g_sm_ptr        dq SECMEM_MAX dup (?)   ; region base
g_sm_len        dq SECMEM_MAX dup (?)   ; region length in bytes
g_sm_count      dd ?                    ; registered regions
g_sm_ok         dd ?                    ; 1 = every region locked successfully

.code

; =============================================================================
; secmem_add(rcx = ptr, rdx = length) -> eax = 1 locked, 0 not locked
;
; Records the region so secmem_wipe_all can find it, then locks it.  A failed
; lock still registers the region: the wipe matters more than the lock, and a
; region that is wiped but unlocked is strictly better than one that is neither.
; =============================================================================
public secmem_add
secmem_add proc frame
    ; 80 (-> alloc 96), not 64.  The deepest local is [rbp-56], the working-set
    ; MAXIMUM that GetProcessWorkingSetSize writes through an out-pointer; at
    ; alloc 80 that slot fell inside the callee's own 32-byte home space, where
    ; a Win32 callee is free to save registers - it would have overwritten the
    ; value it had just returned.  framecheck flagged this on the first build.
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx         ; ptr
    mov     qword ptr [rbp-32], rdx         ; len

    ; ---- record (bounds-checked against the table) -------------------------
    mov     eax, dword ptr [g_sm_count]
    BOUND_CHECK eax, SECMEM_MAX
    mov     r10d, eax
    lea     r11, [g_sm_ptr]
    mov     qword ptr [r11+r10*8], rcx
    lea     r11, [g_sm_len]
    mov     qword ptr [r11+r10*8], rdx
    inc     eax
    mov     dword ptr [g_sm_count], eax

    ; ---- first attempt ------------------------------------------------------
    WINCALL VirtualLock, qword ptr [rbp-24], qword ptr [rbp-32]
    test    eax, eax
    jnz     sa_ok

    ; ---- refused: grow the working set and retry once -----------------------
    ; The usual cause is ERROR_WORKING_SET_QUOTA - the process may not pin more
    ; pages than its minimum working set allows.  Raise both limits by the
    ; region size plus slack, then try again.
    WINCALL GetCurrentProcess
    mov     qword ptr [rbp-40], rax
    WINCALL GetProcessWorkingSetSize, qword ptr [rbp-40], addr rbp-48, addr rbp-56
    test    eax, eax
    jz      sa_fail
    mov     rax, qword ptr [rbp-32]         ; len
    add     rax, SECMEM_WS_SLACK
    add     qword ptr [rbp-48], rax         ; minimum += len + slack
    add     qword ptr [rbp-56], rax         ; maximum += len + slack
    WINCALL SetProcessWorkingSetSize, qword ptr [rbp-40], qword ptr [rbp-48], qword ptr [rbp-56]
    test    eax, eax
    jz      sa_fail
    WINCALL VirtualLock, qword ptr [rbp-24], qword ptr [rbp-32]
    test    eax, eax
    jz      sa_fail

sa_ok:
    mov     eax, 1
    jmp     sa_done
sa_fail:
    mov     dword ptr [g_sm_ok], 0
    xor     eax, eax
sa_done:
    FRAME_EPILOG
    ret
secmem_add endp

; =============================================================================
; secmem_init - register and lock every secret buffer.  Called once from
; hardening_init, so both the CLI and the GUI front-end are covered.
; =============================================================================
public secmem_init
secmem_init proc frame
    FRAME_PROLOG 32
    mov     dword ptr [g_sm_count], 0
    mov     dword ptr [g_sm_ok], 1

    lea     rcx, [g_cfg_pass]
    mov     rdx, MAX_PASSWORD_BYTES+1
    call    secmem_add

    lea     rcx, [g_key]
    mov     rdx, KEY_LEN
    call    secmem_add

    ; The GUI's wide password buffers.  These hold the secret as TYPED, before
    ; the UTF-8 conversion into g_cfg_pass, and with private-desktop entry they
    ; hold it across a desktop switch and a window teardown - long enough to be
    ; paged out.  Locking only the converted copy would have left the original
    ; on disk.
    lea     rcx, [g_passw]
    mov     rdx, PWBUF_CHARS * 2
    call    secmem_add

    lea     rcx, [g_confirmw]
    mov     rdx, PWBUF_CHARS * 2
    call    secmem_add

    ; The two GLOBAL GCM contexts.  Each holds a full expanded key schedule
    ; between operations, and unlike the estream objects (heap, wiped by
    ; tagged_free) nothing wiped these until process exit.  336 bytes each -
    ; nothing like the Argon2 arena, so the lock argument above applies.
    lea     rcx, [g_pkctx]
    mov     rdx, 336
    call    secmem_add

    lea     rcx, [g_gctx]
    mov     rdx, 336
    call    secmem_add

    FRAME_EPILOG
    ret
secmem_init endp

; =============================================================================
; secmem_locked -> eax = 1 if every registered region is pinned, else 0.
; Reported by `myrkr selftest` so the property is observable rather than assumed.
; =============================================================================
public secmem_locked
secmem_locked proc
    mov     eax, dword ptr [g_sm_ok]
    ret
secmem_locked endp

; =============================================================================
; secmem_wipe_all - secure_zero every registered region, then unlock it.
;
; Wipe BEFORE unlocking: VirtualUnlock makes the page evictable again, so
; unlocking first would open exactly the window this module exists to close.
; =============================================================================
public secmem_wipe_all
secmem_wipe_all proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-24], 0           ; index
sw_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_sm_count]
    jae     sw_done
    mov     r10d, eax
    lea     r11, [g_sm_ptr]
    mov     rcx, qword ptr [r11+r10*8]
    lea     r11, [g_sm_len]
    mov     rdx, qword ptr [r11+r10*8]
    mov     qword ptr [rbp-32], rcx
    mov     qword ptr [rbp-40], rdx
    call    secure_zero                     ; rcx = ptr, rdx = len
    WINCALL VirtualUnlock, qword ptr [rbp-32], qword ptr [rbp-40]
    inc     dword ptr [rbp-24]
    jmp     sw_loop
sw_done:
    FRAME_EPILOG
    ret
secmem_wipe_all endp

end
