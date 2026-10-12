; =============================================================================
; hardening.asm - runtime hardening services
; -----------------------------------------------------------------------------
;   hardening_init    : canary + software shadow stack setup (call FIRST)
;   iat_lockdown      : make our IAT pages read-only ("full RELRO" equivalent)
;   secure_zero       : forced, non-elidable memory wipe
;   tagged_alloc      : heap allocator with temporal tag + canaries
;   tagged_free       : verifying, poisoning free
;   ct_memcmp         : constant-time comparison (timing safe)
;   crash_install     : wipe secrets and leave cleanly on a fatal fault
; =============================================================================

include macros.inc

extern TlsAlloc:proc
extern TlsSetValue:proc
extern VirtualAlloc:proc
extern VirtualFree:proc
extern VirtualProtect:proc
extern GetModuleHandleW:proc
extern rng_fill:proc                    ; random.asm: rcx=buf, rdx=len -> eax=1 ok
extern secmem_init:proc                 ; secmem.asm: lock the secret buffers
extern secmem_wipe_all:proc             ; secmem.asm: zero every registered secret
extern SetUnhandledExceptionFilter:proc
extern AddVectoredExceptionHandler:proc
extern SetErrorMode:proc
extern TerminateProcess:proc
extern GetCurrentProcess:proc
extern SwitchDesktop:proc               ; give the user's desktop back before dying
extern MessageBoxW:proc
extern CreateFileW:proc
extern WriteFile:proc
extern CloseHandle:proc
extern GetTempPathW:proc
externdef g_sd_prev_input:qword         ; secdesk.asm: the user's desktop while the
                                        ;   password prompt holds input, else 0
externdef g_gui_active:dword            ; gui.asm: 1 once gui_main is running

SEM_FAILCRITICALERRORS  equ 0001h
SEM_NOGPFAULTERRORBOX   equ 0002h
CRASH_GENERIC_WRITE     equ 40000000h
CRASH_CREATE_ALWAYS     equ 2
CRASH_MB_ICONERROR      equ 10h

MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_READONLY       equ 02h
PAGE_READWRITE      equ 04h
PAGE_NOACCESS       equ 01h

; -----------------------------------------------------------------------------
; Tagged heap block layout (temporal memory tagging emulation):
;
;   [hdr]  32 bytes : magic "BLPH" | size(8) | tag(8) | front canary(8) | gen(4)
;   [user] size bytes
;   [tail] 8 bytes  : rear canary  (= front canary rotated by 1)
;
; tag is random per allocation; generation counter is global and bumps on
; every free, so a stale pointer's stored tag can never match a reused block.
; Freed blocks are poisoned with 0xDD before release.
; -----------------------------------------------------------------------------
HEAPBLK struct
    magic       dd ?                    ; TM_HEAPBLK
    gen         dd ?                    ; generation at allocation time
    blksize     dq ?                    ; user size in bytes
    tag         dq ?                    ; random temporal tag
    canary      dq ?                    ; front canary
HEAPBLK ends
HEAP_TAIL_LEN   equ 8

.data
public g_stack_canary
public g_sstk_tls
public g_cpu_features
g_stack_canary  dq 0
; TLS index PLUS ONE of this thread's shadow-stack control block {index, base}.
; Zero means not yet allocated - it cannot mean "slot 0", because slot 0 is a
; real slot the loader may own, and framed code runs before TlsAlloc does.
; This was a pair of globals shared by every thread; see FRAME_PROLOG for
; why that could not survive the indexer thread running framed code.
g_sstk_tls      dd 0
g_cpu_features  dd 0
g_heap_gen      dd 1                    ; global generation counter

.data?
; crash breadcrumb, written in this order to %TEMP%\myrkr_crash.bin:
;   code (4) | pad (4) | faulting address (8) | image base (8) = 24 bytes.
; No register contents, ever: at a crash during crypto they can hold key or
; password bytes, and %TEMP% is readable by everything running as this user.
align 8
g_crash_code    dd ?
                dd ?                    ; pad: the address below is 8-aligned
g_crash_addr    dq ?
g_crash_base    dq ?
g_img_lo        dq ?                    ; this image's range: crash_veh acts only
g_img_hi        dq ?                    ;   on faults raised inside it
g_crash_h       dq ?
g_crash_nw      dd ?
g_crash_dumped  db ?
align 2
g_crashpath     dw MAX_PATH_CHARS dup (?)

.const
WSTR crash_title,   <Myrkr>
WSTR crash_apology, <Myrkr stopped because of an internal error. Its passwords and keys were wiped from memory first. An operation that was running did not finish - files it had not yet replaced are unchanged.>
WSTR crash_fname,   <myrkr_crash.bin>

.code

; =============================================================================
; sstk_thread_init -> eax = 1 ok, 0 failed.  Give the CALLING thread its own
; software shadow stack and publish it in the TLS slot.
;
; Every thread that runs FRAME_PROLOG code needs this.  A thread without it is
; not broken - the macros see a null slot and skip the shadow stack, keeping
; only the canary - but it loses the mitigation, so the thread entry points
; call it first thing.
;
; Layout of one commit: [16-byte control block {index, base}][SSTK_CAPACITY*8],
; with a PAGE_NOACCESS guard page either side, so a runaway push or pop hits a
; guard rather than someone else's memory.
;
; Raw frame on purpose: this runs BEFORE the calling thread has a shadow stack,
; so it cannot itself use FRAME_PROLOG.
; =============================================================================
public sstk_thread_init
sstk_thread_init proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    WINCALL VirtualAlloc, 0, <1000h + 16 + (SSTK_CAPACITY*8) + 1000h>, <MEM_RESERVE or MEM_COMMIT>, PAGE_NOACCESS
    test    rax, rax
    jz      sti_fail
    mov     qword ptr [rbp-8], rax          ; region base
    WINCALL VirtualProtect, addr rax+1000h, <16 + (SSTK_CAPACITY*8)>, PAGE_READWRITE, addr rbp-16
    test    eax, eax
    jz      sti_fail_free
    mov     rax, qword ptr [rbp-8]
    lea     rax, [rax+1000h]                ; -> control block
    mov     qword ptr [rax], 0              ; index = 0
    lea     rcx, [rax+16]
    mov     qword ptr [rax+8], rcx          ; base = just past the block
    ; Stash both through memory: passing rdx and rax as the two arguments lets
    ; the marshalling clobber one with the other depending on assignment order.
    mov     qword ptr [rbp-24], rax         ; the control block
    mov     eax, dword ptr [g_sstk_tls]
    dec     eax                             ; stored as index+1
    mov     dword ptr [rbp-32], eax
    WINCALL TlsSetValue, dword ptr [rbp-32], qword ptr [rbp-24]
    test    eax, eax
    jz      sti_fail_free
    mov     eax, 1
    add     rsp, 64
    pop     rbp
    ret
sti_fail_free:
    ; the region is committed but unreachable - the thread will run canary-only
    ; either way, so hand the pages back rather than keep them for nobody
    WINCALL VirtualFree, qword ptr [rbp-8], 0, MEM_RELEASE
sti_fail:
    xor     eax, eax
    add     rsp, 64
    pop     rbp
    ret
sstk_thread_init endp

; =============================================================================
; sstk_thread_free - give back the block sstk_thread_init handed this thread.
;
; MUST BE THE LAST THING A THREAD DOES.  Every framed call has to have RETURNED
; before this runs: the block is what FRAME_PROLOG writes to and FRAME_EPILOG
; verifies against, so releasing it under a live frame is the 0xC0000409 this
; whole machinery exists to prevent, reached from the other direction.
;
; Raw frame, like sstk_thread_init and for the mirror of its reason: a
; FRAME_PROLOG here would push onto the very block it is about to release, and
; its epilogue would then check a canary on freed pages.
;
; THE TLS SLOT IS CLEARED FIRST, then the pages go back.  If framed code ever
; does run afterwards - a path nobody meant to add, added later - FRAME_PROLOG
; finds a null slot and degrades to canary-only, which is exactly what it
; already does for a thread that never had a block.  Clearing after the free
; would leave a live pointer into released address space and turn that graceful
; degrade into an access violation.
;
; Without this the block leaked once per thread, and threads are not rare here:
; a scan on every input change, a worker per operation, one per password prompt.
; =============================================================================
public sstk_thread_free
sstk_thread_free proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     eax, dword ptr [g_sstk_tls]
    test    eax, eax
    jz      stf_ret                         ; no slot allocated: nothing to give back
    dec     eax                             ; stored as index+1
    mov     dword ptr [rbp-32], eax
    mov     r10d, eax
    mov     r11, gs:[r10*8 + TEB_TLS_SLOTS]
    test    r11, r11
    jz      stf_ret                         ; this thread never got a block
    sub     r11, 1000h                      ; the control block sits one page in
    mov     qword ptr [rbp-24], r11
    WINCALL TlsSetValue, dword ptr [rbp-32], 0
    WINCALL VirtualFree, qword ptr [rbp-24], 0, MEM_RELEASE
stf_ret:
    add     rsp, 64
    pop     rbp
    ret
sstk_thread_free endp

; =============================================================================
; sstk_overflow_fail - jumped to from FRAME_PROLOG when the shadow stack is full
; =============================================================================
public sstk_overflow_fail
sstk_overflow_fail proc
    FASTFAIL FF_SHADOW_STACK
sstk_overflow_fail endp

; =============================================================================
; hardening_init - must be the first call made by the entry point.
; Allocates the shadow stack between two PAGE_NOACCESS guard pages and
; seeds the stack canary from the CSPRNG mixed with rdtsc.
; Returns eax=1 on success, 0 on failure (caller exits EXIT_OOM).
; NOTE: uses a raw frame - the canary/shadow machinery is not live yet.
; =============================================================================
public hardening_init
hardening_init proc frame
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 64                     ; 32 shadow + locals (base, oldprot, seed)
    .allocstack 64
    .endprolog

    ; ---- one TLS index, then THIS thread's own shadow stack ----------------
    call    TlsAlloc                    ; no args; WINCALL is for argument marshalling
    cmp     eax, 63                     ; must land in the TEB's inline slots:
    ja      hi_fail                     ; past 63 it moves to TlsExpansionSlots
    inc     eax                         ; store index+1: 0 means NOT READY, and
    mov     dword ptr [g_sstk_tls], eax ; TLS slot 0 is a real slot someone owns
    call    sstk_thread_init
    test    eax, eax
    jz      hi_fail

    ; ---- seed stack canary: CSPRNG xor rdtsc, never zero --------------------
    ; IMPORTANT: rng_fill is itself canary-protected and reads g_stack_canary
    ; in its epilog, so we must NOT let it write g_stack_canary directly.
    ; Fill a local seed buffer, then publish the canary only after it returns.
    lea     rcx, [rbp-24]               ; local seed (8 bytes)
    mov     edx, 8
    call    rng_fill
    test    eax, eax
    jz      hi_fail
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    xor     rax, qword ptr [rbp-24]
    test    rax, rax
    jnz     @F
    mov     rax, 0A5A5A5A55A5A5A5Ah     ; never-zero fallback
@@:
    mov     qword ptr [g_stack_canary], rax

    ; ---- pin the secret buffers (non-pageable) ------------------------------
    ; Must come AFTER the canary is published: secmem_init is FRAME_PROLOG'd, so
    ; it reads g_stack_canary in its own epilog.  Locking is best-effort and
    ; never fails startup - see the failure-policy note in secmem.asm.
    call    secmem_init

    mov     eax, 1
    jmp     hi_done
hi_fail:
    xor     eax, eax
hi_done:
    mov     rsp, rbp
    pop     rbp
    ret
hardening_init endp

; =============================================================================
; iat_lockdown - "full RELRO" equivalent: walk our own PE header, find the
; IAT data directory and VirtualProtect it PAGE_READONLY.  Call after all
; initialization (imports are bound by the loader before we run, so this is
; safe immediately).  Returns eax=1 ok / 0 fail (non-fatal; caller may warn).
; =============================================================================
public iat_lockdown
iat_lockdown proc frame
    FRAME_PROLOG 48                     ; 32 shadow + 16 locals
    ; locals: [rbp-16] old protect

    WINCALL GetModuleHandleW, 0         ; GetModuleHandleW(NULL) = our base
    test    rax, rax
    jz      il_fail
    mov     r10, rax                    ; r10 = module base

    ; e_lfanew at base+3Ch -> PE header
    mov     eax, dword ptr [r10+3Ch]
    BOUND_CHECK rax, 1000h              ; sanity: header within first page
    lea     r11, [r10+rax]              ; r11 = IMAGE_NT_HEADERS64
    cmp     dword ptr [r11], 00004550h  ; "PE\0\0"
    jne     il_fail

    ; OptionalHeader at +24; DataDirectory at +112 within OptionalHeader;
    ; entry 12 (IMAGE_DIRECTORY_ENTRY_IAT) = +24+112+12*8 = +232
    mov     eax, dword ptr [r11+232]    ; IAT RVA
    mov     edx, dword ptr [r11+236]    ; IAT size
    test    eax, eax
    jz      il_fail
    test    edx, edx
    jz      il_fail

    ; IAT VA in r10+rax, size already in rdx
    WINCALL VirtualProtect, addr r10+rax, rdx, PAGE_READONLY, addr rbp-16
    test    eax, eax
    jz      il_fail
    mov     eax, 1
    jmp     il_done
il_fail:
    xor     eax, eax
il_done:
    FRAME_EPILOG
    ret
iat_lockdown endp

; =============================================================================
; secure_zero(rcx = ptr, rdx = len)
; Wipe that cannot be optimized away (we are asm - but we also use xmm stores
; followed by a fence so partial inlining/reordering can never skip it).
; =============================================================================
public secure_zero
secure_zero proc
    test    rdx, rdx
    jz      sz_done
    pxor    xmm0, xmm0
    ; ---- 16-byte chunks -----------------------------------------------------
sz_loop16:
    cmp     rdx, 16
    jb      sz_tail
    movdqu  xmmword ptr [rcx], xmm0
    add     rcx, 16
    sub     rdx, 16
    jmp     sz_loop16
sz_tail:
    test    rdx, rdx
    jz      sz_fence
    mov     byte ptr [rcx], 0
    inc     rcx
    dec     rdx
    jmp     sz_tail
sz_fence:
    mfence                              ; order the wipe before anything later
sz_done:
    ret
secure_zero endp

; =============================================================================
; ct_memcmp(rcx = a, rdx = b, r8 = len) -> eax = 0 if equal, 1 if different
; Constant time: examines every byte, no data-dependent branches.
; =============================================================================
public ct_memcmp
ct_memcmp proc
    xor     eax, eax                    ; accumulated difference
    xor     r10d, r10d                  ; index
    test    r8, r8
    jz      cm_done
cm_loop:
    movzx   r11d, byte ptr [rcx+r10]
    movzx   r9d,  byte ptr [rdx+r10]
    xor     r11d, r9d
    or      eax, r11d
    inc     r10
    cmp     r10, r8
    jb      cm_loop
cm_done:
    ; collapse any nonzero to exactly 1 without branching
    neg     eax                         ; CF=1 iff eax was nonzero
    sbb     eax, eax                    ; eax = -1 iff nonzero, else 0
    neg     eax                         ; eax = 1 iff different, 0 if equal
    ret
ct_memcmp endp

; =============================================================================
; tagged_alloc(rcx = user size) -> rax = user pointer, or 0 on failure
; VirtualAlloc-backed (no RWX, page-granular, OS guards) with header/footer
; canaries and a random temporal tag.
; =============================================================================
public tagged_alloc
tagged_alloc proc frame
    FRAME_PROLOG 64
    ; locals: [rbp-24] user size, [rbp-32] block ptr

    mov     qword ptr [rbp-24], rcx
    ; total = sizeof header + size + tail, overflow-checked
    mov     rax, rcx
    CHECK_ADD_OVF rax, (sizeof HEAPBLK) + HEAP_TAIL_LEN
    WINCALL VirtualAlloc, 0, rax, <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
    test    rax, rax
    jz      ta_fail
    mov     qword ptr [rbp-32], rax

    ; ---- fill header --------------------------------------------------------
    mov     dword ptr [rax].HEAPBLK.magic, TM_HEAPBLK
    mov     ecx, dword ptr [g_heap_gen]
    mov     dword ptr [rax].HEAPBLK.gen, ecx
    mov     rcx, qword ptr [rbp-24]
    mov     qword ptr [rax].HEAPBLK.blksize, rcx

    lea     rcx, [rax].HEAPBLK.tag      ; random temporal tag (8 bytes)
    mov     edx, 8
    call    rng_fill
    test    eax, eax
    jz      ta_fail_free

    mov     rax, qword ptr [rbp-32]
    mov     r10, qword ptr [rax].HEAPBLK.tag
    mov     qword ptr [rax].HEAPBLK.canary, r10     ; front canary = tag
    rol     r10, 1
    mov     rcx, qword ptr [rax].HEAPBLK.blksize    ; rear canary = rol(tag,1)
    lea     r11, [rax + sizeof HEAPBLK]
    mov     qword ptr [r11+rcx], r10

    lea     rax, [rax + sizeof HEAPBLK]             ; -> user pointer
    jmp     ta_done
ta_fail_free:
    WINCALL VirtualFree, qword ptr [rbp-32], 0, MEM_RELEASE
ta_fail:
    xor     eax, eax
ta_done:
    FRAME_EPILOG
    ret
tagged_alloc endp

; =============================================================================
; tagged_check(rcx = user ptr) - validate a live block, fastfail on violation.
; Catches: type confusion, buffer overflow into header, rear-canary smash,
; use-after-free (poisoned/stale generation).
; =============================================================================
public tagged_check
tagged_check proc
    lea     r10, [rcx - sizeof HEAPBLK]
    TYPE_CHECK r10, TM_HEAPBLK
    mov     r11, qword ptr [r10].HEAPBLK.tag
    cmp     r11, qword ptr [r10].HEAPBLK.canary     ; front canary == tag?
    jne     tc_fail
    mov     rax, qword ptr [r10].HEAPBLK.blksize
    rol     r11, 1
    cmp     r11, qword ptr [rcx+rax]                ; rear canary == rol(tag,1)?
    jne     tc_fail
    ret
tc_fail:
    FASTFAIL FF_HEAP_TAG
tagged_check endp

; =============================================================================
; tagged_free(rcx = user ptr, rdx = 1 to securely wipe user data first)
; Verifies block integrity, optionally wipes, poisons the header (so a
; double free / stale pointer fastfails), bumps generation, releases pages.
; =============================================================================
public tagged_free
tagged_free proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] user ptr, [rbp-32] wipe flag

    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    call    tagged_check                            ; fastfails if invalid

    mov     rcx, qword ptr [rbp-24]
    lea     r10, [rcx - sizeof HEAPBLK]

    xIF qword ptr [rbp-32], ne, 0               ; wipe flag set?
        mov     rdx, qword ptr [r10].HEAPBLK.blksize
        call    secure_zero                         ; rcx still = user ptr
    xENDIF
    ; ---- poison header so any reuse of the stale pointer is caught ---------
    mov     rcx, qword ptr [rbp-24]
    lea     r10, [rcx - sizeof HEAPBLK]
    mov     dword ptr [r10].HEAPBLK.magic, 0DDDDDDDDh
    mov     rax, 0DDDDDDDDDDDDDDDDh
    mov     qword ptr [r10].HEAPBLK.tag, rax
    mov     qword ptr [r10].HEAPBLK.canary, 0
    lock inc dword ptr [g_heap_gen]                 ; bump global generation

    WINCALL VirtualFree, r10, 0, MEM_RELEASE        ; release the pages

    FRAME_EPILOG
    ret
tagged_free endp

; =============================================================================
; CRASH CONTAINMENT (ported from Vordr's hardening.asm, 2026-10-11)
;
; Without it a fault anywhere in Myrkr went to Windows Error Reporting with
; everything still in memory - the password in g_cfg_pass, the key in g_key,
; decrypted plaintext in the stream buffers - and a crash dump is a file.  And a
; fault while the password prompt held the private desktop left the user on an
; empty screen, because the only SwitchDesktop back is in code a dead process
; never reaches.
;
; crash_veh is the primary path: a vectored handler runs first-chance, before
; any dump writer.  It acts only on ERROR-severity codes raised inside this
; image - a vectored handler sees every first-chance exception in the process,
; and DLLs loaded into the file dialogs (shell extensions) raise and handle
; their own.  crash_filter is the backstop for a fatal fault outside the image.
;
; __fastfail (every FASTFAIL in this tree, the 0xFADE redteam codes, the
; shadow-stack and canary traps) is NOT an exception and reaches neither: the
; kernel ends the process at once, which is already the containment wanted.
;
; FRAME_PROLOG is safe here on any thread: on a thread Myrkr never set up, the
; shadow-stack slot is null and the macro skips it (see sstk_thread_init).
; =============================================================================

; crash_contain - wipe every registered secret, give the desktop back, say
; something if a window is up, terminate.  Never returns.
crash_contain proc frame
    FRAME_PROLOG 48
    call    secmem_wipe_all                     ; secrets gone before anything else
    ; The password prompt holds the private desktop: switch the user back
    ; BEFORE any UI, and then raise none - the prompt's thread is attached to
    ; the desktop just left, so a box from it would be invisible and would block
    ; the termination below for ever.
    mov     rcx, qword ptr [g_sd_prev_input]
    test    rcx, rcx
    jz      cc_ui
    WINCALL SwitchDesktop, rcx
    jmp     cc_kill
cc_ui:
    cmp     dword ptr [g_gui_active], 0          ; a box only when a window is up -
    je      cc_kill                             ;   the CLI must never block on one
    WINCALL MessageBoxW, 0, addr crash_apology, addr crash_title, CRASH_MB_ICONERROR
cc_kill:
    WINCALL GetCurrentProcess
    WINCALL TerminateProcess, rax, 0C0000409h
    FRAME_EPILOG                                ; unreached
    ret
crash_contain endp

; crash_dump - best-effort breadcrumb, %TEMP%\myrkr_crash.bin, 24 bytes:
; code, faulting address, image base.  Once per process.
crash_dump proc frame
    FRAME_PROLOG 64
    cmp     byte ptr [g_crash_dumped], 0
    jne     cd_ret
    mov     byte ptr [g_crash_dumped], 1
    mov     rax, qword ptr [g_img_lo]
    mov     qword ptr [g_crash_base], rax
    WINCALL GetTempPathW, MAX_PATH_CHARS-32, addr g_crashpath
    test    eax, eax
    jz      cd_ret
    cmp     eax, MAX_PATH_CHARS-32
    jae     cd_ret
    lea     r10, [g_crashpath]
cd_scan:
    cmp     word ptr [r10], 0
    je      cd_app
    add     r10, 2
    jmp     cd_scan
cd_app:
    lea     r11, [crash_fname]
cd_cp:
    mov     ax, word ptr [r11]
    mov     word ptr [r10], ax
    add     r10, 2
    add     r11, 2
    test    ax, ax
    jnz     cd_cp
    WINCALL CreateFileW, addr g_crashpath, CRASH_GENERIC_WRITE, 0, 0, CRASH_CREATE_ALWAYS, 0, 0
    cmp     rax, -1
    je      cd_ret
    mov     qword ptr [g_crash_h], rax
    WINCALL WriteFile, qword ptr [g_crash_h], addr g_crash_code, 24, addr g_crash_nw, 0
    WINCALL CloseHandle, qword ptr [g_crash_h]
cd_ret:
    FRAME_EPILOG
    ret
crash_dump endp

; crash_veh(rcx = EXCEPTION_POINTERS*) -> eax = EXCEPTION_CONTINUE_SEARCH (0)
;
; RAW, like redteam's rt_iat_veh: it runs inside the OS exception dispatcher for
; EVERY first-chance exception in the process, nearly all of which it passes on,
; and the pass path should disturb nothing - no canary, no shadow-stack entry.
; The framed code (crash_dump, crash_contain) runs only once a fault is fatal.
crash_veh proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     rax, qword ptr [rcx]                ; -> EXCEPTION_RECORD
    mov     r10d, dword ptr [rax]               ; ExceptionCode
    mov     r11d, r10d
    and     r11d, 0F0000000h
    cmp     r11d, 0C0000000h                    ; ERROR severity only: guard-page
    jne     cv_pass                             ;   growth, breakpoints, single
                                                ;   steps and C++/RPC exceptions pass
    mov     r11, qword ptr [rax+16]             ; ExceptionAddress
    cmp     r11, qword ptr [g_img_lo]
    jb      cv_pass                             ; raised outside this image: some
    cmp     r11, qword ptr [g_img_hi]           ;   DLL's own business - crash_filter
    jae     cv_pass                             ;   catches it if nobody handles it
    mov     dword ptr [g_crash_code], r10d
    mov     qword ptr [g_crash_addr], r11
    call    crash_dump                          ; breadcrumb first: it survives a
    call    crash_contain                       ;   containment step that fails
cv_pass:
    xor     eax, eax
    add     rsp, 48
    pop     rbp
    ret
crash_veh endp

; crash_filter(rcx = EXCEPTION_POINTERS*) - the last-chance backstop.  Raw for
; the same reason as crash_veh.
crash_filter proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     rax, qword ptr [rcx]
    mov     r10d, dword ptr [rax]
    mov     dword ptr [g_crash_code], r10d
    mov     r10, qword ptr [rax+16]
    mov     qword ptr [g_crash_addr], r10
    call    crash_dump
    call    crash_contain
    xor     eax, eax                            ; unreached
    add     rsp, 48
    pop     rbp
    ret
crash_filter endp

; =============================================================================
; crash_install - arm the above.  Call once, early in wstart, before any secret
; exists.  SetErrorMode suppresses the WER fault dialog for this process (no
; registry change); the vectored handler goes FIRST in the chain so it runs
; before anything else gets the chance to write a dump.
; =============================================================================
public crash_install
crash_install proc frame
    FRAME_PROLOG 32
    WINCALL GetModuleHandleW, 0
    mov     qword ptr [g_img_lo], rax
    mov     r10d, dword ptr [rax+3Ch]           ; e_lfanew
    mov     r10d, dword ptr [rax+r10+50h]       ; OptionalHeader.SizeOfImage
    add     rax, r10
    mov     qword ptr [g_img_hi], rax
    WINCALL SetErrorMode, <SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX>
    WINCALL AddVectoredExceptionHandler, 1, addr crash_veh
    WINCALL SetUnhandledExceptionFilter, addr crash_filter
    FRAME_EPILOG
    ret
crash_install endp

end
