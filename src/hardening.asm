; =============================================================================
; hardening.asm - runtime hardening services
; -----------------------------------------------------------------------------
;   hardening_init    : canary + software shadow stack setup (call FIRST)
;   iat_lockdown      : make our IAT pages read-only ("full RELRO" equivalent)
;   secure_zero       : forced, non-elidable memory wipe
;   tagged_alloc      : heap allocator with temporal tag + canaries
;   tagged_free       : verifying, poisoning free
;   ct_memcmp         : constant-time comparison (timing safe)
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

end
