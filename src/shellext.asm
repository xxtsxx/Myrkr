; =============================================================================
; shellext.asm - myrkrshell.dll: the drag-and-drop shell extension.
; -----------------------------------------------------------------------------
; Adds "Decrypt here" / "Encrypt" to the menu Explorer shows when files are
; RIGHT-dragged onto a folder.  That menu is populated by the DROP TARGET, not
; by the dragged file, and only through a COM in-proc handler registered under
; Folder\shellex\DragDropHandlers - there is no registry-only way to do it.
; That requirement is the whole reason this second binary exists.
;
; THIS CODE RUNS INSIDE explorer.exe.  Three consequences shape everything here:
;
;   1. It must never fault.  A crash here takes down the user's shell, not our
;      process.  Every pointer the shell hands us is treated as hostile: checked
;      for NULL, bounded before use, and never trusted for length.
;   2. It must never do the work.  InvokeCommand launches myrkr.exe and returns
;      immediately.  No crypto, no file I/O, no password handling in this DLL -
;      it would run inside Explorer's process and outside the private desktop,
;      which is exactly the surface the rest of Myrkr just closed.  The DLL is a
;      launcher and nothing else.
;   3. It cannot use the hardening macros.  FRAME_PROLOG/FRAME_EPILOG reference
;      the stack canary and the software shadow stack, which live in
;      hardening.asm and are initialised by the exe's startup.  Neither exists
;      here, so every proc below uses a plain prologue.  This is a deliberate
;      exception to the rule the rest of the project follows, and it is why this
;      file is kept small enough to audit by eye.
;
; No global mutable scratch: the command line is built in a heap block allocated
; and freed inside InvokeCommand.  A .data? buffer would be shared by every
; object the shell creates in that one Explorer process, and "the menu is only
; invoked on the UI thread" is an assumption about someone else's code.
;
; Registration is written by the MSI (CLSID\{..}\InprocServer32 plus the
; DragDropHandlers key); there is no DllRegisterServer and there should not be -
; self-registration in an installer is a rollback hazard.
; =============================================================================

include macros.inc

extern CreateProcessW:proc
extern CloseHandle:proc
extern GetModuleFileNameW:proc
extern GetProcessHeap:proc
extern HeapAlloc:proc
extern HeapFree:proc
extern GlobalLock:proc
extern GlobalUnlock:proc
extern DisableThreadLibraryCalls:proc
extern DragQueryFileW:proc
extern SHGetPathFromIDListW:proc
extern ReleaseStgMedium:proc
extern InsertMenuW:proc
extern InsertMenuItemW:proc
extern LoadImageW:proc
extern GetMenuItemCount:proc
extern GetMenuState:proc
extern lstrcmpiW:proc

; ---- COM / shell constants --------------------------------------------------
S_OK                equ 0
S_FALSE             equ 1
E_NOINTERFACE       equ 80004002h
E_OUTOFMEMORY       equ 8007000Eh
E_INVALIDARG        equ 80070057h
E_FAIL              equ 80004005h
E_NOTIMPL           equ 80004001h
CLASS_E_NOAGGREGATION equ 80040110h
CLASS_E_CLASSNOTAVAILABLE equ 80040111h
; MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL, n) = n.  QueryContextMenu
; returns the number of ids it consumed in this form; the shell reads it back
; with HRESULT_CODE, so a wrong facility happens to work and is still wrong.
HR_ONE_ID           equ 1

CF_HDROP            equ 15
DVASPECT_CONTENT    equ 1
TYMED_HGLOBAL       equ 1
MF_SEPARATOR        equ 800h
MF_BYPOSITION       equ 400h
CMF_DEFAULTONLY     equ 1

; ---- MENUITEMINFOW, so the item can carry the Myrkr icon --------------------
; InsertMenuW cannot set hbmpItem, which is the only reason this struct is here.
;
; The x64 layout in full, because cbSize has to be exactly right or the call is
; rejected, and the two pointers force 8-byte alignment that inserts padding
; where a 32-bit reading of the struct would not expect it:
;
;   0  cbSize        4  fMask         8  fType        12 fState
;   16 wID           20 (pad)         24 hSubMenu     32 hbmpChecked
;   40 hbmpUnchecked 48 dwItemData    56 dwTypeData   64 cch
;   68 (pad)         72 hbmpItem      80 = sizeof
;
; Only the fields this actually sets get names: an `equ` nothing references is
; a symbol the dead-code gate has to be argued with, and the layout above is
; the part worth keeping.
MII_cbSize          equ 0
MII_fMask           equ 4
MII_fType           equ 8
MII_wID             equ 16
MII_dwTypeData      equ 56
MII_hbmpItem        equ 72
MII_BYTES           equ 80
MIIM_ID             equ 00000002h
MIIM_STRING         equ 00000040h
MIIM_BITMAP         equ 00000080h
MIIM_FTYPE          equ 00000100h
MFT_STRING          equ 0
IMAGE_BITMAP        equ 0
LR_CREATEDIBSECTION equ 2000h            ; keep the 32bpp DIB, do not flatten it
IDB_MENU            equ 1                ; the BITMAP in myrkrshell.rc
DLL_PROCESS_ATTACH  equ 1
HEAP_ZERO_MEMORY    equ 8
IDATAOBJ_GETDATA    equ 24               ; IDataObject vtable slot 3 (byte offset)
SIZEOF_STARTUPINFOW equ 104
SIZEOF_PROCINFO     equ 24

; What the dragged selection is, which decides both the label and where the item
; goes.  Three states rather than a decryptable/not flag, because .mrk and .zip
; want different words AND different places in the menu: Explorer already offers
; "Extract..." for a .zip, and ours reads as a second extraction choice next to
; it, whereas for everything else ours is the odd one out and goes on top.
KIND_ENCRYPT        equ 0            ; anything else, including a mixed bag
KIND_DECRYPT        equ 1            ; every item a .mrk
KIND_EXTRACT        equ 2            ; every item a .zip

MAX_FILES           equ 64
; Packed NUL-separated dragged paths.  Sized under CreateProcessW's 32767-char
; command-line ceiling on purpose: the quoted command line is built with a bound
; that cannot be exceeded, so "it fit in the buffer" and "CreateProcessW will
; accept it" are the same statement rather than two separate hopes.
PATHBUF_CHARS       equ 30000
DESTBUF_CHARS       equ 1040
CMDBUF_CHARS        equ 32768            ; the CreateProcessW ceiling, exactly

; object layout (heap block)
OBJ_VTBL_INIT       equ 0            ; IShellExtInit vtable ptr
OBJ_VTBL_CTX        equ 8            ; IContextMenu   vtable ptr  <- QI hands this out
OBJ_REF             equ 16           ; refcount (low dword; lock xadd)
OBJ_NFILES          equ 24
OBJ_KIND            equ 32           ; KIND_* below - what the selection is
; 1 = a real drop target (right-DRAG), 0 = plain right-click.  It decides two
; things: whether InvokeCommand appends --to, and where the menu item goes - a
; shortcut menu has a region for third-party verbs and points indexMenu at it,
; whereas the drag menu does not and has to be positioned by hand.
OBJ_HASDEST         equ 40
OBJ_DEST            equ 48           ; drop-target folder (wide), valid iff HASDEST
OBJ_PATHS           equ OBJ_DEST + DESTBUF_CHARS*2
OBJ_SIZE            equ OBJ_PATHS + PATHBUF_CHARS*2

.const
; {7C4A6E10-2F58-4B3D-9C81-5E0A7D9B4F62} - the handler's CLSID.  Fixed forever:
; the MSI writes it, and changing it would orphan the registration.
public CLSID_MyrkrDrop
CLSID_MyrkrDrop     dd 07C4A6E10h
                    dw 02F58h, 04B3Dh
                    db 09Ch,081h,05Eh,00Ah,07Dh,09Bh,04Fh,062h
IID_IUnknown        dd 000000000h
                    dw 00000h, 00000h
                    db 0C0h,000h,000h,000h,000h,000h,000h,046h
IID_IClassFactory   dd 000000001h
                    dw 00000h, 00000h
                    db 0C0h,000h,000h,000h,000h,000h,000h,046h
IID_IShellExtInit   dd 0000214E8h
                    dw 00000h, 00000h
                    db 0C0h,000h,000h,000h,000h,000h,000h,046h
IID_IContextMenu    dd 0000214E4h
                    dw 00000h, 00000h
                    db 0C0h,000h,000h,000h,000h,000h,000h,046h

; One label for every selection.  The verb used to name the OPERATION -
; encrypt / decrypt / extract - which meant the menu committed to an outcome
; before the user had chosen anything, and made three entries out of what is
; one idea: hand this to Myrkr.  What actually happens still depends on what
; was selected; the kind is just no longer spelled out in the menu.
; Two menus, two jobs, and now two kinds of wording.
;
; A right-CLICK opens the window and decides nothing, so its item says where you
; are going: "Open with Myrkr".  A right-DRAG has already been told everything -
; what, and where it goes - and acts on release without asking, so its item has
; to say what will HAPPEN, not which program is about to appear.
;
; No "Myrkr" in the drag labels.  The icon beside the item carries that now, and
; repeating it costs the width that the verb itself needs.
WSTR sx_menu_open,     <Open with Myrkr>
WSTR sx_menu_encrypt,  <Encrypt>
WSTR sx_menu_decrypt,  <Decrypt/extract>
WSTR sx_exe,        <myrkr.exe>
WSTR sx_ext_mrk,    <.mrk>
WSTR sx_ext_zip,    <.zip>
; Raw dw rather than WSTR: WSTR cannot carry a quote through its `forc`, and a
; trailing space inside <> is not reliably preserved.  `even` keeps each label
; 2-aligned - an odd-address wide string handed to a -W API can take an aligned
; read path and fail with ERROR_NOACCESS (see the WSTR note in macros.inc).
even
sx_quote            dw 22h, 0                       ; "
even
sx_quote_sp         dw 22h, 20h, 0                  ; " followed by a space
sx_bslash           dw 5Ch, 0                       ; \
even
sx_to_sp            dw '-', '-', 't', 'o', ' ', 0   ; --to<space>

.data
; Outstanding objects + class-factory locks.  DllCanUnloadNow reports S_FALSE
; while this is non-zero, so COM will not pull the DLL out from under a live
; menu.  Touched only with LOCK-prefixed instructions.
g_dll_refs          dd 0
align 8
g_hinst_dll         dq 0
; The menu bitmap, loaded once on the first QueryContextMenu and kept for the
; life of the DLL.
;
; NOT freed.  A menu owns nothing: hbmpItem stays the caller's to delete, and
; the caller is never told when Explorer destroys the menu - so the only place
; to release it would be DLL_PROCESS_DETACH, which means calling gdi32 under the
; loader lock inside explorer.exe.  A kilobyte held for a session Explorer keeps
; the DLL loaded for is the cheaper of the two by a wide margin, and freeing it
; would also drag gdi32 into this image for one function.
g_hbm_menu          dq 0
g_hbm_tried         dd 0                 ; so a failed load is not retried per click

.code

; =============================================================================
; menu_bitmap() -> rax = HBITMAP for the menu item, or 0 if it could not load.
;
; Cached; a failure is cached too, as a null, so a broken or missing resource
; costs one LoadImageW rather than one per right-click.  A null is not an error
; here - the item is labelled in words and appears with or without the picture.
; =============================================================================
menu_bitmap proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80                          ; shadow + arg5/arg6 spill for LoadImageW
    mov     rax, qword ptr [g_hbm_menu]
    test    rax, rax
    jnz     mb_ret
    cmp     dword ptr [g_hbm_tried], 0
    jne     mb_zero
    mov     dword ptr [g_hbm_tried], 1
    ; 0,0 for the size: the bitmap is used at the size it was authored, because
    ; LoadImageW's own stretching does not respect an alpha channel and doing it
    ; properly needs gdi32.  See tools\make_menu_bmp.py.
    WINCALL LoadImageW, qword ptr [g_hinst_dll], IDB_MENU, IMAGE_BITMAP, 0, 0, \
            LR_CREATEDIBSECTION
    mov     qword ptr [g_hbm_menu], rax
mb_ret:
    add     rsp, 80
    pop     rbp
    ret
mb_zero:
    xor     eax, eax
    add     rsp, 80
    pop     rbp
    ret
menu_bitmap endp

; =============================================================================
; guid_eq(rcx = a, rdx = b) -> eax = 1 if the two 16-byte GUIDs match.
; =============================================================================
guid_eq proc
    mov     rax, qword ptr [rcx]
    cmp     rax, qword ptr [rdx]
    jne     ge_no
    mov     rax, qword ptr [rcx+8]
    cmp     rax, qword ptr [rdx+8]
    jne     ge_no
    mov     eax, 1
    ret
ge_no:
    xor     eax, eax
    ret
guid_eq endp

; =============================================================================
; obj_from_ctx(rcx = IContextMenu*) -> rax = object base.
; The context-menu interface pointer is the SECOND vtable slot, so the shell
; hands back a pointer 8 bytes into the object.  Every IContextMenu method has
; to undo that before touching a field; getting this wrong reads the wrong
; member and is the classic multi-vtable COM bug.
; =============================================================================
obj_from_ctx proc
    lea     rax, [rcx-OBJ_VTBL_CTX]
    ret
obj_from_ctx endp

; =============================================================================
; wlen(rcx = wide string) -> rax = characters before the terminator.
; Capped at PATHBUF_CHARS: an unterminated buffer must not spin forever.
; =============================================================================
wlen proc
    xor     rax, rax
wl_lp:
    cmp     word ptr [rcx+rax*2], 0
    je      wl_done
    inc     rax
    cmp     rax, PATHBUF_CHARS
    jb      wl_lp
wl_done:
    ret
wlen endp

; =============================================================================
; wapp_lim(rcx = dst, rdx = src, r8 = limit) -> rax = new end, or 0 if the
; append would have run past the limit.
;
; limit is the address ONE PAST the last writable wide char, so the terminator
; written at the final position is still inside the buffer.  Every caller must
; test the result: returning 0 rather than truncating means a command line is
; either complete or not built at all - a truncated one would name a different
; file.  tools/wstrcheck.py enforces that r8 is set at each call site.
; =============================================================================
wapp_lim proc
wal_lp:
    cmp     rcx, r8
    jae     wal_ovf
    mov     ax, word ptr [rdx]
    mov     word ptr [rcx], ax
    test    ax, ax
    jz      wal_done
    add     rcx, 2
    add     rdx, 2
    jmp     wal_lp
wal_done:
    mov     rax, rcx
    ret
wal_ovf:
    xor     eax, eax
    ret
wapp_lim endp

; =============================================================================
; wapp_q(rcx = dst, rdx = src, r8 = limit) -> rax = new end, or 0.
; Appends  "<src>"  followed by one space.
;
; Windows paths cannot contain a quote, so quoting is ALMOST the whole of the
; escaping needed - but not quite.  CommandLineToArgvW, which is what myrkr.exe
; parses its own line with (gui.asm:gui_main), treats a run of backslashes
; immediately before a quote as escaping it.  So  "C:\"  hands back a literal
; quote and leaves the argument OPEN, swallowing everything after it:
;
;     "C:\" "D:\notes.txt"        ->  one argument,  C:" D:\notes.txt
;     --to "E:\" "C:\secret.txt"   ->  the input path disappears into --to
;
; A DRIVE ROOT is exactly a path ending in a backslash, and this handler is
; registered on Drive for drag-drop, so the shell hands us that case rather than
; it being hypothetical.  The trailing run is therefore DOUBLED, which is the
; rule the parser implements in reverse; a run in the MIDDLE of a path needs
; nothing, because only the run adjacent to the quote is special.
;
; Dropping the backslash instead would be a different bug: `C:` is drive
; RELATIVE - it names the process's current directory on that drive, not its
; root - so the operation would quietly target somewhere else.
;
; locals: src[-8] limit[-16] path-start[-24] end[-32] left-to-double[-40].
; 96 rather than 48: wapp_lim's outgoing argument area is the low 32 bytes of
; the frame, and at 48 the new locals would have been argument slots.
; =============================================================================
wapp_q proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     qword ptr [rbp-8], rdx           ; src
    mov     qword ptr [rbp-16], r8           ; limit
    lea     rdx, [sx_quote]
    mov     r8, qword ptr [rbp-16]
    call    wapp_lim
    test    rax, rax
    jz      wq_ret
    mov     qword ptr [rbp-24], rax          ; the path starts here
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-8]
    mov     r8, qword ptr [rbp-16]
    call    wapp_lim
    test    rax, rax
    jz      wq_ret
    mov     qword ptr [rbp-32], rax          ; and ends here, at the terminator
    ; ---- count the trailing backslash run ----------------------------------
    mov     r10, rax
    xor     r11, r11
wq_count:
    cmp     r10, qword ptr [rbp-24]
    jbe     wq_dbl                           ; back at the start: no more to see
    cmp     word ptr [r10-2], 5Ch
    jne     wq_dbl
    inc     r11
    sub     r10, 2
    jmp     wq_count
wq_dbl:
    mov     qword ptr [rbp-40], r11
wq_dbl_lp:
    cmp     qword ptr [rbp-40], 0
    je      wq_close
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [sx_bslash]
    mov     r8, qword ptr [rbp-16]
    call    wapp_lim
    test    rax, rax
    jz      wq_ret                           ; no room: build nothing, as ever
    mov     qword ptr [rbp-32], rax
    dec     qword ptr [rbp-40]
    jmp     wq_dbl_lp
wq_close:
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [sx_quote_sp]
    mov     r8, qword ptr [rbp-16]
    call    wapp_lim
wq_ret:
    add     rsp, 96
    pop     rbp
    ret
wapp_q endp

; =============================================================================
; has_ext(rcx = wide path, rdx = wide ".ext") -> eax = 1 if path ends with it.
; Case-insensitive.  Bounded: walks to the terminator first, never past it.
; =============================================================================
has_ext proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    xor     r9, r9
he_len:
    cmp     word ptr [rcx+r9*2], 0
    je      he_have
    inc     r9
    cmp     r9, 40000                       ; refuse an unterminated string
    jb      he_len
    xor     eax, eax
    jmp     he_ret
he_have:
    cmp     r9, 4
    jb      he_no
    mov     rcx, qword ptr [rbp-8]
    lea     rcx, [rcx+r9*2-8]               ; last four characters
    mov     rdx, qword ptr [rbp-16]
    WINCALL lstrcmpiW, rcx, rdx
    test    eax, eax
    jnz     he_no
    mov     eax, 1
    jmp     he_ret
he_no:
    xor     eax, eax
he_ret:
    add     rsp, 48
    pop     rbp
    ret
has_ext endp

; =============================================================================
; IUnknown, shared by both interfaces.  These three take the OBJECT BASE, which
; is what the IShellExtInit vtable already hands them; the IContextMenu vtable
; goes through the thunks below, which subtract the 8-byte interface offset
; first.  One implementation, two entry points - not two implementations.
; =============================================================================

; obj_addref(rcx = base) -> eax = new count
obj_addref proc
    mov     eax, 1
    lock xadd dword ptr [rcx+OBJ_REF], eax
    inc     eax
    ret
obj_addref endp

; obj_release(rcx = base) -> eax = new count; frees the object at zero
obj_release proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     eax, -1
    lock xadd dword ptr [rcx+OBJ_REF], eax
    dec     eax
    jnz     or_ret
    mov     qword ptr [rbp-8], rcx
    WINCALL GetProcessHeap
    WINCALL HeapFree, rax, 0, qword ptr [rbp-8]
    lock dec dword ptr [g_dll_refs]
    xor     eax, eax
or_ret:
    add     rsp, 48
    pop     rbp
    ret
obj_release endp

; obj_queryinterface(rcx = base, rdx = riid, r8 = ppv) -> HRESULT
obj_queryinterface proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx           ; base
    mov     qword ptr [rbp-16], rdx          ; riid
    mov     qword ptr [rbp-24], r8           ; ppv
    test    r8, r8
    jz      qi_badarg
    mov     qword ptr [r8], 0                ; NULL out on every failure path
    test    rdx, rdx
    jz      qi_badarg
    WINCALL guid_eq, qword ptr [rbp-16], addr IID_IContextMenu
    test    eax, eax
    jz      qi_try_init
    mov     rax, qword ptr [rbp-8]
    add     rax, OBJ_VTBL_CTX                ; the second vtable, not the base
    jmp     qi_hand
qi_try_init:
    WINCALL guid_eq, qword ptr [rbp-16], addr IID_IShellExtInit
    test    eax, eax
    jnz     qi_base
    WINCALL guid_eq, qword ptr [rbp-16], addr IID_IUnknown
    test    eax, eax
    jnz     qi_base
    mov     eax, E_NOINTERFACE
    jmp     qi_ret
qi_base:
    mov     rax, qword ptr [rbp-8]
qi_hand:
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10], rax
    mov     rcx, qword ptr [rbp-8]
    call    obj_addref
    mov     eax, S_OK
    jmp     qi_ret
qi_badarg:
    mov     eax, E_INVALIDARG
qi_ret:
    add     rsp, 64
    pop     rbp
    ret
obj_queryinterface endp

; ---- IContextMenu thunks: undo the interface offset, then tail into the above.
Ctx_QueryInterface proc
    sub     rcx, OBJ_VTBL_CTX
    jmp     obj_queryinterface
Ctx_QueryInterface endp

Ctx_AddRef proc
    sub     rcx, OBJ_VTBL_CTX
    jmp     obj_addref
Ctx_AddRef endp

Ctx_Release proc
    sub     rcx, OBJ_VTBL_CTX
    jmp     obj_release
Ctx_Release endp

; =============================================================================
; IShellExtInit::Initialize(this, pidlFolder, pdtobj, hkeyProgID)
;
; pidlFolder is the DROP TARGET - the folder the user dragged onto - and is the
; destination the verb will pass to myrkr.exe as --to.  It is NULL for an
; ordinary right-click, and that is now a supported case rather than a refusal:
; the same object serves both registrations (DragDropHandlers and
; ContextMenuHandlers), and with no drop target the output simply lands beside
; the source, which is where a right-click has always put it.
;
; That one pointer is the only thing distinguishing the two, and the failure
; mode is benign: if the shell ever passes a non-NULL pidlFolder on a
; right-click it is the folder the items already live in, so --to would name
; exactly the directory the output was going to anyway.
;
; The dragged files arrive as CF_HDROP on the data object and are copied out
; here, because the data object is not ours to hold past this call.  Every
; refusal below is a refusal to SHOW the verbs at all - fail-closed, since a
; verb that appears and then quietly does part of the job is worse than one that
; never appeared.
; =============================================================================
ShellExtInit_Initialize proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 224
    mov     qword ptr [rbp-8], rcx           ; this (= object base: init vtable)
    mov     qword ptr [rbp-16], rdx          ; pidlFolder
    mov     qword ptr [rbp-24], r8           ; IDataObject*
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [rax+OBJ_NFILES], 0
    mov     qword ptr [rax+OBJ_KIND], KIND_ENCRYPT
    mov     qword ptr [rax+OBJ_HASDEST], 0
    cmp     qword ptr [rbp-16], 0
    je      sei_nodest                       ; plain right-click: no --to, and that is fine
    lea     rdx, [rax+OBJ_DEST]
    WINCALL SHGetPathFromIDListW, qword ptr [rbp-16], rdx
    test    eax, eax
    jz      sei_fail                         ; a target was named but is not a
                                             ; filesystem folder - decline rather
                                             ; than write somewhere unexpected
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [rax+OBJ_HASDEST], 1
sei_nodest:
    cmp     qword ptr [rbp-24], 0
    je      sei_fail
    ; ---- FORMATETC { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL } ---
    mov     word  ptr [rbp-112], CF_HDROP
    mov     word  ptr [rbp-110], 0
    mov     dword ptr [rbp-108], 0
    mov     qword ptr [rbp-104], 0           ; ptd
    mov     dword ptr [rbp-96], DVASPECT_CONTENT
    mov     dword ptr [rbp-92], -1           ; lindex
    mov     dword ptr [rbp-88], TYMED_HGLOBAL
    mov     dword ptr [rbp-84], 0
    ; ---- STGMEDIUM, zeroed --------------------------------------------------
    mov     qword ptr [rbp-144], 0           ; tymed
    mov     qword ptr [rbp-136], 0           ; hGlobal
    mov     qword ptr [rbp-128], 0           ; pUnkForRelease
    ; ---- IDataObject::GetData ------------------------------------------------
    ; Hand-written rather than WINCALL: the target is a vtable slot, and spelling
    ; the load and the slot offset out is the point.
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rbp-112]
    lea     r8, [rbp-144]
    mov     rax, qword ptr [rcx]             ; IDataObject vtable
    call    qword ptr [rax+IDATAOBJ_GETDATA]
    test    eax, eax                         ; anything but S_OK: no medium to free
    jnz     sei_fail
    WINCALL GlobalLock, qword ptr [rbp-136]
    test    rax, rax
    jz      sei_release
    mov     qword ptr [rbp-32], rax          ; HDROP
    ; ---- how many files? -----------------------------------------------------
    WINCALL DragQueryFileW, qword ptr [rbp-32], 0FFFFFFFFh, 0, 0
    mov     dword ptr [rbp-40], eax
    test    eax, eax
    jz      sei_unlock
    cmp     eax, MAX_FILES
    ja      sei_unlock                       ; decline rather than drop the tail
    ; ---- copy each path into OBJ_PATHS, packed and NUL-separated -------------
    mov     rax, qword ptr [rbp-8]
    lea     r10, [rax+OBJ_PATHS]
    mov     qword ptr [rbp-56], r10          ; write cursor
    mov     qword ptr [rbp-64], PATHBUF_CHARS ; chars still free
    mov     qword ptr [rbp-48], 0            ; i
    mov     qword ptr [rbp-72], 1            ; every item so far is a .mrk
    mov     qword ptr [rbp-152], 1           ; every item so far is a .zip
sei_loop:
    mov     eax, dword ptr [rbp-40]
    cmp     qword ptr [rbp-48], rax
    jae     sei_done
    ; ask for the length first, so the copy below is bounded by a number the
    ; shell gave us AND by the space we actually have
    WINCALL DragQueryFileW, qword ptr [rbp-32], dword ptr [rbp-48], 0, 0
    test    eax, eax
    jz      sei_unlock
    inc     eax                              ; + terminator
    mov     r10d, eax
    cmp     r10, qword ptr [rbp-64]
    ja      sei_unlock
    WINCALL DragQueryFileW, qword ptr [rbp-32], dword ptr [rbp-48], \
            qword ptr [rbp-56], r10d
    test    eax, eax
    jz      sei_unlock
    mov     ecx, eax
    mov     qword ptr [rbp-80], rcx          ; chars written, excluding the NUL
    ; Classify.  Decrypt is offered only while EVERY item is a .mrk, extract only
    ; while EVERY item is a .zip.  A mixed bag - including .mrk and .zip together
    ; - is neither, and falls through to encrypt: that is the one operation that
    ; makes sense on an arbitrary selection, and re-encrypting a container is
    ; meaningful where decrypting a plain file is not.
    cmp     qword ptr [rbp-72], 0
    je      sei_ckzip
    WINCALL has_ext, qword ptr [rbp-56], addr sx_ext_mrk
    test    eax, eax
    jnz     sei_ckzip
    mov     qword ptr [rbp-72], 0
sei_ckzip:
    cmp     qword ptr [rbp-152], 0
    je      sei_adv
    WINCALL has_ext, qword ptr [rbp-56], addr sx_ext_zip
    test    eax, eax
    jnz     sei_adv
    mov     qword ptr [rbp-152], 0
sei_adv:
    mov     rax, qword ptr [rbp-80]
    inc     rax                              ; step over the terminator too
    mov     r10, qword ptr [rbp-56]
    lea     r10, [r10+rax*2]
    mov     qword ptr [rbp-56], r10
    sub     qword ptr [rbp-64], rax
    inc     qword ptr [rbp-48]
    jmp     sei_loop
sei_done:
    mov     rax, qword ptr [rbp-8]
    mov     r10d, dword ptr [rbp-40]
    mov     qword ptr [rax+OBJ_NFILES], r10
    ; all-.zip and all-.mrk cannot both hold for a non-empty selection, so the
    ; order of these two tests is a formality rather than a precedence rule.
    mov     r10, KIND_ENCRYPT
    cmp     qword ptr [rbp-152], 0
    je      sei_kmrk
    mov     r10, KIND_EXTRACT
    jmp     sei_kset
sei_kmrk:
    cmp     qword ptr [rbp-72], 0
    je      sei_kset
    mov     r10, KIND_DECRYPT
sei_kset:
    mov     qword ptr [rax+OBJ_KIND], r10
    WINCALL GlobalUnlock, qword ptr [rbp-136]
    WINCALL ReleaseStgMedium, addr rbp-144
    mov     eax, S_OK
    jmp     sei_ret
sei_unlock:
    WINCALL GlobalUnlock, qword ptr [rbp-136]
sei_release:
    WINCALL ReleaseStgMedium, addr rbp-144
sei_fail:
    mov     eax, E_FAIL
sei_ret:
    add     rsp, 224
    pop     rbp
    ret
ShellExtInit_Initialize endp

; =============================================================================
; IContextMenu::QueryContextMenu(this, hmenu, indexMenu, idCmdFirst, idCmdLast,
;                                uFlags)
; Returns HRESULT with the count of ids used in the low bits (MAKE_HRESULT).
; The 5th and 6th arguments are on the caller's stack: after "push rbp", arg5 is
; at [rbp+48] and arg6 at [rbp+56].
;
; Frame: locals reach down to [rbp-72] and a MENUITEMINFOW occupies
; [rbp-160 .. rbp-81].  rsp sits at rbp-256, so InsertMenuW's fifth argument -
; which spills to [rsp+32] = [rbp-224] - lands below both.
;
; It was 160 bytes before the menu bitmap, which put that spill at [rbp-128] and
; left no room for an 80-byte struct: the nearest place to put one would have
; been [rbp-152 .. rbp-73], straddling the spill.  Raised deliberately rather
; than squeezed.
;
; RAISING IT BROKE EXPLORER, and the way it broke is worth keeping: the prologue
; went to 256 and the epilogue's "add rsp, 160" did not, so every return popped
; rbp and then the return address from 96 bytes below where they were pushed.
; explorer.exe died on the first right-drag, with an access violation in no
; module at all - WER buckets that as BEX64, "faulting module: unknown", which
; names nothing and points nowhere.  A raw proc writes its frame size twice, by
; hand, and nothing in the language ties the two together.
;
; framecheck DOES read this file - it analyses raw push-rbp/sub-rsp procs as well
; as FRAME_PROLOG ones - and it now checks that the two numbers agree, in every
; raw proc in the tree.  The arithmetic below is still written out because the
; checker cannot know WHY 256 is the right number; it can only insist that the
; epilogue says the same thing.
; =============================================================================
ContextMenu_QueryContextMenu proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 256
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx          ; hmenu
    mov     r8d, r8d                         ; UINT: the top halves of r8/r9 are
    mov     r9d, r9d                         ; undefined and both are used as
    mov     qword ptr [rbp-72], r8           ; 64-bit values below - indexMenu
    mov     qword ptr [rbp-32], r9           ; idCmdFirst
    call    obj_from_ctx                     ; rcx still = this
    mov     qword ptr [rbp-40], rax          ; object base
    ; CMF_DEFAULTONLY: the shell only wants the default verb, which is never
    ; ours.  Adding an item here is what puts a stray entry on double-click.
    mov     eax, dword ptr [rbp+56]          ; uFlags
    test    eax, CMF_DEFAULTONLY
    jnz     qcm_none
    ; the shell must have left us at least one id
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [rbp+48]          ; idCmdLast
    ja      qcm_none
    ; Initialize declined or captured nothing -> no verb
    mov     rax, qword ptr [rbp-40]
    cmp     qword ptr [rax+OBJ_NFILES], 0
    je      qcm_none
    ; ---- label -------------------------------------------------------------
    ; The right-CLICK menu keeps one label whatever the selection is, because
    ; that verb always does the same thing: it opens the window.  Naming the
    ; operation there would promise something the window has not been told to do
    ; yet - it still has to ask for a password, and for a container it browses.
    ;
    ; The right-DRAG menu names the operation, because that one runs on release.
    ; Two labels and not three: a .mrk and a .zip differ in how they are opened
    ; and not in what the user is asking for, so they share a verb.
    lea     rdx, [sx_menu_open]
    mov     rax, qword ptr [rbp-40]
    cmp     qword ptr [rax+OBJ_HASDEST], 0
    je      qcm_label_set                    ; no drop target -> a right-click
    lea     rdx, [sx_menu_decrypt]
    cmp     qword ptr [rax+OBJ_KIND], KIND_ENCRYPT
    jne     qcm_label_set
    lea     rdx, [sx_menu_encrypt]
qcm_label_set:
    mov     qword ptr [rbp-48], rdx
    ; ---- where it goes ------------------------------------------------------
    ; Two menus, two rules.
    ;
    ; A SHORTCUT menu (plain right-click, no drop target) has a region set aside
    ; for third-party verbs and indexMenu points at it, so we insert there and
    ; add nothing else.  That is the documented contract and there is no reason
    ; to fight it.
    ;
    ; The DRAG menu does not.  MEASURED, not assumed: by the time Explorer
    ; queries a DragDropHandler that menu ALREADY holds Copy here / Move here /
    ; Create shortcuts here, a separator and Cancel - and, for a .zip, an
    ; "Extract..." group above all of them.  An earlier version appended at the
    ; end on the theory that Cancel came afterwards; it does not, and the verb
    ; appeared underneath Cancel.  So:
    ;
    ;   .zip  -> at the first separator, i.e. directly under "Extract...", so it
    ;            reads as a second extraction choice beside the shell's own
    ;   else  -> index 0 with a separator beneath it, so encrypt/decrypt is
    ;            offered first without displacing "Move here", the bold default
    ;            a plain drag would use
    mov     qword ptr [rbp-56], 0            ; 1 = also insert our own separator
    mov     qword ptr [rbp-24], 0            ; insert position
    mov     rax, qword ptr [rbp-40]
    cmp     qword ptr [rax+OBJ_HASDEST], 0
    jne     qcm_dragpos
    mov     r10, qword ptr [rbp-72]          ; shortcut menu: where we were asked
    mov     qword ptr [rbp-24], r10
    jmp     qcm_insert
qcm_dragpos:
    cmp     qword ptr [rax+OBJ_KIND], KIND_EXTRACT
    je      qcm_findsep
    mov     qword ptr [rbp-56], 1
    jmp     qcm_insert
qcm_findsep:
    ; walk to the first separator; that is the end of the "Extract..." group.
    ; If there is none (no zip handler contributed), this stops at the item
    ; count and the verb lands at the end of the menu rather than nowhere.
    WINCALL GetMenuItemCount, qword ptr [rbp-16]
    cmp     eax, 0
    jl      qcm_none                         ; not a menu we can measure
    mov     dword ptr [rbp-64], eax
qcm_scan:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [rbp-64]
    jae     qcm_insert
    WINCALL GetMenuState, qword ptr [rbp-16], dword ptr [rbp-24], MF_BYPOSITION
    cmp     eax, -1
    je      qcm_insert
    test    eax, MF_SEPARATOR
    jnz     qcm_insert
    inc     qword ptr [rbp-24]
    jmp     qcm_scan
qcm_insert:
    ; InsertMenuItemW and not InsertMenuW: only the struct form can carry
    ; hbmpItem, which is the whole point of the change.  The bitmap may be null
    ; (see menu_bitmap) and the item is correct either way - MIIM_BITMAP with a
    ; null handle means "no picture", not "failed".
    lea     r11, [rbp-160]                   ; MENUITEMINFOW
    xor     r10, r10
qcm_zmii:
    mov     qword ptr [r11+r10], 0
    add     r10, 8
    cmp     r10, MII_BYTES
    jb      qcm_zmii
    mov     dword ptr [r11+MII_cbSize], MII_BYTES
    mov     dword ptr [r11+MII_fMask], MIIM_ID or MIIM_STRING or MIIM_BITMAP or MIIM_FTYPE
    mov     dword ptr [r11+MII_fType], MFT_STRING
    mov     eax, dword ptr [rbp-32]          ; idCmdFirst
    mov     dword ptr [r11+MII_wID], eax
    mov     rax, qword ptr [rbp-48]          ; label
    mov     qword ptr [r11+MII_dwTypeData], rax
    call    menu_bitmap                      ; clobbers rax/r10/r11
    mov     qword ptr [rbp-160+MII_hbmpItem], rax
    WINCALL InsertMenuItemW, qword ptr [rbp-16], dword ptr [rbp-24], 1, addr rbp-160
    test    eax, eax
    jz      qcm_none
    ; a separator carries no id, so this does not change the count we report
    cmp     qword ptr [rbp-56], 0
    je      qcm_done
    mov     rax, qword ptr [rbp-24]
    inc     rax
    mov     qword ptr [rbp-24], rax
    WINCALL InsertMenuW, qword ptr [rbp-16], dword ptr [rbp-24], \
            <MF_BYPOSITION or MF_SEPARATOR>, 0, 0
qcm_done:
    mov     eax, HR_ONE_ID
    jmp     qcm_ret
qcm_none:
    xor     eax, eax                         ; S_OK, zero ids used
qcm_ret:
    add     rsp, 256                         ; MUST match the sub above
    pop     rbp
    ret
ContextMenu_QueryContextMenu endp

; =============================================================================
; IContextMenu::GetCommandString - the shell asks for help text / a verb name.
; Declining is legal and keeps this file smaller; the menu string is already set.
; InvokeCommand relies on this: because we publish no verb name, a call carrying
; a verb STRING cannot be for us, and is refused there.
; =============================================================================
ContextMenu_GetCommandString proc
    mov     eax, E_NOTIMPL
    ret
ContextMenu_GetCommandString endp

; =============================================================================
; IContextMenu::InvokeCommand(this, CMINVOKECOMMANDINFO*)
; Builds  "<dir>\myrkr.exe" "<file>" ... --to "<droptarget>"  and starts it.
; Nothing else happens here - see the header for why the DLL never does the work.
;
; Frame: locals occupy [rbp-8 .. rbp-224]; rsp sits at rbp-352, so the 80-byte
; outgoing-argument area CreateProcessW's ten arguments need ([rsp .. rsp+79] =
; [rbp-352 .. rbp-273]) cannot reach a local.  That overlap is the raw-proc bug
; class tools/framecheck.py exists to catch, and it cannot see a plain prologue.
; =============================================================================
ContextMenu_InvokeCommand proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 352
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-80], rdx          ; CMINVOKECOMMANDINFO*
    call    obj_from_ctx
    mov     qword ptr [rbp-16], rax          ; object base
    ; ---- is this invocation ours? -------------------------------------------
    ; We published exactly one item, at offset 0, with no verb name.  lpVerb is
    ; either a string pointer or a packed offset (IS_INTRESOURCE: nothing above
    ; the low 16 bits).  Anything else belongs to another handler; E_FAIL is the
    ; documented way to say so, and is the one failure worth reporting.
    mov     rdx, qword ptr [rbp-80]
    test    rdx, rdx
    jz      ic_badverb
    mov     rax, qword ptr [rdx+16]          ; lpVerb
    cmp     rax, 0FFFFh
    ja      ic_badverb
    test    eax, eax
    jnz     ic_badverb
    mov     rax, qword ptr [rbp-16]
    cmp     qword ptr [rax+OBJ_NFILES], 0
    je      ic_done
    ; ---- one scratch block: the command line, then our own module path ------
    ; CreateProcessW writes into lpCommandLine, so it must be writable memory -
    ; a .const literal would fault, and a .data? buffer would be shared by every
    ; object in this Explorer process.
    WINCALL GetProcessHeap
    WINCALL HeapAlloc, rax, 0, <(CMDBUF_CHARS + DESTBUF_CHARS)*2>
    test    rax, rax
    jz      ic_done
    mov     qword ptr [rbp-24], rax          ; block, for the free below
    mov     qword ptr [rbp-32], rax          ; command line
    lea     r10, [rax+CMDBUF_CHARS*2]
    mov     qword ptr [rbp-40], r10          ; our module path
    lea     r10, [rax+(CMDBUF_CHARS-1)*2]
    mov     qword ptr [rbp-56], r10          ; one past the last writable char
    ; ---- our own directory ---------------------------------------------------
    WINCALL GetModuleFileNameW, qword ptr [g_hinst_dll], qword ptr [rbp-40], \
            DESTBUF_CHARS
    test    eax, eax
    jz      ic_free
    cmp     eax, DESTBUF_CHARS
    jae     ic_free                          ; truncated - refuse the guess
    ; cut back to the last backslash
    mov     rcx, qword ptr [rbp-40]
    xor     r9, r9
    mov     r10, -1
ic_scan:
    movzx   eax, word ptr [rcx+r9*2]
    test    eax, eax
    je      ic_scandone
    cmp     eax, 5Ch                         ; '\'
    jne     ic_scannext
    mov     r10, r9
ic_scannext:
    inc     r9
    cmp     r9, DESTBUF_CHARS
    jb      ic_scan
ic_scandone:
    cmp     r10, 0
    jl      ic_free
    mov     word ptr [rcx+r10*2+2], 0        ; keep the trailing backslash
    ; ---- "<dir>myrkr.exe" ----------------------------------------------------
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [sx_quote]
    mov     r8, qword ptr [rbp-56]
    call    wapp_lim
    test    rax, rax
    jz      ic_free
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-56]
    call    wapp_lim
    test    rax, rax
    jz      ic_free
    mov     rcx, rax
    lea     rdx, [sx_exe]
    mov     r8, qword ptr [rbp-56]
    call    wapp_lim
    test    rax, rax
    jz      ic_free
    mov     rcx, rax
    lea     rdx, [sx_quote_sp]
    mov     r8, qword ptr [rbp-56]
    call    wapp_lim
    test    rax, rax
    jz      ic_free
    mov     qword ptr [rbp-48], rax          ; running end of the command line
    ; ---- each dragged path, quoted ------------------------------------------
    mov     rax, qword ptr [rbp-16]
    lea     r10, [rax+OBJ_PATHS]
    mov     qword ptr [rbp-64], r10          ; read cursor
    mov     qword ptr [rbp-72], 0            ; i
ic_ploop:
    mov     rax, qword ptr [rbp-16]
    mov     rax, qword ptr [rax+OBJ_NFILES]
    cmp     qword ptr [rbp-72], rax
    jae     ic_pdone
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-64]
    mov     r8, qword ptr [rbp-56]
    call    wapp_q
    test    rax, rax
    jz      ic_free
    mov     qword ptr [rbp-48], rax
    mov     rcx, qword ptr [rbp-64]
    call    wlen
    lea     r10, [rax*2+2]                   ; the path and its terminator
    add     qword ptr [rbp-64], r10
    inc     qword ptr [rbp-72]
    jmp     ic_ploop
ic_pdone:
    ; ---- --to "<droptarget>", only when there IS one --------------------------
    ; A plain right-click has no drop target, so the command line ends after the
    ; paths and myrkr.exe puts the output beside the source - which is what a
    ; right-click has always done.  --to sits AFTER the file arguments because
    ; gui_main requires argv[1] to be a path; see src/gui.asm:gm_argloop.
    mov     r10, qword ptr [rbp-16]
    cmp     qword ptr [r10+OBJ_HASDEST], 0
    je      ic_launch
    mov     rcx, qword ptr [rbp-48]
    lea     rdx, [sx_to_sp]
    mov     r8, qword ptr [rbp-56]
    call    wapp_lim
    test    rax, rax
    jz      ic_free
    mov     rcx, rax
    mov     r10, qword ptr [rbp-16]
    lea     rdx, [r10+OBJ_DEST]
    mov     r8, qword ptr [rbp-56]
    call    wapp_q
    test    rax, rax
    jz      ic_free
ic_launch:
    ; ---- launch and let go ---------------------------------------------------
    lea     rcx, [rbp-192]                   ; STARTUPINFOW
    xor     r9, r9
ic_zsi:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, SIZEOF_STARTUPINFOW
    jb      ic_zsi
    mov     dword ptr [rbp-192], SIZEOF_STARTUPINFOW    ; cb
    lea     rcx, [rbp-224]                   ; PROCESS_INFORMATION
    xor     r9, r9
ic_zpi:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, SIZEOF_PROCINFO
    jb      ic_zpi
    ; no inherited handles, no creation flags, no environment or directory of
    ; ours: myrkr.exe is started as plainly as a double-click would start it
    WINCALL CreateProcessW, 0, qword ptr [rbp-32], 0, 0, 0, 0, 0, 0, \
            addr rbp-192, addr rbp-224
    test    eax, eax
    jz      ic_free
    WINCALL CloseHandle, qword ptr [rbp-224]         ; hProcess
    WINCALL CloseHandle, qword ptr [rbp-216]         ; hThread
ic_free:
    WINCALL GetProcessHeap
    WINCALL HeapFree, rax, 0, qword ptr [rbp-24]
ic_done:
    mov     eax, S_OK                        ; a failure to launch is not
    jmp     ic_ret                           ; Explorer's problem to report
ic_badverb:
    mov     eax, E_FAIL
ic_ret:
    add     rsp, 352
    pop     rbp
    ret
ContextMenu_InvokeCommand endp

; =============================================================================
; IClassFactory.  One static instance (g_factory) - it holds no per-call state,
; so there is nothing to allocate and nothing to free.  Its AddRef/Release move
; the module reference count instead, which is what keeps COM from unloading the
; DLL while the shell still holds the factory.
; =============================================================================
CF_QueryInterface proc                       ; (this, riid, ppv)
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    test    r8, r8
    jz      cqi_badarg
    mov     qword ptr [r8], 0
    test    rdx, rdx
    jz      cqi_badarg
    WINCALL guid_eq, qword ptr [rbp-16], addr IID_IClassFactory
    test    eax, eax
    jnz     cqi_hand
    WINCALL guid_eq, qword ptr [rbp-16], addr IID_IUnknown
    test    eax, eax
    jnz     cqi_hand
    mov     eax, E_NOINTERFACE
    jmp     cqi_ret
cqi_hand:
    mov     r10, qword ptr [rbp-24]
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [r10], rax
    lock inc dword ptr [g_dll_refs]
    mov     eax, S_OK
    jmp     cqi_ret
cqi_badarg:
    mov     eax, E_INVALIDARG
cqi_ret:
    add     rsp, 64
    pop     rbp
    ret
CF_QueryInterface endp

CF_AddRef proc
    mov     eax, 1
    lock xadd dword ptr [g_dll_refs], eax
    inc     eax
    ret
CF_AddRef endp

CF_Release proc
    mov     eax, -1
    lock xadd dword ptr [g_dll_refs], eax
    dec     eax
    ret
CF_Release endp

; CF_CreateInstance(this, pUnkOuter, riid, ppv)
CF_CreateInstance proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     qword ptr [rbp-8], rdx           ; pUnkOuter
    mov     qword ptr [rbp-16], r8           ; riid
    mov     qword ptr [rbp-24], r9           ; ppv
    test    r9, r9
    jz      cci_badarg
    mov     qword ptr [r9], 0
    cmp     qword ptr [rbp-8], 0
    jne     cci_noagg                        ; we are not aggregatable
    WINCALL GetProcessHeap
    WINCALL HeapAlloc, rax, HEAP_ZERO_MEMORY, OBJ_SIZE
    test    rax, rax
    jz      cci_oom
    mov     qword ptr [rbp-32], rax
    lea     r10, [vtbl_ShellExtInit]
    mov     qword ptr [rax+OBJ_VTBL_INIT], r10
    lea     r10, [vtbl_ContextMenu]
    mov     qword ptr [rax+OBJ_VTBL_CTX], r10
    mov     dword ptr [rax+OBJ_REF], 1
    lock inc dword ptr [g_dll_refs]
    ; hand out whichever interface was asked for, then drop OUR reference: the
    ; object now lives or dies by the one QueryInterface took.
    WINCALL obj_queryinterface, qword ptr [rbp-32], qword ptr [rbp-16], \
            qword ptr [rbp-24]
    mov     dword ptr [rbp-40], eax
    mov     rcx, qword ptr [rbp-32]
    call    obj_release
    mov     eax, dword ptr [rbp-40]
    jmp     cci_ret
cci_oom:
    mov     eax, E_OUTOFMEMORY
    jmp     cci_ret
cci_noagg:
    mov     eax, CLASS_E_NOAGGREGATION
    jmp     cci_ret
cci_badarg:
    mov     eax, E_INVALIDARG
cci_ret:
    add     rsp, 96
    pop     rbp
    ret
CF_CreateInstance endp

; CF_LockServer(this, fLock) - hold the DLL in memory across CreateInstance calls
CF_LockServer proc
    test    edx, edx
    jz      cls_unlock
    lock inc dword ptr [g_dll_refs]
    jmp     cls_ret
cls_unlock:
    lock dec dword ptr [g_dll_refs]
cls_ret:
    mov     eax, S_OK
    ret
CF_LockServer endp

; =============================================================================
; DLL entry points.  /entry:DllMain in build.cmd, exports in myrkrshell.def -
; there is no CRT here to run _DllMainCRTStartup, and nothing that needs one.
; =============================================================================
DllMain proc                                 ; (hinstDLL, fdwReason, lpvReserved)
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    cmp     edx, DLL_PROCESS_ATTACH
    jne     dm_ok
    mov     qword ptr [g_hinst_dll], rcx     ; InvokeCommand finds myrkr.exe
    WINCALL DisableThreadLibraryCalls, rcx   ; next to this module
dm_ok:
    mov     eax, 1
    add     rsp, 48
    pop     rbp
    ret
DllMain endp

DllGetClassObject proc                       ; (rclsid, riid, ppv)
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rdx           ; riid
    mov     qword ptr [rbp-16], r8           ; ppv
    test    r8, r8
    jz      dgc_badarg
    mov     qword ptr [r8], 0
    test    rcx, rcx
    jz      dgc_badarg
    WINCALL guid_eq, rcx, addr CLSID_MyrkrDrop
    test    eax, eax
    jz      dgc_noclass
    WINCALL CF_QueryInterface, addr g_factory, qword ptr [rbp-8], \
            qword ptr [rbp-16]
    jmp     dgc_ret
dgc_noclass:
    mov     eax, CLASS_E_CLASSNOTAVAILABLE
    jmp     dgc_ret
dgc_badarg:
    mov     eax, E_INVALIDARG
dgc_ret:
    add     rsp, 64
    pop     rbp
    ret
DllGetClassObject endp

DllCanUnloadNow proc
    mov     eax, S_FALSE
    cmp     dword ptr [g_dll_refs], 0
    jne     dcu_ret
    mov     eax, S_OK
dcu_ret:
    ret
DllCanUnloadNow endp

; =============================================================================
; Vtables, last so that every entry is a backward reference to a proc already
; assembled.  Slot order is the interface's, not ours, and a swapped pair here
; is not a build error - it is Explorer calling Release when it meant AddRef.
; =============================================================================
.const
align 8
vtbl_ShellExtInit label qword
    dq      obj_queryinterface               ; IUnknown::QueryInterface
    dq      obj_addref                       ; IUnknown::AddRef
    dq      obj_release                      ; IUnknown::Release
    dq      ShellExtInit_Initialize

align 8
vtbl_ContextMenu label qword
    dq      Ctx_QueryInterface
    dq      Ctx_AddRef
    dq      Ctx_Release
    dq      ContextMenu_QueryContextMenu
    dq      ContextMenu_InvokeCommand
    dq      ContextMenu_GetCommandString

align 8
vtbl_ClassFactory label qword
    dq      CF_QueryInterface
    dq      CF_AddRef
    dq      CF_Release
    dq      CF_CreateInstance
    dq      CF_LockServer

.data
align 8
g_factory           dq vtbl_ClassFactory     ; the whole of the factory object

end
