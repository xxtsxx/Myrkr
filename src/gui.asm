; =============================================================================
; gui.asm - Win32 GUI front-end for Myrkr (myrkrw.exe, /subsystem:windows)
; -----------------------------------------------------------------------------
; The GUI takes its inputs ONLY from the command line (argv[1..]).  The inputs
; are auto-classified once, up front:
;   * a single argument whose name ends in ".mrk" AND whose header carries the
;     container magic  -> DECRYPT mode
;   * anything else (a single non-container file, or several files/folders)
;                                                 -> ENCRYPT mode
;
; ENCRYPT mode shows: a tree-view of the selected inputs, a password + confirm
; pair (masked, with a Show/Hide toggle), a live entropy strength meter, five
; requirement indicators (lower / upper / number / symbol / length) and an
; Encrypt button that only enables once the two passwords match and satisfy the
; policy.  DECRYPT mode shows: the input file, a suggested destination (the
; input path with the ".mrk" extension removed) plus a Change... folder
; picker, one masked password field with a Show/Hide toggle, and a Decrypt
; button.  Either operation runs on a background worker thread with a live
; progress bar + Cancel so the window stays responsive.
;
; THREADING / HARDENING NOTE: the software shadow stack maintained by
; FRAME_PROLOG is a single process-global structure, so it must only ever be
; used by ONE thread at a time.  Every proc in THIS file is therefore "raw"
; (no FRAME_PROLOG) and the UI thread calls only raw procs + Win32 APIs.  The
; hardened crypto (do_encrypt/do_decrypt and everything they call) runs solely
; on the worker thread, which is the exclusive user of the shadow stack while
; it runs.  Startup init (cpu_gate/hardening_init/con_init) runs sequentially
; on the main thread before any worker exists.
; =============================================================================

include macros.inc

; ---- our runtime (shared with the CLI build) --------------------------------
extern cpu_gate:proc
extern hardening_init:proc
extern con_init:proc
extern con_attach_parent:proc
extern iat_lockdown:proc
extern parse_cmdline:proc                ; CLI tokenizer (main.asm)
extern is_cli_command:proc               ; argv[1] is a known verb? (main.asm)
extern dispatch:proc                     ; CLI command dispatch (main.asm)
extern log_result:proc                   ; audit log (log.asm)
extern print_err:proc
extern secure_zero:proc
extern secmem_wipe_all:proc              ; secmem.asm: wipe + unlock all secrets
extern do_encrypt:proc
extern do_decrypt:proc
extern do_unzip:proc
extern zip_is_encrypted:proc
extern zip_to_index:proc
extern zip_delete_marked:proc
extern do_zip:proc
extern check_password_policy:proc
extern progress_abort:proc
extern prog_speed_x10:proc               ; progress.asm: average MB/s x10, 0 = n/a
extern prog_eta_s:proc                   ; progress.asm: seconds left, -1 = n/a
extern input_size:proc                  ; recursive size of a positional (size column)

externdef g_cfg_in:qword
externdef g_cfg_out:qword
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_positionals:qword
externdef g_poscount:qword
externdef g_prog_total:qword
externdef g_prog_startms:qword
externdef g_prog_label:qword
externdef g_prog_lablen:dword
externdef g_prog_done:qword
externdef g_cur_input:qword
externdef g_cfg_compress:dword           ; 0 store / 1 xpress (consumed by do_pack)
externdef g_cfg_compress_set:dword       ; 1 = explicit (skip size-based default)
externdef g_file_done:qword              ; per-positional bytes done (MAX_ARGS entries)
externdef g_file_total:qword             ; per-positional total bytes (MAX_ARGS entries)

; ---- Win32 imports ----------------------------------------------------------
extern GetModuleHandleW:proc
extern GetCommandLineW:proc
extern CommandLineToArgvW:proc
extern CreateThread:proc
extern sstk_thread_init:proc
extern sstk_thread_free:proc
extern ExitProcess:proc
extern GetFileAttributesW:proc
extern GetFileAttributesExW:proc
extern FindFirstFileW:proc
extern FindNextFileW:proc
extern FindClose:proc
extern CreateFileW:proc
extern ReadFile:proc
extern CloseHandle:proc
extern WideCharToMultiByte:proc
extern GetStockObject:proc
extern InitCommonControlsEx:proc
extern RegisterClassExW:proc
extern CreateWindowExW:proc
extern DefWindowProcW:proc
extern ShowWindow:proc
extern ShowScrollBar:proc
extern SetWindowPos:proc
extern SetLayeredWindowAttributes:proc
extern SetForegroundWindow:proc
extern WaitForSingleObject:proc
extern secdesk_open:proc                 ; secdesk.asm
extern secdesk_enter:proc
extern secdesk_leave:proc
extern secdesk_close:proc
extern UpdateWindow:proc
extern GetMessageW:proc
extern TranslateMessage:proc
extern DispatchMessageW:proc
extern IsDialogMessageW:proc
extern LoadCursorW:proc
extern SetCursor:proc
extern LoadIconW:proc
extern PostQuitMessage:proc
extern DestroyWindow:proc
extern SendMessageW:proc
extern PostMessageW:proc
extern SetWindowTextW:proc
extern GetWindowTextW:proc
extern GetWindowTextLengthW:proc
extern EnableWindow:proc
extern IsWindowEnabled:proc
extern IsWindowVisible:proc
extern GetDlgCtrlID:proc
extern MessageBoxW:proc
extern SetTimer:proc
extern GetTickCount64:proc
extern KillTimer:proc
extern SetFocus:proc
extern GetFocus:proc
extern InvalidateRect:proc
extern RedrawWindow:proc
extern GetSystemMetrics:proc
extern SetWindowRgn:proc
extern CreateRoundRectRgn:proc
extern CreateAcceleratorTableW:proc
extern TranslateAcceleratorW:proc
extern SetWindowLongPtrW:proc
ifdef DBG_TRACE
extern GetEnvironmentVariableW:proc
endif
extern CallWindowProcW:proc
extern GetDC:proc
extern ReleaseDC:proc
extern GetClientRect:proc
extern GetWindowRect:proc
extern MonitorFromWindow:proc
extern GetMonitorInfoW:proc
extern TrackMouseEvent:proc
extern GetWindowLongPtrW:proc
extern GetTextFaceW:proc
extern SetWindowTheme:proc
extern GetSaveFileNameW:proc
; --- action-log viewer --------------------------------------------------------
extern rlog_begin:proc                      ; ramlog.asm: start a new log
extern rlog_wipe:proc                       ; ramlog.asm: release + wipe it
extern rlog_finish:proc                     ; ramlog.asm: the closing summary
externdef g_rl_nadd:qword                   ; ramlog.asm: entries logged, by kind
externdef g_rl_next:qword
externdef g_rl_curname:byte                 ; ramlog.asm: the entry in progress
externdef g_rl_curlen:dword
extern rlog_flatten:proc                    ; ramlog.asm: one contiguous copy
extern mem_alloc:proc
extern mem_free:proc
extern WriteFile:proc
extern GlobalAlloc:proc
extern GlobalLock:proc
extern GlobalUnlock:proc
extern OpenClipboard:proc
extern EmptyClipboard:proc
extern SetClipboardData:proc
extern CloseClipboard:proc
; the container inventory (pack.asm) - what container_load shows
extern idx_read:proc
extern idx_find:proc
extern idx_mark_dropped:proc
extern idx_mark_flag:proc
extern idx_pick_collect:proc
extern pick_reset:proc
externdef g_pick_active:dword
; Set by do_unpack when an extraction failed AFTER writing entries out.  The
; error box says something different in that case - see m_part_extract.
externdef g_unpack_partial:dword

.data?
ALIGN 8
g_fad       db 40 dup (?)                  ; WIN32_FILE_ATTRIBUTE_DATA
.code

extern do_remove_marked:proc
extern do_add:proc
extern do_zip_add:proc
externdef g_keep_key:dword
externdef g_vol_limit:qword              ; volume.asm: 0 = do not split
extern vset_open:proc                    ; volume.asm: a container may be a set
extern vset_close:proc
extern vol_get:proc
extern vol_part_suffix:proc
; Where an append lands inside the archive.  Lives in pack.asm because that is
; where the entry name is built; the GUI is the only thing that ever sets it.
externdef g_add_prefix:byte
externdef g_add_prefixlen:qword
; The STAGED layout - where each input lands, chosen per input rather than per
; run.  Indexed by position, which is why remove_selected has to move it.
externdef g_pos_prefix:dword
externdef g_pfx_arena:byte
extern pfx_reset:proc
extern pfx_stage:proc
externdef g_key:byte
extern MultiByteToWideChar:proc
externdef g_idxptr:qword
extern idx_find:proc
; the drag-out objects (estream.asm): the data object and the drag itself
extern do_create:proc
extern do_add_tree:proc
extern es_drag:proc
extern es_key_live:proc
DO_count            equ 16                   ; mirrors estream.asm
DRAGNAME_BYTES      equ 4096
externdef g_idxlen:qword
externdef g_idxcount:qword
externdef g_idxflags:qword
; uxtheme's dark mode is reachable only by ordinal, so it has to be resolved at
; run time rather than imported.  See enable_dark_mode.
extern LoadLibraryW:proc
extern GetProcAddress:proc
extern GetCursorPos:proc
extern CreateRectRgn:proc
; the overlay scrollbar blends a 1x1 source over the rows (see draw_lv_thumb)
extern GetViewportOrgEx:proc
extern OffsetRgn:proc
extern CreateCompatibleDC:proc
extern CreateCompatibleBitmap:proc
extern DeleteDC:proc
extern AlphaBlend:proc
extern ScreenToClient:proc
extern SHGetFileInfoW:proc
extern ShellExecuteW:proc
; Dropping onto the WINDOW.  Until now inputs only ever arrived on the command
; line - from the exe icon, "Open with", or the shell extension - so a window
; opened with no arguments had no way to be given anything.
extern DragAcceptFiles:proc
extern DragQueryFileW:proc
extern DragFinish:proc
; WM_DROPFILES is subject to UIPI message filtering, so a window that has not
; opted in never receives it and the sender is told ERROR_INVALID_HANDLE - the
; drop simply does nothing, with no error anywhere.  DragAcceptFiles is
; documented to set the filter, but measured here it does not: posting
; WM_DROPFILES was refused while WM_COMMAND to the same window succeeded.  So
; ask for it explicitly rather than depend on a side effect.
extern ChangeWindowMessageFilterEx:proc
; ---- OLE drag-and-drop ------------------------------------------------------
; DragAcceptFiles delivers exactly one notification, at the moment of the drop.
; There is no drag-OVER notification at all, so a window using it cannot paint
; where a file would land, and cannot set the copy-vs-refused cursor either.
; A registered IDropTarget gets DragEnter/DragOver/DragLeave as well.
;
; It also makes this path TESTABLE for the first time.  A synthetic
; WM_DROPFILES cannot reach the window from another process (UIPI blocks it -
; the control experiment posted one at the encrypt view, where the path has
; shipped for years, and it did nothing either), and driving a real OLE drag
; hangs, because DoDragDrop only calls QueryContinueDrag when the drag loop
; receives input and a scripted drag has a stationary cursor.  An interface can
; simply be CALLED: no drag loop, no cursor, no UIPI.  See tests/droptest.ps1.
extern OleInitialize:proc
extern OleUninitialize:proc
extern RegisterDragDrop:proc
extern RevokeDragDrop:proc
extern ReleaseStgMedium:proc
ifdef DBG_TRACE
extern OleGetClipboard:proc
endif
extern CoTaskMemFree:proc
extern CoCreateInstance:proc
extern CoInitializeEx:proc
extern CoUninitialize:proc
; ---- Fluent theming (owner-draw buttons, control colours, validation) --------
extern CreateFontW:proc
extern CreateSolidBrush:proc
extern CreatePen:proc
extern SelectObject:proc
extern RoundRect:proc
extern SetCapture:proc
extern ReleaseCapture:proc
extern GetCapture:proc
extern DeleteObject:proc
extern SetTextColor:proc
extern SetBkColor:proc
extern SetBkMode:proc
extern DrawTextW:proc
extern GetTextExtentPoint32W:proc
extern FillRect:proc
extern FrameRect:proc
extern TextOutW:proc
extern LoadImageW:proc
extern DrawIconEx:proc
extern BeginPath:proc
extern EndPath:proc
extern SelectClipPath:proc
extern SelectClipRgn:proc
extern MoveToEx:proc
extern LineTo:proc
extern Ellipse:proc
extern RegCreateKeyExW:proc
extern RegOpenKeyExW:proc
extern RegQueryValueExW:proc
extern RegSetValueExW:proc
extern RegCloseKey:proc
externdef g_cfg_loglevel:dword              ; log verbosity (main.asm)
externdef g_cfg_securedesk:dword            ; private-desktop password entry (main.asm)
externdef g_cfg_pwminlen:dword              ; password policy: min length (main.asm)
externdef g_cfg_pwminclasses:dword          ; password policy: min char classes
externdef g_cfg_t:dword                     ; Argon2 time cost (main.asm)
externdef g_cfg_m:dword                     ; Argon2 memory, KiB (main.asm)

; ---- constants --------------------------------------------------------------
WS_POPUP            equ 080000000h
WS_CLIPCHILDREN     equ 002000000h          ; keep the parent out of child rects
WS_CLIPSIBLINGS     equ 004000000h          ; keep a child out of its siblings' rects
WS_EX_TOOLWINDOW    equ 000000080h          ; no taskbar / alt-tab entry
WS_EX_LAYERED       equ 000080000h          ; translucent (alpha) window
LWA_ALPHA           equ 000000002h
WIN_ALPHA           equ 250                  ; 98% opaque (0.98 * 255)
; Corner diameter for every borderless window here.  Named because it is used
; TWICE per window and the two have to agree: once as the region the window is
; clipped to, and once as the radius hairline_rect draws its edge at.  A frame
; drawn at a different radius than the clip is a frame with its corners cut off,
; which is exactly what a square one looked like.
WIN_ROUND           equ 16
CS_DROPSHADOW       equ 000020000h          ; class style: drop shadow
WS_CHILD            equ 040000000h
WS_VISIBLE          equ 010000000h
WS_TABSTOP          equ 000010000h
ES_AUTOHSCROLL      equ 000000080h
ES_PASSWORD         equ 000000020h
EM_LIMITTEXT        equ 0000000C5h
EM_SETSEL           equ 0000000B1h
EM_SCROLLCARET      equ 0000000B7h
INFINITE            equ 0FFFFFFFFh
ES_READONLY         equ 000000800h
ES_MULTILINE        equ 000000004h
ES_AUTOVSCROLL      equ 000000040h
WS_VSCROLL          equ 000200000h
SS_NOTIFY           equ 000000100h          ; static sends STN_CLICKED via WM_COMMAND
BS_OWNERDRAW        equ 00000000Bh

; list-view styles
LVS_REPORT          equ 00001h
LVS_NOCOLUMNHEADER  equ 04000h
LVS_NOSORTHEADER    equ 08000h
; The listview is handed the SHELL's system image list (populate_list, via
; SHGetFileInfo/SHGFI_SYSICONINDEX).  Without this style the control OWNS what
; it is given and destroys it - both at window teardown and when a second list
; is assigned - which frees an image list the whole process shares.  It went
; unnoticed while populate_list ran exactly once, because the damage landed at
; exit; re-running it for a drop turned it into an immediate heap corruption
; (STATUS_HEAP_CORRUPTION in ntdll, nowhere near this code).
LVS_SHAREIMAGELISTS equ 00040h

; Borderless top-level window (no caption/menu bar) - drawn dark, drag-by-body.
;
; WS_CLIPCHILDREN is what stops the rows "popping in" during a resize.  Without
; it, the WM_SIZE handler's InvalidateRect(hwnd, NULL, TRUE) erases the WHOLE
; client area with the dark class brush - including the rectangles the listview
; and the owner-drawn strips occupy - and each child then repaints itself a
; moment later.  Every drag step blanked the list and refilled it, which is
; exactly the flicker that reads as rows appearing one at a time.  With the
; style set, the parent's paint and erase are clipped out of the child rects and
; the listview (already LVS_EX_DOUBLEBUFFER) keeps its pixels across the resize.
ST_MAINWND          equ WS_POPUP or WS_CLIPCHILDREN
SS_RIGHT            equ 2
SS_CENTERIMAGE      equ 200h
; WS_CLIPSIBLINGS: the settings host covers the crumb row when it is open, and
; these two sit exactly in that strip.  Without the bit they paint into the
; host's rectangle even though the host is above them - the same rule the list
; needs - and what they landed on was the panel's own section headers, which
; simply vanished.
; SS_NOTIFY: this line is the way in to the action log, so it has to report its
; own clicks.  A plain static swallows them and the window never hears.
ST_SCAN             equ WS_CHILD or WS_VISIBLE or WS_CLIPSIBLINGS or SS_RIGHT or SS_CENTERIMAGE or SS_NOTIFY
; the status line: left-aligned, NOT clickable (no SS_NOTIFY) - it sits beside
; the clickable statistics line, and two adjacent look-alike texts where only
; one responds to a click is bad enough without inviting the click.
ST_STATUS           equ WS_CHILD or WS_VISIBLE or WS_CLIPSIBLINGS or SS_CENTERIMAGE
ST_FILEEDIT         equ WS_CHILD or WS_VISIBLE or ES_READONLY or ES_AUTOHSCROLL
; the action log: read-only, scrollable, selectable, and a tab stop so the
; keyboard can reach it and Ctrl+A / Ctrl+C work without touching the buttons
ST_LOGEDIT          equ WS_CHILD or WS_VISIBLE or WS_TABSTOP or WS_VSCROLL or ES_MULTILINE or ES_READONLY or ES_AUTOVSCROLL
ST_EDIT             equ WS_CHILD or WS_VISIBLE or ES_AUTOHSCROLL or WS_TABSTOP
; password fields are borderless boxes with a coloured validation underline
ST_PWEDIT           equ WS_CHILD or WS_VISIBLE or ES_PASSWORD or ES_AUTOHSCROLL or WS_TABSTOP
ST_OWNERBTN         equ WS_CHILD or WS_VISIBLE or WS_TABSTOP or BS_OWNERDRAW
ST_OWNERBTN_NT      equ WS_CHILD or WS_VISIBLE or BS_OWNERDRAW   ; no tab stop (Show/Change)
; the file list takes no tab stop (tab cycles password -> Encrypt -> Exit only)
; and no border (drag-through: a listview subclass passes clicks to the window)
; WS_CLIPSIBLINGS.  Being ABOVE the list in z-order is not enough to protect
; the settings host: z-order decides who is in front, but a sibling WITHOUT this
; bit still paints over an overlapping sibling when it repaints itself, and the
; list repaints once per scroll step.  Both are needed - the host is raised on
; open, and this clips the list out of whatever the host covers.  Measured: with
; the host proven at the top of the child z-order and nine WM_DRAWITEMs
; confirmed reaching its children, the panel was STILL invisible until this.
;
; On the list only.  Adding it to the panel's own backdrop makes that backdrop
; clip itself against everything above it instead, which is a different bug that
; looks like this one: the breadcrumb bleeds through.
ST_LIST             equ WS_CHILD or WS_VISIBLE or WS_CLIPSIBLINGS or LVS_REPORT or LVS_NOCOLUMNHEADER or LVS_NOSORTHEADER or LVS_SHAREIMAGELISTS
ST_UNDER            equ WS_CHILD or WS_VISIBLE          ; 2px validation underline
SS_OWNERDRAW        equ 00000000Dh
ST_CRUMB            equ WS_CHILD or WS_VISIBLE or WS_CLIPSIBLINGS or SS_OWNERDRAW   ; owner-drawn breadcrumb chip
; The settings host.  Not WS_VISIBLE: it is shown by the hamburger.
;
; NO WS_CLIPCHILDREN, deliberately.  The class brush is the panel background,
; and several of the children - the section headers especially - only draw TEXT
; in their WM_DRAWITEM and leave their own pixels to whatever is behind.  That
; used to be a backdrop static sitting under them; it is this window now, so its
; erase has to reach under the children rather than being clipped out of them.
; With the clip on, the headers rendered onto unpainted pixels and vanished.
;
; WS_CLIPSIBLINGS, though - and it is not the same bit doing the same thing.
; CLIPCHILDREN would keep this window's erase OUT of its children, which is what
; broke the headers.  CLIPSIBLINGS keeps it out of SIBLINGS ABOVE IT, and there
; is exactly one: the password flyout, which opens over this panel and is raised
; above it.  Without the bit, every slider that repainted on hover drew straight
; through the open flyout, leaving it visible only in the gaps BETWEEN controls -
; the children are clipped to this window, so this window's clip is what governs
; whether their paint can reach the flyout at all.
;
; Safe because the host is raised to the top of the sibling z-order every time it
; is shown (toggle_menu), so the only sibling that can ever be above it is the
; flyout it is meant to yield to.
ST_MENUHOST         equ WS_CHILD or WS_CLIPSIBLINGS
; flat owner-drawn progress bars (strength meter + operation bar): solid fill,
; no border.  ST_BARHIDE starts hidden (shown by ShowWindow while running).
ST_BARHIDE          equ WS_CHILD or SS_OWNERDRAW

WM_CREATE           equ 1
WM_DESTROY          equ 2
WM_SIZE             equ 5
WM_GETMINMAXINFO    equ 024h
WM_PAINT            equ 0Fh
WM_ERASEBKGND       equ 014h                 ; the settings panel draws its own
WM_CLOSE            equ 010h
WM_SETFONT          equ 030h
WM_COMMAND          equ 0111h
WM_TIMER            equ 0113h
WM_MOUSEWHEEL       equ 020Ah
WM_APP_DONE         equ 08001h          ; WM_APP+1 posted by the worker thread
WM_APP_INDEXED      equ 08002h          ; WM_APP+2 posted by the indexer thread
ifdef DBG_TRACE
; WM_APP+3, test builds only: run the registered IDropTarget against the data
; object currently on the clipboard.  Carries no pointer, so it crosses the
; process boundary where WM_DROPFILES cannot.  See dt_selfdrop.
WM_APP_DROPTEST     equ 08003h
endif

EM_SETPASSWORDCHAR  equ 0CCh
EN_CHANGE           equ 0300h


; list-view messages / items
LVM_FIRST                   equ 01000h
WM_NCCALCSIZE               equ 083h
LVM_SETIMAGELIST            equ LVM_FIRST + 3
LVM_GETITEMCOUNT            equ LVM_FIRST + 4
LVM_GETITEMRECT             equ LVM_FIRST + 14
; Dropping into a folder while BUILDING an archive (docs/STAGED_LAYOUT.md).
; The machinery is complete and the naming half is under test
; (tests/stagetest.ps1); what is NOT yet verified is the GUI half - that the
; tree draws a staged file inside its destination and the archive then agrees.
; Until tests/stagedroptest.ps1 runs, this stays 0 and the encrypt view behaves
; exactly as it always has: a drop adds a top-level input.
;
; It is gated rather than left enabled because the failure mode is the specific
; one the doc rules out - a file encrypted into a path the list does not show -
; and "it builds and the checkers pass" is not evidence about a tree.
STAGED_DROP_ENABLED         equ 1
DROPBOX_X0                  equ 2             ; the destination box: left inset
DROPBOX_ALPHA               equ 40            ; ...and how much of it shows through
LVM_GETSUBITEMRECT          equ LVM_FIRST + 56
LVM_SETEXTENDEDLISTVIEWSTYLE equ LVM_FIRST + 54
LVM_INSERTITEMW             equ LVM_FIRST + 77
LVM_SETITEMTEXTW            equ LVM_FIRST + 116
LVM_DELETEALLITEMS          equ LVM_FIRST + 9
WM_DROPFILES                equ 0233h
WM_COPYGLOBALDATA           equ 0049h        ; carries the HDROP's memory
MSGFLT_ALLOW                equ 1
; ---- OLE drag-and-drop ------------------------------------------------------
S_OK                        equ 0
E_NOINTERFACE               equ 80004002h
E_INVALIDARG                equ 80070057h
DROPEFFECT_NONE             equ 0
DROPEFFECT_COPY             equ 1
CF_HDROP                    equ 15
DVASPECT_CONTENT            equ 1
TYMED_HGLOBAL               equ 1
; FORMATETC.  cfFormat is a WORD, but a pointer follows it, so the struct is
; 8-aligned and the fields do NOT sit where reading the header's field list
; suggests.  Writing dwAspect at +2 lands inside the padding and GetData then
; fails with DV_E_FORMATETC for no visible reason.
FE_cfFormat                 equ 0
FE_ptd                      equ 8
FE_dwAspect                 equ 16
FE_lindex                   equ 20
FE_tymed                    equ 24
FE_BYTES                    equ 32
STG_tymed                   equ 0
STG_handle                  equ 8            ; the HGLOBAL, which IS the HDROP
STG_pUnkForRelease          equ 16
STG_BYTES                   equ 24
; Vtable slots, by index, counted from the interface's own definition.  A
; wrong one here is not a build error: it is a call to whatever method happens
; to sit at that offset.
IDO_GETDATA                 equ 3*8          ; IDataObject, after the IUnknown 3
IDO_QUERYGETDATA            equ 5*8          ; ... GetData, GetDataHere, then this
IDT_DRAGENTER               equ 3*8          ; IDropTarget, likewise
IDT_DRAGOVER                equ 4*8
IDT_DRAGLEAVE               equ 5*8
IDT_DROP                    equ 6*8
LVM_INSERTCOLUMNW           equ LVM_FIRST + 97
LVSIL_SMALL                 equ 1
LVCF_FMT                    equ 00001h
LVCF_WIDTH                  equ 00002h
LVCF_TEXT                   equ 00004h
LVCF_SUBITEM                equ 00008h
LVCFMT_LEFT                 equ 00000h
LVCFMT_RIGHT                equ 00001h
LVIF_TEXT                   equ 00001h
LVIF_IMAGE                  equ 00002h
LVIR_BOUNDS                 equ 00000h
LVS_EX_FULLROWSELECT        equ 00020h
LVS_EX_DOUBLEBUFFER         equ 10000h
; LVCOLUMNW field offsets (x64)
LVC_mask        equ 0
LVC_fmt         equ 4
LVC_cx          equ 8
LVC_pszText     equ 16
LVC_iSubItem    equ 28
; LVITEMW field offsets (x64)
LVI_mask        equ 0
LVI_iItem       equ 4
LVI_iSubItem    equ 8
LVI_pszText     equ 24
LVI_iImage      equ 36
; SHFILEINFOW / SHGetFileInfo
SHFI_iIcon          equ 8
SHGFI_SYSICONINDEX  equ 04000h
SHGFI_SMALLICON     equ 00001h
SHGFI_USEFILEATTR   equ 00010h               ; icon from the NAME, not from disk
FILE_ATTR_DIR       equ 00010h
FILE_ATTR_NORMAL    equ 00080h
; WM_NOTIFY + NM_CUSTOMDRAW
WM_NOTIFY           equ 0004Eh
NM_CUSTOMDRAW_CODE  equ 0FFFFFFF4h        ; (UINT)-12
NMH_idFrom          equ 8
NMH_code            equ 16
NMCD_dwDrawStage    equ 24
NMCD_hdc            equ 32
NMCD_rc             equ 40                  ; RECT: the row's bounds
NMCD_dwItemSpec     equ 56
NMLVCD_iSubItem     equ 88
CDDS_PREPAINT       equ 00001h
CDDS_ITEMPREPAINT   equ 10001h
CDDS_ITEMPREPAINT_SUB equ 30001h
CDRF_SKIPDEFAULT    equ 00004h
CDRF_NOTIFYITEMDRAW equ 00020h
CDRF_NOTIFYSUBITEMDRAW equ 00020h
; list-view dark colouring
LVM_SETBKCOLOR      equ 01001h              ; LVM_FIRST + 1
LVM_SETTEXTCOLOR    equ 01024h              ; LVM_FIRST + 36
LVM_SETTEXTBKCOLOR  equ 01026h              ; LVM_FIRST + 38
; borderless-window chrome (drag by body, no maximize-on-double-click)
WM_SETFOCUS         equ 00007h
WM_KILLFOCUS        equ 00008h
WM_KEYDOWN          equ 00100h
VK_ESCAPE           equ 0001Bh
WM_NCHITTEST        equ 00084h
WM_NCLBUTTONDBLCLK  equ 000A3h
HTTRANSPARENT       equ -1
HTCLIENT            equ 1
HTCAPTION           equ 2
IDCANCEL            equ 2                    ; IsDialogMessageW sends this on ESC

; strength-meter bar colours (COLORREF = 0x00BBGGRR)

; ---- Fluent theming ---------------------------------------------------------
WM_CTLCOLOREDIT     equ 00133h
WM_CTLCOLORBTN      equ 00135h
WM_CTLCOLORSTATIC   equ 00138h
WM_DRAWITEM         equ 0002Bh
; DRAWITEMSTRUCT field offsets (x64)
DI_CTLID            equ 4
DI_ITEMSTATE        equ 16
DI_HWNDITEM         equ 24
DI_HDC              equ 32
DI_RCITEM           equ 40
ODS_SELECTED        equ 1
NULL_BRUSH          equ 5                    ; GetStockObject(NULL_BRUSH)
PS_SOLID            equ 0
BK_TRANSPARENT      equ 1
DT_LEFT             equ 0
DT_CENTER           equ 1
DT_RIGHT            equ 2
DT_VCENTER          equ 4
DT_PATH_ELLIPSIS    equ 04000h               ; elide the MIDDLE of a path
DT_SINGLELINE       equ 020h
DT_NOPREFIX         equ 0800h
DT_END_ELLIPSIS     equ 08000h
DT_WORDBREAK        equ 010h
DT_TOP              equ 0
DT_CALCRECT         equ 0400h                ; measure only, do not paint
; DT_EDITCONTROL makes DrawTextW wrap exactly as a multi-line edit does, so the
; DT_CALCRECT measurement and the later paint agree.  Without it the two can
; disagree by a line and the last one clips.
DT_EDITCONTROL      equ 02000h
DT_END_ELLIPSIS     equ 08000h
; window metrics + subclassing
SM_CXSCREEN         equ 0
SM_CYSCREEN         equ 1
SM_CXVSCROLL        equ 2                    ; width of the vertical scrollbar
CP_UTF8             equ 65001
GWLP_WNDPROC        equ -4
; list-view notify (non-selectable items)
BTN_RADIUS          equ 8                    ; corner diameter for RoundRect
; breadcrumb chip ??? a lighter panel pill on the dark window
CLR_CRUMB_EDGE      equ 0005A5C5Ch           ; slightly lighter grey 1px edge
CRUMB_PAD           equ 10                   ; horizontal text padding in the chip
; per-file progress bar (listview "Progress" cell, owner-drawn)
CLR_LV_TRACK        equ 0003A3A3Ah           ; empty track  #3A3A3A (panel grey)
PROG_INSET          equ 3                    ; cell padding around the bar
PROG_SBGAP          equ 3                    ; ...and clearance from the scrollbar
; ---- runtime layout metrics -------------------------------------------------
; The edge insets and the fixed bands.  Everything else (list width and height,
; and therefore every control anchored to the list's bottom or the window's
; right) is DERIVED from the client rect in do_layout.  LV_W and LV_H below are
; no longer "the" width and height - they are only what those come out as at the
; default window size, kept so create_controls_enc still has something to build
; with before the first layout pass runs.
LAY_MARGIN          equ 15                   ; window edge inset (left and right)
; The statistics line sits in its own row BETWEEN the list and the rule, which is
; where a count of what is in the list belongs: attached to the list, not
; floating in the heading beside the breadcrumb.  STAT_BAND is what that row
; costs the band below the list, and every offset down there is measured from it
; so the row and the things under it cannot drift apart.
STAT_GAP            equ 4                    ; air between the list and the count
STAT_H              equ 20                   ; the statistics row itself
STAT_W              equ 260                  ; right-anchored; also the click target
STAT_BAND           equ STAT_H + STAT_GAP    ; what the row costs the lower band
LAY_BOTTOM          equ 112 + STAT_BAND      ; band reserved below the list for the
                                             ; statistics row, password row,
                                             ; progress and buttons
LAY_SHOW_W          equ 34                   ; show/hide eye button width
LAY_SHOW_GAP        equ 6                    ; gap between password field and eye
LAY_RIGHT_PW        equ 20                   ; right inset of the eye button
LAY_BTN_W           equ 120                  ; primary action button width
LAY_EXIT_W          equ 80                   ; Exit button width
LAY_BTN_H           equ 32                   ; button height
LAY_BTN_GAP         equ 8                    ; gap between Exit and the action
; Resize: the window is WS_POPUP with custom chrome, so it has no sizing border
; to grab.  These are the outermost pixels that report a border hit code instead
; of the caption code the rest of the body reports.  Kept clear of every control
; (the sidebar starts at LAY_MARGIN, the list ends LAY_MARGIN from the right).
LAY_EDGE            equ 6                    ; resize gripper thickness
LAY_MIN_W           equ 420                  ; below this the button row collides
; +STAT_BAND: the statistics row grew the band below the list, and without this
; the floor that used to leave three rows leaves two.  The minimum is about how
; much LIST survives, so it has to move with everything that is not the list.
LAY_MIN_H           equ 260 + STAT_BAND      ; leaves the list ~3 rows (was 320
                                             ; with the logo band above it)
LAY_LV_MIN_W        equ 120                  ; hard floor, see do_layout
LAY_LV_MIN_H        equ 40
; Listview columns.  Size and Progress keep their widths and Name takes the
; slack, so the three always add up to the list width: at the default 455 this
; yields exactly the 268/80/103 the columns were created with.
LAY_COL_SIZE        equ 80
LAY_COL_PROG        equ 103
LAY_COL_FIXED       equ LAY_COL_SIZE + LAY_COL_PROG + 4   ; +4 = column grid slack
LVM_SETCOLUMNWIDTH  equ 0101Eh               ; LVM_FIRST + 30
LVM_GETITEMSTATE    equ 0102Ch               ; LVM_FIRST + 44
LVM_GETSELECTEDCOUNT equ 01032h              ; LVM_FIRST + 50
LVI_iIndent         equ 48                   ; LVITEMW.iIndent on x64
LVIF_INDENT         equ 00010h
NM_DBLCLK           equ 0FFFFFFFDh            ; NM_FIRST - 3
NMIA_iItem          equ 24                   ; NMITEMACTIVATE.iItem on x64
LVN_ITEMCHANGED     equ 0FFFFFF9Bh            ; LVN_FIRST - 1 (= -101)
LVN_BEGINDRAG       equ 0FFFFFF93h            ; LVN_FIRST - 9 (= -109)
NMLV_iItem          equ 24                   ; NMLISTVIEW on x64
NMLV_uNewState      equ 32
NMLV_uOldState      equ 36
NMLV_uChanged       equ 40
LVIS_FOCUSED        equ 1
LVIF_STATE          equ 8
; ---- the visible-row model (see rows_build) ---------------------------------
ROWS_MAX            equ 2048                 ; rows refused past this, never dropped
ROWARENA_CHARS      equ 262144               ; row path storage
ROW_SIZE            equ 24
ROW_pathoff         equ 0                    ; dword: offset into g_rowarena, in chars
ROW_depth           equ 4                    ; dword: indent level
ROW_size            equ 8                    ; qword
ROW_flags           equ 16                   ; dword
ROW_inputi          equ 20                   ; dword: the top-level input this row came from
ROWF_DIR            equ 1
ROWF_EXPANDED       equ 2
; ---- bounded case-insensitive path set (expanded folders / exclusions) ------
PSET_MAX            equ 512
PSET_ARENA_CHARS    equ 65536
PSET_count          equ 0
PSET_head           equ 8
PSET_offs           equ 16
PSET_arena          equ 16 + PSET_MAX*4
PSET_BYTES          equ PSET_arena + PSET_ARENA_CHARS*2
LVIS_SELECTED       equ 00002h
LVM_HITTEST         equ 01012h               ; LVM_FIRST + 18
SB_HORZ             equ 0
; ---- pixel-smooth list scrolling -------------------------------------------
; A report-mode listview scrolls in whole-item steps and nothing changes that:
; LVM_SCROLL rounds dy to the item height (measured - dy of 3, 5 and 11 all
; moved the content 0 pixels, dy of 20 moved it a full 23-pixel row).  So the
; control is not asked to scroll at all.  It is made as tall as its entire
; contents, and a window REGION shows only the band the viewport covers; moving
; the control by a pixel scrolls the list by a pixel.  The scrollbar is our own
; control alongside it, with its range in pixels rather than items.
;
; The bar is DRAWN, not a control.  A real SCROLLBAR child overlapping the list
; is a sibling, and siblings do not clip each other without WS_CLIPSIBLINGS - so
; every repaint of the list (one per scroll step) painted the rows, and the
; progress cells, straight over the bar, which then repainted itself a moment
; later.  That was the flicker.  Drawn from the list's own CDDS_POSTPAINT it is
; part of the same double-buffered pass as the rows, so nothing can land on top
; of it and there is nothing left to fight.
LV_WHEEL_PX         equ 42          ; pixels per wheel notch - deliberately NOT
                                    ; a whole number of rows, so the list can
                                    ; come to rest showing a partial row
LV_ROWH_FALLBACK    equ 20          ; used only before the first row exists
LVSB_W              equ 8           ; the drawn thumb, narrower than the hot zone
LVSB_INSET          equ 4           ; ... and held off the right edge
LVSB_MINH           equ 28          ; a thumb shorter than this cannot be grabbed
LVSB_ALPHA          equ 130         ; ~51%: legible over dark rows, not a stripe
LVSB_RADIUS         equ 4
CLR_SB_THUMB        equ 000D0D0D0h  ; light grey, before the blend
AC_SRC_OVER         equ 0
HTLEFT              equ 10
HTRIGHT             equ 11
HTTOP               equ 12
HTTOPLEFT           equ 13
HTTOPRIGHT          equ 14
HTBOTTOM            equ 15
HTBOTTOMLEFT        equ 16
HTBOTTOMRIGHT       equ 17
; ---- logo ------------------------------------------------------------------
; The wordmark used to occupy a 100px band across the top of the window, which
; MKCTL then had to shift EVERY control down past.  It was also unreadable there
; (near-black runes on a near-black ground) so the window paid its most valuable
; 100px for something nobody could make out.  It now sits small in the lower
; left, where the version/repo link used to be, and the 100px goes to the list.
LOGO_SM_W           equ 170                  ; wordmark control width
LOGO_SM_H           equ 30                   ; wordmark control height
ID_LOGO             equ 140                  ; owner-draw logo control id
ST_LOGO             equ WS_CHILD or WS_VISIBLE or SS_OWNERDRAW
; Pure black worked when the wordmark was 100px tall: the glyphs read as an
; emboss against #0a0000 and the shine was the only thing that lit them.  At
; 26px that is simply invisible, and this is the app's identity mark sitting
; where a legible grey label used to be - so it gets a visible base and the
; sweep still has ample headroom above it.
CLR_LOGO_BASE       equ 000000000h           ; logo glyphs #000000 (black at rest)
; Shine sweep. The band and the step are scaled to the small wordmark: at the
; old values a 15px half-band covered the whole 26px glyph height at once, and
; a 5px step crossed the short diagonal in a third of a second.
SHINE_BW            equ 8                    ; shine band half-width (px)
SHINE_STEP          equ 3                    ; band advance per 33ms frame
SHINE_IDLE          equ 150                  ; idle frames between sweeps (~5 s)
; ---- left margin / hamburger / settings menu --------------------------------
ID_HAMBURGER        equ 142                  ; menu toggle button
ID_MENU_HOST        equ 165                  ; the settings panel's own window.
                                         ; 165, not 164: ID_SDFORMAT already holds 164.
                                         ; Nothing dispatches this id and the two live in
                                         ; different window procs, so the clash was harmless -
                                         ; but an id collision is how a control on one screen
                                         ; bleeds onto another, and it costs a digit not to.
ID_SECUREDESK       equ 166                  ; private-desktop toggle
ID_KDFTIME          equ 167                  ; Argon2 time-cost slider
ID_KDFMEM           equ 168                  ; Argon2 memory slider (drags in MiB)
ID_KDFHDR           equ 169                  ; "Argon2 KDF" section header
ID_VOLSPLIT         equ 170                  ; file-split size cycler (docs/VOLUMES.md)
ID_LOGLVL           equ 144                  ; log-level cycler button
ID_PWMINLEN         equ 145                  ; password min-length cycler
ID_PWMINCLASSES     equ 146                  ; password min-classes cycler
ID_SCAN             equ 147                  ; scan-status / summary text (crumb row, right)
ID_STATUS           equ 196                  ; operation status: % / MB/s / ETA (summary row, left)
ID_GENHDR           equ 148                  ; "General" section header
ID_PWHDR            equ 149                  ; "Password" section header
ID_PWINFO           equ 150                  ; (i) info button -> class flyout
ID_PWFLYOUT         equ 151                  ; class-explanation flyout panel
ID_ABOUT            equ 153                  ; owner-draw body of the no-args About box
; Menu actions.  The window can now open with nothing in it, so there has to be
; a way in from the UI as well as from a drop.
ID_ADDFILES         equ 154
ID_ADDFOLDER        equ 155
ID_MBBODY           equ 154                  ; owner-draw body of the themed message box
ID_SDBODY           equ 155                  ; owner-draw body of the password prompt
ID_SDPASS           equ 156                  ; prompt password edit
ID_SDCONF           equ 157                  ; prompt confirm edit (encrypt only)
ID_SDUNDER          equ 158                  ; prompt password underline
ID_SDCUNDER         equ 159                  ; prompt confirm underline                  ; prompt confirm edit (encrypt only)
ID_SDFORMAT         equ 164                  ; prompt format chip (encrypt only)

; --- private-desktop password prompt -----------------------------------------
; Same panel language as the message box; OK reuses ID_ACTION and Cancel
; ID_CANCEL so draw_button styles them without knowing this window exists.
SD_W                equ 460
SD_PAD              equ 24
SD_TITLE_H          equ 28
SD_HINT_H           equ 34                   ; two short lines
SD_EDIT_H           equ 22                   ; text height + a little; the underline sits directly under it
SD_GAP              equ 12
SD_BTN_W            equ 96
SD_BTN_H            equ 32
SD_BTN_GAP          equ 10
SD_EYE_W            equ 38                   ; show/hide eye column, right of the field
SD_ROW_H            equ 26                   ; format row, between the fields and the buttons
SDF_CONFIRM         equ 1                    ; flags bit 0: ask twice (encrypt)
SDR_OK              equ 1
SDR_CANCEL          equ 0
SDR_UNAVAILABLE     equ -1                   ; fail closed: no private desktop

; --- themed message box (replaces MessageBoxW) --------------------------------
; The OK button deliberately reuses ID_ACTION and the secondary ID_CANCEL:
; draw_button styles ID_ACTION as the accent button and everything else as the
; standard dark one, so the message box gets the right look without draw_button
; needing to know it exists.  These live in their own window with its own
; wndproc, so the ids cannot collide with the main window's.
MB_W                equ 440                  ; client width
MB_PAD              equ 22                   ; body inset
MB_BAR_W            equ 4                    ; severity stripe width
MB_TITLE_H          equ 30                   ; title line height
MB_GAP              equ 12                   ; title -> body gap
MB_BTN_W            equ 96
MB_BTN_H            equ 32
MB_BTN_GAP          equ 10
MB_TEXT_MIN         equ 34                   ; keep short messages from looking cramped
MB_TEXT_MAX         equ 320                  ; cap, then the text clips rather than the box growing off-screen
CLR_WARN            equ 0000AA9FFh           ; amber RGB(255,169,10) - warning severity

; --- action-log viewer --------------------------------------------------------
; The window behind the statistics line: everything the operation said, in a
; read-only edit so the user can select, scroll and search it with the keys they
; already know, plus Copy and Save for taking it somewhere else.
;
; A real EDIT and not an owner-draw body like the message box: the log can be
; tens of thousands of lines, and hand-drawing a scrollable, selectable text view
; would be re-implementing the control badly.  Its ids live in this window's own
; wndproc, so ID_ACTION is free to mean "Close" here exactly as it means "OK" in
; the message box, and draw_button styles it as the accent button either way.
LB_W                equ 760                  ; client width
LB_H                equ 520                  ; client height
LB_PAD              equ 22
LB_TITLE_H          equ 30
LB_GAP              equ 12
LB_BTN_W            equ 110
LB_BTN_H            equ 32
LB_BTN_GAP          equ 10
ID_LOGBODY          equ 180                  ; owner-draw backdrop + title
ID_LOGTEXT          equ 181                  ; the read-only multi-line edit
ID_LOGCOPY          equ 182
ID_LOGSAVE          equ 183
; --- the right-drag progress window ------------------------------------------
; A right-drag has already been told everything: what, and where it goes.  It is
; not a conversation, so it does not get the main window - that window exists to
; be worked in, and offering it at the end of a gesture that has already decided
; everything invites edits to a job that is over.
;
; This is the shape Windows itself uses for a long copy: what is happening, how
; far along, which file right now, and a details panel folded away underneath.
; Success closes everything; a failure stops here with the details already open,
; because that is the one moment the log is the point rather than a curiosity.
PG_W                equ 520
PG_H                equ 208                  ; collapsed: the progress half only
PG_LOG_H            equ 300                  ; what "Details" adds
PG_PAD              equ 20
PG_BAR_H            equ 8
PG_BTN_W            equ 96
PG_BTN_H            equ 30
PG_TOG_W            equ 108
; The backdrop is ST_LOGO plus WS_CLIPSIBLINGS, and the extra bit is not
; optional.  It is one owner-draw control covering the whole client with two
; buttons sitting ON it, and without WS_CLIPSIBLINGS its paint runs straight
; through those buttons even though they are above it in the z-order - they only
; come back when something invalidates them, which nothing does.  Details and
; Close vanished the moment the backdrop started repainting properly.  Exactly
; what ST_MENUHOST is for on the password flyout; same bug, second surface.
ST_PGBODY           equ ST_LOGO or WS_CLIPSIBLINGS
ID_PG_BODY          equ 190                  ; owner-draw backdrop + all the text
ID_PG_TOGGLE        equ 191
; (192 was a Close id; the button carries ID_ACTION instead, so draw_button
;  gives it the accent without knowing this window exists - the same trick the
;  message box and the log viewer use)
ID_PG_LOG           equ 193                  ; the details EDIT
ID_PG_COPY          equ 194
ID_PG_SAVE          equ 195
CF_UNICODETEXT      equ 13
GMEM_MOVEABLE       equ 00002h               ; the clipboard requires moveable
GENERIC_WRITE       equ 40000000h
CREATE_ALWAYS       equ 2
FILE_ATTR_NORMAL    equ 80h
IDCANCEL            equ 2
ABOUT_W             equ 530                  ; About window client width
ABOUT_H             equ 412                  ; About window client height
IMAGE_ICON          equ 1                    ; LoadImageW: load an HICON
LR_DEFAULTCOLOR     equ 0
DI_NORMAL           equ 3                    ; DrawIconEx: mask + image
WM_MOUSEMOVE        equ 0200h
WM_CANCELMODE       equ 001Fh                 ; "drop any internal modal state"
WM_LBUTTONDOWN      equ 0201h
WM_LBUTTONUP        equ 0202h
MK_LBUTTON          equ 1
ST_OWNERSTAT        equ WS_CHILD or WS_VISIBLE or SS_OWNERDRAW   ; owner-draw static (slider)
CLR_TRACK           equ 000332f2bh           ; slider track (off) grey
CLR_HINT            equ 0007a7a7ah           ; muted section-header grey
CLR_MARGIN          equ 000101010h           ; left margin "hint grey" #101010
GLYPH_INK           equ 000B0B0B0h           ; sidebar glyph ink (light grey)
; ---- glyph buttons (ported from vordr's "ghost button", see its theme.asm) ---
; A frameless button that paints one font glyph plus a rounded hover halo.  The
; glyph codepoint and the hover flag ride in the window's GWLP_USERDATA rather
; than in a parallel table, so a button carries its own state:
;     userdata = glyph<<16 | hover<<8
; The window TEXT stays a readable name - the glyph is unreadable to a screen
; reader, so the accessible name has to come from somewhere.
GWLP_USERDATA       equ -21
GLYPH_HOVER_BIT     equ 00100h
CLR_GLYPH_HOVER     equ 0002C2C2Ch           ; halo: margin blended ~10% toward the ink
WM_MOUSELEAVE       equ 002A3h
; The scrollbar strip is NON-client while the bar is shown and client while it
; is hidden, so the hover has to be tracked on both sides of that line or it
; latches the moment the bar appears under the pointer.
WM_NCMOUSEMOVE      equ 000A0h
WM_NCMOUSELEAVE     equ 002A2h
TME_LEAVE           equ 2
TME_NONCLIENT       equ 010h
; Codepoints.  E000 and above is the Private Use Area, which is where the Segoe
; icon fonts keep their glyphs; below it we are in ordinary Unicode and need the
; symbol font instead.  draw_glyph_btn picks the font from the codepoint.
GLYPH_ADD           equ 0E710h               ; +          (Fluent "Add")
GLYPH_FOLDER        equ 0E8B7h               ; folder     (Fluent "Folder")
GLYPH_SETTINGS      equ 0E713h               ; gear       (Fluent "Setting")
GLYPH_REMOVE        equ 0E738h               ; minus      (Fluent "Remove")
GLYPH_CLEAR         equ 0E894h               ; clear      (Fluent "Clear")
GLYPH_CLOSE         equ 0E711h               ; x          (Fluent "Cancel")
; A glyph button with this flag draws its window text beside the glyph instead
; of centring the glyph alone - the command bar reads as labelled commands, the
; sidebar as bare icons.
GLYPH_LABEL_BIT     equ 1
; ---- command bar ------------------------------------------------------------
; A horizontal strip of labelled commands above the list, in the manner of
; Outlook's.  It holds commands that act on the LIST; the sidebar holds the ones
; that bring things into it.
CMDBAR_H            equ 34                   ; strip height
CMD_BTN_W           equ 104                  ; command button width
CMD_BTN_GAP         equ 2
CMD_ICON_W          equ 38                   ; bare-glyph command button width
CMD_SPACER          equ 24                   ; clear air between the list commands and the gear
; The settings panel is a fixed-height card under the command bar.  It used to
; stretch to the list's bottom, which since Add files / Add folder / About left
; it is mostly empty space.
;
; Three sections now: General and Password side by side, and Encryption full
; width beneath them.  The two KDF sliders went below rather than into either
; column because a third column does not fit in LV_W and a third row of the
; RIGHT column would have grown the panel by the same amount while leaving the
; left one half empty.  Content ends at 180+40 = 220; +8 padding.
MENU_H              equ 228
; ---- the password-class flyout ---------------------------------------------
; PANEL-RELATIVE, and that is the whole redesign.  It used to be placed at
; CRUMB_Y + MENU_H + 4 - four pixels BELOW the settings panel, in the main
; window's own space - so an explanation of the password policy was drawn on top
; of the statistics line, the rule and the password field itself.  It was also
; the one control do_layout never repositioned, so it stayed at its creation
; coordinates while everything around it moved on a resize.
;
; It now sits directly under the (i) that opens it, inside the panel's right
; column, covering the two sliders it is describing while it is open.  The
; assertion below is what stops it drifting outside the panel again.
PWFLY_X             equ 240                  ; panel-relative: the right column
PWFLY_Y             equ 28                   ; just under the Password header row
PWFLY_W             equ 200                  ; the right column's width; going
                                             ; wider would run past the sliders
; MEASURED, not estimated: DrawTextW/DT_CALCRECT on the real string in the real
; font (Segoe UI at -14, gui.asm's g_hfont) wraps to 114px in the 184px column
; this leaves after the 8px insets.  The first number tried was 120, which left
; ONE pixel spare - a fit that any change to the text, the font or the insets
; would turn into a clipped last line, silently.  140 leaves a whole line.
PWFLY_H             equ 140
; Tooltips.  TTF_SUBCLASS lets the tooltip hook each control itself, so no
; message forwarding is needed from wndproc.
TTS_ALWAYSTIP       equ 00001h
TTS_NOPREFIX        equ 00002h
TTF_IDISHWND        equ 00001h
TTF_SUBCLASS        equ 00010h
TTM_ADDTOOLW        equ 00432h               ; WM_USER + 50
; ---- Format: a two-segment picker -------------------------------------------
; The chip it replaces showed only the CURRENT format, so the other choice - and
; the fact that there WAS a choice - was invisible until you clicked it and
; watched the word change.  Both are drawn now, one click each.
FMT_SEG_W           equ 58                   ; one segment, px
FMT_SEG_GAP         equ 4                    ; between the two
FMT_SEG_PAD         equ 4                    ; inset from the control's right edge
FMT_SEG_H2          equ 11                   ; half a segment's height
CMD_GLYPH_X         equ 10                   ; glyph inset inside a labelled button
CMD_LABEL_X         equ 34                   ; label inset (clear of the glyph)
ID_CMDBAR           equ 160
ID_CMD_REMOVE       equ 161
ID_CMD_CLEAR        equ 162
ID_CMD_CLOSE        equ 164                  ; window close (163 is ID_SEP)
ID_SEP              equ 163                  ; hairline under the list
SEP_GAP             equ 6 + STAT_BAND        ; list -> rule, with the row in between
CLR_MENU_BG         equ 000202020h           ; settings panel background #202020
; ---- the settings panel's frame -------------------------------------------
; It was a flat fill the same colour as the rest of the dark chrome, with no
; edge, ending in mid-air above the statistics line - so it read as a hole in
; the window rather than a surface on top of it.  These give it an edge, and
; SETT_* below give the card its geometry.
CLR_MENU_EDGE       equ 000454545h           ; panel border #454545
SETT_PAD            equ 16                   ; panel edge -> content
SETT_GUTTER         equ 24                   ; between the two columns
SETT_COLW_MIN       equ 200                  ; a column never narrower than the
                                             ; fixed width it had
SETT_COLW_MAX       equ 320                  ; ...nor wider than a slider wants to be
CMDBAR_Y            equ 8                    ; command bar top (now the topmost row)
CRUMB_Y             equ 8 + 34 + 7           ; breadcrumb row, below the bar.  The
                                             ; +7 is 5 of headroom on top of the 2
                                             ; it had: the bar ends at 42 and the
                                             ; crumb sat almost against its edge.
VK_RETURN           equ 0Dh
LV_X                equ 15                   ; listview x - the sidebar strip is gone,
                                             ; so the list starts at the window margin
LV_W                equ 455                  ; listview width
LV_Y                equ 77                   ; listview top: below the command bar AND
                                             ; the breadcrumb row that now sits under
                                             ; it.  Moves in step with CRUMB_Y - the
                                             ; crumb is 24 tall, so at 49 it ends at
                                             ; 73 and would sit under the list.
; The list has to stay TALLER than the panel that covers it, or the panel's
; bottom rows hang over the list's edge with nothing behind them.  Panel bottom
; is CRUMB_Y + MENU_H = 277; the list bottom is LV_Y + LV_H = 282.  Both moved
; down by 5 together, so the margin between them is unchanged.
LV_H                equ 205                  ; listview height (~9 rows); snap_list_height trims it to a whole row count at runtime

; =============================================================================
; Layout invariants, checked by the ASSEMBLER.
;
; Every one of these has been checked by hand at least once, on paper, while
; moving a row by a few pixels - and one of them (the breadcrumb against the
; top of the list) came within two pixels of shipping wrong.  Arithmetic done
; in a comment is arithmetic nobody redoes after the next edit, so it is done
; here instead: change a constant these depend on and the build stops rather
; than the window quietly overlapping itself.
;
; They can only check what is expressed as NAMED constants - a row positioned
; with a bare literal is invisible to them, which is the argument for naming it.
;
; And they only earn their place if they CAN fail.  Two obvious candidates were
; written here and then deleted: "the statistics row must not overlap the rule"
; and "the band must reserve room for the row" are both unfalsifiable, because
; SEP_GAP and STAT_BAND are DERIVED from STAT_GAP and STAT_H rather than typed
; out beside them.  That derivation is the real guarantee; an assertion restating
; it would only look like one more thing being checked.  Each of the five below
; compares constants that are independently chosen, so each can actually fire.
; =============================================================================
IF (CRUMB_Y + 24) GT LV_Y
    .ERR <layout: the breadcrumb row runs into the top of the list>
ENDIF
IF (CRUMB_Y + MENU_H) GT (LV_Y + LV_H)
    .ERR <layout: the settings panel hangs below the list it covers>
ENDIF
IF LAY_BOTTOM LT (60 + STAT_BAND + LAY_BTN_H)
    .ERR <layout: the button row falls off the bottom of the window>
ENDIF
IF (LAY_MIN_H - LV_Y - LAY_BOTTOM) LT LAY_LV_MIN_H
    .ERR <layout: at the minimum window height the list is below its own floor>
ENDIF
IF STAT_W GT LV_W
    .ERR <layout: the statistics row is wider than the list it sits under>
ENDIF
IF (PWFLY_Y + PWFLY_H) GT MENU_H
    .ERR <layout: the password flyout hangs out of the bottom of the settings panel>
ENDIF

HKEY_CURRENT_USER   equ 080000001h
HKEY_LOCAL_MACHINE  equ 080000002h
KEY_READ            equ 020019h
KEY_WRITE           equ 020006h
REG_DWORD_          equ 4
; Dark palette (COLORREF 0x00BBGGRR)
CLR_DARK            equ 0000a0000h           ; window + control background #0a0000 (black)
CLR_SURFACE         equ 000F3F3F3h           ; (legacy light surface, unused)
CLR_FIELD           equ 000FFFFFFh           ; (legacy white field, unused)
CLR_WHITE           equ 000FFFFFFh           ; primary text + accent-button text
; Password strength / match line colours, indexed by underline state 0..4.
; Ported from Vordr, which grades in four steps rather than pass/fail: a
; password that merely clears the policy floor should not look as good as a
; strong one, and a two-colour bar cannot say that.
CLR_BAR_AMBER       equ 003CA5E1h            ; meets the policy, minimally
CLR_BAR_LGREEN      equ 00169C84h            ; adequate
CLR_BAR_DGREEN      equ 0055AF2Dh            ; strong / confirmed match
CLR_ACCENT          equ 000B85F00h           ; accent             RGB(0,95,184) #005FB8
; The accent at HALF luminosity, for the hairline round a dialog painted over
; the window.  A COLORREF is 00BBGGRR, not RGB order - B8 5F 00 IS RGB(0,95,184)
; - so halving means halving each byte in place: B8->5C, 5F->2F, 00->00.  Written
; out because getting the order backwards produces a plausible wrong colour
; rather than anything that looks like a mistake.
CLR_ACCENT_PRESS    equ 000934A00h           ; accent pressed     RGB(0,74,147)
CLR_BTN_DARK        equ 0003A3A3Ah           ; standard button fill (dark theme) #3A3A3A
CLR_BTN_DARK_PRESS  equ 0002A2A2Ah           ; standard button pressed
CLR_VALID           equ 0000F7B0Fh           ; underline: valid   green
CLR_INVALID         equ 0001C2BC4h           ; underline: invalid red #C42B1C
CLR_NEUTRAL         equ 000C8C8C8h           ; underline: at rest  grey
CLR_PLACEHOLDER     equ 000969696h           ; cue-banner placeholder grey (ephemeral)

MB_OK               equ 0
MB_OKCANCEL         equ 1
MB_ICONERROR        equ 010h
MB_ICONWARNING      equ 030h
MB_ICONINFORMATION  equ 040h
IDOK                equ 1

SW_HIDE             equ 0
SW_SHOW             equ 5
IDC_ARROW           equ 32512
IDC_HAND            equ 32649                ; the statistics line is clickable
WM_SETCURSOR        equ 020h
ICC_TAB_CLASSES     equ 00000008h            ; registers tooltips_class32 too
ICC_PROGRESS_CLASS  equ 020h
ICC_LISTVIEW_CLASSES equ 001h
GENERIC_READ        equ 080000000h
FILE_SHARE_READ     equ 1
OPEN_EXISTING       equ 3
INVALID_HVAL        equ -1

; control IDs
ID_PASS             equ 102
ID_CONFIRM          equ 103
ID_ACTION           equ 104
ID_PROG             equ 105
ID_CANCEL           equ 107
ID_SHOWPW           equ 108
ID_LIST             equ 109
ID_DEST             equ 112
ID_CHANGE           equ 113
ID_STRENGTH         equ 114
ID_PW_UNDER         equ 130
ID_CRUMB            equ 132
ID_COMPRESS         equ 133
ID_FORMAT           equ 134

; --- modern folder picker (IFileOpenDialog) ---
CLSCTX_INPROC_SERVER     equ 1
COINIT_APARTMENTTHREADED equ 2
FOS_PICKFOLDERS          equ 00000020h
FOS_ALLOWMULTISELECT     equ 00000200h
FOS_FILEMUSTEXIST        equ 00001000h
SIGDN_FILESYSPATH        equ 80058000h
; IFileOpenDialog vtable byte offsets (IUnknown/IModalWindow/IFileDialog)
VT_Show         equ 24
VT_SetOptions   equ 72
VT_GetOptions   equ 80
VT_SetTitle     equ 136
VT_GetResult    equ 160
VT_Release      equ 16
VT_GetDisplayName equ 40         ; IShellItem::GetDisplayName
; IFileOpenDialog adds two methods after IFileDialog's 24 slots.
VT_GetResults   equ 216          ; IFileOpenDialog::GetResults -> IShellItemArray
; IShellItemArray: IUnknown(3) + BindToHandler, GetPropertyStore,
; GetPropertyDescriptionList, GetAttributes, then these two.
VT_SIA_GetCount equ 56
VT_SIA_GetItemAt equ 64

GUI_EXTRA_SLOTS     equ MAX_ARGS - 1   ; inputs beyond the first (total MAX_ARGS)
SLOT_CHARS          equ 1000h       ; wchars per extra-input slot

; ---------------------------------------------------------------------------
; Capacities (wide chars) of every wcopy destination.  These exist so the
; declaration and the bound handed to wcopy cannot drift apart: both are written
; in terms of the same equ.  wcopy used to take no bound at all, which let
; argv[i] (up to MAX_PATH_CHARS) run off the end of a SLOT_CHARS slot.
; ---------------------------------------------------------------------------
FILEPATH_CHARS      equ 8000h       ; g_filepath_w  (= MAX_PATH_CHARS)
OUTPATH_CHARS       equ 8010h       ; g_outpath_w   (path + room for ".mrk"/".zip")
ROOTPATH_CHARS      equ 8010h       ; g_rootpath
CRUMB_CHARS         equ 2000h       ; g_crumbw
CRUMB_SHORT_CHARS   equ 1000h       ; g_crumb_short
BASEBUF_CHARS       equ 8010h       ; g_basebuf
SUMMBUF_CHARS       equ 160         ; g_summbuf
STATUSW_CHARS       equ 256         ; g_statusw
SIZETXT_CHARS       equ 48          ; g_sizetxt
; fmt_size writes at most "1234.5 TB" + NUL; every caller must pass a
; destination of at least this many wide chars (checked by inspection).
FMT_SIZE_MIN_CHARS  equ 32

; WBOUND reg, buf, chars - reg = address of the LAST writable wide char of buf,
; which is the bound wcopy takes in r8.  The same value is valid for every step
; of an append chain, since each step writes further into the same buffer.
WBOUND macro reg, buf, chars
    lea     reg, [buf + ((chars) - 1) * 2]
endm

; WNDCLASSEXW field offsets
WC_SIZE             equ 80

                                     ; PWBUF_CHARS now lives in macros.inc:
                                     ; secmem.asm locks these buffers

; one UTF-16 line of text followed by CR/LF (no NUL); for the help box.
WLINE macro text
    forc ch, <text>
        dw '&ch'
    endm
    dw 13, 10
endm

; The same, without the newline: for wide text that is followed by an explicit
; break, or by more text.  WSTR cannot be used where a control character is
; needed, and WLINE ends every call with one - this is the piece between them.
WTEXT macro text
    forc ch, <text>
        dw '&ch'
    endm
endm

; =============================================================================
.const
WSTR wc_class,  <myrkr_window>
WSTR wtitle_enc, <Myrkr - encrypt>
WSTR wtitle_dec, <Myrkr - decrypt>
WSTR s_crumb_multi, <(multiple locations)>
; Shown in the breadcrumb when the window opened with no inputs at all - the
; no-arguments case.  It has to say what to do next, because an empty list with
; a path-shaped heading above it reads as a bug rather than as a starting point.
WSTR s_crumb_none,  <Drop files or folders here>
WSTR s_add_files,   <Add files...>
WSTR s_add_folder,  <Add folder...>
WSTR s_about_item,  <About Myrkr>
WSTR s_settings_name, <Settings>
WSTR s_close_name, <Close>
WSTR s_cmd_remove,  <Remove>
WSTR s_cmd_clear,   <Clear all>
WSTR s_theme_dark,  <DarkMode_Explorer>
WSTR s_uxtheme_dll, <uxtheme.dll>
WSTR cls_scrollbar, <SCROLLBAR>
WSTR t_add_fail,    <Could not add to the archive>
WSTR m_add_fail,    <Nothing was added and the archive is unchanged. It may be open in another program, or on a drive with no room left.>
WSTR m_add_dup,     <One of those is already in the archive, under the same name. Nothing was added and the archive is unchanged.>
; The CLI prints e_vol_edit for this, which the window never shows - so without
; its own sentence a split container reported "it may be open in another program,
; or on a drive with no room left", which is three wrong guesses at once.
WSTR t_vol_edit,    <This container is split across volumes>
; One line: WSTR is a forc over the literal, so it has no way to carry a line
; break - every other message here is one paragraph for the same reason.
WSTR m_vol_edit,    <A volume set cannot be changed once it is written. Nothing was added or removed, and every part is exactly as it was. You can still open and extract it - to change what is in it, extract it and encrypt the result again.>
WSTR t_excl_full,   <Too many exclusions>
WSTR m_excl_full,   <Myrkr cannot track any more removed items. Clear the list and start again, or add the folders you want instead of removing what you do not.>
WSTR cls_tooltip,   <tooltips_class32>
WSTR s_tip_addfiles,  <Add files to the list>
WSTR s_tip_addfolder, <Add a folder to the list>
WSTR s_tip_remove,    <Remove the selected items from the list>
WSTR s_tip_clear,     <Remove every item from the list>
WSTR s_tip_settings,  <Settings>
WSTR s_change,  <Change...>
WSTR w_opt_to,  <--to>
WSTR s_bslash,  <\>
WSTR s_ph_pass, <Password>
WSTR s_ph_conf, <Confirm>
WSTR s_show,    <Show>
WSTR s_hide,    <Hide>
WSTR s_exit,    <Exit>
WSTR s_encrypt, <Encrypt>
WSTR s_execute, <Archive>             ; action label for the no-password zip case
WSTR s_scan_pre, <Scanning... >       ; live scan-status prefix
WSTR s_files_mid, < files, >          ; between the file count and the total size
WSTR s_folders_mid, < folders, >       ; only when there are any - see fmt_summary
WSTR s_empty, <>                      ; empty prefix -> final summary "N files, X"
WSTR s_decrypt, <Decrypt>
WSTR lg_op_enc, <encrypt>               ; event-log operation names (lowercase)
WSTR lg_op_dec, <decrypt>
WSTR s_comp_on,  <Compress: On>
WSTR s_comp_off, <Compress: Off>
WSTR s_fmt_mrk,  <Format: Myrkr>
WSTR s_fmt_zip,  <Format: Zip>
; --- redesigned settings menu (toggles / sliders / headers / info flyout) ---
WSTR s_hdr_general,   <General>
WSTR s_hdr_password,  <Password>
WSTR s_lbl_compress,  <Compress>
WSTR s_lbl_format,    <Format>
WSTR s_lbl_log,       <Log level>
WSTR s_lbl_minlen,    <Min length>
WSTR s_lbl_split,     <File split>
; The split presets, as the slider names them.  Sizes rather than a free number
; because the useful values are the ones a medium imposes, and 4 GB is DECIMAL -
; 4,000,000,000 - so it stays under FAT32's 4 GiB per-file ceiling rather than
; landing 295 MB over it.
WSTR s_split0,        <Off>
WSTR s_split1,        <100 MB>
WSTR s_split2,        <700 MB (CD)>
WSTR s_split3,        <2 GB>
WSTR s_split4,        <4 GB (FAT32)>
WSTR s_split5,        <25 GB (BD)>
WSTR s_split6,        <100 GB>
ALIGN 8
g_split_names label qword
    dq      s_split0, s_split1, s_split2, s_split3, s_split4, s_split5, s_split6
g_split_sizes label qword
    dq      0, 100000000, 700000000, 2000000000, 4000000000, 25000000000, 100000000000
WSTR s_lbl_minclasses,<Min classes>
WSTR s_hdr_kdf,<Argon2 KDF>
WSTR s_lbl_securedesk,<Private desktop>
WSTR s_lbl_kdftime,   <Time cost>
WSTR s_lbl_kdfmem,    <Memory>
; Slider unit suffix.  The leading space is deliberate and load-bearing - it is
; concatenated straight onto the digits.
WSTR s_unit_mib,      < MiB>
WSTR s_fmt_mrk_s,     <Myrkr>
WSTR s_fmt_zip_s,     <Zip>
WSTR s_lvl_none,      <none>
WSTR s_lvl_error,     <error>
WSTR s_lvl_warning,   <warning>
WSTR s_lvl_full,      <full>
WSTR s_lvl_debug,     <debug>
WSTR s_info_i,        <i>
; Third place the version appears, and the one on the main window.  Kept in step
; with myrkr.rc and s_ab_ver by tools/constcheck.py, which compares the
; major.minor.patch of every site regardless of how each one formats it.
WSTR s_open,          <open>
; Two paragraphs rather than one run-on sentence: the first says what the four
; classes ARE, the second says what the slider next to it does with them.  Split
; with a blank line, so the reader can stop after the half they came for.
;
; Raw dw and not WSTR: the break is a control character and WSTR takes none.
; DT_WORDBREAK still reflows each paragraph, so the wrapping follows the width
; rather than being baked in here - only the paragraph break is forced.
even
s_pwflyout label word
    WTEXT <Uppercase A-Z, lowercase a-z, digits 0-9, and symbols.>
    dw 13,10,13,10
    WTEXT <Min classes is how many of these four kinds a password has to use.>
    dw 0
; registry persistence (HKCU\Software\Myrkr)
ALIGN 8
g_setrows label byte
    ; LogLevel: audit verbosity, 0 off .. 4 debug
    dq      w_val_loglevel, g_cfg_loglevel, 0, 0, 0, g_lock_loglevel, g_pol_loglevel
    dq      g_hloglvl, s_lbl_log
    dd      0, 4, 0, ID_LOGLVL, 0, 4
    dd      0, 0
    dq      0
    ; Compress: drives the GUI toggle AND the CLI/pack default, hence two of
    ; each - the only row that needs val2 and seen2, and the reason they exist
    dq      w_val_compress, g_compress_on, g_cfg_compress, g_cfg_compress_seen, g_cfg_compress_set, g_lock_compress, g_pol_compress
    dq      g_hcompress, 0
    dd      0, 1, 1, ID_COMPRESS, 0, 0
    dd      0, 0
    dq      0
    ; Format: 0 = .mrk container, 1 = WinZip-AES .zip.  No policy value: nothing
    ; re-asserts a format over the command line
    dq      w_val_format, g_make_zip, 0, g_fmt_seen, 0, g_lock_format, 0
    dq      g_hformat, 0
    dd      0, 1, 1, ID_FORMAT, 0, 0
    dd      0, 0
    dq      0
    ; MinLen: password policy floor
    dq      w_val_minlen, g_cfg_pwminlen, 0, 0, 0, g_lock_minlen, g_pol_minlen
    dq      g_hminlen, s_lbl_minlen
    dd      1, 256, 0, ID_PWMINLEN, 8, 32
    dd      0, 0
    dq      0
    ; MinClasses: 0 disables the class rule entirely
    dq      w_val_minclasses, g_cfg_pwminclasses, 0, 0, 0, g_lock_minclasses, g_pol_minclasses
    dq      g_hminclasses, s_lbl_minclasses
    dd      0, 4, 0, ID_PWMINCLASSES, 1, 4
    dd      0, 0
    dq      0
    ; SecureDesktop: private-desktop password entry.  It HAS a control now.  The
    ; position this reverses - that a protection a user can switch off is not a
    ; protection - held while the only way to choose the ordinary prompt was
    ; MYRKR_SECUREDESKTOP=0 at install time.  That made it an installer decision
    ; nobody could revisit.  Where the decision has NOT been made, HKLM is absent
    ; and nothing was protecting anything; where it HAS, the value is present,
    ; the row locks and settings_apply_locks greys the toggle out.  See manifest
    ; 14.6 and 15.
    dq      w_val_securedesk, g_cfg_securedesk, 0, 0, 0, g_lock_securedesk, g_pol_securedesk
    dq      g_hsecuredesk, 0
    dd      0, 1, 1, ID_SECUREDESK, 0, 0
    dd      0, 0
    dq      0
    ; KdfTime: Argon2 passes.  Was reachable only as --kdf-time and never
    ; persisted, so the GUI silently used the default forever.
    dq      w_val_kdftime, g_cfg_t, 0, 0, 0, g_lock_kdftime, g_pol_kdftime
    dq      g_hkdftime, s_lbl_kdftime
    dd      ARGON2_MIN_T, ARGON2_MAX_T, 0, ID_KDFTIME, ARGON2_MIN_T, ARGON2_MAX_T
    dd      0, 0
    dq      0
    ; KdfMemory: Argon2 memory, stored in KiB.  The registry and CLI keep the
    ; full documented 8 MiB..4 GiB; the track stops at 2 GiB because a slider
    ; that can ask for more RAM than the machine has is not a useful control.
    ; A policy value above the track still applies - only the KNOB clamps.
    dq      w_val_kdfmem, g_cfg_m, 0, 0, 0, g_lock_kdfmem, g_pol_kdfmem
    dq      g_hkdfmem, s_lbl_kdfmem
    dd      ARGON2_MIN_M_KIB, ARGON2_MAX_M_KIB, 0, ID_KDFMEM, 8, 2048
    dd      1024, 128
    dq      s_unit_mib
    ; SplitSize: an INDEX into the split presets, not a byte count.  Stored as an
    ; index so the registry value survives the preset list being changed, and so
    ; the slider is a short list of the sizes a medium actually imposes rather
    ; than a free number where almost every value is wrong.  See docs/VOLUMES.md.
    ;
    ; APPENDED, not inserted.  select_slider falls back to 4*SETROW_SIZE for an
    ; id belonging to no slider, and that 4 means MinClasses by position; putting
    ; a row in front of it would silently repoint the fallback.
    dq      w_val_split, g_cfg_splitidx, 0, 0, 0, g_lock_split, g_pol_split
    dq      g_hvolsplit, s_lbl_split
    dd      0, SPLIT_MAX_IDX, 0, ID_VOLSPLIT, 0, SPLIT_MAX_IDX
    dd      0, 0
    dq      0

WSTR w_regkey,      <Software\Myrkr>
WSTR w_regkey_def,  <Software\Myrkr\Defaults>   ; deployed defaults, NOT policy
WSTR w_val_compress,<Compress>
WSTR w_val_format,  <Format>
WSTR w_val_loglevel,<LogLevel>
WSTR w_val_minlen,  <MinLen>
WSTR w_val_minclasses,<MinClasses>
WSTR w_val_securedesk,<SecureDesktop>
WSTR w_val_kdftime, <KdfTime>
WSTR w_val_kdfmem,  <KdfMemory>
WSTR w_val_split,   <SplitSize>

; =============================================================================
; The settings table.  One row per registry value, consumed by load_settings.
;
; It replaces a chain of six hand-written blocks, each of which had to name the
; NEXT one in three separate jumps - "absent", "below the range" and "above the
; range" all had to skip to the right place.  Getting one wrong does not fail to
; build and does not fail visibly: it silently stops every LATER setting from
; being read.  That happened once already and the comment recording it is why
; this exists; Vordr hit the same shape twice in its own settings and says so in
; docs/SETTINGS_DESIGN.md section 9.
;
; A row cannot affect its neighbours now.  Adding a setting is one row.
;
;   name   the value under HKCU\Software\Myrkr and HKLM\SOFTWARE\Myrkr
;   val    where the value goes; val2 a second destination taking the same one
;   seen   a dword set to 1 when the value was present (0 = the row has none)
;   lock   set to 1 when the value came from HKLM, so the GUI disables it
;   pol    takes the value under HKLM, for apply_policy_locks to re-assert
;   min/max  accepted range, INCLUSIVE; a value outside it is ignored
;   bool   1 = the range is not consulted and any nonzero becomes 1
; =============================================================================
sr_name             equ 0
sr_val              equ 8
sr_val2             equ 16
sr_seen             equ 24
sr_seen2            equ 32
sr_lock             equ 40
sr_pol              equ 48
sr_hwnd             equ 56
sr_lbl              equ 64
sr_min              equ 72
sr_max              equ 76
sr_bool             equ 80
sr_id               equ 84
sr_smin             equ 88
sr_smax             equ 92
sr_scale            equ 96
sr_step             equ 100
sr_unit             equ 104
SETROW_SIZE         equ 112
SETROW_COUNT        equ 9
;
; The three fields after the registry ones describe the CONTROL, so the same row
; answers "which panel control is this setting" as well as "where does the value
; live".  Three places used to know that separately - the HKLM lock chain, the
; slider descriptor and the list of sliders to subclass - and each had to be
; edited in step with the others.
;
;   hwnd   a pointer to the control's HWND global; 0 = policy only, no control
;   lbl    the slider's label; 0 = this row is not a slider
;   id     the control id, for looking a row up from a WM_DRAWITEM
;   smin/smax  the SLIDER's range, which is deliberately NOT sr_min/sr_max:
;          those are what the registry will accept, these are what a user can
;          drag to.  MinLen accepts 1..256 from policy but drags 8..32;
;          MinClasses accepts 0 (which disables the class rule) and drags 1..4.
;   scale  what a slider stop is worth in the STORED unit; 0 and 1 both mean
;          "the same unit".  Argon2 memory is held in KiB and would need a
;          4-million-stop track; it drags in MiB and multiplies by 1024.
;   step   the drag granularity, in slider stops; 0 and 1 both mean every
;          integer.  Memory steps in 128 MiB because 2040 one-MiB stops over a
;          180px track is finer than the pointer can express and finer than the
;          setting deserves.  It is a DRAG constraint only - the registry and
;          the CLI still take any value in sr_min..sr_max, so a policy of
;          300 MiB is honoured and simply sits between two stops.
;   unit   a suffix drawn after the number, so "512" reads as "512 MiB"
WSTR s_ready,   <Ready>
WSTR s_working, <Working...>
WSTR s_pfx_enc, <Encrypting  >
WSTR s_pfx_dec, <Decrypting  >
WSTR cls_static,   <STATIC>
WSTR cls_edit,     <EDIT>
WSTR cls_button,   <BUTTON>
WSTR cls_list,     <SysListView32>
WSTR wc_menu,      <myrkr_menu>
WSTR s_col_name,   <Name>
WSTR s_col_size,   <Size>
WSTR s_col_prog,   <Progress>
WSTR s_unit_b,     < B>
WSTR s_unit_kb,    < KB>
WSTR s_unit_mb,    < MB>
WSTR s_unit_gb,    < GB>
WSTR s_unit_tb,    < TB>
WSTR fontface,     <Segoe UI>
WSTR fontface_logo, <Segoe UI Historic>     ; covers the Runic block (U+16A0..)
WSTR fontface_icon,  <Segoe Fluent Icons>   ; Windows 11 icon font (PUA glyphs)
WSTR fontface_icon2, <Segoe MDL2 Assets>    ; Windows 10 fallback, same codepoints
WSTR fontface_sym,   <Segoe UI Symbol>      ; symbols below the PUA
align 2
wlogo_runes  dw 016D8h, 016A2h, 016B1h, 016B4h, 016B1h, 0   ; "Myrkr" in runes
WSTR t_err,     <Myrkr - error>
; Was t_ok, the "Myrkr - done" box.  That box is gone; this title survived it as
; the heading on the overwrite question, which is its only remaining use - and
; "done" was the wrong word above a question that has not done anything yet.
WSTR t_overwrite, <Myrkr - overwrite?>
WSTR t_cancel,  <Myrkr - cancelled>
WSTR t_browse,  <Choose a destination folder>
WSTR t_saveas,  <Save the encrypted container as>
WSTR s_defext_mrk, <mrk>            ; save dialog default extension,
WSTR s_defext_zip, <zip>            ; without the dot the OFN wants omitted
; --- GUIDs for the modern folder picker (IFileOpenDialog / IShellItem) ---
align 8
clsid_fileopen  dd 0DC1C5A9Ch                                    ; CLSID_FileOpenDialog
                dw 0E88Ah, 04DDEh
                db 0A5h,0A1h,060h,0F8h,02Ah,020h,0AEh,0F7h
iid_ifileopen   dd 0D57C7288h                                    ; IID_IFileOpenDialog
                dw 0D4ADh, 04768h
                db 0BEh,002h,09Dh,096h,095h,032h,0D9h,060h
; --- GUIDs for the drop target -----------------------------------------------
align 8
iid_idroptarget dd 000000122h                                    ; IID_IDropTarget
                dw 00000h, 00000h
                db 0C0h,000h,000h,000h,000h,000h,000h,046h
iid_iunknown    dd 000000000h                                    ; IID_IUnknown
                dw 00000h, 00000h
                db 0C0h,000h,000h,000h,000h,000h,000h,046h
WSTR t_addfiles, <Add files to encrypt>
WSTR t_addfolder, <Add a folder to encrypt>
WSTR t_addfiles_arc,  <Add files to the archive>
WSTR t_addfolder_arc, <Add a folder to the archive>
WSTR t_about,     <About Myrkr>
; The About screen's own body lives in draw_about, which is owner-drawn and
; belongs to the no-args window that this replaced.  This is the short version:
; enough to identify the build, with the repo one click away on the version
; label at the bottom left of the main window.
WSTR m_about_body, <Myrkr v1.1.0 - AES-256-GCM + Argon2id file encryption. Drop files or folders onto the window, or use Add files. The version label at the bottom left opens the project page.>
WSTR m_nocpu,   <This CPU lacks the required AES-NI / PCLMULQDQ instructions.>
CSTR c_nocpu,   "error: CPU lacks required features (AES-NI, PCLMULQDQ, SSE4.1)",13,10
WSTR m_nopass,  <Please enter a password.>
WSTR m_badpass, <The password contains invalid characters or is too long.>
WSTR m_policy,  <Password rejected: requires at least 12 characters and 3 of 4 classes (upper lower digit symbol).>
WSTR m_nodest,  <Please choose a destination.>
WSTR m_overwrite, <The output already exists. Overwrite it?>
WSTR m_slow_remove, <Removing from an archive this large means moving a lot of data, which will take a while. The window will not respond until it finishes, and nothing is changed if you stop now. Remove the selected items?>
WSTR t_slow, <Myrkr - this will take a while>
WSTR m_zip_norw, <This archive uses ZIP features Myrkr will not rewrite: entries whose sizes follow their data, or ZIP64 offsets. Rewriting one of those wrongly would destroy it, so nothing was changed.>
WSTR m_zip_io,   <The archive could not be rewritten. Nothing was removed.>
WSTR m_zip_part, <The new archive was written, but it could not be put back in place. Your data is in the file with the .mrktmp extension beside it - rename it over the original.>
WSTR t_zip_del,  <Myrkr - the archive was not changed>
WSTR t_zip_part, <Myrkr - finish this by hand>
WSTR m_auth,    <Authentication failed: wrong password or the file is corrupted.>
WSTR m_io,      <I/O error: a file could not be read or written.>
WSTR m_corrupt, <Not a valid Myrkr container or the file is corrupted.>
; Shown instead of the cause above when an extraction had already written files
; before it failed.  It replaces rather than follows it because the cause is the
; less useful half here: a wrong password cannot produce this (the key check
; fails before any entry is read), so what is left is damage, and the action is
; the same whichever kind it was.  What the user must not do is treat the folder
; as the archive's contents, and that is what this says.
WSTR m_part_extract, <The container could not be read all the way through, so the extraction stopped early. Every file written is authentic - but the folder is INCOMPLETE and does not hold everything the container contains. Do not use it as though it did.>
WSTR m_oom,     <Out of memory.>
WSTR m_cancelled, <Operation cancelled.>
WSTR m_nospace, <Not enough free disk space for this operation.>
WSTR sw_help,   <help>
WSTR sw_h,      <h>
; --- the no-args "About Myrkr" dialog -----------------------------------------
WSTR wc_about,     <myrkr_about>            ; About window class name
WSTR wtitle_about, <About Myrkr>            ; window title (borderless; for alt-tab text)
WSTR s_ab_name,    <Myrkr>                  ; heading beside the icon
; Second copy of the version, and the only one a user ever sees.  It cannot read
; the VERSIONINFO resource cheaply from here, so it is kept in step by hand:
; bump this WHENEVER myrkr.rc's FILEVERSION changes.  tools/constcheck.py cannot
; catch the drift - one side is an .rc, not an equ.
WSTR s_ab_ver,     <Version 1.1.0.0>        ; version line (accent)
WSTR s_ab_tag,     <AES-256-GCM authenticated encryption  -  Argon2id KDF>
WSTR s_ab_foot,    <github.com/xxtsxx/Myrkr>
WSTR s_close,      <Close>
; --- themed message box -------------------------------------------------------
WSTR wc_mbox,      <myrkr_mbox>             ; message-box window class
WSTR s_mb_ok,      <OK>
WSTR s_mb_cancel,  <Cancel>
; --- action-log viewer --------------------------------------------------------
; --- the right-drag progress window -------------------------------------------
WSTR wc_progwin,   <myrkr_progress>
WSTR s_pg_enc,     <Encrypting>
WSTR s_pg_dec,     <Decrypting>
WSTR s_pg_ext,     <Extracting>
WSTR s_pg_details, <Details>
WSTR s_pg_cancel,  <Cancel>
WSTR s_pg_failed,  <It did not finish>
WSTR s_pg_cancd,   <Cancelled>
; What the window actually is during this gap: one Argon2id derivation, measured
; at ~680ms with the shipping -m/-t. "Starting..." said nothing and made a
; deliberate cost look like a stall - the bar sits at zero for the whole of it
; because no file has been touched yet.
WSTR s_pg_starting,<Deriving key...>
WSTR s_pg_nolog,   <Nothing was recorded before it stopped.>
WSTR s_pg_of,      < of >
WSTR s_rate_gap,   <  >
WSTR s_rate_unit,  < MB/s  ETA >
WSTR s_pg_items,   < items>       ; files AND folders - see draw_progwin
WSTR wc_logbox,    <myrkr_logbox>
WSTR t_log,        <What happened>
WSTR s_lb_copy,    <Copy>
WSTR s_lb_save,    <Save to file...>
WSTR t_log_none,   <Myrkr - log>
WSTR m_log_none,   <Nothing has been recorded yet. The log fills up while an operation runs, and it is cleared when the next one starts.>
; Appended to the text, not shown instead of it: a log that ran out of room is
; still worth reading, it just has to say where it stops.  Raw dw rather than
; WSTR because it opens with a blank line and WSTR takes no control characters.
even
s_lb_trunc label word
    dw 13, 10
    WLINE <-- the log ran out of memory here. Everything after this point>
    WLINE <   is missing.>
    dw 0
s_lb_trunc_chars equ ($ - s_lb_trunc) / 2 - 1
WSTR t_log_save,   <Save the log>
WSTR s_defext_txt, <txt>
WSTR s_logname,    <myrkr-log.txt>
WSTR t_log_err,    <Myrkr - log>
WSTR m_log_savefail, <The log could not be written to that location.>
WSTR m_log_copyfail, <The log could not be placed on the clipboard.>
; --- private-desktop password prompt -----------------------------------------
WSTR wc_secdesk,   <myrkr_secdesk>
WSTR s_sd_title,   <Myrkr - password>
WSTR s_sd_hint1,   <Typed on a private desktop, where other programs>
WSTR s_sd_hint2,   <on this machine cannot see or reach it.>
ifdef DBG_TRACE
WSTR w_dbg_nosd,   <MYRKR_DBG_NOSECDESK>
endif
WSTR s_sd_pw,      <Password>
WSTR s_sd_conf,    <Confirm>
WSTR s_sd_mismatch,<The two passwords do not match.>
WSTR t_sd_err,     <Myrkr - secure desktop>
WSTR m_sd_unavail, <Myrkr could not create the private desktop used for password entry, so it has refused to continue rather than fall back to a desktop other programs can observe. An administrator can allow the ordinary prompt by setting SecureDesktop to 0.>
align 2
; one contiguous, newline-separated paragraph painted by draw_about (DrawTextW).
; NOTE: WLINE forbids the apostrophe, ampersand and angle-bracket characters.
ab_body:
    WLINE <Myrkr encrypts files and folders with AES-256-GCM, keyed>
    WLINE <from your password by Argon2id. The result is a single>
    WLINE <authenticated .mrk container; decryption needs only the>
    WLINE <password.>
    WLINE <>
    WLINE <Drag files onto the app, or right-click a file and choose>
    WLINE <Open with Myrkr: a lone .mrk is decrypted, anything else>
    WLINE <is encrypted.>
    WLINE <>
    WLINE <Command line  (run myrkr.exe from a terminal):>
    WLINE <    myrkr encrypt  IN [IN...]  -o OUT  -p PASS  [--compress]>
    WLINE <    myrkr decrypt  IN  [-o OUT]  -p PASS>
    WLINE <    myrkr verify   IN  -p PASS>
    WLINE <    myrkr  zip | unzip | hash | selftest | bench>
    dw 0
WSTR s_ext_agcm, <.mrk>
WSTR s_ext_zip,  <.zip>
WSTR s_extract,  <Extract>
WSTR s_extract_sel, <Extract selected>
WSTR s_decrypt_sel, <Decrypt selected>
WSTR s_ext_dec,  <.dec>
align 2
; one-entry accelerator table: ESC -> ID_CANCEL (Exit).  ACCEL = {BYTE fVirt,
; WORD key, WORD cmd} with natural alignment (fVirt@0, pad@1, key@2, cmd@4).
align 2
g_accel     db 1, 0                     ; fVirt = FVIRTKEY
            dw VK_ESCAPE                ; key
            dw ID_CANCEL                ; cmd

; =============================================================================
.data?
g_haccel    dq ?                        ; HACCEL (ESC -> Exit)
g_hinst     dq ?
g_hwnd      dq ?
g_hfont     dq ?
g_hfont_head dq ?                       ; semibold heading font (breadcrumb)
g_hfont_logo dq ?                       ; large bold runic font (logo)
g_hlogo     dq ?                        ; owner-draw logo control
g_about_icon dq ?                       ; HICON for the no-args About box (64px)
g_shine_pos  dd ?                       ; current diagonal position of the shine band
g_shine_on   dd ?                       ; 1 while a sweep is animating
g_shine_idle dd ?                       ; idle-frame counter between sweeps
g_hcrumb    dq ?                        ; breadcrumb heading static
g_hlist     dq ?                        ; file listview (encrypt mode)
g_himglist  dq ?                        ; system small-icon image list
g_hbr_accent dq ?                       ; accent fill brush (progress bars)
g_hbr_track  dq ?                       ; empty-track brush (progress bars)
g_hfilelbl  dq ?
g_hpass     dq ?
g_hconfirm  dq ?
g_hshow     dq ?
g_hdest     dq ?
g_hchange   dq ?
g_haction   dq ?
g_hcancel   dq ?
g_hcompress dq ?                        ; Compress on/off toggle (encrypt mode)
g_hprog     dq ?
g_hstatus   dq ?
g_hpw_under dq ?                        ; password validation underline static
g_hcf_under dq ?                        ; confirm validation underline static
g_hbr_surface dq ?                      ; themed brushes
g_hbr_dark  dq ?                        ; dark window/control background (#20201F)
g_hbr_field dq ?
g_ubr       dq 5 dup (?)                ; underline brushes by state 0..4
g_hbr_neutral dq ?
g_hbr_valid dq ?
g_hbr_invalid dq ?
g_pw_state  dd ?                        ; underline state: 0 neutral 1 valid 2 invalid
g_cf_state  dd ?
g_strength_pct dd ?                     ; flat strength bar: fill % + colour
g_strength_clr dd ?
g_prog_pct  dd ?                        ; flat operation bar: fill %
g_drag_txtms dq ?                       ; drag-out: last status-text refresh (ms)
g_oldeditproc dq ?                      ; original EDIT wndproc (for placeholder subclass)
g_oldlistproc dq ?                      ; original SysListView32 wndproc (drag-through)
g_oldsliderproc dq ?                    ; original STATIC wndproc (slider subclass)
g_sld_min   dd ?                        ; current slider descriptor (set by slider_desc)
g_sld_max   dd ?
g_sld_valptr dq ?                       ; -> the int value global
g_sld_keyptr dq ?                       ; -> the registry value-name wstr
g_sld_lblptr dq ?                       ; -> the slider label wstr
g_sld_scale dd ?                        ; stops -> stored unit (never 0; see slider_desc)
g_sld_unit  dq ?                        ; -> a suffix wstr, or 0
g_sld_step  dd ?                        ; drag granularity in stops (never 0)
; --- owner-draw scratch (UI thread only; the menu draws never nest) ----------
g_dr_hdc    dq ?
g_dr_l      dd ?
g_dr_t      dd ?
g_dr_r      dd ?
g_dr_b      dd ?
g_dr_x0     dd ?
g_dr_x1     dd ?
g_dr_cy     dd ?
g_dr_thumb  dd ?
g_dr_col    dd ?
g_dr_col2   dd ?                        ; border, where it differs from the fill
g_dr_dis    dd ?                        ; 1 if the control being drawn is disabled
g_dr_txtb   dd ?                        ; bottom of the text line for dr_text
g_dr_rc     db 16 dup (?)               ; RECT for DrawTextW
g_dr_br     dq ?
g_dr_pen    dq ?
g_dr_ob     dq ?
g_dr_op     dq ?
g_dr_br2    dq ?
g_dr_ob2    dq ?
g_has_file  dd ?
g_op        dd ?                        ; 0 = encrypt, 1 = decrypt
g_is_zip    dd ?                        ; 1 = decrypt mode is a WinZip-AES .zip extract
g_zip_enc   dd ?                        ; 1 = the .zip has encrypted entries (needs a password)
g_is_archive dd ?                       ; container archive flag (decrypt)
g_op_result dd ?
g_running   dd ?
g_cancelled dd ?
g_showpw    dd ?                        ; 0 = masked, 1 = shown
g_compress_on dd ?                      ; Compress toggle state (encrypt mode)
g_make_zip  dd ?                        ; encrypt output format: 0 = .mrk, 1 = .zip
g_act_exec  dd ?                        ; action button shows "Execute" (1) vs "Encrypt" (0)
g_hburger   dq ?                        ; hamburger menu button
                        ; settings panel background
g_hloglvl   dq ?                        ; log-level cycler button
g_hminlen   dq ?                        ; password min-length cycler
g_hminclasses dq ?                      ; password min-classes cycler
g_hgenhdr   dq ?                        ; "General" header
g_hpwhdr    dq ?                        ; "Password" header
g_hpwinfo   dq ?                        ; (i) info button
g_hpwflyout dq ?                        ; class-explanation flyout
g_hsecuredesk dq ?                      ; private-desktop toggle
g_hkdfhdr   dq ?                        ; "Argon2 KDF" header
g_hkdftime  dq ?                        ; Argon2 time-cost slider
g_hkdfmem   dq ?                        ; Argon2 memory slider
g_hvolsplit dq ?                        ; file-split size slider
g_drag_prog dd ?                        ; 1 while a drag-out is driving the bar
g_wt_job    dd ?                        ; what worker_thread is being asked to do:
                                        ; 0 crypto, 1 container add, 2 container
                                        ; remove.  Reset in on_done - a stale
                                        ; value would send the next Encrypt into
                                        ; an append.
g_ca_poscount dq ?                      ; g_poscount before an add's picker ran
g_drop_pos0 dq ?                        ; ... and before a drop onto a container
g_pick_only dd ?                        ; 1 = the picker collects paths and
                                        ; nothing else; see container_add
; ---- OLE drop target --------------------------------------------------------
; The object is one vtable pointer and nothing else: there is exactly one
; window, it lives as long as the process, and it holds no per-drag state that
; DragEnter would have to allocate.  So no heap block, no per-object refcount
; to get wrong - g_dt_refs exists only so Release has something to return, and
; the object is never freed by it.
;
; Not initialised here because gui.asm has no .data section; wp_create points
; it at the vtable.  A null here would be handed to RegisterDragDrop, which
; accepts it and then faults inside ole32 on the first drag.
g_droptgt   dq ?                        ; the whole of the drop-target object
g_dt_refs   dd ?
g_dt_ok     dd ?                        ; 1 = RegisterDragDrop returned S_OK
g_ole_ok    dd ?                        ; 1 = OleInitialize succeeded, so the
                                        ; matching OleUninitialize is owed
g_dt_eff    dd ?                        ; the effect DragEnter settled on, which
                                        ; DragOver then repeats
; ---- the insertion line -----------------------------------------------------
; Where the NEXT append lands, when a drag decided it.  g_add_row_set is the
; whole of the handshake: zero - which is what .data? starts as - means "no
; drag chose anything, use the selection", so the buttons need no special case
; and a stale row can never be mistaken for a fresh one.
g_add_row_set dd ?
g_add_row   dd ?                        ; -1 = archive root, else a row index
g_dl_show   dd ?                        ; 1 = paint the destination box
g_dl_y0     dd ?                        ; its edges, in the control's CLIENT
g_dl_y1     dd ?                        ;   space - which is the content space,
g_dl_x0     dd ?                        ;   because lv_apply scrolls by moving
g_dl_x1     dd ?                        ;   the control, not its contents
g_dl_rc     dd 4 dup (?)                ; scratch RECT for LVM_GETITEMRECT
g_dbrc      dd 4 dup (?)                ; ...and for the box itself
g_dbdc      dq ?                        ; 1x1 accent source for the translucent
g_dbbmp     dq ?                        ;   fill, made once and kept
g_expw      dw 2048 dup (?)             ; the add destination, in row-path form
; The drop destination for the ENCRYPT view, frozen as an archive path before
; the input list changes underneath the row index it came from.
g_stage_dest    dd ?                    ; 1 = the next drop is staged somewhere
g_stage_destlen dd ?
g_stagebufw db 1024 dup (?)
g_dt_fmt    db FE_BYTES dup (?)         ; FORMATETC asking for CF_HDROP
g_dt_med    db STG_BYTES dup (?)        ; the STGMEDIUM it comes back in
g_fmt_pt    dd 2 dup (?)                ; pointer position, for the Format hit test
g_fmt_rc    dd 4 dup (?)                ; ... and its client rect
; ---- runtime layout (do_layout) ---------------------------------------------
; Geometry used to be compile-time only: 35 MKCTL sites with constant
; coordinates and no WM_SIZE handler at all.  These hold the CURRENT values so
; the same numbers can be recomputed whenever the client area changes.
g_lay_rc    dd 4 dup (?)                ; GetClientRect scratch
g_lay_cw    dq ?                        ; client width
g_lay_ch    dq ?                        ; client height
g_lay_lvy   dq ?                        ; list top (absolute, includes the logo band)
g_lay_lvw   dq ?                        ; list width
g_lay_lvh   dq ?                        ; list height
g_lay_bot   dq ?                        ; list bottom = lvy + lvh
g_lay_sby   dq ?                        ; sidebar/panel top (absolute)
g_lay_t1    dq ?                        ; scratch: computed x or w for one call
g_lay_t2    dq ?                        ; scratch: computed y or h for one call
g_lay_wr    dd 4 dup (?)                ; GetWindowRect scratch (hit-test, screen coords)
g_ht_x      dd ?                        ; hit-test point, screen x
g_ht_y      dd ?                        ; hit-test point, screen y
; ---- glyph buttons ---------------------------------------------------------
g_font_icon dq ?                        ; Segoe Fluent Icons (or MDL2 Assets on Win10)
g_font_sym  dq ?                        ; Segoe UI Symbol, for codepoints below the PUA
g_oldglyphproc dq ?                     ; button wndproc saved by glyph_attach
g_facebuf   dw 64 dup (?)               ; GetTextFaceW result, for the font fallback check
g_glyphbuf  dw 4 dup (?)                ; the single codepoint being drawn
g_lblbuf    dw 64 dup (?)               ; command-button label (GetWindowTextW)
; LVHITTESTINFO is 24 bytes on comctl32 v6 - POINT, flags, iItem, iSubItem,
; iGroup - and LVM_HITTEST fills the trailing fields.  A 4-dword buffer let the
; control write 8 bytes past it, into whatever the assembler placed next.
g_listhover dd ?                        ; 1 while the SCROLLBAR STRIP is hovered
g_sbw       dd ?                        ; SM_CXVSCROLL: width of that strip
g_lsrc      dd 4 dup (?)                ; the list's window rect, screen coords
g_lspt      dd 2 dup (?)                ; GetCursorPos result, screen coords
g_lhit      dd 8 dup (?)                ; LVHITTESTINFO for the list's hit test
; ---- pixel-smooth scrolling (see lv_apply) ---------------------------------
g_lvscroll  dq ?                        ; scroll offset, in PIXELS from the top
g_lvcontent dq ?                        ; height of the whole tree, in pixels
g_lvview    dq ?                        ; height of the band actually shown
g_lvrowh    dq ?                        ; one row, in pixels (from the control)
g_lvt1      dq ?                        ; lv_apply scratch - see do_layout for
g_lvt2      dq ?                        ; why these are globals and not locals
g_lvt3      dq ?                        ; (and NOT g_lay_t*: do_layout calls in)
g_lvtrack   dd ?                        ; 1 while the thumb is being dragged
g_lvgrab    dq ?                        ; scroll offset when the drag started
g_lvgraby   dq ?                        ; pointer y (client) when it started
g_lvthy     dq ?                        ; last drawn thumb top, viewport-relative
g_lvthh     dq ?                        ; ... and its height
g_lvirc     dd 4 dup (?)                ; LVM_GETITEMRECT scratch
g_sbrc      dd 4 dup (?)                ; thumb rect being drawn
g_vporg     dd 2 dup (?)                ; the paint DC's viewport origin
g_sbdc      dq ?                        ; 1x1 source DC for the alpha blend
g_sbbmp     dq ?                        ; its bitmap, filled with CLR_SB_THUMB
; ---- uxtheme dark mode (resolved by ordinal; see enable_dark_mode) ----------
g_uxtheme   dq ?                        ; uxtheme.dll, or 0 when unavailable
g_darkwndfn dq ?                        ; ord 133 AllowDarkModeForWindow, or 0
g_htip      dq ?                        ; the one shared tooltip window
g_ti        db 64 dup (?)               ; TOOLINFO (V2 size) for TTM_ADDTOOLW
g_hcmdbar   dq ?                        ; command bar background strip
g_hcmdremove dq ?                       ; command: remove selected
g_hcmdclear dq ?                        ; command: clear all
g_hcmdclose dq ?                        ; command bar: the window close X
g_hsep      dq ?                        ; hairline under the list
g_mi        db 40 dup (?)               ; MONITORINFO (cbSize,rcMonitor,rcWork,flags)
g_mmi       dq ?                        ; MINMAXINFO ptr, held across the monitor calls
g_sldbuf    dw 16 dup (?)               ; slider value text scratch
g_menu_open dd ?                        ; 1 while the settings panel is shown
g_sett_c1x  dd ?                        ; left column x, computed in do_layout
g_sett_c2x  dd ?                        ; right column x
g_sett_colw dd ?                        ; column width, shared by both
g_menu_reg  dd ?                        ; 1 once wc_menu is registered
g_hmenuhost dq ?                        ; the settings panel's own window
g_cfg_compress_seen dd ?                ; 1 if a saved Compress value was loaded
g_fmt_seen  dd ?                        ; 1 if a saved Format value was loaded
g_regval    dd ?                        ; scratch DWORD for registry get/set
g_regsz     dd ?                        ; scratch size for RegQueryValueExW
g_reghk     dq ?                        ; open ...\Software\Myrkr handle (load)
g_loading_hklm dd ?                     ; 1 while loading HKLM (enforced policy)
g_lock_compress  dd ?                   ; 1 = setting fixed by HKLM (disable in menu)
g_lock_format    dd ?
g_lock_loglevel  dd ?
g_lock_minlen    dd ?
g_lock_minclasses dd ?
g_lock_securedesk dd ?
g_lock_kdftime   dd ?
g_lock_kdfmem    dd ?
g_lock_split     dd ?
; The HKLM-enforced values, kept alongside the lock flags so apply_policy_locks
; can put them back after the CLI option parser has run.  Without these the lock
; flags only reach the GUI, where they grey a control out; the CLI parser writes
; the same g_cfg_* globals later and simply wins.
g_pol_compress   dd ?
g_pol_loglevel   dd ?
g_pol_minlen     dd ?
g_pol_minclasses dd ?
g_pol_securedesk dd ?
g_pol_kdftime    dd ?
g_pol_kdfmem     dd ?
g_pol_split      dd ?
g_cfg_splitidx   dd ?                    ; 0..5 index into the split presets
g_hformat   dq ?                        ; Format toggle handle
g_input_total dq ?                      ; total input bytes (size-based default)
public g_scan_files, g_scan_bytes, g_scan_dirs
g_scan_files dq ?                       ; indexer: running file count (bg writes, UI reads)
g_scan_bytes dq ?                       ; indexer: running byte total
g_scanning  dd ?                        ; 1 while the indexer thread is walking the inputs
g_index_tid dq ?                        ; indexer thread id
g_hscan     dq ?                        ; status/summary static (top-right of the crumb row)
g_summbuf   dw SUMMBUF_CHARS dup (?)    ; scan-status / summary text scratch
g_btntext   dw 64 dup (?)              ; owner-draw button text scratch
g_tid       dq ?
g_wc        db WC_SIZE dup (?)
g_lvc       db 64 dup (?)               ; LVCOLUMNW scratch
g_lvi       db 96 dup (?)               ; LVITEMW scratch
g_shfi      db 700 dup (?)              ; SHFILEINFOW scratch
g_lvrc      db 16 dup (?)               ; RECT scratch (GetSubItemRect)
g_rowsize   dq MAX_ARGS dup (?)         ; per-INPUT size from the indexer (bytes)
; ---- visible rows.  Zero-filled by the loader, so no explicit init is needed
; for the counts or either set.
g_rows      db ROWS_MAX*ROW_SIZE dup (?)
g_rowcount  dq ?
g_rowhead   dq ?                        ; next free char in g_rowarena
g_dragname  db DRAGNAME_BYTES dup (?)   ; one row path as an entry name, UTF-8
g_rowinput  dq ?                        ; input index rows_add stamps on each row
g_inputdead db MAX_ARGS dup (?)          ; remove_selected: inputs to drop this pass
g_rowarena  dw ROWARENA_CHARS dup (?)
g_expanded  db PSET_BYTES dup (?)       ; folders the user has opened
public g_excluded
public g_rowcount                        ; selftest asserts the tree ordering
public g_cfg_splitidx                    ; selftest drives it over the presets
public g_drag_prog                       ; estream.asm: a drag-out owns the bar
public g_hwnd, g_hprog, g_prog_pct       ; ...and drives the bar directly
g_excluded  db PSET_BYTES dup (?)       ; paths carved out of their input
g_sizetxt   dw SIZETXT_CHARS dup (?)    ; formatted size string scratch
align 2
; Declared with the same equs the wcopy bounds use (see WBOUND), so a buffer
; cannot be resized without its bound moving with it.
g_filepath_w dw FILEPATH_CHARS dup (?)   ; first input (positionals[0])
g_inslots    dw (GUI_EXTRA_SLOTS*SLOT_CHARS) dup (?)  ; inputs 1..N
g_outpath_w  dw OUTPATH_CHARS dup (?)
align 8
g_ofn        db 152 dup (?)                  ; OPENFILENAMEW, x64 layout
g_out_chosen dd ?                            ; 1 once a destination is settled
g_argdest    dw 4100 dup (?)            ; --to <dir>: drop-target folder
g_tmpbase    dw 1100 dup (?)            ; basename held while re-rooting
g_have_dest  dd ?                       ; 1 = --to was given
g_rootpath   dw ROOTPATH_CHARS dup (?)   ; common-root path of the selected inputs
g_crumbw     dw CRUMB_CHARS dup (?)      ; breadcrumb display string (full)
g_crumb_short dw CRUMB_SHORT_CHARS dup (?) ; breadcrumb collapsed ("first > ... > last")
; Scratch for one dropped path on its way from the shell to append_input.
; Sized to what Windows can actually name, so DragQueryFileW cannot overrun it.
g_dropbuf    dw MAX_PATH_CHARS dup (?)
g_haddfiles  dq ?                        ; menu: Add files...
g_haddfolder dq ?                        ; menu: Add folder...
g_basebuf    dw BASEBUF_CHARS dup (?)    ; basename scratch for folder-picker recombine
public g_passw, g_confirmw
g_passw      dw PWBUF_CHARS dup (?)
g_confirmw   dw PWBUF_CHARS dup (?)
g_statusw    dw STATUSW_CHARS dup (?)
g_hdrbuf     db 32 dup (?)
g_argc       dd ?
; --- themed message box state (UI thread only; mbox never nests) --------------
g_mb_hwnd    dq ?                            ; the modal window
g_mb_text    dq ?                            ; caller's body text (wide)
g_mb_title   dq ?                            ; caller's title (wide)
g_mb_flags   dd ?                            ; MB_* as passed to mbox
g_mb_result  dd ?                            ; IDOK / IDCANCEL
g_mb_done    dd ?                            ; 1 once the window is gone
g_mb_h       dd ?                            ; computed client height
g_mb_texth   dd ?                            ; measured wrapped body height
g_mb_reg     dd ?                            ; 1 once the class is registered
g_mb_rc      db 16 dup (?)                   ; RECT scratch (DT_CALCRECT / fills)
g_mb_prc     db 16 dup (?)                   ; parent RECT for centring
; --- action-log viewer state (UI thread only; never nests) --------------------
g_lb_hwnd    dq ?                            ; the modal window
g_lb_edit    dq ?                            ; the read-only text control
g_lb_text    dq ?                            ; the widened log, NUL-terminated
g_lb_bytes   dq ?                            ; its allocation size, for the wipe
g_lb_chars   dq ?                            ; its length in wide chars, with NUL
g_lb_done    dd ?                            ; 1 once the window is gone
g_lb_reg     dd ?                            ; 1 once the class is registered
g_lb_rc      db 16 dup (?)                   ; RECT scratch
g_lb_prc     db 16 dup (?)                   ; parent RECT for centring
g_lb_path    dw MAX_PATH_CHARS dup (?)       ; Save-to-file destination
g_scan_fail  dd ?                            ; 1 = the last operation failed, so
                                             ; the statistics line reads red
g_hcur_hand  dq ?                            ; IDC_HAND, loaded once
; --- the right-drag progress window (one at a time; never nests) --------------
g_pg_hwnd    dq ?                            ; non-zero = this launch is a
                                             ; right-drag, and this window owns
                                             ; the ending instead of on_done
g_pg_edit    dq ?                            ; the details EDIT, once expanded
g_pg_body    dq ?                            ; the owner-draw backdrop, resized on expand
g_pg_open    dd ?                            ; 1 = details showing
g_pg_done    dd ?                            ; 1 = the worker has finished
g_pg_fail    dd ?                            ; 1 = ...and it did not go well
g_pg_reg     dd ?                            ; 1 once the class is registered
g_pg_rc      db 16 dup (?)                   ; RECT scratch
g_pg_txt     dw 600 dup (?)                  ; one assembled line, widened
g_ctl_parent dq ?                            ; create_ctl parent override (0 = g_hwnd)
; --- private-desktop password prompt state (one at a time; never nests) -------
g_sd_hwnd    dq ?
ifdef DBG_TRACE
g_dbg_sdbuf  dw 8 dup (?)
g_dbg_nodesk dd ?
endif
g_pw_ready   dd ?                            ; password already collected pre-window
g_container  dd ?                            ; 1 = window shows a .mrk's contents
g_idx_bytes  dq ?                            ; bytes the inventory accounts for
g_idx_files  dq ?                            ; inventory entries that are FILES
g_idx_dirs   dq ?                            ; inventory entries that are DIRECTORIES
g_scan_dirs  dq ?                            ; folders the summary should mention (0 = none)
g_rowname    dw 4096 dup (?)                 ; one inventory name, widened
g_delname2   db 4096 dup (?)                 ; one entry name to remove, UTF-8
g_sd_show    dd ?                            ; prompt reveal state
g_sd_hunder  dq ?
g_sd_hcunder dq ?
g_sd_hshow   dq ?
g_sd_hpass   dq ?
g_sd_hconf   dq ?
g_sd_hfmt    dq ?                            ; prompt format chip (encrypt only)
g_sd_hok     dq ?
g_sd_hdesk   dq ?                            ; HDESK while the prompt is up
g_sd_flags   dd ?                            ; SDF_*
g_sd_result  dd ?                            ; SDR_*
g_sd_height  dd ?                            ; computed client height
g_sd_fmty    dd ?                            ; y of the format row, from the height pass
g_sd_done    dd ?                            ; 1 once the window is gone
g_sd_reg     dd ?                            ; 1 once the class is registered

.code

; =============================================================================
; wcopy(rcx = dst, rdx = src wide NUL-term, r8 = last writable wide char in dst)
;   -> rax = ptr to the dst NUL terminator (so appends chain: rcx = rax)
;
; Copies until the source NUL or until dst reaches r8, whichever comes first,
; and ALWAYS NUL-terminates.  r8 addresses the last slot that may be written,
; so the terminator may legally land on it.
;
; The bound is not optional.  Without it this copied argv[i] - up to
; MAX_PATH_CHARS wide chars - into a SLOT_CHARS (4096) input slot, overrunning
; it by up to ~57 KB through the neighbouring slots and on into g_outpath_w,
; g_crumbw, g_passw and the rest of .data?.  That is a global-section overflow,
; so neither the stack canary nor either shadow stack can see it;
; tools/wstrcheck.py exists to keep every call site passing r8.
; =============================================================================
wcopy proc
    xor     r9, r9
wcp_l:
    lea     r10, [rcx+r9*2]
    cmp     r10, r8
    jae     wcp_trunc                   ; at the last slot: terminate, do not grow
    mov     ax, word ptr [rdx+r9*2]
    mov     word ptr [rcx+r9*2], ax
    test    ax, ax
    jz      wcp_d
    inc     r9
    jmp     wcp_l
wcp_trunc:
    ; flags still hold `cmp r10, r8`.  Strictly past the bound means the caller
    ; handed us a dst that is already out of room (an append chain that stepped
    ; over a separator), so write nothing at all rather than one wchar past it.
    ja      wcp_d
    mov     word ptr [rcx+r9*2], 0
wcp_d:
    lea     rax, [rcx+r9*2]
    ret
wcopy endp

; =============================================================================
; wlen(rcx = wide ptr) -> rax = length in chars
; =============================================================================
wlen proc
    xor     rax, rax
wl_l:
    cmp     word ptr [rcx+rax*2], 0
    je      wl_d
    inc     rax
    jmp     wl_l
wl_d:
    ret
wlen endp

; =============================================================================
; wzero(rcx = wide ptr, rdx = char count) - zero a wide buffer
; =============================================================================
wzero proc
    xor     r9, r9
wz_l:
    cmp     r9, rdx
    jae     wz_d
    mov     word ptr [rcx+r9*2], 0
    inc     r9
    jmp     wz_l
wz_d:
    ret
wzero endp

; =============================================================================
; wfindbase(rcx = path) -> rax = ptr to char after the last '\' or '/', or the
; start of the string if there is no separator.  (Leaf.)
; =============================================================================
wfindbase proc
    mov     rax, rcx                     ; default = start
    xor     r9, r9
wfb_l:
    movzx   edx, word ptr [rcx+r9*2]
    test    edx, edx
    jz      wfb_d
    cmp     edx, 5Ch                     ; '\'
    je      wfb_sep
    cmp     edx, 2Fh                     ; '/'
    jne     wfb_next
wfb_sep:
    lea     rax, [rcx+r9*2+2]            ; char after the separator
wfb_next:
    inc     r9
    jmp     wfb_l
wfb_d:
    ret
wfindbase endp

; =============================================================================
; slot_addr(rcx = input index) -> rax = wide buffer for that input.
; index 0 is g_filepath_w (also positionals[0]); index>=1 is an extra slot.
; (Leaf; clobbers rax, rcx, r8.)
; =============================================================================
; Returns rax = slot base AND r8 = the slot's last writable wide char, because
; slot 0 is g_filepath_w (FILEPATH_CHARS) while the rest are SLOT_CHARS slots -
; a caller cannot bound the copy without knowing which it got.  Handing both
; back from here is what keeps the two in step.
slot_addr proc
    test    rcx, rcx
    jnz     sa_extra
    lea     rax, [g_filepath_w]
    WBOUND  r8, g_filepath_w, FILEPATH_CHARS
    ret
sa_extra:
    dec     rcx
    imul    rax, rcx, SLOT_CHARS*2
    lea     r8, [g_inslots]
    add     rax, r8
    lea     r8, [rax + (SLOT_CHARS - 1) * 2]
    ret
slot_addr endp

; =============================================================================
; set_input_ptrs(rcx = count) - fill g_positionals[0..count-1] with slot
; addresses and set g_poscount (capped at MAX_ARGS).
; =============================================================================
set_input_ptrs proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    cmp     rcx, MAX_ARGS
    jbe     @F
    mov     rcx, MAX_ARGS
@@:
    mov     qword ptr [rbp-8], rcx
    xor     r9, r9
sip_l:
    cmp     r9, qword ptr [rbp-8]
    jae     sip_d
    mov     qword ptr [rbp-16], r9
    mov     rcx, r9
    call    slot_addr                    ; rax = slot ptr
    mov     r9, qword ptr [rbp-16]
    lea     r11, [g_positionals]
    mov     qword ptr [r11+r9*8], rax
    inc     r9
    jmp     sip_l
sip_d:
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [g_poscount], rax
    add     rsp, 48
    pop     rbp
    ret
set_input_ptrs endp

; =============================================================================
; refresh_inputs - re-run everything that depends on the input list, after it
; has grown.  Same sequence create_controls_enc runs at startup: work out the
; common root, redraw the breadcrumb, then hand the size walk to the indexer
; thread, whose completion (on_index_done) refills the listview and the summary.
;
; Kept as one proc because the order matters and there are now three callers -
; startup, a drop, and the Add menu.
; =============================================================================
refresh_inputs proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     eax, 1
    cmp     qword ptr [g_poscount], 0
    jne     @F
    xor     eax, eax
@@:
    mov     dword ptr [g_has_file], eax
    call    compute_root
    call    build_crumb
    call    build_crumb_short
    ; the breadcrumb is painted by the parent, not a control of its own
    WINCALL InvalidateRect, qword ptr [g_hwnd], 0, 1
    call    start_indexing
    add     rsp, 48
    pop     rbp
    ret
refresh_inputs endp

; =============================================================================
; append_input(rcx = wide path) -> eax = 1 if it was taken.
;
; The one place a new input is written into a slot, shared by the drop path and
; both pickers.  Bounded twice: at MAX_ARGS inputs and at the slot's own
; capacity, and it REFUSES rather than truncates - a truncated path names a
; different file, which is the one thing an encryption tool must not quietly do.
;
; locals: [rbp-8]=src [rbp-16]=slot [rbp-24]=cch
; =============================================================================
append_input proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     rax, qword ptr [g_poscount]
    cmp     rax, MAX_ARGS
    jae     ai_no
    ; slot 0 is g_filepath_w; 1.. are g_inslots entries, which are smaller
    mov     dword ptr [rbp-24], SLOT_CHARS
    test    rax, rax
    jnz     @F
    mov     dword ptr [rbp-24], FILEPATH_CHARS
@@:
    mov     rcx, rax
    call    slot_addr                       ; rax = slot base, r8 = its bound
    mov     qword ptr [rbp-16], rax
    ; length check before any copying
    mov     rcx, qword ptr [rbp-8]
    call    wlen
    inc     rax                             ; + terminator
    cmp     eax, dword ptr [rbp-24]
    ja      ai_no
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-8]
    mov     r8, qword ptr [rbp-16]
    mov     eax, dword ptr [rbp-24]
    dec     eax
    lea     r8, [r8+rax*2]                  ; last writable wide char
    call    wcopy
    inc     qword ptr [g_poscount]
    ; Adding a path undoes any exclusion at or beneath it.  Without this a user
    ; who removes a file and later drags its folder back in keeps encrypting
    ; without that file, with nothing on screen saying so - their own removal
    ; would be impossible to reverse.
    lea     rcx, [g_excluded]
    mov     rdx, qword ptr [rbp-16]
    call    pset_remove_under
    mov     eax, 1
    jmp     ai_ret
ai_no:
    xor     eax, eax
ai_ret:
    add     rsp, 64
    pop     rbp
    ret
append_input endp


; =============================================================================
; take_shellitem(rcx = IShellItem*) - resolve it to a filesystem path and hand
; it to append_input.  Non-filesystem items (a library, a search result) have no
; SIGDN_FILESYSPATH and are skipped rather than guessed at.
; =============================================================================
take_shellitem proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], 0
    mov     rcx, qword ptr [rbp-8]
    mov     edx, SIGDN_FILESYSPATH
    lea     r8, [rbp-16]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_GetDisplayName]
    test    eax, eax
    jnz     ts_ret
    mov     rcx, qword ptr [rbp-16]
    call    append_input
    WINCALL CoTaskMemFree, qword ptr [rbp-16]
ts_ret:
    add     rsp, 64
    pop     rbp
    ret
take_shellitem endp

; =============================================================================
; add_via_picker(ecx = 1 for a folder, 0 for files) - the Add... menu items.
;
; Same IFileOpenDialog the destination picker uses.  Files mode asks for
; FOS_ALLOWMULTISELECT and reads the whole selection back through
; IShellItemArray; folder mode is the single-result path, because a folder
; picker cannot multi-select and the shell will not let it.
;
; locals: [rbp-8]=pfd [rbp-16]=result [rbp-24]=unused [rbp-40]=folder?
;         [rbp-48]=opts [rbp-56]=count [rbp-64]=i [rbp-72]=item
; =============================================================================
add_via_picker proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 160
    mov     dword ptr [rbp-40], ecx
    mov     qword ptr [rbp-8], 0
    mov     qword ptr [rbp-16], 0
    WINCALL CoInitializeEx, 0, COINIT_APARTMENTTHREADED
    lea     rax, [rbp-8]
    WINCALL CoCreateInstance, addr clsid_fileopen, 0, CLSCTX_INPROC_SERVER, addr iid_ifileopen, rax
    test    eax, eax
    jnz     avp_uninit
    ; options
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [rbp-48]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_GetOptions]
    mov     edx, dword ptr [rbp-48]
    or      edx, FOS_FILEMUSTEXIST
    cmp     dword ptr [rbp-40], 0
    je      avp_files
    or      edx, FOS_PICKFOLDERS
    jmp     avp_setopt
avp_files:
    or      edx, FOS_ALLOWMULTISELECT
avp_setopt:
    mov     rcx, qword ptr [rbp-8]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_SetOptions]
    ; Title.  Four of them: files or folder, crossed with what the picked paths
    ; are FOR.  "Add files to encrypt" is a lie when the window is browsing an
    ; archive and the picker is feeding an append - the same dialog, two
    ; different jobs.  g_pick_only is exactly the flag that says which, because
    ; container_add is the only thing that sets it.
    lea     rdx, [t_addfiles]
    lea     r9, [t_addfiles_arc]
    cmp     dword ptr [rbp-40], 0
    je      @F
    lea     rdx, [t_addfolder]
    lea     r9, [t_addfolder_arc]
@@:
    cmp     dword ptr [g_pick_only], 0
    je      avp_title
    mov     rdx, r9
avp_title:
    mov     rcx, qword ptr [rbp-8]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_SetTitle]
    ; Show - a non-zero HRESULT is a cancel, which is not an error
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, qword ptr [g_hwnd]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Show]
    test    eax, eax
    jnz     avp_release
    cmp     dword ptr [rbp-40], 0
    je      avp_multi
    ; ---- folder: one IShellItem -------------------------------------------
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [rbp-16]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_GetResult]
    test    eax, eax
    jnz     avp_release
    mov     rcx, qword ptr [rbp-16]
    call    take_shellitem
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Release]
    jmp     avp_release
    ; ---- files: an IShellItemArray -----------------------------------------
avp_multi:
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [rbp-16]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_GetResults]
    test    eax, eax
    jnz     avp_release
    mov     dword ptr [rbp-56], 0
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [rbp-56]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_SIA_GetCount]
    mov     qword ptr [rbp-64], 0
avp_loop:
    mov     eax, dword ptr [rbp-56]
    cmp     qword ptr [rbp-64], rax
    jae     avp_arrdone
    mov     qword ptr [rbp-72], 0
    mov     rcx, qword ptr [rbp-16]
    mov     edx, dword ptr [rbp-64]
    lea     r8, [rbp-72]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_SIA_GetItemAt]
    test    eax, eax
    jnz     avp_arrnext
    mov     rcx, qword ptr [rbp-72]
    call    take_shellitem
    mov     rcx, qword ptr [rbp-72]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Release]
avp_arrnext:
    inc     qword ptr [rbp-64]
    jmp     avp_loop
avp_arrdone:
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Release]
avp_release:
    mov     rcx, qword ptr [rbp-8]
    test    rcx, rcx
    jz      avp_uninit
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Release]
avp_uninit:
    WINCALL CoUninitialize
    ; In container mode the picked paths are arguments to an APPEND, not new
    ; entries in the input list, and rebuilding that list here would replace the
    ; archive listing on screen and start the indexer walking files nothing is
    ; going to pack.  container_add sets this and repaints the archive itself.
    ; set_input_ptrs runs EITHER way: it is what fills g_positionals[] from the
    ; input slots, and do_add/do_zip_add walk that array.  Skipping it left
    ; positionals[1] stale and the append followed a dead pointer.  Only the
    ; list REPAINT is container-mode-inappropriate.
    mov     rcx, qword ptr [g_poscount]
    call    set_input_ptrs
    cmp     dword ptr [g_pick_only], 0
    jne     avp_nolist
    call    refresh_inputs
avp_nolist:
    add     rsp, 160
    pop     rbp
    ret
add_via_picker endp

; =============================================================================
; add_dropped(rcx = HDROP) - append the dropped paths to the input slots.
;
; Bounded twice over, because this is data from another process: at MAX_ARGS
; inputs, and at each slot's own character capacity.  DragQueryFileW is asked
; for the length first and the copy is skipped rather than truncated if it will
; not fit - a truncated path is a different file, which is the one outcome an
; encryption tool must never quietly produce.
;
; locals: [rbp-8]=hdrop [rbp-16]=count [rbp-24]=i [rbp-32]=slot [rbp-40]=cch
; =============================================================================
add_dropped proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     qword ptr [rbp-8], rcx
    ; how many were dropped?
    WINCALL DragQueryFileW, qword ptr [rbp-8], 0FFFFFFFFh, 0, 0
    mov     dword ptr [rbp-16], eax
    test    eax, eax
    jz      ad_done
    mov     qword ptr [rbp-24], 0
ad_loop:
    mov     eax, dword ptr [rbp-16]
    cmp     qword ptr [rbp-24], rax
    jae     ad_done
    ; Ask the shell for the length, take it into scratch, then let append_input
    ; apply the slot bounds.  Routing the drop through the same writer the
    ; pickers use means one place decides what fits, instead of two that have to
    ; agree - and it puts append_input under the drop test as well.
    WINCALL DragQueryFileW, qword ptr [rbp-8], dword ptr [rbp-24], 0, 0
    test    eax, eax
    jz      ad_next
    inc     eax                             ; + terminator
    cmp     eax, MAX_PATH_CHARS
    ja      ad_next                         ; longer than Windows can name
    WINCALL DragQueryFileW, qword ptr [rbp-8], dword ptr [rbp-24],             addr g_dropbuf, MAX_PATH_CHARS
    test    eax, eax
    jz      ad_next
    lea     rcx, [g_dropbuf]
    call    append_input
ad_next:
    inc     qword ptr [rbp-24]
    jmp     ad_loop
ad_done:
    ; set_input_ptrs rebuilds the pointer table for the new count, and runs
    ; EITHER way - the append procs walk g_positionals[], so skipping it would
    ; leave them following a stale pointer.  Only the list repaint is wrong when
    ; the drop is feeding an archive rather than the input list.
    mov     rcx, qword ptr [g_poscount]
    call    set_input_ptrs
    cmp     dword ptr [g_pick_only], 0
    jne     ad_nolist
    call    refresh_inputs
ad_nolist:
    add     rsp, 96
    pop     rbp
    ret
add_dropped endp

; =============================================================================
; drop_allowed() -> eax = 1 if a drop should be accepted right now.
;
; Split out because it is now asked TWICE per drag and the two answers have to
; be the same one: DragEnter asks it to choose the cursor, and Drop asks it
; again before acting.  A window that shows the copy cursor and then silently
; does nothing is worse than one that shows "no entry" from the start.
; =============================================================================
drop_allowed proc
    xor     eax, eax
    ; Never while an operation is running: adding inputs underneath one would
    ; change what it is working on.
    cmp     dword ptr [g_running], 0
    jne     dal_ret
    ; Browsing an archive?  Then a drop MEANS "add these to it".
    cmp     dword ptr [g_container], 0
    jne     dal_yes
    ; The decrypt dialog is built around exactly one container - its layout and
    ; its destination logic both assume that - so a drop there is refused rather
    ; than half-honoured.
    cmp     dword ptr [g_op], 0
    jne     dal_ret
dal_yes:
    mov     eax, 1
dal_ret:
    ret
drop_allowed endp

; =============================================================================
; drop_hdrop(rcx = HDROP) - carry out a drop, whichever way it arrived.
;
; Shared by WM_DROPFILES and IDropTarget::Drop, and shared rather than copied
; on purpose: the entire point of the OLE target is to be the SAME behaviour
; with feedback attached, and two copies of "what a drop means" would drift the
; first time either was edited.
;
; Does NOT free the HDROP.  WM_DROPFILES owns its one (DragFinish) and the
; STGMEDIUM owns its one (ReleaseStgMedium); the two are not interchangeable,
; and freeing here would double-free whichever caller then did its own.
;
; locals: [rbp-16] = hdrop
; =============================================================================
drop_hdrop proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    call    drop_allowed
    test    eax, eax
    jz      dh_ret
    cmp     dword ptr [g_container], 0
    je      dh_encrypt
    ; The container path: collect the paths, then run the append the Add files
    ; button runs.  It used to be refused in silence, which was defensible when
    ; the container view could only be read and stopped being so the moment it
    ; could be added to: the two surfaces for one action have to agree.
    mov     rax, qword ptr [g_poscount]
    mov     qword ptr [g_drop_pos0], rax
    mov     dword ptr [g_pick_only], 1
    mov     rcx, qword ptr [rbp-16]
    call    add_dropped
    mov     dword ptr [g_pick_only], 0
    mov     rcx, qword ptr [g_drop_pos0]
    call    container_add_run
    jmp     dh_ret
dh_encrypt:
    ; Where the new inputs go has to be decided from the row model as it stands
    ; NOW - add_dropped appends rows and renumbers nothing, but refresh_inputs
    ; rebuilds the tree, and after that the destination row index means
    ; something else.
    mov     rax, qword ptr [g_poscount]
    mov     qword ptr [rbp-24], rax
    call    stage_dest_capture
    ; g_pick_only suppresses add_dropped's OWN refresh, exactly as the container
    ; path uses it.  The refresh has to happen after the staging, or the rebuild
    ; runs before g_pos_prefix says where anything goes and the new rows land at
    ; the top level - but letting add_dropped refresh as well starts a SECOND
    ; indexer pass over the same inputs, and the two of them double-count.  The
    ; symptom was a status line reading "6 files" for three.
    mov     dword ptr [g_pick_only], 1
    mov     rcx, qword ptr [rbp-16]
    call    add_dropped
    mov     dword ptr [g_pick_only], 0
    mov     rcx, qword ptr [rbp-24]
    call    stage_dropped
    call    refresh_inputs                  ; once, and after the staging
dh_ret:
    FRAME_EPILOG
    ret
drop_hdrop endp

; =============================================================================
; stage_dest_capture - freeze the drop destination before the inputs move.
;
; Turns g_add_row (a ROW INDEX, valid only against the tree as it is right now)
; into an archive path, which stays meaningful across the rebuild that follows.
; Also opens the destination, so what lands in it is visible immediately -
; the container view learned that lesson the hard way in 1.0.20.
;
; locals: [rbp-24] row
; =============================================================================
stage_dest_capture proc frame
    FRAME_PROLOG 1152
    mov     dword ptr [g_stage_dest], 0
    cmp     dword ptr [g_add_row_set], 0
    je      sdc_ret
    movsxd  rax, dword ptr [g_add_row]
    cmp     rax, 0
    jl      sdc_ret                         ; the root: nothing to stage
    cmp     rax, qword ptr [g_rowcount]
    jae     sdc_ret
    mov     qword ptr [rbp-24], rax
    ; the destination's archive path
    mov     rcx, qword ptr [rbp-24]
    call    row_path
    mov     qword ptr [rbp-32], rax
    mov     rax, qword ptr [rbp-24]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     edx, dword ptr [r10+ROW_inputi]
    mov     rcx, qword ptr [rbp-32]
    lea     r8, [g_stagebufw]
    mov     r9, 1000
    call    arch_of
    test    eax, eax
    jz      sdc_ret
    mov     dword ptr [g_stage_destlen], eax
    mov     dword ptr [g_stage_dest], 1
    ; open it, so the file that is about to land is not dropped into a shut box
    lea     rcx, [g_expanded]
    mov     rdx, qword ptr [rbp-32]
    call    pset_add
sdc_ret:
    mov     dword ptr [g_add_row_set], 0
    FRAME_EPILOG
    ret
stage_dest_capture endp

; =============================================================================
; stage_dropped(rcx = the first newly added input) - point them all at the
; destination stage_dest_capture froze.
;
; Every dropped file goes to the same folder, because one drag has one cursor.
; =============================================================================
stage_dropped proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_stage_dest], 0
    je      sd_ret                          ; the root: leave them unstaged
sd_loop:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     sd_ret
    mov     rcx, rax
    lea     rdx, [g_stagebufw]
    movsxd  r8, dword ptr [g_stage_destlen]
    call    pfx_stage
    inc     qword ptr [rbp-24]
    jmp     sd_loop
sd_ret:
    mov     dword ptr [g_stage_dest], 0
    FRAME_EPILOG
    ret
stage_dropped endp

; =============================================================================
; IDropTarget - the window as a real OLE drop target.
;
; One static instance, g_droptgt, which is a vtable pointer and nothing else:
; there is exactly one window, it lives as long as the process, and a drag
; carries no state that DragEnter would have to allocate.  So no heap block and
; no lifetime to get wrong.  g_dt_refs exists only so Release has something to
; return; it never frees anything.
;
; Shape follows the hand-written vtables in shellext.asm.  Its rule about not
; using FRAME_PROLOG does NOT apply here: that is a DLL loaded into Explorer,
; whereas this object lives in the exe, which has the canary and the shadow
; stack, and the UI thread has both.
; =============================================================================

; -----------------------------------------------------------------------------
; dt_guid_eq(rcx = a, rdx = b) -> eax = 1 if the two 16-byte GUIDs match.
; -----------------------------------------------------------------------------
dt_guid_eq proc
    mov     rax, qword ptr [rcx]
    cmp     rax, qword ptr [rdx]
    jne     dge_no
    mov     rax, qword ptr [rcx+8]
    cmp     rax, qword ptr [rdx+8]
    jne     dge_no
    mov     eax, 1
    ret
dge_no:
    xor     eax, eax
    ret
dt_guid_eq endp

; -----------------------------------------------------------------------------
; dt_fill_fmt - describe the one format this window wants: CF_HDROP, on an
; HGLOBAL.  The whole first qword is cleared before the WORD goes in, because
; cfFormat is followed by six bytes of padding that GetData reads as part of
; nothing and a debugger reads as garbage.
; -----------------------------------------------------------------------------
dt_fill_fmt proc
    lea     r10, [g_dt_fmt]
    mov     qword ptr [r10+FE_cfFormat], 0
    mov     word ptr [r10+FE_cfFormat], CF_HDROP
    mov     qword ptr [r10+FE_ptd], 0
    mov     dword ptr [r10+FE_dwAspect], DVASPECT_CONTENT
    mov     dword ptr [r10+FE_lindex], -1
    mov     dword ptr [r10+FE_tymed], TYMED_HGLOBAL
    ret
dt_fill_fmt endp

; -----------------------------------------------------------------------------
; dt_has_hdrop(rcx = IDataObject*) -> eax = 1 if it offers CF_HDROP.
;
; QueryGetData, not GetData: this runs on every DragEnter, and GetData would
; render and hand over a copy of the file list only to have it thrown away.
; locals: [rbp-16] = pDataObj
; -----------------------------------------------------------------------------
dt_has_hdrop proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    test    rcx, rcx
    jz      dhh_no
    call    dt_fill_fmt
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [g_dt_fmt]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+IDO_QUERYGETDATA]
    test    eax, eax
    jnz     dhh_no                          ; S_OK is 0; S_FALSE and errors are not
    mov     eax, 1
    jmp     dhh_ret
dhh_no:
    xor     eax, eax
dhh_ret:
    FRAME_EPILOG
    ret
dt_has_hdrop endp

; -----------------------------------------------------------------------------
; DT_QueryInterface(rcx = this, rdx = riid, r8 = ppv)
; locals: [rbp-16] = this  [rbp-24] = riid  [rbp-32] = ppv
; -----------------------------------------------------------------------------
DT_QueryInterface proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    test    r8, r8
    jz      dqi_badarg
    mov     qword ptr [r8], 0               ; null the out param BEFORE failing
    test    rdx, rdx
    jz      dqi_badarg
    WINCALL dt_guid_eq, qword ptr [rbp-24], addr iid_idroptarget
    test    eax, eax
    jnz     dqi_hand
    WINCALL dt_guid_eq, qword ptr [rbp-24], addr iid_iunknown
    test    eax, eax
    jnz     dqi_hand
    mov     eax, E_NOINTERFACE
    jmp     dqi_ret
dqi_hand:
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [r10], rax
    lock inc dword ptr [g_dt_refs]
    mov     eax, S_OK
    jmp     dqi_ret
dqi_badarg:
    mov     eax, E_INVALIDARG
dqi_ret:
    FRAME_EPILOG
    ret
DT_QueryInterface endp

DT_AddRef proc
    mov     eax, 1
    lock xadd dword ptr [g_dt_refs], eax
    inc     eax
    ret
DT_AddRef endp

; Release never destroys anything: the object is static and outlives every drag
; by the life of the process.  Returning the count is all COM asks of it.
DT_Release proc
    mov     eax, -1
    lock xadd dword ptr [g_dt_refs], eax
    dec     eax
    ret
DT_Release endp

; -----------------------------------------------------------------------------
; DT_DragEnter(rcx = this, rdx = pDataObj, r8d = grfKeyState,
;              r9 = pt, [rbp+48] = pdwEffect)
;
; POINTL is two LONGs - eight bytes - so it is passed BY VALUE in r9, packed x
; in the low dword and y in the high.  That pushes pdwEffect out to the FIFTH
; argument, at [rbp+48] once the frame is up.  Taking it from r9 instead, which
; the argument list invites, hands the effect writer a pair of screen
; coordinates to store through.
;
; locals: [rbp-16] = pDataObj  [rbp-24] = pdwEffect
; -----------------------------------------------------------------------------
DT_DragEnter proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rdx
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-24], rax
    mov     dword ptr [g_dt_eff], DROPEFFECT_NONE
    test    rax, rax
    jz      dde_badarg
    call    drop_allowed
    test    eax, eax
    jz      dde_store
    mov     rcx, qword ptr [rbp-16]
    call    dt_has_hdrop
    test    eax, eax
    jz      dde_store
    mov     dword ptr [g_dt_eff], DROPEFFECT_COPY
dde_store:
    ; COPY, never MOVE: a drop must not make the shell delete the original.
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [g_dt_eff]
    mov     dword ptr [r10], eax
    mov     eax, S_OK
    jmp     dde_ret
dde_badarg:
    mov     eax, E_INVALIDARG
dde_ret:
    FRAME_EPILOG
    ret
DT_DragEnter endp

; -----------------------------------------------------------------------------
; DT_DragOver(rcx = this, edx = grfKeyState, r8 = pt, r9 = pdwEffect)
;
; Four arguments, not five: there is no data object here, so pdwEffect moves up
; into r9 and the point stays in r8 - still packed by value, still two LONGs.
;
; The effect repeats what DragEnter decided; nothing it depends on can change
; while the cursor moves.  What DOES change is where the files would land, and
; this is the only notification that can say so.
;
; locals: [rbp-16] pdwEffect  [rbp-24] pt
; -----------------------------------------------------------------------------
DT_DragOver proc frame
    FRAME_PROLOG 64
    test    r9, r9
    jz      dov_badarg
    mov     qword ptr [rbp-16], r9
    mov     qword ptr [rbp-24], r8
    ; No line while the drag is refused: the cursor already says no, and a line
    ; under it would say the opposite.
    cmp     dword ptr [g_dt_eff], DROPEFFECT_NONE
    je      dov_noline
if STAGED_DROP_ENABLED eq 0
    ; The encrypt view shows no destination while staging is gated off: a box
    ; promising a folder the drop will not honour is worse than no box.
    cmp     dword ptr [g_container], 0
    je      dov_noline
endif
    mov     rcx, qword ptr [rbp-24]
    call    dt_row_from_pt
    mov     rcx, rax
    call    dest_row_from_hit
    mov     rcx, rax
    call    drop_box_set
    jmp     dov_eff
dov_noline:
    call    drop_box_clear
dov_eff:
    mov     r10, qword ptr [rbp-16]
    mov     eax, dword ptr [g_dt_eff]
    mov     dword ptr [r10], eax
    mov     eax, S_OK
    jmp     dov_ret
dov_badarg:
    mov     eax, E_INVALIDARG
dov_ret:
    FRAME_EPILOG
    ret
DT_DragOver endp

; DragLeave gets no chance to report anything, so there is nothing to do but
; forget the effect.  It must stay cheap: it runs on every drag that merely
; passes over the window.
DT_DragLeave proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_dt_eff], DROPEFFECT_NONE
    mov     dword ptr [g_add_row_set], 0    ; the destination leaves with the drag
    call    drop_box_clear
    mov     eax, S_OK
    FRAME_EPILOG
    ret
DT_DragLeave endp

; -----------------------------------------------------------------------------
; DT_Drop(rcx = this, rdx = pDataObj, r8d = grfKeyState,
;         r9 = pt, [rbp+48] = pdwEffect)
;
; Re-asks drop_allowed rather than trusting the effect DragEnter chose: the
; window can start an operation between the two, and the drag would still be
; showing the copy cursor from before it did.
;
; The FORMATETC and STGMEDIUM are globals, not locals.  Drops are serialised on
; the UI thread - one window, one drag at a time - so there is nothing to share,
; and keeping the 56 bytes out of the frame keeps the outgoing-argument area
; clear of them.
;
; locals: [rbp-16] = pDataObj  [rbp-24] = pdwEffect
; -----------------------------------------------------------------------------
DT_Drop proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-32], r9          ; pt, for the destination
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-24], rax
    mov     dword ptr [g_dt_eff], DROPEFFECT_NONE
    test    rax, rax
    jz      ddr_badarg
    ; The line has done its job either way, and it must go before the append
    ; repaints the list underneath it.  After the null check, not before: this
    ; call returns in rax, and clearing first would have the test read its
    ; result instead of pdwEffect.
    call    drop_box_clear
    mov     rax, qword ptr [rbp-24]
    ; NONE until the drop has actually been taken.  The source reads this back,
    ; and a drag that reports COPY for a drop it refused has told the shell the
    ; files arrived somewhere.
    mov     dword ptr [rax], DROPEFFECT_NONE
    cmp     qword ptr [rbp-16], 0
    je      ddr_ok
    call    drop_allowed
    test    eax, eax
    jz      ddr_ok
    call    dt_fill_fmt
    lea     r10, [g_dt_med]
    mov     qword ptr [r10+STG_tymed], 0
    mov     qword ptr [r10+STG_handle], 0
    mov     qword ptr [r10+STG_pUnkForRelease], 0
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [g_dt_fmt]
    lea     r8, [g_dt_med]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+IDO_GETDATA]
    test    eax, eax
    jnz     ddr_ok                          ; no CF_HDROP: nothing was dropped
    mov     rcx, qword ptr [g_dt_med+STG_handle]
    test    rcx, rcx
    jz      ddr_release
    ; Where it lands, hit-tested from THIS message's point rather than carried
    ; over from the last DragOver: the cursor at the moment of release is the
    ; authoritative one, and re-asking costs one hit test.
if STAGED_DROP_ENABLED eq 0
    cmp     dword ptr [g_container], 0
    je      ddr_go                          ; encrypt view: the root, as before
endif
    mov     qword ptr [rbp-40], rcx         ; the HDROP, across the two calls
    mov     rcx, qword ptr [rbp-32]         ; pt
    call    dt_row_from_pt
    mov     rcx, rax
    call    dest_row_from_hit
    mov     dword ptr [g_add_row], eax
    mov     dword ptr [g_add_row_set], 1
    mov     rcx, qword ptr [rbp-40]
ddr_go:
    ; add_dropped copies every path out into the input slots before it returns,
    ; so the medium can be released immediately afterwards even though the
    ; append itself runs on the worker thread.
    call    drop_hdrop
    mov     r10, qword ptr [rbp-24]
    mov     dword ptr [r10], DROPEFFECT_COPY
ddr_release:
    WINCALL ReleaseStgMedium, addr g_dt_med
ddr_ok:
    mov     eax, S_OK
    jmp     ddr_ret
ddr_badarg:
    mov     eax, E_INVALIDARG
ddr_ret:
    FRAME_EPILOG
    ret
DT_Drop endp

ifdef DBG_TRACE
; =============================================================================
; dt_selfdrop - TEST BUILDS ONLY.  Drive the registered IDropTarget through a
; full DragEnter / DragOver / Drop using whatever data object is on the
; clipboard as the drag source.
;
; The clipboard is what makes this path testable at all.  Everything else fails
; for its own reason: a synthetic WM_DROPFILES cannot cross the process
; boundary (UIPI), and a scripted OLE drag hangs because DoDragDrop only calls
; QueryContinueDrag when the drag loop receives input.  But OleGetClipboard
; returns a genuine system IDataObject carrying CF_HDROP the moment anything
; copies files - one line from a test - so nothing here is a mock: the same
; GetData, the same STGMEDIUM, the same HDROP a shell drag would produce.
;
; Not covered: ole32's own delivery of a drag to a registered target.  That is
; Microsoft's code, and g_dt_ok records that it accepted the registration.
;
; Calls THROUGH the vtable, never the procs directly, so a slot in the wrong
; order fails the test rather than passing it.
;
; rcx = the POINTL to drag over, packed, in SCREEN coordinates - so a test can
; aim at a particular row and check that the destination follows the cursor
; rather than the selection.  edx = 1 stops after DragOver, leaving the
; insertion line up for the pixels to be inspected; 0 runs the whole sequence.
;
; locals: [rbp-16] = pDataObj  [rbp-24] = effect (in and out)
;         [rbp-32] = pt        [rbp-40] = mode
; =============================================================================
dt_selfdrop proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-32], rcx
    mov     dword ptr [rbp-40], edx
    mov     qword ptr [rbp-16], 0
    mov     dword ptr [rbp-24], DROPEFFECT_COPY
    lea     rax, [rbp-16]
    WINCALL OleGetClipboard, rax
    test    eax, eax
    jnz     dsd_ret
    cmp     qword ptr [rbp-16], 0
    je      dsd_ret
    ; DragEnter(this, pDataObj, 0, pt, &effect)
    lea     rcx, [g_droptgt]
    mov     rdx, qword ptr [rbp-16]
    xor     r8d, r8d
    mov     r9, qword ptr [rbp-32]          ; POINTL by value
    lea     rax, [rbp-24]
    mov     qword ptr [rsp+32], rax
    mov     rax, qword ptr [g_droptgt]
    call    qword ptr [rax+IDT_DRAGENTER]
    ; DragOver(this, 0, pt, &effect)
    lea     rcx, [g_droptgt]
    xor     edx, edx
    mov     r8, qword ptr [rbp-32]
    lea     r9, [rbp-24]
    mov     rax, qword ptr [g_droptgt]
    call    qword ptr [rax+IDT_DRAGOVER]
    ; Hover-only stops here, WITHOUT DragLeave, so the line stays painted.  The
    ; data object is released either way - nothing here holds a reference to it
    ; past this point, and leaving one alive across a wait would be a leak the
    ; test could not see.
    cmp     dword ptr [rbp-40], 0
    jne     dsd_release
    ; A refused drag ends in DragLeave, not Drop - so follow whichever sequence
    ; the effect asks for, rather than always dropping.  Otherwise DragLeave is
    ; a slot nothing ever calls, and the refusal case is only half tested: the
    ; cursor says no and the test never asks what happens next.
    cmp     dword ptr [rbp-24], DROPEFFECT_NONE
    jne     dsd_drop
    lea     rcx, [g_droptgt]
    mov     rax, qword ptr [g_droptgt]
    call    qword ptr [rax+IDT_DRAGLEAVE]
    jmp     dsd_release
dsd_drop:
    ; Drop(this, pDataObj, 0, pt, &effect)
    lea     rcx, [g_droptgt]
    mov     rdx, qword ptr [rbp-16]
    xor     r8d, r8d
    mov     r9, qword ptr [rbp-32]
    lea     rax, [rbp-24]
    mov     qword ptr [rsp+32], rax
    mov     rax, qword ptr [g_droptgt]
    call    qword ptr [rax+IDT_DROP]
dsd_release:
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Release]
dsd_ret:
    FRAME_EPILOG
    ret
dt_selfdrop endp
endif

; --- message box wrapper: rcx=text rdx=title r8d=flags ------------------------
; mbox(rcx = text, rdx = title, r8d = MB_* flags) -> eax = IDOK / IDCANCEL
;
; Themed replacement for MessageBoxW, with the same argument order and return
; values so the nine call sites did not change.  Draws the borderless dark
; rounded panel the rest of the GUI uses instead of the system dialog, which
; looked pasted in from another program.
;
; Runs its own modal pump with the parent disabled.  It must not post WM_QUIT
; (that is the difference from show_about, which owns the only loop in the
; process): the main window's loop is alive underneath, so the box signals
; completion through g_mb_done instead.
mbox proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 256
    mov     qword ptr [g_mb_text], rcx
    mov     qword ptr [g_mb_title], rdx
    mov     dword ptr [g_mb_flags], r8d
    mov     dword ptr [g_mb_done], 0
    mov     dword ptr [g_mb_result], IDCANCEL    ; ESC / close = cancel
    call    mb_measure                           ; -> g_mb_texth, g_mb_h

    ; ---- register the class once ------------------------------------------
    cmp     dword ptr [g_mb_reg], 0
    jne     mb_haveclass
    lea     rcx, [g_wc]
    xor     r9, r9
mb_zwc:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, WC_SIZE
    jb      mb_zwc
    mov     dword ptr [g_wc+0], WC_SIZE
    mov     dword ptr [g_wc+4], CS_DROPSHADOW
    lea     rax, [mb_wndproc]
    mov     qword ptr [g_wc+8], rax
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [g_wc+24], rax
    WINCALL LoadCursorW, 0, IDC_ARROW
    mov     qword ptr [g_wc+40], rax
    mov     rax, qword ptr [g_hbr_dark]
    mov     qword ptr [g_wc+48], rax
    lea     rax, [wc_mbox]
    mov     qword ptr [g_wc+64], rax
    WINCALL RegisterClassExW, addr g_wc
    mov     dword ptr [g_mb_reg], 1
mb_haveclass:
    ; ---- centre over the parent when there is one, else the screen ---------
    mov     dword ptr [rbp-48], MB_W
    mov     eax, dword ptr [g_mb_h]
    mov     dword ptr [rbp-52], eax
    cmp     qword ptr [g_hwnd], 0
    je      mb_centre_screen
    WINCALL GetWindowRect, qword ptr [g_hwnd], addr g_mb_prc
    mov     eax, dword ptr [g_mb_prc+0]
    add     eax, dword ptr [g_mb_prc+8]
    sar     eax, 1
    sub     eax, MB_W / 2
    mov     dword ptr [rbp-72], eax              ; X
    mov     eax, dword ptr [g_mb_prc+4]
    add     eax, dword ptr [g_mb_prc+12]
    sar     eax, 1
    mov     r10d, dword ptr [g_mb_h]
    sar     r10d, 1
    sub     eax, r10d
    mov     dword ptr [rbp-76], eax              ; Y
    jmp     mb_create
mb_centre_screen:
    WINCALL GetSystemMetrics, SM_CXSCREEN
    sub     eax, MB_W
    sar     eax, 1
    mov     dword ptr [rbp-72], eax
    WINCALL GetSystemMetrics, SM_CYSCREEN
    sub     eax, dword ptr [g_mb_h]
    sar     eax, 1
    mov     dword ptr [rbp-76], eax
mb_create:
    WINCALL CreateWindowExW, <WS_EX_TOOLWINDOW or WS_EX_LAYERED>, addr wc_mbox, qword ptr [g_mb_title], \
            ST_MAINWND, dword ptr [rbp-72], dword ptr [rbp-76], dword ptr [rbp-48], dword ptr [rbp-52], \
            qword ptr [g_hwnd], 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_mb_hwnd], rax
    test    rax, rax
    jz      mb_ret                               ; creation failed: return IDCANCEL
    WINCALL SetLayeredWindowAttributes, qword ptr [g_mb_hwnd], 0, WIN_ALPHA, LWA_ALPHA
    mov     r8d, dword ptr [rbp-48]
    inc     r8d
    mov     r9d, dword ptr [rbp-52]
    inc     r9d
    WINCALL CreateRoundRectRgn, 0, 0, r8d, r9d, WIN_ROUND, WIN_ROUND
    WINCALL SetWindowRgn, qword ptr [g_mb_hwnd], rax, 1
    ; modal: block the parent for as long as the box is up
    cmp     qword ptr [g_hwnd], 0
    je      @F
    WINCALL EnableWindow, qword ptr [g_hwnd], 0
@@:
    WINCALL ShowWindow, qword ptr [g_mb_hwnd], SW_SHOW
    WINCALL UpdateWindow, qword ptr [g_mb_hwnd]
mb_loop:
    WINCALL GetMessageW, addr rbp-120, 0, 0, 0   ; MSG at [rbp-120..]
    test    eax, eax
    jz      mb_finish                            ; WM_QUIT: let the outer loop see it too
    js      mb_finish
    cmp     dword ptr [rbp-112], WM_KEYDOWN      ; MSG.message
    jne     mb_disp
    cmp     qword ptr [rbp-104], VK_ESCAPE       ; MSG.wParam
    jne     mb_disp
    mov     dword ptr [g_mb_result], IDCANCEL
    WINCALL DestroyWindow, qword ptr [g_mb_hwnd]
    jmp     mb_check
mb_disp:
    WINCALL IsDialogMessageW, qword ptr [g_mb_hwnd], addr rbp-120
    test    eax, eax
    jnz     mb_check
    WINCALL TranslateMessage, addr rbp-120
    WINCALL DispatchMessageW, addr rbp-120
mb_check:
    cmp     dword ptr [g_mb_done], 0
    je      mb_loop
mb_finish:
    ; re-enable BEFORE destroying anything else, or focus lands on another app
    cmp     qword ptr [g_hwnd], 0
    je      @F
    WINCALL EnableWindow, qword ptr [g_hwnd], 1
    ; Nothing to repaint on the way out.  A RDW_ALLCHILDREN erase stood here for
    ; one release, on the theory that draw_button greys from IsWindowEnabled and
    ; that IsWindowEnabled is FALSE for every child of a disabled parent - so the
    ; buttons would have drawn greyed for as long as a dialog was up.
    ;
    ; IT DOES NOT.  IsWindowEnabled reports the window's OWN state: with this
    ; window disabled and a dialog up, the Exit button still reads enabled, and
    ; still paints white.  tests/greytest.ps1 asserts exactly that, because it is
    ; the fact the theory got wrong.  So the erase repainted correct pixels with
    ; identical correct pixels, and its only effect was the full-window flash
    ; every time a dialog closed - the buttons visibly vanishing and coming back.
    ;
    ; The report it was written for was the Exit button being genuinely disabled
    ; after a removal, fixed in on_done.  Nothing here.
    WINCALL SetFocus, qword ptr [g_hwnd]
@@:
    mov     qword ptr [g_mb_hwnd], 0
mb_ret:
    mov     eax, dword ptr [g_mb_result]
    add     rsp, 256
    pop     rbp
    ret
mbox endp

; =============================================================================
; create_ctl(rcx=class, rdx=text, r8=style, r9=id ; [rbp+48]=x [+56]=y [+64]=w
;            [+72]=h) -> rax = hwnd ; also applies the GUI font
; =============================================================================
create_ctl proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 144
    mov     qword ptr [rbp-8], rcx      ; class
    mov     qword ptr [rbp-16], rdx     ; text
    mov     qword ptr [rbp-24], r8      ; style
    mov     qword ptr [rbp-32], r9      ; id
    ; CreateWindowExW(0, class, text, style, X, Y, W, H, parent, id, hinst, NULL)
    ; NOTE: hand-written, not WINCALL.  This proc's 112-byte frame makes the
    ; 12-argument outgoing area [rsp+32..88] overlap its own locals [rbp-8..-40],
    ; so the register arguments (class/text/style) MUST be read before the stack
    ; arguments are stored.  WINCALL stores stack args first, which would clobber
    ; the style local with lParam and create every control WS_CHILD-less.
    xor     ecx, ecx
    mov     rdx, qword ptr [rbp-8]
    mov     r8,  qword ptr [rbp-16]
    mov     r9,  qword ptr [rbp-24]
    mov     eax, dword ptr [rbp+48]
    mov     dword ptr [rsp+32], eax
    mov     eax, dword ptr [rbp+56]
    mov     dword ptr [rsp+40], eax
    mov     eax, dword ptr [rbp+64]
    mov     dword ptr [rsp+48], eax
    mov     eax, dword ptr [rbp+72]
    mov     dword ptr [rsp+56], eax
    ; Parent: g_ctl_parent when set, else the main window.  Every caller but the
    ; message box builds children of g_hwnd, and the About box works only because
    ; its wndproc assigns g_hwnd to itself on WM_CREATE.  mbox cannot do that -
    ; the main window is still live underneath it - so it sets g_ctl_parent for
    ; the duration instead.  Without this its controls are created as children of
    ; the MAIN window, hidden behind the box, and the box renders empty.
    mov     rax, qword ptr [g_ctl_parent]
    test    rax, rax
    jnz     @F
    mov     rax, qword ptr [g_hwnd]
@@:
    mov     qword ptr [rsp+64], rax
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rsp+72], rax
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [rsp+80], rax
    mov     qword ptr [rsp+88], 0
    call    CreateWindowExW
    mov     qword ptr [rbp-40], rax      ; hwnd
    ; set font
    WINCALL SendMessageW, rax, WM_SETFONT, qword ptr [g_hfont], 1
    mov     rax, qword ptr [rbp-40]
    add     rsp, 144
    pop     rbp
    ret
create_ctl endp

; --- helper macro to fit x/y/w/h into the outgoing arg area --------------------
MKCTL macro classp, textp, style, idv, xx, yy, ww, hh, dst
    lea     rcx, [classp]
    lea     rdx, [textp]
    mov     r8, style
    mov     r9, idv
    mov     dword ptr [rsp+32], xx
    mov     dword ptr [rsp+40], yy
    mov     dword ptr [rsp+48], ww
    mov     dword ptr [rsp+56], hh
    call    create_ctl
    mov     qword ptr [dst], rax
endm

; =============================================================================
; fmt_size(rcx = bytes, rdx = dst wide buf) - human-readable size into dst.
;   < 1024            -> "<n> B"
;   otherwise         -> "<int>.<tenth> <KB|MB|GB|TB>"  (one decimal)
; Raw leaf-ish (own frame, no FRAME_PROLOG).  Clobbers volatiles.
; =============================================================================
fmt_size proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx        ; bytes
    mov     qword ptr [rbp-16], rdx       ; dst
    ; bytes < 1024 -> integer bytes + " B"
    cmp     rcx, 1024
    jae     fs_scale
    mov     rax, rcx
    mov     rcx, rdx
    call    u64_to_wide                   ; rcx=dst, rax=value -> rax=ptr past digits
    mov     rcx, rax
    lea     rdx, [s_unit_b]
    mov     r8, qword ptr [rbp-16]            ; dst base
    add     r8, (FMT_SIZE_MIN_CHARS - 1) * 2  ; -> last writable wide char
    call    wcopy
    jmp     fs_done
fs_scale:
    ; find unit: divisor d, uidx 1..4 (KB,MB,GB,TB)
    mov     rax, qword ptr [rbp-8]
    mov     r8, 1024                      ; d
    mov     r9, 1                         ; uidx
fs_pick:
    mov     r10, r8
    shl     r10, 10                       ; d*1024
    cmp     rax, r10
    jb      fs_have
    cmp     r9, 4
    jae     fs_have
    mov     r8, r10
    inc     r9
    jmp     fs_pick
fs_have:
    mov     qword ptr [rbp-24], r8        ; d
    mov     qword ptr [rbp-32], r9        ; uidx
    ; whole = bytes / d
    xor     edx, edx
    div     r8                            ; rax = whole, rdx = rem
    mov     qword ptr [rbp-40], rax       ; whole
    ; tenth = (rem * 10) / d
    mov     rax, rdx
    mov     r10, 10
    mul     r10                           ; rdx:rax = rem*10 (rem<d<=2^40, safe)
    xor     edx, edx
    div     qword ptr [rbp-24]            ; rax = tenth (0..9)
    mov     qword ptr [rbp-48], rax       ; tenth
    ; emit whole
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-40]
    call    u64_to_wide
    mov     word ptr [rax], '.'
    add     rax, 2
    mov     rcx, qword ptr [rbp-48]       ; tenth digit
    add     rcx, '0'
    mov     word ptr [rax], cx
    add     rax, 2
    mov     word ptr [rax], 0
    ; unit suffix
    mov     rcx, rax
    lea     rdx, [s_unit_kb]
    cmp     qword ptr [rbp-32], 1
    je      fs_unit
    lea     rdx, [s_unit_mb]
    cmp     qword ptr [rbp-32], 2
    je      fs_unit
    lea     rdx, [s_unit_gb]
    cmp     qword ptr [rbp-32], 3
    je      fs_unit
    lea     rdx, [s_unit_tb]
fs_unit:
    mov     r8, qword ptr [rbp-16]            ; dst base
    add     r8, (FMT_SIZE_MIN_CHARS - 1) * 2  ; -> last writable wide char
    call    wcopy
fs_done:
    add     rsp, 64
    pop     rbp
    ret
fmt_size endp

; =============================================================================
; u64_to_wide(rcx = dst, rax = value) -> rax = ptr past the last digit (no NUL).
; Writes the unsigned decimal of 'value' as UTF-16.  Raw leaf.
; =============================================================================
u64_to_wide proc
    sub     rsp, 40
    lea     r8, [rsp+32]                  ; scratch end (digits grow downward)
    mov     r9, 10
uw_div:
    xor     edx, edx
    div     r9                            ; rax/=10, rdx=digit
    add     dl, '0'
    dec     r8
    mov     byte ptr [r8], dl
    test    rax, rax
    jnz     uw_div
    lea     r10, [rsp+32]
uw_cpy:
    movzx   eax, byte ptr [r8]
    mov     word ptr [rcx], ax
    add     rcx, 2
    inc     r8
    cmp     r8, r10
    jb      uw_cpy
    mov     rax, rcx
    add     rsp, 40
    ret
u64_to_wide endp

; =============================================================================
; status_append_rate(rcx = wide cursor) -> rax = new cursor, NUL-terminated.
;
; Appends "   345.6 MB/s   ETA 12:34" (h:mm:ss past an hour) - or nothing at
; all until the rate is measurable.  progress.asm owns what "measurable" means
; (a second past the FIRST BYTE, so the KDF's head never poisons the average),
; and this helper is the only formatter, so the status line and the drag
; window cannot come to different opinions about the same numbers.
;
; When prog_speed_x10 is nonzero, prog_eta_s cannot be -1: both gate on the
; same three conditions.  The belt below treats -1 as 0 anyway.
;
; Callers guarantee ~28 wide chars of room (g_statusw 256, g_pg_txt 600, both
; carrying short prefixes); the wcopy walls are local slack, not the budget.
; Every value crosses a call in the FRAME - pr_dec's r9 lesson, not a fourth
; time.
; =============================================================================
status_append_rate proc frame
    FRAME_PROLOG 64
    ; [rbp-16] cursor  [rbp-24] remainder  [rbp-32] whole part
    mov     qword ptr [rbp-16], rcx
    call    prog_speed_x10
    test    rax, rax
    jnz     sar_have
    mov     rax, qword ptr [rbp-16]     ; not measurable: cursor unchanged
    FRAME_EPILOG
    ret
sar_have:
    xor     edx, edx
    mov     rcx, 10
    div     rcx                         ; rax = whole MB/s, rdx = tenth
    mov     qword ptr [rbp-32], rax
    mov     qword ptr [rbp-24], rdx
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [s_rate_gap]
    lea     r8, [rcx + 40*2]
    call    wcopy
    mov     rcx, rax
    mov     rax, qword ptr [rbp-32]
    call    u64_to_wide
    mov     rcx, rax
    mov     word ptr [rcx], '.'
    add     rcx, 2
    mov     rax, qword ptr [rbp-24]
    add     eax, '0'
    mov     word ptr [rcx], ax
    add     rcx, 2
    lea     rdx, [s_rate_unit]
    lea     r8, [rcx + 32*2]
    call    wcopy
    mov     qword ptr [rbp-16], rax
    call    prog_eta_s
    cmp     rax, -1
    jne     @F
    xor     eax, eax                    ; the unreachable belt
@@:
    mov     rcx, qword ptr [rbp-16]
    xor     edx, edx
    mov     r10, 3600
    div     r10                         ; rax = hours, rdx = the rest
    mov     qword ptr [rbp-24], rdx
    test    rax, rax
    jz      sar_msec
    call    u64_to_wide                 ; hours, then zero-padded minutes
    mov     rcx, rax
    mov     word ptr [rcx], ':'
    add     rcx, 2
    mov     rax, qword ptr [rbp-24]
    xor     edx, edx
    mov     r10, 60
    div     r10
    mov     qword ptr [rbp-24], rdx
    call    wdec2
    jmp     sar_secs
sar_msec:
    mov     rax, qword ptr [rbp-24]
    xor     edx, edx
    mov     r10, 60
    div     r10
    mov     qword ptr [rbp-24], rdx
    call    u64_to_wide                 ; bare minutes: "4:07", not "04:07"
    mov     rcx, rax
sar_secs:
    mov     word ptr [rcx], ':'
    add     rcx, 2
    mov     rax, qword ptr [rbp-24]
    call    wdec2
    mov     word ptr [rcx], 0
    mov     rax, rcx
    FRAME_EPILOG
    ret
status_append_rate endp

; ---------------------------------------------------------------------------
; wdec2(rcx = wide cursor, rax = value 0..99) - two digits, zero-padded, raw
; leaf; advances rcx.  The minutes and seconds of an eta.
; ---------------------------------------------------------------------------
wdec2 proc
    xor     edx, edx
    mov     r10, 10
    div     r10
    add     al, '0'
    mov     word ptr [rcx], ax
    add     rcx, 2
    add     dl, '0'
    mov     word ptr [rcx], dx
    add     rcx, 2
    ret
wdec2 endp

; =============================================================================
; lv_add_column(rcx = index, rdx = text ptr, r8d = width, r9d = fmt)
; =============================================================================
lv_add_column proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-8], rcx        ; index
    mov     qword ptr [rbp-16], rdx       ; text
    mov     dword ptr [rbp-20], r8d       ; width
    mov     dword ptr [rbp-24], r9d       ; fmt
    lea     rcx, [g_lvc]
    xor     r9, r9
lac_z:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, 64
    jb      lac_z
    mov     dword ptr [g_lvc+LVC_mask], LVCF_FMT or LVCF_WIDTH or LVCF_TEXT or LVCF_SUBITEM
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_lvc+LVC_fmt], eax
    mov     eax, dword ptr [rbp-20]
    mov     dword ptr [g_lvc+LVC_cx], eax
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [g_lvc+LVC_pszText], rax
    mov     rax, qword ptr [rbp-8]
    mov     dword ptr [g_lvc+LVC_iSubItem], eax
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_INSERTCOLUMNW, qword ptr [rbp-8], addr g_lvc
    add     rsp, 48
    pop     rbp
    ret
lv_add_column endp

; =============================================================================
; The list as a tree.
;
; Rows used to be one per top-level input, so a row index WAS an input index.
; A browsable list breaks that: a row can be a file nested inside an input.
;
; The model is deliberately a pure function of three things - the inputs, the
; set of expanded folders, and the set of exclusions - so "expand this folder"
; is a set insertion followed by a rebuild, not an insert-into-the-middle with
; index fixups.  Rebuilding a few thousand rows costs nothing next to the
; directory enumeration it replaces, and it removes the whole class of bug
; where the visible rows and the model drift apart.
;
; PSET is that set: a bounded, case-insensitive set of paths.  It REFUSES when
; full rather than dropping the oldest - silently forgetting an exclusion would
; mean encrypting a file the user removed.
; =============================================================================

; -----------------------------------------------------------------------------
; wstr_ieq(rcx = a, rdx = b) -> eax = 1 if equal ignoring ASCII case.
; Paths only, so ASCII folding is the right comparison: Windows compares file
; names case-insensitively and a non-ASCII fold would need the full Unicode
; tables for no benefit here.
; -----------------------------------------------------------------------------
wstr_ieq proc
    xor     r10, r10
wie_loop:
    movzx   eax, word ptr [rcx+r10*2]
    movzx   r11d, word ptr [rdx+r10*2]
    ; fold A-Z to a-z on both sides
    cmp     eax, 'A'
    jb      wie_a_done
    cmp     eax, 'Z'
    ja      wie_a_done
    add     eax, 20h
wie_a_done:
    cmp     r11d, 'A'
    jb      wie_b_done
    cmp     r11d, 'Z'
    ja      wie_b_done
    add     r11d, 20h
wie_b_done:
    cmp     eax, r11d
    jne     wie_no
    test    eax, eax
    jz      wie_yes                     ; both hit NUL together
    inc     r10
    cmp     r10, 8000h                  ; bound the walk
    jb      wie_loop
wie_no:
    xor     eax, eax
    ret
wie_yes:
    mov     eax, 1
    ret
wstr_ieq endp

; -----------------------------------------------------------------------------
; pset_clear(rcx = set base)
; -----------------------------------------------------------------------------
pset_clear proc
    mov     qword ptr [rcx+PSET_count], 0
    mov     qword ptr [rcx+PSET_head], 0
    ret
pset_clear endp

; -----------------------------------------------------------------------------
; pset_find(rcx = set, rdx = path) -> eax = index, or -1.
; -----------------------------------------------------------------------------
pset_find proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], 0
pf_loop:
    mov     rcx, qword ptr [rbp-24]
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [rcx+PSET_count]
    jae     pf_no
    ; entry text = arena + offs[i]*2
    lea     r10, [rcx+PSET_offs]
    mov     r11d, dword ptr [r10+rax*4]
    lea     rcx, [rcx+PSET_arena]
    lea     rcx, [rcx+r11*2]
    mov     rdx, qword ptr [rbp-32]
    call    wstr_ieq
    test    eax, eax
    jnz     pf_yes
    inc     qword ptr [rbp-40]
    jmp     pf_loop
pf_yes:
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
pf_no:
    mov     rax, -1
    FRAME_EPILOG
    ret
pset_find endp

; -----------------------------------------------------------------------------
; pset_has(rcx = set, rdx = path) -> eax = 1 / 0
; -----------------------------------------------------------------------------
public pset_has
pset_has proc frame
    FRAME_PROLOG 48
    call    pset_find
    cmp     rax, 0
    jl      ph_no
    mov     eax, 1
    FRAME_EPILOG
    ret
ph_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
pset_has endp

; -----------------------------------------------------------------------------
; pset_add(rcx = set, rdx = path) -> eax = 1 ok, 0 refused (full).
; Adding an entry that is already present succeeds without duplicating it.
; -----------------------------------------------------------------------------
pset_add proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    call    pset_find
    cmp     rax, 0
    jge     pa_ok                       ; already there
    ; capacity
    mov     rcx, qword ptr [rbp-24]
    mov     rax, qword ptr [rcx+PSET_count]
    cmp     rax, PSET_MAX
    jae     pa_full
    ; arena room: len + 1
    mov     rcx, qword ptr [rbp-32]
    call    wlen
    mov     qword ptr [rbp-40], rax     ; len
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rcx+PSET_head]
    add     r10, qword ptr [rbp-40]
    inc     r10
    cmp     r10, PSET_ARENA_CHARS
    ja      pa_full
    ; copy in
    mov     rcx, qword ptr [rbp-24]
    mov     r11, qword ptr [rcx+PSET_head]
    lea     rax, [rcx+PSET_arena]
    lea     rax, [rax+r11*2]            ; destination
    mov     qword ptr [rbp-48], rax
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-40]
    lea     r8, [rcx+rax*2]             ; last writable wide char
    call    wcopy
    ; record the offset and advance
    mov     rcx, qword ptr [rbp-24]
    mov     rax, qword ptr [rcx+PSET_count]
    lea     r10, [rcx+PSET_offs]
    mov     r11, qword ptr [rcx+PSET_head]
    mov     dword ptr [r10+rax*4], r11d
    inc     qword ptr [rcx+PSET_count]
    mov     r10, qword ptr [rbp-40]
    inc     r10
    add     qword ptr [rcx+PSET_head], r10
pa_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
pa_full:
    xor     eax, eax
    FRAME_EPILOG
    ret
pset_add endp

; -----------------------------------------------------------------------------
; pset_remove(rcx = set, rdx = path).  Removes by swapping the last entry down;
; the arena is not compacted, which only costs space until the next clear.
; -----------------------------------------------------------------------------
pset_remove proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    call    pset_find
    cmp     rax, 0
    jl      pr_done
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rcx+PSET_count]
    dec     r10
    mov     qword ptr [rcx+PSET_count], r10
    cmp     rax, r10
    jae     pr_done                     ; it was the last one
    lea     r11, [rcx+PSET_offs]
    mov     ecx, dword ptr [r11+r10*4]  ; last entry's offset
    mov     dword ptr [r11+rax*4], ecx  ; overwrite the removed slot
pr_done:
    FRAME_EPILOG
    ret
pset_remove endp

; -----------------------------------------------------------------------------
; pset_remove_under(rcx = set, rdx = prefix) - drop the prefix itself and
; everything beneath it.
;
; Adding a folder has to undo any exclusion inside it, or a user who removes a
; file and then drags its folder in again silently keeps encrypting without it,
; with nothing on screen to say so.  The boundary test matters: "C:\ab" must not
; match "C:\abc\d", so the character after the prefix has to be a separator or
; the end of the string.
; -----------------------------------------------------------------------------
pset_remove_under proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     rcx, rdx
    call    wlen
    mov     qword ptr [rbp-40], rax          ; prefix length
    test    rax, rax
    jz      pru_done
    mov     qword ptr [rbp-48], 0            ; scan index
pru_loop:
    mov     rcx, qword ptr [rbp-24]
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [rcx+PSET_count]
    jae     pru_done
    ; entry text
    lea     r10, [rcx+PSET_offs]
    mov     r11d, dword ptr [r10+rax*4]
    lea     r10, [rcx+PSET_arena]
    lea     r10, [r10+r11*2]
    mov     qword ptr [rbp-56], r10          ; entry
    ; compare the first <prefix length> characters, case-folded
    mov     r11, qword ptr [rbp-32]
    xor     r9, r9
pru_cmp:
    cmp     r9, qword ptr [rbp-40]
    jae     pru_boundary
    movzx   eax, word ptr [r10+r9*2]
    movzx   ecx, word ptr [r11+r9*2]
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 20h
@@:
    cmp     ecx, 'A'
    jb      @F
    cmp     ecx, 'Z'
    ja      @F
    add     ecx, 20h
@@:
    cmp     eax, ecx
    jne     pru_next
    inc     r9
    jmp     pru_cmp
pru_boundary:
    ; the entry must end here, or continue with a separator
    mov     r10, qword ptr [rbp-56]
    mov     rax, qword ptr [rbp-40]
    movzx   eax, word ptr [r10+rax*2]
    test    eax, eax
    jz      pru_drop
    cmp     eax, 5Ch
    jne     pru_next
pru_drop:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-56]
    call    pset_remove
    jmp     pru_loop                         ; same index: an entry moved into it
pru_next:
    inc     qword ptr [rbp-48]
    jmp     pru_loop
pru_done:
    FRAME_EPILOG
    ret
pset_remove_under endp

; -----------------------------------------------------------------------------
; path_is_dir(rcx = path) -> eax = 1 if it is a directory.
; -----------------------------------------------------------------------------
path_is_dir proc frame
    FRAME_PROLOG 48
    WINCALL GetFileAttributesW, rcx
    cmp     eax, -1
    je      pid_no
    test    eax, 10h                    ; FILE_ATTRIBUTE_DIRECTORY
    jz      pid_no
    mov     eax, 1
    FRAME_EPILOG
    ret
pid_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
path_is_dir endp

; -----------------------------------------------------------------------------
; rows_reset - empty the visible-row model.
; -----------------------------------------------------------------------------
public rows_reset
rows_reset proc
    mov     qword ptr [g_rowcount], 0
    mov     qword ptr [g_rowhead], 0
    ret
rows_reset endp

; -----------------------------------------------------------------------------
; rows_add(rcx = path, edx = depth, r8 = size, r9d = flags) -> eax = 1 ok.
; Refuses at capacity rather than dropping rows: a list that silently stops
; short would misrepresent what is about to be encrypted.
; -----------------------------------------------------------------------------
public rows_add
rows_add proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], edx
    mov     qword ptr [rbp-40], r8
    mov     dword ptr [rbp-44], r9d
    mov     rax, qword ptr [g_rowcount]
    cmp     rax, ROWS_MAX
    jae     ra_no
    mov     rcx, qword ptr [rbp-24]
    call    wlen
    mov     qword ptr [rbp-56], rax         ; len
    mov     r10, qword ptr [g_rowhead]
    add     r10, rax
    inc     r10
    cmp     r10, ROWARENA_CHARS
    ja      ra_no
    ; copy the path into the arena
    mov     r11, qword ptr [g_rowhead]
    lea     rax, [g_rowarena]
    lea     rax, [rax+r11*2]
    mov     qword ptr [rbp-64], rax
    mov     rcx, qword ptr [rbp-64]
    mov     rdx, qword ptr [rbp-24]
    mov     rax, qword ptr [rbp-56]
    lea     r8, [rcx+rax*2]
    call    wcopy
    ; fill the row
    mov     rax, qword ptr [g_rowcount]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax                        ; -> the row
    mov     r11, qword ptr [g_rowhead]
    mov     dword ptr [r10+ROW_pathoff], r11d
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [r10+ROW_depth], eax
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r10+ROW_size], rax
    mov     eax, dword ptr [rbp-44]
    mov     dword ptr [r10+ROW_flags], eax
    mov     rax, qword ptr [g_rowinput]
    mov     dword ptr [r10+ROW_inputi], eax
    ; advance
    mov     r10, qword ptr [rbp-56]
    inc     r10
    add     qword ptr [g_rowhead], r10
    inc     qword ptr [g_rowcount]
    mov     eax, 1
    FRAME_EPILOG
    ret
ra_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
rows_add endp

; -----------------------------------------------------------------------------
; row_progress(rcx = row index) -> rax = bytes done, rdx = bytes total, for the
; INPUT that row belongs to.  Both zero for an out-of-range row.  Leaf.
;
; progress.asm counts bytes per POSITIONAL INPUT (g_cur_input), which is the
; granularity the packer reports at: a folder is ONE input, and sum_inputs
; records one total for the whole subtree.  g_file_done/g_file_total were being
; indexed by ROW, which is the same number only while every row IS a top-level
; input.  Expand a folder and the rows below it index somebody else's input -
; and past MAX_ARGS entirely once the list is long enough, reading whatever
; follows the array - so every child drew an empty track.  That read as
; "nothing has happened to this file" at the exact moment its folder was being
; written, which is the opposite of the truth.
;
; So a child shows its INPUT's progress, and every row of an expanded folder
; fills together with the folder.  That is precisely what is known.  Splitting
; the input's bytes across its children would mean assuming the packer walks
; them in the order the list happens to be sorted in, and it does not - it
; enumerates, the list sorts folders first and case-folded.  A bar that shows a
; file finished before it has been written is worse than one that is honestly
; coarse.
; -----------------------------------------------------------------------------
row_progress proc
    xor     eax, eax
    xor     edx, edx
    cmp     rcx, qword ptr [g_rowcount]
    jae     rp_ret
    imul    rcx, rcx, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rcx
    mov     r11d, dword ptr [r10+ROW_inputi]
    cmp     r11d, MAX_ARGS
    jae     rp_ret
    lea     r10, [g_file_done]
    mov     rax, qword ptr [r10+r11*8]
    lea     r10, [g_file_total]
    mov     rdx, qword ptr [r10+r11*8]
rp_ret:
    ret
row_progress endp

; -----------------------------------------------------------------------------
; row_path(rcx = row index) -> rax = pointer to that row's path in the arena.
; -----------------------------------------------------------------------------
public row_path
row_path proc
    imul    rcx, rcx, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rcx
    mov     r11d, dword ptr [r10+ROW_pathoff]
    lea     rax, [g_rowarena]
    lea     rax, [rax+r11*2]
    ret
row_path endp

; -----------------------------------------------------------------------------
; rowp_path(rcx = row RECORD pointer) -> rax = its path in the arena.
; row_path takes an index; the sort below moves records around, so it needs the
; record itself.  The arena is never touched by the sort - only ROW_pathoff
; travels, inside the record.
; -----------------------------------------------------------------------------
rowp_path proc
    mov     r11d, dword ptr [rcx+ROW_pathoff]
    lea     rax, [g_rowarena]
    lea     rax, [rax+r11*2]
    ret
rowp_path endp

; -----------------------------------------------------------------------------
; rtc_isdir(rcx = path, rdx = index to scan from, r8d = the row's flags)
;   -> eax = 1 if the component at that level is a FOLDER.
;
; "At that level" is the point: a row can be a file and still have a folder
; where two paths part company - "in\sub\c.txt" is a file, but at the character
; that separates it from "in\alpha.txt" it is inside the folder "sub".  So the
; test is not the row's own flag: a separator anywhere at or after the split
; means the component continues into a subtree and is therefore a folder, and
; only when there is none does the row's own ROWF_DIR decide it.
rtc_isdir proc
    mov     r10, rdx
ri_scan:
    movzx   eax, word ptr [rcx+r10*2]
    test    eax, eax
    jz      ri_end
    cmp     eax, 5Ch
    je      ri_yes
    inc     r10
    jmp     ri_scan
ri_end:
    mov     eax, r8d
    and     eax, ROWF_DIR                   ; bit 0, so this is already 0 or 1
    ret
ri_yes:
    mov     eax, 1
    ret
rtc_isdir endp

; -----------------------------------------------------------------------------
; row_tree_cmp(rcx = path a, rdx = path b, r8d = flags a, r9d = flags b)
;   -> eax < 0 / 0 / > 0
;
; Orders two paths the way a TREE reads, which is not the way plain text sorts.
; Where they part company, FOLDERS COME FIRST - a folder and its contents sit
; above its siblings' files, which is how Explorer draws a tree and what makes
; a deep container readable.  Only then does the character decide it.
;
; Two foldings, and the first one is the whole point:
;
;   '\' -> 1    A separator must sort BELOW every real character, or a folder
;               and its contents come apart.  Compared as text, "sub2" lands
;               between "sub" and "sub\c.txt" - '2' is 32h and '\' is 5Ch - so
;               a sibling would be drawn in the middle of another folder's
;               children, at the wrong indent, which is a worse tree than the
;               unsorted one.  At 1 it sits directly under its parent, and the
;               terminator at 0 still puts the parent itself first.
;   'A'-'Z' -> lowercase    so case does not scatter siblings.  ASCII only:
;               anything else compares by code unit, which is deterministic and
;               is what the rest of this file does with names.
;
; Equal is a real answer (two entries whose names differ only outside ASCII
; case), and the caller keeps such rows in the order they arrived.
;
; locals: [rbp-16] a [rbp-24] b [rbp-28] flags a [rbp-32] flags b
;         [rbp-40] split index [rbp-44] folded a [rbp-48] folded b
;         [rbp-52] a-is-folder
; -----------------------------------------------------------------------------
row_tree_cmp proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     dword ptr [rbp-28], r8d
    mov     dword ptr [rbp-32], r9d
    xor     r9, r9
rtc_next:
    movzx   eax, word ptr [rcx+r9*2]
    movzx   r10d, word ptr [rdx+r9*2]
    cmp     eax, 5Ch
    jne     @F
    mov     eax, 1
    jmp     rtc_afolded
@@:
    cmp     eax, 'A'
    jb      rtc_afolded
    cmp     eax, 'Z'
    ja      rtc_afolded
    add     eax, 20h
rtc_afolded:
    cmp     r10d, 5Ch
    jne     @F
    mov     r10d, 1
    jmp     rtc_bfolded
@@:
    cmp     r10d, 'A'
    jb      rtc_bfolded
    cmp     r10d, 'Z'
    ja      rtc_bfolded
    add     r10d, 20h
rtc_bfolded:
    cmp     eax, r10d
    jne     rtc_diverge
    test    eax, eax
    jz      rtc_eq                          ; both ended, together
    inc     r9
    jmp     rtc_next
rtc_diverge:
    ; They part company here.  Folder before file, and only if that ties does
    ; the character decide it.
    mov     qword ptr [rbp-40], r9
    mov     dword ptr [rbp-44], eax
    mov     dword ptr [rbp-48], r10d
    mov     rdx, r9
    mov     r8d, dword ptr [rbp-28]
    call    rtc_isdir                       ; rcx is still path a
    mov     dword ptr [rbp-52], eax
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    mov     r8d, dword ptr [rbp-32]
    call    rtc_isdir
    cmp     eax, dword ptr [rbp-52]
    je      rtc_bychar
    cmp     dword ptr [rbp-52], 0
    jne     rtc_lt                          ; a is the folder
    jmp     rtc_gt
rtc_bychar:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-48]
    jb      rtc_lt
    jmp     rtc_gt
rtc_lt:
    mov     eax, -1
    FRAME_EPILOG
    ret
rtc_gt:
    mov     eax, 1
    FRAME_EPILOG
    ret
rtc_eq:
    xor     eax, eax
    FRAME_EPILOG
    ret
row_tree_cmp endp

; -----------------------------------------------------------------------------
; rows_sort_tree - put the visible-row model into tree order.
;
; The inventory is stored in the order entries were WRITTEN, which for a freshly
; packed container is already tree order - pack.asm walks depth-first, emitting
; a directory then descending into it.  Appending breaks that: new entries go on
; the end of the index whatever they are called, so a file added to a folder was
; drawn at the bottom of the list instead of inside the folder it was dropped
; on.  Its NAME was right - pack.asm builds it from g_add_prefix - so this is
; the display disagreeing with the container, not with itself.
;
; Sorted here rather than in the index, because the index records storage and
; this model records what is on screen.  Reordering g_idxbuf would also reorder
; the extents a removal rewrite walks, which is a real risk taken for no gain.
;
; Binary insertion sort.  Insertion because the input is nearly sorted - one
; already-ordered run per packing session - so the moves stay near zero in the
; case that actually happens.  Binary because the comparison is the expensive
; part and this runs on every expand and collapse: it bounds the compares at
; n*log2(n) even if an index arrives thoroughly out of order, rather than
; letting a pathological one turn a click into a visible pause.
;
; locals: [rbp-16] i  [rbp-24] lo  [rbp-32] hi  [rbp-40] mid  [rbp-48] scratch
;         [rbp-72 .. rbp-49] the row being placed, lifted out whole
; -----------------------------------------------------------------------------
public rows_sort_tree
rows_sort_tree proc frame
    FRAME_PROLOG 112
    cmp     qword ptr [g_rowcount], 2
    jb      rst_ret
    mov     qword ptr [rbp-16], 1
rst_outer:
    mov     rax, qword ptr [rbp-16]
    cmp     rax, qword ptr [g_rowcount]
    jae     rst_ret
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     rax, qword ptr [r10]
    mov     qword ptr [rbp-72], rax
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [rbp-64], rax
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [rbp-56], rax
    ; ---- where does it belong in rows[0..i)? --------------------------------
    mov     qword ptr [rbp-24], 0
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [rbp-32], rax
rst_bs:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [rbp-32]
    jae     rst_place
    add     rax, qword ptr [rbp-32]
    shr     rax, 1
    mov     qword ptr [rbp-40], rax
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     rcx, r10
    mov     r11d, dword ptr [r10+ROW_flags]
    mov     dword ptr [rbp-80], r11d
    call    rowp_path
    mov     qword ptr [rbp-48], rax
    lea     rcx, [rbp-72]                   ; the lifted row: ROW_pathoff is at 0
    call    rowp_path
    mov     rdx, rax
    mov     rcx, qword ptr [rbp-48]
    mov     r8d, dword ptr [rbp-80]
    mov     r9d, dword ptr [rbp-72+ROW_flags]
    call    row_tree_cmp
    test    eax, eax
    jg      rst_hi
    mov     rax, qword ptr [rbp-40]         ; <= : it goes after, which is what
    inc     rax                             ; keeps equal rows in arrival order
    mov     qword ptr [rbp-24], rax
    jmp     rst_bs
rst_hi:
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rbp-32], rax
    jmp     rst_bs
rst_place:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [rbp-16]
    jae     rst_step                        ; already where it belongs
    mov     r9, qword ptr [rbp-16]
rst_shift:
    cmp     r9, qword ptr [rbp-24]
    jbe     rst_shifted
    mov     rax, r9
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     rax, qword ptr [r10-ROW_SIZE]
    mov     qword ptr [r10], rax
    mov     rax, qword ptr [r10-ROW_SIZE+8]
    mov     qword ptr [r10+8], rax
    mov     rax, qword ptr [r10-ROW_SIZE+16]
    mov     qword ptr [r10+16], rax
    dec     r9
    jmp     rst_shift
rst_shifted:
    mov     rax, qword ptr [rbp-24]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     rax, qword ptr [rbp-72]
    mov     qword ptr [r10], rax
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [r10+8], rax
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [r10+16], rax
rst_step:
    inc     qword ptr [rbp-16]
    jmp     rst_outer
rst_ret:
    FRAME_EPILOG
    ret
rows_sort_tree endp

; =============================================================================
; arch_of(rcx = filesystem path, edx = the input it belongs to,
;         r8 = UTF-8 destination, r9 = destination bytes) -> eax = length, 0 bad
;
; The name this path will have IN THE ARCHIVE.  That is the whole of what step 3
; needs: the row model stores filesystem paths, the staged destinations are
; archive paths, and nothing could compare the two before this existed.
;
; It reproduces exactly what the packers do, which is why it can be trusted to
; agree with them: pack_input_top takes the LEAF of the input, pack_node appends
; each child name as it recurses, and pfx_select puts the staged destination in
; front.  So archive = prefix + leaf(input) + (path - input), separators
; flipped.  A top-level row has an empty suffix and comes out as prefix + leaf.
;
; locals: [rbp-24] path  [rbp-32] dst  [rbp-40] cap  [rbp-48] input path
;         [rbp-56] prefix bytes  [rbp-2104 .. rbp-64] wide scratch (1020 chars)
; =============================================================================
arch_of proc frame
    FRAME_PROLOG 2176
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], r9
    movsxd  rax, edx
    cmp     rax, qword ptr [g_poscount]
    jae     ao_bad
    lea     r11, [g_positionals]
    mov     r10, qword ptr [r11+rax*8]
    mov     qword ptr [rbp-48], r10
    ; ---- the staged destination goes in first, verbatim ---------------------
    lea     r11, [g_pos_prefix]
    mov     r9d, dword ptr [r11+rax*4]
    xor     r10, r10                        ; bytes written so far
    test    r9d, r9d
    jz      ao_noprefix
    lea     r11, [g_pfx_arena]
    mov     rcx, qword ptr [rbp-32]
ao_pcopy:
    mov     al, byte ptr [r11+r9]
    test    al, al
    jz      ao_noprefix
    mov     rdx, qword ptr [rbp-40]
    sub     rdx, 2
    cmp     r10, rdx
    jae     ao_bad
    mov     byte ptr [rcx+r10], al
    inc     r10
    inc     r9
    jmp     ao_pcopy
ao_noprefix:
    mov     qword ptr [rbp-56], r10
    ; ---- leaf(input) + (path - input), built wide then converted once -------
    mov     rcx, qword ptr [rbp-48]
    call    wlen
    mov     r11, rax                        ; input length, = where the suffix starts
    ; leaf start: after the last separator in the input
    mov     rcx, qword ptr [rbp-48]
    xor     r9, r9
    xor     r8, r8
ao_leaf:
    movzx   eax, word ptr [rcx+r9*2]
    test    eax, eax
    jz      ao_leafdone
    cmp     eax, 5Ch
    je      ao_sep
    cmp     eax, 2Fh
    jne     ao_ladv
ao_sep:
    lea     r8, [r9+1]
ao_ladv:
    inc     r9
    jmp     ao_leaf
ao_leafdone:
    ; copy from the leaf to the end of the INPUT, then the path's own tail
    lea     rcx, [rcx+r8*2]                 ; -> leaf
    lea     rdx, [rbp-2104]
    xor     r9, r9
ao_wcopy:
    cmp     r9, 1000
    jae     ao_bad
    movzx   eax, word ptr [rcx+r9*2]
    test    eax, eax
    jz      ao_wleafend
    mov     word ptr [rdx+r9*2], ax
    inc     r9
    jmp     ao_wcopy
ao_wleafend:
    ; ...then everything the path has beyond the input
    mov     rcx, qword ptr [rbp-24]
    lea     rcx, [rcx+r11*2]                ; -> the suffix
    xor     r8, r8
ao_scopy:
    cmp     r9, 1000
    jae     ao_bad
    movzx   eax, word ptr [rcx+r8*2]
    test    eax, eax
    jz      ao_sdone
    cmp     eax, 5Ch                        ; an archive name uses '/'
    jne     @F
    mov     eax, 2Fh
@@:
    mov     word ptr [rdx+r9*2], ax
    inc     r9
    inc     r8
    jmp     ao_scopy
ao_sdone:
    mov     word ptr [rdx+r9*2], 0
    ; ---- convert, appending after the prefix already written ----------------
    mov     r10, qword ptr [rbp-56]
    mov     rax, qword ptr [rbp-32]
    add     rax, r10
    mov     r8, rax                         ; where the conversion goes
    mov     r11, qword ptr [rbp-40]
    sub     r11, r10                        ; ...and what is left for it
    jle     ao_bad
    lea     rdx, [rbp-2104]
    WINCALL WideCharToMultiByte, CP_UTF8, 0, rdx, -1, r8, r11d, 0, 0
    test    eax, eax
    jz      ao_bad
    dec     eax                             ; drop the terminator
    add     rax, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
ao_bad:
    xor     eax, eax
    FRAME_EPILOG
    ret
arch_of endp

; =============================================================================
; emit_input(rcx = input index, edx = depth) - put one top-level input, and
; whatever it is currently showing, into the row model.
;
; Factored out of rows_build because a staged input is emitted from a DIFFERENT
; place - inside the folder it was dropped on - and has to arrive there by
; exactly the same rules.  Two copies of "what a row for an input looks like"
; would drift the first time either was edited.
;
; g_rowinput is saved and restored: it is what rows_add stamps into ROW_inputi,
; and a nested emit would otherwise leave the enclosing walk attributing its
; remaining children to the wrong input.
; =============================================================================
; locals, and the spacing is the point: [rbp-24] index (qword, -24..-17),
; [rbp-32] depth (DWORD, -32..-29), [rbp-40] path (qword, -40..-33),
; [rbp-48] flags (dword), [rbp-72] saved g_rowinput.
;
; The depth used to live at [rbp-28] with the path qword at [rbp-32] - which
; overlaps it, because a qword at -32 occupies -32..-25.  Writing the path
; silently zeroed the depth, so every staged row was emitted at depth 0: drawn
; at the top level while sitting in the middle of the folder it belongs to.
; The tree said one thing and the archive another, which is the exact failure
; this feature is not allowed to have.
emit_input proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     rax, qword ptr [g_rowinput]
    mov     qword ptr [rbp-72], rax         ; saved across the whole call
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     ei_ret
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    mov     qword ptr [rbp-40], rcx
    ; an excluded input is simply absent
    lea     rcx, [g_excluded]
    mov     rdx, qword ptr [rbp-40]
    call    pset_has
    test    eax, eax
    jnz     ei_ret
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_rowinput], rax     ; children inherit it
    xor     r9d, r9d
    mov     rcx, qword ptr [rbp-40]
    call    path_is_dir
    test    eax, eax
    jz      ei_haveflags
    mov     r9d, ROWF_DIR
    mov     dword ptr [rbp-48], r9d
    lea     rcx, [g_expanded]
    mov     rdx, qword ptr [rbp-40]
    call    pset_has
    mov     r9d, dword ptr [rbp-48]
    test    eax, eax
    jz      ei_haveflags
    or      r9d, ROWF_EXPANDED
ei_haveflags:
    mov     dword ptr [rbp-48], r9d
    ; the indexer already sized this input; nested rows carry their own size
    mov     rax, qword ptr [rbp-24]
    lea     r11, [g_rowsize]
    mov     r8, qword ptr [r11+rax*8]
    mov     rcx, qword ptr [rbp-40]
    mov     edx, dword ptr [rbp-32]
    call    rows_add
    mov     r9d, dword ptr [rbp-48]
    test    r9d, ROWF_EXPANDED
    jz      ei_ret
    mov     rcx, qword ptr [rbp-40]
    mov     edx, dword ptr [rbp-32]
    inc     edx
    call    rows_expand_into
ei_ret:
    mov     rax, qword ptr [rbp-72]
    mov     qword ptr [g_rowinput], rax
    FRAME_EPILOG
    ret
emit_input endp

; =============================================================================
; emit_staged_into(rcx = this folder's archive path in UTF-8, including its
;                  trailing '/', edx = depth for what goes inside it)
;
; Any input staged to land in this folder is emitted here, after its real
; children - so a dropped file appears inside the folder it was dropped on,
; while living somewhere else entirely on disk.  This is the whole of step 3:
; the row model stops being a picture of the filesystem and becomes a picture
; of the ARCHIVE, which is what the user is actually building.
;
; locals: [rbp-24] archive path  [rbp-32] depth  [rbp-40] index
; =============================================================================
emit_staged_into proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], 0
esi_loop:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_poscount]
    jae     esi_ret
    lea     r11, [g_pos_prefix]
    mov     r9d, dword ptr [r11+rax*4]
    test    r9d, r9d
    jz      esi_next                        ; not staged: it belongs at the root
    lea     r10, [g_pfx_arena]
    add     r10, r9
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, r10
    call    u8_equal
    test    eax, eax
    jz      esi_next
    mov     rcx, qword ptr [rbp-40]
    mov     edx, dword ptr [rbp-32]
    call    emit_input
esi_next:
    inc     qword ptr [rbp-40]
    jmp     esi_loop
esi_ret:
    FRAME_EPILOG
    ret
emit_staged_into endp

; =============================================================================
; stage_heal - drop any staging whose destination has gone away.
;
; A staged input is only ever drawn by the folder it was staged into.  If that
; folder's input has since been removed, nothing draws it - and it would still
; be encrypted, into a path the tree does not show.  A file in the archive that
; the list does not admit to is the one outcome docs/STAGED_LAYOUT.md rules out,
; so the staging is dropped and the file goes back to the root, where it is
; visible and where the archive will now put it.
;
; A destination that merely happens to be COLLAPSED is left alone: that file is
; hidden exactly the way every other child of a closed folder is hidden, and
; opening the folder shows it.  The test is whether some surviving input could
; host the destination at all, not whether it is on screen right now.
;
; locals: [rbp-24] j  [rbp-32] i  [rbp-1064 .. rbp-40] candidate base (1024)
; =============================================================================
stage_heal proc frame
    FRAME_PROLOG 1152
    mov     qword ptr [rbp-24], 0
sh_outer:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     sh_ret
    lea     r11, [g_pos_prefix]
    mov     r9d, dword ptr [r11+rax*4]
    test    r9d, r9d
    jz      sh_onext                        ; not staged
    lea     r10, [g_pfx_arena]
    add     r10, r9
    mov     qword ptr [rbp-72], r10         ; this input's destination
    ; is there any OTHER input whose own archive path could contain it?
    mov     qword ptr [rbp-32], 0
sh_inner:
    mov     rax, qword ptr [rbp-32]
    cmp     rax, qword ptr [g_poscount]
    jae     sh_orphan
    cmp     rax, qword ptr [rbp-24]
    je      sh_inext                        ; not itself
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    mov     edx, dword ptr [rbp-32]
    lea     r8, [rbp-1064]
    mov     r9, 1000
    call    arch_of
    test    eax, eax
    jz      sh_inext
    lea     r10, [rbp-1064]
    mov     byte ptr [r10+rax], 2Fh
    mov     byte ptr [r10+rax+1], 0
    ; the destination is inside this input if it starts with that input's path
    lea     rcx, [rbp-1064]
    mov     rdx, qword ptr [rbp-72]
    call    u8_startswith
    test    eax, eax
    jnz     sh_onext                        ; somebody can host it
sh_inext:
    inc     qword ptr [rbp-32]
    jmp     sh_inner
sh_orphan:
    mov     rax, qword ptr [rbp-24]
    lea     r11, [g_pos_prefix]
    mov     dword ptr [r11+rax*4], 0        ; back to the root, and visible
sh_onext:
    inc     qword ptr [rbp-24]
    jmp     sh_outer
sh_ret:
    FRAME_EPILOG
    ret
stage_heal endp

; u8_startswith(rcx = prefix, rdx = string) -> eax = 1 if string begins with it.
u8_startswith proc
    xor     r10, r10
us_lp:
    mov     al, byte ptr [rcx+r10]
    test    al, al
    jz      us_yes                          ; the prefix ran out: it matched
    mov     r11b, byte ptr [rdx+r10]
    cmp     al, r11b
    jne     us_no
    inc     r10
    cmp     r10, 4096
    jb      us_lp
us_no:
    xor     eax, eax
    ret
us_yes:
    mov     eax, 1
    ret
u8_startswith endp

; u8_equal(rcx = a, rdx = b) -> eax = 1 if the two NUL-terminated bytes match.
u8_equal proc
    xor     r10, r10
ue_lp:
    mov     al, byte ptr [rcx+r10]
    mov     r11b, byte ptr [rdx+r10]
    cmp     al, r11b
    jne     ue_no
    test    al, al
    jz      ue_yes
    inc     r10
    cmp     r10, 4096
    jb      ue_lp
ue_no:
    xor     eax, eax
    ret
ue_yes:
    mov     eax, 1
    ret
u8_equal endp

; -----------------------------------------------------------------------------
; rows_expand_into(rcx = directory path, edx = depth for its CHILDREN)
;
; Adds one row per child, and recurses into any child directory that is itself
; in the expanded set.  The find-data and the joined path are FRAME locals, not
; globals: this recurses, and a shared scratch buffer would have each level
; overwrite its parent's mid-enumeration state.
; -----------------------------------------------------------------------------
rows_expand_into proc frame
    ; 3968, not 3072: the staged pass at the end needs this folder's ARCHIVE
    ; path, and it has to be a frame local rather than a global because this
    ; proc recurses through emit_staged_into -> emit_input -> here, and a
    ; shared buffer would have the nested level overwrite the name the outer
    ; loop is still comparing against.
    FRAME_PROLOG 3968
    ; [rbp-24] dir  [rbp-28] depth  [rbp-40] hFind
    ; [rbp-2096 .. rbp-48]  joined child path (1024 wide chars)
    ; [rbp-2704 .. rbp-2112] WIN32_FIND_DATAW (592 bytes)
    ; [rbp-3800 .. rbp-2777] this folder's archive path, UTF-8 (1024 bytes)
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], edx
    ; pattern = dir + "\*"  (built in the child-path buffer)
    lea     rcx, [rbp-2096]
    mov     rdx, qword ptr [rbp-24]
    lea     r8, [rbp-2096+2046]
    call    wcopy
    lea     rcx, [rbp-2096]
    call    wlen
    lea     r10, [rbp-2096]
    lea     r10, [r10+rax*2]
    mov     word ptr [r10],   5Ch        ; backslash
    mov     word ptr [r10+2], 2Ah        ; asterisk
    mov     word ptr [r10+4], 0
    lea     rcx, [rbp-2096]
    lea     rdx, [rbp-2704]
    WINCALL FindFirstFileW, rcx, rdx
    cmp     rax, -1
    je      rei_done
    mov     qword ptr [rbp-40], rax
rei_loop:
    ; skip "." and ".."
    lea     r10, [rbp-2704+44]           ; cFileName
    cmp     word ptr [r10], 2Eh
    jne     rei_real
    cmp     word ptr [r10+2], 0
    je      rei_next
    cmp     word ptr [r10+2], 2Eh
    jne     rei_real
    cmp     word ptr [r10+4], 0
    je      rei_next
rei_real:
    ; child = dir + "\" + name
    lea     rcx, [rbp-2096]
    mov     rdx, qword ptr [rbp-24]
    lea     r8, [rbp-2096+2046]
    call    wcopy
    lea     rcx, [rbp-2096]
    call    wlen
    lea     r10, [rbp-2096]
    lea     r10, [r10+rax*2]
    mov     word ptr [r10], 5Ch
    lea     rcx, [r10+2]
    lea     rdx, [rbp-2704+44]
    lea     r8, [rbp-2096+2046]
    call    wcopy
    ; excluded -> it is not part of the input at all
    lea     rcx, [g_excluded]
    lea     rdx, [rbp-2096]
    call    pset_has
    test    eax, eax
    jnz     rei_next
    ; flags + size from the find data
    mov     eax, dword ptr [rbp-2704]    ; dwFileAttributes
    xor     r9d, r9d
    xor     r8, r8
    test    eax, 10h
    jz      rei_file
    mov     r9d, ROWF_DIR
    jmp     rei_haveflags
rei_file:
    mov     eax, dword ptr [rbp-2704+28] ; nFileSizeHigh
    shl     rax, 32
    mov     r8d, dword ptr [rbp-2704+32] ; nFileSizeLow
    or      r8, rax
rei_haveflags:
    ; expanded folders carry the flag so the row can draw as open
    test    r9d, ROWF_DIR
    jz      rei_add
    mov     qword ptr [rbp-56], r8
    mov     dword ptr [rbp-60], r9d
    lea     rcx, [g_expanded]
    lea     rdx, [rbp-2096]
    call    pset_has
    mov     r9d, dword ptr [rbp-60]
    mov     r8, qword ptr [rbp-56]
    test    eax, eax
    jz      rei_add
    or      r9d, ROWF_EXPANDED
rei_add:
    mov     dword ptr [rbp-60], r9d
    lea     rcx, [rbp-2096]
    mov     edx, dword ptr [rbp-28]
    call    rows_add
    ; recurse into an expanded directory
    mov     r9d, dword ptr [rbp-60]
    test    r9d, ROWF_EXPANDED
    jz      rei_next
    lea     rcx, [rbp-2096]
    mov     edx, dword ptr [rbp-28]
    inc     edx
    call    rows_expand_into
rei_next:
    lea     rcx, [rbp-2704]
    WINCALL FindNextFileW, qword ptr [rbp-40], rcx
    test    eax, eax
    jnz     rei_loop
    WINCALL FindClose, qword ptr [rbp-40]
rei_done:
    ; ...and then anything STAGED to land in this folder, after the real
    ; children so it reads as the newest thing in it.  The archive path is
    ; rebuilt here rather than passed in, because this proc recurses and the
    ; caller does not always know it - g_rowinput does, and it is what the rows
    ; being emitted are attributed to anyway.
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [g_rowinput]
    lea     r8, [rbp-3800]
    mov     r9, 1000
    call    arch_of
    test    eax, eax
    jz      rei_ret                         ; too long to be a destination
    ; one trailing '/', to match how pfx_stage stores them
    lea     r10, [rbp-3800]
    mov     byte ptr [r10+rax], 2Fh
    mov     byte ptr [r10+rax+1], 0
    lea     rcx, [rbp-3800]
    mov     edx, dword ptr [rbp-28]
    call    emit_staged_into
rei_ret:
    FRAME_EPILOG
    ret
rows_expand_into endp

; -----------------------------------------------------------------------------
; rows_build - rebuild every visible row from the inputs plus the two sets.
; This is the whole model: rows are derived, never edited in place.
; -----------------------------------------------------------------------------
rows_build proc frame
    FRAME_PROLOG 2304
    ; An input staged into a folder is emitted BY that folder, not here - so
    ; before anything is built, drop any staging whose destination no longer
    ; exists.  Without this a removed folder leaves its lodgers with nowhere to
    ; be drawn: still encrypted, into a path the tree cannot show. That is the
    ; one outcome docs/STAGED_LAYOUT.md says must not happen, and it is why the
    ; healing runs here rather than at the point of removal - this proc is what
    ; every edit ends up calling, so there is one place to get it right.
    call    stage_heal
    call    rows_reset
    mov     qword ptr [rbp-24], 0
rb_loop:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     rb_done
    ; staged inputs appear inside their destination, further down
    lea     r11, [g_pos_prefix]
    mov     r9d, dword ptr [r11+rax*4]
    test    r9d, r9d
    jnz     rb_next
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx                     ; depth 0
    call    emit_input
rb_next:
    inc     qword ptr [rbp-24]
    jmp     rb_loop
rb_done:
    FRAME_EPILOG
    ret
rows_build endp


; =============================================================================
; row_toggle(ecx = row index) - open or close a directory row.
;
; Expansion state lives in g_expanded, keyed by PATH rather than row index,
; because every rebuild renumbers the rows.  Toggling is therefore a set edit
; followed by a rebuild, and a folder stays open across adds and removals.
;
; The enumeration runs on the UI thread.  That is fine for opening one level of
; an ordinary folder and would not be for something enormous; if that becomes a
; problem the fix is to move rows_build to a worker, not to cache it here.
; =============================================================================
row_toggle proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-28], ecx
    cmp     dword ptr [g_running], 0
    jne     rt_done                          ; not while an operation owns the inputs
    mov     eax, dword ptr [rbp-28]
    cmp     rax, 0
    jl      rt_done
    cmp     rax, qword ptr [g_rowcount]
    jae     rt_done
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     eax, dword ptr [r10+ROW_flags]
    test    eax, ROWF_DIR
    jz      rt_done                          ; files do not open
    mov     dword ptr [rbp-32], eax
    mov     ecx, dword ptr [rbp-28]
    call    row_path
    mov     qword ptr [rbp-40], rax
    mov     eax, dword ptr [rbp-32]
    test    eax, ROWF_EXPANDED
    jnz     rt_close
    lea     rcx, [g_expanded]
    mov     rdx, qword ptr [rbp-40]
    call    pset_add
    jmp     rt_refill
rt_close:
    lea     rcx, [g_expanded]
    mov     rdx, qword ptr [rbp-40]
    call    pset_remove
rt_refill:
    call    populate_list
rt_done:
    FRAME_EPILOG
    ret
row_toggle endp
; =============================================================================
; row_display(rcx = row index) -> rax = the text to show for that row.
;
; A top-level row shows its path relative to the common root, as it always has.
; A nested row shows only its leaf name - the indent already says where it sits,
; and repeating the parent on every child is noise.
; =============================================================================
row_display proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    imul    rax, rcx, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     eax, dword ptr [r10+ROW_depth]
    mov     dword ptr [rbp-28], eax
    mov     rcx, qword ptr [rbp-24]
    call    row_path
    mov     qword ptr [rbp-40], rax
    cmp     dword ptr [rbp-28], 0
    jne     rd_leaf
    mov     rcx, qword ptr [rbp-40]
    call    rel_path
    FRAME_EPILOG
    ret
rd_leaf:
    ; scan to the last separator
    mov     rcx, qword ptr [rbp-40]
    mov     rax, rcx                        ; best = whole string
    xor     r10, r10
rd_scan:
    movzx   r11d, word ptr [rcx+r10*2]
    test    r11d, r11d
    jz      rd_scan_done
    cmp     r11d, 5Ch
    jne     @F
    lea     rax, [rcx+r10*2+2]
@@:
    inc     r10
    cmp     r10, 8000h
    jb      rd_scan
rd_scan_done:
    FRAME_EPILOG
    ret
row_display endp

; =============================================================================
; populate_list - fill the listview from the ROW model.
;
; It used to read g_positionals directly, one row per input.  It now rebuilds
; the row model first and renders that, so a row can be a file nested inside an
; expanded folder.  LVITEM.iIndent carries the depth: the listview draws the
; indent itself, which is why this stays a report-mode listview rather than
; becoming a TreeView and losing the columns and the per-row progress bars.
; =============================================================================
populate_list proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    ; WHERE the rows come from depends on what is on screen, and this is the one
    ; place that decides it.  rows_build walks the FILESYSTEM from g_positionals;
    ; a container's rows come from its decrypted inventory instead.
    ;
    ; Running rows_build for a container threw the inventory away and rebuilt the
    ; model from the only thing that IS on disk - the .mrk itself - so the list
    ; showed one row naming the container. container_load did call
    ; rows_from_index first; this then undid it, three lines later, which is why
    ; the summary above the list was right about the contents while the list was
    ; not.  Nothing could be browsed into and nothing could be removed: the one
    ; row's path was the container's own absolute path, which matches no
    ; inventory name.
    cmp     dword ptr [g_container], 0
    jne     pl_fromidx
    call    rows_build
    jmp     pl_built
pl_fromidx:
    call    rows_from_index
pl_built:
    ; Clear first.  This used to run exactly once, at startup, so appending was
    ; the same as filling; now a drop or the Add menu re-runs the whole
    ; index-and-fill pipeline and every row would be duplicated.
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_DELETEALLITEMS, 0, 0
    mov     qword ptr [g_himglist], 0
    xor     r9, r9
pl_l:
    cmp     r9, qword ptr [g_rowcount]
    jae     pl_d
    mov     qword ptr [rbp-8], r9
    ; --- icon: SHGetFileInfo(SYSICONINDEX) -> g_himglist + g_shfi.iIcon ------
    ; An input row names something that exists, so the shell is asked about the
    ; file itself and a .exe or .docx gets its own icon.  A container row names
    ; an entry INSIDE the container: there is no such path on disk, the shell
    ; found nothing and every row came back iconless.  For those, ask by name and
    ; attributes instead - which is all the shell needs to answer "folder" or
    ; "the icon registered for .md".
    mov     rcx, r9
    call    row_path
    mov     rcx, rax
    cmp     dword ptr [g_container], 0
    jne     pl_icon_byname
    WINCALL SHGetFileInfoW, rcx, 0, addr g_shfi, 696, <SHGFI_SYSICONINDEX or SHGFI_SMALLICON>
    jmp     pl_icon_done
pl_icon_byname:
    mov     rax, qword ptr [rbp-8]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     edx, FILE_ATTR_NORMAL
    test    dword ptr [r10+ROW_flags], ROWF_DIR
    jz      @F
    mov     edx, FILE_ATTR_DIR
@@:
    WINCALL SHGetFileInfoW, rcx, edx, addr g_shfi, 696, \
            <SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_USEFILEATTR>
pl_icon_done:
    cmp     qword ptr [g_himglist], 0
    jne     @F
    mov     qword ptr [g_himglist], rax  ; cache system image list (same each call)
@@:
    ; --- insert item (col 0): icon + name, indented by depth ----------------
    mov     r9, qword ptr [rbp-8]
    lea     rcx, [g_lvi]
    xor     r10, r10
pl_z:
    mov     byte ptr [rcx+r10], 0
    inc     r10
    cmp     r10, 96
    jb      pl_z
    mov     dword ptr [g_lvi+LVI_mask], LVIF_TEXT or LVIF_IMAGE or LVIF_INDENT
    mov     eax, r9d
    mov     dword ptr [g_lvi+LVI_iItem], eax
    mov     dword ptr [g_lvi+LVI_iSubItem], 0
    mov     eax, dword ptr [g_shfi+SHFI_iIcon]
    mov     dword ptr [g_lvi+LVI_iImage], eax
    mov     rax, qword ptr [rbp-8]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     eax, dword ptr [r10+ROW_depth]
    mov     dword ptr [g_lvi+LVI_iIndent], eax
    mov     rcx, qword ptr [rbp-8]
    call    row_display
    mov     qword ptr [g_lvi+LVI_pszText], rax
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_INSERTITEMW, 0, addr g_lvi
    ; --- subitem 1: formatted size ------------------------------------------
    ; Directories show nothing: only the top-level ones have a walked total (the
    ; indexer computed it), and printing "0 B" for a nested folder would read as
    ; a fact rather than an absence.
    mov     rax, qword ptr [rbp-8]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     eax, dword ptr [r10+ROW_flags]
    test    eax, ROWF_DIR
    jz      pl_size
    cmp     dword ptr [g_container], 0
    jne     pl_blank                     ; an inventory records no folder totals
    mov     eax, dword ptr [r10+ROW_depth]
    test    eax, eax
    jnz     pl_blank
pl_size:
    mov     rcx, qword ptr [r10+ROW_size]
    lea     rdx, [g_sizetxt]
    call    fmt_size
    jmp     pl_settext
pl_blank:
    mov     word ptr [g_sizetxt], 0
pl_settext:
    lea     rcx, [g_lvi]
    xor     r10, r10
pl_z2:
    mov     byte ptr [rcx+r10], 0
    inc     r10
    cmp     r10, 96
    jb      pl_z2
    mov     dword ptr [g_lvi+LVI_mask], LVIF_TEXT
    mov     dword ptr [g_lvi+LVI_iSubItem], 1
    lea     rax, [g_sizetxt]
    mov     qword ptr [g_lvi+LVI_pszText], rax
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_SETITEMTEXTW, qword ptr [rbp-8], addr g_lvi
    mov     r9, qword ptr [rbp-8]
    inc     r9
    jmp     pl_l
pl_d:
    ; attach the system small-icon image list (shared by every row)
    cmp     qword ptr [g_himglist], 0
    je      pl_ret
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_SETIMAGELIST, LVSIL_SMALL, qword ptr [g_himglist]
pl_ret:
    ; The tree just changed height, so the control has to be resized to it and
    ; the scrollbar's pixel range recomputed.  lv_apply also re-clamps the offset,
    ; which is what keeps a Remove that shortens the list from leaving the view
    ; scrolled past the end.
    call    lv_metrics
    call    lv_apply
    add     rsp, 64
    pop     rbp
    ret
populate_list endp



; =============================================================================
; compute_root - longest common directory of g_positionals[0..n-1] -> g_rootpath
; (case-insensitive; truncated back to the last path separator).  Empty if the
; inputs share no common directory (e.g. different drives).
; locals: [rbp-8]=ref [rbp-16]=lcp_len [rbp-24]=index
; =============================================================================
compute_root proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    ; No inputs at all (launched with no arguments): there is no common root, and
    ; positionals[0] is an uninitialised .data? slot - reading it and walking it
    ; for a terminator is a NULL dereference in the shell's own process.  Report
    ; "no root" and let build_crumb pick the empty-state wording.
    cmp     qword ptr [g_poscount], 0
    jne     cr_have_inputs
    mov     word ptr [g_rootpath], 0
    jmp     cr_ret
cr_have_inputs:
    lea     r11, [g_positionals]
    mov     rax, qword ptr [r11+0]
    mov     qword ptr [rbp-8], rax        ; ref = positionals[0]
    mov     rcx, rax
    call    wlen
    mov     qword ptr [rbp-16], rax       ; lcp_len = wlen(ref)
    mov     qword ptr [rbp-24], 1
cr_loop:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     cr_trunc
    lea     r11, [g_positionals]
    mov     rdx, qword ptr [r11+rax*8]    ; p
    mov     rcx, qword ptr [rbp-8]        ; ref
    xor     r9, r9                        ; i
cr_cmp:
    cmp     r9, qword ptr [rbp-16]
    jae     cr_cmpd
    movzx   eax, word ptr [rcx+r9*2]
    movzx   r8d, word ptr [rdx+r9*2]
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 20h
@@:
    cmp     r8d, 'A'
    jb      @F
    cmp     r8d, 'Z'
    ja      @F
    add     r8d, 20h
@@:
    cmp     eax, r8d
    jne     cr_cmpd
    test    r8d, r8d
    jz      cr_cmpd
    inc     r9
    jmp     cr_cmp
cr_cmpd:
    cmp     r9, qword ptr [rbp-16]
    jae     @F
    mov     qword ptr [rbp-16], r9        ; lcp_len = min(lcp_len, i)
@@:
    inc     qword ptr [rbp-24]
    jmp     cr_loop
cr_trunc:
    ; find the last '\' or '/' within ref[0..lcp_len-1]
    mov     rcx, qword ptr [rbp-8]
    mov     rax, qword ptr [rbp-16]
    xor     r9, r9
    mov     r10, -1
cr_scan:
    cmp     r9, rax
    jae     cr_scd
    movzx   edx, word ptr [rcx+r9*2]
    cmp     edx, 5Ch
    je      cr_mark
    cmp     edx, 2Fh
    jne     cr_sn
cr_mark:
    mov     r10, r9
cr_sn:
    inc     r9
    jmp     cr_scan
cr_scd:
    cmp     r10, -1
    je      cr_none
    ; root = ref[0..r10-1]
    mov     rcx, qword ptr [rbp-8]
    lea     r8, [g_rootpath]
    xor     r9, r9
cr_copy:
    cmp     r9, r10
    jae     cr_copd
    mov     ax, word ptr [rcx+r9*2]
    mov     word ptr [r8+r9*2], ax
    inc     r9
    jmp     cr_copy
cr_copd:
    mov     word ptr [r8+r9*2], 0
    jmp     cr_done
cr_none:
    mov     word ptr [g_rootpath], 0
cr_done:
cr_ret:
    add     rsp, 64
    pop     rbp
    ret
compute_root endp

; =============================================================================
; rel_path(rcx = full path) -> rax = pointer to the part after "g_rootpath\",
; or the full path if it isn't under the root.  (Leaf.)
; =============================================================================
rel_path proc
    lea     r8, [g_rootpath]
    xor     r9, r9                        ; rootlen
rp_rl:
    cmp     word ptr [r8+r9*2], 0
    je      rp_rld
    inc     r9
    jmp     rp_rl
rp_rld:
    test    r9, r9
    jz      rp_full
    xor     r10, r10
rp_cmp:
    cmp     r10, r9
    jae     rp_match
    movzx   eax, word ptr [rcx+r10*2]
    movzx   edx, word ptr [r8+r10*2]
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
    jne     rp_full
    inc     r10
    jmp     rp_cmp
rp_match:
    movzx   eax, word ptr [rcx+r9*2]
    cmp     eax, 5Ch
    je      rp_rel
    cmp     eax, 2Fh
    je      rp_rel
    jmp     rp_full
rp_rel:
    lea     rax, [rcx+r9*2+2]
    ret
rp_full:
    mov     rax, rcx
    ret
rel_path endp

; =============================================================================
; build_crumb - g_rootpath -> g_crumbw, replacing each separator with " > "
; (a U+203A chevron) and upper-casing a leading drive letter, so "c:\temp"
; renders as "C: > temp".  Empty root -> a friendly fallback.
; =============================================================================
build_crumb proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    movzx   eax, word ptr [g_rootpath]
    test    eax, eax
    jnz     bc_have
    ; No root.  Two different reasons, and they need different words: inputs that
    ; share no common directory, versus no inputs at all.
    lea     rdx, [s_crumb_multi]
    cmp     qword ptr [g_poscount], 0
    jne     @F
    lea     rdx, [s_crumb_none]
@@:
    lea     rcx, [g_crumbw]
    WBOUND  r8, g_crumbw, CRUMB_CHARS
    call    wcopy
    jmp     bc_done
bc_have:
    lea     r10, [g_rootpath]
    lea     r11, [g_crumbw]
    xor     r8, r8
bc_loop:
    cmp     r8, 800h                      ; bound the breadcrumb length
    jae     bc_end
    movzx   eax, word ptr [r10+r8*2]
    test    eax, eax
    jz      bc_end
    cmp     eax, 5Ch
    je      bc_sep
    cmp     eax, 2Fh
    je      bc_sep
    mov     word ptr [r11], ax
    add     r11, 2
    jmp     bc_next
bc_sep:
    mov     word ptr [r11], ' '
    mov     word ptr [r11+2], 203Ah       ; > chevron
    mov     word ptr [r11+4], ' '
    add     r11, 6
bc_next:
    inc     r8
    jmp     bc_loop
bc_end:
    mov     word ptr [r11], 0
    ; ---- a single input names itself ---------------------------------------
    ; compute_root gives the longest common DIRECTORY, and with ONE input its
    ; comparison loop never runs - the root is that path truncated back to the
    ; last separator, i.e. the parent.  So the crumb stopped at the folder
    ; ABOVE the thing being worked on: two containers in one directory read
    ; identically, and encrypting a folder named its parent instead of it.
    ;
    ; Keyed on "exactly one input" rather than on g_container, because both
    ; cases are the same case - a lone .mrk being browsed and a lone folder
    ; being encrypted are both one positional whose parent is the root.  With
    ; two or more inputs the root is genuinely shared and there is no single
    ; name to add.
    ;
    ; Appended here rather than corrected in compute_root: rel_path needs
    ; g_rootpath to stay a directory, because every row's display name is taken
    ; relative to it.
    cmp     qword ptr [g_poscount], 1
    jne     bc_upper
    lea     r10, [g_positionals]
    mov     r10, qword ptr [r10]
    test    r10, r10
    jz      bc_upper
    xor     r8, r8
    xor     r9, r9                        ; first char after the last separator
bc_leaf:
    movzx   eax, word ptr [r10+r8*2]
    test    eax, eax
    jz      bc_leafd
    cmp     eax, 5Ch
    jne     @F
    lea     r9, [r8+1]
@@:
    inc     r8
    cmp     r8, 8000h
    jb      bc_leaf
bc_leafd:
    cmp     r9, r8
    jae     bc_upper                      ; nothing after the last separator
    mov     word ptr [r11], ' '
    mov     word ptr [r11+2], 203Ah
    mov     word ptr [r11+4], ' '
    add     r11, 6
bc_leafc:
    movzx   eax, word ptr [r10+r9*2]
    test    eax, eax
    jz      bc_leafe
    mov     word ptr [r11], ax
    add     r11, 2
    inc     r9
    jmp     bc_leafc
bc_leafe:
    mov     word ptr [r11], 0
bc_upper:
    ; upper-case a leading drive letter ("x:" -> "X:")
    movzx   eax, word ptr [g_crumbw+2]
    cmp     ax, ':'
    jne     bc_done
    movzx   eax, word ptr [g_crumbw]
    cmp     eax, 'a'
    jb      bc_done
    cmp     eax, 'z'
    ja      bc_done
    sub     eax, 20h
    mov     word ptr [g_crumbw], ax
bc_done:
    add     rsp, 48
    pop     rbp
    ret
build_crumb endp

; =============================================================================
; build_crumb_short - collapsed breadcrumb "<first> > ... > <last>" in
; g_crumb_short (with a U+2026 ellipsis), used when the full breadcrumb is too
; wide.  For 0/1/2-segment roots there is nothing to collapse -> copy the full
; string.
; =============================================================================
build_crumb_short proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    lea     r10, [g_rootpath]
    xor     r8, r8
    mov     r9, -1                        ; first separator index
    mov     r11, -1                       ; last separator index
    mov     qword ptr [rbp-16], -1        ; second-to-last separator index
bs_scan:
    movzx   eax, word ptr [r10+r8*2]
    test    eax, eax
    jz      bs_scd
    cmp     eax, 5Ch
    je      bs_mk
    cmp     eax, 2Fh
    jne     bs_nx
bs_mk:
    cmp     r9, -1
    jne     @F
    mov     r9, r8
@@:
    mov     rax, r11
    mov     qword ptr [rbp-16], rax       ; the one before it
    mov     r11, r8
bs_nx:
    inc     r8
    jmp     bs_scan
bs_scd:
    movzx   eax, word ptr [g_rootpath]
    test    eax, eax
    jz      bs_copyfull                   ; empty root
    cmp     r9, -1
    je      bs_copyfull                   ; no separator (single segment)
    cmp     r9, r11
    je      bs_copyfull                   ; one separator (two segments)
    ; Keep the DRIVE and the LAST TWO segments, not the drive and the last one.
    ; Collapsing "C:\Users\you\Desktop\Code\myrkr" to "C: > ... > myrkr" threw
    ; away the parent, which is usually the part that identifies WHERE you are -
    ; "C: > ... > Code > myrkr" says it, and costs one segment.
    ; The tail therefore starts at the SECOND-to-last separator.
    mov     rax, qword ptr [rbp-16]
    cmp     rax, r9
    je      bs_copyfull                   ; three segments: the whole path already
    mov     r11, rax
    ; first segment
    lea     r10, [g_rootpath]
    lea     rdx, [g_crumb_short]
    xor     r8, r8
bs_cp1:
    cmp     r8, r9
    jae     bs_mid
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [rdx], ax
    add     rdx, 2
    inc     r8
    jmp     bs_cp1
bs_mid:
    mov     word ptr [rdx+0], ' '
    mov     word ptr [rdx+2], 203Ah       ; >
    mov     word ptr [rdx+4], ' '
    mov     word ptr [rdx+6], 2026h       ; ...
    mov     word ptr [rdx+8], ' '
    mov     word ptr [rdx+10], 203Ah      ; >
    mov     word ptr [rdx+12], ' '
    add     rdx, 14
    lea     r10, [g_rootpath]
    lea     r10, [r10+r11*2+2]            ; -> last segment
    ; The tail now spans the boundary between the last two segments, so the
    ; separator in it has to become a chevron - copying it raw would print a
    ; backslash in the middle of a chevroned breadcrumb.
bs_cp2:
    mov     ax, word ptr [r10]
    test    ax, ax
    jz      bs_cp2_end
    cmp     ax, 5Ch
    je      bs_cp2_sep
    cmp     ax, 2Fh
    je      bs_cp2_sep
    mov     word ptr [rdx], ax
    add     rdx, 2
    add     r10, 2
    jmp     bs_cp2
bs_cp2_sep:
    mov     word ptr [rdx+0], ' '
    mov     word ptr [rdx+2], 203Ah       ; >
    mov     word ptr [rdx+4], ' '
    add     rdx, 6
    add     r10, 2
    jmp     bs_cp2
bs_cp2_end:
    mov     word ptr [rdx], 0
    ; The same single-input name build_crumb appends to the full string.  It has
    ; to be done twice because this form is built from g_rootpath and not from
    ; g_crumbw - and the collapsed form is the one a deep path actually shows,
    ; so appending it only to the full string named the input in precisely the
    ; case where the crumb had room to spare.
    cmp     qword ptr [g_poscount], 1
    jne     bs_upper
    lea     r10, [g_positionals]
    mov     r10, qword ptr [r10]
    test    r10, r10
    jz      bs_upper
    xor     r8, r8
    xor     r9, r9                        ; first char after the last separator
bs_leaf:
    movzx   eax, word ptr [r10+r8*2]
    test    eax, eax
    jz      bs_leafd
    cmp     eax, 5Ch
    jne     @F
    lea     r9, [r8+1]
@@:
    inc     r8
    cmp     r8, 8000h
    jb      bs_leaf
bs_leafd:
    cmp     r9, r8
    jae     bs_upper
    mov     word ptr [rdx+0], ' '
    mov     word ptr [rdx+2], 203Ah
    mov     word ptr [rdx+4], ' '
    add     rdx, 6
bs_leafc:
    movzx   eax, word ptr [r10+r9*2]
    test    eax, eax
    jz      bs_leafe
    mov     word ptr [rdx], ax
    add     rdx, 2
    inc     r9
    jmp     bs_leafc
bs_leafe:
    mov     word ptr [rdx], 0
bs_upper:
    movzx   eax, word ptr [g_crumb_short+2]
    cmp     ax, ':'
    jne     bs_ret
    movzx   eax, word ptr [g_crumb_short]
    cmp     eax, 'a'
    jb      bs_ret
    cmp     eax, 'z'
    ja      bs_ret
    sub     eax, 20h
    mov     word ptr [g_crumb_short], ax
    jmp     bs_ret
bs_copyfull:
    lea     rcx, [g_crumb_short]
    lea     rdx, [g_crumbw]
    WBOUND  r8, g_crumb_short, CRUMB_SHORT_CHARS
    call    wcopy
bs_ret:
    add     rsp, 48
    pop     rbp
    ret
build_crumb_short endp

; =============================================================================
; update_strength - re-evaluate the password (ENCRYPT mode only): set the
; validation underline (green = meets policy, red = not, neutral = empty) and
; enable the Encrypt button only when the password meets the policy.
; locals: [rbp-8]=len [rbp-16]=classmask [rbp-32]=policy_ok
; =============================================================================
update_strength proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    ; With the private-desktop prompt on, this dialog holds no password: the
    ; action button gates on having inputs, and the prompt enforces the policy
    ; (sd_update) at the point the password actually exists.
    cmp     dword ptr [g_cfg_securedesk], 0
    je      us_have_field
    mov     dword ptr [g_pw_state], 0
    mov     edx, 1
    cmp     dword ptr [g_scanning], 0
    je      @F
    xor     edx, edx
@@:
    ; ...and never while the list is empty.  The window can now open with no
    ; inputs at all, and an enabled Encrypt that silently does nothing is worse
    ; than a disabled one that says why.
    cmp     qword ptr [g_poscount], 0
    jne     @F
    xor     edx, edx
@@:
    WINCALL EnableWindow, qword ptr [g_haction], edx
    jmp     us_done
us_have_field:
    ; read the password field
    WINCALL GetWindowTextW, qword ptr [g_hpass], addr g_passw, PWBUF_CHARS
    mov     dword ptr [rbp-8], eax       ; eax = length (chars)
    ; classify g_passw -> class mask (1=lo 2=up 4=di 8=sy)
    xor     r10d, r10d                   ; mask
    lea     r11, [g_passw]
    xor     r9, r9
us_cl:
    movzx   eax, word ptr [r11+r9*2]
    test    eax, eax
    jz      us_cldone
    cmp     eax, 'a'
    jb      @F
    cmp     eax, 'z'
    ja      @F
    or      r10d, 1
    jmp     us_clnext
@@:
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    or      r10d, 2
    jmp     us_clnext
@@:
    cmp     eax, '0'
    jb      @F
    cmp     eax, '9'
    ja      @F
    or      r10d, 4
    jmp     us_clnext
@@:
    or      r10d, 8                      ; anything else counts as a symbol
us_clnext:
    inc     r9
    jmp     us_cl
us_cldone:
    mov     dword ptr [rbp-16], r10d
    ; ---- class count -> policy ---------------------------------------------
    xor     r8d, r8d
    test    r10d, 1
    jz      @F
    inc     r8d
@@: test    r10d, 2
    jz      @F
    inc     r8d
@@: test    r10d, 4
    jz      @F
    inc     r8d
@@: test    r10d, 8
    jz      @F
    inc     r8d
@@:                                      ; r8d = number of classes present
    mov     r9d, 0                        ; policy_ok flag in r9d
    mov     ecx, dword ptr [g_cfg_pwminlen]
    cmp     dword ptr [rbp-8], ecx        ; length >= configured min length?
    jb      us_pol
    cmp     r8d, dword ptr [g_cfg_pwminclasses]   ; classes >= configured min?
    jb      us_pol
    mov     r9d, 1
us_pol:
    mov     dword ptr [rbp-32], r9d       ; policy_ok
    ; ---- password validation underline (format-aware) ---------------------
    ;   empty + .mrk  -> 2 (red): a Myrkr container always requires a password
    ;   empty + .zip  -> 0 (neutral): "no password" is an accepted zip state
    ;   non-empty     -> 1 if it meets the policy, else 2 (red)
    cmp     dword ptr [rbp-8], 0
    jne     us_st_nonempty
    xor     r9d, r9d                      ; .zip empty -> neutral
    cmp     dword ptr [g_make_zip], 0
    jne     us_pwst
    mov     r9d, 1                        ; .mrk empty -> red (required)
    jmp     us_pwst
us_st_nonempty:
    ; below the policy floor -> red; otherwise the grade (2 amber/3 green/4 deep)
    mov     r9d, 1
    cmp     dword ptr [rbp-32], 0
    je      us_pwst
    lea     rcx, [g_passw]
    mov     edx, dword ptr [rbp-8]
    call    pw_grade
    lea     r9d, [rax+1]
us_pwst:
    mov     dword ptr [g_pw_state], r9d
    ; ---- action button: "Execute" (zip + empty) vs "Encrypt", + enable ------
    ; want_exec = .zip && empty password (an unencrypted-archive run)
    xor     r8d, r8d
    cmp     dword ptr [rbp-8], 0
    jne     us_we_done
    cmp     dword ptr [g_make_zip], 0
    je      us_we_done
    mov     r8d, 1
us_we_done:
    mov     dword ptr [rbp-40], r8d       ; want_exec
    ; relabel only on change (avoids repainting the button on every keystroke)
    cmp     r8d, dword ptr [g_act_exec]
    je      us_enable_calc
    mov     dword ptr [g_act_exec], r8d
    lea     rdx, [s_encrypt]
    cmp     dword ptr [rbp-40], 0
    je      @F
    lea     rdx, [s_execute]
@@:
    WINCALL SetWindowTextW, qword ptr [g_haction], rdx
    WINCALL InvalidateRect, qword ptr [g_haction], 0, 1
us_enable_calc:
    ; enable if Execute mode, else (non-empty AND policy ok)
    mov     edx, 1
    cmp     dword ptr [rbp-40], 0
    jne     us_enable
    xor     edx, edx
    cmp     dword ptr [rbp-32], 0
    je      us_enable
    cmp     dword ptr [rbp-8], 0
    je      us_enable
    mov     edx, 1
us_enable:
    cmp     dword ptr [g_scanning], 0     ; never enable the action while indexing
    je      @F
    xor     edx, edx
@@:
    WINCALL EnableWindow, qword ptr [g_haction], edx
    ; repaint the password validation underline
    WINCALL InvalidateRect, qword ptr [g_hpw_under], 0, 1
    ; if the field is now empty, force a FULL repaint so the "Password"
    ; placeholder cue is reapplied (deleting the last char only paints a
    ; partial region, which would otherwise leave the cue missing)
    cmp     dword ptr [rbp-8], 0
    jne     us_done
    WINCALL InvalidateRect, qword ptr [g_hpass], 0, 1   ; bErase=TRUE -> full repaint
us_done:
    add     rsp, 96
    pop     rbp
    ret
update_strength endp

; =============================================================================
; hide_pwrow - when the password is taken on the private desktop, the dialog
; must not ask for it too.  Asking twice is what the first cut did, and it read
; as a bug rather than as security: the user typed a password, met the policy,
; pressed Encrypt, and was asked again by a window that looked unrelated.
;
; The controls are created and then hidden rather than skipped, so every code
; path that reads g_hpass still has a valid (empty) window to talk to and needs
; no null-checking.  With the prompt on, the field stays empty, which is exactly
; what the ".zip with no password" branch already means by empty.
; =============================================================================
hide_pwrow proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    cmp     dword ptr [g_cfg_securedesk], 0
    je      hpr_done
    WINCALL ShowWindow, qword ptr [g_hpass], 0
    WINCALL ShowWindow, qword ptr [g_hpw_under], 0
    WINCALL ShowWindow, qword ptr [g_hshow], 0
hpr_done:
    add     rsp, 48
    pop     rbp
    ret
hide_pwrow endp

; =============================================================================
; toggle_show - flip the Show/Hide state of the password field(s)
; =============================================================================
toggle_show proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     eax, dword ptr [g_showpw]
    xor     eax, 1
    mov     dword ptr [g_showpw], eax
    ; new password char: 0 to reveal, '*' to mask
    xor     r8d, r8d                     ; reveal
    test    eax, eax
    jnz     @F
    mov     r8d, 2Ah                     ; '*'
@@:
    mov     dword ptr [rbp-8], r8d        ; password char
    ; apply to the password field
    WINCALL SendMessageW, qword ptr [g_hpass], EM_SETPASSWORDCHAR, dword ptr [rbp-8], 0
    WINCALL InvalidateRect, qword ptr [g_hpass], 0, 1
    ; apply to the confirm field if present (encrypt mode)
    cmp     qword ptr [g_hconfirm], 0
    je      ts_btn
    WINCALL SendMessageW, qword ptr [g_hconfirm], EM_SETPASSWORDCHAR, dword ptr [rbp-8], 0
    WINCALL InvalidateRect, qword ptr [g_hconfirm], 0, 1
ts_btn:
    ; button text
    lea     rdx, [s_show]
    cmp     dword ptr [g_showpw], 0
    je      @F
    lea     rdx, [s_hide]
@@:
    WINCALL SetWindowTextW, qword ptr [g_hshow], rdx
    add     rsp, 48
    pop     rbp
    ret
toggle_show endp

; =============================================================================
; toggle_compress - flip the Compress on/off state and repaint the toggle
; =============================================================================
toggle_compress proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     eax, dword ptr [g_compress_on]
    xor     eax, 1
    mov     dword ptr [g_compress_on], eax
    lea     rdx, [s_comp_off]
    test    eax, eax
    jz      @F
    lea     rdx, [s_comp_on]
@@:
    WINCALL SetWindowTextW, qword ptr [g_hcompress], rdx
    WINCALL InvalidateRect, qword ptr [g_hcompress], 0, 1
    lea     rcx, [w_val_compress]
    mov     edx, dword ptr [g_compress_on]
    call    save_setting
    add     rsp, 48
    pop     rbp
    ret
toggle_compress endp

; =============================================================================
; toggle_securedesk - flip private-desktop password entry and persist it.
;
; No SetWindowTextW counterpart to toggle_compress's: draw_toggle reads the flag
; itself, and the window text of a toggle is not drawn.  It takes effect at the
; next prompt, since nothing caches g_cfg_securedesk.
;
; It cannot be reached while the control is disabled, which is what an HKLM
; SecureDesktop does to it - but a WM_COMMAND can also arrive by other means, so
; the flip is guarded by the same g_running check the other toggles use rather
; than by trusting the control's enabled state.
; =============================================================================
toggle_securedesk proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    cmp     dword ptr [g_lock_securedesk], 0
    jne     tsd_ret                      ; fixed by policy: ignore the click
    mov     eax, dword ptr [g_cfg_securedesk]
    xor     eax, 1
    mov     dword ptr [g_cfg_securedesk], eax
    WINCALL InvalidateRect, qword ptr [g_hsecuredesk], 0, 1
    lea     rcx, [w_val_securedesk]
    mov     edx, dword ptr [g_cfg_securedesk]
    call    save_setting
tsd_ret:
    add     rsp, 48
    pop     rbp
    ret
toggle_securedesk endp

; =============================================================================
; set_format(eax = 0 for .mrk, 1 for .zip) - select the encrypt output format,
; persist it and repaint.
;
; Split out of the old toggle_format when the chip became a two-segment picker:
; a picker SETS a format, it does not flip one, and the caller now knows which.
; The window text is kept in step even though the picker draws both names
; itself - it is the button's accessible name, which is the one reader of it
; that is not in this process.
; =============================================================================
set_format proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     dword ptr [g_make_zip], eax
    lea     rdx, [s_fmt_mrk]
    test    eax, eax
    jz      @F
    lea     rdx, [s_fmt_zip]
@@:
    WINCALL SetWindowTextW, qword ptr [g_hformat], rdx
    WINCALL InvalidateRect, qword ptr [g_hformat], 0, 1
    lea     rcx, [w_val_format]
    mov     edx, dword ptr [g_make_zip]
    call    save_setting
    ; the password underline depends on the format (empty + .mrk is red,
    ; empty + .zip is neutral) - re-evaluate so it recolours on the change
    call    update_strength
    add     rsp, 48
    pop     rbp
    ret
set_format endp

; =============================================================================
; format_pick - set the format from where the pointer is.
;
; The control is BS_OWNERDRAW with NO tab stop (ST_OWNERBTN_NT), so a WM_COMMAND
; from it can only be a mouse click, and the pointer is still inside the button
; when BN_CLICKED arrives - dragging off a button cancels the click rather than
; delivering it.  That is what lets a two-segment control work without
; subclassing the button to see its own WM_LBUTTONDOWN, which is the machinery
; the sliders need and this does not.
;
; A press on one segment RELEASED over the other picks the one released over.
; That is deliberate: it is where the pointer was when the click completed, and
; it is what every other segmented control does.
;
; A click on the label half - left of both segments - does nothing.  Falling
; through to "the nearer segment" there would mean clicking the word "Format"
; silently changed the format.
; =============================================================================
format_pick proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    WINCALL GetCursorPos, addr g_fmt_pt
    WINCALL ScreenToClient, qword ptr [g_hformat], addr g_fmt_pt
    WINCALL GetClientRect, qword ptr [g_hformat], addr g_fmt_rc
    ; the same geometry draw_format_seg lays out, measured back from the right
    mov     eax, dword ptr [g_fmt_rc+8]
    sub     eax, FMT_SEG_PAD + 2*FMT_SEG_W + FMT_SEG_GAP     ; left segment's left
    mov     ecx, dword ptr [g_fmt_pt]                        ; pointer x, client
    cmp     ecx, eax
    jl      fp_ret                                           ; the label, not a segment
    add     eax, FMT_SEG_W + FMT_SEG_GAP/2                   ; the dividing line
    xor     edx, edx
    cmp     ecx, eax
    jl      @F
    mov     edx, 1
@@:
    cmp     edx, dword ptr [g_make_zip]
    je      fp_ret                                           ; already that format
    mov     eax, edx
    call    set_format
fp_ret:
    add     rsp, 64
    pop     rbp
    ret
format_pick endp

; =============================================================================
; set_round_region - re-cut the window's rounded-corner region for its CURRENT
; size.  The region was previously created once from the creation dimensions;
; leaving it alone through a resize clips the window to its old bounds, so a
; window grown larger simply renders nothing in the new area.
;
; SetWindowRgn takes ownership of the region, and frees the one it replaces, so
; there is deliberately no DeleteObject here.
; =============================================================================
set_round_region proc frame
    FRAME_PROLOG 64
    cmp     qword ptr [g_hwnd], 0
    je      srr_ret
    WINCALL GetClientRect, qword ptr [g_hwnd], addr g_lay_rc
    mov     r8d, dword ptr [g_lay_rc+8]          ; right  = W, region wants W+1
    inc     r8d
    mov     r9d, dword ptr [g_lay_rc+12]         ; bottom = H, region wants H+1
    inc     r9d
    WINCALL CreateRoundRectRgn, 0, 0, r8d, r9d, WIN_ROUND, WIN_ROUND
    WINCALL SetWindowRgn, qword ptr [g_hwnd], rax, 1
srr_ret:
    FRAME_EPILOG
    ret
set_round_region endp

; =============================================================================
; lv_metrics - re-measure the row height and the height of the whole tree.
;
; The row height comes from the control rather than a constant so it stays
; right at any DPI or font size; the fallback only matters before the first row
; exists, where the number is not used for anything visible anyway.
; =============================================================================
lv_metrics proc frame
    FRAME_PROLOG 64
    mov     qword ptr [g_lvrowh], LV_ROWH_FALLBACK
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMCOUNT, 0, 0
    mov     qword ptr [g_lvt1], rax                  ; row count
    test    rax, rax
    jz      lm_total
    mov     dword ptr [g_lvirc+0], LVIR_BOUNDS
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMRECT, 0, addr g_lvirc
    test    eax, eax
    jz      lm_total
    mov     eax, dword ptr [g_lvirc+12]
    sub     eax, dword ptr [g_lvirc+4]
    cmp     eax, 4                                   ; refuse a nonsense height
    jl      lm_total
    cdqe
    mov     qword ptr [g_lvrowh], rax
lm_total:
    mov     rax, qword ptr [g_lvt1]
    imul    rax, qword ptr [g_lvrowh]
    mov     qword ptr [g_lvcontent], rax
    FRAME_EPILOG
    ret
lv_metrics endp

; =============================================================================
; lv_apply - put the list, its clip region and its scrollbar where g_lvscroll
; says they belong.  Every scroll goes through here.
;
; The control is sized to the WHOLE tree and positioned above the viewport by
; the scroll offset, so the rows the user should see land in the viewport band.
; A window region cut to that same band (in the control's own coordinates, so
; it moves down as the control moves up) hides the rest - without it the
; oversized control would paint over the password row and the buttons.
;
; Region coordinates are relative to the window's top-left, and the window has
; moved up by g_lvscroll, so the visible band starts at exactly g_lvscroll.
;
; SetWindowRgn takes ownership of the region and frees the previous one, so
; there is no DeleteObject here - same contract as set_round_region.
;
; SWP flags 01Ch = NOZORDER|NOACTIVATE|NOREDRAW.  NOREDRAW because moving a
; window normally makes Windows blit the old pixels and invalidate only what
; was newly exposed - and with the region changing in the same breath, that
; bookkeeping does not hold.  One InvalidateRect afterwards repaints the band
; honestly, and LVS_EX_DOUBLEBUFFER keeps it from flickering.
; =============================================================================
lv_apply proc frame
    FRAME_PROLOG 96
    cmp     qword ptr [g_hlist], 0
    je      la_ret
    cmp     dword ptr [g_op], 0                      ; the windows that own a list
    je      la_go
    cmp     dword ptr [g_container], 0
    je      la_ret
la_go:
    mov     rax, qword ptr [g_lay_lvh]
    mov     qword ptr [g_lvview], rax
    ; ---- clamp the offset to [0, content - view] ----------------------------
    mov     rax, qword ptr [g_lvcontent]
    sub     rax, qword ptr [g_lvview]
    jns     la_maxok
    xor     rax, rax                                 ; everything fits: no scroll
la_maxok:
    mov     qword ptr [g_lvt1], rax                  ; max offset
    mov     rax, qword ptr [g_lvscroll]
    cmp     rax, qword ptr [g_lvt1]
    jle     la_lo
    mov     rax, qword ptr [g_lvt1]
la_lo:
    test    rax, rax
    jns     la_setpos
    xor     rax, rax
la_setpos:
    mov     qword ptr [g_lvscroll], rax
    ; ---- control height = max(content, view) --------------------------------
    mov     rax, qword ptr [g_lvcontent]
    cmp     rax, qword ptr [g_lvview]
    jge     la_hok
    mov     rax, qword ptr [g_lvview]
la_hok:
    mov     qword ptr [g_lvt2], rax                  ; control height
    ; ---- clip region: the band the viewport shows ---------------------------
    mov     rax, qword ptr [g_lvscroll]
    add     rax, qword ptr [g_lvview]
    mov     qword ptr [g_lvt3], rax                  ; band bottom
    WINCALL CreateRectRgn, 0, qword ptr [g_lvscroll], qword ptr [g_lay_lvw], qword ptr [g_lvt3]
    WINCALL SetWindowRgn, qword ptr [g_hlist], rax, 0
    ; ---- move and size, then repaint the band -------------------------------
    mov     rax, qword ptr [g_lay_lvy]
    sub     rax, qword ptr [g_lvscroll]
    mov     qword ptr [g_lvt3], rax                  ; control y
    WINCALL SetWindowPos, qword ptr [g_hlist], 0, LV_X, qword ptr [g_lvt3], qword ptr [g_lay_lvw], qword ptr [g_lvt2], 01Ch
    WINCALL InvalidateRect, qword ptr [g_hlist], 0, 0
    ; ---- thumb geometry, viewport-relative ----------------------------------
    ; Nothing is painted here.  These two numbers are what draw_lv_thumb uses,
    ; and what the drag hit test measures against; the repaint is the list's,
    ; which the InvalidateRect above has already asked for.
    ;
    ;   height   = view * view / content, floored at LVSB_MINH
    ;   position = scroll * (view - height) / (content - view)
    mov     rax, qword ptr [g_lvcontent]
    cmp     rax, qword ptr [g_lvview]
    jg      la_thumb
    mov     qword ptr [g_lvthh], 0                   ; everything fits: no thumb
    jmp     la_ret
la_thumb:
    mov     rax, qword ptr [g_lvview]
    imul    rax, qword ptr [g_lvview]
    xor     edx, edx
    div     qword ptr [g_lvcontent]
    cmp     rax, LVSB_MINH
    jge     la_thh
    mov     rax, LVSB_MINH
la_thh:
    cmp     rax, qword ptr [g_lvview]
    jle     la_thok
    mov     rax, qword ptr [g_lvview]
la_thok:
    mov     qword ptr [g_lvthh], rax
    mov     rax, qword ptr [g_lvview]
    sub     rax, qword ptr [g_lvthh]                 ; travel available
    imul    rax, qword ptr [g_lvscroll]
    mov     qword ptr [g_lvt1], rax
    mov     rax, qword ptr [g_lvcontent]
    sub     rax, qword ptr [g_lvview]                ; > 0, tested above
    mov     rcx, rax
    mov     rax, qword ptr [g_lvt1]
    xor     edx, edx
    div     rcx
    mov     qword ptr [g_lvthy], rax
la_ret:
    FRAME_EPILOG
    ret
lv_apply endp

; =============================================================================
; draw_lv_thumb(rcx = hdc) - the overlay scrollbar.
;
; Called from the list's WM_PAINT, after the control has painted its rows, on a
; DC fetched with GetDC.  NOT from NM_CUSTOMDRAW's CDDS_POSTPAINT, which was the
; obvious place and does not work: that stage arrives with a DC whose contents
; never reach the screen, and drawing there is silently discarded - measured
; with an opaque FillRect, which was equally invisible.
;
; Only while the strip is hovered or the thumb is being dragged, and only when
; there is something to scroll.
;
; Translucency is a 1x1 source bitmap blown up over the thumb rect with
; AlphaBlend's SourceConstantAlpha - the standard way to get a constant alpha
; out of GDI without a per-pixel alpha bitmap.  The source DC and its bitmap are
; made once and kept; there is no matching cleanup because the process holds
; them until it exits, exactly like the theme brushes.
;
; The rounded ends come from clipping to a round-rect region rather than drawing
; one: AlphaBlend has no notion of a shape, so the shape has to be the clip.
;
; Coordinates are the CONTROL's, and the control is scrolled - so the viewport's
; top edge is at g_lvscroll, not at zero.
;
; locals (frame 128): nmcd[-16] hdc[-24] rgn[-32] brush[-40].  Locals start
; at rbp-16, NOT rbp-8: FRAME_PROLOG keeps the stack canary there, and writing
; a local over it fastfails the process (0xC0000409) in FRAME_EPILOG.  128 because
; AlphaBlend takes ELEVEN arguments - 32 bytes of shadow space plus seven stack
; slots is 88 bytes of outgoing area, and the locals have to sit above that.
; =============================================================================
draw_lv_thumb proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    cmp     qword ptr [g_lvthh], 0
    je      dlt_ret                                  ; nothing to scroll
    cmp     dword ptr [g_listhover], 0
    jne     dlt_draw
    cmp     dword ptr [g_lvtrack], 0
    je      dlt_ret                                  ; not hovered, not dragging
dlt_draw:
    ; the 1x1 source, made on first use
    cmp     qword ptr [g_sbdc], 0
    jne     dlt_haveSrc
    WINCALL CreateCompatibleDC, qword ptr [rbp-24]
    test    rax, rax
    jz      dlt_ret
    mov     qword ptr [g_sbdc], rax
    WINCALL CreateCompatibleBitmap, qword ptr [rbp-24], 1, 1
    test    rax, rax
    jz      dlt_ret
    mov     qword ptr [g_sbbmp], rax
    WINCALL SelectObject, qword ptr [g_sbdc], qword ptr [g_sbbmp]
    mov     dword ptr [g_sbrc+0], 0
    mov     dword ptr [g_sbrc+4], 0
    mov     dword ptr [g_sbrc+8], 1
    mov     dword ptr [g_sbrc+12], 1
    WINCALL CreateSolidBrush, CLR_SB_THUMB
    mov     qword ptr [rbp-40], rax
    WINCALL FillRect, qword ptr [g_sbdc], addr g_sbrc, qword ptr [rbp-40]
    WINCALL DeleteObject, qword ptr [rbp-40]
dlt_haveSrc:
    ; ---- the thumb rect, in control coordinates -----------------------------
    mov     rax, qword ptr [g_lay_lvw]
    sub     rax, LVSB_INSET + LVSB_W
    mov     dword ptr [g_sbrc+0], eax                ; left
    add     rax, LVSB_W
    mov     dword ptr [g_sbrc+8], eax                ; right
    mov     rax, qword ptr [g_lvscroll]
    add     rax, qword ptr [g_lvthy]
    mov     dword ptr [g_sbrc+4], eax                ; top
    add     rax, qword ptr [g_lvthh]
    mov     dword ptr [g_sbrc+12], eax               ; bottom
    ; ---- clip to a round rect, blend, unclip --------------------------------
    mov     eax, dword ptr [g_sbrc+8]
    inc     eax
    mov     qword ptr [g_lvt1], rax
    mov     eax, dword ptr [g_sbrc+12]
    inc     eax
    mov     qword ptr [g_lvt2], rax
    WINCALL CreateRoundRectRgn, dword ptr [g_sbrc+0], dword ptr [g_sbrc+4], qword ptr [g_lvt1], qword ptr [g_lvt2], LVSB_RADIUS*2, LVSB_RADIUS*2
    mov     qword ptr [rbp-32], rax
    test    rax, rax
    jz      dlt_ret
    ; SelectClipRgn takes DEVICE coordinates; AlphaBlend takes logical ones.
    ; A double-buffered listview paints through a DC whose viewport origin is
    ; offset to the update rect, so the two disagree - the region landed outside
    ; the blend, everything was clipped away, and AlphaBlend still returned TRUE
    ; having drawn nothing.  Shift the region by the viewport origin to put it
    ; back where the rest of the drawing is.
    WINCALL GetViewportOrgEx, qword ptr [rbp-24], addr g_vporg
    WINCALL OffsetRgn, qword ptr [rbp-32], dword ptr [g_vporg+0], dword ptr [g_vporg+4]
    WINCALL SelectClipRgn, qword ptr [rbp-24], qword ptr [rbp-32]
    ; AlphaBlend(dst, x, y, w, h, src, 0, 0, 1, 1, BLENDFUNCTION) - eleven
    ; arguments, the last a 4-byte struct passed by value:
    ;   BlendOp AC_SRC_OVER | BlendFlags 0 | SourceConstantAlpha | AlphaFormat 0
    mov     rax, qword ptr [g_lay_lvw]
    sub     rax, LVSB_INSET + LVSB_W
    mov     qword ptr [g_lvt1], rax                  ; x
    mov     rax, qword ptr [g_lvscroll]
    add     rax, qword ptr [g_lvthy]
    mov     qword ptr [g_lvt2], rax                  ; y
    WINCALL AlphaBlend, qword ptr [rbp-24], qword ptr [g_lvt1], qword ptr [g_lvt2], LVSB_W, qword ptr [g_lvthh], \
            qword ptr [g_sbdc], 0, 0, 1, 1, <AC_SRC_OVER or (LVSB_ALPHA shl 16)>
    WINCALL SelectClipRgn, qword ptr [rbp-24], 0
    WINCALL DeleteObject, qword ptr [rbp-32]
dlt_ret:
    FRAME_EPILOG
    ret
draw_lv_thumb endp

; =============================================================================
; lv_thumb_drag - one mouse move during a thumb drag.
;
; Screen coordinates throughout.  The control scrolls by MOVING, so a client y
; measured at the grab and another measured now are in different frames of
; reference; the pointer's position on the screen is the only stable thing.
;
;   scroll = grab + (cursor - grabY) * (content - view) / (view - thumb)
; =============================================================================
lv_thumb_drag proc frame
    FRAME_PROLOG 64
    mov     rax, qword ptr [g_lvview]
    sub     rax, qword ptr [g_lvthh]
    jle     ltd_ret                                  ; thumb fills the track
    mov     qword ptr [g_lvt2], rax                  ; travel = view - thumb
    WINCALL GetCursorPos, addr g_lspt
    mov     eax, dword ptr [g_lspt+4]
    cdqe
    sub     rax, qword ptr [g_lvgraby]               ; pointer delta, signed
    mov     rcx, qword ptr [g_lvcontent]
    sub     rcx, qword ptr [g_lvview]                ; scrollable range
    imul    rax, rcx
    ; the delta carries a sign, so this is a SIGNED divide: cqo + idiv, never
    ; xor edx,edx + div, which would read a negative numerator as enormous
    cqo
    idiv    qword ptr [g_lvt2]
    add     rax, qword ptr [g_lvgrab]
    mov     qword ptr [g_lvscroll], rax               ; lv_apply clamps it
    call    lv_apply
ltd_ret:
    FRAME_EPILOG
    ret
lv_thumb_drag endp

; =============================================================================
; lv_strip_invalidate - repaint just the band the thumb lives in.
; Used when the hover state flips, where the rows have not changed at all.
; =============================================================================
lv_strip_invalidate proc frame
    FRAME_PROLOG 64
    cmp     qword ptr [g_hlist], 0
    je      lsi_ret
    mov     rax, qword ptr [g_lay_lvw]
    sub     rax, LVSB_INSET + LVSB_W + 2
    mov     dword ptr [g_sbrc+0], eax
    mov     rax, qword ptr [g_lvscroll]
    mov     dword ptr [g_sbrc+4], eax
    mov     rax, qword ptr [g_lay_lvw]
    mov     dword ptr [g_sbrc+8], eax
    mov     rax, qword ptr [g_lvscroll]
    add     rax, qword ptr [g_lvview]
    mov     dword ptr [g_sbrc+12], eax
    WINCALL InvalidateRect, qword ptr [g_hlist], addr g_sbrc, 0
lsi_ret:
    FRAME_EPILOG
    ret
lv_strip_invalidate endp

; =============================================================================
; lv_scroll_by(rcx = signed pixel delta) - scroll and re-apply.
; =============================================================================
lv_scroll_by proc frame
    FRAME_PROLOG 48
    add     qword ptr [g_lvscroll], rcx
    call    lv_apply
    FRAME_EPILOG
    ret
lv_scroll_by endp

; =============================================================================
; lv_wheel(rcx = WM_MOUSEWHEEL wParam) - one notch, in pixels.
;
; LV_WHEEL_PX is deliberately not a multiple of the row height: a notch that
; moves a whole number of rows always leaves the list aligned to a row boundary,
; which is the snapping the control used to do and the thing being fixed.
; =============================================================================
lv_wheel proc frame
    FRAME_PROLOG 48
    sar     rcx, 16                                  ; wParam high word
    movsx   rax, cx                                  ; signed, +120 per notch
    imul    rax, rax, LV_WHEEL_PX
    mov     r10, 120
    cqo
    idiv    r10
    neg     rax                                      ; away from the user = up
    mov     rcx, rax
    call    lv_scroll_by
    FRAME_EPILOG
    ret
lv_wheel endp

; =============================================================================
; lv_ensure_visible(rcx = row index) - scroll the row fully into the band.
;
; LVM_ENSUREVISIBLE cannot do this any more: the control is as tall as its
; contents, so every row is already "visible" as far as it is concerned, and it
; scrolls nothing.  Arrow-key navigation would otherwise walk the selection
; straight out of the viewport.
; =============================================================================
lv_ensure_visible proc frame
    FRAME_PROLOG 64
    cmp     qword ptr [g_hlist], 0
    je      lev_ret
    test    rcx, rcx
    js      lev_ret
    mov     qword ptr [g_lvt1], rcx
    mov     dword ptr [g_lvirc+0], LVIR_BOUNDS
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMRECT, qword ptr [g_lvt1], addr g_lvirc
    test    eax, eax
    jz      lev_ret
    ; above the band?  bring its top to the top.
    mov     eax, dword ptr [g_lvirc+4]
    cdqe
    cmp     rax, qword ptr [g_lvscroll]
    jge     lev_below
    mov     qword ptr [g_lvscroll], rax
    call    lv_apply
    jmp     lev_ret
lev_below:
    ; below the band?  bring its bottom to the bottom.
    mov     eax, dword ptr [g_lvirc+12]
    cdqe
    sub     rax, qword ptr [g_lvview]
    cmp     rax, qword ptr [g_lvscroll]
    jle     lev_ret
    mov     qword ptr [g_lvscroll], rax
    call    lv_apply
lev_ret:
    FRAME_EPILOG
    ret
lv_ensure_visible endp

; =============================================================================
; do_layout - position every main-window control from the CURRENT client size.
;
; Until now the geometry existed only at assembly time: 35 MKCTL sites with
; constant coordinates, three SetWindowPos calls in the whole file, and no
; WM_SIZE handler.  A window the user can resize needs those numbers to be
; something that can be RECOMPUTED, so they live here and the MKCTL constants
; become merely what this produces at the default size.
;
; Everything is expressed as an inset from a client edge or an offset from the
; list, never as an absolute: the list grows to absorb the slack, and the
; controls below it ride on its bottom edge.  Positions include the logo band,
; because SetWindowPos and MKCTL now agree: both take real client coordinates.
;
; Only controls whose position depends on the client size are moved.  The
; settings-panel children sit at fixed offsets inside g_hmenubg and follow it
; without being touched.
;
; SWP flags 014h = SWP_NOZORDER or SWP_NOACTIVATE - move and size only, leaving
; the z-order that create order established (the panel must stay above the list).
; =============================================================================
; SetWindowPos takes 7 arguments, so three spill to [rsp+32..rsp+55].  A 48-byte
; request rounds to a 64-byte frame and lands the last of those on rbp-9, one
; byte under the canary - correct but with no margin at all.  64 leaves room.
do_layout proc frame
    FRAME_PROLOG 64
    cmp     qword ptr [g_hwnd], 0
    je      dl_ret                       ; called before the window exists
    cmp     qword ptr [g_hlist], 0
    je      dl_ret                       ; controls not built yet (pre-WM_CREATE)
    ; Encrypt-mode geometry, which the container view also uses - it is the same
    ; control set.  The zip dialog is a different, shorter window with its own,
    ; and several handles below are null there.
    cmp     dword ptr [g_op], 0
    je      dl_go
    cmp     dword ptr [g_container], 0
    je      dl_ret
dl_go:

    WINCALL GetClientRect, qword ptr [g_hwnd], addr g_lay_rc
    xor     rax, rax
    mov     eax, dword ptr [g_lay_rc+8]          ; right (left is always 0)
    mov     qword ptr [g_lay_cw], rax
    xor     rax, rax
    mov     eax, dword ptr [g_lay_rc+12]         ; bottom (top is always 0)
    mov     qword ptr [g_lay_ch], rax

    ; Rows top to bottom: command bar, breadcrumb, list.  The settings panel
    ; covers everything from the breadcrumb down, leaving the bar reachable.
    mov     qword ptr [g_lay_lvy], LV_Y
    mov     qword ptr [g_lay_sby], CRUMB_Y
    ; list width = cw - (left edge of the list) - (right margin)
    mov     rax, qword ptr [g_lay_cw]
    sub     rax, LV_X + LAY_MARGIN
    mov     qword ptr [g_lay_lvw], rax
    ; list height = ch - list top - the band reserved below it
    mov     rax, qword ptr [g_lay_ch]
    sub     rax, LV_Y + LAY_BOTTOM
    mov     qword ptr [g_lay_lvh], rax
    add     rax, LV_Y
    mov     qword ptr [g_lay_bot], rax           ; list bottom
    ; Floor both. WM_GETMINMAXINFO clamps the user's DRAG, but a programmatic
    ; SetWindowPos ignores it, and a negative width or height reaching
    ; SetWindowPos is undefined rather than merely ugly.
    cmp     qword ptr [g_lay_lvw], LAY_LV_MIN_W
    jge     dl_wok
    mov     qword ptr [g_lay_lvw], LAY_LV_MIN_W
dl_wok:
    cmp     qword ptr [g_lay_lvh], LAY_LV_MIN_H
    jge     dl_hok
    mov     qword ptr [g_lay_lvh], LAY_LV_MIN_H
dl_hok:

    ; ---- crumb row: the chip now has the whole width ------------------------
    ; The summary used to take the right-hand 230px of this row.  It has moved
    ; below the list, so the breadcrumb gets the space back - which matters,
    ; because the crumb is a PATH and was the thing being elided.
    WINCALL SetWindowPos, qword ptr [g_hcrumb], 0, LV_X, CRUMB_Y, qword ptr [g_lay_lvw], 24, 014h

    ; ---- settings panel height (it covers the crumb row and the list) -------
    ; The panel deliberately stops at the command bar rather than covering it,
    ; so the gear that opened it stays visible and can close it again.
    mov     rax, qword ptr [g_lay_bot]
    sub     rax, qword ptr [g_lay_sby]
    mov     qword ptr [g_lay_t2], rax

    ; ---- command bar --------------------------------------------------------
    ; Left to right: the two ADD actions as bare glyphs, then the commands that
    ; act on the list, as labelled buttons.  The gear is pinned to the RIGHT
    ; edge, away from all of them, because it opens settings rather than doing
    ; anything to the list.
    WINCALL SetWindowPos, qword ptr [g_hcmdbar], 0, LV_X, CMDBAR_Y, qword ptr [g_lay_lvw], CMDBAR_H, 014h
    WINCALL SetWindowPos, qword ptr [g_haddfiles], 0, LV_X, CMDBAR_Y, CMD_ICON_W, CMDBAR_H-2, 014h
    WINCALL SetWindowPos, qword ptr [g_haddfolder], 0, LV_X + CMD_ICON_W, CMDBAR_Y, CMD_ICON_W, CMDBAR_H-2, 014h
    ; The list commands are right-aligned, with CMD_SPACER of clear air between
    ; them and the gear so "acts on the list" and "opens settings" do not read
    ; as one run of buttons.  Everything below is measured back from the bar's
    ; right edge so it stays put at any window width.
    ; The X owns the right edge; the gear steps one slot in from it.
    mov     rax, qword ptr [g_lay_lvw]
    add     rax, LV_X - CMD_ICON_W
    mov     qword ptr [g_lay_t1], rax            ; close x
    WINCALL SetWindowPos, qword ptr [g_hcmdclose], 0, qword ptr [g_lay_t1], CMDBAR_Y, CMD_ICON_W, CMDBAR_H-2, 014h
    mov     rax, qword ptr [g_lay_t1]
    sub     rax, CMD_ICON_W
    mov     qword ptr [g_lay_t1], rax            ; gear x
    WINCALL SetWindowPos, qword ptr [g_hburger], 0, qword ptr [g_lay_t1], CMDBAR_Y, CMD_ICON_W, CMDBAR_H-2, 014h
    mov     rax, qword ptr [g_lay_t1]
    sub     rax, CMD_SPACER + CMD_BTN_W
    mov     qword ptr [g_lay_t1], rax            ; Clear all x
    WINCALL SetWindowPos, qword ptr [g_hcmdclear], 0, qword ptr [g_lay_t1], CMDBAR_Y, CMD_BTN_W, CMDBAR_H-2, 014h
    ; Remove normally sits left of Clear all - but a CONTAINER view hides Clear
    ; all (adapt_for_container: there is no "empty the container" operation), and
    ; stepping past a button that is not there left Remove stranded a full button
    ; and a gap out into the middle of the bar.  With it hidden, Remove takes its
    ; slot, so the list commands stay together next to the gear.
    ;
    ; It stops at that slot rather than closing up to the gear: CMD_SPACER is the
    ; clear air that keeps "acts on the list" from reading as one run of buttons
    ; with "opens settings", and that distinction is worth more than the last
    ; 24 pixels.
    cmp     dword ptr [g_container], 0
    jne     dl_rm_place                          ; g_lay_t1 is already the slot
    mov     rax, qword ptr [g_lay_t1]
    sub     rax, CMD_BTN_GAP + CMD_BTN_W
    mov     qword ptr [g_lay_t1], rax            ; Remove x
dl_rm_place:
    WINCALL SetWindowPos, qword ptr [g_hcmdremove], 0, qword ptr [g_lay_t1], CMDBAR_Y, CMD_BTN_W, CMDBAR_H-2, 014h

    ; ---- list, and the settings panel that covers it ------------------------
    ; The list is NOT sized to the viewport - lv_apply sizes it to the whole
    ; tree and clips it to g_lay_lvh.  It runs at the end of this proc, once
    ; every geometry global it reads has been recomputed.
    ; the host moves; its children ride along, which is why ONE window is
    ; positioned here instead of ten
    ;
    ; ---- how far down it goes ------------------------------------------------
    ; To the RULE, not to a fixed MENU_H.  At a fixed height it stopped in mid
    ; air with the statistics line showing underneath it, so an open panel was a
    ; rectangle floating over a window that carried on around it.  Ending on the
    ; rule that closes off the list makes it a surface that covers everything
    ; between the command bar and the buttons.
    ;
    ; Never SHORTER than MENU_H, or a small window would clip the controls: the
    ; children sit at fixed offsets down to y=222 and the panel is what they are
    ; clipped to.  A short window gets a panel that overhangs the rule instead,
    ; which is the lesser of the two.
    mov     rax, qword ptr [g_lay_bot]
    add     rax, SEP_GAP
    sub     rax, qword ptr [g_lay_sby]           ; panel top -> rule
    cmp     rax, MENU_H
    jae     @F
    mov     rax, MENU_H
@@:
    mov     qword ptr [g_lay_t2], rax            ; panel height
    WINCALL SetWindowPos, qword ptr [g_hmenuhost], 0, LV_X, qword ptr [g_lay_sby], qword ptr [g_lay_lvw], qword ptr [g_lay_t2], 014h
    ; ---- and how wide the two columns are ------------------------------------
    ; They were pinned at x=16 and x=240, 200 wide, whatever the window did - so
    ; widening the window widened the panel and left the content huddled in its
    ; left half.  Both columns now share the width, which also lengthens every
    ; slider in them, since a slider draws across its own control rect.
    ;
    ; Clamped at both ends: never narrower than the 200 they had, and never
    ; wider than SETT_COLW_MAX, because a slider that spans a maximised window
    ; is harder to set precisely, not easier.
    mov     rax, qword ptr [g_lay_lvw]
    sub     rax, 2*SETT_PAD + SETT_GUTTER
    shr     rax, 1
    cmp     rax, SETT_COLW_MIN
    jae     @F
    mov     rax, SETT_COLW_MIN
@@:
    cmp     rax, SETT_COLW_MAX
    jbe     @F
    mov     rax, SETT_COLW_MAX
@@:
    mov     dword ptr [g_sett_colw], eax
    ; CENTRE the pair once they stop growing.  Past SETT_COLW_MAX the columns
    ; hold their width, and left-aligned they sat against one edge with the
    ; whole surplus as a void down the other side - which reads as a layout that
    ; ran out rather than one that fits.
    lea     r10d, [eax+eax+SETT_GUTTER]          ; content width
    mov     r11d, dword ptr [g_lay_lvw]
    sub     r11d, r10d                           ; slack
    cmp     r11d, 2*SETT_PAD
    jbe     @F                                   ; no room to centre: keep the pad
    shr     r11d, 1
    jmp     dl_sett_x
@@:
    mov     r11d, SETT_PAD
dl_sett_x:
    mov     dword ptr [g_sett_c1x], r11d
    add     eax, r11d
    add     eax, SETT_GUTTER
    mov     dword ptr [g_sett_c2x], eax
    call    settings_place_columns

    ; ---- the password-class flyout rides the panel --------------------------
    ; It is a sibling of the host rather than a child, so nothing carries it
    ; along and it has to be placed here.  Missing this is what left it at its
    ; creation coordinates through every resize.  PWFLY_* are panel-relative, so
    ; the panel's own origin is all that is added.
    mov     rax, qword ptr [g_lay_sby]
    add     rax, PWFLY_Y
    mov     qword ptr [g_lay_t2], rax
    ; x from the COLUMN, not from PWFLY_X: the right column moves with the window
    ; now, and a flyout left at 240 would have drifted off the sliders it is
    ; describing - the same drift the panel-relative rewrite was meant to end.
    mov     eax, dword ptr [g_sett_c2x]
    add     eax, LV_X
    mov     qword ptr [g_lay_t1], rax
    WINCALL SetWindowPos, qword ptr [g_hpwflyout], 0, qword ptr [g_lay_t1], qword ptr [g_lay_t2], PWFLY_W, PWFLY_H, 014h

    ; ---- statistics row, between the list and the rule ----------------------
    ; Right-anchored under the list's right edge, so the count lines up with the
    ; sizes in the column above it rather than starting a new left margin.  It
    ; is STAT_W wide and not full width because the whole control is the click
    ; target for the action log, and a full-width invisible button is a trap.
    mov     rax, qword ptr [g_lay_bot]
    add     rax, STAT_GAP
    mov     qword ptr [g_lay_t2], rax
    mov     rax, qword ptr [g_lay_lvw]
    add     rax, LV_X - STAT_W
    mov     qword ptr [g_lay_t1], rax
    WINCALL SetWindowPos, qword ptr [g_hscan], 0, qword ptr [g_lay_t1], qword ptr [g_lay_t2], STAT_W, STAT_H, 014h
    ; the status line fills the row's remainder, left of the statistics
    mov     r10, qword ptr [g_lay_t1]
    sub     r10, LV_X + 8
    WINCALL SetWindowPos, qword ptr [g_hstatus], 0, LV_X, qword ptr [g_lay_t2], r10, STAT_H, 014h

    ; ---- hairline closing off the list --------------------------------------
    mov     rax, qword ptr [g_lay_bot]
    add     rax, SEP_GAP
    mov     qword ptr [g_lay_t2], rax
    WINCALL SetWindowPos, qword ptr [g_hsep], 0, LV_X, qword ptr [g_lay_t2], qword ptr [g_lay_lvw], 1, 014h

    ; ---- overall progress line, ON the rule ---------------------------------
    ; One pixel above it, three tall: while a job runs the bar IS the rule, and
    ; when it is hidden the rule closes the list off.  Moving the rule down for
    ; the statistics row moved this with it, which is the point of measuring
    ; both from SEP_GAP.
    mov     rax, qword ptr [g_lay_bot]
    add     rax, SEP_GAP - 1
    mov     qword ptr [g_lay_t2], rax
    WINCALL SetWindowPos, qword ptr [g_hprog], 0, LV_X, qword ptr [g_lay_t2], qword ptr [g_lay_lvw], 3, 014h

    ; ---- password row: field stretches, eye stays pinned to the right -------
    ; Everything from here down is offset by STAT_BAND: the statistics row was
    ; inserted above the rule, so the whole lower band moved with it.
    mov     rax, qword ptr [g_lay_cw]
    sub     rax, LAY_MARGIN + LAY_RIGHT_PW + LAY_SHOW_W + LAY_SHOW_GAP
    mov     qword ptr [g_lay_t1], rax            ; password field width
    mov     rax, qword ptr [g_lay_bot]
    add     rax, 16 + STAT_BAND
    mov     qword ptr [g_lay_t2], rax
    WINCALL SetWindowPos, qword ptr [g_hpass], 0, LAY_MARGIN, qword ptr [g_lay_t2], qword ptr [g_lay_t1], 24, 014h
    mov     rax, qword ptr [g_lay_cw]
    sub     rax, LAY_RIGHT_PW + LAY_SHOW_W
    mov     qword ptr [g_lay_t2], rax            ; eye x
    mov     rax, qword ptr [g_lay_bot]
    add     rax, 16 + STAT_BAND
    ; y through memory, not rax: WINCALL emits stack arguments BEFORE register
    ; ones and uses rax as scratch for any 64-bit MEMORY operand among them.
    ; Safe here only because the trailing three are immediates - one edit away
    ; from silently passing that scratch as the y coordinate.
    mov     qword ptr [g_lay_t1], rax
    WINCALL SetWindowPos, qword ptr [g_hshow], 0, qword ptr [g_lay_t2], qword ptr [g_lay_t1], LAY_SHOW_W, 24, 014h
    mov     rax, qword ptr [g_lay_bot]
    add     rax, 40 + STAT_BAND
    mov     qword ptr [g_lay_t2], rax
    WINCALL SetWindowPos, qword ptr [g_hpw_under], 0, LAY_MARGIN, qword ptr [g_lay_t2], qword ptr [g_lay_t1], 2, 014h

    ; ---- buttons: right-anchored, action outermost --------------------------
    mov     rax, qword ptr [g_lay_bot]
    add     rax, 60 + STAT_BAND
    mov     qword ptr [g_lay_t2], rax            ; button row y
    mov     rax, qword ptr [g_lay_cw]
    sub     rax, LAY_MARGIN + LAY_BTN_W
    mov     qword ptr [g_lay_t1], rax            ; action x
    WINCALL SetWindowPos, qword ptr [g_haction], 0, qword ptr [g_lay_t1], qword ptr [g_lay_t2], LAY_BTN_W, LAY_BTN_H, 014h
    mov     rax, qword ptr [g_lay_t1]
    sub     rax, LAY_BTN_GAP + LAY_EXIT_W
    mov     qword ptr [g_lay_t1], rax            ; exit x
    WINCALL SetWindowPos, qword ptr [g_hcancel], 0, qword ptr [g_lay_t1], qword ptr [g_lay_t2], LAY_EXIT_W, LAY_BTN_H, 014h

    ; ---- listview columns: Name absorbs the width change --------------------
    ; Without this the columns keep their creation widths and a widened list
    ; shows a band of empty grid to the right of Progress.
    mov     rax, qword ptr [g_lay_lvw]
    sub     rax, LAY_COL_FIXED
    cmp     rax, 60
    jge     dl_colok
    mov     rax, 60                              ; keep Name clickable when tiny
dl_colok:
    mov     qword ptr [g_lay_t1], rax
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_SETCOLUMNWIDTH, 0, qword ptr [g_lay_t1]

    ; ---- wordmark (lower left), vertically centred on the button row --------
    mov     rax, qword ptr [g_lay_bot]
    add     rax, 60 + STAT_BAND + (LAY_BTN_H - LOGO_SM_H) / 2
    mov     qword ptr [g_lay_t2], rax
    WINCALL SetWindowPos, qword ptr [g_hlogo], 0, LAY_MARGIN, qword ptr [g_lay_t2], LOGO_SM_W, LOGO_SM_H, 014h

    ; ---- the list, its clip band and its scrollbar --------------------------
    ; Last, and only now: lv_apply reads g_lay_lvy/lvw/lvh, and the column width
    ; above changes the row layout it is about to measure.
    call    lv_metrics
    call    lv_apply
dl_ret:
    FRAME_EPILOG
    ret
do_layout endp

; =============================================================================
; create_controls_enc - build the ENCRYPT-mode dialog
; =============================================================================
create_controls_enc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    ; breadcrumb chip (common root of the selected inputs, owner-drawn); the
    ; right end of the row carries the scan status / file-count + size summary
    MKCTL   cls_static, s_ready, ST_CRUMB, ID_CRUMB, LV_X, 8, LV_W, 24, g_hcrumb
    ; the statistics line: its own row under the list, not beside the crumb
    MKCTL   cls_static, s_ready, ST_SCAN, ID_SCAN, LV_X+LV_W-STAT_W, LV_Y+LV_H+STAT_GAP, STAT_W, STAT_H, g_hscan
    ; The operation status - "Encrypting  37%   412.8 MB/s   ETA 4:12" - on the
    ; LEFT of the same row.  set_status_pct, s_working and s_ready have written
    ; this text since the redesign; the CONTROL vanished in a layout rework and
    ; every SetWindowTextW since went to a null hwnd, silently.  Found when the
    ; 1.0.84 rate text did not appear anywhere a screenshot could see.
    MKCTL   cls_static, s_ready, ST_STATUS, ID_STATUS, LV_X, LV_Y+LV_H+STAT_GAP, LV_W-STAT_W-8, STAT_H, g_hstatus
    ; command bar: a strip of list commands between the crumb row and the list.
    ; Created before the list so it sits under nothing; do_layout positions all
    ; of it.  The window text doubles as the drawn label and the MSAA name.
    MKCTL   cls_static, s_ready, ST_CRUMB, ID_CMDBAR, LV_X, LV_Y, LV_W, CMDBAR_H, g_hcmdbar
    ; a hairline closing the list off from the action row below it
    MKCTL   cls_static, s_ready, ST_CRUMB, ID_SEP, LV_X, LV_Y, LV_W, 1, g_hsep
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_CMD_REMOVE, LV_X, LV_Y, CMD_BTN_W, CMDBAR_H-2, g_hcmdremove
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_CMD_CLEAR, LV_X, LV_Y, CMD_BTN_W, CMDBAR_H-2, g_hcmdclear
    WINCALL SetWindowTextW, qword ptr [g_hcmdremove], addr s_cmd_remove
    WINCALL SetWindowTextW, qword ptr [g_hcmdclear], addr s_cmd_clear
    mov     rcx, qword ptr [g_hcmdremove]
    mov     edx, GLYPH_REMOVE
    mov     r8d, GLYPH_LABEL_BIT
    call    glyph_attach
    mov     rcx, qword ptr [g_hcmdclear]
    mov     edx, GLYPH_CLEAR
    mov     r8d, GLYPH_LABEL_BIT
    call    glyph_attach
    ; left margin strip + listview (shifted right of the margin)
    MKCTL   cls_list, s_ready, ST_LIST, ID_LIST, LV_X, LV_Y, LV_W, LV_H, g_hlist
    ; make the (non-selectable) list drag-through so the window moves by it
    mov     rcx, qword ptr [g_hlist]
    call    subclass_list
    ; how wide the scrollbar strip is, for the hover test in scrollbar_eval
    WINCALL GetSystemMetrics, SM_CXVSCROLL
    mov     dword ptr [g_sbw], eax
    ; No scrollbar CONTROL: the bar is drawn into the list's own back buffer by
    ; draw_lv_thumb.  g_sbw is still SM_CXVSCROLL because that is the width of
    ; the strip you reach for, whatever is drawn inside it.
    ; Dark scrollbar, in two halves.  DarkMode_Explorer is the theme Explorer
    ; uses for its own dark panes, but naming it is only half the request: the
    ; theme resolves dark only for a window that has been opted in, on a process
    ; that has declared the preference.  enable_dark_mode did the process; this
    ; does the window, and it has to happen before SetWindowTheme opens the
    ; theme handle.  Without the pair, the bar stayed the light themed one.
    mov     rcx, qword ptr [g_hlist]
    call    dark_mode_window
    WINCALL SetWindowTheme, qword ptr [g_hlist], addr s_theme_dark, 0
    ; A theme change does not repaint the NON-CLIENT area on its own, and the
    ; scrollbar lives there - so the first paint showed the classic 3D bar until
    ; something else happened to recalculate the frame.  SWP_FRAMECHANGED
    ; (0020h) forces that now, with NOMOVE|NOSIZE|NOZORDER|NOACTIVATE (0037h).
    WINCALL SetWindowPos, qword ptr [g_hlist], 0, 0, 0, 0, 0, 0037h
    ; full-row select + double-buffer (reduces flicker on owner-drawn bars)
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_SETEXTENDEDLISTVIEWSTYLE, 0, <LVS_EX_FULLROWSELECT or LVS_EX_DOUBLEBUFFER>
    ; dark listview: dark background + white text
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_SETBKCOLOR, 0, CLR_DARK
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_SETTEXTBKCOLOR, 0, CLR_DARK
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_SETTEXTCOLOR, 0, CLR_WHITE
    ; columns: Name (icon + relative path) | Size | Progress
    xor     rcx, rcx
    lea     rdx, [s_col_name]
    mov     r8d, 268                        ; fit columns within LV_W (no h-scroll)
    mov     r9d, LVCFMT_LEFT
    call    lv_add_column
    mov     rcx, 1
    lea     rdx, [s_col_size]
    mov     r8d, 80
    mov     r9d, LVCFMT_RIGHT
    call    lv_add_column
    mov     rcx, 2
    lea     rdx, [s_col_prog]
    mov     r8d, 103
    mov     r9d, LVCFMT_LEFT
    call    lv_add_column
    ; password row: field on the left (shows a "Password" cue while empty), the
    ; show/hide eye as a SEPARATE button to the right of the field.  Keeping the
    ; button outside the edit avoids the overlap that broke both repaints.
    MKCTL   cls_edit, s_ready, ST_PWEDIT, ID_PASS, 15, LV_Y+LV_H+16+STAT_BAND, 455, 24, g_hpass
    MKCTL   cls_static, s_ready, ST_UNDER, ID_PW_UNDER, 15, LV_Y+LV_H+40+STAT_BAND, 455, 2, g_hpw_under
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_SHOWPW, 476, LV_Y+LV_H+16+STAT_BAND, 34, 24, g_hshow
    ; placeholder cue ("Password") drawn while the field is empty
    mov     rcx, qword ptr [g_hpass]
    call    subclass_edit
    call    hide_pwrow                       ; secure desktop asks instead
    ; overall operation progress: a thin line in its own strip just below the list
    MKCTL   cls_static, s_ready, ST_BARHIDE, ID_PROG, LV_X, LV_Y+LV_H+SEP_GAP-1, LV_W, 3, g_hprog
    ; action (Encrypt) on the right, Exit just to its left
    MKCTL   cls_button, s_exit, ST_OWNERBTN, ID_CANCEL, 307, LV_Y+LV_H+60+STAT_BAND, 80, 32, g_hcancel
    MKCTL   cls_button, s_encrypt, ST_OWNERBTN, ID_ACTION, 395, LV_Y+LV_H+60+STAT_BAND, 120, 32, g_haction
    ; hamburger (top of the left margin) toggles the settings panel
    ; Command-bar buttons.  do_layout gives them their real positions, so the
    ; coordinates here only matter until the first layout pass.
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_ADDFILES,  LV_X, CMDBAR_Y, CMD_ICON_W, CMDBAR_H-2, g_haddfiles
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_ADDFOLDER, LV_X, CMDBAR_Y, CMD_ICON_W, CMDBAR_H-2, g_haddfolder
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_HAMBURGER, LV_X, CMDBAR_Y, CMD_ICON_W, CMDBAR_H-2, g_hburger
    ; Give each one its glyph and the hover subclass.  The window text set below
    ; stays the accessible name - the glyph itself is nothing to a screen reader.
    mov     rcx, qword ptr [g_haddfiles]
    mov     edx, GLYPH_ADD
    xor     r8d, r8d
    call    glyph_attach
    mov     rcx, qword ptr [g_haddfolder]
    mov     edx, GLYPH_FOLDER
    xor     r8d, r8d
    call    glyph_attach
    mov     rcx, qword ptr [g_hburger]
    mov     edx, GLYPH_SETTINGS
    xor     r8d, r8d
    call    glyph_attach
    WINCALL SetWindowTextW, qword ptr [g_hburger], addr s_settings_name
    ; The close X, right of the gear.  A second way out that does not need the
    ; pointer to travel to the bottom of the window - and it is the corner every
    ; other window puts one in.  It sends ID_CMD_CLOSE rather than reusing
    ; ID_CANCEL: WM_DRAWITEM dispatches by control id, and sharing one would
    ; have painted it as the wide Exit button.
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_CMD_CLOSE, LV_X, CMDBAR_Y, CMD_ICON_W, CMDBAR_H-2, g_hcmdclose
    mov     rcx, qword ptr [g_hcmdclose]
    mov     edx, GLYPH_CLOSE
    xor     r8d, r8d
    call    glyph_attach
    WINCALL SetWindowTextW, qword ptr [g_hcmdclose], addr s_close_name
    ; tooltips: the glyphs carry no visible label, so the name has to appear
    ; somewhere the pointer can reach it
    mov     rcx, qword ptr [g_haddfiles]
    lea     rdx, [s_tip_addfiles]
    call    tip_add
    mov     rcx, qword ptr [g_haddfolder]
    lea     rdx, [s_tip_addfolder]
    call    tip_add
    mov     rcx, qword ptr [g_hburger]
    lea     rdx, [s_tip_settings]
    call    tip_add
    mov     rcx, qword ptr [g_hcmdremove]
    lea     rdx, [s_tip_remove]
    call    tip_add
    mov     rcx, qword ptr [g_hcmdclear]
    lea     rdx, [s_tip_clear]
    call    tip_add
    ; settings panel: covers the breadcrumb + listview (from SB_Y down).  Holds
    ; Compress / Format / Log-level / password-policy controls.  Created visible
    ; by style, then hidden until the hamburger opens it.
    ; ---- register the host class once ---------------------------------------
    cmp     dword ptr [g_menu_reg], 0
    jne     cce_haveclass
    lea     rcx, [g_wc]
    xor     r9, r9
cce_zwc:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, WC_SIZE
    jb      cce_zwc
    mov     dword ptr [g_wc+0], WC_SIZE
    lea     rax, [menu_wndproc]
    mov     qword ptr [g_wc+8], rax
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [g_wc+24], rax
    WINCALL LoadCursorW, 0, IDC_ARROW
    mov     qword ptr [g_wc+40], rax
    WINCALL CreateSolidBrush, CLR_MENU_BG
    mov     qword ptr [g_wc+48], rax
    lea     rax, [wc_menu]
    mov     qword ptr [g_wc+64], rax
    WINCALL RegisterClassExW, addr g_wc
    mov     dword ptr [g_menu_reg], 1
cce_haveclass:
    ; The host itself, created AFTER the list so it starts above it, and raised
    ; again on every open because the list does not stay put.
    MKCTL   wc_menu, s_ready, ST_MENUHOST, ID_MENU_HOST, LV_X, CRUMB_Y, LV_W, MENU_H, g_hmenuhost
    ; Everything below is a child of the HOST, so coordinates are relative to it
    ; and the whole panel hides, shows and raises as one window.
    mov     rax, qword ptr [g_hmenuhost]
    mov     qword ptr [g_ctl_parent], rax
    ; Two columns, and the KDF costs are a SUB-SECTION of the right one rather
    ; than a full-width third band underneath both.  They were "Encryption",
    ; which named the wrong thing: nothing here chooses a cipher, and what these
    ; two actually set is how hard the password is to turn into a key.  So they
    ; sit under Password, where the rest of that decision already lives, behind
    ; their own header saying which KDF they are the cost of.
    ;
    ; Private desktop moves the other way, to close out General.  It IS about
    ; the password - which is why it was on the right - but it is a machine
    ; setting rather than a rule about what a password must contain, and the
    ; right column now has two headers' worth of content without it.
    ;
    ; left column - General, in the order asked for on 2026-08-12:
    ; Private desktop, Compress, Format, File split, Log level.
    ;
    ; The two sliders sit at the BOTTOM, which is what the reorder buys beyond
    ; the order itself: the three toggles are now a block of equal-height rows
    ; instead of Log level splitting them.  The column ends at y=222, which is
    ; exactly where the right column ends - that was true before and had to stay
    ; true, or the panel grows for one control.
    MKCTL   cls_static, s_ready, ST_OWNERSTAT, ID_GENHDR, 16, 8, 200, 16, g_hgenhdr
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_SECUREDESK, 16, 30, 200, 26, g_hsecuredesk
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_COMPRESS,   16, 62, 200, 26, g_hcompress
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_FORMAT,     16, 94, 200, 26, g_hformat
    MKCTL   cls_static, s_ready, ST_OWNERSTAT,   ID_VOLSPLIT,   16, 126, 200, 46, g_hvolsplit
    MKCTL   cls_static, s_ready, ST_OWNERSTAT,   ID_LOGLVL,     16, 176, 200, 46, g_hloglvl
    ; right column - Password: (i) info, Min length + Min classes (sliders)
    MKCTL   cls_static, s_ready, ST_OWNERSTAT, ID_PWHDR, 240, 8, 80, 16, g_hpwhdr
    MKCTL   cls_button, s_info_i, ST_OWNERBTN_NT, ID_PWINFO, 302, 6, 18, 18, g_hpwinfo
    MKCTL   cls_static, s_ready, ST_OWNERSTAT, ID_PWMINLEN,     240, 30, 200, 40, g_hminlen
    MKCTL   cls_static, s_ready, ST_OWNERSTAT, ID_PWMINCLASSES, 240, 72, 200, 40, g_hminclasses
    ; ...and its Argon2 KDF sub-section
    MKCTL   cls_static, s_ready, ST_OWNERSTAT, ID_KDFHDR,  240, 118, 200, 16, g_hkdfhdr
    MKCTL   cls_static, s_ready, ST_OWNERSTAT, ID_KDFTIME, 240, 138, 200, 40, g_hkdftime
    MKCTL   cls_static, s_ready, ST_OWNERSTAT, ID_KDFMEM,  240, 182, 200, 40, g_hkdfmem
    mov     qword ptr [g_ctl_parent], 0
    ; Actions.  These are not settings, but the hamburger is the only surface the
    ; window has, and without them a window opened with no arguments can only be
    ; filled by dropping - which is not discoverable on its own.
    WINCALL SetWindowTextW, qword ptr [g_haddfiles],  addr s_add_files
    WINCALL SetWindowTextW, qword ptr [g_haddfolder], addr s_add_folder
    ; class-explanation flyout (hidden until the (i) is clicked)
    ;
    ; Still NOT a child of the host, even though it now sits over it.  As a
    ; SIBLING of the host it is raised above it on open and paints cleanly; as a
    ; child it would be a sibling of the sliders instead, and those repaint on
    ; hover without WS_CLIPSIBLINGS - so moving the mouse would have painted a
    ; slider straight through the open panel.  Same reasoning as the list and
    ; the host, recorded at ST_LIST.
    ;
    ; do_layout places it, from PWFLY_* relative to the panel; the coordinates
    ; here only matter until the first layout pass.
    MKCTL   cls_static, s_ready, ST_OWNERSTAT, ID_PWFLYOUT, LV_X+PWFLY_X, CRUMB_Y+PWFLY_Y, PWFLY_W, PWFLY_H, g_hpwflyout
    ; the sliders handle click + drag via a subclass; the table says which
    call    settings_subclass_sliders
    ; format default: a saved Format wins; else .mrk
    cmp     dword ptr [g_fmt_seen], 0
    jne     @F
    mov     dword ptr [g_make_zip], 0
@@:
    mov     dword ptr [g_menu_open], 0
    WINCALL ShowWindow, qword ptr [g_hpwflyout], SW_HIDE
    ; HKLM-enforced settings: disable the control so it can't be changed
    call    settings_apply_locks
    ; clear placeholder text we passed to the edits / underlines
    mov     word ptr [g_statusw], 0
    WINCALL SetWindowTextW, qword ptr [g_hpass], addr g_statusw
    WINCALL SetWindowTextW, qword ptr [g_hpw_under], addr g_statusw
    ; (no status label any more; overall progress is the thin line in the listview)
    ; Encrypt disabled until the password meets policy (Exit stays enabled)
    WINCALL EnableWindow, qword ptr [g_haction], 0
    ; breadcrumb (common root of the inputs) - cheap, render it immediately
    call    compute_root
    call    build_crumb
    call    build_crumb_short
    ; The recursive size walk is the slow part for huge folders, so run it on a
    ; background thread.  The window paints right away with a live
    ; "Scanning... N files, X" status; on_index_done then fills the listview,
    ; the final summary and the size-based compression default.
    ;
    ; Not for a container: there is nothing to walk, and the walk would fill the
    ; list with the .mrk FILE - which is what the container view was showing
    ; instead of its contents, because on_index_done repopulated the list from
    ; the input model after container_load had filled it from the inventory.
    cmp     dword ptr [g_container], 0
    jne     cce_noindex
    call    start_indexing
cce_noindex:
    ; compression label reflects the current g_compress_on (refined after scan)
    lea     rdx, [s_comp_off]
    cmp     dword ptr [g_compress_on], 0
    je      cce_setlbl
    lea     rdx, [s_comp_on]
cce_setlbl:
    WINCALL SetWindowTextW, qword ptr [g_hcompress], rdx
    ; format label (saved Format may have set g_make_zip)
    lea     rdx, [s_fmt_mrk]
    cmp     dword ptr [g_make_zip], 0
    je      cce_fmtlbl
    lea     rdx, [s_fmt_zip]
cce_fmtlbl:
    WINCALL SetWindowTextW, qword ptr [g_hformat], rdx
    ; the log / min-length / min-classes sliders draw their values directly from
    ; g_cfg_loglevel / g_cfg_pwminlen / g_cfg_pwminclasses on first paint.
    call    update_strength
    ; Run the layout pass once now.  At the default size it reproduces the MKCTL
    ; coordinates exactly, so this is a no-op on screen - which is the point: it
    ; proves the derived geometry matches before anything depends on it.
    call    do_layout
    WINCALL SetFocus, qword ptr [g_hpass]
    add     rsp, 96
    pop     rbp
    ret
create_controls_enc endp

; =============================================================================
; create_controls_dec - build the DECRYPT-mode dialog
; =============================================================================
create_controls_dec proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    ; file name (borderless read-only, no label) - basename only, set below
    MKCTL   cls_edit, s_ready, ST_FILEEDIT, 0, 15, 8, 500, 22, g_hfilelbl
    ; destination (borderless, no label) + Change button
    MKCTL   cls_edit, s_ready, ST_EDIT, ID_DEST, 15, 40, 405, 24, g_hdest
    MKCTL   cls_button, s_change, ST_OWNERBTN, ID_CHANGE, 425, 39, 90, 26, g_hchange
    ; password row - only for .mrk containers and ENCRYPTED zips (full width + eye)
    mov     qword ptr [g_hpass], 0
    cmp     dword ptr [g_is_zip], 0
    je      ccd_pwrow
    cmp     dword ptr [g_zip_enc], 0
    je      ccd_nopw
ccd_pwrow:
    MKCTL   cls_edit, s_ready, ST_PWEDIT, ID_PASS, 15, 80, 455, 24, g_hpass
    MKCTL   cls_static, s_ready, ST_UNDER, ID_PW_UNDER, 15, 104, 455, 2, g_hpw_under
    ; show/hide eye as a separate button to the right of the field (no overlap)
    MKCTL   cls_button, s_ready, ST_OWNERBTN_NT, ID_SHOWPW, 476, 80, 34, 24, g_hshow
    mov     rcx, qword ptr [g_hpass]
    call    subclass_edit
    call    hide_pwrow                       ; secure desktop asks instead
ccd_nopw:
    ; the operation status, in the free band above the bar - same text and
    ; machinery as the main window's (see create_controls_enc)
    MKCTL   cls_static, s_ready, ST_STATUS, ID_STATUS, 15, 110, 500, 18, g_hstatus
    ; overall progress: a thin line (matches the encrypt dialog), hidden until running
    MKCTL   cls_static, s_ready, ST_BARHIDE, ID_PROG, 15, 132, 500, 3, g_hprog
    ; action (Decrypt / Extract) on the right, Exit just to its left (match encrypt)
    MKCTL   cls_button, s_exit, ST_OWNERBTN, ID_CANCEL, 307, 146, 80, 32, g_hcancel
    MKCTL   cls_button, s_decrypt, ST_OWNERBTN, ID_ACTION, 395, 146, 120, 32, g_haction
    cmp     dword ptr [g_is_zip], 0
    je      ccd_lbl_done
    WINCALL SetWindowTextW, qword ptr [g_haction], addr s_extract
ccd_lbl_done:
    ; clear placeholder text from the password field / underline (if present)
    cmp     qword ptr [g_hpass], 0
    je      ccd_clr_done
    mov     word ptr [g_statusw], 0
    WINCALL SetWindowTextW, qword ptr [g_hpass], addr g_statusw
    WINCALL SetWindowTextW, qword ptr [g_hpw_under], addr g_statusw
ccd_clr_done:
    ; file field = the basename only (not the full path)
    lea     rcx, [g_filepath_w]
    call    wfindbase
    mov     qword ptr [rbp-16], rax
    WINCALL SetWindowTextW, qword ptr [g_hfilelbl], qword ptr [rbp-16]
    ; suggested destination = input minus ".mrk" (build_output for decrypt)
    call    build_output                 ; g_outpath_w = suggestion
    WINCALL SetWindowTextW, qword ptr [g_hdest], addr g_outpath_w
    ; (no status label; overall progress is the thin line, like the encrypt dialog)
    ; focus the password field if present, otherwise the action button
    cmp     qword ptr [g_hpass], 0
    je      ccd_focus_action
    WINCALL SetFocus, qword ptr [g_hpass]
    jmp     ccd_focus_done
ccd_focus_action:
    WINCALL SetFocus, qword ptr [g_haction]
ccd_focus_done:
    add     rsp, 96
    pop     rbp
    ret
create_controls_dec endp

; =============================================================================
; create_controls - dispatch to the mode-specific builder
; =============================================================================
create_controls proc
    sub     rsp, 40
    call    make_logo_ctl                ; owner-draw logo spanning the top band
    cmp     dword ptr [g_op], 0
    je      cc_enc
    ; A container is browsed in the SAME window an encrypt uses - list, command
    ; bar, breadcrumb, resize and all.  Building a second window that had to grow
    ; the same features would be two of everything; adapting this one is a
    ; handful of ShowWindow calls.  A zip has no inventory to browse, so it keeps
    ; the small dialog.
    cmp     dword ptr [g_container], 0
    je      cc_dec
cc_enc:
    call    create_controls_enc
    cmp     dword ptr [g_container], 0
    je      cc_ret
    call    adapt_for_container
cc_ret:
    add     rsp, 40
    ret
cc_dec:
    call    create_controls_dec
    add     rsp, 40
    ret
create_controls endp

; =============================================================================
; switch_to_output - the window becomes the file it just made.
;
; Until this existed, a finished encrypt left the window in ENCRYPT mode: same
; title, same Encrypt button, still showing the INPUT list.  So a drop
; afterwards added another input, for an encryption that never ran again, while
; the status line updated as though something had been taken in.  The archive
; on disk was untouched and nothing said so - reported as "the added content
; isn't saved", and recorded in docs/AFTER_ENCRYPT.md.
;
; Nothing here is new machinery.  It is the same sequence an open from the
; command line performs - classify the file, adapt the window, load it - with
; the one difference that the password is already known and must not be asked
; for again.
; =============================================================================
switch_to_output proc frame
    FRAME_PROLOG 64
    ; the file just written becomes the one input
    lea     rcx, [g_filepath_w]
    lea     rdx, [g_outpath_w]
    WBOUND  r8, g_filepath_w, FILEPATH_CHARS
    call    wcopy
    mov     qword ptr [g_poscount], 1
    mov     rcx, 1
    call    set_input_ptrs
    ; --to has now done its entire job, so it stops applying HERE.
    ;
    ; All three things that read it are decisions about starting: which screen
    ; to open on, which folder to build the output in, and whether to ask where
    ; the output goes.  The container just written is past all three.  Leaving
    ; the flag set made detect_op below force g_container to 0 - its rule that a
    ; right-DRAGGED container acts instead of browsing - and this proc then took
    ; the "not browsable" exit and left the window sitting on the INPUT tree.
    ;
    ; That is what a right-drag encrypt looked like when it finished: a list of
    ; the files you had just encrypted, which took clicks, loaded an icon, and
    ; would not expand, with nothing meaningful to do but close it.  The gesture
    ; that says "act immediately" was never meant to also say "and then show the
    ; user something inert".
    ;
    ; Cleared rather than worked around, because it is also right for what comes
    ; next: encrypt something else from this window afterwards and the Save-as
    ; question SHOULD be asked again - the folder that was dropped on has no
    ; claim on a second, unrelated output.
    mov     dword ptr [g_have_dest], 0
    ; classify it exactly as an open from the command line would, so a zip and a
    ; .mrk each get the treatment they already have rather than a second one
    call    detect_op
    cmp     dword ptr [g_container], 0
    je      sto_ret                          ; not browsable: leave the window be
    ; The secret is still in g_cfg_pass and the user typed it twice a moment
    ; ago.  read_password returns immediately once this is set, which is the
    ; whole reason od_restore's wipe must not run on this path.
    mov     dword ptr [g_pw_ready], 1
    call    adapt_for_container
    ; ...and say so.  adapt_for_container changes what the commands mean but not
    ; the caption, because at startup the caption was already right; here it
    ; still reads "encrypt" over a window that is now browsing an archive.
    WINCALL SetWindowTextW, qword ptr [g_hwnd], addr wtitle_dec
    WINCALL ShowWindow, qword ptr [g_hprog], SW_HIDE
    WINCALL EnableWindow, qword ptr [g_haction], 1
    WINCALL EnableWindow, qword ptr [g_hpass], 1
    call    container_load
sto_ret:
    FRAME_EPILOG
    ret
switch_to_output endp

; =============================================================================
; adapt_for_container - turn the encrypt window into a container view.
;
; What differs is what the commands MEAN, not where anything sits: the action
; becomes Decrypt, and the breadcrumb names the container instead of the common
; root of a set of inputs.
;
; Add files and Add folder STAY, and mean "add to this archive".  They were
; hidden here on the reasoning that there is nothing to add to a container,
; which was true when it was written and stopped being true the moment
; container_add existed.  Hiding them left the feature reachable only by a
; posted WM_COMMAND - which is what the tests do, so every test passed while no
; user could get at it.  That is the same stale-comment trap Remove was in, two
; paragraphs down.
; =============================================================================
adapt_for_container proc frame
    FRAME_PROLOG 48
    ; Remove stays: in a container it removes from the container.  Clear all
    ; does not - there is no "empty the container" operation, and a button that
    ; looked like one would be a bad thing to have got wrong.
    WINCALL ShowWindow, qword ptr [g_hcmdclear], SW_HIDE
    ; ...in a zip too, though it means something different there: a zip has no
    ; per-entry extents recorded here (zidx_add_unique leaves them zero) and
    ; nothing to overwrite in place, so removal REWRITES the archive.  The button
    ; used to be hidden for exactly that reason.  zip_delete_marked is that
    ; rewrite, and container_remove_selected picks the path by g_is_zip - so the
    ; zeros are still never acted on, and the command is no longer missing from
    ; half the archives it makes sense for.
afc_action:
    lea     rdx, [s_decrypt]
    cmp     dword ptr [g_is_zip], 0
    je      @F
    lea     rdx, [s_extract]
@@:
    WINCALL SetWindowTextW, qword ptr [g_haction], rdx
    ; create_controls_enc disables the action until the password meets policy.
    ; That is an ENCRYPT rule - there is no policy to meet when decrypting, and
    ; the password has already been given by the time this window is shown.
    WINCALL EnableWindow, qword ptr [g_haction], 1
    call    hide_pwrow                   ; the secure desktop asks instead
    FRAME_EPILOG
    ret
adapt_for_container endp

; =============================================================================
; make_logo_ctl - create the owner-draw STATIC for the logo header band.
; Painted by draw_logo via WM_DRAWITEM; positioned by do_layout in encrypt mode.
; =============================================================================
make_logo_ctl proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    lea     rcx, [cls_button]
    lea     rdx, [s_about_item]          ; readable name for MSAA; glyphs are owner-drawn
    mov     r8, ST_OWNERBTN_NT
    mov     r9, ID_LOGO
    ; Created at the DECRYPT dialog's position, which is a fixed-size window with
    ; no layout pass.  In encrypt mode do_layout moves it to the real spot.
    mov     dword ptr [rsp+32], LAY_MARGIN   ; x
    mov     dword ptr [rsp+40], 158          ; y
    mov     dword ptr [rsp+48], LOGO_SM_W    ; w
    mov     dword ptr [rsp+56], LOGO_SM_H    ; h
    call    create_ctl
    mov     qword ptr [g_hlogo], rax
    add     rsp, 64
    pop     rbp
    ret
make_logo_ctl endp

; =============================================================================
; draw_logo(rcx = DRAWITEMSTRUCT*) - paint the logo band: black fill, runic
; glyphs in #00000A, and (while a sweep is active) a thin diagonal light band
; clipped to the glyph outlines so the light "reflects" only inside the runes.
; =============================================================================
draw_logo proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 144
    ; [rbp-32..-20] RECT(l,t,r,b)  [rbp-40] hdc  [rbp-48] originX  [rbp-52] originY
    ; [rbp-56] k  [rbp-64] oldpen  [rbp-72] ourpen  [rbp-80/-76] SIZE.cx/cy
    ; [rbp-96] colour  [rbp-100] lineX0  [rbp-104] lineX1
    mov     rax, qword ptr [rcx+DI_HDC]
    mov     qword ptr [rbp-40], rax
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-32], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [rbp-28], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-24], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-20], eax
    ; black background
    WINCALL FillRect, qword ptr [rbp-40], addr rbp-32, qword ptr [g_hbr_dark]
    WINCALL SelectObject, qword ptr [rbp-40], qword ptr [g_hfont_logo]
    WINCALL SetBkMode, qword ptr [rbp-40], 1            ; TRANSPARENT
    ; Left-justify the runes in the control and centre them vertically.  No
    ; inset: the control used to span the whole window so the 15px content
    ; margin had to be added here, but it is now placed exactly where the
    ; wordmark starts and an inset would double it.
    WINCALL GetTextExtentPoint32W, qword ptr [rbp-40], addr wlogo_runes, 5, addr rbp-80
    mov     eax, dword ptr [rbp-32]                     ; left
    mov     dword ptr [rbp-48], eax                     ; originX
    mov     eax, dword ptr [rbp-20]
    sub     eax, dword ptr [rbp-28]                     ; rectH
    sub     eax, dword ptr [rbp-76]                     ; - textH
    sar     eax, 1
    add     eax, dword ptr [rbp-28]
    mov     dword ptr [rbp-52], eax                     ; originY
    ; base glyphs (almost black)
    WINCALL SetTextColor, qword ptr [rbp-40], CLR_LOGO_BASE
    WINCALL TextOutW, qword ptr [rbp-40], dword ptr [rbp-48], dword ptr [rbp-52], addr wlogo_runes, 5
    cmp     dword ptr [g_shine_on], 0
    je      dl_done
    ; clip to the glyph outlines
    WINCALL BeginPath, qword ptr [rbp-40]
    WINCALL TextOutW, qword ptr [rbp-40], dword ptr [rbp-48], dword ptr [rbp-52], addr wlogo_runes, 5
    WINCALL EndPath, qword ptr [rbp-40]
    WINCALL SelectClipPath, qword ptr [rbp-40], 5       ; RGN_COPY
    ; diagonal light band: for k=-BW..BW draw line x+y = shine_pos+k, brightest at k=0
    mov     dword ptr [rbp-56], -SHINE_BW
dl_kloop:
    ; num = BW - |k|   (0..BW)
    mov     eax, dword ptr [rbp-56]
    mov     edx, eax
    sar     edx, 31
    xor     eax, edx
    sub     eax, edx                                    ; |k|
    mov     r10d, SHINE_BW
    sub     r10d, eax                                   ; num
    ; colour = 0x00 B G R, channel = base + delta*num/BW  (BW=16 -> >>4)
    mov     eax, r10d
    imul    eax, 0DEh
    shr     eax, 4
    add     eax, 0Ah
    shl     eax, 16                                     ; B
    mov     r8d, eax
    mov     eax, r10d
    imul    eax, 0C8h
    shr     eax, 4
    shl     eax, 8                                      ; G
    or      r8d, eax
    mov     eax, r10d
    imul    eax, 0B8h
    shr     eax, 4                                      ; R
    or      r8d, eax
    mov     dword ptr [rbp-96], r8d
    WINCALL CreatePen, 0, 2, dword ptr [rbp-96]         ; PS_SOLID
    mov     qword ptr [rbp-72], rax
    WINCALL SelectObject, qword ptr [rbp-40], qword ptr [rbp-72]
    mov     qword ptr [rbp-64], rax                     ; old pen
    ; c = shine_pos + k ; line from (c-top, top) to (c-bottom, bottom)
    mov     eax, dword ptr [g_shine_pos]
    add     eax, dword ptr [rbp-56]
    mov     r11d, eax
    sub     eax, dword ptr [rbp-28]                     ; c - top
    mov     dword ptr [rbp-100], eax
    mov     eax, r11d
    sub     eax, dword ptr [rbp-20]                     ; c - bottom
    mov     dword ptr [rbp-104], eax
    WINCALL MoveToEx, qword ptr [rbp-40], dword ptr [rbp-100], dword ptr [rbp-28], 0
    WINCALL LineTo, qword ptr [rbp-40], dword ptr [rbp-104], dword ptr [rbp-20]
    WINCALL SelectObject, qword ptr [rbp-40], qword ptr [rbp-64]
    WINCALL DeleteObject, qword ptr [rbp-72]
    inc     dword ptr [rbp-56]
    cmp     dword ptr [rbp-56], SHINE_BW
    jle     dl_kloop
    WINCALL SelectClipRgn, qword ptr [rbp-40], 0        ; clear clip
dl_done:
    add     rsp, 144
    pop     rbp
    ret
draw_logo endp

; =============================================================================
; on_logo_timer - drive the shine: idle SHINE_IDLE frames, then sweep the band
; across the band's diagonal, repainting the logo control each frame.
; =============================================================================
on_logo_timer proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    cmp     dword ptr [g_shine_on], 0
    jne     olt_active
    ; idle between sweeps
    inc     dword ptr [g_shine_idle]
    mov     eax, dword ptr [g_shine_idle]
    cmp     eax, SHINE_IDLE
    jl      olt_done
    mov     dword ptr [g_shine_idle], 0
    mov     dword ptr [g_shine_on], 1
    mov     dword ptr [g_shine_pos], -SHINE_BW
    jmp     olt_paint
olt_active:
    mov     eax, dword ptr [g_shine_pos]
    add     eax, SHINE_STEP
    mov     dword ptr [g_shine_pos], eax
    cmp     eax, LOGO_SM_W + LOGO_SM_H + SHINE_BW       ; past the far diagonal?
    jle     olt_paint
    mov     dword ptr [g_shine_on], 0                  ; sweep done; one last (base) paint
olt_paint:
    cmp     qword ptr [g_hlogo], 0
    je      olt_done
    WINCALL InvalidateRect, qword ptr [g_hlogo], 0, 0
olt_done:
    add     rsp, 48
    pop     rbp
    ret
on_logo_timer endp

; =============================================================================
; fill_di(rcx = DRAWITEMSTRUCT*, edx = colour) -> rax = hdc.  Fills the item
; rect with a solid colour (creates + frees a temporary brush).
; =============================================================================
fill_di proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     rax, qword ptr [rcx+DI_HDC]
    mov     qword ptr [rbp-8], rax
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-32], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [rbp-28], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-24], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-20], eax
    mov     dword ptr [rbp-36], edx
    WINCALL CreateSolidBrush, dword ptr [rbp-36]
    mov     qword ptr [rbp-16], rax
    WINCALL FillRect, qword ptr [rbp-8], addr rbp-32, qword ptr [rbp-16]
    WINCALL DeleteObject, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-8]
    add     rsp, 64
    pop     rbp
    ret
fill_di endp



; =============================================================================
; Glyph buttons - frameless controls that paint one font glyph plus a rounded
; hover halo.  Ported from vordr's "ghost button" (see its theme.asm /
; gui.asm ghost_attach / ghost_subclass / tdi_ghost).
;
; These replace three hand-drawn glyphs.  Hand-drawing was the rule while the
; strip only needed a hamburger, and it bought independence from any installed
; font - but the command bar needs a dozen glyphs, and hand-drawing those is
; neither practical nor consistent with the rest of Windows.
;
; State lives in the control's own GWLP_USERDATA, not in a side table:
;     userdata = glyph<<16 | hover<<8
; so a button knows what it draws and whether the pointer is on it.  The window
; TEXT stays a readable name: a glyph is invisible to a screen reader, so the
; accessible name has to come from somewhere.
; =============================================================================

; -----------------------------------------------------------------------------
; mk_icon_font - build the PUA icon font, preferring "Segoe Fluent Icons"
; (Windows 11) and falling back to "Segoe MDL2 Assets" (Windows 10).
;
; This check is not optional.  CreateFontW does NOT fail when a face is absent;
; GDI silently substitutes something else, and the PUA codepoints then render as
; empty boxes.  The only way to find out what was actually mapped is to select
; the font into a DC and ask the DC which face it ended up with.
; -----------------------------------------------------------------------------
mk_icon_font proc frame
    FRAME_PROLOG 160
    WINCALL CreateFontW, -18, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr fontface_icon
    mov     qword ptr [g_font_icon], rax
    WINCALL GetDC, 0
    mov     qword ptr [rbp-24], rax
    test    rax, rax
    jz      mif_done                          ; no DC: keep what we made
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_font_icon]
    mov     qword ptr [rbp-32], rax           ; old font
    WINCALL GetTextFaceW, qword ptr [rbp-24], 64, addr g_facebuf
    ; compare the realised face with the one we asked for
    lea     r10, [g_facebuf]
    lea     r11, [fontface_icon]
    xor     r8, r8
mif_cmp:
    movzx   eax, word ptr [r10+r8*2]
    movzx   edx, word ptr [r11+r8*2]
    cmp     eax, edx
    jne     mif_fallback
    test    eax, eax
    jz      mif_restore                       ; both hit NUL together: it matched
    inc     r8
    cmp     r8, 64
    jb      mif_cmp
    jmp     mif_restore
mif_fallback:
    ; Fluent Icons is absent - this is Windows 10.  Take MDL2 Assets, which
    ; carries the same codepoints for every glyph used here.
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-32]
    WINCALL DeleteObject, qword ptr [g_font_icon]
    WINCALL CreateFontW, -18, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr fontface_icon2
    mov     qword ptr [g_font_icon], rax
    WINCALL ReleaseDC, 0, qword ptr [rbp-24]
    jmp     mif_done
mif_restore:
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-32]
    WINCALL ReleaseDC, 0, qword ptr [rbp-24]
mif_done:
    ; symbol font for codepoints below the PUA
    WINCALL CreateFontW, -15, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr fontface_sym
    mov     qword ptr [g_font_sym], rax
    FRAME_EPILOG
    ret
mk_icon_font endp

; -----------------------------------------------------------------------------
; glyph_attach(rcx = button hwnd, edx = glyph codepoint, r8d = flags) - make an
; already created BS_OWNERDRAW button into a glyph button: store the glyph and
; flags, and install the hover subclass.  flags carries GLYPH_LABEL_BIT.  All three share one saved wndproc because they are all
; the same window class.
; -----------------------------------------------------------------------------
glyph_attach proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    test    rcx, rcx
    jz      gat_done
    mov     eax, edx
    shl     eax, 16                           ; glyph in bits 16..31, hover clear
    or      eax, r8d                          ; style flags in the low byte
    mov     edx, eax
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWLP_USERDATA, rdx
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWLP_WNDPROC, addr glyph_subclass
    test    rax, rax
    jz      gat_done
    mov     qword ptr [g_oldglyphproc], rax   ; same for every glyph button
gat_done:
    FRAME_EPILOG
    ret
glyph_attach endp

; -----------------------------------------------------------------------------
; glyph_subclass - hover tracking.  WM_MOUSEMOVE sets the hover bit and arms
; WM_MOUSELEAVE; WM_MOUSELEAVE clears it.  Both repaint.
;
; TRACKMOUSEEVENT's cbSize must be exactly 24 here: TrackMouseEvent rejects a
; wrong size and simply never delivers WM_MOUSELEAVE, which leaves the halo lit
; after the pointer has gone.
; -----------------------------------------------------------------------------
glyph_subclass proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx           ; hwnd
    mov     qword ptr [rbp-32], rdx           ; msg
    mov     qword ptr [rbp-40], r8            ; wParam
    mov     qword ptr [rbp-48], r9            ; lParam
    cmp     rdx, WM_MOUSEMOVE
    je      gs_move
    cmp     rdx, WM_MOUSELEAVE
    je      gs_leave
gs_def:
    WINCALL CallWindowProcW, qword ptr [g_oldglyphproc], qword ptr [rbp-24], \
            qword ptr [rbp-32], qword ptr [rbp-40], qword ptr [rbp-48]
    jmp     gs_ret
gs_move:
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWLP_USERDATA
    test    eax, GLYPH_HOVER_BIT
    jnz     gs_def                            ; already hovering: nothing to do
    or      eax, GLYPH_HOVER_BIT
    mov     edx, eax
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWLP_USERDATA, rdx
    mov     dword ptr [rbp-80], 24            ; cbSize
    mov     dword ptr [rbp-76], TME_LEAVE
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [rbp-72], rax           ; hwndTrack
    mov     dword ptr [rbp-64], 0             ; dwHoverTime
    WINCALL TrackMouseEvent, addr rbp-80
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 1
    jmp     gs_def
gs_leave:
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWLP_USERDATA
    and     eax, NOT GLYPH_HOVER_BIT
    mov     edx, eax
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWLP_USERDATA, rdx
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 1
    jmp     gs_def
gs_ret:
    FRAME_EPILOG
    ret
glyph_subclass endp

; -----------------------------------------------------------------------------
; draw_glyph_btn(rcx = DRAWITEMSTRUCT*) - margin fill, hover halo, then the
; glyph centred.  One routine for every sidebar button; which glyph it paints
; comes from the control's own userdata.
; -----------------------------------------------------------------------------
draw_glyph_btn proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx
    mov     edx, CLR_MARGIN
    call    fill_di
    mov     qword ptr [rbp-32], rax           ; hdc
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-80], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [rbp-76], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-68], eax
    mov     rax, qword ptr [rcx+DI_HWNDITEM]
    mov     qword ptr [rbp-40], rax           ; the control itself
    WINCALL GetWindowLongPtrW, qword ptr [rbp-40], GWLP_USERDATA
    mov     dword ptr [rbp-44], eax           ; userdata
    test    eax, GLYPH_HOVER_BIT
    jz      dgb_glyph
    ; rounded hover halo behind the glyph, borderless (NULL_PEN)
    WINCALL CreateSolidBrush, CLR_GLYPH_HOVER
    mov     qword ptr [rbp-56], rax
    WINCALL GetStockObject, 8                 ; NULL_PEN
    WINCALL SelectObject, qword ptr [rbp-32], rax
    mov     qword ptr [rbp-64], rax           ; old pen
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-56]
    mov     qword ptr [rbp-88], rax           ; old brush
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-80], dword ptr [rbp-76], \
            dword ptr [rbp-72], dword ptr [rbp-68], 8, 8
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-64]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-88]
    WINCALL DeleteObject, qword ptr [rbp-56]
dgb_glyph:
    mov     eax, dword ptr [rbp-44]
    shr     eax, 16
    movzx   eax, ax                           ; codepoint
    test    eax, eax
    jz      dgb_done                          ; no glyph assigned: bare hover area
    mov     word ptr [g_glyphbuf], ax
    mov     word ptr [g_glyphbuf+2], 0
    mov     dword ptr [rbp-92], eax           ; SetTextColor clobbers rax
    WINCALL SetBkMode, qword ptr [rbp-32], 1  ; TRANSPARENT
    WINCALL SetTextColor, qword ptr [rbp-32], GLYPH_INK
    mov     eax, dword ptr [rbp-92]
    cmp     eax, 0E000h                       ; PUA -> icon font, else symbol font
    jb      dgb_sym
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_icon]
    jmp     dgb_draw
dgb_sym:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_sym]
dgb_draw:
    mov     qword ptr [rbp-96], rax           ; old font
    ; Bare glyph (sidebar) is centred; a labelled command (command bar) puts the
    ; glyph in a fixed left gutter so the labels below it line up.
    test    dword ptr [rbp-44], GLYPH_LABEL_BIT
    jnz     dgb_labelled
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_glyphbuf, -1, addr rbp-80, \
            <DT_CENTER or DT_VCENTER or DT_SINGLELINE>
    jmp     dgb_restore
dgb_labelled:
    ; glyph in the gutter
    mov     eax, dword ptr [rbp-80]
    add     eax, CMD_GLYPH_X
    mov     dword ptr [rbp-112], eax
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-108], eax
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [rbp-104], eax
    mov     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-100], eax
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_glyphbuf, -1, addr rbp-112, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE>
    ; label in the UI font, from the window text (which is also the MSAA name)
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_hfont]
    WINCALL GetWindowTextW, qword ptr [rbp-40], addr g_lblbuf, 64
    WINCALL SetTextColor, qword ptr [rbp-32], CLR_WHITE
    mov     eax, dword ptr [rbp-80]
    add     eax, CMD_LABEL_X
    mov     dword ptr [rbp-112], eax
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_lblbuf, -1, addr rbp-112, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE>
dgb_restore:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-96]
dgb_done:
    FRAME_EPILOG
    ret
draw_glyph_btn endp

; -----------------------------------------------------------------------------
; draw_cmdbar(rcx = DI*) - the command strip: window-coloured, with a hairline
; along the bottom so the commands read as a band above the list rather than as
; buttons floating over it.
; -----------------------------------------------------------------------------
; -----------------------------------------------------------------------------
; draw_sep(rcx = DI*) - a 1px rule the width of the list.  Without it the rows
; and the action row below run together on a window with no other edges.
; -----------------------------------------------------------------------------
draw_sep proc frame
    FRAME_PROLOG 64
    mov     edx, CLR_CRUMB_EDGE
    call    fill_di
    FRAME_EPILOG
    ret
draw_sep endp

draw_cmdbar proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     edx, CLR_DARK
    call    fill_di
    mov     qword ptr [rbp-32], rax           ; hdc
    mov     rcx, qword ptr [rbp-24]
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-80], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    sub     eax, 1
    mov     dword ptr [rbp-76], eax           ; top = bottom-1 (a 1px rule)
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-68], eax
    WINCALL CreateSolidBrush, CLR_CRUMB_EDGE
    mov     qword ptr [rbp-40], rax
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-80, qword ptr [rbp-40]
    WINCALL DeleteObject, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
draw_cmdbar endp

; -----------------------------------------------------------------------------
; tip_init - create the one shared tooltip window, on first use.
;
; TTF_SUBCLASS (below) is what makes this work without any message plumbing:
; the tooltip subclasses each tool window itself and picks the hover up from
; there, so nothing has to be forwarded from wndproc.
; -----------------------------------------------------------------------------
tip_init proc frame
    FRAME_PROLOG 128
    cmp     qword ptr [g_htip], 0
    jne     ti_done                              ; one window serves every tool
    WINCALL CreateWindowExW, 0, addr cls_tooltip, 0, \
            <WS_POPUP or TTS_NOPREFIX or TTS_ALWAYSTIP>, \
            0, 0, 0, 0, qword ptr [g_hwnd], 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_htip], rax
ti_done:
    FRAME_EPILOG
    ret
tip_init endp

; -----------------------------------------------------------------------------
; tip_add(rcx = control hwnd, rdx = text) - give a control a tooltip.
;
; cbSize is the V2 size (64 on x64: cbSize, uFlags, hwnd, uId, RECT, hinst,
; lpszText, lParam).  The V3 struct adds lpReserved and is 72; sending 72 to an
; older comctl32 makes TTM_ADDTOOL fail outright, and 64 is accepted by both.
; -----------------------------------------------------------------------------
tip_add proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    test    rcx, rcx
    jz      ta_done
    call    tip_init
    cmp     qword ptr [g_htip], 0
    je      ta_done
    lea     rcx, [g_ti]
    xor     r10, r10
ta_zero:
    mov     byte ptr [rcx+r10], 0
    inc     r10
    cmp     r10, 64
    jb      ta_zero
    mov     dword ptr [g_ti+0], 64
    mov     dword ptr [g_ti+4], TTF_IDISHWND or TTF_SUBCLASS
    mov     rax, qword ptr [g_hwnd]
    mov     qword ptr [g_ti+8], rax              ; owner
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_ti+16], rax             ; uId IS the control hwnd
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [g_ti+48], rax             ; lpszText
    WINCALL SendMessageW, qword ptr [g_htip], TTM_ADDTOOLW, 0, addr g_ti
ta_done:
    FRAME_EPILOG
    ret
tip_add endp

; -----------------------------------------------------------------------------
; remove_selected - take the selected rows out of what will be encrypted.
;
; Two different operations, decided by depth, because a row is no longer an
; input:
;   depth 0  - a top-level input.  Dropped from g_positionals outright.
;   depth > 0 - a file or folder INSIDE an input.  The input stays; the path
;               joins g_excluded and everything downstream skips it.
;
; Nothing on disk is touched either way.
;
; Compaction copies each surviving input's TEXT down into the slot for its new
; index, which is always safe in this direction: slot 0 is the large
; g_filepath_w and every other slot is an equal-sized g_inslots entry, so a
; survivor only ever moves to a slot the same size or bigger.
; -----------------------------------------------------------------------------
remove_selected proc frame
    FRAME_PROLOG 96
    cmp     dword ptr [g_running], 0
    jne     rs_done                           ; never while an operation is live
    ; In a container view the same button means something else entirely: not
    ; "do not encrypt this" but "take this out of the container".
    cmp     dword ptr [g_container], 0
    je      rs_inputs
    call    container_remove_selected
    jmp     rs_done
rs_inputs:
    ; The indexer thread WALKS g_positionals.  Compacting the array underneath
    ; it is a data race on the very thing it is reading, so wait for the scan to
    ; finish rather than rearrange it mid-walk.
    cmp     dword ptr [g_scanning], 0
    jne     rs_done
    cmp     qword ptr [g_rowcount], 0
    je      rs_done
    ; ---- pass 1: classify every selected row ------------------------------
    xor     r10, r10
rs_clear:
    cmp     r10, MAX_ARGS
    jae     rs_scan
    lea     r11, [g_inputdead]
    mov     byte ptr [r11+r10], 0
    inc     r10
    jmp     rs_clear
rs_scan:
    mov     qword ptr [rbp-24], 0             ; row index
    mov     dword ptr [rbp-52], 0             ; anything selected?
rs_loop:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_rowcount]
    jae     rs_apply
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMSTATE, qword ptr [rbp-24], LVIS_SELECTED
    test    eax, LVIS_SELECTED
    jz      rs_next
    mov     dword ptr [rbp-52], 1
    mov     rax, qword ptr [rbp-24]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     eax, dword ptr [r10+ROW_depth]
    test    eax, eax
    jnz     rs_exclude
    ; top-level: mark its input for removal
    mov     eax, dword ptr [r10+ROW_inputi]
    cmp     eax, MAX_ARGS
    jae     rs_next
    lea     r11, [g_inputdead]
    mov     byte ptr [r11+rax], 1
    jmp     rs_next
rs_exclude:
    ; nested: carve just this path out of its input
    mov     rcx, qword ptr [rbp-24]
    call    row_path
    mov     rdx, rax
    lea     rcx, [g_excluded]
    call    pset_add
    test    eax, eax
    jnz     rs_next
    ; The set is full.  Refusing is the honest failure: dropping an exclusion
    ; would encrypt a file the user just removed.
    lea     rcx, [m_excl_full]
    lea     rdx, [t_excl_full]
    mov     r8d, MB_OK
    call    mbox
    jmp     rs_done
rs_next:
    inc     qword ptr [rbp-24]
    jmp     rs_loop
    ; ---- pass 2: compact the inputs the marked rows named ------------------
rs_apply:
    cmp     dword ptr [rbp-52], 0
    je      rs_done                           ; nothing was selected
    mov     qword ptr [rbp-24], 0             ; src
    mov     qword ptr [rbp-32], 0             ; dst
rs_pack:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     rs_fin
    lea     r11, [g_inputdead]
    cmp     byte ptr [r11+rax], 0
    jne     rs_skip
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [rbp-32]
    je      rs_keep                           ; already in the right slot
    mov     rcx, qword ptr [rbp-32]
    call    slot_addr                         ; rax = dst slot, r8 = its last char
    mov     qword ptr [rbp-40], rax
    mov     qword ptr [rbp-48], r8
    lea     r11, [g_positionals]
    mov     r9, qword ptr [rbp-24]
    mov     rdx, qword ptr [r11+r9*8]         ; src text
    mov     rcx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-48]
    call    wcopy
    lea     r11, [g_positionals]
    mov     r9, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r11+r9*8], rax
rs_keep:
    ; The staged destination follows its input into the new slot.  g_pos_prefix
    ; is indexed by POSITION, and this loop is what renumbers positions - left
    ; alone it would not merely be stale, it would name a folder for a file
    ; that is now somebody else.
    mov     rax, qword ptr [rbp-24]
    lea     r11, [g_pos_prefix]
    mov     r9d, dword ptr [r11+rax*4]
    mov     rax, qword ptr [rbp-32]
    mov     dword ptr [r11+rax*4], r9d
    inc     qword ptr [rbp-32]
rs_skip:
    inc     qword ptr [rbp-24]
    jmp     rs_pack
rs_fin:
    ; and the slots that fell off the end go back to the root, so an input
    ; added later does not inherit a removed one's folder
    mov     rax, qword ptr [rbp-32]
rs_tail:
    cmp     rax, qword ptr [g_poscount]         ; still the OLD count here
    jae     rs_tdone
    lea     r11, [g_pos_prefix]
    mov     dword ptr [r11+rax*4], 0
    inc     rax
    jmp     rs_tail
rs_tdone:
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [g_poscount], rax
    call    refresh_inputs                    ; re-root, re-crumb, re-index, re-fill
    call    update_strength                   ; Encrypt may no longer be legal
rs_done:
    FRAME_EPILOG
    ret
remove_selected endp

; -----------------------------------------------------------------------------
; clear_inputs - empty the list entirely.  Same "inputs, not files" rule.
; -----------------------------------------------------------------------------
clear_inputs proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_running], 0
    jne     ci_done
    cmp     dword ptr [g_scanning], 0
    jne     ci_done                           ; same race as remove_selected
    cmp     qword ptr [g_poscount], 0
    je      ci_done
    mov     qword ptr [g_poscount], 0
    ; Both sets go with the inputs.  A surviving exclusion would silently carve
    ; a file out of a path the user adds again later, and a surviving expansion
    ; would reopen a folder they had closed.
    lea     rcx, [g_expanded]
    call    pset_clear
    lea     rcx, [g_excluded]
    call    pset_clear
    call    pfx_reset                         ; ...and so do the staged folders
    call    refresh_inputs
    call    update_strength
ci_done:
    FRAME_EPILOG
    ret
clear_inputs endp

; =============================================================================
; draw_show_icon(rcx = DRAWITEMSTRUCT*) - the show/hide "eye" overlaid in the
; password field: a hollow eye outline + pupil; a slash is added when revealed.
; =============================================================================
draw_show_icon proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 160
    mov     qword ptr [rbp-8], rcx
    mov     edx, CLR_DARK                    ; field background (black)
    call    fill_di
    mov     qword ptr [rbp-16], rax          ; hdc
    mov     rcx, qword ptr [rbp-8]
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-24], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [rbp-28], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-32], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-36], eax
    mov     eax, dword ptr [rbp-24]
    add     eax, dword ptr [rbp-32]
    sar     eax, 1
    mov     dword ptr [rbp-40], eax          ; cx
    mov     eax, dword ptr [rbp-28]
    add     eax, dword ptr [rbp-36]
    sar     eax, 1
    mov     dword ptr [rbp-44], eax          ; cy
    ; light-grey pen + hollow brush for the outline
    WINCALL CreatePen, PS_SOLID, 1, 000C0C0C0h
    mov     qword ptr [rbp-56], rax
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [rbp-56]
    mov     qword ptr [rbp-64], rax
    WINCALL GetStockObject, NULL_BRUSH
    mov     qword ptr [rbp-72], rax
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [rbp-72]
    mov     qword ptr [rbp-80], rax
    ; eye outline ellipse (cx-9, cy-5)-(cx+9, cy+5)
    mov     eax, dword ptr [rbp-40]
    sub     eax, 9
    mov     dword ptr [rbp-100], eax
    mov     eax, dword ptr [rbp-44]
    sub     eax, 5
    mov     dword ptr [rbp-104], eax
    mov     eax, dword ptr [rbp-40]
    add     eax, 9
    mov     dword ptr [rbp-108], eax
    mov     eax, dword ptr [rbp-44]
    add     eax, 5
    mov     dword ptr [rbp-112], eax
    WINCALL Ellipse, qword ptr [rbp-16], dword ptr [rbp-100], dword ptr [rbp-104], dword ptr [rbp-108], dword ptr [rbp-112]
    ; filled pupil
    WINCALL CreateSolidBrush, 000C0C0C0h
    mov     qword ptr [rbp-88], rax
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [rbp-88]
    mov     qword ptr [rbp-96], rax
    mov     eax, dword ptr [rbp-40]
    sub     eax, 2
    mov     dword ptr [rbp-100], eax
    mov     eax, dword ptr [rbp-44]
    sub     eax, 2
    mov     dword ptr [rbp-104], eax
    mov     eax, dword ptr [rbp-40]
    add     eax, 3
    mov     dword ptr [rbp-108], eax
    mov     eax, dword ptr [rbp-44]
    add     eax, 3
    mov     dword ptr [rbp-112], eax
    WINCALL Ellipse, qword ptr [rbp-16], dword ptr [rbp-100], dword ptr [rbp-104], dword ptr [rbp-108], dword ptr [rbp-112]
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [rbp-96]
    WINCALL DeleteObject, qword ptr [rbp-88]
    ; slash when the password is revealed
    cmp     dword ptr [g_showpw], 0
    je      dsi_done
    mov     eax, dword ptr [rbp-40]
    sub     eax, 9
    mov     dword ptr [rbp-100], eax
    mov     eax, dword ptr [rbp-44]
    add     eax, 6
    mov     dword ptr [rbp-104], eax
    WINCALL MoveToEx, qword ptr [rbp-16], dword ptr [rbp-100], dword ptr [rbp-104], 0
    mov     eax, dword ptr [rbp-40]
    add     eax, 9
    mov     dword ptr [rbp-108], eax
    mov     eax, dword ptr [rbp-44]
    sub     eax, 6
    mov     dword ptr [rbp-112], eax
    WINCALL LineTo, qword ptr [rbp-16], dword ptr [rbp-108], dword ptr [rbp-112]
dsi_done:
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [rbp-64]
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [rbp-80]
    WINCALL DeleteObject, qword ptr [rbp-56]
    add     rsp, 160
    pop     rbp
    ret
draw_show_icon endp

; =============================================================================
; Redesigned settings menu - owner-draw helpers + controls.  All use the shared
; g_dr_* scratch (UI thread only; the menu draws never nest).
; =============================================================================

; dr_load(rcx = DI*, edx = bg colour) - fill bg, cache hdc + control rect.
dr_load proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-8], rcx
    call    fill_di
    mov     qword ptr [g_dr_hdc], rax
    mov     rcx, qword ptr [rbp-8]
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [g_dr_l], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [g_dr_t], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [g_dr_r], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [g_dr_b], eax
    mov     eax, dword ptr [g_dr_b]
    mov     dword ptr [g_dr_txtb], eax       ; default text line = whole control
    ; disabled? (HKLM-locked controls render greyed and ignore input)
    mov     rcx, qword ptr [rbp-8]
    mov     rcx, qword ptr [rcx+DI_HWNDITEM]
    WINCALL IsWindowEnabled, rcx
    test    eax, eax
    setz    al
    movzx   eax, al
    mov     dword ptr [g_dr_dis], eax
    add     rsp, 48
    pop     rbp
    ret
dr_load endp

; dr_setfont - UI font, transparent bg, white (or grey if disabled) text.
dr_setfont proc
    sub     rsp, 40
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_hfont]
    WINCALL SetBkMode, qword ptr [g_dr_hdc], 1
    mov     edx, CLR_WHITE
    cmp     dword ptr [g_dr_dis], 0
    je      @F
    mov     edx, CLR_HINT
@@:
    WINCALL SetTextColor, qword ptr [g_dr_hdc], edx
    add     rsp, 40
    ret
dr_setfont endp

; dr_text(rcx = text, edx = DT flags, r8d = left, r9d = right) - draw a single
; text line in [left, g_dr_t, right, g_dr_txtb].
dr_text proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-8], rcx
    mov     dword ptr [rbp-16], edx
    mov     dword ptr [g_dr_rc+0], r8d
    mov     eax, dword ptr [g_dr_t]
    mov     dword ptr [g_dr_rc+4], eax
    mov     dword ptr [g_dr_rc+8], r9d
    mov     eax, dword ptr [g_dr_txtb]
    mov     dword ptr [g_dr_rc+12], eax
    WINCALL DrawTextW, qword ptr [g_dr_hdc], qword ptr [rbp-8], -1, addr g_dr_rc, dword ptr [rbp-16]
    add     rsp, 48
    pop     rbp
    ret
dr_text endp

; dr_pill(g_dr_x0,g_dr_x1 = ends; g_dr_cy = centre; g_dr_col = colour) - draw a
; filled rounded pill (height 18) on g_dr_hdc.
dr_pill proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80
    WINCALL CreateSolidBrush, dword ptr [g_dr_col]
    mov     qword ptr [g_dr_br], rax
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_br]
    mov     qword ptr [g_dr_ob], rax
    WINCALL CreatePen, PS_SOLID, 1, dword ptr [g_dr_col]
    mov     qword ptr [g_dr_pen], rax
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_pen]
    mov     qword ptr [g_dr_op], rax
    mov     eax, dword ptr [g_dr_cy]
    sub     eax, 9
    mov     dword ptr [rbp-8], eax
    mov     eax, dword ptr [g_dr_cy]
    add     eax, 9
    mov     dword ptr [rbp-16], eax
    WINCALL RoundRect, qword ptr [g_dr_hdc], dword ptr [g_dr_x0], dword ptr [rbp-8], dword ptr [g_dr_x1], dword ptr [rbp-16], 18, 18
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_op]
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_ob]
    WINCALL DeleteObject, qword ptr [g_dr_pen]
    WINCALL DeleteObject, qword ptr [g_dr_br]
    add     rsp, 80
    pop     rbp
    ret
dr_pill endp

; dr_knob(eax = centre x; g_dr_cy = centre y) - white filled circle radius 7.
dr_knob proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     dword ptr [g_dr_thumb], eax
    mov     edx, CLR_WHITE
    cmp     dword ptr [g_dr_dis], 0
    je      @F
    mov     edx, CLR_HINT
@@:
    WINCALL CreateSolidBrush, edx
    mov     qword ptr [g_dr_br2], rax
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_br2]
    mov     qword ptr [g_dr_ob2], rax
    mov     eax, dword ptr [g_dr_thumb]
    sub     eax, 7
    mov     dword ptr [rbp-8], eax
    mov     eax, dword ptr [g_dr_cy]
    sub     eax, 7
    mov     dword ptr [rbp-16], eax
    mov     eax, dword ptr [g_dr_thumb]
    add     eax, 7
    mov     dword ptr [rbp-24], eax
    mov     eax, dword ptr [g_dr_cy]
    add     eax, 7
    mov     dword ptr [rbp-32], eax
    WINCALL Ellipse, qword ptr [g_dr_hdc], dword ptr [rbp-8], dword ptr [rbp-16], dword ptr [rbp-24], dword ptr [rbp-32]
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_ob2]
    WINCALL DeleteObject, qword ptr [g_dr_br2]
    add     rsp, 64
    pop     rbp
    ret
dr_knob endp

; draw_toggle(rcx = DI*) - label + on/off pill, for either of the two toggles.
;
; Compress and Private desktop differ only in their label and which flag the
; pill reads, so this picks both up front - the same two-way choice draw_header
; makes for its section headers.  A table lookup would buy nothing at two rows.
draw_toggle proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     eax, dword ptr [rcx+DI_CTLID]
    lea     r10, [s_lbl_compress]
    lea     r11, [g_compress_on]
    cmp     eax, ID_COMPRESS
    je      @F
    lea     r10, [s_lbl_securedesk]
    lea     r11, [g_cfg_securedesk]
@@:
    mov     qword ptr [rbp-8], r10           ; label
    mov     qword ptr [rbp-16], r11          ; -> the flag the pill shows
    mov     edx, CLR_MENU_BG
    call    dr_load
    call    dr_setfont
    mov     rcx, qword ptr [rbp-8]
    mov     edx, DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [g_dr_l]
    add     r8d, 2
    mov     r9d, dword ptr [g_dr_r]
    sub     r9d, 50
    call    dr_text
    mov     eax, dword ptr [g_dr_t]
    add     eax, dword ptr [g_dr_b]
    sar     eax, 1
    mov     dword ptr [g_dr_cy], eax
    mov     eax, dword ptr [g_dr_r]
    sub     eax, 44
    mov     dword ptr [g_dr_x0], eax
    mov     eax, dword ptr [g_dr_r]
    sub     eax, 6
    mov     dword ptr [g_dr_x1], eax
    mov     dword ptr [g_dr_col], CLR_TRACK
    mov     r10, qword ptr [rbp-16]
    cmp     dword ptr [g_dr_dis], 0
    jne     @F                            ; disabled -> grey pill regardless of state
    cmp     dword ptr [r10], 0
    je      @F
    mov     dword ptr [g_dr_col], CLR_ACCENT
@@:
    call    dr_pill
    mov     eax, dword ptr [g_dr_x0]
    add     eax, 9
    mov     r10, qword ptr [rbp-16]       ; dr_pill clobbers the volatiles
    cmp     dword ptr [r10], 0
    je      @F
    mov     eax, dword ptr [g_dr_x1]
    sub     eax, 9
@@:
    call    dr_knob
    add     rsp, 48
    pop     rbp
    ret
draw_toggle endp

; dr_seg - one rounded segment of the Format picker.  Reads g_dr_x0/g_dr_x1 for
; its edges, g_dr_cy for the centre line, and g_dr_col/g_dr_col2 for fill and
; border - the same global-scratch convention dr_pill and dr_knob already use.
;
; It is not dr_pill with different numbers: a pill paints its border in the fill
; colour, and an INACTIVE segment is a dark fill inside a grey border, so the two
; colours have to be separate.
dr_seg proc
    push    rbp
    mov     rbp, rsp
    ; 80, not 48, for the 7-arg RoundRect.  The chip this replaces carried the
    ; note explaining why: at 48 the spilled args 5-7 land on the locals and on
    ; the saved rbp, so RoundRect got a hardcoded 8 as its top edge and "pop rbp"
    ; restored 8 as the frame pointer.
    sub     rsp, 80
    WINCALL CreateSolidBrush, dword ptr [g_dr_col]
    mov     qword ptr [g_dr_br], rax
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_br]
    mov     qword ptr [g_dr_ob], rax
    WINCALL CreatePen, PS_SOLID, 1, dword ptr [g_dr_col2]
    mov     qword ptr [g_dr_pen], rax
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_pen]
    mov     qword ptr [g_dr_op], rax
    mov     eax, dword ptr [g_dr_cy]
    sub     eax, FMT_SEG_H2
    mov     dword ptr [rbp-8], eax
    mov     eax, dword ptr [g_dr_cy]
    add     eax, FMT_SEG_H2
    mov     dword ptr [rbp-16], eax
    WINCALL RoundRect, qword ptr [g_dr_hdc], dword ptr [g_dr_x0], dword ptr [rbp-8], dword ptr [g_dr_x1], dword ptr [rbp-16], 8, 8
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_op]
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_ob]
    WINCALL DeleteObject, qword ptr [g_dr_pen]
    WINCALL DeleteObject, qword ptr [g_dr_br]
    add     rsp, 80
    pop     rbp
    ret
dr_seg endp

; fmt_seg_colours(eax = 1 if this is the selected segment) - fill + border.
; A disabled picker still shows WHICH format is selected; it just says so in
; grey, because hiding the selection would make a locked setting unreadable.
fmt_seg_colours proc
    mov     dword ptr [g_dr_col], CLR_DARK
    mov     dword ptr [g_dr_col2], CLR_TRACK
    test    eax, eax
    jz      fsc_ret
    mov     dword ptr [g_dr_col], CLR_ACCENT
    mov     dword ptr [g_dr_col2], CLR_ACCENT
    cmp     dword ptr [g_dr_dis], 0
    je      fsc_ret
    mov     dword ptr [g_dr_col], CLR_TRACK
    mov     dword ptr [g_dr_col2], CLR_TRACK
fsc_ret:
    ret
fmt_seg_colours endp

; fmt_seg_text(eax = 1 if this is the selected segment) - set the text colour.
fmt_seg_text proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     edx, CLR_HINT
    test    eax, eax
    jz      @F
    mov     edx, CLR_WHITE
    cmp     dword ptr [g_dr_dis], 0
    je      @F
    mov     edx, CLR_HINT
@@:
    WINCALL SetTextColor, qword ptr [g_dr_hdc], edx
    add     rsp, 48
    pop     rbp
    ret
fmt_seg_text endp

; draw_format_seg(rcx = DI*) - Format: label on the left, two segments on the
; right, the selected one filled with the accent.
;
; The segments are right-anchored so the row lines up with Compress's pill above
; it, and the label's right edge is derived from theirs rather than hardcoded -
; widening a segment must not silently start overprinting the word "Format".
draw_format_seg proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     edx, CLR_MENU_BG
    call    dr_load
    call    dr_setfont
    ; geometry, measured back from the right edge
    mov     eax, dword ptr [g_dr_r]
    sub     eax, FMT_SEG_PAD
    mov     dword ptr [rbp-32], eax          ; right segment, right edge
    sub     eax, FMT_SEG_W
    mov     dword ptr [rbp-24], eax          ; right segment, left edge
    sub     eax, FMT_SEG_GAP
    mov     dword ptr [rbp-16], eax          ; left segment, right edge
    sub     eax, FMT_SEG_W
    mov     dword ptr [rbp-8], eax           ; left segment, left edge
    ; label, stopping clear of the segments
    lea     rcx, [s_lbl_format]
    mov     edx, DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [g_dr_l]
    add     r8d, 2
    mov     r9d, dword ptr [rbp-8]
    sub     r9d, 6
    call    dr_text
    ; both segments share the control's centre line
    mov     eax, dword ptr [g_dr_t]
    add     eax, dword ptr [g_dr_b]
    sar     eax, 1
    mov     dword ptr [g_dr_cy], eax
    ; left segment - Myrkr, selected when g_make_zip is 0
    mov     eax, dword ptr [rbp-8]
    mov     dword ptr [g_dr_x0], eax
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_dr_x1], eax
    mov     eax, dword ptr [g_make_zip]
    xor     eax, 1
    call    fmt_seg_colours
    call    dr_seg
    ; right segment - Zip
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_dr_x0], eax
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_dr_x1], eax
    mov     eax, dword ptr [g_make_zip]
    call    fmt_seg_colours
    call    dr_seg
    ; the names, each centred in its own segment
    mov     eax, dword ptr [g_make_zip]
    xor     eax, 1
    call    fmt_seg_text
    lea     rcx, [s_fmt_mrk_s]
    mov     edx, DT_CENTER or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [rbp-8]
    mov     r9d, dword ptr [rbp-16]
    call    dr_text
    mov     eax, dword ptr [g_make_zip]
    call    fmt_seg_text
    lea     rcx, [s_fmt_zip_s]
    mov     edx, DT_CENTER or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [rbp-24]
    mov     r9d, dword ptr [rbp-32]
    call    dr_text
    add     rsp, 64
    pop     rbp
    ret
draw_format_seg endp

; draw_info_icon(rcx = DI*) - a small circled "i".
draw_info_icon proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     edx, CLR_MENU_BG
    call    dr_load
    WINCALL GetStockObject, NULL_BRUSH
    WINCALL SelectObject, qword ptr [g_dr_hdc], rax
    mov     qword ptr [g_dr_ob], rax
    WINCALL CreatePen, PS_SOLID, 1, CLR_HINT
    mov     qword ptr [g_dr_pen], rax
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_pen]
    mov     qword ptr [g_dr_op], rax
    WINCALL Ellipse, qword ptr [g_dr_hdc], dword ptr [g_dr_l], dword ptr [g_dr_t], dword ptr [g_dr_r], dword ptr [g_dr_b]
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_op]
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_dr_ob]
    WINCALL DeleteObject, qword ptr [g_dr_pen]
    call    dr_setfont
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_HINT
    lea     rcx, [s_info_i]
    mov     edx, DT_CENTER or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [g_dr_l]
    mov     r9d, dword ptr [g_dr_r]
    call    dr_text
    add     rsp, 48
    pop     rbp
    ret
draw_info_icon endp

; draw_header(rcx = DI*) - a muted-grey section header ("General" / "Password").
draw_header proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-8], rcx
    mov     edx, CLR_MENU_BG
    call    dr_load
    call    dr_setfont
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_HINT
    mov     rcx, qword ptr [rbp-8]
    mov     eax, dword ptr [rcx+DI_CTLID]
    lea     rcx, [s_hdr_general]
    cmp     eax, ID_GENHDR
    je      @F
    lea     rcx, [s_hdr_kdf]
    cmp     eax, ID_KDFHDR
    je      @F
    lea     rcx, [s_hdr_password]
@@:
    mov     edx, DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [g_dr_l]
    mov     r9d, dword ptr [g_dr_r]
    call    dr_text
    add     rsp, 48
    pop     rbp
    ret
draw_header endp

; draw_flyout(rcx = DI*) - the class-explanation card (dark, word-wrapped).
; =============================================================================
; hairline_rect(rcx = hdc, rdx = RECT*, r8d = corner diameter (0 = square),
;               r9d = the surface's OWN accent, at full strength)
;
; One pixel of edge around a surface that would otherwise have none: every panel
; here is painted over a window that is the same black, so without it nothing
; says where the card begins.
;
; THE COLOUR IS HALVED HERE, not by the caller.  Each surface passes the accent
; it already uses for its own stripe and heading - which for the message box is
; the SEVERITY colour, so an error box is edged in red and a warning in amber,
; and the whole card reads as the thing it is instead of only a 4px stripe.
; Halving in one place is what keeps "half luminosity" meaning the same thing on
; all of them; a caller passing a pre-dimmed colour would be dimmed twice.
; COLORREF is 00BBGGRR, so a byte-wise shift halves each channel independently -
; the low bit of each is lost, which at these values is invisible.  The AND is
; not decoration: it clears the bit each channel's shift drags in from the one
; above it, which would otherwise brighten blue with green's low bit.
;
; Worked, against the value this replaces: CLR_ACCENT 00B85F00 >> 1 = 005C2F80,
; masked = 005C2F00 - exactly the CLR_ACCENT_DIM constant that was hand-written
; for 1.0.37 and approved on screen.  So the formula reproduces an edge that has
; already been looked at, and the constant could be deleted rather than trusted.
;
; SQUARE OR ROUNDED, because the dialogs are not the panels.  Every one of these
; windows is clipped to CreateRoundRectRgn(..., WIN_ROUND, WIN_ROUND), so a
; square frame gets its corners cut off by the region and the edge visibly stops
; short on all four - which is what it did.  A RoundRect outline at the same
; radius follows the clip instead of fighting it.  The flyout passes 0: it is a
; panel inside the main window, not a window, and has square corners to match.
;
; FrameRect / RoundRect and not Rectangle: exactly one pixel, interior untouched,
; so whatever the caller has already filled stands.
;
; A proc and not a fifth copy of the same block: it started as one in the flyout,
; and by the time the log viewer wanted it the version that got copied would have
; been whichever one was found first.
; =============================================================================
hairline_rect proc
    push    rbp
    mov     rbp, rsp
    ; 192: RoundRect takes SEVEN arguments, so its outgoing area runs to rsp+55
    ; (= rbp-137) and every local below has to sit above that.
    sub     rsp, 192
    ; [rbp-8] hdc  [rbp-16] rect  [rbp-24] diameter  [rbp-32] dim colour
    ; [rbp-40] pen/brush  [rbp-48] old pen  [rbp-56] old brush
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     eax, r8d
    mov     qword ptr [rbp-24], rax
    mov     eax, r9d
    shr     eax, 1
    and     eax, 07F7F7Fh                    ; half of each channel
    mov     dword ptr [rbp-32], eax
    cmp     qword ptr [rbp-24], 0
    jne     hr_round
    ; ---- square: a brush and one FrameRect ---------------------------------
    WINCALL CreateSolidBrush, dword ptr [rbp-32]
    test    rax, rax
    jz      hr_ret                           ; no brush: the panel has no edge
    mov     qword ptr [rbp-40], rax
    WINCALL FrameRect, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-40]
    WINCALL DeleteObject, qword ptr [rbp-40]
    jmp     hr_ret
hr_round:
    ; ---- rounded: a 1px pen, no fill ---------------------------------------
    WINCALL CreatePen, PS_SOLID, 1, dword ptr [rbp-32]
    test    rax, rax
    jz      hr_ret
    mov     qword ptr [rbp-40], rax
    WINCALL SelectObject, qword ptr [rbp-8], qword ptr [rbp-40]
    mov     qword ptr [rbp-48], rax
    WINCALL GetStockObject, NULL_BRUSH        ; outline only - the fill is already there
    WINCALL SelectObject, qword ptr [rbp-8], rax
    mov     qword ptr [rbp-56], rax
    ; RECT is exclusive and so is RoundRect, so the rect goes through unadjusted
    ; and the outline lands on the last pixel INSIDE it - the same pixels the
    ; window region keeps.
    mov     r10, qword ptr [rbp-16]
    mov     eax, dword ptr [r10+0]
    mov     dword ptr [rbp-64], eax
    mov     eax, dword ptr [r10+4]
    mov     dword ptr [rbp-68], eax
    mov     eax, dword ptr [r10+8]
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [r10+12]
    mov     dword ptr [rbp-76], eax
    WINCALL RoundRect, qword ptr [rbp-8], dword ptr [rbp-64], dword ptr [rbp-68], \
            dword ptr [rbp-72], dword ptr [rbp-76], qword ptr [rbp-24], qword ptr [rbp-24]
    WINCALL SelectObject, qword ptr [rbp-8], qword ptr [rbp-56]
    WINCALL SelectObject, qword ptr [rbp-8], qword ptr [rbp-48]
    WINCALL DeleteObject, qword ptr [rbp-40]
hr_ret:
    add     rsp, 192                         ; MUST match the sub above
    pop     rbp
    ret
hairline_rect endp

draw_flyout proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64                       ; 64, not 48: DrawTextW takes five
                                          ; arguments, so its fifth spills to
                                          ; rsp+32 - which at 48 was the brush
                                          ; slot below.  Dead by then, but a
                                          ; frame that relies on that is a frame
                                          ; that breaks when the order changes.
    mov     edx, CLR_DARK
    call    dr_load
    mov     eax, dword ptr [g_dr_l]
    mov     dword ptr [g_dr_rc+0], eax
    mov     eax, dword ptr [g_dr_t]
    mov     dword ptr [g_dr_rc+4], eax
    mov     eax, dword ptr [g_dr_r]
    mov     dword ptr [g_dr_rc+8], eax
    mov     eax, dword ptr [g_dr_b]
    mov     dword ptr [g_dr_rc+12], eax
    mov     rcx, qword ptr [g_dr_hdc]
    lea     rdx, [g_dr_rc]
    xor     r8d, r8d                      ; square: a panel inside the window, not a window
    mov     r9d, CLR_ACCENT
    call    hairline_rect
    call    dr_setfont
    mov     eax, dword ptr [g_dr_l]
    add     eax, 8
    mov     dword ptr [g_dr_rc+0], eax
    mov     eax, dword ptr [g_dr_t]
    add     eax, 5
    mov     dword ptr [g_dr_rc+4], eax
    mov     eax, dword ptr [g_dr_r]
    sub     eax, 8
    mov     dword ptr [g_dr_rc+8], eax
    mov     eax, dword ptr [g_dr_b]
    mov     dword ptr [g_dr_rc+12], eax
    WINCALL DrawTextW, qword ptr [g_dr_hdc], addr s_pwflyout, -1, addr g_dr_rc, <DT_LEFT or DT_WORDBREAK or DT_NOPREFIX>
    add     rsp, 64
    pop     rbp
    ret
draw_flyout endp

; slider_desc(ecx = control ID) - fill g_sld_min/max/valptr/keyptr/lblptr.
slider_desc proc
    ; Clobbers rax, r10, r11 only - callers keep the id in their own frame and
    ; nothing of theirs lives in those across the call.
    mov     r11d, ecx
    xor     eax, eax                        ; byte offset into the table
sld_row:
    cmp     eax, SETROW_COUNT*SETROW_SIZE
    jae     sld_default
    lea     r10, [g_setrows]
    add     r10, rax
    cmp     qword ptr [r10+sr_lbl], 0
    je      sld_next                        ; not a slider
    cmp     r11d, dword ptr [r10+sr_id]
    je      sld_fill
sld_next:
    add     eax, SETROW_SIZE
    jmp     sld_row
sld_default:
    ; The if-chain this replaces ended in an unguarded else that filled
    ; MinClasses' descriptor, so an id belonging to no slider landed there.
    ; Kept, because the alternative is leaving g_sld_* holding the LAST slider's
    ; values while the caller draws or drags a different control - stale is worse
    ; than consistently wrong.  Both callers pass a real slider id, so this is
    ; unreachable in practice.
    lea     r10, [g_setrows]
    add     r10, 4*SETROW_SIZE
sld_fill:
    mov     eax, dword ptr [r10+sr_smin]
    mov     dword ptr [g_sld_min], eax
    mov     eax, dword ptr [r10+sr_smax]
    mov     dword ptr [g_sld_max], eax
    mov     rax, qword ptr [r10+sr_val]
    mov     qword ptr [g_sld_valptr], rax
    mov     rax, qword ptr [r10+sr_name]
    mov     qword ptr [g_sld_keyptr], rax
    mov     rax, qword ptr [r10+sr_lbl]
    mov     qword ptr [g_sld_lblptr], rax
    ; 0 and 1 both mean "no scaling"; normalising here keeps the DIV in
    ; draw_slider from having to guard against a zero divisor twice.
    mov     eax, dword ptr [r10+sr_scale]
    test    eax, eax
    jnz     @F
    mov     eax, 1
@@:
    mov     dword ptr [g_sld_scale], eax
    mov     eax, dword ptr [r10+sr_step]
    test    eax, eax
    jnz     @F
    mov     eax, 1
@@:
    mov     dword ptr [g_sld_step], eax
    mov     rax, qword ptr [r10+sr_unit]
    mov     qword ptr [g_sld_unit], rax
    ret
slider_desc endp

; =============================================================================
; settings_place_columns - put the panel's children on the computed columns.
;
; They are created at fixed offsets (16 and 240, 200 wide) and that is all they
; ever were: the panel widened with the window and the content did not.  This
; runs from do_layout, after g_sett_c1x/c2x/colw are worked out, and it is the
; only place those offsets are decided now.
;
; y and height are left alone.  The rows are a designed vertical rhythm ending
; at 222 in both columns, and nothing about a wider window changes it.
; =============================================================================
settings_place_columns proc frame
    ; 96, not 64: SetWindowPos takes SEVEN arguments, so the outgoing area
    ; reaches rsp+55 and a local at rbp-40 would have been one of its stack
    ; slots.  The same trap three other procs here record hitting.
    FRAME_PROLOG 96
    cmp     qword ptr [g_hmenuhost], 0
    je      spc_ret                          ; called before the panel exists
    mov     eax, dword ptr [g_sett_c1x]
    mov     qword ptr [rbp-16], rax          ; left x
    mov     eax, dword ptr [g_sett_c2x]
    mov     qword ptr [rbp-24], rax          ; right x
    mov     eax, dword ptr [g_sett_colw]
    mov     qword ptr [rbp-32], rax          ; column width
    ; SWP_NOZORDER|SWP_NOACTIVATE|SWP_NOMOVE is not usable here - x moves and y
    ; does not, so each call passes the y it already has.  They are constants in
    ; the creation list above and constants here; keeping them as immediates is
    ; what makes the two lists comparable by eye.
    ; left column - General
    WINCALL SetWindowPos, qword ptr [g_hgenhdr],     0, qword ptr [rbp-16], 8,   qword ptr [rbp-32], 16, 014h
    WINCALL SetWindowPos, qword ptr [g_hsecuredesk], 0, qword ptr [rbp-16], 30,  qword ptr [rbp-32], 26, 014h
    WINCALL SetWindowPos, qword ptr [g_hcompress],   0, qword ptr [rbp-16], 62,  qword ptr [rbp-32], 26, 014h
    WINCALL SetWindowPos, qword ptr [g_hformat],     0, qword ptr [rbp-16], 94,  qword ptr [rbp-32], 26, 014h
    WINCALL SetWindowPos, qword ptr [g_hvolsplit],   0, qword ptr [rbp-16], 126, qword ptr [rbp-32], 46, 014h
    WINCALL SetWindowPos, qword ptr [g_hloglvl],     0, qword ptr [rbp-16], 176, qword ptr [rbp-32], 46, 014h
    ; right column - Password, then the KDF sub-section
    WINCALL SetWindowPos, qword ptr [g_hpwhdr],      0, qword ptr [rbp-24], 8,   80, 16, 014h
    ; the (i) rides the header's right edge rather than a fixed 302
    mov     rax, qword ptr [rbp-24]
    add     rax, 62
    mov     qword ptr [rbp-40], rax
    WINCALL SetWindowPos, qword ptr [g_hpwinfo],     0, qword ptr [rbp-40], 6,   18, 18, 014h
    WINCALL SetWindowPos, qword ptr [g_hminlen],     0, qword ptr [rbp-24], 30,  qword ptr [rbp-32], 40, 014h
    WINCALL SetWindowPos, qword ptr [g_hminclasses], 0, qword ptr [rbp-24], 72,  qword ptr [rbp-32], 40, 014h
    WINCALL SetWindowPos, qword ptr [g_hkdfhdr],     0, qword ptr [rbp-24], 118, qword ptr [rbp-32], 16, 014h
    WINCALL SetWindowPos, qword ptr [g_hkdftime],    0, qword ptr [rbp-24], 138, qword ptr [rbp-32], 40, 014h
    WINCALL SetWindowPos, qword ptr [g_hkdfmem],     0, qword ptr [rbp-24], 182, qword ptr [rbp-32], 40, 014h
spc_ret:
    xor     eax, eax
    FRAME_EPILOG
    ret
settings_place_columns endp

; =============================================================================
; settings_apply_locks - disable every panel control HKLM has fixed.
;
; A value's PRESENCE under HKLM is what locks it (manifest 14), and load_settings
; records that in the row's lock flag.  This turns it into the greyed-out control.
; Rows with no control of their own are skipped rather than special-cased.
; =============================================================================
settings_apply_locks proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], 0
sal_row:
    mov     rax, qword ptr [rbp-8]
    cmp     rax, SETROW_COUNT*SETROW_SIZE
    jae     sal_ret
    lea     r10, [g_setrows]
    add     r10, rax
    mov     rcx, qword ptr [r10+sr_lock]
    test    rcx, rcx
    jz      sal_next
    cmp     dword ptr [rcx], 0
    je      sal_next                        ; not fixed by policy
    mov     rcx, qword ptr [r10+sr_hwnd]
    test    rcx, rcx
    jz      sal_next                        ; policy only: nothing to disable
    WINCALL EnableWindow, qword ptr [rcx], 0
sal_next:
    add     qword ptr [rbp-8], SETROW_SIZE
    jmp     sal_row
sal_ret:
    add     rsp, 64
    pop     rbp
    ret
settings_apply_locks endp

; =============================================================================
; settings_subclass_sliders - hand every slider its click/drag subclass.
;
; The rows say which controls are sliders, so adding one cannot leave it inert
; the way a fourth hardcoded call site could have been forgotten.
; =============================================================================
settings_subclass_sliders proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-8], 0
sss_row:
    mov     rax, qword ptr [rbp-8]
    cmp     rax, SETROW_COUNT*SETROW_SIZE
    jae     sss_ret
    lea     r10, [g_setrows]
    add     r10, rax
    cmp     qword ptr [r10+sr_lbl], 0
    je      sss_next                        ; not a slider
    mov     rcx, qword ptr [r10+sr_hwnd]
    test    rcx, rcx
    jz      sss_next
    mov     rcx, qword ptr [rcx]
    call    subclass_slider
sss_next:
    add     qword ptr [rbp-8], SETROW_SIZE
    jmp     sss_row
sss_ret:
    add     rsp, 48
    pop     rbp
    ret
settings_subclass_sliders endp

; log_name(eax = level 0..4) -> rax = ptr to its wide name.
; =============================================================================
; vsplit_name -> rax = the label for g_cfg_splitidx, and vsplit_bytes -> rax = the
; size it means.  One index, two tables, and they are checked against each other
; by selftest rather than by eye: a slider that says "700 MB (CD)" and produces
; 100 MB volumes is wrong in a way nobody would notice until the disc did not
; fit.
; =============================================================================
vsplit_name proc
    mov     eax, dword ptr [g_cfg_splitidx]
    cmp     eax, SPLIT_MAX_IDX
    jbe     @F
    xor     eax, eax                         ; out of range reads as Off
@@:
    lea     r10, [g_split_names]
    mov     rax, qword ptr [r10+rax*8]
    ret
vsplit_name endp

public vsplit_bytes
vsplit_bytes proc
    mov     eax, dword ptr [g_cfg_splitidx]
    cmp     eax, SPLIT_MAX_IDX
    jbe     @F
    xor     eax, eax
@@:
    lea     r10, [g_split_sizes]
    mov     rax, qword ptr [r10+rax*8]
    ret
vsplit_bytes endp

log_name proc
    lea     rax, [s_lvl_none]
    cmp     dword ptr [g_cfg_loglevel], 1
    jb      ln_ret
    lea     rax, [s_lvl_error]
    je      ln_ret
    lea     rax, [s_lvl_warning]
    cmp     dword ptr [g_cfg_loglevel], 2
    je      ln_ret
    lea     rax, [s_lvl_full]
    cmp     dword ptr [g_cfg_loglevel], 3
    je      ln_ret
    lea     rax, [s_lvl_debug]
ln_ret:
    ret
log_name endp

; draw_slider(rcx = DI*) - label + value on the top line, track + fill + thumb
; below.  Reads the descriptor for this control's ID.
draw_slider proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     edx, CLR_MENU_BG
    call    dr_load
    mov     rcx, qword ptr [rbp-8]
    mov     ecx, dword ptr [rcx+DI_CTLID]
    mov     dword ptr [rbp-24], ecx          ; ctl id
    call    slider_desc
    call    dr_setfont
    ; text line top = g_dr_t..g_dr_t+20
    mov     eax, dword ptr [g_dr_t]
    add     eax, 20
    mov     dword ptr [g_dr_txtb], eax
    ; label (left)
    mov     rcx, qword ptr [g_sld_lblptr]
    mov     edx, DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [g_dr_l]
    add     r8d, 2
    mov     r9d, dword ptr [g_dr_r]
    call    dr_text
    ; value (right): a name for the log slider, else the number
    mov     eax, dword ptr [rbp-24]
    cmp     eax, ID_VOLSPLIT
    jne     @F
    call    vsplit_name
    mov     qword ptr [rbp-16], rax
    jmp     sd_drawval
@@:
    cmp     eax, ID_LOGLVL
    jne     sd_num
    mov     eax, dword ptr [g_cfg_loglevel]
    call    log_name
    mov     qword ptr [rbp-16], rax
    jmp     sd_drawval
sd_num:
    mov     rcx, qword ptr [g_sld_valptr]
    mov     eax, dword ptr [rcx]
    xor     edx, edx
    div     dword ptr [g_sld_scale]          ; KiB -> MiB for Memory, identity else
    lea     rcx, [g_sldbuf]
    call    u64_to_wide
    mov     word ptr [rax], 0                ; NUL-terminate
    cmp     qword ptr [g_sld_unit], 0
    je      @F
    mov     rcx, rax                         ; append onto the digits
    mov     rdx, qword ptr [g_sld_unit]
    lea     r8, [g_sldbuf+30]                ; last slot of the 16-wchar buffer
    call    wcopy
@@:
    lea     rax, [g_sldbuf]
    mov     qword ptr [rbp-16], rax
sd_drawval:
    mov     rcx, qword ptr [rbp-16]
    mov     edx, DT_RIGHT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [g_dr_l]
    mov     r9d, dword ptr [g_dr_r]
    sub     r9d, 2
    call    dr_text
    ; track geometry: x0=l+10, x1=r-10, cy = t+32
    mov     eax, dword ptr [g_dr_l]
    add     eax, 10
    mov     dword ptr [g_dr_x0], eax
    mov     eax, dword ptr [g_dr_r]
    sub     eax, 10
    mov     dword ptr [g_dr_x1], eax
    mov     eax, dword ptr [g_dr_t]
    add     eax, 32
    mov     dword ptr [g_dr_cy], eax
    ; thumb x = x0 + (cur-min)*(x1-x0)/(max-min)
    mov     rcx, qword ptr [g_sld_valptr]
    mov     eax, dword ptr [rcx]
    xor     edx, edx
    div     dword ptr [g_sld_scale]
    ; The value can sit outside what the track can express - MinLen accepts
    ; 1..256 from policy but drags 8..32, and Memory accepts 4 GiB while the
    ; track stops at 2 - so clamp the POSITION, never the value.  Without this
    ; the knob is drawn outside the control and the fill runs past the track.
    cmp     eax, dword ptr [g_sld_min]
    jge     @F
    mov     eax, dword ptr [g_sld_min]
@@:
    cmp     eax, dword ptr [g_sld_max]
    jle     @F
    mov     eax, dword ptr [g_sld_max]
@@:
    sub     eax, dword ptr [g_sld_min]       ; cur-min
    mov     ecx, dword ptr [g_dr_x1]
    sub     ecx, dword ptr [g_dr_x0]         ; span px
    imul    ecx
    mov     ecx, dword ptr [g_sld_max]
    sub     ecx, dword ptr [g_sld_min]       ; range
    test    ecx, ecx
    jnz     @F
    mov     ecx, 1
@@:
    cdq
    idiv    ecx
    add     eax, dword ptr [g_dr_x0]
    mov     dword ptr [g_dr_thumb], eax
    ; track (grey)
    mov     dword ptr [g_dr_rc+0], 0
    mov     eax, dword ptr [g_dr_x0]
    mov     dword ptr [g_dr_rc+0], eax
    mov     eax, dword ptr [g_dr_cy]
    sub     eax, 2
    mov     dword ptr [g_dr_rc+4], eax
    mov     eax, dword ptr [g_dr_x1]
    mov     dword ptr [g_dr_rc+8], eax
    mov     eax, dword ptr [g_dr_cy]
    add     eax, 2
    mov     dword ptr [g_dr_rc+12], eax
    WINCALL CreateSolidBrush, CLR_TRACK
    mov     qword ptr [g_dr_br], rax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_dr_rc, qword ptr [g_dr_br]
    WINCALL DeleteObject, qword ptr [g_dr_br]
    ; filled portion (accent, grey if disabled) x0..thumb
    mov     eax, dword ptr [g_dr_thumb]
    mov     dword ptr [g_dr_rc+8], eax
    mov     edx, CLR_ACCENT
    cmp     dword ptr [g_dr_dis], 0
    je      @F
    mov     edx, CLR_HINT
@@:
    WINCALL CreateSolidBrush, edx
    mov     qword ptr [g_dr_br], rax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_dr_rc, qword ptr [g_dr_br]
    WINCALL DeleteObject, qword ptr [g_dr_br]
    ; thumb (white circle)
    mov     eax, dword ptr [g_dr_thumb]
    call    dr_knob
    add     rsp, 64
    pop     rbp
    ret
draw_slider endp

; subclass_slider(rcx = slider hwnd) - install slider_subclass, cache the
; original STATIC proc once.
subclass_slider proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    WINCALL SetWindowLongPtrW, rcx, GWLP_WNDPROC, addr slider_subclass
    mov     qword ptr [g_oldsliderproc], rax
    add     rsp, 48
    pop     rbp
    ret
subclass_slider endp

; slider_apply(rcx = hwnd, edx = mouse x) - set this slider's value from x,
; snapping to its integer stops; persist, repaint, re-validate.
slider_apply proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     dword ptr [rbp-12], edx
    WINCALL GetDlgCtrlID, qword ptr [rbp-8]
    mov     ecx, eax
    call    slider_desc
    ; client width
    WINCALL GetClientRect, qword ptr [rbp-8], addr g_dr_rc
    mov     eax, dword ptr [g_dr_rc+8]       ; width
    sub     eax, 20                          ; track span (x0=10, x1=w-10)
    mov     dword ptr [rbp-16], eax          ; span
    ; rel = clamp(x-10, 0, span)
    mov     eax, dword ptr [rbp-12]
    sub     eax, 10
    jns     @F
    xor     eax, eax
@@:
    cmp     eax, dword ptr [rbp-16]
    jle     @F
    mov     eax, dword ptr [rbp-16]
@@:
    ; value = min + round(rel*range/span)
    mov     ecx, dword ptr [g_sld_max]
    sub     ecx, dword ptr [g_sld_min]       ; range
    imul    ecx                              ; eax = rel*range
    mov     ecx, dword ptr [rbp-16]
    test    ecx, ecx
    jnz     @F
    mov     ecx, 1
@@:
    ; round: add span/2 before dividing
    mov     edx, ecx
    sar     edx, 1
    add     eax, edx
    cdq
    idiv    ecx
    add     eax, dword ptr [g_sld_min]       ; new value
    ; Snap to the row's step BEFORE the clamp, so rounding up near either end
    ; cannot land outside the range - 2000 MiB rounds to 2048, which is the max
    ; rather than past it, and anything under 64 rounds to 0 and is pulled back
    ; up to the 8 MiB floor.  That floor is why 8 stays reachable at the far
    ; left even though it is not a multiple of the step.
    mov     ecx, dword ptr [g_sld_step]
    cmp     ecx, 1
    jbe     @F                               ; every integer is a stop
    mov     r10d, ecx
    shr     r10d, 1
    add     eax, r10d                        ; round to nearest, not down
    xor     edx, edx
    div     ecx
    mul     ecx
@@:
    ; clamp to [min,max]
    cmp     eax, dword ptr [g_sld_min]
    jge     @F
    mov     eax, dword ptr [g_sld_min]
@@:
    cmp     eax, dword ptr [g_sld_max]
    jle     @F
    mov     eax, dword ptr [g_sld_max]
@@:
    ; back into the stored unit.  Everything below - the change test, the global
    ; and the registry - is in that unit, so this must happen before the compare
    ; or a 1-MiB drag would look like no change at all.
    imul    eax, dword ptr [g_sld_scale]
    ; changed?
    mov     rcx, qword ptr [g_sld_valptr]
    cmp     eax, dword ptr [rcx]
    je      sa_ret
    mov     dword ptr [rcx], eax
    ; persist
    mov     rcx, qword ptr [g_sld_keyptr]
    mov     rax, qword ptr [g_sld_valptr]
    mov     edx, dword ptr [rax]
    call    save_setting
    WINCALL InvalidateRect, qword ptr [rbp-8], 0, 1
    ; password sliders affect the live validation
    call    update_strength
sa_ret:
    add     rsp, 64
    pop     rbp
    ret
slider_apply endp

; slider_subclass(rcx=hwnd, rdx=msg, r8=wParam, r9=lParam) - click + drag.
slider_subclass proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    cmp     rdx, WM_NCHITTEST
    je      ssub_hit                     ; claim the hit so clicks don't drag the window
    cmp     rdx, WM_LBUTTONDOWN
    je      ssub_down
    cmp     rdx, WM_MOUSEMOVE
    je      ssub_move
    cmp     rdx, WM_LBUTTONUP
    je      ssub_up
    jmp     ssub_pass
ssub_hit:
    mov     rax, HTCLIENT
    add     rsp, 64
    pop     rbp
    ret
ssub_down:
    WINCALL SetCapture, qword ptr [rbp-8]
    mov     rcx, qword ptr [rbp-8]
    movsx   edx, word ptr [rbp-32]           ; LOWORD(lParam) = x
    call    slider_apply
    jmp     ssub_zero
ssub_move:
    test    dword ptr [rbp-24], MK_LBUTTON   ; only while the button is held
    jz      ssub_pass
    WINCALL GetCapture
    cmp     rax, qword ptr [rbp-8]
    jne     ssub_pass
    mov     rcx, qword ptr [rbp-8]
    movsx   edx, word ptr [rbp-32]
    call    slider_apply
    jmp     ssub_zero
ssub_up:
    WINCALL GetCapture
    cmp     rax, qword ptr [rbp-8]
    jne     ssub_pass
    WINCALL ReleaseCapture
ssub_zero:
    xor     rax, rax
    add     rsp, 64
    pop     rbp
    ret
ssub_pass:
    WINCALL CallWindowProcW, qword ptr [g_oldsliderproc], qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    add     rsp, 64
    pop     rbp
    ret
slider_subclass endp

; =============================================================================
; menu_wndproc - the settings host's window procedure.
;
; It owns no behaviour.  Everything the panel's controls raise - WM_DRAWITEM for
; the owner-drawn toggles, sliders and headers, WM_COMMAND for the clicks - is
; forwarded to the MAIN window proc, which already has a handler for every one
; of those ids.  Re-parenting the controls would otherwise have meant moving
; those handlers too, and Vordr's settings migration (docs/SETTINGS_DESIGN.md
; there, section 7) records what that costs: ten calls left aimed at the window
; the control used to be in, all of which Win32 fails SILENTLY.  Forwarding
; means there is nothing to re-aim.
;
; The background is the CLASS BRUSH, so DefWindowProc erases it and the window
; is opaque on its own.  The first version answered WM_ERASEBKGND with 1 and
; left the painting to an owner-draw backdrop child; that child never drew, the
; host stayed fully transparent, and the breadcrumb and file rows behind it
; showed through a panel that the z-order dump proved was on top.  A window that
; occludes has to actually paint.
; =============================================================================
; =============================================================================
; raise_window(rcx = hwnd) - move it to the top of the sibling z-order without
; moving, sizing or activating it.
;
; A proc rather than the call open-coded at each site: SetWindowPos takes SEVEN
; arguments, so its outgoing area is 56 bytes, and both callers had frames too
; small for that - framecheck caught it as a return-address smash the moment it
; was written.  One frame, sized once.
; =============================================================================
raise_window proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    ; HWND_TOP, NOSIZE|NOMOVE|NOACTIVATE
    WINCALL SetWindowPos, rcx, 0, 0, 0, 0, 0, 013h
    add     rsp, 96
    pop     rbp
    ret
raise_window endp

menu_wndproc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx          ; hwnd
    mov     qword ptr [rbp-16], rdx         ; msg
    mov     qword ptr [rbp-24], r8          ; wparam
    mov     qword ptr [rbp-32], r9          ; lparam
    mov     eax, edx
    cmp     eax, WM_ERASEBKGND
    je      mwp_erase
    cmp     eax, WM_DRAWITEM
    je      mwp_fwd
    cmp     eax, WM_COMMAND
    je      mwp_fwd
    cmp     eax, WM_CTLCOLORSTATIC
    je      mwp_fwd
    cmp     eax, WM_NOTIFY
    je      mwp_fwd
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    jmp     mwp_ret
mwp_erase:
    ; The panel paints its own background so it can have an EDGE.  The class
    ; brush filled it flat, which is why it read as a hole cut in the window
    ; rather than a surface laid over it - nothing said where it stopped except
    ; the controls happening to end.
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, qword ptr [rbp-24]              ; wParam = the HDC
    call    draw_settings_bg
    mov     eax, 1                               ; erased; do not let DefWindowProc
    jmp     mwp_ret
mwp_fwd:
    WINCALL SendMessageW, qword ptr [g_hwnd], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
mwp_ret:
    add     rsp, 64
    pop     rbp
    ret
menu_wndproc endp

; =============================================================================
; draw_settings_bg(rcx = panel hwnd, rdx = hdc) - the panel's surface and edge.
;
; The panel paints its own background so it can have an EDGE.  The class brush
; filled it flat, which is why an open panel read as a hole cut in the window
; rather than a surface laid over it: nothing said where it stopped except the
; controls happening to end.
;
; Four looks were built and compared in the running program - flat, framed, a
; rounded card, and framed with a box behind each column - with a cycle button in
; the command bar to switch between them.  Framed won, and the other three and
; the button are gone: an unreachable variant is not a choice, it is three code
; paths nothing can enter.  They are in the history if the question reopens
; (CHANGES 1.0.66 says which commit).
; =============================================================================
draw_settings_bg proc frame
    FRAME_PROLOG 96
    ; Locals start at [rbp-16].  [rbp-8] is the STACK CANARY that FRAME_PROLOG
    ; plants and FRAME_EPILOG checks, so a local there overwrites it and the
    ; proc fastfails on its own return - which is exactly what the first draft
    ; of this did, and it took a bisect to see because the symptom is the whole
    ; process vanishing the moment the panel is opened.
    mov     qword ptr [rbp-16], rcx              ; hwnd
    mov     qword ptr [rbp-24], rdx              ; hdc
    WINCALL GetClientRect, qword ptr [rbp-16], addr rbp-48
    WINCALL CreateSolidBrush, CLR_MENU_BG
    mov     qword ptr [rbp-56], rax
    WINCALL FillRect, qword ptr [rbp-24], addr rbp-48, qword ptr [rbp-56]
    WINCALL DeleteObject, qword ptr [rbp-56]
    WINCALL CreateSolidBrush, CLR_MENU_EDGE
    mov     qword ptr [rbp-56], rax
    WINCALL FrameRect, qword ptr [rbp-24], addr rbp-48, qword ptr [rbp-56]
    WINCALL DeleteObject, qword ptr [rbp-56]
    xor     eax, eax
    FRAME_EPILOG
    ret
draw_settings_bg endp


; =============================================================================
; toggle_menu - hamburger click: show/hide the settings panel over the listview.
;
; ONE window, shown and RAISED in a single call.  The raise is the whole reason
; this had to become a window: the listview sits ABOVE the panel in z-order -
; measured by walking the child list at runtime, not assumed - so "created
; later" does not put the panel in front, and the rows painted straight over it.
; Raising nine loose controls would have meant nine calls in the right relative
; order, re-checked every time a setting is added.
; =============================================================================
toggle_menu proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     eax, dword ptr [g_menu_open]
    xor     eax, 1
    mov     dword ptr [g_menu_open], eax
    test    eax, eax
    jz      tm_hide
    WINCALL ShowWindow, qword ptr [g_hmenuhost], SW_SHOW
    mov     rcx, qword ptr [g_hmenuhost]
    call    raise_window
    jmp     tm_flyout
tm_hide:
    WINCALL ShowWindow, qword ptr [g_hmenuhost], SW_HIDE
tm_flyout:
    ; the class explanation never survives a toggle either way
    WINCALL ShowWindow, qword ptr [g_hpwflyout], SW_HIDE
    add     rsp, 48
    pop     rbp
    ret
toggle_menu endp



; =============================================================================
; save_setting(rcx = value-name wide, edx = DWORD value) - write to
; HKCU\Software\Myrkr (created if needed).  Best effort.
; =============================================================================
save_setting proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     qword ptr [rbp-8], rcx       ; value name
    mov     dword ptr [g_regval], edx    ; value
    mov     ecx, HKEY_CURRENT_USER
    WINCALL RegCreateKeyExW, rcx, addr w_regkey, 0, 0, 0, KEY_WRITE, 0, \
            addr rbp-16, addr rbp-24
    test    eax, eax
    jnz     ss_done
    WINCALL RegSetValueExW, qword ptr [rbp-16], qword ptr [rbp-8], 0, \
            REG_DWORD_, addr g_regval, 4
    WINCALL RegCloseKey, qword ptr [rbp-16]
ss_done:
    add     rsp, 96
    pop     rbp
    ret
save_setting endp

; =============================================================================
; ls_read(rcx = value-name wide) -> eax = 1 if the DWORD was read into g_regval.
; Reads from the key opened in g_reghk.
; =============================================================================
ls_read proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     dword ptr [g_regsz], 4
    WINCALL RegQueryValueExW, qword ptr [g_reghk], rcx, 0, 0, addr g_regval, addr g_regsz
    test    eax, eax
    jnz     lr_no
    mov     eax, 1
    add     rsp, 64
    pop     rbp
    ret
lr_no:
    xor     eax, eax
    add     rsp, 64
    pop     rbp
    ret
ls_read endp

; =============================================================================
; load_settings(rcx = root HKEY) - read Compress/Format/LogLevel/MinLen/
; MinClasses from <root>\Software\Myrkr.  Called twice from wstart: HKCU before
; parse_cmdline (so CLI flags override it) and HKLM after (so it overrides CLI
; and HKCU).  While g_loading_hklm is set, each present value also locks the
; matching GUI control so the user cannot weaken an admin-enforced policy.
; =============================================================================
public load_settings
load_settings proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80
    ; rdx names the SUBKEY, because two of them under HKLM mean opposite things:
    ; Software\Myrkr is POLICY and locks what it sets, Software\Myrkr\Defaults is
    ; a deployed starting value the user may still change.  [rbp-32] is clear of
    ; both the locals below and the outgoing arguments of the five-argument call
    ; that follows.
    mov     qword ptr [rbp-32], rdx
    WINCALL RegOpenKeyExW, rcx, qword ptr [rbp-32], 0, KEY_READ, addr g_reghk
    test    eax, eax
    jnz     ls_done                      ; key absent -> nothing to apply
    mov     qword ptr [rbp-8], 0         ; row index
ls_row:
    mov     rax, qword ptr [rbp-8]
    cmp     rax, SETROW_COUNT
    jae     ls_close
    imul    rax, rax, SETROW_SIZE
    lea     r10, [g_setrows]
    add     r10, rax
    mov     qword ptr [rbp-16], r10
    mov     rcx, qword ptr [r10+sr_name]
    call    ls_read
    test    eax, eax
    jz      ls_next                      ; absent: every LATER row still runs
    mov     r10, qword ptr [rbp-16]      ; ls_read clobbered it
    mov     eax, dword ptr [g_regval]
    cmp     dword ptr [r10+sr_bool], 0
    je      ls_range
    test    eax, eax                     ; 0/1: anything nonzero is on
    jz      ls_store
    mov     eax, 1
    jmp     ls_store
ls_range:
    cmp     eax, dword ptr [r10+sr_min]
    jb      ls_next                      ; out of range: ignored, not fatal
    cmp     eax, dword ptr [r10+sr_max]
    ja      ls_next
ls_store:
    mov     dword ptr [rbp-24], eax
    mov     rcx, qword ptr [r10+sr_val]
    mov     dword ptr [rcx], eax
    mov     rcx, qword ptr [r10+sr_val2]
    test    rcx, rcx
    jz      @F
    mov     dword ptr [rcx], eax
@@:
    mov     rcx, qword ptr [r10+sr_seen]
    test    rcx, rcx
    jz      @F
    mov     dword ptr [rcx], 1
@@:
    mov     rcx, qword ptr [r10+sr_seen2]
    test    rcx, rcx
    jz      @F
    mov     dword ptr [rcx], 1
@@:
    ; HKLM only: lock the control and record what policy said
    cmp     dword ptr [g_loading_hklm], 0
    je      ls_next
    mov     rcx, qword ptr [r10+sr_lock]
    test    rcx, rcx
    jz      @F
    mov     dword ptr [rcx], 1
@@:
    mov     rcx, qword ptr [r10+sr_pol]
    test    rcx, rcx
    jz      ls_next
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [rcx], eax
ls_next:
    inc     qword ptr [rbp-8]
    jmp     ls_row
ls_close:
    ; Hand-written, and staying that way: this is not a setting, it is a
    ; DEBUG-ONLY escape from one.  A table row implies "read a value, store it",
    ; and this reads an ENVIRONMENT variable to move the prompt to another
    ; desktop.  Vordr keeps its TPM enrolment out of the table for the same
    ; reason - a row should not imply a side effect.
    ; Condition preserved from the chain it replaces: HKLM pass, SecureDesktop
    ; present (which is exactly what set g_lock_securedesk).
ifdef DBG_TRACE
    cmp     dword ptr [g_loading_hklm], 0
    je      ls_regclose
    cmp     dword ptr [g_lock_securedesk], 0
    je      ls_regclose
    ; DEBUG BUILDS ONLY - work on the prompt's own UI without a second desktop.
    ; MYRKR_DBG_NOSECDESK=1 keeps the prompt on the interactive desktop so it can
    ; be screenshotted and driven; the window is identical either way, only the
    ; desktop it lives on differs.  This is a deliberate hole and is why it is
    ; inside DBG_TRACE: a release binary has no way to reach it, and a build that
    ; did would defeat the control it exists to develop.  See manifest 11.1.
    WINCALL GetEnvironmentVariableW, addr w_dbg_nosd, addr g_dbg_sdbuf, 8
    test    eax, eax
    jz      ls_regclose
    cmp     word ptr [g_dbg_sdbuf], '1'
    jne     ls_regclose
    ; Move the prompt to the interactive desktop WITHOUT clearing
    ; g_cfg_securedesk.  Clearing it would also switch off everything else the
    ; setting governs - notably the dialog's own password row - so the thing
    ; under test would no longer be the thing that ships.
    mov     dword ptr [g_dbg_nodesk], 1
endif
ls_regclose:
    WINCALL RegCloseKey, qword ptr [g_reghk]
ls_done:
    add     rsp, 80
    pop     rbp
    ret
load_settings endp

; =============================================================================
; apply_policy_locks - re-assert every HKLM-enforced value over whatever the CLI
; option parser just wrote.  Call AFTER collect_options and before the command
; handler runs (dispatch, main.asm).
;
; wstart loads HKLM after parse_cmdline, which reads as though policy already
; wins - but parse_cmdline only tokenizes.  The options are parsed later, inside
; dispatch, so `--min-len 4` and `--no-policy` were applied after the policy
; value and overrode it: an HKLM MinLen=16 was bypassable from a shell while the
; GUI dutifully greyed the control out.  The lock flags reached one front-end
; and not the other.
;
; Format is not re-asserted: it selects the GUI's output format and has no CLI
; flag, so there is nothing for a command line to override.
;
; The three graded settings are a FLOOR, not a pin: policy wins only where the
; command line is weaker.  An admin's MinLen=16 is a minimum, so `--min-len 24`
; must still be honoured - pinning the value exactly would have refused a user
; who asked to be stricter than required, which is not what a minimum means.
; Compress is pinned instead: it is not a graded control and "stricter" has no
; meaning for it.
; =============================================================================
public apply_policy_locks
apply_policy_locks proc
    cmp     dword ptr [g_lock_minlen], 0
    je      @F
    mov     eax, dword ptr [g_pol_minlen]
    cmp     eax, dword ptr [g_cfg_pwminlen]
    jbe     @F                                  ; CLI is already stricter: keep it
    mov     dword ptr [g_cfg_pwminlen], eax
@@:
    cmp     dword ptr [g_lock_minclasses], 0
    je      @F
    mov     eax, dword ptr [g_pol_minclasses]
    cmp     eax, dword ptr [g_cfg_pwminclasses]
    jbe     @F
    mov     dword ptr [g_cfg_pwminclasses], eax
@@:
    cmp     dword ptr [g_lock_loglevel], 0
    je      @F
    mov     eax, dword ptr [g_pol_loglevel]
    cmp     eax, dword ptr [g_cfg_loglevel]
    jbe     @F                                  ; more logging than required: fine
    mov     dword ptr [g_cfg_loglevel], eax
@@:
    cmp     dword ptr [g_lock_compress], 0
    je      @F
    mov     eax, dword ptr [g_pol_compress]
    mov     dword ptr [g_cfg_compress], eax
    mov     dword ptr [g_cfg_compress_set], 1   ; beat the size-based default too
@@:
    ; KDF cost is a FLOOR, like the password rules and for the same reason: an
    ; administrator's value is a minimum amount of work, so --kdf-time 8 over a
    ; policy of 4 must stand.  Pinning would have refused a user asking to be
    ; more expensive than required, which is not what a minimum means.
    cmp     dword ptr [g_lock_kdftime], 0
    je      @F
    mov     eax, dword ptr [g_pol_kdftime]
    cmp     eax, dword ptr [g_cfg_t]
    jbe     @F
    mov     dword ptr [g_cfg_t], eax
@@:
    cmp     dword ptr [g_lock_kdfmem], 0
    je      @F
    mov     eax, dword ptr [g_pol_kdfmem]
    cmp     eax, dword ptr [g_cfg_m]
    jbe     @F
    mov     dword ptr [g_cfg_m], eax
@@:
    ; SecureDesktop is pinned exactly, not floored: an administrator who sets it
    ; to 0 is deliberately accepting the cost, and one who sets it to 1 must not
    ; be overridable downward.  There is no CLI flag for it, so this only guards
    ; against a future one.  It is also now a control the user can reach, which
    ; is what makes the pin do real work rather than guard a hypothetical.
    cmp     dword ptr [g_lock_securedesk], 0
    je      @F
    mov     eax, dword ptr [g_pol_securedesk]
    mov     dword ptr [g_cfg_securedesk], eax
@@:
    ret
apply_policy_locks endp

; =============================================================================
; ends_with_agcm(rcx = wide path) -> eax = 1 if it ends in ".mrk" (any case)
; =============================================================================
ends_with_agcm proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-8], rcx
    call    wlen
    cmp     rax, 4
    jb      ewa_no
    mov     r10, qword ptr [rbp-8]
    lea     r10, [r10+rax*2-8]           ; -> path[len-4]
    lea     r8, [s_ext_agcm]
    xor     r9, r9
ewa_cmp:
    movzx   eax, word ptr [r10+r9*2]
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
    jne     ewa_no
    inc     r9
    cmp     r9, 4
    jb      ewa_cmp
    mov     eax, 1
    jmp     ewa_done
ewa_no:
    xor     eax, eax
ewa_done:
    add     rsp, 48
    pop     rbp
    ret
ends_with_agcm endp

; ends_with_zip(rcx = wide path) -> eax = 1 if it ends in ".zip" (any case)
ends_with_zip proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-8], rcx
    call    wlen
    cmp     rax, 4
    jb      ewz_no
    mov     r10, qword ptr [rbp-8]
    lea     r10, [r10+rax*2-8]
    lea     r8, [s_ext_zip]
    xor     r9, r9
ewz_cmp:
    movzx   eax, word ptr [r10+r9*2]
    movzx   edx, word ptr [r8+r9*2]
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 20h
@@:
    cmp     eax, edx
    jne     ewz_no
    inc     r9
    cmp     r9, 4
    jb      ewz_cmp
    mov     eax, 1
    jmp     ewz_done
ewz_no:
    xor     eax, eax
ewz_done:
    add     rsp, 48
    pop     rbp
    ret
ends_with_zip endp

; =============================================================================
; detect_op - classify the inputs into g_op (0 = encrypt, 1 = decrypt).
; Decrypt iff exactly one input that ends in ".mrk" AND carries the container
; header magic.  Also records g_is_archive from header byte 17.
; =============================================================================
detect_op proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80
    mov     dword ptr [g_op], 0          ; default encrypt
    mov     dword ptr [g_container], 0
    mov     dword ptr [g_is_archive], 0
    mov     dword ptr [g_is_zip], 0
    mov     dword ptr [g_zip_enc], 1     ; safe default: assume a password is needed
    cmp     qword ptr [g_poscount], 1
    jne     do_done
    ; extension test
    lea     rcx, [g_filepath_w]
    call    ends_with_agcm
    test    eax, eax
    jz      do_checkzip
    ; Header test, THROUGH THE VOLUME LAYER.  This used to be a raw ReadFile of
    ; the first 32 bytes, which is wrong for a volume set twice over: part 1
    ; begins with the 32-byte MVOL header rather than MYRK, and any later part
    ; begins in the middle of the ciphertext.  Either way the magic did not
    ; match, so a .part001.mrk was classified as something to ENCRYPT - the
    ; window offered to encrypt the container it had been asked to open.
    ;
    ; vset_open assembles the set and vol_get addresses the logical stream, so
    ; offset 0 is the container header whichever member was double-clicked. For
    ; an ordinary .mrk it is file_open_read and a read, exactly as before.
    ;
    ; Third instance of the same mistake, after peek_archive and do_unpack's
    ; entry loop.  docs/VOLUMES.md section 8 says every path that opens a
    ; container has to go through the layer; this one was missed anyway because
    ; it does not look like a container reader - it is a classifier.
    lea     rcx, [g_filepath_w]
    call    vset_open
    cmp     rax, INVALID_HVAL
    je      do_done
    mov     qword ptr [rbp-8], rax       ; handle (or part 1's)
    mov     rcx, rax
    xor     rdx, rdx
    lea     r8, [g_hdrbuf]
    mov     r9, 32
    call    vol_get
    mov     dword ptr [rbp-16], eax      ; 0 = the 32 bytes are there
    mov     rcx, qword ptr [rbp-8]
    call    vset_close
    cmp     dword ptr [rbp-16], 0
    jne     do_done
    mov     eax, dword ptr [g_hdrbuf]
    cmp     eax, HDR_MAGIC
    jne     do_done
    mov     dword ptr [g_op], 1          ; decrypt
    mov     dword ptr [g_container], 1   ; ... and it can be browsed, not just run
    movzx   eax, byte ptr [g_hdrbuf+17]  ; archive flag
    cmp     eax, 1
    jne     do_done
    mov     dword ptr [g_is_archive], 1
    jmp     do_done
do_checkzip:
    ; not a .mrk container - is it a .zip with the local-file signature?
    lea     rcx, [g_filepath_w]
    call    ends_with_zip
    test    eax, eax
    jz      do_done
    WINCALL CreateFileW, addr g_filepath_w, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0
    cmp     rax, INVALID_HVAL
    je      do_done
    mov     qword ptr [rbp-8], rax
    mov     dword ptr [rbp-16], 0
    WINCALL ReadFile, qword ptr [rbp-8], addr g_hdrbuf, 4, addr rbp-16, 0
    WINCALL CloseHandle, qword ptr [rbp-8]
    cmp     dword ptr [rbp-16], 4
    jb      do_done
    cmp     dword ptr [g_hdrbuf], 04034B50h    ; "PK\3\4" local file header
    jne     do_done
    mov     dword ptr [g_op], 1          ; extract
    mov     dword ptr [g_is_zip], 1
    mov     dword ptr [g_is_archive], 1  ; extracts into a folder
    ; A zip OPENS the same way a .mrk does - it is browsed, and extracting is
    ; the button pressed next.  Handing one to Myrkr used to start the extract
    ; immediately, so the contents were on disk before anyone had seen what they
    ; were; the same reasoning that stopped a .mrk extracting itself applies
    ; here, and there is no reason for the two to behave differently.
    mov     dword ptr [g_container], 1
    ; probe whether the archive is actually encrypted; only then need a password
    lea     rcx, [g_filepath_w]
    call    zip_is_encrypted
    test    eax, eax                     ; 0 = no encrypted entries
    jnz     do_done                      ; 1 (encrypted) or -1 (unknown) -> keep default
    mov     dword ptr [g_zip_enc], 0
do_done:
    ; ---- a RIGHT-DRAG acts, it does not browse ------------------------------
    ; --to is only ever passed by the shell extension when there is a drop
    ; target, which means a right-drag and nothing else - a plain right-click
    ; and a double-click never carry it.  So it is already the discriminator
    ; and no new flag is needed.
    ;
    ; A container handed over that way goes straight to its operation instead
    ; of opening the browser.  The reasoning that made browsing the default is
    ; NOT being reversed: a double-click still shows you what is inside before
    ; anything is written, because that gesture says "look at this".  Dragging
    ; a container onto a folder says where the contents should go, which is
    ; already the decision browsing exists to let you make.
    ;
    ; Nothing is decrypted without the password either way - this chooses which
    ; screen the window opens on, not whether it asks.
    cmp     dword ptr [g_have_dest], 0
    je      do_ret
    mov     dword ptr [g_container], 0
do_ret:
    add     rsp, 80
    pop     rbp
    ret
detect_op endp

; =============================================================================
; build_output - g_outpath_w from g_filepath_w according to g_op
;   encrypt: out = in + ".mrk"
;   decrypt: strip a trailing ".mrk" (else append ".dec")
; =============================================================================
build_output proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    cmp     dword ptr [g_op], 0
    jne     bo_dec
    lea     rcx, [g_outpath_w]
    lea     rdx, [g_filepath_w]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy                        ; rax -> NUL of copy
    mov     rcx, rax
    lea     rdx, [s_ext_agcm]
    cmp     dword ptr [g_make_zip], 0    ; zip output -> ".zip" instead of ".mrk"
    je      @F
    lea     rdx, [s_ext_zip]
@@:
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
    jmp     bo_done
bo_dec:
    ; An archive (.mrk with the archive flag, or a .zip) already carries its own
    ; top-level folder inside the tar, so the destination is the folder to
    ; extract INTO - the container's own directory - not a fresh folder named
    ; after the container.  Naming one produced test\Code\Code\... : the tar's
    ; Code/ nested inside a Code/ the GUI had invented.  A single-FILE container
    ; still needs a filename, so it keeps the .mrk-stripping path below.
    mov     eax, dword ptr [g_is_archive]
    or      eax, dword ptr [g_is_zip]
    jz      bo_dec_file
    lea     rcx, [g_outpath_w]
    lea     rdx, [g_filepath_w]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
    lea     rcx, [g_outpath_w]
    call    wfindbase                    ; rax -> the basename within the copy
    lea     rdx, [g_outpath_w]
    cmp     rax, rdx
    jbe     bo_dec_file                  ; no directory part: fall back
    mov     word ptr [rax-2], 0          ; cut the trailing '\' -> parent folder
    jmp     bo_done
bo_dec_file:
    lea     rcx, [g_filepath_w]
    call    wlen                         ; rax = len
    mov     r10, rax
    cmp     r10, 4
    jb      bo_dec_append
    lea     r11, [g_filepath_w]
    lea     r11, [r11+r10*2-8]
    lea     r8, [s_ext_agcm]
    cmp     dword ptr [g_is_zip], 0      ; zip extract -> strip ".zip" instead
    je      @F
    lea     r8, [s_ext_zip]
@@:
    xor     r9, r9
bo_cmp:
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
    jne     bo_dec_append
    inc     r9
    cmp     r9, 4
    jb      bo_cmp
    ; matched ".mrk": copy in[0..len-4]
    mov     r8, r10
    sub     r8, 4
    ; ...and a ".partNNN" in front of it.  THIS is the path a right-drag takes,
    ; and fixing only cmd.asm's copy of the rule left it still writing
    ; boot.wim.part001 - reported after that fix shipped.  One rule, one place.
    lea     rcx, [g_filepath_w]
    mov     rdx, r8
    call    vol_part_suffix
    mov     r8, rax
    lea     rcx, [g_outpath_w]
    lea     rdx, [g_filepath_w]
    xor     r9, r9
bo_copy:
    cmp     r9, r8
    jae     bo_copydone
    mov     ax, word ptr [rdx+r9*2]
    mov     word ptr [rcx+r9*2], ax
    inc     r9
    jmp     bo_copy
bo_copydone:
    mov     word ptr [rcx+r9*2], 0
    jmp     bo_done
bo_dec_append:
    lea     rcx, [g_outpath_w]
    lea     rdx, [g_filepath_w]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
    mov     rcx, rax
    lea     rdx, [s_ext_dec]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
bo_done:
    ; --to: keep the name build_output just decided and only change the folder
    ; it lives in.  Re-rooting at the end means encrypt and decrypt, file and
    ; archive, all inherit it without each deriving a destination of its own.
    cmp     dword ptr [g_have_dest], 0
    je      bo_ret
    ; Two shapes come out of build_output and --to has to treat them
    ; differently.  An ARCHIVE decrypt yields a FOLDER to extract into, with no
    ; filename part at all (see bo_dec above) - so the drop target replaces it
    ; outright.  Appending a basename there produced <drop>\<drop's own name>,
    ; which is why decrypt silently produced nothing.
    cmp     dword ptr [g_op], 0
    je      bo_reroot                            ; encrypt: always a file name
    mov     eax, dword ptr [g_is_archive]
    or      eax, dword ptr [g_is_zip]
    jz      bo_reroot                            ; single-file decrypt: a name
    lea     rcx, [g_outpath_w]
    lea     rdx, [g_argdest]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
    jmp     bo_ret
bo_reroot:
    lea     rcx, [g_outpath_w]
    call    wfindbase                            ; rax -> basename within it
    lea     rcx, [g_tmpbase]
    mov     rdx, rax
    WBOUND  r8, g_tmpbase, 1100
    call    wcopy
    lea     rcx, [g_outpath_w]
    lea     rdx, [g_argdest]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
    mov     rcx, rax                             ; rax = end of the copy
    lea     rdx, [s_bslash]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
    mov     rcx, rax
    lea     rdx, [g_tmpbase]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
bo_ret:
    add     rsp, 48
    pop     rbp
    ret
build_output endp

; =============================================================================
; do_change_dest - folder picker; recombine chosen folder with the current
; destination's basename and update the dest edit (DECRYPT mode).
; =============================================================================
; do_change_dest - pick a destination folder with the modern common-item
; dialog (IFileOpenDialog + FOS_PICKFOLDERS), replacing the legacy
; SHBrowseForFolder tree.  The original file's basename is preserved and
; re-appended to the folder the user chooses.
;
; Locals (128-byte frame keeps [rsp+0..40) free for outgoing shadow/args):
;   [rbp-8]  pfd      IFileOpenDialog*
;   [rbp-16] psi      IShellItem*
;   [rbp-24] pszPath  fs path from GetDisplayName (CoTaskMem)
;   [rbp-32] opts     dialog options (DWORD)
do_change_dest proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    mov     qword ptr [rbp-8], 0
    mov     qword ptr [rbp-16], 0
    ; current destination -> g_outpath_w, isolate basename into g_basebuf
    WINCALL GetWindowTextW, qword ptr [g_hdest], addr g_outpath_w, 8000h
    lea     rcx, [g_outpath_w]
    call    wfindbase                    ; rax -> basename
    lea     rcx, [g_basebuf]
    mov     rdx, rax
    WBOUND  r8, g_basebuf, BASEBUF_CHARS
    call    wcopy
    ; COM apartment for this thread (balanced by CoUninitialize below)
    WINCALL CoInitializeEx, 0, COINIT_APARTMENTTHREADED
    ; CoCreateInstance(CLSID_FileOpenDialog, NULL, INPROC, IID_IFileOpenDialog, &pfd)
    lea     rax, [rbp-8]
    WINCALL CoCreateInstance, addr clsid_fileopen, 0, CLSCTX_INPROC_SERVER, addr iid_ifileopen, rax
    test    eax, eax
    jnz     dcd_uninit
    ; opts |= FOS_PICKFOLDERS
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [rbp-32]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_GetOptions]
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [rbp-32]
    or      edx, FOS_PICKFOLDERS
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_SetOptions]
    ; SetTitle
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [t_browse]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_SetTitle]
    ; Show(hwnd) - nonzero HRESULT means cancelled/failed
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, qword ptr [g_hwnd]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Show]
    test    eax, eax
    jnz     dcd_release
    ; GetResult(&psi)
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [rbp-16]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_GetResult]
    test    eax, eax
    jnz     dcd_release
    ; psi->GetDisplayName(SIGDN_FILESYSPATH, &pszPath)
    mov     rcx, qword ptr [rbp-16]
    mov     edx, SIGDN_FILESYSPATH
    lea     r8, [rbp-24]
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_GetDisplayName]
    test    eax, eax
    jnz     dcd_relpsi
    ; new dest = folder [+ '\'] + basename, built in g_outpath_w
    lea     rcx, [g_outpath_w]
    mov     rdx, qword ptr [rbp-24]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy                        ; rax -> NUL after folder
    ; For an archive the picked folder IS the destination: the tar supplies the
    ; folder name.  Re-appending the old basename here is what turned a chosen
    ; "test" into "test\Code", which extraction then nested a second Code inside.
    ; A single-file destination is a FILENAME, so that case still recombines.
    mov     eax, dword ptr [g_is_archive]
    or      eax, dword ptr [g_is_zip]
    jnz     dcd_setdest
    lea     rdx, [g_outpath_w]
    cmp     rax, rdx                     ; non-empty?
    jbe     dcd_sep
    movzx   edx, word ptr [rax-2]
    cmp     edx, 5Ch
    je      dcd_nosep
dcd_sep:
    ; the folder came from the shell picker and the basename from the dropped
    ; path; unbounded, their sum could exceed g_outpath_w.  Only lay down the
    ; separator while a slot for it plus a terminator remains.
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    cmp     rax, r8
    jae     dcd_nosep
    mov     word ptr [rax], 5Ch
    add     rax, 2
dcd_nosep:
    mov     rcx, rax
    lea     rdx, [g_basebuf]
    WBOUND  r8, g_outpath_w, OUTPATH_CHARS
    call    wcopy
dcd_setdest:
    WINCALL SetWindowTextW, qword ptr [g_hdest], addr g_outpath_w
    WINCALL CoTaskMemFree, qword ptr [rbp-24]
dcd_relpsi:
    mov     rcx, qword ptr [rbp-16]
    test    rcx, rcx
    jz      dcd_release
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Release]   ; psi->Release()
dcd_release:
    mov     rcx, qword ptr [rbp-8]
    test    rcx, rcx
    jz      dcd_uninit
    mov     rax, qword ptr [rcx]
    call    qword ptr [rax+VT_Release]   ; pfd->Release()
dcd_uninit:
    WINCALL CoUninitialize
    add     rsp, 128
    pop     rbp
    ret
do_change_dest endp

; =============================================================================
; fmt_summary(rcx = prefix wstr) -> g_summbuf = "<prefix><g_scan_files> files,
; <fmt_size g_scan_bytes>".  Used for the live scan status and the final summary.
; =============================================================================
fmt_summary proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    ; Recomputing the count means the list has been rescanned, which is a new
    ; state - so the red left over from a failed run goes with it.  Without
    ; this the line stays red through every later change until something else
    ; runs, and starts describing a selection the failure was never about.
    mov     dword ptr [g_scan_fail], 0
    mov     qword ptr [rbp-8], rcx        ; prefix
    lea     rcx, [g_summbuf]
    mov     rdx, qword ptr [rbp-8]
    WBOUND  r8, g_summbuf, SUMMBUF_CHARS
    call    wcopy                          ; rax -> NUL after the prefix
    mov     rcx, rax
    mov     rax, qword ptr [g_scan_files]
    call    u64_to_wide                    ; rax -> past the digits
    mov     rcx, rax
    lea     rdx, [s_files_mid]
    WBOUND  r8, g_summbuf, SUMMBUF_CHARS
    call    wcopy                          ; rax -> NUL
    ; "N files, M folders, SIZE" when there are folders, exactly the two numbers
    ; Explorer's properties dialog shows, so the two can be compared without
    ; arithmetic.  Suppressed at zero, because "0 folders" on a plain list of
    ; files is noise - and the input side, which counts files only, never sets
    ; this.  (Expect a container's folder count to be ONE higher than Explorer's:
    ; the archive stores its own root folder as an entry, and Explorer is
    ; describing what is inside that folder rather than the folder itself.)
    cmp     qword ptr [g_scan_dirs], 0
    je      fs_size
    mov     rcx, rax
    mov     rax, qword ptr [g_scan_dirs]
    call    u64_to_wide
    mov     rcx, rax
    lea     rdx, [s_folders_mid]
    WBOUND  r8, g_summbuf, SUMMBUF_CHARS
    call    wcopy
fs_size:
    mov     rcx, qword ptr [g_scan_bytes]
    mov     rdx, rax
    call    fmt_size                       ; appends the size (NUL-terminated)
    add     rsp, 48
    pop     rbp
    ret
fmt_summary endp

; =============================================================================
; indexer_thread - walk every input computing its size (g_rowsize), the grand
; total (g_input_total) and the running file count/bytes (g_scan_*).  Runs OFF
; the UI thread so the window paints and stays responsive while a huge folder is
; scanned.  Posts WM_APP_INDEXED when done.  (rcx = unused thread param.)
; =============================================================================
indexer_thread proc
    ; This thread runs FRAME_PROLOG'd code, so it needs its OWN shadow stack.
    ; Sharing one with the UI thread is the race that fastfailed the process.
    call    sstk_thread_init
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [g_input_total], 0
    xor     r9, r9
it_loop:
    cmp     r9, qword ptr [g_poscount]
    jae     it_done
    mov     qword ptr [rbp-8], r9
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+r9*8]
    call    input_size                     ; rax = bytes; updates g_scan_* live
    mov     r9, qword ptr [rbp-8]
    lea     r11, [g_rowsize]
    mov     qword ptr [r11+r9*8], rax
    add     qword ptr [g_input_total], rax
    mov     r9, qword ptr [rbp-8]
    inc     r9
    jmp     it_loop
it_done:
    mov     dword ptr [g_scanning], 0
    WINCALL PostMessageW, qword ptr [g_hwnd], WM_APP_INDEXED, 0, 0
    call    sstk_thread_free                ; last: nothing framed may follow it
    xor     eax, eax
    add     rsp, 48
    pop     rbp
    ret
indexer_thread endp

; =============================================================================
; container_remove_selected - take the selected entries out of the container.
;
; Which of the two removal paths runs is the container's size, exactly as the
; rules say: under 500 MiB the container is rewritten without the entries, so
; the bytes are gone and the file shrinks; at or above it that means rewriting
; hundreds of megabytes to reclaim a fraction of them, so the user is asked, and
; the alternative is an overwrite in place with random - fast, but the space
; stays spent.  The question is only ever asked above the threshold, and the
; answer is never assumed.
;
; This runs on the UI thread, so a large overwrite will hold the window while it
; writes.  Moving it to the worker thread that encrypt and decrypt use is
; outstanding work, not a decision.
;
; locals (frame 128): row[-24] marked[-32] size[-40] name[-48] namelen[-56].
; 128 because WideCharToMultiByte takes EIGHT arguments, so its outgoing area is
; 64 bytes and has to sit below the deepest local, not through it.
; =============================================================================
; =============================================================================
; container_add(ecx = 0 files / 1 folder) - append to the archive being browsed.
;
; The picker already appends what it collects to the input slots, and slot 0 is
; g_filepath_w, which is the archive itself.  So after it runs the layout is
; exactly the one do_add and do_zip_add want: positionals[0] the archive,
; positionals[1..] the things to add.  Nothing has to be marshalled.
;
; No password prompt.  The archive was opened with one to browse it and it is
; still in g_cfg_pass; asking again for the same secret in the same session is
; how people get trained to type it into whatever asks.
;
; g_poscount is put back before returning, so a cancelled or failed add does not
; leave the picked paths sitting in the list for the next one to re-add.
;
; Runs on the UI thread, like container_remove_selected, so a large add holds the
; window.  Same outstanding work, same reason it is not fixed here.
;
; locals (frame 96): mode[-8] poscount0[-16] code[-24]
; =============================================================================
; =============================================================================
; container_add_run(rcx = g_poscount before the paths were collected)
;
; Everything an append needs once the paths are in the input slots, whichever
; surface put them there - the picker or a drop.  Both leave exactly the same
; state, which is why this is shared rather than duplicated: slot 0 is the
; archive and the rest are what to add.
; =============================================================================
; =============================================================================
; container_prefix_from_selection - choose where added files land.
;
; The rule, in one line: a selected FOLDER means "inside that folder"; a
; selected FILE means the folder that file is in; nothing selected means the
; archive root.  Selecting a file and getting its parent is the same reading
; the drop indicator will use - putting something "next to" a file means
; putting it where that file lives.
;
; FIRST selection wins.  A multi-selection has no single answer, and choosing
; one is better than refusing: the alternative is a button that sometimes does
; nothing, which is the failure mode this whole feature arc has been removing.
;
; Runs on every append, and clears the destination when there is no selection,
; so a stale prefix cannot survive into the next one.
;
; locals: [rbp-24] row  [rbp-32] path  [rbp-40] len
; =============================================================================
; -----------------------------------------------------------------------------
; cdo_rowname(rcx = row) -> eax 1 with g_dragname / [rbp-40] set, 0 on failure
;
; A row displays a Windows path; the inventory records a tar name.  Both passes
; of container_drag_out need the same conversion, and having it once is what
; keeps the count and the add looking at the same string.
;
; NOT a proc: it reads and writes the caller's [rbp-40] deliberately, because
; the length has to come back and there is exactly one caller.
; -----------------------------------------------------------------------------
cdo_rowname:
    call    row_path
    ; Staged, not passed in rax.  WideCharToMultiByte takes eight arguments, so
    ; four of them go on the outgoing area - and WINCALL emits those FIRST,
    ; using rax as its scratch.  An argument still sitting in rax is read after
    ; it has been overwritten.  framecheck caught this one.
    mov     qword ptr [rbp-48], rax
    WINCALL WideCharToMultiByte, CP_UTF8, 0, qword ptr [rbp-48], -1, addr g_dragname, DRAGNAME_BYTES, 0, 0
    test    eax, eax
    jle     cdo_rn_no
    dec     eax                             ; drop the terminator
    jz      cdo_rn_no
    cdqe
    mov     qword ptr [rbp-40], rax
    lea     r11, [g_dragname]
    xor     r9, r9
cdo_rn_sep:
    cmp     r9, qword ptr [rbp-40]
    jae     cdo_rn_yes
    cmp     byte ptr [r11+r9], 5Ch
    jne     @F
    mov     byte ptr [r11+r9], 2Fh
@@:
    inc     r9
    jmp     cdo_rn_sep
cdo_rn_yes:
    mov     eax, 1
    ret
cdo_rn_no:
    xor     eax, eax
    ret

; =============================================================================
; container_drag_out - dragging selected entries OUT of an open container.
;
; Step 3 of docs/DRAG_OUT.md, and the mirror of the drop that already works.
; LVN_BEGINDRAG says the user has started pulling rows; this builds an
; IDataObject over the entries those rows name and hands it to DoDragDrop.
; Nothing is decrypted here - the target asks for contents through
; IStream::Read, or never asks at all if the drag is abandoned.
;
; REFUSED EARLY, or not at all.  The gates are all before the drag starts,
; because once DoDragDrop is running there is nowhere to report a problem:
; IStream::Read sits inside the target's copy loop with no window to prompt
; from, and a failure there arrives as Explorer blaming the file.
;   - not a container view      -> the encrypt view has no entries to give
;   - the container is not open -> g_pw_ready.  A ZIP's listing can be read
;                                  without a password but its contents cannot,
;                                  so this gate is the one that matters for one.
;   - the key is not live       -> es_key_live, and .mrk ONLY: it tests a .mrk
;                                  header's KCV, and a zip has no such thing.
;                                  Its entries are opened from g_cfg_pass, which
;                                  the container view deliberately keeps.
;
; Both kinds of container are draggable, by different machinery: a .mrk entry
; is streamed and decrypted as the target reads it, a zip entry is run to
; completion into memory first.  docs/DRAG_OUT.md Â§7 has why they differ, and
; do_create's kind argument is where the choice is recorded.
;
; locals: [rbp-16] row [rbp-24] selected files [rbp-32] the data object
;         [rbp-40] name length [rbp-56] kind
; =============================================================================
container_drag_out proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-32], 0
    cmp     dword ptr [g_container], 0
    je      cdo_ret
    cmp     dword ptr [g_pw_ready], 0
    je      cdo_ret
    cmp     dword ptr [g_ole_ok], 0
    je      cdo_ret                         ; OleInitialize failed at startup
    mov     eax, dword ptr [g_is_zip]
    mov     dword ptr [rbp-56], eax
    test    eax, eax
    jnz     cdo_gated                       ; a zip has no KCV to check
    call    es_key_live
    test    eax, eax
    jz      cdo_ret
cdo_gated:
    ; ---- how many file rows are selected -----------------------------------
    mov     qword ptr [rbp-24], 0
    mov     qword ptr [rbp-16], 0
cdo_count:
    mov     rax, qword ptr [rbp-16]
    cmp     rax, qword ptr [g_rowcount]
    jae     cdo_counted
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMSTATE, qword ptr [rbp-16], LVIS_SELECTED
    test    eax, LVIS_SELECTED
    jz      cdo_countn
    ; A folder is however many entries lie beneath it, so the capacity has to
    ; come from the same walk that will do the adding.  Nested selections are
    ; counted twice here and de-duplicated when added, which over-estimates -
    ; the safe direction for a size.
    mov     rcx, qword ptr [rbp-16]
    call    cdo_rowname
    test    eax, eax
    jz      cdo_countn
    xor     rcx, rcx                        ; count only
    lea     rdx, [g_dragname]
    mov     r8, qword ptr [rbp-40]
    call    do_add_tree
    add     qword ptr [rbp-24], rax
cdo_countn:
    inc     qword ptr [rbp-16]
    jmp     cdo_count
cdo_counted:
    cmp     qword ptr [rbp-24], 0
    je      cdo_ret                         ; nothing draggable in the selection
    ; ---- the data object, sized to what was selected ------------------------
    ; A zip passes no key: there is none to pass, and the password it does need
    ; is already where extract_zip_entry reads it.
    lea     rcx, [g_filepath_w]
    lea     rdx, [g_key]
    cmp     dword ptr [rbp-56], 0
    je      @F
    xor     rdx, rdx
@@:
    mov     r8, qword ptr [rbp-24]
    mov     r9d, dword ptr [rbp-56]
    call    do_create
    test    rax, rax
    jz      cdo_ret
    mov     qword ptr [rbp-32], rax
    ; ---- one item per selected file row -------------------------------------
    mov     qword ptr [rbp-16], 0
cdo_add:
    mov     rax, qword ptr [rbp-16]
    cmp     rax, qword ptr [g_rowcount]
    jae     cdo_added
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMSTATE, qword ptr [rbp-16], LVIS_SELECTED
    test    eax, LVIS_SELECTED
    jz      cdo_addn
    mov     rcx, qword ptr [rbp-16]
    call    cdo_rowname
    test    eax, eax
    jz      cdo_addn
    ; A folder brings everything beneath it; a file brings itself.  Either way
    ; the names offered are relative to the selection's parent, so dragging out
    ; sub/c.txt drops c.txt while dragging sub drops sub\c.txt - see
    ; do_add_tree.  Selecting both a folder and something inside it is dropped
    ; to one copy there rather than offered twice.
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [g_dragname]
    mov     r8, qword ptr [rbp-40]
    call    do_add_tree
cdo_addn:
    inc     qword ptr [rbp-16]
    jmp     cdo_add
cdo_added:
    ; Every row could have failed to resolve, and an empty data object would
    ; start a drag that offers nothing - a cursor the user chases for no reason.
    mov     r10, qword ptr [rbp-32]
    cmp     qword ptr [r10+DO_count], 0
    je      cdo_release
    mov     rcx, r10
    call    es_drag
cdo_release:
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    call    qword ptr [rax+16]              ; IUnknown::Release
cdo_ret:
    ; ---- hand the mouse back ------------------------------------------------
    ; LVN_BEGINDRAG arrives from INSIDE the list's own tracking: it has captured
    ; the mouse and is waiting for the button to go up.  That button-up never
    ; reaches it - DoDragDrop takes the capture for the duration and consumes
    ; the release itself - so the list is left believing a drag is still in
    ; progress and swallows what comes next.  The window still has the keyboard,
    ; which is why Alt+F4 closes it while a CLICK on Exit does nothing.
    ;
    ; WM_CANCELMODE is the message that exists for exactly this: it tells a
    ; control to abandon any internal modal state and drop the capture, without
    ; the side effects of faking a button-up at some coordinate the pointer was
    ; never at (which would land a selection on whatever row is under 0,0).
    ;
    ; On EVERY path out, not just the one that dragged.  The four gates above
    ; return before DoDragDrop is ever called, and the list is in the same state
    ; for those - a refused drag left the window just as unclickable as a
    ; completed one.
    WINCALL SendMessageW, qword ptr [g_hlist], WM_CANCELMODE, 0, 0
    WINCALL GetCapture
    test    rax, rax
    jz      @F
    WINCALL ReleaseCapture
@@:
    FRAME_EPILOG
    ret
container_drag_out endp

container_prefix_from_selection proc frame
    FRAME_PROLOG 64
    mov     rcx, -1
    cmp     dword ptr [g_container], 0
    je      cps_go                          ; the encrypt view has no archive folders
    xor     r10, r10
cps_row:
    cmp     r10, qword ptr [g_rowcount]
    jae     cps_go                          ; nothing selected -> rcx is still -1
    mov     qword ptr [rbp-16], r10
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMSTATE, qword ptr [rbp-16], LVIS_SELECTED
    test    eax, LVIS_SELECTED
    jnz     cps_found
    mov     r10, qword ptr [rbp-16]
    inc     r10
    jmp     cps_row
cps_found:
    mov     rcx, qword ptr [rbp-16]
cps_go:
    call    container_prefix_from_row
    FRAME_EPILOG
    ret
container_prefix_from_selection endp

; =============================================================================
; container_prefix_from_row(rcx = row index, or -1 for the archive root)
;
; Turns a row into g_add_prefix.  Split from the selection walk above so that a
; drag can supply the row instead - which is the whole of step 3's behaviour
; change; the naming rule underneath it does not move.
;
; locals: [rbp-24] row  [rbp-32] path  [rbp-40] len
; =============================================================================
container_prefix_from_row proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [g_add_prefixlen], 0
    mov     byte ptr [g_add_prefix], 0
    cmp     qword ptr [rbp-24], 0
    jl      cpf_ret                         ; the root
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_rowcount]
    jae     cpf_ret                         ; a row that has since gone away
    mov     rcx, qword ptr [rbp-24]
    call    row_path                        ; the row's path, with '\' separators
    mov     qword ptr [rbp-32], rax
    ; ADDPFX_MAX, not the buffer size: the leaf still has to fit after this, and
    ; capping here is what lets add_prefix_copy and both name builders treat the
    ; length as already safe.
    WINCALL WideCharToMultiByte, 65001, 0, qword ptr [rbp-32], -1, addr g_add_prefix, ADDPFX_MAX, 0, 0
    test    eax, eax
    jle     cpf_none
    dec     eax                             ; drop the terminator
    cdqe
    mov     qword ptr [rbp-40], rax
    ; the row model holds Windows separators; an archive name holds '/'
    lea     r11, [g_add_prefix]
    xor     r9, r9
cpf_sep:
    cmp     r9, qword ptr [rbp-40]
    jae     cpf_sepd
    cmp     byte ptr [r11+r9], 5Ch
    jne     cpf_sepn
    mov     byte ptr [r11+r9], 2Fh
cpf_sepn:
    inc     r9
    jmp     cpf_sep
cpf_sepd:
    ; A folder keeps its whole path; a file is cut back to its parent, which
    ; means cutting at the LAST separator and keeping it.  No separator at all
    ; means the file sits at the root, and so does what joins it.
    mov     rax, qword ptr [rbp-24]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    test    dword ptr [r10+ROW_flags], ROWF_DIR
    jnz     cpf_dir
    mov     rax, qword ptr [rbp-40]
cpf_back:
    test    rax, rax
    jz      cpf_none                        ; a file at the root
    dec     rax
    lea     r11, [g_add_prefix]
    cmp     byte ptr [r11+rax], 2Fh
    jne     cpf_back
    inc     rax                             ; keep the separator
    mov     qword ptr [rbp-40], rax
    jmp     cpf_store
cpf_dir:
    ; "docs" + "/" so the leaf that follows lands inside it rather than beside
    ; it.  Without this, adding to a folder called docs would produce entries
    ; called "docsreport.pdf".
    mov     rax, qword ptr [rbp-40]
    lea     r11, [g_add_prefix]
    mov     byte ptr [r11+rax], 2Fh
    inc     rax
    mov     qword ptr [rbp-40], rax
cpf_store:
    mov     rax, qword ptr [rbp-40]
    lea     r11, [g_add_prefix]
    mov     byte ptr [r11+rax], 0
    mov     qword ptr [g_add_prefixlen], rax
    FRAME_EPILOG
    ret
cpf_none:
    mov     qword ptr [g_add_prefixlen], 0
    mov     byte ptr [g_add_prefix], 0
cpf_ret:
    FRAME_EPILOG
    ret
container_prefix_from_row endp

; =============================================================================
; dest_row_from_hit(rcx = the row under the cursor, or -1) -> rax = the row of
; the FOLDER the file would land in, or -1 for the archive root.
;
; A folder is its own answer; a file gives the folder it is in, found by walking
; back to the first row one level shallower.  That backward walk is why the row
; model is the right thing to ask: it already holds the depth the tree was drawn
; with, so this cannot disagree with what the user is looking at.
; =============================================================================
dest_row_from_hit proc
    mov     rax, -1
    cmp     rcx, 0
    jl      dfh_ret
    cmp     rcx, qword ptr [g_rowcount]
    jae     dfh_ret
    mov     r10, rcx
    imul    r10, r10, ROW_SIZE
    lea     r11, [g_rows]
    add     r11, r10
    test    dword ptr [r11+ROW_flags], ROWF_DIR
    jz      dfh_file
    mov     rax, rcx                        ; a folder is its own destination
    ret
dfh_file:
    mov     r10d, dword ptr [r11+ROW_depth]
    test    r10d, r10d
    jz      dfh_ret                         ; a file at depth 0 -> the root
    dec     r10d                            ; the depth its parent sits at
dfh_back:
    test    rcx, rcx
    jz      dfh_ret                         ; ran off the top: treat as the root
    dec     rcx
    mov     r11, rcx
    imul    r11, r11, ROW_SIZE
    lea     rax, [g_rows]
    add     r11, rax
    cmp     dword ptr [r11+ROW_depth], r10d
    jne     dfh_back
    mov     rax, rcx
    ret
dfh_ret:
    ret
dest_row_from_hit endp

; =============================================================================
; row_last_descendant(rcx = row) -> rax = the last VISIBLE row still inside it.
;
; Its own index when it has no visible children, which is what a collapsed or
; empty folder gives - so the box drawn from it covers exactly what the user
; can see belongs to that folder, and nothing that is merely hidden inside it.
; =============================================================================
row_last_descendant proc
    mov     rax, rcx
    cmp     rcx, 0
    jl      rld_ret
    cmp     rcx, qword ptr [g_rowcount]
    jae     rld_ret
    mov     r10, rcx
    imul    r10, r10, ROW_SIZE
    lea     r11, [g_rows]
    add     r11, r10
    mov     r10d, dword ptr [r11+ROW_depth]  ; the folder's own depth
rld_fwd:
    lea     r11, [rax+1]
    cmp     r11, qword ptr [g_rowcount]
    jae     rld_ret
    mov     rcx, r11
    imul    rcx, rcx, ROW_SIZE
    lea     r9, [g_rows]
    add     rcx, r9
    cmp     dword ptr [rcx+ROW_depth], r10d
    jle     rld_ret                          ; back out to the folder's own level
    mov     rax, r11
    jmp     rld_fwd
rld_ret:
    ret
row_last_descendant endp

; =============================================================================
; drop_box_set(rcx = destination row, or -1 for the archive root)
;
; The indicator is a translucent box around the destination folder AND
; everything visible inside it, so what is being pointed at is the folder the
; files are going into rather than a position in a list.
;
; This replaced an insertion line, through two corrections worth keeping:
;
;   - the line first hung under the folder's last visible descendant, so that
;     "inside docs" and "the archive root" drew the SAME line whenever docs was
;     the last folder.  Two destinations, one picture.
;   - it was then indented one level to say "inside this", which cost
;     arithmetic and bought nothing: the listing order on the next refresh is
;     the archive's to decide, not the indicator's.
;
; A box has neither problem.  It says which folder by enclosing it, so there is
; nothing to disambiguate and nothing to indent.  The archive root still draws
; NOTHING: the indicator names a folder, and the root is not one.
;
; locals: [rbp-24] dest  [rbp-32] last
; =============================================================================
drop_box_set proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    cmp     qword ptr [g_hlist], 0
    je      dbs_hide
    cmp     qword ptr [g_rowcount], 0
    je      dbs_hide                        ; an empty archive has nothing to enclose
    cmp     qword ptr [rbp-24], 0
    jl      dbs_hide                        ; the root: no folder, no box
    ; ---- top edge: the folder's own row -------------------------------------
    mov     dword ptr [g_dl_rc+0], LVIR_BOUNDS
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMRECT, qword ptr [rbp-24], addr g_dl_rc
    test    eax, eax
    jz      dbs_hide                        ; not laid out
    ; NO g_lvscroll here.  This list scrolls by MOVING THE WHOLE CONTROL - the
    ; window is as tall as the content and is repositioned upward, with a window
    ; region clipping it to the visible band (lv_apply).  So the control's client
    ; space IS the content space: LVM_GETITEMRECT already returns the same
    ; coordinates the paint DC draws in, and adding the scroll offset counts it
    ; twice.  draw_lv_thumb DOES add it, correctly, because the thumb geometry it
    ; works from is viewport-relative - which is the opposite starting point, and
    ; is what made this look like the thing to copy.
    ;
    ; Wrong by exactly g_lvscroll, so it is right at precisely one scroll
    ; position: the top.  Which is where every test left the list.
    mov     eax, dword ptr [g_dl_rc+4]
    mov     dword ptr [rbp-40], eax
    ; ---- bottom edge: the last row still inside it --------------------------
    mov     rcx, qword ptr [rbp-24]
    call    row_last_descendant
    mov     qword ptr [rbp-32], rax
    mov     dword ptr [g_dl_rc+0], LVIR_BOUNDS
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMRECT, qword ptr [rbp-32], addr g_dl_rc
    test    eax, eax
    jz      dbs_hide
    mov     eax, dword ptr [g_dl_rc+12]
    mov     r11d, eax                       ; bottom
    mov     r10d, dword ptr [rbp-40]        ; top
    ; ---- and the width, stopping short of the scrollbar strip ---------------
    mov     rax, qword ptr [g_lay_lvw]
    sub     rax, LVSB_INSET + LVSB_W
    ; changed?  DragOver fires on every mouse message, and invalidating on each
    ; one would repaint the list continuously for the length of the drag.
    cmp     dword ptr [g_dl_show], 1
    jne     dbs_store
    cmp     dword ptr [g_dl_y0], r10d
    jne     dbs_store
    cmp     dword ptr [g_dl_y1], r11d
    jne     dbs_store
    cmp     dword ptr [g_dl_x1], eax
    je      dbs_ret                         ; identical: no repaint
dbs_store:
    mov     dword ptr [g_dl_y0], r10d
    mov     dword ptr [g_dl_y1], r11d
    mov     dword ptr [g_dl_x0], DROPBOX_X0
    mov     dword ptr [g_dl_x1], eax
    mov     dword ptr [g_dl_show], 1
    call    drop_box_invalidate
    FRAME_EPILOG
    ret
dbs_hide:
    cmp     dword ptr [g_dl_show], 0
    je      dbs_ret
    mov     dword ptr [g_dl_show], 0
    call    drop_box_invalidate
dbs_ret:
    FRAME_EPILOG
    ret
drop_box_set endp

; =============================================================================
; drop_box_clear - take the box away.  Must run on DragLeave AND on Drop: a
; drag that ends either way leaves the list painted, and a box left behind
; after the files have landed frames something that already happened.
; =============================================================================
drop_box_clear proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_dl_show], 0
    je      dbc_ret
    mov     dword ptr [g_dl_show], 0
    call    drop_box_invalidate
dbc_ret:
    FRAME_EPILOG
    ret
drop_box_clear endp

; Whole list, not the box's own rect: the rect that has to be repainted is the
; OLD one and the new one both, and the list is small enough that working out
; their union costs more than it saves.  LVS_EX_DOUBLEBUFFER is already on, so
; this does not flicker.
drop_box_invalidate proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_hlist], 0
    je      dbi_ret
    WINCALL InvalidateRect, qword ptr [g_hlist], 0, 0
    WINCALL UpdateWindow, qword ptr [g_hlist]
dbi_ret:
    FRAME_EPILOG
    ret
drop_box_invalidate endp

; =============================================================================
; draw_drop_box(rcx = hdc) - paint it, from the list's WM_PAINT.
;
; Same place and the same reasoning as draw_lv_thumb: after the control has
; painted its rows, on a DC from GetDC.  NM_CUSTOMDRAW's CDDS_POSTPAINT arrives
; with a DC whose contents never reach the screen - measured, not assumed.
;
; Translucency is the same 1x1-source trick the thumb uses, with its own source
; because that one is filled with the thumb's grey.  The border is drawn SOLID
; on top: a tint alone is easy to miss against a dark list, and a solid edge is
; also the thing a test can find by exact colour.
;
; locals: [rbp-16] hdc  [rbp-24] brush  [rbp-32] w  [rbp-40] h
; 128 because AlphaBlend takes ELEVEN arguments - 88 bytes of outgoing area.
; =============================================================================
draw_drop_box proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], rcx
    cmp     dword ptr [g_dl_show], 0
    je      ddb_ret
    mov     eax, dword ptr [g_dl_x1]
    sub     eax, dword ptr [g_dl_x0]
    jle     ddb_ret
    mov     dword ptr [rbp-32], eax                  ; width
    mov     eax, dword ptr [g_dl_y1]
    sub     eax, dword ptr [g_dl_y0]
    jle     ddb_ret
    mov     dword ptr [rbp-40], eax                  ; height
    ; the 1x1 accent source, made on first use and kept, like the thumb's
    cmp     qword ptr [g_dbdc], 0
    jne     ddb_haveSrc
    WINCALL CreateCompatibleDC, qword ptr [rbp-16]
    test    rax, rax
    jz      ddb_ret
    mov     qword ptr [g_dbdc], rax
    WINCALL CreateCompatibleBitmap, qword ptr [rbp-16], 1, 1
    test    rax, rax
    jz      ddb_ret
    mov     qword ptr [g_dbbmp], rax
    WINCALL SelectObject, qword ptr [g_dbdc], qword ptr [g_dbbmp]
    mov     dword ptr [g_dbrc+0], 0
    mov     dword ptr [g_dbrc+4], 0
    mov     dword ptr [g_dbrc+8], 1
    mov     dword ptr [g_dbrc+12], 1
    WINCALL CreateSolidBrush, CLR_ACCENT
    mov     qword ptr [rbp-24], rax
    WINCALL FillRect, qword ptr [g_dbdc], addr g_dbrc, qword ptr [rbp-24]
    WINCALL DeleteObject, qword ptr [rbp-24]
ddb_haveSrc:
    ; AlphaBlend(dst, x, y, w, h, src, 0, 0, 1, 1, BLENDFUNCTION) - eleven
    ; arguments, the last a 4-byte struct by value:
    ;   BlendOp AC_SRC_OVER | BlendFlags 0 | SourceConstantAlpha | AlphaFormat 0
    WINCALL AlphaBlend, qword ptr [rbp-16], dword ptr [g_dl_x0], dword ptr [g_dl_y0], \
            dword ptr [rbp-32], dword ptr [rbp-40], \
            qword ptr [g_dbdc], 0, 0, 1, 1, <AC_SRC_OVER or (DROPBOX_ALPHA shl 16)>
    ; the solid edge
    mov     eax, dword ptr [g_dl_x0]
    mov     dword ptr [g_dbrc+0], eax
    mov     eax, dword ptr [g_dl_y0]
    mov     dword ptr [g_dbrc+4], eax
    mov     eax, dword ptr [g_dl_x1]
    mov     dword ptr [g_dbrc+8], eax
    mov     eax, dword ptr [g_dl_y1]
    mov     dword ptr [g_dbrc+12], eax
    WINCALL CreateSolidBrush, CLR_ACCENT
    mov     qword ptr [rbp-24], rax
    test    rax, rax
    jz      ddb_ret
    WINCALL FrameRect, qword ptr [rbp-16], addr g_dbrc, qword ptr [rbp-24]
    WINCALL DeleteObject, qword ptr [rbp-24]
ddb_ret:
    FRAME_EPILOG
    ret
draw_drop_box endp

; =============================================================================
; dt_row_from_pt(rcx = POINTL, packed: x in the low dword, y in the high)
;   -> rax = the row under that screen point, or -1.
;
; g_lhit is shared with list_subclass's WM_NCHITTEST.  Both run on the UI
; thread and neither re-enters the other, so there is one user at a time.
; =============================================================================
dt_row_from_pt proc frame
    FRAME_PROLOG 64
    mov     r10d, ecx
    mov     dword ptr [g_lhit+0], r10d      ; x
    mov     rax, rcx
    sar     rax, 32                         ; y, sign-extended out of the high half
    mov     dword ptr [g_lhit+4], eax
    mov     rax, -1
    cmp     qword ptr [g_hlist], 0
    je      drp_ret
    WINCALL ScreenToClient, qword ptr [g_hlist], addr g_lhit
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_HITTEST, 0, addr g_lhit
    movsxd  rax, eax
    cmp     rax, 0
    jl      drp_none
    cmp     rax, qword ptr [g_rowcount]
    jb      drp_ret                         ; a real row
drp_none:
    mov     rax, -1
drp_ret:
    FRAME_EPILOG
    ret
dt_row_from_pt endp

container_add_run proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     rax, qword ptr [g_poscount]
    cmp     rax, qword ptr [rbp-16]
    je      car_ret                         ; nothing was collected
    ; Where the files land, decided HERE so that the buttons and the drop get
    ; the same answer - this is the one proc both of them reach.  A drag has
    ; already chosen a row (the one the line was pointing at); everything else
    ; falls back to the selection.  The flag is cleared either way, so a row
    ; from one drag can never survive into the next append.
    cmp     dword ptr [g_add_row_set], 0
    je      car_fromsel
    mov     dword ptr [g_add_row_set], 0
    movsxd  rcx, dword ptr [g_add_row]
    call    container_prefix_from_row
    jmp     car_haveprefix
car_fromsel:
    call    container_prefix_from_selection
car_haveprefix:
    lea     rax, [g_filepath_w]
    mov     qword ptr [g_cfg_in], rax
    ; g_poscount is NOT put back here - the worker is about to walk
    ; g_positionals[].  on_done does it.
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [g_ca_poscount], rax
    mov     dword ptr [g_wt_job], 1
    call    enter_running
car_ret:
    FRAME_EPILOG
    ret
container_add_run endp

container_add proc frame
    FRAME_PROLOG 96
    mov     dword ptr [rbp-16], ecx
    cmp     dword ptr [g_container], 0
    je      ca_ret                          ; not browsing anything
    cmp     dword ptr [g_running], 0
    jne     ca_ret
    mov     rax, qword ptr [g_poscount]
    mov     qword ptr [rbp-24], rax
    mov     dword ptr [g_pick_only], 1
    mov     ecx, dword ptr [rbp-16]
    call    add_via_picker
    mov     dword ptr [g_pick_only], 0
    mov     rcx, qword ptr [rbp-24]
    call    container_add_run
ca_ret:
    FRAME_EPILOG
    ret
container_add endp

; =============================================================================
; container_update_action - the action button says what it will actually do.
;
; Extracting only the marked rows is otherwise invisible: the same button, the
; same click, a different amount of data.  Selecting nothing still means the
; whole archive, so the label goes back when the selection is cleared.
; =============================================================================
container_update_action proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    cmp     dword ptr [g_container], 0
    je      cua_ret
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETSELECTEDCOUNT, 0, 0
    mov     qword ptr [rbp-8], rax
    lea     rdx, [s_decrypt]
    cmp     dword ptr [g_is_zip], 0
    je      @F
    lea     rdx, [s_extract]
@@:
    cmp     qword ptr [rbp-8], 0
    je      cua_set
    lea     rdx, [s_decrypt_sel]
    cmp     dword ptr [g_is_zip], 0
    je      cua_set
    lea     rdx, [s_extract_sel]
cua_set:
    WINCALL SetWindowTextW, qword ptr [g_haction], rdx
    WINCALL InvalidateRect, qword ptr [g_haction], 0, 1
cua_ret:
    add     rsp, 64
    pop     rbp
    ret
container_update_action endp

; =============================================================================
; confirm_slow_remove -> eax = 1 go ahead, 0 the user stopped.
;
; Removal is proportional to what follows the hole - the survivors are moved
; down over it - so on a large archive it is a long synchronous write on the UI
; thread, and the window stops answering.  Being told that afterwards is no use,
; so it is said first, with a way out.
;
; The threshold is a size, not a guess about the disk: 100 MiB is where the
; pause stops being instant on anything.  Below it the question would be noise,
; and a dialog people learn to click through is worse than no dialog.
;
; Nothing has been written when this is asked, so cancelling costs nothing and
; the message says so.
; =============================================================================
SLOW_REMOVE_BYTES   equ 6400000h                  ; 100 MiB

confirm_slow_remove proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80
    WINCALL GetFileAttributesExW, addr g_filepath_w, 0, addr g_fad
    test    eax, eax
    jz      csr_yes                               ; size unknown: do not invent a warning
    mov     eax, dword ptr [g_fad+28]             ; nFileSizeHigh
    test    eax, eax
    jnz     csr_ask                               ; over 4 GiB: certainly slow
    mov     eax, dword ptr [g_fad+32]             ; nFileSizeLow
    cmp     eax, SLOW_REMOVE_BYTES
    jb      csr_yes
csr_ask:
    lea     rcx, [m_slow_remove]
    lea     rdx, [t_slow]
    mov     r8d, MB_OKCANCEL or MB_ICONWARNING
    call    mbox
    cmp     eax, IDOK
    jne     csr_no
csr_yes:
    mov     eax, 1
    add     rsp, 80
    pop     rbp
    ret
csr_no:
    xor     eax, eax
    add     rsp, 80
    pop     rbp
    ret
confirm_slow_remove endp

; =============================================================================
; container_mark_selected(r8d = flag bits) -> rax = entries marked.
;
; Walks the selected rows and marks each entry, and everything under it, with
; the given bit.  Removal and the extraction pick share it so that "this folder"
; cannot come to mean two different things - a pick that took a folder without
; its contents would extract an empty directory and look like it had worked.
;
; locals (frame 128): row[-24] marked[-32] flag[-40] name[-48] namelen[-56].
; 128 because WideCharToMultiByte takes EIGHT arguments, so its outgoing area is
; 64 bytes and has to sit below the deepest local, not through it.
; =============================================================================
container_mark_selected proc frame
    FRAME_PROLOG 128
    mov     dword ptr [rbp-40], r8d
    ; ---- mark every selected row -------------------------------------------
    mov     qword ptr [rbp-32], 0
    xor     r10, r10
cms_row:
    cmp     r10, qword ptr [g_rowcount]
    jae     cms_done
    mov     qword ptr [rbp-24], r10
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMSTATE, qword ptr [rbp-24], LVIS_SELECTED
    test    eax, LVIS_SELECTED
    jz      cms_next
    mov     rcx, qword ptr [rbp-24]
    call    row_path                        ; the entry name, with '\' separators
    mov     qword ptr [rbp-48], rax
    WINCALL WideCharToMultiByte, 65001, 0, qword ptr [rbp-48], -1, addr g_delname2, 4000, 0, 0
    test    eax, eax
    jle     cms_next
    dec     eax                             ; drop the terminator
    cdqe
    mov     qword ptr [rbp-56], rax
    ; the inventory holds tar names; the row model holds Windows ones
    lea     r11, [g_delname2]
    xor     r9, r9
cms_sep:
    cmp     r9, qword ptr [rbp-56]
    jae     cms_sepd
    cmp     byte ptr [r11+r9], 5Ch
    jne     cms_sepn
    mov     byte ptr [r11+r9], 2Fh
cms_sepn:
    inc     r9
    jmp     cms_sep
cms_sepd:
    lea     rcx, [g_delname2]
    mov     rdx, qword ptr [rbp-56]
    mov     r8d, dword ptr [rbp-40]
    call    idx_mark_flag                   ; a folder takes its contents with it
    add     qword ptr [rbp-32], rax
cms_next:
    mov     r10, qword ptr [rbp-24]
    inc     r10
    jmp     cms_row
cms_done:
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
container_mark_selected endp

container_remove_selected proc frame
    FRAME_PROLOG 128
    cmp     qword ptr [g_rowcount], 0
    je      crs_ret
    cmp     dword ptr [g_is_zip], 0
    jne     crs_zip
    ; the index, and the key, which both removal paths need alive
    mov     dword ptr [g_keep_key], 1
    call    idx_read
    mov     dword ptr [g_keep_key], 0
    test    eax, eax
    jnz     crs_ret
    mov     r8d, IDXEF_DROPPED
    call    container_mark_selected
    mov     qword ptr [rbp-32], rax
    ; nothing selected: no question, and nothing to do
    cmp     qword ptr [rbp-32], 0
    je      crs_wipekey
    call    confirm_slow_remove
    test    eax, eax
    jz      crs_wipekey
crs_marked:
    cmp     qword ptr [rbp-32], 0
    je      crs_wipekey                     ; nothing selected that is in there
    ; One removal, whatever the size: the entry is overwritten where it lies and
    ; the gap closed.  There used to be a question here - rewrite the container
    ; or overwrite in place - and it existed because rewriting meant decrypting
    ; and re-encrypting everything.  Closing the gap is a byte copy now, so there
    ; is nothing to weigh and nothing to ask.
    mov     dword ptr [g_wt_job], 2
    call    enter_running
crs_ret:
    FRAME_EPILOG
    ret
crs_wipekey:
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
    FRAME_EPILOG
    ret

; ---- the same command against a zip ----------------------------------------
; The shape is deliberately the container's: refresh the inventory, mark what is
; selected, ask if this will be slow, act, reload.  Only the middle step differs,
; because a zip is rewritten rather than edited in place.
;
; zip_to_index first, for the reason the container path calls idx_read first: it
; rebuilds the inventory from the file, so marks left behind by a removal the
; user CANCELLED cannot still be sitting on entries when the next one runs.  On
; the container side the re-read is forced by the key; here nothing would force
; it, and stale marks would quietly delete more than was asked for.
;
; No key to wipe on the way out - a zip's entries carry their own, and this
; rewrite never derives one.
crs_zip:
    lea     rax, [g_filepath_w]
    mov     qword ptr [g_cfg_in], rax
    call    zip_to_index
    test    eax, eax
    jnz     crs_ret
    mov     r8d, IDXEF_DROPPED
    call    container_mark_selected
    mov     qword ptr [rbp-32], rax
    cmp     qword ptr [rbp-32], 0
    je      crs_ret
    call    confirm_slow_remove
    test    eax, eax
    jz      crs_ret                         ; stopped: the next removal re-reads
    mov     dword ptr [g_wt_job], 2
    call    enter_running
    FRAME_EPILOG
    ret
container_remove_selected endp

; =============================================================================
; container_load - unlock a .mrk and show what is in it.
;
; This is the point of the format work: opening a container shows its contents
; instead of extracting them.  The password is collected first - the inventory
; is behind the same key as the payload, so there is nothing to show until it
; has been given - and then ONLY the inventory is read.  The payload is never
; touched, so this costs one Argon2 derivation whatever the container holds.
;
; eax = 0 when the listing is up, non-zero when it is not (cancelled, wrong
; password, or a container with nothing to list).
; =============================================================================
container_load proc frame
    FRAME_PROLOG 64
    lea     rax, [g_filepath_w]
    mov     qword ptr [g_cfg_in], rax
    cmp     dword ptr [g_is_zip], 0
    jne     cl_zip
    ; the password, once: read_password caches it, so the Decrypt that follows
    ; does not ask again for the same container
    call    read_password
    test    eax, eax
    jnz     cl_fail
    mov     dword ptr [g_pw_ready], 1
    ; The key OUTLIVES the listing here, which it does not for a CLI list.
    ;
    ; Dragging an entry out has to be refused at LVN_BEGINDRAG or not at all -
    ; there is nowhere to report a failure once the target's copy loop is
    ; running - so the key has to be there already when the gesture starts.
    ; Deriving it then would mean an Argon2 pass, most of a second, at the exact
    ; moment the user is moving the mouse.
    ;
    ; The exposure is bounded by the same thing that already bounds g_cfg_pass,
    ; which this window deliberately keeps for its lifetime: the process.
    ; secmem locks and wipes g_key at exit, and every re-listing re-derives it,
    ; so an add or a delete leaves it correct rather than stale.
    mov     dword ptr [g_keep_key], 1
    call    idx_read
    mov     dword ptr [g_keep_key], 0
    test    eax, eax
    jnz     cl_fail
    jmp     cl_listed
cl_zip:
    ; The password comes first here too, whenever there is one to give.  It buys
    ; no secrecy - WinZip-AES encrypts entry data and nothing else, so a zip's
    ; names and sizes are readable by anyone holding the file whatever this
    ; window does - and it is asked anyway so that opening an archive means the
    ; same thing whichever kind it is: give the password, look at what is in it,
    ; then choose.  Being asked at the end instead, after browsing and marking,
    ; is the surprise worth avoiding.
    ;
    ; A zip with nothing encrypted in it is not asked, because there would be
    ; nothing to check the answer against: a prompt whose input cannot be wrong
    ; is a prompt that teaches the user their answer does not matter.
    cmp     dword ptr [g_zip_enc], 0
    je      cl_ziplist
    call    read_password
    test    eax, eax
    jnz     cl_fail
    mov     dword ptr [g_pw_ready], 1
cl_ziplist:
    call    zip_to_index
    test    eax, eax
    jnz     cl_fail
cl_listed:
    ; populate_list derives the rows from the inventory itself now, so there is
    ; no separate rows_from_index call here to fall out of step with it.
    call    populate_list
    ; Open on the top LEVEL, not on the top ROW.  An input list starts collapsed
    ; because its top level is what the user picked and each row names something
    ; they chose; a container's top level is an accident of how it was packed -
    ; very often exactly one folder - and a list with one row in it is not a
    ; listing of anything.  Seeded once, so a collapse made afterwards sticks.
    call    container_expand_top
    call    populate_list
    ; The summary reports what the inventory says, and it says FILES.  This was
    ; g_idxcount - every index entry, directories included - so a folder tree
    ; reported thousands more than Explorer does for the same folder, and there
    ; was no way to reconcile the two.  For the 587 GB report: Explorer said
    ; 76,286 files and 7,792 folders, this said "84079 files", and 76286 + 7792 +
    ; 1 is exactly 84079 - the +1 being the archive's own root entry.
    call    idx_summarise
    mov     rax, qword ptr [g_idx_files]
    mov     qword ptr [g_scan_files], rax
    mov     rax, qword ptr [g_idx_dirs]
    mov     qword ptr [g_scan_dirs], rax
    mov     rax, qword ptr [g_idx_bytes]
    mov     qword ptr [g_scan_bytes], rax
    lea     rcx, [s_empty]
    call    fmt_summary
    WINCALL SetWindowTextW, qword ptr [g_hscan], addr g_summbuf
    xor     eax, eax
    FRAME_EPILOG
    ret
cl_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
container_load endp

; =============================================================================
; container_expand_top - mark every top-level directory of a freshly loaded
; container as expanded.  Runs over the ROW model rather than over the inventory
; a second time: straight after the first populate_list every row is depth 0, so
; this is the top level by construction.  The depth test keeps that true if it
; is ever called anywhere else.
; =============================================================================
; =============================================================================
; container_expand_prefix - open the folder an add just went into, and every
; folder above it, so that what was added can be seen.
;
; Without this, adding into a COLLAPSED folder looks exactly like adding
; nothing: the entry is in the archive, the reload is correct, and the tree
; does not change by a single row - not on the reload and not on reopening
; either, because the folder is still shut.  That is indistinguishable from the
; silent-refusal bug this whole feature arc has been removing, and it is worse,
; because here the file really did arrive.
;
; Reads g_add_prefix, which still holds the destination at this point: only the
; next append overwrites it, and do_pack / do_zip clear it for fresh archives.
;
; locals: [rbp-24] cursor  [rbp-32] chars
; =============================================================================
container_expand_prefix proc frame
    FRAME_PROLOG 80
    cmp     qword ptr [g_add_prefixlen], 0
    je      cep_ret                         ; the root: nothing to open
    WINCALL MultiByteToWideChar, CP_UTF8, 0, addr g_add_prefix, \
            qword ptr [g_add_prefixlen], addr g_expw, 2040
    test    eax, eax
    jle     cep_ret
    cdqe
    mov     qword ptr [rbp-32], rax
    ; Indexed through a register base, never "[g_expw+rax*2]": that assembles as
    ; a 32-bit absolute address, which is illegal under /highentropyva and fails
    ; at LINK with LNK2017 rather than anywhere useful.
    lea     r11, [g_expw]
    mov     word ptr [r11+rax*2], 0
    ; The set is keyed by row paths, which carry Windows separators; the prefix
    ; carries archive ones.
    xor     r10, r10
cep_sep:
    cmp     r10, qword ptr [rbp-32]
    jae     cep_sepd
    cmp     word ptr [r11+r10*2], 2Fh
    jne     cep_sepn
    mov     word ptr [r11+r10*2], 5Ch
cep_sepn:
    inc     r10
    jmp     cep_sep
cep_sepd:
    ; The prefix ends in a separator, so cutting at every separator yields the
    ; destination itself and each ancestor in turn - "a\b\c\" gives a\b\c, a\b,
    ; a.  Each is NUL-terminated in place for the call and put back afterwards,
    ; because the next cut needs the whole string again.
    mov     qword ptr [rbp-24], 0
cep_walk:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [rbp-32]
    jae     cep_ret
    lea     r11, [g_expw]
    cmp     word ptr [r11+rax*2], 5Ch
    jne     cep_next
    mov     word ptr [r11+rax*2], 0
    lea     rcx, [g_expanded]
    lea     rdx, [g_expw]
    call    pset_add
    mov     rax, qword ptr [rbp-24]
    lea     r11, [g_expw]
    mov     word ptr [r11+rax*2], 5Ch
cep_next:
    inc     qword ptr [rbp-24]
    jmp     cep_walk
cep_ret:
    FRAME_EPILOG
    ret
container_expand_prefix endp

container_expand_top proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], 0
cet_row:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_rowcount]
    jae     cet_done
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    cmp     dword ptr [r10+ROW_depth], 0
    jne     cet_next
    mov     eax, dword ptr [r10+ROW_flags]
    test    eax, ROWF_DIR
    jz      cet_next
    mov     rcx, qword ptr [rbp-24]
    call    row_path
    lea     rcx, [g_expanded]
    mov     rdx, rax
    call    pset_add
cet_next:
    inc     qword ptr [rbp-24]
    jmp     cet_row
cet_done:
    FRAME_EPILOG
    ret
container_expand_top endp

; =============================================================================
; idx_summarise - files, directories and bytes across the WHOLE inventory.
;
; Called once when a container is opened.  It used to be done inside
; rows_from_index, one entry at a time, which meant re-walking every entry on
; every expand, collapse and repaint - work that is invisible at 84,000 entries
; and quadratic-feeling the moment the index stops being resident (see
; docs/V5_WORK.md, step A1).
;
; Bounds are checked exactly as rows_from_index checks them: the table is
; authentic, but a container from a future version could still describe an entry
; that runs off the end of it.  A short read stops the walk rather than trusting
; the count.
; =============================================================================
idx_summarise proc frame
    FRAME_PROLOG 64
    mov     qword ptr [g_idx_bytes], 0
    mov     qword ptr [g_idx_files], 0
    mov     qword ptr [g_idx_dirs], 0
    mov     qword ptr [rbp-16], 0                ; cursor
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-24], rax              ; entries left
is_next:
    cmp     qword ptr [rbp-24], 0
    je      is_done
    mov     rax, qword ptr [rbp-16]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      is_done
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-16]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      is_done
    mov     qword ptr [rbp-32], rax              ; next cursor
    test    dword ptr [r10+IDXE_flags], IDXEF_DIR
    jz      is_file
    inc     qword ptr [g_idx_dirs]
    jmp     is_step
is_file:
    inc     qword ptr [g_idx_files]
    mov     rax, qword ptr [r10+IDXE_size]
    add     qword ptr [g_idx_bytes], rax
is_step:
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-16], rax
    dec     qword ptr [rbp-24]
    jmp     is_next
is_done:
    xor     eax, eax
    FRAME_EPILOG
    ret
idx_summarise endp

; =============================================================================
; rows_from_index - turn the decrypted inventory into the visible-row model, so
; a container's contents display through exactly the same path an input tree
; does: same list, same indentation, same scrolling, same scrollbar.
;
; Inventory names are tar names ('/'); the row model displays paths the way
; Windows writes them, so the separators are translated on the way in.  Depth is
; the separator count, which is what indents the row.
;
; locals (frame 112): cursor[-24] left[-32] depth[-40] next[-48] name[-56]
; len[-64] ancestor-scan[-72] size[-80].  112, not 96: MultiByteToWideChar takes
; six arguments, so at frame 96 the outgoing area reaches [rbp-65] and the two
; new locals would have been argument slots rather than locals.  At 112 it
; reaches [rbp-81], so [rbp-80] is the lowest one that is safe.
; =============================================================================
rows_from_index proc frame
    FRAME_PROLOG 112
    call    rows_reset
    mov     qword ptr [rbp-24], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-32], rax
rfi_next:
    cmp     qword ptr [rbp-32], 0
    je      rfi_done
    ; bounds, exactly as do_list checks them: the table is authentic, but a
    ; container from a future version could still describe an entry off its end
    mov     rax, qword ptr [rbp-24]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      rfi_done
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      rfi_done
    mov     qword ptr [rbp-48], rax
    lea     rcx, [r10+IDXE_name]
    mov     qword ptr [rbp-56], rcx
    mov     qword ptr [rbp-64], r11
    WINCALL MultiByteToWideChar, CP_UTF8, 0, qword ptr [rbp-56], qword ptr [rbp-64], addr g_rowname, 4090
    test    eax, eax
    jle     rfi_skip
    cdqe
    lea     r10, [g_rowname]
    mov     word ptr [r10+rax*2], 0          ; a COUNTED conversion does not
                                             ; terminate the result for us
    mov     qword ptr [rbp-40], 0
    xor     r9, r9
rfi_sep:
    cmp     r9, rax
    jae     rfi_sepdone
    cmp     word ptr [r10+r9*2], 2Fh         ; '/'
    jne     rfi_sepnext
    mov     word ptr [r10+r9*2], 5Ch         ; '\'
    inc     qword ptr [rbp-40]
rfi_sepnext:
    inc     r9
    jmp     rfi_sep
rfi_sepdone:
    ; The summary used to be accounted HERE, once per entry, on every call - and
    ; this proc runs on every expand, collapse and repaint.  It is idx_summarise
    ; now, called once when the container is opened.  At 84,000 entries the
    ; difference is invisible; at the sizes docs/V5_WORK.md is about, with the
    ; index no longer resident, re-walking it per click would mean decrypting the
    ; whole thing per click.
    ; ---- visible? every ancestor has to be expanded --------------------------
    ; The input model never states this rule: rows_expand_into only descends INTO
    ; an expanded directory, so a collapsed ancestor hides everything below it as
    ; a consequence of the recursion.  A flat inventory has no recursion to
    ; inherit it from, so the same rule is applied directly here.  Without it the
    ; container listed itself fully expanded, and the folder rows had nothing to
    ; collapse.
    ;
    ; The key is the row's own path with backslashes, which is exactly what
    ; row_toggle puts into g_expanded - so expanding works out of the box rather
    ; than through a second, parallel notion of what is open.
    cmp     qword ptr [rbp-40], 0
    je      rfi_visible
    lea     r10, [g_rowname]
    xor     r9, r9
rfi_anc:
    movzx   r11d, word ptr [r10+r9*2]
    test    r11d, r11d
    jz      rfi_visible
    cmp     r11d, 5Ch                        ; '\' -> g_rowname[0..r9) is an ancestor
    jne     rfi_ancnext
    mov     word ptr [r10+r9*2], 0           ; cut it short, ask, put it back
    mov     qword ptr [rbp-72], r9
    lea     rcx, [g_expanded]
    lea     rdx, [g_rowname]
    call    pset_has
    mov     r9, qword ptr [rbp-72]
    lea     r10, [g_rowname]
    mov     word ptr [r10+r9*2], 5Ch
    test    eax, eax
    jz      rfi_skip                         ; collapsed above: this row is hidden
rfi_ancnext:
    inc     r9
    jmp     rfi_anc
rfi_visible:
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    mov     r8, qword ptr [r10+IDXE_size]
    mov     r9d, dword ptr [r10+IDXE_flags]
    and     r9d, IDXEF_DIR                   ; ROWF_DIR shares bit 0
    test    r9d, ROWF_DIR
    jnz     rfi_dir
    ; (bytes are accounted at rfi_accounted, over the whole inventory)
    jmp     rfi_add
rfi_dir:
    ; An open directory has to say so in its own flags: row_toggle reads
    ; ROWF_EXPANDED to decide whether a double-click opens or closes.  Setting
    ; only ROWF_DIR here made every double-click an "open", so a folder could be
    ; opened and never closed again - it went into g_expanded and nothing ever
    ; took it out.  rows_build sets the same bit the same way for the input tree.
    mov     qword ptr [rbp-80], r8
    lea     rcx, [g_expanded]
    lea     rdx, [g_rowname]
    call    pset_has
    mov     r8, qword ptr [rbp-80]
    mov     r9d, ROWF_DIR
    test    eax, eax
    jz      rfi_add
    mov     r9d, ROWF_DIR or ROWF_EXPANDED
rfi_add:
    lea     rcx, [g_rowname]
    mov     edx, dword ptr [rbp-40]
    call    rows_add
rfi_skip:
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [rbp-24], rax
    dec     qword ptr [rbp-32]
    jmp     rfi_next
rfi_done:
    ; The inventory is in WRITE order, which stops being tree order the moment
    ; anything is appended - see rows_sort_tree.  Sorted here, at the one place
    ; a container's rows are built, so no caller can forget it.
    call    rows_sort_tree
    FRAME_EPILOG
    ret
rows_from_index endp

; =============================================================================
; start_indexing - reset counters, show the initial scan status, then launch the
; indexer thread plus a 120ms status timer.  If the thread fails to start, index
; inline so the app still works.
; =============================================================================
start_indexing proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [g_scan_files], 0
    mov     qword ptr [g_scan_dirs], 0
    mov     qword ptr [g_scan_bytes], 0
    mov     qword ptr [g_input_total], 0
    mov     dword ptr [g_scanning], 1
    lea     rcx, [s_scan_pre]
    call    fmt_summary
    WINCALL SetWindowTextW, qword ptr [g_hscan], addr g_summbuf
    WINCALL SetTimer, qword ptr [g_hwnd], 3, 120, 0
    WINCALL CreateThread, 0, 0, addr indexer_thread, 0, 0, addr g_index_tid
    test    rax, rax
    jz      si_inline
    WINCALL CloseHandle, rax
    jmp     si_done
si_inline:
    call    indexer_thread                 ; thread failed -> run inline (posts msg)
si_done:
    add     rsp, 48
    pop     rbp
    ret
start_indexing endp

; =============================================================================
; on_scan_timer - refresh the live scan status from the running counters.
; =============================================================================
on_scan_timer proc
    sub     rsp, 40
    cmp     dword ptr [g_scanning], 0
    je      ost_ret
    lea     rcx, [s_scan_pre]
    call    fmt_summary
    WINCALL SetWindowTextW, qword ptr [g_hscan], addr g_summbuf
ost_ret:
    add     rsp, 40
    ret
on_scan_timer endp

; =============================================================================
; on_index_done - WM_APP_INDEXED: indexing finished.  Stop the status timer,
; fill the listview from the precomputed sizes, show the summary, apply the
; size-based compression default and re-enable the action button.
; =============================================================================
on_index_done proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     dword ptr [g_scanning], 0
    WINCALL KillTimer, qword ptr [g_hwnd], 3
    call    populate_list                  ; sizes ready in g_rowsize -> no walk
    lea     rcx, [s_empty]
    call    fmt_summary                    ; final "<N> files, <size>"
    WINCALL SetWindowTextW, qword ptr [g_hscan], addr g_summbuf
    ; size-based compression default (unless a saved/explicit setting already won)
    cmp     dword ptr [g_cfg_compress_seen], 0
    jne     oid_complbl
    mov     dword ptr [g_compress_on], 0
    mov     rax, qword ptr [g_input_total]
    cmp     rax, COMPRESS_AUTO_MAX
    jae     oid_complbl
    mov     dword ptr [g_compress_on], 1
oid_complbl:
    lea     rdx, [s_comp_off]
    cmp     dword ptr [g_compress_on], 0
    je      oid_setlbl
    lea     rdx, [s_comp_on]
oid_setlbl:
    WINCALL SetWindowTextW, qword ptr [g_hcompress], rdx
    call    update_strength                ; re-enable the action button per policy
    add     rsp, 48
    pop     rbp
    ret
on_index_done endp

; =============================================================================
; worker_thread(rcx = param) - runs the crypto, posts WM_APP_DONE.  Runs on its
; OWN thread and is the sole user of the software shadow stack while active.
; =============================================================================
worker_thread proc
    ; This thread runs FRAME_PROLOG'd code, so it needs its OWN shadow stack.
    ; Sharing one with the UI thread is the race that fastfailed the process.
    call    sstk_thread_init
    sub     rsp, 40
    ; The container edits come through here now, so a large add or removal no
    ; longer holds the message loop.  They are the same procs as before - only
    ; the thread they run on changed - and everything that touches a control
    ; stayed behind on the UI thread.
    cmp     dword ptr [g_wt_job], 0
    je      wt_crypto
    cmp     dword ptr [g_wt_job], 1
    jne     wt_cremove
    cmp     dword ptr [g_is_zip], 0
    jne     wt_zipadd
    call    do_add
    jmp     wt_fin
wt_zipadd:
    call    do_zip_add
    jmp     wt_fin
wt_cremove:
    cmp     dword ptr [g_is_zip], 0
    jne     wt_zipdel
    call    do_remove_marked
    jmp     wt_fin
wt_zipdel:
    call    zip_delete_marked
    jmp     wt_fin
wt_crypto:
    cmp     dword ptr [g_op], 0
    jne     wt_dec
    cmp     dword ptr [g_make_zip], 0
    je      wt_encrypt
    call    do_zip
    jmp     wt_fin
wt_encrypt:
    call    do_encrypt
    jmp     wt_fin
wt_dec:
    cmp     dword ptr [g_is_zip], 0
    je      wt_decrypt
    call    do_unzip
    jmp     wt_fin
wt_decrypt:
    call    do_decrypt
wt_fin:
    mov     dword ptr [g_op_result], eax
    WINCALL PostMessageW, qword ptr [g_hwnd], WM_APP_DONE, 0, 0
    call    sstk_thread_free                ; last: nothing framed may follow it
    add     rsp, 40
    xor     eax, eax
    ret
worker_thread endp

; =============================================================================
; enter_running - shared UI transition into the "working" state + launch worker
; =============================================================================
enter_running proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     dword ptr [g_running], 1
    mov     dword ptr [g_cancelled], 0
    mov     qword ptr [g_prog_total], 0
    mov     qword ptr [g_prog_done], 0
    ; The action log covers ONE operation.  Started here, on the UI thread and
    ; before the worker exists, so nothing is appending while it is cleared -
    ; and so the log the statistics line opens is about what the user just did,
    ; not about everything since the window opened.
    call    rlog_begin
    mov     dword ptr [g_scan_fail], 0      ; a new run is not the last one's failure
    ; disable inputs
    WINCALL EnableWindow, qword ptr [g_haction], 0
    WINCALL EnableWindow, qword ptr [g_hpass], 0
    cmp     qword ptr [g_hconfirm], 0
    je      @F
    WINCALL EnableWindow, qword ptr [g_hconfirm], 0
@@:
    cmp     qword ptr [g_hdest], 0
    je      @F
    WINCALL EnableWindow, qword ptr [g_hdest], 0
    WINCALL EnableWindow, qword ptr [g_hchange], 0
@@:
    ; enable cancel, show progress
    WINCALL EnableWindow, qword ptr [g_hcancel], 1
    mov     dword ptr [g_prog_pct], 0
    WINCALL ShowWindow, qword ptr [g_hprog], SW_SHOW
    ; An ADD (job 1) now totals its inputs and checks for cancellation between
    ; them, so it gets both.  A REMOVAL (job 2) gets neither: do_remove_marked
    ; overwrites entries in place and zip_delete_marked rewrites the archive,
    ; and stopping either half way leaves work that the user would have to be
    ; told about rather than simply undone.  A Cancel that cannot cleanly undo
    ; is worse than no Cancel.
    cmp     dword ptr [g_wt_job], 2
    jne     @F
    WINCALL EnableWindow, qword ptr [g_hcancel], 0
    ; A .mrk removal totals its work exactly and drives the bar.  A zip removal
    ; still cannot: zip_delete_marked copies whole local records and the survey
    ; pass does not add their bytes up, so any total would be an estimate - and
    ; a bar that lands near 100 rather than on it is worse than none.
    cmp     dword ptr [g_is_zip], 0
    je      @F
    WINCALL ShowWindow, qword ptr [g_hprog], SW_HIDE
@@:
    WINCALL SetWindowTextW, qword ptr [g_hstatus], addr s_working
    ; 100ms timer
    WINCALL SetTimer, qword ptr [g_hwnd], 1, 100, 0
    ; CreateThread(NULL, 0, worker_thread, NULL, 0, &tid)
    WINCALL CreateThread, 0, 0, addr worker_thread, 0, 0, addr g_tid
    test    rax, rax
    jz      er_fail
    WINCALL CloseHandle, rax
    jmp     er_done
er_fail:
    mov     dword ptr [g_running], 0
er_done:
    add     rsp, 64
    pop     rbp
    ret
enter_running endp

; =============================================================================
; read_password -> eax: 0 ok (g_cfg_pass/len set), nonzero on a (reported) error
; Reads g_hpass, requires non-empty, converts to UTF-8.
; =============================================================================
read_password proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80
    ; Already asked, before the main window was shown (gui_main).  The secret is
    ; still in g_cfg_pass; asking again would be the double-prompt this whole
    ; change exists to remove.
    cmp     dword ptr [g_pw_ready], 0
    je      @F
    xor     eax, eax
    jmp     rp_ret
@@:
    ; The secret is collected here and nowhere else, which is why this is the
    ; only place that needed changing: both encrypt and decrypt reach it.  It no
    ; longer comes from the in-window edit - that control lives on the
    ; interactive desktop, where any process can WM_SETTEXT a password into it
    ; and post a click, which is exactly how this GUI was driven headlessly in
    ; testing.  secdesk_prompt asks on a desktop that other processes cannot
    ; enumerate or message.
    xor     ecx, ecx
    cmp     dword ptr [g_op], 0             ; 0 = encrypt -> confirm the password
    jne     @F
    mov     ecx, SDF_CONFIRM
@@:
    call    secdesk_prompt
    cmp     eax, SDR_UNAVAILABLE
    jne     @F
    ; fail closed - see secdesk_prompt.  Falling back to the ordinary desktop
    ; here would silently disable the control at the moment it is most needed.
    lea     rcx, [m_sd_unavail]
    lea     rdx, [t_sd_err]
    mov     r8d, MB_OK or MB_ICONERROR
    call    mbox
    mov     eax, 1
    jmp     rp_ret
@@:
    cmp     eax, SDR_OK
    je      rp_have
    mov     eax, 1                          ; cancelled: no operation, no message
    jmp     rp_ret
rp_have:
    ; g_passw already holds the typed password (wide) from the prompt.
    ; UTF-8 conversion (CP_UTF8, WC_ERR_INVALID_CHARS, ...)
    WINCALL WideCharToMultiByte, 65001, 80h, addr g_passw, -1, addr g_cfg_pass, MAX_PASSWORD_BYTES+1, 0, 0
    test    eax, eax
    jz      rp_bad
    dec     eax
    cmp     eax, MAX_PASSWORD_BYTES
    ja      rp_bad
    mov     dword ptr [g_cfg_passlen], eax
    xor     eax, eax
    jmp     rp_ret
rp_bad:
    lea     rcx, [m_badpass]
    lea     rdx, [t_err]
    mov     r8d, MB_OK or MB_ICONERROR
    call    mbox
    mov     eax, 1
rp_ret:
    add     rsp, 80
    pop     rbp
    ret
read_password endp

; =============================================================================
; start_encrypt - validate + launch the ENCRYPT worker
; =============================================================================
; =============================================================================
; ask_output -> eax 0 = a destination was chosen (in g_outpath_w), 1 = cancelled
;
; Encrypting used to put the container next to its input under a name derived
; from it, and say so only afterwards.  That is fine when it is what you wanted
; and unhelpful when it is not, so the name and the place are asked for - once,
; before the password, because where a thing goes is a smaller question than
; committing a secret to it.
;
; The derived name is what the dialog opens with, so accepting it is one click
; and the old behaviour is still the default.
;
; OFN_OVERWRITEPROMPT means the dialog asks about an existing file itself, which
; is why the caller no longer does.
;
; OPENFILENAMEW field offsets are the x64 ones: the pointers are eight bytes and
; the DWORDs that follow them are padded to match.
; =============================================================================
OFN_OVERWRITEPROMPT equ 00000002h
OFN_NOCHANGEDIR     equ 00000008h
OFN_PATHMUSTEXIST   equ 00000800h
OFN_EXPLORER        equ 00080000h
OFN_lStructSize     equ 0
OFN_hwndOwner       equ 8
OFN_lpstrFile       equ 48
OFN_nMaxFile        equ 56
OFN_lpstrTitle      equ 88
OFN_Flags           equ 96
OFN_lpstrDefExt     equ 104

ask_output proc frame
    FRAME_PROLOG 64
    ; A right-DRAG already said where the output goes - that is what dropping on
    ; a folder MEANS - so there is nothing to ask.  The question is for the case
    ; the destination is not otherwise defined; asking anyway turned a gesture
    ; that had answered it into a dialog demanding the same answer twice.
    cmp     dword ptr [g_have_dest], 0
    je      ao_ask
    mov     dword ptr [g_out_chosen], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
ao_ask:
    ; zero the struct: every field this does not set must read as absent
    lea     r10, [g_ofn]
    xor     r9, r9
ao_zero:
    mov     byte ptr [r10+r9], 0
    inc     r9
    cmp     r9, 152
    jb      ao_zero
    mov     dword ptr [r10+OFN_lStructSize], 152
    mov     rax, qword ptr [g_hwnd]
    mov     qword ptr [r10+OFN_hwndOwner], rax
    lea     rax, [g_outpath_w]                  ; opens on the derived name
    mov     qword ptr [r10+OFN_lpstrFile], rax
    mov     dword ptr [r10+OFN_nMaxFile], OUTPATH_CHARS
    lea     rax, [t_saveas]
    mov     qword ptr [r10+OFN_lpstrTitle], rax
    lea     rax, [s_defext_mrk]
    cmp     dword ptr [g_make_zip], 0
    je      ao_ext
    lea     rax, [s_defext_zip]
ao_ext:
    mov     qword ptr [r10+OFN_lpstrDefExt], rax
    mov     dword ptr [r10+OFN_Flags], OFN_OVERWRITEPROMPT or OFN_PATHMUSTEXIST or OFN_NOCHANGEDIR or OFN_EXPLORER
    WINCALL GetSaveFileNameW, addr g_ofn
    test    eax, eax
    jz      ao_cancel
    mov     dword ptr [g_out_chosen], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
ao_cancel:
    ; Cancelled is an answer, not an error: nothing was started, so nothing is
    ; reported.  g_outpath_w still holds the suggestion and is simply unused.
    mov     eax, 1
    FRAME_EPILOG
    ret
ask_output endp

start_encrypt proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    cmp     dword ptr [g_has_file], 0
    je      se_wipe
    ; Where it goes, before what protects it.  build_output only ever makes the
    ; suggestion now; ask_output is what settles it - and it is asked once,
    ; whether this encrypt was reached from the launch path (which asks before
    ; the password) or from the button in a window that was already open.
    cmp     dword ptr [g_out_chosen], 0
    jne     se_haveout
    call    build_output
    call    ask_output
    test    eax, eax
    jnz     se_ret
se_haveout:
    ; unencrypted zip: .zip format + empty password -> no password, skip policy
    cmp     dword ptr [g_make_zip], 0
    je      se_needpw
    ; With the prompt in play the dialog's field is hidden and always empty, so
    ; its length cannot decide this any more - it would make EVERY zip
    ; unencrypted.  Ask, then judge by what came back.
    cmp     dword ptr [g_cfg_securedesk], 0
    jne     se_needpw
    WINCALL GetWindowTextLengthW, qword ptr [g_hpass]
    test    eax, eax
    jnz     se_needpw
    mov     dword ptr [g_cfg_passlen], 0     ; no password -> plain (stored/deflated) zip
    jmp     se_polok
se_needpw:
    ; read the password (private-desktop prompt, or the field when opted out)
    call    read_password
    test    eax, eax
    jnz     se_wipe
    ; an empty password is a legitimate answer for .zip: an unencrypted archive
    cmp     dword ptr [g_cfg_passlen], 0
    jne     @F
    cmp     dword ptr [g_make_zip], 0
    jne     se_polok
@@:
    ; policy
    call    check_password_policy
    test    eax, eax
    jz      se_polok
    lea     rcx, [m_policy]
    lea     rdx, [t_err]
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
    jmp     se_wipe
se_polok:
    lea     rax, [g_filepath_w]
    mov     qword ptr [g_cfg_in], rax
    lea     rax, [g_outpath_w]
    mov     qword ptr [g_cfg_out], rax
    ; No overwrite prompt here any more: the save dialog carries
    ; OFN_OVERWRITEPROMPT, so asking again would be asking twice.
se_launch:
    ; carry the Compress toggle to the engine as an explicit choice
    mov     eax, dword ptr [g_compress_on]
    mov     dword ptr [g_cfg_compress], eax
    mov     dword ptr [g_cfg_compress_set], 1
    call    enter_running
    jmp     se_ret
se_wipe:
    lea     rcx, [g_passw]
    mov     rdx, PWBUF_CHARS
    call    wzero
se_ret:
    add     rsp, 64
    pop     rbp
    ret
start_encrypt endp

; =============================================================================
; start_decrypt - validate + launch the DECRYPT worker
; =============================================================================
start_decrypt proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    ; The container view has no destination edit - it is the encrypt window,
    ; which never had one - so it extracts to the suggestion build_output makes
    ; (the container's path minus ".mrk"), the same default the small dialog
    ; showed.  Choosing somewhere else from this window is not wired up yet.
    cmp     dword ptr [g_container], 0
    je      sd_fromedit
    call    build_output
    jmp     sd_havedest
sd_fromedit:
    ; destination from the edit
    WINCALL GetWindowTextW, qword ptr [g_hdest], addr g_outpath_w, 8000h
    test    eax, eax
    jnz     sd_havedest
    lea     rcx, [m_nodest]
    lea     rdx, [t_err]
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
    jmp     sd_ret
sd_havedest:
    ; ---- extract only what is marked, when anything is -----------------------
    ; Selecting nothing means the whole archive, which is what the button said
    ; before selection existed and what it still says when none is made.  The
    ; flag is cleared FIRST every time: picks survive in the index across a
    ; browse, and a stale one would quietly shrink the next extract.
    call    pick_reset
    cmp     dword ptr [g_container], 0
    je      sd_havepick
    mov     r8d, IDXEF_PICK
    call    container_mark_selected
    test    rax, rax
    jz      sd_havepick
    ; Lift the marks out of the index before anything rebuilds it: do_unpack
    ; re-reads and decrypts the table over g_idxbuf, so a bit set here would be
    ; gone by the time the extraction loop looked for it.
    call    idx_pick_collect
    test    rax, rax
    jz      sd_havepick
    mov     dword ptr [g_pick_active], 1
sd_havepick:
    ; a plain (unencrypted) zip needs no password; extract with an empty one
    cmp     dword ptr [g_is_zip], 0
    je      sd_needpw
    cmp     dword ptr [g_zip_enc], 0
    jne     sd_needpw
    mov     dword ptr [g_cfg_passlen], 0
    jmp     sd_setpaths
sd_needpw:
    call    read_password
    test    eax, eax
    jnz     sd_wipe
sd_setpaths:
    lea     rax, [g_filepath_w]
    mov     qword ptr [g_cfg_in], rax
    lea     rax, [g_outpath_w]
    mov     qword ptr [g_cfg_out], rax
    ; Overwrite prompt only for a single-file output.  This used to claim
    ; archives "extract into a folder, which do_unpack creates/uses without
    ; clobbering existing files", and that was never true: entries are written
    ; with CREATE_ALWAYS, so extracting over a folder REPLACES any file whose
    ; name an entry matches, silently.  The prompt is not extended to archives
    ; here because the question would have to be per file (an archive can
    ; collide with one of a thousand), which is a dialog this window does not
    ; have; it is recorded in docs/SECURITY.md instead of being implied away.
    cmp     dword ptr [g_is_archive], 0
    jne     sd_launch
    WINCALL GetFileAttributesW, addr g_outpath_w
    cmp     eax, -1
    je      sd_launch
    lea     rcx, [m_overwrite]
    lea     rdx, [t_overwrite]
    mov     r8d, MB_OKCANCEL or MB_ICONWARNING
    call    mbox
    cmp     eax, IDOK
    jne     sd_wipe
sd_launch:
    call    enter_running
    jmp     sd_ret
sd_wipe:
    lea     rcx, [g_passw]
    mov     rdx, PWBUF_CHARS
    call    wzero
sd_ret:
    add     rsp, 64
    pop     rbp
    ret
start_decrypt endp

; =============================================================================
; start_operation - dispatch by mode
; =============================================================================
start_operation proc
    sub     rsp, 40
    cmp     dword ptr [g_op], 0
    jne     sop_dec
    ; The split size, resolved HERE rather than read from the setting inside
    ; do_pack, because the setting is a preset index and pack.asm has no business
    ; knowing what the presets are.
    ;
    ; And only for .mrk: the zip writer does not go through the volume layer at
    ; all, so leaving a limit set while Format is zip would be a setting that
    ; silently does nothing.  Cleared rather than refused - the setting is about
    ; how a container is written, and a zip is not one.
    mov     qword ptr [g_vol_limit], 0
    cmp     dword ptr [g_make_zip], 0
    jne     @F
    call    vsplit_bytes
    mov     qword ptr [g_vol_limit], rax
@@:
    call    start_encrypt
    add     rsp, 40
    ret
sop_dec:
    call    start_decrypt
    add     rsp, 40
    ret
start_operation endp

; =============================================================================
; cur_file_item -> eax = index of the file currently being processed (the first
; with done < total), or the last item if all complete, or -1 if the list empty.
; =============================================================================
cur_file_item proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMCOUNT, 0, 0
    test    eax, eax
    jz      cfi_none
    ; count and index through memory: row_progress is a leaf but it clobbers
    ; r10/r11, which is where these used to live
    mov     dword ptr [rbp-8], eax       ; count
    mov     dword ptr [rbp-16], 0        ; i
cfi_loop:
    mov     ecx, dword ptr [rbp-16]
    call    row_progress                 ; rax = done, rdx = total
    test    rdx, rdx
    jz      cfi_next                     ; not started / empty -> skip
    cmp     rax, rdx
    jb      cfi_found                    ; done<total -> active row
cfi_next:
    inc     dword ptr [rbp-16]
    mov     eax, dword ptr [rbp-16]
    cmp     eax, dword ptr [rbp-8]
    jb      cfi_loop
    mov     eax, dword ptr [rbp-8]
    dec     eax                          ; all done -> keep last in view
    jmp     cfi_ret
cfi_found:
    mov     eax, dword ptr [rbp-16]
    jmp     cfi_ret
cfi_none:
    mov     eax, -1
cfi_ret:
    add     rsp, 48
    pop     rbp
    ret
cur_file_item endp

; =============================================================================
; on_timer - update the progress bar from g_prog_done / g_prog_total
; =============================================================================
; =============================================================================
; drag_prog_show(ecx = 1 show / 0 hide) and drag_prog_tick - the bar during a
; drag-out, called from es_drag and ES_Read.
;
; The bar is created ST_BARHIDE and only ever shown for an operation, so the
; first version of this drove counters at a control nobody could see. Showing it
; is half the job; the other half is that the repaint CANNOT rely on the 100ms
; timer, because DoDragDrop runs its own modal loop and a modal loop is not
; obliged to dispatch WM_TIMER to us. So the tick paints synchronously, the same
; way on_done's final 100% does.
;
; Safe because the reads arrive on THIS thread: DoDragDrop is synchronous on the
; thread that owns the listing (docs/DRAG_OUT.md Â§4). UpdateWindow from another
; thread would not be.
; =============================================================================
; =============================================================================
; drag_rows_mark(ecx = 1 arm / 0 clear) - make the per-row bars follow a drag.
;
; The row cell already draws from row_progress, which reads
; g_file_done/g_file_total indexed by ROW_inputi.  In the container view nothing
; ever stamped that field, so every row read input 0, whose total was 0 - an
; empty track, which is what "the total bar moves but the file's does not" was.
;
; Per-ENTRY attribution is not available: those arrays are MAX_ARGS long because
; they were built for command-line inputs, and a container has far more entries
; than that.  So the dragged rows share input 0 and fill TOGETHER, and every
; other row is stamped past MAX_ARGS so row_progress returns nothing for it.
;
; That is deliberately the same coarseness row_progress already documents for an
; expanded folder, and for the same reason: showing a file finished before its
; bytes have been handed over would be worse than being honestly coarse. For the
; usual case - dragging one file - coarse and exact are the same thing.
; =============================================================================
public drag_rows_mark
drag_rows_mark proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    ; The counter lives on the stack the whole way round: SendMessageW clobbers
    ; every volatile, and keeping it in one was the first version of this loop.
    mov     dword ptr [rbp-8], ecx
    mov     qword ptr [rbp-16], 0
dm_loop:
    mov     rax, qword ptr [rbp-16]
    cmp     rax, qword ptr [g_rowcount]
    jae     dm_done
    cmp     dword ptr [rbp-8], 0
    je      dm_clear
    ; armed: selected rows take input 0, the rest are put out of range
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETITEMSTATE, qword ptr [rbp-16], LVIS_SELECTED
    mov     dword ptr [rbp-24], eax
    mov     rax, qword ptr [rbp-16]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    test    dword ptr [rbp-24], LVIS_SELECTED
    jz      dm_out
    mov     dword ptr [r10+ROW_inputi], 0
    jmp     dm_next
dm_out:
    mov     dword ptr [r10+ROW_inputi], MAX_ARGS
    jmp     dm_next
dm_clear:
    mov     rax, qword ptr [rbp-16]
    imul    rax, rax, ROW_SIZE
    lea     r10, [g_rows]
    add     r10, rax
    mov     dword ptr [r10+ROW_inputi], 0
dm_next:
    inc     qword ptr [rbp-16]
    jmp     dm_loop
dm_done:
    add     rsp, 48
    pop     rbp
    ret
drag_rows_mark endp

public drag_prog_show
drag_prog_show proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    test    ecx, ecx
    jz      dps_hide
    WINCALL ShowWindow, qword ptr [g_hprog], SW_SHOW
    jmp     dps_ret
dps_hide:
    WINCALL ShowWindow, qword ptr [g_hprog], SW_HIDE
    ; the tick below writes "Decrypting NN% ..." over the status line, and a
    ; drag that has ended is not decrypting anything
    WINCALL SetWindowTextW, qword ptr [g_hstatus], addr s_ready
dps_ret:
    add     rsp, 48
    pop     rbp
    ret
drag_prog_show endp

public drag_prog_tick
drag_prog_tick proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     rax, qword ptr [g_prog_total]
    test    rax, rax
    jz      dpt_ret                      ; nothing promised: nothing to draw
    mov     rax, qword ptr [g_prog_done]
    mov     r8, 100
    mul     r8
    mov     r8, qword ptr [g_prog_total]
    xor     edx, edx
    div     r8
    cmp     rax, 100
    jbe     @F
    mov     rax, 100
@@:
    cmp     eax, dword ptr [g_prog_pct]
    jne     dpt_paint
    ; Unchanged percent: no repaint per read - that is this gate's point.  But
    ; the rate and the eta move anyway, so the TEXT refreshes once a second.
    ; This tick was the bar's ONLY driver during a drag (DoDragDrop's modal
    ; loop need not dispatch our WM_TIMER, so on_timer - the proc that writes
    ; the status line everywhere else - never ran), which is why a drag-out
    ; decrypt moved the bar while the text sat on "Ready" for the whole job.
    WINCALL GetTickCount64
    sub     rax, qword ptr [g_drag_txtms]
    cmp     rax, 1000
    jb      dpt_ret
    jmp     dpt_text
dpt_paint:
    mov     dword ptr [g_prog_pct], eax
    WINCALL InvalidateRect, qword ptr [g_hprog], 0, 0
    WINCALL UpdateWindow, qword ptr [g_hprog]
    ; and the list, whose per-row cells read the same counters.  bErase=FALSE:
    ; the list is double-buffered, exactly as on_timer does it.
    WINCALL InvalidateRect, qword ptr [g_hlist], 0, 0
    WINCALL UpdateWindow, qword ptr [g_hlist]
dpt_text:
    WINCALL GetTickCount64
    mov     qword ptr [g_drag_txtms], rax
    mov     ecx, dword ptr [g_prog_pct]
    call    set_status_pct
    ; synchronously, like the bar: the modal loop owes us no WM_PAINT either
    WINCALL UpdateWindow, qword ptr [g_hstatus]
dpt_ret:
    add     rsp, 48
    pop     rbp
    ret
drag_prog_tick endp

on_timer proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    cmp     dword ptr [g_running], 0
    je      ot_done
    ; repaint the per-file progress cells (encrypt-mode listview)
    cmp     dword ptr [g_op], 0
    jne     ot_nolist
    cmp     qword ptr [g_hlist], 0
    je      ot_nolist
    WINCALL InvalidateRect, qword ptr [g_hlist], 0, 0    ; bErase=FALSE (double-buffered)
    ; auto-scroll so the file currently being processed stays in view
    call    cur_file_item
    cmp     eax, 0
    jl      ot_nolist
    movsxd  rax, eax
    mov     rcx, rax
    call    lv_ensure_visible            ; not LVM_ENSUREVISIBLE - see that proc
ot_nolist:
    mov     rax, qword ptr [g_prog_total]
    test    rax, rax
    jz      ot_done
    mov     rcx, qword ptr [g_prog_done]
    mov     rax, rcx
    mov     r8, 100
    mul     r8
    mov     r8, qword ptr [g_prog_total]
    xor     edx, edx
    div     r8
    cmp     eax, 100
    jbe     @F
    mov     eax, 100
@@:
    mov     dword ptr [rbp-8], eax
    mov     dword ptr [g_prog_pct], eax
    WINCALL InvalidateRect, qword ptr [g_hprog], 0, 0    ; bErase=FALSE
    mov     ecx, dword ptr [rbp-8]
    call    set_status_pct
ot_done:
    add     rsp, 48
    pop     rbp
    ret
on_timer endp

; =============================================================================
; set_status_pct(ecx = percent) - status text = "<prefix>NN%"
; =============================================================================
set_status_pct proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     dword ptr [rbp-8], ecx
    ; The control is 187 px wide at the default window size (LV_W - STAT_W - 8)
    ; and "Encrypting  69%   303.3 MB/s   ETA 0:07" needs ~250 - the user's
    ; screenshot showed it clipped at "ETA 0:".  Once the rate is measurable
    ; the prefix goes: a percent flanked by MB/s and an ETA needs no
    ; introduction, and the ~70 px it frees is exactly the tail that was cut.
    call    prog_speed_x10
    test    rax, rax
    jnz     ssp_bare
    lea     rcx, [g_statusw]
    lea     rdx, [s_pfx_enc]
    cmp     dword ptr [g_op], 0
    jne     ssp_dec
    ; the post-encrypt browse window keeps g_op = 0, but a drag-out from it is
    ; still a decrypt - and the drag tick is a caller of this proc now
    cmp     dword ptr [g_drag_prog], 0
    je      @F
ssp_dec:
    lea     rdx, [s_pfx_dec]
@@:
    WBOUND  r8, g_statusw, STATUSW_CHARS
    call    wcopy
    mov     r11, rax
    jmp     ssp_digits
ssp_bare:
    lea     r11, [g_statusw]
ssp_digits:
    mov     eax, dword ptr [rbp-8]
    lea     r10, [rbp-12]
    mov     ecx, 10
ssp_div:
    xor     edx, edx
    div     ecx
    add     dl, '0'
    dec     r10
    mov     byte ptr [r10], dl
    test    eax, eax
    jnz     ssp_div
ssp_cpy:
    movzx   eax, byte ptr [r10]
    mov     word ptr [r11], ax
    add     r11, 2
    inc     r10
    lea     rdx, [rbp-12]
    cmp     r10, rdx
    jb      ssp_cpy
    mov     word ptr [r11], '%'
    mov     word ptr [r11+2], 0
    ; rate and eta, when measurable - on_timer calls this every 100ms while an
    ; operation runs, so the readout ticks live
    lea     rcx, [r11+2]
    call    status_append_rate
    WINCALL SetWindowTextW, qword ptr [g_hstatus], addr g_statusw
    add     rsp, 48
    pop     rbp
    ret
set_status_pct endp

; =============================================================================
; on_done - worker finished (WM_APP_DONE).  Show result, restore UI.
; =============================================================================
on_done proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    WINCALL KillTimer, qword ptr [g_hwnd], 1
    mov     dword ptr [g_running], 0
    ; The Exit button comes back ON EVERY completion path, before any of them
    ; branch.  A REMOVAL (job 2) deliberately disables it at the start - it
    ; doubles as Cancel while a job runs, and a removal cannot be cleanly undone
    ; half way, so offering Cancel would be a lie.  But nothing ever turned it
    ; back on: od_c_reload restores g_haction and g_hpass, od_restore those plus
    ; three more, and neither touches this one.
    ;
    ; So after ANY removal - refused, failed or perfectly successful - the Exit
    ; button stayed dead for the life of the window. Reported twice as "the Exit
    ; button stopped working", and it was never about volume sets: those merely
    ; made the removal fail fast enough to notice the button had gone. ESC still
    ; closed the window because the accelerator posts ID_CANCEL straight to the
    ; wndproc without asking the button whether it is enabled - which is exactly
    ; why this looked like a phantom for two rounds.
    ;
    ; Here rather than in the two restore blocks, because the reason it is
    ; disabled belongs to the JOB, and the job is over at this line.
    WINCALL EnableWindow, qword ptr [g_hcancel], 1
    ; The statistics line carries the verdict from here on.  Cancelled is not
    ; failed - the user asked for it - so only a real error turns it red.
    mov     eax, dword ptr [g_op_result]
    cmp     dword ptr [g_cancelled], 0
    je      @F
    xor     eax, eax
@@:
    test    eax, eax
    setne   al
    movzx   eax, al
    mov     dword ptr [g_scan_fail], eax
    ; Guarded: the DECRYPT window has no statistics line, and InvalidateRect
    ; with a null HWND does not mean "nothing" - it means the whole desktop.
    cmp     qword ptr [g_hscan], 0
    je      @F
    WINCALL InvalidateRect, qword ptr [g_hscan], 0, 1
@@:
    ; Close the action log: when it ended, how much it covered, how it went.
    ; BEFORE the branch, so a container edit gets a trailer too - that path
    ; returns without ever reaching the code below it.
    mov     ecx, dword ptr [g_op_result]
    mov     edx, dword ptr [g_cancelled]
    call    rlog_finish
    ; A right-drag ends in its own window, not this one.  Nothing below here
    ; applies: no result box (the log says it, and better), no switch to the
    ; archive (the gesture did not ask to browse anything), no restoring a
    ; window that was never shown.
    cmp     qword ptr [g_pg_hwnd], 0
    je      @F
    call    progwin_finish
    add     rsp, 48
    pop     rbp
    ret
@@:
    cmp     dword ptr [g_wt_job], 0
    jne     od_container
    ; ---- audit log: GUI operation result -> Event Log (skip if cancelled) ---
    cmp     dword ptr [g_cancelled], 0
    jne     od_nolog
    lea     rcx, [lg_op_enc]
    cmp     dword ptr [g_op], 0
    je      @F
    lea     rcx, [lg_op_dec]
@@:
    mov     edx, dword ptr [g_op_result]
    call    log_result
od_nolog:
    ; paint the per-file bars at their FINAL state (full on success) before the
    ; modal result box - the 100ms timer may never have ticked on a fast job.
    cmp     dword ptr [g_op], 0
    jne     od_norepaint
    cmp     qword ptr [g_hlist], 0
    je      od_norepaint
    WINCALL InvalidateRect, qword ptr [g_hlist], 0, 0
    WINCALL UpdateWindow, qword ptr [g_hlist]    ; force the repaint now (before mbox)
od_norepaint:
    ; force the operation bar + status to 100% on success: the 100ms timer may
    ; not have ticked at the final progress_add (especially for bursty/fast zip
    ; jobs), leaving the bar frozen short of the end.
    cmp     dword ptr [g_cancelled], 0
    jne     od_nofull
    cmp     dword ptr [g_op_result], 0
    jne     od_nofull
    mov     dword ptr [g_prog_pct], 100
    WINCALL InvalidateRect, qword ptr [g_hprog], 0, 0
    WINCALL UpdateWindow, qword ptr [g_hprog]
    mov     ecx, 100
    call    set_status_pct
od_nofull:
    cmp     dword ptr [g_cancelled], 0
    je      od_chkok
    lea     rcx, [m_cancelled]
    lea     rdx, [t_cancel]
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
    jmp     od_restore
od_chkok:
    cmp     dword ptr [g_op_result], 0
    jne     od_err
    ; ---- no "Myrkr - done" box: the work ends with the window open ----------
    ; It was a modal box whose whole content was "Saved to: <path>", and the
    ; only thing you could do with it was dismiss it before you could look at
    ; anything.  What it said has not been lost - the tool prints that same
    ; path, so it is in the action log the statistics line opens, one click
    ; away instead of one click in the way.
    ;
    ; An ENCRYPT leaves the window showing what it produced, so "add a file to
    ; it" means the same thing before and after the archive exists.  Decrypt
    ; keeps the old ending: what it produced is a folder, not something this
    ; window browses.
    cmp     dword ptr [g_op], 0
    jne     od_restore
    call    switch_to_output
    add     rsp, 48
    pop     rbp
    ret
od_err:
    mov     eax, dword ptr [g_op_result]
    lea     rcx, [m_io]
    cmp     eax, EXIT_AUTH
    jne     @F
    lea     rcx, [m_auth]
@@:
    cmp     eax, EXIT_CORRUPT
    jne     @F
    lea     rcx, [m_corrupt]
@@:
    cmp     eax, EXIT_OOM
    jne     @F
    lea     rcx, [m_oom]
@@:
    cmp     eax, EXIT_USAGE
    jne     @F
    lea     rcx, [m_policy]
@@:
    cmp     eax, EXIT_NOSPACE
    jne     @F
    lea     rcx, [m_nospace]
@@:
    ; LAST, so it wins over every cause above.  An extraction that stopped part
    ; way leaves files on disk, and "authentication failed" alone would let the
    ; user look at a folder with files in it and conclude the failure was about
    ; something else.
    cmp     dword ptr [g_unpack_partial], 0
    je      @F
    lea     rcx, [m_part_extract]
@@:
    lea     rdx, [t_err]
    mov     r8d, MB_OK or MB_ICONERROR
    call    mbox
; ---- a container edit finished ---------------------------------------------
; Deliberately NOT od_restore: that path wipes g_cfg_pass, and the container view
; holds the password for the life of the window so a second add does not prompt
; again.  Wiping it here would make the next Add fail with no explanation.
;
; It also undoes what enter_running did FOR THIS JOB - the action button and the
; password edit, and the progress bar.
;
; That last one was missing, and this comment used to be why: it claimed "a
; container edit never showed the progress bar", which stopped being true when
; Add started totalling its inputs and driving the bar.  So an Add left the bar
; on screen frozen at whatever the last 100ms tick had sampled - typically some
; way short of the end, because the tick before the job finished is up to a
; tenth of a second old.  It read as a bar that had computed the wrong answer,
; and it stayed there until the next operation.
;
; Hidden rather than forced to 100 first: nothing pauses between here and the
; reload, so a full bar would be painted and removed in the same breath.  What
; says the add worked is the tree coming back with the files in it.
od_container:
    WINCALL ShowWindow, qword ptr [g_hprog], SW_HIDE
    mov     dword ptr [g_prog_pct], 0        ; so the next run cannot flash this one
    mov     rax, qword ptr [g_ca_poscount]
    test    rax, rax
    jz      @F
    mov     qword ptr [g_poscount], rax     ; the picked paths were arguments
    mov     qword ptr [g_ca_poscount], 0
@@:
    ; the key was derived on the UI thread and used on the worker; it dies here
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
    cmp     dword ptr [g_op_result], 0
    je      od_c_reload
    ; Cancelled is not failed: the rollback already put the archive back, and a
    ; box saying it did not work would describe the user's own decision as a
    ; fault.
    cmp     dword ptr [g_cancelled], 0
    jne     od_c_reload
    cmp     dword ptr [g_wt_job], 1
    jne     od_c_remerr
    ; A name already in the archive is the one failure a user can act on, so it
    ; gets its own sentence rather than the generic one.
    lea     rcx, [m_add_fail]
    lea     rdx, [t_add_fail]
    cmp     dword ptr [g_op_result], EXIT_USAGE
    jne     @F
    lea     rcx, [m_add_dup]
@@:
    ; A volume set refuses the edit before anything is written, and that is the
    ; second failure here a user can act on - so it says what it is rather than
    ; guessing at a locked file or a full disk.
    ; A volume set refuses the edit before anything is written, and that is the
    ; second failure here a user can act on - so it says what it is rather than
    ; guessing at a locked file or a full disk.
    cmp     dword ptr [g_op_result], EXIT_UNSUPPORTED
    jne     @F
    lea     rcx, [m_vol_edit]
    lea     rdx, [t_vol_edit]
@@:
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
    jmp     od_c_reload
od_c_remerr:
    ; A .mrk normally reports its own removal errors in place, so this path is
    ; the zip's - except for the volume-set refusal, which nothing else surfaces.
    ; Without this, REMOVING from a set failed silently: the entry stayed, no box
    ; appeared, and nothing said why.
    cmp     dword ptr [g_op_result], EXIT_UNSUPPORTED
    jne     od_c_remzip
    cmp     dword ptr [g_is_zip], 0
    jne     od_c_remzip
    lea     rcx, [m_vol_edit]
    lea     rdx, [t_vol_edit]
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
    jmp     od_c_reload
od_c_remzip:
    cmp     dword ptr [g_is_zip], 0
    je      od_c_reload                     ; the .mrk path reports in place
    ; Say which of the two it was.  "It did not work" is the same sentence for an
    ; archive that is untouched and one whose only copy is now under another
    ; name, and those need different things from the user.
    lea     rcx, [m_zip_io]
    lea     rdx, [t_zip_del]
    cmp     dword ptr [g_op_result], EXIT_UNSUPPORTED
    jne     @F
    lea     rcx, [m_zip_norw]
@@:
    cmp     dword ptr [g_op_result], EXIT_PARTIAL
    jne     @F
    lea     rcx, [m_zip_part]
    lea     rdx, [t_zip_part]
@@:
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
od_c_reload:
    ; Cleared BEFORE anything can start another job, or the next Encrypt would
    ; run down this branch instead of the crypto one.
    mov     dword ptr [g_wt_job], 0
    WINCALL EnableWindow, qword ptr [g_haction], 1
    WINCALL EnableWindow, qword ptr [g_hpass], 1
    ; Open the folder it went into BEFORE reloading, so the rebuilt tree shows
    ; what arrived.  container_load seeds the top level only, which leaves an
    ; add into a collapsed folder invisible.
    call    container_expand_prefix
    call    container_load
    add     rsp, 48
    pop     rbp
    ret

od_restore:
    ; final repaint of the per-file bars (full on success, partial otherwise)
    cmp     dword ptr [g_op], 0
    jne     @F
    cmp     qword ptr [g_hlist], 0
    je      @F
    WINCALL InvalidateRect, qword ptr [g_hlist], 0, 0
@@:
    WINCALL ShowWindow, qword ptr [g_hprog], SW_HIDE
    WINCALL EnableWindow, qword ptr [g_haction], 1
    WINCALL EnableWindow, qword ptr [g_hpass], 1
    cmp     qword ptr [g_hconfirm], 0
    je      @F
    WINCALL EnableWindow, qword ptr [g_hconfirm], 1
@@:
    cmp     qword ptr [g_hdest], 0
    je      @F
    WINCALL EnableWindow, qword ptr [g_hdest], 1
    WINCALL EnableWindow, qword ptr [g_hchange], 1
@@:
    ; (Exit button stays enabled throughout)
    WINCALL SetWindowTextW, qword ptr [g_hstatus], addr s_ready
    ; clear password fields + buffers
    mov     word ptr [g_statusw], 0
    WINCALL SetWindowTextW, qword ptr [g_hpass], addr g_statusw
    cmp     qword ptr [g_hconfirm], 0
    je      @F
    WINCALL SetWindowTextW, qword ptr [g_hconfirm], addr g_statusw
@@:
    lea     rcx, [g_passw]
    mov     rdx, PWBUF_CHARS
    call    wzero
    lea     rcx, [g_confirmw]
    mov     rdx, PWBUF_CHARS
    call    wzero
    lea     rcx, [g_cfg_pass]
    xor     r9, r9
od_wp:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, MAX_PASSWORD_BYTES+1
    jb      od_wp
    ; refresh the strength UI back to the empty state (encrypt mode)
    cmp     dword ptr [g_op], 0
    jne     od_fin
    call    update_strength
od_fin:
    add     rsp, 48
    pop     rbp
    ret
on_done endp


; =============================================================================
; lv_fill_row(rcx = NMCUSTOMDRAW*) - paint the whole row rect the list's own
; background before the control draws the row.
;
; This is what removes the vertical column rules.  They are not gridlines -
; LVS_EX_GRIDLINES is not set - and nothing here draws them: comctl32 v6 fills
; each SUBITEM rect with the LVM_SETBKCOLOR colour and leaves a one-pixel column
; between them unpainted, so the themed listview background shows through as a
; hairline.  It was invisible under v5 because the whole row was filled in one
; go.  Painting the row first means those gaps are already the right colour when
; the control leaves them alone.
;
; locals (frame 64): hdc[-8] rc[-32..-17]
; =============================================================================
lv_fill_row proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     rax, qword ptr [rcx+NMCD_hdc]
    mov     qword ptr [rbp-8], rax
    mov     eax, dword ptr [rcx+NMCD_rc+0]
    mov     dword ptr [rbp-32], eax
    mov     eax, dword ptr [rcx+NMCD_rc+4]
    mov     dword ptr [rbp-28], eax
    mov     eax, dword ptr [rcx+NMCD_rc+8]
    mov     dword ptr [rbp-24], eax
    mov     eax, dword ptr [rcx+NMCD_rc+12]
    mov     dword ptr [rbp-20], eax
    WINCALL FillRect, qword ptr [rbp-8], addr rbp-32, qword ptr [g_hbr_dark]
    add     rsp, 64
    pop     rbp
    ret
lv_fill_row endp


; =============================================================================
; make_theme - create the Fluent palette brushes (once, before RegisterClass)
; =============================================================================
make_theme proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    WINCALL CreateSolidBrush, CLR_SURFACE
    mov     qword ptr [g_hbr_surface], rax
    WINCALL CreateSolidBrush, CLR_DARK
    mov     qword ptr [g_hbr_dark], rax
    WINCALL CreateSolidBrush, CLR_FIELD
    mov     qword ptr [g_hbr_field], rax
    WINCALL CreateSolidBrush, CLR_NEUTRAL
    mov     qword ptr [g_hbr_neutral], rax
    WINCALL CreateSolidBrush, CLR_VALID
    mov     qword ptr [g_hbr_valid], rax
    WINCALL CreateSolidBrush, CLR_INVALID
    mov     qword ptr [g_hbr_invalid], rax
    ; underline palette, contiguous so a grade can index it directly
    mov     rax, qword ptr [g_hbr_neutral]
    mov     qword ptr [g_ubr+0], rax             ; 0 neutral
    mov     rax, qword ptr [g_hbr_invalid]
    mov     qword ptr [g_ubr+8], rax             ; 1 red
    WINCALL CreateSolidBrush, CLR_BAR_AMBER
    mov     qword ptr [g_ubr+16], rax            ; 2 amber
    WINCALL CreateSolidBrush, CLR_BAR_LGREEN
    mov     qword ptr [g_ubr+24], rax            ; 3 light green
    WINCALL CreateSolidBrush, CLR_BAR_DGREEN
    mov     qword ptr [g_ubr+32], rax            ; 4 deep green
    WINCALL CreateSolidBrush, CLR_ACCENT
    mov     qword ptr [g_hbr_accent], rax
    WINCALL CreateSolidBrush, CLR_LV_TRACK
    mov     qword ptr [g_hbr_track], rax
    add     rsp, 48
    pop     rbp
    ret
make_theme endp

; =============================================================================
; draw_lv_progress(rcx = NMLVCUSTOMDRAW*) - paint the per-file progress bar in
; the listview "Progress" cell (subitem 2) for the given row.  Flat, solid,
; borderless: a light track filled left-to-right by g_file_done/g_file_total.
; locals (frame 128): nm[-8] hdc[-16] row[-24] rc[-40..-25] cellw[-44]
;   fillrc[-72..-57]
; =============================================================================
draw_lv_progress proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    mov     qword ptr [rbp-8], rcx
    mov     rax, qword ptr [rcx+NMCD_hdc]
    mov     qword ptr [rbp-16], rax
    mov     rax, qword ptr [rcx+NMCD_dwItemSpec]
    mov     qword ptr [rbp-24], rax        ; row index
    ; --- cell rect: LVM_GETSUBITEMRECT(row, &rc{top=2,left=LVIR_BOUNDS}) ------
    mov     dword ptr [g_lvrc+0], LVIR_BOUNDS  ; left field doubles as flags in
    mov     dword ptr [g_lvrc+4], 2            ; top  field doubles as subitem #
    WINCALL SendMessageW, qword ptr [g_hlist], LVM_GETSUBITEMRECT, qword ptr [rbp-24], addr g_lvrc
    ; copy + inset the rect into a RECT at [rbp-40..-25] (left,top,right,bottom)
    mov     eax, dword ptr [g_lvrc+0]
    add     eax, PROG_INSET
    mov     dword ptr [rbp-40], eax        ; left
    mov     eax, dword ptr [g_lvrc+4]
    add     eax, PROG_INSET
    mov     dword ptr [rbp-36], eax        ; top
    mov     eax, dword ptr [g_lvrc+8]
    sub     eax, PROG_INSET
    ; ...and held clear of the overlay scrollbar, which is drawn ON TOP of the
    ; rows rather than beside them, so the cell rect knows nothing about it and
    ; a full-width bar runs straight under the thumb.  Clamped rather than
    ; always shortened: a list with nothing to scroll keeps the full cell.
    mov     r10, qword ptr [g_lay_lvw]
    sub     r10, LVSB_INSET + LVSB_W + PROG_SBGAP
    cmp     eax, r10d
    jle     @F
    mov     eax, r10d
@@:
    mov     dword ptr [rbp-32], eax        ; right
    mov     eax, dword ptr [g_lvrc+12]
    sub     eax, PROG_INSET
    mov     dword ptr [rbp-28], eax        ; bottom
    ; cellw = right - left
    mov     eax, dword ptr [rbp-32]
    sub     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-44], eax
    cmp     eax, 2                          ; degenerate cell -> nothing to draw
    jle     dlp_ret
    ; --- track: solid light fill, no border ---------------------------------
    WINCALL FillRect, qword ptr [rbp-16], addr rbp-40, qword ptr [g_hbr_track]
    ; --- fill width = cellw * done / total ----------------------------------
    mov     rcx, qword ptr [rbp-24]         ; row
    call    row_progress                    ; rax = done, rdx = total (per INPUT)
    mov     r10, rdx
    test    r10, r10
    jz      dlp_ret                         ; total 0 -> empty track only
    cmp     rax, r10
    jb      @F
    mov     rax, r10                        ; clamp done<=total
@@:
    movsxd  r8, dword ptr [rbp-44]          ; cellw
    mul     r8                              ; rdx:rax = done*cellw
    div     r10                             ; rax = fillw
    test    eax, eax
    jz      dlp_ret
    ; accent fill: solid rect [left,top,left+fillw,bottom] at [rbp-72..-57]
    mov     ecx, dword ptr [rbp-40]
    mov     dword ptr [rbp-72], ecx        ; left
    mov     ecx, dword ptr [rbp-36]
    mov     dword ptr [rbp-68], ecx        ; top
    mov     ecx, dword ptr [rbp-40]
    add     ecx, eax
    mov     dword ptr [rbp-64], ecx        ; left + fillw
    mov     ecx, dword ptr [rbp-28]
    mov     dword ptr [rbp-60], ecx        ; bottom
    WINCALL FillRect, qword ptr [rbp-16], addr rbp-72, qword ptr [g_hbr_accent]
dlp_ret:
    add     rsp, 128
    pop     rbp
    ret
draw_lv_progress endp

; =============================================================================
; draw_bar(rcx = DRAWITEMSTRUCT*) - flat, solid, borderless progress bar for the
; strength meter (ID_STRENGTH) and the operation bar (ID_PROG).  Reads its fill
; percent + colour from globals keyed by the control id.
; locals (frame 128): di[-8] id[-12] hdc[-16] rc[-40..-25] pct[-44] color[-48]
;   fillrc[-72..-57] brush[-80] freebrush[-84]
; (frame must keep the deepest local above the 32-byte outgoing shadow space.)
; =============================================================================
draw_bar proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    mov     qword ptr [rbp-8], rcx
    mov     eax, dword ptr [rcx+DI_CTLID]
    mov     dword ptr [rbp-12], eax
    mov     rax, qword ptr [rcx+DI_HDC]
    mov     qword ptr [rbp-16], rax
    ; copy rcItem -> RECT [rbp-40..-25]
    mov     rcx, qword ptr [rbp-8]
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-40], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [rbp-36], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-32], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-28], eax
    ; pct + colour by control id (default = operation bar / accent)
    mov     eax, dword ptr [g_prog_pct]
    mov     r8d, CLR_ACCENT
    cmp     dword ptr [rbp-12], ID_STRENGTH
    jne     @F
    mov     eax, dword ptr [g_strength_pct]
    mov     r8d, dword ptr [g_strength_clr]
@@:
    mov     dword ptr [rbp-44], eax
    mov     dword ptr [rbp-48], r8d
    ; track: solid light fill, no border
    WINCALL FillRect, qword ptr [rbp-16], addr rbp-40, qword ptr [g_hbr_track]
    ; fillw = (right-left) * pct / 100
    mov     eax, dword ptr [rbp-32]
    sub     eax, dword ptr [rbp-40]
    imul    eax, dword ptr [rbp-44]
    xor     edx, edx
    mov     ecx, 100
    div     ecx                            ; eax = fillw
    test    eax, eax
    jz      db_done
    ; fill rect [left,top,left+fillw,bottom] at [rbp-72..-57]
    mov     ecx, dword ptr [rbp-40]
    mov     dword ptr [rbp-72], ecx
    mov     ecx, dword ptr [rbp-36]
    mov     dword ptr [rbp-68], ecx
    mov     ecx, dword ptr [rbp-40]
    add     ecx, eax
    mov     dword ptr [rbp-64], ecx
    mov     ecx, dword ptr [rbp-28]
    mov     dword ptr [rbp-60], ecx
    ; fill brush: operation bar reuses g_hbr_accent; strength makes one per paint
    cmp     dword ptr [rbp-12], ID_STRENGTH
    je      db_strbrush
    mov     rax, qword ptr [g_hbr_accent]
    mov     qword ptr [rbp-80], rax
    mov     dword ptr [rbp-84], 0
    jmp     db_fill
db_strbrush:
    WINCALL CreateSolidBrush, dword ptr [rbp-48]
    mov     qword ptr [rbp-80], rax
    mov     dword ptr [rbp-84], 1
db_fill:
    WINCALL FillRect, qword ptr [rbp-16], addr rbp-72, qword ptr [rbp-80]
    cmp     dword ptr [rbp-84], 0
    je      db_done
    WINCALL DeleteObject, qword ptr [rbp-80]
db_done:
    add     rsp, 128
    pop     rbp
    ret
draw_bar endp

; =============================================================================
; subclass_edit(rcx = edit hwnd) - install the placeholder subclass on an edit.
; The original proc (identical for every EDIT) is cached in g_oldeditproc.
; =============================================================================
subclass_edit proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    WINCALL SetWindowLongPtrW, rcx, GWLP_WNDPROC, addr edit_subclass
    mov     qword ptr [g_oldeditproc], rax
    add     rsp, 48
    pop     rbp
    ret
subclass_edit endp

; =============================================================================
; subclass_list(rcx = listview hwnd) - make the (non-selectable) file list
; "drag-through": its clicks fall to the parent so the window can be moved by
; the list area.  The original proc is cached in g_oldlistproc.
; =============================================================================
; =============================================================================
; enable_dark_mode - switch this PROCESS to dark mode so that the themed common
; controls draw their dark variants.
;
; SetWindowTheme(list, "DarkMode_Explorer") does nothing on its own.  The theme
; class only resolves to its dark form once uxtheme has been told the process
; prefers dark, and there is no documented way to say so.  The two calls that do
; it are exported BY ORDINAL ONLY, with no names in the export table:
;
;     ord 135   SetPreferredAppMode(PreferredAppMode)   (1809: AllowDarkModeForApp)
;     ord 133   AllowDarkModeForWindow(HWND, BOOL)
;
; Both arrived in Windows 10 1809 (build 17763) and have kept their ordinals
; through Windows 11.  Undocumented is still undocumented, so this is guarded on
; both sides: the OS build number is read from the PEB before uxtheme is even
; loaded (below 17763 those ordinals are entirely different functions and
; calling them would be a genuine hazard), and each resolved pointer is
; null-checked before use.  If any step fails the scrollbar simply stays light -
; which is what it looked like before this existed, so the failure is cosmetic.
;
; PreferredAppMode: 0 Default, 1 AllowDark, 2 ForceDark, 3 ForceLight.  ForceDark
; is the right one here: this window is dark whatever the desktop is set to, and
; AllowDark would leave the bar light for anyone running a light theme.
;
; locals (frame 48): fn[-8]
; =============================================================================
enable_dark_mode proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    ; PEB via the TEB (gs:[60h]): OSMajorVersion +118h, OSBuildNumber +120h (16-bit)
    mov     rax, gs:[060h]
    cmp     dword ptr [rax+0118h], 10
    jb      edm_ret
    movzx   ecx, word ptr [rax+0120h]
    cmp     ecx, 17763
    jb      edm_ret
    WINCALL LoadLibraryW, addr s_uxtheme_dll
    test    rax, rax
    jz      edm_ret
    mov     qword ptr [g_uxtheme], rax
    ; GetProcAddress takes an ordinal as a bare integer in place of the name
    WINCALL GetProcAddress, qword ptr [g_uxtheme], 135
    test    rax, rax
    jz      edm_wnd
    mov     qword ptr [rbp-8], rax
    mov     ecx, 2                               ; ForceDark
    call    qword ptr [rbp-8]
edm_wnd:
    WINCALL GetProcAddress, qword ptr [g_uxtheme], 133
    mov     qword ptr [g_darkwndfn], rax         ; 0 is handled by dark_mode_window
edm_ret:
    add     rsp, 48
    pop     rbp
    ret
enable_dark_mode endp

; =============================================================================
; dark_mode_window(rcx = hwnd) - opt one window into the dark mode that
; enable_dark_mode turned on for the process.  A no-op when the ordinal did not
; resolve.  Must come BEFORE that window's SetWindowTheme, which is when the
; theme handle is opened and the preference read.
; =============================================================================
dark_mode_window proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     rax, qword ptr [g_darkwndfn]
    test    rax, rax
    jz      dmw_ret
    mov     edx, 1                               ; allow = TRUE
    call    rax                                  ; rcx is already the hwnd
dmw_ret:
    add     rsp, 48
    pop     rbp
    ret
dark_mode_window endp

subclass_list proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    WINCALL SetWindowLongPtrW, rcx, GWLP_WNDPROC, addr list_subclass
    mov     qword ptr [g_oldlistproc], rax
    add     rsp, 48
    pop     rbp
    ret
subclass_list endp

; =============================================================================
; scrollbar_eval(rcx = listview hwnd) - show the vertical scrollbar exactly
; while the pointer is inside the strip it occupies, and hide it otherwise.
;
; This is deliberately stateless about WHICH message asked: it reads the cursor
; and the list's window rect, both in screen coordinates, and derives the answer.
; Every earlier attempt reasoned from the message's own coordinates instead and
; broke on the same thing - the control is scrolled, so its client coordinates
; mean something different from one moment to the next.  Screen coordinates do
; not move.
;
; Never hidden mid-drag: a thumb drag that wanders off the strip - which is most
; of them - would otherwise pull the thumb out from under the pointer.
;
; rcx = listview hwnd, edx = 1 to (re-)arm leave tracking, 0 to leave it alone.
;
; That second argument is not a nicety.  Arming is only ever correct while the
; pointer is genuinely inside the window: TrackMouseEvent asked to watch for a
; leave when the pointer has ALREADY left posts WM_MOUSELEAVE straight back, so
; arming from inside the leave handler is a message loop that never ends.  It
; does not hang or crash - it simply saturates the UI thread, and the visible
; symptom is that clicks stop selecting rows and double-clicks stop expanding
; folders, because real input never gets a turn.  So the move messages arm and
; the leave messages do not.
;
; locals (frame 160): hwnd[-8] want[-16] arm[-24] tme[-80..-57].  The outgoing
; area is the BOTTOM of the frame - 32 bytes of shadow space plus room for the
; stack arguments of the widest call, which here is SetWindowPos at seven, so 56
; bytes.  At 128 that area ended at rbp-73 and overlapped the TRACKMOUSEEVENT;
; a corrupt cbSize makes TrackMouseEvent fail silently and no leave ever
; arrives.  160 keeps the two apart.
; =============================================================================
scrollbar_eval proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 160
    mov     qword ptr [rbp-8], rcx
    mov     dword ptr [rbp-24], edx
    mov     dword ptr [rbp-16], 0                ; want = hidden
    cmp     dword ptr [g_lvtrack], 0
    je      se_notdrag
    mov     dword ptr [rbp-16], 1                ; dragging: stays up regardless
    jmp     se_decided
se_notdrag:
    ; the settings panel covers the list, so the thumb has no business showing
    cmp     dword ptr [g_menu_open], 0
    jne     se_decided
    ; nothing to scroll -> nothing to show, however hard the strip is hovered
    mov     rax, qword ptr [g_lvcontent]
    cmp     rax, qword ptr [g_lvview]
    jle     se_decided
    ; The strip in SCREEN coordinates.  The list's window rect gives the left and
    ; right edges directly; its top is the top of the WHOLE tree, so the visible
    ; band starts g_lvscroll below it.
    WINCALL GetWindowRect, qword ptr [rbp-8], addr g_lsrc
    WINCALL GetCursorPos, addr g_lspt
    mov     eax, dword ptr [g_lsrc+4]
    add     rax, qword ptr [g_lvscroll]
    mov     r10d, eax                            ; band top
    mov     eax, dword ptr [g_lspt+4]            ; cursor y
    cmp     eax, r10d
    jl      se_decided
    add     r10d, dword ptr [g_lvview]
    cmp     eax, r10d
    jge     se_decided
    mov     eax, dword ptr [g_lspt+0]            ; cursor x
    cmp     eax, dword ptr [g_lsrc+8]            ; rc.right
    jge     se_decided
    mov     r10d, dword ptr [g_lsrc+8]
    sub     r10d, dword ptr [g_sbw]              ; left edge of the hot strip
    cmp     eax, r10d
    jl      se_decided
    mov     dword ptr [rbp-16], 1                ; want = shown
se_decided:
    cmp     dword ptr [rbp-24], 0
    je      se_notrack
    ; TME_NONCLIENT as well as TME_LEAVE: crossing from the list into the bar is
    ; a move TOWARDS the strip, not away from the list, but it still leaves the
    ; CLIENT area.  Tracking both sides means that crossing arrives as a matched
    ; pair, and either message just re-runs this proc, where the cursor position
    ; settles it.  cbSize must be exactly 24 or TrackMouseEvent refuses.
    mov     dword ptr [rbp-80], 24
    mov     dword ptr [rbp-76], TME_LEAVE or TME_NONCLIENT
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [rbp-72], rax
    mov     dword ptr [rbp-64], 0
    WINCALL TrackMouseEvent, addr rbp-80
se_notrack:
    mov     eax, dword ptr [rbp-16]
    cmp     eax, dword ptr [g_listhover]
    je      se_ret                               ; already in that state
    mov     dword ptr [g_listhover], eax
    ; The whole cost of a state change is now one narrow invalidate: the thumb
    ; is drawn by the list itself, so appearing and disappearing is just the
    ; list repainting a strip it already owns.
    call    lv_strip_invalidate
se_ret:
    add     rsp, 160                             ; must match the prologue exactly
    pop     rbp
    ret
scrollbar_eval endp

; =============================================================================
; list_subclass(rcx=hwnd, rdx=msg, r8=wParam, r9=lParam) -> rax
; Returns HTTRANSPARENT for WM_NCHITTEST over empty space so those hits pass to
; the parent (which reports HTCAPTION - the window drags).  All other messages
; go to the original listview proc, so painting / NM_CUSTOMDRAW progress bars
; are unaffected.  Raw window proc (no FRAME_PROLOG; UI thread only).
; =============================================================================
list_subclass proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128                         ; ls_ret MUST restore the same
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    ; ---- the scrollbar appears only while ITS OWN strip is hovered ----------
    ; A permanent bar is a bright vertical stripe down a very dark window, and it
    ; only means anything once you have reached for it.  Hidden by default (see
    ; the end of populate_list); scrollbar_eval decides from the cursor position
    ; on any mouse traffic in either area, so all four messages do the same thing.
    cmp     rdx, WM_MOUSEMOVE
    je      ls_moved
    cmp     rdx, WM_NCMOUSEMOVE
    je      ls_moved
    cmp     rdx, WM_MOUSELEAVE
    je      ls_left
    cmp     rdx, WM_NCMOUSELEAVE
    je      ls_left
    cmp     rdx, WM_MOUSEWHEEL
    jne     ls_notwheel
    mov     rcx, qword ptr [rbp-24]
    call    lv_wheel
    xor     rax, rax
    jmp     ls_ret
ls_notwheel:
    cmp     rdx, WM_PAINT
    jne     ls_notpaint
    ; Let the control paint its rows, then put the thumb on top of them.  Both
    ; happen inside this one message, so the pair reaches the screen together.
    WINCALL CallWindowProcW, qword ptr [g_oldlistproc], qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    mov     qword ptr [rbp-40], rax
    ; Two overlays share the one DC now: the scrollbar thumb and the drop
    ; indicator.  Either can want it on its own, so the fetch is gated on the
    ; pair rather than on the thumb - which is what it used to test, and which
    ; would have left the line invisible whenever there was nothing to scroll.
    cmp     qword ptr [g_lvthh], 0
    jne     ls_overlay
    cmp     dword ptr [g_dl_show], 0
    je      ls_ret_saved
ls_overlay:
    WINCALL GetDC, qword ptr [rbp-8]
    mov     qword ptr [rbp-48], rax
    test    rax, rax
    jz      ls_ret_saved
    cmp     qword ptr [g_lvthh], 0
    je      ls_noThumb
    mov     rcx, qword ptr [rbp-48]
    call    draw_lv_thumb
ls_noThumb:
    mov     rcx, qword ptr [rbp-48]
    call    draw_drop_box
    WINCALL ReleaseDC, qword ptr [rbp-8], qword ptr [rbp-48]
ls_ret_saved:
    mov     rax, qword ptr [rbp-40]
    jmp     ls_ret
ls_notpaint:
    cmp     rdx, WM_LBUTTONDOWN
    je      ls_lbdown
    cmp     rdx, WM_LBUTTONUP
    jne     ls_nothover
    ; ---- end of a thumb drag ------------------------------------------------
    cmp     dword ptr [g_lvtrack], 0
    je      ls_nothover
    mov     dword ptr [g_lvtrack], 0
    WINCALL ReleaseCapture
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx
    call    scrollbar_eval                   ; may hide it, if the pointer left
    xor     rax, rax
    jmp     ls_ret
ls_lbdown:
    ; ---- a press in the strip belongs to the bar, not to the rows -----------
    ; Nothing else claims it: with no scrollbar control there is no window here
    ; to take the click, so the strip has to be recognised by geometry.
    cmp     qword ptr [g_lvthh], 0
    je      ls_nothover                      ; nothing to scroll
    mov     rax, qword ptr [rbp-32]          ; lParam: CLIENT point
    movsx   r10d, ax
    mov     eax, dword ptr [g_lay_lvw]
    sub     eax, dword ptr [g_sbw]
    cmp     r10d, eax
    jl      ls_nothover                      ; left of the strip: a row click
    mov     rax, qword ptr [rbp-32]
    sar     rax, 16
    movsx   r10d, ax                         ; client y, in CONTROL coordinates
    mov     rax, qword ptr [g_lvscroll]
    add     rax, qword ptr [g_lvthy]         ; thumb top
    cmp     r10d, eax
    jl      ls_pageup
    add     rax, qword ptr [g_lvthh]         ; thumb bottom
    cmp     r10d, eax
    jge     ls_pagedown
    ; on the thumb: capture, and remember where both it and the pointer were.
    ; The GRAB POSITION IS IN SCREEN COORDINATES because the control moves as
    ; it scrolls - a client y taken now means something else one step later.
    WINCALL GetCursorPos, addr g_lspt
    mov     eax, dword ptr [g_lspt+4]
    cdqe
    mov     qword ptr [g_lvgraby], rax
    mov     rax, qword ptr [g_lvscroll]
    mov     qword ptr [g_lvgrab], rax
    mov     dword ptr [g_lvtrack], 1
    WINCALL SetCapture, qword ptr [rbp-8]
    xor     rax, rax
    jmp     ls_ret
ls_pageup:
    mov     rcx, qword ptr [g_lvview]
    neg     rcx
    call    lv_scroll_by
    xor     rax, rax
    jmp     ls_ret
ls_pagedown:
    mov     rcx, qword ptr [g_lvview]
    call    lv_scroll_by
    xor     rax, rax
    jmp     ls_ret
ls_left:
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx                         ; do NOT re-arm: see scrollbar_eval
    call    scrollbar_eval
    jmp     ls_pass
ls_moved:
    ; a drag in progress owns every move until the button comes up
    cmp     dword ptr [g_lvtrack], 0
    je      ls_hover_only
    call    lv_thumb_drag
    xor     rax, rax
    jmp     ls_ret
ls_hover_only:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, 1                           ; pointer is inside: arm the leave
    call    scrollbar_eval
    jmp     ls_pass
ls_nothover:
    cmp     rdx, WM_NCHITTEST
    jne     @F
    ; The list used to report HTTRANSPARENT unconditionally so the whole control
    ; was drag-through and the window could be moved by it.  That makes the rows
    ; unclickable, which a list you can select and remove from cannot be.
    ;
    ; Ask the listview FIRST.  Its answer is HTVSCROLL over a shown scrollbar,
    ; and overriding that (as this did, by only ever answering from a row hit)
    ; made the bar unusable: the thumb could not be grabbed, because the hit
    ; landed on the parent instead.  Only HTCLIENT is ours to reinterpret.
    WINCALL CallWindowProcW, qword ptr [g_oldlistproc], qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    cmp     rax, HTCLIENT
    jne     ls_ret                               ; scrollbar / border: not ours
    mov     rax, qword ptr [rbp-32]              ; lParam: screen point
    movsx   r10d, ax
    mov     dword ptr [g_lhit+0], r10d           ; pt.x
    mov     rax, qword ptr [rbp-32]
    sar     rax, 16
    movsx   r10d, ax
    mov     dword ptr [g_lhit+4], r10d           ; pt.y
    ; While the bar is HIDDEN its strip is ordinary client area with no row in
    ; it, so the empty-space rule below would hand it to the parent and the list
    ; would never see the WM_MOUSEMOVE that reveals the bar.  That is why the
    ; two previous attempts at this "never reached the reveal branch": the strip
    ; has to claim its own hits before the row test gets a look at them.
    WINCALL GetWindowRect, qword ptr [rbp-8], addr g_lsrc
    mov     eax, dword ptr [g_lhit+0]            ; still screen x here
    mov     ecx, dword ptr [g_lsrc+8]
    sub     ecx, dword ptr [g_sbw]
    cmp     eax, ecx
    jge     ls_client                            ; in the strip -> keep the hit
    ; Otherwise it depends on what is under the pointer: over a ROW, behave
    ; normally and let the listview handle selection; over empty space below the
    ; last row, stay transparent so the window still drags from the blank area.
    WINCALL ScreenToClient, qword ptr [rbp-8], addr g_lhit
    WINCALL SendMessageW, qword ptr [rbp-8], LVM_HITTEST, 0, addr g_lhit
    cmp     eax, 0
    jl      ls_transparent                       ; no row here -> drag-through
ls_client:
    mov     rax, HTCLIENT
    jmp     ls_ret
ls_transparent:
    mov     rax, HTTRANSPARENT
    jmp     ls_ret
@@:
    cmp     rdx, WM_NCCALCSIZE
    jne     ls_pass
    ; let the listview do its NC calc, then force the HORIZONTAL scrollbar away.
    ; It used to hide BOTH, which is fine for a list that never exceeds its
    ; height and wrong for one you can expand folders into - there has to be a
    ; way to reach rows past the bottom.  Columns still fit by construction
    ; (do_layout sizes them to the list), so the horizontal one stays hidden.
    WINCALL CallWindowProcW, qword ptr [g_oldlistproc], qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    mov     qword ptr [rbp-40], rax
    WINCALL ShowScrollBar, qword ptr [rbp-8], SB_HORZ, 0
    mov     rax, qword ptr [rbp-40]
    jmp     ls_ret
ls_pass:
    WINCALL CallWindowProcW, qword ptr [g_oldlistproc], qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
ls_ret:
    add     rsp, 128                         ; must match the prologue exactly
    pop     rbp
    ret
list_subclass endp

; =============================================================================
; edit_subclass(rcx=hwnd, rdx=msg, r8=wParam, r9=lParam) -> rax
; Password/confirm edit subclass: after the edit paints, if it is empty, draw a
; grey placeholder ("Password"/"Confirm") inside the field.  It vanishes the
; instant any text is entered (the field is no longer empty).  Raw window proc
; (no FRAME_PROLOG; UI thread only, like wndproc).
; locals (frame 128): hwnd[-8] msg[-16] wParam[-24] lParam[-32] result[-40]
;   hdc[-48] oldfont[-56] phptr[-80] rc[-72..-57]
; =============================================================================
edit_subclass proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    ; let the original EDIT proc handle the message first
    WINCALL CallWindowProcW, qword ptr [g_oldeditproc], qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    mov     qword ptr [rbp-40], rax        ; result to return
    ; On focus changes the default EDIT repaints itself (caret/selection) outside
    ; our WM_PAINT path, wiping the cue.  Force a full repaint while empty so the
    ; "Password" cue is redrawn after tabbing out or clicking away (hamburger).
    cmp     qword ptr [rbp-16], WM_KILLFOCUS
    je      es_focus
    cmp     qword ptr [rbp-16], WM_SETFOCUS
    jne     es_chkpaint
es_focus:
    WINCALL GetWindowTextLengthW, qword ptr [rbp-8]
    test    eax, eax
    jnz     es_ret
    WINCALL InvalidateRect, qword ptr [rbp-8], 0, 1
    jmp     es_ret
es_chkpaint:
    ; only augment WM_PAINT, and only while the field is empty
    cmp     qword ptr [rbp-16], WM_PAINT
    jne     es_ret
    WINCALL GetWindowTextLengthW, qword ptr [rbp-8]
    test    eax, eax
    jnz     es_ret
    ; placeholder text by hwnd (confirm vs password)
    lea     r10, [s_ph_pass]
    mov     rax, qword ptr [rbp-8]
    cmp     rax, qword ptr [g_hconfirm]
    je      @F
    cmp     rax, qword ptr [g_sd_hconf]        ; the prompt's confirm field too
    jne     es_havecue
@@:
    lea     r10, [s_ph_conf]
es_havecue:
    mov     qword ptr [rbp-80], r10
    WINCALL GetDC, qword ptr [rbp-8]
    mov     qword ptr [rbp-48], rax
    WINCALL SelectObject, qword ptr [rbp-48], qword ptr [g_hfont]
    mov     qword ptr [rbp-56], rax        ; old font
    WINCALL SetBkMode, qword ptr [rbp-48], BK_TRANSPARENT
    WINCALL SetTextColor, qword ptr [rbp-48], CLR_PLACEHOLDER
    WINCALL GetClientRect, qword ptr [rbp-8], addr rbp-72
    add     dword ptr [rbp-72], 2          ; small left inset to match typed text
    ; DT_TOP, not DT_VCENTER: a single-line EDIT draws its text at the top of the
    ; client rect, so a centred cue sits BELOW the typed text rather than behind
    ; it - which showed up as a grey ghost under the asterisks.
    WINCALL DrawTextW, qword ptr [rbp-48], qword ptr [rbp-80], -1, addr rbp-72, <DT_LEFT or DT_TOP or DT_SINGLELINE or DT_NOPREFIX>
    WINCALL SelectObject, qword ptr [rbp-48], qword ptr [rbp-56]   ; restore font
    WINCALL ReleaseDC, qword ptr [rbp-8], qword ptr [rbp-48]
es_ret:
    mov     rax, qword ptr [rbp-40]
    add     rsp, 128
    pop     rbp
    ret
edit_subclass endp

; =============================================================================
; underline_brush(ecx = state 0/1/2) -> rax = neutral/valid/invalid brush
; =============================================================================
underline_brush proc
    ; state 0 neutral / 1 red / 2 amber / 3 light green / 4 deep green
    cmp     ecx, 4
    jbe     @F
    xor     ecx, ecx
@@:
    mov     eax, ecx
    lea     r10, [g_ubr]
    mov     rax, qword ptr [r10+rax*8]
    ret
underline_brush endp

; =============================================================================
; pw_policy_ok(rcx = wide passwordZ) -> eax = 1 if it satisfies the configured
; policy (min length + min distinct character classes), else 0.  Empty is never
; policy-ok; callers that allow an empty password (unprotected .zip) decide that
; for themselves rather than having it hidden in here.
; =============================================================================
pw_policy_ok proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    xor     r8d, r8d                          ; class mask
    xor     r9d, r9d                          ; length
ppo_lp:
    movzx   eax, word ptr [rcx+r9*2]
    test    eax, eax
    jz      ppo_done
    cmp     eax, 'a'
    jb      ppo_u
    cmp     eax, 'z'
    ja      ppo_u
    or      r8d, 1
    jmp     ppo_nx
ppo_u:
    cmp     eax, 'A'
    jb      ppo_d
    cmp     eax, 'Z'
    ja      ppo_d
    or      r8d, 2
    jmp     ppo_nx
ppo_d:
    cmp     eax, '0'
    jb      ppo_s
    cmp     eax, '9'
    ja      ppo_s
    or      r8d, 4
    jmp     ppo_nx
ppo_s:
    or      r8d, 8
ppo_nx:
    inc     r9d
    jmp     ppo_lp
ppo_done:
    xor     r10d, r10d
    test    r8d, 1
    jz      @F
    inc     r10d
@@: test    r8d, 2
    jz      @F
    inc     r10d
@@: test    r8d, 4
    jz      @F
    inc     r10d
@@: test    r8d, 8
    jz      @F
    inc     r10d
@@:
    xor     eax, eax
    test    r9d, r9d
    jz      ppo_ret                           ; empty is never policy-ok
    mov     ecx, dword ptr [g_cfg_pwminlen]
    cmp     r9d, ecx
    jb      ppo_ret
    cmp     r10d, dword ptr [g_cfg_pwminclasses]
    jb      ppo_ret
    mov     eax, 1
ppo_ret:
    add     rsp, 48
    pop     rbp
    ret
pw_policy_ok endp

; =============================================================================
; pw_grade(rcx = wide password, edx = length in chars) -> eax = 0..3
;   0 weak / 1 fair / 2 good / 3 strong.  Length + character-class count, the
;   same shape Vordr uses.  This is a PRESENTATION grade only - it never decides
;   whether a password is allowed; the configured policy does that.  Keeping the
;   two separate is why a password can be "fair" and still accepted, or "good"
;   and still refused for missing a required class.
; =============================================================================
pw_grade proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    xor     r8d, r8d                          ; class mask
    xor     r9d, r9d                          ; i
pg_lp:
    cmp     r9d, edx
    jae     pg_classes
    movzx   eax, word ptr [rcx+r9*2]
    cmp     eax, 'a'
    jb      pg_cku
    cmp     eax, 'z'
    ja      pg_cku
    or      r8d, 1
    jmp     pg_next
pg_cku:
    cmp     eax, 'A'
    jb      pg_ckd
    cmp     eax, 'Z'
    ja      pg_ckd
    or      r8d, 2
    jmp     pg_next
pg_ckd:
    cmp     eax, '0'
    jb      pg_sym
    cmp     eax, '9'
    ja      pg_sym
    or      r8d, 4
    jmp     pg_next
pg_sym:
    or      r8d, 8
pg_next:
    inc     r9d
    jmp     pg_lp
pg_classes:
    xor     r10d, r10d                        ; class count
    test    r8d, 1
    jz      @F
    inc     r10d
@@: test    r8d, 2
    jz      @F
    inc     r10d
@@: test    r8d, 4
    jz      @F
    inc     r10d
@@: test    r8d, 8
    jz      @F
    inc     r10d
@@:
    xor     eax, eax                          ; weak
    cmp     edx, 8
    jb      pg_ret
    mov     eax, 1                            ; fair
    cmp     edx, 12                           ; good: (L>=12 & c>=2) | (L>=10 & c>=3)
    jb      pg_g2
    cmp     r10d, 2
    jae     pg_good
pg_g2:
    cmp     edx, 10
    jb      pg_ret
    cmp     r10d, 3
    jb      pg_ret
pg_good:
    mov     eax, 2                            ; good
    cmp     edx, 16                           ; strong: (L>=16 & c>=3) | (L>=12 & c==4)
    jb      pg_s2
    cmp     r10d, 3
    jae     pg_strong
pg_s2:
    cmp     edx, 12
    jb      pg_ret
    cmp     r10d, 4
    jb      pg_ret
pg_strong:
    mov     eax, 3
pg_ret:
    add     rsp, 48
    pop     rbp
    ret
pw_grade endp

; =============================================================================
; draw_button(rcx = DRAWITEMSTRUCT*) - paint a Fluent owner-draw button.
; ID_ACTION is the accent (filled blue) button; the rest are standard (light
; fill + border).  Honours pressed (ODS_SELECTED) and disabled (ODS_DISABLED).
; locals (frame 160): dis[-8] id[-16] state[-20] hdc[-24] hwnd[-32]
;   rc[-56..-41] fill[-60] txt[-64] border[-68] brush[-72] pen[-80]
;   oldbrush[-88] oldpen[-96]
; =============================================================================
draw_button proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 192
    mov     qword ptr [rbp-8], rcx
    mov     eax, dword ptr [rcx+DI_CTLID]
    mov     dword ptr [rbp-16], eax
    mov     eax, dword ptr [rcx+DI_ITEMSTATE]
    mov     dword ptr [rbp-20], eax
    mov     rax, qword ptr [rcx+DI_HDC]
    mov     qword ptr [rbp-24], rax
    mov     rax, qword ptr [rcx+DI_HWNDITEM]
    mov     qword ptr [rbp-32], rax
    ; real enabled state (more reliable than ODS_DISABLED here)
    WINCALL IsWindowEnabled, qword ptr [rbp-32]
    mov     dword ptr [rbp-104], eax
    ; copy rcItem
    mov     rcx, qword ptr [rbp-8]
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-56], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [rbp-52], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-48], eax
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-44], eax
    ; fill the whole item rect with the dark window colour (RoundRect corners blend)
    WINCALL FillRect, qword ptr [rbp-24], addr rbp-56, qword ptr [g_hbr_dark]
    ; choose colours
    cmp     dword ptr [rbp-16], ID_ACTION
    jne     db_standard
    mov     eax, CLR_ACCENT
    cmp     dword ptr [rbp-104], 0          ; disabled?
    jne     @F
    mov     eax, CLR_BTN_DARK               ; disabled accent -> dark panel
    jmp     db_acc
@@:
    test    dword ptr [rbp-20], ODS_SELECTED
    jz      db_acc
    mov     eax, CLR_ACCENT_PRESS
db_acc:
    mov     dword ptr [rbp-60], eax
    mov     dword ptr [rbp-64], CLR_WHITE
    mov     dword ptr [rbp-68], eax
    jmp     db_draw
db_standard:
    mov     eax, CLR_BTN_DARK
    test    dword ptr [rbp-20], ODS_SELECTED
    jz      @F
    mov     eax, CLR_BTN_DARK_PRESS
@@:
    mov     dword ptr [rbp-60], eax
    mov     dword ptr [rbp-64], CLR_WHITE
    cmp     dword ptr [rbp-104], 0
    jne     @F
    mov     dword ptr [rbp-64], CLR_PLACEHOLDER
@@:
    mov     dword ptr [rbp-68], CLR_CRUMB_EDGE
db_draw:
    WINCALL CreateSolidBrush, dword ptr [rbp-60]
    mov     qword ptr [rbp-72], rax
    WINCALL CreatePen, PS_SOLID, 1, dword ptr [rbp-68]
    mov     qword ptr [rbp-80], rax
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-72]
    mov     qword ptr [rbp-88], rax
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-80]
    mov     qword ptr [rbp-96], rax
    ; RoundRect(hdc, left, top, right, bottom, BTN_RADIUS, BTN_RADIUS)
    WINCALL RoundRect, qword ptr [rbp-24], dword ptr [rbp-56], dword ptr [rbp-52], dword ptr [rbp-48], dword ptr [rbp-44], BTN_RADIUS, BTN_RADIUS
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-88]
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-96]
    WINCALL DeleteObject, qword ptr [rbp-72]
    WINCALL DeleteObject, qword ptr [rbp-80]
    ; caption text, centred
    WINCALL GetWindowTextW, qword ptr [rbp-32], addr g_btntext, 64
    WINCALL SetBkMode, qword ptr [rbp-24], BK_TRANSPARENT
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [rbp-64]
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_hfont]
    WINCALL DrawTextW, qword ptr [rbp-24], addr g_btntext, -1, addr rbp-56, <DT_CENTER or DT_VCENTER or DT_SINGLELINE>
    ; ---- keyboard-focus ring -----------------------------------------------
    WINCALL GetFocus
    cmp     rax, qword ptr [rbp-32]      ; focused control is this button?
    jne     db_nofocus
    ; white rounded outline, inset 2px (NULL brush -> edge only)
    WINCALL CreatePen, PS_SOLID, 1, CLR_WHITE
    mov     qword ptr [rbp-112], rax
    WINCALL GetStockObject, NULL_BRUSH
    mov     qword ptr [rbp-128], rax
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-112]
    mov     qword ptr [rbp-120], rax     ; old pen
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-128]
    mov     qword ptr [rbp-136], rax     ; old brush
    mov     edx, dword ptr [rbp-56]
    add     edx, 2
    mov     r8d, dword ptr [rbp-52]
    add     r8d, 2
    mov     r9d, dword ptr [rbp-48]
    sub     r9d, 2
    mov     eax, dword ptr [rbp-44]
    sub     eax, 2
    WINCALL RoundRect, qword ptr [rbp-24], edx, r8d, r9d, eax, BTN_RADIUS, BTN_RADIUS
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-120]
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-136]
    WINCALL DeleteObject, qword ptr [rbp-112]
db_nofocus:
    add     rsp, 192
    pop     rbp
    ret
draw_button endp

; =============================================================================
; draw_crumb(rcx = DRAWITEMSTRUCT*) - the breadcrumb chip: a dark rounded box
; with a 1px lighter edge and white text, hugging the text.  Uses the full
; breadcrumb if it fits, otherwise the collapsed one, otherwise end-ellipsis.
; locals (frame 192): dis[-8] hdc[-16] rc[-32..-17] oldfont[-40] avail[-48]
;   len[-56] size[-72..-65] textptr[-80] tw[-84] boxw[-88] brush[-96] pen[-104]
;   oldbrush[-112] oldpen[-120] trc[-144..-129]
; =============================================================================
draw_crumb proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 192
    mov     qword ptr [rbp-8], rcx
    mov     rax, qword ptr [rcx+DI_HDC]
    mov     qword ptr [rbp-16], rax
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-32], eax       ; left
    mov     rcx, qword ptr [rbp-8]
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [rbp-28], eax       ; top
    mov     rcx, qword ptr [rbp-8]
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-24], eax       ; right
    mov     rcx, qword ptr [rbp-8]
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-20], eax       ; bottom
    ; clear the control rect to the dark window colour
    WINCALL FillRect, qword ptr [rbp-16], addr rbp-32, qword ptr [g_hbr_dark]
    ; select the normal UI font (regular weight)
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [g_hfont]
    mov     qword ptr [rbp-40], rax
    ; avail = (right-left) - 2*PAD
    mov     eax, dword ptr [rbp-24]
    sub     eax, dword ptr [rbp-32]
    sub     eax, 2*CRUMB_PAD
    mov     dword ptr [rbp-48], eax
    ; measure the full breadcrumb
    lea     rcx, [g_crumbw]
    call    wlen
    mov     dword ptr [rbp-56], eax
    WINCALL GetTextExtentPoint32W, qword ptr [rbp-16], addr g_crumbw, dword ptr [rbp-56], addr rbp-72
    mov     eax, dword ptr [rbp-72]       ; size.cx
    cmp     eax, dword ptr [rbp-48]
    jg      dc_short
    lea     rax, [g_crumbw]
    mov     qword ptr [rbp-80], rax
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [rbp-84], eax       ; tw = full width
    jmp     dc_box
dc_short:
    lea     rax, [g_crumb_short]
    mov     qword ptr [rbp-80], rax
    lea     rcx, [g_crumb_short]
    call    wlen
    mov     dword ptr [rbp-56], eax
    WINCALL GetTextExtentPoint32W, qword ptr [rbp-16], addr g_crumb_short, dword ptr [rbp-56], addr rbp-72
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [rbp-84], eax       ; tw = short width
dc_box:
    ; boxw = tw + 2*PAD, clamped to control width
    mov     eax, dword ptr [rbp-84]
    add     eax, 2*CRUMB_PAD
    mov     dword ptr [rbp-88], eax
    mov     eax, dword ptr [rbp-24]
    sub     eax, dword ptr [rbp-32]       ; control width
    cmp     dword ptr [rbp-88], eax
    jle     @F
    mov     dword ptr [rbp-88], eax
@@:
    ; (no background pill or border: just the heading text on the window)
    ; white text, padded + vcentred, ellipsised if needed
    WINCALL SetBkMode, qword ptr [rbp-16], BK_TRANSPARENT
    WINCALL SetTextColor, qword ptr [rbp-16], CLR_WHITE
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [rbp-144], eax      ; trc.left = control left (no inset)
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [rbp-140], eax      ; trc.top
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [rbp-136], eax      ; trc.right = control right
    mov     eax, dword ptr [rbp-20]
    mov     dword ptr [rbp-132], eax      ; trc.bottom
    WINCALL DrawTextW, qword ptr [rbp-16], qword ptr [rbp-80], -1, addr rbp-144, <DT_VCENTER or DT_SINGLELINE or DT_END_ELLIPSIS>
    ; restore font
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [rbp-40]
    add     rsp, 192
    pop     rbp
    ret
draw_crumb endp

; =============================================================================
; wndproc(rcx=hwnd, rdx=msg, r8=wParam, r9=lParam) -> rax (raw; no FRAME_PROLOG)
; =============================================================================
wndproc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80
    mov     qword ptr [rbp-8], rcx       ; hwnd
    mov     qword ptr [rbp-16], rdx      ; msg
    mov     qword ptr [rbp-24], r8        ; wParam
    mov     qword ptr [rbp-32], r9        ; lParam

    mov     rax, rdx
    cmp     rax, WM_CREATE
    je      wp_create
    cmp     rax, WM_COMMAND
    je      wp_command
    cmp     rax, WM_TIMER
    je      wp_timer
    cmp     rax, WM_APP_DONE
    je      wp_appdone
    cmp     rax, WM_APP_INDEXED
    je      wp_appindexed
    cmp     rax, WM_DRAWITEM
    je      wp_drawitem
    cmp     rax, WM_NOTIFY
    je      wp_notify
    cmp     rax, WM_CTLCOLORSTATIC
    je      wp_ctlstatic
    cmp     rax, WM_CTLCOLOREDIT
    je      wp_ctledit
    cmp     rax, WM_CTLCOLORBTN
    je      wp_ctlbtn
    cmp     rax, WM_NCHITTEST
    je      wp_nchittest
    cmp     rax, WM_SIZE
    je      wp_size
    cmp     rax, WM_MOUSEWHEEL
    je      wp_wheel
    cmp     rax, WM_GETMINMAXINFO
    je      wp_minmax
    cmp     rax, WM_NCLBUTTONDBLCLK
    je      wp_zero                      ; swallow body double-click (no maximize)
    cmp     rax, WM_SETFOCUS
    je      wp_setfocus
    cmp     rax, WM_DROPFILES
    je      wp_dropfiles
ifdef DBG_TRACE
    cmp     rax, WM_APP_DROPTEST
    je      wp_droptest
endif
    cmp     rax, WM_SETCURSOR
    je      wp_setcursor
    cmp     rax, WM_CLOSE
    je      wp_close
    cmp     rax, WM_DESTROY
    je      wp_destroy
    jmp     wp_default

; Nothing else says the statistics line can be clicked - it is a line of text
; among other lines of text - so the pointer says it.  WM_SETCURSOR arrives at
; the PARENT with the child in wParam, which is the only hook a plain STATIC
; gives without subclassing it.
wp_setcursor:
    mov     rax, qword ptr [rbp-24]          ; wParam = the child under the cursor
    cmp     rax, qword ptr [g_hscan]
    jne     wp_default
    cmp     qword ptr [g_hcur_hand], 0
    jne     @F
    WINCALL LoadCursorW, 0, IDC_HAND
    mov     qword ptr [g_hcur_hand], rax
@@:
    cmp     qword ptr [g_hcur_hand], 0
    je      wp_default                       ; no hand cursor: leave it alone
    WINCALL SetCursor, qword ptr [g_hcur_hand]
    mov     rax, 1
    jmp     wp_ret

wp_dropfiles:
    ; Both drop mechanisms now go through drop_hdrop, so they cannot disagree.
    ; This one survives alongside the OLE target because a real shell drag
    ; always reaches the registered IDropTarget instead - the shell looks for
    ; one first - so nothing arrives here except a POSTED WM_DROPFILES, which
    ; is what the in-process tests send.
    ;
    ; DragFinish is unconditional: the shell allocated the HDROP whatever we
    ; decide to do with it.
    mov     rcx, qword ptr [rbp-24]          ; wParam = HDROP
    call    drop_hdrop
    WINCALL DragFinish, qword ptr [rbp-24]
    jmp     wp_zero

ifdef DBG_TRACE
wp_droptest:
    ; lParam = the screen point to drag over, packed as a POINTL - x in the LOW
    ; dword, y in the high - which is what OLE hands the interface, not the two
    ; SHORTs a mouse message packs.  wParam = 1 for hover-only.
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    dt_selfdrop
    jmp     wp_zero
endif

wp_size:
    ; Re-derive the geometry, re-cut the corner region for the new bounds, then
    ; let the list re-snap to whole rows (it trims controls, not the window, so
    ; this cannot recurse).  Repaint: the owner-drawn surfaces all size with the
    ; window and would otherwise keep their stale pixels.
    call    do_layout
    call    set_round_region
    ; RedrawWindow with RDW_ALLCHILDREN, not InvalidateRect.  WS_CLIPCHILDREN
    ; means the parent's erase no longer reaches into the child rectangles - the
    ; point of the style - but neither does its invalidation, and a resized
    ; owner-drawn static only repaints the strip that was newly exposed.  The
    ; breadcrumb ended up with its old text still under the new.  RDW_ALLCHILDREN
    ; invalidates the children explicitly instead of painting over them.
    ; 085h = RDW_INVALIDATE|RDW_ERASE|RDW_ALLCHILDREN
    WINCALL RedrawWindow, qword ptr [rbp-8], 0, 0, 085h
    jmp     wp_zero

wp_wheel:
    ; The wheel reaches here when the focus is somewhere other than the list -
    ; the password field, say - because DefWindowProc hands an unhandled wheel
    ; to the parent.  Over the list itself, list_subclass takes it first, so
    ; only one of the two ever acts on a given notch.
    cmp     dword ptr [g_op], 0
    jne     wp_default
    mov     rcx, qword ptr [rbp-24]
    call    lv_wheel
    jmp     wp_zero

wp_minmax:
    ; lParam -> MINMAXINFO; ptMinTrackSize is at +24 (x) / +28 (y).  Without this
    ; the window can be dragged down to nothing and the derived widths go negative.
    mov     rax, qword ptr [rbp-32]
    test    rax, rax
    jz      wp_zero
    mov     dword ptr [rax+24], LAY_MIN_W
    mov     dword ptr [rax+28], LAY_MIN_H
    mov     qword ptr [g_mmi], rax               ; held across the monitor calls
    ; Maximise (Win+Up, Aero Snap) must fill the WORK AREA of whichever monitor
    ; the window is on.  A WS_POPUP has no frame for the shell to reason about,
    ; so left to itself it maximises over the taskbar.  Monitor-relative, not
    ; screen-relative, so this stays correct on a second display.
    WINCALL MonitorFromWindow, qword ptr [rbp-8], 2   ; MONITOR_DEFAULTTONEAREST
    test    rax, rax
    jz      wp_zero
    mov     dword ptr [g_mi], 40                 ; cbSize
    WINCALL GetMonitorInfoW, rax, addr g_mi
    test    eax, eax
    jz      wp_zero
    mov     rax, qword ptr [g_mmi]
    mov     ecx, dword ptr [g_mi+28]             ; rcWork.right
    sub     ecx, dword ptr [g_mi+20]             ; - rcWork.left
    mov     dword ptr [rax+8], ecx               ; ptMaxSize.x
    mov     ecx, dword ptr [g_mi+32]             ; rcWork.bottom
    sub     ecx, dword ptr [g_mi+24]             ; - rcWork.top
    mov     dword ptr [rax+12], ecx              ; ptMaxSize.y
    mov     ecx, dword ptr [g_mi+20]
    sub     ecx, dword ptr [g_mi+4]              ; work.left - monitor.left
    mov     dword ptr [rax+16], ecx              ; ptMaxPosition.x
    mov     ecx, dword ptr [g_mi+24]
    sub     ecx, dword ptr [g_mi+8]              ; work.top - monitor.top
    mov     dword ptr [rax+20], ecx              ; ptMaxPosition.y
    jmp     wp_zero

wp_nchittest:
    ; Borderless window: the body acts as a caption so the window can be dragged,
    ; and the outermost LAY_EDGE pixels report a border code so DefWindowProc
    ; runs its sizing loop.  That works without WS_THICKFRAME, which this window
    ; cannot have without losing the custom chrome.
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    cmp     rax, HTCLIENT
    jne     wp_ret
    ; lParam is a SCREEN point: x in the low word, y in the high word, both
    ; signed (a window on a second monitor can have negative coordinates).
    mov     rax, qword ptr [rbp-32]
    movsx   r10d, ax
    mov     dword ptr [g_ht_x], r10d
    mov     rax, qword ptr [rbp-32]
    sar     rax, 16
    movsx   r10d, ax
    mov     dword ptr [g_ht_y], r10d
    WINCALL GetWindowRect, qword ptr [rbp-8], addr g_lay_wr
    ; No further calls below this point, so the flags can live in volatiles.
    xor     r8d, r8d                     ; horizontal: 0 none, 1 left, 2 right
    mov     eax, dword ptr [g_ht_x]
    sub     eax, dword ptr [g_lay_wr+0]
    cmp     eax, LAY_EDGE
    jge     ht_noleft
    mov     r8d, 1
ht_noleft:
    mov     eax, dword ptr [g_lay_wr+8]
    sub     eax, dword ptr [g_ht_x]
    cmp     eax, LAY_EDGE
    jge     ht_noright
    mov     r8d, 2
ht_noright:
    xor     r9d, r9d                     ; vertical: 0 none, 1 top, 2 bottom
    mov     eax, dword ptr [g_ht_y]
    sub     eax, dword ptr [g_lay_wr+4]
    cmp     eax, LAY_EDGE
    jge     ht_notop
    mov     r9d, 1
ht_notop:
    mov     eax, dword ptr [g_lay_wr+12]
    sub     eax, dword ptr [g_ht_y]
    cmp     eax, LAY_EDGE
    jge     ht_nobottom
    mov     r9d, 2
ht_nobottom:
    ; corners first - a corner is both flags set
    cmp     r9d, 1
    jne     ht_notopedge
    cmp     r8d, 1
    je      ht_tl
    cmp     r8d, 2
    je      ht_tr
    mov     rax, HTTOP
    jmp     wp_ret
ht_tl:
    mov     rax, HTTOPLEFT
    jmp     wp_ret
ht_tr:
    mov     rax, HTTOPRIGHT
    jmp     wp_ret
ht_notopedge:
    cmp     r9d, 2
    jne     ht_novert
    cmp     r8d, 1
    je      ht_bl
    cmp     r8d, 2
    je      ht_br
    mov     rax, HTBOTTOM
    jmp     wp_ret
ht_bl:
    mov     rax, HTBOTTOMLEFT
    jmp     wp_ret
ht_br:
    mov     rax, HTBOTTOMRIGHT
    jmp     wp_ret
ht_novert:
    cmp     r8d, 1
    je      ht_l
    cmp     r8d, 2
    je      ht_r
    ; Not an edge.  Before claiming the point as caption, check whether it lies
    ; over the LIST: the top-level window is hit-tested before the system
    ; descends into children, so reporting HTCAPTION here made the whole list
    ; area a drag handle and no click ever reached the rows.  Over the list,
    ; report HTCLIENT and let list_subclass decide row (select) vs empty space
    ; (transparent, so the window still drags from the blank part).
    ;
    ; This is the VIEWPORT, deliberately built from the layout globals rather
    ; than taken from GetWindowRect(g_hlist).  The control is now as tall as the
    ; whole tree and sits partly above and partly below the band on show, so its
    ; window rect covers the crumb row, the password field and the buttons -
    ; using it here would quietly stop the window being dragged by any of that.
    cmp     qword ptr [g_hlist], 0
    je      ht_caption
    cmp     dword ptr [g_op], 0
    jne     ht_caption                   ; decrypt window has no list
    ; g_lay_wr already holds THIS window's rect, from the border test above
    mov     eax, dword ptr [g_ht_x]
    sub     eax, dword ptr [g_lay_wr+0]  ; client x (no frame on a WS_POPUP)
    cmp     eax, LV_X
    jl      ht_caption
    mov     r10d, LV_X
    add     r10d, dword ptr [g_lay_lvw]
    cmp     eax, r10d
    jge     ht_caption
    mov     eax, dword ptr [g_ht_y]
    sub     eax, dword ptr [g_lay_wr+4]  ; client y
    cmp     eax, dword ptr [g_lay_lvy]
    jl      ht_caption
    mov     r10d, dword ptr [g_lay_lvy]
    add     r10d, dword ptr [g_lay_lvh]
    cmp     eax, r10d
    jge     ht_caption
    mov     rax, HTCLIENT
    jmp     wp_ret
ht_caption:
    mov     rax, HTCAPTION               ; body: drag the window
    jmp     wp_ret
ht_l:
    mov     rax, HTLEFT
    jmp     wp_ret
ht_r:
    mov     rax, HTRIGHT
    jmp     wp_ret

wp_setfocus:
    ; keep keyboard focus on the password field
    mov     rcx, qword ptr [g_hpass]
    test    rcx, rcx
    jz      wp_zero
    WINCALL SetFocus, rcx
    jmp     wp_zero

wp_create:
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [g_hwnd], rax
    call    create_controls
    ; accept files dropped onto the window itself (WM_DROPFILES).  Both calls
    ; are needed: DragAcceptFiles registers the window as a drop target, and the
    ; filter calls let the two messages past UIPI.
    WINCALL DragAcceptFiles, qword ptr [g_hwnd], 1
    WINCALL ChangeWindowMessageFilterEx, qword ptr [g_hwnd], WM_DROPFILES, MSGFLT_ALLOW, 0
    WINCALL ChangeWindowMessageFilterEx, qword ptr [g_hwnd], WM_COPYGLOBALDATA, MSGFLT_ALLOW, 0
    ; ...and as a real OLE drop target, which is the one that a shell drag
    ; actually reaches.  The object is pointed at its vtable HERE rather than
    ; being initialised where it is declared, because gui.asm has no .data
    ; section; a null left here is accepted by RegisterDragDrop and faults
    ; inside ole32 on the first drag over the window.
    lea     rax, [vtbl_DropTarget]
    mov     qword ptr [g_droptgt], rax
    mov     dword ptr [g_dt_refs], 1
    ; OleInitialize enters the apartment RegisterDragDrop requires, and is
    ; deliberately NOT balanced here: the registration has to outlive wp_create.
    ; wp_destroy revokes and uninitialises.  The CoInitializeEx/CoUninitialize
    ; pairs around the file pickers nest inside it harmlessly - same apartment
    ; model, so they return S_FALSE and only move the reference count.
    WINCALL OleInitialize, 0
    test    eax, eax
    js      wp_create_nodrag                 ; FAILED(hr): only the sign bit says so
    mov     dword ptr [g_ole_ok], 1
    WINCALL RegisterDragDrop, qword ptr [g_hwnd], addr g_droptgt
    test    eax, eax
    jnz     wp_create_nodrag
    mov     dword ptr [g_dt_ok], 1
wp_create_nodrag:
    ; logo shine animation timer (id 2, ~30 fps)
    WINCALL SetTimer, qword ptr [g_hwnd], 2, 33, 0
    xor     rax, rax
    jmp     wp_ret

wp_drawitem:
    mov     rcx, qword ptr [rbp-32]      ; DRAWITEMSTRUCT*
    mov     eax, dword ptr [rcx+DI_CTLID]
    cmp     eax, ID_LOGO
    jne     @F
    call    draw_logo
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_HAMBURGER
    je      @F
    cmp     eax, ID_CMD_CLOSE
    jne     dr_notglyph
@@:
    call    draw_glyph_btn
    mov     rax, 1
    jmp     wp_ret
dr_notglyph:
    cmp     eax, ID_SEP
    jne     @F
    call    draw_sep
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_CMDBAR
    jne     @F
    call    draw_cmdbar
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_CMD_REMOVE
    jne     @F
    call    draw_glyph_btn
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_CMD_CLEAR
    jne     @F
    call    draw_glyph_btn
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_ADDFILES
    jne     @F
    call    draw_glyph_btn
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_ADDFOLDER
    jne     @F
    call    draw_glyph_btn
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_SHOWPW
    jne     @F
    call    draw_show_icon
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_COMPRESS
    je      wp_di_toggle
    cmp     eax, ID_SECUREDESK
    jne     @F
wp_di_toggle:
    call    draw_toggle
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_FORMAT
    jne     @F
    call    draw_format_seg
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_PWINFO
    jne     @F
    call    draw_info_icon
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_GENHDR
    je      wp_di_hdr
    cmp     eax, ID_KDFHDR
    je      wp_di_hdr
    cmp     eax, ID_PWHDR
    jne     @F
wp_di_hdr:
    call    draw_header
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_PWFLYOUT
    jne     @F
    call    draw_flyout
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_LOGLVL
    je      wp_di_slider
    cmp     eax, ID_VOLSPLIT
    je      wp_di_slider
    cmp     eax, ID_PWMINLEN
    je      wp_di_slider
    cmp     eax, ID_KDFTIME
    je      wp_di_slider
    cmp     eax, ID_KDFMEM
    je      wp_di_slider
    cmp     eax, ID_PWMINCLASSES
    jne     @F
wp_di_slider:
    call    draw_slider
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_CRUMB
    jne     @F
    call    draw_crumb
    mov     rax, 1
    jmp     wp_ret
@@:
    cmp     eax, ID_STRENGTH
    je      wp_di_bar
    cmp     eax, ID_PROG
    jne     @F
wp_di_bar:
    call    draw_bar
    mov     rax, 1
    jmp     wp_ret
@@:
    call    draw_button
    mov     rax, 1
    jmp     wp_ret

wp_notify:
    mov     rcx, qword ptr [rbp-32]      ; NMHDR*
    mov     rdx, qword ptr [rcx+NMH_idFrom]
    cmp     rdx, ID_LIST
    jne     wp_default
    mov     eax, dword ptr [rcx+NMH_code]
    ; Double-click opens or closes a folder row.  Chosen over a click target on
    ; a chevron because the rows are owner-measured and a hit zone that small
    ; would be its own source of misses.
    cmp     eax, NM_DBLCLK
    jne     @F
    mov     ecx, dword ptr [rcx+NMIA_iItem]
    call    row_toggle
    xor     rax, rax
    jmp     wp_ret
@@:
    ; LVN_ITEMCHANGING used to be answered with TRUE whenever LVIF_STATE was
    ; involved, which VETOES the change - the list was a read-only display and
    ; was made non-selectable on purpose.  The list is now something you select
    ; rows in and remove them, so the veto is gone.  It was the actual reason
    ; clicks did nothing: the control received them, asked permission, and was
    ; refused.
    ;
    ; Focus moving to a row scrolls it into the band.  The control cannot do
    ; this itself any more - it is as tall as its contents, so as far as it is
    ; concerned every row is already on screen - and without it the arrow keys
    ; walk the selection straight out of the viewport.
    ; Dragging rows OUT.  The list sends this once the user has moved far
    ; enough with the button down for it to be a drag rather than a click, so
    ; there is no threshold to guess at here.
    cmp     eax, LVN_BEGINDRAG
    jne     @F
    call    container_drag_out
    xor     rax, rax
    jmp     wp_ret
@@:
    cmp     eax, LVN_ITEMCHANGED
    jne     @F
    mov     eax, dword ptr [rcx+NMLV_uChanged]
    test    eax, LVIF_STATE
    jz      wp_notify_def
    mov     qword ptr [rbp-40], rcx          ; the handler below still needs it
    call    container_update_action
    mov     rcx, qword ptr [rbp-40]
    mov     eax, dword ptr [rcx+NMLV_uNewState]
    test    eax, LVIS_FOCUSED
    jz      wp_notify_def
    mov     eax, dword ptr [rcx+NMLV_uOldState]
    test    eax, LVIS_FOCUSED
    jnz     wp_notify_def                ; already had focus: nothing moved
    movsxd  rcx, dword ptr [rcx+NMLV_iItem]
    call    lv_ensure_visible
    xor     rax, rax
    jmp     wp_ret
@@:
    ; per-file progress cells: owner-draw via NM_CUSTOMDRAW
    cmp     eax, NM_CUSTOMDRAW_CODE
    jne     wp_default
    mov     eax, dword ptr [rcx+NMCD_dwDrawStage]
    cmp     eax, CDDS_PREPAINT
    jne     @F
    mov     rax, CDRF_NOTIFYITEMDRAW
    jmp     wp_ret
@@:
    cmp     eax, CDDS_ITEMPREPAINT
    jne     @F
    call    lv_fill_row                  ; rcx still = NMCUSTOMDRAW*
    mov     rax, CDRF_NOTIFYSUBITEMDRAW
    jmp     wp_ret
@@:
    cmp     eax, CDDS_ITEMPREPAINT_SUB
    jne     wp_notify_def
    mov     edx, dword ptr [rcx+NMLVCD_iSubItem]
    cmp     edx, 2                       ; only the Progress column
    jne     wp_notify_def
    call    draw_lv_progress             ; rcx still = NMLVCUSTOMDRAW*
    mov     rax, CDRF_SKIPDEFAULT
    jmp     wp_ret
wp_notify_def:
    xor     rax, rax                     ; CDRF_DODEFAULT
    jmp     wp_ret

wp_ctlstatic:
    ; validation underlines get a state-coloured brush; labels get dark bg + white text
    mov     rax, qword ptr [rbp-32]      ; lParam = control hwnd
    cmp     rax, qword ptr [g_hpw_under]
    je      wp_under_pw
    cmp     rax, qword ptr [g_hcf_under]
    je      wp_under_cf
    ; The statistics line carries the outcome now that nothing else does: there
    ; is no "Done" box to dismiss, so a failed run has to be visible in the
    ; window itself rather than only in the box that was already closed.
    cmp     rax, qword ptr [g_hscan]
    jne     wp_ctl_white
    cmp     dword ptr [g_scan_fail], 0
    je      wp_ctl_white
    WINCALL SetTextColor, qword ptr [rbp-24], CLR_INVALID
    WINCALL SetBkColor, qword ptr [rbp-24], CLR_DARK
    mov     rax, qword ptr [g_hbr_dark]
    jmp     wp_ret
wp_ctl_white:
    WINCALL SetTextColor, qword ptr [rbp-24], CLR_WHITE   ; rbp-24 = hdc
    WINCALL SetBkColor, qword ptr [rbp-24], CLR_DARK
    mov     rax, qword ptr [g_hbr_dark]
    jmp     wp_ret
wp_under_pw:
    mov     ecx, dword ptr [g_pw_state]
    call    underline_brush
    jmp     wp_ret
wp_under_cf:
    mov     ecx, dword ptr [g_cf_state]
    call    underline_brush
    jmp     wp_ret

wp_ctledit:
    ; password field: dark bg, white typed text (placeholder stays grey, drawn
    ; separately by edit_subclass)
    WINCALL SetTextColor, qword ptr [rbp-24], CLR_WHITE
    WINCALL SetBkColor, qword ptr [rbp-24], CLR_DARK
    mov     rax, qword ptr [g_hbr_dark]
    jmp     wp_ret

wp_ctlbtn:
    WINCALL SetTextColor, qword ptr [rbp-24], CLR_WHITE
    WINCALL SetBkColor, qword ptr [rbp-24], CLR_DARK
    mov     rax, qword ptr [g_hbr_dark]
    jmp     wp_ret

wp_command:
    ; id = LOWORD(wParam), notif = HIWORD(wParam)
    mov     rax, qword ptr [rbp-24]
    mov     r9, rax
    shr     r9, 16
    movzx   r9d, r9w                     ; notif
    movzx   eax, ax                      ; id
    cmp     eax, ID_ACTION
    je      wp_action
    cmp     eax, ID_CANCEL
    je      wp_cancel
    cmp     eax, IDCANCEL                ; ESC (via IsDialogMessageW)
    je      wp_escape
    cmp     eax, ID_SHOWPW
    je      wp_show
    cmp     eax, ID_COMPRESS
    je      wp_compress
    cmp     eax, ID_FORMAT
    je      wp_format
    cmp     eax, ID_SECUREDESK
    je      wp_securedesk
    cmp     eax, ID_HAMBURGER
    je      wp_hamburger
    cmp     eax, ID_PWINFO
    je      wp_pwinfo
    cmp     eax, ID_CHANGE
    je      wp_change
    cmp     eax, ID_ADDFILES
    je      wp_addfiles
    cmp     eax, ID_ADDFOLDER
    je      wp_addfolder
    cmp     eax, ID_CMD_REMOVE
    je      wp_cmdremove
    cmp     eax, ID_CMD_CLEAR
    je      wp_cmdclear
    cmp     eax, ID_CMD_CLOSE
    je      wp_cancel                    ; same answer as the Exit button
    cmp     eax, ID_SCAN
    je      wp_showlog                   ; the statistics line opens the action log
    cmp     eax, ID_LOGO
    je      wp_aboutitem                 ; the wordmark IS the About trigger now
    cmp     eax, ID_PASS
    je      wp_pwchange
    cmp     eax, ID_CONFIRM
    je      wp_pwchange
    jmp     wp_default
; These two are invoked from the SIDEBAR now, not from inside the panel, so the
; panel is normally already closed.  toggle_menu is unconditional - calling it
; here used to close the panel the item was sitting in, and from the sidebar it
; would OPEN it instead, which is exactly what happened on the first run.
; ESC closes the flyout first, and only closes the WINDOW if it was not open.
; A panel that a click opened has to be dismissable without deciding to quit,
; and Escape is where everyone reaches for that.  Only on this path, not on
; ID_CANCEL: that is the Exit BUTTON, and pressing Exit means Exit whatever else
; happens to be showing.
wp_escape:
    cmp     qword ptr [g_hpwflyout], 0
    je      wp_cancel
    WINCALL IsWindowVisible, qword ptr [g_hpwflyout]
    test    eax, eax
    jz      wp_cancel
    WINCALL ShowWindow, qword ptr [g_hpwflyout], SW_HIDE
    jmp     wp_zero

; Deliberately allowed WHILE a job runs.  "What is it doing" is a question that
; wants answering during, not only after, and the log is written on the worker
; and read here in a way that tolerates exactly that (see ramlog.asm).
wp_showlog:
    call    show_logbox
    jmp     wp_zero
wp_addfiles:
    cmp     dword ptr [g_running], 0
    jne     wp_zero
    cmp     dword ptr [g_menu_open], 0
    je      @F
    call    toggle_menu                  ; only if the user left it open
@@:
    xor     ecx, ecx
    cmp     dword ptr [g_container], 0
    je      @F
    call    container_add                ; browsing: append to the archive
    jmp     wp_zero
@@:
    call    add_via_picker
    jmp     wp_zero
wp_addfolder:
    cmp     dword ptr [g_running], 0
    jne     wp_zero
    cmp     dword ptr [g_menu_open], 0
    je      @F
    call    toggle_menu
@@:
    mov     ecx, 1
    cmp     dword ptr [g_container], 0
    je      @F
    call    container_add
    jmp     wp_zero
@@:
    call    add_via_picker
    jmp     wp_zero
wp_cmdremove:
    call    remove_selected
    jmp     wp_zero
wp_cmdclear:
    call    clear_inputs
    jmp     wp_zero
wp_aboutitem:
    ; Reached from the WORDMARK now, not from inside the settings panel, so the
    ; panel is normally already closed - toggle_menu would open it.  Same trap
    ; the two add actions hit when they moved to the sidebar.
    cmp     dword ptr [g_menu_open], 0
    je      @F
    call    toggle_menu
@@:
    ; show_about owns the process's only message loop and posts WM_QUIT when it
    ; closes, so calling it from here would take the main window down with it.
    ; mbox runs a modal pump that leaves the main loop alive - see its header.
    lea     rcx, [m_about_body]
    lea     rdx, [t_about]
    mov     r8d, MB_OK
    call    mbox
    jmp     wp_zero
wp_action:
    cmp     dword ptr [g_running], 0
    jne     wp_zero
    cmp     dword ptr [g_menu_open], 0   ; close the settings panel first if open
    je      @F
    call    toggle_menu
@@:
    call    start_operation
    jmp     wp_zero
wp_cancel:
    ; Exit button: while idle -> close the window; while running -> cancel the op
    cmp     dword ptr [g_running], 0
    jne     wp_exit_cancel
    WINCALL DestroyWindow, qword ptr [rbp-8]
    jmp     wp_zero
wp_exit_cancel:
    mov     dword ptr [g_cancelled], 1
    call    progress_abort
    jmp     wp_zero
wp_show:
    call    toggle_show
    jmp     wp_zero
wp_compress:
    cmp     dword ptr [g_running], 0
    jne     wp_zero
    call    toggle_compress
    jmp     wp_zero
wp_format:
    cmp     dword ptr [g_running], 0
    jne     wp_zero
    call    format_pick
    jmp     wp_zero
wp_securedesk:
    cmp     dword ptr [g_running], 0
    jne     wp_zero
    call    toggle_securedesk
    jmp     wp_zero
wp_hamburger:
    call    toggle_menu
    jmp     wp_zero
wp_pwinfo:
    ; toggle the class-explanation flyout.  It lives on the main window, not in
    ; the host, so it needs the raise the host gets in toggle_menu.
    WINCALL IsWindowVisible, qword ptr [g_hpwflyout]
    test    eax, eax
    mov     ecx, 5                       ; SW_SHOW
    jz      @F
    xor     ecx, ecx                     ; already visible -> SW_HIDE
@@:
    cmp     ecx, 0
    je      @F
    mov     rcx, qword ptr [g_hpwflyout]
    call    raise_window
    mov     ecx, 5
@@:
    WINCALL ShowWindow, qword ptr [g_hpwflyout], ecx
    jmp     wp_zero

wp_change:
    cmp     dword ptr [g_running], 0
    jne     wp_zero
    call    do_change_dest
    jmp     wp_zero
wp_pwchange:
    cmp     r9d, EN_CHANGE
    jne     wp_zero
    cmp     dword ptr [g_op], 0
    jne     wp_zero
    call    update_strength
    jmp     wp_zero

wp_timer:
    cmp     qword ptr [rbp-24], 2        ; wParam = timer id
    jne     @F
    call    on_logo_timer
    jmp     wp_zero
@@:
    cmp     qword ptr [rbp-24], 3        ; scan-status timer
    jne     @F
    call    on_scan_timer
    jmp     wp_zero
@@:
    call    on_timer
    jmp     wp_zero

wp_appdone:
    call    on_done
    jmp     wp_zero

wp_appindexed:
    call    on_index_done
    jmp     wp_zero

wp_close:
    cmp     dword ptr [g_running], 0
    jne     wp_zero
    WINCALL DestroyWindow, qword ptr [rbp-8]
    jmp     wp_zero

wp_destroy:
    ; Revoke while the HWND is still valid.  ole32 keys its target table by
    ; window handle, and an entry that outlives its window is a dangling one.
    cmp     dword ptr [g_dt_ok], 0
    je      wp_destroy_noole
    mov     dword ptr [g_dt_ok], 0
    WINCALL RevokeDragDrop, qword ptr [g_hwnd]
wp_destroy_noole:
    cmp     dword ptr [g_ole_ok], 0
    je      wp_destroy_quit
    mov     dword ptr [g_ole_ok], 0
    WINCALL OleUninitialize
wp_destroy_quit:
    call    rlog_wipe                    ; it held every path the operation touched
    WINCALL PostQuitMessage, 0
    jmp     wp_zero

wp_default:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    jmp     wp_ret
wp_zero:
    xor     rax, rax
wp_ret:
    add     rsp, 80
    pop     rbp
    ret
wndproc endp

; =============================================================================
; wstr_equal(rcx = a, rdx = b) -> eax = 1 if identical, else 0.  EXACT and
; case-sensitive, unlike weqi below: this compares a password against its
; confirmation.  Not constant-time, and it does not need to be - both strings
; were just typed by the same user into the same process, so there is no
; attacker-observable timing channel here.
wstr_equal proc
    xor     r9, r9
wse_loop:
    ; Load the second string's char into r8d, NOT dx: dx IS the low half of rdx,
    ; so writing it would overwrite the pointer being walked and every compare
    ; past index 0 would read from a corrupted address.  That bug shipped, and
    ; its effect was that two identical passwords never matched.
    movzx   eax, word ptr [rcx+r9*2]
    movzx   r8d, word ptr [rdx+r9*2]
    cmp     eax, r8d
    jne     wse_no
    test    eax, eax
    jz      wse_yes
    inc     r9
    jmp     wse_loop
wse_no:
    xor     eax, eax
    ret
wse_yes:
    mov     eax, 1
    ret
wstr_equal endp

; weqi(rcx = a, rdx = b) -> eax 1 if equal (case-insensitive ASCII), else 0
; =============================================================================
weqi proc
    xor     r9, r9
weqi_l:
    movzx   eax, word ptr [rcx+r9*2]
    movzx   r8d, word ptr [rdx+r9*2]
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 20h
@@:
    cmp     r8d, 'A'
    jb      @F
    cmp     r8d, 'Z'
    ja      @F
    add     r8d, 20h
@@:
    cmp     eax, r8d
    jne     weqi_no
    test    eax, eax
    jz      weqi_yes
    inc     r9
    jmp     weqi_l
weqi_no:
    xor     eax, eax
    ret
weqi_yes:
    mov     eax, 1
    ret
weqi endp

; =============================================================================
; warg_is_help(rcx = wide arg) -> eax 1 if it's a help switch.
; Accepts (any case): /? -? ? /h -h h /help -help --help help.
; =============================================================================
warg_is_help proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     r10, rcx
wih_skip:
    movzx   eax, word ptr [r10]
    cmp     ax, '/'
    je      wih_adv
    cmp     ax, '-'
    je      wih_adv
    jmp     wih_chk
wih_adv:
    add     r10, 2
    jmp     wih_skip
wih_chk:
    movzx   eax, word ptr [r10]
    cmp     ax, '?'
    je      wih_yes
    mov     rcx, r10
    lea     rdx, [sw_help]
    call    weqi
    test    eax, eax
    jnz     wih_yes
    mov     rcx, r10
    lea     rdx, [sw_h]
    call    weqi
    test    eax, eax
    jnz     wih_yes
    xor     eax, eax
    jmp     wih_done
wih_yes:
    mov     eax, 1
wih_done:
    add     rsp, 48
    pop     rbp
    ret
warg_is_help endp

; =============================================================================
; gui_main - parse argv, classify mode, register class, create window, run loop
; =============================================================================
gui_main proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 256                     ; large frame: keep locals clear of the
                                         ; CreateWindowExW outgoing-arg area so W/H
                                         ; survive for the post-create rounding
    WINCALL GetCommandLineW
    WINCALL CommandLineToArgvW, rax, addr g_argc
    mov     qword ptr [rbp-16], rax              ; argv
    ; No arguments is now a normal start, not a usage error: the main window
    ; opens empty and files arrive by drop or from the menu.  About moved to the
    ; hamburger, since this used to be its only way in.
    cmp     dword ptr [g_argc], 2
    jl      gm_gather
gm_chkhelp:
    mov     rax, qword ptr [rbp-16]
    mov     rcx, qword ptr [rax+8]               ; argv[1]
    call    warg_is_help
    test    eax, eax
    jz      gm_gather
    call    show_about                           ; -h / --help / help
    jmp     gm_quit
gm_gather:
    ; argv[1..] become inputs (capped at MAX_ARGS)
    mov     qword ptr [rbp-24], 1                ; argv index
    mov     qword ptr [rbp-32], 0                ; input index
gm_argloop:
    mov     eax, dword ptr [g_argc]
    cmp     qword ptr [rbp-24], rax
    jae     gm_argdone
    cmp     qword ptr [rbp-32], MAX_ARGS
    jae     gm_argdone
    mov     rax, qword ptr [rbp-16]
    mov     r10, qword ptr [rbp-24]
    mov     rdx, qword ptr [rax+r10*8]           ; argv[i]
    mov     qword ptr [rbp-40], rdx
    ; "--to <dir>" - where the shell extension hands over the drop target.  It
    ; sits AFTER the file arguments on purpose: argv[1] must stay a path, or
    ; is_cli_command would route this to the (refused) CLI instead of the GUI.
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [w_opt_to]
    call    wstr_equal
    test    eax, eax
    jz      gm_notto
    mov     rax, qword ptr [rbp-24]
    inc     rax
    mov     r10d, dword ptr [g_argc]
    cmp     rax, r10
    jae     gm_argdone                           ; "--to" with nothing after it
    mov     r10, qword ptr [rbp-16]
    mov     rdx, qword ptr [r10+rax*8]           ; the directory
    lea     rcx, [g_argdest]
    WBOUND  r8, g_argdest, 4100
    call    wcopy
    mov     dword ptr [g_have_dest], 1
    add     qword ptr [rbp-24], 2                ; consume both
    jmp     gm_argloop
gm_notto:
    mov     rcx, qword ptr [rbp-32]
    call    slot_addr                            ; rax = dst slot, r8 = its bound
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-40]              ; argv[i] - attacker-length path
    call    wcopy                                ; r8 still holds slot_addr's bound
    inc     qword ptr [rbp-24]
    inc     qword ptr [rbp-32]
    jmp     gm_argloop
gm_argdone:
    ; Zero inputs is no longer a reason to quit - it is the empty window.
    ; g_has_file stays 0, which already gates start_encrypt and the up-front
    ; password prompt; update_strength keeps the action button disabled.
    mov     rcx, qword ptr [rbp-32]
    call    set_input_ptrs
    mov     eax, 1
    cmp     qword ptr [g_poscount], 0
    jne     @F
    xor     eax, eax
@@:
    mov     dword ptr [g_has_file], eax
    call    detect_op                            ; sets g_op / g_is_archive

    ; ---- init ---------------------------------------------------------------
    WINCALL GetModuleHandleW, 0
    mov     qword ptr [g_hinst], rax
    ; Segoe UI ~10pt UI font (h, w, esc, orient, weight, ital, undl, strk,
    ;   charset, outprec, clipprec, quality, pitch, face)
    WINCALL CreateFontW, -14, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr fontface
    mov     qword ptr [g_hfont], rax
    ; Segoe UI Semibold ~11pt heading font (breadcrumb)
    WINCALL CreateFontW, -15, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, addr fontface
    mov     qword ptr [g_hfont_head], rax
    ; large bold runic font for the logo (Segoe UI Historic covers the Runic block)
    ; sized for the small lower-left wordmark (was -70 for the old 100px band)
    WINCALL CreateFontW, -26, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0, addr fontface_logo
    mov     qword ptr [g_hfont_logo], rax
    ; icon + symbol fonts for the glyph buttons (probes for the real face)
    call    mk_icon_font
    ; Fluent palette brushes
    call    make_theme
    ; Dark mode has to be declared before any themed control exists, so it goes
    ; ahead of InitCommonControlsEx - a control that has already opened its theme
    ; handle keeps the light one.
    call    enable_dark_mode
    ; InitCommonControlsEx({8, ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES})
    mov     dword ptr [rbp-8], 8
    mov     dword ptr [rbp-4], ICC_PROGRESS_CLASS or ICC_LISTVIEW_CLASSES or ICC_TAB_CLASSES
    WINCALL InitCommonControlsEx, addr rbp-8
    ; register class
    lea     rcx, [g_wc]
    xor     r9, r9
gm_zwc:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, WC_SIZE
    jb      gm_zwc
    mov     dword ptr [g_wc+0], WC_SIZE
    mov     dword ptr [g_wc+4], CS_DROPSHADOW   ; class style: drop shadow
    lea     rax, [wndproc]
    mov     qword ptr [g_wc+8], rax
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [g_wc+24], rax
    WINCALL LoadIconW, qword ptr [g_hinst], 1   ; our app icon (resource ID 1)
    mov     qword ptr [g_wc+32], rax            ; hIcon
    mov     qword ptr [g_wc+72], rax            ; hIconSm
    WINCALL LoadCursorW, 0, IDC_ARROW
    mov     qword ptr [g_wc+40], rax
    mov     rax, qword ptr [g_hbr_dark]
    mov     qword ptr [g_wc+48], rax            ; dark window background (#20201F)
    lea     rax, [wc_class]
    mov     qword ptr [g_wc+64], rax
    WINCALL RegisterClassExW, addr g_wc
    ; window title + size depend on the mode (WS_POPUP: this is the client size)
    lea     r8, [wtitle_enc]
    mov     dword ptr [rbp-48], 530              ; W (encrypt)
    ; LAY_BOTTOM, not a second copy of it: do_layout reserves exactly this band
    ; below the list, and the two disagreeing means the first layout pass moves
    ; everything the moment the window appears.
    mov     dword ptr [rbp-52], LV_Y+LV_H+LAY_BOTTOM   ; H: list + stats + pw + buttons
    cmp     dword ptr [g_op], 0
    je      @F
    lea     r8, [wtitle_dec]
    ; ... but a CONTAINER view is the encrypt window with different labels, so it
    ; needs the encrypt window's room.  Only the zip dialog is the short one.
    cmp     dword ptr [g_container], 0
    jne     @F
    mov     dword ptr [rbp-48], 530              ; W (decrypt)
    mov     dword ptr [rbp-52], 198              ; H (decrypt)
@@:
    mov     qword ptr [rbp-64], r8               ; title ptr
    ; centre the window: X = (screenW - W)/2, Y = (screenH - H)/2
    WINCALL GetSystemMetrics, SM_CXSCREEN
    sub     eax, dword ptr [rbp-48]              ; - W
    sar     eax, 1
    mov     dword ptr [rbp-72], eax              ; X
    WINCALL GetSystemMetrics, SM_CYSCREEN
    sub     eax, dword ptr [rbp-52]              ; - H
    sar     eax, 1
    mov     dword ptr [rbp-76], eax              ; Y
    ; CreateWindowExW(WS_EX_TOOLWINDOW, class, title, style, X, Y, W, H, 0, 0, hinst, 0)
    WINCALL CreateWindowExW, <WS_EX_TOOLWINDOW or WS_EX_LAYERED>, addr wc_class, qword ptr [rbp-64], ST_MAINWND, dword ptr [rbp-72], dword ptr [rbp-76], dword ptr [rbp-48], dword ptr [rbp-52], 0, 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_hwnd], rax
    ; 90% opaque: uniform layered alpha over the whole window
    WINCALL SetLayeredWindowAttributes, qword ptr [g_hwnd], 0, WIN_ALPHA, LWA_ALPHA
    ; round the window corners: SetWindowRgn(CreateRoundRectRgn(0,0,W+1,H+1,16,16))
    mov     r8d, dword ptr [rbp-48]              ; right = W+1
    inc     r8d
    mov     r9d, dword ptr [rbp-52]              ; bottom = H+1
    inc     r9d
    WINCALL CreateRoundRectRgn, 0, 0, r8d, r9d, WIN_ROUND, WIN_ROUND
    ; region (owned by the window now), redraw
    WINCALL SetWindowRgn, qword ptr [g_hwnd], rax, 1
    ; accelerator table: ESC -> Exit
    WINCALL CreateAcceleratorTableW, addr g_accel, 1
    mov     qword ptr [g_haccel], rax
    ; ---- ask for the password BEFORE anything is shown -----------------------
    ; Launched from the context menu the intent is already stated - encrypt this,
    ; decrypt that - so a window whose only job is to collect a second
    ; confirmation is a step with nothing in it.  Ask first; the main window then
    ; appears already working, as progress.  It is created but not yet shown, so
    ; it can carry that progress when it arrives.
    ;
    ; Cancelling exits without ever painting a window, which is the honest answer
    ; to "I changed my mind": nothing was started, so nothing is reported.
    cmp     dword ptr [g_has_file], 0
    je      gm_show
    ; ---- a .mrk container OPENS; it does not extract itself ------------------
    ; Handing a container to Myrkr used to mean "decrypt this now", so the
    ; contents were gone before anyone had seen what they were.  Opening one now
    ; asks for the password - the inventory is behind the same key, so there is
    ; nothing to show until it has been given - and then shows what is inside.
    ; Extracting is the button the user presses next, not something that has
    ; already happened.
    ;
    ; This runs whatever g_cfg_securedesk says: that setting is about WHERE the
    ; password is typed, which read_password settles, not about what opening a
    ; container means.  The encrypt and zip paths below still consult it, and
    ; only to decide whether to ask before the window appears.
    cmp     dword ptr [g_container], 0
    je      gm_notcontainer
    call    container_load
    test    eax, eax
    jnz     gm_cl_failed
    WINCALL ShowWindow, qword ptr [g_hwnd], SW_SHOW
    WINCALL UpdateWindow, qword ptr [g_hwnd]
    jmp     gm_loop
gm_cl_failed:
    ; cancelled, or the password was wrong: nothing was started and nothing was
    ; shown, which is the honest answer to either
    WINCALL DestroyWindow, qword ptr [g_hwnd]
    jmp     gm_quit
gm_notcontainer:
    cmp     dword ptr [g_cfg_securedesk], 0
    je      gm_show
    ; Encrypting something handed in from the shell: ask where the container
    ; goes BEFORE asking for the password.  Where a thing goes is a smaller
    ; question than committing a secret to it, and cancelling here costs
    ; nothing - which is not true once a password has been typed.
    cmp     dword ptr [g_op], 0
    jne     gm_pw
    call    build_output
    call    ask_output
    test    eax, eax
    jz      gm_pw
    WINCALL DestroyWindow, qword ptr [g_hwnd]
    jmp     gm_quit
gm_pw:
    call    read_password
    test    eax, eax
    jz      @F
    WINCALL DestroyWindow, qword ptr [g_hwnd]
    jmp     gm_quit
@@:
    mov     dword ptr [g_pw_ready], 1
    ; A RIGHT-DRAG gets out of the way.  It has already been told what and where,
    ; so the main window has nothing left to ask and offering it at the end only
    ; invites edits to a job that is over.  The small progress window takes its
    ; place and owns the ending: closes itself on success, stops with the log
    ; open on a failure.
    ;
    ; The main window is still CREATED, just never shown.  It owns the controls
    ; the worker's completion posts to, the timer, and every handler on_done
    ; drives; making the operation run without it would mean rewriting all of
    ; that to prove a point about which window is visible.
    cmp     dword ptr [g_have_dest], 0
    je      gm_pw_mainwin
    call    progwin_show
    test    eax, eax
    jz      gm_pw_mainwin                     ; could not create it: fall back
    call    start_operation
    jmp     gm_loop
gm_pw_mainwin:
    WINCALL ShowWindow, qword ptr [g_hwnd], SW_SHOW
    WINCALL UpdateWindow, qword ptr [g_hwnd]
    call    start_operation
    jmp     gm_loop
gm_show:
    WINCALL ShowWindow, qword ptr [g_hwnd], SW_SHOW
    WINCALL UpdateWindow, qword ptr [g_hwnd]
    ; put keyboard focus on the password field so typing starts there at once
    mov     rcx, qword ptr [g_hpass]
    test    rcx, rcx
    jz      gm_loop
    WINCALL SetFocus, rcx
gm_loop:
    WINCALL GetMessageW, addr rbp-80, 0, 0, 0    ; MSG at [rbp-80..rbp-33]
    test    eax, eax
    jz      gm_quit
    js      gm_quit
    ; Enter while typing the password -> click Encrypt (only if it is enabled)
    cmp     dword ptr [rbp-72], WM_KEYDOWN        ; MSG.message
    jne     gm_notret
    cmp     qword ptr [rbp-64], VK_RETURN         ; MSG.wParam
    jne     gm_notret
    WINCALL GetFocus
    cmp     rax, qword ptr [g_hpass]
    jne     gm_notret
    WINCALL IsWindowEnabled, qword ptr [g_haction]
    test    eax, eax
    jz      gm_loop                               ; disabled -> swallow the Enter
    WINCALL SendMessageW, qword ptr [g_hwnd], WM_COMMAND, ID_ACTION, 0
    jmp     gm_loop
gm_notret:
    ; ESC -> Exit via the accelerator table (sends WM_COMMAND ID_CANCEL)
    WINCALL TranslateAcceleratorW, qword ptr [g_hwnd], qword ptr [g_haccel], addr rbp-80
    test    eax, eax
    jnz     gm_loop
    WINCALL IsDialogMessageW, qword ptr [g_hwnd], addr rbp-80
    test    eax, eax
    jnz     gm_loop
    WINCALL TranslateMessage, addr rbp-80
    WINCALL DispatchMessageW, addr rbp-80
    jmp     gm_loop
gm_quit:
    xor     eax, eax
    add     rsp, 256
    pop     rbp
    ret
gui_main endp

; =============================================================================
; draw_about(rcx = DRAWITEMSTRUCT*) - paint the body of the no-args About box:
; the app icon, the name/version/tagline header, a hairline rule, the prose +
; command-line synopsis, and a footer URL.  Owner-draw STATIC, so the HDC and
; rcItem arrive in the DRAWITEMSTRUCT and (0,0) is just below the logo band.
;   locals (frame 160): di[-8] hdc[-16] rcItem(l-32,t-28,r-24,b-20)
;                        scratch RECT(l-56,t-52,r-48,b-44)  iconY[-64]
; =============================================================================
draw_about proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 160
    mov     qword ptr [rbp-8], rcx
    mov     rax, qword ptr [rcx+DI_HDC]
    mov     qword ptr [rbp-16], rax
    mov     eax, dword ptr [rcx+DI_RCITEM+0]
    mov     dword ptr [rbp-32], eax              ; L
    mov     eax, dword ptr [rcx+DI_RCITEM+4]
    mov     dword ptr [rbp-28], eax              ; T
    mov     eax, dword ptr [rcx+DI_RCITEM+8]
    mov     dword ptr [rbp-24], eax              ; R
    mov     eax, dword ptr [rcx+DI_RCITEM+12]
    mov     dword ptr [rbp-20], eax              ; B
    WINCALL FillRect, qword ptr [rbp-16], addr rbp-32, qword ptr [g_hbr_dark]
    ; hairline edge.  This one is its OWN top-level window rather than a panel
    ; over the main one, so the edge separates it from the desktop instead - the
    ; same job, and the same answer.
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [rbp-32]
    mov     r8d, WIN_ROUND
    mov     r9d, CLR_ACCENT
    call    hairline_rect
    WINCALL SetBkMode, qword ptr [rbp-16], BK_TRANSPARENT
    ; --- app icon (64x64) at (30, T+14) -------------------------------------
    mov     eax, dword ptr [rbp-28]
    add     eax, 14
    mov     dword ptr [rbp-64], eax
    WINCALL DrawIconEx, qword ptr [rbp-16], 30, dword ptr [rbp-64], qword ptr [g_about_icon], 64, 64, 0, 0, DI_NORMAL
    ; --- name (white, head font) at (112, T+14) -----------------------------
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [g_hfont_head]
    WINCALL SetTextColor, qword ptr [rbp-16], CLR_WHITE
    mov     eax, dword ptr [rbp-28]
    add     eax, 14
    mov     dword ptr [rbp-56], 112
    mov     dword ptr [rbp-52], eax
    mov     dword ptr [rbp-48], 400
    add     eax, 34
    mov     dword ptr [rbp-44], eax
    WINCALL DrawTextW, qword ptr [rbp-16], addr s_ab_name, -1, addr rbp-56, <DT_LEFT or DT_SINGLELINE or DT_NOPREFIX>
    ; --- version (accent, body font) at (114, T+48) -------------------------
    WINCALL SelectObject, qword ptr [rbp-16], qword ptr [g_hfont]
    WINCALL SetTextColor, qword ptr [rbp-16], CLR_ACCENT
    mov     eax, dword ptr [rbp-28]
    add     eax, 48
    mov     dword ptr [rbp-56], 114
    mov     dword ptr [rbp-52], eax
    mov     dword ptr [rbp-48], 514
    add     eax, 20
    mov     dword ptr [rbp-44], eax
    WINCALL DrawTextW, qword ptr [rbp-16], addr s_ab_ver, -1, addr rbp-56, <DT_LEFT or DT_SINGLELINE or DT_NOPREFIX>
    ; --- tagline (grey) at (114, T+70) --------------------------------------
    WINCALL SetTextColor, qword ptr [rbp-16], CLR_PLACEHOLDER
    mov     eax, dword ptr [rbp-28]
    add     eax, 70
    mov     dword ptr [rbp-56], 114
    mov     dword ptr [rbp-52], eax
    mov     dword ptr [rbp-48], 514
    add     eax, 20
    mov     dword ptr [rbp-44], eax
    WINCALL DrawTextW, qword ptr [rbp-16], addr s_ab_tag, -1, addr rbp-56, <DT_LEFT or DT_SINGLELINE or DT_NOPREFIX>
    ; --- hairline rule (1px #3A3A3A) at y = T+96, x 30..R-30 ----------------
    mov     eax, dword ptr [rbp-28]
    add     eax, 96
    mov     dword ptr [rbp-56], 30
    mov     dword ptr [rbp-52], eax
    mov     edx, dword ptr [rbp-24]
    sub     edx, 30
    mov     dword ptr [rbp-48], edx
    add     eax, 1
    mov     dword ptr [rbp-44], eax
    WINCALL FillRect, qword ptr [rbp-16], addr rbp-56, qword ptr [g_hbr_track]
    ; --- body prose + CLI synopsis (light grey) rect (30, T+108, R-24, B-44) -
    WINCALL SetTextColor, qword ptr [rbp-16], 0C8C8C8h
    mov     eax, dword ptr [rbp-28]
    add     eax, 108
    mov     dword ptr [rbp-56], 30
    mov     dword ptr [rbp-52], eax
    mov     edx, dword ptr [rbp-24]
    sub     edx, 24
    mov     dword ptr [rbp-48], edx
    mov     edx, dword ptr [rbp-20]
    sub     edx, 44
    mov     dword ptr [rbp-44], edx
    WINCALL DrawTextW, qword ptr [rbp-16], addr ab_body, -1, addr rbp-56, <DT_LEFT or DT_NOPREFIX or DT_WORDBREAK>
    ; --- footer URL (hint grey) at (30, B-30) -------------------------------
    WINCALL SetTextColor, qword ptr [rbp-16], CLR_HINT
    mov     eax, dword ptr [rbp-20]
    sub     eax, 30
    mov     dword ptr [rbp-56], 30
    mov     dword ptr [rbp-52], eax
    mov     dword ptr [rbp-48], 360
    add     eax, 20
    mov     dword ptr [rbp-44], eax
    WINCALL DrawTextW, qword ptr [rbp-16], addr s_ab_foot, -1, addr rbp-56, <DT_LEFT or DT_SINGLELINE or DT_NOPREFIX>
    add     rsp, 160
    pop     rbp
    ret
draw_about endp

; =============================================================================
; make_about_controls - children of the About window: the shared owner-draw
; logo band, the owner-draw body static, and a "Close" button.  Parent is
; g_hwnd (set by about_wndproc on WM_CREATE), so create_ctl wires them up.
; =============================================================================
make_about_controls proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    ; single owner-draw body static spanning the whole window
    lea     rcx, [cls_static]
    lea     rdx, [s_ab_name]                     ; text unused (owner-draw)
    mov     r8, ST_LOGO
    mov     r9, ID_ABOUT
    mov     dword ptr [rsp+32], 0
    mov     dword ptr [rsp+40], 0
    mov     dword ptr [rsp+48], ABOUT_W
    mov     dword ptr [rsp+56], ABOUT_H
    call    create_ctl
    ; Close button, lower-right
    lea     rcx, [cls_button]
    lea     rdx, [s_close]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_CANCEL
    mov     dword ptr [rsp+32], ABOUT_W - 120
    mov     dword ptr [rsp+40], ABOUT_H - 46
    mov     dword ptr [rsp+48], 90
    mov     dword ptr [rsp+56], 30
    call    create_ctl
    mov     qword ptr [g_hcancel], rax
    add     rsp, 64
    pop     rbp
    ret
make_about_controls endp

; =============================================================================
; about_wndproc(rcx=hwnd, rdx=msg, r8=wParam, r9=lParam) -> rax  (raw, no prolog)
; Borderless dark About window: owner-draw logo/body/button, drag-anywhere body,
; close on the Close button.  ESC is handled by the show_about message pump.
; =============================================================================
about_wndproc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    mov     rax, rdx
    cmp     rax, WM_CREATE
    je      ab_create
    cmp     rax, WM_DRAWITEM
    je      ab_draw
    cmp     rax, WM_COMMAND
    je      ab_cmd
    cmp     rax, WM_NCHITTEST
    je      ab_hit
    cmp     rax, WM_NCLBUTTONDBLCLK
    je      ab_zero                              ; swallow body double-click
    cmp     rax, WM_CLOSE
    je      ab_close
    cmp     rax, WM_DESTROY
    je      ab_destroy
    jmp     ab_def
ab_create:
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [g_hwnd], rax
    call    make_about_controls
    mov     rcx, qword ptr [g_hcancel]
    test    rcx, rcx
    jz      ab_zero
    WINCALL SetFocus, rcx
    jmp     ab_zero
ab_draw:
    mov     rcx, qword ptr [rbp-32]              ; DRAWITEMSTRUCT*
    mov     eax, dword ptr [rcx+DI_CTLID]
    cmp     eax, ID_ABOUT
    jne     @F
    call    draw_about
    jmp     ab_one
@@:
    cmp     eax, ID_CANCEL
    jne     ab_def
    mov     rcx, qword ptr [rbp-32]
    call    draw_button
ab_one:
    mov     rax, 1
    jmp     ab_ret
ab_cmd:
    mov     eax, dword ptr [rbp-24]              ; LOWORD(wParam) = control id
    and     eax, 0FFFFh
    cmp     eax, ID_CANCEL
    jne     ab_zero
    WINCALL DestroyWindow, qword ptr [g_hwnd]
    jmp     ab_zero
ab_hit:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    cmp     rax, HTCLIENT
    jne     ab_ret
    mov     rax, HTCAPTION                       ; drag the borderless body
    jmp     ab_ret
ab_close:
    WINCALL DestroyWindow, qword ptr [g_hwnd]
ab_zero:
    xor     rax, rax
    jmp     ab_ret
ab_destroy:
    WINCALL PostQuitMessage, 0
    xor     rax, rax
    jmp     ab_ret
ab_def:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
ab_ret:
    add     rsp, 64
    pop     rbp
    ret
about_wndproc endp

; =============================================================================
; draw_secdesk(rcx = DRAWITEMSTRUCT*) - owner-draw body of the password prompt.
; =============================================================================
draw_secdesk proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     qword ptr [rbp-8], rcx
    call    dr_load
    mov     eax, dword ptr [g_dr_l]
    mov     dword ptr [g_mb_rc+0], eax
    mov     eax, dword ptr [g_dr_t]
    mov     dword ptr [g_mb_rc+4], eax
    mov     eax, dword ptr [g_dr_r]
    mov     dword ptr [g_mb_rc+8], eax
    mov     eax, dword ptr [g_dr_b]
    mov     dword ptr [g_mb_rc+12], eax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_mb_rc, qword ptr [g_hbr_dark]
    ; accent stripe, same language as the message box
    mov     dword ptr [g_mb_rc+8], MB_BAR_W
    WINCALL CreateSolidBrush, CLR_ACCENT
    mov     qword ptr [rbp-48], rax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_mb_rc, qword ptr [rbp-48]
    WINCALL DeleteObject, qword ptr [rbp-48]
    ; hairline edge, after the stripe for the same reason as the message box
    mov     eax, dword ptr [g_dr_r]
    mov     dword ptr [g_mb_rc+8], eax
    mov     rcx, qword ptr [g_dr_hdc]
    lea     rdx, [g_mb_rc]
    mov     r8d, WIN_ROUND
    mov     r9d, CLR_ACCENT
    call    hairline_rect
    WINCALL SetBkMode, qword ptr [g_dr_hdc], 1
    ; title
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_hfont_head]
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_ACCENT
    mov     dword ptr [g_mb_rc+0], SD_PAD
    mov     dword ptr [g_mb_rc+4], SD_PAD
    mov     dword ptr [g_mb_rc+8], SD_W - SD_PAD
    mov     dword ptr [g_mb_rc+12], SD_PAD + SD_TITLE_H
    WINCALL DrawTextW, qword ptr [g_dr_hdc], addr s_sd_title, -1, addr g_mb_rc, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX>
    ; why-this-looks-different hint: an unexplained desktop switch reads as a
    ; fault, so say what happened before the user decides something is wrong.
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_hfont]
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_HINT
    mov     eax, SD_PAD + SD_TITLE_H + 4
    mov     dword ptr [g_mb_rc+4], eax
    add     eax, 17
    mov     dword ptr [g_mb_rc+12], eax
    WINCALL DrawTextW, qword ptr [g_dr_hdc], addr s_sd_hint1, -1, addr g_mb_rc, \
            <DT_LEFT or DT_SINGLELINE or DT_NOPREFIX>
    mov     eax, SD_PAD + SD_TITLE_H + 21
    mov     dword ptr [g_mb_rc+4], eax
    add     eax, 17
    mov     dword ptr [g_mb_rc+12], eax
    WINCALL DrawTextW, qword ptr [g_dr_hdc], addr s_sd_hint2, -1, addr g_mb_rc, \
            <DT_LEFT or DT_SINGLELINE or DT_NOPREFIX>
    ; No drawn field labels: each edit carries its own in-field cue
    ; (edit_subclass), which is where the user is already looking.  Having
    ; both printed the word twice, once above the box and once inside it.
dsd_done:
    add     rsp, 96
    pop     rbp
    ret
draw_secdesk endp

; =============================================================================
; make_secdesk_controls - body, one or two password edits, OK + Cancel.
; =============================================================================
make_secdesk_controls proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    lea     rcx, [cls_static]
    lea     rdx, [s_sd_title]
    mov     r8, ST_LOGO
    mov     r9, ID_SDBODY
    mov     dword ptr [rsp+32], 0
    mov     dword ptr [rsp+40], 0
    mov     dword ptr [rsp+48], SD_W
    mov     eax, dword ptr [g_sd_height]
    mov     dword ptr [rsp+56], eax
    call    create_ctl
    ; password edit
    lea     rcx, [cls_edit]
    lea     rdx, [s_empty]
    mov     r8, ST_PWEDIT
    mov     r9, ID_SDPASS
    mov     dword ptr [rsp+32], SD_PAD
    mov     dword ptr [rsp+40], SD_PAD + SD_TITLE_H + SD_HINT_H + SD_GAP + 2
    mov     dword ptr [rsp+48], SD_W - SD_PAD - SD_PAD - SD_EYE_W    ; stop short of the eye
    mov     dword ptr [rsp+56], SD_EDIT_H
    call    create_ctl
    mov     qword ptr [g_sd_hpass], rax
    WINCALL SendMessageW, rax, EM_LIMITTEXT, PWBUF_CHARS-1, 0
    mov     rcx, qword ptr [g_sd_hpass]
    call    subclass_edit                     ; in-field "Password" cue
    ; strength underline, directly under the field (Vordr's model: the field's
    ; own underline carries the grade, so there is no separate bar to explain)
    lea     rcx, [cls_static]
    lea     rdx, [s_empty]
    mov     r8, ST_UNDER
    mov     r9, ID_SDUNDER
    mov     dword ptr [rsp+32], SD_PAD
    mov     dword ptr [rsp+40], SD_PAD + SD_TITLE_H + SD_HINT_H + SD_GAP + 2 + SD_EDIT_H
    mov     dword ptr [rsp+48], SD_W - SD_PAD - SD_PAD - SD_EYE_W
    mov     dword ptr [rsp+56], 2
    call    create_ctl
    mov     qword ptr [g_sd_hunder], rax
    ; show/hide eye, right of the password field
    lea     rcx, [cls_button]
    lea     rdx, [s_empty]
    mov     r8, ST_OWNERBTN_NT
    mov     r9, ID_SHOWPW
    mov     eax, SD_W - SD_PAD - SD_EYE_W + 4
    mov     dword ptr [rsp+32], eax
    mov     dword ptr [rsp+40], SD_PAD + SD_TITLE_H + SD_HINT_H + SD_GAP + 2
    mov     dword ptr [rsp+48], SD_EYE_W - 4
    mov     dword ptr [rsp+56], SD_EDIT_H
    call    create_ctl
    mov     qword ptr [g_sd_hshow], rax
    ; confirm edit + format row (encrypt only)
    mov     qword ptr [g_sd_hconf], 0
    mov     qword ptr [g_sd_hfmt], 0
    test    dword ptr [g_sd_flags], SDF_CONFIRM
    jz      msc_buttons
    lea     rcx, [cls_edit]
    lea     rdx, [s_empty]
    mov     r8, ST_PWEDIT
    mov     r9, ID_SDCONF
    mov     dword ptr [rsp+32], SD_PAD
    mov     dword ptr [rsp+40], SD_PAD + SD_TITLE_H + SD_HINT_H + SD_GAP + 2 + SD_EDIT_H + SD_GAP + 2
    mov     dword ptr [rsp+48], SD_W - SD_PAD - SD_PAD - SD_EYE_W    ; stop short of the eye
    mov     dword ptr [rsp+56], SD_EDIT_H
    call    create_ctl
    mov     qword ptr [g_sd_hconf], rax
    WINCALL SendMessageW, rax, EM_LIMITTEXT, PWBUF_CHARS-1, 0
    mov     rcx, qword ptr [g_sd_hconf]
    call    subclass_edit                     ; in-field "Confirm" cue
    lea     rcx, [cls_static]
    lea     rdx, [s_empty]
    mov     r8, ST_UNDER
    mov     r9, ID_SDCUNDER
    mov     dword ptr [rsp+32], SD_PAD
    mov     eax, SD_PAD + SD_TITLE_H + SD_HINT_H + SD_GAP + 2 + SD_EDIT_H + SD_GAP + 2 + SD_EDIT_H
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], SD_W - SD_PAD - SD_PAD - SD_EYE_W
    mov     dword ptr [rsp+56], 2
    call    create_ctl
    mov     qword ptr [g_sd_hcunder], rax
    ; ---- format ------------------------------------------------------------
    ; Which container this becomes is a question about the output, and on the
    ; drag-and-drop path this prompt is the only surface the output is ever
    ; discussed on: the drop said where it goes, and nothing else opens.  The
    ; settings panel still carries the default; this changes THIS one.
    lea     rcx, [cls_button]
    lea     rdx, [s_empty]
    mov     r8, ST_OWNERBTN                   ; a tab stop: the prompt may be the
    mov     r9, ID_SDFORMAT                   ; only place this can be reached
    mov     dword ptr [rsp+32], SD_PAD
    mov     eax, dword ptr [g_sd_fmty]
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], SD_W - SD_PAD - SD_PAD
    mov     dword ptr [rsp+56], SD_ROW_H
    call    create_ctl
    mov     qword ptr [g_sd_hfmt], rax
    ; a Format an administrator has fixed is fixed here too - the prompt is not
    ; a way around the setting panel's lock
    cmp     dword ptr [g_lock_format], 0
    je      msc_buttons
    WINCALL EnableWindow, qword ptr [g_sd_hfmt], 0
msc_buttons:
    mov     eax, dword ptr [g_sd_height]
    sub     eax, SD_PAD + SD_BTN_H
    mov     dword ptr [rbp-8], eax
    lea     rcx, [cls_button]
    lea     rdx, [s_mb_ok]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_ACTION
    mov     dword ptr [rsp+32], SD_W - SD_PAD - SD_BTN_W
    mov     eax, dword ptr [rbp-8]
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], SD_BTN_W
    mov     dword ptr [rsp+56], SD_BTN_H
    call    create_ctl
    mov     qword ptr [g_sd_hok], rax
    lea     rcx, [cls_button]
    lea     rdx, [s_mb_cancel]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_CANCEL
    mov     dword ptr [rsp+32], SD_W - SD_PAD - SD_BTN_W - SD_BTN_GAP - SD_BTN_W
    mov     eax, dword ptr [rbp-8]
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], SD_BTN_W
    mov     dword ptr [rsp+56], SD_BTN_H
    call    create_ctl
    ; OK starts disabled: nothing typed yet cannot satisfy the policy
    WINCALL EnableWindow, qword ptr [g_sd_hok], 0
    mov     dword ptr [g_pw_state], 0
    mov     dword ptr [g_cf_state], 0
    WINCALL SetFocus, qword ptr [g_sd_hpass]
    add     rsp, 96
    pop     rbp
    ret
make_secdesk_controls endp

; =============================================================================
; draw_sd_format(rcx = DRAWITEMSTRUCT*) - the prompt's Format row: the label on
; the left, a filled pill on the right naming what the output will be.
;
; The settings panel's chip is a dark fill with an accent outline, which works
; because the panel behind it is #202020.  The prompt's body is #0a0000, so the
; same chip would be an outline around nothing; the fill carries it here
; instead, and the colour does the rest of the work - accent for the encrypted
; container, the muted track grey for a plain zip, because those two are not
; equivalent choices and nothing else on this row says so.
; =============================================================================
draw_sd_format proc
    push    rbp
    mov     rbp, rsp
    ; 96, not 48: dr_pill's RoundRect takes 7 arguments, so the outgoing area
    ; runs to [rsp+56] and the locals have to start above it.
    sub     rsp, 96
    mov     edx, CLR_DARK
    call    dr_load
    call    dr_setfont
    lea     rcx, [s_lbl_format]
    mov     edx, DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [g_dr_l]
    add     r8d, 2
    mov     r9d, dword ptr [g_dr_r]
    sub     r9d, 88
    call    dr_text
    ; pill on the right, vertically centred on the row
    mov     eax, dword ptr [g_dr_t]
    add     eax, dword ptr [g_dr_b]
    sar     eax, 1
    mov     dword ptr [g_dr_cy], eax
    mov     eax, dword ptr [g_dr_r]
    sub     eax, 84
    mov     dword ptr [g_dr_x0], eax
    mov     eax, dword ptr [g_dr_r]
    sub     eax, 4
    mov     dword ptr [g_dr_x1], eax
    mov     edx, CLR_ACCENT
    cmp     dword ptr [g_make_zip], 0
    je      @F
    mov     edx, CLR_TRACK
@@:
    cmp     dword ptr [g_dr_dis], 0           ; locked -> grey whichever it is
    je      @F
    mov     edx, CLR_TRACK
@@:
    mov     dword ptr [g_dr_col], edx
    call    dr_pill
    ; the name, centred over the pill
    lea     rcx, [s_fmt_mrk_s]
    cmp     dword ptr [g_make_zip], 0
    je      @F
    lea     rcx, [s_fmt_zip_s]
@@:
    mov     edx, DT_CENTER or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX
    mov     r8d, dword ptr [g_dr_x0]
    mov     r9d, dword ptr [g_dr_x1]
    call    dr_text
    add     rsp, 96
    pop     rbp
    ret
draw_sd_format endp

; =============================================================================
; out_retarget - the destination is settled before the password is asked for,
; so a format changed AT the prompt has to reach the name that was settled
; under the old one.  Without this a right-drag switched to Zip writes a zip
; called .mrk, which every later open then misreads.
;
; Only a tail that IS the old format's extension is replaced.  A name the user
; typed themselves in the save dialog is theirs, and silently rewriting it
; would be this dialog overruling the one before it; the container is still
; written in the chosen format, under the name that was asked for.
;
; Both extensions are four characters, so the swap is in place.  The comparison
; folds case because the name may have come back from the save dialog.
; =============================================================================
out_retarget proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    ; g_make_zip already holds the NEW format, so the old extension is the one
    ; the other setting would have produced
    lea     r10, [s_ext_zip]
    lea     r11, [s_ext_agcm]
    cmp     dword ptr [g_make_zip], 0
    je      or_have
    lea     r10, [s_ext_agcm]
    lea     r11, [s_ext_zip]
or_have:
    mov     qword ptr [rbp-8], r10               ; extension to replace
    mov     qword ptr [rbp-16], r11              ; extension to write
    lea     rcx, [g_outpath_w]
    call    wlen
    cmp     rax, 4
    jb      or_ret
    lea     rcx, [g_outpath_w]
    lea     rcx, [rcx+rax*2-8]                   ; -> the last four characters
    mov     qword ptr [rbp-24], rcx
    mov     r10, qword ptr [rbp-8]
    xor     r9, r9
or_cmp:
    movzx   eax, word ptr [rcx+r9*2]
    movzx   edx, word ptr [r10+r9*2]             ; the constants are lower case
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 20h
@@:
    cmp     eax, edx
    jne     or_ret                               ; not the derived extension: leave it
    inc     r9
    cmp     r9, 4
    jb      or_cmp
    mov     rcx, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-16]
    xor     r9, r9
or_put:
    mov     ax, word ptr [r11+r9*2]
    mov     word ptr [rcx+r9*2], ax
    inc     r9
    cmp     r9, 4
    jb      or_put
or_ret:
    add     rsp, 48
    pop     rbp
    ret
out_retarget endp

; =============================================================================
; sd_toggle_format - flip the output format from the prompt.
;
; Deliberately does NOT save_setting the way toggle_format does.  The settings
; panel is where the default is set; this is one container being written now,
; and a format picked for a single drag should not quietly become what every
; later drag produces.
; =============================================================================
sd_toggle_format proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     eax, dword ptr [g_make_zip]
    xor     eax, 1
    mov     dword ptr [g_make_zip], eax
    call    out_retarget
    WINCALL InvalidateRect, qword ptr [g_sd_hfmt], 0, 1
    ; A zip with no password is a legitimate outcome and a .mrk never is, so the
    ; format decides whether an empty password may be accepted - re-evaluate, or
    ; OK stays disabled on a choice that has just made it valid.
    call    sd_update
    add     rsp, 48
    pop     rbp
    ret
sd_toggle_format endp

; =============================================================================
; sd_toggle_show - the prompt's own show/hide, mirroring toggle_show.  It cannot
; reuse it: that one drives the main window's fields, which live on the other
; desktop and must not be touched from this thread.
; =============================================================================
sd_toggle_show proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     eax, dword ptr [g_sd_show]
    xor     eax, 1
    mov     dword ptr [g_sd_show], eax
    xor     r8d, r8d                          ; 0 = reveal
    test    eax, eax
    jnz     @F
    mov     r8d, 2Ah                          ; '*'
@@:
    mov     dword ptr [rbp-8], r8d
    WINCALL SendMessageW, qword ptr [g_sd_hpass], EM_SETPASSWORDCHAR, dword ptr [rbp-8], 0
    WINCALL InvalidateRect, qword ptr [g_sd_hpass], 0, 1
    cmp     qword ptr [g_sd_hconf], 0
    je      @F
    WINCALL SendMessageW, qword ptr [g_sd_hconf], EM_SETPASSWORDCHAR, dword ptr [rbp-8], 0
    WINCALL InvalidateRect, qword ptr [g_sd_hconf], 0, 1
@@:
    WINCALL InvalidateRect, qword ptr [g_sd_hshow], 0, 1
    add     rsp, 48
    pop     rbp
    ret
sd_toggle_show endp

; =============================================================================
; sd_update - recompute strength, confirm match and the OK button after every
; keystroke.  Colours each field's OWN underline (Vordr's model) rather than a
; separate bar: password = grade, confirm = match/mismatch.
;
; The policy decides ENABLEMENT; the grade only decides COLOUR.  A password can
; therefore read "fair" and still be accepted, or "good" and still be refused
; for missing a required class - which is the honest thing to show, since the
; policy is an administrator's floor and the grade is advice.
; =============================================================================
sd_update proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80
    WINCALL GetWindowTextW, qword ptr [g_sd_hpass], addr g_passw, PWBUF_CHARS
    mov     dword ptr [rbp-8], eax               ; password length
    ; ---- policy (the gate) ----
    lea     rcx, [g_passw]
    call    pw_policy_ok
    mov     dword ptr [rbp-16], eax
    ; ---- grade (the colour) ----
    xor     eax, eax
    cmp     dword ptr [rbp-8], 0
    je      sdu_pwstate
    lea     rcx, [g_passw]
    mov     edx, dword ptr [rbp-8]
    call    pw_grade
    inc     eax                                  ; grade 0..3 -> state 1..4
sdu_pwstate:
    ; empty -> neutral; fails the policy -> red; else the grade
    cmp     dword ptr [rbp-8], 0
    jne     @F
    xor     eax, eax
    jmp     sdu_setpw
@@:
    cmp     dword ptr [rbp-16], 0
    jne     @F
    mov     eax, 1                               ; red: below the policy floor
@@:
sdu_setpw:
    mov     dword ptr [g_pw_state], eax
    ; ---- confirm ----
    mov     dword ptr [rbp-24], 1                ; match (vacuously, if absent)
    mov     dword ptr [g_cf_state], 0
    cmp     qword ptr [g_sd_hconf], 0
    je      sdu_enable
    WINCALL GetWindowTextW, qword ptr [g_sd_hconf], addr g_confirmw, PWBUF_CHARS
    mov     dword ptr [rbp-32], eax
    lea     rcx, [g_passw]
    lea     rdx, [g_confirmw]
    call    wstr_equal
    mov     dword ptr [rbp-24], eax
    cmp     dword ptr [rbp-32], 0                ; empty confirm -> neutral, not red
    je      sdu_enable
    mov     eax, 1                               ; mismatch -> red
    cmp     dword ptr [rbp-24], 0
    je      @F
    mov     eax, 4                               ; match -> deep green
@@:
    mov     dword ptr [g_cf_state], eax
sdu_enable:
    ; OK: policy satisfied AND (no confirm field, or the two agree).
    ; An unprotected .zip is a legitimate outcome, so an empty password is
    ; allowed when the output format is zip - matching the main dialog.
    mov     edx, dword ptr [rbp-16]
    test    edx, edx
    jnz     @F
    cmp     dword ptr [rbp-8], 0
    jne     @F
    cmp     dword ptr [g_make_zip], 0
    je      @F
    mov     edx, 1                               ; empty + .zip = unencrypted, allowed
@@:
    cmp     dword ptr [rbp-24], 0
    jne     @F
    xor     edx, edx
@@:
    WINCALL EnableWindow, qword ptr [g_sd_hok], edx
    ; repaint the fields across the empty<->non-empty boundary: the cue is drawn
    ; only while empty, and typing one character repaints only that character's
    ; box, leaving the rest of the word on screen
    cmp     dword ptr [rbp-8], 1
    ja      @F
    WINCALL InvalidateRect, qword ptr [g_sd_hpass], 0, 1
@@:
    cmp     qword ptr [g_sd_hconf], 0
    je      @F
    cmp     dword ptr [rbp-32], 1
    ja      @F
    WINCALL InvalidateRect, qword ptr [g_sd_hconf], 0, 1
@@:
    WINCALL InvalidateRect, qword ptr [g_sd_hunder], 0, 1
    cmp     qword ptr [g_sd_hcunder], 0
    je      @F
    WINCALL InvalidateRect, qword ptr [g_sd_hcunder], 0, 1
@@:
    ; the live copies were only needed to score: keep nothing resident between
    ; keystrokes, the same hygiene Vordr applies
    lea     rcx, [g_passw]
    mov     rdx, PWBUF_CHARS*2
    call    secure_zero
    lea     rcx, [g_confirmw]
    mov     rdx, PWBUF_CHARS*2
    call    secure_zero
    add     rsp, 80
    pop     rbp
    ret
sd_update endp

; =============================================================================
; sd_accept - OK pressed: pull both fields, compare, publish into g_passw.
; -> eax = 1 accept (close), 0 keep the prompt up (mismatch)
; =============================================================================
sd_accept proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    WINCALL GetWindowTextW, qword ptr [g_sd_hpass], addr g_passw, PWBUF_CHARS
    test    dword ptr [g_sd_flags], SDF_CONFIRM
    jz      sda_ok
    WINCALL GetWindowTextW, qword ptr [g_sd_hconf], addr g_confirmw, PWBUF_CHARS
    lea     rcx, [g_passw]
    lea     rdx, [g_confirmw]
    call    wstr_equal
    test    eax, eax
    jnz     sda_ok
    ; Mismatch: wipe both and stay put.  The wipe matters because this window
    ; can be retried any number of times and a stale confirm would otherwise sit
    ; in a locked buffer for the rest of the session.
    lea     rcx, [g_passw]
    mov     rdx, PWBUF_CHARS*2
    call    secure_zero
    lea     rcx, [g_confirmw]
    mov     rdx, PWBUF_CHARS*2
    call    secure_zero
    WINCALL SetWindowTextW, qword ptr [g_sd_hconf], addr s_empty
    WINCALL SetFocus, qword ptr [g_sd_hconf]
    lea     rcx, [s_sd_mismatch]
    lea     rdx, [t_sd_err]
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
    xor     eax, eax
    jmp     sda_ret
sda_ok:
    mov     eax, 1
sda_ret:
    add     rsp, 64
    pop     rbp
    ret
sd_accept endp

; =============================================================================
; sd_wndproc - the prompt's window procedure (raw, no prolog).
; Like mb_wndproc it must not PostQuitMessage: its pump is nested inside the
; caller's, and on the secure-desktop path inside a worker thread as well.
; =============================================================================
sd_wndproc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    mov     rax, rdx
    cmp     rax, WM_CREATE
    je      sdw_create
    cmp     rax, WM_DRAWITEM
    je      sdw_draw
    cmp     rax, WM_COMMAND
    je      sdw_cmd
    cmp     rax, WM_CTLCOLOREDIT
    je      sdw_ctledit
    cmp     rax, WM_CTLCOLORSTATIC
    je      sdw_ctledit
    cmp     rax, WM_CLOSE
    je      sdw_close
    cmp     rax, WM_DESTROY
    je      sdw_destroy
    jmp     sdw_def
sdw_create:
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [g_ctl_parent], rax
    call    make_secdesk_controls
    mov     qword ptr [g_ctl_parent], 0
    jmp     sdw_zero
sdw_draw:
    mov     rcx, qword ptr [rbp-32]
    mov     eax, dword ptr [rcx+DI_CTLID]
    cmp     eax, ID_SDBODY
    jne     @F
    call    draw_secdesk
    jmp     sdw_one
@@:
    cmp     eax, ID_SHOWPW
    jne     @F
    mov     rcx, qword ptr [rbp-32]
    call    draw_show_icon
    jmp     sdw_one
@@:
    cmp     eax, ID_SDFORMAT
    jne     sdw_notfmt
    mov     rcx, qword ptr [rbp-32]
    call    draw_sd_format
    jmp     sdw_one
sdw_notfmt:
    cmp     eax, ID_ACTION
    je      sdw_btn
    cmp     eax, ID_CANCEL
    jne     sdw_def
sdw_btn:
    mov     rcx, qword ptr [rbp-32]
    call    draw_button
sdw_one:
    mov     rax, 1
    jmp     sdw_ret
sdw_ctledit:
    ; the two underlines are statics: hand back the brush for their current state
    mov     rax, qword ptr [rbp-32]
    cmp     rax, qword ptr [g_sd_hunder]
    jne     @F
    mov     ecx, dword ptr [g_pw_state]
    call    underline_brush
    jmp     sdw_ret
@@:
    cmp     rax, qword ptr [g_sd_hcunder]
    jne     @F
    mov     ecx, dword ptr [g_cf_state]
    call    underline_brush
    jmp     sdw_ret
@@:
    WINCALL SetTextColor, qword ptr [rbp-24], CLR_WHITE
    WINCALL SetBkColor, qword ptr [rbp-24], CLR_DARK
    mov     rax, qword ptr [g_hbr_dark]
    jmp     sdw_ret
sdw_cmd:
    ; EN_CHANGE on either field -> regrade
    mov     eax, dword ptr [rbp-24]
    shr     eax, 16
    cmp     eax, EN_CHANGE
    jne     @F
    mov     eax, dword ptr [rbp-24]
    and     eax, 0FFFFh
    cmp     eax, ID_SDPASS
    je      sdw_regrade
    cmp     eax, ID_SDCONF
    jne     @F
sdw_regrade:
    call    sd_update
    jmp     sdw_zero
@@:
    mov     eax, dword ptr [rbp-24]
    and     eax, 0FFFFh
    cmp     eax, ID_SHOWPW
    jne     @F
    call    sd_toggle_show
    jmp     sdw_zero
@@:
    cmp     eax, ID_SDFORMAT
    jne     sdw_notfmtcmd
    call    sd_toggle_format
    jmp     sdw_zero
sdw_notfmtcmd:
    cmp     eax, ID_ACTION
    jne     @F
    call    sd_accept
    test    eax, eax
    jz      sdw_zero                     ; mismatch: prompt stays up
    mov     dword ptr [g_sd_result], SDR_OK
    jmp     sdw_end
@@:
    cmp     eax, ID_CANCEL
    jne     sdw_zero
    mov     dword ptr [g_sd_result], SDR_CANCEL
sdw_end:
    WINCALL DestroyWindow, qword ptr [g_sd_hwnd]
    jmp     sdw_zero
sdw_close:
    mov     dword ptr [g_sd_result], SDR_CANCEL
    WINCALL DestroyWindow, qword ptr [g_sd_hwnd]
sdw_zero:
    xor     rax, rax
    jmp     sdw_ret
sdw_destroy:
    mov     dword ptr [g_sd_done], 1
    xor     rax, rax
    jmp     sdw_ret
sdw_def:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
sdw_ret:
    add     rsp, 64
    pop     rbp
    ret
sd_wndproc endp

; =============================================================================
; sd_build_pump - register (once), create the window, run a modal loop.
; Runs on whichever thread and desktop the caller has arranged.
; =============================================================================
sd_build_pump proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 256
    ; height: pad + title + hint + gap + label + edit [+ gap + label + edit]
    ;         + gap + buttons + pad
    mov     eax, SD_PAD + SD_TITLE_H + SD_HINT_H + SD_GAP + 2 + SD_EDIT_H + 6
    mov     dword ptr [g_sd_fmty], 0
    test    dword ptr [g_sd_flags], SDF_CONFIRM
    jz      @F
    add     eax, SD_GAP + 2 + SD_EDIT_H + 6
    ; Encrypting: the format row goes here, between the fields and the buttons.
    ; Its y comes out of this same running total rather than being written out
    ; again in make_secdesk_controls - the two would drift apart, and the way
    ; that shows is the row landing under the OK button.
    add     eax, SD_GAP
    mov     dword ptr [g_sd_fmty], eax
    add     eax, SD_ROW_H
@@:
    add     eax, SD_GAP + SD_BTN_H + SD_PAD
    mov     dword ptr [g_sd_height], eax
    ; class (registered once per process; harmless if this runs on a second
    ; desktop, since a window class is per-process not per-desktop)
    cmp     dword ptr [g_sd_reg], 0
    jne     sdb_have
    lea     rcx, [g_wc]
    xor     r9, r9
sdb_zwc:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, WC_SIZE
    jb      sdb_zwc
    mov     dword ptr [g_wc+0], WC_SIZE
    mov     dword ptr [g_wc+4], CS_DROPSHADOW
    lea     rax, [sd_wndproc]
    mov     qword ptr [g_wc+8], rax
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [g_wc+24], rax
    WINCALL LoadCursorW, 0, IDC_ARROW
    mov     qword ptr [g_wc+40], rax
    mov     rax, qword ptr [g_hbr_dark]
    mov     qword ptr [g_wc+48], rax
    lea     rax, [wc_secdesk]
    mov     qword ptr [g_wc+64], rax
    WINCALL RegisterClassExW, addr g_wc
    mov     dword ptr [g_sd_reg], 1
sdb_have:
    WINCALL GetSystemMetrics, SM_CXSCREEN
    sub     eax, SD_W
    sar     eax, 1
    mov     dword ptr [rbp-72], eax
    WINCALL GetSystemMetrics, SM_CYSCREEN
    sub     eax, dword ptr [g_sd_height]
    sar     eax, 1
    mov     dword ptr [rbp-76], eax
    mov     dword ptr [g_sd_done], 0
    WINCALL CreateWindowExW, WS_EX_TOOLWINDOW, addr wc_secdesk, addr s_sd_title, ST_MAINWND, \
            dword ptr [rbp-72], dword ptr [rbp-76], SD_W, dword ptr [g_sd_height], \
            0, 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_sd_hwnd], rax
    test    rax, rax
    jz      sdb_done
    mov     r8d, SD_W
    inc     r8d
    mov     r9d, dword ptr [g_sd_height]
    inc     r9d
    WINCALL CreateRoundRectRgn, 0, 0, r8d, r9d, WIN_ROUND, WIN_ROUND
    WINCALL SetWindowRgn, qword ptr [g_sd_hwnd], rax, 1
    WINCALL ShowWindow, qword ptr [g_sd_hwnd], SW_SHOW
    WINCALL UpdateWindow, qword ptr [g_sd_hwnd]
    WINCALL SetForegroundWindow, qword ptr [g_sd_hwnd]
sdb_loop:
    WINCALL GetMessageW, addr rbp-160, 0, 0, 0
    test    eax, eax
    jle     sdb_done
    cmp     dword ptr [rbp-152], WM_KEYDOWN
    jne     sdb_disp
    cmp     qword ptr [rbp-144], VK_ESCAPE
    je      sdb_cancel
    ; Enter = OK, from either field: having just typed the password, reaching for
    ; the mouse (or tabbing past the eye) to commit it is a step with nothing in
    ; it.  Honoured only while OK is enabled, so Enter can never bypass the
    ; policy or the confirm match - a disabled OK swallows the key instead.
    cmp     qword ptr [rbp-144], VK_RETURN
    jne     sdb_disp
    WINCALL IsWindowEnabled, qword ptr [g_sd_hok]
    test    eax, eax
    jz      sdb_check
    WINCALL SendMessageW, qword ptr [g_sd_hwnd], WM_COMMAND, ID_ACTION, 0
    jmp     sdb_check
sdb_cancel:
    mov     dword ptr [g_sd_result], SDR_CANCEL
    WINCALL DestroyWindow, qword ptr [g_sd_hwnd]
    jmp     sdb_check
sdb_disp:
    WINCALL IsDialogMessageW, qword ptr [g_sd_hwnd], addr rbp-160
    test    eax, eax
    jnz     sdb_check
    WINCALL TranslateMessage, addr rbp-160
    WINCALL DispatchMessageW, addr rbp-160
sdb_check:
    cmp     dword ptr [g_sd_done], 0
    je      sdb_loop
sdb_done:
    mov     qword ptr [g_sd_hwnd], 0
    add     rsp, 256
    pop     rbp
    ret
sd_build_pump endp

; sd_thread - worker for the secure-desktop path.  SetThreadDesktop refuses a
; thread that already owns windows, so the prompt must be built here, not on the
; GUI thread.
sd_thread proc
    ; This thread runs FRAME_PROLOG'd code, so it needs its OWN shadow stack.
    ; Sharing one with the UI thread is the race that fastfailed the process.
    call    sstk_thread_init
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     rcx, qword ptr [g_sd_hdesk]
    call    secdesk_enter
    test    eax, eax
    jz      sdt_fail
    call    sd_build_pump
    call    secdesk_leave
    jmp     sdt_ret
sdt_fail:
    mov     dword ptr [g_sd_result], SDR_UNAVAILABLE
sdt_ret:
    call    sstk_thread_free                ; last: nothing framed may follow it
    xor     eax, eax
    add     rsp, 48
    pop     rbp
    ret
sd_thread endp

; =============================================================================
; secdesk_prompt(ecx = SDF_* flags) -> eax = SDR_OK / SDR_CANCEL / SDR_UNAVAILABLE
;
; On success the password is in g_passw (wide) - read_password converts it.
;
; FAILS CLOSED.  If SecureDesktop is on and the private desktop cannot be
; created, this returns SDR_UNAVAILABLE rather than quietly prompting on the
; interactive desktop: a silent fallback is the control switching itself off at
; exactly the moment something is interfering with it.  An administrator who
; needs the ordinary prompt sets SecureDesktop=0 deliberately.
; =============================================================================
public secdesk_prompt
secdesk_prompt proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     dword ptr [g_sd_flags], ecx
    mov     dword ptr [g_sd_result], SDR_CANCEL
    mov     dword ptr [g_sd_show], 0                 ; always start masked
    cmp     dword ptr [g_cfg_securedesk], 0
    je      sdp_here
ifdef DBG_TRACE
    cmp     dword ptr [g_dbg_nodesk], 0
    jne     sdp_here
endif
    jmp     sdp_secure
sdp_here:
    ; opted out: ordinary modal, this thread, this desktop
    call    sd_build_pump
    jmp     sdp_ret
sdp_secure:
    call    secdesk_open
    mov     qword ptr [g_sd_hdesk], rax
    test    rax, rax
    jnz     @F
    mov     dword ptr [g_sd_result], SDR_UNAVAILABLE
    jmp     sdp_ret
@@:
    WINCALL CreateThread, 0, 0, addr sd_thread, 0, 0, 0
    mov     qword ptr [rbp-8], rax
    test    rax, rax
    jnz     @F
    mov     dword ptr [g_sd_result], SDR_UNAVAILABLE
    jmp     sdp_close
@@:
    WINCALL WaitForSingleObject, qword ptr [rbp-8], INFINITE
    WINCALL CloseHandle, qword ptr [rbp-8]
sdp_close:
    mov     rcx, qword ptr [g_sd_hdesk]
    call    secdesk_close
    mov     qword ptr [g_sd_hdesk], 0
sdp_ret:
    mov     eax, dword ptr [g_sd_result]
    add     rsp, 96
    pop     rbp
    ret
secdesk_prompt endp

; =============================================================================
; draw_mbox(rcx = DRAWITEMSTRUCT*) - owner-draw body of the themed message box:
; a severity stripe down the left edge, the title in the heading font, and the
; wrapped body text below it.  Buttons are separate owner-draw controls.
; =============================================================================
draw_mbox proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     qword ptr [rbp-8], rcx
    call    dr_load                              ; -> g_dr_hdc, g_dr_l/t/r/b
    ; ---- background --------------------------------------------------------
    mov     eax, dword ptr [g_dr_l]
    mov     dword ptr [g_mb_rc+0], eax
    mov     eax, dword ptr [g_dr_t]
    mov     dword ptr [g_mb_rc+4], eax
    mov     eax, dword ptr [g_dr_r]
    mov     dword ptr [g_mb_rc+8], eax
    mov     eax, dword ptr [g_dr_b]
    mov     dword ptr [g_mb_rc+12], eax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_mb_rc, qword ptr [g_hbr_dark]
    ; ---- severity stripe ---------------------------------------------------
    ; MB_ICONERROR 0x10 red, MB_ICONWARNING 0x30 amber, anything else accent.
    mov     eax, dword ptr [g_mb_flags]
    and     eax, 0F0h
    mov     r10d, CLR_ACCENT
    cmp     eax, MB_ICONERROR
    jne     @F
    mov     r10d, CLR_INVALID
@@:
    cmp     eax, MB_ICONWARNING
    jne     @F
    mov     r10d, CLR_WARN
@@:
    mov     dword ptr [rbp-40], r10d
    mov     dword ptr [g_mb_rc+8], MB_BAR_W      ; left stripe: x from 0..MB_BAR_W
    WINCALL CreateSolidBrush, dword ptr [rbp-40]
    mov     qword ptr [rbp-48], rax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_mb_rc, qword ptr [rbp-48]
    WINCALL DeleteObject, qword ptr [rbp-48]
    ; ---- hairline edge -----------------------------------------------------
    ; After the stripe, so the two overlap at the left rather than the hairline
    ; being half-covered by it.  The stripe says what KIND of message this is;
    ; the hairline says where the card ends, and both are wanted.
    mov     eax, dword ptr [g_dr_r]
    mov     dword ptr [g_mb_rc+8], eax           ; put the width back
    mov     rcx, qword ptr [g_dr_hdc]
    lea     rdx, [g_mb_rc]
    mov     r8d, WIN_ROUND
    mov     r9d, dword ptr [rbp-40]              ; the severity colour, dimmed
    call    hairline_rect
    ; ---- title (heading font, severity colour) -----------------------------
    WINCALL SetBkMode, qword ptr [g_dr_hdc], 1
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_hfont_head]
    WINCALL SetTextColor, qword ptr [g_dr_hdc], dword ptr [rbp-40]
    mov     dword ptr [g_mb_rc+0], MB_PAD
    mov     dword ptr [g_mb_rc+4], MB_PAD
    mov     dword ptr [g_mb_rc+8], MB_W - MB_PAD
    mov     dword ptr [g_mb_rc+12], MB_PAD + MB_TITLE_H
    WINCALL DrawTextW, qword ptr [g_dr_hdc], qword ptr [g_mb_title], -1, addr g_mb_rc, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX or DT_END_ELLIPSIS>
    ; ---- body text (UI font, white, wrapped) -------------------------------
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_hfont]
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_WHITE
    mov     dword ptr [g_mb_rc+0], MB_PAD
    mov     eax, MB_PAD + MB_TITLE_H + MB_GAP
    mov     dword ptr [g_mb_rc+4], eax
    mov     dword ptr [g_mb_rc+8], MB_W - MB_PAD
    add     eax, dword ptr [g_mb_texth]
    mov     dword ptr [g_mb_rc+12], eax
    WINCALL DrawTextW, qword ptr [g_dr_hdc], qword ptr [g_mb_text], -1, addr g_mb_rc, \
            <DT_LEFT or DT_TOP or DT_WORDBREAK or DT_NOPREFIX or DT_EDITCONTROL>
    add     rsp, 96
    pop     rbp
    ret
draw_mbox endp

; =============================================================================
; mb_measure - wrap the body text at the box width and record its height in
; g_mb_texth, then derive the whole client height into g_mb_h.  DT_CALCRECT
; needs a real DC with the body font selected, or the wrap width is measured
; against the wrong metrics and every long message comes out the same height.
; =============================================================================
mb_measure proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    WINCALL GetDC, 0
    mov     qword ptr [rbp-8], rax
    WINCALL SelectObject, qword ptr [rbp-8], qword ptr [g_hfont]
    mov     qword ptr [rbp-16], rax              ; previous font
    mov     dword ptr [g_mb_rc+0], 0
    mov     dword ptr [g_mb_rc+4], 0
    mov     dword ptr [g_mb_rc+8], MB_W - MB_PAD - MB_PAD
    mov     dword ptr [g_mb_rc+12], 0
    WINCALL DrawTextW, qword ptr [rbp-8], qword ptr [g_mb_text], -1, addr g_mb_rc, \
            <DT_CALCRECT or DT_WORDBREAK or DT_NOPREFIX or DT_EDITCONTROL>
    WINCALL SelectObject, qword ptr [rbp-8], qword ptr [rbp-16]
    WINCALL ReleaseDC, 0, qword ptr [rbp-8]
    mov     eax, dword ptr [g_mb_rc+12]          ; measured height
    cmp     eax, MB_TEXT_MIN
    jae     @F
    mov     eax, MB_TEXT_MIN
@@:
    cmp     eax, MB_TEXT_MAX
    jbe     @F
    mov     eax, MB_TEXT_MAX
@@:
    mov     dword ptr [g_mb_texth], eax
    ; client height = pad + title + gap + text + gap + button row + pad
    add     eax, MB_PAD + MB_TITLE_H + MB_GAP + MB_GAP + MB_BTN_H + MB_PAD
    mov     dword ptr [g_mb_h], eax
    add     rsp, 96
    pop     rbp
    ret
mb_measure endp

; =============================================================================
; make_mbox_controls - the owner-draw body plus one or two buttons.  Buttons are
; right-aligned; OK is rightmost so it sits under the pointer where the eye ends.
; =============================================================================
make_mbox_controls proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    ; body static over the whole client area
    lea     rcx, [cls_static]
    lea     rdx, [s_mb_ok]                       ; text unused (owner-draw)
    mov     r8, ST_LOGO
    mov     r9, ID_MBBODY
    mov     dword ptr [rsp+32], 0
    mov     dword ptr [rsp+40], 0
    mov     dword ptr [rsp+48], MB_W
    mov     eax, dword ptr [g_mb_h]
    mov     dword ptr [rsp+56], eax
    call    create_ctl
    ; button row Y
    mov     eax, dword ptr [g_mb_h]
    sub     eax, MB_PAD + MB_BTN_H
    mov     dword ptr [rbp-8], eax
    ; OK (accent) at the right edge
    lea     rcx, [cls_button]
    lea     rdx, [s_mb_ok]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_ACTION
    mov     dword ptr [rsp+32], MB_W - MB_PAD - MB_BTN_W
    mov     eax, dword ptr [rbp-8]
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], MB_BTN_W
    mov     dword ptr [rsp+56], MB_BTN_H
    call    create_ctl
    mov     qword ptr [rbp-16], rax
    ; Cancel only for MB_OKCANCEL
    mov     eax, dword ptr [g_mb_flags]
    and     eax, 0Fh
    cmp     eax, MB_OKCANCEL
    jne     mmc_focus
    lea     rcx, [cls_button]
    lea     rdx, [s_mb_cancel]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_CANCEL
    mov     dword ptr [rsp+32], MB_W - MB_PAD - MB_BTN_W - MB_BTN_GAP - MB_BTN_W
    mov     eax, dword ptr [rbp-8]
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], MB_BTN_W
    mov     dword ptr [rsp+56], MB_BTN_H
    call    create_ctl
mmc_focus:
    WINCALL SetFocus, qword ptr [rbp-16]         ; OK takes focus: Enter confirms
    add     rsp, 96
    pop     rbp
    ret
make_mbox_controls endp

; =============================================================================
; mb_wndproc - message-box window procedure (raw, no prolog).
;
; Unlike about_wndproc this must NOT PostQuitMessage on destroy: it runs while
; the main window's message loop is alive, and a WM_QUIT would tear the whole
; GUI down instead of just this box.  The modal pump in mbox watches g_mb_done.
; =============================================================================
mb_wndproc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    mov     rax, rdx
    cmp     rax, WM_CREATE
    je      mbw_create
    cmp     rax, WM_DRAWITEM
    je      mbw_draw
    cmp     rax, WM_COMMAND
    je      mbw_cmd
    cmp     rax, WM_NCHITTEST
    je      mbw_hit
    cmp     rax, WM_NCLBUTTONDBLCLK
    je      mbw_zero
    cmp     rax, WM_CLOSE
    je      mbw_close
    cmp     rax, WM_DESTROY
    je      mbw_destroy
    jmp     mbw_def
mbw_create:
    ; create_ctl parents to g_hwnd unless told otherwise, and g_hwnd is the main
    ; window here - point it at this box for the duration, then clear it.
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [g_ctl_parent], rax
    call    make_mbox_controls
    mov     qword ptr [g_ctl_parent], 0
    jmp     mbw_zero
mbw_draw:
    mov     rcx, qword ptr [rbp-32]              ; DRAWITEMSTRUCT*
    mov     eax, dword ptr [rcx+DI_CTLID]
    cmp     eax, ID_MBBODY
    jne     @F
    call    draw_mbox
    jmp     mbw_one
@@:
    cmp     eax, ID_ACTION
    je      mbw_btn
    cmp     eax, ID_CANCEL
    jne     mbw_def
mbw_btn:
    mov     rcx, qword ptr [rbp-32]
    call    draw_button
mbw_one:
    mov     rax, 1
    jmp     mbw_ret
mbw_cmd:
    mov     eax, dword ptr [rbp-24]              ; LOWORD(wParam) = control id
    and     eax, 0FFFFh
    cmp     eax, ID_ACTION
    jne     @F
    mov     dword ptr [g_mb_result], IDOK
    jmp     mbw_end
@@:
    cmp     eax, ID_CANCEL
    jne     mbw_zero
    mov     dword ptr [g_mb_result], IDCANCEL
mbw_end:
    WINCALL DestroyWindow, qword ptr [g_mb_hwnd]
    jmp     mbw_zero
mbw_hit:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    cmp     rax, HTCLIENT
    jne     mbw_ret
    mov     rax, HTCAPTION                       ; drag the borderless body
    jmp     mbw_ret
mbw_close:
    mov     dword ptr [g_mb_result], IDCANCEL
    WINCALL DestroyWindow, qword ptr [g_mb_hwnd]
mbw_zero:
    xor     rax, rax
    jmp     mbw_ret
mbw_destroy:
    mov     dword ptr [g_mb_done], 1             ; NOT PostQuitMessage - see above
    xor     rax, rax
    jmp     mbw_ret
mbw_def:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
mbw_ret:
    add     rsp, 64
    pop     rbp
    ret
mb_wndproc endp

; =============================================================================
; pg_curfile - widen the entry ramlog last published into g_pg_txt.
; -> rax = g_pg_txt, and it is always a valid string: "Starting..." until the
;    first entry arrives, so the line never flickers empty.
;
; g_rl_curlen is written AFTER the bytes on the worker thread, so reading it
; first and clamping to it can only ever yield a SHORT name, never a name half
; overwritten by the next one.
; =============================================================================
pg_curfile proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     eax, dword ptr [g_rl_curlen]
    test    eax, eax
    jz      pgc_none
    cmp     eax, 599
    jbe     @F
    mov     eax, 599
@@:
    mov     dword ptr [rbp-8], eax
    WINCALL MultiByteToWideChar, CP_UTF8, 0, addr g_rl_curname, dword ptr [rbp-8], \
            addr g_pg_txt, 599
    test    eax, eax
    jz      pgc_none
    lea     rcx, [g_pg_txt]
    mov     word ptr [rcx+rax*2], 0
    mov     rax, rcx
    add     rsp, 64
    pop     rbp
    ret
pgc_none:
    ; "Deriving key..." is TRUE until the first byte and stale forever after: a
    ; bare single-file operation publishes no log entry until it completes, so
    ; this placeholder used to sit beside a live MB/s readout claiming the KDF
    ; was still running, seventeen seconds after it finished.  Once bytes flow,
    ; show the operation's own label instead - the same ASCII label the CLI bar
    ; carries, widened.
    cmp     qword ptr [g_prog_startms], 0
    je      pgc_kdf
    mov     r10, qword ptr [g_prog_label]
    test    r10, r10
    jz      pgc_kdf
    lea     rcx, [g_pg_txt]
    xor     r9d, r9d
pgc_widen:
    cmp     r9d, dword ptr [g_prog_lablen]
    jae     pgc_dots
    cmp     r9d, 32
    jae     pgc_dots
    movzx   eax, byte ptr [r10+r9]
    mov     word ptr [rcx+r9*2], ax
    inc     r9d
    jmp     pgc_widen
pgc_dots:
    mov     dword ptr [rcx+r9*2], 2E002Eh       ; ".."
    mov     dword ptr [rcx+r9*2+4], 02Eh        ; "." NUL
    lea     rax, [g_pg_txt]
    add     rsp, 64
    pop     rbp
    ret
pgc_kdf:
    lea     rcx, [g_pg_txt]
    lea     rdx, [s_pg_starting]
    WBOUND  r8, g_pg_txt, 600
    call    wcopy
    lea     rax, [g_pg_txt]
    add     rsp, 64
    pop     rbp
    ret
pg_curfile endp

; =============================================================================
; draw_progwin(rcx = DRAWITEMSTRUCT*) - the whole progress half, in one pass.
;
; Heading, the file being worked on, a bar, and a count.  All owner-drawn for the
; same reason the rest of this GUI is: a themed progress control would arrive
; with its own idea of what a dark window looks like.
; =============================================================================
draw_progwin proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    mov     qword ptr [rbp-8], rcx
    call    dr_load
    ; ---- the state colour, once --------------------------------------------
    ; Everything that carries the accent on this window - the left stripe, the
    ; edge, the heading, the bar - takes it from here, so the window says what
    ; state it is in with its colour and not only with its words.
    ;
    ; Three states, because three are all it can be SEEN in: it is working
    ; (accent), it stopped on an error (red), or it stopped because the user
    ; cancelled (amber, since that is not a failure - it is also not a success).
    ; There is deliberately no green: progwin_finish destroys the window the
    ; moment a job succeeds, so a success colour would be pixels nobody can look
    ; at.
    mov     r10d, CLR_ACCENT
    cmp     dword ptr [g_pg_done], 0
    je      pgd_col
    cmp     dword ptr [g_pg_fail], 0
    je      pgd_col                           ; finished cleanly, on its way out
    mov     r10d, CLR_INVALID
    cmp     dword ptr [g_cancelled], 0
    je      pgd_col
    mov     r10d, CLR_WARN
pgd_col:
    mov     dword ptr [rbp-40], r10d
    WINCALL CreateSolidBrush, dword ptr [rbp-40]
    mov     qword ptr [rbp-48], rax           ; stripe and bar share the one brush
    ; ---- backdrop ----------------------------------------------------------
    mov     eax, dword ptr [g_dr_l]
    mov     dword ptr [g_pg_rc+0], eax
    mov     eax, dword ptr [g_dr_t]
    mov     dword ptr [g_pg_rc+4], eax
    mov     eax, dword ptr [g_dr_r]
    mov     dword ptr [g_pg_rc+8], eax
    mov     eax, dword ptr [g_dr_b]
    mov     dword ptr [g_pg_rc+12], eax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_pg_rc, qword ptr [g_hbr_dark]
    ; ---- severity stripe down the left margin ------------------------------
    ; MB_BAR_W, the same 4px the message box and the log box use: this is the
    ; same piece of language, and a progress window that spoke it differently
    ; would just look like a different program.
    mov     eax, dword ptr [g_dr_l]
    add     eax, MB_BAR_W
    mov     dword ptr [g_pg_rc+8], eax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_pg_rc, qword ptr [rbp-48]
    mov     eax, dword ptr [g_dr_r]
    mov     dword ptr [g_pg_rc+8], eax        ; put the width back
    ; ---- edge --------------------------------------------------------------
    ; After the stripe, so the two overlap at the left rather than the hairline
    ; being half-covered by it - the same order as the message box.
    mov     rcx, qword ptr [g_dr_hdc]
    lea     rdx, [g_pg_rc]
    mov     r8d, WIN_ROUND
    mov     r9d, dword ptr [rbp-40]
    call    hairline_rect
    WINCALL SetBkMode, qword ptr [g_dr_hdc], BK_TRANSPARENT
    ; ---- heading -----------------------------------------------------------
    ; It says what is happening while it happens, and what happened once it has.
    lea     r10, [s_pg_enc]
    cmp     dword ptr [g_op], 0
    je      @F
    lea     r10, [s_pg_dec]
    cmp     dword ptr [g_is_zip], 0
    je      @F
    lea     r10, [s_pg_ext]
@@:
    cmp     dword ptr [g_pg_done], 0
    je      pgd_head
    cmp     dword ptr [g_pg_fail], 0
    je      pgd_head                          ; finished cleanly: heading stands
    lea     r10, [s_pg_failed]
    cmp     dword ptr [g_cancelled], 0
    je      pgd_head
    lea     r10, [s_pg_cancd]
pgd_head:
    ; The colour comes from the one computed above rather than being chosen
    ; again here - they are the same decision, and two copies of it drift.
    mov     qword ptr [rbp-16], r10
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_hfont_head]
    WINCALL SetTextColor, qword ptr [g_dr_hdc], dword ptr [rbp-40]
    mov     dword ptr [g_pg_rc+0], PG_PAD
    mov     dword ptr [g_pg_rc+4], PG_PAD
    mov     dword ptr [g_pg_rc+8], PG_W - PG_PAD
    mov     dword ptr [g_pg_rc+12], PG_PAD + 30
    WINCALL DrawTextW, qword ptr [g_dr_hdc], qword ptr [rbp-16], -1, addr g_pg_rc, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX>
    ; ---- where it is going -------------------------------------------------
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_hfont]
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_HINT
    mov     dword ptr [g_pg_rc+4], PG_PAD + 30
    mov     dword ptr [g_pg_rc+12], PG_PAD + 50
    WINCALL DrawTextW, qword ptr [g_dr_hdc], addr g_outpath_w, -1, addr g_pg_rc, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX or DT_PATH_ELLIPSIS>
    ; ---- the bar -----------------------------------------------------------
    mov     dword ptr [g_pg_rc+0], PG_PAD
    mov     dword ptr [g_pg_rc+4], PG_PAD + 62
    mov     dword ptr [g_pg_rc+8], PG_W - PG_PAD
    mov     dword ptr [g_pg_rc+12], PG_PAD + 62 + PG_BAR_H
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_pg_rc, qword ptr [g_hbr_track]
    mov     eax, dword ptr [g_prog_pct]
    cmp     eax, 100
    jbe     @F
    mov     eax, 100
@@:
    mov     r10d, PG_W - PG_PAD - PG_PAD
    imul    eax, r10d
    mov     r10d, 100
    xor     edx, edx
    div     r10d
    test    eax, eax
    jz      pgd_file
    add     eax, PG_PAD
    mov     dword ptr [g_pg_rc+8], eax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_pg_rc, qword ptr [rbp-48]
pgd_file:
    ; ---- the file being worked on ------------------------------------------
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_WHITE
    mov     dword ptr [g_pg_rc+0], PG_PAD
    mov     dword ptr [g_pg_rc+4], PG_PAD + 82
    mov     dword ptr [g_pg_rc+8], PG_W - PG_PAD
    mov     dword ptr [g_pg_rc+12], PG_PAD + 102
    call    pg_curfile
    mov     qword ptr [rbp-16], rax
    WINCALL DrawTextW, qword ptr [g_dr_hdc], qword ptr [rbp-16], -1, addr g_pg_rc, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX or DT_PATH_ELLIPSIS>
    ; ---- the count ---------------------------------------------------------
    ; Straight from the log's own tallies, so this number and the list behind
    ; Details are the same number.
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_HINT
    ; A bare single-file operation has no item entries, so "0 of 0 items" is
    ; noise sitting beside a live rate.  When the denominator is zero the count
    ; fragment is skipped and the line is rate/eta alone.
    mov     rax, qword ptr [g_scan_files]
    add     rax, qword ptr [g_scan_dirs]
    jnz     pgd_count
    lea     rcx, [g_pg_txt]
    mov     word ptr [rcx], 0
    call    status_append_rate
    jmp     pgd_countdone
pgd_count:
    lea     rcx, [g_pg_txt]
    mov     rax, qword ptr [g_rl_nadd]
    add     rax, qword ptr [g_rl_next]
    call    u64_to_wide
    mov     rcx, rax
    lea     rdx, [s_pg_of]
    WBOUND  r8, g_pg_txt, 600
    call    wcopy
    mov     rcx, rax
    ; Files AND folders, because the numerator above counts both - it is the
    ; log's tally, and the log gets a line per index ENTRY, a directory being an
    ; entry like any other.  Against a files-only denominator the numerator ran
    ; straight past it: "84000 of 76286 files" on a folder of 76,286 files and
    ; 7,792 directories.  Both ends now mean the same thing, and the word is
    ; "items" rather than "files" because 7,793 of them are not files.
    mov     rax, qword ptr [g_scan_files]
    add     rax, qword ptr [g_scan_dirs]
    call    u64_to_wide
    mov     rcx, rax
    lea     rdx, [s_pg_items]
    WBOUND  r8, g_pg_txt, 600
    call    wcopy
    ; and the rate/eta, same helper and therefore same numbers as the status bar
    mov     rcx, rax
    call    status_append_rate
pgd_countdone:
    mov     dword ptr [g_pg_rc+4], PG_PAD + 104
    mov     dword ptr [g_pg_rc+12], PG_PAD + 124
    WINCALL DrawTextW, qword ptr [g_dr_hdc], addr g_pg_txt, -1, addr g_pg_rc, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX>
    WINCALL DeleteObject, qword ptr [rbp-48]
    add     rsp, 128
    pop     rbp
    ret
draw_progwin endp

; =============================================================================
; make_progwin_controls - the backdrop, the two buttons, and nothing else.
; The details EDIT is created only when it is first needed (progwin_expand), so
; a job that succeeds never builds a control nobody saw.
; =============================================================================
make_progwin_controls proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    lea     rcx, [cls_static]
    lea     rdx, [s_ready]
    mov     r8, ST_PGBODY                        ; owner-draw, whole client
    mov     r9, ID_PG_BODY
    mov     dword ptr [rsp+32], 0
    mov     dword ptr [rsp+40], 0
    mov     dword ptr [rsp+48], PG_W
    ; Exactly the window's height, NOT the tallest state it can reach.  It used
    ; to be created at PG_H + PG_LOG_H so it would never need resizing, and that
    ; put its bottom edge 300px below the visible client: hairline_rect draws
    ; round the rect it is given, so the collapsed window's bottom line and both
    ; bottom corners were drawn off-screen and the frame hung open at the bottom.
    ; progwin_expand grows it with the window instead.
    mov     dword ptr [rsp+56], PG_H
    call    create_ctl
    mov     qword ptr [g_pg_body], rax
    ; Details toggle, bottom left
    lea     rcx, [cls_button]
    lea     rdx, [s_pg_details]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_PG_TOGGLE
    mov     dword ptr [rsp+32], PG_PAD
    mov     dword ptr [rsp+40], PG_H - PG_PAD - PG_BTN_H
    mov     dword ptr [rsp+48], PG_TOG_W
    mov     dword ptr [rsp+56], PG_BTN_H
    call    create_ctl
    ; Cancel / Close, bottom right.  ID_ACTION so draw_button gives it the accent.
    lea     rcx, [cls_button]
    lea     rdx, [s_pg_cancel]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_ACTION
    mov     dword ptr [rsp+32], PG_W - PG_PAD - PG_BTN_W
    mov     dword ptr [rsp+40], PG_H - PG_PAD - PG_BTN_H
    mov     dword ptr [rsp+48], PG_BTN_W
    mov     dword ptr [rsp+56], PG_BTN_H
    call    create_ctl
    mov     qword ptr [g_hcancel], rax           ; so enable/disable can find it
    ; The backdrop goes to the BOTTOM of the z-order, and this is not tidiness.
    ; EnumChildWindows lists this window's children with the backdrop FIRST -
    ; that is, on top of every control - so the moment it repaints it covers
    ; Details, Close, the log and its buttons, and WS_CLIPSIBLINGS cannot help
    ; because there is nothing above it to clip.  It went unnoticed while the
    ; repaint was aimed at the window instead of the backdrop, which meant the
    ; backdrop never repainted at all: the buttons survived, and the bar and the
    ; count sat frozen on their first frame for the whole job.
    ; HWND_BOTTOM = 1; 013h = SWP_NOSIZE|SWP_NOMOVE|SWP_NOACTIVATE.
    WINCALL SetWindowPos, qword ptr [g_pg_body], 1, 0, 0, 0, 0, 013h
    add     rsp, 96
    pop     rbp
    ret
make_progwin_controls endp

; =============================================================================
; progwin_expand - fold the details out, building them the first time.
;
; The log is flattened into the SAME g_lb_text the viewer dialog uses, so Copy
; and Save to file are the procs that already exist rather than second copies of
; them.  Called again after the job ends to refresh the text, which is the point
; on a failure: the errors are the last thing appended.
; =============================================================================
progwin_expand proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    cmp     qword ptr [g_pg_hwnd], 0
    je      pge_ret
    ; release any previous flatten before taking another
    mov     rcx, qword ptr [g_lb_text]
    test    rcx, rcx
    jz      @F
    mov     rdx, qword ptr [g_lb_bytes]
    call    mem_free
    mov     qword ptr [g_lb_text], 0
@@:
    call    lb_build_text
    mov     dword ptr [rbp-8], eax               ; 0 = nothing was recorded
    cmp     qword ptr [g_pg_edit], 0
    jne     pge_have
    ; first time: the EDIT and its two buttons
    mov     rax, qword ptr [g_pg_hwnd]
    mov     qword ptr [g_ctl_parent], rax
    lea     rcx, [cls_edit]
    lea     rdx, [s_ready]
    mov     r8, ST_LOGEDIT
    mov     r9, ID_PG_LOG
    mov     dword ptr [rsp+32], PG_PAD
    mov     dword ptr [rsp+40], PG_H
    mov     dword ptr [rsp+48], PG_W - PG_PAD - PG_PAD
    mov     dword ptr [rsp+56], PG_LOG_H - PG_PAD - PG_BTN_H - PG_PAD
    call    create_ctl
    mov     qword ptr [g_pg_edit], rax
    mov     rcx, rax
    call    dark_mode_window
    WINCALL SetWindowTheme, qword ptr [g_pg_edit], addr s_theme_dark, 0
    WINCALL SendMessageW, qword ptr [g_pg_edit], EM_LIMITTEXT, 0, 0
    lea     rcx, [cls_button]
    lea     rdx, [s_lb_save]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_PG_SAVE
    mov     dword ptr [rsp+32], PG_W - PG_PAD - LB_BTN_W
    mov     dword ptr [rsp+40], PG_H + PG_LOG_H - PG_PAD - PG_BTN_H
    mov     dword ptr [rsp+48], LB_BTN_W
    mov     dword ptr [rsp+56], PG_BTN_H
    call    create_ctl
    lea     rcx, [cls_button]
    lea     rdx, [s_lb_copy]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_PG_COPY
    mov     dword ptr [rsp+32], PG_W - PG_PAD - LB_BTN_W - LB_BTN_GAP - PG_BTN_W
    mov     dword ptr [rsp+40], PG_H + PG_LOG_H - PG_PAD - PG_BTN_H
    mov     dword ptr [rsp+48], PG_BTN_W
    mov     dword ptr [rsp+56], PG_BTN_H
    call    create_ctl
    mov     qword ptr [g_ctl_parent], 0
pge_have:
    ; The panel opens whether or not there is anything in it.  It used to give up
    ; before creating the control when the log came back empty, which meant a
    ; failure early enough to have logged nothing opened a details pane that was
    ; not there - and a null passed to SetWindowTextW leaves an EDIT showing the
    ; placeholder it was created with, so it read as "Ready" instead of "nothing
    ; happened".  Say which it is.
    cmp     dword ptr [rbp-8], 0
    je      pge_empty
    cmp     qword ptr [g_lb_text], 0
    je      pge_empty
    WINCALL SetWindowTextW, qword ptr [g_pg_edit], qword ptr [g_lb_text]
    jmp     pge_sel
pge_empty:
    WINCALL SetWindowTextW, qword ptr [g_pg_edit], addr s_pg_nolog
pge_sel:
    ; scroll to the end - on a failure the reason is the LAST thing written
    WINCALL SendMessageW, qword ptr [g_pg_edit], EM_SETSEL, -1, -1
    WINCALL SendMessageW, qword ptr [g_pg_edit], EM_SCROLLCARET, 0, 0
    cmp     dword ptr [g_pg_open], 0
    jne     pge_ret                              ; already out: text refreshed only
    mov     dword ptr [g_pg_open], 1
    WINCALL SetWindowPos, qword ptr [g_pg_hwnd], 0, 0, 0, PG_W, PG_H + PG_LOG_H, 016h
    ; The backdrop grows with it, or the edge it draws stops where the window
    ; used to end and the log sits outside the frame.
    ; HWND_BOTTOM again, not SWP_NOZORDER: the controls built above were created
    ; after the backdrop and land BELOW it, so the z-order has to be restated
    ; every time this runs, not only once at creation.
    WINCALL SetWindowPos, qword ptr [g_pg_body], 1, 0, 0, PG_W, PG_H + PG_LOG_H, 012h
    ; RDW_ALLCHILDREN, for the same reason the main window's resize uses it: the
    ; backdrop's repaint covers Details and Close, and nothing invalidates them
    ; afterwards, so they stay covered. Invalidating the children explicitly is
    ; the fix; painting over them and hoping is not.
    WINCALL RedrawWindow, qword ptr [g_pg_hwnd], 0, 0, 0185h
pge_ret:
    add     rsp, 96
    pop     rbp
    ret
progwin_expand endp

; =============================================================================
; progwin_finish - the worker is done, and in right-drag mode this owns what
; happens next.  Called from on_done INSTEAD of everything it would normally do.
;
; Success closes the lot: the gesture asked for a thing to happen, it happened,
; and there is nothing left to look at.  A failure stops here with the details
; already open - that is the one moment the log is the point.
; =============================================================================
progwin_finish proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     dword ptr [g_pg_done], 1
    ; The secret dies here either way.  od_restore normally does this and is not
    ; reached on this path, and a window left open on an error must not be
    ; sitting on the password that made it.
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
    lea     rcx, [g_cfg_pass]
    xor     r9, r9
pgf_wipe:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, MAX_PASSWORD_BYTES+1
    jb      pgf_wipe
    lea     rcx, [g_passw]
    mov     rdx, PWBUF_CHARS
    call    wzero
    ; Cancelled is not a failure - the user asked for it - but it is not a
    ; success either, so it stops here rather than closing as if it worked.
    mov     eax, dword ptr [g_op_result]
    test    eax, eax
    jnz     pgf_stop
    cmp     dword ptr [g_cancelled], 0
    jne     pgf_stop
    ; ---- it worked: take everything down -----------------------------------
    mov     dword ptr [g_prog_pct], 100
    WINCALL DestroyWindow, qword ptr [g_pg_hwnd]
    mov     qword ptr [g_pg_hwnd], 0
    WINCALL PostQuitMessage, 0
    add     rsp, 64
    pop     rbp
    ret
pgf_stop:
    mov     dword ptr [g_pg_fail], 1
    ; the button stops being Cancel the moment there is nothing left to cancel
    WINCALL SetWindowTextW, qword ptr [g_hcancel], addr s_close
    call    progwin_expand
    ; Not conditional on the expand having done it: progwin_expand returns early
    ; when the panel was already open, and this is the paint that turns the whole
    ; surface red - including the button that has just become Close.
    WINCALL RedrawWindow, qword ptr [g_pg_hwnd], 0, 0, 0185h
    WINCALL SetForegroundWindow, qword ptr [g_pg_hwnd]
    add     rsp, 64
    pop     rbp
    ret
progwin_finish endp

; =============================================================================
; pg_wndproc - the progress window (raw, no prolog).
;
; It POSTS WM_QUIT on destroy, unlike the message box: in right-drag mode this
; window IS the process's only visible one, so closing it ends the run.
; =============================================================================
pg_wndproc proc
    push    rbp
    mov     rbp, rsp
    ; 96, not the 64 the other window procs use: this one resizes itself, and
    ; SetWindowPos takes SEVEN arguments - at 64 its spill (rsp+32..rsp+55) lands
    ; exactly on the saved hwnd/msg/wParam/lParam.  It would have "worked",
    ; because the paths that resize return without reading them again; framecheck
    ; called it and it is right to.  A frame that depends on nobody looking at a
    ; local after it has been overwritten is one edit from being wrong.
    sub     rsp, 96
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    mov     rax, rdx
    cmp     rax, WM_CREATE
    je      pgw_create
    cmp     rax, WM_DRAWITEM
    je      pgw_draw
    cmp     rax, WM_COMMAND
    je      pgw_cmd
    cmp     rax, WM_CTLCOLOREDIT
    je      pgw_ctl
    cmp     rax, WM_CTLCOLORSTATIC
    je      pgw_ctl
    cmp     rax, WM_TIMER
    je      pgw_timer
    cmp     rax, WM_NCHITTEST
    je      pgw_hit
    cmp     rax, WM_NCLBUTTONDBLCLK
    je      pgw_zero
    cmp     rax, WM_CLOSE
    je      pgw_close
    cmp     rax, WM_DESTROY
    je      pgw_destroy
    jmp     pgw_def
pgw_create:
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [g_ctl_parent], rax
    call    make_progwin_controls
    mov     qword ptr [g_ctl_parent], 0
    ; its own timer, not the main window's: that one only ticks while g_running,
    ; and this window has a first frame to paint before the worker starts
    WINCALL SetTimer, qword ptr [rbp-8], 4, 100, 0
    jmp     pgw_zero
pgw_timer:
    cmp     dword ptr [g_pg_done], 0
    jne     pgw_zero                             ; frozen on the final state
    ; The BODY, not the window.  Everything on this surface is drawn by the
    ; owner-draw backdrop, and invalidating its parent does not invalidate it -
    ; a child repaints when its OWN region is dirty. Aimed at the window, the
    ; heading, the bar and the count never changed after their first paint: on a
    ; failure the window went on saying "Encrypting" in accent blue while the
    ; region uncovered by the expand - the only part painted fresh - came out
    ; red. Half a window in one state and half in the other, which is how this
    ; was spotted.
    WINCALL InvalidateRect, qword ptr [g_pg_body], 0, 0
    jmp     pgw_zero
pgw_ctl:
    WINCALL SetTextColor, qword ptr [rbp-24], CLR_WHITE
    WINCALL SetBkColor, qword ptr [rbp-24], CLR_DARK
    mov     rax, qword ptr [g_hbr_dark]
    jmp     pgw_ret
pgw_draw:
    mov     rcx, qword ptr [rbp-32]
    mov     eax, dword ptr [rcx+DI_CTLID]
    cmp     eax, ID_PG_BODY
    jne     @F
    call    draw_progwin
    jmp     pgw_one
@@:
    cmp     eax, ID_ACTION
    je      pgw_btn
    cmp     eax, ID_PG_TOGGLE
    je      pgw_btn
    cmp     eax, ID_PG_COPY
    je      pgw_btn
    cmp     eax, ID_PG_SAVE
    jne     pgw_def
pgw_btn:
    mov     rcx, qword ptr [rbp-32]
    call    draw_button
pgw_one:
    mov     rax, 1
    jmp     pgw_ret
pgw_cmd:
    mov     eax, dword ptr [rbp-24]
    and     eax, 0FFFFh
    cmp     eax, ID_PG_TOGGLE
    jne     @F
    cmp     dword ptr [g_pg_open], 0
    jne     pgw_collapse
    call    progwin_expand
    jmp     pgw_zero
pgw_collapse:
    mov     dword ptr [g_pg_open], 0
    WINCALL SetWindowPos, qword ptr [g_pg_hwnd], 0, 0, 0, PG_W, PG_H, 016h
    WINCALL SetWindowPos, qword ptr [g_pg_body], 1, 0, 0, PG_W, PG_H, 012h
    WINCALL RedrawWindow, qword ptr [g_pg_hwnd], 0, 0, 0185h
    jmp     pgw_zero
@@:
    cmp     eax, ID_PG_COPY
    jne     @F
    call    lb_copy
    jmp     pgw_zero
@@:
    cmp     eax, ID_PG_SAVE
    jne     @F
    call    lb_save
    jmp     pgw_zero
@@:
    cmp     eax, ID_ACTION
    je      pgw_close
    cmp     eax, IDCANCEL
    jne     pgw_zero
pgw_close:
    ; While it is still running this means CANCEL: stop the worker and let the
    ; normal completion path arrive here again with g_cancelled set, so the
    ; rollback runs rather than the window vanishing mid-write.
    cmp     dword ptr [g_pg_done], 0
    jne     pgw_reallyclose
    cmp     dword ptr [g_running], 0
    je      pgw_reallyclose
    mov     dword ptr [g_cancelled], 1
    call    progress_abort
    jmp     pgw_zero
pgw_reallyclose:
    WINCALL DestroyWindow, qword ptr [g_pg_hwnd]
    jmp     pgw_zero
pgw_hit:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    cmp     rax, HTCLIENT
    jne     pgw_ret
    mov     rax, HTCAPTION                       ; drag the borderless body
    jmp     pgw_ret
pgw_zero:
    xor     rax, rax
    jmp     pgw_ret
pgw_destroy:
    mov     qword ptr [g_pg_hwnd], 0
    WINCALL PostQuitMessage, 0                   ; this window IS the run
    xor     rax, rax
    jmp     pgw_ret
pgw_def:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
pgw_ret:
    add     rsp, 96                              ; MUST match the sub above
    pop     rbp
    ret
pg_wndproc endp

; =============================================================================
; progwin_show -> eax = 1 if the window is up.  Registers the class on first use
; and centres on the screen (there is no parent window to centre over - the main
; one exists but is deliberately never shown on this path).
; =============================================================================
progwin_show proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    cmp     dword ptr [g_pg_reg], 0
    jne     pgs_haveclass
    lea     rcx, [g_wc]
    xor     r9, r9
pgs_zwc:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, WC_SIZE
    jb      pgs_zwc
    mov     dword ptr [g_wc+0], WC_SIZE
    mov     dword ptr [g_wc+4], CS_DROPSHADOW
    lea     rax, [pg_wndproc]
    mov     qword ptr [g_wc+8], rax
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [g_wc+24], rax
    WINCALL LoadIconW, qword ptr [g_hinst], 1
    mov     qword ptr [g_wc+32], rax
    mov     qword ptr [g_wc+72], rax
    WINCALL LoadCursorW, 0, IDC_ARROW
    mov     qword ptr [g_wc+40], rax
    mov     rax, qword ptr [g_hbr_dark]
    mov     qword ptr [g_wc+48], rax
    lea     rax, [wc_progwin]
    mov     qword ptr [g_wc+64], rax
    WINCALL RegisterClassExW, addr g_wc
    mov     dword ptr [g_pg_reg], 1
pgs_haveclass:
    WINCALL GetSystemMetrics, SM_CXSCREEN
    sub     eax, PG_W
    sar     eax, 1
    mov     dword ptr [rbp-8], eax
    WINCALL GetSystemMetrics, SM_CYSCREEN
    sub     eax, PG_H
    sar     eax, 1
    mov     dword ptr [rbp-12], eax
    WINCALL CreateWindowExW, WS_EX_TOOLWINDOW, addr wc_progwin, addr s_pg_enc, \
            ST_MAINWND, dword ptr [rbp-8], dword ptr [rbp-12], PG_W, PG_H, \
            0, 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_pg_hwnd], rax
    test    rax, rax
    jz      pgs_no
    WINCALL CreateRoundRectRgn, 0, 0, PG_W+1, PG_H + PG_LOG_H + 1, WIN_ROUND, WIN_ROUND
    WINCALL SetWindowRgn, qword ptr [g_pg_hwnd], rax, 1
    WINCALL ShowWindow, qword ptr [g_pg_hwnd], SW_SHOW
    WINCALL UpdateWindow, qword ptr [g_pg_hwnd]
    mov     eax, 1
    add     rsp, 128
    pop     rbp
    ret
pgs_no:
    xor     eax, eax
    add     rsp, 128
    pop     rbp
    ret
progwin_show endp

; =============================================================================
; draw_logbox(rcx = DRAWITEMSTRUCT*) - the viewer's backdrop and title.
; The text itself is a real EDIT sitting on top of this; all this paints is the
; dark panel, the accent stripe and the heading, so the window matches the
; message box it is a bigger cousin of.
; =============================================================================
draw_logbox proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     qword ptr [rbp-8], rcx
    call    dr_load                              ; -> g_dr_hdc, g_dr_l/t/r/b
    mov     eax, dword ptr [g_dr_l]
    mov     dword ptr [g_lb_rc+0], eax
    mov     eax, dword ptr [g_dr_t]
    mov     dword ptr [g_lb_rc+4], eax
    mov     eax, dword ptr [g_dr_r]
    mov     dword ptr [g_lb_rc+8], eax
    mov     eax, dword ptr [g_dr_b]
    mov     dword ptr [g_lb_rc+12], eax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_lb_rc, qword ptr [g_hbr_dark]
    ; hairline accent edge, as on every other panel
    mov     rcx, qword ptr [g_dr_hdc]
    lea     rdx, [g_lb_rc]
    mov     r8d, WIN_ROUND
    mov     r9d, CLR_ACCENT
    call    hairline_rect
    ; accent stripe down the left, same language as the message box severity bar
    mov     dword ptr [g_lb_rc+0], 0
    mov     dword ptr [g_lb_rc+4], 0
    mov     dword ptr [g_lb_rc+8], MB_BAR_W
    mov     dword ptr [g_lb_rc+12], LB_H
    WINCALL CreateSolidBrush, CLR_ACCENT
    mov     qword ptr [rbp-24], rax
    WINCALL FillRect, qword ptr [g_dr_hdc], addr g_lb_rc, qword ptr [rbp-24]
    WINCALL DeleteObject, qword ptr [rbp-24]
    ; title
    WINCALL SetBkMode, qword ptr [g_dr_hdc], 1
    WINCALL SelectObject, qword ptr [g_dr_hdc], qword ptr [g_hfont_head]
    WINCALL SetTextColor, qword ptr [g_dr_hdc], CLR_ACCENT
    mov     dword ptr [g_lb_rc+0], LB_PAD
    mov     dword ptr [g_lb_rc+4], LB_PAD
    mov     dword ptr [g_lb_rc+8], LB_W - LB_PAD
    mov     dword ptr [g_lb_rc+12], LB_PAD + LB_TITLE_H
    WINCALL DrawTextW, qword ptr [g_dr_hdc], addr t_log, -1, addr g_lb_rc, \
            <DT_LEFT or DT_VCENTER or DT_SINGLELINE or DT_NOPREFIX>
    add     rsp, 96
    pop     rbp
    ret
draw_logbox endp

; =============================================================================
; make_logbox_controls - backdrop, the text control, and the three buttons.
; =============================================================================
make_logbox_controls proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    ; backdrop over the whole client area
    lea     rcx, [cls_static]
    lea     rdx, [s_mb_ok]                       ; text unused (owner-draw)
    mov     r8, ST_LOGO
    mov     r9, ID_LOGBODY
    mov     dword ptr [rsp+32], 0
    mov     dword ptr [rsp+40], 0
    mov     dword ptr [rsp+48], LB_W
    mov     dword ptr [rsp+56], LB_H
    call    create_ctl
    ; the log text
    lea     rcx, [cls_edit]
    lea     rdx, [s_ready]
    mov     r8, ST_LOGEDIT
    mov     r9, ID_LOGTEXT
    mov     dword ptr [rsp+32], LB_PAD
    mov     dword ptr [rsp+40], LB_PAD + LB_TITLE_H + LB_GAP
    mov     dword ptr [rsp+48], LB_W - LB_PAD - LB_PAD
    mov     dword ptr [rsp+56], LB_H - LB_PAD - LB_TITLE_H - LB_GAP - LB_GAP - LB_BTN_H - LB_PAD
    call    create_ctl
    mov     qword ptr [g_lb_edit], rax
    ; dark scrollbar: the window opt-in first, then the theme name (see the
    ; listview's copy of this pair for why one without the other does nothing)
    mov     rcx, qword ptr [g_lb_edit]
    call    dark_mode_window
    WINCALL SetWindowTheme, qword ptr [g_lb_edit], addr s_theme_dark, 0
    ; EM_LIMITTEXT 0 - the control's default cap is far below what a big job
    ; produces, and a silently truncated log is the one thing this must not do.
    WINCALL SendMessageW, qword ptr [g_lb_edit], EM_LIMITTEXT, 0, 0
    WINCALL SetWindowTextW, qword ptr [g_lb_edit], qword ptr [g_lb_text]
    ; button row
    mov     eax, LB_H - LB_PAD - LB_BTN_H
    mov     dword ptr [rbp-8], eax
    ; Close (accent) at the right edge
    lea     rcx, [cls_button]
    lea     rdx, [s_close]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_ACTION
    mov     dword ptr [rsp+32], LB_W - LB_PAD - LB_BTN_W
    mov     eax, dword ptr [rbp-8]
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], LB_BTN_W
    mov     dword ptr [rsp+56], LB_BTN_H
    call    create_ctl
    mov     qword ptr [rbp-16], rax
    ; Save to file...
    lea     rcx, [cls_button]
    lea     rdx, [s_lb_save]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_LOGSAVE
    mov     dword ptr [rsp+32], LB_W - LB_PAD - LB_BTN_W*2 - LB_BTN_GAP
    mov     eax, dword ptr [rbp-8]
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], LB_BTN_W
    mov     dword ptr [rsp+56], LB_BTN_H
    call    create_ctl
    ; Copy
    lea     rcx, [cls_button]
    lea     rdx, [s_lb_copy]
    mov     r8, ST_OWNERBTN
    mov     r9, ID_LOGCOPY
    mov     dword ptr [rsp+32], LB_W - LB_PAD - LB_BTN_W*3 - LB_BTN_GAP*2
    mov     eax, dword ptr [rbp-8]
    mov     dword ptr [rsp+40], eax
    mov     dword ptr [rsp+48], LB_BTN_W
    mov     dword ptr [rsp+56], LB_BTN_H
    call    create_ctl
    WINCALL SetFocus, qword ptr [rbp-16]         ; Close takes focus: Enter closes
    add     rsp, 96
    pop     rbp
    ret
make_logbox_controls endp

; =============================================================================
; lb_copy - put the log on the clipboard as CF_UNICODETEXT.
;
; The clipboard takes OWNERSHIP of the moveable block on success, so it is not
; freed here; on any failure along the way it is, or the block leaks for the
; life of the process holding the user's file paths.
; =============================================================================
lb_copy proc frame
    FRAME_PROLOG 64
    ; [rbp-16] = hglobal   [rbp-24] = locked ptr   [rbp-32] = byte count
    ; The TEXT length, not the allocation: the buffer keeps room for a note that
    ; may not have been written, and pasting a tail of NULs into a mail is the
    ; kind of thing nobody reports and everybody notices.
    mov     rax, qword ptr [g_lb_chars]
    shl     rax, 1
    mov     qword ptr [rbp-32], rax
    WINCALL OpenClipboard, qword ptr [g_lb_hwnd]
    test    eax, eax
    jz      lc_fail
    WINCALL GlobalAlloc, GMEM_MOVEABLE, qword ptr [rbp-32]
    test    rax, rax
    jz      lc_close
    mov     qword ptr [rbp-16], rax
    WINCALL GlobalLock, qword ptr [rbp-16]
    test    rax, rax
    jz      lc_free
    mov     qword ptr [rbp-24], rax
    ; plain byte copy, bounded by the size the block was asked for
    mov     rcx, qword ptr [g_lb_text]
    mov     rdx, qword ptr [rbp-24]
    xor     r9, r9
lc_cpy:
    mov     al, byte ptr [rcx+r9]
    mov     byte ptr [rdx+r9], al
    inc     r9
    cmp     r9, qword ptr [rbp-32]
    jb      lc_cpy
    WINCALL GlobalUnlock, qword ptr [rbp-16]
    WINCALL EmptyClipboard
    WINCALL SetClipboardData, CF_UNICODETEXT, qword ptr [rbp-16]
    test    rax, rax
    jz      lc_free                              ; refused: the block is still ours
    WINCALL CloseClipboard
    FRAME_EPILOG
    ret
lc_free:
    ; GlobalFree is not imported and this is the one path that would need it;
    ; leaving the block to the process teardown is the lesser of the two, and
    ; SetClipboardData refusing is not something a user can provoke.
    WINCALL CloseClipboard
    jmp     lc_say
lc_close:
    WINCALL CloseClipboard
lc_fail:
lc_say:
    lea     rcx, [m_log_copyfail]
    lea     rdx, [t_log_err]
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
    FRAME_EPILOG
    ret
lb_copy endp

; =============================================================================
; lb_save - ask where, then write the log as UTF-8.
;
; UTF-8 and not the UTF-16 held in memory: the file is meant to be pasted into a
; mail or an issue, and every tool that will open it reads UTF-8.  It is
; re-encoded here rather than a second copy being kept alive next to the first.
; =============================================================================
lb_save proc frame
    ; 128: WideCharToMultiByte takes EIGHT arguments, so its outgoing area runs
    ; to rsp+63 (= rbp-81) and every local has to sit above that.  At 96 the
    ; deepest local was rbp-48 and the area started at rbp-49 - one byte of
    ; clearance, and no room for the second size the fix below needs.
    FRAME_PROLOG 128
    ; [rbp-16]=utf8 buf  [rbp-24]=bytes to write  [rbp-32]=handle
    ; [rbp-40]=written  [rbp-48]=WriteFile result  [rbp-56]=alloc size (with NUL)
    lea     rcx, [g_lb_path]
    lea     rdx, [s_logname]
    WBOUND  r8, g_lb_path, MAX_PATH_CHARS
    call    wcopy
    ; zero the struct: every field this does not set must read as absent
    lea     r10, [g_ofn]
    xor     r9, r9
ls_zero:
    mov     byte ptr [r10+r9], 0
    inc     r9
    cmp     r9, 152
    jb      ls_zero
    mov     dword ptr [r10+OFN_lStructSize], 152
    mov     rax, qword ptr [g_lb_hwnd]
    mov     qword ptr [r10+OFN_hwndOwner], rax
    lea     rax, [g_lb_path]
    mov     qword ptr [r10+OFN_lpstrFile], rax
    mov     dword ptr [r10+OFN_nMaxFile], MAX_PATH_CHARS
    lea     rax, [t_log_save]
    mov     qword ptr [r10+OFN_lpstrTitle], rax
    lea     rax, [s_defext_txt]
    mov     qword ptr [r10+OFN_lpstrDefExt], rax
    mov     dword ptr [r10+OFN_Flags], OFN_OVERWRITEPROMPT or OFN_PATHMUSTEXIST or OFN_NOCHANGEDIR or OFN_EXPLORER
    WINCALL GetSaveFileNameW, addr g_ofn
    test    eax, eax
    jz      ls_ret                               ; cancelled is an answer
    ; ---- widen back down to UTF-8 ------------------------------------------
    ; TWO sizes, and conflating them is why this used to fail EVERY time.  With
    ; a source length of -1 the API measures and writes a NUL-TERMINATED string,
    ; so the count it returns includes the terminator and the buffer it is given
    ; has to have room for it.  Decrementing first and passing that as the
    ; capacity asked it to write a NUL it had nowhere to put: it wrote nothing,
    ; returned 0, and the window said the location could not be written to - which
    ; sent everyone looking at the folder they had picked.
    ;
    ; So: allocate and convert with the terminator, and write the file without it.
    WINCALL WideCharToMultiByte, CP_UTF8, 0, qword ptr [g_lb_text], -1, 0, 0, 0, 0
    test    eax, eax
    jz      ls_fail
    mov     dword ptr [rbp-56], eax              ; bytes INCLUDING the NUL
    dec     eax
    jz      ls_ret                               ; empty: nothing worth a file
    mov     dword ptr [rbp-24], eax              ; bytes to WRITE
    mov     ecx, dword ptr [rbp-56]
    call    mem_alloc
    test    rax, rax
    jz      ls_fail
    mov     qword ptr [rbp-16], rax
    WINCALL WideCharToMultiByte, CP_UTF8, 0, qword ptr [g_lb_text], -1, \
            qword ptr [rbp-16], dword ptr [rbp-56], 0, 0
    test    eax, eax
    jz      ls_freefail
    WINCALL CreateFileW, addr g_lb_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      ls_freefail
    mov     qword ptr [rbp-32], rax
    WINCALL WriteFile, qword ptr [rbp-32], qword ptr [rbp-16], dword ptr [rbp-24], addr rbp-40, 0
    mov     dword ptr [rbp-48], eax
    WINCALL CloseHandle, qword ptr [rbp-32]
    mov     rcx, qword ptr [rbp-16]
    mov     edx, dword ptr [rbp-56]              ; the ALLOCATION, so the wipe covers it all
    call    mem_free                             ; wipes: it held the paths too
    cmp     dword ptr [rbp-48], 0
    je      ls_fail
ls_ret:
    FRAME_EPILOG
    ret
ls_freefail:
    mov     rcx, qword ptr [rbp-16]
    mov     edx, dword ptr [rbp-56]
    call    mem_free
ls_fail:
    lea     rcx, [m_log_savefail]
    lea     rdx, [t_log_err]
    mov     r8d, MB_OK or MB_ICONWARNING
    call    mbox
    FRAME_EPILOG
    ret
lb_save endp

; =============================================================================
; lb_build_text -> eax = 1 there is something to show, 0 there is not.
;
; Takes the UTF-8 log, widens it into one NUL-terminated block for the EDIT, and
; releases the UTF-8 copy immediately - both buffers hold the user's file paths,
; so only one of them is alive at a time and mem_free wipes on the way out.
; =============================================================================
lb_build_text proc frame
    FRAME_PROLOG 96
    ; [rbp-16]=utf8 ptr [rbp-24]=utf8 len [rbp-32]=state [rbp-40]=wchars
    ; [rbp-48]=alloc bytes
    lea     rcx, [rbp-16]
    lea     rdx, [rbp-24]
    call    rlog_flatten
    mov     dword ptr [rbp-32], eax
    test    eax, eax
    jz      lbt_none
    ; how many UTF-16 units does it need?
    WINCALL MultiByteToWideChar, CP_UTF8, 0, qword ptr [rbp-16], dword ptr [rbp-24], 0, 0
    test    eax, eax
    jz      lbt_free
    mov     dword ptr [rbp-40], eax
    ; room for the text, the truncation note if it is needed, and the NUL
    mov     eax, dword ptr [rbp-40]
    add     eax, s_lb_trunc_chars + 1
    shl     eax, 1
    mov     dword ptr [rbp-48], eax
    mov     ecx, eax
    call    mem_alloc
    test    rax, rax
    jz      lbt_free
    mov     qword ptr [g_lb_text], rax
    mov     ecx, dword ptr [rbp-48]
    mov     qword ptr [g_lb_bytes], rcx
    WINCALL MultiByteToWideChar, CP_UTF8, 0, qword ptr [rbp-16], dword ptr [rbp-24], \
            qword ptr [g_lb_text], dword ptr [rbp-40]
    ; NUL-terminate: the count-limited form does not
    mov     rcx, qword ptr [g_lb_text]
    mov     eax, dword ptr [rbp-40]
    mov     word ptr [rcx+rax*2], 0
    inc     eax
    mov     ecx, eax
    mov     qword ptr [g_lb_chars], rcx          ; wide chars INCLUDING the NUL
    ; the UTF-8 copy has served its purpose
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    call    mem_free
    ; say so if it is incomplete
    cmp     dword ptr [rbp-32], 2
    jne     lbt_ok
    mov     rcx, qword ptr [g_lb_text]
    mov     eax, dword ptr [rbp-40]
    lea     rcx, [rcx+rax*2]                     ; dst: over the NUL just written
    lea     r8, [rcx + s_lb_trunc_chars*2]       ; last writable wide char
    lea     rdx, [s_lb_trunc]
    call    wcopy
    mov     rcx, qword ptr [g_lb_chars]
    add     rcx, s_lb_trunc_chars
    mov     qword ptr [g_lb_chars], rcx
lbt_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
lbt_free:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    call    mem_free
lbt_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
lb_build_text endp

; =============================================================================
; show_logbox - the statistics line was clicked.  Show what happened.
;
; Modal over the main window, on the same terms as mbox: its own pump, no
; WM_QUIT, completion signalled through g_lb_done.  The widened text is released
; and wiped on the way out, so the window is the only place it ever lives.
; =============================================================================
show_logbox proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 256
    cmp     qword ptr [g_lb_hwnd], 0
    jne     lb_ret                               ; already up: never nests
    call    lb_build_text
    test    eax, eax
    jnz     lb_haveclass_pre
    lea     rcx, [m_log_none]
    lea     rdx, [t_log_none]
    mov     r8d, MB_OK or MB_ICONINFORMATION
    call    mbox
    jmp     lb_ret
lb_haveclass_pre:
    mov     dword ptr [g_lb_done], 0
    cmp     dword ptr [g_lb_reg], 0
    jne     lb_haveclass
    lea     rcx, [g_wc]
    xor     r9, r9
lb_zwc:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, WC_SIZE
    jb      lb_zwc
    mov     dword ptr [g_wc+0], WC_SIZE
    mov     dword ptr [g_wc+4], CS_DROPSHADOW
    lea     rax, [lb_wndproc]
    mov     qword ptr [g_wc+8], rax
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [g_wc+24], rax
    WINCALL LoadCursorW, 0, IDC_ARROW
    mov     qword ptr [g_wc+40], rax
    mov     rax, qword ptr [g_hbr_dark]
    mov     qword ptr [g_wc+48], rax
    lea     rax, [wc_logbox]
    mov     qword ptr [g_wc+64], rax
    WINCALL RegisterClassExW, addr g_wc
    mov     dword ptr [g_lb_reg], 1
lb_haveclass:
    ; centre over the parent when there is one, else the screen
    cmp     qword ptr [g_hwnd], 0
    je      lb_centre_screen
    WINCALL GetWindowRect, qword ptr [g_hwnd], addr g_lb_prc
    mov     eax, dword ptr [g_lb_prc+0]
    add     eax, dword ptr [g_lb_prc+8]
    sar     eax, 1
    sub     eax, LB_W / 2
    mov     dword ptr [rbp-72], eax              ; X
    mov     eax, dword ptr [g_lb_prc+4]
    add     eax, dword ptr [g_lb_prc+12]
    sar     eax, 1
    sub     eax, LB_H / 2
    mov     dword ptr [rbp-76], eax              ; Y
    jmp     lb_create
lb_centre_screen:
    WINCALL GetSystemMetrics, SM_CXSCREEN
    sub     eax, LB_W
    sar     eax, 1
    mov     dword ptr [rbp-72], eax
    WINCALL GetSystemMetrics, SM_CYSCREEN
    sub     eax, LB_H
    sar     eax, 1
    mov     dword ptr [rbp-76], eax
lb_create:
    WINCALL CreateWindowExW, <WS_EX_TOOLWINDOW or WS_EX_LAYERED>, addr wc_logbox, addr t_log, \
            ST_MAINWND, dword ptr [rbp-72], dword ptr [rbp-76], LB_W, LB_H, \
            qword ptr [g_hwnd], 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_lb_hwnd], rax
    test    rax, rax
    jz      lb_freetext
    WINCALL SetLayeredWindowAttributes, qword ptr [g_lb_hwnd], 0, WIN_ALPHA, LWA_ALPHA
    WINCALL CreateRoundRectRgn, 0, 0, LB_W+1, LB_H+1, WIN_ROUND, WIN_ROUND
    WINCALL SetWindowRgn, qword ptr [g_lb_hwnd], rax, 1
    cmp     qword ptr [g_hwnd], 0
    je      @F
    WINCALL EnableWindow, qword ptr [g_hwnd], 0
@@:
    WINCALL ShowWindow, qword ptr [g_lb_hwnd], SW_SHOW
    WINCALL UpdateWindow, qword ptr [g_lb_hwnd]
lb_loop:
    WINCALL GetMessageW, addr rbp-120, 0, 0, 0   ; MSG at [rbp-120..]
    test    eax, eax
    jz      lb_finish                            ; WM_QUIT: let the outer loop see it
    js      lb_finish
    cmp     dword ptr [rbp-112], WM_KEYDOWN      ; MSG.message
    jne     lb_disp
    cmp     qword ptr [rbp-104], VK_ESCAPE       ; MSG.wParam
    jne     lb_disp
    WINCALL DestroyWindow, qword ptr [g_lb_hwnd]
    jmp     lb_check
lb_disp:
    WINCALL IsDialogMessageW, qword ptr [g_lb_hwnd], addr rbp-120
    test    eax, eax
    jnz     lb_check
    WINCALL TranslateMessage, addr rbp-120
    WINCALL DispatchMessageW, addr rbp-120
lb_check:
    cmp     dword ptr [g_lb_done], 0
    je      lb_loop
lb_finish:
    cmp     qword ptr [g_hwnd], 0
    je      @F
    WINCALL EnableWindow, qword ptr [g_hwnd], 1
    WINCALL SetFocus, qword ptr [g_hwnd]    ; no repaint needed - see mbox
@@:
    mov     qword ptr [g_lb_hwnd], 0
    mov     qword ptr [g_lb_edit], 0
lb_freetext:
    ; The EDIT kept its own copy of this and it died with the window; ours goes
    ; the same way, wiped, because both were full of the user's file paths.
    mov     rcx, qword ptr [g_lb_text]
    mov     rdx, qword ptr [g_lb_bytes]
    call    mem_free
    mov     qword ptr [g_lb_text], 0
    mov     qword ptr [g_lb_bytes], 0
lb_ret:
    add     rsp, 256
    pop     rbp
    ret
show_logbox endp

; =============================================================================
; lb_wndproc - the action-log viewer's window procedure (raw, no prolog).
; Like mb_wndproc it must NOT PostQuitMessage: the main loop is alive under it.
; =============================================================================
lb_wndproc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    mov     rax, rdx
    cmp     rax, WM_CREATE
    je      lbw_create
    cmp     rax, WM_DRAWITEM
    je      lbw_draw
    cmp     rax, WM_COMMAND
    je      lbw_cmd
    cmp     rax, WM_CTLCOLOREDIT
    je      lbw_ctl
    cmp     rax, WM_CTLCOLORSTATIC
    je      lbw_ctl
    cmp     rax, WM_NCHITTEST
    je      lbw_hit
    cmp     rax, WM_NCLBUTTONDBLCLK
    je      lbw_zero
    cmp     rax, WM_CLOSE
    je      lbw_close
    cmp     rax, WM_DESTROY
    je      lbw_destroy
    jmp     lbw_def
lbw_create:
    mov     rax, qword ptr [rbp-8]
    mov     qword ptr [g_ctl_parent], rax
    call    make_logbox_controls
    mov     qword ptr [g_ctl_parent], 0
    jmp     lbw_zero
lbw_ctl:
    ; the EDIT is a system control: without this it paints itself white
    WINCALL SetTextColor, qword ptr [rbp-24], CLR_WHITE
    WINCALL SetBkColor, qword ptr [rbp-24], CLR_DARK
    mov     rax, qword ptr [g_hbr_dark]
    jmp     lbw_ret
lbw_draw:
    mov     rcx, qword ptr [rbp-32]              ; DRAWITEMSTRUCT*
    mov     eax, dword ptr [rcx+DI_CTLID]
    cmp     eax, ID_LOGBODY
    jne     @F
    call    draw_logbox
    jmp     lbw_one
@@:
    cmp     eax, ID_ACTION
    je      lbw_btn
    cmp     eax, ID_LOGCOPY
    je      lbw_btn
    cmp     eax, ID_LOGSAVE
    jne     lbw_def
lbw_btn:
    mov     rcx, qword ptr [rbp-32]
    call    draw_button
lbw_one:
    mov     rax, 1
    jmp     lbw_ret
lbw_cmd:
    mov     eax, dword ptr [rbp-24]              ; LOWORD(wParam) = control id
    and     eax, 0FFFFh
    cmp     eax, ID_LOGCOPY
    jne     @F
    call    lb_copy
    jmp     lbw_zero
@@:
    cmp     eax, ID_LOGSAVE
    jne     @F
    call    lb_save
    jmp     lbw_zero
@@:
    cmp     eax, ID_ACTION
    je      lbw_end
    cmp     eax, IDCANCEL
    jne     lbw_zero
lbw_end:
    WINCALL DestroyWindow, qword ptr [g_lb_hwnd]
    jmp     lbw_zero
lbw_hit:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    cmp     rax, HTCLIENT
    jne     lbw_ret
    mov     rax, HTCAPTION                       ; drag the borderless body
    jmp     lbw_ret
lbw_close:
    WINCALL DestroyWindow, qword ptr [g_lb_hwnd]
lbw_zero:
    xor     rax, rax
    jmp     lbw_ret
lbw_destroy:
    mov     dword ptr [g_lb_done], 1             ; NOT PostQuitMessage - see above
    xor     rax, rax
    jmp     lbw_ret
lbw_def:
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
lbw_ret:
    add     rsp, 64
    pop     rbp
    ret
lb_wndproc endp

; =============================================================================
; show_about - the no-args / --help screen.  Self-contained: builds the fonts,
; theme brushes and icon it needs (gui_main has not run that setup at this
; point), registers a borderless rounded class, and pumps its own modal loop
; until the window closes.  Process exits afterwards, so the shared g_* slots
; it reuses (g_hinst/g_hfont*/g_hwnd/g_hcancel) are free to borrow.
; =============================================================================
show_about proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 256
    WINCALL GetModuleHandleW, 0
    mov     qword ptr [g_hinst], rax
    ; fonts: ~10pt body, ~16pt semibold heading, large bold runic logo
    WINCALL CreateFontW, -14, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr fontface
    mov     qword ptr [g_hfont], rax
    WINCALL CreateFontW, -22, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, addr fontface
    mov     qword ptr [g_hfont_head], rax
    call    make_theme
    ; 64px app icon from resource ID 1
    WINCALL LoadImageW, qword ptr [g_hinst], 1, IMAGE_ICON, 64, 64, LR_DEFAULTCOLOR
    mov     qword ptr [g_about_icon], rax
    ; zero + fill the WNDCLASSEXW
    lea     rcx, [g_wc]
    xor     r9, r9
sa_zwc:
    mov     byte ptr [rcx+r9], 0
    inc     r9
    cmp     r9, WC_SIZE
    jb      sa_zwc
    mov     dword ptr [g_wc+0], WC_SIZE
    mov     dword ptr [g_wc+4], CS_DROPSHADOW
    lea     rax, [about_wndproc]
    mov     qword ptr [g_wc+8], rax
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [g_wc+24], rax
    mov     rax, qword ptr [g_about_icon]
    mov     qword ptr [g_wc+32], rax            ; hIcon
    mov     qword ptr [g_wc+72], rax            ; hIconSm
    WINCALL LoadCursorW, 0, IDC_ARROW
    mov     qword ptr [g_wc+40], rax
    mov     rax, qword ptr [g_hbr_dark]
    mov     qword ptr [g_wc+48], rax
    lea     rax, [wc_about]
    mov     qword ptr [g_wc+64], rax
    WINCALL RegisterClassExW, addr g_wc
    ; centre on screen
    mov     dword ptr [rbp-48], ABOUT_W
    mov     dword ptr [rbp-52], ABOUT_H
    WINCALL GetSystemMetrics, SM_CXSCREEN
    sub     eax, dword ptr [rbp-48]
    sar     eax, 1
    mov     dword ptr [rbp-72], eax             ; X
    WINCALL GetSystemMetrics, SM_CYSCREEN
    sub     eax, dword ptr [rbp-52]
    sar     eax, 1
    mov     dword ptr [rbp-76], eax             ; Y
    WINCALL CreateWindowExW, <WS_EX_TOOLWINDOW or WS_EX_LAYERED>, addr wc_about, addr wtitle_about, ST_MAINWND, dword ptr [rbp-72], dword ptr [rbp-76], dword ptr [rbp-48], dword ptr [rbp-52], 0, 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_hwnd], rax
    WINCALL SetLayeredWindowAttributes, qword ptr [g_hwnd], 0, WIN_ALPHA, LWA_ALPHA
    ; rounded corners (region owned by the window)
    mov     r8d, dword ptr [rbp-48]
    inc     r8d
    mov     r9d, dword ptr [rbp-52]
    inc     r9d
    WINCALL CreateRoundRectRgn, 0, 0, r8d, r9d, WIN_ROUND, WIN_ROUND
    WINCALL SetWindowRgn, qword ptr [g_hwnd], rax, 1
    WINCALL ShowWindow, qword ptr [g_hwnd], SW_SHOW
    WINCALL UpdateWindow, qword ptr [g_hwnd]
sa_loop:
    WINCALL GetMessageW, addr rbp-80, 0, 0, 0    ; MSG at [rbp-80..]
    test    eax, eax
    jz      sa_done
    js      sa_done
    ; ESC -> close
    cmp     dword ptr [rbp-72], WM_KEYDOWN        ; MSG.message
    jne     sa_disp
    cmp     qword ptr [rbp-64], VK_ESCAPE         ; MSG.wParam
    jne     sa_disp
    WINCALL DestroyWindow, qword ptr [g_hwnd]
    jmp     sa_loop
sa_disp:
    WINCALL IsDialogMessageW, qword ptr [g_hwnd], addr rbp-80
    test    eax, eax
    jnz     sa_loop
    WINCALL TranslateMessage, addr rbp-80
    WINCALL DispatchMessageW, addr rbp-80
    jmp     sa_loop
sa_done:
    add     rsp, 256
    pop     rbp
    ret
show_about endp

; =============================================================================
; wstart - unified entry point for the single hybrid binary.
;
; This executable is linked /subsystem:windows, but it behaves as the full CLI
; whenever its first argument names a known command verb (encrypt, decrypt,
; verify, zip, unzip, hash, selftest, bench).  Otherwise it runs the GUI - so
; double-clicking, "Open with", and drag-and-drop (a bare file path, not a verb)
; all land in the windowed front-end exactly as before.
;
; Shared startup (cpu_gate -> hardening_init) runs first; then we tokenize the
; command line and branch.  CLI mode attaches to the launching console so output
; is visible, then runs the same parse/dispatch path as the old console build.
; =============================================================================
public wstart
wstart proc
    sub     rsp, 56
    call    cpu_gate                     ; raw frame; sets g_cpu_features
    mov     dword ptr [rsp+48], eax      ; cpu-ok flag (checked per-mode below)
    call    hardening_init               ; canary + shadow stack live
    test    eax, eax
    jz      ws_oom
    ; ---- settings, weakest source first -------------------------------------
    ; 1. HKLM\Software\Myrkr\Defaults - what an administrator DEPLOYED.  Read with
    ;    g_loading_hklm clear, so it sets the value and locks nothing: a starting
    ;    point the user may change and have the change stick.
    ; 2. HKCU\Software\Myrkr           - what this user chose.  It is where the
    ;    window saves to, so it beats the deployed default.
    ; 3. the command line.
    ; 4. HKLM\Software\Myrkr           - POLICY.  Last, and it locks.
    ;
    ; The two HKLM keys are the point of the split: presence under the policy key
    ; means "and you may not change this", which is the wrong answer for an
    ; administrator who only wants Zip to be the default on a new machine.
    mov     dword ptr [g_loading_hklm], 0
    mov     ecx, HKEY_LOCAL_MACHINE       ; deployed defaults: set, do not lock
    lea     rdx, [w_regkey_def]
    call    load_settings
    mov     ecx, HKEY_CURRENT_USER        ; this user's own choice
    lea     rdx, [w_regkey]
    call    load_settings
    ; ---- decide CLI vs GUI from argv[1] ------------------------------------
    call    parse_cmdline                ; tokenize into the CLI g_argv/g_argc
    mov     dword ptr [g_loading_hklm], 1 ; HKLM policy (post-parse: overrides CLI+HKCU)
    mov     ecx, HKEY_LOCAL_MACHINE
    lea     rdx, [w_regkey]
    call    load_settings
    mov     dword ptr [g_loading_hklm], 0
    call    is_cli_command               ; eax = 1 if argv[1] is a known verb
    test    eax, eax
    jz      ws_gui
    ; ========================= CLI MODE =====================================
    call    con_attach_parent            ; connect to the launching terminal
    call    con_init                     ; cache stdout/stderr handles
    cmp     dword ptr [rsp+48], 0
    je      ws_nocpu_cli
    call    iat_lockdown
    call    dispatch                     ; run the command; eax = exit code
    mov     dword ptr [rsp+52], eax
    call    secmem_wipe_all              ; wipe + unlock password AND key
    WINCALL ExitProcess, dword ptr [rsp+52]
ws_nocpu_cli:
    lea     rcx, [c_nocpu]
    mov     edx, c_nocpu_len
    call    print_err
    WINCALL ExitProcess, EXIT_NOCPU
    ; ========================= GUI MODE =====================================
ws_gui:
    call    con_init
    cmp     dword ptr [rsp+48], 0
    je      ws_nocpu
    call    iat_lockdown
    call    gui_main
    call    secmem_wipe_all              ; same as the CLI path above: the
                                         ; container view keeps g_cfg_pass for
                                         ; the window's life, so it is still
                                         ; live here when that window is closed
    WINCALL ExitProcess, 0
ws_nocpu:
    ; The one MessageBoxW left, and it has to stay.  The CPU gate fails before
    ; gui_main has created the fonts, theme brushes or window class the themed
    ; mbox draws with, so calling it here would render an empty box - or crash
    ; on a null brush - while reporting the very condition that prevents the
    ; program from running.  A system dialog is the correct fallback when the
    ; process cannot draw its own.
    WINCALL MessageBoxW, 0, addr m_nocpu, addr t_err, <MB_OK or MB_ICONERROR>
    WINCALL ExitProcess, EXIT_NOCPU
ws_oom:
    WINCALL ExitProcess, EXIT_OOM
wstart endp

; =============================================================================
; The IDropTarget vtable, last so that every entry is a backward reference to a
; proc already assembled.  Slot order is the interface's, not ours, and a
; swapped pair here is not a build error - it is ole32 calling Release when it
; meant AddRef.  dt_selfdrop calls through this table for exactly that reason.
; =============================================================================
.const
align 8
vtbl_DropTarget label qword
    dq      DT_QueryInterface                ; IUnknown::QueryInterface
    dq      DT_AddRef                        ; IUnknown::AddRef
    dq      DT_Release                       ; IUnknown::Release
    dq      DT_DragEnter
    dq      DT_DragOver
    dq      DT_DragLeave
    dq      DT_Drop

end
