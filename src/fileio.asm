; =============================================================================
; fileio.asm - file read/write and memory helpers
; -----------------------------------------------------------------------------
;   mem_alloc(rcx = size)               -> rax = ptr (0 on failure)
;   mem_free (rcx = ptr, rdx = size)    (wipes then releases)
;   read_file(rcx = wpath, rdx = *outbuf, r8 = *outsize) -> eax 0 / EXIT_IO
;   write_file(rcx = wpath, rdx = buf, r8 = size)        -> eax 0 / EXIT_IO
; =============================================================================

include macros.inc

extern CreateFileW:proc
extern ReadFile:proc
extern WriteFile:proc
extern GetFileSizeEx:proc
extern SetFilePointerEx:proc
extern SetEndOfFile:proc
extern CloseHandle:proc
extern GetFileType:proc
extern GetFileInformationByHandleEx:proc
extern GetFinalPathNameByHandleW:proc
extern FindFirstFileW:proc
extern FindClose:proc
extern MoveFileExW:proc
extern DeleteFileW:proc
extern GetDiskFreeSpaceExW:proc
extern GetFileAttributesW:proc
extern FlushFileBuffers:proc
extern secure_zero:proc
extern tagged_alloc:proc
extern tagged_free:proc
extern tagged_check:proc
externdef g_allow_unc:dword             ; gui.asm: AllowUnc policy/setting (default 1)

MOVEFILE_REPLACE_EXISTING equ 1
MOVEFILE_WRITE_THROUGH    equ 8
INVALID_FILE_ATTRIBUTES   equ 0FFFFFFFFh
FILE_SHARE_ALL            equ 7          ; read | write | delete

GENERIC_READ        equ 80000000h
GENERIC_WRITE       equ 40000000h
FILE_SHARE_READ     equ 1
OPEN_EXISTING       equ 3
CREATE_ALWAYS       equ 2
CREATE_NEW          equ 1
FILE_ATTR_NORMAL    equ 80h
FILE_FLAG_OPEN_RP   equ 00200000h        ; FILE_FLAG_OPEN_REPARSE_POINT
FILE_ATTR_REPARSE_  equ 00000400h        ; FILE_ATTRIBUTE_REPARSE_POINT
REPARSE_SURROGATE_  equ 20000000h        ; IsReparseTagNameSurrogate bit
FILE_TYPE_DISK_     equ 1
FILE_ATTR_TAG_INFO  equ 9                ; FileAttributeTagInfo
IO_CHUNK            equ 1000000h         ; 16 MiB per ReadFile/WriteFile

.data?
align 8
g_fvh_find  db 600 dup (?)               ; WIN32_FIND_DATAW (592 bytes)
align 2
g_dfdir     dw MAX_PATH_CHARS dup (?)    ; scratch: directory of a path
g_fvh_final dw (MAX_PATH_CHARS + 16) dup (?)

.code

; =============================================================================
; file_path_allowed(rcx = wide path) -> eax = 1 allowed / 0 refused.
; Pre-CreateFileW gate:
;   - rejects NULL / empty paths
;   - blocks Win32 device namespaces ("\\.\" and "\\?\GLOBALROOT\...")
;   - checks g_allow_unc on UNC paths ("\\server\..." and "\\?\UNC\...")
;   - rejects NTFS Alternate Data Stream ':' colons past the drive letter
; =============================================================================
public file_path_allowed
file_path_allowed proc
    test    rcx, rcx
    jz      fpa_no
    cmp     word ptr [rcx], 0
    je      fpa_no
    mov     r10, rcx
    movzx   eax, word ptr [r10]
    cmp     ax, 5Ch
    je      fpa_bs1
    cmp     ax, '/'
    jne     fpa_scan_ads
fpa_bs1:
    movzx   eax, word ptr [r10+2]
    cmp     ax, 5Ch
    je      fpa_bs2
    cmp     ax, '/'
    jne     fpa_scan_ads
fpa_bs2:
    ; starts with "\\" or "//"
    movzx   eax, word ptr [r10+4]
    cmp     ax, '.'
    je      fpa_no                              ; "\\.\" device namespace -> refuse
    cmp     ax, '?'
    jne     fpa_unc                             ; "\\server\..." -> check g_allow_unc
    movzx   eax, word ptr [r10+6]
    cmp     ax, 5Ch
    je      fpa_qbody
    cmp     ax, '/'
    jne     fpa_no
fpa_qbody:
    ; "\\?\" prefix: allow "\\?\X:\..." local drive; check "\\?\UNC\..."; refuse others
    movzx   eax, word ptr [r10+8]
    or      ax, 20h
    cmp     ax, 'a'
    jb      fpa_no
    cmp     ax, 'z'
    ja      fpa_no
    cmp     word ptr [r10+10], ':'
    je      fpa_qdrive
    cmp     ax, 'u'
    jne     fpa_no                              ; e.g. "\\?\GLOBALROOT\..." -> refuse
    movzx   eax, word ptr [r10+10]
    or      ax, 20h
    cmp     ax, 'n'
    jne     fpa_no
    movzx   eax, word ptr [r10+12]
    or      ax, 20h
    cmp     ax, 'c'
    jne     fpa_no
    movzx   eax, word ptr [r10+14]
    cmp     ax, 5Ch
    je      fpa_unc
    cmp     ax, '/'
    je      fpa_unc
    jmp     fpa_no
fpa_qdrive:
    movzx   eax, word ptr [r10+12]
    cmp     ax, 5Ch
    je      fpa_scan_ads
    cmp     ax, '/'
    je      fpa_scan_ads
    jmp     fpa_no
fpa_unc:
    cmp     dword ptr [g_allow_unc], 0
    je      fpa_no
fpa_scan_ads:
    ; Reject NTFS Alternate Data Stream ':' anywhere except index 1 ("X:...")
    ; or index 5 on "\\?\X:..."
    xor     r8d, r8d
fpa_colon_lp:
    movzx   eax, word ptr [r10 + r8*2]
    test    ax, ax
    jz      fpa_ok
    cmp     ax, ':'
    jne     fpa_colon_next
    cmp     r8d, 1
    je      fpa_colon_next
    cmp     r8d, 5
    jne     fpa_no
    cmp     word ptr [r10], 5Ch
    jne     fpa_no
    cmp     word ptr [r10+4], '?'
    jne     fpa_no
fpa_colon_next:
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS + 16
    jb      fpa_colon_lp
    jmp     fpa_no
fpa_ok:
    mov     eax, 1
    ret
fpa_no:
    xor     eax, eax
    ret
file_path_allowed endp

; file_leaf_surrogate(rcx = wide path) -> eax = 1 if path exists as a symlink,
; junction, or mount point (name-surrogate reparse point); 0 otherwise (including
; non-existent files and OneDrive cloud placeholders).
file_leaf_surrogate proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL GetFileAttributesW, rcx
    cmp     eax, INVALID_FILE_ATTRIBUTES
    je      fls_no
    test    eax, FILE_ATTR_REPARSE_
    jz      fls_no
    WINCALL FindFirstFileW, qword ptr [rbp-24], addr g_fvh_find
    cmp     rax, -1
    je      fls_yes
    mov     qword ptr [rbp-32], rax
    WINCALL FindClose, qword ptr [rbp-32]
    test    dword ptr [g_fvh_find+36], REPARSE_SURROGATE_
    jz      fls_no
fls_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
fls_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
file_leaf_surrogate endp

; =============================================================================
; file_validate_handle(rcx = hFile) -> eax = 1 valid disk file / 0 refused.
;   1. GetFileType(h) == FILE_TYPE_DISK (rejects pipes, CON, NUL, COM*, etc.)
;   2. GetFileInformationByHandleEx(FileAttributeTagInfo): rejects name-surrogate
;      reparse points while preserving OneDrive/cloud placeholder compatibility
;   3. GetFinalPathNameByHandleW -> file_path_allowed (enforces g_allow_unc and
;      ADS ':' rejection after resolving parent junctions / mapped drives)
; =============================================================================
public file_validate_handle
file_validate_handle proc frame
    FRAME_PROLOG 80
    ; [rbp-24] = hFile, [rbp-40..-33] = FILE_ATTRIBUTE_TAG_INFO (8 bytes)
    mov     qword ptr [rbp-24], rcx
    WINCALL GetFileType, rcx
    cmp     eax, FILE_TYPE_DISK_
    jne     fvh_no
    mov     qword ptr [rbp-40], 0
    WINCALL GetFileInformationByHandleEx, qword ptr [rbp-24], FILE_ATTR_TAG_INFO, addr rbp-40, 8
    test    eax, eax
    jz      fvh_final
    test    dword ptr [rbp-40], FILE_ATTR_REPARSE_
    jz      fvh_final
    test    dword ptr [rbp-36], REPARSE_SURROGATE_
    jnz     fvh_no
fvh_final:
    WINCALL GetFinalPathNameByHandleW, qword ptr [rbp-24], addr g_fvh_final, <MAX_PATH_CHARS + 16>, 0
    test    eax, eax
    jz      fvh_no
    cmp     eax, MAX_PATH_CHARS + 16
    jae     fvh_no
    lea     rcx, [g_fvh_final]
    call    file_path_allowed
    test    eax, eax
    jz      fvh_no
    mov     eax, 1
    FRAME_EPILOG
    ret
fvh_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
file_validate_handle endp

; Keep the source immutable to other writers while allowing our atomic rename.
public file_open_rewrite_source
file_open_rewrite_source proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    call    file_path_allowed
    test    eax, eax
    jz      fors_bad
    mov     rcx, qword ptr [rbp-24]
    call    file_leaf_surrogate
    test    eax, eax
    jnz     fors_bad
    WINCALL CreateFileW, qword ptr [rbp-24], 0C0000000h, 5, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      fors_done
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      fors_close
    mov     rax, qword ptr [rbp-32]
    jmp     fors_done
fors_close:
    WINCALL CloseHandle, qword ptr [rbp-32]
fors_bad:
    mov     rax, -1
fors_done:
    FRAME_EPILOG
    ret
file_open_rewrite_source endp

; =============================================================================
; disk_has_space(rcx = wide path on the target volume, rdx = required bytes)
;   -> eax: 0 = enough free, 1 = NOT enough, 2 = could not determine
; The path may be a not-yet-existing file; we query the volume of its parent
; directory (everything up to the last separator), which always exists at the
; point of the check.  Returns 2 (proceed) if the query fails, so a finicky
; filesystem never blocks a valid operation.
; =============================================================================
public disk_has_space
disk_has_space proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = required   [rbp-32] = free-bytes-available (out)
    mov     qword ptr [rbp-24], rdx
    ; copy path -> g_dfdir, remembering the last separator index
    mov     r10, rcx                     ; src
    lea     r11, [g_dfdir]               ; dst
    xor     r9, r9                       ; index
    mov     rax, -1                      ; last separator index (none yet)
dhs_cpy:
    mov     dx, word ptr [r10+r9*2]
    mov     word ptr [r11+r9*2], dx
    test    dx, dx
    jz      dhs_cpyd
    cmp     dx, '\'
    je      dhs_sep
    cmp     dx, '/'
    jne     dhs_adv
dhs_sep:
    mov     rax, r9
dhs_adv:
    inc     r9
    cmp     r9, MAX_PATH_CHARS-1
    jb      dhs_cpy
dhs_cpyd:
    xIF rax, ne, -1                      ; a separator was found
        lea     r11, [g_dfdir]           ; truncate just after the last sep
        inc     rax
        mov     word ptr [r11+rax*2], 0
    xENDIF
dhs_query:
    WINCALL GetDiskFreeSpaceExW, addr g_dfdir, addr rbp-32, 0, 0
    xIFZ eax
        mov     eax, 2                   ; query failed -> proceed anyway
    xELSE
        mov     rax, qword ptr [rbp-32]
        xIF rax, b, qword ptr [rbp-24]   ; free < required (unsigned)
            mov     eax, 1
        xELSE
            xor     eax, eax             ; enough
        xENDIF
    xENDIF
    FRAME_EPILOG
    ret
disk_has_space endp

; =============================================================================
public mem_alloc
mem_alloc proc frame
    FRAME_PROLOG 48
    xIFZ rcx
        mov     rcx, 1                   ; never request 0 bytes
    xENDIF
    call    tagged_alloc
    FRAME_EPILOG
    ret
mem_alloc endp

; =============================================================================
public mem_free
mem_free proc frame
    FRAME_PROLOG 48
    xIFT rcx                             ; ptr != 0
        mov     qword ptr [rbp-24], rcx
        mov     qword ptr [rbp-32], rdx
        call    tagged_check             ; verify header + canaries; returns rax = blksize
        mov     rcx, qword ptr [rbp-24]
        mov     rdx, qword ptr [rbp-32]
        xIFT rdx                         ; touched len != 0 -> clamp & wipe
            cmp     rdx, rax
            jbe     mf_wipe
            mov     rdx, rax
mf_wipe:
            call    secure_zero          ; wipe only touched pages (keeps PeakWS bounded)
        xENDIF
        mov     rcx, qword ptr [rbp-24]
        xor     edx, edx                 ; already wiped touched prefix above
        call    tagged_free
    xENDIF
    FRAME_EPILOG
    ret
mem_free endp

; =============================================================================
; read_file(rcx = wpath, rdx = *outbuf, r8 = *outsize) -> eax
; =============================================================================
public read_file
read_file proc frame
    FRAME_PROLOG 144                    ; 144 (alloc 160): leaves [rbp-88] clear
                                        ; of 7-arg CreateFileW's outgoing area
    ; [rbp-24]=outbuf* [rbp-32]=outsize* [rbp-40]=handle
    ; [rbp-48]=filesize [rbp-56]=buf [rbp-64]=cursor [rbp-72]=remaining
    ; [rbp-88]=wpath
    mov     qword ptr [rbp-88], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8

    call    file_path_allowed
    test    eax, eax
    jz      rf_io
    mov     rcx, qword ptr [rbp-88]
    call    file_leaf_surrogate
    test    eax, eax
    jnz     rf_io

    WINCALL CreateFileW, qword ptr [rbp-88], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      rf_io
    mov     qword ptr [rbp-40], rax

    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      rf_io_close

    WINCALL GetFileSizeEx, qword ptr [rbp-40], addr rbp-48
    test    eax, eax
    jz      rf_io_close

    ; allocate buffer
    mov     rcx, qword ptr [rbp-48]
    call    mem_alloc
    test    rax, rax
    jz      rf_oom_close
    mov     qword ptr [rbp-56], rax
    mov     qword ptr [rbp-64], rax              ; cursor
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [rbp-72], rax              ; remaining

    xWHILE qword ptr [rbp-72], ne, 0         ; while bytes remain
        mov     r10, qword ptr [rbp-72]
        xIF r10, a, IO_CHUNK
            mov     r10, IO_CHUNK
        xENDIF
        WINCALL ReadFile, qword ptr [rbp-40], qword ptr [rbp-64], r10, addr rbp-80, 0
        test    eax, eax
        jz      rf_io_freebuf                    ; I/O error -> cleanup
        mov     r10d, dword ptr [rbp-80]
        xIFZ r10d                                ; 0 bytes read = EOF
            xBREAK
        xENDIF
        add     qword ptr [rbp-64], r10
        sub     qword ptr [rbp-72], r10
    xENDW
rf_ok:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-56]
    mov     qword ptr [rax], r10                 ; *outbuf
    mov     rax, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-48]
    mov     qword ptr [rax], r10                 ; *outsize
    xor     eax, eax
    jmp     rf_done

rf_io_freebuf:
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
rf_io_close:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_IO
    jmp     rf_done
rf_oom_close:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_OOM
    jmp     rf_done
rf_io:
    mov     eax, EXIT_IO
rf_done:
    FRAME_EPILOG
    ret
read_file endp

; =============================================================================
; Handle-based primitives for streaming I/O
; =============================================================================

; file_open_read(rcx = wpath) -> rax = handle (or INVALID_HANDLE_VALUE = -1)
public file_open_read
file_open_read proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    call    file_path_allowed
    test    eax, eax
    jz      for_bad
    mov     rcx, qword ptr [rbp-24]
    call    file_leaf_surrogate
    test    eax, eax
    jnz     for_bad
    WINCALL CreateFileW, qword ptr [rbp-24], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      for_done
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      for_close
    mov     rax, qword ptr [rbp-32]
    jmp     for_done
for_close:
    WINCALL CloseHandle, qword ptr [rbp-32]
for_bad:
    mov     rax, -1
for_done:
    FRAME_EPILOG
    ret
file_open_read endp

; file_open_write(rcx = wpath) -> rax = handle (or -1)
public file_open_write
file_open_write proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    call    file_path_allowed
    test    eax, eax
    jz      fow_bad
    mov     rcx, qword ptr [rbp-24]
    call    file_leaf_surrogate
    test    eax, eax
    jnz     fow_bad
    WINCALL CreateFileW, qword ptr [rbp-24], GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      fow_done
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      fow_close
    mov     rax, qword ptr [rbp-32]
    jmp     fow_done
fow_close:
    WINCALL CloseHandle, qword ptr [rbp-32]
fow_bad:
    mov     rax, -1
fow_done:
    FRAME_EPILOG
    ret
file_open_write endp

; file_open_new(rcx = wpath) -> rax = handle (or -1)
; CREATE_NEW: fails if ANYTHING already has the name - a file, a directory, a
; link.  Extraction writes into a fresh random sibling through this and renames
; it over the real name only once its bytes have verified, so an existing file
; is never truncated before that point and a pre-placed hardlink is replaced
; rather than written through.
public file_open_new
file_open_new proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    call    file_path_allowed
    test    eax, eax
    jz      fon_bad
    mov     rcx, qword ptr [rbp-24]
    call    file_leaf_surrogate
    test    eax, eax
    jnz     fon_bad
    WINCALL CreateFileW, qword ptr [rbp-24], GENERIC_WRITE, 0, 0, CREATE_NEW, <FILE_ATTR_NORMAL or FILE_FLAG_OPEN_RP>, 0
    cmp     rax, -1
    je      fon_done
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      fon_close
    mov     rax, qword ptr [rbp-32]
    jmp     fon_done
fon_close:
    WINCALL CloseHandle, qword ptr [rbp-32]
fon_bad:
    mov     rax, -1
fon_done:
    FRAME_EPILOG
    ret
file_open_new endp

; get_file_size(rcx = handle, rdx = *size) -> eax 0/EXIT_IO
public get_file_size
get_file_size proc frame
    FRAME_PROLOG 48
    WINCALL GetFileSizeEx, rcx, rdx
    test    eax, eax
    jz      gfs_io
    xor     eax, eax
    FRAME_EPILOG
    ret
gfs_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
get_file_size endp

; file_read_exact(rcx = handle, rdx = buf, r8 = len) -> eax 0/EXIT_IO
; reads exactly len bytes (looping); short read before len -> EXIT_IO
public file_read_exact
file_read_exact proc frame
    FRAME_PROLOG 80                     ; 80 (alloc 96), not 64.  At 64 the
                                        ; lpOverlapped=NULL stack slot [rsp+32]
                                        ; WAS [rbp-48] - the same address handed
                                        ; to ReadFile as lpNumberOfBytesRead.
                                        ; That aliasing only works if the callee
                                        ; consumes the arg before writing the
                                        ; count; do not depend on it.
    mov     qword ptr [rbp-24], rcx     ; handle
    mov     qword ptr [rbp-32], rdx     ; cursor
    mov     qword ptr [rbp-40], r8      ; remaining
    xWHILE qword ptr [rbp-40], ne, 0         ; while bytes remain
        mov     r10, qword ptr [rbp-40]
        xIF r10, a, IO_CHUNK
            mov     r10, IO_CHUNK
        xENDIF
        WINCALL ReadFile, qword ptr [rbp-24], qword ptr [rbp-32], r10, addr rbp-48, 0
        test    eax, eax
        jz      fre_io
        mov     r10d, dword ptr [rbp-48]
        test    r10d, r10d
        jz      fre_io                       ; short read / unexpected EOF
        add     qword ptr [rbp-32], r10
        sub     qword ptr [rbp-40], r10
    xENDW
fre_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
fre_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
file_read_exact endp

; =============================================================================
; file_read_at(rcx=handle, rdx=offset64, r8=buf, r9=len) -> eax 0/EXIT_IO
; Positioned exact read: seek to offset (FILE_BEGIN) then read len bytes.  Leaves
; the file pointer at offset+len so sequential file_read_exact can continue.
; =============================================================================
public file_read_at
file_read_at proc frame
    FRAME_PROLOG 64                     ; 64 (alloc 80), not 48: [rbp-40] sat in
                                        ; SetFilePointerEx's home space
    mov     qword ptr [rbp-24], rcx         ; handle
    mov     qword ptr [rbp-32], r8          ; buf
    mov     qword ptr [rbp-40], r9          ; len
    ; SetFilePointerEx(handle, distance=offset, NULL, FILE_BEGIN=0)
    WINCALL SetFilePointerEx, rcx, rdx, 0, 0
    test    eax, eax
    jz      fra_io
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-40]
    call    file_read_exact
    FRAME_EPILOG
    ret
fra_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
file_read_at endp

; =============================================================================
; file_open_rw(rcx = wpath) -> rax = handle (or -1)
; Read AND write on an existing file, for the one operation that edits a
; container where it lies instead of rewriting it: deleting an entry in place.
; =============================================================================
public file_open_rw
file_open_rw proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    call    file_path_allowed
    test    eax, eax
    jz      forw_bad
    mov     rcx, qword ptr [rbp-24]
    call    file_leaf_surrogate
    test    eax, eax
    jnz     forw_bad
    WINCALL CreateFileW, qword ptr [rbp-24], <GENERIC_READ or GENERIC_WRITE>, 0, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      forw_done
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      forw_close
    mov     rax, qword ptr [rbp-32]
    jmp     forw_done
forw_close:
    WINCALL CloseHandle, qword ptr [rbp-32]
forw_bad:
    mov     rax, -1
forw_done:
    FRAME_EPILOG
    ret
file_open_rw endp

; =============================================================================
; file_truncate(rcx = handle, rdx = new length) -> eax 0/EXIT_IO
; =============================================================================
public file_truncate
file_truncate proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    call    file_seek
    test    eax, eax
    jnz     ftr_io
    WINCALL SetEndOfFile, qword ptr [rbp-16]
    test    eax, eax
    jz      ftr_io
    xor     eax, eax
    FRAME_EPILOG
    ret
ftr_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
file_truncate endp

; =============================================================================
; file_seek(rcx = handle, rdx = offset64) -> eax 0/EXIT_IO
; Position only, for readers that then stream sequentially from there - which is
; how an entry's extent is honoured rather than assumed to follow the last one.
; =============================================================================
public file_seek
file_seek proc frame
    FRAME_PROLOG 48
    WINCALL SetFilePointerEx, rcx, rdx, 0, 0    ; FILE_BEGIN
    test    eax, eax
    jz      fsk_io
    xor     eax, eax
    FRAME_EPILOG
    ret
fsk_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
file_seek endp

; file_write_all(rcx = handle, rdx = buf, r8 = len) -> eax 0/EXIT_IO
public file_write_all
file_write_all proc frame
    FRAME_PROLOG 80                     ; 80 (alloc 96), not 64: same
                                        ; lpOverlapped/lpNumberOfBytesWritten
                                        ; aliasing as file_read_exact
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    xWHILE qword ptr [rbp-40], ne, 0         ; while bytes remain
        mov     r10, qword ptr [rbp-40]
        xIF r10, a, IO_CHUNK
            mov     r10, IO_CHUNK
        xENDIF
        WINCALL WriteFile, qword ptr [rbp-24], qword ptr [rbp-32], r10, addr rbp-48, 0
        test    eax, eax
        jz      fwa_io                           ; I/O error
        mov     r10d, dword ptr [rbp-48]
        add     qword ptr [rbp-32], r10
        sub     qword ptr [rbp-40], r10
    xENDW
fwa_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
fwa_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
file_write_all endp

; file_close(rcx = handle)
public file_close
file_close proc frame
    FRAME_PROLOG 48
    xIF rcx, ne, -1
        WINCALL CloseHandle, rcx
    xENDIF
    FRAME_EPILOG
    ret
file_close endp

; file_rename(rcx = from, rdx = to) -> eax 0/EXIT_IO  (atomic replace)
public file_rename
file_rename proc frame
    FRAME_PROLOG 96
    ; [rbp-24] from  [rbp-32] to  [rbp-40] handle
    ;
    ; REPLACING a file is the case that needs care.  NTFS journals the rename
    ; but writes the file's data lazily, so after a power cut a rename that
    ; reached the disk can name a file whose data did not - the user's existing
    ; file replaced by zeros, which is exactly what temp-then-rename (1.1.3)
    ; promised could not happen.  So when the destination exists: flush the new
    ; file's data first, and rename with MOVEFILE_WRITE_THROUGH so the call does
    ; not return before the rename is on disk.  (Vordr's fileio does the same.)
    ;
    ; A NEW name gets neither.  Losing a file that did not exist before costs
    ; nothing a re-run cannot restore, and a flush per file would make a 20,000-
    ; file extraction into a fresh folder many times slower.
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    call    file_path_allowed
    test    eax, eax
    jz      frn_io
    mov     rcx, qword ptr [rbp-32]
    call    file_path_allowed
    test    eax, eax
    jz      frn_io
    mov     rcx, qword ptr [rbp-24]
    call    file_leaf_surrogate
    test    eax, eax
    jnz     frn_io
    WINCALL GetFileAttributesW, qword ptr [rbp-32]
    cmp     eax, INVALID_FILE_ATTRIBUTES
    je      frn_plain
    ; Best effort: a source somebody holds without sharing write cannot be
    ; reopened, and then only the write-through rename is had.
    WINCALL CreateFileW, qword ptr [rbp-24], GENERIC_WRITE, FILE_SHARE_ALL, 0, OPEN_EXISTING, <FILE_ATTR_NORMAL or FILE_FLAG_OPEN_RP>, 0
    cmp     rax, -1
    je      frn_through
    mov     qword ptr [rbp-40], rax
    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      frn_close_bad
    WINCALL FlushFileBuffers, qword ptr [rbp-40]
    WINCALL CloseHandle, qword ptr [rbp-40]
    jmp     frn_through
frn_close_bad:
    WINCALL CloseHandle, qword ptr [rbp-40]
    jmp     frn_io
frn_through:
    WINCALL MoveFileExW, qword ptr [rbp-24], qword ptr [rbp-32], <MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH>
    jmp     frn_check
frn_plain:
    WINCALL MoveFileExW, qword ptr [rbp-24], qword ptr [rbp-32], MOVEFILE_REPLACE_EXISTING
frn_check:
    test    eax, eax
    jz      frn_io
    xor     eax, eax
    FRAME_EPILOG
    ret
frn_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
file_rename endp

; file_delete(rcx = wpath)
public file_delete
file_delete proc frame
    FRAME_PROLOG 48
    WINCALL DeleteFileW, rcx
    FRAME_EPILOG
    ret
file_delete endp

end
