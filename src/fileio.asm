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
extern VirtualAlloc:proc
extern VirtualFree:proc
extern MoveFileExW:proc
extern DeleteFileW:proc
extern GetDiskFreeSpaceExW:proc
extern secure_zero:proc

MOVEFILE_REPLACE_EXISTING equ 1

GENERIC_READ        equ 80000000h
GENERIC_WRITE       equ 40000000h
FILE_SHARE_READ     equ 1
OPEN_EXISTING       equ 3
CREATE_ALWAYS       equ 2
FILE_ATTR_NORMAL    equ 80h
MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_READWRITE      equ 04h
IO_CHUNK            equ 1000000h         ; 16 MiB per ReadFile/WriteFile

.data?
align 2
g_dfdir     dw MAX_PATH_CHARS dup (?)    ; scratch: directory of a path

.code

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
    WINCALL VirtualAlloc, 0, rcx, <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
    FRAME_EPILOG
    ret
mem_alloc endp

; =============================================================================
public mem_free
mem_free proc frame
    FRAME_PROLOG 48
    xIFT rcx                             ; ptr != 0
        mov     qword ptr [rbp-24], rcx
        xIFT rdx                         ; len != 0 -> wipe before release
            call    secure_zero          ; (rcx=ptr, rdx=len)
        xENDIF
        WINCALL VirtualFree, qword ptr [rbp-24], 0, MEM_RELEASE
    xENDIF
    FRAME_EPILOG
    ret
mem_free endp

; =============================================================================
; read_file(rcx = wpath, rdx = *outbuf, r8 = *outsize) -> eax
; =============================================================================
public read_file
read_file proc frame
    FRAME_PROLOG 128                    ; 128 (alloc 144), not 96: the 7-arg
                                        ; CreateFileW's outgoing area reached the
                                        ; local at [rbp-80]
    ; [rbp-24]=outbuf* [rbp-32]=outsize* [rbp-40]=handle
    ; [rbp-48]=filesize [rbp-56]=buf [rbp-64]=cursor [rbp-72]=remaining
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8

    WINCALL CreateFileW, rcx, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      rf_io
    mov     qword ptr [rbp-40], rax

    WINCALL GetFileSizeEx, rax, addr rbp-48
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
    FRAME_PROLOG 64
    WINCALL CreateFileW, rcx, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    FRAME_EPILOG
    ret
file_open_read endp

; file_open_write(rcx = wpath) -> rax = handle (or -1)
public file_open_write
file_open_write proc frame
    FRAME_PROLOG 64
    WINCALL CreateFileW, rcx, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTR_NORMAL, 0
    FRAME_EPILOG
    ret
file_open_write endp

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
    FRAME_PROLOG 64
    WINCALL CreateFileW, rcx, <GENERIC_READ or GENERIC_WRITE>, 0, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
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
    FRAME_PROLOG 48
    WINCALL MoveFileExW, rcx, rdx, MOVEFILE_REPLACE_EXISTING
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
