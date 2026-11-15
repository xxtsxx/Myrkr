; =============================================================================
; fs_exfat.asm - Read-Only exFAT Filesystem Parser
; -----------------------------------------------------------------------------
; Validates the "EXFAT   " boot sector, parses 0x85 + 0xC0 + 0xC1 directory
; entry sets with 16-bit SetChecksum verification, supports both NoFatChain
; contiguous and FAT-chained streams, and honours ValidDataLength.
;
; Exports:
;   exfat_probe         () -> eax: 4 (TCVC_FS_EXFAT), 0 = not exFAT, -1 = corrupt
;   exfat_enum          () -> eax = EXIT_*
;   exfat_extract_entry (rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================

include macros.inc

extern tcvc_read_bytes:proc
extern tcvc_idx_add:proc
extern tcvc_is_sys_root:proc
extern tcvc_sink_write:proc
extern secure_zero:proc
extern WideCharToMultiByte:proc

externdef g_tcvc_data_size:qword

EXF_CP_UTF8             equ 65001

EXF_ATTR_DIRECTORY      equ 10h
EXF_FLAG_ALLOC_POSS     equ 01h
EXF_FLAG_NO_FAT_CHAIN   equ 02h

EXF_MAX_DEPTH           equ 64
EXF_MAX_DIRS            equ 262144
EXF_MAX_DIR_BYTES       equ 04000000h   ; 64 MiB directory stream cap

; Stream cursor layout (32 bytes on stack):
EXFS_curClus            equ 0           ; dd
EXFS_inClusOff          equ 4           ; dd
EXFS_remBytes           equ 8           ; dq
EXFS_steps              equ 16          ; dd
EXFS_noFatChain         equ 20          ; dd

.data?
align 8
g_exf_fat_off           dq ?
g_exf_fat_end           dq ?
g_exf_heap_off          dq ?
g_exf_max_fsize         dq ?
g_exf_cbytes            dq ?

g_exf_nclus             dd ?
g_exf_maxclus           dd ?
g_exf_root_clus         dd ?
g_exf_vis_cnt           dd ?

align 4
g_exf_anc_clus          dd (EXF_MAX_DEPTH + 2) dup (?)

align 2
g_exf_name_w            dw 272 dup (?)

align 16
g_exf_set               db 640 dup (?)  ; up to 19 * 32 = 608 bytes
g_exf_path              db 4096 dup (?)
g_exf_comp8             db 1024 dup (?)
g_exf_iobuf             db 65536 dup (?)

.code

; =============================================================================
; exfat_probe() -> eax: 4 = valid exFAT, 0 = not exFAT, -1 = corrupt exFAT
; =============================================================================
public exfat_probe
exfat_probe proc frame
    FRAME_PROLOG 64
    ; [rbp-16..40] saved rbx, rsi, rdi, r12
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12

    cmp     qword ptr [g_tcvc_data_size], 12288
    jb      ep_not_exf

    xor     ecx, ecx
    lea     rdx, [g_exf_iobuf]
    mov     r8d, 512
    call    tcvc_read_bytes
    test    eax, eax
    jnz     ep_not_exf

    lea     rsi, [g_exf_iobuf]

    ; Check FileSystemName == "EXFAT   " at +3..10
    mov     rax, qword ptr [rsi+3]
    mov     rdx, 02020205441465845h
    cmp     rax, rdx
    jne     ep_not_exf

    ; MustBeZero (+11..63, 53 bytes) must all be 0
    mov     ecx, 11
ep_mbz:
    cmp     byte ptr [rsi + rcx], 0
    jne     ep_corrupt
    inc     ecx
    cmp     ecx, 64
    jb      ep_mbz

    ; BytesPerSectorShift (+108): 9..12 (512..4096)
    movzx   ebx, byte ptr [rsi+108]
    cmp     ebx, 9
    jb      ep_corrupt
    cmp     ebx, 12
    ja      ep_corrupt

    ; Per Microsoft exFAT spec §3.1.20, BootSignature 0xAA55 sits at BytesPerSector - 2
    mov     ecx, ebx
    mov     r8d, 1
    shl     r8d, cl                         ; sectorBytes (512..4096)
    cmp     ebx, 9
    je      ep_chk_bootsig
    xor     ecx, ecx
    mov     rdx, rsi
    call    tcvc_read_bytes
    test    eax, eax
    jnz     ep_corrupt
    mov     ecx, ebx
    mov     r8d, 1
    shl     r8d, cl
ep_chk_bootsig:
    cmp     word ptr [rsi + r8 - 2], 0AA55h
    jne     ep_corrupt

    ; SectorsPerClusterShift (+109): ebx + edi <= 25 (<= 32 MiB per cluster)
    movzx   edi, byte ptr [rsi+109]
    lea     eax, [ebx + edi]
    cmp     eax, 25
    ja      ep_corrupt

    ; NumberOfFats (+110): 1..2
    movzx   r8d, byte ptr [rsi+110]
    cmp     r8d, 1
    jb      ep_corrupt
    cmp     r8d, 2
    ja      ep_corrupt

    ; FatOffset (+80), FatLength (+84), ClusterHeapOffset (+88), ClusterCount (+92), Root (+96)
    mov     r9d,  dword ptr [rsi+80]        ; FatOffset (sectors)
    mov     r10d, dword ptr [rsi+84]        ; FatLength (sectors)
    mov     r11d, dword ptr [rsi+88]        ; ClusterHeapOffset (sectors)
    mov     r12d, dword ptr [rsi+92]        ; ClusterCount

    cmp     r9d, 24
    jb      ep_corrupt
    test    r10d, r10d
    jz      ep_corrupt
    test    r12d, r12d
    jz      ep_corrupt
    cmp     r12d, 0FFFFFFF5h
    ja      ep_corrupt

    ; FatOffset + FatLength * NumberOfFats <= ClusterHeapOffset
    mov     rax, r10
    imul    rax, r8
    add     rax, r9
    cmp     rax, r11
    ja      ep_corrupt

    ; RootClus in 2 .. ClusterCount + 1
    mov     edx, dword ptr [rsi+96]
    cmp     edx, 2
    jb      ep_corrupt
    lea     eax, [r12d + 1]
    cmp     edx, eax
    ja      ep_corrupt
    mov     dword ptr [g_exf_root_clus], edx
    mov     dword ptr [g_exf_nclus], r12d
    mov     dword ptr [g_exf_maxclus], eax

    ; ClusterBytes = 1 << (ebx + edi)
    lea     ecx, [ebx + edi]
    mov     rax, 1
    shl     rax, cl
    mov     qword ptr [g_exf_cbytes], rax

    ; g_exf_max_fsize = ClusterCount * ClusterBytes
    mov     rdx, rax
    imul    rdx, r12
    jc      ep_corrupt
    mov     qword ptr [g_exf_max_fsize], rdx

    ; Byte offsets: fat_off, fat_end, heap_off
    mov     ecx, ebx
    mov     rax, r9
    shl     rax, cl
    mov     qword ptr [g_exf_fat_off], rax

    mov     ecx, ebx
    mov     rdx, r10
    shl     rdx, cl                         ; FatByteLen (exf_next_cluster enforces fat_end)
    cmp     rdx, 12
    jb      ep_corrupt

    mov     rax, qword ptr [g_exf_fat_off]
    add     rax, rdx
    mov     qword ptr [g_exf_fat_end], rax

    mov     ecx, ebx
    mov     rax, r11
    shl     rax, cl                         ; heap_off
    mov     qword ptr [g_exf_heap_off], rax

    ; Verify heap_off + g_exf_max_fsize <= g_tcvc_data_size
    add     rax, qword ptr [g_exf_max_fsize]
    jc      ep_corrupt
    cmp     rax, qword ptr [g_tcvc_data_size]
    ja      ep_corrupt

    mov     eax, TCVC_FS_EXFAT
    jmp     ep_out

ep_not_exf:
    xor     eax, eax
    jmp     ep_out

ep_corrupt:
    mov     eax, -1

ep_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    mov     r12, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
exfat_probe endp

; =============================================================================
; exf_next_cluster(ecx = cluster) -> eax:
;   2..maxclus = next cluster
;   0          = EOC (0xFFFFFFF8..0xFFFFFFFF)
;   -1         = corrupt / bad / I/O error
; =============================================================================
exf_next_cluster proc frame
    FRAME_PROLOG 48
    cmp     ecx, 2
    jb      enc_bad
    cmp     ecx, dword ptr [g_exf_maxclus]
    ja      enc_bad
    mov     dword ptr [rbp-20], ecx

    mov     eax, ecx
    shl     rax, 2
    add     rax, qword ptr [g_exf_fat_off]
    lea     rdx, [rax + 4]
    cmp     rdx, qword ptr [g_exf_fat_end]
    ja      enc_bad

    mov     rcx, rax
    lea     rdx, [rbp-16]
    mov     r8d, 4
    call    tcvc_read_bytes
    test    eax, eax
    jnz     enc_bad

    mov     eax, dword ptr [rbp-16]
    cmp     eax, 0FFFFFFF8h
    jae     enc_eoc
    cmp     eax, 2
    jb      enc_bad
    cmp     eax, dword ptr [g_exf_maxclus]
    ja      enc_bad
    cmp     eax, dword ptr [rbp-20]         ; reject self-loop FAT[c] == c
    je      enc_bad
    jmp     enc_out

enc_eoc:
    xor     eax, eax
    jmp     enc_out

enc_bad:
    mov     eax, -1

enc_out:
    FRAME_EPILOG
    ret
exf_next_cluster endp

; =============================================================================
; exf_mark_dir_visited(ecx = cluster, edx = depth) -> eax = EXIT_*
; Checks active ancestor stack [0..depth-1] for directory cycles, records
; cluster at g_exf_anc_clus[depth], and bounds total directories visited.
; =============================================================================
exf_mark_dir_visited proc
    lea     r8,  [g_exf_anc_clus]
    xor     eax, eax
emdv_lp:
    cmp     eax, edx
    jae     emdv_anc_ok
    cmp     dword ptr [r8 + rax*4], ecx
    je      emdv_cycle
    inc     eax
    jmp     emdv_lp
emdv_anc_ok:
    mov     eax, dword ptr [g_exf_vis_cnt]
    cmp     eax, EXF_MAX_DIRS
    jae     emdv_oom
    inc     eax
    mov     dword ptr [g_exf_vis_cnt], eax
    mov     eax, edx
    mov     dword ptr [r8 + rax*4], ecx
    xor     eax, eax
    ret
emdv_cycle:
    mov     eax, EXIT_CORRUPT
    ret
emdv_oom:
    mov     eax, EXIT_OOM
    ret
exf_mark_dir_visited endp

; =============================================================================
; exf_dir_read32(rcx = streamPtr, rdx = out32) -> eax:
;   0  = read 32 bytes
;   1  = clean end of directory stream
;   -1 = corrupt / I/O error
; =============================================================================
exf_dir_read32 proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi

    mov     rbx, rcx                        ; streamPtr
    mov     rsi, rdx                        ; out32

    cmp     qword ptr [rbx + EXFS_remBytes], 32
    jb      edr_eof

    mov     eax, dword ptr [rbx + EXFS_inClusOff]
    cmp     rax, qword ptr [g_exf_cbytes]
    jb      edr_have_clus

    ; Advance to next cluster
    inc     dword ptr [rbx + EXFS_steps]
    mov     eax, dword ptr [rbx + EXFS_steps]
    cmp     eax, dword ptr [g_exf_nclus]
    ja      edr_bad

    cmp     dword ptr [rbx + EXFS_noFatChain], 0
    je      edr_fat_step

    ; Contiguous stream
    mov     eax, dword ptr [rbx + EXFS_curClus]
    inc     eax
    cmp     eax, dword ptr [g_exf_maxclus]
    ja      edr_bad
    mov     dword ptr [rbx + EXFS_curClus], eax
    mov     dword ptr [rbx + EXFS_inClusOff], 0
    jmp     edr_have_clus

edr_fat_step:
    mov     ecx, dword ptr [rbx + EXFS_curClus]
    call    exf_next_cluster
    test    eax, eax
    jz      edr_eof
    cmp     eax, -1
    je      edr_bad
    mov     dword ptr [rbx + EXFS_curClus], eax
    mov     dword ptr [rbx + EXFS_inClusOff], 0

edr_have_clus:
    mov     eax, dword ptr [rbx + EXFS_curClus]
    cmp     eax, 2
    jb      edr_bad
    cmp     eax, dword ptr [g_exf_maxclus]
    ja      edr_bad
    sub     eax, 2
    imul    rax, qword ptr [g_exf_cbytes]
    add     rax, qword ptr [g_exf_heap_off]
    mov     ecx, dword ptr [rbx + EXFS_inClusOff]
    add     rcx, rax

    mov     rdx, rsi
    mov     r8d, 32
    call    tcvc_read_bytes
    test    eax, eax
    jnz     edr_bad

    add     dword ptr [rbx + EXFS_inClusOff], 32
    sub     qword ptr [rbx + EXFS_remBytes], 32
    xor     eax, eax
    jmp     edr_out

edr_eof:
    mov     eax, 1
    jmp     edr_out

edr_bad:
    mov     eax, -1

edr_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
exf_dir_read32 endp

; =============================================================================
; exf_set_checksum(rcx = setBuf, edx = totalBytes) -> ax = 16-bit SetChecksum
; Skips bytes 2 and 3 per Microsoft exFAT specification §6.3.3.
; =============================================================================
exf_set_checksum proc
    xor     eax, eax
    xor     r8d, r8d
esc_lp:
    cmp     r8d, 2
    je      esc_skip
    cmp     r8d, 3
    je      esc_skip
    ror     ax, 1
    movzx   r9d, byte ptr [rcx + r8]
    add     ax, r9w
esc_skip:
    inc     r8d
    cmp     r8d, edx
    jb      esc_lp
    ret
exf_set_checksum endp

; =============================================================================
; exf_walk_dir(ecx = startClus, rdx = dirBytes, r8d = noFatChain,
;              r9d = prefixLen, [rbp+48] = depth) -> eax = EXIT_*
; =============================================================================
exf_walk_dir proc frame
    FRAME_PROLOG 224
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-68]       prefixLen
    ; [rbp-72]       depth
    ; [rbp-76]       secCount
    ; [rbp-80]       attr
    ; [rbp-88]       validLen
    ; [rbp-96]       dataLen
    ; [rbp-100]      firstClus
    ; [rbp-104]      secFlags
    ; [rbp-136..105] EXF_STREAM (32 bytes)
    ; alloc = 240; 240 - 136 = 104 >= 64 (outgoing [rsp+32..56])
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     eax, dword ptr [rbp+48]
    cmp     eax, EXF_MAX_DEPTH
    ja      ewd_corrupt
    mov     dword ptr [rbp-72], eax         ; depth
    mov     dword ptr [rbp-68], r9d         ; prefixLen

    test    rdx, rdx
    jz      ewd_ok

    cmp     ecx, 2
    jb      ewd_corrupt
    cmp     ecx, dword ptr [g_exf_maxclus]
    ja      ewd_corrupt

    ; Clamp dirBytes to EXF_MAX_DIR_BYTES
    cmp     rdx, EXF_MAX_DIR_BYTES
    jbe     ewd_dir_cap
    mov     rdx, EXF_MAX_DIR_BYTES
ewd_dir_cap:

    ; Initialize stream cursor on stack at [rbp-136]
    mov     dword ptr [rbp-136 + EXFS_curClus], ecx
    mov     dword ptr [rbp-136 + EXFS_inClusOff], 0
    mov     qword ptr [rbp-136 + EXFS_remBytes], rdx
    mov     dword ptr [rbp-136 + EXFS_steps], 0
    mov     dword ptr [rbp-136 + EXFS_noFatChain], r8d

    mov     edx, dword ptr [rbp-72]
    call    exf_mark_dir_visited
    test    eax, eax
    jnz     ewd_ret

ewd_loop:
    lea     rcx, [rbp-136]
    lea     rdx, [g_exf_set]
    call    exf_dir_read32
    cmp     eax, 1
    je      ewd_ok
    test    eax, eax
    jnz     ewd_corrupt

    lea     rsi, [g_exf_set]
    movzx   eax, byte ptr [rsi]
    test    eax, eax
    jz      ewd_ok                          ; 0x00 = end of directory
    test    eax, 80h
    jz      ewd_loop                        ; unused entry -> skip
    cmp     al, 85h
    jne     ewd_loop                        ; AllocationBitmap (0x81), UpCase (0x82), Label (0x83) -> skip

    ; ---- 0x85 File Directory Entry Set --------------------------------------
    movzx   ebx, byte ptr [rsi + 1]         ; SecondaryCount (2..18)
    cmp     ebx, 2
    jb      ewd_corrupt
    cmp     ebx, 18
    ja      ewd_corrupt
    mov     dword ptr [rbp-76], ebx

    ; Read SecondaryCount * 32 bytes into g_exf_set[32..]
    mov     r12d, 1
ewd_rd_sec:
    lea     rcx, [rbp-136]
    mov     eax, r12d
    shl     eax, 5
    lea     rdx, [g_exf_set]
    add     rdx, rax
    call    exf_dir_read32
    test    eax, eax                        ; EOF inside an active set is corrupt!
    jnz     ewd_corrupt
    inc     r12d
    cmp     r12d, ebx
    jbe     ewd_rd_sec

    ; Verify 16-bit SetChecksum
    lea     rcx, [g_exf_set]
    lea     edx, [ebx + 1]
    shl     edx, 5
    call    exf_set_checksum
    cmp     ax, word ptr [g_exf_set + 2]
    jne     ewd_corrupt

    ; Parse File entry (+0) and Stream Extension (+32)
    lea     rsi, [g_exf_set]
    movzx   eax, word ptr [rsi + 4]
    mov     dword ptr [rbp-80], eax         ; FileAttributes

    cmp     byte ptr [rsi + 32], 0C0h       ; StreamExtension
    jne     ewd_corrupt
    movzx   eax, byte ptr [rsi + 32 + 1]
    mov     dword ptr [rbp-104], eax        ; GeneralSecondaryFlags
    movzx   r13d, byte ptr [rsi + 32 + 3]   ; NameLength (UTF-16 chars, 1..255)
    test    r13d, r13d
    jz      ewd_corrupt

    ; Verify (NameLength + 14) / 15 <= SecondaryCount - 1
    lea     eax, [r13d + 14]
    xor     edx, edx
    mov     ecx, 15
    div     ecx
    lea     ecx, [ebx - 1]
    cmp     eax, ecx
    ja      ewd_corrupt

    mov     rax, qword ptr [rsi + 32 + 8]   ; ValidDataLength
    mov     rdx, qword ptr [rsi + 32 + 24]  ; DataLength
    cmp     rax, rdx
    ja      ewd_corrupt
    cmp     rdx, qword ptr [g_exf_max_fsize]
    ja      ewd_corrupt
    mov     qword ptr [rbp-88], rax
    mov     qword ptr [rbp-96], rdx

    mov     eax, dword ptr [rsi + 32 + 20]  ; FirstCluster
    mov     dword ptr [rbp-100], eax

    ; Validate FirstCluster when DataLength > 0
    test    rdx, rdx
    jz      ewd_clus_ok
    test    byte ptr [rbp-104], EXF_FLAG_ALLOC_POSS
    jz      ewd_corrupt
    cmp     eax, 2
    jb      ewd_corrupt
    cmp     eax, dword ptr [g_exf_maxclus]
    ja      ewd_corrupt
ewd_clus_ok:

    ; Assemble UTF-16LE filename from 0xC1 entries
    lea     rdi, [g_exf_name_w]
    xor     r14d, r14d                      ; charsCopied
    mov     r12d, 2                         ; entry index in set (2 .. ebx)
ewd_fn_ent:
    cmp     r14d, r13d
    jae     ewd_fn_done
    cmp     r12d, ebx
    ja      ewd_corrupt
    mov     eax, r12d
    shl     eax, 5
    lea     rcx, [rsi + rax]
    cmp     byte ptr [rcx], 0C1h
    jne     ewd_corrupt

    xor     edx, edx                        ; word 0..14 inside 0xC1 entry
ewd_fn_ch:
    cmp     r14d, r13d
    jae     ewd_fn_done
    cmp     edx, 15
    jae     ewd_fn_next_ent
    mov     ax, word ptr [rcx + 2 + rdx*2]
    test    ax, ax                          ; embedded NUL inside NameLength is corrupt
    jz      ewd_corrupt
    mov     word ptr [rdi + r14*2], ax
    inc     r14d
    inc     edx
    jmp     ewd_fn_ch

ewd_fn_next_ent:
    inc     r12d
    jmp     ewd_fn_ent

ewd_fn_done:
    WINCALL WideCharToMultiByte, EXF_CP_UTF8, 0, addr g_exf_name_w, r13d, addr g_exf_comp8, 1020, 0, 0
    test    eax, eax
    jz      ewd_corrupt
    mov     r14d, eax                       ; compLen

    ; Skip "." and ".." if present
    lea     rdi, [g_exf_comp8]
    cmp     r14d, 1
    jne     ewd_chk_d2
    cmp     byte ptr [rdi], '.'
    je      ewd_loop
ewd_chk_d2:
    cmp     r14d, 2
    jne     ewd_join
    cmp     word ptr [rdi], 2E2Eh
    je      ewd_loop

ewd_join:
    cmp     dword ptr [rbp-68], 0
    jne     ewd_not_sys
    mov     rcx, rdi
    mov     edx, r14d
    call    tcvc_is_sys_root
    test    eax, eax
    jnz     ewd_loop
ewd_not_sys:
    mov     ecx, dword ptr [rbp-68]         ; prefixLen
    lea     eax, [ecx + r14d]
    cmp     eax, ENTRY_NAME_MAX
    ja      ewd_corrupt
    mov     r15d, eax                       ; fullLen

    lea     rdx, [g_exf_path]
    add     rdx, rcx
    xor     ecx, ecx
ewd_cp:
    mov     al, byte ptr [rdi + rcx]
    mov     byte ptr [rdx + rcx], al
    inc     ecx
    cmp     ecx, r14d
    jb      ewd_cp

    test    dword ptr [rbp-80], EXF_ATTR_DIRECTORY
    jnz     ewd_is_dir

    ; Emit regular file entry
    lea     rcx, [g_exf_path]
    mov     edx, r15d
    mov     r8,  qword ptr [rbp-96]         ; size = DataLength
    xor     r9d, r9d                        ; flags = 0
    mov     eax, dword ptr [rbp-100]
    mov     qword ptr [rsp+32], rax         ; meta0 = FirstCluster
    mov     rax, qword ptr [rbp-88]
    mov     qword ptr [rsp+40], rax         ; meta1 = ValidDataLength
    mov     eax, dword ptr [rbp-104]
    mov     qword ptr [rsp+48], rax         ; meta2 = GeneralSecondaryFlags
    call    tcvc_idx_add
    test    eax, eax
    jnz     ewd_ret
    jmp     ewd_loop

ewd_is_dir:
    ; Emit directory entry
    lea     rcx, [g_exf_path]
    mov     edx, r15d
    xor     r8d, r8d
    mov     r9d, IDXEF_DIR
    mov     eax, dword ptr [rbp-100]
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_add
    test    eax, eax
    jnz     ewd_ret

    ; Empty subdirectory (DataLength == 0) has nothing to walk
    cmp     qword ptr [rbp-96], 0
    je      ewd_loop

    lea     eax, [r15d + 1]
    cmp     eax, ENTRY_NAME_MAX
    ja      ewd_corrupt
    lea     rdx, [g_exf_path]
    mov     byte ptr [rdx + r15], '/'

    mov     ecx, dword ptr [rbp-100]        ; child FirstCluster
    mov     rdx, qword ptr [rbp-96]         ; child DataLength
    xor     r8d, r8d
    test    dword ptr [rbp-104], EXF_FLAG_NO_FAT_CHAIN
    setnz   r8b                             ; noFatChain = 0 or 1
    lea     r9d, [r15d + 1]                 ; newPrefixLen
    mov     eax, dword ptr [rbp-72]
    inc     eax
    mov     qword ptr [rsp+32], rax         ; depth + 1
    call    exf_walk_dir
    test    eax, eax
    jnz     ewd_ret
    jmp     ewd_loop

ewd_ok:
    xor     eax, eax
    jmp     ewd_ret

ewd_corrupt:
    mov     eax, EXIT_CORRUPT

ewd_ret:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
exf_walk_dir endp

; =============================================================================
; exfat_enum() -> eax = EXIT_*
; =============================================================================
public exfat_enum
exfat_enum proc frame
    FRAME_PROLOG 64
    mov     dword ptr [g_exf_vis_cnt], 0

    mov     ecx, dword ptr [g_exf_root_clus]
    mov     edx, EXF_MAX_DIR_BYTES
    xor     r8d, r8d                        ; root directory is always FAT-chained
    xor     r9d, r9d                        ; prefixLen = 0
    mov     qword ptr [rsp+32], 0           ; depth = 0
    call    exf_walk_dir

    FRAME_EPILOG
    ret
exfat_enum endp

; =============================================================================
; exfat_extract_entry(rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================
public exfat_extract_entry
exfat_extract_entry proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi

    mov     rsi, qword ptr [rcx + IDXE_size]    ; total DataLength
    mov     r12, qword ptr [rcx + IDXE_stored]  ; ValidDataLength
    mov     r13d, dword ptr [rcx + IDXE_offset] ; curClus
    mov     eax, dword ptr [rcx + IDXE_ordinal] ; GeneralSecondaryFlags
    mov     dword ptr [rbp-64], eax
    xor     r14d, r14d                          ; steps

    test    rsi, rsi
    jz      eee_ok

    cmp     r12, rsi
    ja      eee_corrupt
    cmp     rsi, qword ptr [g_exf_max_fsize]
    ja      eee_corrupt

    sub     rsi, r12                            ; zeroTailBytes = DataLength - ValidDataLength

    ; If ValidDataLength > 0, check NoFatChain contiguous range up front
    test    r12, r12
    jz      eee_zero_tail

    test    dword ptr [rbp-64], EXF_FLAG_NO_FAT_CHAIN
    jz      eee_clus_lp

    ; Contiguous check: (r12 + cbytes - 1) / cbytes clusters starting at r13d <= maxclus + 1
    mov     rax, r12
    mov     rcx, qword ptr [g_exf_cbytes]
    lea     rax, [rax + rcx - 1]
    xor     edx, edx
    div     rcx                                 ; rax = neededClusters
    mov     ecx, r13d
    add     rax, rcx
    dec     rax                                 ; lastClus
    mov     ecx, dword ptr [g_exf_maxclus]
    cmp     rax, rcx
    ja      eee_corrupt

eee_clus_lp:
    cmp     r13d, 2
    jb      eee_corrupt
    cmp     r13d, dword ptr [g_exf_maxclus]
    ja      eee_corrupt

    inc     r14d
    cmp     r14d, dword ptr [g_exf_nclus]
    ja      eee_corrupt

    ; bytesInClus = min(r12, g_exf_cbytes)
    mov     rbx, qword ptr [g_exf_cbytes]
    cmp     r12, rbx
    jae     eee_csz
    mov     rbx, r12
eee_csz:
    mov     eax, r13d
    sub     eax, 2
    imul    rax, qword ptr [g_exf_cbytes]
    add     rax, qword ptr [g_exf_heap_off]
    mov     r15, rax

eee_chunk_lp:
    test    rbx, rbx
    jz      eee_clus_done
    mov     rcx, rbx
    cmp     rcx, 65536
    jbe     eee_rd
    mov     ecx, 65536
eee_rd:
    mov     dword ptr [rbp-68], ecx
    mov     rcx, r15
    lea     rdx, [g_exf_iobuf]
    mov     r8d, dword ptr [rbp-68]
    call    tcvc_read_bytes
    test    eax, eax
    jnz     eee_out

    lea     rcx, [g_exf_iobuf]
    mov     edx, dword ptr [rbp-68]
    call    tcvc_sink_write
    test    eax, eax
    jnz     eee_out

    mov     eax, dword ptr [rbp-68]
    add     r15, rax
    sub     rbx, rax
    sub     r12, rax
    jmp     eee_chunk_lp

eee_clus_done:
    test    r12, r12
    jz      eee_zero_tail

    test    dword ptr [rbp-64], EXF_FLAG_NO_FAT_CHAIN
    jz      eee_fat_adv
    inc     r13d
    jmp     eee_clus_lp

eee_fat_adv:
    mov     ecx, r13d
    call    exf_next_cluster
    cmp     eax, 2
    jb      eee_corrupt
    mov     r13d, eax
    jmp     eee_clus_lp

eee_zero_tail:
    test    rsi, rsi
    jz      eee_ok
    lea     rcx, [g_exf_iobuf]
    mov     edx, 65536
    call    secure_zero
eee_zt_lp:
    test    rsi, rsi
    jz      eee_ok
    mov     rdx, rsi
    cmp     rdx, 65536
    jbe     eee_zt_wr
    mov     edx, 65536
eee_zt_wr:
    mov     dword ptr [rbp-68], edx
    lea     rcx, [g_exf_iobuf]
    call    tcvc_sink_write
    test    eax, eax
    jnz     eee_out
    mov     eax, dword ptr [rbp-68]
    sub     rsi, rax
    jmp     eee_zt_lp

eee_ok:
    xor     eax, eax
    jmp     eee_out

eee_corrupt:
    mov     eax, EXIT_CORRUPT

eee_out:
    mov     dword ptr [rbp-72], eax
    lea     rcx, [g_exf_iobuf]
    mov     edx, 65536
    call    secure_zero
    mov     eax, dword ptr [rbp-72]
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
exfat_extract_entry endp

end
