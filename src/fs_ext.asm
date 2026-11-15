; =============================================================================
; fs_ext.asm - Read-Only ext2 / ext3 / ext4 Filesystem Parser
; -----------------------------------------------------------------------------
; Validates the superblock at +1024 (magic 0xEF53), supports 1/2/4..64 KiB
; blocks, 32-byte and 64-byte group descriptors (INCOMPAT_64BIT), 128..1024B
; inodes, both classic direct + 1/2/3-indirect block maps and EXT4_EXTENTS_FL
; B-trees (0xF30A, depth <= 5, including uninitialized preallocated extents and
; sparse holes), and traverses directories from root inode 2.
;
; Exports:
;   ext_probe         () -> eax: 6 (TCVC_FS_EXT), 0 = not ext, -1 = corrupt
;   ext_enum          () -> eax = EXIT_*
;   ext_extract_entry (rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================

include macros.inc

extern tcvc_read_bytes:proc
extern tcvc_idx_add:proc
extern tcvc_is_sys_root:proc
extern tcvc_sink_write:proc
extern secure_zero:proc
extern mem_alloc:proc
extern mem_free:proc
extern MultiByteToWideChar:proc

externdef g_tcvc_data_size:qword

EXT_MAGIC               equ 0EF53h
EXT_EH_MAGIC            equ 0F30Ah

EXT_CP_UTF8             equ 65001
EXT_MB_ERR_INVALID      equ 08h

EXT_S_IFMT              equ 0F000h
EXT_S_IFDIR             equ 04000h
EXT_S_IFREG             equ 08000h

EXT_INCOMPAT_64BIT      equ 0080h

EXT_FL_ENCRYPT          equ 00000800h
EXT_FL_EXTENTS          equ 00080000h
EXT_FL_INLINE_DATA      equ 10000000h

EXT_MAX_DEPTH           equ 64
EXT_MAX_DIRS            equ 262144
EXT_MAX_DIR_BYTES       equ 04000000h   ; 64 MiB directory cap
EXT_MAX_FSIZE           equ 00007FFFFFFFFFFFh

.data?
align 8
g_ext_tot_blks          dq ?
g_ext_max_fsize         dq ?
g_ext_bsize             dq ?
g_ext_gdt_off           dq ?

g_ext_bshift            dd ?
g_ext_inodes_cnt        dd ?
g_ext_inodes_pg         dd ?
g_ext_num_groups        dd ?
g_ext_inode_sz          dd ?
g_ext_desc_sz           dd ?
g_ext_rev               dd ?
g_ext_is64              dd ?
g_ext_vis_cnt           dd ?

align 4
g_ext_anc_ino           dd (EXT_MAX_DEPTH + 2) dup (?)

align 16
g_ext_inode_dir         db 1024 dup (?)
g_ext_inode_tmp         db 1024 dup (?)
g_ext_gd_buf            db 1024 dup (?)
g_ext_eblk              db 65536 dup (?)
g_ext_iobuf             db 65536 dup (?)
g_ext_zbuf              db 65536 dup (?)
g_ext_path              db 4096 dup (?)
g_ext_comp8             db 1024 dup (?)
align 2
g_ext_tmpw              dw 512 dup (?)

.code

; =============================================================================
; ext_probe() -> eax: 6 = TCVC_FS_EXT, 0 = not ext, -1 = corrupt ext
; =============================================================================
public ext_probe
ext_probe proc frame
    FRAME_PROLOG 1120
    ; [rbp-16..40]   saved rbx, rsi, rdi, r12
    ; [rsp+32..1055] 1024-byte superblock buffer
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12

    cmp     qword ptr [g_tcvc_data_size], 4096
    jb      ep_not_ext

    mov     ecx, 1024
    lea     rdx, [rsp+32]
    mov     r8d, 1024
    call    tcvc_read_bytes
    test    eax, eax
    jnz     ep_not_ext

    lea     rsi, [rsp+32]
    cmp     word ptr [rsi + 56], EXT_MAGIC
    jne     ep_not_ext

    ; Matched 0xEF53: any structural violation from here is -1 (corrupt)
    mov     ecx, dword ptr [rsi + 24]       ; s_log_block_size
    cmp     ecx, 6                          ; 1024..65536
    ja      ep_corrupt
    add     ecx, 10
    mov     dword ptr [g_ext_bshift], ecx
    mov     rbx, 1
    shl     rbx, cl
    mov     qword ptr [g_ext_bsize], rbx

    ; s_first_data_block (+20): must be 1 for 1 KiB blocks, 0 for >1 KiB blocks
    mov     eax, dword ptr [rsi + 20]
    cmp     rbx, 1024
    jne     ep_fdb_gt1k
    cmp     eax, 1
    jne     ep_corrupt
    jmp     ep_inodes
ep_fdb_gt1k:
    test    eax, eax
    jnz     ep_corrupt

ep_inodes:
    mov     edi, dword ptr [rsi + 0]        ; s_inodes_count
    cmp     edi, 2
    jb      ep_corrupt
    mov     dword ptr [g_ext_inodes_cnt], edi

    mov     r8d, dword ptr [rsi + 40]       ; s_inodes_per_group
    test    r8d, r8d
    jz      ep_corrupt
    cmp     r8d, edi
    ja      ep_corrupt
    mov     dword ptr [g_ext_inodes_pg], r8d

    cmp     dword ptr [rsi + 32], 0         ; s_blocks_per_group
    je      ep_corrupt

    ; numGroups = (s_inodes_count + s_inodes_per_group - 1) / s_inodes_per_group
    lea     eax, [edi - 1]
    xor     edx, edx
    div     r8d
    inc     eax
    mov     dword ptr [g_ext_num_groups], eax

    ; Revision & inode/descriptor sizes
    mov     eax, dword ptr [rsi + 76]       ; s_rev_level
    mov     dword ptr [g_ext_rev], eax
    mov     dword ptr [g_ext_is64], 0
    mov     dword ptr [g_ext_desc_sz], 32
    mov     dword ptr [g_ext_inode_sz], 128

    mov     r12d, dword ptr [rsi + 4]       ; s_blocks_count_lo

    test    eax, eax
    jz      ep_chk_blks

    ; Dynamic revision (rev >= 1)
    movzx   ecx, word ptr [rsi + 88]        ; s_inode_size
    cmp     ecx, 128
    jb      ep_corrupt
    cmp     ecx, 1024
    ja      ep_corrupt
    cmp     rcx, rbx
    ja      ep_corrupt
    lea     edx, [ecx - 1]
    test    ecx, edx
    jnz     ep_corrupt
    mov     dword ptr [g_ext_inode_sz], ecx

    mov     eax, dword ptr [rsi + 96]       ; s_feature_incompat
    test    eax, EXT_INCOMPAT_64BIT
    jz      ep_chk_blks

    mov     dword ptr [g_ext_is64], 1
    movzx   ecx, word ptr [rsi + 254]       ; s_desc_size
    test    ecx, ecx
    jnz     ep_dsz_nz
    mov     ecx, 64
ep_dsz_nz:
    cmp     ecx, 64
    jb      ep_corrupt
    cmp     ecx, 1024
    ja      ep_corrupt
    lea     edx, [ecx - 1]
    test    ecx, edx
    jnz     ep_corrupt
    mov     dword ptr [g_ext_desc_sz], ecx

    mov     eax, dword ptr [rsi + 336]      ; s_blocks_count_hi
    shl     rax, 32
    or      r12, rax

ep_chk_blks:
    cmp     r12, 2
    jb      ep_corrupt
    mov     rax, r12
    mov     ecx, dword ptr [g_ext_bshift]
    shl     rax, cl
    ; Check overflow via >> cl == r12
    mov     rdx, rax
    shr     rdx, cl
    cmp     rdx, r12
    jne     ep_corrupt
    cmp     rax, qword ptr [g_tcvc_data_size]
    ja      ep_corrupt

    mov     qword ptr [g_ext_tot_blks], r12
    mov     qword ptr [g_ext_max_fsize], rax

    ; Group Descriptor Table offset: 2048 for 1 KiB blocks, else blockBytes
    mov     rax, rbx
    cmp     rbx, 1024
    jne     ep_gdt_set
    mov     eax, 2048
ep_gdt_set:
    mov     qword ptr [g_ext_gdt_off], rax

    ; Verify GDT fits inside volume
    mov     ecx, dword ptr [g_ext_num_groups]
    mov     edx, dword ptr [g_ext_desc_sz]
    imul    rcx, rdx
    add     rax, rcx
    jc      ep_corrupt
    cmp     rax, qword ptr [g_ext_max_fsize]
    ja      ep_corrupt

    mov     eax, TCVC_FS_EXT
    jmp     ep_out

ep_not_ext:
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
ext_probe endp

; =============================================================================
; ext_read_inode(ecx = ino, rdx = outInodeBuf) -> eax = EXIT_*
; =============================================================================
ext_read_inode proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi

    cmp     ecx, 2
    jb      eri_corrupt
    cmp     ecx, dword ptr [g_ext_inodes_cnt]
    ja      eri_corrupt

    mov     rsi, rdx                        ; outInodeBuf
    lea     eax, [ecx - 1]
    xor     edx, edx
    div     dword ptr [g_ext_inodes_pg]
    ; eax = group, edx = idxInGroup
    mov     ebx, edx

    cmp     eax, dword ptr [g_ext_num_groups]
    jae     eri_corrupt

    mov     ecx, dword ptr [g_ext_desc_sz]
    imul    rax, rcx
    add     rax, qword ptr [g_ext_gdt_off]

    mov     rcx, rax
    lea     rdx, [g_ext_gd_buf]
    mov     r8d, dword ptr [g_ext_desc_sz]
    call    tcvc_read_bytes
    test    eax, eax
    jnz     eri_out

    lea     rcx, [g_ext_gd_buf]
    mov     eax, dword ptr [rcx + 8]        ; bg_inode_table_lo
    cmp     dword ptr [g_ext_is64], 0
    je      eri_it_got
    mov     edx, dword ptr [rcx + 40]       ; bg_inode_table_hi
    shl     rdx, 32
    or      rax, rdx
eri_it_got:
    test    rax, rax
    jz      eri_corrupt
    cmp     rax, qword ptr [g_ext_tot_blks]
    jae     eri_corrupt

    mov     ecx, dword ptr [g_ext_bshift]
    shl     rax, cl
    mov     edx, dword ptr [g_ext_inode_sz]
    imul    rbx, rdx
    add     rax, rbx
    jc      eri_corrupt

    lea     rcx, [rax + rdx]
    cmp     rcx, qword ptr [g_ext_max_fsize]
    ja      eri_corrupt

    mov     rcx, rax
    mov     rdx, rsi
    mov     r8d, dword ptr [g_ext_inode_sz]
    call    tcvc_read_bytes
    jmp     eri_out

eri_corrupt:
    mov     eax, EXIT_CORRUPT

eri_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
ext_read_inode endp

; =============================================================================
; ext_inode_size(rcx = inodePtr) -> rax = byte size
; =============================================================================
ext_inode_size proc
    mov     eax, dword ptr [rcx + 4]        ; i_size_lo
    movzx   edx, word ptr [rcx + 0]         ; i_mode
    and     edx, EXT_S_IFMT
    cmp     edx, EXT_S_IFREG
    jne     eis_done
    cmp     dword ptr [g_ext_rev], 0
    je      eis_done
    mov     edx, dword ptr [rcx + 108]      ; i_size_high
    shl     rdx, 32
    or      rax, rdx
eis_done:
    ret
ext_inode_size endp

; =============================================================================
; ext_read_u32_ptr(rcx = blkNum, rdx = idx, r8 = outU32Ptr) -> eax = EXIT_*
; Reads little-endian u32 pointer at block blkNum, slot idx into *outU32Ptr.
; =============================================================================
ext_read_u32_ptr proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx
    mov     rbx, r8

    cmp     rcx, qword ptr [g_ext_tot_blks]
    jae     erup_bad

    mov     rax, rcx
    mov     ecx, dword ptr [g_ext_bshift]
    shl     rax, cl
    lea     rcx, [rax + rdx*4]
    mov     rdx, rbx
    mov     r8d, 4
    call    tcvc_read_bytes
    jmp     erup_out

erup_bad:
    mov     eax, EXIT_CORRUPT

erup_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
ext_read_u32_ptr endp

; =============================================================================
; ext_map_lblock(rcx = inodePtr, rdx = lblk, r8 = outPhysBlkPtr) -> eax = EXIT_*
; Resolves logical block lblk -> physical block (0 = sparse hole / uninit).
; =============================================================================
ext_map_lblock proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; inodePtr
    mov     r12, rdx                        ; lblk
    mov     r13, r8                         ; outPhysBlkPtr
    mov     qword ptr [r13], 0

    mov     eax, dword ptr [rsi + 32]       ; i_flags
    test    eax, EXT_FL_ENCRYPT
    jnz     eml_unsup
    test    eax, EXT_FL_INLINE_DATA
    jnz     eml_unsup
    test    eax, EXT_FL_EXTENTS
    jnz     eml_extents

    ; ---- Classic ext2/3 direct + 1/2/3-indirect block map -------------------
    cmp     r12, 12
    jae     eml_ind1

    mov     eax, dword ptr [rsi + 40 + r12*4]
    jmp     eml_chk_phys32

eml_ind1:
    mov     ecx, dword ptr [g_ext_bshift]
    sub     ecx, 2                          ; ptrShift = bshift - 2
    mov     r14, 1
    shl     r14, cl                         ; ptrsPerBlk

    sub     r12, 12
    cmp     r12, r14
    jae     eml_ind2

    mov     ecx, dword ptr [rsi + 40 + 12*4]
    test    ecx, ecx
    jz      eml_ok                          ; sparse hole
    mov     rdx, r12                        ; idx0
    lea     r8,  [rbp-72]
    call    ext_read_u32_ptr
    test    eax, eax
    jnz     eml_out
    mov     eax, dword ptr [rbp-72]
    jmp     eml_chk_phys32

eml_ind2:
    sub     r12, r14
    mov     rax, r14
    imul    rax, r14                        ; ptrsPerBlk^2
    cmp     r12, rax
    jae     eml_ind3

    mov     eax, dword ptr [rsi + 40 + 13*4]
    test    eax, eax
    jz      eml_ok
    ; idx1 = r12 / r14, idx0 = r12 % r14
    mov     r15, rax                        ; l1_blk
    mov     rax, r12
    xor     edx, edx
    div     r14
    mov     r12, rdx                        ; idx0
    mov     rdx, rax                        ; idx1
    mov     rcx, r15
    lea     r8,  [rbp-72]
    call    ext_read_u32_ptr
    test    eax, eax
    jnz     eml_out
    mov     ecx, dword ptr [rbp-72]
    test    ecx, ecx
    jz      eml_ok
    mov     rdx, r12
    lea     r8,  [rbp-72]
    call    ext_read_u32_ptr
    test    eax, eax
    jnz     eml_out
    mov     eax, dword ptr [rbp-72]
    jmp     eml_chk_phys32

eml_ind3:
    sub     r12, rax
    imul    rax, r14                        ; ptrsPerBlk^3
    cmp     r12, rax
    jae     eml_corrupt

    mov     eax, dword ptr [rsi + 40 + 14*4]
    test    eax, eax
    jz      eml_ok
    mov     r15, rax                        ; l2_blk

    ; r14^2 in rcx
    mov     rcx, r14
    imul    rcx, r14
    mov     rax, r12
    xor     edx, edx
    div     rcx                             ; rax = idx2, rdx = rem
    mov     r12, rdx
    mov     rdx, rax
    mov     rcx, r15
    lea     r8,  [rbp-72]
    call    ext_read_u32_ptr
    test    eax, eax
    jnz     eml_out
    mov     r15d, dword ptr [rbp-72]
    test    r15d, r15d
    jz      eml_ok

    mov     rax, r12
    xor     edx, edx
    div     r14                             ; rax = idx1, rdx = idx0
    mov     r12, rdx
    mov     rdx, rax
    mov     rcx, r15
    lea     r8,  [rbp-72]
    call    ext_read_u32_ptr
    test    eax, eax
    jnz     eml_out
    mov     ecx, dword ptr [rbp-72]
    test    ecx, ecx
    jz      eml_ok
    mov     rdx, r12
    lea     r8,  [rbp-72]
    call    ext_read_u32_ptr
    test    eax, eax
    jnz     eml_out
    mov     eax, dword ptr [rbp-72]

eml_chk_phys32:
    test    eax, eax
    jz      eml_ok
    cmp     rax, qword ptr [g_ext_tot_blks]
    jae     eml_corrupt
    mov     qword ptr [r13], rax
    jmp     eml_ok

    ; ---- ext4 Extent B-Tree (i_flags & EXT_FL_EXTENTS) ----------------------
eml_extents:
    cmp     r12, 0FFFFFFFFh
    ja      eml_corrupt

    lea     rdi, [rsi + 40]                 ; nodePtr (starts at i_block[0..59])
    mov     r14d, 60                        ; nodeCapBytes
    mov     r15d, -1                        ; prevDepth (-1 = root)

eml_ext_lvl:
    cmp     r14d, 12
    jb      eml_corrupt
    cmp     word ptr [rdi + 0], EXT_EH_MAGIC
    jne     eml_corrupt

    movzx   ebx, word ptr [rdi + 2]         ; eh_entries
    movzx   edx, word ptr [rdi + 6]         ; eh_depth
    cmp     edx, 5
    ja      eml_corrupt

    cmp     r15d, -1
    je      eml_ext_d_ok
    lea     eax, [edx + 1]
    cmp     eax, r15d                       ; must strictly decrease by 1 each level!
    jne     eml_corrupt
eml_ext_d_ok:
    mov     r15d, edx

    imul    eax, ebx, 12
    add     eax, 12
    cmp     eax, r14d
    ja      eml_corrupt

    test    edx, edx
    jnz     eml_ext_idx

    ; Leaf node: scan ext4_extent records
    xor     ecx, ecx
eml_leaf_lp:
    cmp     ecx, ebx
    jae     eml_ok                          ; not covered -> sparse hole (0)

    imul    eax, ecx, 12
    lea     r8, [rdi + 12 + rax]
    mov     eax, dword ptr [r8 + 0]         ; ee_block
    movzx   edx, word ptr [r8 + 4]          ; ee_len_raw
    test    edx, edx
    jz      eml_corrupt

    xor     r9d, r9d                        ; uninitFlag = 0
    cmp     edx, 32768
    jbe     eml_len_ok
    sub     edx, 32768
    jz      eml_corrupt
    mov     r9d, 1
eml_len_ok:
    cmp     r12, rax
    jb      eml_leaf_next
    lea     r10, [rax + rdx]
    cmp     r12, r10
    jae     eml_leaf_next

    ; Matched extent!
    test    r9d, r9d
    jnz     eml_ok                          ; uninitialized extent reads as zeros!

    mov     edx, dword ptr [r8 + 8]         ; ee_start_lo
    movzx   ecx, word ptr [r8 + 6]          ; ee_start_hi
    shl     rcx, 32
    or      rdx, rcx
    mov     rcx, r12
    sub     rcx, rax
    add     rdx, rcx
    jz      eml_corrupt
    cmp     rdx, qword ptr [g_ext_tot_blks]
    jae     eml_corrupt
    mov     qword ptr [r13], rdx
    jmp     eml_ok

eml_leaf_next:
    inc     ecx
    jmp     eml_leaf_lp

eml_ext_idx:
    ; Internal node: find last ext4_extent_idx with ei_block <= r12
    test    ebx, ebx
    jz      eml_ok
    mov     eax, dword ptr [rdi + 12]       ; first ei_block
    cmp     r12, rax
    jb      eml_ok                          ; before first index key -> hole

    xor     ecx, ecx                        ; bestIdx = 0
    mov     edx, 1
eml_idx_lp:
    cmp     edx, ebx
    jae     eml_idx_follow
    imul    eax, edx, 12
    mov     r8d, dword ptr [rdi + 12 + rax] ; ei_block
    cmp     r8, r12
    ja      eml_idx_follow
    mov     ecx, edx
    inc     edx
    jmp     eml_idx_lp

eml_idx_follow:
    imul    eax, ecx, 12
    lea     r8, [rdi + 12 + rax]
    mov     eax, dword ptr [r8 + 4]         ; ei_leaf_lo
    movzx   ecx, word ptr [r8 + 8]          ; ei_leaf_hi
    shl     rcx, 32
    or      rax, rcx
    jz      eml_corrupt
    cmp     rax, qword ptr [g_ext_tot_blks]
    jae     eml_corrupt

    mov     ecx, dword ptr [g_ext_bshift]
    shl     rax, cl
    mov     rcx, rax
    lea     rdx, [g_ext_eblk]
    mov     r8,  qword ptr [g_ext_bsize]
    call    tcvc_read_bytes
    test    eax, eax
    jnz     eml_out

    lea     rdi, [g_ext_eblk]
    mov     r14d, dword ptr [g_ext_bsize]
    jmp     eml_ext_lvl

eml_ok:
    xor     eax, eax
    jmp     eml_out

eml_unsup:
    mov     eax, EXIT_UNSUPPORTED
    jmp     eml_out

eml_corrupt:
    mov     eax, EXIT_CORRUPT

eml_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ext_map_lblock endp

; =============================================================================
; ext_decode_name(rcx = rawBytes, edx = rawLen) -> eax = utf8Len in g_ext_comp8
; Validates UTF-8 via MultiByteToWideChar; if raw Linux bytes are non-UTF-8
; Latin-1, widens 0x80..0xFF losslessly to UTF-8 so no valid file is dropped.
; =============================================================================
ext_decode_name proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rsi
    mov     qword ptr [rbp-24], rdi
    mov     qword ptr [rbp-32], rbx

    test    edx, edx
    jz      edn_bad
    cmp     edx, 255
    ja      edn_bad

    mov     rsi, rcx
    mov     ebx, edx

    ; Reject embedded NUL or '/'
    xor     ecx, ecx
edn_chk:
    movzx   eax, byte ptr [rsi + rcx]
    test    eax, eax
    jz      edn_bad
    cmp     al, '/'
    je      edn_bad
    inc     ecx
    cmp     ecx, ebx
    jb      edn_chk

    WINCALL MultiByteToWideChar, EXT_CP_UTF8, EXT_MB_ERR_INVALID, rsi, ebx, addr g_ext_tmpw, 510
    test    eax, eax
    jz      edn_latin1

    ; Valid UTF-8 -> copy verbatim to g_ext_comp8
    lea     rdi, [g_ext_comp8]
    xor     ecx, ecx
edn_cp:
    mov     al, byte ptr [rsi + rcx]
    mov     byte ptr [rdi + rcx], al
    inc     ecx
    cmp     ecx, ebx
    jb      edn_cp
    mov     byte ptr [rdi + rbx], 0
    mov     eax, ebx
    jmp     edn_out

edn_latin1:
    ; Lossless Latin-1 -> UTF-8 fallback
    lea     rdi, [g_ext_comp8]
    xor     ecx, ecx
    xor     edx, edx
edn_l1_lp:
    movzx   eax, byte ptr [rsi + rcx]
    cmp     eax, 80h
    jb      edn_l1_ascii
    mov     r8d, eax
    shr     r8d, 6
    or      r8d, 0C0h
    mov     byte ptr [rdi + rdx], r8b
    and     eax, 3Fh
    or      eax, 80h
    mov     byte ptr [rdi + rdx + 1], al
    add     edx, 2
    jmp     edn_l1_next
edn_l1_ascii:
    mov     byte ptr [rdi + rdx], al
    inc     edx
edn_l1_next:
    inc     ecx
    cmp     ecx, ebx
    jb      edn_l1_lp
    mov     byte ptr [rdi + rdx], 0
    mov     eax, edx
    jmp     edn_out

edn_bad:
    xor     eax, eax

edn_out:
    mov     rsi, qword ptr [rbp-16]
    mov     rdi, qword ptr [rbp-24]
    mov     rbx, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
ext_decode_name endp

; =============================================================================
; ext_mark_dir_visited(ecx = ino, edx = depth) -> eax = EXIT_*
; Checks active ancestor stack [0..depth-1] for directory cycles, records ino
; at g_ext_anc_ino[depth], and bounds total directories visited.
; =============================================================================
ext_mark_dir_visited proc
    lea     r8,  [g_ext_anc_ino]
    xor     eax, eax
emdv_lp:
    cmp     eax, edx
    jae     emdv_anc_ok
    cmp     dword ptr [r8 + rax*4], ecx
    je      emdv_cycle
    inc     eax
    jmp     emdv_lp
emdv_anc_ok:
    mov     eax, dword ptr [g_ext_vis_cnt]
    cmp     eax, EXT_MAX_DIRS
    jae     emdv_oom
    inc     eax
    mov     dword ptr [g_ext_vis_cnt], eax
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
ext_mark_dir_visited endp

; =============================================================================
; ext_walk_dir(ecx = dirIno, edx = prefixLen, r8d = depth) -> eax = EXIT_*
; =============================================================================
ext_walk_dir proc frame
    FRAME_PROLOG 192
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-72]       dirSize (dq)
    ; [rbp-80]       dirBlkHeap (dq)
    ; [rbp-88]       physBlk (dq)
    ; [rbp-96]       prefixLen (dd), depth (dd at -92)
    ; [rbp-104]      dirIno (dd), childIno (dd at -100)
    ; [rbp-112]      numDirBlks (dq)
    ; [rbp-120]      curLblk (dq)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     qword ptr [rbp-80], 0

    cmp     r8d, EXT_MAX_DEPTH
    ja      ewd_corrupt

    mov     dword ptr [rbp-104], ecx        ; dirIno
    mov     dword ptr [rbp-96], edx         ; prefixLen
    mov     dword ptr [rbp-92], r8d         ; depth

    mov     edx, r8d
    call    ext_mark_dir_visited
    test    eax, eax
    jnz     ewd_out

    mov     ecx, dword ptr [rbp-104]
    lea     rdx, [g_ext_inode_dir]
    call    ext_read_inode
    test    eax, eax
    jnz     ewd_out

    lea     rcx, [g_ext_inode_dir]
    movzx   eax, word ptr [rcx + 0]
    and     eax, EXT_S_IFMT
    cmp     eax, EXT_S_IFDIR
    jne     ewd_corrupt

    call    ext_inode_size
    cmp     rax, EXT_MAX_DIR_BYTES
    ja      ewd_corrupt
    mov     qword ptr [rbp-72], rax

    ; numDirBlks = (dirSize + blockBytes - 1) >> bshift
    mov     rdx, qword ptr [g_ext_bsize]
    lea     rax, [rax + rdx - 1]
    mov     ecx, dword ptr [g_ext_bshift]
    shr     rax, cl
    mov     qword ptr [rbp-112], rax
    mov     qword ptr [rbp-120], 0

    mov     rcx, qword ptr [g_ext_bsize]
    call    mem_alloc
    test    rax, rax
    jz      ewd_oom
    mov     qword ptr [rbp-80], rax

ewd_blk_lp:
    mov     rax, qword ptr [rbp-120]
    cmp     rax, qword ptr [rbp-112]
    jae     ewd_ok

    ; Re-read dirIno into g_ext_inode_dir before mapping block (child recursion may overwrite it)
    mov     ecx, dword ptr [rbp-104]
    lea     rdx, [g_ext_inode_dir]
    call    ext_read_inode
    test    eax, eax
    jnz     ewd_cleanup

    lea     rcx, [g_ext_inode_dir]
    mov     rdx, qword ptr [rbp-120]
    lea     r8,  [rbp-88]
    call    ext_map_lblock
    test    eax, eax
    jnz     ewd_cleanup

    mov     rax, qword ptr [rbp-88]
    test    rax, rax
    jz      ewd_next_blk                    ; sparse dir block -> skip

    mov     ecx, dword ptr [g_ext_bshift]
    shl     rax, cl
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-80]
    mov     r8,  qword ptr [g_ext_bsize]
    call    tcvc_read_bytes
    test    eax, eax
    jnz     ewd_cleanup

    mov     rsi, qword ptr [rbp-80]         ; block base
    xor     r12d, r12d                      ; off within block
    mov     rax, qword ptr [rbp-120]
    mov     ecx, dword ptr [g_ext_bshift]
    shl     rax, cl
    mov     rdx, qword ptr [rbp-72]         ; dirSize
    sub     rdx, rax
    mov     r13, qword ptr [g_ext_bsize]
    cmp     rdx, r13
    jae     ewd_ent_lp
    mov     r13d, edx

ewd_ent_lp:
    cmp     r12d, r13d
    jae     ewd_next_blk

    lea     eax, [r12d + 8]
    cmp     eax, r13d
    ja      ewd_corrupt

    mov     eax, dword ptr [rsi + r12 + 0]  ; d_inode
    movzx   ebx, word ptr [rsi + r12 + 4]   ; d_rec_len
    cmp     ebx, 8
    jb      ewd_corrupt
    test    ebx, 3
    jnz     ewd_corrupt
    lea     ecx, [r12d + ebx]
    cmp     ecx, r13d
    ja      ewd_corrupt

    test    eax, eax
    jz      ewd_ent_adv                     ; unused / deleted / tail checksum slot

    mov     dword ptr [rbp-100], eax        ; childIno
    movzx   edx, byte ptr [rsi + r12 + 6]   ; d_name_len
    test    edx, edx
    jz      ewd_ent_adv
    lea     ecx, [edx + 8]
    cmp     ecx, ebx
    ja      ewd_corrupt

    ; Skip "." and ".."
    cmp     edx, 1
    jne     ewd_chk_dot2
    cmp     byte ptr [rsi + r12 + 8], '.'
    je      ewd_ent_adv
ewd_chk_dot2:
    cmp     edx, 2
    jne     ewd_dec_nm
    cmp     word ptr [rsi + r12 + 8], 2E2Eh
    je      ewd_ent_adv

ewd_dec_nm:
    lea     rcx, [rsi + r12 + 8]
    call    ext_decode_name
    test    eax, eax
    jz      ewd_corrupt
    mov     r14d, eax                       ; compLen

    ; Inspect child inode to classify S_IFREG vs S_IFDIR vs special
    mov     ecx, dword ptr [rbp-100]
    lea     rdx, [g_ext_inode_tmp]
    call    ext_read_inode
    test    eax, eax
    jnz     ewd_cleanup

    lea     rcx, [g_ext_inode_tmp]
    test    dword ptr [rcx + 32], EXT_FL_ENCRYPT
    jnz     ewd_unsup
    movzx   edi, word ptr [rcx + 0]
    and     edi, EXT_S_IFMT
    cmp     edi, EXT_S_IFDIR
    je      ewd_build_p
    cmp     edi, EXT_S_IFREG
    jne     ewd_ent_adv                     ; skip symlinks, sockets, FIFOs, devices!

ewd_build_p:
    cmp     dword ptr [rbp-96], 0
    jne     ewd_not_sys
    lea     rcx, [g_ext_comp8]
    mov     edx, r14d
    call    tcvc_is_sys_root
    test    eax, eax
    jnz     ewd_ent_adv
ewd_not_sys:
    mov     ecx, dword ptr [rbp-96]         ; prefixLen
    lea     eax, [ecx + r14d]
    cmp     eax, ENTRY_NAME_MAX
    ja      ewd_corrupt
    mov     r15d, eax                       ; fullLen

    lea     rdx, [g_ext_path]
    add     rdx, rcx
    lea     r8,  [g_ext_comp8]
    xor     ecx, ecx
ewd_cp_p:
    mov     al, byte ptr [r8 + rcx]
    mov     byte ptr [rdx + rcx], al
    inc     ecx
    cmp     ecx, r14d
    jb      ewd_cp_p

    cmp     edi, EXT_S_IFDIR
    je      ewd_is_dir

    ; Regular file (including sparse files where logical i_size > volume size)
    lea     rcx, [g_ext_inode_tmp]
    call    ext_inode_size
    mov     rcx, EXT_MAX_FSIZE
    cmp     rax, rcx
    ja      ewd_corrupt

    mov     r8, rax                         ; size
    lea     rcx, [g_ext_path]
    mov     edx, r15d
    xor     r9d, r9d
    mov     eax, dword ptr [rbp-100]        ; childIno
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_add
    test    eax, eax
    jnz     ewd_cleanup
    jmp     ewd_ent_adv

ewd_is_dir:
    lea     rcx, [g_ext_path]
    mov     edx, r15d
    xor     r8d, r8d
    mov     r9d, IDXEF_DIR
    mov     eax, dword ptr [rbp-100]
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_add
    test    eax, eax
    jnz     ewd_cleanup

    lea     eax, [r15d + 1]
    cmp     eax, ENTRY_NAME_MAX
    ja      ewd_corrupt
    lea     rdx, [g_ext_path]
    mov     byte ptr [rdx + r15], '/'

    mov     ecx, dword ptr [rbp-100]
    mov     edx, eax                        ; newPrefixLen
    mov     r8d, dword ptr [rbp-92]
    inc     r8d                             ; depth + 1
    call    ext_walk_dir
    test    eax, eax
    jnz     ewd_cleanup

ewd_ent_adv:
    add     r12d, ebx
    jmp     ewd_ent_lp

ewd_next_blk:
    inc     qword ptr [rbp-120]
    jmp     ewd_blk_lp

ewd_ok:
    xor     eax, eax
    jmp     ewd_cleanup

ewd_oom:
    mov     eax, EXIT_OOM
    jmp     ewd_cleanup
ewd_unsup:
    mov     eax, EXIT_UNSUPPORTED
    jmp     ewd_cleanup
ewd_corrupt:
    mov     eax, EXIT_CORRUPT

ewd_cleanup:
    mov     ebx, eax
    mov     rcx, qword ptr [rbp-80]
    test    rcx, rcx
    jz      ewd_out_f
    mov     rdx, qword ptr [g_ext_bsize]
    call    mem_free
ewd_out_f:
    mov     eax, ebx

ewd_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ext_walk_dir endp

; =============================================================================
; ext_enum() -> eax = EXIT_*
; =============================================================================
public ext_enum
ext_enum proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_ext_vis_cnt], 0
    mov     ecx, 2                          ; Root directory inode 2
    xor     edx, edx
    xor     r8d, r8d
    call    ext_walk_dir
    FRAME_EPILOG
    ret
ext_enum endp

; =============================================================================
; ext_extract_entry(rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================
public ext_extract_entry
ext_extract_entry proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], rbx

    mov     r12, qword ptr [rcx + IDXE_size]    ; remBytes
    mov     r13d, dword ptr [rcx + IDXE_offset] ; ino
    xor     r14d, r14d                          ; lblk = 0

    test    r12, r12
    jz      eee_ok

    mov     ecx, r13d
    lea     rdx, [g_ext_inode_tmp]
    call    ext_read_inode
    test    eax, eax
    jnz     eee_out

    lea     rcx, [g_ext_zbuf]
    mov     rdx, qword ptr [g_ext_bsize]
    call    secure_zero

eee_blk_lp:
    test    r12, r12
    jz      eee_ok

    lea     rcx, [g_ext_inode_tmp]
    mov     rdx, r14
    lea     r8,  [rbp-48]                   ; &physBlk
    call    ext_map_lblock
    test    eax, eax
    jnz     eee_clean

    mov     rbx, qword ptr [g_ext_bsize]
    cmp     r12, rbx
    jae     eee_chunk
    mov     rbx, r12
eee_chunk:
    mov     rax, qword ptr [rbp-48]
    test    rax, rax
    jz      eee_sparse

    mov     ecx, dword ptr [g_ext_bshift]
    shl     rax, cl
    mov     rcx, rax
    lea     rdx, [g_ext_iobuf]
    mov     r8d, ebx
    call    tcvc_read_bytes
    test    eax, eax
    jnz     eee_clean

    lea     rcx, [g_ext_iobuf]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     eee_clean
    jmp     eee_adv

eee_sparse:
    lea     rcx, [g_ext_zbuf]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     eee_clean

eee_adv:
    sub     r12, rbx
    inc     r14
    jmp     eee_blk_lp

eee_ok:
    xor     eax, eax

eee_clean:
    mov     ebx, eax
    lea     rcx, [g_ext_iobuf]
    mov     edx, 65536
    call    secure_zero
    mov     eax, ebx

eee_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     rbx, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
ext_extract_entry endp

end
