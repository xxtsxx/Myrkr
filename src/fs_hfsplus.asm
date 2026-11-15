; =============================================================================
; fs_hfsplus.asm - Read-Only macOS HFS+ / HFSX Filesystem Parser
; -----------------------------------------------------------------------------
; Supports big-endian HFS+ ("H+", v4) and case-sensitive HFSX ("HX", v5)
; volumes, including HFS+ volumes embedded inside a classic "BD" HFS wrapper.
; Walks the Catalog B-Tree from root folder CNID 2, converts UTF-16BE decomposed
; (NFD) filenames to precomposed (NFC) UTF-8, skips internal macOS journal /
; private metadata and symlinks/devices, and extracts regular-file data forks
; across both the 8 inline extents and the Extents Overflow B-Tree.
;
; Exports:
;   hfsplus_probe         () -> eax: 7 (TCVC_FS_HFSPLUS), 0 = not HFS+, -1 = corrupt
;   hfsplus_enum          () -> eax = EXIT_*
;   hfsplus_extract_entry (rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================

include macros.inc

extern tcvc_read_bytes:proc
extern tcvc_idx_add:proc
extern tcvc_sink_write:proc
extern secure_zero:proc
extern mem_alloc:proc
extern mem_free:proc
extern FoldStringW:proc
extern WideCharToMultiByte:proc

externdef g_tcvc_data_size:qword

HFS_CP_UTF8             equ 65001
HFS_MAP_PRECOMPOSED     equ 20h

HFS_SIG_BD              equ 4244h       ; "BD" classic HFS wrapper
HFS_SIG_PLUS            equ 482Bh       ; "H+" HFS+ v4
HFS_SIG_HFSX            equ 4858h       ; "HX" HFSX v5

HFS_BT_LEAF             equ -1          ; 0xFF (i8)
HFS_BT_INDEX            equ 0
HFS_BT_HEADER           equ 1

HFS_REC_FOLDER          equ 1
HFS_REC_FILE            equ 2
HFS_REC_FOLDER_THD      equ 3
HFS_REC_FILE_THD        equ 4

HFS_CNID_ROOT_DIR       equ 2
HFS_CNID_CATALOG        equ 4

HFS_S_IFMT              equ 0F000h
HFS_S_IFREG             equ 08000h
HFS_FDTYPE_SLNK         equ 736C6E6Bh   ; 'slnk'

HFS_MAX_DEPTH           equ 64
HFS_MAX_BTREE_DEPTH     equ 32
HFS_MAX_DIRS            equ 262144

.data?
align 8
g_hfs_embed_off         dq ?
g_hfs_part_size         dq ?
g_hfs_bsize             dq ?
g_hfs_tot_blks          dq ?
g_hfs_cat_size          dq ?
g_hfs_ext_size          dq ?

g_hfs_bshift            dd ?
g_hfs_cat_nsize         dd ?
g_hfs_cat_totn          dd ?
g_hfs_cat_root          dd ?
g_hfs_cat_depth         dd ?
g_hfs_ext_nsize         dd ?
g_hfs_ext_totn          dd ?
g_hfs_ext_root          dd ?
g_hfs_ext_depth         dd ?
g_hfs_vis_cnt           dd ?

align 4
g_hfs_anc_cnid          dd (HFS_MAX_DEPTH + 2) dup (?)
g_hfs_cat_exts          dd 16 dup (?)   ; 8 x { startBlock, blockCount } host LE
g_hfs_ext_exts          dd 16 dup (?)   ; 8 x { startBlock, blockCount } host LE

align 2
g_hfs_name_w1           dw 264 dup (?)
g_hfs_name_w2           dw 520 dup (?)

align 16
g_hfs_ext_node          db 65536 dup (?)
g_hfs_leaf_buf          db 65536 dup (?)
g_hfs_path              db 4096 dup (?)
g_hfs_comp8             db 1024 dup (?)
g_hfs_iobuf             db 65536 dup (?)

.code

; =============================================================================
; hfs_unpack_extents8(rcx = be64BytesPtr, rdx = outLeU32x16)
; Converts 8 big-endian HFSPlusExtentDescriptor pairs into host little-endian.
; =============================================================================
hfs_unpack_extents8 proc
    xor     r8d, r8d
hue_lp:
    mov     eax, dword ptr [rcx + r8*4]
    bswap   eax
    mov     dword ptr [rdx + r8*4], eax
    inc     r8d
    cmp     r8d, 16
    jb      hue_lp
    ret
hfs_unpack_extents8 endp

; =============================================================================
; hfs_validate_node(rcx = nodeBuf, edx = nodeSize) -> eax = 0 ok, -1 corrupt
; Validates BTNodeDescriptor record count and strictly increasing big-endian
; record offsets at the end of the node.
; =============================================================================
hfs_validate_node proc
    cmp     edx, 512
    jb      hvn_bad

    movzx   r8d, word ptr [rcx + 10]        ; numRecords (BE16)
    rol     r8w, 8
    movzx   r8d, r8w

    ; Need 14 + 2*(numRecords + 1) <= nodeSize
    lea     eax, [r8d + 1]
    add     eax, eax
    mov     r9d, edx
    sub     r9d, eax                        ; r9d = maxFreeOffset = nodeSize - 2*(numRecords+1)
    cmp     r9d, 14
    jl      hvn_bad

    ; Check offsets i = 0 .. numRecords
    ; recOff[i] sits at nodeBuf + nodeSize - 2*(i + 1)
    lea     r10, [rcx + rdx - 2]            ; &recOff[0]
    movzx   r11d, word ptr [r10]
    rol     r11w, 8
    movzx   r11d, r11w                      ; prevOff = recOff[0]
    cmp     r11d, 14
    jb      hvn_bad
    cmp     r11d, r9d
    ja      hvn_bad

    xor     eax, eax                        ; i = 0
hvn_lp:
    cmp     eax, r8d
    jae     hvn_ok
    sub     r10, 2
    movzx   edx, word ptr [r10]
    rol     dx, 8
    movzx   edx, dx                         ; curOff = recOff[i+1]
    cmp     edx, r11d                       ; must be strictly > prevOff
    jbe     hvn_bad
    cmp     edx, r9d                        ; must be <= maxFreeOffset
    ja      hvn_bad
    mov     r11d, edx
    inc     eax
    jmp     hvn_lp

hvn_ok:
    xor     eax, eax
    ret
hvn_bad:
    mov     eax, -1
    ret
hfs_validate_node endp

; =============================================================================
; hfs_get_rec_bounds(rcx = validatedNodeBuf, edx = nodeSize, r8d = recIdx,
;                    r9 = outRecLenPtr) -> rax = recPtr
; =============================================================================
hfs_get_rec_bounds proc
    lea     rax, [rcx + rdx]
    lea     r10d, [r8d + 1]
    add     r10d, r10d
    sub     rax, r10                        ; &recOff[recIdx]
    movzx   r10d, word ptr [rax]
    rol     r10w, 8
    movzx   r10d, r10w                      ; off0
    movzx   r11d, word ptr [rax - 2]
    rol     r11w, 8
    movzx   r11d, r11w                      ; off1
    sub     r11d, r10d
    mov     dword ptr [r9], r11d
    lea     rax, [rcx + r10]
    ret
hfs_get_rec_bounds endp

; Forward declaration: hfs_fork_read calls hfs_lookup_overflow_blk, which reads
; Extents B-Tree nodes via hfs_fork_read with cnidForOverflow == 0 (non-recursive).

; =============================================================================
; hfs_cmp_ext_key(rcx = recPtr, edx = recLen, r8d = targetFileID, r9d = targetLblk)
;   -> eax: -1 (rec < target), 0 (==), +1 (rec > target), -2 (corrupt key)
; Compares HFSPlusExtentKey in TN1150 order: (fileID, forkType, startBlock) vs
; (targetFileID, 0x00 data fork, targetLblk).
; =============================================================================
hfs_cmp_ext_key proc
    cmp     edx, 12
    jb      hcek_bad
    movzx   eax, word ptr [rcx]
    rol     ax, 8
    cmp     ax, 10
    jne     hcek_bad

    mov     eax, dword ptr [rcx + 4]        ; fileID (BE32)
    bswap   eax
    cmp     eax, r8d
    jb      hcek_lt
    ja      hcek_gt

    movzx   eax, byte ptr [rcx + 2]         ; forkType (0 = data, 0xFF = rsrc)
    test    eax, eax
    jnz     hcek_gt                         ; any non-zero forkType > 0

    mov     eax, dword ptr [rcx + 8]        ; startBlock (BE32)
    bswap   eax
    cmp     eax, r9d
    jb      hcek_lt
    ja      hcek_gt

    xor     eax, eax
    ret
hcek_lt:
    mov     eax, -1
    ret
hcek_gt:
    mov     eax, 1
    ret
hcek_bad:
    mov     eax, -2
    ret
hfs_cmp_ext_key endp

; =============================================================================
; hfs_lookup_overflow_blk(ecx = fileID, edx = targetLblk, r8 = outPhysBlkPtr,
;                         r9 = outAvailBlksPtr) -> eax = EXIT_*
; Searches Extents Overflow B-Tree for data-fork extent covering targetLblk.
; =============================================================================
hfs_lookup_overflow_blk proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     r12d, ecx                       ; fileID
    mov     r13d, edx                       ; targetLblk
    mov     qword ptr [rbp-72], r8          ; outPhysBlkPtr
    mov     qword ptr [rbp-80], r9          ; outAvailBlksPtr

    mov     ebx, dword ptr [g_hfs_ext_root]
    test    ebx, ebx
    jz      hlob_corrupt
    mov     edi, dword ptr [g_hfs_ext_nsize]
    test    edi, edi
    jz      hlob_corrupt

    mov     r14d, dword ptr [g_hfs_ext_depth]
    inc     r14d                            ; max levels
    mov     r15d, 0FFh                      ; prevHeight

hlob_descend:
    test    r14d, r14d
    jz      hlob_corrupt
    dec     r14d

    cmp     ebx, dword ptr [g_hfs_ext_totn]
    jae     hlob_corrupt

    ; Read node ebx from Extents Overflow File (cnid = 0 -> inline extents only)
    mov     eax, ebx
    imul    rax, rdi                        ; byteOff = nodeNum * extNodeSize
    lea     rcx, [g_hfs_ext_exts]
    xor     edx, edx                        ; cnidForOverflow = 0
    mov     r8,  rax
    lea     r9,  [g_hfs_ext_node]
    mov     qword ptr [rsp+32], rdi
    call    hfs_fork_read
    test    eax, eax
    jnz     hlob_out

    lea     rcx, [g_hfs_ext_node]
    mov     edx, edi
    call    hfs_validate_node
    test    eax, eax
    jnz     hlob_corrupt

    lea     rsi, [g_hfs_ext_node]
    movzx   eax, byte ptr [rsi + 9]         ; height
    cmp     eax, r15d
    jae     hlob_corrupt
    mov     r15d, eax

    movzx   eax, word ptr [rsi + 10]
    rol     ax, 8
    movzx   eax, ax                         ; numRecords
    test    eax, eax
    jz      hlob_corrupt
    mov     dword ptr [rbp-84], eax         ; numRecords

    movsx   eax, byte ptr [rsi + 8]         ; kind
    cmp     eax, HFS_BT_INDEX
    je      hlob_index
    cmp     eax, HFS_BT_LEAF
    je      hlob_leaf
    jmp     hlob_corrupt

hlob_index:
    mov     dword ptr [rbp-88], -1          ; bestIdx = -1
    xor     ebx, ebx                        ; i = 0
hlob_idx_lp:
    cmp     ebx, dword ptr [rbp-84]
    jae     hlob_idx_follow
    mov     rcx, rsi
    mov     edx, edi
    mov     r8d, ebx
    lea     r9,  [rbp-92]                   ; &recLen
    call    hfs_get_rec_bounds
    mov     rcx, rax
    mov     edx, dword ptr [rbp-92]
    mov     r8d, r12d
    mov     r9d, r13d
    call    hfs_cmp_ext_key
    cmp     eax, -2
    je      hlob_corrupt
    cmp     eax, 0
    jg      hlob_idx_follow
    mov     dword ptr [rbp-88], ebx
    inc     ebx
    jmp     hlob_idx_lp

hlob_idx_follow:
    mov     r8d, dword ptr [rbp-88]
    cmp     r8d, 0
    jl      hlob_corrupt                    ; target < minimum key in index node
    mov     rcx, rsi
    mov     edx, edi
    lea     r9,  [rbp-92]
    call    hfs_get_rec_bounds
    cmp     dword ptr [rbp-92], 16
    jb      hlob_corrupt
    mov     ebx, dword ptr [rax + 12]       ; childNode (BE32)
    bswap   ebx
    test    ebx, ebx
    jz      hlob_corrupt
    jmp     hlob_descend

hlob_leaf:
    mov     dword ptr [rbp-88], -1          ; bestIdx = -1
    xor     ebx, ebx
hlob_lf_lp:
    cmp     ebx, dword ptr [rbp-84]
    jae     hlob_lf_check
    mov     rcx, rsi
    mov     edx, edi
    mov     r8d, ebx
    lea     r9,  [rbp-92]
    call    hfs_get_rec_bounds
    mov     rcx, rax
    mov     edx, dword ptr [rbp-92]
    mov     r8d, r12d
    mov     r9d, r13d
    call    hfs_cmp_ext_key
    cmp     eax, -2
    je      hlob_corrupt
    cmp     eax, 0
    jg      hlob_lf_check
    mov     dword ptr [rbp-88], ebx
    inc     ebx
    jmp     hlob_lf_lp

hlob_lf_check:
    mov     r8d, dword ptr [rbp-88]
    cmp     r8d, 0
    jl      hlob_corrupt
    mov     rcx, rsi
    mov     edx, edi
    lea     r9,  [rbp-92]
    call    hfs_get_rec_bounds
    cmp     dword ptr [rbp-92], 76          ; 12B key + 64B (8 extents)
    jb      hlob_corrupt

    ; Verify matched key has exact fileID and forkType == 0
    mov     ecx, dword ptr [rax + 4]
    bswap   ecx
    cmp     ecx, r12d
    jne     hlob_corrupt
    cmp     byte ptr [rax + 2], 0
    jne     hlob_corrupt

    mov     ecx, dword ptr [rax + 8]        ; recStartBlk (BE32)
    bswap   ecx

    ; Scan the 8 extents at [rax + 12]
    xor     edx, edx                        ; extIdx = 0..7
hlob_ext_lp:
    cmp     edx, 8
    jae     hlob_corrupt
    mov     r8d, dword ptr [rax + 12 + rdx*8]       ; physStart (BE32)
    bswap   r8d
    mov     r9d, dword ptr [rax + 12 + rdx*8 + 4]   ; blkCnt (BE32)
    bswap   r9d
    test    r9d, r9d
    jz      hlob_corrupt

    cmp     r13d, ecx
    jb      hlob_corrupt
    mov     r10d, ecx
    add     r10d, r9d
    jc      hlob_corrupt
    cmp     r13d, r10d
    jb      hlob_found

    mov     ecx, r10d
    inc     edx
    jmp     hlob_ext_lp

hlob_found:
    ; offsetInExt = r13d - ecx
    mov     eax, r13d
    sub     eax, ecx
    add     r8,  rax                        ; physBlk = physStart + offsetInExt
    sub     r9d, eax                        ; availBlks = blkCnt - offsetInExt
    mov     rcx, qword ptr [rbp-72]
    mov     qword ptr [rcx], r8
    mov     rcx, qword ptr [rbp-80]
    mov     qword ptr [rcx], r9
    xor     eax, eax
    jmp     hlob_out

hlob_corrupt:
    mov     eax, EXIT_CORRUPT

hlob_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
hfs_lookup_overflow_blk endp

; =============================================================================
; hfs_fork_read(rcx = exts8LePtr, edx = cnidForOverflow, r8 = byteOff,
;               r9 = dstBuf, [rbp+48] = byteLen) -> eax = EXIT_*
; Reads byteLen bytes at byteOff across 8 host-LE inline extents (and, if
; cnidForOverflow != 0, continuation records in the Extents Overflow B-Tree).
; =============================================================================
hfs_fork_read proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; exts8LePtr
    mov     r12d, edx                       ; cnidForOverflow
    mov     r13, r8                         ; curByteOff
    mov     rdi, r9                         ; curDst
    mov     r14, qword ptr [rbp+48]         ; remBytes

hfr_loop:
    test    r14, r14
    jz      hfr_ok

    ; logicalBlk = curByteOff >> bshift, inBlkOff = curByteOff & (bsize - 1)
    mov     rax, r13
    mov     ecx, dword ptr [g_hfs_bshift]
    shr     rax, cl                         ; rax = logicalBlk
    cmp     rax, 0FFFFFFFFh
    ja      hfr_corrupt

    mov     rbx, qword ptr [g_hfs_bsize]
    dec     rbx
    and     rbx, r13                        ; rbx = inBlkOff

    ; Check inline 8 extents first
    xor     ecx, ecx                        ; accumBlks = 0
    xor     edx, edx                        ; i = 0..7
hfr_in_lp:
    cmp     edx, 8
    jae     hfr_overflow
    mov     r8d, dword ptr [rsi + rdx*8]        ; startBlk
    mov     r9d, dword ptr [rsi + rdx*8 + 4]    ; blkCnt
    test    r9d, r9d
    jz      hfr_overflow
    mov     r10, rcx
    add     r10, r9
    cmp     rax, r10
    jb      hfr_in_hit
    mov     rcx, r10
    inc     edx
    jmp     hfr_in_lp

hfr_in_hit:
    sub     rax, rcx                        ; offInExt
    add     r8,  rax                        ; physBlk
    sub     r9,  rax                        ; availBlks
    mov     qword ptr [rbp-72], r8
    mov     qword ptr [rbp-80], r9
    jmp     hfr_do_read

hfr_overflow:
    test    r12d, r12d
    jz      hfr_corrupt
    mov     ecx, r12d
    mov     edx, eax                        ; targetLblk
    lea     r8,  [rbp-72]                   ; &physBlk
    lea     r9,  [rbp-80]                   ; &availBlks
    call    hfs_lookup_overflow_blk
    test    eax, eax
    jnz     hfr_out

hfr_do_read:
    mov     r8,  qword ptr [rbp-72]         ; physBlk
    mov     r9,  qword ptr [rbp-80]         ; availBlks
    test    r9,  r9
    jz      hfr_corrupt

    mov     rax, r8
    add     rax, r9
    jc      hfr_corrupt
    cmp     rax, qword ptr [g_hfs_tot_blks]
    ja      hfr_corrupt

    ; availBytes = availBlks * bsize - inBlkOff
    mov     ecx, dword ptr [g_hfs_bshift]
    shl     r9,  cl
    sub     r9,  rbx
    mov     r15, r14
    cmp     r15, r9
    jbe     hfr_chunk_ok
    mov     r15, r9
hfr_chunk_ok:
    shl     r8,  cl
    add     r8,  rbx
    add     r8,  qword ptr [g_hfs_embed_off]

    mov     rcx, r8
    mov     rdx, rdi
    mov     r8,  r15
    call    tcvc_read_bytes
    test    eax, eax
    jnz     hfr_out

    add     r13, r15
    add     rdi, r15
    sub     r14, r15
    jmp     hfr_loop

hfr_ok:
    xor     eax, eax
    jmp     hfr_out

hfr_corrupt:
    mov     eax, EXIT_CORRUPT

hfr_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
hfs_fork_read endp

; =============================================================================
; hfs_init_btree_hdr(rcx = exts8LePtr, rdx = forkSize, r8 = outHdr16Ptr) -> eax = 0 ok, -1 bad
; Parses Node 0 BTHeaderRec into outHdr16Ptr:
;   [0]=nodeSize, [4]=totalNodes, [8]=rootNode, [12]=treeDepth.
; =============================================================================
hfs_init_btree_hdr proc frame
    FRAME_PROLOG 608
    ; [rbp-16..40] saved rbx, rsi, rdi, r12
    ; [rsp+48..559] 512-byte header node prefix buffer
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12

    mov     rsi, rcx                        ; exts8LePtr
    mov     rbx, rdx                        ; forkSize
    mov     rdi, r8                         ; outHdr16Ptr

    cmp     rbx, 512
    jb      hibh_bad

    mov     rcx, rsi
    xor     edx, edx                        ; Node 0 is always within inline extents
    xor     r8d, r8d
    lea     r9,  [rsp+48]
    mov     qword ptr [rsp+32], 512
    call    hfs_fork_read
    test    eax, eax
    jnz     hibh_bad

    lea     r12, [rsp+48]
    cmp     byte ptr [r12 + 8], HFS_BT_HEADER
    jne     hibh_bad

    movzx   eax, word ptr [r12 + 10]        ; numRecords (BE16)
    rol     ax, 8
    cmp     ax, 1
    jb      hibh_bad

    ; treeDepth (+14, BE16)
    movzx   ecx, word ptr [r12 + 14]
    rol     cx, 8
    movzx   ecx, cx
    cmp     ecx, HFS_MAX_BTREE_DEPTH
    ja      hibh_bad

    ; rootNode (+16, BE32)
    mov     edx, dword ptr [r12 + 16]
    bswap   edx

    ; nodeSize (+32, BE16): power of two in 512..65536
    movzx   r8d, word ptr [r12 + 32]
    rol     r8w, 8
    movzx   r8d, r8w
    cmp     r8d, 512
    jb      hibh_bad
    lea     eax, [r8d - 1]
    test    r8d, eax
    jnz     hibh_bad

    ; totalNodes (+36, BE32)
    mov     r9d, dword ptr [r12 + 36]
    bswap   r9d
    cmp     r9d, 1
    jb      hibh_bad

    ; totalNodes * nodeSize <= forkSize
    mov     rax, r9
    imul    rax, r8
    cmp     rax, rbx
    ja      hibh_bad

    ; If rootNode != 0, require rootNode < totalNodes and treeDepth >= 1
    test    edx, edx
    jz      hibh_store
    cmp     edx, r9d
    jae     hibh_bad
    test    ecx, ecx
    jz      hibh_bad

hibh_store:
    mov     dword ptr [rdi + 0],  r8d       ; nodeSize
    mov     dword ptr [rdi + 4],  r9d       ; totalNodes
    mov     dword ptr [rdi + 8],  edx       ; rootNode
    mov     dword ptr [rdi + 12], ecx       ; treeDepth
    xor     eax, eax
    jmp     hibh_out

hibh_bad:
    mov     eax, -1

hibh_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    mov     r12, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
hfs_init_btree_hdr endp

; =============================================================================
; hfsplus_probe() -> eax: 7 = TCVC_FS_HFSPLUS, 0 = not HFS+, -1 = corrupt HFS+
; =============================================================================
public hfsplus_probe
hfsplus_probe proc frame
    FRAME_PROLOG 624
    ; [rbp-16..48]  saved rbx, rsi, rdi, r12, r13
    ; [rbp-64..-49] btreeHdr16 scratch
    ; [rsp+48..559] 512-byte Volume Header buffer
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12
    mov     qword ptr [rbp-48], r13

    mov     rax, qword ptr [g_tcvc_data_size]
    cmp     rax, 2048
    jb      hp_not_hfs

    mov     qword ptr [g_hfs_embed_off], 0
    mov     qword ptr [g_hfs_part_size], rax
    xor     r13d, r13d                      ; fromWrapper = 0

    mov     ecx, 1024
    lea     rdx, [rsp+48]
    mov     r8d, 512
    call    tcvc_read_bytes
    test    eax, eax
    jnz     hp_not_hfs

    lea     rsi, [rsp+48]
    movzx   eax, word ptr [rsi + 0]
    rol     ax, 8
    cmp     ax, HFS_SIG_BD
    jne     hp_chk_vh

    ; Classic HFS "BD" wrapper -> check embedded HFS+ signature at +124
    movzx   eax, word ptr [rsi + 124]
    rol     ax, 8
    cmp     ax, HFS_SIG_PLUS
    jne     hp_not_hfs                      ; plain old Mac OS Standard HFS, not HFS+

    mov     r13d, 1                         ; matched HFS+ wrapper -> errors now return -1
    mov     ebx, dword ptr [rsi + 20]       ; drAlBlkSiz (BE32)
    bswap   ebx
    cmp     ebx, 512
    jb      hp_corrupt
    test    ebx, 511
    jnz     hp_corrupt

    movzx   ecx, word ptr [rsi + 28]        ; drAlBlSt (BE16)
    rol     cx, 8
    movzx   ecx, cx
    shl     rcx, 9                          ; drAlBlSt * 512

    movzx   edx, word ptr [rsi + 126]       ; embed.startBlock (BE16)
    rol     dx, 8
    movzx   edx, dx
    imul    rdx, rbx
    add     rcx, rdx                        ; embedBaseOff

    movzx   eax, word ptr [rsi + 128]       ; embed.blockCount (BE16)
    rol     ax, 8
    movzx   eax, ax
    test    eax, eax
    jz      hp_corrupt
    imul    rax, rbx                        ; embedPartSize

    mov     rdx, rcx
    add     rdx, rax
    jc      hp_corrupt
    cmp     rdx, qword ptr [g_tcvc_data_size]
    ja      hp_corrupt
    cmp     rax, 2048
    jb      hp_corrupt

    mov     qword ptr [g_hfs_embed_off], rcx
    mov     qword ptr [g_hfs_part_size], rax

    add     rcx, 1024
    lea     rdx, [rsp+48]
    mov     r8d, 512
    call    tcvc_read_bytes
    test    eax, eax
    jnz     hp_corrupt

hp_chk_vh:
    movzx   eax, word ptr [rsi + 0]         ; signature (BE16)
    rol     ax, 8
    movzx   edx, word ptr [rsi + 2]         ; version (BE16)
    rol     dx, 8

    cmp     ax, HFS_SIG_PLUS
    je      hp_chk_v4
    cmp     ax, HFS_SIG_HFSX
    je      hp_chk_v5
    test    r13d, r13d
    jnz     hp_corrupt
    jmp     hp_not_hfs

hp_chk_v4:
    cmp     dx, 4
    jne     hp_corrupt
    jmp     hp_vh_geom

hp_chk_v5:
    cmp     dx, 5
    jne     hp_corrupt

hp_vh_geom:
    ; blockSize (+40, BE32): power of two in 512..1048576
    mov     ebx, dword ptr [rsi + 40]
    bswap   ebx
    cmp     ebx, 512
    jb      hp_corrupt
    cmp     ebx, 100000h
    ja      hp_corrupt
    lea     eax, [ebx - 1]
    test    ebx, eax
    jnz     hp_corrupt
    mov     qword ptr [g_hfs_bsize], rbx
    bsf     eax, ebx
    mov     dword ptr [g_hfs_bshift], eax

    ; totalBlocks (+44, BE32)
    mov     edi, dword ptr [rsi + 44]
    bswap   edi
    test    edi, edi
    jz      hp_corrupt
    mov     qword ptr [g_hfs_tot_blks], rdi

    mov     rax, rdi
    imul    rax, rbx
    cmp     rax, qword ptr [g_hfs_part_size]
    ja      hp_corrupt

    ; Parse extentsFile (+192)
    mov     rax, qword ptr [rsi + 192]
    bswap   rax
    cmp     rax, qword ptr [g_hfs_part_size]
    ja      hp_corrupt
    mov     qword ptr [g_hfs_ext_size], rax

    lea     rcx, [rsi + 192 + 16]
    lea     rdx, [g_hfs_ext_exts]
    call    hfs_unpack_extents8

    mov     dword ptr [g_hfs_ext_nsize], 0
    mov     dword ptr [g_hfs_ext_totn],  0
    mov     dword ptr [g_hfs_ext_root],  0
    mov     dword ptr [g_hfs_ext_depth], 0

    cmp     qword ptr [g_hfs_ext_size], 0
    je      hp_parse_cat

    lea     rcx, [g_hfs_ext_exts]
    mov     rdx, qword ptr [g_hfs_ext_size]
    lea     r8,  [rbp-64]
    call    hfs_init_btree_hdr
    test    eax, eax
    jnz     hp_corrupt
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [g_hfs_ext_nsize], eax
    mov     eax, dword ptr [rbp-60]
    mov     dword ptr [g_hfs_ext_totn],  eax
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [g_hfs_ext_root],  eax
    mov     eax, dword ptr [rbp-52]
    mov     dword ptr [g_hfs_ext_depth], eax

hp_parse_cat:
    ; Parse catalogFile (+272)
    mov     rax, qword ptr [rsi + 272]
    bswap   rax
    cmp     rax, 512
    jb      hp_corrupt
    cmp     rax, qword ptr [g_hfs_part_size]
    ja      hp_corrupt
    mov     qword ptr [g_hfs_cat_size], rax

    lea     rcx, [rsi + 272 + 16]
    lea     rdx, [g_hfs_cat_exts]
    call    hfs_unpack_extents8

    lea     rcx, [g_hfs_cat_exts]
    mov     rdx, qword ptr [g_hfs_cat_size]
    lea     r8,  [rbp-64]
    call    hfs_init_btree_hdr
    test    eax, eax
    jnz     hp_corrupt
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [g_hfs_cat_nsize], eax
    mov     eax, dword ptr [rbp-60]
    mov     dword ptr [g_hfs_cat_totn],  eax
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [g_hfs_cat_root],  eax
    mov     eax, dword ptr [rbp-52]
    mov     dword ptr [g_hfs_cat_depth], eax

    mov     eax, TCVC_FS_HFSPLUS
    jmp     hp_out

hp_not_hfs:
    xor     eax, eax
    jmp     hp_out

hp_corrupt:
    mov     eax, -1

hp_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    mov     r12, qword ptr [rbp-40]
    mov     r13, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
hfsplus_probe endp

; =============================================================================
; hfs_read_cat_node(ecx = nodeNum, rdx = dstNodeBuf) -> eax = EXIT_*
; Reads and validates one Catalog B-Tree node.
; =============================================================================
hfs_read_cat_node proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi

    cmp     ecx, dword ptr [g_hfs_cat_totn]
    jae     hrcn_corrupt

    mov     rsi, rdx                        ; dstNodeBuf
    mov     ebx, dword ptr [g_hfs_cat_nsize]
    mov     eax, ecx
    imul    rax, rbx                        ; byteOff

    lea     rcx, [g_hfs_cat_exts]
    mov     edx, HFS_CNID_CATALOG
    mov     r8,  rax
    mov     r9,  rsi
    mov     qword ptr [rsp+32], rbx
    call    hfs_fork_read
    test    eax, eax
    jnz     hrcn_out

    mov     rcx, rsi
    mov     edx, ebx
    call    hfs_validate_node
    test    eax, eax
    jnz     hrcn_corrupt

    xor     eax, eax
    jmp     hrcn_out

hrcn_corrupt:
    mov     eax, EXIT_CORRUPT

hrcn_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
hfs_read_cat_node endp

; =============================================================================
; hfs_is_root_meta(rcx = beUtf16Ptr, edx = u16Len) -> eax = 1 skip, 0 keep
; Skips macOS HFS+ internal root metadata:
;   - "\0\0\0\0HFS+ Private Data" (starts with U+0000)
;   - ".journal" (8 chars)
;   - ".journal_info_block" (19 chars)
;   - ".HFS+ Private Directory Data\r" (29 chars, prefix ".HFS+ Private ")
; =============================================================================
hfs_is_root_meta proc
    test    edx, edx
    jz      hirm_no
    cmp     word ptr [rcx], 0               ; "\0\0\0\0HFS+ Private Data"
    je      hirm_yes

    ; Check ".journal" (len 8) or ".journal_info_block" (len 19)
    cmp     word ptr [rcx], 2E00h           ; '.' in UTF-16BE is 00 2E -> LE word 2E00h
    jne     hirm_no

    cmp     edx, 8
    je      hirm_chk_j
    cmp     edx, 19
    je      hirm_chk_jib
    cmp     edx, 29
    je      hirm_chk_pdd
    jmp     hirm_no

hirm_chk_j:
    cmp     word ptr [rcx + 2],  6A00h      ; 'j'
    jne     hirm_no
    cmp     word ptr [rcx + 4],  6F00h      ; 'o'
    jne     hirm_no
    cmp     word ptr [rcx + 6],  7500h      ; 'u'
    jne     hirm_no
    cmp     word ptr [rcx + 8],  7200h      ; 'r'
    jne     hirm_no
    cmp     word ptr [rcx + 10], 6E00h      ; 'n'
    jne     hirm_no
    cmp     word ptr [rcx + 12], 6100h      ; 'a'
    jne     hirm_no
    cmp     word ptr [rcx + 14], 6C00h      ; 'l'
    jne     hirm_no
    jmp     hirm_yes

hirm_chk_jib:
    cmp     word ptr [rcx + 2],  6A00h      ; 'j'
    jne     hirm_no
    cmp     word ptr [rcx + 14], 6C00h      ; 'l'
    jne     hirm_no
    cmp     word ptr [rcx + 16], 5F00h      ; '_'
    jne     hirm_no
    cmp     word ptr [rcx + 18], 6900h      ; 'i'
    jne     hirm_no
    cmp     word ptr [rcx + 36], 6B00h      ; 'k'
    jne     hirm_no
    jmp     hirm_yes

hirm_chk_pdd:
    cmp     word ptr [rcx + 2],  4800h      ; 'H'
    jne     hirm_no
    cmp     word ptr [rcx + 4],  4600h      ; 'F'
    jne     hirm_no
    cmp     word ptr [rcx + 6],  5300h      ; 'S'
    jne     hirm_no
    cmp     word ptr [rcx + 8],  2B00h      ; '+'
    jne     hirm_no
    cmp     word ptr [rcx + 56], 0D00h      ; '\r'
    jne     hirm_no

hirm_yes:
    mov     eax, 1
    ret
hirm_no:
    xor     eax, eax
    ret
hfs_is_root_meta endp

; =============================================================================
; hfs_decode_name(rcx = beUtf16Ptr, edx = u16Len) -> eax = utf8Len in g_hfs_comp8
; Byte-swaps UTF-16BE -> UTF-16LE, normalizes NFD -> NFC via FoldStringW, maps
; Finder ':'/'/'/'\' inside leaf names to '_', and encodes strict UTF-8.
; =============================================================================
hfs_decode_name proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi

    test    edx, edx
    jz      hdn_bad
    cmp     edx, 255
    ja      hdn_bad

    mov     ebx, edx                        ; u16Len
    lea     rdi, [g_hfs_name_w1]
    xor     r8d, r8d
hdn_swp:
    movzx   eax, word ptr [rcx + r8*2]
    rol     ax, 8
    test    ax, ax
    jz      hdn_bad                         ; embedded NUL rejected
    cmp     ax, ':'
    je      hdn_repl
    cmp     ax, '/'
    je      hdn_repl
    cmp     ax, '\'
    je      hdn_repl
    jmp     hdn_store_w
hdn_repl:
    mov     ax, '_'
hdn_store_w:
    mov     word ptr [rdi + r8*2], ax
    inc     r8d
    cmp     r8d, ebx
    jb      hdn_swp

    ; Precompose macOS NFD -> Windows NFC
    WINCALL FoldStringW, HFS_MAP_PRECOMPOSED, addr g_hfs_name_w1, ebx, addr g_hfs_name_w2, 512
    test    eax, eax
    jz      hdn_use_raw
    lea     rsi, [g_hfs_name_w2]
    mov     ebx, eax
    jmp     hdn_to_utf8

hdn_use_raw:
    lea     rsi, [g_hfs_name_w1]

hdn_to_utf8:
    WINCALL WideCharToMultiByte, HFS_CP_UTF8, 0, rsi, ebx, addr g_hfs_comp8, 1020, 0, 0
    test    eax, eax
    jz      hdn_bad

    ; Reject "." and ".."
    lea     rcx, [g_hfs_comp8]
    cmp     eax, 1
    jne     hdn_dot2
    cmp     byte ptr [rcx], '.'
    je      hdn_bad
hdn_dot2:
    cmp     eax, 2
    jne     hdn_done
    cmp     word ptr [rcx], 2E2Eh
    je      hdn_bad

hdn_done:
    mov     byte ptr [rcx + rax], 0
    jmp     hdn_out

hdn_bad:
    xor     eax, eax

hdn_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
hfs_decode_name endp

; =============================================================================
; hfs_mark_dir_visited(ecx = cnid, edx = depth) -> eax = EXIT_*
; Checks active ancestor stack [0..depth-1] for folder cycles, records cnid at
; g_hfs_anc_cnid[depth], and bounds total folders visited.
; =============================================================================
hfs_mark_dir_visited proc
    lea     r8,  [g_hfs_anc_cnid]
    xor     eax, eax
hmdv_lp:
    cmp     eax, edx
    jae     hmdv_anc_ok
    cmp     dword ptr [r8 + rax*4], ecx
    je      hmdv_cycle
    inc     eax
    jmp     hmdv_lp
hmdv_anc_ok:
    mov     eax, dword ptr [g_hfs_vis_cnt]
    cmp     eax, HFS_MAX_DIRS
    jae     hmdv_oom
    inc     eax
    mov     dword ptr [g_hfs_vis_cnt], eax
    mov     eax, edx
    mov     dword ptr [r8 + rax*4], ecx
    xor     eax, eax
    ret
hmdv_cycle:
    mov     eax, EXIT_CORRUPT
    ret
hmdv_oom:
    mov     eax, EXIT_OOM
    ret
hfs_mark_dir_visited endp

; =============================================================================
; hfs_walk_dir(ecx = folderCNID, edx = prefixLen, r8d = depth) -> eax = EXIT_*
; =============================================================================
hfs_walk_dir proc frame
    FRAME_PROLOG 192
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-72]       nodeHeap (dq)
    ; [rbp-80]       folderCNID (dd), prefixLen (dd at -76)
    ; [rbp-88]       depth (dd), curNode (dd at -84)
    ; [rbp-96]       numRecords (dd), recIdx (dd at -92)
    ; [rbp-104]      leafSteps (dd), recLen (dd at -100)
    ; [rbp-112]      fullLen (dd), childCNID (dd at -108)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     qword ptr [rbp-72], 0

    cmp     r8d, HFS_MAX_DEPTH
    ja      hwd_corrupt

    mov     dword ptr [rbp-80], ecx         ; folderCNID
    mov     dword ptr [rbp-76], edx         ; prefixLen
    mov     dword ptr [rbp-88], r8d         ; depth

    mov     edx, r8d
    call    hfs_mark_dir_visited
    test    eax, eax
    jnz     hwd_cleanup

    mov     ebx, dword ptr [g_hfs_cat_root]
    test    ebx, ebx
    jz      hwd_ok                          ; empty Catalog B-Tree

    mov     ecx, dword ptr [g_hfs_cat_nsize]
    call    mem_alloc
    test    rax, rax
    jz      hwd_oom
    mov     qword ptr [rbp-72], rax
    mov     rsi, rax                        ; nodeHeap

    ; ---- Descend Catalog B-Tree index nodes to first leaf for folderCNID ----
    mov     edi, dword ptr [g_hfs_cat_nsize]
    mov     r14d, dword ptr [g_hfs_cat_depth]
    inc     r14d
    mov     r15d, 0FFh                      ; prevHeight

hwd_descend:
    test    r14d, r14d
    jz      hwd_corrupt
    dec     r14d

    mov     ecx, ebx
    mov     rdx, rsi
    call    hfs_read_cat_node
    test    eax, eax
    jnz     hwd_cleanup

    movzx   eax, byte ptr [rsi + 9]         ; height
    cmp     eax, r15d
    jae     hwd_corrupt
    mov     r15d, eax

    movsx   eax, byte ptr [rsi + 8]         ; kind
    cmp     eax, HFS_BT_LEAF
    je      hwd_at_leaf
    cmp     eax, HFS_BT_INDEX
    jne     hwd_corrupt

    movzx   r12d, word ptr [rsi + 10]
    rol     r12w, 8
    movzx   r12d, r12w                      ; numRecords
    test    r12d, r12d
    jz      hwd_corrupt

    xor     r13d, r13d                      ; bestIdx = 0
    xor     ebx, ebx                        ; i = 0
hwd_idx_lp:
    cmp     ebx, r12d
    jae     hwd_idx_follow
    mov     rcx, rsi
    mov     edx, edi
    mov     r8d, ebx
    lea     r9,  [rbp-100]                  ; &recLen
    call    hfs_get_rec_bounds
    cmp     dword ptr [rbp-100], 10         ; min 6B key + 4B childNode
    jb      hwd_corrupt
    movzx   ecx, word ptr [rax]
    rol     cx, 8
    cmp     cx, 6
    jb      hwd_corrupt
    mov     edx, dword ptr [rax + 2]        ; recParentID (BE32)
    bswap   edx
    cmp     edx, dword ptr [rbp-80]
    jae     hwd_idx_follow
    mov     r13d, ebx
    inc     ebx
    jmp     hwd_idx_lp

hwd_idx_follow:
    mov     rcx, rsi
    mov     edx, edi
    mov     r8d, r13d
    lea     r9,  [rbp-100]
    call    hfs_get_rec_bounds
    movzx   ecx, word ptr [rax]
    rol     cx, 8
    movzx   ecx, cx
    add     ecx, 3
    and     ecx, 0FFFFFFFEh                 ; even-aligned dataOff
    lea     edx, [ecx + 4]
    cmp     edx, dword ptr [rbp-100]
    ja      hwd_corrupt
    mov     ebx, dword ptr [rax + rcx]      ; childNode (BE32)
    bswap   ebx
    test    ebx, ebx
    jz      hwd_corrupt
    jmp     hwd_descend

    ; ---- Scan leaf chain while recParentID <= folderCNID --------------------
hwd_at_leaf:
    mov     dword ptr [rbp-84], ebx         ; curNode
    mov     dword ptr [rbp-104], 0          ; leafSteps = 0

hwd_leaf_loop:
    movzx   eax, word ptr [rsi + 10]
    rol     ax, 8
    movzx   eax, ax
    mov     dword ptr [rbp-96], eax         ; numRecords
    mov     dword ptr [rbp-92], 0           ; recIdx = 0

hwd_rec_loop:
    mov     r8d, dword ptr [rbp-92]
    cmp     r8d, dword ptr [rbp-96]
    jae     hwd_next_leaf

    mov     rcx, rsi
    mov     edx, edi
    lea     r9,  [rbp-100]
    call    hfs_get_rec_bounds
    mov     r12, rax                        ; recPtr
    mov     r13d, dword ptr [rbp-100]       ; recLen
    cmp     r13d, 10
    jb      hwd_corrupt

    movzx   eax, word ptr [r12]             ; keyLength (BE16)
    rol     ax, 8
    movzx   eax, ax
    cmp     eax, 6
    jb      hwd_corrupt

    mov     ecx, dword ptr [r12 + 2]        ; recParentID (BE32)
    bswap   ecx
    cmp     ecx, dword ptr [rbp-80]
    jb      hwd_rec_adv
    ja      hwd_ok                          ; passed all children of folderCNID!

    movzx   ebx, word ptr [r12 + 6]         ; nodeName.length (BE16)
    rol     bx, 8
    movzx   ebx, bx
    lea     edx, [ebx*2 + 6]
    cmp     edx, eax
    ja      hwd_corrupt

    lea     r14d, [eax + 3]
    and     r14d, 0FFFFFFFEh                ; dataOff
    lea     edx, [r14d + 2]
    cmp     edx, r13d
    ja      hwd_corrupt

    lea     r15, [r12 + r14]                ; recDataPtr
    movzx   eax, word ptr [r15]             ; recordType (BE16)
    rol     ax, 8
    movzx   eax, ax

    cmp     eax, HFS_REC_FOLDER_THD
    je      hwd_rec_adv
    cmp     eax, HFS_REC_FILE_THD
    je      hwd_rec_adv
    cmp     eax, HFS_REC_FOLDER
    je      hwd_chk_name
    cmp     eax, HFS_REC_FILE
    je      hwd_chk_name
    jmp     hwd_corrupt

hwd_chk_name:
    mov     r14d, eax                       ; save recordType (1 or 2)
    cmp     dword ptr [rbp-80], HFS_CNID_ROOT_DIR
    jne     hwd_do_decode
    lea     rcx, [r12 + 8]
    mov     edx, ebx
    call    hfs_is_root_meta
    test    eax, eax
    jnz     hwd_rec_adv

hwd_do_decode:
    lea     rcx, [r12 + 8]
    mov     edx, ebx
    call    hfs_decode_name
    test    eax, eax
    jz      hwd_corrupt
    mov     ebx, eax                        ; compLen

    mov     ecx, dword ptr [rbp-76]         ; prefixLen
    lea     eax, [ecx + ebx]
    cmp     eax, ENTRY_NAME_MAX
    ja      hwd_corrupt
    mov     dword ptr [rbp-112], eax        ; fullLen

    lea     rdx, [g_hfs_path]
    add     rdx, rcx
    lea     r8,  [g_hfs_comp8]
    xor     ecx, ecx
hwd_cp_nm:
    mov     al, byte ptr [r8 + rcx]
    mov     byte ptr [rdx + rcx], al
    inc     ecx
    cmp     ecx, ebx
    jb      hwd_cp_nm

    cmp     r14d, HFS_REC_FOLDER
    je      hwd_rec_folder

    ; ---- Regular file record (248 bytes) ------------------------------------
    mov     rax, r15
    sub     rax, r12                        ; dataOff
    add     eax, 248
    cmp     eax, r13d
    ja      hwd_corrupt

    ; Skip symlinks / special POSIX nodes
    mov     eax, dword ptr [r15 + 56]       ; userInfo.fdType (BE32)
    bswap   eax
    cmp     eax, HFS_FDTYPE_SLNK
    je      hwd_rec_adv

    movzx   eax, word ptr [r15 + 48]        ; bsdInfo.fileMode (BE16)
    rol     ax, 8
    test    ax, ax
    jz      hwd_file_sz
    and     eax, HFS_S_IFMT
    cmp     eax, HFS_S_IFREG
    jne     hwd_rec_adv

hwd_file_sz:
    mov     ecx, dword ptr [r15 + 8]        ; fileID (BE32)
    bswap   ecx
    mov     dword ptr [rbp-108], ecx

    mov     r8,  qword ptr [r15 + 88]       ; dataFork.logicalSize (BE64)
    bswap   r8
    cmp     r8,  qword ptr [g_hfs_part_size]
    ja      hwd_corrupt

    mov     eax, dword ptr [r15 + 100]      ; dataFork.totalBlocks (BE32)
    bswap   eax
    mov     ecx, dword ptr [g_hfs_bshift]
    shl     rax, cl
    cmp     rax, r8
    jb      hwd_corrupt                     ; allocated blocks must cover logicalSize

    lea     rcx, [g_hfs_path]
    mov     edx, dword ptr [rbp-112]
    xor     r9d, r9d
    mov     eax, dword ptr [rbp-84]         ; meta0 = curNode
    mov     qword ptr [rsp+32], rax
    mov     eax, dword ptr [rbp-92]         ; meta1 = recIdx
    mov     qword ptr [rsp+40], rax
    mov     eax, dword ptr [rbp-108]        ; meta2 = fileID
    mov     qword ptr [rsp+48], rax
    call    tcvc_idx_add
    test    eax, eax
    jnz     hwd_cleanup
    jmp     hwd_rec_adv

hwd_rec_folder:
    mov     rax, r15
    sub     rax, r12
    add     eax, 88
    cmp     eax, r13d
    ja      hwd_corrupt

    mov     ecx, dword ptr [r15 + 8]        ; folderID (BE32)
    bswap   ecx
    cmp     ecx, 3
    jb      hwd_corrupt
    mov     dword ptr [rbp-108], ecx

    lea     rcx, [g_hfs_path]
    mov     edx, dword ptr [rbp-112]
    xor     r8d, r8d
    mov     r9d, IDXEF_DIR
    mov     eax, dword ptr [rbp-108]
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_add
    test    eax, eax
    jnz     hwd_cleanup

    mov     ecx, dword ptr [rbp-112]
    lea     eax, [ecx + 1]
    cmp     eax, ENTRY_NAME_MAX
    ja      hwd_corrupt
    lea     rdx, [g_hfs_path]
    mov     byte ptr [rdx + rcx], '/'

    mov     ecx, dword ptr [rbp-108]
    mov     edx, eax                        ; newPrefixLen
    mov     r8d, dword ptr [rbp-88]
    inc     r8d                             ; depth + 1
    call    hfs_walk_dir
    test    eax, eax
    jnz     hwd_cleanup

hwd_rec_adv:
    inc     dword ptr [rbp-92]
    jmp     hwd_rec_loop

hwd_next_leaf:
    mov     ebx, dword ptr [rsi + 0]        ; fLink (BE32)
    bswap   ebx
    test    ebx, ebx
    jz      hwd_ok

    inc     dword ptr [rbp-104]
    mov     eax, dword ptr [rbp-104]
    cmp     eax, dword ptr [g_hfs_cat_totn]
    jae     hwd_corrupt                     ; fLink cycle guard

    mov     ecx, ebx
    mov     rdx, rsi
    call    hfs_read_cat_node
    test    eax, eax
    jnz     hwd_cleanup
    cmp     byte ptr [rsi + 8], 0FFh        ; must still be kBTLeafNode
    jne     hwd_corrupt
    mov     dword ptr [rbp-84], ebx
    jmp     hwd_leaf_loop

hwd_ok:
    xor     eax, eax
    jmp     hwd_cleanup

hwd_oom:
    mov     eax, EXIT_OOM
    jmp     hwd_cleanup

hwd_corrupt:
    mov     eax, EXIT_CORRUPT

hwd_cleanup:
    mov     ebx, eax
    mov     rcx, qword ptr [rbp-72]
    test    rcx, rcx
    jz      hwd_out
    mov     edx, dword ptr [g_hfs_cat_nsize]
    call    mem_free
hwd_out:
    mov     eax, ebx
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
hfs_walk_dir endp

; =============================================================================
; hfsplus_enum() -> eax = EXIT_*
; =============================================================================
public hfsplus_enum
hfsplus_enum proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_hfs_vis_cnt], 0
    mov     ecx, HFS_CNID_ROOT_DIR
    xor     edx, edx
    xor     r8d, r8d
    call    hfs_walk_dir
    FRAME_EPILOG
    ret
hfsplus_enum endp

; =============================================================================
; hfsplus_extract_entry(rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================
public hfsplus_extract_entry
hfsplus_extract_entry proc frame
    FRAME_PROLOG 176
    ; [rbp-16..48]    saved r12..r15, rbx
    ; [rbp-56]        recLen (dd)
    ; [rbp-128..-65]  inlineExts8Le (64 bytes = 16 dwords)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx

    mov     r12, qword ptr [rcx + IDXE_size]        ; remBytes
    mov     r13d, dword ptr [rcx + IDXE_offset]     ; leafNodeNum
    mov     r14d, dword ptr [rcx + IDXE_stored]     ; recIdx
    mov     r15d, dword ptr [rcx + IDXE_ordinal]    ; expected fileID

    test    r12, r12
    jz      hee_ok

    ; Re-read leaf node and verify record
    mov     ecx, r13d
    lea     rdx, [g_hfs_leaf_buf]
    call    hfs_read_cat_node
    test    eax, eax
    jnz     hee_out

    lea     rcx, [g_hfs_leaf_buf]
    cmp     byte ptr [rcx + 8], 0FFh
    jne     hee_corrupt

    movzx   eax, word ptr [rcx + 10]
    rol     ax, 8
    movzx   eax, ax
    cmp     r14d, eax
    jae     hee_corrupt

    mov     edx, dword ptr [g_hfs_cat_nsize]
    mov     r8d, r14d
    lea     r9,  [rbp-56]
    call    hfs_get_rec_bounds
    mov     ebx, dword ptr [rbp-56]         ; recLen
    cmp     ebx, 256
    jb      hee_corrupt

    movzx   ecx, word ptr [rax]             ; keyLen
    rol     cx, 8
    movzx   ecx, cx
    add     ecx, 3
    and     ecx, 0FFFFFFFEh                 ; dataOff
    lea     edx, [ecx + 248]
    cmp     edx, ebx
    ja      hee_corrupt

    add     rax, rcx                        ; recDataPtr
    movzx   ecx, word ptr [rax]
    rol     cx, 8
    cmp     cx, HFS_REC_FILE
    jne     hee_corrupt

    mov     ecx, dword ptr [rax + 8]        ; fileID (BE32)
    bswap   ecx
    cmp     ecx, r15d
    jne     hee_corrupt

    ; Unpack 8 inline dataFork extents at [rax + 88 + 16 = rax + 104]
    lea     rcx, [rax + 104]
    lea     rdx, [rbp-128]
    call    hfs_unpack_extents8

    xor     r13d, r13d                      ; curByteOff = 0
hee_stream:
    test    r12, r12
    jz      hee_ok

    mov     ebx, 65536
    cmp     r12, rbx
    jae     hee_rd
    mov     ebx, r12d
hee_rd:
    lea     rcx, [rbp-128]
    mov     edx, r15d                       ; fileID for Extents Overflow B-Tree
    mov     r8,  r13
    lea     r9,  [g_hfs_iobuf]
    mov     qword ptr [rsp+32], rbx
    call    hfs_fork_read
    test    eax, eax
    jnz     hee_clean

    lea     rcx, [g_hfs_iobuf]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     hee_clean

    add     r13, rbx
    sub     r12, rbx
    jmp     hee_stream

hee_ok:
    xor     eax, eax

hee_clean:
    mov     ebx, eax
    lea     rcx, [g_hfs_iobuf]
    mov     edx, 65536
    call    secure_zero
    mov     eax, ebx
    jmp     hee_out

hee_corrupt:
    mov     eax, EXIT_CORRUPT

hee_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
hfsplus_extract_entry endp

end
