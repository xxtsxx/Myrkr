; =============================================================================
; fs_ntfs.asm - Read-Only NTFS Filesystem Parser
; -----------------------------------------------------------------------------
; Validates the "NTFS    " $Boot sector, applies USA multi-sector fixups on all
; FILE and INDX records, bootstraps $MFT runlists, traverses $INDEX_ROOT +
; $INDEX_ALLOCATION ($I30) directory B-trees from root MFT record 5 (resolving
; $ATTRIBUTE_LIST extension records and preferring Win32/POSIX names over DOS
; 8.3 aliases), and streams resident, non-resident, sparse, and LZNT1-compressed
; unnamed $DATA attributes.
;
; Exports:
;   ntfs_probe         () -> eax: 5 (TCVC_FS_NTFS), 0 = not NTFS, -1 = corrupt
;   ntfs_enum          () -> eax = EXIT_*
;   ntfs_extract_entry (rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================

include macros.inc

extern tcvc_read_bytes:proc
extern tcvc_idx_add:proc
extern tcvc_is_sys_root:proc
extern tcvc_sink_write:proc
extern secure_zero:proc
extern mem_alloc:proc
extern mem_free:proc
extern WideCharToMultiByte:proc

externdef g_tcvc_data_size:qword

NTF_CP_UTF8             equ 65001

NTF_MAGIC_FILE          equ 454C4946h   ; "FILE"
NTF_MAGIC_INDX          equ 58444E49h   ; "INDX"

NTF_AT_ATTR_LIST        equ 20h
NTF_AT_FILE_NAME        equ 30h
NTF_AT_DATA             equ 80h
NTF_AT_INDEX_ROOT       equ 90h
NTF_AT_INDEX_ALLOC      equ 0A0h
NTF_AT_REPARSE          equ 0C0h
NTF_AT_END              equ 0FFFFFFFFh

NTF_MFT_IN_USE          equ 01h
NTF_MFT_IS_DIR          equ 02h

NTF_AF_COMPRESSED       equ 0001h
NTF_AF_ENCRYPTED        equ 4000h

NTF_FN_NS_DOS           equ 02h
NTF_DUP_REPARSE         equ 0400h

NTF_IE_SUBNODE          equ 01h
NTF_IE_END              equ 02h

NTF_MAX_DEPTH           equ 64
NTF_MAX_BTREE_DEPTH     equ 32
NTF_MAX_DIRS            equ 262144
NTF_MAX_MFT_RUNS        equ 4096
NTF_MAX_DATA_RUNS       equ 4096
NTF_MAX_EXT_RECS        equ 128
NTF_MAX_FSIZE           equ 00007FFFFFFFFFFFh
NTF_MAX_RUN_CLUSTERS    equ 000000FFFFFFFFFFh

; Each run entry is 16 bytes: { dq vcn_len, dq lcn (-1 = sparse) }
NTF_RUN_STRIDE          equ 16
NTF_IA_HEAP_BYTES       equ (NTF_MAX_DATA_RUNS * NTF_RUN_STRIDE)

.data?
align 8
g_ntf_bps               dq ?
g_ntf_cbytes            dq ?
g_ntf_tot_clus          dq ?
g_ntf_mft_bytes         dq ?
g_ntf_idx_bytes         dq ?

g_ntf_mft_runcnt        dd ?
g_ntf_vis_cnt           dd ?

align 8
g_ntf_anc_mft           dq (NTF_MAX_DEPTH + 2) dup (?)
g_ntf_mft_runs          dq (NTF_MAX_MFT_RUNS * 2) dup (?)
g_ntf_data_runs         dq (NTF_MAX_DATA_RUNS * 2) dup (?)

align 16
g_ntf_rec_main          db 4096 dup (?)
g_ntf_rec_child         db 4096 dup (?)
g_ntf_rec_ext           db 4096 dup (?)
g_ntf_alist_buf         db 262144 dup (?)
g_ntf_path              db 4096 dup (?)
g_ntf_comp8             db 1024 dup (?)
g_ntf_iobuf             db 65536 dup (?)
g_ntf_zbuf              db 65536 dup (?)

.code

; =============================================================================
; ntfs_apply_usa(rcx = buf, edx = byteLen, r8d = expectedMagic) -> eax = 0 ok, -1 bad
; Validates magic and USA multi-sector fixup array (512-byte USA stride).
; =============================================================================
ntfs_apply_usa proc
    cmp     edx, 512
    jb      nau_bad
    test    edx, 511
    jnz     nau_bad

    cmp     dword ptr [rcx], r8d
    jne     nau_bad

    movzx   r9d, word ptr [rcx+4]           ; usa_ofs
    movzx   r10d, word ptr [rcx+6]          ; usa_cnt
    cmp     r9d, 24
    jb      nau_bad
    test    r9d, 1
    jnz     nau_bad

    ; Expected usa_cnt == (byteLen >> 9) + 1
    mov     eax, edx
    shr     eax, 9
    inc     eax
    cmp     r10d, eax
    jne     nau_bad

    lea     eax, [r9d + r10d*2]
    cmp     eax, edx
    ja      nau_bad

    movzx   r11d, word ptr [rcx + r9]       ; usn
    mov     eax, 1
nau_lp:
    cmp     eax, r10d
    jae     nau_ok
    mov     r8d, eax
    shl     r8d, 9                          ; i * 512
    cmp     word ptr [rcx + r8 - 2], r11w
    jne     nau_bad
    lea     edx, [r9d + eax*2]
    movzx   edx, word ptr [rcx + rdx]
    mov     word ptr [rcx + r8 - 2], dx
    inc     eax
    jmp     nau_lp

nau_ok:
    xor     eax, eax
    ret
nau_bad:
    mov     eax, -1
    ret
ntfs_apply_usa endp

; =============================================================================
; ntfs_decode_runs(rcx = runPtr, edx = maxBytes, r8 = outRuns, r9d = maxRuns)
;   -> eax = runCount (>= 0), or -1 on corruption
; Appends { vcn_len: dq, lcn: dq (-1 = sparse) } entries to outRuns.
; =============================================================================
ntfs_decode_runs proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12
    mov     qword ptr [rbp-48], r13

    mov     rsi, rcx                        ; cur
    lea     r12, [rcx + rdx]                ; end
    mov     rdi, r8                         ; outRuns
    mov     r13d, r9d                       ; maxRuns
    xor     ebx, ebx                        ; count
    xor     r10, r10                        ; prev_lcn = 0

ndr_loop:
    cmp     rsi, r12
    jae     ndr_bad                         ; missing 0x00 terminator
    movzx   eax, byte ptr [rsi]
    inc     rsi
    test    eax, eax
    jz      ndr_done

    mov     ecx, eax
    and     ecx, 0Fh                        ; len_sz (1..8)
    jz      ndr_bad
    cmp     ecx, 8
    ja      ndr_bad

    shr     eax, 4                          ; off_sz (0..8)
    cmp     eax, 8
    ja      ndr_bad

    lea     rdx, [rsi + rcx]
    add     rdx, rax
    cmp     rdx, r12
    ja      ndr_bad

    cmp     ebx, r13d
    jae     ndr_bad

    ; Read unsigned run_len (len_sz bytes LE)
    xor     r8, r8
    xor     edx, edx
ndr_len_lp:
    movzx   r9d, byte ptr [rsi + rdx]
    mov     dword ptr [rbp-56], ecx
    mov     ecx, edx
    shl     ecx, 3
    shl     r9, cl
    mov     ecx, dword ptr [rbp-56]
    or      r8, r9
    inc     edx
    cmp     edx, ecx
    jb      ndr_len_lp
    add     rsi, rcx

    test    r8, r8
    jz      ndr_bad
    mov     r9, NTF_MAX_RUN_CLUSTERS
    cmp     r8, r9
    ja      ndr_bad

    test    eax, eax
    jnz     ndr_phys

    ; Sparse run: lcn = -1, prev_lcn unchanged
    mov     qword ptr [rdi], r8
    mov     qword ptr [rdi+8], -1
    add     rdi, NTF_RUN_STRIDE
    inc     ebx
    jmp     ndr_loop

ndr_phys:
    ; Read signed delta (off_sz = eax bytes LE)
    xor     r9, r9
    xor     edx, edx
ndr_off_lp:
    movzx   r11d, byte ptr [rsi + rdx]
    mov     ecx, edx
    shl     ecx, 3
    shl     r11, cl
    or      r9, r11
    inc     edx
    cmp     edx, eax
    jb      ndr_off_lp
    add     rsi, rax

    ; Sign-extend from (eax * 8) bits if eax < 8
    cmp     eax, 8
    jae     ndr_add_delta
    mov     ecx, eax
    shl     ecx, 3                          ; bit width (8..56)
    mov     rdx, 1
    dec     ecx
    shl     rdx, cl                         ; sign bit mask
    test    r9, rdx
    jz      ndr_add_delta
    inc     ecx
    mov     rdx, -1
    shl     rdx, cl
    or      r9, rdx

ndr_add_delta:
    add     r10, r9                         ; cur_lcn = prev_lcn + delta
    js      ndr_bad
    mov     rax, r10
    add     rax, r8
    jc      ndr_bad
    cmp     rax, qword ptr [g_ntf_tot_clus]
    ja      ndr_bad

    mov     qword ptr [rdi], r8
    mov     qword ptr [rdi+8], r10
    add     rdi, NTF_RUN_STRIDE
    inc     ebx
    jmp     ndr_loop

ndr_done:
    mov     eax, ebx
    jmp     ndr_out

ndr_bad:
    mov     eax, -1

ndr_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    mov     r12, qword ptr [rbp-40]
    mov     r13, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
ntfs_decode_runs endp

; =============================================================================
; ntfs_read_runs_at(rcx = runsPtr, edx = runCnt, r8 = byteOff, r9 = dstBuf,
;                   [rbp+48] = byteLen) -> eax = EXIT_*
; Reads byteLen bytes starting at virtual byteOff across a decoded runlist.
; =============================================================================
ntfs_read_runs_at proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; runsPtr
    mov     r12d, edx                       ; runCnt
    mov     r13, r8                         ; curByteOff
    mov     rdi, r9                         ; curDst
    mov     r14, qword ptr [rbp+48]         ; remBytes

    test    r14, r14
    jz      nrra_ok

    ; Locate starting run: vcn = curByteOff / cbytes, inRunOff = curByteOff % cbytes
    mov     rax, r13
    xor     edx, edx
    div     qword ptr [g_ntf_cbytes]        ; rax = targetVcn, rdx = inClusOff
    mov     r13, rdx                        ; inClusOff
    xor     ebx, ebx                        ; runIdx

nrra_find:
    cmp     ebx, r12d
    jae     nrra_corrupt
    mov     ecx, ebx
    shl     rcx, 4
    mov     r8, qword ptr [rsi + rcx]       ; run_vcn_len
    cmp     rax, r8
    jb      nrra_found
    sub     rax, r8
    inc     ebx
    jmp     nrra_find

nrra_found:
    ; rax = cluster offset within run ebx, r13 = byte offset within that cluster
nrra_rd_loop:
    test    r14, r14
    jz      nrra_ok
    cmp     ebx, r12d
    jae     nrra_corrupt

    mov     ecx, ebx
    shl     rcx, 4
    mov     r8,  qword ptr [rsi + rcx]      ; run_vcn_len
    mov     r9,  qword ptr [rsi + rcx + 8]  ; run_lcn

    ; availBytesInRun = (run_vcn_len - rax) * cbytes - r13
    sub     r8, rax
    imul    r8, qword ptr [g_ntf_cbytes]
    sub     r8, r13
    mov     r15, r14
    cmp     r15, r8
    jbe     nrra_chunk_sz
    mov     r15, r8
nrra_chunk_sz:
    cmp     r9, -1
    jne     nrra_phys_rd

    ; Sparse run -> zero fill r15 bytes
    mov     rcx, rdi
    mov     rdx, r15
    call    secure_zero
    jmp     nrra_adv

nrra_phys_rd:
    ; volOff = (run_lcn + rax) * cbytes + r13
    add     r9, rax
    imul    r9, qword ptr [g_ntf_cbytes]
    add     r9, r13
    mov     rcx, r9
    mov     rdx, rdi
    mov     r8,  r15
    call    tcvc_read_bytes
    test    eax, eax
    jnz     nrra_out

nrra_adv:
    add     rdi, r15
    sub     r14, r15
    xor     eax, eax                        ; next run starts at cluster 0
    xor     r13d, r13d                      ; inClusOff = 0
    inc     ebx
    jmp     nrra_rd_loop

nrra_ok:
    xor     eax, eax
    jmp     nrra_out

nrra_corrupt:
    mov     eax, EXIT_CORRUPT

nrra_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ntfs_read_runs_at endp

; =============================================================================
; ntfs_read_mft_rec(rcx = mftRecNum, rdx = outBuf4k) -> eax = EXIT_*
; Reads MFT record mftRecNum via g_ntf_mft_runs and applies "FILE" USA fixups.
; =============================================================================
ntfs_read_mft_rec proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rbx
    mov     rbx, rdx

    mov     rax, qword ptr [g_ntf_mft_bytes]
    mul     rcx
    jo      nrmr_corrupt

    mov     r8, rax                         ; byteOff in $MFT
    lea     rcx, [g_ntf_mft_runs]
    mov     edx, dword ptr [g_ntf_mft_runcnt]
    mov     r9, rbx
    mov     rax, qword ptr [g_ntf_mft_bytes]
    mov     qword ptr [rsp+32], rax
    call    ntfs_read_runs_at
    test    eax, eax
    jnz     nrmr_out

    mov     rcx, rbx
    mov     edx, dword ptr [g_ntf_mft_bytes]
    mov     r8d, NTF_MAGIC_FILE
    call    ntfs_apply_usa
    test    eax, eax
    jnz     nrmr_corrupt

    ; Validate attrs_offset & bytes_in_use
    movzx   ecx, word ptr [rbx + 20]        ; attrs_offset
    mov     edx, dword ptr [rbx + 24]       ; bytes_in_use
    cmp     ecx, 42
    jb      nrmr_corrupt
    cmp     edx, dword ptr [g_ntf_mft_bytes]
    ja      nrmr_corrupt
    cmp     ecx, edx
    ja      nrmr_corrupt

    xor     eax, eax
    jmp     nrmr_out

nrmr_corrupt:
    mov     eax, EXIT_CORRUPT

nrmr_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
ntfs_read_mft_rec endp

; =============================================================================
; ntfs_attr_is_i30(rcx = attrPtr) -> eax = 1 if attr name == "$I30", 0 else
; =============================================================================
ntfs_attr_is_i30 proc
    cmp     byte ptr [rcx + 9], 4
    jne     nai_no
    movzx   edx, word ptr [rcx + 10]
    lea     r8d, [edx + 8]
    cmp     r8d, dword ptr [rcx + 4]
    ja      nai_no
    cmp     word ptr [rcx + rdx],     '$'
    jne     nai_no
    cmp     word ptr [rcx + rdx + 2], 'I'
    jne     nai_no
    cmp     word ptr [rcx + rdx + 4], '3'
    jne     nai_no
    cmp     word ptr [rcx + rdx + 6], '0'
    jne     nai_no
    mov     eax, 1
    ret
nai_no:
    xor     eax, eax
    ret
ntfs_attr_is_i30 endp

; =============================================================================
; ntfs_probe() -> eax: 5 = TCVC_FS_NTFS, 0 = not NTFS, -1 = corrupt NTFS
; =============================================================================
public ntfs_probe
ntfs_probe proc frame
    FRAME_PROLOG 1200
    ; [rbp-16..64]   saved rbx, rsi, rdi, r12, r13, r14, r15
    ; [rbp-72]       saved attr off/len (dd at -72, dd at -68)
    ; [rsp+48..559]  512-byte $Boot buffer (reused as extRecNums[128] at [rsp+48..1071])
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12
    mov     qword ptr [rbp-48], r13
    mov     qword ptr [rbp-56], r14
    mov     qword ptr [rbp-64], r15

    cmp     qword ptr [g_tcvc_data_size], 8192
    jb      np_not_ntfs

    xor     ecx, ecx
    lea     rdx, [rsp+48]
    mov     r8d, 512
    call    tcvc_read_bytes
    test    eax, eax
    jnz     np_not_ntfs

    lea     rsi, [rsp+48]
    mov     rax, qword ptr [rsi + 3]
    mov     rdx, 0202020205346544Eh         ; "NTFS    "
    cmp     rax, rdx
    jne     np_not_ntfs

    ; Matched "NTFS    ": any structural violation from here is -1 (corrupt)
    cmp     word ptr [rsi + 510], 0AA55h
    jne     np_corrupt

    ; BytesPerSector (+11, u16): power of two in 512..4096
    movzx   ebx, word ptr [rsi + 11]
    cmp     ebx, 512
    jb      np_corrupt
    cmp     ebx, 4096
    ja      np_corrupt
    lea     eax, [ebx - 1]
    test    ebx, eax
    jnz     np_corrupt
    mov     qword ptr [g_ntf_bps], rbx

    ; SectorsPerCluster (+13, u8): power of two 1..128, or 244..255 -> 1 << (256 - v)
    movzx   ecx, byte ptr [rsi + 13]
    test    ecx, ecx
    jz      np_corrupt
    cmp     ecx, 128
    ja      np_spc_neg
    lea     eax, [ecx - 1]
    test    ecx, eax
    jnz     np_corrupt
    mov     edi, ecx
    jmp     np_spc_ok
np_spc_neg:
    cmp     ecx, 244
    jb      np_corrupt
    mov     eax, 256
    sub     eax, ecx
    mov     ecx, eax
    mov     edi, 1
    shl     edi, cl
np_spc_ok:
    mov     rax, rbx
    imul    rax, rdi
    cmp     rax, 200000h                    ; <= 2 MiB cluster
    ja      np_corrupt
    mov     qword ptr [g_ntf_cbytes], rax

    ; TotalSectors (+40, u64): Windows formats TotalSectors = PartitionSectors - 1,
    ; so validate TotalSectors * bps <= g_tcvc_data_size, then derive g_ntf_tot_clus
    ; from g_tcvc_data_size / g_ntf_cbytes so runs in the last cluster are accepted.
    mov     rax, qword ptr [rsi + 40]
    test    rax, rax
    jz      np_corrupt
    mul     rbx                             ; rdx:rax = TotalSectors * bps
    test    rdx, rdx
    jnz     np_corrupt
    cmp     rax, qword ptr [g_tcvc_data_size]
    ja      np_corrupt

    mov     rax, qword ptr [g_tcvc_data_size]
    xor     edx, edx
    div     qword ptr [g_ntf_cbytes]
    cmp     rax, 2
    jb      np_corrupt
    mov     qword ptr [g_ntf_tot_clus], rax

    ; MftLcn (+48, u64)
    mov     r12, qword ptr [rsi + 48]
    test    r12, r12
    jz      np_corrupt
    cmp     r12, rax
    jae     np_corrupt

    ; ClustersPerMftRecord (+64, i8) -> 512..4096 power of two
    movsx   ecx, byte ptr [rsi + 64]
    test    ecx, ecx
    jz      np_corrupt
    js      np_mft_neg
    cmp     ecx, 8
    ja      np_corrupt
    mov     rax, qword ptr [g_ntf_cbytes]
    imul    rax, rcx
    jmp     np_mft_chk
np_mft_neg:
    neg     ecx
    cmp     ecx, 9
    jb      np_corrupt
    cmp     ecx, 12
    ja      np_corrupt
    mov     eax, 1
    shl     eax, cl
np_mft_chk:
    cmp     rax, 512
    jb      np_corrupt
    cmp     rax, 4096
    ja      np_corrupt
    lea     rdx, [rax - 1]
    test    rax, rdx
    jnz     np_corrupt
    mov     qword ptr [g_ntf_mft_bytes], rax

    ; ClustersPerIndexBlock (+68, i8) -> 512..65536 power of two
    movsx   ecx, byte ptr [rsi + 68]
    test    ecx, ecx
    jz      np_corrupt
    js      np_idx_neg
    cmp     ecx, 128
    ja      np_corrupt
    mov     rax, qword ptr [g_ntf_cbytes]
    imul    rax, rcx
    jmp     np_idx_chk
np_idx_neg:
    neg     ecx
    cmp     ecx, 9
    jb      np_corrupt
    cmp     ecx, 16
    ja      np_corrupt
    mov     eax, 1
    shl     eax, cl
np_idx_chk:
    cmp     rax, 512
    jb      np_corrupt
    cmp     rax, 65536
    ja      np_corrupt
    lea     rdx, [rax - 1]
    test    rax, rdx
    jnz     np_corrupt
    mov     qword ptr [g_ntf_idx_bytes], rax

    ; Bootstrap $MFT record 0 from MftLcn * cbytes
    mov     rcx, r12
    imul    rcx, qword ptr [g_ntf_cbytes]
    lea     rdx, [g_ntf_rec_main]
    mov     r8,  qword ptr [g_ntf_mft_bytes]
    call    tcvc_read_bytes
    test    eax, eax
    jnz     np_corrupt

    lea     rcx, [g_ntf_rec_main]
    mov     edx, dword ptr [g_ntf_mft_bytes]
    mov     r8d, NTF_MAGIC_FILE
    call    ntfs_apply_usa
    test    eax, eax
    jnz     np_corrupt

    ; Collect all unnamed non-resident $DATA (0x80) extents in $MFT record 0
    mov     dword ptr [g_ntf_mft_runcnt], 0
    lea     rsi, [g_ntf_rec_main]
    movzx   ecx, word ptr [rsi + 20]        ; attrs_offset
    mov     edx, dword ptr [rsi + 24]       ; bytes_in_use
    cmp     ecx, 42
    jb      np_corrupt
    cmp     edx, dword ptr [g_ntf_mft_bytes]
    ja      np_corrupt
    mov     r13d, edx

np_mft_attr:
    cmp     ecx, r13d
    jae     np_mft_ext
    lea     rdi, [rsi + rcx]
    mov     eax, dword ptr [rdi]
    cmp     eax, NTF_AT_END
    je      np_mft_ext
    mov     edx, dword ptr [rdi + 4]
    cmp     edx, 24
    jb      np_corrupt
    lea     r8d, [ecx + edx]
    cmp     r8d, r13d
    ja      np_corrupt

    cmp     eax, NTF_AT_DATA
    jne     np_mft_next
    cmp     byte ptr [rdi + 9], 0           ; unnamed $DATA
    jne     np_mft_next
    cmp     byte ptr [rdi + 8], 1           ; must be non-resident
    jne     np_corrupt
    cmp     edx, 64
    jb      np_corrupt
    movzx   eax, word ptr [rdi + 32]        ; mapping_pairs_offset
    cmp     eax, edx
    jae     np_corrupt

    mov     r10d, dword ptr [g_ntf_mft_runcnt]
    cmp     r10d, NTF_MAX_MFT_RUNS
    jae     np_corrupt
    lea     r8,  [g_ntf_mft_runs]
    mov     r9d, r10d
    shl     r9d, 4
    add     r8,  r9
    mov     r9d, NTF_MAX_MFT_RUNS
    sub     r9d, r10d
    mov     dword ptr [rbp-72], ecx
    mov     dword ptr [rbp-68], edx
    lea     rcx, [rdi + rax]
    sub     edx, eax
    call    ntfs_decode_runs
    mov     ecx, dword ptr [rbp-72]
    mov     edx, dword ptr [rbp-68]
    cmp     eax, 0
    jle     np_corrupt
    add     dword ptr [g_ntf_mft_runcnt], eax

np_mft_next:
    add     ecx, edx
    jmp     np_mft_attr

np_mft_ext:
    cmp     dword ptr [g_ntf_mft_runcnt], 0
    je      np_corrupt

    ; Also append unnamed $DATA extents from $ATTRIBUTE_LIST extension records of $MFT
    lea     rcx, [g_ntf_rec_main]
    lea     rdx, [rsp+48]
    mov     r8d, NTF_MAX_EXT_RECS
    mov     r9d, NTF_AT_DATA
    mov     qword ptr [rsp+32], 0           ; baseRecNum = 0 ($MFT)
    call    ntfs_collect_ext_recs
    cmp     eax, 0
    jl      np_corrupt
    jz      np_mft_done

    mov     r15d, eax
    xor     r14d, r14d
np_ext_lp:
    cmp     r14d, r15d
    jae     np_mft_done
    mov     rcx, qword ptr [rsp+48 + r14*8]
    lea     rdx, [g_ntf_rec_ext]
    call    ntfs_read_mft_rec
    test    eax, eax
    jnz     np_corrupt
    lea     rsi, [g_ntf_rec_ext]
    movzx   ecx, word ptr [rsi + 20]
    mov     ebx, dword ptr [rsi + 24]
np_ext_attr:
    cmp     ecx, ebx
    jae     np_ext_next
    lea     rdi, [rsi + rcx]
    mov     eax, dword ptr [rdi]
    cmp     eax, NTF_AT_END
    je      np_ext_next
    mov     edx, dword ptr [rdi + 4]
    cmp     edx, 24
    jb      np_corrupt
    lea     r8d, [ecx + edx]
    cmp     r8d, ebx
    ja      np_corrupt
    cmp     eax, NTF_AT_DATA
    jne     np_ext_adv
    cmp     byte ptr [rdi + 9], 0
    jne     np_ext_adv
    cmp     byte ptr [rdi + 8], 1
    jne     np_corrupt
    cmp     edx, 64
    jb      np_corrupt
    movzx   eax, word ptr [rdi + 32]
    cmp     eax, edx
    jae     np_corrupt

    mov     r10d, dword ptr [g_ntf_mft_runcnt]
    cmp     r10d, NTF_MAX_MFT_RUNS
    jae     np_corrupt
    lea     r8,  [g_ntf_mft_runs]
    mov     r9d, r10d
    shl     r9d, 4
    add     r8,  r9
    mov     r9d, NTF_MAX_MFT_RUNS
    sub     r9d, r10d
    mov     dword ptr [rbp-72], ecx
    mov     dword ptr [rbp-68], edx
    lea     rcx, [rdi + rax]
    sub     edx, eax
    call    ntfs_decode_runs
    mov     ecx, dword ptr [rbp-72]
    mov     edx, dword ptr [rbp-68]
    cmp     eax, 0
    jle     np_corrupt
    add     dword ptr [g_ntf_mft_runcnt], eax
np_ext_adv:
    add     ecx, edx
    jmp     np_ext_attr
np_ext_next:
    inc     r14d
    jmp     np_ext_lp

np_mft_done:
    mov     eax, TCVC_FS_NTFS
    jmp     np_out

np_not_ntfs:
    xor     eax, eax
    jmp     np_out

np_corrupt:
    mov     eax, -1

np_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    mov     r12, qword ptr [rbp-40]
    mov     r13, qword ptr [rbp-48]
    mov     r14, qword ptr [rbp-56]
    mov     r15, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ntfs_probe endp

; =============================================================================
; ntfs_collect_ext_recs(rcx = baseRec, rdx = outRecNums, r8d = maxRecs,
;                       r9d = wantAttrType, [rbp+48] = baseRecNum) -> eax = count or -1
; Scans $ATTRIBUTE_LIST (0x20), if present, for unique extension MFT record numbers
; holding attributes of wantAttrType.
; =============================================================================
ntfs_collect_ext_recs proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; baseRec
    mov     rdi, rdx                        ; outRecNums (dq[])
    mov     r12d, r8d                       ; maxRecs
    mov     r13d, r9d                       ; wantAttrType
    xor     ebx, ebx                        ; count = 0

    movzx   ecx, word ptr [rsi + 20]
    mov     r14d, dword ptr [rsi + 24]
ncer_scan:
    cmp     ecx, r14d
    jae     ncer_done
    lea     r10, [rsi + rcx]
    mov     eax, dword ptr [r10]
    cmp     eax, NTF_AT_END
    je      ncer_done
    mov     edx, dword ptr [r10 + 4]
    cmp     edx, 24
    jb      ncer_bad
    lea     r8d, [ecx + edx]
    cmp     r8d, r14d
    ja      ncer_bad

    cmp     eax, NTF_AT_ATTR_LIST
    je      ncer_found_al
    add     ecx, edx
    jmp     ncer_scan

ncer_found_al:
    cmp     byte ptr [r10 + 8], 0
    jne     ncer_al_nonres

    ; Resident $ATTRIBUTE_LIST
    mov     r15d, dword ptr [r10 + 16]      ; val_len
    movzx   eax, word ptr [r10 + 20]        ; val_ofs
    lea     ecx, [eax + r15d]
    cmp     ecx, edx
    ja      ncer_bad
    lea     rsi, [r10 + rax]
    jmp     ncer_walk_al

ncer_al_nonres:
    cmp     edx, 64
    jb      ncer_bad
    mov     r15, qword ptr [r10 + 48]       ; data_size
    cmp     r15, 262144
    ja      ncer_bad
    movzx   eax, word ptr [r10 + 32]
    cmp     eax, edx
    jae     ncer_bad
    lea     rcx, [r10 + rax]
    sub     edx, eax
    lea     r8,  [g_ntf_data_runs]
    mov     r9d, NTF_MAX_DATA_RUNS
    call    ntfs_decode_runs
    cmp     eax, 0
    jle     ncer_bad

    lea     rcx, [g_ntf_data_runs]
    mov     edx, eax
    xor     r8d, r8d
    lea     r9,  [g_ntf_alist_buf]
    mov     qword ptr [rsp+32], r15
    call    ntfs_read_runs_at
    test    eax, eax
    jnz     ncer_bad
    lea     rsi, [g_ntf_alist_buf]

ncer_walk_al:
    xor     ecx, ecx
ncer_al_lp:
    lea     eax, [ecx + 26]
    cmp     eax, r15d
    ja      ncer_done
    mov     eax, dword ptr [rsi + rcx]      ; attr_type
    movzx   edx, word ptr [rsi + rcx + 4]   ; entry_len
    cmp     edx, 26
    jb      ncer_bad
    lea     r8d, [ecx + edx]
    cmp     r8d, r15d
    ja      ncer_bad

    test    r13d, r13d
    jz      ncer_type_ok
    cmp     eax, r13d
    jne     ncer_al_next
ncer_type_ok:

    mov     rax, qword ptr [rsi + rcx + 16]
    mov     r9,  0000FFFFFFFFFFFFh
    and     rax, r9                         ; extRecNum
    cmp     rax, qword ptr [rbp+48]         ; skip baseRecNum itself
    je      ncer_al_next

    ; Deduplicate in outRecNums[0..ebx-1]
    xor     r8d, r8d
ncer_dup:
    cmp     r8d, ebx
    jae     ncer_push
    cmp     qword ptr [rdi + r8*8], rax
    je      ncer_al_next
    inc     r8d
    jmp     ncer_dup
ncer_push:
    cmp     ebx, r12d
    jae     ncer_bad
    mov     qword ptr [rdi + rbx*8], rax
    inc     ebx

ncer_al_next:
    add     ecx, edx
    jmp     ncer_al_lp

ncer_done:
    mov     eax, ebx
    jmp     ncer_out

ncer_bad:
    mov     eax, -1

ncer_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ntfs_collect_ext_recs endp

; =============================================================================
; ntfs_inspect_child(rcx = childRecNum, edx = expectedSeq, r8 = parentDirRecNum,
;                    r9 = outSizePtr, [rbp+48] = outInfoPtr)
;   -> eax = EXIT_*
;      *outInfoPtr bits:
;         bit 0 = skip (DOS alias shadowed by Win32/POSIX, reparse point, or EFS)
;         bit 1 = isDir
;         bit 2 = hasUnnamedData (regular file or dir)
; =============================================================================
ntfs_inspect_child proc frame
    FRAME_PROLOG 1200
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-72]       childRecNum
    ; [rbp-80]       parentDirRecNum
    ; [rbp-88]       hasBetterWin32Name (dd), isDir (dd at -84)
    ; [rbp-96]       foundData (dd), skipEntry (dd at -92)
    ; [rbp-104]      fileSize (dq)
    ; [rsp+48..1071] extRecNums[128] (1024 bytes)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     qword ptr [rbp-72], rcx
    mov     r12d, edx                       ; expectedSeq
    mov     qword ptr [rbp-80], r8          ; parentDirRecNum
    mov     r14, r9                         ; outSizePtr
    mov     r15, qword ptr [rbp+48]         ; outInfoPtr

    mov     dword ptr [rbp-88], 0           ; hasBetterWin32Name
    mov     dword ptr [rbp-84], 0           ; isDir
    mov     dword ptr [rbp-96], 0           ; foundData
    mov     dword ptr [rbp-92], 0           ; skipEntry
    mov     qword ptr [rbp-104], 0          ; fileSize

    lea     rdx, [g_ntf_rec_child]
    call    ntfs_read_mft_rec
    test    eax, eax
    jnz     nic_out

    lea     rsi, [g_ntf_rec_child]
    movzx   eax, word ptr [rsi + 16]        ; sequence_number
    cmp     eax, r12d
    jne     nic_skip_stale                  ; stale index entry

    movzx   eax, word ptr [rsi + 22]        ; flags
    test    eax, NTF_MFT_IN_USE
    jz      nic_skip_stale
    test    eax, NTF_MFT_IS_DIR
    jz      nic_scan_base
    mov     dword ptr [rbp-84], 1

nic_scan_base:
    movzx   ecx, word ptr [rsi + 20]
    mov     ebx, dword ptr [rsi + 24]
nic_attr_lp:
    cmp     ecx, ebx
    jae     nic_chk_ext
    lea     rdi, [rsi + rcx]
    mov     eax, dword ptr [rdi]
    cmp     eax, NTF_AT_END
    je      nic_chk_ext
    mov     edx, dword ptr [rdi + 4]
    cmp     edx, 24
    jb      nic_corrupt
    lea     r8d, [ecx + edx]
    cmp     r8d, ebx
    ja      nic_corrupt

    cmp     eax, NTF_AT_REPARSE
    je      nic_mark_skip
    cmp     eax, NTF_AT_FILE_NAME
    je      nic_chk_fn
    cmp     eax, NTF_AT_DATA
    je      nic_chk_data
    jmp     nic_attr_next

nic_mark_skip:
    mov     dword ptr [rbp-92], 1
    jmp     nic_finish

nic_chk_fn:
    cmp     byte ptr [rdi + 8], 0
    jne     nic_attr_next
    mov     r8d, dword ptr [rdi + 16]
    cmp     r8d, 66
    jb      nic_attr_next
    movzx   r9d, word ptr [rdi + 20]
    lea     eax, [r9d + r8d]
    cmp     eax, edx
    ja      nic_corrupt
    ; Check if reparse bit set in $FILE_NAME flags (+56)
    test    dword ptr [rdi + r9 + 56], NTF_DUP_REPARSE
    jnz     nic_mark_skip
    ; Check parent ref & namespace != DOS (2)
    mov     rax, qword ptr [rdi + r9]
    mov     r10, 0000FFFFFFFFFFFFh
    and     rax, r10
    cmp     rax, qword ptr [rbp-80]
    jne     nic_attr_next
    cmp     byte ptr [rdi + r9 + 65], NTF_FN_NS_DOS
    je      nic_attr_next
    mov     dword ptr [rbp-88], 1           ; has non-DOS name in this parent!
    jmp     nic_attr_next

nic_chk_data:
    cmp     byte ptr [rdi + 9], 0           ; unnamed $DATA only
    jne     nic_attr_next
    test    word ptr [rdi + 12], NTF_AF_ENCRYPTED
    jnz     nic_unsup
    cmp     byte ptr [rdi + 8], 0
    jne     nic_data_nonres
    mov     eax, dword ptr [rdi + 16]
    mov     qword ptr [rbp-104], rax
    mov     dword ptr [rbp-96], 1
    jmp     nic_attr_next
nic_data_nonres:
    cmp     edx, 64
    jb      nic_corrupt
    cmp     qword ptr [rdi + 16], 0         ; lowest_vcn == 0 holds DataSize
    jne     nic_attr_next
    mov     rax, qword ptr [rdi + 48]
    mov     r10, NTF_MAX_FSIZE
    cmp     rax, r10
    ja      nic_corrupt
    mov     qword ptr [rbp-104], rax
    mov     dword ptr [rbp-96], 1

nic_attr_next:
    add     ecx, edx
    jmp     nic_attr_lp

nic_chk_ext:
    ; Scan $ATTRIBUTE_LIST extension records (for $FILE_NAME, $REPARSE_POINT, and $DATA)
    lea     rcx, [g_ntf_rec_child]
    lea     rdx, [rsp+48]
    mov     r8d, NTF_MAX_EXT_RECS
    xor     r9d, r9d                        ; wantAttrType = 0 (all attributes)
    mov     rax, qword ptr [rbp-72]
    mov     qword ptr [rsp+32], rax
    call    ntfs_collect_ext_recs
    cmp     eax, 0
    jl      nic_corrupt
    jz      nic_finish

    mov     r13d, eax
    xor     r12d, r12d
nic_ext_lp:
    cmp     r12d, r13d
    jae     nic_finish
    mov     rcx, qword ptr [rsp+48 + r12*8]
    lea     rdx, [g_ntf_rec_ext]
    call    ntfs_read_mft_rec
    test    eax, eax
    jnz     nic_out

    lea     rsi, [g_ntf_rec_ext]
    movzx   ecx, word ptr [rsi + 20]
    mov     ebx, dword ptr [rsi + 24]
nic_ext_attr:
    cmp     ecx, ebx
    jae     nic_ext_next_rec
    lea     rdi, [rsi + rcx]
    mov     eax, dword ptr [rdi]
    cmp     eax, NTF_AT_END
    je      nic_ext_next_rec
    mov     edx, dword ptr [rdi + 4]
    cmp     edx, 24
    jb      nic_corrupt
    lea     r8d, [ecx + edx]
    cmp     r8d, ebx
    ja      nic_corrupt

    cmp     eax, NTF_AT_REPARSE
    je      nic_mark_skip
    cmp     eax, NTF_AT_FILE_NAME
    je      nic_ext_fn
    cmp     eax, NTF_AT_DATA
    je      nic_ext_data
    jmp     nic_ext_adv

nic_ext_fn:
    cmp     byte ptr [rdi + 8], 0
    jne     nic_ext_adv
    mov     r8d, dword ptr [rdi + 16]
    cmp     r8d, 66
    jb      nic_ext_adv
    movzx   r9d, word ptr [rdi + 20]
    lea     eax, [r9d + r8d]
    cmp     eax, edx
    ja      nic_corrupt
    test    dword ptr [rdi + r9 + 56], NTF_DUP_REPARSE
    jnz     nic_mark_skip
    mov     rax, qword ptr [rdi + r9]
    mov     r10, 0000FFFFFFFFFFFFh
    and     rax, r10
    cmp     rax, qword ptr [rbp-80]
    jne     nic_ext_adv
    cmp     byte ptr [rdi + r9 + 65], NTF_FN_NS_DOS
    je      nic_ext_adv
    mov     dword ptr [rbp-88], 1
    jmp     nic_ext_adv

nic_ext_data:
    cmp     byte ptr [rdi + 9], 0
    jne     nic_ext_adv
    test    word ptr [rdi + 12], NTF_AF_ENCRYPTED
    jnz     nic_unsup
    cmp     dword ptr [rbp-96], 0
    jne     nic_ext_adv
    cmp     byte ptr [rdi + 8], 0
    jne     nic_ext_nr
    mov     eax, dword ptr [rdi + 16]
    mov     qword ptr [rbp-104], rax
    mov     dword ptr [rbp-96], 1
    jmp     nic_ext_adv
nic_ext_nr:
    cmp     edx, 64
    jb      nic_corrupt
    cmp     qword ptr [rdi + 16], 0
    jne     nic_ext_adv
    mov     rax, qword ptr [rdi + 48]
    mov     r10, NTF_MAX_FSIZE
    cmp     rax, r10
    ja      nic_corrupt
    mov     qword ptr [rbp-104], rax
    mov     dword ptr [rbp-96], 1
nic_ext_adv:
    add     ecx, edx
    jmp     nic_ext_attr
nic_ext_next_rec:
    inc     r12d
    jmp     nic_ext_lp

nic_skip_stale:
    mov     dword ptr [rbp-92], 1

nic_finish:
    mov     rax, qword ptr [rbp-104]
    mov     qword ptr [r14], rax

    xor     eax, eax
    cmp     dword ptr [rbp-92], 0
    je      nic_f_dir
    or      eax, 1                          ; bit 0: skip
nic_f_dir:
    cmp     dword ptr [rbp-84], 0
    je      nic_f_win
    or      eax, 2                          ; bit 1: isDir
nic_f_win:
    cmp     dword ptr [rbp-88], 0
    je      nic_f_dat
    or      eax, 4                          ; bit 2: hasWin32NameInParent
nic_f_dat:
    mov     dword ptr [r15], eax
    xor     eax, eax
    jmp     nic_out

nic_unsup:
    mov     eax, EXIT_UNSUPPORTED
    jmp     nic_out

nic_corrupt:
    mov     eax, EXIT_CORRUPT

nic_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ntfs_inspect_child endp

; =============================================================================
; ntfs_mark_dir_visited(rcx = mftRecNum, edx = dirDepth) -> eax = EXIT_*
; Checks active ancestor stack [0..dirDepth-1] for directory cycles, records
; mftRecNum at g_ntf_anc_mft[dirDepth], and bounds total directories visited.
; =============================================================================
ntfs_mark_dir_visited proc
    lea     r8,  [g_ntf_anc_mft]
    xor     eax, eax
nmdv_lp:
    cmp     eax, edx
    jae     nmdv_anc_ok
    cmp     qword ptr [r8 + rax*8], rcx
    je      nmdv_cycle
    inc     eax
    jmp     nmdv_lp
nmdv_anc_ok:
    mov     eax, dword ptr [g_ntf_vis_cnt]
    cmp     eax, NTF_MAX_DIRS
    jae     nmdv_oom
    inc     eax
    mov     dword ptr [g_ntf_vis_cnt], eax
    mov     eax, edx
    mov     qword ptr [r8 + rax*8], rcx
    xor     eax, eax
    ret
nmdv_cycle:
    mov     eax, EXIT_CORRUPT
    ret
nmdv_oom:
    mov     eax, EXIT_OOM
    ret
ntfs_mark_dir_visited endp

; Forward declaration via mutual call in same module: ntfs_walk_dir
; =============================================================================
; ntfs_walk_index_entries(rcx = entStart, edx = entBytes, r8 = dirCtxPtr,
;                         r9d = btreeDepth) -> eax = EXIT_*
; dirCtx layout:
;   +0  dq dirRecNum
;   +8  dd prefixLen
;   +12 dd dirDepth
;   +16 dq iaRunsPtr
;   +24 dd iaRunCnt
;   +28 dd pad
; =============================================================================
ntfs_walk_index_entries proc frame
    FRAME_PROLOG 192
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-72]       childSize (dq)
    ; [rbp-80]       childInfo (dd), btreeDepth (dd at -76)
    ; [rbp-88]       indxBufPtr (dq)
    ; [rbp-96]       childRecNum (dq)
    ; [rbp-104]      childSeq (dd), fullLen (dd at -100)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    cmp     r9d, NTF_MAX_BTREE_DEPTH
    ja      nwie_corrupt

    mov     rsi, rcx                        ; curEnt
    lea     r12, [rcx + rdx]                ; endEnt
    mov     r13, r8                         ; dirCtxPtr
    mov     dword ptr [rbp-76], r9d         ; btreeDepth

nwie_loop:
    lea     rax, [rsi + 16]
    cmp     rax, r12
    ja      nwie_corrupt

    movzx   ebx, word ptr [rsi + 8]         ; entry_len
    cmp     ebx, 16
    jb      nwie_corrupt
    test    ebx, 3
    jnz     nwie_corrupt
    lea     rax, [rsi + rbx]
    cmp     rax, r12
    ja      nwie_corrupt

    movzx   edi, word ptr [rsi + 12]        ; ie_flags
    test    edi, NTF_IE_SUBNODE
    jz      nwie_chk_end

    ; Subnode VCN sits in last 8 bytes of INDEX_ENTRY
    cmp     ebx, 24
    jb      nwie_corrupt
    cmp     dword ptr [r13 + 24], 0         ; iaRunCnt must be > 0
    je      nwie_corrupt

    mov     r14, qword ptr [rsi + rbx - 8]  ; subnode VCN
    ; Allocate one IndexBlockBytes buffer on heap for this B-tree level
    mov     rcx, qword ptr [g_ntf_idx_bytes]
    call    mem_alloc
    test    rax, rax
    jz      nwie_oom
    mov     qword ptr [rbp-88], rax

    ; byteOff = (idx_bytes >= cbytes) ? vcn * cbytes : vcn * 512
    mov     rax, qword ptr [g_ntf_idx_bytes]
    cmp     rax, qword ptr [g_ntf_cbytes]
    jb      nwie_vcn_sec
    mov     r8, r14
    imul    r8, qword ptr [g_ntf_cbytes]
    jmp     nwie_rd_indx
nwie_vcn_sec:
    mov     r8, r14
    shl     r8, 9
nwie_rd_indx:
    mov     rcx, qword ptr [r13 + 16]       ; iaRunsPtr
    mov     edx, dword ptr [r13 + 24]       ; iaRunCnt
    mov     r9,  qword ptr [rbp-88]
    mov     rax, qword ptr [g_ntf_idx_bytes]
    mov     qword ptr [rsp+32], rax
    call    ntfs_read_runs_at
    test    eax, eax
    jnz     nwie_free_sub_err

    mov     rcx, qword ptr [rbp-88]
    mov     edx, dword ptr [g_ntf_idx_bytes]
    mov     r8d, NTF_MAGIC_INDX
    call    ntfs_apply_usa
    test    eax, eax
    jnz     nwie_free_sub_corrupt

    mov     rax, qword ptr [rbp-88]
    mov     ecx, dword ptr [rax + 24]       ; entries_offset (rel +24)
    mov     edx, dword ptr [rax + 28]       ; index_length (rel +24)
    cmp     ecx, 16
    jb      nwie_free_sub_corrupt
    cmp     edx, ecx
    jb      nwie_free_sub_corrupt
    lea     r8d, [edx + 24]
    cmp     r8d, dword ptr [g_ntf_idx_bytes]
    ja      nwie_free_sub_corrupt

    sub     edx, ecx
    lea     rcx, [rax + 24 + rcx]
    mov     r8,  r13
    mov     r9d, dword ptr [rbp-76]
    inc     r9d
    call    ntfs_walk_index_entries
    mov     r15d, eax

    mov     rcx, qword ptr [rbp-88]
    mov     rdx, qword ptr [g_ntf_idx_bytes]
    call    mem_free
    test    r15d, r15d
    jnz     nwie_ret_r15

nwie_chk_end:
    test    edi, NTF_IE_END
    jnz     nwie_ok

    ; Process $FILE_NAME key at rsi + 16
    movzx   ecx, word ptr [rsi + 10]        ; key_len
    cmp     ecx, 66
    jb      nwie_corrupt
    lea     eax, [ecx + 16]
    cmp     eax, ebx
    ja      nwie_corrupt

    movzx   r14d, byte ptr [rsi + 16 + 64]  ; fn_len (UTF-16 chars)
    test    r14d, r14d
    jz      nwie_corrupt
    lea     eax, [r14d*2 + 66]
    cmp     eax, ecx
    ja      nwie_corrupt

    ; Extract childRecNum & childSeq
    mov     rax, qword ptr [rsi]
    mov     rdx, rax
    shr     rdx, 48
    mov     dword ptr [rbp-104], edx        ; childSeq
    mov     rcx, 0000FFFFFFFFFFFFh
    and     rax, rcx
    mov     qword ptr [rbp-96], rax         ; childRecNum

    ; Skip NTFS metafiles (mftRecNum < 24)
    cmp     rax, 24
    jb      nwie_next

    ; Skip '$' system names at root (e.g. $Extend)
    cmp     dword ptr [r13 + 8], 0
    jne     nwie_insp
    cmp     word ptr [rsi + 16 + 66], '$'
    je      nwie_next

nwie_insp:
    mov     rcx, rax
    mov     edx, dword ptr [rbp-104]
    mov     r8,  qword ptr [r13]            ; parentDirRecNum
    lea     r9,  [rbp-72]                   ; &childSize
    lea     rax, [rbp-80]                   ; &childInfo
    mov     qword ptr [rsp+32], rax
    call    ntfs_inspect_child
    test    eax, eax
    jnz     nwie_out

    mov     eax, dword ptr [rbp-80]         ; childInfo
    test    eax, 1                          ; skip flag (reparse/stale)
    jnz     nwie_next

    ; If this index entry is DOS namespace (2) AND child has a non-DOS name in this parent, skip!
    cmp     byte ptr [rsi + 16 + 65], NTF_FN_NS_DOS
    jne     nwie_conv_name
    test    eax, 4
    jnz     nwie_next

nwie_conv_name:
    ; Convert UTF-16LE name at [rsi + 82], length r14d, to UTF-8 in g_ntf_comp8
    lea     r8, [rsi + 82]
    WINCALL WideCharToMultiByte, NTF_CP_UTF8, 0, r8, r14d, addr g_ntf_comp8, 1020, 0, 0
    test    eax, eax
    jz      nwie_corrupt
    mov     r15d, eax                       ; compLen

    ; Skip "." and ".." if ever present
    lea     rdi, [g_ntf_comp8]
    cmp     r15d, 1
    jne     nwie_dot2
    cmp     byte ptr [rdi], '.'
    je      nwie_next
nwie_dot2:
    cmp     r15d, 2
    jne     nwie_join
    cmp     word ptr [rdi], 2E2Eh
    je      nwie_next

nwie_join:
    cmp     dword ptr [r13 + 8], 0
    jne     nwie_not_sys
    mov     rcx, rdi
    mov     edx, r15d
    call    tcvc_is_sys_root
    test    eax, eax
    jnz     nwie_next
nwie_not_sys:
    mov     ecx, dword ptr [r13 + 8]        ; prefixLen
    lea     eax, [ecx + r15d]
    cmp     eax, ENTRY_NAME_MAX
    ja      nwie_corrupt
    mov     dword ptr [rbp-100], eax        ; fullLen

    lea     rdx, [g_ntf_path]
    add     rdx, rcx
    xor     ecx, ecx
nwie_cp_nm:
    mov     al, byte ptr [rdi + rcx]
    mov     byte ptr [rdx + rcx], al
    inc     ecx
    cmp     ecx, r15d
    jb      nwie_cp_nm

nwie_emit_chk:
    test    dword ptr [rbp-80], 2           ; isDir?
    jnz     nwie_is_dir

    ; Emit regular file: meta0 = childRecNum, meta1 = childSeq
    lea     rcx, [g_ntf_path]
    mov     edx, dword ptr [rbp-100]
    mov     r8,  qword ptr [rbp-72]
    xor     r9d, r9d
    mov     rax, qword ptr [rbp-96]
    mov     qword ptr [rsp+32], rax
    mov     eax, dword ptr [rbp-104]
    mov     qword ptr [rsp+40], rax
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_add
    test    eax, eax
    jnz     nwie_out
    jmp     nwie_next

nwie_is_dir:
    lea     rcx, [g_ntf_path]
    mov     edx, dword ptr [rbp-100]
    xor     r8d, r8d
    mov     r9d, IDXEF_DIR
    mov     rax, qword ptr [rbp-96]
    mov     qword ptr [rsp+32], rax
    mov     eax, dword ptr [rbp-104]
    mov     qword ptr [rsp+40], rax
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_add
    test    eax, eax
    jnz     nwie_out

    mov     eax, dword ptr [rbp-100]
    inc     eax
    cmp     eax, ENTRY_NAME_MAX
    ja      nwie_corrupt
    mov     ecx, dword ptr [rbp-100]
    lea     rdx, [g_ntf_path]
    mov     byte ptr [rdx + rcx], '/'

    mov     rcx, qword ptr [rbp-96]         ; childRecNum
    mov     edx, eax                        ; newPrefixLen
    mov     r8d, dword ptr [r13 + 12]
    inc     r8d                             ; dirDepth + 1
    call    ntfs_walk_dir
    test    eax, eax
    jnz     nwie_out

nwie_next:
    add     rsi, rbx
    jmp     nwie_loop

nwie_free_sub_corrupt:
    mov     r15d, EXIT_CORRUPT
    jmp     nwie_do_free
nwie_free_sub_err:
    mov     r15d, eax
nwie_do_free:
    mov     rcx, qword ptr [rbp-88]
    mov     rdx, qword ptr [g_ntf_idx_bytes]
    call    mem_free
nwie_ret_r15:
    mov     eax, r15d
    jmp     nwie_out

nwie_oom:
    mov     eax, EXIT_OOM
    jmp     nwie_out

nwie_corrupt:
    mov     eax, EXIT_CORRUPT
    jmp     nwie_out

nwie_ok:
    xor     eax, eax

nwie_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ntfs_walk_index_entries endp

; =============================================================================
; ntfs_walk_dir(rcx = dirRecNum, edx = prefixLen, r8d = dirDepth) -> eax = EXIT_*
; =============================================================================
ntfs_walk_dir proc frame
    FRAME_PROLOG 1216
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-96..-65]  dirCtx (32 bytes)
    ; [rbp-104]      iaRunsHeap (dq)
    ; [rbp-112]      rootCopyHeap (dq)
    ; [rbp-120]      rootEntLen (dd), iaRunCnt (dd at -116)
    ; [rsp+48..1071] extRecNums[128] (1024 bytes)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     qword ptr [rbp-104], 0
    mov     qword ptr [rbp-112], 0
    mov     dword ptr [rbp-120], 0
    mov     dword ptr [rbp-116], 0

    cmp     r8d, NTF_MAX_DEPTH
    ja      nwd_corrupt

    mov     r12, rcx                        ; dirRecNum
    mov     dword ptr [rbp-96 + 8],  edx    ; prefixLen
    mov     dword ptr [rbp-96 + 12], r8d    ; dirDepth
    mov     qword ptr [rbp-96 + 0],  rcx

    mov     edx, r8d
    call    ntfs_mark_dir_visited
    test    eax, eax
    jnz     nwd_cleanup_err

    ; Allocate per-directory iaRuns buffer (4096 runs * 16 = 65536B) + rootCopy (4096B)
    mov     ecx, NTF_IA_HEAP_BYTES
    call    mem_alloc
    test    rax, rax
    jz      nwd_oom
    mov     qword ptr [rbp-104], rax
    mov     qword ptr [rbp-96 + 16], rax

    mov     ecx, 4096
    call    mem_alloc
    test    rax, rax
    jz      nwd_oom
    mov     qword ptr [rbp-112], rax

    mov     rcx, r12
    lea     rdx, [g_ntf_rec_main]
    call    ntfs_read_mft_rec
    test    eax, eax
    jnz     nwd_cleanup_err

    ; Scan base record for $INDEX_ROOT:$I30 and $INDEX_ALLOCATION:$I30
    lea     rsi, [g_ntf_rec_main]
    test    word ptr [rsi + 22], NTF_MFT_IS_DIR
    jz      nwd_corrupt

    movzx   ecx, word ptr [rsi + 20]
    mov     ebx, dword ptr [rsi + 24]
nwd_base_lp:
    cmp     ecx, ebx
    jae     nwd_chk_ext_ia
    lea     rdi, [rsi + rcx]
    mov     eax, dword ptr [rdi]
    cmp     eax, NTF_AT_END
    je      nwd_chk_ext_ia
    mov     edx, dword ptr [rdi + 4]
    cmp     edx, 24
    jb      nwd_corrupt
    lea     r8d, [ecx + edx]
    cmp     r8d, ebx
    ja      nwd_corrupt

    cmp     eax, NTF_AT_INDEX_ROOT
    je      nwd_got_ir
    cmp     eax, NTF_AT_INDEX_ALLOC
    je      nwd_got_ia
    jmp     nwd_base_next

nwd_got_ir:
    mov     dword ptr [rbp-128], ecx
    mov     dword ptr [rbp-132], edx
    mov     rcx, rdi
    call    ntfs_attr_is_i30
    mov     ecx, dword ptr [rbp-128]
    mov     edx, dword ptr [rbp-132]
    test    eax, eax
    jz      nwd_base_next
    cmp     byte ptr [rdi + 8], 0           ; $INDEX_ROOT is always resident
    jne     nwd_corrupt
    mov     r8d, dword ptr [rdi + 16]       ; val_len
    movzx   r9d, word ptr [rdi + 20]        ; val_ofs
    cmp     r8d, 32
    jb      nwd_corrupt
    lea     eax, [r9d + r8d]
    cmp     eax, edx
    ja      nwd_corrupt
    lea     r10, [rdi + r9]                 ; INDEX_ROOT value
    mov     eax, dword ptr [r10 + 16]       ; entries_offset (rel +16)
    mov     r11d, dword ptr [r10 + 20]      ; index_length (rel +16)
    cmp     eax, 16
    jb      nwd_corrupt
    cmp     r11d, eax
    jb      nwd_corrupt
    lea     r14d, [r11d + 16]
    cmp     r14d, r8d
    ja      nwd_corrupt
    sub     r11d, eax                       ; entBytes
    cmp     r11d, 4096
    ja      nwd_corrupt
    mov     dword ptr [rbp-120], r11d
    ; Copy $INDEX_ROOT entries to rootCopyHeap so g_ntf_rec_main can be reused
    mov     r14, qword ptr [rbp-112]
    lea     r10, [r10 + 16 + rax]
    xor     r15d, r15d
nwd_cp_ir:
    cmp     r15d, r11d
    jae     nwd_base_next
    mov     al, byte ptr [r10 + r15]
    mov     byte ptr [r14 + r15], al
    inc     r15d
    jmp     nwd_cp_ir

nwd_got_ia:
    mov     dword ptr [rbp-128], ecx
    mov     dword ptr [rbp-132], edx
    mov     rcx, rdi
    call    ntfs_attr_is_i30
    mov     ecx, dword ptr [rbp-128]
    mov     edx, dword ptr [rbp-132]
    test    eax, eax
    jz      nwd_base_next
    cmp     byte ptr [rdi + 8], 1
    jne     nwd_corrupt
    cmp     edx, 64
    jb      nwd_corrupt
    movzx   eax, word ptr [rdi + 32]
    cmp     eax, edx
    jae     nwd_corrupt
    mov     r14d, dword ptr [rbp-116]       ; cur iaRunCnt
    cmp     r14d, NTF_MAX_DATA_RUNS
    jae     nwd_corrupt
    mov     r8, qword ptr [rbp-104]
    mov     r9d, r14d
    shl     r9d, 4
    add     r8, r9
    mov     r9d, NTF_MAX_DATA_RUNS
    sub     r9d, r14d
    mov     dword ptr [rbp-128], ecx
    mov     dword ptr [rbp-132], edx
    lea     rcx, [rdi + rax]
    sub     edx, eax
    call    ntfs_decode_runs
    mov     ecx, dword ptr [rbp-128]
    mov     edx, dword ptr [rbp-132]
    cmp     eax, 0
    jl      nwd_corrupt
    add     dword ptr [rbp-116], eax

nwd_base_next:
    add     ecx, edx
    jmp     nwd_base_lp

nwd_chk_ext_ia:
    ; Also check $ATTRIBUTE_LIST for extension $INDEX_ROOT and $INDEX_ALLOCATION
    lea     rcx, [g_ntf_rec_main]
    lea     rdx, [rsp+48]
    mov     r8d, NTF_MAX_EXT_RECS
    xor     r9d, r9d                        ; wantAttrType = 0 (both 0x90 and 0xA0)
    mov     qword ptr [rsp+32], r12
    call    ntfs_collect_ext_recs
    cmp     eax, 0
    jl      nwd_corrupt
    jz      nwd_run_walk

    mov     r15d, eax
    xor     r14d, r14d
nwd_ext_ia_lp:
    cmp     r14d, r15d
    jae     nwd_run_walk
    mov     rcx, qword ptr [rsp+48 + r14*8]
    lea     rdx, [g_ntf_rec_ext]
    call    ntfs_read_mft_rec
    test    eax, eax
    jnz     nwd_cleanup_err
    lea     rsi, [g_ntf_rec_ext]
    movzx   ecx, word ptr [rsi + 20]
    mov     ebx, dword ptr [rsi + 24]
nwd_ext_ia_attr:
    cmp     ecx, ebx
    jae     nwd_ext_ia_next
    lea     rdi, [rsi + rcx]
    mov     eax, dword ptr [rdi]
    cmp     eax, NTF_AT_END
    je      nwd_ext_ia_next
    mov     edx, dword ptr [rdi + 4]
    cmp     edx, 24
    jb      nwd_corrupt
    lea     r8d, [ecx + edx]
    cmp     r8d, ebx
    ja      nwd_corrupt
    cmp     eax, NTF_AT_INDEX_ROOT
    je      nwd_ext_ir
    cmp     eax, NTF_AT_INDEX_ALLOC
    je      nwd_ext_ia
    jmp     nwd_ext_ia_adv

nwd_ext_ir:
    cmp     dword ptr [rbp-120], 0
    jne     nwd_ext_ia_adv
    mov     dword ptr [rbp-128], ecx
    mov     dword ptr [rbp-132], edx
    mov     rcx, rdi
    call    ntfs_attr_is_i30
    mov     ecx, dword ptr [rbp-128]
    mov     edx, dword ptr [rbp-132]
    test    eax, eax
    jz      nwd_ext_ia_adv
    cmp     byte ptr [rdi + 8], 0
    jne     nwd_corrupt
    mov     r8d, dword ptr [rdi + 16]
    movzx   r9d, word ptr [rdi + 20]
    cmp     r8d, 32
    jb      nwd_corrupt
    lea     eax, [r9d + r8d]
    cmp     eax, edx
    ja      nwd_corrupt
    lea     r10, [rdi + r9]
    mov     eax, dword ptr [r10 + 16]
    mov     r11d, dword ptr [r10 + 20]
    cmp     eax, 16
    jb      nwd_corrupt
    cmp     r11d, eax
    jb      nwd_corrupt
    lea     r9d, [r11d + 16]
    cmp     r9d, r8d
    ja      nwd_corrupt
    sub     r11d, eax
    cmp     r11d, 4096
    ja      nwd_corrupt
    mov     dword ptr [rbp-120], r11d
    mov     r8, qword ptr [rbp-112]
    lea     r10, [r10 + 16 + rax]
    xor     r9d, r9d
nwd_cp_ext_ir:
    cmp     r9d, r11d
    jae     nwd_ext_ia_adv
    mov     al, byte ptr [r10 + r9]
    mov     byte ptr [r8 + r9], al
    inc     r9d
    jmp     nwd_cp_ext_ir

nwd_ext_ia:
    mov     dword ptr [rbp-128], ecx
    mov     dword ptr [rbp-132], edx
    mov     rcx, rdi
    call    ntfs_attr_is_i30
    mov     ecx, dword ptr [rbp-128]
    mov     edx, dword ptr [rbp-132]
    test    eax, eax
    jz      nwd_ext_ia_adv
    cmp     byte ptr [rdi + 8], 1
    jne     nwd_corrupt
    cmp     edx, 64
    jb      nwd_corrupt
    movzx   eax, word ptr [rdi + 32]
    cmp     eax, edx
    jae     nwd_corrupt
    mov     r10d, dword ptr [rbp-116]
    cmp     r10d, NTF_MAX_DATA_RUNS
    jae     nwd_corrupt
    mov     r8, qword ptr [rbp-104]
    mov     r9d, r10d
    shl     r9d, 4
    add     r8, r9
    mov     r9d, NTF_MAX_DATA_RUNS
    sub     r9d, r10d
    mov     dword ptr [rbp-128], ecx
    mov     dword ptr [rbp-132], edx
    lea     rcx, [rdi + rax]
    sub     edx, eax
    call    ntfs_decode_runs
    mov     ecx, dword ptr [rbp-128]
    mov     edx, dword ptr [rbp-132]
    cmp     eax, 0
    jl      nwd_corrupt
    add     dword ptr [rbp-116], eax
nwd_ext_ia_adv:
    add     ecx, edx
    jmp     nwd_ext_ia_attr
nwd_ext_ia_next:
    inc     r14d
    jmp     nwd_ext_ia_lp

nwd_run_walk:
    mov     edx, dword ptr [rbp-120]        ; rootEntLen
    test    edx, edx
    jz      nwd_corrupt                     ; directory missing $INDEX_ROOT:$I30

    mov     eax, dword ptr [rbp-116]
    mov     dword ptr [rbp-96 + 24], eax    ; iaRunCnt

    mov     rcx, qword ptr [rbp-112]        ; rootCopyHeap
    lea     r8,  [rbp-96]                   ; dirCtx
    xor     r9d, r9d                        ; btreeDepth = 0
    call    ntfs_walk_index_entries
    jmp     nwd_cleanup_err

nwd_oom:
    mov     eax, EXIT_OOM
    jmp     nwd_cleanup_err

nwd_corrupt:
    mov     eax, EXIT_CORRUPT

nwd_cleanup_err:
    mov     ebx, eax
    mov     rcx, qword ptr [rbp-112]
    test    rcx, rcx
    jz      nwd_f1
    mov     edx, 4096
    call    mem_free
nwd_f1:
    mov     rcx, qword ptr [rbp-104]
    test    rcx, rcx
    jz      nwd_f2
    mov     edx, NTF_IA_HEAP_BYTES
    call    mem_free
nwd_f2:
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
ntfs_walk_dir endp

; =============================================================================
; ntfs_enum() -> eax = EXIT_*
; =============================================================================
public ntfs_enum
ntfs_enum proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_ntf_vis_cnt], 0
    mov     ecx, 5                          ; Root directory MFT record 5
    xor     edx, edx
    xor     r8d, r8d
    call    ntfs_walk_dir
    FRAME_EPILOG
    ret
ntfs_enum endp

; =============================================================================
; ntfs_lznt1_decompress(rcx = compBuf, edx = compLen, r8 = outBuf, r9d = outCap)
;   -> eax = EXIT_* (fills outBuf[0..outCap-1], zero-padding after 0x0000 end hdr)
; =============================================================================
ntfs_lznt1_decompress proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     rsi, rcx                        ; compCur
    lea     r12, [rcx + rdx]                ; compEnd
    mov     rdi, r8                         ; outBase
    mov     r13d, r9d                       ; outCap
    xor     r14d, r14d                      ; outPos

nld_chunk_lp:
    cmp     r14d, r13d
    jae     nld_ok

    lea     rax, [rsi + 2]
    cmp     rax, r12
    ja      nld_zero_rem

    movzx   eax, word ptr [rsi]
    add     rsi, 2
    test    eax, eax
    jz      nld_zero_rem                    ; 0x0000 = end of compressed unit

    mov     ecx, eax
    and     ecx, 0FFFh
    inc     ecx                             ; chunkCompLen (1..4096)
    lea     r15, [rsi + rcx]                ; chunkSrcEnd
    cmp     r15, r12
    ja      nld_corrupt

    test    eax, 8000h
    jnz     nld_comp_sub

    ; Uncompressed 4096-byte sub-chunk
    cmp     ecx, 4096
    jne     nld_corrupt
    mov     edx, r13d
    sub     edx, r14d
    cmp     edx, 4096
    jbe     nld_raw_cp
    mov     edx, 4096
nld_raw_cp:
    xor     eax, eax
nld_raw_lp:
    cmp     eax, edx
    jae     nld_raw_done
    mov     bl, byte ptr [rsi + rax]
    mov     ecx, r14d
    add     ecx, eax
    mov     byte ptr [rdi + rcx], bl
    inc     eax
    jmp     nld_raw_lp
nld_raw_done:
    mov     rsi, r15
    add     r14d, edx
    jmp     nld_chunk_lp

nld_comp_sub:
    ; LZNT1-compressed sub-chunk (produces up to 4096 bytes from r14d)
    xor     ebx, ebx                        ; subPos in 0..4096
nld_tag_lp:
    cmp     rsi, r15
    jae     nld_sub_done
    cmp     ebx, 4096
    jae     nld_corrupt

    movzx   r8d, byte ptr [rsi]             ; tag byte
    inc     rsi
    xor     r9d, r9d                        ; bit = 0..7

nld_bit_lp:
    cmp     r9d, 8
    jae     nld_tag_lp
    cmp     rsi, r15
    jae     nld_sub_done

    bt      r8d, r9d
    jc      nld_match

    ; Literal byte
    cmp     ebx, 4096
    jae     nld_corrupt
    mov     al, byte ptr [rsi]
    inc     rsi
    lea     ecx, [r14d + ebx]
    cmp     ecx, r13d
    jae     nld_lit_adv
    mov     byte ptr [rdi + rcx], al
nld_lit_adv:
    inc     ebx
    inc     r9d
    jmp     nld_bit_lp

nld_match:
    lea     rax, [rsi + 2]
    cmp     rax, r15
    ja      nld_corrupt
    test    ebx, ebx
    jz      nld_corrupt

    movzx   edx, word ptr [rsi]             ; tuple
    add     rsi, 2

    ; Adaptive split: v = ebx - 1; l_mask = 0xFFF; o_shift = 12
    lea     eax, [ebx - 1]
    mov     r10d, 0FFFh
    mov     ecx, 12
nld_shift_lp:
    cmp     eax, 10h
    jb      nld_shift_done
    shr     eax, 1
    shr     r10d, 1
    dec     ecx
    jmp     nld_shift_lp
nld_shift_done:
    mov     eax, edx
    and     eax, r10d
    add     eax, 3                          ; match_len
    shr     edx, cl
    inc     edx                             ; match_dist

    cmp     edx, ebx
    ja      nld_corrupt
    lea     r11d, [ebx + eax]
    cmp     r11d, 4096
    ja      nld_corrupt

nld_mcopy:
    mov     ecx, r14d
    add     ecx, ebx
    cmp     ecx, r13d
    jae     nld_mc_adv
    mov     r10d, ecx
    sub     r10d, edx
    mov     r11b, byte ptr [rdi + r10]
    mov     byte ptr [rdi + rcx], r11b
nld_mc_adv:
    inc     ebx
    dec     eax
    jnz     nld_mcopy

    inc     r9d
    jmp     nld_bit_lp

nld_sub_done:
    add     r14d, ebx
    cmp     r14d, r13d
    jbe     nld_chunk_lp
    mov     r14d, r13d
    jmp     nld_ok

nld_zero_rem:
    cmp     r14d, r13d
    jae     nld_ok
    lea     rcx, [rdi + r14]
    mov     edx, r13d
    sub     edx, r14d
    call    secure_zero

nld_ok:
    xor     eax, eax
    jmp     nld_out

nld_corrupt:
    mov     eax, EXIT_CORRUPT

nld_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ntfs_lznt1_decompress endp

; =============================================================================
; ntfs_extract_entry(rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================
public ntfs_extract_entry
ntfs_extract_entry proc frame
    FRAME_PROLOG 1248
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-72]       remDataSize (dq)
    ; [rbp-80]       initSize (dq)
    ; [rbp-88]       emittedPos (dq)
    ; [rbp-96]       totalRunCnt (dd), isCompressed (dd at -92)
    ; [rbp-104]      compInHeap (dq)
    ; [rbp-112]      compOutHeap (dq)
    ; [rbp-120]      unitBytes (dq)
    ; [rbp-128]      mftRecNum (dq)
    ; [rsp+48..1071] extRecNums[128] (1024 bytes)
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    mov     qword ptr [rbp-104], 0
    mov     qword ptr [rbp-112], 0
    mov     dword ptr [rbp-96], 0
    mov     dword ptr [rbp-92], 0

    mov     rax, qword ptr [rcx + IDXE_size]
    mov     qword ptr [rbp-72], rax         ; remDataSize
    mov     qword ptr [rbp-80], rax         ; default initSize
    mov     qword ptr [rbp-88], 0           ; emittedPos

    mov     r12, qword ptr [rcx + IDXE_offset] ; mftRecNum
    mov     qword ptr [rbp-128], r12
    mov     r13d, dword ptr [rcx + IDXE_stored]; expectedSeq

    mov     rcx, r12
    lea     rdx, [g_ntf_rec_main]
    call    ntfs_read_mft_rec
    test    eax, eax
    jnz     nee_out

    lea     rsi, [g_ntf_rec_main]
    movzx   eax, word ptr [rsi + 16]
    cmp     eax, r13d
    jne     nee_corrupt

    cmp     qword ptr [rbp-72], 0
    je      nee_ok

    ; Scan base record for unnamed $DATA (0x80)
    movzx   ecx, word ptr [rsi + 20]
    mov     ebx, dword ptr [rsi + 24]
nee_base_lp:
    cmp     ecx, ebx
    jae     nee_chk_ext
    lea     rdi, [rsi + rcx]
    mov     eax, dword ptr [rdi]
    cmp     eax, NTF_AT_END
    je      nee_chk_ext
    mov     edx, dword ptr [rdi + 4]
    cmp     edx, 24
    jb      nee_corrupt
    lea     r8d, [ecx + edx]
    cmp     r8d, ebx
    ja      nee_corrupt

    cmp     eax, NTF_AT_DATA
    jne     nee_base_next
    cmp     byte ptr [rdi + 9], 0
    jne     nee_base_next
    test    word ptr [rdi + 12], NTF_AF_ENCRYPTED
    jnz     nee_unsup

    cmp     byte ptr [rdi + 8], 0
    jne     nee_base_nonres

    ; Resident unnamed $DATA!
    mov     r8d, dword ptr [rdi + 16]       ; val_len
    movzx   eax, word ptr [rdi + 20]        ; val_ofs
    lea     ecx, [eax + r8d]
    cmp     ecx, edx
    ja      nee_corrupt
    cmp     r8, qword ptr [rbp-72]
    jb      nee_corrupt
    lea     rcx, [rdi + rax]
    mov     edx, dword ptr [rbp-72]
    call    tcvc_sink_write
    jmp     nee_out

nee_base_nonres:
    cmp     edx, 64
    jb      nee_corrupt
    test    word ptr [rdi + 12], NTF_AF_COMPRESSED
    jz      nee_bnr_nocomp
    cmp     byte ptr [rdi + 34], 4          ; LZNT1 compression_unit must be 4 (16 clusters)
    jne     nee_unsup
    mov     dword ptr [rbp-92], 1
nee_bnr_nocomp:
    cmp     qword ptr [rdi + 16], 0
    jne     nee_bnr_runs
    mov     rax, qword ptr [rdi + 56]       ; initialized_size
    mov     qword ptr [rbp-80], rax
nee_bnr_runs:
    movzx   eax, word ptr [rdi + 32]
    cmp     eax, edx
    jae     nee_corrupt
    mov     r10d, dword ptr [rbp-96]
    cmp     r10d, NTF_MAX_DATA_RUNS
    jae     nee_corrupt
    lea     r8,  [g_ntf_data_runs]
    mov     r9d, r10d
    shl     r9d, 4
    add     r8,  r9
    mov     r9d, NTF_MAX_DATA_RUNS
    sub     r9d, r10d
    mov     dword ptr [rbp-136], ecx
    mov     dword ptr [rbp-140], edx
    lea     rcx, [rdi + rax]
    sub     edx, eax
    call    ntfs_decode_runs
    mov     ecx, dword ptr [rbp-136]
    mov     edx, dword ptr [rbp-140]
    cmp     eax, 0
    jl      nee_corrupt
    add     dword ptr [rbp-96], eax

nee_base_next:
    add     ecx, edx
    jmp     nee_base_lp

nee_chk_ext:
    ; Append any unnamed $DATA runs from $ATTRIBUTE_LIST extension records
    lea     rcx, [g_ntf_rec_main]
    lea     rdx, [rsp+48]
    mov     r8d, NTF_MAX_EXT_RECS
    mov     r9d, NTF_AT_DATA
    mov     rax, qword ptr [rbp-128]
    mov     qword ptr [rsp+32], rax
    call    ntfs_collect_ext_recs
    cmp     eax, 0
    jl      nee_corrupt
    jz      nee_have_runs

    mov     r15d, eax
    xor     r14d, r14d
nee_ext_lp:
    cmp     r14d, r15d
    jae     nee_have_runs
    mov     rcx, qword ptr [rsp+48 + r14*8]
    lea     rdx, [g_ntf_rec_ext]
    call    ntfs_read_mft_rec
    test    eax, eax
    jnz     nee_out
    lea     rsi, [g_ntf_rec_ext]
    movzx   ecx, word ptr [rsi + 20]
    mov     ebx, dword ptr [rsi + 24]
nee_ext_attr:
    cmp     ecx, ebx
    jae     nee_ext_next
    lea     rdi, [rsi + rcx]
    mov     eax, dword ptr [rdi]
    cmp     eax, NTF_AT_END
    je      nee_ext_next
    mov     edx, dword ptr [rdi + 4]
    cmp     edx, 24
    jb      nee_corrupt
    lea     r8d, [ecx + edx]
    cmp     r8d, ebx
    ja      nee_corrupt
    cmp     eax, NTF_AT_DATA
    jne     nee_ext_adv
    cmp     byte ptr [rdi + 9], 0
    jne     nee_ext_adv
    test    word ptr [rdi + 12], NTF_AF_ENCRYPTED
    jnz     nee_unsup
    cmp     byte ptr [rdi + 8], 0
    jne     nee_ext_nr
    ; Resident $DATA inside extension record
    mov     r8d, dword ptr [rdi + 16]
    movzx   eax, word ptr [rdi + 20]
    lea     ecx, [eax + r8d]
    cmp     ecx, edx
    ja      nee_corrupt
    cmp     r8, qword ptr [rbp-72]
    jb      nee_corrupt
    lea     rcx, [rdi + rax]
    mov     edx, dword ptr [rbp-72]
    call    tcvc_sink_write
    jmp     nee_out
nee_ext_nr:
    cmp     edx, 64
    jb      nee_corrupt
    test    word ptr [rdi + 12], NTF_AF_COMPRESSED
    jz      nee_enr_nc
    cmp     byte ptr [rdi + 34], 4
    jne     nee_unsup
    mov     dword ptr [rbp-92], 1
nee_enr_nc:
    cmp     qword ptr [rdi + 16], 0
    jne     nee_enr_runs
    mov     rax, qword ptr [rdi + 56]
    mov     qword ptr [rbp-80], rax
nee_enr_runs:
    movzx   eax, word ptr [rdi + 32]
    cmp     eax, edx
    jae     nee_corrupt
    mov     r10d, dword ptr [rbp-96]
    cmp     r10d, NTF_MAX_DATA_RUNS
    jae     nee_corrupt
    lea     r8,  [g_ntf_data_runs]
    mov     r9d, r10d
    shl     r9d, 4
    add     r8,  r9
    mov     r9d, NTF_MAX_DATA_RUNS
    sub     r9d, r10d
    mov     dword ptr [rbp-136], ecx
    mov     dword ptr [rbp-140], edx
    lea     rcx, [rdi + rax]
    sub     edx, eax
    call    ntfs_decode_runs
    mov     ecx, dword ptr [rbp-136]
    mov     edx, dword ptr [rbp-140]
    cmp     eax, 0
    jl      nee_corrupt
    add     dword ptr [rbp-96], eax
nee_ext_adv:
    add     ecx, edx
    jmp     nee_ext_attr
nee_ext_next:
    inc     r14d
    jmp     nee_ext_lp

nee_have_runs:
    cmp     dword ptr [rbp-96], 0
    je      nee_corrupt

    cmp     dword ptr [rbp-92], 0
    jne     nee_stream_lznt1

    ; ---- Uncompressed / Sparse Non-Resident Stream --------------------------
    lea     rcx, [g_ntf_zbuf]
    mov     edx, 65536
    call    secure_zero

    xor     r12d, r12d                      ; runIdx
    mov     r13, qword ptr [rbp-72]         ; remDataSize

nee_nr_run_lp:
    test    r13, r13
    jz      nee_ok
    cmp     r12d, dword ptr [rbp-96]
    jae     nee_tail_uninit

    mov     eax, r12d
    shl     rax, 4
    lea     rsi, [g_ntf_data_runs]
    mov     r14, qword ptr [rsi + rax]      ; vcn_len
    mov     r15, qword ptr [rsi + rax + 8]  ; lcn (-1 = sparse)
    imul    r14, qword ptr [g_ntf_cbytes]   ; runBytes

    cmp     r14, r13
    jbe     nee_nr_rlen
    mov     r14, r13
nee_nr_rlen:
    cmp     r15, -1
    je      nee_nr_sparse

    imul    r15, qword ptr [g_ntf_cbytes]   ; volOff
nee_nr_phys_lp:
    test    r14, r14
    jz      nee_nr_next_run
    mov     ebx, 65536
    cmp     r14, rbx
    jae     nee_nr_pchk
    mov     ebx, r14d
nee_nr_pchk:
    ; Check initialized_size boundary
    mov     rax, qword ptr [rbp-88]
    cmp     rax, qword ptr [rbp-80]
    jae     nee_nr_zero_p                   ; wholly past initialized_size

    mov     rdx, qword ptr [rbp-80]
    sub     rdx, rax
    cmp     rdx, rbx
    jae     nee_nr_do_rd
    mov     ebx, edx                        ; split at initialized_size boundary!
nee_nr_do_rd:
    mov     rcx, r15
    lea     rdx, [g_ntf_iobuf]
    mov     r8d, ebx
    call    tcvc_read_bytes
    test    eax, eax
    jnz     nee_cleanup
    lea     rcx, [g_ntf_iobuf]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     nee_cleanup
    jmp     nee_nr_padv

nee_nr_zero_p:
    lea     rcx, [g_ntf_zbuf]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     nee_cleanup

nee_nr_padv:
    add     r15, rbx
    add     qword ptr [rbp-88], rbx
    sub     r14, rbx
    sub     r13, rbx
    jmp     nee_nr_phys_lp

nee_nr_sparse:
    test    r14, r14
    jz      nee_nr_next_run
    mov     ebx, 65536
    cmp     r14, rbx
    jae     nee_nr_sp_wr
    mov     ebx, r14d
nee_nr_sp_wr:
    lea     rcx, [g_ntf_zbuf]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     nee_cleanup
    add     qword ptr [rbp-88], rbx
    sub     r14, rbx
    sub     r13, rbx
    jmp     nee_nr_sparse

nee_nr_next_run:
    inc     r12d
    jmp     nee_nr_run_lp

nee_tail_uninit:
    ; If runs ended at initialized_size < data_size, emit trailing zeros
    mov     rax, qword ptr [rbp-88]
    cmp     rax, qword ptr [rbp-80]
    jb      nee_corrupt                     ; premature end before initialized_size!
nee_tail_lp:
    test    r13, r13
    jz      nee_ok
    mov     ebx, 65536
    cmp     r13, rbx
    jae     nee_tail_wr
    mov     ebx, r13d
nee_tail_wr:
    lea     rcx, [g_ntf_zbuf]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     nee_cleanup
    sub     r13, rbx
    jmp     nee_tail_lp

    ; ---- LZNT1 Compressed Stream (16-cluster compression units) -------------
nee_stream_lznt1:
    mov     rax, qword ptr [g_ntf_cbytes]
    shl     rax, 4                          ; unitBytes = 16 * cbytes
    cmp     rax, 2000000h                   ; <= 32 MiB sanity
    ja      nee_unsup
    mov     qword ptr [rbp-120], rax

    mov     rcx, rax
    call    mem_alloc
    test    rax, rax
    jz      nee_oom
    mov     qword ptr [rbp-104], rax        ; compInHeap

    mov     rcx, qword ptr [rbp-120]
    call    mem_alloc
    test    rax, rax
    jz      nee_oom
    mov     qword ptr [rbp-112], rax        ; compOutHeap

    xor     r12d, r12d                      ; curRunIdx
    xor     r13, r13                        ; inRunVcnOff
    mov     r14, qword ptr [rbp-72]         ; remDataSize

nee_lz_unit_lp:
    test    r14, r14
    jz      nee_ok

    ; Gather 16 clusters across runs into compInHeap, counting physClusters vs sparseClusters
    xor     ebx, ebx                        ; clusIdxInUnit (0..15)
    xor     edi, edi                        ; physClusters (before sparse tail)
    xor     r15d, r15d                      ; seenSparseFlag

nee_lz_clus_lp:
    cmp     ebx, 16
    jae     nee_lz_unit_got

    cmp     r12d, dword ptr [rbp-96]
    jae     nee_lz_implicit_sparse

    mov     eax, r12d
    shl     rax, 4
    lea     rsi, [g_ntf_data_runs]
    mov     rcx, qword ptr [rsi + rax]      ; run_vcn_len
    mov     rdx, qword ptr [rsi + rax + 8]  ; run_lcn

    cmp     rdx, -1
    je      nee_lz_sparse_c

    ; Physical cluster inside unit: must not follow a sparse cluster in same 16-clus unit!
    test    r15d, r15d
    jnz     nee_corrupt

    add     rdx, r13
    imul    rdx, qword ptr [g_ntf_cbytes]   ; volOff
    mov     rcx, rdx
    mov     rax, rdi
    imul    rax, qword ptr [g_ntf_cbytes]
    mov     rdx, qword ptr [rbp-104]
    add     rdx, rax
    mov     r8,  qword ptr [g_ntf_cbytes]
    call    tcvc_read_bytes
    test    eax, eax
    jnz     nee_cleanup
    inc     edi
    jmp     nee_lz_adv_c

nee_lz_sparse_c:
    mov     r15d, 1

nee_lz_adv_c:
    inc     r13
    mov     eax, r12d
    shl     rax, 4
    lea     rsi, [g_ntf_data_runs]
    cmp     r13, qword ptr [rsi + rax]
    jb      nee_lz_next_c
    xor     r13d, r13d
    inc     r12d
    jmp     nee_lz_next_c

nee_lz_implicit_sparse:
    mov     r15d, 1

nee_lz_next_c:
    inc     ebx
    jmp     nee_lz_clus_lp

nee_lz_unit_got:
    ; emitLen = min(r14, unitBytes)
    mov     rbx, qword ptr [rbp-120]
    cmp     r14, rbx
    jae     nee_lz_elen
    mov     rbx, r14
nee_lz_elen:
    test    edi, edi
    jz      nee_lz_all_sparse
    cmp     edi, 16
    je      nee_lz_all_raw

    ; Compressed unit (1..15 physical clusters + sparse tail)!
    mov     rcx, qword ptr [rbp-104]
    mov     eax, edi
    imul    rax, qword ptr [g_ntf_cbytes]
    mov     edx, eax
    mov     r8,  qword ptr [rbp-112]
    mov     r9d, ebx
    call    ntfs_lznt1_decompress
    test    eax, eax
    jnz     nee_cleanup

    mov     rcx, qword ptr [rbp-112]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     nee_cleanup
    sub     r14, rbx
    jmp     nee_lz_unit_lp

nee_lz_all_raw:
    mov     rcx, qword ptr [rbp-104]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     nee_cleanup
    sub     r14, rbx
    jmp     nee_lz_unit_lp

nee_lz_all_sparse:
    mov     rcx, qword ptr [rbp-112]
    mov     edx, ebx
    call    secure_zero
    mov     rcx, qword ptr [rbp-112]
    mov     edx, ebx
    call    tcvc_sink_write
    test    eax, eax
    jnz     nee_cleanup
    sub     r14, rbx
    jmp     nee_lz_unit_lp

nee_ok:
    xor     eax, eax
    jmp     nee_cleanup

nee_oom:
    mov     eax, EXIT_OOM
    jmp     nee_cleanup
nee_unsup:
    mov     eax, EXIT_UNSUPPORTED
    jmp     nee_cleanup
nee_corrupt:
    mov     eax, EXIT_CORRUPT

nee_cleanup:
    mov     ebx, eax
    lea     rcx, [g_ntf_iobuf]
    mov     edx, 65536
    call    secure_zero

    mov     rcx, qword ptr [rbp-104]
    test    rcx, rcx
    jz      nee_f1
    mov     rdx, qword ptr [rbp-120]
    call    mem_free
nee_f1:
    mov     rcx, qword ptr [rbp-112]
    test    rcx, rcx
    jz      nee_f2
    mov     rdx, qword ptr [rbp-120]
    call    mem_free
nee_f2:
    mov     eax, ebx

nee_out:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
ntfs_extract_entry endp

end
