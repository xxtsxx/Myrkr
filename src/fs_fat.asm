; =============================================================================
; fs_fat.asm - Read-Only FAT12 / FAT16 / FAT32 (+ VFAT UTF-16LE LFN) Parser
; -----------------------------------------------------------------------------
; All reads go through tcvc_read_bytes (backed by tcvc.asm's 64 KiB decrypted
; sector cache).  Every BPB field, cluster chain, directory depth, and LFN
; sequence is treated as untrusted input under the XTS threat model.
;
; Exports:
;   fat_probe         () -> eax: 1..3 (FAT12/16/32), 0 = not FAT, -1 = corrupt
;   fat_enum          () -> eax = EXIT_*
;   fat_extract_entry (rcx = idxEntPtr) -> eax = EXIT_*
; =============================================================================

include macros.inc

extern tcvc_read_bytes:proc
extern tcvc_idx_add:proc
extern tcvc_sink_write:proc
extern secure_zero:proc
extern MultiByteToWideChar:proc
extern WideCharToMultiByte:proc

externdef g_tcvc_data_size:qword

FAT_CP_OEM              equ 1
FAT_CP_UTF8             equ 65001
FAT_WC_ERR_INVALID      equ 80h

FAT_ATTR_VOLUME_ID      equ 08h
FAT_ATTR_DIRECTORY      equ 10h
FAT_ATTR_LFN            equ 0Fh

FAT_MAX_DEPTH           equ 64
FAT_MAX_DIRS            equ 16384
FAT_MAX_DIR_ENTRIES     equ 262144      ; cap 8 MiB per directory

.data?
align 8
g_fat_fat_off           dq ?
g_fat_fat_end           dq ?
g_fat_root_off          dq ?
g_fat_data_off          dq ?
g_fat_max_fsize         dq ?

g_fat_type              dd ?
g_fat_cbytes            dd ?
g_fat_nclus             dd ?
g_fat_maxclus           dd ?
g_fat_root_ent          dd ?
g_fat_root_clus         dd ?
g_fat_vis_cnt           dd ?
g_fat_lfn_max           dd ?

align 4
g_fat_vis_clus          dd FAT_MAX_DIRS dup (?)

align 2
g_fat_lfn_w             dw 272 dup (?)
g_fat_oem_w             dw 16 dup (?)

align 16
g_fat_path              db 4096 dup (?)
g_fat_comp8             db 1024 dup (?)
g_fat_oem8              db 16 dup (?)
g_fat_iobuf             db 65536 dup (?)

.code

; =============================================================================
; fat_has_hint(rcx = boot512) -> eax = 1 if sector looks intended as FAT
; Checks "FAT" at +54 or +82, or standard x86 JMP boot opcode + 0xAA55 sig.
; =============================================================================
fat_has_hint proc
    cmp     word ptr [rcx+510], 0AA55h
    jne     fhh_chk_str
    movzx   eax, byte ptr [rcx]
    cmp     al, 0EBh
    je      fhh_yes
    cmp     al, 0E9h
    je      fhh_yes
fhh_chk_str:
    cmp     dword ptr [rcx+54], 031544146h  ; "FAT1"
    je      fhh_yes
    cmp     dword ptr [rcx+82], 033544146h  ; "FAT3"
    je      fhh_yes
    xor     eax, eax
    ret
fhh_yes:
    mov     eax, 1
    ret
fat_has_hint endp

; =============================================================================
; fat_probe() -> eax: 1=FAT12, 2=FAT16, 3=FAT32, 0=not FAT, -1=corrupt FAT
; =============================================================================
public fat_probe
fat_probe proc frame
    FRAME_PROLOG 608
    ; [rbp-16..40] saved rbx, rsi, rdi, r12
    ; [rsp+32..543] 512-byte boot sector buffer
    mov     qword ptr [rbp-16], rbx
    mov     qword ptr [rbp-24], rsi
    mov     qword ptr [rbp-32], rdi
    mov     qword ptr [rbp-40], r12

    cmp     qword ptr [g_tcvc_data_size], 1024
    jb      fp_not_fat

    xor     ecx, ecx
    lea     rdx, [rsp+32]
    mov     r8d, 512
    call    tcvc_read_bytes
    test    eax, eax
    jnz     fp_not_fat

    lea     rsi, [rsp+32]

    ; Reject if OEM is explicitly EXFAT or NTFS
    mov     rax, qword ptr [rsi+3]
    mov     rdx, 02020205441465845h         ; "EXFAT   "
    cmp     rax, rdx
    je      fp_not_fat
    mov     rdx, 0202020205346544Eh         ; "NTFS    "
    cmp     rax, rdx
    je      fp_not_fat

    ; Check 0xAA55 boot signature at +510
    cmp     word ptr [rsi+510], 0AA55h
    jne     fp_maybe_corrupt

    ; BytesPerSector (+11, u16): power of two in 512..4096
    movzx   ebx, word ptr [rsi+11]
    cmp     ebx, 512
    jb      fp_maybe_corrupt
    cmp     ebx, 4096
    ja      fp_maybe_corrupt
    lea     eax, [ebx - 1]
    test    ebx, eax
    jnz     fp_maybe_corrupt

    ; SectorsPerCluster (+13, u8): power of two in 1..128
    movzx   edi, byte ptr [rsi+13]
    test    edi, edi
    jz      fp_maybe_corrupt
    cmp     edi, 128
    ja      fp_maybe_corrupt
    lea     eax, [edi - 1]
    test    edi, eax
    jnz     fp_maybe_corrupt

    ; ReservedSectorCount (+14, u16) >= 1
    movzx   r8d, word ptr [rsi+14]
    test    r8d, r8d
    jz      fp_maybe_corrupt

    ; NumFATs (+16, u8) in 1..4
    movzx   r9d, byte ptr [rsi+16]
    test    r9d, r9d
    jz      fp_maybe_corrupt
    cmp     r9d, 4
    ja      fp_maybe_corrupt

    ; Media (+21, u8): 0xF0 or >= 0xF8
    movzx   eax, byte ptr [rsi+21]
    cmp     al, 0F0h
    je      fp_media_ok
    cmp     al, 0F8h
    jb      fp_maybe_corrupt
fp_media_ok:

    ; RootEntCnt (+17, u16) and FATSz16 (+22, u16)
    movzx   r10d, word ptr [rsi+17]         ; RootEntCnt
    movzx   r11d, word ptr [rsi+22]         ; FATSz16

    ; TotSec = u16[+19] ? u16[+19] : u32[+32]
    movzx   r12d, word ptr [rsi+19]
    test    r12d, r12d
    jnz     fp_tot_ok
    mov     r12d, dword ptr [rsi+32]
    test    r12d, r12d
    jz      fp_maybe_corrupt
fp_tot_ok:

    ; Check TotSec * BytesPerSector <= g_tcvc_data_size
    mov     rax, r12
    imul    rax, rbx
    cmp     rax, qword ptr [g_tcvc_data_size]
    ja      fp_corrupt_if_hint

    ; FATSz: if FATSz16 != 0 -> FAT12/16; else FATSz32 (+36) -> FAT32
    test    r11d, r11d
    jnz     fp_fatsz_1216
    ; FAT32 requires RootEntCnt == 0 and FSVer (+42) == 0
    test    r10d, r10d
    jnz     fp_corrupt_if_hint
    cmp     word ptr [rsi+42], 0
    jne     fp_corrupt_if_hint
    mov     r11d, dword ptr [rsi+36]        ; FATSz32
    test    r11d, r11d
    jz      fp_corrupt_if_hint
    jmp     fp_fatsz_done

fp_fatsz_1216:
    ; FAT12/16 requires RootEntCnt > 0
    test    r10d, r10d
    jz      fp_corrupt_if_hint

fp_fatsz_done:
    ; RootDirSectors = ((RootEntCnt * 32) + (bps - 1)) / bps
    mov     eax, r10d
    shl     eax, 5
    lea     eax, [eax + ebx - 1]
    xor     edx, edx
    div     ebx
    mov     ecx, eax                        ; RootDirSectors

    ; FirstDataSector = RsvdSecCnt + NumFATs * FATSz + RootDirSectors
    mov     rax, r9
    imul    rax, r11                        ; NumFATs * FATSz
    add     rax, r8                         ; + RsvdSecCnt
    mov     rdx, rax                        ; rdx = RootDirStartSector
    add     rax, rcx                        ; rax = FirstDataSector
    cmp     rax, r12
    jae     fp_corrupt_if_hint

    ; DataSec = TotSec - FirstDataSector; CountofClusters = DataSec / SecPerClus
    mov     rcx, r12
    sub     rcx, rax                        ; DataSec
    mov     qword ptr [rbp-48], rax         ; save FirstDataSector
    mov     qword ptr [rbp-56], rdx         ; save RootDirStartSector
    mov     rax, rcx
    mov     ecx, edi                        ; SecPerClus
    xor     edx, edx
    div     rcx                             ; rax = CountofClusters
    mov     rdx, qword ptr [rbp-56]         ; RootDirStartSector
    mov     rcx, qword ptr [rbp-48]         ; FirstDataSector

    test    rax, rax
    jz      fp_corrupt_if_hint
    cmp     rax, 0FFFFFF5h
    ja      fp_corrupt_if_hint

    ; Populate geometry globals
    mov     dword ptr [g_fat_nclus], eax
    lea     r9d, [eax + 1]
    mov     dword ptr [g_fat_maxclus], r9d
    mov     dword ptr [g_fat_root_ent], r10d

    mov     r9d, ebx
    imul    r9d, edi
    mov     dword ptr [g_fat_cbytes], r9d

    ; g_fat_max_fsize = CountofClusters * ClusterBytes
    mov     r9, rax
    mov     eax, dword ptr [g_fat_cbytes]
    imul    r9, rax
    mov     qword ptr [g_fat_max_fsize], r9

    ; Byte offsets: fat_off, fat_end, root_off, data_off
    mov     rax, r8                         ; RsvdSecCnt
    imul    rax, rbx
    mov     qword ptr [g_fat_fat_off], rax

    mov     r9, r11                         ; FATSz
    imul    r9, rbx
    add     r9, rax
    mov     qword ptr [g_fat_fat_end], r9

    imul    rdx, rbx                        ; RootDirStartSector * bps
    mov     qword ptr [g_fat_root_off], rdx

    imul    rcx, rbx                        ; FirstDataSector * bps
    mov     qword ptr [g_fat_data_off], rcx

    ; Classify FAT12 / FAT16 / FAT32
    cmp     word ptr [rsi+22], 0
    je      fp_is_fat32

    mov     eax, dword ptr [g_fat_nclus]
    cmp     eax, 4085
    jb      fp_is_fat12
    mov     dword ptr [g_fat_type], TCVC_FS_FAT16
    mov     dword ptr [g_fat_root_clus], 0
    ; Verify FAT16 table fits (maxclus + 1) * 2 <= FATSz * bps
    mov     eax, dword ptr [g_fat_maxclus]
    inc     eax
    shl     rax, 1
    add     rax, qword ptr [g_fat_fat_off]
    cmp     rax, qword ptr [g_fat_fat_end]
    ja      fp_corrupt
    mov     eax, TCVC_FS_FAT16
    jmp     fp_out

fp_is_fat12:
    mov     dword ptr [g_fat_type], TCVC_FS_FAT12
    mov     dword ptr [g_fat_root_clus], 0
    ; Verify FAT12 table fits ((maxclus * 3) / 2 + 2) <= FATSz * bps
    mov     eax, dword ptr [g_fat_maxclus]
    mov     ecx, eax
    shr     ecx, 1
    add     eax, ecx
    add     eax, 2
    add     rax, qword ptr [g_fat_fat_off]
    cmp     rax, qword ptr [g_fat_fat_end]
    ja      fp_corrupt
    mov     eax, TCVC_FS_FAT12
    jmp     fp_out

fp_is_fat32:
    mov     eax, dword ptr [rsi+44]         ; BPB_RootClus
    and     eax, 0FFFFFFFh
    cmp     eax, 2
    jb      fp_corrupt
    cmp     eax, dword ptr [g_fat_maxclus]
    ja      fp_corrupt
    mov     dword ptr [g_fat_root_clus], eax
    mov     dword ptr [g_fat_type], TCVC_FS_FAT32
    ; Verify FAT32 table fits (maxclus + 1) * 4 <= FATSz * bps
    mov     eax, dword ptr [g_fat_maxclus]
    inc     eax
    shl     rax, 2
    add     rax, qword ptr [g_fat_fat_off]
    cmp     rax, qword ptr [g_fat_fat_end]
    ja      fp_corrupt
    mov     eax, TCVC_FS_FAT32
    jmp     fp_out

fp_maybe_corrupt:
fp_corrupt_if_hint:
    mov     rcx, rsi
    call    fat_has_hint
    test    eax, eax
    jnz     fp_corrupt
fp_not_fat:
    xor     eax, eax
    jmp     fp_out

fp_corrupt:
    mov     eax, -1

fp_out:
    mov     rbx, qword ptr [rbp-16]
    mov     rsi, qword ptr [rbp-24]
    mov     rdi, qword ptr [rbp-32]
    mov     r12, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
fat_probe endp

; =============================================================================
; fat_next_cluster(ecx = cluster) -> eax:
;   2..maxclus = next cluster
;   0          = end of chain (EOC)
;   -1         = corrupt / bad / free / I/O error
; =============================================================================
fat_next_cluster proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rbx

    cmp     ecx, 2
    jb      fnc_bad
    cmp     ecx, dword ptr [g_fat_maxclus]
    ja      fnc_bad

    mov     ebx, ecx
    mov     eax, dword ptr [g_fat_type]
    cmp     eax, TCVC_FS_FAT16
    je      fnc_16
    cmp     eax, TCVC_FS_FAT32
    je      fnc_32

    ; FAT12: off = cluster + (cluster >> 1)
    mov     ecx, ebx
    shr     ecx, 1
    add     ecx, ebx
    add     rcx, qword ptr [g_fat_fat_off]
    lea     rax, [rcx + 2]
    cmp     rax, qword ptr [g_fat_fat_end]
    ja      fnc_bad
    lea     rdx, [rbp-24]
    mov     r8d, 2
    call    tcvc_read_bytes
    test    eax, eax
    jnz     fnc_bad
    movzx   eax, word ptr [rbp-24]
    test    ebx, 1
    jz      fnc_12_even
    shr     eax, 4
    jmp     fnc_12_chk
fnc_12_even:
    and     eax, 0FFFh
fnc_12_chk:
    cmp     eax, 0FF8h
    jae     fnc_eoc
    jmp     fnc_chk_valid

fnc_16:
    mov     ecx, ebx
    shl     rcx, 1
    add     rcx, qword ptr [g_fat_fat_off]
    lea     rax, [rcx + 2]
    cmp     rax, qword ptr [g_fat_fat_end]
    ja      fnc_bad
    lea     rdx, [rbp-24]
    mov     r8d, 2
    call    tcvc_read_bytes
    test    eax, eax
    jnz     fnc_bad
    movzx   eax, word ptr [rbp-24]
    cmp     eax, 0FFF8h
    jae     fnc_eoc
    jmp     fnc_chk_valid

fnc_32:
    mov     ecx, ebx
    shl     rcx, 2
    add     rcx, qword ptr [g_fat_fat_off]
    lea     rax, [rcx + 4]
    cmp     rax, qword ptr [g_fat_fat_end]
    ja      fnc_bad
    lea     rdx, [rbp-24]
    mov     r8d, 4
    call    tcvc_read_bytes
    test    eax, eax
    jnz     fnc_bad
    mov     eax, dword ptr [rbp-24]
    and     eax, 0FFFFFFFh
    cmp     eax, 0FFFFFF8h
    jae     fnc_eoc

fnc_chk_valid:
    cmp     eax, 2
    jb      fnc_bad
    cmp     eax, dword ptr [g_fat_maxclus]
    ja      fnc_bad
    cmp     eax, ebx                        ; reject self-loop FAT[c] == c
    je      fnc_bad
    jmp     fnc_out

fnc_eoc:
    xor     eax, eax
    jmp     fnc_out

fnc_bad:
    mov     eax, -1

fnc_out:
    mov     rbx, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
fat_next_cluster endp

; =============================================================================
; fat_sfn_checksum(rcx = ent32) -> al = VFAT 8.3 checksum over ent[0..10]
; =============================================================================
fat_sfn_checksum proc
    xor     eax, eax
    xor     edx, edx
fsc_lp:
    mov     r8d, eax
    and     r8d, 1
    shl     r8d, 7
    shr     eax, 1
    add     eax, r8d
    movzx   r8d, byte ptr [rcx + rdx]
    add     eax, r8d
    and     eax, 0FFh
    inc     edx
    cmp     edx, 11
    jb      fsc_lp
    ret
fat_sfn_checksum endp

; =============================================================================
; fat_decode_sfn(rcx = ent32) -> eax = UTF-8 byte length in g_fat_comp8 (0 = bad)
; =============================================================================
fat_decode_sfn proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], rsi
    mov     qword ptr [rbp-24], rdi

    mov     rsi, rcx
    lea     rdi, [g_fat_oem8]

    ; Base length: trim trailing spaces from ent[0..7]
    mov     r8d, 8
fds_trim_b:
    test    r8d, r8d
    jz      fds_bad
    cmp     byte ptr [rsi + r8 - 1], 20h
    jne     fds_copy_b
    dec     r8d
    jmp     fds_trim_b

fds_copy_b:
    movzx   r10d, byte ptr [rsi + 12]       ; NTRes case flags
    xor     ecx, ecx
    xor     r11d, r11d                      ; non-ASCII flag
fds_cb_lp:
    movzx   eax, byte ptr [rsi + rcx]
    test    ecx, ecx
    jnz     fds_cb_n0
    cmp     al, 05h                         ; 0x05 -> 0xE5 KANJI escape
    jne     fds_cb_n0
    mov     al, 0E5h
fds_cb_n0:
    cmp     al, 80h
    jb      fds_cb_case
    mov     r11d, 1
    jmp     fds_cb_st
fds_cb_case:
    test    r10d, 08h                       ; lowercase base
    jz      fds_cb_st
    cmp     al, 'A'
    jb      fds_cb_st
    cmp     al, 'Z'
    ja      fds_cb_st
    add     al, 20h
fds_cb_st:
    mov     byte ptr [rdi + rcx], al
    inc     ecx
    cmp     ecx, r8d
    jb      fds_cb_lp

    ; Extension length: trim trailing spaces from ent[8..10]
    mov     r9d, 3
fds_trim_e:
    test    r9d, r9d
    jz      fds_ext_done
    cmp     byte ptr [rsi + 8 + r9 - 1], 20h
    jne     fds_copy_e
    dec     r9d
    jmp     fds_trim_e

fds_copy_e:
    mov     byte ptr [rdi + rcx], '.'
    inc     ecx
    xor     edx, edx
fds_ce_lp:
    movzx   eax, byte ptr [rsi + 8 + rdx]
    cmp     al, 80h
    jb      fds_ce_case
    mov     r11d, 1
    jmp     fds_ce_st
fds_ce_case:
    test    r10d, 10h                       ; lowercase ext
    jz      fds_ce_st
    cmp     al, 'A'
    jb      fds_ce_st
    cmp     al, 'Z'
    ja      fds_ce_st
    add     al, 20h
fds_ce_st:
    mov     byte ptr [rdi + rcx], al
    inc     ecx
    inc     edx
    cmp     edx, r9d
    jb      fds_ce_lp

fds_ext_done:
    test    r11d, r11d
    jnz     fds_oem_conv

    ; Fast ASCII copy to g_fat_comp8
    lea     rdx, [g_fat_comp8]
    xor     eax, eax
fds_asc_cp:
    mov     r8b, byte ptr [rdi + rax]
    mov     byte ptr [rdx + rax], r8b
    inc     eax
    cmp     eax, ecx
    jb      fds_asc_cp
    mov     byte ptr [rdx + rax], 0
    jmp     fds_out

fds_oem_conv:
    mov     dword ptr [rbp-28], ecx
    WINCALL MultiByteToWideChar, FAT_CP_OEM, 0, addr g_fat_oem8, dword ptr [rbp-28], addr g_fat_oem_w, 15
    test    eax, eax
    jz      fds_bad
    mov     dword ptr [rbp-28], eax
    WINCALL WideCharToMultiByte, FAT_CP_UTF8, 0, addr g_fat_oem_w, dword ptr [rbp-28], addr g_fat_comp8, 1020, 0, 0
    test    eax, eax
    jz      fds_bad
    lea     rdx, [g_fat_comp8]
    mov     byte ptr [rdx + rax], 0
    jmp     fds_out

fds_bad:
    xor     eax, eax

fds_out:
    mov     rsi, qword ptr [rbp-16]
    mov     rdi, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
fat_decode_sfn endp

; =============================================================================
; fat_mark_dir_visited(ecx = cluster) -> eax = 0 ok, 1 already visited / full
; =============================================================================
fat_mark_dir_visited proc
    mov     edx, dword ptr [g_fat_vis_cnt]
    lea     r8,  [g_fat_vis_clus]
    xor     eax, eax
fmdv_lp:
    cmp     eax, edx
    jae     fmdv_add
    cmp     dword ptr [r8 + rax*4], ecx
    je      fmdv_dup
    inc     eax
    jmp     fmdv_lp
fmdv_add:
    cmp     edx, FAT_MAX_DIRS
    jae     fmdv_dup
    mov     dword ptr [r8 + rdx*4], ecx
    inc     edx
    mov     dword ptr [g_fat_vis_cnt], edx
    xor     eax, eax
    ret
fmdv_dup:
    mov     eax, 1
    ret
fat_mark_dir_visited endp

; =============================================================================
; fat_walk_dir(ecx = startCluster, edx = isFixedRoot, r8d = prefixLen, r9d = depth)
;   -> eax = EXIT_*
; =============================================================================
fat_walk_dir proc frame
    FRAME_PROLOG 224
    ; [rbp-16..64]   saved r12..r15, rbx, rsi, rdi
    ; [rbp-68]       isFixedRoot
    ; [rbp-72]       prefixLen
    ; [rbp-76]       depth
    ; [rbp-80]       steps
    ; [rbp-84]       lfnValid
    ; [rbp-88]       lfnExpected
    ; [rbp-92]       lfnChk
    ; [rbp-96]       childClus
    ; [rbp-128..97]  32-byte directory entry buffer
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx
    mov     qword ptr [rbp-56], rsi
    mov     qword ptr [rbp-64], rdi

    cmp     r9d, FAT_MAX_DEPTH
    ja      fwd_corrupt

    mov     r12d, ecx                       ; curClus
    mov     dword ptr [rbp-68], edx         ; isFixedRoot
    mov     dword ptr [rbp-72], r8d         ; prefixLen
    mov     dword ptr [rbp-76], r9d         ; depth
    mov     dword ptr [rbp-80], 0           ; steps
    mov     dword ptr [rbp-84], 0           ; lfnValid
    xor     r13d, r13d                      ; inClusOff (or root entry idx * 32)
    xor     r14d, r14d                      ; totalEntriesSeen

    test    edx, edx
    jnz     fwd_loop

    ; Cluster-backed dir: validate and mark startCluster visited
    cmp     r12d, 2
    jb      fwd_corrupt
    cmp     r12d, dword ptr [g_fat_maxclus]
    ja      fwd_corrupt
    mov     ecx, r12d
    call    fat_mark_dir_visited
    test    eax, eax
    jnz     fwd_corrupt

fwd_loop:
    inc     r14d
    cmp     r14d, FAT_MAX_DIR_ENTRIES
    ja      fwd_corrupt

    cmp     dword ptr [rbp-68], 0
    je      fwd_clus_pos

    ; Fixed FAT12/16 root directory
    mov     eax, dword ptr [g_fat_root_ent]
    shl     eax, 5
    cmp     r13d, eax
    jae     fwd_ok
    mov     rcx, qword ptr [g_fat_root_off]
    mov     eax, r13d
    add     rcx, rax
    add     r13d, 32
    jmp     fwd_read_ent

fwd_clus_pos:
    cmp     r13d, dword ptr [g_fat_cbytes]
    jb      fwd_clus_have
    ; Advance to next cluster in directory chain
    inc     dword ptr [rbp-80]
    mov     eax, dword ptr [rbp-80]
    cmp     eax, dword ptr [g_fat_nclus]
    ja      fwd_corrupt
    mov     ecx, r12d
    call    fat_next_cluster
    test    eax, eax
    jz      fwd_ok                          ; EOC -> directory finished
    cmp     eax, -1
    je      fwd_corrupt
    mov     r12d, eax
    xor     r13d, r13d

fwd_clus_have:
    ; volOff = g_fat_data_off + (curClus - 2) * cbytes + inClusOff
    mov     eax, r12d
    sub     eax, 2
    mov     ecx, dword ptr [g_fat_cbytes]
    imul    rax, rcx
    add     rax, qword ptr [g_fat_data_off]
    mov     ecx, r13d
    add     rcx, rax
    add     r13d, 32

fwd_read_ent:
    lea     rdx, [rbp-128]
    mov     r8d, 32
    call    tcvc_read_bytes
    test    eax, eax
    jnz     fwd_ret                         ; propagate EXIT_IO / EXIT_CORRUPT

    lea     rsi, [rbp-128]
    movzx   eax, byte ptr [rsi]
    test    eax, eax
    jz      fwd_ok                          ; 0x00 = end of directory
    cmp     al, 0E5h
    jne     fwd_not_del
    mov     dword ptr [rbp-84], 0           ; deleted -> reset LFN
    jmp     fwd_loop

fwd_not_del:
    movzx   edx, byte ptr [rsi+11]
    mov     ecx, edx
    and     ecx, 03Fh
    cmp     ecx, FAT_ATTR_LFN
    jne     fwd_sfn

    ; ---- VFAT Long File Name slot -------------------------------------------
    cmp     word ptr [rsi+26], 0            ; LDIR_FstClusLO must be 0
    jne     fwd_lfn_drop
    mov     ecx, eax
    and     ecx, 03Fh                       ; seq = 1..20
    jz      fwd_lfn_drop
    cmp     ecx, 20
    ja      fwd_lfn_drop

    test    eax, 40h                        ; LAST_LONG_ENTRY (first slot on disk)
    jz      fwd_lfn_cont

    ; Start of a new LFN sequence
    mov     dword ptr [rbp-84], 1           ; lfnValid = 1
    lea     edx, [ecx - 1]
    mov     dword ptr [rbp-88], edx         ; lfnExpected = seq - 1
    movzx   edx, byte ptr [rsi+13]
    mov     dword ptr [rbp-92], edx         ; lfnChk
    imul    edx, ecx, 13
    mov     dword ptr [g_fat_lfn_max], edx
    lea     rdi, [g_fat_lfn_w]
    mov     word ptr [rdi + rdx*2], 0       ; NUL-cap at max_seq * 13
    jmp     fwd_lfn_store

fwd_lfn_cont:
    cmp     dword ptr [rbp-84], 0
    je      fwd_loop
    cmp     ecx, dword ptr [rbp-88]
    jne     fwd_lfn_drop
    movzx   edx, byte ptr [rsi+13]
    cmp     edx, dword ptr [rbp-92]
    jne     fwd_lfn_drop
    dec     dword ptr [rbp-88]

fwd_lfn_store:
    ; Copy 13 UTF-16LE chars into g_fat_lfn_w[(seq - 1) * 13]
    dec     ecx
    imul    ecx, ecx, 13
    lea     rdi, [g_fat_lfn_w]
    lea     rdi, [rdi + rcx*2]
    mov     ax, word ptr [rsi+1]
    mov     word ptr [rdi], ax
    mov     ax, word ptr [rsi+3]
    mov     word ptr [rdi+2], ax
    mov     ax, word ptr [rsi+5]
    mov     word ptr [rdi+4], ax
    mov     ax, word ptr [rsi+7]
    mov     word ptr [rdi+6], ax
    mov     ax, word ptr [rsi+9]
    mov     word ptr [rdi+8], ax
    mov     ax, word ptr [rsi+14]
    mov     word ptr [rdi+10], ax
    mov     ax, word ptr [rsi+16]
    mov     word ptr [rdi+12], ax
    mov     ax, word ptr [rsi+18]
    mov     word ptr [rdi+14], ax
    mov     ax, word ptr [rsi+20]
    mov     word ptr [rdi+16], ax
    mov     ax, word ptr [rsi+22]
    mov     word ptr [rdi+18], ax
    mov     ax, word ptr [rsi+24]
    mov     word ptr [rdi+20], ax
    mov     ax, word ptr [rsi+28]
    mov     word ptr [rdi+22], ax
    mov     ax, word ptr [rsi+30]
    mov     word ptr [rdi+24], ax
    jmp     fwd_loop

fwd_lfn_drop:
    mov     dword ptr [rbp-84], 0
    jmp     fwd_loop

    ; ---- Standard 8.3 entry (possibly preceded by valid LFN) ----------------
fwd_sfn:
    test    edx, FAT_ATTR_VOLUME_ID
    jz      fwd_not_vol
    mov     dword ptr [rbp-84], 0           ; volume label -> ignore
    jmp     fwd_loop

fwd_not_vol:
    ; Try LFN first if lfnValid == 1 and lfnExpected == 0
    cmp     dword ptr [rbp-84], 1
    jne     fwd_use_sfn
    mov     dword ptr [rbp-84], 0           ; consume LFN state
    cmp     dword ptr [rbp-88], 0
    jne     fwd_use_sfn

    mov     rcx, rsi
    call    fat_sfn_checksum
    cmp     eax, dword ptr [rbp-92]
    jne     fwd_use_sfn

    ; Measure UTF-16 length in g_fat_lfn_w up to NUL, 0xFFFF pad, or g_fat_lfn_max
    lea     rcx, [g_fat_lfn_w]
    mov     r8d, dword ptr [g_fat_lfn_max]
    xor     r9d, r9d
fwd_lfn_len:
    cmp     r9d, r8d
    jae     fwd_lfn_conv
    movzx   eax, word ptr [rcx + r9*2]
    test    eax, eax
    jz      fwd_lfn_conv
    cmp     eax, 0FFFFh
    je      fwd_lfn_conv
    inc     r9d
    jmp     fwd_lfn_len
fwd_lfn_conv:
    test    r9d, r9d
    jz      fwd_use_sfn
    WINCALL WideCharToMultiByte, FAT_CP_UTF8, FAT_WC_ERR_INVALID, addr g_fat_lfn_w, r9d, addr g_fat_comp8, 1020, 0, 0
    test    eax, eax
    jz      fwd_corrupt
    mov     ebx, eax                        ; compLen
    jmp     fwd_have_name

fwd_use_sfn:
    mov     rcx, rsi
    call    fat_decode_sfn
    test    eax, eax
    jz      fwd_corrupt
    mov     ebx, eax                        ; compLen

fwd_have_name:
    ; Skip "." and ".."
    lea     rdi, [g_fat_comp8]
    cmp     ebx, 1
    jne     fwd_chk_dot2
    cmp     byte ptr [rdi], '.'
    je      fwd_loop
fwd_chk_dot2:
    cmp     ebx, 2
    jne     fwd_build_path
    cmp     word ptr [rdi], 2E2Eh           ; ".."
    je      fwd_loop

fwd_build_path:
    ; Combine prefix + comp8 into g_fat_path
    mov     ecx, dword ptr [rbp-72]         ; prefixLen
    lea     eax, [ecx + ebx]
    cmp     eax, ENTRY_NAME_MAX
    ja      fwd_corrupt
    mov     r15d, eax                       ; fullLen

    lea     rdx, [g_fat_path]
    add     rdx, rcx
    xor     ecx, ecx
fwd_cp_comp:
    mov     al, byte ptr [rdi + rcx]
    mov     byte ptr [rdx + rcx], al
    inc     ecx
    cmp     ecx, ebx
    jb      fwd_cp_comp

    ; Extract starting cluster & file size from SFN entry [rbp-128]
    movzx   eax, word ptr [rbp-128 + 26]    ; FstClusLO
    cmp     dword ptr [g_fat_type], TCVC_FS_FAT32
    jne     fwd_clus_got
    movzx   ecx, word ptr [rbp-128 + 20]    ; FstClusHI
    shl     ecx, 16
    or      eax, ecx
    and     eax, 0FFFFFFFh
fwd_clus_got:
    mov     dword ptr [rbp-96], eax         ; childClus

    test    byte ptr [rbp-128 + 11], FAT_ATTR_DIRECTORY
    jnz     fwd_is_dir

    ; Regular file: validate size & cluster
    mov     r8d, dword ptr [rbp-128 + 28]   ; FileSize (u32 -> r8)
    cmp     r8, qword ptr [g_fat_max_fsize]
    ja      fwd_corrupt
    test    r8d, r8d
    jz      fwd_add_file
    cmp     eax, 2
    jb      fwd_corrupt
    cmp     eax, dword ptr [g_fat_maxclus]
    ja      fwd_corrupt

fwd_add_file:
    lea     rcx, [g_fat_path]
    mov     edx, r15d
    xor     r9d, r9d                        ; flags = 0 (file)
    mov     eax, dword ptr [rbp-96]
    mov     qword ptr [rsp+32], rax         ; meta0 = startCluster
    mov     qword ptr [rsp+40], 0
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_add
    test    eax, eax
    jnz     fwd_ret
    jmp     fwd_loop

fwd_is_dir:
    ; Directory entry: emit IDXEF_DIR then recurse
    lea     rcx, [g_fat_path]
    mov     edx, r15d
    xor     r8d, r8d                        ; size = 0
    mov     r9d, IDXEF_DIR
    mov     eax, dword ptr [rbp-96]
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0
    mov     qword ptr [rsp+48], 0
    call    tcvc_idx_add
    test    eax, eax
    jnz     fwd_ret

    ; Append '/' and recurse
    lea     eax, [r15d + 1]
    cmp     eax, ENTRY_NAME_MAX
    ja      fwd_corrupt
    lea     rdx, [g_fat_path]
    mov     byte ptr [rdx + r15], '/'

    mov     ecx, dword ptr [rbp-96]         ; startCluster
    xor     edx, edx                        ; isFixedRoot = 0
    lea     r8d, [r15d + 1]                 ; newPrefixLen
    mov     r9d, dword ptr [rbp-76]
    inc     r9d                             ; depth + 1
    call    fat_walk_dir
    test    eax, eax
    jnz     fwd_ret
    jmp     fwd_loop

fwd_ok:
    xor     eax, eax
    jmp     fwd_ret

fwd_corrupt:
    mov     eax, EXIT_CORRUPT

fwd_ret:
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    mov     rsi, qword ptr [rbp-56]
    mov     rdi, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
fat_walk_dir endp

; =============================================================================
; fat_enum() -> eax = EXIT_*
; Enumerates the entire FAT12/16/32 volume into g_idxptr.
; =============================================================================
public fat_enum
fat_enum proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_fat_vis_cnt], 0

    cmp     dword ptr [g_fat_type], TCVC_FS_FAT32
    je      fe_32

    xor     ecx, ecx
    mov     edx, 1                          ; fixed root
    xor     r8d, r8d
    xor     r9d, r9d
    call    fat_walk_dir
    jmp     fe_done

fe_32:
    mov     ecx, dword ptr [g_fat_root_clus]
    xor     edx, edx                        ; cluster-backed root
    xor     r8d, r8d
    xor     r9d, r9d
    call    fat_walk_dir

fe_done:
    FRAME_EPILOG
    ret
fat_enum endp

; =============================================================================
; fat_extract_entry(rcx = idxEntPtr) -> eax = EXIT_*
; Streams exact IDXE_size bytes of file content to tcvc_sink_write.
; =============================================================================
public fat_extract_entry
fat_extract_entry proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], r12
    mov     qword ptr [rbp-24], r13
    mov     qword ptr [rbp-32], r14
    mov     qword ptr [rbp-40], r15
    mov     qword ptr [rbp-48], rbx

    mov     r12, qword ptr [rcx + IDXE_size]    ; remaining bytes
    mov     r13d, dword ptr [rcx + IDXE_offset] ; curClus
    xor     r14d, r14d                          ; steps

    test    r12, r12
    jz      fee_ok

    cmp     r12, qword ptr [g_fat_max_fsize]
    ja      fee_corrupt

fee_clus_lp:
    cmp     r13d, 2
    jb      fee_corrupt
    cmp     r13d, dword ptr [g_fat_maxclus]
    ja      fee_corrupt

    inc     r14d
    cmp     r14d, dword ptr [g_fat_nclus]
    ja      fee_corrupt

    ; clusBytesToRead = min(r12, g_fat_cbytes)
    mov     ebx, dword ptr [g_fat_cbytes]
    cmp     r12, rbx
    jae     fee_clus_sz
    mov     ebx, r12d
fee_clus_sz:
    ; volOff = g_fat_data_off + (curClus - 2) * g_fat_cbytes
    mov     eax, r13d
    sub     eax, 2
    mov     ecx, dword ptr [g_fat_cbytes]
    imul    rax, rcx
    add     rax, qword ptr [g_fat_data_off]
    mov     r15, rax                        ; curVolOff within cluster

fee_chunk_lp:
    test    ebx, ebx
    jz      fee_clus_done
    mov     ecx, ebx
    cmp     ecx, 65536
    jbe     fee_rd
    mov     ecx, 65536
fee_rd:
    mov     dword ptr [rbp-56], ecx
    mov     rcx, r15
    lea     rdx, [g_fat_iobuf]
    mov     r8d, dword ptr [rbp-56]
    call    tcvc_read_bytes
    test    eax, eax
    jnz     fee_out

    lea     rcx, [g_fat_iobuf]
    mov     edx, dword ptr [rbp-56]
    call    tcvc_sink_write
    test    eax, eax
    jnz     fee_out

    mov     eax, dword ptr [rbp-56]
    add     r15, rax
    sub     ebx, eax
    sub     r12, rax
    jmp     fee_chunk_lp

fee_clus_done:
    test    r12, r12
    jz      fee_ok

    mov     ecx, r13d
    call    fat_next_cluster
    cmp     eax, 2
    jb      fee_corrupt                     ; premature EOC (0) or bad (-1)
    mov     r13d, eax
    jmp     fee_clus_lp

fee_ok:
    xor     eax, eax
    jmp     fee_out

fee_corrupt:
    mov     eax, EXIT_CORRUPT

fee_out:
    mov     dword ptr [rbp-60], eax
    lea     rcx, [g_fat_iobuf]
    mov     edx, 65536
    call    secure_zero
    mov     eax, dword ptr [rbp-60]
    mov     r12, qword ptr [rbp-16]
    mov     r13, qword ptr [rbp-24]
    mov     r14, qword ptr [rbp-32]
    mov     r15, qword ptr [rbp-40]
    mov     rbx, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
fat_extract_entry endp

end
