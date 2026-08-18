; =============================================================================
; pack.asm - pack (multi-file -> ustar -> encrypt) and unpack (decrypt -> extract)
; -----------------------------------------------------------------------------
; pack streams a ustar archive of the input files through the streaming GCM
; encryptor into a Myrkr container (archive flag set in header byte 17).  unpack
; decrypts to a temp tar, verifies the tag, then extracts with path-traversal
; safety (no "..", absolute, or drive-letter entry names).  Store mode.
; =============================================================================

include macros.inc

extern check_password_policy:proc
extern print_policy_error:proc
extern derive_key:proc
extern normalize_path:proc
extern make_temp_path:proc
extern rng_fill:proc
extern secure_zero:proc
extern VirtualAlloc:proc                ; the inventory buffer: reserved once,
                                        ; committed as far as it actually reaches
extern gcm_init:proc
extern gcm_aad:proc
extern gcm_crypt:proc
extern gcm_final:proc
extern ct_memcmp:proc
extern file_open_read:proc
extern file_open_write:proc
extern get_file_size:proc
extern file_read_exact:proc
extern file_read_at:proc
extern file_seek:proc
extern file_open_rw:proc
extern file_truncate:proc
extern file_write_all:proc
; TEST_IO, not DBG_TRACE: every DBG_TRACE build also defines TEST_IO (build dbg
; sets both), but a testio build sets only TEST_IO - and the nonce log lives in
; testio builds too, because the security suite runs against one.
ifdef TEST_IO
extern GetEnvironmentVariableW:proc     ; MYRKR_DBG_* knobs, see do_pack/nonce_log
extern CreateFileW:proc                 ; the nonce log, see nonce_log
extern WriteFile:proc
extern CloseHandle:proc
endif
extern vol_begin:proc                   ; volume.asm: the container's write sink
extern vol_write:proc
extern vol_put:proc
extern vol_discard:proc
extern vol_finish:proc
extern vset_open:proc                   ; volume.asm: the read side
extern vset_close:proc
extern vol_get:proc
extern vol_size:proc
extern vol_is_set:proc
externdef g_vol_limit:qword
externdef g_vol_hout:qword
externdef g_vol_split:dword
externdef g_vol_toomany:dword
extern file_close:proc
extern file_rename:proc
extern file_delete:proc
extern tar_build_header:proc
extern print_a:proc
extern print_err:proc
extern print_wz:proc
extern print_u64:proc
extern fmt_u64:proc                     ; console.asm: digits into a buffer
extern print_u64e:proc
extern CreateDirectoryW:proc
extern WideCharToMultiByte:proc
extern MultiByteToWideChar:proc
extern GetFileAttributesW:proc
; Exclusions live in gui.asm because that is where the user creates them, but
; they MUST be honoured here.  If only the list applied them, the summary and
; the container would disagree about what is being encrypted - the user would
; be told one thing and handed another.  In a CLI run the set is simply empty.
externdef g_excluded:byte
extern pset_has:proc
extern FindFirstFileW:proc
extern FindNextFileW:proc
extern FindClose:proc
extern comp_init:proc
extern comp_block:proc
extern comp_close:proc
; The entry decoder.  It lives in estream.asm because a drag-out needs an
; IStream over one entry, but the decoder underneath that COM object is the only
; one in the tree that knows how to turn an entry's ciphertext back into its
; content - decrypt, de-frame, skip the tar header, stop at the recorded size,
; drain the padding, check the tag.  do_unpack extracts THROUGH it rather than
; keeping a second copy of those rules: two copies of a rule is how
; vol_part_suffix shipped a version that could not read 4-digit volume parts.
extern es_new:proc
extern es_bind:proc
extern es_consume:proc
extern es_code:proc
extern es_destroy:proc
extern progress_begin:proc
extern progress_add:proc
extern rlog_added:proc                  ; ramlog.asm: one line per entry
extern rlog_extracted:proc
extern progress_done:proc
extern compute_kcv:proc
extern disk_has_space:proc
externdef g_cfg_compress:dword
externdef g_cfg_compress_set:dword

FILE_ATTR_DIR   equ 10h
FIND_CFILENAME  equ 44          ; offset of cFileName in WIN32_FIND_DATAW
CBLOCK          equ 100000h     ; 1 MiB compression block

externdef g_cfg_in:qword
externdef g_cfg_out:qword
externdef g_prog_abort:dword
externdef g_cfg_t:dword
externdef g_cfg_m:dword
externdef g_positionals:qword
externdef g_poscount:qword
externdef g_scan_files:qword             ; GUI indexer: running file count
externdef g_scan_dirs:qword              ; GUI indexer: running directory count
externdef g_scan_bytes:qword             ; GUI indexer: running byte total
externdef g_key:byte
externdef g_temppath:word
externdef g_out_np:word
externdef g_cur_input:qword              ; current positional index (per-file progress)
externdef g_file_total:qword             ; per-positional total bytes (16 entries)

; The virtual-memory flags for the inventory buffer's reserve/commit pair.
; constcheck compares these against fileio.asm's copies.
MEM_COMMIT      equ 1000h
MEM_RESERVE     equ 2000h
PAGE_READWRITE  equ 04h
GCTX_SIZE       equ 336
CHUNK           equ 100000h
INVALID         equ -1
CP_UTF8         equ 65001
ifdef TEST_IO
; the nonce log's file plumbing (test builds only - see nonce_log)
FILE_APPEND_DATA equ 4
OPEN_ALWAYS      equ 4
FILE_SHARE_READ  equ 1
FILE_ATTR_NORMAL equ 128
endif

.const
CSTR msg_pack_ok,    "packed -> "
CSTR msg_enc_ok2,    "encrypted -> "
CSTR msg_unpack_ok,  "unpacked -> "
CSTR msg_dec_ok2,    "decrypted -> "
CSTR msg_nl,         13,10
ifdef DBG_TRACE
WSTR w_dbg_volb,     <MYRKR_DBG_VOLBYTES>   ; debug builds only - see do_pack
WSTR w_dbg_segb,     <MYRKR_DBG_SEGBYTES>   ; debug builds only - see do_pack
endif
ifdef TEST_IO
WSTR w_dbg_nlog,     <MYRKR_DBG_NONCELOG>   ; test builds only - see nonce_log
WSTR w_dbg_idxmax,   <MYRKR_DBG_IDXMAX>     ; test builds only - see idx_cap
endif
CSTR e_pio,          "error: I/O failure",13,10
CSTR e_volparts,     "error: this would need more than 4096 volume parts. Nothing usable was written; choose a larger part size and run it again.",13,10
CSTR e_poom,         "error: out of memory",13,10
CSTR e_pcorrupt,     "error: not a valid Myrkr container",13,10
; A container whose VERSION does not match is not a damaged container, and
; saying "not a valid Myrkr container" about one tells someone their data is
; corrupt when it is intact.  The two need different things from them: one is
; a restore from backup, the other is a different build of Myrkr.
CSTR e_pver1,        "error: this container is format version "
CSTR e_pver2,        ", and this build of Myrkr reads versions "
CSTR e_pver2b,       " to "
CSTR e_pver3,        ".",13,10,"       The file is not damaged - it needs a build that matches it.",13,10
; Extraction writes each entry as it authenticates it, so a container that goes
; bad half way leaves the entries before it on disk.  Every one of those was
; verified on its own and none of it is unauthenticated - but the SET is short,
; and an attacker who can corrupt a container can choose where it stops.  Saying
; nothing would let a folder that looks complete pass for one.
CSTR e_pincomplete,  "warning: the extraction stopped early. Each file written was authenticated on its own, but the archive holds more than reached the disk - do not treat this folder as its contents. Entries extracted before the failure: "
CSTR msg_add_ok,     "add: OK",13,10
CSTR e_add_usage,    "usage: myrkr add CONTAINER FILE [FILE...] -p PASSWORD",13,10
CSTR e_add_dup,      "error: the container already holds an entry named: "
; The remedy is in the message because the exit code cannot carry it, and this
; is the one refusal here a user cannot act on by guessing.
CSTR e_idx_revfull,  "error: this container has been rewritten as many times as the format allows.",13,10,"  Repack it (encrypt it afresh) to continue editing - that draws a new key,",13,10,"  which is what makes the internal counter safe to reset.",13,10
; Refusing is the whole point of this message: the alternative, which is what
; this used to do, was to write the files and not record them.
CSTR e_idx_full,     "error: too many entries for one container - the inventory is full.",13,10,"  No container was produced. Encrypt fewer files per container.",13,10
; Says what CAN be done, because a refusal that only says no leaves the user to
; guess whether their data is stuck.  It is not: reading a set is supported.
CSTR e_vol_edit,     "error: this container is split across volumes and cannot be edited.",13,10,"  It can still be opened and extracted. To change what is in it, extract",13,10,"  it and encrypt the result again.",13,10
CSTR e_pparams,      "error: container has out-of-range KDF parameters",13,10
CSTR e_ptoobig,      "error: a single file exceeds what one AES-GCM stream can seal (~64 GiB)",13,10
CSTR e_ptoobig2,     "       (split the input, or encrypt it in parts)",13,10
; The ADD variant: the ceiling is the CONTAINER'S, because it was written before
; segments existed - a fresh container has no such limit.
CSTR e_atoobig2,     "       This container was written without segments and cannot hold it. Nothing was added; encrypt the file into a NEW container, which can hold files of any size.",13,10
CSTR e_pnotarch,     "error: container is not an archive (use 'decrypt' instead)",13,10
CSTR e_pauth,        "error: authentication failed - wrong password or corrupted archive",13,10
CSTR e_pname,        "error: archive entry name too long or unsafe (rejected)",13,10
CSTR e_pnospace,     "error: not enough free disk space",13,10
CSTR msg_lst_hdr,    "contents:",13,10
CSTR msg_lst_dir,    "  <dir>  "
CSTR msg_lst_pre,    "  "
CSTR msg_lst_sep,    "  "
CSTR msg_lst_trunc,  "  (listing incomplete - the container holds more than the inventory records)",13,10
CSTR msg_lst_none,   "  (no inventory - container predates the listing, or it was truncated)",13,10
CSTR msg_lst_nl,     13,10
CSTR msg_del_moved,  "overwritten with random, then the gap closed",13,10
CSTR e_del_nf,       "error: no such entry in the container: "
CSTR e_del_usage,    "error: name at least one entry to remove",13,10
CSTR lbl_pack,       "packing"
CSTR lbl_unpack,     "unpacking"

.data?
public g_bare
public g_peek_compress
; estream.asm needs the header: it is the entry AAD, and its bytes 17/18 are
; what say whether an entry's plaintext carries a tar header and whether it is
; compression-framed.  Published rather than copied, so a stream and an extract
; cannot come to different conclusions about the same container.
public g_pkhdr
public g_namew, g_extw, g_outdir_np
align 16
public g_pkctx                          ; secmem locks it; see secmem_init
g_pkctx     db GCTX_SIZE dup (?)
g_pkhdr     db HDR_BYTES dup (?)     ; 80: param block (64) + KCV (16)
g_pkkcv     db 16 dup (?)            ; recomputed KCV (unpack compare)
g_pktag     db 16 dup (?)
g_pktag2    db 16 dup (?)
g_sink      db CHUNK dup (?)
g_filebuf   db CHUNK dup (?)
g_tarhdr    db 512 dup (?)
g_zeros     db 1024 dup (?)
g_sinkfill  dq ?
g_sink_hout dq ?
g_packerr   dq ?
g_rel       db 4096 dup (?)
g_rellen    dq ?
; Destination inside the archive for an APPEND: a UTF-8 archive path with a
; trailing '/', or empty for the root.  Prepended to the entry name in
; pack_input_top and zip_input_top, which is the only place either format
; decides what an added file is called - the .mrk side is no harder than the
; zip side, because an entry's AAD is header||ordinal and the name is not in
; it.  Zero-initialised, so the CLI verbs and every fresh archive get the root
; without asking; only the GUI ever sets it.
g_add_prefix    db ADDPFX_BYTES dup (?)
g_add_prefixlen dq ?
; The STAGED layout: where each input goes, chosen before the run rather than
; shared by all of it.  g_add_prefix above is the destination of whatever input
; is being walked RIGHT NOW; pfx_select puts one of these into it.
g_pos_prefix    dd MAX_ARGS dup (?)     ; offset into the arena, 0 = the root
g_pfx_arena     db PFXARENA_BYTES dup (?)
g_pfx_head      dq ?                    ; next free offset; 0 means "not opened
                                        ; yet", and allocation starts at 1 so
                                        ; that offset 0 stays the empty string
g_walk      dw 8000h dup (?)        ; UTF-16 full path during recursion
g_walklen   dq ?
g_childu8   db 1024 dup (?)         ; UTF-8 child name
g_namebuf   db 104 dup (?)          ; ustar name field (<=100)
g_prefixbuf db 160 dup (?)          ; ustar prefix field (<=155)
g_pk_np     dw 8000h dup (?)
g_extw      dw 8000h dup (?)
g_outdir_np dw 8000h dup (?)
g_namew     dw 4096 dup (?)
; One index entry's name, NUL-terminated.  The inventory stores names with an
; explicit length and no terminator; sanitize_name and MultiByteToWideChar both
; want a C string, so extraction copies it here first.  Sized against g_rel,
; which is what the writer built the name in - and NOT against the 300-byte
; buffer the tar-header parser used to reassemble names into, which a container
; whose index names something longer than ustar can express would overrun.
g_entname   db 4096 dup (?)
g_compress  dq ?                    ; active mode: 0 store / 1 xpress
; ---- segmentation (docs/V5_WORK.md B4) --------------------------------------
; g_cfg_segshift is what do_pack WRITES into a new container's header:
; SEG_SHIFT_DEFAULT, or MYRKR_DBG_SEGBYTES in a dbg build.  The other three are
; what the writer RUNS on, and they come from the header via seg_bytes_from_hdr
; in entry_begin - not from the config - so an append to an existing container
; segments (or does not) exactly as that container says, never as this build's
; default says.
g_cfg_segshift dd ?                 ; shift for a NEW container's header
g_segbytes  dq ?                    ; 1 << header's seg_shift, or 0 = off
g_segfill   dq ?                    ; bytes fed to GCM in the open segment
g_segidx    dd ?                    ; which segment of this entry is open
g_bare      dd ?                    ; 1 = single-file (no tar) container, 0 = archive
g_peek_compress dd ?                ; compression byte read by peek_archive
public g_verify_only
g_verify_only dd ?                  ; 1 = do_unpack authenticates and writes nothing
; 1 = an extraction failed after entries had already been written out.  The
; files on disk are each authentic; the SET is short.  gui.asm shows a different
; message for it, because a folder with files in it reads as a partial success
; and this is not one.
public g_unpack_partial
g_unpack_partial dd ?
g_packtotal dq ?                    ; total input bytes (progress total, pack)
g_biggest   dq ?                    ; largest single input the sizing walk saw.
                                    ; The AES-GCM ceiling bounds one ENTRY now,
                                    ; so this - not the total - is what the
                                    ; pre-flight has to weigh against it.
g_packents  dq ?                    ; tar entries the inputs will produce (files +
                                    ; directories).  Counted alongside g_packtotal
                                    ; so the MAX_PLAINTEXT_SIZE pre-flight can add
                                    ; tar framing, which for many tiny files is far
                                    ; larger than the content itself.  Kept separate
                                    ; from the GUI's g_scan_files, which counts
                                    ; files only and which sum_inputs resets at
                                    ; the start of its walk.
; ---- the inventory (see macros.inc) -----------------------------------------
public g_idxptr, g_idxlen, g_idxcount, g_idxflags, g_keep_key
public g_add_prefix, g_add_prefixlen
public g_pos_prefix, g_pfx_arena
public g_pick_active
public pick_reset, pick_add, pick_has
g_pick_active dd ?                  ; 1 = extract only the picked entries
g_picklen   dq ?                    ; bytes used in g_pickbuf
g_pickbuf   db PICK_MAX_BYTES dup (?)   ; picked names, each u32 len + bytes
; WHERE THE INVENTORY LIVES.  A POINTER, AND NULL UNTIL SOMETHING NEEDS ONE.
;
; This was 64 MiB of .data?, and a PE's uninitialised data is COMMITTED at load
; rather than merely reserved: `myrkr hash` - which touches neither the index nor
; the KDF - charged 79.3 MB of private commit, 64 of it for a buffer it never
; read a byte of.  Every invocation paid that, including the GUI opening on an
; empty window and every shell-extension launch.
;
; It is allocated by idx_buf_ensure, on the first operation that actually needs
; an inventory, and never freed: the GUI's row model reads it between operations
; for as long as a container is open, so a free at the end of one operation is a
; use-after-free at the start of the next repaint.  A process that has touched an
; index pays what it always paid; one that has not pays nothing.
g_idxptr    dq ?                        ; listing, plaintext then encrypted in place
g_idxcommit dq ?                        ; bytes of it committed so far
; do_list's output buffer.  See lst_add: a listing is five fragments an entry,
; and one WriteFile per fragment cost 8.5 minutes on 500,000 of them.
LST_BUF_BYTES equ 65536
g_lstbuf    db LST_BUF_BYTES dup (?)
g_lstfill   dq ?
g_lstnum    db 24 dup (?)              ; one entry size, formatted
g_idxlen    dq ?                        ; bytes used in g_idxbuf
g_idxcount  dq ?                        ; entries recorded
g_idxflags  dq ?                        ; IDXF_TRUNCATED once the buffer is full
g_idxrev    dd ?                        ; index revision (see IDX_NONCE_BASE)
g_delname   db 4096 dup (?)             ; one entry name to remove, UTF-8
g_keep_key  dd ?                        ; 1 = idx_read leaves g_key alive
align 16
align 16
g_idxtrl    db IDX_TRAILER_BYTES dup (?)
g_idxaad    db IDX_AAD_BYTES dup (?)    ; header || trailer
g_idxnonce  db 16 dup (?)               ; 12 used; the counter, little-endian
g_payoff    dq ?                        ; payload bytes written so far = the
                                        ; offset the next entry will start at
g_entnext   dq ?                        ; ordinal to give the next entry
g_entoff    dq ?                        ; where the entry in progress started
g_entaad    db ENTRY_AAD_SEG_BYTES dup (?)  ; header || ordinal [|| segment]
                                    ; sized for the LONGER of the two, so the
                                    ; version-8 form does not overrun a buffer
                                    ; declared for the version-7 one
align 16
g_rawblk    db CBLOCK dup (?)       ; raw tar accumulation block (pack)
g_rawfill   dq ?
g_compbuf   db (2*CBLOCK) dup (?)   ; compressed output
ifdef DBG_TRACE
g_dbg_volbuf dw 24 dup (?)          ; MYRKR_DBG_VOLBYTES text
g_dbg_segbuf dw 24 dup (?)          ; MYRKR_DBG_SEGBYTES text
endif
ifdef TEST_IO
g_idxcap_state dd ?                 ; 0 unchecked / 1 resolved
g_idxcap     dq ?                   ; the resolved writer cap
g_idxcap_buf dw 24 dup (?)          ; MYRKR_DBG_IDXMAX text
g_nlog_state dd ?                   ; 0 unchecked / 1 off / 2 on
g_nlog_path  dw 300 dup (?)         ; MYRKR_DBG_NONCELOG value
g_nlog_line  db 32 dup (?)          ; 24 hex chars + CRLF
g_nlog_wr    dd ?                   ; WriteFile's bytes-written out-param
align 8
endif
g_frame     db 16 dup (?)           ; [u32 orig][u32 payload] frame header

.code

ifdef DBG_TRACE
extern dbg_putc:proc
endif
DBG macro ch
ifdef DBG_TRACE
    mov     al, ch
    call    dbg_putc
endif
endm


prn macro msg
    lea     rcx, [msg]
    mov     edx, msg&_len
    call    print_err
endm
prn_a macro msg
    lea     rcx, [msg]
    mov     edx, msg&_len
    call    print_a
endm

; =============================================================================
; sink_write(rcx = src, rdx = len) - buffer into g_sink, encrypt+write full
; CHUNKs.  Errors set g_packerr (sticky).
; =============================================================================
sink_write proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
sw_loop:
    cmp     qword ptr [g_packerr], 0
    jne     sw_done
    cmp     qword ptr [rbp-32], 0
    je      sw_done
    mov     rax, CHUNK
    sub     rax, qword ptr [g_sinkfill]
    mov     rdx, qword ptr [rbp-32]
    cmp     rax, rdx
    jbe     @F
    mov     rax, rdx
@@:
    lea     r10, [g_sink]
    add     r10, qword ptr [g_sinkfill]
    mov     r11, qword ptr [rbp-24]
    xor     r9, r9
sw_cpy:
    mov     dl, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], dl
    inc     r9
    cmp     r9, rax
    jb      sw_cpy
    add     qword ptr [g_sinkfill], rax
    add     qword ptr [rbp-24], rax
    sub     qword ptr [rbp-32], rax
    cmp     qword ptr [g_sinkfill], CHUNK
    jne     sw_loop
    call    sink_flush_block
    jmp     sw_loop
sw_done:
    FRAME_EPILOG
    ret
sink_write endp

sink_flush_block proc frame
    FRAME_PROLOG 64
    ; [rbp-16] = bytes of g_sink already fed   [rbp-24] = this piece
    ;
    ; A LOOP, not one call, because a segment boundary can fall anywhere inside
    ; the buffered block - and with MYRKR_DBG_SEGBYTES far below CHUNK, a single
    ; 1 MiB flush crosses SEVERAL boundaries, which is exactly the case that
    ; finds an off-by-one.  Unsegmented (g_segbytes = 0) the loop runs once over
    ; the whole buffer and this is byte-for-byte the old behaviour.
    ;
    ; gcm_crypt requires every call but a stream's last to be a multiple of 16.
    ; That holds here by construction: mid-entry flushes are full CHUNKs, a
    ; boundary cut is (segbytes - segfill) where both terms are multiples of 16,
    ; and the one piece that may not be a multiple of 16 - the tail of the
    ; entry's final flush - is by then the last call before a gcm_final.
    cmp     qword ptr [g_sinkfill], 0
    je      sfb_done
    mov     qword ptr [rbp-16], 0
sfb_loop:
    cmp     qword ptr [g_packerr], 0
    jne     sfb_zero                        ; sticky: a failed roll stops the rest
    mov     rax, qword ptr [g_sinkfill]
    sub     rax, qword ptr [rbp-16]
    jz      sfb_zero                        ; everything fed
    ; roll FIRST when the open segment is full - so an entry that ends exactly
    ; on a boundary never opens an empty tail segment (see seg_roll)
    mov     r10, qword ptr [g_segbytes]
    test    r10, r10
    jz      sfb_piece
    cmp     qword ptr [g_segfill], r10
    jb      sfb_room
    call    seg_roll
    jmp     sfb_loop
sfb_room:
    ; piece = min(what is left in the buffer, what is left in the segment)
    mov     r11, r10
    sub     r11, qword ptr [g_segfill]
    cmp     rax, r11
    jbe     sfb_piece
    mov     rax, r11
sfb_piece:
    mov     qword ptr [rbp-24], rax
    lea     rcx, [g_pkctx]
    lea     rdx, [g_sink]
    add     rdx, qword ptr [rbp-16]
    mov     r8, rdx
    mov     r9, qword ptr [rbp-24]
    call    gcm_crypt
    ; vol_put, NOT vol_write: this sink is shared with do_add, which is
    ; appending to one existing file and whose bytes must go to ITS handle.
    ; Only a fresh pack has a volume set open.
    mov     rcx, qword ptr [g_sink_hout]
    lea     rdx, [g_sink]
    add     rdx, qword ptr [rbp-16]
    mov     r8, qword ptr [rbp-24]
    call    vol_put
    test    eax, eax
    jz      sfb_ok
    ; The code vol_put RETURNED, not a blanket EXIT_IO.  The volume layer refuses
    ; with EXIT_UNSUPPORTED when a set would outgrow what a reader will assemble,
    ; and flattening that to EXIT_IO prints "I/O failure" - sending the user to
    ; look at a disk that is fine, when the answer is a larger part size.  Same
    ; lesson as the split-container add message.
    mov     r10d, eax
    mov     qword ptr [g_packerr], r10
    jmp     sfb_zero
sfb_ok:
    ; the running payload offset is what the index records extents against
    mov     rax, qword ptr [rbp-24]
    add     qword ptr [g_payoff], rax
    add     qword ptr [rbp-16], rax
    add     qword ptr [g_segfill], rax
    jmp     sfb_loop
sfb_zero:
    mov     qword ptr [g_sinkfill], 0
sfb_done:
    FRAME_EPILOG
    ret
sink_flush_block endp

; =============================================================================
; tar_out(rcx = src, rdx = len) - route tar bytes through compression or store
; =============================================================================
tar_out proc
    cmp     qword ptr [g_compress], 0
    jne     to_comp
    jmp     sink_write
to_comp:
    jmp     csink_write
tar_out endp

; =============================================================================
; csink_write(rcx = src, rdx = len) - accumulate into the raw block, compress
; and frame full blocks through the (gcm) sink.
; =============================================================================
csink_write proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
cw_loop:
    cmp     qword ptr [g_packerr], 0
    jne     cw_done
    cmp     qword ptr [rbp-32], 0
    je      cw_done
    mov     rax, CBLOCK
    sub     rax, qword ptr [g_rawfill]
    mov     rdx, qword ptr [rbp-32]
    cmp     rax, rdx
    jbe     @F
    mov     rax, rdx
@@:
    lea     r10, [g_rawblk]
    add     r10, qword ptr [g_rawfill]
    mov     r11, qword ptr [rbp-24]
    xor     r9, r9
cw_cpy:
    mov     dl, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], dl
    inc     r9
    cmp     r9, rax
    jb      cw_cpy
    add     qword ptr [g_rawfill], rax
    add     qword ptr [rbp-24], rax
    sub     qword ptr [rbp-32], rax
    cmp     qword ptr [g_rawfill], CBLOCK
    jne     cw_loop
    call    csink_flush
    jmp     cw_loop
cw_done:
    FRAME_EPILOG
    ret
csink_write endp

; =============================================================================
; csink_flush - compress the current raw block, frame it, push through sink
; =============================================================================
csink_flush proc frame
    FRAME_PROLOG 48
    ; [rbp-24]=payload ptr  [rbp-32]=payload len
    cmp     qword ptr [g_rawfill], 0
    je      csf_done
    lea     rcx, [g_rawblk]
    mov     rdx, qword ptr [g_rawfill]
    lea     r8, [g_compbuf]
    mov     r9, 2*CBLOCK
    call    comp_block
    test    eax, eax
    jz      csf_store
    cmp     rax, qword ptr [g_rawfill]
    jae     csf_store
    lea     r10, [g_compbuf]
    mov     qword ptr [rbp-24], r10
    mov     qword ptr [rbp-32], rax
    jmp     csf_frame
csf_store:
    lea     r10, [g_rawblk]
    mov     qword ptr [rbp-24], r10
    mov     rax, qword ptr [g_rawfill]
    mov     qword ptr [rbp-32], rax
csf_frame:
    lea     r10, [g_frame]
    mov     eax, dword ptr [g_rawfill]
    mov     dword ptr [r10+0], eax          ; orig_len
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r10+4], eax          ; payload_len
    lea     rcx, [g_frame]
    mov     rdx, 8
    call    sink_write
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    sink_write
    mov     qword ptr [g_rawfill], 0
csf_done:
    FRAME_EPILOG
    ret
csink_flush endp

; =============================================================================
; split_name(rcx = utf8 path, rdx = len) -> eax 0 ok / 1 too long
; Fills g_namebuf (<=100, NUL) and g_prefixbuf (<=155, NUL) for the ustar header.
; =============================================================================
split_name proc
    cmp     rdx, 100
    ja      sp_split
    lea     r10, [g_namebuf]
    xor     r9, r9
sp_c1:
    cmp     r9, rdx
    jae     sp_c1d
    mov     al, byte ptr [rcx+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    jmp     sp_c1
sp_c1d:
    mov     byte ptr [r10+r9], 0
    lea     r10, [g_prefixbuf]
    mov     byte ptr [r10], 0
    xor     eax, eax
    ret
sp_split:
    mov     r9, rdx
    sub     r9, 101                     ; earliest split index for suffix<=100
sp_scan:
    cmp     r9, 155
    ja      sp_toolong
    cmp     r9, rdx
    jae     sp_toolong
    movzx   eax, byte ptr [rcx+r9]
    cmp     al, '/'
    je      sp_found
    cmp     al, '\'
    je      sp_found
    inc     r9
    jmp     sp_scan
sp_found:
    mov     rax, rdx
    dec     rax
    sub     rax, r9                      ; name length = len-1-r9
    cmp     rax, 100
    ja      sp_toolong
    lea     r10, [g_prefixbuf]
    xor     r8, r8
sp_pc:
    cmp     r8, r9
    jae     sp_pcd
    mov     al, byte ptr [rcx+r8]
    mov     byte ptr [r10+r8], al
    inc     r8
    jmp     sp_pc
sp_pcd:
    mov     byte ptr [r10+r8], 0
    lea     r10, [g_namebuf]
    lea     r11, [rcx+r9+1]
    xor     r8, r8
sp_nc:
    mov     al, byte ptr [r11+r8]
    test    al, al
    jz      sp_ncd
    mov     byte ptr [r10+r8], al
    inc     r8
    cmp     r8, 100
    jb      sp_nc
sp_ncd:
    mov     byte ptr [r10+r8], 0
    xor     eax, eax
    ret
sp_toolong:
    mov     eax, 1
    ret
split_name endp

; =============================================================================
; idx_reset - start a fresh listing.
; =============================================================================
idx_reset proc
    mov     qword ptr [g_idxlen], 0
    mov     qword ptr [g_idxcount], 0
    mov     qword ptr [g_idxflags], 0
    mov     dword ptr [g_idxrev], 0
    ret
idx_reset endp

; =============================================================================
; idx_buf_ensure -> eax 0 ok / 1 out of memory
;
; RESERVES the inventory buffer the first time anything needs one.  Reserve, not
; commit: IDX_MAX_BYTES is 2047 MiB, and committing that to open a container
; holding four files would be worse than the 64 MiB of .data? this replaced.
; What gets committed is idx_buf_commit's business, and only as far as the index
; actually reaches.
;
; Called from the three procs that WRITE into the buffer - idx_auth (every read
; decrypts into it), idx_add (every pack and append) and zip_add_uniq (the zip
; listing) - and from nowhere else.  Everything that only READS runs after one of
; those three has succeeded, so a reader can take a valid pointer for granted;
; that is why the 45 load sites carry no null check, and why an allocation added
; at a leaf site instead would have needed 45 of them.
;
; Reserving the whole ceiling up front is what keeps the pointer STILL.  Growing
; by reallocation would move it, and 45 sites load it into a register and then
; make calls - so a growth during any of those would leave a stale base behind.
; Address space is free; this buys the pointer's stability with none of it.
;
; Never freed, deliberately.  The GUI's row model reads the buffer between
; operations for as long as a container is open, so freeing at the end of one
; operation is a use-after-free at the start of the next repaint.
; =============================================================================
public idx_buf_ensure
idx_buf_ensure proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_idxptr], 0
    jne     ibe_ok
    WINCALL VirtualAlloc, 0, IDX_MAX_BYTES, MEM_RESERVE, PAGE_READWRITE
    test    rax, rax
    jz      ibe_no
    mov     qword ptr [g_idxptr], rax
    mov     qword ptr [g_idxcommit], 0
ibe_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
ibe_no:
    mov     eax, 1
    FRAME_EPILOG
    ret
idx_buf_ensure endp

; =============================================================================
; idx_buf_commit(rcx = bytes that must be writable) -> eax 0 ok / 1 out of memory
;
; Commits the reservation as far as the index actually reaches, in 1 MiB steps so
; that packing a large tree does not make a system call per entry.  Committing an
; already-committed page is legal and free, but the syscall is not, hence the
; g_idxcommit high-water mark.
;
; Every caller has already been through idx_buf_ensure, so the reservation
; exists.  Anything past IDX_MAX_BYTES is refused rather than clamped: a caller
; asking for more than the ceiling has already made a mistake its own bound
; should have caught, and quietly committing less than it asked for would hand
; it a buffer shorter than it believes.
; =============================================================================
public idx_buf_commit
idx_buf_commit proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    cmp     rcx, qword ptr [g_idxcommit]
    jbe     ibc_ok                          ; already writable
    mov     rax, IDX_MAX_BYTES
    cmp     rcx, rax
    ja      ibc_no
    ; round up to a whole megabyte, saturating at the ceiling
    add     rcx, 0FFFFFh
    and     rcx, NOT 0FFFFFh
    mov     rax, IDX_MAX_BYTES
    cmp     rcx, rax
    jbe     @F
    mov     rcx, rax
@@:
    mov     qword ptr [rbp-24], rcx
    WINCALL VirtualAlloc, qword ptr [g_idxptr], qword ptr [rbp-24], MEM_COMMIT, PAGE_READWRITE
    test    rax, rax
    jz      ibc_no
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_idxcommit], rax
ibc_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
ibc_no:
    mov     eax, 1
    FRAME_EPILOG
    ret
idx_buf_commit endp

; =============================================================================
; idx_cap -> rax = the largest inventory THIS BUILD WILL WRITE.
;
; IDX_MAX_BYTES is the size of g_idxbuf and therefore two different limits at
; once: how much a reader may read INTO that buffer, and how much a writer will
; build inside it.  Only the second is adjustable, and the distinction is the
; whole point of this proc.
;
; The reader's bounds (idx_tail, idx_auth) stay pinned to IDX_MAX_BYTES and must
; never call this: a knob that loosened THOSE would be a buffer overflow with a
; switch on it.  This one can only make the writer refuse EARLIER, and a
; container written under a small cap is an ordinary container any build reads.
;
; Why it needs to be adjustable at all: idx_add's refusal is the fix for the
; worst failure this project has had - 76,286 files encrypted, 16,780 recorded,
; exit 0 - and reaching it honestly costs half a million files.  A control that
; nothing can exercise is a control nobody has seen work; see
; tests/indexfulltest.ps1, which reaches it with three.
; =============================================================================
public idx_cap
ifdef TEST_IO
idx_cap proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_idxcap_state], 0
    jne     ic_have
    mov     dword ptr [g_idxcap_state], 1
    mov     qword ptr [g_idxcap], IDX_MAX_BYTES
    WINCALL GetEnvironmentVariableW, addr w_dbg_idxmax, addr g_idxcap_buf, 24
    test    eax, eax
    jz      ic_have
    xor     r10, r10                        ; accumulated value
    xor     r9, r9
    lea     r11, [g_idxcap_buf]
ic_digit:
    movzx   eax, word ptr [r11+r9*2]
    test    eax, eax
    jz      ic_val
    sub     eax, '0'
    cmp     eax, 9
    ja      ic_have                         ; not a decimal number: ignore
    imul    r10, r10, 10
    add     r10, rax
    inc     r9
    cmp     r9, 20
    jb      ic_digit
ic_val:
    ; A FLOOR as well as a ceiling.  Zero, or something smaller than one entry,
    ; would refuse every possible pack - which looks exactly like the bug this
    ; exists to test for, and would make the test pass for the wrong reason.
    cmp     r10, IDXE_FIXED + 1024
    jb      ic_have
    cmp     r10, IDX_MAX_BYTES
    ja      ic_have
    mov     qword ptr [g_idxcap], r10
ic_have:
    mov     rax, qword ptr [g_idxcap]
    FRAME_EPILOG
    ret
idx_cap endp
else
idx_cap proc
    mov     rax, IDX_MAX_BYTES
    ret
idx_cap endp
endif

; =============================================================================
; nonce_set(rcx = counter, rdx = 12-byte destination, r8d = segment)
;
; The 96-bit GCM nonce, little-endian, as TWO fields in disjoint bit ranges:
;
;     bits  0..63   the counter   - an entry's ordinal + 1, or
;                                   IDX_NONCE_BASE + the index revision
;     bits 64..95   the segment   - which slice of a large entry this is
;
; Counters, not random values: see macros.inc.
;
; THE TOP 32 BITS WERE ALWAYS WRITTEN AS ZERO, and phase B spends them.  Passing
; segment 0 therefore reproduces every nonce this tool has ever written, byte
; for byte - which is why this could be plumbed through and proved before
; anything had a second segment to put there.
;
; The disjointness is the whole safety property and it is worth stating rather
; than assuming: two nonces are equal only if BOTH fields are equal.  A future
; edit that packed the segment into spare bits of the counter, or widened the
; counter over the segment, would reuse a nonce under one key - the one mistake
; in this design that no later fix undoes.  selftest.asm pins the layout with
; vectors chosen to fail if the two fields ever overlap by even one bit.
; =============================================================================
public nonce_set
ifdef TEST_IO
; The test-build variant logs every nonce it builds, encrypt and decrypt side
; alike - tests/segmenttest.ps1 sets MYRKR_DBG_NONCELOG only around an ENCRYPT
; run, so what lands in the file is exactly the set of nonces sealed under that
; container's key, and the test asserts no two lines match.  Nonce reuse is the
; one unrecoverable mistake in this design, this is the instrument that would
; see the code commit it, and it was written BEFORE the writer could segment.
nonce_set proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rdx], rcx
    mov     dword ptr [rdx+8], r8d
    mov     rcx, rdx
    call    nonce_log
    FRAME_EPILOG
    ret
nonce_set endp

; nonce_log(rcx = 12-byte nonce) - append it as one hex line to the file named
; by MYRKR_DBG_NONCELOG, when set.  Open/append/close per call: slow, simple,
; and only ever paid when the environment variable is present in a test build.
;
; THE LOG DOES NOT KNOW WHICH DIRECTION A NONCE WAS USED IN, so uniqueness only
; means anything over a run that never DECRYPTS - which an `add` is not: it
; reads the index (logging the current revision's nonce) before rewriting it
; under the next.  Wrapping an add therefore shows one benign duplicate, the
; read of what a previous run wrote.  Demonstrated in the 1.0.82 deep audit -
; encrypt + add = 18 issued, 17 distinct, the collision being idx rev 0 written
; then read - and the reason segmenttest.ps1 sets the variable around pure
; encrypts only.
nonce_log proc frame
    FRAME_PROLOG 96
    ; [rbp-16] nonce  [rbp-24] handle
    mov     qword ptr [rbp-16], rcx
    cmp     dword ptr [g_nlog_state], 1
    je      nl_ret                          ; checked before: off
    cmp     dword ptr [g_nlog_state], 2
    je      nl_fmt
    WINCALL GetEnvironmentVariableW, addr w_dbg_nlog, addr g_nlog_path, 300
    test    eax, eax
    jnz     @F
    mov     dword ptr [g_nlog_state], 1
    jmp     nl_ret
@@:
    mov     dword ptr [g_nlog_state], 2
nl_fmt:
    mov     r10, qword ptr [rbp-16]
    lea     r11, [g_nlog_line]
    xor     r9d, r9d
nl_hex:
    movzx   eax, byte ptr [r10+r9]
    mov     ecx, eax
    shr     eax, 4
    and     ecx, 0Fh
    add     eax, '0'
    cmp     eax, '9'
    jbe     @F
    add     eax, 'a' - '0' - 10
@@:
    mov     byte ptr [r11+r9*2], al
    mov     eax, ecx
    add     eax, '0'
    cmp     eax, '9'
    jbe     @F
    add     eax, 'a' - '0' - 10
@@:
    mov     byte ptr [r11+r9*2+1], al
    inc     r9d
    cmp     r9d, 12
    jb      nl_hex
    mov     byte ptr [r11+24], 13
    mov     byte ptr [r11+25], 10
    ; FILE_APPEND_DATA + OPEN_ALWAYS: every writer in the process appends
    ; atomically, so interleaved calls cannot shear a line
    WINCALL CreateFileW, addr g_nlog_path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTR_NORMAL, 0
    cmp     rax, INVALID
    je      nl_ret
    mov     qword ptr [rbp-24], rax
    ; the handle from the frame, never from rax: WINCALL emits stack args first
    ; and uses rax as its scratch - the checker below is what caught exactly that
    WINCALL WriteFile, qword ptr [rbp-24], addr g_nlog_line, 26, addr g_nlog_wr, 0
    WINCALL CloseHandle, qword ptr [rbp-24]
nl_ret:
    FRAME_EPILOG
    ret
nonce_log endp
else
nonce_set proc
    mov     qword ptr [rdx], rcx
    mov     dword ptr [rdx+8], r8d
    ret
nonce_set endp
endif

; =============================================================================
; idx_nonce_set - the index stream's nonce for the revision in the trailer.
; =============================================================================
idx_nonce_set proc frame
    FRAME_PROLOG 48
    lea     r10, [g_idxtrl]
    mov     ecx, dword ptr [r10+IDXT_rev]
    mov     rax, IDX_NONCE_BASE
    add     rcx, rax
    lea     rdx, [g_idxnonce]
    xor     r8d, r8d                        ; the index is never segmented: it is
                                            ; rewritten whole, and its revision -
                                            ; not a slice number - is what keeps
                                            ; its nonces apart
    call    nonce_set
    FRAME_EPILOG
    ret
idx_nonce_set endp

; =============================================================================
; idx_rev_bump -> eax = 0 advanced, 1 exhausted
;
; The one counter in this design that can WRAP.  The index's nonce is
; IDX_NONCE_BASE + revision and the revision is a 32-bit trailer field, so the
; 4294967296th rewrite of one container would roll it to 0 and encrypt a
; different index under revision 0's nonce - the mistake this whole scheme
; exists to avoid, arrived at by counting rather than by tampering.
;
; Every caller that is about to rewrite the index goes through here rather than
; incrementing the global, so the ceiling cannot be missed by a path added
; later.  It is deliberately NOT checked in idx_write: by the time the value is
; being turned into a nonce a wrapped revision reads as 0, which is exactly what
; a freshly packed container legitimately holds, and the two are then
; indistinguishable.  The check has to be at the increment or it is not a check.
;
; Refusing costs the container its last possible revision.  Repacking resets it,
; because a repack draws a fresh salt and a fresh key, and a fresh key makes the
; whole nonce space available again.
;
; No selftest can reach this by counting to 2^32, so selftest.asm drives
; g_idxrev directly - which is why it is public.
; =============================================================================
public idx_rev_bump, g_idxrev
idx_rev_bump proc
    mov     eax, dword ptr [g_idxrev]
    cmp     eax, IDX_REV_MAX
    jae     irb_full
    inc     dword ptr [g_idxrev]
    xor     eax, eax
    ret
irb_full:
    mov     eax, 1
    ret
idx_rev_bump endp

; =============================================================================
; seg_bytes_from_hdr(rcx = container header) -> rax = segment size in bytes,
;                                               0 = unsegmented, -1 = invalid
;
; THE ONLY PLACE A seg_shift BECOMES A BYTE COUNT.  Three reasons it is one
; place and it validates first:
;   - versions below HDR_VERSION_SEG ignore the byte entirely (it was reserved,
;     written 0, validated nowhere - a hostile v6 container could carry junk
;     there and every shipped reader ignored it, so this one must too);
;   - `shl rax, cl` masks cl to 6 bits, so an unvalidated shift of 64 quietly
;     computes 1 << 0 - a 1-BYTE segment - instead of failing;
;   - the bounds also keep one segment's plaintext under MAX_PLAINTEXT_SIZE,
;     which is the ceiling segments exist to duck.
; Clobbers rax, rcx only.
; =============================================================================
public seg_bytes_from_hdr
seg_bytes_from_hdr proc
    mov     eax, dword ptr [rcx+4]
    cmp     eax, HDR_VERSION_SEG
    jb      sbh_none
    movzx   eax, byte ptr [rcx+CONTAINER_HDR.seg_shift]
    test    eax, eax
    jz      sbh_none
    cmp     eax, SEG_SHIFT_MIN
    jb      sbh_bad
    cmp     eax, SEG_SHIFT_MAX
    ja      sbh_bad
    mov     ecx, eax
    mov     rax, 1
    shl     rax, cl
    ret
sbh_none:
    xor     eax, eax
    ret
sbh_bad:
    mov     rax, -1
    ret
seg_bytes_from_hdr endp

; =============================================================================
; entry_stream_open(rcx = gcm ctx, rdx = header, r8 = ordinal, r9 = decrypt,
;                   [rbp+48] = key)
;
; Open the GCM stream for one entry.  Nonce is the ordinal plus one - zero
; belongs to the index - and the ordinal goes into the AAD, so an entry cannot
; be moved, duplicated or spliced in from another position without failing its
; tag.  One proc rather than three copies: the writer, the archive reader and
; the single-file reader must agree on this exactly, and the cheapest way to
; guarantee that is for there to be only one of it.
;
; The KEY is a parameter and not g_key, for the same reason gcm_init takes its
; context by pointer.  Every caller here passes g_key, and reads exactly as
; before; estream.asm does not, because a drag-out stream is constructed while
; the user is still holding the mouse button and is READ minutes later, long
; after idx_read has wiped the global (see g_keep_key, below).  A key it fetched
; from a global at that point would be zeros - and the only symptom is a failing
; tag, which is indistinguishable from a corrupted container.
; =============================================================================
public entry_stream_open
entry_stream_open proc frame
    FRAME_PROLOG 112                        ; 112, not 80: the key made a fifth
                                            ; local and at 64 it landed exactly
                                            ; where gcm_init's outgoing area
                                            ; began; the segment and the AAD
                                            ; length make seven, and at 80 the
                                            ; last two would land there instead.
                                            ; framecheck is what says so.
    ; [rbp-16]=ctx [rbp-24]=hdr [rbp-32]=ordinal [rbp-40]=decrypt [rbp-48]=key
    ; [rbp-56]=segment [rbp-64]=aad length
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], r9
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-48], rax             ; key
    mov     eax, dword ptr [rbp+56]
    mov     dword ptr [rbp-56], eax             ; segment
    mov     rcx, r8
    inc     rcx
    lea     rdx, [g_idxnonce]
    mov     r8d, dword ptr [rbp-56]
    call    nonce_set
    lea     r10, [g_entaad]
    mov     r11, qword ptr [rbp-24]
    xor     r9, r9
eso_aad:
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    cmp     r9, HDR_BYTES
    jb      eso_aad
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+HDR_BYTES], rax
    ; The AAD length is decided HERE and nowhere else, from the version in the
    ; header this call was handed.  A reader opening an old container and a
    ; writer producing a new one both arrive at it the same way, so they cannot
    ; disagree about how many bytes GHASH covered.
    mov     r11, qword ptr [rbp-24]
    mov     r8, ENTRY_AAD_BYTES
    cmp     dword ptr [r11+4], HDR_VERSION_SEG
    jb      eso_len
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [r10+HDR_BYTES+8], eax
    mov     r8, ENTRY_AAD_SEG_BYTES
eso_len:
    mov     qword ptr [rbp-64], r8
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-48]
    lea     r8, [g_idxnonce]
    mov     r9, qword ptr [rbp-40]
    call    gcm_init
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [g_entaad]
    mov     r8, qword ptr [rbp-64]
    call    gcm_aad
    FRAME_EPILOG
    ret
entry_stream_open endp

; =============================================================================
; entry_begin - open a fresh GCM stream for the next entry.
;
; Nonce is the entry's ordinal plus one (zero belongs to the index), and the
; ordinal goes into the AAD so an entry cannot be moved, duplicated or spliced
; in from another position without failing its tag.
; =============================================================================
entry_begin proc frame
    FRAME_PROLOG 48
    mov     rax, qword ptr [g_payoff]
    mov     qword ptr [g_entoff], rax
    ; Segmentation comes FROM THE HEADER, per entry - not from this build's
    ; config - so an append to an existing container behaves exactly as that
    ; container says.  -1 cannot reach here on the pack path (the header is
    ; ours) and idx_read refuses it on the add path; the guard is for the day
    ; either of those stops being true, and g_packerr is the sticky error every
    ; level of the walk already checks.
    lea     rcx, [g_pkhdr]
    call    seg_bytes_from_hdr
    cmp     rax, -1
    jne     @F
    mov     qword ptr [g_packerr], EXIT_CORRUPT
    xor     eax, eax
@@:
    mov     qword ptr [g_segbytes], rax
    mov     qword ptr [g_segfill], 0
    mov     dword ptr [g_segidx], 0
    lea     rcx, [g_pkctx]
    lea     rdx, [g_pkhdr]
    mov     r8, qword ptr [g_entnext]
    xor     r9, r9                              ; encrypt
    lea     rax, [g_key]
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0               ; every entry starts at segment 0
    call    entry_stream_open
    mov     qword ptr [g_sinkfill], 0
    mov     qword ptr [g_rawfill], 0
    FRAME_EPILOG
    ret
entry_begin endp

; =============================================================================
; seg_roll - close the open segment's GCM stream and start the next one.
;
; Called from sink_flush_block when the open segment is FULL and more bytes are
; about to be fed - never merely because it filled.  That laziness is load-
; bearing: an entry whose plaintext is an exact multiple of SEG_BYTES must end
; with k full segments, not k plus an empty one, because the reader derives the
; segment count from IDXE_stored as n = ceil(stored / (SEG_BYTES + 16)) and an
; empty tail segment would make the writer and that formula disagree.
;
; THE ORDINAL DOES NOT CHANGE.  entry_end advances g_entnext once per ENTRY,
; after its last segment; a roll re-opens the same ordinal at segment+1.
; Touching g_entnext here would give two entries one ordinal - nonce reuse,
; the one mistake in this design that no later fix undoes.  The selftest's
; nonce-layout vectors pin the fields; tests/segmenttest.ps1's log harness is
; what catches a duplicate actually being issued.
; =============================================================================
seg_roll proc frame
    FRAME_PROLOG 64
    lea     rcx, [g_pkctx]
    lea     rdx, [g_pktag]
    call    gcm_final
    ; vol_put, not vol_write: same reason as the sink - an append writes to one
    ; existing file's handle, and only a fresh pack has a volume set open.
    mov     rcx, qword ptr [g_sink_hout]
    lea     rdx, [g_pktag]
    mov     r8, GCM_TAG_LEN
    call    vol_put
    test    eax, eax
    jz      sr_counted
    mov     r10d, eax
    mov     qword ptr [g_packerr], r10
    jmp     sr_ret
sr_counted:
    add     qword ptr [g_payoff], GCM_TAG_LEN
    inc     dword ptr [g_segidx]
    lea     rcx, [g_pkctx]
    lea     rdx, [g_pkhdr]
    mov     r8, qword ptr [g_entnext]           ; the SAME ordinal - see above
    xor     r9, r9                              ; encrypt
    lea     rax, [g_key]
    mov     qword ptr [rsp+32], rax
    mov     eax, dword ptr [g_segidx]
    mov     qword ptr [rsp+40], rax
    call    entry_stream_open
    mov     qword ptr [g_segfill], 0
sr_ret:
    FRAME_EPILOG
    ret
seg_roll endp

; =============================================================================
; entry_end - close the entry's stream: flush, tag, and append the tag.
; The tag counts toward the entry's stored length, so an extent covers
; everything a reader needs and nothing it does not.
; =============================================================================
entry_end proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_compress], 0
    je      ee_flush
    call    csink_flush
ee_flush:
    call    sink_flush_block
    cmp     qword ptr [g_packerr], 0
    jne     ee_ret
    lea     rcx, [g_pkctx]
    lea     rdx, [g_pktag]
    call    gcm_final
    ; vol_put for the same reason as the sink: entry_end runs for an append too
    mov     rcx, qword ptr [g_sink_hout]
    lea     rdx, [g_pktag]
    mov     r8, GCM_TAG_LEN
    call    vol_put
    test    eax, eax
    jz      ee_counted
    mov     qword ptr [g_packerr], EXIT_IO
    jmp     ee_ret
ee_counted:
    add     qword ptr [g_payoff], GCM_TAG_LEN
    inc     qword ptr [g_entnext]
ee_ret:
    FRAME_EPILOG
    ret
entry_end endp

; =============================================================================
; idx_add(rcx = size, edx = entry flags) - record g_rel in the listing.
;
; Called from the packing pass, not from the sizing walk, so an entry exists if
; and only if the container holds it.  Once the buffer is full the listing is
; marked truncated and further entries are dropped: a container whose preview is
; incomplete is far better than an encrypt that fails over a preview.
; =============================================================================
idx_add proc frame
    FRAME_PROLOG 64                         ; 64, not 48: at 48 the flags local
                                            ; [rbp-24] lands at rsp+24, inside the
                                            ; outgoing shadow space, so any call
                                            ; between storing and reading it would
                                            ; clobber it.  Nothing called there
                                            ; until the refusal below did.
    ; [rbp-16]=size [rbp-24]=flags
    mov     qword ptr [rbp-16], rcx
    mov     dword ptr [rbp-24], edx
    mov     rax, qword ptr [g_rellen]
    test    rax, rax
    jz      ia_ret                          ; nameless entry: nothing to list
    call    idx_buf_ensure                  ; the buffer exists from here on
    test    eax, eax
    jz      ia_haveb
    mov     qword ptr [g_packerr], EXIT_OOM ; sticky; unwinds the whole pack
    jmp     ia_ret
ia_haveb:
    call    idx_cap                         ; what this build will WRITE
    mov     r11, rax
    mov     rax, qword ptr [g_rellen]
    add     rax, IDXE_FIXED
    add     rax, qword ptr [g_idxlen]
    cmp     rax, r11
    ja      ia_full
    ; make the bytes this entry is about to occupy writable.  After the ceiling
    ; test, so a container that is refused never commits anything for it.
    mov     rcx, rax
    call    idx_buf_commit
    test    eax, eax
    jz      ia_room
    mov     qword ptr [g_packerr], EXIT_OOM
    jmp     ia_ret
ia_full:
    ; FULL: fail the pack.  This used to set IDXF_TRUNCATED and return, leaving
    ; pack_node to write the entry into the payload anyway - an entry with no
    ; index record, and the index is the only thing that locates an entry, so it
    ; became ciphertext nobody can address.  The encrypt then said "packed ->".
    ; g_packerr is sticky and every level of the walk checks it, so this unwinds
    ; the whole pack and the caller discards the partial output.
    prn     e_idx_full
    mov     qword ptr [g_packerr], EXIT_UNSUPPORTED
    jmp     ia_ret
ia_room:
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [g_idxlen]       ; -> this entry
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [r10+IDXE_size], rax
    ; the extent: where entry_begin started this entry, and everything
    ; entry_end has written since, its tag included
    mov     rax, qword ptr [g_entoff]
    mov     qword ptr [r10+IDXE_offset], rax
    mov     rax, qword ptr [g_payoff]
    sub     rax, qword ptr [g_entoff]
    mov     qword ptr [r10+IDXE_stored], rax
    ; The ordinal is RECORDED, not implied by position: deleting an entry must
    ; not renumber the survivors, whose tags are bound to the ordinal they were
    ; sealed with.  entry_end has already advanced g_entnext past this one.
    mov     rax, qword ptr [g_entnext]
    dec     rax
    mov     qword ptr [r10+IDXE_ordinal], rax
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [r10+IDXE_flags], eax
    mov     rax, qword ptr [g_rellen]
    mov     dword ptr [r10+IDXE_namelen], eax
    lea     r11, [g_rel]
    xor     r9, r9
ia_copy:
    cmp     r9, qword ptr [g_rellen]
    jae     ia_copied
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+IDXE_name+r9], al
    inc     r9
    jmp     ia_copy
ia_copied:
    mov     rax, qword ptr [g_rellen]
    add     rax, IDXE_FIXED
    add     qword ptr [g_idxlen], rax
    inc     qword ptr [g_idxcount]
    ; One line in the window's action log per entry that actually landed in the
    ; listing.  HERE and not at the caller: this is the point where the entry is
    ; committed, so a name logged from it was genuinely written.  Every .mrk path
    ; funnels through it - a fresh container, an add, and the bare single-file
    ; case - so there is one call site rather than three.  No-op in the CLI.
    lea     rcx, [g_rel]
    mov     edx, dword ptr [g_rellen]
    call    rlog_added
ia_ret:
    FRAME_EPILOG
    ret
idx_add endp

; =============================================================================
; idx_bare_name - put the lone input's base name in g_rel, for the one entry a
; single-file container gets.  Archive mode has g_rel from the tar naming; bare
; mode packs raw bytes and never builds one.
; =============================================================================
; locals (frame 96): base[-16] chars[-24].  96, not 64: WideCharToMultiByte
; takes EIGHT arguments, so its outgoing area is 32 bytes of shadow space plus
; four stack slots - 64 bytes - and at 64 that area swallowed the character
; count on its way to being passed.
idx_bare_name proc frame
    FRAME_PROLOG 96
    mov     qword ptr [g_rellen], 0
    cmp     qword ptr [g_poscount], 0
    je      ibn_ret
    lea     r11, [g_positionals]
    mov     r11, qword ptr [r11]                ; argv path, UTF-16
    test    r11, r11
    jz      ibn_ret
    ; walk to the terminator, remembering the last separator
    xor     r9, r9
    xor     r10, r10                            ; index just past the last '\' or '/'
ibn_scan:
    movzx   eax, word ptr [r11+r9*2]
    test    ax, ax
    jz      ibn_scanned
    cmp     ax, 5Ch
    je      ibn_sep
    cmp     ax, 2Fh
    jne     ibn_next
ibn_sep:
    lea     r10, [r9+1]
ibn_next:
    inc     r9
    cmp     r9, 8000h
    jb      ibn_scan
ibn_scanned:
    cmp     r10, r9
    jae     ibn_ret                             ; path ends in a separator
    lea     rcx, [r11+r10*2]
    mov     qword ptr [rbp-16], rcx
    sub     r9, r10
    mov     qword ptr [rbp-24], r9              ; chars in the base name
    ; CP_UTF8 = 65001; -1 length would copy the NUL, so pass the count
    WINCALL WideCharToMultiByte, 65001, 0, qword ptr [rbp-16], qword ptr [rbp-24], addr g_rel, 4000, 0, 0
    test    eax, eax
    jle     ibn_ret
    cdqe
    mov     qword ptr [g_rellen], rax
ibn_ret:
    FRAME_EPILOG
    ret
idx_bare_name endp

; =============================================================================
; idx_write(rcx = output handle) -> eax 0 / EXIT_IO
;
; Encrypts the listing in place and appends it, its tag and the trailer to the
; container.  Runs after the payload's own gcm_final, so g_pkctx is free to be
; re-initialised for the second stream.
; =============================================================================
idx_write proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx         ; handle
    ; ---- trailer ------------------------------------------------------------
    lea     r10, [g_idxtrl]
    mov     eax, dword ptr [g_idxflags]
    mov     dword ptr [r10+IDXT_flags], eax
    mov     eax, dword ptr [g_idxcount]
    mov     dword ptr [r10+IDXT_count], eax
    mov     rax, qword ptr [g_idxlen]
    mov     qword ptr [r10+IDXT_len], rax
    mov     dword ptr [r10+IDXT_magic], IDX_MAGIC
    mov     eax, dword ptr [g_idxrev]
    mov     dword ptr [r10+IDXT_rev], eax
    ; The high-water ordinal, so the next writer cannot reissue one.  This is
    ; written on EVERY index rewrite, including a delete's - a delete must not
    ; be able to lower it, and the only reason it cannot is that nothing between
    ; idx_auth and here ever assigns g_entnext downward.
    mov     rax, qword ptr [g_entnext]
    mov     qword ptr [r10+IDXT_next], rax
    ; ---- nonce: the revision, at the top of the counter space ---------------
    ; A rewritten index is different plaintext under the same key; reusing the
    ; nonce it had would be fatal, so each revision gets its own.
    call    idx_nonce_set
    ; ---- AAD: header then trailer, contiguous so one gcm_aad covers both -----
    lea     r10, [g_idxaad]
    lea     r11, [g_pkhdr]
    xor     r9, r9
iw_aad1:
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    cmp     r9, HDR_BYTES
    jb      iw_aad1
    lea     r11, [g_idxtrl]
    xor     r9, r9
iw_aad2:
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+HDR_BYTES+r9], al
    inc     r9
    cmp     r9, IDX_TRAILER_BYTES
    jb      iw_aad2
    ; ---- encrypt in place ---------------------------------------------------
    lea     rcx, [g_pkctx]
    lea     rdx, [g_key]
    lea     r8, [g_idxnonce]
    xor     r9, r9                          ; encrypt
    call    gcm_init
    lea     rcx, [g_pkctx]
    lea     rdx, [g_idxaad]
    mov     r8, IDX_AAD_BYTES
    call    gcm_aad
    cmp     qword ptr [g_idxlen], 0
    je      iw_tag
    lea     rcx, [g_pkctx]
    mov     rdx, qword ptr [g_idxptr]
    mov     r8, qword ptr [g_idxptr]
    mov     r9, qword ptr [g_idxlen]
    call    gcm_crypt
iw_tag:
    lea     rcx, [g_pkctx]
    lea     rdx, [g_pktag2]
    call    gcm_final
    ; ---- append: ciphertext, tag, trailer -----------------------------------
    cmp     qword ptr [g_idxlen], 0
    je      iw_wtag
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [g_idxptr]
    mov     r8, qword ptr [g_idxlen]
    call    vol_put
    test    eax, eax
    jnz     iw_io
iw_wtag:
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [g_pktag2]
    mov     r8, GCM_TAG_LEN
    call    vol_put
    test    eax, eax
    jnz     iw_io
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [g_idxtrl]
    mov     r8, IDX_TRAILER_BYTES
    call    vol_put
    test    eax, eax
    jnz     iw_io
    xor     eax, eax
    FRAME_EPILOG
    ret
iw_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
idx_write endp

; =============================================================================
; idx_tail(rcx = handle, rdx = file size, r8 = header destination)
;   -> rax = bytes the inventory occupies after the payload tag, or -1 if the
;      trailer is not a valid one.
;
; Leaves the file pointer where the caller wants it: at HDR_BYTES, having read
; the header on the way back.  Both readers need exactly that, and doing it here
; keeps the seek-to-the-end out of their streaming logic.
; =============================================================================
public idx_tail
idx_tail proc frame
    FRAME_PROLOG 64
    ; [rbp-16]=handle [rbp-24]=size [rbp-40]=header dest
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-40], r8
    mov     rax, rdx
    sub     rax, CONTAINER_MIN_SIZE + IDX_TAIL_FIXED
    js      it_bad                          ; too small to hold an inventory
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    sub     rdx, IDX_TRAILER_BYTES
    lea     r8, [g_idxtrl]
    mov     r9, IDX_TRAILER_BYTES
    call    vol_get
    test    eax, eax
    jnz     it_bad
    lea     r10, [g_idxtrl]
    cmp     dword ptr [r10+IDXT_magic], IDX_MAGIC
    jne     it_bad
    mov     rax, qword ptr [r10+IDXT_len]
    ; A negative length is a hostile one, and this is the test that says so.
    ; There used to be a bare `js` on the line after the mov, which could never
    ; fire: `mov` writes no flags, so it read the sign of the MAGIC comparison
    ; two lines up - and that comparison is equal on every path that reaches
    ; here, so SF was always 0.  The bound below happens to have covered the case
    ; anyway because `ja` is unsigned and a negative length is a huge unsigned
    ; one, but a guard that cannot fire is worse than no guard: it reads as
    ; protection, and the protection would have vanished the day someone made
    ; that `ja` signed.
    test    rax, rax
    js      it_bad
    cmp     rax, IDX_MAX_BYTES
    ja      it_bad
    add     rax, IDX_TAIL_FIXED
    ; the payload must still have room for its own header and tag
    mov     r10, qword ptr [rbp-24]
    sub     r10, CONTAINER_MIN_SIZE
    cmp     rax, r10
    ja      it_bad
    mov     qword ptr [rbp-32], rax
    ; back to the header, leaving the pointer at HDR_BYTES as the callers expect
    mov     rcx, qword ptr [rbp-16]
    xor     rdx, rdx
    mov     r8, qword ptr [rbp-40]
    mov     r9, HDR_BYTES
    call    vol_get
    test    eax, eax
    jnz     it_bad
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
it_bad:
    mov     rax, -1
    FRAME_EPILOG
    ret
idx_tail endp

; =============================================================================
; pack_emit_file - emit ustar file entry for g_walk (path) named g_rel
; =============================================================================
pack_emit_file proc frame
    FRAME_PROLOG 160
    ; [rbp-32]=hin [rbp-40]=remaining [rbp-56]=chunklen [rbp-64]=padlen [rbp-72]=size
    mov     qword ptr [rbp-32], INVALID
    lea     rcx, [g_rel]
    mov     rdx, qword ptr [g_rellen]
    call    split_name
    test    eax, eax
    jnz     pe_toolong
    lea     rcx, [g_walk]
    call    file_open_read
    cmp     rax, INVALID
    je      pe_err
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    lea     rdx, [rbp-72]
    call    get_file_size
    test    eax, eax
    jnz     pe_err
    mov     rax, qword ptr [rbp-72]
    and     rax, 511
    mov     r8, 512
    sub     r8, rax
    and     r8, 511
    mov     qword ptr [rbp-64], r8
    mov     rax, qword ptr [rbp-72]
    mov     qword ptr [rbp-40], rax
    call    entry_begin                  ; this file is its own GCM stream
    lea     rcx, [g_tarhdr]
    lea     rdx, [g_namebuf]
    lea     r8, [g_prefixbuf]
    mov     r9, qword ptr [rbp-72]
    mov     qword ptr [rsp+32], '0'
    call    tar_build_header
    lea     rcx, [g_tarhdr]
    mov     rdx, 512
    call    tar_out
    xWHILE qword ptr [rbp-40], ne, 0     ; while file bytes remain
        mov     r8, qword ptr [rbp-40]
        xIF r8, a, CHUNK
            mov     r8, CHUNK
        xENDIF
        mov     qword ptr [rbp-56], r8
        mov     rcx, qword ptr [rbp-32]
        lea     rdx, [g_filebuf]
        call    file_read_exact
        test    eax, eax
        jnz     pe_err
        lea     rcx, [g_filebuf]
        mov     rdx, qword ptr [rbp-56]
        call    tar_out
        mov     rcx, qword ptr [rbp-56]
        call    progress_add
        test    eax, eax
        jnz     pe_err                   ; cancel requested
        mov     rax, qword ptr [rbp-56]
        sub     qword ptr [rbp-40], rax
    xENDW
pe_pad:
    cmp     qword ptr [rbp-64], 0
    je      pe_close
    lea     rcx, [g_zeros]
    mov     rdx, qword ptr [rbp-64]
    call    tar_out
pe_close:
    call    entry_end
    ; the inventory is written by the same pass that writes the entry it
    ; describes, and only once the extent is known
    mov     rcx, qword ptr [rbp-72]
    xor     edx, edx
    call    idx_add
    mov     rcx, qword ptr [rbp-32]
    call    file_close
    FRAME_EPILOG
    ret
pe_toolong:
    prn     e_pname
    mov     qword ptr [g_packerr], EXIT_CORRUPT
    jmp     pe_cleanup
pe_err:
    mov     qword ptr [g_packerr], EXIT_IO
pe_cleanup:
    mov     rcx, qword ptr [rbp-32]
    call    file_close
    FRAME_EPILOG
    ret
pack_emit_file endp

; =============================================================================
; pack_emit_dirhdr - emit ustar directory entry for g_rel (name + '/')
; =============================================================================
pack_emit_dirhdr proc frame
    FRAME_PROLOG 64
    lea     r10, [g_childu8]
    lea     r11, [g_rel]
    mov     rcx, qword ptr [g_rellen]
    xor     r9, r9
pd_c:
    cmp     r9, rcx
    jae     pd_cd
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    jmp     pd_c
pd_cd:
    mov     byte ptr [r10+r9], '/'
    inc     r9
    mov     byte ptr [r10+r9], 0
    lea     rcx, [g_childu8]
    mov     rdx, qword ptr [g_rellen]
    inc     rdx
    call    split_name
    test    eax, eax
    jnz     pdh_toolong
    lea     rcx, [g_tarhdr]
    lea     rdx, [g_namebuf]
    lea     r8, [g_prefixbuf]
    xor     r9, r9
    mov     qword ptr [rsp+32], '5'
    call    tar_build_header
    call    entry_begin
    lea     rcx, [g_tarhdr]
    mov     rdx, 512
    call    tar_out
    call    entry_end
    ; the listing carries the bare name and a flag; the trailing '/' above is a
    ; tar convention, not something a reader of the inventory should have to strip
    xor     rcx, rcx
    mov     edx, IDXEF_DIR
    call    idx_add
    FRAME_EPILOG
    ret
pdh_toolong:
    prn     e_pname
    mov     qword ptr [g_packerr], EXIT_CORRUPT
    FRAME_EPILOG
    ret
pack_emit_dirhdr endp

; =============================================================================
; pack_node - process g_walk (full path) with entry name g_rel; recurse on dirs
; =============================================================================
pack_node proc frame
    FRAME_PROLOG 720
    ; finddata at [rsp+64] (592 bytes) ; [rbp-24]=hfind
    WINCALL GetFileAttributesW, addr g_walk
    cmp     eax, -1
    je      pn_err
    test    eax, FILE_ATTR_DIR
    jz      pn_isfile

    call    pack_emit_dirhdr
    cmp     qword ptr [g_packerr], 0
    jne     pn_ret
    ; append "\*" for the directory search
    mov     rax, qword ptr [g_walklen]
    lea     r10, [g_walk]
    mov     word ptr [r10+rax*2], 5Ch
    mov     word ptr [r10+rax*2+2], '*'
    mov     word ptr [r10+rax*2+4], 0
    WINCALL FindFirstFileW, addr g_walk, addr rsp+64
    mov     r11, qword ptr [g_walklen]  ; restore g_walk (remove \*)
    lea     r10, [g_walk]
    mov     word ptr [r10+r11*2], 0
    cmp     rax, -1
    je      pn_ret
    mov     qword ptr [rbp-24], rax
pn_child:
    ; skip "." and ".."
    lea     r10, [rsp+64+FIND_CFILENAME]
    movzx   eax, word ptr [r10]
    cmp     ax, '.'
    jne     pn_dochild
    movzx   edx, word ptr [r10+2]
    test    dx, dx
    jz      pn_next
    cmp     dx, '.'
    jne     pn_dochild
    movzx   edx, word ptr [r10+4]
    test    dx, dx
    jz      pn_next
pn_dochild:
    mov     rax, qword ptr [g_walklen]
    mov     qword ptr [rbp-32], rax     ; save walk len
    mov     rax, qword ptr [g_rellen]
    mov     qword ptr [rbp-40], rax     ; save rel len
    ; g_walk += "\" + child
    mov     rax, qword ptr [g_walklen]
    lea     r10, [g_walk]
    mov     word ptr [r10+rax*2], 5Ch
    inc     rax
    lea     r11, [rsp+64+FIND_CFILENAME]
    xor     r9, r9
pn_wcpy:
    mov     dx, word ptr [r11+r9*2]
    test    dx, dx
    jz      pn_wcpyd
    mov     word ptr [r10+rax*2], dx
    inc     rax
    inc     r9
    cmp     rax, 7F00h
    jb      pn_wcpy
pn_wcpyd:
    mov     word ptr [r10+rax*2], 0
    mov     qword ptr [g_walklen], rax
    ; Excluded?  The full child path is built by now, so this costs a set probe
    ; and nothing else.  Skipping here is what keeps the container honest.
    cmp     qword ptr [g_excluded], 0        ; PSET_count: usually zero
    je      pn_notexcl
    lea     rcx, [g_excluded]
    lea     rdx, [g_walk]
    call    pset_has
    test    eax, eax
    jz      pn_notexcl
    mov     rax, qword ptr [rbp-32]          ; restore walk + rel lengths
    mov     qword ptr [g_walklen], rax
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_rellen], rax
    jmp     pn_next
pn_notexcl:
    ; child UTF-16 -> g_childu8
    WINCALL WideCharToMultiByte, CP_UTF8, 0, addr rsp+64+FIND_CFILENAME, -1, addr g_childu8, 1024, 0, 0
    ; g_rel += "/" + g_childu8
    mov     rax, qword ptr [g_rellen]
    lea     r10, [g_rel]
    mov     byte ptr [r10+rax], '/'
    inc     rax
    lea     r11, [g_childu8]
    xor     r9, r9
pn_rcpy:
    mov     dl, byte ptr [r11+r9]
    test    dl, dl
    jz      pn_rcpyd
    mov     byte ptr [r10+rax], dl
    inc     rax
    inc     r9
    cmp     rax, 4000
    jb      pn_rcpy
pn_rcpyd:
    mov     byte ptr [r10+rax], 0
    mov     qword ptr [g_rellen], rax
    call    pack_node
    ; restore lengths + terminators
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [g_walklen], rax
    lea     r10, [g_walk]
    mov     word ptr [r10+rax*2], 0
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_rellen], rax
    lea     r10, [g_rel]
    mov     byte ptr [r10+rax], 0
    cmp     qword ptr [g_packerr], 0
    jne     pn_findclose
pn_next:
    WINCALL FindNextFileW, qword ptr [rbp-24], addr rsp+64
    test    eax, eax
    jnz     pn_child
pn_findclose:
    WINCALL FindClose, qword ptr [rbp-24]
pn_ret:
    FRAME_EPILOG
    ret
pn_isfile:
    call    pack_emit_file
    FRAME_EPILOG
    ret
pn_err:
    mov     qword ptr [g_packerr], EXIT_IO
    FRAME_EPILOG
    ret
pack_node endp

; =============================================================================
; add_prefix_copy(rcx = dst) -> rax = bytes written.
;
; Puts the append destination at the front of an entry-name buffer, so that the
; leaf that follows lands inside a folder rather than at the archive root.
; Shared by both formats: they build names in different buffers but by the same
; rule, and one copy of that rule is the point.
;
; Clamps at ADDPFX_MAX regardless of what g_add_prefixlen says.  Every builder
; already caps before writing, so this can only fire if something set the
; length without setting the bytes - and truncating a destination is far better
; than running off the end of the name buffer.
; =============================================================================
; =============================================================================
; pfx_reset - forget every staged destination.
;
; Called wherever the input list is rebuilt from scratch.  The offsets are
; indexed by POSITION, and positions are not stable across a rebuild - so a
; stale array does not merely say the wrong thing, it says it about a different
; file.  Cheaper and safer to drop the lot than to try to move it.
; =============================================================================
public pfx_reset
pfx_reset proc
    xor     rax, rax
pr_lp:
    cmp     rax, MAX_ARGS
    jae     pr_done
    lea     r10, [g_pos_prefix]
    mov     dword ptr [r10+rax*4], 0
    inc     rax
    jmp     pr_lp
pr_done:
    mov     qword ptr [g_pfx_head], 0
    ret
pfx_reset endp

; =============================================================================
; pfx_stage(rcx = input index, rdx = UTF-8 folder, r8 = length) -> eax 0 ok
;
; Records where one input is to land.  Stored with exactly one trailing '/', so
; the name builders can concatenate without deciding anything, and refused
; rather than truncated if the arena is full: a destination that is almost
; right names a different folder.
;
; The stored text is NOT validated here.  sanitize_name runs on the COMBINED
; name in pack_input_top / zip_input_top, which is the only place the whole
; string exists - see docs/DROP_INDICATOR.md.
; =============================================================================
public pfx_stage
pfx_stage proc
    cmp     rcx, MAX_ARGS
    jae     ps_bad
    test    r8, r8
    jz      ps_clear                        ; empty means the root
    cmp     r8, ADDPFX_MAX - 2
    jae     ps_bad
    mov     r9, qword ptr [g_pfx_head]
    test    r9, r9
    jnz     ps_haveHead
    mov     r9, 1                           ; keep offset 0 as the empty string
ps_haveHead:
    mov     rax, r9
    add     rax, r8
    add     rax, 2                          ; the '/' and the terminator
    cmp     rax, PFXARENA_BYTES
    jae     ps_bad
    lea     r10, [g_pos_prefix]
    mov     dword ptr [r10+rcx*4], r9d
    lea     r10, [g_pfx_arena]
    xor     r11, r11
ps_copy:
    cmp     r11, r8
    jae     ps_copied
    mov     al, byte ptr [rdx+r11]
    cmp     al, 5Ch                         ; a Windows separator would survive
    jne     @F                              ; into an entry name otherwise
    mov     al, 2Fh
@@:
    mov     byte ptr [r10+r9], al
    inc     r9
    inc     r11
    jmp     ps_copy
ps_copied:
    ; exactly one trailing separator, whatever the caller passed
    cmp     byte ptr [r10+r9-1], 2Fh
    je      @F
    mov     byte ptr [r10+r9], 2Fh
    inc     r9
@@:
    mov     byte ptr [r10+r9], 0
    inc     r9
    mov     qword ptr [g_pfx_head], r9
    xor     eax, eax
    ret
ps_clear:
    lea     r10, [g_pos_prefix]
    mov     dword ptr [r10+rcx*4], 0
    xor     eax, eax
    ret
ps_bad:
    mov     eax, 1
    ret
pfx_stage endp

; =============================================================================
; pfx_select(rcx = input index) - make that input's destination the current one.
;
; do_pack and do_zip call this before every input, so a single run can place
; different inputs in different folders.  do_add and do_zip_add do NOT: an
; append has one destination for the whole drop, already in g_add_prefix, and
; calling this would overwrite it with nothing.
; =============================================================================
public pfx_select
pfx_select proc
    mov     qword ptr [g_add_prefixlen], 0
    mov     byte ptr [g_add_prefix], 0
    cmp     rcx, MAX_ARGS
    jae     psel_ret
    lea     r10, [g_pos_prefix]
    mov     r9d, dword ptr [r10+rcx*4]
    test    r9d, r9d
    jz      psel_ret                        ; offset 0 = the root
    lea     r10, [g_pfx_arena]
    lea     r11, [g_add_prefix]
    xor     rax, rax
psel_copy:
    cmp     rax, ADDPFX_MAX
    jae     psel_done
    mov     dl, byte ptr [r10+r9]
    mov     byte ptr [r11+rax], dl
    test    dl, dl
    jz      psel_done
    inc     rax
    inc     r9
    jmp     psel_copy
psel_done:
    mov     byte ptr [r11+rax], 0
    mov     qword ptr [g_add_prefixlen], rax
psel_ret:
    ret
pfx_select endp

public add_prefix_copy
add_prefix_copy proc
    xor     rax, rax
    mov     r11, qword ptr [g_add_prefixlen]
    cmp     r11, ADDPFX_MAX
    jbe     apc_lp
    mov     r11, ADDPFX_MAX
apc_lp:
    cmp     rax, r11
    jae     apc_ret
    lea     r10, [g_add_prefix]
    movzx   edx, byte ptr [r10+rax]
    mov     byte ptr [rcx+rax], dl
    inc     rax
    jmp     apc_lp
apc_ret:
    ret
add_prefix_copy endp

; =============================================================================
; pack_input_top(rcx = positional path) - set up g_walk/g_rel then pack_node
; =============================================================================
pack_input_top proc frame
    FRAME_PROLOG 96
    lea     r10, [g_walk]
    xor     r9, r9
pit_c:
    mov     ax, word ptr [rcx+r9*2]
    mov     word ptr [r10+r9*2], ax
    test    ax, ax
    jz      pit_cd
    inc     r9
    cmp     r9, 7F00h
    jb      pit_c
pit_cd:
    mov     qword ptr [g_walklen], r9
    ; leaf start = after last separator
    xor     r8, r8
    xor     r9, r9
pit_scan:
    movzx   eax, word ptr [r10+r9*2]
    test    eax, eax
    jz      pit_scandone
    cmp     eax, '\'
    je      pit_sep
    cmp     eax, '/'
    jne     pit_sadv
pit_sep:
    lea     r8, [r9+1]
pit_sadv:
    inc     r9
    jmp     pit_scan
pit_scandone:
    lea     rax, [g_walk]
    lea     r8, [rax+r8*2]              ; leaf ptr (src)
    mov     qword ptr [rbp-16], r8      ; survives the helper call below
    ; The destination goes in first and the leaf is converted AFTER it, so the
    ; combined name is what pack_node then recurses from - children inherit the
    ; prefix for free, because g_rel is the base every child appends to.
    lea     rcx, [g_rel]
    call    add_prefix_copy
    mov     r11, rax                    ; prefix bytes actually written
    lea     r10, [g_rel]
    add     r10, r11                    ; where the leaf goes
    mov     r8, qword ptr [rbp-16]
    neg     r11
    add     r11, 4096                   ; ...and what is left for it
    WINCALL WideCharToMultiByte, CP_UTF8, 0, r8, -1, r10, r11d, 0, 0
    test    eax, eax
    jz      pit_err
    dec     eax                         ; drop the terminator
    add     rax, qword ptr [g_add_prefixlen]
    mov     qword ptr [g_rellen], rax
    ; Check the COMBINED name, not the leaf: the prefix is what can carry '..'
    ; or an absolute path, and it comes from an archive index that a hostile
    ; zip wrote.  Only when there IS one - a prefix-free add is byte-for-byte
    ; the operation that shipped before this, and running a new check over it
    ; would start rejecting names that have always been accepted.
    cmp     qword ptr [g_add_prefixlen], 0
    je      pit_go
    lea     rcx, [g_rel]
    call    sanitize_name
    test    eax, eax
    jnz     pit_unsafe
pit_go:
    call    pack_node
    FRAME_EPILOG
    ret
pit_unsafe:
    mov     qword ptr [g_packerr], EXIT_CORRUPT
    FRAME_EPILOG
    ret
pit_err:
    mov     qword ptr [g_packerr], EXIT_IO
    FRAME_EPILOG
    ret
pack_input_top endp

; =============================================================================
; child_excluded(rcx = cFileName of the current find-data child) -> eax = 1 if
; g_walk + "\" + name is in the exclusion set.  g_walk / g_walklen are restored
; before returning.
;
; size_node's fast path deliberately never builds a plain file's path - that is
; what saves ~4 syscalls per file on a big tree - so testing a file for
; exclusion means building it here.  Gated on the set being non-empty, so a run
; with no exclusions (every CLI run, and most GUI ones) pays one compare.
; =============================================================================
child_excluded proc frame
    FRAME_PROLOG 64
    cmp     qword ptr [g_excluded], 0        ; PSET_count
    je      ce_no
    mov     qword ptr [rbp-24], rcx
    mov     rax, qword ptr [g_walklen]
    mov     qword ptr [rbp-32], rax          ; saved length
    lea     r10, [g_walk]
    mov     word ptr [r10+rax*2], 5Ch
    inc     rax
    mov     r11, qword ptr [rbp-24]
    xor     r9, r9
ce_cpy:
    mov     dx, word ptr [r11+r9*2]
    test    dx, dx
    jz      ce_cpyd
    mov     word ptr [r10+rax*2], dx
    inc     rax
    inc     r9
    cmp     rax, 7F00h
    jb      ce_cpy
ce_cpyd:
    mov     word ptr [r10+rax*2], 0
    lea     rcx, [g_excluded]
    lea     rdx, [g_walk]
    call    pset_has
    mov     dword ptr [rbp-40], eax
    ; restore the parent path exactly as it was
    mov     rax, qword ptr [rbp-32]
    lea     r10, [g_walk]
    mov     word ptr [r10+rax*2], 0
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
ce_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
child_excluded endp

; =============================================================================
; size_node - recursively add file sizes under g_walk into g_packtotal.
; Metadata-only (open+size+close per file); best-effort (unreadable entries
; are skipped, since the pack itself will surface real errors).
; =============================================================================
size_node proc frame
    FRAME_PROLOG 720
    ; finddata at [rsp+64]; [rbp-24]=hfind [rbp-32]=savedlen [rbp-40]=fsize
    WINCALL GetFileAttributesW, addr g_walk
    cmp     eax, -1
    je      sz_ret
    test    eax, FILE_ATTR_DIR
    jz      sz_isfile
    ; directory: enumerate "\*"
    mov     rax, qword ptr [g_walklen]
    lea     r10, [g_walk]
    mov     word ptr [r10+rax*2], 5Ch
    mov     word ptr [r10+rax*2+2], '*'
    mov     word ptr [r10+rax*2+4], 0
    WINCALL FindFirstFileW, addr g_walk, addr rsp+64
    mov     r11, qword ptr [g_walklen]
    lea     r10, [g_walk]
    mov     word ptr [r10+r11*2], 0
    cmp     rax, -1
    je      sz_ret
    mov     qword ptr [rbp-24], rax
sz_child:
    lea     r10, [rsp+64+FIND_CFILENAME]
    movzx   eax, word ptr [r10]
    cmp     ax, '.'
    jne     sz_dochild
    movzx   edx, word ptr [r10+2]
    test    dx, dx
    jz      sz_next
    cmp     dx, '.'
    jne     sz_dochild
    movzx   edx, word ptr [r10+4]
    test    dx, dx
    jz      sz_next
sz_dochild:
    ; carved out by the user?  then it is not part of the input at all
    lea     rcx, [rsp+64+FIND_CFILENAME]
    call    child_excluded
    test    eax, eax
    jnz     sz_next
    ; fast path: a regular file's size is already in the find-data, so add it
    ; directly instead of building the path and re-opening it (huge folders open
    ; ~4 syscalls/file otherwise).  Only directories still recurse.
    mov     eax, dword ptr [rsp+64+0]        ; dwFileAttributes
    test    eax, FILE_ATTR_DIR
    jnz     sz_dir
    mov     eax, dword ptr [rsp+64+32]        ; nFileSizeLow
    mov     edx, dword ptr [rsp+64+28]        ; nFileSizeHigh
    shl     rdx, 32
    or      rax, rdx                          ; 64-bit file size
    add     qword ptr [g_packtotal], rax
    add     qword ptr [g_scan_bytes], rax
    inc     qword ptr [g_scan_files]
    inc     qword ptr [g_packents]           ; one tar entry per file
    cmp     rax, qword ptr [g_biggest]
    jbe     sz_next
    mov     qword ptr [g_biggest], rax
    jmp     sz_next
sz_dir:
    inc     qword ptr [g_packents]           ; directories get a header too
    ; ...and the GUI is told about them separately, so its summary can show the
    ; two numbers Explorer shows rather than one number that is neither.
    inc     qword ptr [g_scan_dirs]
    mov     rax, qword ptr [g_walklen]
    mov     qword ptr [rbp-32], rax
    lea     r10, [g_walk]
    mov     word ptr [r10+rax*2], 5Ch
    inc     rax
    lea     r11, [rsp+64+FIND_CFILENAME]
    xor     r9, r9
sz_wcpy:
    mov     dx, word ptr [r11+r9*2]
    test    dx, dx
    jz      sz_wcpyd
    mov     word ptr [r10+rax*2], dx
    inc     rax
    inc     r9
    cmp     rax, 7F00h
    jb      sz_wcpy
sz_wcpyd:
    mov     word ptr [r10+rax*2], 0
    mov     qword ptr [g_walklen], rax
    call    size_node
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [g_walklen], rax
    lea     r10, [g_walk]
    mov     word ptr [r10+rax*2], 0
sz_next:
    WINCALL FindNextFileW, qword ptr [rbp-24], addr rsp+64
    test    eax, eax
    jnz     sz_child
    WINCALL FindClose, qword ptr [rbp-24]
sz_ret:
    FRAME_EPILOG
    ret
sz_isfile:
    lea     rcx, [g_walk]
    call    file_open_read
    cmp     rax, INVALID
    je      sz_ret
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    lea     rdx, [rbp-40]
    call    get_file_size
    test    eax, eax
    jnz     sz_close
    mov     rax, qword ptr [rbp-40]
    add     qword ptr [g_packtotal], rax
    add     qword ptr [g_scan_bytes], rax
    inc     qword ptr [g_scan_files]
    inc     qword ptr [g_packents]           ; one tar entry per file
    cmp     rax, qword ptr [g_biggest]
    jbe     sz_close
    mov     qword ptr [g_biggest], rax
sz_close:
    mov     rcx, qword ptr [rbp-24]
    call    file_close
    FRAME_EPILOG
    ret
size_node endp

; =============================================================================
; size_input_top(rcx = positional path) - seed g_walk then size_node
; =============================================================================
size_input_top proc frame
    FRAME_PROLOG 32
    lea     r10, [g_walk]
    xor     r9, r9
sit_c:
    mov     ax, word ptr [rcx+r9*2]
    mov     word ptr [r10+r9*2], ax
    test    ax, ax
    jz      sit_cd
    inc     r9
    cmp     r9, 7F00h
    jb      sit_c
sit_cd:
    mov     qword ptr [g_walklen], r9
    ; The input ITSELF, when it is a folder.  size_node counts the directories it
    ; FINDS - a child is counted at sz_dir on the way into it - so the one it was
    ; handed was counted by nobody, while the archive stores it as an entry like
    ; any other ("<dir> src" is in every folder container).  The pre-flight was
    ; therefore one tar header short, and the progress line ended at one MORE
    ; than its own total.  Once per positional, so the extra attribute query
    ; costs nothing next to the walk it precedes.
    WINCALL GetFileAttributesW, addr g_walk
    cmp     eax, -1
    je      sit_walk
    test    eax, FILE_ATTR_DIR
    jz      sit_walk
    inc     qword ptr [g_packents]
    inc     qword ptr [g_scan_dirs]
sit_walk:
    call    size_node
    FRAME_EPILOG
    ret
size_input_top endp

; =============================================================================
; est_container_bytes() -> rax = an upper bound on the container this run will
; produce.  sum_inputs must have run first.
;
; STORE mode deliberately: compression can only make the result smaller, so the
; store figure bounds both - the same argument the MAX_PLAINTEXT_SIZE pre-flight
; already relies on.  Over-estimating costs nothing worse than a split that
; turns out to be unnecessary, and vol_settle undoes that; UNDER-estimating would
; write a file past the size the user capped, so every term rounds up and the
; arithmetic saturates rather than wrapping.
; =============================================================================
est_container_bytes proc frame
    FRAME_PROLOG 64      ; 64, not 48: [rbp-24] holds the estimate across the
                         ; idx_cap call, and at 48 it is inside the outgoing
                         ; argument area
    mov     rax, qword ptr [g_packtotal]
    mov     r10, qword ptr [g_packents]
    mov     r11, PACK_ENTRY_OVERHEAD        ; tar framing, at the ceiling check's
    call    est_mul_add                     ; own generous 1024 per entry
    mov     qword ptr [rbp-16], rax
    ; the inventory: fixed part plus a generous name, per entry.  Capped at
    ; IDX_MAX_BYTES, because idx_add refuses past it - the index cannot be
    ; larger than that however many entries there are.
    xor     eax, eax
    mov     r10, qword ptr [g_packents]
    mov     r11, IDXE_FIXED + 1024
    call    est_mul_add
    mov     qword ptr [rbp-24], rax
    call    idx_cap                         ; the same limit idx_add enforces
    mov     r11, rax
    mov     rax, qword ptr [rbp-24]
    cmp     rax, r11
    jbe     @F
    mov     rax, r11
@@:
    add     rax, qword ptr [rbp-16]
    jc      ecb_sat
    add     rax, HDR_BYTES + IDX_TAIL_FIXED
    jnc     ecb_ret
ecb_sat:
    mov     rax, -1                         ; saturated: nothing fits under this
ecb_ret:
    FRAME_EPILOG
    ret
est_container_bytes endp

; est_mul_add(rax = running, r10 = count, r11 = each) -> rax, saturating.
; count * per-entry is exactly where a crafted tree would try to wrap the
; estimate and win a limit it should not have.
est_mul_add proc
    push    rdx
    push    rax
    mov     rax, r10
    mul     r11                             ; rdx:rax
    test    rdx, rdx
    jnz     ema_sat
    pop     r10
    add     rax, r10
    jc      ema_sat2
    pop     rdx
    ret
ema_sat:
    pop     r10
ema_sat2:
    mov     rax, -1
    pop     rdx
    ret
est_mul_add endp

; =============================================================================
; sum_inputs - total bytes of all positional inputs -> g_packtotal
; =============================================================================
sum_inputs proc frame
    FRAME_PROLOG 48
    ; [rbp-24]=index [rbp-32]=running total before this input
    mov     qword ptr [g_packtotal], 0
    mov     qword ptr [g_packents], 0
    mov     qword ptr [g_biggest], 0
    ; size_node bumps the GUI's live scan counters as it walks, and this is a
    ; WHOLE-INPUT walk - the second one, because the GUI already indexed the same
    ; inputs to fill its list.  Without this reset the two passes accumulate and
    ; the summary reads exactly double: one 8-byte file shows "2 files, 16 B".
    ; start_indexing resets them for its own pass; this is the same contract for
    ; this one.
    mov     qword ptr [g_scan_files], 0
    mov     qword ptr [g_scan_dirs], 0
    mov     qword ptr [g_scan_bytes], 0
    mov     qword ptr [rbp-24], 0        ; all positionals are inputs
si_loop:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_poscount]
    jae     si_done
    mov     r8, qword ptr [g_packtotal]
    mov     qword ptr [rbp-32], r8       ; total before this input
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    call    size_input_top
    ; record this input's own size (delta) for the GUI per-file progress bar
    mov     rax, qword ptr [g_packtotal]
    sub     rax, qword ptr [rbp-32]
    mov     r9, qword ptr [rbp-24]
    cmp     r9, MAX_ARGS
    jae     si_skip
    lea     r11, [g_file_total]
    mov     qword ptr [r11+r9*8], rax
si_skip:
    inc     qword ptr [rbp-24]
    jmp     si_loop
si_done:
    FRAME_EPILOG
    ret
sum_inputs endp

; =============================================================================
; apply_auto_compress(rcx = total input bytes)
; If the user gave neither --compress nor --store (g_cfg_compress_set==0),
; choose the size-based default: compress when total < COMPRESS_AUTO_MAX.
; Idempotent; a no-op once the mode is fixed (explicit flag or prior call).
; Leaf proc (no calls) -> no frame needed.
; =============================================================================
public apply_auto_compress
apply_auto_compress proc
    cmp     dword ptr [g_cfg_compress_set], 0
    jne     aac_ret
    xor     eax, eax
    cmp     rcx, COMPRESS_AUTO_MAX
    jae     aac_set
    mov     eax, 1
aac_set:
    mov     dword ptr [g_cfg_compress], eax
    mov     dword ptr [g_cfg_compress_set], 1
aac_ret:
    ret
apply_auto_compress endp

; =============================================================================
; input_size(rcx = positional path) -> rax = total bytes (recursive for dirs).
; Thin wrapper around size_input_top for the GUI to fill its size column at
; populate time.  Metadata-only walk; best-effort (unreadable entries skipped).
; =============================================================================
public input_size
input_size proc frame
    FRAME_PROLOG 32
    mov     qword ptr [g_packtotal], 0
    call    size_input_top              ; rcx already = path
    mov     rax, qword ptr [g_packtotal]
    FRAME_EPILOG
    ret
input_size endp

; =============================================================================
; pack_bare(rcx = input path) - stream a single file's raw bytes through the
; (store/compress) sink with NO tar framing.  Used for single-file containers
; (header archive flag = 0).  Errors set g_packerr (sticky).
; =============================================================================
pack_bare proc frame
    FRAME_PROLOG 96
    ; [rbp-32]=hin [rbp-40]=remaining [rbp-48]=chunklen [rbp-56]=size
    mov     qword ptr [rbp-32], INVALID
    call    file_open_read
    cmp     rax, INVALID
    je      pb_err
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    lea     rdx, [rbp-56]
    call    get_file_size
    test    eax, eax
    jnz     pb_err
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [rbp-40], rax
    ; a single-file container is one entry, framed exactly like any other - the
    ; only difference is that its plaintext is the raw file, with no tar header
    call    entry_begin
pb_loop:
    cmp     qword ptr [rbp-40], 0
    je      pb_close
    mov     r8, qword ptr [rbp-40]
    cmp     r8, CHUNK
    jbe     @F
    mov     r8, CHUNK
@@:
    mov     qword ptr [rbp-48], r8
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [g_filebuf]
    call    file_read_exact
    test    eax, eax
    jnz     pb_err
    lea     rcx, [g_filebuf]
    mov     rdx, qword ptr [rbp-48]
    call    tar_out
    mov     rcx, qword ptr [rbp-48]
    call    progress_add
    test    eax, eax
    jnz     pb_err                       ; cancel requested
    mov     rax, qword ptr [rbp-48]
    sub     qword ptr [rbp-40], rax
    jmp     pb_loop
pb_close:
    call    entry_end
    call    idx_bare_name
    mov     rcx, qword ptr [rbp-56]
    xor     edx, edx
    call    idx_add
    mov     rcx, qword ptr [rbp-32]
    call    file_close
    FRAME_EPILOG
    ret
pb_err:
    mov     qword ptr [g_packerr], EXIT_IO
    mov     rcx, qword ptr [rbp-32]
    call    file_close
    FRAME_EPILOG
    ret
pack_bare endp

; =============================================================================
; do_pack -> eax exit code
; =============================================================================
public do_pack
do_pack proc frame
    FRAME_PROLOG 96                         ; 96, not 64: at 64 the saved exit
                                            ; code [rbp-56] is the callee's rdx
                                            ; home slot, and dp_done stores it
                                            ; before calling secure_zero,
                                            ; file_close and file_delete.  Latent
                                            ; rather than live - nothing here
                                            ; spills to home space - but the
                                            ; convention is enforced nowhere, and
                                            ; this slot is a return value.
    ; A FRESH archive has no folder to land in, so the destination is cleared
    ; rather than inherited.  Only do_add sets one, and only the GUI sets it on
    ; do_add's behalf; clearing here means a stale value can never reach an
    ; encrypt, whatever the window was showing beforehand.
    mov     qword ptr [g_add_prefixlen], 0
    ; [rbp-24]=hout [rbp-32]=inidx [rbp-56]=code
    mov     qword ptr [g_packerr], 0
    mov     qword ptr [rbp-24], INVALID
    mov     word ptr [g_temppath], 0

    call    check_password_policy
    test    eax, eax
    jz      dp_pol_ok
    call    print_policy_error
    mov     eax, EXIT_USAGE
    jmp     dp_done
dp_pol_ok:
    mov     rcx, qword ptr [g_cfg_out]
    lea     rdx, [g_out_np]
    call    normalize_path
    test    eax, eax
    jnz     dp_io

    ; pre-flight: sum input sizes and check the output drive has room (before
    ; the expensive KDF and before opening the temp).  g_packtotal is reused
    ; later to drive the progress bar.
    call    sum_inputs

    ; ---- segmentation for THIS container -----------------------------------
    ; SEG_SHIFT_DEFAULT (32: 4 GiB) unless a dbg build's MYRKR_DBG_SEGBYTES says
    ; otherwise.  Read before the ceiling pre-flight below, because the two
    ; disagree about what the ceiling bounds.
    mov     dword ptr [g_cfg_segshift], SEG_SHIFT_DEFAULT
ifdef DBG_TRACE
    ; DEBUG BUILDS ONLY - same reasoning as MYRKR_DBG_VOLBYTES: a half-built
    ; feature reachable from a shipping binary is how a container nobody can
    ; open gets written.  The value is BYTES, must be a power of two inside
    ; [1<<SEG_SHIFT_MIN, 1<<SEG_SHIFT_MAX]; anything else is ignored and the
    ; test asserts the header byte, so a typo fails visibly there.
    WINCALL GetEnvironmentVariableW, addr w_dbg_segb, addr g_dbg_segbuf, 24
    test    eax, eax
    jz      dp_noseg
    xor     r10, r10                        ; accumulated value
    xor     r9, r9
    lea     r11, [g_dbg_segbuf]
dp_segdig:
    movzx   eax, word ptr [r11+r9*2]
    test    eax, eax
    jz      dp_segval
    sub     eax, '0'
    cmp     eax, 9
    ja      dp_noseg                        ; not a decimal number: ignore
    imul    r10, r10, 10
    add     r10, rax
    inc     r9
    cmp     r9, 20
    jb      dp_segdig
dp_segval:
    test    r10, r10
    jz      dp_noseg
    lea     rax, [r10-1]
    test    rax, r10
    jnz     dp_noseg                        ; not a power of two
    bsf     rcx, r10
    cmp     ecx, SEG_SHIFT_MIN
    jb      dp_noseg
    cmp     ecx, SEG_SHIFT_MAX
    ja      dp_noseg
    mov     dword ptr [g_cfg_segshift], ecx
dp_noseg:
endif

    ; ---- pre-flight: AES-GCM per-key plaintext ceiling ----------------------
    ; One container = one key (fresh salt), so the whole GCM plaintext must stay
    ; under MAX_PLAINTEXT_SIZE.  Past it the 32-bit counter block wraps and the
    ; keystream repeats, which silently destroys confidentiality - so this is
    ; refused up front rather than discovered at byte 2^39.
    ;
    ; The plaintext is NOT the input total.  In archive mode it is the tar
    ; stream: 512 bytes of header per entry plus content padded to a 512
    ; boundary, which for many small files dwarfs the content.  Estimate high
    ; (PACK_ENTRY_OVERHEAD rounds 512+511 up to 1024) so the check can only ever
    ; refuse early, never allow a container that would wrap.  Compression can
    ; only shrink what GCM then sees, so the store-mode figure bounds both.
    ; Each ENTRY is its own GCM stream now, so the ceiling bounds one entry
    ; rather than the whole archive - a tree of many files can exceed 64 GiB in
    ; total and be perfectly safe.  g_biggest is the largest single input the
    ; sizing walk saw; add the tar framing that will wrap it.
    ; With segments on, the ceiling bounds a SEGMENT, and SEG_SHIFT_MAX keeps
    ; every segment under it by construction - so the per-entry refusal below
    ; is exactly the 64 GiB limit this phase exists to lift, and it is skipped.
    ; Forgetting this skip would ship a format that still refuses the file the
    ; format change was for.
    cmp     dword ptr [g_cfg_segshift], 0
    jne     dp_size_ok
    mov     rax, qword ptr [g_biggest]
    CHECK_ADD_OVF rax, PACK_ENTRY_OVERHEAD
    mov     r10, MAX_PLAINTEXT_SIZE
    cmp     rax, r10
    ja      dp_toobig
dp_size_ok:

    mov     rcx, qword ptr [g_packtotal]
    call    apply_auto_compress         ; size-based default if no explicit flag
    lea     rcx, [g_out_np]
    mov     rdx, qword ptr [g_packtotal]
    add     rdx, DISK_MARGIN
    call    disk_has_space
    cmp     eax, 1
    je      dp_nospace

    ; header (archive flag in byte 17)
    lea     r10, [g_pkhdr]
    mov     dword ptr [r10+0], HDR_MAGIC
    mov     dword ptr [r10+4], HDR_VERSION
    mov     eax, dword ptr [g_cfg_t]
    mov     dword ptr [r10+8], eax
    mov     eax, dword ptr [g_cfg_m]
    mov     dword ptr [r10+12], eax
    mov     byte ptr [r10+CONTAINER_HDR.lanes], 1        ; lanes
    mov     eax, dword ptr [g_bare]
    xor     eax, 1
    mov     byte ptr [r10+CONTAINER_HDR.archive], al       ; archive flag = NOT bare
    mov     eax, dword ptr [g_cfg_compress]
    and     eax, 1
    mov     qword ptr [g_compress], rax
    mov     byte ptr [r10+CONTAINER_HDR.compressed], al       ; compression: 0 store / 1 xpress
    ; the segment size chosen above; 0 = the entries are not segmented
    mov     eax, dword ptr [g_cfg_segshift]
    mov     byte ptr [r10+CONTAINER_HDR.seg_shift], al
    lea     rcx, [r10+20]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      dp_io
    lea     rcx, [g_pkhdr+52]           ; set id, not a nonce: v4 nonces are
    mov     edx, 12                     ; counters (see macros.inc)
    call    rng_fill
    test    eax, eax
    jz      dp_io
    lea     rcx, [g_pkhdr+20]
    mov     edx, dword ptr [g_cfg_t]
    mov     r8d, dword ptr [g_cfg_m]
    call    derive_key
    test    eax, eax
    jnz     dp_oom

    lea     rcx, [g_pkhdr+KCV_OFFSET]   ; key-check value into header[64..79]
    call    compute_kcv

    lea     rcx, [g_pkctx]
    lea     rdx, [g_key]
    lea     r8, [g_pkhdr+52]
    xor     r9, r9
    call    gcm_init
    lea     rcx, [g_pkctx]
    lea     rdx, [g_pkhdr]
    mov     r8, HDR_BYTES
    call    gcm_aad

    lea     rcx, [g_out_np]
    call    make_temp_path
ifdef DBG_TRACE
    ; DEBUG BUILDS ONLY, and the only way to set a split size until the GUI
    ; control exists.  MYRKR_DBG_VOLBYTES=<decimal> is read here rather than
    ; wired to a flag, because a half-built feature reachable from a shipping
    ; binary is how a container nobody can open gets written.  Same reasoning as
    ; MYRKR_DBG_NOSECDESK; see manifest 11.1.
    WINCALL GetEnvironmentVariableW, addr w_dbg_volb, addr g_dbg_volbuf, 24
    test    eax, eax
    jz      dp_novol
    xor     r10, r10                        ; accumulated value
    xor     r9, r9
    lea     r11, [g_dbg_volbuf]             ; through a register: RIP-relative
                                            ; cannot carry an index (ADDR32)
dp_volparse:
    movzx   eax, word ptr [r11+r9*2]
    cmp     ax, '0'
    jb      dp_volset
    cmp     ax, '9'
    ja      dp_volset
    sub     eax, '0'
    imul    r10, r10, 10
    add     r10, rax
    inc     r9
    cmp     r9, 20
    jb      dp_volparse
dp_volset:
    mov     qword ptr [g_vol_limit], r10
dp_novol:
endif
    ; The container's bytes go through the volume layer from here on, so that
    ; splitting is a property of the SINK rather than something the pack path
    ; has to know about.  g_vol_limit is 0 today, which makes vol_write a
    ; pass-through to one file with no volume header - the output keeps its usual shape.
    ; See docs/VOLUMES.md.
    ; A single container is written to a temp name and renamed into place, so a
    ; partial one never appears under the final name.  A SET cannot use that
    ; trick without N renames, each of which can fail half way and leave the set
    ; split across two names - worse than what it protects against.  So parts are
    ; written under their final names and a failure deletes the ones created.
    ; ---- does it even need splitting? ---------------------------------------
    ; A split SIZE is not a request for a set - it is a ceiling on how big one
    ; file may get.  A 50 MB container under a 100 MB limit was still written as
    ; <base>.part001.mrk with a volume header on it, named like a member of a set
    ; and refusing edits like one, for a size it never came near.
    ;
    ; est_container_bytes is a STORE-mode upper bound and compression can only
    ; shrink what is actually written, so a limit dropped here is one the output
    ; genuinely cannot reach.  The other direction - estimated over, actual under
    ; - lands on vol_settle, which puts the single part back under its plain name.
    cmp     qword ptr [g_vol_limit], 0
    je      dp_vol_ready                    ; not splitting at all
    call    est_container_bytes
    cmp     rax, qword ptr [g_vol_limit]
    ja      dp_vol_ready                    ; will not fit: the limit stands
    mov     qword ptr [g_vol_limit], 0      ; it fits: one ordinary container
dp_vol_ready:
    lea     rcx, [g_temppath]
    cmp     qword ptr [g_vol_limit], 0
    je      @F
    lea     rcx, [g_out_np]
@@:
    mov     rdx, qword ptr [g_vol_limit]
    call    vol_begin
    test    eax, eax
    jnz     dp_io
    mov     rax, qword ptr [g_vol_hout]
    mov     qword ptr [rbp-24], rax
    mov     qword ptr [g_sink_hout], rax
    mov     qword ptr [g_sinkfill], 0
    lea     rcx, [g_pkhdr]
    mov     rdx, HDR_BYTES
    call    vol_write
    test    eax, eax
    jnz     dp_io

    call    idx_reset
    mov     qword ptr [g_payoff], 0
    mov     qword ptr [g_entnext], 0

    ; initialise compressor if compression is enabled
    mov     qword ptr [g_rawfill], 0
    cmp     qword ptr [g_compress], 0
    je      dp_nocomp
    call    comp_init
    test    eax, eax
    jz      dp_nocomp
    mov     qword ptr [g_packerr], EXIT_IO
    jmp     dp_packerr
dp_nocomp:

    ; start the progress bar (g_packtotal already computed in the pre-flight)
    mov     rcx, qword ptr [g_packtotal]
    lea     rdx, [lbl_pack]
    mov     r8d, lbl_pack_len
    call    progress_begin

    ; bare single-file mode: stream the lone input's bytes (no tar framing)
    cmp     dword ptr [g_bare], 0
    je      dp_archive
    mov     qword ptr [g_cur_input], 0
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11]
    call    pack_bare
    cmp     qword ptr [g_packerr], 0
    jne     dp_packerr
    jmp     dp_flush
dp_archive:
    ; pack each input (positionals[0 .. poscount-1])
    mov     qword ptr [rbp-32], 0
dp_inloop:
    mov     rax, qword ptr [rbp-32]
    cmp     rax, qword ptr [g_poscount]
    jae     dp_endblocks
    mov     qword ptr [g_cur_input], rax    ; attribute bytes to this input
    mov     rcx, rax                        ; ...and where that input lands
    call    pfx_select
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    call    pack_input_top
    cmp     qword ptr [g_packerr], 0
    jne     dp_packerr
    inc     qword ptr [rbp-32]
    jmp     dp_inloop
dp_endblocks:
    ; No tar trailer: the two zero blocks told a sequential reader where the
    ; archive stopped, and extraction is driven by the inventory's extents now.
    ; Nothing reads the payload sequentially any more either: unpack_entry is
    ; handed one extent at a time and never looks for a terminator.
dp_flush:
    cmp     qword ptr [g_compress], 0
    je      dp_eb_sink
    call    comp_close
dp_eb_sink:
    cmp     qword ptr [g_packerr], 0
    jne     dp_packerr
    ; ---- the inventory, after the last entry --------------------------------
dp_idx:
    mov     rcx, qword ptr [g_sink_hout]
    call    idx_write
    test    eax, eax
    jnz     dp_io
    ; vol_finish closes the last part - and marks it final when there are
    ; several - so the close does not happen here any more.
    call    vol_finish
    test    eax, eax
    jnz     dp_io
    mov     qword ptr [rbp-24], INVALID
    cmp     dword ptr [g_vol_split], 0
    jne     dp_named                        ; a set is already under its names
    lea     rcx, [g_temppath]
    lea     rdx, [g_out_np]
    call    file_rename
    test    eax, eax
    jnz     dp_io
dp_named:
    call    progress_done
    cmp     dword ptr [g_bare], 0
    je      dp_okmsg
    prn_a   msg_enc_ok2                 ; single-file container
    jmp     dp_okname
dp_okmsg:
    prn_a   msg_pack_ok
dp_okname:
    mov     rcx, qword ptr [g_cfg_out]
    call    print_wz
    lea     rcx, [msg_nl]
    mov     edx, 2
    call    print_a
    xor     eax, eax
    jmp     dp_done
dp_packerr:
    call    progress_done
    mov     eax, dword ptr [g_packerr]
    cmp     eax, EXIT_CORRUPT           ; name-too-long already printed
    je      dp_done
    cmp     eax, EXIT_UNSUPPORTED       ; so has the inventory-full refusal
    jne     dp_perr_io
    cmp     dword ptr [g_vol_toomany], 0
    je      dp_done                     ; inventory-full: it printed its own
    prn     e_volparts
    mov     eax, dword ptr [g_packerr]
    jmp     dp_done
dp_perr_io:
    prn     e_pio
    ; RELOAD.  prn ends in a call and print_err returns a value, so eax here was
    ; print_err's, not the exit code - and dp_done stores whatever eax holds.
    ; EXIT_CORRUPT looked correct only because it is the one code that jumps
    ; over the print; everything else reported 1. A real I/O failure said 1
    ; instead of EXIT_IO, and had done since this path was written.
    mov     eax, dword ptr [g_packerr]
    jmp     dp_done
dp_io:
    call    progress_done
    prn     e_pio
    mov     eax, EXIT_IO
    jmp     dp_done
dp_oom:
    prn     e_poom
    mov     eax, EXIT_OOM
    jmp     dp_done
dp_nospace:
    prn     e_pnospace
    mov     eax, EXIT_NOSPACE
    jmp     dp_done
dp_toobig:
    ; EXIT_USAGE, matching the password-policy refusal: the request is rejected
    ; before anything is read or written, and no output exists to clean up.
    prn     e_ptoobig
    prn     e_ptoobig2
    mov     eax, EXIT_USAGE
dp_done:
    mov     dword ptr [rbp-56], eax
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
    mov     rcx, qword ptr [rbp-24]
    call    file_close
    cmp     dword ptr [rbp-56], 0
    je      dp_ret
    lea     rcx, [g_temppath]
    call    file_delete
    ; ...and the parts, if this was a split set.  The delete above names the
    ; un-split output, which a split run never creates, so without this a failed
    ; encrypt left its parts lying about - openable by nothing, since the last
    ; one never got VOLF_FINAL.
    call    vol_discard
dp_ret:
    mov     eax, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
do_pack endp

; =============================================================================
; sanitize_name(rcx = utf8 name) -> eax 0 safe / 1 unsafe
; Rejects absolute (leading / or \), drive (X:), and any ".." component.
; =============================================================================
public sanitize_name
.const
; Three characters per entry; the list ends with a NUL.  Lower case, because
; sn_reserved folds the name it is checking down to match.
sn_dev3     db "conprnauxnul",0        ; CON PRN AUX NUL
sn_dev4     db "comlpt",0              ; COM<digit> LPT<digit>
; CONIN$ and CONOUT$ are device names too, and they are the two that do not fit
; the fixed-width table above: 6 and 7 characters against its 3 and 4.  Opening
; one hands back the console input or screen buffer instead of creating a file,
; so an entry named CONIN$ extracts to nothing and reports success - the same
; outcome CON is already refused for.  NUL-separated, list ends with a second
; NUL; lower case, because snr_long folds what it is checking.
sn_devn     db "conin$",0,"conout$",0,0
.code

; =============================================================================
; sn_reserved(rdx = start of a path component) -> eax = 1 if that component
; names a DOS device, 0 if it does not.  Clobbers rax and nothing else, because
; it is called from the middle of sanitize_name's scan, which keeps its cursor
; and its at-a-component-start flag in volatiles.
;
; The base is what precedes the first dot: "com3.txt" IS com3, which is why the
; check cannot be a whole-component string compare.  Trailing spaces are ignored
; because Windows ignores them - "CON " opens CON.
; =============================================================================
sn_reserved proc
    push    rcx
    push    rdx
    push    r10
    push    r11
    mov     r10, rdx
    xor     r11d, r11d
snr_len:
    movzx   eax, byte ptr [r10+r11]
    test    al, al
    jz      snr_have
    cmp     al, '.'
    je      snr_have
    cmp     al, '/'
    je      snr_have
    cmp     al, 5Ch
    je      snr_have
    inc     r11d
    cmp     r11d, 16
    jb      snr_len
    jmp     snr_no                      ; far too long to be a device name
snr_have:
snr_trim:
    test    r11d, r11d
    jz      snr_no
    cmp     byte ptr [r10+r11-1], 20h
    jne     snr_sized
    dec     r11d
    jmp     snr_trim
snr_sized:
    cmp     r11d, 3
    je      snr_three
    cmp     r11d, 6
    je      snr_long
    cmp     r11d, 7
    je      snr_long
    cmp     r11d, 4
    jne     snr_no
    movzx   eax, byte ptr [r10+3]       ; COM<digit> / LPT<digit>
    cmp     al, '0'
    jb      snr_no
    cmp     al, '9'
    ja      snr_no
    lea     rcx, [sn_dev4]
    jmp     snr_table
snr_three:
    lea     rcx, [sn_dev3]
snr_table:
snr_entry:
    movzx   eax, byte ptr [rcx]
    test    al, al
    jz      snr_no
    xor     r11d, r11d
snr_cmp:
    movzx   eax, byte ptr [r10+r11]
    or      al, 20h                     ; fold to lower; the table already is
    movzx   edx, byte ptr [rcx+r11]
    cmp     al, dl
    jne     snr_next
    inc     r11d
    cmp     r11d, 3
    jb      snr_cmp
    mov     eax, 1
    jmp     snr_ret
snr_next:
    add     rcx, 3
    jmp     snr_entry
snr_long:
    ; The variable-length names, matched whole rather than by fixed width.  Only
    ; rax, rcx and rdx are touched: r8 and r9 are sanitize_name's scan cursor and
    ; its at-a-component-start flag, and this runs in the middle of that scan.
    lea     rcx, [sn_devn]
snr_lentry:
    cmp     byte ptr [rcx], 0
    je      snr_no                      ; empty entry = end of the list
    xor     edx, edx
snr_lcmp:
    movzx   eax, byte ptr [rcx+rdx]
    test    al, al
    jz      snr_lfin                    ; this name ended
    cmp     edx, r11d
    jae     snr_lnext                   ; the component ended first: not a match
    movzx   eax, byte ptr [r10+rdx]
    or      al, 20h                     ; fold to lower; '$' and digits unaffected
    cmp     al, byte ptr [rcx+rdx]
    jne     snr_lnext
    inc     edx
    jmp     snr_lcmp
snr_lfin:
    cmp     edx, r11d                   ; both ended together, or not at all
    jne     snr_lnext
    mov     eax, 1
    jmp     snr_ret
snr_lnext:
    movzx   eax, byte ptr [rcx]         ; step past this name's terminator
    inc     rcx
    test    al, al
    jnz     snr_lnext
    jmp     snr_lentry
snr_no:
    xor     eax, eax
snr_ret:
    pop     r11
    pop     r10
    pop     rdx
    pop     rcx
    ret
sn_reserved endp

sanitize_name proc
    movzx   eax, byte ptr [rcx+0]
    test    al, al
    jz      sn_bad
    cmp     al, '/'
    je      sn_bad
    cmp     al, '\'
    je      sn_bad
    xor     r9d, r9d
    mov     r8d, 1                      ; at component start
sn_loop:
    movzx   eax, byte ptr [rcx+r9]
    test    al, al
    jz      sn_ok
    ; A COLON, ANYWHERE.  At index 1 it is a drive ("C:evil") - which is all
    ; this used to look for.  Anywhere else it names an ALTERNATE DATA STREAM
    ; ("notes.txt:hidden"), which writes real content that no ordinary listing
    ; of the output directory shows.  Neither escapes OUTDIR, so this is not the
    ; traversal rule; it refuses to create something the user cannot see they
    ; have.  A colon is legal in a POSIX name and cannot be written on Windows
    ; as anything but a stream, so nothing extractable is given up.
    cmp     al, ':'
    je      sn_bad
    test    r8d, r8d
    jz      sn_notstart
    ; A DOS DEVICE NAME as a component - CON, NUL, COM3, "com3.txt" - opens the
    ; DEVICE rather than creating a file, and having a directory in front of it
    ; does not help.  The extraction then writes to a console or a serial port
    ; and reports success, which is a worse outcome than refusing the entry.
    lea     rdx, [rcx+r9]
    call    sn_reserved
    test    eax, eax
    jnz     sn_bad
    movzx   eax, byte ptr [rcx+r9]      ; sn_reserved returned in rax; reload
    cmp     al, '.'
    jne     sn_clearstart
    movzx   edx, byte ptr [rcx+r9+1]
    cmp     dl, '.'
    jne     sn_clearstart
    movzx   edx, byte ptr [rcx+r9+2]
    test    dl, dl
    jz      sn_bad
    cmp     dl, '/'
    je      sn_bad
    cmp     dl, '\'
    je      sn_bad
sn_clearstart:
    xor     r8d, r8d
sn_notstart:
    cmp     al, '/'
    je      sn_start
    cmp     al, '\'
    jne     sn_adv
sn_start:
    mov     r8d, 1
sn_adv:
    inc     r9d
    jmp     sn_loop
sn_ok:
    xor     eax, eax
    ret
sn_bad:
    mov     eax, 1
    ret
sanitize_name endp

; =============================================================================
; create_parents(rcx = path UTF-16) - CreateDirectoryW for each ancestor
; (errors ignored: already-exists, drive prefixes, etc.)
; =============================================================================
public create_parents
create_parents proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], 0
cp_loop:
    mov     r10, qword ptr [rbp-24]
    mov     r9, qword ptr [rbp-32]
    movzx   eax, word ptr [r10+r9*2]
    test    eax, eax
    jz      cp_done
    cmp     eax, 5Ch                    ; '\'
    jne     cp_next
    test    r9, r9
    jz      cp_next
    mov     word ptr [r10+r9*2], 0
    WINCALL CreateDirectoryW, r10, 0
    mov     r10, qword ptr [rbp-24]
    mov     r9, qword ptr [rbp-32]
    mov     word ptr [r10+r9*2], 5Ch
cp_next:
    inc     qword ptr [rbp-32]
    jmp     cp_loop
cp_done:
    FRAME_EPILOG
    ret
create_parents endp

; =============================================================================
; build_extract_path - g_extw = g_outdir_np + '\' + g_namew (mapping / -> \)
; =============================================================================
public build_extract_path
build_extract_path proc
    lea     r10, [g_extw]
    xor     r9, r9
    lea     r11, [g_outdir_np]
    xor     r8, r8
bp_o:
    mov     ax, word ptr [r11+r8*2]
    test    ax, ax
    jz      bp_osep
    mov     word ptr [r10+r9*2], ax
    inc     r8
    inc     r9
    cmp     r9, 7F00h
    jb      bp_o
bp_osep:
    mov     word ptr [r10+r9*2], 5Ch
    inc     r9
    lea     r11, [g_namew]
    xor     r8, r8
bp_n:
    mov     ax, word ptr [r11+r8*2]
    test    ax, ax
    jz      bp_done
    cmp     ax, 2Fh                     ; '/' -> '\'
    jne     @F
    mov     ax, 5Ch
@@:
    mov     word ptr [r10+r9*2], ax
    inc     r8
    inc     r9
    cmp     r9, 7FF0h
    jb      bp_n
bp_done:
    mov     word ptr [r10+r9*2], 0
    ret
build_extract_path endp

; =============================================================================
; entry_path(rcx = index entry) -> eax 0 ok / 1 unsafe name / 2 unusable name
;
; The inventory's name for an entry, turned into the full output path in g_extw.
; Exactly the steps the tar-walking extractor ran against the header it had just
; parsed - NUL-terminate, sanitize, widen, join to the output directory - run
; against the index instead, which records the same names.
;
; sanitize_name is FIRST and is not optional: the name comes out of the
; container, and a container is not a trusted document just because its tag
; verified.  It rejects traversal, absolute paths, alternate data streams and
; DOS device names; everything it refuses would otherwise be created somewhere
; the user did not ask for and cannot see.
; =============================================================================
entry_path proc frame
    FRAME_PROLOG 64
    mov     eax, dword ptr [rcx+IDXE_namelen]
    test    eax, eax
    jz      ep_bad                          ; a nameless entry has nowhere to go
    cmp     eax, 4095
    ja      ep_bad                          ; g_entname is 4096 with its terminator
    lea     r10, [g_entname]
    lea     r11, [rcx+IDXE_name]
    xor     r9d, r9d
ep_copy:
    cmp     r9d, eax
    jae     ep_copied
    mov     dl, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], dl
    inc     r9d
    jmp     ep_copy
ep_copied:
    mov     byte ptr [r10+r9], 0
    lea     rcx, [g_entname]
    call    sanitize_name
    test    eax, eax
    jnz     ep_unsafe
    ; -1 for the length, so the terminator is written too; 4096 is g_namew's
    ; capacity and the call FAILS rather than truncating if it does not fit.
    WINCALL MultiByteToWideChar, CP_UTF8, 0, addr g_entname, -1, addr g_namew, 4096
    test    eax, eax
    jz      ep_bad
    call    build_extract_path
    xor     eax, eax
    FRAME_EPILOG
    ret
ep_unsafe:
    mov     eax, 1
    FRAME_EPILOG
    ret
ep_bad:
    mov     eax, 2
    FRAME_EPILOG
    ret
entry_path endp

; =============================================================================
; bare_part_path - g_extw = g_outdir_np + ".part"
;
; A single-file container is decoded under this name and renamed to the real one
; once its tag has verified, so A FILE UNDER THE NAME THE USER ASKED FOR HAS
; ALWAYS BEEN AUTHENTICATED.  The route this replaced got that property from a
; whole temporary copy of the plaintext; a rename in the same directory costs
; one metadata operation and gets the same thing.
;
; It is deliberately NOT done per entry when extracting an archive.  That path
; never had the property (the tar walk wrote real names as it went), and a
; rename per file is a real cost at the scale this codebase is heading for -
; see docs/SECURITY.md, which now says so rather than implying otherwise.
; =============================================================================
bare_part_path proc
    lea     r10, [g_extw]
    lea     r11, [g_outdir_np]
    xor     r9, r9
bpp_c:
    mov     ax, word ptr [r11+r9*2]
    test    ax, ax
    jz      bpp_suffix
    mov     word ptr [r10+r9*2], ax
    inc     r9
    cmp     r9, 7FF0h
    jb      bpp_c
bpp_suffix:
    mov     word ptr [r10+r9*2], '.'
    mov     word ptr [r10+r9*2+2], 'p'
    mov     word ptr [r10+r9*2+4], 'a'
    mov     word ptr [r10+r9*2+6], 'r'
    mov     word ptr [r10+r9*2+8], 't'
    mov     word ptr [r10+r9*2+10], 0
    ret
bare_part_path endp

; =============================================================================
; idx_extract_bytes -> rax = content bytes the entries about to be extracted
;                            hold, saturating at 2^63-1
;
; Known before a byte is decrypted, because the inventory records every entry's
; size.  It is the progress denominator and the disk pre-flight's real
; requirement.  The route this replaced asked for the CONTAINER's size twice -
; once for a whole temporary copy of the archive and once for the output - and a
; COMPRESSED archive needs more room than the container it came out of, which
; that check could never see.
;
; It honours the pick, because a pre-flight that weighs a whole container
; against a drive that only has to hold the four files the user selected refuses
; work it could have done.
;
; Saturating rather than wrapping: the sizes come from an authenticated index,
; but authentic only means we wrote it.  A container from a future version, or
; from a writer with a bug, can still name sizes whose sum does not fit - and a
; total that wrapped to something small would let the disk check pass.
;
; locals: [rbp-16] cursor [rbp-24] entries left [rbp-32] total [rbp-40] next
; =============================================================================
idx_extract_bytes proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-24], rax
    mov     qword ptr [rbp-32], 0
ieb_next:
    cmp     qword ptr [rbp-24], 0
    je      ieb_done
    ; The same bounds the extraction loop enforces.  Here they only stop the
    ; counting: do_unpack refuses the container properly a moment later, and
    ; this proc has no way to report anything.
    mov     rax, qword ptr [rbp-16]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      ieb_done
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-16]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      ieb_done
    mov     qword ptr [rbp-40], rax
    cmp     dword ptr [g_pick_active], 0
    je      ieb_count
    lea     rcx, [r10+IDXE_name]
    mov     edx, dword ptr [r10+IDXE_namelen]
    call    pick_has
    test    eax, eax
    jz      ieb_skip
    mov     r10, qword ptr [g_idxptr]                 ; pick_has clobbered it
    add     r10, qword ptr [rbp-16]
ieb_count:
    mov     rax, qword ptr [r10+IDXE_size]
    add     rax, qword ptr [rbp-32]
    jnc     @F
    mov     rax, 7FFFFFFFFFFFFFFFh
@@:
    mov     qword ptr [rbp-32], rax
ieb_skip:
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rbp-16], rax
    dec     qword ptr [rbp-24]
    jmp     ieb_next
ieb_done:
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
idx_extract_bytes endp

; =============================================================================
; unpack_entry(rcx = decoder context, rdx = index entry, r8 = output path or 0)
;   -> eax 0 / EXIT_*
;
; ONE entry, from the inventory to its final file, with nothing in between.
;
; What this replaced wrote every entry's plaintext into a complete temporary tar
; and then walked that file back to produce the real outputs: 3N of I/O and N of
; scratch disk for an N-byte archive, and a full second copy of the user's data
; sitting decrypted on disk for the length of the run.  The inventory already
; carries the name, the size, the extent and the flags - everything the tar
; header was being re-parsed for - so the middle step buys nothing.
;
; r8 selects where the bytes land:
;   0        the name in the index, under g_outdir_np (an archive)
;   non-zero exactly this path (a single-file container: it has one entry and
;            the user named the output themselves)
; and g_verify_only overrides both: nothing is opened and nothing is written,
; but every byte still goes through the decoder, because the tag is only correct
; once all of them have.
;
; THE DECODER IS estream's.  Three layers have to come off an entry in order -
; decrypt, de-frame, then skip the tar header and stop at the recorded size -
; and the rules for the last of them are subtle enough that a second
; implementation would be a second set of bugs.  See the head of estream.asm.
;
; locals: [rbp-16] es [rbp-24] entry [rbp-32] outpath [rbp-40] hout
;         [rbp-48] content left [rbp-56] this chunk [rbp-64] exit code
; =============================================================================
unpack_entry proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], INVALID
    mov     dword ptr [rbp-64], EXIT_OK
    ; ---- point the decoder at this entry ------------------------------------
    lea     r8, [g_key]                     ; rcx = ctx, rdx = entry already
    call    es_bind
    test    eax, eax
    jnz     ue_corrupt                      ; an extent too short to hold a tag
    mov     r10, qword ptr [rbp-24]
    mov     rax, qword ptr [r10+IDXE_size]
    mov     qword ptr [rbp-48], rax
    ; ---- where do the bytes go? ---------------------------------------------
    cmp     dword ptr [g_verify_only], 0
    jne     ue_stream                       ; nowhere: hout stays INVALID
    cmp     qword ptr [rbp-32], 0
    jne     ue_named                        ; a single-file container
    mov     rcx, qword ptr [rbp-24]
    call    entry_path
    cmp     eax, 1
    je      ue_unsafe
    cmp     eax, 2
    je      ue_corrupt
    ; A DIRECTORY entry creates the directory and holds no content - but its
    ; plaintext is still a sealed 512-byte tar header, so it goes through the
    ; decoder like anything else.  Skipping that would leave part of the
    ; container unauthenticated, which is the whole failure mode the per-entry
    ; tags exist to prevent.
    mov     r10, qword ptr [rbp-24]
    test    dword ptr [r10+IDXE_flags], IDXEF_DIR
    jz      ue_openout
    lea     rcx, [g_extw]
    call    create_parents
    WINCALL CreateDirectoryW, addr g_extw, 0
    jmp     ue_stream
ue_openout:
    lea     rcx, [g_extw]
    call    create_parents
    lea     rcx, [g_extw]
    jmp     ue_open
ue_named:
    mov     rcx, qword ptr [rbp-32]
ue_open:
    call    file_open_write
    cmp     rax, INVALID
    je      ue_io
    mov     qword ptr [rbp-40], rax
ue_stream:
    cmp     qword ptr [rbp-48], 0
    je      ue_empty
ue_loop:
    mov     rax, qword ptr [rbp-48]
    cmp     rax, CHUNK
    jbe     @F
    mov     rax, CHUNK
@@:
    mov     qword ptr [rbp-56], rax
    mov     rcx, qword ptr [rbp-16]
    xor     rdx, rdx                        ; no destination = discard
    cmp     qword ptr [rbp-40], INVALID
    je      @F
    lea     rdx, [g_filebuf]
@@:
    mov     r8, qword ptr [rbp-56]
    call    es_consume
    test    eax, eax
    jnz     ue_esfail
    cmp     qword ptr [rbp-40], INVALID
    je      ue_counted
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [g_filebuf]
    mov     r8, qword ptr [rbp-56]
    call    file_write_all
    test    eax, eax
    jnz     ue_io
ue_counted:
    mov     rcx, qword ptr [rbp-56]
    call    progress_add
    test    eax, eax
    jnz     ue_cancel
    mov     rax, qword ptr [rbp-56]
    sub     qword ptr [rbp-48], rax
    jnz     ue_loop
    jmp     ue_close
ue_empty:
    ; An empty file, or a directory.  Zero content bytes still means a call:
    ; that is what skips the tar header, drains the padding and checks the tag.
    ; An entry nobody authenticated is an entry nobody can trust, with or
    ; without content in it.
    mov     rcx, qword ptr [rbp-16]
    xor     rdx, rdx
    xor     r8, r8
    call    es_consume
    test    eax, eax
    jnz     ue_esfail
ue_close:
    cmp     qword ptr [rbp-40], INVALID
    je      ue_ok                           ; verify, or a directory
    mov     rcx, qword ptr [rbp-40]
    call    file_close
    mov     qword ptr [rbp-40], INVALID
    ; One line in the window's action log per file written out, AFTER the close:
    ; the name is only claimed once the bytes are on disk.
    mov     r10, qword ptr [rbp-24]
    lea     rcx, [r10+IDXE_name]
    mov     edx, dword ptr [r10+IDXE_namelen]
    call    rlog_extracted
ue_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
ue_esfail:
    ; The decoder knows WHICH of the three it was - a failed tag, a disk that
    ; did not answer, or a frame that did not decode - and they are three
    ; different things to tell someone about their archive.
    mov     rcx, qword ptr [rbp-16]
    call    es_code
    test    eax, eax
    jnz     @F
    mov     eax, EXIT_CORRUPT               ; it failed without saying why
@@:
    mov     dword ptr [rbp-64], eax
    jmp     ue_fail
ue_cancel:
    ; The same code the streaming loop this replaced returned for a cancel.
    mov     dword ptr [rbp-64], EXIT_IO
    jmp     ue_fail
ue_io:
    mov     dword ptr [rbp-64], EXIT_IO
    jmp     ue_fail
ue_unsafe:
    ; The one failure that is about the NAME rather than the bytes.  Returned
    ; distinctly so do_unpack can say so; it maps back to EXIT_CORRUPT there.
    mov     dword ptr [rbp-64], EXIT_UNSUPPORTED
    jmp     ue_fail
ue_corrupt:
    mov     dword ptr [rbp-64], EXIT_CORRUPT
ue_fail:
    ; THE PARTIAL OUTPUT DOES NOT SURVIVE.  A file that stopped half way because
    ; its tag failed is not a shorter version of the user's file; it is a
    ; fragment of something unauthenticated, sitting on disk under the real
    ; name, which is how it ends up being used.
    cmp     qword ptr [rbp-40], INVALID
    je      ue_failed
    mov     rcx, qword ptr [rbp-40]
    call    file_close
    mov     rcx, qword ptr [rbp-32]
    test    rcx, rcx
    jnz     @F
    lea     rcx, [g_extw]
@@:
    call    file_delete
ue_failed:
    mov     eax, dword ptr [rbp-64]
    FRAME_EPILOG
    ret
unpack_entry endp

; =============================================================================
; hdr_bad_version(rcx = the format version the container carries)
;
; Shared by every reader, so the three of them cannot come to describe the same
; situation differently.  The peek path (cmd.asm) deliberately does NOT call it:
; it is a silent probe that answers "is this ours?" for the GUI, and a probe
; that printed would put an error on screen for a file the user only hovered.
; =============================================================================
public hdr_bad_version
hdr_bad_version proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    prn     e_pver1
    mov     rcx, qword ptr [rbp-16]
    call    print_u64e
    prn     e_pver2
    mov     rcx, HDR_VERSION_MIN
    call    print_u64e
    prn     e_pver2b
    mov     rcx, HDR_VERSION
    call    print_u64e
    prn     e_pver3
    FRAME_EPILOG
    ret
hdr_bad_version endp

; =============================================================================
; hdr_version_ok(rcx = container header) -> eax 1 = this build can read it
;
; THE ONLY PLACE THE VERSION IS JUDGED.  There were four, each comparing for
; exact equality, and the reason to collapse them is not tidiness: the segment
; work makes the version decide BEHAVIOUR (the AAD length, the index entry
; layout), and four sites that agree today are four sites that can disagree
; after one of them is edited.  Whatever a reader needs to know about a version,
; it asks here.
;
; Prints nothing.  The peek path in cmd.asm answers "is this one of ours?" for a
; file the user has only hovered over in Explorer, and a probe that printed
; would put an error on screen for it.  Callers that report to a user follow a
; refusal with hdr_bad_version.
; =============================================================================
public hdr_version_ok
hdr_version_ok proc
    mov     eax, dword ptr [rcx+4]
    cmp     eax, HDR_VERSION_MIN
    jb      hvo_no
    cmp     eax, HDR_VERSION
    ja      hvo_no
    mov     eax, 1
    ret
hvo_no:
    xor     eax, eax
    ret
hdr_version_ok endp

; =============================================================================
; do_unpack -> eax exit code
; =============================================================================
public do_unpack
do_unpack proc frame
    FRAME_PROLOG 160
    ; [rbp-24]=hin [rbp-32]=decoder [rbp-40]=insize [rbp-56]=code
    ; [rbp-72]=compressed flag [rbp-80]=inventory bytes [rbp-88]=index cursor
    ; [rbp-96]=entries left [rbp-112]=next cursor [rbp-128]=bytes to extract
    mov     qword ptr [rbp-24], INVALID
    mov     qword ptr [rbp-32], 0
    mov     dword ptr [g_unpack_partial], 0

    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_pk_np]
    call    normalize_path
    test    eax, eax
    jnz     du_io
    ; vset_open, not file_open_read: handed any member of a volume set it
    ; assembles the whole set, and every read below then addresses the logical
    ; stream.  Handed an ordinary container it IS file_open_read and nothing
    ; else happens.
    lea     rcx, [g_pk_np]
    call    vset_open
    cmp     rax, INVALID
    je      du_io
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    lea     rdx, [rbp-40]
    call    vol_size
    test    eax, eax
    jnz     du_io
    cmp     qword ptr [rbp-40], CONTAINER_MIN_SIZE
    jb      du_corrupt

    ; The inventory sits after the payload tag, so the payload no longer runs to
    ; the end of the file.  idx_tail reads the trailer, validates it, and leaves
    ; the header in g_pkhdr with the file pointer at HDR_BYTES - which is exactly
    ; where the streaming below expects to start.
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [g_pkhdr]
    call    idx_tail
    cmp     rax, 0
    jl      du_corrupt
    mov     qword ptr [rbp-80], rax          ; bytes of inventory at the end
    lea     r10, [g_pkhdr]
    cmp     dword ptr [r10+0], HDR_MAGIC
    jne     du_corrupt
    mov     rcx, r10
    call    hdr_version_ok
    test    eax, eax
    jz      du_version
    ; an out-of-range seg_shift is refused before anything derives from it -
    ; see seg_bytes_from_hdr for what an unvalidated one costs
    lea     rcx, [g_pkhdr]
    call    seg_bytes_from_hdr
    cmp     rax, -1
    je      du_corrupt
    lea     r10, [g_pkhdr]
    cmp     byte ptr [r10+CONTAINER_HDR.lanes], 1
    jne     du_corrupt
    movzx   eax, byte ptr [r10+CONTAINER_HDR.archive]      ; archive flag
    mov     r11d, dword ptr [g_bare]    ; expected flag = NOT bare
    xor     r11d, 1
    cmp     eax, r11d
    jne     du_notarch
    movzx   eax, byte ptr [r10+CONTAINER_HDR.compressed]      ; 0 store / 1 xpress
    cmp     eax, 1
    ja      du_corrupt
    mov     qword ptr [rbp-72], rax

    ; ---- pre-auth KDF-parameter guard -------------------------------------
    ; t_cost and m_cost come from the file, and the file is not authenticated
    ; yet - the GCM tag only clears after the key exists, and the key is what
    ; these two parameters produce.  So they must be range-checked BEFORE the
    ; KDF runs, or a hostile container names m_cost = 4 TiB (an allocation that
    ; cannot succeed) or t_cost = 0FFFFFFFFh (a derivation that never finishes)
    ; and the process is wedged by a file nobody has proved they can decrypt.
    ; open_container (cmd.asm) has always done this for single-file containers;
    ; the archive path did not, and reached derive_key with whatever the header
    ; said.  Same bounds, same exit code, so the two paths cannot diverge.
    mov     eax, dword ptr [r10+8]      ; t_cost
    cmp     eax, ARGON2_MIN_T
    jb      du_params
    cmp     eax, ARGON2_MAX_T
    ja      du_params
    mov     eax, dword ptr [r10+12]     ; m_cost (KiB)
    cmp     eax, ARGON2_MIN_M_KIB
    jb      du_params
    cmp     eax, ARGON2_MAX_M_KIB
    ja      du_params

    lea     rcx, [g_pkhdr+20]
    mov     edx, dword ptr [g_pkhdr+8]
    mov     r8d, dword ptr [g_pkhdr+12]
    call    derive_key
    test    eax, eax
    jnz     du_oom
    ; key-check: reject a wrong password before streaming/decompressing
    lea     rcx, [g_pkkcv]
    call    compute_kcv
    lea     rcx, [g_pkkcv]
    lea     rdx, [g_pkhdr+KCV_OFFSET]
    mov     r8, KCV_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     du_auth
    ; The inventory locates every entry, so it has to be read first now - and
    ; authenticating it is not optional even for verify, since a container is
    ; one object and a byte changed anywhere in it must fail.
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-80]
    call    idx_auth
    test    eax, eax
    jz      du_idxok
    cmp     eax, EXIT_AUTH
    je      du_auth
    jmp     du_io
du_idxok:

    ; ---- what is about to be written, and where ----------------------------
    ; Both answers come from the inventory, before anything is decrypted.  There
    ; is no temporary copy of the archive any more, so the only disk that has to
    ; be weighed is the output's, and the amount is the real one: the entries'
    ; content, not the container's size.
    call    idx_extract_bytes
    mov     qword ptr [rbp-128], rax
    cmp     dword ptr [g_verify_only], 0
    jne     du_out_ready                ; verify writes nothing, anywhere
    mov     rcx, qword ptr [g_cfg_out]
    lea     rdx, [g_outdir_np]
    call    normalize_path
    test    eax, eax
    jnz     du_io
    lea     rcx, [g_outdir_np]
    mov     rdx, qword ptr [rbp-128]
    add     rdx, DISK_MARGIN
    call    disk_has_space
    cmp     eax, 1
    je      du_nospace
    ; A single-file container's output is a FILE, and g_outdir_np is its path -
    ; but it is written under a .part name and renamed once the tag verifies.
    ; An archive's output is a directory, which has to exist before the first
    ; entry lands in it.
    cmp     dword ptr [g_bare], 0
    je      du_mkoutdir
    call    bare_part_path
    jmp     du_out_ready
du_mkoutdir:
    WINCALL CreateDirectoryW, addr g_outdir_np, 0
du_out_ready:

    ; ---- one decoder for the whole run --------------------------------------
    ; es_new is the container half of estream's constructor: the buffers, a
    ; handle, and one decompressor.  Bound to each entry in turn below, so a
    ; hundred thousand files cost one allocation rather than a hundred thousand.
    lea     rcx, [g_pk_np]
    call    es_new
    test    rax, rax
    jz      du_oom                      ; the container is demonstrably open
                                        ; already, so what failed was the
                                        ; allocation or the decompressor
    mov     qword ptr [rbp-32], rax

    ; ---- extract, one entry at a time ---------------------------------------
    ; The inventory has already been decrypted and authenticated (above), so its
    ; extents can be trusted; each entry is its own GCM stream and is verified on
    ; its own, by unpack_entry, as it writes it.
    ;
    ; [rbp-88]=cursor into g_idxbuf  [rbp-96]=entries left
    mov     rcx, qword ptr [rbp-128]
    lea     rdx, [lbl_unpack]
    mov     r8d, lbl_unpack_len
    call    progress_begin
    mov     qword ptr [rbp-88], 0
    mov     qword ptr [rbp-104], 0           ; entries actually written out
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-96], rax
du_entry:
    cmp     qword ptr [rbp-96], 0
    je      du_entries_done
    ; bounds: the table is authentic, but a container written by a future
    ; version could still describe an entry that runs off the end of it
    mov     rax, qword ptr [rbp-88]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      du_corrupt
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-88]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      du_corrupt
    mov     qword ptr [rbp-112], rax         ; cursor for the next entry
    ; ---- was this one asked for? -------------------------------------------
    ; Only when a selection is actually in force.  The bit alone must not decide
    ; it: a stale pick left over from an earlier browse would silently narrow an
    ; extract that had asked for everything, and the user would get part of
    ; their data with nothing on screen saying so.
    cmp     dword ptr [g_pick_active], 0
    je      du_picked
    lea     rcx, [r10+IDXE_name]
    mov     edx, dword ptr [r10+IDXE_namelen]
    call    pick_has
    test    eax, eax
    jnz     du_picked
    mov     rax, qword ptr [rbp-112]
    mov     qword ptr [rbp-88], rax
    dec     qword ptr [rbp-96]
    jmp     du_entry
du_picked:
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-88]
    ; the extent must lie inside the payload run
    mov     rax, qword ptr [r10+IDXE_stored]
    cmp     rax, GCM_TAG_LEN
    jb      du_corrupt
    mov     r11, qword ptr [r10+IDXE_offset]
    CHECK_ADD_OVF r11, rax
    mov     rcx, qword ptr [rbp-40]
    sub     rcx, HDR_BYTES
    sub     rcx, qword ptr [rbp-80]          ; payload run length
    cmp     r11, rcx
    ja      du_corrupt
    ; ---- decrypt it straight into its own file ------------------------------
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [g_idxptr]
    add     rdx, qword ptr [rbp-88]
    xor     r8, r8                           ; the name in the index decides
    cmp     dword ptr [g_bare], 0
    je      @F
    lea     r8, [g_extw]                     ; ...except for a single file, which
                                             ; goes to its .part name
@@:
    call    unpack_entry
    test    eax, eax
    jnz     du_entry_err
    inc     qword ptr [rbp-104]
    mov     rax, qword ptr [rbp-112]
    mov     qword ptr [rbp-88], rax
    dec     qword ptr [rbp-96]
    jmp     du_entry
du_entries_done:
    call    progress_done
    mov     rcx, qword ptr [rbp-32]
    call    es_destroy
    mov     qword ptr [rbp-32], 0
    ; close the container.  vset_close, because the "container" may be a whole
    ; set of open parts - it closes one plain handle when it is one.
    mov     rcx, qword ptr [rbp-24]
    call    vset_close
    mov     qword ptr [rbp-24], INVALID

    ; verify is done the moment every tag has matched: nothing was written, so
    ; there is nothing to rename, extract or clean up.
    cmp     dword ptr [g_verify_only], 0
    je      @F
    xor     eax, eax
    jmp     du_done
@@:
    cmp     dword ptr [g_bare], 0
    je      du_okmsg
    ; every byte verified: the .part becomes the file the user asked for
    lea     rcx, [g_extw]
    lea     rdx, [g_outdir_np]
    call    file_rename
    test    eax, eax
    jnz     du_partfail
    prn_a   msg_dec_ok2                      ; single-file container
    jmp     du_okname
du_partfail:
    lea     rcx, [g_extw]
    call    file_delete                      ; do not leave a stray .part behind
    jmp     du_io
du_okmsg:
    prn_a   msg_unpack_ok
du_okname:
    mov     rcx, qword ptr [g_cfg_out]
    call    print_wz
    lea     rcx, [msg_nl]
    mov     edx, 2
    call    print_a
    xor     eax, eax
    jmp     du_done
du_entry_err:
    ; unpack_entry has already closed and deleted whatever it had partly
    ; written.  It reports WHY, and the three reasons are not interchangeable:
    ; a failed tag means the container is not what it was, a refused name means
    ; it is describing a file we will not create, and everything else is the
    ; disk.
    mov     dword ptr [rbp-56], eax
    call    progress_done
    mov     eax, dword ptr [rbp-56]
    cmp     eax, EXIT_AUTH
    jne     @F
    prn     e_pauth
    jmp     du_partial
@@:
    cmp     eax, EXIT_UNSUPPORTED
    jne     @F
    prn     e_pname
    mov     dword ptr [rbp-56], EXIT_CORRUPT ; what the tar walk returned for it
    jmp     du_partial
@@:
    cmp     eax, EXIT_CORRUPT
    jne     @F
    prn     e_pcorrupt
    jmp     du_partial
@@:
    prn     e_pio
du_partial:
    ; What is already on disk, said out loud.  verify writes nothing, and a
    ; failure on the very first entry left nothing behind either.
    cmp     dword ptr [g_verify_only], 0
    jne     du_done2
    cmp     qword ptr [rbp-104], 0
    je      du_done2
    mov     dword ptr [g_unpack_partial], 1
    prn     e_pincomplete
    mov     rcx, qword ptr [rbp-104]
    call    print_u64e
    prn     msg_nl
du_done2:
    mov     eax, dword ptr [rbp-56]
    jmp     du_done
du_auth:
    prn     e_pauth
    mov     eax, EXIT_AUTH
    jmp     du_done
du_corrupt:
    prn     e_pcorrupt
    mov     eax, EXIT_CORRUPT
    jmp     du_done
du_params:
    prn     e_pparams
    mov     eax, EXIT_CORRUPT
    jmp     du_done
du_version:
    lea     r10, [g_pkhdr]
    mov     ecx, dword ptr [r10+4]
    call    hdr_bad_version
    mov     eax, EXIT_UNSUPPORTED
    jmp     du_done
du_notarch:
    prn     e_pnotarch
    mov     eax, EXIT_CORRUPT
    jmp     du_done
du_nospace:
    call    progress_done
    prn     e_pnospace
    mov     eax, EXIT_NOSPACE
    jmp     du_done
du_io:
    call    progress_done
    prn     e_pio
    mov     eax, EXIT_IO
    jmp     du_done
du_oom:
    prn     e_poom
    mov     eax, EXIT_OOM
du_done:
    ; No temporary files to remove: there are none.  That is the point of the
    ; change - the plaintext of the whole archive never existed anywhere but in
    ; the files the user asked for.
    mov     dword ptr [rbp-56], eax
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
    mov     rcx, qword ptr [rbp-32]
    test    rcx, rcx
    jz      @F
    call    es_destroy                       ; wipes its buffers: they held
                                             ; plaintext and an expanded key
    mov     qword ptr [rbp-32], 0
@@:
    mov     rcx, qword ptr [rbp-24]
    call    vset_close                       ; may be a set; see above
    mov     eax, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
do_unpack endp

; =============================================================================
; idx_auth(rcx = handle, rdx = file size, r8 = tail bytes from idx_tail)
;   -> eax 0 / EXIT_AUTH / EXIT_IO
;
; Decrypt the inventory into g_idxbuf and check its tag.  Assumes g_key is
; already derived and g_idxtrl already holds the trailer idx_tail validated.
;
; Every reader calls this, not just the ones that want the listing.  decrypt and
; verify have no use for the entries, but a container is a single object and a
; changed byte anywhere in it must be a failure - without this, flipping a bit
; inside the inventory decrypted cleanly and said nothing, which is exactly the
; kind of silent tolerance the tamper suite exists to catch (and did: 43/44).
;
; locals (frame 96): handle[-16] size[-24] tail[-32] index offset[-40]
; =============================================================================
; =============================================================================
; idx_next_floor -> rax = one past the highest ordinal the decrypted index
; lists, or 0 when it lists nothing.
;
; The lowest value the trailer's counter is allowed to hold.  Walks g_idxbuf, so
; it is only meaningful after the index has been decrypted.
; =============================================================================
idx_next_floor proc
    xor     rax, rax                         ; floor so far = one past the last
    xor     r11, r11                         ; cursor into the table
inf_next:
    cmp     r11, qword ptr [g_idxlen]
    jae     inf_ret
    mov     r10, qword ptr [g_idxptr]
    add     r10, r11
    mov     rdx, qword ptr [r10+IDXE_ordinal]
    ; STRICTLY increasing, which is the check that catches a REUSED ordinal
    ; rather than merely a counter that is too low.  It holds by construction:
    ; ordinals are issued in order, a pack and an add both append in order, and
    ; do_remove_marked compacts without reordering.  A duplicate would sit at or
    ; below its predecessor and land here.
    cmp     rdx, rax
    jb      inf_bad
    inc     rdx
    mov     rax, rdx
    mov     edx, dword ptr [r10+IDXE_namelen]
    add     r11, IDXE_FIXED
    add     r11, rdx                         ; namelen 0 still advances by FIXED
    jmp     inf_next
inf_bad:
    ; -1 is a floor no counter can meet, so the caller refuses the container.
    ; Deliberately the same outcome as a too-low counter: both mean an ordinal
    ; is about to be issued twice, and neither is safe to append to.
    mov     rax, -1
inf_ret:
    ret
idx_next_floor endp

public idx_auth
idx_auth proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    ; AFTER the arguments are in the frame, not before: idx_buf_ensure is a
    ; framed proc and clobbers rcx, rdx and r8 - which are the handle, the size
    ; and the tail length.  Called first, it fed this proc three garbage values
    ; and every read in the tree failed with "I/O failure".
    call    idx_buf_ensure                  ; every read decrypts into it
    test    eax, eax
    jnz     ia_oom
    lea     r10, [g_idxtrl]
    mov     rax, qword ptr [r10+IDXT_len]
    mov     qword ptr [g_idxlen], rax
    ; BOUND IT HERE, not only in idx_tail.  This value is read out of the trailer
    ; before anything has authenticated it - the comment further down says so -
    ; and it is then used as a length twice over: the read into g_idxbuf, which
    ; is bounded by IDX_MAX_BYTES, and the secure_zero of that buffer on the
    ; failure paths.  Every caller happens to run idx_tail first, which rejects a
    ; length past IDX_MAX_BYTES, so the invariant holds today - but it holds in a
    ; different proc, and this one is where a bad value would do the damage.  Two
    ; instructions to stop that being a refactor away.
    cmp     rax, IDX_MAX_BYTES
    ja      ia_toolong
    ; And commit that much of the reservation before anything reads into it.
    ; The length is still UNAUTHENTICATED here, so this is also the most a
    ; hostile container can make this process commit - which is why the bound
    ; above has to come first, and why the ceiling is a ceiling rather than
    ; whatever the file claims.
    mov     rcx, rax
    call    idx_buf_commit
    test    eax, eax
    jnz     ia_oom
    lea     r10, [g_idxtrl]
    mov     eax, dword ptr [r10+IDXT_count]
    mov     qword ptr [g_idxcount], rax
    mov     eax, dword ptr [r10+IDXT_flags]
    mov     qword ptr [g_idxflags], rax
    mov     eax, dword ptr [r10+IDXT_rev]
    mov     dword ptr [g_idxrev], eax
    mov     rax, qword ptr [rbp-24]
    sub     rax, qword ptr [rbp-32]          ; start of the inventory
    mov     qword ptr [rbp-40], rax
    cmp     qword ptr [g_idxlen], 0
    je      ia_readtag
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [g_idxptr]
    mov     r9, qword ptr [g_idxlen]
    call    vol_get
    test    eax, eax
    jnz     ia_io
ia_readtag:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-40]
    add     rdx, qword ptr [g_idxlen]
    lea     r8, [g_pktag2]                   ; the stored tag
    mov     r9, GCM_TAG_LEN
    call    vol_get
    test    eax, eax
    jnz     ia_io

    ; ---- AAD, exactly as the writer built it --------------------------------
    lea     r10, [g_idxaad]
    lea     r11, [g_pkhdr]
    xor     r9, r9
ia_aad1:
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    cmp     r9, HDR_BYTES
    jb      ia_aad1
    lea     r11, [g_idxtrl]
    xor     r9, r9
ia_aad2:
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+HDR_BYTES+r9], al
    inc     r9
    cmp     r9, IDX_TRAILER_BYTES
    jb      ia_aad2
    ; nonce: from the revision in the trailer, as the writer derived it
    call    idx_nonce_set

    lea     rcx, [g_pkctx]
    lea     rdx, [g_key]
    lea     r8, [g_idxnonce]
    mov     r9, 1                            ; decrypt
    call    gcm_init
    lea     rcx, [g_pkctx]
    lea     rdx, [g_idxaad]
    mov     r8, IDX_AAD_BYTES
    call    gcm_aad
    cmp     qword ptr [g_idxlen], 0
    je      ia_final
    lea     rcx, [g_pkctx]
    mov     rdx, qword ptr [g_idxptr]
    mov     r8, qword ptr [g_idxptr]
    mov     r9, qword ptr [g_idxlen]
    call    gcm_crypt
ia_final:
    lea     rcx, [g_pkctx]
    lea     rdx, [g_pktag]
    call    gcm_final
    lea     rcx, [g_pktag]
    lea     rdx, [g_pktag2]
    mov     r8, GCM_TAG_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     ia_bad
    ; ---- the ordinal counter, taken only now that the tag has proven it ------
    ; Deliberately not hoisted up with g_idxlen and the rest: those are needed to
    ; PERFORM the authentication, this is needed after it.  A value read before
    ; the tag was checked is attacker-chosen, and the one thing it steers is
    ; which nonce the next entry gets.
    lea     r10, [g_idxtrl]
    mov     rax, qword ptr [r10+IDXT_next]
    mov     qword ptr [g_entnext], rax
    call    idx_next_floor
    cmp     qword ptr [g_entnext], rax
    jb      ia_lowcounter
    xor     eax, eax
    FRAME_EPILOG
    ret
ia_lowcounter:
    ; Authenticated, so this is not tampering - it is our own writer having
    ; written a counter that would hand a live ordinal out a second time.  Refuse
    ; the container rather than append onto a reused nonce.
    mov     qword ptr [g_entnext], 0
    mov     rcx, qword ptr [g_idxptr]
    mov     rdx, qword ptr [g_idxlen]
    call    secure_zero
    call    idx_reset
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
ia_bad:
    ; a failed tag means the bytes are not ours to believe; do not leave whatever
    ; they decrypted to sitting in the buffer for a caller to walk
    mov     rcx, qword ptr [g_idxptr]
    mov     rdx, qword ptr [g_idxlen]
    call    secure_zero
    call    idx_reset
    mov     eax, EXIT_AUTH
    FRAME_EPILOG
    ret
ia_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
ia_oom:
    ; Callers map anything that is not EXIT_AUTH to "I/O failure", so an OOM
    ; here prints as a disk problem.  Reviewed in the 1.0.82 audit and left:
    ; the only way to fail a RESERVATION of address space on x64 is a process
    ; already in serious trouble, and threading a fourth error message through
    ; three callers for it buys almost nothing.  Recorded so the wart is a
    ; decision, not an oversight.
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
ia_toolong:
    ; Nothing has been read into the inventory buffer yet, so there is nothing to
    ; wipe - and wiping it would itself use the length being rejected.
    mov     qword ptr [g_idxlen], 0
    call    idx_reset
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
idx_auth endp

; =============================================================================
; idx_read -> eax exit code.  Decrypt and authenticate ONLY the inventory of the
; container named by g_cfg_in, leaving g_idxbuf holding the entry table and
; g_idxcount / g_idxflags describing it.
;
; This is the point of the whole v3 change: the listing is behind the same key
; as the payload, so a password is still required, but reading it costs one
; Argon2 derivation and a few kilobytes of GCM - not a pass over the archive.
; The payload's own ciphertext is never touched.
; =============================================================================
public idx_read
idx_read proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=hin [rbp-32]=size [rbp-40]=tail [rbp-48]=index offset
    mov     qword ptr [rbp-24], INVALID
    call    idx_reset
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_pk_np]
    call    normalize_path
    test    eax, eax
    jnz     ir_io
    ; a set, or a plain container - see the note in do_unpack
    lea     rcx, [g_pk_np]
    call    vset_open
    cmp     rax, INVALID
    je      ir_io
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    lea     rdx, [rbp-32]
    call    vol_size
    test    eax, eax
    jnz     ir_io
    cmp     qword ptr [rbp-32], CONTAINER_MIN_SIZE
    jb      ir_corrupt

    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [g_pkhdr]
    call    idx_tail
    cmp     rax, 0
    jl      ir_corrupt
    mov     qword ptr [rbp-40], rax
    lea     r10, [g_pkhdr]
    cmp     dword ptr [r10+0], HDR_MAGIC
    jne     ir_corrupt
    mov     rcx, r10
    call    hdr_version_ok
    test    eax, eax
    jz      ir_version
    ; the add path takes its header from here, and entry_begin will derive the
    ; segment size from whatever this admits - so an invalid shift stops now
    lea     rcx, [g_pkhdr]
    call    seg_bytes_from_hdr
    cmp     rax, -1
    je      ir_corrupt
    lea     r10, [g_pkhdr]
    cmp     byte ptr [r10+CONTAINER_HDR.lanes], 1
    jne     ir_corrupt
    ; same pre-auth KDF-parameter guard as every other reader: these two numbers
    ; come from an unauthenticated file and decide how much memory and time the
    ; derivation costs
    mov     eax, dword ptr [r10+8]
    cmp     eax, ARGON2_MIN_T
    jb      ir_params
    cmp     eax, ARGON2_MAX_T
    ja      ir_params
    mov     eax, dword ptr [r10+12]
    cmp     eax, ARGON2_MIN_M_KIB
    jb      ir_params
    cmp     eax, ARGON2_MAX_M_KIB
    ja      ir_params

    lea     rcx, [g_pkhdr+20]
    mov     edx, dword ptr [g_pkhdr+8]
    mov     r8d, dword ptr [g_pkhdr+12]
    call    derive_key
    test    eax, eax
    jnz     ir_oom
    lea     rcx, [g_pkkcv]
    call    compute_kcv
    lea     rcx, [g_pkkcv]
    lea     rdx, [g_pkhdr+KCV_OFFSET]
    mov     r8, KCV_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     ir_auth

    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-40]
    call    idx_auth
    test    eax, eax
    jz      ir_close
    cmp     eax, EXIT_AUTH
    je      ir_auth
    jmp     ir_io
ir_auth:
    prn     e_pauth
    mov     eax, EXIT_AUTH
    jmp     ir_close
ir_version:
    lea     r10, [g_pkhdr]
    mov     ecx, dword ptr [r10+4]
    call    hdr_bad_version
    mov     eax, EXIT_UNSUPPORTED
    jmp     ir_close
ir_corrupt:
    prn     e_pcorrupt
    mov     eax, EXIT_CORRUPT
    jmp     ir_close
ir_params:
    prn     e_pparams
    mov     eax, EXIT_CORRUPT
    jmp     ir_close
ir_oom:
    prn     e_poom
    mov     eax, EXIT_OOM
    jmp     ir_close
ir_io:
    prn     e_pio
    mov     eax, EXIT_IO
ir_close:
    mov     dword ptr [rbp-56], eax
    ; The key normally dies here - it was derived for one listing and is not
    ; needed after it.  A caller that is about to REWRITE the index needs it a
    ; moment longer, and says so; it wipes the key itself when it is done.
    cmp     dword ptr [g_keep_key], 0
    jne     ir_nowipe
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
ir_nowipe:
    mov     rcx, qword ptr [rbp-24]
    call    vset_close                       ; may be a set; see do_unpack
    mov     eax, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
idx_read endp

; =============================================================================
; idx_find(rcx = utf8 name, rdx = name length) -> rax = cursor into g_idxbuf, or
; -1.  Exact match on the recorded entry name.
;
; Published because a drag OUT starts from a selected row, and a row carries the
; path it displays rather than a cursor - so the name is the only handle the GUI
; has on the entry behind it.
; =============================================================================
public idx_find
idx_find proc frame
    FRAME_PROLOG 64
    ; [rbp-16]=name [rbp-24]=len [rbp-32]=cursor [rbp-40]=left
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-40], rax
if_next:
    cmp     qword ptr [rbp-40], 0
    je      if_none
    mov     rax, qword ptr [rbp-32]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      if_none
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-32]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      if_none
    mov     qword ptr [rbp-48], rax
    cmp     r11, qword ptr [rbp-24]
    jne     if_step
    mov     rcx, qword ptr [rbp-16]
    xor     r9, r9
if_cmp:
    cmp     r9, r11
    jae     if_hit
    mov     al, byte ptr [rcx+r9]
    cmp     al, byte ptr [r10+IDXE_name+r9]
    jne     if_step
    inc     r9
    jmp     if_cmp
if_hit:
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
if_step:
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [rbp-32], rax
    dec     qword ptr [rbp-40]
    jmp     if_next
if_none:
    mov     rax, -1
    FRAME_EPILOG
    ret
idx_find endp

; =============================================================================
; idx_mark_dropped(rcx = utf8 name, rdx = name length) -> rax = entries marked,
; 0 if there is no such entry.
;
; Removing a DIRECTORY means removing what is in it.  Marking only the directory
; entry left every file beneath it in the container - still in the index, still
; in the payload, still under the same key - and a full decrypt handed them all
; back.  Nothing on screen said so: a child whose parent is gone can never be
; expanded into view, so the listing looked exactly like a successful delete and
; the only thing that reported the truth was an extract.  That is the worst
; possible shape for this bug, which is why the subtree walk lives HERE, in the
; one place both the CLI verb and the GUI's Remove mark through, rather than in
; either caller.
;
; A descendant is an entry whose name begins with the directory's name followed
; by '/'.  The separator test is what keeps "tree/secret" from taking
; "tree/secretive/x" with it.
;
; Marking is idempotent, so selecting a folder AND something inside it is fine;
; the count may then exceed the number of distinct entries, and its only use is
; "was anything selected at all".
; =============================================================================
; A tail jump, so no frame of its own: "proc frame" without FRAME_PROLOG would
; claim unwind data this never sets up.
public idx_mark_dropped
idx_mark_dropped proc
    mov     r8d, IDXEF_DROPPED
    jmp     idx_mark_flag
idx_mark_dropped endp


; =============================================================================
; The pick list - names chosen for extraction, held OUTSIDE the index.
;
; The obvious place was a flag bit on the entry, and it does not work:
; do_unpack calls idx_auth, which re-reads and decrypts the index over
; g_idxbuf, so any bit the caller set is gone by the time the extraction loop
; looks for it.  The symptom was the worst kind - a selection that produced NO
; files at all while every part of the UI said the right thing.
;
; Names rather than positions or ordinals, because both of those are properties
; of a table that gets rebuilt: a position is meaningless after a delete, and a
; zip entry has no ordinal at all.  A name is what the user picked.
;
; Format: u32 length, then that many bytes, repeated.  Linear scan; a selection
; is small and this runs once per entry extracted.
; =============================================================================
public pick_reset
pick_reset proc
    mov     qword ptr [g_picklen], 0
    mov     dword ptr [g_pick_active], 0
    ret
pick_reset endp

; pick_add(rcx = utf8 name, rdx = length) -> eax = 1 added, 0 no room.
public pick_add
pick_add proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     r10, qword ptr [g_picklen]
    add     r10, 4
    add     r10, rdx
    cmp     r10, PICK_MAX_BYTES
    jbe     pa_room
    ; Refuse rather than truncate.  A pick list that quietly stops short would
    ; extract part of what was asked for and report success.
    xor     eax, eax
    FRAME_EPILOG
    ret
pa_room:
    lea     r10, [g_pickbuf]
    add     r10, qword ptr [g_picklen]
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [r10], eax
    mov     r11, qword ptr [rbp-16]
    xor     r9, r9
pa_copy:
    cmp     r9, qword ptr [rbp-24]
    jae     pa_copied
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+4+r9], al
    inc     r9
    jmp     pa_copy
pa_copied:
    mov     rax, qword ptr [rbp-24]
    add     rax, 4
    add     qword ptr [g_picklen], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
pick_add endp

; pick_has(rcx = utf8 name, rdx = length) -> eax = 1 if it was picked.
public pick_has
pick_has proc
    xor     r9, r9                              ; cursor
ph_next:
    mov     r10, r9
    add     r10, 4
    cmp     r10, qword ptr [g_picklen]
    ja      ph_no
    lea     r11, [g_pickbuf]
    add     r11, r9
    mov     r8d, dword ptr [r11]                ; this entry's length
    mov     r10, r9
    add     r10, 4
    add     r10, r8
    cmp     r10, qword ptr [g_picklen]
    ja      ph_no
    cmp     r8, rdx
    jne     ph_step
    xor     rax, rax
ph_cmp:
    cmp     rax, rdx
    jae     ph_yes
    mov     r8b, byte ptr [rcx+rax]
    cmp     r8b, byte ptr [r11+4+rax]
    jne     ph_step
    inc     rax
    jmp     ph_cmp
ph_step:
    mov     r9, r10
    jmp     ph_next
ph_yes:
    mov     eax, 1
    ret
ph_no:
    xor     eax, eax
    ret
pick_has endp

; =============================================================================
; idx_pick_collect - copy every IDXEF_PICK name into the pick list.
;
; idx_mark_flag does the subtree walk against the index; this lifts the result
; out of it, so the choice survives the index being rebuilt.
; =============================================================================
public idx_pick_collect
idx_pick_collect proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=cursor [rbp-32]=left [rbp-40]=next [rbp-48]=count
    call    pick_reset
    mov     qword ptr [rbp-48], 0
    mov     qword ptr [rbp-24], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-32], rax
ipc_next:
    cmp     qword ptr [rbp-32], 0
    je      ipc_done
    mov     rax, qword ptr [rbp-24]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      ipc_done
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      ipc_done
    mov     qword ptr [rbp-40], rax
    test    dword ptr [r10+IDXE_flags], IDXEF_PICK
    jz      ipc_step
    lea     rcx, [r10+IDXE_name]
    mov     rdx, r11
    call    pick_add
    test    eax, eax
    jz      ipc_full
    inc     qword ptr [rbp-48]
ipc_step:
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rbp-24], rax
    dec     qword ptr [rbp-32]
    jmp     ipc_next
ipc_full:
    ; out of room: fall back to extracting everything rather than a silent
    ; subset, and say so by leaving the selection off
    call    pick_reset
    xor     eax, eax
    FRAME_EPILOG
    ret
ipc_done:
    mov     rax, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
idx_pick_collect endp

; =============================================================================
; idx_mark_flag(rcx = utf8 name, rdx = name length, r8d = flag bits)
;   -> rax = entries marked, 0 if there is no such entry.
;
; The subtree rule above, for any in-memory mark: removal uses it, and so does
; the extraction pick, because "this folder" has to mean the same thing to both.
; A selection that took a folder without its contents would extract an empty
; directory and look like it had worked.
; =============================================================================
public idx_mark_flag
idx_mark_flag proc frame
    FRAME_PROLOG 96
    ; [rbp-16]=name [rbp-24]=len [rbp-32]=cursor [rbp-40]=left [rbp-48]=next
    ; [rbp-56]=marked [rbp-64]=flag
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     dword ptr [rbp-64], r8d
    mov     qword ptr [rbp-56], 0
    call    idx_find                            ; rcx/rdx are still the arguments
    cmp     rax, 0
    jl      imd_none
    mov     r10, qword ptr [g_idxptr]
    add     r10, rax
    mov     eax, dword ptr [rbp-64]
    or      dword ptr [r10+IDXE_flags], eax
    mov     qword ptr [rbp-56], 1
    test    dword ptr [r10+IDXE_flags], IDXEF_DIR
    jz      imd_done                            ; a file takes nothing with it
    ; ---- everything under "<name>/" -----------------------------------------
    mov     qword ptr [rbp-32], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-40], rax
imd_next:
    cmp     qword ptr [rbp-40], 0
    je      imd_done
    ; the same bounds check the other walkers make: the table is authentic, but
    ; a container from a future version could still describe an entry off its end
    mov     rax, qword ptr [rbp-32]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      imd_done
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-32]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      imd_done
    mov     qword ptr [rbp-48], rax
    ; long enough to be "<name>/something", and separated by '/' at that point
    mov     rax, qword ptr [rbp-24]
    inc     rax
    cmp     r11, rax
    jb      imd_step
    mov     rax, qword ptr [rbp-24]
    cmp     byte ptr [r10+rax+IDXE_name], 2Fh
    jne     imd_step
    mov     rcx, qword ptr [rbp-16]
    xor     r9, r9
imd_cmp:
    cmp     r9, qword ptr [rbp-24]
    jae     imd_hit
    mov     al, byte ptr [rcx+r9]
    cmp     al, byte ptr [r10+IDXE_name+r9]
    jne     imd_step
    inc     r9
    jmp     imd_cmp
imd_hit:
    mov     eax, dword ptr [rbp-64]
    or      dword ptr [r10+IDXE_flags], eax
    inc     qword ptr [rbp-56]
imd_step:
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [rbp-32], rax
    dec     qword ptr [rbp-40]
    jmp     imd_next
imd_done:
    mov     rax, qword ptr [rbp-56]
    FRAME_EPILOG
    ret
imd_none:
    xor     rax, rax
    FRAME_EPILOG
    ret
idx_mark_flag endp

; =============================================================================
; idx_drop(rcx = cursor of the entry to remove) - take it out of the table.
; The survivors keep the ordinals they were sealed with, which is the whole
; reason those are recorded rather than implied by position.
; =============================================================================
idx_drop proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     r10, qword ptr [g_idxptr]
    add     r10, rcx
    mov     eax, dword ptr [r10+IDXE_namelen]
    add     rax, IDXE_FIXED
    mov     qword ptr [rbp-24], rax             ; bytes this entry occupies
    ; slide the tail down over it
    mov     r11, qword ptr [rbp-16]
    add     r11, rax                            ; source
    mov     rcx, qword ptr [g_idxlen]
    sub     rcx, r11                            ; bytes to move
    mov     r10, qword ptr [g_idxptr]
    add     r11, r10                            ; source pointer
    mov     rdx, qword ptr [rbp-16]
    add     rdx, r10                            ; destination pointer
    xor     r9, r9
id_move:
    cmp     r9, rcx
    jae     id_moved
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [rdx+r9], al
    inc     r9
    jmp     id_move
id_moved:
    mov     rax, qword ptr [rbp-24]
    sub     qword ptr [g_idxlen], rax
    dec     qword ptr [g_idxcount]
    FRAME_EPILOG
    ret
idx_drop endp

; =============================================================================
; do_delete -> eax exit code.  Remove named entries from a container IN PLACE.
;
; This is the >= 500 MB half of the delete rules: the entry's ciphertext is
; overwritten where it lies with random bytes and taken out of the index, so
; nothing is rewritten but the index and nothing survives to be recovered.  The
; carve half - decrypt, drop, re-encrypt under a fresh key - is a repack and is
; not this proc.
;
; RANDOM, never zeros: a run of zeros in a container advertises exactly where
; something used to be and how big it was.  Random bytes are indistinguishable
; from the ciphertext around them.
;
; The index rewrite is the one part that encrypts anything, and it consumes
; exactly one counter: the next revision.  Re-encrypting a changed index under
; the nonce the old one used would be catastrophic, which is why the revision
; lives in the trailer and the nonce is derived from it.
;
; locals (frame 192): handle[-16] size[-24] tail[-32] idxoff[-40] argi[-48]
;   remaining[-56] chunk[-64] code[-72] argname[-80] entry[-88] fileoff[-96].
;   192 because WideCharToMultiByte takes EIGHT arguments - 32 bytes of shadow
;   space plus four stack slots - and that outgoing area has to sit below the
;   deepest local, not through it.
; =============================================================================
public do_delete
do_delete proc frame
    FRAME_PROLOG 192
    mov     qword ptr [rbp-16], INVALID
    ; the inventory, which is also the password check and the key.  The key has
    ; to outlive it here: whichever path runs will encrypt something.
    mov     dword ptr [g_keep_key], 1
    call    idx_read
    mov     dword ptr [g_keep_key], 0
    test    eax, eax
    jnz     dd_ret_code
    cmp     qword ptr [g_poscount], 2
    jb      dd_usage
    ; ---- mark what is to go -------------------------------------------------
    ; Marked, not removed: which of the two removal paths runs depends on the
    ; container's size, and both need to know what was chosen.
    mov     qword ptr [rbp-48], 1
dd_arg:
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [g_poscount]
    jae     dd_marked
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    mov     qword ptr [rbp-80], rcx
    WINCALL WideCharToMultiByte, 65001, 0, qword ptr [rbp-80], -1, addr g_delname, 4000, 0, 0
    test    eax, eax
    jle     dd_notfound
    dec     eax                                 ; drop the terminator
    cdqe
    lea     rcx, [g_delname]
    mov     rdx, rax
    call    idx_mark_dropped                    ; a directory takes its contents
    test    rax, rax
    jz      dd_notfound
dd_next:
    inc     qword ptr [rbp-48]
    jmp     dd_arg
dd_notfound:
    prn     e_del_nf
    mov     rcx, qword ptr [rbp-80]
    call    print_wz
    prn     msg_lst_nl
    jmp     dd_next
dd_marked:
    call    do_remove_marked
    jmp     dd_ret_code
dd_usage:
    prn     e_del_usage
    mov     eax, EXIT_USAGE
    jmp     dd_wipekey
dd_io:
    prn     e_pio
    mov     eax, EXIT_IO
dd_wipekey:
    mov     dword ptr [rbp-72], eax
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
    mov     rcx, qword ptr [rbp-16]
    call    file_close
    mov     eax, dword ptr [rbp-72]
dd_ret_code:
    FRAME_EPILOG
    ret
do_delete endp

; =============================================================================
; idx_dup_since(rcx = the listing's length before this add)
;   -> rax = cursor of the first entry added since that point whose name an
;      OLDER entry already used, or -1 when every added name is new.
;
; New-against-old only.  The entries one walk adds cannot collide with each
; other - a tree walk visits each path once - so this is new x old rather than
; the square of the whole listing.
; =============================================================================
idx_dup_since proc frame
    FRAME_PROLOG 64
    ; [rbp-16]=idxlen0 [rbp-24]=new cursor [rbp-32]=old cursor
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rcx
ids_new:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_idxlen]
    jae     ids_none
    mov     r10, qword ptr [g_idxptr]
    add     r10, rax                            ; -> the added entry
    mov     r8d, dword ptr [r10+IDXE_namelen]
    mov     qword ptr [rbp-32], 0
ids_old:
    mov     rdx, qword ptr [rbp-32]
    cmp     rdx, qword ptr [rbp-16]
    jae     ids_nextnew
    mov     r11, qword ptr [g_idxptr]
    add     r11, rdx                            ; -> an entry already there
    mov     r9d, dword ptr [r11+IDXE_namelen]
    cmp     r9d, r8d
    jne     ids_nextold                         ; different length, different name
    xor     r9, r9                              ; r9 becomes the byte cursor
ids_cmp:
    cmp     r9d, r8d
    jae     ids_hit                             ; every byte matched
    mov     al, byte ptr [r10+IDXE_name+r9]
    cmp     al, byte ptr [r11+IDXE_name+r9]
    jne     ids_nextold
    inc     r9
    jmp     ids_cmp
ids_nextold:
    mov     r11, qword ptr [g_idxptr]
    add     r11, qword ptr [rbp-32]
    mov     eax, dword ptr [r11+IDXE_namelen]
    add     rax, IDXE_FIXED
    add     qword ptr [rbp-32], rax
    jmp     ids_old
ids_nextnew:
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+IDXE_namelen]
    add     rax, IDXE_FIXED
    add     qword ptr [rbp-24], rax
    jmp     ids_new
ids_hit:
    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
ids_none:
    mov     rax, -1
    FRAME_EPILOG
    ret
idx_dup_since endp

; =============================================================================
; do_add -> eax exit code.  Append positionals[1..] to the container named by
; positionals[0], in place.
;
; This is what format v6 exists for.  Every added entry is sealed with an
; ordinal taken from g_entnext, which idx_read restored from the trailer's
; AUTHENTICATED counter - never from the entry count and never from one past the
; highest survivor, either of which would hand out an ordinal a deleted entry
; already spent under this same key.  That is GCM nonce reuse, and it is the one
; mistake in this format that cannot be recovered from.
;
; The new entries are written AFTER the old trailer rather than over the old
; index.  That costs the old inventory's bytes as dead space in the middle of
; the file - never referenced, because extraction is extent-driven - and it buys
; a clean abort: nothing at or below the original length is touched, so any
; refusal truncates back and leaves the container byte for byte what it was.
; Writing over the index instead would mean a REFUSED add had already destroyed
; the listing, which is a poor trade for a few hundred bytes.
;
; A crash mid-write is still fatal to the listing: once the file has grown past
; the old trailer there is no valid trailer at its end until the new one lands.
; That is a property of editing in place - do_remove_marked has it too - not
; something appending introduced.
;
; Compression follows the CONTAINER, not the current setting.  The reader takes
; store-versus-xpress from header byte 18 for the whole file, so an entry added
; in the other mode would decode to nothing.
;
; locals (frame 128): hout[-16] size0[-24] idxlen0[-32] argi[-40] code[-48]
;   dup[-56]
; =============================================================================
public do_add
do_add proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], INVALID
    ; A volume set cannot be edited.  Checked BEFORE the password is asked for:
    ; the refusal does not depend on knowing the key, and making someone type a
    ; password to be told no is its own small insult.  The path has to be
    ; normalized first - idx_read is what usually does that, and it has not run.
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_pk_np]
    call    normalize_path
    test    eax, eax
    jnz     da_io
    lea     rcx, [g_pk_np]
    call    vol_is_set
    test    eax, eax
    jnz     da_isset
    ; The inventory, which is also the password check, the key, and - the part
    ; this proc cannot do without - g_entnext.
    mov     dword ptr [g_keep_key], 1
    call    idx_read
    mov     dword ptr [g_keep_key], 0
    test    eax, eax
    jnz     da_ret_code
    cmp     qword ptr [g_poscount], 2
    jb      da_usage
    lea     rcx, [g_pk_np]
    call    file_open_rw
    cmp     rax, INVALID
    je      da_io
    mov     qword ptr [rbp-16], rax
    mov     rcx, rax
    lea     rdx, [rbp-24]
    call    get_file_size
    test    eax, eax
    jnz     da_io
    ; where the listing ended before this add, so the duplicate scan can tell
    ; the added entries from the ones already there
    mov     rax, qword ptr [g_idxlen]
    mov     qword ptr [rbp-32], rax
    ; ---- point the packing globals at the end of the file -------------------
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [g_sink_hout], rax
    mov     qword ptr [g_sinkfill], 0
    mov     qword ptr [g_rawfill], 0
    mov     qword ptr [g_packerr], 0
    mov     rax, qword ptr [rbp-24]
    sub     rax, HDR_BYTES
    mov     qword ptr [g_payoff], rax        ; extents are relative to HDR_BYTES
    movzx   eax, byte ptr [g_pkhdr+CONTAINER_HDR.compressed]
    mov     qword ptr [g_compress], rax
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    call    file_seek
    test    eax, eax
    jnz     da_io
    cmp     qword ptr [g_compress], 0
    je      da_nocomp
    call    comp_init
    test    eax, eax
    jz      da_nocomp                        ; 0 is success, as in do_pack
    mov     qword ptr [g_packerr], EXIT_IO
    jmp     da_packerr
da_nocomp:
    ; ---- progress: total the inputs being ADDED, not the archive ------------
    ; positionals[0] is the archive and is not being read, so sum_inputs (which
    ; walks the whole array) would inflate the total by the archive's own size
    ; and leave the bar short of the end.
    mov     qword ptr [rbp-64], 0
    mov     qword ptr [g_biggest], 0         ; the walk below tracks the largest
                                             ; single file, for the per-entry
                                             ; ceiling check at da_sumd
    mov     qword ptr [rbp-40], 1
da_sum:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_poscount]
    jae     da_sumd
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    call    input_size
    add     qword ptr [rbp-64], rax
    inc     qword ptr [rbp-40]
    jmp     da_sum
da_sumd:
    ; ---- the per-entry ceiling, which ADD never checked ---------------------
    ; do_pack has refused an oversized single file since the beginning; an add
    ; of the same file sailed straight past and wrote one GCM stream over the
    ; counter wrap - the keystream-reuse failure everything else here exists to
    ; prevent.  Present since v4 made entries the streams; found in the 1.0.83
    ; audit of the segment-default flip.
    ;
    ; Judged per the HEADER, not per this build: an add to a segmented container
    ; rolls at SEG_BYTES and has no per-entry bound; an add to a pre-segment
    ; container must fit one stream.  Nothing is open or written yet, so the
    ; no-rollback exit is the right one - same reasoning as da_isset.
    lea     rcx, [g_pkhdr]
    call    seg_bytes_from_hdr              ; -1 impossible: idx_read refused it
    test    rax, rax
    jnz     da_size_ok
    mov     rax, qword ptr [g_biggest]
    CHECK_ADD_OVF rax, PACK_ENTRY_OVERHEAD
    mov     r10, MAX_PLAINTEXT_SIZE
    cmp     rax, r10
    jbe     da_size_ok
    prn     e_ptoobig
    prn     e_atoobig2
    mov     eax, EXIT_USAGE
    jmp     da_close
da_size_ok:
    mov     rcx, qword ptr [rbp-64]
    lea     rdx, [lbl_pack]
    mov     r8d, lbl_pack_len
    call    progress_begin
    ; ---- walk the new inputs, exactly as do_pack walks its own --------------
    mov     qword ptr [rbp-40], 1            ; [0] is the container itself
da_inloop:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_poscount]
    jae     da_walked
    mov     qword ptr [g_cur_input], rax
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+rax*8]
    call    pack_input_top
    cmp     qword ptr [g_packerr], 0
    jne     da_packerr
    ; Cancel is checked BETWEEN inputs, where the rollback below still puts the
    ; file back exactly.  Checking mid-entry would abandon a half-written one
    ; past the old trailer, which the truncate would still clean up - but the
    ; entry boundary is where the accounting is simplest to be sure about.
    cmp     dword ptr [g_prog_abort], 0
    jne     da_cancelled
    inc     qword ptr [rbp-40]
    jmp     da_inloop
da_walked:
    cmp     qword ptr [g_compress], 0
    je      da_dupscan
    call    comp_close
    cmp     qword ptr [g_packerr], 0
    jne     da_packerr
da_dupscan:
    ; Refused rather than allowed: two entries under one name extract as
    ; whichever is written second, which is a silent wrong answer.  Nothing is
    ; committed yet, so the rollback below puts the file back untouched.
    mov     rcx, qword ptr [rbp-32]
    call    idx_dup_since
    cmp     rax, -1
    jne     da_dupname
    ; ---- commit: a fresh revision, then the new listing ---------------------
    ; The revision is what gives the rewritten index its own nonce.  Encrypting
    ; a changed index under the nonce the old one used would be catastrophic.
    ; Nothing is committed yet, so an exhausted counter rolls back like any
    ; other refusal and the container is left exactly as it was.
    call    idx_rev_bump
    test    eax, eax
    jnz     da_revfull
    mov     rcx, qword ptr [rbp-16]
    call    idx_write
    test    eax, eax
    jnz     da_io
    call    progress_done
    prn_a   msg_add_ok
    xor     eax, eax
    jmp     da_close
da_revfull:
    prn     e_idx_revfull
    mov     eax, EXIT_UNSUPPORTED
    jmp     da_rollback
da_dupname:
    mov     qword ptr [rbp-56], rax
    prn     e_add_dup
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-56]
    mov     edx, dword ptr [r10+IDXE_namelen]
    lea     rcx, [r10+IDXE_name]
    call    print_a
    lea     rcx, [msg_nl]
    mov     edx, 2
    call    print_a
    mov     eax, EXIT_USAGE
    jmp     da_rollback
da_cancelled:
    call    progress_done
    mov     eax, EXIT_CANCELLED
    jmp     da_rollback
da_packerr:
    call    progress_done
    mov     eax, dword ptr [g_packerr]
    cmp     eax, EXIT_CORRUPT               ; name-too-long already reported
    je      da_rollback
    prn     e_pio
    mov     eax, EXIT_IO
    jmp     da_rollback
da_io:
    prn     e_pio
    mov     eax, EXIT_IO
    jmp     da_rollback
da_usage:
    prn     e_add_usage
    mov     eax, EXIT_USAGE
    jmp     da_close
da_isset:
    ; Straight to da_close, not da_rollback: nothing has been opened or written,
    ; and the rollback path would truncate a file it never touched.
    prn     e_vol_edit
    mov     eax, EXIT_UNSUPPORTED
    jmp     da_close
da_rollback:
    ; Nothing at or below the original length was written, so putting the length
    ; back restores the container exactly.  This is the whole reason the new
    ; entries went after the old trailer instead of over the old index.
    mov     dword ptr [rbp-48], eax
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    call    file_truncate
    mov     eax, dword ptr [rbp-48]
da_close:
    mov     dword ptr [rbp-48], eax
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
    mov     rcx, qword ptr [rbp-16]
    call    file_close
    mov     eax, dword ptr [rbp-48]
da_ret_code:
    FRAME_EPILOG
    ret
do_add endp

; =============================================================================
; do_remove_marked -> eax exit code.  Remove the marked entries: overwrite them
; where they lie, then close the gap they leave.
;
; Two steps, both cheap, and neither of them touches the crypto of what survives:
;
;   OVERWRITE with random.  This is what makes the removal unrecoverable, and it
;   is why the entry is not simply dropped from the index and forgotten.  RANDOM,
;   never zeros - a run of zeros advertises exactly where something used to be
;   and how big it was, where random is indistinguishable from the ciphertext
;   around it.
;
;   COMPACT.  An entry's tag does not depend on where it sits: the nonce comes
;   from its recorded ordinal, the AAD is header || ordinal, and the offset
;   appears nowhere in the tag.  So the survivors' ciphertext is MOVED down over
;   the hole and their extents updated - a byte copy, no decryption, no
;   re-encryption, no fresh key.
;
; The move is front to back and every destination is at or below its source, so
; a forward copy can never overwrite bytes it has not read yet.  An index whose
; offsets are not ascending would break that, so it is checked rather than
; assumed.
;
; Only the index is re-encrypted, and it consumes exactly one counter: the next
; revision.  Re-encrypting a changed index under the nonce the old one used would
; be catastrophic, which is why the revision lives in the trailer.
;
; locals (frame 160): handle[-16] size[-24] idxoff[-32] cursor[-40] left[-48]
;   remaining[-56] chunk[-64] code[-72] next[-80] newoff[-88] src[-96] dst[-104]
; =============================================================================
public do_remove_marked
do_remove_marked proc frame
    FRAME_PROLOG 224
    mov     qword ptr [rbp-16], INVALID
    ; ---- claim the revision UP FRONT, before anything is destroyed ----------
    ; This operation ends by rewriting the index, so it needs a fresh revision -
    ; but unlike an add it has already overwritten the dropped entries with
    ; random and slid the survivors down by the time it gets there. Refusing at
    ; that point would leave a container whose payload has been rewritten and
    ; whose index has not, which is worse than either outcome the check exists
    ; to choose between. So it is claimed here, where refusing costs nothing.
    ;
    ; Claiming one and then failing is harmless: a skipped revision is a nonce
    ; never used, and g_idxrev is re-read from the trailer next time the
    ; container is opened. Only REUSE is unsafe, and this errs the other way.
    ; And a set cannot be deleted from either, for the same reason and with more
    ; at stake: this path overwrites entries in place.  g_pk_np is already
    ; normalized here - idx_read ran before the GUI marked anything.
    lea     rcx, [g_pk_np]
    call    vol_is_set
    test    eax, eax
    jnz     dw_isset
    call    idx_rev_bump
    test    eax, eax
    jnz     dw_revfull
    lea     rcx, [g_pk_np]
    call    file_open_rw
    cmp     rax, INVALID
    je      dw_io
    mov     qword ptr [rbp-16], rax
    mov     rcx, rax
    lea     rdx, [rbp-24]
    call    get_file_size
    test    eax, eax
    jnz     dw_io
    ; ---- what this operation will actually write ----------------------------
    ; Every dropped entry is overwritten, and every survivor AFTER the first
    ; dropped one slides down over the hole.  A survivor BEFORE it does not
    ; move at all - its destination equals its source and the compact pass
    ; skips it - so summing every entry would over-report and leave the bar
    ; stalled short of the end.
    ;
    ; Entries are in ascending offset order (the compact pass depends on it and
    ; checks it), so "after the first dropped one" is just "seen a dropped one
    ; already" in cursor order.
    ; [rbp-112]=total [rbp-120]=seen a drop [rbp-128]=cursor [rbp-136]=left
    mov     qword ptr [rbp-112], 0
    mov     qword ptr [rbp-120], 0
    mov     qword ptr [rbp-128], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-136], rax
dw_tot:
    cmp     qword ptr [rbp-136], 0
    je      dw_totd
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-128]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    mov     rax, qword ptr [r10+IDXE_stored]
    mov     r9d, dword ptr [r10+IDXE_flags]
    test    r9d, IDXEF_DROPPED
    jz      dw_tot_keep
    add     qword ptr [rbp-112], rax         ; it gets overwritten
    mov     qword ptr [rbp-120], 1
    jmp     dw_tot_step
dw_tot_keep:
    cmp     qword ptr [rbp-120], 0
    je      dw_tot_step                      ; sits before the first hole: stays put
    add     qword ptr [rbp-112], rax         ; it slides down
dw_tot_step:
    mov     rax, qword ptr [rbp-128]
    add     rax, IDXE_FIXED
    add     rax, r11
    mov     qword ptr [rbp-128], rax
    dec     qword ptr [rbp-136]
    jmp     dw_tot
dw_totd:
    mov     rcx, qword ptr [rbp-112]
    lea     rdx, [lbl_pack]
    mov     r8d, lbl_pack_len
    call    progress_begin
    ; ---- step one: random over every marked entry ---------------------------
    mov     qword ptr [rbp-40], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-48], rax
dw_entry:
    cmp     qword ptr [rbp-48], 0
    je      dw_move
    mov     rax, qword ptr [rbp-40]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      dw_corrupt
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-40]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      dw_corrupt
    mov     qword ptr [rbp-80], rax
    mov     eax, dword ptr [r10+IDXE_flags]
    test    eax, IDXEF_DROPPED
    jz      dw_step
    mov     rax, qword ptr [r10+IDXE_stored]
    mov     qword ptr [rbp-56], rax
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [r10+IDXE_offset]
    add     rdx, HDR_BYTES
    call    file_seek
    test    eax, eax
    jnz     dw_io
dw_wipe:
    cmp     qword ptr [rbp-56], 0
    je      dw_step
    mov     r8, qword ptr [rbp-56]
    cmp     r8, CHUNK
    jbe     dw_wsz
    mov     r8, CHUNK
dw_wsz:
    mov     qword ptr [rbp-64], r8
    lea     rcx, [g_filebuf]
    mov     edx, dword ptr [rbp-64]
    call    rng_fill
    test    eax, eax
    jz      dw_io
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [g_filebuf]
    mov     r8, qword ptr [rbp-64]
    call    file_write_all
    test    eax, eax
    jnz     dw_io
    mov     rcx, qword ptr [rbp-64]
    call    progress_add
    mov     rax, qword ptr [rbp-64]
    sub     qword ptr [rbp-56], rax
    jmp     dw_wipe
dw_step:
    mov     rax, qword ptr [rbp-80]
    mov     qword ptr [rbp-40], rax
    dec     qword ptr [rbp-48]
    jmp     dw_entry
; ---- step two: slide the survivors down over the holes ----------------------
dw_move:
    mov     qword ptr [rbp-88], 0               ; where the next survivor goes
    mov     qword ptr [rbp-40], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-48], rax
dw_m_next:
    cmp     qword ptr [rbp-48], 0
    je      dw_compact
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-40]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    mov     rax, qword ptr [rbp-40]
    add     rax, IDXE_FIXED
    add     rax, r11
    mov     qword ptr [rbp-80], rax
    mov     eax, dword ptr [r10+IDXE_flags]
    test    eax, IDXEF_DROPPED
    jnz     dw_m_step                           ; its space is what we are closing
    mov     rax, qword ptr [r10+IDXE_offset]
    mov     qword ptr [rbp-96], rax
    mov     rax, qword ptr [r10+IDXE_stored]
    mov     qword ptr [rbp-56], rax
    mov     rax, qword ptr [rbp-88]
    cmp     rax, qword ptr [rbp-96]
    ja      dw_corrupt                          ; not ascending: refuse to guess
    je      dw_m_place                          ; already where it belongs
    ; move it down
    mov     rax, qword ptr [rbp-96]
    add     rax, HDR_BYTES
    mov     qword ptr [rbp-96], rax             ; source, absolute
    mov     rax, qword ptr [rbp-88]
    add     rax, HDR_BYTES
    mov     qword ptr [rbp-104], rax            ; destination, absolute
dw_m_chunk:
    cmp     qword ptr [rbp-56], 0
    je      dw_m_place
    mov     r8, qword ptr [rbp-56]
    cmp     r8, CHUNK
    jbe     dw_m_sz
    mov     r8, CHUNK
dw_m_sz:
    mov     qword ptr [rbp-64], r8
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-96]
    lea     r8, [g_filebuf]
    mov     r9, qword ptr [rbp-64]
    call    file_read_at
    test    eax, eax
    jnz     dw_io
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-104]
    call    file_seek
    test    eax, eax
    jnz     dw_io
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [g_filebuf]
    mov     r8, qword ptr [rbp-64]
    call    file_write_all
    test    eax, eax
    jnz     dw_io
    mov     rcx, qword ptr [rbp-64]
    call    progress_add
    mov     rax, qword ptr [rbp-64]
    add     qword ptr [rbp-96], rax
    add     qword ptr [rbp-104], rax
    sub     qword ptr [rbp-56], rax
    jmp     dw_m_chunk
dw_m_place:
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-88]
    mov     qword ptr [r10+IDXE_offset], rax    ; the extent is the only thing
    mov     rax, qword ptr [r10+IDXE_stored]    ; a move changes
    add     qword ptr [rbp-88], rax
dw_m_step:
    mov     rax, qword ptr [rbp-80]
    mov     qword ptr [rbp-40], rax
    dec     qword ptr [rbp-48]
    jmp     dw_m_next
; ---- take the marked entries out of the table ------------------------------
dw_compact:
    mov     qword ptr [rbp-40], 0
dw_c_next:
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_idxlen]
    jae     dw_rewrite
    mov     r10, qword ptr [g_idxptr]
    add     r10, rax
    mov     r11d, dword ptr [r10+IDXE_namelen]
    mov     eax, dword ptr [r10+IDXE_flags]
    test    eax, IDXEF_DROPPED
    jnz     dw_c_drop
    mov     rax, qword ptr [rbp-40]
    add     rax, IDXE_FIXED
    add     rax, r11
    mov     qword ptr [rbp-40], rax
    jmp     dw_c_next
dw_c_drop:
    mov     rcx, qword ptr [rbp-40]
    call    idx_drop                            ; leaves the cursor where it is
    jmp     dw_c_next
; ---- the inventory goes where the payload now ends -------------------------
dw_rewrite:
    mov     rax, qword ptr [rbp-88]
    add     rax, HDR_BYTES
    mov     qword ptr [rbp-32], rax
    ; the revision was claimed at the top of this proc, before the overwrite
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-32]
    call    file_seek
    test    eax, eax
    jnz     dw_io
    mov     rcx, qword ptr [rbp-16]
    call    idx_write
    test    eax, eax
    jnz     dw_io
    mov     rax, qword ptr [rbp-32]
    add     rax, qword ptr [g_idxlen]
    add     rax, IDX_TAIL_FIXED
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, rax
    call    file_truncate
    test    eax, eax
    jnz     dw_io
    call    progress_done
    prn_a   msg_del_moved
    xor     eax, eax
    jmp     dw_close
dw_corrupt:
    call    progress_done
    prn     e_pcorrupt
    mov     eax, EXIT_CORRUPT
    jmp     dw_close
dw_io:
    call    progress_done
    prn     e_pio
    mov     eax, EXIT_IO
    jmp     dw_close
dw_isset:
    prn     e_vol_edit
    mov     eax, EXIT_UNSUPPORTED
    jmp     dw_close
dw_revfull:
    prn     e_idx_revfull
    mov     eax, EXIT_UNSUPPORTED
dw_close:
    mov     dword ptr [rbp-72], eax
    lea     rcx, [g_key]
    mov     rdx, 32
    call    secure_zero
    mov     rcx, qword ptr [rbp-16]
    call    file_close
    mov     eax, dword ptr [rbp-72]
    FRAME_EPILOG
    ret
do_remove_marked endp

; =============================================================================
; do_list -> eax exit code.  Print the inventory of a container.
; =============================================================================
public do_list
; =============================================================================
; lst_flush - hand do_list's buffer to stdout and empty it.
; =============================================================================
lst_flush proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_lstfill], 0
    je      lf_ret
    lea     rcx, [g_lstbuf]
    mov     edx, dword ptr [g_lstfill]
    mov     qword ptr [g_lstfill], 0    ; before the call, not after: print_a
                                        ; cannot recurse here, but a half-written
                                        ; flag is the kind of thing that later
                                        ; becomes true
    call    print_a
lf_ret:
    FRAME_EPILOG
    ret
lst_flush endp

; =============================================================================
; lst_add(rcx = bytes, rdx = length) - append to do_list's line buffer.
;
; A listing is five fragments an entry - the size prefix, the digits, the
; separator, the name, the newline - and every print_* is one unbuffered
; WriteFile.  At 500,000 entries that was 2.5 MILLION SYSCALLS and 8.5 minutes,
; against 2.6 seconds for `verify` to decrypt and authenticate the same index:
; the listing was not paying for the index, it was paying for the syscalls.
;
; Buffered HERE rather than inside write_handle, which would be the larger win
; and a much worse risk: stdout would have to be flushed before every stderr
; write or the two interleave differently and everything that reads combined
; output starts lying, the action-log tee would have to keep seeing every
; fragment in order, and NINE ExitProcess sites would each need a flush - where
; missing one silently truncates a command's output.  This buffer is emptied by
; the one proc that fills it, on every path out of it.
;
; An oversized fragment bypasses the buffer instead of overflowing it: names come
; out of a container, and although the index is authenticated, a future version
; could record one longer than this whole buffer.
; locals: [rbp-16] src  [rbp-24] len
; =============================================================================
lst_add proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    test    rdx, rdx
    jz      la_ret
    cmp     rdx, LST_BUF_BYTES
    jb      la_fits
    call    lst_flush                   ; keep the order, then write it straight
    mov     rcx, qword ptr [rbp-16]
    mov     edx, dword ptr [rbp-24]
    call    print_a
    jmp     la_ret
la_fits:
    mov     rax, qword ptr [g_lstfill]
    add     rax, qword ptr [rbp-24]
    cmp     rax, LST_BUF_BYTES
    jbe     la_room
    call    lst_flush
la_room:
    lea     r10, [g_lstbuf]
    add     r10, qword ptr [g_lstfill]
    mov     r11, qword ptr [rbp-16]
    mov     rcx, qword ptr [rbp-24]
    xor     r9, r9
la_copy:
    cmp     r9, rcx
    jae     la_done
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], al
    inc     r9
    jmp     la_copy
la_done:
    mov     rax, qword ptr [rbp-24]
    add     qword ptr [g_lstfill], rax
la_ret:
    FRAME_EPILOG
    ret
lst_add endp

lsta macro msg
    lea     rcx, [msg]
    mov     rdx, msg&_len
    call    lst_add
endm

do_list proc frame
    FRAME_PROLOG 64
    mov     qword ptr [g_lstfill], 0
    ; [rbp-24]=cursor into g_idxbuf [rbp-32]=entries left
    call    idx_read
    test    eax, eax
    jnz     dl_ret
    prn_a   msg_lst_hdr
    cmp     qword ptr [g_idxcount], 0
    jne     dl_walk
    prn_a   msg_lst_none
    xor     eax, eax
    jmp     dl_ret
dl_walk:
    mov     qword ptr [rbp-24], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-32], rax
dl_next:
    cmp     qword ptr [rbp-32], 0
    je      dl_end
    ; every read below is bounds-checked against g_idxlen: the entry table came
    ; out of a file, and although its tag has been verified, a container written
    ; by a future version could still describe an entry that runs off the end
    mov     rax, qword ptr [rbp-24]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      dl_end
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    mov     rax, qword ptr [rbp-24]
    add     rax, IDXE_FIXED
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      dl_end
    mov     qword ptr [rbp-40], rax          ; cursor for the next entry
    ; "  <dir>  name" or "  <size>  name"
    mov     eax, dword ptr [r10+IDXE_flags]
    test    eax, IDXEF_DIR
    jz      dl_size
    lsta    msg_lst_dir
    jmp     dl_name
dl_size:
    lsta    msg_lst_pre
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [r10+IDXE_size]
    lea     rdx, [g_lstnum]
    call    fmt_u64                     ; the digits into a buffer, not to a handle
    lea     rcx, [g_lstnum]
    mov     edx, eax
    call    lst_add
    lsta    msg_lst_sep
dl_name:
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    lea     rcx, [r10+IDXE_name]
    mov     edx, dword ptr [r10+IDXE_namelen]
    call    lst_add
    lsta    msg_lst_nl
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rbp-24], rax
    dec     qword ptr [rbp-32]
    jmp     dl_next
dl_end:
    ; The buffer is emptied HERE, and this is the only place it needs to be:
    ; every path that reaches the loop leaves through dl_end, and the two that
    ; return earlier - idx_read failing, and a container with no entries - do so
    ; before a single byte has been put in it.  do_list zeroes g_lstfill on the
    ; way in, so neither can leak a previous run's tail either.
    call    lst_flush
    test    qword ptr [g_idxflags], IDXF_TRUNCATED
    jz      dl_ok
    prn_a   msg_lst_trunc
dl_ok:
    xor     eax, eax
dl_ret:
    FRAME_EPILOG
    ret
do_list endp

end
