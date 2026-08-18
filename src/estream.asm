; =============================================================================
; estream.asm - an IStream over ONE entry of a Myrkr container.
; -----------------------------------------------------------------------------
; Step 1 of docs/DRAG_OUT.md.  Dragging entries OUT of the container view uses
; the virtual-file protocol (CFSTR_FILEDESCRIPTORW + CFSTR_FILECONTENTS), and
; the target asks for each file's contents as an IStream.  Nothing is written
; to disk until something asks, and a cancelled drag writes nothing at all -
; which is the whole reason for not handing over CF_HDROP from a temp folder.
;
; THE OBJECT IS PER-INSTANCE, DELIBERATELY.  Extraction elsewhere in this tree
; runs through globals - g_pkctx, g_filebuf, g_pktag - which is one stream at a
; time by construction, because nothing has ever needed two.  The shell is free
; to hold several open at once, and with multi-selection it very likely will.
; So each object carries its OWN GCM context, its own read buffer, its own file
; handle and its own decompressor; gcm_init already takes its context by
; pointer, so a context is relocatable and this costs one allocation and
; nothing else.  It also settles the threading question: a stream that owns
; everything it touches shares nothing with the container view it came from.
;
; The one thing still shared is CONSTRUCTION: entry_stream_open writes the
; scratch globals g_idxnonce and g_entaad on its way into gcm_init/gcm_aad.  So
; es_create must be called from ONE thread at a time - which it is, because the
; data object below lives in an STA and COM serialises calls onto its owning
; thread.  That is load-bearing rather than incidental: anything that makes
; these objects free-threaded has to give entry_stream_open its own scratch
; first.  Reading is free of all of it.
;
; AND THE KEY MUST BE LIVE WHEN es_create RUNS.  idx_read WIPES g_key on its way
; out unless the caller sets g_keep_key first - it derived the key for one
; listing and does not assume anyone wants it afterwards.  Without that, every
; stream decrypts under a key of zeros: the plaintext is garbage, the tag fails,
; and the only symptom is a Read that returns E_FAIL, which reads exactly like a
; corrupted container.  Cost a debugging round here, so it is written down.
;
; The requirement stops at construction: gcm_init expands the round keys INTO
; the context, so once every stream is built the global key can be wiped and the
; only copies left are inside the objects - wiped in turn by tagged_free.  That
; is a better place for key material to live than a process-wide global, and it
; is what the drag should do when step 3 wires this up.
;
; WHAT AN ENTRY ACTUALLY HOLDS, which decides everything below:
;
;   ciphertext = GCM(entry i, nonce = i+1, AAD = header || i) || 16-byte tag
;   plaintext  = [512-byte tar header] content [zero pad to a 512 boundary]
;
; - the tar header is present only when the container is an archive (header
;   byte 17); a bare single-file container's entry plaintext IS the file.
; - when the container is compressed (header byte 18), that plaintext is not
;   the tar stream but compress.asm's framing of it:
;   [u32 orig][u32 payload][payload], payload < orig meaning XPRESS.  entry_end
;   flushes the compressor per entry, so an entry's frames are self-contained.
;
; So there are three layers, not one - decrypt, then de-frame, then skip the
; tar header and stop at the recorded size - and the content ENDS BEFORE THE
; ENTRY DOES.  That matters more than it looks: GCM's tag only clears once
; every ciphertext byte has passed through it, so a reader that stops at the
; last content byte never authenticates anything.  ES_Read therefore drains the
; padding and verifies the tag on the read that consumes the final byte, and
; fails THAT read if the tag is wrong.  A copy that completed is a copy that
; was authenticated.  (Bytes already handed over cannot be unsaid; failing the
; last read is what makes Explorer abandon and delete the partial file.)
;
; Shape of the COM plumbing follows the IDropTarget in gui.asm, which follows
; shellext.asm.  Its "no FRAME_PROLOG" rule is for the DLL loaded into
; Explorer; this lives in the exe, which has the canary and the shadow stack.
;
; The IDataObject that hands these streams to a drop target is further down the
; same file - step 2, and the reason the key above became a parameter.
;
; This SHIPS.  It was gated under TEST_IO while nothing but the exercisers
; called it - a release binary should not carry unwired COM objects with vtables
; in them - and step 3 of DRAG_OUT.md (IDropSource + LVN_BEGINDRAG) removed the
; gate: gui.asm calls es_drag from the list's LVN_BEGINDRAG.
;
; What is still under TEST_IO is only the exercisers at the bottom of this file
; (the largest span by far) plus the zip_to_index they need.  Read an ifdef here
; as "the harness", not "unfinished".
; =============================================================================

include macros.inc


extern gcm_crypt:proc
extern gcm_final:proc
extern ct_memcmp:proc
extern entry_stream_open:proc
extern seg_bytes_from_hdr:proc   ; pack.asm: the only place a shift becomes bytes
extern idx_read:proc
extern normalize_path:proc
extern tagged_alloc:proc
extern tagged_free:proc
extern mem_free:proc
extern zip_entry_to_mem:proc
ifdef TEST_IO
extern zip_to_index:proc
endif
extern file_open_read:proc
extern file_open_write:proc
extern file_read_at:proc
extern vset_open:proc                    ; volume.asm: a container may be a set
extern vset_close:proc
extern vol_get:proc
extern progress_begin:proc               ; the window's bar drives a drag-out
extern progress_add:proc
extern progress_done:proc
extern drag_rows_mark:proc
extern drag_prog_show:proc
extern drag_prog_tick:proc
extern InvalidateRect:proc
externdef g_hwnd:qword
externdef g_hprog:qword
externdef g_drag_prog:dword
externdef g_prog_total:qword
externdef g_prog_done:qword
externdef g_prog_pct:dword
externdef g_cur_input:qword
externdef g_file_total:qword
externdef g_file_done:qword
extern file_write_all:proc
extern file_close:proc
extern print_a:proc
extern print_err:proc
extern print_u64:proc
extern print_wz:proc
extern secure_zero:proc
; The decompressor is created PER CONTEXT rather than through a shared handle in
; a global, which is how compress.asm's writing half still works.  Same reason as
; the GCM context: two streams open at once must not share it.  (compress.asm's
; DECOMPRESSING half no longer exists - this was its last competitor, and when
; extraction started coming through here it became its only caller too.)
extern CreateDecompressor:proc
extern Decompress:proc
extern CloseDecompressor:proc
extern RegisterClipboardFormatW:proc
extern GlobalAlloc:proc
extern GlobalFree:proc
extern GlobalLock:proc
extern GlobalUnlock:proc
extern MultiByteToWideChar:proc
extern WideCharToMultiByte:proc
extern DoDragDrop:proc
extern compute_kcv:proc

externdef g_key:byte
externdef g_pkhdr:byte
externdef g_idxptr:qword
externdef g_idxlen:qword
externdef g_idxcount:qword
externdef g_cfg_in:qword
externdef g_cfg_out:qword
externdef g_positionals:qword
externdef g_poscount:qword
externdef g_keep_key:dword

COMPRESS_ALGORITHM_XPRESS equ 3
CBLOCK          equ 100000h     ; 1 MiB compression block (mirrors pack.asm)
GCTX_SIZE       equ 336
INVALID         equ -1
CP_UTF8         equ 65001

S_OK                    equ 0
E_NOTIMPL               equ 80004001h
E_NOINTERFACE           equ 80004002h
E_FAIL                  equ 80004005h
E_INVALIDARG            equ 80070057h
STG_E_INVALIDFUNCTION   equ 80030001h
STG_E_ACCESSDENIED      equ 80030005h
STG_E_INVALIDPOINTER    equ 80030009h
STGTY_STREAM            equ 2

; STATSTG - 80 bytes.  Every field is 8-aligned, so cbSize is at 16 and not at
; 12: the same trap FORMATETC set for the drop target.  Prefixed SSTG_ and not
; STG_, because gui.asm already has an STG_BYTES and it is a different struct.
SSTG_type               equ 8
SSTG_cbSize             equ 16
SSTG_grfMode            equ 48
SSTG_BYTES              equ 80

; -----------------------------------------------------------------------------
; The object.
;
; ES_RAW is the post-GCM, pre-decompression buffer.  It is sized at
; MAX_PATH_CHARS*2 rather than at some round number because es_create borrows it
; ONCE, before any ciphertext is read, as normalize_path's destination - which
; needs exactly that many bytes.  The two must not drift apart.  It is also a
; multiple of 16, which gcm_crypt requires of every call but the last.
; -----------------------------------------------------------------------------
ES_vtbl         equ 0           ; dq  vtable pointer (must be first)
ES_refs         equ 8           ; dd  reference count
ES_flags        equ 12          ; dd  ESF_*
ES_hfile        equ 16          ; dq  this stream's own handle on the container
ES_hdec         equ 24          ; dq  this stream's own decompressor (or 0)
ES_ctoff        equ 32          ; dq  absolute offset of the next ciphertext byte
ES_ctleft       equ 40          ; dq  ciphertext bytes not yet read (tag excluded)
ES_size         equ 48          ; dq  the entry's content size, from the index
ES_left         equ 56          ; dq  content bytes not yet delivered
ES_pos          equ 64          ; dq  content bytes delivered so far
ES_skip         equ 72          ; dq  plaintext bytes still to discard (tar header)
ES_rawlen       equ 80          ; dq  valid bytes in ES_RAW
ES_rawpos       equ 88          ; dq  next byte to consume in ES_RAW
ES_outlen       equ 96          ; dq  valid bytes in ES_OUT
ES_outpos       equ 104         ; dq  next byte to consume in ES_OUT
ES_tag          equ 112         ; 16  computed tag
ES_tag2         equ 128         ; 16  stored tag
; WHY the stream failed, not just that it did.  ESF_ERR is one bit and every
; caller inside this file only ever needed the bit; do_unpack needs the code,
; because "the tag did not match" (EXIT_AUTH) and "the disk did not answer"
; (EXIT_IO) are different things to tell a user about their archive.  Set once,
; at the point of failure, and left alone afterwards - ESF_ERR is sticky, so the
; first reason is the true one.
ES_ecode        equ 144         ; dd  EXIT_AUTH / EXIT_IO / EXIT_CORRUPT
; ---- segments (docs/V5_WORK.md B4/B5).  A large entry is a RUN of GCM streams,
; [ct][tag] per segment, every segment's plaintext SEG_BYTES long except the
; last.  Crossing a boundary means finishing one stream - tag verified - and
; opening the next at segment+1, which needs the ordinal and the RAW KEY again:
; on the drag-out path the global key is wiped long before the first Read, so
; the object carries its own copy (wiped with the rest by tagged_free).
ES_segidx       equ 148         ; dd  which segment is open
ES_segbytes     equ 152         ; dq  1 << header seg_shift, 0 = unsegmented
ES_ctremain     equ 160         ; dq  ciphertext in segments NOT yet started
ES_ordinal      equ 168         ; dq  for reopening at a boundary
ES_key          equ 176         ; 32  the raw key, this object's own copy
ES_ctx          equ 208         ; GCTX_SIZE
ES_RAW          equ 544         ; ES_ctx + GCTX_SIZE
ES_RAW_BYTES    equ MAX_PATH_CHARS*2
ES_IN           equ ES_RAW + ES_RAW_BYTES    ; compressed payload (framed only)
ES_OUT          equ ES_IN + CBLOCK           ; decompressed block (framed only)
ES_SIZE_STORE   equ ES_IN
ES_SIZE_COMP    equ ES_OUT + CBLOCK

ESF_COMP        equ 1           ; the container is XPRESS-framed
ESF_TAR         equ 2           ; the entry's plaintext starts with a tar header
ESF_DONE        equ 4           ; every ciphertext byte consumed AND the tag verified
ESF_ERR         equ 8           ; failed: every further call returns E_FAIL

; the exerciser's limits
ES_TEST_MAX     equ 8           ; streams held open at once
ES_TEST_CHUNK   equ 7919        ; a prime, so no read lands on a block boundary

.const
align 8
iid_es_unknown  dd 000000000h                                   ; IID_IUnknown
                dw 00000h, 00000h
                db 0C0h,000h,000h,000h,000h,000h,000h,046h
iid_es_stream   dd 00000000Ch                                   ; IID_IStream
                dw 00000h, 00000h
                db 0C0h,000h,000h,000h,000h,000h,000h,046h
iid_es_seq      dd 0C733A30h                                    ; IID_ISequentialStream
                dw 02A1Ch, 011CEh
                db 0ADh,0E5h,000h,0AAh,000h,044h,077h,03Dh

; The drag-out progress label - NOT inside ifdef TEST_IO, which is where it
; first landed and where a release build could not see it.
CSTR s_drag_lbl,    "copying"

ifdef TEST_IO
CSTR msg_es_ok,     "estream: OK, entries streamed: "
CSTR msg_es_nl,     13,10
CSTR msg_es_sep,    " "
CSTR e_es_read,     "estream: Read failed (tag, I/O, or a malformed frame)",13,10
CSTR e_es_create,   "estream: could not construct a stream over an entry",13,10
CSTR e_es_io,       "estream: could not open an output file",13,10
CSTR e_es_iface,    "estream: Stat or Seek disagreed with the index",13,10
CSTR msg_do_ok,     "dataobj: OK, items: "
CSTR e_do_create,   "dataobj: could not build the data object",13,10
CSTR e_do_iface,    "dataobj: an IDataObject method answered wrongly",13,10
CSTR e_es_none,     "estream: the container holds no file entries",13,10

; Spelled out rather than built with WSTR: the separator is a backslash, and a
; backslash inside <> is a line-continuation to MASM before it is a character.
even
w_es_sep    dw '\','e','s','_',0
w_es_ext    dw '.','b','i','n',0
endif

.data?
align 8
ifdef TEST_IO
g_es_objs   dq ES_TEST_MAX dup (?)      ; the live IStream*s
g_es_files  dq ES_TEST_MAX dup (?)      ; where each one is being written
g_es_buf    db ES_TEST_CHUNK dup (?)
g_es_got    dd ?
align 8
g_es_stat   db SSTG_BYTES dup (?)
g_es_tell   dq ?
align 8
g_do_unk    dq ?                            ; QueryInterface out params
g_do_unk2   dq ?
g_do_enum   dq ?
g_do_fetched dd ?
; ES_TEST_CHUNK is a prime, so g_es_buf is an odd length and everything after it
; would sit on an odd address - which a -W API can read with an aligned SSE path
; and fail with ERROR_NOACCESS.  aligncheck caught exactly that here.
align 8
g_es_path   dw 2048 dup (?)
endif

.code

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
; es_copy(rcx = dst, rdx = src, r8 = len) - forward copy, no overlap.
; =============================================================================
es_copy proc
    test    r8, r8
    jz      ec_done
ec_loop:
    mov     al, byte ptr [rdx]
    mov     byte ptr [rcx], al
    inc     rcx
    inc     rdx
    dec     r8
    jnz     ec_loop
ec_done:
    ret
es_copy endp

; =============================================================================
; es_guid_eq(rcx = a, rdx = b) -> eax = 1 if the two 16-byte GUIDs match.
; =============================================================================
es_guid_eq proc
    mov     rax, qword ptr [rcx]
    cmp     rax, qword ptr [rdx]
    jne     ege_no
    mov     rax, qword ptr [rcx+8]
    cmp     rax, qword ptr [rdx+8]
    jne     ege_no
    mov     eax, 1
    ret
ege_no:
    xor     eax, eax
    ret
es_guid_eq endp

; =============================================================================
; es_raw_refill(rcx = this) -> eax 0 = bytes available, 1 = failed, 2 = clean end
;
; Layer A: entry ciphertext -> entry plaintext.  Reads at most ES_RAW_BYTES at a
; time, which is a multiple of 16 - gcm_crypt allows a short final call and no
; other.  When the ciphertext runs out this is where the tag is read, computed
; and compared; a mismatch is sticky, because a stream that has produced one
; unauthenticated byte must not produce another.
; locals: [rbp-16] this  [rbp-24] n
; =============================================================================
es_raw_refill proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    test    dword ptr [rcx+ES_flags], ESF_ERR
    jnz     err_fail_q
err_rescan:
    mov     rax, qword ptr [rcx+ES_rawpos]
    cmp     rax, qword ptr [rcx+ES_rawlen]
    jb      err_have
    cmp     qword ptr [rcx+ES_ctleft], 0
    je      err_tag
    ; n = min(ctleft, ES_RAW_BYTES)
    mov     rax, qword ptr [rcx+ES_ctleft]
    cmp     rax, ES_RAW_BYTES
    jbe     @F
    mov     rax, ES_RAW_BYTES
@@:
    mov     qword ptr [rbp-24], rax
    mov     r10, qword ptr [rbp-16]
    mov     rcx, qword ptr [r10+ES_hfile]
    mov     rdx, qword ptr [r10+ES_ctoff]
    lea     r8, [r10+ES_RAW]
    mov     r9, qword ptr [rbp-24]
    call    vol_get
    test    eax, eax
    jnz     err_io
    mov     r10, qword ptr [rbp-16]
    lea     rcx, [r10+ES_ctx]
    lea     rdx, [r10+ES_RAW]
    mov     r8, rdx
    mov     r9, qword ptr [rbp-24]
    call    gcm_crypt
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-24]
    add     qword ptr [r10+ES_ctoff], rax
    sub     qword ptr [r10+ES_ctleft], rax
    mov     qword ptr [r10+ES_rawlen], rax
    mov     qword ptr [r10+ES_rawpos], 0
err_have:
    xor     eax, eax
    FRAME_EPILOG
    ret
err_tag:
    mov     r10, qword ptr [rbp-16]
    test    dword ptr [r10+ES_flags], ESF_DONE
    jnz     err_eof                         ; verified already; just report the end
    mov     rcx, qword ptr [r10+ES_hfile]
    mov     rdx, qword ptr [r10+ES_ctoff]
    lea     r8, [r10+ES_tag2]
    mov     r9, GCM_TAG_LEN
    call    vol_get
    test    eax, eax
    jnz     err_io
    mov     r10, qword ptr [rbp-16]
    lea     rcx, [r10+ES_ctx]
    lea     rdx, [r10+ES_tag]
    call    gcm_final
    mov     r10, qword ptr [rbp-16]
    lea     rcx, [r10+ES_tag]
    lea     rdx, [r10+ES_tag2]
    mov     r8, GCM_TAG_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     err_auth
    mov     r10, qword ptr [rbp-16]
    cmp     qword ptr [r10+ES_ctremain], 0
    jne     err_nextseg
    or      dword ptr [r10+ES_flags], ESF_DONE
err_eof:
    mov     eax, 2
    FRAME_EPILOG
    ret
err_nextseg:
    ; This segment's tag VERIFIED and more segments follow: step past the tag,
    ; open the next stream at segment+1, and fall back into the normal read
    ; path - to a caller nothing happened, which is the point.  Same shape as
    ; vol_get crossing a part boundary, one layer up.
    ;
    ; The reopen re-enters entry_stream_open, whose scratch (g_idxnonce,
    ; g_entaad) is shared - the same constraint es_create documents at the top
    ; of this file, now extended from construction to a Read that crosses a
    ; boundary.  Both arrive through the STA (or through single-threaded
    ; do_unpack), so the serialisation that covered one covers the other.
    add     qword ptr [r10+ES_ctoff], GCM_TAG_LEN
    inc     dword ptr [r10+ES_segidx]
    ; ctleft = min(SEG_BYTES, ctremain); ctremain -= ctleft
    mov     rax, qword ptr [r10+ES_ctremain]
    mov     rcx, qword ptr [r10+ES_segbytes]
    cmp     rax, rcx
    jbe     @F
    mov     rax, rcx
@@:
    mov     qword ptr [r10+ES_ctleft], rax
    sub     qword ptr [r10+ES_ctremain], rax
    lea     rcx, [r10+ES_ctx]
    lea     rdx, [g_pkhdr]
    mov     r8, qword ptr [r10+ES_ordinal]
    mov     r9, 1                           ; decrypt
    lea     rax, [r10+ES_key]
    mov     qword ptr [rsp+32], rax
    mov     eax, dword ptr [r10+ES_segidx]
    mov     qword ptr [rsp+40], rax
    call    entry_stream_open
    mov     rcx, qword ptr [rbp-16]
    jmp     err_rescan
err_io:
    mov     r10, qword ptr [rbp-16]
    mov     dword ptr [r10+ES_ecode], EXIT_IO
    jmp     err_fail
err_auth:
    mov     r10, qword ptr [rbp-16]
    mov     dword ptr [r10+ES_ecode], EXIT_AUTH
err_fail:
    mov     r10, qword ptr [rbp-16]
    or      dword ptr [r10+ES_flags], ESF_ERR
err_fail_q:
    mov     eax, 1
    FRAME_EPILOG
    ret
es_raw_refill endp

; =============================================================================
; es_raw_take(rcx = this, rdx = dst or 0 to discard, r8 = len)
;   -> eax 0 = all of it, 1 = failed, 2 = the entry ended first
; locals: [rbp-16] this [rbp-24] dst [rbp-32] left [rbp-40] n
; =============================================================================
es_raw_take proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
ert_loop:
    cmp     qword ptr [rbp-32], 0
    je      ert_ok
    mov     rcx, qword ptr [rbp-16]
    call    es_raw_refill
    cmp     eax, 0
    jne     ert_stop                        ; 1 = failed, 2 = clean end
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [r10+ES_rawlen]
    sub     rax, qword ptr [r10+ES_rawpos]  ; available
    cmp     rax, qword ptr [rbp-32]
    jbe     @F
    mov     rax, qword ptr [rbp-32]
@@:
    mov     qword ptr [rbp-40], rax
    cmp     qword ptr [rbp-24], 0
    je      ert_skip                        ; discarding: advance and copy nothing
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-16]
    lea     rdx, [r10+ES_RAW]
    add     rdx, qword ptr [r10+ES_rawpos]
    mov     r8, qword ptr [rbp-40]
    call    es_copy
    mov     rax, qword ptr [rbp-40]
    add     qword ptr [rbp-24], rax
ert_skip:
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-40]
    add     qword ptr [r10+ES_rawpos], rax
    sub     qword ptr [rbp-32], rax
    jmp     ert_loop
ert_ok:
    xor     eax, eax
ert_stop:
    FRAME_EPILOG
    ret
es_raw_take endp

; =============================================================================
; es_frame_fill(rcx = this) -> eax 0 = a block is in ES_OUT, 1 = failed, 2 = end
;
; Layer B, compressed containers only: one [u32 orig][u32 payload][payload]
; frame.  A stored frame (payload == orig) is read STRAIGHT into ES_OUT, which
; is why the header is parsed before the payload is read - it saves a megabyte
; of copying on the case where compression did not help.
; locals: [rbp-16] this  [rbp-24] frame header (two dwords)  [rbp-32] orig
;         [rbp-40] paylen  [rbp-48] Decompress's out size  [rbp-56..-72] its
;         staged pointer arguments
; =============================================================================
es_frame_fill proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], 0
    lea     rdx, [rbp-24]
    mov     r8, 8
    call    es_raw_take
    cmp     eax, 0
    jne     eff_stop                        ; 2 here is the clean end of the entry
    mov     eax, dword ptr [rbp-24]
    mov     qword ptr [rbp-32], rax         ; orig
    mov     eax, dword ptr [rbp-20]
    mov     qword ptr [rbp-40], rax         ; payload
    ; A frame is bounded by construction; these come off a tag-verified stream,
    ; but a container written by a future version could still say anything.
    cmp     qword ptr [rbp-32], 0
    je      eff_bad
    cmp     qword ptr [rbp-32], CBLOCK
    ja      eff_bad
    cmp     qword ptr [rbp-40], 0
    je      eff_bad
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [rbp-32]
    ja      eff_bad                         ; payload can never exceed orig
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [rbp-32]
    jne     eff_comp
    ; stored frame: straight into ES_OUT
    mov     rcx, r10
    lea     rdx, [r10+ES_OUT]
    mov     r8, qword ptr [rbp-40]
    call    es_raw_take
    test    eax, eax
    jnz     eff_bad                         ; a truncated frame is not a clean end
    jmp     eff_have
eff_comp:
    mov     rcx, r10
    lea     rdx, [r10+ES_IN]
    mov     r8, qword ptr [rbp-40]
    call    es_raw_take
    test    eax, eax
    jnz     eff_bad
    ; Every argument is staged into a local first.  Decompress takes six, so the
    ; last two go on the outgoing area - and WINCALL emits those FIRST, using rax
    ; as its scratch.  An argument left in rax (or in any register an `addr`
    ; argument would tread on) is read after it has already been overwritten.
    mov     r10, qword ptr [rbp-16]
    mov     qword ptr [rbp-48], 0
    lea     rax, [r10+ES_IN]
    mov     qword ptr [rbp-56], rax
    lea     rax, [r10+ES_OUT]
    mov     qword ptr [rbp-64], rax
    mov     rax, qword ptr [r10+ES_hdec]
    mov     qword ptr [rbp-72], rax
    WINCALL Decompress, qword ptr [rbp-72], qword ptr [rbp-56], qword ptr [rbp-40], \
            qword ptr [rbp-64], CBLOCK, addr rbp-48
    test    eax, eax
    jz      eff_bad
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [rbp-32]
    jne     eff_bad                         ; short inflate: refuse, never pad
eff_have:
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+ES_outlen], rax
    mov     qword ptr [r10+ES_outpos], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
eff_bad:
    ; A malformed frame inside an AUTHENTIC entry is corruption we produced, not
    ; tampering: the tag is checked over the ciphertext, and this is the layer
    ; above it.  Reported as such rather than as an authentication failure, which
    ; would send the user looking for an attacker.
    ;
    ; But only when nothing below has already answered.  Half the jumps here come
    ; from es_raw_take returning 1 - which means the raw layer failed and has
    ; ALREADY recorded whether that was the tag or the disk.  Overwriting it would
    ; report every tampered container as merely corrupt.
    mov     r10, qword ptr [rbp-16]
    test    dword ptr [r10+ES_flags], ESF_ERR
    jnz     eff_mark
    mov     dword ptr [r10+ES_ecode], EXIT_CORRUPT
eff_mark:
    or      dword ptr [r10+ES_flags], ESF_ERR
    mov     eax, 1
eff_stop:
    FRAME_EPILOG
    ret
es_frame_fill endp

; =============================================================================
; es_take(rcx = this, rdx = dst or 0 to discard, r8 = len)
;   -> eax 0 = all of it, 1 = failed, 2 = the entry ended first
;
; Layer C's supplier: plaintext as the tar stream sees it, whichever of the two
; framings the container uses.
; locals: [rbp-16] this [rbp-24] dst [rbp-32] left [rbp-40] n
; =============================================================================
es_take proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    test    dword ptr [rcx+ES_flags], ESF_COMP
    jnz     etk_framed
    call    es_raw_take                     ; rdx/r8 still hold dst/len
    FRAME_EPILOG
    ret
etk_framed:
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
etk_loop:
    cmp     qword ptr [rbp-32], 0
    je      etk_ok
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [r10+ES_outpos]
    cmp     rax, qword ptr [r10+ES_outlen]
    jb      etk_have
    mov     rcx, r10
    call    es_frame_fill
    cmp     eax, 0
    jne     etk_stop
etk_have:
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [r10+ES_outlen]
    sub     rax, qword ptr [r10+ES_outpos]
    cmp     rax, qword ptr [rbp-32]
    jbe     @F
    mov     rax, qword ptr [rbp-32]
@@:
    mov     qword ptr [rbp-40], rax
    cmp     qword ptr [rbp-24], 0
    je      etk_skip
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-16]
    lea     rdx, [r10+ES_OUT]
    add     rdx, qword ptr [r10+ES_outpos]
    mov     r8, qword ptr [rbp-40]
    call    es_copy
    mov     rax, qword ptr [rbp-40]
    add     qword ptr [rbp-24], rax
etk_skip:
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-40]
    add     qword ptr [r10+ES_outpos], rax
    sub     qword ptr [rbp-32], rax
    jmp     etk_loop
etk_ok:
    xor     eax, eax
etk_stop:
    FRAME_EPILOG
    ret
es_take endp

; =============================================================================
; es_drain(rcx = this) -> eax 0 = the entry ended cleanly and its tag verified,
;                             1 = failed
;
; Discards whatever the entry still holds past the content: the tar padding, at
; most 511 bytes of it, and then the tag.  This is the step that makes a
; completed copy an AUTHENTICATED copy - stopping at the last content byte
; leaves GCM one block short of a verdict.
; =============================================================================
es_drain proc frame
    FRAME_PROLOG 48
    xor     rdx, rdx                        ; discard
    mov     r8, 7FFFFFFFFFFFFFFFh           ; "to the end"; only ever subtracted
    call    es_take
    cmp     eax, 2                          ; 2 = ran out, which is the point
    jne     edr_bad
    xor     eax, eax
    FRAME_EPILOG
    ret
edr_bad:
    mov     eax, 1
    FRAME_EPILOG
    ret
es_drain endp

; =============================================================================
; es_consume(rcx = this, rdx = dst or 0, r8 = n) -> eax 0 ok / 1 failed
;
; n content bytes, with everything that surrounds them: the one-time tar-header
; skip in front, the position bookkeeping, and the drain-and-verify behind the
; final byte.  Read and the forward half of Seek are both this.
; locals: [rbp-16] this [rbp-24] dst [rbp-32] n
; =============================================================================
es_consume proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    cmp     qword ptr [rcx+ES_skip], 0
    je      ecn_body
    mov     r8, qword ptr [rcx+ES_skip]
    xor     rdx, rdx
    call    es_take
    test    eax, eax
    jnz     ecn_bad                         ; a header that is not there is corrupt
    mov     r10, qword ptr [rbp-16]
    mov     qword ptr [r10+ES_skip], 0
ecn_body:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    es_take
    test    eax, eax
    jnz     ecn_bad
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-32]
    sub     qword ptr [r10+ES_left], rax
    add     qword ptr [r10+ES_pos], rax
    cmp     qword ptr [r10+ES_left], 0
    jne     ecn_ok
    mov     rcx, r10
    call    es_drain
    test    eax, eax
    jnz     ecn_bad
ecn_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
ecn_bad:
    ; es_take returning 2 here means the entry ran out before the index said it
    ; should - a size the container disagrees with, which is corruption and not a
    ; failed tag.  Same rule as eff_bad: only speak if nothing below already has.
    mov     r10, qword ptr [rbp-16]
    test    dword ptr [r10+ES_flags], ESF_ERR
    jnz     ecn_mark
    mov     dword ptr [r10+ES_ecode], EXIT_CORRUPT
ecn_mark:
    or      dword ptr [r10+ES_flags], ESF_ERR
    mov     eax, 1
    FRAME_EPILOG
    ret
es_consume endp

; =============================================================================
; es_code(rcx = this) -> eax = why the stream failed, or EXIT_OK if it has not.
; =============================================================================
public es_code
es_code proc
    xor     eax, eax
    test    dword ptr [rcx+ES_flags], ESF_ERR
    jz      esc_ret
    mov     eax, dword ptr [rcx+ES_ecode]
esc_ret:
    ret
es_code endp


; =============================================================================
; es_destroy(rcx = this) - close everything and wipe the block.
;
; tagged_free's second argument is the one that matters here: the buffers hold
; decrypted plaintext, and a freed page that still holds it is the same leak as
; a temp file that was never deleted.
; locals: [rbp-16] this
; =============================================================================
es_destroy proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    test    rcx, rcx
    jz      edy_ret
    mov     rcx, qword ptr [rcx+ES_hfile]
    cmp     rcx, INVALID
    je      @F
    call    vset_close
@@:
    mov     r10, qword ptr [rbp-16]
    mov     rcx, qword ptr [r10+ES_hdec]
    test    rcx, rcx
    jz      @F
    WINCALL CloseDecompressor, rcx
@@:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, 1                          ; wipe: these pages held plaintext
    call    tagged_free
edy_ret:
    FRAME_EPILOG
    ret
es_destroy endp

; =============================================================================
; es_new(rcx = container path) -> rax = context or 0
;
; Everything about the CONTAINER: the allocation sized to its framing, the
; handle, the decompressor, the vtable.  Nothing about any one entry - that is
; es_bind, and a context can be bound to entry after entry without paying for
; any of this again.
;
; That split is what lets do_unpack extract a whole archive through this decoder
; with ONE allocation, ONE handle and ONE decompressor for the run, instead of a
; 2 MiB allocation and a CreateDecompressor per file.  Drag-out still wants one
; object per entry, and gets it through es_create below - which is exactly these
; two calls in a row.
;
; locals: [rbp-16] path  [rbp-32] this
; =============================================================================
public es_new
es_new proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-32], 0
    ; one allocation, sized to what this container's framing actually needs
    movzx   eax, byte ptr [g_pkhdr+CONTAINER_HDR.compressed]
    test    eax, eax
    jz      esn_store
    mov     rcx, ES_SIZE_COMP
    jmp     esn_alloc
esn_store:
    mov     rcx, ES_SIZE_STORE
esn_alloc:
    call    tagged_alloc
    test    rax, rax
    jz      esn_no
    mov     qword ptr [rbp-32], rax
    mov     r10, rax
    mov     qword ptr [r10+ES_hfile], INVALID
    lea     rax, [vtbl_EntryStream]
    mov     qword ptr [r10+ES_vtbl], rax
    mov     dword ptr [r10+ES_refs], 1
    ; framing flags, from the header the index was authenticated against
    xor     r9d, r9d
    movzx   eax, byte ptr [g_pkhdr+CONTAINER_HDR.compressed]
    test    eax, eax
    jz      @F
    or      r9d, ESF_COMP
@@:
    movzx   eax, byte ptr [g_pkhdr+CONTAINER_HDR.archive]
    test    eax, eax
    jz      @F
    or      r9d, ESF_TAR
@@:
    mov     dword ptr [r10+ES_flags], r9d
    ; the segment size, from the same header the flags came from.  -1 (an
    ; out-of-range shift) fails construction: every route to an index refused it
    ; already, and this guard is for the day one stops doing so.
    lea     rcx, [g_pkhdr]
    call    seg_bytes_from_hdr
    cmp     rax, -1
    je      esn_fail
    mov     r10, qword ptr [rbp-32]
    mov     qword ptr [r10+ES_segbytes], rax
    ; the container, opened per context.  ES_RAW is borrowed as normalize_path's
    ; destination - it is exactly MAX_PATH_CHARS*2 bytes and nothing has read a
    ; byte of ciphertext into it yet.
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [r10+ES_RAW]
    call    normalize_path
    test    eax, eax
    jnz     esn_fail
    mov     r10, qword ptr [rbp-32]
    ; vset_open: a container handed to drag-out may be a volume set, and the
    ; extents in ES_ctoff are LOGICAL offsets into the whole stream.  Opened
    ; per context and refcounted, because drag-out keeps every entry's stream
    ; open at once and one closing must not shut the others' parts.
    lea     rcx, [r10+ES_RAW]
    call    vset_open
    cmp     rax, INVALID
    je      esn_fail
    mov     r10, qword ptr [rbp-32]
    mov     qword ptr [r10+ES_hfile], rax
    ; a decompressor of this context's own, when the container is framed.  One
    ; per context and not one per entry: XPRESS blocks are self-contained, so a
    ; handle carries nothing across a Decompress call that the next entry could
    ; inherit.
    test    dword ptr [r10+ES_flags], ESF_COMP
    jz      esn_ok
    lea     rax, [r10+ES_hdec]
    WINCALL CreateDecompressor, COMPRESS_ALGORITHM_XPRESS, 0, rax
    test    eax, eax
    jz      esn_fail
esn_ok:
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
esn_fail:
    mov     rcx, qword ptr [rbp-32]
    call    es_destroy
esn_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
es_new endp

; =============================================================================
; es_bind(rcx = this, rdx = index entry, r8 = key) -> eax 0 ok / 1 refused
;
; Point an existing context at one entry.  Every field the decoder reads is
; reset here - the two buffer cursors included, because a context that gave up
; part-way through the previous entry still has bytes of it in ES_RAW, and a
; second entry that inherited them would decrypt the right ciphertext into the
; wrong place.  The error state is cleared for the same reason: ESF_ERR is
; sticky WITHIN an entry, which is what makes an unauthenticated byte
; unrepeatable, and meaningless across two.
;
; The entry pointer is not kept: everything is copied out, so a reload of
; g_idxbuf afterwards cannot leave a live stream reading a description that has
; moved.  The KEY is a parameter for the reason entry_stream_open's comment in
; pack.asm gives.
;
; locals: [rbp-16] this [rbp-24] entry [rbp-32] key [rbp-40] stored
; =============================================================================
public es_bind
es_bind proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    ; A DIRECTORY is not refused here.  Its entry is a 512-byte tar header
    ; sealed like any other, so it authenticates like any other and yields zero
    ; content bytes - which is exactly what a target asking for the contents of
    ; a folder descriptor should get.  Refusing it would abort the whole copy
    ; over an empty folder.
    mov     rax, qword ptr [rdx+IDXE_stored]
    cmp     rax, GCM_TAG_LEN
    jb      esb_no                          ; not even room for the tag
    mov     qword ptr [rbp-40], rax
    mov     r10, rcx
    and     dword ptr [r10+ES_flags], (ESF_COMP or ESF_TAR)
    mov     dword ptr [r10+ES_ecode], EXIT_OK
    mov     qword ptr [r10+ES_rawlen], 0
    mov     qword ptr [r10+ES_rawpos], 0
    mov     qword ptr [r10+ES_outlen], 0
    mov     qword ptr [r10+ES_outpos], 0
    mov     qword ptr [r10+ES_pos], 0
    mov     dword ptr [r10+ES_segidx], 0
    ; the ordinal and a copy of the KEY, both for reopening at a segment
    ; boundary.  The copy matters on the drag-out path: the global is wiped
    ; before the first Read, and a boundary is crossed minutes later.
    mov     rax, qword ptr [rdx+IDXE_ordinal]
    mov     qword ptr [r10+ES_ordinal], rax
    lea     rcx, [r10+ES_key]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, KEY_LEN
    call    es_copy
    mov     r10, qword ptr [rbp-16]
    mov     r11, qword ptr [rbp-24]
    ; the extent, and where the content sits inside it
    mov     rax, qword ptr [r11+IDXE_offset]
    add     rax, HDR_BYTES                  ; extents are relative to the payload run
    mov     qword ptr [r10+ES_ctoff], rax
    ; ---- how many GCM streams the extent holds ------------------------------
    ; n = ceil(stored / (SEG_BYTES + 16)): every segment is SEG_BYTES of
    ; plaintext plus a 16-byte tag except the last, which is shorter - so the
    ; count follows from the extent alone (docs/V5_WORK.md B2, verified
    ; exhaustively).  Unsegmented, n = 1 and this is the old arithmetic.
    ;
    ; The index is authenticated, but a hostile future container can still say
    ; anything: an extent too small for its tags is refused here, and one whose
    ; split does not line up fails its first tag compare - closed either way.
    mov     r11, qword ptr [r10+ES_segbytes]
    test    r11, r11
    jz      esb_oneseg
    mov     rax, qword ptr [rbp-40]         ; stored
    lea     rcx, [r11+GCM_TAG_LEN]          ; SEG_BYTES + 16
    add     rax, rcx
    dec     rax                             ; stored + (S+16) - 1
    xor     edx, edx
    div     rcx                             ; rax = n
    mov     rcx, rax
    shl     rcx, 4                          ; 16 * n
    mov     rax, qword ptr [rbp-40]
    cmp     rax, rcx
    jb      esb_no                          ; not even room for the tags
    sub     rax, rcx                        ; total ct across all segments
    jmp     esb_split
esb_oneseg:
    mov     rax, qword ptr [rbp-40]
    sub     rax, GCM_TAG_LEN
esb_split:
    ; this segment gets min(SEG_BYTES, total); the rest wait in ES_ctremain
    mov     rcx, rax
    test    r11, r11
    jz      @F
    cmp     rcx, r11
    jbe     @F
    mov     rcx, r11
@@:
    mov     qword ptr [r10+ES_ctleft], rcx
    sub     rax, rcx
    mov     qword ptr [r10+ES_ctremain], rax
    mov     r11, qword ptr [rbp-24]
    mov     rax, qword ptr [r11+IDXE_size]
    mov     qword ptr [r10+ES_size], rax
    mov     qword ptr [r10+ES_left], rax
    mov     qword ptr [r10+ES_skip], 0
    test    dword ptr [r10+ES_flags], ESF_TAR
    jz      @F
    mov     qword ptr [r10+ES_skip], 512
@@:
    ; nonce = (ordinal + 1, segment), AAD = header || ordinal [|| segment].  The
    ; ordinal the entry was SEALED with, which a delete leaves alone - not its
    ; position in the table.  Segment 0 until B4 gives an entry more than one.
    lea     rcx, [r10+ES_ctx]
    lea     rdx, [g_pkhdr]
    mov     r8, qword ptr [r11+IDXE_ordinal]
    mov     r9, 1                           ; decrypt
    lea     rax, [r10+ES_key]               ; the object's copy, same as a reopen
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0
    call    entry_stream_open
    xor     eax, eax
    FRAME_EPILOG
    ret
esb_no:
    mov     eax, 1
    FRAME_EPILOG
    ret
es_bind endp

; =============================================================================
; es_create(rcx = index entry, rdx = container path, r8 = key)
;   -> rax = IStream* or 0
;
; The COM constructor: a context of its own, bound to one entry, ready to be
; handed to a drop target.  es_new + es_bind and nothing else.
; locals: [rbp-16] entry [rbp-24] path [rbp-32] this [rbp-40] key
; =============================================================================
public es_create
es_create proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-40], r8
    mov     rcx, rdx
    call    es_new
    test    rax, rax
    jz      ecr_no
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-16]
    mov     r8, qword ptr [rbp-40]
    call    es_bind
    test    eax, eax
    jnz     ecr_fail
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
ecr_fail:
    mov     rcx, qword ptr [rbp-32]
    call    es_destroy
ecr_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
es_create endp

; =============================================================================
; IStream - 14 slots: IUnknown (3), ISequentialStream (2), IStream (9).
; =============================================================================

; -----------------------------------------------------------------------------
; ES_QueryInterface(rcx = this, rdx = riid, r8 = ppv)
; locals: [rbp-16] this [rbp-24] riid [rbp-32] ppv
; -----------------------------------------------------------------------------
ES_QueryInterface proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    test    r8, r8
    jz      eqi_badarg
    mov     qword ptr [r8], 0               ; null the out param BEFORE failing
    test    rdx, rdx
    jz      eqi_badarg
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_stream
    test    eax, eax
    jnz     eqi_hand
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_seq
    test    eax, eax
    jnz     eqi_hand
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_unknown
    test    eax, eax
    jnz     eqi_hand
    mov     eax, E_NOINTERFACE
    jmp     eqi_ret
eqi_hand:
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [r10], rax
    mov     r11, qword ptr [rbp-16]
    lock inc dword ptr [r11+ES_refs]
    mov     eax, S_OK
    jmp     eqi_ret
eqi_badarg:
    mov     eax, E_INVALIDARG
eqi_ret:
    FRAME_EPILOG
    ret
ES_QueryInterface endp

ES_AddRef proc
    mov     eax, 1
    lock xadd dword ptr [rcx+ES_refs], eax
    inc     eax
    ret
ES_AddRef endp

; -----------------------------------------------------------------------------
; ES_Release - unlike the drop target's, this one really does destroy: the
; object is per-drag, per-entry and heap-allocated, and the shell decides when
; it is finished with it.
; locals: [rbp-16] this
; -----------------------------------------------------------------------------
ES_Release proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     eax, -1
    lock xadd dword ptr [rcx+ES_refs], eax
    dec     eax
    jnz     erl_ret
    mov     rcx, qword ptr [rbp-16]
    call    es_destroy
    xor     eax, eax
erl_ret:
    FRAME_EPILOG
    ret
ES_Release endp

; -----------------------------------------------------------------------------
; ES_Read(rcx = this, rdx = pv, r8d = cb, r9 = pcbRead)
;
; cb is a ULONG - 32 bits - so the upper half of r8 is whatever the caller
; happened to leave there.
; locals: [rbp-16] this [rbp-24] pv [rbp-32] cb [rbp-40] pcbRead [rbp-48] n
; -----------------------------------------------------------------------------
ES_Read proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     r8d, r8d                        ; ULONG: discard the high half
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], r9
    test    r9, r9
    jz      @F
    mov     dword ptr [r9], 0
@@:
    test    dword ptr [rcx+ES_flags], ESF_ERR
    jnz     erd_fail
    cmp     qword ptr [rbp-32], 0
    je      erd_zero
    test    rdx, rdx
    jz      erd_badarg
    ; n = min(cb, left)
    mov     rax, qword ptr [rcx+ES_left]
    cmp     rax, qword ptr [rbp-32]
    jbe     @F
    mov     rax, qword ptr [rbp-32]
@@:
    mov     qword ptr [rbp-48], rax
    test    rax, rax
    jz      erd_end
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-48]
    call    es_consume
    test    eax, eax
    jnz     erd_fail
    ; Bytes actually handed to the target, which is what the bar should show -
    ; counted here rather than at the refill, so a read that fails part way does
    ; not claim progress it did not make.  A no-op unless a drag is running:
    ; progress_add only touches counters, and g_drag_prog gates the repaint.
    cmp     dword ptr [g_drag_prog], 0
    je      @F
    mov     rcx, qword ptr [rbp-48]
    call    progress_add
    call    drag_prog_tick                  ; paints; the timer is not dispatched
                                            ; inside DoDragDrop's modal loop
@@:
    mov     r10, qword ptr [rbp-40]
    test    r10, r10
    jz      @F
    mov     rax, qword ptr [rbp-48]
    mov     dword ptr [r10], eax
@@:
    mov     eax, S_OK
    FRAME_EPILOG
    ret
erd_end:
    ; The content is finished.  An entry whose content is zero bytes long has
    ; never had its tag checked at this point, and neither has one whose last
    ; Read asked for exactly the remaining bytes and got them - so the verdict
    ; is taken here, once, before reporting the end.
    mov     r10, qword ptr [rbp-16]
    test    dword ptr [r10+ES_flags], ESF_DONE
    jnz     erd_zero
    mov     rcx, r10
    call    es_drain
    test    eax, eax
    jnz     erd_fail
erd_zero:
    mov     eax, S_OK
    FRAME_EPILOG
    ret
erd_badarg:
    mov     eax, E_INVALIDARG
    FRAME_EPILOG
    ret
erd_fail:
    mov     r10, qword ptr [rbp-16]
    or      dword ptr [r10+ES_flags], ESF_ERR
    mov     eax, E_FAIL
    FRAME_EPILOG
    ret
ES_Read endp

; -----------------------------------------------------------------------------
; ES_Seek(rcx = this, rdx = dlibMove, r8d = dwOrigin, r9 = plibNewPosition)
;
; LARGE_INTEGER is eight bytes, so it is passed BY VALUE in rdx - the same trap
; POINTL set for DT_DragEnter.  Taking the move distance from a pointer here
; would read whatever address the caller's offset happened to look like.
;
; An entry decrypts sequentially and its tag clears only at the last byte, so
; there is no going back: a backward seek is refused rather than served by
; reopening, which would silently start a second GCM stream over the same data.
; Forward is served by reading and discarding, which is what it costs.
; locals: [rbp-16] this [rbp-24] target [rbp-32] plib
; -----------------------------------------------------------------------------
ES_Seek proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-32], r9
    test    dword ptr [rcx+ES_flags], ESF_ERR
    jnz     esk_fail
    cmp     r8d, 0                          ; STREAM_SEEK_SET
    jne     @F
    mov     qword ptr [rbp-24], rdx
    jmp     esk_have
@@:
    cmp     r8d, 1                          ; STREAM_SEEK_CUR
    jne     esk_nofunc                      ; END: the size is known, the position is not recoverable
    mov     rax, qword ptr [rcx+ES_pos]
    add     rax, rdx
    mov     qword ptr [rbp-24], rax
esk_have:
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [r10+ES_pos]
    jb      esk_nofunc                      ; backward, or negative and enormous
    cmp     rax, qword ptr [r10+ES_size]
    ja      esk_nofunc
    sub     rax, qword ptr [r10+ES_pos]
    test    rax, rax
    jz      esk_ok
    mov     rcx, r10
    xor     rdx, rdx                        ; discard
    mov     r8, rax
    call    es_consume
    test    eax, eax
    jnz     esk_fail
esk_ok:
    mov     r10, qword ptr [rbp-32]
    test    r10, r10
    jz      @F
    mov     r11, qword ptr [rbp-16]
    mov     rax, qword ptr [r11+ES_pos]
    mov     qword ptr [r10], rax
@@:
    mov     eax, S_OK
    FRAME_EPILOG
    ret
esk_nofunc:
    mov     eax, STG_E_INVALIDFUNCTION
    FRAME_EPILOG
    ret
esk_fail:
    mov     eax, E_FAIL
    FRAME_EPILOG
    ret
ES_Seek endp

; -----------------------------------------------------------------------------
; ES_Stat(rcx = this, rdx = pstatstg, r8d = grfStatFlag)
;
; cbSize MUST match the size the file descriptor advertises, or Explorer stops
; the copy early believing it is done.  Both come from IDXE_size, which is what
; makes them agree.  pwcsName is left null: the name belongs to the descriptor,
; and allocating one here would hand the caller a CoTaskMemFree obligation for
; no benefit.  grfStatFlag is therefore not consulted - STATFLAG_NONAME is
; already what this does.
; -----------------------------------------------------------------------------
ES_Stat proc frame
    FRAME_PROLOG 48
    test    rdx, rdx
    jz      est_badptr
    xor     eax, eax
    mov     r10, rdx
    mov     r11, SSTG_BYTES/8
@@:
    mov     qword ptr [r10], rax
    add     r10, 8
    dec     r11
    jnz     @B
    mov     dword ptr [rdx+SSTG_type], STGTY_STREAM
    mov     rax, qword ptr [rcx+ES_size]
    mov     qword ptr [rdx+SSTG_cbSize], rax
    mov     dword ptr [rdx+SSTG_grfMode], 0  ; STGM_READ
    mov     eax, S_OK
    FRAME_EPILOG
    ret
est_badptr:
    mov     eax, STG_E_INVALIDPOINTER
    FRAME_EPILOG
    ret
ES_Stat endp

; -----------------------------------------------------------------------------
; The rest.  Write and SetSize say ACCESSDENIED rather than NOTIMPL, because
; the stream is not missing the ability to write - it refuses to.  Clone is
; NOTIMPL for the reason Seek is restricted: a second cursor over one sequential
; GCM stream cannot exist without decrypting the entry twice.
; -----------------------------------------------------------------------------
ES_Denied proc
    mov     eax, STG_E_ACCESSDENIED
    ret
ES_Denied endp

ES_NotImpl proc
    mov     eax, E_NOTIMPL
    ret
ES_NotImpl endp

.const
align 8
vtbl_EntryStream label qword
    dq      ES_QueryInterface, ES_AddRef, ES_Release
    dq      ES_Read, ES_Denied
    dq      ES_Seek, ES_Denied, ES_NotImpl, ES_NotImpl, ES_NotImpl
    dq      ES_NotImpl, ES_NotImpl, ES_Stat, ES_NotImpl

.code

; =============================================================================
; The ZIP entry stream - a buffer, deliberately.
; -----------------------------------------------------------------------------
; Step 5 of docs/DRAG_OUT.md, and it is the OPPOSITE shape from the stream
; above.  §7c has the reconnaissance; the short form is that extract_zip_entry
; already authenticates an entry before or independently of handing its bytes
; over (HMAC-then-decrypt for deflate, decrypt-into-a-.part-then-verify-then-
; rename for stored), and a streaming zip reader could not keep either
; promise.  So a zip entry is run to completion by that reader - the only
; WinZip-AES reader in this program, and the point is that it stays the only
; one - and what the shell gets is an IStream over the result.
;
; What that buys, against the .mrk stream: the entry is fully authenticated
; before a single byte is offered, so a tampered entry fails GetData outright
; rather than part way through a copy; Seek works in both directions; and
; nothing here touches a cipher.
;
; What it costs, stated plainly: an open stream holds the whole entry.  No cap
; is invented here - mem_alloc failing is reported as E_OUTOFMEMORY, and the
; existing DEFLATE_RD_CAP still governs what the reader will attempt.
;
; The password is NOT copied into the object the way the .mrk key is.  It
; already lives in g_cfg_pass for the life of the container view - the view
; deliberately does not restore it, so that Extract does not re-prompt - and
; duplicating a secret into a per-drag object would mean more copies of it, not
; fewer.  The container PATH is still the object's own.
; =============================================================================

ZS_vtbl                     equ 0
ZS_refs                     equ 8
ZS_len                      equ 16
ZS_pos                      equ 24
ZS_buf                      equ 32           ; mem_alloc'd, ZS_len bytes, owned
ZS_BYTES                    equ 40

; -----------------------------------------------------------------------------
; zs_destroy(rcx = this) - the buffer holds decrypted plaintext, so it goes
; back wiped; mem_free's second argument is what does that.
; locals: [rbp-16] this
; -----------------------------------------------------------------------------
zs_destroy proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    test    rcx, rcx
    jz      zdy_ret
    mov     rcx, qword ptr [rcx+ZS_buf]
    test    rcx, rcx
    jz      @F
    mov     r10, qword ptr [rbp-16]
    mov     rdx, qword ptr [r10+ZS_len]
    call    mem_free
@@:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, 1
    call    tagged_free
zdy_ret:
    FRAME_EPILOG
    ret
zs_destroy endp

; -----------------------------------------------------------------------------
; zs_create(rcx = data-object item, rdx = wide container path) -> IStream* / 0
;
; An ITEM, not a bare index entry, because a zip entry is located by NAME and
; the name lives at DI_uname - the item's own copy of it.  es_create takes the
; entry's fixed part alone and needs nothing else; this one does.
;
; A DIRECTORY yields an empty stream without going near the archive.  A zip's
; listing contains folder rows that have no central-directory header at all -
; zidx_parents synthesises the parents of "a/b/c.txt" so the tree can be shown -
; so looking one up would fail, and failing would abort a whole copy over a
; folder that is only there to hold the shape.
; locals: [rbp-16] entry [rbp-24] path [rbp-32] this
;         [rbp-48] out.ptr, [rbp-40] out.len - one 16-byte area, low end first
; -----------------------------------------------------------------------------
public zs_create
zs_create proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-48], 0
    mov     qword ptr [rbp-40], 0
    test    dword ptr [rcx+IDXE_flags], IDXEF_DIR
    jnz     zcr_alloc
    mov     r8d, dword ptr [rcx+IDXE_namelen]
    lea     rdx, [rcx+DI_uname]
    mov     rcx, qword ptr [rbp-24]
    lea     r9, [rbp-48]
    call    zip_entry_to_mem
    test    eax, eax
    jnz     zcr_no
zcr_alloc:
    mov     rcx, ZS_BYTES
    call    tagged_alloc
    test    rax, rax
    jz      zcr_freebuf
    mov     qword ptr [rbp-32], rax
    mov     r10, rax
    lea     rax, [vtbl_ZipStream]
    mov     qword ptr [r10+ZS_vtbl], rax
    mov     dword ptr [r10+ZS_refs], 1
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [r10+ZS_buf], rax
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r10+ZS_len], rax
    mov     qword ptr [r10+ZS_pos], 0
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
zcr_freebuf:
    ; the bytes are already decrypted and there is now nothing to own them
    mov     rcx, qword ptr [rbp-48]
    test    rcx, rcx
    jz      zcr_no
    mov     rdx, qword ptr [rbp-40]
    call    mem_free
zcr_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
zs_create endp

; -----------------------------------------------------------------------------
; ZS_QueryInterface(rcx = this, rdx = riid, r8 = ppv)
; locals: [rbp-16] this [rbp-24] riid [rbp-32] ppv
; -----------------------------------------------------------------------------
ZS_QueryInterface proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    test    r8, r8
    jz      zqi_badarg
    mov     qword ptr [r8], 0
    test    rdx, rdx
    jz      zqi_badarg
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_stream
    test    eax, eax
    jnz     zqi_hand
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_seq
    test    eax, eax
    jnz     zqi_hand
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_unknown
    test    eax, eax
    jnz     zqi_hand
    mov     eax, E_NOINTERFACE
    jmp     zqi_ret
zqi_hand:
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [r10], rax
    mov     r11, qword ptr [rbp-16]
    lock inc dword ptr [r11+ZS_refs]
    mov     eax, S_OK
zqi_ret:
    FRAME_EPILOG
    ret
zqi_badarg:
    mov     eax, E_INVALIDARG
    FRAME_EPILOG
    ret
ZS_QueryInterface endp

ZS_AddRef proc
    mov     eax, 1
    lock xadd dword ptr [rcx+ZS_refs], eax
    inc     eax
    ret
ZS_AddRef endp

; locals: [rbp-16] this
ZS_Release proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     eax, -1
    lock xadd dword ptr [rcx+ZS_refs], eax
    dec     eax
    jnz     zrl_ret
    mov     rcx, qword ptr [rbp-16]
    call    zs_destroy
    xor     eax, eax
zrl_ret:
    FRAME_EPILOG
    ret
ZS_Release endp

; -----------------------------------------------------------------------------
; ZS_Read(rcx = this, rdx = pv, r8d = cb, r9 = pcbRead)
;
; cb is a ULONG, so the upper half of r8 is whatever the caller left there.
; locals: [rbp-16] this [rbp-24] pv [rbp-32] cb [rbp-40] pcbRead [rbp-48] n
; -----------------------------------------------------------------------------
ZS_Read proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     r8d, r8d
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], r9
    test    r9, r9
    jz      @F
    mov     dword ptr [r9], 0
@@:
    cmp     qword ptr [rbp-32], 0
    je      zrd_ok
    test    rdx, rdx
    jz      zrd_badarg
    ; n = min(cb, len - pos).  pos is never allowed past len, so this cannot
    ; wrap - ZS_Seek is the only thing that moves it and it refuses to overshoot.
    mov     rax, qword ptr [rcx+ZS_len]
    sub     rax, qword ptr [rcx+ZS_pos]
    cmp     rax, qword ptr [rbp-32]
    jbe     @F
    mov     rax, qword ptr [rbp-32]
@@:
    mov     qword ptr [rbp-48], rax
    test    rax, rax
    jz      zrd_ok
    mov     r10, qword ptr [rcx+ZS_buf]
    add     r10, qword ptr [rcx+ZS_pos]
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, r10
    mov     r8, rax
    call    es_copy
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-48]
    add     qword ptr [r10+ZS_pos], rax
zrd_ok:
    mov     r10, qword ptr [rbp-40]
    test    r10, r10
    jz      @F
    mov     rax, qword ptr [rbp-48]
    mov     dword ptr [r10], eax
@@:
    mov     eax, S_OK
    FRAME_EPILOG
    ret
zrd_badarg:
    mov     eax, E_INVALIDARG
    FRAME_EPILOG
    ret
ZS_Read endp

; -----------------------------------------------------------------------------
; ZS_Seek(rcx = this, rdx = dlibMove, r8d = dwOrigin, r9 = plibNewPosition)
;
; LARGE_INTEGER is eight bytes, so it arrives BY VALUE in rdx - the trap
; POINTL set for DT_DragEnter and ES_Seek documents too.
;
; All three origins, both directions: there is no sequential decoder to rewind.
; Seeking PAST the end is refused rather than allowed-then-read-as-zero, which
; keeps ZS_Read's subtraction from ever wrapping.  A negative move lands past
; the end once it is read unsigned, so one comparison rejects both.
; locals: [rbp-16] this [rbp-24] target
; -----------------------------------------------------------------------------
ZS_Seek proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    cmp     r8d, 0                          ; STREAM_SEEK_SET
    jne     @F
    mov     qword ptr [rbp-24], rdx
    jmp     zsk_have
@@:
    cmp     r8d, 1                          ; STREAM_SEEK_CUR
    jne     @F
    mov     rax, qword ptr [rcx+ZS_pos]
    add     rax, rdx
    mov     qword ptr [rbp-24], rax
    jmp     zsk_have
@@:
    cmp     r8d, 2                          ; STREAM_SEEK_END
    jne     zsk_nofunc
    mov     rax, qword ptr [rcx+ZS_len]
    add     rax, rdx
    mov     qword ptr [rbp-24], rax
zsk_have:
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [r10+ZS_len]
    ja      zsk_nofunc
    mov     qword ptr [r10+ZS_pos], rax
    test    r9, r9
    jz      @F
    mov     qword ptr [r9], rax
@@:
    mov     eax, S_OK
    FRAME_EPILOG
    ret
zsk_nofunc:
    mov     eax, STG_E_INVALIDFUNCTION
    FRAME_EPILOG
    ret
ZS_Seek endp

; -----------------------------------------------------------------------------
; ZS_Stat(rcx = this, rdx = pstatstg, r8d = grfStatFlag)
;
; cbSize must agree with what the file descriptor advertises or Explorer stops
; the copy early believing it is done.  Here they can DISAGREE in a way the
; .mrk stream's cannot: the descriptor's size comes from the listing, this one
; from what the reader actually produced.  That is the honest number - an entry
; whose header lied about its size is better reported at its real length than
; padded to a claim - and Explorer takes the descriptor's figure for the
; progress bar either way.  pwcsName is left null, as in ES_Stat.
; -----------------------------------------------------------------------------
ZS_Stat proc frame
    FRAME_PROLOG 48
    test    rdx, rdx
    jz      zst_badptr
    xor     eax, eax
    mov     r10, rdx
    mov     r11, SSTG_BYTES/8
@@:
    mov     qword ptr [r10], rax
    add     r10, 8
    dec     r11
    jnz     @B
    mov     dword ptr [rdx+SSTG_type], STGTY_STREAM
    mov     rax, qword ptr [rcx+ZS_len]
    mov     qword ptr [rdx+SSTG_cbSize], rax
    mov     dword ptr [rdx+SSTG_grfMode], 0  ; STGM_READ
    mov     eax, S_OK
    FRAME_EPILOG
    ret
zst_badptr:
    mov     eax, STG_E_INVALIDPOINTER
    FRAME_EPILOG
    ret
ZS_Stat endp

.const
align 8
; Clone is NOTIMPL here for a different reason than it is above: a second
; cursor over a buffer is entirely possible, it would just mean refcounting the
; buffer separately from the object, and nothing asks for it.
vtbl_ZipStream label qword
    dq      ZS_QueryInterface, ZS_AddRef, ZS_Release
    dq      ZS_Read, ES_Denied
    dq      ZS_Seek, ES_Denied, ES_NotImpl, ES_NotImpl, ES_NotImpl
    dq      ES_NotImpl, ES_NotImpl, ZS_Stat, ES_NotImpl

.code

; =============================================================================
; IDataObject + IEnumFORMATETC - the source side of the drag.
; -----------------------------------------------------------------------------
; Step 2 of docs/DRAG_OUT.md.  Two formats, and the pair is the whole point:
;
;   CFSTR_FILEDESCRIPTORW ("FileGroupDescriptorW"), TYMED_HGLOBAL - names and
;       sizes for every item, rendered on demand into one moveable block.
;   CFSTR_FILECONTENTS    ("FileContents"), TYMED_ISTREAM - one entry's bytes,
;       chosen by FORMATETC.lindex, produced as the IStream above.
;
; Nothing is decrypted until a target asks for contents, and a cancelled drag
; asks for nothing - so it writes nothing, which is the reason this exists
; rather than CF_HDROP over a temp folder.
;
; The object owns its own copy of the container path AND OF THE KEY.  Both are
; needed at GetData time, which is a long way after the drag started and after
; the GUI has wiped its globals; see entry_stream_open in pack.asm for why the
; key became a parameter.  Both die with the object, wiped by tagged_free.
;
; Names in the descriptor are LEAF names: dragging out sub/c.txt means dropping
; c.txt where the mouse went, not recreating "sub" there.  That leaves one gap,
; and it belongs to step 4 rather than here - two entries with the same leaf in
; different folders would collide within one drag.  Folder drags are where
; relative paths become the right answer, and they are the same step.
; =============================================================================

FE_cfFormat                 equ 0
FE_ptd                      equ 8
FE_dwAspect                 equ 16
FE_lindex                   equ 20
FE_tymed                    equ 24
FE_BYTES                    equ 32
STG_tymed                   equ 0
STG_handle                  equ 8
STG_pUnkForRelease          equ 16
STG_BYTES                   equ 24
DVASPECT_CONTENT            equ 1
TYMED_HGLOBAL               equ 1
TYMED_ISTREAM               equ 4
DATADIR_GET                 equ 1
S_FALSE                     equ 1
DV_E_FORMATETC              equ 80040064h
DV_E_TYMED                  equ 80040069h
DV_E_LINDEX                 equ 80040068h
DV_E_DVASPECT               equ 8004006Bh
OLE_E_ADVISENOTSUPPORTED    equ 80040003h
E_OUTOFMEMORY               equ 8007000Eh
GHND                        equ 42h          ; GMEM_MOVEABLE or GMEM_ZEROINIT
FILE_ATTR_NORMAL            equ 128
FILE_ATTR_DIR               equ 16

; FILEDESCRIPTORW - 592 bytes, every field 4-aligned.  cFileName is a fixed
; 260-WCHAR ARRAY, not a pointer, so a name that does not fit has to be refused
; rather than truncated: handing over a file under a name the user never had is
; worse than not handing it over.
FDW_dwFlags                 equ 0
FDW_dwFileAttributes        equ 36
FDW_nFileSizeHigh           equ 64
FDW_nFileSizeLow            equ 68
FDW_cFileName               equ 72
FDW_NAME_CHARS              equ 260
FDW_BYTES                   equ 592
FGD_cItems                  equ 0
FGD_fgd                     equ 4
FD_ATTRIBUTES               equ 4
FD_FILESIZE                 equ 40h

; One item: the index entry's fixed part verbatim - which is everything
; es_create reads - plus the wide leaf name the descriptor needs, plus the
; entry's OFFSET in g_idxbuf, which is what identifies it for the duplicate
; check.  The offset and not the ordinal: a zip's entries all carry ordinal
; zero (zidx_add_unique writes zeros, because a zip has no extent), so an
; ordinal match would have declared every zip row after the first a duplicate
; of the first and dragged out exactly one file.  An offset is unique for both
; kinds of container, and it is never dereferenced - only compared.
;
; And the entry's own name, in UTF-8, which is a THIRD name and not either of
; the other two: DI_wname is what the item is offered to the shell as (relative
; to the selection, backslashes), while this is what the entry is called inside
; the archive.  Only the zip half needs it - zip_entry_to_mem finds an entry by
; name, having no extent to seek to - but it is copied for the reason
; everything else here is copied: at GetData time the listing may have been
; rebuilt, and an object that reaches back into g_idxbuf to find out what it is
; describing is one reload away from describing something else.  A name that
; does not fit is refused, the same answer DI_wname gives.
DI_fixed                    equ 0
DI_wname                    equ IDXE_FIXED
DI_slot                     equ IDXE_FIXED + FDW_NAME_CHARS*2
DI_uname                    equ IDXE_FIXED + FDW_NAME_CHARS*2 + 8
DI_UNAME_BYTES              equ 520
DI_BYTES                    equ IDXE_FIXED + FDW_NAME_CHARS*2 + 8 + DI_UNAME_BYTES

DO_vtbl                     equ 0
DO_refs                     equ 8
DO_kind                     equ 12           ; 0 = .mrk stream, 1 = zip buffer
DO_count                    equ 16
DO_cap                      equ 24
DO_key                      equ 32           ; KEY_LEN bytes, this drag's own
DO_path                     equ 64           ; MAX_PATH_CHARS*2
DO_items                    equ 64 + MAX_PATH_CHARS*2
; Bounds the one allocation and nothing else: callers size the object to what
; they actually mean to offer (do_add_tree with a null object counts it), so
; this only stops an absurd index from asking for an absurd block.
DO_MAXITEMS                 equ 65536

EN_vtbl                     equ 0
EN_refs                     equ 8
EN_pos                      equ 16
EN_BYTES                    equ 24
EN_FORMATS                  equ 2
DRAGSEL_BYTES               equ 4096

.const
align 8
iid_es_dataobj  dd 00000010Eh                                   ; IID_IDataObject
                dw 00000h, 00000h
                db 0C0h,000h,000h,000h,000h,000h,000h,046h
iid_es_enumfmt  dd 000000103h                                   ; IID_IEnumFORMATETC
                dw 00000h, 00000h
                db 0C0h,000h,000h,000h,000h,000h,000h,046h
WSTR w_cf_fgd,  <FileGroupDescriptorW>
WSTR w_cf_fc,   <FileContents>
ifdef TEST_IO
w_dot_zip   dw '.','z','i','p',0
endif

.data?
align 4
g_cf_fgd    dd ?                            ; registered once, process-wide
g_cf_fc     dd ?
align 8
ifdef TEST_IO
g_do_fmt    db FE_BYTES dup (?)             ; the exerciser drives these; they
g_do_fmts   db (FE_BYTES*4) dup (?)         ; sit here rather than with the rest
g_do_med    db STG_BYTES dup (?)            ; because the equs above size them
g_dragsel   db DRAGSEL_BYTES dup (?)        ; the exerciser's selection, UTF-8
endif

.code

; -----------------------------------------------------------------------------
; do_regfmt -> eax 0 ok / 1 failed.
;
; RegisterClipboardFormatW returns the same id for a given name for the life of
; the session, so asking twice is free - but the ids are NOT constants and must
; never be hardcoded.
; -----------------------------------------------------------------------------
do_regfmt proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_cf_fgd], 0
    je      drf_reg
    cmp     dword ptr [g_cf_fc], 0
    jne     drf_ok
drf_reg:
    WINCALL RegisterClipboardFormatW, addr w_cf_fgd
    test    eax, eax
    jz      drf_fail
    mov     dword ptr [g_cf_fgd], eax
    WINCALL RegisterClipboardFormatW, addr w_cf_fc
    test    eax, eax
    jz      drf_fail
    mov     dword ptr [g_cf_fc], eax
drf_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
drf_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
do_regfmt endp

; -----------------------------------------------------------------------------
; do_destroy(rcx = this) - wipe and release.  The key is in here.
; -----------------------------------------------------------------------------
do_destroy proc frame
    FRAME_PROLOG 48
    test    rcx, rcx
    jz      ddy_ret
    mov     rdx, 1                          ; wipe: the key and the path
    call    tagged_free
ddy_ret:
    FRAME_EPILOG
    ret
do_destroy endp

; -----------------------------------------------------------------------------
; do_create(rcx = wide container path, rdx = key or 0, r8 = capacity,
;           r9d = kind: 0 = .mrk, 1 = zip)
;   -> rax = IDataObject* or 0
;
; A zip passes no key.  Its entries are opened with the password still in
; g_cfg_pass - see the ZS object's header for why that is not copied in here.
; locals: [rbp-16] path [rbp-24] key [rbp-32] cap [rbp-40] this [rbp-48] kind
; -----------------------------------------------------------------------------
public do_create
do_create proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    mov     dword ptr [rbp-48], r9d
    mov     qword ptr [rbp-40], 0
    test    r8, r8
    jz      dcr_no
    cmp     r8, DO_MAXITEMS
    ja      dcr_no
    call    do_regfmt
    test    eax, eax
    jnz     dcr_no
    mov     rax, qword ptr [rbp-32]
    mov     r10, DI_BYTES
    mul     r10                             ; capacity is bounded above, so this
    add     rax, DO_items                   ; cannot come near an overflow
    mov     rcx, rax
    call    tagged_alloc
    test    rax, rax
    jz      dcr_no
    mov     qword ptr [rbp-40], rax
    mov     r10, rax
    lea     rax, [vtbl_DataObject]
    mov     qword ptr [r10+DO_vtbl], rax
    mov     dword ptr [r10+DO_refs], 1
    mov     qword ptr [r10+DO_count], 0
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+DO_cap], rax
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [r10+DO_kind], eax
    ; the key, copied.  From here the object is self-sufficient: the caller is
    ; free to wipe the global the moment this returns.  A zip passes none, and
    ; the field stays as tagged_alloc left it.
    cmp     qword ptr [rbp-24], 0
    je      dcr_nokey
    lea     rcx, [r10+DO_key]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, KEY_LEN
    call    es_copy
dcr_nokey:
    ; and the path, bounded by what the buffer holds
    mov     r10, qword ptr [rbp-40]
    mov     r11, qword ptr [rbp-16]
    xor     r9, r9
dcr_path:
    cmp     r9, MAX_PATH_CHARS-1
    jae     dcr_pdone
    mov     ax, word ptr [r11+r9*2]
    mov     word ptr [r10+DO_path+r9*2], ax
    test    ax, ax
    jz      dcr_done
    inc     r9
    jmp     dcr_path
dcr_pdone:
    mov     word ptr [r10+DO_path+r9*2], 0
dcr_done:
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
dcr_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
do_create endp

; -----------------------------------------------------------------------------
; do_item(rcx = this, rdx = index) -> rax = item pointer.  Clobbers rdx (mul).
; -----------------------------------------------------------------------------
do_item proc
    mov     rax, rdx
    mov     r10, DI_BYTES
    mul     r10
    add     rax, DO_items
    add     rax, rcx
    ret
do_item endp

; -----------------------------------------------------------------------------
; do_additem(rcx = this, rdx = index entry, r8 = utf8 name, r9 = name length)
;   -> eax 0 added / 1 refused
;
; The NAME is given rather than derived, because only the caller knows what the
; drag is relative to: dragging sub/c.txt out means dropping c.txt, but dragging
; the folder sub means dropping sub\c.txt.  do_add_tree below is what works that
; out; this just records the answer.
;
; The entry's fixed part is COPIED, so a reload of g_idxbuf during the drag
; cannot leave the object describing something that has moved - the rule
; es_create follows for the same reason.
;
; A DUPLICATE IS REFUSED, matched on where the entry sits in g_idxbuf - see
; DI_slot for why that and not the ordinal.  Selecting a folder AND something
; inside it is a thing people do by accident, and without this the same file
; would be offered twice under two different names - the shell would ask about
; a collision that only existed because we made it.  Rows are walked in display
; order, so the folder is seen first and its relative name is the one that
; survives, which is also the one the user asked for by selecting the folder.
;
; locals: [rbp-16] this [rbp-24] entry [rbp-32] item [rbp-40] name [rbp-48] len
;         [rbp-56] wide destination [rbp-64] scan cursor [rbp-72] slot
; -----------------------------------------------------------------------------
public do_additem
do_additem proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    test    r9, r9
    jz      dai_no
    mov     rax, qword ptr [rcx+DO_count]
    cmp     rax, qword ptr [rcx+DO_cap]
    jae     dai_no
    ; the entry's offset in g_idxbuf - its identity for the duplicate check
    mov     rax, qword ptr [g_idxptr]
    mov     r11, qword ptr [rbp-24]
    sub     r11, rax
    mov     qword ptr [rbp-72], r11
    ; ---- already offered? ---------------------------------------------------
    mov     qword ptr [rbp-64], 0
dai_dup:
    mov     rax, qword ptr [rbp-64]
    mov     r10, qword ptr [rbp-16]
    cmp     rax, qword ptr [r10+DO_count]
    jae     dai_fresh
    mov     rcx, r10
    mov     rdx, rax
    call    do_item
    mov     r11, qword ptr [rbp-72]
    cmp     r11, qword ptr [rax+DI_slot]
    je      dai_no
    inc     qword ptr [rbp-64]
    jmp     dai_dup
dai_fresh:
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rcx+DO_count]
    call    do_item
    mov     qword ptr [rbp-32], rax
    mov     r11, qword ptr [rbp-72]
    mov     qword ptr [rax+DI_slot], r11
    lea     rcx, [rax+DI_fixed]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, IDXE_FIXED
    call    es_copy
    ; the entry's own name, terminated - see DI_uname
    mov     r10, qword ptr [rbp-24]
    mov     r8d, dword ptr [r10+IDXE_namelen]
    cmp     r8, DI_UNAME_BYTES
    jae     dai_no
    mov     r11, qword ptr [rbp-32]
    lea     rcx, [r11+DI_uname]
    lea     rdx, [r10+IDXE_name]
    call    es_copy
    mov     r11, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+IDXE_namelen]
    mov     byte ptr [r11+rax+DI_uname], 0
    ; ---- the advertised name ------------------------------------------------
    ; Bounded at FDW_NAME_CHARS-1 so the terminator always fits.  A name that
    ; does not fit is REFUSED, not truncated: handing over a file under a name
    ; the user never had is worse than not handing it over.
    mov     r10, qword ptr [rbp-32]
    lea     rax, [r10+DI_wname]
    mov     qword ptr [rbp-56], rax
    WINCALL MultiByteToWideChar, CP_UTF8, 0, qword ptr [rbp-40], qword ptr [rbp-48], \
            qword ptr [rbp-56], FDW_NAME_CHARS-1
    test    eax, eax
    jle     dai_no
    cdqe
    mov     r10, qword ptr [rbp-56]
    mov     word ptr [r10+rax*2], 0
    ; archive names use '/'; a descriptor path uses '\', and that separator is
    ; what makes the shell recreate the folders on the way in
    xor     r9, r9
dai_sep:
    cmp     r9, rax
    jae     dai_done
    cmp     word ptr [r10+r9*2], 2Fh
    jne     @F
    mov     word ptr [r10+r9*2], 5Ch
@@:
    inc     r9
    jmp     dai_sep
dai_done:
    mov     r11, qword ptr [rbp-16]
    inc     qword ptr [r11+DO_count]
    xor     eax, eax
    FRAME_EPILOG
    ret
dai_no:
    mov     eax, 1
    FRAME_EPILOG
    ret
do_additem endp

; -----------------------------------------------------------------------------
; do_add_tree(rcx = this OR 0 to count only, rdx = utf8 entry path, r8 = length)
;   -> rax = items added, or how many WOULD be
;
; The zero case exists so a caller can size the object before building it: a
; folder expands to however many entries lie beneath it, which is not knowable
; from the selection.  Counting through the SAME walk is the point - a count
; that could disagree with the add is how a drag silently loses its tail.
;
; One selected thing, whatever it is.  A file adds itself; a FOLDER adds itself
; and every entry beneath it.  Either way the names offered are relative to the
; selection's PARENT, which is the rule that makes both cases read the way the
; gesture looks:
;
;   drag  sub/c.txt   ->  c.txt                       (parent is "sub/")
;   drag  sub         ->  sub, sub\c.txt, sub\d.txt   (parent is "")
;   drag  a/b         ->  b, b\...                    (parent is "a/")
;
; Directories are offered as items in their own right, with the directory
; attribute and no size.  The shell creates intermediate folders from the
; backslashes alone, so this is only strictly needed for EMPTY ones - but an
; empty folder silently vanishing from a copy is exactly the kind of quiet
; partial result this tool should not produce.  Their streams are real: a
; directory entry is a 512-byte tar header sealed like any other, so it
; authenticates like any other and yields zero content bytes.
;
; locals: [rbp-16] this [rbp-24] path [rbp-32] len [rbp-40] baselen
;         [rbp-48] cursor [rbp-56] left [rbp-64] added [rbp-72] next cursor
; -----------------------------------------------------------------------------
public do_add_tree
do_add_tree proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-64], 0
    test    r8, r8
    jz      dat_ret
    ; baselen: one past the last '/', or 0 - the selection's parent
    mov     qword ptr [rbp-40], 0
    xor     r9, r9
dat_base:
    cmp     r9, qword ptr [rbp-32]
    jae     dat_walk
    mov     r10, qword ptr [rbp-24]
    cmp     byte ptr [r10+r9], '/'
    jne     @F
    lea     rax, [r9+1]
    mov     qword ptr [rbp-40], rax
@@:
    inc     r9
    jmp     dat_base
dat_walk:
    mov     qword ptr [rbp-48], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-56], rax
dat_next:
    cmp     qword ptr [rbp-56], 0
    je      dat_ret
    ; the same bounds discipline do_list uses: the table is authentic, but a
    ; container written by a future version could still describe an entry that
    ; runs off the end of it
    mov     rax, qword ptr [rbp-48]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      dat_ret
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-48]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      dat_ret
    mov     qword ptr [rbp-72], rax
    ; does this entry belong to the selection?
    mov     r11d, dword ptr [r10+IDXE_namelen]
    cmp     r11, qword ptr [rbp-32]
    jb      dat_skip                        ; shorter than the selection: no
    je      dat_maybe_self
    ; longer: it is inside only if the selection is followed by a separator
    lea     rax, [r10+IDXE_name]
    add     rax, qword ptr [rbp-32]
    cmp     byte ptr [rax], '/'
    jne     dat_skip
dat_maybe_self:
    lea     rcx, [r10+IDXE_name]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    es_bytes_equal
    test    eax, eax
    jz      dat_skip
    ; relative to the selection's parent
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-48]
    cmp     qword ptr [rbp-16], 0
    je      dat_tally                       ; counting: no object to add to
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, r10
    lea     r8, [r10+IDXE_name]
    add     r8, qword ptr [rbp-40]
    mov     r9d, dword ptr [r10+IDXE_namelen]
    sub     r9, qword ptr [rbp-40]
    call    do_additem
    test    eax, eax
    jnz     dat_skip
dat_tally:
    inc     qword ptr [rbp-64]
dat_skip:
    mov     rax, qword ptr [rbp-72]
    mov     qword ptr [rbp-48], rax
    dec     qword ptr [rbp-56]
    jmp     dat_next
dat_ret:
    mov     rax, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
do_add_tree endp

; -----------------------------------------------------------------------------
; es_bytes_equal(rcx = a, rdx = b, r8 = len) -> eax = 1 if equal
; Names, not secrets: this is a plain compare and does not need to be constant
; time.  ct_memcmp is for the tag.
; -----------------------------------------------------------------------------
es_bytes_equal proc
    test    r8, r8
    jz      ebe_yes
    xor     r9, r9
ebe_loop:
    mov     al, byte ptr [rcx+r9]
    cmp     al, byte ptr [rdx+r9]
    jne     ebe_no
    inc     r9
    cmp     r9, r8
    jb      ebe_loop
ebe_yes:
    mov     eax, 1
    ret
ebe_no:
    xor     eax, eax
    ret
es_bytes_equal endp

; -----------------------------------------------------------------------------
; do_build_fgd(rcx = this) -> rax = HGLOBAL or 0
;
; Rendered on demand, once per GetData, because the target OWNS what it is
; handed and will GlobalFree it - returning the same block twice would be a
; double free in someone else's process.
; locals: [rbp-16] this [rbp-24] hglobal [rbp-32] base [rbp-40] i [rbp-48] fd
; -----------------------------------------------------------------------------
do_build_fgd proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-16], rcx
    mov     rax, qword ptr [rcx+DO_count]
    mov     r10, FDW_BYTES
    mul     r10
    add     rax, FGD_fgd
    WINCALL GlobalAlloc, GHND, rax
    test    rax, rax
    jz      dbf_no
    mov     qword ptr [rbp-24], rax
    WINCALL GlobalLock, rax
    test    rax, rax
    jz      dbf_free
    mov     qword ptr [rbp-32], rax
    mov     r10, qword ptr [rbp-16]
    mov     rax, qword ptr [r10+DO_count]
    mov     r11, qword ptr [rbp-32]
    mov     dword ptr [r11+FGD_cItems], eax
    mov     qword ptr [rbp-40], 0
dbf_each:
    mov     rax, qword ptr [rbp-40]
    mov     r10, qword ptr [rbp-16]
    cmp     rax, qword ptr [r10+DO_count]
    jae     dbf_unlock
    mov     r11, FDW_BYTES
    mul     r11
    add     rax, FGD_fgd
    add     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-48], rax         ; -> this FILEDESCRIPTORW
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, qword ptr [rbp-40]
    call    do_item
    mov     r11, qword ptr [rbp-48]
    ; A folder advertises no size at all - FD_FILESIZE left out rather than set
    ; to zero, because a zero-byte FILE and a FOLDER are different things and
    ; the flag is what distinguishes them.
    test    dword ptr [rax+IDXE_flags], IDXEF_DIR
    jz      dbf_file
    mov     dword ptr [r11+FDW_dwFlags], FD_ATTRIBUTES
    mov     dword ptr [r11+FDW_dwFileAttributes], FILE_ATTR_DIR
    jmp     dbf_named
dbf_file:
    ; FD_PROGRESSUI (0x4000) is NOT set, and its equ is gone so nothing can set
    ; it back by habit.  It is the documented way to ASK the shell for a
    ; progress indicator, and what it gives is the old Vista-era copy dialog -
    ; which is what appeared over a drag-out and is not something this window
    ; should be summoning.  Without it Explorer transfers quietly.
    ;
    ; The cost is real and worth stating: a large entry now drags with no
    ; feedback at all.  FD_FILESIZE still tells the shell how big it is, so it
    ; can still raise its own UI if it decides the transfer is slow enough to
    ; warrant one - that decision is now the shell's rather than ours.
    mov     dword ptr [r11+FDW_dwFlags], (FD_ATTRIBUTES or FD_FILESIZE)
    mov     dword ptr [r11+FDW_dwFileAttributes], FILE_ATTR_NORMAL
    mov     r10, qword ptr [rax+IDXE_size]
    mov     dword ptr [r11+FDW_nFileSizeLow], r10d
    shr     r10, 32
    mov     dword ptr [r11+FDW_nFileSizeHigh], r10d
dbf_named:
    lea     rcx, [r11+FDW_cFileName]
    lea     rdx, [rax+DI_wname]
    mov     r8, FDW_NAME_CHARS*2
    call    es_copy
    inc     qword ptr [rbp-40]
    jmp     dbf_each
dbf_unlock:
    WINCALL GlobalUnlock, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
dbf_free:
    WINCALL GlobalFree, qword ptr [rbp-24]
dbf_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
do_build_fgd endp

; -----------------------------------------------------------------------------
; do_match(rcx = this, rdx = pformatetc, r8 = *kind) -> eax = HRESULT
; kind 0 = the descriptor, 1 = contents.  GetData and QueryGetData are asking
; the same question and have to answer it identically, so they ask it once.
; locals: [rbp-16] kind out
; -----------------------------------------------------------------------------
do_match proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], r8
    mov     dword ptr [r8], -1
    cmp     dword ptr [rdx+FE_dwAspect], DVASPECT_CONTENT
    jne     dmt_aspect
    movzx   eax, word ptr [rdx+FE_cfFormat]
    cmp     eax, dword ptr [g_cf_fgd]
    jne     dmt_try_fc
    test    dword ptr [rdx+FE_tymed], TYMED_HGLOBAL
    jz      dmt_tymed
    mov     r10, qword ptr [rbp-16]
    mov     dword ptr [r10], 0
    jmp     dmt_ok
dmt_try_fc:
    cmp     eax, dword ptr [g_cf_fc]
    jne     dmt_fmt
    test    dword ptr [rdx+FE_tymed], TYMED_ISTREAM
    jz      dmt_tymed
    mov     r10, qword ptr [rbp-16]
    mov     dword ptr [r10], 1
dmt_ok:
    mov     eax, S_OK
    FRAME_EPILOG
    ret
dmt_fmt:
    mov     eax, DV_E_FORMATETC
    FRAME_EPILOG
    ret
dmt_tymed:
    mov     eax, DV_E_TYMED
    FRAME_EPILOG
    ret
dmt_aspect:
    mov     eax, DV_E_DVASPECT
    FRAME_EPILOG
    ret
do_match endp

DO_NotImpl proc
    mov     eax, E_NOTIMPL
    ret
DO_NotImpl endp

DO_Advise proc
    mov     eax, OLE_E_ADVISENOTSUPPORTED
    ret
DO_Advise endp

; -----------------------------------------------------------------------------
; DO_QueryInterface(rcx = this, rdx = riid, r8 = ppv)
; locals: [rbp-16] this [rbp-24] riid [rbp-32] ppv
; -----------------------------------------------------------------------------
DO_QueryInterface proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    test    r8, r8
    jz      dqi2_badarg
    mov     qword ptr [r8], 0
    test    rdx, rdx
    jz      dqi2_badarg
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_dataobj
    test    eax, eax
    jnz     dqi2_hand
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_unknown
    test    eax, eax
    jnz     dqi2_hand
    mov     eax, E_NOINTERFACE
    jmp     dqi2_ret
dqi2_hand:
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [r10], rax
    mov     r11, qword ptr [rbp-16]
    lock inc dword ptr [r11+DO_refs]
    mov     eax, S_OK
    jmp     dqi2_ret
dqi2_badarg:
    mov     eax, E_INVALIDARG
dqi2_ret:
    FRAME_EPILOG
    ret
DO_QueryInterface endp

DO_AddRef proc
    mov     eax, 1
    lock xadd dword ptr [rcx+DO_refs], eax
    inc     eax
    ret
DO_AddRef endp

; Unlike the drop target's, this Release really does destroy: the object is
; per-drag and heap-allocated, and the shell decides when it is finished.
; locals: [rbp-16] this
DO_Release proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     eax, -1
    lock xadd dword ptr [rcx+DO_refs], eax
    dec     eax
    jnz     drl_ret
    mov     rcx, qword ptr [rbp-16]
    call    do_destroy
    xor     eax, eax
drl_ret:
    FRAME_EPILOG
    ret
DO_Release endp

; -----------------------------------------------------------------------------
; DO_GetData(rcx = this, rdx = pformatetcIn, r8 = pmedium)
;
; The medium is zeroed BEFORE anything can fail: a caller handed an error must
; not also be handed a tymed it will then try to release.
; locals: [rbp-16] this [rbp-24] fmt [rbp-32] medium [rbp-40] kind
; -----------------------------------------------------------------------------
DO_GetData proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    test    r8, r8
    jz      dgd_badarg
    mov     qword ptr [r8+STG_tymed], 0
    mov     qword ptr [r8+STG_handle], 0
    mov     qword ptr [r8+STG_pUnkForRelease], 0
    test    rdx, rdx
    jz      dgd_badarg
    lea     r8, [rbp-40]
    call    do_match
    test    eax, eax
    jnz     dgd_ret
    cmp     dword ptr [rbp-40], 0
    jne     dgd_contents
    ; ---- the descriptor -----------------------------------------------------
    mov     rcx, qword ptr [rbp-16]
    call    do_build_fgd
    test    rax, rax
    jz      dgd_oom
    mov     r10, qword ptr [rbp-32]
    mov     dword ptr [r10+STG_tymed], TYMED_HGLOBAL
    mov     qword ptr [r10+STG_handle], rax
    mov     eax, S_OK
    jmp     dgd_ret
dgd_contents:
    ; ---- one entry's bytes, chosen by lindex --------------------------------
    ; lindex is a LONG and can arrive negative - the enumerator itself offers
    ; -1.  Sign-extending and comparing UNSIGNED rejects that along with
    ; everything past the end, in one test.
    mov     r11, qword ptr [rbp-24]
    movsxd  rax, dword ptr [r11+FE_lindex]
    mov     r10, qword ptr [rbp-16]
    cmp     rax, qword ptr [r10+DO_count]
    jae     dgd_lindex
    mov     rcx, r10
    mov     rdx, rax
    call    do_item
    mov     r10, qword ptr [rbp-16]
    cmp     dword ptr [r10+DO_kind], 0
    jne     dgd_zip
    mov     rcx, rax
    lea     rdx, [r10+DO_path]
    lea     r8, [r10+DO_key]
    call    es_create
    jmp     dgd_stream
dgd_zip:
    mov     rcx, rax
    lea     rdx, [r10+DO_path]
    call    zs_create
dgd_stream:
    test    rax, rax
    jz      dgd_fail
    mov     r10, qword ptr [rbp-32]
    mov     dword ptr [r10+STG_tymed], TYMED_ISTREAM
    mov     qword ptr [r10+STG_handle], rax
    mov     eax, S_OK
    jmp     dgd_ret
dgd_lindex:
    mov     eax, DV_E_LINDEX
    jmp     dgd_ret
dgd_oom:
    mov     eax, E_OUTOFMEMORY
    jmp     dgd_ret
dgd_fail:
    mov     eax, E_FAIL
    jmp     dgd_ret
dgd_badarg:
    mov     eax, E_INVALIDARG
dgd_ret:
    FRAME_EPILOG
    ret
DO_GetData endp

; -----------------------------------------------------------------------------
; DO_QueryGetData(rcx = this, rdx = pformatetc) -> S_OK / DV_E_*
; locals: [rbp-16] kind (written by do_match, not read here)
; -----------------------------------------------------------------------------
DO_QueryGetData proc frame
    FRAME_PROLOG 48
    test    rdx, rdx
    jz      dqg_badarg
    lea     r8, [rbp-16]
    call    do_match
    FRAME_EPILOG
    ret
dqg_badarg:
    mov     eax, E_INVALIDARG
    FRAME_EPILOG
    ret
DO_QueryGetData endp

; -----------------------------------------------------------------------------
; DO_EnumFormatEtc(rcx = this, edx = dwDirection, r8 = ppenum)
; locals: [rbp-16] ppenum
; -----------------------------------------------------------------------------
DO_EnumFormatEtc proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], r8
    test    r8, r8
    jz      def_badarg
    mov     qword ptr [r8], 0
    cmp     edx, DATADIR_GET
    jne     def_notimpl                     ; SET: nothing here accepts data
    xor     rcx, rcx                        ; a fresh enumerator, at the start
    call    en_create
    test    rax, rax
    jz      def_oom
    mov     r10, qword ptr [rbp-16]
    mov     qword ptr [r10], rax
    mov     eax, S_OK
    FRAME_EPILOG
    ret
def_notimpl:
    mov     eax, E_NOTIMPL
    FRAME_EPILOG
    ret
def_oom:
    mov     eax, E_OUTOFMEMORY
    FRAME_EPILOG
    ret
def_badarg:
    mov     eax, E_INVALIDARG
    FRAME_EPILOG
    ret
DO_EnumFormatEtc endp

; -----------------------------------------------------------------------------
; IEnumFORMATETC.  Two formats, in the order a target should try them.
; -----------------------------------------------------------------------------

; en_create(rcx = starting position) -> rax = IEnumFORMATETC* or 0
; locals: [rbp-16] pos
en_create proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     rcx, EN_BYTES
    call    tagged_alloc
    test    rax, rax
    jz      enc_ret
    lea     r10, [vtbl_EnumFormat]
    mov     qword ptr [rax+EN_vtbl], r10
    mov     dword ptr [rax+EN_refs], 1
    mov     r10, qword ptr [rbp-16]
    mov     qword ptr [rax+EN_pos], r10
enc_ret:
    FRAME_EPILOG
    ret
en_create endp

; EN_QueryInterface(rcx = this, rdx = riid, r8 = ppv)
; locals: [rbp-16] this [rbp-24] riid [rbp-32] ppv
EN_QueryInterface proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    test    r8, r8
    jz      eqi2_badarg
    mov     qword ptr [r8], 0
    test    rdx, rdx
    jz      eqi2_badarg
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_enumfmt
    test    eax, eax
    jnz     eqi2_hand
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_unknown
    test    eax, eax
    jnz     eqi2_hand
    mov     eax, E_NOINTERFACE
    jmp     eqi2_ret
eqi2_hand:
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [r10], rax
    mov     r11, qword ptr [rbp-16]
    lock inc dword ptr [r11+EN_refs]
    mov     eax, S_OK
    jmp     eqi2_ret
eqi2_badarg:
    mov     eax, E_INVALIDARG
eqi2_ret:
    FRAME_EPILOG
    ret
EN_QueryInterface endp

EN_AddRef proc
    mov     eax, 1
    lock xadd dword ptr [rcx+EN_refs], eax
    inc     eax
    ret
EN_AddRef endp

; locals: [rbp-16] this
EN_Release proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     eax, -1
    lock xadd dword ptr [rcx+EN_refs], eax
    dec     eax
    jnz     erl2_ret
    mov     rcx, qword ptr [rbp-16]
    xor     rdx, rdx                        ; nothing secret in an enumerator
    call    tagged_free
    xor     eax, eax
erl2_ret:
    FRAME_EPILOG
    ret
EN_Release endp

; -----------------------------------------------------------------------------
; en_fill(rcx = FORMATETC*, rdx = which) - one enumerated format.
;
; lindex is -1 in the ENUMERATION even for FileContents: the enumerator says
; what is on offer, and the target names the item it wants when it calls
; GetData.  cfFormat is cleared as a qword because six bytes of padding follow
; it, and a target that memcmps the struct would otherwise compare garbage.
; -----------------------------------------------------------------------------
en_fill proc
    mov     qword ptr [rcx+FE_cfFormat], 0
    mov     qword ptr [rcx+FE_ptd], 0
    mov     dword ptr [rcx+FE_dwAspect], DVASPECT_CONTENT
    mov     dword ptr [rcx+FE_lindex], -1
    test    rdx, rdx
    jnz     enf_contents
    mov     eax, dword ptr [g_cf_fgd]
    mov     word ptr [rcx+FE_cfFormat], ax
    mov     dword ptr [rcx+FE_tymed], TYMED_HGLOBAL
    ret
enf_contents:
    mov     eax, dword ptr [g_cf_fc]
    mov     word ptr [rcx+FE_cfFormat], ax
    mov     dword ptr [rcx+FE_tymed], TYMED_ISTREAM
    ret
en_fill endp

; -----------------------------------------------------------------------------
; EN_Next(rcx = this, edx = celt, r8 = rgelt, r9 = pceltFetched)
; locals: [rbp-16] this [rbp-24] celt [rbp-32] rgelt [rbp-40] pceltFetched
;         [rbp-48] fetched
; -----------------------------------------------------------------------------
EN_Next proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx
    mov     edx, edx                        ; ULONG: drop the high half
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], r9
    mov     qword ptr [rbp-48], 0
    test    r8, r8
    jz      enx_badarg
    ; celt > 1 with nowhere to report the count is the one case the interface
    ; calls invalid, because the caller could not then tell how many it got.
    cmp     rdx, 1
    jbe     @F
    test    r9, r9
    jz      enx_badarg
@@:
    test    r9, r9
    jz      @F
    mov     dword ptr [r9], 0
@@:
enx_loop:
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [rbp-24]
    jae     enx_done
    mov     r10, qword ptr [rbp-16]
    cmp     qword ptr [r10+EN_pos], EN_FORMATS
    jae     enx_done
    mov     r11, FE_BYTES
    mul     r11
    add     rax, qword ptr [rbp-32]
    mov     rcx, rax
    mov     r10, qword ptr [rbp-16]
    mov     rdx, qword ptr [r10+EN_pos]
    call    en_fill
    mov     r10, qword ptr [rbp-16]
    inc     qword ptr [r10+EN_pos]
    inc     qword ptr [rbp-48]
    jmp     enx_loop
enx_done:
    mov     r10, qword ptr [rbp-40]
    test    r10, r10
    jz      @F
    mov     rax, qword ptr [rbp-48]
    mov     dword ptr [r10], eax
@@:
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [rbp-24]
    jne     enx_short
    mov     eax, S_OK
    FRAME_EPILOG
    ret
enx_short:
    mov     eax, S_FALSE
    FRAME_EPILOG
    ret
enx_badarg:
    mov     eax, E_INVALIDARG
    FRAME_EPILOG
    ret
EN_Next endp

; EN_Skip(rcx = this, edx = celt)
EN_Skip proc
    mov     edx, edx
    mov     rax, qword ptr [rcx+EN_pos]
    add     rax, rdx
    cmp     rax, EN_FORMATS
    ja      ensk_short
    mov     qword ptr [rcx+EN_pos], rax
    mov     eax, S_OK
    ret
ensk_short:
    mov     qword ptr [rcx+EN_pos], EN_FORMATS
    mov     eax, S_FALSE
    ret
EN_Skip endp

EN_Reset proc
    mov     qword ptr [rcx+EN_pos], 0
    mov     eax, S_OK
    ret
EN_Reset endp

; EN_Clone(rcx = this, rdx = ppenum).  Implementable, unlike the stream's: an
; enumerator is a cursor over two static formats and nothing else.
; locals: [rbp-16] ppenum
EN_Clone proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rdx
    test    rdx, rdx
    jz      encl_badarg
    mov     qword ptr [rdx], 0
    mov     rcx, qword ptr [rcx+EN_pos]
    call    en_create
    test    rax, rax
    jz      encl_oom
    mov     r10, qword ptr [rbp-16]
    mov     qword ptr [r10], rax
    mov     eax, S_OK
    FRAME_EPILOG
    ret
encl_oom:
    mov     eax, E_OUTOFMEMORY
    FRAME_EPILOG
    ret
encl_badarg:
    mov     eax, E_INVALIDARG
    FRAME_EPILOG
    ret
EN_Clone endp

.const
align 8
vtbl_DataObject label qword
    dq      DO_QueryInterface, DO_AddRef, DO_Release
    dq      DO_GetData, DO_NotImpl, DO_QueryGetData, DO_NotImpl, DO_NotImpl
    dq      DO_EnumFormatEtc, DO_Advise, DO_Advise, DO_Advise
vtbl_EnumFormat label qword
    dq      EN_QueryInterface, EN_AddRef, EN_Release
    dq      EN_Next, EN_Skip, EN_Reset, EN_Clone

.code


; =============================================================================
; IDropSource, and the drag itself.
; -----------------------------------------------------------------------------
; Step 3 of docs/DRAG_OUT.md - the smallest piece, and deliberately so: it is
; the only one no test here can drive (docs/UI_SURFACES.md records four attempts
; and why the last cannot work - DoDragDrop's SetCapture only takes effect for
; the foreground thread).  So it carries the least logic that will fit.
;
; ONE STATIC INSTANCE, like the drop target: a drag carries no state that
; QueryContinueDrag would have to allocate, there is one window, and DoDragDrop
; is synchronous - the source cannot outlive the call.  g_ds_refs exists only so
; Release has something to return.
;
; COPY ONLY.  Move would mean this source deletes the original afterwards, and
; it cannot: removing an entry from a container is a rewrite, not a delete, and
; it is not what dragging a file to the desktop should trigger.
; =============================================================================

DROPEFFECT_COPY_            equ 1
MK_LBUTTON                  equ 1
DRAGDROP_S_DROP             equ 00040100h
DRAGDROP_S_CANCEL           equ 00040101h
DRAGDROP_S_USEDEFAULTCURSORS equ 00040102h

.const
align 8
iid_es_dropsrc  dd 000000121h                                   ; IID_IDropSource
                dw 00000h, 00000h
                db 0C0h,000h,000h,000h,000h,000h,000h,046h

.data?
align 8
g_dropsrc   dq ?                            ; a vtable pointer and nothing else
g_ds_refs   dd ?
g_ds_effect dd ?                            ; DoDragDrop's out param
g_ds_kcv    db KCV_LEN dup (?)

.code

; -----------------------------------------------------------------------------
; DS_QueryInterface(rcx = this, rdx = riid, r8 = ppv)
; locals: [rbp-16] this [rbp-24] riid [rbp-32] ppv
; -----------------------------------------------------------------------------
DS_QueryInterface proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    test    r8, r8
    jz      sqi_badarg
    mov     qword ptr [r8], 0
    test    rdx, rdx
    jz      sqi_badarg
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_dropsrc
    test    eax, eax
    jnz     sqi_hand
    WINCALL es_guid_eq, qword ptr [rbp-24], addr iid_es_unknown
    test    eax, eax
    jnz     sqi_hand
    mov     eax, E_NOINTERFACE
    jmp     sqi_ret
sqi_hand:
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [r10], rax
    lock inc dword ptr [g_ds_refs]
    mov     eax, S_OK
    jmp     sqi_ret
sqi_badarg:
    mov     eax, E_INVALIDARG
sqi_ret:
    FRAME_EPILOG
    ret
DS_QueryInterface endp

DS_AddRef proc
    mov     eax, 1
    lock xadd dword ptr [g_ds_refs], eax
    inc     eax
    ret
DS_AddRef endp

; Never destroys: the object is static and outlives every drag.
DS_Release proc
    mov     eax, -1
    lock xadd dword ptr [g_ds_refs], eax
    dec     eax
    ret
DS_Release endp

; -----------------------------------------------------------------------------
; DS_QueryContinueDrag(rcx = this, edx = fEscapePressed, r8d = grfKeyState)
;
; The whole of the drag's control flow.  Escape cancels; letting go of the
; button drops; anything else keeps going.  fEscapePressed is a BOOL, so any
; non-zero counts.
; -----------------------------------------------------------------------------
DS_QueryContinueDrag proc
    test    edx, edx
    jnz     sqc_cancel
    test    r8d, MK_LBUTTON
    jz      sqc_drop
    mov     eax, S_OK
    ret
sqc_drop:
    mov     eax, DRAGDROP_S_DROP
    ret
sqc_cancel:
    mov     eax, DRAGDROP_S_CANCEL
    ret
DS_QueryContinueDrag endp

; The shell's own cursors say copy/no-drop better than anything here would, and
; getting them wrong is a drag that lies about what it will do.
DS_GiveFeedback proc
    mov     eax, DRAGDROP_S_USEDEFAULTCURSORS
    ret
DS_GiveFeedback endp

.const
align 8
vtbl_DropSource label qword
    dq      DS_QueryInterface, DS_AddRef, DS_Release
    dq      DS_QueryContinueDrag, DS_GiveFeedback

.code

; =============================================================================
; es_key_live -> eax 1 if g_key currently decrypts this container, else 0
;
; The drag has to be refused at the START or not at all.  IStream::Read is deep
; inside the target's copy loop: there is no window to prompt from and no way to
; say "the key went away" that arrives anywhere useful, so a drag begun without
; a key would fail silently halfway and Explorer would blame the file.
;
; The check is the one the container already carries - recompute the key-check
; value and compare it with the header's - so it cannot drift from what the
; readers do.  One SHA-256, which is nothing next to the Argon2 that produced
; the key.
; =============================================================================
es_key_live proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_ds_kcv]
    call    compute_kcv
    lea     rcx, [g_ds_kcv]
    lea     rdx, [g_pkhdr+KCV_OFFSET]
    mov     r8, KCV_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     ekl_no
    mov     eax, 1
    FRAME_EPILOG
    ret
ekl_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
es_key_live endp

; =============================================================================
; es_drag(rcx = IDataObject*) -> eax = DoDragDrop's HRESULT
;
; Synchronous: it does not return until the user drops or cancels, and the
; window's message loop is pumped by OLE for the duration.  The data object is
; NOT released here - the caller made it and the caller lets it go.
; locals: [rbp-16] data object
; =============================================================================
public es_drag
; The window's own progress bar runs the transfer, in place of the shell's copy
; dialog that FD_PROGRESSUI used to summon.  This is only possible because
; DoDragDrop is SYNCHRONOUS on the thread that owns the listing (docs/DRAG_OUT.md
; §4): the target's reads land in es_read on this thread, inside DoDragDrop's own
; modal loop, so the counters move and the loop dispatches the WM_TIMER that
; repaints. A free-threaded object would need something else entirely.
;
; The total is summed from the items rather than measured as it goes, because a
; bar that does not know where it is going is not a bar.
es_drag proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    ; ---- total bytes on offer ----------------------------------------------
    ; Each item begins with a copy of the index entry's fixed part, so IDXE_size
    ; is right there.  Folders carry 0 and add nothing, which is correct: they
    ; produce no bytes.
    xor     r9, r9                              ; running total
    xor     r10, r10                            ; index
    mov     r11, qword ptr [rbp-16]
esd_sum:
    cmp     r10, qword ptr [r11+DO_count]
    jae     esd_summed
    mov     rax, r10
    imul    rax, rax, DI_BYTES
    lea     rax, [r11+DO_items+rax]
    add     r9, qword ptr [rax+IDXE_size]
    inc     r10
    jmp     esd_sum
esd_summed:
    mov     qword ptr [rbp-24], r9
    mov     rcx, r9
    lea     rdx, [s_drag_lbl]
    mov     r8d, s_drag_lbl_len
    call    progress_begin
    mov     dword ptr [g_drag_prog], 1
    mov     dword ptr [g_prog_pct], 0
    ; SHOW it.  The bar is created ST_BARHIDE and only ever shown for an
    ; operation, so the first version of this drove a control nobody could see.
    mov     ecx, 1
    call    drag_prog_show
    ; ...and make the dragged ROWS follow it too.  g_cur_input 0 is what
    ; progress_add attributes to, and drag_rows_mark points exactly those rows
    ; at input 0 - see it for why per-entry attribution is not available.
    mov     qword ptr [g_cur_input], 0
    lea     r10, [g_file_total]
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10], rax
    lea     r10, [g_file_done]
    mov     qword ptr [r10], 0
    mov     ecx, 1
    call    drag_rows_mark
    lea     rax, [vtbl_DropSource]
    mov     qword ptr [g_dropsrc], rax
    mov     dword ptr [g_ds_refs], 1
    mov     dword ptr [g_ds_effect], 0
    WINCALL DoDragDrop, qword ptr [rbp-16], addr g_dropsrc, DROPEFFECT_COPY_, addr g_ds_effect
    ; ---- and put the bar back, on every outcome -----------------------------
    ; Including a cancelled or refused drag: the bar must not be left showing a
    ; transfer that is not happening.
    mov     dword ptr [g_drag_prog], 0
    call    progress_done
    mov     qword ptr [g_prog_total], 0
    mov     qword ptr [g_prog_done], 0
    mov     dword ptr [g_prog_pct], 0
    lea     r10, [g_file_total]
    mov     qword ptr [r10], 0
    lea     r10, [g_file_done]
    mov     qword ptr [r10], 0
    xor     ecx, ecx
    call    drag_rows_mark
    xor     ecx, ecx
    call    drag_prog_show
    FRAME_EPILOG
    ret
es_drag endp

; =============================================================================
; The exercisers.  TEST_IO only: they are how the three objects above are driven
; without a drag, and a release binary has no business carrying a way to script
; extraction.  Everything ABOVE this line ships.
; =============================================================================
ifdef TEST_IO

; =============================================================================
; es_out_path(rcx = index 0..9) - build g_cfg_out + "\es_<i>.bin" in g_es_path.
; =============================================================================
es_out_path proc frame
    FRAME_PROLOG 64
    ; [rbp-16] index [rbp-24] cursor
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], 0
    mov     r10, qword ptr [g_cfg_out]
    lea     r11, [g_es_path]
    xor     r9, r9
eop_copy:
    cmp     r9, 2000
    jae     eop_tail
    mov     ax, word ptr [r10+r9*2]
    test    ax, ax
    jz      eop_tail
    mov     word ptr [r11+r9*2], ax
    inc     r9
    jmp     eop_copy
eop_tail:
    mov     qword ptr [rbp-24], r9
    lea     r10, [w_es_sep]
    xor     r8, r8
eop_sep:
    mov     ax, word ptr [r10+r8*2]
    test    ax, ax
    jz      eop_digit
    mov     r9, qword ptr [rbp-24]
    mov     word ptr [r11+r9*2], ax
    inc     qword ptr [rbp-24]
    inc     r8
    jmp     eop_sep
eop_digit:
    mov     rax, qword ptr [rbp-16]
    add     rax, '0'
    mov     r9, qword ptr [rbp-24]
    mov     word ptr [r11+r9*2], ax
    inc     qword ptr [rbp-24]
    lea     r10, [w_es_ext]
    xor     r8, r8
eop_ext:
    mov     ax, word ptr [r10+r8*2]
    test    ax, ax
    jz      eop_term
    mov     r9, qword ptr [rbp-24]
    mov     word ptr [r11+r9*2], ax
    inc     qword ptr [rbp-24]
    inc     r8
    jmp     eop_ext
eop_term:
    mov     r9, qword ptr [rbp-24]
    mov     word ptr [r11+r9*2], 0
    FRAME_EPILOG
    ret
es_out_path endp

; =============================================================================
; do_estream - the exerciser.  TEST_IO only, and the only caller of any of the
; above until IDataObject lands.
;
;   myrkr estream CONTAINER OUTDIR -p PASSWORD
;
; It opens a stream for EVERY file entry (up to ES_TEST_MAX) at once and then
; reads them ROUND ROBIN, a prime number of bytes at a time.  That is the point
; of the test rather than a flourish: reading them one after another would pass
; just as happily against the global-state design this object exists to avoid,
; and interleaving is what a multi-file drag actually does.  The odd chunk size
; makes every read land off both the 16-byte GCM boundary and the 512-byte tar
; boundary.
;
; locals: [rbp-24] cursor into g_idxbuf [rbp-32] entries left [rbp-40] count
;         [rbp-48] live streams [rbp-56] loop index
; =============================================================================
public do_estream
do_estream proc frame
    FRAME_PROLOG 96
    mov     dword ptr [g_keep_key], 1       ; see the header: es_create needs it
    call    idx_read
    mov     dword ptr [g_keep_key], 0
    test    eax, eax
    jnz     des_wipe
    mov     qword ptr [rbp-24], 0
    mov     qword ptr [rbp-40], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-32], rax
des_next:
    cmp     qword ptr [rbp-32], 0
    je      des_built
    cmp     qword ptr [rbp-40], ES_TEST_MAX
    jae     des_built
    ; the same bounds discipline do_list uses: the table is authentic, but a
    ; container written by a future version could still describe an entry that
    ; runs off the end of it
    mov     rax, qword ptr [rbp-24]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      des_built
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      des_built
    mov     qword ptr [rbp-64], rax         ; cursor for the next entry
    test    dword ptr [r10+IDXE_flags], IDXEF_DIR
    jnz     des_skip
    mov     rcx, r10
    mov     rdx, qword ptr [g_cfg_in]
    lea     r8, [g_key]
    call    es_create
    test    rax, rax
    jz      des_cfail
    mov     r11, qword ptr [rbp-40]
    lea     r10, [g_es_objs]
    mov     qword ptr [r10+r11*8], rax
    mov     rcx, r11
    call    es_out_path
    lea     rcx, [g_es_path]
    call    file_open_write
    cmp     rax, INVALID
    je      des_iofail
    mov     r11, qword ptr [rbp-40]
    lea     r10, [g_es_files]
    mov     qword ptr [r10+r11*8], rax
    ; Stat and Seek, through the vtable, before a byte is read.
    ;
    ; Stat's cbSize is not decoration: it has to match what the file descriptor
    ; advertises or Explorer stops the copy early believing it is done.  Seek is
    ; here for the argument shape - dlibMove is a LARGE_INTEGER passed BY VALUE
    ; in rdx, the same trap POINTL sets for DragEnter - so a zero-offset tell
    ; that comes back S_OK with position 0 says the decode is right.
    ; poisoned first, so a method that returns S_OK without writing anything
    ; fails this rather than passing on a zero that was already there
    mov     qword ptr [g_es_stat+SSTG_cbSize], -1
    mov     qword ptr [g_es_tell], -1
    mov     r11, qword ptr [rbp-40]
    lea     r10, [g_es_objs]
    mov     r11, qword ptr [r10+r11*8]
    mov     rax, qword ptr [r11]
    mov     rcx, r11
    lea     rdx, [g_es_stat]
    xor     r8d, r8d
    call    qword ptr [rax+96]              ; slot 12 = Stat
    test    eax, eax
    jnz     des_ifail
    mov     rax, qword ptr [rbp-40]
    lea     r10, [g_es_objs]
    mov     r11, qword ptr [r10+rax*8]
    mov     rax, qword ptr [r11]
    mov     rcx, r11
    xor     rdx, rdx                        ; dlibMove = 0, by value
    mov     r8d, 1                          ; STREAM_SEEK_CUR
    lea     r9, [g_es_tell]
    call    qword ptr [rax+40]              ; slot 5 = Seek
    test    eax, eax
    jnz     des_ifail
    cmp     qword ptr [g_es_tell], 0
    jne     des_ifail
    ; name the mapping, so a test can compare es_<i>.bin against the right file
    ; rather than against whatever has the same length, and print the size Stat
    ; reported so the test can check that too
    mov     rcx, qword ptr [rbp-40]
    call    print_u64
    prn_a   msg_es_sep
    mov     rcx, qword ptr [g_es_stat+SSTG_cbSize]
    call    print_u64
    prn_a   msg_es_sep
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    lea     rcx, [r10+IDXE_name]
    mov     edx, dword ptr [r10+IDXE_namelen]
    call    print_a
    prn_a   msg_es_nl
    inc     qword ptr [rbp-40]
des_skip:
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [rbp-24], rax
    dec     qword ptr [rbp-32]
    jmp     des_next
des_built:
    ; Every stream now carries its own expanded round keys, so the global copy
    ; has no further use - and a drag that lasts as long as a copy dialogue has
    ; no business leaving one lying about.
    lea     rcx, [g_key]
    mov     rdx, KEY_LEN
    call    secure_zero
    cmp     qword ptr [rbp-40], 0
    je      des_none
    mov     rcx, qword ptr [rbp-40]
    call    es_pump
    test    eax, eax
    jz      des_done
    cmp     eax, EXIT_IO
    je      des_iofail
    jmp     des_rfail
des_done:
    prn_a   msg_es_ok
    mov     rcx, qword ptr [rbp-40]
    call    print_u64
    prn_a   msg_es_nl
    xor     eax, eax
    FRAME_EPILOG
    ret
des_none:
    prn     e_es_none
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
des_cfail:
    prn     e_es_create
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
des_ifail:
    prn     e_es_iface
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
des_rfail:
    prn     e_es_read
    mov     eax, EXIT_AUTH
    FRAME_EPILOG
    ret
des_iofail:
    prn     e_es_io
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
des_wipe:
    mov     dword ptr [rbp-72], eax
    lea     rcx, [g_key]
    mov     rdx, KEY_LEN
    call    secure_zero
    mov     eax, dword ptr [rbp-72]
    FRAME_EPILOG
    ret
do_estream endp

; =============================================================================
; es_pump(rcx = count) -> eax 0 ok / EXIT_AUTH read failed / EXIT_IO write failed
;
; Reads g_es_objs[0..count) ROUND ROBIN into g_es_files[0..count), a prime
; number of bytes at a time, releasing and closing each as it ends.
;
; The interleaving is the test, not a flourish.  Reading the streams one after
; another would pass just as happily against the global-state design estream.asm
; exists to avoid, and a multi-file drag is exactly this: several streams open
; at once, pulled at whatever rate the target feels like.  The odd chunk size
; puts every read off both the 16-byte GCM boundary and the 512-byte tar one.
;
; locals: [rbp-16] count [rbp-24] live [rbp-32] i
; =============================================================================
es_pump proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rcx
esp_round:
    cmp     qword ptr [rbp-24], 0
    je      esp_ok
    mov     qword ptr [rbp-32], 0
esp_each:
    mov     rax, qword ptr [rbp-32]
    cmp     rax, qword ptr [rbp-16]
    jae     esp_round
    lea     r10, [g_es_objs]
    mov     r11, qword ptr [r10+rax*8]
    test    r11, r11
    jz      esp_step
    ; pStream->Read(g_es_buf, ES_TEST_CHUNK, &g_es_got)
    mov     dword ptr [g_es_got], 0
    mov     rax, qword ptr [r11]
    mov     rcx, r11
    lea     rdx, [g_es_buf]
    mov     r8d, ES_TEST_CHUNK
    lea     r9, [g_es_got]
    call    qword ptr [rax+24]              ; slot 3 = Read
    test    eax, eax
    jnz     esp_rfail
    cmp     dword ptr [g_es_got], 0
    je      esp_close
    mov     rax, qword ptr [rbp-32]
    lea     r10, [g_es_files]
    mov     rcx, qword ptr [r10+rax*8]
    lea     rdx, [g_es_buf]
    mov     r8d, dword ptr [g_es_got]
    call    file_write_all
    test    eax, eax
    jnz     esp_iofail
    jmp     esp_step
esp_close:
    mov     rax, qword ptr [rbp-32]
    lea     r10, [g_es_objs]
    mov     r11, qword ptr [r10+rax*8]
    mov     qword ptr [r10+rax*8], 0
    mov     rax, qword ptr [r11]
    mov     rcx, r11
    call    qword ptr [rax+16]              ; slot 2 = Release
    mov     rax, qword ptr [rbp-32]
    lea     r10, [g_es_files]
    mov     rcx, qword ptr [r10+rax*8]
    call    file_close
    dec     qword ptr [rbp-24]
esp_step:
    inc     qword ptr [rbp-32]
    jmp     esp_each
esp_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
esp_rfail:
    mov     eax, EXIT_AUTH
    FRAME_EPILOG
    ret
esp_iofail:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
es_pump endp

; =============================================================================
; dd_kind -> eax 1 if g_cfg_in names a .zip, 0 otherwise.  TEST_IO only.
;
; By EXTENSION, and that is enough here but not in the GUI: do_open reads the
; local-file signature as well, because a user can hand it anything.  A test
; names its own input.
; =============================================================================
dd_kind proc
    mov     r10, qword ptr [g_cfg_in]
    test    r10, r10
    jz      ddk_no
    xor     r9, r9
ddk_len:
    cmp     word ptr [r10+r9*2], 0
    je      ddk_have
    inc     r9
    cmp     r9, MAX_PATH_CHARS
    jb      ddk_len
    jmp     ddk_no
ddk_have:
    cmp     r9, 4
    jb      ddk_no
    sub     r9, 4
    lea     r10, [r10+r9*2]                 ; the last four characters
    lea     r11, [w_dot_zip]
    xor     r8, r8
ddk_c:
    cmp     r8, 4
    jae     ddk_yes
    movzx   eax, word ptr [r10+r8*2]
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 32                         ; fold, so ".ZIP" counts
@@:
    movzx   edx, word ptr [r11+r8*2]
    cmp     eax, edx
    jne     ddk_no
    inc     r8
    jmp     ddk_c
ddk_yes:
    mov     eax, 1
    ret
ddk_no:
    xor     eax, eax
    ret
dd_kind endp

; =============================================================================
; do_dataobj - the step 2 exerciser.  TEST_IO only.
;
;   myrkr dataobj CONTAINER -o OUTDIR -p PASSWORD
;
; Builds the IDataObject over every file entry and then drives it the way a
; drop target would, entirely through vtables: QueryInterface, EnumFormatEtc +
; Next, QueryGetData, GetData for the descriptor, GetData for each entry's
; contents, and GetData for an lindex that does not exist.  Explorer's own copy
; loop is the one thing left outside, and that is the same boundary the drop
; target has and the same answer: it is Microsoft's code.
;
; THE KEY IS WIPED the moment the object exists, before a single GetData.  That
; is not tidiness - it is the assertion that the object really is self-contained,
; and it is the difference between this working in a drag and working only in a
; test.  It failed exactly here the first time.
;
; A .zip is accepted too, and everything after the listing is identical: the
; object is driven exactly the same way and the assertions are the same ones.
; That is the point of putting the kind inside do_create rather than at the
; call sites - one exerciser covers both, and the zip half of DO_GetData is not
; a path only the GUI can reach.
;
; locals: [rbp-24] cursor [rbp-32] entries left [rbp-40] count [rbp-48] dataobj
;         [rbp-56] i [rbp-64] next cursor [rbp-72] scratch/exit [rbp-96] kind
; =============================================================================
public do_dataobj
do_dataobj proc frame
    FRAME_PROLOG 160                        ; locals reach [rbp-96]; at 96 they
                                            ; ended exactly where GlobalLock's
                                            ; outgoing area began
    mov     qword ptr [rbp-48], 0
    call    dd_kind
    mov     dword ptr [rbp-96], eax
    test    eax, eax
    jz      ddo_mrk
    mov     rcx, qword ptr [g_cfg_in]
    call    zip_to_index                    ; no key, no g_keep_key: a zip's
    jmp     ddo_listed                      ; entries open from g_cfg_pass
ddo_mrk:
    mov     dword ptr [g_keep_key], 1
    call    idx_read
    mov     dword ptr [g_keep_key], 0
ddo_listed:
    test    eax, eax
    jnz     ddo_wipe
    cmp     qword ptr [g_idxcount], 0
    je      ddo_none
    ; one object, sized to the whole listing; directories are refused by
    ; do_additem and simply do not become items
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_key]
    cmp     dword ptr [rbp-96], 0
    je      @F
    xor     rdx, rdx
@@:
    mov     r8, qword ptr [g_idxcount]
    mov     r9d, dword ptr [rbp-96]
    call    do_create
    test    rax, rax
    jz      ddo_cfail
    mov     qword ptr [rbp-48], rax
    ; An explicit SELECTION, if one was given: "myrkr dataobj C.mrk sub -o OUT"
    ; drags exactly that entry as a drag would, which is the only way to test
    ; the naming rule for something that is not at the top level - a nested file
    ; must come out under its LEAF name, and a nested folder under its own name
    ; plus everything beneath it, both relative to the selection's parent.
    cmp     qword ptr [g_poscount], 2
    jb      ddo_toplevel
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+8]
    mov     qword ptr [rbp-80], rcx
    WINCALL WideCharToMultiByte, CP_UTF8, 0, qword ptr [rbp-80], -1, addr g_dragsel, DRAGSEL_BYTES, 0, 0
    test    eax, eax
    jle     ddo_cfail
    dec     eax                                 ; drop the terminator
    jz      ddo_cfail
    cdqe
    mov     qword ptr [rbp-88], rax
    lea     r11, [g_dragsel]
    xor     r9, r9
ddo_sel_sep:
    cmp     r9, qword ptr [rbp-88]
    jae     ddo_sel_go
    cmp     byte ptr [r11+r9], 5Ch
    jne     @F
    mov     byte ptr [r11+r9], 2Fh
@@:
    inc     r9
    jmp     ddo_sel_sep
ddo_sel_go:
    mov     rcx, qword ptr [rbp-48]
    lea     rdx, [g_dragsel]
    mov     r8, qword ptr [rbp-88]
    call    do_add_tree
    jmp     ddo_built
ddo_toplevel:
    mov     qword ptr [rbp-24], 0
    mov     rax, qword ptr [g_idxcount]
    mov     qword ptr [rbp-32], rax
ddo_next:
    cmp     qword ptr [rbp-32], 0
    je      ddo_built
    ; the same bounds discipline do_list uses
    mov     rax, qword ptr [rbp-24]
    add     rax, IDXE_FIXED
    cmp     rax, qword ptr [g_idxlen]
    ja      ddo_built
    mov     r10, qword ptr [g_idxptr]
    add     r10, qword ptr [rbp-24]
    mov     r11d, dword ptr [r10+IDXE_namelen]
    add     rax, r11
    cmp     rax, qword ptr [g_idxlen]
    ja      ddo_built
    mov     qword ptr [rbp-64], rax
    ; Only TOP-LEVEL entries, expanded as trees.  That is what dragging the
    ; whole of a container out looks like, and it is the only shape that
    ; exercises the relative naming: a top-level folder brings everything under
    ; it, named relative to the container root.  Entries nested inside one are
    ; reached that way, and do_additem refuses them the second time.
    mov     rcx, qword ptr [rbp-48]
    lea     rdx, [r10+IDXE_name]
    mov     r8d, dword ptr [r10+IDXE_namelen]
    call    do_add_tree
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [rbp-24], rax
    dec     qword ptr [rbp-32]
    jmp     ddo_next
ddo_built:
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10+DO_count]
    mov     qword ptr [rbp-40], rax
    test    rax, rax
    jz      ddo_none
    ; ---- the key dies here, before anything is asked of the object ----------
    lea     rcx, [g_key]
    mov     rdx, KEY_LEN
    call    secure_zero

    ; ---- QueryInterface ----------------------------------------------------
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    lea     rdx, [iid_es_dataobj]
    lea     r8, [g_do_unk]
    call    qword ptr [rax+0]
    test    eax, eax
    jnz     ddo_ifail
    cmp     qword ptr [g_do_unk], 0
    je      ddo_ifail
    ; and the one it must refuse
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    lea     rdx, [iid_es_stream]
    lea     r8, [g_do_unk2]
    call    qword ptr [rax+0]
    test    eax, eax
    jz      ddo_ifail                       ; S_OK here would be a lie
    cmp     qword ptr [g_do_unk2], 0
    jne     ddo_ifail                       ; and it must have nulled the out param
    ; the successful QI took a reference; give it back
    mov     r10, qword ptr [g_do_unk]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    call    qword ptr [rax+16]

    ; ---- EnumFormatEtc + Next ----------------------------------------------
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    mov     edx, DATADIR_GET
    lea     r8, [g_do_enum]
    call    qword ptr [rax+64]              ; slot 8 = EnumFormatEtc
    test    eax, eax
    jnz     ddo_ifail
    mov     r10, qword ptr [g_do_enum]
    test    r10, r10
    jz      ddo_ifail
    ; ask for three; there are two, so it must report two and say S_FALSE
    mov     dword ptr [g_do_fetched], 0
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    mov     edx, 3
    lea     r8, [g_do_fmts]
    lea     r9, [g_do_fetched]
    call    qword ptr [rax+24]              ; slot 3 = Next
    cmp     eax, S_FALSE
    jne     ddo_ifail
    cmp     dword ptr [g_do_fetched], EN_FORMATS
    jne     ddo_ifail
    ; the two it offered must be the two it serves, in that order
    movzx   eax, word ptr [g_do_fmts+FE_cfFormat]
    cmp     eax, dword ptr [g_cf_fgd]
    jne     ddo_ifail
    cmp     dword ptr [g_do_fmts+FE_tymed], TYMED_HGLOBAL
    jne     ddo_ifail
    movzx   eax, word ptr [g_do_fmts+FE_BYTES+FE_cfFormat]
    cmp     eax, dword ptr [g_cf_fc]
    jne     ddo_ifail
    cmp     dword ptr [g_do_fmts+FE_BYTES+FE_tymed], TYMED_ISTREAM
    jne     ddo_ifail
    ; exhausted: a second Next must fetch nothing
    mov     dword ptr [g_do_fetched], 0
    mov     r10, qword ptr [g_do_enum]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    mov     edx, 1
    lea     r8, [g_do_fmts]
    lea     r9, [g_do_fetched]
    call    qword ptr [rax+24]
    cmp     eax, S_FALSE
    jne     ddo_ifail
    cmp     dword ptr [g_do_fetched], 0
    jne     ddo_ifail
    mov     r10, qword ptr [g_do_enum]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    call    qword ptr [rax+16]              ; Release the enumerator

    ; ---- QueryGetData: both offered formats yes, an unoffered one no -------
    lea     rcx, [g_do_fmt]
    xor     rdx, rdx
    call    do_fmt_fill
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    lea     rdx, [g_do_fmt]
    call    qword ptr [rax+40]              ; slot 5 = QueryGetData
    test    eax, eax
    jnz     ddo_ifail
    lea     rcx, [g_do_fmt]
    mov     rdx, 1
    call    do_fmt_fill
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    lea     rdx, [g_do_fmt]
    call    qword ptr [rax+40]
    test    eax, eax
    jnz     ddo_ifail
    lea     rcx, [g_do_fmt]
    mov     rdx, 2                          ; CF_TEXT, which is not on offer
    call    do_fmt_fill
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    lea     rdx, [g_do_fmt]
    call    qword ptr [rax+40]
    test    eax, eax
    jz      ddo_ifail

    ; ---- GetData: the descriptor -------------------------------------------
    lea     rcx, [g_do_fmt]
    xor     rdx, rdx
    call    do_fmt_fill
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    lea     rdx, [g_do_fmt]
    lea     r8, [g_do_med]
    call    qword ptr [rax+24]              ; slot 3 = GetData
    test    eax, eax
    jnz     ddo_ifail
    cmp     dword ptr [g_do_med+STG_tymed], TYMED_HGLOBAL
    jne     ddo_ifail
    WINCALL GlobalLock, qword ptr [g_do_med+STG_handle]
    test    rax, rax
    jz      ddo_ifail
    mov     qword ptr [rbp-72], rax
    mov     eax, dword ptr [rax+FGD_cItems]
    cmp     rax, qword ptr [rbp-40]
    jne     ddo_ifail
    ; print "<i> <size> <name>" per descriptor, the same shape estream prints,
    ; so one test parser reads both
    mov     qword ptr [rbp-56], 0
ddo_pr:
    mov     rax, qword ptr [rbp-56]
    cmp     rax, qword ptr [rbp-40]
    jae     ddo_prdone
    mov     r11, FDW_BYTES
    mul     r11
    add     rax, FGD_fgd
    add     rax, qword ptr [rbp-72]
    mov     qword ptr [rbp-80], rax
    mov     rcx, qword ptr [rbp-56]
    call    print_u64
    prn_a   msg_es_sep
    mov     r10, qword ptr [rbp-80]
    mov     ecx, dword ptr [r10+FDW_nFileSizeHigh]
    shl     rcx, 32
    mov     eax, dword ptr [r10+FDW_nFileSizeLow]
    or      rcx, rax
    call    print_u64
    prn_a   msg_es_sep
    mov     r10, qword ptr [rbp-80]
    lea     rcx, [r10+FDW_cFileName]
    call    print_wz
    prn_a   msg_es_nl
    inc     qword ptr [rbp-56]
    jmp     ddo_pr
ddo_prdone:
    WINCALL GlobalUnlock, qword ptr [g_do_med+STG_handle]
    ; the target owns the block once it has it, so this is the target freeing it
    WINCALL GlobalFree, qword ptr [g_do_med+STG_handle]

    ; ---- GetData: one IStream per item, then read them all interleaved -----
    mov     qword ptr [rbp-56], 0
ddo_get:
    mov     rax, qword ptr [rbp-56]
    cmp     rax, qword ptr [rbp-40]
    jae     ddo_pump
    lea     rcx, [g_do_fmt]
    mov     rdx, 1
    call    do_fmt_fill
    mov     rax, qword ptr [rbp-56]
    mov     dword ptr [g_do_fmt+FE_lindex], eax
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    lea     rdx, [g_do_fmt]
    lea     r8, [g_do_med]
    call    qword ptr [rax+24]
    test    eax, eax
    jnz     ddo_ifail
    cmp     dword ptr [g_do_med+STG_tymed], TYMED_ISTREAM
    jne     ddo_ifail
    mov     rax, qword ptr [g_do_med+STG_handle]
    test    rax, rax
    jz      ddo_ifail
    mov     r11, qword ptr [rbp-56]
    lea     r10, [g_es_objs]
    mov     qword ptr [r10+r11*8], rax
    mov     rcx, r11
    call    es_out_path
    lea     rcx, [g_es_path]
    call    file_open_write
    cmp     rax, INVALID
    je      ddo_iofail
    mov     r11, qword ptr [rbp-56]
    lea     r10, [g_es_files]
    mov     qword ptr [r10+r11*8], rax
    inc     qword ptr [rbp-56]
    jmp     ddo_get
ddo_pump:
    ; ---- an lindex past the end must be refused, not clamped ----------------
    lea     rcx, [g_do_fmt]
    mov     rdx, 1
    call    do_fmt_fill
    mov     rax, qword ptr [rbp-40]
    mov     dword ptr [g_do_fmt+FE_lindex], eax
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    lea     rdx, [g_do_fmt]
    lea     r8, [g_do_med]
    call    qword ptr [rax+24]
    test    eax, eax
    jz      ddo_ifail
    cmp     qword ptr [g_do_med+STG_handle], 0
    jne     ddo_ifail                       ; a failed GetData must hand back nothing

    mov     rcx, qword ptr [rbp-40]
    call    es_pump
    test    eax, eax
    jnz     ddo_pfail
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10]
    mov     rcx, r10
    call    qword ptr [rax+16]              ; Release the data object
    prn_a   msg_do_ok
    mov     rcx, qword ptr [rbp-40]
    call    print_u64
    prn_a   msg_es_nl
    xor     eax, eax
    FRAME_EPILOG
    ret
ddo_none:
    prn     e_es_none
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
ddo_cfail:
    prn     e_do_create
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
ddo_ifail:
    prn     e_do_iface
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
ddo_pfail:
    mov     dword ptr [rbp-72], eax
    prn     e_es_read
    mov     eax, dword ptr [rbp-72]
    FRAME_EPILOG
    ret
ddo_iofail:
    prn     e_es_io
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
ddo_wipe:
    mov     dword ptr [rbp-72], eax
    lea     rcx, [g_key]
    mov     rdx, KEY_LEN
    call    secure_zero
    mov     eax, dword ptr [rbp-72]
    FRAME_EPILOG
    ret
do_dataobj endp

; =============================================================================
; do_fmt_fill(rcx = FORMATETC*, rdx = which: 0 descriptor, 1 contents, 2 CF_TEXT)
; The exerciser's stand-in for what a drop target builds before it asks.
; =============================================================================
do_fmt_fill proc
    mov     qword ptr [rcx+FE_cfFormat], 0
    mov     qword ptr [rcx+FE_ptd], 0
    mov     dword ptr [rcx+FE_dwAspect], DVASPECT_CONTENT
    mov     dword ptr [rcx+FE_lindex], -1
    cmp     rdx, 1
    je      dff_fc
    ja      dff_text
    mov     eax, dword ptr [g_cf_fgd]
    mov     word ptr [rcx+FE_cfFormat], ax
    mov     dword ptr [rcx+FE_tymed], TYMED_HGLOBAL
    ret
dff_fc:
    mov     eax, dword ptr [g_cf_fc]
    mov     word ptr [rcx+FE_cfFormat], ax
    mov     dword ptr [rcx+FE_tymed], TYMED_ISTREAM
    ret
dff_text:
    mov     word ptr [rcx+FE_cfFormat], 1   ; CF_TEXT, which is not on offer
    mov     dword ptr [rcx+FE_tymed], TYMED_HGLOBAL
    ret
do_fmt_fill endp

endif

end
