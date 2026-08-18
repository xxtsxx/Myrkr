; =============================================================================
; macros.inc - shared constants, structures and hardening macros
; =============================================================================
; Every non-leaf procedure in this project uses the FRAME_PROLOG /
; FRAME_EPILOG pair.  Together they provide, per call:
;   1. a proper SEH unwind frame        (.pushreg / .setframe / .allocstack)
;   2. a stack canary                   (random cookie, checked on exit)
;   3. a software shadow-stack entry    (return address verified on exit)
; Any violation terminates the process immediately via __fastfail (int 29h),
; which the kernel treats as a non-continuable, non-handlable fault.
; =============================================================================

OPTION CASEMAP:NONE

; ---------------------------------------------------------------------------
; Exit codes (see manifest.md section 10)
; ---------------------------------------------------------------------------
EXIT_OK             equ 0
EXIT_USAGE          equ 1
EXIT_IO             equ 2
EXIT_AUTH           equ 3
EXIT_CORRUPT        equ 4
EXIT_OOM            equ 5
EXIT_NOCPU          equ 6
EXIT_SELFTEST       equ 7
EXIT_NOSPACE        equ 8          ; insufficient free disk space (pre-flight)
EXIT_UNSUPPORTED    equ 9          ; the input uses a feature we will not act on
                                   ; rather than act on it wrongly (see
                                   ; zip_delete_marked)
EXIT_PARTIAL        equ 10
EXIT_CANCELLED      equ 11         ; the user stopped it; the archive was put back         ; the new file is written and the old one is
                                   ; gone, but the two could not be swapped: the
                                   ; data is under the temporary name

DISK_MARGIN         equ 100000h    ; 1 MiB slack added to free-space estimates

; ---------------------------------------------------------------------------
; __fastfail codes (int 29h, rcx = code).  2/10 are the documented Windows
; codes for cookie / indirect-call failures; codes >= 0F000h are ours.
; ---------------------------------------------------------------------------
FF_STACK_COOKIE     equ 2          ; FAST_FAIL_STACK_COOKIE_CHECK_FAILURE
FF_GUARD_ICALL      equ 10         ; FAST_FAIL_GUARD_ICALL_CHECK_FAILURE
FF_SHADOW_STACK     equ 0F001h     ; software shadow stack mismatch
FF_HEAP_TAG         equ 0F002h     ; temporal heap tag / canary violation
FF_TYPE_MAGIC       equ 0F003h     ; struct type-magic mismatch
FF_BOUNDS           equ 0F004h     ; bounds check failed
FF_OVERFLOW         equ 0F005h     ; integer overflow in size arithmetic
FF_IAT_RO           equ 01A70h     ; write attempted to the locked-down IAT.
                               ; Not raised by us - the CPU raises an access
                               ; violation and redteam.asm reports it under this
                               ; code so every control answers the same way.
                               ; Here rather than in redteam.asm so the codes an
                               ; operator may see are enumerated in ONE place.

; ---------------------------------------------------------------------------
; CPU feature flag bits kept in g_cpu_features (set once in cpu_gate)
; ---------------------------------------------------------------------------
CPUF_AESNI          equ 1          ; leaf 1  ecx[25]
CPUF_PCLMUL         equ 2          ; leaf 1  ecx[1]
CPUF_SSE41          equ 4          ; leaf 1  ecx[19]
CPUF_SHANI          equ 8          ; leaf 7  ebx[29]
CPUF_AVX2           equ 16         ; leaf 7  ebx[5]
CPUF_RDSEED         equ 32         ; leaf 7  ebx[18]

; ---------------------------------------------------------------------------
; Limits (input validation)
; ---------------------------------------------------------------------------
MAX_ARGS            equ 256        ; argv[0] + up to 255 file inputs
MAX_PATH_CHARS      equ 8000h      ; 32768 UTF-16 units (Windows extended-length max)
MAX_PASSWORD_BYTES  equ 1024       ; UTF-8 bytes after conversion
MIN_PASSWORD_BYTES  equ 1
; AES-GCM's per-key plaintext ceiling: 2^39 - 256 bits = 68,719,476,704 bytes
; (32 bytes under 64 GiB).  Past it the 32-bit counter block wraps and keystream
; repeats, which is fatal.  A fresh salt per file means a fresh key per file, so
; this is a per-CONTAINER limit.
;
; This was previously written 0FFFFFFFFFh ("64 GiB - 1"), which is 31 bytes ABOVE
; the real bound - harmless while nothing enforced it, wrong once something does.
; Enforced at pre-flight by do_pack (pack.asm); see PACK_ENTRY_OVERHEAD for how
; the archive case accounts for tar framing.
MAX_PLAINTEXT_SIZE  equ 0FFFFFFFE0h  ; 2^39 - 256 bits, in bytes
; Worst-case tar bytes added per archive entry: a 512-byte header plus up to 511
; bytes padding the content to a 512 boundary.  Rounded up to 1024 so the
; pre-flight estimate can only ever over-count.
PACK_ENTRY_OVERHEAD equ 1024

ARGON2_MIN_T        equ 1
ARGON2_MAX_T        equ 16
ARGON2_MIN_M_KIB    equ 8192       ; 8 MiB
ARGON2_MAX_M_KIB    equ 4194304    ; 4 GiB
ARGON2_DEF_T        equ 3
ARGON2_DEF_M_KIB    equ 524288     ; 512 MiB (tuned for ~600-700ms with AVX2)

; ---------------------------------------------------------------------------
; Container header (80 bytes, used verbatim as GCM AAD) - manifest.md section 4
; The first 64 bytes are the parameter block; bytes 64..79 are a key-check
; value = SHA-256(key)[0..15], allowing a wrong password to be rejected right
; after key derivation (before any data is processed) and making the scheme
; key-committing.  Version 2 introduced the KCV; v1 containers are rejected.
; ---------------------------------------------------------------------------
HDR_MAGIC           equ 4B52594Dh  ; "MYRK" little-endian
; The on-disk format revision.  TWO numbers, not one, and the pair is the whole
; of phase B1 (docs/V5_WORK.md).
;
; Until 1.0.74 there was only HDR_VERSION and every reader compared it for
; EXACT EQUALITY, so bumping it made every container anyone already had read as
; "not a valid Myrkr container" - the tool calling intact data damaged.  That is
; not a thing to discover while shipping a format change.
;
; HDR_VERSION      what the writer emits.
; HDR_VERSION_MIN  the oldest a reader accepts.  It only ever moves if support
;                  for an old format is deliberately dropped, and dropping one
;                  means the containers written under it stop opening.
;
; Readers go through hdr_version_ok (pack.asm) rather than comparing here, so a
; version that decides BEHAVIOUR - which the segment work will introduce - has
; one place to be decided in and not four.
;
; 7 is byte-for-byte identical to 6.  That is deliberate: it makes the dispatch
; live and continuously exercised (every test writes 7; tests/fixtures/v6-*.mrk
; are 6) BEFORE anything hangs off it, so the first real divergence lands on
; plumbing that is already known to work.
HDR_VERSION         equ 8
HDR_VERSION_MIN     equ 6
KEY_LEN             equ 32         ; AES-256 file key (Argon2id output).  Shared
                                   ; rather than cmd.asm-local because secmem.asm
                                   ; must lock g_key using the same length that
                                   ; declares it.
; SHA-1 context bytes, supplied by the caller of sha1_init.  Shared here because
; the size had drifted into three spellings - SHA1_CTX_SIZE (sha1.asm, which owns
; the layout, and which nothing used), SHA1CTX (zip.asm) and a bare 96 in
; unzip.asm - so growing the context would have silently under-allocated the HMAC
; scratch in both ZIP paths.  An `equ` cannot cross modules as a link-time
; absolute and still size a `dup`, so it lives in the shared include instead.
SHA1_CTX_SIZE       equ 96
; Wide chars in the GUI's password/confirm edits.  Shared rather than
; gui.asm-local because secmem.asm locks those buffers and must size them with
; the same constant that declares them.
PWBUF_CHARS         equ 1100

; Auto-compression threshold: when neither --compress nor --store is given, the
; default is to compress inputs whose total size is below this, and store above.
COMPRESS_AUTO_MAX   equ 03200000h  ; 50 MiB

CONTAINER_HDR struct
    magic       dd ?               ; "MYRK"
    version     dd ?               ; HDR_VERSION when written; readers accept
                                   ; HDR_VERSION_MIN..HDR_VERSION.  NOT the
                                   ; "v4"/"v5" the design documents use - those
                                   ; name the DESIGN generation, this names the
                                   ; on-disk revision, and the two have drifted.
    t_cost      dd ?               ; Argon2id passes
    m_cost_kib  dd ?               ; Argon2id memory (KiB)
    ; These four were ONE field, "lanes dd ?", while the writer put four
    ; separate bytes here and sixteen sites across four files read them as raw
    ; offsets - so the struct that IS this format's definition did not mention
    ; the two flags decoding depends on.  Same 64 bytes, same offsets, same
    ; output; only the names are new.
    lanes       db ?               ; Argon2id parallelism (always 1)
    archive     db ?               ; 1 = the payload is a tar stream, 0 = one file
    compressed  db ?               ; 0 = store, 1 = XPRESS-framed
    ; Was hdr_rsvd, "must be 0" - written as zero by one writer and validated by
    ; no reader, which is what made it free.  Phase B spends it: 0 means the
    ; entries are not segmented (every container up to version 7, and any
    ; version 8 that had nothing large enough to split), otherwise the segment
    ; size is 1 << seg_shift.  A power of two so the writer's boundary
    ; arithmetic is a shift and a mask rather than a divide.
    seg_shift   db ?               ; 0 = unsegmented, else SEG_BYTES = 1 << it
    salt        db 32 dup (?)      ; CSPRNG salt
    set_id      db 12 dup (?)      ; CSPRNG container identity.  This field held
                                   ; the GCM nonce up to v3; v4 nonces are
                                   ; counters, so the space now carries an
                                   ; identity instead - which is what a volume
                                   ; set will need to prove its members belong
                                   ; together.  Still AAD, so it is bound in.
CONTAINER_HDR ends

KCV_LEN             equ 16         ; key-check value bytes (SHA-256(key) prefix)
KCV_OFFSET          equ (sizeof CONTAINER_HDR)            ; 64
HDR_BYTES           equ (sizeof CONTAINER_HDR) + KCV_LEN  ; 80 (full header = AAD)
GCM_TAG_LEN         equ 16
CONTAINER_MIN_SIZE  equ HDR_BYTES + GCM_TAG_LEN           ; 96

; ---------------------------------------------------------------------------
; Version 4: per-entry streams, and the inventory that locates them
;
; Every entry - one file, or one directory header - is its own AES-GCM stream
; with its own nonce and its own tag, and the inventory records where each one
; lives.  The container is one opaque run of ciphertext with no framing in it;
; the extents exist only inside the encrypted index, so an attacker without the
; password still sees a single blob and learns neither the file count nor any
; individual size.
;
;   [80-byte header][entry 0][entry 1]...[entry N-1]
;                   [index ciphertext][index tag 16][trailer 24]
;
; where each entry is its ciphertext followed by its own 16-byte tag, and the
; entry's plaintext is a ustar header, the content, and the padding to 512 -
; compressed in framed blocks when compression is on.
;
; What this buys, in the order the reasons actually matter:
;
;   Random access.  One file can be decrypted and authenticated without reading
;   the rest.  A tag covers a whole stream, so authenticated random access is
;   only possible if the streams are per-entry - which is why the split into
;   volumes (later) must sit BELOW the crypto, slicing the ciphertext run rather
;   than becoming the streams themselves.
;
;   No 64 GiB ceiling on the container.  AES-GCM's limit is per invocation, so
;   it now bounds one entry rather than the whole archive.  A single file larger
;   than that still needs chunking within the entry; the container as a whole no
;   longer has a limit worth naming.
;
;   Containment.  A damaged entry costs that entry, not the archive.  This is a
;   consequence worth having, not the reason - it is containment, not
;   correction, and a bad sector still loses that file.
;
; NONCES ARE COUNTERS, NOT RANDOM.  Entry i uses the ordinal it was sealed with,
; plus one; the index uses IDX_NONCE_BASE + its revision; all are 96-bit
; little-endian.  An entry's ordinal is RECORDED rather than implied by its
; position, because deleting an entry must not renumber the survivors - their
; tags are bound to the ordinal they were sealed with.  A counter cannot collide with itself, where 96-bit
; random values merely probably do not - and since the key is fresh per
; container (fresh salt), a counter is safe here in a way it would not be if
; keys were reused.  Nothing is stored: the value IS the position.
;
; The corollary is a rule, not a preference: NEVER append newly encrypted data
; to an existing container under its existing key.  Repacking with a fresh key
; is the only supported way to add to one.  Overwriting an entry in place with
; random bytes consumes no counter and is therefore fine - and rewriting the
; index after such a delete consumes exactly one, the next revision.
;
; AAD binds an entry to its position: header || u64 ordinal.  A reordered,
; duplicated or spliced-in entry fails its tag rather than decrypting to
; something plausible.  The index's AAD is header || trailer.
;
; The index still goes at the END, and its length still lives in a trailer.
; Packing is a single streaming pass and the entries are only all known once the
; last one has been written; a length in the header would need either a second
; walk of the tree - which can disagree with the first - or a rewind of a file
; being written sequentially.  Recording entries AS THEY ARE PACKED means the
; listing cannot describe anything the container does not hold.
; ---------------------------------------------------------------------------
IDX_MAGIC           equ 5844494Dh  ; "MIDX" little-endian
IDX_TRAILER_BYTES   equ 32
IDX_AAD_BYTES       equ HDR_BYTES + IDX_TRAILER_BYTES     ; 112
; An entry's AAD is the header followed by its ordinal, so position is bound in
; - and, from version 8, by the SEGMENT number after it, so a slice of a large
; entry cannot be moved within that entry either.
;
; Belt and braces rather than load-bearing: the NONCE already differs per
; segment, so a moved or spliced segment fails its tag without the AAD's help.
; FORMAT_V5.md 3.2 asks for it and it costs one branch.
;
; The length is therefore version-dependent, which is the first thing in this
; format that is.  It is decided in ONE place - entry_stream_open, which is
; handed the header and reads the version out of it - so a reader and a writer
; cannot come to different conclusions about the same container.
ENTRY_AAD_BYTES     equ HDR_BYTES + 8                     ; 88, version <= 7
ENTRY_AAD_SEG_BYTES equ HDR_BYTES + 12                    ; 92, version >= 8
HDR_VERSION_SEG     equ 8      ; the first version whose AAD carries the segment
; Segment size bounds, as exponents (SEG_BYTES = 1 << seg_shift).
;
; MAX is 35 (32 GiB) because a SEGMENT is one GCM stream and must stay under
; MAX_PLAINTEXT_SIZE (2^36 - 32): shift 36 is exactly 2^36, over it.  MIN is 12
; (4 KiB) - anything smaller is tag overhead for nothing, and a floor also
; bounds what a hostile header can make a reader do.  Both bounds matter for a
; third reason: `shl rax, cl` masks cl to 6 bits on x64, so an UNVALIDATED
; shift of 64 quietly computes 1 << 0.  seg_bytes_from_hdr (pack.asm) is the
; only place a shift becomes a byte count, and it range-checks first.
;
; The DEFAULT was 0 (off) from 1.0.77 to 1.0.82 while the machinery sat under
; tests/segmenttest.ps1 and the deep-audit composition runs; 1.0.83 turned it
; on at 32 (4 GiB - docs/FORMAT_V5.md 3.5) after a user hit the 64 GiB refusal
; on real data.  Every new container is segmented; a <4 GiB entry is exactly
; one segment, and only the header byte differs from what 1.0.82 wrote.
SEG_SHIFT_MIN       equ 12
SEG_SHIFT_MAX       equ 35
SEG_SHIFT_DEFAULT   equ 32     ; 4 GiB - ON since 1.0.83; see the note above
; Trailer field offsets
IDXT_flags          equ 0          ; dd  bit 0: the listing is incomplete
IDXT_count          equ 4          ; dd  entries recorded
IDXT_len            equ 8          ; dq  index ciphertext bytes (tag excluded)
IDXT_magic          equ 16         ; dd  IDX_MAGIC
IDXT_rev            equ 20         ; dd  index revision: 0 when packed, +1 per
                                   ;     rewrite.  See IDX_NONCE_BASE.
; v6.  The ordinal an added entry must take, and the single thing that makes
; adding to an existing container safe.
;
; Ordinals ARE nonces (entry i uses i+1), and the key does not change when a
; container is edited.  Deleting does not renumber the survivors - their tags are
; bound to the ordinal they were sealed with - so after deleting the highest
; entry, "one past the highest surviving ordinal" is an ordinal that has ALREADY
; been used under this key.  Issuing it again is GCM nonce reuse, which is the
; one mistake in this design that cannot be recovered from.
;
; So the next ordinal is remembered rather than recomputed, and it only ever goes
; up: a delete leaves it alone, an add advances it by the number of entries
; added.  It sits in the trailer, which is inside the index's AAD, so it is
; authenticated - a tampered counter fails the tag rather than steering the
; writer onto a used nonce.  idx_auth additionally refuses a container whose
; counter is at or below an ordinal the index still lists, which catches OUR
; bugs rather than an attacker.
IDXT_next           equ 24         ; dq  next ordinal to issue
IDXF_TRUNCATED      equ 1
; The index's nonce comes from its revision, not from a fixed zero, because
; deleting an entry in place REWRITES the index under the container's existing
; key - and re-encrypting different plaintext under a nonce that has already
; been used is the one mistake in this design that cannot be recovered from.
; Revisions live at the top of the counter space, where entry ordinals (which
; count up from 1, one per file) can never reach.
IDX_NONCE_BASE      equ 8000000000000000h
; And the revision has a CEILING, because it is the one counter here that can
; wrap.  IDXT_rev is 32 bits, so the 4294967296th rewrite of a single container
; would roll it back to 0 and issue revision 0's nonce a second time, under the
; same key, over different plaintext.  Every other counter in this design is
; 64-bit and unreachable; this one is merely astronomical, and "astronomical"
; is not the same as "cannot".  idx_rev_bump refuses at the ceiling instead,
; which costs the container its last possible revision and nothing else - the
; remedy is to repack, which draws a fresh salt and therefore a fresh key, and
; a fresh key makes every nonce available again.
IDX_REV_MAX         equ 0FFFFFFFFh
; Removing an entry is one operation, whatever the container's size: overwrite
; it where it lies with random, then close the gap.
;
; The overwrite is what makes it unrecoverable, and it is the step that cannot be
; skipped.  Rewriting the container to a new file and renaming - which is what
; "carve" used to do - releases the ORIGINAL's blocks with their contents intact,
; still encrypted under a key the password still derives; a recovery tool and the
; password get the deleted file back.  Overwriting in place does not have that
; hole.
;
; Closing the gap is then almost free, and this is what per-entry encryption
; bought: an entry's tag does not depend on where it sits.  The nonce comes from
; its recorded ordinal, the AAD is header || ordinal, and GHASH runs over the AAD
; and the ciphertext bytes - the offset appears nowhere in it.  So the survivors'
; ciphertext can simply be MOVED down over the hole and their extents updated in
; the index.  No decryption, no re-encryption, no fresh key: a byte copy of
; whatever followed the hole.
;
; (SSDs qualify the first step: overwriting a logical sector need not overwrite
; the physical cell, since wear-levelling may remap it.  That is a property of
; the storage, not of this format.)
; One index entry.  The extent is what makes a container randomly accessible:
; entry i's ciphertext is stored_len bytes at offset from the start of the
; payload run, and nothing outside that extent has to be read - or trusted - to
; get that one file back.  The names are still the tar entry names, so a listing
; and an extraction agree exactly.
IDXE_size           equ 0          ; dq  content bytes (0 for a directory)
IDXE_offset         equ 8          ; dq  from the payload run's start (= HDR_BYTES)
IDXE_stored         equ 16         ; dq  ciphertext + its 16-byte tag
; The append destination (g_add_prefix).  Sized against g_rel / g_zrel, which
; are both 4096: the prefix and the leaf share that one buffer, so the prefix
; is capped well short of it and the leaf gets whatever is left.  ADDPFX_MAX is
; the cap every builder applies BEFORE writing, so no consumer has to defend
; against a prefix that cannot fit.
ADDPFX_BYTES        equ 4096
ADDPFX_MAX          equ 3072       ; leaves 1024 for the leaf, which is MAX_PATH-ish
; Staged layout: a destination PER INPUT, so one encrypt can place different
; inputs in different folders.  Offsets into this arena live in g_pos_prefix;
; offset 0 is the empty string, which is why the array reads as "everything at
; the root" when it has never been written - the state every release before
; this one was in.
PFXARENA_BYTES      equ 8192
IDXE_ordinal        equ 24         ; dq  the counter this entry was sealed with
IDXE_flags          equ 32         ; dd  bit 0: directory
IDXE_namelen        equ 36         ; dd
IDXE_name           equ 40
IDXE_FIXED          equ 40
IDXEF_DIR           equ 1
IDXEF_DROPPED       equ 2          ; marked for removal, in memory only -
                                   ; no container ever stores this bit
IDXEF_PICK          equ 4          ; marked for extraction, in memory only.
                                   ; Meaningful ONLY while g_pick_active is set;
                                   ; a stale bit with no selection in force must
                                   ; never narrow an extract that asked for all
                                   ; of it, which is why the flag alone does not
                                   ; decide anything.
; A ceiling, because the buffer is static and a tree has no natural bound.  At
; An entry costs IDXE_FIXED + its path, so 40 bytes PLUS the name - not 40, which
; is what this comment used to claim while calling the result "some 50,000
; files".  At an 85-character average path 2 MiB held 16,777 of them.
;
; WHAT IS LOST IS NOT A PREVIEW.  That was the belief behind the old cap, and it
; was wrong: idx_add dropped every entry past the limit while pack_node went on
; writing them into the payload, and unpack is driven entirely by this table -
; "the inventory locates every entry".  A dropped entry has no offset, no
; ordinal and no name recorded anywhere a reader consults, so its ciphertext sits
; in the container unreferenced and unreachable.  Encrypt reported success.
;
; Reported 2026-08-12 against 1.0.50: 76,286 files in, 16,780 out, no error.
; That count is the cap, not a property of the data.
;
; So two things changed.  This is now 64 MiB - about 500,000 files at an
; 85-character path, and it is .data? so it costs address space and not a byte
; of the binary - and, far more importantly, exceeding it is a hard failure
; rather than a flag.  A cap that refuses is a capacity limit; a cap that
; silently drops files is data loss with a success message.
; THE INVENTORY CEILING.  Just under 2 GiB, and the "just under" is load-bearing.
;
; At the entry costs measured in docs/V5_WORK.md that is roughly 25 million
; entries at 40-character paths, 16 million at 85 and 10.7 million at 150 - so
; the ten-million-file target holds for any realistic tree, not only for short
; paths.
;
; IT IS RESERVED ADDRESS SPACE, NOT MEMORY.  idx_buf_ensure reserves this much
; and idx_buf_commit commits only as far as the index actually reaches, so a
; small container costs a megabyte and a command that opens none costs nothing.
; Until 1.0.80 this was 64 MiB of .data?, committed at load, paid by every
; invocation whether it opened a container or not.
;
; WHY NOT A ROUND 2 GiB.  At 2^31 and above, an `imm32` operand SIGN EXTENDS:
; `cmp rax, IDX_MAX_BYTES` would compare against 0FFFFFFFF80000000h and every
; unsigned bound test against it would invert, and `mov qword ptr [x],
; IDX_MAX_BYTES` would store that same negative value.  Both forms appear here.
; Staying below 2^31 keeps every immediate correct by construction rather than
; by an audit that has to be redone whenever a new site is added; the guard
; below is what stops the value being raised past that without noticing.
IDX_MAX_BYTES       equ 7FF00000h  ; 2047 MiB of listing
IF IDX_MAX_BYTES GE 80000000h
    .ERR <IDX_MAX_BYTES at or above 2^31: every imm32 comparison sign-extends - see the note above>
ENDIF

; ---------------------------------------------------------------------------
; Volume set (docs/VOLUMES.md).  A part is a 32-byte header followed by a slice
; of the ordinary container byte stream; concatenating the slices reproduces the
; container exactly.  The split sits BELOW the crypto, so none of this is inside
; a tag - it is addressing, and a misassembled stream fails the container's own
; tags rather than decrypting to something plausible.
;
; The slice length is deliberately NOT a field: it is the file size minus the
; header, and a stored length would be a second source of truth the filesystem
; already holds.  Neither is the part TOTAL - it is unknown when part 1 is
; written, so the last part carries VOLF_FINAL instead and a reader requires
; 1..N contiguous with the flag on N.  A missing tail is then a missing flag.
; ---------------------------------------------------------------------------
VOL_MAGIC           equ 4C4F564Dh  ; "MVOL" little-endian
VOL_VERSION         equ 1
VOLH_magic          equ 0          ; dd
VOLH_version        equ 4          ; dd
VOLH_setid          equ 8          ; db 12 - copied from CONTAINER_HDR.set_id
VOLH_part           equ 20         ; dd    - 1-based
VOLH_flags          equ 24         ; dd
VOLH_reserved       equ 28         ; dd
VOL_HDR_BYTES       equ 32
VOLF_FINAL          equ 1          ; bit 0: the last part of the set
VOL_PATH_CHARS      equ 8000h      ; matches MAX_PATH_CHARS
; Parts a set may have.  A cap rather than a growing table because the reader
; holds every part OPEN at once - random access can land in any of them - and
; 4096 open handles is already far past what a person will assemble by hand.
; Exceeding it is a refusal, not a truncation; see 1.0.51 for why that matters.
VOL_MAX_PARTS       equ 4096
VOL_SHIFT_CHUNK     equ 65536      ; vol_settle strips a 32-byte header in place
VOL_PART_STRIDE     equ 24         ; per part: handle, logical start, slice len
VOLP_handle         equ 0
VOLP_start          equ 8
VOLP_len            equ 16
; ".partNNN.mrk" - what vset_open strips to find the other members
VOL_SUFFIX_CHARS    equ 12
; The GUI's split-size presets are an index 0..SPLIT_MAX_IDX; shared because
; selftest checks the two tables behind it agree and cannot see a gui.asm equ.
SPLIT_MAX_IDX       equ 6
; Where set_id sits inside the container header, for the copy into a part header.
CONTAINER_SETID_OFF equ 52
PICK_MAX_BYTES      equ 40000h     ; 256 KiB of picked names
; Everything a v3 container carries after its payload tag.
IDX_TAIL_FIXED      equ GCM_TAG_LEN + IDX_TRAILER_BYTES   ; 48

; ---------------------------------------------------------------------------
; Struct type magics (TYPE_CHECK targets)
; ---------------------------------------------------------------------------
TM_HEAPBLK          equ 48504C42h  ; "BLPH" heap block header

; ---------------------------------------------------------------------------
; Software shadow stack
; ---------------------------------------------------------------------------
SSTK_CAPACITY       equ 4096       ; max simultaneous frames (entries), PER THREAD
; The shadow stack is per thread, reached through a TLS slot rather than a
; global.  TEB_TLS_SLOTS is the offset of the TEB's 64-slot TlsSlots array on
; x64, so a lookup is two instructions and needs no call - which matters when
; every framed procedure in the program does it twice.
TEB_TLS_SLOTS       equ 1480h

; landing-pad magic for DLPV - emitted in front of every indirect-call target
LP_MAGIC            equ 0D1B7C0DEFACEB00Ch

; =============================================================================
; FRAME_PROLOG localbytes
; -----------------------------------------------------------------------------
; Use immediately after "name PROC FRAME".  localbytes = bytes you need for
; locals INCLUDING the 32-byte shadow space for any calls you make.  The
; macro adds the canary slot and rounds to 16.
;
; Resulting frame layout:
;   [rbp+8]              return address (verified against shadow stack)
;   [rbp]                saved rbp
;   [rbp-8]              stack canary
;   [rbp-16 ... down]    your locals
;   [rsp .. rsp+31]      shadow space for callees (bottom of frame)
;
; Clobbers rax, r10, r11 (all volatile, never argument registers).
; =============================================================================
FRAME_PROLOG macro localbytes
    local no_sstk
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, ((localbytes + 8 + 15) AND 0FFFFFFF0h)
    .allocstack ((localbytes + 8 + 15) AND 0FFFFFFF0h)
    .endprolog
    ; ---- plant stack canary ------------------------------------------------
    mov     rax, qword ptr [g_stack_canary]
    mov     qword ptr [rbp-8], rax
    ; ---- push return address onto THIS THREAD's software shadow stack -------
    ; The stack is per thread, reached through a TLS slot.  It used to be one
    ; pair of globals for the whole process, which is a data race the moment a
    ; second thread runs framed code: the indexer thread and the UI thread
    ; interleaved their pushes, each then failed to find its own return address,
    ; and the guard fastfailed the process (0xC0000409) on its own bookkeeping.
    ;
    ; A thread with no block yet simply skips the shadow stack - it keeps the
    ; canary, and degrading is far better than trapping.  sstk_thread_init gives
    ; a thread its own block.
    mov     r10d, dword ptr [g_sstk_tls]
    test    r10d, r10d
    jz      no_sstk                         ; 0 = TLS index not allocated yet
    dec     r10d
    mov     r11, gs:[r10*8 + TEB_TLS_SLOTS]
    test    r11, r11
    jz      no_sstk
    mov     r10, qword ptr [r11]            ; this thread's index
    cmp     r10, SSTK_CAPACITY
    jae     sstk_overflow_fail              ; shared fail stub (hardening.asm)
    mov     rax, qword ptr [r11+8]          ; this thread's base
    lea     rax, [rax+r10*8]                ; -> the slot to write
    mov     r10, qword ptr [rbp+8]          ; our return address
    mov     qword ptr [rax], r10
    inc     qword ptr [r11]
no_sstk:
endm

; =============================================================================
; FRAME_EPILOG - place immediately before "ret".
; Verifies canary + shadow stack, restores rsp/rbp.
; Preserves rax/rdx/xmm0 (return values).  Clobbers r10, r11.
; =============================================================================
FRAME_EPILOG macro
    local ok1, ok2, sse_scan, sse_fail, no_sstk
    ; ---- verify stack canary ------------------------------------------------
    mov     r10, qword ptr [g_stack_canary]
    cmp     r10, qword ptr [rbp-8]
    je      ok1
    mov     ecx, FF_STACK_COOKIE
    jmp     ff_trap
ok1:
    ; ---- pop + verify the software shadow stack (SEH-unwind tolerant) -------
    ; The OS SEH unwinder restores rsp/rbp but does NOT pop this software shadow
    ; stack, so an exception unwinding through framed procs leaves stale entries
    ; above the live frame's.  Popping exactly one entry and demanding a match
    ; then fastfails on the next perfectly legitimate return - the process dies
    ; from having survived an exception, not from an attack.  (Vordr hit this
    ; with the Windows GUI/CoreMessaging exceptions raised around its unlock
    ; dialog; Myrkr runs framed worker-thread procs under a live GUI, which is
    ; the same exposure.)
    ;
    ; So scan DOWN for THIS frame's return address: found -> resync, dropping
    ; the stale entries above it; absent from the whole stack -> a genuine
    ; return-address (ROP) violation.  rax/rdx/xmm0 carry return values here, so
    ; the scan uses only r10/r11 - the registers this macro already clobbers.
    ; Per-thread block, exactly as the prologue found it.  rcx carries it: it is
    ; volatile and is not a return-value register, and the scan already needs
    ; both r10 and r11.  A null slot means this thread never pushed, so there is
    ; nothing to verify - that is the degrade path, not an error.
    mov     r10d, dword ptr [g_sstk_tls]
    test    r10d, r10d
    jz      no_sstk
    dec     r10d
    mov     rcx, gs:[r10*8 + TEB_TLS_SLOTS]
    test    rcx, rcx
    jz      no_sstk
    mov     r11, qword ptr [rbp+8]              ; the return address to match
    mov     r10, qword ptr [rcx]                ; this thread's index
    shl     r10, 3                              ; index -> byte offset
    add     r10, qword ptr [rcx+8]              ; -> one past the top entry
sse_scan:
    cmp     r10, qword ptr [rcx+8]
    jbe     sse_fail                            ; hit the bottom -> not ours -> ROP
    sub     r10, 8
    cmp     r11, qword ptr [r10]
    jne     sse_scan
    sub     r10, qword ptr [rcx+8]              ; resync to just below the match
    shr     r10, 3
    mov     qword ptr [rcx], r10
no_sstk:
    jmp     ok2
sse_fail:
    mov     ecx, FF_SHADOW_STACK
    jmp     ff_trap
ok2:
    mov     rsp, rbp
    pop     rbp
endm

; =============================================================================
; LANDING_PAD - emit before any label that is the target of an indirect call.
; CALL_GUARDED validates the 8-byte magic at [entry-8] before transferring.
;
; Layout must guarantee the magic sits EXACTLY 8 bytes before the proc entry
; no matter how MASM aligns the following PROC (1..16).  We align to 16, then
; emit 8 bytes of filler + the 8-byte magic, leaving the cursor on a 16-byte
; boundary.  Any proc alignment of <=16 then places the entry right there, so
; [entry-8] is always the magic.
; =============================================================================
LANDING_PAD macro
    align   16
    dq      0CCCCCCCCCCCCCCCCh          ; filler (never executed)
    dq      LP_MAGIC
    align   16
endm

; CALL_GUARDED reg - DLPV-validated indirect call through 'reg'
CALL_GUARDED macro reg
    local ok
    mov     r11, LP_MAGIC
    cmp     r11, qword ptr [reg-8]
    je      ok
    mov     ecx, FF_GUARD_ICALL
    jmp     ff_trap
ok:
    call    reg
endm

; =============================================================================
; Integer-overflow-checked arithmetic on unsigned sizes.  Fail-closed.
; =============================================================================
CHECK_ADD_OVF macro dst, src        ; dst = dst + src, fastfail on carry
    local ok
    add     dst, src
    jnc     ok
    mov     ecx, FF_OVERFLOW
    jmp     ff_trap
ok:
endm

; There were SUB and MUL variants of this beside it, and NOTHING CALLED EITHER.
; An unused macro protects nothing, while docs/SECURITY.md listing it as a
; control made the binary sound better defended than it is - which is the more
; dangerous of the two. They are gone; they were found in the pre-release
; audit. Add one back the day a subtraction or a multiplication of
; sizes needs it, and give it a call site in the same commit.

; =============================================================================
; BOUND_CHECK index, limit - fastfail unless index < limit (unsigned)
; =============================================================================
BOUND_CHECK macro index, limit
    local ok
    cmp     index, limit
    jb      ok
    mov     ecx, FF_BOUNDS
    jmp     ff_trap
ok:
endm

; =============================================================================
; TYPE_CHECK preg, magic32 - verify struct type tag (first dword of struct)
; (parameter must not be named "ptr" - that is a MASM keyword)
; =============================================================================
TYPE_CHECK macro preg, magic32
    local ok
    cmp     dword ptr [preg], magic32
    je      ok
    mov     ecx, FF_TYPE_MAGIC
    jmp     ff_trap
ok:
endm

; =============================================================================
; FASTFAIL code - unconditional immediate termination
; =============================================================================
FASTFAIL macro code
    mov     ecx, code
    jmp     ff_trap
endm

; =============================================================================
; WINCALL fn, arg1, arg2, ...  -- call with the Win64 calling convention.
;
; The first four arguments load into rcx, rdx, r8, r9; the fifth onward land on
; the caller's shadow space at [rsp+32], [rsp+40], ...  An argument written as
; "addr X" passes the ADDRESS of X via lea (required under /highentropyva, where
; a 32-bit absolute "mov reg, offset X" is illegal); any other argument passes
; its value with mov.  An argument already sitting in its destination register
; is skipped.
;
; Register arguments are emitted rcx-LAST (r9, r8, rdx, rcx) so a value arriving
; in rcx can still be used as the source for the later arguments -- e.g.
;   WINCALL VirtualAlloc, 0, rcx, <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
; copies the incoming rcx into rdx before rcx is overwritten with 0.  (Cross
; dependencies among rdx/r8/r9 are not auto-resolved; stage those via r10/r11.)
;
; Clobbers rax (scratch for address / memory stack arguments).
;
; Ordering: stack arguments (5th+) are stored BEFORE the register arguments are
; loaded.  This is safe unless a register argument's SOURCE is a memory slot that
; a stack-argument DESTINATION overwrites -- which only happens when a proc's
; locals overlap its outgoing-argument area (a small frame passing many args).
; In that rare case (see create_ctl) keep the call hand-written.
; =============================================================================
; load one register argument, matching the destination width to the operand
; (a 32-bit operand zero-extends into the 32-bit dest, exactly like the original
; "mov r8d, edx" hand-code; type()==4 means a 32-bit register or dword memory).
__WREGARG macro op:req, dst:req, dst32:req
    if @InStr(1, <&op&>, <addr >) eq 1
        lea     dst, [@SubStr(<&op&>, 6)]
    elseifidni <&op&>, <&dst&>
        ; already in the destination register -- nothing to do
    elseifidni <&op&>, <&dst32&>
        ; already in the low half of the destination -- nothing to do
    elseif (type (op)) eq 4
        mov     dst32, op
    else
        mov     dst, op
    endif
endm

__WSTKARG macro op:req, off:req
    if @InStr(1, <&op&>, <addr >) eq 1
        lea     rax, [@SubStr(<&op&>, 6)]
        mov     qword ptr [rsp+off], rax
    elseif (opattr (op)) AND 004h          ; absolute constant -> direct store
        mov     qword ptr [rsp+off], op
    elseif (type (op)) eq 4                ; 32-bit reg/mem -> zero-extend via eax
        mov     eax, op
        mov     qword ptr [rsp+off], rax
    elseif (opattr (op)) AND 010h          ; 64-bit register -> direct store
        mov     qword ptr [rsp+off], op
    else                                   ; 64-bit memory value -> via rax
        mov     rax, op
        mov     qword ptr [rsp+off], rax
    endif
endm

WINCALL macro fn:req, args:VARARG
    local n
    n = 0
    for a, <args>
        n = n + 1
        if n eq 1
            __WA1 textequ <a>
        elseif n eq 2
            __WA2 textequ <a>
        elseif n eq 3
            __WA3 textequ <a>
        elseif n eq 4
            __WA4 textequ <a>
        else
            __WSTKARG <a>, %(32 + 8 * (n - 5))
        endif
    endm
    if n ge 4
        __WREGARG %__WA4, r9, r9d
    endif
    if n ge 3
        __WREGARG %__WA3, r8, r8d
    endif
    if n ge 2
        __WREGARG %__WA2, rdx, edx
    endif
    if n ge 1
        __WREGARG %__WA1, rcx, ecx
    endif
    call    fn
endm

; =============================================================================
; Structured conditionals.  ml64 has no high-level .IF/.ELSE/.ENDIF, so these
; build the equivalent from cmp + jcc.  The condition code is given EXPLICITLY
; (e/ne, unsigned a/ae/b/be, signed g/ge/l/le, z/nz/s/ns), which keeps the
; signed-vs-unsigned choice in the author's hands -- no hidden default.
;
;   xIF  rax, e, 0          ; if rax == 0
;       ...
;   xELIF rax, a, 100h      ; else if (unsigned) rax > 0x100
;       ...
;   xELSE
;       ...
;   xENDIF
;
;   xIFT rcx               ; "if rcx != 0" (test rcx,rcx; taken when nonzero)
;   xIFZ rcx               ; "if rcx == 0"
;
; Nesting is supported (a per-depth sequence id is stacked).  The condition is
; the TAKEN condition for the then-block; the macro emits the inverse jump.
; =============================================================================
__cf_seq   = 0
__cf_depth = 0

; map a taken condition code -> the opposite jump mnemonic (to skip the block)
__cf_jinv macro cc, lbl
    ifidni <cc>, <e>
        jne lbl
    elseifidni <cc>, <z>
        jnz lbl
    elseifidni <cc>, <ne>
        je  lbl
    elseifidni <cc>, <nz>
        jz  lbl
    elseifidni <cc>, <a>
        jbe lbl
    elseifidni <cc>, <ae>
        jb  lbl
    elseifidni <cc>, <b>
        jae lbl
    elseifidni <cc>, <be>
        ja  lbl
    elseifidni <cc>, <g>
        jle lbl
    elseifidni <cc>, <ge>
        jl  lbl
    elseifidni <cc>, <l>
        jge lbl
    elseifidni <cc>, <le>
        jg  lbl
    elseifidni <cc>, <s>
        jns lbl
    elseifidni <cc>, <ns>
        js  lbl
    else
        .err <xIF: unknown condition code cc>
    endif
endm

; per-depth state:
;   __cf_chain_<d>   = id of the (stable) end label for this if/elif/else chain
;   __cf_cur_<d>     = id of the CURRENT branch's false label
;   __cf_haselse_<d> = 1 once xELSE has been emitted
xIF macro lhs:req, cc:req, rhs:req
    __cf_seq   = __cf_seq + 1
    __cf_depth = __cf_depth + 1
    @CatStr(<__cf_chain_>, %__cf_depth)   = __cf_seq
    @CatStr(<__cf_cur_>, %__cf_depth)     = __cf_seq
    @CatStr(<__cf_haselse_>, %__cf_depth) = 0
    cmp     lhs, rhs
    __cf_jinv cc, @CatStr(<__cf_false_>, %__cf_seq)
endm

; test-style entry: xIFT reg -> if reg != 0 ; xIFZ reg -> if reg == 0
xIFT macro reg:req
    __cf_seq   = __cf_seq + 1
    __cf_depth = __cf_depth + 1
    @CatStr(<__cf_chain_>, %__cf_depth)   = __cf_seq
    @CatStr(<__cf_cur_>, %__cf_depth)     = __cf_seq
    @CatStr(<__cf_haselse_>, %__cf_depth) = 0
    test    reg, reg
    jz      @CatStr(<__cf_false_>, %__cf_seq)
endm
xIFZ macro reg:req
    __cf_seq   = __cf_seq + 1
    __cf_depth = __cf_depth + 1
    @CatStr(<__cf_chain_>, %__cf_depth)   = __cf_seq
    @CatStr(<__cf_cur_>, %__cf_depth)     = __cf_seq
    @CatStr(<__cf_haselse_>, %__cf_depth) = 0
    test    reg, reg
    jnz     @CatStr(<__cf_false_>, %__cf_seq)
endm

xELSE macro
    __cf_a = @CatStr(<__cf_chain_>, %__cf_depth)
    __cf_b = @CatStr(<__cf_cur_>, %__cf_depth)
    @CatStr(<__cf_haselse_>, %__cf_depth) = 1
    jmp     @CatStr(<__cf_end_>, %__cf_a)
    @CatStr(<__cf_false_>, %__cf_b):
endm

; else-if: close the current then with a jump to end, open a fresh compare
xELIF macro lhs:req, cc:req, rhs:req
    __cf_a = @CatStr(<__cf_chain_>, %__cf_depth)
    __cf_b = @CatStr(<__cf_cur_>, %__cf_depth)
    jmp     @CatStr(<__cf_end_>, %__cf_a)
    @CatStr(<__cf_false_>, %__cf_b):
    __cf_seq = __cf_seq + 1
    @CatStr(<__cf_cur_>, %__cf_depth) = __cf_seq
    cmp     lhs, rhs
    __cf_jinv cc, @CatStr(<__cf_false_>, %__cf_seq)
endm

xENDIF macro
    __cf_a = @CatStr(<__cf_chain_>, %__cf_depth)
    __cf_b = @CatStr(<__cf_cur_>, %__cf_depth)
    if (@CatStr(<__cf_haselse_>, %__cf_depth)) eq 0
        @CatStr(<__cf_false_>, %__cf_b):    ; no else: false target == end
    endif
    @CatStr(<__cf_end_>, %__cf_a):
    __cf_depth = __cf_depth - 1
endm

; =============================================================================
; Structured top-tested loops (ml64 also has no .WHILE).  Same explicit-cc rule.
;
;   xWHILE qword ptr [rbp-40], ne, 0     ; while (remaining != 0)
;       ...
;       xIFZ eax                          ; (xBREAK / xCONTINUE work too)
;           xBREAK
;       xENDIF
;   xENDW
;
;   xWHILET reg   ; while reg != 0   (test reg,reg)
;   xWHILEZ reg   ; while reg == 0
;
; Nesting supported; xBREAK / xCONTINUE target the innermost loop.
; =============================================================================
__lp_seq   = 0
__lp_depth = 0

xWHILE macro lhs:req, cc:req, rhs:req
    __lp_seq   = __lp_seq + 1
    __lp_depth = __lp_depth + 1
    @CatStr(<__lp_id_>, %__lp_depth) = __lp_seq
    @CatStr(<__lp_top_>, %__lp_seq):
    cmp     lhs, rhs
    __cf_jinv cc, @CatStr(<__lp_end_>, %__lp_seq)
endm
xWHILET macro reg:req
    __lp_seq   = __lp_seq + 1
    __lp_depth = __lp_depth + 1
    @CatStr(<__lp_id_>, %__lp_depth) = __lp_seq
    @CatStr(<__lp_top_>, %__lp_seq):
    test    reg, reg
    jz      @CatStr(<__lp_end_>, %__lp_seq)
endm
xWHILEZ macro reg:req
    __lp_seq   = __lp_seq + 1
    __lp_depth = __lp_depth + 1
    @CatStr(<__lp_id_>, %__lp_depth) = __lp_seq
    @CatStr(<__lp_top_>, %__lp_seq):
    test    reg, reg
    jnz     @CatStr(<__lp_end_>, %__lp_seq)
endm
xENDW macro
    __lp_t = @CatStr(<__lp_id_>, %__lp_depth)
    jmp     @CatStr(<__lp_top_>, %__lp_t)
    @CatStr(<__lp_end_>, %__lp_t):
    __lp_depth = __lp_depth - 1
endm
xBREAK macro
    __lp_t = @CatStr(<__lp_id_>, %__lp_depth)
    jmp     @CatStr(<__lp_end_>, %__lp_t)
endm
xCONTINUE macro
    __lp_t = @CatStr(<__lp_id_>, %__lp_depth)
    jmp     @CatStr(<__lp_top_>, %__lp_t)
endm

; =============================================================================
; ASCII string in .const with automatic length constant:
;   CSTR msg_hello, "hello", 13, 10
; defines  msg_hello  and  msg_hello_len
; =============================================================================
CSTR macro name, text:VARARG
    name db text
    name&_len equ $ - name
endm

; UTF-16 string literal:  WSTR cmd_encrypt, <encrypt>
; (text inside <> may not contain commas; use multiple WSTRs or raw dw)
; Every wide string MUST start 2-aligned: an odd-address WSTR passed to a Win32
; -W API can take an aligned (SSE) read path, raise STATUS_DATATYPE_MISALIGNMENT
; and fail with ERROR_NOACCESS -- Vordr lost a RegisterClassW to exactly this.
; A single odd-length CSTR earlier in the section shifts every WSTR after it (in
; main.asm, msg_st_fail did precisely that to all 29 of them).  The `even` here
; aligns every WSTR, so no block can drift odd.  Callers address these by label,
; never by adjacency, so the padding is free.
WSTR macro name, text
    even
    name label word
    forc c, <text>
        dw '&c'
    endm
    dw 0
endm

; ---------------------------------------------------------------------------
; Globals owned by hardening.asm, referenced by the frame macros everywhere
; ---------------------------------------------------------------------------
externdef g_stack_canary:qword
externdef g_sstk_tls:dword
externdef g_cpu_features:dword
externdef sstk_overflow_fail:near
externdef ff_trap:near                  ; central fail handler (main.asm)
