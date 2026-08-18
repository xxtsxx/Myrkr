# Format v5 — ten million files, and files past 64 GiB

**Status: design only. Nothing here is built.** Written 2026-08-13, in the house
pattern: the design before the code, the way `DROP_INDICATOR.md` and
`VOLUMES.md` went.

Two ceilings were asked about together. They are unrelated in cause and share
one mechanism in the fix, which is why they are designed together and shipped
apart.

---

## 1. The two ceilings

| Ceiling | Value | Whose limit |
|---|---|---|
| One entry's content | 68,719,475,680 bytes ≈ **64 GiB** | **AES-GCM's**, not ours: 2³⁹−256 bits under one (key, nonce) pair. Past it the counter block wraps and the keystream repeats. |
| Files per container | ~**400k–800k**, by path length | **Ours**: the index is one fixed 64 MiB buffer, 40 bytes per entry plus the name. |

Both refuse loudly today — exit 1 with the GCM message, and `idx_add` failing
with no container produced. Neither silently truncates, and that is the floor
this design must not fall below.

---

## 2. The observation that shapes both

The nonce is 96 bits and only 64 of them are in use:

```asm
nonce_set proc              ; rcx = counter, rdx = 12-byte nonce
    mov     qword ptr [rdx], rcx
    mov     dword ptr [rdx+8], 0        ; <- 32 bits, always zero
    ret
```

Entry *i* uses counter `i+1`; the index uses `2⁶³ + revision`. **The top 32 bits
have never been used for anything.** That is exactly one sub-counter's worth of
free, collision-proof nonce space, and both problems need exactly one.

```
        96-bit nonce
  ┌──────────────64──────────────┬────────32────────┐
  │ entry ordinal + 1            │ segment index    │   an entry's segments
  │ 2⁶³ + index revision         │ chunk index      │   the index's chunks
  └──────────────────────────────┴──────────────────┘
```

Bit 63 already separates entries from the index, so the two schemes cannot
collide with each other, and **segment 0 / chunk 0 reproduces today's nonce
exactly** — a v5 container holding one-segment entries has bit-identical nonces
to a v4 one.

---

## 3. Problem A — entries past 64 GiB

### 3.1 Segmented entries

An entry's content becomes one or more **segments**, each its own GCM stream
with its own nonce and its own 16-byte tag:

```
  entry = [ seg 0 ct ][tag][ seg 1 ct ][tag] … [ seg n ct ][tag]
            nonce = (ordinal+1, 0)   (ordinal+1, 1)   (ordinal+1, n)
```

`SEG_BYTES` is a container-wide constant recorded in the header (so it is AAD,
so it cannot be altered) and applied to the bytes **fed to GCM** — i.e. after
compression, not before.

> **Settled against the code, 2026-08-14.** It goes in `hdr_rsvd`, the header's
> one already-reserved byte, as a **power-of-two exponent**: `SEG_BYTES =
> 1 << seg_shift`, `0` meaning unsegmented. That byte is written as zero and
> validated nowhere, so it is free — and being *in* the header it is AAD, which
> is all this paragraph ever wanted. No header growth, no change to `HDR_BYTES`,
> and therefore no version-dependent AAD length anywhere. See
> [`V5_WORK.md`](V5_WORK.md) B2.

### 3.2 AAD, and how a missing segment is caught

Today an entry's AAD is `header ‖ u64 ordinal`. It becomes
`header ‖ u64 ordinal ‖ u32 segment`, so a segment cannot be moved to another
entry, reordered within one, or spliced in from a different container.

**The segment count is deliberately not in the AAD.** With compression the count
is not known until the last byte is written, and an AAD that must be known
up-front would force either a second pass or a rewind — the same argument that
put the index at the end of the container in the first place. Instead the count
and the total content size live in the **index**, which has its own tag. A
dropped final segment is then a size mismatch caught before the last byte is
handed over, exactly as a volume set's missing final part is caught by its flag.

### 3.3 What the index entry gains — nothing, in the end

This section proposed `IDXE_segcount dd`. **It is not needed.** With `S =
SEG_BYTES`, `P` the entry's GCM plaintext and `n` its segment count:

```
  stored = P + 16n   and   n = ceil(P / S)     =>     n = ceil(stored / (S + 16))
```

so the count follows from `IDXE_stored`, which the index already carries.
Verified exhaustively rather than argued — every `P` from 0 to `5S+40` across
nine values of `S`, zero mismatches, including the `P = 0` case and every
exact-multiple boundary.

That matters out of proportion to its size: an index entry whose layout changes
would have to be understood by `idx_find`, `idx_summarise`, `rows_from_index`,
`unpack_entry`, `es_bind` and every edit path, in two versions each. Nothing
changes instead.

`IDXE_size` is still the content length, `IDXE_stored` still the bytes on disk
including every tag.

### 3.4 The bonus worth naming

`SEG_BYTES` is also the **random-access granularity**. Today, reading the last
byte of a 60 GiB entry means decrypting 60 GiB — a GCM stream authenticates from
its start. With 4 GiB segments it means decrypting at most 4 GiB. Dragging one
file out of a large container gets faster, not just possible.

### 3.5 Choosing `SEG_BYTES`

| Segment | Tags for a 100 GB file | Worst-case seek cost |
|---|---|---|
| 32 GiB | 4 (64 B) | 32 GiB |
| 8 GiB | 12 (192 B) | 8 GiB |
| **4 GiB** | **24 (384 B)** | **4 GiB** |
| 1 GiB | 94 (1.5 KB) | 1 GiB |

**Proposal: 4 GiB.** The overhead is noise at any of these; the seek cost is
not. It also keeps a whole segment inside a 32-bit length in the places that
still use one.

### 3.6 Reader changes

`ES_Read` and the unpack loop map a logical offset to `(segment, offset)` and
reopen the stream at a boundary. This is the same shape as `vol_get` spanning
parts — a mapping layer over a run of streams — one level up. `vol_get` is the
model to copy, including its "a read that crosses a cut is the normal case, not
an edge one" test posture.

---

## 4. Problem B — ten million files

### 4.1 Why the current index cannot stretch

`g_idxbuf` is a fixed 64 MiB `.data?` buffer holding the **whole plaintext
index**, and every consumer — `idx_find`, `rows_from_index`, the drag-out
streams, unpack — walks it linearly. Ten million entries at ~120 bytes is
1.2 GB. There is no tuning of `IDX_MAX_BYTES` that survives that.

### 4.2 Design: sorted entries, fixed chunks, a chunk directory

Three changes, and the second is what makes the third affordable.

**a. Entries are sorted** by tar name, byte order. Today they are in walk order.
Sorting makes a folder's children *contiguous*, which is what turns "list this
directory" from a full scan into a range read.

**b. The index is cut into chunks** of `IDX_CHUNK_BYTES` plaintext (proposal:
256 KiB), each its own GCM stream, nonce `(2⁶³ + revision, chunk)`.

**c. A chunk directory** at the end names each chunk:

```
  per chunk: { plaintext offset, ciphertext offset, ciphertext length,
               first name (truncated, for the binary search) }
```

The directory is itself a GCM stream, nonce `(2⁶³ + revision, 0xFFFFFFFF)`, and
the trailer grows an offset and length for it. Ten million entries at 256 KiB
chunks is about 4,700 directory rows — tens of kilobytes, always in memory.

### 4.3 What that buys

| Operation | Today | v5 |
|---|---|---|
| Find one entry | scan the whole index | binary search the directory, decrypt **one** chunk |
| List a folder | scan the whole index | binary search to the prefix, read while it matches |
| Open a container | decrypt the whole index | decrypt the directory only |
| Working set | 64 MiB, fixed | a bounded chunk cache (proposal: 16 MiB) |

### 4.4 The new machinery, stated plainly

**Sorting needs the whole entry list before the index is written.** Packing is
one streaming pass and entries are recorded as they are packed — deliberately,
so the listing cannot describe something the container does not hold. That
property is kept: entries are still *recorded* as packed, but into a **spill
file** rather than a buffer, and the spill is externally merge-sorted at the end,
before the index is written.

> **Superseded by §9.3.** A sorted recursive walk produces the order directly,
> with no spill file and no merge at all. This subsection is kept because the
> reasoning that led to it is what makes §9.3 obviously better.

An external merge sort in a no-CRT codebase is the largest single piece of new
code in this plan. It is also the piece most likely to be got subtly wrong, and
it has no security consequence if it fails loudly — which argues for making it
fail loudly and testing it on its own, away from the container.

### 4.5 Edits

Add and remove already bump the revision and rewrite the index. With chunks they
rewrite the *affected* chunks plus the directory. The nonce rule holds because
the revision is in the nonce's low 64 bits and the chunk index in the high 32 —
a rewritten chunk under a bumped revision has never been used.

### 4.6 The GUI

`ROWS_MAX` stays at 2048 — a listing of ten million rows is not a listing.
`rows_from_index` becomes a windowed read over the sorted index: the visible
range plus the expanded folders, each a range read. Collapsed subtrees are
skipped by *not reading their chunks*, where today they are skipped after being
walked.

---

## 5. Phasing

**One format bump, two releases.** v5 is defined once, with both the segment
count and the chunked-index shape in it. Phase 1 writes v5 containers whose
entries mostly have one segment and whose index is one chunk — a legal v5 that
exercises the new fields at their trivial values. Phase 2 makes both plural. Two
bumps would mean two migrations for no benefit.

| Phase | Delivers | Rough shape |
|---|---|---|
| **0** | This document, reviewed. | — |
| **1** | Files past 64 GiB. | Header gains `SEG_BYTES`; `IDXE_segcount`; writer cuts at boundaries; reader maps offsets; AAD gains the segment index. Self-contained: no GUI change, no sort. |
| **2a** | The index off the static buffer. | Chunking, the directory, the chunk cache, the trailer fields. Insertion order kept — **no sort yet**. Everything still works, nothing is faster. |
| **2b** | Sorted entries. | A sorted recursive walk (§9.3), not a merge sort. Lookups and folder listings become range reads. |
| **2c** | The GUI at scale. | Windowed `rows_from_index`; expansion as a range read. |
| **3** | v4 read-only compatibility, kept forever. | The reader dispatches on `HDR_version`; v4 containers stay readable and are not rewritten in place. |

Phase 1 is worth doing on its own even if phase 2 never happens. Phase 2a is
worth doing on its own — it removes a fixed 64 MiB allocation from every run.

---

## 6. How this gets tested, which is what decides whether it is real

**Neither ceiling can be reached on an ordinary machine.** A real 100 GB
round-trip needs 200 GB of disk; ten million files needs hours and a punished
MFT. A design that can only be tested at full scale will not be tested.

So both constants become **debug-shrinkable**, exactly as `MYRKR_DBG_VOLBYTES`
already does for volume parts:

```
  MYRKR_DBG_SEGBYTES=1048576     segment every 1 MiB   -> 10 segments in a 10 MB file
  MYRKR_DBG_IDXCHUNK=4096        4 KiB index chunks    -> ~40 chunks at 20k files
```

That is the whole testing strategy, and it is the reason to believe the plan.
Every boundary case — a read spanning a segment cut, a folder spanning a chunk,
an edit rewriting the middle chunk of five — becomes reachable in a two-second
test. `volumetest.ps1` is the working precedent: it splits 10 MiB at ~2 MB a part
and has caught real defects at that scale that would have been invisible at 25 GB.

Additional checks the design earns:

- **A nonce-uniqueness test.** Dump every (nonce, stream) pair a container used
  and assert no repeats. Cheap, and it is the one mistake in this design that
  cannot be recovered from.
- **Sparse-file refusal tests**, which already work — that is how the 64 GiB
  boundary was measured for this document, at a cost of zero disk.
- **The external sort tested alone**, on adversarial name sets, before it is
  wired to anything.
- `manyfiles.ps1` extended past the current 20,000.

---

## 7. Risks, in the order they should worry us

1. **Nonce reuse.** The unrecoverable one. Two counters now live in one nonce,
   and every path that constructs one must agree. Mitigated by the uniqueness
   test above, by bit 63 keeping the two spaces apart, and by segment 0 / chunk 0
   being byte-identical to v4 — so the common case is the already-proven case.
2. **The external merge sort.** New, non-trivial, no-CRT, and the place a subtle
   bug would silently mis-order an index. Test it alone first.
3. **Windowed GUI reads.** A bigger change than it looks; `rows_from_index` is
   already the most intricate proc in `gui.asm`.
4. **Edit paths.** Add and remove already have the most delicate invariants in
   the codebase (the ordinal counter, in-place overwrite). Chunking touches them.
5. **v4 compatibility drift.** Two readers is two code paths; the older one gets
   exercised only by old containers. Keep a v4 fixture in the test suite forever.

---

## 8. What this does *not* solve

Worth saying, so the numbers are not oversold:

- **Ten million files still costs 5 GB of tar framing** (512 bytes an entry) and
  160 MB of GCM tags, before any content. The container is large because the file
  count is large.
- **Encrypt time at that scale is dominated by per-file syscalls**, not by
  crypto. Nothing here makes it fast.
- **Explorer is not going to enjoy it either.** Dragging ten million entries out
  is not a use case this makes good.
- **`MAX_ARGS` stays at 255 inputs.** Ten million files means one folder, not ten
  million arguments.

---

## 9. Optimisations the new parameters open up

Reviewed after the design above was written, looking for what becomes possible —
or newly unaffordable — at these scales. Ordered by value, and checked against
the code; where a claim is not checked, it says so.

### 9.1 Extraction should be driven by the index, not by a temp tar  ✅ *done, 1.0.71*

**The largest single win available, and it was available today, without v5.**
Shipped as step A2 of [`V5_WORK.md`](V5_WORK.md); the rest of this section is
left as it was written, because it is the reasoning that produced the change.

A full decrypt of an archive currently does this, and the source says so plainly:

> *"The entries are written out back to back, which reproduces exactly the byte
> stream the old single-stream format held — so everything downstream (frame
> decompression, tar extraction) is untouched."*

`do_unpack` decrypts every entry into a **complete plaintext tar in a temp file**,
and `extract_tar` then walks that file writing the individual outputs. For an
archive of N bytes:

```
   write N (temp)  +  read N (temp)  +  write N (output)   = 3N of I/O
   plus N bytes of scratch disk on top of the output
```

It was a deliberate compatibility choice when per-entry streams arrived in v4,
and at the sizes of the time it cost little. At the sizes this document is about
it dominates: a 587 GB archive moves about 1.2 TB more than it needs to and
demands 587 GB of scratch.

The index already holds name, size, offset, ordinal and flags for every entry —
everything `extract_tar` recovers by parsing. **Extract straight from the index:**
for each entry, create the output file and decrypt its stream into it.

```
   read N  +  write N     = 2N,  and no temp file at all
```

That also deletes the "not enough free disk space" refusal for the common case,
because the output becomes the only thing written.

Three consequences follow:

- **The 512-byte tar header per entry becomes dead weight** for `.mrk`. At ten
  million files that is **5 GB of pure framing**.
- `extract_tar` and `decompress_archive` leave the `.mrk` path. **In the event
  they left the tree entirely** — `unzip` turned out to use neither, and
  `tar_parse_header` went with them, which retires a parser that ran on
  attacker-supplied bytes.
- Extraction parallelises per entry (§9.5).

**The first draft of this section claimed an obstacle and was wrong.** It said
compressed frames could span two entries. They cannot: `entry_end` calls
`csink_flush` at every entry boundary, so an entry's frames are self-contained,
and `estream.asm` already relies on exactly that to serve one entry out of a
compressed container. Direct extraction works for stored and compressed
archives alike, which makes this change cheaper than it looked and makes §9.2
unnecessary.

### 9.2 Compression is already per entry — withdrawn

This proposed making compression per entry so that §9.1 would work on compressed
archives. **It already is per entry.** `entry_end` flushes the compressor before
closing each entry's GCM stream, so every entry ends on a frame boundary;
`estream.asm` documents the three-layer decode and depends on it.

Withdrawn rather than deleted, because a reader who wonders "why is compression
not per entry?" deserves the answer that it is — and because the withdrawal is
what makes §9.1 cheap.

### 9.3 The external merge sort can probably be deleted before it is written

§4.4 called it "the largest single piece of new code in this plan" and "the piece
most likely to be got subtly wrong". It may not be needed at all.

The walk is depth-first over a directory tree. **Sort each directory's children
before recursing** — a small in-memory list — and the emitted sequence is already
in a total order. No spill file, no merge, no second pass over 1.2 GB.

The catch is *which* order, and it is a genuine trap: byte-order on full paths and
depth-first-with-sorted-children are **not** the same order. `.` (0x2E) sorts
before `/` (0x2F), so `a.txt` precedes `a/b` bytewise, while a recursive walk
emits everything under `a/` first. Pick one and use it everywhere:

**Define the index order as component-wise** — compare path components, not raw
bytes — which is exactly what a sorted recursive walk produces. The binary search
in §4.3 uses the same comparator, and a folder's children stay contiguous, which
is the only property the design actually needs.

Sorting is then O(k log k) per directory on lists that fit in cache, and risk 2
in §7 disappears.

### 9.4 The index entry can be made much smaller — and only sorting makes it so

Sorted neighbours share long prefixes. Three savings compound:

| Field | Today | Under v5 |
|---|---|---|
| `IDXE_offset` (8 B) | absolute | derivable: chunk base plus the running sum of `stored`. **Drop it.** |
| `IDXE_ordinal` (8 B) | absolute | equals position + 1 except after deletions — store a flag and a delta |
| name | full path | front-coded: shared-prefix length plus suffix |

`ComfyUI/models/checkpoints/…` repeated thousands of times collapses to a byte or
two per entry. A realistic tree goes from ~120 bytes an entry to about **30**,
which moves ten million files from a 1.2 GB index to roughly 300 MB.

**Or simply compress each chunk** with the XPRESS codec already in the tree
(`compress.asm`) before encrypting it. Chunks are independent, so random access
survives at chunk granularity, and it is far less new code than front-coding.
Worth measuring both: front-coding wins on lookup cost, per-chunk compression
wins on effort.

### 9.5 Segments make large work parallel — the point, not a side effect

Each segment is an independent GCM stream with its own nonce; nothing sequences
them. So under §3:

- a 100 GB file encrypts, decrypts and verifies **across cores**, where today one
  file is one sequential stream;
- `verify` is embarrassingly parallel — it writes nothing, so there is not even an
  output-ordering constraint;
- with §9.1, a full extract parallelises per entry as well as per segment.

The codebase is already multi-threaded (the indexer thread) and the shadow stack
is already per-thread, so the machinery exists. AES-NI runs at roughly 5 GB/s per
core; four cores saturate most NVMe. This is the difference between "100 GB is
possible" and "100 GB is practical".

### 9.6 The summary counts belong in the trailer

`counttest` exposed that the file count, folder count and byte total are
recomputed by **walking the whole inventory inside `rows_from_index`**, which runs
on every expand and collapse. At 84,000 entries that is unnoticeable. At ten
million, with the index no longer resident, it would mean decrypting the entire
index on every click.

Put the three totals in the trailer, which is already inside the index's AAD and
therefore already authenticated. The summary becomes O(1) and no walk happens at
all. **Worth doing now, independently of v5.**

### 9.7 Lookups that are linear today and should not stay that way

| Proc | Cost now | Where it bites |
|---|---|---|
| `idx_find` | linear scan of every entry | the add-duplicate check calls it **per added file** — adding 1,000 files to a 500k-entry container is about 5×10⁸ name comparisons. Sorted index → binary search, ~19 each. |
| `pset_find` | linear over the expanded-folder set | called once per **ancestor per row** in `rows_from_index`. Fine at 2,048 rows; not fine as the set grows. |

Both become cheap under §4.2 with no new algorithm — the sort is what buys it.

### 9.8 Two things that get worse, and are not solved here

- **The action log is one line per entry, uncapped** by explicit instruction. Ten
  million entries is roughly a gigabyte of log. That needs a scale story before
  ten million is a supported number; a cap contradicts the instruction, so the
  answer is probably to log entries only at `debug`.
- **Per-entry GCM overhead does not amortise for tiny files.** Ten million entries
  carry 160 MB of tags and ten million stream setups regardless of content.
  Bundling small files into a shared stream would fix it and would destroy
  per-entry random access and per-entry containment — the two properties the
  format exists for. **Named, not taken.**

### 9.9 What this changes about the plan

§9.1, §9.6 and §9.7 are worth doing **whether or not v5 happens**: the first is a
3N → 2N improvement on every archive extract that exists today, and the other two
are cheap. §9.3 removes the plan's biggest risk before it is taken. §9.2 is withdrawn — it described
a change that turned out to be in the code already.

Suggested revision to the phasing in §5: insert **phase 0.5 — index-driven
extraction and cached counts** *before* segments. It
is independent of the format bump, it pays immediately, and it removes the
temp-tar machinery that would otherwise be carried through every later phase.

---

## 10. Recommendation

Do **phase 1** first and ship it: it is self-contained, it removes a limit that
is a hard refusal today, and it makes large-entry random access faster as a side
effect.

Do **phase 2a** next whether or not 2b follows — taking a fixed 64 MiB buffer out
of every run is worth having by itself, and it is the step that makes the rest
possible.

Treat **2b and 2c as a separate decision**, made after 2a is in and measured.
Ten million files is a real target only if the walk, the framing and the GUI are
all acceptable at that scale, and the honest way to find out is to measure a
million first.
