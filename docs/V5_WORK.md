# v5 — the work plan

The **executable** counterpart to [`FORMAT_V5.md`](FORMAT_V5.md), which holds the
reasoning. This one holds the order, the exact code to touch, and how each step
is proved. It is written to be picked up cold: nothing here assumes you remember
the conversation it came from.

**Rule for every step below:** one step, one release. Build strict, run the
suites, mutation-check the new test, bump, MSI, install, push. A step that cannot
be proved does not ship.

---

## Phase A — pays off now, no format change

Nothing in phase A alters a byte of the container. Old containers keep working
and new ones stay v4.

### A1 · Cache the summary counts  ✅ *(smallest, do first)*

**Problem.** `rows_from_index` (`gui.asm`) recomputes `g_idx_files`,
`g_idx_dirs` and `g_idx_bytes` by walking every index entry — and it runs on
every expand, collapse and repaint. At 84k entries that is invisible; with a
non-resident index (phase C) it would mean decrypting the whole index per click.

**Change.** Walk once when the container is opened and cache. `rows_from_index`
reads the cache and stops accounting.

- `gui.asm` — the accounting block at `rfi_accounted`; move it to a new
  `idx_summarise` called from the open path (near where `g_scan_files` is set
  from `g_idx_files`).
- Guard: the cache must be invalidated by any edit (add/remove reloads the
  container, so hooking the same place the reload does is enough).

**Proof.** `counttest.ps1` already asserts the numbers from both sides; it must
still pass unchanged. Add one check: the summary must be identical **after**
expanding a folder, which is what catches a cache that is never refilled.
Mutation: make `idx_summarise` a no-op → counts read 0.

### A1b · Name the header bytes the struct does not admit exist

**Inert — no format change, no behaviour change. Ships with A1.**

`CONTAINER_HDR` declares `lanes dd ?` at offset 16. The writer puts four
separate bytes there:

```asm
mov     byte ptr [r10+16], 1        ; lanes
mov     byte ptr [r10+17], al       ; archive flag  (NOT (bare))
mov     byte ptr [r10+18], al       ; compression   (0 store / 1 xpress)
mov     byte ptr [r10+19], 0        ; reserved
```

So the canonical definition of the container format **omits the two fields that
decode depends on**, and eight call sites across four files read them as raw
offsets instead:

```
cmd.asm:605  [r10+16]   cmd.asm:607  [r10+17]   cmd.asm:881  [r10+18]
cmd.asm:883  [r10+17]   estream.asm:751 [g_pkhdr+18]   estream.asm:770 [g_pkhdr+18]
estream.asm:775 [g_pkhdr+17]          pack.asm:2171 [r10+16]
```

Nothing on disk is wrong and nothing changes on disk. But the struct **is** the
format's documentation, `constcheck` cannot see the discrepancy, and phase B
edits this header — against a description that does not match it.

**Change.**

```asm
    lanes       db ?               ; Argon2id parallelism (always 1)
    archive     db ?               ; 1 = the payload is a tar stream, 0 = one file
    compressed  db ?               ; 0 = store, 1 = XPRESS-framed
    hdr_rsvd    db ?               ; must be 0
```

Same 64 bytes, same offsets, same output. Then replace the eight raw offsets
with `CONTAINER_HDR.archive` / `.compressed` / `.lanes`.

**Proof.** `build release` is reproducible, so the strongest check is that the
binary is **byte-identical before and after** — a pure renaming that changed a
byte would show up immediately. Failing that: `manyfiles.ps1` covers archive and
bare, stored and compressed, in both directions, and `estreamtest` covers the two
`estream` sites. No new test; this is a refactor whose whole claim is that
nothing changes.

### A2 · Extract straight from the index, not through a temp tar  ✅ *(1.0.71)*

**Was.** `do_unpack` decrypted every entry into a complete plaintext tar beside
the container, then `extract_tar` walked that file writing the real outputs.
`3N` of I/O, `N` of scratch disk, and a full decrypted copy of the archive on
disk for the length of the run.

**Is.** `unpack_entry` decodes one entry straight into its own output file. `2N`,
no temp, and the disk pre-flight now asks for the entries' actual content size on
the OUTPUT drive instead of the container's size on the container's drive twice.

#### What the plan got wrong, and what the code turned out to be

This section previously said A2 was *gated* on lifting the frame decoder out of
`estream.asm` into a shared context — roughly 80 lines of state machine plus a
six-argument `Decompress` call — because writing a second de-framer in `pack.asm`
is what `vol_part_suffix` exists to warn against.

**The gate was real; the work was not.** Reading `estream.asm` properly showed
the shared context ALREADY EXISTS: the ES object is one. It carries the GCM
context, both buffers, the decompressor and the position, and `es_consume`
already delivers "n content bytes with the tar header skipped, the padding
drained and the tag checked". The COM vtable is a wrapper on top of it, not the
thing itself. So the lift was a **split, not a move**:

- `es_new(path)` — everything about the CONTAINER: the allocation sized to its
  framing, the handle, the decompressor.
- `es_bind(this, entry, key)` — everything about ONE ENTRY, resettable.
- `es_create` = the two in a row, so drag-out is unchanged.

`do_unpack` holds one context for the whole run: one allocation and one
`CreateDecompressor` for an archive of any size, rather than one per entry.
`estreamtest` passed untouched, which was the stated proof.

One thing did have to be added rather than moved: `ES_ecode`. The decoder only
ever set a sticky error BIT, which is all the COM path needs (`E_FAIL`), but
"the tag did not match" (`EXIT_AUTH`), "the disk did not answer" (`EXIT_IO`) and
"that frame did not decode" (`EXIT_CORRUPT`) are three different things to tell
someone about their archive, and `do_unpack` had been distinguishing them.

#### What else fell out

- `extract_tar`, `decompress_archive`, `build_temptar`, `g_temptar`, `g_decin`,
  `g_decout` (2 MiB of BSS) and `compress.asm`'s `decomp_init` / `decomp_block` /
  `decomp_close` had no other caller and are gone. So is **`tar_parse_header`** —
  a parser that ran on attacker-supplied bytes and whose every output (name,
  size, type) the authenticated inventory already records.
- Names now come from the index rather than a tar header, so `entry_path` runs
  `sanitize_name` against the index name. The traversal control is the same one,
  in the same place in the sequence; `secsuite`'s C1 case covers it and passes.

#### Two behaviour changes, both deliberate

1. **A failed extraction leaves the entries it had already verified.** They are
   each authentic, but the SET is short, and an attacker who can corrupt a
   container chooses where it stops. So the run SAYS so — `e_pincomplete` on
   stderr, `m_part_extract` in the window (replacing the cause box, because a
   folder with files in it reads as a partial success). `docs/SECURITY.md` §6.
2. **A single-file container is decoded to `OUTPUT.part` and renamed** once its
   tag verifies, so a file under the name the user asked for has always been
   authenticated. The temp copy used to provide that; a rename provides it for
   one metadata operation. NOT done per entry for archives — that is a rename
   per file, and archives never had the property anyway.

**Proof.** `manyfiles`, `volumetest`, `estreamtest`, `counttest`, `pickertest`,
`prefixtest`, `droptest`, `canceltest`, `afterencrypttest`, `greytest` and both
phases of `tests/run.ps1` pass untouched. New `tests/extracttest.ps1` adds the
two claims that are specific to this change — no scratch (proved by denying the
process the right to create files in the container's own directory, not by
watching for a temp to appear, which is a race) and a tampered entry never
reaching disk — mutation-checked five ways, listed at the bottom of that file.

### A3 · Binary-search the duplicate check

**Problem.** `idx_find` (`pack.asm`) is a linear scan and `do_add` calls it once
per added file. Adding 1,000 files to a 500k-entry container is ~5×10⁸ name
comparisons.

**Change.** Deferred to phase D, where the index is sorted and the search is
19 comparisons. Recorded here so it is not lost: **do not** hand-roll a hash
index in phase A to fix it early.

---

## Phase B — segments (a format bump)

Unlocks entries past 64 GiB. Self-contained: no GUI change, no sorting.

### What reading the code first changed about this phase (2026-08-14)

Three things phase B was written on top of turned out not to hold. None of them
is fatal; all of them change the order.

**1. The on-disk version is 6, not 4.** `HDR_VERSION equ 6` in `macros.inc`.
The `v4`/`v5` in these documents name the *design generation*; the header field
names the on-disk revision, and it has been bumped since. The struct's own
comment said `; 4` and has been corrected. **Phase B bumps 6 → 7**, and nothing
in either document should say "v5" about a number that goes in a file.

**2. Nothing in the tree can read an older container.** All four readers compare
the version for exact equality and jump to *corrupt* on any difference. So "v4
stays readable forever" is not a property being preserved — it is a property that
**does not exist yet and has to be built**. Until it is, a bump makes every
container anyone already has unreadable, and tells them it is damaged.

**3. The fixture had to be made before anything else.** The plan says the old
format "gets a fixture in the suite that is never regenerated". That fixture
**cannot be produced after the bump** — once the writer emits the new version
there is nothing left that writes the old one, and the compatibility claim
becomes permanently untestable. It was therefore frozen first, at 1.0.72.

### B0 · Freeze the old format, and stop calling it corrupt  ✅ *(1.0.73)*

- `tests/fixtures/v6-*.mrk` — five containers written by the 1.0.72 writer:
  archive stored, archive compressed, bare stored, bare compressed, and a
  three-part volume set. Checked in, **never regenerated**;
  `tools/make_v6_fixtures.ps1` records how, and refuses to run.
- `tests/compattest.ps1` opens all five, compares every file by SHA-256, lists
  and verifies. It also asserts the fixtures' **on-disk version byte**, because a
  fixture regenerated by a newer writer would still decrypt and the test would
  pass while proving nothing.
- Mutation-checked with the exact change phase B makes — `HDR_VERSION 6 → 7` —
  which fails every check with "not a valid Myrkr container" while the fixture
  assertions still pass, i.e. it correctly blames the reader.
- A version mismatch now says so (`hdr_bad_version`, `EXIT_UNSUPPORTED`) instead
  of "not a valid Myrkr container". Telling someone their intact archive is
  corrupt sends them to a backup they do not need.

**This is green today against an unchanged format.** That is the point: it is in
place before the bump, so the day the bump lands it is the thing that catches it.

### B1 · Read a RANGE of versions, not one  ✅ *(1.0.74)*

Done before the writer changes anything, so it could be proved against the
fixtures while they were still the only thing in existence.

- `HDR_VERSION` (what the writer emits) and `HDR_VERSION_MIN` (the oldest a
  reader accepts). Four exact-equality compares became one gate,
  `hdr_version_ok` — because the segment work makes the version decide
  **behaviour**, and four sites that agree today are four sites that can
  disagree after one of them is edited.
- The gate **prints nothing**. The GUI's peek path answers "is this one of
  ours?" about a file the user has only hovered over; callers that report to a
  user follow a refusal with `hdr_bad_version`.
- **The writer moved to 7, and 7 is byte-for-byte identical to 6.** That is the
  point: the dispatch is live and continuously exercised — every test now writes
  7, and `tests/fixtures/v6-*.mrk` are 6 — *before* anything hangs off it. The
  first real divergence therefore lands on plumbing already known to work.
- `compattest` gained the check that makes the rest of it mean anything: that
  this build's writer actually emits a **different** version from the fixtures.
  Without it the whole file passes just as well against a build that never
  moved, i.e. a compatibility test only reading its own output.

**Consequence, and it is inherent to any bump:** containers written by 1.0.74
and later do not open in 1.0.73 and earlier. They say so properly now rather
than calling the file corrupt, which is what B0 was for.

### B2 · The format fields — settled 2026-08-14, and much smaller than planned

`FORMAT_V5.md` §3 asks for two things: `SEG_BYTES` in the header, and
`IDXE_segcount` in every index entry. Both were checked against the code before
building, and **neither is needed**.

#### `SEG_BYTES` goes in the header byte that is already reserved

The header has exactly one spare byte, `hdr_rsvd` at offset 19. It is written as
`0` by `do_pack` and **validated nowhere** — checked, one writer, no reader. So:

```
    seg_shift   db ?    ; 0 = unsegmented.  Otherwise SEG_BYTES = 1 << seg_shift.
```

This gets everything §3.1 wanted from putting it in the header — it *is* the
header, so it is AAD for every entry, so it cannot be altered without failing
every tag — at a cost of **nothing at all**:

- `HDR_BYTES` stays 80, so no AAD length changes anywhere;
- no header growth, so no version-dependent header parsing;
- v6 and v7 containers have `0` there already, which reads as "unsegmented",
  which is exactly what they are.

The only thing given up is that `SEG_BYTES` must be a power of two. That is not
a loss: a power of two is what makes boundary arithmetic a shift and a mask
instead of a divide, which is what the writer wants anyway. **Proposal stands at
4 GiB, i.e. `seg_shift = 32`.**

The plan's "grow the header to 128 bytes, once and generously" was written for a
world where a field had to go in it. Nothing here does. Phase C can revisit it
if the chunk directory really cannot fit anywhere else — and the trailer, not
the header, is the cheaper place to grow, because the trailer is in **one** AAD
(the index's) while the header is in one per entry.

#### `IDXE_segcount` is not needed either — the count is derivable

An entry stores `n` segments as `[ct][tag] × n`, where every segment but the
last holds exactly `SEG_BYTES` of GCM plaintext. With `P` the total plaintext
and `S = SEG_BYTES`:

```
    stored = P + 16n        and        n = ceil(P / S)
    =>      n = ceil(stored / (S + 16))
```

which needs only `IDXE_stored`, already in the index. **Verified exhaustively**
rather than argued: across S ∈ {1, 2, 3, 7, 16, 64, 1024, 4096, 1 MiB} and every
P from 0 to 5S+40, the derived n matched the writer's n in every case — zero
mismatches, including the P = 0 entry (a directory) and every exact-multiple
boundary.

That removes the entire index-entry layout change, and with it:

- no version-dependent index walking;
- no "normalise the index at load" pass;
- nothing to teach `idx_find`, `idx_summarise`, `rows_from_index`, `unpack_entry`,
  `es_bind`, or any edit path.

It is also authenticated for free: `IDXE_stored` comes out of the index, which
has its own tag, and `SEG_BYTES` comes out of the header, which is AAD.

#### So the whole of B2's format change is

```
    macros.inc:  hdr_rsvd -> seg_shift        (a byte that was already there)
                 HDR_VERSION 7 -> 8           (readers already accept a range)
```

and nothing else. Everything remaining in phase B is *behaviour*: B3 the nonce
and AAD, B4 the writer, B5 the reader, B6 the proof.

#### Not shipped on its own, deliberately

Recording a field nobody honours is the exact mistake B1 avoided: a branch that
first runs in the same release that gives it something difficult to do. There is
no way to prove `seg_shift` round-trips except by segmenting something, so B2
lands **with B3–B5**, in one release, proved by `segmenttest.ps1`.

That release is the one that touches the crypto core, and it is the first in
this programme where a mistake is unrecoverable rather than merely wrong: a
nonce reused across two segments cannot be undone by a later fix. It gets its
own sitting, with the nonce-uniqueness harness of B6 written **first**.

### B3a · The nonce carries the segment  ✅ *(1.0.75)*

`nonce_set` takes the segment as a third argument and writes it into bits 64..95
of the 96-bit nonce — the 32 bits that were **always written as zero**. Every
caller passes 0, so this changes not one byte on disk, which is exactly why it
could be landed and proved before anything had a second segment to put there.

The safety property is that the two fields occupy **disjoint bit ranges**, so
two nonces are equal only if both fields are. That is now pinned by
`selftest.asm`, not assumed:

- **Layout vectors** — seven `(counter, segment)` pairs with their expected 12
  bytes, chosen so a segment written even one bit low, or a counter allowed one
  bit high, changes a byte one of them names.
- **An all-pairs distinctness sweep** — 8 counters × 8 segments, every one of
  the 2016 pairs compared. "Obviously injective" is what a later edit breaks.

Mutation-checked two ways, each the shape the real mistake would take: writing
the segment at `[rdx+7]` instead of `[rdx+8]` (one byte low, overlapping the
counter), and OR-ing the segment into the counter instead of placing it above.
Both fail the case. `compattest` still passes, which is the other half of the
proof: segment 0 reproduces the nonces of every container ever written.

### B3b · The AAD gains the segment, version 8  ✅ *(1.0.76)*

`header ‖ u64 ordinal` becomes `header ‖ u64 ordinal ‖ u32 segment` for version 8
and later, so `ENTRY_AAD_BYTES` (88) and `ENTRY_AAD_SEG_BYTES` (92) are the
format's **first version-dependent length**. Every entry's tag changes, which is
why it is a version bump; the segment is 0 everywhere until B4.

Decided in **one place** — `entry_stream_open`, which is already handed the
header and reads the version out of it — so a reader opening an old container
and a writer producing a new one cannot disagree about how many bytes GHASH
covered.

`hdr_rsvd` became `seg_shift` in the same change, still written as 0. B4 only
has to put a value in it.

**Proof, and the asymmetry that needed a second fixture set.** A change to the
*short* AAD is caught by the version-6 fixtures. A change to the *long* one is
invisible to a round-trip, because this build is both writer and reader and
would simply agree with itself. So `v8-archive-store.mrk` and
`v8-archive-comp.mrk` are frozen too — files written before the next change, for
the next change to disagree with.

There is deliberately **no version-7 fixture**: 7 was byte-identical to 6 and
shares its AAD length, so the v6 set already exercises that path. Nothing was
lost by 7 never being frozen — worth stating, because it looks like the oversight
B0 exists to prevent and is not one.

Mutation-checked by putting the segment in *every* version's AAD: all five
version-6 checks fail with `exit 3, authentication failed` — sealed over 88
bytes, read over 92 — while the version-8 pair passes.

Note the AAD's segment is belt-and-braces rather than load-bearing: the *nonce*
already differs per segment, so a segment moved within an entry, or spliced in
from another, fails its tag without the AAD's help. `FORMAT_V5.md` §3.2 asks for
it and it costs one branch.

- **The segment count is not in the AAD** (§3.2) — it is derivable from
  `IDXE_stored` (B2), and the index has its own tag.

### B4 + B5 · The writer splits and the reader joins  ✅ *(1.0.77, shipped OFF)*

Built as one change, as specified — and the spec held, with one addition and one
correction found while building:

- **The writer.** `entry_begin` derives `g_segbytes` from the *header* (not the
  build's config), so an append to an existing container segments exactly as
  that container says. `sink_flush_block` became a boundary-aware loop;
  `seg_roll` closes a stream and opens the next **under the same ordinal** —
  and rolls *lazily*, only when more bytes are about to be fed, so an entry
  whose plaintext is an exact multiple of `SEG_BYTES` ends with k full segments
  and not k plus an empty one. That laziness is what keeps the writer in
  agreement with B2's `n = ceil(stored / (SEG_BYTES+16))`; the boundary-exact
  fixture in `segmenttest` is there because of it.
- **The reader.** All in the ES object: `es_bind` derives the segment count and
  copies the key (32 bytes — a drag-out crosses boundaries minutes after the
  global is wiped); `es_raw_refill`'s tag path verifies, steps past the tag,
  reopens at segment+1, and falls back into the normal read path. `ES_Seek`
  needed nothing: forward seeks go through `es_consume`, and backward was
  already refused.
- **`seg_bytes_from_hdr` is the only place a shift becomes a byte count**, and
  it validates first: `shl rax, cl` masks cl to 6 bits, so an unvalidated shift
  of 64 quietly computes `1 << 0`. Out-of-range shifts are refused by both
  index readers and by `es_new`; `segmenttest` feeds 63, 11 and 36.
- The `MAX_PLAINTEXT_SIZE` pre-flight is skipped when segmenting — the ceiling
  bounds a segment now, and `SEG_SHIFT_MAX` keeps every segment under it by
  construction.

**Shipped OFF.** `SEG_SHIFT_DEFAULT = 0`; a release build writes `seg_shift 0`
and cannot be made to segment. The machinery is reachable only through
`MYRKR_DBG_SEGBYTES` in a dbg build, exercised end to end by
`tests/segmenttest.ps1`, and turning it on is a one-line change to a constant
once it has sat.

> Flipped ON in 1.0.83 (`SEG_SHIFT_DEFAULT = 32`), the day a user hit the
> 64 GiB refusal on real data — and field-proven the day after by their own
> SHA-256 over a 155.4 GB entry. The flip's audit also closed the `add` path's
> missing per-entry ceiling (see 1.0.83 in CHANGES.md).

### B6 · Proof  ✅ *(with B4+B5)*

`tests/segmenttest.ps1`, stored and compressed at 64 KiB segments: round trip,
verify, and the **drag path** (which reads every entry's stream round robin in
7919-byte pieces, so boundary reopens interleave across entries — a shape a
plain decrypt never makes). Tampers in a middle segment, in a segment *tag*,
and near the tail; truncation; the knife-edge shifts; and seg_shift 0 without
the knob.

**The nonce log is the check the file exists for.** Test builds log every nonce
`nonce_set` builds; the test runs the encrypt with `MYRKR_DBG_NONCELOG` set and
asserts every line distinct *and* — stored mode, where tar arithmetic is exact —
that the count equals the sum of the per-entry segment counts plus the index.

Mutation 1 is why: delete the segment increment from **both** the writer's roll
and the reader's reopen, and every content check passes — round trip, verify,
drag, all of it — while 10 of 18 nonces are duplicates. A writer and reader that
repeat a nonce *in step* agree with each other perfectly; only the log of what
was actually issued can see it. Mutations 2 (roll advances the ordinal) and 3
(tag not stepped over) fail closed with auth errors, observed.

The B2 derivation needed no second proof: the boundary-exact entry (2 segments,
131,072 bytes of plaintext) round-trips, which it could not if writer and
formula disagreed.

---

## Phase C — the index ceiling

### What measuring first changed about this phase

**The 64 MiB buffer costs nothing at rest.** `g_idxbuf` is `.data?`, so the
image's 81 MB of BSS is demand-zero: `myrkr selftest` peaks at **3.4 MB** of
working set. So "takes the index off the fixed 64 MiB buffer" is not motivated
by memory — nothing is paying for that buffer until it is used. It is motivated
entirely by the **entry ceiling**:

| average path | entries that fit |
|---|---|
| 40 chars | ~838,000 |
| 85 chars | ~537,000 |
| 150 chars | ~353,000 |

That is the number to move, and it means the case for chunking has to be made on
the *resident* cost of a large index rather than on the buffer's existence. Ten
million entries is ~1.25 GB of index however it is stored; chunking is what
keeps that off the heap, and it is worth knowing that is the only thing it buys.

### C0 · Make the ceiling reachable  ✅ *(1.0.78)*

`idx_add`'s refusal is the fix for the worst failure this project has had —
76,286 files encrypted, 16,780 recorded, exit 0 — and **nothing had ever
exercised it**, because reaching it honestly costs half a million files.
Whatever C does at that boundary, the boundary must be reachable in a test
before it is moved.

`idx_cap` (pack.asm) is now the one place the writer's limit comes from, and
`MYRKR_DBG_IDXMAX` lowers it in test builds. The distinction that matters:

- the **writer's** limit is adjustable — a container built under a small cap is
  an ordinary container that any build reads;
- the **reader's** bounds (`idx_tail`, `idx_auth`) stay pinned to
  `IDX_MAX_BYTES` and must never call `idx_cap`, because they bound a read into
  a fixed buffer. A knob that loosened those would be a buffer overflow with a
  switch on it.

`tests/indexfulltest.ps1` reaches the refusal with **forty files**, and
mutation 1 puts the 1.0.50 behaviour back (`IDXF_TRUNCATED` and return): exit 0,
a container present, listing 12 of 40. The original disaster in miniature.

### C1 · The buffer has to move before the ceiling can  — measured

The working-set figure above was the wrong instrument. Private **commit** is the
one that matters, and a PE's uninitialised data is committed at load, not merely
reserved:

```
  myrkr hash <400 MB file>   private commit, peak : 79.3 MB
  BSS in the image                                : 77.6 MB
```

`hash` touches neither the index nor the KDF. **Every run of the tool pays 64 MiB
of commit for `g_idxbuf`, used or not** — the GUI opening on an empty window,
`selftest`, a shell-extension launch, all of it.

That settles the design question, and not the way the plan assumed:

- **Raising `IDX_MAX_BYTES` is not viable.** A 1 GB index buffer would charge
  1 GB of commit to `myrkr hash`. On a machine with a modest commit limit that is
  a failure to start, for a feature almost no run uses.
- So **the buffer must come off `.data?` regardless of whether chunking
  follows.** Heap-allocating it is worth doing on its own merits — it removes
  64 MiB of commit from every invocation — and it is the precondition for any
  ceiling change, chunked or not.

Chunking remains the answer for *bounded* memory at ten million entries. It is
no longer the only thing standing between here and a larger ceiling.

### C1a · The inventory is reached through a pointer  ✅ *(1.0.79)*

45 sites took `g_idxbuf`'s address directly, and a buffer 45 sites hold the
address of cannot move. They load `g_idxptr` instead — an initialised `.data`
pointer aimed at the same static buffer, so **not one byte of behaviour
changes**, which is what makes it provable now.

Proof: the whole suite passes untouched — `manyfiles`, `segmenttest`,
`compattest`, `extracttest`, `volumetest`, `estreamtest`, `counttest`,
`indexfulltest`, `optiontest`, `pickertest`, `prefixtest`, both phases of
`run.ps1`, and `selftest`. There is nothing here a test *could* fail on that
those do not already cover; a pure indirection either works everywhere or fails
immediately everywhere.

### C1b · The inventory is allocated on demand  ✅ *(1.0.80)*

`g_idxptr` starts null and is allocated by `idx_buf_ensure` on the first
operation that actually needs an inventory.

```
  myrkr hash, private commit (peak)   79.3 MB  ->  15.2 MB
```

Allocation sits at the **three procs that write into the buffer** — `idx_auth`
(every read decrypts into it), `idx_add` (every pack and append) and
`zip_add_uniq` (the zip listing) — each of which already had a way to fail:
`EXIT_OOM`, the sticky `g_packerr`, and `IDXF_TRUNCATED` respectively. Everything
that only *reads* runs after one of those three has succeeded, which is why the
45 load sites carry no null check; an allocation added lazily at a leaf site
would have needed 45 of them, in code where a missed one is a null dereference.

**Never freed, deliberately.** The GUI's row model reads the buffer between
operations for as long as a container is open, so freeing at the end of one
operation is a use-after-free at the start of the next repaint.

`indexfulltest` asserts the commit figure, and the mutation that puts the buffer
back in `.data?` moves it to 79.4 MB while **nothing else in the suite changes** —
the buffer works identically either way, which is exactly why the cost needed a
number rather than an eye.

*Cost while building:* the first version called `idx_buf_ensure` at the top of
`idx_auth`, before its three arguments were saved to the frame — a framed proc
clobbers `rcx`, `rdx` and `r8`, which are the handle, the size and the tail
length. Every read in the tree failed with "I/O failure". Caught by the suite
immediately; recorded because it is the same volatile-register class that the
1.0.71 audit swept clean and that 1.0.75 already reintroduced once.

### C1c · The ceiling is raised  ✅ *(1.0.81)*

`IDX_MAX_BYTES` goes from 64 MiB to **2047 MiB**, which at the measured entry
costs is roughly 25 million entries at 40-character paths, **17 million at 85**
and 11 million at 150. The ten-million-file target holds for any realistic tree,
not only for short paths.

**Reserved, not committed.** `idx_buf_ensure` reserves the ceiling;
`idx_buf_commit` commits only as far as the index actually reaches, in 1 MiB
steps. Measured:

```
  myrkr hash                              15.2 MB   (unchanged - no index at all)
  list a 40-entry container               47.3 MB   (~1 MiB of index; the rest is
                                                     that fixture's Argon2 arena)
  the same, if the ceiling were COMMITTED  2066 MB
```

Reserving the whole ceiling up front is also what keeps the pointer **still**.
Growing by reallocation would move it, and 45 sites load it into a register and
then make calls — a growth during any of those leaves a stale base behind.
Address space is free; this buys the pointer's stability with none of it.

**Why 2047 MiB and not 2048.** At 2³¹ an `imm32` operand sign-extends:
`cmp rax, IDX_MAX_BYTES` would compare against `0FFFFFFFF80000000h` and every
unsigned bound test against it would invert, while
`mov qword ptr [x], IDX_MAX_BYTES` would store that same negative value. Both
forms are in the tree. Staying below 2³¹ keeps every immediate correct *by
construction* rather than by an audit that must be redone whenever a site is
added — and an `IF … .ERR` in `macros.inc` fails the assembly if the value is
ever raised past that point without dealing with it.

The unauthenticated `IDXT_len` is bounded by the ceiling *before* anything is
committed for it, so the most a hostile container can make a reader commit is
that ceiling — the same shape as the pre-auth KDF-parameter guard.

`indexfulltest` asserts both figures. Mutation 4 commits the reservation instead
of reserving it: the small-container check fails at 2066 MB while everything else
passes, because a fully committed reservation works perfectly — it just charges
two gigabytes to open a container holding forty files.

### C2 · Chunking — not needed for the target, still available

Chunking was phase C's original plan, and it is no longer what stands between
here and ten million files. What it would still buy is **bounded** memory: with
a resident index, ten million entries is ~1.25 GB committed while a container is
open. If that proves painful in practice, §4.2 of `FORMAT_V5.md` is the design,
and everything it needs is now in place — `idx_buf_ensure`/`idx_buf_commit` are
the seam a cache would replace, `indexfulltest` reaches the ceiling to prove the
refusal, and the trailer (not the header) is the cheaper place to put a chunk
directory.

Worth measuring a real ten-million-entry pack before deciding it is needed.

## Proven in the field — 155.4 GB, one file, 2026-08-15

The day after 1.0.83 flipped segments on, the user who hit the 64 GiB refusal
ran their real data through it: `text_encoders` (ComfyUI model data), **155.4 GB
as a single entry** — roughly 37 segments under one ordinal — encrypted into a
container, extracted back out, and verified by a SHA-256 **they computed
themselves**:

```
  8D132A2C8B2480E43A571C3038C34F495E98EA63BA76A2C93C3382137CAC4D98   before
  8D132A2C8B2480E43A571C3038C34F495E98EA63BA76A2C93C3382137CAC4D98   after
```

The v5 programme's original request was "can we support a single file that is
100 GB?". Answered at half again over spec, on the machine and the data the
question was asked about, with a hash this repository did not produce. Both of
the programme's ceilings are now not merely lifted but **used**.

## Measured at scale — 500,000 files, 2026-08-14

`tests/scaletest.ps1` (not in the default suite: it builds half a million files
and takes minutes). 89-character leaves, ~137 bytes an entry, so the inventory is
**68.5 MB — larger than the entire 64 MiB ceiling that existed before 1.0.81.**
The container is one this tool could not have produced two releases ago.

| operation | time | peak commit |
|---|---|---|
| encrypt (500,000 files → 590 MB container) | 78.7 s | 83.3 MB |
| **list** | **509.3 s** | 83.4 MB |
| verify | 2.6 s | 83.4 MB |
| add one file (linear `idx_find` over 500,000) | **0.3 s** | 83.5 MB |
| decrypt | 334.1 s | 83.5 MB |

**The ceiling raise works, and commits what it uses.** 83 MB peak is the 68 MB
index plus the base — the reservation is 2047 MiB and nothing committed the rest.

**A3 was right to be deferred.** `idx_find`'s linear scan over 500,000 entries
costs 0.3 s for a whole `add`, because it compares the name LENGTH first and
rejects a non-match in about six instructions. At ten million that is a few
seconds per added file — worth fixing when the index is sorted (phase D), not
before.

### The finding: `list` spends 8.5 minutes in syscalls

`verify` decrypts and authenticates the same 68 MB index in **2.6 seconds**, so
`list` is not paying for the index. It is paying for output.

`do_list` prints **five separate fragments per entry** — the size prefix, the
digits, the separator, the name, the newline — and each one is a `write_handle`
call, and each of those is an unbuffered `WriteFile`. At 500,000 entries that is
**2.5 million syscalls**, which at ~200 µs each is the entire 509 seconds.

**The fix is buffering, and the safe form of it is local.** Buffering
`write_handle` globally would be a bigger win but has to get three things right
that a local fix does not: stdout must be flushed before every stderr write or
interleaving changes and the tests that read combined output start lying; the
ramlog tee must still see everything in order; and **nine `ExitProcess` sites**
would each need a flush, where missing one silently truncates a command's output.

Building the line in a buffer inside `do_list` and flushing it when full turns
2.5 million syscalls into a few hundred, is self-contained, and changes no
ordering anywhere. That is the version to build. It needs a `fmt_u64` that
formats into a caller's buffer rather than to a handle — `print_u64` builds the
digits and then calls `print_a`, so the formatting half is already there and
wants separating.

**Built in 1.0.82, exactly that way: 509.3 s → 1.0 s**, all 500,001 entries
listed, re-measured against the same container. `fmt_u64` came out of
`print_u64` to make it possible - the formatting half, so a caller assembling a
line can have the digits without a syscall.

---

## Phase D — sorted index

- **Component-wise comparator**, not raw byte order on full paths — `.` sorts
  before `/`, so `a.txt` would otherwise precede `a/b` while a recursive walk
  emits `a/`'s subtree first (§9.3).
- **Sort each directory's children before recursing.** That produces the total
  order with no spill file and no merge sort. The external sort in §4.4 is
  superseded.
- `idx_find` becomes a binary search (closes A3).
- Index entries shrink: drop `IDXE_offset` (derivable), delta-code
  `IDXE_ordinal`, and either front-code names or compress each chunk with the
  in-tree XPRESS codec (§9.4). Measure both.

---

## Phase E — the GUI at scale

- `rows_from_index` becomes a windowed read: the visible range plus expanded
  folders, each a range read over chunks. Collapsed subtrees are skipped by not
  *reading* their chunks.
- `pset_find` is linear over the expanded set and is called per ancestor per row.
  Replace with something better once the set can grow.
- `ROWS_MAX` stays 2048 — a listing of ten million rows is not a listing.

---

## Order, and why

| # | Step | Ships | Depends on |
|---|---|---|---|
| 1 | **A1** cached counts + **A1b** named header bytes | ✅ 1.0.70 | — |
| 2 | **A2** index-driven extraction | ✅ 1.0.71 | A1 (not strictly, but keeps diffs small) |
| 3a | **B0** freeze the old format, stop calling it corrupt | ✅ 1.0.73 | must precede the bump |
| 3b | **B1** read a range of versions, not one | ✅ 1.0.74 | B0 (the fixtures are its proof) |
| 3c | **B2** where SEG_BYTES lives, and what the index needs | ✅ settled, no code | measured against the tree |
| 3d | **B3a** the nonce carries the segment | ✅ 1.0.75 | B2 |
| 3e | **B3b** the AAD carries the segment, version 8 | ✅ 1.0.76 | B3a |
| 3f | **B4+B5+B6** segments, shipped OFF behind the dbg knob | ✅ 1.0.77 | B3b, A2 |
| 3g | flip `SEG_SHIFT_DEFAULT` to 32 (4 GiB) | ✅ 1.0.83 — a user hit the 64 GiB refusal on real data | B4 |
| 4a | **C0** make the ceiling reachable in a test | ✅ 1.0.78 | — |
| 4b | **C1a** reach the inventory through a pointer | ✅ 1.0.79 | C0 |
| 4c | **C1b** allocate on demand (−64 MiB commit, every run) | ✅ 1.0.80 | C1a |
| 4d | **C1c** raise the ceiling to 2047 MiB, reserved not committed | ✅ 1.0.81 | C1b |
| 4e | **C2** chunking, if bounded memory turns out to matter | measure first | C1c |
| 5 | **D** sorted index | its own release | C |
| 6 | **E** GUI at scale | its own release | D |

A1 and A2 are worth having whether or not v5 ever happens. B is worth having
whether or not C follows. Stop anywhere and what shipped still stands on its own.

---

## Standing constraints, from this codebase

- Locals start at `[rbp-16]`; `[rbp-8]` is the stack canary.
- A frame must be large enough for its own outgoing arguments — `framecheck`
  gates it, and a 7-argument `WINCALL` reaches `rsp+55`.
- Control ids 102–195 are taken.
- `WINCALL` assigns r9, r8, rdx, rcx in that order and emits stack arguments
  first using rax as scratch.
- Never append newly encrypted data to an existing container under its existing
  key. Ordinals are nonces.
- Every new test must be shown to **fail** against a deliberately broken build
  before it is trusted. If it cannot be made to fail, say so in the test.
