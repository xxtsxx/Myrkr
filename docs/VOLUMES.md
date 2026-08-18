# Splitting a container across volumes

**Status: built.** Set a size under **Settings ▸ File split** and an encrypt
writes a volume set; opening any part reads the whole thing back. Editing a set
is refused. With the setting at *Off* — the default — the output has exactly the
shape it always had, and nothing about a single container changes.

Asked for on 2026-08-12. The groundwork predates the request — `CONTAINER_HDR`
has carried a `set_id` since format v4 with a comment saying it is "what a volume
set will need to prove its members belong together", and `manifest.md` records
the constraint below — but no code for it has ever existed. This is a new
feature, not a restored one.

## 1. The constraint that decides the whole design

From `manifest.md`:

> Random access. One file can be decrypted *and authenticated* without reading
> the rest. A tag covers a whole stream, so authenticated random access is only
> possible if the streams are per-entry — which is why a future split into
> volumes must sit *below* the crypto, slicing the ciphertext run rather than
> becoming the streams themselves.

So a volume is **not** a unit of encryption. The container is produced exactly as
it is today — one header, per-entry GCM streams, an index, a trailer — and the
resulting byte stream is then **cut into pieces**. Concatenating the pieces gives
back the original container byte for byte.

Everything follows from that:

- **The crypto is untouched.** No new nonces, no new keys, no new AAD. A volume
  set has exactly the integrity guarantees a single container has, because it *is*
  a single container with cuts in it.
- **A tampered volume header cannot forge anything.** It is plaintext addressing
  that sits below the ciphertext. The worst it can do is misassemble the stream,
  and a misassembled stream fails a GCM tag.
- **The index needs no change at all.** `g_payoff` is already a *logical* cursor
  and entry extents are already recorded relative to `HDR_BYTES`, so an extent
  means the same thing whether the bytes live in one file or nine. This was
  luck rather than foresight, but it is why the reader is a mapping layer and not
  a format change.

The alternative — one GCM stream per volume — would have made each volume
independently verifiable, and would have cost per-entry random access. That is
the wrong trade for an archive you browse.

## 2. Layout

A part is a 32-byte header followed by a slice of the container stream:

```
  [VOL_HDR 32][slice]
```

```
  off  size  field
    0     4  magic 'MVOL'
    4     4  format version (1)
    8    12  set_id      - copied verbatim from CONTAINER_HDR.set_id
   20     4  part number - 1-based
   24     4  flags       - bit 0: this is the final part
   28     4  reserved (0)
```

The slice length is **not** stored: it is the file size minus 32. A length field
would be a second source of truth for something the filesystem already knows, and
the two could disagree.

**Total parts is not stored either.** It is not known when part 1 is written, and
patching it afterwards means going back to a file that may already be on removable
media. Instead the last part carries a *final* flag, and the reader requires
part numbers 1..N contiguous with the flag on N. A missing tail is then a missing
final flag rather than a silently short archive — which, after the inventory
ceiling of 1.0.51, is a distinction this project has earned the right to care
about.

## 3. `set_id` is the membership proof

Every part carries the container's `set_id`, which is 12 CSPRNG bytes drawn per
container and already part of the header AAD. Parts from two different sets
cannot be mixed without the mismatch being obvious, and since `set_id` is bound
into the real header's AAD, a forged volume header claiming another set's id
still fails the container's own tag.

This is what the v4 comment reserved the field for.

## 4. Naming

```
  folder.part001.mrk
  folder.part002.mrk
  ...
```

1-based, and **`.mrk` stays last** so Windows file association keeps working on
every part — double-clicking part 7 opens Myrkr, which then finds the rest. That
is the RAR convention rather than the 7-Zip one (`.7z.001`), chosen for exactly
that reason.

**Three digits to part 999, four beyond**, up to the 4096-part ceiling below.
Zero padding is cosmetic: the set is assembled from part numbers in the headers,
never from a lexical sort of filenames. The *width*, however, is not cosmetic,
and got this wrong for four releases.

The name used to be three digits with nothing checking that the number fitted in
them. Part 1000 put 10 in the hundreds place, and `'0' + 10` is `:` — which in a
Windows path is not a character but the alternate-data-stream separator. Parts
1000–1099 were created as hidden streams on a zero-length file called
`<base>.part`; 1100 onward came out as `<base>.part;NN.mrk`. Encrypt exited 0.

It even round-tripped on the machine that wrote it, because the reader builds the
same broken name and follows the writer into the same stream — so nothing short
of looking at the files could have caught it. What it does not survive is the
folder being **copied**: streams do not travel to FAT, into a zip, over a share,
or through most backup tools, and moving the pieces is the entire purpose of
splitting. Reachable at the smallest split offered (100 MB) on any input past
~100 GB.

`tests/volumetest.ps1` now asserts the filenames, the absence of a stream host,
and that a set opens when handed a member above 999.

### Ceiling

A set is capped at **4096 parts**, the number the reader will assemble. The
writer previously knew nothing about that limit, so a small enough part size on a
large enough input produced a set that encrypt called a success and no reader
could ever open again. Past the ceiling the encrypt is refused — mid-write,
because the part count is not knowable at the start — and every part it had
written is deleted, since `do_pack`'s existing cleanup names the un-split output
that a split run never creates.

At the smallest offered split that is 409 GB in one set; larger part sizes lift
it proportionally.

## 4b. A set of one is not a set

The split size is a **ceiling on how big one file may get**, not a request for a
set. A container that fits inside it comes out as one ordinary file: no part
number, no volume header, and editable like any other. Setting 100 MB and
encrypting 50 MB gives `thing.mrk`.

Two mechanisms, and they are redundant on purpose:

1. **`est_container_bytes`**, before anything is written. A store-mode upper
   bound — input bytes, plus the tar framing the ceiling check already estimates
   at 1024 an entry, plus the inventory capped at `IDX_MAX_BYTES`, plus header
   and trailer. Compression can only shrink what actually gets written, so a
   limit dropped on this basis is one the output genuinely cannot reach. Every
   term rounds up and the arithmetic saturates: over-estimating costs an
   unnecessary split, under-estimating would write past the size the user
   capped.
2. **`vol_settle`**, after the last part is closed. If exactly one part was
   written, its 32-byte header is stripped **in place** — read at k+32, write at
   k, then truncate — and the file is renamed to the name it would have had all
   along. In place rather than copied to a second file, because a copy needs as
   much free space again and failing for want of room *after* a successful
   encrypt is a worse outcome than the naming was.

The second only runs when the first was wrong, which takes compression: the
estimate says 20 MB, the limit is 5 MB, and what lands is a kilobyte. That is
also why the strip is cheap when it happens — the file is small precisely
because it compressed.

Because the estimate keeps the common case off the volume path entirely, that
case also keeps the write-to-temp-then-rename protection a single container has
and a set gives up.

## 5. No header when there is no split

With no size limit set, the writer emits a plain single container with **no**
volume header at all, so the file has exactly the shape previous versions
produced.

Not byte-*identical* to any particular earlier run — the salt and `set_id` are
drawn fresh per container, so two encrypts of the same input never match, and any
claim of reproducibility here would be false. The claim is about layout, and it
is checked by reading the first four bytes: `MYRK` is a container, `MVOL` is a
part of a set.

This is why step 1 could be wired in without changing any output: the layer is
always in the write path, and a limit of zero makes it a pass-through.

## 6. Scope

**Splitting applies to a fresh encrypt only.** Adding to, or deleting from, a
volume set is refused. Both edit paths rewrite the index in place and one of them
slides survivors down over a hole; doing that across a set of files, some of
which may be on removable media that is not present, is a different problem and
does not have to be solved to make splitting useful. The refusal is explicit, not
an omission.

## 7. What is built, and what is not

| Piece | State |
|---|---|
| Format constants, `VOL_HDR` | in |
| Part-name construction | in |
| Write-side rolling sink | in |
| Fresh-pack output routed through it | in — output shape unchanged, suite green |
| Reading a set back | **in** — round-trips, from any member |
| A size limit the user can set | **in** — Settings ▸ File split |
| GUI control | **in** — a preset slider, persisted as `SplitSize` |
| Refusing edits on a set | **in** — checked before anything is written |
| Part count bounded to what a reader assembles | **in** — refused past 4096, and the parts written are deleted |

A set now round-trips: 40 files split into 6 parts, decrypted from part 1 *and*
from a middle part, all matching byte for byte, with a missing tail refused.
`tests/volumetest.ps1` is that test.

It also covers the two ways the *naming* was wrong: a set of 1173 parts, with
every part asserted to be a real file with a legal name and no alternate-data-
stream host anywhere, opened by handing it part 1000; and a set past the ceiling,
which must be refused with the reason and must leave nothing behind.

## 7a. The control

**Settings ▸ File split**, a slider over presets rather than a free number,
because the useful sizes are the ones a medium imposes and almost every other
value is wrong. `Off`, 100 MB, 700 MB (CD), 2 GB, 4 GB (FAT32), 25 GB (BD) —
and 4 GB is *decimal*, 4,000,000,000, so it stays under FAT32's 4 GiB per-file
ceiling rather than landing 295 MB over it.

Persisted as `SplitSize` under `Software\Myrkr`, and stored as the **index**, not
the byte count, so the value survives the preset list changing. It is an ordinary
settings row, so it locks to policy from HKLM like every other setting.

The index is resolved to bytes in `start_operation`, not inside `do_pack`:
`pack.asm` has no business knowing what the presets are. The limit is also
cleared when Format is **Zip** — the zip writer does not go through the volume
layer, so leaving it set there would be a setting that silently does nothing.

Two tables share that index — the labels and the sizes — and nothing checks by
eye that entry 2 says "700 MB (CD)" *and* means 700,000,000. `selftest` checks
what is checkable: `Off` is 0, because 0 is what the whole write path treats as
"do not split", and the rest strictly increase, which is what breaks if a row is
inserted or reordered in one table and not the other.

`MYRKR_DBG_VOLBYTES` still exists in debug builds and still overrides, because
the tests need an arbitrary small size and none of the presets is small enough to
split 10 MiB.

## 8. Every read of a container has to go through the layer

Learned the hard way. The reader was wired through `do_unpack` — the open, the
size, `idx_tail`, `idx_auth`, and the entry loop — and a set still failed with
*"not a valid Myrkr container"*, before `do_unpack` was ever reached.

`do_decrypt` calls `peek_archive` **first**, to decide archive-vs-single from the
header, and it opened the file itself. So a set was inspected raw, the first four
bytes were `MVOL` where `MYRK` was expected, and the container was rejected as
malformed by a proc nobody had thought of as part of the reader.

The lesson generalises: the layer is only correct if *every* path that opens a
container goes through it. A single direct `file_open_read` on a container is a
bug, and the symptom will point somewhere else entirely.

Two shapes of read had to change, not just their call sites:

- **`do_unpack`'s entry loop** used `file_seek` and then read sequentially. A
  handle's file position means nothing across a part boundary, so it carries an
  explicit logical cursor now and every read is `vol_get` at that offset.
- **`peek_archive`** used `file_read_exact` from the current position, for the
  same reason.
