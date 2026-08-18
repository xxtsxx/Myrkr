# Dragging OUT of an archive to extract

**Status: BUILT, all four steps, and zips too.** Decision taken 2026-08-09:
build the design before the code, the way the drop indicator went. Sections
4b-4f record what building each step found, and §7 does the same for zips.

Dragging any selection - files, folders, or a mixture - out of an open
container works end to end, for **both** kinds: a `.mrk` and a WinZip-AES
`.zip`. The two get there by opposite routes, and §7 is why.

Dragging entries from the container view into Explorer extracts them there. It
is the mirror of the drop that now works, and it is a much larger piece: the
window stops being only a drop *target* and becomes a drag *source*, which means
a second hand-written COM object with a harder interface.

## 1. What has to be built

| piece | why |
|---|---|
| `IDataObject` | the source object. `GetData`, `QueryGetData`, `EnumFormatEtc`, `GetCanonicalFormatEtc`, and the `SetData`/`DAdvise` family stubbed to `E_NOTIMPL` |
| `IEnumFORMATETC` | `EnumFormatEtc` must return one, so it is a second object with its own vtable and its own `Clone` |
| `IDropSource` | `QueryContinueDrag` and `GiveFeedback` - small, and the only easy one |
| drag detection | `LVN_BEGINDRAG` from the list, then `DoDragDrop` |

`shellext.asm` is again the in-tree template for the vtable shape, and the
`IDropTarget` in `gui.asm` is a closer one - same image, same `FRAME_PROLOG`
rules, same landing-pad question (none: the shell calls through the vtable, not
through `CALL_GUARDED`).

## 2. The real decision: which format to offer

**`CF_HDROP` after extracting to temp.** The data object hands over paths to
files that already exist. Explorer copies them like any other file.

- Simple, and every drop target understands it.
- **It writes decrypted plaintext to disk before the user has said where the
  files are going** - and leaves it there if the drag is cancelled. For a tool
  whose entire point is that plaintext does not lie around, that is the wrong
  default, and `myrkr-no-automation-stance` is the same instinct.

**`CFSTR_FILEDESCRIPTORW` + `CFSTR_FILECONTENTS`.** The virtual-file protocol:
the data object describes the files, and the target asks for each one's contents
as an `IStream`. Nothing is written until something asks.

- Correct: extraction happens into the target's own copy, one entry at a time,
  and a cancelled drag writes nothing at all.
- Costs a third COM object - an `IStream` per entry, `Read`/`Seek` at minimum -
  and `GetData` has to honour `lindex` to say *which* file is being asked for.
- Explorer supports it (it is how mail attachments and zip folders drag out).

**Recommendation: virtual files.** The temp-file version is a day's work and a
security regression; this feature is the one place where "simplest thing that
works" writes plaintext to disk on a gesture that can be made by accident.

## 3. The password question, which has no good answer yet

A `.mrk` needs the key to produce contents. The container view already holds it
for the window's lifetime (`od_container` deliberately does not wipe
`g_cfg_pass`), so a drag *from an open container* has what it needs.

What it does not have is a way to fail politely. `IStream::Read` is deep inside
Explorer's copy loop; there is no window to prompt from and no way to say "wrong
password" that arrives anywhere useful. So:

- the drag must be **refused at `LVN_BEGINDRAG`** unless the key is already
  live - never started and then failed halfway;
- a failure during `Read` can only return `E_FAIL`, and Explorer will report its
  own error. Nothing here can improve that message, so nothing should try.

## 4. What it must not do

- **No dragging out of a container that has not been unlocked.** The listing is
  readable for a zip without a password; the contents are not.
- **No partial file left behind.** If `Read` fails midway, the stream returns an
  error rather than short-reading - a truncated extraction that reports success
  is the same class of bug as a truncated path.
- **The drag must not offer `DROPEFFECT_MOVE`.** Move means the source deletes
  the original afterwards, and this source cannot: removing an entry from an
  archive is a rewrite, not a delete, and it is not what a drag to the desktop
  should trigger. `COPY` only.

## 4a. What the code already gives you

Reconnaissance done 2026-08-09, before any of this was built.

**`entry_stream_open` (pack.asm) is the foundation.** It opens the GCM stream
for one entry: nonce = ordinal + 1, ordinal in the AAD. Its comment says why it
is one proc rather than three copies - the writer, the archive reader and the
single-file reader must agree exactly - and that argument applies with equal
force to a fourth reader living behind an `IStream`. Build on it; do not
reimplement the nonce and AAD rules beside it.

**The GCM contract decides the IStream's semantics**, and this is the part that
is easy to get wrong:

- An entry decrypts **sequentially**, and its tag is only verified once the
  last byte has been consumed. So `Seek` backwards cannot be supported
  (`STG_E_INVALIDFUNCTION`), and `Read` must return an error rather than a
  short read - a truncated extraction that reports success is the same class of
  bug as a truncated path.
- A drag cancelled mid-copy leaves an entry **partially read and never
  authenticated**. For a virtual file that is harmless: nothing was written.
  For the `CF_HDROP`-from-temp version it is the opposite - unauthenticated
  plaintext, left on disk, by a gesture the user abandoned. That is a second
  and independent reason to skip step 1 rather than ship it.
- `IStream::Stat` has to report the entry's size up front, which the index
  already knows. Explorer uses it for the progress bar, and getting it wrong is
  cosmetic rather than dangerous - but the descriptor's size must match, or the
  copy stops early believing it is done.
- **`FD_PROGRESSUI` is deliberately not set** (1.0.56). It is the documented way
  to ask the shell for a progress indicator, and what it produces is the
  Vista-era copy dialog — which appeared over a drag-out and is not something
  this window should be summoning. Its `equ` was deleted along with it, so
  nothing sets it back by habit.
- **The window's own bar runs the transfer instead** (1.0.57, repaired 1.0.58).
  `es_drag` sums the offered entries' sizes, calls `progress_begin`, and **shows**
  the bar - which is created `ST_BARHIDE` and is otherwise only ever shown for an
  operation, so the first attempt drove counters at a control nobody could see.
  `ES_Read` reports the bytes it actually handed over, counted at the hand-off
  rather than at the refill, so a read that fails part way cannot claim progress
  it did not make.

  The repaint is **synchronous** - `InvalidateRect` then `UpdateWindow`, only when
  the percentage changes. It deliberately does NOT go through the 100 ms timer:
  `DoDragDrop` runs its own modal loop, and a modal loop is under no obligation
  to dispatch `WM_TIMER`. The first attempt assumed it would.

  **Measured, not assumed** (1.0.59). A temporary probe reported the bytes
  counted when `DoDragDrop` returned, and it was the whole entry - so the
  shell's reads really do land inside the call, on this thread, and the bracket
  around it is the right place for the progress to start and stop. Worth having
  measured: two releases were spent fixing details of an arrangement whose
  central assumption had never been checked.

  **This is only possible because `DoDragDrop` is synchronous on the thread that
  owns the listing** (§4 above). The target's reads land in `ES_Read` on that
  same thread, inside `DoDragDrop`'s own modal loop - which is also what makes
  `UpdateWindow` safe to call from there. Anything that later makes this object
  free-threaded breaks the progress bar as well as `entry_stream_open`.

  It is **not** an operation: `g_running` stays 0, so the Cancel button, the drop
  handling and everything else that flag gates are untouched. A separate
  `g_drag_prog` shares only the repaint, and is cleared on every outcome —
  including a cancelled or refused drag, so the bar is never left showing a
  transfer that is not happening.

**And the one that decides the object's shape: the reader is GLOBAL today.**
Extraction runs through `g_pkctx` (a single `GCTX_SIZE` block), `g_filebuf` and
`g_pktag` - one stream at a time, by construction, because nothing has ever
needed two. An `IStream` cannot assume that: the shell is free to hold several
open at once, and with multi-selection (step 4) it very likely will.

Two ways out, and the choice belongs at the START of the work rather than
halfway through it:

- **Per-instance state.** `gcm_init` already takes the context by pointer, so
  contexts are relocatable - each stream object carries its own `GCTX_SIZE`
  block, its own read buffer and its own file handle. Costs a heap allocation
  per stream and nothing else. This is the right answer.
- **One live stream at a time**, refusing a second with `E_ACCESSDENIED`. Less
  code, and it would work for the common case of Explorer copying files one
  after another - but it fails exactly when several entries are dragged, which
  is the feature. Not worth it.

The per-instance route also removes any question about the worker thread: a
stream that owns everything it touches has nothing to share with the container
view it was dragged from.

## 4b. What building step 1 actually found

`src/estream.asm`, 2026-08-10. The per-instance decision in §4a held up. Four
things it did not predict:

**An entry's plaintext is not the file.** It is `[512-byte tar header] content
[zero pad to 512]`, and when the container is compressed it is not even that -
it is `compress.asm`'s framing of it, `[u32 orig][u32 payload][payload]`, with
`entry_end` flushing the compressor per entry so an entry's frames are
self-contained. So the stream is three layers, not one: decrypt, de-frame, then
skip the header and stop at the recorded size. A bare single-file container is
the exception the header's byte 17 announces - there, the entry's plaintext
really is the file.

**The content ends before the entry does, and that is a security property, not
a detail.** GCM's tag only clears once every ciphertext byte has passed through
it. A reader that stops at the last content byte - which is the obvious way to
write this - returns the right bytes and never asks for a verdict, so a
container tampered with anywhere in the 511 bytes of padding copies out clean.
`ES_Read` therefore drains to the end of the entry and verifies on the read
that consumes the final content byte, and fails *that* read. Bytes already
handed over cannot be unsaid; failing the last read is what makes Explorer
abandon and delete the partial file. `tests/estreamtest.ps1` tampers with the
padding specifically, because that is the case a naive implementation passes.

**`idx_read` wipes the key on the way out** unless the caller sets
`g_keep_key` first - it derived the key for one listing and does not assume
anyone wants it afterwards. Without that, every stream decrypts under a key of
zeros: garbage plaintext, a failing tag, and the only symptom is a `Read`
returning `E_FAIL`, which is indistinguishable from a corrupted container. It
cost a debugging round. §3's "the container view already holds it" was about
the *password*, not the key - the drag will have to re-derive or keep it.

The consolation is that the requirement stops at construction: `gcm_init`
expands the round keys **into** the context, so once every stream is built the
global key can be wiped and the only copies left are inside the objects, wiped
in turn by `tagged_free`. That is a better place for key material than a
process-wide global, and step 3 should do it.

**`LARGE_INTEGER` is passed by value** in `rdx` for `Seek`, exactly as `POINTL`
is for `DragEnter`. Reading it as a pointer would take a byte offset for an
address.

`Stat` and a zero-offset `Seek` tell are exercised through the vtable on every
stream before a byte is read - `Stat`'s `cbSize` because step 2's descriptor
must carry the same number, and `Seek` because that by-value `LARGE_INTEGER` is
the trap. Both outputs are poisoned first, so a method that returns `S_OK`
without writing fails rather than passing on a zero that was already there.

Seek is served forward by reading and discarding, and refused backward
(`STG_E_INVALIDFUNCTION`); `Clone` is `E_NOTIMPL` for the same reason - a
second cursor over one sequential GCM stream cannot exist without decrypting
the entry twice. `Write`/`SetSize` say `STG_E_ACCESSDENIED` rather than
`E_NOTIMPL`, because the stream is not missing the ability to write, it refuses
to.

**It is gated under `TEST_IO`.** Nothing calls it but the exerciser, and a
release binary should not carry an unwired COM object with a vtable in it. Step
2 is what removes the gate.

## 4c. What building step 2 found

`IDataObject` + `IEnumFORMATETC`, 2026-08-10. Smaller than step 1 and mostly
went as §1 and §2 said it would. Three things worth writing down:

**The key had to stop being a global, properly.** §4b noted that `es_create`
needs `g_key` live, and §4b's consolation - wipe it once the streams exist -
does not survive contact with a real drag: `GetData` arrives from Explorer long
*after* the drag started, and the streams do not exist until then. So
`entry_stream_open` now takes the key **as an argument**. Every caller in
`pack.asm` and `cmd.asm` passes `g_key` and reads exactly as before; the data
object passes its own copy, taken at construction and wiped by `tagged_free`
with the object. The exerciser wipes the global immediately after `do_create`
returns and before it asks the object for anything - which is the assertion
that the object really is self-contained, and it is the difference between
working in a drag and working only in a test.

**A failed `GetData` must hand back nothing.** The `STGMEDIUM` is zeroed before
any check can fail, so a caller given an error is not also given a `tymed` it
will then try to release. The test asks for an `lindex` past the end and checks
both the failure *and* the empty medium.

**The descriptor is rendered per call, never cached.** The target owns the
`HGLOBAL` it is handed and will `GlobalFree` it, so returning the same block
twice would be a double free in someone else's process.

`lindex` is `-1` in the *enumeration* even for `FileContents` - the enumerator
says what is on offer and the target names the item when it calls `GetData` -
and `-1` is also what a caller that never set it will pass, so `GetData`
sign-extends and compares unsigned, rejecting negatives and overruns in one
test.

Names in the descriptor are **leaf** names: dragging out `sub/c.txt` drops
`c.txt` where the mouse went rather than recreating `sub` there. That leaves
one gap, and it is step 4's: two entries with the same leaf in different
folders would collide within one drag. Folder drags are where relative paths
become the right answer, and they are the same step.

**One load-bearing assumption, recorded because it is invisible.**
`es_create` reaches `entry_stream_open`, which uses the process-wide scratch
`g_idxnonce` and `g_entaad` on its way into `gcm_init`/`gcm_aad`. Two `GetData`
calls running *at the same time* would interleave there and produce a wrong
nonce for one of them - a failing tag, indistinguishable from corruption again.
That cannot happen only because the object lives in an **STA**: `wp_create`
already calls `OleInitialize`, a data object with no marshaller of its own is
apartment-threaded, and COM serialises cross-apartment calls onto the owning
thread. The per-instance work in §4a is what makes several streams *open* at
once safe; the apartment is what makes several *constructions* safe. Anything
that later makes this object free-threaded has to fix `entry_stream_open`'s
scratch first.

## 4d. What building step 3 found

`IDropSource` + `LVN_BEGINDRAG`, 2026-08-10. The smallest piece, as §5 said,
and it went as §3 said it would. What it did force was a decision §3 left open.

**The key now outlives the listing in the container view.** §3 said the drag
must be refused at `LVN_BEGINDRAG` unless the key is already live - and it was
never live, because `idx_read` wipes it. Deriving it at the gesture would mean
an Argon2 pass, most of a second, at the exact moment the user starts moving
the mouse. So `container_load` sets `g_keep_key`, and the key stays for the
window's life.

That is a real change to the window's posture, and the argument for it is that
the exposure is bounded by the same thing that already bounds `g_cfg_pass`,
which this window deliberately keeps for its lifetime: the process. `secmem`
locks and wipes `g_key` at exit, and every re-listing re-derives it, so an add
or a delete leaves it correct rather than stale.

**The refusal is still checked, not assumed.** `es_key_live` recomputes the
key-check value and compares it with the header's - the same test every reader
makes - so a drag cannot start against a key that has gone away. One SHA-256,
next to nothing beside the Argon2 that produced the key. Along with it:
not-a-container, a zip (a WinZip-AES entry is a different reader), and
`OleInitialize` having failed at startup.

**Directories are skipped, not refused.** Dragging a mixed selection gives you
the files in it. A folder needs every entry beneath it with relative paths in
the descriptor, which is step 4 and is also where same-leaf collisions get
solved.

**framecheck earned its keep again.** The `WideCharToMultiByte` that turns a
row's path into an entry name takes eight arguments, so four route through the
outgoing area - and WINCALL emits those first, using `rax` as scratch. The row
pointer was still sitting in `rax`. Same class as the bug in `es_frame_fill`
one step earlier; caught at the gate both times.

## 4e. What is NOT verified by a test here, and why

`docs/UI_SURFACES.md` records four attempts at driving a drag and why the last
one cannot work: `DoDragDrop`'s `SetCapture` only takes effect for the
foreground thread. So `LVN_BEGINDRAG` -> `DoDragDrop` -> Explorer's copy loop is
exercised by **using it**, and nothing else.

Everything either side of that is covered: `tests/estreamtest.ps1` drives the
`IStream` and the `IDataObject` through their vtables against real containers,
and Explorer's copy loop is the same boundary the drop target has, with the
same answer - it is Microsoft's code.

Step 4 shrank the gap further rather than widening it. The naming and expansion
could have gone in `container_drag_out`, where nothing could reach them; they
went into `do_add_tree` instead, so the `dataobj` verb can be handed a selection
("`myrkr dataobj C.mrk in/sub -o OUT`") and the exact list of offered names
asserted. What is left untested is now only: reading the selected rows out of
the list, converting each row path, and the five lines of `IDropSource`.

## 4f. What building step 4 found

Multi-selection and folders, 2026-08-10.

**One naming rule does both gestures.** Every item is named relative to the
**selection's parent**:

| dragged | offered |
|---|---|
| `sub/c.txt` | `c.txt` |
| `sub` | `sub`, `sub\c.txt`, `sub\d.txt` |
| `a/b` | `b`, `b\...` |

That is the whole of it. §4c worried about leaf collisions between entries in
different folders; the rule dissolves them, because a folder drag carries its
own structure and a file drag was always going to be named by its leaf. Two
files with the *same* leaf selected from different folders still collide - but
that is what dragging two identically-named files means anywhere in Windows,
and the shell asks about it. Not our problem to invent an answer to.

**Counting and adding go through the same walk.** A folder expands to however
many entries lie beneath it, which the selection does not say, so the object
has to be sized first. `do_add_tree` with a null object counts instead of
adding - one match rule, not two. A count that could disagree with the add is
precisely how a drag silently loses its tail, and a silently short copy is the
failure this feature must not have.

**Folders are offered as items, and their streams are real.** The shell creates
intermediate directories from the backslashes alone, so a folder item is only
strictly needed for an EMPTY one - but an empty folder vanishing from a copy is
the same class of quiet partial result. A directory entry is a 512-byte tar
header sealed like every other entry, so it authenticates like every other
entry and yields zero content bytes. `es_create` no longer refuses them:
refusing would have aborted an entire copy over an empty folder.

**Nested selections are de-duplicated by ordinal.** Selecting a folder *and*
something inside it is a thing people do by accident, and without this the same
file is offered twice under two different names - the shell would ask about a
collision that only existed because we made it. Rows are walked in display
order, so the folder is seen first and its relative name survives, which is
also the one the user asked for by selecting the folder.

**A prefix is not a match.** `in/s` must not pull in `in/sub`: an entry longer
than the selection counts only if the selection is followed by a separator.
Tested, because it is a one-character mistake that would quietly widen a drag.

## 5. Order to build it

**Revised after §4a: do not build step 1.** It was there to prove the drag
starts before investing in the stream, and it buys that at the cost of writing
unauthenticated plaintext to disk - which, per §4a, a cancelled drag then
leaves behind. The stream is testable on its own without any drag at all, so
the proving order can be inverted at no cost.

1. ~~**The `IStream` over one entry**~~ - **DONE**, `src/estream.asm`, on
   `entry_stream_open` as planned. No COM plumbing around it, no drag: the
   `estream` verb constructs one per file entry, holds them all open and reads
   them round robin 7919 bytes at a time, then `tests/estreamtest.ps1` compares
   the bytes against a `myrkr decrypt` of the same container. The interleaving
   is the test rather than a flourish - reading them one after another would
   pass just as happily against the global-state design §4a rejected. See §4b.
2. ~~**`IDataObject` + `IEnumFORMATETC`**~~ - **DONE**, offering
   `CFSTR_FILEDESCRIPTORW` and `CFSTR_FILECONTENTS` as planned, with `GetData`
   honouring `lindex`. Still no drag: the `dataobj` verb calls every method
   through the vtable - including `QueryInterface` for an interface it must
   refuse, and `GetData` for an `lindex` past the end - exactly as
   `tests/droptest.ps1` calls the drop target. See §4c.
3. ~~**`IDropSource` and `LVN_BEGINDRAG`**~~ - **DONE**. The smallest piece and
   the only one that needs a real drag to exercise; per §6 that is the one
   thing no test here can drive, so it went last and carries the least logic.
   See §4d and §4e.
4. ~~Multi-selection, and folders~~ - **DONE**. A folder is every entry beneath
   it, with the descriptor carrying relative paths, exactly as this line said -
   and one rule (names are relative to the selection's parent) turned out to
   cover both it and the single-file case. See §4f.

## 6. Testing it

Same lesson as the drop: **do not try to drive a drag.** `docs/UI_SURFACES.md`
records four attempts and why the last one cannot work - `DoDragDrop`'s
`SetCapture` only takes effect for the foreground thread.

The source object is testable the same way the target was: build it, then call
`GetData` / `EnumFormatEtc` / `IStream::Read` directly through the vtable and
compare the bytes against a known extraction. That covers everything except
Explorer's own copy loop, which is the same boundary as before and the same
answer: it is Microsoft's code.

## 7. Zip entries

**Status: BUILT.** Reconnaissance done 2026-08-10 before any code, for the same
reason §4a was: what follows decides the object's shape, and finding it halfway
through is expensive. Built 2026-08-11; §7f records what building it found.

`container_drag_out` used to refuse a zip. Lifting that turned out to want the
*opposite* design from the `.mrk` stream.

### 7a. There is no extent to stream from

`zidx_add_unique` (unzip.asm) records a zip entry's name, size and flags and
sets `IDXE_offset`, `IDXE_stored` and `IDXE_ordinal` to **zero** - deliberately,
with a comment: a zip is never rewritten in place, so there is no extent to
record. The real locator is the central-directory header in `g_cdbuf`.

So the first missing piece is a name-to-header lookup, and `es_create` does not
apply at all: it decrypts a GCM extent, and a zip entry has neither.

### 7b. `inflate` is one-shot, and that is already policy

`inflate` (inflate.asm) takes a whole input buffer and a whole output buffer and
keeps its state in globals. `extract_zip_entry` therefore allocates the entire
compressed size AND the entire uncompressed size and inflates in a single call -
and refuses deflate entries over `DEFLATE_RD_CAP`, 512 MiB, saying so in a
comment for exactly this reason.

That cap already governs `myrkr unzip`. A buffered drag-out inherits it rather
than inventing it, which is the difference between a limitation and a
regression.

### 7c. The decider: nothing unauthenticated is ever exposed

This is the finding that settles the design, and it points the opposite way from
§4a.

`extract_zip_entry` has two WinZip-AES paths and they keep that promise
differently:

- **deflate** reads the whole ciphertext, computes `hmac_sha1` over it, compares
  against the stored 10-byte tag, **and only then decrypts**. Nothing is
  decrypted that has not already been authenticated.
- **stored** streams: decrypt a megabyte, write it, repeat, and check the tag at
  the end. It gets away with that because it writes to `OUTPUT.part` and
  **renames only after the tag passes** - unauthenticated plaintext is never
  visible as the real output.

*(The reconnaissance note first written here claimed the first shape for both.
The stored path is the second; the conclusion is unchanged, and the temp-then-
rename structure is what the memory sink had to reproduce.)*

A *streaming* reader could keep neither promise: it hands bytes to the target as
it produces them, so there is no `.part` to withhold and no way to check first.
That is what the `.mrk` stream does, and what §4b had to work hard to make safe
(drain the padding, fail the last read). For GCM there was no choice; here there
is, and the existing code took the stronger one.

So: **do not stream a zip entry. Materialise it.**

### 7d. What that makes the object

`zs_create` runs the existing reader to completion into memory, and the
`IStream` over the result is a buffer with `Read`/`Seek`/`Stat` - perhaps a
hundred lines, no crypto in it at all. That is *stronger* than the `.mrk`
stream, not weaker:

- the entry is fully authenticated (HMAC, and CRC-32) before a single byte is
  handed over, so a bad entry fails `GetData` and the drag never offers it;
- `Seek` can be supported in both directions, because there is no sequential
  decoder to rewind;
- no second WinZip-AES implementation exists to drift from the first.

That last point is the `entry_stream_open` argument again: one reader, and the
cheapest way to keep a second one honest is for there not to be one.

**Cost, stated plainly:** an open stream holds the entry's uncompressed size,
plus the compressed size transiently. Several selected entries hold several.
No new cap - allocation failure returns `E_OUTOFMEMORY` and the shell reports a
copy error, rather than a policy limit invented here.

### 7e. Build order

1. **A memory sink for the existing reader.** `extract_zip_entry` has two: the
   whole-buffer `uz_write_file` (deflate path) and the chunked `hpart` writes
   (stored path). Both need to divert to a buffer when one is set. This is the
   only change to tested crypto code and it must not restructure the proc -
   one reader, two sinks.
2. **`zip_cd_find(name, len) -> central-dir header`**, so a selected row can
   reach its entry.
3. **`zs_create` + the memory-backed `IStream`**, and `DO_GetData` choosing
   between it and `es_create` by container kind.
4. **Let `container_drag_out` accept a zip**, and drop the `g_is_zip` refusal.
   §4's "no dragging out of a container that has not been unlocked" still holds:
   a zip's *listing* is readable without a password but its contents are not, so
   an encrypted zip still needs `g_pw_ready`, and `es_key_live` is the wrong
   check for one - it tests a `.mrk` header's KCV.
5. **Test it** the way everything else here was: the `dataobj` verb already
   takes a container and a selection, so it should take a `.zip` too and the
   same assertions apply - names, sizes, bytes against `myrkr unzip`, and a
   tampered entry refused.

### 7f. What building it found

The plan above survived, with one step that did not exist in it and two defects
that a test caught rather than a user.

**There are three sinks, not two.** §7e counted `uz_write_file` and the stored
path's chunked writes. `extract_zip_entry` actually has three: the AES-stored
loop writes to `OUTPUT.part` and renames, the *unencrypted* stored loop writes
straight to the output, and the deflate path writes one whole buffer. They now
go through `uz_sink_open`/`uz_sink_write`/`uz_sink_close`/`uz_sink_discard`,
which check one global and otherwise call exactly what they used to. The proc
was not restructured, which was the constraint.

The sink also has to make `uz_sink_discard` a distinct thing from a close: in
file mode a failed entry deletes its `.part`, and in memory mode there is no
`.part` - deleting one anyway would remove a leftover from an earlier real
extraction.

**`zip_cd_find` became `zip_entry_to_mem`, and it re-reads the directory.**
`zip_to_index` frees `g_cdbuf` and closes the archive when it finishes, so
there is no central directory sitting in memory to look an entry up in. The
lookup, the sizing, the extraction and the cleanup are therefore one proc that
opens the archive for itself. It matches the name the way the *listing* spells
it - backslashes folded, trailing separator dropped - because that is the
spelling the dragged row carries, and `uz_entry_picked` had already learned
that lesson.

The buffer is sized from the entry's **declared** uncompressed size and capped
there, so an archive that declares one length and delivers another is refused
by `uz_mem_take` rather than overflowing.

**Defect 1: every zip entry carries ordinal zero.** `do_additem` de-duplicated
on `IDXE_ordinal`, which is unique per entry in a `.mrk` and *always zero* in a
zip (§7a - `zidx_add_unique` writes zeros because there is no extent). Every
row after the first would have been called a duplicate of the first, and a drag
of a whole zip would have handed over exactly one file and reported success.
That is the quiet-partial-result failure this feature has been avoiding since
step 4, arriving from a direction step 4 did not look at. Identity is now the
entry's **offset in `g_idxbuf`** (`DI_slot`), which is unique for both kinds.

**Defect 2: the item does not contain the entry's name.** A data-object item
copies the index entry's *fixed* part, 40 bytes, "which is everything
`es_create` reads" - and the name starts at byte 40. A `.mrk` entry is found by
extent so it never needed one; a zip entry is found by **name**. Reading
`IDXE_name` off the copy silently read the wide offered name instead and
matched nothing, so every `GetData` failed. Items now carry `DI_uname`, the
entry's own UTF-8 name, which is a *third* name distinct from both the offered
one and the extraction path.

It is copied rather than read back out of `g_idxbuf` at `GetData` time, for the
reason everything else here is copied. The alternative would have worked -
`DoDragDrop` is synchronous on the thread that owns the listing - but that is
the argument that made the key lifetime bug in §4b, and it costs a memcpy to
not make it again.

**`es_key_live` is not the gate for a zip**, as §7e predicted: it compares a
KCV against a `.mrk` header. A zip is gated on `g_pw_ready` alone, and its
entries open from `g_cfg_pass`, which the container view already keeps alive
for the session so that Extract does not re-prompt. The password is
deliberately **not** copied into the drag object the way the `.mrk` key is:
that would mean more copies of the secret, not fewer.

**Coverage.** `tests/estreamtest.ps1` now runs 100 checks. The zip half drives
the same `IDataObject` through the same vtable calls, against three archives -
AES deflate, AES stored, and unencrypted - one per output path in the reader,
with the bytes compared to `myrkr unzip` and both AES archives tampered and
refused. `tests/mkzip.py` builds the fixtures with pyzipper, because myrkr
cannot write a WinZip-AES archive and a fixture should owe the code under test
nothing.

## 8. The mouse has to be handed back

**Found by using it, 2026-08-11, in 1.0.27. Fixed in 1.0.28 and confirmed the
same way** - the diagnosis below was reasoned from the symptom rather than
reproduced in a harness, because nothing here can drive a drag, so the
confirmation had to come from use as well.

Reported symptom: after dragging
a file out of a zip and dropping it in Explorer, *the Exit button stopped
working* and the window had to be closed with Alt+F4. Everything up to that
point — creating the zip, dropping a file into it, reopening, extracting by
drag — worked.

The asymmetry is the diagnosis. Alt+F4 is **keyboard**: it reaches the window,
so the window is alive and pumping messages. The Exit button is a real
owner-drawn `BUTTON` that only produces `WM_COMMAND` when a **mouse** click
reaches it. Keyboard in, mouse out means the mouse is going somewhere else, and
there is only one thing that does that: capture.

`LVN_BEGINDRAG` is not a standalone event. The list-view sends it from **inside
its own mouse tracking**, having captured the mouse on the button-down and
still waiting for the button-up. `container_drag_out` then runs `DoDragDrop`
inside that notification. `DoDragDrop` takes the capture for the duration of
the drag and **consumes the button-up itself** — so when it returns and the
list-view's handler resumes, the list-view has never been told the drag ended.
It goes on believing one is in progress and swallows what comes next.

The fix is `WM_CANCELMODE` to the list, which is the message that exists for
precisely this: abandon any internal modal state, drop the capture. It is sent
in preference to faking a `WM_LBUTTONUP`, which is the other common remedy and
has a side effect — a synthetic button-up carries coordinates, and the ones
usually used (0,0) would land a selection on whatever row is under them.

**On every path out, not only the one that dragged.** The gates at the top of
`container_drag_out` return before `DoDragDrop` is ever reached, and the
list-view is in exactly the same state for those. A *refused* drag left the
window just as unclickable as a completed one — which means this was reachable
before zips were, by dragging from a container whose key had gone stale.

### What this says about the coverage boundary

`docs/UI_SURFACES.md` records four attempts at driving a drag and why the last
one cannot work: `DoDragDrop`'s `SetCapture` only takes effect for the
foreground thread. Both objects either side of the drag are driven through
their vtables by `tests/estreamtest.ps1`, and all 100 of those checks passed
against the build that shipped this defect — because the defect is not in
either object. It is in what the *window* is left holding afterwards, and the
window is the part nothing here can drive.

That is the second defect this arc has taken from that same blind spot (the
first being the five drag-and-drop defects `tests/README.md` records). The
lesson is not "write more tests for the objects" — they were fine. It is that
`DoDragDrop` returning is a **state transition for the control that started the
drag**, and the handler owns putting that control back.
