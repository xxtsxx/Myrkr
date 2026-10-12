# Changes

All notable changes to **Myrkr** are logged here. Newest first. Dates are
ISO-8601 (`YYYY-MM-DD`).

This file is maintained by hand alongside every change; each entry summarizes
what changed and why, not a raw commit dump.

## [1.1.6] - 2026-10-12

### Fixed

- **A zip that lied about an entry's size could make Myrkr consume that much
  memory.** The sizes in a zip's central directory are the archive's word, and
  three buffers were sized from them and then wiped at the claimed size on the
  way out - touching every page of memory that had never been used. A 64 KiB
  zip claiming a 3 GiB entry drove `unzip` (and extracting in the window, and
  dragging the row out) to about 3 GiB of working set before it failed. Now an
  entry's stored bytes must lie inside the archive (a compressed size past the
  end of the file is reported as corrupt, exit 4, not as an I/O error), a
  drag-out buffer is sized only to what the entry could hold, and every wipe
  covers only the bytes actually written. The same zip now costs about 8 MiB.
- **The window silently took only part of a large selection.** It holds at
  most 256 inputs, and past that it stopped reading the command line: dropping
  300 files onto Myrkr's icon or a shortcut, or sending them with Send To,
  opened a window holding 256 with nothing on screen to say 44 were missing.
  (The shell extension's menu caps a selection at 64, so its right-drag was
  not affected; the stop would also have dropped its `--to` destination.) A
  selection over the limit is now refused whole with an error - nothing is
  encrypted - and a drop or picker past it keeps what fits and says some items
  were not added.
- **Argon2 changed registers its callers rely on.** The Windows x64 ABI makes
  r12-r15 callee-saved; the key derivation used three of them as scratch
  without saving them, so every derivation returned to its caller - including
  Windows code above a window procedure or thread start - with them changed.
  Nothing visibly broke, but only by luck. They are saved and restored now, and
  a new build checker, `tools/nvcheck.py`, holds every procedure to the rule
  (it also found the self-test doing the same).
- **A crash left secrets for the crash dump.** Myrkr had no crash handling: a
  fault went to Windows Error Reporting with the password, key and any
  decrypted data still in memory, and a fault while the password prompt held
  the private desktop left the user on an empty screen. A fatal fault in Myrkr
  now wipes every registered secret first, switches back to the user's desktop,
  suppresses the crash dialog, writes a 24-byte breadcrumb
  (`%TEMP%\myrkr_crash.bin`: code and address, never register contents) and
  ends the process.
- **Replacing an existing file was not safe against power loss.** Extraction
  writes a temporary file and renames it over the existing one, but the rename
  could reach the disk before the data, so a power cut shortly after could
  leave the user's file zero-filled. When a rename replaces a file, the new
  data is now flushed first and the rename is written through. A rename to a
  new name is unchanged, so extracting into an empty folder costs no more.
- **Key material left on the stack and in buffers:** the AES-GCM partial-block
  keystream, the last WinZip-AES keystream block and BLAKE2b's working state
  (which Argon2 fills with password-derived data) are now wiped; a failed tag
  check in the one-shot `gcm_open` scrubs the plaintext it already wrote; and
  the final Argon2 block, which alone is enough to recreate the key, is pinned
  in RAM while the derivation runs.

  These four came from comparing Myrkr with Vordr, which shares its crypto core
  and had fixed all of them - as it had the Argon2 indexing bug that 1.1.5 fixed.
- **A path too long for an input slot was truncated, not refused.** A
  4,108-character file path became its 4,095-character folder, so the folder's
  other files would have been encrypted with it. It is now refused with an
  error.

### Tests

- `tests/zipclaimtest.py` measures the peak working set of `unzip` and of the
  drag-out data object against zips that lie about their sizes; it fails
  against 1.1.5 and is part of Phase 1.
- `tests/crashtest.py` (Phase 2) drives the crash containment with a new
  `redteam crash` case and checks the exit status and the breadcrumb.
- `tools/nvcheck.py` gates `build strict` on callee-saved registers; on the
  1.1.5 sources it reports exactly the five unsaved registers fixed above.
- `tests/inputcaptest.ps1` covers the input limits from the command line and
  from a drop, including the exact-256 boundary; it fails against 1.1.5 and is
  part of Phase 2.

## [1.1.5] - 2026-10-11

### Changed - format version 9: the key is RFC 9106 Argon2id exactly

- New containers are format version 9, and their key is derived with Argon2id
  exactly as RFC 9106 specifies, so any standard Argon2 library reproduces it.
  Versions 6-8 were derived with a variant: the first segment's pseudo-random
  values were taken two positions off (argon2.asm indexed the address block by a
  per-segment counter rather than by block position). It was found in 1.1.4 by
  decrypting Myrkr's output with an independent implementation; the RFC's own
  test vector is too small to show it. It was not a weakness - the same values,
  each used once, the same memory-hardness - but it tied every container to
  Myrkr.
- **Every existing container still opens, unchanged.** The key rule is chosen
  by the header's version, in one place (`derive_key`). Editing an older
  container - add or delete - re-encrypts it as version 9, as edits always
  re-encrypt.
- Older Myrkr builds (1.1.4 and before) cannot open version 9 containers; they
  report a newer format version rather than damage.

### Tests

- `myrkr selftest` adds the reference implementation's single-lane 64 MiB
  Argon2id vector - the case every container uses, which the RFC vector cannot
  reach - and pins the legacy rule with a fixed vector.
- `tests/indepdecrypttest.py` checks both directions: what Myrkr writes opens
  with standard Argon2id and not with the legacy rule, every frozen v6/v8
  fixture opens with the legacy rule and not with the standard one, and adding
  to a v8 fixture produces a version 9 container.
- `compattest.ps1` and `segmenttest.ps1` expect version 9 from the writer; a
  mutant that derived every version with the standard rule fails every
  `compattest` fixture check with exit 3.
- `ARGON2REQ` is defined once, in `macros.inc`, instead of three times.

## [1.1.4] - 2026-10-11

### Fixed

- **A volume set that cannot be assembled** - a part missing, out of order, or
  from another set - went wrong three ways at once. The parts Myrkr had already
  opened while checking were never closed, so the window kept them locked
  (they could not be moved, renamed or deleted) until it exited; the window took
  the part for an ordinary file and offered to encrypt it; and the CLI said
  "I/O failure" (exit 2). It is now reported as an incomplete volume set, exit 4,
  with an error in the window, and every part is released.
- A second open of a container while a volume set was open joined that set
  whatever path it named, so a different container would have read the set's
  bytes. Nothing reached that (drag-out finishes before anything else can
  open), but it is now a refusal unless the path names the same set.

### Tests and tooling

- `tests/indepdecrypttest.py` decrypts Myrkr's containers with an
  implementation that shares none of its code (Argon2id from RFC 9106,
  pycryptodomex AES-GCM, the layout from `src/macros.inc`), across stored,
  compressed, segmented, split and edited containers. It found that Myrkr's
  Argon2id is not RFC 9106: the address block is indexed by a per-segment
  counter rather than by block position, which differs in the first segment of
  the first pass. Not a weakness, but no standard library derives a Myrkr key,
  and the RFC's own vector is too small to show it. The test pins the current
  behaviour for format versions up to 8; changing it is a format decision and
  has not been made.
- `volumetest.ps1` covers the three incomplete-set failures above, each shown
  failing against 1.1.3.
- `tools/compare.ps1` runs one test against an older commit and against the
  working tree, and passes only when the old build fails it and the new one
  does not - the proof a regression test needs, which 1.1.3 did by hand.
- `tests/lib/gui.psm1` holds the window helpers every GUI test used to
  re-declare. The copies had drifted into probe bugs: a hit-test lParam packed
  as `y*65536+x`, wrong for any negative coordinate. `guifailtest.ps1` uses it,
  and `compare.ps1` confirms it still fails against 1.1.2.
- `tests/all.ps1` runs every suite in sequence (`-Quick` leaves out the
  11-minute `scaletest`) and no longer runs the four `run.ps1` hosts against a
  build they were not written for.
- `secsuite.py` runs its 200-sample salt check four at a time: Phase 1 went
  from about four minutes to two and a half.

## [1.1.3] - 2026-10-11

An in-depth review of 1.1.2 found that extraction could destroy files the user
already had, and could be steered outside its destination. Fixed, along with a
set of logic gaps the review turned up beside them.

### Fixed - extraction no longer destroys existing files

- Each archive entry is written into a fresh, randomly named sibling opened with
  `CREATE_NEW`, and renamed over its real name only once every byte has
  authenticated (or, for a plain zip entry, passed its CRC). Up to 1.1.2 the
  entry was written straight into the real name and deleted when it failed - so
  a damaged entry, an I/O error or a **Cancel** destroyed a file the user already
  had under that name, with nothing replacing it. No attacker was needed: a
  damaged backup extracted over working files was enough. Plain zip stored
  entries were worse, keeping their damaged bytes under the real name. Now the
  existing file is either replaced whole by a verified copy or not touched.
- A hardlink planted at an output name is now replaced, not written through into
  the file it links to outside the destination.
- A cancelled extraction reports as cancelled, not as an I/O failure.

### Fixed - extraction cannot be steered outside its destination

- An entry `evil/x` aimed at a destination already holding a junction or symbolic
  link `evil` was written wherever the link pointed. Every folder below the
  destination is now checked before anything is created; a junction, symbolic
  link or mount point stops the run (exit 9) with the path named. The
  destination itself is trusted, and cloud-file placeholders are not refused.
  The check is by path: a link swapped in while the extraction runs is not
  caught, and `docs/SECURITY.md` says so.
- The guard caches the folders it has verified, so the per-entry safety costs
  nothing at scale: extracting 20,000 small files is 9% *faster* than in 1.1.2.

### Fixed - names that could not be stored faithfully

- `encrypt` and `zip` refused nothing when two inputs would be stored under one
  name - two folders both called `docs` - and extraction then silently kept only
  the last. Refused now, before anything is written, and so are names that differ
  only in case, which are one file on Windows. `add` checks the same way against
  the container, case-insensitively, before re-encrypting anything; it used to
  fail with no message at all, and only after a full rewrite.
- `delete` naming something not in the container said so and then exited 0
  after rewriting the container anyway. It now changes nothing and fails.
- Adding a file over 64 GiB to an older, unsegmented container told the window
  user it was "already in the archive". It now says what is wrong.

### Fixed - the window

- A failed encrypt or decrypt showed its error and then a second, unrelated one
  ("The full re-encryption could not be completed"), and skipped the restore
  step that clears the typed password. One dialog now, and the same restore a
  successful decrypt takes.
- A refusal could show the previous job's reason; every job now starts clean.
- The replacement-failed dialog explains what the recovery file is and what to
  do with it, instead of showing a bare path.
- The About box claimed a version label opened the project page; nothing did.
  It now says where the project is, and the link at the foot of the About
  window opens it.

### Changed

- Every edit raises the container's key-derivation cost to at least the current
  setting (including an administrator's floor), never lowering it. Each edit
  already derived a new key; a container made at a weak cost no longer stays weak.

### Tests and documentation

- `tests/extracthazardtest.py` covers all of the above for the native extractor
  and both zip paths, and was run against 1.1.2 (17 failures) as well as 1.1.3.
- `tests/run.ps1` no longer requires PowerShell 7: without it, the runner
  aborted at its first GUI suite, skipping every adversarial test and leaving a
  test build in `bin\`.
- Four suites had been failing since 1.1.1 unnoticed, because the runner never
  reached them: `afterencrypttest` and `volumetest` still expected labels 1.1.1
  renamed; `rmbartest` counted the bar's post-completion reset as the bar going
  backwards; `nativeeditguitest` hashed the source while the rewrite still held
  it. All four were test faults, each confirmed against 1.1.2 - the product
  behaved correctly - and each now asserts what it was written to check.
- Corrected an overstatement in the README and the 1.1.0 notes: secrets are
  locked against paging where Windows allows, not unconditionally.

## [1.1.2] - 2026-09-05

- Remove the native writer's unnecessary ustar name restriction: preserve full
  names in the authenticated index and use a marker only in the ignored legacy
  header. Keep v8 framing and content offsets unchanged. Fix the undersized
  directory-name scratch buffer exposed by paths beyond 1 KiB.
- Bound native/ZIP relative-name construction at 4,094 UTF-8 bytes without
  silent truncation; report the failing source. Explain Myrkr versus ZIP format
  limits in ZIP reader errors and path documentation. Reject combined extraction
  paths that do not fit instead of shortening them.
- Test long leaves, Unicode, deep checkpoint paths, 4,094-byte boundaries,
  streaming drag-out, full rewrites, and independent ZIP readback.

## [1.1.1] - 2026-09-05

- Clarify GUI workflows: Create .mrk / Create ZIP for new archives, Extract all /
  Extract selected for open archives, Delete for saved entries versus Remove
  for staged inputs. Explain immediate saving in status/tooltips. Use Close
  while idle and Cancel while working; honor uncancellable ZIP deletion for
  keyboard/command-bar shortcuts too. Cover labels in GUI regressions.

- Remove vertical column seams from unused list space by disabling Explorer
  visual styles on the list control only. Remove the old per-row background
  overpaint; retain native full-row selection and double buffering. Add empty/
  populated-list pixel regressions across resizing and theme notifications.
- Blend command-bar buttons into the window background at rest; retain rounded
  hover/pressed feedback and mute disabled commands. Fix overlapping glyph-draw
  locals that could corrupt label handles. Add six-button paint regressions.
- Reject ZIP64 extra records whose declared payload cannot hold the size and
  offset fields being read, or whose record extends beyond the extra area.
- Reject ZIP entry names containing NUL bytes or exceeding the extraction name
  buffer instead of silently extracting under a shortened name.
- Add deterministic ZIP parser regressions to the security-suite runner.
- Replace native in-place add/removal with full streaming re-encryption under a
  fresh salt, key, and container identity. Copied/restored containers no longer
  share an edit nonce namespace. Preserve compression, KDF costs, and segmentation.
- Keep plaintext in memory; flush a CREATE_NEW encrypted sibling before replacing
  the original. Cancellation/pre-commit failures leave the original unchanged;
  replacement failures retain an encrypted recovery file and report its path.
- Warn before GUI rewrites at 100 MiB of container/content/added-input size.
  Native removals support cancellation, including requests during preflight.
- Add copied-container fresh-key, rollback, corruption, readback, and GUI warning/
  cancellation regressions. Earlier exposure from old binaries cannot be repaired.
- Make the heap-canary fault-injection test flip a bit instead of writing a
  fixed byte that can already match the random canary (a 1-in-256 false failure).

## [1.1.0] - 2026-08-18

First public release. Myrkr was developed privately through a long 1.0.x
series; this is that work published as a single release rather than as its
development history.

### What it does

Encrypt a file or a folder on Windows so nobody without the password can read
it - or change it without you finding out. Drop something on the window, type a
password, get one encrypted file back. **AES-256-GCM** for confidentiality and
authentication, **Argon2id** (RFC 9106) for key derivation, written entirely in
hand-written 64-bit assembly with no C runtime and no dependencies beyond the
Windows API.

### Container format

- **Per-entry GCM streams.** Every file in a container is sealed under its own
  stream with the entry's ordinal in the AAD, so an entry cannot be moved,
  duplicated, or spliced in from another container without failing its tag.
- **Counter nonces in disjoint bit fields** - a 64-bit counter and a 32-bit
  segment index - so two nonces are equal only if both fields are. The layout
  is pinned by self-test vectors chosen to fail if the fields ever overlap.
- **Segmented entries** (4 GiB segments by default) lift AES-GCM's ~64 GiB
  per-stream plaintext limit. Field-proven on a 155 GB single file.
- **An encrypted inventory**, so a container can be browsed - names, sizes,
  tree structure - for the cost of one key derivation, without decrypting the
  payload. The listing sits behind the same key as the data.
- **Volume splitting** for containers that must cross media, reassembled
  transparently when any member is opened.

### The application

- A drag-and-drop window, Explorer right-click and right-drag integration, and
  a container browser you can drag files back *out* of.
- **Password entry on a private desktop**, so window discovery, message
  injection, and desktop-scoped keyboard hooks cannot reach the prompt.
- Progress metering with transfer rate and ETA on long operations.
- ZIP support alongside the native format: extraction (including WinZip-AES),
  and adding to existing archives.
- An MSI with per-machine policy - administrators can pin or floor the KDF
  cost, the password rules, logging, and the private-desktop requirement.

### Security posture

- The password and the keys derived from it are wiped after use, including on
  the paths that fail, and held in memory locked against paging wherever
  Windows allows it - best effort: the Argon2 working area is too large to lock
  and is wiped instead. *(Corrected in 1.1.3: this line first claimed every
  secret lived in non-pageable memory, which overstated it.)*
- **Fail-closed at every guard**: unauthenticated key-derivation parameters are
  range-checked before the KDF runs; the inventory is authenticated before it
  is parsed; a failed tag wipes what it decrypted rather than leaving it for a
  caller to walk.
- Memory-safety hardening throughout: stack canaries, a per-thread software
  shadow stack, CET, a temporally-tagged heap, bounds and integer-overflow
  checks, and a read-only IAT. `myrkr redteam` (instrumented builds) proves
  each control fires and fails closed.
- `myrkr selftest` runs published known-answer vectors - FIPS-197, SP800-38D,
  RFC 7693, RFC 9106, FIPS 180-4 - alongside the format's own invariants.

### Verification

The tree ships its own checkers - frame layout, calling convention, dead code,
string encoding, alignment, constant agreement - that a strict build must pass,
and a test suite covering the format, the GUI, the shell extension, scale
limits, and adversarial input, including a fuzzer asserting that a malformed
zip may be rejected but may never crash or hang the extractor.
