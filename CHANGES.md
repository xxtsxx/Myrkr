# Changes

All notable changes to **Myrkr** are logged here. Newest first. Dates are
ISO-8601 (`YYYY-MM-DD`).

This file is maintained by hand alongside every change; each entry summarizes
what changed and why, not a raw commit dump.

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
