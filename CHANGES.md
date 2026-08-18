# Changes

All notable changes to **Myrkr** are logged here. Newest first. Dates are
ISO-8601 (`YYYY-MM-DD`).

This file is maintained by hand alongside every change; each entry summarizes
what changed and why, not a raw commit dump.

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

- Secrets live in **locked, non-pageable memory** and are wiped after use,
  including on the paths that fail.
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
