# Adding files to an existing archive

**Status: the foundation is built and tested; the three pieces that use it are
specified, not built.** Container format v6 landed in `785e117` — the trailer
now records the next ordinal to issue, which is the thing that makes appending
to a `.mrk` safe at all. What remains is the append paths themselves and the UI
that reaches them.

Split this way on purpose: v6 is a self-contained, independently verifiable
change, and `do_pack`'s streaming payload walk has to be factored before the
`.mrk` append can reuse it. Starting that factoring without room to finish it
would leave the most safety-critical file in the tree half-refactored.

## 1. Why the two formats need different work

| | `.mrk` | zip |
|---|---|---|
| key per entry | one key for the whole container | per-entry, derived from a per-entry salt |
| nonce | ordinal, must never repeat under the key | not applicable |
| what makes appending safe | the v6 counter | the format itself |
| cost of adding one small file | O(new data) | O(new data) |

WinZip-AES gives every entry its own salt, so a new entry gets its own key and
appending is safe by construction. A `.mrk` has a single key and counter nonces,
so the whole problem is "which ordinal may this entry have" — answered by
`IDXT_next`, see manifest §4.

## 2. `.mrk`: append at the payload's end

The index lives at the end of the file, so the end of the payload run *is* where
the index starts. New entries go there and the index moves out past them.

```
before   [hdr 80][e0][e1][e2][idx][tag][trl 32]
during   [hdr 80][e0][e1][e2][e3][e4]...            <- index overwritten
after    [hdr 80][e0][e1][e2][e3][e4][idx'][tag][trl' 32]
```

1. Open read/write. `idx_tail` then `idx_auth` — this authenticates, fills
   `g_idxbuf`/`g_idxlen`/`g_idxcount`/`g_idxrev`, and restores `g_entnext`.
   **Nothing may use `g_entnext` before `idx_auth` returns 0**; that is the whole
   reason it is restored on the success path rather than with the other trailer
   fields.
2. Derive the key from the password and the header's existing salt. Same key —
   that is the point of v6.
3. Seek to `filesize - tail`, the old index's first byte. Track that offset as
   the write cursor; `IDXE_offset` is relative to `HDR_BYTES`, so the first new
   entry's offset is `cursor - HDR_BYTES`.
4. For each new input, exactly as `do_pack` does per entry: `entry_begin` /
   stream / `entry_end` (which takes the ordinal from `g_entnext` and advances
   it), then `idx_add`.
5. `inc g_idxrev` — a rewritten index is different plaintext under the same key,
   so it needs a fresh nonce. `do_remove_marked` already does this; the add path
   must not forget it.
6. `idx_write`, then `file_truncate` to the new end.

**What has to be factored out of `do_pack` first.** Its payload loop currently
assumes it is writing a fresh container from `HDR_BYTES` with `g_entnext` at 0.
The append path needs the same loop starting from an arbitrary cursor with
`g_entnext` already set. Everything below that — `entry_begin`, `entry_end`,
`idx_add`, the compressor, the tar framing — is already position-independent,
because an entry's tag does not depend on where it sits.

**Two decisions still open:**

- **A name already in the container.** Adding `a/b.txt` when the index already
  lists it. Extraction would write both and the last would win, which is a silent
  wrong answer. Refusing the whole operation with the offending name is the
  conservative choice and the recommendation; replacing (drop the old entry, add
  the new, leave the old ciphertext to be reclaimed by the existing delete path)
  is what a user probably expects. Do not leave it as "both entries exist".
- **Compression.** `g_cfg_compress` may differ from what the container was
  packed with. Entries are framed individually, so a mixed container is
  well-formed. Simplest correct behaviour: honour the current setting per added
  entry, since nothing reads a container-wide compression flag.

**The crash window is real and is not new.** Step 3 overwrites the old index, so
from the first new byte until the new trailer is written the file has no valid
trailer at its end. A power cut there leaves a container whose payload entries
are all present and encrypted but whose index is gone. This is the same exposure
`do_remove_marked` already carries — it moves survivors and rewrites the index in
place — so it is a property of in-place editing, not of appending. Say so in the
manifest rather than implying appending is atomic.

## 3. Zip: append after the old central directory

Crash-safe *and* O(new data), which the `.mrk` path cannot be:

```
before   [lh0][d0][lh1][d1][CD][EOCD]
after    [lh0][d0][lh1][d1][CD][lh2][d2][CD'][EOCD']
                            ^ dead bytes, harmless
```

Write the new local headers and their encrypted data starting at the **old
EOCD's offset**, then a new central directory covering old and new entries, then
the new EOCD **last**. Until that final write the old EOCD is still intact at the
end of the file and still points at the old CD, which has not been touched — so
an interrupted add leaves the original archive readable. The old CD becomes dead
bytes in the middle; a few hundred per add, and no reader looks at them because
readers locate the CD through the EOCD.

`zip_read_cd` already parses what is needed and leaves the CD offset in
`g_cdoff`. The new entries are written the way `do_zip` writes them; the CD
records for the existing entries are copied verbatim, exactly as
`zip_delete_marked` copies survivors, with only the local-header offset patched
where it moves — here it does not move at all, so they copy unchanged.

**Check the password against the archive first.** WinZip-AES stores a two-byte
password verification value per entry. Derive against an existing encrypted
entry's salt and compare before writing anything. Without this, a typo produces
an archive whose entries have two different passwords — every tool will open the
old entries and fail the new ones, and the user has no way to tell what happened.
If the archive has no encrypted entries, there is nothing to check against and
the new entries simply set the password for themselves.

**State: DONE. Encrypted and unencrypted append both work.** A wrong password
is refused before a byte is written, with the archive byte-for-byte unchanged.

What is already right in that work:

- `zip_finish` factored out of `do_zip` (close the CD temp, append it, ZIP64,
  EOCD) and shared with a new `do_zip_add`. The existing directory records copy
  in verbatim ahead of the new ones - nothing moved, so no local-header offset
  needs patching.
- The write ordering works. `myrkr zipadd plain.zip folder` on an unencrypted
  archive produces a file that **.NET's `ZipFile` reads correctly**, sees all
  four entries in, and reads appended content back from. That independent
  reader is the check that matters; our own round-trip could pass on a
  directory only we could follow.
- A new `zipadd` verb, refused by release builds like the other password-taking
  ones, with a `LANDING_PAD` (a dispatch target without one trips
  `CALL_GUARDED` -> `FF_GUARD_ICALL`, which is `0xFADE000A`, not a crash).

Three faults found and fixed along the way, all worth not repeating:

- `zip_read_cd` takes its path in **rcx**, not from `g_cfg_in`. Calling it
  without setting rcx normalised whatever was in the register; the failure came
  back as a bare exit code with nothing printed, so the verb exited 2 in
  silence. Every error path in the new code now prints.
- `g_cfg_in` needs an `externdef` in zip.asm.
- `zip_check_password`'s frame must be **160**, not 96: `pbkdf2_hmac_sha1` takes
  seven arguments, so its outgoing area at `[rsp+32..48]` sat exactly on
  `saltlen`/`namelen`/`extralen`, and the verifier comparison after the call
  reads `saltlen`.

Two things still wrong, in priority order:

1. ~~The phase 2 timeout~~ - FIXED, and it was not zip code at all. `CMD_COUNT`
   was hand-counted, so adding the `zipadd` verb pushed `redteam` off the end of
   the command table and an unmatched verb hangs. It is derived from the table's
   own length now. The guess recorded here first - a non-terminating loop in
   `zcp_step` - was wrong, and chasing it would have wasted the next session
   too: all six redteam cases hung identically, which is what said the fault was
   before the case dispatch rather than inside it.
2. ~~`zip_check_password` returns `EXIT_IO`~~ - FIXED. `and rax, 0FFFFFFFFh`
   assembles as AND r64, **imm32**, and an imm32 is sign-extended, so the mask
   was `0FFFFFFFFFFFFFFFFh` and did nothing. The qword at CD+42 carries the
   first four bytes of the entry NAME in its high half, so the local-header
   offset came out astronomically large and the read failed. Read a 4-byte
   field with a 32-bit load - writing eax zero-extends into rax. **Anywhere
   else in this codebase that masks a qword down to 32 bits with an immediate
   has the same bug**; a 32-bit load is the idiom.

   Reasoning did not find this and would not have. Two probe builds did: the
   first said which of the two reads failed, the second said the offset was not
   what the file's own bytes showed it should be.

**ZIP64.** `zip_read_cd` already handles the ZIP64 EOCD and locator. An append
that pushes the archive past a 32-bit boundary has to write ZIP64 records where
the original had none. Either handle it or refuse the add above the threshold —
refusing is acceptable, silently writing a broken CD is not.

## 4. UI — built, with one gap in the testing

`container_add` is wired to both Add commands and routes by `g_is_zip`. The
picker already appends what it collects to the input slots and slot 0 is
`g_filepath_w`, the archive itself — so after it runs the layout is exactly what
`do_add` and `do_zip_add` want, and nothing has to be marshalled. `g_poscount`
is restored afterwards so a cancelled or failed add leaves nothing behind.

`add_via_picker` grew a `g_pick_only` flag: in container mode it must not
rebuild the input list, which would replace the archive listing on screen and
start the indexer walking files nothing is going to pack.

**Verified end to end.** `tests/pickertest.ps1` drives the real modal dialog
with real keystrokes: open an unencrypted zip, Add files, type a path, Enter -
then check that the archive grew, that .NET (an independent reader) sees the new
entry with matching bytes, that the container view refreshed itself, and that
the process is still alive. The fixture archive is built by .NET too, so neither
end of the test is Myrkr own code.

Driving it found two defects every cheaper check had passed:

- `g_pick_only` skipped `set_input_ptrs` as well as `refresh_inputs`.
  `set_input_ptrs` fills `g_positionals[]` from the input slots and the append
  procs walk that array, so the append followed a stale pointer. Only the list
  *repaint* is container-mode-inappropriate.
- `container_add` used `[rbp-8]`, where `FRAME_PROLOG` plants the stack canary.
  It fail-fasted in its own epilog **after all its work had completed**, so the
  archive was appended correctly and then the process died - which reads as a
  fault in whatever it called. A release build's `0xC0000409` carries no FF
  code; the giveaway was that the work had visibly succeeded first.

### Original notes

The container view already has the command bar and `g_is_zip` to pick a path.
Add files / Add folder exist as sidebar actions and are currently wired only for
the encrypt view.

- Enable them while `g_container` is set; route by `g_is_zip`.
- Both paths need the password. The container was opened with it for browsing,
  so it is already in hand — do not prompt twice.
- Report failures the way removal does: `m_zip_io` and friends, plus a partial
  outcome, since an add that wrote some entries and then failed is exactly the
  case a single "it failed" message would misdescribe.
- Like `container_remove_selected`, this runs on the UI thread. Adding a large
  file will hold the window. Same outstanding work, same note.

## 5. Tests

The one that matters most:

**No ordinal is ever issued twice.** Add two files, delete the entry with the
highest ordinal, add another, then read every `IDXE_ordinal` in the decrypted
index plus `IDXT_next` and assert all ordinals are distinct and all are below
`next`. Recomputing the counter instead of storing it passes a naive add-only
test and fails this one. `tests/rmbartest.ps1` drives a GUI removal and reads
process globals through the map - the delete half and the readout pattern to
extend. (A session-local script used to be named here; it no longer exists.)

Also worth pinning:

- append → `verify` → `decrypt`, and every file matches its original, including
  the ones that were there before the add
- an interrupted add (kill the process mid-write) leaves the *zip* readable —
  the property the write ordering exists for
- adding to a zip with a wrong password is refused before any byte is written
- `g_idxrev` advances on an add, so the rewritten index gets a fresh nonce

**Two harness traps already paid for**, both of which make a test pass for the
wrong reason:

- `LVM_SETITEMSTATE` is not marshalled across processes. The `LVITEM` must be
  written into the target with `VirtualAllocEx`/`WriteProcessMemory`, and
  `state`/`stateMask` are at offsets 12 and 16, not 0 and 4. Get either wrong and
  nothing is selected, the removal does nothing, and "the counter held" is
  vacuously true. Assert the selection count *and* that the rewrite actually
  happened before believing any result that follows.
- Browsing a `.mrk` needs the password, and with HKLM `SecureDesktop=1` that
  prompt is on a desktop the harness cannot reach. Use a `dbg` build with
  `MYRKR_DBG_NOSECDESK=1`, and remember to rebuild release afterwards.
