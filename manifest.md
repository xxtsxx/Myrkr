# Myrkr — Technical Manifest

**myrkr.exe** is a self-contained Windows x64 console application that encrypts,
decrypts, verifies, and archives files using AES-256-GCM with an Argon2id key
derivation function. It is written entirely in 64-bit MASM assembly
(`ml64.exe` + `link.exe`), links only against OS-inbox DLLs (kernel32, bcrypt,
cabinet), and carries no C runtime, no third-party libraries, and no external
dependencies of any kind.

This document is the authoritative, current-state record of *what* has been
built and *why* each design decision was made. It is maintained alongside the
code; when behavior changes, this file changes with it. The companion document
`README.md` covers user-facing usage. §14 (Security and risk assessment) ties
together the cryptographic design (§5), the container/key-commitment format
(§4), the archive-safety layering (§6.5–6.6), and the exploit-hardening set
(§9).

---

## 1. Design philosophy

Every choice in this project is driven by four principles, in priority order:

1. **No trusted runtime.** The CRT, the .NET runtime, OpenSSL, libsodium — each
   is attack surface and a supply-chain liability. By writing directly to the
   Win32 API and the CPU's cryptographic instructions, the trusted computing
   base is the OS kernel, a handful of inbox DLLs, and the silicon. Nothing
   else.

2. **Hardware crypto only.** All bulk cryptography runs on dedicated CPU
   instructions (AES-NI, PCLMULQDQ, SHA-NI, AVX2/SSE2). This is faster than any
   software implementation *and* constant-time by construction — the AES and
   GHASH instructions have data-independent latency, which removes an entire
   class of cache/timing side channels for free.

3. **Defense in depth, fail closed.** The binary stacks every practical
   exploit mitigation the platform offers — hardware (CET, CFG) and software
   (canaries, a shadow stack, DLPV, a tagged heap, bounds/overflow/type checks).
   Any detected violation calls `__fastfail`, which the kernel treats as a
   non-continuable, non-catchable fault. There is no "log and continue" path:
   a corrupted invariant ends the process.

4. **Verifiable correctness.** Every cryptographic primitive is checked against
   its official RFC/NIST test vector *at every program startup* via
   `myrkr selftest`, and was cross-validated against an independent C reference
   on the same CPU before being trusted. Correctness is demonstrated, not
   assumed.

A fifth, softer principle governs the source itself: **readability**. The code
is broken into small, single-responsibility procedures; cross-cutting concerns
(prologues, bounds checks, overflow checks, secure zeroing) are expressed as
named macros so intent is visible at the call site; and the work was built in
small, individually tested phases rather than as a monolith.

---

## 2. Toolchain and build

| Aspect | Choice | Rationale |
|---|---|---|
| Assembler | `ml64.exe` (MSVC x64) | Native MASM64; produces proper `.pdata`/`.xdata` unwind info, which x64 SEH and the debugger require. |
| Linker | `link.exe` | Emits the CFG guard tables and load-config directory; honors all mitigation switches. |
| Libraries | `kernel32.lib bcrypt.lib cabinet.lib` (import libs only) | All three back OS-inbox DLLs. `bcrypt` for the CSPRNG, `cabinet` for XPRESS compression. No static code is pulled in. |
| CRT | none (`/nodefaultlib`) | Removes the entire CRT attack surface and startup machinery; the entry point is our own `wstart`. |

`myrkr.exe` is a **single hybrid binary**: it is linked `/subsystem:windows` with
the GUI entry point `wstart`, but `wstart` runs the full CLI whenever the first
argument is a known command verb (or begins with `-`), and only opens the window
otherwise (no args, or a bare dropped file path). See §11.

Mitigation switches on the shipping link line:

```
/subsystem:windows /entry:wstart /nodefaultlib /incremental:no
/dynamicbase /highentropyva /nxcompat /largeaddressaware
/CETCOMPAT
/manifest:embed /manifestinput:myrkr.manifest /manifestuac:no
```

- `/subsystem:windows` (not `console`) lets the one binary create windows. The
  cost is that a terminal does not wait for it — see §11 — and `/guard:cf` must
  stay off because the GUI hands the OS callback pointers that CFG validates
  against this image's (absent) guard table.

- `/incremental:no` is **mandatory**, not cosmetic: incremental linking inserts
  jump thunks in front of functions, which breaks the DLPV `[target-8]` magic
  check (see §9). This was discovered during integration and is now fixed.
- `/largeaddressaware` + `/highentropyva` give the full 64-bit ASLR entropy
  budget. A consequence is that `[g_symbol + reg*scale]` addressing is illegal
  (it would need a 32-bit absolute relocation); the code always does
  `lea reg,[g_symbol]` first. This constraint caused several early crashes and
  is now a standing rule.
- The manifest (`myrkr.manifest`) declares `longPathAware` so the OS does not
  impose the legacy 260-character `MAX_PATH` cap (see §7).
- A resource script (`myrkr.rc` → `rc.exe` → `obj\myrkr.res`, linked in) carries
  a `VERSIONINFO` block — FileVersion/ProductVersion `1.1.0.0`, product name,
  description, company and copyright (shown under Properties → Details) — and the
  application **icon** (`myrkr.ico`, a multi-resolution 16–256px set rendered from
  `logo/myrkr.svg`). Resource ID 1 makes it the shell file icon; `gui.asm` also
  loads it into the window class (`hIcon`/`hIconSm`).

`build.cmd` assembles every module in `src/` (including `gui.asm`), links the
single `myrkr.exe` with the above, and runs an optional `dumpbin /headers`
mitigation check. Two variants exist: `build nohw` drops `/CETCOMPAT` (software
mitigations only, for CPUs/loaders without CET), and `build dbg` adds
`/DDBG_TRACE` for single-character breadcrumb tracing during development plus the
`redteam` fault-injection self-test.

**A second binary: `myrkrshell.dll`.** `src/shellext.asm` is assembled with the
same flags but linked separately, into an in-process COM DLL that Explorer loads
to populate the right-drag menu (§15). It shares no object file with the exe —
its own source, its own `VERSIONINFO` (`myrkrshell.rc`, whose version
`constcheck` compares against `myrkr.rc`), its own `.def` file, and four import
libraries:

```
/dll /entry:DllMain /nodefaultlib /incremental:no
/dynamicbase /highentropyva /nxcompat /CETCOMPAT
/def:myrkrshell.def
kernel32.lib user32.lib shell32.lib ole32.lib
```

`/entry:DllMain` because there is no CRT to run `_DllMainCRTStartup`, and not
`/noentry` because `DllMain` must capture `hinstDLL` — that is how the DLL finds
`myrkr.exe` beside itself. It links no `loadcfg.obj`: the exe's names `start` in
its CFG table, and `/guard:cf` is off here for the same reason it is off there.
The two exports are `DllGetClassObject` and `DllCanUnloadNow`; there is
deliberately no `DllRegisterServer`, since a self-registering DLL cannot be
rolled back cleanly by Windows Installer and leaves a half-registered CLSID
behind when an install fails. The MSI writes the registry instead (§15).

---

## 3. Module map

All source is in `src/`. The build order (and `SOURCES` in `build.cmd`) is:

| Module | Responsibility |
|---|---|
| `macros.inc` | All shared constants, the container struct, and every hardening/readability macro: the hardening set (`FRAME_PROLOG/EPILOG`, `CALL_GUARDED`, `LANDING_PAD`, `CHECK_*_OVF`, `BOUND_CHECK`, `TYPE_CHECK`, `SECURE_ZERO`, string macros) plus the cleanup layer -- **`WINCALL`** (Win64 call wrapper: arg marshalling into rcx/rdx/r8/r9 + shadow space, `addr X`->`lea`, width-matching, rcx-loaded-last for dependencies) and the structured-control macros **`xIF`/`xELIF`/`xELSE`/`xENDIF`** (+`xIFT`/`xIFZ`) and **`xWHILE`/`xWHILET`/`xWHILEZ`/`xENDW`** (+`xBREAK`/`xCONTINUE`). The latter exist because ml64 dropped the high-level `.IF`/`.WHILE` directives; the condition code is always explicit, so signedness is never guessed. |
| `main.asm` | CPU feature gate, command-line tokenizer (`parse_cmdline`) + option collector, command dispatch table (`dispatch`), the `is_cli_command` verb/`-`option test used by the hybrid entry to pick CLI vs GUI, IAT lockdown trigger, the legacy console `start` (unused by the shipping binary, which enters at `wstart`), and (dbg builds) the `dbg_putc` breadcrumb writer and `ff_trap` fast-fail handler. |
| `loadcfg.asm` | The `_load_config_used` image load-config directory. Without it the loader sets the CFG bit but has no guard metadata (LNK4266); this supplies the guard table/count/flags symbols the loader needs and rotates `__security_cookie` at start. |
| `hardening.asm` | Runtime hardening: canary initialization, the software shadow-stack region, the tagged heap allocator (`tagged_alloc`/`tagged_free`), `secure_zero`, `ct_memcmp`, and `iat_lockdown`. |
| `random.asm` | CSPRNG: `BCryptGenRandom(SYSTEM_PREFERRED_RNG)` XOR-mixed with `RDSEED`. Fails closed. |
| `sha256.asm` | SHA-256 via the SHA-NI instructions, for the `hash` command. |
| `aesgcm.asm` | AES-256 key expansion (AES-NI), CTR mode, GHASH (PCLMULQDQ), and the streaming GCM context API (`gcm_init/aad/crypt/final`) plus `gcm_seal`/`gcm_open` wrappers. |
| `blake2b.asm` | BLAKE2b (RFC 7693) and the variable-length `H'` used by Argon2. |
| `argon2.asm` | Argon2id (RFC 9106): the `G` compression function with scalar, SSE2, and AVX2 implementations behind a runtime dispatcher, plus indexing and memory fill. |
| `fileio.asm` | Unicode (`*W`) chunked file I/O, size queries, atomic rename (`MoveFileExW`), delete, and the pre-flight free-space check (`disk_has_space`). |
| `console.asm` | Console/stderr output helpers and hex formatting, plus `con_attach_parent` (`AttachConsole(ATTACH_PARENT_PROCESS)`) so the hybrid binary's CLI mode reaches the launching terminal. |
| `cmd.asm` | The high-level commands `encrypt`/`decrypt`/`verify`/`hash`/`bench`, key derivation glue, path normalization (`\\?\`), temp-path construction, and password-policy enforcement. |
| `archive.asm` | ustar (POSIX tar) header **writer**, including the GNU base-256 large-size extension; octal helpers; path-bounded copy. It had a parser too, until extraction stopped needing one (1.0.71): the inventory records the name, size and type the parser recovered, and it is authenticated, so `tar_parse_header` and `parse_octal` ran on attacker-supplied bytes for nothing. A tombstone comment in the file says so. |
| `pack.asm` | Pack/encrypt core (the `do_pack`/`do_unpack` reached from `encrypt`/`decrypt`, for both single files and archives): recursive directory walk, tar emission, bare single-file streaming, the GCM "sink", the XPRESS compression framing layer, the size-based compression default (`apply_auto_compress`), input-size pre-sum (`size_node` takes each file's size straight from the directory enumeration's `WIN32_FIND_DATA` and only recurses into sub-directories — no per-file open — so a 76k-file tree is walked in one pass; it also bumps the GUI's `g_scan_files`/`g_scan_bytes` counters live), name sanitization, and traversal-safe extraction. |
| `compress.asm` | Thin wrappers over the Windows Compression API (`CreateCompressor`/`Compress`, Cabinet.dll) for XPRESS block **compression**. Decompression is not here: it needs a handle per open stream rather than one in a global, because two entries can be read at once, so it lives in `estream.asm` with the rest of the entry decoder. |
| `zip.asm` | Encrypted-ZIP **writer** reached from `zip`: recursive input walk, per-entry DEFLATE compression (store fallback), fresh-salt PBKDF2 key derivation, AES-256-CTR encryption with HMAC-SHA1 authentication, and ZIP local/central/EOCD emission with automatic ZIP64. AE-2. An interoperability compromise, not the hardened `.mrk` path. |
| `deflate.asm` | Raw DEFLATE (RFC 1951) **encoder** used by the ZIP writer: per-32-KiB-chunk fixed-Huffman blocks with an LZ77 hash-chain matcher. Produces a standard bitstream any inflate (ours, zlib, 7-Zip) decodes; the caller stores any entry it fails to shrink. |
| `unzip.asm` | **Streaming** encrypted-ZIP (WinZip AES-128/192/256) extractor reached from `unzip` (positioned reads, bounded memory; stored entries stream to `OUTPUT.part` then rename): EOCD/central-directory/local-header parsing (incl. ZIP64), AES extra-field (0x9901) handling, per-entry PBKDF2 key derivation, password-verify, HMAC-SHA1 authentication, AES-256-CTR decryption, DEFLATE/STORE output, CRC-32 check, and traversal-safe writing (reuses `sanitize_name`/`create_parents`). Also exports `zip_is_encrypted` — a self-contained central-directory probe (method 99 / encrypted-bit, no allocation) used by the CLI parser and the GUI to decide whether a password is needed at all. And exports `zip_entry_to_mem`, which is the same reader with its output diverted: setting `g_uz_mem` redirects all three of its sinks (the AES-stored `.part` loop, the unencrypted stored loop, and the whole-buffer deflate write) into a caller-owned buffer, so dragging an entry out of a zip does not need a second WinZip-AES implementation. The buffer is the `.part` file - it is sized from the entry's declared length and capped there, so an archive that lies about a size is refused rather than overflowing, and a failed entry is wiped and reported rather than handed back. |
| `crc32.asm` | Table-driven IEEE CRC-32 (poly 0xEDB88320) — ZIP entry integrity. (The SSE4.2 `crc32` instruction is CRC-32**C**, a different polynomial, so it can't be used.) |
| `sha1.asm` | Software SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1 — used only for WinZip-AES key derivation and entry authentication. |
| `inflate.asm` | Hand-written raw DEFLATE (RFC 1951) decompressor — a structural port of Mark Adler's puff.c (per-bit canonical-Huffman decode, 32 KiB LZ77 window). Inflates ZIP entries after they pass HMAC authentication. |
| `progress.asm` | In-place console progress bar (`progress_begin`/`add`/`done`) for long streaming operations; renders to stderr, suppressed when stderr is not a console; also exposes a cooperative cancel flag, the overall live counters and the per-input counters (`g_cur_input`/`g_file_done`/`g_file_total`) the GUI reads for its per-file bars. |
| `secdesk.asm` | Private-desktop primitives for password entry: `secdesk_open` (`CreateDesktopW`), `secdesk_enter` (`SetThreadDesktop` + `SwitchDesktop`, saving both the thread's previous desktop and the previously active input desktop), `secdesk_leave` and `secdesk_close`. A window must be created on the desktop its thread is attached to, and `SetThreadDesktop` fails for a thread that already owns windows or hooks, so the prompt runs on a dedicated thread that attaches before creating anything — the GUI's own thread never leaves the interactive desktop. Debug builds add a `secdesk` smoke-test verb. See §11 and §14.2. |
| `gui.asm` | The shipping entry point `wstart` (CLI-vs-GUI dispatch, see §11) and the Win32 GUI front-end: command-line-fed inputs, up-front mode classification, the encrypt dialog (a common-root breadcrumb chip, a headerless non-selectable list-view of the inputs with icon/name/size/per-file-progress columns, and a single label-less password field with show/hide, a placeholder cue and a validation underline) and the decrypt dialog (suggested destination + folder picker, password), all over a threaded progress bar in a borderless **dark** (#20201F) centred window with accent owner-draw buttons and an Exit button. A **right-drag** gets none of that: it opens a small progress window instead (heading, destination, bar, the entry being worked on, an N-of-M count, and the action log folded away behind Details), closes everything by itself when the job succeeds, and halts with the details out and the error showing when it does not. That window is one owner-draw backdrop with controls on top of it, and the backdrop MUST stay at `HWND_BOTTOM` - it covers the whole client, so anything it sits above it erases the moment it repaints, and nothing invalidates those controls afterwards. Its state colour (accent working, invalid red failed, warning amber cancelled) is computed once per paint and shared by the stripe, the frame, the heading and the bar. Reuses the exact crypto by calling `do_encrypt`/`do_decrypt`. See §11. |
| `estream.asm` | The source side of dragging entries **out** of an open container (`docs/DRAG_OUT.md`): hand-written `IDataObject` + `IEnumFORMATETC` offering `CFSTR_FILEDESCRIPTORW` and `CFSTR_FILECONTENTS`, an `IDropSource`, and TWO `IStream` implementations over one entry - because the two container kinds want opposite shapes. A `.mrk` entry is **streamed**: `es_create` opens its own handle, its own decompressor and its own GCM context (`entry_stream_open` takes the key as a parameter for exactly this, since the drag is constructed while the mouse is still down and read minutes later), then peels back three framing layers as the target reads - ciphertext to plaintext, XPRESS frames, tar header and padding - and takes the GCM verdict at the end of the ENTRY rather than the end of the content, so an entry whose last content byte was already delivered still fails. A **zip** entry is instead run to completion into memory by `unzip.asm`'s reader and served from a buffer, because that reader never exposes plaintext it has not authenticated and a streaming one could not keep the promise. The object copies everything it needs at drag time - the container path, the key, each entry's fixed part and its name - so a listing rebuilt underneath it cannot leave it describing something that has moved; both buffers are wiped on release. Under `TEST_IO` it also carries the `estream` and `dataobj` verbs `tests/estreamtest.ps1` drives, which is how everything but the five lines of `IDropSource` is covered by a test. |
| `selftest.asm` | Embedded RFC/NIST vectors and the `selftest` driver. |
| `log.asm` | Plain-text audit log (no admin rights, kernel32 only). `dispatch` (CLI) and `on_done` (GUI) call `log_result(name, exitcode)` after every operation; it classifies the outcome (success → `INFO`, auth failure → `WARN`, other errors → `ERROR`), applies the `--log` verbosity level (`g_cfg_loglevel`), formats one UTF-8 line `YYYY-MM-DD HH:MM:SS  LEVEL  command: result`, and appends it to a log file (`CreateFileW` with `FILE_APPEND_DATA`, opened per event). The default file is `%LOCALAPPDATA%\Myrkr\myrkr.log` (resolved via `GetEnvironmentVariableW` + `CreateDirectoryW`); `--log-file PATH` (`g_cfg_logfile`) overrides it. Off by default (level `none`); opt in with `--log LEVEL`; input/output paths are appended only at `debug`. |
| `ramlog.asm` | The **in-RAM action log** the window's statistics line opens — not `log.asm`, which is a one-line-per-command audit trail on disk. This keeps every byte the tool printed during one operation, in memory only, and is uncapped by decision: a user who asks what happened to 40,000 files gets the answer for all 40,000. It is filled by a **tee** in `console.asm`'s `write_handle`, so every refusal reason lands in it in the tool's own wording without `pack.asm` or `unzip.asm` being threaded with logging calls — an exit code cannot say "that name is already in the archive", and that sentence exists as text on the print path and nowhere else. `rlog_begin` (UI thread, before a worker starts) is what arms capture, so a CLI run keeps nothing. The bytes then arrive on the **worker** thread and are read on the **UI** thread when the viewer opens, possibly mid-job, so nothing is ever freed while capturing: 64 KiB chunks are allocated forward and never moved, and `g_rl_total` — the only published length — is advanced *after* the bytes behind it are written, so a reader always sees a valid prefix and never a byte that is not there. That is the whole synchronisation story; there is no lock. `rlog_flatten` returns one contiguous copy for the viewer and the clipboard, and says (return 2) when an allocation failed rather than trimming the tail silently. Chunks come from `mem_alloc`/`mem_free`, so release wipes them — this buffer is full of the user's file paths. The chunk seam is the one part that can be wrong invisibly, so `selftest.asm` appends a vector deliberately larger than a chunk and checks every byte of it, with the first piece *printed* rather than appended so the tee itself is covered too. Since 1.0.47 it also exposes `rlog_added` / `rlog_extracted`, called once per entry from `idx_add`, `zip_emit_file`, `uz_entry_done` and `unpack_entry` — the four points where an entry is COMMITTED. That deliberately reverses the original "logging stays GUI-side" rule: the tee carries outcomes, and no outcome names the files it covers, so the only honest place to record a name is where the entry was written. Deriving the list afterwards would claim files were written that were never observed being written. The CLI pays one compare against `g_rl_on` per entry and prints nothing. |
| `shellext.asm` | **Not part of `myrkr.exe`** — the whole of `myrkrshell.dll` (§2, §15). An in-process COM server implementing `IShellExtInit` + `IContextMenu` so Explorer offers a Myrkr verb both when a selection is **right-clicked** and when it is **right-dragged onto a folder or drive**. The two menus word themselves differently, because they do different jobs: a right-click says "Open with Myrkr", since that verb opens the window and decides nothing; a right-drag says **Encrypt** or **Decrypt/extract**, because it has already been told what and where and acts on release. Two drag labels and not three - a `.mrk` and a `.zip` differ in how they are opened, not in what is being asked for - and neither repeats the product name, which the menu icon now carries. One DLL serves both registrations (`ContextMenuHandlers` and `DragDropHandlers`) and tells them apart by `pidlFolder`: non-NULL is a drop target and becomes `--to`, NULL is a right-click and the output lands beside the source. Either way the WHOLE selection reaches one window — the thing a registry `%1` verb cannot do, since it substitutes one path per launch. `Initialize` captures the drop target from `pidlFolder` and copies the dragged paths out of the data object's `CF_HDROP`; `QueryContextMenu` classifies the selection three ways and both names and places the item from that: every item a `.mrk` → "Myrkr decrypt" at index 0 with a separator under it; every item a `.zip` → "Myrkr extract" at the first separator, i.e. directly below Explorer's own "Extract…", where it reads as a second extraction choice; anything else, mixed containers included → "Myrkr encrypt", again at the top. Placement depends on which menu it is: a shortcut menu has a region for third-party verbs and `indexMenu` points at it, so the item goes there untouched; the drag menu has no such region — by the time a `DragDropHandler` is queried it already holds Copy/Move/Create-shortcuts, a separator and Cancel — so that case is positioned by hand, and the reasoning is recorded at the call site. `InvokeCommand` builds `"<dir>\myrkr.exe" "<file>"... --to "<target>"` and calls `CreateProcessW`. Three constraints shape all of it: it runs **inside `explorer.exe`**, so every pointer the shell passes is bounds-checked and every refusal is fail-closed (decline the verb rather than do part of the job); it **never does the work** — no crypto, no file I/O, no password handling, because that would run outside the private desktop and inside a process Myrkr does not own; and it **cannot use `FRAME_PROLOG`/`FRAME_EPILOG`**, which need the canary and software shadow stack that the exe's startup creates and a DLL has neither of. Plain prologues throughout — a deliberate exception to §9, and the reason the file is kept small enough to audit by eye. The menu item carries the **Myrkr icon**, which is why `myrkrshell.rc` has one `BITMAP` in it: `MENUITEMINFO.hbmpItem` takes an HBITMAP and not an HICON, and converting one to the other at runtime would mean linking gdi32 into a DLL that lives inside Explorer. So the conversion happens at author time (`tools/make_menu_bmp.py`, which premultiplies the alpha a menu needs to draw it with transparency at all) and the DLL just calls `LoadImageW`, which is user32 and already imported — the import list stays at four libraries. The handle is cached for the life of the DLL and deliberately **not** freed: a menu owns nothing, the caller is never told when Explorer destroys it, and the only remaining place to release it would be `DLL_PROCESS_DETACH`, i.e. calling gdi32 under the loader lock inside `explorer.exe`. A kilobyte is the cheaper of the two. |
| `redteam.asm` | Fault-injection self-test (instrumented `build.cmd dbg` only; gated by `DBG_TRACE`, absent from the shipping binary). The `redteam <case>` command deliberately commits one memory-safety violation per invocation so the hardening controls can be measured: each case fastfails with its specific `FF_*` code (stack canary, software shadow stack, DLPV, integer overflow, bounds, type magic, tagged-heap canary) or, for IAT lockdown, an access violation. Driven by `tests/redteam.py`; see `docs/security-testing.md`. |

The `tests/` directory holds the security-control test suite
(`docs/security-testing.md`): `secsuite.py` (adversarial crypto/input tests
against the shipping binary), `redteam.py` (memory-safety fault injection against
the instrumented build), and `run.ps1` to run both phases.

---

## 4. Container format (Myrkr — design generation v4, on-disk version 8)

An 80-byte header, used **verbatim as GCM additional authenticated data (AAD)**,
followed by ciphertext, a 16-byte tag, and the inventory (§4.1):

| off | size | field |
|----:|-----:|-------|
| 0 | 4 | magic `"MYRK"` (0x4B52594D LE) |
| 4 | 4 | version: the writer emits `HDR_VERSION` (8); readers accept `HDR_VERSION_MIN`..`HDR_VERSION` (6..8) through one gate, `hdr_version_ok`. 7 = 6 byte-for-byte; 8 added the segment to the entry AAD |
| 8 | 4 | Argon2id t_cost (passes) |
| 12 | 4 | Argon2id m_cost (KiB) |
| 16 | 1 | parallelism / lanes (=1) |
| 17 | 1 | archive flag (0 = single file, 1 = tar archive) |
| 18 | 1 | compression (0 = store, 1 = XPRESS) |
| 19 | 1 | `seg_shift`: 0 = entries not segmented, else segment size = `1 << seg_shift` (v8; was reserved-as-0, which is what every older container carries there). Validated by `seg_bytes_from_hdr` — an unvalidated shift of 64 would quietly compute `1 << 0` |
| 20 | 32 | salt (CSPRNG) |
| 52 | 12 | container id (CSPRNG) - held the GCM nonce up to v3 |
| 64 | 16 | key-check value = `SHA-256(key)[0..15]` |

A container is at least **96 bytes** — the header alone, holding nothing.

The upper bound is set by AES-GCM, and it is a hard mathematical limit rather
than a tuning choice. A single GCM stream can encrypt at most **`MAX_PLAINTEXT_SIZE`
= 68,719,476,704 bytes**, which is 32 bytes short of 64 GiB (the NIST SP800-38D
ceiling of 2³⁹ − 256 *bits* of plaintext per key). One byte past it, the cipher's
internal 32-bit block counter wraps, the keystream repeats, and confidentiality
is lost — so this is enforced, not advised.

Two design choices keep that ceiling from limiting real use:

- **Per-entry streams (v4).** Every entry in an archive is its own GCM stream, so
  the 64 GiB limit bounds a *single entry*, never the container. An archive of any
  total size is fine; only one individual file larger than the limit is a problem.
- **Segments (v8, default since 1.0.83).** A large entry is sliced into segments,
  each its own stream, so the limit bounds a *segment* rather than the entry.
  With segments on, a single file of any size encrypts — field-proven on a
  155.4 GB entry.

The `encrypt` pre-flight therefore refuses an over-large input only when
segmentation is off, and only when a *single* input exceeds the bound (§14.2). In
archive mode it weighs each entry's tar framing, not the raw file, since the
framing is what the stream actually seals.

### The hard limits, in one place

Every fixed ceiling in the format is collected here, because they are otherwise
scattered across the sections that introduce them. Two things are true of all of
them. First, **the crypto-derived ones are not preferences** — the GCM plaintext
limit and the index-revision limit exist because crossing them would repeat a
keystream or reuse a nonce, which silently destroys confidentiality; they are the
reason several of these caps exist at all. Second, **every limit fails closed**:
reaching one produces a refusal with a clear exit code, never a silent
truncation, wrap, or corrupt output. A container that would have been unsafe is
never written.

| Limit | Value | Why it exists | At the limit |
|---|---|---|---|
| Plaintext per GCM stream | 68,719,476,704 B (~64 GiB, `MAX_PLAINTEXT_SIZE`) | AES-GCM's 32-bit block counter wraps past it and the keystream repeats | `encrypt` refuses an over-large single input when unsegmented; segments remove the limit in practice |
| Segment size | 4 KiB … 32 GiB (`SEG_SHIFT_MIN`=12 … `SEG_SHIFT_MAX`=35; default 4 GiB) | Each segment must stay under the GCM ceiling by construction | An out-of-range `seg_shift` is rejected before anything derives from it (`seg_bytes_from_hdr`) |
| Inventory size | 2047 MiB (`IDX_MAX_BYTES`, ≈17 M files at 85-char paths) | Kept just under 2³¹ so no `imm32` bound test can sign-extend and invert | `idx_add` fails the pack; nothing is dropped silently (§4.1) |
| In-place rewrites of one container | 2³² − 1 (`IDX_REV_MAX`, ≈4.29 billion) | The index nonce is `IDX_NONCE_BASE + revision`; wrapping would reuse revision 0's nonce | `idx_rev_bump` refuses the rewrite; a repack draws a fresh key and resets it |
| Parts in a volume set | 4096 (`VOL_MAX_PARTS`) | Bounds the reassembly bookkeeping | A split needing more parts is refused before writing (§14.4) |
| Filesystem path | 32,767 UTF-16 units (`MAX_PATH_CHARS`) | The Windows extended-length maximum; where a file is read from or written to (§7) | A longer path is rejected, not truncated |
| Stored entry name | 100 B per component, 256 B total (ustar name + prefix) | The POSIX ustar header fields; there is no long-name (PAX/LongLink) extension | The entry is refused (`EXIT_CORRUPT`, "name too long") rather than stored under a lossy name |
| CLI file inputs | 255 (`MAX_ARGS` − 1) | Fixed argument-vector width | Extra inputs beyond the cap are not taken |
| Password | 1024 UTF-8 bytes (`MAX_PASSWORD_BYTES`) | Fixed, locked secret buffer | A longer password is rejected at entry |

The two path limits are different measurements and do not contradict. The
**filesystem** limit governs where files live on disk — the absolute path Myrkr
reads from or extracts to, up to the full Windows maximum (§7). The **stored
entry name** is the path *relative to the encryption root* that ustar records
inside the container, and ustar caps it at 100 bytes per component and 256 bytes
overall. In normal use the relative names are short even when the absolute paths
are long, so the ustar cap is rarely met; a genuinely deep tree *within* the
encrypted set is the case that reaches it, and it is refused rather than
truncated.

The two nonce-driven caps — the GCM plaintext limit and the revision limit — are
the load-bearing ones: they are not about resource use but about never letting the
same keystream or nonce be produced twice under one key. The rest bound memory or
bookkeeping, and are set generously enough that ordinary use never meets them (a
2047 MiB *listing* alone is roughly seventeen million files).

**Why the KDF parameters live in the header:** decrypt and unpack must
reconstruct the exact key, so the cost parameters travel with the ciphertext.
This makes containers self-describing and forward-compatible — raising the
default memory cost later does not break old files.

**Why the whole header is AAD:** binding magic, version, KDF parameters, salt,
nonce, the archive/compression flags *and the key-check value* into the GCM tag
means none of them can be tampered with. An attacker cannot flip the
compression flag, downgrade the memory cost, or alter the KCV without failing
authentication.

**The key-check value (KCV), version 2.** After deriving the key, the encoder
stores `SHA-256(key)` truncated to 16 bytes in the header. On decrypt/unpack the
decoder re-derives the key and compares this value *immediately* — before
streaming or decompressing any data. The effects:

- **Fast wrong-password rejection.** A wrong password yields a wrong key whose
  KCV won't match, so the operation fails after a single Argon2 derivation
  (~0.7 s) instead of reading and GHASH-ing the entire file. Measured: a wrong
  password on a 9.4 GB container fails in **738 ms** rather than ~30 s. The KDF
  cost is unavoidable (that's the point of a slow KDF); only the wasted full-file
  pass is eliminated.
- **Key commitment.** Plain AES-GCM is not key-committing — a ciphertext can be
  made to decrypt under two different keys. Publishing `SHA-256(key)` commits the
  container to one key, closing that class of partitioning/confused-decryption
  issues. It leaks nothing useful: it's a one-way hash of a high-entropy key, and
  brute-forcing still pays the full Argon2 cost per guess, so the KCV gives an
  attacker no speed-up.

Validation on read: magic, `version == 4`, `1 ≤ t ≤ 16`,
`8192 ≤ m_KiB ≤ 4 GiB`, `p == 1`, archive flag ∈ {0,1}, compression ∈ {0,1},
file size ≥ 96, KCV match, and every length computation is overflow-checked.
The tag is still verified **before any plaintext byte is released**
(decrypt-then-rename); the KCV is an early-out check layered in front of it, not
a replacement for it. (Versions 1-3 are rejected; re-encrypt them with this
build.)

### 4.1 Entries and the inventory

Every **entry** - one file, or one directory header - is its own AES-GCM stream
with its own nonce and its own tag, and the inventory records where each one
lives. The container is one opaque run of ciphertext with **no framing in it**:
the extents exist only inside the encrypted index, so an attacker without the
password still sees a single blob and learns neither the file count nor any
individual size.

```
[80-byte header][entry 0][entry 1]...[entry N-1]
                [index ciphertext][index tag 16][trailer 32]
```

Each entry is its ciphertext followed by its own 16-byte tag; the entry's
plaintext is a ustar header, the content, and the padding to 512 - compressed in
framed blocks when compression is on. A single-file container is the same thing
with one entry whose plaintext is the raw file.

**Nonces are counters, not random values.** Entry *i* uses *i*+1; the index uses
0; all are 96-bit little-endian. A counter cannot collide with itself, where
96-bit random values merely probably do not - and because the key is fresh per
container (fresh salt), a counter is safe here in a way it would not be if keys
were reused. Nothing is stored: the value *is* the position, which is also why
the header's old nonce field became the container id.

The corollary used to be an absolute rule — *never append newly encrypted data
to an existing container under its existing key* — because an ordinal is a nonce
and nothing recorded which ones had been spent. Deleting does not renumber the
survivors (their tags are bound to the ordinal they were sealed with), so after
deleting the highest entry, "one past the highest survivor" names an ordinal
that has **already been used under this key**. Recomputing it would have been
nonce reuse, which is the one mistake in this design that cannot be recovered
from.

**v6 records it instead.** The trailer carries `IDXT_next`, the next ordinal to
issue, and it only ever moves up: a delete leaves it alone, an add advances it
by the number of entries added. That is what makes appending to an existing
container safe without a fresh key, and it is the whole reason the trailer grew
from 24 bytes to 32. Overwriting an entry in place with random bytes still
consumes no counter and is still fine.

The counter sits inside the index's AAD, so it is authenticated — a tampered
value fails the tag rather than steering the writer onto a spent nonce. And
because an authenticated-but-wrong value would still be fatal, `idx_auth`
refuses any container whose counter is at or below an ordinal the index still
lists. That check exists to catch *our* bugs; the AAD already covers an
attacker's.

**The inventory has a ceiling, and exceeding it is a refusal** (1.0.51).
`IDX_MAX_BYTES` is 2047 MiB since 1.0.81 (64 MiB before it) — an entry costs
`IDXE_FIXED` **plus its path**, so roughly 17 million files at an 85-character
path — and `idx_add` fails the pack when it is reached. The buffer behind it is
*reserved* address space, committed only as far as the index reaches
(`idx_buf_ensure`/`idx_buf_commit`), so the ceiling costs nothing until used —
and it stays just under 2³¹ because an `imm32` at 2³¹ sign-extends and inverts
every unsigned bound test against it. `tests/indexfulltest.ps1` reaches the
refusal with forty files via `MYRKR_DBG_IDXMAX`; `tests/scaletest.ps1` proved a
real 500,000-entry container end to end. It used to set `IDXF_TRUNCATED` and drop the entry while
`pack_node` went on writing it into the payload, on the belief that "what is lost
is a preview, not data". It is not a preview: unpack is driven entirely by this
table, so a dropped entry has no offset, ordinal or name recorded anywhere a
reader consults, and its ciphertext sits in the container unreachable. Reported
2026-08-12 against 1.0.50 — 76,286 files in, 16,780 out, no error. `IDXF_TRUNCATED`
survives for reading older containers and for the zip-browse listing, where a
short listing costs nothing because the zip itself is untouched.

**The index revision has a ceiling** (`IDX_REV_MAX`, 1.0.50). The index's nonce
is `IDX_NONCE_BASE + IDXT_rev`, and unlike every other counter here `IDXT_rev` is
32 bits — so the 4294967296th rewrite of one container would roll it back to 0
and encrypt a different index under revision 0's nonce. Astronomical is not the
same as impossible, and the failure is the unrecoverable one, so `idx_rev_bump`
refuses at the ceiling instead. It is the single point every rewrite path goes
through, and the check is at the *increment*: by the time a revision is being
turned into a nonce, a wrapped one reads as 0, which is exactly what a freshly
packed container legitimately holds.

Refusing costs the container its last possible revision. Repacking resets it,
because a repack draws a fresh salt and therefore a fresh key, and a fresh key
makes the whole nonce space available again.

The delete path claims its revision *before* it overwrites anything, not at the
rewrite: by then it has already overwritten the dropped entries with random and
slid the survivors down, and refusing at that point would leave a container whose
payload has been rewritten and whose index has not. Claiming one and then failing
is harmless — a skipped revision is a nonce never used, and `g_idxrev` is re-read
from the trailer next time the container is opened. Only reuse is unsafe, and
this errs the other way.

**AAD binds an entry to its position:** header || u64 ordinal. A reordered,
duplicated or spliced-in entry fails its tag rather than decrypting to something
plausible. The index's AAD is header || trailer.

What this buys, in the order the reasons actually matter:

- **Random access.** One file can be decrypted *and authenticated* without
  reading the rest. A tag covers a whole stream, so authenticated random access
  is only possible if the streams are per-entry - which is why a future split
  into volumes must sit *below* the crypto, slicing the ciphertext run rather
  than becoming the streams themselves.
- **No 64 GiB ceiling on the container.** AES-GCM's limit is per invocation, so
  it now bounds one entry rather than the whole archive; the pre-flight weighs
  the largest single input, not the total. A file larger than that still needs
  chunking within the entry.
- **Containment.** A damaged entry costs that entry, not the archive. Worth
  having, but a consequence rather than the reason: it is containment, not
  correction, and a bad sector still loses that file.

### 4.2 Removing an entry

One operation, whatever the container's size: **overwrite the entry where it
lies with random, then close the gap.**

**A removal that will be slow says so first.** The survivors are moved down
over the hole, so on a large archive it is a long synchronous write on the UI
thread and the window stops answering. Past 100 MiB `confirm_slow_remove` asks
before anything is touched, and cancelling costs nothing because nothing has
been written yet. Below that the question would be noise, and a dialog people
learn to click through is worse than no dialog.

**Extraction can be narrowed to a selection.** Marked rows extract alone;
marking nothing still extracts everything, which is what the button said before
selections existed and what it still says when none is made. The marks live in
a list of NAMES outside the index (`pick_add`/`pick_has`), because `do_unpack`
calls `idx_auth`, which re-reads and decrypts the table over `g_idxbuf` — a flag
bit set on an entry is gone by the time the extraction loop looks for it, and
the symptom was a selection that produced no files at all while every part of
the UI said the right thing. Names rather than positions or ordinals: a position
is meaningless after a delete, and a zip entry has no ordinal.

**Removing a directory removes what is in it.** `idx_mark_dropped` is the single
place both the `delete` verb and the GUI's Remove mark through, and when the
named entry is a directory it also marks every entry whose name begins with that
name followed by `/`. The separator is what keeps `tree/secret` from taking
`tree/secretive` with it. Marking only the directory's own entry left every file
beneath it in the container — in the index and in the payload, under the same
key — and a full decrypt handed them all back. Nothing on screen said so: a
child whose parent is gone can never be expanded into view, so the listing
looked exactly like a successful delete. The only thing that reported the truth
was an extract, which is why the tests for this assert on extract output rather
than on what `list` prints.

The overwrite is what makes the removal unrecoverable, and it is the step that
cannot be skipped. Rewriting the container to a new file and renaming - the
obvious implementation, and the one this replaced - releases the *original's*
blocks with their contents intact, still encrypted under a key the password
still derives. A recovery tool and the password get the deleted file back.
Overwriting in place does not have that hole. Random, never zeros: a run of
zeros advertises exactly where something used to be and how big it was, where
random is indistinguishable from the ciphertext around it.

Closing the gap is then almost free, and it is what per-entry encryption bought.
An entry's tag does not depend on where it sits: the nonce is (ordinal+1,
segment), the AAD is header ‖ ordinal (‖ segment from v8), and GHASH runs over
the AAD and the ciphertext bytes - the offset appears nowhere in any of it, and
the segment number is entry-relative, so the argument survives segmentation
unchanged. So the survivors'
ciphertext is simply **moved** down over the hole and their extents updated in
the index. No decryption, no re-encryption, no fresh key; a byte copy of
whatever followed the hole. The move is front to back and every destination is
at or below its source, so a forward copy can never overwrite bytes it has not
read yet - and an index whose offsets are not ascending is refused rather than
guessed at.

Only the index is re-encrypted, under the next revision (§4.1).

One caveat belongs to the storage, not the format: on an SSD, overwriting a
logical sector need not overwrite the physical cell, because wear-levelling may
remap it and leave the old copy readable by firmware-level tools.

Trailer (little-endian):

| off | size | field |
|----:|-----:|-------|
| 0 | 4 | flags — bit 0: the listing is incomplete |
| 4 | 4 | entry count |
| 8 | 8 | index ciphertext bytes (tag excluded) |
| 16 | 4 | magic `"MIDX"` |
| 20 | 4 | index revision — the index nonce is `2⁶³ + rev`, +1 per rewrite, refused at `IDX_REV_MAX` (§4.1) |
| 24 | 8 | next ordinal to issue — the counter that makes `add` safe: ordinals are nonces, deletes do not renumber, so the floor only ever rises |

Each entry is `u64 size`, `u64 offset` (from the payload run's start), `u64
stored` (ciphertext + every tag), `u64 ordinal` (the counter it was **sealed**
with — its nonce and AAD, not its position), `u32 flags` (bit 0: directory),
`u32 name length`, then that many UTF-8 bytes — `IDXE_FIXED` = 40 plus the name.
The names are the tar entry names, so a listing and an extraction agree exactly.

*(This table previously showed the v3 layout — size/flags/namelen only, trailer
ending in "reserved" — which lacks the offset, stored length and ordinal that
per-entry extraction is driven by, and the two trailer fields the nonce-safety
rules live in. The canonical description had drifted from the format exactly the
way `CONTAINER_HDR` had before 1.0.70, found the same way: by auditing.)*

**Why the index is at the end, not after the header.** Packing is a single
streaming pass, and the entries are only all known once the last one has been
written. A length in the header would need either a second walk of the tree —
which can disagree with the first — or a rewind of a file being written
sequentially. Recording entries *as they are packed* means the listing cannot
describe anything the container does not hold. It also leaves the payload
stream byte-for-byte where v2 had it.

**Nonce separation.** The index nonce is the payload nonce with the top bit of
its first byte flipped. Two GCM streams under one key must never share a nonce;
deriving one from the other makes them distinct by construction rather than by
luck, and saves storing (and having to authenticate) a second random value.

**AAD.** The index stream's AAD is the header followed by the trailer, so the
entry count, the length, the flags and the ordinal counter are all covered —
tampering with any of them fails the tag rather than mis-steering the reader.
The counter is the one that would matter most: it decides which nonce the next
appended entry is sealed with.

**Every reader authenticates it.** `decrypt` and `verify` have no use for the
entries, but a container is one object: a changed byte anywhere in it must be a
failure. Without that check, flipping a bit inside the inventory decrypted
cleanly and said nothing — which the tamper suite caught at 43/44.

**Bounds.** The listing is capped at 2 MiB (roughly 50,000 entries). Past it the
trailer's truncated bit is set and the container remains perfectly valid; what
is lost is a preview, not data.

---

## 5. Cryptographic design

### 5.1 Key derivation — Argon2id (RFC 9106)

- **Why Argon2id:** it is the PHC competition winner and the modern standard for
  password-based key derivation. The "id" variant is hybrid — data-independent
  addressing on the first half-pass (resisting side-channel leakage of the
  password) and data-dependent addressing thereafter (resisting time-memory
  trade-off / GPU attacks). RFC 9106 explicitly recommends Argon2id as the
  default.
- **Parameters:** default t=3 passes, m=512 MiB, p=1 lane, 32-byte output.
  512 MiB is deliberately large — memory hardness is what defeats GPU/ASIC
  cracking rigs, so we spend memory generously. The `bench` command measures
  one derivation on the target CPU; `-m`/`-t` tune within enforced bounds.
- **Performance:** the BLAKE2b-based `G` function was ported to three
  implementations and selected at runtime by CPU capability. Measured on the
  development machine for one derivation at the default size:
  scalar ≈ 620 ms → SSE2 ≈ 438 ms → **AVX2 ≈ 335 ms**. With AVX2 the 512 MiB
  default lands around 700 ms, inside the 500–1000 ms target band (slow enough
  to punish guessing, fast enough for interactive use).

### 5.2 Cipher — AES-256-GCM

- **Why AES-256-GCM:** GCM is an AEAD construction (authenticated encryption
  with associated data), so confidentiality and integrity come from one pass.
  AES-256 gives a 256-bit key matching the 256-bit derived material, and both
  halves run on dedicated instructions.
- **Implementation:** key schedule and CTR-mode encryption use AES-NI
  (`aeskeygenassist`, `aesenc`/`aesenclast`); the GHASH universal hash uses
  PCLMULQDQ carry-less multiplication in the byte-reflected domain. Both are
  constant-time in hardware.
- **Streaming:** GCM is exposed as a context API (`gcm_init`/`gcm_aad`/
  `gcm_crypt`/`gcm_final`) over a caller-allocated 336-byte context, and data
  is processed in 1 MiB chunks. This bounds memory use regardless of file size,
  so a 26 GB file encrypts in constant RAM.
- **Nonce strategy:** a fresh 32-byte salt per file yields a fresh key per file,
  so a random 96-bit nonce never collides on a reused (key, nonce) pair — the
  one catastrophic failure mode of GCM is structurally avoided.
- **Tag handling:** the 16-byte tag is compared in constant time (`ct_memcmp`)
  and verified before any plaintext is exposed.

### 5.3 Hashing — SHA-256 (SHA-NI)

The `hash` command computes SHA-256 using the SHA-NI message-schedule and round
instructions (`sha256msg1`/`sha256msg2`/`sha256rnds2`). Fast, constant-time, no
tables. A single file prints `<sha256>  <path>` (sha256sum-style); a **folder**
is walked recursively (the same `FindFirstFileW` recursion `do_pack` uses, but
seeded with an empty relative path so the folder name is not prefixed) and every
file is printed with its path **relative to the folder** (forward-slash
separated). The `--json` flag (parsed in `collect_options`, stored in
`g_cfg_json`) switches the output to a JSON array of `{"sha256","path"}` objects;
paths are JSON-escaped and progress bars are suppressed so stdout stays valid
JSON. Files follow filesystem-enumeration order; the first unreadable file
aborts with `EXIT_IO`. The result is written to **stdout** (so it redirects and
pipes), or directly to a file with `-o OUTFILE` — implemented by opening the file
and pointing `g_hstdout` at it for the duration of the command, so the existing
`print_a`/`print_hex` paths write the file unchanged; errors and the progress bar
stay on stderr.

Redirection works because `con_attach_parent` captures the shell-provided
stdout/stderr **before** `AttachConsole(ATTACH_PARENT_PROCESS)` (which would
otherwise replace them with the console's handles) and `con_init` keeps the
captured handle for any stream that `GetFileType` reports as a disk file or pipe.
This applies to every command, not just `hash`.

### 5.4 Randomness — CSPRNG

`BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` is the OS-vetted source;
its output is XOR-mixed with `RDSEED` (the CPU's hardware entropy source) when
the CPU advertises it. XOR-mixing two independent sources is safe — the result
is at least as strong as the stronger source. **The RNG fails closed:** if the
OS call fails, key derivation aborts rather than falling back to anything
weaker.

### 5.5 CPU gate

At startup, CPUID verifies AES-NI, PCLMULQDQ and SSE4.1 (plus SHA-NI for the
`hash` command). On an unsupported CPU the program prints a message and exits
with code 6 rather than attempting a slow or non-constant-time software
fallback.

---

## 6. Archiving and compression

When `encrypt` is given multiple inputs or a single directory it bundles them
into one encrypted container, and `decrypt` extracts such a container back to a
tree (see §10 — there is no separate `pack`/`unpack` command; this is the
archive path of encrypt/decrypt). The design layers cleanly:

```
inputs ──► ustar tar stream ──► [optional XPRESS framing] ──► GCM ──► container
```

### 6.1 Why in-process tar

The brief required combining multiple inputs into one encrypted output. Rather
than shell out to an external archiver (a dependency and an attack surface), the
tool builds a **ustar (POSIX tar)** stream in process. ustar is a trivially
simple, universally understood format — 512-byte headers with octal fields and
a checksum — which keeps the assembly implementation small and auditable. The
header layout was validated byte-for-byte against GNU `tar` before use.

Directories are walked recursively with `FindFirstFileW`/`FindNextFileW`; the
tree, including empty directories, is reproduced on extraction.

### 6.2 Large-member support — GNU base-256

Classic ustar stores a file's size as 11 octal digits, capping members at
8 GiB − 1. The intended workloads include multi-gigabyte AI model checkpoints
(9.4 GB and 26 GB were tested), so the writer and parser implement the **GNU
base-256 extension**: when a size does not fit in octal, the field's first byte
is `0x80` and the remaining bytes hold the big-endian binary magnitude. This is
the same format GNU tar itself emits, so archives remain interoperable, and
members are effectively unbounded. This was proven end-to-end: a 9.4 GB
checkpoint packed and unpacked byte-identical.

### 6.3 Why XPRESS, and the size-based default

The compression requirement was scoped as "favor speed over size; don't burn
time on this step." After evaluating the options:

- **Store (no compression)** — fastest, no dependency.
- **XPRESS** — the Windows Compression API's light LZ77 codec (inbox via
  Cabinet.dll). Fast, no third-party code.
- Heavier codecs (LZMS, etc.) were rejected as too slow for the stated goal.

XPRESS was implemented as an optional layer and benchmarked. On a 9.4 GB model
checkpoint (high-entropy, essentially incompressible — the realistic workload):

| mode | pack time | output size |
|---|---|---|
| `--store` | 26.1 s | 10,025,480,784 |
| `--compress` | 57.5 s | 10,021,385,307 |

That is **2.2× slower for a 0.04% size reduction**. The cost is intrinsic:
XPRESS still scans every block for matches before concluding the data is
incompressible.

The lesson is size-dependent: on small inputs the scan is cheap and the win is
real, while on large inputs (which are disproportionately already-compressed
media or model weights) it is pure cost. So the default is **size-based**: with
neither switch given, `encrypt` compresses when the **total input is under
50 MiB** (`COMPRESS_AUTO_MAX`) and stores otherwise. `--compress` / `--store`
force the choice regardless of size. The decision is made once, after the
input-size pre-sum, by `apply_auto_compress`, which is a no-op when an explicit
switch was passed (a tri-state flag: `g_cfg_compress` + `g_cfg_compress_set`).
The GUI exposes the same choice as a **Compress On/Off** toggle whose initial
state is the size-based default.

This applies to **single-file containers as well as archives**. A single regular
file is encrypted "bare" — its bytes are streamed straight through the same
compression/store sink with no tar framing (header archive flag = 0), and the
header's compression byte records the mode so `decrypt` reverses it
automatically.

### 6.4 Compression framing

When enabled, the tar stream is cut into 1 MiB blocks. Each block is XPRESS-
compressed and emitted as `[u32 orig_len][u32 payload_len][payload]`. If the
compressed form is not smaller, the block is **stored verbatim**
(`payload_len == orig_len`), so a compressed archive is never more than a
fraction of a percent larger than store. On a block of zeros this is dramatic —
1 MiB compresses to 43 bytes.

### 6.5 Why compression sits below tar and above GCM

The ordering — **tar → compress → encrypt** — is a security decision, not just
an engineering one. Because compression happens before encryption, the
decompressor on the `unpack` side only ever runs on data that has *already
passed GCM tag authentication*. An attacker cannot feed crafted,
unauthenticated bytes into the XPRESS decompressor (decompressors are a classic
source of memory-safety bugs). `unpack` decodes ONE ENTRY AT A TIME, straight
into that entry's own output file: decrypt, de-frame if the container is
compressed, skip the 512-byte tar header, write the size the inventory records,
drain the padding, check the tag. The decompressor still only ever sees bytes
that came out of a GCM stream.

Until 1.0.71 it went the long way round — decrypt the whole container into a
temporary file, inflate that into a second one, then walk the tar — which cost
3N of I/O, N of scratch disk, and a complete decrypted copy of the archive
sitting on disk for the length of the run. See `docs/V5_WORK.md` step A2.

### 6.6 Extraction safety

Archive entry names are sanitized on extraction: absolute paths, drive letters,
and `..` traversal components are **rejected**. A malicious archive therefore
cannot write outside the chosen output directory. This is covered by a dedicated
selftest (`archive path-traversal safety`).

### 6.7 Encrypted-ZIP extraction (WinZip AES-256)

The `unzip` command opens a *foreign* format: standard `.zip` archives whose
entries are encrypted with **WinZip AES** — AES-128, AES-192 or AES-256
(compression method 99, AES extra field 0x9901, AE-1/AE-2), as produced by
7-Zip, WinRAR and WinZip. This is
deliberately separate from Myrkr's own `.mrk` container — it exists so the tool
can open encrypted zips received from elsewhere, reusing the same hand-written,
no-CRT philosophy rather than shelling out to an unzip utility.

The reader is **streaming** — memory is bounded independent of archive size
(`file_read_at` does positioned reads via `SetFilePointerEx`). Only the central
directory is held in memory (capped); the tail is read to find the
End-Of-Central-Directory (the ZIP64 EOCD/locator are followed for large
archives), then each central-directory entry is walked. For each encrypted
entry, WinZip AES is implemented exactly:

1. `key = PBKDF2-HMAC-SHA1(password, salt, 1000, 2·K+2)` →
   `aesKey[K] ‖ macKey[K] ‖ pwVerify[2]`, where the key size `K` (16/24/32) and
   salt length (8/12/16) follow the AES strength byte.
2. The 2-byte `pwVerify` is checked (a fast wrong-password reject), then the
   ciphertext is authenticated with `HMAC-SHA1(macKey, ciphertext)` truncated to
   80 bits and compared to the entry's trailer — **before any decryption**
   (encrypt-then-MAC). A wrong password or any tampering fails here, so the
   decryptor and the inflate path only ever see authenticated bytes.
3. The data is decrypted with **AES-256-CTR** (a 16-byte counter incremented as
   a little-endian integer *before* each block — WinZip's specific construction,
   distinct from GCM's big-endian counter), then inflated if the real method is
   DEFLATE.

Stored entries are **streamed**: ciphertext is read in 1 MiB chunks through the
HMAC and AES-CTR into `OUTPUT.part`, the tag is verified, then the file is
renamed into place — so an entry of any size extracts in O(chunk) memory, and
unauthenticated plaintext is never exposed under the real name (temp-then-rename,
the same property the `.mrk` path has). DEFLATE entries are held in memory (our
inflate is whole-buffer) up to a 512 MiB cap; larger ones are refused with a
clear message. A 4.3 GiB encrypted archive extracts in ~5 MiB of working set.

This required four new hand-written primitives, each with a known-answer
selftest: **CRC-32** (IEEE, table-driven — the SSE4.2 `crc32` instruction is the
incompatible Castagnoli polynomial), **SHA-1 / HMAC-SHA1 / PBKDF2-HMAC-SHA1**,
**AES-128/192/256** (a software FIPS-197 key schedule producing the same round-
key layout `aesenc` consumes, driven in CTR mode by the AES-NI round function;
checked against the FIPS-197 single-block vectors), and a raw
**DEFLATE inflate** (RFC 1951, a structural port of puff.c). The inflate selftest
deliberately uses a *dynamic*-Huffman stream: an earlier fixed-Huffman-only
vector masked an HDIST-field-width bug that only the dynamic path exercises.

Entry names are sanitised with the same `sanitize_name` used by tar extraction,
which refuses four things. **Traversal** — an absolute name, or `..` at any
component start. **A colon anywhere** — at index 1 it is a drive (`C:evil`), and
anywhere else it names an alternate data stream (`notes.txt:hidden`), which
writes real content that no ordinary listing of the output directory shows.
Neither escapes OUTDIR, so the second is not a traversal rule; it refuses to
create something the user cannot see they have. **A DOS device name as a
component** — `CON`, `NUL`, `COM3`, and `com3.txt` too, because the device is
what precedes the first dot; trailing spaces are ignored the way Windows ignores
them, so `CON ` is also `CON`. Opening one of those writes to a console or a
serial port and reports success, and a directory in front of it does not help.
A colon is legal in a POSIX name and a device name cannot be created on Windows
at all, so refusing both gives up nothing that was ever extractable — verified
against fourteen legitimate names that still come out, including `com.txt`,
`comX.txt`, `nul2.txt`, `console.txt` and `a..b.txt`, none of which are
devices. Legacy PKWARE **ZipCrypto** is refused as insecure;
unencrypted `store`/`deflate` entries inside an otherwise-encrypted zip are
extracted as a convenience. The GUI detects a `.zip` input (by extension plus the
`PK\3\4` local-file signature) and opens its decrypt dialog in **Extract** mode,
running the same `do_unzip` on the worker thread.

The reverse direction, `zip` (`zip.asm`), **creates** WinZip AES-256 (AE-2)
archives so data can be sent to recipients who only have 7-Zip/WinRAR/WinZip.
This is an explicit security compromise — it forgoes `.mrk`'s Argon2id KDF and
key-committing AES-GCM for format compatibility, and is documented as such; the
`.mrk` path remains the recommended one. The writer mirrors the reader: per
entry it draws a fresh CSPRNG salt, derives the key with PBKDF2-HMAC-SHA1,
**DEFLATE-compresses** it with our own RFC-1951 encoder (`deflate.asm`; entries
that don't shrink are stored), encrypts with AES-256-CTR while streaming the
ciphertext through a manually constructed HMAC-SHA1 (ipad/opad over a running
SHA-1 context, so large files need no buffering), and writes
`salt ‖ pwVerify ‖ ciphertext ‖ tag[0..9]`. The CRC field is 0 (AE-2). Local
headers, a central directory (accumulated in a sibling temp file), and the EOCD
are written, with **ZIP64** records (per-entry 0x0001 extras and a ZIP64 EOCD +
locator) emitted automatically once any size/offset reaches 4 GiB or the entry
count reaches 65535. The DEFLATE encoder is a from-scratch fixed-Huffman + LZ77
(hash-chain) codec, validated both against our own inflate and by round-tripping
through zlib (pyzipper). The GUI offers a **Format: Myrkr / Zip** toggle in the
encrypt dialog that routes the worker thread to `do_zip`, and the same choice
again on the password prompt (§11.1) — which on the drag-and-drop path is the
only surface the output is ever discussed on.

**Opening a `.zip` browses it**, exactly as opening a `.mrk` does; extracting is
the button pressed next, not something that has already happened. `zip_to_index`
turns the central directory into the same in-memory inventory `idx_read`
produces, so the row model, expand/collapse, display and summary are shared
rather than duplicated. Three things differ from a container, and each is a
property of the format rather than a choice:

- **The password is asked first, when there is one to give.** It buys no
  secrecy — WinZip-AES encrypts entry data and nothing else, so a zip's names
  and sizes are readable by anyone holding the file whatever this window does —
  and it is asked anyway so that opening an archive means the same thing
  whichever kind it is. A zip with nothing encrypted in it is not asked, because
  there would be nothing to check the answer against, and a prompt whose input
  cannot be wrong teaches the user their answer does not matter.
- **Missing parents are synthesised.** Only file records are required in a zip,
  so `a/b/c.txt` can be the only trace of `a` and `a/b`. Built from the entries
  alone the tree would have no folder rows, every file would sit behind
  ancestors that do not exist, and the window would come up empty on a perfectly
  good archive.
- **Remove rewrites the archive rather than editing it.** A container records
  where every entry's ciphertext lies, so removing one is an overwrite in place
  and a slide of what follows; a zip's entries are reachable only by walking, and
  `zidx_add_unique` leaves their extents zero because there is nothing truthful
  to put there. `zip_delete_marked` therefore rebuilds the file, and
  `container_remove_selected` picks the path by `g_is_zip` so those zeros are
  still never acted on.

#### Removing from a zip: write, wipe, delete

The order is the design, and it is the order the user asked for:

1. **Write** the new archive beside the old one under `<name>.mrktmp`. The
   original is untouched throughout, so every failure up to the end of this step
   costs a temp file and nothing else — and that is where nearly all the work is.
   Survivors are copied as **raw bytes**: local header, extras, compressed data.
   A WinZip-AES entry carries its own salt, password verifier and authentication
   tag inside those bytes, so it still decrypts under the same password
   afterwards. Nothing is decrypted to move it, and the password is not needed to
   do any of this — which also means a wrong password cannot corrupt an archive
   this rewrote. Each surviving central-directory record is written back
   verbatim except for its local-offset field, patched in our own copy as the
   entry is placed.

2. **Overwrite** the old file with random where the removed entries lay, and
   over its central directory through to end of file. This is the step that makes
   the removal a removal. Deleting the file alone unlinks it and leaves every
   removed entry's ciphertext in freed blocks, still decryptable by whoever knows
   the password — the same leak in-place removal exists to avoid for containers
   (§4.2). The directory is overwritten because it *names* everything, including
   what was just removed, and a name is the disclosure that outlives the data.
   **Random, never zeros**, for the reason `do_remove_marked` gives.

   Only the removed entries and the directory are overwritten, **not the whole
   file**. The survivors' bytes are not a secret being destroyed: by this point
   they are in the new archive, unchanged, so a second full pass over the file
   would protect nothing. The test asserts both halves of that — the removed
   entry's bytes changed, the surviving entry's did not.

   The writes are **flushed before the handle closes**. Deleting a file discards
   its dirty pages, so an unflushed overwrite followed by a delete can reach the
   disk never: the wipe would have been a no-op that looked like a wipe, and the
   failure is invisible from inside the process.

3. **Delete** the old file, then rename the new one into its place. If the rename
   fails the archive is under the temporary name, and the window says so by name
   rather than reporting a generic failure — an untouched archive and one whose
   only copy has moved need different things from the user.

**What it refuses rather than guesses at.** An entry with general-purpose bit 3
has its sizes only *after* its data, so a byte copy cannot know where it ends
without decoding it; ZIP64 offsets and multi-disk records do not fit the
directory this writes; and a record whose local signature is not where the
directory says stops the whole thing. Every refusal is decided in a survey pass
before a byte is written anywhere, so it costs the user nothing but the answer,
and the archive is left byte-identical. Refusing to rewrite an archive is an
inconvenience; rewriting one wrongly destroys it. Myrkr's own zips carry none of
these.

`uz_entry_dropped` decides membership against the same inventory the window was
drawn from, normalising the name the way `zip_to_index` did — into a scratch
buffer, not in place as `uz_entry_picked` does it, because the record is copied
verbatim into the new archive and a name rewritten here would no longer match
the local header it belongs to. **Anything the lookup does not find is kept**: an
entry wrongly kept is visible, an entry wrongly destroyed is not.
`container_remove_selected` runs `zip_to_index` first for the same reason the
container path runs `idx_read` first — it rebuilds the inventory from the file,
so marks left behind by a removal the user *cancelled* cannot still be sitting on
entries when the next one runs.

What none of this can promise is the filesystem's own copies — a snapshot, a
journal, a flash translation layer that wrote the block elsewhere. Same caveat as
removal from a container, and it is a property of the medium.

A backslash in an entry name is treated as a separator. The spec says `/`, and
Windows tools write `\` anyway — .NET's `ZipFile.CreateFromDirectory` does — and
`build_extract_path` already passes one straight into the output path, so the
extractor makes a folder from it. Listing it as a literal character would show
one flat row for something that extracts as a tree.

When **no password** is supplied (CLI `zip` without `-p`, or the GUI's
**Execute** button), `zip_emit_file` instead emits a **standard unencrypted**
entry: same STORE/DEFLATE decision, but with a real **CRC-32** of the
uncompressed data (in-memory entries CRC their buffer; a large streamed-store
entry pre-scans the file with positioned reads, then rewinds), general-purpose
flag `0x0800` (UTF-8, not encrypted), the real method/sizes, and no
salt/pwVerify/HMAC/AES-extra. The resulting archive opens in Windows Explorer,
7-Zip, and `myrkr unzip`. `do_zip` skips the policy check entirely when the
password length is zero.

---

## 6.8 Progress reporting

Long streaming operations — `encrypt`, `decrypt`, `verify`, `hash`, `pack`,
`unpack` — render a live progress bar so multi-GB jobs are not silent:

```
  encrypting  [############------------]  62%   5734 / 9248 MiB
```

Design choices and their rationale:

- **Rendered to stderr**, not stdout, so a redirected/piped stdout (`> out` or
  `| tool`) stays free of bar/carriage-return noise. The success and hash-digest
  lines remain on stdout.
- **Auto-suppressed when not interactive.** `progress_begin` probes the stderr
  handle with `GetConsoleMode`; if it is a file or pipe (not a console) the bar
  is silently disabled. So scripted/redirected use is clean.
- **Throttled to integer-percent changes** (≤ 101 repaints for the whole job),
  so the bar costs nothing measurable even on a 26 GB file.
- **Accurate totals.** For `encrypt`/`hash` the total is the input size; for
  `decrypt`/`verify`/`unpack` it is the container's ciphertext length; for
  `pack` a quick metadata-only pre-walk sums all input file sizes up front.
- The bar always ends with a newline (on success or error) before any status or
  error message prints, so output never collides on the bar line.

## 7. Long-path support

All file APIs are the Unicode (`*W`) variants, and every path is normalized to
the extended-length `\\?\` form internally. Combined with the `longPathAware`
manifest, this supports paths up to the Windows maximum of 32,767 characters,
far beyond the legacy 260-character `MAX_PATH`. Drive-absolute and UNC paths are
handled directly; relative paths resolve via `GetFullPathNameW`.

This is the limit on the **filesystem** path — where a file is read from or
written to. It is distinct from the length of the entry name *stored inside* a
container, which POSIX ustar caps at 100 bytes per component and 256 overall
(§4, "The hard limits, in one place"); the two rarely collide because the stored
names are relative to the encryption root.

---

## 8. Password policy

When a container is created (`encrypt` and `pack`), a configurable strength
policy is enforced: by default a minimum of 12 characters and at least 3 of the
4 character classes (uppercase, lowercase, digit, symbol). Length is counted in
UTF-8 code points. Tunable with `--min-len N` / `--min-classes K`, or disabled
with `--no-policy`. The policy applies only at creation time; `decrypt`,
`verify`, and `unpack` accept whatever password the container was made with.

A **Myrkr container always requires a password**, so the `encrypt`/`pack` policy
has no "empty" exemption. A **`.zip`, however, may be created without a password**
— `zip` with no `-p` (and the GUI's **Execute** button) emits a standard
*unencrypted* archive (STORE/DEFLATE entries with a real CRC-32, no AES); a zip
password, if given, must still satisfy the policy.

**Where the password comes from.** A release build takes it only from the prompt
on the private desktop (§11.1) — never from an argument, so it cannot reach a
process list, a shell history or a scheduled task. Test builds accept `-p`, which
does expose it that way; that is one more reason a `TEST_IO` binary must never
ship, and why the packager refuses to wrap one (§12).

---

## 9. Hardening architecture

Hand-written assembly with no C runtime removes a large class of library bugs and
takes away the compiler's safety features in the same stroke, so the equivalents
are implemented explicitly.

**Every row below carries its evidence.** The instrumented build (`build dbg`)
has a `redteam <case>` command that deliberately violates a control and asserts
the process dies with that control's exact code; `tests/redteam.py` drives all of
them and is Phase 2 of `tests/run.ps1`. Rows without a fault-injection case say
so — an unmeasured control listed beside measured ones overstates the whole
table.

| Mitigation | Mechanism | Evidence |
|---|---|---|
| Stack canaries | Per-process random cookie (CSPRNG ⊕ `rdtsc`, never zero) planted at `[rbp-8]` by `FRAME_PROLOG`, verified by `FRAME_EPILOG`, in every non-leaf proc | `redteam canary` → `FF_STACK_COOKIE` |
| SW shadow stack | Parallel return-address stack, **per thread** via a TLS slot, in a `VirtualAlloc` region left `PAGE_NOACCESS` with only the middle made writable — guard pages either side. Every epilog scans for its own return address | `redteam shadow` → `FF_SHADOW_STACK` |
| HW shadow stack | Linker `/CETCOMPAT` (Intel CET) | `dumpbin /headers` → **CET compatible** |
| DLPV (forward edge) | 8-byte landing-pad magic before each of **our own** indirect-call targets; `CALL_GUARDED` validates `[target-8]` before transferring | `redteam dlpv` → `FF_GUARD_ICALL`; scope below |
| Integer overflow | `CHECK_ADD_OVF` on size arithmetic that can wrap (4 sites) | `redteam overflow` → `FF_OVERFLOW` |
| Bounds checking | `BOUND_CHECK` before indexed access in parsing paths (14 sites) | `redteam bounds` → `FF_BOUNDS` |
| Type confusion | 32-bit type magic in the heap block header, checked on access (`TYPE_CHECK`) | `redteam typemagic` → `FF_TYPE_MAGIC` |
| Tagged heap (temporal) | Header {magic, size, generation, canary} + trailing canary; checked on access and free; freed blocks poisoned `0xDD` and the generation bumped | `redteam heaptag` → `FF_HEAP_TAG` |
| IAT lockdown ("RELRO") | Own PE walked at startup, IAT `VirtualProtect`ed `PAGE_READONLY` **before any user input is parsed** | `redteam iat` → AV on the locked slot, reported `FF_IAT_RO` |
| ASLR / DEP / NX | `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /LARGEADDRESSAWARE` | `dumpbin /headers` reports all |
| x64 SEH unwind | `.pushreg` / `.setframe` / `.allocstack` emitted by `FRAME_PROLOG` on every framed proc | `framecheck` gates `build strict` |
| Secure zeroing | `secure_zero` (volatile stores + fence) on keys, passwords, derived material and the Argon2 arena before release | 34 call sites — **no fault-injection case** |
| Constant-time compare | `ct_memcmp` for tags and passwords; AES-NI/PCLMULQDQ are inherently constant-time | by construction — **not measured** |
| CFG (`/guard:cf`) | **Not used.** It needs per-function metadata a hand-written assembler cannot emit, and the OS CFG-checks this binary's GUI callback pointers and fast-fails at load | n/a — DLPV is the hand-rolled equivalent |

Every detected violation routes to `ff_trap` → `__fastfail` (`int 29h`): a
non-continuable, non-catchable kernel termination, so nothing continues in a
corrupted state. The codes are enumerated in **one** place, `macros.inc`:
`FF_STACK_COOKIE`, `FF_GUARD_ICALL`, `FF_SHADOW_STACK`, `FF_HEAP_TAG`,
`FF_TYPE_MAGIC`, `FF_BOUNDS`, `FF_OVERFLOW`, `FF_IAT_RO`.

In the instrumented build `ff_trap` exits `0xFADE<code>` instead of trapping, so
a test harness can read which check fired without depending on console output.

### 9.1 Scope of the forward-edge guard

The binary makes **49 indirect calls. Two are its own function-pointer dispatch,
and both are guarded.** The other 47 are COM virtual calls into objects we did
not create — Explorer's drop target, the shell's file dialogs, the `IDataObject`
on the far end of a drag. A landing pad cannot be placed in someone else's
vtable, so those are covered by the OS's control-flow integrity rather than ours.

This is recorded because the table used to claim a landing pad "before every
indirect-call target", which was untrue and made the binary sound better defended
than it is. Found in the pre-release audit.

### 9.2 What the same audit removed

`CHECK_SUB_OVF` and `CHECK_MUL_OVF` were defined beside `CHECK_ADD_OVF` and
**nothing called either**. An unused macro protects nothing while making the
mitigation list longer, which is the wrong direction for a document an operator
relies on. Both are gone; add one back the day a subtraction or multiplication of
sizes needs it, with its call site in the same commit.

`FRAME_PROLOG`/`FRAME_EPILOG` remains the cornerstone: one macro pair gives every
non-leaf procedure its SEH unwind data, its canary and its shadow-stack entry, so
the protections are uniform and visible rather than hand-rolled per function.
`framecheck` refuses a build where a frame is too small for its own outgoing
arguments, which is the failure mode that silently overwrites a local with a
callee's argument.

---

## 10. Command-line interface

```
myrkr hash    FILE|FOLDER [--json] [-o OUTFILE]
myrkr selftest
myrkr bench
```

**The release CLI cannot encrypt or decrypt.** `encrypt`, `decrypt`, `verify`,
`zip` and `unzip` — and the `-p PASSWORD` option that feeds them — are compiled
only into `TEST_IO` builds. A shipping binary has no code path that accepts a
password as an argument; the password is typed on a private desktop
(§11, §14.2). Section 14.1 gives the reason: a signed, allow-listed Myrkr that
takes a password on the command line is a ready-made bulk-encryption engine for
anyone already permitted to run it, and that is worth more to an attacker than
scripted encryption is to a legitimate user. The three verbs that remain take no
password and cannot destroy anything.

The five verbs stay **in `cmd_table`** and are refused rather than deleted.
Removing the names would make `myrkr encrypt foo` fail `is_cli_command`, which
treats an unrecognised `argv[1]` as a dropped file path — the GUI would open on
a file called "encrypt", which reads as a bug rather than as a policy. Instead
`dispatch` refuses them with an explanation pointing at the window and the
Explorer context menu, and it does so **before** `collect_options` runs: parsing
first rejected them for the wrong reason ("`-p` is required", or "unknown option
`-p`") and printed usage instead of saying why the verb is gone.

The paragraphs below describe the encrypt/decrypt semantics as they exist in a
test build, and — for everything except argument handling — as the GUI drives
them.

**Unified encrypt/decrypt (no separate `pack`/`unpack`).** `encrypt` takes any
number of input positionals and one `-o` output. It auto-selects its mode: a
single regular-file input is encrypted on its own; multiple inputs, or a single
directory, are bundled into one encrypted archive (it delegates to the same
internal pack core). `decrypt` peeks the container header's archive flag and
dispatches: a single-file container decrypts to a file, an archive extracts its
tree. With no `-o`, decrypt derives the output from the container: stripping
`.mrk` for a file (`derive_output_name`), or, for an archive, the folder the
container sits in (`derive_output_dir`). The archive case deliberately does not
create a folder named after the container — an archive built from one folder
already carries that folder as the tar's top level, so doing both nested it twice
(`project/project/…`). An archive built from several inputs has no shared top
level and therefore extracts beside the container; `-o` gathers it. The GUI
follows the same rule, and its **Change…** picker takes the chosen folder
verbatim rather than re-appending the previous basename. The release command table is `hash selftest bench` (plus the five refused
verbs); a test build adds `encrypt decrypt verify zip unzip`, and a debug build
further adds `redteam` and `secdesk`. The old `pack`/`unpack` verbs were removed (their cores live on as the archive
path of `encrypt`/`decrypt`).

Exit codes: 0 ok, 1 usage, 2 I/O, 3 auth/tag failure, 4 corrupt/invalid
container, 5 out of memory, 6 unsupported CPU, 7 selftest failure, 8 not enough
free disk space.

**Pre-flight disk-space check.** Before writing, `encrypt`/`decrypt` query free
space on the target volume (`GetDiskFreeSpaceExW`) and abort with exit code 8 if
the estimated output won't fit (output size + 1 MiB margin), so a multi-GB
operation never starts when the drive can't hold the result. The estimate uses
the input/summed-input size for encrypt and the container size for decrypt; an
archive decrypt checks both the temp-file drive (the decrypted archive) and the
output drive (the extracted files). The query targets the parent directory of
the output path, and if it can't be determined the operation proceeds
(fail-open) rather than blocking a valid run. The GUI surfaces the same
condition as a "not enough free disk space" dialog.

---

## 11. Hybrid entry + GUI front-end

There is **one** executable. `gui.asm` provides the entry point `wstart`, which
the binary is linked to enter (`/subsystem:windows`). `wstart` runs the shared
startup (`cpu_gate` → `hardening_init`), tokenizes the command line with the
CLI's own `parse_cmdline`, and then branches:

- **CLI mode** when `is_cli_command` reports that `argv[1]` is a known verb
  (`encrypt`/`decrypt`/`verify`/`zip`/`unzip`/`hash`/`selftest`/`bench` — the
  first five are *recognised so they can be refused*, §10) or
  begins with `-` (so `--help` prints console usage). It calls
  `con_attach_parent` to reach the launching terminal, `con_init` to cache the
  std handles, then `dispatch` — the identical command path the old console
  build ran — and exits with its code (wiping `g_cfg_pass` first).
- **GUI mode** otherwise — no arguments, or a bare file/folder path (drag-drop /
  "Open with", which is never a verb). `gui_main` runs the window.

Because a `/subsystem:windows` image does not keep a terminal waiting, a shell
prompt returns immediately while CLI output streams to the console; scripts that
need to wait use `Start-Process -Wait`, `cmd /c start /wait`, or output
redirection. The trade for this is that `/guard:cf` cannot be used (the GUI hands
the OS callback pointers CFG validates against an absent guard table); CET and
all software mitigations remain. The old standalone console `start` proc still
exists in `main.asm` but is dead code in the shipping binary.

When the GUI runs, the inputs (`myrkr FILE [FILE...]`) are **classified once, up
front**, and the window opens directly into the matching mode:

- **Decrypt** iff there is exactly one input whose name ends in `.mrk` *and*
  whose header carries the container magic (both the extension and the header are
  checked; the archive flag at header byte 17 is also read so the dialog knows
  whether the output is a folder or a file).
- **Encrypt** otherwise — a single non-container file, or any combination of
  several files and/or folders (multiple inputs or a folder are archived
  automatically by the shared core).

Each mode has its own dialog:

- **Encrypt dialog:** a **list-view** (report mode, no column header, items not
  selectable) of the selected inputs with three columns — a system file/folder
  icon and the root-relative name, the file size (human-readable; folders show
  their recursive total via `input_size`), and a **per-file progress bar**. Note
  a folder is **one** row (its recursive total), not one row per contained file,
  so the list stays small regardless of folder size. **The recursive size walk
  runs on a background `indexer_thread`** so the window paints immediately rather
  than blocking on a huge folder; a status line at the right of the breadcrumb
  row shows a live **"Scanning... N files, X"** and settles into the final
  **"N files, total size"** summary, and the action button stays disabled until
  the scan finishes (`g_scanning`). There is also a
  single, label-less **password field** (masked, with a Show/Hide toggle and a
  grey **placeholder cue** — "Password" — drawn while it is empty) carrying a
  **format-aware** validation underline: green once it meets the policy, red
  otherwise — and, while empty, red for the **.mrk** format (a Myrkr container
  always requires a password) but neutral for **.zip** (no password is an
  accepted state for the policy; a set zip password must still pass). The action
  button normally reads **Encrypt** and enables once the password passes
  `check_password_policy`; in the **.zip + empty-password** case it instead reads
  **Execute** and stays enabled, producing a standard *unencrypted* archive. An
  **Exit** button (always enabled, also bound to **ESC**) cancels a running
  operation or, when idle, closes the window. The window is a **borderless
  `WS_POPUP`** (no title/menu bar) painted **dark grey (#20201F)** with white
  text, with **rounded corners**, a **drop shadow** and **no taskbar/Alt-Tab
  entry**, **centred on the screen**; the entire body — including the file list,
  progress bars and text — drags it. The password field takes keyboard focus on
  open; Tab cycles only password → Encrypt → Exit (with a visible focus ring on
  the buttons).
- **Decrypt dialog:** a label-less, minimal layout — the input file's **basename
  only** (borderless, read-only) at the top; a suggested destination (the input
  path with `.mrk` removed, borderless) with a **Change…** button that opens the
  modern common-item folder picker (`IFileOpenDialog` with `FOS_PICKFOLDERS`, via
  `CoCreateInstance`) and recombines the chosen folder with the basename; one
  full-width masked password field with an inline Show/Hide eye; and right-aligned
  Exit / Decrypt buttons. No password policy is ever enforced here — the container
  is the only authority.

The GUI just populates the same `g_positionals`/`g_poscount`/`g_cfg_*` globals
the CLI uses and lets the shared `do_encrypt`/`do_decrypt` auto-dispatch, so
behavior is identical; an archive decrypt extracts into the chosen folder. The
container format and all hardening are identical to the CLI. (The GUI
deliberately uses the classic, non-themed common controls — the app manifest
does not opt into comctl32 v6 — which is why the password placeholder is drawn by
an edit subclass rather than the v6-only `EM_SETCUEBANNER`. The binary
additionally links `user32`/`comctl32`/`shell32`/`comdlg32`/`ole32`/`gdi32` for
the GUI; `ole32` provides `CoCreateInstance`/`CoInitializeEx`/`CoUninitialize` for
the `IFileOpenDialog` folder picker and `CoTaskMemFree` to release the path string
it returns.)

Three design decisions are worth recording:

- **Threading vs. the software shadow stack.** The shadow stack maintained by
  `FRAME_PROLOG` is **per thread**, reached through a TLS slot. It was once one
  process-global structure, and that was a data race the moment a second thread
  ran framed code: the indexer and the UI thread interleaved their pushes, each
  then failed to find its own return address, and the guard fastfailed the
  process on its own bookkeeping (`0xC0000409`). `sstk_thread_init` gives the
  calling thread its own guard-paged block; a thread without one keeps its canary
  and simply skips the shadow stack, because degrading beats trapping.

  `sstk_thread_free` gives that block back, and **must be the last thing a thread
  does** — every framed call has to have returned, since the block is what
  `FRAME_PROLOG` writes to and `FRAME_EPILOG` verifies against, and releasing it
  under a live frame is the same fastfail arrived at from the other direction.
  The TLS slot is cleared *before* the pages go back, so framed code appearing
  on that path later degrades to canary-only rather than dereferencing released
  address space. Both procs are raw for the mirror of the same reason: one runs
  before the block exists, the other after it is gone.

  Without the free the block leaked once per thread, and threads are not rare
  here — a scan on every input change, a worker per operation, one per password
  prompt. Measured by counting the allocations themselves (an
  `0x1000 + 16 + 4096*8 + 0x1000` reservation is unmistakable): eight extracts in
  one process took it from 4 regions to 12 before, and left it flat at 3 after.

  The crypto runs on a dedicated **worker thread**, while every proc in
  `gui.asm` is "raw" (no `FRAME_PROLOG`) and the UI thread calls only Win32 APIs
  + raw helpers. A
  100 ms `WM_TIMER` polls `g_prog_done`/`g_prog_total` to drive a Win32 progress
  bar; Cancel sets a flag via the raw `progress_abort`, and the streaming loop
  bails (deleting its temp) at the next chunk.

- **No `/guard:cf` in the hybrid binary.** Control Flow Guard requires
  per-function metadata that hand-written MASM cannot emit, and the GUI hands the
  OS callback pointers (window proc, thread proc) that CFG-instrumented OS code
  validates against the image's (absent) CFG table — which fast-fails at load
  (`STATUS_STACK_BUFFER_OVERRUN`, 0xC0000409). Since the single binary also drives
  the GUI, CFG must stay off; it is built with `/CETCOMPAT` only. The hardware
  shadow stack, the software shadow stack, stack canaries and DLPV still protect
  the crypto path, and DLPV (our software forward-edge CFG) covers the same
  indirect-call threat CFG would.

- **Validation ordering and UX.** For encrypt, all input validation (confirm
  match, then password policy) happens before the "output exists — overwrite?"
  prompt, so the user is never asked about an overwrite that can't proceed; the
  Encrypt button is moreover kept disabled until the live evaluation already
  shows a matching, policy-passing pair, so the prompt path is rarely reached on
  a bad password. Encrypt and decrypt are entirely separate dialogs (rather than
  one window that hides its Confirm field), since a password confirmation only
  makes sense when setting a new password. The overwrite prompt is shown only
  for single-file output; an archive decrypt extracts into a folder, which
  `do_unpack` creates/uses without a clobber prompt. A wrong password is
  reported in about one KDF thanks to the §4 key-check value, instead of after a
  full read.

- **Fluent-styled standard window.** The window keeps an ordinary top-level
  frame (`WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX`, system title bar and
  min/close buttons, default position) — no acrylic, layering, blur, custom
  shadow or non-client customisation — but a lightweight Fluent skin is applied
  entirely with classic GDI (no comctl32 v6, no WinUI/WinAppSDK/.NET, no extra
  runtime). The skin has three parts:
  - **Light surface + font.** The window-class background brush is a light
    `CLR_SURFACE` (`#F3F3F3`); `WM_CTLCOLORSTATIC`/`EDIT`/`BTN` paint dark body
    text (`CLR_TXT`) on the surface (or white for edit fields); a single
    `CreateFontW` "Segoe UI" ~10pt ClearType font is applied via `WM_SETFONT`.
  - **Accent owner-draw buttons.** Every button is `BS_OWNERDRAW`; the
    `WM_DRAWITEM` handler (`draw_button`) paints a rounded `RoundRect` — the
    primary action button (`ID_ACTION`) is the filled **accent** style (`#005FB8`,
    white caption), the rest are the subtle "standard" style (light fill +
    `CLR_BTN_BORDER`), each honouring pressed (`ODS_SELECTED`) and disabled
    (`ODS_DISABLED`) states. Five accent colours are pre-defined; the brush/pen
    are created and freed per paint.
  - **Validating password box.** The password (and confirm) fields are
    borderless white `EDIT`s with a 2-px `STATIC` "underline" beneath each.
    `update_strength` classifies each field into a state — neutral, valid, or
    invalid/mismatch — stored in `g_pw_state`/`g_cf_state`. The empty case is
    format-aware: red (invalid) for a `.mrk` container, which always requires a
    password, but neutral for `.zip`, where an empty password is an accepted
    state (toggling the format re-runs `update_strength`).
    `WM_CTLCOLORSTATIC` returns the matching brush (grey / green `CLR_VALID` /
    red `CLR_INVALID`) and `InvalidateRect` repaints the underline live as the
    user types, mirroring a WinUI `PasswordBox` with inline validation. (The
    owner-draw buttons read their real enabled state with `IsWindowEnabled`
    rather than `ODS_DISABLED`, which is unreliable when the disable happens
    while the window is still hidden.)
  - **Breadcrumb chip.** `compute_root` finds the longest common directory of the
    selected inputs (case-insensitive longest-common-prefix, truncated back to
    the last separator → `g_rootpath`); `build_crumb` renders it friendly — each
    separator becomes a `›` (U+203A) chevron and a leading drive letter is
    upper-cased, so `c:\temp` shows as **`C: › temp`** (drive and folder as
    distinct items, not a raw path). `build_crumb_short` precomputes a collapsed
    form `first › … › last` (U+2026). The breadcrumb is an `SS_OWNERDRAW` static
    painted by `draw_crumb`: a dark (`CLR_CRUMB_BG`/`#20201F`) `RoundRect` chip
    with a 1px lighter edge and white semibold text, sized to hug the text; it
    measures the full string with `GetTextExtentPoint32W` and falls back to the
    collapsed form (then `DT_END_ELLIPSIS`) when it won't fit. The list-view lists
    each entry *relative* to that root (`rel_path` strips the common prefix), so
    the chip shows where the files live and the list shows the structure beneath.
  - **Per-file progress bars.** The list-view's "Progress" column is owner-drawn
    via `NM_CUSTOMDRAW` (`draw_lv_progress`): at the sub-item pre-paint stage for
    column 2 it fetches the cell rect (`LVM_GETSUBITEMRECT`) and paints a **flat,
    solid, borderless** light track with an accent fill (`FillRect`, no
    `RoundRect`/pen) whose width is `g_file_done[row] / g_file_total[row]`. Those
    counters are maintained by the shared crypto path: `do_pack` sets
    `g_cur_input` to the positional it is currently streaming, and `progress_add`
    attributes each chunk to `g_file_done[g_cur_input]`; `sum_inputs` (and the
    single-file `do_encrypt`) fill `g_file_total`. Because encryption is streamed
    *as* each input is archived, the bars fill one input at a time, in order. The
    GUI timer invalidates the list every 100 ms while the worker runs, and
    `on_done` forces one final repaint (`UpdateWindow`) before the result box so
    completion always shows full bars even on a sub-tick job. These counters are
    read-only/unused on the CLI and decrypt paths.
  - **Flat operation bar.** The operation progress bar is an `SS_OWNERDRAW`
    static painted by `draw_bar` — a light track plus a solid accent fill
    (`FillRect`, no border), sized from `g_prog_pct`. (`draw_bar`'s frame must be
    ≥ deepest-local + 32 so a called `FillRect`/`CreateSolidBrush` cannot clobber
    its locals through the outgoing 32-byte shadow space.)
  - **Dark borderless window.** `ST_MAINWND` is a bare `WS_POPUP` (no caption /
    menu bar) so the whole surface can be one colour; the class background brush is
    `g_hbr_dark` (#20201F) and `WM_CTLCOLORSTATIC/EDIT/BTN` return that brush with
    white text. The list-view is recoloured with `LVM_SETBKCOLOR`/
    `LVM_SETTEXTBKCOLOR`/`LVM_SETTEXTCOLOR`; the breadcrumb chip and standard
    buttons use a lighter panel grey (#3A3A3A) so they read as raised; only the
    grey placeholder cue stays non-white. The window has **rounded corners**
    (`SetWindowRgn` with a `CreateRoundRectRgn`) and a **drop shadow**
    (`CS_DROPSHADOW` class style), and `WS_EX_TOOLWINDOW` keeps it **out of the
    taskbar / Alt-Tab**. Lacking a title bar, the whole body drags the window:
    `WM_NCHITTEST` → `HTCAPTION` for the parent, and the list-view is subclassed to
    return `HTTRANSPARENT` (its clicks fall to the parent) so even the file list,
    progress bars and text drag it; `WM_NCLBUTTONDBLCLK` is swallowed so a
    double-click can't maximize. (Note: `gui_main` uses a deliberately large stack
    frame so `CreateWindowExW`'s outgoing arguments don't overwrite the W/H locals
    that the post-create `SetWindowRgn` reads back.)
  - **Non-selectable list + no header + no border.** `LVS_NOCOLUMNHEADER` drops
    the header row and the list has no `WS_BORDER` (it blends into the dark
    surface); selection is vetoed by returning `TRUE` from `LVN_ITEMCHANGING`
    whenever the change touches item state, so the list reads as a static manifest.
  - **Keyboard affordances.** Owner-draw buttons draw a white focus ring when
    `GetFocus()` matches them, so Tab is visible; an accelerator table
    (`CreateAcceleratorTableW` + `TranslateAcceleratorW` in the message loop) maps
    **ESC → ID_CANCEL** so Escape triggers the Exit button.
  - **Focus + tab order.** `gui_main` calls `SetFocus(g_hpass)` after the window
    is shown (and `WM_SETFOCUS` re-homes focus there), so typing starts in the
    password field immediately. The list and the Show button are created without
    `WS_TABSTOP` (`ST_OWNERBTN_NT`), so `IsDialogMessageW` cycles Tab through only
    password → Encrypt → Exit.
  - **Placeholder cue.** Without ComCtl32 v6 the native `EM_SETCUEBANNER` does
    nothing, so the password edit is subclassed (`edit_subclass`, installed by
    `subclass_edit`): after the original edit proc paints, if the field is empty
    it draws "Password" in grey inside the field. It disappears the instant any
    character is entered. Because deleting the *last* character only repaints a
    partial region, `update_strength` force-invalidates the whole field
    (`InvalidateRect …, TRUE`) when it goes empty, so the cue is reliably reapplied.
  - **Minimal encrypt form.** The dialog deliberately carries no confirm field,
    no separate strength meter, and no per-class requirement check-boxes — just
    the file list and one password field; `update_strength` only sets the
    validation underline and the Encrypt button's enabled state, and the worker's
    `check_password_policy` remains the authority on weak passwords.

---

### 11.1 Password entry on a private desktop

`read_password` does not read the dialog's own password field. It calls
`secdesk_prompt`, which creates a desktop of its own (`Myrkr-Secure`), starts a
thread, attaches *that* thread to the desktop, builds a small prompt window and
pump there, switches the display to it, and returns the typed password to the
caller before switching back.

**What this buys, precisely** — the boundary is narrower than "secure desktop"
sounds, and the code says so where it lives:

- `FindWindow`, `EnumWindows`, `SendMessage`, `PostMessage` and
  `SetWindowsHookEx` are **desktop-scoped**: a thread only sees windows on its
  own desktop. A script on the interactive desktop cannot locate the prompt,
  cannot `WM_SETTEXT` a password into it, and cannot post a click to its OK
  button. That is the property this exists for — driving the old GUI headlessly
  was exactly this easy.
- A keylogger or screen-capture hook installed on the interactive desktop
  observes nothing typed here, and the prompt does not appear in a shared-screen
  meeting.

**What it does not buy:** a same-user attacker who can call `SetThreadDesktop`
reaches it. The desktop is owned by this user, so any DACL that lets Myrkr use it
lets them use it — `secdesk_open` therefore passes `NULL` security attributes
deliberately rather than inventing an ACL that would imply a boundary that does
not exist. UAC's desktop is protected because it belongs to Winlogon/SYSTEM, a
context a user-mode process cannot claim. What raises the cost is the
*environment*: reaching another desktop requires direct API calls, which a WDAC
policy with Constrained Language Mode does not let a script host make. The
control is strong in that estate and weaker outside it.

`CreateDesktopW` is called with flags `0`, not `DF_ALLOWOTHERACCOUNTHOOK` — that
flag would let processes of other accounts install hooks on this desktop, the
opposite of the point.

**It fails closed.** If the desktop cannot be created or entered,
`secdesk_prompt` returns `SDR_UNAVAILABLE` and the operation is abandoned with an
explanation; it does not quietly fall back to an ordinary prompt, because a
silent fallback is the control turning itself off at the moment it is needed. The
`SecureDesktop` setting (default 1, and written unconditionally by the MSI —
§15) is the only way to choose the ordinary prompt, and §14.6 states the cost.
It is reachable two ways: the HKLM/HKCU value, and — since 1.0.9 — a **Private
desktop** toggle on the settings panel, which the HKLM value greys out. On a
managed machine the MSI has already written HKLM, so the toggle is inert there
and the installer decision still stands; on a machine nobody managed, HKLM is
absent and there was never anything to weaken.

The prompt is also where the password *is*: `secmem.asm` `VirtualLock`s the
`g_passw`/`g_confirmw` buffers alongside `g_cfg_pass` and `g_key`, so nothing
typed there reaches the pagefile.

**Encrypting, it also carries the output format.** Right-dragging onto a folder
answers where the container goes — that is what dropping on a folder means, and
`ask_output` does not ask again — so the prompt is the only window that gesture
ever opens, and without a Format row on it the choice between a Myrkr container
and a zip could not be made at all on that path. (The main window is created
first but stays **hidden** until the password has been given, then appears to
carry the progress bar. Anything enumerating windows on the interactive desktop
during that gap therefore sees a hidden `myrkr_window` and no prompt at all —
the prompt is on the private desktop — which reads convincingly like a window
that failed to show. It is not; `MYRKR_DBG_NOSECDESK=1` on a `dbg` build is what
makes that gap observable.) The row appears only with
`SDF_CONFIRM` (encrypt); a decrypt has no output format to choose. Three
consequences are wired deliberately:

- The destination is settled *before* the password is asked for, so a format
  changed here has to reach the name already decided under the old one:
  `out_retarget` swaps the extension in place. It replaces only a tail that **is**
  the old format's extension — a name typed into the save dialog is the user's,
  and rewriting it would be this prompt overruling the one before it.
- `sd_update` re-runs on the toggle. A zip with no password is a legitimate
  outcome and a `.mrk` never is, so the format is what decides whether an empty
  password may be accepted; without the re-run, OK would stay disabled on the
  choice that has just made it valid.
- It does **not** `save_setting`. The settings panel holds the default; this is
  one container being written now, and a format picked for a single drag should
  not quietly become what every later drag produces. An HKLM-locked `Format`
  disables the row, so the prompt is not a way around the lock.

---

## 12. Testing and verification

The development method was: implement → cross-check against an independent C
reference with identical logic on the same CPU features → mirror into MASM →
embed the official vector as a startup selftest → review → fix → re-verify.

Verification now stands on four independent gates. §14.5 is the security-facing
synthesis of the same material; this section is the operational detail.

**1. Known-answer selftests.** `myrkr selftest` runs sixteen checks, all
currently passing. Note these run **on demand, not at every launch**: startup is
not gated on them, so a corrupted binary is not caught by merely running it. That
is a deliberate cost tradeoff (the Argon2id vector alone is a full derivation),
not an oversight — but it means `selftest` is only assurance if someone runs it:

1. SHA-256 (FIPS 180-4 `"abc"`)
2. AES-256-GCM (NIST SP 800-38D + round-trip)
3. AES-256-GCM with AAD round-trip
4. AES-256-GCM in-place + tail
5. BLAKE2b (RFC 7693 `"abc"`)
6. Argon2 compression block KAT
7. Argon2id (RFC 9106 test vector)
8. Password policy (length + class rules)
9. Archive path-traversal safety
10. Secret buffers locked (non-pageable) — a property report, not a KAT
11. CRC-32 (`"123456789"` → `0xCBF43926`)
12. SHA-1 (FIPS 180-4 `"abc"`)
13. PBKDF2-HMAC-SHA1 (WinZip-AES, 1000 iterations)
14. Inflate (raw DEFLATE round-trip)
15. AES-128/192/256 ECB (FIPS-197 vectors)
16. Deflate (encode → inflate round-trip)

**2. Fault injection.** A debug build (`build dbg`) exposes
`myrkr redteam <case>`, which deliberately triggers each hardening control and
requires the process to die with the matching `0xFADExxxx` fail-fast code:
`canary`, `shadow`, `dlpv`, `overflow`, `bounds`, `typemagic`, `heaptag`. A
control that had quietly stopped firing is otherwise indistinguishable from one
that was never tested — which matters most for the frame macros, since they are
expanded into every framed procedure and a regression there is invisible until
something needs them.

**3. Static analysis (`tools/`, gated by `build strict`).** Five checkers over
the sources, any finding failing a strict build: `framecheck` (stack-argument
spills overrunning a frame or landing on a live local), `constcheck` (an `equ`
that disagrees between modules, plus the product version across `myrkr.rc`,
`myrkrshell.rc` and the two on-screen strings), `deadcode` (orphaned symbols),
`wstrcheck` (a bounded copy — `wcopy` or `shellext.asm`'s `wapp_lim` — called
without its bound register), `aligncheck` (odd-address wide strings, and
oversized `dup (?)` arrays emitted into `.data`). Each was added after a bug of
that shape got past both the assembler and a careful read; three such bugs are
recorded in §13. `tools/floors.py` records how much each checker inspected and
fails the build if that count collapses, so a checker that stops *looking* cannot
pass as one that found nothing.

All five glob `src/*.asm`, so `shellext.asm` is covered by default — but two of
them needed telling that a second binary exists. `deadcode` allowlists
`DllMain`/`DllGetClassObject`/`DllCanUnloadNow`, which are referenced only from
`build.cmd` and `myrkrshell.def` and are therefore permanently "unreferenced"
rather than pending deletion. `constcheck` reads both `.rc` files, because one
MSI now installs two binaries and a pair reporting different versions is a
support call nobody can answer. `framecheck` is the one gap: it only inspects
`FRAME_PROLOG` procedures, and the DLL has none by design (§3), so its frames —
including `InvokeCommand`'s, which passes ten arguments to `CreateProcessW` — are
sized by hand and commented with the arithmetic.

`tools/make_msi.ps1` adds two package-time gates of the same kind: it refuses a
`myrkrshell.dll` that does not export both COM entry points, and it reassembles
`CLSID_MyrkrDrop` from the *bytes* in `shellext.asm` and compares it against the
CLSID the MSI registers. The second matters because the two live in different
files with nothing linking them; a mismatch registers a class no server
implements, and the only symptom is a menu item that never appears.

**4. Integration testing.** Full encrypt/decrypt/verify round trips,
tamper-every-byte rejection, wrong-password rejection, truncation, large-file
streaming, multi-file and directory archive encrypt/decrypt (byte-identical in
both store and compress modes), auto-named folder extraction, `--compress` on a
9.4 GB checkpoint, `bench` calibration, forged KDF-parameter headers rejected
pre-authentication, and the plaintext ceiling refused at pre-flight (exercised
with a 70 GiB sparse file, so the size check is reached without the I/O). GUI
paths are launched and inspected separately: several procedures the CLI never
reaches — the window procedure, control creation, the owner-draw painters — live
only in `gui.asm`, so a CLI-only pass proves nothing about them.

**Testing needs the CLI the release build no longer has.** Every automated check
above drives encrypt/decrypt through the command line, and §10 removed it. The
verbs therefore survive under `TEST_IO`, and `tests\run.ps1` builds three
flavours in sequence — `dbg` for fault injection, `testio` for the adversarial
crypto suite, then a plain release to leave in `bin\` — asserting at the end that
no test marker remains in the shipping binary. `build.cmd testio` also stamps the
image with a `MYRKR_TEST_IO_BUILD` string, and `tools\make_msi.ps1` refuses to
package a binary carrying it (or the `redteam` marker). The failure mode this
guards against is shipping the test build by accident, which would silently
restore `-p` to production — so the check is in the packager, where a mistake is
caught before it leaves the machine, not only in the test script.

**What the automated tests still cannot do** is type a password into the private
desktop prompt: the window is on another desktop by design, and a harness that
could reach it would disprove the control it is meant to verify. That path is
verified by hand.

**Known gap.** There is no continuous integration and no differential check
against an independent implementation. Cross-checking against a C reference
happened during development (the method described above) but is not re-run
automatically, so the
selftests currently prove the implementation agrees with *itself* and with the
published vectors, not that a future change still agrees with a third party's
reading of the standard.

---

## 13. Engineering notes — notable bugs found and fixed

These are recorded because each represents a real x64/MASM hazard worth
remembering:

- **`/LARGEADDRESSAWARE` addressing.** `[g_sym + reg*scale]` needs an illegal
  32-bit absolute relocation; the rule is `lea reg,[g_sym]` first. Caused early
  access-violation crashes.
- **Incremental-link thunks vs. DLPV.** Incremental linking put a jump thunk in
  front of functions, so `[target-8]` no longer held the landing-pad magic.
  Fixed with `/INCREMENTAL:NO`.
- **Canary self-reference.** `rng_fill` wrote the global canary that its own
  epilog then checked, before the value was stable. Fixed by filling a local and
  publishing afterward.
- **In-place GCM tail.** The streaming tail XOR'd ciphertext into the plaintext
  buffer *before* GHASHing, so in-place decrypt authenticated over plaintext.
  Fixed by building the ciphertext into a separate buffer before overwrite.
- **`and rax, 0FFFFFFFFh` sign-extension.** Used to zero the upper half of a
  register, it is a no-op on a value already in `eax`; corrupted an Argon2
  index. Fixed to `mov eax, r15d` (which zero-extends).
- **Pointer vs. buffer in pack.** `mov rcx, qword ptr [g_out_np]` loaded the
  first 8 bytes of a path *string* as a pointer; fixed to `lea rcx,[g_out_np]`.
- **8 GiB tar ceiling.** The octal size field silently truncated members ≥ 8 GiB.
  Fixed with the GNU base-256 extension (§6.2).
- **Directory headers bypassing compression framing.** `pack_emit_dirhdr` wrote
  its tar header straight to the GCM sink instead of through the compression
  layer, producing a mixed raw/framed stream that only failed on archives
  containing directories. Fixed by routing every tar-level write through the
  `tar_out` dispatcher.
- **XPRESS decompress buffer size.** Block-mode XPRESS does not embed the
  original length; `Decompress` must be told the exact uncompressed size, not a
  capacity. Fixed to pass the frame's `orig_len`.
- **MASM reserved mnemonics.** `XSAVE`/`SS` cannot be labels; `sha256rnds2`
  needs its explicit `xmm0` operand. Both corrected.
- **`/guard:cf` fast-fails a GUI built from hand-written asm.** The GUI exit
  code was `0xC0000409` at startup. Isolated to `/guard:cf` (CET was fine) by
  building `nohw`/`cfg`/`cet` variants and probing with an early `ExitProcess`.
  Hand-written MASM can't emit CFG metadata, and the OS CFG-checks our callback
  pointers against an absent table. Fixed by building the GUI with `/CETCOMPAT`
  only (§11).
- **GUI overwrite prompt before validation.** The "overwrite?" dialog ran before
  the password policy was checked, so it appeared even when the operation could
  not proceed. Fixed by moving all validation ahead of the overwrite check.
- **Cleanup exit-code clobber.** Command cleanup paths overwrote the saved exit
  code with `mem_free`'s return value. Restructured to a single zero-initialized
  cleanup that frees unconditionally and preserves the code.
- **Stack-argument spill past a raw frame.** `draw_format_chip` (replaced in
  1.0.9 by `dr_seg`/`draw_format_seg`, which carry the same 80-byte frame and
  the same note) issued a 7-arg
  `RoundRect` from a 48-byte frame. Args 5–7 land at `[rsp+32..48]`, which in
  that frame were the `top` local and **the saved `rbp`** — so `pop rbp` restored
  the constant `8`. Worse, `WINCALL` emits stack arguments *before* register
  arguments, and `top` was also register arg 3: it was overwritten with `8`
  before being loaded, pinning the chip's top edge regardless of what the code
  computed. Three successive commits had "nudged" that geometry without effect.
  Fixed by widening the frame; `tools/framecheck.py` now gates the class.
- **Win32 callees own the caller's home space.** A callee may save registers into
  the 32-byte home area, so any local living there at call time is fair game.
  Thirteen procedures had locals inside their own outgoing-argument region;
  `file_read_exact`/`file_write_all` went further and aliased `ReadFile`'s
  `lpNumberOfBytesRead` with the `lpOverlapped = NULL` slot, which is correct
  only if the callee consumes the argument before writing the count. All widened.
- **A copy helper with no bound.** `wcopy` copied until the source NUL with no
  destination capacity at all, and `gui_main` fed it `argv[i]` — up to
  `MAX_PATH_CHARS` — into a 4096-wchar input slot. Being a `.data?` overflow,
  neither the stack canary nor either shadow stack could see it. Fixed by taking
  the bound in `r8`; `tools/wstrcheck.py` enforces that every call site sets it.
  Register contracts are invisible to the assembler, which is why they need a
  checker rather than a convention.
- **Odd-address wide strings.** A single odd-length `CSTR` shifted every `WSTR`
  after it, and an odd-address wide string handed to a `-W` API can take an
  aligned (SSE) read path and fail with `ERROR_NOACCESS`. The `WSTR` macro now
  emits `even`; `tools/aligncheck.py` gates it.
- **SEH unwinds desynchronize the software shadow stack.** `FRAME_EPILOG` popped
  one entry and fail-fasted unless it matched, but the OS unwinder restores
  `rsp`/`rbp` without touching *our* shadow stack — so an exception unwinding
  through framed procedures left stale entries and killed the next perfectly
  legitimate return. Now it scans down for the frame's own return address and
  resynchronizes; absent from the whole stack still means ROP and still
  fail-fasts.
- **A constant in three spellings.** The SHA-1 context size existed as
  `SHA1_CTX_SIZE` (in `sha1.asm`, which owns the layout, and which nothing used),
  `SHA1CTX` in `zip.asm`, and a bare `96` in `unzip.asm`. Growing the context
  would have silently under-allocated the HMAC scratch in both ZIP paths.
  `constcheck` cannot catch this on its own — it compares constants of the *same
  name* — so the fix is the shared definition, not the checker.
- **Checkers that mis-model the assembler.** Ported from Vordr, `framecheck`
  counted each `add rsp,N` epilogue as a frame shrink (Myrkr's raw procedures
  return that way; Vordr's use `mov rsp,rbp`), driving a running total negative
  and reporting an impossible frame as FATAL. `aligncheck` could not size
  `MAX_ARGS dup (?)`, treated the array as one element, and *manufactured* two
  misalignments that did not exist. A static checker that models the source
  wrongly does not merely miss bugs — it invents them, and the invented ones
  spend the reviewer's attention. Both now resolve `equ` names and `sizeof`, and
  `aligncheck` refuses to report from an offset it could not compute.

Every fix was verified by re-running the on-device selftests and the adversarial
suite (tamper, truncation, wrong-format, wrong-password, empty and multi-block
round-trips), plus the `redteam` fault-injection cases for anything touching the
frame macros.

---

## 14. Security and risk assessment

> **If you are reading only one security document, read
> [`docs/SECURITY.md`](docs/SECURITY.md), not this section.** That one is written
> to be understood without the assembly, states each control beside the test that
> proves it, and lists what is *not* measured. This section is the detailed
> counterpart for a reader who already has the mechanism sections in view.

Mechanism detail lives in §4 (container format + key-check value), §5
(cryptographic design), §6.5–6.6 (archive-safety layering) and §9 (exploit
hardening); this is the synthesis to read alongside them.

### 14.1 Threat model

myrkr protects the **confidentiality and integrity of file contents at rest**
against an adversary who obtains the container (and any number of containers)
but not the password. Concretely, without the password an attacker cannot
recover plaintext, cannot forge or silently modify a container (any change fails
the GCM tag), and cannot meaningfully accelerate guessing beyond paying the full
Argon2id cost per attempt.

A second goal, added deliberately and at a cost: **myrkr should be poor material
for abuse.** A signed, allow-listed encryption tool that takes a password on the
command line is a ready-made bulk-encryption engine for anyone already permitted
to run it. That matters most in exactly the estate myrkr is built for — one where
WDAC and Constrained Language Mode mean an attacker cannot compile their own tool
or run foreign code, so the authorised binaries *are* the available toolset.
Encryption that can be scripted across a fleet is worth more to that attacker
than scripted encryption is to a legitimate user, who is encrypting things one
decision at a time. So the release build has no way to take a password
non-interactively (§10) and types it on a desktop a script cannot reach (§11.1).
myrkr is not a backup tool and will not become one; automation belongs in a
separate program that is not also the one people are asked to trust.

This is misuse *resistance*, not prevention. It raises the cost and removes the
easy path; it does not stop an attacker who can run arbitrary code, and it is not
claimed to.

Out of scope — myrkr does **not** defend against: a compromised endpoint
(keyloggers, malware, a hostile OS) — though see §11.1 for what the private
desktop does take away from a same-desktop keylogger, live-process memory scraping while a key is resident (secrets reaching the
pagefile or a hibernation image *are* defended — §14.2), rubber-hose/coercion,
traffic/metadata analysis (file sizes and the fact that a file is encrypted are
not hidden), and side channels beyond the constant-time measures noted below.
It is a file-at-rest tool, not a secure-channel or anti-forensics tool.

### 14.2 Security properties and guarantees

- **The password is never an argument, and never on the interactive desktop.**
  A release build contains no code that reads a password from the command line
  (§10), so it cannot appear in a process list, a shell history, a scheduled
  task, or an EDR command-line telemetry field. It is typed on a private desktop
  (§11.1), which puts the prompt outside the reach of `FindWindow`/`SendMessage`
  automation and of hooks installed on the interactive desktop. Fails closed.
- **Confidentiality + integrity (AEAD).** AES-256-GCM. The 16-byte tag covers
  the entire 80-byte header (as AAD) and all ciphertext, and is verified
  **before any plaintext is released** (decrypt-then-rename; failure deletes the
  temp, leaving no output — exit 3). Binding the header as AAD means the KDF
  parameters, salt, nonce, archive/compression flags and the KCV cannot be
  altered without detection.
- **Key commitment.** The header stores `SHA-256(key)` truncated to 16 bytes
  (the KCV). Plain AES-GCM is *not* key-committing — a ciphertext can be crafted
  to decrypt under two keys — which enables partitioning-oracle attacks. The KCV
  commits each container to a single key, closing that gap. It also lets a wrong
  password be rejected after one Argon2 derivation instead of a full-file pass,
  without any brute-force speed-up (each guess still pays the KDF). The KCV is an
  early-out *in front of* the real tag check, never a replacement for it.
- **Password hardening.** Argon2id (RFC 9106), memory-hard at 512 MiB default
  (~0.7 s/derivation), with a fresh 32-byte CSPRNG salt per file, so equal
  passwords yield unequal keys and rainbow-table/cross-file attacks do not apply.
- **Randomness fails closed.** Salt and nonce come from
  `BCryptGenRandom(SYSTEM_PREFERRED_RNG)` XOR-mixed with `RDSEED`; if the OS RNG
  fails the operation aborts rather than deriving key material from a weaker
  source.
- **Nonce safety.** A fresh key per file makes the random 96-bit nonce safe — a
  catastrophic (key, nonce) reuse cannot occur across files.
- **Plaintext ceiling enforced.** Within a single container the counter block is
  what must not repeat: past 2³⁹ − 256 bits under one key it wraps and the
  keystream reuses. Because one container is one key, `encrypt` compares the
  input against that bound **before the KDF runs** and refuses (exit 1, nothing
  read, no temp file). For archives the figure checked is the tar stream — a
  512-byte header per entry plus padding to a 512 boundary, which for many small
  files exceeds the content itself — estimated upward so the check can only
  refuse early, never admit a container that would wrap. This is enforced on the
  writing side only: a pre-existing oversized container is already compromised,
  and refusing to open it would cost availability without undoing the reuse.
- **Pre-authentication input validation.** `t_cost` and `m_cost` are read from an
  unauthenticated header — the tag cannot clear until the key exists, and these
  are what produce the key. Both are range-checked before the KDF runs on the
  single-file *and* archive paths, so a hostile container cannot demand a 4 TiB
  allocation or an unbounded derivation from a file nobody has proved they can
  decrypt.
- **Constant-time secret handling.** Tag and password comparisons use
  `ct_memcmp`; AES-NI and PCLMULQDQ are data-independent by construction. There
  are no secret-dependent branches or table lookups in the crypto.
- **Memory hygiene.** `secure_zero` (SSE stores + `mfence`) wipes the key,
  password, derived material and the Argon2 arena before release. The tagged
  heap turns use-after-free and double-free into an immediate `__fastfail`.
- **Secrets are not pageable.** The password and the derived key are
  `VirtualLock`ed at startup (`secmem.asm`), so the kernel may not write them to
  the pagefile or a hibernation image. Wiping alone never covered this: a page
  evicted *before* the wipe leaves a copy the process can no longer reach but
  that outlives it. On exit both are wiped and *then* unlocked — unlocking first
  would reopen the window. `myrkr selftest` reports whether the locks hold, so
  the property is observable rather than asserted. Locking is best-effort by
  design: if it fails even after growing the working set the operation still
  proceeds, because a quota setting must not be able to stop someone decrypting
  their own data. This is the one place the fail-closed rule is deliberately not
  applied, and it is stated rather than buried.

### 14.3 Authentication and output handling (transient-plaintext tradeoff)

Because files are streamed in 1 MiB chunks, GCM cannot verify the tag until the
whole entry is processed. So **unverified plaintext touches disk transiently**
before being deleted on failure — the same property as other streaming AEAD
tools — and what differs between the two container kinds is what NAME it wears
while it does.

A **single-file container** is decoded to `OUTPUT.part` and renamed only after
the tag verifies; on authentication failure or any I/O error the `.part` is
deleted. So a file under the name the user asked for has always been
authenticated. This used to be provided by a whole temporary copy of the
plaintext; a rename in the same directory buys the same property for one
metadata operation.

An **archive** writes each entry under its real name as it goes, deleting the
one it was working on if that entry fails. It has always done this — the tar
walk did too — and it is not free to change: a `.part` per entry is a rename per
file, which at the scale this codebase is being taken to (see
`docs/FORMAT_V5.md`) is a real cost. The consequence, stated rather than
implied: an extraction that fails part way leaves the entries that had already
been verified, so the folder is authentic but SHORT, and an attacker who can
corrupt a container chooses where it stops. Both the CLI and the window say so
explicitly rather than reporting only the cause — `e_pincomplete` and
`m_part_extract`, gated on `g_unpack_partial`.

`verify` authenticates with no output at all and avoids this entirely — for
**both** container kinds. It runs the same GCM stream (the tag is only correct
once every ciphertext byte has passed through it) with the write suppressed, so
no temp file is created and no plaintext, verified or not, reaches disk. That
makes it the right way to check a large archive you do not want to unpack.
Archives were previously refused by `verify` outright, which left the claim above
true only of single-file containers.

### 14.4 Archive-mode safety

When `encrypt` archives multiple inputs or a folder, the ustar stream is inside
the authenticated plaintext, so the whole archive is tag-verified before any
extraction. Decompression (when `--compress` is used) sits **below** tar and
**above** GCM, so the XPRESS decompressor only ever runs on data that already
passed authentication — it never processes attacker-controlled, unauthenticated
bytes. On extraction, entry names are sanitized: absolute paths, drive letters,
and `..` traversal components are rejected, so a crafted archive cannot write
outside the chosen output folder (covered by a dedicated selftest).

### 14.5 Assurance

Every cryptographic primitive is verified against its official test vector on
demand via `myrkr selftest`: SHA-256 (FIPS 180-4), AES-256-GCM (NIST SP 800-38D,
plus AAD and in-place + tail round-trips), BLAKE2b (RFC 7693), Argon2id (RFC
9106) and an Argon2 block KAT, SHA-1, PBKDF2-HMAC-SHA1, CRC-32, AES ECB, inflate
and deflate round-trips, the password-policy rules, and the archive
name-sanitizer's traversal rejection. It also reports one non-KAT property — that
the secret buffers are locked non-pageable — because a silent failure there is a
real weakening. During development each primitive was additionally cross-checked
against an independent C reference on the same CPU before being trusted, and the
build was exercised with an adversarial suite (tamper-every-byte, truncation,
wrong format, wrong password, empty and multi-block round-trips). `__fastfail`
(`int 29h`) terminations are non-continuable and non-catchable, so a detected
corruption cannot be swallowed.

**Fault injection.** A debug build exposes `myrkr redteam <case>`, which
deliberately triggers each hardening control — stack canary, software shadow
stack, DLPV, integer overflow, bounds, type magic, heap tag — and requires the
process to die with the matching `0xFADExxxx` fail-fast code. A control that
stopped firing would otherwise be indistinguishable from one that was never
tested.

**Static analysis.** Five checkers in `tools/` scan the sources for the mistakes
hand-written Win64 assembly invites, and `build strict` fails on any finding:
`framecheck` (a `WINCALL`'s stack-argument spill overrunning a procedure frame or
landing on a live local — the class that silently pinned a `RoundRect` coordinate
and clobbered a saved `rbp`), `constcheck` (an `equ` that disagrees between
modules), `deadcode` (orphaned symbols), `wstrcheck` (a bounded copy called
without its bound register), and `aligncheck` (odd-address wide strings handed to
`-W` APIs, which can fail with `ERROR_NOACCESS`). Each exists because a bug of
that shape got past both the assembler and a careful read. `tools/floors.py`
records how much each checker inspected and fails the build if that count
collapses — a checker that stops *looking* and one that finds nothing otherwise
print the same word.

### 14.6 Known limitations and accepted tradeoffs

- **No automation, and no way to add it back.** There is no unattended encrypt
  or decrypt: no `-p`, no stdin, no environment variable, no response file. This
  is the intended posture (§14.1), but it is a real cost, and it is not a
  tradeoff every deployment would make. Backups, CI pipelines and scheduled jobs
  cannot use myrkr. If you need those, use something else — a build with `-p`
  re-enabled would be a different tool with a different threat model, not a
  configuration of this one.
- **Turning `SecureDesktop` off is a downgrade with a specific price.** Setting
  `MYRKR_SECUREDESKTOP=0`, the HKLM value directly, or — on a machine with no
  HKLM value — the **Private desktop** toggle on the settings panel, moves the
  prompt back to
  the interactive desktop, and with it: the prompt window becomes reachable by
  `FindWindow`/`EnumWindows` from any process in the session, so a script can
  locate it, `WM_SETTEXT` a password into the field and post a click at the OK
  button — unattended encryption is available again to anything already running
  as the user; and keyboard/screen hooks on that desktop can observe what is
  typed, including during a shared-screen call. In exchange you get a prompt that
  works where `CreateDesktopW`/`SwitchDesktop` do not — some session-virtualisation,
  kiosk and remote-assistance stacks — and one that assistive technology can
  reach, since a screen reader on the interactive desktop cannot see the private
  one. That accessibility case is a legitimate reason to set it; convenience is
  not. Leave it at `1` unless a named environment forces the change, and if you
  do set it to `0`, prefer scoping it to the machines that need it rather than
  the estate.
- **The private desktop does not stop a same-user attacker.** It is desktop
  scoping, not a privilege boundary; anything that can call `SetThreadDesktop`
  can follow. §11.1 states the boundary and why no DACL improves it.
- **Transient plaintext on disk** during decrypt (§14.3); `verify` avoids it.
  No longer a *second, complete* copy of an archive: extraction is entry-driven
  and writes only the files asked for.
- **A failed extraction leaves the entries it had already verified.** Each is
  authentic; the set is short. §14.3 and `docs/SECURITY.md` §6.
- **Memory use** is bounded by the Argon2id arena at the chosen `-m` (default
  512 MiB); file data itself is streamed O(chunk), not O(file).
- **64 GiB per ENTRY, while segmentation is off.** AES-GCM's per-key ceiling
  (§14.2) bounds one GCM stream. Since v4 each entry is its own stream, so an
  archive of any total size is fine and only a single input past ~64 GiB is
  refused. Segmented containers (v8, `seg_shift`, the default since 1.0.83)
  remove even that: the ceiling then bounds a segment, capped at 32 GiB by
  `SEG_SHIFT_MAX` — field-proven by a 155.4 GB single entry round-tripped
  against the user's own SHA-256. This bullet said "per container" long after §4.1
  — §4.1 has said otherwise since v4; the two now agree.
- **The Argon2 arena is not `VirtualLock`ed.** It holds key-derivation state, but
  pinning the default 512 MiB is far beyond any reasonable working-set quota, and
  a failed lock would take the feature down with it. It is `secure_zero`ed before
  release. The GCM round keys in the cipher contexts are likewise unlocked —
  worthwhile future work, not a property claimed here.
- **The hybrid binary omits `/guard:cf`** (hand-written assembly cannot emit the
  per-function CFG metadata the OS needs to validate the GUI's callback pointers;
  see §11 and §13). It retains the hardware (CET) and software shadow stacks,
  stack canaries, and DLPV on the crypto path; DLPV is the software forward-edge
  CFG that stands in for `/guard:cf`.
- **Hand-written assembly** has no compiler-provided memory safety. This is
  mitigated by the layered hardening set (§9), the always-on vector selftests,
  and the recorded review history (§13) — but it remains the central residual
  risk and the area most warranting independent review.

---

## 15. Packaging and deployment

Full detail in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md); this is the design
rationale.

`tools/make_msi.ps1` builds a per-machine MSI around `bin\myrkr.exe` and
`bin\myrkrshell.dll` using only components Windows ships — the database is
authored through the WindowsInstaller COM automation and the payload packed with
`makecab`. Requiring WiX to cut a release would undercut the same "no external
dependencies" position the binary itself takes (§1).

**What it owns.** Both binaries in `%ProgramFiles%\Myrkr`, a Start Menu shortcut,
an ARP entry, the `.mrk` ProgId, the context-menu verbs, the drag-drop handler's
CLSID, and any policy value the administrator names. There is no `RemoveFile`
table and there must never be:
MSI removes a component's own files automatically, so `RemoveFile` exists only to
delete things the installer did *not* install — which here means a user's
encrypted containers. Its absence is the safeguard.

**Policy surface.** Most values `load_settings` reads are public MSI properties
(`MYRKR_MINLEN`, `MYRKR_MINCLASSES`, `MYRKR_LOGLEVEL`, `MYRKR_COMPRESS`,
`MYRKR_FORMAT`). Each sits in its own component conditioned on its property, so
an unnamed value is not written. `KdfTime` and `KdfMemory` (1.0.9) are the
exception: `load_settings` reads them and `apply_policy_locks` enforces them from
HKLM, but the MSI has no property for either, so an administrator sets them by
writing the values. Adding the properties is a package change with no code behind
it; until then this list and the settings table are not the same list. That follows directly from §11's HKLM>HKCU
model: the *presence* of an HKLM value is what locks a setting against the user,
so an installer that wrote every default would produce a machine on which nothing
is user-changeable. Components set attribute 256 (64-bit registry view) — without
it an x64 package writes to `WOW6432Node`, the install reports success, and the
policy simply never takes effect.

**`SecureDesktop` is the exception, and is written unconditionally.** Every other
setting is absent unless the administrator asks for it; `MYRKR_SECUREDESKTOP`
defaults to `1` and its component carries no condition, so a plain
`msiexec /i myrkr.msi` produces a machine where the private-desktop prompt is
locked on and a user cannot turn it off. The property it guards is the one that
keeps an authorised Myrkr from being driven by a script (§14.1), and passing
`MYRKR_SECUREDESKTOP=0` opts the estate out — §14.6 states what that costs.

This paragraph used to end "a control that a user can disable from the settings
dialog is not a control", and that is why the panel had no toggle for it. The
position was wrong about which machines it protected. Where an administrator has
made the decision, the HKLM value is present and the toggle is greyed — exactly
as the reasoning wanted. Where nobody has, HKLM is absent, and refusing the
toggle protected nothing; it only made an install-time choice permanently
unrevisitable by the person living with it. Since 1.0.9 the toggle exists and
`settings_apply_locks` disables it from the same lock flag every other policy
value uses. The unconditional component is what makes that safe, and is why it
stays unconditional.

**Association and verbs.** `.mrk` maps to `Myrkr.Container`. The `.mrk` and
`.zip` context verbs are registered under `SystemFileAssociations\<ext>`, which
contributes a verb *without* owning the extension's ProgId — installing Myrkr
must not make it the machine's zip handler. All verbs run the same command line
and rely on `detect_op` (§11) to choose encrypt, decrypt or extract, so the
installer encodes no mode logic of its own. Both the association and the verbs
are opt-out (`MYRKR_NOASSOC`, `MYRKR_NOCONTEXT`).

**Why verification is a separate script.** `tools/verify_msi.ps1` reads the tables
back *and* opens the package as a costed Windows Installer session with
properties set, checking which components would really install. Only the second
pass can catch a wrong component condition or a property missing from
`SecureCustomProperties`: both produce a package that installs cleanly and
silently writes nothing, with every row present and correct. An administrative
install (`msiexec /a`) evaluates none of it.

**What policy binds.** Both front-ends. In the GUI the HKLM pass runs with
`g_loading_hklm` set, which sets `g_lock_*` and disables the control. On the CLI
`apply_policy_locks` re-asserts the enforced values after the option parser runs
— necessary because `wstart` loads HKLM after `parse_cmdline`, which reads as
though policy already wins, while `parse_cmdline` only tokenizes and the real
parsing happens later inside `dispatch`. A flag therefore landed on top of the
policy value, and `--no-policy` bypassed an enforced minimum; found by testing a
real install rather than by reading the code, which looked correct.

Policy is a floor, not a pin: it wins only where the command line is weaker, so a
user may be stricter than required but never laxer. That applies to `MinLen`,
`MinClasses`, `LogLevel` and both KDF costs — a higher Argon2 time or memory is
more work, not less, so a command line asking for more must stand; `Compress` is
pinned, having no graded sense of
"stricter", and `Format` is not re-asserted because no CLI flag sets it.

The limit worth stating: the binary is world-readable in Program Files, so a user
who can run Myrkr can run a copy that never reads the registry. Policy constrains
this installation, not the format.

**Why the registry verbs are gone.** Explorer integration used to be four `%1`
verbs. Windows substitutes `%1` with **one path per launch**, so selecting four
files and invoking the verb started four independent `myrkr.exe` instances: four
password prompts, four single-file containers, no archive. That was recorded here
as an accepted caveat until a live install showed exactly how it reads to a user
— four prompts stacking up, then output that silently contained one file.

Handing a whole selection to a single instance is not something the registry can
express. Two shell-extension registrations do, and they are the same object:
`shellex\ContextMenuHandlers` for a right-click, and `shellex\DragDropHandlers`
for a right-drag, where the menu is populated by the drop target and there is no
registry-only equivalent at all. Both hand over the entire selection as
`CF_HDROP`. That requirement is the entire reason `myrkrshell.dll` exists, and
the two registrations are why one DLL now covers both gestures.

It is a real cost, and it was paid deliberately: the DLL is loaded into
`explorer.exe`, which is the only code in this project running in a process Myrkr
does not own. Three things bound what that buys an attacker. It **does no work** —
`InvokeCommand` builds a command line and calls `CreateProcessW`, so no crypto,
no file I/O and no password handling happen inside Explorer, and the password is
still typed on the private desktop of a separate process (§11.1). It is **one
source file with four imports and two exports**, small enough to read end to end.
And it **fails closed at every step**: a named drop target that is not a
filesystem folder, a path that will not fit, more than 64 items — each declines
`Initialize`, so the verb never appears rather than appearing and doing part of
the job. (A *missing* drop target is no longer a refusal: that is simply the
right-click case, where the output goes beside the source.)

The command line it builds is **quoted, and the trailing backslashes are
doubled**. Quoting alone is nearly enough — a Windows path cannot contain a
quote — but `CommandLineToArgvW`, which is what `gui_main` parses the line with,
treats a run of backslashes immediately before a quote as escaping it. A drive
root is exactly a path ending in a backslash, and this handler is registered on
`Drive` for drag-drop, so the shell hands us that case rather than it being
hypothetical. Undoubled, `"C:\"` yielded a literal quote and left the argument
open, swallowing whatever followed: dragging a drive plus a file produced one
argument instead of two, and `--to "E:\"` absorbed the input path so it vanished
from `argv` entirely. Doubling is the rule the parser implements in reverse.
Dropping the backslash instead would be a *different* bug — `C:` is drive
relative, naming the process's current directory on that drive rather than its
root — so the operation would quietly target somewhere else. Only the run
adjacent to the quote matters; separators inside a path need nothing.

The DLL is installed and registered by the same component, so a registration can
never outlive the file it points at. `MYRKR_NOSHELLEXT=1` opts out of everything:
no registration *and* no DLL on the machine, which is the stronger statement an
administrator who does not want third-party code in Explorer is actually asking
for. `MYRKR_NOCONTEXT=1` drops only the right-click entry, and its component is
conditioned on *both* properties, since those rows name a CLSID whose server is
the DLL.

Where each registration goes is deliberate:

| Registration | Classes | Why |
|---|---|---|
| `DragDropHandlers` | `Directory`, `Drive` | siblings, not parent and child, so `Directory` alone never fires on a drive root; adding their shared parent `Folder` too would offer the verb twice |
| `ContextMenuHandlers` | `*`, `Directory` | every file and every folder — but **not** `Drive`: as a drop *target* a drive is a destination, whereas as a right-click *selection* it would put "encrypt this whole volume" one slip away |

---

## 16. Status and maintenance

The build is feature-complete. A single hybrid `myrkr.exe` (`/CETCOMPAT`, no
`/guard:cf`) is both the CLI and the GUI; it passes all sixteen selftests;
multi-file/folder archive encrypt/decrypt round-trips byte-identical in store and
compress modes including a >8 GiB member; `--store` is the default. In GUI mode it
wraps the same crypto with a threaded progress bar.
Containers are format version 2 (80-byte header with a key-check value): a wrong
password is rejected after one Argon2 derivation (738 ms on a 9.4 GB container),
and the scheme is key-committing. Version 1 containers are not readable by this
build. A single container is capped at AES-GCM's per-key plaintext ceiling
(§14.2); larger inputs are refused at pre-flight rather than encrypted into a
container whose keystream would repeat.

A second binary ships alongside it: `myrkrshell.dll` (§2, §3, §15), the
drag-drop shell extension that lets one right-drag hand a whole selection to a
single Myrkr window. It is driven through the full COM sequence Explorer uses —
`DllGetClassObject` → `CreateInstance` → `QueryInterface` across both vtables →
`Initialize` with a real `CF_HDROP` data object → `QueryContextMenu` →
`InvokeCommand` — and verified to build the right command line for paths
containing spaces, to label the item from the selection's contents, and to
decline (rather than truncate) a selection above the 64-item cap. That harness
is not committed: it is C++ against a live shell, which is a toolchain this
project does not otherwise carry.

**Upgrades must use Restart Manager.** Explorer keeps `myrkrshell.dll` mapped
between uses, so replacing it in place leaves a running Explorer executing the
old code against the new registry entries. The package originally declared
Windows Installer 2.0, which silently disabled Restart Manager and produced
exactly that — and, on one upgrade, three `explorer.exe` hangs. Declaring 4.0
(summary property 14) lets the installer detect the holder, shut it down, swap
the file and restart it; `tools/verify_msi.ps1` gates on the schema being 400 or
higher, because a package with the wrong value looks entirely normal from the
outside. Confirmed on a live upgrade against a mapped DLL: RM opened a session,
reported shutting down the applications holding files in use, and restarted
them, with no reboot scheduled and no hang.

It has since been **installed and exercised inside a real `explorer.exe`**. The
MSI's registration resolves through `CoCreateInstance` by CLSID alone — no path
named anywhere — and loads the Program Files copy; a right-drag of a real
selection onto a folder encrypts and decrypts end to end, with the output in the
drop target rather than beside the source. Two things that only a live install
shows: Explorer keeps the DLL mapped between drags, so replacing the file needs
Explorer restarted (Windows Installer renames the mapped image and writes the new
one, so no reboot is scheduled — but a running Explorer goes on executing the old
code until it is restarted); and the private-desktop password prompt means a
window-enumeration harness on the `Default` desktop cannot see the prompt at all,
which is §11.1 working as designed rather than a fault.

**Build modes.** `build` is the ordinary release build. `build strict` adds the
static-analysis gate (§12) and is the mode to use before committing — it is
currently clean, and keeping it that way is cheaper than re-clearing it later.
`build release` additionally pins the two sources of link nondeterminism, so two
clean builds of the same commit are byte-identical and a published SHA-256 is
worth checking. `build dbg` exposes the `redteam` fault-injection cases.

**Known gaps.** No continuous integration, no differential crypto check against
an independent implementation (§12), and no external security review (§14.6).
The last of these remains the most significant: everything here is
self-assessment.

This manifest is the single source of truth for the project. Any future change
to the container format, cryptographic parameters, hardening set, security
posture (§14), CLI, GUI, or archiving/compression behavior should be reflected
here in the same commit. The same applies to the static-analysis gate: a checker
added to `tools/` without a line in §12 is one nobody will know to run.
