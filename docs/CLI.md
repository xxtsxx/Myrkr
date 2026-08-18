# Command-line reference

`myrkr.exe` is both the window and a command-line tool. Which one you get depends
on the first argument: a known verb (or anything starting with `-`) runs on the
console; anything else — including a dropped file path, and no arguments at all —
opens the window.

---

## 1. Encrypting is not on the command line

**The verbs that need a password refuse to take one as an argument.** In a
release build `encrypt`, `decrypt`, `verify`, `zip` and `unzip` are *recognised*
— they print an explanation and exit 1, rather than being mistaken for a filename
— but they only act in a test build (`build.cmd testio`), which is how the test
suite drives the crypto.

This is a deliberate limit. A signed, allow-listed encryption tool that accepts
`-p` is a ready-made bulk-encryption engine for anyone already permitted to run
it, and in an estate with application control the approved binaries *are* the
attacker's toolset. [`SECURITY.md` §2.2](SECURITY.md) sets out the reasoning and
what it costs.

So encrypting and decrypting happen in the window: right-click a file or folder,
double-click a `.mrk`, or run `myrkr` with no arguments and drop things on it.
The password is typed on Myrkr's own private desktop, so it never reaches a
process list, a shell history or a scheduled task.

---

## 2. What the command line does keep

Everything that takes no password and destroys nothing.

```
myrkr hash  FILE|FOLDER [--json] [-o OUTFILE]
myrkr list  CONTAINER
myrkr selftest
myrkr bench
myrkr --help
```

### An option it does not recognise is refused

An argument beginning with `-` that matches no option is an **error**, named in
the message:

```
$ myrkr hash project --jsonn
error: unrecognized option: --jsonn
       run 'myrkr --help' for the options this command takes.
       to name an input that really does begin with '-', write it as .\-name
```

Before 1.0.72 it became an input **path** instead. Usually that failed with
`error: I/O failure`, which blames the disk for a typo; and if a file of that
name happened to exist, the run *succeeded* with the option silently ignored and
that file quietly included. An option's **value** may still begin with `-` — a
password or a path — because a value is consumed by its own option and never
reaches this check.

### `hash`

Prints `<sha256>  <path>` per file, like `sha256sum`. Given a **folder** it
recurses and prints each path relative to that folder, forward-slash separated.

```
$ myrkr hash project
83ca68be…59b4  docs/guide.md
711a6108…fabe  README.md
0d6e4079…3605  src/main.asm

$ myrkr hash project --json
[
  {"sha256":"83ca68be…59b4","path":"docs/guide.md"},
  {"sha256":"711a6108…fabe","path":"README.md"}
]
```

Output goes to **stdout**, so it redirects and pipes cleanly; progress is drawn
on stderr and never pollutes it. `-o` writes straight to a file instead. Files
come out in filesystem-enumeration order, and the first unreadable file aborts
with a non-zero exit.

### `selftest`

Runs every cryptographic primitive against its official test vector — FIPS-197
for AES, RFC 9106 for Argon2id, plus GCM, SHA-256 and a deflate round-trip — and
exits 0 only if all pass. This is the check to run after a build, an update, or
any time you want the binary to prove itself.

### `bench`

Times the primitives on this machine. Useful for choosing an Argon2 cost that
lands where you want it.

---

## 3. A terminal does not wait

`myrkr.exe` is linked as a Windows-subsystem application, because the same binary
opens windows. A consequence: **your shell prompt returns immediately** while
output still streams to the console.

For scripting, launch it so the parent waits:

```powershell
Start-Process myrkr -Wait -ArgumentList "selftest"
```

```cmd
cmd /c start /wait myrkr selftest
```

…or redirect output to a file, which also makes the caller wait.

---

## 4. Exit codes

| Code | Meaning |
|----:|---------|
| 0 | success |
| 1 | usage error (including a password that fails the policy) |
| 2 | I/O failure |
| 3 | authentication failed — wrong password, or the data was altered |
| 4 | corrupt or invalid container |
| 5 | out of memory |
| 6 | this CPU lacks a required feature (AES-NI / PCLMULQDQ / SSE4.1) |
| 7 | self-test failure |
| 8 | not enough free disk space (checked before anything is written) |
| 9 | the input uses something Myrkr will not act on (e.g. editing a volume set) |
| 10 | partial success |
| 11 | cancelled by the user; the archive was put back |

Exit code 8 comes from a pre-flight: before writing, Myrkr checks the target
drive has room for the output plus a margin, so a large operation never starts
when it cannot finish.

---

## 5. The audit log

**Off by default.** Pass `--log LEVEL` on any command to turn it on. Each
operation — from the window as well as the command line — appends one UTF-8 line
to a text file. No administrator rights and no setup: the default path is
`%LOCALAPPDATA%\Myrkr\myrkr.log`, which is always writable. `--log-file PATH`
overrides it.

| Level | Records |
|---|---|
| `none` *(default)* | nothing |
| `error` | hard failures only — I/O, corrupt, out of memory |
| `warning` | + authentication failures (wrong password or tampering) |
| `full` | + successful operations |
| `debug` | + the input and output **file paths** |

**Paths are recorded only at `debug`**, so by default the log keeps no filename
metadata at all. Lines look like this:

```
2026-06-16 22:50:37  INFO   hash: completed successfully
2026-06-16 22:50:38  WARN   decrypt: authentication failed (wrong password or tampered data)
2026-06-16 22:50:39  ERROR  hash: I/O error
2026-06-16 22:50:40  INFO   encrypt: completed successfully [in=C:\a\b.txt out=C:\a\b.mrk]
```

The file is opened in append mode per event, so concurrent runs interleave
cleanly. An administrator can set the level for every run from the installer
(`MYRKR_LOGLEVEL`, or `MYRKR_DEF_LOGLEVEL` for a changeable default) — see
[`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## 6. Progress

Long operations draw a live bar on **stderr**:

```
encrypting  [############------------]  62%   5734 / 9248 MiB
```

It is suppressed automatically when output is redirected to a file or a pipe, so
captured output stays clean.

---

## 7. Long paths

Every file API used is the Unicode (`*W`) form, and each path is normalised
internally to the extended-length `\\?\` shape, so paths up to the Windows
maximum of 32,767 characters work — far past the legacy 260-character limit.
Drive-absolute (`X:\…`) and UNC (`\\server\share\…`) paths are handled directly;
relative paths resolve through `GetFullPathNameW`. The image also carries a
`longPathAware` manifest.

---

## See also

- [`../README.md`](../README.md) — what Myrkr is and how to use the window.
- [`SECURITY.md`](SECURITY.md) — why the password cannot be an argument.
- [`../manifest.md`](../manifest.md) §10 — how the command table is dispatched,
  and the hardening around it.
