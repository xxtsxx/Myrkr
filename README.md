# Myrkr

**Encrypt a file or a folder on Windows so nobody without the password can read
it — or change it without you finding out.**

Drop something on the window, type a password, and you get one encrypted file.
Double-click that file later, type the password, and you get your data back.

AES-256-GCM with an Argon2id key derivation, in a single executable with no
dependencies beyond what Windows already ships. Written entirely in 64-bit
assembly.

```
myrkr.exe          <- the whole program
```

---

## Contents

- [Install](#install) · [Using it](#using-it) · [What you get](#what-you-get)
- [Splitting across volumes](#splitting-across-volumes) ·
  [ZIP files](#zip-files) · [Settings](#settings)
- [For administrators](#for-administrators) · [For developers](#for-developers)
- [Documentation map](#documentation-map)

---

## Install

Run the MSI. It installs the program, a Start Menu entry, the `.mrk` file
association, and the Explorer integration:

```
msiexec /i myrkr-<version>.msi
```

Every part of that is optional and can be switched off at install time — see
[For administrators](#for-administrators).

To build it yourself, see [For developers](#for-developers).

---

## Using it

### The window

Launch Myrkr and drop files or folders onto it, or use **Add files** /
**Add folder**. Type a password, press **Encrypt**. You get one `.mrk` file.

Give it a `.mrk` file instead — drop it on the window, or double-click it — and
the window opens in decrypt mode: it lists what is inside, and **Decrypt** puts
it back.

An open container is a working view, not just a listing. You can:

- **drag files out of it** into Explorer, and they are decrypted where you drop
  them;
- **drop files into it** to add them;
- **select rows and Remove** to take them out.

### From Explorer

Select any number of files or folders and either **right-click** them or
**right-drag** them onto a folder or drive:

| What you selected | What you get |
|---|---|
| anything | **Myrkr encrypt** |
| all `.mrk` files | **Myrkr decrypt** |
| all `.zip` files | **Myrkr extract** |

The difference between the two gestures is only where the output lands: a
right-drag writes it where you dropped it, a right-click puts it beside the
original. Either way the whole selection goes to **one** window.

### From the command line

`myrkr.exe` is also a command-line tool — `list`, `verify`, `hash`, `selftest`,
`bench` and others. The verbs that need a password **deliberately refuse to take
one as an argument**, so they cannot be scripted; that is a security property,
and [`docs/SECURITY.md`](docs/SECURITY.md) explains what it buys. Run
`myrkr --help` for the full list.

---

## What you get

**One file.** A folder of 76,000 files becomes one `.mrk` container. Its
contents, names, sizes and structure are all inside the encryption — someone
without the password sees a single opaque file.

**Detection, not just secrecy.** Every byte is authenticated. A container that
has been altered — even by one bit, even in its own header — fails to decrypt
rather than producing plausible-looking wrong data.

**A wrong password fails fast.** About 0.7 seconds, not a full read of the file.

**No recovery.** There is no escrow, no back door and no reset. If you forget the
password the data is gone. That is the point, and it is also the most likely way
to lose data with this tool.

**Very large inputs are fine.** Files are streamed in chunks, so memory use does
not grow with the file. Paths up to the Windows maximum of 32,767 characters
work, well past the old 260-character limit.

---

## Splitting across volumes

For media or transfers that will not take one large file, set **File split** in
the settings panel. The presets are 100 MB, 700 MB (CD), 2 GB, 4 GB (FAT32),
25 GB (BD) and 100 GB.

```
folder.part001.mrk
folder.part002.mrk
...
```

Hand **any** part to Myrkr — double-click it, drop it on the window — and the
whole set is reassembled. The set is found from the part numbers inside the
files, not from their names, so which one you pick makes no difference.

The size is a **ceiling, not a request for a set**: a container that fits inside
it is written as one ordinary file, with no part number and no restriction on
editing it. Setting 100 MB and encrypting 50 MB gives you `thing.mrk`.

A set is *not* a different kind of encryption — it is the same container with
cuts in it, so it has exactly the same integrity properties. Three things are
refused rather than guessed at: a **missing final part**, **editing a set**, and
**more than 4096 parts**. Details in [`docs/VOLUMES.md`](docs/VOLUMES.md).

---

## ZIP files

Myrkr also reads and writes **WinZip-AES** `.zip` archives, so it can exchange
encrypted data with tools that do not know about `.mrk`:

- `unzip` extracts AES-128/192/256 zips made by 7-Zip, WinZip and others;
- setting **Format → Zip** produces an encrypted zip instead of a container.

A zip is the interoperable option rather than the strong one; what differs is in
[`manifest.md`](manifest.md).

---

## Settings

The gear in the command bar opens the settings panel:

| Setting | What it does |
|---|---|
| **Private desktop** | Type the password on a desktop other programs cannot reach. On by default. |
| **Compress** | Shrink before encrypting. Automatic under 50 MiB, off above it. |
| **Format** | `.mrk` container, or WinZip-AES `.zip`. |
| **File split** | Ceiling on the size of one output file. |
| **Log level** | How much goes to the audit log. |
| **Password policy** | Minimum length, and how many character classes are required. |
| **Argon2 cost** | Time and memory spent turning the password into a key. |

Your choices are remembered per user. An administrator can deploy different
starting values, or lock a setting outright — see below.

---

## For administrators

Everything is set from the MSI command line. There are two separate surfaces,
and the difference matters:

```
msiexec /i myrkr.msi /qn MYRKR_DEF_FORMAT=1     <- Zip by default, user may change it
msiexec /i myrkr.msi /qn MYRKR_FORMAT=1         <- Zip, and the control is locked
```

- `MYRKR_DEF_*` writes a **starting value**. The user can change it, and their
  change sticks.
- `MYRKR_*` writes **policy**. The value is enforced and the control is greyed
  out.

The Explorer integration, the file association and the shell extension can each
be suppressed (`MYRKR_NOCONTEXT=1`, `MYRKR_NOASSOC=1`, `MYRKR_NOSHELLEXT=1`).
The full property table, what each value costs, and how to set policy without the
MSI: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## For developers

From an **x64 Native Tools Command Prompt for VS**:

```
build              build it
build strict       fail on any static-checker finding
build release      reproducible: two clean builds of a commit are identical
build dbg          instrumented, for the test suites
```

No third-party dependencies. Six static checkers gate `build strict`: stack
frames, mirrored constants, dead code, string bounds, alignment, and the shape of
every Windows call.

Tests: `tests\run.ps1` runs the two security suites; `tests\README.md` lists the
feature tests and what each one asserts.

---

## Documentation map

| Read this | For |
|---|---|
| [`docs/SECURITY.md`](docs/SECURITY.md) | **Start here for anything security-related.** Threat model, what is and is not defended, every hardening control with the test that proves it, and an honest residual-risk list. |
| [`manifest.md`](manifest.md) | The technical reference: container format, cryptographic construction, module map, engineering notes. |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Installing across an estate — every MSI property, policy versus default, and the registry surface. |
| [`docs/VOLUMES.md`](docs/VOLUMES.md) | Splitting a container across several files. |
| [`docs/security-testing.md`](docs/security-testing.md) | The security test plan and its results. |
| [`tests/README.md`](tests/README.md) | Every test, and what it asserts. |
| [`docs/`](docs/) | Design records for individual features — drag and drop, the container view, the settings panel. Each records what was built, what was tried and rejected, and why. |
| [`CHANGES.md`](CHANGES.md) | Every release, with the reasoning behind each change. |

---

## Status

A personal project, maintained. See [`CHANGES.md`](CHANGES.md) for the current
version and the release history.
