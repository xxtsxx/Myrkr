# Myrkr

**Lock a file or a whole folder behind one password, so nobody else can read it
— or change it without you knowing.**

Drop something on the window, type a password, and you get a single encrypted
file back. Double-click that file later, type the password, and your data
returns exactly as it was. That is the entire idea, and everything below is in
service of doing it well and doing it honestly.

```
myrkr.exe          <- the whole program: one file, nothing to install alongside it
```

---

## Why Myrkr

Most encryption you meet is wrapped around something else — a disk, a cloud
account, a messaging app — and you mostly have to trust that the wrapping is
sound. Myrkr is the opposite: a small, self-contained tool that does one thing,
where every part of how it works is written down and can be checked.

- **Your data becomes one sealed file.** A folder of tens of thousands of files
  turns into a single container. The names, the sizes, the folder structure —
  all of it is *inside* the encryption. Someone who finds the file sees one
  opaque blob and learns nothing about what it holds.
- **Tampering is caught, not just hidden.** It is not enough that an attacker
  cannot read your data; they must not be able to alter it and have you accept
  the result. Change one bit of a Myrkr container — anywhere, even in its
  header — and it refuses to open rather than handing back quietly corrupted
  data.
- **There is no way in but the password.** No escrow, no recovery key, no
  vendor back door, no "reset". This is a promise and a warning in the same
  breath: forget the password and the data is genuinely gone.
- **Nothing to trust but the program itself.** One executable, no runtime to
  install, no third-party libraries, no network. It reads your file, writes an
  encrypted one, and stops.
- **Built to stay strong for a long time** — including against the quantum
  computers people worry will break today's encryption. See
  [Built for a quantum future](#built-for-a-quantum-future).

If you want the rigorous version — the threat model, what is *not* protected,
and how each claim was tested — read [`docs/SECURITY.md`](docs/SECURITY.md). It
is written to be understood without reading a line of the code.

---

## Contents

- [Why Myrkr](#why-myrkr) · [Design principles](#design-principles) ·
  [Built for a quantum future](#built-for-a-quantum-future)
- [Install](#install) · [Using it](#using-it) · [What you get](#what-you-get)
- [Splitting across volumes](#splitting-across-volumes) ·
  [ZIP files](#zip-files) · [Settings](#settings)
- [For administrators](#for-administrators) · [For developers](#for-developers)
- [Documentation map](#documentation-map)

---

## Design principles

These are the rules the whole project is held to. They explain not just what
Myrkr does but why it is shaped the way it is.

**One job, done completely.** Myrkr encrypts and decrypts files. It is not a
backup tool, a sync client, or a service, and it does not try to become one.
A tool with a small, fixed purpose is a tool you can actually reason about.

**Fail closed, always.** When anything is wrong — a flipped bit, a truncated
file, a value that does not make sense, a password that does not match — Myrkr
*stops*, with a clear reason, rather than pressing on and producing something
that looks fine but is not. Silence and plausible-but-wrong output are treated
as the worst outcomes, and the design bends over backwards to avoid them.

**Confidentiality and integrity together.** Keeping a secret and detecting
tampering are two halves of the same job. Every byte Myrkr writes is
authenticated, so "nobody can read it" and "nobody can change it undetected"
hold at the same time.

**Hide the shape, not just the contents.** File names, sizes, and folder layout
leak more than people expect. Myrkr puts all of it inside the encryption, so the
container reveals nothing about what it contains.

**No secret ingredients.** The container format and the cryptography are
documented down to the byte. There is no obscurity doing any of the security
work — the password is the only secret, exactly as it should be.

**Defence in depth.** The password is typed on a private desktop other programs
cannot reach; secrets are held in memory that cannot be swapped to disk and are
wiped after use; the program is hardened against whole classes of memory
attacks. No single one of these is load-bearing — they are layers.

**Honest about limits.** The security documentation lists what Myrkr does *not*
protect against as plainly as what it does, and every protective claim is
written next to the test that checks it. A guarantee with no evidence beside it
is marked as such.

**Friction where friction protects you.** The command line deliberately refuses
to take a password as an argument, so encryption cannot be silently scripted
across an estate. Sometimes the secure choice is to make the dangerous thing
harder, not easier.

---

## Built for a quantum future

You may have heard that quantum computers will one day break modern encryption.
That worry is real — but it is far more specific than the headlines suggest, and
Myrkr was designed on the safe side of it.

The quantum threat lands almost entirely on one family of cryptography: the
**public-key** maths behind web-address padlocks, secure messaging, and digital
signatures — the handshakes where two strangers agree on a secret. A future
quantum computer is expected to unpick those handshakes.

**Myrkr does not use any of that.** There are no key exchanges, no public/private
key pairs, no certificates — nothing for the quantum computer's headline trick to
grab hold of. Your key comes from your password and nothing else.

The one thing Myrkr does rely on — a **256-bit AES key** — faces only a much
weaker quantum effect, one that at best cuts a key's strength roughly in half.
A 256-bit key was chosen from the start with exactly this in mind: even halved,
what remains is an amount of guessing no computer, quantum or otherwise, is
expected to get through. The password-scrambling step (Argon2id) rests on the
same solid ground.

So the honest summary is this: **the part of cryptography that quantum computers
are expected to break is not in Myrkr, and the part that is has been sized with
room to spare.** This is not a promise that any specific algorithm is unbreakable
forever — it is a deliberate choice to stand only on the ground widely expected
to survive. The mathematical detail, and the reasoning, is in
[`docs/SECURITY.md`](docs/SECURITY.md#quantum-resistance).

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
| [`docs/SECURITY.md`](docs/SECURITY.md) | **Start here for anything security-related.** Threat model, what is and is not defended, the quantum-resistance reasoning, every hardening control with the test that proves it, and an honest residual-risk list. |
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
