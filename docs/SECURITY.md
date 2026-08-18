# Security and risk

What Myrkr protects, what it does not, and how each claim was checked.

This is the document to read first. It is written to be understood without
reading the assembly. Where a mechanism is summarised here, `manifest.md` has the
full detail and names the file; where a claim is tested, the test is named so you
can run it yourself.

**Every mitigation table in this document lists the evidence beside the claim.**
A control with no test beside it is marked as such. That is deliberate: a
security document that lists intentions alongside measurements is worse than one
that lists fewer things and means them.

---

## 1. What Myrkr is for

Myrkr encrypts files and folders on Windows so that their contents cannot be read
or silently altered by anyone who does not have the password.

It is a **manual tool**. You point it at something, type a password, and it
produces one encrypted container. It is not a backup product, not a sync client,
and not a service.

---

## 2. Threat model

### 2.1 What it defends against

An adversary who **obtains the container** — one of them, or all of them — but
not the password. Against that adversary, Myrkr's claim is:

- they cannot recover the plaintext;
- they cannot alter a container without the change being detected;
- they cannot test passwords faster than paying the full Argon2id cost for each
  attempt, per container;
- they learn nothing from having many containers that they would not learn from
  one (every container has its own random salt, so every container has its own
  key).

This covers the ordinary cases: a stolen laptop, a misplaced USB stick, a backup
that ended up somewhere it should not have, a cloud folder shared wider than
intended.

### 2.2 What it deliberately makes hard — being used *by* an attacker

A signed, allow-listed encryption tool that accepts a password on the command
line is a ready-made bulk-encryption engine for anybody already permitted to run
it. That matters most in exactly the environment Myrkr is built for: one where
application control means an attacker cannot bring their own tools, so the
approved binaries *are* the available toolset.

Encryption that can be scripted across a fleet is worth far more to that attacker
than scripted encryption is to a legitimate user, who encrypts one decision at a
time. So:

- **The shipping build cannot take a password non-interactively.** The five verbs
  that need one refuse `-p` outright. There is no environment variable, no
  response file, no stdin path.
- **The password is typed on a private desktop** by default, which a script
  running in the ordinary session cannot see or send input to.

The cost is real and is accepted: Myrkr cannot be automated, and it will not
grow the ability. Scheduled backups belong in a tool built for that purpose.

### 2.3 What it does **not** defend against

Stated plainly, because a threat model that lists only successes is not one:

| Not defended | Why |
|---|---|
| An attacker who has your password | There is nothing left to protect. |
| Malware running as you, right now | It can read the files before you encrypt them, log the password as you type it, or read the plaintext you just decrypted. Encryption at rest does not address a compromised endpoint. |
| A machine with a hardware keylogger or a hypervisor under it | Out of reach of anything a user-mode program can do. |
| Traffic analysis of the container itself | Its **size** and the fact that it exists are not hidden. Neither are file *counts* or *names* — those live in the encrypted index, so they are hidden from anyone without the password, but the container's overall size is not. |
| Forgotten passwords | There is no recovery, no escrow, no back door. This is a property, not a gap. |
| The plaintext you asked for | Decryption writes plaintext to the destination you chose. From that moment it is an ordinary file with ordinary permissions. |

---

## 3. Cryptographic design, in one page

| Choice | Value | Why |
|---|---|---|
| Cipher | AES-256-GCM | Authenticated encryption: confidentiality and integrity in one construction. Hardware-accelerated (AES-NI + PCLMULQDQ). |
| Key derivation | Argon2id, RFC 9106 | Memory-hard, so a GPU or ASIC buys an attacker much less than it would against a plain hash. |
| Default cost | t = 3, m = 512 MiB | Tuned to roughly 0.6–0.7 s per attempt on a modern desktop. Adjustable; the memory cost is what makes parallel guessing expensive. |
| Salt | 32 CSPRNG bytes per container | A fresh key per container. Two encrypts of the same file with the same password share nothing. |
| Nonces | Counters, never random | A repeated nonce under one key is fatal for GCM. A counter within a fresh-key container cannot repeat; a random nonce could. |
| Key check | 16 bytes of SHA-256(key) in the header | A wrong password is rejected after one derivation (~0.7 s) instead of a full-file read. It also makes the construction key-committing. |
| Integrity scope | Every byte, including the header | The header is the AAD for the entries, so altering the recorded costs or flags fails the tag rather than changing how the file is read. |

All primitives are validated against official test vectors on demand:

```
myrkr selftest
```

<a name="quantum-resistance"></a>

### 3.1 Quantum resistance

The security of every algorithm above rests on **symmetric** cryptography and
password hashing. Myrkr uses **no public-key cryptography** — no RSA, no
elliptic curves, no Diffie–Hellman, no key exchange, no digital signatures.
This is verifiable rather than asserted: there is no such primitive anywhere in
`src/`, and the container needs none, because the key comes from the password
via Argon2id and nothing is negotiated with a second party.

That matters because the two quantum algorithms of concern are not equal in
reach:

| Quantum algorithm | Breaks | Present in Myrkr? |
|---|---|---|
| **Shor's** | Public-key cryptography (RSA, ECC, DH) — a full break, exponential speed-up | **No such primitive exists in Myrkr.** Nothing for it to attack. |
| **Grover's** | Symmetric ciphers — a *quadratic* speed-up only, i.e. it halves the effective key length | Applies to AES-256, which is sized for it (below). |

**Shor's algorithm is what makes "quantum breaks encryption" frightening**, and
it is confined to public-key systems — the handshakes and signatures Myrkr does
not use. It has no bearing on a Myrkr container.

**Grover's algorithm** is the only quantum result that touches Myrkr's cipher,
and its speed-up is merely quadratic: it reduces a brute-force search from
2²⁵⁶ to about 2¹²⁸ operations for a 256-bit key. 2¹²⁸ is the same security
level AES-128 offers *today* against classical attack — already beyond any
feasible search, and Grover parallelises poorly, which erodes even that
advantage in practice. NIST's own post-quantum guidance treats AES-256 as
appropriate for the quantum era for exactly this reason. The 256-bit key was
chosen with this halving in mind; a 128-bit cipher would have been the
questionable choice, not this one.

Argon2id derives the key from the password and is memory-hard; Grover offers no
special leverage against it beyond the same quadratic factor, and the memory
cost — not the raw operation count — is what dominates the attacker's bill.

**What this is and is not.** This is not a claim that AES-256 is unbreakable, or
that cryptography cannot advance. It is the deliberate, checkable position that
Myrkr stands only on the primitive family widely expected to survive scalable
quantum computers, and sizes it with margin. If that expectation ever changes,
the fix is a larger symmetric key inside the same format — not a change of
cryptographic species, because the species vulnerable to Shor was never here.

---

## 4. Exploit hardening — claim, mechanism, evidence

Myrkr is hand-written assembly with no C runtime. That removes a large class of
library bugs and takes away the compiler's safety features at the same time, so
the equivalents are implemented explicitly.

**Each row below was fault-injected**: the instrumented build has a `redteam`
command that deliberately violates the control and asserts the process dies with
that control's exact code. Run it with `python tests\redteam.py bin\myrkr.exe`
after `build dbg`.

| Control | Mechanism | Evidence |
|---|---|---|
| Stack canaries | Per-process random cookie (CSPRNG ⊕ `rdtsc`), planted at `[rbp-8]` by `FRAME_PROLOG` and verified by `FRAME_EPILOG` in every non-leaf procedure | `redteam canary` → `FF_STACK_COOKIE` ✔ |
| Software shadow stack | A parallel return-address stack, per thread, in a region with guard pages either side; every epilogue verifies its own return address is on it | `redteam shadow` → `FF_SHADOW_STACK` ✔ |
| Hardware shadow stack | Linked `/CETCOMPAT` (Intel CET) | `dumpbin /headers` reports **CET compatible** ✔ |
| Forward-edge guard (DLPV) | An 8-byte landing-pad magic before each of **our own** indirect-call targets; `CALL_GUARDED` validates it before transferring | `redteam dlpv` → `FF_GUARD_ICALL` ✔ — see the scope note below |
| Integer overflow | `CHECK_ADD_OVF` on size arithmetic that could wrap | `redteam overflow` → `FF_OVERFLOW` ✔ |
| Bounds checking | `BOUND_CHECK` before indexed access in parsing paths (14 sites) | `redteam bounds` → `FF_BOUNDS` ✔ |
| Type confusion | 32-bit type magic on the heap block header, checked on access | `redteam typemagic` → `FF_TYPE_MAGIC` ✔ |
| Use-after-free / double-free | Tagged heap: header {magic, size, generation, canary} plus a trailing canary; freed blocks poisoned `0xDD` and the generation bumped | `redteam heaptag` → `FF_HEAP_TAG` ✔ |
| IAT lockdown ("RELRO") | The import address table is made `PAGE_READONLY` immediately after startup, before any user input is parsed | `redteam iat` → access violation on the locked slot ✔ |
| ASLR / DEP / NX | `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` | `dumpbin /headers` reports all three ✔ |
| SEH unwind data | `.pushreg` / `.setframe` / `.allocstack` on every framed procedure | `framecheck` gates the build ✔ |
| Secret erasure | `secure_zero` (volatile stores + fence) on keys, passwords, derived material and the Argon2 arena before release | 34 call sites; no fault-injection case — see §6 |
| Constant-time comparison | `ct_memcmp` for tags and passwords; AES-NI and PCLMULQDQ are inherently constant-time | reasoned, not measured — see §6 |

A violation of any of these terminates the process immediately through
`__fastfail` (`int 29h`) — not an exception, not catchable, no chance to
continue in a corrupted state. The codes are enumerated in one place,
`src/macros.inc`.

### Scope note: what the forward-edge guard covers

Myrkr makes 49 indirect calls. Two of them are its own function-pointer
dispatch, and both are guarded. **The other 47 are COM virtual calls into objects
we did not create** — Explorer's drop target, the shell's file dialogs, the
`IDataObject` on the other end of a drag. You cannot put a landing pad in
somebody else's vtable, so those calls are guarded by the OS's own control-flow
integrity, not by ours.

This is stated because an earlier version of this table said "before every
indirect-call target", which was not true and made the binary sound better
defended than it is.

### Control-Flow Guard is deliberately off

`/guard:cf` needs per-function metadata a hand-written assembler cannot emit, and
because this binary also drives a GUI, the OS control-flow-checks its callback
pointers and fast-fails at load. The DLPV landing pads above are the
hand-rolled equivalent for our own dispatch.

---

## 5. What has been tested, and how

| Suite | What it measures | Run it |
|---|---|---|
| **Self-test** | Every primitive against official vectors (FIPS-197, RFC 9106, GCM, SHA-256, deflate round-trip) | `myrkr selftest` |
| **Phase 1 — adversarial** | GCM and WinZip-AES tamper matrices, salt and nonce uniqueness across many runs, a path-traversal corpus, malformed archives, password policy | `tests\run.ps1` |
| **Phase 2 — fault injection** | Every memory-safety control above, each asserted to fire with its exact code, plus a no-false-positive check | `tests\run.ps1` |
| **Feature tests** | Drag and drop in both directions, the container view, volume sets, counts, settings and their locking, the shell extension, the installer | `tests\README.md` lists all of them |
| **Installer** | 189 checks over the built MSI: every property, component, condition, registry row and sequence | `tools\verify_msi.ps1` |

The feature tests exist because five defects in the drag-and-drop work reached
the user rather than a test — all five built clean and passed every static
checker. What would have caught them was asserting what is *drawn*, or reading a
result back through something that owes the feature nothing. That is now the
house style, and several of those tests record the mutation that proves they can
fail.

---

## 6. Residual risk — the honest list

**Two controls in §4 have no fault-injection case.** `secure_zero` is called at
34 sites and the code is straightforward, but nothing asserts that a key is
actually gone from memory afterwards; that needs a memory-dump harness that does
not exist here. `ct_memcmp` is constant-time by construction and by inspection,
but no timing measurement has been made. Both are believed correct and neither
is *measured*.

**A drag out of a container is not automatically tested end to end.** The
objects on either side of it are (`estreamtest`), but `DoDragDrop`'s own capture
behaviour cannot be driven from a test harness; `docs/DRAG_OUT.md` §4e records
exactly how much logic that leaves uncovered and why four attempts failed.

**Decryption writes plaintext.** Between the moment a file is written and the
moment you remove it, it is an ordinary file. Myrkr authenticates *before* it
hands over the last byte, so a tampered container fails rather than delivering
corrupted output — but bytes already written to your disk cannot be unwritten,
and a failure mid-way leaves a partial file that Myrkr deletes on the paths it
controls.

Until 1.0.71, decrypting an archive wrote a complete decrypted copy of it to a
temporary file first, and extracted from that. **It no longer does**: each entry
is decoded straight into its own output file, so the only plaintext that reaches
your disk is the files you asked for. A single-file container is decoded under a
`.part` name and renamed once its tag verifies, so a file under the name you
asked for has always been authenticated.

**An extraction that fails part-way leaves the files it had already finished.**
Every one of them carries its own authentication tag and was verified before
being written, so nothing on disk is unverified — but the *set* is short. An
attacker who can corrupt a container therefore chooses where the extraction
stops, and so which files you end up with. Myrkr says so — on stderr, and in the
window with a message that replaces the usual cause box precisely because a
folder with files in it reads as a partial success — and exits non-zero. Treat a
run that reported a failure as having produced nothing, whatever is in the
folder. Per-file `.part` naming would close this for archives too, at one rename
per file; it is not done, and this entry exists so the choice is visible rather
than implied.

**Extracting an archive replaces files in the destination, without asking.**
Entries are written with `CREATE_ALWAYS`, so if the output folder already holds a
file whose name an entry matches, the entry wins and the old file is gone. A
*single-file* decrypt does prompt. The asymmetry is real and not principled — an
archive would need the question per file, which the window has no dialog for —
so extract into an empty folder if what is already there matters. Found during
the 1.0.71 audit, where a code comment asserted the opposite.

**The private desktop can be turned off** by policy (`MYRKR_SECUREDESKTOP=0`).
Doing so restores the window-message surface it exists to remove. It is a
supported configuration and it is a real reduction; §14.6 of `manifest.md` says
what it costs.

**There is no key escrow and no recovery.** A forgotten password means the data
is gone. This is intended, and it is the single most likely way to lose data with
this tool — considerably more likely than any attack in §2.

**Reproducible builds are asserted, not notarised.** Two clean builds of a commit
are byte-identical (`build release`, checked by `tools/verify_repro.ps1`), but
nothing is signed by a third party and there is no transparency log.

---

## 7. Reporting a problem

Myrkr is a personal project without a security mailbox. If you find something,
open an issue describing the impact and how to reproduce it. If the finding is
sensitive, say so in the issue without the detail and a private channel can be
arranged.

---

## See also

- [`manifest.md`](../manifest.md) — the technical reference: container format,
  cryptographic construction, module map, and the full risk assessment (§14).
- [`security-testing.md`](security-testing.md) — the test plan behind §5, with
  results.
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — policy and default values an administrator
  can set, and what each one costs.
