# Myrkr security-control test plan & results

> This is the **test plan and its results**. For what Myrkr defends against and
> the controls those tests measure, read [`SECURITY.md`](SECURITY.md) first.


This document is both the **test plan** for measuring how effective every
implemented security control is, and a record of the **results** from running
it. It is executable: `tests/secsuite.py` (Phase 1) and `tests/redteam.py`
(Phase 2), orchestrated by `tests/run.ps1`.

## Measurement model

A control's effectiveness is not "is it present" — it is "does it fire on a real
violation, fail closed, and not break legitimate use." Every control is judged
on five axes:

| Axis | Question | Technique |
|------|----------|-----------|
| Presence | Is it compiled/enabled? | PE-header attestation, source scan |
| Efficacy | Does it detect & block the violation it targets? | adversarial / fault-injection tests |
| Fail-closed | On detection, does it abort with no bad output? | exit/fastfail-code + output-hash assertions |
| No false positives | Does legitimate use still work? | round-trip / regression corpus |
| Coverage | Is it applied everywhere it should be? | source static checks, differential builds |

## Test infrastructure

- **Builds.** `B-full` = shipping (`build.cmd`, CET + all software mitigations).
  `B-dbg` = instrumented (`build.cmd dbg`, `/DDBG_TRACE`); in this build
  `ff_trap` encodes the fastfail code into the process exit status as
  `0xFADE<code>`, so a child process's fault can be attributed to the exact
  check that fired regardless of console redirection. `B-dbg` also compiles the
  `redteam` fault-injection command (§Phase 2); the shipping binary does not
  contain it (verified: the `redteam` UTF-16 string is absent from `B-full`).
- **Oracles.** Round-trip identity (SHA-256 of plaintext vs. decrypt(encrypt));
  the built-in `selftest` KAT vectors; independent references
  (`pyzipper`/`zlib`/`cryptography`) for crafting adversarial inputs.
- **Harness.** Python drivers assert on child **exit code**, stdout/stderr, and
  output-file hashes. `tests/run.ps1` runs both phases end to end.

---

## Phase 1 — cryptographic, input-validation & operational controls

Scriptable against the shipping binary (`tests/secsuite.py`).

| ID | Control | Test | Pass criterion |
|----|---------|------|----------------|
| A0 | AEAD / WinZip-AES | `.mrk` and `.zip` encrypt→decrypt round-trip | byte-identical output (no false positive) |
| A1 | AES-256-GCM | flip one byte across each region — header AAD (magic/ver/KDF-params/salt/nonce/KCV), ciphertext, tag | **every** tamper rejected, no correct plaintext ever written |
| A3 | KCV + AEAD / WinZip-AES | wrong password on `.mrk` and `.zip` | exit 3 (AUTH), no plaintext |
| A5 | CSPRNG | encrypt the same file 200× | all 200 salts and all 200 nonces distinct |
| A8 | WinZip-AES | tamper salt / ciphertext / HMAC trailer inside the entry data | exit 3, no plaintext (encrypt-then-MAC, auth before decrypt) |
| C1 | Path-traversal sanitiser (shared `sanitize_name`) | extract a crafted zip (encrypted + plain) whose entries are `../../ABOVE/..`, absolute, and back-slash traversal names | nothing written outside the chosen OUTDIR |
| C2 | Input robustness | 60 truncated / bit-flipped / garbage `.zip` and `.mrk` inputs | no crash/hang — graceful exit 2/3/4 only |
| C4 | Password policy | encrypt with short / single-class / empty passwords | all rejected (non-zero exit) |

PE-header attestation (B10/B5 presence) is checked at build time via `dumpbin`:
Dynamic base, High-Entropy VA, NX, and CET-compatible are all set (CFG is
intentionally absent in the hybrid GUI/CLI image — see manifest §9 / CHANGES).

**Result (latest run): 11/11 checks pass.** Representative detail: A1 detected
44/44 single-byte tampers (8 rejected as malformed header, 36 as auth
failures); A8 3/3; A5 200/200 unique salts and nonces; C1 zero escapes; C2 0
crashes over 60 malformed inputs (26 exit-3, 34 exit-4).

---

## Phase 2 — memory-safety / exploitation-hardening controls

These controls only fire under memory corruption, so they cannot be reached
through the normal CLI. The instrumented build adds a hidden `redteam <case>`
command (`src/redteam.asm`) that commits exactly one violation per invocation in
a child process; `tests/redteam.py` asserts the child terminated with the
**exact** expected fastfail code. Attribution by code proves it was *that*
control — not luck — that caught the violation. A case that returns cleanly
(control failed to fire) is a FAIL.

| Case | Control | Injected violation | Expected |
|------|---------|--------------------|----------|
| `canary` | Stack canary | overwrite the planted canary, run verifying epilog | FF_STACK_COOKIE `0x002` |
| `shadow` | SW shadow stack | corrupt the saved return address, leave canary intact | FF_SHADOW_STACK `0xF001` |
| `dlpv` | DLPV forward-edge CFG | guarded indirect call through a pointer with no landing-pad magic | FF_GUARD_ICALL `0x00A` |
| `overflow` | Integer-overflow check | checked add that carries out of 64 bits | FF_OVERFLOW `0xF005` |
| `bounds` | Bounds check | index ≥ limit | FF_BOUNDS `0xF004` |
| `typemagic` | Struct type tag | type-check a buffer whose magic dword is wrong | FF_TYPE_MAGIC `0xF003` |
| `heaptag` | Tagged heap (temporal) | overflow a live block's user region into its rear canary, then validate | FF_HEAP_TAG `0xF002` |
| `iat` | IAT lockdown (RELRO) | write to an IAT slot after `iat_lockdown` made it read-only | access violation `0xC0000005` |
| _(selftest)_ | No-false-positive | run a benign KAT selftest in the instrumented build | clean exit 0, no spurious fastfail |

**Result (latest run): 9/9 controls measured-effective.** Each case terminated
with its exact expected code (e.g. `canary` → `0xFADE0002`, `bounds` →
`0xFADEF004`, `iat` → `0xC0000005`), and the benign selftest exited 0.

---

## Running it

```powershell
# from the repo root, in a vcvars64 shell
pwsh tests\run.ps1
```

`run.ps1` builds the instrumented binary and runs Phase 2, then builds the
shipping binary and runs Phase 1, printing a combined PASS/FAIL. Individually:

```powershell
build.cmd dbg ; python tests\redteam.py bin\myrkr.exe     # Phase 2
build.cmd     ; python tests\secsuite.py bin\myrkr.exe      # Phase 1
```

Phase 1 runs Argon2id (~0.7 s) hundreds of times (200× for the uniqueness test
alone), so it takes a few minutes.

## Scope & limitations

- The plan tests the documented threat model (manifest §14.1): confidentiality
  and integrity of file contents at rest against an adversary holding the
  container but not the password. It does **not** test out-of-scope threats
  (compromised endpoint, live-memory key scraping, coercion, metadata leakage).
- CET (hardware shadow stack) is measured by PE attestation + the `shadow`
  software-shadow-stack case; it is not separately fault-injected (no portable
  way to force a hardware #CP from user code here).
- Secure-zeroing (D1) and constant-time compare timing (A7) from the broader
  plan are not yet automated here; they require a memory-dump harness and a
  statistical timing rig respectively, and are noted as future work.
- Per the project's testing constraint, password/auth cases are kept minimal
  (one wrong-password assertion per format) rather than large guessing batteries.
