# Documentation map

Four kinds of document live here. Knowing which kind you are reading saves time:
the first two are **current reference**, the third is **history**, and the fourth
is **process**.

---

## Start here

| Document | Read it when |
|---|---|
| [`../README.md`](../README.md) | You want to know what Myrkr is and how to use it. |
| [`SECURITY.md`](SECURITY.md) | **Anything security-related.** What is defended, what is not, every hardening control with the test that proves it, and the residual-risk list. |
| [`CLI.md`](CLI.md) | You are at a command prompt: verbs, exit codes, the audit log, and why encrypting is not among them. |
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | You are installing this on more than your own machine: every MSI property, policy versus default, the registry surface. |

## Reference

| Document | Covers |
|---|---|
| [`../manifest.md`](../manifest.md) | The technical reference: design philosophy, build, module map, container format (§4), cryptographic design (§5), archiving (§6), hardening (§9), the GUI (§11), testing (§12), risk assessment (§14), packaging (§15). |
| [`VOLUMES.md`](VOLUMES.md) | Splitting one container across several files — format, naming, the ceiling, and why a set of one is not a set. |
| [`UI_SURFACES.md`](UI_SURFACES.md) | Every action and the surfaces it can be reached from, plus what cannot be driven from a test and why. |
| [`security-testing.md`](security-testing.md) | The security test plan and its measured results. |
| [`FORMAT_V5.md`](FORMAT_V5.md) | **Design only, not built.** How ten million files and entries past 64 GiB would work: segmented entries, a chunked and sorted index, and the phasing. |
| [`V5_WORK.md`](V5_WORK.md) | **The work plan for the above.** Phase order, the exact procs each step touches, how each is proved, and the standing constraints of this codebase. Written to be picked up cold. |
| [`../tests/README.md`](../tests/README.md) | Every test, and what each one asserts. |

## Design records

These document how a feature was built, what was tried and rejected, and what
went wrong on the way. They are **not** kept current with the code — they are the
record of a decision at the time it was made. Where one contradicts the
reference documents above, the reference wins.

| Document | The feature |
|---|---|
| [`DRAG_OUT.md`](DRAG_OUT.md) | Dragging files out of a container to decrypt them. The longest of these, and §4e is the honest account of what a test cannot reach. |
| [`DROP_INDICATOR.md`](DROP_INDICATOR.md) | Showing which folder a drop will land in. |
| [`STAGED_LAYOUT.md`](STAGED_LAYOUT.md) | Dropping into a folder while the archive is still being built. |
| [`ARCHIVE_APPEND.md`](ARCHIVE_APPEND.md) | Adding files to a container that already exists. |
| [`CONTAINER_EDITS_THREADING.md`](CONTAINER_EDITS_THREADING.md) | Moving those edits off the UI thread. |
| [`REMOVAL_PROGRESS.md`](REMOVAL_PROGRESS.md) | A progress bar for removals. |
| [`AFTER_ENCRYPT.md`](AFTER_ENCRYPT.md) | What the window becomes once an encrypt finishes. |
| [`SETTINGS_OPTIONS.md`](SETTINGS_OPTIONS.md) | Putting the remaining options on the settings panel. |

---

## A note on how these are written

Every document here tries to record **why**, not just what — including the things
that turned out to be wrong. Several of them contain a section saying "this was
the theory and it was false", kept deliberately, because the wrong idea is
usually more useful to the next reader than the right one alone.

The same rule applies to the tests: where a check is capable of passing against a
broken build, that is stated rather than left for someone to discover.
