# Deploying Myrkr

Building and pushing `myrkr.exe` to a fleet: the MSI, the policy properties it
exposes, the file association, and the Explorer context menus.

## Building the package

```
build strict
powershell -ExecutionPolicy Bypass -File tools\make_msi.ps1
powershell -ExecutionPolicy Bypass -File tools\verify_msi.ps1
```

`make_msi.ps1` needs no third-party toolchain — the MSI database is authored
through the WindowsInstaller COM automation and the payload is packed with
`makecab`, both of which ship with Windows. Requiring WiX to cut a release would
undercut the project's "no external dependencies" position.

The version is read from the exe's own version resource, so `myrkr.rc` stays the
single source of truth and the package cannot drift from the binary it wraps.
The script refuses to wrap a `build dbg` binary: that build compiles in the
`redteam` fault-injection verb, and nothing about the file otherwise says which
build it is.

`verify_msi.ps1` is not optional busywork. It does two passes — it reads every
row back, *and* it opens the package as a costed Windows Installer session with
properties set and checks which components would actually be installed. The
second pass is the one that matters: a wrong component condition, or a property
missing from `SecureCustomProperties`, produces an MSI that installs cleanly and
silently writes nothing. Reading rows back cannot detect that, because the rows
are all present and correct, and `msiexec /a` evaluates none of it.

## What the package installs

| | |
|---|---|
| `%ProgramFiles%\Myrkr\myrkr.exe` | the binary |
| `%ProgramFiles%\Myrkr\myrkrshell.dll` | the drag-drop handler, unless `MYRKR_NOSHELLEXT=1` |
| Start Menu shortcut | all users |
| Add/Remove Programs entry | with ProductName and ProductVersion |
| `HKLM\SOFTWARE\Myrkr` values | **only** those named on the command line |
| `.mrk` association | unless `MYRKR_NOASSOC=1` |
| Explorer context menus | unless `MYRKR_NOCONTEXT=1` |
| the drag-drop handler's CLSID | unless `MYRKR_NOSHELLEXT=1` |

It owns nothing else. There is no `RemoveFile` table and there must never be:
uninstall removes only what the installer put there, so a user who removes Myrkr
keeps their containers and their preferences. One `RemoveFile` row aimed at the
wrong directory is all it takes to delete the encrypted files the tool exists to
protect.

The install is **per-machine** and needs elevation. That is the only scope in
which `HKLM` policy and machine-wide associations can be registered, and Program
Files is read-only to standard users. It does not contradict `myrkr.manifest`'s
`asInvoker`, which governs how the program *runs*, never how it is installed.

## Policy properties

Every `HKLM` value `load_settings` reads is exposed as a public MSI property:

```
msiexec /i myrkr-<version>.msi /qn MYRKR_MINLEN=16 MYRKR_MINCLASSES=4 MYRKR_LOGLEVEL=3
```

| Property | Value | Range | Meaning (default) |
|---|---|---|---|
| `MYRKR_MINLEN` | `MinLen` | 1–256 | minimum password length (12) |
| `MYRKR_MINCLASSES` | `MinClasses` | 0–4 | character classes a password must mix; 0 disables the policy (3) |
| `MYRKR_LOGLEVEL` | `LogLevel` | 0–4 | audit-log verbosity: 0 off, 1 error, 2 warning, 3 full, 4 debug — **4 records file paths** (0) |
| `MYRKR_COMPRESS` | `Compress` | 0/1 | force compression on or off, overriding the 50 MiB size-based default (size-based) |
| `MYRKR_FORMAT` | `Format` | 0/1 | output format: 0 = `.mrk`, 1 = WinZip-AES `.zip` (0) |
| `MYRKR_SECUREDESKTOP` | `SecureDesktop` | 0/1 | type the password on a private desktop — **always written, defaults to 1** (see below) |

`tools\make_msi.ps1` prints this same table when it builds the package.

> **Before you plan a rollout test:** the installed binary cannot encrypt or
> decrypt from a command line — there is no `-p`, by design (manifest §14.1).
> `myrkr selftest` is the scriptable health check; anything involving a password
> has to go through the window or the context menu. `make_msi.ps1` refuses to
> package a `TEST_IO` build, so a package that *can* be scripted cannot be
> produced by accident.

**`SecureDesktop` is the one value written whether or not you name it.** Every
other row above is installed only when its property is given, so an unnamed
setting stays user-changeable. This one is unconditional and defaults to `1`,
because it decides whether the password is typed where other processes can
reach it — a control enforced only where an administrator remembered to name it
is not a control. Pass `MYRKR_SECUREDESKTOP=0` to allow the ordinary prompt; the
value is present and locked either way, so the choice is yours, not the user's.
What you give up by setting `0` is itemised in manifest §14.6: the prompt goes
back on the interactive desktop, where any process in the session can find it
with `FindWindow`, push a password into it with `WM_SETTEXT` and click OK — which
restores exactly the unattended-encryption path the rest of this design removes —
and where keyboard and screen hooks can watch it. The one sound reason to set it
is accessibility: a screen reader running on the interactive desktop cannot see
the private one. If that applies, scope the `0` to the machines that need it
rather than to the estate.

**Only the properties you name are written.** That is not a convenience — in
Myrkr the *presence* of an `HKLM` value is what locks the setting against the
user (`load_settings` sets the matching `g_lock_*` for anything it finds while
loading the HKLM pass, and the GUI disables that control). A package that
helpfully wrote every default would hand you a machine where the user can change
nothing.

Values are clamped on read, so a typo degrades to the clamp rather than to
something undefined. They are not validated at build time — they arrive at
install time.

**MSI does not remember properties.** An upgrade that does not repeat them
installs without those components, and the old product's values are removed along
with it. Repeat the full property set on *every* install, upgrades included, or
policy is silently dropped. Deployment tooling normally does exactly that.

**Policy applies at first install, not on a re-run.** Running the *same* package
again over an existing install puts Windows Installer into maintenance mode,
where component conditions are not re-evaluated — properties on the command line
are accepted and ignored, and `msiexec` still exits 0:

```
Product registered: entering maintenance mode
Component: PolMinLen; Installed: Local;  Request: Null;  Action: Null
```

`REINSTALL=ALL REINSTALLMODE=amus` does **not** fix this: it reinstalls
components that are already installed, and a policy component whose property was
absent at first install was never installed to begin with. To change policy on a
machine that already has Myrkr, either deploy a genuinely newer package (a new
ProductCode, which is what `make_msi.ps1` produces on every build, so the upgrade
path replaces the product and re-evaluates conditions), or uninstall and
reinstall with the properties you want:

```
msiexec /x myrkr-<version>.msi /qn
msiexec /i myrkr-<version>.msi /qn MYRKR_MINLEN=16 MYRKR_LOGLEVEL=3
```

Setting the registry values directly (below) also works and is not subject to
any of this.

**A newer package always replaces the binary.** `RemoveExistingProducts` is
scheduled immediately after `InstallInitialize`, so an upgrade uninstalls the old
product *before* files are copied. That placement is deliberate and load-bearing:
MSI only overwrites a **versioned** file when the incoming version is *higher*, so
with the removal scheduled late, rebuilding at an unchanged `FILEVERSION` logged

```
File: C:\Program Files\Myrkr\myrkr.exe;  Won't Overwrite;  Existing file is of an equal version
```

and kept the old binary while reporting success — a shipped fix that silently
does not land. Removing first means the file is gone before `InstallFiles` runs,
so the new binary installs whether or not the version moved. A failure part-way
is covered by rollback, which restores the previous product rather than leaving
nothing installed.

### Bump the version for every release

The early `RemoveExistingProducts` makes upgrades work even at an unchanged
version, but that is a safety net, not a substitute. `ProductVersion` comes from
the binary's own resource, so leaving `FILEVERSION` alone means Add/Remove
Programs, `Win32_Product` inventories and every fleet-management report keep
showing the old number no matter what is actually deployed — the machine is
patched and the audit says otherwise.

Bump `FILEVERSION` **and** `PRODUCTVERSION` in `myrkr.rc`, both string values
beside them, and `s_ab_ver` in `src/gui.asm` (the About box — the only version a
user ever sees). Those four sites cannot reference each other, so
`tools\constcheck.py` compares them and fails a strict build if they disagree.

### What policy binds

An HKLM value binds **both front-ends**.

In the GUI, `load_settings` runs the HKLM pass with `g_loading_hklm` set, which
sets the matching `g_lock_*` and disables that control.

On the CLI, `apply_policy_locks` re-asserts the enforced values after the option
parser has run. That ordering is the whole point: `wstart` loads HKLM after
`parse_cmdline`, which *reads* as though policy already wins, but `parse_cmdline`
only tokenizes — options are parsed later inside `dispatch`, so a flag would
otherwise land on top of the policy value. It did, and `--no-policy` bypassed an
enforced minimum until this was fixed.

Policy is a **floor, not a pin**: it wins only where the request is weaker, so a
user may ask to be stricter than required but never laxer. The example below uses
test-build command lines because they show the two directions compactly; the
shipping binary applies the same floor to the settings dialog, where a user can
raise `min-len` above the policy but not below it.

```
HKLM\SOFTWARE\Myrkr\MinLen = 16   (test build; release has no -p)
myrkr encrypt f -o f.mrk -p "Abcdef123456"                  -> rejected (needs 16)
myrkr encrypt f -o f.mrk -p "Abcdef123456" --min-len 4      -> rejected
myrkr encrypt f -o f.mrk -p "Abcdef123456" --no-policy      -> rejected
myrkr encrypt f -o f.mrk -p "Abcdefghij1234567"             -> accepted
myrkr encrypt f -o f.mrk -p "Abcdefghij1234567" --min-len 24 -> rejected (user asked stricter)
```

`MinLen`, `MinClasses` and `LogLevel` behave this way. `Compress` is pinned
exactly instead — it is not a graded control, so "stricter" has no meaning for
it. `Format` is not re-asserted at all: it selects the GUI's output format and
has no CLI flag to override it.

One thing policy cannot do: the binary lives in Program Files and is readable by
everyone, so a user who can run Myrkr can also run a copy of it that never reads
your registry. Policy constrains this installation, not the algorithm.

### Setting policy without the MSI

The values are ordinary `REG_DWORD`s; the installer is a convenience, not a
requirement:

```
reg add HKLM\SOFTWARE\Myrkr /v MinLen /t REG_DWORD /d 16 /f
```

Use the 64-bit view — a 32-bit `reg.exe` or script writes to `WOW6432Node`, where
the 64-bit `myrkr.exe` never looks. This is the same trap the MSI avoids by
setting component attribute 256.

## File association

`.mrk` is registered to the `Myrkr.Container` ProgId, so double-clicking a
container opens Myrkr's decrypt dialog and Explorer's Type column reads "Myrkr
encrypted container". Pass `MYRKR_NOASSOC=1` to leave associations alone.

Containers get **their own icon**, distinct from the application's:
`myrkr.rc` compiles two icon groups, and `DefaultIcon` points at
`myrkr.exe,1` — the `,N` suffix indexes those groups in resource-id order, so
id 1 is index 0 (the app) and id 2 is index 1 (the container). The context-menu
verbs deliberately keep index 0: a verb names the program that acts, and
"Encrypt with Myrkr" appears on ordinary files and folders, which must not be
labelled as though they were already containers.

Uninstall removes the ProgId and everything under it. There is deliberately no
remove-tree row aimed at the `.mrk` extension key itself — another application
may have added itself there, and deleting a key we do not exclusively own is how
an uninstaller breaks an unrelated program.

What that means in practice, confirmed on a real uninstall: Windows Installer
removes the *value* Myrkr wrote (`.mrk`'s default, pointing at the ProgId) and
then deletes the key **if that leaves it empty**. So on a machine where only
Myrkr claimed `.mrk`, the key does disappear — correctly, since an empty orphan
key is litter. Where another application has also written there, its values
remain and the key survives, which is the case this rule exists for.

## Context menu (right-click)

Right-click any selection of files or folders and one entry appears, named for
what is selected — **Myrkr encrypt**, **Myrkr decrypt** (every item a `.mrk`) or
**Myrkr extract** (every item a `.zip`). The whole selection goes to one Myrkr
window and the output lands beside the source. Pass `MYRKR_NOCONTEXT=1` to skip
it.

This is a **shell extension**, not a registry verb:

| Key | Value |
|---|---|
| `HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Myrkr` | the CLSID |
| `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Myrkr` | the CLSID |

**Why it is not four `%1` verbs any more.** It used to be: *Encrypt with Myrkr*
on `*` and `Directory`, *Decrypt Myrkr file* and *Extract with Myrkr* under
`SystemFileAssociations\<ext>`. Windows substitutes `%1` with **one path per
launch**, so selecting four files and invoking the verb started four independent
`myrkr.exe` instances — four password prompts, four single-file containers, no
archive. That was documented as a caveat and confirmed in testing to be exactly
as confusing as it reads. A `ContextMenuHandler` receives the entire selection
through `CF_HDROP`, so it is the same one-window path as the right-drag menu.

`Drive` is deliberately **not** registered here. As a drag *target* a drive is a
destination, which is harmless; as a right-click *selection* it would put "encrypt
this entire volume" one slip away from a stray click.

The component is conditioned on `NOT MYRKR_NOCONTEXT AND NOT MYRKR_NOSHELLEXT`:
these rows name a CLSID whose in-proc server is `myrkrshell.dll`, so suppressing
the DLL has to suppress them too, or the shell is pointed at a server that was
never installed.

The `.mrk` **association** is separate and unaffected — that governs
double-clicking, not the context menu, and `MYRKR_NOASSOC` still controls it.

## Drag-drop handler (`myrkrshell.dll`)

Right-drag a selection onto a folder or a drive and the menu offers one entry,
named and placed according to what was dragged:

| Selection | Entry | Placement |
|---|---|---|
| anything else | **Myrkr encrypt** | index 0, with a separator beneath it |
| every item a `.mrk` | **Myrkr decrypt** | index 0, with a separator beneath it |
| every item a `.zip` | **Myrkr extract** | at the first separator — i.e. directly below Explorer's own **Extract…** |

A mixed selection, `.mrk` and `.zip` together included, is none of the first two
and falls through to **Myrkr encrypt**.

The placement is chosen by the handler, not by the shell: by the time Explorer
queries a `DragDropHandler` the menu already holds Copy/Move/Create-shortcuts, a
separator and Cancel, so `indexMenu` is deliberately ignored. The `.zip` case
finds the first separator rather than assuming **Extract…** is at index 0; if no
zip handler contributed one, the entry lands at the end of the first group
instead, which is a degenerate menu rather than a wrong one.

One window, the whole selection, output written to the folder you dropped on.
This is the case the `%1` verbs above cannot serve: the right-drag menu is
populated by the **drop target**, not by the dragged file, and only through an
in-process COM handler. The registry has no equivalent, so the feature and the
DLL are one decision.

The handler runs `"[INSTALLDIR]myrkr.exe" "<file>"… --to "<folder>"` and returns.
It does no crypto, no file I/O and no password handling inside Explorer — the
password is still typed on the private desktop of a separate process. It declines
outright (so the menu item never appears) when there is no drop target, when the
target is not a filesystem folder, when a path will not fit its buffer, or when
more than 64 items were dragged.

Registration, all in the component that owns the DLL itself, so it cannot outlive
the file:

| Key | Value |
|---|---|
| `HKLM\SOFTWARE\Classes\CLSID\{7C4A6E10-…}\InprocServer32` | `[INSTALLDIR]myrkrshell.dll`, `ThreadingModel=Apartment` |
| `…\Classes\Directory\shellex\DragDropHandlers\Myrkr` | the CLSID |
| `…\Classes\Drive\shellex\DragDropHandlers\Myrkr` | the CLSID |
| `…\Shell Extensions\Approved` | the CLSID (a value, not a key) |

`Directory` and `Drive` are siblings, not parent and child: a handler registered
only under `Directory` never fires on a drive root, while adding their shared
parent `Folder` as well would offer the verb twice on an ordinary folder. The
`Approved` entry only matters where the `EnforceShellExtensionSecurity` policy is
on — but where it is, an unlisted handler is silently never loaded, which looks
exactly like a handler that does not work. Uninstall removes the CLSID key and
both `DragDropHandlers` entries; it removes only its own *value* from `Approved`,
never that key, which holds every other application's handlers.

**`MYRKR_NOSHELLEXT=1` skips the DLL as well as the registration.** That is
deliberate: an administrator who does not want third-party code loaded into
`explorer.exe` is asking for the binary not to be there, not for it to sit
unregistered in Program Files.

**Uninstall may ask for a restart.** If Explorer still has the DLL loaded,
Windows Installer cannot delete it in place and will schedule the removal — it
says so rather than failing.

### Upgrading: when Explorer actually needs restarting

An upgrade **always rewrites `myrkrshell.dll`**, whatever version it carries.
`RemoveExistingProducts` is sequenced immediately after `InstallInitialize`, so
the old product is uninstalled before `InstallFiles` runs and there is no
existing file for the installer's version comparison to skip. Freezing the
DLL's version between releases would therefore change nothing here — the file
churn is the upgrade sequence, not the version number.

What an upgrade *can* leave behind is an `explorer.exe` still holding the old
image. It need not: the DLL is demand-loaded and Explorer drops it when idle,
so a good deal of the time there is nothing stale and restarting Explorer is
pure disruption for the user.

```
powershell -ExecutionPolicy Bypass -File tools\shellext_mapped.ps1
```

Exit 1 means Explorer has it mapped. **Run this before `msiexec`, not after** —
that is the only moment the answer means anything. Mapped beforehand says the
image Explorer holds is the outgoing one, so restart afterwards
(`-Restart` does it). Mapped only afterwards says Explorer picked the new file
up by itself, and a restart would achieve nothing.

Do not reach for a version comparison instead. A loaded module reports the
version of the file at its path, and the installer has already replaced that
file by the time you would look — a stale mapping and a fresh one give the same
number. Presence, plus *when* you asked, is what separates them.

## Verifying a package before you push it

```
powershell -ExecutionPolicy Bypass -File tools\verify_msi.ps1 -Msi bin\myrkr-<version>.msi
```

Exit code 0 means every structural and behavioural check passed. Run it against
the exact file you intend to distribute, not a rebuild — the point is to check
that artifact.

For a reproducible binary inside the package, build with `build release` first:
it pins the PE timestamp and the PDB path so two clean builds of the same commit
are byte-identical, which is what makes a published SHA-256 worth checking.

## Uninstall

```
msiexec /x myrkr-<version>.msi /qn
```

Removes the binary, the shortcut, the ARP entry, the ProgId, the context-menu
verbs, and any policy values the package installed. It does not touch containers,
`HKCU\SOFTWARE\Myrkr`, or the audit log.
