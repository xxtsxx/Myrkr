# Putting the remaining options on the settings panel

**Status: BUILT in 1.0.9.** Decisions below are the user's, taken 2026-08-08.
This was written as a specification first, while screen capture was unavailable and
the layout half could not be checked; it was implemented as written the next session,
once capture came back. Kept as the record of *why* each choice was made — the
reasoning behind the reversed SecureDesktop position and the MiB scale is not
recoverable from the diff. Section 6 is the verification that was actually run, plus
a screenshot that confirmed it.

## 1. What is missing

The panel carries Compress, Format, Log level, Min length and Min classes. Everything
in `g_cfg_*` that a user could reasonably set, and does not appear:

| option | global | range | default | today |
|---|---|---|---|---|
| Argon2 time cost | `g_cfg_t` | `ARGON2_MIN_T`..`ARGON2_MAX_T` (1..16) | 3 | CLI only, not persisted |
| Argon2 memory | `g_cfg_m` | 8192..4194304 KiB (8 MiB..4 GiB) | 524288 (512 MiB) | CLI only, not persisted |
| Private desktop | `g_cfg_securedesk` | 0/1 | 1 | in `g_setrows` with `sr_hwnd = 0` — deliberately no control |

The rest of `g_cfg_*` is not a setting: `in`/`out`/`logfile` are paths, `pass`/`passlen`
is the secret, `json` is a CLI output mode.

## 2. Private desktop: the decision that changed

It was withheld on the reasoning recorded in the manifest — *"a control a user can
switch off is not a control"* — with §15 making `MYRKR_SECUREDESKTOP=0` at install
time the only way to choose the ordinary prompt.

**That is now overruled deliberately:** the toggle goes on the panel, and disables
itself when HKLM pins the value. The reasoning given: if the decision to allow the
ordinary prompt has been made, the user should be able to act on it; where it has
*not* been made, policy is already what stops them. `settings_apply_locks` gives that
for free once the row has an `sr_hwnd` — the lock flag is already set from the HKLM
pass, and the MSI writes `SecureDesktop` unconditionally, so a managed install shows
the control greyed.

**Manifest §14.6 and §15 must be edited in the same commit.** Leaving them asserting
the old position while the code does the opposite is worse than either choice.

## 3. Memory needs a scaled slider

8 MiB..4 GiB is unusable linearly over a 200px track. The slider carries **MiB**,
8..2048, and scales by 1024 into `g_cfg_m`:

- `sr_scale` (dword, 0 or 1 = no scaling) — the stored value is `slider position × scale`
- `sr_unit` (qword, 0 = none) — a suffix drawn after the number
- `sr_step` (dword, added after the fact) — the drag granularity in stops. Even
  scaled, 8..2048 in MiB is 2040 stops over 180px; the answer to "which of these
  is 1408 MiB" is that nobody was aiming for it. 128 was chosen over a
  power-of-two ladder deliberately: a ladder would have spaced the stops evenly
  and put the 512 MiB default at 3/4 of the track instead of 1/4, but it makes
  the track non-linear, and the value under the knob then stops being
  predictable from its position. Linear and coarse won.

Three procs change: `slider_desc` publishes `g_sld_scale`/`g_sld_unit`; `slider_apply`
divides by the scale to place the thumb and multiplies back to store; `draw_slider`
divides for display and appends the unit. About fifteen lines.

The registry and CLI keep the full documented 8192..4194304 KiB — `sr_min`/`sr_max`
are unchanged by this. The UI cap of 2 GiB is a UI cap, exactly as `MinLen` already
drags 8..32 while accepting 1..256 from policy. That distinction is why `sr_smin`/
`sr_smax` exist separately (see CHANGES 1.0.8).

## 4. Layout: three sections, +20px of window

Two columns at x=16 and x=240, 200 wide, and a third full-width section beneath
them so the panel grows as little as possible.

```
General                        Password            (i)
  Compress    (16,30,200,26)     Min length   (240,30,200,40)
  Format      (16,62,200,26)     Min classes  (240,76,200,40)
  Log level   (16,98,200,46)     Private desktop (240,122,200,26)   <- new

Encryption                                          <- new, header (16,158,200,16)
  Time cost   (16,180,200,40)    Memory      (240,180,200,40)       <- both new
```

- `MENU_H` 156 → **228**
- `LV_H` 185 → **205**, so the list bottom (277) clears the panel bottom (272).
  The window is `LV_Y+LV_H+112` tall, so it grows 369 → **389**.
- The class-explanation flyout sits at panel-relative y=144 today, which the taller
  panel now occupies. Move it below the panel: `CRUMB_Y + MENU_H + 4`.

## 5. Plumbing each new row needs

Both KDF rows want the full row, so they persist and can be pinned like the others:

- value names `w_val_kdftime` / `w_val_kdfmem` (`KdfTime`, `KdfMemory`)
- lock and policy globals `g_lock_kdftime`/`g_pol_kdftime` and the memory pair
- an entry each in `g_setrows`, with `sr_hwnd`, `sr_lbl`, `sr_id`, `sr_smin`/`sr_smax`
  and the new `sr_scale`/`sr_unit`

`apply_policy_locks` is **not** table-driven and must not become so casually: its
semantics differ per setting — MinLen, MinClasses and LogLevel are floors (`jbe`
keeps a stricter CLI value), Compress and SecureDesktop are pinned exactly. KDF cost
should be a **floor**, matching the password-policy rows: a higher cost is stronger,
so an administrator's value must not be lowered but may be exceeded.

The MSI does not expose these as properties. HKLM still works — an administrator can
write the values by hand — but adding `MYRKR_KDFTIME`/`MYRKR_KDFMEMORY` to
`tools/make_msi.ps1` (and their assertions to `verify_msi.ps1`, which counts 126)
would make them first-class. That is a separate change.

## 6. How it was verified

Screen capture came back, so the panel was also looked at. It was still checked
structurally first, and that is the part worth keeping: a screenshot shows one window
size on one machine, while the rect checks hold at any. Both ran green.

The structural pass enumerates every child of the host and asserts:

- exactly 12 controls are found - asserted first, because an empty enumeration
  makes every check below vacuously true, and that is exactly what happened on the
  first run: PowerShell resolves members case-insensitively, so a field named `kids`
  shadowed the method `Kids` and the whole structure check passed on nothing
- no two settings controls overlap, except 149/150, which is by design and predates
  this change: the (i) button sits inside the "Password" header's own rect
- every control lies inside the host's client rect
- the host lies inside the window's client rect
- the list VIEWPORT bottom (`g_lay_bot`, 277) is at or below the panel bottom (272).
  Not the list HWND's rect: `lv_apply` sizes that control to the whole tree and clips
  it, so its bottom is 532 and means nothing here.

The behaviour half needs no pixels at all and was tested the way the settings table
was: each of the five sliders driven to both ends and clamping to **its own** range -
`LogLevel` 0..4, `MinLen` 8..32, `MinClasses` 1..4, `Time cost` 1..16, `Memory`
8192..2097152 KiB - read back out of the process, with `KdfMemory` reaching HKCU in
KiB. A row looked up wrongly would have clamped `Time cost` to 4.

One thing the fixture had to be right about: bare files on the command line are the
encrypt path, where the window stays hidden until a password is given, and with HKLM
`SecureDesktop=1` that prompt is on a desktop the harness cannot reach. Browsing a zip
puts up the same window with the same settings host. The first run reported "no main
window" and that is what it meant.

**Not covered on this machine.** The MSI wrote HKLM `SecureDesktop=1`, so the toggle
is greyed here and the flip cannot be exercised. What was verified is the locked half:
the control exists, is disabled, and a `WM_COMMAND` posted straight at the window -
past the disabled control - does not change `g_cfg_securedesk`. The unlocked half
needs a machine with no HKLM `SecureDesktop` value.
