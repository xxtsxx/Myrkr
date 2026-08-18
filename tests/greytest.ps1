# Two facts about greying, both of which have been guessed wrong here before.
#
# 1. A button that is genuinely disabled must LOOK disabled. draw_button decides
#    that, and it is the kind of thing that can break silently: get the test
#    backwards and every button in the program renders enabled forever, with
#    nothing else in the suite to notice.
#
# 2. A button under a MODAL dialog must NOT look disabled - and this is the one
#    that was got wrong. 1.0.61 added a full-window RDW_ALLCHILDREN erase to
#    both modals, on the theory that IsWindowEnabled walks UP the parent chain,
#    so every child of a window disabled for a dialog would paint itself greyed
#    and keep those pixels afterwards.
#
#    IsWindowEnabled does not do that. It reports the window's OWN state. This
#    test asserts it directly: with the main window disabled and a dialog up,
#    the Exit button reads enabled and paints white. The erase was repainting
#    correct pixels with identical correct pixels, and its only visible effect
#    was the flash of every button vanishing and coming back on each dialog
#    close. It is gone; this check is what stops it being reinvented.
#
# The repaint under the dialog is FORCED from here. Nothing invalidates those
# buttons on its own while a dialog sits over them - which is exactly why the
# 1.0.61 theory was untestable, and why the pixel check written for it was
# deleted for passing against its own mutant. An exposure is the trigger, so
# this supplies one rather than hoping for one.
#
# The password prompt is the fixture for (1): its OK starts disabled with an
# empty box and enables on the first keystroke, with no job running and no
# timing to lose. It is also the ACCENT button, whose disabled state is a
# different fill over most of its surface - hundreds of pixels, not a few dozen
# antialiased glyph edges.
#
# Pixels come from each button's own client DC. GetDC, not PrintWindow over
# non-client - docs/UI_SURFACES.md.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "myrkr_greytest"
$PW   = "Correct-Horse-Battery-9"
$fail = 0

# A dbg build, because encrypt is refused on the command line in a release one -
# the container here is only a way to make the password prompt appear.
"building dbg..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public struct RC { public int l,t,r,b; }
public class G {
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h,IntPtr dc);
  [DllImport("gdi32.dll")]  public static extern uint GetPixel(IntPtr dc,int x,int y);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h,out RC r);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h,int i);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool RedrawWindow(IntPtr h,IntPtr a,IntPtr b,uint f);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  public delegate bool EW(IntPtr h,IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EW cb,IntPtr l);
  // EnumWindows and compare the class, NOT FindWindowEx with a class name: these
  // classes do not resolve by name from another process, and FindWindowEx then
  // reports "no such window" rather than failing loudly. volumetest learned it
  // first; this one relearned it.
  public static IntPtr Find(uint pid,string cls){ IntPtr r=IntPtr.Zero;
    EnumWindows(delegate(IntPtr h,IntPtr q){ uint w; GetWindowThreadProcessId(h,out w);
      if(w!=pid||!IsWindowVisible(h)) return true; var c=new StringBuilder(128); GetClassName(h,c,128);
      if(c.ToString()==cls){ r=h; return false; } return true;},IntPtr.Zero); return r; }
}
"@

# What "disabled" LOOKS like on the accent button is the FILL: draw_button picks
# CLR_ACCENT when enabled and CLR_BTN_DARK when not, and the label stays white
# either way. So count those two colours. Diffing the whole face instead is what
# let the first version of this test pass against a deliberately broken build -
# the face also moves for reasons that have nothing to do with being disabled,
# and any difference at all read as success.
#
# GetPixel returns COLORREF (0x00BBGGRR), the same byte order the source uses,
# so these are the constants from gui.asm verbatim.
# CLR_ACCENT_PRESS counts as accent. Both are the ENABLED appearance - the one
# the button wears while a click is held - and which of the two you catch is not
# this test's business: draw_button reaches the pressed shade whenever the
# control reports ODS_SELECTED, and it does so intermittently just after being
# enabled. Insisting on the exact resting shade made this fail two runs in three
# for a reason that has nothing to do with the defect. What the regression is
# about is the DISABLED fill, and that is asserted exactly.
$CLR_ACCENT   = 0x00B85F00
$CLR_ACC_PRESS= 0x00934A00
$CLR_BTN_DARK = 0x003A3A3A

# A STANDARD button (anything but ID_ACTION) keeps its fill and greys its TEXT:
# draw_button picks CLR_WHITE or CLR_PLACEHOLDER. That is what Exit does, so the
# modal check below reads the label rather than the fill.
$CLR_PLACEHOLDER = 0x00969696
$CLR_WHITE       = 0x00FFFFFF

function Label([IntPtr]$h) {
  $f = Settled $h
  if ($null -eq $f) { return $null }
  @{ white = $(if ($f.ContainsKey([uint32]$CLR_WHITE))       { $f[[uint32]$CLR_WHITE] }       else { 0 })
     grey  = $(if ($f.ContainsKey([uint32]$CLR_PLACEHOLDER)) { $f[[uint32]$CLR_PLACEHOLDER] } else { 0 }) }
}

function Ink([IntPtr]$h) {
  $f = Settled $h
  if ($null -eq $f) { return $null }
  $a = 0
  foreach ($c in @($CLR_ACCENT, $CLR_ACC_PRESS)) { if ($f.ContainsKey([uint32]$c)) { $a += $f[[uint32]$c] } }
  @{ accent = $a
     dark   = $(if ($f.ContainsKey([uint32]$CLR_BTN_DARK)) { $f[[uint32]$CLR_BTN_DARK] } else { 0 }) }
}

# Every pixel of the button's face, as a histogram.
function Face([IntPtr]$h) {
  $r = New-Object RC
  [void][G]::GetClientRect($h, [ref]$r)
  $dc = [G]::GetDC($h)
  if ($dc -eq [IntPtr]::Zero) { return $null }
  $acc = @{}
  for ($y = 2; $y -lt $r.b - 2; $y += 1) {
    for ($x = 2; $x -lt $r.r - 2; $x += 1) {
      $p = [G]::GetPixel($dc, $x, $y)
      if ($acc.ContainsKey($p)) { $acc[$p]++ } else { $acc[$p] = 1 }
    }
  }
  [void][G]::ReleaseDC($h, $dc)
  return $acc
}

# A SETTLED capture, not merely a delayed one. draw_button fills the whole item
# rect with the window colour first and draws the rounded fill over it, so a
# capture taken between those two steps sees a uniformly dark button and reports
# neither colour - which is exactly how this test failed once and passed the next
# run with nothing changed. Two identical captures in a row is the only way to
# know the surface has stopped moving; a sleep is a guess.
function Settled([IntPtr]$h) {
  $prev = Face $h
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 150
    $now = Face $h
    if (Same $prev $now) { return $now }
    $prev = $now
  }
  return $null      # never stopped changing - the caller must say so
}

function Same($a, $b) {
  if ($null -eq $a -or $null -eq $b) { return $false }
  if ($a.Count -ne $b.Count) { return $false }
  foreach ($k in $a.Keys) { if (-not $b.ContainsKey($k) -or $b[$k] -ne $a[$k]) { return $false } }
  return $true
}

if (Test-Path $w) { Remove-Item $w -Recurse -Force }
New-Item -ItemType Directory -Path $w | Out-Null
$b = New-Object byte[] 4096
for ($i = 0; $i -lt 4096; $i++) { $b[$i] = [byte]($i % 251) }
[System.IO.File]::WriteAllBytes("$w\f.bin", $b)

& $exe encrypt "$w\f.bin" -o "$w\f.mrk" -p $PW 2>&1 | Out-Null
if (-not (Test-Path "$w\f.mrk")) { "  FAIL could not make a container to open"; exit 1 }

$env:MYRKR_DBG_NOSECDESK = "1"
Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
$q = Start-Process $exe -ArgumentList @("`"$w\f.mrk`"") -PassThru
$sd = [IntPtr]::Zero
for ($i = 0; $i -lt 80 -and $sd -eq [IntPtr]::Zero; $i++) {
  Start-Sleep -Milliseconds 150; $sd = [G]::Find([uint32]$q.Id, "myrkr_secdesk")
}
if ($sd -eq [IntPtr]::Zero) { "  FAIL no password prompt"; exit 1 }
Start-Sleep -Milliseconds 500

$ok  = [G]::GetDlgItem($sd, 104)     # ID_ACTION - starts disabled
$can = [G]::GetDlgItem($sd, 107)     # ID_CANCEL - always enabled
if ($ok -eq [IntPtr]::Zero -or $can -eq [IntPtr]::Zero) { "  FAIL buttons not found"; exit 1 }

# State first, so a pixel result that disagrees with it is reported as such
# rather than quietly read as the other case.
$WS_DISABLED = 0x08000000
$okDis = ([G]::GetWindowLongW($ok, -16) -band $WS_DISABLED) -ne 0
if ($okDis) { "  ok   OK starts with WS_DISABLED set (nothing typed yet)" }
else { "  FAIL OK does not start disabled - the fixture is wrong, not the code"; $fail++ }

# Comparing OK against the Cancel beside it was the other half of the first
# version's mistake: different label, different pixels, always - it could not
# have failed either. What is asserted now is the colour itself.
$inkOff = Ink $ok
if ($null -eq $inkOff) {
  "  FAIL the button's face never settled - no pixel check here can mean anything"; $fail++
} elseif ($inkOff.accent -eq 0 -and $inkOff.dark -gt 200) {
  "  ok   the disabled accent button is filled dark, with no accent left"
} else {
  "  FAIL disabled fill: accent=$($inkOff.accent) dark=$($inkOff.dark) - expected accent=0, dark>200"
  $fail++
}

# Type, which enables OK. The fill must turn accent - same button, same pixels,
# one style bit apart.
$ed = [G]::GetDlgItem($sd, 156)
[void][G]::SendMessageW($ed, 0x000C, [IntPtr]::Zero, $PW)
Start-Sleep -Milliseconds 400
[void][G]::RedrawWindow($ok, [IntPtr]::Zero, [IntPtr]::Zero, 0x105)
Start-Sleep -Milliseconds 300

$okDis2 = ([G]::GetWindowLongW($ok, -16) -band $WS_DISABLED) -ne 0
if ($okDis2) { "  FAIL OK is still WS_DISABLED after typing a password"; $fail++ }
else { "  ok   typing clears WS_DISABLED on OK" }

$inkOn = Ink $ok
if ($null -eq $inkOn) {
  "  FAIL the button's face never settled after typing"; $fail++
} elseif ($inkOn.accent -gt 200 -and $inkOn.dark -eq 0) {
  "  ok   and the accent fill comes back once it is enabled"
} else {
  "  FAIL enabled fill: accent=$($inkOn.accent) dark=$($inkOn.dark) - expected accent>200, dark=0"
  $top = (Face $ok).GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 4
  foreach ($t in $top) { "       dominant: 0x{0:X6} x{1}" -f $t.Key, $t.Value }
  $fail++
}


# ==========================================================================
# A button UNDERNEATH a modal dialog.
#
# The log box is the fixture: it is modal (show_logbox disables the main window
# for its duration, and with nothing logged yet it puts up an mbox that does the
# same) and it opens with the window IDLE, so nothing below it is legitimately
# disabled and every button must still look live. The refusal dialog from
# volumetest would not do - it arrives on a removal, and a removal disables Exit
# on purpose, so a greyed button there would prove nothing.
#
# The enabled=... in the line below is the whole point: the parent is disabled
# and the child still reads enabled. That single fact is what 1.0.61 assumed the
# opposite of.
# ==========================================================================
[void][G]::SendMessageW($sd, 0x0111, [IntPtr]104, [IntPtr]::Zero)     # OK
$mw = [IntPtr]::Zero
for ($i = 0; $i -lt 100 -and $mw -eq [IntPtr]::Zero; $i++) {
  Start-Sleep -Milliseconds 150; $mw = [G]::Find([uint32]$q.Id, "myrkr_window")
}
if ($mw -eq [IntPtr]::Zero) { "  FAIL the container did not open in a window"; $fail++ }
else {
  $ex = [G]::GetDlgItem($mw, 107)          # ID_CANCEL - the Exit button
  $inkIdle = Label $ex
  if ($null -eq $inkIdle -or $inkIdle.white -eq 0) {
    "  FAIL Exit is not white-labelled even with no dialog up - fixture is wrong"; $fail++
  } else {
    [void][G]::PostMessageW($mw, 0x0111, [IntPtr]147, [IntPtr]::Zero)  # ID_SCAN -> log box
    # Either window will do. With nothing logged yet, show_logbox puts up an
    # mbox saying so instead of the log itself - and both are modal the same
    # way, by disabling the main window, which is the whole point here.
    $lb = [IntPtr]::Zero; $lbc = ""
    for ($i = 0; $i -lt 80 -and $lb -eq [IntPtr]::Zero; $i++) {
      Start-Sleep -Milliseconds 150
      foreach ($c in @("myrkr_logbox", "myrkr_mbox")) {
        if ($lb -eq [IntPtr]::Zero) { $lb = [G]::Find([uint32]$q.Id, $c); if ($lb -ne [IntPtr]::Zero) { $lbc = $c } }
      }
    }
    if ($lb -eq [IntPtr]::Zero) { "  FAIL no modal window opened"; $fail++ }
    else {
      $mwEn = [G]::IsWindowEnabled($mw)
      $exEn = [G]::IsWindowEnabled($ex)
      if ($mwEn) {
        "  FAIL the main window is NOT disabled under $lbc - wrong fixture for this"; $fail++
      } else {
        "  ok   a modal $lbc is up and the main window is disabled (Exit reads enabled=$exEn)"
      }
      # Force the exposure the bug needs.
      [void][G]::RedrawWindow($ex, [IntPtr]::Zero, [IntPtr]::Zero, 0x105)
      $inkMod = Label $ex
      if ($null -eq $inkMod) {
        "  FAIL Exit never settled under the dialog"; $fail++
      } elseif ($inkMod.grey -gt 0 -or $inkMod.white -eq 0) {
        "  FAIL Exit greyed itself under the dialog: white=$($inkMod.white) grey=$($inkMod.grey)"
        $fail++
      } else {
        "  ok   a button repainted under a modal dialog does NOT grey itself"
      }
      [void][G]::PostMessageW($lb, 0x0111, [IntPtr]104, [IntPtr]::Zero)      # OK
      [void][G]::PostMessageW($lb, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)   # or WM_CLOSE
      Start-Sleep -Milliseconds 600
    }
  }
}

Get-Process -Id $q.Id -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
Remove-Item $w -Recurse -Force -EA SilentlyContinue
Remove-Item Env:\MYRKR_DBG_NOSECDESK -EA SilentlyContinue

""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

""
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "greytest: all checks passed"; exit 0 }
