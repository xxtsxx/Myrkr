# A DEPLOYED DEFAULT IS NOT A POLICY.
#
# Myrkr has always had one HKLM key, and the PRESENCE of a value in it locks the
# setting against the user. That is right for policy and wrong for an
# administrator who only wants Zip to be the default on a new machine - asked
# for on 2026-08-13.
#
# There are two keys now and they must not blur into each other:
#
#   HKLM\SOFTWARE\Myrkr\Defaults\<V>  sets the value, locks nothing
#   HKLM\SOFTWARE\Myrkr\<V>           sets the value AND greys the control
#
# So this asserts the DIFFERENCE, not just that a value arrives. Both halves
# would pass a test that only checked the value: the interesting question is
# whether the control is still the user's to change, and that is read from the
# control's own WS_DISABLED bit (see greytest for why that bit and not
# IsWindowEnabled).
#
# NEEDS ELEVATION to write HKLM. Skips rather than fails without it, because a
# suite that cannot run is not the same as a product that is broken.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$fail = 0

$elevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
    "defaultstest: SKIPPED - needs elevation to write HKLM\SOFTWARE\Myrkr"
    exit 0
}

"building dbg..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public struct RC { public int l,t,r,b; }
public class D {
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
  [DllImport("user32.dll")] public static extern IntPtr PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h,int i);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h,out RC r);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h,IntPtr dc);
  [DllImport("gdi32.dll")]  public static extern uint GetPixel(IntPtr dc,int x,int y);
  public delegate bool EW(IntPtr h,IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EW cb,IntPtr l);
  public static IntPtr Find(uint pid,string cls){ IntPtr r=IntPtr.Zero;
    EnumWindows(delegate(IntPtr h,IntPtr q){ uint p; GetWindowThreadProcessId(h,out p);
      if(p!=pid||!IsWindowVisible(h)) return true; var c=new StringBuilder(128); GetClassName(h,c,128);
      if(c.ToString()==cls){ r=h; return false; } return true;},IntPtr.Zero); return r; }
}
"@

$POLICY   = "HKLM:\SOFTWARE\Myrkr"
$DEFAULTS = "HKLM:\SOFTWARE\Myrkr\Defaults"
$USERKEY  = "HKCU:\Software\Myrkr"
$ID_FORMAT    = 134
$ID_MENU_HOST = 165             # the settings panel window; the rows are ITS children
$ACCENT   = 0x00B85F00          # CLR_ACCENT, the selected segment's fill
$FMT_W = 58; $FMT_GAP = 4; $FMT_PAD = 4   # gui.asm FMT_SEG_W / _GAP / _PAD
$TRACK    = 0x00332F2B          # CLR_TRACK, the selected fill when LOCKED

# What the window was left holding before this test started, so it can be put
# back: the user's own Format lives in HKCU and this drives the real one.
$savedUser = $null
if (Test-Path $USERKEY) { $savedUser = (Get-ItemProperty $USERKEY -EA SilentlyContinue).Format }
$hadDefaults = Test-Path $DEFAULTS
$savedPolicy = if (Test-Path $POLICY) { (Get-ItemProperty $POLICY -EA SilentlyContinue).Format } else { $null }

function Clear-All {
    Remove-ItemProperty $POLICY   -Name Format -EA SilentlyContinue
    Remove-ItemProperty $DEFAULTS -Name Format -EA SilentlyContinue
    Remove-ItemProperty $USERKEY  -Name Format -EA SilentlyContinue
}

# Open the settings panel and report the Format row: is it locked, and which of
# the two segments is filled with the accent colour?
function Probe {
    Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
    $env:MYRKR_DBG_NOSECDESK = "1"
    $q = Start-Process $exe -PassThru
    $mw = [IntPtr]::Zero
    for ($i=0; $i -lt 100 -and $mw -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 150; $mw = [D]::Find([uint32]$q.Id,"myrkr_window") }
    if ($mw -eq [IntPtr]::Zero) { return $null }
    [void][D]::PostMessageW($mw, 0x0111, [IntPtr]142, [IntPtr]::Zero)   # the gear
    Start-Sleep -Milliseconds 900
    # Through the HOST. The settings rows are children of the panel window, not
    # of the main window, so GetDlgItem($mw, ID_FORMAT) is 0 and always was -
    # which made all four cases report "could not read the Format row" and told
    # us nothing about the feature under test.
    $panel = [D]::GetDlgItem($mw, $ID_MENU_HOST)
    $h = if ($panel -ne [IntPtr]::Zero) { [D]::GetDlgItem($panel, $ID_FORMAT) } else { [IntPtr]::Zero }
    if ($h -eq [IntPtr]::Zero) { Get-Process -Id $q.Id -EA SilentlyContinue | ForEach-Object { $_.Kill() }; return $null }
    $locked = ([D]::GetWindowLongW($h, -16) -band 0x08000000) -ne 0
    # The SEGMENTS' own rects, not halves of the control. Both segments sit at
    # the control's right edge (format_pick measures the same way), so splitting
    # the control down the middle put BOTH of them in the "right" half and
    # reported Zip whichever was selected.
    #
    #   ...label............ [ Myrkr ][gap][ Zip ]|pad|
    $r = New-Object RC; [void][D]::GetClientRect($h, [ref]$r)
    $segL0 = $r.r - ($FMT_PAD + 2*$FMT_W + $FMT_GAP)      # Myrkr, left edge
    $segL1 = $segL0 + $FMT_W
    $segR0 = $segL1 + $FMT_GAP                             # Zip, left edge
    $segR1 = $segR0 + $FMT_W
    # A LOCKED picker still shows which format is selected - it says so in grey
    # rather than accent, so that a locked setting stays readable (gui.asm,
    # fmt_seg_colours). Counting CLR_ACCENT alone therefore read 0 and 0 on the
    # policy case and reported "the value did not take" for a value that had.
    #
    #             selected        unselected
    #   enabled   CLR_ACCENT      CLR_DARK
    #   locked    CLR_TRACK       CLR_DARK
    #
    # So count either fill, and sample the segment's INTERIOR only: the
    # unselected segment is outlined in CLR_TRACK too, and an inset of 4 keeps
    # that border out of the count.
    $dc = [D]::GetDC($h)
    $left = 0; $right = 0
    for ($y = 6; $y -lt $r.b - 6; $y += 2) {
      for ($x = $segL0; $x -lt $segR1; $x += 2) {
        $px = [D]::GetPixel($dc, $x, $y)
        if ($px -eq $ACCENT -or $px -eq $TRACK) {
          if ($x -ge $segL0 + 4 -and $x -lt $segL1 - 4) { $left++ }
          elseif ($x -ge $segR0 + 4 -and $x -lt $segR1 - 4) { $right++ }
        }
      }
    }
    [void][D]::ReleaseDC($h, $dc)
    Get-Process -Id $q.Id -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
    @{ locked = $locked; zip = ($right -gt $left); left = $left; right = $right }
}

New-Item -Path $DEFAULTS -Force | Out-Null
Clear-All

# --- 1. nothing set: the built-in default, and nothing locked ----------------
$a = Probe
if ($null -eq $a) { "  FAIL could not read the Format row at all"; $fail++ }
elseif ($a.locked) { "  FAIL Format is locked with no HKLM value present"; $fail++ }
elseif ($a.zip) { "  FAIL Format defaults to Zip with nothing set"; $fail++ }
else { "  ok   with nothing deployed: Myrkr format, control unlocked" }

# --- 2. a DEPLOYED DEFAULT: value applied, control still the user's ----------
New-ItemProperty $DEFAULTS -Name Format -Value 1 -PropertyType DWord -Force | Out-Null
$b = Probe
if ($null -eq $b) { "  FAIL no Format row with a default deployed"; $fail++ }
elseif (-not $b.zip) { "  FAIL the deployed default did not take (accent L=$($b.left) R=$($b.right))"; $fail++ }
elseif ($b.locked) { "  FAIL a DEFAULT locked the control - that is policy behaviour"; $fail++ }
else { "  ok   a deployed default selects Zip and leaves the control unlocked" }

# --- 3. the user's own choice beats the deployed default --------------------
New-ItemProperty $USERKEY -Name Format -Value 0 -PropertyType DWord -Force | Out-Null
$c = Probe
if ($null -eq $c) { "  FAIL no Format row with an HKCU value"; $fail++ }
elseif ($c.zip) { "  FAIL HKCU did not override the deployed default"; $fail++ }
else { "  ok   and the user's own choice overrides it" }
Remove-ItemProperty $USERKEY -Name Format -EA SilentlyContinue

# --- 4. POLICY still locks --------------------------------------------------
New-ItemProperty $POLICY -Name Format -Value 1 -PropertyType DWord -Force | Out-Null
$d = Probe
if ($null -eq $d) { "  FAIL no Format row with a policy value"; $fail++ }
elseif (-not $d.locked) { "  FAIL the policy key no longer locks the control"; $fail++ }
elseif (-not $d.zip) { "  FAIL the policy value did not take"; $fail++ }
else { "  ok   the policy key still applies AND locks" }

# --- put the machine back ----------------------------------------------------
Clear-All
if ($null -ne $savedPolicy) { New-ItemProperty $POLICY -Name Format -Value $savedPolicy -PropertyType DWord -Force | Out-Null }
if ($null -ne $savedUser)   { New-ItemProperty $USERKEY -Name Format -Value $savedUser -PropertyType DWord -Force | Out-Null }
if (-not $hadDefaults) { Remove-Item $DEFAULTS -Force -EA SilentlyContinue }
Remove-Item Env:\MYRKR_DBG_NOSECDESK -EA SilentlyContinue

""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

""
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "defaultstest: all checks passed"; exit 0 }

# =============================================================================
# MUTATION - applied, run elevated by the user, observed, reverted.
#
#   gui.asm, wstart: delete the deployed-defaults pass (the HKEY_LOCAL_MACHINE /
#   w_regkey_def call to load_settings), leaving the HKCU and policy passes.
#     -> exactly check 2 FAILS: "the deployed default did not take
#        (accent L=129 R=0)" - the Zip segment never fills because the deployed
#        value is never read. Check 1 passes (no Defaults key exists, so the
#        missing pass changes nothing), check 4 passes (the policy pass is
#        untouched), and check 3 passes VACUOUSLY - the user's HKCU choice wins
#        whether or not the default was read first, so it cannot distinguish
#        this mutant. All four outcomes were predicted before the run.
#
#   Recorded 2026-08-15, paying the debt CHANGES.md logged at 1.0.69 ("not
#   mutation-checked ... weaker than this project's usual bar"). Needs an
#   ELEVATED run, which is why it was parked: the harness cannot elevate itself.
# =============================================================================
