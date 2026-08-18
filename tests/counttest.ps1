# The numbers the window puts on screen have to be reconcilable with Explorer.
#
# That matters here more than it looks. After 1.0.51 turned 76,286 files into
# 16,780 with no error, the file count is the thing a user checks to satisfy
# themselves nothing was lost - so a count that cannot be lined up against the
# folder's properties dialog is not cosmetic, it is the one instrument for
# detecting the next real failure.
#
# Two faults were reported on one line reading "84079 files, 309 B", for a
# 587 GB folder of 76,286 files and 7,792 folders:
#
#  1. THE COUNT WAS ENTRIES, NOT FILES. 76286 + 7792 + 1 = 84079 exactly, the
#     +1 being the archive's own root folder. Explorer counts files and folders
#     separately and Myrkr counted them together while calling them "files", so
#     the two could never agree. The same mismatch drove the progress window's
#     numerator past its denominator: "84000 of 76286 files", because the
#     numerator is the action log's tally, which gets a line per index ENTRY.
#
#  2. THE BYTE TOTAL COVERED ONLY VISIBLE ROWS. It was accumulated inside the
#     row walk, after the check that skips rows whose ancestors are collapsed -
#     and a container opens with its folders shut. So a 587 GB archive reported
#     whatever happened to sit at its top level, and the figure changed every
#     time a folder was opened or closed.
#
# The fixture is built for the second one: almost all of the bytes live inside a
# subfolder, so a visible-only total misses them. Without the nesting this
# passes against the broken build.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "myrkr_counttest"
$PW   = "Correct-Horse-Battery-9"
$fail = 0

"building dbg..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class C {
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,StringBuilder l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,string l);
  [DllImport("user32.dll")] public static extern IntPtr PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  public delegate bool EW(IntPtr h,IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EW cb,IntPtr l);
  public static IntPtr Find(uint pid,string cls){ IntPtr r=IntPtr.Zero;
    EnumWindows(delegate(IntPtr h,IntPtr q){ uint p; GetWindowThreadProcessId(h,out p);
      if(p!=pid||!IsWindowVisible(h)) return true; var c=new StringBuilder(128); GetClassName(h,c,128);
      if(c.ToString()==cls){ r=h; return false; } return true;},IntPtr.Zero); return r; }
  // WM_GETTEXT, not GetWindowTextW - cross-process the latter does not send it
  // and returns the control's creation text. See afterencrypttest's Edit().
  public static string Txt(IntPtr h){ var b=new StringBuilder(512);
    SendMessageW(h,0x000D,(IntPtr)512,b); return b.ToString(); }
}
"@

Remove-Item $w -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory "$w\src\sub\deeper" -Force | Out-Null
# 2 files, 3 folders (src, src\sub, src\sub\deeper). Nearly every byte is two
# levels down, where a visible-only total cannot see it.
[IO.File]::WriteAllBytes("$w\src\top.txt", (New-Object byte[] 309))
$b = New-Object byte[] 5000000
(New-Object Random 3).NextBytes($b)
[IO.File]::WriteAllBytes("$w\src\sub\deeper\big.bin", $b)
$onDiskFiles = (Get-ChildItem "$w\src" -Recurse -File).Count
$onDiskDirs  = (Get-ChildItem "$w\src" -Recurse -Directory).Count + 1   # + the root, which the archive stores
$onDiskBytes = (Get-ChildItem "$w\src" -Recurse -File | Measure-Object Length -Sum).Sum
"on disk      : $onDiskFiles files, $onDiskDirs folders (incl. the root), $onDiskBytes bytes"

# ---- the ENCRYPT side must say the same thing as the container side --------
# Opening the folder to encrypt it and opening the container made from it are
# two different walks, and they used to disagree about the root: size_node
# counts the directories it FINDS, so the folder it was handed was counted by
# nobody, while the archive stores it as an entry like any other. One short in
# the denominator is one MORE in the numerator at the end of a job.
#
# Launched BARE and handed the folder as a drop, not launched with the folder
# as an argument: that route puts a "Save the encrypted container as" dialog up
# first and leaves the window itself hidden behind it, and a common file dialog
# does not take a posted IDOK.
Add-Type -AssemblyName System.Windows.Forms
$env:MYRKR_DBG_NOSECDESK = "1"
Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
$qe = Start-Process $exe -PassThru
$me = [IntPtr]::Zero
for ($i=0; $i -lt 100 -and $me -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 150; $me = [C]::Find([uint32]$qe.Id,"myrkr_window") }
if ($me -eq [IntPtr]::Zero) { "  FAIL no window on a bare launch"; $fail++ }
else {
  $col = New-Object System.Collections.Specialized.StringCollection
  [void]$col.Add("$w\src")
  [Windows.Forms.Clipboard]::SetFileDropList($col)
  Start-Sleep -Milliseconds 400
  [void][C]::PostMessageW($me, 0x8003, [IntPtr]0, [IntPtr]0)
  Start-Sleep -Seconds 3                      # let the indexer walk it
  $sumIn = [C]::Txt([C]::GetDlgItem($me, 147))
  "input line   : '$sumIn'"
  $fIn = if ($sumIn -match '(\d+)\s+files') { [int]$matches[1] } else { -1 }
  $dIn = if ($sumIn -match '(\d+)\s+folders')    { [int]$matches[1] } else { -1 }
  if ($fIn -eq $onDiskFiles -and $dIn -eq $onDiskDirs) {
    "  ok   the input scan agrees with the disk too: $fIn files, $dIn folders"
  } elseif ($dIn -eq $onDiskDirs - 1) {
    "  FAIL the input scan misses the root folder: $dIn, expected $onDiskDirs"; $fail++
  } else {
    "  FAIL input scan says $fIn files / $dIn folders, disk has $onDiskFiles / $onDiskDirs"; $fail++
  }
}
Get-Process -Id $qe.Id -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }

cmd /c "`"$exe`" encrypt `"$w\src`" -o `"$w\c.mrk`" -p $PW 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) { "  FAIL encrypt exit $LASTEXITCODE"; exit 1 }

$env:MYRKR_DBG_NOSECDESK = "1"
Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
$q = Start-Process $exe -ArgumentList @("`"$w\c.mrk`"") -PassThru
$sd = [IntPtr]::Zero
for ($i=0; $i -lt 80 -and $sd -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 150; $sd = [C]::Find([uint32]$q.Id,"myrkr_secdesk") }
if ($sd -eq [IntPtr]::Zero) { "  FAIL no password prompt"; exit 1 }
[void][C]::SendMessageW([C]::GetDlgItem($sd,156), 0x000C, [IntPtr]::Zero, $PW)
Start-Sleep -Milliseconds 300
[void][C]::PostMessageW($sd, 0x0111, [IntPtr]104, [IntPtr]::Zero)
$mw = [IntPtr]::Zero
for ($i=0; $i -lt 100 -and $mw -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 150; $mw = [C]::Find([uint32]$q.Id,"myrkr_window") }
if ($mw -eq [IntPtr]::Zero) { "  FAIL the container did not open in a window"; exit 1 }
Start-Sleep -Milliseconds 900

$sum = [C]::Txt([C]::GetDlgItem($mw, 147))
"summary line : '$sum'"

if ($sum -match '^\s*(\d+)\s+files') { $n = [int]$matches[1] } else { $n = -1 }
if ($n -eq $onDiskFiles) { "  ok   it says $n files, which is what is on disk" }
elseif ($n -eq $onDiskFiles + $onDiskDirs) {
  "  FAIL it counts folders as files: $n = $onDiskFiles files + $onDiskDirs folders"; $fail++
} else { "  FAIL it says $n files, on disk there are $onDiskFiles"; $fail++ }

if ($sum -match '(\d+)\s+folders') { $d = [int]$matches[1] } else { $d = -1 }
if ($d -eq $onDiskDirs) { "  ok   and $d folders, reported separately as Explorer does" }
else { "  FAIL folders reported as '$d', expected $onDiskDirs"; $fail++ }

# The size, which is the half that was visibly wrong. Parsed back to bytes and
# allowed the rounding the display does, but nothing like the shortfall a
# visible-only total produces - here that would be 309 B against 5,000,309.
if ($sum -match '([\d\.]+)\s*(B|KB|MB|GB|TB)\s*$') {
  $v = [double]$matches[1]
  $mult = @{ 'B'=1; 'KB'=1KB; 'MB'=1MB; 'GB'=1GB; 'TB'=1TB }[$matches[2]]
  $bytes = $v * $mult
  $ratio = $bytes / $onDiskBytes
  if ($ratio -gt 0.98 -and $ratio -lt 1.02) {
    "  ok   and a size that accounts for the whole archive ($($matches[1]) $($matches[2]))"
  } else {
    "  FAIL size reads $($matches[1]) $($matches[2]) = $bytes bytes, archive holds $onDiskBytes"
    "       (a collapsed folder's contents are being left out of the total)"
    $fail++
  }
} else { "  FAIL could not read a size out of '$sum'"; $fail++ }

# ---- and it must survive expanding a folder ---------------------------------
# The counts are computed ONCE when the container opens (idx_summarise) rather
# than re-walked on every repaint - that is step A1 of docs/V5_WORK.md, and at
# the sizes that document is about, re-walking per click would mean decrypting
# the whole index per click.
#
# A cache has a failure mode a per-repaint walk does not: filled once and never
# refreshed, or cleared by something that then does not refill it. Expanding a
# folder is the cheapest way to make the window redraw its rows, so the summary
# is read again afterwards and must be IDENTICAL. Without this the accounting
# could move back inside the row walk and no check would notice.
[void][C]::PostMessageW($mw, 0x0111, [IntPtr]147, [IntPtr]::Zero)   # nudge a redraw
Start-Sleep -Milliseconds 300
$lv = [C]::GetDlgItem($mw, 109)
if ($lv -ne [IntPtr]::Zero) {
  [void][C]::PostMessageW($lv, 0x0100, [IntPtr]39, [IntPtr]::Zero)  # VK_RIGHT: expand
  Start-Sleep -Milliseconds 500
}
$sum2 = [C]::Txt([C]::GetDlgItem($mw, 147))
if ($sum2 -eq $sum) { "  ok   and it is unchanged after the rows redraw" }
else { "  FAIL the summary changed on redraw: '$sum' -> '$sum2'"; $fail++ }

Get-Process -Id $q.Id -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
Remove-Item $w -Recurse -Force -EA SilentlyContinue
Remove-Item Env:\MYRKR_DBG_NOSECDESK -EA SilentlyContinue

""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

""
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "counttest: all checks passed"; exit 0 }
