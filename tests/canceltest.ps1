# Cancel during an add. The claim being tested is not "it stops" but "it stops
# AND the archive is exactly what it was" - the append writes past the old EOCD
# precisely so a refusal can truncate back, and cancel is a refusal.
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "cancel1"
$exe  = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\myrkr.exe"
$fail = 0
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class C {
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr SendStr(IntPtr h,uint m,IntPtr w,string l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
  public delegate bool EnumProc(IntPtr h,IntPtr p);
  public static IntPtr Find(uint pid,string cls){ IntPtr r=IntPtr.Zero;
    EnumWindows(delegate(IntPtr h,IntPtr q){ uint w; GetWindowThreadProcessId(h,out w);
      if(w!=pid||!IsWindowVisible(h)) return true;
      StringBuilder c=new StringBuilder(128); GetClassName(h,c,128);
      if(c.ToString()==cls){ r=h; return false; } return true;},IntPtr.Zero); return r; }
  public static IntPtr found;
  public static IntPtr ById(IntPtr t,int id){ found=IntPtr.Zero;
    EnumChildWindows(t,delegate(IntPtr h,IntPtr q){ if(GetDlgCtrlID(h)==id){found=h;return false;} return true;},IntPtr.Zero); return found; }
}
"@
function Stop-Myrkr { Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }; Start-Sleep -Milliseconds 500 }
function Entries($z){ $a=[IO.Compression.ZipFile]::OpenRead($z); $n=@($a.Entries|ForEach-Object{$_.FullName}); $a.Dispose(); return $n }
function Locked($f){ try { $h=[IO.File]::Open($f,'Open','Write','None'); $h.Close(); return $false } catch { return $true } }

Stop-Myrkr
New-Item -ItemType Directory "$w\src" -Force | Out-Null
New-Item -ItemType Directory "$w\extra" -Force | Out-Null
Set-Content "$w\src\small.txt" "seed"
# Several large incompressible files, so the walk crosses input boundaries -
# which is where cancellation is checked - more than once.
$rng = New-Object byte[] (4MB); (New-Object Random 99).NextBytes($rng)
1..4 | ForEach-Object {
  $fs=[IO.File]::Create("$w\extra\big$_.bin"); 1..45 | ForEach-Object { $fs.Write($rng,0,$rng.Length) }; $fs.Close() }
$z = "$w\plain.zip"
if (Test-Path $z) { Remove-Item -LiteralPath $z -Force }
[IO.Compression.ZipFile]::CreateFromDirectory("$w\src", $z)
$before = Entries $z; $sz0 = (Get-Item $z).Length
$hash0 = (Get-FileHash $z).Hash
"before: $($before.Count) entries, $sz0 bytes"

$p = Start-Process $exe -ArgumentList @("`"$z`"") -PassThru
$m=[IntPtr]::Zero; for($i=0;$i -lt 60 -and $m -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250; $m=[C]::Find([uint32]$p.Id,"myrkr_window")}
if ($m -eq [IntPtr]::Zero) { "FAIL no window"; Stop-Myrkr; exit 1 }
Start-Sleep -Seconds 2
[void][C]::SetForegroundWindow($m); Start-Sleep -Milliseconds 300
[void][C]::PostMessageW($m,0x0111,[IntPtr]154,[IntPtr]::Zero)
$dlg=[IntPtr]::Zero
for($i=0;$i -lt 40 -and $dlg -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $dlg=[C]::Find([uint32]$p.Id,"#32770") }
if ($dlg -eq [IntPtr]::Zero) { "FAIL no picker"; Stop-Myrkr; exit 1 }
# Multi-select via WM_SETTEXT on the dialog's filename field (cmb13, 1148),
# then a posted IDOK - not SendKeys. Keystrokes go to whatever has the
# foreground, and losing that race delivered ONE quoted path instead of four:
# a 180 MB add that finished in under a second, a cancel that landed after it,
# and a "did not roll back" verdict over an add that had nothing to cancel.
# The morning it "passed", the same one-file add was merely slow enough. A
# message names its window; the foreground is not consulted.
Start-Sleep -Milliseconds 700
$sel = (1..4 | ForEach-Object { '"' + "$w\extra\big$_.bin" + '"' }) -join ' '
$fld = [C]::ById($dlg,1148)
if ($fld -eq [IntPtr]::Zero) { "FAIL no filename field in the picker"; Stop-Myrkr; exit 1 }
[void][C]::SendStr($fld,0x000C,[IntPtr]::Zero,$sel); Start-Sleep -Milliseconds 400
[void][C]::PostMessageW($dlg,0x0111,[IntPtr]1,[IntPtr]::Zero)   # IDOK

# wait until it is genuinely working, then cancel
$busy = $false
for ($i=0; $i -lt 100 -and -not $busy; $i++) { Start-Sleep -Milliseconds 60; $busy = Locked $z }
"append started: $busy"
if (-not $busy) { "  FAIL never saw the append begin"; $fail++ }
$cancelBtn = [C]::ById($m,107)
"Cancel enabled during the add: $([C]::IsWindowEnabled($cancelBtn))"
if (-not [C]::IsWindowEnabled($cancelBtn)) { "  FAIL Cancel is not enabled"; $fail++ }
Start-Sleep -Milliseconds 400
[void][C]::PostMessageW($m,0x0111,[IntPtr]107,[IntPtr]::Zero)   # ID_CANCEL
for ($i=0; $i -lt 200 -and (Locked $z); $i++) { Start-Sleep -Milliseconds 100 }
Start-Sleep -Seconds 3

$after = Entries $z; $sz1 = (Get-Item $z).Length
"after : $($after.Count) entries, $sz1 bytes"
# Three outcomes, told apart - a racing fixture must not read as a product bug:
#   unchanged            -> the rollback worked (the claim under test)
#   all four appended    -> cancel landed after the add completed: no runway,
#                           a fixture failure with its own words
#   a subset appended    -> the product kept part of a cancelled add - the
#                           real "did not roll back"
if ($sz1 -eq $sz0 -and (Get-FileHash $z).Hash -eq $hash0) {
  "  ok   the archive is byte-for-byte what it was" }
elseif (@($after | Where-Object { $_ -like 'big*.bin' }).Count -eq 4) {
  "  FAIL the add completed before cancel landed - the fixture gave it no runway"; $fail++ }
else {
  "  FAIL the archive changed - cancel did not roll back ($sz0 -> $sz1)"; $fail++ }
$p.Refresh()
if ($p.HasExited) { "  FAIL the process died - exit $($p.ExitCode)"; $fail++ } else { "  ok   still alive" }
# and it still works afterwards
[void][C]::PostMessageW($m,0x0111,[IntPtr]154,[IntPtr]::Zero)
$dlg2=[IntPtr]::Zero
for($i=0;$i -lt 40 -and $dlg2 -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $dlg2=[C]::Find([uint32]$p.Id,"#32770") }
if ($dlg2 -eq [IntPtr]::Zero) { "  FAIL the picker did not reopen after a cancel"; $fail++ }
else { "  ok   the window is usable again after cancelling" }
Stop-Myrkr
"`n$(if($fail -eq 0){'ALL PASS'}else{"$fail FAILURE(S)"})"
# Explicit, or the runner records exit 0 over a printed failure - the hole
# the 1.0.87 suite run found in rmbartest, fixed here for the same reason.
exit $(if ($fail -eq 0) { 0 } else { 1 })
