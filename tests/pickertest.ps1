# The one thing the container-view wiring was never verified on: picker ->
# append -> refresh, end to end, with the modal dialog actually driven.
#
# Unencrypted zip on purpose - browsing it needs no password, so the private
# desktop stays out of it and this can run against the shipping release build.
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "picker1"
$exe  = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\myrkr.exe"
$fail = 0
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class P {
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
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
function Entries($z) { $a=[IO.Compression.ZipFile]::OpenRead($z); $n=@($a.Entries | ForEach-Object { $_.FullName }); $a.Dispose(); return $n }

Stop-Myrkr
New-Item -ItemType Directory "$w\src" -Force | Out-Null
New-Item -ItemType Directory "$w\extra" -Force | Out-Null
1..2 | ForEach-Object { Set-Content "$w\src\f$_.txt" ("alpha $_ " * 40) }
Set-Content "$w\extra\added.txt" ("appended through the picker " * 20)
$z = "$w\plain.zip"
# Built by .NET, not by myrkr: the release build refuses the zip verb from the
# CLI, and an independent producer makes this a better test anyway - the
# archive myrkr appends to was not written by myrkr.
if (Test-Path $z) { Remove-Item -LiteralPath $z -Force }
[IO.Compression.ZipFile]::CreateFromDirectory("$w\src", $z)
$before = Entries $z
"before: $($before.Count) entries -> $($before -join ', ')"
$sizeBefore = (Get-Item $z).Length

$p = Start-Process $exe -ArgumentList @("`"$z`"") -PassThru
$m=[IntPtr]::Zero; for($i=0;$i -lt 60 -and $m -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250; $m=[P]::Find([uint32]$p.Id,"myrkr_window")}
if ($m -eq [IntPtr]::Zero) { "FAIL no container window"; Stop-Myrkr; exit 1 }
Start-Sleep -Seconds 2
$lv = [P]::ById($m,109)
$rows0 = [int][P]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
"container view: $rows0 rows"

[void][P]::SetForegroundWindow($m); Start-Sleep -Milliseconds 400
[void][P]::PostMessageW($m,0x0111,[IntPtr]154,[IntPtr]::Zero)     # ID_ADDFILES
# the common item dialog is a #32770; wait for it to belong to our process
$dlg=[IntPtr]::Zero
for($i=0;$i -lt 40 -and $dlg -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $dlg=[P]::Find([uint32]$p.Id,"#32770") }
if ($dlg -eq [IntPtr]::Zero) { "FAIL the picker never appeared"; Stop-Myrkr; exit 1 }
$t = New-Object Text.StringBuilder 256; [void][P]::GetWindowText($dlg,$t,256)
$title = $t.ToString()
"picker up: '$title'"
# The title has to say what the picked files are FOR. This dialog is shared
# with the encrypt view, where "to encrypt" is right and here it is a lie.
if ($title -notlike "*archive*") { "  FAIL the picker still calls this encrypting: '$title'"; $fail++ }
else { "  ok   the title names the job it is doing" }

# Type the path into whatever the dialog focused (its filename edit) and commit.
[void][P]::SetForegroundWindow($dlg); Start-Sleep -Milliseconds 800
[System.Windows.Forms.SendKeys]::SendWait("$w\extra\added.txt")
Start-Sleep -Milliseconds 700
[System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
Start-Sleep -Seconds 5

$p.Refresh()
"process alive after the append: $(-not $p.HasExited)"
if ($p.HasExited) {
  $c = $p.ExitCode
  "  FAIL it died - exit $c (0x{0:X8})" -f $c
  $fail++
}
$rows1 = [int][P]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
"container view now: $rows1 rows (was $rows0)"
Stop-Myrkr

$after = Entries $z
"after : $($after.Count) entries -> $($after -join ', ')"
"size  : $sizeBefore -> $((Get-Item $z).Length)"
if ($after.Count -le $before.Count) { "  FAIL nothing was appended"; $fail++ }
elseif ($after -notcontains 'added.txt' -and -not ($after | Where-Object { $_ -like '*added.txt' })) {
  "  FAIL the picked file is not in the archive"; $fail++ }
else { "  ok   the picked file reached the archive, via an independent reader" }
if ($rows1 -le $rows0) { "  FAIL the container view did not refresh ($rows0 -> $rows1)"; $fail++ }
else { "  ok   the view refreshed on its own ($rows0 -> $rows1 rows)" }
# and the appended bytes are actually right
try {
  $a=[IO.Compression.ZipFile]::OpenRead($z)
  $e=$a.Entries | Where-Object { $_.FullName -like "*added.txt" } | Select-Object -First 1
  $r=New-Object IO.StreamReader($e.Open()); $txt=$r.ReadToEnd(); $r.Dispose(); $a.Dispose()
  if ($txt -eq (Get-Content "$w\extra\added.txt" -Raw)) { "  ok   and its bytes match the original" }
  else { "  FAIL appended bytes differ"; $fail++ }
} catch { "  FAIL reading it back: $_"; $fail++ }

"`n$(if($fail -eq 0){'ALL PASS'}else{"$fail FAILURE(S)"})"
# Explicit, or the runner records exit 0 over a printed failure - the hole
# the 1.0.87 suite run found in rmbartest, fixed here for the same reason.
exit $(if ($fail -eq 0) { 0 } else { 1 })
