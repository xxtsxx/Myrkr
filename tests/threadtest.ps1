# The container edits run on the worker thread now. The only thing that proves
# it is that the window still ANSWERS while one is running - so this adds a file
# big enough to take real time and pings the window throughout with
# SendMessageTimeout(WM_NULL). On the UI thread that ping times out; off it, it
# returns immediately.
#
# Also does a second add afterwards, which is what would catch g_wt_job or
# g_poscount being left dirty by the first.
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "thread1"
$exe  = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\myrkr.exe"
$fail = 0
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class T {
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h,uint m,IntPtr w,IntPtr l,uint f,uint t,out IntPtr r);
  public delegate bool EnumProc(IntPtr h,IntPtr p);
  public static IntPtr Find(uint pid,string cls){ IntPtr r=IntPtr.Zero;
    EnumWindows(delegate(IntPtr h,IntPtr q){ uint w; GetWindowThreadProcessId(h,out w);
      if(w!=pid||!IsWindowVisible(h)) return true;
      StringBuilder c=new StringBuilder(128); GetClassName(h,c,128);
      if(c.ToString()==cls){ r=h; return false; } return true;},IntPtr.Zero); return r; }
  public static IntPtr found;
  public static IntPtr ById(IntPtr t,int id){ found=IntPtr.Zero;
    EnumChildWindows(t,delegate(IntPtr h,IntPtr q){ if(GetDlgCtrlID(h)==id){found=h;return false;} return true;},IntPtr.Zero); return found; }
  // SMTO_ABORTIFHUNG = 2. Non-zero return means the window answered.
  public static bool Ping(IntPtr h,uint ms){ IntPtr r; return SendMessageTimeoutW(h,0,IntPtr.Zero,IntPtr.Zero,2,ms,out r)!=IntPtr.Zero; }
}
"@
function Stop-Myrkr { Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }; Start-Sleep -Milliseconds 500 }
function Entries($z){ $a=[IO.Compression.ZipFile]::OpenRead($z); $n=@($a.Entries|ForEach-Object{$_.FullName}); $a.Dispose(); return $n }
function AddViaPicker($main,$path) {
  [void][T]::SetForegroundWindow($main); Start-Sleep -Milliseconds 300
  [void][T]::PostMessageW($main,0x0111,[IntPtr]154,[IntPtr]::Zero)
  $dlg=[IntPtr]::Zero
  for($i=0;$i -lt 40 -and $dlg -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $dlg=[T]::Find([uint32]$script:pid2,"#32770") }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][T]::SetForegroundWindow($dlg); Start-Sleep -Milliseconds 700
  [System.Windows.Forms.SendKeys]::SendWait($path); Start-Sleep -Milliseconds 500
  [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
  return $true
}

Stop-Myrkr
New-Item -ItemType Directory "$w\src" -Force | Out-Null
New-Item -ItemType Directory "$w\extra" -Force | Out-Null
Set-Content "$w\src\small.txt" "seed"
# Big enough that the append cannot finish before the measurement starts. At
# 80 MB it finished in half a second and the "it stayed responsive" result rested
# on three pings - which the UI-thread version would also have passed, because
# the work had barely begun. Deflate on incompressible bytes is the slow case.
$big = "$w\extra\big.bin"
$rng = New-Object byte[] (4MB)
(New-Object Random 12345).NextBytes($rng)
$fs = [IO.File]::Create($big); 1..120 | ForEach-Object { $fs.Write($rng,0,$rng.Length) }; $fs.Close()
Set-Content "$w\extra\second.txt" "the second add"
"big file: $([math]::Round((Get-Item $big).Length/1MB,1)) MB"
$z = "$w\plain.zip"
if (Test-Path $z) { Remove-Item -LiteralPath $z -Force }
[IO.Compression.ZipFile]::CreateFromDirectory("$w\src", $z)

$p = Start-Process $exe -ArgumentList @("`"$z`"") -PassThru
$script:pid2 = $p.Id
$m=[IntPtr]::Zero; for($i=0;$i -lt 60 -and $m -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250; $m=[T]::Find([uint32]$p.Id,"myrkr_window")}
if ($m -eq [IntPtr]::Zero) { "FAIL no container window"; Stop-Myrkr; exit 1 }
Start-Sleep -Seconds 2
if (-not (AddViaPicker $m $big)) { "FAIL picker never appeared"; Stop-Myrkr; exit 1 }

# ---- the measurement -------------------------------------------------------
# The append window is exactly the time myrkr holds the archive open for
# writing, so that is what is measured - not a guess at a duration. Pinging
# outside it would prove nothing.
function Locked($f){ try { $h=[IO.File]::Open($f,'Open','Write','None'); $h.Close(); return $false } catch { return $true } }
$pings = 0; $misses = 0; $busy = 0
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.Elapsed.TotalSeconds -lt 90) {
  $isBusy = Locked $z
  if ($isBusy) {
    $busy++
    if ([T]::Ping($m,250)) { $pings++ } else { $misses++ }
  } elseif ($busy -gt 0) { break }      # it was working and now it is not
  Start-Sleep -Milliseconds 60
}
$sw.Stop()
"append window: $([math]::Round($sw.Elapsed.TotalSeconds,1))s, $pings pings answered, $misses timed out"
# A handful of pings is not evidence: at 80 MB the whole append took half a
# second and three pings passed, which the UI-thread build would have passed too.
if ($pings + $misses -lt 15) {
  "  FAIL only $($pings+$misses) pings landed inside the append - too fast to measure, use a bigger file"; $fail++ }
elseif ($misses -gt 0) {
  "  FAIL the window stopped answering $misses times - the work is still on the UI thread"; $fail++ }
else { "  ok   answered all $pings pings across the whole append, so it ran off the UI thread" }

Start-Sleep -Seconds 6
$after = Entries $z
"after the big add: $($after.Count) entries -> $($after -join ', ')"
if ($after.Count -ne 2) { "  FAIL the big file did not land"; $fail++ } else { "  ok   it landed" }

# ---- a second add, which a dirty g_wt_job or g_poscount would break --------
if (-not (AddViaPicker $m "$w\extra\second.txt")) { "  FAIL the picker did not reopen"; $fail++ }
else {
  Start-Sleep -Seconds 5
  $after2 = Entries $z
  "after the second add: $($after2.Count) entries -> $($after2 -join ', ')"
  if ($after2.Count -ne 3) { "  FAIL the second add did not land - state left dirty by the first"; $fail++ }
  else { "  ok   a second add works, so the job and the input list were reset" }
}
$p.Refresh()
if ($p.HasExited) { "  FAIL the process died - exit $($p.ExitCode)"; $fail++ } else { "  ok   still alive" }
Stop-Myrkr
"`n$(if($fail -eq 0){'ALL PASS'}else{"$fail FAILURE(S)"})"
# Explicit, or the runner records exit 0 over a printed failure - the hole
# the 1.0.87 suite run found in rmbartest, fixed here for the same reason.
exit $(if ($fail -eq 0) { 0 } else { 1 })
