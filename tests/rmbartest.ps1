# Does the removal bar's total match the work actually done?
#
# Not a timing test. After the removal finishes, g_prog_done must EQUAL
# g_prog_total - which is the whole claim, and the one that fails silently if
# the total counts survivors that never moved. A bar can look fine and still be
# built on a total that is wrong; this reads both numbers out of the process.
#
# Needs a dbg build - `encrypt -p` on the command line is refused by the
# shipping binary on purpose, and MYRKR_DBG_NOSECDESK is a TEST_IO knob - so it
# builds one itself and puts the release build back on every exit, pass or
# fail.  It used to assume bin already held one, and against a release build it
# died as "FAIL no prompt": the setup encrypt had been refused into Out-Null
# and the container never existed.
$root = Split-Path -Parent $PSScriptRoot
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "rmbar1"
$exe  = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\myrkr.exe"
$map  = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\myrkr.map"
$PW   = "Correct-Horse-9x"
$fail = 0
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class R {
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,int n,out IntPtr r);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
  [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr SendStr(IntPtr h,uint m,IntPtr w,string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,IntPtr n,uint t,uint p);
  [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,int n,out IntPtr w);
  public delegate bool EnumProc(IntPtr h,IntPtr p);
  public static IntPtr Find(uint pid,string cls,bool vis){ IntPtr r=IntPtr.Zero;
    EnumWindows(delegate(IntPtr h,IntPtr q){ uint x; GetWindowThreadProcessId(h,out x);
      if(x!=pid) return true; if(vis && !IsWindowVisible(h)) return true;
      StringBuilder c=new StringBuilder(128); GetClassName(h,c,128);
      if(c.ToString()==cls){ r=h; return false; } return true;},IntPtr.Zero); return r; }
  public static IntPtr found;
  public static IntPtr ById(IntPtr t,int id){ found=IntPtr.Zero;
    EnumChildWindows(t,delegate(IntPtr h,IntPtr q){ if(GetDlgCtrlID(h)==id){found=h;return false;} return true;},IntPtr.Zero); return found; }
}
"@
function Rva($n){ $l=Select-String -Path $map -Pattern "\s$n\s"|Select-Object -First 1
  if(-not $l){return $null}; [long]([Convert]::ToUInt64((($l.Line.Trim() -split '\s+')[2]),16)-0x140000000) }
function Q($proc,$sym){ $r=Rva $sym; if($null -eq $r){return -1}; $b=New-Object byte[] 8; $g=[IntPtr]::Zero
  [void][R]::ReadProcessMemory($proc.Handle,[IntPtr]([long]$proc.MainModule.BaseAddress+$r),$b,8,[ref]$g)
  [BitConverter]::ToInt64($b,0) }
function D($proc,$sym){ $r=Rva $sym; if($null -eq $r){return -1}; $b=New-Object byte[] 4; $g=[IntPtr]::Zero
  [void][R]::ReadProcessMemory($proc.Handle,[IntPtr]([long]$proc.MainModule.BaseAddress+$r),$b,4,[ref]$g)
  [BitConverter]::ToInt32($b,0) }
function Stop-Myrkr { Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }; Start-Sleep -Milliseconds 500 }
# Every exit goes through here so a failed run cannot leave a test build in
# bin - the next packaging run would wrap whatever it finds (see run.ps1).
function Finish([int]$code) {
  "=== Restore: shipping build ==="
  $blog = cmd /c "$root\build.cmd strict release" 2>&1
  if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; if ($code -eq 0) { $code = 1 } }
  else { "  bin\myrkr.exe is a release build - ok" }
  exit $code
}

Stop-Myrkr
"building dbg (encrypt on the command line and MYRKR_DBG_NOSECDESK need it)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }
New-Item -ItemType Directory "$w\src" -Force | Out-Null
# Several big entries so the removal has real bytes to wipe AND to slide down.
$rng = New-Object byte[] (4MB); (New-Object Random 7).NextBytes($rng)
# Kept under SLOW_REMOVE_BYTES (100 MiB). Above it confirm_slow_remove puts up a
# modal that nothing answers, the removal never starts, and the total reads 0 -
# which looks exactly like progress_begin never being called.
1..4 | ForEach-Object { $fs=[IO.File]::Create("$w\src\e$_.bin"); 1..5 | ForEach-Object { $fs.Write($rng,0,$rng.Length) }; $fs.Close() }
$mrk = "$w\t.mrk"
if (Test-Path $mrk) { Remove-Item -LiteralPath $mrk -Force }
$elog = cmd /c "$exe encrypt ""$w\src"" -o ""$mrk"" -p $PW 2>&1"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $mrk)) {
  # loud, not Out-Null: refused -p (a release build under test) and a disk
  # problem must read differently from "the prompt never appeared"
  "FAIL setup encrypt (exit $LASTEXITCODE)"
  $elog | Select-Object -Last 5
  Finish 1
}
"container: $([math]::Round((Get-Item $mrk).Length/1MB,1)) MB"

$env:MYRKR_DBG_NOSECDESK = "1"
try {
  $p = Start-Process $exe -ArgumentList @("`"$mrk`"") -PassThru
  $prompt=[IntPtr]::Zero
  for($i=0;$i -lt 80 -and $prompt -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $prompt=[R]::Find([uint32]$p.Id,"myrkr_secdesk",$true) }
  if ($prompt -eq [IntPtr]::Zero) { "FAIL no prompt"; Stop-Myrkr; Finish 1 }
  [void][R]::SendStr([R]::GetDlgItem($prompt,156),0x000C,[IntPtr]::Zero,$PW); Start-Sleep -Milliseconds 300
  [void][R]::PostMessageW($prompt,0x0111,[IntPtr]104,[IntPtr]::Zero)
  $m=[IntPtr]::Zero
  for($i=0;$i -lt 80 -and $m -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $m=[R]::Find([uint32]$p.Id,"myrkr_window",$true) }
  if ($m -eq [IntPtr]::Zero) { "FAIL container never opened"; Stop-Myrkr; Finish 1 }
  Start-Sleep -Seconds 2
  $lv=[R]::ById($m,109); $n=[int][R]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
  "rows: $n"
  # select the FIRST file row, so survivors after it have to slide - which is
  # the case the total is easy to get wrong on
  $mem=[R]::VirtualAllocEx($p.Handle,[IntPtr]::Zero,[IntPtr]128,0x3000,4)
  $li=New-Object byte[] 88; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([uint32]8).CopyTo($li,0)
  [BitConverter]::GetBytes([uint32]2).CopyTo($li,12)
  [BitConverter]::GetBytes([uint32]2).CopyTo($li,16)
  [void][R]::WriteProcessMemory($p.Handle,$mem,$li,88,[ref]$wr)
  [void][R]::SendMessageW($lv,0x102B,[IntPtr]1,$mem)
  Start-Sleep -Milliseconds 400
  $sel=[int][R]::SendMessageW($lv,0x1032,[IntPtr]::Zero,[IntPtr]::Zero)
  "selected: $sel"
  if ($sel -ne 1) { "  FAIL selection did not take"; $fail++ }
  [void][R]::PostMessageW($m,0x0111,[IntPtr]161,[IntPtr]::Zero)   # ID_CMD_REMOVE
  # sample the bar while it runs
  $seen=@(); for($i=0;$i -lt 120;$i++){ Start-Sleep -Milliseconds 100
    $pct=D $p 'g_prog_pct'; if($pct -ge 0){ $seen += $pct }
    if ((D $p 'g_running') -eq 0 -and $i -gt 8) { break } }
  $done  = Q $p 'g_prog_done'
  $total = Q $p 'g_prog_total'
  "g_prog_done = $done"
  "g_prog_total= $total"
  $mono = $true; for($i=1;$i -lt $seen.Count;$i++){ if($seen[$i] -lt $seen[$i-1]){ $mono=$false } }
  "samples: $($seen.Count), max $(($seen | Measure-Object -Maximum).Maximum), monotonic $mono"
  if ($total -le 0) { "  FAIL no total was set"; $fail++ }
  elseif ($done -ne $total) { "  FAIL done != total ($done vs $total) - the total counts work that never happened"; $fail++ }
  else { "  ok   every byte the total promised was written" }
  if (-not $mono) { "  FAIL the bar went backwards"; $fail++ } else { "  ok   the bar never went backwards" }
}
finally { Stop-Myrkr; Remove-Item Env:\MYRKR_DBG_NOSECDESK -EA SilentlyContinue }
cmd /c "$exe verify ""$mrk"" -p $PW 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) { "  FAIL the container no longer authenticates"; $fail++ } else { "  ok   still authenticates" }
# and the code has to LEAVE through exit: a $fail++ that only printed gave
# this script exit 0 in the suite runner, which records green over a failure
if ($fail -gt 0) { "`n$fail FAILURE(S)"; Finish 1 } else { "`nALL PASS"; Finish 0 }
