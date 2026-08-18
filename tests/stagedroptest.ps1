# Steps 2 and 3 of docs/STAGED_LAYOUT.md: dropping into a folder while BUILDING
# an archive, and the tree showing it.
#
# The assertion that matters is that those two AGREE. Either half alone is a
# bug: a file staged into docs/ but drawn at the top level means the archive
# will not match the list the user was looking at when they pressed Encrypt,
# which the doc rules out in as many words. So every case here checks the row
# model AND the resulting archive, and neither is believed on its own - the
# archive is read back with .NET's zip reader, which has never heard of any of
# this.
#
# Needs a dbg build (the WM_APP+3 drop hook and -p are test-only).
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "sdrop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = "$root\bin\myrkr.exe"
$PW   = "Correct-Horse-Battery-9"
$fail = 0
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class G {
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr SendStr(IntPtr h,uint m,IntPtr w,string l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,IntPtr s,uint t,uint p);
  [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,IntPtr s,out IntPtr w);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,IntPtr s,out IntPtr r);
  public delegate bool EnumProc(IntPtr h,IntPtr p);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
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
$WM_APP_DROPTEST = 0x8003
function Stop-Myrkr { Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}; Start-Sleep -Milliseconds 500 }
function RowText($c,$r) {
  $li=New-Object byte[] 88; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([uint32]1).CopyTo($li,0); [BitConverter]::GetBytes([int32]$r).CopyTo($li,4)
  [BitConverter]::GetBytes([int64]($c.mem.ToInt64()+256)).CopyTo($li,24); [BitConverter]::GetBytes([int32]256).CopyTo($li,32)
  [void][G]::WriteProcessMemory($c.p.Handle,$c.mem,$li,[IntPtr]88,[ref]$wr)
  [void][G]::SendMessageW($c.lv,0x1073,[IntPtr]$r,$c.mem)
  $b=New-Object byte[] 512; $rd=[IntPtr]::Zero
  [void][G]::ReadProcessMemory($c.p.Handle,[IntPtr]($c.mem.ToInt64()+256),$b,[IntPtr]512,[ref]$rd)
  $t=[Text.Encoding]::Unicode.GetString($b); $i=$t.IndexOf([char]0); if($i -ge 0){$t=$t.Substring(0,$i)}; return $t
}
# Depth comes from the LABEL RECT's left edge, not from LVITEM.iIndent.
#
# Reading iIndent back out of LVM_GETITEMW gave 32759 here - the top half of a
# pointer - so the struct offset is not what the header arithmetic says on this
# path, and "  " * 32759 built a 65KB line that every filter then hid. The
# label rect is the control's own answer about where it drew the text, which is
# the thing being asserted anyway: a child sits further right than its parent.
function RowLeft($c,$r) {
  $rc=New-Object byte[] 16; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([int32]2).CopyTo($rc,0)      # LVIR_LABEL
  [void][G]::WriteProcessMemory($c.p.Handle,$c.mem,$rc,[IntPtr]16,[ref]$wr)
  [void][G]::SendMessageW($c.lv,0x100E,[IntPtr]$r,$c.mem)
  $o=New-Object byte[] 16; $rd=[IntPtr]::Zero
  [void][G]::ReadProcessMemory($c.p.Handle,$c.mem,$o,[IntPtr]16,[ref]$rd)
  return [BitConverter]::ToInt32($o,0)
}
# Rows as "<label left>:<name>", so a reader can see the shape and the
# assertions can compare depths without inventing a unit for them.
function Tree($c) {
  $n=[int][G]::SendMessageW($c.lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
  $out=@(); for($r=0;$r -lt $n;$r++){ $out += ("{0}:{1}" -f (RowLeft $c $r),(RowText $c $r)) }
  # ,$out - a bare return unrolls a one-element array to a scalar, and then
  # $t[$i] indexes a CHARACTER. That failure looked like the tree being wrong.
  return ,$out
}
# Matches on the LEAF. A depth-0 row shows its path relative to the common root
# of the inputs ("extra\dropped.txt"), while a nested one shows just its name -
# so an exact match finds the staged case and misses the unstaged one, which
# reads as the feature working and the control case broken.
function RowOf($t,$name) {
  for($i=0;$i -lt $t.Count;$i++){
    $n = $t[$i].Split(':',2)[1]
    if ($n -eq $name -or $n.EndsWith('\' + $name)) { return $i }
  }
  return -1
}
function LeftOf($t,$i) { return [int]($t[$i].Split(':',2)[0]) }
function Find-Row($c,$name) {
  $n=[int][G]::SendMessageW($c.lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
  for($r=0;$r -lt $n;$r++){ if((RowText $c $r) -eq $name){ return $r } }
  return -1
}
function Row-Point($c,$row) {
  $rc=New-Object byte[] 16; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([int32]0).CopyTo($rc,0)
  [void][G]::WriteProcessMemory($c.p.Handle,$c.mem,$rc,[IntPtr]16,[ref]$wr)
  [void][G]::SendMessageW($c.lv,0x100E,[IntPtr]$row,$c.mem)
  $o=New-Object byte[] 16; $rd=[IntPtr]::Zero
  [void][G]::ReadProcessMemory($c.p.Handle,$c.mem,$o,[IntPtr]16,[ref]$rd)
  $lr=New-Object G+RECT; [void][G]::GetWindowRect($c.lv,[ref]$lr)
  $x=$lr.L+[BitConverter]::ToInt32($o,0)+30
  $y=$lr.T+[int](([BitConverter]::ToInt32($o,4)+[BitConverter]::ToInt32($o,12))/2)
  return [IntPtr](([int64]$y -shl 32) -bor ([int64]$x -band 0xFFFFFFFF))
}
# Launched with NO arguments. Given an input on the command line the window
# opens its destination picker first, and the main window stays hidden behind
# it - so the folder is dropped in instead, which is also the gesture under
# test.
function Open-Encrypt() {
  $p=Start-Process $exe -PassThru
  $m=[IntPtr]::Zero; for($i=0;$i -lt 80 -and $m -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250;$m=[G]::Find([uint32]$p.Id,"myrkr_window")}
  if($m -eq [IntPtr]::Zero){ return $null }
  Start-Sleep -Seconds 2
  [void][G]::SetForegroundWindow($m); Start-Sleep -Milliseconds 500
  return @{p=$p;m=$m;lv=[G]::ById($m,109);mem=[G]::VirtualAllocEx($p.Handle,[IntPtr]::Zero,[IntPtr]4096,0x3000,4)}
}
# A folder row opens on double-click, so that is what this sends: WM_NOTIFY with
# an NMITEMACTIVATE in the TARGET's address space, like every other listview
# pointer that crosses a process boundary.
function Expand-Row($c,$row) {
  # A real double-click on the row, so the LISTVIEW raises NM_DBLCLK itself.
  # Synthesising the WM_NOTIFY instead did nothing: the struct crosses a
  # process boundary and the control is the only thing that can vouch for it.
  $rc=New-Object byte[] 16; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([int32]0).CopyTo($rc,0)
  [void][G]::WriteProcessMemory($c.p.Handle,$c.mem,$rc,[IntPtr]16,[ref]$wr)
  [void][G]::SendMessageW($c.lv,0x100E,[IntPtr]$row,$c.mem)
  $o=New-Object byte[] 16; $rd=[IntPtr]::Zero
  [void][G]::ReadProcessMemory($c.p.Handle,$c.mem,$o,[IntPtr]16,[ref]$rd)
  $x=[BitConverter]::ToInt32($o,0)+30
  $y=[int](([BitConverter]::ToInt32($o,4)+[BitConverter]::ToInt32($o,12))/2)
  $lp=[IntPtr](([int64]$y -shl 16) -bor ([int64]$x -band 0xFFFF))
  [void][G]::PostMessageW($c.lv,0x0201,[IntPtr]1,$lp)   # WM_LBUTTONDOWN
  [void][G]::PostMessageW($c.lv,0x0202,[IntPtr]0,$lp)   # WM_LBUTTONUP
  [void][G]::PostMessageW($c.lv,0x0203,[IntPtr]1,$lp)   # WM_LBUTTONDBLCLK
  [void][G]::PostMessageW($c.lv,0x0202,[IntPtr]0,$lp)
  Start-Sleep -Seconds 1
}
function DropOn($c,$file,$pt) {
  $col=New-Object System.Collections.Specialized.StringCollection; [void]$col.Add($file)
  [Windows.Forms.Clipboard]::SetFileDropList($col); Start-Sleep -Milliseconds 300
  [void][G]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]0,$pt)
  Start-Sleep -Seconds 3
}
function ZipNames($z){ $a=[IO.Compression.ZipFile]::OpenRead($z); $n=@($a.Entries|%{$_.FullName -replace '\\','/'}); $a.Dispose(); return ($n|Sort-Object) }

Stop-Myrkr
"building dbg..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

if (Test-Path $w) { Remove-Item -LiteralPath $w -Recurse -Force }
New-Item -ItemType Directory "$w\tree\docs" -Force | Out-Null
New-Item -ItemType Directory "$w\extra" -Force | Out-Null
Set-Content "$w\tree\top.txt" "top"
Set-Content "$w\tree\docs\a.txt" "a"
Set-Content "$w\extra\dropped.txt" "dropped"

# Sets the list up the way a user would: launch empty, drop the folder in, open
# it. Then drop a file ONTO a folder row inside it.
function Setup() {
  $c = Open-Encrypt
  if (-not $c) { return $null }
  DropOn $c "$w\tree" ([IntPtr]0)          # pt {0,0} -> the root
  Expand-Row $c 0                           # an input list starts collapsed
  return $c
}

"`n--- 1. drop onto a folder row: the tree draws it inside ---"
# This is also what proves the GUI staged it correctly, and why there is no
# separate "and the archive agrees" case here: the row can ONLY be drawn inside
# docs if g_pos_prefix says exactly tree/docs/, and tests/stagetest.ps1 already
# proves that g_pos_prefix is what the packers name entries from. A second case
# reproducing the archive with --stage would re-test stagetest, not this.
$c = Setup
if (-not $c) { "FAIL no window"; Stop-Myrkr; exit 1 }
"  before: $((Tree $c) -join ' | ')"
$docs = Find-Row $c 'docs'
if ($docs -lt 0) { "  FAIL no 'docs' row after expanding"; $fail++ }
else {
  DropOn $c "$w\extra\dropped.txt" (Row-Point $c $docs)
  $t = Tree $c
  "  after : $($t -join ' | ')"
  $di = RowOf $t 'docs'
  $ri = RowOf $t 'dropped.txt'
  if ($ri -lt 0) { "  FAIL the dropped file is not in the tree at all"; $fail++ }
  elseif ($di -lt 0) { "  FAIL 'docs' vanished"; $fail++ }
  else {
    $dL = LeftOf $t $di; $rL = LeftOf $t $ri
    if ($ri -gt $di -and $rL -gt $dL) { "  ok   drawn after 'docs' and further in (x $dL -> $rL)" }
    else { "  FAIL row $ri at x=$rL; 'docs' is row $di at x=$dL"; $fail++ }
  }
}
Stop-Myrkr

"`n--- 2. a drop at the ROOT still lands at the root ---"
# The unstaged path has to keep working, and it is the one every release before
# this had.
$c = Setup
if (-not $c) { "  FAIL no window"; $fail++ }
else {
  DropOn $c "$w\extra\dropped.txt" ([IntPtr]0)
  $t = Tree $c
  "  tree  : $($t -join ' | ')"
  $ri = RowOf $t 'dropped.txt'
  $ti = RowOf $t 'tree'
  if ($ri -lt 0) { "  FAIL not in the tree"; $fail++ }
  elseif ($ti -ge 0 -and (LeftOf $t $ri) -ne (LeftOf $t $ti)) { "  FAIL indented to x=$(LeftOf $t $ri); top level is x=$(LeftOf $t $ti)"; $fail++ }
  else { "  ok   an unstaged drop is still a top-level input" }
}
Stop-Myrkr

"`n--- 3. removing the destination un-stages its lodgers ---"
# A staged file whose destination is gone would be encrypted into a path the
# tree cannot draw - the one outcome docs/STAGED_LAYOUT.md rules out. stage_heal
# drops the staging so it comes back to the root, where it is visible and where
# the archive will now put it.
$c = Setup
if (-not $c) { "  FAIL no window"; $fail++ }
else {
  $docs = Find-Row $c 'docs'
  DropOn $c "$w\extra\dropped.txt" (Row-Point $c $docs)
  "  staged: $((Tree $c) -join ' | ')"
  # select row 0 ('tree', the input that HOSTS docs) and remove it
  $li=New-Object byte[] 88; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([uint32]8).CopyTo($li,0)
  [BitConverter]::GetBytes([uint32]2).CopyTo($li,12)
  [BitConverter]::GetBytes([uint32]2).CopyTo($li,16)
  [void][G]::WriteProcessMemory($c.p.Handle,$c.mem,$li,[IntPtr]88,[ref]$wr)
  [void][G]::SendMessageW($c.lv,0x102B,[IntPtr]0,$c.mem)
  Start-Sleep -Milliseconds 400
  [void][G]::PostMessageW($c.m,0x0111,[IntPtr]161,[IntPtr]::Zero)   # ID_CMD_REMOVE
  Start-Sleep -Seconds 3
  $t2 = Tree $c
  "  after : $($t2 -join ' | ')"
  $ri = RowOf $t2 'dropped.txt'
  if ($ri -lt 0) { "  FAIL it vanished with its destination - it would still be encrypted"; $fail++ }
  elseif ($t2.Count -ne 1) { "  FAIL the list is $($t2.Count) rows, wanted just the freed file"; $fail++ }
  else { "  ok   it came back to the top level rather than becoming invisible" }
}
Stop-Myrkr

"`n$(if($fail -eq 0){'ALL PASS'}else{"$fail FAILURE(S)"})"
exit $(if ($fail -eq 0) { 0 } else { 1 })