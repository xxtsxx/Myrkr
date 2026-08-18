# Step 2 of docs/DROP_INDICATOR.md: added files land in the SELECTED folder,
# not always at the archive root.
#
# The rule under test, for both formats:
#   nothing selected  -> the archive root  (what every version before this did)
#   a FOLDER selected -> inside that folder
#   a FILE   selected -> the folder that file is in
#
# Both formats, because both build the entry name in the same shape and share
# add_prefix_copy - and because a rule that holds for zip and not for .mrk is
# worse than one that holds for neither: it would be invisible until someone
# relied on it.
#
# The zip results are checked with .NET's reader and the .mrk results by
# extracting and looking at where the file actually landed on disk. Neither
# believes the container view's own row model, which is the thing being driven.
#
# Needs a dbg build (the WM_APP+3 drop hook and -p are test-only); it builds
# one, and the caller is expected to rebuild release afterwards.
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "pfx1"
$root = Split-Path -Parent $PSScriptRoot
$exe  = "$root\bin\myrkr.exe"
$PW   = "Correct-Horse-Battery-9"
$fail = 0
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class X {
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr SendStr(IntPtr h,uint m,IntPtr w,string l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,IntPtr s,uint t,uint p);
  [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,IntPtr s,out IntPtr w);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,IntPtr s,out IntPtr r);
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
$WM_APP_DROPTEST = 0x8003
function Stop-Myrkr { Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }; Start-Sleep -Milliseconds 500 }
function Entries($z) { $a=[IO.Compression.ZipFile]::OpenRead($z); $n=@($a.Entries|ForEach-Object{$_.FullName}); $a.Dispose(); return $n }

# Launch on an archive and return @{p;m;lv;mem}. $pw non-empty means answer the
# secure-desktop prompt first (MYRKR_DBG_NOSECDESK keeps it on this desktop).
function Open-Archive($path,$pw) {
  $p = Start-Process $exe -ArgumentList @("`"$path`"") -PassThru
  if ($pw) {
    $prompt=[IntPtr]::Zero
    for($i=0;$i -lt 80 -and $prompt -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $prompt=[X]::Find([uint32]$p.Id,"myrkr_secdesk") }
    if ($prompt -eq [IntPtr]::Zero) { return $null }
    [void][X]::SendStr([X]::GetDlgItem($prompt,156),0x000C,[IntPtr]::Zero,$pw); Start-Sleep -Milliseconds 300
    [void][X]::PostMessageW($prompt,0x0111,[IntPtr]104,[IntPtr]::Zero)
  }
  $m=[IntPtr]::Zero
  for($i=0;$i -lt 80 -and $m -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $m=[X]::Find([uint32]$p.Id,"myrkr_window") }
  if ($m -eq [IntPtr]::Zero) { return $null }
  Start-Sleep -Seconds 2
  $lv=[X]::ById($m,109)
  $mem=[X]::VirtualAllocEx($p.Handle,[IntPtr]::Zero,[IntPtr]4096,0x3000,4)
  return @{ p=$p; m=$m; lv=$lv; mem=$mem }
}

# LVM_GETITEMTEXTW needs the LVITEM *and* the text buffer in the target's own
# address space - the message is not marshalled across processes.
function Get-RowText($c,$row) {
  $li=New-Object byte[] 88; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([uint32]1).CopyTo($li,0)                      # LVIF_TEXT
  [BitConverter]::GetBytes([int32]$row).CopyTo($li,4)
  [BitConverter]::GetBytes([int64]($c.mem.ToInt64()+256)).CopyTo($li,24) # pszText
  [BitConverter]::GetBytes([int32]256).CopyTo($li,32)                    # cchTextMax
  [void][X]::WriteProcessMemory($c.p.Handle,$c.mem,$li,[IntPtr]88,[ref]$wr)
  [void][X]::SendMessageW($c.lv,0x1073,[IntPtr]$row,$c.mem)
  $buf=New-Object byte[] 512; $rd=[IntPtr]::Zero
  [void][X]::ReadProcessMemory($c.p.Handle,[IntPtr]($c.mem.ToInt64()+256),$buf,[IntPtr]512,[ref]$rd)
  $t=[Text.Encoding]::Unicode.GetString($buf)
  $i=$t.IndexOf([char]0); if ($i -ge 0) { $t=$t.Substring(0,$i) }
  return $t
}
function Find-Row($c,$name) {
  $n=[int][X]::SendMessageW($c.lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
  for($r=0;$r -lt $n;$r++){ if ((Get-RowText $c $r) -eq $name) { return $r } }
  return -1
}
# state and stateMask are at offsets 12 and 16, NOT 0 and 4. Getting that wrong
# selects nothing, and a test that then counts rows "passes" vacuously.
function Select-Row($c,$row) {
  $li=New-Object byte[] 88; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([uint32]8).CopyTo($li,0)      # LVIF_STATE
  [BitConverter]::GetBytes([uint32]2).CopyTo($li,12)     # state     = LVIS_SELECTED
  [BitConverter]::GetBytes([uint32]2).CopyTo($li,16)     # stateMask = LVIS_SELECTED
  [void][X]::WriteProcessMemory($c.p.Handle,$c.mem,$li,[IntPtr]88,[ref]$wr)
  [void][X]::SendMessageW($c.lv,0x102B,[IntPtr]$row,$c.mem)
  Start-Sleep -Milliseconds 400
  return [int][X]::SendMessageW($c.lv,0x1032,[IntPtr]::Zero,[IntPtr]::Zero)   # GETSELECTEDCOUNT
}
# Through the Add files BUTTON, not through a drop.
#
# It used to use the drop hook, which was quicker and is now wrong: since the
# insertion line landed, a drop decides its own destination from the cursor and
# deliberately ignores the selection. Driving the selection rule through a
# surface that no longer consults it would have gone on passing for the wrong
# reason if the destination were ever read from the wrong place - so this drives
# the surface that actually uses it, which is what step 2's plan said before I
# took the shortcut.
function Add-ViaButton($c,$file) {
  [void][X]::SetForegroundWindow($c.m); Start-Sleep -Milliseconds 400
  [void][X]::PostMessageW($c.m,0x0111,[IntPtr]154,[IntPtr]::Zero)     # ID_ADDFILES
  $dlg=[IntPtr]::Zero
  for($i=0;$i -lt 40 -and $dlg -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $dlg=[X]::Find([uint32]$c.p.Id,"#32770") }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][X]::SetForegroundWindow($dlg); Start-Sleep -Milliseconds 800
  [System.Windows.Forms.SendKeys]::SendWait($file)
  Start-Sleep -Milliseconds 700
  [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
  Start-Sleep -Seconds 5
  return $true
}

Stop-Myrkr
"building dbg (the drop hook and -p are test-only)..."
# Every exit leaves through here - the same funnel rmbartest and droptest got,
# for the same two reasons: the release build goes back into bin (this test
# builds dbg and used to leave it there), and the exit code says what happened
# (a $fail++ that only printed gave this script exit 0 in the suite runner).
function Finish([int]$code) {
  "=== Restore: shipping build ==="
  $blog = cmd /c "$root\build.cmd strict release" 2>&1
  if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; if ($code -eq 0) { $code = 1 } }
  else { "  bin\myrkr.exe is a release build - ok" }
  exit $code
}

$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

New-Item -ItemType Directory "$w\src\docs\sub" -Force | Out-Null
New-Item -ItemType Directory "$w\extra" -Force | Out-Null
Set-Content "$w\src\top.txt" "top"
Set-Content "$w\src\docs\a.txt" "a"
Set-Content "$w\src\docs\sub\b.txt" "b"
Set-Content "$w\extra\added.txt" ("landed here " * 20)

# select = $null (root) | 'docs' (a folder) | 'a.txt' (a file inside docs)
$cases = @(
  @{ sel=$null;   want='added.txt';      label='nothing selected  -> archive root' },
  @{ sel='docs';  want='docs/added.txt'; label='folder selected   -> inside it' },
  @{ sel='a.txt'; want='docs/added.txt'; label='file selected     -> its parent folder' }
)

"`n=== zip ==="
foreach ($case in $cases) {
  $z = "$w\z_$($case.sel).zip"
  if (Test-Path $z) { Remove-Item -LiteralPath $z -Force }
  [IO.Compression.ZipFile]::CreateFromDirectory("$w\src", $z)
  $c = Open-Archive $z $null
  if (-not $c) { "  FAIL [$($case.label)] window never opened"; $fail++; Stop-Myrkr; continue }
  $ok = $true
  if ($case.sel) {
    $r = Find-Row $c $case.sel
    if ($r -lt 0) { "  FAIL [$($case.label)] no row named '$($case.sel)'"; $fail++; $ok=$false }
    else {
      $n = Select-Row $c $r
      if ($n -ne 1) { "  FAIL [$($case.label)] selection did not take (selected=$n)"; $fail++; $ok=$false }
    }
  }
  if ($ok) {
    if (-not (Add-ViaButton $c "$w\extra\added.txt")) { "  FAIL [$($case.label)] the picker never appeared"; $fail++; Stop-Myrkr; continue }
    Stop-Myrkr
    $e = Entries $z
    $hit = @($e | Where-Object { $_ -replace '\\','/' -eq $case.want })
    if ($hit.Count -eq 1) { "  ok   $($case.label)  ->  $($case.want)" }
    else { "  FAIL $($case.label): wanted '$($case.want)', got [$($e -join ', ')]"; $fail++ }
  }
  Stop-Myrkr
}

"`n=== zip: a hostile destination ==="
# The prefix is the one part of an entry name that does NOT come from the file
# being added - it comes from a row, which came from an archive index, which a
# hostile zip wrote. So it can carry '..'. sanitize_name runs on the COMBINED
# name for exactly this, and only when a prefix is set, so a prefix-free add
# stays byte-for-byte the operation that shipped before.
$zx = "$w\evil.zip"
if (Test-Path $zx) { Remove-Item -LiteralPath $zx -Force }
$fs=[IO.File]::Create($zx)
$za=New-Object IO.Compression.ZipArchive($fs,[IO.Compression.ZipArchiveMode]::Create)
foreach ($n in @('good.txt','../escape/x.txt')) {
  $e=$za.CreateEntry($n); $s=New-Object IO.StreamWriter($e.Open()); $s.Write("x"); $s.Dispose()
}
$za.Dispose(); $fs.Dispose()
$before = Entries $zx
"crafted: $($before -join ', ')"
$c = Open-Archive $zx $null
if (-not $c) { "  FAIL window never opened"; $fail++ }
else {
  $r = Find-Row $c '..'
  if ($r -lt 0) {
    "  ok   the traversing entry never becomes a selectable folder row"
  } else {
    $n = Select-Row $c $r
    if ($n -ne 1) { "  FAIL could not select the '..' row"; $fail++ }
    else {
      [void](Add-ViaButton $c "$w\extra\added.txt")
      Stop-Myrkr
      $after = Entries $zx
      # Not just "no '..' was written": the add must be refused OUTRIGHT and
      # rolled back. Checking only for a traversing name would pass just as
      # happily if the prefix were silently dropped and the file landed at the
      # root - which is the wrong answer arriving quietly, the exact failure
      # shape this arc keeps running into.
      $any = @($after | Where-Object { $_ -like '*added.txt*' })
      if ($any.Count -gt 0) { "  FAIL the add went ahead: $($any -join ', ')"; $fail++ }
      elseif ($after.Count -ne $before.Count) { "  FAIL the archive changed: [$($after -join ', ')]"; $fail++ }
      else { "  ok   the add was refused outright and rolled back" }
    }
  }
}
Stop-Myrkr

"`n=== mrk ==="
$env:MYRKR_DBG_NOSECDESK = "1"
foreach ($case in $cases) {
  $mrk = "$w\m_$($case.sel).mrk"
  if (Test-Path $mrk) { Remove-Item -LiteralPath $mrk -Force }
  # two positionals, so the entries are top.txt and docs/... - the same shape as
  # the zip, rather than everything under one "src" root
  cmd /c "$exe encrypt ""$w\src\top.txt"" ""$w\src\docs"" -o ""$mrk"" -p $PW 2>&1" | Out-Null
  if (-not (Test-Path $mrk)) { "  FAIL [$($case.label)] fixture not built"; $fail++; continue }
  $c = Open-Archive $mrk $PW
  if (-not $c) { "  FAIL [$($case.label)] container never opened"; $fail++; Stop-Myrkr; continue }
  $ok = $true
  if ($case.sel) {
    $r = Find-Row $c $case.sel
    if ($r -lt 0) { "  FAIL [$($case.label)] no row named '$($case.sel)'"; $fail++; $ok=$false }
    else {
      $n = Select-Row $c $r
      if ($n -ne 1) { "  FAIL [$($case.label)] selection did not take (selected=$n)"; $fail++; $ok=$false }
    }
  }
  if ($ok) {
    if (-not (Add-ViaButton $c "$w\extra\added.txt")) { "  FAIL [$($case.label)] the picker never appeared"; $fail++; Stop-Myrkr; continue }
    Stop-Myrkr
    # extract and look at where it actually landed
    $out = "$w\out_$($case.sel)"
    if (Test-Path $out) { Remove-Item -LiteralPath $out -Recurse -Force }
    cmd /c "$exe decrypt ""$mrk"" -o ""$out"" -p $PW 2>&1" | Out-Null
    $got = @(Get-ChildItem $out -Recurse -File -EA SilentlyContinue |
             ForEach-Object { $_.FullName.Substring($out.Length+1) -replace '\\','/' })
    $hit = @($got | Where-Object { $_ -eq $case.want })
    if ($hit.Count -eq 1) { "  ok   $($case.label)  ->  $($case.want)" }
    else { "  FAIL $($case.label): wanted '$($case.want)', got [$($got -join ', ')]"; $fail++ }
  }
  Stop-Myrkr
}
Remove-Item Env:\MYRKR_DBG_NOSECDESK -EA SilentlyContinue

if ($fail -gt 0) { "`n$fail FAILURE(S)"; Finish 1 } else { "`nALL PASS"; Finish 0 }

