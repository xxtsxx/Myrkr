# Step 3 of docs/DROP_INDICATOR.md: the destination box, and the destination
# following the CURSOR rather than the selection.
#
# The decisive case is the third one. Steps 2 and 3 are indistinguishable if
# the hovered row and the selected row agree, so every hover case here selects
# a DIFFERENT row first - one whose rule gives a different answer. A pass then
# cannot come from step 2 still doing the work.
#
# The box itself is checked in pixels, read out of the listview's own DC. That
# is the only honest way to assert that something was painted: g_dl_show says
# what the program intended, and this says what reached the screen. Client-area
# GetDC, not PrintWindow over non-client - see docs/UI_SURFACES.md for why that
# distinction is worth keeping.
#
# The fill is translucent, so it does not match CLR_ACCENT exactly; the border
# is drawn solid on top and that is what these assertions find. Which is half
# the reason it is drawn solid.
#
# Needs a dbg build (the WM_APP+3 hook is test-only); it builds one, and the
# caller is expected to rebuild release afterwards.
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "line1"
$root = Split-Path -Parent $PSScriptRoot
$exe  = "$root\bin\myrkr.exe"
$fail = 0
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class L {
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h,IntPtr dc);
  [DllImport("gdi32.dll")]  public static extern uint GetPixel(IntPtr dc,int x,int y);
  [DllImport("gdi32.dll")]  public static extern IntPtr CreateRectRgn(int a,int b,int c,int d);
  [DllImport("gdi32.dll")]  public static extern int GetRgnBox(IntPtr r,out RECT b);
  [DllImport("gdi32.dll")]  public static extern bool DeleteObject(IntPtr o);
  [DllImport("user32.dll")] public static extern int GetWindowRgn(IntPtr h,IntPtr r);
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
$ACCENT = 0x00B85F00        # CLR_ACCENT as a COLORREF: 0x00BBGGRR, RGB(0,95,184)
function Stop-Myrkr { Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }; Start-Sleep -Milliseconds 500 }
function Entries($z) { $a=[IO.Compression.ZipFile]::OpenRead($z); $n=@($a.Entries|ForEach-Object{$_.FullName}); $a.Dispose(); return $n }

function Open-Zip($path) {
  $p = Start-Process $exe -ArgumentList @("`"$path`"") -PassThru
  $m=[IntPtr]::Zero
  for($i=0;$i -lt 80 -and $m -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 250; $m=[L]::Find([uint32]$p.Id,"myrkr_window") }
  if ($m -eq [IntPtr]::Zero) { return $null }
  Start-Sleep -Seconds 2
  [void][L]::SetForegroundWindow($m); Start-Sleep -Milliseconds 600
  return @{ p=$p; m=$m; lv=[L]::ById($m,109); mem=[L]::VirtualAllocEx($p.Handle,[IntPtr]::Zero,[IntPtr]4096,0x3000,4) }
}
function Get-RowText($c,$row) {
  $li=New-Object byte[] 88; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([uint32]1).CopyTo($li,0)
  [BitConverter]::GetBytes([int32]$row).CopyTo($li,4)
  [BitConverter]::GetBytes([int64]($c.mem.ToInt64()+256)).CopyTo($li,24)
  [BitConverter]::GetBytes([int32]256).CopyTo($li,32)
  [void][L]::WriteProcessMemory($c.p.Handle,$c.mem,$li,[IntPtr]88,[ref]$wr)
  [void][L]::SendMessageW($c.lv,0x1073,[IntPtr]$row,$c.mem)
  $buf=New-Object byte[] 512; $rd=[IntPtr]::Zero
  [void][L]::ReadProcessMemory($c.p.Handle,[IntPtr]($c.mem.ToInt64()+256),$buf,[IntPtr]512,[ref]$rd)
  $t=[Text.Encoding]::Unicode.GetString($buf); $i=$t.IndexOf([char]0)
  if ($i -ge 0) { $t=$t.Substring(0,$i) }; return $t
}
function Find-Row($c,$name) {
  $n=[int][L]::SendMessageW($c.lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
  for($r=0;$r -lt $n;$r++){ if ((Get-RowText $c $r) -eq $name) { return $r } }
  return -1
}
# LVM_GETITEMRECT: the code goes in rc.left before the call, and the RECT has
# to live in the target's address space like every other listview pointer.
function Get-RowRect($c,$row) {
  $rc=New-Object byte[] 16; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([int32]0).CopyTo($rc,0)     # LVIR_BOUNDS
  [void][L]::WriteProcessMemory($c.p.Handle,$c.mem,$rc,[IntPtr]16,[ref]$wr)
  [void][L]::SendMessageW($c.lv,0x100E,[IntPtr]$row,$c.mem)
  $out=New-Object byte[] 16; $rd=[IntPtr]::Zero
  [void][L]::ReadProcessMemory($c.p.Handle,$c.mem,$out,[IntPtr]16,[ref]$rd)
  return @{ L=[BitConverter]::ToInt32($out,0); T=[BitConverter]::ToInt32($out,4)
            R=[BitConverter]::ToInt32($out,8); B=[BitConverter]::ToInt32($out,12) }
}
# A screen point in the middle of a row - what a cursor hovering it would be.
function Row-Point($c,$row) {
  $r = Get-RowRect $c $row
  $lr = New-Object L+RECT; [void][L]::GetWindowRect($c.lv,[ref]$lr)
  $x = $lr.L + $r.L + 20
  $y = $lr.T + [int](($r.T + $r.B)/2)
  return @{ x=$x; y=$y; packed=[IntPtr](([int64]$y -shl 32) -bor ([int64]$x -band 0xFFFFFFFF)) }
}
function Select-Row($c,$row) {
  $li=New-Object byte[] 88; $wr=[IntPtr]::Zero
  [BitConverter]::GetBytes([uint32]8).CopyTo($li,0)
  [BitConverter]::GetBytes([uint32]2).CopyTo($li,12)     # state
  [BitConverter]::GetBytes([uint32]2).CopyTo($li,16)     # stateMask
  [void][L]::WriteProcessMemory($c.p.Handle,$c.mem,$li,[IntPtr]88,[ref]$wr)
  [void][L]::SendMessageW($c.lv,0x102B,[IntPtr]$row,$c.mem)
  Start-Sleep -Milliseconds 400
  return [int][L]::SendMessageW($c.lv,0x1032,[IntPtr]::Zero,[IntPtr]::Zero)
}
# How many accent-coloured pixels are in the list's client area right now.
function Count-Accent($c) {
  $lr = New-Object L+RECT; [void][L]::GetWindowRect($c.lv,[ref]$lr)
  $dc = [L]::GetDC($c.lv); if ($dc -eq [IntPtr]::Zero) { return -1 }
  $n = 0
  for ($y=0; $y -lt ($lr.B-$lr.T); $y+=1) {
    for ($x=4; $x -lt ($lr.R-$lr.L-24); $x+=4) {
      if ([L]::GetPixel($dc,$x,$y) -eq $ACCENT) { $n++ }
    }
  }
  [void][L]::ReleaseDC($c.lv,$dc)
  return $n
}
function Set-Clip($file) {
  $col = New-Object System.Collections.Specialized.StringCollection
  [void]$col.Add($file); [Windows.Forms.Clipboard]::SetFileDropList($col)
  Start-Sleep -Milliseconds 300
}

Stop-Myrkr
"building dbg (the drop hook is test-only)..."
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
function Fresh-Zip($tag) {
  $z = "$w\$tag.zip"; if (Test-Path $z) { Remove-Item -LiteralPath $z -Force }
  [IO.Compression.ZipFile]::CreateFromDirectory("$w\src", $z); return $z
}

"`n--- 1. the box is painted while a drag hovers, and only then ---"
$z = Fresh-Zip 'line'
$c = Open-Zip $z
if (-not $c) { "  FAIL window never opened"; Stop-Myrkr; Finish 1 }
$before = Count-Accent $c
"  accent pixels at rest: $before"
$docs = Find-Row $c 'docs'
if ($docs -lt 0) { "  FAIL no 'docs' row"; $fail++ }
else {
  $pt = Row-Point $c $docs
  Set-Clip "$w\extra\added.txt"
  [void][L]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]1,$pt.packed)   # hover only
  Start-Sleep -Seconds 2
  $during = Count-Accent $c
  "  accent pixels while hovering: $during"
  if ($during -le $before) { "  FAIL nothing was painted while the drag hovered"; $fail++ }
  else { "  ok   the box is painted while a drag hovers ($before -> $during)" }
  # and it goes away again
  [void][L]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]0,$pt.packed)   # full: drop
  Start-Sleep -Seconds 5
  $after = Count-Accent $c
  "  accent pixels after the drop: $after"
  if ($after -ge $during) { "  FAIL the box was still there after the drop"; $fail++ }
  else { "  ok   the box is taken away by the drop ($during -> $after)" }
}
Stop-Myrkr

"`n--- 2. the box encloses the folder AND its contents; the root has none ---"
# The point of a box over a line: it says which folder by enclosing it. So the
# height is the assertion. In the tree top.txt / docs / a.txt / sub, hovering
# 'docs' must enclose THREE rows (itself, a.txt, sub) and hovering 'sub' must
# enclose ONE (itself - it is collapsed, so nothing of it is visible).
#
# The archive root draws nothing at all: the indicator names a folder, and the
# root is not one.
function Box-Extent($c) {
  $lr = New-Object L+RECT; [void][L]::GetWindowRect($c.lv,[ref]$lr)
  $dc = [L]::GetDC($c.lv); if ($dc -eq [IntPtr]::Zero) { return @{t=-1;b=-1} }
  $t = -1; $b = -1
  for ($y=0; $y -lt ($lr.B-$lr.T); $y++) {
    for ($x=4; $x -lt ($lr.R-$lr.L-24); $x+=4) {
      if ([L]::GetPixel($dc,$x,$y) -eq $ACCENT) { if ($t -lt 0) { $t=$y }; $b=$y; break }
    }
  }
  [void][L]::ReleaseDC($c.lv,$dc)
  return @{t=$t; b=$b}
}
function Hover($c,$name) {
  [void][L]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]1,(Row-Point $c (Find-Row $c $name)).packed)
  Start-Sleep -Seconds 2
  return Box-Extent $c
}
$z = Fresh-Zip 'track'
$c = Open-Zip $z
if (-not $c) { "  FAIL window never opened"; $fail++ }
else {
  # one row's height, measured rather than assumed
  $r0 = Get-RowRect $c 0
  $rowH = $r0.B - $r0.T
  Set-Clip "$w\extra\added.txt"
  $bDocs = Hover $c 'docs'
  $bSub  = Hover $c 'sub'
  $bRoot = Hover $c 'top.txt'
  $hDocs = $bDocs.b - $bDocs.t + 1
  $hSub  = $bSub.b  - $bSub.t  + 1
  "  row height $rowH; box over 'docs' = $hDocs px (y $($bDocs.t)..$($bDocs.b)), over 'sub' = $hSub px, over root = $(if($bRoot.t -lt 0){'none'}else{"y $($bRoot.t)"})"
  if ($bDocs.t -lt 0 -or $bSub.t -lt 0) { "  FAIL no box over a folder"; $fail++ }
  else {
    # 3 rows vs 1, allowing a pixel of slop at each edge
    if ($hDocs -lt (2.5*$rowH) -or $hDocs -gt (3.5*$rowH)) { "  FAIL 'docs' box is $hDocs px, wanted about 3 rows ($(3*$rowH))"; $fail++ }
    else { "  ok   'docs' encloses itself and its two visible children" }
    if ($hSub -gt (1.5*$rowH)) { "  FAIL collapsed 'sub' box is $hSub px, wanted about 1 row ($rowH)"; $fail++ }
    else { "  ok   collapsed 'sub' encloses just itself" }
    if ($bDocs.t -eq $bSub.t) { "  FAIL the box did not move between two different folders"; $fail++ }
    else { "  ok   the box moves between destinations" }
  }
  if ($bRoot.t -ge 0) { "  FAIL the archive root drew a box at y=$($bRoot.t)"; $fail++ }
  else { "  ok   the archive root draws nothing" }
}
Stop-Myrkr

"`n--- 3. the destination follows the CURSOR, not the selection ---"
# Hover a file inside 'docs' (destination: docs/) while 'top.txt' is SELECTED
# (whose rule would give the archive root). Only one of the two can be right,
# so this separates step 3 from step 2.
$z = Fresh-Zip 'cursor'
$c = Open-Zip $z
if (-not $c) { "  FAIL window never opened"; $fail++ }
else {
  $a   = Find-Row $c 'a.txt'
  $top = Find-Row $c 'top.txt'
  if ($a -lt 0 -or $top -lt 0) { "  FAIL rows not found (a.txt=$a top.txt=$top)"; $fail++ }
  else {
    $n = Select-Row $c $top
    if ($n -ne 1) { "  FAIL selection did not take (selected=$n)"; $fail++ }
    else {
      "  selected 'top.txt' (would give the root); hovering 'a.txt' (inside docs)"
      Set-Clip "$w\extra\added.txt"
      [void][L]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]0,(Row-Point $c $a).packed)
      Start-Sleep -Seconds 5
      Stop-Myrkr
      $e = Entries $z
      $got = @($e | Where-Object { $_ -like '*added.txt' }) | ForEach-Object { $_ -replace '\\','/' }
      if ($got -contains 'docs/added.txt') { "  ok   landed in docs/ - the cursor won" }
      elseif ($got -contains 'added.txt') { "  FAIL landed at the root: the SELECTION won, so the hover is not wired"; $fail++ }
      else { "  FAIL nothing was added: [$($e -join ', ')]"; $fail++ }
    }
  }
}
Stop-Myrkr

"`n--- 4. a drop off the rows lands at the root, whatever is selected ---"
# The empty-space rule, and a check that the hover really does override: 'docs'
# is selected, so the SELECTION rule would say docs/ and the cursor says root.
#
# This does NOT test the buttons - they open a picker and are covered by
# tests/prefixtest.ps1, which drives them for exactly this reason. An earlier
# draft of this case claimed to and did not; the label is the assertion.
$z = Fresh-Zip 'button'
$c = Open-Zip $z
if (-not $c) { "  FAIL window never opened"; $fail++ }
else {
  $docs = Find-Row $c 'docs'
  $n = Select-Row $c $docs
  if ($n -ne 1) { "  FAIL selection did not take"; $fail++ }
  else {
    Set-Clip "$w\extra\added.txt"
    [void][L]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]0,[IntPtr]0)   # pt {0,0}: off the rows
    Start-Sleep -Seconds 5
    Stop-Myrkr
    $e = Entries $z
    $got = @($e | Where-Object { $_ -like '*added.txt' }) | ForEach-Object { $_ -replace '\\','/' }
    # {0,0} is outside the list, so the hover gives the root - and that is the
    # answer a real drag onto blank space should give too.
    if ($got -contains 'added.txt') { "  ok   a drop off the rows lands at the root" }
    else { "  FAIL wanted the root, got [$($got -join ', ')]"; $fail++ }
  }
}
Stop-Myrkr


"`n--- 5. dropping into a COLLAPSED folder shows what arrived ---"
# The bug this test was written for. The entry reached the archive and the tree
# did not change by a single row - not on the reload, and not on reopening -
# because the folder it went into was shut. That is indistinguishable from the
# silent refusal this whole arc has been removing, and worse, because the file
# really did arrive.
$z = Fresh-Zip 'collapsed'
$c = Open-Zip $z
if (-not $c) { "  FAIL window never opened"; $fail++ }
else {
  $sub = Find-Row $c 'sub'          # a folder one level down: collapsed on load
  $n0  = [int][L]::SendMessageW($c.lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
  if ($sub -lt 0) { "  FAIL no 'sub' row"; $fail++ }
  else {
    Set-Clip "$w\extra\added.txt"
    [void][L]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]0,(Row-Point $c $sub).packed)
    Start-Sleep -Seconds 6
    $n1 = [int][L]::SendMessageW($c.lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
    $seen = $false
    for ($r=0; $r -lt $n1; $r++) { if ((Get-RowText $c $r) -eq 'added.txt') { $seen = $true } }
    Stop-Myrkr
    $e = Entries $z
    $inzip = @($e | Where-Object { ($_ -replace '\\','/') -eq 'docs/sub/added.txt' }).Count -eq 1
    "  rows $n0 -> $n1; in the archive: $inzip; visible in the tree: $seen"
    if (-not $inzip) { "  FAIL it did not reach docs/sub/: [$($e -join ', ')]"; $fail++ }
    elseif (-not $seen) { "  FAIL it is in the archive but the tree never opened the folder"; $fail++ }
    else { "  ok   the destination folder is opened, so the new entry is visible" }
  }
}
Stop-Myrkr


"--- 6. SCROLLED: the box lands on the row, and so does the drop ---"
# Reported from real use: targeting only worked at the very top of the list.
#
# This list scrolls by MOVING THE WHOLE CONTROL - the window is as tall as the
# content and is repositioned upward, clipped to the visible band by a window
# region (lv_apply). So the control's client space IS the content space, and
# LVM_GETITEMRECT already returns what the paint DC draws in. drop_box_set was
# adding g_lvscroll on top of that, which is wrong by exactly the scroll offset
# - right at precisely one position, the top, which is where every case above
# leaves the list.
#
# So: scroll first, then assert the painted box coincides with the row's own
# rect, both read in the control's client space. Comparing the box against the
# same arithmetic that positions it would prove nothing; LVM_GETITEMRECT is an
# independent answer from the control itself.
$zs = "$w\scrolled.zip"
if (Test-Path $zs) { Remove-Item -LiteralPath $zs -Force }
New-Item -ItemType Directory "$w\deep\zfolder" -Force | Out-Null
# FOLDERS as filler, not files: the tree sorts folders first, so among files
# 'zfolder' sat at row 0 and the wheel below scrolled it OFF the top - the
# fixture then aimed at nothing, every run, and the silent exit code hid it.
# Forty sibling folders put 'zfolder' last IN THE FOLDER GROUP, which is the
# bottom of a scrolled root, which is what this case is about.
1..40 | ForEach-Object {
  $d = "$w\deep\" + ("f{0:d2}fill" -f $_)
  New-Item -ItemType Directory $d -Force | Out-Null
  Set-Content "$d\x.txt" "x" }
1..3  | ForEach-Object { Set-Content "$w\deep\zfolder\c$_.txt" "c" }
[IO.Compression.ZipFile]::CreateFromDirectory("$w\deep", $zs)
$c = Open-Zip $zs
if (-not $c) { "  FAIL window never opened"; $fail++ }
else {
  # wheel the list down; the subclass turns WM_MOUSEWHEEL into lv_scroll_by
  for ($i=0; $i -lt 40; $i++) { [void][L]::SendMessageW($c.lv,0x020A,[IntPtr](-120 -shl 16),[IntPtr]0) }
  Start-Sleep -Milliseconds 800
  # The VISIBLE band, straight from the window region lv_apply sets. Without it
  # this case aimed at a row that was merely in the control and not on the
  # screen - LVM_HITTEST answers from client coordinates whether or not the row
  # is painted, so the drop "worked" while nothing was under the cursor at all.
  $rgn = [L]::CreateRectRgn(0,0,1,1); [void][L]::GetWindowRgn($c.lv,$rgn)
  $band = New-Object L+RECT; [void][L]::GetRgnBox($rgn,[ref]$band); [void][L]::DeleteObject($rgn)
  $row = Find-Row $c 'zfolder'
  $rr  = Get-RowRect $c $row
  "  scrolled; visible band y $($band.T)..$($band.B); 'zfolder' is row $row, client y $($rr.T)..$($rr.B)"
  if ($band.T -le 0) { "  FAIL the list did not scroll - nothing was under test"; $fail++ }
  elseif ($rr.T -lt $band.T -or $rr.B -gt $band.B) {
    "  FAIL the fixture put 'zfolder' outside the visible band - nothing was under the cursor"; $fail++ }
  else {
    Set-Clip "$w\extra\added.txt"
    [void][L]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]1,(Row-Point $c $row).packed)
    Start-Sleep -Seconds 2
    $b = Box-Extent $c
    "  box y $($b.t)..$($b.b) vs row y $($rr.T)..$($rr.B)"
    if ($b.t -lt 0) { "  FAIL no box was painted at all"; $fail++ }
    elseif ([Math]::Abs($b.t - $rr.T) -gt 2) {
      "  FAIL the box is $($b.t - $rr.T) px off the row it names"; $fail++ }
    else { "  ok   the box sits on its row when the list is scrolled" }
    # and the drop itself must still pick that folder
    [void][L]::PostMessageW($c.m,$WM_APP_DROPTEST,[IntPtr]0,(Row-Point $c $row).packed)
    Start-Sleep -Seconds 6
    Stop-Myrkr
    $e = Entries $zs
    if (@($e | Where-Object { ($_ -replace '\\','/') -eq 'zfolder/added.txt' }).Count -eq 1) {
      "  ok   and the drop lands in that folder, not another" }
    else { "  FAIL the drop went elsewhere: $(@($e | Where-Object { $_ -like '*added.txt' }) -join ', ')"; $fail++ }
  }
}
Stop-Myrkr

if ($fail -gt 0) { "`n$fail FAILURE(S)"; Finish 1 } else { "`nALL PASS"; Finish 0 }

