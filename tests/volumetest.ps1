# A container split across volumes comes back whole.
#
# The design is in docs/VOLUMES.md: a volume is NOT a unit of encryption. The
# container is produced exactly as it always is and the byte stream is then cut,
# so concatenating the parts reproduces it. That is what this checks, from both
# ends - the parts exist and are shaped as the format says, and the archive
# extracts identically whichever member you hand the reader.
#
# Needs a dbg build: encrypt/decrypt are refused on the command line in release,
# and MYRKR_DBG_VOLBYTES only exists there.
# SHOWN TO FAIL, against real broken builds rather than synthetic mutations:
#
#  - 1.0.64: `vol_name` wrote 3 digits past part 999, so a 1000-part set produced
#    parts named `set.part100:0.mrk` - a name Windows reads as an ALTERNATE DATA
#    STREAM. A hundred parts went into hidden streams and encrypt exited 0. The
#    "1173 parts, every one a real file with a legal name" and "no alternate data
#    stream host was created" checks were added for it and fail against 1.0.64.
#  - 1.0.65: `vol_part_suffix` matched a fixed 8-character suffix, so 4-digit
#    part numbers leaked into the decrypted entry NAMES. "a right-drag decrypt
#    names it boot.wim, not boot.wim.partNNN" fails against it.
#  - 1.0.68: `vol_settle` cleared `g_vol_split` when it promoted a 1-of-1 set, so
#    do_pack then tried a temp->final rename for a temp that never existed and
#    reported "I/O failure" over a perfectly good container. "a split that
#    produced one part is put back under its plain name" fails against it.
#
# This block exists because the suite's own rule is that a test nobody has seen
# fail is a test nobody should believe, and until 1.0.71 this file did not say
# which failures it had seen.
$ErrorActionPreference = "Stop"
$fail = 0
$w = Join-Path $env:TEMP "mrk_volume"
$exe = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\myrkr.exe"
$PW = "Correct-Horse-Battery-9"

"building dbg..."
$blog = cmd /c "$(Split-Path -Parent $PSScriptRoot)\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

Remove-Item $w -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory "$w\in" -Force | Out-Null
# Enough data to need several parts at the limit below, and content that is
# checked byte for byte afterwards rather than merely counted.
1..40 | ForEach-Object {
  $b = New-Object byte[] 262144
  (New-Object Random $_).NextBytes($b)
  [IO.File]::WriteAllBytes("$w\in\f$_.bin", $b)
}
$made = (Get-ChildItem "$w\in" -File).Count
"input        : $made files, $([math]::Round((Get-ChildItem "$w\in" -File | Measure-Object Length -Sum).Sum/1MB,1)) MiB"

# ---- split ------------------------------------------------------------------
$env:MYRKR_DBG_VOLBYTES = "2000000"      # ~2 MB per part
$enc = cmd /c "`"$exe`" encrypt `"$w\in`" -o `"$w\set.mrk`" -p $PW 2>&1"
"encrypt exit $LASTEXITCODE"
if ($LASTEXITCODE -ne 0) { $enc | Select-Object -Last 4; "  FAIL encrypt"; exit 1 }
$parts = @(Get-ChildItem $w -Filter "set.part*.mrk" | Sort-Object Name)
"parts        : $($parts.Count)  [$(($parts | ForEach-Object { [math]::Round($_.Length/1MB,2) }) -join ', ') MiB]"
if ($parts.Count -lt 2) { "  FAIL the limit did not split anything"; $fail++ }
else { "  ok   it split into $($parts.Count) parts" }
if (Test-Path "$w\set.mrk") { "  FAIL an unsplit container was written as well"; $fail++ }

# every part must be a part, and only the last may be final
$bad = 0; $final = 0
foreach ($p in $parts) {
  $h = [IO.File]::ReadAllBytes($p.FullName)[0..31]
  if ([Text.Encoding]::ASCII.GetString($h[0..3]) -ne "MVOL") { $bad++ }
  if ($h[24] -band 1) { $final++ }
}
if ($bad -eq 0) { "  ok   every part carries the MVOL header" } else { "  FAIL $bad parts are not parts"; $fail++ }
if ($final -eq 1) { "  ok   exactly one part is marked final" } else { "  FAIL $final parts marked final"; $fail++ }

# ---- read it back, from part 1 ---------------------------------------------
$dec = cmd /c "`"$exe`" decrypt `"$($parts[0].FullName)`" -o `"$w\back1`" -p $PW 2>&1"
if ($LASTEXITCODE -ne 0) { "  FAIL decrypt from part 1 exit $LASTEXITCODE"; $dec | Select-Object -Last 3; $fail++ }
else { "  ok   it decrypts when handed part 1" }

# ---- and from a MIDDLE part, which is the point of assembling by header -----
if ($parts.Count -ge 2) {
  $mid = $parts[[int]($parts.Count/2)]
  $dec = cmd /c "`"$exe`" decrypt `"$($mid.FullName)`" -o `"$w\back2`" -p $PW 2>&1"
  if ($LASTEXITCODE -ne 0) { "  FAIL decrypt from $($mid.Name) exit $LASTEXITCODE"; $fail++ }
  else { "  ok   it decrypts when handed $($mid.Name)" }
}

# ---- contents, byte for byte ------------------------------------------------
$src = Get-ChildItem "$w\in" -File | Sort-Object Name
$got = Get-ChildItem "$w\back1" -Recurse -File -EA SilentlyContinue | Sort-Object Name
if ($got.Count -ne $made) { "  FAIL $($got.Count) of $made files came back"; $fail++ }
else {
  $diff = 0
  foreach ($f in $src) {
    $b = Get-ChildItem "$w\back1" -Recurse -File | Where-Object { $_.Name -eq $f.Name }
    if (-not $b) { $diff++; continue }
    if ((Get-FileHash $f.FullName -Algorithm SHA256).Hash -ne (Get-FileHash $b.FullName -Algorithm SHA256).Hash) { $diff++ }
  }
  if ($diff -eq 0) { "  ok   all $made files match byte for byte" }
  else { "  FAIL $diff files differ"; $fail++ }
}

# ---- a set cannot be edited, and refusing must not damage it ----------------
# Both edit paths rewrite the index through a plain handle and one of them
# overwrites entries in place; run against a set they would write past the end
# of whichever part happened to be last. The refusal has to come BEFORE any of
# that, so the set has to still be readable afterwards - which is the half of
# this check that would catch a refusal placed too late.
$before = @{}
foreach ($p in $parts) { $before[$p.Name] = (Get-FileHash $p.FullName -Algorithm SHA256).Hash }
$add = cmd /c "`"$exe`" add `"$($parts[0].FullName)`" `"$w\in\f1.bin`" -p $PW 2>&1"
if ($LASTEXITCODE -eq 0) { "  FAIL adding to a volume set was allowed"; $fail++ }
else { "  ok   adding to a set is refused (exit $LASTEXITCODE)" }
$changed = 0
foreach ($p in $parts) {
  if (-not (Test-Path $p.FullName)) { $changed++; continue }
  if ((Get-FileHash $p.FullName -Algorithm SHA256).Hash -ne $before[$p.Name]) { $changed++ }
}
if ($changed -eq 0) { "  ok   the refusal left every part byte-for-byte unchanged" }
else { "  FAIL the refused add altered $changed parts"; $fail++ }
$dec = cmd /c "`"$exe`" decrypt `"$($parts[0].FullName)`" -o `"$w\back4`" -p $PW 2>&1"
if ($LASTEXITCODE -eq 0 -and (Get-ChildItem "$w\back4" -Recurse -File -EA SilentlyContinue).Count -eq $made) {
  "  ok   and the set still reads back in full"
} else { "  FAIL the set no longer reads after a refused add"; $fail++ }

# ---- the WINDOW must open a part in decrypt mode -----------------------------
# Reported 2026-08-12: "the split archives are not recognized by Myrkr as Myrkr
# files, so it will try to encrypt them again instead of decrypting them."
# detect_op read the first 32 bytes raw and compared them to the container magic,
# which for a part is MVOL - so the window offered to ENCRYPT the container it
# had been asked to open. The CLI checks above all passed while this was broken,
# because none of them goes through the window.
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public struct RC { public int l,t,r,b; }
public class V { [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr GetCapture();
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RC r);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint x,uint y,uint d,IntPtr e);
 [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h,IntPtr a,int x,int y,int cx,int cy,uint f);
 public static void Top(IntPtr h){ SetWindowPos(h,(IntPtr)(-1),0,0,0,0,0x13); }
 // A click posted STRAIGHT TO THE CONTROL, in its own client coordinates.
 // The cursor version below (ClickAt) drives SetCursorPos + mouse_event, which
 // needs the target to be the topmost window at that screen point and nothing
 // to be covering it - and when that is not true the click silently lands
 // somewhere else and the check fails having tested nothing. WM_LBUTTONDOWN
 // carries its coordinates in lParam, so it needs no cursor, no z-order and no
 // foreground: the message goes onto the control's own queue. It works across
 // processes because nothing here is a pointer.
 public static void ClickIn(IntPtr h,int dx,int dy){
  IntPtr lp=(IntPtr)((dy<<16)|(dx&0xFFFF));
  PostMessageW(h,0x0201,(IntPtr)1,lp); System.Threading.Thread.Sleep(60);
  PostMessageW(h,0x0202,IntPtr.Zero,lp); }
 public static void ClickAt(IntPtr h){ RC r; GetWindowRect(h,out r);
  SetCursorPos((r.l+r.r)/2,(r.t+r.b)/2); System.Threading.Thread.Sleep(120);
  mouse_event(2,0,0,0,IntPtr.Zero); System.Threading.Thread.Sleep(60); mouse_event(4,0,0,0,IntPtr.Zero); }
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr SendStr(IntPtr h,uint m,IntPtr w,string l);
 [DllImport("user32.dll",EntryPoint="SendMessageW")] public static extern IntPtr SendMsg(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
 public delegate bool EnumProc(IntPtr h,IntPtr p);
 public static IntPtr found;
 public static IntPtr ById(IntPtr t,int id){ found=IntPtr.Zero;
  EnumChildWindows(t,delegate(IntPtr h,IntPtr q){ if(GetDlgCtrlID(h)==id){found=h;return false;} return true;},IntPtr.Zero); return found; }
 public static string Txt(IntPtr h){ var b=new StringBuilder(256); GetWindowTextW(h,b,256); return b.ToString(); }
 public static IntPtr Find(uint pid,string cls){ IntPtr r=IntPtr.Zero;
  EnumWindows(delegate(IntPtr h,IntPtr q){ uint w; GetWindowThreadProcessId(h,out w);
   if(w!=pid||!IsWindowVisible(h)) return true; var c=new StringBuilder(128); GetClassName(h,c,128);
   if(c.ToString()==cls){ r=h; return false; } return true;},IntPtr.Zero); return r; } }
"@
$env:MYRKR_DBG_NOSECDESK="1"
Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
$q=Start-Process $exe -ArgumentList @("`"$($parts[0].FullName)`"") -PassThru
$sd=[IntPtr]::Zero
for($i=0;$i -lt 80 -and $sd -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 150; $sd=[V]::Find([uint32]$q.Id,"myrkr_secdesk") }
# A container asks for a password before it opens; an ENCRYPT does not - the
# password lives in the window. So the prompt appearing is itself the assertion.
if ($sd -ne [IntPtr]::Zero) { "  ok   opening a part asks for the password (it is a container)" }
else {
  $mw=[V]::Find([uint32]$q.Id,"myrkr_window")
  if ($mw -ne [IntPtr]::Zero) { "  FAIL a part opened as '$([V]::Txt([V]::ById($mw,104)))' - it was not recognised as a container" }
  else { "  FAIL opening a part produced neither a prompt nor a window" }
  $fail++
}
Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
$env:MYRKR_DBG_NOSECDESK=""

# ---- dragging OUT of a split container ---------------------------------------
# Reported 2026-08-12: double-clicking part 1 opened the container fine, and
# dragging the file out of it failed with Explorer's "Unspecified error".
# estream.asm opened the container with its own file_open_read and read at
# LOGICAL offsets - fourth instance of the same mistake.
#
# `estream` drives the same IStream/IDataObject the drag uses, through the
# vtable, with no drag anywhere near it (see estreamtest.ps1).
$out = "$w\dragged"
New-Item -ItemType Directory $out -Force | Out-Null   # estream will not create it
$r = cmd /c "`"$exe`" estream `"$($parts[0].FullName)`" -o `"$out`" -p $PW 2>&1"
if ($LASTEXITCODE -ne 0) {
  "  FAIL dragging out of a set failed (exit $LASTEXITCODE)"; $r | Select-Object -Last 3 | ForEach-Object { "       $_" }; $fail++
} else {
  # `estream` holds ES_TEST_MAX (8) streams open at once and stops there, so it
  # drags out 8 of the 40 - the harness's cap, not a limit of the feature. Eight
  # CONCURRENT streams is the case that matters here anyway: it is what the set
  # refcount exists for, since one stream closing must not shut the parts the
  # other seven are still reading.
  $got = @(Get-ChildItem $out -Recurse -File -EA SilentlyContinue)
  if ($got.Count -lt 1) { "  FAIL nothing dragged out of the set"; $fail++ }
  else {
    # Compared by CONTENT, not by name: `estream` writes es_0.bin, es_1.bin...
    # by index, so a name-based match would fail for every file whatever the
    # bytes were - which it duly did the first time this was written.
    $want = @{}
    foreach ($f in Get-ChildItem "$w\in" -File) { $want[(Get-FileHash $f.FullName -Algorithm SHA256).Hash] = $true }
    $bad = 0
    foreach ($b in $got) { if (-not $want[(Get-FileHash $b.FullName -Algorithm SHA256).Hash]) { $bad++ } }
    if ($bad -eq 0) { "  ok   $($got.Count) concurrent streams drag out of the set byte for byte" }
    else { "  FAIL $bad of $($got.Count) dragged files differ"; $fail++ }
  }
}

# ---- the name a set decrypts to, through the WINDOW --------------------------
# Reported twice. The first fix touched derive_output_name (cmd.asm) and the
# report came back: a right-drag goes through build_output (gui.asm), which had
# its own copy of the ".mrk" strip. Both call one helper now, and this drives the
# GUI path rather than the CLI one - which is the whole reason it was missed.
#
# It has to be a SINGLE-FILE container. An archive extracts into the container's
# parent folder and never derives a name by stripping, so build_output's strip is
# not reached at all - the first version of this check used the folder container
# above and passed with the fix removed, which is worth more than the check.
$rd = "$w\rd"
New-Item -ItemType Directory $rd -Force | Out-Null
$one = "$w\boot.wim"
$ob = New-Object byte[] 900000
(New-Object Random 21).NextBytes($ob)
[IO.File]::WriteAllBytes($one, $ob)
$env:MYRKR_DBG_VOLBYTES = "300000"
cmd /c "`"$exe`" encrypt `"$one`" -o `"$w\boot.wim.mrk`" -p $PW" | Out-Null
$oneparts = @(Get-ChildItem $w -Filter "boot.wim.part*.mrk" | Sort-Object Name)
$env:MYRKR_DBG_VOLBYTES = ""
if ($oneparts.Count -lt 2) { "  FAIL the single-file container did not split"; $fail++ }
$env:MYRKR_DBG_NOSECDESK="1"
Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
$q=Start-Process $exe -ArgumentList @("`"$($oneparts[0].FullName)`"","--to","`"$rd`"") -PassThru
$pr=[IntPtr]::Zero
for($i=0;$i -lt 80 -and $pr -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 150; $pr=[V]::Find([uint32]$q.Id,"myrkr_secdesk") }
if ($pr -eq [IntPtr]::Zero) { "  FAIL no prompt on the right-drag decrypt"; $fail++ }
else {
  [void][V]::SendStr([V]::GetDlgItem($pr,156),0x000C,[IntPtr]::Zero,$PW); Start-Sleep -Milliseconds 300
  [void][V]::PostMessageW($pr,0x0111,[IntPtr]104,[IntPtr]::Zero)
  for($i=0;$i -lt 200;$i++){ Start-Sleep -Milliseconds 100; try { $null=Get-Process -Id $q.Id -EA Stop } catch { break } }
  $names = @(Get-ChildItem $rd -Recurse -EA SilentlyContinue | ForEach-Object { $_.Name })
  if ($names -contains "boot.wim") { "  ok   a right-drag decrypt names it boot.wim, not boot.wim.partNNN" }
  else { "  FAIL right-drag produced: $($names -join ', ')"; $fail++ }
  if (($names | Where-Object { $_ -like "*.part0*" }).Count -eq 0) { "  ok   no part number leaked into the name" }
  else { "  FAIL a part number leaked into the output name: $($names -join ', ')"; $fail++ }
  $back = Get-ChildItem $rd -Recurse -File | Where-Object { $_.Name -eq "boot.wim" }
  if ($back -and (Get-FileHash $one -Algorithm SHA256).Hash -eq (Get-FileHash $back.FullName -Algorithm SHA256).Hash) {
    "  ok   and its contents are byte-identical"
  } else { "  FAIL the right-dragged file does not match the original"; $fail++ }
}
Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
$env:MYRKR_DBG_NOSECDESK=""

# ---- and the WINDOW says WHY, rather than guessing -------------------------
# Reported: dropping a file into an open set gave "It may be open in another
# program, or on a drive with no room left" - three wrong guesses at once. The
# CLI prints the real reason, but the window never shows stderr, so it fell back
# to the generic add-failure text.
$env:MYRKR_DBG_NOSECDESK="1"
Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
$q=Start-Process $exe -ArgumentList @("`"$($oneparts[0].FullName)`"") -PassThru
$sd=[IntPtr]::Zero
for($i=0;$i -lt 80 -and $sd -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 150; $sd=[V]::Find([uint32]$q.Id,"myrkr_secdesk") }
if ($sd -eq [IntPtr]::Zero) { "  FAIL no prompt when opening the set"; $fail++ }
else {
  [void][V]::SendStr([V]::GetDlgItem($sd,156),0x000C,[IntPtr]::Zero,$PW); Start-Sleep -Milliseconds 300
  [void][V]::PostMessageW($sd,0x0111,[IntPtr]104,[IntPtr]::Zero)
  $mw=[IntPtr]::Zero
  for($i=0;$i -lt 100 -and $mw -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 150; $mw=[V]::Find([uint32]$q.Id,"myrkr_window") }
  if ($mw -eq [IntPtr]::Zero) { "  FAIL the set did not open in a window"; $fail++ }
  else {
    # REMOVE, not a drop. The reported sequence was Remove -> refusal -> Exit
    # dead, and a removal is job 2 - the one job that disables the Exit button on
    # purpose, because it doubles as Cancel and a removal cannot be undone half
    # way. A drop is job 1 and leaves the button enabled, which is why driving a
    # drop here reproduced nothing for two rounds.
    $lv=[V]::ById($mw,109)
    # No Top() and no cursor: the click is posted to the list view itself (see
    # ClickIn). This check failed for a whole day because SetCursorPos put the
    # pointer over a window that was not this one - the same foreground-lock
    # class of probe bug this suite has hit three times.
    [V]::ClickIn($lv, 40, 14)                                               # select row 0
    Start-Sleep -Milliseconds 400
    # Prove the click DID something before relying on it: a listview with no
    # selection means Remove has nothing to do and would produce no message,
    # which is indistinguishable from the bug this check is looking for.
    # LVM_GETSELECTEDCOUNT is LVM_FIRST+50 = 0x1032.  A first version of this
    # line used 0x1004, which is LVM_GETITEMCOUNT - so it read the number of ROWS,
    # was always >= 1, and could never fail.  Caught by mutating the click to land
    # where no row is: the guard stayed silent and the old vague failure came back.
    $sel = [V]::SendMsg($lv, 0x1032, [IntPtr]::Zero, [IntPtr]::Zero)        # LVM_GETSELECTEDCOUNT
    if ([int]$sel -lt 1) { "  FAIL the probe selected no row - it is testing nothing"; $fail++ }
    [void][V]::PostMessageW($mw,0x0111,[IntPtr]161,[IntPtr]::Zero)          # ID_CMD_REMOVE
    $mb=[IntPtr]::Zero
    for($i=0;$i -lt 120 -and $mb -eq [IntPtr]::Zero;$i++){ Start-Sleep -Milliseconds 150; $mb=[V]::Find([uint32]$q.Id,"myrkr_mbox") }
    if ($mb -eq [IntPtr]::Zero) { "  FAIL dropping into a set produced no message at all"; $fail++ }
    else {
      # The BODY is owner-drawn from a global, so it has no window text. The
      # TITLE is the box's caption, and a top-level caption reads fine
      # cross-process - unlike an EDIT, per afterencrypttest's Edit() note.
      $t=[V]::Txt($mb)
      if ($t -match "split across volumes") { "  ok   the window says the container is split, not that the disk is full" }
      else { "  FAIL the box was titled: '$t'"; $fail++ }
      # ...and the window must still be USABLE afterwards. Reported: Exit stopped
      # working after this dialog while Decrypt still did. mbox disables the parent
      # for the duration and re-enables it on the way out; if anything leaves the
      # Exit button disabled, the only way out of the window is the X.
      [void][V]::PostMessageW($mb,0x0111,[IntPtr]104,[IntPtr]::Zero)   # OK
      Start-Sleep -Milliseconds 800
      $ex=[V]::ById($mw,107)                                           # ID_CANCEL = Exit
      if ($ex -eq [IntPtr]::Zero) { "  FAIL no Exit button after the dialog"; $fail++ }
      elseif (-not [V]::IsWindowEnabled($ex)) { "  FAIL the Exit button is left DISABLED after the dialog"; $fail++ }
      else {
        "  ok   the Exit button is enabled after the dialog"
        # A REAL click, not a posted command: the report is that the button does
        # not respond to the mouse, and posting WM_COMMAND bypasses exactly the
        # input routing that would be at fault. Capture is reported too - if
        # anything still holds it, child buttons never see a click.
        "       capture after the dialog: $([V]::GetCapture())"
        [V]::Top($mw); Start-Sleep -Milliseconds 300
        [V]::ClickAt($ex)
        $gone=$false
        for($i=0;$i -lt 60;$i++){ Start-Sleep -Milliseconds 100; try { $null=Get-Process -Id $q.Id -EA Stop } catch { $gone=$true; break } }
        if ($gone) { "  ok   and clicking Exit closes the window" }
        else { "  FAIL Exit did nothing - the window is still open"; $fail++ }
      }
    }
  }
}
Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
$env:MYRKR_DBG_NOSECDESK=""

# ---- a missing tail must be refused, not silently short ---------------------
# The final flag exists for exactly this. Remove the last part and the set must
# fail to open rather than extracting a prefix.
Remove-Item $parts[-1].FullName -Force
$dec = cmd /c "`"$exe`" decrypt `"$($parts[0].FullName)`" -o `"$w\back3`" -p $PW 2>&1"
if ($LASTEXITCODE -eq 0) { "  FAIL a set missing its last part still opened"; $fail++ }
else { "  ok   a missing tail is refused (exit $LASTEXITCODE)" }


# ---- MORE THAN 999 PARTS -----------------------------------------------------
# The part number is written into the name by hand, and it used to be three
# digits with no check that the number fitted. Part 1000 put 10 in the hundreds
# place, and '0'+10 is ':' - which in a Windows path is not a character, it is
# the alternate-data-stream separator. Parts 1000-1099 were created as HIDDEN
# STREAMS on a zero-length file called "<base>.part", parts 1100+ came out as
# "<base>.part;NN.mrk", and encrypt exited 0.
#
# It even round-tripped on the machine that wrote it, because the reader builds
# the same broken name and follows the writer into the same stream - so a check
# that only asked "does it come back" would have passed. What it does not
# survive is the folder being COPIED anywhere: streams do not travel to FAT, to
# a zip, to a share, or through most backup tools. Splitting exists so that the
# pieces can be moved.
#
# Reachable at the smallest split the GUI offers (100 MB) on any input over
# ~100 GB. So this asserts the FILES, not the round trip.
$w2 = "$env:TEMP\myrkr_voltest_1000"
Remove-Item $w2 -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory $w2 | Out-Null
$big = New-Object byte[] 1200000
(New-Object Random 7).NextBytes($big)
[System.IO.File]::WriteAllBytes("$w2\big.bin", $big)
$env:MYRKR_DBG_VOLBYTES = "1024"
cmd /c "`"$exe`" encrypt `"$w2\big.bin`" -o `"$w2\set.mrk`" -p $PW 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) { "  FAIL a 1000+ part encrypt failed (exit $LASTEXITCODE)"; $fail++ }
else {
  $named = @(Get-ChildItem "$w2\set.part*.mrk" -EA SilentlyContinue)
  $odd   = @(Get-ChildItem $w2 -File | Where-Object { $_.Name -notmatch '^(big\.bin|set\.part\d{3,4}\.mrk)$' })
  if ($named.Count -le 999) { "  FAIL only $($named.Count) parts - the fixture never passed 999"; $fail++ }
  elseif ($odd.Count) { "  FAIL $($odd.Count) part(s) with unusable names, e.g. '$($odd[0].Name)'"; $fail++ }
  else { "  ok   $($named.Count) parts, every one a real file with a legal name" }

  # An ADS host is invisible to a plain listing, so ask for the streams.
  $adshost = Get-Item "$w2\set.part" -EA SilentlyContinue
  if ($adshost) {
    $ads = @(Get-Item "$w2\set.part" -Stream * -EA SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' })
    "  FAIL parts went into $($ads.Count) alternate data streams on 'set.part'"; $fail++
  } else { "  ok   no alternate data stream host was created" }

  # And it must open when handed a member ABOVE 999 - the reader strips the
  # ".partNNNN.mrk" tail to find the siblings, and a fixed-width strip cuts in
  # the wrong place and then looks for a set that does not exist.
  # Only the well-formed names, and only for a label. Sorting the broken ones
  # throws, and a check that dies takes the checks after it down with it - the
  # ceiling cases below never ran the first time this caught the bug.
  $ok4 = @($named | Where-Object { $_.Name -match '^set\.part\d{3,4}\.mrk$' })
  $hi  = ($ok4 | Sort-Object { [int]($_.Name -replace '\D','') } | Select-Object -Last 1)
  cmd /c "`"$exe`" decrypt `"$w2\set.part1000.mrk`" -o `"$w2\back`" -p $PW 2>&1" | Out-Null
  $rc = $LASTEXITCODE
  $got = Get-ChildItem "$w2\back" -Recurse -File -EA SilentlyContinue | Select-Object -First 1
  if ($rc -ne 0 -or -not $got) { "  FAIL handing it part 1000 did not open the set (exit $rc)"; $fail++ }
  elseif ((Get-FileHash $got.FullName -Algorithm SHA256).Hash -ne (Get-FileHash "$w2\big.bin" -Algorithm SHA256).Hash) {
    "  FAIL opened by part 1000 but the contents differ"; $fail++
  } else { "  ok   the set opens when handed part 1000, byte for byte (last is $($hi.Name))" }
}
Remove-Item $w2 -Recurse -Force -EA SilentlyContinue

# ---- past the ceiling: refused, and nothing left behind ----------------------
# The reader refuses a set with more members than it will assemble. The writer
# knew nothing about that, so a small enough part size on a big enough input
# produced a set that encrypt called a success and no reader could ever open. It
# now stops at the same number - and deletes what it wrote, because do_pack's
# cleanup names the un-split output, which a split run never creates.
$w3 = "$env:TEMP\myrkr_voltest_cap"
Remove-Item $w3 -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory $w3 | Out-Null
$big2 = New-Object byte[] 6000000
(New-Object Random 9).NextBytes($big2)
[System.IO.File]::WriteAllBytes("$w3\big.bin", $big2)
$out = cmd /c "`"$exe`" encrypt `"$w3\big.bin`" -o `"$w3\set.mrk`" -p $PW 2>&1"
$rc  = $LASTEXITCODE
$left = @(Get-ChildItem "$w3\set.part*.mrk" -EA SilentlyContinue)
if ($rc -eq 0) { "  FAIL a set past the part ceiling was written as a success"; $fail++ }
elseif (($out -join ' ') -notmatch "volume parts") {
  "  FAIL refused, but blamed something else: $($out | Select-Object -Last 1)"; $fail++
} else { "  ok   past the part ceiling it refuses and says which limit (exit $rc)" }
if ($left.Count -ne 0) { "  FAIL $($left.Count) unusable parts left behind after the refusal"; $fail++ }
else { "  ok   and it deleted the parts it had written" }
Remove-Item $w3 -Recurse -Force -EA SilentlyContinue


# ---- A SPLIT SIZE IS A CEILING, NOT A REQUEST FOR A SET ---------------------
# Reported 2026-08-13: with the split set to 100 MB, a 50 MB container was still
# written as <base>.part001.mrk with a volume header on it - named like a member
# of a set and refusing edits like one, for a size it never came near.
#
# Two mechanisms, deliberately redundant. do_pack estimates the container up
# front and drops the limit when it cannot be reached; vol_settle catches a
# split that produced one part anyway. Removing the ESTIMATE alone changes no
# outcome here - vol_settle puts the file back - so the check below cannot
# isolate it, and saying so beats implying otherwise. What the estimate buys is
# that the common case costs nothing: no volume header is written, so none has
# to be stripped out again, and the container keeps the write-to-temp-then-
# rename protection that a set gives up. Removing VOL_SETTLE alone DOES fail,
# in the second case below.
$w4 = "$env:TEMP\myrkr_voltest_fits"
Remove-Item $w4 -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory $w4 | Out-Null
$small = New-Object byte[] 3000000
(New-Object Random 11).NextBytes($small)
[IO.File]::WriteAllBytes("$w4\a.bin", $small)
$env:MYRKR_DBG_VOLBYTES = "50000000"          # 50 MB limit, 3 MB of input
cmd /c "`"$exe`" encrypt `"$w4\a.bin`" -o `"$w4\out.mrk`" -p $PW 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) { "  FAIL encrypt under an unreachable limit failed ($LASTEXITCODE)"; $fail++ }
else {
  $parts4 = @(Get-ChildItem "$w4\out.part*.mrk" -EA SilentlyContinue)
  if ($parts4.Count -ne 0) { "  FAIL a container that fits was still split into $($parts4.Count) part(s)"; $fail++ }
  elseif (-not (Test-Path "$w4\out.mrk")) { "  FAIL no plain container was produced"; $fail++ }
  else {
    # The MVOL header must be gone too, not just the name - the first four bytes
    # decide what every reader treats it as.
    $magic = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes("$w4\out.mrk")[0..3])
    if ($magic -ne "MYRK") { "  FAIL it is named plainly but still starts '$magic'"; $fail++ }
    else { "  ok   a container that fits the limit is a plain container, not a 1-of-1 set" }
  }
  # ...and the whole point: it takes edits, which a set refuses.
  Set-Content "$w4\extra.txt" "added after the fact"
  cmd /c "`"$exe`" add `"$w4\out.mrk`" `"$w4\extra.txt`" -p $PW 2>&1" | Out-Null
  if ($LASTEXITCODE -ne 0) { "  FAIL it still refuses edits (exit $LASTEXITCODE)"; $fail++ }
  else { "  ok   and it accepts an edit" }
}
Remove-Item $w4 -Recurse -Force -EA SilentlyContinue

# ---- estimated over, actual under: vol_settle puts it back ------------------
# The estimate is store-mode, so compression is the one thing that can beat it.
# 20 MB of zeros under a 5 MB limit: the estimate says 20 MB and enables the
# split, and what actually gets written is about a kilobyte. That single part
# has to end up as an ordinary container, header stripped and renamed - which is
# the path a test would otherwise never reach.
$w5 = "$env:TEMP\myrkr_voltest_settle"
Remove-Item $w5 -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory $w5 | Out-Null
[IO.File]::WriteAllBytes("$w5\z.bin", (New-Object byte[] 20000000))
$env:MYRKR_DBG_VOLBYTES = "5000000"
cmd /c "`"$exe`" encrypt `"$w5\z.bin`" --compress -o `"$w5\out.mrk`" -p $PW 2>&1" | Out-Null
$rc5 = $LASTEXITCODE
$parts5 = @(Get-ChildItem "$w5\out.part*.mrk" -EA SilentlyContinue)
if ($rc5 -ne 0) { "  FAIL the mispredicted split reported exit $rc5"; $fail++ }
elseif ($parts5.Count -ne 0) { "  FAIL it was left as a $($parts5.Count)-part set"; $fail++ }
elseif (-not (Test-Path "$w5\out.mrk")) { "  FAIL no plain container after the promotion"; $fail++ }
else {
  $magic5 = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes("$w5\out.mrk")[0..3])
  if ($magic5 -ne "MYRK") { "  FAIL promoted, but it still starts '$magic5'"; $fail++ }
  else { "  ok   a split that produced one part is put back under its plain name" }
  Remove-Item "$w5\back" -Recurse -Force -EA SilentlyContinue
  cmd /c "`"$exe`" decrypt `"$w5\out.mrk`" -o `"$w5\back`" -p $PW 2>&1" | Out-Null
  $got5 = Get-ChildItem "$w5\back" -Recurse -File -EA SilentlyContinue | Select-Object -First 1
  if ($got5 -and (Get-FileHash $got5.FullName -Algorithm SHA256).Hash -eq (Get-FileHash "$w5\z.bin" -Algorithm SHA256).Hash) {
    "  ok   and it decrypts byte for byte after the header strip"
  } else { "  FAIL the promoted container did not come back intact"; $fail++ }
}
Remove-Item $w5 -Recurse -Force -EA SilentlyContinue

$env:MYRKR_DBG_VOLBYTES = ""
Remove-Item $w -Recurse -Force -EA SilentlyContinue

""
"=== Restore: shipping build ==="
$blog = cmd /c "$(Split-Path -Parent $PSScriptRoot)\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

"`n$(if($fail -eq 0){'ALL PASS'}else{"$fail FAILURE(S)"})"
exit $(if ($fail -eq 0) { 0 } else { 1 })
