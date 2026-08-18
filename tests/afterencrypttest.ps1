# Two contracts, both of which have been wrong at some point.
#
# 1. A RIGHT-DRAG stays out of the way.  It gets the small progress window, not
#    the main one, and on success it takes everything down by itself.  The main
#    window is still created - it owns the controls the worker posts to - but it
#    must never be SHOWN on this path, and the process must exit on its own.
#
# 2. OPENING a container gives you a window you can work in.  That is the case
#    the original bug was about: a finished encrypt used to leave the window in
#    encrypt mode, same title, same Encrypt button, still showing the INPUT
#    list, so a drop added another input for an encryption that never ran again
#    while the status line updated as though something had been taken in.
#    See docs/AFTER_ENCRYPT.md.
#
# The archive is read back with the CLI, which owes nothing to the window - the
# row count going up is exactly the symptom that made the original bug
# convincing, so it is not allowed to be the evidence.
#
# Needs a dbg build (-p and MYRKR_DBG_NOSECDESK are test-only).
$fail = 0
$w=Join-Path $env:TEMP "myrkr-tests\repro"
$exe=Join-Path (Split-Path -Parent $PSScriptRoot) "bin\myrkr.exe"
$PW="Correct-Horse-Battery-9"
Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class Z { [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr SendStr(IntPtr h,uint m,IntPtr w,string l);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr SendBuf(IntPtr h,uint m,IntPtr w,StringBuilder l);
 [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
 [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
 [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
 public delegate bool EnumProc(IntPtr h,IntPtr p);
 public static IntPtr Find(uint pid,string cls){ IntPtr r=IntPtr.Zero;
  EnumWindows(delegate(IntPtr h,IntPtr q){ uint w; GetWindowThreadProcessId(h,out w);
   if(w!=pid||!IsWindowVisible(h)) return true; var c=new StringBuilder(128); GetClassName(h,c,128);
   if(c.ToString()==cls){ r=h; return false; } return true;},IntPtr.Zero); return r; }
 public static IntPtr found;
 public static IntPtr ById(IntPtr t,int id){ found=IntPtr.Zero;
  EnumChildWindows(t,delegate(IntPtr h,IntPtr q){ if(GetDlgCtrlID(h)==id){found=h;return false;} return true;},IntPtr.Zero); return found; }
 // Child ids in z-order, TOP first - which is how EnumChildWindows enumerates.
 public static string ids;
 public static string Order(IntPtr t){ ids="";
  EnumChildWindows(t,delegate(IntPtr h,IntPtr q){ ids += GetDlgCtrlID(h)+" "; return true;},IntPtr.Zero); return ids.Trim(); }
 public static string Txt(IntPtr h){ var b=new StringBuilder(512); GetWindowTextW(h,b,512); return b.ToString(); }
 // Txt() is NOT usable on an EDIT in another process.  Cross-process,
 // GetWindowTextW does not send WM_GETTEXT - it returns the string USER32 cached
 // from CreateWindow's lpWindowName - and an EDIT keeps its text in its own
 // buffer, so one whose contents were replaced by SetWindowTextW still reads
 // back as its creation placeholder.  That cost a long hunt for a bug in the
 // code that was really a bug in the measurement, on top of the identical
 // lesson from $p.HasExited below.  Ask the control.
 public static string Edit(IntPtr h){ var b=new StringBuilder(65536); SendBuf(h,0x000D,(IntPtr)65535,b); return b.ToString(); } }
"@
Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
"building dbg (-p and MYRKR_DBG_NOSECDESK are test-only)..."
$blog = cmd /c "$(Split-Path -Parent $PSScriptRoot)\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }
$stamp=Get-Random; $d="$w\dest$stamp"
New-Item -ItemType Directory $d -Force | Out-Null
New-Item -ItemType Directory "$w\folder" -Force | Out-Null
New-Item -ItemType Directory "$w\src" -Force | Out-Null
Set-Content "$w\folder\one.txt" "one"; Set-Content "$w\folder\two.txt" "two"
Set-Content "$w\src\ADDED.txt" "this is the added file"
$env:MYRKR_DBG_NOSECDESK="1"

# Whether a process is gone, asked of the OS rather than of a cached property.
# $p.HasExited on a Start-Process -PassThru object is not dependable once the
# process has actually gone - it can throw, and a throw inside a loop condition
# reads as "still running" forever. That cost a full round of chasing a bug in
# the code that was really a bug in the measurement.
function Gone($proc) { try { $null = Get-Process -Id $proc.Id -EA Stop; return $false } catch { return $true } }

# ---- 1. a right-drag gets the progress window and closes itself -------------
$p=Start-Process $exe -ArgumentList @("`"$w\folder`"","--to","`"$d`"") -PassThru
$pr=[IntPtr]::Zero; for($i=0;$i -lt 60 -and $pr -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250;$pr=[Z]::Find([uint32]$p.Id,"myrkr_secdesk")}
if($pr -eq [IntPtr]::Zero){"FAIL no prompt"; exit 1}
[void][Z]::SendStr([Z]::GetDlgItem($pr,156),0x000C,[IntPtr]::Zero,$PW); Start-Sleep -Milliseconds 300
[void][Z]::SendStr([Z]::GetDlgItem($pr,157),0x000C,[IntPtr]::Zero,$PW); Start-Sleep -Milliseconds 400
[void][Z]::PostMessageW($pr,0x0111,[IntPtr]104,[IntPtr]::Zero)
# Catch the progress window while the job is still running.  Polled rather than
# slept for: on a small folder the whole thing is over in under a second, and a
# fixed wait would race the very window under test out of existence.
$pg=[IntPtr]::Zero
for($i=0;$i -lt 80 -and $pg -eq [IntPtr]::Zero -and -not (Gone $p);$i++){
  Start-Sleep -Milliseconds 50; $pg=[Z]::Find([uint32]$p.Id,"myrkr_progress") }
if ($pg -ne [IntPtr]::Zero) { "  ok   the right-drag showed the progress window" }
else { "  FAIL no progress window - a right-drag fell back to the main window"; $fail++ }
# and the main window must NOT be on screen while it runs
$mv=[Z]::Find([uint32]$p.Id,"myrkr_window")
if ($mv -eq [IntPtr]::Zero) { "  ok   the main window stayed out of the way" }
else { "  FAIL the main window is visible on a right-drag"; $fail++ }
# success takes everything down by itself
for($i=0;$i -lt 200 -and -not (Gone $p);$i++){ Start-Sleep -Milliseconds 100 }
if (Gone $p) { "  ok   it closed itself when the job succeeded " }
else {
  "  FAIL still running after a successful right-drag"; $fail++
  # Say WHAT it is stuck on rather than only that it is stuck.
  $stillpg=[Z]::Find([uint32]$p.Id,"myrkr_progress")
  $stillsd=[Z]::Find([uint32]$p.Id,"myrkr_secdesk")
  $stillmb=[Z]::Find([uint32]$p.Id,"myrkr_mbox")
  "       progress=$($stillpg -ne [IntPtr]::Zero) secdesk=$($stillsd -ne [IntPtr]::Zero) mbox=$($stillmb -ne [IntPtr]::Zero)"
  if ($stillmb -ne [IntPtr]::Zero) { "       mbox says: $([Z]::Txt($stillmb))" }
  if ($stillpg -ne [IntPtr]::Zero) {
    $ed=[Z]::ById($stillpg,193)
    if ($ed -ne [IntPtr]::Zero) { "       log tail: " + ((([Z]::Edit($ed) -split "`r`n") | Select-Object -Last 3) -join " | ") } }
  Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}} }
$made = Get-ChildItem $d -File -EA SilentlyContinue | Select-Object -First 1
if ($made) { "  ok   it produced $($made.Name)" }
else { "  FAIL nothing was written"; $fail++; exit 1 }

# ---- 1b. a right-drag that FAILS halts and shows why ------------------------
# The other half of the contract, and the half that has never been asserted:
# success closes everything, a failure stops on the progress window with the
# details already folded out and the error in them.  Forced by pointing --to at
# a FILE, so the output cannot be created there.
$bad="$w\notadir$stamp"
Set-Content $bad "I am a file, not a folder"
$q=Start-Process $exe -ArgumentList @("`"$w\folder`"","--to","`"$bad`"") -PassThru
$pr=[IntPtr]::Zero; for($i=0;$i -lt 60 -and $pr -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250;$pr=[Z]::Find([uint32]$q.Id,"myrkr_secdesk")}
if($pr -eq [IntPtr]::Zero){"  FAIL no prompt on the failing right-drag"; $fail++}
else {
  [void][Z]::SendStr([Z]::GetDlgItem($pr,156),0x000C,[IntPtr]::Zero,$PW); Start-Sleep -Milliseconds 300
  [void][Z]::SendStr([Z]::GetDlgItem($pr,157),0x000C,[IntPtr]::Zero,$PW); Start-Sleep -Milliseconds 400
  [void][Z]::PostMessageW($pr,0x0111,[IntPtr]104,[IntPtr]::Zero)
  Start-Sleep -Seconds 5
  $pg=[Z]::Find([uint32]$q.Id,"myrkr_progress")
  if ($pg -eq [IntPtr]::Zero) { "  FAIL the failing right-drag did not halt on the progress window"; $fail++ }
  else {
    "  ok   it halted on the progress window"
    # The button becomes Close - a failure has nothing left to cancel.
    $act=[Z]::Txt([Z]::ById($pg,104))
    if ($act -eq 'Close') { "  ok   the button became Close" }
    else { "  FAIL the button still says '$act'"; $fail++ }
    # The backdrop must be at the BOTTOM of the z-order, and this is not a style
    # point. It is one owner-draw control covering the whole client; anything it
    # sits above, it paints over, and nothing invalidates those controls
    # afterwards. Created first, it lands on TOP, and expanding the panel wiped
    # Details, Close, the log and its buttons off the window. It stayed hidden
    # for a while because the repaint was aimed at the window rather than at the
    # backdrop, so the backdrop never repainted at all - which also left the bar
    # and the file count frozen on their first frame for the whole job.
    # EnumChildWindows enumerates top-first, so id 190 must come LAST.
    $order = [Z]::Order($pg)
    if ($order -match '190$') { "  ok   the backdrop is at the bottom of the z-order" }
    else { "  FAIL the backdrop is not at the bottom - it will paint over the controls (z-order: $order)"; $fail++ }
    $ed=[Z]::ById($pg,193)
    if ($ed -eq [IntPtr]::Zero) { "  FAIL the details panel never opened"; $fail++ }
    else {
      # Read it with WM_GETTEXT.  Txt() would report the creation placeholder
      # here whatever the control holds - see the note on Edit() above.
      $log=[Z]::Edit($ed)
      if ($log -match 'error') { "  ok   the details panel is showing the error" }
      else { "  FAIL the details panel does not show the error: '$log'"; $fail++ }
      if ($log -match 'finished') { "  ok   and the summary is there too" }
      else { "  FAIL no summary in the details panel"; $fail++ }
    }
  }
  Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
}

# ---- 2. OPENING that container gives a window you can work in ---------------
# No --to this time: this is the double-click path, and it is the one that has
# to end up editable.
$p=Start-Process $exe -ArgumentList @("`"$($made.FullName)`"") -PassThru
$pr=[IntPtr]::Zero; for($i=0;$i -lt 60 -and $pr -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250;$pr=[Z]::Find([uint32]$p.Id,"myrkr_secdesk")}
if($pr -eq [IntPtr]::Zero){"FAIL no prompt on open"; exit 1}
[void][Z]::SendStr([Z]::GetDlgItem($pr,156),0x000C,[IntPtr]::Zero,$PW); Start-Sleep -Milliseconds 300
[void][Z]::PostMessageW($pr,0x0111,[IntPtr]104,[IntPtr]::Zero)
Start-Sleep -Seconds 6
$m=[Z]::Find([uint32]$p.Id,"myrkr_window")
if($m -eq [IntPtr]::Zero){"FAIL no main window when opening the container"; $fail++; exit 1}
$title = [Z]::Txt($m); $action = [Z]::Txt([Z]::ById($m,104))
"opened        : title='$title'  action='$action'"
if ($action -ne 'Decrypt') { "  FAIL the window is not the container view - a drop will not reach the archive"; $fail++ }
else { "  ok   the container opened in a window that can be worked in" }
$lv=[Z]::ById($m,109)
"                rows=$([int][Z]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero))"

# ---- 3. and a drop into it really reaches the archive ----------------------
$col=New-Object System.Collections.Specialized.StringCollection; [void]$col.Add("$w\src\ADDED.txt")
[Windows.Forms.Clipboard]::SetFileDropList($col); Start-Sleep -Milliseconds 300
[void][Z]::PostMessageW($m,0x8003,[IntPtr]0,[IntPtr]0)
Start-Sleep -Seconds 8
"after drop    : rows=$([int][Z]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero))"

# ---- 4. exit -----------------------------------------------------------------
Get-Process myrkr -EA SilentlyContinue|%{try{$_.Kill()}catch{}}

# ---- 5. read it back with the CLI - an answer that owes nothing to the window
$made = Get-ChildItem $d -File | Select-Object -First 1
$out="$w\r$stamp"
cmd /c "$exe decrypt ""$($made.FullName)"" -o ""$out"" -p $PW 2>&1" | Out-Null
"decrypt exit $LASTEXITCODE"
"archive contents:"
Get-ChildItem $out -Recurse -File -EA SilentlyContinue | ForEach-Object { "   " + $_.FullName.Substring($out.Length+1) }

if ($LASTEXITCODE -ne 0) { "  FAIL decrypt exit $LASTEXITCODE"; $fail++ }
$got = @(Get-ChildItem $out -Recurse -File -EA SilentlyContinue | ForEach-Object { $_.FullName.Substring($out.Length+1) -replace '\\','/' })
if ($got -contains 'ADDED.txt') { "  ok   the dropped file is in the archive" }
else { "  FAIL the dropped file never reached the archive: $($got -join ', ')"; $fail++ }
if ($got -contains 'folder/one.txt' -and $got -contains 'folder/two.txt') { "  ok   and the original contents survived" }
else { "  FAIL the original contents are wrong: $($got -join ', ')"; $fail++ }

# ---- Restore: shipping build -----------------------------------------------
# This test builds `dbg` - which carries BOTH the redteam fault injection and
# -p on the command line - and used to leave it sitting in bin\ looking like the
# shipping binary. A comment is not a cleanup step; run.ps1 and estreamtest were
# fixed the same way. "strict release" so bin\ comes back hashing to
# bin\SHA256SUMS.txt rather than merely being correct.
""
"=== Restore: shipping build ==="
$blog = cmd /c "$(Split-Path -Parent $PSScriptRoot)\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else {
  # Assert it. The markers are WIDE strings: an ASCII search finds nothing and
  # reports an instrumented build as clean, which is the wrong way round.
  $hay = [IO.File]::ReadAllBytes($exe); $left = 0
  foreach ($mk in @("MYRKR_TEST_IO_BUILD","redteam")) {
    $nee = [Text.Encoding]::Unicode.GetBytes($mk); $found = $false
    for ($i = 0; $i -le $hay.Length - $nee.Length -and -not $found; $i++) {
      if ($hay[$i] -ne $nee[0]) { continue }
      $hit = $true
      for ($j = 1; $j -lt $nee.Length; $j++) { if ($hay[$i+$j] -ne $nee[$j]) { $hit = $false; break } }
      if ($hit) { $found = $true }
    }
    if ($found) { "  FAIL bin\myrkr.exe still carries '$mk'"; $left = 1 }
  }
  if ($left) { $fail++ } else { "  bin\myrkr.exe is a release build - ok" }
}

"`n$(if($fail -eq 0){'ALL PASS'}else{"$fail FAILURE(S)"})"
exit $(if ($fail -eq 0) { 0 } else { 1 })
