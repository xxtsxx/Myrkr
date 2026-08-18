# The drop path, verified for the first time.
#
# It has never been tested. Three approaches failed for three different
# reasons, all recorded in docs/UI_SURFACES.md: a posted WM_DROPFILES cannot
# cross the process boundary (UIPI blocks it, and the control experiment proved
# it by failing identically in the encrypt view, where the path has shipped for
# years); a scripted OLE drag hangs, because DoDragDrop only calls
# QueryContinueDrag when the drag loop receives input and a scripted cursor
# never moves; and driving real mouse input is not a test, it is a demo.
#
# Registering a real IDropTarget is what makes it testable: an interface can be
# CALLED. This posts WM_APP+3, and the window runs DragEnter/DragOver/Drop
# against whatever data object is on the clipboard - a genuine system
# IDataObject carrying CF_HDROP, not a mock. What is not covered is ole32's own
# delivery of a drag to a registered target; g_dt_ok records that ole32
# accepted the registration, and the OleDropTargetInterface property below is
# that same fact observed from outside.
#
# Needs a dbg build (the WM_APP+3 hook is test-only); it builds one, and puts
# the release build back on every exit through Finish - pass, fail, or early
# abort - so a failed run cannot leave a test build for the next packaging run
# to wrap.  (It used to say "the caller is expected to rebuild release", which
# every caller forgot precisely when a failure had them reading the output.)
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "drop1"
$root = Split-Path -Parent $PSScriptRoot
$exe  = "$root\bin\myrkr.exe"
$fail = 0
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class D {
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumProc cb,IntPtr p);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr GetProp(IntPtr h,string s);
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
# Every exit leaves through here - same funnel as rmbartest, same two reasons:
# the release build goes back into bin, and the exit code says what happened
# (a $fail++ that only printed gave this script exit 0 in the suite runner).
function Finish([int]$code) {
  "=== Restore: shipping build ==="
  $blog = cmd /c "$root\build.cmd strict release" 2>&1
  if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; if ($code -eq 0) { $code = 1 } }
  else { "  bin\myrkr.exe is a release build - ok" }
  exit $code
}
function Entries($z) { $a=[IO.Compression.ZipFile]::OpenRead($z); $n=@($a.Entries|ForEach-Object{$_.FullName}); $a.Dispose(); return $n }

$WM_APP_DROPTEST = 0x8003

Stop-Myrkr
# NOT piped through Select-Object: that terminates the upstream pipeline, which
# once killed build.cmd partway and left a stale binary under test.
"building dbg (the WM_APP+3 hook is test-only)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
# -join first: -notmatch against an ARRAY is a filter, not a test, and returns
# every line that does not match - which is almost all of them, so a successful
# build reads as a failure.
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

New-Item -ItemType Directory "$w\src" -Force | Out-Null
New-Item -ItemType Directory "$w\extra" -Force | Out-Null
1..2 | ForEach-Object { Set-Content "$w\src\f$_.txt" ("seed $_ " * 40) }
Set-Content "$w\extra\dropped.txt" ("arrived through IDropTarget::Drop " * 20)
$z = "$w\plain.zip"
if (Test-Path $z) { Remove-Item -LiteralPath $z -Force }
[IO.Compression.ZipFile]::CreateFromDirectory("$w\src", $z)
$before = Entries $z
"before: $($before.Count) entries -> $($before -join ', ')"

$p = Start-Process $exe -ArgumentList @("`"$z`"") -PassThru
$m=[IntPtr]::Zero; for($i=0;$i -lt 60 -and $m -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250; $m=[D]::Find([uint32]$p.Id,"myrkr_window")}
if ($m -eq [IntPtr]::Zero) { "FAIL no container window"; Stop-Myrkr; Finish 1 }
Start-Sleep -Seconds 2
$lv = [D]::ById($m,109)
$rows0 = [int][D]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
"container view: $rows0 rows"

# --- 1. is the window actually a registered OLE drop target? ------------------
# RegisterDragDrop hangs the interface pointer off the window as a property.
# Observing it from outside proves the registration took, which no amount of
# in-process bookkeeping can: g_dt_ok records what ole32 RETURNED, this records
# what ole32 DID.
$prop = [D]::GetProp($m,"OleDropTargetInterface")
if ($prop -eq [IntPtr]::Zero) { "  FAIL the window is not a registered OLE drop target"; $fail++ }
else { "  ok   registered as an OLE drop target (target=0x{0:X})" -f [int64]$prop }

# --- 2. the control: a data object with no CF_HDROP must be refused -----------
# Runs FIRST, so that a pass on the real case cannot be the same thing
# happening to every message. If text appends files, the test is worthless.
[Windows.Forms.Clipboard]::SetText("not a file list")
Start-Sleep -Milliseconds 300
[void][D]::PostMessageW($m,$WM_APP_DROPTEST,[IntPtr]::Zero,[IntPtr]::Zero)
Start-Sleep -Seconds 3
$rowsCtl = [int][D]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
if ($rowsCtl -ne $rows0) { "  FAIL a text-only data object was accepted as a drop ($rows0 -> $rowsCtl)"; $fail++ }
elseif ((Entries $z).Count -ne $before.Count) { "  FAIL a text-only data object changed the archive"; $fail++ }
else { "  ok   a data object with no CF_HDROP is refused" }

# --- 3. the real thing --------------------------------------------------------
$col = New-Object System.Collections.Specialized.StringCollection
[void]$col.Add("$w\extra\dropped.txt")
[Windows.Forms.Clipboard]::SetFileDropList($col)
Start-Sleep -Milliseconds 300
[void][D]::PostMessageW($m,$WM_APP_DROPTEST,[IntPtr]::Zero,[IntPtr]::Zero)
Start-Sleep -Seconds 6

$p.Refresh()
if ($p.HasExited) { $c=$p.ExitCode; "  FAIL it died - exit $c (0x{0:X8})" -f $c; $fail++ }
else { "  ok   survived the drop" }
$rows1 = [int][D]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
"container view now: $rows1 rows (was $rows0)"
Stop-Myrkr

$after = Entries $z
"after : $($after.Count) entries -> $($after -join ', ')"
if ($after.Count -le $before.Count) { "  FAIL nothing was appended"; $fail++ }
elseif (-not ($after | Where-Object { $_ -like '*dropped.txt' })) { "  FAIL the dropped file is not in the archive"; $fail++ }
else { "  ok   the dropped file reached the archive, via an independent reader" }
if ($rows1 -le $rows0) { "  FAIL the container view did not refresh ($rows0 -> $rows1)"; $fail++ }
else { "  ok   the view refreshed on its own ($rows0 -> $rows1 rows)" }
try {
  $a=[IO.Compression.ZipFile]::OpenRead($z)
  $e=$a.Entries | Where-Object { $_.FullName -like "*dropped.txt" } | Select-Object -First 1
  $r=New-Object IO.StreamReader($e.Open()); $txt=$r.ReadToEnd(); $r.Dispose(); $a.Dispose()
  if ($txt -eq (Get-Content "$w\extra\dropped.txt" -Raw)) { "  ok   and its bytes match the original" }
  else { "  FAIL dropped bytes differ"; $fail++ }
} catch { "  FAIL reading it back: $_"; $fail++ }


# --- 4. the encrypt view, which has never been tested either ------------------
# A real shell drag reaches the registered IDropTarget instead of WM_DROPFILES,
# so the encrypt view's drop now runs through this code too. That path has
# shipped for years without a single test behind it, for the same UIPI reason.
# It costs one more window to cover it.
"`n--- encrypt view ---"
$p2 = Start-Process $exe -PassThru
$m2=[IntPtr]::Zero; for($i=0;$i -lt 60 -and $m2 -eq [IntPtr]::Zero;$i++){Start-Sleep -Milliseconds 250; $m2=[D]::Find([uint32]$p2.Id,"myrkr_window")}
if ($m2 -eq [IntPtr]::Zero) { "  FAIL no encrypt window"; $fail++ }
else {
  Start-Sleep -Seconds 2
  $lv2 = [D]::ById($m2,109)
  $e0 = [int][D]::SendMessageW($lv2,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
  $col2 = New-Object System.Collections.Specialized.StringCollection
  [void]$col2.Add("$w\src\f1.txt"); [void]$col2.Add("$w\src\f2.txt")
  [Windows.Forms.Clipboard]::SetFileDropList($col2)
  Start-Sleep -Milliseconds 300
  [void][D]::PostMessageW($m2,$WM_APP_DROPTEST,[IntPtr]::Zero,[IntPtr]::Zero)
  Start-Sleep -Seconds 3
  $e1 = [int][D]::SendMessageW($lv2,0x1004,[IntPtr]::Zero,[IntPtr]::Zero)
  $p2.Refresh()
  if ($p2.HasExited) { $c=$p2.ExitCode; "  FAIL it died - exit $c (0x{0:X8})" -f $c; $fail++ }
  elseif ($e1 -le $e0) { "  FAIL the dropped files did not reach the input list ($e0 -> $e1)"; $fail++ }
  else { "  ok   dropped files reached the encrypt input list ($e0 -> $e1 rows)" }
}
Stop-Myrkr

if ($fail -gt 0) { "`n$fail FAILURE(S)"; Finish 1 } else { "`nALL PASS"; Finish 0 }
