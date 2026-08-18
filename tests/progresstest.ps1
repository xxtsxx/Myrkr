# The progress bar tells the truth about time: average MB/s and a ticking eta.
#
# Requested after a 155 GB encrypt: a bar alone on a job that size is a promise
# with no schedule. The rate is the CUMULATIVE average (a windowed rate swings
# the eta by minutes on a disk hiccup) and its clock starts at the FIRST BYTE,
# not at progress_begin - key derivation runs between the two, and folding that
# idle head in would make the first minute's rate a lie in exactly the
# direction that misleads. The eta CEILS, so a moving bar never reads 0:00.
#
# WHY THIS IS CAPTURABLE AT ALL. The bar deliberately aims at the CONSOLE, not
# at the stderr handle print_err uses: the hybrid binary's AttachConsole
# replaces the std handles, so with a parent terminal the bar stays on screen
# even when the user redirects 2> to a file - file clean, bar visible. That
# also made it invisible to every harness, in both directions. Test builds
# honour MYRKR_DBG_PROGRESS, which renders into the captured REAL stderr
# instead; release builds have no override in either direction.
#
# The arithmetic itself (the 128-bit remaining*elapsed product, the 99:59:59
# cap, the not-measurable gates) is selftest's job, with injected state; this
# file proves the rendered line against a real encrypt.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "myrkr_progresstest"
$PW   = "Correct-Horse-Battery-9"
$fail = 0

"building dbg (MYRKR_DBG_PROGRESS and encrypt on the command line need it)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

if (Test-Path $w) { [IO.Directory]::Delete($w, $true) }
New-Item -ItemType Directory $w | Out-Null

# Big enough that the stream outlives the 1-second measurability gate by a wide
# margin on any disk: ~1.5 GiB at several hundred MB/s is 3-5 seconds.
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$buf = [byte[]]::new(64MB)
$fs = [IO.File]::Create("$w\big.bin")
for ($i = 0; $i -lt 24; $i++) { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }
$fs.Close()

# ---- 1. with the override: frames carry rate and a counting-down eta --------
$env:MYRKR_DBG_PROGRESS = "1"
cmd /c "`"$exe`" encrypt `"$w\big.bin`" -o `"$w\big.mrk`" -p $PW --store -m 512 -t 3 2>`"$w\bar.txt`"" | Out-Null
Remove-Item Env:\MYRKR_DBG_PROGRESS
if ($LASTEXITCODE -ne 0) { "  FAIL encrypt exit $LASTEXITCODE"; exit 1 }

$frames = (Get-Content "$w\bar.txt" -Raw) -split "`r"
$rated  = @($frames | Where-Object { $_ -match "(\d+)\.(\d) MB/s\s+eta (\d+):(\d\d)" })
if ($rated.Count -lt 2) {
    "  FAIL only $($rated.Count) frames carried a rate - the line never formed"; $fail++
} else {
    "  ok   $($rated.Count) frames carry '<n>.<n> MB/s  eta <m>:<ss>'"
}

# The rate must be sane: a real disk on this machine is between 10 and 10,000
# MB/s, and a formatting bug (wrong divisor, tenth in the wrong place) lands
# outside that band immediately.
$bad = @($rated | Where-Object { $_ -match "(\d+)\.\d MB/s" -and ([int]$Matches[1] -lt 10 -or [int]$Matches[1] -gt 10000) })
if ($bad.Count) { "  FAIL implausible rate: $($bad[0].Trim())"; $fail++ }
else { "  ok   every rate is in a plausible band" }

# The eta may only ever read 0:00 on a finished bar - the ceiling exists so a
# moving bar never promises "done" while it is not.
$lying = @($rated | Where-Object { $_ -match "eta 0:00" -and $_ -notmatch "100%" })
if ($lying.Count) { "  FAIL a moving bar read eta 0:00: $($lying[0].Trim())"; $fail++ }
else { "  ok   eta 0:00 appears only at 100%" }

# And it must actually count DOWN across the run (first rated frame vs last):
# an eta computed from a broken clock sits still or climbs.
function EtaS([string]$f) { if ($f -match "eta (\d+):(\d\d)") { [int]$Matches[1]*60 + [int]$Matches[2] } else { -1 } }
$first = EtaS $rated[0]; $lastMoving = EtaS (@($rated | Where-Object { $_ -notmatch "100%" })[-1])
if ($first -le $lastMoving -and $first -gt 1) {
    "  FAIL the eta did not fall: first $first s, last moving $lastMoving s"; $fail++
} else { "  ok   the eta fell: $first s -> $lastMoving s" }

# ---- 2. without the override: a redirected stderr stays clean ---------------
# The suppression is the shipping behaviour a user's `2> errors.txt` relies on;
# the override must not have weakened it.
cmd /c "`"$exe`" encrypt `"$w\big.bin`" -o `"$w\big2.mrk`" -p $PW --store -m 512 -t 3 2>`"$w\quiet.txt`"" | Out-Null
if ((Get-Item "$w\quiet.txt").Length -ne 0) {
    "  FAIL bar frames leaked into a redirected stderr without the override"; $fail++
} else { "  ok   without the override, a redirected stderr gets nothing" }

# ---- 3. the main window's status line shows the same numbers ----------------
# The status text has been WRITTEN since the redesign - set_status_pct on every
# timer tick - but the control it targeted vanished in a layout rework and
# every SetWindowTextW went to a null hwnd, silently, until 1.0.85 recreated
# it (ID_STATUS = 196). A control that died unnoticed once needs a test that
# notices, which is this.
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public class PT { [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProcPT cb,IntPtr p);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,string l);
 [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h,IntPtr a,int x,int y,int cx,int cy,uint f);
 public static IntPtr Find(uint pid,string cls){ IntPtr f=IntPtr.Zero;
  EnumWindows((h,p)=>{ uint q; GetWindowThreadProcessId(h,out q);
   if(q==pid&&IsWindowVisible(h)){ var sb=new StringBuilder(64); GetClassName(h,sb,64);
    if(sb.ToString()==cls){ f=h; return false; } } return true; },IntPtr.Zero); return f; }
 public static string Txt(IntPtr h){ var sb=new StringBuilder(256); GetWindowTextW(h,sb,256); return sb.ToString(); }
}
public delegate bool EnumProcPT(IntPtr h,IntPtr p);
"@
$env:MYRKR_DBG_NOSECDESK = "1"
Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
# The plaintext must be gone first: the browse-decrypt's default output is the
# original path, and an overwrite prompt would park the run before any rate.
Remove-Item "$w\big.bin" -Force
$q = Start-Process $exe -ArgumentList "`"$w\big.mrk`"" -PassThru
$sd = [IntPtr]::Zero
for ($i=0; $i -lt 80 -and $sd -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 150; $sd = [PT]::Find([uint32]$q.Id, "myrkr_secdesk") }
if ($sd -eq [IntPtr]::Zero) { "  FAIL no password prompt appeared"; $fail++ }
else {
    [void][PT]::SendMessageW([PT]::GetDlgItem($sd,156), 0x000C, [IntPtr]::Zero, $PW)
    Start-Sleep -Milliseconds 300
    [void][PT]::PostMessageW($sd, 0x0111, [IntPtr]104, [IntPtr]::Zero)
    $mw = [IntPtr]::Zero
    for ($i=0; $i -lt 100 -and $mw -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 150; $mw = [PT]::Find([uint32]$q.Id, "myrkr_window") }
    if ($mw -eq [IntPtr]::Zero) { "  FAIL the window never appeared"; $fail++ }
    else {
        # At the window's MINIMUM width, which is where the user works and where
        # the status control is narrowest - the clipping bug lived there, and a
        # probe at a comfortable size would never have seen it. GetWindowTextW
        # reads the full string regardless of clipping, so what is asserted
        # about width is the STRING being short enough: with the rate showing,
        # the prefix must be gone.
        [void][PT]::SetWindowPos($mw, [IntPtr]::Zero, 0, 0, 420, 500, 0x0016)
        Start-Sleep -Milliseconds 800
        [void][PT]::PostMessageW($mw, 0x0111, [IntPtr]104, [IntPtr]::Zero)   # Decrypt selected
        $seen = @()
        for ($i=0; $i -lt 120; $i++) {
            Start-Sleep -Milliseconds 250
            $t = [PT]::Txt([PT]::GetDlgItem($mw, 196))          # ID_STATUS
            if ($t -match "MB/s\s+ETA \d+:\d\d") { $seen += $t; if ($seen.Count -ge 3) { break } }
        }
        if ($seen.Count -eq 0) {
            "  FAIL the status line never showed a rate (last: '$([PT]::Txt([PT]::GetDlgItem($mw,196)))')"; $fail++
        } else {
            "  ok   the window's status line reads: '$($seen[-1])'"
            # "the string doesn't seem to update" was the report - so UPDATING is
            # the assertion, not one lucky read: three captures, not all equal.
            if (($seen | Sort-Object -Unique).Count -lt 2 -and $seen.Count -ge 3) {
                "  FAIL the status line never changed across $($seen.Count) reads: '$($seen[0])'"; $fail++
            } else { "  ok   and it updates: $($seen.Count) reads, $((($seen | Sort-Object -Unique)).Count) distinct" }
            if ($seen[-1] -match "^(Encrypting|Decrypting)") {
                "  FAIL the prefix is still present with the rate showing - it will not fit the control"; $fail++
            } else { "  ok   the prefix yields once the rate shows, so the line fits 187 px" }
        }
    }
}
Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
Remove-Item Env:\MYRKR_DBG_NOSECDESK

""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

if (Test-Path $w) { [IO.Directory]::Delete($w, $true) }

# =============================================================================
# MUTATIONS - applied, run, observed, reverted.
#
#  1. progress.asm, prog_eta_s: delete the `add rax, 999` ceiling.
#       -> "eta 0:00 appears only at 100%" FAILS: the tail of the run shows a
#          moving bar promising done. (This was the shipped first draft, caught
#          by reading the captured frames - "eta 0:00" at 59% is arithmetically
#          true for sub-second remainders and reads as a bug anyway.)
#
#  2. progress.asm, progress_add: skip setting g_prog_startms (clock never
#     starts).
#       -> "only 0 frames carried a rate" FAILS - prog_speed_x10 gates on the
#          clock, which is the point: no clock, no claims.
# =============================================================================
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "progresstest: all checks passed"; exit 0 }
