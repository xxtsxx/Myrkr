# A container that could not have existed before 1.0.81, and what it costs.
#
# NOT part of the default suite - it builds half a million files and takes
# minutes. Run it deliberately:  pwsh tests\scaletest.ps1 [-N 500000]
#
# WHY IT EXISTS. Everything else in the suite proves the index ceiling works with
# forty files and a debug knob (indexfulltest) or twenty thousand real ones
# (manyfiles). Neither can say whether the ceiling being 2047 MiB rather than
# 64 MiB is USABLE - only that the arithmetic is right. The failure this project
# has actually had was found at scale, by a user, on 76,286 files, and it did not
# look like a failure at all: exit 0 and a container missing sixty thousand
# entries.
#
# THE ARITHMETIC, because the point is to exceed a specific number. An index
# entry costs IDXE_FIXED (40) plus its recorded name. ustar bounds the name: the
# leaf must fit the 100-byte name field and the rest the 155-byte prefix, and
# `encrypt` REFUSES anything longer - which is what a first version of this file
# discovered by asking for 200-character leaves and being told, correctly, that
# the entry name was too long.
#
# So: ~95-character leaves under one-level directories gives ~101 bytes of name
# and ~141 bytes an entry. The OLD 64 MiB ceiling therefore fell at about
# 476,000 entries, and the default N below is past it. This container's index is
# larger than any container this tool could produce before 1.0.81 - the claim,
# stated as a file that either exists or does not.
#
# It also times the operations that are LINEAR in entry count, because raising a
# ceiling moves a failure rather than removing it if what waits on the other side
# is an hour of scanning: idx_find is a linear scan and do_add calls it once per
# added file.
param([int]$N = 500000)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "mrk_scale"   # short root: the names are long
$PW   = "Correct-Horse-Battery-9"
$fail = 0

"building dbg (encrypt/decrypt are refused on the command line in release)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

if (Test-Path $w) { "clearing the previous run..."; [IO.Directory]::Delete($w, $true) }
New-Item -ItemType Directory -Path "$w\in" | Out-Null

# ---- the tree -------------------------------------------------------------
# Spread across directories: a single folder with 300,000 entries is NTFS's
# problem, not Myrkr's, and would time the wrong thing.
# 95-character leaves: "f<i>-<pad>.txt" - inside ustar's 100-byte name field with
# room for six digits of index, which is what makes the entry cost predictable.
$pad = "p" * 82
$sw = [Diagnostics.Stopwatch]::StartNew()
$perDir = 2000
$dirs = [math]::Ceiling($N / $perDir)
for ($d = 0; $d -lt $dirs; $d++) {
    $dir = "$w\in\d$d"
    [IO.Directory]::CreateDirectory($dir) | Out-Null
    $lo = $d * $perDir
    $hi = [math]::Min($lo + $perDir, $N)
    for ($i = $lo; $i -lt $hi; $i++) {
        [IO.File]::WriteAllText("$dir\f$i-$pad.txt", "x")
    }
    if ($d % 25 -eq 0) { Write-Host ("  created {0:n0} of {1:n0}..." -f $hi, $N) }
}
$sw.Stop()
"created {0:n0} files in {1:n1}s" -f $N, $sw.Elapsed.TotalSeconds
$leaf = ("f0-$pad.txt").Length
$perEntry = 40 + $leaf + 8      # IDXE_FIXED + leaf + "in/dN/"
"expected inventory ~{0:n0} bytes; the pre-1.0.81 ceiling was {1:n0}" -f ($N * $perEntry), 0x4000000
if (($N * $perEntry) -le 0x4000000) {
    "  NOTE  this N does not exceed the old ceiling - raise it to prove the raise"
}

Add-Type @"
using System;using System.Runtime.InteropServices;
public class SC {
  [StructLayout(LayoutKind.Sequential)] public struct PMC {
    public uint cb; public uint PageFaultCount; public UIntPtr PeakWorkingSetSize;
    public UIntPtr WorkingSetSize; public UIntPtr QuotaPeakPagedPoolUsage;
    public UIntPtr QuotaPagedPoolUsage; public UIntPtr QuotaPeakNonPagedPoolUsage;
    public UIntPtr QuotaNonPagedPoolUsage; public UIntPtr PagefileUsage;
    public UIntPtr PeakPagefileUsage; public UIntPtr PrivateUsage; }
  [DllImport("psapi.dll")] public static extern bool GetProcessMemoryInfo(IntPtr h, out PMC c, uint cb);
}
"@
# Runs the tool, returning seconds, peak private commit in MB, exit code and output.
function Run([string[]]$a) {
    $q = ($a | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $out = Join-Path $w "o.txt"
    $t = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process $exe -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError (Join-Path $w "e.txt")
    $peak = 0
    while (-not $p.HasExited) {
        $c = New-Object SC+PMC; $c.cb = [uint32][Runtime.InteropServices.Marshal]::SizeOf($c)
        try { if ([SC]::GetProcessMemoryInfo($p.Handle, [ref]$c, $c.cb)) {
            $pv = [uint64]$c.PrivateUsage; if ($pv -gt $peak) { $peak = $pv } } } catch {}
        Start-Sleep -Milliseconds 100
    }
    $t.Stop()
    return [pscustomobject]@{
        rc = $p.ExitCode; sec = [math]::Round($t.Elapsed.TotalSeconds,1)
        mb = [math]::Round($peak/1MB,1)
        out = ((Get-Content $out -EA SilentlyContinue) -join "`n") + ((Get-Content (Join-Path $w "e.txt") -EA SilentlyContinue) -join "`n")
    }
}

$mrk = Join-Path $w "big.mrk"
""
"=== encrypt ==="
$r = Run @("encrypt", "$w\in", "-o", $mrk, "-p", $PW, "--store", "-m", "32", "-t", "1")
"  {0:n1}s, peak commit {1} MB, exit {2}" -f $r.sec, $r.mb, $r.rc
if ($r.rc -ne 0) { "  FAIL encrypt: $($r.out)"; $fail++; }
else {
    $idx = (Get-Item $mrk).Length
    "  container {0:n0} bytes" -f $idx
    "  ok   {0:n0} entries packed - an inventory the 64 MiB ceiling could not have held" -f $N
}

""
"=== list ==="
$r = Run @("list", $mrk, "-p", $PW)
"  {0:n1}s, peak commit {1} MB, exit {2}" -f $r.sec, $r.mb, $r.rc
$listed = ([regex]::Matches($r.out, "\.txt")).Count
if ($listed -ne $N) { "  FAIL listed {0:n0} of {1:n0}" -f $listed, $N; $fail++ }
else { "  ok   every one of {0:n0} is listed" -f $N }

""
"=== verify ==="
$r = Run @("verify", $mrk, "-p", $PW)
"  {0:n1}s, peak commit {1} MB, exit {2}" -f $r.sec, $r.mb, $r.rc
if ($r.rc -ne 0) { "  FAIL verify: $($r.out)"; $fail++ } else { "  ok   authenticates" }

""
"=== add one file (times idx_find's linear scan) ==="
[IO.File]::WriteAllText("$w\extra.txt", "added later")
$r = Run @("add", $mrk, "$w\extra.txt", "-p", $PW)
"  {0:n1}s, peak commit {1} MB, exit {2}" -f $r.sec, $r.mb, $r.rc
if ($r.rc -ne 0) { "  note  add refused: $($r.out)" }
else { "  ok   added; the duplicate check scanned {0:n0} entries" -f $N }

""
"=== decrypt ==="
$out = Join-Path $w "back"
$r = Run @("decrypt", $mrk, "-o", $out, "-p", $PW)
"  {0:n1}s, peak commit {1} MB, exit {2}" -f $r.sec, $r.mb, $r.rc
if ($r.rc -ne 0) { "  FAIL decrypt: $($r.out)"; $fail++ }
else {
    $back = (Get-ChildItem -Recurse -File "$out\in" -EA SilentlyContinue).Count
    if ($back -ne $N) { "  FAIL {0:n0} of {1:n0} came back" -f $back, $N; $fail++ }
    else { "  ok   all {0:n0} came back" -f $N }
}

""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

"leaving $w in place - delete it yourself; it is several gigabytes of small files"
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "scaletest: all checks passed"; exit 0 }
