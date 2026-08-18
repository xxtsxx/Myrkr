# Runs the full Myrkr security-control test suite end to end.
#   Phase 2 (fault inject): build instrumented (dbg) binary, run redteam cases.
#   Phase 1 (adversarial):  build a TESTIO binary, run the crypto/input tests.
#   Restore:                rebuild the shipping binary into bin\.
#
# Why phase 1 needs a testio build: the shipping binary refuses the five
# password-taking verbs, because a password on the command line is exactly the
# surface that lets an authorized-but-abused Myrkr be scripted across an estate.
# The suite still has to drive those paths non-interactively, so it builds a
# binary that accepts -p, uses it, and throws it away.  make_msi.ps1 refuses to
# package such a build, and this script asserts bin\ is left holding a release
# binary - a test build left behind would be wrapped by the next packaging run.
#
# Usage:  pwsh tests\run.ps1   (from the repo root)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root "bin\myrkr.exe"
$dbg = Join-Path $root "bin\myrkr_dbg.exe"

# vcvars sits in a different edition/path on different machines; take the first
# that exists rather than pinning one and failing on everyone else's box.
$vcCandidates = @(
    "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)
$vc = $vcCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vc) { throw "no vcvars64.bat found; edit `$vcCandidates in tests\run.ps1" }

function Build($buildArgs) {
    cmd /c "`"$vc`" >nul 2>&1 && `"$root\build.cmd`" $buildArgs" | Out-Null
    if ($LASTEXITCODE) { throw "build $buildArgs failed" }
}

function Test-Marker([string]$path, [string]$text) {
    $hay = [IO.File]::ReadAllBytes($path)
    $n = [Text.Encoding]::Unicode.GetBytes($text)
    for ($i = 0; $i -le $hay.Length - $n.Length; $i++) {
        if ($hay[$i] -ne $n[0]) { continue }
        $hit = $true
        for ($j = 1; $j -lt $n.Length; $j++) { if ($hay[$i+$j] -ne $n[$j]) { $hit = $false; break } }
        if ($hit) { return $true }
    }
    return $false
}

Write-Host "=== Phase 2: instrumented build (redteam fault injection) ==="
Build "dbg strict"; Copy-Item $exe $dbg -Force
python (Join-Path $PSScriptRoot "redteam.py") $dbg
$p2 = $LASTEXITCODE

Write-Host "`n=== Phase 1: testio build (adversarial crypto/input tests) ==="
Build "testio strict"
$wd = Join-Path $env:TEMP "myrkr_sec_run"
Remove-Item -Recurse -Force $wd -EA SilentlyContinue
python (Join-Path $PSScriptRoot "secsuite.py") $exe $wd
$p1 = $LASTEXITCODE

Write-Host "`n=== Restore: shipping build ==="
# "strict release", not "strict": a shipping build is the RELEASE build, and the
# difference is pe_normalise, which zeroes the timestamps ml64 stamps into every
# object.  Restoring without it leaves bin\ holding binaries that are correct but
# do NOT hash to bin\SHA256SUMS.txt - so anyone who runs the suite after building
# an MSI and then compares the installed files against bin\ sees a mismatch and
# has to work out that the difference is timestamps.  That happened; this is the
# fix, and it also means the restore proves the build still reproduces.
Build "strict release"
$leftover = 0
foreach ($m in @("MYRKR_TEST_IO_BUILD", "redteam")) {
    if (Test-Marker $exe $m) {
        Write-Host "  FAIL: bin\myrkr.exe still carries the '$m' marker after restore"
        $leftover = 1
    }
}
if (-not $leftover) { Write-Host "  bin\myrkr.exe is a release build - ok" }
Remove-Item $dbg -Force -EA SilentlyContinue

Write-Host "`n================= SUITE RESULT ================="
Write-Host ("Phase 1 (crypto/input):   {0}" -f $(if($p1 -eq 0){"PASS"}else{"FAIL"}))
Write-Host ("Phase 2 (memory-safety):  {0}" -f $(if($p2 -eq 0){"PASS"}else{"FAIL"}))
Write-Host ("Restore (release in bin): {0}" -f $(if($leftover -eq 0){"PASS"}else{"FAIL"}))
exit ($p1 -bor $p2 -bor $leftover)
