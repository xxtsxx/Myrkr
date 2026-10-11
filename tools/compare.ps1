# compare.ps1 - does a test actually catch the change?  Runs ONE test, as it is
# in the working tree now, against a build of an older commit and against a
# build of the working tree, and says whether the verdicts differ.
#
#   powershell -File tools\compare.ps1 tests\extracthazardtest.py -Ref v1.1.2
#   powershell -File tools\compare.ps1 tests\guifailtest.ps1 -Ref 166f4d4
#
# A regression test that passes against the code it was written to catch is
# not a test; this is the check.  It is what was done by hand three times for
# 1.1.3 (and caught a tamper offset that hit the index instead of an entry, so
# the "damaged entry" cases passed against the broken build).
#
#   -Ref      the old commit (default HEAD - i.e. "does my uncommitted change
#             make a difference to this test").
#   -Variant  build arguments for BOTH sides (default "dbg": a superset of
#             testio, and what the GUI tests need).
#   -TestArgs extra arguments.  A .py test gets the exe path first, then these.
#
# The current tests\ directory is copied over the old checkout, so a new test
# and its new fixtures run unchanged against the old code.  bin\ is restored to
# a release build on every exit, as tests\run.ps1 does.
# Exit 0 only when the old build FAILS the test and the working tree PASSES it.
param(
    [Parameter(Mandatory, Position = 0)][string]$Test,
    [string]$Ref = 'HEAD',
    [string]$Variant = 'dbg',
    [string[]]$TestArgs = @(),
    [switch]$KeepWorktree
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'tests\lib\gui.psm1') -Force

$testFull = (Resolve-Path -LiteralPath (Join-Path $root $Test) -ErrorAction SilentlyContinue)
if (-not $testFull) { $testFull = Resolve-Path -LiteralPath $Test }
$testRel = $testFull.Path.Substring($root.Length).TrimStart('\')
if (-not $testRel.StartsWith('tests\')) { throw "the test must live under tests\: $testRel" }

$sha = (git -C $root rev-parse --short $Ref).Trim()
if ($LASTEXITCODE) { throw "unknown ref: $Ref" }
$wt  = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-cmp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$logs = "$wt-logs"      # outside the worktree, so they survive its removal
New-Item -ItemType Directory $logs | Out-Null

# git writes progress to stderr, and Windows PowerShell 5.1 turns a redirected
# native stderr line into a terminating error under ErrorAction Stop.
function Git-Quiet {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & git -C $root @args 2>&1 | Out-Null } finally { $ErrorActionPreference = $eap }
}

function Run-Test([string]$tree, [string]$log) {
    $file = Join-Path $tree $testRel
    Push-Location $tree
    try {
        if ($file -like '*.py') {
            $exe = Join-Path $tree 'bin\myrkr.exe'
            & python $file $exe @TestArgs *> $log
        } else {
            & powershell -NoProfile -ExecutionPolicy Bypass -File $file @TestArgs *> $log
        }
        return $LASTEXITCODE
    } finally { Pop-Location; Stop-Myrkr }
}

$old = $null; $new = $null
try {
    Write-Host "=== old: $Ref ($sha) in $wt ==="
    Git-Quiet worktree add --detach $wt $sha
    if ($LASTEXITCODE) { throw "git worktree add failed" }
    Copy-Item -Recurse -Force (Join-Path $root 'tests\*') (Join-Path $wt 'tests')
    Invoke-MyrkrBuild -Variant $Variant -Root $wt
    $old = Run-Test $wt (Join-Path $logs 'old.txt')
    Write-Host "    exit $old"

    Write-Host "=== new: working tree ==="
    Invoke-MyrkrBuild -Variant $Variant -Root $root
    $new = Run-Test $root (Join-Path $logs 'new.txt')
    Write-Host "    exit $new"
} finally {
    Stop-Myrkr
    Write-Host "=== restore: release build in bin ==="
    try { Invoke-MyrkrBuild -Variant 'strict release' -Root $root; Write-Host '    ok' }
    catch { Write-Host "    FAIL: $($_.Exception.Message)" }
    if (-not $KeepWorktree) { Git-Quiet worktree remove --force $wt }
}

# The lines that differ, failures first - the reason for the verdict.
$pat = '\bFAIL|\bPASS\b|^\s*ok\b|error|Traceback'
foreach ($side in 'old', 'new') {
    $f = Join-Path $logs "$side.txt"
    $hits = @(Select-String -LiteralPath $f -Pattern $pat | ForEach-Object { $_.Line.TrimEnd() })
    $fails = @($hits | Where-Object { $_ -cmatch '\bFAIL|Traceback|\berror:' })   # case-sensitive: "PASS a failed decrypt..." is a pass
    Write-Host ("`n--- {0}: {1} result lines, {2} failing ---" -f $side, $hits.Count, $fails.Count)
    $fails | Select-Object -First 25 | ForEach-Object { Write-Host "  $_" }
}
Write-Host "`nlogs: $logs"

Write-Host ''
if ($old -ne 0 -and $new -eq 0) { Write-Host "VERDICT: the test CATCHES the change (old $old, new 0)"; exit 0 }
if ($old -eq 0 -and $new -eq 0) { Write-Host "VERDICT: the test does NOT tell $sha from the working tree - both pass"; exit 1 }
if ($new -ne 0)                 { Write-Host "VERDICT: the working tree FAILS the test (old $old, new $new)"; exit 1 }
Write-Host "VERDICT: inconclusive (old $old, new $new)"; exit 1
