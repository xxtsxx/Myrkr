# all.ps1 - every suite, one after another: run.ps1 (security, adversarial and
# the GUI regressions it hosts), then each feature test.  Sequential on purpose:
# the GUI tests share the desktop, the foreground and bin\myrkr.exe.
#
#   powershell -File tests\all.ps1            # everything (~27 min; scaletest is ~11)
#   powershell -File tests\all.ps1 -Quick     # without scaletest
#   powershell -File tests\all.ps1 -Only greytest,droptest
#
# The tests run.ps1 already runs against its dbg build are not run again here:
# standalone, against the release build run.ps1 leaves behind, they fail for a
# reason that is not a defect (no -p, no MYRKR_DBG_NOSECDESK).
# Each test's output goes to its own log; the summary is exit codes and times.
param([switch]$Quick, [string[]]$Only = @(), [string[]]$Skip = @())
$root = Split-Path $PSScriptRoot -Parent
$ps   = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
$logs = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-all-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory $logs | Out-Null

$hosted = @('nativeeditguitest', 'cmdbartest', 'listsurfacetest', 'guifailtest')   # run by run.ps1
$slow   = @('scaletest')
$tests  = @('run') + @(Get-ChildItem (Join-Path $PSScriptRoot '*.ps1') |
          ForEach-Object BaseName | Where-Object { $_ -notin @('run', 'all') + $hosted } | Sort-Object)
if ($Quick)       { $tests = $tests | Where-Object { $_ -notin $slow } }
if ($Only.Count)  { $tests = $tests | Where-Object { $_ -in $Only } }
if ($Skip.Count)  { $tests = $tests | Where-Object { $_ -notin $Skip } }

$failed = @()
$all = [Diagnostics.Stopwatch]::StartNew()
foreach ($t in $tests) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "$t.ps1") *> (Join-Path $logs "$t.txt")
    $code = $LASTEXITCODE
    $line = '{0,-22} {1,-4} {2,6:n0}s' -f $t, $(if ($code -eq 0) { 'ok' } else { "FAIL($code)" }), $sw.Elapsed.TotalSeconds
    Write-Host $line
    if ($code -ne 0) { $failed += $t }
}
Write-Host ("`n{0} suites in {1:n1} min; logs in {2}" -f $tests.Count, $all.Elapsed.TotalMinutes, $logs)
if ($failed.Count) { Write-Host "FAILED: $($failed -join ', ')"; exit 1 }
Write-Host 'ALL PASSED'; exit 0
