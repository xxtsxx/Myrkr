# Two window regressions from the 1.1.3 review, both invisible to the CLI suites.
#
# 1. A failed encrypt or decrypt showed its error and then FELL THROUGH into the
#    container-edit tail of on_done, which showed a second, unrelated dialog
#    ("The full re-encryption could not be completed") and skipped od_restore -
#    the step that clears the typed password.  A tampered single-file container
#    is decrypted here and every message box counted: exactly one is correct.
#
# 2. The About window draws "github.com/xxtsxx/Myrkr" at its foot, and the main
#    About box used to claim a version label opened the project page while
#    nothing did.  The foot is now a real link: WM_NCHITTEST must say HTCLIENT
#    (clickable) on it and HTCAPTION (drag) beside it.  The link is NOT clicked -
#    that would launch the user's browser.
#
# Needs a dbg build (MYRKR_DBG_NOSECDESK, and encrypt -p for the fixture).
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$exe  = Join-Path $root 'bin\myrkr.exe'
$work = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-guifail-' + [guid]::NewGuid().ToString('N').Substring(0,8))
$fail = 0
Import-Module (Join-Path $PSScriptRoot 'lib\gui.psm1') -Force
New-Item -ItemType Directory $work | Out-Null
$old = $env:MYRKR_DBG_NOSECDESK
$p = $null
try {
  # ---- 1. one dialog for one failed decrypt ---------------------------------
  $src = Join-Path $work 'doc.txt'; $mrk = Join-Path $work 'doc.mrk'
  [IO.File]::WriteAllText($src, ('secret line ' * 4000))
  $rc = Invoke-MyrkrCli -Exe $exe -Arguments @('encrypt',$src,'-o',$mrk,'-p','Test-Password-9','--store','-m','8','-t','1')
  if ($rc -ne 0) { throw "fixture encrypt failed: $rc" }
  Remove-Item -LiteralPath $src
  $b = [IO.File]::ReadAllBytes($mrk); $b[$b.Length - 200] = $b[$b.Length - 200] -bxor 1; [IO.File]::WriteAllBytes($mrk, $b)
  $env:MYRKR_DBG_NOSECDESK = '1'
  $p = Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList $mrk -PassThru
  if (-not (Submit-MyrkrPassword -Process $p -Password 'Test-Password-9')) { throw 'no password prompt' }
  $main = Wait-MyrkrWindow -Process $p -Class 'myrkr_window'
  if ($main -eq [IntPtr]::Zero) { throw 'no main window' }
  Start-Sleep -Milliseconds 800
  Send-MyrkrCommand -Window $main -Id 104                                   # Decrypt
  $titles = Get-MyrkrDialogs -Process $p -Max 4
  if ($titles.Count -eq 1 -and $titles[0] -eq 'Myrkr - error') { 'PASS a failed decrypt shows exactly one dialog' }
  else { "FAIL a failed decrypt showed $($titles.Count) dialog(s): $($titles -join ' | ')"; $fail++ }
  if (-not (Test-Path (Join-Path $work 'doc.txt'))) { 'PASS no plaintext output survives the failed decrypt' }
  else { 'FAIL plaintext output left behind'; $fail++ }
  $p.Kill(); $p.WaitForExit(); $p = $null

  # ---- 2. the About window's link -------------------------------------------
  $p = Start-Process -FilePath $exe -ArgumentList 'help' -PassThru
  $about = Wait-MyrkrWindow -Process $p -Class 'myrkr_about'
  if ($about -eq [IntPtr]::Zero) { throw 'no About window' }
  $r = Get-MyrkrRect $about
  # Window-relative points; the About window is borderless, so the window rect
  # IS the client rect.  The link sits 30..230 px across, 30..10 px up from the bottom.
  $cases = @(
    @{ n = 'on the link';           x = $r.L + 60;  y = $r.B - 20; want = 1 },
    @{ n = 'beside the link';       x = $r.L + 300; y = $r.B - 20; want = 2 },
    @{ n = 'the body (drag area)';  x = $r.L + 200; y = $r.T + 40; want = 2 }
  )
  foreach ($c in $cases) {
    $got = Test-MyrkrHit -Window $about -X $c.x -Y $c.y
    if ($got -eq $c.want) { "PASS About: $($c.n) hit-tests as $got" }
    else { "FAIL About: $($c.n) hit-tests as $got, want $($c.want)"; $fail++ }
  }
} finally {
  if ($p -and -not $p.HasExited) { $p.Kill() }
  if ($null -eq $old) { Remove-Item Env:\MYRKR_DBG_NOSECDESK -EA SilentlyContinue } else { $env:MYRKR_DBG_NOSECDESK = $old }
  if ((Split-Path $work -Leaf) -like 'myrkr-guifail-*') { Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue }
}
if ($fail) { "$fail FAILURE(S)"; exit 1 } else { 'guifailtest: all checks passed'; exit 0 }
