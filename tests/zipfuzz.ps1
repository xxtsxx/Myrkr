# The zip extractor is a parser on attacker-controlled bytes: myrkr extracts
# plain zips as a convenience, so a malformed one is hostile input. The rule is
# narrow and absolute - a malformed zip may be REJECTED or (by luck) extracted,
# but it may NEVER crash the process or hang it. No exit code below zero (an NT
# exception - access violation, fastfail) and no timeout are allowed.
#
# This landed with a real bug: extract_zip_entry trusted the central-directory
# filename-length field and computed the extra-field pointer (ch+46+nlen) from
# it with no bound, unlike the two sibling walks that check ch+46+nlen against
# g_cdsize. A corrupted length aimed that pointer past the buffer; the release
# build escaped it only by heap layout, the instrumented build access-violated.
# The first case below is that exact minimised input; the sweep is the net that
# caught it. Found by an adversarial fuzz of the extract path, 2026-08-18.
#
# Needs a dbg build: `unzip` takes a password (WinZip-AES entries), so the
# SHIPPING binary refuses it from the command line - against release every
# input is turned away before it is parsed and the fuzz tests nothing. So this
# builds dbg, and restores the release build through Finish on every exit. The
# build-sanity gate below is the tripwire for a wrong build: the GOOD zip must
# extract, or the run is vacuous and says so instead of passing hollowly.
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "myrkr-zipfuzz"
$fail = 0
Add-Type -AssemblyName System.IO.Compression.FileSystem
Remove-Item -Recurse -Force $w -EA SilentlyContinue
New-Item -ItemType Directory "$w\src" -Force | Out-Null

function Finish([int]$code) {
  "=== Restore: shipping build ==="
  $blog = cmd /c "$root\build.cmd strict release" 2>&1
  if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; if ($code -eq 0) { $code = 1 } }
  else { "  bin\myrkr.exe is a release build - ok" }
  exit $code
}

"building dbg (unzip is refused from the command line by the shipping build)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

# a real multi-entry zip, both stored and deflated so both parse paths run
1..5 | ForEach-Object { Set-Content "$w\src\file$_.txt" ("payload-$_-" * 200) }
[IO.Compression.ZipFile]::CreateFromDirectory("$w\src", "$w\store.zip", [IO.Compression.CompressionLevel]::NoCompression, $false)
[IO.Compression.ZipFile]::CreateFromDirectory("$w\src", "$w\defl.zip",  [IO.Compression.CompressionLevel]::Optimal, $false)

function Run($zip, $outdir) {
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $exe; $psi.Arguments = "unzip `"$zip`" -o `"$outdir`""
  $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  $p = [Diagnostics.Process]::Start($psi)
  if (-not $p.WaitForExit(15000)) { try { $p.Kill() } catch {}; return "HANG" }
  return $p.ExitCode
}
function Verdict($code) {
  # < 0 is an NT exception code (0xC0000005 AV, 0xC0000409 fastfail): a crash.
  if ($code -eq "HANG") { return "HANG" }
  if ($code -is [int] -and $code -lt 0) { return "CRASH" }
  return "clean"       # 0 (extracted) or a positive myrkr exit (rejected) - both fine
}

# ---- build-sanity gate: the good zip must extract, or the fuzz is vacuous -----
$orig = Get-ChildItem "$w\src" | Sort-Object Name | ForEach-Object { (Get-FileHash $_.FullName).Hash }
foreach ($base in "store.zip","defl.zip") {
  [void](Run "$w\$base" "$w\ok-$base")
  $got = Get-ChildItem "$w\ok-$base" -Recurse -File -EA SilentlyContinue | Sort-Object Name | ForEach-Object { (Get-FileHash $_.FullName).Hash }
  if (($orig -join '') -eq ($got -join '')) { "  ok   $base extracts all 5 entries byte-for-byte (build is a real extractor)" }
  else { "  FAIL $base did not extract - wrong build, or the bound rejects a valid record; the sweep below would be vacuous"; $fail++ }
}
if ($fail) { "`n$fail FAILURE(S)"; Finish 1 }

# ---- 1. the minimised regression: CD filename-length high byte corrupted -----
# Find the last central-directory record (sig 0x02014b50) and set the high byte
# of its 2-byte filename-length field (record offset +28) large, so ch+46+nlen
# points far past the directory buffer.
$zb = [IO.File]::ReadAllBytes("$w\store.zip")
$lastCd = -1
for ($i = 0; $i -le $zb.Length - 4; $i++) { if ([BitConverter]::ToUInt32($zb,$i) -eq 0x02014b50) { $lastCd = $i } }
if ($lastCd -lt 0) { "  FAIL could not locate a central-directory record in the fixture"; $fail++ }
else {
  $mut = [byte[]]$zb.Clone(); $mut[$lastCd + 29] = 0x84
  [IO.File]::WriteAllBytes("$w\regress.zip", $mut)
  $v = Verdict (Run "$w\regress.zip" "$w\rout"); Remove-Item -Recurse -Force "$w\rout" -EA SilentlyContinue
  if ($v -eq "clean") { "  ok   a corrupted CD filename-length is refused, not a crash" }
  else { "  FAIL the CD-filename-length overflow $v-ed the extractor (the 2026-08-18 bug)"; $fail++ }
}

# ---- 2. the sweep: random byte corruption, both parse paths ------------------
$crash = 0; $hang = 0; $trials = 0
foreach ($base in "store.zip","defl.zip") {
  $zb = [IO.File]::ReadAllBytes("$w\$base")
  $rnd = New-Object Random 20260818
  for ($i = 0; $i -lt 250; $i++) {
    $mut = [byte[]]$zb.Clone()
    foreach ($e in 1..$rnd.Next(1,5)) { $mut[$rnd.Next(0,$mut.Length)] = [byte]$rnd.Next(0,256) }
    [IO.File]::WriteAllBytes("$w\m.zip", $mut)
    $v = Verdict (Run "$w\m.zip" "$w\out"); Remove-Item -Recurse -Force "$w\out" -EA SilentlyContinue; $trials++
    if ($v -eq "CRASH") { $crash++; [IO.File]::WriteAllBytes("$w\crash-$base-$i.zip", $mut) }
    elseif ($v -eq "HANG") { $hang++; [IO.File]::WriteAllBytes("$w\hang-$base-$i.zip", $mut) }
  }
}
if ($crash) { "  FAIL $crash of $trials random-corrupted zips crashed the extractor (saved under $w)"; $fail++ }
if ($hang)  { "  FAIL $hang of $trials random-corrupted zips hung the extractor (saved under $w)"; $fail++ }
if (-not $crash -and -not $hang) { "  ok   $trials random-corrupted zips (store + deflate) all handled, no crash, no hang" }

if ($fail -gt 0) { "`n$fail FAILURE(S)"; Finish 1 } else { "`nzipfuzz: all checks passed"; Finish 0 }
