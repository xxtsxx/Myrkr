# Every file that goes in comes back out.
#
# Reported 2026-08-12 against 1.0.50: 587GB / 76,286 files encrypted with no
# error, producing a container holding 16,780. Nothing was excluded for being
# small - the INDEX has a fixed ceiling, and idx_add dropped every entry past it
# while the payload went on receiving them. Unpack is driven entirely by the
# index ("the inventory locates every entry"), so those files became ciphertext
# with nothing recording their offset, ordinal or name. Encrypt said "packed ->".
#
# 2 MiB / 16,780 = 125 bytes an entry = IDXE_FIXED(40) + an 85-character path.
# The count WAS the cap.
#
# So this asserts the only thing that actually matters: count in == count out.
# Nothing else in the suite did. Long names are used so the index fills with
# thousands of files instead of tens of thousands - at 90 characters an entry
# costs ~130 bytes, so the old 2 MiB cap fell at ~16,100 and 20,000 cleared it.
#
# Needs a dbg build: encrypt/decrypt are refused on the command line in release.
$ErrorActionPreference = "Stop"
$fail = 0
# Short root on purpose: the scratchpad path plus a 90-char name is already
# close to MAX_PATH, and the test must fail for its own reasons only.
$w = Join-Path $env:TEMP "mrk_manyfiles"
$exe = Join-Path (Split-Path -Parent $PSScriptRoot) "bin\myrkr.exe"
$PW = "Correct-Horse-Battery-9"
$N = 20000

"building dbg (encrypt/decrypt are refused on the command line in release)..."
$blog = cmd /c "$(Split-Path -Parent $PSScriptRoot)\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

Remove-Item $w -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory "$w\in" -Force | Out-Null
$pad = "n" * 80
for ($i = 0; $i -lt $N; $i++) {
  [IO.File]::WriteAllText(("{0}\in\{1}_{2:D5}.txt" -f $w, $pad, $i), "x")
}
$made = (Get-ChildItem "$w\in" -File).Count
"created       : $made files"

$enc = cmd /c "`"$exe`" encrypt `"$w\in`" -o `"$w\out.mrk`" -p $PW 2>&1"
$encRc = $LASTEXITCODE
if ($encRc -ne 0) {
  # A refusal is the CORRECT behaviour when the inventory really is full - but
  # then it must produce nothing, not a container short of files.
  "  encrypt refused (exit $encRc):"
  $enc | Select-Object -Last 3 | ForEach-Object { "       $_" }
  if (Test-Path "$w\out.mrk") { "  FAIL refused but still wrote a container"; $fail++ }
  else { "  ok   refused without producing a container" }
  "  FAIL $made files should fit - the ceiling is too low or the entry cost grew"
  exit 1
}
"  ok   encrypt exit 0"

# The listing must not admit to being short, and must not BE short.
$lst = cmd /c "`"$exe`" list `"$w\out.mrk`" -p $PW 2>&1"
if (($lst -join "`n") -match "listing incomplete") {
  "  FAIL the container reports an incomplete inventory"; $fail++
} else { "  ok   the inventory is complete" }
$listed = ($lst | Where-Object { $_ -match "\.txt" }).Count
"listed        : $listed"
if ($listed -ne $made) { "  FAIL listed $listed of $made"; $fail++ }
else { "  ok   every file is listed" }

$dec = cmd /c "`"$exe`" decrypt `"$w\out.mrk`" -o `"$w\back`" -p $PW 2>&1"
if ($LASTEXITCODE -ne 0) { "  FAIL decrypt exit $LASTEXITCODE"; $fail++ }
$got = (Get-ChildItem "$w\back" -Recurse -File -EA SilentlyContinue).Count
"extracted     : $got"
# The one that would have caught the report.
if ($got -ne $made) { "  FAIL $($made - $got) of $made files did not come back"; $fail++ }
else { "  ok   every file came back" }

Remove-Item $w -Recurse -Force -EA SilentlyContinue

# ---- verify tells the truth, in both directions -----------------------------
# Nothing covered `verify` at all, and it was wrong for every single-file
# container - reporting "authentication failed" about sound archives. A check
# that only asserts "intact says OK" would pass a verify that always says OK,
# which is the far more dangerous failure for an integrity tool, so the tamper
# cases are the point of this block.
$v = "$w`_v"
Remove-Item $v -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory "$v\d" -Force | Out-Null
1..3 | ForEach-Object { Set-Content "$v\d\f$_.txt" "content $_" }
$bytes = New-Object byte[] 400000
(New-Object Random 5).NextBytes($bytes)
[IO.File]::WriteAllBytes("$v\one.bin", $bytes)
foreach ($case in @(@("single compressed","one.bin",""), @("single stored","one.bin","--store"), @("archive","d",""))) {
  $name = $case[0]; $src = "$v\$($case[1])"; $mode = $case[2]
  cmd /c "`"$exe`" encrypt `"$src`" -o `"$v\c.mrk`" -p $PW $mode" | Out-Null
  cmd /c "`"$exe`" verify `"$v\c.mrk`" -p $PW 2>&1" | Out-Null
  if ($LASTEXITCODE -eq 0) { "  ok   verify says OK for an intact $name container" }
  else { "  FAIL verify called an intact $name container corrupt (exit $LASTEXITCODE)"; $fail++ }
  # and it must still catch a flipped bit well inside the ciphertext
  $len = (Get-Item "$v\c.mrk").Length
  $f = [IO.File]::Open("$v\c.mrk",'Open','ReadWrite')
  $f.Position = [int]($len/2); $b0 = $f.ReadByte(); $f.Position = [int]($len/2); $f.WriteByte($b0 -bxor 1); $f.Close()
  cmd /c "`"$exe`" verify `"$v\c.mrk`" -p $PW 2>&1" | Out-Null
  if ($LASTEXITCODE -ne 0) { "  ok   and catches a flipped bit in a $name container" }
  else { "  FAIL verify passed a TAMPERED $name container"; $fail++ }
  Remove-Item "$v\c.mrk" -Force -EA SilentlyContinue
}
Remove-Item $v -Recurse -Force -EA SilentlyContinue

""
"=== Restore: shipping build ==="
$blog = cmd /c "$(Split-Path -Parent $PSScriptRoot)\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

"`n$(if($fail -eq 0){'ALL PASS'}else{"$fail FAILURE(S)"})"
exit $(if ($fail -eq 0) { 0 } else { 1 })
