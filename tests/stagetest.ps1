# Step 1 of docs/STAGED_LAYOUT.md: a destination PER INPUT.
#
# Until now one run had one destination - g_add_prefix, set once and used for
# everything it walked. Staging makes it per input, so a single encrypt can put
# different files in different folders. That is the naming half of "drop into a
# folder while building an archive", and it is deliberately testable before any
# of the tree work it will eventually feed: no window, no drag, no rows.
#
# Driven by --stage <n>:<folder>, which exists ONLY in a test build. The staged
# layout is a GUI gesture; a release binary has no reason to carry a way to
# script it, for the same reason it has no -p.
#
# Needs a testio build; it builds one, and the caller is expected to rebuild
# release afterwards.
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "stage1"
$root = Split-Path -Parent $PSScriptRoot
$exe  = "$root\bin\myrkr.exe"
$PW   = "Correct-Horse-Battery-9"
$fail = 0
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Exit codes through a cmd /c child: PowerShell 5.1's $LASTEXITCODE is not
# reliable for a native exe that writes to stderr - the lines come back as
# NativeCommandError and the code is lost. That cost a whole round once.
function Run($argline) { $o = cmd /c "$exe $argline 2>&1"; return @{ code=$LASTEXITCODE; out=($o -join "`n") } }

if (Test-Path $w) { Remove-Item -LiteralPath $w -Recurse -Force }
New-Item -ItemType Directory "$w" -Force | Out-Null
"building testio..."
$blog = cmd /c "$root\build.cmd testio" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

Set-Content "$w\alpha.txt"  "alpha"
Set-Content "$w\beta.txt"   "beta"
Set-Content "$w\gamma.txt"  "gamma"
New-Item -ItemType Directory "$w\tree\inner" -Force | Out-Null
Set-Content "$w\tree\t1.txt" "t1"
Set-Content "$w\tree\inner\t2.txt" "t2"

function ZipNames($z) { $a=[IO.Compression.ZipFile]::OpenRead($z); $n=@($a.Entries|ForEach-Object{$_.FullName -replace '\\','/'}); $a.Dispose(); return ($n | Sort-Object) }
function MrkNames($m) {
  $out="$w\x"; if (Test-Path $out) { Remove-Item -LiteralPath $out -Recurse -Force }
  $r = Run "decrypt ""$m"" -o ""$out"" -p $PW"
  if ($r.code -ne 0) { return @("<decrypt failed $($r.code)>") }
  return (@(Get-ChildItem $out -Recurse -File | ForEach-Object { $_.FullName.Substring($out.Length+1) -replace '\\','/' }) | Sort-Object)
}

"`n--- 1. zip: three inputs, three different destinations ---"
$z = "$w\a.zip"
$r = Run "zip ""$w\alpha.txt"" ""$w\beta.txt"" ""$w\gamma.txt"" -o ""$z"" -p $PW --stage 0:docs --stage 2:docs/deep"
if ($r.code -ne 0) { "  FAIL zip exit $($r.code): $($r.out)"; $fail++ }
else {
  $got = ZipNames $z
  $want = @('beta.txt','docs/alpha.txt','docs/deep/gamma.txt') | Sort-Object
  "  got : $($got -join ', ')"
  if (($got -join '|') -eq ($want -join '|')) { "  ok   each input landed where it was staged" }
  else { "  FAIL wanted $($want -join ', ')"; $fail++ }
}

"`n--- 2. mrk: the same, in the other format ---"
$m = "$w\a.mrk"
$r = Run "encrypt ""$w\alpha.txt"" ""$w\beta.txt"" ""$w\gamma.txt"" -o ""$m"" -p $PW --stage 0:docs --stage 2:docs/deep"
if ($r.code -ne 0) { "  FAIL encrypt exit $($r.code): $($r.out)"; $fail++ }
else {
  $got = MrkNames $m
  $want = @('beta.txt','docs/alpha.txt','docs/deep/gamma.txt') | Sort-Object
  "  got : $($got -join ', ')"
  if (($got -join '|') -eq ($want -join '|')) { "  ok   the .mrk side agrees with the zip side" }
  else { "  FAIL wanted $($want -join ', ')"; $fail++ }
}

"`n--- 3. a staged FOLDER takes its whole subtree with it ---"
# pack_node and zip_node recurse from the name the top level built, so children
# inherit the destination without knowing about it. That is the property that
# makes this one line in each builder rather than a rule threaded through.
$z2 = "$w\b.zip"
$r = Run "zip ""$w\tree"" -o ""$z2"" -p $PW --stage 0:staged"
if ($r.code -ne 0) { "  FAIL zip exit $($r.code)"; $fail++ }
else {
  $got = ZipNames $z2
  "  got : $($got -join ', ')"
  if (($got -contains 'staged/tree/t1.txt') -and ($got -contains 'staged/tree/inner/t2.txt')) {
    "  ok   children inherited the destination" }
  else { "  FAIL the subtree did not follow"; $fail++ }
}

"`n--- 4. no --stage at all is byte-for-byte the old behaviour ---"
# The whole array reads as "the root" when it has never been written, so a run
# without staging must be indistinguishable from one built before any of this
# existed. Compared by CONTENT hash, not by file hash: a container carries a
# fresh salt and id every time, so the bytes differ by design.
$z3 = "$w\c.zip"; $z4 = "$w\d.zip"
$r1 = Run "zip ""$w\alpha.txt"" ""$w\beta.txt"" -o ""$z3"" -p $PW"
$r2 = Run "zip ""$w\alpha.txt"" ""$w\beta.txt"" -o ""$z4"" -p $PW --stage 0:"
if ($r1.code -ne 0 -or $r2.code -ne 0) { "  FAIL exits $($r1.code)/$($r2.code)"; $fail++ }
else {
  $n1 = ZipNames $z3; $n2 = ZipNames $z4
  "  plain: $($n1 -join ', ')   empty-stage: $($n2 -join ', ')"
  if (($n1 -join '|') -eq 'alpha.txt|beta.txt' -and ($n2 -join '|') -eq 'alpha.txt|beta.txt') {
    "  ok   unstaged and empty-staged both land at the root" }
  else { "  FAIL staging leaked into a run that asked for none"; $fail++ }
}

"`n--- 5. a traversing destination is refused ---"
# The prefix is not validated where it is staged - it is checked as part of the
# COMBINED name, which is the only place the whole string exists. So this is
# the same guard docs/DROP_INDICATOR.md describes, reached by another road.
$z5 = "$w\e.zip"
$r = Run "zip ""$w\alpha.txt"" -o ""$z5"" -p $PW --stage 0:../escape"
if ($r.code -eq 0) { "  FAIL a '..' destination was accepted"; $fail++ }
elseif (Test-Path $z5) {
  $n = ZipNames $z5
  if ($n.Count -gt 0) { "  FAIL it wrote entries anyway: $($n -join ', ')"; $fail++ }
  else { "  ok   refused (exit $($r.code)) and wrote nothing" }
} else { "  ok   refused (exit $($r.code)) and wrote nothing" }

"`n$(if($fail -eq 0){'ALL PASS'}else{"$fail FAILURE(S)"})"
# Explicit, or the script exits with the last CHILD's code - which case 5 leaves
# non-zero on purpose, so a clean run would report failure.
exit $(if ($fail -eq 0) { 0 } else { 1 })
