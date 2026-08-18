# Prove the release build reproduces: build it twice, from scratch, and compare.
#
# This is the check that build.cmd used to claim and never performed. Its
# release step printed two SHA-256 values at a human and compared nothing, so
# when /Brepro stopped producing identical output nothing said so - two builds
# of one commit came out 73 bytes apart, both stamped 1.0.23.0, and the only
# way to notice was to hash them by hand.
#
# Why it has to build TWICE rather than relink: the nondeterminism was in the
# .obj files, not the link. ml64 stamps each object it writes, /Brepro hashes
# the linker's inputs to make its "deterministic" timestamp, and build.cmd
# reassembles everything on every run - so relinking the same objects would
# reproduce perfectly while a real rebuild did not. Only a full rebuild tests
# the thing that actually broke.
#
# Takes about twice as long as a release build. It is not part of build.cmd on
# purpose: gating every build on this would tempt someone to skip it, and the
# property only matters when something is about to be published.
$root = Split-Path -Parent $PSScriptRoot
$fail = 0
Push-Location $root

function Hashes {
  @{ exe = (Get-FileHash "bin\myrkr.exe" -Algorithm SHA256).Hash
     dll = (Get-FileHash "bin\myrkrshell.dll" -Algorithm SHA256).Hash }
}

# Both builds start from nothing. Clearing only BETWEEN them compares a build
# that inherited whatever obj\ happened to hold - a dbg run leaves test-build
# objects there - against a clean one, and reports the difference as a
# reproducibility failure. That is a harness bug that looks exactly like the
# defect being tested for, which is the trap this whole session kept hitting.
Remove-Item "obj\*.obj" -Force -EA SilentlyContinue
"verify_repro: building release (1 of 2), from clean objects..."
$o1 = cmd /c "$root\build.cmd strict release" 2>&1
if (($o1 -join "`n") -notmatch "BUILD OK") { "FAIL first build"; $o1 | Select-Object -Last 15; Pop-Location; exit 1 }
$h1 = Hashes
"  exe $($h1.exe.Substring(0,32))"
"  dll $($h1.dll.Substring(0,32))"

Remove-Item "obj\*.obj" -Force -EA SilentlyContinue
"verify_repro: building release (2 of 2), from clean objects..."
$o2 = cmd /c "$root\build.cmd strict release" 2>&1
if (($o2 -join "`n") -notmatch "BUILD OK") { "FAIL second build"; $o2 | Select-Object -Last 15; Pop-Location; exit 1 }
$h2 = Hashes
"  exe $($h2.exe.Substring(0,32))"
"  dll $($h2.dll.Substring(0,32))"

""
if ($h1.exe -eq $h2.exe) { "  ok   myrkr.exe reproduces" }
else { "  FAIL myrkr.exe differs between builds"; $fail++ }
if ($h1.dll -eq $h2.dll) { "  ok   myrkrshell.dll reproduces" }
else { "  FAIL myrkrshell.dll differs between builds"; $fail++ }

# ...and the recorded hashes have to be the ones actually shipped, or the file
# is decoration.
# Normalisation must not cost a mitigation. The first version of pe_normalise
# cleared every debug-directory payload, which turned CET off - shadow-stack
# compatibility is advertised by an EX_DLLCHARACTERISTICS entry whose payload
# IS the flags. Only build.cmd's optional dumpbin line noticed, by quietly
# ceasing to print one word. Asserting it here means the next person cannot
# trade a mitigation for a reproducible hash without being told.
foreach ($img in @("bin\myrkr.exe", "bin\myrkrshell.dll")) {
  $h = & dumpbin /headers $img 2>$null
  if (-not $h) { "  (dumpbin unavailable - mitigation check skipped for $img)"; continue }
  foreach ($flag in @("Dynamic base", "NX compatible", "High Entropy", "CET compatible")) {
    if (($h -join "`n") -notmatch [regex]::Escape($flag)) {
      "  FAIL $img lost '$flag' after normalisation"; $fail++
    }
  }
}
if ($fail -eq 0) { "  ok   mitigations survive normalisation (DEP, ASLR, HEVA, CET)" }

$sums = Get-Content "bin\SHA256SUMS.txt" -EA SilentlyContinue
if (-not $sums) { "  FAIL bin\SHA256SUMS.txt was not written"; $fail++ }
elseif (($sums -join ' ') -notmatch $h2.exe -or ($sums -join ' ') -notmatch $h2.dll) {
  "  FAIL SHA256SUMS.txt does not match the binaries beside it"; $fail++ }
else { "  ok   SHA256SUMS.txt matches what was built" }

""
if ($fail -eq 0) { "ALL PASS" } else { "$fail FAILURE(S)" }
Pop-Location
exit $(if ($fail -eq 0) { 0 } else { 1 })
