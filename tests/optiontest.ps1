# An argument that looks like an option and is not one must be REFUSED, not
# quietly turned into an input path.
#
# Found in the 1.0.71 audit. Until 1.0.72 the option collector fell through to
# "this is a positional" for anything it did not recognise, so:
#
#   myrkr encrypt in -o out.mrk -p PW --no-compress
#
# treated "--no-compress" (there is no such option - it is "--store") as a
# SECOND FILE TO ENCRYPT. What happened next depended on whether a file of that
# name happened to exist:
#
#   it does not (the usual case)  the run died with "error: I/O failure", which
#                                 blames the disk for a typo and names nothing
#   it does                       EXIT 0. The option was silently ignored and
#                                 THAT FILE WENT INTO THE ARCHIVE
#
# The second was measured, not supposed: with a file called "--stor" sitting in
# the working directory, `encrypt in -o out.mrk --stor` succeeded and listed
# "--stor" as an entry. The operator asked for no compression, got compression,
# and got a file they never named - with a zero exit code over all of it.
#
# The refusal has to be narrow. An option's VALUE is consumed inside its own
# handler and never reaches the positional fallback, so a password or a path
# beginning with '-' must still be accepted - and a real file whose name begins
# with '-' must still be nameable, which is what ".\-name" is for. Both are
# checked here, because a fix that broke either would be worse than the bug.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "myrkr_optiontest"
$PW   = "Correct-Horse-Battery-9"
$fail = 0

"building dbg (encrypt/decrypt are refused on the command line in release)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

if (Test-Path $w) { [IO.Directory]::Delete($w, $true) }
New-Item -ItemType Directory -Path (Join-Path $w "in") | Out-Null
[IO.File]::WriteAllText((Join-Path $w "in\a.txt"), "hello")

# Through cmd, NOT `& $exe`: myrkr.exe is a /subsystem:windows image, so a
# PowerShell caller does not wait for it and $LASTEXITCODE means nothing.
function Run([string[]]$a) {
    $q = ($a | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $o = cmd /c "`"$exe`" $q 2>&1"
    return [pscustomobject]@{ rc = $LASTEXITCODE; out = (($o | Out-String) -replace "`r", "") }
}

# ---- 1. a typo is refused, and named -------------------------------------
foreach ($typo in @("--no-compress", "--logfile", "--minlen", "-q")) {
    $r = Run @("encrypt", "$w\in", "-o", "$w\t.mrk", "-p", $PW, $typo)
    if ($r.rc -eq 0) {
        "  FAIL '$typo' was accepted (exit 0)"; $fail++
    } elseif ($r.out -notmatch [regex]::Escape($typo)) {
        "  FAIL '$typo' was refused but not named: $($r.out)"; $fail++
    } elseif (Test-Path "$w\t.mrk") {
        "  FAIL '$typo' was refused but a container was written anyway"; $fail++
    } else {
        "  ok   '$typo' is refused (exit $($r.rc)) and named in the message"
    }
    Remove-Item "$w\t.mrk" -Force -EA SilentlyContinue
}

# ---- 1b. the case that used to SUCCEED ------------------------------------
# A file whose name is the typo. This is the one that mattered: the old parser
# took it as an input, ignored the option, and exited 0 with an archive holding
# a file the operator never named.
# In the working directory the command runs FROM, because that is where a bare
# "--stor" resolves. Putting it under in\ made this check unable to fail.
$decoy = Join-Path $w "--stor"
[IO.File]::WriteAllText($decoy, "not an option")
Push-Location $w
$r = Run @("encrypt", "in", "-o", "$w\c.mrk", "-p", $PW, "--stor")
Pop-Location
if ($r.rc -eq 0) {
    "  FAIL '--stor' was accepted because a file of that name exists (exit 0)"; $fail++
    $l = Run @("list", "$w\c.mrk", "-p", $PW)
    if ($l.out -match "\-\-stor") { "       ...and it went into the archive" }
} else {
    "  ok   '--stor' is refused even though a file of that name exists (exit $($r.rc))"
}
Remove-Item "$w\c.mrk" -Force -EA SilentlyContinue
Remove-Item $decoy -Force

# A bare '-' too: it is not a filename and there is no stdin convention here.
$r = Run @("encrypt", "-", "-o", "$w\t.mrk", "-p", $PW)
if ($r.rc -eq 0) { "  FAIL a bare '-' was accepted"; $fail++ }
else { "  ok   a bare '-' is refused (exit $($r.rc))" }

# ---- 2. the real options still work ---------------------------------------
foreach ($opt in @("--store", "--compress")) {
    $r = Run @("encrypt", "$w\in", "-o", "$w\r.mrk", "-p", $PW, $opt)
    if ($r.rc -ne 0) { "  FAIL '$opt' stopped working: $($r.out)"; $fail++ }
    else { "  ok   '$opt' still works" }
    Remove-Item "$w\r.mrk" -Force -EA SilentlyContinue
}

# ---- 3. a VALUE beginning with '-' is still accepted -----------------------
# The whole point of refusing at the positional fallback rather than earlier.
$dashpw = "-Dashy-Horse-Battery-9"
$r = Run @("encrypt", "$w\in", "-o", "$w\v.mrk", "-p", $dashpw)
if ($r.rc -ne 0) {
    "  FAIL a password beginning with '-' was rejected: $($r.out)"; $fail++
} else {
    $r = Run @("verify", "$w\v.mrk", "-p", $dashpw)
    if ($r.rc -ne 0) { "  FAIL the container did not verify under that password"; $fail++ }
    else { "  ok   an option value beginning with '-' is still accepted" }
}

# ---- 4. a real file whose name begins with '-' is still nameable ------------
$dashfile = Join-Path $w "in2\-weird.txt"
New-Item -ItemType Directory -Path (Join-Path $w "in2") | Out-Null
[IO.File]::WriteAllText($dashfile, "dash")
Push-Location (Join-Path $w "in2")
$r = Run @("encrypt", ".\-weird.txt", "-o", "$w\d.mrk", "-p", $PW)
Pop-Location
if ($r.rc -ne 0) {
    "  FAIL '.\-weird.txt' was refused: $($r.out)"; $fail++
} else {
    $r = Run @("list", "$w\d.mrk", "-p", $PW)
    if ($r.out -notmatch "-weird\.txt") { "  FAIL it did not keep its real name: $($r.out)"; $fail++ }
    else { "  ok   '.\-name' still names a file that really begins with '-'" }
}

""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

if (Test-Path $w) { [IO.Directory]::Delete($w, $true) }

# =============================================================================
# MUTATION - applied, run, and the stated check observed to fail.
#
#   collect_options (main.asm): delete the `cmp edx, '-'` / `je co_badopt` pair
#   at the positional fallback, restoring the old behaviour.
#     -> all five typo checks FAIL. The four in check 1 fail with exit 2 and
#        "error: I/O failure" - the typo became an input file that is not there.
#        Check 1b fails the other way: exit 0, and the run also prints
#        "...and it went into the archive", which is the hazard in one line.
#
#        NOT what this note first predicted. It said the value-less flags would
#        be accepted with exit 0; they are not, unless a file of that name
#        exists, which is precisely what 1b arranges. And 1b did not fail at all
#        on its first run - the decoy file had been created one directory below
#        where a bare "--stor" resolves, so the check could not fail and was
#        reporting a pass it had not earned. Both corrections are recorded here
#        rather than quietly fixed, because a test that cannot fail is the thing
#        this file exists to guard against.
# =============================================================================
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "optiontest: all checks passed"; exit 0 }
