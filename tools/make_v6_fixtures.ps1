# How tests/fixtures/v6-*.mrk were produced, recorded for provenance.
#
# DO NOT RUN THIS. The fixtures are checked in and are never regenerated: their
# entire value is that they were written by a build that predates the format
# change they guard against, and re-running this against a newer build destroys
# exactly that. tests/compattest.ps1 asserts their on-disk version byte for the
# same reason.
#
# Run once at 1.0.72 (2026-08-14), against a `build dbg` binary, because a
# release build refuses `encrypt` on the command line.
#
# The inputs are deterministic - fixed text repeated, and one random blob from a
# seeded Random(19700101) - so anyone can rebuild the plaintext and check the
# SHA-256 values compattest.ps1 asserts, without the fixture having to carry
# them.
throw "make_v6_fixtures.ps1 is provenance, not a tool. See the comment at the top."

$root = Split-Path -Parent $PSScriptRoot
$w = "$env:TEMP\v6fix"
$F = Join-Path $root "tests\fixtures"
$PW = "Fixture-Horse-Battery-9"

New-Item -ItemType Directory -Path "$w\tree\sub" -Force | Out-Null
New-Item -ItemType Directory -Path "$w\tree\emptydir" -Force | Out-Null
[IO.File]::WriteAllText("$w\tree\a.txt", "the quick brown fox jumps over the lazy dog`n" * 200)
[IO.File]::WriteAllText("$w\tree\sub\b.txt", "second file, nested one level`n" * 50)
[IO.File]::WriteAllBytes("$w\tree\empty.bin", [byte[]]::new(0))
$rng = [Random]::new(19700101); $b = [byte[]]::new(9000); $rng.NextBytes($b)
[IO.File]::WriteAllBytes("$w\tree\rand.bin", $b)
[IO.File]::WriteAllText("$w\one.txt", "a single-file container`n" * 100)

# -m 32 -t 1: a low KDF cost, so compattest opens five containers quickly. The
# parameters live in the header, so this is as valid a container as any other -
# it just costs less to open. Nothing here is a secret.
$exe = Join-Path $root "bin\myrkr.exe"
& $exe encrypt "$w\tree"    -o "$F\v6-archive-store.mrk" -p $PW --store    -m 32 -t 1
& $exe encrypt "$w\tree"    -o "$F\v6-archive-comp.mrk"  -p $PW --compress -m 32 -t 1
& $exe encrypt "$w\one.txt" -o "$F\v6-bare-store.mrk"    -p $PW --store    -m 32 -t 1
& $exe encrypt "$w\one.txt" -o "$F\v6-bare-comp.mrk"     -p $PW --compress -m 32 -t 1
# A volume set too: assembling one is a distinct read path, and it has its own
# 32-byte MVOL header in front of the container header.
$env:MYRKR_DBG_VOLBYTES = "8192"
& $exe encrypt "$w\tree" -o "$F\v6-set.mrk" -p $PW --store -m 32 -t 1
Remove-Item Env:\MYRKR_DBG_VOLBYTES
