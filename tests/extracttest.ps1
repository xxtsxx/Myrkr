# Extraction goes straight from the inventory to the files, with nothing in
# between.
#
# Until 1.0.71 a decrypt of an archive wrote EVERY entry's plaintext into one
# complete temporary tar beside the container, and then walked that file back to
# produce the real outputs. Three costs, all of them invisible to a user:
#
#  1. 3N of I/O for an N-byte archive, and N of free scratch disk on the
#     CONTAINER's drive - which the pre-flight demanded even when the output was
#     going somewhere else entirely.
#  2. A second, complete, DECRYPTED copy of everything sitting on disk for the
#     length of the run. A cancelled or crashed decrypt left it there.
#  3. The tar headers - attacker-controlled bytes - were parsed to recover names
#     and sizes that the authenticated inventory already recorded.
#
# What replaced it (docs/V5_WORK.md, step A2) decodes each entry through
# estream's decoder straight into its own output file. That makes two claims
# this file exists to hold it to:
#
#   NO SCRATCH. Proved by denying this process the right to create files in the
#   container's own directory. Not by watching for a temp file to appear, which
#   is a race - by making one impossible to create and requiring success anyway.
#
#   A TAMPERED ENTRY NEVER REACHES DISK. Each entry carries its own GCM tag and
#   is written as it authenticates, so a corrupted one must fail the run AND
#   leave nothing of itself behind. The entries before it survive - they are
#   individually authentic - so the run also has to SAY the extraction is
#   incomplete, or a short folder passes for a complete one.
#
# Mutation-checked (see MUTATIONS at the bottom).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "myrkr_extracttest"
$PW   = "Correct-Horse-Battery-9"
$fail = 0

"building dbg (encrypt/decrypt are refused on the command line in release)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

Remove-Item $w -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory -Path $w | Out-Null

# The fixture spans the cases the decoder branches on: several entries so there
# is a "before" and an "after" for the tamper, a nested folder, an empty file
# and an empty folder (zero content bytes still has to go through the decoder,
# because that is what checks the tag), and enough bytes that an entry crosses
# the 1 MiB chunk the streaming loop works in.
$src = Join-Path $w "src"
New-Item -ItemType Directory -Path (Join-Path $src "sub") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $src "emptydir") | Out-Null
$rng = [Random]::new(20260814)
function Blob([int]$n) { $b = [byte[]]::new($n); $rng.NextBytes($b); return $b }
[IO.File]::WriteAllBytes((Join-Path $src "a.bin"), (Blob 300000))
[IO.File]::WriteAllBytes((Join-Path $src "b.bin"), (Blob 2500000))   # > 1 MiB
[IO.File]::WriteAllBytes((Join-Path $src "sub\c.bin"), (Blob 400000))
[IO.File]::WriteAllBytes((Join-Path $src "empty.bin"), [byte[]]::new(0))
# text, so the compressed container actually compresses and exercises the
# de-framing path rather than storing every frame
[IO.File]::WriteAllText((Join-Path $src "sub\text.txt"), ("the quick brown fox " * 60000))

# Through cmd, NOT `& $exe`. myrkr.exe is a /subsystem:windows image, so a
# PowerShell caller does not wait for it and $LASTEXITCODE is whatever the last
# thing to actually finish returned - which reads as a pass. cmd /c waits.
function Run([string[]]$a) {
    $q = ($a | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $o = cmd /c "`"$exe`" $q 2>&1"
    return [pscustomobject]@{ rc = $LASTEXITCODE; out = (($o | Out-String) -replace "`r", "") }
}
function TreeHash([string]$dir) {
    $h = @{}
    if (-not (Test-Path $dir)) { return $h }
    Get-ChildItem -Recurse -File $dir | ForEach-Object {
        $rel = $_.FullName.Substring($dir.Length).TrimStart('\')
        $h[$rel] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
    return $h
}
function SameTree($a, $b) {
    if ($a.Count -ne $b.Count) { return $false }
    foreach ($k in $a.Keys) { if ($b[$k] -ne $a[$k]) { return $false } }
    return $true
}
$want = TreeHash $src

foreach ($mode in @("stored", "compressed")) {
    ""
    "=== $mode ==="
    $flag = if ($mode -eq "compressed") { "--compress" } else { "--store" }
    # The container lives in a directory of its own, because the no-scratch
    # check locks that directory down and must not lock down the fixture.
    $cdir = Join-Path $w "box_$mode"
    New-Item -ItemType Directory -Path $cdir | Out-Null
    $mrk = Join-Path $cdir "a.mrk"
    $r = Run @("encrypt", $src, "-o", $mrk, "-p", $PW, $flag)
    if ($r.rc -ne 0) { "  FAIL encrypt exit $($r.rc): $($r.out)"; $fail++; continue }

    # ---- 1. no scratch ------------------------------------------------------
    # Deny this user the right to add files to the container's directory. The
    # route this replaced created its temp there (make_temp_path takes the
    # container's path), so it could not have survived this.
    $me = "$env:USERDOMAIN\$env:USERNAME"
    icacls $cdir /deny "${me}:(WD,AD)" | Out-Null
    $canWrite = $true
    try { [IO.File]::WriteAllText((Join-Path $cdir "probe.tmp"), "x") } catch { $canWrite = $false }
    if ($canWrite) {
        # The lock did not take (an unusual ACL, or elevation). Say so rather
        # than reporting a pass the run did not earn.
        Remove-Item (Join-Path $cdir "probe.tmp") -Force -EA SilentlyContinue
        "  SKIP could not make $cdir unwritable - no-scratch not proved here"
    } else {
        $out = Join-Path $w "out_$mode"
        $r = Run @("decrypt", $mrk, "-o", $out, "-p", $PW)
        if ($r.rc -ne 0) {
            "  FAIL decrypt needed to write beside the container (exit $($r.rc)): $($r.out)"; $fail++
        } elseif (SameTree $want (TreeHash (Join-Path $out "src"))) {
            "  ok   it decrypts with the container's own directory read-only"
        } else {
            "  FAIL the extraction differs from the input"; $fail++
        }
        # and nothing was left in there either
        $stray = Get-ChildItem -Force $cdir | Where-Object { $_.Name -ne "a.mrk" }
        if ($stray) { "  FAIL left behind: $($stray.Name -join ', ')"; $fail++ }
        else { "  ok   and leaves nothing in it" }
    }
    icacls $cdir /remove:d $me | Out-Null

    # ---- 2. a tampered entry ------------------------------------------------
    # Flip a byte a long way into the payload, so several entries authenticate
    # and are written before the damaged one is reached.
    $bad = Join-Path $w "bad_$mode.mrk"
    Copy-Item $mrk $bad -Force
    $b = [IO.File]::ReadAllBytes($bad)
    # Past the header and past the first entries, but well short of the
    # inventory at the tail - so this corrupts an ENTRY, not the index.
    $at = [int]($b.Length * 0.55)
    $b[$at] = $b[$at] -bxor 0x40
    [IO.File]::WriteAllBytes($bad, $b)

    $tout = Join-Path $w "tout_$mode"
    $r = Run @("decrypt", $bad, "-o", $tout, "-p", $PW)
    if ($r.rc -eq 0) { "  FAIL a tampered container decrypted with exit 0"; $fail++ }
    else { "  ok   a flipped byte inside an entry fails the run (exit $($r.rc))" }

    # Whatever IS there has to be byte-identical to the input: partial output is
    # allowed, WRONG output is not.
    $got = TreeHash $tout
    $bogus = @()
    foreach ($k in $got.Keys) {
        $rel = $k -replace '^src\\', ''
        if ($want[$rel] -ne $got[$k]) { $bogus += $k }
    }
    if ($bogus.Count) { "  FAIL damaged or unknown files were left on disk: $($bogus -join ', ')"; $fail++ }
    else { "  ok   every file it did write is byte-identical to the original ($($got.Count) of $($want.Count))" }

    if ($got.Count -ge $want.Count) {
        "  FAIL it wrote the whole archive out of a container it had rejected"; $fail++
    } else {
        "  ok   the damaged entry is not among them"
    }

    # A short folder must not be able to pass for a complete one.
    if ($got.Count -gt 0 -and $r.out -notmatch "stopped early") {
        "  FAIL it left $($got.Count) files behind without saying the set is incomplete"; $fail++
    } else {
        "  ok   and it says the extraction is incomplete"
    }

    # ---- 3. verify sees it too ---------------------------------------------
    $r = Run @("verify", $bad, "-p", $PW)
    if ($r.rc -eq 0) { "  FAIL verify passed the tampered container"; $fail++ }
    else { "  ok   verify rejects it as well (exit $($r.rc))" }

    # ---- 4. a single-file container ----------------------------------------
    # A FILE UNDER THE NAME THE USER ASKED FOR HAS ALWAYS BEEN AUTHENTICATED.
    # It is decoded under a .part name and renamed once the tag verifies, which
    # is the property the whole-file temp copy used to provide. Archives do not
    # have it and never did - see docs/SECURITY.md.
    $one = Join-Path $w "one_$mode.mrk"
    $r = Run @("encrypt", (Join-Path $src "b.bin"), "-o", $one, "-p", $PW, $flag)
    if ($r.rc -ne 0) { "  FAIL single-file encrypt exit $($r.rc)"; $fail++ }
    $got1 = Join-Path $w "one_$mode.out"
    $r = Run @("decrypt", $one, "-o", $got1, "-p", $PW)
    if ($r.rc -ne 0) { "  FAIL single-file decrypt exit $($r.rc): $($r.out)"; $fail++ }
    elseif ((Get-FileHash $got1).Hash -ne (Get-FileHash (Join-Path $src "b.bin")).Hash) {
        "  FAIL the single-file output differs"; $fail++
    } else { "  ok   a single-file container round-trips" }
    if (Test-Path "$got1.part") { "  FAIL a .part file was left behind"; $fail++ }

    $one2 = Join-Path $w "onebad_$mode.mrk"
    Copy-Item $one $one2 -Force
    $b = [IO.File]::ReadAllBytes($one2)
    $at = [int]($b.Length * 0.6)
    $b[$at] = $b[$at] -bxor 0x20
    [IO.File]::WriteAllBytes($one2, $b)
    $bad1 = Join-Path $w "onebad_$mode.out"
    $r = Run @("decrypt", $one2, "-o", $bad1, "-p", $PW)
    if ($r.rc -eq 0) { "  FAIL a tampered single-file container decrypted with exit 0"; $fail++ }
    elseif (Test-Path $bad1) {
        "  FAIL unverified plaintext was left under the name the user asked for"; $fail++
    } elseif (Test-Path "$bad1.part") {
        "  FAIL the rejected .part was left behind"; $fail++
    } else {
        "  ok   a tampered single file leaves nothing at all (exit $($r.rc))"
    }
}

""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

Remove-Item $w -Recurse -Force -EA SilentlyContinue

# =============================================================================
# MUTATIONS - each was applied, the suite run, and the stated check observed to
# fail. A test nobody has seen fail is a test nobody should believe.
#
#  1. es_raw_refill (estream.asm): after ct_memcmp, replace `jnz err_auth` with
#     `nop` so a wrong tag is accepted.
#       -> "a flipped byte inside an entry fails the run" FAILS (exit 0), in
#          both modes. This is the tag check itself.
#
#  2. unpack_entry (pack.asm): at ue_fail, jump straight to ue_failed so the
#     partly written file is closed but not deleted.
#       -> "every file it did write is byte-identical to the original" FAILS:
#          the truncated entry is left on disk under its real name.
#
#  3. do_unpack (pack.asm): at du_partial, jump straight to du_done2 so nothing
#     is said about the extraction being short.
#       -> "and it says the extraction is incomplete" FAILS.
#
#  4. do_unpack (pack.asm): restore a scratch write by calling make_temp_path
#     and file_open_write on it before the entry loop.
#       -> "it decrypts with the container's own directory read-only" FAILS
#          (exit 2), which is what the old route would have scored here.
#
#  5. do_unpack (pack.asm): pass g_outdir_np rather than g_extw for a bare
#     container, so it is decoded straight under its final name.
#       -> "a single-file container round-trips" FAILS (exit 2) in both modes.
#          NOT the failure this mutation was written to provoke: the rename that
#          follows still looks for the .part, does not find it, and reports I/O.
#          The check that would have caught the property directly - a tampered
#          single file leaving plaintext under the real name - is never reached,
#          because the good case dies first. Recorded as observed rather than as
#          intended; the mutation is detected, just not by the check named here.
# =============================================================================
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "extracttest: all checks passed"; exit 0 }
