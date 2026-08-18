# A large entry is a run of GCM streams - segments - and this is the file that
# holds both ends of that to their word (docs/V5_WORK.md B4/B5).
#
# SEG_BYTES applies to the bytes fed to GCM. The writer closes a stream (tag)
# when a segment fills and opens the next at segment+1 under the SAME ordinal;
# the reader derives the segment count from IDXE_stored alone -
# n = ceil(stored / (SEG_BYTES+16)) - verifies every tag, and reopens across
# each boundary. The nonce is (ordinal+1, segment); the AAD carries the segment
# too (version 8).
#
# Segmentation shipped OFF from 1.0.77 to 1.0.82 and this file was the only
# thing in the world exercising it; 1.0.83 flipped SEG_SHIFT_DEFAULT to 32
# (4 GiB), so every release encrypt now takes the paths tested here.
# MYRKR_DBG_SEGBYTES still shrinks the segment so ten boundaries cost kilobytes
# instead of 40 GiB.  The reason this file exists is unchanged and is its last
# check, the nonce log: nonce reuse under one key is the one mistake in this
# design that no later fix undoes, and a round-trip CANNOT catch it (a writer
# and reader that repeat a nonce in the same way agree with each other
# perfectly). Only the log of what was actually issued can - proven in the
# field 2026-08-15 by a 155.4 GB entry whose user-computed SHA-256 matched.
#
# Mutation-checked (see MUTATIONS at the bottom).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "myrkr_segmenttest"
$PW   = "Correct-Horse-Battery-9"
$SEG  = 65536
$fail = 0

"building dbg (MYRKR_DBG_SEGBYTES and encrypt on the command line need it)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

if (Test-Path $w) { [IO.Directory]::Delete($w, $true) }
New-Item -ItemType Directory -Path (Join-Path $w "in\sub") | Out-Null

# The fixture is built around the boundary cases:
#   big.bin    307,200 B content -> 307,712 B tar plaintext = 4 full segments + a tail
#   exact.bin  130,560 B content -> 131,072 B tar plaintext = EXACTLY 2 segments,
#              which is the lazy-roll case: 2 streams, not 2 plus an empty one
#   sub\text   compressible, so the compressed run exercises frames SPANNING a cut
#   small/empty/dir  single-segment and zero-content entries
$rng = [Random]::new(20260814)
$b = [byte[]]::new(307200); $rng.NextBytes($b); [IO.File]::WriteAllBytes("$w\in\big.bin", $b)
[IO.File]::WriteAllBytes("$w\in\exact.bin", [byte[]](,[byte]65 * 130560))
[IO.File]::WriteAllText("$w\in\sub\text.txt", ("the quick brown fox jumps over the lazy dog " * 8000))
[IO.File]::WriteAllText("$w\in\small.txt", "hello")
[IO.File]::WriteAllBytes("$w\in\empty.bin", [byte[]]::new(0))

function Run([string[]]$a) {
    $q = ($a | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $o = cmd /c "`"$exe`" $q 2>&1"
    return [pscustomobject]@{ rc = $LASTEXITCODE; out = (($o | Out-String) -replace "`r", "") }
}
function TreeHash([string]$dir) {
    $h = @{}
    if (-not (Test-Path $dir)) { return $h }
    Get-ChildItem -Recurse -File $dir | ForEach-Object {
        $h[$_.FullName.Substring($dir.Length).TrimStart('\')] = (Get-FileHash $_.FullName).Hash
    }
    return $h
}
function SameTree($a, $b) {
    if ($a.Count -ne $b.Count) { return $false }
    foreach ($k in $a.Keys) { if ($b[$k] -ne $a[$k]) { return $false } }
    return $true
}
$want = TreeHash "$w\in"

foreach ($mode in @("stored", "compressed")) {
    ""
    "=== $mode, $SEG-byte segments ==="
    $flag = if ($mode -eq "compressed") { "--compress" } else { "--store" }
    $mrk  = Join-Path $w "$mode.mrk"
    $nlog = Join-Path $w "$mode-nonces.txt"

    # The environment drives BOTH knobs, and only around the encrypt: the nonce
    # log must hold exactly the set sealed under this container's key, and a
    # decrypt in the same environment would append the same nonces again.
    $env:MYRKR_DBG_SEGBYTES = "$SEG"
    $env:MYRKR_DBG_NONCELOG = $nlog
    $r = Run @("encrypt", "$w\in", "-o", $mrk, "-p", $PW, $flag, "-m", "32", "-t", "1")
    Remove-Item Env:\MYRKR_DBG_SEGBYTES
    Remove-Item Env:\MYRKR_DBG_NONCELOG
    if ($r.rc -ne 0) { "  FAIL encrypt exit $($r.rc): $($r.out)"; $fail++; continue }

    # ---- the header says what the container is --------------------------------
    $hdr = [IO.File]::ReadAllBytes($mrk)
    $shift = $hdr[19]
    if ([BitConverter]::ToUInt32($hdr,4) -ne 8 -or (1 -shl $shift) -ne $SEG) {
        "  FAIL header: version $([BitConverter]::ToUInt32($hdr,4)), seg_shift $shift"; $fail++
    } else { "  ok   version 8, seg_shift $shift (= $SEG bytes)" }

    # ---- round trip ----------------------------------------------------------
    $out = Join-Path $w "out-$mode"
    $r = Run @("decrypt", $mrk, "-o", $out, "-p", $PW)
    if ($r.rc -ne 0) { "  FAIL decrypt exit $($r.rc): $($r.out)"; $fail++ }
    elseif (-not (SameTree $want (TreeHash "$out\in"))) { "  FAIL round trip differs"; $fail++ }
    else { "  ok   round-trips byte for byte" }

    $r = Run @("verify", $mrk, "-p", $PW)
    if ($r.rc -ne 0) { "  FAIL verify rejected it (exit $($r.rc))"; $fail++ }
    else { "  ok   verify authenticates every segment" }

    # ---- the drag path joins segments too -------------------------------------
    # estream keeps every entry's stream open at once and reads them round robin
    # in 7919-byte pieces, so boundary reopens INTERLEAVE across entries - the
    # exact shape drag-out produces, and one an end-to-end decrypt never makes.
    $es = Join-Path $w "es-$mode"
    New-Item -ItemType Directory -Path $es | Out-Null
    $r = Run @("estream", $mrk, "-o", $es, "-p", $PW)
    if ($r.rc -ne 0) { "  FAIL estream exit $($r.rc): $($r.out)"; $fail++ }
    else {
        # es_N.bin in index order: big, exact, sub\text.txt IS NOT among the
        # first files... entries are walk order: big, exact, small, empty, sub/text
        $names = @("big.bin","exact.bin","empty.bin","small.txt","sub\text.txt") |
                 Sort-Object  # not the walk order; compare by content instead
        $got = Get-ChildItem "$es\es_*.bin" | ForEach-Object { (Get-FileHash $_.FullName).Hash }
        $missing = @()
        foreach ($k in $want.Keys) { if ($got -notcontains $want[$k]) { $missing += $k } }
        if ($missing.Count) { "  FAIL estream output missing: $($missing -join ', ')"; $fail++ }
        else { "  ok   the drag path yields every file byte-identical" }
    }

    # ---- the nonce log: every nonce issued, no two alike ----------------------
    $lines = Get-Content $nlog
    $uniq  = $lines | Sort-Object -Unique
    if ($lines.Count -ne $uniq.Count) {
        "  FAIL NONCE REUSED: $($lines.Count) issued, $($uniq.Count) distinct"; $fail++
        $lines | Group-Object | Where-Object Count -gt 1 | ForEach-Object { "       $($_.Name) x$($_.Count)" }
    } else { "  ok   $($lines.Count) nonces issued, all distinct" }

    if ($mode -eq "stored") {
        # Stored plaintext sizes are exact (512 header + content padded to 512),
        # so the segment count per entry is computable and the log's SIZE can be
        # pinned too - a log that is merely unique could also be merely empty.
        #   dir in (the root itself): 512 -> 1     dir in/sub:    512 -> 1
        #   big:   307712 -> 5                    exact:      131072 -> 2
        #   empty:    512 -> 1                    small:        1024 -> 1
        #   text:  352768 -> 6                    + the index stream:   1
        $expect = 1 + 1 + 5 + 2 + 1 + 1 + 6 + 1
        if ($lines.Count -ne $expect) {
            "  FAIL expected $expect nonces (per-entry segment counts + the index), saw $($lines.Count)"; $fail++
        } else { "  ok   and the count is exactly the sum of the segment counts ($expect)" }
    }

    # ---- tamper: a middle segment, its tag, and the final segment -------------
    $cbytes = [IO.File]::ReadAllBytes($mrk)
    $clen   = [int]$cbytes.Length
    $off1   = [int](80 + 2 * $SEG + 200)   # inside big.bin's third segment
    $off2   = [int](80 + $SEG + 2)         # inside the first segment tag's span
    $off3   = [int]($clen - 1024)          # near the tail (index / last entry)
    $tampers = @()
    $tampers += , @("a byte in segment 3 of big.bin", $off1)
    $tampers += , @("a segment tag", $off2)
    $tampers += , @("the last kilobyte", $off3)
    foreach ($t in $tampers) {
        $bad = Join-Path $w "bad.mrk"
        $bb = [byte[]]$cbytes.Clone()
        $ix = [int]$t[1]
        $bb[$ix] = $bb[$ix] -bxor 0x40
        [IO.File]::WriteAllBytes($bad, $bb)
        $r = Run @("verify", $bad, "-p", $PW)
        if ($r.rc -eq 0) { "  FAIL verify passed with $($t[0]) flipped"; $fail++ }
        else { "  ok   flipping $($t[0]) fails verify (exit $($r.rc))" }
    }

    # ---- truncation: the container ends mid-segment ---------------------------
    $bad = Join-Path $w "short.mrk"
    $short = [byte[]]::new($clen - 2000)
    [Array]::Copy($cbytes, $short, $short.Length)
    [IO.File]::WriteAllBytes($bad, $short)
    $r = Run @("verify", $bad, "-p", $PW)
    if ($r.rc -eq 0) { "  FAIL a truncated container verified"; $fail++ }
    else { "  ok   truncation is refused (exit $($r.rc))" }
}

""
"=== the knife-edges ==="
# A hostile seg_shift: valid magic, version 8, shift = 63.  1 << 63 read
# unvalidated would be a 1-byte... no: shl masks to 6 bits, so 63 is 2^63 - and
# 64 would quietly compute 1.  Both live outside [SEG_SHIFT_MIN, SEG_SHIFT_MAX]
# and must be refused as corrupt, not obeyed.
$src = Join-Path $w "stored.mrk"
foreach ($s in @(63, 11, 36)) {
    $bb = [IO.File]::ReadAllBytes($src)
    $bb[19] = $s
    $bad = Join-Path $w "shift$s.mrk"
    [IO.File]::WriteAllBytes($bad, $bb)
    $r = Run @("list", $bad, "-p", $PW)
    if ($r.rc -eq 0) { "  FAIL seg_shift=$s was accepted"; $fail++ }
    else { "  ok   seg_shift=$s is refused (exit $($r.rc))" }
}
# Without the knob, an encrypt now writes SEG_SHIFT_DEFAULT (32, 4 GiB - on
# since 1.0.83).  This check asserted 0 while segmentation shipped off; it pins
# the default either way, so an accidental change to the constant fails here.
$plain = Join-Path $w "plain.mrk"
$r = Run @("encrypt", "$w\in\small.txt", "-o", $plain, "-p", $PW, "-m", "32", "-t", "1")
$bb = [IO.File]::ReadAllBytes($plain)
if ($bb[19] -ne 32) { "  FAIL a default encrypt wrote seg_shift $($bb[19]), expected 32"; $fail++ }
else { "  ok   without the knob, seg_shift is the shipped default (32 = 4 GiB)" }
# ...and it still round-trips: a <4 GiB entry is exactly one segment.
$r = Run @("decrypt", $plain, "-o", (Join-Path $w "plain.out"), "-p", $PW)
if ($r.rc -ne 0 -or (Get-Content (Join-Path $w "plain.out") -Raw) -ne "hello") {
    "  FAIL the default-segmented single file did not round-trip"; $fail++
} else { "  ok   and a sub-boundary entry round-trips as one segment" }

# The per-entry ceiling on ADD, which never existed until 1.0.83's flip forced
# the question: do_pack refused an oversized file from the start, but `add`
# sailed past and wrote one GCM stream over the counter wrap - keystream reuse,
# through the front door. Judged per the HEADER: a legacy (unsegmented)
# container must refuse; a segmented one has no per-entry bound.
#
# A SPARSE 70 GiB file makes this free to test: the pre-flight reads sizes,
# never content, and the refusal must land before anything is written.
$huge = Join-Path $w "huge.bin"
fsutil file createnew $huge 0 | Out-Null
fsutil sparse setflag $huge | Out-Null
fsutil file seteof $huge 75161927680 | Out-Null
$legacy = Join-Path $w "legacy.mrk"
Copy-Item (Join-Path $root "tests\fixtures\v6-archive-store.mrk") $legacy -Force
$before = (Get-FileHash $legacy).Hash
$r = Run @("add", $legacy, $huge, "-p", "Fixture-Horse-Battery-9")
if ($r.rc -eq 0) { "  FAIL a 70 GiB add to an unsegmented container was ACCEPTED - that is a counter wrap"; $fail++ }
elseif ($r.out -notmatch "without segments") { "  FAIL refused, but not for the stated reason: $($r.out)"; $fail++ }
elseif ((Get-FileHash $legacy).Hash -ne $before) { "  FAIL the refusal modified the container"; $fail++ }
else { "  ok   a 70 GiB add to a pre-segment container is refused, container untouched" }


""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

if (Test-Path $w) { [IO.Directory]::Delete($w, $true) }

# =============================================================================
# MUTATIONS - each applied, run, observed to fail, reverted.
#
#  1. THE MONEY CASE. seg_roll (pack.asm): delete `inc dword [g_segidx]`, AND
#     es_raw_refill (estream.asm): delete `inc dword [r10+ES_segidx]`. Writer
#     and reader now both use segment 0 for every segment - so every nonce and
#     every AAD agree, every tag verifies, and THE ROUND TRIP PASSES while the
#     container reuses one nonce per extra segment. Only the nonce-log check
#     fails: "NONCE REUSED: 17 issued, 10 distinct". That check is the reason
#     this file exists; nothing else here, and nothing else in the suite, can
#     see the mistake.
#
#  2. seg_roll: `inc g_entnext` added (roll advances the ORDINAL). The reader
#     reopens under the sealed ordinal, the writer sealed under a drifted one:
#     round trip FAILS exit 3 on big.bin's second segment. Caught immediately,
#     which is why mutation 1 - where both sides drift in step - is the one
#     that matters.
#
#  3. es_raw_refill: `add [r10+ES_ctoff], GCM_TAG_LEN` deleted at err_nextseg.
#     The reader re-reads the tag bytes as ciphertext: exit 3. (An offset bug
#     fails closed - GCM's tag is doing the catching.)
#
#  4. do_add (pack.asm): delete the da_sumd size gate (the seg_bytes_from_hdr
#     call through `jmp da_close`).
#       -> "a 70 GiB add to a pre-segment container is refused" FAILS with
#          "was ACCEPTED - that is a counter wrap". The add then begins writing
#          a 70 GiB stream into the fixture copy, which is the 1.0.82-and-
#          earlier behaviour this check exists to keep dead.
# =============================================================================
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "segmenttest: all checks passed"; exit 0 }
