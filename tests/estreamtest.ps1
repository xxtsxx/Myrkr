# Step 1 of docs/DRAG_OUT.md: the IStream over one archive entry.
#
# What is under test is a COM object, so it is driven the way the drop target
# was - through the vtable, with no drag anywhere near it.  `myrkr estream`
# constructs one IStream per file entry, holds them ALL open, and reads them
# round robin 7919 bytes at a time.  Reading them one after another would pass
# just as happily against the global-state design this object exists to avoid,
# so the interleaving is the test, not a flourish; the odd chunk size puts every
# read off both the 16-byte GCM boundary and the 512-byte tar boundary.
#
# The bytes are then compared against `myrkr decrypt` of the same container.
# That is the only comparison worth making: it owes nothing to the stream, and
# it is the extraction users already rely on.
#
# Cases: an XPRESS-compressed archive, a stored archive, a bare single-file
# container (no tar header in the entry at all), and a tampered container, which
# must FAIL rather than hand over unauthenticated plaintext.
#
# Needs a testio build (estream and -p are both test-only), so it builds one -
# and RESTORES the shipping build before it exits.  It used to leave the testio
# binary in bin\ and say, in this comment, that the caller was expected to
# rebuild.  A comment is not a cleanup step: what was left behind accepts a
# password on the command line, which is the one thing a release build refuses
# to do, and it sat there looking like the shipping binary.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$exe  = Join-Path $root "bin\myrkr.exe"
$sp   = Join-Path $env:TEMP "myrkr-tests"
$w    = Join-Path $sp "estreamtest"
$PW   = "Correct-Horse-Battery-9"
$fail = 0

function Say($ok, $msg) {
    if ($ok) { Write-Host "  ok   $msg" } else { Write-Host "  FAIL $msg"; $script:fail++ }
}

# myrkr.exe is /subsystem:windows, so PowerShell will not wait for it and will
# not see its exit code unless it is started explicitly.  `& $exe` silently
# races instead - which looked like every command failing at once.
function M {
    param([string[]]$a)
    $o = Join-Path $w "stdout.txt"; $e = Join-Path $w "stderr.txt"
    $p = Start-Process -FilePath $exe -ArgumentList $a -Wait -PassThru -NoNewWindow `
                       -RedirectStandardOutput $o -RedirectStandardError $e
    [pscustomobject]@{
        Code = $p.ExitCode
        Out  = (Get-Content $o -Raw)
        Err  = (Get-Content $e -Raw)
    }
}

Remove-Item -Recurse -Force $w -EA SilentlyContinue
New-Item -ItemType Directory -Force $w | Out-Null

Write-Host "=== building a testio binary ==="
$vcCandidates = @(
    "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)
$vc = $vcCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vc) { throw "no vcvars64.bat found" }
cmd /c "`"$vc`" >nul 2>&1 && `"$root\build.cmd`" testio strict" | Out-Null
if ($LASTEXITCODE) { throw "build testio strict failed" }

# ---------------------------------------------------------------------------
# The input tree.  The sizes are chosen against the framing rather than for
# variety: 1 byte is smaller than the tar header the stream has to skip; 0 bytes
# is an entry whose content ends before any Read happens, and whose tag would
# never be checked at all by a reader that stopped at the last content byte;
# 700000 spans several 7919-byte reads and, compressed, more than one frame
# boundary is not reachable at 1 MiB blocks - but 100000 and 700000 do land
# mid-block, which is the part that matters.  Random bytes, so XPRESS stores
# rather than compresses them, and text, so it compresses.
# ---------------------------------------------------------------------------
$in = Join-Path $w "in"
New-Item -ItemType Directory -Force (Join-Path $in "sub") | Out-Null
$rand = New-Object Random 20260810
$mk = {
    param($rel, $len, $text)
    $path = Join-Path $in $rel
    if ($text) {
        $sb = New-Object Text.StringBuilder
        while ($sb.Length -lt $len) { [void]$sb.Append("the quick brown fox jumps over the lazy dog. ") }
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::ASCII.GetBytes($sb.ToString(0, $len)))
    } else {
        $b = New-Object byte[] $len; if ($len) { $rand.NextBytes($b) }
        [IO.File]::WriteAllBytes($path, $b)
    }
}
& $mk "a.bin"      1      $false
& $mk "b.bin"      100000 $false
& $mk "sub\c.txt"  700000 $true
& $mk "sub\d.txt"  0      $false

# ---------------------------------------------------------------------------
# One case = one container.  Extract it with `decrypt`, stream it with
# `estream`, and compare the two file by file using the name mapping estream
# prints (index -> tar entry name), so nothing is matched up by size.
# ---------------------------------------------------------------------------
function Check-Container($label, $mrk, $srcRoot) {
    $ref = Join-Path $w "ref_$label"
    $out = Join-Path $w "out_$label"
    Remove-Item -Recurse -Force $ref, $out -EA SilentlyContinue
    New-Item -ItemType Directory -Force $out | Out-Null

    $r = M @("decrypt", $mrk, "-o", $ref, "-p", $PW)
    if ($r.Code -ne 0) { Say $false "$label : decrypt failed ($($r.Code)) $($r.Err)"; return }

    $r = M @("estream", $mrk, "-o", $out, "-p", $PW)
    if ($r.Code -ne 0) { Say $false "$label : estream failed ($($r.Code)) $($r.Out)$($r.Err)"; return }

    # "<i> <cbSize from IStream::Stat> <name>" lines, then the OK line
    $map = @{}; $stat = @{}
    foreach ($line in ($r.Out -split "`r?`n")) {
        if ($line -match '^(\d+) (\d+) (.+)$') {
            $map[[int]$Matches[1]]  = $Matches[3]
            $stat[[int]$Matches[1]] = [int64]$Matches[2]
        }
    }
    if ($map.Count -eq 0) { Say $false "$label : estream printed no entry mapping"; return }

    foreach ($i in ($map.Keys | Sort-Object)) {
        $name = $map[$i]
        # tar entry names are relative to the packed root and use '/'
        $refFile = Join-Path $ref ($name -replace '/', '\')
        # a container packed from a folder carries that folder as the top level;
        # decrypt writes the same tree, so the two paths line up as-is
        $got = Join-Path $out ("es_{0}.bin" -f $i)
        if (-not (Test-Path $refFile)) { Say $false "$label : $name has no reference file at $refFile"; continue }
        if (-not (Test-Path $got))     { Say $false "$label : $name produced no stream output"; continue }
        $a = [IO.File]::ReadAllBytes($refFile)
        $b = [IO.File]::ReadAllBytes($got)
        if ($a.Length -ne $b.Length) {
            Say $false "$label : $name is $($b.Length) bytes, reference is $($a.Length)"
            continue
        }
        $same = $true
        for ($k = 0; $k -lt $a.Length; $k++) { if ($a[$k] -ne $b[$k]) { $same = $false; break } }
        Say $same "$label : $name ($($a.Length) bytes) streams byte-identical"
        # Stat's cbSize has to agree with the real size, or the file descriptor
        # step 2 builds from the same number will make Explorer stop the copy
        # early believing it is done.
        Say ($stat[$i] -eq $a.Length) "$label : $name Stat reports $($stat[$i]), file is $($a.Length)"
    }
}

# ---------------------------------------------------------------------------
# Step 2: the same container through the IDataObject instead.
#
# `dataobj` drives every method through its vtable - QueryInterface (including
# an interface it must REFUSE), EnumFormatEtc + Next, QueryGetData for both
# offered formats and one that is not offered, GetData for the descriptor,
# GetData for each entry's contents, and GetData for an lindex past the end.
# Any wrong answer exits non-zero, so a zero exit is the whole interface
# assertion; what is checked here is the part a test can see from outside: the
# descriptor's names and sizes, and the bytes the streams produce.
#
# Names are LEAF names by design, so the reference file is found by leaf. The
# fixture keeps every leaf unique, which is also the limitation: two entries
# with the same leaf in different folders would collide in one drag, and that
# is step 4's problem (see docs/DRAG_OUT.md).
# ---------------------------------------------------------------------------
function Check-DataObj($label, $mrk) {
    $ref = Join-Path $w "ref_$label"          # written by Check-Container already
    $out = Join-Path $w "do_$label"
    Remove-Item -Recurse -Force $out -EA SilentlyContinue
    New-Item -ItemType Directory -Force $out | Out-Null

    $r = M @("dataobj", $mrk, "-o", $out, "-p", $PW)
    if ($r.Code -ne 0) { Say $false "$label/dataobj : failed ($($r.Code)) $($r.Out)$($r.Err)"; return }

    $rows = @()
    foreach ($line in ($r.Out -split "`r?`n")) {
        if ($line -match '^(\d+) (\d+) (.+)$') {
            $rows += [pscustomobject]@{ I = [int]$Matches[1]; Size = [int64]$Matches[2]; Name = $Matches[3] }
        }
    }
    if ($rows.Count -eq 0) { Say $false "$label/dataobj : no descriptor rows"; return }

    # Names are RELATIVE PATHS now, rooted where the drag started, so they line
    # up with the extracted tree directly - no searching by leaf, which is what
    # made a collision possible in the first place.
    foreach ($row in $rows) {
        $refPath = Join-Path $ref $row.Name
        $got     = Join-Path $out ("es_{0}.bin" -f $row.I)
        if (-not (Test-Path $refPath)) { Say $false "$label/dataobj : $($row.Name) is in the descriptor but not in the extraction"; continue }
        if (Test-Path $refPath -PathType Container) {
            # A folder is offered as an item so an EMPTY one survives the copy.
            # Its stream is real - a 512-byte tar header sealed like any other -
            # so it must authenticate and yield nothing.
            Say ($row.Size -eq 0) "$label/dataobj : $($row.Name) is a folder, descriptor size 0"
            Say ((Test-Path $got) -and ((Get-Item $got).Length -eq 0)) `
                "$label/dataobj : $($row.Name) folder stream authenticates and yields no bytes"
            continue
        }
        if (-not (Test-Path $got)) { Say $false "$label/dataobj : $($row.Name) produced no contents"; continue }
        $a = [IO.File]::ReadAllBytes($refPath)
        $b = [IO.File]::ReadAllBytes($got)
        Say ($row.Size -eq $a.Length) "$label/dataobj : $($row.Name) descriptor says $($row.Size), file is $($a.Length)"
        $same = $a.Length -eq $b.Length
        if ($same) { for ($k = 0; $k -lt $a.Length; $k++) { if ($a[$k] -ne $b[$k]) { $same = $false; break } } }
        Say $same "$label/dataobj : $($row.Name) contents byte-identical via CFSTR_FILECONTENTS"
    }

    # Nothing may be silently left behind.  A drag that quietly drops half a
    # folder is the failure this whole step exists to avoid, and it would look
    # exactly like success from every check above.
    $want = @(Get-ChildItem -Recurse $ref | ForEach-Object {
        $_.FullName.Substring($ref.Length + 1)
    }) | Sort-Object
    $have = @($rows | ForEach-Object { $_.Name }) | Sort-Object
    $missing = @(Compare-Object $want $have | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject })
    Say ($missing.Count -eq 0) "$label/dataobj : every extracted path is offered ($($have.Count) items; missing: $($missing -join ', '))"
}

Write-Host "`n=== compressed archive ==="
$c1 = Join-Path $w "comp.mrk"
$r = M @("encrypt", $in, "-o", $c1, "-p", $PW, "--compress"); if ($r.Code) { throw "encrypt --compress failed: $($r.Err)" }
Check-Container "comp" $c1 $in
Write-Host "`n=== compressed archive, through the IDataObject ==="
Check-DataObj "comp" $c1

Write-Host "`n=== stored archive ==="
$c2 = Join-Path $w "store.mrk"
$r = M @("encrypt", $in, "-o", $c2, "-p", $PW, "--store"); if ($r.Code) { throw "encrypt --store failed: $($r.Err)" }
Check-Container "store" $c2 $in
Write-Host "`n=== stored archive, through the IDataObject ==="
Check-DataObj "store" $c2

Write-Host "`n=== what a selection is named, which is the whole of step 4 ==="
# Names are relative to the SELECTION'S PARENT.  That one rule has to make both
# gestures read the way they look, and it is the part that cannot be checked by
# dragging the top level - everything there is already relative to the root.
#
#   drag a nested FILE   -> its leaf, dropped where the mouse went
#   drag a nested FOLDER -> the folder itself plus what is under it
#   drag a top-level file-> its leaf, same as any other file
#
# Folders appear as items in their own right so an empty one survives the copy.
function Check-Selection($sel, $expected) {
    $out = Join-Path $w "sel"
    Remove-Item -Recurse -Force $out -EA SilentlyContinue
    New-Item -ItemType Directory -Force $out | Out-Null
    $r = M @("dataobj", $c2, $sel, "-o", $out, "-p", $PW)
    if ($r.Code -ne 0) { Say $false "select '$sel' : failed ($($r.Code)) $($r.Out)$($r.Err)"; return }
    $names = @()
    foreach ($line in ($r.Out -split "`r?`n")) {
        if ($line -match '^(\d+) (\d+) (.+)$') { $names += $Matches[3] }
    }
    $got = $names -join ", "
    $want = $expected -join ", "
    Say ($got -eq $want) "select '$sel' -> $got   (wanted: $want)"
}
Check-Selection "in/sub"       @("sub", "sub\c.txt", "sub\d.txt")
Check-Selection "in/sub/c.txt" @("c.txt")
Check-Selection "in/a.bin"     @("a.bin")

# A selection that names nothing must produce an empty object, not a drag that
# offers a file the user never chose.
$outn = Join-Path $w "seln"; New-Item -ItemType Directory -Force $outn | Out-Null
$rn = M @("dataobj", $c2, "in/nosuch", "-o", $outn, "-p", $PW)
Say ($rn.Code -ne 0) "select 'in/nosuch' : refused rather than offering something else (exit $($rn.Code))"

# And a PREFIX of a real name is not a match: "in/s" must not pull in "in/sub".
$outp = Join-Path $w "selp"; New-Item -ItemType Directory -Force $outp | Out-Null
$rp = M @("dataobj", $c2, "in/s", "-o", $outp, "-p", $PW)
Say ($rp.Code -ne 0) "select 'in/s' : a partial name matches nothing (exit $($rp.Code))"

Write-Host "`n=== bare single-file container (no tar header in the entry) ==="
# The one case where an entry's plaintext IS the file: header byte 17 is clear
# and the stream must not skip 512 bytes it would then never get back.
$c3 = Join-Path $w "bare.mrk"
$r = M @("encrypt", (Join-Path $in "b.bin"), "-o", $c3, "-p", $PW, "--store"); if ($r.Code) { throw "encrypt bare failed: $($r.Err)" }
$outb = Join-Path $w "out_bare"; New-Item -ItemType Directory -Force $outb | Out-Null
$r = M @("estream", $c3, "-o", $outb, "-p", $PW)
if ($r.Code -ne 0) {
    Say $false "bare : estream failed ($($r.Code)) $($r.Out)$($r.Err)"
} else {
    $a = [IO.File]::ReadAllBytes((Join-Path $in "b.bin"))
    $b = [IO.File]::ReadAllBytes((Join-Path $outb "es_0.bin"))
    $same = $a.Length -eq $b.Length
    if ($same) { for ($k = 0; $k -lt $a.Length; $k++) { if ($a[$k] -ne $b[$k]) { $same = $false; break } } }
    Say $same "bare : b.bin ($($a.Length) bytes) streams byte-identical"
}

Write-Host "`n=== a tampered entry must fail the stream, not leak plaintext ==="
# Flip one bit inside the payload run.  Nothing in the index changes, so the
# container still lists and still CONSTRUCTS streams - only the GCM tag knows,
# and the tag is at the end of the entry.
#
# The stored container's layout is fixed by its inputs, so the three regions of
# a.bin's entry can be named exactly.  The payload run starts at HDR_BYTES = 80.
# Entry 0 is the directory "in/": one 512-byte tar block plus a 16-byte tag, so
# 80..608.  Entry 1 is a.bin: 512 header + 1 content byte + 511 padding = 1024
# plaintext, ciphertext 608..1632, tag 1632..1648.  Therefore
#
#   1400 -> the PADDING.  This is the one that matters: a reader that stopped at
#           the last CONTENT byte would hand over a correct a.bin and report
#           success, having never asked GCM for a verdict.  ES_Read drains to the
#           end of the entry and verifies before reporting the end, so it fails.
#   1120 -> the single content byte
#    900 -> the tar header, which the stream skips but must still decrypt,
#           because GCM is sequential and skipping is not the same as not reading
foreach ($t in @(@(1400, "padding"), @(1120, "content"), @(900, "tar header"))) {
    $off = $t[0]; $what = $t[1]
    $c4 = Join-Path $w "tamper_$off.mrk"
    Copy-Item $c2 $c4 -Force
    $bytes = [IO.File]::ReadAllBytes($c4)
    $bytes[$off] = $bytes[$off] -bxor 0x40
    [IO.File]::WriteAllBytes($c4, $bytes)

    $outt = Join-Path $w "out_tamper_$off"; New-Item -ItemType Directory -Force $outt | Out-Null
    $r = M @("estream", $c4, "-o", $outt, "-p", $PW)
    # It must have got far enough to build streams - otherwise this is testing
    # idx_read's tag, not the stream's, and would pass for the wrong reason.
    $built = ($r.Out -split "`r?`n") | Where-Object { $_ -match '^\d+ \d+ ' }
    Say ($built.Count -gt 0) "tamper($what) : streams were still constructed ($($built.Count)) - the index is intact"
    Say ($r.Code -ne 0)      "tamper($what) : estream refuses to complete (exit $($r.Code))"

    # and the reference extraction must refuse it too, so the case is genuine
    $r2 = M @("decrypt", $c4, "-o", (Join-Path $w "ref_tamper_$off"), "-p", $PW)
    Say ($r2.Code -ne 0)     "tamper($what) : decrypt refuses it as well (exit $($r2.Code))"

    # the data object hands out the same streams, so it must fail the same way -
    # the descriptor renders fine either way, because names and sizes come from
    # the index and the index is untouched
    $outd = Join-Path $w "do_tamper_$off"; New-Item -ItemType Directory -Force $outd | Out-Null
    $r3 = M @("dataobj", $c4, "-o", $outd, "-p", $PW)
    Say ($r3.Code -ne 0)     "tamper($what) : the IDataObject refuses to complete too (exit $($r3.Code))"
}

Write-Host "`n=== zip containers, which drag out the OTHER way ==="
# docs/DRAG_OUT.md §7: a .mrk entry is streamed and decrypted as the target
# reads it, a zip entry is run to completion into memory first.  Everything
# above this line exercised the streaming half; `dataobj` takes a .zip and
# drives the identical object, so these are the same assertions against the
# other implementation of CFSTR_FILECONTENTS.
#
# The reference is `myrkr unzip`, for the reason `decrypt` is the reference
# above: it owes the drag nothing and it is what users already rely on.
$z = Join-Path $w "zips"
$py = python (Join-Path $PSScriptRoot "mkzip.py") $in $z $PW 2>&1
if ($LASTEXITCODE) { throw "mkzip.py failed: $py" }

function Check-Zip($label, $zip, $pass) {
    $ref = Join-Path $w "zref_$label"
    $out = Join-Path $w "zdo_$label"
    Remove-Item -Recurse -Force $ref, $out -EA SilentlyContinue
    New-Item -ItemType Directory -Force $out | Out-Null

    $cmd = @("unzip", $zip, "-o", $ref)
    if ($pass) { $cmd += @("-p", $PW) }
    $r = M $cmd
    if ($r.Code -ne 0) { Say $false "$label : unzip failed ($($r.Code)) $($r.Err)"; return }

    $cmd = @("dataobj", $zip, "-o", $out)
    if ($pass) { $cmd += @("-p", $PW) }
    $r = M $cmd
    if ($r.Code -ne 0) { Say $false "$label/dataobj : failed ($($r.Code)) $($r.Out)$($r.Err)"; return }

    $rows = @()
    foreach ($line in ($r.Out -split "`r?`n")) {
        if ($line -match '^(\d+) (\d+) (.+)$') {
            $rows += [pscustomobject]@{ I = [int]$Matches[1]; Size = [int64]$Matches[2]; Name = $Matches[3] }
        }
    }
    if ($rows.Count -eq 0) { Say $false "$label/dataobj : no descriptor rows"; return }

    foreach ($row in $rows) {
        $refPath = Join-Path $ref $row.Name
        $got     = Join-Path $out ("es_{0}.bin" -f $row.I)
        if (-not (Test-Path $refPath)) { Say $false "$label : $($row.Name) is offered but was not extracted"; continue }
        if (Test-Path $refPath -PathType Container) {
            # A zip's folder rows are SYNTHESISED by zidx_parents - there is no
            # central-directory header behind them at all - so zs_create has to
            # answer without looking one up.  Failing here would abort the copy
            # of every file underneath.
            Say ($row.Size -eq 0) "$label : $($row.Name) is a folder, descriptor size 0"
            Say ((Test-Path $got) -and ((Get-Item $got).Length -eq 0)) `
                "$label : $($row.Name) folder stream yields no bytes without a CD lookup"
            continue
        }
        if (-not (Test-Path $got)) { Say $false "$label : $($row.Name) produced no contents"; continue }
        $a = [IO.File]::ReadAllBytes($refPath)
        $b = [IO.File]::ReadAllBytes($got)
        Say ($row.Size -eq $a.Length) "$label : $($row.Name) descriptor says $($row.Size), file is $($a.Length)"
        $same = $a.Length -eq $b.Length
        if ($same) { for ($k = 0; $k -lt $a.Length; $k++) { if ($a[$k] -ne $b[$k]) { $same = $false; break } } }
        Say $same "$label : $($row.Name) contents byte-identical against myrkr unzip"
    }

    $want = @(Get-ChildItem -Recurse $ref | ForEach-Object { $_.FullName.Substring($ref.Length + 1) }) | Sort-Object
    $have = @($rows | ForEach-Object { $_.Name }) | Sort-Object
    $missing = @(Compare-Object $want $have | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject })
    Say ($missing.Count -eq 0) "$label : every extracted path is offered ($($have.Count) items; missing: $($missing -join ', '))"
}

# One per output path in extract_zip_entry: the whole-buffer inflate, the
# chunked AES-CTR stream, and the unencrypted case.
Check-Zip "aes_deflate" (Join-Path $z "aes_deflate.zip") $true
Check-Zip "aes_store"   (Join-Path $z "aes_store.zip")   $true
# The unencrypted archive still takes -p: the verb requires one, and an
# unencrypted entry never looks at it.
Check-Zip "plain"       (Join-Path $z "plain.zip")       $true

# A selection names one entry here too, and the naming rule is do_add_tree's -
# the same code both kinds of container go through.
$zsel = Join-Path $w "zsel"
Remove-Item -Recurse -Force $zsel -EA SilentlyContinue
New-Item -ItemType Directory -Force $zsel | Out-Null
$r = M @("dataobj", (Join-Path $z "aes_deflate.zip"), "sub", "-o", $zsel, "-p", $PW)
$znames = @()
foreach ($line in ($r.Out -split "`r?`n")) { if ($line -match '^(\d+) (\d+) (.+)$') { $znames += $Matches[3] } }
Say (($znames -join ", ") -eq "sub, sub\c.txt, sub\d.txt") `
    "zip select 'sub' -> $($znames -join ', ')"

# The dedup that ordinals used to do.  Every zip entry carries ordinal 0, so a
# match on ordinal would have called every row after the first a duplicate of
# the first and dragged out exactly ONE file - a copy that loses everything and
# reports success.  DI_slot is what stops it; this is the assertion that it does.
$zall = Join-Path $w "zall"
Remove-Item -Recurse -Force $zall -EA SilentlyContinue
New-Item -ItemType Directory -Force $zall | Out-Null
$r = M @("dataobj", (Join-Path $z "aes_deflate.zip"), "-o", $zall, "-p", $PW)
$n = @(($r.Out -split "`r?`n") | Where-Object { $_ -match '^\d+ \d+ ' }).Count
Say ($n -ge 5) "zip : all $n rows are offered, not collapsed to one by a shared ordinal"

Write-Host "`n=== a tampered zip entry must fail GetData ==="
# The tag is checked before or independently of any byte reaching the shell -
# HMAC-then-decrypt on the deflate path, decrypt-then-verify-into-a-buffer on
# the stored one - so a flipped bit has to come out as a refusal, not as a file.
# The last 4 KiB is inside the entry data of the largest entry either way.
foreach ($zt in @("aes_deflate", "aes_store")) {
    $src = Join-Path $z "$zt.zip"
    $bad = Join-Path $w "tamper_$zt.zip"
    Copy-Item $src $bad -Force
    $bytes = [IO.File]::ReadAllBytes($bad)
    $off = [int]($bytes.Length / 2)
    $bytes[$off] = $bytes[$off] -bxor 0x40
    [IO.File]::WriteAllBytes($bad, $bytes)

    $outz = Join-Path $w "do_tamper_$zt"; New-Item -ItemType Directory -Force $outz | Out-Null
    $r = M @("dataobj", $bad, "-o", $outz, "-p", $PW)
    Say ($r.Code -ne 0) "tamper($zt) : the IDataObject refuses to complete (exit $($r.Code))"
    $r2 = M @("unzip", $bad, "-o", (Join-Path $w "zref_tamper_$zt"), "-p", $PW)
    Say ($r2.Code -ne 0) "tamper($zt) : unzip refuses it as well, so the case is genuine (exit $($r2.Code))"
}

Write-Host ""
Write-Host "=== Restore: shipping build ==="
# "strict release", not "strict": release is what normalises the build
# timestamps, so bin\ comes back hashing to bin\SHA256SUMS.txt instead of merely
# being correct.  Without that, comparing an installed file against bin\ after
# running this reports a mismatch that is only timestamps - which cost a real
# diagnosis once already.
cmd /c "`"$vc`" >nul 2>&1 && `"$root\build.cmd`" strict release" | Out-Null
if ($LASTEXITCODE) { Write-Host "  FAIL: could not restore the release build"; exit 1 }
# Assert it, do not assume it.  The marker is a WIDE string in the binary, so an
# ASCII search finds nothing and reports a testio build as clean - which is
# exactly the wrong way round for a check whose whole job is to catch one.
$hay = [IO.File]::ReadAllBytes($exe)
$nee = [Text.Encoding]::Unicode.GetBytes("MYRKR_TEST_IO_BUILD")
$found = $false
for ($i = 0; $i -le $hay.Length - $nee.Length -and -not $found; $i++) {
    if ($hay[$i] -ne $nee[0]) { continue }
    $hit = $true
    for ($j = 1; $j -lt $nee.Length; $j++) { if ($hay[$i+$j] -ne $nee[$j]) { $hit = $false; break } }
    if ($hit) { $found = $true }
}
if ($found) { Write-Host "  FAIL: bin\myrkr.exe still carries MYRKR_TEST_IO_BUILD"; exit 1 }
Write-Host "  bin\myrkr.exe is a release build - ok"

Write-Host ""
if ($fail) { Write-Host "estreamtest: $fail FAILURE(S)"; exit 1 }
Write-Host "estreamtest: all checks passed"
exit 0
