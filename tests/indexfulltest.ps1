# The inventory-full refusal - the fix for the worst failure this project has
# had - reached with forty files instead of half a million.
#
# WHAT IT GUARDS. Reported against 1.0.50: a 587 GB folder of 76,286 files
# encrypted with no error into a container holding 16,780. The index has a fixed
# ceiling; idx_add hit it, set IDXF_TRUNCATED and RETURNED, and pack_node wrote
# the entry into the payload anyway. Sixty thousand files became ciphertext with
# nothing recording their offset, ordinal or name - unaddressable forever - and
# the encrypt said "packed ->" and exited 0.
#
# idx_add now fails the pack instead: g_packerr is sticky, every level of the
# walk checks it, and the caller discards the partial output. That control has
# been shipping since 1.0.51 and NOTHING HAS EVER EXERCISED IT, because reaching
# it honestly costs ~500,000 files (64 MiB of index at ~125 bytes an entry).
# manyfiles.ps1 proves the count comes back for 20,000; it cannot get near the
# ceiling itself.
#
# MYRKR_DBG_IDXMAX (test builds only) lowers the limit the WRITER applies, so
# the same code path is reached at forty files. It cannot lower what a READER
# will accept into g_idxbuf - idx_tail and idx_auth stay pinned to
# IDX_MAX_BYTES, because a knob that loosened those would be a buffer overflow
# with a switch on it. See idx_cap in pack.asm.
#
# This is the first step of phase C (docs/V5_WORK.md), which raises that ceiling
# for real: whatever C does at the boundary, the boundary has to be reachable in
# a test before it is moved.
#
# Mutation-checked (see MUTATIONS at the bottom).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root "bin\myrkr.exe"
$w    = Join-Path $env:TEMP "myrkr_indexfulltest"
$PW   = "Correct-Horse-Battery-9"
$CAP  = 1064          # the smallest MYRKR_DBG_IDXMAX honours: IDXE_FIXED + 1024
$N    = 40
$fail = 0

"building dbg (MYRKR_DBG_IDXMAX and encrypt on the command line need it)..."
$blog = cmd /c "$root\build.cmd dbg" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "FAIL build"; $blog | Select-Object -Last 15; exit 1 }

if (Test-Path $w) { [IO.Directory]::Delete($w, $true) }
New-Item -ItemType Directory -Path (Join-Path $w "in") | Out-Null
1..$N | ForEach-Object {
    [IO.File]::WriteAllText((Join-Path $w "in\a-reasonably-long-file-name-number-$_.txt"), "file $_")
}

function Run([string[]]$a) {
    $q = ($a | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $o = cmd /c "`"$exe`" $q 2>&1"
    return [pscustomobject]@{ rc = $LASTEXITCODE; out = (($o | Out-String) -replace "`r", "") }
}

# ---- 1. the whole point: it refuses, and produces nothing -------------------
$mrk = Join-Path $w "full.mrk"
$env:MYRKR_DBG_IDXMAX = "$CAP"
$r = Run @("encrypt", "$w\in", "-o", $mrk, "-p", $PW, "--store", "-m", "32", "-t", "1")
Remove-Item Env:\MYRKR_DBG_IDXMAX

if ($r.rc -eq 0) {
    "  FAIL an index that did not fit was packed anyway (exit 0) - this is the 1.0.50 bug"; $fail++
} else {
    "  ok   an inventory that will not fit fails the pack (exit $($r.rc))"
}
if ($r.out -notmatch "inventory is full") {
    "  FAIL the refusal did not say why: $($r.out)"; $fail++
} else { "  ok   and says which limit it hit" }

# The output must not exist. A container whose index is short is worse than no
# container: it looks complete, lists a subset, and the rest is unaddressable.
if (Test-Path $mrk) {
    "  FAIL a container was left behind by a failed pack"; $fail++
    $l = Run @("list", $mrk, "-p", $PW)
    "       it lists $(([regex]::Matches($l.out, '\.txt')).Count) of $N files"
} else { "  ok   and leaves no container behind" }

# ---- 2. and it is the CEILING doing it, not something else ------------------
# The same inputs, the same command, the default limit: everything fits and
# every file is listed. Without this the check above passes just as well
# against a build that refuses everything.
$ok = Join-Path $w "ok.mrk"
$r = Run @("encrypt", "$w\in", "-o", $ok, "-p", $PW, "--store", "-m", "32", "-t", "1")
if ($r.rc -ne 0) { "  FAIL the same inputs failed at the default limit: $($r.out)"; $fail++ }
else {
    $l = Run @("list", $ok, "-p", $PW)
    $listed = ([regex]::Matches($l.out, "a-reasonably-long-file-name-number-\d+\.txt")).Count
    if ($listed -ne $N) { "  FAIL the default limit listed $listed of $N"; $fail++ }
    else { "  ok   at the default limit all $N are packed and listed" }
}

# ---- 3. the knob cannot be turned into a way to refuse everything -----------
# A cap below one entry would make every pack fail, which looks exactly like
# the control working and would make check 1 pass for the wrong reason. idx_cap
# ignores anything under IDXE_FIXED + 1024.
$env:MYRKR_DBG_IDXMAX = "8"
$r = Run @("encrypt", "$w\in", "-o", (Join-Path $w "floor.mrk"), "-p", $PW, "--store", "-m", "32", "-t", "1")
Remove-Item Env:\MYRKR_DBG_IDXMAX
if ($r.rc -ne 0) { "  FAIL a nonsense cap was honoured and refused a valid pack"; $fail++ }
else { "  ok   a cap below one entry is ignored, not obeyed" }

# ---- 4. the knob does not reach the reader ---------------------------------
# A container that fits the DEFAULT limit must still open with a tiny cap set:
# the cap bounds what a writer builds, never what a reader accepts.
$env:MYRKR_DBG_IDXMAX = "$CAP"
$out = Join-Path $w "out"
$r = Run @("decrypt", $ok, "-o", $out, "-p", $PW)
Remove-Item Env:\MYRKR_DBG_IDXMAX
if ($r.rc -ne 0) { "  FAIL a tiny writer cap stopped a good container being READ: $($r.out)"; $fail++ }
elseif ((Get-ChildItem -Recurse -File "$out\in").Count -ne $N) {
    "  FAIL the read-back is short"; $fail++
} else { "  ok   and it does not bound what a reader will accept" }

# ---- 5. the buffer is not paid for by runs that never open a container ------
# It was 64 MiB of .data?, and a PE's uninitialised data is COMMITTED at load,
# not merely reserved - so every invocation charged it, `myrkr hash` included.
# It is heap-allocated on demand now (idx_buf_ensure), and this is the number
# that says so. Working set would NOT: the pages were never touched either way.
Add-Type @"
using System;using System.Runtime.InteropServices;
public class IFT {
  [StructLayout(LayoutKind.Sequential)] public struct PMC {
    public uint cb; public uint PageFaultCount; public UIntPtr PeakWorkingSetSize;
    public UIntPtr WorkingSetSize; public UIntPtr QuotaPeakPagedPoolUsage;
    public UIntPtr QuotaPagedPoolUsage; public UIntPtr QuotaPeakNonPagedPoolUsage;
    public UIntPtr QuotaNonPagedPoolUsage; public UIntPtr PagefileUsage;
    public UIntPtr PeakPagefileUsage; public UIntPtr PrivateUsage; }
  [DllImport("psapi.dll")] public static extern bool GetProcessMemoryInfo(IntPtr h, out PMC c, uint cb);
}
"@
$big = Join-Path $w "hashme.bin"
[IO.File]::WriteAllBytes($big, [byte[]]::new(64MB))
$hp = Start-Process $exe -ArgumentList "hash","`"$big`"" -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $w "h.txt")
$peak = 0
while (-not $hp.HasExited) {
    $c = New-Object IFT+PMC; $c.cb = [uint32][Runtime.InteropServices.Marshal]::SizeOf($c)
    if ([IFT]::GetProcessMemoryInfo($hp.Handle, [ref]$c, $c.cb)) {
        $pv = [uint64]$c.PrivateUsage; if ($pv -gt $peak) { $peak = $pv }
    }
}
$mb = [math]::Round($peak / 1MB, 1)
# 64 MiB is what the static buffer charged. Anything at or above it means the
# inventory is being committed by a command that never reads an inventory.
if ($mb -ge 64) {
    "  FAIL 'hash' commits $mb MB - the inventory buffer is charged to every run"; $fail++
} else {
    "  ok   'hash' commits $mb MB - no inventory buffer is charged to it"
}

# ---- 6. and a container commits what its index needs, not the ceiling ------
# The ceiling is 2047 MiB. It is RESERVED address space; only as much as the
# index actually reaches is committed. A 40-entry container needs a few
# kilobytes of it, so what shows up here is the megabyte granularity plus this
# fixture's Argon2 arena (-m 32) - not two gigabytes.
$lp = Start-Process $exe -ArgumentList "list","`"$ok`"","-p",$PW -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $w "l.txt")
$lpeak = 0
while (-not $lp.HasExited) {
    $c = New-Object IFT+PMC; $c.cb = [uint32][Runtime.InteropServices.Marshal]::SizeOf($c)
    try { if ([IFT]::GetProcessMemoryInfo($lp.Handle, [ref]$c, $c.cb)) {
        $pv = [uint64]$c.PrivateUsage; if ($pv -gt $lpeak) { $lpeak = $pv } } } catch {}
}
$lmb = [math]::Round($lpeak / 1MB, 1)
if ($lmb -ge 200) {
    "  FAIL listing a 40-entry container commits $lmb MB - the ceiling is being committed, not reserved"; $fail++
} else {
    "  ok   listing a 40-entry container commits $lmb MB, not the 2047 MiB ceiling"
}

""
"=== Restore: shipping build ==="
$blog = cmd /c "$root\build.cmd strict release" 2>&1
if (($blog -join "`n") -notmatch "BUILD OK") { "  FAIL could not restore the release build"; $fail++ }
else { "  bin\myrkr.exe is a release build - ok" }

if (Test-Path $w) { [IO.Directory]::Delete($w, $true) }

# =============================================================================
# MUTATIONS - applied, run, observed to fail, reverted.
#
#  1. THE 1.0.50 BUG, PUT BACK. idx_add (pack.asm): replace the two lines
#       prn     e_idx_full
#       mov     qword ptr [g_packerr], EXIT_UNSUPPORTED
#     with
#       or      qword ptr [g_idxflags], IDXF_TRUNCATED
#     which is what it did before 1.0.51.
#       -> "an inventory that did not fit was packed anyway (exit 0)" FAILS, and
#          "leaves no container behind" FAILS with the container present and
#          listing 11 of 40 files. That is the original disaster in miniature:
#          exit 0, a container that looks fine, and 29 files inside it that
#          nothing can address. It is the entire reason this file exists.
#
#  2. idx_cap: parse the environment but never store it (delete the
#     `mov [g_idxcap], r10`), so the cap is always IDX_MAX_BYTES.
#       -> checks 1 and its two companions FAIL: exit 0, no message, and a
#          container left behind. The ceiling is never reached, so the control
#          is never exercised - the state this file was written to end.
#
#     A FIRST ATTEMPT AT THIS MUTATION WAS WRONG and is recorded rather than
#     quietly replaced: jumping straight to `ic_have` skipped the
#     INITIALISATION as well as the environment read, leaving g_idxcap at zero
#     so every pack refused. Checks 2, 3 and 4 failed instead of check 1 - the
#     test still caught it, but for a reason the note would have misdescribed.
#
#  3. pack.asm: point g_idxptr back at a static .data? buffer instead of
#     allocating.
#       -> "'hash' commits N MB" FAILS at ~79 MB. Nothing else in the suite
#          moves: the buffer works identically either way, which is exactly why
#          the cost needed a number rather than an eye.
#
#  4. pack.asm, idx_buf_ensure: reserve AND commit the whole ceiling in one
#     VirtualAlloc (MEM_RESERVE or MEM_COMMIT), as mem_alloc does.
#       -> "listing a 40-entry container commits N MB" FAILS at over 2000 MB.
#          Everything else still passes - a fully committed reservation works
#          perfectly, it just charges two gigabytes to open a container holding
#          forty files.
# =============================================================================
if ($fail -gt 0) { "$fail FAILURE(S)"; exit 1 } else { "indexfulltest: all checks passed"; exit 0 }
