# The window takes at most MAX_ARGS (256) inputs and a bounded path length.
# Past either limit it must SAY so - never encrypt part of what was selected.
#
# Until 1.1.6 both limits were enforced in silence:
#   - gui_main stopped reading argv at 256 inputs, so the rest of a selection
#     was dropped (300 files dropped on the program icon, or sent with Send To,
#     opened a window holding 256) and so would a trailing "--to <dir>" have
#     been - the shell extension caps its menu at 64 files, so that half was
#     unreachable, but the loop no longer depends on it;
#   - each argv path was copied with wcopy, which truncates to the slot, so a
#     4,108-char file path became its 4,095-char folder - siblings included;
#   - a drop or a picker past the limit skipped the rest without a word.
# Shown failing against 1.1.5 with tools\compare.ps1.
#
# Needs a dbg build (MYRKR_DBG_NOSECDESK, WM_APP_DROPTEST, the map for globals);
# run.ps1 hosts it in Phase 2.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $PSScriptRoot 'lib\gui.psm1') -Force
Add-Type -AssemblyName System.Windows.Forms
$exe  = Join-Path $root 'bin\myrkr.exe'
$map  = Join-Path $root 'bin\myrkr.map'
$work = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-inputcap-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$fail = 0
function Check($ok, $what) { if ($ok) { "  ok   $what" } else { "  FAIL $what"; $script:fail++ } }

New-Item -ItemType Directory $work | Out-Null
$files = 1..300 | ForEach-Object { $p = Join-Path $work ('f{0:d3}.txt' -f $_); [IO.File]::WriteAllText($p, "file $_"); $p }
$dest = Join-Path $work 'dest'; New-Item -ItemType Directory $dest | Out-Null
$old = $env:MYRKR_DBG_NOSECDESK
$env:MYRKR_DBG_NOSECDESK = '1'

function Launch([string[]]$paths, [switch]$To) {
    $a = @($paths | ForEach-Object { '"' + $_ + '"' })
    if ($To) { $a += @('--to', '"' + $dest + '"') }
    Stop-Myrkr
    if ($a.Count) { return Start-Process $exe -ArgumentList $a -PassThru }
    return Start-Process $exe -PassThru
}
# The error box, or $null if none appears in $ms.
function ErrorBox($p, $ms = 8000) {
    $h = Wait-MyrkrWindow -Process $p -Class 'myrkr_mbox' -TimeoutMs $ms
    if ($h -eq [IntPtr]::Zero) { return $null }
    return [pscustomobject]@{ H = $h; Title = (Get-MyrkrTitle $h) }
}
function NoEncryption { @(Get-ChildItem $work -Recurse -File -Include '*.mrk', '*.zip').Count -eq 0 }

try {
    # ---- 1. 300 inputs from the shell: refused whole, said out loud ---------
    $p = Launch $files -To
    $b = ErrorBox $p
    Check ($b -and $b.Title -eq 'Myrkr - error') "300 inputs: an error, not a window holding 256 of them (got '$($b.Title)')"
    Check ((Read-MyrkrGlobal -Process $p -Map $map -Symbol g_argover) -eq 44) 'and it knows exactly 44 did not fit'
    Check ((Find-MyrkrWindow -Process $p -Class 'myrkr_window') -eq [IntPtr]::Zero) 'the main window is never shown'
    if ($b) { Send-MyrkrCommand -Window $b.H -Id 104 }
    Check ($p.WaitForExit(8000)) 'pressing OK ends it - nothing was started'
    Check (NoEncryption) 'and nothing was encrypted anywhere'

    # ---- 2. exactly 256: accepted, and --to still read --------------------
    $p = Launch $files[0..255] -To
    $b = ErrorBox $p 3000
    Check ($null -eq $b) "256 inputs: no error ($($b.Title))"
    Check ((Read-MyrkrGlobal -Process $p -Map $map -Symbol g_poscount -Size 8) -eq 256) 'all 256 are inputs'
    Check ((Read-MyrkrGlobal -Process $p -Map $map -Symbol g_have_dest) -eq 1) '--to after 256 inputs is still read'
    Stop-Myrkr

    # ---- 3. a path too long for its slot: refused, never truncated -----------
    $long = python -I -c @"
import os, sys
p = sys.argv[1]
while len(p) < 4095 - 210:
    p += '\\' + 'd' * 200
    os.makedirs('\\\\?\\' + p, exist_ok=True)
p += '\\' + 'e' * (4095 - len(p) - 1)
os.makedirs('\\\\?\\' + p, exist_ok=True)
open('\\\\?\\' + p + '\\picked.txt', 'w').write('x')
open('\\\\?\\' + p + '\\sibling.txt', 'w').write('x')
print(p + '\\picked.txt')
"@ (Join-Path $work 'deep')
    $p = Launch @($files[0], $long)
    $b = ErrorBox $p
    Check ($b -and $b.Title -eq 'Myrkr - error') "a $($long.Length)-char path: an error, not its folder in its place"
    Check ((Read-MyrkrGlobal -Process $p -Map $map -Symbol g_arglong) -eq 1) 'counted as too long'
    Check ((Find-MyrkrWindow -Process $p -Class 'myrkr_window') -eq [IntPtr]::Zero) 'the main window is never shown'
    Stop-Myrkr

    # ---- 4. a drop past the limit: what fits goes in, and it says so ---------
    $p = Launch @()
    $m = Wait-MyrkrWindow -Process $p -Class 'myrkr_window'
    Start-Sleep -Milliseconds 800
    $col = New-Object Collections.Specialized.StringCollection
    $files | ForEach-Object { [void]$col.Add($_) }
    [Windows.Forms.Clipboard]::SetFileDropList($col)
    [void][MyrkrGui.Native]::PostMessageW($m, 0x8003, [IntPtr]::Zero, [IntPtr]::Zero)   # WM_APP_DROPTEST
    $b = ErrorBox $p
    Check ($b -and $b.Title -eq 'Some items were not added') "a 300-file drop warns (got '$($b.Title)')"
    Check ((Read-MyrkrGlobal -Process $p -Map $map -Symbol g_poscount -Size 8) -eq 256) 'and keeps the 256 that fit'
    Stop-Myrkr

    # ---- 5. a drop within the limit says nothing -------------------------------
    $p = Launch @()
    $m = Wait-MyrkrWindow -Process $p -Class 'myrkr_window'
    Start-Sleep -Milliseconds 800
    $col = New-Object Collections.Specialized.StringCollection
    $files[0..9] | ForEach-Object { [void]$col.Add($_) }
    [Windows.Forms.Clipboard]::SetFileDropList($col)
    [void][MyrkrGui.Native]::PostMessageW($m, 0x8003, [IntPtr]::Zero, [IntPtr]::Zero)
    $b = ErrorBox $p 3000
    Check ($null -eq $b) "a 10-file drop: no warning ($($b.Title))"
    Check ((Read-MyrkrGlobal -Process $p -Map $map -Symbol g_poscount -Size 8) -eq 10) 'and all 10 are inputs'
    Stop-Myrkr
} finally {
    Stop-Myrkr
    if ($null -eq $old) { Remove-Item Env:\MYRKR_DBG_NOSECDESK -EA SilentlyContinue } else { $env:MYRKR_DBG_NOSECDESK = $old }
    if ((Split-Path $work -Leaf) -like 'myrkr-inputcap-*') {
        cmd /c "rmdir /s /q `"\\?\$work`"" 2>$null
    }
}
if ($fail) { "$fail FAILURE(S)"; exit 1 } else { 'inputcaptest: all checks passed'; exit 0 }
