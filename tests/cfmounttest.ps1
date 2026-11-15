# End-to-end verification for user-mode Windows Cloud Files drive mounting
# (src/cfmount.asm + ID_MOUNTDRV=176 in src/gui.asm):
#   1. Crash-recovery startup sweep (cfmount_sweep_stale) reaps unlocked orphan
#      sync-root folders and unmaps orphaned session drive letters.
#   2. VeraCrypt (.hc) auto-mounts on GUI open, serves exact file contents to
#      external processes, enforces read-only attributes, dehydrates placeholders
#      back to 0 on-disk bytes after close completion, and toggles unmount/remount
#      via command-bar button 176.
#   3. Native Myrkr (.mrk) mounts via command-bar button 176, serves compressed
#      and stored entries with SHA-256 parity, and fails closed with an I/O/CRC
#      error (0 unauthenticated plaintext bytes) if an entry's ciphertext is
#      tampered with.
# Requires build dbg (MYRKR_DBG_NOSECDESK=1); touches only its own child processes.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$exe  = Join-Path $root 'bin\myrkr.exe'
$work = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-cfmount-' + [guid]::NewGuid())
$mountsBase = Join-Path $env:LOCALAPPDATA 'Myrkr\Mounts'
$oldNoSd = $env:MYRKR_DBG_NOSECDESK
$procs = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$orphanDrv = $null
$orphanDir = $null

Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class CfMountGui {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
  [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern IntPtr Text(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int idx);
  [DllImport("kernel32.dll")] public static extern uint GetLogicalDrives();
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool DefineDosDeviceW(uint flags, string devName, string targetPath);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern uint GetCompressedFileSizeW(string fileName, out uint high);

  public static long OnDiskBytes(string path) {
    uint hi = 0;
    uint lo = GetCompressedFileSizeW(path, out hi);
    if (lo == 0xFFFFFFFFu && Marshal.GetLastWin32Error() != 0) return -1;
    return ((long)hi << 32) | lo;
  }
  public static IntPtr Find(uint pid, string cls) {
    IntPtr found = IntPtr.Zero;
    EnumWindows(delegate(IntPtr h, IntPtr unused) {
      uint owner; GetWindowThreadProcessId(h, out owner);
      if (owner != pid || !IsWindowVisible(h)) return true;
      var s = new StringBuilder(256); GetClassName(h, s, 256);
      if (s.ToString() == cls) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string Title(IntPtr h) {
    var s = new StringBuilder(512); GetWindowText(h, s, 512); return s.ToString();
  }
  public static IntPtr Child(IntPtr parent, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, delegate(IntPtr h, IntPtr unused) {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@

function Start-Myrkr([string[]]$argList) {
    if ($argList.Count -gt 0) {
        $proc = Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList $argList -PassThru
    } else {
        $proc = Start-Process -WindowStyle Hidden -FilePath $exe -PassThru
    }
    $procs.Add($proc)
    return $proc
}

function Wait-Win($proc, [string]$cls) {
    for ($i = 0; $i -lt 150; $i++) {
        if ($proc.HasExited) { throw "Myrkr exited unexpectedly with code $($proc.ExitCode)" }
        $h = [CfMountGui]::Find([uint32]$proc.Id, $cls)
        if ($h -ne [IntPtr]::Zero) { return $h }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for window class $cls"
}

function Unlock-Prompt($proc, [string]$pw) {
    $prompt = Wait-Win $proc 'myrkr_secdesk'
    $pwBox = [CfMountGui]::GetDlgItem($prompt, 156)
    [void][CfMountGui]::Text($pwBox, 0x000C, [IntPtr]::Zero, $pw)
    $wparamChange = [IntPtr]((0x0300 -shl 16) -bor 156)
    [void][CfMountGui]::SendMessageW($prompt, 0x0111, $wparamChange, $pwBox)
    [void][CfMountGui]::PostMessageW($prompt, 0x0111, [IntPtr]104, [IntPtr]::Zero)
}

function Run-Cli([string[]]$cliArgs) {
    $quoted = ($cliArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $out = cmd /c "`"$exe`" $quoted 2>&1"
    return [pscustomobject]@{ rc = $LASTEXITCODE; out = ($out | Out-String) }
}

function Pick-FreeDriveBottomUp {
    $mask = [CfMountGui]::GetLogicalDrives()
    for ($c = [int][char]'D'; $c -le [int][char]'Z'; $c++) {
        $bit = 1 -shl ($c - [int][char]'A')
        if (($mask -band $bit) -eq 0) { return "$([char]$c):" }
    }
    throw "No free drive letter available between D: and Z:"
}

try {
    [void](New-Item -ItemType Directory -Path $work -Force)
    $env:MYRKR_DBG_NOSECDESK = '1'
    $psExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }

    # -------------------------------------------------------------------------
    # 1. Crash-recovery startup sweep (cfmount_sweep_stale)
    # -------------------------------------------------------------------------
    [void](New-Item -ItemType Directory -Path $mountsBase -Force)
    $orphanId = 'deadbeef' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $orphanDir = Join-Path $mountsBase $orphanId
    [void](New-Item -ItemType Directory -Path $orphanDir -Force)
    $orphanFile = Join-Path $orphanDir 'leftover.bin'
    [IO.File]::WriteAllBytes($orphanFile, [Text.Encoding]::UTF8.GetBytes('sensitive-cached-bytes'))
    [IO.File]::SetAttributes($orphanFile, [IO.FileAttributes]::ReadOnly)
    $orphanDrv = Pick-FreeDriveBottomUp
    if (-not [CfMountGui]::DefineDosDeviceW(0, $orphanDrv, $orphanDir)) {
        throw "Failed to map synthetic orphan drive $orphanDrv -> $orphanDir"
    }

    $pSweep = Start-Myrkr @()
    # Empty window is created hidden unless shown or args given; wait for window handle
    for ($i = 0; $i -lt 100; $i++) {
        $pSweep.Refresh()
        if ($pSweep.MainWindowHandle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 100
    }
    $sweepHwnd = $pSweep.MainWindowHandle
    if ($sweepHwnd -eq [IntPtr]::Zero) { throw "Empty Myrkr window did not initialise" }
    if (Test-Path -LiteralPath $orphanDir) {
        throw "cfmount_sweep_stale did not remove unlocked orphan directory $orphanDir"
    }
    if (Test-Path -LiteralPath "$orphanDrv\") {
        throw "cfmount_sweep_stale did not unmap orphaned session drive $orphanDrv"
    }
    $orphanDrv = $null
    $orphanDir = $null
    [void][CfMountGui]::PostMessageW($sweepHwnd, 0x0111, [IntPtr]107, [IntPtr]::Zero)
    [void]$pSweep.WaitForExit(5000)
    'PASS: cfmount_sweep_stale wipes unlocked orphan sync roots and unmaps dead session drives'

    # -------------------------------------------------------------------------
    # 2. VeraCrypt (.hc) auto-mount, child-PID hydration + close dehydration,
    #    read-only enforcement, and WM_COMMAND 176 unmount/remount toggle
    # -------------------------------------------------------------------------
    $hc = Join-Path $work 'mount_vc.hc'
    $pyVc = @"
import os, sys, hashlib
sys.path.insert(0, r'$($PSScriptRoot)')
import tcvctest as tc
big = (b'VeraCrypt-CloudFiles-Hydration-Line-0123456789ABCDEF\n' * 1600)
fs = tc.build_fat_image(16, {
    'big.txt': big,
    'sub': {'note.txt': b'Nested read-only file via Cloud Files.\n'},
})
vol = tc.build_tcvc_volume(fs, b'vcpass', [], is_vera=True, kdf_alg='sha512')
with open(r'$hc', 'wb') as f:
    f.write(vol)
print(hashlib.sha256(big).hexdigest().upper())
"@
    $expectedVcBigHash = (& python -c $pyVc).Trim()
    if ($LASTEXITCODE -ne 0 -or $expectedVcBigHash.Length -ne 64) {
        throw "Failed to build mount_vc.hc fixture"
    }

    $beforeDirs = @()
    if (Test-Path -LiteralPath $mountsBase) {
        $beforeDirs = @(Get-ChildItem -LiteralPath $mountsBase -Directory | Select-Object -ExpandProperty FullName)
    }

    $pVc = Start-Myrkr @($hc)
    Unlock-Prompt $pVc 'vcpass'
    $mainVc = Wait-Win $pVc 'myrkr_window'
    if (([CfMountGui]::GetWindowLongW($mainVc, -20) -band 0x00000008) -ne 0) {
        throw "myrkr_window must NOT retain WS_EX_TOPMOST after initial front placement"
    }
    $statusCtlVc = [CfMountGui]::Child($mainVc, 196)
    $drvLetterVc = $null
    for ($i = 0; $i -lt 100; $i++) {
        $st = [CfMountGui]::Title($statusCtlVc)
        if ($st -match '([D-Z]):\\') { $drvLetterVc = $Matches[1]; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $drvLetterVc) {
        throw "VeraCrypt container did not auto-mount a drive letter (status='$([CfMountGui]::Title($statusCtlVc))')"
    }
    $drvRootVc = "${drvLetterVc}:\"
    $syncDirVc = @(Get-ChildItem -LiteralPath $mountsBase -Directory |
                   Where-Object { $_.FullName -notin $beforeDirs } |
                   Select-Object -ExpandProperty FullName)[0]
    if (-not $syncDirVc) { throw "Could not locate active sync-root directory under $mountsBase" }
    if (([IO.File]::GetAttributes($mountsBase) -band [IO.FileAttributes]::Encrypted) -ne 0) {
        throw "$mountsBase must NOT carry FILE_ATTRIBUTE_ENCRYPTED (triggers Windows EFS tray prompt)"
    }
    if (([IO.File]::GetAttributes($syncDirVc) -band [IO.FileAttributes]::Encrypted) -ne 0) {
        throw "$syncDirVc must NOT carry FILE_ATTRIBUTE_ENCRYPTED (triggers Windows EFS tray prompt)"
    }

    # Verify recursive directory enumeration (FindFirstFileW / IRP_MJ_DIRECTORY_CONTROL)
    # and real Windows Shell namespace enumeration complete fast without hanging
    $enumScript = @"
`$ErrorActionPreference = 'Stop'
`$entries = @(Get-ChildItem -LiteralPath '${drvRootVc}' -Recurse -Force | ForEach-Object { `$_.Name })
if (`$entries -notcontains 'big.txt' -or `$entries -notcontains 'sub' -or `$entries -notcontains 'note.txt') {
    throw "Directory enumeration missing expected entries: `$(`$entries -join ',')"
}
`$sh = New-Object -ComObject Shell.Application
`$nsRoot = `$sh.NameSpace('${drvRootVc}')
if (`$null -eq `$nsRoot) { throw "Shell.Application.NameSpace('${drvRootVc}') returned null" }
`$rootItems = @(`$nsRoot.Items())
if (`$rootItems.Count -lt 2) { throw "Expected >=2 Shell items in root, got `$(`$rootItems.Count)" }
foreach (`$it in `$rootItems) { [void]`$nsRoot.GetDetailsOf(`$it, 0); [void]`$nsRoot.GetDetailsOf(`$it, 1) }
`$nsSub = `$sh.NameSpace('${drvRootVc}sub')
if (`$null -eq `$nsSub -or @(`$nsSub.Items()).Count -ne 1) { throw "Shell subfolder enumeration failed" }
Write-Output 'ENUM_OK'
"@
    $encEnum = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($enumScript))
    $psiEnum = [System.Diagnostics.ProcessStartInfo]::new($psExe, "-NoProfile -EncodedCommand $encEnum")
    $psiEnum.CreateNoWindow = $true
    $psiEnum.UseShellExecute = $false
    $psiEnum.RedirectStandardOutput = $true
    $psiEnum.RedirectStandardError = $true
    $enumProc = [System.Diagnostics.Process]::Start($psiEnum)
    $procs.Add($enumProc)
    $enumOutTask = $enumProc.StandardOutput.ReadToEndAsync()
    $enumErrTask = $enumProc.StandardError.ReadToEndAsync()
    if (-not $enumProc.WaitForExit(10000)) {
        throw "Directory / Windows Shell enumeration on $drvRootVc HUNG (>10s)!"
    }
    $enumProc.WaitForExit()
    $enumOut = $enumOutTask.Result
    $enumErr = $enumErrTask.Result
    if ($enumProc.ExitCode -ne 0 -or $enumOut -notmatch 'ENUM_OK') {
        throw "Directory / Windows Shell enumeration failed (rc=$($enumProc.ExitCode)): $enumOut $enumErr"
    }

    # Before first content read, placeholder must occupy 0 on-disk bytes
    $phBigPath = Join-Path $syncDirVc 'big.txt'
    $preDisk = [CfMountGui]::OnDiskBytes($phBigPath)
    if ($preDisk -ne 0) {
        throw "Expected unhydrated placeholder big.txt OnDiskBytes == 0, got $preDisk"
    }

    # Read from an external child process so cldflt.sys delivers NOTIFY_FILE_CLOSE_COMPLETION
    # when the child closes its handle, and verify write attempts are denied.
    $childScript = @"
`$ErrorActionPreference = 'Stop'
`$h = (Get-FileHash -LiteralPath '${drvRootVc}big.txt' -Algorithm SHA256).Hash
`$n = [IO.File]::ReadAllText('${drvRootVc}sub\note.txt')
if (`$n -ne "Nested read-only file via Cloud Files.`n") { throw "Nested content mismatch" }
`$wDenied = `$false
try { [IO.File]::WriteAllText('${drvRootVc}big.txt', 'overwrite') } catch { `$wDenied = `$true }
if (-not `$wDenied) { throw "Write to read-only mounted file unexpectedly succeeded!" }
Write-Output `$h
"@
    $encChild = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $childOut = (& $psExe -NoProfile -EncodedCommand $encChild 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "External reader failed against $drvRootVc : $childOut" }
    if ($childOut -ne $expectedVcBigHash) {
        throw "Mounted big.txt SHA-256 mismatch: expected $expectedVcBigHash, got $childOut"
    }

    # Poll for close-completion placeholder dehydration back to 0 on-disk bytes
    $dehydrated = $false
    for ($i = 0; $i -lt 50; $i++) {
        if ([CfMountGui]::OnDiskBytes($phBigPath) -eq 0) { $dehydrated = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $dehydrated) {
        throw "Placeholder big.txt did not dehydrate back to 0 bytes after handle close (got $([CfMountGui]::OnDiskBytes($phBigPath)))"
    }
    'PASS: VeraCrypt auto-mount serves verified plaintext, blocks writes, and dehydrates back to 0 bytes on close'

    # Toggle unmount via ID_MOUNTDRV (176)
    [void][CfMountGui]::SendMessageW($mainVc, 0x0111, [IntPtr]176, [IntPtr]::Zero)
    if (Test-Path -LiteralPath $drvRootVc) {
        throw "Drive $drvRootVc still exists after clicking Unmount (176)"
    }
    if (Test-Path -LiteralPath $syncDirVc) {
        throw "Sync-root directory $syncDirVc was not wiped/removed on unmount"
    }

    # Toggle re-mount via ID_MOUNTDRV (176) (MYRKR_DBG_NOSECDESK=1 suppresses Explorer window)
    [void][CfMountGui]::SendMessageW($mainVc, 0x0111, [IntPtr]176, [IntPtr]::Zero)
    $stRemount = [CfMountGui]::Title($statusCtlVc)
    if ($stRemount -notmatch '([D-Z]):\\') {
        throw "Clicking Mount (176) did not re-mount container (status='$stRemount')"
    }
    $drvRootVc2 = "$($Matches[1]):\"
    if ((Get-FileHash -LiteralPath "${drvRootVc2}big.txt" -Algorithm SHA256).Hash -ne $expectedVcBigHash) {
        throw "Re-mounted drive $drvRootVc2 big.txt SHA-256 mismatch"
    }
    [void][CfMountGui]::PostMessageW($mainVc, 0x0111, [IntPtr]107, [IntPtr]::Zero)
    if (-not $pVc.WaitForExit(5000)) { throw "VC Myrkr window did not exit cleanly" }
    if (Test-Path -LiteralPath $drvRootVc2) {
        throw "Re-mounted drive $drvRootVc2 remained after window exit"
    }
    'PASS: Command-bar button 176 cleanly unmounts and re-mounts TC/VC volumes'

    # -------------------------------------------------------------------------
    # 3. Native .mrk manual mount + compressed readback + fail-closed tamper check
    # -------------------------------------------------------------------------
    $mrkPass = 'Mount-Mrk-Strong#99'
    $srcDir = Join-Path $work 'mrk_src'
    [void](New-Item -ItemType Directory -Path (Join-Path $srcDir 'nested') -Force)
    $mrkPayload = [Text.Encoding]::UTF8.GetBytes(('Authenticated native Myrkr Cloud Files stream line! ' * 2500))
    $mrkFileA = Join-Path $srcDir 'payload.txt'
    $mrkFileB = Join-Path $srcDir 'nested\small.bin'
    [IO.File]::WriteAllBytes($mrkFileA, $mrkPayload)
    [IO.File]::WriteAllBytes($mrkFileB, [byte[]](0..255))
    $expectedHashA = (Get-FileHash -LiteralPath $mrkFileA -Algorithm SHA256).Hash
    $expectedHashB = (Get-FileHash -LiteralPath $mrkFileB -Algorithm SHA256).Hash

    $goodMrk = Join-Path $work 'good.mrk'
    $encRes = Run-Cli @('encrypt', $srcDir, '-o', $goodMrk, '-p', $mrkPass, '--compress', '-m', '16', '-t', '1')
    if ($encRes.rc -ne 0) { throw "Failed to create good.mrk ($($encRes.rc)): $($encRes.out)" }

    $pMrk = Start-Myrkr @($goodMrk)
    Unlock-Prompt $pMrk $mrkPass
    $mainMrk = Wait-Win $pMrk 'myrkr_window'
    $mntBtnMrk = [CfMountGui]::Child($mainMrk, 176)
    if (-not [CfMountGui]::IsWindowEnabled($mntBtnMrk)) {
        throw "Mount drive button (176) should be enabled when browsing .mrk container"
    }
    # .mrk does NOT auto-mount on open; mount explicitly via ID_MOUNTDRV (176)
    $statusMrk = [CfMountGui]::Child($mainMrk, 196)
    if ([CfMountGui]::Title($statusMrk) -match '[D-Z]:\\') {
        throw ".mrk container unexpectedly auto-mounted before clicking button 176"
    }
    [void][CfMountGui]::SendMessageW($mainMrk, 0x0111, [IntPtr]176, [IntPtr]::Zero)
    $stMrkMnt = [CfMountGui]::Title($statusMrk)
    if ($stMrkMnt -notmatch '([D-Z]):\\') {
        throw "Clicking button 176 on .mrk container did not mount a drive (status='$stMrkMnt')"
    }
    $mrkDrv = "$($Matches[1]):\"
    $mountedA = Join-Path $mrkDrv 'mrk_src\payload.txt'
    $mountedB = Join-Path $mrkDrv 'mrk_src\nested\small.bin'
    if ((Get-FileHash -LiteralPath $mountedA -Algorithm SHA256).Hash -ne $expectedHashA) {
        throw "Mounted .mrk payload.txt SHA-256 mismatch"
    }
    if ((Get-FileHash -LiteralPath $mountedB -Algorithm SHA256).Hash -ne $expectedHashB) {
        throw "Mounted .mrk nested/small.bin SHA-256 mismatch"
    }
    [void][CfMountGui]::PostMessageW($mainMrk, 0x0111, [IntPtr]107, [IntPtr]::Zero)
    if (-not $pMrk.WaitForExit(5000)) { throw ".mrk Myrkr window did not exit cleanly" }
    if (Test-Path -LiteralPath $mrkDrv) {
        throw ".mrk mounted drive $mrkDrv remained after window exit"
    }
    'PASS: Native .mrk container mounts on demand, serves compressed entries, and unmounts on exit'

    # Tampered .mrk entry test: create stored archive folder so payload sits
    # cleanly between header+tar (offset ~1136) and trailing index, flip 1 byte in
    # entry ciphertext, mount, and verify ReadAllBytes throws an I/O error with
    # zero unauthenticated plaintext leaked!
    $tamperDir = Join-Path $work 'tamper_dir'
    [void](New-Item -ItemType Directory -Path $tamperDir -Force)
    $tamperSrc = Join-Path $tamperDir 'tamper_payload.bin'
    $rng = [Random]::new(424242)
    $rawBytes = [byte[]]::new(65536)
    $rng.NextBytes($rawBytes)
    [IO.File]::WriteAllBytes($tamperSrc, $rawBytes)
    $tamperMrk = Join-Path $work 'tampered.mrk'
    $encTamper = Run-Cli @('encrypt', $tamperDir, '-o', $tamperMrk, '-p', $mrkPass, '--store', '-m', '16', '-t', '1')
    if ($encTamper.rc -ne 0) { throw "Failed to create tampered.mrk fixture ($($encTamper.rc))" }

    $mrkBytes = [IO.File]::ReadAllBytes($tamperMrk)
    $flipOff = 4096
    $mrkBytes[$flipOff] = $mrkBytes[$flipOff] -bxor 0x5A
    [IO.File]::WriteAllBytes($tamperMrk, $mrkBytes)

    $pBad = Start-Myrkr @($tamperMrk)
    Unlock-Prompt $pBad $mrkPass
    $mainBad = Wait-Win $pBad 'myrkr_window'
    [void][CfMountGui]::SendMessageW($mainBad, 0x0111, [IntPtr]176, [IntPtr]::Zero)
    $stBad = [CfMountGui]::Title([CfMountGui]::Child($mainBad, 196))
    if ($stBad -notmatch '([D-Z]):\\') {
        throw "Failed to mount tampered.mrk index (status='$stBad')"
    }
    $badDrv = "$($Matches[1]):\"
    $tamperedReadFailed = $false
    try {
        $leaked = [IO.File]::ReadAllBytes((Join-Path $badDrv 'tamper_dir\tamper_payload.bin'))
        throw "SECURITY FAILURE: ReadAllBytes succeeded on tampered .mrk entry ($($leaked.Length) bytes returned)!"
    } catch {
        if ($_.Exception.Message -like 'SECURITY FAILURE*') { throw }
        $tamperedReadFailed = $true
    }
    if (-not $tamperedReadFailed) {
        throw "Tampered .mrk entry did not raise an I/O error"
    }
    [void][CfMountGui]::PostMessageW($mainBad, 0x0111, [IntPtr]107, [IntPtr]::Zero)
    [void]$pBad.WaitForExit(5000)
    'PASS: Tampered .mrk entry fails closed before hydration with zero unauthenticated plaintext leaked'

} finally {
    foreach ($pr in $procs) {
        if ($pr -and -not $pr.HasExited) {
            try { $pr.Kill(); $pr.WaitForExit() } catch {}
        }
    }
    if ($orphanDrv) {
        try { [void][CfMountGui]::DefineDosDeviceW(2, $orphanDrv, $null) } catch {}
    }
    if ($orphanDir -and (Test-Path -LiteralPath $orphanDir)) {
        try {
            Get-ChildItem -LiteralPath $orphanDir -Recurse -Force | ForEach-Object { $_.Attributes = 'Normal' }
            Remove-Item -LiteralPath $orphanDir -Recurse -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    if ($null -eq $oldNoSd) {
        Remove-Item Env:\MYRKR_DBG_NOSECDESK -ErrorAction SilentlyContinue
    } else {
        $env:MYRKR_DBG_NOSECDESK = $oldNoSd
    }
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
