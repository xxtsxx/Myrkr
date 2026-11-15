# End-to-end GUI verification for read-only TrueCrypt (.tc) / VeraCrypt (.hc)
# container browsing, keyfile prompt controls, read-only control disabling,
# status-bar cipher/KDF/FS metadata, Extract selected, and Extract all.
# Requires build dbg (MYRKR_DBG_NOSECDESK=1); touches only its own child process.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$exe  = Join-Path $root 'bin\myrkr.exe'
$work = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-tcvcgui-' + [guid]::NewGuid())
$p    = $null
$old  = $env:MYRKR_DBG_NOSECDESK

Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class TcVcGui {
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
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, IntPtr n, uint t, uint prot);
  [DllImport("kernel32.dll")] public static extern bool VirtualFreeEx(IntPtr h, IntPtr a, IntPtr n, uint t);
  [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, int n, out IntPtr written);
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
  public static void SetRowSelected(IntPtr hProc, IntPtr lv, int idx, bool sel) {
    IntPtr remote = VirtualAllocEx(hProc, IntPtr.Zero, (IntPtr)88, 0x3000, 4);
    if (remote == IntPtr.Zero) throw new Exception("VirtualAllocEx failed");
    try {
      byte[] item = new byte[88];
      BitConverter.GetBytes(sel ? 2u : 0u).CopyTo(item, 12); // state = LVIS_SELECTED
      BitConverter.GetBytes(2u).CopyTo(item, 16);            // stateMask = LVIS_SELECTED
      IntPtr written;
      if (!WriteProcessMemory(hProc, remote, item, 88, out written))
        throw new Exception("WriteProcessMemory failed");
      SendMessageW(lv, 0x102B, (IntPtr)idx, remote);         // LVM_SETITEMSTATE
    } finally {
      VirtualFreeEx(hProc, remote, IntPtr.Zero, 0x8000);
    }
  }
}
'@

function Wait-Window($class) {
    for ($i = 0; $i -lt 150; $i++) {
        if ($p.HasExited) { throw "Test process exited unexpectedly ($($p.ExitCode))" }
        $h = [TcVcGui]::Find([uint32]$p.Id, $class)
        if ($h -ne [IntPtr]::Zero) { return $h }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $class"
}

try {
    [void](New-Item -ItemType Directory -Path $work)
    $hc = Join-Path $work 'sample.hc'
    $pyCode = @"
import sys
sys.path.insert(0, r'$($PSScriptRoot)')
import tcvctest as tc
fs = tc.build_fat_image(12, {
    '`$RECYCLE.BIN': {'S-1-5-21': {'deleted.txt': b'must not appear\n'}},
    'System Volume Information': {'WPSettings.dat': b'must not appear\n'},
    'pagefile.sys': b'must not appear\n',
    'hello.txt': b'Hello from GUI VeraCrypt browse!\n',
    'docs': {'readme.txt': b'Nested folder extracted selectively.\n'},
})
vol = tc.build_tcvc_volume(fs, b'short', [], is_vera=True, kdf_alg='sha512')
with open(r'$hc', 'wb') as f:
    f.write(vol)
"@
    & python -c $pyCode
    if ($LASTEXITCODE -ne 0) { throw "Failed to generate fixture .hc" }
    $beforeHash = (Get-FileHash -LiteralPath $hc).Hash

    $env:MYRKR_DBG_NOSECDESK = '1'
    $p = Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList @($hc) -PassThru

    # 1. Verify TC/VC prompt exposes keyfile buttons and permits short password ('short')
    $prompt = Wait-Window 'myrkr_secdesk'
    foreach ($kfId in @(172, 173, 174)) {
        $btn = [TcVcGui]::GetDlgItem($prompt, $kfId)
        if ($btn -eq [IntPtr]::Zero) { throw "Missing TC/VC keyfile button id $kfId on prompt" }
    }
    if ([TcVcGui]::IsWindowEnabled([TcVcGui]::GetDlgItem($prompt, 174))) {
        throw "Clear keyfiles button (174) should start disabled when 0 keyfiles are staged"
    }
    $pwBox = [TcVcGui]::GetDlgItem($prompt, 156)
    [void][TcVcGui]::Text($pwBox, 0x000C, [IntPtr]::Zero, 'short')
    # Notify EN_CHANGE so prompt re-evaluates button enablement
    $wparamChange = [IntPtr]((0x0300 -shl 16) -bor 156)
    [void][TcVcGui]::SendMessageW($prompt, 0x0111, $wparamChange, $pwBox)
    $okBtn = [TcVcGui]::GetDlgItem($prompt, 104)
    if (-not [TcVcGui]::IsWindowEnabled($okBtn)) {
        throw "TC/VC prompt rejected short password ('short') under encryption policy floor"
    }
    'PASS: TC/VC prompt renders keyfile controls and allows non-policy password'

    [void][TcVcGui]::PostMessageW($prompt, 0x0111, [IntPtr]104, [IntPtr]::Zero)

    # 2. Wait for container browser window & verify read-only state + status line
    $main = Wait-Window 'myrkr_window'
    $lv = [TcVcGui]::Child($main, 109)
    for ($i = 0; $i -lt 100; $i++) {
        if ([TcVcGui]::SendMessageW($lv, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64() -ge 2) { break }
        Start-Sleep -Milliseconds 100
    }
    $rowCount = [TcVcGui]::SendMessageW($lv, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
    # Folders start collapsed by default: row 0 = docs (collapsed), row 1 = hello.txt
    if ($rowCount -ne 2) { throw "Expected 2 collapsed tree rows on open (docs, hello.txt), got $rowCount" }

    # Single-click the chevron gutter on row 0 ('docs', x=11, y=10) to expand it
    $chevPt = [IntPtr]((10 -shl 16) -bor 11)
    [void][TcVcGui]::PostMessageW($lv, 0x0201, [IntPtr]1, $chevPt)
    [void][TcVcGui]::PostMessageW($lv, 0x0202, [IntPtr]0, $chevPt)
    for ($i = 0; $i -lt 30; $i++) {
        if ([TcVcGui]::SendMessageW($lv, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64() -eq 3) { break }
        Start-Sleep -Milliseconds 50
    }
    $rowCountExp = [TcVcGui]::SendMessageW($lv, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
    if ($rowCountExp -ne 3) { throw "Clicking folder chevron did not expand 'docs' (expected 3 rows, got $rowCountExp)" }

    foreach ($disabledId in @(154, 155, 161)) {
        $ctl = [TcVcGui]::Child($main, $disabledId)
        if ([TcVcGui]::IsWindowEnabled($ctl)) {
            throw "Archive-mutation button $disabledId must be disabled in read-only TC/VC mode"
        }
    }
    if (-not [TcVcGui]::IsWindowEnabled([TcVcGui]::Child($main, 171))) {
        throw "Open TC/VC glyph button (171) should remain enabled"
    }
    if (-not [TcVcGui]::IsWindowEnabled([TcVcGui]::Child($main, 176))) {
        throw "Mount drive glyph button (176) should be enabled for open TC/VC volume"
    }
    $statusTxt = [TcVcGui]::Title([TcVcGui]::Child($main, 196))
    if ($statusTxt -notmatch '^VeraCrypt .* AES-256 .* SHA-512 .* FAT12 .* ([D-Z]):\\ .* Read-Only \(XTS\)$') {
        throw "Unexpected TC/VC status line (expected auto-mounted drive letter): '$statusTxt'"
    }
    $mntDrv = "$($Matches[1]):\"
    if ([IO.File]::ReadAllText((Join-Path $mntDrv 'hello.txt')) -ne "Hello from GUI VeraCrypt browse!`n") {
        throw "Mounted drive $mntDrv hello.txt content mismatch"
    }
    if ([TcVcGui]::Title([TcVcGui]::Child($main, 104)) -ne 'Extract all') {
        throw "Expected 'Extract all' on action button, got '$([TcVcGui]::Title([TcVcGui]::Child($main, 104)))'"
    }
    'PASS: TC/VC browser auto-mounts drive letter, disables Add/Delete, and shows XTS metadata'

    # 3. Select row 0 ('docs' folder), verify Left/Right arrow collapse & expand, then 'Extract selected'
    [TcVcGui]::SetRowSelected($p.Handle, $lv, 0, $true)
    [void][TcVcGui]::SendMessageW($lv, 0x0100, [IntPtr]0x25, [IntPtr]::Zero) # VK_LEFT collapses 'docs'
    if ([TcVcGui]::SendMessageW($lv, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64() -ne 2) {
        throw "VK_LEFT did not collapse 'docs' folder back to 2 rows"
    }
    [void][TcVcGui]::SendMessageW($lv, 0x0100, [IntPtr]0x27, [IntPtr]::Zero) # VK_RIGHT re-expands 'docs'
    if ([TcVcGui]::SendMessageW($lv, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64() -ne 3) {
        throw "VK_RIGHT did not re-expand 'docs' folder to 3 rows"
    }
    if ([TcVcGui]::Title([TcVcGui]::Child($main, 104)) -ne 'Extract selected') {
        throw "Selecting row 0 did not switch action button to 'Extract selected'"
    }
    [void][TcVcGui]::PostMessageW($main, 0x0111, [IntPtr]104, [IntPtr]::Zero)

    $outDir    = Join-Path $work 'sample'
    $nestedOut = Join-Path $outDir 'docs\readme.txt'
    $rootOut   = Join-Path $outDir 'hello.txt'
    for ($i = 0; $i -lt 100; $i++) {
        if ((Test-Path -LiteralPath $nestedOut) -and ([TcVcGui]::Title([TcVcGui]::Child($main, 107)) -eq 'Close')) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $nestedOut)) { throw "Extract selected did not produce $nestedOut" }
    if (Test-Path -LiteralPath $rootOut) { throw "Extract selected unexpectedly extracted unselected $rootOut" }
    if ([IO.File]::ReadAllText($nestedOut) -ne "Nested folder extracted selectively.`n") {
        throw "Extracted docs/readme.txt content mismatch"
    }
    'PASS: Extract selected extracts only the chosen folder subtree'

    # 4. Deselect row 0 -> 'Extract all' -> extract remaining files without re-prompting
    [TcVcGui]::SetRowSelected($p.Handle, $lv, 0, $false)
    if ([TcVcGui]::Title([TcVcGui]::Child($main, 104)) -ne 'Extract all') {
        throw "Clearing selection did not restore 'Extract all'"
    }
    Remove-Item -LiteralPath $outDir -Recurse -Force
    [void][TcVcGui]::PostMessageW($main, 0x0111, [IntPtr]104, [IntPtr]::Zero)
    for ($i = 0; $i -lt 100; $i++) {
        if ((Test-Path -LiteralPath $rootOut) -and (Test-Path -LiteralPath $nestedOut) -and ([TcVcGui]::Title([TcVcGui]::Child($main, 107)) -eq 'Close')) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $rootOut) -or -not (Test-Path -LiteralPath $nestedOut)) {
        throw "Extract all did not extract all entries"
    }
    if ([IO.File]::ReadAllText($rootOut) -ne "Hello from GUI VeraCrypt browse!`n") {
        throw "Extracted hello.txt content mismatch"
    }
    foreach ($sysEntry in @('$RECYCLE.BIN', 'System Volume Information', 'pagefile.sys')) {
        if (Test-Path -LiteralPath (Join-Path $outDir $sysEntry)) {
            throw "OS volume metadata '$sysEntry' leaked into extracted output!"
        }
    }
    if ((Get-FileHash -LiteralPath $hc).Hash -ne $beforeHash) {
        throw "Source .hc container was modified during read-only browse/extract!"
    }
    'PASS: Extract all extracts full volume and preserves source container byte-for-byte'

    # 5. Close window cleanly and verify auto-unmount removes drive letter
    [void][TcVcGui]::PostMessageW($main, 0x0111, [IntPtr]107, [IntPtr]::Zero)
    if (-not $p.WaitForExit(5000)) { throw "Myrkr window did not close cleanly on Close button" }
    if (Test-Path -LiteralPath $mntDrv) {
        throw "Mounted drive $mntDrv remained mapped after Myrkr exited"
    }
    'PASS: Closing Myrkr cleanly unmounts the session drive letter'
} finally {
    if ($p -and -not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
    if ($null -eq $old) { Remove-Item Env:\MYRKR_DBG_NOSECDESK -ErrorAction SilentlyContinue } else { $env:MYRKR_DBG_NOSECDESK = $old }
    if ((Split-Path $work -Leaf) -like 'myrkr-tcvcgui-*' -and (Test-Path -LiteralPath $work)) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
