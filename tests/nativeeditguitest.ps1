# A native removal reaches do_remove_marked directly from the GUI worker.
# Prove small rewrites succeed and large rewrites warn before making changes.
# Requires build dbg (the private-desktop test override); launches and
# terminates only its own test process.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root 'bin\myrkr.exe'
$work = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-editguard-' + [guid]::NewGuid())
$p = $null
$old = $env:MYRKR_DBG_NOSECDESK
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class EditGuardUI {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
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
    IntPtr found=IntPtr.Zero;
    EnumWindows(delegate(IntPtr h, IntPtr unused) {
      uint owner; GetWindowThreadProcessId(h,out owner);
      if(owner!=pid || !IsWindowVisible(h)) return true;
      var s=new StringBuilder(256); GetClassName(h,s,256);
      if(s.ToString()==cls) { found=h; return false; } return true;
    }, IntPtr.Zero); return found;
  }
  public static string Title(IntPtr h) { var s=new StringBuilder(512); GetWindowText(h,s,512); return s.ToString(); }
  public static IntPtr Child(IntPtr parent, int id) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent, delegate(IntPtr h, IntPtr unused) {
      if(GetDlgCtrlID(h)==id) { found=h; return false; } return true;
    }, IntPtr.Zero); return found;
  }
}
'@
function Get-HashOrNull($path) {
    # The rewrite holds a write-excluding handle on the source while it works,
    # so a hash taken mid-rewrite is a sharing violation: that means "not yet".
    try { return (Get-FileHash -LiteralPath $path -ErrorAction Stop).Hash } catch { return $null }
}
function Wait-Window($class) {
    for ($i=0; $i -lt 100; $i++) {
        if ($p.HasExited) { throw 'Test process exited unexpectedly' }
        $h = [EditGuardUI]::Find([uint32]$p.Id, $class)
        if ($h -ne [IntPtr]::Zero) { return $h }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $class"
}
try {
  foreach ($large in @($false, $true)) {
    $work = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-edit-' + [guid]::NewGuid())
    [void](New-Item -ItemType Directory -Path $work)
    $src = Join-Path $work 'seed.txt'
    $mrk = Join-Path $work 'seed.mrk'
    [IO.File]::WriteAllText($src, 'synthetic GUI guard fixture')
    if ($large) {
        $fixture = [IO.File]::OpenWrite($src)
        try { $fixture.SetLength(100MB) } finally { $fixture.Dispose() }
    }
    $setup = Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList @('encrypt', $src, '-o', $mrk, '-p', 'Test-Password-9', '--store', '-m', '8', '-t', '1') -Wait -PassThru
    if ($setup.ExitCode -ne 0) { throw "Setup failed: $($setup.ExitCode)" }
    $before = (Get-FileHash -LiteralPath $mrk).Hash
    $env:MYRKR_DBG_NOSECDESK = '1'
    $p = Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList $mrk -PassThru
    $prompt = Wait-Window 'myrkr_secdesk'
    [void][EditGuardUI]::Text([EditGuardUI]::GetDlgItem($prompt,156), 12, [IntPtr]::Zero, 'Test-Password-9')
    [void][EditGuardUI]::PostMessageW($prompt, 0x111, [IntPtr]104, [IntPtr]::Zero)
    $main = Wait-Window 'myrkr_window'
    $lv = [EditGuardUI]::Child($main,109)
    for ($i=0; $i -lt 100; $i++) {
        if ([EditGuardUI]::SendMessageW($lv,0x1004,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -gt 0) { break }
        Start-Sleep -Milliseconds 100
    }
    foreach ($expected in @(@(104,'Extract all'),@(107,'Close'),@(161,'Delete'),@(196,'Edits save immediately'))) {
        if ([EditGuardUI]::Title([EditGuardUI]::Child($main,$expected[0])) -ne $expected[1]) { throw "Wrong archive label: $expected" }
    }
    $remote = [EditGuardUI]::VirtualAllocEx($p.Handle,[IntPtr]::Zero,[IntPtr]88,0x3000,4)
    if ($remote -eq [IntPtr]::Zero) { throw 'Cannot allocate test LVITEM' }
    try {
        $item = [byte[]]::new(88)
        [BitConverter]::GetBytes([uint32]2).CopyTo($item,12)
        [BitConverter]::GetBytes([uint32]2).CopyTo($item,16)
        $written = [IntPtr]::Zero
        if (-not [EditGuardUI]::WriteProcessMemory($p.Handle,$remote,$item,88,[ref]$written)) { throw 'Cannot select fixture row' }
        [void][EditGuardUI]::SendMessageW($lv,0x102B,[IntPtr]0,$remote)
    } finally { [void][EditGuardUI]::VirtualFreeEx($p.Handle,$remote,[IntPtr]::Zero,0x8000) }
    if ([EditGuardUI]::SendMessageW($lv,0x1032,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -ne 1) { throw 'No fixture row selected' }
    if ([EditGuardUI]::Title([EditGuardUI]::Child($main,104)) -ne 'Extract selected') { throw 'Wrong selected action label' }
    [void][EditGuardUI]::PostMessageW($main,0x111,[IntPtr]161,[IntPtr]::Zero)
    if ($large) {
        $dialog = Wait-Window 'myrkr_mbox'
        if ([EditGuardUI]::Title($dialog) -ne 'Myrkr - this will take a while') { throw 'Missing large rewrite warning' }
        if ((Get-FileHash -LiteralPath $mrk).Hash -ne $before) { throw 'Changed before confirmation' }
        [void][EditGuardUI]::PostMessageW($dialog,0x111,[IntPtr]107,[IntPtr]::Zero)
        Start-Sleep -Milliseconds 300
        if ((Get-FileHash -LiteralPath $mrk).Hash -ne $before) { throw 'Warning cancellation changed source' }
        'PASS: 100 MiB native rewrite warns first; declining leaves source unchanged'
        # Confirm a second attempt, then cancel the worker immediately.
        [void][EditGuardUI]::PostMessageW($main,0x111,[IntPtr]161,[IntPtr]::Zero)
        $dialog = Wait-Window 'myrkr_mbox'
        [void][EditGuardUI]::PostMessageW($dialog,0x111,[IntPtr]104,[IntPtr]::Zero)
        for ($i=0; $i -lt 100; $i++) {
            Start-Sleep -Milliseconds 2
            [void][EditGuardUI]::PostMessageW($main,0x111,[IntPtr]107,[IntPtr]::Zero)
            if ([EditGuardUI]::Find([uint32]$p.Id, 'myrkr_mbox') -eq [IntPtr]::Zero) { break }
        }
        # Wait for the cancelled job to let go of the source.  A cancel is honoured
        # at the next check, and the key derivation before the first one cannot be
        # interrupted - at the default cost that alone outlasts a fixed sleep.
        $h = $null
        for ($i=0; $i -lt 150 -and -not $h; $i++) { Start-Sleep -Milliseconds 100; $h = Get-HashOrNull $mrk }
        if ($h -ne $before) { throw 'Worker cancellation changed source' }
        'PASS: cancelling native removal leaves the source unchanged'
    } else {
        for ($i=0; $i -lt 100; $i++) {
            Start-Sleep -Milliseconds 100
            $h = Get-HashOrNull $mrk
            if ($h -and $h -ne $before) { break }
        }
        if ((Get-FileHash -LiteralPath $mrk).Hash -eq $before) { throw 'Small GUI rewrite did not complete' }
        'PASS: small native removal rewrites without a large-file warning'
    }
    for ($i=0; $i -lt 100; $i++) {
        if ([EditGuardUI]::Title([EditGuardUI]::Child($main,107)) -eq 'Close') { break }
        Start-Sleep -Milliseconds 100
    }
    if ([EditGuardUI]::Title([EditGuardUI]::Child($main,107)) -ne 'Close') { throw 'Close label not restored after edit' }
    'PASS: archive action labels and Close restored after editing'
    $p.Kill(); $p.WaitForExit(); $p = $null
    $check = Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList @('verify', $mrk, '-p', 'Test-Password-9') -Wait -PassThru
    if ($check.ExitCode -ne 0) { throw 'GUI result failed authentication' }
    # Only this freshly created, explicit fixture directory is removed.
    if ((Split-Path $work -Leaf) -notlike 'myrkr-edit-*') { throw 'Unsafe fixture cleanup path' }
    Remove-Item -LiteralPath $work -Recurse -Force
  }
} finally {
    if ($p -and -not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
    $env:MYRKR_DBG_NOSECDESK = $old
}
