# Shared helpers for the GUI tests: find Myrkr's windows, drive them, read
# their controls and globals from outside the process.
#
#   Import-Module (Join-Path $PSScriptRoot 'lib\gui.psm1') -Force
#
# Every GUI test used to declare its own P/Invoke class and re-type the same
# dozen helpers, and the copies drifted: an ANSI-marshalled FindWindowW, a
# WM_NCHITTEST lParam packed as y*65536+x (wrong for any negative coordinate),
# FindWindowEx by class name (does not resolve these classes from another
# process - see greytest).  Each was a probe bug that read as a product bug.
# This module is the one copy; new tests should use it.
#
# Conventions: window handles are [IntPtr], [IntPtr]::Zero means "not found";
# processes are [Diagnostics.Process]; screen coordinates are absolute.

if (-not ('MyrkrGui.Native' -as [type])) {
Add-Type @'
using System; using System.Text; using System.Runtime.InteropServices;
namespace MyrkrGui {
public struct RECT { public int L, T, R, B; }
public static class Native {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern IntPtr SendText(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern IntPtr SendBuf(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int i);
  [DllImport("user32.dll")] public static extern bool RedrawWindow(IntPtr h, IntPtr r, IntPtr g, uint f);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("gdi32.dll")]  public static extern uint GetPixel(IntPtr dc, int x, int y);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, IntPtr n, uint t, uint p);
  [DllImport("kernel32.dll")] public static extern bool VirtualFreeEx(IntPtr h, IntPtr a, IntPtr n, uint t);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr n, out IntPtr r);
  [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr n, out IntPtr w);

  // EnumWindows + class compare, never FindWindowEx by class: Myrkr's classes
  // do not resolve by name from another process.
  public static IntPtr Find(uint pid, string cls, bool visibleOnly) {
    IntPtr found = IntPtr.Zero;
    EnumWindows(delegate(IntPtr h, IntPtr u) {
      uint o; GetWindowThreadProcessId(h, out o);
      if (o != pid) return true;
      if (visibleOnly && !IsWindowVisible(h)) return true;
      var s = new StringBuilder(256); GetClassNameW(h, s, 256);
      if (s.ToString() == cls) { found = h; return false; }
      return true; }, IntPtr.Zero);
    return found;
  }
  // By control id at any depth; GetDlgItem only sees direct children.
  public static IntPtr Child(IntPtr top, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(top, delegate(IntPtr h, IntPtr u) {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true; }, IntPtr.Zero);
    return found;
  }
  public static string ClassOf(IntPtr h) { var s = new StringBuilder(256); GetClassNameW(h, s, 256); return s.ToString(); }
  public static string TitleOf(IntPtr h) { var s = new StringBuilder(1024); GetWindowTextW(h, s, 1024); return s.ToString(); }
}
}
'@
}

$script:WM_SETTEXT     = 0x000C
$script:WM_GETTEXT     = 0x000D
$script:WM_CLOSE       = 0x0010
$script:WM_NCHITTEST   = 0x0084
$script:WM_COMMAND     = 0x0111
$script:ID_ACTION      = 104
$script:ID_PW_EDIT     = 156

# ---------------------------------------------------------------- processes ---

function Stop-Myrkr {
    Get-Process myrkr -EA SilentlyContinue | ForEach-Object { try { $_.Kill(); $_.WaitForExit(3000) | Out-Null } catch {} }
}

# Starts bin\myrkr.exe hidden and waits; returns the exit code.  For CLI fixture
# setup (encrypt -p ...), which needs a testio or dbg build.  Start-Process, not
# `&`: Windows PowerShell's `&` mis-captures this GUI-subsystem exe.
function Invoke-MyrkrCli {
    param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string[]]$Arguments)
    $q = foreach ($a in $Arguments) { if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a } }
    $p = Start-Process -WindowStyle Hidden -FilePath $Exe -ArgumentList $q -Wait -PassThru
    return $p.ExitCode
}

# ------------------------------------------------------------------ windows ---

function Find-MyrkrWindow {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][string]$Class, [switch]$IncludeHidden)
    return [MyrkrGui.Native]::Find([uint32]$Process.Id, $Class, -not $IncludeHidden)
}

# Polls until one of -Class appears; returns the handle (and sets $script:LastClass
# to which one), or [IntPtr]::Zero on timeout.
function Wait-MyrkrWindow {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][string[]]$Class,
          [int]$TimeoutMs = 10000, [switch]$IncludeHidden)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        foreach ($c in $Class) {
            $h = [MyrkrGui.Native]::Find([uint32]$Process.Id, $c, -not $IncludeHidden)
            if ($h -ne [IntPtr]::Zero) { $script:LastClass = $c; return $h }
        }
        if ($Process.HasExited) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return [IntPtr]::Zero
}
function Get-MyrkrLastClass { $script:LastClass }

function Get-MyrkrControl {
    param([Parameter(Mandatory)][IntPtr]$Window, [Parameter(Mandatory)][int]$Id)
    return [MyrkrGui.Native]::Child($Window, $Id)
}

function Get-MyrkrClass { param([Parameter(Mandatory)][IntPtr]$Hwnd) [MyrkrGui.Native]::ClassOf($Hwnd) }

# The title of a TOP-LEVEL window.  For a control in another process use
# Get-MyrkrText: GetWindowTextW does not read a cross-process EDIT.
function Get-MyrkrTitle { param([Parameter(Mandatory)][IntPtr]$Hwnd) [MyrkrGui.Native]::TitleOf($Hwnd) }

function Get-MyrkrText {
    param([Parameter(Mandatory)][IntPtr]$Hwnd)
    $sb = New-Object Text.StringBuilder 4096
    [void][MyrkrGui.Native]::SendBuf($Hwnd, $WM_GETTEXT, [IntPtr]4096, $sb)
    return $sb.ToString()
}

function Set-MyrkrText {
    param([Parameter(Mandatory)][IntPtr]$Hwnd, [Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    [void][MyrkrGui.Native]::SendText($Hwnd, $WM_SETTEXT, [IntPtr]::Zero, $Text)
}

# WM_COMMAND with a control id - a button press.  Posted by default (the
# handler may open a modal loop, and a Send would block until it closes).
function Send-MyrkrCommand {
    param([Parameter(Mandatory)][IntPtr]$Window, [Parameter(Mandatory)][int]$Id, [switch]$Sync)
    if ($Sync) { [void][MyrkrGui.Native]::SendMessageW($Window, $WM_COMMAND, [IntPtr]$Id, [IntPtr]::Zero) }
    else       { [void][MyrkrGui.Native]::PostMessageW($Window, $WM_COMMAND, [IntPtr]$Id, [IntPtr]::Zero) }
}

function Close-MyrkrWindow { param([Parameter(Mandatory)][IntPtr]$Window)
    [void][MyrkrGui.Native]::PostMessageW($Window, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) }

# Waits for the secure-desktop prompt (MYRKR_DBG_NOSECDESK=1 puts it on the
# normal desktop), types the password and presses OK.  Returns $true on success.
function Submit-MyrkrPassword {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][string]$Password, [int]$TimeoutMs = 10000)
    $sd = Wait-MyrkrWindow -Process $Process -Class 'myrkr_secdesk' -TimeoutMs $TimeoutMs
    if ($sd -eq [IntPtr]::Zero) { return $false }
    $ed = Get-MyrkrControl -Window $sd -Id $ID_PW_EDIT
    if ($ed -eq [IntPtr]::Zero) { return $false }
    Set-MyrkrText -Hwnd $ed -Text $Password
    Send-MyrkrCommand -Window $sd -Id $ID_ACTION
    return $true
}

# Collects the titles of every myrkr_mbox that appears, pressing OK on each,
# until none shows for -QuietMs.  The count is the point: "exactly one dialog".
function Get-MyrkrDialogs {
    param([Parameter(Mandatory)]$Process, [int]$QuietMs = 4000, [int]$Max = 8)
    $titles = @()
    for ($k = 0; $k -lt $Max; $k++) {
        $d = Wait-MyrkrWindow -Process $Process -Class 'myrkr_mbox' -TimeoutMs $QuietMs
        if ($d -eq [IntPtr]::Zero) { break }
        $titles += Get-MyrkrTitle $d
        Send-MyrkrCommand -Window $d -Id $ID_ACTION
        Start-Sleep -Milliseconds 400
    }
    return ,$titles
}

# ------------------------------------------------------------- geometry/paint ---

function Get-MyrkrRect {
    param([Parameter(Mandatory)][IntPtr]$Hwnd, [switch]$Client)
    $r = New-Object MyrkrGui.RECT
    if ($Client) { [void][MyrkrGui.Native]::GetClientRect($Hwnd, [ref]$r) }
    else         { [void][MyrkrGui.Native]::GetWindowRect($Hwnd, [ref]$r) }
    return $r
}

# MAKELPARAM for a screen point: each coordinate is a SIGNED 16-bit field, so
# mask before shifting.  y*65536+x is wrong for any negative x (a monitor left
# of the primary) and carries into y.
function ConvertTo-MyrkrLParam {
    param([Parameter(Mandatory)][int]$X, [Parameter(Mandatory)][int]$Y)
    return [IntPtr][int64]((([int64]$Y -band 0xFFFF) -shl 16) -bor ([int64]$X -band 0xFFFF))
}

# WM_NCHITTEST at an ABSOLUTE screen point.  1 = HTCLIENT, 2 = HTCAPTION.
function Test-MyrkrHit {
    param([Parameter(Mandatory)][IntPtr]$Window, [Parameter(Mandatory)][int]$X, [Parameter(Mandatory)][int]$Y)
    return [int][MyrkrGui.Native]::SendMessageW($Window, $WM_NCHITTEST, [IntPtr]::Zero, (ConvertTo-MyrkrLParam $X $Y))
}

# Histogram of a window's client pixels (COLORREF 0x00BBGGRR -> count), from its
# own DC - never PrintWindow (it does not see non-client or layered content
# faithfully; docs/UI_SURFACES.md).
function Get-MyrkrPixels {
    param([Parameter(Mandatory)][IntPtr]$Hwnd, [int]$Inset = 0, [int]$Step = 1)
    $r = Get-MyrkrRect $Hwnd -Client
    $dc = [MyrkrGui.Native]::GetDC($Hwnd)
    if ($dc -eq [IntPtr]::Zero) { return $null }
    $acc = @{}
    try {
        for ($y = $Inset; $y -lt $r.B - $Inset; $y += $Step) {
            for ($x = $Inset; $x -lt $r.R - $Inset; $x += $Step) {
                $p = [MyrkrGui.Native]::GetPixel($dc, $x, $y)
                if ($acc.ContainsKey($p)) { $acc[$p]++ } else { $acc[$p] = 1 }
            }
        }
    } finally { [void][MyrkrGui.Native]::ReleaseDC($Hwnd, $dc) }
    return $acc
}

# ------------------------------------------------------- process memory (dbg) ---

# The RVA of a public symbol from bin\myrkr.map (preferred base 0x140000000).
# The map must come from the SAME build as the running exe.
function Get-MyrkrRva {
    param([Parameter(Mandatory)][string]$Map, [Parameter(Mandatory)][string]$Symbol)
    $l = Select-String -LiteralPath $Map -Pattern ("\s" + [regex]::Escape($Symbol) + "\s") | Select-Object -First 1
    if (-not $l) { return $null }
    return [int64]([Convert]::ToUInt64((($l.Line.Trim() -split '\s+')[2]), 16) - 0x140000000)
}

# Reads a global out of a running Myrkr: 4 bytes as Int32, 8 as Int64, anything
# else as byte[].  Returns $null when the symbol is not in the map - which is
# DIFFERENT from a value of 0 or -1; a caller that confuses them passes vacuously.
function Read-MyrkrGlobal {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][string]$Map,
          [Parameter(Mandatory)][string]$Symbol, [int]$Size = 4)
    $rva = Get-MyrkrRva -Map $Map -Symbol $Symbol
    if ($null -eq $rva) { return $null }
    $b = New-Object byte[] $Size; $got = [IntPtr]::Zero
    $addr = [IntPtr]([int64]$Process.MainModule.BaseAddress + $rva)
    if (-not [MyrkrGui.Native]::ReadProcessMemory($Process.Handle, $addr, $b, [IntPtr]$Size, [ref]$got)) { return $null }
    switch ($Size) { 4 { return [BitConverter]::ToInt32($b, 0) } 8 { return [BitConverter]::ToInt64($b, 0) } default { return ,$b } }
}

# ----------------------------------------------------- listview (cross-process) ---
# A listview's LVITEM/RECT pointers must live in the TARGET's address space, so
# these work through a page allocated there: New-MyrkrRemote once per process.

function New-MyrkrRemote {
    param([Parameter(Mandatory)]$Process)
    $mem = [MyrkrGui.Native]::VirtualAllocEx($Process.Handle, [IntPtr]::Zero, [IntPtr]4096, 0x3000, 4)
    if ($mem -eq [IntPtr]::Zero) { throw "VirtualAllocEx failed in pid $($Process.Id)" }
    return [pscustomobject]@{ Process = $Process; Mem = $mem }
}

function Write-Remote($r, [byte[]]$bytes, [int]$off = 0) {
    $w = [IntPtr]::Zero
    [void][MyrkrGui.Native]::WriteProcessMemory($r.Process.Handle, [IntPtr]($r.Mem.ToInt64() + $off), $bytes, [IntPtr]$bytes.Length, [ref]$w)
}
function Read-Remote($r, [int]$n, [int]$off = 0) {
    $b = New-Object byte[] $n; $g = [IntPtr]::Zero
    [void][MyrkrGui.Native]::ReadProcessMemory($r.Process.Handle, [IntPtr]($r.Mem.ToInt64() + $off), $b, [IntPtr]$n, [ref]$g)
    return ,$b
}

function Get-MyrkrListCount {
    param([Parameter(Mandatory)][IntPtr]$ListView)
    return [int][MyrkrGui.Native]::SendMessageW($ListView, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero)   # LVM_GETITEMCOUNT
}

function Get-MyrkrListText {
    param([Parameter(Mandatory)]$Remote, [Parameter(Mandatory)][IntPtr]$ListView, [Parameter(Mandatory)][int]$Row, [int]$Column = 0)
    $li = New-Object byte[] 88                                        # LVITEMW (x64)
    [BitConverter]::GetBytes([uint32]1).CopyTo($li, 0)                # mask = LVIF_TEXT
    [BitConverter]::GetBytes([int32]$Row).CopyTo($li, 4)
    [BitConverter]::GetBytes([int32]$Column).CopyTo($li, 8)
    [BitConverter]::GetBytes([int64]($Remote.Mem.ToInt64() + 256)).CopyTo($li, 24)
    [BitConverter]::GetBytes([int32]256).CopyTo($li, 32)
    Write-Remote $Remote $li
    [void][MyrkrGui.Native]::SendMessageW($ListView, 0x1073, [IntPtr]$Row, $Remote.Mem)          # LVM_GETITEMTEXTW
    $t = [Text.Encoding]::Unicode.GetString((Read-Remote $Remote 512 256))
    $i = $t.IndexOf([char]0); if ($i -ge 0) { $t = $t.Substring(0, $i) }
    return $t
}

function Find-MyrkrListRow {
    param([Parameter(Mandatory)]$Remote, [Parameter(Mandatory)][IntPtr]$ListView, [Parameter(Mandatory)][string]$Text)
    $n = Get-MyrkrListCount $ListView
    for ($r = 0; $r -lt $n; $r++) { if ((Get-MyrkrListText $Remote $ListView $r) -eq $Text) { return $r } }
    return -1
}

# LVM_GETITEMRECT (LVIR_BOUNDS), client coordinates of the listview.
function Get-MyrkrListRowRect {
    param([Parameter(Mandatory)]$Remote, [Parameter(Mandatory)][IntPtr]$ListView, [Parameter(Mandatory)][int]$Row)
    Write-Remote $Remote (New-Object byte[] 16)                       # rc.left = LVIR_BOUNDS (0)
    [void][MyrkrGui.Native]::SendMessageW($ListView, 0x100E, [IntPtr]$Row, $Remote.Mem)
    $o = Read-Remote $Remote 16
    $r = New-Object MyrkrGui.RECT
    $r.L = [BitConverter]::ToInt32($o, 0); $r.T = [BitConverter]::ToInt32($o, 4)
    $r.R = [BitConverter]::ToInt32($o, 8); $r.B = [BitConverter]::ToInt32($o, 12)
    return $r
}

# Selects exactly one row (LVM_SETITEMSTATE on that row); returns the
# selected count afterwards.
function Select-MyrkrListRow {
    param([Parameter(Mandatory)]$Remote, [Parameter(Mandatory)][IntPtr]$ListView, [Parameter(Mandatory)][int]$Row)
    $li = New-Object byte[] 88
    [BitConverter]::GetBytes([uint32]8).CopyTo($li, 0)                # mask = LVIF_STATE
    [BitConverter]::GetBytes([uint32]2).CopyTo($li, 12)               # state = LVIS_SELECTED
    [BitConverter]::GetBytes([uint32]2).CopyTo($li, 16)               # stateMask
    Write-Remote $Remote $li
    [void][MyrkrGui.Native]::SendMessageW($ListView, 0x102B, [IntPtr]$Row, $Remote.Mem)
    Start-Sleep -Milliseconds 300
    return [int][MyrkrGui.Native]::SendMessageW($ListView, 0x1032, [IntPtr]::Zero, [IntPtr]::Zero) # LVM_GETSELECTEDCOUNT
}

# ------------------------------------------------------------------- builds ---

function Get-MyrkrVcvars {
    @("C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
      "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
      "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
      "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
}

# Builds a variant in -Root (default: this repo).  Throws on failure, with the
# tail of the log - a test that carries on against the previous binary reports
# that binary's behaviour as its own.
function Invoke-MyrkrBuild {
    param([string]$Variant = 'strict release', [string]$Root = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent))
    $vc = Get-MyrkrVcvars
    if (-not $vc) { throw 'no vcvars64.bat found' }
    $log = cmd /c "`"$vc`" >nul 2>&1 && `"$Root\build.cmd`" $Variant" 2>&1
    if (($log -join "`n") -notmatch 'BUILD OK') { throw "build '$Variant' failed:`n" + (($log | Select-Object -Last 15) -join "`n") }
}

Export-ModuleMember -Function *-Myrkr*, Stop-Myrkr, Invoke-MyrkrCli
