# =============================================================================
# shellexttest.ps1 - myrkrshell.dll survives being asked for a context menu.
#
#   powershell -ExecutionPolicy Bypass -File tests\shellexttest.ps1
#
# WHY THIS EXISTS
# ---------------
# This DLL had no automated coverage at all, and it is the one binary here that
# runs inside a process Myrkr does not own.  1.0.40 shipped a raw prologue raised
# from 160 to 256 bytes with the matching epilogue left at 160, so every return
# from QueryContextMenu popped rbp and the return address from 96 bytes below
# where they were pushed.  explorer.exe died on the first right-drag.  Nothing in
# the build noticed: the assembler was happy, the linker was happy, and Windows
# Error Reporting called it BEX64 in "faulting module: unknown".
#
# tools\framecheck.py now catches that class statically.  This catches it
# dynamically, and catches whatever the static check cannot see - it loads the
# real DLL, creates the real COM object through DllGetClassObject, and calls
# QueryContextMenu through its vtable.
#
# It runs the call in a CHILD process on purpose.  A smashed return address does
# not raise a catchable error; it takes the process down.  So the child is the
# thing that dies and its exit code is the result - a harness that crashed with
# the code under test could not report anything.
#
# WHAT IT DOES NOT COVER: the item's placement, its label, and its icon, all of
# which need a real selection in a real Explorer menu.  QueryContextMenu is
# called WITHOUT Initialize here, which is the documented "decline" path - the
# handler must add nothing and return S_OK with zero ids.  That still runs the
# whole prologue and epilogue, which is the part that was fatal.
# =============================================================================
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dll = Join-Path $root 'bin\myrkrshell.dll'
$fail = 0

function Check([string]$what, [bool]$ok, [string]$detail) {
    if ($ok) { "  ok   $what  $detail" } else { $script:fail++; "  FAIL $what  $detail" }
}

if (-not (Test-Path $dll)) { "shellexttest: $dll not built"; exit 1 }

# The child does the dangerous part.  It prints one line of results and exits 0;
# any other exit code (or no output) means it did not get that far.
$child = @'
$dll = $args[0]
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SX {
  [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr LoadLibraryW(string f);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("user32")] public static extern IntPtr CreatePopupMenu();
  [DllImport("user32")] public static extern bool DestroyMenu(IntPtr h);
  [DllImport("user32")] public static extern int GetMenuItemCount(IntPtr h);
  [DllImport("ole32")] public static extern int CoInitialize(IntPtr p);

  // DllGetClassObject(REFCLSID, REFIID, void**)
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int DllGetClassObjectFn(ref Guid clsid, ref Guid iid, out IntPtr ppv);

  // IClassFactory::CreateInstance is vtable slot 3 (QI/AddRef/Release first)
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int CreateInstanceFn(IntPtr self, IntPtr outer, ref Guid iid, out IntPtr ppv);
  // IContextMenu::QueryContextMenu is vtable slot 3
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int QueryContextMenuFn(IntPtr self, IntPtr hmenu, uint indexMenu,
                                         uint idCmdFirst, uint idCmdLast, uint uFlags);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate uint ReleaseFn(IntPtr self);

  public static IntPtr Slot(IntPtr obj, int i) {
    IntPtr vtbl = Marshal.ReadIntPtr(obj);
    return Marshal.ReadIntPtr(vtbl, i * IntPtr.Size);
  }
}
"@
[void][SX]::CoInitialize([IntPtr]::Zero)
$h = [SX]::LoadLibraryW($dll)
if ($h -eq [IntPtr]::Zero) { "ERR load $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit 2 }
$p = [SX]::GetProcAddress($h, "DllGetClassObject")
if ($p -eq [IntPtr]::Zero) { "ERR noexport"; exit 3 }

# {7C4A6E10-2F58-4B3D-9C81-5E0A7D9B4F62} - fixed forever, see shellext.asm
$clsid = [Guid]"7C4A6E10-2F58-4B3D-9C81-5E0A7D9B4F62"
$IID_IClassFactory = [Guid]"00000001-0000-0000-C000-000000000046"
$IID_IContextMenu  = [Guid]"000214E4-0000-0000-C000-000000000046"

$dgco = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, [SX+DllGetClassObjectFn])
$cf = [IntPtr]::Zero
$hr = $dgco.Invoke([ref]$clsid, [ref]$IID_IClassFactory, [ref]$cf)
if ($hr -ne 0 -or $cf -eq [IntPtr]::Zero) { "ERR dgco 0x{0:X8}" -f $hr; exit 4 }

$ci = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([SX]::Slot($cf,3), [SX+CreateInstanceFn])
$cm = [IntPtr]::Zero
$hr = $ci.Invoke($cf, [IntPtr]::Zero, [ref]$IID_IContextMenu, [ref]$cm)
if ($hr -ne 0 -or $cm -eq [IntPtr]::Zero) { "ERR createinstance 0x{0:X8}" -f $hr; exit 5 }

$menu = [SX]::CreatePopupMenu()
$qcm = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([SX]::Slot($cm,3), [SX+QueryContextMenuFn])
# No Initialize: the handler captured nothing, so it must decline.  Called twice -
# a frame that is restored wrongly can still return once by luck, and the second
# call is what a user makes when the first menu was not what they wanted.
$hr1 = $qcm.Invoke($cm, $menu, 0, 1, 0x7FFF, 0)
$hr2 = $qcm.Invoke($cm, $menu, 0, 1, 0x7FFF, 0)
$n = [SX]::GetMenuItemCount($menu)
[void][SX]::DestroyMenu($menu)
$rel = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([SX]::Slot($cm,2), [SX+ReleaseFn])
[void]$rel.Invoke($cm)
$relf = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([SX]::Slot($cf,2), [SX+ReleaseFn])
[void]$relf.Invoke($cf)
"OK {0} {1} {2}" -f $hr1, $hr2, $n
exit 0
'@

"=== myrkrshell.dll answers QueryContextMenu and returns ==="
$tmp = Join-Path ([IO.Path]::GetTempPath()) "myrkr_shellext_child.ps1"
Set-Content -Path $tmp -Value $child -Encoding UTF8
$out = & powershell -NoProfile -ExecutionPolicy Bypass -File $tmp $dll 2>&1
$code = $LASTEXITCODE
Remove-Item $tmp -Force -ErrorAction SilentlyContinue
$line = ($out | Where-Object { $_ -match '^(OK|ERR)' } | Select-Object -Last 1)

# The whole point: a smashed return address kills the child.  Survival IS a check.
Check "the child process survived the call" ($code -eq 0) "exit=$code $(if ($code -ne 0) { $out -join ' / ' })"

if ($line -match '^OK\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)$') {
    $hr1 = [int]$Matches[1]; $hr2 = [int]$Matches[2]; $items = [int]$Matches[3]
    # S_OK with zero ids used: HRESULT_FROM_WIN32-style MAKE_HRESULT(0,0,0) = 0
    Check "declines cleanly with no Initialize (1st call)" ($hr1 -eq 0) "hr=0x$('{0:X8}' -f $hr1)"
    Check "and again on the second call" ($hr2 -eq 0) "hr=0x$('{0:X8}' -f $hr2)"
    Check "added no menu item it was not entitled to" ($items -eq 0) "$items item(s)"
} elseif ($code -eq 0) {
    Check "the child reported a result" $false "got: $($out -join ' / ')"
}

""
if ($fail -eq 0) { "shellexttest: all checks passed"; exit 0 }
"shellexttest: $fail check(s) failed"; exit 1
