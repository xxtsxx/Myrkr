# Render only controls belonging to our own test process; no desktop capture,
# pointer movement, clipboard use, or interaction with existing Myrkr windows.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class CmdBarPaint {
  delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnableWindow(IntPtr h, bool enabled);
  [DllImport("user32.dll")] public static extern IntPtr GetWindowLongPtrW(IntPtr h, int index);
  [DllImport("user32.dll")] public static extern IntPtr SetWindowLongPtrW(IntPtr h, int index, IntPtr value);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("user32.dll")] static extern bool RedrawWindow(IntPtr h, IntPtr r, IntPtr region, uint flags);
  [DllImport("gdi32.dll")] static extern uint GetPixel(IntPtr dc, int x, int y);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int command);
  [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr h, out Rect r);
  [StructLayout(LayoutKind.Sequential)] struct Rect { public int l,t,r,b; }
  public static IntPtr Child(IntPtr h, int id) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(h, (w,p) => { if(GetDlgCtrlID(w)==id) found=w; return true; }, IntPtr.Zero);
    return found;
  }
  public static uint Pixel(IntPtr h) {
    RedrawWindow(h,IntPtr.Zero,IntPtr.Zero,0x101);
    Rect r; GetClientRect(h,out r);
    var dc=GetDC(h);
    try { return GetPixel(dc,(r.r-r.l)/2,3); }
    finally { ReleaseDC(h,dc); }
  }
  public static int LabelInk(IntPtr h) {
    Rect r; GetClientRect(h,out r);
    var dc=GetDC(h); int count=0;
    try {
      for(int y=5;y<r.b-4;y++) for(int x=30;x<r.r-3;x++)
        if(GetPixel(dc,x,y)==0xFFFFFF) count++;
      return count;
    } finally { ReleaseDC(h,dc); }
  }
}
'@
$p = $null
function Pixel($h) {
    $color = [CmdBarPaint]::Pixel($h)
    if ($color -eq [uint32]::MaxValue) { throw 'Cannot read test control pixels' }
    return $color
}
try {
    $p = Start-Process -WindowStyle Hidden -FilePath (Join-Path $root 'bin\myrkr.exe') -PassThru
    for ($i=0; $i -lt 100; $i++) {
        $p.Refresh()
        if ($p.MainWindowHandle -ne [IntPtr]::Zero) { break }
        if ($p.HasExited) { throw 'Test application exited' }
        Start-Sleep -Milliseconds 100
    }
    $main = $p.MainWindowHandle
    if ($main -eq [IntPtr]::Zero) { throw 'No test window' }
    [void][CmdBarPaint]::ShowWindow($main,4) # show without activating
    # IDs are pinned to gui.asm so an accidental control/layout change is visible.
    $bar = [CmdBarPaint]::Child($main,160)
    if ($bar -eq [IntPtr]::Zero) { throw 'Command bar not found' }
    $background = Pixel $bar
    foreach ($id in @(154,155,161,162,142,164)) {
        $button = [CmdBarPaint]::Child($main,$id)
        if ($button -eq [IntPtr]::Zero) { throw "Button $id not found" }
        [void][CmdBarPaint]::EnableWindow($button,$true)
        [void][CmdBarPaint]::SendMessageW($button,0x2A3,[IntPtr]::Zero,[IntPtr]::Zero)
        if ((Pixel $button) -ne $background) { throw "Button $id idle fill differs from bar" }
        if ($id -in @(161,162) -and [CmdBarPaint]::LabelInk($button) -eq 0) { throw "Button $id label is missing" }
        # Set the paint state directly: a synthetic mouse-move would immediately
        # receive mouse-leave because the real pointer remains untouched.
        $style = [CmdBarPaint]::GetWindowLongPtrW($button,-21).ToInt64()
        [void][CmdBarPaint]::SetWindowLongPtrW($button,-21,[IntPtr]($style -bor 0x100))
        $hover = Pixel $button
        if ($hover -eq $background) { throw "Button $id lacks hover feedback" }
        [void][CmdBarPaint]::SendMessageW($button,0xF3,[IntPtr]1,[IntPtr]::Zero)
        $pressed = Pixel $button
        if ($pressed -eq $hover -or $pressed -eq $background) { throw "Button $id lacks distinct pressed feedback" }
        [void][CmdBarPaint]::EnableWindow($button,$false)
        if ((Pixel $button) -ne $background) { throw "Disabled button $id retains a highlight" }
        if ($id -in @(161,162) -and [CmdBarPaint]::LabelInk($button) -ne 0) { throw "Disabled button $id label is not muted" }
        "PASS button ${id}: blended idle, hover, pressed, disabled"
    }
} finally {
    if ($p -and -not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
}
