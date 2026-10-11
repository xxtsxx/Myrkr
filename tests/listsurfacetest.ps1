# Pixel regression for themed column seams in unused list space. Only our own
# test windows are inspected; no desktop capture or pointer/clipboard changes.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
# Windows PowerShell 5.1 does not load this assembly on its own (PowerShell 7
# does), and without it [IO.Compression.ZipFile] is an unknown type.
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ListSurface {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, System.Text.StringBuilder text, int n);
  public static string Title(IntPtr h) { var text=new System.Text.StringBuilder(256); GetWindowText(h,text,256); return text.ToString(); }
  delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("user32.dll")] static extern bool RedrawWindow(IntPtr h, IntPtr r, IntPtr region, uint flags);
  [DllImport("gdi32.dll")] static extern uint GetPixel(IntPtr dc, int x, int y);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int command);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int w, int height, uint flags);
  [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr h, out Rect r);
  [StructLayout(LayoutKind.Sequential)] struct Rect { public int l,t,r,b; }
  public static IntPtr Child(IntPtr h, int id) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(h,(w,p)=>{ if(GetDlgCtrlID(w)==id) found=w; return true; },IntPtr.Zero);
    return found;
  }
  public static void Check(IntPtr h) {
    RedrawWindow(h,IntPtr.Zero,IntPtr.Zero,0x101);
    Rect r; if(!GetClientRect(h,out r) || r.b<70) throw new Exception("Invalid list geometry");
    uint bg=(uint)SendMessageW(h,0x1000,IntPtr.Zero,IntPtr.Zero).ToInt64();
    var dc=GetDC(h);
    try {
      foreach(int y in new int[]{r.b/2,r.b-8})
        for(int x=4;x<r.r-20;x++) {
          uint pixel=GetPixel(dc,x,y);
          if(pixel==0xFFFFFFFF) throw new Exception("Cannot read list pixels");
          if(pixel!=bg) throw new Exception(String.Format("Column seam at ({0},{1}): {2:X6}, expected {3:X6}",x,y,pixel,bg));
        }
    } finally { ReleaseDC(h,dc); }
    long styles=SendMessageW(h,0x1037,IntPtr.Zero,IntPtr.Zero).ToInt64();
    if((styles&0x10020)!=0x10020 || (styles&1)!=0) throw new Exception("Double buffering/full-row selection/gridline styles regressed");
  }
}
'@
$p = $null
$work = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-list-surface-' + [guid]::NewGuid())
try {
    [void](New-Item -ItemType Directory -Path $work)
    $seed = Join-Path $work 'seed'
    [void](New-Item -ItemType Directory -Path $seed)
    [IO.File]::WriteAllText((Join-Path $seed 'one-row.txt'),'Synthetic list rendering fixture')
    # Plain ZIP opens a real populated model without a password prompt.
    $fixture = Join-Path $work 'one-row.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($seed,$fixture)
    foreach ($populated in @($false,$true)) {
        $launch = @{WindowStyle='Hidden'; FilePath=(Join-Path $root 'bin\myrkr.exe'); PassThru=$true}
        if ($populated) { $launch.ArgumentList = ('"' + $fixture + '"') }
        $p = Start-Process @launch
        for ($i=0; $i -lt 100; $i++) {
            $p.Refresh()
            if ($p.MainWindowHandle -ne [IntPtr]::Zero) { break }
            if ($p.HasExited) { throw 'Test application exited' }
            Start-Sleep -Milliseconds 100
        }
        $main = $p.MainWindowHandle
        if ($main -eq [IntPtr]::Zero) { throw 'No test window' }
        [void][ListSurface]::ShowWindow($main,4)
        $list = [ListSurface]::Child($main,109)
        if ($list -eq [IntPtr]::Zero) { throw 'No list control' }
        for ($i=0; $i -lt 100; $i++) {
            $count = [ListSurface]::SendMessageW($list,0x1004,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()
            if (-not $populated -or $count -gt 0) { break }
            Start-Sleep -Milliseconds 100
        }
        if ($populated -and $count -eq 0) { throw 'Fixture row did not load' }
        $action = [ListSurface]::Title([ListSurface]::Child($main,104))
        if ($populated) {
            if ($action -ne 'Extract all') { throw "Wrong ZIP action: $action" }
            if ([ListSurface]::Title([ListSurface]::Child($main,161)) -ne 'Delete') { throw 'Wrong ZIP Delete label' }
            if ([ListSurface]::Title([ListSurface]::Child($main,196)) -ne 'Edits save immediately') { throw 'Missing immediate-save hint' }
        } elseif ($action -notin @('Create .mrk','Create ZIP')) { throw "Wrong creation action: $action" }
        if ([ListSurface]::Title([ListSurface]::Child($main,107)) -ne 'Close') { throw 'Wrong idle Close label' }
        foreach ($size in @(@(600,450),@(920,680),@(650,490),@(800,550),@(600,450))) {
            [void][ListSurface]::SetWindowPos($main,[IntPtr]::Zero,0,0,$size[0],$size[1],0x16)
            [ListSurface]::Check($list)
        }
        [void][ListSurface]::SendMessageW($list,0x31A,[IntPtr]::Zero,[IntPtr]::Zero)
        [ListSurface]::Check($list)
        "PASS populated=${populated}: uniform empty space after resizing and theme notification; double buffering retained"
        $p.Kill(); $p.WaitForExit(); $p = $null
    }
} finally {
    if ($p -and -not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
    $target = [IO.Path]::GetFullPath($work)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path $target -Leaf) -like 'myrkr-list-surface-*') {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}
