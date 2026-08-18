# =============================================================================
# menuicon.ps1 - the context-menu bitmap survives the trip into myrkrshell.dll.
#
#   powershell -ExecutionPolicy Bypass -File tests\menuicon.ps1
#
# tools\make_menu_bmp.py --check (run by build.cmd) proves menu16.bmp still
# matches myrkr.ico.  That is the ASSET.  This proves the PIPELINE: that rc.exe
# embedded it, that the resource id the DLL asks for is the one that is there,
# and that LoadImageW hands back a 32-bit DIB whose alpha is still premultiplied
# after the round trip.  Those are three different ways for the icon to come out
# as a grey box, and none of them is visible in a build log.
#
# It loads the DLL with LOAD_LIBRARY_AS_DATAFILE, so DllMain never runs and
# nothing is registered - this reads a resource out of a file, it does not
# install a shell extension.
#
# What it CANNOT check is what the item looks like in Explorer's menu. Nothing
# scriptable can; that one is done by right-clicking a file.
# =============================================================================
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dll = Join-Path $root 'bin\myrkrshell.dll'
$fail = 0

function Check([string]$what, [bool]$ok, [string]$detail) {
    if ($ok) { "  ok   $what  $detail" }
    else { $script:fail++; "  FAIL $what  $detail" }
}

if (-not (Test-Path $dll)) { "menuicon: $dll not built"; exit 1 }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class MenuIcon {
  [DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  [DllImport("kernel32", SetLastError=true)]
  public static extern bool FreeLibrary(IntPtr h);
  [DllImport("user32", SetLastError=true)]
  public static extern IntPtr LoadImageW(IntPtr hInst, IntPtr name, uint type,
                                         int cx, int cy, uint fuLoad);
  [StructLayout(LayoutKind.Sequential)]
  public struct BITMAP {
    public int bmType, bmWidth, bmHeight, bmWidthBytes;
    public ushort bmPlanes, bmBitsPixel;
    public IntPtr bmBits;
  }
  [DllImport("gdi32")] public static extern int GetObjectW(IntPtr h, int c, out BITMAP b);
  [DllImport("gdi32")] public static extern bool DeleteObject(IntPtr h);
}
'@

"=== the menu bitmap loads out of the shipping DLL ==="
$LOAD_AS_DATAFILE = 0x2
$IMAGE_BITMAP = 0
$LR_CREATEDIBSECTION = 0x2000
$IDB_MENU = 1                            # must match IDB_MENU in shellext.asm

$h = [MenuIcon]::LoadLibraryExW($dll, [IntPtr]::Zero, $LOAD_AS_DATAFILE)
if ($h -eq [IntPtr]::Zero) {
    "  FAIL could not map the DLL as a data file  err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    exit 1
}

$bmp = [MenuIcon]::LoadImageW($h, [IntPtr]$IDB_MENU, $IMAGE_BITMAP, 0, 0, $LR_CREATEDIBSECTION)
Check "resource $IDB_MENU is present and loads" ($bmp -ne [IntPtr]::Zero) `
      "err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"

if ($bmp -ne [IntPtr]::Zero) {
    $b = New-Object MenuIcon+BITMAP
    [void][MenuIcon]::GetObjectW($bmp, [Runtime.InteropServices.Marshal]::SizeOf($b), [ref]$b)

    Check "16x16" ($b.bmWidth -eq 16 -and [Math]::Abs($b.bmHeight) -eq 16) `
          "$($b.bmWidth)x$($b.bmHeight)"
    # 32bpp is not cosmetic: a menu draws hbmpItem with alpha ONLY for a 32-bit
    # DIB.  At 24bpp it comes out as an opaque rectangle in the menu colour.
    Check "32 bits per pixel" ($b.bmBitsPixel -eq 32) "$($b.bmBitsPixel) bpp"
    Check "LR_CREATEDIBSECTION gave us the bits" ($b.bmBits -ne [IntPtr]::Zero) ""

    if ($b.bmBits -ne [IntPtr]::Zero -and $b.bmBitsPixel -eq 32) {
        $n = $b.bmWidthBytes * [Math]::Abs($b.bmHeight)
        $px = New-Object byte[] $n
        [Runtime.InteropServices.Marshal]::Copy($b.bmBits, $px, 0, $n)
        # Premultiplied means every colour channel is <= its own alpha.  A
        # straight-alpha bitmap violates that on any pixel that is both
        # translucent and bright, and shows up as a halo round the icon.
        $bad = 0; $opaque = 0; $clear = 0
        for ($i = 0; $i -lt $n; $i += 4) {
            $a = $px[$i+3]
            $m = [Math]::Max([Math]::Max($px[$i], $px[$i+1]), $px[$i+2])
            if ($m -gt $a) { $bad++ }
            if ($a -eq 255) { $opaque++ }
            if ($a -eq 0) { $clear++ }
        }
        Check "alpha is premultiplied" ($bad -eq 0) "$bad pixel(s) with a channel above alpha"
        # Guards the degenerate cases: a fully transparent bitmap draws nothing
        # and a fully opaque one draws a rectangle.  Both "load" perfectly.
        Check "there is actually an image" ($opaque -gt 0) "$opaque opaque pixel(s)"
        Check "and it is not a solid block" ($clear -gt 0 -or $opaque -lt ($n / 4)) `
              "$clear transparent of $($n / 4)"
    }
    [void][MenuIcon]::DeleteObject($bmp)
}
[void][MenuIcon]::FreeLibrary($h)

""
if ($fail -eq 0) { "menuicon: all checks passed"; exit 0 }
"menuicon: $fail check(s) failed"; exit 1
