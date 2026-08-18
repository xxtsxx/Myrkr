#!/usr/bin/env python3
"""make_menu_bmp - build the context-menu bitmap from myrkr.ico.

    python tools\\make_menu_bmp.py            write menu16.bmp
    python tools\\make_menu_bmp.py --check    fail if it is out of date

Writes menu16.bmp next to myrkr.ico.  Run it only when the icon changes; the
result is committed, so an ordinary build needs neither Python nor Pillow.

--check is what build.cmd runs.  A generated asset that is committed alongside
its source is a file that silently stops matching: change myrkr.ico, forget this
step, and the menu keeps the OLD icon with nothing anywhere reporting it.  So
the build regenerates into memory and compares.  It skips - quietly, exit 0 -
when Pillow is absent, because that is a missing tool and not a stale asset;
the gate exists to catch drift on the machine that can see it.

WHY A BITMAP AND NOT THE ICON
-----------------------------
MENUITEMINFO.hbmpItem takes an HBITMAP, not an HICON.  Converting one to the
other at runtime means CreateCompatibleDC / CreateDIBSection / DrawIconEx /
SelectObject / DeleteDC - that is gdi32, and myrkrshell.dll is loaded INTO
explorer.exe.  Its whole design is four imported libraries and no UI of its own,
so pulling in a graphics library to draw one 16x16 image is the wrong trade.

A BITMAP resource is loaded by LoadImageW, which is user32 - already imported.
So the conversion happens here, once, at author time.

WHY THE ALPHA IS PREMULTIPLIED
------------------------------
A menu draws hbmpItem with alpha only when it is a 32-bit DIB whose colour
channels are already multiplied by the alpha channel.  Hand a straight-alpha
bitmap over and the edges come out with a bright halo against a dark menu and a
dark one against a light menu - the classic sign of this being skipped.  So it
is done here, and the result is what the DLL loads verbatim.

WHY 16x16
---------
The DLL cannot resize it: stretching a DIB needs gdi32 again, and LoadImageW's
own stretching does not respect the alpha channel.  16 is the menu-check size at
100% DPI.  Above that the icon reads small beside the text - visibly modest
rather than wrong - and fixing it properly means either a runtime scale (gdi32)
or one bitmap per DPI bucket picked at load time.  Neither is worth it for a
decoration; both are worth it if this ever becomes something a user must SEE to
use the menu safely.  It is not: the item is labelled in words.
"""
import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SRC = os.path.join(ROOT, "myrkr.ico")
DST = os.path.join(ROOT, "menu16.bmp")
SIZE = 16


def build(Image):
    img = Image.open(SRC)
    # Every entry in myrkr.ico is PNG-compressed, so the 16x16 one cannot simply
    # be copied out as a DIB - it has to be decoded.  Ask for the size directly
    # rather than resampling a larger frame: the 16x16 art in an icon is drawn
    # for that size, not scaled down from the 256.
    img.size = (SIZE, SIZE)
    img = img.convert("RGBA")
    if img.size != (SIZE, SIZE):
        raise SystemExit(f"make_menu_bmp: {SRC} has no {SIZE}x{SIZE} frame")

    px = img.load()
    rows = []
    for y in range(SIZE - 1, -1, -1):           # BMP scanlines run bottom-up
        row = bytearray()
        for x in range(SIZE):
            r, g, b, a = px[x, y]
            # premultiply: c' = c * a / 255, rounded
            row += bytes(((b * a + 127) // 255,
                          (g * a + 127) // 255,
                          (r * a + 127) // 255,
                          a))
        rows.append(bytes(row))
    bits = b"".join(rows)                        # 32bpp rows are always 4-aligned

    # BITMAPINFOHEADER: 32bpp, BI_RGB, no palette.  rc.exe strips the 14-byte
    # BITMAPFILEHEADER below and embeds everything from here on.
    info = struct.pack("<IiiHHIIiiII", 40, SIZE, SIZE, 1, 32, 0, len(bits),
                       2835, 2835, 0, 0)
    fileh = struct.pack("<HIHHI", 0x4D42, 14 + len(info) + len(bits), 0, 0,
                        14 + len(info))
    return fileh + info + bits


def main():
    check = "--check" in sys.argv[1:]
    try:
        from PIL import Image
    except ImportError:
        if check:
            print("make_menu_bmp: Pillow absent, cannot check menu16.bmp is "
                  "current (not a failure - see the header)")
            return 0
        print("make_menu_bmp: needs Pillow (pip install pillow)", file=sys.stderr)
        return 2

    want = build(Image)
    if check:
        try:
            with open(DST, "rb") as f:
                have = f.read()
        except OSError:
            print(f"make_menu_bmp: {DST} is missing - run "
                  f"'python tools\\make_menu_bmp.py'", file=sys.stderr)
            return 1
        if have != want:
            print(f"make_menu_bmp: {DST} does not match myrkr.ico - the icon "
                  f"changed and the menu bitmap did not.  Run "
                  f"'python tools\\make_menu_bmp.py' and commit the result.",
                  file=sys.stderr)
            return 1
        print(f"make_menu_bmp: menu16.bmp matches myrkr.ico ({SIZE}x{SIZE}, "
              f"32bpp premultiplied)")
        return 0

    with open(DST, "wb") as f:
        f.write(want)
    print(f"make_menu_bmp: wrote {DST} ({SIZE}x{SIZE}, 32bpp premultiplied, "
          f"{len(want)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
