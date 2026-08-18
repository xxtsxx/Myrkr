#!/usr/bin/env python3
"""pe_normalise - zero the build timestamps in a PE image.

A release build claims to be reproducible: same commit, same bytes, and a
published SHA-256 anyone can check.  It was not.  Two `build.cmd strict release`
runs from an identical working tree, 36 minutes apart, produced binaries that
differed in 73 bytes of 301,056 - and both carried version 1.0.23.0, so nothing
about either file said which one you had.

Every differing byte was a timestamp:

  * the COFF header's TimeDateStamp, and
  * the TimeDateStamp in each IMAGE_DEBUG_DIRECTORY entry (28 bytes apiece,
    which is what made the diff show up on a 28-byte stride).

`/Brepro` is supposed to prevent exactly this by replacing timestamps with a
hash of the linker's inputs.  It does - but ml64 stamps each .obj it writes,
build.cmd reassembles every source on every run, so the inputs it hashes are
themselves different each time.  The determinism has to be restored after the
link, not asked for during it.

Zeroing is safe: Windows does not validate either field, and neither is load-
bearing for a binary that is not signed or served from a symbol server.  What
is lost is "when was this built", which is what the version resource and the
commit are for.

Idempotent, so running it twice is not an error - and re-running it on a
shipped binary is how you check one.

Usage: python tools\\pe_normalise.py <image> [<image> ...]
Exit code: 0 if every image was normalised, 1 on any parse failure.
"""
import struct
import sys


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _save(path, b, changed):
    """Write back only if something moved, and report how much."""
    if changed:
        with open(path, "wb") as f:
            f.write(b)
    return changed


def normalise(path):
    """Zero the build timestamps in `path`.  Returns how many were non-zero."""
    with open(path, "rb") as f:
        b = bytearray(f.read())

    if b[:2] != b"MZ":
        raise ValueError("not a PE image (no MZ)")
    pe = _u32(b, 0x3C)
    if b[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image (no PE signature at e_lfanew)")

    changed = 0

    # --- COFF header TimeDateStamp -----------------------------------------
    if _u32(b, pe + 8) != 0:
        struct.pack_into("<I", b, pe + 8, 0)
        changed += 1

    # --- the debug directory, reached through the data directories ---------
    nsections = _u16(b, pe + 6)
    optsize = _u16(b, pe + 20)
    opt = pe + 24
    magic = _u16(b, opt)
    if magic == 0x20B:            # PE32+
        ddir = opt + 112
    elif magic == 0x10B:          # PE32
        ddir = opt + 96
    else:
        raise ValueError("unknown optional header magic 0x%X" % magic)
    nddir = _u32(b, ddir - 4)
    sect = opt + optsize

    def rva_to_off(rva):
        for i in range(nsections):
            s = sect + i * 40
            va, vsz = _u32(b, s + 12), _u32(b, s + 8)
            raw, rawsz = _u32(b, s + 20), _u32(b, s + 16)
            if va <= rva < va + max(vsz, rawsz):
                return raw + (rva - va)
        return None

    # --- the EXPORT directory's own TimeDateStamp --------------------------
    # An exe has no exports, which is why myrkr.exe reproduced while
    # myrkrshell.dll did not: IMAGE_EXPORT_DIRECTORY carries a timestamp at +4
    # and the linker writes the build time into it regardless of /Brepro.
    if nddir > 0:
        exp_rva, exp_size = _u32(b, ddir), _u32(b, ddir + 4)
        if exp_rva and exp_size:
            eo = rva_to_off(exp_rva)
            if eo is not None and _u32(b, eo + 4) != 0:
                struct.pack_into("<I", b, eo + 4, 0)
                changed += 1

    if nddir <= 6:
        return _save(path, b, changed)
    dbg_rva = _u32(b, ddir + 6 * 8)
    dbg_size = _u32(b, ddir + 6 * 8 + 4)
    if dbg_rva == 0 or dbg_size == 0:
        return _save(path, b, changed)

    off = rva_to_off(dbg_rva)
    if off is None:
        raise ValueError("debug directory RVA 0x%X is in no section" % dbg_rva)

    # IMAGE_DEBUG_DIRECTORY is 28 bytes: TimeDateStamp at +4, SizeOfData at
    # +16, PointerToRawData at +24.
    #
    # The stamps alone are not enough.  Zeroing them took two builds of one
    # commit from 73 differing bytes to 49, and the rest live in the CodeView
    # payload - it carries a PDB GUID that the linker regenerates on every
    # link, so it differs even when the code does not.
    #
    # ONLY the CodeView payload (Type 2).  The first version of this cleared
    # every entry's payload "rather than leaving whichever one changes next",
    # and that silently turned CET off: hardware shadow-stack compatibility is
    # advertised by an IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS entry (Type 20)
    # whose payload IS the flags.  build.cmd's mitigation check caught it -
    # "CET compatible" simply stopped being printed - which is the whole reason
    # that check exists.  A build-hygiene fix that disables a mitigation is a
    # far worse bug than the one it set out to fix.
    #
    # Nothing at load time reads the CodeView record.  What is given up is
    # matching this image to a .pdb, and the .pdb is a local artifact the MSI
    # has never packaged, so nothing shipped loses anything.
    # Every payload EXCEPT that one.  Restricting it to CodeView was not enough
    # either: /Brepro writes its own IMAGE_DEBUG_TYPE_REPRO record whose payload
    # is the hash of the linker's inputs, and those inputs are the timestamped
    # .obj files, so that record varies build to build as well.  Rather than
    # chase each record type as it turns up, the rule is inverted - clear
    # everything, preserve the one that means something.
    EX_DLLCHARACTERISTICS = 20
    for i in range(dbg_size // 28):
        e = off + i * 28
        if e + 28 > len(b):
            raise ValueError("debug directory runs past the end of the file")
        if _u32(b, e + 4) != 0:
            struct.pack_into("<I", b, e + 4, 0)
            changed += 1
        if _u32(b, e + 12) == EX_DLLCHARACTERISTICS:
            continue                          # CET lives here - leave it alone
        raw_sz, raw_ptr = _u32(b, e + 16), _u32(b, e + 24)
        if raw_ptr and raw_sz:
            if raw_ptr + raw_sz > len(b):
                raise ValueError("debug payload runs past the end of the file")
            if b[raw_ptr:raw_ptr + raw_sz] != bytearray(raw_sz):
                b[raw_ptr:raw_ptr + raw_sz] = bytearray(raw_sz)
                changed += 1

    return _save(path, b, changed)


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 1
    rc = 0
    for path in argv[1:]:
        try:
            n = normalise(path)
            print("pe_normalise: %-24s %s" %
                  (path, "already normalised" if n == 0 else "zeroed %d timestamp(s)" % n))
        except Exception as e:                                   # noqa: BLE001
            print("pe_normalise: %s: %s" % (path, e))
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
