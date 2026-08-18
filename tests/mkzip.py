# Builds the zip fixtures tests/estreamtest.ps1 drags out of.
#
#   mkzip.py SRCDIR OUTDIR PASSWORD
#
# Three archives, because extract_zip_entry has three output paths and a
# drag-out has to survive all of them:
#
#   aes_deflate.zip - WinZip AES-256, method 8.  The whole-buffer path: HMAC
#                     verified, THEN decrypted, then inflated in one call.
#   aes_store.zip   - WinZip AES-256, method 0.  The chunked path: decrypted a
#                     megabyte at a time with the tag checked only at the end.
#   plain.zip       - no encryption at all, which the extractor accepts as a
#                     convenience and the container view will therefore list.
#
# Written with pyzipper because myrkr cannot produce a WinZip-AES archive - it
# only reads them - so the fixture has to come from something that owes this
# code nothing.  Phase 1 already depends on pyzipper for the same reason.
import os
import sys

import pyzipper


def walk(src):
    out = []
    for root, dirs, files in os.walk(src):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, src).replace("\\", "/")
            out.append((rel, full))
    return out


def build(path, entries, password, compression):
    kw = {"compression": compression}
    if password:
        kw["encryption"] = pyzipper.WZ_AES
    cls = pyzipper.AESZipFile if password else pyzipper.ZipFile
    with cls(path, "w", **kw) as z:
        if password:
            z.setpassword(password.encode("utf-8"))
            z.setencryption(pyzipper.WZ_AES, nbits=256)
        for rel, full in entries:
            with open(full, "rb") as f:
                z.writestr(rel, f.read())


def main():
    src, out, pw = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(out, exist_ok=True)
    entries = walk(src)
    build(os.path.join(out, "aes_deflate.zip"), entries, pw, pyzipper.ZIP_DEFLATED)
    build(os.path.join(out, "aes_store.zip"), entries, pw, pyzipper.ZIP_STORED)
    build(os.path.join(out, "plain.zip"), entries, None, pyzipper.ZIP_DEFLATED)
    print("%d entries" % len(entries))


main()
