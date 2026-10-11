"""Extraction must never cost the user a file it did not replace, and must never
write outside the destination; edits and encrypts must refuse names they cannot
store faithfully.  Requires build testio (the CLI verbs take -p).

Each case below failed on 1.1.2 and is the regression for its 1.1.3 fix:

  * a corrupted entry extracted over an existing file DELETED that file: the
    entry was written into the real name, then removed when its tag failed
    (native) or kept after its CRC failed (ZIP stored) - extract now writes a
    random CREATE_NEW sibling and renames it in only once verified;
  * a hardlink planted at an output name was written THROUGH, into the file it
    links to outside the destination;
  * a junction inside the destination was FOLLOWED, writing outside it;
  * two inputs stored under one name (or one differing only in case) were
    accepted, and extraction silently kept the last;
  * `delete` of a missing name exited 0 after rewriting the container;
  * a duplicate `add` failed with no message, after a full re-encryption;
  * a rewrite kept the source's key-derivation cost, however weak.

Fixtures are synthetic and live in a unique temp directory; nothing outside it
is read or written.  Junctions and hardlinks need no privileges.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

PW = "Correct-Horse-9x"
fails = 0


def check(name, cond, detail=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  [{detail}]"))
    if not cond:
        fails += 1


def run(exe, *args):
    p = subprocess.run([str(exe), *map(str, args)], capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip().replace("\n", " | ")


def junction(link, target):
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=True)


def hardlink(link, target):
    subprocess.run(["cmd", "/c", "mklink", "/H", str(link), str(target)], capture_output=True, check=True)


def text(path):
    return path.read_text().strip() if path.exists() else "<gone>"


def temps(d):
    return [f for _, _, fs in os.walk(d) for f in fs if f.endswith((".tmp", ".part"))]


def flip(src, dst, needle_or_offset):
    b = bytearray(src.read_bytes())
    i = b.find(needle_or_offset) + 3 if isinstance(needle_or_offset, bytes) else needle_or_offset
    b[i] ^= 0x01
    dst.write_bytes(b)


def extraction(exe, w, kind, make_good, extract):
    """The same four hazards for one extractor."""
    good = make_good()
    bad = w / f"bad-{kind}"
    # The flip must land INSIDE THE FILE ENTRY'S STREAM, or extraction never
    # starts and the case tests nothing.  The tail of a .mrk is its index, which
    # fails before any file is opened - the first version of this test flipped
    # there and passed against the very code it exists to catch.  80-byte header,
    # the folder entry (512-byte tar header + 16-byte tag), then the file entry:
    # offset 780 is inside the file entry's own tar header, which shares its tag.
    flip(good, bad, b"NEW ARCHIVE CONTENT" if kind != "mrk" else 80 + 700)
    # junction
    d, out = w / f"j-{kind}", w / f"outside-{kind}"
    d.mkdir(); out.mkdir()
    junction(d / "evil", out)
    c, o = extract(good, d)
    check(f"{kind}: junction in the destination refused, nothing outside", c == 9 and not any(out.iterdir()), f"exit {c} {o}")
    # corrupted entry over an existing user file
    d = w / f"c-{kind}"; (d / "evil").mkdir(parents=True)
    (d / "evil" / "doc.txt").write_text("IRREPLACEABLE USER DOCUMENT")
    c, o = extract(bad, d)
    check(f"{kind}: damaged entry leaves the existing file intact, no temp",
          c != 0 and text(d / "evil" / "doc.txt") == "IRREPLACEABLE USER DOCUMENT" and not temps(d),
          f"exit {c} file={text(d / 'evil' / 'doc.txt')[:30]} temps={temps(d)} {o}")
    # hardlink, good and damaged
    for which, arc, code in (("good", good, 0), ("damaged", bad, None)):
        d = w / f"h-{kind}-{which}"; (d / "evil").mkdir(parents=True)
        victim = w / f"victim-{kind}-{which}.txt"; victim.write_text("VICTIM ORIGINAL")
        hardlink(d / "evil" / "doc.txt", victim)
        c, o = extract(arc, d)
        ok = text(victim) == "VICTIM ORIGINAL" and (c == 0 if code == 0 else c != 0)
        check(f"{kind}: {which} extract onto a planted hardlink leaves the outside file intact", ok,
              f"exit {c} victim={text(victim)} {o}")
    # clean
    d = w / f"e-{kind}"
    c, o = extract(good, d)
    check(f"{kind}: clean extract works and leaves no temp",
          c == 0 and text(d / "evil" / "doc.txt").startswith("NEW ARCHIVE") and not temps(d), f"exit {c} {o}")


def main():
    exe = pathlib.Path(sys.argv[1]).resolve()
    w = pathlib.Path(tempfile.mkdtemp(prefix="myrkr-hazard-"))
    try:
        src = w / "src" / "evil"; src.mkdir(parents=True)
        (src / "doc.txt").write_text("NEW ARCHIVE CONTENT " * 40)

        def make_mrk():
            out = w / "good.mrk"
            c, o = run(exe, "encrypt", src, "-o", out, "--store", "-p", PW)
            assert c == 0, o
            return out

        def make_zip(comp):
            def make():
                out = w / f"good-{comp}.zip"
                with zipfile.ZipFile(out, "w", comp) as z:
                    z.writestr("evil/doc.txt", "NEW ARCHIVE CONTENT " * 40)
                return out
            return make

        extraction(exe, w, "mrk", make_mrk, lambda a, d: run(exe, "decrypt", a, "-o", d, "-p", PW))
        extraction(exe, w, "zip-stored", make_zip(zipfile.ZIP_STORED), lambda a, d: run(exe, "unzip", a, "-o", d))
        extraction(exe, w, "zip-deflate", make_zip(zipfile.ZIP_DEFLATED), lambda a, d: run(exe, "unzip", a, "-o", d))

        # ---- the verified-folder cache must not cover a NEAR miss -------------
        # The guard caches the last folder it verified.  "ok" is verified first;
        # "ok2" shares its first characters but is a different folder - and here
        # it is a junction.  A prefix compare that stopped at the shared part
        # would wave it through.
        near = w / "near"
        for d in ("ok", "ok2"):
            (near / d).mkdir(parents=True)
            (near / d / "f.txt").write_text(d)
        near_mrk, near_zip = w / "near.mrk", w / "near.zip"
        c, o = run(exe, "encrypt", near / "ok", near / "ok2", "-o", near_mrk, "--store", "-p", PW)
        assert c == 0, o
        with zipfile.ZipFile(near_zip, "w") as z:
            z.writestr("ok/f.txt", "ok")
            z.writestr("ok2/f.txt", "ok2")
        for kind, arc, ex in (("mrk", near_mrk, lambda a, d: run(exe, "decrypt", a, "-o", d, "-p", PW)),
                              ("zip", near_zip, lambda a, d: run(exe, "unzip", a, "-o", d))):
            d, out = w / f"near-{kind}", w / f"near-outside-{kind}"
            d.mkdir(); out.mkdir()
            junction(d / "ok2", out)
            c, o = ex(arc, d)
            check(f"{kind}: cached 'ok' does not cover junction 'ok2'",
                  c == 9 and not any(out.iterdir()) and text(d / "ok" / "f.txt") == "ok", f"exit {c} {o}")

        # ---- names that cannot be stored faithfully ---------------------------
        for a in ("one", "two"):
            (w / a / "docs").mkdir(parents=True)
            (w / a / "docs" / "r.txt").write_text(a)
        (w / "c1").mkdir(); (w / "c1" / "Notes.txt").write_text("U")
        (w / "c2").mkdir(); (w / "c2" / "notes.txt").write_text("l")
        c, o = run(exe, "encrypt", w / "one" / "docs", w / "two" / "docs", "-o", w / "dup.mrk", "-p", PW)
        check("encrypt refuses two inputs with one stored name", c == 1 and not (w / "dup.mrk").exists(), f"exit {c} {o}")
        c, o = run(exe, "encrypt", w / "c1" / "Notes.txt", w / "c2" / "notes.txt", "-o", w / "case.mrk", "-p", PW)
        check("encrypt refuses names that differ only in case", c == 1 and not (w / "case.mrk").exists(), f"exit {c} {o}")
        c, o = run(exe, "zip", w / "one" / "docs", w / "two" / "docs", "-o", w / "dup.zip", "-p", PW)
        check("zip refuses two inputs with one stored name", c == 1 and not (w / "dup.zip").exists(), f"exit {c} {o}")

        box = w / "box.mrk"
        c, o = run(exe, "encrypt", w / "one" / "docs", "-o", box, "-p", PW)
        before = box.read_bytes()
        c, o = run(exe, "add", box, w / "two" / "docs", "-p", PW)
        check("add refuses an existing name, says so, changes nothing",
              c == 1 and "already holds" in o and box.read_bytes() == before, f"exit {c} {o}")
        upper = w / "x" / "DOCS"; upper.mkdir(parents=True); (upper / "z.txt").write_text("Z")
        c, o = run(exe, "add", box, upper, "-p", PW)
        check("add refuses a case-only variant", c == 1 and box.read_bytes() == before, f"exit {c} {o}")
        c, o = run(exe, "delete", box, "no-such.txt", "-p", PW)
        check("delete of a missing name fails and does not rewrite", c == 1 and box.read_bytes() == before, f"exit {c} {o}")

        weak = w / "weak.mrk"; (w / "f.txt").write_text("f"); (w / "g.txt").write_text("g")
        run(exe, "encrypt", w / "f.txt", "-o", weak, "-m", "8", "-t", "1", "-p", PW)
        run(exe, "add", weak, w / "g.txt", "-p", PW)
        h = weak.read_bytes()
        t, m = int.from_bytes(h[8:12], "little"), int.from_bytes(h[12:16], "little")
        check(f"a rewrite raises a weak key-derivation cost (now t={t}, m={m} KiB)", t >= 3 and m >= 524288, f"t={t} m={m}")
    finally:
        shutil.rmtree(w, ignore_errors=True)
    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILURE(S)'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
