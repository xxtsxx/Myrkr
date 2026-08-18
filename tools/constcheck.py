#!/usr/bin/env python3
"""constcheck - cross-module constant agreement gate for Myrkr.

Some `equ` constants are deliberately mirrored in more than one module: Win32
values each file needs, and a few sizes that MUST match the module which
actually allocates the array.  Nothing enforces the second kind, and in Vordr it
drifted:

    main.asm      MAX_FIELDS equ 96      <- allocates g_field_list (dq 3*MAX_FIELDS)
    gui.asm       MAX_FIELDS equ 96
    zipimport.asm MAX_FIELDS equ 56      <- comment claimed "matches main.asm"

Imported entries silently lost every field past the 56th while the array had
room for 96.  Too small only loses data; too LARGE would have overrun the array.

So: any constant defined in more than one file must agree everywhere.  A name is
gated only when at least two files give it a literal value - a definition this
script cannot evaluate is skipped rather than guessed at, so an `equ` built from
an expression never produces a false conflict.

Values are parsed as decimal, 0x.. hex, or MASM trailing-h hex.  Simple integer
expressions over names already resolved IN THE SAME FILE are folded too;
anything else is left unresolved and ignored.

Exit code: number of conflicting names, so `build strict` can gate on it.
Usage: python tools/constcheck.py [--src DIR]
"""
import re, os, sys, glob, argparse, collections
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.normpath(os.path.join(HERE, "..", "src"))

RE_EQU  = re.compile(r'^\s*([A-Za-z_][\w$]*)\s+equ\s+(.+?)\s*$', re.I)
# Only fold expressions built from names, integer literals, whitespace, the four
# operators and parens.  Anything with a register, string, or MASM operator in it
# is left alone rather than guessed at.
RE_SAFE = re.compile(r'^[\w\s$+\-*/()]+$')

def strip_comment(line):
    q = None; out = []
    for c in line:
        if q:
            out.append(c)
            if c == q: q = None
        elif c in "'\"":
            q = c; out.append(c)
        elif c == ';':
            break
        else:
            out.append(c)
    return ''.join(out)

def parse_int(tok):
    t = tok.strip()
    if re.fullmatch(r'\d+', t):                    return int(t)
    if re.fullmatch(r'0[xX][0-9A-Fa-f]+', t):      return int(t, 16)
    if re.fullmatch(r'[0-9][0-9A-Fa-f]*[hH]', t):  return int(t[:-1], 16)
    return None

def fold(expr, known):
    """Integer value of `expr` using same-file names in `known`, or None."""
    v = parse_int(expr)
    if v is not None:
        return v
    if not RE_SAFE.match(expr):
        return None
    # substitute known names; bail if any bare identifier is still unresolved
    def sub(m):
        return str(known[m.group(0)]) if m.group(0) in known else m.group(0)
    e = re.sub(r'[A-Za-z_][\w$]*', sub, expr)
    if re.search(r'[A-Za-z_$]', e):
        return None
    try:
        val = eval(e, {"__builtins__": {}}, {})       # digits and + - * / ( ) only
        return int(val) if isinstance(val, (int, float)) else None
    except Exception:
        return None

def parse_file(path):
    """-> {name: value} for every equ in `path` we can evaluate."""
    known, pending = {}, []
    for line in open(path, encoding='latin-1'):
        m = RE_EQU.match(strip_comment(line.rstrip('\n')))
        if not m: continue
        name, expr = m.group(1), m.group(2)
        v = fold(expr, known)
        if v is None:
            pending.append((name, expr))
        else:
            known.setdefault(name, v)
    # a couple of extra passes: definitions that referenced a later name
    for _ in range(3):
        if not pending: break
        again = []
        for name, expr in pending:
            v = fold(expr, known)
            if v is None: again.append((name, expr))
            else:         known.setdefault(name, v)
        if len(again) == len(pending): break
        pending = again
    return known

RE_RC_FILEVER = re.compile(r'^\s*FILEVERSION\s+(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)', re.I)
RE_RC_STRVER  = re.compile(r'VALUE\s+"(FileVersion|ProductVersion)"\s*,\s*"([\d.]+)"', re.I)
RE_ASM_ABVER  = re.compile(r'^\s*WSTR\s+s_ab_ver\s*,\s*<\s*Version\s+([\d.]+)\s*>', re.I)
# There used to be a third asm site, s_version - the clickable "Myrkr v1.0.1"
# label in the main window's lower-left corner.  The UI redesign removed that
# label (the wordmark took its place), so the site is gone rather than renamed.
# The About box still carries the version in the GUI, which is what this check
# exists to keep honest.


def _mmp(v):
    """major.minor.patch of a version however it is written: 1,0,1,0 / 1.0.1.0 /
    1.0.1 all reduce to (1,0,1).  The sites format the version differently - the
    resource uses four fields, the About box four, the main-window label three -
    so comparing the strings verbatim would either miss drift or report it
    constantly."""
    parts = [p for p in v.replace(",", ".").split(".") if p != ""]
    parts = (parts + ["0", "0", "0"])[:3]
    return ".".join(parts)


def version_check(root):
    """The product version lives in several places that cannot reference each
    other: myrkr.rc's FILEVERSION, the same file's FileVersion/ProductVersion
    strings, the About box's s_ab_ver, and s_version on the main window.  The MSI
    reads the binary's resource, so a stale on-screen string ships a package whose
    installer and window disagree.  None of this is an `equ`, so the rest of this
    checker cannot see it.

    s_version was missed by the first version of this check because it reads
    "Myrkr v1.0" - three fields where the others have four - so the check passed
    while the main window showed a stale number.  Hence the normalisation above:
    compare what the version IS, not how each site spells it.

    myrkrshell.rc joined the list when the shell extension became a second
    binary.  One MSI now installs two files, and two files reporting different
    versions is a support call nobody can answer - so its resource is compared
    against the exe's rather than left to be updated by memory."""
    gui = os.path.join(os.path.join(root, "src"), "gui.asm")
    rcs = [("myrkr.rc", os.path.join(root, "myrkr.rc")),
           ("myrkrshell.rc", os.path.join(root, "myrkrshell.rc"))]
    rcs = [(n, p) for n, p in rcs if os.path.exists(p)]
    if not (rcs and os.path.exists(gui)):
        return 0
    found = {}
    for name, path in rcs:
        for line in open(path, encoding='latin-1'):
            m = RE_RC_FILEVER.match(line)
            if m:
                found.setdefault(f"{name} FILEVERSION", ".".join(m.groups()))
            m = RE_RC_STRVER.search(line)
            if m:
                found.setdefault(f"{name} {m.group(1)}", m.group(2))
    for line in open(gui, encoding='latin-1'):
        m = RE_ASM_ABVER.match(line)
        if m:
            found.setdefault("gui.asm s_ab_ver", m.group(1))
    for k in list(found):
        found[k] = _mmp(found[k])
    # Every site must be found, not merely agree: a regex that stops matching
    # would otherwise turn into a silent pass, which is how s_version drifted.
    required = ["gui.asm s_ab_ver"] + \
               [f"{n} FILEVERSION" for n, _ in rcs]
    for req in required:
        if req not in found:
            print(f"[FLOOR] constcheck: version site '{req}' not found - the "
                  f"check has lost its reach; fix the pattern rather than the symptom")
            return 1
    if len(found) < 2:
        print("[FLOOR] constcheck: fewer than two version sites found - the version "
              "check has lost its reach; verify myrkr.rc and gui.asm's s_ab_ver")
        return 1
    vals = set(found.values())
    if len(vals) > 1:
        where = ", ".join(f"{k}={v}" for k, v in sorted(found.items()))
        print(f"[CONFLICT] product version disagrees across sites: {where}")
        return 1
    where = ", ".join(n for n, _ in rcs)
    print(f"constcheck: product version {vals.pop()} agrees across "
          f"{len(found)} sites ({where}, About box)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEF_SRC)
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.src, "*.asm")) +
                   glob.glob(os.path.join(args.src, "*.inc")))
    if not files:
        print(f"constcheck: no sources under {args.src}")
        sys.exit(0)

    defs = collections.defaultdict(dict)
    for f in files:
        for name, v in parse_file(f).items():
            defs[name].setdefault(os.path.basename(f), v)

    shared    = {n: d for n, d in defs.items() if len(d) > 1}
    conflicts = {n: d for n, d in shared.items() if len(set(d.values())) > 1}

    for name in sorted(conflicts):
        where = ", ".join(f"{f}={v}" for f, v in sorted(conflicts[name].items()))
        print(f"[CONFLICT] {name} disagrees across modules: {where}")
    for name in sorted(shared):
        if name in conflicts: continue
        v = next(iter(shared[name].values()))
        print(f"[info] {name} = {v} mirrored in {', '.join(sorted(shared[name]))}")

    print(f"constcheck: {len(conflicts)} conflicting constant(s) across "
          f"{len(files)} files, {len(shared)} mirrored "
          f"({'clean' if not conflicts else 'CROSS-MODULE DRIFT'})")
    bad = len(conflicts) + floors.check("constcheck",
                                       {"mirrored": len(shared), "files": len(files)})
    bad += version_check(os.path.normpath(os.path.join(args.src, "..")))
    sys.exit(min(bad, 255))

if __name__ == "__main__":
    main()
