#!/usr/bin/env python3
"""deadcode.py - static dead-symbol detector for Myrkr's MASM sources.

Replaces the manual dead-symbol sweeps (commits "cleanup: remove orphaned
equ/data/macro symbols", "chore: remove orphaned data, stale externs...") with a
repeatable tool.  It reads every src/*.asm file, collects the symbols each one
*defines* (procs, data labels, and equ/textequ constants), then pools every
identifier *referenced* anywhere across all sources.  A defined symbol whose name
never appears as a reference is dead code.

Why source, not obj/*.lst: build.cmd does not clean obj/, so stale listings from
deleted modules linger there and would produce phantom results.  The sources are
the ground truth and need no build.

References are pooled across ALL files, so a proc defined in one module and
called from another counts as live.  A symbol used only through a macro still
appears - the macros (WINCALL, WSTR, CALL_GUARDED, ...) take the symbol name as
a literal argument, so the name token is present in the source text.

Categories: proc | data | equ | macro.  --only <cat> narrows the report.
Exit code = number of dead symbols found (minus the allowlist), so
"build strict" can gate on it.  Usage:
    python tools\\deadcode.py [--src DIR] [--only proc|data|equ|macro] [-v]
"""
import re, glob, os, sys, argparse
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.normpath(os.path.join(HERE, "..", "src"))

# Symbols that are live but referenced only from OUTSIDE the .asm sources (the
# linker, the build script, or the resource compiler).  Anything reached through
# an in-source call/dispatch table (cmd_* verbs, window procs via addr/offset,
# selftest sub-procs) already shows up as a reference and does NOT belong here.
ALLOWLIST = {
    # Every entry below is one this checker actually reports; an allowlist line
    # that never fires is a claim about the codebase that nothing verifies, so
    # they are pruned rather than left as decoration.
    "wstart",          # /entry:wstart in build.cmd - the PE entry point
    "_load_config_used",  # loadcfg.asm: the PE load-config marker the linker
                       # looks up by name - referenced by the tool, not by code.
    # myrkrshell.dll (shellext.asm).  Its three entry points are reached only
    # from outside the sources: DllMain via /entry: in build.cmd, the other two
    # via myrkrshell.def.  Nothing in src/ may call them, so "unreferenced" is
    # the correct and permanent state - not a symbol waiting to be deleted.
    "DllMain", "DllGetClassObject", "DllCanUnloadNow",
    "tagged_free",     # hardening.asm: the third member of the tagged-heap
                       # family (alloc / check / free).  Only the DBG_TRACE
                       # redteam probe allocates today, and it never frees, so
                       # this reads as dead - but shipping alloc+check with no
                       # safe way to free would mean the next real caller has to
                       # re-derive the poison/generation-bump logic.  Kept whole.
    "MAX_PLAINTEXT_SIZE",  # macros.inc: the AES-GCM per-key plaintext ceiling
                       # (64 GiB - 1).  NOT CURRENTLY ENFORCED anywhere - see
                       # the note in macros.inc.  Kept because deleting it would
                       # erase the only in-code record of a real cryptographic
                       # bound; it should become a check, not a deletion.
    # macros.inc library families: complete by design, exercised as needed -
    # deleting the unused members just means re-adding them on next use.
    "CHECK_SUB_OVF", "CHECK_MUL_OVF",
    "xELSE", "xELIF", "xWHILET", "xWHILEZ", "xCONTINUE",
}

# MASM identifiers: letter/_/$/?/@ then letter/digit/_/$/?/@.  Matches both the
# definition names and the reference tokens.
IDENT = r'[A-Za-z_$?@][A-Za-z0-9_$?@]*'
RE_TOKEN = re.compile(IDENT)
RE_DEF = re.compile(
    r'^\s*(' + IDENT + r')\s+(proc|macro|equ|textequ|label|d[bwdq]|d[ft]|real[48]|tbyte)\b',
    re.I)
# STRUCT/UNION open a layout block; every field inside defines an offset, not a
# removable symbol, so those lines are skipped for BOTH def and ref collection.
RE_STRUCT_OPEN = re.compile(r'^\s*' + IDENT + r'\s+(struct|union)\b', re.I)
RE_STRUCT_END = re.compile(r'^\s*(' + IDENT + r')\s+ends\b', re.I)
# "<name> endp" closes a proc; the leading name is a bookkeeping marker paired
# with the def, NOT a reference - counting it would make every proc look live.
RE_ENDP = re.compile(r'^\s*(' + IDENT + r')\s+endp\b', re.I)
# public/extern/externdef lines name a symbol but do not USE it.  Counting them
# as references makes every public symbol self-immortal: a public proc with zero
# callers must read as dead.  Real uses (call/WINCALL/addr/lea) still produce
# their own tokens elsewhere.
RE_DIRECTIVE = re.compile(r'^\s*(public|extern|externdef)\b', re.I)
KIND_MAP = {"proc": "proc", "macro": "macro", "equ": "equ", "textequ": "equ"}
# equ names with a resource-id prefix mirror myrkr.rc.  Their true reference is
# the resource script, not asm code, so an unused one is expected, not dead.
# They are reported under the "rcid" category but never gated.
RE_RCID = re.compile(r'^(IDC_|DLG_|IDD_|IDD|IDR_|IDS_|IDB_|IDI_|DLG)', re.I)
# Categories the strict gate counts (proc/data/equ/macro).  "rcid" is advisory.
GATED = {"proc", "data", "equ", "macro"}


def strip_line(l):
    """Drop the ; comment and blank out quoted-string contents so string bytes
    like db "myrkr-kat" never masquerade as identifier references."""
    out = []
    q = None
    for c in l:
        if q:
            if c == q:
                q = None
            # swallow string body
        elif c in "'\"":
            q = c
        elif c == ';':
            break
        else:
            out.append(c)
    return ''.join(out)


def kind_of(directive):
    d = directive.lower()
    return KIND_MAP.get(d, "data")   # label / db / dw / dd / dq / real* -> data


def scan(paths):
    defs = {}        # name -> (file, lineno, kind)
    refs = set()     # every identifier used anywhere
    for path in paths:
        fname = os.path.basename(path)
        in_struct = False
        for n, raw in enumerate(open(path, encoding='latin-1'), 1):
            s = strip_line(raw.rstrip('\n'))
            if not s.strip():
                continue
            if in_struct:
                # inside a STRUCT/UNION: fields are layout, not symbols.  Watch
                # only for the matching "<name> ends".
                if RE_STRUCT_END.match(s):
                    in_struct = False
                continue
            if RE_STRUCT_OPEN.match(s):
                # the struct/union type name itself is a real symbol; record it
                # and enter skip mode for the body.
                nm = RE_TOKEN.match(s.strip()).group(0)
                defs.setdefault(nm, (fname, n, "data"))
                in_struct = True
                continue
            if RE_DIRECTIVE.match(s):
                continue           # public/extern/externdef: declaration, not use
            me = RE_ENDP.match(s)
            if me:
                # count tokens after the proc name (usually none), never the name
                refs.update(RE_TOKEN.findall(s[me.end(1):]))
                continue
            m = RE_DEF.match(s)
            if m:
                name, directive = m.group(1), m.group(2)
                kind = kind_of(directive)
                if kind == "equ" and RE_RCID.match(name):
                    kind = "rcid"
                # first definition wins; keep its location for the report
                defs.setdefault(name, (fname, n, kind))
                # the rest of the def line can still reference other symbols
                # (equ RHS, label type, dd initialiser) - count those, but not
                # the symbol being defined (its leading token).
                rest = s[m.end(1):]
                refs.update(RE_TOKEN.findall(rest))
            else:
                refs.update(RE_TOKEN.findall(s))
    return defs, refs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEF_SRC)
    ap.add_argument("--only", choices=["proc", "data", "equ", "macro", "rcid"])
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list allowlisted-but-dead symbols too")
    args = ap.parse_args()

    paths = sorted(glob.glob(os.path.join(args.src, "*.asm")))
    inc = os.path.join(args.src, "macros.inc")     # macros reference symbols
    if os.path.exists(inc):                        # (FRAME_PROLOG/FASTFAIL) that
        paths.append(inc)                          # look dead without it
    defs, refs = scan(paths)

    dead = []
    for name, (fname, line, kind) in sorted(defs.items(), key=lambda kv: (kv[1][0], kv[1][1])):
        if name in refs:
            continue
        if args.only and kind != args.only:
            continue
        allow = name in ALLOWLIST
        if allow and not args.verbose:
            continue
        dead.append((fname, line, kind, name, allow))

    gated = 0        # counts toward the exit code (proc/data/equ/macro)
    advisory = 0     # rcid: reported, never gated
    for fname, line, kind, name, allow in dead:
        tag = " (allowlisted)" if allow else ""
        label = "unused rcid" if kind == "rcid" else f"dead {kind}"
        if not allow:
            if kind in GATED:
                gated += 1
            else:
                advisory += 1
        print(f"[{label}] {fname}:{line} {name}{tag}")

    n_def = len(defs)
    extra = f", {advisory} advisory rcid" if advisory else ""
    print(f"deadcode: {gated} dead / {n_def} symbols{extra} "
          f"({'clean' if gated == 0 else 'DEAD CODE PRESENT'})")
    gated += floors.check("deadcode", {"symbols": n_def})
    sys.exit(min(gated, 255))


if __name__ == "__main__":
    main()
