#!/usr/bin/env python3
"""aligncheck.py - data-alignment auditor for Myrkr's MASM sources.

Ported from Vordr, where a `dw` class-name string landed at an ODD address
because an odd-length `db` string earlier in the section shifted it.  The OS
class-name reader took an aligned (SSE) path, raised
STATUS_DATATYPE_MISALIGNMENT, and RegisterClassW failed with ERROR_NOACCESS.

Myrkr is exposed to exactly this: gui.asm holds ~94 WSTR literals in a .const
block that also carries odd-length `db` data, and hands many of them straight to
-W APIs (RegisterClassExW, CreateWindowExW, SetWindowTextW).

This tool tracks the running byte offset of every data label in each source file
and reports labels that cannot be naturally aligned for their access width:
  - dw / word / WSTR   -> must be 2-aligned
  - dd / dword         -> must be 4-aligned
  - dq / qword         -> must be 8-aligned

Sections are page-aligned by the linker, so per-file offset tracking is
sufficient.  STRUCT/UNION bodies are skipped (layout alignment is explicit),
and align/even directives reset the running offset.

Not every odd `dw` is a bug: most APIs read wide strings byte-wise.  But as a
CONTROL the rule is: any wide string or array that an OS API or an SSE code path
might touch must be naturally aligned.  Flagged sites are fixed with an explicit
`align` (documenting intent) or allowlisted here with a reason.

Exit code = number of misaligned labels (so "build strict" can gate on it).
Usage: python tools\\aligncheck.py [--src DIR] [--scalars]
"""
import re, glob, os, sys, argparse
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.normpath(os.path.join(HERE, "..", "src"))

# macros.inc's WSTR macro emits `even` before its label, so every wide string
# self-aligns regardless of a drifted running offset.  Model that here.  (Set
# False to see what the offsets would be without it.)
WSTR_EMITS_EVEN = True

# Sites reviewed and accepted as harmless (name only - the data is consumed
# byte-wise and is never handed to an OS API or an SSE load).
ALLOWLIST = {
}

DIRECTIVE_SIZE = {"db": 1, "dw": 2, "dd": 4, "dq": 8, "dt": 10,
                  "byte": 1, "word": 2, "dword": 4, "qword": 8}

# --- second rule: big uninitialised arrays belong in .data? -----------------
# "dup (?)" reads like a declaration of intent not to initialise, but in an
# INITIALISED section the assembler emits the bytes anyway.  In Vordr six path
# buffers grown to MAX_PATH_CHARS landed in .data and put 394 KB of zeros in the
# image.  It built, it ran, every gate passed; the only symptom was the file
# size, which for a project that publishes a reproducible hash is not a symptom
# to leave lying around.
#
# Small ones are not worth the noise: a scalar or a short scratch in .data costs
# nothing and moving it would churn code for no gain.
BSS_MIN_BYTES = 4096
DUP_DECL = re.compile(r'^(\w+)\s+(db|dw|dd|dq)\s+(.+?)\s+dup\s*\(\s*\?\s*\)', re.I)

# `equ` values collected from every source, so a dup count written as a NAME
# ("MAX_ARGS dup (?)", "LINELEN dup (?)") sizes correctly.  Without this the
# array counted as a single element and every offset after it was wrong - which
# manufactured two phantom misalignments (g_logpath, g_sizetxt) on the first
# run of this tool against Myrkr.
EQUS = {}
STRUCTS = {}                              # name -> byte size, for `sizeof NAME`
RE_EQU_DEF = re.compile(r'^\s*([A-Za-z_][\w$]*)\s+equ\s+(.+?)\s*$', re.I)
RE_STRUCT_OPEN = re.compile(r'^\s*([\w$]+)\s+struct\b', re.I)
RE_STRUCT_ENDS = re.compile(r'^\s*[\w$]+\s+ends\b', re.I)
RE_FIELD_DEF = re.compile(r'^\s*(?:[\w$]+\s+)?(db|dw|dd|dq|dt)\b\s*(.*)$', re.I)


def masm_int(tok):
    """MASM integer literal -> int or None: decimal, 0x.., or trailing-h hex."""
    t = tok.strip()
    if re.fullmatch(r'\d+', t): return int(t)
    if re.fullmatch(r'0[xX][0-9A-Fa-f]+', t): return int(t, 16)
    if re.fullmatch(r'[0-9][0-9A-Fa-f]*[hH]', t): return int(t[:-1], 16)
    return None


def resolve(expr, depth=0):
    """Integer value of a MASM constant expression, or None if unresolvable."""
    if depth > 16:
        return None
    expr = expr.strip()
    v = masm_int(expr)
    if v is not None:
        return v
    m = re.fullmatch(r'\(?\s*sizeof\s+([\w$]+)\s*\)?', expr, re.I)
    if m:
        return STRUCTS.get(m.group(1))
    # sizeof inside a larger expression: fold it to a literal first
    if re.search(r'\bsizeof\b', expr, re.I):
        def _sz(mm):
            n = STRUCTS.get(mm.group(1))
            return str(n) if n is not None else 'sizeof_unknown'
        expr = re.sub(r'\bsizeof\s+([\w$]+)', _sz, expr, flags=re.I)
        if 'sizeof_unknown' in expr:
            return None
    out = []
    for t in re.findall(r'[\w$]+|[()+*/-]', expr):
        n = masm_int(t)
        if n is not None:
            out.append(str(n))
        elif re.fullmatch(r'[\w$]+', t):
            if t not in EQUS:
                return None
            sub = resolve(EQUS[t], depth + 1)
            if sub is None:
                return None
            out.append(str(sub))
        else:
            out.append(t)
    pyexpr = ' '.join(out)
    if not re.fullmatch(r'[0-9()+*/ \-]+', pyexpr):
        return None
    try:
        return int(eval(pyexpr, {"__builtins__": {}}, {}))
    except Exception:
        return None


def build_equs(paths):
    """Collect `NAME equ EXPR` and `NAME struct .. ends` sizes from every source."""
    for path in paths:
        cur = None; size = 0
        for raw in open(path, encoding='latin-1'):
            s = strip_line(raw.rstrip('\n'))
            if cur is None:
                m = RE_EQU_DEF.match(s)
                if m:
                    EQUS.setdefault(m.group(1), m.group(2))
                    continue
                m = RE_STRUCT_OPEN.match(s)
                if m:
                    cur = m.group(1); size = 0
                continue
            if RE_STRUCT_ENDS.match(s):
                STRUCTS[cur] = size; cur = None; continue
            m = RE_FIELD_DEF.match(s)
            if m:
                cnt = 1
                d = re.match(r'(\d+)\s+dup\b', m.group(2))
                if d: cnt = int(d.group(1))
                size += cnt * DIRECTIVE_SIZE[m.group(1).lower()]


def dup_bytes(count_expr, unit):
    """Byte size of a `N dup (?)`, where N may be any constant expression."""
    n = resolve(count_expr)
    return None if n is None else n * unit


def scan_sections(path, results):
    """Flag `N dup (?)` arrays of BSS_MIN_BYTES or more sitting in .data."""
    sec = None
    for ln, raw in enumerate(open(path, encoding="latin-1").read().split("\n"), 1):
        code = raw.split(";")[0].rstrip()
        t = code.strip()
        low = t.lower()
        if low in (".data", ".data?", ".code", ".const"):
            sec = low
            continue
        if sec != ".data":
            continue
        m = DUP_DECL.match(t)
        if not m:
            continue
        n = dup_bytes(m.group(3), DIRECTIVE_SIZE[m.group(2).lower()])
        if n is not None and n >= BSS_MIN_BYTES:
            results.append(("initialised-bss", os.path.basename(path), ln, m.group(1),
                            m.group(2),  0,
                            f"{n} bytes of `dup (?)` in .data - the assembler emits every "
                            f"one of them into the image; .data? costs virtual size only"))


LABEL_ALIGN   = {"db": 1, "dw": 2, "dd": 4, "dq": 8, "dt": 4,
                 "byte": 1, "word": 2, "dword": 4, "qword": 8}

RE_SECTION = re.compile(r'^\s*\.(data\??|const|code)\b', re.I)
RE_STRUCT  = re.compile(r'^\s*[\w$]+\s+(struct|union)\b', re.I)
RE_ENDS    = re.compile(r'^\s*[\w$]+\s+ends\b', re.I)
RE_ALIGN   = re.compile(r'^\s*(align|even)\b\s*(\d+)?', re.I)
RE_LABEL   = re.compile(r'^\s*([\w$]+)\s+(label)\s+(\w+)\b', re.I)
RE_DEF     = re.compile(r'^\s*(?:([\w$]+)\s+)?(db|dw|dd|dq|dt)\b(.*)$', re.I)
RE_DUP     = re.compile(r'(.+?)\s+dup\s*\((.*)\)', re.I)
RE_WSTR    = re.compile(r'^\s*WSTR\s+([\w$]+)\s*,\s*<(.*)>\s*$', re.I)
RE_CSTR    = re.compile(r'^\s*CSTR\s+([\w$]+)\s*,\s*"(.*)"\s*$', re.I)

def strip_line(l):
    """Drop ; comment, keep quoted strings intact (we need their lengths)."""
    out = []
    q = None
    for c in l:
        if q:
            if c == q: q = None
            out.append(c)
        elif c in "'\"":
            q = c; out.append(c)
        elif c == ';':
            break
        else:
            out.append(c)
    return ''.join(out)

def split_items(s):
    """Split a MASM operand list on commas at depth 0, respecting quotes/parens."""
    parts, depth, q, cur = [], 0, None, []
    for c in s:
        if q:
            cur.append(c)
            if c == q: q = None
        elif c in "'\"": q = c; cur.append(c)
        elif c in '([{': depth += 1; cur.append(c)
        elif c in ')]}': depth -= 1; cur.append(c)
        elif c == ',' and depth == 0:
            parts.append(''.join(cur).strip()); cur = []
        else:
            cur.append(c)
    parts.append(''.join(cur).strip())
    return [p for p in parts if p]

def item_bytes(tok, dirsize):
    """Byte count of one MASM data item (numbers, chars, strings, ?, expressions)."""
    tok = tok.strip()
    if not tok: return 0
    if tok == '?': return dirsize
    if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
        return len(tok) - 2
    if tok.startswith("'"):
        # char literal(s): 'A' -> 1 per char of content (single quotes hold 1-2)
        inner = tok[1:-1] if tok.endswith("'") else tok[1:]
        return len(inner) if dirsize == 1 else dirsize
    return dirsize

def operand_bytes(rest, dirsize):
    """Byte span of a data directive's operands, or None if any `dup` count is
    unresolvable.  None must poison the running offset rather than being treated
    as zero: a wrongly-sized array silently shifts every label after it, which is
    how a checker manufactures misalignments that are not there."""
    total = 0
    for part in split_items(rest):
        m = RE_DUP.match(part)
        if m:
            n = resolve(m.group(1))
            if n is None:
                return None
            inner = split_items(m.group(2))
            sub = sum(item_bytes(t, dirsize) for t in inner)
            total += n * max(sub, dirsize if inner else 0)
        else:
            total += item_bytes(part, dirsize)
    return total

def scan_file(path, results):
    fname = os.path.basename(path)
    section = None
    offsets = {}          # section -> running byte offset
    in_struct = False
    for n, raw in enumerate(open(path, encoding='latin-1'), 1):
        s = strip_line(raw.rstrip('\n')).strip()
        if not s: continue
        m = RE_SECTION.match(s)
        if m:
            section = m.group(1).lower()
            offsets.setdefault(section, 0)
            continue
        if section not in ('data', 'data?', 'const'):
            continue
        if offsets.get(section) is None and section in offsets:
            continue          # offset untrustworthy from here on in this section
        if in_struct:
            if RE_ENDS.match(s): in_struct = False
            continue
        if RE_STRUCT.match(s):
            in_struct = True
            continue
        m = RE_ALIGN.match(s)
        if m:
            a = int(m.group(2)) if m.group(2) else 2
            if s.lower().startswith('even'): a = 2
            if a > 0:
                offsets[section] = (offsets[section] + a - 1) & ~(a - 1)
            continue
        # WSTR name, <text>  -> [even +] label + dw text + dw 0
        m = RE_WSTR.match(s)
        if m:
            name, text = m.group(1), m.group(2)
            off = offsets[section]
            if WSTR_EMITS_EVEN:
                off = (off + 1) & ~1               # the WSTR macro's `even`
            elif off % 2:
                results.append(("string", fname, n, name, "WSTR", off,
                    f"WSTR label at offset {off} (odd) - a -W API may take an aligned "
                    f"(SSE) read path and fail with ERROR_NOACCESS; give the WSTR macro "
                    f"an `even` (the Vordr fix) or add an explicit align here"))
            offsets[section] = off + 2 * (len(text) + 1)
            continue
        # CSTR name, "text"  -> db text + db 0
        m = RE_CSTR.match(s)
        if m:
            offsets[section] += len(m.group(2)) + 1
            continue
        # name label word|dword|qword|byte
        m = RE_LABEL.match(s)
        if m:
            name, kind = m.group(1), m.group(3).lower()
            need = LABEL_ALIGN.get(kind, 1)
            off = offsets[section]
            if need > 1 and off % need:
                cat = "string" if need == 2 else "scalar"
                results.append((cat, fname, n, name, kind, off,
                    f"{kind} label at offset {off} (not {need}-aligned) - can land "
                    f"unaligned for an aligned-width read"))
            continue
        # [name] db/dw/dd/dq/dt items
        m = RE_DEF.match(s)
        if m:
            name, directive, rest = m.group(1), m.group(2).lower(), m.group(3)
            need = LABEL_ALIGN[directive]
            off = offsets[section]
            if name and need > 1 and off % need:
                cat = "string" if need == 2 else "scalar"
                results.append((cat, fname, n, name, directive, off,
                    f"{directive} label at offset {off} (not {need}-aligned) - can land "
                    f"unaligned for an aligned-width read"))
            span = operand_bytes(rest, DIRECTIVE_SIZE[directive])
            if span is None:
                results.append(("unsized", fname, n, name or directive, directive, off,
                    f"cannot size `{rest.strip()}` - offset tracking for this section "
                    f"stops here rather than reporting from a wrong running offset"))
                offsets[section] = None
                continue
            offsets[section] = off + span
            continue

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEF_SRC)
    ap.add_argument("--scalars", action="store_true",
                    help="also report misaligned dq/dd scalar globals (review list)")
    args = ap.parse_args()
    files = sorted(glob.glob(os.path.join(args.src, "*.asm"))) + \
            sorted(glob.glob(os.path.join(args.src, "*.inc")))
    build_equs(files)                     # dup counts written as equ names
    results = []
    for f in files:
        scan_file(f, results)
        scan_sections(f, results)
    n_str = 0
    n_scalar = 0
    n_bss = 0
    n_unsized = 0
    for cat, fname, line, name, kind, off, msg in results:
        if name in ALLOWLIST: continue
        if cat == "unsized":
            n_unsized += 1
            print(f"[UNSIZED] {fname}:{line} {name}: {msg}")
            continue
        if cat == "initialised-bss":
            n_bss += 1
            print(f"[BLOAT] {fname}:{line} {name}: {msg}")
            continue
        if cat == "scalar" and not args.scalars:
            n_scalar += 1
            continue
        if cat == "string": n_str += 1
        else: n_scalar += 1
        print(f"[{cat}] {fname}:{line} {name}: {msg}")
    n_str += n_bss
    print(f"aligncheck: {n_str - n_bss} misaligned strings"
          + (f", {n_bss} oversized .data array(s)" if n_bss else "")
          + (f", {n_unsized} unsized decl(s) - coverage gap" if n_unsized else "")
          + (f", {n_scalar} scalars (review)" if n_scalar else "")
          + f" ({'clean' if n_str == 0 else 'MISALIGNMENT PRESENT'})")
    n_str += floors.check("aligncheck", {"scalars": n_scalar})
    sys.exit(min(n_str, 255))

if __name__ == "__main__":
    main()
