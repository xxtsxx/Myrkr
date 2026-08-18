#!/usr/bin/env python3
"""framecheck - static stack-frame safety scanner for Myrkr's MASM sources.

Ported from Vordr, where each rule below was added after a bug of that shape got
past both the assembler and a careful read.

Two proc shapes are scanned:

1. FRAME_PROLOG procs: flag procs where the stack-arg spill of the widest
   WINCALL (args 5+ go to [rsp+32], [rsp+40], ...) could overlap the proc's
   deepest [rbp-N] local.  This is a HEURISTIC: per the project's frame
   convention a spill slot may legally share bytes with a local that is DEAD at
   that call, so these are reported as "warn" and a curated allowlist silences
   the verified-safe sites.  The frame size may be a plain number or any
   constant MASM expression ("FRAME_PROLOG 32 + sizeof ARGON2REQ + 32"); equ
   names and sizeof STRUCT are evaluated from the sources, and a frame whose
   size cannot be resolved is reported as warn (never silently skipped).

2. Raw procs ("push rbp / mov rbp,rsp / sub rsp,N", no FRAME_PROLOG - i.e.
   every proc in gui.asm, which must stay raw because the software shadow stack
   is single-threaded).  These are the dangerous ones:
   - FATAL: a WINCALL (or explicit [rsp+K] arg store) whose spill area extends
     PAST the N-byte frame, clobbering the saved rbp / return address.  In Vordr
     this class crashed a dialog proc (a 14-arg CreateFontW in a sub rsp,64
     frame -> ret to 0 -> BEX64 c0000005 at fault offset 0).
   - WARN:  the spill stays inside the frame but reaches into the proc's
     deepest [rbp-N] local region (possible silent corruption).
   Manual "sub rsp,K ... call ... add rsp,K" extensions and push/pop are
   tracked, so widened call sites are judged with K included.

Exit code: number of FATALs (so "build strict" can gate on it); warns are
informational.  Usage: python tools\\framecheck.py [--src DIR] [--fatal-only]
"""
import re, glob, os, sys, argparse
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.normpath(os.path.join(HERE, "..", "src"))

# FRAME_PROLOG heuristic findings reviewed and accepted (proc names).  Add a
# name here only with a comment saying why the overlapped local is dead at that
# call - an unexplained entry is indistinguishable from a silenced bug.
ALLOW_FP = set()

# Home-space findings that are safe by inspection rather than by frame size
# (e.g. a proc that deliberately aliases an out-param slot with a NULL arg slot).
ALLOW_HOME = set()

# Raw-proc warn findings verified safe.
ALLOW_RAW_WARN = set()

def strip_comment(l):
    q = None; out = []
    for c in l:
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

def join_continuations(lines):
    """Merge trailing-backslash continuation lines; keep original line numbers."""
    out = []
    i = 0
    while i < len(lines):
        ln = i; s = lines[i]
        while s.rstrip().endswith('\\') and i + 1 < len(lines):
            i += 1
            s = s.rstrip()[:-1] + ' ' + lines[i].lstrip()
        out.append((ln, s))
        i += 1
    return out

def wincall_parts(s):
    """(callee, [args]) for a WINCALL line, or (None, []) if not a WINCALL."""
    m = re.search(r'\bWINCALL\s+([\w$]+)\s*(,(.*))?$', s)
    if not m: return (None, [])
    if not m.group(3): return (m.group(1), [])
    depth = 0; cur = ''; args = []
    for c in m.group(3):
        if c in '[(': depth += 1
        elif c in '])': depth -= 1
        if c == ',' and depth == 0:
            args.append(cur.strip()); cur = ''
        else:
            cur += c
    args.append(cur.strip())
    return (m.group(1), args)

def wincall_args(s):
    """Number of args of a WINCALL line (0 if not a WINCALL)."""
    callee, args = wincall_parts(s)
    return len(args) if callee else 0

def clobbers_rax(arg):
    """True if __WSTKARG routes this stack arg through rax."""
    a = arg.strip()
    if a.lower().startswith('addr '): return True       # lea rax, [X]
    if a.lower() in REG64: return False                 # direct store
    if RE_SAFEARG.match(a) and '[' not in a and ' ' not in a:
        return False                                    # absolute constant / equ
    return True                                         # 32-bit or memory -> via rax

RE_PROC   = re.compile(r'^\s*([\w$]+)\s+proc\b', re.I)
RE_ENDP   = re.compile(r'^\s*[\w$]+\s+endp\b', re.I)
RE_FP     = re.compile(r'\bFRAME_PROLOG\s+(.+?)\s*$')
RE_SUBRSP = re.compile(r'^\s*sub\s+rsp\s*,\s*([0-9*+ ]+?)\s*$', re.I)
RE_ADDRSP = re.compile(r'^\s*add\s+rsp\s*,\s*([0-9*+ ]+?)\s*$', re.I)
RE_PUSH   = re.compile(r'^\s*push\s+\w+', re.I)
RE_POP    = re.compile(r'^\s*pop\s+\w+', re.I)
# A local is referenced either as [rbp-N] or, when its ADDRESS is handed to an
# API, as "addr rbp-N".  Missing the second form hides an output buffer inside
# the call's own home space.
RE_LOCAL  = re.compile(r'(?:\[rbp\s*-\s*(\d+)\]|\baddr\s+rbp\s*-\s*(\d+)\b)', re.I)
RE_EXTERN = re.compile(r'^\s*extern\s+([\w$]+)\s*:\s*proc', re.I)
# __WSTKARG stores an absolute constant or a 64-bit register straight to [rsp+K];
# everything else (addr X, any 32-bit operand, 64-bit memory) round-trips via rax.
RE_SAFEARG = re.compile(r'^(?:[0-9][0-9a-fx]*h?|r[a-z0-9]+|'
                        r'[A-Z_][A-Z0-9_]*)$', re.I)
REG64 = {'rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
         'r8','r9','r10','r11','r12','r13','r14','r15'}
RE_EQU    = re.compile(r'^\s*([\w$]+)\s+equ\s+(.+?)\s*$', re.I)
RE_STRUCT = re.compile(r'^\s*([\w$]+)\s+struct\b', re.I)
RE_SENDS  = re.compile(r'^\s*[\w$]+\s+ends\b', re.I)
RE_FIELD  = re.compile(r'^\s*(?:[\w$]+\s+)?(db|dw|dd|dq|dt)\b\s*(.*)$', re.I)
FSIZE     = {'db': 1, 'dw': 2, 'dd': 4, 'dq': 8, 'dt': 10}
# a WRITE to [rsp+K]: mov/lea/movdq* with the [rsp+K] as the FIRST operand
RE_RSPST  = re.compile(
    r'^\s*(mov|movdqu|movdqa|movups|movaps|lea)\s+'
    r'(?:(qword|dword|word|byte|xmmword)\s+ptr\s+)?\[rsp\s*\+\s*(\d+)\]\s*,', re.I)
ST_SIZE = {'qword': 8, 'dword': 4, 'word': 2, 'byte': 1, 'xmmword': 16}
RE_MOVRSPBASE = re.compile(r'^\s*mov\s+rsp\s*,\s*rbp', re.I)
RE_POPRBP     = re.compile(r'^\s*pop\s+rbp\b', re.I)

EQUS = {}
STRUCTS = {}
EXTERNS = set()          # `extern X:proc` - a Win32 callee, free to use its home space
STATS = {'fp': 0, 'sym': 0, 'raw': 0}

def masm_int(tok):
    """MASM integer literal -> int or None: decimal, 0x.., or trailing-h hex (0FFh)."""
    t = tok.strip()
    if re.fullmatch(r'\d+', t): return int(t)
    if re.fullmatch(r'0[xX][0-9A-Fa-f]+', t): return int(t, 16)
    if re.fullmatch(r'[0-9][0-9A-Fa-f]*[hH]', t): return int(t[:-1], 16)
    return None

def eval_size(expr, depth=0):
    """Evaluate a MASM size expression: literals, equ names, sizeof STRUCT, + - * / ( ).
    Raises ValueError when anything is unresolvable (caller must surface it)."""
    if depth > 16: raise ValueError("equ cycle")
    expr = expr.strip()
    v = masm_int(expr)
    if v is not None: return v
    m = re.fullmatch(r'sizeof\s+([\w$]+)', expr, re.I)
    if m:
        if m.group(1) not in STRUCTS: raise ValueError(f"unknown struct {m.group(1)}")
        return STRUCTS[m.group(1)]
    # `sizeof NAME` inside a larger expression ("32 + (sizeof ARGON2REQ) + 32"):
    # fold each occurrence to a literal before tokenising, or the loop below
    # meets a bare `sizeof` token and gives up - which silently left derive_key,
    # on the key-derivation path, reported as NOT CHECKED.
    if re.search(r'\bsizeof\b', expr, re.I):
        missing = []
        def _sz(mm):
            name = mm.group(1)
            if name not in STRUCTS:
                missing.append(name)
                return '0'
            return str(STRUCTS[name])
        expr = re.sub(r'\bsizeof\s+([\w$]+)', _sz, expr, flags=re.I)
        if missing:
            raise ValueError(f"unknown struct {missing[0]}")
    out = []
    for t in re.findall(r'[\w$]+|[()+*/-]', expr):
        n = masm_int(t)
        if n is not None:
            out.append(str(n))
        elif re.fullmatch(r'[\w$]+', t):
            if t.lower() == 'sizeof': raise ValueError("sizeof needs a name")
            if t not in EQUS: raise ValueError(f"unknown equ {t}")
            out.append(str(eval_size(EQUS[t], depth + 1)))
        elif t in '()+*/-':
            out.append(t)
        else:
            raise ValueError(f"unresolvable token {t!r}")
    pyexpr = ' '.join(out)
    if not re.fullmatch(r'[0-9()+*/ \-]+', pyexpr): raise ValueError("unsafe expr")
    return int(eval(pyexpr, {'__builtins__': {}}))

def build_tables(files):
    """Collect `NAME equ EXPR` and `NAME struct .. ends` sizes from every source."""
    for path in files:
        raw = [strip_comment(l.rstrip('\n')) for l in open(path, encoding='latin-1')]
        cur = None; size = 0
        for s in raw:
            xm = RE_EXTERN.match(s)
            if xm: EXTERNS.add(xm.group(1))
            em = RE_EQU.match(s)
            if em and not cur: EQUS[em.group(1)] = em.group(2)
            sm = RE_STRUCT.match(s)
            if sm and not cur: cur = sm.group(1); size = 0; continue
            if cur:
                if RE_SENDS.match(s): STRUCTS[cur] = size; cur = None; continue
                fm = RE_FIELD.match(s)
                if fm:
                    cnt = 1
                    dm = re.match(r'(\d+)\s+dup\b', fm.group(2))
                    if dm: cnt = int(dm.group(1))
                    size += cnt * FSIZE[fm.group(1).lower()]

def scan_file(path, results):
    raw = [strip_comment(l.rstrip('\n')) for l in open(path, encoding='latin-1')]
    fname = os.path.basename(path)
    i = 0
    while i < len(raw):
        m = RE_PROC.match(raw[i])
        if not m:
            i += 1; continue
        name = m.group(1); start = i
        end = next((x for x in range(i + 1, len(raw)) if RE_ENDP.match(raw[x])), len(raw) - 1)
        body = raw[start:end + 1]
        merged = join_continuations(body)

        fp = next((RE_FP.search(s) for _, s in merged if 'FRAME_PROLOG' in s), None)
        maxloc = 0
        for _, s in merged:
            for mm in RE_LOCAL.finditer(s):
                maxloc = max(maxloc, int(mm.group(1) or mm.group(2)))

        if fp:
            # ---- heuristic on FRAME_PROLOG procs ----------------------------
            try:
                N = eval_size(fp.group(1))
            except ValueError as e:
                results.append(("warn", fname, start + 1, name,
                    f"FRAME_PROLOG {fp.group(1).strip()!r} frame size unresolvable ({e}) "
                    f"- proc NOT CHECKED"))
                i = end + 1; continue
            STATS['fp'] += 1
            if masm_int(fp.group(1)) is None: STATS['sym'] += 1
            alloc = ((N + 8 + 15) & ~15)
            maxargs = 0; at = start
            for ln, s in merged:
                n = wincall_args(s)
                if n > maxargs: maxargs = n; at = start + ln
            need = maxloc + 32 + max(0, maxargs - 4) * 8
            if maxargs > 4 and alloc < need and name not in ALLOW_FP:
                results.append(("warn", fname, at + 1, name,
                    f"FRAME_PROLOG {fp.group(1).strip()} (alloc {alloc}) < heuristic need {need} "
                    f"(deepest local -{maxloc}, {maxargs}-arg WINCALL) - "
                    f"verify the overlapped local is dead at that call"))
            # ---- home-space overlap on Win32 callees ------------------------
            # The 32-byte home area belongs to the CALLEE for any arg count, and
            # a Win32 callee really does save nonvolatiles there (GetClientRect
            # homes four on its first instruction).  Internal procs never touch a
            # caller's home space - an unwritten invariant this codebase relies
            # on - so only extern callees are judged here.
            worst = 0; wat = start; wcallee = None
            for ln, s in merged:
                callee, args = wincall_parts(s)
                if not callee or callee not in EXTERNS: continue
                span = 32 + max(0, len(args) - 4) * 8
                if span > worst: worst, wat, wcallee = span, start + ln, callee
                # ---- WINCALL rax-clobber ----------------------------------
                # __WSTKARG emits the stack args BEFORE the register args, and
                # every form except an absolute constant or a 64-bit register
                # goes out through rax.  Passing rax itself as arg 1-4 then
                # loads the wrong value.
                if len(args) > 4 and any(a.strip().lower() in ('rax', 'eax')
                                         for a in args[:4]) \
                   and any(clobbers_rax(a) for a in args[4:]):
                    results.append(("FATAL", fname, start + ln + 1, name,
                        f"WINCALL {callee} passes rax as a register arg while a "
                        f"later stack arg routes through rax - the register arg "
                        f"receives the WRONG value; stage the handle in a local"))
            if worst and alloc - maxloc < worst and maxloc \
               and name not in ALLOW_FP and name not in ALLOW_HOME:
                results.append(("warn", fname, wat + 1, name,
                    f"FRAME_PROLOG {fp.group(1).strip()} (alloc {alloc}): local "
                    f"-{maxloc} lies in {wcallee}'s home/arg area (rsp..rsp+{worst}) "
                    f"- a Win32 callee may save registers over it"))
        else:
            # ---- raw proc ---------------------------------------------------
            # find the raw prologue: sub rsp,N within the first few lines
            N = None; pidx = None
            for idx, (ln, s) in enumerate(merged[:6]):
                sm = RE_SUBRSP.match(s)
                if sm: N = eval(sm.group(1)); pidx = idx; break
            if N is None:
                i = end + 1; continue   # leaf/trampoline without a frame
            STATS['raw'] += 1
            extra = 0                    # manual sub/add rsp + push/pop tracking
            tail = merged[pidx + 1:]
            # An "add rsp, N" whose next code line is "pop rbp" is an EPILOGUE,
            # not a frame shrink: control resumes at the following label with the
            # original frame intact.  gui.asm's raw procs return through several
            # such exits, and counting each one drove the running total negative,
            # reporting an impossible frame and a phantom FATAL in
            # slider_subclass.  Vordr's procs epilogue with "mov rsp, rbp"
            # instead, which RE_MOVRSPBASE already handled, so its version never
            # saw this idiom.  Mark both lines of each pair as epilogue.
            epilogue = set()
            epilogue_add = {}            # index of the "add rsp,N" -> N
            for k, (_, s) in enumerate(tail):
                am0 = RE_ADDRSP.match(s)
                if not am0:
                    continue
                nxt = next(((j, t) for j, (_, t) in enumerate(tail[k + 1:k + 3])
                            if t.strip()), None)
                if nxt and RE_POPRBP.match(nxt[1]):
                    epilogue.add(k)
                    epilogue.add(k + 1 + nxt[0])
                    epilogue_add[k] = eval(am0.group(1))
            for k, (ln, s) in enumerate(tail):
                # ---- the epilogue must give back exactly what the prologue took.
                # A raw proc writes its frame size TWICE, by hand, and the two can
                # be edited apart: raise "sub rsp,160" to 256 for a bigger local,
                # leave "add rsp,160" alone, and every return pops rbp and then the
                # return address from 96 bytes below where they were pushed.  The
                # process jumps to whatever that stack slot held.
                #
                # It costs nothing to check and it is invisible otherwise: the
                # assembler is happy, the linker is happy, and the failure arrives
                # as an access violation in no module at all (WER buckets it BEX64,
                # "faulting module: unknown").  That is exactly how it presented in
                # myrkrshell.dll's QueryContextMenu, where it took explorer.exe
                # down on every right-drag.
                if k in epilogue_add:
                    want = N + extra
                    if epilogue_add[k] != want:
                        results.append(("FATAL", fname, start + ln + 1, name,
                            f"epilogue gives back {epilogue_add[k]} bytes but the frame "
                            f"is {want} (sub rsp,{N}"
                            + (f" plus {extra} pushed since" if extra else "")
                            + ") - pop rbp and ret then read the wrong slots"))
                    extra = 0; continue
                if k in epilogue:
                    extra = 0; continue  # frame restored for the next label
                if RE_MOVRSPBASE.match(s):
                    extra = 0; continue  # epilogue "mov rsp, rbp"
                sm = RE_SUBRSP.match(s)
                if sm:
                    extra += eval(sm.group(1)); continue
                am = RE_ADDRSP.match(s)
                if am: extra -= eval(am.group(1)); continue
                if RE_PUSH.match(s): extra += 8; continue
                if RE_POP.match(s):  extra -= 8; continue

                spill_end = 0; desc = None; live_end = 0
                n = wincall_args(s)
                if n > 4:
                    spill_end = 32 + 8 * (n - 4)
                    desc = f"{n}-arg WINCALL"
                    # A stack arg whose SOURCE is the very slot it is stored to
                    # is a no-op: __WSTKARG loads [rbp-M] and writes it back to
                    # [rsp+K], and for this frame those are the same address.
                    # Such a slot cannot corrupt anything, so it must not count
                    # toward the "reaches the local region" warning - otherwise
                    # the idiom that dr_text/draw_logo/list_subclass all use
                    # produces a permanent warn nobody can act on.
                    _, cargs = wincall_parts(s)
                    frame_now = N + extra
                    live_end = 32
                    for k in range(4, len(cargs)):
                        dest = 32 + 8 * (k - 4)
                        m_self = re.fullmatch(
                            r'(?:qword|dword|word|byte)\s+ptr\s+\[rbp\s*-\s*(\d+)\]',
                            cargs[k].strip(), re.I)
                        if m_self and int(m_self.group(1)) == frame_now - dest:
                            continue                # self-write: harmless
                        live_end = max(live_end, dest + 8)
                else:
                    # explicit write to [rsp+K] (outgoing arg or xmm save)
                    mm = RE_RSPST.match(s)
                    if mm:
                        op = mm.group(1).lower()
                        sz = 16 if op.startswith('movdq') or op in ('movups', 'movaps') \
                             else ST_SIZE.get((mm.group(2) or 'qword').lower(), 8)
                        k = int(mm.group(3))
                        if k + sz > spill_end:
                            spill_end = k + sz; desc = f"{sz}-byte store to [rsp+{k}]"
                            live_end = spill_end
                if not spill_end: continue

                frame = N + extra
                if spill_end > frame:
                    results.append(("FATAL", fname, start + ln + 1, name,
                        f"{desc} spills to rsp+{spill_end - 8} but the raw frame is "
                        f"only {frame} bytes (sub rsp,{N}{f' +{extra} manual' if extra else ''}) "
                        f"- saved rbp/return address clobbered (BEX64 class)"))
                elif live_end > frame - maxloc and maxloc and name not in ALLOW_RAW_WARN:
                    results.append(("warn", fname, start + ln + 1, name,
                        f"{desc} spill (to rsp+{live_end - 8}) reaches the local region "
                        f"(frame {frame}, deepest local -{maxloc}) - verify liveness"))
        i = end + 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEF_SRC)
    ap.add_argument("--fatal-only", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="count warns toward the exit code.  The tree is at zero "
                         "warns; gating keeps it there, so a new overlap has to be "
                         "either fixed or allowlisted with a reason, not just "
                         "printed into a list nobody reads.")
    args = ap.parse_args()
    files = sorted(glob.glob(os.path.join(args.src, "*.asm")))
    inc = os.path.join(args.src, "macros.inc")
    build_tables(files + ([inc] if os.path.exists(inc) else []))
    results = []
    for f in files:
        scan_file(f, results)
    fatals = 0
    for sev, fname, line, name, msg in results:
        if sev == "FATAL": fatals += 1
        if args.fatal_only and sev != "FATAL": continue
        print(f"[{sev}] {fname}:{line} {name}: {msg}")
    n_warn = sum(1 for r in results if r[0] == 'warn')
    print(f"framecheck: {fatals} fatal, {n_warn} warn "
          f"({'clean' if fatals == 0 else 'FRAME BUGS PRESENT'}); "
          f"{STATS['fp']} FRAME_PROLOG + {STATS['raw']} raw procs checked "
          f"({STATS['sym']} symbolic-size)")
    fatals += floors.check("framecheck", {"procs": STATS['fp'], "raw": STATS['raw']})
    if args.strict:
        fatals += n_warn
    sys.exit(min(fatals, 255))

if __name__ == "__main__":
    main()
