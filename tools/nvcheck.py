#!/usr/bin/env python3
"""nvcheck - every proc that writes a callee-saved register saves and restores it.

The Windows x64 ABI makes rbx, rbp, rsi, rdi, r12-r15 and xmm6-xmm15
NON-VOLATILE: a function may use them only if it puts them back.  Nothing in
this build checked that.  argon2id_hash used r12, r13 and r15 as scratch for
years without saving them, so every key derivation returned to its caller -
ours, or user32/kernel32 above a window procedure or a thread start - with
three registers changed under it.  Nothing visibly broke, which is luck, not a
property: the day a caller kept a pointer in r12 across derive_key it would
have followed garbage.  Vordr had already fixed its copy; this one was found by
comparing the two (2026-10-11).

Rule, per proc: for each non-volatile register the proc WRITES, there must be a
save before the first write (push reg, or a store of reg to memory) and a
restore somewhere in the proc (pop reg, or a load of reg from memory).  rbp is
left to framecheck - FRAME_PROLOG and every raw prologue push it.

What it cannot see: writes inside a macro body (the proc only shows the macro's
name - GBM in argon2.asm writes nothing non-volatile, and argon2_compress_scalar
saves rsi around it), and a restore on one exit path but not another.  It is a
gate on the shape, not a proof.

Exit code: number of findings (so "build strict" can gate on it).
Usage: python tools/nvcheck.py
"""
import re, os, sys, glob
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.normpath(os.path.join(HERE, "..", "src"))

GPR = {
    'rbx': ['rbx', 'ebx', 'bx', 'bl', 'bh'],
    'rsi': ['rsi', 'esi', 'si', 'sil'],
    'rdi': ['rdi', 'edi', 'di', 'dil'],
}
for r in ('r12', 'r13', 'r14', 'r15'):
    GPR[r] = [r, r + 'd', r + 'w', r + 'b']
XMM = {f'xmm{n}': [f'xmm{n}', f'ymm{n}'] for n in range(6, 16)}
REGS = {**GPR, **XMM}

# Procs that never return to a caller, so they owe nobody their registers.
# Each entry says why; adding one is a reviewable line, not a silent pass.
EXEMPT = {
    'ff_trap': 'the fastfail trap: it raises __fastfail and the process ends',
}

# An instruction whose FIRST operand is written.
WRITE = re.compile(r'^(?:v?mov\w*|lea|xor|v?pxor|add|sub|inc|dec|and|or|not|neg|shl|shr|sar|sal|'
                   r'rol|ror|rcl|rcr|imul|adc|sbb|cmov\w+|set\w+|bswap|xchg|pop|v?movdq\w|'
                   r'v?pshuf\w*|v?padd\w*|v?psub\w*|v?pand\w*|v?por|v?psll\w*|v?psrl\w*|v?pal\w*|'
                   r'v?punpck\w*|v?pclmul\w*|aes\w+|v?pinsr\w|v?pblend\w*|v?perm\w*|v?pmul\w*|'
                   r'v?pcmp\w*|v?shuf\w*|v?xorp\w|v?andp\w|v?orp\w|vinserti128|vextracti128|'
                   r'vpbroadcast\w*|vzero\w*)\s+(\w+)\b', re.I)


def scan(path):
    findings, procs = [], 0
    lines = open(path, encoding='latin-1').read().split('\n')
    name = None
    for i, raw in enumerate(lines, 1):
        l = raw.split(';', 1)[0].strip()
        m = re.match(r'^(\w+)\s+proc\b', l, re.I)
        if m:
            name, start, saved, restored, written = m.group(1), i, set(), set(), {}
            continue
        if name is None:
            continue
        if re.match(r'^' + re.escape(name) + r'\s+endp\b', l, re.I):
            procs += 1
            if name not in EXEMPT:
                for r, line in sorted(written.items(), key=lambda kv: kv[1]):
                    if r not in saved:
                        findings.append(f"[NV] {os.path.basename(path)}:{line} {name} writes {r} "
                                        f"without saving it first (callee-saved, Windows x64 ABI)")
                    elif r not in restored:
                        findings.append(f"[NV] {os.path.basename(path)}:{start} {name} saves {r} "
                                        f"but never restores it")
            name = None
            continue
        if not l:
            continue
        lo = l.lower()
        for r, aliases in REGS.items():
            alt = '|'.join(aliases)
            # saves: push r, or a store of r into memory (before its first write)
            if re.match(r'^push\s+(' + alt + r')\b', lo) or \
               re.match(r'^\S+\s+(?:\w+\s+ptr\s*)?\[[^\]]*\]\s*,\s*(' + alt + r')\b', lo):
                if r not in written:
                    saved.add(r)
            # restores: pop r, or a load of r from memory after it was saved.  Any
            # base register: the SIMD compress routines keep their xmm save area
            # behind r11, not at a fixed rbp/rsp offset.
            if re.match(r'^pop\s+(' + alt + r')\b', lo) or \
               (r in saved and re.match(r'^\S+\s+(' + alt + r')\s*,\s*(?:\w+\s+ptr\s*)?\[[^\]]*\]', lo)):
                restored.add(r)
                if lo.startswith('pop'):
                    continue
            w = WRITE.match(lo)
            if w and w.group(1) in aliases and not lo.startswith('push'):
                written.setdefault(r, i)
    return findings, procs


def main():
    findings, procs = [], 0
    for path in sorted(glob.glob(os.path.join(SRC, '*.asm'))):
        f, p = scan(path)
        findings += f
        procs += p
    for f in findings:
        print(f)
    print(f"nvcheck: {len(findings)} finding(s) across {procs} procs "
          f"({'clean' if not findings else 'CALLEE-SAVED REGISTER CLOBBERED'})")
    bad = len(findings) + floors.check("nvcheck", {"procs": procs})
    sys.exit(min(bad, 255))


if __name__ == "__main__":
    main()
