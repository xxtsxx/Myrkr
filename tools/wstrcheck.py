#!/usr/bin/env python3
"""wstrcheck - every bounded-copy call site actually passes its bound.

wcopy (gui.asm) copies a wide string until the source's NUL.  It takes the limit
in r8: the address of the last writable wide char in the destination.  A call
site that forgets to set r8 does not fail to build and does not fail visibly --
it copies against whatever r8 happened to hold, which is either a limit far too
small (silent truncation) or far too large (no bound at all, which is where this
function started: it took no bound, and gui_main copied argv[i] -- up to
MAX_PATH_CHARS wide chars -- into a 4096-wchar input slot).

That is a register contract, and register contracts are exactly what nothing
else in this build checks: the assembler is happy, the linker is happy, and the
overflow lands in .data? where neither the stack canary nor either shadow stack
can see it.

So: every call must set r8 within the few instructions before it.  The bound may
arrive three ways --
  * WBOUND r8, <buf>, <CHARS>   the macro, for a fixed destination
  * lea/mov r8, ...             computed, e.g. from a caller-supplied dst
  * call slot_addr              which returns rax = slot base AND r8 = its bound,
                                because slot 0 and slots 1..N differ in capacity

Exit code: number of call sites missing their bound (so "build strict" gates).
Usage: python tools/wstrcheck.py
"""
import re, os, sys, glob
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.normpath(os.path.join(HERE, "..", "src"))

# callee -> (register that carries the bound, how many lines back to look)
CONTRACTS = {
    "wcopy": ("r8", 8),
    # shellext.asm's bounded append, same contract and same reason.  It matters
    # more there, not less: that copy builds a command line inside explorer.exe,
    # and an unbounded one would overflow a heap block rather than a .data?
    # buffer.  wapp_lim returns 0 instead of truncating, so a missed bound is
    # the only way its callers can be wrong.
    "wapp_lim": ("r8", 8),
}

SETS = {
    "r8": re.compile(r'^\s*(?:(lea|mov|xor)\s+r8d?\s*,'
                     r'|WBOUND\s+r8\s*,'
                     r'|call\s+slot_addr\s*$)', re.I),
}


def main():
    bad = total = 0
    for path in sorted(glob.glob(os.path.join(SRC, "*.asm"))):
        base = os.path.basename(path)
        lines = [l.split(";")[0] for l in open(path, encoding="latin-1").read().split("\n")]
        for i, l in enumerate(lines):
            m = re.match(r'^\s*call\s+(\w+)\s*$', l.rstrip())
            if not m or m.group(1) not in CONTRACTS:
                continue
            reg, back = CONTRACTS[m.group(1)]
            total += 1
            window = lines[max(0, i - back):i]
            if not any(SETS[reg].match(w) for w in window):
                bad += 1
                print(f"[NO BOUND] {base}:{i+1} call {m.group(1)} without setting {reg} "
                      f"in the {back} lines before it - the copy would run against "
                      f"whatever {reg} happened to hold")
    print(f"wstrcheck: {bad} unbounded call site(s) across {total} bounded-copy call(s) "
          f"({'clean' if bad == 0 else 'UNBOUNDED COPY PRESENT'})")
    bad += floors.check("wstrcheck", {"calls": total})
    sys.exit(min(bad, 255))


if __name__ == "__main__":
    main()
