#!/usr/bin/env python3
"""Phase 2: fault-injection measurement of the memory-safety controls.

Runs each `myrkr redteam <case>` in a child process and asserts the control
fired: the child must terminate abnormally with the expected fastfail code
(read from the instrumented build's "FFxxxx" print) or, for the IAT test, an
access violation.  A control that lets the violation return (clean exit) is a
FAIL.  Requires the dbg build (build dbg).

Usage:  python redteam.py <path-to-dbg-myrkr.exe>
"""
import os, re, sys, subprocess

STATUS_AV   = 0xC0000005
# In the instrumented (dbg) build ff_trap exits 0xFADE<code> so the exact check
# that fired can be read from the child's exit status (console-independent).
FADE_MASK   = 0xFFFF0000
FADE_TAG    = 0xFADE0000

# case -> expected FF code.  Every case reports through the 0xFADE<code> exit
# status, including "iat": judging that one by the exit status of an UNHANDLED
# access violation measured how Windows reported the death rather than whether
# the mitigation fired, and ntdll fast-failing during dispatch (0xC0000409) made
# a working control report FAIL on roughly a third of runs.
# None still means "expect a bare access violation" if a future case needs it.
CASES = {
    "canary":    0x0002,   # FF_STACK_COOKIE
    "shadow":    0xF001,   # FF_SHADOW_STACK
    "dlpv":      0x000A,   # FF_GUARD_ICALL
    "overflow":  0xF005,   # FF_OVERFLOW
    "bounds":    0xF004,   # FF_BOUNDS
    "typemagic": 0xF003,   # FF_TYPE_MAGIC
    "heaptag":   0xF002,   # FF_HEAP_TAG
    "iat":       0x1A70,   # FF_IAT_RO: AV on a write to the locked IAT slot
}

def run(exe, args):
    p = subprocess.run([exe]+args, capture_output=True, timeout=60)
    return (p.returncode & 0xFFFFFFFF), p.stdout+p.stderr

def main():
    exe = os.path.abspath(sys.argv[1])
    print(f"exe={exe}\n== Phase 2: memory-safety control fault injection ==")
    passed = 0
    for case, want_ff in CASES.items():
        rc, out = run(exe, ["redteam", case])
        got_ff = (rc & ~FADE_MASK) if (rc & FADE_MASK)==FADE_TAG else None
        if want_ff is None:                                  # IAT: access violation
            ok = (rc == STATUS_AV)
            detail = f"exit=0x{rc:08X} (want AV 0x{STATUS_AV:08X})"
        else:                                                # fastfail, code encoded
            ok = (got_ff == want_ff)
            detail = f"exit=0x{rc:08X} FF={('0x%03X'%got_ff) if got_ff is not None else None} (want 0x{want_ff:03X})"
        passed += ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {case:<10} {detail}")

    # no-false-positive: the instrumented binary must run a benign op cleanly
    rc, out = run(exe, ["selftest"])
    nofp = (rc == 0)
    print(f"  [{'PASS' if nofp else 'FAIL'}] {'selftest':<10} benign op no spurious fastfail (exit={rc})")
    passed += nofp

    total = len(CASES)+1
    print(f"\nTOTAL: {passed}/{total} controls measured-effective")
    return 0 if passed==total else 1

if __name__=="__main__":
    sys.exit(main())
