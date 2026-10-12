#!/usr/bin/env python3
"""A fatal fault inside Myrkr is contained: secrets wiped, no crash dialog, a
breadcrumb that names the fault, and an exit the harness can recognise.

Until 1.1.6 Myrkr had no crash handling at all.  A fault went to Windows Error
Reporting with the password, key and plaintext still in memory - a crash dump is
a file - and a fault while the password prompt held the private desktop left the
user on an empty screen.  hardening.asm's crash containment (ported from Vordr)
handles both; this drives it with `myrkr redteam crash`, an ordinary access
violation raised inside the image.

Checked:
  - the process ends promptly with 0xC0000409 (TerminateProcess from
    crash_contain) - a WER dialog would hold it open until the timeout;
  - %TEMP%\\myrkr_crash.bin exists, written by crash_dump, which runs only
    from the handlers: code 0xC0000005, an address inside the image, and the
    image base - 24 bytes, no register contents;
  - nothing on stderr from Windows' own fault reporting.
What it cannot see from outside: the wipe itself (the memory is gone with the
process).  crash_contain wipes before it does anything else, and the breadcrumb
is written immediately before that call.

Needs a dbg build (`redteam` exists only there); run.ps1 hosts it in Phase 2.

    python tests/crashtest.py <dbg myrkr.exe>
"""
import os, sys, struct, subprocess, tempfile

def main():
    exe = os.path.abspath(sys.argv[1])
    crumb = os.path.join(tempfile.gettempdir(), 'myrkr_crash.bin')
    if os.path.exists(crumb):
        os.remove(crumb)
    fails = []
    def check(ok, what):
        print('  %s %s' % ('ok  ' if ok else 'FAIL', what), flush=True)
        if not ok: fails.append(what)

    try:
        p = subprocess.run([exe, 'redteam', 'crash'], capture_output=True, timeout=30)
        rc = p.returncode & 0xFFFFFFFF
    except subprocess.TimeoutExpired:
        rc = None
    check(rc is not None, 'the process ended by itself - no crash dialog held it open')
    check(rc == 0xC0000409, 'exit 0xC0000409 from crash_contain (got %s)' % (hex(rc) if rc is not None else 'timeout'))
    check(os.path.exists(crumb), 'the breadcrumb %s was written' % crumb)
    if os.path.exists(crumb):
        b = open(crumb, 'rb').read()
        check(len(b) == 24, 'it is 24 bytes - code, address, base, no registers (got %d)' % len(b))
        if len(b) >= 24:
            code, _pad, addr, base = struct.unpack('<IIQQ', b[:24])
            check(code == 0xC0000005, 'it names an access violation (0x%08X)' % code)
            check(base != 0 and base <= addr < base + 0x10000000,
                  'at an address inside the image (0x%X, base 0x%X)' % (addr, base))
        os.remove(crumb)
    print('\n%s' % ('crashtest: all checks passed' if not fails else '%d FAILURE(S)' % len(fails)))
    return 1 if fails else 0

if __name__ == '__main__':
    sys.exit(main())
