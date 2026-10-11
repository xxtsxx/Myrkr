#!/usr/bin/env python3
"""A zip that LIES about an entry's size must cost what the entry is, not what it claims.

The central directory states each entry's compressed and uncompressed size, and
both are the archive's word.  Up to 1.1.5 three buffers were sized from them and
then wiped on the way out at the claimed size - every page of a never-touched
VirtualAlloc region faulted in to be zeroed:

  - zip_entry_to_mem (a drag-out of a zip row) allocated the declared
    uncompressed size and, on failure, wiped all of it: a 64 KiB entry claiming
    3 GiB drove the process to 2.9 GiB of working set - on the GUI thread;
  - extract_zip_entry's deflate output buffer was freed with a wipe of the
    declared uncompressed size (up to the 512 MiB deflate cap) whatever inflate
    actually produced - this one in every extraction, CLI and window alike;
  - its input buffer was sized from the declared COMPRESSED size with nothing
    holding that inside the archive (zip_delete always checked; extraction did
    not), so a short read was followed by a wipe of the whole claim;
  - zip_read_cd sized the central directory from the end record, capped at
    256 MiB but not held inside the file, and every caller wiped it on failure.

Each case below measures the child's PEAK working set after it exits
(GetProcessMemoryInfo on the still-open handle), so nothing depends on sampling
a process that finishes in milliseconds.  Shown failing against 1.1.5 with
tools/compare.ps1.

    python tests/zipclaimtest.py <testio or dbg myrkr.exe>
"""
import os, sys, struct, zipfile, subprocess, tempfile, shutil, uuid, ctypes
from ctypes import wintypes

PW = 'Correct-Horse-Battery-9'          # dataobj takes -p even for a plain zip
LIMIT = 200 * 1024 * 1024               # far above an honest run (~10 MiB), far
                                        # below any of the claims (500 MiB+)

class PMC(ctypes.Structure):
    _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]
_psapi = ctypes.WinDLL('psapi')
_psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]

def run(exe, args):
    p = subprocess.Popen([exe, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = p.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        p.kill(); out, err = p.communicate()
        return 'HANG', 0, ''
    m = PMC(); m.cb = ctypes.sizeof(PMC)
    _psapi.GetProcessMemoryInfo(int(p._handle), ctypes.byref(m), m.cb)
    return p.returncode & 0xFFFFFFFF, m.PeakWorkingSetSize, (out + err).decode(errors='replace')

def main():
    exe = os.path.abspath(sys.argv[1])
    w = os.path.join(tempfile.gettempdir(), 'myrkr-zipclaim-' + uuid.uuid4().hex[:8])
    os.makedirs(w)
    fails = []
    def check(ok, what):
        print('  %s %s' % ('ok  ' if ok else 'FAIL', what), flush=True)
        if not ok: fails.append(what)

    data = os.urandom(32768) + b'A' * 32768
    honest = os.path.join(w, 'honest.zip')
    with zipfile.ZipFile(honest, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('big.bin', data)
    raw = open(honest, 'rb').read()
    cd, lh = raw.find(b'PK\x01\x02'), raw.find(b'PK\x03\x04')

    def variant(name, usize=None, csize=None, badcrc=False):
        b = bytearray(raw)
        if usize is not None:
            struct.pack_into('<I', b, cd + 24, usize); struct.pack_into('<I', b, lh + 22, usize)
        if csize is not None:
            struct.pack_into('<I', b, cd + 20, csize); struct.pack_into('<I', b, lh + 18, csize)
        if badcrc:
            b[cd + 16] ^= 0xFF; b[lh + 14] ^= 0xFF
        p = os.path.join(w, name); open(p, 'wb').write(b); return p

    # The end record's directory size: capped at 256 MiB (CD_CAP), but not by the
    # file until this test - so a 250 MiB claim committed and then wiped 250 MiB.
    eocd = raw.rfind(b'PK\x05\x06')
    b = bytearray(raw); struct.pack_into('<I', b, eocd + 12, 250 * 1024 * 1024)
    cdliar = os.path.join(w, 'cd250m.zip'); open(cdliar, 'wb').write(b)
    liar = variant('claims3g.zip', usize=0xC0000000)
    liar500 = variant('claims500m-badcrc.zip', usize=500 * 1024 * 1024, badcrc=True)
    cliar = variant('csize3g.zip', csize=0xC0000000)

    def outdir():
        d = os.path.join(w, uuid.uuid4().hex[:6]); os.makedirs(d); return d

    print('== an honest zip still works both ways ==')
    d = outdir()
    rc, peak, log = run(exe, ['dataobj', honest, '-o', d, '-p', PW])
    got = os.path.join(d, 'es_0.bin')
    check(rc == 0 and os.path.exists(got) and open(got, 'rb').read() == data,
          'drag-out of the honest entry: exit %s, contents byte-identical' % rc)
    d = outdir()
    rc, peak, log = run(exe, ['unzip', honest, '-o', d])
    got = os.path.join(d, 'big.bin')
    check(rc == 0 and os.path.exists(got) and open(got, 'rb').read() == data,
          'unzip of the honest entry: exit %s, contents byte-identical' % rc)

    print('== lies about the size cost nothing ==')
    for label, z, verbs in (
            ('claims 3 GiB uncompressed', liar, ('dataobj', 'unzip')),
            ('claims 500 MiB, CRC wrong', liar500, ('dataobj', 'unzip')),
            ('claims 3 GiB compressed', cliar, ('dataobj', 'unzip')),
            ('claims a 250 MiB directory', cdliar, ('dataobj', 'unzip'))):
        for verb in verbs:
            args = [verb, z, '-o', outdir()] + (['-p', PW] if verb == 'dataobj' else [])
            rc, peak, log = run(exe, args)
            ok = rc != 0 and rc != 'HANG' and peak < LIMIT and not (isinstance(rc, int) and rc >= 0xC0000000)
            check(ok, '%s, %s: refused (exit %s), peak working set %d MiB'
                  % (label, verb, rc, peak // (1024 * 1024)))
    # The compressed-size lie is not just expensive, it is impossible: the bytes
    # cannot extend past the end of the file.  unzip should call it corrupt.
    rc, peak, log = run(exe, ['unzip', cliar, '-o', outdir()])
    check(rc == 4, 'a compressed size past the end of the archive is corrupt input (exit %s)' % rc)

    shutil.rmtree(w, ignore_errors=True)
    print('\n%s' % ('zipclaimtest: all checks passed' if not fails else '%d FAILURE(S)' % len(fails)))
    return 1 if fails else 0

if __name__ == '__main__':
    sys.exit(main())
