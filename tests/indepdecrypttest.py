#!/usr/bin/env python3
"""Decrypt Myrkr's containers with an implementation that shares nothing with it.

Every other test reads a container back with Myrkr's own reader, and a writer
and a reader that make the same mistake agree with each other perfectly - a
round trip cannot see it.  This one cannot share a mistake: Argon2id is written
here from RFC 9106, AES-GCM is pycryptodomex, and the layout is taken from the
definitions in src/macros.inc.  If Myrkr and its definition part company - a
nonce, an AAD, the KCV, the index, the segment walk, the volume slicing - this
fails, whichever side moved.

It found one on its first run (2026-10-11): Myrkr's Argon2id is NOT RFC 9106.
argon2.asm indexes the data-independent address block with a call counter that
starts at 0 in every segment; the RFC indexes it with the block's position,
which in pass 0 / slice 0 starts at 2.  The two agree only when a segment holds
two blocks - which is exactly the RFC's own test vector (m=32, p=4), so the
self-test could never see it.  Not a weakness (the same PRF values, shifted by
two, each used once), but no standard Argon2 library derives a Myrkr key.
Containers up to header version 8 depend on it, so it is reproduced here as the
format's KDF for those versions (myrkr_counter=True) and pinned: the test checks
that the standard function does NOT open them, so a change to either side is
noticed rather than absorbed.  A version that adopts the standard function is
expected to be decrypted with it - see kdf_for().

SHOWN TO FAIL: a mutant that wrote ordinal+1 into every entry's AAD - writer
and reader alike, since both go through entry_stream_open - still passed
Myrkr's own `verify` ("OK (authentic)"), and failed every container case here
with "MAC check failed".  That is the class of mistake this file exists for.

Needs a dbg build: the segmented and split cases use MYRKR_DBG_SEGBYTES and
MYRKR_DBG_VOLBYTES, and encrypt takes -p.  pycryptodomex comes with pyzipper.

    python tests/indepdecrypttest.py <dbg myrkr.exe>
"""
import os, sys, re, struct, hashlib, ctypes, subprocess, tempfile, shutil, uuid
from Cryptodome.Cipher import AES

sys.stdout.reconfigure(encoding='utf-8')

# ============================================================== Argon2id ====
M64 = (1 << 64) - 1

def _le32(x): return struct.pack('<I', x)
def _h(data, n): return hashlib.blake2b(data, digest_size=n).digest()

def hprime(x, t):                                  # H', RFC 9106 3.3
    if t <= 64:
        return _h(_le32(t) + x, t)
    r = -(-t // 32) - 2
    v = _h(_le32(t) + x, 64); out = v[:32]
    for _ in range(r - 1):
        v = _h(v, 64); out += v[:32]
    return out + _h(v, t - 32 * r)

def _gb(v, a, b, c, d):
    va, vb, vc, vd = v[a], v[b], v[c], v[d]
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & M64
    vd ^= va; vd = ((vd >> 32) | (vd << 32)) & M64
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & M64
    vb ^= vc; vb = ((vb >> 24) | (vb << 40)) & M64
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & M64
    vd ^= va; vd = ((vd >> 16) | (vd << 48)) & M64
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & M64
    vb ^= vc; vb = ((vb >> 63) | (vb << 1)) & M64
    v[a], v[b], v[c], v[d] = va, vb, vc, vd

def _p(v):
    _gb(v, 0, 4, 8, 12); _gb(v, 1, 5, 9, 13); _gb(v, 2, 6, 10, 14); _gb(v, 3, 7, 11, 15)
    _gb(v, 0, 5, 10, 15); _gb(v, 1, 6, 11, 12); _gb(v, 2, 7, 8, 13); _gb(v, 3, 4, 9, 14)

_COLS = [[16 * r + 2 * i + k for r in range(8) for k in (0, 1)] for i in range(8)]

def _g(x, y):                                      # compression G, 3.5
    r = [a ^ b for a, b in zip(x, y)]; q = r[:]
    for i in range(8):
        row = q[16 * i:16 * i + 16]; _p(row); q[16 * i:16 * i + 16] = row
    for cols in _COLS:
        col = [q[k] for k in cols]; _p(col)
        for k, val in zip(cols, col): q[k] = val
    return [a ^ b for a, b in zip(q, r)]

def argon2id(pwd, salt, t, m, p, tag_len, secret=b'', ad=b'', myrkr_counter=False):
    """RFC 9106 Argon2id.  myrkr_counter=True reproduces argon2.asm through
    header version 8: the address block indexed by a per-segment call counter
    from 0 instead of by i % 128 (pass 0 / slice 0 starts at i = 2)."""
    y = 2
    h0 = _h(_le32(p) + _le32(tag_len) + _le32(m) + _le32(t) + _le32(0x13) + _le32(y)
            + _le32(len(pwd)) + pwd + _le32(len(salt)) + salt
            + _le32(len(secret)) + secret + _le32(len(ad)) + ad, 64)
    mp = 4 * p * (m // (4 * p)); q = mp // p; sl = q // 4
    B = [[None] * q for _ in range(p)]
    for l in range(p):
        B[l][0] = list(struct.unpack('<128Q', hprime(h0 + _le32(0) + _le32(l), 1024)))
        B[l][1] = list(struct.unpack('<128Q', hprime(h0 + _le32(1) + _le32(l), 1024)))
    zero = [0] * 128
    for r in range(t):
        for s in range(4):
            for l in range(p):
                indep = r == 0 and s < 2
                start = 2 if (r == 0 and s == 0) else 0
                addr, ctr, calls = None, 0, 0
                def next_block():
                    nonlocal ctr
                    ctr += 1
                    return _g(zero, _g(zero, [r, l, s, mp, t, y, ctr] + [0] * 121))
                if indep and start and not myrkr_counter:
                    addr = next_block()            # the RFC: index 2 uses v[2]
                for i in range(start, sl):
                    col = s * sl + i
                    prev = col - 1 if col else q - 1
                    if indep:
                        k = calls if myrkr_counter else i
                        if k % 128 == 0:
                            addr = next_block()
                        rnd = addr[k % 128]; calls += 1
                    else:
                        rnd = B[l][prev][0]
                    j1, j2 = rnd & 0xFFFFFFFF, rnd >> 32
                    rl = l if (r == 0 and s == 0) else j2 % p
                    if r == 0:
                        w = s * sl + i - 1 if rl == l else s * sl - (1 if i == 0 else 0)
                    else:
                        w = q - sl + i - 1 if rl == l else q - sl - (1 if i == 0 else 0)
                    rel = w - 1 - ((w * ((j1 * j1) >> 32)) >> 32)
                    st = 0 if (r == 0 or s == 3) else (s + 1) * sl
                    new = _g(B[l][prev], B[rl][(st + rel) % q])
                    B[l][col] = new if r == 0 else [a ^ b for a, b in zip(new, B[l][col])]
    c = B[0][q - 1]
    for l in range(1, p):
        c = [a ^ b for a, b in zip(c, B[l][q - 1])]
    return hprime(struct.pack('<128Q', *c), tag_len)

def kdf_for(version):
    """The container format's key derivation, by header version.  Every version
    so far uses argon2.asm's counter indexing; when one adopts the standard
    function, add it here rather than changing what older versions mean."""
    return lambda pw, salt, t, m: argon2id(pw, salt, t, m, 1, 32, myrkr_counter=version <= 8)

# ============================================================ the reader ====
HDR_BYTES, TAG, TRAILER = 80, 16, 32

def read_logical(path):
    """The container byte stream: one file, or a volume set's slices joined
    (part 1 upward, final flag on the last - docs/VOLUMES.md)."""
    data = open(path, 'rb').read()
    if data[:4] != b'MVOL':
        return data
    base = re.match(r'(.*)\.part\d{3,4}\.mrk$', path, re.I).group(1)
    out, n = bytearray(), 1
    while True:
        p = next((c for c in (base + '.part%03d.mrk' % n, base + '.part%04d.mrk' % n) if os.path.exists(c)), None)
        if p is None:
            raise ValueError('set incomplete: part %d missing' % n)
        b = open(p, 'rb').read()
        ver, = struct.unpack_from('<I', b, 4); part, flags = struct.unpack_from('<II', b, 20)
        if b[:4] != b'MVOL' or ver != 1 or part != n:
            raise ValueError('bad part header in %s' % p)
        out += b[32:]
        if flags & 1:
            return bytes(out)
        n += 1

def gcm_open(key, counter, seg, aad, ct, tag):
    c = AES.new(key, AES.MODE_GCM, nonce=struct.pack('<QI', counter, seg), mac_len=16)
    c.update(aad)
    return c.decrypt_and_verify(ct, tag)

_cab = None
def xpress(payload, orig):
    """XPRESS through the OS codec - the same one Myrkr uses.  What this test
    owns is the FRAMING around it, not the compressor."""
    global _cab
    if _cab is None:
        _cab = ctypes.WinDLL('cabinet')
        _cab.CreateDecompressor.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        _cab.Decompress.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                    ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        _cab.CloseDecompressor.argtypes = [ctypes.c_void_p]
    h = ctypes.c_void_p()
    assert _cab.CreateDecompressor(3, None, ctypes.byref(h)), 'CreateDecompressor'
    out = ctypes.create_string_buffer(orig); got = ctypes.c_size_t()
    ok = _cab.Decompress(h, payload, len(payload), out, orig, ctypes.byref(got))
    _cab.CloseDecompressor(h)
    assert ok and got.value == orig, 'XPRESS frame did not inflate to its stated size'
    return out.raw[:orig]

def deframe(stream):                               # [u32 orig][u32 payload][payload]...
    out, i = bytearray(), 0
    while i < len(stream):
        orig, pay = struct.unpack_from('<II', stream, i); i += 8
        assert 0 < pay <= orig, 'bad frame %d/%d' % (orig, pay)
        blk = stream[i:i + pay]; i += pay
        out += blk if pay == orig else xpress(blk, orig)
    return bytes(out)

def decrypt(path, password, kdf=None):
    """-> dict with the header fields and files: [(name, flags, content, segments)]."""
    c = read_logical(path)
    hdr = c[:HDR_BYTES]
    magic, ver, t, m = struct.unpack_from('<4sIII', hdr, 0)
    lanes, archive, comp, seg_shift = hdr[16], hdr[17], hdr[18], hdr[19]
    assert magic == b'MYRK' and lanes == 1, 'not a container'
    key = (kdf or kdf_for(ver))(password.encode('utf-8'), hdr[20:52], t, m)
    if hashlib.sha256(key).digest()[:16] != hdr[64:80]:
        raise ValueError('KCV mismatch: the derived key is not the one this container was made with')
    trl = c[-TRAILER:]
    _flags, count, ilen, imagic, rev, nxt = struct.unpack('<IIQ4sIQ', trl)
    assert imagic == b'MIDX', 'no index trailer'
    i0 = len(c) - TRAILER - TAG - ilen
    idx = gcm_open(key, (1 << 63) + rev, 0, hdr + trl, c[i0:i0 + ilen], c[i0 + ilen:i0 + ilen + TAG])
    seg = (1 << seg_shift) if (ver >= 8 and seg_shift) else 0
    files, o = [], 0
    for _ in range(count):
        size, off, stored, ordn, eflags, nlen = struct.unpack_from('<QQQQII', idx, o)
        name = idx[o + 40:o + 40 + nlen].decode('utf-8'); o += 40 + nlen
        ext = c[HDR_BYTES + off:HDR_BYTES + off + stored]
        assert len(ext) == stored, 'extent runs past the payload: ' + name
        plain, s, pos = bytearray(), 0, 0
        while pos < stored:                        # n = ceil(stored / (SEG+16))
            ctlen = stored - pos - TAG if not seg else min(seg, stored - pos - TAG)
            aad = hdr + struct.pack('<Q', ordn) + (struct.pack('<I', s) if ver >= 8 else b'')
            plain += gcm_open(key, ordn + 1, s, aad, ext[pos:pos + ctlen], ext[pos + ctlen:pos + ctlen + TAG])
            pos += ctlen + TAG; s += 1
        plain = deframe(bytes(plain)) if comp else bytes(plain)
        if archive:
            assert plain[257:262] == b'ustar', 'no ustar header: ' + name
            body = plain[512:512 + size]
        else:
            body = plain[:size]
        files.append((name, eflags, body, s))
    assert o == len(idx), 'index has %d bytes past its last entry' % (len(idx) - o)
    return dict(version=ver, comp=comp, seg=seg, rev=rev, next=nxt, count=count, files=files)

# ================================================================= the run ====
def main():
    exe = os.path.abspath(sys.argv[1])
    work = os.path.join(tempfile.gettempdir(), 'myrkr-indep-' + uuid.uuid4().hex[:8])
    os.makedirs(work)
    fails = []
    def check(ok, what):
        print('  %s %s' % ('ok  ' if ok else 'FAIL', what), flush=True)
        if not ok: fails.append(what)

    # ---- the reference itself, before it is trusted with anything ----------
    print('== Argon2id reference ==')
    check(argon2id(b'\x01' * 32, b'\x02' * 16, 3, 32, 4, 32, b'\x03' * 8, b'\x04' * 12).hex()
          == '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
          'RFC 9106 5.3 vector (t=3, m=32 KiB, p=4, secret, ad)')
    # The RFC vector cannot see the address-block indexing (a 2-block segment
    # computes nothing in slice 0); this one, from the reference implementation's
    # test.c, is single-lane and 64 MiB - it exercises all of it.
    check(argon2id(b'password', b'somesalt', 2, 65536, 1, 32).hex()
          == '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7',
          'reference test.c vector (t=2, m=64 MiB, p=1)')

    # ---- fixtures ------------------------------------------------------------
    src = os.path.join(work, 'in')
    spec = {
        'in/a.txt': b'hello world\n' * 100,
        'in/empty.bin': b'',
        'in/sub/r.bin': os.urandom(200_000),
        'in/sub/deep/zé中.txt': 'unicode name ☃'.encode('utf-8') * 50,
        'in/exact.bin': os.urandom(130_560),       # tar plaintext = exactly 2 x 64 KiB
        'in/big.bin': os.urandom(307_200),         # 4 full segments and a tail
    }
    for rel, data in spec.items():
        p = os.path.join(work, *rel.split('/')); os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, 'wb').write(data)
    one = os.path.join(work, 'one.bin'); open(one, 'wb').write(os.urandom(150_000))

    def myrkr(*args, env=None):
        e = dict(os.environ); e.update(env or {})
        r = subprocess.run([exe, *args], capture_output=True, env=e, timeout=600)
        return r.returncode & 0xFFFFFFFF, (r.stdout + r.stderr).decode(errors='replace')

    def same_tree(res, want):
        got = {n: b for n, f, b, _ in res['files'] if not f & 1}
        return [k for k in want if got.get(k) != want[k]] + [k for k in got if k not in want]

    PW = 'Correct-Horse-Battery-9'
    PWU = 'Pässwörd-æøå-中文-9x!'
    cases = [   # name, input, flags, env, password, minimum segments in one entry
        ('archive, stored',          src, ['--store'],    {}, PW, 1),
        ('archive, compressed',      src, ['--compress'], {}, PW, 1),
        ('single file, stored',      one, ['--store'],    {}, PW, 1),
        ('single file, compressed',  one, ['--compress'], {}, PW, 1),
        ('segmented, stored',        src, ['--store'],    {'MYRKR_DBG_SEGBYTES': '65536'}, PW, 5),
        ('segmented, compressed',    src, ['--compress'], {'MYRKR_DBG_SEGBYTES': '65536'}, PW, 2),
        ('volume set',               src, ['--store'],    {'MYRKR_DBG_VOLBYTES': '150000'}, PW, 1),
        ('non-ASCII password',       src, ['--store'],    {}, PWU, 1),
        ('t=3, m=9 MiB',             src, ['--store', '-t', '3', '-m', '9'], {}, PW, 1),
    ]
    print('== containers written by Myrkr, read by this file ==')
    first = None
    for i, (name, inp, flags, env, pw, minseg) in enumerate(cases):
        out = os.path.join(work, 'c%d.mrk' % i)
        args = ['encrypt', inp, '-o', out, '-p', pw, '--no-policy'] + flags
        if '-m' not in flags: args += ['-m', '8', '-t', '1']
        rc, log = myrkr(*args, env=env)
        if rc != 0:
            check(False, '%s: encrypt exit %d %s' % (name, rc, log.strip()[-160:])); continue
        target = out
        if 'MYRKR_DBG_VOLBYTES' in env:
            parts = sorted(f for f in os.listdir(work) if f.startswith('c%d.part' % i))
            if len(parts) < 3:
                check(False, '%s: only %d part(s) - is this a dbg build?' % (name, len(parts))); continue
            target = os.path.join(work, parts[1])  # a MIDDLE part, as a user might
        try:
            res = decrypt(target, pw)
        except Exception as ex:
            check(False, '%s: %s' % (name, ex)); continue
        if inp == src:
            bad = same_tree(res, spec)
        else:
            bad = [] if [b for _, _, b, _ in res['files']] == [open(one, 'rb').read()] else ['the file']
        segs = max(s for *_, s in res['files'])
        check(not bad and segs >= minseg, '%s: v%d, %d entries, up to %d segment(s) %s'
              % (name, res['version'], res['count'], segs, ('MISMATCH ' + str(bad)) if bad else ''))
        if first is None and not bad:
            first = (target, pw, res['version'])

    # ---- an edited container: a full re-encryption under a fresh key --------
    ed = os.path.join(work, 'c0.mrk')
    added = os.path.join(work, 'added.txt'); open(added, 'wb').write(b'added later\n')
    rc1, _ = myrkr('add', ed, added, '-p', PW, '-m', '8', '-t', '1')
    rc2, _ = myrkr('delete', ed, 'in/a.txt', '-p', PW, '-m', '8', '-t', '1')
    want = dict(spec); want.pop('in/a.txt'); want['added.txt'] = b'added later\n'
    try:
        res = decrypt(ed, PW)
        bad = same_tree(res, want)
        check(rc1 == 0 and rc2 == 0 and not bad, 'after add and delete: %d entries, next ordinal %d %s'
              % (res['count'], res['next'], ('MISMATCH ' + str(bad)) if bad else ''))
    except Exception as ex:
        check(False, 'after add (exit %d) and delete (exit %d): %s' % (rc1, rc2, ex))

    # ---- the reader has teeth ---------------------------------------------------
    print('== and this reader refuses what it should ==')
    if first:
        target, pw, ver = first
        try:
            decrypt(target, pw, kdf=lambda p_, s_, t_, m_: argon2id(p_, s_, t_, m_, 1, 32))
            check(ver > 8, 'standard RFC 9106 Argon2id opens a version-%d container' % ver)
        except ValueError:
            check(ver <= 8, 'standard RFC 9106 Argon2id does NOT open a version-%d container '
                            '(argon2.asm\'s counter indexing - see the header)' % ver)
        try:
            decrypt(target, pw + 'x'); check(False, 'a wrong password was accepted')
        except ValueError:
            check(True, 'a wrong password fails the KCV')
        blob = bytearray(open(os.path.join(work, 'c0.mrk'), 'rb').read())
        blob[HDR_BYTES + 700] ^= 1                 # inside the first entry, not the index
        tam = os.path.join(work, 'tampered.mrk'); open(tam, 'wb').write(blob)
        try:
            decrypt(tam, PW); check(False, 'a flipped ciphertext bit decrypted')
        except ValueError:
            check(True, 'a flipped ciphertext bit fails its GCM tag')
    else:
        check(False, 'no container decrypted, so the negative checks could not run')

    shutil.rmtree(work, ignore_errors=True)
    print('\n%s' % ('indepdecrypttest: all checks passed' if not fails else '%d FAILURE(S)' % len(fails)))
    return 1 if fails else 0

if __name__ == '__main__':
    sys.exit(main())
