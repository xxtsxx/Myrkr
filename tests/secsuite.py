#!/usr/bin/env python3
"""Myrkr security-control test suite -- Phase 1 (scriptable, no tool changes).

Measures effectiveness of the cryptographic, input-validation and operational
controls by adversarial testing against the shipping binary.  Each control is
scored on: efficacy (does it block the violation), fail-closed (no bad output),
and no-false-positive (legit use still works).

Usage:  python secsuite.py <path-to-myrkr.exe> [workdir]
Exit code 0 iff every control passes.
"""
import os, sys, subprocess, hashlib, tempfile, shutil, struct, random

PW = "Hunter2Hunter2!"          # meets policy (len>=12, 3+ classes)
WRONG = "totally-wrong-pass-9"

EXIT = dict(OK=0, USAGE=1, IO=2, AUTH=3, CORRUPT=4, OOM=5, NOCPU=6, SELFTEST=7, NOSPACE=8)
# fastfail / AV exit codes (abnormal termination = a hardening control or a crash)
STATUS_FASTFAIL = 0xC0000409        # __fastfail / int 29h (stack-buffer-overrun status)
STATUS_AV       = 0xC0000005        # access violation

results = []   # (control, axis, name, passed, detail)
def record(control, axis, name, passed, detail=""):
    results.append((control, axis, name, passed, detail))
    tag = "PASS" if passed else "FAIL"
    print(f"  [{tag}] {control:<14} {name}  {detail}")

def run(exe, args, want_exit=None):
    p = subprocess.run([exe]+args, capture_output=True, timeout=300)
    rc = p.returncode & 0xFFFFFFFF
    return rc, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")

def sha(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda: f.read(1<<20), b""): h.update(b)
    return h.hexdigest()

# ---------------------------------------------------------------------------
def main():
    exe = os.path.abspath(sys.argv[1])
    work = sys.argv[2] if len(sys.argv)>2 else tempfile.mkdtemp(prefix="myrkr_sec_")
    os.makedirs(work, exist_ok=True)
    print(f"exe={exe}\nwork={work}\n")

    # a reference plaintext (incompressible so ciphertext != plaintext obviously)
    src = os.path.join(work,"plain.bin")
    data = os.urandom(300_000)
    open(src,"wb").write(data)
    src_hash = sha(src)

    regression_ok = []

    # ===================== A0: baseline round-trips (no-false-positive) =====
    print("== A0 baseline round-trips (control must not break legit use) ==")
    mrk = os.path.join(work,"a.mrk"); dec = os.path.join(work,"a.dec")
    rc,o,e = run(exe,["encrypt",src,"-o",mrk,"-p",PW])
    rc2,_,_ = run(exe,["decrypt",mrk,"-o",dec,"-p",PW])
    ok = rc==0 and rc2==0 and os.path.exists(dec) and sha(dec)==src_hash
    record("AEAD","no-fp",".mrk round-trip", ok); regression_ok.append(ok)

    zp = os.path.join(work,"a.zip"); zout = os.path.join(work,"zout")
    rc,_,_ = run(exe,["zip",src,"-o",zp,"-p",PW])
    rc2,_,_ = run(exe,["unzip",zp,"-o",zout,"-p",PW])
    extracted = os.path.join(zout,"plain.bin")
    ok = rc==0 and rc2==0 and os.path.exists(extracted) and sha(extracted)==src_hash
    record("WinZip-AES","no-fp",".zip round-trip", ok); regression_ok.append(ok)

    # ===================== A1: .mrk AEAD tamper matrix ======================
    print("== A1 AES-256-GCM tamper detection (.mrk) ==")
    blob = open(mrk,"rb").read(); n=len(blob)
    regions = {
        "magic":       range(0,4),
        "version":     range(4,8),
        "kdf-params":  range(8,20),     # t_cost,m_cost,lanes (AAD + change key)
        "salt":        range(20,52),
        "set_id":      range(52,64),
        "KCV":         range(64,80),
        "ciphertext":  range(80, n-16),
        "gcm-tag":     range(n-16, n),
    }
    rng = random.Random(1234)
    miss = 0; total = 0; codes = {}
    for rname, rg in regions.items():
        offs = list(rg)
        sample = offs if len(offs)<=6 else rng.sample(offs, 6)
        for off in sample:
            tam = bytearray(blob); tam[off] ^= 0x01
            tpath = os.path.join(work,"t.mrk"); open(tpath,"wb").write(tam)
            outp = os.path.join(work,"t.dec")
            if os.path.exists(outp): os.remove(outp)
            rc,_,_ = run(exe,["decrypt",tpath,"-o",outp,"-p",PW])
            total += 1; codes[rc]=codes.get(rc,0)+1
            # effectiveness = NO correct plaintext is ever produced
            leaked = os.path.exists(outp) and sha(outp)==src_hash
            if leaked or rc==0: miss += 1
    record("AEAD","efficacy",f".mrk tamper x{total}", miss==0,
           f"detections={total-miss}/{total} exit-codes={codes}")

    # ===================== A3: wrong password ===============================
    print("== A3 wrong password ==")
    outp = os.path.join(work,"w.dec");  open(mrk,"rb")  # ensure exists
    if os.path.exists(outp): os.remove(outp)
    rc,_,_ = run(exe,["decrypt",mrk,"-o",outp,"-p",WRONG])
    ok = rc==EXIT["AUTH"] and not (os.path.exists(outp) and sha(outp)==src_hash)
    record("KCV/AEAD","efficacy",".mrk wrong-pw -> exit3", ok, f"rc={rc}")
    rc,_,_ = run(exe,["unzip",zp,"-o",os.path.join(work,"wz"),"-p",WRONG])
    ok = rc==EXIT["AUTH"]
    record("WinZip-AES","efficacy",".zip wrong-pw -> exit3", ok, f"rc={rc}")

    # ================= A5: salt / container-id uniqueness ====================
    # Nonces are counters from v4 on (entry i uses i+1), so per-container nonce
    # uniqueness is guaranteed by construction and there is nothing to sample.
    # What still has to be random and distinct is the SALT - it is what makes
    # the key fresh per container, which is what makes counter nonces safe - and
    # the container id in the same header field the nonce used to occupy.
    print("== A5 per-file salt/container-id uniqueness ==")
    N=200; salts=set(); ids=set()
    for i in range(N):
        m = os.path.join(work,"u.mrk")
        run(exe,["encrypt",src,"-o",m,"-p",PW])
        hdr = open(m,"rb").read(80)
        salts.add(hdr[20:52]); ids.add(hdr[52:64])
    record("CSPRNG","efficacy",f"salt uniqueness x{N}", len(salts)==N, f"distinct={len(salts)}")
    record("CSPRNG","efficacy",f"container-id uniqueness x{N}", len(ids)==N, f"distinct={len(ids)}")

    # ===================== A8: WinZip-AES tamper within entry data =========
    print("== A8 WinZip-AES tamper (.zip entry data) ==")
    import zipfile
    zf = zipfile.ZipFile(zp); info = zf.infolist()[0]
    # local header: 30 + name + extra ; then salt16|pwverify2|ct|hmac10
    raw = open(zp,"rb").read()
    lho = info.header_offset
    nlen = struct.unpack_from("<H", raw, lho+26)[0]
    elen = struct.unpack_from("<H", raw, lho+28)[0]
    data0 = lho+30+nlen+elen
    csize = info.compress_size
    spots = {"salt":data0+2, "ciphertext":data0+18+ (csize-28)//2, "hmac-tag":data0+csize-3}
    miss=0; total=0; codes={}
    for sname,off in spots.items():
        tam=bytearray(raw); tam[off]^=0x01
        tp=os.path.join(work,"t2.zip"); open(tp,"wb").write(tam)
        od=os.path.join(work,"t2out"); shutil.rmtree(od,ignore_errors=True)
        rc,_,_=run(exe,["unzip",tp,"-o",od,"-p",PW]); total+=1; codes[rc]=codes.get(rc,0)+1
        leaked = os.path.exists(os.path.join(od,"plain.bin")) and sha(os.path.join(od,"plain.bin"))==src_hash
        if leaked or rc==0: miss+=1
    record("WinZip-AES","efficacy",f".zip tamper x{total}", miss==0, f"detections={total-miss}/{total} codes={codes}")

    # ===================== C1: path-traversal sanitisation =================
    print("== C1 path-traversal sanitisation (shared sanitize_name) ==")
    # pyzipper is only needed to BUILD an encrypted malicious zip.  It is a
    # third-party package and may not be installed; a missing one used to abort
    # the whole run here, taking every later test with it.  The plain-zip half
    # below uses the stdlib and drives the same sanitize_name code path, so skip
    # only the encrypted case and keep the coverage that does not need it.
    try:
        import pyzipper
    except ModuleNotFoundError:
        pyzipper = None
    sand = os.path.join(work,"sandbox"); os.makedirs(sand, exist_ok=True)
    canary_dir = os.path.join(work,"ABOVE"); os.makedirs(canary_dir, exist_ok=True)
    evil_names = ["../../ABOVE/PWNED.txt", r"..\..\ABOVE\PWNED2.txt",
                  "/abs_pwned.txt", "a/../../ABOVE/PWNED3.txt"]
    cases = []
    # encrypted (WinZip-AES) malicious zip
    if pyzipper is not None:
        ez = os.path.join(work,"evil_enc.zip")
        with pyzipper.AESZipFile(ez,"w",compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as z:
            z.setpassword(PW.encode())
            for nm in evil_names: z.writestr(nm, b"pwned")
        cases.append(("enc",ez,PW))
    else:
        print("  [SKIP] WinZip-AES    encrypted traversal zip - pyzipper not installed "
              "(pip install pyzipper); the plain-zip case below still covers sanitize_name")
    # plain malicious zip
    pz = os.path.join(work,"evil_plain.zip")
    with zipfile.ZipFile(pz,"w") as z:
        for nm in evil_names: z.writestr(nm, b"pwned")
    cases.append(("plain",pz,None))
    before = set()
    for r,_,fs in os.walk(canary_dir):
        for f in fs: before.add(os.path.join(r,f))
    for label,zz,pw in cases:
        od=os.path.join(work,f"trav_{label}"); shutil.rmtree(od,ignore_errors=True)
        args=["unzip",zz,"-o",od]+(["-p",pw] if pw else [])
        run(exe,args)
    # measure: did ANYTHING land outside the intended OUTDIR (i.e. in ABOVE/)?
    after = set()
    for r,_,fs in os.walk(canary_dir):
        for f in fs: after.add(os.path.join(r,f))
    escaped = after - before
    # also check no absolute-root write
    abs_pwn = os.path.exists(os.path.join(os.path.splitdrive(work)[0]+os.sep,"abs_pwned.txt"))
    record("path-traversal","efficacy","no escape outside OUTDIR", len(escaped)==0 and not abs_pwn,
           f"escaped={list(escaped)} abs={abs_pwn}")

    # ===================== C2: malformed-archive robustness ================
    print("== C2 malformed-archive robustness (no crash; graceful exit) ==")
    crashes=0; total=0; codes={}
    rng2=random.Random(99)
    # seed from a real zip + a real mrk, then mutate/truncate
    seeds=[open(zp,"rb").read(), open(mrk,"rb").read()]
    for trial in range(60):
        base=rng2.choice(seeds); b=bytearray(base)
        mode=rng2.randint(0,2)
        if mode==0 and len(b)>40: del b[rng2.randint(20,len(b)-1):]      # truncate
        elif mode==1:                                                    # random byte flips
            for _ in range(rng2.randint(1,40)): b[rng2.randrange(len(b))]^=rng2.randint(1,255)
        else:                                                            # pure garbage
            b=bytearray(os.urandom(rng2.randint(0,4000)))
        ext=".zip" if base is seeds[0] else ".mrk"
        fp=os.path.join(work,f"fuzz{ext}"); open(fp,"wb").write(b)
        od=os.path.join(work,"fuzzout"); shutil.rmtree(od,ignore_errors=True)
        cmd = ["unzip",fp,"-o",od,"-p",PW] if ext==".zip" else ["decrypt",fp,"-o",os.path.join(work,"fz.dec"),"-p",PW]
        try:
            rc,_,_=run(exe,cmd)
        except subprocess.TimeoutExpired:
            rc=-999
        total+=1; codes[rc]=codes.get(rc,0)+1
        if rc in (STATUS_FASTFAIL, STATUS_AV, -999): crashes+=1
    record("input-robustness","efficacy",f"malformed x{total} no crash", crashes==0,
           f"crashes={crashes} codes={codes}")

    # ===================== C4: password policy =============================
    print("== C4 password policy enforcement ==")
    weak = {"short":"aB1!", "no-classes":"aaaaaaaaaaaa", "empty":""}
    polok=0; poltot=0
    for nm,wp in weak.items():
        poltot+=1
        rc,_,_=run(exe,["encrypt",src,"-o",os.path.join(work,"pol.mrk"),"-p",wp])
        # weak pw must be rejected (non-zero); valid pw earlier succeeded
        if rc!=0: polok+=1
    record("password-policy","efficacy",f"weak rejected {polok}/{poltot}", polok==poltot)

    # ===================== summary =========================================
    print("\n================= SCORECARD =================")
    bycat={}
    for c,axis,name,ok,det in results:
        bycat.setdefault(c,[0,0]); bycat[c][0]+=ok; bycat[c][1]+=1
    for c,(p,t) in sorted(bycat.items()):
        print(f"  {c:<18} {p}/{t} pass")
    failed=[r for r in results if not r[3]]
    print(f"\nTOTAL: {sum(1 for r in results if r[3])}/{len(results)} checks passed")
    if failed:
        print("FAILURES:")
        for c,axis,name,ok,det in failed: print(f"  - {c} :: {name} :: {det}")
    return 0 if not failed else 1

if __name__=="__main__":
    sys.exit(main())
