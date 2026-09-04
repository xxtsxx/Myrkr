"""Targeted ZIP extra-field and filename bounds checks; requires build testio.

Fixtures use Python's ZIP writer, then change only central-directory metadata.
No user files are read or overwritten; each run has a unique temporary directory.
"""
import pathlib
import struct
import subprocess
import sys
import tempfile
import zipfile


def archive(name="payload.txt", extra=b""):
    import io
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        info = zipfile.ZipInfo(name)
        info.extra = extra
        z.writestr(info, b"verified payload")
    return bytearray(stream.getvalue())


def main():
    exe = pathlib.Path(sys.argv[1]).resolve()
    cases = [("ordinary", archive(), True)]
    # A ZIP64 record replacing all three 32-bit fields.
    valid = archive(extra=struct.pack("<HHQQQ", 1, 24, 16, 16, 0))
    cd = valid.index(b"PK\x01\x02")
    for offset in (20, 24, 42):
        struct.pack_into("<I", valid, cd + offset, 0xFFFFFFFF)
    cases.append(("zip64-valid", valid, True))
    extra_at = cd + 46 + struct.unpack_from("<H", valid, cd + 28)[0]
    for length in (0, 7, 8, 15, 16, 23, 25, 65535):
        bad = valid.copy()
        struct.pack_into("<H", bad, extra_at + 2, length)
        cases.append((f"zip64-length-{length}", bad, False))
    nul = archive("payload.txt")
    cd = nul.index(b"PK\x01\x02")
    nul[cd + 46 + 7] = 0
    cases.append(("embedded-nul", nul, False))
    cases.append(("oversized-name", archive("a" * 4095), False))
    failures = 0
    with tempfile.TemporaryDirectory(prefix="myrkr-zipbounds-") as tmp:
        root = pathlib.Path(tmp)
        for name, data, accepted in cases:
            source, output = root / (name + ".zip"), root / name
            source.write_bytes(data)
            run = subprocess.run([str(exe), "unzip", str(source), "-o", str(output)],
                                 capture_output=True, timeout=15)
            files = list(output.rglob("*")) if output.exists() else []
            files = [p for p in files if p.is_file()]
            ok = (run.returncode == 0 and len(files) == 1 and
                  files[0].read_bytes() == b"verified payload") if accepted else (
                      run.returncode == 4 and not files)
            print(f"{'PASS' if ok else 'FAIL'} {name}: exit={run.returncode}, files={len(files)}")
            failures += not ok
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
