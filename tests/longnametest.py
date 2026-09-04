"""Long native names, ZIP interoperability, and fail-closed relative-name limits.

Uses only synthetic fixtures in a unique temp directory; requires build testio.
"""
import pathlib
import subprocess
import sys
import tempfile
import zipfile


def main():
    exe = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="myrkr-longnames-", dir="\\\\?\\" + tempfile.gettempdir()) as tmp:
        root = pathlib.Path(tmp)
        pw = "Synthetic-Long-Name-9"

        def run(*args, expected=0):
            p = subprocess.run([str(exe), *map(str, args), "-p", pw],
                               capture_output=True, timeout=60)
            assert p.returncode == expected, (args, p.returncode, p.stdout, p.stderr)
            return p.stdout + p.stderr

        seed = root / "Code"
        # Same shape as the reported checkpoint, including its UUID child.
        rel = ("myrkr/.git/refs/codex/turn-diffs/checkpoints/" + "a" * 64 +
               "/" + "b" * 64 + "/1788563370008/83ad7b41-c1d0-4807-95b5-fea00d5b5e6f")
        wanted = {rel: b"checkpoint", "c" * 180: b"long leaf",
                  "\u754c" * 80 + ".txt": b"UTF-8 byte length, not characters"}
        # A directory exceeding the old 1024-byte temporary buffer, plus a
        # file exactly at the shared 4094-byte writer/ZIP-reader boundary.
        parts = ["d" * 200] * 20
        prefix = "/".join(parts)
        leaflen = 4094 - len("Code/" + prefix + "/")
        wanted[prefix + "/" + "z" * leaflen] = b"boundary"
        for name, data in wanted.items():
            path = seed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        empty = seed / prefix / "empty"
        empty.mkdir()
        extra = root / "extra.txt"
        extra.write_bytes(b"trigger full rewrite")
        for mode in ("--store", "--compress"):
            mrk = root / (mode + ".mrk")
            run("encrypt", seed, "-o", mrk, mode, "-m", 8, "-t", 1)
            run("verify", mrk)
            out = root / (mode + "-out")
            run("decrypt", mrk, "-o", out)
            for name, data in wanted.items():
                assert (out / "Code" / name).read_bytes() == data, name
            assert (out / "Code" / prefix / "empty").is_dir()
            # Drag-out's streaming decoder must still skip exactly one header.
            streams = root / (mode + "-streams")
            streams.mkdir()
            run("estream", mrk, "-o", streams)
            assert sorted(p.read_bytes() for p in streams.glob("es_*.bin")) == sorted(wanted.values())
            run("add", mrk, extra)
            run("delete", mrk, "extra.txt")
            rewritten = root / (mode + "-rewritten")
            run("decrypt", mrk, "-o", rewritten)
            for name, data in wanted.items():
                assert (rewritten / "Code" / name).read_bytes() == data, name
            boundary = prefix + "/" + "z" * leaflen
            run("delete", mrk, "Code/" + boundary)
            deleted = root / (mode + "-deleted")
            run("decrypt", mrk, "-o", deleted)
            assert not (deleted / "Code" / boundary).exists(), "4094-byte name could not be deleted"
            print(f"PASS {mode}: long leaves, Unicode, checkpoint, 4094-byte path, drag-out and full rewrite", flush=True)
        # Native fix must not impose tar rules on ZIP. Plain ZIP is also read
        # by Python's independent implementation, with exact stored names.
        zipped = root / "names.zip"
        p = subprocess.run([str(exe), "zip", str(seed), "-o", str(zipped)], capture_output=True)
        assert p.returncode == 0, p.stderr
        with zipfile.ZipFile(zipped) as z:
            assert set(z.namelist()) == {"Code/" + name for name in wanted}
            for name, data in wanted.items():
                assert z.read("Code/" + name) == data
        zout = root / "zip-out"
        run("unzip", zipped, "-o", zout)
        for name, data in wanted.items():
            assert (zout / "Code" / name).read_bytes() == data
        print("PASS ZIP: exact long names interoperate with Python and Myrkr", flush=True)
        # Add one byte beyond the common limit; both writers must report the
        # actual offending source and never quietly truncate it to 4000 bytes.
        bad = seed / prefix / ("z" * (leaflen + 1))
        bad.write_bytes(b"must not be renamed")
        for verb, suffix in (("encrypt", ".mrk"), ("zip", ".zip")):
            result = run(verb, seed, "-o", root / ("bad" + suffix), "-m", 8, "-t", 1, expected=4)
            assert b"4094" in result and bad.name.encode() in result, result
        before = zipped.read_bytes()
        run("zipadd", zipped, seed, expected=4)
        assert zipped.read_bytes() == before, "failed ZIP append changed the original"
        base = root / "rollback.mrk"
        run("encrypt", extra, "-o", base, "-m", 8, "-t", 1)
        before = base.read_bytes()
        run("add", base, seed, expected=4)
        assert base.read_bytes() == before, "failed native addition changed the original"
        # A valid ZIP can exceed Myrkr's implementation limit. Identify this
        # as a name limit, not generic corruption or the ZIP specification cap.
        foreign = root / "foreign.zip"
        badname = "Code/" + prefix + "/" + bad.name
        with zipfile.ZipFile(foreign, "w") as z:
            z.writestr(badname, b"payload")
        result = run("unzip", foreign, "-o", root / "foreign-out", expected=4)
        assert b"4094" in result and b"65535" in result and badname.encode() in result
        print("PASS boundaries: no silent truncation; native/ZIP diagnostics identify rejected names", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
