"""Fresh-key transactional native edits; requires a testio binary."""
import pathlib
import os
import ctypes
import shutil
import subprocess
import sys
import tempfile


def main():
    exe = pathlib.Path(sys.argv[1]).resolve()
    segmented = "--segments" in sys.argv[2:]
    if segmented:
        # Debug-only knob: force many boundaries in both reader and writer.
        os.environ["MYRKR_DBG_SEGBYTES"] = "65536"
    with tempfile.TemporaryDirectory(prefix="myrkr-noncefork-") as tmp:
        root = pathlib.Path(tmp)
        password = "Synthetic-Audit-Password-9"

        def run(*args, expected=0):
            result = subprocess.run([str(exe), *map(str, args), "-p", password],
                                    capture_output=True, timeout=30)
            if result.returncode != expected:
                raise AssertionError(f"{args[0]}: expected {expected}, got {result.returncode}: "
                                     + result.stderr.decode(errors="replace"))
            return result

        seed = root / "seed"
        seed.mkdir()
        (seed / "a.txt").write_bytes(b"seed A")
        (seed / "b.txt").write_bytes(b"seed B")
        blob = os.urandom(2 * 1024 * 1024 + 123)
        (seed / "blob.bin").write_bytes(blob)
        (seed / "empty.bin").write_bytes(b"")
        (seed / "empty-dir").mkdir()
        for mode in ("--store", "--compress"):
            original = root / (mode + ".mrk")
            run("encrypt", seed, "-o", original, mode, "-m", "8", "-t", "1")
            snapshot = original.read_bytes()
            if segmented:
                assert snapshot[19] == 16, "--segments requires a dbg binary"
            salts = set()
            for label, byte in (("left", b"A"), ("right", b"B")):
                folder = root / (mode + label)
                folder.mkdir()
                payload = folder / "added.bin"
                payload.write_bytes(byte * 64)
                copy = folder / "copy.mrk"
                shutil.copyfile(original, copy)
                run("add", copy, payload)
                changed = copy.read_bytes()
                assert changed[20:52] != snapshot[20:52], "edit reused source key salt"
                salts.add(changed[20:52])
                run("verify", copy)
                # A duplicate or missing input must not modify the original.
                run("add", copy, payload, expected=1)
                assert copy.read_bytes() == changed
                run("add", copy, folder / "absent.txt", expected=2)
                assert copy.read_bytes() == changed
                # A reader that denies write sharing must prevent a rewrite.
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                    ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                    ctypes.c_uint32, ctypes.c_void_p]
                kernel.CreateFileW.restype = ctypes.c_void_p
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                handle = kernel.CreateFileW(str(copy), 0x80000000, 1, None, 3, 0x80, None)
                assert handle != ctypes.c_void_p(-1).value
                try:
                    run("delete", copy, "seed/a.txt", expected=2)
                finally:
                    kernel.CloseHandle(handle)
                assert copy.read_bytes() == changed, "locked-source edit changed bytes"
                out = folder / "out"
                run("decrypt", copy, "-o", out)
                assert (out / "seed" / "a.txt").read_bytes() == b"seed A"
                assert (out / "added.bin").read_bytes() == byte * 64
                assert (out / "seed" / "blob.bin").read_bytes() == blob
                assert (out / "seed" / "empty.bin").read_bytes() == b""
                assert (out / "seed" / "empty-dir").is_dir()
                run("delete", copy, "seed/a.txt")
                deleted = copy.read_bytes()
                assert deleted[20:52] != changed[20:52]
                salts.add(deleted[20:52])
                run("verify", copy)
                out2 = folder / "out2"
                run("decrypt", copy, "-o", out2)
                assert not (out2 / "seed" / "a.txt").exists()
                assert (out2 / "seed" / "b.txt").read_bytes() == b"seed B"
                assert (out2 / "added.bin").read_bytes() == byte * 64
                assert (out2 / "seed" / "blob.bin").read_bytes() == blob
                # Corruption in a retained entry must never be committed.
                damaged = bytearray(snapshot)
                damaged[90] ^= 1
                copy.write_bytes(damaged)
                run("add", copy, payload, expected=3 if mode == "--store" else 4)
                assert copy.read_bytes() == damaged
                assert not list(folder.glob("*.tmp")), "aborted rewrite leaked a temp"
                print(f"PASS {mode} {label}: fresh-key add/delete, rollback, authentication")
            assert len(salts) == 4, "forked edits reused a salt"
            fresh = root / (mode + "-fresh.mrk")
            run("encrypt", seed, "-o", fresh, mode, "-m", "8", "-t", "1")
            assert fresh.read_bytes()[20:52] != snapshot[20:52], "fresh encryption reused salt"
            print(f"PASS {mode}: fresh encryption uses a new salt")
        # The gate must be scoped to native containers: ZIP uses separate salts.
        zipped = root / "editable.zip"
        extra = root / "extra.txt"
        extra.write_bytes(b"ZIP append still works")
        run("zip", seed, "-o", zipped)
        run("zipadd", zipped, extra)
        zipout = root / "zipout"
        run("unzip", zipped, "-o", zipout)
        assert (zipout / "extra.txt").read_bytes() == extra.read_bytes()
        assert (zipout / "seed" / "a.txt").read_bytes() == b"seed A"
        assert (zipout / "seed" / "b.txt").read_bytes() == b"seed B"
        print("PASS: ZIP creation, append, and extraction remain available")
        # Frozen older files must upgrade without losing any decoded content.
        password = "Fixture-Horse-Battery-9"
        fixtures = pathlib.Path(__file__).parent / "fixtures"
        for fixture in sorted(fixtures.glob("v[68]-*.mrk")):
            if "part" in fixture.name:
                continue
            folder = root / fixture.stem
            folder.mkdir()
            copy = folder / "copy.mrk"
            shutil.copyfile(fixture, copy)
            original_bytes = copy.read_bytes()
            before = folder / "before"
            run("decrypt", copy, "-o", before)
            wanted = sorted(p.read_bytes() for p in before.rglob("*") if p.is_file()) if before.is_dir() else [before.read_bytes()]
            run("add", copy, extra)
            assert copy.read_bytes()[20:52] != original_bytes[20:52]
            run("verify", copy)
            after = folder / "after"
            run("decrypt", copy, "-o", after)
            actual = sorted(p.read_bytes() for p in after.rglob("*") if p.is_file())
            assert actual == sorted(wanted + [extra.read_bytes()]), fixture.name
            run("delete", copy, "extra.txt")
            run("verify", copy)
            print(f"PASS: full rewrite upgrades frozen {fixture.name}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
