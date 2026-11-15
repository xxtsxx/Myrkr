#!/usr/bin/env python3
"""Adversarial & corruption test suite for TrueCrypt/VeraCrypt XTS volumes.

Under XTS encryption, data sectors carry no MAC: an adversary with write access
to a .tc/.hc container can flip arbitrary ciphertext blocks to randomize 16-byte
plaintext blocks or craft cyclic/out-of-bounds filesystem metadata.

This suite verifies that Myrkr's volume header parser and all 5 read-only
filesystem parsers (FAT12/16/32, exFAT, NTFS, ext2/3/4, macOS HFS+) treat every
decrypted byte as untrusted input:
  1. Never hang on cyclic cluster chains, B-tree index/fLink loops, or rec_len=0.
  2. Never crash (no 0xC0000005 AV, no 0xC0000409 __fastfail, no stack overflow).
  3. Refuse hidden volumes, system encryption, path traversal, ADS ':', and
     out-of-bounds runs/extents cleanly with EXIT_CORRUPT (4) or EXIT_UNSUPPORTED (9).
  4. Leave zero partial unverified output files behind when extraction aborts.

Usage:  python tests/tcvcfuzz.py [path-to-myrkr.exe]
"""
import os
import random
import struct
import subprocess
import sys
import tempfile
import zlib

# Reuse clean builders from tcvctest.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tcvctest as tc  # noqa: E402

EXIT_OK          = 0
EXIT_IO          = 2
EXIT_AUTH        = 3
EXIT_CORRUPT     = 4
EXIT_UNSUPPORTED = 9


def seal_fast_tc(
    fs_image: bytes,
    pw: bytes = b"FuzzPass!",
    *,
    hidden_size: int = 0,
    flags: int = 0,
    sec_size: int = 512,
    vol_data_size_override: int | None = None,
) -> bytes:
    """Seals a filesystem image into a 1000-iter TrueCrypt AES-XTS volume for fast fuzzing."""
    if len(fs_image) % 512 != 0:
        fs_image = fs_image + b"\x00" * (512 - (len(fs_image) % 512))
    data_off = 131072
    backup_len = 131072
    data_size = len(fs_image) if vol_data_size_override is None else vol_data_size_override

    mk1 = b"\x11" * 32
    mk2 = b"\x22" * 32
    salt = b"\x55" * 64
    dk = tc.pbkdf2_derive("sha512", pw, salt, 1000, 64)
    hk1, hk2 = dk[:32], dk[32:64]

    plain = bytearray(448)
    plain[0:4] = b"TRUE"
    struct.pack_into(">HH", plain, 4, 5, 0x0700)
    struct.pack_into(">Q", plain, 28, hidden_size)
    struct.pack_into(">Q", plain, 36, data_size)
    struct.pack_into(">Q", plain, 44, data_off)
    struct.pack_into(">Q", plain, 52, data_size)
    struct.pack_into(">I", plain, 60, flags)
    struct.pack_into(">I", plain, 64, sec_size)
    plain[192:224] = mk1
    plain[224:256] = mk2
    struct.pack_into(">I", plain, 8, zlib.crc32(plain[192:448]) & 0xFFFFFFFF)
    struct.pack_into(">I", plain, 188, zlib.crc32(plain[0:188]) & 0xFFFFFFFF)

    hdr512 = salt + tc.aes256_xts_encrypt(hk1, hk2, bytes(plain), 0)
    pri = bytearray(data_off)
    pri[0:512] = hdr512
    bak = bytearray(backup_len)
    bak[0:512] = hdr512
    enc_data = tc.aes256_xts_encrypt(mk1, mk2, fs_image, data_off // 512)
    return bytes(pri) + enc_data + bytes(bak)


def run_case(exe: str, vol_path: str, out_dir: str, pw: str = "FuzzPass!") -> tuple[int, str]:
    p = subprocess.run(
        [exe, "decrypt", vol_path, "-o", out_dir, "-p", pw],
        capture_output=True,
        timeout=15,
    )
    rc = p.returncode & 0xFFFFFFFF
    out = (p.stdout + p.stderr).decode("utf-8", errors="replace")
    # NTSTATUS crash codes (0xC0000005 AV, 0xC0000409 __fastfail, 0xC00000FD stack overflow, etc.)
    if rc >= 0x80000000:
        raise AssertionError(f"CRASHED with NTSTATUS 0x{rc:08X}! output={out!r}")
    return rc, out


def main() -> int:
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join("bin", "myrkr.exe"))
    if not os.path.isfile(exe):
        print(f"error: executable not found: {exe}", file=sys.stderr)
        return 1

    print(f"exe = {exe}")
    print("== TrueCrypt / VeraCrypt Adversarial & Corruption Fuzz Suite ==")
    failures = 0

    with tempfile.TemporaryDirectory(prefix="myrkr_tcvcfuzz_") as tmp:
        def check_reject(name: str, vol_bytes: bytes, allowed_codes: set[int]):
            nonlocal failures
            vpath = os.path.join(tmp, f"{name}.tc")
            odir = os.path.join(tmp, f"out_{name}")
            with open(vpath, "wb") as f:
                f.write(vol_bytes)
            try:
                rc, out = run_case(exe, vpath, odir)
                if rc not in allowed_codes:
                    raise AssertionError(f"expected rc in {allowed_codes}, got rc={rc} out={out!r}")
                # Ensure no temporary .part / partial junk survived if 0 files succeeded
                if os.path.isdir(odir):
                    for root, _ds, fs in os.walk(odir):
                        for fn in fs:
                            if ".tmp" in fn or ".part" in fn:
                                raise AssertionError(f"temp artifact leaked on failure: {fn}")
                print(f"  [PASS] {name} -> cleanly rejected (rc={rc})")
            except Exception as exc:
                failures += 1
                print(f"  [FAIL] {name}: {exc}")

        # ---- 1. Header & Container Boundary Checks --------------------------
        base_fat32 = tc.build_fat_image(32, {"ok.txt": b"hello"}, spc=1)

        # 1a. Non-zero HiddenVolumeSize -> EXIT_UNSUPPORTED (9)
        check_reject("hdr_hidden_volume", seal_fast_tc(base_fat32, hidden_size=65536), {EXIT_UNSUPPORTED})

        # 1b. System encryption flag bit 0 -> EXIT_UNSUPPORTED (9)
        check_reject("hdr_system_enc_flag", seal_fast_tc(base_fat32, flags=1), {EXIT_UNSUPPORTED})

        # 1c. VolumeDataSize exceeding physical container size -> EXIT_CORRUPT (4) / EXIT_AUTH (3)
        check_reject(
            "hdr_oversized_data_len",
            seal_fast_tc(base_fat32, vol_data_size_override=len(base_fat32) + 1048576),
            {EXIT_CORRUPT, EXIT_AUTH},
        )

        # 1d. Invalid sector size (1000) -> EXIT_CORRUPT / EXIT_UNSUPPORTED / EXIT_AUTH
        check_reject("hdr_bad_sector_size", seal_fast_tc(base_fat32, sec_size=1000), {EXIT_CORRUPT, EXIT_UNSUPPORTED, EXIT_AUTH})

        # 1e. Unrecognized all-zero filesystem -> EXIT_UNSUPPORTED (9)
        check_reject("fs_unrecognized_zeros", seal_fast_tc(bytes(65536)), {EXIT_UNSUPPORTED})

        # ---- 2. FAT12/16/32 Adversarial Mutations ---------------------------
        # 2a. Cyclic FAT32 cluster chain: FAT[2] <-> FAT[3] loop in root directory!
        cyc_fat = bytearray(base_fat32)
        fat_off = 32 * 512
        fatsz = struct.unpack_from("<I", cyc_fat, 36)[0]
        data_off = (32 + 2 * fatsz) * 512
        # Mark empty slots in clusters 2 & 3 as 0xE5 (deleted) so dir walk traverses FAT[2]->3->2
        for slot_off in range(data_off, data_off + 1024, 32):
            if cyc_fat[slot_off] == 0x00:
                cyc_fat[slot_off] = 0xE5
        struct.pack_into("<II", cyc_fat, fat_off + 2 * 4, 3, 2)
        check_reject("fat32_cyclic_cluster_loop", seal_fast_tc(bytes(cyc_fat)), {EXIT_CORRUPT})

        # 2b. Path traversal "../escape.txt" in VFAT LFN -> rejected by entry_path!
        trav_fat = tc.build_fat_image(16, {"../escape.txt": b"boom"}, spc=1)
        check_reject("fat_vfat_path_traversal", seal_fast_tc(trav_fat), {EXIT_CORRUPT, EXIT_UNSUPPORTED})

        # 2c. Spoofed 3 GiB file size in 32-byte FAT dirent -> exceeds volume data_size!
        spoof_fat = bytearray(tc.build_fat_image(16, {"tiny.bin": (b"abcd", (b"TINY    BIN", 0))}, spc=1))
        root_off = (1 + 2 * 17) * 512
        struct.pack_into("<I", spoof_fat, root_off + 28, 0xC0000000)
        check_reject("fat16_spoofed_4gb_size", seal_fast_tc(bytes(spoof_fat)), {EXIT_CORRUPT})

        # ---- 3. exFAT Adversarial Mutations ---------------------------------
        exf_clean, _ = tc.build_exfat_image()
        # 3a. Corrupt SetChecksum in root directory first 0x85 entry
        exf_bad_cs = bytearray(exf_clean)
        root_clus_off = 32 * 512  # heap_off_sec=32, clus 2
        exf_bad_cs[root_clus_off + 32 + 2] ^= 0xFF  # +32 skips 0x83 volume label
        check_reject("exfat_bad_set_checksum", seal_fast_tc(bytes(exf_bad_cs)), {EXIT_CORRUPT})

        # 3b. Cyclic exFAT FAT chain: FAT[25] = 25 self-loop
        exf_loop = bytearray(exf_clean)
        struct.pack_into("<I", exf_loop, 24 * 512 + 25 * 4, 25)
        check_reject("exfat_self_loop_cluster", seal_fast_tc(bytes(exf_loop)), {EXIT_CORRUPT})

        # ---- 4. NTFS Adversarial Mutations ----------------------------------
        ntfs_clean, _ = tc.build_ntfs_image()
        # 4a. Corrupt USA fixup end-of-sector word in $MFT record 0
        ntfs_bad_usa = bytearray(ntfs_clean)
        ntfs_bad_usa[4 * 4096 + 510] ^= 0xFF
        check_reject("ntfs_corrupt_mft_usa", seal_fast_tc(bytes(ntfs_bad_usa)), {EXIT_CORRUPT})

        # 4b. Corrupt LZNT1 match distance > subPos (cluster 40 holds compressed stream)
        ntfs_bad_lz = bytearray(ntfs_clean)
        # In _lznt1_compress_simple: [0..1]=hdr, [2]=tag0, [3..10]=8B, [11]=tag1, [12..19]=8B, [20]=0x01, [21..22]=tuple
        # Force distance = 4096 at subPos = 16 -> tuple = (4095 << 12) | 10 = 0xFFF00A (u16 max = 0xF00A -> dist=16, wait: at pos=16 o_shift=12 -> max dist=16; at subPos=1, force match right at byte 0 where subPos==0!)
        struct.pack_into("<HBH", ntfs_bad_lz, 40 * 4096, 0xB002, 0x01, 0x1005)
        check_reject("ntfs_lznt1_underflow_match", seal_fast_tc(bytes(ntfs_bad_lz)), {EXIT_CORRUPT})

        # ---- 5. ext2 / ext4 Adversarial Mutations ---------------------------
        ext2_clean, _ = tc.build_ext2_image()
        ext4_clean, _ = tc.build_ext4_image()

        # 5a. Zero rec_len = 0 in ext2 root directory block 10 -> must NOT infinite-loop!
        ext2_reclen0 = bytearray(ext2_clean)
        struct.pack_into("<H", ext2_reclen0, 10 * 1024 + 4, 0)
        check_reject("ext2_dir_reclen_zero", seal_fast_tc(bytes(ext2_reclen0)), {EXIT_CORRUPT})

        # 5b. Cyclic ext4 extent tree: leaf block 15 claims eh_depth = 1 instead of 0!
        ext4_bad_depth = bytearray(ext4_clean)
        struct.pack_into("<H", ext4_bad_depth, 15 * 4096 + 6, 1)
        check_reject("ext4_cyclic_extent_depth", seal_fast_tc(bytes(ext4_bad_depth)), {EXIT_CORRUPT})

        # 5c. Out-of-bounds physical block in ext4 extent leaf
        ext4_oob_blk = bytearray(ext4_clean)
        struct.pack_into("<I", ext4_oob_blk, 15 * 4096 + 12 + 8, 999999)
        check_reject("ext4_oob_extent_block", seal_fast_tc(bytes(ext4_oob_blk)), {EXIT_CORRUPT})

        # ---- 6. macOS HFS+ Adversarial Mutations ----------------------------
        hfs_clean, _ = tc.build_hfsplus_wrapped_image()

        # 6a. Cyclic Catalog leaf fLink: Leaf 3 (at embed_off=8192 + blk 100*512 + 3*4096) fLink = 2!
        hfs_flink_loop = bytearray(hfs_clean)
        leaf3_off = 8192 + 100 * 512 + 3 * 4096
        struct.pack_into(">I", hfs_flink_loop, leaf3_off + 0, 2)
        # Also make Leaf 3's last record still parentID=2 so root scan chases fLink forever without guard!
        leaf2_off = 8192 + 100 * 512 + 2 * 4096
        struct.pack_into(">I", hfs_flink_loop, leaf2_off + 0, 2)  # self-loop fLink = 2!
        check_reject("hfsplus_catalog_flink_cycle", seal_fast_tc(bytes(hfs_flink_loop)), {EXIT_CORRUPT})

        # 6b. Corrupt B-Tree end-of-node record offset table in Catalog Root Node 1
        hfs_bad_recoff = bytearray(hfs_clean)
        node1_off = 8192 + 100 * 512 + 1 * 4096
        struct.pack_into(">H", hfs_bad_recoff, node1_off + 4096 - 2, 65000)
        check_reject("hfsplus_corrupt_btree_offsets", seal_fast_tc(bytes(hfs_bad_recoff)), {EXIT_CORRUPT})

        # ---- 7. Deterministic Multi-FS Byte/Sector Fuzzing (25 iterations) --
        rng = random.Random(0x4D59524B)
        corpora = [
            ("fat32", base_fat32),
            ("exfat", exf_clean),
            ("ntfs", ntfs_clean),
            ("ext4", ext4_clean),
            ("hfsplus", hfs_clean),
        ]
        fuzz_ok = 0
        for idx in range(25):
            kind, clean_img = corpora[idx % len(corpora)]
            mut = bytearray(clean_img)
            # Mutate 8..32 random regions inside filesystem metadata & data sectors
            for _ in range(rng.randint(8, 32)):
                pos = rng.randrange(0, len(mut) - 8)
                for b_i in range(rng.randint(1, 8)):
                    mut[pos + b_i] ^= rng.randint(1, 255)
            vpath = os.path.join(tmp, f"rand_{idx:02d}_{kind}.tc")
            odir = os.path.join(tmp, f"out_rand_{idx:02d}")
            with open(vpath, "wb") as f:
                f.write(seal_fast_tc(bytes(mut)))
            try:
                rc, _ = run_case(exe, vpath, odir)
                assert rc in {EXIT_OK, EXIT_IO, EXIT_CORRUPT, EXIT_UNSUPPORTED}, f"unexpected rc={rc}"
                fuzz_ok += 1
            except Exception as exc:
                failures += 1
                print(f"  [FAIL] random_fuzz_{idx:02d}_{kind}: {exc}")

        if fuzz_ok == 25:
            print("  [PASS] 25/25 deterministic multi-filesystem fuzz mutations handled without crash or hang")

    if failures:
        print(f"FAILED: {failures} adversarial test(s)")
        return 1
    print("ALL TC/VC ADVERSARIAL & FUZZ TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
