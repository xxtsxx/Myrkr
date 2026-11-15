#!/usr/bin/env python3
"""End-to-end TrueCrypt (.tc) & VeraCrypt (.hc) read-only container test suite.

Builds authentic XTS-encrypted TrueCrypt 7.1a and VeraCrypt volumes from scratch
using Windows bcrypt.dll (AES-ECB for XTS) + stdlib hashlib/zlib, covering:
  - FAT12 (even/odd 12-bit FAT entries, 8.3 NTRes case, VFAT Unicode LFN, 0-byte, nested dirs)
  - FAT16 (large >64 KiB file crossing sector-cache chunks, password + multi-keyfile order-independence)
  - FAT32 (cluster-backed multi-cluster dir, high cluster bits, deleted/label slots, keyfile-only)
  - exFAT (NoFatChain contiguous + FAT-chained fragmented, ValidDataLength < DataLength zero tail,
           Unicode entry sets with SetChecksum, keyfile folder containing the volume + hidden file)
  - Backup header fallback (corrupted primary header at offset 0)
  - Wrong password / wrong keyfile rejection (EXIT_AUTH = 3)
  - Magic-byte exclusion when a .mrk container is renamed to .tc

Usage:  python tests/tcvctest.py [path-to-myrkr.exe]
"""
import ctypes
import hashlib
import hmac
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

EXIT_OK   = 0
EXIT_AUTH = 3

FILE_ATTRIBUTE_HIDDEN = 0x02


# =============================================================================
# Windows BCrypt AES-ECB -> AES-256-XTS (IEEE P1619, 512-byte encryption units)
# =============================================================================
class _BCryptAES:
    def __init__(self):
        self.bc = ctypes.windll.bcrypt
        alg = ctypes.c_void_p()
        st = self.bc.BCryptOpenAlgorithmProvider(
            ctypes.byref(alg), ctypes.c_wchar_p("AES"), None, 0
        )
        assert st == 0, f"BCryptOpenAlgorithmProvider failed: 0x{st:08X}"
        mode = "ChainingModeECB".encode("utf-16le") + b"\x00\x00"
        prop = "ChainingMode"
        st = self.bc.BCryptSetProperty(
            alg, ctypes.c_wchar_p(prop), mode, len(mode), 0
        )
        assert st == 0, f"BCryptSetProperty ECB failed: 0x{st:08X}"
        self.alg = alg

    def ecb_encrypt(self, key32: bytes, data: bytes) -> bytes:
        assert len(key32) == 32 and len(data) % 16 == 0
        hkey = ctypes.c_void_p()
        st = self.bc.BCryptGenerateSymmetricKey(
            self.alg, ctypes.byref(hkey), None, 0, key32, 32, 0
        )
        assert st == 0, f"BCryptGenerateSymmetricKey failed: 0x{st:08X}"
        try:
            out = ctypes.create_string_buffer(len(data))
            cb = ctypes.c_ulong(0)
            st = self.bc.BCryptEncrypt(
                hkey, data, len(data), None, None, 0,
                out, len(data), ctypes.byref(cb), 0
            )
            assert st == 0, f"BCryptEncrypt failed: 0x{st:08X}"
            return out.raw
        finally:
            self.bc.BCryptDestroyKey(hkey)


_AES = _BCryptAES()


def gf128_mul_x(tweak16: bytes) -> bytes:
    lo, hi = struct.unpack("<QQ", tweak16)
    carry = (hi >> 63) & 1
    hi = ((hi << 1) | (lo >> 63)) & 0xFFFFFFFFFFFFFFFF
    lo = (lo << 1) & 0xFFFFFFFFFFFFFFFF
    if carry:
        lo ^= 0x87
    return struct.pack("<QQ", lo, hi)


def aes256_xts_encrypt(k1: bytes, k2: bytes, data: bytes, start_unit: int) -> bytes:
    assert len(data) % 16 == 0 and len(data) > 0
    n_units = (len(data) + 511) // 512
    # Batch encrypt all initial tweaks in one BCrypt call
    tweak_in = b"".join(struct.pack("<QQ", start_unit + u, 0) for u in range(n_units))
    enc_tweaks = _AES.ecb_encrypt(k2, tweak_in)

    xor_Pre = bytearray(len(data))
    tweaks_all = bytearray(len(data))
    for u in range(n_units):
        t = enc_tweaks[u * 16 : (u + 1) * 16]
        base = u * 512
        blocks_in_unit = min(32, (len(data) - base) // 16)
        for b in range(blocks_in_unit):
            off = base + b * 16
            tweaks_all[off : off + 16] = t
            p_lo, p_hi = struct.unpack_from("<QQ", data, off)
            t_lo, t_hi = struct.unpack("<QQ", t)
            struct.pack_into("<QQ", xor_Pre, off, p_lo ^ t_lo, p_hi ^ t_hi)
            t = gf128_mul_x(t)

    ct = bytearray(_AES.ecb_encrypt(k1, bytes(xor_Pre)))
    for i in range(0, len(ct), 8):
        v = struct.unpack_from("<Q", ct, i)[0] ^ struct.unpack_from("<Q", tweaks_all, i)[0]
        struct.pack_into("<Q", ct, i, v)
    return bytes(ct)


# =============================================================================
# TrueCrypt / VeraCrypt Keyfile Mixing & Header Construction
# =============================================================================
def mix_keyfiles(password: bytes, keyfile_blobs: list[bytes]) -> bytes:
    if not keyfile_blobs:
        return password
    pool_len = 64 if len(password) <= 64 else 128
    pool = [0] * pool_len
    for blob in keyfile_blobs:
        crc = 0xFFFFFFFF
        wpos = 0
        for b in blob[: 1024 * 1024]:
            # Standard reflected CRC-32 step without final ~0xFFFFFFFF
            crc = (zlib.crc32(bytes([b]), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF
            pool[wpos]     = (pool[wpos]     + ((crc >> 24) & 0xFF)) & 0xFF
            pool[wpos + 1] = (pool[wpos + 1] + ((crc >> 16) & 0xFF)) & 0xFF
            pool[wpos + 2] = (pool[wpos + 2] + ((crc >> 8)  & 0xFF)) & 0xFF
            pool[wpos + 3] = (pool[wpos + 3] + (crc & 0xFF)) & 0xFF
            wpos = (wpos + 4) % pool_len
    out_len = max(len(password), pool_len)
    out = bytearray(out_len)
    out[: len(password)] = password
    for i in range(pool_len):
        out[i] = (out[i] + pool[i]) & 0xFF
    return bytes(out)


def pbkdf2_derive(alg: str, pw: bytes, salt: bytes, iters: int, dklen: int) -> bytes:
    try:
        return hashlib.pbkdf2_hmac(alg, pw, salt, iters, dklen)
    except ValueError:
        hfn = lambda d=b"": hashlib.new(alg, d)
        out = bytearray()
        blk = 1
        while len(out) < dklen:
            u = hmac.new(pw, salt + struct.pack(">I", blk), hfn).digest()
            acc = bytearray(u)
            for _ in range(iters - 1):
                u = hmac.new(pw, u, hfn).digest()
                for i in range(len(acc)):
                    acc[i] ^= u[i]
            out.extend(acc)
            blk += 1
        return bytes(out[:dklen])


def build_tcvc_volume(
    fs_image: bytes,
    password: bytes,
    keyfile_blobs: list[bytes],
    *,
    is_vera: bool = True,
    kdf_alg: str = "sha512",
    salt_seed: bytes = b"S",
    hdr_ver: int = 5,
    req_ver: int | None = None,
    sec_size: int = 512,
    legacy_v1: bool = False,
) -> bytes:
    assert len(fs_image) % 512 == 0
    data_off = 512 if legacy_v1 else 131072
    backup_len = 0 if legacy_v1 else 131072
    data_size = len(fs_image)

    mixed_pw = mix_keyfiles(password, keyfile_blobs)
    iters = (655331 if kdf_alg == "ripemd160" else 500000) if is_vera else (
        2000 if kdf_alg == "ripemd160" else 1000
    )

    master_k1 = hashlib.sha256(b"mk1:" + salt_seed).digest()
    master_k2 = hashlib.sha256(b"mk2:" + salt_seed).digest()
    eff_req_ver = req_ver if req_ver is not None else (0x010B if is_vera else 0x0700)

    def make_header(salt64: bytes, override_data_size: int | None = None) -> bytes:
        assert len(salt64) == 64
        dk = pbkdf2_derive(kdf_alg, mixed_pw, salt64, iters, 64)
        hk1, hk2 = dk[:32], dk[32:64]

        plain = bytearray(448)
        plain[0:4] = b"VERA" if is_vera else b"TRUE"
        struct.pack_into(">H", plain, 4, hdr_ver)
        struct.pack_into(">H", plain, 6, eff_req_ver)
        struct.pack_into(">Q", plain, 28, 0)                          # HiddenVolumeSize = 0 (normal volume)
        vds = data_size if override_data_size is None else override_data_size
        struct.pack_into(">Q", plain, 36, vds)                        # VolumeDataSize
        struct.pack_into(">Q", plain, 44, 0 if legacy_v1 else data_off)
        struct.pack_into(">Q", plain, 52, 0 if legacy_v1 else vds)
        struct.pack_into(">I", plain, 60, 0)                          # flags = 0 (non-system)
        if hdr_ver >= 5:
            struct.pack_into(">I", plain, 64, sec_size)
        plain[192:224] = master_k1
        plain[224:256] = master_k2
        crc_keys = zlib.crc32(plain[192:448]) & 0xFFFFFFFF
        struct.pack_into(">I", plain, 8, crc_keys)
        if hdr_ver >= 4:
            crc_hdr = zlib.crc32(plain[0:188]) & 0xFFFFFFFF
            struct.pack_into(">I", plain, 188, crc_hdr)

        enc448 = aes256_xts_encrypt(hk1, hk2, bytes(plain), 0)
        return salt64 + enc448

    salt_pri = (hashlib.sha512(b"pri:" + salt_seed).digest())
    salt_bak = (hashlib.sha512(b"bak:" + salt_seed).digest())

    pri_area = bytearray(data_off)
    pri_area[0:512] = make_header(salt_pri)

    enc_data = aes256_xts_encrypt(master_k1, master_k2, fs_image, data_off // 512)
    if legacy_v1:
        return bytes(pri_area) + enc_data

    bak_area = bytearray(backup_len)
    bak_area[0:512] = make_header(salt_bak)
    return bytes(pri_area) + enc_data + bytes(bak_area)


# =============================================================================
# Minimal FAT12 / FAT16 / FAT32 & exFAT Image Builders
# =============================================================================
def _vfat_checksum(sfn11: bytes) -> int:
    s = 0
    for b in sfn11:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def _make_fat_dirent(
    name: str,
    attr: int,
    clus: int,
    size: int,
    sfn_idx: int,
    *,
    force_sfn: tuple[bytes, int] | None = None,
) -> bytes:
    if name in (".", ".."):
        sfn = name.encode("ascii").ljust(11, b" ")
        ent = bytearray(32)
        ent[0:11] = sfn
        ent[11] = attr
        struct.pack_into("<H", ent, 20, (clus >> 16) & 0xFFFF)
        struct.pack_into("<H", ent, 26, clus & 0xFFFF)
        struct.pack_into("<I", ent, 28, size)
        return bytes(ent)

    if force_sfn is not None:
        sfn, ntres = force_sfn
        lfn_slots = b""
    else:
        sfn = f"F{sfn_idx:05d}~1BIN".encode("ascii")[:11].ljust(11, b" ")
        ntres = 0
        chk = _vfat_checksum(sfn)
        u16 = name.encode("utf-16le")
        nchars = len(u16) // 2
        nslots = (nchars + 12) // 13
        slots = []
        padded = list(struct.unpack(f"<{nchars}H", u16))
        if len(padded) < nslots * 13:
            padded.append(0x0000)
            while len(padded) < nslots * 13:
                padded.append(0xFFFF)
        for seq in range(nslots, 0, -1):
            chunk = padded[(seq - 1) * 13 : seq * 13]
            sl = bytearray(32)
            sl[0] = seq | (0x40 if seq == nslots else 0)
            for i, pos in enumerate((1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)):
                struct.pack_into("<H", sl, pos, chunk[i])
            sl[11] = 0x0F
            sl[12] = 0
            sl[13] = chk
            struct.pack_into("<H", sl, 26, 0)
            slots.append(bytes(sl))
        lfn_slots = b"".join(slots)

    ent = bytearray(32)
    ent[0:11] = sfn
    ent[11] = attr
    ent[12] = ntres
    struct.pack_into("<H", ent, 20, (clus >> 16) & 0xFFFF)
    struct.pack_into("<H", ent, 26, clus & 0xFFFF)
    struct.pack_into("<I", ent, 28, size)
    return lfn_slots + bytes(ent)


def build_fat_image(
    fat_bits: int,
    tree: dict,
    *,
    spc: int = 1,
    fragment_map: dict[str, list[int]] | None = None,
    inject_deleted_and_label: bool = False,
) -> bytes:
    bps = 512
    cbytes = bps * spc
    if fat_bits == 12:
        nclus = 256
        rsvd = 1
        root_ent = 512
        fatsz = 2
    elif fat_bits == 16:
        nclus = 4200
        rsvd = 1
        root_ent = 512
        fatsz = 17
    else:
        assert fat_bits == 32
        nclus = 512  # FAT32 triggered by FATSz16 == 0 in BPB!
        rsvd = 32
        root_ent = 0
        fatsz = 8

    nfats = 2
    root_sec = ((root_ent * 32) + bps - 1) // bps
    first_data_sec = rsvd + nfats * fatsz + root_sec
    tot_sec = first_data_sec + nclus * spc
    img = bytearray(tot_sec * bps)

    # Boot sector
    img[0:3] = b"\xEB\x58\x90"
    img[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", img, 11, bps)
    img[13] = spc
    struct.pack_into("<H", img, 14, rsvd)
    img[16] = nfats
    struct.pack_into("<H", img, 17, root_ent)
    if tot_sec < 65536 and fat_bits != 32:
        struct.pack_into("<H", img, 19, tot_sec)
    else:
        struct.pack_into("<I", img, 32, tot_sec)
    img[21] = 0xF8
    if fat_bits != 32:
        struct.pack_into("<H", img, 22, fatsz)
        img[54:62] = b"FAT12   " if fat_bits == 12 else b"FAT16   "
    else:
        struct.pack_into("<H", img, 22, 0)
        struct.pack_into("<I", img, 36, fatsz)
        struct.pack_into("<I", img, 44, 2)  # RootClus = 2
        img[82:90] = b"FAT32   "
    struct.pack_into("<H", img, 510, 0xAA55)

    eoc = 0xFFF if fat_bits == 12 else (0xFFFF if fat_bits == 16 else 0x0FFFFFFF)
    fat = [0] * (nclus + 2)
    fat[0] = (eoc & ~0xFF) | 0xF8
    fat[1] = eoc

    used = set([0, 1])
    if fragment_map:
        for seq in fragment_map.values():
            for c in seq:
                used.add(c)
    next_free = [3 if fat_bits == 32 else 2]
    if fat_bits == 32:
        used.add(2)

    def alloc_chain(n_bytes: int, forced: list[int] | None = None) -> list[int]:
        need = max(1, (n_bytes + cbytes - 1) // cbytes) if n_bytes > 0 else 0
        if need == 0:
            return []
        if forced is not None:
            assert len(forced) == need
            chain = forced
        else:
            chain = []
            while len(chain) < need:
                c = next_free[0]
                next_free[0] += 1
                if c not in used:
                    used.add(c)
                    chain.append(c)
        for i in range(len(chain) - 1):
            fat[chain[i]] = chain[i + 1]
        fat[chain[-1]] = eoc
        return chain

    def write_chain(chain: list[int], payload: bytes):
        for idx, c in enumerate(chain):
            off = (first_data_sec + (c - 2) * spc) * bps
            chunk = payload[idx * cbytes : (idx + 1) * cbytes]
            img[off : off + len(chunk)] = chunk

    sfn_counter = [1]

    def build_dir(node: dict, cur_clus: int, parent_clus: int, is_root: bool, rel_prefix: str) -> bytes:
        buf = bytearray()
        if not is_root:
            buf += _make_fat_dirent(".", 0x10, cur_clus, 0, 0)
            buf += _make_fat_dirent("..", 0x10, parent_clus, 0, 0)
        elif inject_deleted_and_label:
            lbl = bytearray(32)
            lbl[0:11] = b"MYVOL_LABEL"
            lbl[11] = 0x08
            buf += lbl
            dele = bytearray(32)
            dele[0] = 0xE5
            dele[1:11] = b"OLDFILETXT"
            dele[11] = 0x20
            buf += dele

        for name, val in node.items():
            full_rel = f"{rel_prefix}{name}"
            idx = sfn_counter[0]
            sfn_counter[0] += 1
            if isinstance(val, dict):
                # Reserve 1 cluster first, grow if dir bytes > cbytes
                dclus = next_free[0]
                while dclus in used:
                    next_free[0] += 1
                    dclus = next_free[0]
                used.add(dclus)
                next_free[0] += 1
                sub_bytes = build_dir(val, dclus, 0 if is_root else cur_clus, False, full_rel + "/")
                need_c = max(1, (len(sub_bytes) + cbytes - 1) // cbytes)
                dchain = [dclus]
                while len(dchain) < need_c:
                    nc = next_free[0]
                    next_free[0] += 1
                    if nc not in used:
                        used.add(nc)
                        dchain.append(nc)
                for i in range(len(dchain) - 1):
                    fat[dchain[i]] = dchain[i + 1]
                fat[dchain[-1]] = eoc
                write_chain(dchain, sub_bytes)
                buf += _make_fat_dirent(name, 0x10, dclus, 0, idx)
            else:
                data, force_sfn = val if isinstance(val, tuple) else (val, None)
                forced = fragment_map.get(full_rel) if fragment_map else None
                fchain = alloc_chain(len(data), forced)
                if fchain:
                    write_chain(fchain, data)
                fclus = fchain[0] if fchain else 0
                buf += _make_fat_dirent(name, 0x20, fclus, len(data), idx, force_sfn=force_sfn)
        return bytes(buf)

    root_bytes = build_dir(tree, 2 if fat_bits == 32 else 0, 0, True, "")
    if fat_bits != 32:
        root_off = (rsvd + nfats * fatsz) * bps
        assert len(root_bytes) <= root_ent * 32
        img[root_off : root_off + len(root_bytes)] = root_bytes
    else:
        need_rc = max(1, (len(root_bytes) + cbytes - 1) // cbytes)
        rchain = [2]
        while len(rchain) < need_rc:
            nc = next_free[0]
            next_free[0] += 1
            if nc not in used:
                used.add(nc)
                rchain.append(nc)
        for i in range(len(rchain) - 1):
            fat[rchain[i]] = rchain[i + 1]
        fat[rchain[-1]] = eoc
        write_chain(rchain, root_bytes)

    # Serialize FAT into both FAT copies
    fat_buf = bytearray(fatsz * bps)
    if fat_bits == 12:
        for c in range(len(fat)):
            off = c + (c >> 1)
            val = fat[c] & 0xFFF
            cur = struct.unpack_from("<H", fat_buf, off)[0]
            if c & 1:
                cur = (cur & 0x000F) | (val << 4)
            else:
                cur = (cur & 0xF000) | val
            struct.pack_into("<H", fat_buf, off, cur)
    elif fat_bits == 16:
        for c in range(len(fat)):
            struct.pack_into("<H", fat_buf, c * 2, fat[c] & 0xFFFF)
    else:
        for c in range(len(fat)):
            struct.pack_into("<I", fat_buf, c * 4, fat[c] & 0x0FFFFFFF)

    for copy_idx in range(nfats):
        foff = (rsvd + copy_idx * fatsz) * bps
        img[foff : foff + len(fat_buf)] = fat_buf

    return bytes(img)


def _exfat_name_hash(u16: bytes) -> int:
    # For read-only extraction our parser validates SetChecksum; compute standard NameHash too
    h = 0
    for i in range(0, len(u16), 2):
        ch = struct.unpack_from("<H", u16, i)[0]
        if 0x61 <= ch <= 0x7A:
            ch -= 0x20
        for b in (ch & 0xFF, (ch >> 8) & 0xFF):
            h = (((h & 1) << 15) | (h >> 1)) + b
            h &= 0xFFFF
    return h


def _exfat_set_checksum(raw_set: bytearray) -> int:
    cs = 0
    for i, b in enumerate(raw_set):
        if i in (2, 3):
            continue
        cs = (((cs & 1) << 15) | (cs >> 1)) + b
        cs &= 0xFFFF
    return cs


def _make_exfat_entry_set(
    name: str,
    is_dir: bool,
    first_clus: int,
    valid_len: int,
    data_len: int,
    no_fat_chain: bool,
) -> bytes:
    u16 = name.encode("utf-16le")
    nchars = len(u16) // 2
    name_ents = (nchars + 14) // 15
    sec_cnt = 1 + name_ents

    e85 = bytearray(32)
    e85[0] = 0x85
    e85[1] = sec_cnt
    struct.pack_into("<H", e85, 4, 0x10 if is_dir else 0x20)

    ec0 = bytearray(32)
    ec0[0] = 0xC0
    flags = (0x01 if data_len > 0 or is_dir else 0x00) | (0x02 if (no_fat_chain and (data_len > 0 or is_dir)) else 0x00)
    ec0[1] = flags
    ec0[3] = nchars
    struct.pack_into("<H", ec0, 4, _exfat_name_hash(u16))
    struct.pack_into("<Q", ec0, 8, valid_len)
    struct.pack_into("<I", ec0, 20, first_clus if (data_len > 0 or is_dir) else 0)
    struct.pack_into("<Q", ec0, 24, data_len)

    c1_list = []
    padded = u16 + b"\x00" * (name_ents * 30 - len(u16))
    for s in range(name_ents):
        ec1 = bytearray(32)
        ec1[0] = 0xC1
        ec1[1] = 0
        ec1[2:32] = padded[s * 30 : (s + 1) * 30]
        c1_list.append(ec1)

    full = bytearray(e85) + bytearray(ec0) + b"".join(c1_list)
    cs = _exfat_set_checksum(full)
    struct.pack_into("<H", full, 2, cs)
    return bytes(full)


def build_exfat_image() -> tuple[bytes, dict[str, bytes]]:
    bps_shift = 9   # 512
    spc_shift = 3   # 8 sectors = 4096 B per cluster
    bps = 1 << bps_shift
    spc = 1 << spc_shift
    cbytes = bps * spc

    fat_off_sec = 24
    fat_len_sec = 4
    heap_off_sec = 32
    nclus = 128
    tot_sec = heap_off_sec + nclus * spc
    img = bytearray(tot_sec * bps)

    # Boot sector
    img[0:3] = b"\xEB\x76\x90"
    img[3:11] = b"EXFAT   "
    # +11..63 MustBeZero (already 0)
    struct.pack_into("<Q", img, 72, tot_sec)
    struct.pack_into("<I", img, 80, fat_off_sec)
    struct.pack_into("<I", img, 84, fat_len_sec)
    struct.pack_into("<I", img, 88, heap_off_sec)
    struct.pack_into("<I", img, 92, nclus)
    struct.pack_into("<I", img, 96, 2)  # RootClus = 2
    img[108] = bps_shift
    img[109] = spc_shift
    img[110] = 1  # NumberOfFats = 1
    struct.pack_into("<H", img, 510, 0xAA55)

    fat = [0] * (nclus + 2)
    fat[0] = 0xFFFFFFF8
    fat[1] = 0xFFFFFFFF

    def clus_off(c: int) -> int:
        return (heap_off_sec + (c - 2) * spc) * bps

    expected: dict[str, bytes] = {}

    # 1. Contiguous NoFatChain file (clusters 10..12 = 10,000 bytes)
    contig_data = hashlib.sha512(b"contig").digest() * 156 + b"TAIL!"
    img[clus_off(10) : clus_off(10) + len(contig_data)] = contig_data
    expected["contiguous_no_fat_chain.bin"] = contig_data

    # 2. Fragmented FAT-chained file across out-of-order clusters 25 -> 21 -> 28
    frag_p0 = b"A" * cbytes
    frag_p1 = b"B" * cbytes
    frag_p2 = b"C" * 1777
    frag_data = frag_p0 + frag_p1 + frag_p2
    fat[25] = 21
    fat[21] = 28
    fat[28] = 0xFFFFFFFF
    img[clus_off(25) : clus_off(25) + cbytes] = frag_p0
    img[clus_off(21) : clus_off(21) + cbytes] = frag_p1
    img[clus_off(28) : clus_off(28) + len(frag_p2)] = frag_p2
    expected["fragmented_chained.bin"] = frag_data

    # 3. ValidDataLength < DataLength (valid=5000, data=9500, non-zero garbage in tail!)
    vdl_valid = (b"VDL_OK_" * 715)[:5000]
    img[clus_off(30) : clus_off(30) + 5000] = vdl_valid
    img[clus_off(30) + 5000 : clus_off(30) + 12000] = b"\xDE\xAD\xBE\xEF" * 1750
    expected["vdl_zero_tail.dat"] = vdl_valid + (b"\x00" * (9500 - 5000))

    # 4. Nested directory "deep/unicode_dir" (cluster 3 -> cluster 4) + Unicode file (cluster 40)
    uni_name = "exfat_über_日本語_test.bin"
    uni_data = b"exFAT Unicode payload!\n" * 300
    img[clus_off(40) : clus_off(40) + len(uni_data)] = uni_data
    expected[f"deep/unicode_dir/{uni_name}"] = uni_data

    # Sub-subdirectory cluster 4 (NoFatChain = True)
    sub2_dir = _make_exfat_entry_set(uni_name, False, 40, len(uni_data), len(uni_data), True)
    img[clus_off(4) : clus_off(4) + len(sub2_dir)] = sub2_dir

    # Subdirectory "deep" cluster 3 (FAT-chained to test dir FAT chain)
    fat[3] = 0xFFFFFFFF
    sub1_dir = _make_exfat_entry_set("unicode_dir", True, 4, cbytes, cbytes, True)
    img[clus_off(3) : clus_off(3) + len(sub1_dir)] = sub1_dir

    # Root directory cluster 2 (NoFatChain = False, FAT[2] = EOC)
    fat[2] = 0xFFFFFFFF
    # Include a benign Volume Label entry (0x83) to verify non-0x85 entries are skipped cleanly
    vol_lbl = bytearray(32)
    vol_lbl[0] = 0x83
    vol_lbl[1] = 4
    vol_lbl[2:10] = "EXFV".encode("utf-16le")

    root_dir = (
        bytes(vol_lbl)
        + _make_exfat_entry_set("contiguous_no_fat_chain.bin", False, 10, len(contig_data), len(contig_data), True)
        + _make_exfat_entry_set("fragmented_chained.bin", False, 25, len(frag_data), len(frag_data), False)
        + _make_exfat_entry_set("vdl_zero_tail.dat", False, 30, 5000, 9500, True)
        + _make_exfat_entry_set("deep", True, 3, cbytes, cbytes, False)
    )
    img[clus_off(2) : clus_off(2) + len(root_dir)] = root_dir

    # Write FAT
    fat_off = fat_off_sec * bps
    for c, v in enumerate(fat):
        struct.pack_into("<I", img, fat_off + c * 4, v)

    return bytes(img), expected


# =============================================================================
# Minimal NTFS Image Builder (USA fixups, $MFT, $I30 B-Tree, Resident, Sparse,
# LZNT1 Compression, DOS 8.3 Alias Deduplication, and $ATTRIBUTE_LIST)
# =============================================================================
def _ntfs_pack_usa(buf: bytearray, magic: bytes, usn: int = 0x0103) -> bytes:
    assert len(buf) % 512 == 0
    nsec = len(buf) // 512
    usa_cnt = nsec + 1
    buf[0:4] = magic
    usa_ofs = 48 if magic == b"FILE" else 40
    struct.pack_into("<HH", buf, 4, usa_ofs, usa_cnt)
    struct.pack_into("<H", buf, usa_ofs, usn)
    for i in range(1, usa_cnt):
        end_pos = i * 512 - 2
        orig = struct.unpack_from("<H", buf, end_pos)[0]
        struct.pack_into("<H", buf, usa_ofs + i * 2, orig)
        struct.pack_into("<H", buf, end_pos, usn)
    return bytes(buf)


def _ntfs_attr_res(atype: int, val: bytes, name: str = "", flags: int = 0) -> bytes:
    nb = name.encode("utf-16le")
    nlen = len(nb) // 2
    hdr_len = (24 + len(nb) + 7) & ~7
    tot_len = (hdr_len + len(val) + 7) & ~7
    b = bytearray(tot_len)
    struct.pack_into("<IIBBHHH", b, 0, atype, tot_len, 0, nlen, 24 if nlen else 0, flags, 0)
    b[24 : 24 + len(nb)] = nb
    struct.pack_into("<IH", b, 16, len(val), hdr_len)
    b[hdr_len : hdr_len + len(val)] = val
    return bytes(b)


def _ntfs_encode_runs(runs: list[tuple[int, int | None]]) -> bytes:
    out = bytearray()
    prev_lcn = 0
    for vlen, lcn in runs:
        assert vlen > 0
        lb = vlen.to_bytes((vlen.bit_length() + 7) // 8, "little", signed=False)
        if lcn is None:
            out.append(len(lb))
            out.extend(lb)
        else:
            delta = lcn - prev_lcn
            prev_lcn = lcn
            # Minimal signed two's-complement byte length
            ob_len = max(1, (delta.bit_length() + 8) // 8)
            ob = delta.to_bytes(ob_len, "little", signed=True)
            out.append((len(ob) << 4) | len(lb))
            out.extend(lb)
            out.extend(ob)
    out.append(0)
    return bytes(out)


def _ntfs_attr_nonres(
    atype: int,
    runs: list[tuple[int, int | None]],
    alloc_sz: int,
    data_sz: int,
    init_sz: int,
    *,
    name: str = "",
    flags: int = 0,
    comp_unit: int = 0,
    low_vcn: int = 0,
) -> bytes:
    nb = name.encode("utf-16le")
    nlen = len(nb) // 2
    hdr_base = 72 if comp_unit else 64
    mp_ofs = (hdr_base + len(nb) + 7) & ~7
    rb = _ntfs_encode_runs(runs)
    tot_len = (mp_ofs + len(rb) + 7) & ~7
    b = bytearray(tot_len)
    struct.pack_into("<IIBBHHH", b, 0, atype, tot_len, 1, nlen, hdr_base if nlen else 0, flags, 0)
    b[hdr_base : hdr_base + len(nb)] = nb
    total_vcns = sum(v for v, _ in runs)
    high_vcn = low_vcn + total_vcns - 1 if total_vcns else 0
    struct.pack_into("<QQHBB", b, 16, low_vcn, high_vcn, mp_ofs, comp_unit, 0)
    struct.pack_into("<QQQ", b, 40, alloc_sz, data_sz, init_sz)
    if comp_unit:
        struct.pack_into("<Q", b, 64, alloc_sz)
    b[mp_ofs : mp_ofs + len(rb)] = rb
    return bytes(b)


def _ntfs_fn_val(parent_rec: int, parent_seq: int, name: str, namespace: int = 1, fn_flags: int = 0) -> bytes:
    u16 = name.encode("utf-16le")
    nchars = len(u16) // 2
    b = bytearray(66 + len(u16))
    pref = (parent_seq << 48) | parent_rec
    struct.pack_into("<Q", b, 0, pref)
    struct.pack_into("<I", b, 56, fn_flags)
    b[64] = nchars
    b[65] = namespace
    b[66:] = u16
    return bytes(b)


def _ntfs_idx_entry(child_rec: int, child_seq: int, fn_val: bytes, sub_vcn: int | None = None) -> bytes:
    flags = 0x01 if sub_vcn is not None else 0x00
    base_len = (16 + len(fn_val) + 7) & ~7
    tot_len = base_len + (8 if sub_vcn is not None else 0)
    b = bytearray(tot_len)
    struct.pack_into("<QHHBB", b, 0, (child_seq << 48) | child_rec, tot_len, len(fn_val), flags, 0)
    b[16 : 16 + len(fn_val)] = fn_val
    if sub_vcn is not None:
        struct.pack_into("<Q", b, tot_len - 8, sub_vcn)
    return bytes(b)


def _ntfs_idx_end(sub_vcn: int | None = None) -> bytes:
    flags = 0x02 | (0x01 if sub_vcn is not None else 0x00)
    tot_len = 24 if sub_vcn is not None else 16
    b = bytearray(tot_len)
    struct.pack_into("<QHHBB", b, 0, 0, tot_len, 0, flags, 0)
    if sub_vcn is not None:
        struct.pack_into("<Q", b, 16, sub_vcn)
    return bytes(b)


def _ntfs_mft_record(seq: int, is_dir: bool, attrs: list[bytes], rec_size: int = 1024) -> bytes:
    rec = bytearray(rec_size)
    attrs_ofs = 56
    body = b"".join(attrs) + struct.pack("<II", 0xFFFFFFFF, 0)
    used = attrs_ofs + len(body)
    assert used <= rec_size
    struct.pack_into("<HHHHII", rec, 16, seq, 1, attrs_ofs, 0x03 if is_dir else 0x01, used, rec_size)
    rec[attrs_ofs : attrs_ofs + len(body)] = body
    return _ntfs_pack_usa(rec, b"FILE")


def _lznt1_compress_simple(plain: bytes) -> bytes:
    """Packs data into valid LZNT1 4096B sub-chunks: chunk 0 uses literals + a back-reference
    match tuple; chunk 1 is stored raw (uncompressed 4096B); followed by 0x0000 terminator."""
    out = bytearray()
    seed = b"LZNT1_HEADER_OK!"  # 16 bytes
    assert len(plain) >= 8192 and plain[:4096] == seed * 256
    # Chunk 0: 16 literal bytes (2 tag bytes of 0x00) + 1 match tuple repeating 4080 bytes!
    # At pos=16, v = pos - 1 = 15 < 0x10 -> o_shift = 12, l_mask = 0xFFF = 4095, max match = 4098 >= 4080.
    sub = bytearray()
    sub.append(0x00)
    sub.extend(seed[:8])
    sub.append(0x00)
    sub.extend(seed[8:16])
    sub.append(0x01)  # bit 0 = match, stream ends right after the 2-byte tuple
    tup = ((16 - 1) << 12) | (4080 - 3)
    sub.extend(struct.pack("<H", tup))
    hdr0 = 0xB000 | (len(sub) - 1)
    out.extend(struct.pack("<H", hdr0))
    out.extend(sub)

    # Chunk 1: uncompressed 4096-byte sub-chunk (header = 0x3FFF -> flag 0x8000 clear, len = 4096)
    chunk1 = plain[4096:8192]
    out.extend(struct.pack("<H", 0x3FFF))
    out.extend(chunk1)

    # Terminator 0x0000 -> rest of compression unit zero-filled
    out.extend(b"\x00\x00")
    return bytes(out)


def build_ntfs_image() -> tuple[bytes, dict[str, bytes]]:
    bps = 512
    spc = 8
    cbytes = bps * spc  # 4096
    tot_clus = 96
    tot_sec = tot_clus * spc
    img = bytearray(tot_sec * bps)

    # $Boot at sector 0
    img[0:3] = b"\xEB\x52\x90"
    img[3:11] = b"NTFS    "
    struct.pack_into("<HB", img, 11, bps, spc)
    img[21] = 0xF8
    struct.pack_into("<QQQ", img, 40, tot_sec, 4, 2)  # MftLcn = 4 (32 records in clusters 4..11)
    struct.pack_into("<b", img, 64, -10)  # 1024B MFT record
    struct.pack_into("<b", img, 68, 1)    # 1 cluster = 4096B INDX block
    struct.pack_into("<H", img, 510, 0xAA55)

    def clus_off(lcn: int) -> int:
        return lcn * cbytes

    def put_mft(rec_num: int, raw1k: bytes):
        off = clus_off(4) + rec_num * 1024
        img[off : off + 1024] = raw1k

    expected: dict[str, bytes] = {}

    # Record 24: Resident $DATA file ("resident_note.txt")
    res_bytes = b"Resident $DATA inside MFT record 24!\n" * 5
    fn24 = _ntfs_fn_val(5, 1, "resident_note.txt", namespace=1)
    put_mft(24, _ntfs_mft_record(2, False, [_ntfs_attr_res(0x30, fn24), _ntfs_attr_res(0x80, res_bytes)]))
    expected["resident_note.txt"] = res_bytes

    # Record 25: Fragmented non-resident file + DOS 8.3 alias deduplication!
    # Cluster 30 (first 4096B) then backwards jump to Cluster 22 (next 2500B)!
    frag_a = hashlib.sha512(b"ntfs_frag_a").digest() * 64  # 4096B
    frag_b = (hashlib.sha512(b"ntfs_frag_b").digest() * 40)[:2500]
    img[clus_off(30) : clus_off(30) + 4096] = frag_a
    img[clus_off(22) : clus_off(22) + 2500] = frag_b
    frag_total = frag_a + frag_b
    fn25_dos = _ntfs_fn_val(5, 1, "LONGFI~1.BIN", namespace=2)
    fn25_win = _ntfs_fn_val(5, 1, "Long_Win32_Fragmented_NTFS.bin", namespace=1)
    put_mft(
        25,
        _ntfs_mft_record(
            3,
            False,
            [
                _ntfs_attr_res(0x30, fn25_dos),
                _ntfs_attr_res(0x30, fn25_win),
                _ntfs_attr_nonres(0x80, [(1, 30), (1, 22)], 8192, len(frag_total), len(frag_total)),
            ],
        ),
    )
    expected["Long_Win32_Fragmented_NTFS.bin"] = frag_total

    # Record 26: Sparse hole + initialized_size < data_size!
    # Run 0: 1 cluster @ LCN 32, Run 1: 2 sparse clusters (8192 zeros), Run 2: 1 cluster @ LCN 33
    # data_size = 18000, init_size = 14000 (so bytes 14000..17999 MUST be zero despite 0xEE garbage!)
    sp_p0 = b"S" * 4096
    sp_p2_valid = b"T" * (14000 - 4096 - 8192)  # 1712 bytes
    img[clus_off(32) : clus_off(32) + 4096] = sp_p0
    img[clus_off(33) : clus_off(33) + len(sp_p2_valid)] = sp_p2_valid
    img[clus_off(33) + len(sp_p2_valid) : clus_off(33) + 4096] = b"\xEE" * (4096 - len(sp_p2_valid))
    fn26 = _ntfs_fn_val(5, 1, "sparse_uninit.dat", namespace=3)
    put_mft(
        26,
        _ntfs_mft_record(
            1,
            False,
            [
                _ntfs_attr_res(0x30, fn26),
                _ntfs_attr_nonres(0x80, [(1, 32), (2, None), (1, 33)], 20480, 18000, 14000),
            ],
        ),
    )
    expected["sparse_uninit.dat"] = sp_p0 + (b"\x00" * 8192) + sp_p2_valid + (b"\x00" * (18000 - 14000))

    # Record 27: Subdirectory "sub_ntfs" containing Record 28 (LZNT1 compressed) & Record 29+30 ($ATTRIBUTE_LIST)!
    lz_chunk0 = b"LZNT1_HEADER_OK!" * 256  # 4096B
    lz_chunk1 = os.urandom(4096)           # 4096B raw sub-chunk
    lz_plain = lz_chunk0 + lz_chunk1 + (b"\x00" * 1800)  # 10,000 bytes total (zero tail after 0x0000)
    lz_comp = _lznt1_compress_simple(lz_plain)
    assert len(lz_comp) <= 2 * cbytes
    img[clus_off(40) : clus_off(40) + len(lz_comp)] = lz_comp
    fn28 = _ntfs_fn_val(27, 1, "lznt1_stream.log", namespace=1)
    put_mft(
        28,
        _ntfs_mft_record(
            1,
            False,
            [
                _ntfs_attr_res(0x30, fn28),
                # 16-cluster unit: 2 physical clusters @ LCN 40 + 14 sparse clusters!
                _ntfs_attr_nonres(
                    0x80, [(2, 40), (14, None)], 16 * cbytes, len(lz_plain), len(lz_plain), flags=0x0001, comp_unit=4
                ),
            ],
        ),
    )
    expected["sub_ntfs/lznt1_stream.log"] = lz_plain

    # Record 29 (base) + Record 30 (extension via $ATTRIBUTE_LIST 0x20)!
    al_payload = b"Attribute-list extension MFT record payload!\n" * 120
    img[clus_off(45) : clus_off(45) + len(al_payload)] = al_payload
    fn29 = _ntfs_fn_val(27, 1, "via_attr_list.bin", namespace=1)
    # $ATTRIBUTE_LIST entry (32 bytes): type=0x80, len=32, name_len=0, name_ofs=26, low_vcn=0, mft_ref=(1<<48)|30
    al_ent = struct.pack("<IHBBQQHHI", 0x80, 32, 0, 26, 0, (1 << 48) | 30, 0, 0, 0)[:32]
    put_mft(29, _ntfs_mft_record(4, False, [_ntfs_attr_res(0x20, al_ent), _ntfs_attr_res(0x30, fn29)]))
    put_mft(30, _ntfs_mft_record(1, False, [_ntfs_attr_nonres(0x80, [(2, 45)], 8192, len(al_payload), len(al_payload))]))
    expected["sub_ntfs/via_attr_list.bin"] = al_payload

    # Record 31: Symlink / Reparse point (MUST be skipped!)
    fn31 = _ntfs_fn_val(5, 1, "bad_reparse_link", namespace=1, fn_flags=0x0400)
    put_mft(31, _ntfs_mft_record(1, False, [_ntfs_attr_res(0x30, fn31), _ntfs_attr_res(0xC0, b"\x00" * 16)]))

    # Build Record 27 ("sub_ntfs" directory, inline $INDEX_ROOT:$I30)
    sub_ents = _ntfs_idx_entry(28, 1, fn28) + _ntfs_idx_entry(29, 4, fn29) + _ntfs_idx_end()
    # Exact INDEX_ROOT header: 16B root hdr + 16B node hdr (entries_ofs=16, idx_len=16+len, alloc_len=16+len, flags=0)
    ir27_val = struct.pack("<IIII", 0x30, 1, cbytes, 1) + struct.pack("<IIII", 16, 16 + len(sub_ents), 16 + len(sub_ents), 0) + sub_ents
    fn27 = _ntfs_fn_val(5, 1, "sub_ntfs", namespace=1)
    put_mft(27, _ntfs_mft_record(1, True, [_ntfs_attr_res(0x30, fn27), _ntfs_attr_res(0x90, ir27_val, name="$I30")]))

    # Build Root Directory Record 5 with $INDEX_ROOT:$I30 pointing to $INDEX_ALLOCATION:$I30 subnode VCN 0 @ LCN 50!
    fn_extend = _ntfs_fn_val(5, 1, "$Extend", namespace=3)  # system $ name at root -> skipped
    leaf_ents = (
        _ntfs_idx_entry(11, 1, fn_extend)
        + _ntfs_idx_entry(24, 2, fn24)
        + _ntfs_idx_entry(25, 3, fn25_dos)
        + _ntfs_idx_entry(25, 3, fn25_win)
        + _ntfs_idx_entry(26, 1, fn26)
        + _ntfs_idx_entry(27, 1, fn27)
        + _ntfs_idx_entry(31, 1, fn31)
        + _ntfs_idx_end()
    )
    indx_blk = bytearray(cbytes)
    struct.pack_into("<Q", indx_blk, 16, 0)  # VCN 0
    ent_ofs = 40  # relative to +24 -> starts at +64 (8B-aligned, past 9-word USA array at +40..57)
    struct.pack_into("<IIII", indx_blk, 24, ent_ofs, ent_ofs + len(leaf_ents), cbytes - 24, 0)
    indx_blk[24 + ent_ofs : 24 + ent_ofs + len(leaf_ents)] = leaf_ents
    img[clus_off(50) : clus_off(50) + cbytes] = _ntfs_pack_usa(indx_blk, b"INDX")

    root_ents = _ntfs_idx_end(sub_vcn=0)
    ir5_val = struct.pack("<IIII", 0x30, 1, cbytes, 1) + struct.pack("<IIII", 16, 16 + len(root_ents), 16 + len(root_ents), 1) + root_ents
    put_mft(
        5,
        _ntfs_mft_record(
            1,
            True,
            [
                _ntfs_attr_res(0x90, ir5_val, name="$I30"),
                _ntfs_attr_nonres(0xA0, [(1, 50)], cbytes, cbytes, cbytes, name="$I30"),
            ],
        ),
    )

    # Record 0: $MFT itself (32 records = 32 KiB = 8 clusters @ LCN 4)
    put_mft(0, _ntfs_mft_record(1, False, [_ntfs_attr_nonres(0x80, [(8, 4)], 8 * cbytes, 8 * cbytes, 8 * cbytes)]))

    return bytes(img), expected


# =============================================================================
# Minimal ext2 (indirect blocks) & ext4 (64-bit + Extent B-Tree) Image Builders
# =============================================================================
def _ext_dirent(ino: int, name_raw: bytes, ftype: int, rec_len: int | None = None) -> bytes:
    min_len = (8 + len(name_raw) + 3) & ~3
    rlen = rec_len if rec_len is not None else min_len
    b = bytearray(rlen)
    struct.pack_into("<IHBB", b, 0, ino, rlen, len(name_raw), ftype)
    b[8 : 8 + len(name_raw)] = name_raw
    return bytes(b)


def _pack_ext_dir_block(entries: list[tuple[int, bytes, int]], bsize: int) -> bytes:
    buf = bytearray()
    for i, (ino, nm, ft) in enumerate(entries):
        if i + 1 < len(entries):
            buf.extend(_ext_dirent(ino, nm, ft))
        else:
            buf.extend(_ext_dirent(ino, nm, ft, rec_len=bsize - len(buf)))
    assert len(buf) == bsize
    return bytes(buf)


def build_ext2_image() -> tuple[bytes, dict[str, bytes]]:
    bsize = 1024
    tot_blks = 320
    inodes_pg = 32
    inode_sz = 128
    img = bytearray(tot_blks * bsize)

    # Superblock at +1024 (block 1); GDT at block 2; inode table at block 3..6 (4 blocks)
    sb = memoryview(img)[1024:2048]
    struct.pack_into("<III", sb, 0, inodes_pg, tot_blks, 0)
    struct.pack_into("<II", sb, 20, 1, 0)  # s_first_data_block = 1, log_block_size = 0 (1024B)
    struct.pack_into("<III", sb, 32, tot_blks, tot_blks, inodes_pg)
    struct.pack_into("<H", sb, 56, 0xEF53)
    struct.pack_into("<I", sb, 76, 1)  # rev 1
    struct.pack_into("<IH", sb, 84, 11, inode_sz)
    struct.pack_into("<I", sb, 96, 0x0002)  # EXT_INCOMPAT_FILETYPE

    # Group descriptor 0 at block 2 (offset 2048): bg_inode_table_lo = 3
    struct.pack_into("<III", img, 2048, 7, 8, 3)

    def put_inode(ino: int, mode: int, size: int, flags: int, iblock60: bytes):
        off = 3 * bsize + (ino - 1) * inode_sz
        ino_b = bytearray(inode_sz)
        struct.pack_into("<HHI", ino_b, 0, mode, 0, size & 0xFFFFFFFF)
        struct.pack_into("<I", ino_b, 32, flags)
        ino_b[40 : 40 + len(iblock60)] = iblock60
        struct.pack_into("<I", ino_b, 108, (size >> 32) & 0xFFFFFFFF)
        img[off : off + inode_sz] = ino_b

    expected: dict[str, bytes] = {}

    file_parts = bytearray()
    direct_ptrs = []
    for i in range(12):
        pblk = 20 + i
        blk_data = bytes([(0x30 + i) & 0xFF]) * bsize
        img[pblk * bsize : (pblk + 1) * bsize] = blk_data
        file_parts.extend(blk_data)
        direct_ptrs.append(pblk)

    # Single-indirect block 32: slot 0 -> blk 33, slot 1 -> 0 (sparse), slot 2 -> blk 34, slots 3..255 -> 0 (sparse!)
    b33 = b"IND1_SLOT0!" * 93 + b"X"
    b34 = b"IND1_SLOT2!" * 93 + b"Y"
    img[33 * bsize : 34 * bsize] = b33
    img[34 * bsize : 35 * bsize] = b34
    struct.pack_into("<III", img, 32 * bsize, 33, 0, 34)
    file_parts.extend(b33)
    file_parts.extend(b"\x00" * bsize)
    file_parts.extend(b34)
    file_parts.extend(b"\x00" * (253 * bsize))

    # Double-indirect block 35 -> slot 0 = blk 36 -> slot 0 = blk 37 (partial tail 333 bytes!)
    b37 = b"DBL_INDIRECT_TAIL!" * 18 + b"END_EXT2!"  # 333 bytes
    img[37 * bsize : 37 * bsize + len(b37)] = b37
    struct.pack_into("<I", img, 35 * bsize, 36)
    struct.pack_into("<I", img, 36 * bsize, 37)
    file_parts.extend(b37)

    ib12 = struct.pack("<15I", *direct_ptrs, 32, 35, 0)
    put_inode(12, 0x81A4, len(file_parts), 0, ib12)
    expected["indirect_and_sparse.bin"] = bytes(file_parts)

    # Inode 13: Raw Latin-1 non-UTF-8 filename (b"caf\xe9_note.txt" -> "café_note.txt")
    lat_body = b"Lossless Latin-1 filename decoding on ext2!\n"
    img[40 * bsize : 40 * bsize + len(lat_body)] = lat_body
    put_inode(13, 0x81A4, len(lat_body), 0, struct.pack("<I", 40))
    expected["café_note.txt"] = lat_body

    # Inode 14: Symlink (0xA1FF) -> MUST be skipped!
    put_inode(14, 0xA1FF, 10, 0, b"/etc/hosts")

    # Root Inode 2 -> directory block 10
    root_blk = _pack_ext_dir_block(
        [
            (2, b".", 2),
            (2, b"..", 2),
            (12, b"indirect_and_sparse.bin", 1),
            (13, b"caf\xe9_note.txt", 1),
            (14, b"skipped_symlink", 7),
        ],
        bsize,
    )
    img[10 * bsize : 11 * bsize] = root_blk
    put_inode(2, 0x41ED, bsize, 0, struct.pack("<I", 10))

    return bytes(img), expected


def build_ext4_image() -> tuple[bytes, dict[str, bytes]]:
    bsize = 4096
    tot_blks = 64
    inodes_pg = 32
    inode_sz = 256
    desc_sz = 64
    img = bytearray(tot_blks * bsize)

    # Superblock at +1024 (inside block 0); GDT at block 1; inode table at blocks 2..3
    sb = memoryview(img)[1024:2048]
    struct.pack_into("<III", sb, 0, inodes_pg, tot_blks, 0)
    struct.pack_into("<II", sb, 20, 0, 2)  # s_first_data_block = 0, log_block_size = 2 (4096B)
    struct.pack_into("<III", sb, 32, tot_blks, tot_blks, inodes_pg)
    struct.pack_into("<H", sb, 56, 0xEF53)
    struct.pack_into("<I", sb, 76, 1)
    struct.pack_into("<IH", sb, 84, 11, inode_sz)
    # INCOMPAT: FILETYPE (0x02) | EXTENTS (0x40) | 64BIT (0x80) = 0xC2
    struct.pack_into("<I", sb, 96, 0x00C2)
    struct.pack_into("<H", sb, 254, desc_sz)

    # 64B group descriptor at block 1 (offset 4096): bg_inode_table_lo = 2, hi = 0
    struct.pack_into("<III", img, 4096, 4, 5, 2)

    def _ext4_leaf_hdr(entries: list[tuple[int, int, int]]) -> bytes:
        hdr = struct.pack("<HHHHI", 0xF30A, len(entries), 4, 0, 0)
        body = b"".join(
            struct.pack("<IHHI", lblk, elen, (pblk >> 32) & 0xFFFF, pblk & 0xFFFFFFFF)
            for lblk, elen, pblk in entries
        )
        return hdr + body

    def put_inode(ino: int, mode: int, size: int, flags: int, iblock60: bytes):
        off = 2 * bsize + (ino - 1) * inode_sz
        ino_b = bytearray(inode_sz)
        struct.pack_into("<HHI", ino_b, 0, mode, 0, size & 0xFFFFFFFF)
        struct.pack_into("<I", ino_b, 32, flags)
        ino_b[40 : 40 + len(iblock60)] = iblock60
        struct.pack_into("<I", ino_b, 108, (size >> 32) & 0xFFFFFFFF)
        img[off : off + inode_sz] = ino_b

    expected: dict[str, bytes] = {}

    # Inode 12: 2-level extent B-tree (eh_depth=1 in inode -> leaf block 15)!
    # Logical 0..1 -> phys 20..21 (init); Logical 2 -> sparse gap;
    # Logical 3..4 -> uninitialized extent (ee_len = 32768 + 2, phys 22..23 filled with 0xAA garbage -> MUST read as zeros!);
    # Logical 5 -> phys 24 (partial tail 1234 bytes).
    e_init0 = os.urandom(2 * bsize)
    img[20 * bsize : 22 * bsize] = e_init0
    img[22 * bsize : 24 * bsize] = b"\xAA" * (2 * bsize)  # uninit garbage!
    e_tail = b"EXT4_DEPTH1_TAIL!" * 72 + b"Z" * 10         # 1234 bytes
    img[24 * bsize : 24 * bsize + len(e_tail)] = e_tail

    leaf_bytes = _ext4_leaf_hdr([(0, 2, 20), (3, 32768 + 2, 22), (5, 1, 24)])
    img[15 * bsize : 15 * bsize + len(leaf_bytes)] = leaf_bytes

    idx_root = struct.pack("<HHHHI", 0xF30A, 1, 4, 1, 0) + struct.pack("<IIHH", 0, 15, 0, 0)
    tot_f12 = 5 * bsize + len(e_tail)
    put_inode(12, 0x81A4, tot_f12, 0x80000, idx_root)
    expected["var/log/ext4_tree_uninit.bin"] = e_init0 + (b"\x00" * (3 * bsize)) + e_tail

    # Subdirs "var" (ino 10, blk 11) -> "log" (ino 11, blk 12)
    img[12 * bsize : 13 * bsize] = _pack_ext_dir_block(
        [(11, b".", 2), (10, b"..", 2), (12, b"ext4_tree_uninit.bin", 1)], bsize
    )
    put_inode(11, 0x41ED, bsize, 0x80000, _ext4_leaf_hdr([(0, 1, 12)]))

    img[11 * bsize : 12 * bsize] = _pack_ext_dir_block([(10, b".", 2), (2, b"..", 2), (11, b"log", 2)], bsize)
    put_inode(10, 0x41ED, bsize, 0x80000, _ext4_leaf_hdr([(0, 1, 11)]))

    img[10 * bsize : 11 * bsize] = _pack_ext_dir_block([(2, b".", 2), (2, b"..", 2), (10, b"var", 2)], bsize)
    put_inode(2, 0x41ED, bsize, 0x80000, _ext4_leaf_hdr([(0, 1, 10)]))

    return bytes(img), expected


# =============================================================================
# Minimal macOS HFS+ ("H+" in "BD" HFS Wrapper + Overflow B-Tree) & HFSX ("HX")
# =============================================================================
def _hfs_pack_btree_node(kind: int, height: int, f_link: int, b_link: int, records: list[bytes], node_size: int) -> bytes:
    node = bytearray(node_size)
    struct.pack_into(">IIbbHH", node, 0, f_link, b_link, kind, height, len(records), 0)
    pos = 14
    offsets = [pos]
    for rec in records:
        node[pos : pos + len(rec)] = rec
        pos += len(rec)
        offsets.append(pos)
    for i, off in enumerate(offsets):
        struct.pack_into(">H", node, node_size - 2 * (i + 1), off)
    return bytes(node)


def _hfs_btree_hdr_node(tree_depth: int, root_node: int, leaf_recs: int, first_leaf: int, last_leaf: int, node_size: int, total_nodes: int) -> bytes:
    hdr_rec = bytearray(106)
    struct.pack_into(">HIIIIHHII", hdr_rec, 0, tree_depth, root_node, leaf_recs, first_leaf, last_leaf, node_size, 516, total_nodes, 0)
    struct.pack_into(">I", hdr_rec, 38, 0x00000006)  # kBTBigKeysMask | kBTVariableIndexKeysMask
    user_rec = bytes(128)
    map_rec = bytes(node_size - 256)
    return _hfs_pack_btree_node(1, 0, 0, 0, [bytes(hdr_rec), user_rec, map_rec], node_size)


def _hfs_cat_key(parent_id: int, name_u16be_units: list[int] | str) -> bytes:
    if isinstance(name_u16be_units, str):
        u16be = name_u16be_units.encode("utf-16be")
        nchars = len(u16be) // 2
    else:
        nchars = len(name_u16be_units)
        u16be = struct.pack(f">{nchars}H", *name_u16be_units)
    key_len = 6 + len(u16be)
    return struct.pack(">HIH", key_len, parent_id, nchars) + u16be


def _hfs_folder_rec(folder_id: int) -> bytes:
    b = bytearray(88)
    struct.pack_into(">HHII", b, 0, 1, 0, 0, folder_id)
    return bytes(b)


def _hfs_file_rec(
    file_id: int,
    logical_size: int,
    total_blocks: int,
    extents8: list[tuple[int, int]],
    *,
    file_mode: int = 0x81A4,
    fd_type: int = 0,
) -> bytes:
    b = bytearray(248)
    struct.pack_into(">HHII", b, 0, 2, 0, 0, file_id)
    struct.pack_into(">H", b, 48, file_mode)
    struct.pack_into(">I", b, 56, fd_type)
    struct.pack_into(">QII", b, 88, logical_size, 0, total_blocks)
    for i, (sb, bc) in enumerate(extents8[:8]):
        struct.pack_into(">II", b, 104 + i * 8, sb, bc)
    return bytes(b)


def build_hfsplus_wrapped_image() -> tuple[bytes, dict[str, bytes]]:
    """Builds an HFS+ v4 ('H+') volume embedded inside a classic 'BD' HFS wrapper,
    with a 2-level Catalog B-Tree (2 linked leaves), NFD decomposed Unicode name,
    Finder ':' slash substitution, skipped macOS journal/private/symlink entries,
    and an 11-extent file overflowing into the Extents Overflow B-Tree!"""
    embed_off = 8192
    bsize = 512
    tot_blks = 256
    part_bytes = tot_blks * bsize
    img = bytearray(embed_off + part_bytes)

    # Classic "BD" HFS Master Directory Block at +1024 pointing to embed_off = 8192 (drAlBlSt=4 -> 2048, drAlBlkSiz=2048, startBlock=3 -> 2048 + 6144 = 8192!)
    struct.pack_into(">H", img, 1024 + 0, 0x4244)
    struct.pack_into(">I", img, 1024 + 20, 2048)       # drAlBlkSiz
    struct.pack_into(">H", img, 1024 + 28, 4)          # drAlBlSt (4 * 512 = 2048)
    struct.pack_into(">HHH", img, 1024 + 124, 0x482B, 3, part_bytes // 2048)

    def blk_off(b: int) -> int:
        return embed_off + b * bsize

    expected: dict[str, bytes] = {}

    # 1. NFD decomposed Unicode filename: "Mac_Cafe\u0301_u\u0308ber.txt" -> NFC "Mac_Café_über.txt"
    nfd_name = "Mac_Cafe\u0301_u\u0308ber.txt"
    nfc_name = "Mac_Café_über.txt"
    nfd_body = b"macOS HFS+ NFD -> NFC precomposed UTF-8 test!\n" * 15
    img[blk_off(40) : blk_off(40) + len(nfd_body)] = nfd_body
    expected[nfc_name] = nfd_body

    # 2. Finder ':' filename ("2026:11 Report.txt" -> "2026_11 Report.txt") inside folder "Projects" (CNID 20)
    colon_body = b"Finder slash stored as colon in HFS+ Catalog!\n"
    img[blk_off(44) : blk_off(44) + len(colon_body)] = colon_body
    expected["Projects/2026_11 Report.txt"] = colon_body

    # 3. Fragmented 11-extent file (CNID 30): 8 inline non-contiguous 1-block extents + 3 overflow extents!
    ext_blocks = [50, 52, 54, 56, 58, 60, 62, 64, 70, 73, 76]
    frag_body = bytearray()
    for idx, pb in enumerate(ext_blocks):
        chunk = bytes([0x41 + idx]) * (bsize if idx < 10 else 311)
        img[blk_off(pb) : blk_off(pb) + len(chunk)] = chunk
        frag_body.extend(chunk)
    expected["Projects/overflow_11_extents.bin"] = bytes(frag_body)

    # Build Extents Overflow B-Tree (node_size = 1024, 2 nodes = 4 blocks @ blk 10..13):
    # Node 0 = Header (root=1, depth=1), Node 1 = Leaf with key (fork=0, fileID=30, startBlock=8) -> [(70,1), (73,1), (76,1)]
    ext_nsize = 1024
    ovf_rec = bytearray(12 + 64)
    struct.pack_into(">HBBI", ovf_rec, 0, 10, 0, 0, 30)
    struct.pack_into(">I", ovf_rec, 8, 8)  # logical startBlock = 8
    for i, (sb, bc) in enumerate([(70, 1), (73, 1), (76, 1)]):
        struct.pack_into(">II", ovf_rec, 12 + i * 8, sb, bc)
    ext_n0 = _hfs_btree_hdr_node(1, 1, 1, 1, 1, ext_nsize, 2)
    ext_n1 = _hfs_pack_btree_node(-1, 1, 0, 0, [bytes(ovf_rec)], ext_nsize)
    img[blk_off(10) : blk_off(10) + 2 * ext_nsize] = ext_n0 + ext_n1

    # Build Catalog B-Tree (node_size = 4096, 4 nodes = 32 blocks @ blk 100..131):
    # Node 0 = Header (depth=2, root=1)
    # Node 1 = Index node pointing to Leaf 2 (parentID=2) and Leaf 3 (parentID=20)
    # Leaf 2 (fLink=3): root children (including .journal, \0\0\0\0HFS+ Private Data, symlink, nfd_name, Projects folder CNID 20)
    # Leaf 3 (fLink=0): CNID 20 children ("2026:11 Report.txt" and "overflow_11_extents.bin")
    cat_nsize = 4096
    priv_units = [0, 0, 0, 0] + [ord(c) for c in "HFS+ Private Data"]
    leaf2_recs = [
        _hfs_cat_key(2, priv_units) + _hfs_folder_rec(18),
        _hfs_cat_key(2, ".journal") + _hfs_file_rec(19, 512, 1, [(39, 1)]),
        _hfs_cat_key(2, "bad_symlink") + _hfs_file_rec(21, 12, 1, [(38, 1)], file_mode=0xA1FF),
        _hfs_cat_key(2, nfd_name) + _hfs_file_rec(22, len(nfd_body), 2, [(40, 2)]),
        _hfs_cat_key(2, "Projects") + _hfs_folder_rec(20),
    ]
    leaf3_recs = [
        _hfs_cat_key(20, "") + struct.pack(">H", 3) + bytes(16),  # folder thread record (type 3) -> ignored
        _hfs_cat_key(20, "2026:11 Report.txt") + _hfs_file_rec(25, len(colon_body), 1, [(44, 1)]),
        _hfs_cat_key(20, "overflow_11_extents.bin")
        + _hfs_file_rec(30, len(frag_body), 11, [(b, 1) for b in ext_blocks[:8]]),
    ]
    cat_n0 = _hfs_btree_hdr_node(2, 1, len(leaf2_recs) + len(leaf3_recs), 2, 3, cat_nsize, 4)
    idx_recs = [
        _hfs_cat_key(2, priv_units) + struct.pack(">I", 2),
        _hfs_cat_key(20, "") + struct.pack(">I", 3),
    ]
    cat_n1 = _hfs_pack_btree_node(0, 2, 0, 0, idx_recs, cat_nsize)
    cat_n2 = _hfs_pack_btree_node(-1, 1, 3, 0, leaf2_recs, cat_nsize)
    cat_n3 = _hfs_pack_btree_node(-1, 1, 0, 2, leaf3_recs, cat_nsize)
    cat_blob = cat_n0 + cat_n1 + cat_n2 + cat_n3
    img[blk_off(100) : blk_off(100) + len(cat_blob)] = cat_blob

    # Volume Header at embed_off + 1024
    vh = bytearray(512)
    struct.pack_into(">HH", vh, 0, 0x482B, 4)          # "H+", version 4
    struct.pack_into(">II", vh, 40, bsize, tot_blks)
    # extentsFile at +192
    struct.pack_into(">QII", vh, 192, 2 * ext_nsize, 0, (2 * ext_nsize) // bsize)
    struct.pack_into(">II", vh, 192 + 16, 10, (2 * ext_nsize) // bsize)
    # catalogFile at +272
    struct.pack_into(">QII", vh, 272, len(cat_blob), 0, len(cat_blob) // bsize)
    struct.pack_into(">II", vh, 272 + 16, 100, len(cat_blob) // bsize)
    img[embed_off + 1024 : embed_off + 1536] = vh

    return bytes(img), expected


def build_hfsx_image() -> tuple[bytes, dict[str, bytes]]:
    """Builds a direct case-sensitive HFSX ('HX', v5) volume."""
    bsize = 4096
    tot_blks = 32
    img = bytearray(tot_blks * bsize)

    body_a = b"HFSX v5 case-sensitive volume test payload!\n" * 50
    img[10 * bsize : 10 * bsize + len(body_a)] = body_a
    expected = {"CaseDir/Readme_HX.txt": body_a}

    cat_nsize = 8192
    leaf_recs = [
        _hfs_cat_key(2, "CaseDir") + _hfs_folder_rec(16),
        _hfs_cat_key(16, "Readme_HX.txt") + _hfs_file_rec(17, len(body_a), 1, [(10, 1)], file_mode=0),
    ]
    cat_n0 = _hfs_btree_hdr_node(1, 1, 2, 1, 1, cat_nsize, 2)
    cat_n1 = _hfs_pack_btree_node(-1, 1, 0, 0, leaf_recs, cat_nsize)
    cat_blob = cat_n0 + cat_n1
    img[4 * bsize : 4 * bsize + len(cat_blob)] = cat_blob

    vh = bytearray(512)
    struct.pack_into(">HH", vh, 0, 0x4858, 5)  # "HX", version 5
    struct.pack_into(">II", vh, 40, bsize, tot_blks)
    struct.pack_into(">QII", vh, 272, len(cat_blob), 0, len(cat_blob) // bsize)
    struct.pack_into(">II", vh, 272 + 16, 4, len(cat_blob) // bsize)
    img[1024:1536] = vh

    return bytes(img), expected


# =============================================================================
# Test Runner Helpers
# =============================================================================
def run_myrkr(exe: str, args: list[str]) -> tuple[int, str]:
    p = subprocess.run([exe] + args, capture_output=True, timeout=120)
    out = (p.stdout + p.stderr).decode("utf-8", errors="replace")
    return (p.returncode & 0xFFFFFFFF), out


def collect_extracted_files(root_dir: str) -> dict[str, bytes]:
    got: dict[str, bytes] = {}
    for base, _dirs, files in os.walk(root_dir):
        for fn in files:
            full = os.path.join(base, fn)
            rel = os.path.relpath(full, root_dir).replace("\\", "/")
            with open(full, "rb") as f:
                got[rel] = f.read()
    return got


def assert_tree_matches(got: dict[str, bytes], expected: dict[str, bytes], label: str):
    if set(got.keys()) != set(expected.keys()):
        raise AssertionError(
            f"[{label}] file set mismatch:\n  got:      {sorted(got.keys())}\n  expected: {sorted(expected.keys())}"
        )
    for k, want_bytes in expected.items():
        if got[k] != want_bytes:
            raise AssertionError(
                f"[{label}] content mismatch for {k!r}: got {len(got[k])} B (sha256={hashlib.sha256(got[k]).hexdigest()[:16]}), "
                f"want {len(want_bytes)} B (sha256={hashlib.sha256(want_bytes).hexdigest()[:16]})"
            )


def main() -> int:
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join("bin", "myrkr.exe"))
    if not os.path.isfile(exe):
        print(f"error: executable not found: {exe}", file=sys.stderr)
        return 1

    print(f"exe = {exe}")
    print("== TrueCrypt / VeraCrypt Stage 2 Integration Suite ==")
    failures = 0

    with tempfile.TemporaryDirectory(prefix="myrkr_tcvc_") as tmp:
        # ---------------------------------------------------------------------
        # Case 1: TrueCrypt .tc + FAT12 (even/odd FAT12 chain, NTRes lowercase,
        #         VFAT Unicode LFN, 0-byte file, nested dirs, default -o)
        # ---------------------------------------------------------------------
        try:
            u_name = "Unicode_LFN_Файл_αβγ_long_filename_test.dat"
            lfn_payload = os.urandom(3700)  # 8 clusters across odd/even FAT12 entries
            note_payload = b"# Nested Notes\nHello from FAT12!\n"
            readme_payload = b"8.3 lowercase base+ext via NTRes=0x18!\n"

            fat12_tree = {
                "readme.txt": (readme_payload, (b"README  TXT", 0x18)),
                "zero.bin": b"",
                u_name: lfn_payload,
                "docs": {"sub": {"notes.md": note_payload}},
            }
            fat12_expected = {
                "readme.txt": readme_payload,
                "zero.bin": b"",
                u_name: lfn_payload,
                "docs/sub/notes.md": note_payload,
            }
            fat12_img = build_fat_image(
                12,
                fat12_tree,
                fragment_map={u_name: [9, 4, 7, 2, 11, 6, 3, 8]},  # odd <-> even jumps!
            )
            tc12_path = os.path.join(tmp, "vol_fat12.tc")
            with open(tc12_path, "wb") as f:
                f.write(build_tcvc_volume(fat12_img, b"Tr0ub4dor&TC71a!", [], is_vera=False, kdf_alg="sha512", salt_seed=b"f12"))

            rc, out = run_myrkr(exe, ["verify", tc12_path, "-p", "Tr0ub4dor&TC71a!"])
            assert rc == EXIT_OK and "verified: OK" in out, f"verify failed: rc={rc} out={out}"

            rc, out = run_myrkr(exe, ["list", tc12_path, "-p", "Tr0ub4dor&TC71a!"])
            assert rc == EXIT_OK and "docs/sub/notes.md" in out and "readme.txt" in out, f"list failed: rc={rc} out={out}"

            # Default output folder (omitting -o strips .tc -> tmp/vol_fat12)
            rc, out = run_myrkr(exe, ["decrypt", tc12_path, "-p", "Tr0ub4dor&TC71a!"])
            assert rc == EXIT_OK, f"decrypt failed: rc={rc} out={out}"
            got12 = collect_extracted_files(os.path.join(tmp, "vol_fat12"))
            assert_tree_matches(got12, fat12_expected, "TC-FAT12")
            print("  [PASS] TC 7.1a + FAT12 (odd/even 12-bit chains, NTRes 8.3, VFAT Unicode, 0B, default -o)")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] TC 7.1a + FAT12: {exc}")

        # ---------------------------------------------------------------------
        # Case 2: VeraCrypt .hc + FAT16 (>64 KiB file, password + 2 keyfiles
        #         supplied in reverse order)
        # ---------------------------------------------------------------------
        try:
            kf1 = os.path.join(tmp, "alpha.key")
            kf2 = os.path.join(tmp, "beta.key")
            kf1_b = os.urandom(4096)
            kf2_b = os.urandom(90000)  # > 64 KiB keyfile read chunk boundary!
            with open(kf1, "wb") as f:
                f.write(kf1_b)
            with open(kf2, "wb") as f:
                f.write(kf2_b)

            big_payload = os.urandom(150_000)  # crosses 64 KiB sector cache multiple times
            fat16_tree = {
                "large_stream.bin": big_payload,
                "nested": {"cfg.json": b'{"ok": true}\n'},
            }
            fat16_expected = {
                "large_stream.bin": big_payload,
                "nested/cfg.json": b'{"ok": true}\n',
            }
            fat16_img = build_fat_image(16, fat16_tree, spc=2)
            hc16_path = os.path.join(tmp, "vol_fat16.hc")
            with open(hc16_path, "wb") as f:
                f.write(
                    build_tcvc_volume(
                        fat16_img,
                        b"VeraPass#2026",
                        [kf1_b, kf2_b],
                        is_vera=True,
                        kdf_alg="sha256",
                        salt_seed=b"f16",
                    )
                )

            out16 = os.path.join(tmp, "out_fat16")
            # Supply keyfiles in REVERSE order [kf2, kf1] to prove order-independence!
            rc, out = run_myrkr(
                exe,
                ["decrypt", hc16_path, "-o", out16, "-p", "VeraPass#2026", "--keyfile", kf2, "--keyfile", kf1],
            )
            assert rc == EXIT_OK, f"decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out16), fat16_expected, "VC-FAT16")

            # Missing one keyfile must fail with EXIT_AUTH
            rc_bad, _ = run_myrkr(exe, ["verify", hc16_path, "-p", "VeraPass#2026", "--keyfile", kf1])
            assert rc_bad == EXIT_AUTH, f"expected EXIT_AUTH when missing kf2, got {rc_bad}"
            print("  [PASS] VeraCrypt + FAT16 (>64 KiB cache cross, multi-keyfile order-independence, missing-kf auth fail)")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] VeraCrypt + FAT16: {exc}")

        # ---------------------------------------------------------------------
        # Case 3: TrueCrypt .tc + FAT32 (multi-cluster root dir, deleted/label
        #         entries, high cluster bits, keyfile-only omitted -p & -p "")
        # ---------------------------------------------------------------------
        try:
            kf_only = os.path.join(tmp, "master.kf")
            kf_only_b = os.urandom(2048)
            with open(kf_only, "wb") as f:
                f.write(kf_only_b)

            fat32_tree: dict = {}
            fat32_expected: dict[str, bytes] = {}
            # 18 long-named files force root directory to span > 1 cluster (512B)!
            for i in range(18):
                fn = f"entry_{i:02d}_cluster_spanned_directory_item.txt"
                body = f"FAT32 payload #{i}\n".encode("utf-8") * (i + 1)
                fat32_tree[fn] = body
                fat32_expected[fn] = body

            fat32_img = build_fat_image(32, fat32_tree, spc=1, inject_deleted_and_label=True)
            tc32_path = os.path.join(tmp, "vol_fat32.TC")  # uppercase .TC tests case-insensitive routing!
            with open(tc32_path, "wb") as f:
                f.write(
                    build_tcvc_volume(
                        fat32_img,
                        b"",
                        [kf_only_b],
                        is_vera=False,
                        kdf_alg="ripemd160",
                        salt_seed=b"f32",
                    )
                )

            out32_a = os.path.join(tmp, "out_fat32_omit_p")
            rc, out = run_myrkr(exe, ["decrypt", tc32_path, "-o", out32_a, "--keyfile", kf_only])
            assert rc == EXIT_OK, f"keyfile-only (omitted -p) failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out32_a), fat32_expected, "TC-FAT32-omit-p")

            out32_b = os.path.join(tmp, "out_fat32_empty_p")
            rc, out = run_myrkr(exe, ["decrypt", tc32_path, "-o", out32_b, "-p", "", "--keyfile", kf_only])
            assert rc == EXIT_OK, f"keyfile-only (-p '') failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out32_b), fat32_expected, "TC-FAT32-empty-p")
            print("  [PASS] TC 7.1a RIPEMD-160 + FAT32 (.TC uppercase, multi-cluster dir, keyfile-only omitted/-p '')")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] TC 7.1a + FAT32: {exc}")

        # ---------------------------------------------------------------------
        # Case 4: VeraCrypt BLAKE2s .hc + exFAT (NoFatChain + FAT-chained +
        #         ValidDataLength zero-tail + keyfile folder holding volume +
        #         backup header fallback!)
        # ---------------------------------------------------------------------
        try:
            kf_dir = os.path.join(tmp, "kf_folder")
            os.makedirs(kf_dir, exist_ok=True)
            kfa_b = os.urandom(1500)
            kfb_b = os.urandom(2500)
            with open(os.path.join(kf_dir, "k1.bin"), "wb") as f:
                f.write(kfa_b)
            with open(os.path.join(kf_dir, "k2.bin"), "wb") as f:
                f.write(kfb_b)

            # Hidden file inside keyfile folder MUST be ignored per VeraCrypt Keyfiles.c:349
            hidden_kf = os.path.join(kf_dir, "ignored_hidden.bin")
            with open(hidden_kf, "wb") as f:
                f.write(b"MUST_NOT_BE_MIXED")
            ctypes.windll.kernel32.SetFileAttributesW(ctypes.c_wchar_p(hidden_kf), FILE_ATTRIBUTE_HIDDEN)

            exf_img, exf_expected = build_exfat_image()
            # Place the .hc container INSIDE kf_dir itself to test self-skip!
            hc_exf_path = os.path.join(kf_dir, "inside_folder.hc")
            vol_bytes = bytearray(
                build_tcvc_volume(
                    exf_img,
                    b"ExFatVcPass!",
                    [kfa_b, kfb_b],
                    is_vera=True,
                    kdf_alg="blake2s",
                    salt_seed=b"exf",
                )
            )
            # ALSO corrupt primary header [0..511] to exercise automatic backup header fallback!
            vol_bytes[0:512] = os.urandom(512)
            with open(hc_exf_path, "wb") as f:
                f.write(vol_bytes)

            out_exf = os.path.join(tmp, "out_exfat")
            rc, out = run_myrkr(
                exe,
                ["decrypt", hc_exf_path, "-o", out_exf, "-p", "ExFatVcPass!", "--keyfile", kf_dir],
            )
            assert rc == EXIT_OK, f"exFAT decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out_exf), exf_expected, "VC-exFAT")

            # Wrong password check
            rc_wrong, _ = run_myrkr(
                exe, ["verify", hc_exf_path, "-p", "WrongPass!", "--keyfile", kf_dir]
            )
            assert rc_wrong == EXIT_AUTH, f"expected EXIT_AUTH on wrong password, got {rc_wrong}"
            print("  [PASS] VeraCrypt BLAKE2s + exFAT (NoFatChain, fragmented, VDL zero-tail, keyfile-dir self/hidden skip, backup hdr)")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] VeraCrypt + exFAT: {exc}")

        # ---------------------------------------------------------------------
        # Case 5: Misnamed Myrkr container (.mrk renamed to .tc) excluded by magic
        # ---------------------------------------------------------------------
        try:
            src_plain = os.path.join(tmp, "hello.txt")
            with open(src_plain, "wb") as f:
                f.write(b"Native Myrkr container disguised as .tc!\n")
            disguised_mrk = os.path.join(tmp, "actually_myrkr.tc")
            rc, out = run_myrkr(
                exe,
                ["encrypt", src_plain, "-o", disguised_mrk, "-p", "MyrkrStrong#Pass99", "-m", "16", "-t", "1"],
            )
            assert rc == EXIT_OK, f"encrypt .mrk failed: rc={rc} out={out}"

            dec_plain = os.path.join(tmp, "hello_out.txt")
            rc, out = run_myrkr(
                exe, ["decrypt", disguised_mrk, "-o", dec_plain, "-p", "MyrkrStrong#Pass99"]
            )
            assert rc == EXIT_OK, f"decrypt disguised .mrk failed: rc={rc} out={out}"
            with open(dec_plain, "rb") as f:
                assert f.read() == b"Native Myrkr container disguised as .tc!\n"
            print("  [PASS] Magic exclusion (.mrk renamed to .tc routes cleanly to native Myrkr engine)")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] Magic exclusion: {exc}")

        # ---------------------------------------------------------------------
        # Case 6: VeraCrypt .hc + NTFS ($Boot, USA, $I30 INDX B-tree, resident,
        #         fragmented negative-delta run, sparse+uninit, LZNT1, $ATTRIBUTE_LIST,
        #         DOS 8.3 deduplication, $Extend & reparse skip)
        # ---------------------------------------------------------------------
        try:
            ntfs_img, ntfs_expected = build_ntfs_image()
            hc_ntfs = os.path.join(tmp, "vol_ntfs.hc")
            with open(hc_ntfs, "wb") as f:
                f.write(
                    build_tcvc_volume(ntfs_img, b"NtfsVera#2026!", [], is_vera=True, kdf_alg="sha512", salt_seed=b"ntfs")
                )
            out_ntfs = os.path.join(tmp, "out_ntfs")
            rc, out = run_myrkr(exe, ["decrypt", hc_ntfs, "-o", out_ntfs, "-p", "NtfsVera#2026!"])
            assert rc == EXIT_OK, f"NTFS decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out_ntfs), ntfs_expected, "VC-NTFS")
            print("  [PASS] VeraCrypt + NTFS (resident, fragmented, sparse/uninit, LZNT1, $ATTRIBUTE_LIST, $I30 INDX, DOS dedup)")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] VeraCrypt + NTFS: {exc}")

        # ---------------------------------------------------------------------
        # Case 7: TC 7.1a + ext2 (12 direct + 1/2-indirect + sparse + Latin-1 +
        #         symlink skip) AND VeraCrypt + ext4 (64-bit + 2-level extent tree + uninit)
        # ---------------------------------------------------------------------
        try:
            ext2_img, ext2_expected = build_ext2_image()
            tc_ext2 = os.path.join(tmp, "vol_ext2.tc")
            with open(tc_ext2, "wb") as f:
                f.write(build_tcvc_volume(ext2_img, b"Ext2TcPass!", [], is_vera=False, kdf_alg="sha512", salt_seed=b"ext2"))
            out_ext2 = os.path.join(tmp, "out_ext2")
            rc, out = run_myrkr(exe, ["decrypt", tc_ext2, "-o", out_ext2, "-p", "Ext2TcPass!"])
            assert rc == EXIT_OK, f"ext2 decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out_ext2), ext2_expected, "TC-ext2")

            ext4_img, ext4_expected = build_ext4_image()
            hc_ext4 = os.path.join(tmp, "vol_ext4.hc")
            with open(hc_ext4, "wb") as f:
                f.write(build_tcvc_volume(ext4_img, b"Ext4VcPass!", [], is_vera=True, kdf_alg="sha256", salt_seed=b"ext4"))
            out_ext4 = os.path.join(tmp, "out_ext4")
            rc, out = run_myrkr(exe, ["decrypt", hc_ext4, "-o", out_ext4, "-p", "Ext4VcPass!"])
            assert rc == EXIT_OK, f"ext4 decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out_ext4), ext4_expected, "VC-ext4")
            print("  [PASS] TC ext2 (direct + 1/2-indirect + sparse + Latin-1) & VeraCrypt ext4 (64-bit + depth-1 extent tree + uninit)")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] ext2 / ext4: {exc}")

        # ---------------------------------------------------------------------
        # Case 8: macOS HFS+ ('H+' v4 in 'BD' HFS wrapper, 2-level Catalog B-Tree,
        #         NFD->NFC Unicode, Extents Overflow B-Tree) & HFSX ('HX' v5)
        # ---------------------------------------------------------------------
        try:
            hfs_img, hfs_expected = build_hfsplus_wrapped_image()
            hc_hfs = os.path.join(tmp, "vol_hfsplus.hc")
            with open(hc_hfs, "wb") as f:
                f.write(build_tcvc_volume(hfs_img, b"MacHfsPlus#1", [], is_vera=True, kdf_alg="sha512", salt_seed=b"hfs"))
            out_hfs = os.path.join(tmp, "out_hfs")
            rc, out = run_myrkr(exe, ["decrypt", hc_hfs, "-o", out_hfs, "-p", "MacHfsPlus#1"])
            assert rc == EXIT_OK, f"HFS+ decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out_hfs), hfs_expected, "VC-HFS+")

            hfsx_img, hfsx_expected = build_hfsx_image()
            tc_hfsx = os.path.join(tmp, "vol_hfsx.tc")
            with open(tc_hfsx, "wb") as f:
                f.write(build_tcvc_volume(hfsx_img, b"MacHfsxTc!", [], is_vera=False, kdf_alg="ripemd160", salt_seed=b"hfsx"))
            out_hfsx = os.path.join(tmp, "out_hfsx")
            rc, out = run_myrkr(exe, ["decrypt", tc_hfsx, "-o", out_hfsx, "-p", "MacHfsxTc!"])
            assert rc == EXIT_OK, f"HFSX decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out_hfsx), hfsx_expected, "TC-HFSX")
            print("  [PASS] macOS HFS+ ('BD'-wrapped 'H+', NFD->NFC, 11-extent Overflow B-Tree) & HFSX ('HX' v5)")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] macOS HFS+ / HFSX: {exc}")

        # ---------------------------------------------------------------------
        # Case 9: Aged NTFS edge cases ($MFT fragmented via $ATTRIBUTE_LIST,
        #         TotalSectors = tot_sec - 1 + last-cluster LCN, ext-MFT dir
        #         Win32 $FILE_NAME + $INDEX_ROOT, sparse file > container size)
        # ---------------------------------------------------------------------
        try:
            bps = 512
            spc = 8
            cbytes = bps * spc  # 4096
            tot_clus = 96
            tot_sec = tot_clus * spc
            aged_ntfs = bytearray(tot_sec * bps)

            aged_ntfs[0:3] = b"\xEB\x52\x90"
            aged_ntfs[3:11] = b"NTFS    "
            struct.pack_into("<HB", aged_ntfs, 11, bps, spc)
            aged_ntfs[21] = 0xF8
            # Windows format.exe writes TotalSectors = PartitionSectors - 1!
            struct.pack_into("<QQQ", aged_ntfs, 40, tot_sec - 1, 4, 2)
            struct.pack_into("<b", aged_ntfs, 64, -10)  # 1024B MFT record
            struct.pack_into("<b", aged_ntfs, 68, 1)    # 4096B INDX block
            struct.pack_into("<H", aged_ntfs, 510, 0xAA55)

            def put_aged_mft(rec_num: int, raw1k: bytes):
                # Records 0..31 in fragment 0 (LCN 4..11); records 32..63 in fragment 1 (LCN 70..77)
                if rec_num < 32:
                    off = 4 * cbytes + rec_num * 1024
                else:
                    off = 70 * cbytes + (rec_num - 32) * 1024
                aged_ntfs[off : off + 1024] = raw1k

            aged_expected: dict[str, bytes] = {}

            # Record 43 (in $MFT 2nd fragment!): file inside Aged_Directory_Ext_MFT
            f43_body = b"Stored in MFT record 43 (second $MFT fragment via $ATTRIBUTE_LIST)!\n" * 30
            aged_ntfs[80 * cbytes : 80 * cbytes + len(f43_body)] = f43_body
            fn43 = _ntfs_fn_val(40, 1, "deep_in_mft_frag2.txt", namespace=1)
            put_aged_mft(
                43,
                _ntfs_mft_record(
                    1,
                    False,
                    [
                        _ntfs_attr_res(0x30, fn43),
                        _ntfs_attr_nonres(0x80, [(1, 80)], cbytes, len(f43_body), len(f43_body)),
                    ],
                ),
            )
            aged_expected["Aged_Directory_Ext_MFT/deep_in_mft_frag2.txt"] = f43_body

            # Record 40 (base dir) + Record 41 (ext dir holding Win32 $FILE_NAME + $INDEX_ROOT:$I30)
            fn40_dos = _ntfs_fn_val(5, 1, "AGEDDI~1", namespace=2)
            fn40_win = _ntfs_fn_val(5, 1, "Aged_Directory_Ext_MFT", namespace=1)
            ir40_ents = _ntfs_idx_entry(43, 1, fn43) + _ntfs_idx_end()
            ir40_val = (
                struct.pack("<IIII", 0x30, 1, cbytes, 1)
                + struct.pack("<IIII", 16, 16 + len(ir40_ents), 16 + len(ir40_ents), 0)
                + ir40_ents
            )
            al40 = (
                struct.pack("<IHBBQQ", 0x30, 32, 0, 26, 0, (1 << 48) | 40).ljust(32, b"\x00")
                + struct.pack("<IHBBQQ", 0x30, 32, 0, 26, 0, (1 << 48) | 41).ljust(32, b"\x00")
                + struct.pack("<IHBBQQ", 0x90, 32, 4, 26, 0, (1 << 48) | 41).ljust(32, b"\x00")
            )
            put_aged_mft(40, _ntfs_mft_record(1, True, [_ntfs_attr_res(0x20, al40), _ntfs_attr_res(0x30, fn40_dos)]))
            put_aged_mft(
                41,
                _ntfs_mft_record(1, True, [_ntfs_attr_res(0x30, fn40_win), _ntfs_attr_res(0x90, ir40_val, name="$I30")]),
            )

            # Record 42: Sparse file with logical data_size > entire container + physical tail in LAST cluster (LCN 95)!
            sparse_clusters = 110  # 450,560 bytes > 393,216-byte volume!
            tail_last = b"LAST_CLUSTER_95_OK!" * 60  # 1,140 bytes in LCN 95 (tot_clus - 1)
            aged_ntfs[95 * cbytes : 95 * cbytes + len(tail_last)] = tail_last
            tot_sp42 = sparse_clusters * cbytes + len(tail_last)
            fn42 = _ntfs_fn_val(5, 1, "oversized_sparse_last_clus.bin", namespace=1)
            put_aged_mft(
                42,
                _ntfs_mft_record(
                    1,
                    False,
                    [
                        _ntfs_attr_res(0x30, fn42),
                        _ntfs_attr_nonres(0x80, [(sparse_clusters, None), (1, 95)], (sparse_clusters + 1) * cbytes, tot_sp42, tot_sp42),
                    ],
                ),
            )
            aged_expected["oversized_sparse_last_clus.bin"] = (b"\x00" * (sparse_clusters * cbytes)) + tail_last

            # Root directory Record 5 listing DOS + Win32 entries for Record 40 and Record 42
            r5_ents = (
                _ntfs_idx_entry(40, 1, fn40_dos)
                + _ntfs_idx_entry(40, 1, fn40_win)
                + _ntfs_idx_entry(42, 1, fn42)
                + _ntfs_idx_end()
            )
            ir5_aged = (
                struct.pack("<IIII", 0x30, 1, cbytes, 1)
                + struct.pack("<IIII", 16, 16 + len(r5_ents), 16 + len(r5_ents), 0)
                + r5_ents
            )
            put_aged_mft(5, _ntfs_mft_record(1, True, [_ntfs_attr_res(0x90, ir5_aged, name="$I30")]))

            # Fragmented $MFT: Record 0 (VCN 0..7 @ LCN 4) + $ATTRIBUTE_LIST -> Record 15 (VCN 8..15 @ LCN 70)
            al_mft0 = (
                struct.pack("<IHBBQQ", 0x80, 32, 0, 26, 0, (1 << 48) | 0).ljust(32, b"\x00")
                + struct.pack("<IHBBQQ", 0x80, 32, 0, 26, 8, (1 << 48) | 15).ljust(32, b"\x00")
            )
            put_aged_mft(
                0,
                _ntfs_mft_record(
                    1,
                    False,
                    [
                        _ntfs_attr_res(0x20, al_mft0),
                        _ntfs_attr_nonres(0x80, [(8, 4)], 16 * cbytes, 16 * cbytes, 16 * cbytes),
                    ],
                ),
            )
            put_aged_mft(
                15,
                _ntfs_mft_record(
                    1,
                    False,
                    [_ntfs_attr_nonres(0x80, [(8, 70)], 0, 0, 0, low_vcn=8)],
                ),
            )

            hc_aged = os.path.join(tmp, "aged_ntfs.hc")
            with open(hc_aged, "wb") as f:
                f.write(build_tcvc_volume(bytes(aged_ntfs), b"AgedNtfs#Pass1", [], is_vera=True, kdf_alg="sha512", salt_seed=b"aged"))
            out_aged = os.path.join(tmp, "out_aged_ntfs")
            rc, out = run_myrkr(exe, ["decrypt", hc_aged, "-o", out_aged, "-p", "AgedNtfs#Pass1"])
            assert rc == EXIT_OK, f"Aged NTFS decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out_aged), aged_expected, "VC-Aged-NTFS")
            print("  [PASS] Aged NTFS (fragmented $MFT+$ATTRIBUTE_LIST, TotalSectors-1 last cluster, ext-MFT dir, sparse > vol)")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] Aged NTFS edge cases: {exc}")

        # ---------------------------------------------------------------------
        # Case 10: Real-world FAT16 boundary + FAT clamping + empty FstClus=0 dir
        #          + Legacy V1 TC header + unaligned host file + corrupt-hdr backup recovery
        # ---------------------------------------------------------------------
        try:
            # Build FAT16 image, adjust cluster count to 4060 (<4085 with "FAT16   " like VC Fat.c),
            # then extend TotSec32 past FATSz16 capacity to exercise fastfat.sys cluster clamping,
            # and inject an empty subdirectory (FstClus=0) + blank SFN slot in root directory!
            fat_edge = bytearray(build_fat_image(16, {"keep_me.txt": b"FAT16 boundary & clamping works!\n" * 20}, spc=1))
            # Shrink FATSz16 header claim? Easier: append 300 sectors to image and bump TotSec so DataSec > FATSz16*256!
            orig_tot16 = struct.unpack_from("<H", fat_edge, 19)[0]
            orig_tot = orig_tot16 if orig_tot16 else struct.unpack_from("<I", fat_edge, 32)[0]
            fat_edge.extend(b"\x00" * (300 * 512))
            struct.pack_into("<H", fat_edge, 19, 0)
            struct.pack_into("<I", fat_edge, 32, orig_tot + 300)

            # Inject blank SFN slot + empty subdir (attr=0x10, FstClus=0) into root directory
            root_off = (1 + 2 * 17) * 512
            pos = root_off
            while fat_edge[pos] != 0:
                pos += 32
            blank_slot = bytearray(32)
            blank_slot[0:11] = b"           "
            blank_slot[11] = 0x20
            empty_dir_slot = _make_fat_dirent("EMPTYDIR", 0x10, 0, 0, 99, force_sfn=(b"EMPTYDIR   ", 0))
            fat_edge[pos : pos + 32] = blank_slot
            fat_edge[pos + 32 : pos + 64] = empty_dir_slot

            # Seal in Legacy V1 TrueCrypt v3 header (RequiredProgramVersion=0x0500, EncryptedAreaStart=0,
            # VolumeDataSize != 0) AND append +137 trailing unaligned bytes to outer file!
            tc_v1_bytes = build_tcvc_volume(
                bytes(fat_edge),
                b"LegacyTcV1Pass!",
                [],
                is_vera=False,
                kdf_alg="ripemd160",
                salt_seed=b"v1fat",
                hdr_ver=3,
                req_ver=0x0500,
                legacy_v1=True,
            ) + (b"\xAB" * 137)
            tc_v1_path = os.path.join(tmp, "legacy_unaligned.tc")
            with open(tc_v1_path, "wb") as f:
                f.write(tc_v1_bytes)

            out_v1 = os.path.join(tmp, "out_v1_fat")
            rc, out = run_myrkr(exe, ["decrypt", tc_v1_path, "-o", out_v1, "-p", "LegacyTcV1Pass!"])
            assert rc == EXIT_OK, f"Legacy V1 + FAT16 edge decrypt failed: rc={rc} out={out}"
            assert os.path.isdir(os.path.join(out_v1, "EMPTYDIR")), "EMPTYDIR with FstClus=0 not created"
            assert collect_extracted_files(out_v1) == {"keep_me.txt": b"FAT16 boundary & clamping works!\n" * 20}

            # Also verify backup header fallback when primary header authenticates with CORRUPT geometry
            # (and test v5 header with SectorSize == 0 defaulting to 512)!
            good_vol = bytearray(
                build_tcvc_volume(
                    bytes(fat_edge),
                    b"BackupCorruptPri!",
                    [],
                    is_vera=True,
                    kdf_alg="sha256",
                    salt_seed=b"bakcorr",
                    hdr_ver=5,
                    sec_size=0,
                )
            )
            # Re-encrypt primary header at [0..511] with same password/salt but oversized VolumeDataSize -> EXIT_CORRUPT
            salt_p = bytes(good_vol[0:64])
            dk_p = pbkdf2_derive("sha256", b"BackupCorruptPri!", salt_p, 500000, 64)
            bad_plain = bytearray(448)
            bad_plain[0:4] = b"VERA"
            struct.pack_into(">HH", bad_plain, 4, 5, 0x010B)
            struct.pack_into(">QQQ", bad_plain, 36, 0x0000400000000000, 131072, 0x0000400000000000)
            struct.pack_into(">I", bad_plain, 8, zlib.crc32(bad_plain[192:448]) & 0xFFFFFFFF)
            struct.pack_into(">I", bad_plain, 188, zlib.crc32(bad_plain[0:188]) & 0xFFFFFFFF)
            good_vol[64:512] = aes256_xts_encrypt(dk_p[:32], dk_p[32:64], bytes(bad_plain), 0)

            hc_bak_corr = os.path.join(tmp, "corrupt_pri_valid_bak.hc")
            with open(hc_bak_corr, "wb") as f:
                f.write(good_vol)
            out_bak_corr = os.path.join(tmp, "out_bak_corr")
            rc, out = run_myrkr(exe, ["decrypt", hc_bak_corr, "-o", out_bak_corr, "-p", "BackupCorruptPri!"])
            assert rc == EXIT_OK, f"Backup fallback on corrupt primary failed: rc={rc} out={out}"
            assert collect_extracted_files(out_bak_corr) == {"keep_me.txt": b"FAT16 boundary & clamping works!\n" * 20}
            print("  [PASS] FAT16 clamping + empty FstClus=0 dir + Legacy V1 header + unaligned .tc + corrupt-primary backup recovery")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] FAT16 / Legacy V1 / Backup recovery edge cases: {exc}")

        # ---------------------------------------------------------------------
        # Case 11: 4096-byte-sector exFAT (0xAA55 at +4094) & ext4 partial dir
        #          block + sparse file > volume size
        # ---------------------------------------------------------------------
        try:
            bps_s = 12  # 4096B sector!
            spc_s = 1   # 8192B cluster
            bps4 = 1 << bps_s
            spc4 = 1 << spc_s
            cb4 = bps4 * spc4
            fo_sec, fl_sec, ho_sec, ncl4 = 24, 1, 32, 32
            exf4 = bytearray((ho_sec + ncl4 * spc4) * bps4)
            exf4[0:3] = b"\xEB\x76\x90"
            exf4[3:11] = b"EXFAT   "
            struct.pack_into("<QIIII", exf4, 72, ho_sec + ncl4 * spc4, fo_sec, fl_sec, ho_sec, ncl4)
            struct.pack_into("<I", exf4, 96, 2)
            exf4[108] = bps_s
            exf4[109] = spc_s
            exf4[110] = 1
            # +510 is 0x0000; 0xAA55 is at +4094 per exFAT spec §3.1.20!
            assert exf4[510:512] == b"\x00\x00"
            struct.pack_into("<H", exf4, bps4 - 2, 0xAA55)
            struct.pack_into("<III", exf4, fo_sec * bps4, 0xFFFFFFF8, 0xFFFFFFFF, 0xFFFFFFFF)

            p4k = b"4096-byte native sector exFAT payload!\n" * 250
            exf4[(ho_sec + 2 * spc4) * bps4 : (ho_sec + 2 * spc4) * bps4 + len(p4k)] = p4k
            rdir4 = _make_exfat_entry_set("sector4k_ok.bin", False, 4, len(p4k), len(p4k), True)
            exf4[ho_sec * bps4 : ho_sec * bps4 + len(rdir4)] = rdir4

            hc_4k = os.path.join(tmp, "exfat_4k.hc")
            with open(hc_4k, "wb") as f:
                f.write(
                    build_tcvc_volume(
                        bytes(exf4), b"Exfat4kPass!", [], is_vera=True, kdf_alg="blake2s", salt_seed=b"4k", sec_size=4096
                    )
                )
            out_4k = os.path.join(tmp, "out_exf4k")
            rc, out = run_myrkr(exe, ["decrypt", hc_4k, "-o", out_4k, "-p", "Exfat4kPass!"])
            assert rc == EXIT_OK, f"4K-sector exFAT decrypt failed: rc={rc} out={out}"
            assert collect_extracted_files(out_4k) == {"sector4k_ok.bin": p4k}

            # ext4 partial directory i_size (512B < 4096B block) + sparse file i_size > volume size
            ext4_mod, ext4_exp = build_ext4_image()
            ext4_m = bytearray(ext4_mod)
            # Shrink subdir "log" (inode 11, at 2*4096 + 10*256) i_size from 4096 to 512,
            # adjusting last dirent rec_len to end at 512!
            log_blk_off = 12 * 4096
            d0_len = struct.unpack_from("<H", ext4_m, log_blk_off + 4)[0]
            d1_len = struct.unpack_from("<H", ext4_m, log_blk_off + d0_len + 4)[0]
            struct.pack_into("<H", ext4_m, log_blk_off + d0_len + d1_len + 4, 512 - d0_len - d1_len)
            ino11_off = 2 * 4096 + (11 - 1) * 256
            struct.pack_into("<I", ext4_m, ino11_off + 4, 512)
            # Inflate inode 12 logical i_size to 512 KiB (> 256 KiB volume!) -> trailing sparse zeros
            ino12_off = 2 * 4096 + (12 - 1) * 256
            old_f12 = ext4_exp["var/log/ext4_tree_uninit.bin"]
            new_sz = 512 * 1024
            struct.pack_into("<I", ext4_m, ino12_off + 4, new_sz)
            ext4_exp["var/log/ext4_tree_uninit.bin"] = old_f12 + (b"\x00" * (new_sz - len(old_f12)))

            hc_ext4_edge = os.path.join(tmp, "ext4_edge.hc")
            with open(hc_ext4_edge, "wb") as f:
                f.write(build_tcvc_volume(bytes(ext4_m), b"Ext4Edge!", [], is_vera=True, kdf_alg="sha256", salt_seed=b"e4e"))
            out_e4e = os.path.join(tmp, "out_e4e")
            rc, out = run_myrkr(exe, ["decrypt", hc_ext4_edge, "-o", out_e4e, "-p", "Ext4Edge!"])
            assert rc == EXIT_OK, f"ext4 partial-dir/sparse decrypt failed: rc={rc} out={out}"
            assert_tree_matches(collect_extracted_files(out_e4e), ext4_exp, "VC-ext4-edge")
            print("  [PASS] 4096B-sector exFAT (0xAA55 at +4094) & ext4 partial-block dir + sparse file > vol")
        except Exception as exc:
            failures += 1
            print(f"  [FAIL] 4K exFAT / ext4 edge cases: {exc}")

    if failures:
        print(f"FAILED: {failures} test case(s)")
        return 1
    print("ALL TC/VC FILESYSTEM & CRYPTO INTEGRATION TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
