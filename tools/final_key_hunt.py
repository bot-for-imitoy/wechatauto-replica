#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""final_key_hunt.py — 按 WCDB/SQLCipher4 已逆向确认的公式做最终密钥狩猎。

社区已确认的微信 4.x WCDB 加密格式（wxkey/wechat-decrypt 等项目实测）：
  页 1 布局（4096B）: [0:16]=salt [16:4016]=密文 [4016:4032]=IV [4032:4096]=HMAC-SHA512
  HMAC 输入: content || IV || LE32(page_num=1)
  enc_key = PBKDF2-HMAC-SHA512(password, salt, 256000, 32)
  mac_key = PBKDF2-HMAC-SHA512(enc_key, salt^0x3A, **iter=2**, 32)   ← WCDB 变种
  WCDB 在内存中以 x'<96hex>' 缓存 enc_key(64hex)+salt(32hex)，或 x'<64hex>' 仅 enc_key
  微信 4.0.x: 内存即 enc_key；4.1+: 内存是 password（需 256000 轮派生）

策略：
  1. 扫描进程内存所有 x'<hex>' 串与裸 64/96 hex 串
  2. 96hex 且后 32hex==库 salt → 直接配对；否则全部候选 × 全部库
  3. 先用正确公式 HMAC 验证（便宜）；x''/keys-file 候选再走解密验证与
     password→enc_key 派生路径
用法（root）:
  sudo ./venv/bin/python tools/final_key_hunt.py --pid 60243 \
      --db-dir /home/imitoy/.local/state/wechat/xwechat_files
  可选 --keys-file tools/keys_round5.txt --deep（对全部裸 hex 候选跑解密验证）
"""

import argparse
import hashlib
import hmac as hmac_mod
import os
import re
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PAGE_SZ = 4096
RESERVE = 80
IV_SZ = 16
HMAC_SZ = 64
DATA_END = PAGE_SZ - RESERVE      # 4016
IV_OFF = PAGE_SZ - RESERVE        # 4016
MAC_OFF = PAGE_SZ - RESERVE + IV_SZ  # 4032
KDF_ITER = 256000
MAC_KDF_ITER = 2


def xor3a(salt: bytes) -> bytes:
    return bytes(b ^ 0x3A for b in salt)


def le32(n: int) -> bytes:
    return struct.pack("<I", n)


def mac_key_from_enc(enc: bytes, salt: bytes, it: int = MAC_KDF_ITER) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", enc, xor3a(salt), it, dklen=32)


def page1_hmac(mac_key: bytes, content: bytes, iv: bytes,
               page_no: int = 1) -> bytes:
    return hmac_mod.new(mac_key, content + iv + le32(page_no),
                        hashlib.sha512).digest()


def collect_db_files(db_dir: Path):
    xw = db_dir / "xwechat_files"
    root = xw if xw.is_dir() else db_dir
    return [(str(p.relative_to(root)), p) for p in sorted(root.rglob("*.db"))]


def find_wechat_pids():
    pids = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip().lower()
            if "wechat" in name or "weixin" in name:
                pids.append(int(pid))
        except OSError:
            continue
    return sorted(pids)


def scan_memory_hex_candidates(pid: int):
    """扫描进程内存，返回 hex 候选集合（x'' 串单独标记）。"""
    xprime = set()   # x'<hex>' 包裹的高置信候选
    bare = set()     # 裸 64/96 hex
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    rx_xp = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
    rx_bare = re.compile(rb"(?<![0-9a-zA-Z])([0-9a-fA-F]{96})(?![0-9a-zA-Z])")
    rx_bare64 = re.compile(rb"(?<![0-9a-zA-Z])([0-9a-fA-F]{64})(?![0-9a-zA-Z])")
    regions = []
    with open(maps_path) as f:
        for line in f:
            perms = line.split()[1]
            if perms[0] != "r":
                continue
            addr, _, off = line.split()[0:3]
            start, end = (int(x, 16) for x in addr.split("-"))
            if end - start > 512 * 1024 * 1024:
                continue
            if end - start < 64:
                continue
            regions.append((start, end))
    total = 0
    with open(mem_path, "rb", buffering=0) as mem:
        for start, end in regions:
            try:
                mem.seek(start)
                data = mem.read(end - start)
            except OSError:
                continue
            total += len(data)
            for m in rx_xp.finditer(data):
                xprime.add(m.group(1).decode("ascii", "ignore").lower())
            for m in rx_bare.finditer(data):
                bare.add(m.group(1).decode("ascii", "ignore").lower())
            for m in rx_bare64.finditer(data):
                bare.add(m.group(1).decode("ascii", "ignore").lower())
    print(f"  内存扫描完成：读入 {total/2**20:.0f} MB，"
          f"x'' 候选 {len(xprime)}，裸 hex 候选 {len(bare)}")
    return xprime, bare


def verify_enc_key_hmac(enc: bytes, page1: bytes, salt: bytes,
                        mac_iters=(MAC_KDF_ITER,)):
    """用正确公式验证 enc_key；返回命中的 mac 迭代数或 None。"""
    content = page1[16:DATA_END]
    iv = page1[IV_OFF:IV_OFF + IV_SZ]
    stored = page1[MAC_OFF:MAC_OFF + HMAC_SZ]
    for it in mac_iters:
        mk = mac_key_from_enc(enc, salt, it)
        if hmac_mod.compare_digest(page1_hmac(mk, content, iv), stored):
            return it
    return None


def try_decrypt(enc: bytes, page1: bytes):
    """解密验证（SQLCipher 标准 reserve=80 布局）。返回原因或 None。"""
    try:
        from Crypto.Cipher import AES
        dec = lambda k, iv, ct: AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import (
                Cipher, algorithms, modes)
            dec = lambda k, iv, ct: (
                lambda d: d.update(ct) + d.finalize())(
                Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor())
        except ImportError:
            return "no-aes-lib"
    salt = page1[:16]
    ct = page1[16:DATA_END]
    iv = page1[IV_OFF:IV_OFF + IV_SZ]
    try:
        pt = dec(enc, iv, ct)
    except Exception:
        return None
    if pt[0:2] == b"\x10\x00" and pt[2] in (1, 2) and pt[3] in (1, 2) \
            and pt[5:8] == bytes([64, 32, 32]):
        return f"sqlite-header(直接解密, salt={salt.hex()})"
    return None


def load_keys_file(path):
    keys = []
    if path and Path(path).exists():
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        keys = [m.group(1).lower() for m in
                re.finditer(r"\b([0-9a-fA-F]{64})\b", text)]
    return keys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--db-dir", default="/home/imitoy/.local/state/wechat/xwechat_files")
    ap.add_argument("--keys-file", default="")
    ap.add_argument("--deep", action="store_true",
                    help="对全部裸 hex 候选也做解密验证（慢）")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    pids = [args.pid] if args.pid else find_wechat_pids()
    print(f"微信进程: {pids}")
    if not pids:
        print("未找到进程"); sys.exit(2)
    pid = pids[0]

    dbs = collect_db_files(Path(args.db_dir).expanduser())
    print(f"库文件 {len(dbs)} 个")
    page1s = {}
    for label, p in dbs:
        try:
            with open(p, "rb") as f:
                pg = f.read(PAGE_SZ)
            if len(pg) == PAGE_SZ:
                page1s[label] = pg
        except OSError:
            pass
    print(f"可读页1 {len(page1s)} 个")

    print("步骤 1: 扫描内存 hex 候选")
    xprime, bare = scan_memory_hex_candidates(pid)
    kf = load_keys_file(args.keys_file)
    if kf:
        xprime.update(kf)
        print(f"  keys-file 追加 {len(kf)} 个")

    # 96hex x'' 的后 32 hex 是 salt，可先按盐配对缩小范围
    salt_map = {pg[:16].hex(): lb for lb, pg in page1s.items()}
    print("步骤 2: HMAC 验证（正确公式 mac_key=PBKDF2(enc,salt^0x3A,2,32)）")
    hits = []
    checked = 0
    cands = sorted(xprime | bare)
    for cand in cands:
        if len(cand) == 96:
            salt_hex = cand[32 * 2:]
            if salt_hex in salt_map:
                targets = [(salt_map[salt_hex], page1s[salt_map[salt_hex]])]
            else:
                targets = list(page1s.items())
        else:
            targets = list(page1s.items())
        enc = bytes.fromhex(cand[:64])
        for label, pg in targets:
            checked += 1
            it = verify_enc_key_hmac(enc, pg, pg[:16])
            if it:
                hits.append((label, cand, f"HMAC命中(mac_kdf_iter={it})"))
                print(f"!! HMAC 命中 [{label}] enc_key={cand[:64]} salt={pg[:16].hex()}")
    print(f"  HMAC 验证 {checked} 组合")

    print("步骤 3: 解密验证（x''/keys-file 候选 + --deep 时全部候选）")
    pool = sorted(xprime | bare) if args.deep else sorted(xprime)
    for cand in pool:
        enc = bytes.fromhex(cand[:64])
        for label, pg in page1s.items():
            reason = try_decrypt(enc, pg)
            if reason:
                hits.append((label, cand, reason))
                print(f"!! 解密命中 [{label}] enc_key={cand[:64]} — {reason}")

    print("步骤 4: password 派生路径（x''/keys-file 候选视作 passphrase）")
    for cand in sorted(xprime):
        pw = bytes.fromhex(cand[:64])
        for label, pg in page1s.items():
            salt = pg[:16]
            enc = hashlib.pbkdf2_hmac("sha512", pw, salt, KDF_ITER, dklen=32)
            it = verify_enc_key_hmac(enc, pg, salt)
            reason = try_decrypt(enc, pg) if not it else "pbkdf2560000"
            if it or reason:
                hits.append((label, cand, f"password→PBKDF2(256000)→enc_key "
                                          f"{'HMAC命中' if it else reason}"))
                print(f"!! password 路径命中 [{label}] password={cand[:64]} "
                      f"enc_key={enc.hex()}")

    print("=" * 62)
    if hits:
        print(f"共 {len(hits)} 处命中！")
        seen = set()
        with open("wechat_keys_found.txt", "w") as f:
            for label, cand, how in hits:
                key = (label, cand[:64])
                if key in seen:
                    continue
                seen.add(key)
                f.write(f"{label}\t{cand[:64]}\t{how}\n")
        print("已写入 wechat_keys_found.txt（标签\\ enc_key\\ 方式）")
    else:
        print("仍无命中。若如此，下一步抓 WCDB 库版本与 CipherConfig 结构再对齐。")


def selftest():
    """合成一个符合已确认公式的加密库，验证检测逻辑。"""
    try:
        from Crypto.Cipher import AES
        encf = lambda k, iv, pt: AES.new(k, AES.MODE_CBC, iv).encrypt(pt)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        encf = lambda k, iv, pt: (
            lambda e: e.update(pt) + e.finalize())(
            Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor())
    password = bytes(range(32))
    salt = bytes.fromhex("a1b2c3d4" * 4)
    enc = hashlib.pbkdf2_hmac("sha512", password, salt, KDF_ITER, dklen=32)
    # 完整文件头 4016 字节：magic + 页大小 + 版本/特征字节 + 填充
    fh = bytearray(b"SQLite format 3\x00")
    fh += struct.pack(">H", 4096) + bytes([1, 1, 0, 64, 32, 32])
    fh += bytes(PAGE_SZ - RESERVE - len(fh))
    plaintext_region = bytes(fh[16:])   # 数据区明文 = 文件头偏移 16 起
    iv = bytes(range(16))
    ct = encf(enc, iv, plaintext_region)
    mk = mac_key_from_enc(enc, salt)
    page1 = salt + ct + iv + page1_hmac(mk, ct, iv)
    p = Path("/tmp/fkh_selftest.db")
    p.write_bytes(page1 + os.urandom(PAGE_SZ))

    # 场景 A：内存即 enc_key（x'' 96hex）
    it = verify_enc_key_hmac(enc, page1, salt)
    r1 = try_decrypt(enc, page1)
    # 场景 B：内存是 password
    enc2 = hashlib.pbkdf2_hmac("sha512", password, salt, KDF_ITER, dklen=32)
    it2 = verify_enc_key_hmac(enc2, page1, salt)
    ok = it == 2 and r1 and it2 == 2
    print(f"[selftest] enc_key路径 HMAC={'过' if it else '败'} 解密={'过' if r1 else '败'}; "
          f"password路径 HMAC={'过' if it2 else '败'}")
    p.unlink(missing_ok=True)
    return 0 if ok else 1


if __name__ == "__main__":
    main()
