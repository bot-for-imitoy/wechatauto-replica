#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""final_decrypt_test.py — 终极验证：放弃 HMAC，直接解密页 1 检查 SQLite 头。

背景：五轮扫描已从内存拿到 42 个数学有效的 AES-256 密钥扩展表（布局 B/mbedTLS），
反推出裸密钥，但任何 HMAC 参数组合都无法通过页 1 校验，且 mac_key 不以独立字节
存在于内存中 → 强烈怀疑 Linux 版 WCDB 未启用页级 HMAC（SQLCipher hmac=OFF）。

本脚本不再依赖 HMAC：对每个 (库文件, 候选密钥) 组合直接 AES-256-CBC 解密页 1，
检查明文是否呈现 SQLite 文件头特征：
  - 明文偏移 0 对应文件头偏移 16（页 1 前 16 字节被 salt 覆盖）
  - 页大小字段 == 4096（0x1000 大端）
  - 写/读版本字节 ∈ {1,2}
  - 特征三连 64,32,32（max/min/leaf payload fraction）
只要命中一个库，密钥即被最终确认，HMAC 是否开启已无关紧要。

用法（需 root 读库文件与日志）:
  sudo ./venv/bin/python tools/final_decrypt_test.py \
      --db-dir ~/.local/state/wechat/xwechat_files \
      --log log.log
可选:
  --keys aa11...,bb22...   手工指定候选密钥（hex64，逗号分隔）
  --reserves 80,48,64,...  自定义 reserve 扫描列表
  --selftest               生成合成加密库自测（无需微信）
"""

import argparse
import os
import re
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from Crypto.Cipher import AES  # pycryptodome

    def _cbc_encrypt(key, iv, pt):
        return AES.new(key, AES.MODE_CBC, iv).encrypt(pt)

    def _cbc_decrypt(key, iv, ct):
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)

    _AES_OK = True
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)

        def _cbc_encrypt(key, iv, pt):
            e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            return e.update(pt) + e.finalize()

        def _cbc_decrypt(key, iv, ct):
            d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            return d.update(ct) + d.finalize()

        _AES_OK = True
    except ImportError:
        _AES_OK = False

PAGE_SZ_DEFAULT = 4096
DEFAULT_RESERVES = [16, 32, 48, 64, 80, 96, 112, 128]
SQLITE_HEADER_MAGIC = b"SQLite format 3\x00"


def collect_db_files(db_dir: Path):
    """返回 [(标签, 绝对路径)]，标签为 相对路径。"""
    xw = db_dir / "xwechat_files"
    root = xw if xw.is_dir() else db_dir
    out = []
    for p in sorted(root.rglob("*.db")):
        rel = p.relative_to(root)
        out.append((str(rel), p))
    return out


def load_keys(args) -> list:
    keys = []
    if args.keys:
        for k in re.split(r"[,\s]+", args.keys.strip()):
            k = k.strip().lower()
            if len(k) == 64 and re.fullmatch(r"[0-9a-f]{64}", k):
                keys.append(k)
    if args.log and Path(args.log).exists():
        text = Path(args.log).read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"\bkey=([0-9a-fA-F]{64})\b", text):
            k = m.group(1).lower()
            if k not in keys:
                keys.append(k)
    # 剔除明显的测试密钥（0x00..1f 递增序列等人工常量）
    keys = [k for k in keys if k != "000102030405060708090a0b0c0d0e0f"
                                "101112131415161718191a1b1c1d1e1f"]
    return keys


def plausible_sqlite_pt(pt: bytes):
    """判断解密明文（对应文件头偏移 16 起）是否像 SQLite 头。返回原因或 None。"""
    if len(pt) < 32:
        return None
    page_size = struct.unpack(">H", pt[0:2])[0]
    if page_size != 4096 and page_size != 1:  # 1 表示 65536
        return None
    if page_size == 4096:
        if pt[2] not in (1, 2) or pt[3] not in (1, 2):
            return None
        if pt[5:8] != bytes([64, 32, 32]):  # 文件头偏移 21-23
            return None
        return "sqlite-header(page-size=4096, 64/32/32)"
    return None


def try_page1(db_path: Path, key_bytes: bytes, reserves, page_sz: int):
    try:
        with open(db_path, "rb") as f:
            page = f.read(page_sz)
    except OSError as e:
        return None
    if len(page) < page_sz:
        return None
    salt = page[:16]
    for reserve in reserves:
        data_end = page_sz - reserve
        if data_end <= 16:
            continue
        ct = page[16:data_end]
        if len(ct) % 16:
            continue
        iv_cands = [
            page[data_end:data_end + 16],  # SQLCipher 标准：IV 在 reserve 开头
            page[page_sz - 16:],           # 备选：页尾
            salt,                          # 备选：IV=salt
            b"\x00" * 16,                  # 备选：零 IV
        ]
        seen_iv = set()
        for iv in iv_cands:
            if iv in seen_iv:
                continue
            seen_iv.add(iv)
            try:
                pt = _cbc_decrypt(key_bytes, iv, ct)
            except Exception:
                continue
            reason = plausible_sqlite_pt(pt)
            if reason:
                return (reserve, iv, pt, reason)
    return None


def selftest(reserves):
    """合成一个 SQLCipher 风格加密库，验证检测逻辑。"""
    if not _AES_OK:
        print("[selftest] 无 AES 库可用"); return 1
    import hashlib
    key = bytes(range(32))
    salt = bytes.fromhex("c0ffee" * 5 + "aa")  # 16 bytes
    reserve = 80
    header = bytearray(SQLITE_HEADER_MAGIC)
    header += struct.pack(">H", 4096) + bytes([1, 1, 0, 64, 32, 32])
    header += struct.pack(">I", 7) + struct.pack(">I", 7)  # change counter / size
    header += bytes(4096 - 16 - len(header))
    plaintext = bytes(header)
    iv = bytes(range(16))
    ct = _cbc_encrypt(key, iv, plaintext[16:4096 - reserve])
    page1 = salt + ct + iv + os.urandom(reserve - 16)
    p = Path("/tmp/fdt_selftest.db")
    p.write_bytes(page1 + os.urandom(4096))
    hit = try_page1(p, key, reserves, 4096)
    if hit and "sqlite-header" in hit[3]:
        print(f"[selftest] 通过：reserve={hit[0]} reason={hit[3]}")
        p.unlink()
        return 0
    print(f"[selftest] 失败：hit={hit}")
    p.unlink(missing_ok=True)
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-dir", default=os.path.expanduser(
        "~/.local/state/wechat/xwechat_files"))
    ap.add_argument("--log", default="log.log")
    ap.add_argument("--keys", default="")
    ap.add_argument("--reserves", default=",".join(map(str, DEFAULT_RESERVES)))
    ap.add_argument("--page-size", type=int, default=PAGE_SZ_DEFAULT)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest(DEFAULT_RESERVES))

    if not _AES_OK:
        print("缺少 AES 实现：请安装 pycryptodome 或 cryptography")
        sys.exit(2)

    reserves = sorted({int(x) for x in args.reserves.split(",") if x.strip()})
    keys = load_keys(args)
    print(f"候选密钥 {len(keys)} 个（来自 log/手工指定，已剔除人工测试常量）")
    dbs = collect_db_files(Path(args.db_dir).expanduser())
    print(f"库文件 {len(dbs)} 个；reserve 扫描 {reserves}；页大小 {args.page_size}")
    print("=" * 62)

    hits = 0
    tried = 0
    for label, dbp in dbs:
        for kh in keys:
            tried += 1
            r = try_page1(dbp, bytes.fromhex(kh), reserves, args.page_size)
            if r:
                reserve, iv, pt, reason = r
                hits += 1
                print(f"!! 命中 [{label}]")
                print(f"   key = {kh}")
                print(f"   reserve={reserve} iv={iv.hex()} 依据={reason}")
                print(f"   明文头 48 字节: {pt[:48].hex()}")
    print("=" * 62)
    print(f"共尝试 {tried} 组合，命中 {hits}")
    if hits:
        print("密钥已确认！用该 key 直接以 SQLCipher 参数解密即可；"
              "若需 HMAC 参数可再围绕已确认 key 反推。")
    else:
        print("全部未命中——密钥仍可能正确但加密格式超出网格（考虑 IV 位置/加密范围差异）。")


if __name__ == "__main__":
    main()
