#!/usr/bin/env python3
"""probe_memory.py — Linux 微信内存密钥探测/诊断（需 root）

动机：linux_key.py 初版只把内存候选当「逐库裸密钥」直接验证，但微信 4.x
内存里驻留的是主密钥（逐库密钥 = PBKDF2-SHA512(主密钥, 库 salt, 256000)）。
真机 probe 又发现 Config.Cipher 锚点只存在于二进制只读段（编译期字面量），
锚点窗口策略同样落空。本脚本按命中概率排序逐个假设排查：

  H0: 库文件根本没加密（明文 SQLite）
  H4: salt 锚定 —— 库文件头 16 字节 salt 必然出现在打开该库的进程的
      cipher 上下文里；定位 salt → dump 周边 ±32KB → 候选同时按
      「逐库裸密钥」与「主密钥派生」两条路验证   ★ 推荐首选
  H1: 逐库裸密钥直扫（全内存 stride=8 / 堆匿名区 stride=1）
  H2: 64 位 hex 字符串形式的密钥
  H3: Config.Cipher 锚点窗口 + 主密钥派生（真机已证锚点在 rodata，
      基本无效，保留作对照）
  H5: AES-256 密钥扩展表反推 —— SQLCipher 打开的库必然在堆里留着
      60 词扩展表，从扩展表可数学反推出原始 32 字节页密钥（numpy 加速，
      无 numpy 时自动跳过）

用法:
  sudo python3 tools/probe_memory.py                 # 全流程（自动探测数据目录）
  sudo python3 tools/probe_memory.py --pid 12345     # 指定进程
  sudo python3 tools/probe_memory.py --skip-h1       # 只跑 H0/H4/H2/H3/H5
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as hmac_mod
import os
import re
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wechatauto.db import (CONFIG_CIPHER_NAME, PAGE_SZ,
                           _pbkdf2, _verify_enc_key, auto_detect_db_dir)
from wechatauto.linux_key import (_parse_maps, collect_db_files,
                                  find_wechat_pids)

HEX64_RE = re.compile(rb"[0-9a-fA-F]{64}")
KDF_ITER = 256000


def log(msg: str) -> None:
    print(msg, flush=True)


def head(title: str) -> None:
    log(f"\n{'=' * 62}\n== {title}\n{'=' * 62}")


# ---------------------------------------------------------------------------
# H0: 库文件状态
# ---------------------------------------------------------------------------
def check_db_files(db_dir: str):
    """兼容两种传法：账号目录的父目录，或账号目录本身。"""
    accounts = collect_db_files(db_dir)
    if not accounts and os.path.isdir(os.path.join(db_dir, "db_storage")):
        files = []
        base = os.path.join(db_dir, "db_storage")
        for root, _, names in os.walk(base):
            for name in names:
                if name.endswith(".db") and not name.endswith(("-wal", "-shm")):
                    p = os.path.join(root, name)
                    files.append((os.path.relpath(p, base), p, os.path.getsize(p)))
        accounts = [(os.path.basename(os.path.normpath(db_dir)), files)]

    plaintext, usable = [], []
    for account, db_files in accounts:
        log(f"账号 {account}：{len(db_files)} 个库文件")
        for rel, path, size in db_files[:40]:
            try:
                with open(path, "rb") as f:
                    page1 = f.read(PAGE_SZ)
            except OSError as exc:
                log(f"  [不可读] {rel}: {exc}")
                continue
            if page1[:16] == b"SQLite format 3\x00":
                plaintext.append(f"{account}/{rel}")
                log(f"  [明文SQLite!] {rel} ({size} B) —— 未加密，无需密钥可直接读")
                continue
            if len(page1) < PAGE_SZ:
                log(f"  [过小] {rel}: {size} B")
                continue
            usable.append((f"{account}/{rel}", path, size))
            log(f"  [加密库] {rel} ({size} B)  page1[0:32]={page1[:32].hex()}")
    return plaintext, usable


def pids_holding_dbs() -> list:
    """扫 /proc/*/fd，找真正打开了 db_storage/*.db 的进程。"""
    holders = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            fd_dir = f"/proc/{entry}/fd"
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if ".db" in target and "db_storage" in target:
                    holders.setdefault(int(entry), set()).add(target)
        except (OSError, ValueError):
            continue
    return sorted(holders)


# ---------------------------------------------------------------------------
# 内存一次读入，所有假设复用
# ---------------------------------------------------------------------------
def read_all_chunks(pid: int):
    """读入全部可读私有区，返回 [(start, buf, path)]。约需与可读区等量 RAM。"""
    chunks = []
    regions = _parse_maps(pid)
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
        for start, end, path, _w in regions:
            try:
                f.seek(start)
                buf = f.read(end - start)
            except (OSError, ValueError):
                continue
            if buf:
                chunks.append((start, buf, path))
    return chunks


def maps_summary(pid: int):
    rows = _parse_maps(pid)
    total = anon_rw = file_rw = readonly = 0
    for start, end, path, writable in rows:
        size = end - start
        total += size
        if path:
            if writable:
                file_rw += size
        elif writable:
            anon_rw += size
        else:
            readonly += size
    log(f"  可读私有区共 {total / 1e6:.0f} MB"
        f"（匿名可写 {anon_rw / 1e6:.0f} MB / 文件私有可写 {file_rw / 1e6:.0f} MB"
        f" / 只读 {readonly / 1e6:.0f} MB），区域数 {len(rows)}")


def anchor_stats(chunks):
    anchors, hexstrs, locs = 0, 0, []
    for start, buf, path in chunks:
        n = buf.count(CONFIG_CIPHER_NAME)
        if n:
            anchors += n
            locs.append((hex(start), f"file:{path}" if path else "anon"))
        hexstrs += len(HEX64_RE.findall(buf))
    log(f"  锚点 {CONFIG_CIPHER_NAME.decode()} 出现 {anchors} 次 {locs[:6]}")
    log(f"  64 位 hex 字符串共 {hexstrs} 处")
    return anchors


# ---------------------------------------------------------------------------
# 验证原语
# ---------------------------------------------------------------------------
def verify_direct(cand: bytes, page1s) -> list:
    """候选当逐库裸密钥，返回命中的 [rel]。"""
    if len(cand) == 32 and len(set(cand)) < 15:
        return []
    return [rel for rel, page1 in page1s if _verify_enc_key(cand, page1)]


_test_page1 = None


def _test_master(cand: bytes):
    derived = _pbkdf2(cand, _test_page1[:16], KDF_ITER)
    return cand.hex() if _verify_enc_key(derived, _test_page1) else None


def master_pool(cands, page1_0, workers, label):
    """主密钥假设批量验证（线程池，pbkdf2 释放 GIL）。"""
    global _test_page1
    _test_page1 = page1_0
    found = []
    t0 = time.time()
    with ThreadPoolExecutor(workers) as pool:
        for i, res in enumerate(pool.map(_test_master, cands, chunksize=8)):
            if (i + 1) % 500 == 0:
                log(f"    … {i + 1}/{len(cands)} ({time.time() - t0:.0f}s)")
            if res:
                found.append(res)
                log(f"    !! {label} 主密钥命中: {res}")
    log(f"    [{label}] {len(cands)} 候选，耗时 {time.time() - t0:.0f}s")
    return found


# ---------------------------------------------------------------------------
# H4: salt 锚定（首选）
# ---------------------------------------------------------------------------
def scan_salt_anchored(chunks, page1s, workers, ctx_radius=0x8000,
                       master: bool = True):
    """定位库 salt / mac_salt 在内存中的位置 → 上下文窗口内候选双路验证。

    cipher 上下文里存有 salt（PBKDF2 用）与 mac_salt（页 HMAC 用），
    找到 salt 就等于找到了放密钥的结构体。
    master=False 时跳过 路 2（PBKDF2×256000 每窗口数分钟，真机已证
    零命中），只做瞬时裸密钥验证。
    """
    page1_by_rel = dict(page1s)
    salts = {}
    for rel, page1 in page1s:
        salt = page1[:16]
        salts[salt] = rel
        salts[bytes(b ^ 0x3A for b in salt)] = rel

    direct_hits, master_hits = {}, []
    seen_ctx = set()
    for start, buf, path in chunks:
        for salt, rel in salts.items():
            pos = 0
            while True:
                pos = buf.find(salt, pos)
                if pos < 0:
                    break
                ctx_id = (start + pos) // 0x1000   # 同一页只处理一次
                if ctx_id not in seen_ctx:
                    seen_ctx.add(ctx_id)
                    lo = max(0, pos - ctx_radius)
                    hi = min(len(buf), pos + ctx_radius)
                    window = buf[lo:hi]
                    log(f"  [H4] {rel} salt 命中 @ {hex(start + pos)}"
                        f"（{'anon' if not path else path}），窗口 {len(window) // 1024}KB")
                    own = [(rel, page1_by_rel[rel])]
                    # 路 1：直接当逐库裸密钥（瞬时，只验命中 salt 的那个库）
                    mv = memoryview(window)
                    for off in range(0, max(0, len(window) - 32)):
                        cand = bytes(mv[off:off + 32])
                        for hit in verify_direct(cand, own):
                            if hit not in direct_hits:
                                direct_hits[hit] = cand
                                log(f"    !! H4 逐库裸密钥命中 {hit}: {cand.hex()}")
                    # 路 2：当主密钥派生验证（PBKDF2×256000，慢；主密钥
                    # 账号级唯一，统一用第一个库的 salt 派生验证即可）
                    if master and not direct_hits:
                        cands = [bytes(mv[o:o + 32])
                                 for o in range(0, max(0, len(window) - 32))]
                        cands = [c for c in cands if len(set(c)) >= 15]
                        # 保守去重（窗口有限，set 可承受）
                        uniq = list(dict.fromkeys(cands))
                        for mh in master_pool(uniq, page1s[0][1], workers, "H4"):
                            master_hits.append(mh)
                pos += 1
    return direct_hits, master_hits


# ---------------------------------------------------------------------------
# H1: 裸密钥直扫（线程池并行）
# ---------------------------------------------------------------------------
def _scan_chunk_direct(args):
    _start, buf, stride, page1s = args
    hits = []
    mv = memoryview(buf)
    for off in range(0, max(0, len(buf) - 32), stride):
        cand = bytes(mv[off:off + 32])
        if len(set(cand)) < 15:
            continue
        for rel, page1 in page1s:
            if _verify_enc_key(cand, page1):
                hits.append((rel, cand))
    return hits


def scan_direct(chunks, page1s, stride: int, label: str, workers: int,
                anon_only: bool = False):
    sel = [(s, b) for s, b, p in chunks if not anon_only or not p]
    log(f"  [{label}] stride={stride}，{len(sel)} 个区域，{workers} 线程…")
    hits = []
    t0 = time.time()
    with ThreadPoolExecutor(workers) as pool:
        for res in pool.map(_scan_chunk_direct,
                            [(s, b, stride, page1s) for s, b in sel],
                            chunksize=1):
            for rel, cand in res:
                log(f"    !! H1 命中 {rel}: {cand.hex()}")
            hits += res
    log(f"  [{label}] 完成，耗时 {time.time() - t0:.0f}s，命中 {len(hits)}")
    return hits


# ---------------------------------------------------------------------------
# H2: hex 字符串
# ---------------------------------------------------------------------------
def scan_hexstrings(chunks, page1s):
    seen, hits = set(), []
    for start, buf, _p in chunks:
        for m in HEX64_RE.finditer(buf):
            cand = bytes.fromhex(m.group().decode())
            if cand in seen:
                continue
            seen.add(cand)
            for hit in verify_direct(cand, page1s):
                hits.append((hit, cand))
                log(f"    !! H2 命中 {hit}: {cand.hex()}")
    log(f"  [H2] 唯一 hex 候选 {len(seen)}，命中 {len(hits)}")
    return hits


# ---------------------------------------------------------------------------
# H3: Config.Cipher 锚点窗口 + 主密钥派生（对照用，真机已证基本无效）
# ---------------------------------------------------------------------------
def scan_anchor_master(chunks, page1s, workers, anchor_window=0x8000,
                       max_candidates=200000):
    rel0, page1_0 = page1s[0]
    cands, seen, truncated = [], set(), False
    for start, buf, _p in chunks:
        pos = 0
        while True:
            pos = buf.find(CONFIG_CIPHER_NAME, pos)
            if pos < 0:
                break
            lo = max(0, pos - anchor_window)
            hi = min(len(buf), pos + len(CONFIG_CIPHER_NAME) + anchor_window)
            for off in range(lo, max(lo, hi - 32)):
                cand = buf[off:off + 32]
                if cand not in seen and len(set(cand)) >= 15:
                    seen.add(cand)
                    cands.append(cand)
            pos += len(CONFIG_CIPHER_NAME)
            if len(cands) >= max_candidates:
                truncated = True
                break
        if truncated:
            break
    log(f"  [H3] 锚点窗口候选 {len(cands)}"
        + ("（已截断）" if truncated else ""))
    if not cands:
        return []
    return master_pool(cands, page1_0, workers, "H3")


# ---------------------------------------------------------------------------
# H5: AES-256 密钥扩展表反推（numpy 向量化；无 numpy 跳过）
# ---------------------------------------------------------------------------
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_RCON = [0x01000000, 0x02000000, 0x04000000, 0x08000000,
         0x10000000, 0x20000000, 0x40000000]


def _subword_np(x, rotate: bool):
    """值域 SubWord（可选 RotWord=循环左移 8 位），向量化。

    OpenSSL rd_key[i] = GETU32(...)（语义大端值存为本地 u32），扫描统一用
    '<u4' 读出语义值，故 SubWord/RotWord 全部在值域完成，无字节序陷阱。
    """
    import numpy as np
    if rotate:
        x = (x << np.uint32(8)) | (x >> np.uint32(24))
    b0 = (x >> np.uint32(24)) & np.uint32(0xFF)
    b1 = (x >> np.uint32(16)) & np.uint32(0xFF)
    b2 = (x >> np.uint32(8)) & np.uint32(0xFF)
    b3 = x & np.uint32(0xFF)
    return ((_SBOX_NP[b0].astype(np.uint32) << np.uint32(24)) |
            (_SBOX_NP[b1].astype(np.uint32) << np.uint32(16)) |
            (_SBOX_NP[b2].astype(np.uint32) << np.uint32(8)) |
            _SBOX_NP[b3].astype(np.uint32))


def scan_aes_schedules(chunks, page1s, chunk_bytes=1 << 26):
    """H5：扫描 AES-256 扩展表并反推原始密钥。

    AES-256 扩展 60 词（语义域）：W[8i] = W[8i-8] ^ SubWord(RotWord(W[8i-1]))
    ^ Rcon[i]；W[8i+4] = W[8i-4] ^ SubWord(W[8i+3])。
    检测用 W[j] = W[j-8] ^ SubWord(RotWord(W[j-1])) ^ Rcon1 对全部字偏移
    stride-1 扫（单关系误报率 2^-32：真表必命中、随机数据几乎不命中），
    命中处完整验证 14 轮关系，取前 8 词还原密钥（大端字节序），最后页 1
    HMAC 确认。
    """
    try:
        import numpy as np
    except ImportError:
        log("  [H5] 未安装 numpy，跳过（pip install numpy 后重跑可启用）")
        return []
    global _SBOX_NP
    _SBOX_NP = np.frombuffer(_SBOX, dtype=np.uint8)
    rcon1 = np.uint32(0x01000000)

    # 16-bit LUT：SubWord(x) = T_LO[x & 0xFFFF] | T_HI[x >> 16]。
    # 2 次表格 gather（64K×4B 表，常驻 L2）替代逐字节 4 次 gather，
    # 实测比 _subword_np 快约 4 倍（2GB 全扫从 ~100s 降到 ~25s）。
    idx16 = np.arange(1 << 16, dtype=np.uint32)
    t_lo = (_SBOX_NP[idx16 & 0xFF].astype(np.uint32) |
            (_SBOX_NP[(idx16 >> 8) & 0xFF].astype(np.uint32) << np.uint32(8)))
    t_hi = ((_SBOX_NP[idx16 & 0xFF].astype(np.uint32) << np.uint32(16)) |
            (_SBOX_NP[(idx16 >> 8) & 0xFF].astype(np.uint32) << np.uint32(24)))

    def detect(piece):
        """首关系筛选：返回词偏移数组 j（W[j] 为某扩展表第 9 词）。"""
        w = np.frombuffer(piece, dtype="<u4")
        if len(w) < 69:
            return w, []
        x = w[7:-1]
        rot = (x << np.uint32(8)) | (x >> np.uint32(24))      # RotWord = rotl8
        sub = t_lo[rot & np.uint32(0xFFFF)] | t_hi[rot >> np.uint32(16)]
        match = w[8:] == (w[:-8] ^ sub ^ rcon1)
        return w, np.nonzero(match)[0]

    def verify(words60):
        """完整验证 60 词扩展表（语义域逐词）。relB 最后一个位置越界不查。"""
        for i in range(1, 8):
            j = 8 * i
            x = int(words60[j - 1])
            rot = ((x << 8) & 0xFFFFFFFF) | (x >> 24)
            sub = 0
            for k in range(4):
                sub |= _SBOX[(rot >> (24 - 8 * k)) & 0xFF] << (24 - 8 * k)
            if int(words60[j]) != int(words60[j - 8]) ^ sub ^ _RCON[i - 1]:
                return False
            if i == 7:
                continue  # W[64] 不存在（60 词表），relB 只到 i=6
            x = int(words60[j + 3])
            sub = (_SBOX[(x >> 24) & 0xFF] << 24 | _SBOX[(x >> 16) & 0xFF] << 16 |
                   _SBOX[(x >> 8) & 0xFF] << 8 | _SBOX[x & 0xFF])
            if int(words60[j + 4]) != int(words60[j - 4]) ^ sub:
                return False
        return True

    hits = []
    seen_keys = set()
    for start, buf, _path in chunks:
        off = 0
        while off < len(buf) - 256:
            piece = buf[off:off + chunk_bytes + 256]
            w, js = detect(piece)
            for idx in js:
                j = int(idx) + 8   # match 数组下标 0 对应词偏移 8
                if j + 52 > len(w):
                    continue
                words60 = w[j - 8: j - 8 + 60]
                if not verify(words60):
                    continue
                # 还原密钥：语义字 → 大端字节序
                key = b"".join(struct.pack(">I", int(x)) for x in words60[:8])
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                for rel, page1 in page1s:
                    if _verify_enc_key(key, page1):
                        hits.append((rel, key))
                        log(f"    !! H5 命中 {rel}: {key.hex()} "
                            f"@ {hex(start + off + (j - 8) * 4)}")
            off += chunk_bytes
    log(f"  [H5] 完成，命中 {len(hits)}")
    return hits


# ---------------------------------------------------------------------------
def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db-dir", help="数据目录（xwechat_files 或账号目录），默认自动探测")
    ap.add_argument("--pid", type=int, action="append", help="只扫指定进程（可多次）")
    ap.add_argument("--stride", type=int, default=8, help="H1 全内存步长（默认 8）")
    ap.add_argument("--skip-h1", action="store_true", help="跳过 H1/H1b 暴力直扫")
    ap.add_argument("--skip-salt", action="store_true", help="跳过 H4 salt 锚定")
    ap.add_argument("--skip-master", action="store_true",
                    help="跳过所有主密钥派生验证（H4 路2 + H3；真机已证零命中且慢）")
    ap.add_argument("--skip-aes", action="store_true", help="跳过 H5 AES 扩展表反推")
    args = ap.parse_args()

    head("步骤 1/4: 库文件状态（H0）")
    db_dir = args.db_dir or auto_detect_db_dir()
    if not db_dir:
        log("!! 未找到数据目录，请 --db-dir 指定")
        return 2
    log(f"数据目录: {db_dir}")
    plaintext, usable = check_db_files(db_dir)
    if plaintext:
        log("\n>>> 结论：存在明文库！直接 sqlite3 打开即可，根本不需要密钥。")
        return 0
    if not usable:
        log("!! 没有可用的加密库文件")
        return 2
    page1s = []
    for rel, path, _ in usable:
        with open(path, "rb") as f:
            page1s.append((rel, f.read(PAGE_SZ)))

    head("步骤 2/4: 进程定位")
    wechat_pids = find_wechat_pids()
    holders = pids_holding_dbs()
    log(f"微信进程: {wechat_pids}")
    log(f"持有打开 .db 文件的进程: {holders or '（无——微信是否已登录？）'}")
    targets = args.pid or (holders or wechat_pids)
    log(f"扫描目标: {targets}")

    workers = max(1, (os.cpu_count() or 2) - 1)
    summary = {}

    for pid in targets:
        head(f"步骤 3/4: 扫描进程 {pid}")
        try:
            os.kill(pid, 0)
        except OSError as exc:
            log(f"  无法访问进程 {pid}: {exc}")
            continue
        maps_summary(pid)
        t0 = time.time()
        chunks = read_all_chunks(pid)
        log(f"  读入 {sum(len(b) for _, b, _ in chunks) / 1e6:.0f} MB"
            f"（{len(chunks)} 区域，{time.time() - t0:.0f}s）")
        anchor_stats(chunks)
        found = []

        if not args.skip_salt:
            head(f"进程 {pid}: H4 salt 锚定（cipher 上下文定位，首选）")
            direct, masters = scan_salt_anchored(chunks, page1s, workers,
                                                 master=not args.skip_master)
            if direct:
                found.append(("H4-direct", {r: k.hex() for r, k in direct.items()}))
            if masters:
                found.append(("H4-master", masters))

        if not args.skip_h1:
            head(f"进程 {pid}: H1 裸密钥直扫（全内存 stride={args.stride}）")
            if scan_direct(chunks, page1s, args.stride, f"H1-all", workers):
                found.append(("H1", True))
            head(f"进程 {pid}: H1b 堆/匿名区 stride=1 细扫")
            if scan_direct(chunks, page1s, 1, "H1b-anon", workers, anon_only=True):
                found.append(("H1b", True))

        head(f"进程 {pid}: H2 hex 字符串")
        if scan_hexstrings(chunks, page1s):
            found.append(("H2", True))

        if not args.skip_master:
            head(f"进程 {pid}: H3 Config.Cipher 锚点窗口 + 主密钥派生")
            masters = scan_anchor_master(chunks, page1s, workers)
            if masters:
                found.append(("H3-master", masters))

        if not args.skip_aes:
            head(f"进程 {pid}: H5 AES-256 密钥扩展表反推")
            hits = scan_aes_schedules(chunks, page1s)
            if hits:
                found.append(("H5", {r: k.hex() for r, k in hits}))

        summary[pid] = found

    head("步骤 4/4: 结论")
    hit_any = False
    for pid, found in summary.items():
        for item in found:
            hit_any = True
            log(f"  pid {pid} {item[0]}: {item[1] if item[0] in ('H4-direct', 'H5') else '命中'}")
    if hit_any:
        log("\n把完整输出发回即可确定修复方案（H4-master/H3-master 的 hex 即主密钥，"
            "H4-direct/H5 的 hex 即逐库密钥）。")
        return 0
    log("全部假设未命中。请把【完整输出】发回，重点看：\n"
        "  1. H0 是否出现明文库\n"
        "  2. 「持有打开 .db 的进程」与「微信进程」是否为空/不一致\n"
        "  3. H4 的 salt 命中次数（0 = 打开库的进程里没有上下文，扫错进程）\n"
        "  4. H5 是否因缺 numpy 跳过\n"
        "  5. 各假设候选数量级是否异常")
    return 1


if __name__ == "__main__":
    sys.exit(main())
