#!/usr/bin/env python3
"""probe_memory.py — Linux 微信内存密钥探测/诊断（需 root）

动机：linux_key.py 初版只把内存候选当「逐库裸密钥」直接验证，但微信 4.x
内存里驻留的是主密钥（逐库密钥 = PBKDF2-SHA512(主密钥, 库 salt, 256000)），
导致真机扫描全空。本脚本逐个假设排查并输出完整诊断报告：

  假设 H0: 库文件根本没加密（Linux 版可能明文 SQLite）
  假设 H1: 逐库裸密钥存在于内存（初版逻辑，stride 可调）
  假设 H2: 64 位 hex 字符串形式的密钥/主密钥存在于内存
  假设 H3: 主密钥存在于内存，锚点(com.Tencent.WCDB.Config.Cipher)窗口内
           （PBKDF2 256000 派生 + 页1 HMAC 验证，多进程）

用法:
  sudo python3 tools/probe_memory.py                 # 全流程
  sudo python3 tools/probe_memory.py --pid 12345     # 指定进程
  sudo python3 tools/probe_memory.py --db-dir ~/xwechat_files/wxid_xxx
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor  # noqa: F401（下方再次引用）

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wechatauto.db import (CONFIG_CIPHER_NAME, PAGE_SZ, RESERVE_SZ,
                           _pbkdf2, _verify_enc_key, auto_detect_db_dir)
from wechatauto.linux_key import (_parse_maps, _read_mem, collect_db_files,
                                  find_wechat_pids)

HEX64_RE = re.compile(rb"[0-9a-fA-F]{64}")


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
        # 用户直接传了账号目录
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


# ---------------------------------------------------------------------------
# 进程选择：谁持有打开的 db？
# ---------------------------------------------------------------------------
def pids_holding_dbs() -> list:
    """扫 /proc/*/fd，找真正打开了 db_storage/*.db 的进程。"""
    holders = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            fd_dir = f"/proc/{entry}/fd"
            comm = open(f"/proc/{entry}/comm", "rb").read().strip().decode(
                "utf-8", "replace")
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


def anchor_stats(pid: int):
    """统计 WCDB 锚点与 hex 串在内存中的分布。"""
    anchors = hexstrs = 0
    anchor_locs = []
    regions = _parse_maps(pid)
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
        for start, end, path, _w in regions:
            buf = _read_mem(f, start, end - start)
            if not buf:
                continue
            n = buf.count(CONFIG_CIPHER_NAME)
            if n:
                anchors += n
                anchor_locs.append((hex(start), "file:" + path if path else "anon"))
            hexstrs += len(HEX64_RE.findall(buf))
    log(f"  锚点 {CONFIG_CIPHER_NAME.decode()} 出现 {anchors} 次 {anchor_locs[:6]}")
    log(f"  64 位 hex 字符串共 {hexstrs} 处")
    return anchors, hexstrs


# ---------------------------------------------------------------------------
# 候选收集
# ---------------------------------------------------------------------------
def iter_chunks(pid: int, anon_only: bool = False, stride: int = 1):
    regions = _parse_maps(pid)
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
        for start, end, path, _w in regions:
            if anon_only and path:
                continue
            buf = _read_mem(f, start, end - start)
            if buf:
                yield start, buf, stride


def scan_direct(pid: int, page1s, stride: int, label: str, anon_only: bool = False):
    """H1：候选直接当逐库密钥验证（2 迭代，微秒级）。

    不做全局去重（数亿候选的去重集合会爆内存），靠 probable_key 过滤
    平凡值 + 速度硬扛；重复候选的重复计算可接受。
    """
    log(f"  [{label}] stride={stride} 扫描中…")
    tested = hits = 0
    t0 = time.time()
    for start, buf, st in iter_chunks(pid, anon_only=anon_only, stride=stride):
        mv = memoryview(buf)
        for off in range(0, max(0, len(buf) - 32), st):
            cand = bytes(mv[off:off + 32])
            if len(set(cand)) < 15:
                continue
            tested += 1
            for rel, page1 in page1s:
                if _verify_enc_key(cand, page1):
                    hits += 1
                    log(f"    !! H1 命中 {rel}: {cand.hex()}")
    log(f"  [{label}] 候选 {tested}，耗时 {time.time() - t0:.0f}s，命中 {hits}")
    return hits


def scan_hexstrings(pid: int, page1s):
    """H2：内存中的 64-hex 字符串（可能以文本形式存密钥）。"""
    log("  [H2-hex] 检索 64 位 hex 字符串…")
    seen, hits = set(), 0
    for start, buf, _ in iter_chunks(pid):
        for m in HEX64_RE.finditer(buf):
            cand = bytes.fromhex(m.group().decode())
            if cand in seen:
                continue
            seen.add(cand)
            for rel, page1 in page1s:
                if _verify_enc_key(cand, page1):
                    hits += 1
                    log(f"    !! H2 命中 {rel}: {cand.hex()}")
    log(f"  [H2-hex] 唯一 {len(seen)}，命中 {hits}")
    return hits


# H3: 主密钥假设 —— 用线程池（hashlib.pbkdf2_hmac 释放 GIL，线程即并行）
_first_page1 = None


def _test_master(cand: bytes):
    derived = _pbkdf2(cand, _first_page1[:16], 256000)
    if _verify_enc_key(derived, _first_page1):
        return cand.hex()
    return None


def scan_master_anchored(pid: int, page1s, anchor_window: int, workers: int,
                         max_candidates: int):
    """H3：锚点窗口内候选 → PBKDF2 256000 派生 → 验证。"""
    global _first_page1
    rel0, page1_0 = page1s[0]
    _first_page1 = page1_0
    log(f"  [H3-master] 锚点窗口 ±{anchor_window // 1024}KB，"
        f"用 {rel0} 做初筛，{workers} 进程并行…")

    candidates = []
    seen = set()
    regions = _parse_maps(pid)
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
        for start, end, path, _w in regions:
            buf = _read_mem(f, start, end - start)
            if not buf:
                continue
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
                        candidates.append(cand)
                pos += len(CONFIG_CIPHER_NAME)
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                log(f"  [H3-master] 候选达到上限 {max_candidates}，截断")
                break

    log(f"  [H3-master] 唯一候选 {len(candidates)}，开始 PBKDF2 派生验证"
        f"（每个 ~0.1-0.3s，预计 {len(candidates) * 0.2 / max(1, workers) / 60:.0f} 分钟）…")
    t0 = time.time()
    found = []
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(workers) as pool:
        for i, res in enumerate(pool.map(_test_master, candidates, chunksize=16)):
            if (i + 1) % 200 == 0:
                log(f"    … {i + 1}/{len(candidates)} ({time.time() - t0:.0f}s)")
            if res:
                found.append(res)
                log(f"    !! H3 主密钥命中: {res}")
    log(f"  [H3-master] 完成，耗时 {time.time() - t0:.0f}s，命中 {len(found)}")
    return found


def dump_anchor_context(pid: int, before: int = 128, after: int = 192):
    """全失败时的兜底：dump 锚点周围内存供人工分析。"""
    regions = _parse_maps(pid)
    dumped = 0
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
        for start, end, path, _w in regions:
            buf = _read_mem(f, start, end - start)
            if not buf:
                continue
            pos = 0
            while True:
                pos = buf.find(CONFIG_CIPHER_NAME, pos)
                if pos < 0:
                    break
                dumped += 1
                lo = max(0, pos - before)
                hi = min(len(buf), pos + after)
                log(f"\n  --- 锚点 #{dumped} @ {hex(start + pos)}"
                    f"（{'anon' if not path else path}）---")
                blob = buf[lo:hi]
                for i in range(0, len(blob), 32):
                    row = blob[i:i + 32]
                    log(f"    {start + lo + i:012x}  {row.hex(' ')}")
                pos += len(CONFIG_CIPHER_NAME)
                if dumped >= 4:
                    return


# ---------------------------------------------------------------------------
def main():
    # sudo 下 locale 常被重置成 POSIX，强制 UTF-8 输出避免中文变 ???
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db-dir", help="账号数据目录（含 db_storage 的目录）")
    ap.add_argument("--pid", type=int, action="append",
                    help="只扫指定进程（可多次）")
    ap.add_argument("--stride", type=int, default=8,
                    help="H1 裸密钥滑窗步长（默认 8；1 更彻底但慢 8 倍）")
    ap.add_argument("--anchor-window", type=int, default=0x8000,
                    help="H3 主密钥锚点窗口半径（默认 32KB）")
    ap.add_argument("--max-master", type=int, default=200000,
                    help="H3 候选上限（默认 200000）")
    ap.add_argument("--skip-direct", action="store_true", help="跳过 H1/H2")
    ap.add_argument("--skip-master", action="store_true", help="跳过 H3")
    ap.add_argument("--dump-context", action="store_true",
                    help="额外 dump 锚点周边内存")
    args = ap.parse_args()

    head("步骤 1/4: 库文件状态（H0）")
    db_dir = args.db_dir or auto_detect_db_dir()
    if not db_dir:
        log("!! 未找到数据目录，请 --db-dir 指定（含 db_storage 的账号目录）")
        return 2
    log(f"数据目录: {db_dir}")
    plaintext, usable = check_db_files(db_dir)
    if plaintext:
        log("\n>>> 结论：存在明文库！直接用 sqlite3 打开即可，根本不需要密钥。")
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

    found = {}

    for pid in targets:
        head(f"步骤 3/4: 扫描进程 {pid}")
        try:
            os.kill(pid, 0)
        except OSError as exc:
            log(f"  无法访问进程 {pid}: {exc}")
            continue
        maps_summary(pid)
        anchors, _ = anchor_stats(pid)

        if not args.skip_direct:
            head(f"进程 {pid}: H1 裸密钥直扫（全内存 stride={args.stride}）")
            if scan_direct(pid, page1s, args.stride, f"pid{pid}-all"):
                found.setdefault(pid, "H1")
            head(f"进程 {pid}: H1b 堆/匿名区细扫（stride=1，捕捉非对齐密钥）")
            if scan_direct(pid, page1s, 1, f"pid{pid}-heap", anon_only=True):
                found.setdefault(pid, "H1b")
            head(f"进程 {pid}: H2 hex 字符串")
            if scan_hexstrings(pid, page1s):
                found.setdefault(pid, "H2")

        if anchors and not args.skip_master:
            head(f"进程 {pid}: H3 主密钥（锚点窗口 + PBKDF2×256000）")
            if scan_master_anchored(pid, page1s, args.anchor_window,
                                    max(1, (os.cpu_count() or 2) - 1),
                                    args.max_master):
                found.setdefault(pid, "H3")
        elif not anchors:
            log("  （无锚点，H3 跳过——微信版本可能改用了其他配置对象）")

        if args.dump_context:
            head(f"进程 {pid}: 锚点上下文 dump")
            dump_anchor_context(pid)

    head("步骤 4/4: 结论")
    if found:
        log(f"命中假设: {found} —— 把本输出发回即可确定修复方案")
        return 0
    log("全部假设未命中。请把【完整输出】发回，重点看：\n"
        "  1. H0 是否出现明文库\n"
        "  2. 「持有打开 .db 的进程」与「微信进程」是否为空/不一致\n"
        "  3. 锚点出现次数是否为 0\n"
        "  4. 各假设的候选数量级是否异常（0 说明区域被过滤光了）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
