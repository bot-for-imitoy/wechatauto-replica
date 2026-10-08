# -*- coding: utf-8 -*-
"""wechatauto Linux 密钥提取模块（微信 4.x Linux 客户端）

Linux 上没有 kernel32/OpenProcess，本模块用 /proc 文件系统完成等价工作：

    1. 定位微信进程（/proc/*/comm|cmdline 匹配 WeChat/wechat/weixin）；
    2. 解析 /proc/<pid>/maps，读取全部可读私有内存区域（堆 + 匿名 + 私有
       文件映射）；
    3. 扫描候选密钥：
       a. 锚点扫描（默认）：在内存中定位 WCDB 配置对象名字符串
          ``com.Tencent.WCDB.Config.Cipher``，只验证锚点附近 ±128KB 窗口内的
          32 字节候选——Linux 客户端与 Windows 版同源 WCDB，该字符串通常
          同样存在；
       b. 深度扫描（--deep，兜底）：步长 8 字节暴力滑窗全部可读写匿名区域，
          速度约几十 MB/分钟，仅在锚点扫描一无所获时才值得使用；
    4. 每个候选都用 SQLCipher 4 页 1 HMAC 强校验（复用 db._verify_enc_key，
       零误报），通过的写进 keys.json 缓存。

权限模型（为什么是一次性 root 而不是常驻守护进程）：

    微信 4.x 的库密钥由主密钥 + 库文件随机 salt 派生，**与账号绑定、静态
    不变**：微信重启不换钥、更新不重加密（原项目正是依赖这一点把 keys.json
    缓存跨会话复用，并且每次加载都会用页 1 HMAC 重新验证，失效自动重取）。
    因此 root 权限只需要成功使用一次：

        sudo python -m wechatauto.linux_key

    之后普通用户跑 ``WeChatDB`` 直接命中缓存，全程无特权。这比常驻 root
    守护进程的权限面小得多；万一哪天密钥真的动态化（缓存校验失败会明确
    报错），可用 ``--watch`` 模式按需重扫，或参考 docs/linux-support.md
    的最小权限守护进程方案。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Dict, List, Optional, Sequence, Tuple

from wechatauto.db import (
    CONFIG_CIPHER_NAME,
    IS_WINDOWS,
    PAGE_SZ,
    _verify_enc_key,
)

# 进程名候选（官方 Linux 客户端主进程名，含大小写变体与别名）
WECHAT_PROC_NAMES = {"wechat", "weixin", "weixin.exe", "wechatapp"}

# 锚点扫描窗口（锚点前后各 128KB 足够覆盖相邻堆块里的配置对象）
ANCHOR_WINDOW = 0x20000

Chunk = Tuple[int, bytes]  # (起始地址, 内容)


# ---------------------------------------------------------------------------
# 进程与内存区域枚举
# ---------------------------------------------------------------------------
def find_wechat_pids() -> List[int]:
    """枚举本机微信进程 pid（/proc 扫描，任何用户可执行）。"""
    pids: List[int] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm", "rb") as f:
                comm = f.read().strip().decode("utf-8", "replace").lower()
            if comm in WECHAT_PROC_NAMES:
                pids.append(int(entry))
                continue
            # comm 被 15 字符截断时看 cmdline 兜底
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmd = f.read().split(b"\x00")[0].decode("utf-8", "replace").lower()
            if any(name in os.path.basename(cmd) for name in ("wechat", "weixin")):
                pids.append(int(entry))
        except (OSError, ValueError):
            continue
    return sorted(pids)


def _parse_maps(pid: int) -> List[Tuple[int, int, str, bool]]:
    """解析 maps，返回 [(start, end, pathname, writable)]，仅可读私有区域。

    私有映射（p 标志）是堆、匿名内存与写时复制数据段的所在——密钥只可能
    在这里；共享映射与设备映射直接跳过。
    """
    regions: List[Tuple[int, int, str, bool]] = []
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split(maxsplit=5)
                if len(parts) < 5:
                    continue
                perms = parts[1]
                if "r" not in perms or "p" not in perms:
                    continue
                start, end = (int(x, 16) for x in parts[0].split("-"))
                path = parts[5].strip() if len(parts) == 6 else ""
                if path.startswith("/dev") or path.startswith("[vvar") \
                        or path.startswith("[vdso") or path.startswith("[vsyscall"):
                    continue
                # 跳过明显的纯代码段（r-x / --x 已被 "r in perms and..." 过滤）
                regions.append((start, end, path, "w" in perms))
    except OSError as exc:
        raise RuntimeError(f"无法读取 /proc/{pid}/maps: {exc}") from exc
    return regions


def _read_mem(f, start: int, size: int) -> Optional[bytes]:
    """从已打开的 /proc/<pid>/mem 句柄读取一段内存，失败返回 None。

    权限不足在 open 阶段就会抛 PermissionError（见 scan_pid_keys），
    这里只兜底"区域刚好被释放"等瞬时错误。
    """
    try:
        f.seek(start)
        return f.read(size)
    except (OSError, ValueError):
        return None


def _select_regions(pid: int, deep: bool) -> List[Tuple[int, int]]:
    """挑出要扫描的区域：锚点模式只要可读私有区；deep 模式聚焦可写匿名/堆。"""
    regions = _parse_maps(pid)
    out: List[Tuple[int, int]] = []
    for start, end, path, writable in regions:
        size = end - start
        if size > 0x40000000:          # >1GB 的映射不是堆，跳过
            continue
        if deep:
            # 深扫聚焦堆/匿名可写区（密钥是运行时数据，只读文件映射没有）
            if writable and not path:
                out.append((start, end))
        else:
            out.append((start, end))
    return out


# ---------------------------------------------------------------------------
# 候选收集与校验
# ---------------------------------------------------------------------------
def _iter_candidates_anchored(chunks: Sequence[Chunk], step: int = 8):
    """在锚点附近窗口内滑窗产出 32 字节候选。"""
    for base, buf in chunks:
        pos = 0
        while True:
            pos = buf.find(CONFIG_CIPHER_NAME, pos)
            if pos < 0:
                break
            lo = max(0, pos - ANCHOR_WINDOW)
            hi = min(len(buf), pos + len(CONFIG_CIPHER_NAME) + ANCHOR_WINDOW)
            window = memoryview(buf)[lo:hi]
            for off in range(0, max(0, len(window) - 32), step):
                yield base + lo + off, window[off:off + 32]
            pos += len(CONFIG_CIPHER_NAME)


def _iter_candidates_deep(chunks: Sequence[Chunk], step: int = 8):
    """全区域暴力滑窗（慢，兜底）。"""
    for base, buf in chunks:
        mv = memoryview(buf)
        for off in range(0, max(0, len(buf) - 32), step):
            yield base + off, mv[off:off + 32]


def _probable_key(b: bytes) -> bool:
    """与 db.WeChatDB._probable_key 同判据：剔除全零/全重复的平凡值。"""
    return len(set(b)) >= 15


def _load_page1s(db_files: Sequence[Tuple[str, str, int]]) -> List[Tuple[str, bytes]]:
    out = []
    for rel, path, _ in db_files:
        try:
            with open(path, "rb") as f:
                page1 = f.read(PAGE_SZ)
        except OSError:
            continue
        if len(page1) >= PAGE_SZ:
            out.append((rel, page1))
    return out


def _validate_candidate(cand: bytes, page1s: Sequence[Tuple[str, bytes]]) -> Dict[str, bytes]:
    """候选 32 字节 → 逐库页 1 HMAC 校验，返回 {rel: key}。"""
    if not _probable_key(cand):
        return {}
    hits: Dict[str, bytes] = {}
    for rel, page1 in page1s:
        if _verify_enc_key(cand, page1):
            hits[rel] = bytes(cand)
    return hits


def scan_pid_keys(
    pid: int,
    db_files: Sequence[Tuple[str, str, int]],
    deep: bool = False,
    progress=None,
) -> Dict[str, bytes]:
    """扫描单个微信进程内存，返回 {rel: 已验证密钥}。"""
    page1s = _load_page1s(db_files)
    if not page1s:
        raise RuntimeError("没有任何可读的 .db 文件（未登录或数据目录不对）")

    # 显式暴露权限问题（root / ptrace_scope），不做静默降级
    try:
        mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except PermissionError as exc:
        raise PermissionError(
            f"/proc/{pid}/mem 不可读：需要 root（sudo python -m wechatauto.linux_key）"
        ) from exc
    with mem:
        regions = _select_regions(pid, deep=False)
        chunks: List[Chunk] = []
        for start, end in regions:
            buf = _read_mem(mem, start, end - start)
            if buf:
                chunks.append((start, buf))

        def _report(done: int, total: int, stage: str):
            if progress:
                progress(stage, done, total)

        found: Dict[str, bytes] = {}
        tested = 0

        # 阶段 1：锚点扫描
        for _, cand in _iter_candidates_anchored(chunks):
            tested += 1
            remaining = [p for p in page1s if p[0] not in found]
            if remaining:
                for rel, key in _validate_candidate(bytes(cand), remaining).items():
                    found.setdefault(rel, key)

        if found or not deep:
            return found

        # 阶段 2：锚点失败 → 自动退化到堆/匿名区深扫
        _report(0, 0, "deep")
        deep_regions = _select_regions(pid, deep=True)
        chunks = []
        for start, end in deep_regions:
            buf = _read_mem(mem, start, end - start)
            if buf:
                chunks.append((start, buf))
        for _, cand in _iter_candidates_deep(chunks):
            tested += 1
            remaining = [p for p in page1s if p[0] not in found]
            if remaining:
                for rel, key in _validate_candidate(bytes(cand), remaining).items():
                    found.setdefault(rel, key)
        _report(tested, tested, "done")
        return found


def extract_keys_for_dbs(
    db_files: Sequence[Tuple[str, str, int]],
    pids: Optional[Sequence[int]] = None,
) -> Dict[str, bytes]:
    """WeChatDB.extract_keys 的 Linux 后端：扫描全部微信进程直到集齐密钥。"""
    if IS_WINDOWS:
        raise RuntimeError("extract_keys_for_dbs 仅用于 Linux")
    pids = list(pids) if pids else find_wechat_pids()
    if not pids:
        raise RuntimeError(
            "未检测到微信进程。请先在 Linux 上安装并登录微信 4.x 客户端"
            "（官方 Linux 版 / flatpak com.tencent.WeChat），再运行本功能。"
        )
    collected: Dict[str, bytes] = {}
    for pid in pids:
        try:
            collected.update(scan_pid_keys(pid, db_files))
        except PermissionError:
            raise RuntimeError(_ROOT_HINT) from None
        except RuntimeError:
            raise
        if len(collected) >= len(db_files):
            break
    if not collected:
        sys.stderr.write(_ROOT_HINT + "\n")
    return collected


def collect_candidates_for_dbs(
    db_files: Sequence[Tuple[str, str, int]],
) -> Dict[str, bytes]:
    """账号自愈路径用：与 extract_keys_for_dbs 相同（Linux 上无账号歧义）。"""
    return extract_keys_for_dbs(db_files)


_ROOT_HINT = (
    "[wechatauto] 读取微信进程内存需要 root 权限。密钥为账号绑定的静态值，"
    "只需以 root 成功运行一次：\n"
    "    sudo python -m wechatauto.linux_key\n"
    "成功后密钥写入缓存，之后普通用户运行 WeChatDB 不再需要任何特权。"
)


# ---------------------------------------------------------------------------
# 缓存落盘（与 WeChatDB 的 keys.json / 稳定副本目录完全兼容）
# ---------------------------------------------------------------------------
def _workdir_for(account: str) -> str:
    import tempfile
    return os.path.join(tempfile.gettempdir(), "wechatauto_db", account)


def _stable_dir() -> str:
    env = os.environ.get("WECHATAUTO_KEYS_DIR")
    if env:
        return env
    return os.path.join(
        os.path.expanduser("~"), ".local", "share", "wechatauto_keys")


def save_key_cache(db_dir: str, account: str, keys: Dict[str, bytes]) -> List[str]:
    """把密钥写进 WeChatDB 约定的两处缓存（0600 权限，原子写）。

    db_dir 语义与 WeChatDB.db_dir 一致：账号目录的**父目录**（如 ~/xwechat_files）。
    """
    data = {rel: key.hex() for rel, key in keys.items()}
    written = []
    for directory, name in (
        (_workdir_for(account), "keys.json"),
        (_stable_dir(), account + ".json"),
    ):
        try:
            os.makedirs(directory, exist_ok=True)
            path = os.path.join(directory, name)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            written.append(path)
        except OSError as exc:
            sys.stderr.write(f"[wechatauto] 缓存写入失败 {directory}: {exc!r}\n")
    return written


def collect_db_files(db_dir: str) -> List[Tuple[str, List[Tuple[str, str, int]]]]:
    """按 WeChatDB 的规则收集各账号的库文件。

    db_dir 为账号目录的父目录（与 WeChatDB.db_dir 一致）。返回
    [(account, [(rel, path, size)])]，跳过 migrate 目录（微信保留的
    unspportmsg.db 无对应内存密钥，原版同样排除）。
    """
    accounts: List[Tuple[str, List[Tuple[str, str, int]]]] = []
    for name in sorted(os.listdir(db_dir)):
        base = os.path.join(db_dir, name, "db_storage")
        if not os.path.isdir(base):
            continue
        files: List[Tuple[str, str, int]] = []
        for root, _, names in os.walk(base):
            if os.path.normcase(os.path.relpath(root, base)).startswith("migrate"):
                continue
            for fname in names:
                if fname.endswith(".db") and not fname.endswith(("-wal", "-shm")):
                    path = os.path.join(root, fname)
                    files.append((os.path.relpath(path, base), path,
                                  os.path.getsize(path)))
        if files:
            accounts.append((name, files))
    return accounts


# ---------------------------------------------------------------------------
# CLI：sudo python -m wechatauto.linux_key [--db-dir DIR] [--deep] [--watch N]
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    from wechatauto.db import auto_detect_db_dir

    ap = argparse.ArgumentParser(
        prog="python -m wechatauto.linux_key",
        description="微信 4.x Linux 客户端：一次性 root 内存扫描提取数据库密钥"
                    "（密钥为静态值，成功一次后普通用户读库不再需要权限）",
    )
    ap.add_argument("--db-dir", help="微信数据目录（含 db_storage 的账号目录的父目录），"
                                     "默认自动探测 ~/xwechat_files 等")
    ap.add_argument("--pid", type=int, action="append",
                    help="指定微信进程 pid（默认自动枚举），可多次")
    ap.add_argument("--deep", action="store_true",
                    help="锚点扫描失败后追加堆/匿名区全量滑窗（慢，分钟级）")
    ap.add_argument("--watch", type=int, metavar="SECONDS", default=0,
                    help="每 N 秒重扫一次（兜底用途；密钥是静态值，正常无需开启）")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    args = ap.parse_args(argv)

    if IS_WINDOWS:
        print("本模块仅用于 Linux；Windows 上 WeChatDB 已内置密钥提取。", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print(_ROOT_HINT, file=sys.stderr)
        return 1

    db_dir = args.db_dir or auto_detect_db_dir()
    if not db_dir:
        print("未找到微信数据目录。请用 --db-dir 指定（形如 ~/xwechat_files，"
              "即账号目录的父目录）。", file=sys.stderr)
        return 2
    accounts = collect_db_files(db_dir)
    if not accounts:
        print(f"{db_dir} 下没有含 db_storage 的账号目录（微信是否已登录过？）",
              file=sys.stderr)
        return 2

    def progress(stage: str, done: int, total: int):
        if stage == "deep":
            print("[wechatauto] 锚点扫描未命中，转入堆/匿名区深度扫描（较慢）...",
                  file=sys.stderr)

    pids = args.pid or find_wechat_pids()
    if not pids:
        print("未检测到微信进程，请先启动并登录微信。", file=sys.stderr)
        return 2

    print(f"[wechatauto] 数据目录: {db_dir}"
          f"（账号: {', '.join(a for a, _ in accounts)}）", file=sys.stderr)
    print(f"[wechatauto] 微信进程: {pids}", file=sys.stderr)

    while True:
        results = {}
        for account, db_files in accounts:
            keys: Dict[str, bytes] = {}
            for pid in pids:
                try:
                    keys.update(scan_pid_keys(pid, db_files, deep=args.deep,
                                              progress=progress))
                except (RuntimeError, OSError) as exc:
                    sys.stderr.write(f"[wechatauto] pid {pid} 扫描失败: {exc!r}\n")
                if len(keys) >= len(db_files):
                    break
            results[account] = (keys, db_files)

        if args.json:
            print(json.dumps(
                {acct: {rel: k.hex() for rel, k in keys.items()}
                 for acct, (keys, _) in results.items()}, indent=2))
        total_keys = sum(len(k) for k, _ in results.values())
        total_dbs = sum(len(f) for _, f in results.values())
        if total_keys:
            saved = []
            for acct, (keys, _) in results.items():
                if keys:
                    saved += save_key_cache(db_dir, acct, keys)
            print(f"[wechatauto] 提取成功: {total_keys}/{total_dbs} 个库密钥，"
                  f"已缓存到:\n  " + "\n  ".join(saved), file=sys.stderr)
            for acct, (keys, db_files) in results.items():
                missing = [rel for rel, _, _ in db_files if rel not in keys]
                if missing:
                    print(f"[wechatauto] 账号 {acct} 以下库未解出"
                          f"（可能未打开过对应功能，不影响已解出的库）: "
                          + ", ".join(missing[:8]), file=sys.stderr)
            if not args.watch:
                return 0
        else:
            print("[wechatauto] 未找到任何密钥。建议：① 确认微信已登录；"
                  "② 加 --deep 重试；③ 微信版本过新时锚点可能漂移，"
                  "欢迎到上游项目提 issue 附 probe 输出。", file=sys.stderr)
            if not args.watch:
                return 3
        time.sleep(args.watch)


if __name__ == "__main__":
    raise SystemExit(main())
