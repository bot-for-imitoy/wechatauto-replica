# -*- coding: utf-8 -*-
"""Linux 密钥提取自测：不依赖真微信，验证扫描→校验→缓存全链路。

原理：用 SQLCipher 4 页 1 的真实 HMAC 格式构造两个假 .db（contact.db /
message_0.db），把对应 32 字节密钥种进一个子进程的内存（并放置
Config.Cipher 锚点字符串模拟微信进程布局），然后：

    1. scan_pid_keys 必须从子进程内存扫出两个密钥并通过页 1 HMAC 校验；
    2. save_key_cache 落盘后，WeChatDB（显式传 db_dir + workdir）必须能
       纯靠缓存解开两个库（不触碰任何内存读取）；
    3. 反向验证：换成错误密钥必须校验失败（证明断言真能咬住回归）。

运行：python tools/test_linux_key.py
（读的是子进程自己的内存，无需 root；真机取钥才需要 sudo。）
"""
import hmac as hmac_mod
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from wechatauto.db import PAGE_SZ, _verify_enc_key  # noqa: E402
from wechatauto.linux_key import (  # noqa: E402
    collect_db_files,
    save_key_cache,
    scan_pid_keys,
)

CHILD_SRC = r"""
import sys, time
sys.path.insert(0, "%(repo)s")
from wechatauto.db import CONFIG_CIPHER_NAME

HELD = [
    bytes.fromhex("%(k1)s"),
    bytes.fromhex("%(k2)s"),
    CONFIG_CIPHER_NAME,          # 模拟微信进程内的 WCDB 配置对象名
]
ANCHOR = CONFIG_CIPHER_NAME * 4  # 放大锚点，确保扫描窗口命中

print("READY", flush=True)
time.sleep(120)
"""


def make_fake_db(path: str, key: bytes) -> None:
    """构造页 1 能通过 SQLCipher 4 HMAC 校验的假库文件。"""
    salt = os.urandom(16)
    body = os.urandom(PAGE_SZ - 16)
    page1 = salt + body                       # 4096 B
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=32)
    hm = hmac_mod.new(mac_key, page1[16: PAGE_SZ - 64], hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    page1 = page1[: PAGE_SZ - 64] + hm.digest()
    assert len(page1) == PAGE_SZ
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(page1)
        f.write(os.urandom(PAGE_SZ))          # 假的第 2 页


def spawn_child(k1: bytes, k2: bytes) -> subprocess.Popen:
    src = CHILD_SRC % {"repo": REPO, "k1": k1.hex(), "k2": k2.hex()}
    return subprocess.Popen([sys.executable, "-c", src],
                            stdout=subprocess.PIPE, text=True)


def main() -> int:
    from wechatauto.db import WeChatDB

    failures = 0
    tmp = tempfile.mkdtemp(prefix="wxkeytest_")
    k1, k2 = os.urandom(32), os.urandom(32)
    # WeChatDB.db_dir 语义 = 账号目录的父目录（如 ~/xwechat_files）
    db_dir = tmp
    make_fake_db(os.path.join(db_dir, "wxid_demo_ab12", "db_storage",
                              "contact", "contact.db"), k1)
    make_fake_db(os.path.join(db_dir, "wxid_demo_ab12", "db_storage",
                              "message", "message_0.db"), k2)

    child = spawn_child(k1, k2)
    try:
        assert child.stdout is not None
        line = child.stdout.readline().strip()
        assert line == "READY", f"子进程启动异常: {line!r}"
        pid = child.pid

        account, db_files = collect_db_files(db_dir)[0]
        assert account == "wxid_demo_ab12"
        assert len(db_files) == 2, db_files

        # 1) 扫描：必须扫出两个库的密钥
        found = scan_pid_keys(pid, db_files, deep=True)
        ok1 = found.get("contact/contact.db") == k1
        ok2 = found.get("message/message_0.db") == k2
        print(("PASS" if ok1 and ok2 else "FAIL") +
              f"  扫描结果: {[(rel, k.hex()[:12] + '…') for rel, k in found.items()]}")
        failures += (ok1 and ok2) is False

        # 2) 反向：错误密钥必须验不过（HMAC 闸门真的在咬人）
        bad = bytes(b ^ 0xFF for b in k1)
        with open(db_files[0][1], "rb") as f:
            page1 = f.read(PAGE_SZ)
        assert not _verify_enc_key(bad, page1), "错误密钥竟通过校验？"
        print("PASS  错误密钥被页 1 HMAC 正确拒绝")

        # 3) 缓存落盘 + WeChatDB 纯缓存解库（不碰内存读取）
        paths = save_key_cache(db_dir, account, found)
        workdir = paths[0].rsplit(os.sep, 1)[0]
        assert os.path.exists(paths[0]) and os.path.exists(paths[1])
        assert oct(os.stat(paths[0]).st_mode & 0o777) == "0o600", "缓存必须是 0600"
        assert json.load(open(paths[0]))["contact/contact.db"] == k1.hex()
        db = WeChatDB(db_dir=db_dir, workdir=workdir, account=account)
        loaded = {rel: db._keys[rel] for rel in db._keys}
        ok3 = loaded.get("contact/contact.db") == k1 and \
            loaded.get("message/message_0.db") == k2
        print(("PASS" if ok3 else "FAIL") +
              f"  WeChatDB 从缓存加载并解开 {len(loaded)}/2 个库")
        failures += (ok3) is False
    finally:
        child.kill()

    print("=" * 48)
    print("全部通过" if failures == 0 else f"{failures} 项失败")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
