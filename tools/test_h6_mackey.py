"""H6 mac_key 上下文搜索的端到端测试。

模拟真机形态：内存里只有
  - salt（cipher 上下文里）
  - 派生好的 mac_key（快速 KDF 产物）
  - mbedTLS 布局的 AES-256 扩展表（无裸密钥、无主密钥）
"""
import os, sys, hashlib, hmac as hm_, struct, subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wechatauto.db import PAGE_SZ, _pbkdf2
import probe_memory as P

SBOX = P._SBOX


def subw(t):
    return sum(SBOX[(t >> (24 - 8 * k)) & 0xFF] << (24 - 8 * k) for k in range(4))


def expand_aes256(key):
    w = [int.from_bytes(key[i * 4:(i + 1) * 4], "big") for i in range(8)]
    for k in range(8, 60):
        t = w[k - 1]
        if k % 8 == 0:
            t = subw(((t << 8) & 0xFFFFFFFF) | (t >> 24)) ^ P._RCON[k // 8 - 1]
        elif k % 8 == 4:
            t = subw(t)
        w.append(w[k - 8] ^ t)
    return w


def sched_b_bytes(derived):
    """mbedTLS 布局：内存 u32 的 LE 字节即 key 字节序。"""
    w_sem = expand_aes256(derived)
    return b"".join(struct.pack("<I", int.from_bytes(w_sem[i].to_bytes(4, "big"),
                                                     "little"))
                    for i in range(60))


def make_db(key, hash_name="sha512", pageno="le", reserve=80):
    salt = os.urandom(16)
    derived = _pbkdf2(key, salt, 256000)
    mac_key = hashlib.pbkdf2_hmac(hash_name, derived, bytes(b ^ 0x3A for b in salt),
                                  2, dklen=32)
    hlen = 64 if hash_name == "sha512" else 32
    page1 = bytearray(salt + os.urandom(PAGE_SZ - 16))
    h = hm_.new(mac_key, bytes(page1[16:PAGE_SZ - reserve + 16]),
                hashlib.sha512 if hash_name == "sha512" else hashlib.sha256)
    h.update(struct.pack("<I" if pageno == "le" else ">I", 1))
    page1[PAGE_SZ - hlen:] = h.digest()
    return bytes(page1), derived, mac_key


def run_child(hexblob):
    child = subprocess.Popen([sys.executable, "-c", f'''
import sys, time
sys.path.insert(0, ".")
HELD = bytes.fromhex("{hexblob}")
print("READY", flush=True); time.sleep(60)
'''], stdout=subprocess.PIPE, text=True)
    assert child.stdout.readline().strip() == "READY"
    return child


def run_case(tag, hash_name, pageno, reserve):
    page1, derived, mac_key = make_db(os.urandom(32), hash_name=hash_name,
                                      pageno=pageno, reserve=reserve)
    salt = page1[:16]
    blob = (salt + os.urandom(0x18) + mac_key + os.urandom(0x20) +
            sched_b_bytes(derived))
    child = run_child(blob.hex())
    chunks = P.read_all_chunks(child.pid)
    P.scan_aes_schedules(chunks, [("contact/contact.db", page1)])
    keys = [k for _, k in P.H5_KEYS]
    has_key = derived in keys
    h6 = P.scan_mackey_windows(chunks, [("contact/contact.db", page1)], keys)
    child.kill()
    ok = any(s.startswith(hash_name) and "mac3a/kdf2" in s and c for _, _, s, c in h6)
    print(f"{tag}: H5候选{len(keys)}(含真密钥:{has_key}) H6 →",
          "PASS" if ok and has_key else f"FAIL({h6})")


run_case("用例1(sha512/le/80 标准)", "sha512", "le", 80)
run_case("用例2(sha256/be/48 非标准)", "sha256", "be", 48)
