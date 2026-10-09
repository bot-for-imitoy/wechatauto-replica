"""H5 双布局 + 参数扫描的端到端测试。"""
import os, sys, hashlib, hmac as hm_, struct, subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wechatauto.db import PAGE_SZ, _pbkdf2, _verify_enc_key
import probe_memory as P

SBOX = P._SBOX


def subw(t):
    return sum(SBOX[(t >> (24 - 8 * k)) & 0xFF] << (24 - 8 * k) for k in range(4))


def expand_aes256(key):
    """语义域（大端字）标准扩展。"""
    w = [int.from_bytes(key[i * 4:(i + 1) * 4], "big") for i in range(8)]
    for k in range(8, 60):
        t = w[k - 1]
        if k % 8 == 0:
            t = subw(((t << 8) & 0xFFFFFFFF) | (t >> 24)) ^ P._RCON[k // 8 - 1]
        elif k % 8 == 4:
            t = subw(t)
        w.append(w[k - 8] ^ t)
    return w


def make_db(key):
    salt = os.urandom(16)
    derived = _pbkdf2(key, salt, 256000)
    page1 = bytearray(salt + os.urandom(PAGE_SZ - 16))
    mac_key = hashlib.pbkdf2_hmac("sha512", derived, bytes(b ^ 0x3A for b in salt), 2, dklen=32)
    h = hm_.new(mac_key, bytes(page1[16:PAGE_SZ - 64]), hashlib.sha512)
    h.update(struct.pack("<I", 1))
    page1[PAGE_SZ - 64:] = h.digest()
    return bytes(page1), derived


def run_child(hexblob):
    child = subprocess.Popen([sys.executable, "-c", f'''
import sys, time
sys.path.insert(0, ".")
HELD = bytes.fromhex("{hexblob}")
print("READY", flush=True); time.sleep(60)
'''], stdout=subprocess.PIPE, text=True)
    assert child.stdout.readline().strip() == "READY"
    return child


page1, derived = make_db(os.urandom(32))
page1s = [("contact/contact.db", page1)]

# ---- 测试 1：布局 A（OpenSSL 语义大端）回归 ----
sched_a = b"".join(struct.pack("<I", x & 0xFFFFFFFF) for x in expand_aes256(derived))
child = run_child(sched_a.hex())
hits = P.scan_aes_schedules(P.read_all_chunks(child.pid), page1s)
child.kill()
print("布局A:", "PASS" if any(k == derived for _, k in hits) else "FAIL")

# ---- 测试 2：布局 B（mbedTLS 语义小端）----
sched_b = b"".join(struct.pack("<I", int.from_bytes(derived[i*4:i*4+4], "little"))
                   for i in range(0, 0))  # 占位
w_sem = expand_aes256(derived)
sched_b = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in w_sem)
# 布局 B：内存 u32 的 LE 字节序即 key 字节序 → 每词 pack("<I", LE语义值)
sched_b = b"".join(struct.pack("<I", int.from_bytes(w_sem[i].to_bytes(4, "big"), "little"))
                   for i in range(60))
child = run_child(sched_b.hex())
hits = P.scan_aes_schedules(P.read_all_chunks(child.pid), page1s)
child.kill()
print("布局B:", "PASS" if any(k == derived for _, k in hits) else "FAIL")

# ---- 测试 3：参数扫描——非标准参数（sha256 / reserve48 / 页号BE）----
salt = page1[:16]
mac_key = hashlib.pbkdf2_hmac("sha256", derived, bytes(b ^ 0x3A for b in salt), 2, dklen=32)
page2 = bytearray(page1)
h = hm_.new(mac_key, bytes(page2[16:PAGE_SZ - 48 + 16]), hashlib.sha256)
h.update(struct.pack(">I", 1))
page2[PAGE_SZ - 32:] = h.digest()
combo = P.verify_key_sweep(derived, bytes(page2))
print("参数扫描(sha256/be/48):", "PASS" if combo and "sha256" in combo and "reserve48" in combo else f"FAIL({combo})")

# ---- 测试 4：错误密钥全组合必拒 ----
combo = P.verify_key_sweep(os.urandom(32), page1)
print("错误密钥拒绝:", "PASS" if combo is None else "FAIL")
