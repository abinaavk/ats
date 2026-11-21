#!/usr/bin/env python3
"""Full-stack rehearsal of the multi-server flow, using real processes.

Runs a real Global daemon (started from the unit file `server setup --apply` generates, by a
stand-in systemctl), the real Monitor adapter under a Flask-only interpreter, a TLS tunnel simulator
that routes strictly by the generated Cloudflare YAML, and a real Local Monitor under gunicorn.
Real `systemd-analyze` and `cloudflared ... ingress validate` check the generated files.

Needs: root, free ports 443, 9999, 19997, 19998, a sibling ats-monitor checkout (or ATS_MONITOR_DIR), PyYAML and Flask for
REHEARSAL_GLOBAL_PYTHON (default /usr/bin/python3), and the Monitor requirements for
REHEARSAL_MONITOR_PYTHON (default: this interpreter). It touches nothing outside a temporary directory
(deleted afterwards; pass --keep to retain it) and never calls the host's systemctl or cloudflared service.
Exit status: 0 all checks passed, 1 a check failed, 77 skipped because the host is unsuitable.

    sudo python3 tests/rehearsal/rehearse.py
"""
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shutil
import signal
import hashlib
import hmac
import http.client
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
ATS_SRC = HERE.parents[1]
MON = Path(os.environ.get('ATS_MONITOR_DIR') or ATS_SRC.parent / 'ats-monitor')
VENV = os.environ.get('REHEARSAL_MONITOR_PYTHON') or sys.executable
SYSPY = os.environ.get('REHEARSAL_GLOBAL_PYTHON') or '/usr/bin/python3'   # ideally Flask only, like a clean Global
PORT, TLS_PORT, MON_PORT, HOOK_PORT = 19997, 443, 19998, 9999
failures, procs = [], []


def skip(reason):
    print('SKIPPED: ' + reason)
    sys.exit(77)


def port_free(port):
    with socket.socket() as probe:
        return probe.connect_ex(('127.0.0.1', port)) != 0


if os.geteuid() != 0:
    skip('ATS is root-only; run with sudo')
if not (MON / 'remote_host.py').is_file():
    skip(f'ats-monitor checkout not found at {MON}; set ATS_MONITOR_DIR')
for _port in (TLS_PORT, PORT, MON_PORT, HOOK_PORT):
    if not port_free(_port):
        skip(f'port {_port} is in use on this host')
KEEP = '--keep' in sys.argv
E = Path(tempfile.mkdtemp(prefix='ats-rehearsal-'))
os.chmod(E, 0o755)
# Run a throwaway copy: ATS keeps its private pairing export inside its own checkout, and a
# rehearsal must never touch the real one.
ATS = E / 'ats'
shutil.copytree(ATS_SRC, ATS, ignore=shutil.ignore_patterns('.git', 'files', '__pycache__', 'tests'))
G, L = E / 'g', E / 'l'
UNITS, STATE = E / 'units', E / 'state'
CF = G / 'cloudflared.yml'


def step(text):
    print('\n== ' + text, flush=True)


def check(condition, message):
    print(('  PASS  ' if condition else '  FAIL  ') + message, flush=True)
    if not condition:
        failures.append(message)
    return condition


def wait_port(port, seconds=40):
    end = time.time() + seconds
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                return True
        time.sleep(0.3)
    return False


def sh(argv, env, stdin=None, cwd=None, timeout=240):
    r = subprocess.run(argv, input=stdin, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


# ---------------------------------------------------------------- environment
for path in (G, L, UNITS, STATE):
    path.mkdir(parents=True)
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(E / 'key.pem'),
    '-out', str(E / 'cert.pem'), '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)

CF.write_text("tunnel: e2e-tunnel\ncredentials-file: /nonexistent/e2e.json\ningress:\n"
              "  - hostname: app.example.test\n    service: http://localhost:8000\n  - service: http_status:404\n")
(G / 'config.yml').write_text(
    f"service_user: root\nmain_domain: example.test\ndefault_storage: {G/'storage'}\ncloudflare_config: {CF}\n"
    f"ats_home: {G/'home'}\ncloudflared_service: ats-e2e-tunnel\nservice_group: root\n")
(G / 'config.yml').chmod(0o600)

base = {'PATH': f"{HERE/'fakebin'}:/usr/local/bin:/usr/bin:/bin", 'HOME': '/root', 'LANG': 'C.UTF-8',
        'E2E_STATE': str(STATE), 'E2E_UNITS': str(UNITS), 'E2E_CF': str(CF), 'E2E_TUNNEL_UNIT': 'ats-e2e-tunnel.service',
        'E2E_CERT': str(E / 'cert.pem'), 'E2E_KEY': str(E / 'key.pem'), 'E2E_TLS_PORT': str(TLS_PORT),
        'SSL_CERT_FILE': str(E / 'cert.pem')}
genv = dict(base, ATS_CONFIG_FILE=str(G / 'config.yml'), ATS_CLUSTER_DB=str(G / 'cluster.sqlite3'), ATS_REMOTE_PORT=str(PORT),
            E2E_ADAPTER=str(MON / 'remote_host.py'), E2E_ADAPTER_STATE=str(G / 'adapter'), ATS_CLOUDFLARE_CONFIG=str(CF),
            REHEARSAL_ATS=str(ATS))
lenv = dict(base, ATS_CLUSTER_DB=str(L / 'cluster.sqlite3'), ATS_MODULE_DIR=str(ATS), ATS_SECURITY_DB=str(L / 'security.sqlite3'),
            ATS_COOKIE_SECURE='false', ATS_ACCESS_PASSWORD='e2e-password', ATS_HOME=str(L / 'home'), ATS_MONITOR_JOBS_DIR=str(L / 'jobs'),
            ATS_CLI=f'{SYSPY} {ATS}/app.py', MONITOR_BIND=f'127.0.0.1:{MON_PORT}', GUNICORN_WORKER='gevent')

try:
    step('Start the tunnel simulator (TLS on 443, routes strictly by the tunnel YAML)')
    p = subprocess.Popen([SYSPY, str(HERE / 'tunnel_sim.py')], env=genv, stdout=open(E / 'tunnel.log', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
    procs.append(p)
    check(wait_port(TLS_PORT), 'tunnel simulator is listening on 443')

    step('Configure the Global exactly as an operator would (server configure)')
    rc, out, err = sh([SYSPY, str(ATS / 'app.py'), 'server', 'configure', '--role', 'global', '--name', 'E2E Global', '--api-domain', 'https://localhost'], genv)
    check(rc == 0, 'server configure --role global succeeds'); print(out.strip()[-300:], err.strip()[-300:])
    pairing_path = ATS / 'files' / 'pairing.json'
    check(pairing_path.is_file() and (pairing_path.stat().st_mode & 0o777) == 0o600, 'private pairing file exported (0600)')
    gnode = json.loads(pairing_path.read_text())
    sid = gnode['id']
    rc, out, err = sh([SYSPY, str(ATS / 'app.py'), '--api', 'services.list'], genv, stdin='{}')
    check(rc == 0 and '"ok": true' in out.replace('"ok":true', '"ok": true'), 'Global ATS CLI answers a headless services.list (creates its database)')

    step('doctor BEFORE setup: must fail with clear fixes, not stack traces')
    rc, out, err = sh([SYSPY, str(HERE / 'global_task.py'), 'doctor'], genv)
    print(out)
    check(rc == 1 and 'not installed' in out and 'server setup --apply' in out, 'doctor reports the missing service and the exact command')
    check('Traceback' not in out + err, 'no traceback')

    step('setup preview (read-only) on a fresh Global with no ats*.service unit (systemctl exits 1)')
    rc, out, err = sh([SYSPY, str(HERE / 'global_task.py'), 'plan'], genv)
    print(out[-900:], err[-500:])
    check(rc == 0 and '"route_change": true' in out, 'plan succeeds on a first install and reports a route change')
    check(not list(UNITS.iterdir()) and 'hostname: localhost' not in (G / 'cloudflared.yml').read_text(), 'preview changed nothing')

    step('setup --apply: unit file + Cloudflare route + real daemon + verification')
    rc, out, err = sh([SYSPY, str(HERE / 'global_task.py'), 'apply'], genv, timeout=300)
    print(out[-2200:], err[-1500:])
    check(rc == 0, 'apply succeeded')
    unit_name = f'ats-global-{sid}.service'
    unit_file = UNITS / unit_name
    check(unit_file.is_file(), 'systemd unit written: ' + unit_file.name)
    text = unit_file.read_text() if unit_file.is_file() else ''
    check('ATS_MONITOR_ADAPTER' in text and '--daemon' in text and 'Restart=always' in text, 'unit has adapter env, --daemon and Restart=always')
    check('secret' not in text.lower() and gnode['secret'] not in text, 'the passkey is not in the unit file')
    cfg = (G / 'cloudflared.yml').read_text()
    check('hostname: localhost' in cfg and '^/v1/request$' in cfg and 'http://127.0.0.1:%d' % PORT in cfg, 'tunnel route added for the API hostname')
    check('hostname: app.example.test' in cfg and 'http_status:404' in cfg, 'unrelated route and catch-all preserved')
    check(wait_port(PORT, 5), 'Global API daemon is listening on loopback')
    check('public_health' in out and 'verified' in out.split('public_health')[1][:40], 'public HTTPS check verified through the tunnel')
    check('Next: on the Local server' in out, 'summary tells the operator the next step')
    check((G / 'adapter' / 'security.sqlite3').parent.is_dir() and oct((G / 'adapter').stat().st_mode & 0o777) == '0o700', 'adapter state directory is private (0700)')

    step('doctor AFTER setup on the Global')
    rc, out, err = sh([SYSPY, str(HERE / 'global_task.py'), 'doctor'], genv)
    print(out)
    check(rc == 0, 'doctor finds no problems on the configured Global')

    step('Start the real Local Monitor (gunicorn + gevent websocket worker)')
    from_local = f"import sys;sys.path.insert(0,'{ATS}');import ats_cluster;s=ats_cluster.Store();s.configure('local','E2E Local',webhook='hooks.example.test')"
    rc, out, err = sh([VENV, '-c', from_local], lenv)
    check(rc == 0, 'Local identity configured: ' + err[-200:])
    mp = subprocess.Popen([VENV, '-m', 'gunicorn', '-c', 'gunicorn.conf.py', 'app:app'], cwd=MON, env=lenv,
                          stdout=open(E / 'monitor.log', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
    procs.append(mp)
    check(wait_port(MON_PORT), 'Monitor is listening')

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base_url = f'http://127.0.0.1:{MON_PORT}'

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    plain = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)

    def call(method, path, body=None, headers=None, form=None, opener_=None):
        data, hdrs = None, {'Origin': base_url, 'X-Requested-With': 'ats-monitor'}
        if body is not None:
            data, hdrs['Content-Type'] = json.dumps(body).encode(), 'application/json'
        if form is not None:
            data, hdrs['Content-Type'] = urllib.parse.urlencode(form).encode(), 'application/x-www-form-urlencoded'
        hdrs.update(headers or {})
        request = urllib.request.Request(base_url + path, data=data, headers=hdrs, method=method)
        try:
            with (opener_ or opener).open(request, timeout=90) as r:
                raw, status = r.read(), r.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, raw.decode('utf-8', 'replace')

    status, html = call('GET', '/login')
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    status, _ = call('POST', '/login', form={'password': 'e2e-password', 'csrf_token': token}, opener_=plain)
    check(status == 302, 'login succeeds')
    csrf = lambda: call('GET', '/api/settings')[1]['csrf_token']

    step('Pair the Global in Monitor with the exported pairing file')
    bundle = json.loads(pairing_path.read_text())
    status, body = call('POST', '/api/servers', {'id': bundle['id'], 'name': bundle['name'], 'domain': bundle['domain'], 'secret': bundle['secret']},
                        headers={'X-CSRF-Token': csrf()})
    check(status == 200, f'pairing verified over real HTTPS through the tunnel: {status} {body}')
    status, body = call('GET', '/api/servers')
    check(any(s['id'] == sid and s['connected'] for s in body['servers']), 'server listed as enabled')
    check(bundle['secret'] not in json.dumps(body), 'the passkey is never returned by the API')
    status, body = call('GET', f'/api/servers/{sid}/health')
    check(status == 200 and body['management_ready'] is True, 'health: reachable and management adapter ready')

    step('Real management reads/writes on the Global through Local Monitor')
    target = {'X-ATS-Target': sid}
    for path in ('/api/manage/services', '/api/manage/settings', '/api/overview', '/api/logs', '/api/stats', '/api/manage/backups'):
        status, body = call('GET', path, headers=target)
        check(status == 200, f'GET {path} via Global -> {status}' + ('' if status == 200 else f' {str(body)[:200]}'))
    status, body = call('POST', '/api/manage/services/nope/action', {'action': 'restart'}, headers={**target, 'X-CSRF-Token': csrf()})
    check(status in (400, 404), f'service action on the Global reaches the Global ATS (unknown service rejected): {status} {str(body)[:120]}')
    status, body = call('GET', '/api/manage/services', headers={'X-ATS-Target': 'f' * 32})
    check(status == 503 and 'No operation was sent to Local' in str(body), 'unknown server fails closed, never falls back to Local')

    step('Wrong key -> a precise explanation (rotate on Global without telling Local)')
    rc, out, err = sh([SYSPY, str(ATS / 'app.py'), 'server', 'rotate'], genv)
    check(rc == 0, 'server rotate on the Global'); print(out.strip()[-200:], err.strip()[-200:])
    status, body = call('GET', '/api/manage/services', headers=target)
    check(status == 503 and 'rejected the server ID or passkey' in str(body), f'explained: {str(body)[:230]}')
    status, body = call('GET', f'/api/servers/{sid}/health')
    check(status == 503 and 'passkey' in str(body.get('error')), 'health endpoint explains it too')

    step('Update ID and passkey with the new pairing file (same ID, new key)')
    new = json.loads(pairing_path.read_text())
    check(new['secret'] != bundle['secret'] and new['id'] == sid, 'pairing file refreshed with the new key')
    status, body = call('POST', f'/api/servers/{sid}/credentials', {'id': new['id'], 'name': new['name'], 'domain': new['domain'], 'secret': new['secret']},
                        headers={'X-CSRF-Token': csrf()})
    check(status == 200, f'credentials replaced: {status} {body}')
    status, body = call('GET', '/api/manage/services', headers=target)
    check(status == 200, 'management works again with the new key, no daemon restart needed')

    step('Global reinstalled: brand-new ID AND key; update the existing Local entry')
    # map a repository on Local so we can prove explicit webhook mappings follow the new ID
    mapping = f"import sys;sys.path.insert(0,'{ATS}');import ats_cluster,secrets;s=ats_cluster.Store();s.mapping('owner/repo','{sid}','svc','main',secrets.token_hex(32))"
    check(sh([VENV, '-c', mapping], lenv)[0] == 0, 'webhook mapping created on Local for the old ID')
    sh([SYSPY, str(HERE / 'fakebin' / 'systemctl'), 'stop', unit_name], genv)
    (G / 'cluster.sqlite3').unlink()
    shutil.rmtree(ATS / 'files')
    rc, out, err = sh([SYSPY, str(ATS / 'app.py'), 'server', 'configure', '--role', 'global', '--name', 'E2E Global', '--api-domain', 'https://localhost'], genv)
    check(rc == 0, 'server configure again (fresh identity)')
    fresh = json.loads(pairing_path.read_text())
    check(fresh['id'] != sid, f'identity changed: {sid[:8]}… -> {fresh["id"][:8]}…')
    sh([SYSPY, str(HERE / 'fakebin' / 'systemctl'), 'start', unit_name], genv)
    check(wait_port(PORT, 20), 'daemon restarted against the new registry')
    status, body = call('GET', '/api/manage/services', headers=target)
    check(status == 503, 'old saved ID now fails closed: ' + str(body)[:160])
    status, body = call('POST', f'/api/servers/{sid}/credentials', {'id': fresh['id'], 'name': fresh['name'], 'domain': fresh['domain'], 'secret': fresh['secret']},
                        headers={'X-CSRF-Token': csrf()})
    check(status == 200, f'ID + passkey replaced on the existing entry: {status} {body}')
    status, body = call('GET', '/api/manage/services', headers={'X-ATS-Target': fresh['id']})
    check(status == 200, 'new ID serves management requests')
    rc, out, err = sh([VENV, '-c', f"import sys;sys.path.insert(0,'{ATS}');import ats_cluster;s=ats_cluster.Store()\nwith s.db() as db: print([r['server_id'] for r in db.execute('select server_id from routes')])"], lenv)
    check(fresh['id'] in out and sid not in out, 'explicit webhook mapping migrated to the new ID')
    sid = fresh['id']
    target = {'X-ATS-Target': sid}

    step('Revoke from Local, then re-pair from the refreshed pairing file (no Global restart)')
    status, body = call('POST', f'/api/servers/{sid}/revoke', {}, headers={'X-CSRF-Token': csrf()})
    check(status == 200, f'revoke confirmed by the Global: {status} {body}')
    after = json.loads(pairing_path.read_text())
    check(after['secret'] != fresh['secret'], 'exported pairing file already holds the replacement key')
    status, body = call('POST', '/api/servers', {'id': after['id'], 'name': after['name'], 'domain': after['domain'], 'secret': after['secret']},
                        headers={'X-CSRF-Token': csrf()})
    check(status == 200, f're-paired with the refreshed file: {status} {body}')
    status, body = call('GET', '/api/manage/services', headers=target)
    check(status == 200, 'management works after re-pairing')


    step('GitHub webhook -> real Local receiver -> real Global (signed, explicit mapping)')
    (L / 'config.yml').write_text(
        f"service_user: root\nmain_domain: example.test\ndefault_storage: {L/'storage'}\ncloudflare_config: {L/'cloudflared.yml'}\n"
        f"ats_home: {L/'home'}\ncloudflared_service: ats-e2e-tunnel\nservice_group: root\n")
    (L / 'config.yml').chmod(0o600)
    (L / 'cloudflared.yml').write_text('tunnel: local\ningress:\n  - service: http_status:404\n')
    local_ats = dict(base, ATS_CONFIG_FILE=str(L / 'config.yml'), ATS_CLUSTER_DB=str(L / 'cluster.sqlite3'))
    # Create each ATS database, then a service on the Global and one on the Local for the mappings to target.
    check(sh([SYSPY, str(ATS / 'app.py'), '--api', 'services.list'], local_ats, stdin='{}')[0] == 0, 'Local ATS CLI initialised its database')
    def add_service(home, name, port):
        with sqlite3.connect(home / 'ats.db') as database:
            database.execute("INSERT INTO services(name,port,domain,storage_path,repo_url,branch) VALUES(?,?,?,?,?,'main')",
                             (name, port, f'{name}.example.test', str(E / 'storage'), 'https://github.com/owner/' + name + '.git'))
    add_service(G / 'home', 'hooksvc', 18080)
    add_service(L / 'home', 'localsvc', 18081)
    def map_with(argv, label):
        rc, out, err = sh([SYSPY, str(ATS / 'app.py'), 'server', 'map', *argv], local_ats)
        check(rc == 0, f'server map {label}: {(out + err).strip()[-110:]}')
        return out
    # A Global service gets a freshly generated secret that is shown once.
    out = map_with(['--repository', 'owner/hooksvc', '--server-id', sid, '--service', 'hooksvc', '--branch', 'main', '--generate-secret'], '--generate-secret (Global)')
    shown = re.search(r'Secret\s*: ([0-9a-f]{64})', out)
    check(bool(shown) and 'shown once' in out and 'webhook/hooksvc' in out, 'the generated secret and the GitHub payload URL are printed once')
    remote_secret = shown.group(1) if shown else ''
    # A Local service that already had an old-style per-service secret keeps working with no GitHub change.
    legacy_secret = os.urandom(32).hex()
    with sqlite3.connect(L / 'home' / 'ats.db') as database:
        database.execute('UPDATE services SET webhook_secret=? WHERE name=?', (legacy_secret, 'localsvc'))
    out = map_with(['--from-service', 'localsvc'], '--from-service (Local, existing secret)')
    check('needs no change' in out and legacy_secret not in out, 'the existing secret is reused and never echoed')
    local_secret = legacy_secret
    local_id = json.loads(sh([VENV, '-c', f"import sys,json;sys.path.insert(0,'{ATS}');import ats_cluster;print(json.dumps(ats_cluster.Store().node()['id']))"], lenv)[1])
    hook_daemon = subprocess.Popen([SYSPY, str(ATS / 'app.py'), '--daemon'], env=local_ats, cwd=str(ATS),
                                   stdout=open(E / 'local-daemon.log', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
    procs.append(hook_daemon)
    check(wait_port(HOOK_PORT, 60), 'Local daemon is listening for webhooks on 127.0.0.1:9999')

    def deliver(secret, repo='owner/hooksvc', service='hooksvc', event='push', ref='refs/heads/main', delivery=None, commit=None, signature=None, path=None):
        body = json.dumps({'repository': {'full_name': repo}, 'ref': ref, 'after': commit or os.urandom(20).hex(), 'deleted': False}).encode()
        mac = signature or 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        connection = http.client.HTTPConnection('127.0.0.1', HOOK_PORT, timeout=30)
        connection.request('POST', path or '/webhook/' + service, body, {'X-GitHub-Event': event, 'X-GitHub-Delivery': delivery or os.urandom(8).hex(),
                                                                         'X-Hub-Signature-256': mac, 'Content-Type': 'application/json'})
        response = connection.getresponse(); text = response.read().decode(); connection.close()
        return response.status, text, body
    def events(service):
        with sqlite3.connect(L / 'home' / 'ats.db') as database:
            return database.execute('SELECT result,message FROM webhook_events WHERE service_name=? ORDER BY id', (service,)).fetchall()
    def wait_event(service, count, seconds=60):
        end = time.time() + seconds
        while time.time() < end:
            rows = events(service)
            if len(rows) >= count and rows[count - 1][0] not in ('pending', 'running'):
                return rows[count - 1]
            time.sleep(0.5)
        return events(service)[count - 1] if len(events(service)) >= count else None

    status, text, _ = deliver(remote_secret, event='ping'); check(status == 200, f'GitHub ping accepted: {status} {text}')
    check(deliver(remote_secret, signature='sha256=' + '0' * 64)[0] == 401, 'a wrong signature is rejected (401)')
    check(deliver(remote_secret, signature='nonsense')[0] == 401, 'a malformed signature is rejected (401)')
    check(deliver(remote_secret, repo='owner/unmapped')[0] == 400, 'an unmapped repository is rejected (400)')
    check(deliver(remote_secret, ref='refs/heads/other')[0] == 400, 'a push to another branch is rejected (400)')
    check(deliver(remote_secret, path='/webhook/localsvc')[0] == 400, 'the wrong service path is rejected (400)')
    check(deliver(remote_secret, repo='owner/localsvc', service='localsvc')[0] == 401, "one repository's secret cannot trigger another's mapping (401)")
    check(not events('hooksvc'), 'rejected deliveries start nothing')

    status, text, body = deliver(remote_secret, delivery='delivery-1', commit='b' * 40)
    check(status == 202, f'valid push accepted before work starts: {status} {text}')
    result = wait_event('hooksvc', 1)
    check(result is not None and result[0] == 'dispatched', f'Local forwarded it to the Global (event recorded as dispatched): {result}')
    jobs = [json.loads(m.read_text()) for m in (G / 'adapter' / 'jobs').glob('*/meta.json')]
    check(any(j.get('op') == 'services.action' and j.get('name') == 'hooksvc' for j in jobs), 'the Global started its own update job for hooksvc (jobs: %s)' % [(j.get("op"), j.get("name")) for j in jobs])
    check(any(j.get('server_id') == sid for j in jobs), 'the job is stamped with the Global identity, not the Local')
    status, text, _ = deliver(remote_secret, delivery='delivery-1', commit='b' * 40)
    check(status == 200 and 'Duplicate' in text, f'an exact replay is not deployed twice: {status} {text}')
    check(len(events('hooksvc')) == 1, 'the replay created no second update')

    status, text, _ = deliver(local_secret, repo='owner/localsvc', service='localsvc', commit='c' * 40)
    check(status == 202, f'push mapped to the Local itself is accepted: {status}')
    result = wait_event('localsvc', 1)
    check(result is not None and result[0] in ('updated', 'failed'), f'Local update was attempted and its outcome recorded (never stuck pending): {result}')
    check(result is not None and 'Delivery failed or outcome unknown' not in result[1] and 'inspect the destination' in result[1], f'a failure states its real reason, not a generic message: {result and result[1][:140]}')

    call('POST', f'/api/servers/{sid}/disconnect', {}, headers={'X-CSRF-Token': csrf()})
    status, text, _ = deliver(remote_secret, commit='d' * 40)
    check(status == 503, f'a disconnected Global is not contacted: {status} {text}')
    check(len(events('hooksvc')) == 1, 'nothing was dispatched while disconnected')
    call('POST', f'/api/servers/{sid}/reconnect', {}, headers={'X-CSRF-Token': csrf()})
    status, text, _ = deliver(remote_secret, commit='e' * 40)
    check(status == 202 and wait_event('hooksvc', 2) and wait_event('hooksvc', 2)[0] == 'dispatched', 'after reconnecting, deliveries are forwarded again')
    probe = http.client.HTTPConnection('127.0.0.1', HOOK_PORT, timeout=10); probe.request('GET', '/webhook/hooksvc')
    check(probe.getresponse().status == 405, 'GET is refused with 405'); probe.close()
    os.killpg(hook_daemon.pid, signal.SIGTERM)

    step('Failure explanations: tunnel route removed / daemon stopped / tunnel down')
    original = CF.read_text()
    import yaml
    document = yaml.safe_load(original)
    document['ingress'] = [r for r in document['ingress'] if r.get('hostname') != 'localhost']
    CF.write_text(yaml.safe_dump(document, sort_keys=False))
    status, body = call('GET', f'/api/servers/{sid}/health')
    check(status == 503 and '/v1/request route' in str(body), 'missing tunnel route is named: ' + str(body.get('error'))[:140])
    CF.write_text(original)
    sh([SYSPY, str(HERE / 'fakebin' / 'systemctl'), 'stop', unit_name], genv)
    time.sleep(1)
    status, body = call('GET', f'/api/servers/{sid}/health')
    check(status == 503 and 'unreachable through its tunnel' in str(body), 'stopped daemon behind a live tunnel is named: ' + str(body.get('error'))[:140])
    tp = procs[0]
    tp.send_signal(signal.SIGTERM); tp.wait(10)
    status, body = call('GET', f'/api/servers/{sid}/health')
    check(status == 503 and 'refused the connection' in str(body), 'dead tunnel is named: ' + str(body.get('error'))[:140])

    step('doctor on Local')
    rc, out, err = sh([VENV, str(ATS / 'app.py'), 'server', 'doctor'], dict(lenv, ATS_CONFIG_FILE=str(G / 'config.yml')))
    print(out[-1200:], err[-400:])
    check('E2E Global' in out and 'refused the connection' in out, 'Local doctor lists the Global with the cause')
finally:
    for p in procs:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    for pidfile in (STATE / 'run').glob('*.pid') if (STATE / 'run').exists() else []:
        try:
            os.kill(int(pidfile.read_text()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
    shutil.rmtree(ATS / 'files', ignore_errors=True)
    if not KEEP:
        shutil.rmtree(E, ignore_errors=True)
print('\n' + ('ALL REHEARSAL CHECKS PASSED' if not failures else f'{len(failures)} CHECK(S) FAILED:\n  - ' + '\n  - '.join(failures)))
sys.exit(1 if failures else 0)
