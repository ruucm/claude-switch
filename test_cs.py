#!/usr/bin/env python3
"""Tests for cs.py — run against a fake HOME and a fake API server (token rotation · single-use refresh tokens ·
User-Agent check · per-token organizations · per-account reset times · usage call counting · 429 + Retry-After).
The real login files are never touched.

  python3 test_cs.py
"""
import contextlib
import datetime
import fcntl
import importlib.util
import json
import os
import pty
import re
import secrets
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CS = os.path.join(HERE, 'cs.py')
A, B = 'first.jay@example.com', 'first.joe@example.com'
ORG_T = '7c1e2f0a-1111-4222-8333-944455556666'  # team organization that jay's email also belongs to


class State:
    """token → (email, organization). Without an organization the email's personal organization 'o-<email>' is used."""
    def __init__(self):
        self.lock = threading.Lock()
        self.at, self.rt = {}, {}
        self.refresh_calls = 0
        self.profile_fail = False
        self.usage = {}
        self.extra = {}
        self.orgs = {}
        self.issued = []
        self.t0 = time.time()  # reference for reset times — the same offset gives every account the same time
        self.resets = {}  # (email, org) or email → (seconds until the 5-hour reset, seconds until the weekly reset) · None = no reset
        self.usage_calls = {}  # (email, org) → number of usage lookups
        self.limited = {}  # (email, org) → Retry-After seconds — usage lookups answer 429

    def issue(self, email, org=None):
        who = (email, org or 'o-' + email)
        at, rt = 'at-' + secrets.token_hex(12), 'rt-' + secrets.token_hex(12)
        with self.lock:
            self.at[at] = who
            self.rt[rt] = who
            self.issued += [at, rt]
        return at, rt

    def revoke(self, email):
        with self.lock:
            for d in (self.at, self.rt):
                for k in [k for k, v in d.items() if v[0] == email]:
                    del d[k]

    def org_json(self, who):
        meta = self.orgs.get(who[1]) or {}
        return {'uuid': who[1], 'name': meta.get('name', who[0] + "'s Organization"),
                'organization_type': meta.get('type', 'claude_max')}


S = State()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj=None, raw=None, headers=None):
        b = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain' if raw is not None else 'application/json')
        self.send_header('Content-Length', str(len(b)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _ua_ok(self):
        if 'claude-cli' not in (self.headers.get('User-Agent') or ''):
            self._send(403, raw=b'error code: 1010\n')  # like Cloudflare
            return False
        return True

    def _who(self):
        auth = self.headers.get('Authorization') or ''
        return S.at.get(auth[7:]) if auth.startswith('Bearer ') else None

    def do_GET(self):
        if not self._ua_ok():
            return
        who = self._who()
        if self.path.startswith('/api/oauth/usage'):
            if not who:
                return self._send(401, {'error': 'unauthorized'})
            with S.lock:
                S.usage_calls[who] = S.usage_calls.get(who, 0) + 1
            if who in S.limited:
                return self._send(429, {'error': {'type': 'rate_limit_error'}},
                                  headers={'Retry-After': str(S.limited[who])})
            ses, wk, fb = S.usage.get(who) or S.usage.get(who[0]) or (10, 20, 30)
            ses_in, wk_in = S.resets.get(who) or S.resets.get(who[0]) or (3 * 3600, 3 * 86400)
            ses_at = iso_at(None if ses_in is None else S.t0 + ses_in)
            wk_at = iso_at(None if wk_in is None else S.t0 + wk_in)
            limits = [{'kind': 'session', 'percent': ses, 'resets_at': ses_at},
                      {'kind': 'weekly_all', 'percent': wk, 'resets_at': wk_at}]
            if fb is not None:
                limits.append({'kind': 'weekly_scoped', 'percent': fb, 'resets_at': wk_at,
                               'scope': {'model': {'display_name': 'Fable'}}})
            return self._send(200, {'limits': limits, 'extra_usage': {'is_enabled': bool(S.extra.get(who[1]))}})
        if self.path.startswith('/api/oauth/profile'):
            if S.profile_fail or not who:
                return self._send(401, {'error': 'unauthorized'})
            return self._send(200, {'account': {'email': who[0], 'uuid': 'u-' + who[0]},
                                    'organization': S.org_json(who)})
        self._send(404, {})

    def do_POST(self):
        if not self._ua_ok():
            return
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or b'{}')
        if self.path.startswith('/v1/oauth/token'):
            with S.lock:
                S.refresh_calls += 1
                who = S.rt.pop(body.get('refresh_token'), None)  # single use
            if who is None:
                return self._send(400, {'error': 'invalid_grant', 'error_description': 'Refresh token not found or invalid'})
            at, rt = S.issue(*who)
            return self._send(200, {'access_token': at, 'refresh_token': rt, 'expires_in': 28800,
                                    'refresh_token_expires_in': 2592000, 'scope': body.get('scope', ''),
                                    'account': {'email_address': who[0]},
                                    'organization': {'uuid': who[1], 'name': S.org_json(who)['name']}})
        self._send(404, {})


FAILS = []


def iso_at(t):
    return None if t is None else datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat()


def table_rows(out):
    """Table rows → [(number, label, is current)]."""
    return [(m.group(2), m.group(3), m.group(1) == '▶')
            for m in re.finditer(r'^(▶| )\s+(\d+)\s+(\S+)\s', out, re.M)]


ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')


def strip_ansi(s):
    return ANSI_RE.sub('', s).replace('\r\n', '\n').replace('\r', '')


def dwidth(s):
    return sum(2 if unicodedata.east_asian_width(ch) in ('W', 'F') else 1 for ch in s)


def screen_rows(frame):
    """Live-screen table rows → [(cursor row?, current account?, number, label)]."""
    return [(m.group(1) == '❯', m.group(2) == '▶', m.group(3), m.group(4))
            for m in re.finditer(r'^([❯ ]) {2}([▶ ]) {2}(\d+)\s+(\S+)', frame, re.M)]


def row_line(frame, name):
    return next((ln for ln in frame.split('\n') if re.match(r'^[❯ ] {2}[▶ ] {2}\d+\s+' + re.escape(name) + r'\s', ln)), '')


class Tui:
    """Runs cs as a live screen on a fake terminal (pty) — a real controlling terminal, so Ctrl-C and resize signals work."""

    def __init__(self, env, cols=130, rows=40, args=()):
        self.master, slave = pty.openpty()
        self.resize(cols, rows, fd=slave)
        boot = ('import os, sys, fcntl, termios; os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0); '
                f'os.execv(sys.executable, [sys.executable, "-I", {CS!r}] + {list(args)!r})')
        self.p = subprocess.Popen([sys.executable, '-I', '-c', boot], env=env,
                                  stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        self.raw = b''

    def resize(self, cols, rows=40, fd=None):
        fcntl.ioctl(self.master if fd is None else fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

    def pump(self, timeout=0.1):
        r, _, _ = select.select([self.master], [], [], timeout)
        if not r:
            return False
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            return False
        self.raw += chunk
        return bool(chunk)

    def frame(self):
        """The last fully drawn frame (\\x1b[H … \\x1b[J)."""
        t = self.raw.decode('utf-8', 'replace')
        end = t.rfind('\x1b[J')
        start = t.rfind('\x1b[H', 0, end) if end >= 0 else -1
        return strip_ansi(t[start + 3:end]) if start >= 0 else ''

    def wait(self, pred, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            f = self.frame()
            if f and pred(f):
                return f
            if not self.pump(0.1) and self.p.poll() is not None:
                return None
        return None

    def idle(self, sec):
        deadline = time.time() + sec
        while time.time() < deadline:
            self.pump(0.1)

    def send(self, s):
        os.write(self.master, s.encode() if isinstance(s, str) else s)

    def finish(self, timeout=30):
        deadline = time.time() + timeout
        while self.p.poll() is None and time.time() < deadline:
            self.pump(0.1)
        while self.pump(0.1):
            pass
        if self.p.poll() is None:
            self.p.kill()
            self.p.wait()
        with contextlib.suppress(OSError):
            os.close(self.master)
        return self.p.returncode, self.raw.decode('utf-8', 'replace')


def check(cond, msg):
    print(('  ok   ' if cond else '  FAIL ') + msg)
    if not cond:
        FAILS.append(msg)


def jload(p):
    with open(p, encoding='utf-8') as f:
        return json.load(f)


def write_live(home, email, at, rt, *, expires_in_s=8 * 3600, with_email=True):
    now = int(time.time() * 1000)
    cred = {'claudeAiOauth': {'accessToken': at, 'refreshToken': rt, 'expiresAt': now + expires_in_s * 1000,
                              'scopes': ['user:inference', 'user:profile'], 'subscriptionType': 'max',
                              'rateLimitTier': 'default_claude_max_20x', 'refreshTokenExpiresAt': now + 28 * 86400000,
                              'subscriptionTypeSource': 'sign_in'}}
    cp = os.path.join(home, '.claude', '.credentials.json')
    with open(cp, 'w') as f:
        f.write(json.dumps(cred, separators=(',', ':')))
    os.chmod(cp, 0o600)
    cfgp = os.path.join(home, '.claude.json')
    cfg = jload(cfgp) if os.path.exists(cfgp) else {'numStartups': 7, 'projects': {'/home/x': {'allowedTools': []}}}
    if with_email:
        cfg['oauthAccount'] = {'accountUuid': 'u-' + email, 'emailAddress': email, 'displayName': email.split('@')[0]}
    else:
        cfg.pop('oauthAccount', None)
    with open(cfgp, 'w') as f:
        f.write(json.dumps(cfg, indent=2, ensure_ascii=False))
    os.chmod(cfgp, 0o600)


def write_cred_only(home, at, rt, *, sub='max', tier='default_claude_max_20x'):
    """Only the login file changes, like when Claude refreshes its own token (.claude.json stays)."""
    now = int(time.time() * 1000)
    cp = os.path.join(home, '.claude', '.credentials.json')
    with open(cp, 'w') as f:
        f.write(json.dumps({'claudeAiOauth': {'accessToken': at, 'refreshToken': rt, 'expiresAt': now + 8 * 3600000,
                                              'scopes': ['user:inference', 'user:profile'], 'subscriptionType': sub,
                                              'rateLimitTier': tier}}, separators=(',', ':')))
    os.chmod(cp, 0o600)


def live(home):
    return jload(os.path.join(home, '.claude', '.credentials.json'))['claudeAiOauth']


def vault(home, email):
    return jload(os.path.join(home, '.claude-accounts', 'accounts', email + '.json'))


def vault_files(home, email):
    d = os.path.join(home, '.claude-accounts', 'accounts')
    return sorted(f for f in os.listdir(d) if f.endswith('.json') and jload(os.path.join(d, f)).get('email') == email)


def vault_find(home, email, org):
    """(path, entry) — organization from the org field, else oauthAccount.organizationUuid."""
    d = os.path.join(home, '.claude-accounts', 'accounts')
    for f in vault_files(home, email):
        e = jload(os.path.join(d, f))
        if (e.get('org') or (e.get('oauthAccount') or {}).get('organizationUuid')) == org:
            return os.path.join(d, f), e
    return None, None


def main():
    srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{srv.server_port}'
    home = tempfile.mkdtemp(prefix='cs-home-')
    os.makedirs(os.path.join(home, '.claude'))
    fake = os.path.join(home, 'fake_claude.py')
    login_file = os.path.join(home, 'next_login.json')
    with open(fake, 'w') as f:
        f.write(f'''#!{sys.executable}
import json, os
d = json.load(open({login_file!r}))
cp = os.path.join(os.environ['HOME'], '.claude', '.credentials.json')
cred = json.load(open(cp)) if os.path.exists(cp) else {{}}
cred['claudeAiOauth'] = {{'accessToken': d['at'], 'refreshToken': d['rt'], 'expiresAt': d['exp'], 'scopes': ['user:inference', 'user:profile'], 'subscriptionType': d.get('sub', 'max'), 'rateLimitTier': d.get('tier', 'default_claude_max_20x')}}
open(cp, 'w').write(json.dumps(cred, separators=(',', ':')))
cfgp = os.path.join(os.environ['HOME'], '.claude.json')
cfg = json.load(open(cfgp))
acct = {{'accountUuid': 'u-' + d['email'], 'emailAddress': d['email']}}
if d.get('org'):
    acct.update(organizationUuid=d['org'], organizationName=d.get('org_name'), organizationType=d.get('org_type'))
cfg['oauthAccount'] = acct
open(cfgp, 'w').write(json.dumps(cfg, indent=2))
print('Login successful.')
''')
    os.chmod(fake, 0o755)
    env = dict(os.environ, HOME=home, CS_API_BASE=base, CS_TOKEN_URL=base + '/v1/oauth/token',
               CS_CLAUDE_BIN=fake, CS_LOCK_WAIT='2', NO_COLOR='1')
    outputs = []

    def run(*args):
        p = subprocess.run([sys.executable, '-I', CS, *args], env=env, capture_output=True, text=True, timeout=60)
        outputs.append(p.stdout + p.stderr)
        return p

    def run_tty(answer):
        """TERM=dumb terminal — asks for a number/name instead of showing the live screen."""
        master, slave = pty.openpty()
        p = subprocess.Popen([sys.executable, '-I', CS], env=dict(env, TERM='dumb'),
                             stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        out, sent, deadline = b'', False, time.time() + 30
        while time.time() < deadline:
            r, _, _ = select.select([master], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                if not sent and b'Switch to' in out:
                    os.write(master, (answer + '\n').encode())
                    sent = True
            elif p.poll() is not None:
                break
        p.wait(timeout=10)
        os.close(master)
        text = out.decode('utf-8', 'replace')
        outputs.append(text)
        return p.returncode, text

    S.usage = {A: (3, 60, 62), B: (100, 45, 30)}
    at_a, rt_a = S.issue(A)
    write_live(home, A, at_a, rt_a)
    lock = os.path.join(home, '.claude', '.oauth_refresh.lock')

    print('S1 first run — stores the current login (jay) + table')
    p = run()
    print(p.stdout)
    check(p.returncode == 0, 'exit 0')
    check('jay' in p.stdout and '97%' in p.stdout and '40%' in p.stdout and '38%' in p.stdout, 'table shows jay 97% · 40% · 38%')
    check(vault(home, A)['claudeAiOauth']['refreshToken'] == rt_a, 'vault holds the jay token')
    check(oct(os.stat(os.path.join(home, '.claude-accounts')).st_mode & 0o777) == '0o700', 'vault folder is 700')
    check(oct(os.stat(os.path.join(home, '.claude-accounts', 'accounts', A + '.json')).st_mode & 0o777) == '0o600', 'vault file is 600')

    print('S2 cs add — joe logs in')
    at_b, rt_b = S.issue(B)
    json.dump({'email': B, 'at': at_b, 'rt': rt_b, 'exp': int(time.time() * 1000) + 8 * 3600000}, open(login_file, 'w'))
    p = run('add')
    print(p.stdout + p.stderr)
    check(p.returncode == 0, 'exit 0')
    check(live(home)['refreshToken'] == rt_b, 'current login = joe')
    check(vault(home, B)['claudeAiOauth']['refreshToken'] == rt_b and vault(home, A)['claudeAiOauth']['refreshToken'] == rt_a, 'vault holds both jay and joe')
    check('jay' in p.stdout and 'joe' in p.stdout, 'table shows both')

    print('S3 cs jay — switch')
    p = run('jay')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and '✓ switched to jay' in p.stdout, 'switch message')
    check(live(home)['refreshToken'] == rt_a and live(home)['accessToken'] == at_a, 'login file = jay token')
    cfg = jload(os.path.join(home, '.claude.json'))
    check(cfg['oauthAccount']['emailAddress'] == A and cfg.get('numStartups') == 7 and 'projects' in cfg, '.claude.json account = jay · other keys kept')
    raw = open(os.path.join(home, '.claude.json')).read()
    check('\n  "' in raw and not raw.endswith('\n'), '.claude.json keeps indent 2 · no trailing newline')
    check('\n' not in open(os.path.join(home, '.claude', '.credentials.json')).read(), 'login file stays single-line JSON')
    check(oct(os.stat(os.path.join(home, '.claude', '.credentials.json')).st_mode & 0o777) == '0o600', 'login file is 600')
    backups = sorted(os.listdir(os.path.join(home, '.claude-accounts', 'backup')))
    check(backups and jload(os.path.join(home, '.claude-accounts', 'backup', backups[-1]))['credentials']['claudeAiOauth']['refreshToken'] == rt_b, 'the outgoing login (joe) was backed up')
    check(not os.path.exists(lock) and not os.path.exists(home + '/.claude.lock') and not os.path.exists(home + '/.claude.json.lock'), 'all locks released')
    check(S.refresh_calls == 0, '0 refresh calls (token still valid)')

    print('S4 idle joe token expires → cs refreshes (rotates) it and stores the result')
    vb = vault(home, B)
    vb['claudeAiOauth']['expiresAt'] = int(time.time() * 1000) - 1000
    json.dump(vb, open(os.path.join(home, '.claude-accounts', 'accounts', B + '.json'), 'w'))
    p = run()
    print(p.stdout)
    nb = vault(home, B)['claudeAiOauth']
    check(S.refresh_calls == 1 and nb['refreshToken'] != rt_b and nb['refreshToken'] in S.rt, 'joe refreshed once · new refresh token stored')
    check(rt_b not in S.rt, 'old joe refresh token discarded by the server')
    check('0%' in p.stdout, 'joe shows 0% left on the 5-hour window')
    check(live(home)['refreshToken'] == rt_a, 'current login (jay) untouched')

    print('S5 Claude rotates the jay token → cs verifies via profile and stores it · never refreshes jay itself')
    at_a2, rt_a2 = S.issue(A)
    S.rt.pop(rt_a, None)
    write_live(home, A, at_a2, rt_a2)
    calls = S.refresh_calls
    p = run()
    check(vault(home, A)['claudeAiOauth']['refreshToken'] == rt_a2, 'vault jay = new token')
    check(S.refresh_calls == calls, '0 refresh calls for the current login')

    print('S6 Claude is refreshing (lock held) → gives up after waiting · a stale lock is removed and the switch goes through')
    os.mkdir(lock)
    p = run('joe')
    print(p.stdout + p.stderr)
    check(p.returncode == 1 and 'refreshing its token' in p.stderr, 'lock held → no switch, explanation')
    check(live(home)['refreshToken'] == rt_a2, 'login unchanged')
    old = time.time() - 120
    os.utime(lock, (old, old))
    p = run('joe')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and live(home)['refreshToken'] == vault(home, B)['claudeAiOauth']['refreshToken'], 'stale lock removed · switched to joe')
    check(not os.path.exists(lock), 'lock released')
    check(vault(home, A)['claudeAiOauth']['refreshToken'] == rt_a2, 'outgoing jay stored with its newest token')

    print('S7 plain terminal (TERM=dumb) → number prompt instead of the live screen')
    rc, out = run_tty('1')
    print(out)
    check(rc == 0 and '✓ switched to jay' in out and live(home)['refreshToken'] == rt_a2, 'typing 1 → switched to jay')

    print('S8 joe login revoked server-side → shown as expired · switch refused')
    S.revoke(B)
    vb = vault(home, B)
    vb['claudeAiOauth']['expiresAt'] = int(time.time() * 1000) - 1000
    json.dump(vb, open(os.path.join(home, '.claude-accounts', 'accounts', B + '.json'), 'w'))
    p = run()
    print(p.stdout)
    check('login expired' in p.stdout and vault(home, B).get('dead'), 'joe shown as expired · marked in the vault')
    p = run('joe')
    check(p.returncode == 1 and 'expired' in p.stderr and live(home)['refreshToken'] == rt_a2, 'no switch to an expired account')

    print('S9 current login cannot be verified → neither refresh nor switch')
    S.profile_fail = True
    at_x, rt_x = 'at-unknown-' + secrets.token_hex(6), 'rt-unknown-' + secrets.token_hex(6)
    S.issued += [at_x, rt_x]
    write_live(home, A, at_x, rt_x, with_email=False)
    calls = S.refresh_calls
    p = run()
    print(p.stdout + p.stderr)
    check('Could not verify' in p.stdout and S.refresh_calls == calls, 'explanation · 0 refreshes')
    p = run('jay')
    check(p.returncode == 1 and live(home)['refreshToken'] == rt_x, 'switch refused · login unchanged')
    write_live(home, A, at_x, rt_x, with_email=True)  # the config file says jay, but it cannot be verified
    p = run()
    check(vault(home, A)['claudeAiOauth']['refreshToken'] == rt_a2, 'an unverified login does not overwrite the jay entry')
    S.profile_fail = False

    print('S10 logged out → cs jay restores the login')
    os.unlink(os.path.join(home, '.claude', '.credentials.json'))
    p = run('jay')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and live(home)['refreshToken'] == rt_a2, 'jay login restored')

    cfgp = os.path.join(home, '.claude.json')
    hour8 = lambda: int(time.time() * 1000) + 8 * 3600000  # noqa: E731

    print('S11 team seat of the same email (jay) — cs add → stored separately · personal jay untouched')
    S.orgs[ORG_T] = {'name': 'AIPM', 'type': 'claude_team'}
    S.usage[(A, ORG_T)] = (25, 50, None)
    S.extra[ORG_T] = True
    at_t, rt_t = S.issue(A, ORG_T)
    json.dump({'email': A, 'at': at_t, 'rt': rt_t, 'exp': hour8(), 'org': ORG_T, 'org_name': 'AIPM',
               'org_type': 'claude_team', 'sub': 'team', 'tier': 'default_claude_max_5x'}, open(login_file, 'w'))
    # ↑ a real team seat reported rateLimitTier default_claude_max_5x
    p = run('add')
    print(p.stdout + p.stderr)
    check(p.returncode == 0, 'exit 0')
    check(live(home)['refreshToken'] == rt_t, 'current login = jay team seat')
    check(len(vault_files(home, A)) == 2, f'2 vault files for jay {vault_files(home, A)}')
    _, pe = vault_find(home, A, 'o-' + A)
    _, te = vault_find(home, A, ORG_T)
    check(pe is not None and pe['claudeAiOauth']['refreshToken'] == rt_a2, 'personal jay entry untouched')
    check(te is not None and te['claudeAiOauth']['refreshToken'] == rt_t
          and te['oauthAccount'].get('organizationUuid') == ORG_T, 'team entry = team token · team organization info')
    check(re.search(r'\d+\s+jay-team\s+Team 5x · AIPM', p.stdout) is not None, 'table shows jay-team · Team 5x · AIPM')
    check('stored: jay-team' in p.stdout and '⚠ extra usage' in p.stdout, 'stored notice · team extra-usage warning')

    print('S12 cs jay ↔ cs team — switching between two organizations of one email')
    p = run('jay')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and '✓ switched to jay (' in p.stdout and live(home)['refreshToken'] == rt_a2, 'switched to jay (personal)')
    check(jload(cfgp)['oauthAccount'].get('organizationUuid') != ORG_T, '.claude.json = personal organization')
    p = run('team')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and '✓ switched to jay-team' in p.stdout and live(home)['refreshToken'] == rt_t, 'cs team → jay-team')
    cfg = jload(cfgp)
    check(cfg['oauthAccount'].get('organizationUuid') == ORG_T and cfg['oauthAccount'].get('organizationName') == 'AIPM'
          and cfg.get('numStartups') == 7, '.claude.json = team organization · other keys kept')
    check('team seat' in p.stdout and '⚠ extra usage on' in p.stdout, 'team policy · extra-usage notice')
    p = run(A)
    check(p.returncode == 1 and 'jay · jay-team' in p.stderr and live(home)['refreshToken'] == rt_t,
          'picking by email lists both names · nothing changed')

    print('S13 Claude rotates the team token → only the team entry updates · personal jay untouched')
    at_t2, rt_t2 = S.issue(A, ORG_T)
    S.rt.pop(rt_t, None)
    write_cred_only(home, at_t2, rt_t2, sub='team', tier='default_claude_max_5x')
    calls = S.refresh_calls
    p = run()
    print(p.stdout)
    check(vault_find(home, A, ORG_T)[1]['claudeAiOauth']['refreshToken'] == rt_t2, 'team entry = new token')
    check(vault_find(home, A, 'o-' + A)[1]['claudeAiOauth']['refreshToken'] == rt_a2, 'personal jay entry untouched')
    check(len(vault_files(home, A)) == 2 and S.refresh_calls == calls, 'still 2 files · 0 refresh calls')
    check(re.search(r'▶\s+\d+\s+jay-team', p.stdout) is not None, '▶ = jay-team row')

    print('S14 meant to add the team but picked the personal organization → personal jay gets the new token · no duplicate · notice')
    at_p3, rt_p3 = S.issue(A)
    json.dump({'email': A, 'at': at_p3, 'rt': rt_p3, 'exp': hour8(), 'org': 'o-' + A,
               'org_name': A + "'s Organization", 'org_type': 'claude_max'}, open(login_file, 'w'))
    p = run('add')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and 'was already stored' in p.stdout and 'choose the team' in p.stdout, 'already-stored notice + how to pick the team')
    check(len(vault_files(home, A)) == 2, 'still 2 vault files for jay')
    check(vault_find(home, A, 'o-' + A)[1]['claudeAiOauth']['refreshToken'] == rt_p3
          and vault_find(home, A, ORG_T)[1]['claudeAiOauth']['refreshToken'] == rt_t2, 'personal = new token · team untouched')

    print('S15 idle team seat token expires → cs refreshes (rotates) the team only')
    tp, te = vault_find(home, A, ORG_T)
    te['claudeAiOauth']['expiresAt'] = int(time.time() * 1000) - 1000
    json.dump(te, open(tp, 'w'))
    calls = S.refresh_calls
    p = run()
    print(p.stdout)
    nt = vault_find(home, A, ORG_T)[1]['claudeAiOauth']
    check(S.refresh_calls == calls + 1 and nt['refreshToken'] != rt_t2 and S.rt.get(nt['refreshToken']) == (A, ORG_T),
          'team refreshed once · the new refresh token belongs to the team organization')
    check(vault_find(home, A, 'o-' + A)[1]['claudeAiOauth']['refreshToken'] == rt_p3 and live(home)['refreshToken'] == rt_p3,
          'personal jay (current login) untouched')
    check(re.search(r'jay-team.*75%', p.stdout) is not None and '⚠ jay-team' not in p.stdout, 'table shows jay-team 75% · no warning')

    print('S16 legacy vault file (no org field · same shape as early vaults) → still read · no extra file after a rotation')
    C, OC = 'first.dean@example.com', '8ca87483-bfb1-4712-929a-c3ebfcc8c808'
    at_c, rt_c = S.issue(C, OC)
    cpath = os.path.join(home, '.claude-accounts', 'accounts', C + '.json')
    json.dump({'email': C, 'savedAt': int(time.time() * 1000),
               'claudeAiOauth': {'accessToken': at_c, 'refreshToken': rt_c, 'expiresAt': hour8(),
                                 'scopes': ['user:inference', 'user:profile'], 'subscriptionType': 'max',
                                 'rateLimitTier': 'default_claude_max_20x'},
               'oauthAccount': {'accountUuid': 'u-' + C, 'emailAddress': C, 'organizationUuid': OC,
                                'organizationType': 'claude_max'}}, open(cpath, 'w'))
    os.chmod(cpath, 0o600)
    p = run('dean')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and live(home)['refreshToken'] == rt_c, 'switched to dean')
    at_c2, rt_c2 = S.issue(C, OC)
    S.rt.pop(rt_c, None)
    write_cred_only(home, at_c2, rt_c2)
    p = run()
    print(p.stdout)
    check(vault_files(home, C) == [C + '.json'], 'still one dean file')
    check(jload(cpath)['claudeAiOauth']['refreshToken'] == rt_c2 and jload(cpath).get('org') == OC, 'legacy file got the new token · org field filled in')
    check([r[1] for r in table_rows(p.stdout)] == ['dean', 'jay', 'jay-team', 'joe'],
          'equal resets keep vault order (personal → team) · expired joe last')

    print('S17 soonest weekly reset first — table order · use-first hint · number switching follow the same order')
    S.t0 = time.time()
    S.resets = {(A, ORG_T): (1 * 3600, 5 * 3600), (A, 'o-' + A): (2 * 3600, 30 * 3600), (C, OC): (4 * 3600, 3 * 86400)}
    p = run()
    print(p.stdout)
    rows = table_rows(p.stdout)
    check([r[1] for r in rows] == ['jay-team', 'jay', 'dean', 'joe'] and rows[2][2],
          f'order = jay-team (weekly in 5h) · jay (30h) · dean (3d · ▶) · joe (expired) {rows}')
    check(re.search(r'jay-team .*in 5h', p.stdout) is not None and re.search(r'\n.*2\s+jay .*in 1d 6h', p.stdout) is not None,
          'time until the weekly reset shown')
    check('→ Use first: jay-team (#1) — its weekly reset is the soonest (in 5h), so the remaining 50% (= 14 on the 20x scale) disappears first' in p.stdout,
          'use first = #1 jay-team · reason · 5x seat also on the 20x scale')
    S.usage[(A, ORG_T)] = (25, 100, None)  # jay-team weekly used up
    p = run()
    print(p.stdout)
    check([r[1] for r in table_rows(p.stdout)] == ['jay-team', 'jay', 'dean', 'joe'], 'a used-up jay-team keeps its place in reset order')
    check('→ Use first: jay (#2) — the soonest weekly reset among the usable accounts' in p.stdout, 'use first = #2 jay, skipping the used-up #1')
    p = run('2')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and '✓ switched to jay (' in p.stdout and live(home)['refreshToken'] == rt_p3,
          'cs 2 (without a table) = #2 of the last table = jay')
    check('weekly 40% (resets in 1d 6h)' in p.stdout, 'switch message shows time until the weekly reset')
    p = run()
    check('→ Use first: jay (in use)' in p.stdout and re.search(r'▶\s+2\s+jay\s', p.stdout) is not None,
          'the current jay = use first')
    S.resets[(A, 'o-' + A)] = (2 * 3600, None)  # jay has no weekly reset yet (freshly refilled)
    p = run()
    print(p.stdout)
    rows = table_rows(p.stdout)
    check([r[1] for r in rows] == ['jay-team', 'dean', 'jay', 'joe'], f'jay with an unknown reset sorts after the known ones {rows}')
    check('→ Use first: dean (#2)' in p.stdout, 'use first = dean')
    rc, out = run_tty('2')
    print(out)
    check(rc == 0 and '✓ switched to dean' in out and live(home)['refreshToken'] == vault(home, C)['claudeAiOauth']['refreshToken'],
          'plain terminal: 2 → #2 of the table = dean')
    tp, te = vault_find(home, A, ORG_T)
    te['lastUsage']['weekly'] = [100, iso_at(time.time() - 60)]  # jay-team's weekly reset passed after the last table
    json.dump(te, open(tp, 'w'))
    p = run('1')
    print(p.stdout + p.stderr)
    check(p.returncode == 0 and 'already using dean' in p.stdout, 'a passed reset sorts last — cs 1 = the new #1 dean (already in use)')
    S.usage[A] = (100, 60, 62)            # jay 5-hour used up → frees in 2 hours
    S.usage[(C, OC)] = (10, 100, 30)      # dean weekly used up → frees in 3 days
    p = run()
    print(p.stdout)
    check(re.search(r'→ No account is usable right now — the first to free up is jay \(', p.stdout) is not None,
          'everything used up → the first account to free up is named')

    # ── live screen (cs · on a pty, like a real terminal) ──
    tenv = {k: v for k, v in env.items() if k != 'NO_COLOR'}  # colours on (including the inverted cursor row)
    tenv.update(TERM='xterm-256color', CS_INTERVAL='1', CS_IDLE_INTERVAL='4', CS_LIMIT_BACKOFF='30')
    locks = [os.path.join(home, '.claude', '.oauth_refresh.lock'), os.path.join(home, '.claude.lock'),
             os.path.join(home, '.claude.json.lock')]
    rt_jay = lambda: vault_find(home, A, 'o-' + A)[1]['claudeAiOauth']['refreshToken']  # noqa: E731
    rt_team = lambda: vault_find(home, A, ORG_T)[1]['claudeAiOauth']['refreshToken']  # noqa: E731
    rt_dean = lambda: vault(home, C)['claudeAiOauth']['refreshToken']  # noqa: E731
    four = lambda f: len(screen_rows(f)) == 4  # noqa: E731
    tuis = []

    def tui(**kw):
        t = Tui(tenv, **kw)
        tuis.append(t)
        return t

    print('S18 live screen — ↑↓ to pick, Enter to switch · usage keeps refreshing · q to quit')
    S.t0 = time.time()
    S.usage.update({A: (5, 60, 62), (C, OC): (10, 20, 30), (A, ORG_T): (25, 50, None)})
    S.resets = {(A, ORG_T): (1 * 3600, 5 * 3600), (A, 'o-' + A): (2 * 3600, 30 * 3600), (C, OC): (4 * 3600, 3 * 86400)}
    t = tui()
    f = t.wait(four) or ''
    print(f)
    rows = screen_rows(f)
    check([r[3] for r in rows] == ['jay-team', 'jay', 'dean', 'joe'], f'screen table = reset order {rows}')
    check(bool(rows) and rows[0][0] and rows[2][1], 'initial cursor = use-first account (#1 jay-team) · ▶ = dean')
    check('↑↓ select' in f and 'current account every 1s · others every 4s' in f and 'Fetched' in f, 'key help · refresh intervals · Fetched column')
    check('\x1b[7m' in t.raw.decode('utf-8', 'replace'), 'cursor row inverted')
    t.send('\x1b[B')
    check(t.wait(lambda f: any(r[0] and r[3] == 'jay' for r in screen_rows(f)), 10) is not None, '↓ → cursor on #2 jay')
    t.send('\r')
    f = t.wait(lambda f: '✓ switched to jay' in f and any(r[1] and r[3] == 'jay' for r in screen_rows(f)), 15)
    check(f is not None and live(home)['refreshToken'] == rt_jay(), 'Enter → switched to jay · ▶ moves to jay')
    S.usage[A] = (30, 60, 62)  # an agent is using jay — 5-hour left 95% → 70%
    f = t.wait(lambda f: '70%' in row_line(f, 'jay'), 10)
    check(f is not None, 'the current account (jay) refreshes while the screen is open (95% → 70%)')
    with S.lock:
        S.usage_calls.clear()
    t.idle(6.5)
    calls = dict(S.usage_calls)
    check(calls.get((A, 'o-' + A), 0) >= 5 and calls.get((C, OC), 0) <= 3,
          f'current account every 1s · idle accounts every 4s (jay {calls.get((A, "o-" + A), 0)} · dean {calls.get((C, OC), 0)})')
    check(calls.get((B, 'o-' + B), 0) == 0, 'expired joe is never asked')
    t.send('q')
    rc, raw = t.finish()
    after = strip_ansi(raw.split('\x1b[?1049l')[-1])
    print(after)
    check(rc == 0 and '\x1b[?1049l' in raw and '\x1b[?25h' in raw, 'exit 0 · alternate screen and cursor restored')
    check('Claude accounts · remaining usage' in after and '✓ switched to jay' in after
          and [r[1] for r in table_rows(after)] == ['jay-team', 'jay', 'dean', 'joe'], 'last table and switch result left on the normal screen')
    check(not any(os.path.exists(x) for x in locks), 'all locks released')

    print('S19 another cs runs immediately while the screen is open (no vault lock held) · ▶ follows · ㅂ (Korean-layout q)')
    t = tui()
    t.wait(four)
    t0 = time.monotonic()
    p = run('dean')
    took = time.monotonic() - t0
    check(p.returncode == 0 and took < 5 and live(home)['refreshToken'] == rt_dean(), f'cs dean from another terminal finished in {took:.1f}s')
    check(t.wait(lambda f: any(r[1] and r[3] == 'dean' for r in screen_rows(f)), 10) is not None, '▶ on the screen moves to dean')
    t.send('ㅂ')
    rc, _ = t.finish()
    check(rc == 0, 'ㅂ quits')

    print('S20 usage rate limit (429 · Retry-After) — only that account waits · r respects the wait')
    S.limited[(A, ORG_T)] = 30
    t = tui()
    f = t.wait(lambda f: 'rate limited' in row_line(f, 'jay-team'), 15)
    print(f)
    check(f is not None, 'jay-team row = last value + rate limited')
    with S.lock:
        S.usage_calls.clear()
    t.idle(4)
    t.send('r')
    check(t.wait(lambda f: 'rate limited, still waiting: jay-team' in f, 5) is not None, 'r → says the limited account keeps waiting')
    t.idle(2)
    calls = dict(S.usage_calls)
    check(calls.get((A, ORG_T), 0) == 0 and calls.get((C, OC), 0) >= 4,
          f'jay-team not asked · current account dean keeps refreshing ({calls.get((A, ORG_T), 0)} · {calls.get((C, OC), 0)})')
    t.send('q')
    rc, _ = t.finish()
    check(rc == 0, 'quit')
    del S.limited[(A, ORG_T)]

    print('S21 current account hits a limit — bell · warning · cursor jumps to the next usable account (Enter switches) · Esc')
    t = tui()
    t.wait(four)
    t.send('3')
    check(t.wait(lambda f: any(r[0] and r[3] == 'dean' for r in screen_rows(f)), 5) is not None, '3 → cursor on #3 dean (current)')
    S.usage[(C, OC)] = (100, 20, 30)  # dean 5-hour used up
    f = t.wait(lambda f: '⚠ the current account dean has hit a limit' in f, 10)
    print(f)
    check(f is not None and 'Enter switches to jay-team' in f
          and any(r[0] and r[3] == 'jay-team' for r in screen_rows(f)), 'warning · cursor on jay-team')
    check('\a' in t.raw.decode('utf-8', 'replace'), 'one bell')
    check(live(home)['refreshToken'] == rt_dean(), 'nothing switched by itself')
    t.send('\r')
    f = t.wait(lambda f: '✓ switched to jay-team' in f, 15)
    check(f is not None and live(home)['refreshToken'] == rt_team(), 'Enter → switched to jay-team')
    t.send('\x1b')
    rc, _ = t.finish()
    check(rc == 0, 'Esc quits')
    S.usage[(C, OC)] = (10, 20, 30)

    print('S22 narrow terminal (80 columns) drops columns · widening brings them back · Ctrl-C quits')
    t = tui(cols=80)
    f = t.wait(four) or ''
    print(f)
    table = [ln for ln in f.split('\n') if re.match(r'^[❯ ] {2}[▶ ] {2}(\d+|#)', ln) or 'Plan' in ln or 'Total' in ln]
    check('Fetched' not in f and 'Fable weekly' not in f, 'narrow → Fetched and Fable columns dropped')
    check(bool(table) and max(dwidth(ln) for ln in table) <= 80, f'table lines fit in 80 columns (max {max([dwidth(x) for x in table] + [0])})')
    t.resize(130)
    check(t.wait(lambda f: 'Fetched' in f and 'Fable weekly' in f, 10) is not None, 'widened to 130 → everything back')
    t.send('\x03')
    rc, raw = t.finish()
    check(rc == 0 and raw.rfind('\x1b[?1049l') > raw.rfind('\x1b[?1049h'), 'Ctrl-C quits · screen restored')

    print('S23 SSH drops (SIGHUP) — finishes the running job and exits · no locks left · next cs runs right away')
    t = tui()
    t.wait(four)
    t.p.send_signal(signal.SIGHUP)
    rc, _ = t.finish()
    check(rc == 128 + signal.SIGHUP, f'exit code {rc}')
    check(not any(os.path.exists(x) for x in locks), 'all locks released')
    p = run()
    check(p.returncode == 0 and 'jay-team' in p.stdout, 'next cs runs right away')

    for t in tuis:
        if t.p.poll() is None:
            t.p.kill()
        outputs.append(t.raw.decode('utf-8', 'replace'))

    print('S24 Left/Total — one 20x week = 100 (a 5x seat ≈ 29) · Total row · ratio override · unknown plans left out')
    S.usage[(A, ORG_T)] = (25, 40, None)  # jay-team weekly 60% left → 0.6 × 100/3.5 = 17.1
    S.usage[A] = (30, 60, 62)             # jay weekly 40% left → 40
    S.usage[(C, OC)] = (10, 20, 30)       # dean weekly 80% left → 80

    def row(out, name):
        return next((ln for ln in out.split('\n') if re.match(r'^[▶ ]\s+\d+\s+' + re.escape(name) + r'\s', ln)), '')

    def total(out):
        return next((ln for ln in out.split('\n') if 'Total' in ln and '×' in ln), '').strip()

    p = run('ls')
    print(p.stdout)
    check(' 40 / 100' in row(p.stdout, 'jay') and ' 17 / 29' in row(p.stdout, 'jay-team')
          and ' 80 / 100' in row(p.stdout, 'dean'), 'per row left / total (jay 40/100 · jay-team 17/29 · dean 80/100)')
    check('login expired' in row(p.stdout, 'joe') and ' / ' not in row(p.stdout, 'joe'), 'expired joe has no amount')
    check('137 / 229' in total(p.stdout) and '= 1.4 × one 20x week' in total(p.stdout), f'total 137 / 229 · 1.4 × one 20x week ({total(p.stdout)})')
    check('a Team/Max 5x week ≈ 29 (20x ≈ 5x × 3.5 · measured estimate' in p.stdout, 'scale explanation line')
    check('remaining 60% (= 17 on the 20x scale) disappears first' in p.stdout, 'use-first hint for a 5x seat also on the 20x scale')
    p = subprocess.run([sys.executable, '-I', CS, 'ls'], env=dict(env, CS_WEEK_RATIO='4'),
                       capture_output=True, text=True, timeout=60)
    outputs.append(p.stdout + p.stderr)
    check(' 15 / 25' in row(p.stdout, 'jay-team') and '135 / 225' in total(p.stdout)
          and 'set by CS_WEEK_RATIO' in p.stdout, 'CS_WEEK_RATIO=4 → jay-team 15/25 · total 135/225')
    dp = os.path.join(home, '.claude-accounts', 'accounts', C + '.json')
    de = jload(dp)
    de['claudeAiOauth'].update(rateLimitTier='default_claude_pro', subscriptionType='pro')
    json.dump(de, open(dp, 'w'))
    p = run('ls')
    print(p.stdout)
    check(re.search(r'dean\s+Pro\s.*\s\?\s', row(p.stdout, 'dean')) is not None, 'unknown plan (Pro) = ?')
    check('57 / 129' in total(p.stdout) and 'dean: unknown plan, not counted' in total(p.stdout), f'dean left out of the total ({total(p.stdout)})')
    de = jload(dp)
    de['claudeAiOauth'].update(rateLimitTier='default_claude_max_20x', subscriptionType='max')
    json.dump(de, open(dp, 'w'))
    spec = importlib.util.spec_from_file_location('cs_under_test', CS)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    e5 = {'claudeAiOauth': {'rateLimitTier': 'default_claude_max_5x'}}
    now = time.time()
    check(m.week_amount(e5, {'weekly': [100, iso_at(now - 60)]}, now) == (100 / 3.5, 100 / 3.5)
          and m.week_amount(e5, {'weekly': [100, iso_at(now + 3600)]}, now)[0] == 0,
          'a stored value whose weekly reset has passed counts as full')
    check(m.amount_text(0.4) == '<1' and m.amount_text(17.14) == '17' and m.amount_text(0) == '0', 'amount text (<1 · 17 · 0)')

    # ── auto-switch ──
    aenv = dict(tenv, CS_AUTO_COOLDOWN='1')
    set_path = os.path.join(home, '.claude-accounts', 'settings.json')
    log_path = os.path.join(home, '.claude-accounts', 'auto-switch.log')

    def atui():
        t = Tui(aenv)
        tuis.append(t)
        return t

    def auto_log():
        try:
            with open(log_path, encoding='utf-8') as f:
                return f.read().splitlines()
        except OSError:
            return []

    def live_name(f):
        return next((r[3] for r in screen_rows(f) if r[1]), None)

    print('S25 auto-switch — cs auto on · the live screen leaves a draining account at the floor (1% left) · extra-usage accounts skipped · log · bell')
    S.t0 = time.time()
    S.resets = {(A, ORG_T): (3600, 5 * 3600), (A, 'o-' + A): (2 * 3600, 30 * 3600), (C, OC): (4 * 3600, 3 * 86400)}
    S.usage.update({A: (95, 60, 62), (C, OC): (10, 20, 30), (A, ORG_T): (25, 40, None)})
    S.extra[ORG_T] = True  # jay-team has extra usage on — first in the table, but auto-switch never goes there
    p = run('jay')
    check(p.returncode == 0 and live(home)['refreshToken'] == rt_jay(), 'start on jay (first in line after the skipped jay-team)')
    p = run('auto')
    check('Auto-switch off' in p.stdout, 'cs auto → off')
    p = run('auto', 'on')
    check('Auto-switch on' in p.stdout and 'no live cs screen is open' in p.stdout and jload(set_path).get('autoSwitch') is True,
          'cs auto on → on · warns that nothing moves without a screen · settings.json')
    t = atui()
    f = t.wait(lambda f: four(f) and '→ dean' in f, 20) or ''
    print(f)
    check('Auto-switch on — jay is first in line · when it runs low' in f and '→ dean' in f,
          'header: on · jay first in line · next is dean (extra-usage jay-team skipped)')
    p = run('ls')
    check('live cs screen (pid' in p.stdout, 'cs ls from another terminal → the live screen is in charge')
    check(live(home)['refreshToken'] == rt_jay(), '5% left → stays')
    bells = t.raw.count(b'\a')
    S.usage[A] = (99, 60, 62)  # jay 5-hour 1% left
    f = t.wait(lambda f: 'auto-switch: jay → dean' in f and live_name(f) == 'dean', 20) or ''
    print(f)
    check(bool(f) and live(home)['refreshToken'] == rt_dean(), 'jay at 1% → moved to dean')
    check(any('jay → dean (jay 5-hour 1% left)' in ln for ln in auto_log()), 'log file: jay → dean')
    check(t.raw.count(b'\a') > bells, 'bell')
    check('auto-switch log' in f, 'log shown on the screen')

    print('S26 first in line — once jay has enough quota again the screen moves back to it (its weekly reset comes first)')
    S.usage[A] = (96, 60, 62)  # jay 4% left — under AUTO_MIN: not worth moving onto
    t.idle(5)
    check(live(home)['refreshToken'] == rt_dean(), 'jay at 4% → stays on dean')
    S.usage[A] = (60, 60, 62)  # jay 5-hour refilled to 40% left
    f = t.wait(lambda f: 'auto-switch: dean → jay' in f and live_name(f) == 'jay', 20) or ''
    print(f)
    check(bool(f) and live(home)['refreshToken'] == rt_jay(), 'jay usable again → moved back to jay although dean was fine')
    check(any(re.search(r'dean → jay \(jay first in line · weekly resets in 1d [56]h\)', ln) for ln in auto_log()),
          'log file: dean → jay (jay first in line · weekly resets in 1d 6h)')

    print('S27 burn rate — moves before the floor when the next check would come too late')
    t.idle(2)  # let the screen see jay sitting at 60 a few times — the rate must come from the burn below (2%/0.5s = 240%/min)
    stop = threading.Event()

    def burn():
        u = 60
        while not stop.is_set() and u < 100:
            S.usage[A] = (u, 60, 62)
            u += 2
            time.sleep(0.5)

    th = threading.Thread(target=burn, daemon=True)
    th.start()
    f = t.wait(lambda f: 'auto-switch: jay → dean' in f and live_name(f) == 'dean', 30) or ''
    stop.set()
    S.usage[A] = (100, 60, 62)  # jay dry — stays idle until it refills
    th.join()
    print(f)
    last = next((ln for ln in reversed(auto_log()) if 'jay → dean' in ln), '')
    mm = re.search(r'jay 5-hour (\d+)% left · draining ([\d.]+)%/min', last)
    check(bool(f) and mm is not None and int(mm.group(1)) >= 5 and 100 <= float(mm.group(2)) <= 500,
          f'moved early from the burn rate (about 240%/min) ({last.split(chr(9))[-1] if last else "-"})')
    t.idle(3)
    check(live(home)['refreshToken'] == rt_dean(), 'login = dean, and it stays there while jay is dry')

    print('S28 nowhere to go — waits, then moves as soon as an account frees up')
    S.usage[(C, OC)] = (99, 20, 30)  # current dean 1% left · jay dry · jay-team extra usage · joe expired
    f = t.wait(lambda f: 'nowhere to go' in f, 20) or ''
    print(f)
    check(bool(f) and live(home)['refreshToken'] == rt_dean(), 'nowhere to go → stays · notice')
    S.usage[A] = (5, 60, 62)         # jay 5-hour refilled
    f = t.wait(lambda f: live_name(f) == 'jay' and 'auto-switch: dean → jay' in f, 30) or ''
    check(bool(f) and live(home)['refreshToken'] == rt_jay(), 'jay refilled → moved right away')

    print('S29 a turns it off → no move · ㅁ (Korean-layout a) turns it back on → moves')
    t.send('a')
    f = t.wait(lambda f: 'Auto-switch off' in f, 10) or ''
    check(bool(f) and jload(set_path).get('autoSwitch') is False, 'a → off · settings.json')
    S.usage[(C, OC)] = (10, 20, 30)  # dean refilled (somewhere to go)
    S.usage[A] = (99, 60, 62)        # current jay 1% left
    t.idle(5)
    check(live(home)['refreshToken'] == rt_jay(), 'off → stays even at 1%')
    t.send('ㅁ')
    f = t.wait(lambda f: 'auto-switch: jay → dean' in f and live_name(f) == 'dean', 20) or ''
    check(bool(f) and live(home)['refreshToken'] == rt_dean() and jload(set_path).get('autoSwitch') is True,
          'ㅁ → on → moves to dean right away')

    print('S30 two screens — only one is in charge; when it quits the other takes over · cs auto off')
    t2 = atui()
    f2 = t2.wait(lambda f: four(f) and 'another cs screen is in charge' in f, 20) or ''
    check(bool(f2), 'second screen: another cs screen is in charge (watch only)')
    t.send('q')
    rc, _ = t.finish()
    check(rc == 0, 'first screen quit')
    f2 = t2.wait(lambda f: 'Auto-switch on — dean is first in line' in f, 20) or ''
    check(bool(f2), 'second screen took over')
    S.usage[A] = (5, 60, 62)  # jay refilled — first in line again
    f2 = t2.wait(lambda f: 'auto-switch: dean → jay' in f, 20) or ''
    check(bool(f2) and live(home)['refreshToken'] == rt_jay(), 'the screen that took over moves back to jay')
    t2.send('q')
    rc, raw = t2.finish()
    after = strip_ansi(raw.split('\x1b[?1049l')[-1])
    check(rc == 0 and 'no live cs screen is open' in after, 'after quitting: on, but no screen is open')
    p = run('auto', 'off')
    check('Auto-switch off' in p.stdout and jload(set_path).get('autoSwitch') is False, 'cs auto off')
    check(oct(os.stat(set_path).st_mode & 0o777) == '0o600' and oct(os.stat(log_path).st_mode & 0o777) == '0o600',
          'settings and log files are 600')
    for x in (t, t2):
        outputs.append(x.raw.decode('utf-8', 'replace'))

    print('S31 decision functions — floor · burn rate · passed reset · picking the target and the preferred account')
    now = time.time()
    fut, past = iso_at(now + 3600), iso_at(now - 60)
    check(m.need_switch({'session': [99, fut], 'weekly': [10, fut]}, None, now) == '5-hour 1% left', '1% left → leave')
    check(m.need_switch({'session': [96, fut], 'weekly': [10, fut]}, None, now) is None, '4% left · rate unknown → stay')
    check((m.need_switch({'session': [96, fut], 'weekly': [10, fut]}, {'session': 3 / 60}, now) or '').endswith('draining 3.0%/min'),
          '4% left · 3%/min (dry before the next check in 60s) → leave')
    check(m.need_switch({'session': [96, fut], 'weekly': [10, fut]}, {'session': 2 / 60}, now) is None, '4% left · 2%/min → stay')
    check(m.need_switch({'session': [100, past], 'weekly': [10, fut]}, None, now) is None, 'used up but the reset passed → stay')
    check(m.need_switch({'session': [10, fut], 'weekly': [99.4, fut]}, None, now) == 'weekly 1% left', 'weekly 1% left → leave')
    mk = lambda em, org: {'email': em, 'org': org, 'claudeAiOauth': {'rateLimitTier': 'default_claude_max_20x'}}  # noqa: E731
    ents = [mk('x@a', 'o1'), mk('y@a', 'o2'), mk('z@a', 'o3'), mk('w@a', 'o4')]
    keys = [m.ekey(e) for e in ents]
    res = {keys[0]: {'usage': {'session': [10, fut], 'weekly': [10, fut], 'extra': True}},
           keys[1]: {'error': 'rate limited — retrying later'},
           keys[2]: {'usage': {'session': [96, fut], 'weekly': [10, fut]}},
           keys[3]: {'usage': {'session': [50, fut], 'weekly': [50, fut]}}}
    check(m.auto_target(ents, res, 'v@a#o9', now) is ents[3], 'target: skips extra usage · failed fetch · ≤5% left, takes the first that remains')
    check(m.auto_preferred(ents, res, 'v@a#o9', None, now) is ents[3], 'preferred (current not in the list): the same first usable account')
    check(m.auto_preferred(ents, res, keys[2], None, now) is ents[2], 'preferred: the current account at 4% is above the floor, so it stays')
    check(m.auto_preferred(ents, res, keys[3], None, now) is ents[3], 'preferred: the current account is first in line → no move')
    check(m.first_in_line_reason(ents[3], res, now) == 'first in line · weekly resets in 1h', 'reason text for a proactive move')
    wch = m.Watch()
    wch.live = 'k'
    for dt, ses in ((0, 50), (60, 52), (120, 56)):
        wch.note_sample('k', {'session': [ses, fut], 'weekly': [10, fut]}, 1000 + dt)
    check(abs(wch.rates('k').get('session', 0) * 60 - 4.0) < 1e-6 and 'weekly' not in wch.rates('k'),
          'burn rate = 4%/min over the last minute (faster than the 3%/min average) · unused weekly absent')
    wch.note_sample('k', {'session': [5, fut], 'weekly': [10, fut]}, 1180)
    check('session' not in wch.rates('k'), 'values from before a reset (used % went down) are ignored')

    print('S32 cs keep — runs inside tmux · survives a closed window (SIGHUP) · re-attaches · q ends it')
    tm = shutil.which('tmux')
    if not tm:
        print('  (tmux not installed — skipped)')
    else:
        tdir = tempfile.mkdtemp(prefix='cs-tmux-')
        kenv = {k: v for k, v in aenv.items() if k != 'TMUX'}
        kenv['TMUX_TMPDIR'] = tdir  # a tmux server just for this test

        def tmux(*a):
            return subprocess.run([tm, *a], env=kenv, capture_output=True, text=True, timeout=10)

        def until(pred, timeout=20):
            deadline = time.time() + timeout
            while time.time() < deadline:
                if pred():
                    return True
                time.sleep(0.2)
            return False

        k1 = Tui(kenv, args=['keep'])
        shown = until(lambda: 'Claude accounts · remaining usage' in tmux('capture-pane', '-p', '-t', 'cs').stdout)
        check(shown, 'cs keep → screen inside tmux session cs')
        k1.p.send_signal(signal.SIGHUP)  # like a dropped SSH session or a closed window
        k1.finish(10)
        time.sleep(1)
        check(tmux('has-session', '-t', 'cs').returncode == 0
              and 'Claude accounts · remaining usage' in tmux('capture-pane', '-p', '-t', 'cs').stdout,
              'cs keeps running inside tmux after the window closed')
        k2 = Tui(kenv, args=['keep'])
        check(until(lambda: tmux('list-clients', '-t', 'cs').stdout.strip() != ''), 'cs keep again → attached to that screen')
        tmux('send-keys', '-t', 'cs', 'q')
        check(until(lambda: tmux('has-session', '-t', 'cs').returncode != 0), 'q → cs ends → tmux session ends')
        k2.finish(10)
        tmux('kill-server')
        shutil.rmtree(tdir, ignore_errors=True)
        outputs.extend(x.raw.decode('utf-8', 'replace') for x in (k1, k2))

    print('S33 no token ever appears in the output')
    blob = '\n'.join(outputs)
    check(not any(t in blob for t in S.issued), '0 token strings')

    srv.shutdown()
    shutil.rmtree(home, ignore_errors=True)
    print()
    print('FAIL:', FAILS) if FAILS else print('all passed')
    return 1 if FAILS else 0


if __name__ == '__main__':
    sys.exit(main())
