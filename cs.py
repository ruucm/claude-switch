#!/usr/bin/env python3
"""cs — Claude subscription accounts: remaining usage at a glance + account switching.

Every `claude` process on this machine (including agents that drive Claude Code) runs on one login — the file
~/.claude/.credentials.json on Linux, the login keychain item "Claude Code-credentials" on macOS. cs keeps a copy of
that login per account in ~/.claude-accounts/, shows how much of each account's 5-hour and weekly limits is left, and
swaps the stored login to switch accounts.
An account is an email + organization. If the same email has a personal subscription and a Team/Enterprise
seat, both are kept separately — they show up as e.g. jay and jay-team.

  cs              In a terminal: a live screen that keeps refreshing usage (current account every minute,
                  the others every 5 minutes); ↑↓ to pick, Enter to switch. Outside a terminal: print the
                  table once (= cs ls). Rows are sorted by soonest weekly reset — whatever is left when the
                  weekly window resets is lost, so use the top row first. Row numbers follow the table order
                  and therefore change after a reset.
  cs <n|name>     Switch to that account
  cs add [email]  Log a new account in (claude auth login) and store it
  cs ls           Print the table once
  cs auto [on|off] Show, enable or disable auto-switch (same as pressing a on the live screen — it only runs
                  while a live screen is open)
  cs keep         Run the live screen inside tmux session 'cs' so it survives closed windows and dropped SSH
                  sessions (run it again to re-attach)
  cs help         This help

How it works (verified against the Claude CLI 2.1.310 binaries — Linux x64 and macOS arm64):
- Linux: before each API call the CLI compares the mtime of .credentials.json and re-reads the file when it changed
  → swapping the file moves even running agents to the new account from their next request.
- macOS: the login lives in the login keychain — service "Claude Code-credentials", account = $USER; the CLI reads it with
  `security find-generic-password … -w` and writes it with `security add-generic-password -U … -X <hex>`.
  .credentials.json is only the fallback the CLI writes when a keychain write fails hard; when it exists the CLI reads
  the keychain first and the file second. Keychain reads are cached for 30 s; before each API call the CLI re-checks
  the keychain (or, when a .credentials.json exists, that file's mtime) → cs writes the keychain item the same way and
  rewrites a leftover file as well, so running agents follow within about 30 s.
- Credential writes also take <config dir>/.storage-write.lock (proper-lockfile, stale after 15 s) → so does cs.
- CLAUDE_CONFIG_DIR moves .credentials.json, .claude.json and the locks, and suffixes the keychain service name with the
  first 8 hex digits of sha256(CLAUDE_CONFIG_DIR) → cs follows it.
- Token refresh takes ~/.claude/.oauth_refresh.lock and ~/.claude.lock; config saves take ~/.claude.json.lock
  (proper-lockfile directory locks) → cs takes the same locks in the same order before writing.
- A refresh token is single-use (rotated) → cs never refreshes the token of the account currently in use.
  Only idle accounts are refreshed, and the result is written to the vault immediately.
- The token endpoint (platform.claude.com) rejects Python's default User-Agent (Cloudflare 1010) → cs sends
  the CLI's User-Agent.
- A login token is bound to one organization. If the email belongs to several, the browser asks which one
  (the orgUUID login parameter is reserved for managed settings' forceLoginOrgUUID); the chosen organization
  is reported by /api/oauth/profile as organization.uuid. subscriptionType comes from organization_type
  (claude_max → max · claude_team → team · claude_enterprise → enterprise).
- Usage lookups (/api/oauth/usage) are rate limited too — on 429/403 the CLI honours Retry-After, otherwise
  it backs off 5 minutes (max 1 hour) for that token, and it only calls the endpoint on demand.
  → The live screen asks once a minute for the current account, every 5 minutes for idle ones, and backs
  off the same way when limited.
"""
import codecs
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import pwd
import queue
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time
import tty
import unicodedata
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HOME = os.path.expanduser('~')
CONFIG_DIR_ENV = os.environ.get('CLAUDE_CONFIG_DIR') or ''  # the CLI's config-home override (meant to be an absolute path)
CLAUDE_DIR = os.path.abspath(CONFIG_DIR_ENV) if CONFIG_DIR_ENV else os.path.join(HOME, '.claude')
CRED_PATH = os.path.join(CLAUDE_DIR, '.credentials.json')
CONFIG_PATH = os.path.join(CLAUDE_DIR if CONFIG_DIR_ENV else HOME, '.claude.json')  # .claude.json moves into CLAUDE_CONFIG_DIR
VAULT_DIR = os.environ.get('CS_VAULT_DIR') or os.path.join(HOME, '.claude-accounts')
ACCOUNTS_DIR = os.path.join(VAULT_DIR, 'accounts')
BACKUP_DIR = os.path.join(VAULT_DIR, 'backup')
API_BASE = os.environ.get('CS_API_BASE', 'https://api.anthropic.com')
TOKEN_URL = os.environ.get('CS_TOKEN_URL', 'https://platform.claude.com/v1/oauth/token')
CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e'  # Claude Code's public OAuth client id
OAUTH_BETA = 'oauth-2025-04-20'
DEFAULT_SCOPES = ['user:profile', 'user:inference', 'user:sessions:claude_code',
                  'user:mcp_servers', 'user:file_upload']
CLAUDE_BIN = (os.environ.get('CS_CLAUDE_BIN') or shutil.which('claude')
              or os.path.join(HOME, '.local', 'bin', 'claude'))
_ver = os.path.basename(os.path.realpath(CLAUDE_BIN))
if not re.fullmatch(r'\d+\.\d+\.\d+', _ver):
    _ver = '2.1.310'
USER_AGENT = f'claude-cli/{_ver} (external, cli)'
LOCK_WAIT_S = float(os.environ.get('CS_LOCK_WAIT', '20'))


def _env_s(name, default, low):
    try:
        return max(low, float(os.environ.get(name, default)))
    except ValueError:
        return float(default)


# How often the live screen re-fetches usage (seconds) — current account · idle accounts · after a 429/403
LIVE_EVERY = _env_s('CS_INTERVAL', 60, 1)
IDLE_EVERY = max(LIVE_EVERY, _env_s('CS_IDLE_INTERVAL', 300, 1))
LIMIT_BACKOFF = _env_s('CS_LIMIT_BACKOFF', 300, 1)  # like the Claude CLI: 5 minutes, doubling
LIMIT_BACKOFF_MAX = max(LIMIT_BACKOFF, 3600.0)

# Comparing weekly limits across accounts — the usage API only returns percentages (the limit_dollars fields exist
# but are null). The only official multipliers are for the 5-hour window (Max 5x / 20x = 5× / 20× Pro → 20x = 5x × 4).
# The weekly multiplier was never published; the default is a community measurement: Classmethod (2026-08-20)
# matched /usage weekly percentages of three accounts against local token logs priced at API rates and found
# 20x ≈ 5x × 3.5 (3.1–3.9 depending on method).
WEEK_RATIO = _env_s('CS_WEEK_RATIO', 3.5, 1)  # one 20x week = one 5x week × this
WEEK_RATIO_SRC = 'set by CS_WEEK_RATIO' if os.environ.get('CS_WEEK_RATIO') else 'measured estimate, no official figure'

# Auto-switch (press a on the live screen).
# 1. Keep the first-in-line account in use: whenever an account that sorts above the current one (its weekly
#    reset comes sooner) is usable, move there — otherwise the quota it still has is lost at its reset.
# 2. Leave a draining account just before it runs dry: a response that is in flight when the limit hits fails with
#    "session limit" and the thread has to be resumed by hand → move when ≤ AUTO_FLOOR % is left, or when the
#    recent burn rate says it will hit 0 before the next check (LIVE_EVERY).
# An account is only moved *into* when both its windows have more than AUTO_MIN % left, so cs never hops onto an
# account it would have to leave minutes later.
AUTO_FLOOR = _env_s('CS_AUTO_FLOOR', 1, 0)
AUTO_MIN = max(_env_s('CS_AUTO_MIN', 5, 0), AUTO_FLOOR)
AUTO_COOLDOWN = _env_s('CS_AUTO_COOLDOWN', 30, 1)  # seconds before auto-switch is evaluated again
SETTINGS_PATH = os.path.join(VAULT_DIR, 'settings.json')  # {"autoSwitch": true}
AUTO_LOCK_PATH = os.path.join(VAULT_DIR, 'auto.lock')      # only the live screen holding this lock switches
AUTO_LOG_PATH = os.path.join(VAULT_DIR, 'auto-switch.log')

# Same lock paths as the Claude CLI (lri · saveConfigWithLock · the secure-storage write lock)
REFRESH_LOCK = os.path.join(CLAUDE_DIR, '.oauth_refresh.lock')
LEGACY_LOCK = os.path.realpath(CLAUDE_DIR) + '.lock'
STORAGE_LOCK = os.path.join(CLAUDE_DIR, '.storage-write.lock')  # held by the CLI around every credential write
CONFIG_LOCK = CONFIG_PATH + '.lock'

DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
KEEP_BACKUPS = 30
TRANSIENT = ('warn', '_path')

COLOR = sys.stdout.isatty() and not os.environ.get('NO_COLOR')


class CsError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status, body, retry_after=None):
        super().__init__(f'HTTP {status}')
        self.status = status
        self.body = body
        self.retry_after = retry_after  # seconds (only when Retry-After was numeric)


class Dead(Exception):
    pass


def now_ms():
    return int(time.time() * 1000)


def local_dt(ts=None):
    """epoch seconds → local-time datetime (now when omitted). Times are shown in the machine's time zone (TZ)."""
    return datetime.datetime.now() if ts is None else datetime.datetime.fromtimestamp(ts)


def c(text, code):
    return f'\033[{code}m{text}\033[0m' if COLOR else text


# ── files · locks ─────────────────────────────────────────────────────

def write_json(path, data, *, mode=0o600, indent=None, newline=False):
    """Temp file in the same folder → fsync → rename. A crash half-way leaves the original untouched."""
    folder = os.path.dirname(path) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.', suffix='.cs-tmp', dir=folder)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            if indent is None:
                json.dump(data, f, ensure_ascii=False, separators=(',', ':'))
            else:
                json.dump(data, f, ensure_ascii=False, indent=indent)
            if newline:
                f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_json_retry(path, tries=5):
    for i in range(tries):
        with open(path, encoding='utf-8') as f:
            raw = f.read()
        try:
            return raw, json.loads(raw)
        except ValueError:
            if i == tries - 1:
                raise
            time.sleep(0.1)


@contextlib.contextmanager
def claude_lock(path, stale_s, busy_msg, wait_s=None):
    """Directory lock compatible with proper-lockfile — the same paths the Claude CLI takes."""
    deadline = time.monotonic() + (LOCK_WAIT_S if wait_s is None else wait_s)
    while True:
        try:
            os.mkdir(path)
            break
        except FileExistsError:
            try:
                age = time.time() - os.stat(path).st_mtime
            except FileNotFoundError:
                continue
            if age > stale_s:
                with contextlib.suppress(OSError):
                    os.rmdir(path)  # stale lock — removed like proper-lockfile does
                    continue
            if time.monotonic() > deadline:
                raise CsError(busy_msg)
            time.sleep(0.2)
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            os.rmdir(path)


@contextlib.contextmanager
def vault_lock():
    os.makedirs(ACCOUNTS_DIR, mode=0o700, exist_ok=True)
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    os.chmod(VAULT_DIR, 0o700)
    fd = os.open(os.path.join(VAULT_DIR, '.lock'), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise CsError('another cs is running — try again when it is done')
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)


# ── login store ───────────────────────────────────────────────────────
# Linux: <config dir>/.credentials.json. macOS: the login keychain item the CLI uses — service "Claude Code-credentials"
# (plus -<sha256(CLAUDE_CONFIG_DIR)[:8]> when that variable is set), account = $USER, data = the same JSON the file would
# hold. cs reads and writes it with the same `security` commands as the CLI. CS_CRED_STORE=file|keychain overrides the
# platform default (tests); CS_SECURITY_BIN points at another security tool (tests).

CRED_STORE = os.environ.get('CS_CRED_STORE') or ('keychain' if sys.platform == 'darwin' else 'file')
if CRED_STORE not in ('file', 'keychain'):
    raise SystemExit('CS_CRED_STORE must be "file" or "keychain"')
SECURITY_BIN = os.environ.get('CS_SECURITY_BIN') or 'security'
KEYCHAIN_SERVICE = 'Claude Code-credentials' + (
    '-' + hashlib.sha256(CONFIG_DIR_ENV.encode('utf-8')).hexdigest()[:8] if CONFIG_DIR_ENV else '')
SECURITY_TIMEOUT = 10       # seconds per security call (the CLI allows 2)
SECURITY_LINE_MAX = 4032    # longer add-generic-password commands go as arguments instead of through `security -i`
KC_NOT_FOUND, KC_NO_INTERACTION = 44, 36  # security exit codes: errSecItemNotFound · errSecInteractionNotAllowed (locked)


def keychain_account():
    """The CLI's keychain account name: $USER (else the passwd name); anything outside [A-Za-z0-9._-] → claude-code-user."""
    name = os.environ.get('USER') or ''
    if not name:
        with contextlib.suppress(KeyError, OSError):
            name = pwd.getpwuid(os.getuid()).pw_name
    return name if re.fullmatch(r'[a-zA-Z0-9._-]+', name or '') else 'claude-code-user'


KEYCHAIN_ACCOUNT = keychain_account()


def security(args, stdin=None):
    """Run the security tool → (exit code, stdout, stderr). Only a missing tool or a hang raises."""
    try:
        p = subprocess.run([SECURITY_BIN] + args, input=stdin, capture_output=True, timeout=SECURITY_TIMEOUT)
    except FileNotFoundError:
        raise CsError(f'{SECURITY_BIN} was not found — on macOS it is /usr/bin/security; elsewhere run cs with CS_CRED_STORE=file') from None
    except subprocess.TimeoutExpired:
        raise CsError(f'the security tool did not answer within {SECURITY_TIMEOUT}s — is the keychain waiting for a password prompt?') from None
    return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')


def keychain_error(code, err, what):
    if code == KC_NO_INTERACTION:
        return CsError(f'the login keychain is locked, so the Claude login cannot be {what} (security exited 36) — '
                       'unlock it with: security unlock-keychain')
    detail = err.strip().splitlines()[-1] if err.strip() else ''
    return CsError(f'could not {what} the keychain item "{KEYCHAIN_SERVICE}" (security exited {code}'
                   + (f': {detail}' if detail else '') + ')')


def keychain_read():
    """The CLI's keychain item → its text. None when there is no item (exit 44)."""
    code, out, err = security(['find-generic-password', '-a', KEYCHAIN_ACCOUNT, '-w', '-s', KEYCHAIN_SERVICE])
    if code == 0:
        return out.rstrip('\r\n')
    if code == KC_NOT_FOUND:
        return None
    raise keychain_error(code, err, 'read')


def keychain_write(text):
    """add-generic-password -U … -X <hex> like the CLI: through `security -i` while the command fits its line buffer, as
    arguments otherwise. -U replaces the item in place, so its access list (which trusts `security`) is kept."""
    hexdata = text.encode('utf-8').hex()
    line = f'add-generic-password -U -a "{KEYCHAIN_ACCOUNT}" -s "{KEYCHAIN_SERVICE}" -X "{hexdata}"\n'
    if len(line) <= SECURITY_LINE_MAX:
        code, _, err = security(['-i'], stdin=line.encode('utf-8'))
    else:
        code, _, err = security(['add-generic-password', '-U', '-a', KEYCHAIN_ACCOUNT, '-s', KEYCHAIN_SERVICE, '-X', hexdata])
    if code != 0:
        raise keychain_error(code, err, 'write')


def parse_cred_text(text):
    """Keychain text → dict. `security -w` prints data that is not plain text as hex — accept that too."""
    try:
        return json.loads(text)
    except ValueError:
        try:
            return json.loads(bytes.fromhex(text.strip()).decode('utf-8'))
        except ValueError:
            raise ValueError('keychain item is not JSON') from None


def read_cred():
    """The current login as the CLI finds it → (raw text, dict, source 'keychain' | 'file' | ''). macOS reads the keychain
    first and the file only when the keychain holds nothing usable — the CLI's own order. Logged out → ('', {}, '')."""
    if CRED_STORE == 'keychain':
        text = keychain_read()
        if text is not None:
            try:
                cred = parse_cred_text(text)
                if isinstance(cred, dict):
                    return text, cred, 'keychain'
            except ValueError:
                pass  # not JSON — the CLI ignores such an item too and falls back to the file
    try:
        raw, cred = read_json_retry(CRED_PATH)
        return raw, (cred if isinstance(cred, dict) else {}), 'file'
    except FileNotFoundError:
        return '', {}, ''


def write_cred(raw, cred, src):
    """Store the login where the CLI reads it, keeping the file's formatting. macOS: the keychain item; a .credentials.json
    that exists as well is rewritten with the same content — a running CLI watches that file's mtime when it exists."""
    if CRED_STORE == 'keychain':
        keychain_write(json.dumps(cred, ensure_ascii=False, separators=(',', ':')))
        if not os.path.exists(CRED_PATH):
            return
        if src != 'file':
            try:
                with open(CRED_PATH, encoding='utf-8') as f:
                    raw = f.read()
            except OSError:
                raw = ''
    write_json(CRED_PATH, cred, mode=0o600, indent=2 if '\n' in raw else None, newline=raw.endswith('\n'))


# ── API ───────────────────────────────────────────────────────────────

def http_json(method, url, token=None, payload=None, timeout=20):
    headers = {'Content-Type': 'application/json', 'User-Agent': USER_AGENT}
    if token:
        headers['Authorization'] = 'Bearer ' + token
        headers['anthropic-beta'] = OAUTH_BETA
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            ra = float((e.headers or {}).get('Retry-After') or '')
        except (TypeError, ValueError):
            ra = None
        raise ApiError(e.code, e.read().decode('utf-8', 'replace')[:400], ra) from None


def token_fresh(oauth, margin_s=60):
    exp = oauth.get('expiresAt')
    return bool(oauth.get('accessToken')) and (exp is None or exp - now_ms() > margin_s * 1000)


def fetch_usage(token):
    return summarize(http_json('GET', API_BASE + '/api/oauth/usage', token=token, timeout=20))


# ── vault ─────────────────────────────────────────────────────────────
# Account key = '<email>#<organization UUID>'. Older vault files (no org field) derive it from oauthAccount.organizationUuid.

def org_of(e):
    return e.get('org') or (e.get('oauthAccount') or {}).get('organizationUuid') or ''


def mkkey(email, org):
    return f'{email}#{org or ""}'


def split_key(key):
    email, _, org = key.rpartition('#')
    return email, org


def ekey(e):
    return mkkey(e['email'], org_of(e))


def find_entry(entries, key):
    return next((e for e in entries if ekey(e) == key), None) if key else None


def org_name(e):
    return (e.get('oauthAccount') or {}).get('organizationName') or ''


def plan_kind(e):
    """'team' or 'ent' for an organization seat, '' for a personal subscription."""
    sub = ((e.get('claudeAiOauth') or {}).get('subscriptionType') or '').lower()
    typ = ((e.get('oauthAccount') or {}).get('organizationType') or '').lower().replace('claude_', '')
    if 'enterprise' in (sub, typ):
        return 'ent'
    if 'team' in (sub, typ):
        return 'team'
    return ''


def sort_entries(entries):
    """Vault order: personal subscriptions (by email) first, team seats after. The table re-sorts by reset (order_by_reset)."""
    entries.sort(key=lambda e: (1 if plan_kind(e) else 0, e['email'], org_name(e), org_of(e)))


def new_entry_path(email, org):
    """First account of an email → <email>.json; another organization of the same email → <email>--<org[:8]>.json."""
    base = re.sub(r'[^A-Za-z0-9._@+-]', '_', email)
    tail = re.sub(r'[^A-Za-z0-9-]', '', org or '')
    names = [base] + ([f'{base}--{tail[:8]}', f'{base}--{tail}'] if tail else []) + \
        [f'{base}--{n}' for n in range(2, 100)]
    for name in names:
        p = os.path.join(ACCOUNTS_DIR, name + '.json')
        if not os.path.exists(p):
            return p
    raise CsError('too many vault files for the same email')


def load_entries():
    seen = {}
    for fn in sorted(os.listdir(ACCOUNTS_DIR)):
        if not fn.endswith('.json') or fn.startswith('.'):
            continue
        path = os.path.join(ACCOUNTS_DIR, fn)
        try:
            with open(path, encoding='utf-8') as f:
                e = json.load(f)
        except (OSError, ValueError):
            continue
        if not (isinstance(e, dict) and e.get('email') and isinstance(e.get('claudeAiOauth'), dict)):
            continue
        e['_path'] = path
        k = ekey(e)
        if k not in seen or (e.get('savedAt') or 0) > (seen[k].get('savedAt') or 0):
            seen[k] = e  # two files for the same account → the newer one
    out = list(seen.values())
    sort_entries(out)
    return out


def save_entry(e):
    if not e.get('_path'):
        e['_path'] = new_entry_path(e['email'], org_of(e))
    data = {k: v for k, v in e.items() if k not in TRANSIENT}
    write_json(e['_path'], data, mode=0o600, indent=2, newline=True)


def labels_for(entries):
    """→ {account key: label}. first.jay@example.com → jay; a team seat of the same email → jay-team.
    Clashing labels fall back to the whole local part, then to the full email. Two team seats of one email get
    the first 4 characters of the organization UUID appended."""
    emails = sorted({e['email'] for e in entries})
    short = {}
    for em in emails:
        local = em.split('@')[0]
        short[em] = local.split('.')[-1] if '.' in local else local
    vals = list(short.values())
    names = {em: (s if vals.count(s) == 1 else em.split('@')[0]) for em, s in short.items()}
    if len(set(names.values())) < len(names):
        names = {em: em for em in emails}
    out = {}
    for em in emails:
        group = [e for e in entries if e['email'] == em]
        labs = {ekey(e): names[em] + (f'-{plan_kind(e)}' if plan_kind(e) else '') for e in group}
        counts = list(labs.values())
        for e in group:
            if counts.count(labs[ekey(e)]) > 1:
                labs[ekey(e)] += '-' + (re.sub(r'[^A-Za-z0-9]', '', org_of(e))[:4] or 'x')
        out.update(labs)
    if len(set(out.values())) < len(out):
        out = {ekey(e): ekey(e) for e in entries}
    return out


def label_of(labs, key):
    return labs.get(key) or (split_key(key)[0] if key else '?')


def read_live():
    """→ (raw text, whole credentials, claudeAiOauth, oauthAccount from .claude.json, source: 'keychain' | 'file' | '').
    Empty when logged out."""
    raw, cred, src = read_cred()
    try:
        _, cfg = read_json_retry(CONFIG_PATH)
        acct = cfg.get('oauthAccount') or {}
    except (OSError, ValueError, AttributeError):
        acct = {}
    return raw, cred, cred.get('claudeAiOauth') or {}, acct, src


def resolve_key(email, org, entries):
    """Unknown organization → only resolves when exactly one vault entry has that email."""
    if org:
        return mkkey(email, org)
    same = [e for e in entries if e['email'] == email]
    return ekey(same[0]) if len(same) == 1 else mkkey(email, '')


def identify(oauth, acct, entries):
    """Which account (email + organization) is the current login? → (key, verified, profile).
    Verified when the token matches a vault entry or the profile API confirms it; otherwise taken from the
    config file and marked unverified."""
    rt, at = oauth.get('refreshToken'), oauth.get('accessToken')
    if not rt and not at:
        return None, False, None
    for e in entries:
        v = e['claudeAiOauth']
        if (rt and v.get('refreshToken') == rt) or (at and v.get('accessToken') == at):
            return ekey(e), True, None
    if at and token_fresh(oauth):
        try:
            prof = http_json('GET', API_BASE + '/api/oauth/profile', token=at, timeout=15)
            email = (prof.get('account') or {}).get('email')
            if email:
                return resolve_key(email, (prof.get('organization') or {}).get('uuid'), entries), True, prof
        except (ApiError, OSError, ValueError):
            pass
    email = acct.get('emailAddress')
    return (resolve_key(email, acct.get('organizationUuid'), entries) if email else None), False, None


def account_from_profile(prof):
    a, g = prof.get('account') or {}, prof.get('organization') or {}
    return {k: v for k, v in {
        'accountUuid': a.get('uuid'), 'emailAddress': a.get('email'),
        'organizationUuid': g.get('uuid'), 'displayName': a.get('display_name'),
        'fullName': a.get('full_name'), 'organizationName': g.get('name'),
        'organizationType': g.get('organization_type'), 'organizationRateLimitTier': g.get('rate_limit_tier'),
        'seatTier': g.get('seat_tier'),
        'billingType': g.get('billing_type'), 'hasExtraUsageEnabled': g.get('has_extra_usage_enabled'),
    }.items() if v is not None}


def capture(entries, oauth, acct, key, verified, prof):
    """Store the current login in the vault. An unverified identity never overwrites an entry that holds a different
    token, and an unverified login with an unknown organization never creates a new entry."""
    if not key or not oauth.get('refreshToken'):
        return None
    email, org = split_key(key)
    e = find_entry(entries, key)
    if e is not None and not verified and e['claudeAiOauth'].get('refreshToken') != oauth.get('refreshToken'):
        return e
    if e is None:
        if not verified and not org:
            return None
        e = {'email': email}
        entries.append(e)
    if acct.get('emailAddress') == email and (acct.get('organizationUuid') or org) == org:
        new_acct = acct  # only when the config file names the same email and organization (keeps team seats clean)
    else:
        new_acct = e.get('oauthAccount') or (account_from_profile(prof) if prof else {})
    new_org = org or e.get('org') or ''
    if (e.get('claudeAiOauth') != oauth or e.get('oauthAccount') != new_acct or e.get('dead')
            or (e.get('org') or '') != new_org):
        e['claudeAiOauth'] = dict(oauth)
        e['oauthAccount'] = new_acct
        if new_org:
            e['org'] = new_org
        e['savedAt'] = now_ms()
        e.pop('dead', None)
        save_entry(e)
    sort_entries(entries)
    return e


def backup_live(cred, acct):
    if not cred:
        return
    name = local_dt().strftime('live-%Y%m%d-%H%M%S-%f.json')
    write_json(os.path.join(BACKUP_DIR, name), {'credentials': cred, 'oauthAccount': acct},
               mode=0o600, indent=2, newline=True)
    old = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith('live-'))
    for f in old[:-KEEP_BACKUPS]:
        with contextlib.suppress(OSError):
            os.unlink(os.path.join(BACKUP_DIR, f))


def refresh_entry(e, live_oauth):
    """Refresh an idle account's token only. The rotated refresh token is saved as soon as it arrives."""
    v = e['claudeAiOauth']
    if live_oauth.get('refreshToken') and v.get('refreshToken') == live_oauth.get('refreshToken'):
        raise CsError('cs never refreshes the login that is in use')  # safety net — reaching this is a bug
    payload = {'grant_type': 'refresh_token', 'refresh_token': v['refreshToken'],
               'client_id': v.get('clientId') or CLIENT_ID,
               'scope': ' '.join(v.get('scopes') or DEFAULT_SCOPES)}
    try:
        r = http_json('POST', TOKEN_URL, payload=payload, timeout=30)
    except ApiError as err:
        if err.status in (400, 401) and 'invalid_grant' in err.body:
            e['dead'] = 'invalid_grant'
            save_entry(e)
            raise Dead() from None
        raise
    t = now_ms()
    nv = dict(v)
    nv['accessToken'] = r['access_token']
    nv['refreshToken'] = r.get('refresh_token') or v['refreshToken']
    nv['expiresAt'] = t + int(r.get('expires_in') or 0) * 1000
    if r.get('refresh_token_expires_in'):
        nv['refreshTokenExpiresAt'] = t + int(r['refresh_token_expires_in']) * 1000
    if r.get('scope'):
        nv['scopes'] = r['scope'].split()
    e['claudeAiOauth'] = nv
    e['savedAt'] = t
    e.pop('dead', None)
    save_entry(e)
    got = (r.get('account') or {}).get('email_address')
    got_org = (r.get('organization') or {}).get('uuid')
    if got and got != e['email']:
        e['warn'] = f'token belongs to {got}'
    elif got_org and org_of(e) and got_org != org_of(e):
        e['warn'] = 'token organization differs from the vault entry'


# ── usage ─────────────────────────────────────────────────────────────

def summarize(u):
    s = {'session': None, 'weekly': None, 'scoped': [], 'extra': False}
    for lim in u.get('limits') or []:
        kind, pct, reset = lim.get('kind'), lim.get('percent'), lim.get('resets_at')
        if kind == 'session':
            s['session'] = [pct, reset]
        elif kind == 'weekly_all':
            s['weekly'] = [pct, reset]
        elif kind == 'weekly_scoped':
            name = ((lim.get('scope') or {}).get('model') or {}).get('display_name') or 'model'
            s['scoped'].append([name, pct, reset])
    if s['session'] is None and u.get('five_hour'):
        s['session'] = [u['five_hour'].get('utilization'), u['five_hour'].get('resets_at')]
    if s['weekly'] is None and u.get('seven_day'):
        s['weekly'] = [u['seven_day'].get('utilization'), u['seven_day'].get('resets_at')]
    s['extra'] = bool((u.get('extra_usage') or {}).get('is_enabled'))
    return s


EXPIRED = 'login expired → cs add to sign in again'
REFRESH_PENDING = 'token refresh pending — refreshed on the next claude request'


def fetch_status(e, live_key, live_oauth, may_refresh):
    """Usage of one account → {'usage'|'error'|'note'}. The account in use is never refreshed."""
    is_live = ekey(e) == live_key or bool(
        live_oauth.get('refreshToken') and e['claudeAiOauth'].get('refreshToken') == live_oauth.get('refreshToken'))
    v = live_oauth if (is_live and live_oauth.get('accessToken')) else e['claudeAiOauth']
    if e.get('dead') and not is_live:
        return {'error': EXPIRED}
    if not token_fresh(v):
        if is_live:
            return {'note': REFRESH_PENDING}
        if not may_refresh:
            return {'note': 'skipped — current login could not be verified'}
        try:
            refresh_entry(e, live_oauth)
        except Dead:
            return {'error': EXPIRED}
        except (ApiError, OSError, ValueError) as err:
            return {'error': f'token refresh failed ({err})'}
        v = e['claudeAiOauth']
    for attempt in (1, 2):
        try:
            s = fetch_usage(v['accessToken'])
            e['lastUsage'], e['lastUsageAt'] = s, now_ms()
            save_entry(e)
            return {'usage': s}
        except ApiError as err:
            if err.status == 401 and attempt == 1 and not is_live and may_refresh:
                try:
                    refresh_entry(e, live_oauth)
                except Dead:
                    return {'error': EXPIRED}
                except (ApiError, OSError, ValueError) as err2:
                    return {'error': f'token refresh failed ({err2})'}
                v = e['claudeAiOauth']
                continue
            if err.status == 401 and is_live:
                return {'note': REFRESH_PENDING}
            if err.status in (429, 403):  # the Claude CLI treats both as the usage rate limit
                return {'error': 'rate limited — retrying later', 'limited': True, 'retry_after': err.retry_after}
            return {'error': f'fetch failed ({err})'}
        except (OSError, ValueError) as err:
            return {'error': f'fetch failed ({type(err).__name__})'}
    return {'error': 'fetch failed'}


# ── table ─────────────────────────────────────────────────────────────

ANSI = re.compile(r'\033\[[0-9;]*m')


def dwidth(s):
    w = 0
    for ch in ANSI.sub('', s):
        if unicodedata.combining(ch):
            continue
        w += 2 if unicodedata.east_asian_width(ch) in ('W', 'F') else 1
    return w


def pad(s, width, right=False):
    gap = ' ' * max(0, width - dwidth(s))
    return gap + s if right else s + gap


def left_pct(used):
    if used is None:
        return None
    return max(0, min(100, round(100 - float(used))))


def pct_text(used):
    p = left_pct(used)
    if p is None:
        return '-'
    return c(f'{p}%', '32' if p >= 50 else ('33' if p >= 20 else '1;31'))


ISO_FRAC = re.compile(r'\.(\d+)(?=[+-]\d\d:\d\d$|$)')


def parse_iso(iso):
    """ISO 8601 time from the API → aware datetime. Python before 3.11 only takes 3 or 6 fractional digits — normalise to 6."""
    s = iso.strip().replace('Z', '+00:00')
    s = ISO_FRAC.sub(lambda m: '.' + (m.group(1) + '000000')[:6], s)
    dt = datetime.datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def when(iso, with_date):
    if not iso:
        return '?'
    t = to_minute(parse_iso(iso).astimezone())
    return f'{t.month}/{t.day} {DAYS[t.weekday()]} {t:%H:%M}' if with_date else f'{t:%H:%M}'


def to_minute(dt):
    """Reset times arrive as 10:59:59.95 or 11:00:00.3 — snap to the nearest minute (11:00)."""
    return (dt + datetime.timedelta(seconds=30)).replace(second=0, microsecond=0)


def reset_ts(iso):
    """ISO time → epoch seconds (None when missing or unreadable)."""
    if not iso:
        return None
    try:
        return parse_iso(iso).timestamp()
    except ValueError:
        return None


def future_reset(lim, now_s):
    """[percent, reset] → the upcoming reset time. None when unknown or already past."""
    t = reset_ts(lim[1]) if lim else None
    return t if t is not None and t > now_s else None


def until(t, now_s):
    """Time until a reset → '1d 8h' (hours rounded beyond a day) · '3h 12m' · '25m'."""
    m = max(1, int((t - now_s + 59) // 60))
    if m >= 1440:
        d, h = divmod((m + 30) // 60, 24)
        return f'{d}d {h}h' if h else f'{d}d'
    h, m = divmod(m, 60)
    if h:
        return f'{h}h {m}m' if m else f'{h}h'
    return f'{m}m'


def wd_hm(t):
    dt = to_minute(local_dt(t))
    return f'{DAYS[dt.weekday()]} {dt:%H:%M}'


def when_ts(t):
    dt = to_minute(local_dt(t))
    if dt.date() == local_dt().date():
        return f'{dt:%H:%M}'
    return f'{dt.month}/{dt.day} {DAYS[dt.weekday()]} {dt:%H:%M}'


def usage_of(e, results=None):
    """Usage the table shows: this round's value, else the last stored one (None for an expired account)."""
    if results is not None:
        r = results.get(ekey(e)) or {}
        if r.get('usage'):
            return r['usage']
        if r.get('error') == EXPIRED:
            return None
    elif e.get('dead'):
        return None
    return e.get('lastUsage')


def reset_key(e, results, now_s):
    """Table order = soonest weekly reset, then soonest 5-hour reset. Unknown or past resets (= a freshly refilled account) sort last."""
    s = usage_of(e, results) or {}
    wk, ses = future_reset(s.get('weekly'), now_s), future_reset(s.get('session'), now_s)
    return (wk is None, wk or 0, ses is None, ses or 0)


def order_by_reset(entries, results=None):
    """Vault order first, then by reset (ties keep vault order). cs <n> follows this order too —
    without results it uses the last stored usage (= the last table the user saw)."""
    now_s = time.time()
    sort_entries(entries)
    entries.sort(key=lambda e: reset_key(e, results, now_s))


def blocked_until(s, now_s):
    """When a limit is used up: the time it frees (inf when unknown). None when the account is usable now."""
    out = None
    for lim in (s.get('weekly'), s.get('session')):
        if lim and lim[0] is not None and left_pct(lim[0]) <= 0:
            t = reset_ts(lim[1])
            if t is not None and t <= now_s:
                continue  # reset already happened
            out = max(out or 0, t if t is not None else float('inf'))
    return out


def clip(s, width):
    out, w = '', 0
    for ch in s:
        cw = 2 if unicodedata.east_asian_width(ch) in ('W', 'F') else 1
        if w + cw > width:
            return out + '…'
        out, w = out + ch, w + cw
    return out


def tier_mult(e):
    """Multiplier from rateLimitTier — default_claude_max_20x → 20 · a team seat's default_claude_max_5x → 5. None when unknown."""
    m = re.search(r'max_(\d+)x', (e['claudeAiOauth'].get('rateLimitTier') or '').lower())
    return int(m.group(1)) if m else None


def plan_name(e, short=False):
    """Max 20x · Team 5x · <org> (team seats show the seat multiplier and organization — percentages are relative to each
    account's own limit). short = narrow terminal — drops the organization name."""
    v = e['claudeAiOauth']
    kind = plan_kind(e)
    mult = tier_mult(e)
    if kind:
        org = '' if short else clip(org_name(e), 14)
        return ('Team' if kind == 'team' else 'Enterprise') + (f' {mult}x' if mult else '') + (f' · {org}' if org else '')
    if mult:
        return f'Max {mult}x'
    sub = v.get('subscriptionType') or ''
    return sub.capitalize() if sub else '-'


def week_cap(e):
    """Size of the weekly limit with one Max 20x week = 100 (a 5x week = 100 / WEEK_RATIO). None for unknown plans."""
    return {20: 100.0, 5: 100.0 / WEEK_RATIO}.get(tier_mult(e))


def week_amount(e, s, now_s):
    """→ (left, total) on the shared scale (one 20x week = 100) so accounts can be added and compared.
    A stored value whose weekly reset has passed counts as full. None when the plan is unknown."""
    cap = week_cap(e)
    wk = (s or {}).get('weekly')
    if cap is None or not wk or wk[0] is None:
        return None
    t = reset_ts(wk[1])
    left = 100 if t is not None and t <= now_s else left_pct(wk[0])
    return cap * left / 100.0, cap


def amount_text(x):
    return '<1' if 0 < x < 1 else f'{x:.0f}'


def usage_line(s):
    """One-line summary: weekly 40% (resets in 1d 8h) · 5-hour 97% (resets 09:10) · Fable 38% left"""
    parts, now_s = [], time.time()
    if s.get('weekly') and s['weekly'][0] is not None:
        t = future_reset(s['weekly'], now_s)
        parts.append(f'weekly {pct_text(s["weekly"][0])}' + (f' (resets in {until(t, now_s)})' if t else ''))
    if s.get('session') and s['session'][0] is not None:
        parts.append(f'5-hour {pct_text(s["session"][0])}'
                     + (f' (resets {when(s["session"][1], False)})' if s['session'][1] else ''))
    for name, pct, _ in s.get('scoped') or []:
        parts.append(f'{name} {pct_text(pct)}')
    line = ' · '.join(parts) + ' left' if parts else ''
    if s.get('extra'):
        line += c('  ⚠ extra usage on', '1;33')
    return line


def shown_rows(entries, results):
    """Rows for the table: (account, fetch result, usage, tail note) — a failed fetch shows the last value and its age."""
    shown = []
    for e in entries:
        r = results.get(ekey(e)) or {}
        s, tail = r.get('usage'), ''
        if s is None and e.get('lastUsage') and r.get('error') != EXPIRED:
            s = e['lastUsage']
            mins = max(0, (now_ms() - (e.get('lastUsageAt') or now_ms())) // 60000)
            why = r.get('error') or r.get('note')
            tail = c(f'  ({mins}m old' + (f' · {why}' if why else '') + ')', '2')
        shown.append((e, r, s, tail))
    return shown


def ago(sec):
    if sec < 10:
        return 'now'
    if sec < 60:
        return f'{int(sec)}s ago'
    if sec < 3600:
        return f'{int(sec // 60)}m ago'
    return f'{int(sec // 3600)}h ago'


def table_lines(entries, live_key, verified, results, logged_in=True, *, pointer=False, cursor=None,
                ages=None, compact=False, now_s=None, split=False):
    """Table + notes → list of lines. Keeps the entries order — row number = that order.
    The live screen (pointer) adds a ❯ column, inverts the cursor row (account key) and fills the 'Fetched' column from
    ages (key → seconds since fetched). 'Left/Total' = weekly limits on the shared scale (one 20x week = 100) + a Total row.
    compact = narrow terminal — drops Fetched, per-model weekly, weekday/time of the weekly reset and team organization names.
    split = return (table lines, note lines) separately — only the table lines are measured against the terminal width."""
    labs = labels_for(entries)
    now_s = time.time() if now_s is None else now_s
    shown = shown_rows(entries, results)
    scoped_name = None if compact else next(
        (s['scoped'][0][0] for _, _, s, _ in shown if s and s.get('scoped')), None)
    show_age = ages is not None and not compact
    amounts = {ekey(e): week_amount(e, s, now_s) for e, _, s, _ in shown}
    show_amt = any(a is not None for a in amounts.values())
    rel = {}  # time until the weekly reset — built first so the column lines up
    for e, _, s, _ in shown:
        wk = (s or {}).get('weekly')
        t = reset_ts(wk[1]) if wk and wk[0] is not None else None
        rel[ekey(e)] = (t, '' if t is None else ('reset passed' if t <= now_s else 'in ' + until(t, now_s)))
    rel_w = max([dwidth(x) for _, x in rel.values()] + [0])
    head = ([''] if pointer else []) + ['', '#', 'Account', 'Plan'] \
        + (['Weekly · reset'] + (['Left/Total'] if show_amt else []) + ['5-hour'] if compact
           else ['Weekly left · reset'] + (['Left/Total'] if show_amt else []) + ['5-hour · reset']) \
        + ([f'{scoped_name} weekly'] if scoped_name else []) + (['Fetched'] if show_age else [])
    sep = '/' if compact else ' / '
    rows = []
    for i, (e, r, s, tail) in enumerate(shown, 1):
        k = ekey(e)
        live = k == live_key
        cells = ([c('❯', '1') if k == cursor else ' '] if pointer else []) \
            + [c('▶', '1;36') if live else ' ', str(i), c(labs[k], '1') if live else labs[k], plan_name(e, compact)]
        if s:
            ses, wk = s.get('session') or [None, None], s.get('weekly') or [None, None]
            if wk[0] is None:
                cells.append('-')
            else:
                t, text = rel[k]
                when_txt = '' if not t else (f'  {pad(text, rel_w)}' if compact else f'  {pad(text, rel_w)}  ({wd_hm(t)})')
                cells.append(pad(pct_text(wk[0]), 4, True) + when_txt)
            if show_amt:
                a = amounts[k]
                cells.append('?' if a is None else pad(amount_text(a[0]), 3, True) + sep + amount_text(a[1]))
            if ses[0] is None:
                cells.append('-')
            else:
                cells.append(pad(pct_text(ses[0]), 4, True) + (f'  ({when(ses[1], False)})' if ses[1] else ''))
            if scoped_name:
                sc = s.get('scoped') or []
                cells.append(pad(pct_text(sc[0][1]), 4, True) if sc else '-')
            if show_age:
                cells.append(c(ago(ages[k]), '2') if r.get('usage') and k in ages else '')
            if s.get('extra'):
                tail += c('  ⚠extra' if compact else '  ⚠ extra usage', '1;33')
        else:
            msg = r.get('error') or r.get('note') or ('fetching…' if pointer else 'not fetched')
            tail = c(msg, '31' if r.get('error') else '2')
        rows.append((k, cells, tail))
    known = [amounts[ekey(e)] for e, _, s, _ in shown if s and amounts[ekey(e)] is not None]
    if show_amt and len(known) >= 2:  # Total row — Left/Total column only
        rem, cap = sum(a[0] for a in known), sum(a[1] for a in known)
        unknown = [labs[ekey(e)] for e, _, s, _ in shown if s and amounts[ekey(e)] is None]
        cells = ([' '] if pointer else []) + [' ', '', 'Total', '']
        cells += [''] + [c(pad(amount_text(rem), 3, True) + sep + amount_text(cap), '1')]
        cells += [''] * (len(head) - len(cells))
        tail = c(f'  = {rem / 100:.1f} × one 20x week' + (f' ({", ".join(unknown)}: unknown plan, not counted)' if unknown else ''), '2')
        rows.append((None, cells, tail))
    widths = [dwidth(h) for h in head]
    for _, cells, _ in rows:
        for j, x in enumerate(cells):
            widths[j] = max(widths[j], dwidth(x))
    grid = ['  '.join(pad(c(h, '2'), widths[j]) for j, h in enumerate(head)).rstrip()]
    for k, cells, tail in rows:
        line = '  '.join(pad(x, widths[j]) for j, x in enumerate(cells))
        line = (line + '  ' + tail) if len(cells) < len(head) else (line.rstrip() + tail)
        if pointer and k is not None and k == cursor and COLOR:
            line = '\033[7m' + line.replace('\033[0m', '\033[0m\033[7m') + '\033[0m'  # inverted cursor row
        grid.append(line)
    lines = []
    if show_amt:
        five = 100 / WEEK_RATIO
        lines.append(c(f'※ Left/Total: one 20x week = 100 · 5x ≈ {five:.0f} (estimate)' if compact else
                       f'※ Left/Total = weekly limit scaled so one Max 20x week = 100 — a Team/Max 5x week ≈ {five:.0f}'
                       f' (20x ≈ 5x × {WEEK_RATIO:g} · {WEEK_RATIO_SRC})', '2'))
    lines.append('')
    if find_entry(entries, live_key) is not None:
        note = '' if verified else ' (from the config file · not verified)'
        lines.append(c(f'▶ current login{note} — every claude process on this machine runs on it.', '2'))
    elif logged_in:
        lines.append(c('Could not verify which account is logged in — switching is disabled. Try again shortly.', '33'))
    else:
        lines.append(c('Logged out right now — pick a number or name to log in as that account.', '33'))
    if len(shown) >= 2:
        lines.append(first_hint(shown, labs, live_key, now_s))
    for e in entries:
        if e.get('warn'):
            lines.append(c(f'⚠ {labs[ekey(e)]}: {e["warn"]}', '33'))
    return (grid, lines) if split else grid + lines


def fitted_table(cols, *args, **kw):
    """Table that fits the terminal — wide layout first, compact when the table lines overflow. → (table lines, notes)"""
    for compact in (False, True):
        grid, notes = table_lines(*args, compact=compact, split=True, **kw)
        if compact or max(dwidth(x) for x in grid) <= cols:
            return grid, notes


def render(entries, live_key, verified, results, logged_in=True):
    """Prints entries in order_by_reset order — row number = that order. Compact layout on narrow terminals."""
    now = local_dt()
    print(c('Claude accounts · remaining usage', '1') + c(' · soonest weekly reset first', '1;36')
          + c(f'   {now.month}/{now.day} {DAYS[now.weekday()]} {now:%H:%M}', '2'))
    print()
    cols = shutil.get_terminal_size((10 ** 4, 40)).columns if sys.stdout.isatty() else 10 ** 4
    grid, notes = fitted_table(cols, entries, live_key, verified, results, logged_in, now_s=now.timestamp())
    print('\n'.join(grid + notes))
    print(auto_status_line())


def usable(shown, now_s):
    """Accounts usable right now (both weekly and 5-hour have something left) → [(row number, account, usage)] in table order."""
    return [(i, e, s) for i, (e, _, s, _) in enumerate(shown, 1) if s and blocked_until(s, now_s) is None]


def first_hint(shown, labs, live_key, now_s):
    """→ Use first: the top usable account (both windows have something left) = the soonest weekly reset."""
    ok = usable(shown, now_s)
    if not ok:
        waits = [(blocked_until(s, now_s), e) for e, _, s, _ in shown if s]
        waits = [(t, e) for t, e in waits if t not in (None, float('inf'))]
        if not waits:
            return c('→ No account is usable right now.', '33')
        t, e = min(waits, key=lambda x: x[0])
        return c(f'→ No account is usable right now — the first to free up is {labs[ekey(e)]} ({when_ts(t)})', '33')
    i, e, s = ok[0]
    line = c('→ Use first: ', '1') + c(labs[ekey(e)], '1;36') \
        + c(' (in use)' if ekey(e) == live_key else f' (#{i})', '1')
    wk = s.get('weekly')
    t = future_reset(wk, now_s)
    if t and i == 1:
        a = week_amount(e, s, now_s)
        conv = f' (= {amount_text(a[0])} on the 20x scale)' if a and a[1] != 100 else ''  # a 5x seat also gets the shared-scale amount
        line += c(f' — its weekly reset is the soonest (in {until(t, now_s)}), so the remaining {left_pct(wk[0])}%{conv} disappears first', '2')
    elif t:
        line += c(f' — the soonest weekly reset among the usable accounts (in {until(t, now_s)})', '2')
    # Running low? 5-hour by its own %, weekly by the shared-scale amount (one 20x week = 100) under 10 — a 5x seat drains that much faster
    a = week_amount(e, s, now_s)
    lows = [left_pct(lim[0]) for lim in (s.get('session'),) + (() if a else (wk,)) if lim and lim[0] is not None]
    lows += [a[0]] if a else []
    if lows and min(lows) < 10 and len(ok) > 1:
        j, nxt, _ = ok[1]
        line += c(f' · if it runs out soon, next is {labs[ekey(nxt)]} (#{j})', '2')
    return line


# ── actions ───────────────────────────────────────────────────────────

def prepare():
    """Load the vault, identify the current login and store it (always with the newest token)."""
    entries = load_entries()
    _, _, oauth, acct, _ = read_live()
    key, verified, prof = identify(oauth, acct, entries)
    capture(entries, oauth, acct, key, verified, prof)
    order_by_reset(entries)  # same order as the last table shown — cs <n> follows that table's numbers
    return entries, oauth, key, verified


def collect(keys=None):
    """Vault + current login + usage fetch (only `keys` when given) → sorted by reset.
    → (entries, current oauth, current account key, verified, {key: fetch result}, logged in?)"""
    entries, oauth, key, verified = prepare()
    results = {}
    todo = [e for e in entries if keys is None or ekey(e) in keys]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = {ekey(e): pool.submit(fetch_status, e, key, oauth, verified) for e in todo}
        for k, f in futs.items():
            try:
                results[k] = f.result()
            except Exception as err:  # one failing account must not take the table down
                results[k] = {'error': f'fetch failed ({type(err).__name__})'}
    order_by_reset(entries, results)
    return entries, oauth, key, verified, results, bool(oauth.get('refreshToken') or oauth.get('accessToken'))


def status(show=True):
    entries, oauth, key, verified, results, logged_in = collect()
    if show:
        render(entries, key, verified, results, logged_in)
    return entries, oauth, key, verified


def pick(entries, arg):
    labs = labels_for(entries)
    a = arg.strip().lower()
    if a.isdigit():
        if 1 <= int(a) <= len(entries):
            return entries[int(a) - 1]
        raise CsError(f'there is no account #{a} — run cs to see the list')
    for e in entries:
        if labs[ekey(e)].lower() == a:
            return e
    for match in (lambda e: e['email'].lower() == a,
                  lambda e: a and (a in e['email'].lower() or a in labs[ekey(e)].lower())):
        hits = [e for e in entries if match(e)]
        if len(hits) == 1:
            return hits[0]
        if hits:
            raise CsError(f'"{arg}" matches {len(hits)} accounts — pick one by name: '
                          + ' · '.join(labs[ekey(e)] for e in hits))
    raise CsError(f'no account matches "{arg}" — run cs to see the list')


def relogin_hint(e):
    h = f'sign in again with cs add {e["email"]}'
    if plan_kind(e):
        h += f' (choose {org_name(e) or "the team"} when the browser asks for an organization)'
    return h


def switch(entries, live_oauth, live_key, target, say=print, show_usage=True):
    """Swap the login file to `target`. Messages go through `say` (the live screen collects them in its message area)."""
    labs = labels_for(entries)
    tk = ekey(target)
    name = labs[tk]
    if tk == live_key:
        say(f'already using {name}.')
        return 0
    if live_oauth.get('refreshToken') and find_entry(entries, live_key) is None:
        raise CsError('could not verify which account is logged in, so nothing was changed — try again shortly')
    if target.get('dead'):
        raise CsError(f'the {name} login has expired — {relogin_hint(target)}')
    if (target['claudeAiOauth'].get('expiresAt') or 0) - now_ms() < 30 * 60 * 1000:
        try:
            refresh_entry(target, live_oauth)  # idle account — safe to refresh
        except Dead:
            raise CsError(f'the {name} login has expired — {relogin_hint(target)}') from None
        except (ApiError, OSError, ValueError) as err:
            raise CsError(f'token refresh for {name} failed ({err}) — nothing was changed') from None
    t0 = time.monotonic()
    busy = 'Claude is refreshing its token right now — try again in a few seconds'
    cfg_note = ''
    with claude_lock(REFRESH_LOCK, 60, busy), claude_lock(LEGACY_LOCK, 60, busy):
        raw, cred, oauth, acct, src = read_live()
        if (oauth.get('refreshToken'), oauth.get('accessToken')) != \
                (live_oauth.get('refreshToken'), live_oauth.get('accessToken')):
            # Claude rotated its token or someone logged in meanwhile → identify again and store the newest login
            key, verified, prof = identify(oauth, acct, entries)
            if key == tk:
                say(f'already using {name}.')
                return 0
            capture(entries, oauth, acct, key, verified, prof)
            if oauth.get('refreshToken') and find_entry(entries, key) is None:
                raise CsError('could not verify which account is logged in, so nothing was changed — try again shortly')
        backup_live(cred, acct)
        new_cred = dict(cred)
        new_cred['claudeAiOauth'] = dict(target['claudeAiOauth'])
        with claude_lock(STORAGE_LOCK, 15, 'Claude is saving its login right now — try again in a few seconds'):
            write_cred(raw, new_cred, src)
        if target.get('oauthAccount'):
            try:
                with claude_lock(CONFIG_LOCK, 10, 'Claude is saving its config', wait_s=min(10, LOCK_WAIT_S)):
                    craw, cfg = read_json_retry(CONFIG_PATH)
                    cfg['oauthAccount'] = target['oauthAccount']
                    write_json(CONFIG_PATH, cfg, mode=os.stat(CONFIG_PATH).st_mode & 0o777,
                               indent=2 if '\n' in craw else None, newline=craw.endswith('\n'))
            except (CsError, OSError, ValueError) as err:
                cfg_note = f' (the account name shown inside claude was not updated: {err} — harmless)'
    dt = time.monotonic() - t0
    say(c(f'✓ switched to {name} ({dt:.1f}s)', '1;32') + cfg_note)
    if show_usage:
        try:
            say('  ' + usage_line(fetch_usage(target['claudeAiOauth']['accessToken'])))
        except (ApiError, OSError, ValueError):
            pass
    follow = 'within about 30 seconds (the CLI caches keychain reads)' if CRED_STORE == 'keychain' else 'from its next request'
    say(c(f'  every claude process on this machine uses {name} {follow} '
          '(a response already in flight may finish on the previous account).', '2'))
    if plan_kind(target):
        say(c('  this is a team seat — any managed settings or policies set by the team admin apply to this machine while it is in use.', '2'))
    return 0


def add(email_hint=None):
    entries, oauth_before, before, _ = prepare()
    had = {ekey(e) for e in entries}
    labs = labels_for(entries)
    if before:
        print(f'the current account {label_of(labs, before)} is stored.')
    print('Starting a new login. Open the URL below in a browser, sign in, then paste the code it shows back here.')
    print('If the email belongs to both a personal subscription and a team, the browser asks which organization to use — pick the one you want to add.')
    print(c('The moment the login completes, every claude on this machine is on the new account — you can switch back afterwards.', '2'))
    print(flush=True)
    rc = subprocess.call([CLAUDE_BIN, 'auth', 'login', '--claudeai'] + (['--email', email_hint] if email_hint else []))
    print()
    _, _, oauth, _, _ = read_live()
    if oauth.get('refreshToken') == oauth_before.get('refreshToken'):
        print('The login did not change (cancelled or failed) — nothing stored.' + (f' (claude exit code {rc})' if rc else ''))
        return 1 if rc else 0
    entries, live_oauth, live, verified = status(show=True)
    labs = labels_for(entries)
    new = find_entry(entries, live)
    if not live or not verified or new is None:
        raise CsError('could not verify which account the new login is — run cs once more')
    if live in had:
        print(f'\n{labs[live]} ({plan_name(new)}) was already stored — only its token was renewed.')
        if not plan_kind(new):
            print(c('If you meant to add a team seat, run cs add again and choose the team when the browser asks for an organization.', '33'))
    else:
        print(f'\nstored: {labs[live]} ({plan_name(new)})')
    back = find_entry(entries, before)
    if back is not None and before != live and sys.stdin.isatty():
        try:
            ans = input(f'\nNow on {labs[live]}. Switch back to {labs[before]}? (y/N) ').strip().lower()
        except EOFError:
            ans = ''
        if ans in ('y', 'yes'):
            return switch(entries, live_oauth, live, back)
    return 0


# ── auto-switch ───────────────────────────────────────────────────────
# The on/off setting lives in ~/.claude-accounts/settings.json. Switching is done by a live cs screen; with several
# screens open, only the one holding auto.lock acts. Every move is appended to auto-switch.log.

def load_settings():
    try:
        with open(SETTINGS_PATH, encoding='utf-8') as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def auto_enabled():
    return bool(load_settings().get('autoSwitch'))


def set_auto(on):
    os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
    d = load_settings()
    d['autoSwitch'] = bool(on)
    d['autoSwitchChangedAt'] = now_ms()
    write_json(SETTINGS_PATH, d, mode=0o600, indent=2, newline=True)


WINDOWS = (('5-hour', 'session'), ('weekly', 'weekly'))


def need_switch(s, rates, now_s):
    """Should the current account be left? → reason text (None when not).
    True when either window has ≤ AUTO_FLOOR % left, or when rates (window → % used per second) say it hits 0 before the
    next check. Per-model weekly limits (e.g. Fable) are ignored — they only block that model, the default model keeps working."""
    for name, field in WINDOWS:
        lim = s.get(field)
        if not lim or lim[0] is None:
            continue
        t = reset_ts(lim[1])
        if t is not None and t <= now_s:
            continue  # reset already happened — refilled
        left = left_pct(lim[0])
        if left <= AUTO_FLOOR:
            return f'{name} {left}% left'
        rate = (rates or {}).get(field)
        if rate and left <= rate * (LIVE_EVERY * 1.5 + 5):
            per_min = rate * 60
            speed = f'{per_min:.0f}' if per_min >= 10 else f'{per_min:.1f}'
            return f'{name} {left}% left · draining {speed}%/min'
    return None


def min_left(s, now_s):
    """Smallest remaining % across the 5-hour and weekly windows (100 when nothing is known; past resets count as full)."""
    out = 100
    for _, field in WINDOWS:
        lim = s.get(field)
        if not lim or lim[0] is None:
            continue
        t = reset_ts(lim[1])
        if t is not None and t <= now_s:
            continue
        out = min(out, left_pct(lim[0]))
    return out


def auto_candidate(k, results, now_s):
    """Can auto-switch move onto this account? Needs usage fetched this round (expired, failed and rate-limited lookups
    don't count), more than AUTO_MIN % left in both windows, and extra usage off (an account with extra usage never
    blocks — it bills instead, so cs never moves there on its own; Enter still can)."""
    s = (results.get(k) or {}).get('usage')
    return bool(s) and not s.get('extra') and min_left(s, now_s) > AUTO_MIN


def auto_preferred(entries, results, live_key, rates, now_s):
    """The account auto-switch wants in use: the first in table order (soonest weekly reset) that is usable.
    The current account counts as usable until it is draining (need_switch); any other account must pass auto_candidate.
    None when nothing is usable."""
    for e in entries:
        k = ekey(e)
        if k == live_key:
            s = (results.get(k) or {}).get('usage')
            if s and not need_switch(s, rates, now_s):
                return e
            continue
        if auto_candidate(k, results, now_s):
            return e
    return None


def auto_target(entries, results, live_key, now_s):
    """Where to go when the current account is draining: the first candidate in table order other than the current one."""
    for e in entries:
        k = ekey(e)
        if k != live_key and auto_candidate(k, results, now_s):
            return e
    return None


def first_in_line_reason(e, results, now_s):
    """Why an account is moved onto proactively, e.g. 'joe is first in line · weekly resets in 5h 47m'."""
    s = (results.get(ekey(e)) or {}).get('usage') or {}
    t = future_reset(s.get('weekly'), now_s)
    return 'first in line' + (f' · weekly resets in {until(t, now_s)}' if t else '')


def auto_log_append(line):
    with contextlib.suppress(OSError):
        os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
        fd = os.open(AUTO_LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (local_dt().strftime('%Y-%m-%d %H:%M:%S') + '\t' + line + '\n').encode())
        finally:
            os.close(fd)


def auto_log_tail(n=3, max_age_s=86400):
    """Last n lines of the auto-switch log → [(time, text)] — entries older than a day are dropped."""
    try:
        with open(AUTO_LOG_PATH, 'rb') as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 4096))
            lines = f.read().decode('utf-8', 'replace').splitlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        ts, _, text = ln.partition('\t')
        try:
            t = datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S').timestamp()
        except ValueError:
            continue
        if time.time() - t <= max_age_s:
            out.append((t, text))
    return out


def tty_name():
    with contextlib.suppress(OSError):
        return os.ttyname(sys.stdin.fileno()).replace('/dev/', '')
    return '-'


class AutoLock:
    """The one live screen in charge of auto-switch — flock on auto.lock (released automatically when the process dies)."""

    def __init__(self):
        self.fd = None

    def acquire(self):
        if self.fd is not None:
            return True
        try:
            os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
            fd = os.open(AUTO_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        with contextlib.suppress(OSError):
            os.ftruncate(fd, 0)
            os.write(fd, f'{os.getpid()} {tty_name()}\n'.encode())
        self.fd = fd
        return True

    def release(self):
        if self.fd is not None:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = None


def auto_holder():
    """The cs screen in charge of auto-switch → 'pid 1234 · pts/3' (None when there is none)."""
    try:
        fd = os.open(AUTO_LOCK_PATH, os.O_RDONLY)
    except OSError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            parts = os.read(fd, 200).decode('utf-8', 'replace').split()
            return f'pid {parts[0]} · {parts[1]}' if len(parts) >= 2 else 'another cs'
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    finally:
        os.close(fd)


def auto_status_line():
    """The auto-switch status line printed by cs ls and cs auto."""
    if not auto_enabled():
        return c('Auto-switch off', '2') + c(' — press a on the live screen (cs) or run cs auto on', '2')
    holder = auto_holder()
    if holder:
        return c('Auto-switch on', '1;32') + c(f' — the live cs screen ({holder}) is in charge', '2')
    return c('Auto-switch on', '1;32') + c(' — but no live cs screen is open, so nothing moves right now. Keep cs or cs keep running.', '33')


def keep():
    """Run the live screen inside tmux session 'cs' (attach when it exists). It keeps running when the window closes or SSH drops."""
    tm = shutil.which('tmux')
    if not tm:
        raise CsError('tmux is not installed — just leave cs running instead')
    cmd = shlex.quote(os.path.abspath(sys.argv[0]))
    if os.environ.get('TMUX'):  # already inside tmux — switch to the session instead of nesting
        if subprocess.call([tm, 'has-session', '-t', 'cs'], stderr=subprocess.DEVNULL) != 0:
            subprocess.call([tm, 'new-session', '-d', '-s', 'cs', cmd])
        os.execv(tm, [tm, 'switch-client', '-t', 'cs'])
    os.execv(tm, [tm, 'new-session', '-A', '-s', 'cs', cmd])


# ── live screen (cs in a terminal) ────────────────────────────────────
# The screen (keys · drawing) runs on the main thread; network and vault work runs on one worker thread, one job at a time.
# The vault lock is only held for the duration of a job — a live screen never blocks another cs (cs jay · cs add).

CHAR_KEYS = {
    '\r': 'enter', '\n': 'enter', 'k': 'up', 'K': 'up', 'ㅏ': 'up', 'j': 'down', 'J': 'down', 'ㅓ': 'down',
    'g': 'home', 'G': 'end', 'q': 'quit', 'Q': 'quit', 'ㅂ': 'quit', 'ㅃ': 'quit', '\x04': 'quit',
    'r': 'refresh', 'R': 'refresh', 'ㄱ': 'refresh', 'ㄲ': 'refresh', '\x0c': 'redraw',
    'a': 'auto', 'A': 'auto', 'ㅁ': 'auto',
}  # the Hangul entries let a Korean 2-set keyboard layout press the same physical keys: ㅏ(k) ㅓ(j) ㅂ(q) ㄱ(r) ㅁ(a)


def esc_key(seq):
    """\\x1b[A · \\x1bOA · \\x1b[1;2A · \\x1b[5~ … → key name."""
    if seq[1:2] == 'O':
        return {'A': 'up', 'B': 'down', 'H': 'home', 'F': 'end', 'M': 'enter'}.get(seq[2:3])
    final = seq[-1:]
    if final in ('A', 'B', 'H', 'F'):
        return {'A': 'up', 'B': 'down', 'H': 'home', 'F': 'end'}[final]
    if final == '~':
        return {'1': 'home', '7': 'home', '5': 'home', '4': 'end', '8': 'end', '6': 'end'}.get(seq[2:-1].split(';')[0])
    return None


def parse_keys(text):
    """Terminal input → list of keys. Digits 1–9 = ('row', n)."""
    keys, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == '\x1b':
            nxt = text[i + 1:i + 2]
            if nxt in ('[', 'O'):
                j = i + 2
                while j < len(text) and not ('\x40' <= text[j] <= '\x7e'):
                    j += 1
                keys.append(esc_key(text[i:j + 1]))
                i = j + 1
            elif nxt == '':
                keys.append('quit')  # a lone Esc
                i += 1
            else:
                i += 2  # Alt+key — ignored
            continue
        keys.append(CHAR_KEYS.get(ch) or (('row', int(ch)) if ch in '123456789' else None))
        i += 1
    return [k for k in keys if k]


def span(sec):
    sec = int(round(sec))
    if sec < 60:
        return f'{sec}s'
    m, s = divmod(sec, 60)
    return f'{m}m' + (f' {s}s' if s else '')


class Screen:
    """Alternate screen + cbreak (one key at a time, no echo) + hidden cursor. Always restored on exit."""

    def __init__(self, fd_in, fd_out):
        self.fd_in, self.fd_out = fd_in, fd_out
        self.saved = termios.tcgetattr(fd_in)
        self.active = False

    def enter(self):
        tty.setcbreak(self.fd_in, termios.TCSANOW)
        self.write('\033[?1049h\033[?25l\033[H\033[2J')
        self.active = True

    def leave(self):
        if not self.active:
            return
        self.active = False
        with contextlib.suppress(OSError):
            self.write('\033[?25h\033[?1049l')
        with contextlib.suppress(termios.error, OSError):
            termios.tcsetattr(self.fd_in, termios.TCSADRAIN, self.saved)

    def write(self, s):
        data = s.encode('utf-8', 'replace')
        while data:
            data = data[os.write(self.fd_out, data):]

    def size(self):
        try:
            return os.get_terminal_size(self.fd_out)
        except OSError:
            return os.terminal_size((120, 40))


class Worker(threading.Thread):
    """Runs usage fetches and switches one at a time. Results go to the done queue; a pipe wakes the screen."""

    def __init__(self, wake_fd):
        super().__init__(name='cs-worker', daemon=True)
        self.jobs, self.done, self.wake_fd = queue.Queue(), queue.Queue(), wake_fd

    def run(self):
        while True:
            job = self.jobs.get()
            if job is None:
                return
            try:
                out = self.do(job)
            except CsError as err:
                out = ('error', job, str(err))
            except Exception as err:  # keep the screen alive
                out = ('error', job, f'{type(err).__name__}: {err}')
            self.done.put(out)
            with contextlib.suppress(OSError):
                os.write(self.wake_fd, b'.')

    def do(self, job):
        """→ ('fetched', job, collect() result, fetch time, messages, auto-switch info or None)"""
        with vault_lock():
            if job[0] == 'fetch':
                return ('fetched', job, collect(job[1]), time.time(), [], None)
            if job[0] == 'auto':
                return self.auto(job)
            entries, oauth, live, _ = prepare()  # 'switch' — re-check the login at this moment, then swap
            target = find_entry(entries, job[1])
            if target is None:
                raise CsError('that account is no longer in the vault — press r to refresh')
            msgs = []
            switch(entries, oauth, live, target, say=msgs.append, show_usage=False)
            return ('fetched', job, collect({job[1]} | ({live} if live else set())), time.time(), msgs, None)

    def auto(self, job):
        """Auto-switch — re-fetch every account first, then decide again on fresh numbers:
        leave a draining account for the first candidate, or move onto the first-in-line account when it is not the
        current one. Nothing happens when the screen's numbers were stale or another cs switched meanwhile."""
        _, seen_live, rates = job
        entries, oauth, live, verified, results, logged_in = snap = collect()
        now = time.time()
        if not live or find_entry(entries, live) is None:
            return ('fetched', job, snap, now, [], {'skip': True})
        s = (results.get(live) or {}).get('usage')
        if not s:
            return ('fetched', job, snap, now, [], {'skip': True})
        labs = labels_for(entries)
        why = need_switch(s, rates if live == seen_live else None, now)
        if why:
            target = auto_target(entries, results, live, now)
            if target is None:
                return ('fetched', job, snap, now, [], {'none': why})
            why = f'{labs[live]} {why}'
        else:
            target = auto_preferred(entries, results, live, None, now)
            if target is None or ekey(target) == live:
                return ('fetched', job, snap, now, [], {'skip': True})
            why = f'{labs[ekey(target)]} {first_in_line_reason(target, results, now)}'
        msgs = []
        switch(entries, oauth, live, target, say=msgs.append, show_usage=False)
        e2, o2, live2, v2, r2, li2 = collect({ekey(target), live})
        merged = dict(results)
        merged.update(r2)
        order_by_reset(e2, merged)
        info = {'from': labs[live], 'to': labs[ekey(target)], 'why': why} if live2 == ekey(target) else {'skip': True}
        return ('fetched', job, (e2, o2, live2, v2, merged, li2), time.time(), msgs, info)


class Watch:
    """State of the live screen — table · cursor · next fetch time per account."""

    def __init__(self):
        self.entries, self.results = [], {}
        self.fetched, self.due, self.backoff = {}, {}, {}  # key → fetch time · next fetch time · backoff (seconds)
        self.live, self.verified, self.logged_in = None, False, True
        self.cursor = None
        self.msgs = []
        self.inflight = 0
        self.switching = None
        self.loaded = False
        self.retry_at = 0.0  # when to retry after the first fetch failed
        self.blocked = False  # is the current account out of quota — announced once, when it happens
        self.bell = False
        self.quitting = False
        # auto-switch
        self.auto = auto_enabled()
        self.auto_lock = AutoLock()
        self.auto_owner = False   # does this screen hold auto.lock (only one live screen switches)
        self.auto_retry_at = 0.0  # when auto-switch is evaluated again
        self.auto_wait = False    # waiting because there was nowhere to go
        self.hist = []            # (time, key, 5-hour used %, weekly used %) — burn rate of the current account
        self.settings_seen = None
        self.log_seen, self.log_cache = None, []

    def submit(self, worker, *job):
        self.inflight += 1
        worker.jobs.put(job)

    def sync_auto(self):
        """Follow the setting (also when another screen or cs auto changed it). Try to take charge when enabled."""
        try:
            m = os.stat(SETTINGS_PATH).st_mtime_ns
        except OSError:
            m = None
        if m != self.settings_seen:
            self.settings_seen = m
            self.auto = auto_enabled()
        if self.auto and not self.auto_owner and not self.quitting:
            self.auto_owner = self.auto_lock.acquire()
            if self.auto_owner:
                self.auto_retry_at, self.auto_wait = 0.0, False
        elif (not self.auto or self.quitting) and self.auto_owner:
            self.auto_lock.release()
            self.auto_owner = False

    def toggle_auto(self):
        on = not self.auto
        try:
            set_auto(on)
        except (OSError, ValueError) as err:
            self.msgs = [c(f'✗ could not save the auto-switch setting: {err}', '1;31')]
            return
        self.settings_seen = None
        self.sync_auto()
        if not on:
            self.msgs = ['Auto-switch off — accounts now change only with Enter.']
        elif self.auto_owner:
            self.msgs = [c('Auto-switch on', '1;32') + ' — while this screen is open, cs keeps the first-in-line account in use and leaves a draining one just before it runs dry.']
        else:
            self.msgs = [c('Auto-switch on', '1;32') + ' — another cs screen is already in charge; this one only watches.']

    def note_sample(self, k, s, t):
        """Collect the current account's values only — to measure its burn rate. Starts over when the current account changes."""
        if not k or not s:
            return
        keep = max(5 * LIVE_EVERY, 30)
        self.hist = [h for h in self.hist if h[1] == k and t - h[0] <= keep]
        self.hist.append((t, k, (s.get('session') or [None])[0], (s.get('weekly') or [None])[0]))

    def rates(self, k):
        """Burn rate of the current account → {'session': % used per second, 'weekly': …} (missing when unknown).
        The faster of "since one check interval ago" and "since a few minutes ago" — so bursts are caught too. Values from
        before a reset are not used."""
        pts = [h for h in self.hist if h[1] == k]
        out = {}
        if len(pts) < 2:
            return out
        last = pts[-1]
        for field, idx in (('session', 2), ('weekly', 3)):
            cur = last[idx]
            if cur is None:
                continue
            best, prev = 0.0, cur
            for h in reversed(pts[:-1]):
                v = h[idx]
                if v is None or v > prev:
                    break  # earlier values are from before a reset
                prev = v
                dt = last[0] - h[0]
                if dt >= 0.8 * LIVE_EVERY:  # percentages are integers — two values too close together only produce noise
                    best = max(best, (cur - v) / dt)
            if best > 0:
                out[field] = best
        return out

    def auto_reason(self, now):
        """"Should the current account be left?" judged from this screen's numbers — only when they are fresh."""
        k = self.live
        s = (self.results.get(k) or {}).get('usage') if k else None
        if not s or now - self.fetched.get(k, 0) > max(3 * LIVE_EVERY, 90):
            return None
        return need_switch(s, self.rates(k), now)

    def auto_due(self, now):
        if not (self.auto and self.auto_owner and self.loaded) or self.switching or self.quitting:
            return False
        if self.auto_reason(now):
            if now >= self.auto_retry_at:
                return True
            # waiting because there was nowhere to go — act as soon as this screen sees an account to go to
            return self.auto_wait and auto_target(self.entries, self.results, self.live, now) is not None
        if now < self.auto_retry_at:
            return False
        pref = auto_preferred(self.entries, self.results, self.live, self.rates(self.live), now)
        return pref is not None and ekey(pref) != self.live

    def on_auto(self, info, msgs, now):
        info = info or {}
        if info.get('to'):
            line = f"{info['from']} → {info['to']} ({info['why']})"
            auto_log_append(line)
            self.msgs = [c(f'⇄ auto-switch: {line}', '1;32')] + msgs[1:]
            self.auto_retry_at, self.auto_wait, self.bell = now + AUTO_COOLDOWN, False, True
        elif info.get('none'):
            if not self.auto_wait:
                self.bell = True
            self.msgs = [c(f'⚠ auto-switch: the current account is almost dry ({info["none"]}) but there is nowhere to go — moving as soon as an account frees up', '33')]
            self.auto_retry_at, self.auto_wait = now + IDLE_EVERY, True
        else:
            self.auto_retry_at = now + AUTO_COOLDOWN

    def next_event(self):
        """Next fetch time — the screen wakes up for it (None when nothing is scheduled)."""
        if self.inflight or self.quitting:
            return None
        if not self.loaded:
            return self.retry_at
        return min((self.due.get(ekey(e), 0) for e in self.entries), default=None)

    def schedule(self, worker, now):
        if self.inflight or self.quitting:
            return
        if not self.loaded:
            if now >= self.retry_at:
                self.submit(worker, 'fetch', None)
            return
        if self.auto_due(now):
            self.submit(worker, 'auto', self.live, self.rates(self.live))
            return
        keys = {ekey(e) for e in self.entries if self.due.get(ekey(e), 0) <= now}
        if keys:
            self.submit(worker, 'fetch', keys)

    def next_due(self, k, r, t):
        if r.get('limited'):  # rate limited — Retry-After, else 5 minutes doubling (max 1 hour)
            b = min(LIMIT_BACKOFF_MAX, max(LIMIT_BACKOFF, self.backoff.get(k, 0) * 2, r.get('retry_after') or 0))
            self.backoff[k] = b
            return t + b
        self.backoff.pop(k, None)
        every = LIVE_EVERY if k == self.live else IDLE_EVERY
        if r.get('error') and r['error'] != EXPIRED:
            every = min(every, 60.0)
        due = t + every
        s = r.get('usage') or {}
        for lim in (s.get('session'), s.get('weekly')):
            rt = future_reset(lim, t)
            if rt and rt + 5 < due:
                due = rt + 5  # look again right after a reset
        return due

    def on_done(self, out, now):
        self.inflight -= 1
        job = out[1]
        if out[0] == 'error':
            self.msgs = [c('✗ ' + out[2], '1;31')]
            if job[0] == 'switch':
                self.switching = None
            elif job[0] == 'auto':
                self.msgs[0] += c(' (auto-switch — retrying shortly)', '2')
                self.auto_retry_at = now + 10
            elif not self.loaded:
                self.retry_at = now + 10
            else:
                for k in (job[1] or {ekey(e) for e in self.entries}):
                    self.due[k] = now + 10
            return
        _, job, snap, t, msgs, info = out
        entries, _, live, verified, results, logged_in = snap
        prev_live = self.live
        self.live, self.verified, self.logged_in = live, verified, logged_in
        if live != prev_live:
            self.hist = []
        self.note_sample(live, (results.get(live) or {}).get('usage'), t)
        keys = {ekey(e) for e in entries}
        for d in (self.results, self.fetched, self.due, self.backoff):
            for k in [k for k in d if k not in keys]:
                del d[k]
        for k, r in results.items():
            self.results[k], self.fetched[k] = r, t
            self.due[k] = self.next_due(k, r, t)
        for k in keys:
            self.due.setdefault(k, 0)  # an account another cs just added is fetched right away
        if self.loaded and live and live != prev_live and live not in results:
            self.due[live] = 0  # switched elsewhere → fetch the new current account right away
        self.entries = entries
        order_by_reset(self.entries, self.results)
        if job[0] == 'switch':
            self.switching = None
            self.msgs = msgs
        elif job[0] == 'auto':
            self.on_auto(info, msgs, now)
        if not self.loaded:
            self.loaded = True
            self.cursor = self.start_cursor(now)
        elif find_entry(self.entries, self.cursor) is None:
            self.cursor = ekey(self.entries[0]) if self.entries else None
        self.check_blocked(now)

    def start_cursor(self, now):
        """Initial cursor = the account to use first (one Enter switches there) → else the current account."""
        ok = usable(shown_rows(self.entries, self.results), now)
        if ok:
            return ekey(ok[0][1])
        if find_entry(self.entries, self.live) is not None:
            return self.live
        return ekey(self.entries[0]) if self.entries else None

    def live_usage(self):
        e = find_entry(self.entries, self.live)
        return usage_of(e, self.results) if e is not None else None

    def check_blocked(self, now):
        """When the current account has just hit a limit: move the cursor to the next usable account + one bell
        (switching is up to the user). When this screen runs auto-switch, that takes care of it instead."""
        s = self.live_usage()
        blocked = bool(s) and blocked_until(s, now) is not None
        if blocked and not self.blocked and not (self.auto and self.auto_owner):
            ok = [x for x in usable(shown_rows(self.entries, self.results), now) if ekey(x[1]) != self.live]
            if ok:
                self.cursor = ekey(ok[0][1])
            self.bell = True
        self.blocked = blocked

    def move(self, key):
        keys = [ekey(e) for e in self.entries]
        if not keys:
            return
        i = keys.index(self.cursor) if self.cursor in keys else 0
        if isinstance(key, tuple):
            if key[1] > len(keys):
                return
            i = key[1] - 1
        else:
            i = {'up': max(0, i - 1), 'down': min(len(keys) - 1, i + 1), 'home': 0, 'end': len(keys) - 1}[key]
        self.cursor = keys[i]

    def enter(self, worker):
        if not self.loaded or self.cursor is None or self.switching:
            return
        labs = labels_for(self.entries)
        if self.cursor == self.live:
            self.msgs = [f'already using {labs[self.cursor]}.']
            return
        self.switching = self.cursor
        self.msgs = [c(f'… switching to {labs[self.cursor]}', '33')]
        self.submit(worker, 'switch', self.cursor)

    def refresh_now(self, now):
        labs, waiting = labels_for(self.entries), []
        for e in self.entries:
            k = ekey(e)
            if self.backoff.get(k) and self.due.get(k, 0) > now:
                waiting.append(f'{labs[k]} in {span(self.due[k] - now)}')  # rate-limited accounts keep waiting
            else:
                self.due[k] = 0
        self.msgs = [c('rate limited, still waiting: ' + ' · '.join(waiting), '33')] if waiting else []

    def blocked_line(self, now):
        if not self.blocked:
            return ''
        labs = labels_for(self.entries)
        t = blocked_until(self.live_usage() or {}, now)
        line = c(f'⚠ the current account {label_of(labs, self.live)} has hit a limit', '1;31')
        if t not in (None, float('inf')):
            line += c(f' (frees up at {when_ts(t)})', '31')
        if self.auto and self.auto_owner:
            line += c(' — nowhere to go yet, waiting' if self.auto_wait else ' — auto-switch is moving', '1')
            return line
        ok = {ekey(x[1]) for x in usable(shown_rows(self.entries, self.results), now)}
        if self.cursor in ok and self.cursor != self.live:
            line += c(f' — Enter switches to {labs[self.cursor]}', '1')
        return line

    def auto_line(self, cols, now):
        """Third header line — auto-switch state and where it goes next."""
        if not self.auto:
            return c('Auto-switch off — press a to keep the first-in-line account in use and leave a draining one just before it runs dry', '2')
        head = c('Auto-switch on', '1;32')
        if not self.auto_owner:
            return head + c(' — another cs screen is in charge (this one only watches)', '2')
        labs = labels_for(self.entries) if self.entries else {}
        if not self.loaded or find_entry(self.entries, self.live) is None:
            return head + c(' — checking the current account', '2')
        name = label_of(labs, self.live)
        pref = auto_preferred(self.entries, self.results, self.live, self.rates(self.live), now)
        if pref is not None and ekey(pref) != self.live:
            return head + c(' — ', '2') + c(labs[ekey(pref)], '1') + c(f' is {first_in_line_reason(pref, self.results, now)} → moving there', '2')
        tgt = auto_target(self.entries, self.results, self.live, now)
        if tgt is None:
            return head + c(f' — {name} is first in line · nowhere to go when it runs low (will move as soon as an account frees up)', '33')
        cond = '' if cols < 120 else f' (≤{AUTO_FLOOR:g}% left, or draining fast enough to hit 0 before the next check)'
        return head + c(f' — {name} is first in line · when it runs low{cond} → ', '2') + c(labs[ekey(tgt)], '1')

    def log_lines(self):
        """Auto-switch log (last 3 lines within a day) — read from the file so moves by other screens show too."""
        try:
            m = os.stat(AUTO_LOG_PATH).st_mtime_ns
        except OSError:
            return []
        if m != self.log_seen:
            self.log_seen, self.log_cache = m, auto_log_tail(3)
        if not self.log_cache:
            return []
        return [c('auto-switch log', '2')] + [c(f'  {when_ts(t)}  {text}', '2') for t, text in self.log_cache]

    def frame(self, cols, now):
        clock = local_dt(now)
        sub = c(f'current account every {span(LIVE_EVERY)} · others every {span(IDLE_EVERY)}', '2')
        if self.inflight and not self.switching:
            sub += c(' · fetching…', '33')
        lines = [c('Claude accounts · remaining usage', '1') + c(' · soonest weekly reset first', '1;36')
                 + c(f'   {clock:%H:%M:%S}', '2'), sub, self.auto_line(cols, now), '']
        if not self.loaded:
            lines.append(c('fetching usage…', '2'))
        elif not self.entries:
            lines.append('No accounts stored yet — quit with q and run cs add to sign in.')
        else:
            ages = {k: now - t for k, t in self.fetched.items()}
            grid, notes = fitted_table(cols, self.entries, self.live, self.verified, self.results, self.logged_in,
                                       pointer=True, cursor=self.cursor, ages=ages, now_s=now)
            lines += grid + notes
            if len(self.entries) == 1:
                lines.append(c('To add another account, quit with q and run cs add — it will show up here.', '2'))
        log = self.log_lines()
        if log:
            lines += [''] + log
        warn = self.blocked_line(now)
        if warn:
            lines += ['', warn]
        if self.msgs:
            lines += [''] + self.msgs
        lines += ['', c('↑↓ select · Enter switch · a auto-switch on/off · r refresh · q quit', '2')]
        if self.quitting:
            lines.append(c('finishing the current fetch before quitting…', '33'))
        return lines


def fit_rows(lines, cols, rows):
    """Cut lines that do not fit the screen height (overflow scrolls the screen and garbles redraws). Long lines wrap and use several rows."""
    out, used = [], 0
    for line in lines:
        need = max(1, -(-dwidth(line) // max(1, cols)))
        if used + need > rows - 1:
            break
        out.append(line)
        used += need
    return out


def watch():
    """cs (in a terminal) — the live screen. Leaves the last table on the normal screen when it exits."""
    fd_in, fd_out = sys.stdin.fileno(), sys.stdout.fileno()
    scr = Screen(fd_in, fd_out)
    wake_r, wake_w = os.pipe()
    os.set_blocking(wake_r, False)
    os.set_blocking(wake_w, False)
    worker, w = Worker(wake_w), Watch()
    decoder = codecs.getincrementaldecoder('utf-8')('ignore')
    st = {'clear': True, 'eof': False, 'force': False}

    def wake(*_):
        with contextlib.suppress(OSError):
            os.write(wake_w, b'!')

    def on_winch(*_):
        st['clear'] = True
        wake()

    def on_term(signum, _):
        raise SystemExit(128 + signum)

    def on_tstp(*_):  # Ctrl-Z — restore the terminal, stop, and redraw when resumed with fg
        scr.leave()
        signal.signal(signal.SIGTSTP, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGTSTP)
        signal.signal(signal.SIGTSTP, on_tstp)
        scr.enter()
        st['clear'] = True

    def handle(key):
        if key == 'quit':
            st['force'] = w.quitting  # a second quit while quitting → leave right away
            w.quitting = True
        elif key == 'enter':
            w.enter(worker)
        elif key == 'auto':
            if not w.quitting:
                w.toggle_auto()
        elif key == 'refresh':
            w.refresh_now(time.time())
        elif key == 'redraw':
            st['clear'] = True
        elif not w.quitting:
            w.move(key)

    def step():
        now = time.time()
        w.sync_auto()
        w.schedule(worker, now)
        if w.quitting and (not w.inflight or st['force']):
            return False
        size = scr.size()
        frame = fit_rows(w.frame(size.columns, now), size.columns, size.lines)
        out = ('\033[2J' if st['clear'] else '') + '\033[H' + '\033[K\n'.join(frame) + '\033[K\033[J'
        st['clear'] = False
        if w.bell:
            out, w.bell = out + '\a', False
        try:
            scr.write(out)
        except OSError:  # the terminal is gone
            st['eof'] = w.quitting = True
            return True
        watch_fds = [wake_r] + ([] if st['eof'] else [fd_in])
        now = time.time()
        timeout = 1.0 - (now % 1.0)  # the clock ticks every second
        nxt = w.next_event()
        if nxt is not None:
            timeout = min(timeout, nxt - now)  # wake up earlier for a scheduled fetch
        ready, _, _ = select.select(watch_fds, [], [], max(0.02, timeout))
        if fd_in in ready:
            try:
                data = os.read(fd_in, 1024)
            except OSError:
                data = b''
            if not data:
                st['eof'] = w.quitting = True
            else:
                if data.endswith(b'\x1b'):  # a lone Esc, or the start of an arrow-key sequence? wait a moment
                    more, _, _ = select.select([fd_in], [], [], 0.05)
                    if more:
                        data += os.read(fd_in, 1024)
                for key in parse_keys(decoder.decode(data)):
                    handle(key)
        if wake_r in ready:
            with contextlib.suppress(BlockingIOError, OSError):
                os.read(wake_r, 4096)
        while True:
            try:
                done = worker.done.get_nowait()
            except queue.Empty:
                break
            w.on_done(done, time.time())
        return True

    old = {sig: signal.signal(sig, fn) for sig, fn in (
        (signal.SIGWINCH, on_winch), (signal.SIGHUP, on_term), (signal.SIGTERM, on_term), (signal.SIGTSTP, on_tstp))}
    worker.start()
    try:
        scr.enter()
        while True:
            try:
                if not step():
                    break
            except KeyboardInterrupt:  # Ctrl-C = q (twice → right away)
                st['force'] = w.quitting
                w.quitting = True
    finally:
        worker.jobs.put(None)
        # finish the running job — an idle account whose token was just rotated must be saved, or it needs a new login
        worker.join(timeout=3 if st['force'] else 60)
        w.auto_lock.release()  # let another screen take over auto-switch
        scr.leave()
        for sig, fn in old.items():
            with contextlib.suppress(OSError, ValueError, TypeError):
                signal.signal(sig, fn)
        for fd in (wake_r, wake_w):
            with contextlib.suppress(OSError):
                os.close(fd)
    if w.loaded and w.entries:  # leave the last table visible after exit
        render(w.entries, w.live, w.verified, w.results, w.logged_in)
    for m in w.msgs:
        print(m)
    return 0


def interactive():
    return sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get('TERM', '') not in ('', 'dumb')


HELP = f"""cs — Claude subscription accounts: remaining usage + switching (the login every claude on this machine uses)

  cs              live screen — keeps refreshing usage (current account every {span(LIVE_EVERY)} · others every {span(IDLE_EVERY)})
                  ↑↓ (or digits) select · Enter switch · a auto-switch on/off · r refresh · q quit
                  rows: soonest weekly reset first — whatever is left at the reset is lost, so use the top row first (→ Use first)
                  Left/Total = weekly limits scaled so one Max 20x week = 100 (a 5x seat ≈ 29 · estimate) + a Total row
  cs ls           print the table once (cs does this too when it is not in a terminal)
  cs <n|name>     switch to that account (e.g. cs 2 · cs joe · cs jay-team)
                  numbers follow the table order and change after a reset — use the name when you have not just seen the table
  cs add [email]  log a new account in and store it — use this instead of /login so the current account is not lost
  cs auto [on|off] show, enable or disable auto-switch (same as a on the live screen)
  cs keep         run the live screen inside tmux — survives closed windows and dropped SSH sessions (run again to re-attach)
  cs help         this help

auto-switch: while a live cs screen is open it keeps the first-in-line account (soonest weekly reset) in use, and leaves a
         draining account just before it runs dry (≤{AUTO_FLOOR:g}% left, or draining fast enough to hit 0 before the next check)
         for the next account in line. It never moves onto an account with extra usage enabled, or one with ≤{AUTO_MIN:g}% left.
         Nothing moves while no screen is open — keep one running with cs keep. Log: ~/.claude-accounts/auto-switch.log

team seats: if an email has both a personal subscription and a team seat, run cs add once more and choose the team when
         the browser asks for an organization. The seat is stored separately as <name>-team; the personal entry stays.
from another machine:  ssh -t <host> '~/.local/bin/cs'
macOS:   the login is the keychain item "Claude Code-credentials" (what claude itself uses); cs reads and writes it with the
         security tool, so running claude sessions follow a switch within about 30 seconds. cs keep needs tmux (brew install tmux).
vault: ~/.claude-accounts (contains login tokens — do not copy it elsewhere)
note: never use /logout inside claude — it can invalidate the stored login of that account."""


def main(argv):
    args = argv[1:]
    if args and args[0] in ('-h', '--help', 'help'):
        print(HELP)
        return 0
    if args and args[0] == 'auto':
        arg = args[1].lower() if len(args) > 1 else ''
        if arg in ('on', '1', 'true'):
            set_auto(True)
        elif arg in ('off', '0', 'false'):
            set_auto(False)
        elif arg:
            raise CsError('usage: cs auto on · cs auto off · cs auto (show the current setting)')
        print(auto_status_line())
        return 0
    if args and args[0] == 'keep':
        return keep()
    if not args and interactive():
        return watch()  # the worker takes the vault lock per job only
    with vault_lock():
        if args and args[0] in ('add', 'login'):
            return add(args[1] if len(args) > 1 else None)
        if args and args[0] in ('ls', 'list') and len(args) == 1:
            entries, _, _, _ = status(show=True)
            if len(entries) < 2:
                print(c('Only one account stored — sign another one in with cs add and it shows up here.', '2'))
            return 0
        if args:
            entries, oauth, live, _ = prepare()
            return switch(entries, oauth, live, pick(entries, ' '.join(args)))
        entries, oauth, live, _ = status(show=True)
        if len(entries) < 2:
            print(c('Only one account stored — sign another one in with cs add and it shows up here.', '2'))
            return 0
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return 0
        # a plain terminal such as TERM=dumb — ask for a number or name instead of the live screen
        try:
            ans = input('\nSwitch to (number or name, Enter = keep): ').strip()
        except EOFError:
            return 0
        if not ans:
            return 0
        return switch(entries, oauth, live, pick(entries, ans))


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except CsError as err:
        print(c(f'✗ {err}', '1;31'), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(130)
