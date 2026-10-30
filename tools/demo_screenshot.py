#!/usr/bin/env python3
"""Render assets/screenshot.png — the live screen on a fake vault (no real accounts or tokens involved).

Reuses the fake API server from test_cs.py, seeds four demo accounts, runs cs on a pty with auto-switch on,
grabs the last fully drawn frame and paints it with Pillow (DejaVu Sans Mono).

  python3 tools/demo_screenshot.py [out.png]
"""
import json
import os
import re
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import test_cs as T  # noqa: E402

from PIL import Image, ImageDraw, ImageFont  # noqa: E402

FONT_DIR = '/usr/share/fonts/truetype/dejavu'
PALETTE = {'fg': (214, 219, 226), 'bg': (17, 20, 26), 'dim': (120, 128, 140),
           '31': (240, 92, 92), '32': (96, 211, 120), '33': (235, 196, 76), '36': (86, 203, 230)}


def seed(home, base):
    """Four accounts: alice (weekly resets soonest) · bob · carol (current) · carol-team (5x seat)."""
    T.S.t0 = time.time()
    AL, BO, CA = 'alice@example.com', 'bob@example.com', 'carol@example.com'
    ORG = '7640a7c9-2222-4333-8444-955566667777'
    T.S.orgs[ORG] = {'name': 'Acme', 'type': 'claude_team'}
    T.S.usage = {AL: (0, 52, 40), BO: (100, 17, 10), CA: (15, 3, 5), (CA, ORG): (0, 0, None)}
    T.S.resets = {AL: (5 * 3600 + 2 * 60, 5 * 3600 + 47 * 60), BO: (1 * 3600 + 50 * 60, 5 * 86400 + 20 * 3600),
                  CA: (4 * 3600 + 40 * 60, 6 * 86400 + 3 * 3600), (CA, ORG): (3600, 6 * 86400 + 5 * 3600)}
    at, rt = T.S.issue(CA)
    T.write_live(home, CA, at, rt)
    accounts = os.path.join(home, '.claude-accounts', 'accounts')
    os.makedirs(accounts, mode=0o700)
    now = int(time.time() * 1000)
    for email, org, tier, sub in ((AL, None, 'default_claude_max_20x', 'max'), (BO, None, 'default_claude_max_20x', 'max'),
                                  (CA, ORG, 'default_claude_max_5x', 'team')):
        a, r = T.S.issue(email, org)
        entry = {'email': email, 'savedAt': now,
                 'claudeAiOauth': {'accessToken': a, 'refreshToken': r, 'expiresAt': now + 8 * 3600000,
                                   'scopes': ['user:inference', 'user:profile'], 'subscriptionType': sub, 'rateLimitTier': tier},
                 'oauthAccount': {'accountUuid': 'u-' + email, 'emailAddress': email}}
        if org:
            entry['org'] = org
            entry['oauthAccount'].update(organizationUuid=org, organizationName='Acme', organizationType='claude_team')
        name = email + ('--' + org[:8] if org else '') + '.json'
        with open(os.path.join(accounts, name), 'w') as f:
            json.dump(entry, f)
    with open(os.path.join(home, '.claude-accounts', 'settings.json'), 'w') as f:
        json.dump({'autoSwitch': True}, f)


def capture(home, base, cols=118, rows=34):
    env = dict(os.environ, HOME=home, CS_API_BASE=base, CS_TOKEN_URL=base + '/v1/oauth/token', TERM='xterm-256color',
               CS_INTERVAL='1', CS_IDLE_INTERVAL='4', CS_AUTO_COOLDOWN='1', TZ='Asia/Seoul')
    env.pop('NO_COLOR', None)
    t = T.Tui(env, cols=cols, rows=rows)
    t.wait(lambda f: 'auto-switch: carol → alice' in f and 'when it runs low' in f, 30)
    t.idle(1.5)
    raw = t.raw.decode('utf-8', 'replace')
    t.send('q')
    t.finish()
    end = raw.rfind('\x1b[J')
    start = raw.rfind('\x1b[H', 0, end)
    return raw[start + 3:end].replace('\x1b[K', '')


SGR = re.compile(r'\x1b\[([0-9;]*)m')


def runs(line):
    """ANSI line → [(text, fg, bold, inverse)]."""
    out, pos = [], 0
    st = {'fg': 'fg', 'bold': False, 'inv': False, 'dim': False}
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], dict(st)))
        for code in (m.group(1) or '0').split(';'):
            if code in ('', '0'):
                st.update(fg='fg', bold=False, inv=False, dim=False)
            elif code == '1':
                st['bold'] = True
            elif code == '2':
                st['dim'] = True
            elif code == '7':
                st['inv'] = True
            elif code in PALETTE:
                st['fg'] = code
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], dict(st)))
    return out


def paint(frame, out_path, size=15):
    mono = ImageFont.truetype(os.path.join(FONT_DIR, 'DejaVuSansMono.ttf'), size)
    bold = ImageFont.truetype(os.path.join(FONT_DIR, 'DejaVuSansMono-Bold.ttf'), size)
    fallback = ImageFont.truetype(os.path.join(FONT_DIR, 'DejaVuSans.ttf'), size)
    cw = mono.getlength('M')
    lh = int(size * 1.45)
    lines = frame.split('\n')
    while lines and not SGR.sub('', lines[-1]).strip():
        lines.pop()
    width = int(max(len(SGR.sub('', ln)) for ln in lines) * cw) + 48
    img = Image.new('RGB', (width, lh * len(lines) + 40), PALETTE['bg'])
    d = ImageDraw.Draw(img)
    for row, ln in enumerate(lines):
        x, y = 24, 20 + row * lh
        for text, st in runs(ln):
            fg = PALETTE['dim'] if st['dim'] else PALETTE[st['fg']]
            bg = None
            if st['inv']:
                fg, bg = PALETTE['bg'], (fg if st['fg'] != 'fg' else PALETTE['fg'])
            font = bold if st['bold'] else mono
            for ch in text:
                if bg:
                    d.rectangle([x, y - 2, x + cw, y + lh - 2], fill=bg)
                f = fallback if ch in '⚠' else font
                d.text((x, y), ch, font=f, fill=fg)
                x += cw
    img.save(out_path)
    return out_path


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'assets', 'screenshot.png')
    srv = ThreadingHTTPServer(('127.0.0.1', 0), T.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{srv.server_port}'
    home = tempfile.mkdtemp(prefix='cs-demo-')
    os.makedirs(os.path.join(home, '.claude'))
    seed(home, base)
    frame = capture(home, base)
    print(SGR.sub('', frame))
    print(paint(frame, out))
    srv.shutdown()


if __name__ == '__main__':
    main()
