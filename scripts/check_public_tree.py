#!/usr/bin/env python3
"""Check staged/tracked publication files without reading private app state."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DENIED_DIRS = {'.venv', '__pycache__', '.pytest_cache', '.private', '.runtime', 'exports', 'state', 'dist'}
DENIED_NAMES = {'keys.json', 'identity.json', 'config.json', 'active-profile.json', 'claude_desktop_config.json'}
DENIED_SUFFIXES = {'.db', '.sqlite', '.sqlite3', '.dat', '.log', '.pdf', '.png', '.jpg', '.jpeg', '.mp4', '.mov', '.pem', '.key', '.p12'}
NATIVE = 'sender/src/wechat_sender/native_pipeline.dylib'

def check():
    listing = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    paths = [Path(item) for item in listing if item]
    if not paths:
        raise SystemExit('No staged or tracked files. Stage the public snapshot first.')
    problems = []
    for relative in paths:
        path = ROOT / relative
        if path.is_symlink():
            problems.append((str(relative), 'symlink'))
            continue
        if (DENIED_DIRS.intersection(relative.parts) or relative.name in DENIED_NAMES
                or relative.suffix.lower() in DENIED_SUFFIXES
                or any(part.endswith('.app') for part in relative.parts)
                or relative.name.startswith('.env')):
            problems.append((str(relative), 'private/generated file type'))
        if not path.is_file():
            problems.append((str(relative), 'missing tracked file'))
            continue
        content = path.read_bytes()
        if b'\0' in content and relative.as_posix() != NATIVE:
            problems.append((str(relative), 'unexpected binary'))
        text = content.decode('utf-8', errors='ignore')
        if re.search(r'/Users/(?!<[^>]+>/|someone/)[A-Za-z0-9._-]+/', text):
            problems.append((str(relative), 'non-placeholder home path'))
        if re.search(r'wxid_(?!fictional(?:_|\b))[A-Za-z0-9]+', text):
            problems.append((str(relative), 'non-fixture account identifier'))
    profile = json.loads((ROOT/'sender/src/wechat_sender/profiles/wechat-4.1.15-270135-arm64.json').read_text())
    if any(profile.get(key) is not False for key in ('runtime_verified', 'sending_permitted', 'send_framing_verified')):
        problems.append(('sender profile', 'public send gate enabled'))
    if profile['native_pipeline'].get('enabled') is not False:
        problems.append(('sender profile', 'public native gate enabled'))
    digest = hashlib.sha256((ROOT/NATIVE).read_bytes()).hexdigest()
    if profile['native_pipeline']['library_sha256'] != digest:
        problems.append((NATIVE, 'profile hash mismatch'))
    if (ROOT/'LICENSE').read_bytes() != (ROOT/'sender/LICENSE').read_bytes():
        problems.append(('LICENSE', 'sender/root license mismatch'))
    for path, problem in problems:
        print(f'{path}: {problem}', file=sys.stderr)
    if problems:
        raise SystemExit(1)
    print(f'Public tree check passed: {len(paths)} files; disabled profile and native hash verified.')

if __name__ == '__main__':
    check()
