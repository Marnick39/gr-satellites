#!/usr/bin/env python3
"""F27 — ~/.gr_satellites/ parent dir is world-traversable.

Same root cause as F16 but at the directory level: the unpatched
mkdir() respects the default umask, producing mode 0o755 on the
parent dir. That lets any other user reach config.ini even if the
file itself is later tightened.

Run:
    python3 poc_F27_dir_traversable.py
"""

import os
import stat
import tempfile
from pathlib import Path


def mkdir_unpatched(parent):
    d = Path(parent) / '.gr_satellites'
    Path.mkdir(d)
    return d


def mkdir_patched(parent):
    d = Path(parent) / '.gr_satellites'
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def main():
    os.umask(0o022)
    print('=== F27 PoC — parent dir mode under default umask ===')
    print(f'  current umask: {oct(0o022)}')
    print()
    with tempfile.TemporaryDirectory() as td_unpatched:
        d_unpatched = mkdir_unpatched(td_unpatched)
        mode_unpatched = stat.S_IMODE(os.stat(d_unpatched).st_mode)
        traversable = bool(mode_unpatched & 0o001)
        print(f'  unpatched: mode {oct(mode_unpatched)} '
              f'(world-traversable: {traversable})')
    with tempfile.TemporaryDirectory() as td_patched:
        d_patched = mkdir_patched(td_patched)
        mode_patched = stat.S_IMODE(os.stat(d_patched).st_mode)
        traversable = bool(mode_patched & 0o001)
        print(f'  patched:   mode {oct(mode_patched)} '
              f'(world-traversable: {traversable})')

    if mode_unpatched & 0o007:
        print()
        print(f'  [PASS] F27 confirmed: unpatched mode {oct(mode_unpatched)}'
              ' allows other users to reach inside the directory.')


if __name__ == '__main__':
    main()
