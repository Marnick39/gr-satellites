#!/usr/bin/env python3
"""F26 — Path.mkdir() without exist_ok races on concurrent start.

Two threads racing into the unpatched mkdir() — the second one hits
FileExistsError, which propagates up through open_config() and crashes
the flowgraph construction.

Run:
    python3 poc_F26_mkdir_race.py
"""

import os
import tempfile
import threading
from pathlib import Path


# ----------------------------------------------------------------------
# Verbatim from python/utils/config.py:21-28 pre-F26 fix
# ----------------------------------------------------------------------
def open_config_unpatched(config_dir_path):
    config_dir = Path(config_dir_path) / '.gr_satellites'
    if not config_dir.exists():
        Path.mkdir(config_dir)


def open_config_patched(config_dir_path):
    config_dir = Path(config_dir_path) / '.gr_satellites'
    config_dir.mkdir(mode=0o700, exist_ok=True)


def race(target, basedir, results, idx):
    try:
        target(basedir)
        results[idx] = 'ok'
    except FileExistsError as e:
        results[idx] = f'FileExistsError: {e}'
    except OSError as e:
        results[idx] = f'OSError: {e}'


def main():
    print('=== F26 PoC — concurrent mkdir race ===')
    print()
    for label, target in [('unpatched', open_config_unpatched),
                          ('patched', open_config_patched)]:
        # Run the race multiple times since timing matters
        fired = 0
        for trial in range(8):
            with tempfile.TemporaryDirectory() as td:
                results = ['?', '?']
                a = threading.Thread(target=race,
                                     args=(target, td, results, 0))
                b = threading.Thread(target=race,
                                     args=(target, td, results, 1))
                # Start both as close together as possible
                a.start()
                b.start()
                a.join()
                b.join()
                if any('FileExistsError' in r for r in results):
                    fired += 1
        print(f'  {label}: FileExistsError fired in {fired}/8 trials')


if __name__ == '__main__':
    main()
