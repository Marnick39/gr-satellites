#!/usr/bin/env python3
"""F16 — config.ini world-readable on multi-user hosts.

Reimplements the unpatched config-write flow from
python/utils/config.py:35-66 against a temp dir, then asserts the
resulting mode is 0o644 under the default umask 0o022 — which means
any other unprivileged user on the same Unix host can read the BME
password, FUNcube auth_code, and PW-Sat2 credentials path.

Run:
    python3 poc_F16_world_readable.py
"""

import configparser
import os
import stat
import tempfile


def write_default_config_unpatched(file):
    """Verbatim from python/utils/config.py pre-F16 fix."""
    config = configparser.ConfigParser()
    config['Groundstation'] = {
        'callsign': '',
        'submit_tlm': 'yes',
    }
    config['FUNcube'] = {
        'site_id': 'OPERATOR_SITE_ID',
        'auth_code': 'FUNCUBE_TOKEN_DEADBEEF',
    }
    config['BME'] = {
        'user': 'OPERATOR_BME_USER',
        'password': 'HUNTER2_SECRET',
    }
    with open(file, 'w') as f:
        config.write(f)


def write_default_config_patched(file):
    """Verbatim from python/utils/config.py post-F16 fix."""
    fd = os.open(str(file),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                 0o600)
    config = configparser.ConfigParser()
    config['Groundstation'] = {'callsign': '', 'submit_tlm': 'no'}
    config['FUNcube'] = {
        'site_id': 'OPERATOR_SITE_ID',
        'auth_code': 'FUNCUBE_TOKEN_DEADBEEF',
    }
    config['BME'] = {
        'user': 'OPERATOR_BME_USER',
        'password': 'HUNTER2_SECRET',
    }
    with os.fdopen(fd, 'w') as f:
        config.write(f)


def main():
    print('=== F16 PoC — config file mode under default umask ===')
    print(f'  current umask: {oct(os.umask(0o022))}')
    os.umask(0o022)

    with tempfile.TemporaryDirectory() as td:
        ini_a = os.path.join(td, 'config_unpatched.ini')
        ini_b = os.path.join(td, 'config_patched.ini')
        write_default_config_unpatched(ini_a)
        write_default_config_patched(ini_b)

        mode_a = stat.S_IMODE(os.stat(ini_a).st_mode)
        mode_b = stat.S_IMODE(os.stat(ini_b).st_mode)
        print(f'  unpatched: mode {oct(mode_a)}  (world-readable: '
              f'{bool(mode_a & 0o004)})')
        print(f'  patched:   mode {oct(mode_b)}  (world-readable: '
              f'{bool(mode_b & 0o004)})')

        if mode_a & 0o077:
            print()
            print('  [PASS] F16 confirmed: unpatched mode '
                  f'{oct(mode_a)} exposes credentials to other local users.')
            print('  Realistic affected populations: university/club ground'
                  ' stations on shared Pi/workstation, multi-user citizen-'
                  'science VPS receivers, shared lab Pis with secondary'
                  ' accounts.')


if __name__ == '__main__':
    main()
