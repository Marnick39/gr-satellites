#!/usr/bin/env python3
"""F15 — submit_tlm default contradicts the documentation.

No GNU Radio needed. Invokes the verbatim write_default_config() body
from python/utils/config.py against a tempdir and asserts the written
value is 'yes' (opt-in by default), contradicting docs/source/
command_line.rst which shows 'no' in the example.

Run:
    python3 poc_F15_default.py
"""

import configparser
import os
import tempfile

# ----------------------------------------------------------------------
# Verbatim from src/python/utils/config.py (pre-F15 fix)
# ----------------------------------------------------------------------
def write_default_config_unpatched(file):
    config = configparser.ConfigParser()
    config['Groundstation'] = {
        'callsign': '',
        'latitude': 0,
        'longitude': 0,
        'submit_tlm': 'yes',     # <-- F15: docs show 'no'
    }
    config['FUNcube'] = {'site_id': '', 'auth_code': ''}
    config['PW-Sat2'] = {'credentials_file': ''}
    config['BME'] = {'user': '', 'password': ''}
    with open(file, 'w') as f:
        config.write(f)
    return config


def main():
    with tempfile.TemporaryDirectory() as td:
        ini = os.path.join(td, 'config.ini')
        write_default_config_unpatched(ini)
        with open(ini) as f:
            for line in f:
                if line.startswith('submit_tlm'):
                    val = line.split('=', 1)[1].strip()
                    print(f'  default value of submit_tlm: {val!r}')
                    if val == 'yes':
                        print('  [PASS] F15 confirmed: default contradicts docs')
                        print('  ', '-' * 60)
                        print('  Documentation example at',
                              'docs/source/command_line.rst:531 shows',
                              "submit_tlm = no")
                        print('  Operators who follow the docs and expect',
                              'opt-out-by-default get opt-in-by-default.')
                        return
        print('  [FAIL] could not find submit_tlm in the written file')


if __name__ == '__main__':
    main()
