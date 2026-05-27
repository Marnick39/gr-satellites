#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2019 Daniel Estevez <daniel@destevez.net>
#
# This file is part of gr-satellites
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import configparser
import os
import stat
from pathlib import Path


def open_config():
    """
    Opens and returns the gr-satellites config .ini file

    If the ini file does not exist, it creates a default one
    """
    config_dir = Path.home() / '.gr_satellites'
    config_filename = config_dir / 'config.ini'

    # Audit finding F26: exist_ok=True so two concurrent gr-satellites
    # starts do not race into FileExistsError. Audit finding F27: mode
    # 0o700 so the parent is not world-traversable on a shared host.
    config_dir.mkdir(mode=0o700, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except OSError:
        pass

    if not config_filename.exists():
        return write_default_config(config_filename)

    # Audit finding F16: tighten any pre-existing config that was created
    # with the default umask 0o644 by an older gr-satellites.
    try:
        current = stat.S_IMODE(os.stat(config_filename).st_mode)
        if current & 0o077:
            os.chmod(config_filename, 0o600)
    except OSError:
        pass

    config = configparser.ConfigParser()
    config.read(config_filename)
    return config


def write_default_config(file):
    """
    Writes a default configuration and returns the
    default configuration values.

    Args:
        file: the filename to write to
    """
    config = configparser.ConfigParser()
    config['Groundstation'] = {
        'callsign': '',
        'latitude': 0,
        'longitude': 0,
        # Audit finding F15: default 'no' — opt in explicitly rather than
        # exporting the operator's coordinates and frame contents to the
        # public SatNOGS DB without their knowledge. The example value
        # in docs/source/command_line.rst already shows 'no'.
        'submit_tlm': 'no',
    }

    config['FUNcube'] = {
        'site_id': '',
        'auth_code': '',
    }

    config['PW-Sat2'] = {
        'credentials_file': '',
    }

    config['BME'] = {
        'user': '',
        'password': '',
    }

    # Audit finding F16: create the file with mode 0o600 atomically so
    # the credentials are never readable by other local users, even for
    # the brief window between create and the eventual chmod.
    fd = os.open(str(file),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                 0o600)
    with os.fdopen(fd, 'w') as f:
        config.write(f)

    return config
