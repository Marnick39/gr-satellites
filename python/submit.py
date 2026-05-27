#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2017,2020 Daniel Estevez <daniel@destevez.net>
#
# This file is part of gr-satellites
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import datetime
import sys
import urllib.error
import urllib.parse
import urllib.request

from gnuradio import gr
import pmt
import numpy


def parse_timestamp(s):
    t = None
    t_tz_frac = None
    if sys.version_info < (3, 11):
        # In Python 3.10, fromisoformat() does not accept a trailing Z, and it
        # can only parse millisecond resolution. If there is fractional part,
        # we remove any trailing Z, and parse the fractional seconds
        # separately. Python 3.10 does not support fractional seconds in the
        # timezone, so this is also handled separately.
        s = s.rstrip('Z')
        if '+' in s:
            # s has a timezone
            s, s_tz = s.split('+')
            if '.' in s_tz:
                # The timezone has a fractional seconds part. The fractional
                # part is incorporated back near the end of this function.
                s_tz, s_tz_frac = s_tz.split('.')
                t_tz_frac = float(f'0.{s_tz_frac}')
        else:
            s_tz = None
        if '.' in s:
            # s has a fractional seconds part
            s_int, s_frac = s.split('.')
            if s_tz is not None:
                # Put back the timezone in s_int
                s_int = f'{s_int}+{s_tz}'
            t_int = datetime.datetime.fromisoformat(s_int)
            t_frac = float(f'0.{s_frac}')
            # Truncate t_frac to integer microseconds to match behaviour of
            # fromisoformat() in newer Python version
            t = t_int + datetime.timedelta(
                microseconds=int(t_frac * 1000000))
        elif s_tz is not None:
            # Put back the timezone in s
            s = f'{s}+{s_tz}'
    if t is None:
        t = datetime.datetime.fromisoformat(s)
    if t_tz_frac is not None:
        t -= datetime.timedelta(microseconds=int(t_tz_frac * 1000000))
    if t.tzinfo is None:
        # The default timezone for this function is UTC
        t = t.replace(tzinfo=datetime.timezone.utc)
    else:
        # Make sure that we are returning a datetime object for the UTC
        # timezone, to avoid surprises by mixing timezones in downstream code
        t = t.astimezone(datetime.timezone.utc)
    return t


class submit(gr.basic_block):
    """docstring for block submit"""
    def __init__(self, url, noradID, source,
                 longitude, latitude, initialTimestamp):
        gr.basic_block.__init__(
            self,
            name='submit',
            in_sig=[],
            out_sig=[])

        self.url = url
        # Audit finding F21: keep the numeric lat/lon separately so we can
        # actually compare them to 0 below. The previous code only stored
        # the stringified versions ('0.0E' / '0.0N'), making the
        # "operator left coordinates at default" guard always false.
        self._latitude = float(latitude)
        self._longitude = float(longitude)
        self.request = {
            'noradID': noradID,
            'source': source,
            'locator': 'longLat',
            'longitude': str(
                abs(longitude)) + ('E' if longitude >= 0 else 'W'),
            'latitude': str(
                abs(latitude)) + ('N' if latitude >= 0 else 'S'),
            'version': '1.6.6',
            }
        self.initialTimestamp = (
            parse_timestamp(initialTimestamp)
            if initialTimestamp != '' else None)
        self.startTimestamp = datetime.datetime.now(tz=datetime.timezone.utc)

        self.message_port_register_in(pmt.intern('in'))
        self.set_msg_handler(pmt.intern('in'), self.handle_msg)

    def handle_msg(self, msg_pmt):
        # Check that callsign and QTH have been entered. Operators leaving
        # their coordinates at the default are explicitly opting out of
        # publishing their station location.
        if self.request['source'] == '':
            return
        if self._longitude == 0.0 and self._latitude == 0.0:
            return

        msg = pmt.cdr(msg_pmt)
        if not pmt.is_u8vector(msg):
            print('[ERROR] Received invalid message type. Expected u8vector')
            return

        self.request['frame'] = bytes(pmt.u8vector_elements(msg)).hex().upper()

        t_now = datetime.datetime.now(tz=datetime.timezone.utc)
        t_prop = (
            t_now - self.startTimestamp + self.initialTimestamp
            if self.initialTimestamp else t_now)
        t_prop_fmt = t_prop.replace(tzinfo=None).isoformat()[:-3] + 'Z'
        self.request['timestamp'] = t_prop_fmt

        params = urllib.parse.urlencode(self.request)
        # Audit finding F104: defence-in-depth against a malicious SatYAML
        # that bypassed the loader's scheme check. urlopen() handles
        # file://, ftp://, data: by default; reject anything that isn't
        # http(s) before the request goes out.
        if not (self.url.startswith('http://')
                or self.url.startswith('https://')):
            print('Refusing to submit to non-http(s) URL:', self.url)
            return
        # Audit finding F22c: previously, only urlopen() was wrapped; the
        # subsequent f.read() / f.getcode() / f.close() could still raise
        # on a half-closed stream and kill the block thread. Bound the
        # whole I/O sequence and add timeout= so a stalled server cannot
        # block the handler indefinitely.
        try:
            f = urllib.request.urlopen(
                '{}?{}'.format(self.url, params),
                data=bytes(params, encoding='ascii'),
                timeout=10)
            try:
                reply = f.read()
                code = f.getcode()
                if code < 200 or code >= 300:
                    print('Server error while submitting telemetry')
                    print('Reply:')
                    print(reply)
                    print('URL:', f.geturl())
                    print('HTTP code:', f.getcode())
                    print('Info:')
                    print(f.info())
            finally:
                f.close()
        except Exception as e:
            print('Error while submitting telemetry:', e)
            return
