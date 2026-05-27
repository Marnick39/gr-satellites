#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2020 Daniel Estevez <daniel@destevez.net>
#
# This file is part of gr-satellites
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from .imagereceiver import ImageReceiver
from ..telemetry import by70_1 as tlm


class ImageReceiverBY701(ImageReceiver):
    def filename(self, fid):
        return f'{fid}.jpg'

    def parse_chunk(self, chunk):
        # Audit finding F72: catch any parse failure (ConstructError,
        # ValueError from custom adapters like RSSIAdapter, etc.) so the
        # file-receiver dispatch layer does not propagate the exception
        # upward into the GR scheduler.
        try:
            frame = tlm.parse(chunk)
        except Exception:
            return None
        return frame.camera


by70_1 = ImageReceiverBY701
