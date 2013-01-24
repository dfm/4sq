#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)

__all__ = ["Config"]

import os


class Config(object):

    # Flask stuff.
    SERVER_NAME = None
    SECRET_KEY = unicode(os.environ.get("SECRET", "development secret key")) \
                         .encode("utf-8")

    # Foursquare.
    FOURSQUARE_ID = unicode(os.environ["FOURSQUARE_ID"])
    FOURSQUARE_SECRET = unicode(os.environ["FOURSQUARE_SECRET"])
