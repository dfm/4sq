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

    # Database connection.
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL",
                                        "postgresql://localhost/foursquare")

    # Foursquare.
    FOURSQUARE_ID = unicode(os.environ["FOURSQUARE_ID"])
    FOURSQUARE_SECRET = unicode(os.environ["FOURSQUARE_SECRET"])
    FOURSQUARE_URL = unicode(os.environ["FOURSQUARE_URL"])

    # Twilio.
    TWILIO_ID = unicode(os.environ["TWILIO_ID"])
    TWILIO_SECRET = unicode(os.environ["TWILIO_SECRET"])
    TWILIO_NUMBER = unicode(os.environ["TWILIO_NUMBER"])
