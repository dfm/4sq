#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)

__all__ = []

import flask

app = flask.Flask(__name__)
app.config.from_object("config.Config")
