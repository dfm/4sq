#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)

__all__ = ["app"]

import flask
from flask.ext.sqlalchemy import SQLAlchemy

import foursquare

app = flask.Flask(__name__)
app.config.from_object("config.Config")

# The database connection.
db = SQLAlchemy(app)

# Foursquare API interface.
foursquare = foursquare.Foursquare(
                        client_id=app.config["FOURSQUARE_ID"],
                        client_secret=app.config["FOURSQUARE_SECRET"],
                        redirect_uri="http://localhost:5000/oauth/authorize")
                        # redirect_uri="http://4sq.dfm.io/oauth/authorize")


def get_current_user():
    user_id = flask.session.get("user_id", None)
    if user_id is not None:
        u = User.query.filter_by(foursquare_id=user_id).first()
        return u
    return None


@app.route("/")
def index():
    user = get_current_user()
    if user is not None:
        foursquare.set_access_token(user.token)
        user = foursquare.users()["user"]
        # return "Hi " + user["firstName"]

    return flask.render_template("index.html")


@app.route("/api")
def api():
    user = get_current_user()
    if user is None:
        flask.abort(403)

    q = flask.request.args.get("q", None)
    params = {"query": q,
              "near": "NYC",
              "intent": "checkin"}
    print(foursquare.venues.search(params=params))

    return "S'up"


@app.route("/login")
def login():
    return flask.redirect(foursquare.oauth.auth_url())


@app.route("/logout")
def logout():
    flask.session["user_id"] = None
    return flask.redirect(flask.url_for(".index"))


@app.route("/oauth/authorize")
def authorize():
    # Get the authorization code.
    code = flask.request.args.get("code", None)
    if code is None:
        return flask.redirect(flask.url_for(".index", error="Login error."))

    # Get the OAuth token.
    token = foursquare.oauth.get_token(code)

    # Find the current user.
    foursquare.set_access_token(token)
    user = foursquare.users()["user"]
    u0 = User.query.filter_by(foursquare_id=user["id"]).first()
    if u0 is None:
        u0 = User(user["id"], token)
        db.session.add(u0)
        db.session.commit()

    # Log the current user in.
    flask.session["user_id"] = user["id"]

    return flask.redirect(flask.url_for(".index"))


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    foursquare_id = db.Column(db.Text)
    token = db.Column(db.Text)
    phone = db.Column(db.Text)
    confirmed = db.Column(db.Boolean)
    code = db.Column(db.Integer)

    def __init__(self, foursquare_id, token):
        self.foursquare_id = foursquare_id
        self.token = token
        self.phone = None
        self.confirmed = False
        self.code = None

    def __repr__(self):
        return "User({0.foursquare_id}, {0.token})".format(self)


if __name__ == "__main__":
    app.debug = True
    app.run()
