#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)

__all__ = ["app"]

import re
import json
import flask
from flask.ext.sqlalchemy import SQLAlchemy

import foursquare

app = flask.Flask(__name__)
app.config.from_object("config.Config")
app.debug = True

# The database connection.
db = SQLAlchemy(app)

# Foursquare API interface.
api_connection = foursquare.Foursquare(
                        client_id=app.config["FOURSQUARE_ID"],
                        client_secret=app.config["FOURSQUARE_SECRET"],
                        redirect_uri="http://4sq.dfm.io/oauth/authorize")


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
        api_connection.set_access_token(user.token)
        try:
            user = api_connection.users()["user"]
        except foursquare.InvalidAuth:
            user = None
        else:
            return flask.render_template("text.html", user=user)

    return flask.render_template("index.html", user=user)


def parse_query(q):
    # Strip any newlines.
    q = " ".join(q.splitlines())

    # Determine the privacy settings for this check-in.
    privacy_re = re.compile(r"(?:\s*)(/private)(?:\s*)",
                            re.I | re.S | re.M)
    private = len(privacy_re.findall(q)) > 0
    q = " ".join([w for w in privacy_re.split(q) if w.lower() != "/private"])

    # Parse the query here.
    prog = re.compile(r"^(.*?)(?:$|(?:\:(?:\s+)(.*)))", re.I | re.S)
    match = prog.search(q)

    # Fail if we couldn't match.
    if match is None:
        return False, {"rendered": "Couldn't parse request."}

    # Split the results of the parse.
    venue, shout = match.groups()
    return True, {"venue": venue, "shout": shout, "private": private}


@app.route("/api")
def api():
    user = get_current_user()
    if user is None:
        flask.abort(403)

    # Authenticate.
    api_connection.set_access_token(user.token)

    # Retrieve the request query.
    q = flask.request.args.get("q", None)
    if q is None:
        flask.abort(404)

    # Parse the query and build the API query.
    success, result = parse_query(q)
    if not success:
        return json.dumps(result)

    # Find the most recent check-in to use for geolocation.
    recent = api_connection.users.checkins(params={"limit": 1}) \
                                .get("checkins", {"items": []})["items"]

    # If we found a recent check-in, find the latitude and longitude.
    lat, lng = None, None
    if len(recent) > 0:
        recent = recent[0]
        if "location" in recent:
            loc = recent["location"]
            lat, lng = loc.get("lat", None), loc.get("lng", None)

        if (lat is None or lng is None) \
                    and "location" in recent.get("venue", {}):
            loc = recent["venue"]["location"]
            lat, lng = loc.get("lat", None), loc.get("lng", None)

    # Make sure that we found a location.
    if lat is None or lng is None:
        return json.dumps({"rendered": "You don't have a location."})

    # Build and execute the API call.
    params = {
                "ll": "{0},{1}".format(lat, lng),
                "intent": "checkin",
                "query": result["venue"],
                "limit": 1,
             }
    r = api_connection.venues.search(params=params)

    # Search for the specified venue.
    if len(r.get("venues", [])) == 0:
        return json.dumps({"rendered":
                        "No matches for venue: '{0}'".format(result["venue"])})

    v = r["venues"][0]
    rendered = "Check-in at: "
    rendered += "<a href=\"{0[canonicalUrl]}\" target=\"_blank\">{0[name]}</a>"

    print(v["id"], result["shout"])
    p = {"venueId": v["id"], "broadcast": "private"}
    if result["shout"] is not None:
        p["shout"] = result["shout"]
    api_connection.checkins.add(p)

    return json.dumps({"rendered": rendered.format(v)})


@app.route("/login")
def login():
    return flask.redirect(api_connection.oauth.auth_url())


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
    token = api_connection.oauth.get_token(code)

    # Find the current user.
    api_connection.set_access_token(token)
    user = api_connection.users()["user"]

    # See if we can find a home city.
    home_city = user.get("homeCity", None)

    # Find the user if it's already in the database.
    u0 = User.query.filter_by(foursquare_id=user["id"]).first()
    if u0 is None:
        u0 = User(user["id"], token, home_city)

    # Update the token and home city.
    u0.token = token
    u0.homeCity = home_city

    # Commit changes to the database.
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
    homeCity = db.Column(db.Text)

    def __init__(self, foursquare_id, token, homeCity):
        self.foursquare_id = foursquare_id
        self.token = token
        self.phone = None
        self.confirmed = False
        self.code = None
        self.homeCity = homeCity

    def __repr__(self):
        return "User({0.foursquare_id}, {0.token})".format(self)


if __name__ == "__main__":
    app.debug = True
    app.run()
