#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)

__all__ = ["app"]

import re
import json
import random

import flask
from flask.ext.sqlalchemy import SQLAlchemy

import foursquare
import twilio.twiml
from twilio.rest import TwilioRestClient

app = flask.Flask(__name__)
app.config.from_object("config.Config")
app.debug = True

# The database connection.
db = SQLAlchemy(app)

# Foursquare API interface.
api_connection = foursquare.Foursquare(
                        client_id=app.config["FOURSQUARE_ID"],
                        client_secret=app.config["FOURSQUARE_SECRET"],
                        redirect_uri=app.config["FOURSQUARE_URL"])


def get_current_user():
    user_id = flask.session.get("user_id", None)
    if user_id is not None:
        u = User.query.filter_by(foursquare_id=user_id).first()
        return u
    return None


def get_twilio_client():
    client = TwilioRestClient(app.config.get("TWILIO_ID"),
                              app.config.get("TWILIO_SECRET"))
    return client


@app.route("/4sq.js")
def js():
    r = flask.make_response(flask.render_template("4sq.js"))
    r.headers["Content-Type"] = "application/javascript; charset=utf-8"
    return r


@app.route("/")
def index():
    user = get_current_user()
    if user is not None:
        return flask.render_template("main.html", user=user)

    return flask.render_template("index.html", user=user)


def parse_query(q):
    # Strip any newlines.
    q = " ".join(q.splitlines())

    # Determine the privacy settings for this check-in.
    privacy_re = re.compile(r"(?:\s*)(/p)(?:\s*)",
                            re.I | re.S | re.M)
    private = len(privacy_re.findall(q)) > 0
    q = " ".join([w for w in privacy_re.split(q) if w.lower() != "/p"])

    # Parse the query here.
    prog = re.compile(r"^(.*?)(?:$|(?:\:(?:\s+)(.*)))", re.I | re.S)
    match = prog.search(q)

    # Fail if we couldn't match.
    if match is None:
        return False, {}

    # Split the results of the parse.
    venue, shout = match.groups()

    # Find any location hint.
    near = None
    venue, hint = re.findall(r"\A(.*?)(?:(?:\((.*)\))|\Z)", venue)[0]
    if len(hint) > 0:
        near = hint

    # Find the mentions in the shout.
    mention = re.compile(r"(?:\A|\s):(\w+?):(?:\s|\Z|\W)")
    mentions = []
    if shout is not None:
        for i, m in enumerate(mention.finditer(shout)):
            s, e = m.span(1)
            mentions.append((m.groups()[0], s - 1 - 2 * i, e - 2 * i))

        for m in mentions:
            shout = shout[:m[1]] + m[0] + shout[m[2] + 1:]

    return True, {"venue": venue, "near": near, "shout": shout,
                  "private": private, "mentions": mentions}


def send_confirmation(number):
    # Create a random code.
    code = "".join([unicode(random.randint(0, 9)) for i in range(5)])

    # Update the user.
    user = get_current_user()
    user.phone = number
    user.code = code
    user.confirmed = False
    db.session.add(user)
    db.session.commit()

    # Send the confirmation SMS.
    client = get_twilio_client()
    client.sms.messages.create(to="+1" + number,
                               from_=app.config.get("TWILIO_NUMBER"),
                               body="Confirm your number for Foursquare SMS "
                                    "by entering the code: {0}".format(code))


@app.route("/api/check")
def check_number():
    # Get the provided number.
    number = flask.request.args.get("number", None)
    if number is None:
        return json.dumps("Please provide a number."), 400

    # Parse the number.
    number = "".join(re.findall("[0-9]", number))
    if len(number) != 10:
        return json.dumps("Invalid number."), 400

    send_confirmation(number)

    return json.dumps({"number": "{0}-{1}-{2}".format(number[:3],
                                                      number[3:6],
                                                      number[6:])})


@app.route("/api/confirm/<code>")
def confirm_code(code):
    user = get_current_user()
    print(user.code.strip(), code.strip())
    if user.code.strip() == code.strip():
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        return json.dumps({"success": True})

    return "Wrong code.", 400


@app.route("/api/sms", methods=["GET", "POST"])
def get_sms():
    resp = twilio.twiml.Response()

    # Parse the input.
    vals = flask.request.values
    number = vals.get("From", None)
    body = vals.get("Body", None)
    if number is None or body is None:
        print("No number.")
        return unicode(resp)

    # Find the associated user.
    user = User.query.filter_by(phone=number[2:]).first()
    if user is None or not user.confirmed:
        resp.sms("We don't recognize your number.")
        return unicode(resp)

    # Authenticate.
    api_connection.set_access_token(user.token)

    # Parse the query and build the API query.
    success, result = parse_query(body)
    if not success:
        resp.sms("Something went wrong with the Foursquare API.")
        return unicode(resp)

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
        resp.sms("We couldn't place your current location. Try providing a "
                 "hint.")
        return unicode(resp)

    # Build and execute the API call.
    ll = "{0},{1}".format(lat, lng)
    params = {
                "ll": ll,
                "intent": "checkin",
                "query": result["venue"],
                "limit": 1,
             }

    # Was a location hint provided?
    if result["near"] is not None:
        ll = params.pop("ll")
        params["near"] = result["near"]

    try:
        r = api_connection.venues.search(params=params)
    except foursquare.FailedGeocode:
        params.pop("near")
        params["ll"] = ll
        r = api_connection.venues.search(params=params)

    # Search for the specified venue.
    if len(r.get("venues", [])) == 0:
        resp.sms("No matches for '{0}'.".format(result["venue"]))
        return unicode(resp)

    # Set up the request.
    v = r["venues"][0]
    p = {"venueId": v["id"],
         "broadcast": "private" if result["private"] else "public"}
    if result["shout"] is not None:
        p["shout"] = result["shout"]

    # Search for mentions.
    if len(result["mentions"]) > 0:
        # Get list of friends. NOTE: everything breaks if you have more than
        # 500 friends... LOSER.
        friends = api_connection.users.friends(params={"limit": 500})
        friends = friends.get("friends", {"count": 0, "items": []})
        count, friends = friends["count"], friends["items"]

        mentions = []
        for m in result["mentions"]:
            for f in friends:
                n = f["firstName"] + " " + f["lastName"]
                if m[0].lower() in n.lower():
                    mentions.append("{0},{1},{2}".format(m[1], m[2] - 1,
                                    f["id"]))
                    break
        p["mentions"] = ";".join(mentions)

    # Submit the check-in.
    api_connection.checkins.add(p)

    # Send the response.
    resp.sms("You're at {0}".format(v["name"]))
    return unicode(resp)


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
        u0.phone = user.get("contact", {}).get("phone", None)

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

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    foursquare_id = db.Column(db.Text)
    token = db.Column(db.Text)
    phone = db.Column(db.Text)
    confirmed = db.Column(db.Boolean)
    code = db.Column(db.Text)
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
