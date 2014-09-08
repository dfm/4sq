#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division, print_function

__all__ = []

import re
import os
import psycopg2
import functools

try:
    import urllib.parse as urllib_parse  # py3
except ImportError:
    import urllib as urllib_parse  # py2

import tornado.web
import tornado.gen
import tornado.auth
import tornado.httpserver
import tornado.httpclient
from tornado.escape import json_encode, json_decode
from tornado.options import define, options, parse_command_line

define("port", default=3067, help="run on the given port", type=int)
define("debug", default=False, help="run in debug mode")
define("xheaders", default=True, help="use X-headers")
define("cookie_secret", default="secret key", help="secure key")

define("foursquare_id", default=None, help="Foursquare OAuth2 ID")
define("foursquare_secret", default=None, help="Foursquare OAuth2 secret")

define("postgres_user", default=None, help="Postgres username")
define("postgres_pass", default=None, help="Postgres password")
define("postgres_db", default="foursquare", help="Postgres database name")


class Application(tornado.web.Application):

    def __init__(self):
        handlers = [
            (r"/login", FoursquareLoginHandler),
            (r"/logout", LogoutHandler),
            (r"/settings", SettingsHandler),
            (r"/checkin", CheckinHandler),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            xheaders=options.xheaders,
            cookie_secret=options.cookie_secret,
            debug=options.debug,
            login_url="/login",
        )
        super(Application, self).__init__(handlers, **settings)

        dsn = "dbname={0}".format(options.postgres_db)
        if options.postgres_user is not None:
            dsn += " user={0}".format(options.postgres_user)
        if options.postgres_pass is not None:
            dsn += " password={0}".format(options.postgres_pass)
        self._db = psycopg2.connect(dsn)

    @property
    def db(self):
        return self._db


class BaseHandler(tornado.web.RequestHandler):

    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        return self.get_secure_cookie("user_id")


class FoursquareMixin(tornado.auth.OAuth2Mixin):

    _OAUTH_ACCESS_TOKEN_URL = "https://foursquare.com/oauth2/access_token?"
    _OAUTH_AUTHORIZE_URL = "https://foursquare.com/oauth2/authenticate?"
    _OAUTH_NO_CALLBACKS = False
    _FOURSQUARE_URL = "https://api.foursquare.com/v2"

    def get_auth_http_client(self):
        return tornado.httpclient.AsyncHTTPClient()

    @tornado.auth._auth_return_future
    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
                               code, callback, extra_fields=None):
        http = self.get_auth_http_client()
        args = {
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "extra_params": dict(grant_type="authorization_code"),
        }
        http.fetch(self._oauth_request_token_url(**args),
                   functools.partial(self._on_access_token, redirect_uri,
                                     client_id, client_secret, callback))

    def _on_access_token(self, redirect_uri, client_id, client_secret,
                         future, response):
        if response.error:
            future.set_exception(tornado.auth.AuthError(
                "Foursquare auth error: {0}".format(response.error)))
            return

        token = json_decode(response.body)["access_token"]
        self.foursquare_request(
            "/users/self",
            callback=functools.partial(self._on_user_info, future, token),
            token=token,
        )

    def _on_user_info(self, future, token, response):
        if response is None:
            future.set_result(None)
            return
        future.set_result(dict(
            user=response["response"]["user"],
            token=token,
        ))

    @tornado.auth._auth_return_future
    def foursquare_request(self, path, callback, token=None, post_args=None,
                           **args):
        url = self._FOURSQUARE_URL + path

        # Add the URL arguments.
        all_args = dict(v="20140907")
        if token:
            all_args["oauth_token"] = token
            all_args.update(args)
        url += "?" + urllib_parse.urlencode(all_args)

        # Format the callback.
        callback = functools.partial(self._on_request, callback)
        http = self.get_auth_http_client()
        if post_args is not None:
            http.fetch(url, method="POST", callback=callback,
                       body=urllib_parse.urlencode(post_args))
        else:
            http.fetch(url, callback=callback)

    def _on_request(self, future, response):
        if response.error:
            future.set_exception(tornado.auth.AuthError(
                "Error '{0}' when fetching: {1}".format(response.error,
                                                        response.request.url)))
            return
        future.set_result(json_decode(response.body))


class FoursquareLoginHandler(BaseHandler, FoursquareMixin):

    def _format_redirect_url(self, url):
        return "{0}://{1}{2}".format(self.request.protocol,
                                     self.request.host, url)

    @tornado.gen.coroutine
    def get(self):
        if self.current_user:
            self.redirect("/settings")
            return

        code = self.get_argument("code", None)
        if code is not None:
            result = yield self.get_authenticated_user(
                redirect_uri=self._format_redirect_url("/login"),
                client_id=options.foursquare_id,
                client_secret=options.foursquare_secret,
                code=code)
            user_id = result["user"]["id"]
            token = result["token"]

            # Save or update the user in the database.
            with self.db as conn:
                c = conn.cursor()
                try:
                    c.execute("""
                        insert into foursquare_users(foursquare_id, token)
                        values(%s, %s)
                    """, (user_id, token))
                except psycopg2.IntegrityError:
                    conn.rollback()
                    c.execute("update foursquare_users set token=%s "
                              "where foursquare_id=%s", (token, user_id))

            self.set_secure_cookie("user_id", user_id)
            self.redirect("/settings")
        else:
            yield self.authorize_redirect(
                redirect_uri=self._format_redirect_url("/login"),
                client_id=options.foursquare_id,
                extra_params=dict(response_type="code"),
            )


class LogoutHandler(BaseHandler):

    @tornado.web.authenticated
    def get(self):
        self.clear_cookie("user_id")
        self.redirect("/")


class SettingsHandler(BaseHandler):

    @tornado.web.authenticated
    def get(self):
        self.write("profile")


class CheckinHandler(BaseHandler, FoursquareMixin):

    @tornado.web.asynchronous
    @tornado.web.authenticated
    def get(self):
        # Parse the input query.
        q = self.get_argument("q", None)
        if q is None:
            self.set_status(400)
            self.write("Invalid query.")
            return
        self._run_checkin(q)

    def _run_checkin(self, q):
        # Parse the input.
        flag, q = parse_query(q)

        # Get the current user token.
        user_id = self.current_user
        with self.db as conn:
            c = conn.cursor()
            c.execute("select token from foursquare_users "
                      "where foursquare_id=%s", (user_id, ))
            token = c.fetchone()

        # Check to make sure that the token exists.
        if token is None:
            self.set_status(404)
            self.write("Fail.")
            return
        q["token"] = token[0]

        # If a location hint wasn't provided, look for the most recent checkin.
        if q["near"] is None:
            self.foursquare_request("/users/self/checkins",
                                    functools.partial(self._on_recent, q),
                                    token=q["token"], limit=1)
        else:
            self._venue_search(q)

    def _on_recent(self, q, response):
        # If we found a recent check-in, find the latitude and longitude.
        lat, lng = None, None
        recent = response["response"]["checkins"]["items"]
        if len(recent) > 0:
            recent = recent[0]
            if "location" in recent:
                loc = recent["location"]
                lat, lng = loc.get("lat", None), loc.get("lng", None)

            if ((lat is None or lng is None)
                    and "location" in recent.get("venue", {})):
                loc = recent["venue"]["location"]
                lat, lng = loc.get("lat", None), loc.get("lng", None)

        # Make sure that we found a location.
        if lat is None or lng is None:
            self.write("We couldn't place your current location. "
                       "Try providing a hint.")
            self.finish()
            return

        self._venue_search(q, ll="{0},{1}".format(lat, lng))

    def _venue_search(self, q, ll=None):
        # Build the query.
        params = dict(
            intent="checkin",
            token=q["token"],
            query=q["venue"],
            limit=1,
        )

        # Add the location information.
        if ll is not None:
            params["ll"] = ll
        else:
            if q["near"] is None:
                self.write("We couldn't place your current location. "
                           "Try providing a hint.")
                self.finish()
                return
            params["near"] = q["near"]

        # Run the venue search.
        self.foursquare_request("/venues/search",
                                functools.partial(self._on_venue_search, q),
                                **params)

    def _on_venue_search(self, q, response):
        venues = response["response"]["venues"]
        if not len(venues):
            self.write("No venues")
            self.finish()
            return
        venue = venues[0]

        # Build the query.
        params = dict(
            venueId=venue["id"],
            broadcast="private",
        )

        # Run the venue search.
        self.foursquare_request("/checkins/add",
                                functools.partial(self._on_add, q, venue),
                                token=q["token"],
                                post_args=params)

    def _on_add(self, q, venue, response):
        print(response)
        self.write("dude")
        self.finish()


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


def main():
    parse_command_line()

    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port, address="127.0.0.1")
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()
