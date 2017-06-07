#!/usr/bin/env python3

from flask import Flask, send_from_directory, render_template, session, redirect, request
from flask.ext.sso.config import SSO_ATTRIBUTE_MAP
from flask_sso import SSO
import base64
import hashlib
import hmac
import os
import random
import redis
import socket
import urllib

app = Flask(__name__)
app.secret_key = os.environ.get("TRAININGWHEELS_SECRET_KEY")
if not app.secret_key:
    print("Please set a TRAININGWHEELS_SECRET_KEY envvar (be sure to also set it in your Discourse settings)")
    exit(1)

app.debug = True
app.config["DEBUG"] = True

sso = SSO(app=app)

hostname = socket.gethostname()
redis = redis.Redis("localhost")

sso_auth_proxy = 'http://localhost:2001'
return_sso_url = "http://localhost:2001/sso_login"

#: Default attribute map
SSO_ATTRIBUTE_MAP.update({
    'ADFS_AUTHLEVEL': (False, 'authlevel'),
    'ADFS_GROUP': (False, 'group'),
    'ADFS_LOGIN': (False, 'login'),
    'ADFS_ROLE': (False, 'admin'),
    'ADFS_EMAIL': (True, 'email'),
    'ADFS_IDENTITYCLASS': (False, 'external'),
    'HTTP_SHIB_AUTHENTICATION_METHOD': (False, 'authmethod'),
    'SSO_LOGIN_ENDPOINT': (False, sso_auth_proxy),
    'SSO_LOGIN_URL': (False, sso_auth_proxy),
})

app.config['SSO_ATTRIBUTE_MAP'] = SSO_ATTRIBUTE_MAP


@app.route('/login')
def login_screen():
    """
    Send auth request to Discourse:
    Redirect the user to DISCOURSE_ROOT_URL/session/sso_provider?sso=URL_ENCODED_PAYLOAD&sig=HEX_SIGNATURE
    """
    session.clear()

    # Generate a random nonce99. Save it temporarily so that you can verify it with returned nonce value
    nonce = generate_nonce()
    session["nonce"] = nonce

    payload = make_payload()
    data = {"sig": make_sig(payload), "sso": payload}
    url = "{}?{}".format(app.config['SSO_ATTRIBUTE_MAP']['SSO_LOGIN_ENDPOINT'][1], urllib.parse.urlencode(data))
    return redirect(url)


@app.route('/sso_login')
def sso_login_screen():
    response = base64.decodestring(request.args['sso'].encode()).decode()
    user_data = urllib.parse.parse_qs(response)
    if user_data['nonce'][0] != session["nonce"]:
        session.clear()
    session['user'] = user_data

    return redirect("/authed")


@app.errorhandler(500)
def error(e):
    app.logger.log(msg=e, level=1)
    raise(e)
    return render_template('error.html',
                           hostname=hostname, error=e), 500


@sso.login_handler
def login_callback(user_info):
    """Store information in session."""
    app.logger.log(msg="in login handler", level=3)
    app.logger.log(msg=user_info, level=1)
    if user_info.get("email"):
        session['user'] = user_info
        return redirect('/authed')
    return redirect('/auth_failed')


@app.route('/auth_failed')
def auth_failed():
    return "Login failed. <a href='/login'>Try again?</a>"


@app.route('/logout')
def logout():
    request.cookies = {}
    session.clear()
    return "<a href='/login'>Log in</a>"


@app.route('/')
def index():
    """Display user information or force login."""
    user = retrieve_user_data()

    if user:
        session['user'] = user
        return 'Welcome {name}<br><a href="/authed">Dashboard</a>'.format(name=session['user'])

    return redirect("/login")


@app.route('/authed')
def dashboard():
    if 'user' not in session:
        return "<a href='/login'>Log in</a>"
    user = session['user']

    redis.zincrby("counters", hostname)
    counters = redis.zrevrange("counters", 0, -1, withscores=True)
    counters = [(s.decode(), int(i)) for (s, i) in counters]
    thiscount = int(redis.zscore("counters", hostname))
    totalcount = sum(i for (s, i) in counters)
    return render_template("index.html",
                           hostname=hostname, counters=counters,
                           thiscount=thiscount, totalcount=totalcount, name=user['username'])


@app.route("/assets/<path:path>")
def assets(path):
    return send_from_directory("assets", path)


def make_sig(payload):
    hmac_thing = hmac.new(app.secret_key, msg=payload.encode(), digestmod=hashlib.sha256)
    return hmac_thing.hexdigest()


def generate_nonce(length=99):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def make_payload():
    """
    Return a hex string containing a signed, base64-encoded payload using sso_secret as the key.
    """

    # Create a new payload with nonce and return url (where the Discourse will redirect user after verification).
    # Payload should look like: nonce=NONCE&return_sso_url=RETURN_URL
    data = {"nonce": session["nonce"], "return_sso_url": return_sso_url}
    url_encoded = urllib.parse.urlencode(data)

    # Base64 encode the above raw payload. Let's call this payload as BASE64_PAYLOAD
    base64_encoded = base64.b64encode(url_encoded.encode())
    return base64_encoded.decode()


def retrieve_user_data():
    user = session.get('user')
    if user:
        return user

    sso_args = request.args.get('sso')
    if sso_args:
        sso_args = base64.b64decode(sso_args)
        user = urllib.parse.parse_qs(sso_args)
    return user


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
