"""Extra-family fixture for custom taint/search rules (not part of eval labels)."""
import hashlib
import logging
import os
import traceback

import ldap
from flask import Flask, redirect, request

app = Flask(__name__)
app.config["DEBUG"] = True


def login():
    password = request.form.get("password", "")
    h = hashlib.md5(password.encode()).hexdigest()
    return h


def go():
    url = request.args.get("next", "/")
    return redirect(url)


def logit(user):
    logging.info(f"user {user} logged in")


def save():
    f = request.files["doc"]
    f.save("/uploads/" + f.filename)


def find(uid):
    return ldap.search("dc=example,dc=com", uid)


os.chmod("/tmp/state", 0o777)

try:
    1 / 0
except Exception:
    traceback.print_exc()
