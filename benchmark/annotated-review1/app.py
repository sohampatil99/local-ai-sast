"""Routes that hand user input to helpers in other files (cross-file data-flow benchmark)."""
import os

from flask import Flask, request

import storage
from helpers import search_term
from net import fetch
from render import page

app = Flask(__name__)


@app.route("/doc")
def doc():
    return storage.read_doc(request.args["name"])


@app.route("/owner")
def owner():
    return str(storage.find_owner(request.args["id"]))


@app.route("/proxy")
def proxy():
    return fetch(request.args.get("url"))


@app.route("/hello")
def hello():
    return page(request.args.get("who", ""))


@app.route("/grep")
def grep():
    term = search_term()
    return os.popen("grep " + term + " /var/log/app.log").read()  # VULN:cmdi


@app.route("/count")
def count():
    return str(storage.count_rows())


@app.route("/public")
def public():
    return storage.read_public(request.args["name"])
