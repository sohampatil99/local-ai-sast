"""Flask views where user input travels through helper functions, plus look-alike safe code."""
import html
import os
import shlex
import sqlite3
import subprocess

import requests
from flask import Flask, request, send_file

app = Flask(__name__)
REPORT_DIR = "/srv/reports"
USERS_TABLE = "users"


def get_db():
    return sqlite3.connect("app.db")


# ---- real: user input reaches the sink inside a helper ----------------------------

def load_report(report_name):
    with open(os.path.join(REPORT_DIR, report_name)) as fh:
        return fh.read()


@app.route("/report")
def report():
    return load_report(request.args["name"])


def fetch_preview(link):
    return requests.get(link, timeout=5).text


@app.route("/preview")
def preview():
    target = request.args.get("url")
    return fetch_preview(target)


def current_search():
    return request.args.get("q", "")


@app.route("/greet")
def greet():
    q = current_search()
    return "<p>Results for " + q + "</p>"


def archive_path(user_file):
    return os.path.join("/srv/archive", user_file)


def serve_archive(archive_file):
    return send_file(archive_path(archive_file))


@app.route("/archive")
def archive():
    return serve_archive(request.args["f"])


# ---- safe: constants and sanitized input ------------------------------------------

def count_users():
    cur = get_db().cursor()
    cur.execute("SELECT COUNT(*) FROM " + USERS_TABLE)
    return cur.fetchone()[0]


@app.route("/item")
def item():
    item_id = int(request.args["id"])
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM items WHERE id = {item_id}")
    return str(cur.fetchone())


@app.route("/lookup")
def lookup():
    host = shlex.quote(request.args["host"])
    return subprocess.check_output("nslookup " + host, shell=True)


@app.route("/avatar")
def avatar():
    avatar_name = os.path.basename(request.args["name"])
    return send_file(os.path.join("/srv/avatars", avatar_name))


@app.route("/echo")
def echo():
    msg = html.escape(request.args.get("m", ""))
    return "<p>" + msg + "</p>"


@app.route("/sort")
def sorted_users():
    order = "DESC" if request.args.get("desc") else "ASC"
    cur = get_db().cursor()
    cur.execute("SELECT name FROM users ORDER BY name " + order)
    return str(cur.fetchall())
