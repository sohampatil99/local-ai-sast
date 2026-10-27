"""Export and statistics endpoints."""
import os
import re
import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("stats.db")


@app.route("/export")
def export():
    kind = request.args["kind"]
    if kind not in ("pdf", "csv"):
        abort(400)
    os.system(f"exporter --format {kind} --out /tmp/export")
    return "queued"


@app.route("/export/legacy")
def export_legacy():
    kind = request.args["kind"]
    if not kind.startswith("pdf"):
        abort(400)
    os.system(f"exporter --format {kind} --out /tmp/export")
    return "queued"


@app.route("/stats")
def stats():
    name = request.args["metric"]
    if not re.fullmatch(r"[a-z0-9_]+", name):
        abort(400)
    cur = get_db().cursor()
    cur.execute(f"SELECT day, value FROM {name}_daily")
    return str(cur.fetchall())


@app.route("/stats/raw")
def stats_raw():
    name = request.args["metric"]
    if not re.search(r"[a-z]+", name):
        abort(400)
    cur = get_db().cursor()
    cur.execute(f"SELECT day, value FROM {name}_daily")
    return str(cur.fetchall())
