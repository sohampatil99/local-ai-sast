"""Shop admin endpoints."""
import os
import sqlite3
import uuid

from flask import Flask, abort, request, send_file

app = Flask(__name__)
DOCS_DIR = "/srv/docs"
SORT_COLUMNS = {"name": "name", "date": "created_at", "price": "price"}
ALLOWED_SERVICES = {"nginx", "redis", "worker"}


def get_db():
    return sqlite3.connect("shop.db")


@app.route("/products")
def products():
    col = SORT_COLUMNS.get(request.args.get("sort"), "name")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM products ORDER BY {col}")
    return str(cur.fetchall())


@app.route("/orders")
def orders():
    col = request.args.get("sort", "id")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM orders ORDER BY {col}")
    return str(cur.fetchall())


@app.route("/restart", methods=["POST"])
def restart():
    svc = request.form["service"]
    if svc not in ALLOWED_SERVICES:
        abort(400)
    os.system("systemctl restart " + svc)
    return "restarted"


@app.route("/dig")
def dig():
    host = request.args["host"]
    if ";" in host:
        abort(400)
    return os.popen("dig +short " + host).read()


@app.route("/doc")
def doc():
    target = os.path.realpath(os.path.join(DOCS_DIR, request.args["p"]))
    if not target.startswith(DOCS_DIR + os.sep):
        abort(403)
    return send_file(target)


@app.route("/attachment")
def attachment():
    target = os.path.join(DOCS_DIR, request.args["p"])
    if not target.startswith(DOCS_DIR):
        abort(403)
    return send_file(target)


def purge_job_dir():
    job = uuid.uuid4().hex
    os.system(f"rm -rf /tmp/jobs/{job}")


def convert_image(fmt):
    os.system(f"convert upload.png out.{fmt}")


@app.route("/convert")
def convert():
    convert_image(request.args["format"])
    return "ok"
