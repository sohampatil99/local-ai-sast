"""Sample Flask service used as the SAST benchmark fixture."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, make_response, render_template_string, request, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "s3cr3t-flask-key-9f8e7d6c5b"
DB_PASSWORD = "Adm1n@2024!"


def get_db():
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cur.fetchone())


@app.route("/search")
def search():
    term = request.args.get("q", "")
    cur = get_db().cursor()
    query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    cur.execute(query)
    return str(cur.fetchall())


@app.route("/user/safe")
def get_user_safe():
    user_id = request.args.get("id")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cur.fetchone())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()


@app.route("/backup")
def backup():
    name = request.form["name"]
    subprocess.call(f"tar czf /backups/{name}.tgz /data", shell=True)
    subprocess.run(["ls", "-l", "/backups"])
    return "ok"


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return make_response(f"<h1>Hello {name}</h1>")


@app.route("/page")
def page():
    tpl = request.args.get("tpl")
    return render_template_string(tpl)


@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("/srv/files", filename))


@app.route("/read")
def read_log():
    path = request.args.get("log")
    with open(path) as fh:
        return fh.read()


@app.route("/session", methods=["POST"])
def load_session():
    blob = request.get_data()
    return str(pickle.loads(blob))


@app.route("/config", methods=["POST"])
def load_config():
    cfg = yaml.load(request.data)
    safe = yaml.safe_load(request.data)
    return str(cfg) + str(safe)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, verify=False).text


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def file_checksum(data):
    return hashlib.sha256(data).hexdigest()


def legacy_token(user):
    return hashlib.sha1(user.encode()).hexdigest()


def db_password():
    return os.environ.get("DB_PASSWORD")


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
