"""Deliberately vulnerable endpoint for the pull-request check demo. Never merged."""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    return os.popen("ping -c 1 " + request.args["host"]).read()
