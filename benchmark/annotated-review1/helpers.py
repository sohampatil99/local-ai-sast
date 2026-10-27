from flask import request


def search_term():
    return request.args.get("q", "")
