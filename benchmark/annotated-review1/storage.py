"""Storage helpers. They never read request data themselves."""
import os
import sqlite3

DOC_DIR = "/srv/docs"
TABLE = "documents"


def read_doc(doc_name):
    with open(os.path.join(DOC_DIR, doc_name)) as fh:  # VULN:path_traversal
        return fh.read()


def read_public(public_name):
    safe = os.path.basename(public_name)
    with open(os.path.join(DOC_DIR, safe)) as fh:
        return fh.read()


def find_owner(doc_id):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT owner FROM documents WHERE id = {doc_id}")  # VULN:sqli
    return cur.fetchone()


def count_rows():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT COUNT(*) FROM " + TABLE)
    return cur.fetchone()[0]
