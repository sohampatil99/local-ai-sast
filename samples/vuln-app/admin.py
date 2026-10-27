from flask import Blueprint, jsonify, request, session

admin = Blueprint("admin", __name__)
INVOICES = {1: {"owner": "alice", "total": 120}, 2: {"owner": "bob", "total": 75}}


@admin.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    if "user" not in session:
        return jsonify(error="login required"), 401
    return jsonify(INVOICES.get(invoice_id))


@admin.route("/admin/delete_user", methods=["POST"])
def delete_user():
    if request.json.get("role") == "admin":
        return jsonify(deleted=request.json["username"])
    return jsonify(error="forbidden"), 403


@admin.route("/reset_password", methods=["POST"])
def reset_password():
    user = request.json["username"]
    if request.json["token"] == user[::-1]:
        return jsonify(ok=True)
    return jsonify(ok=False), 400
