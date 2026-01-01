from flask import Blueprint, jsonify

main_bp = Blueprint("main", __name__)

@main_bp.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Secure Authentication System is running"}), 200
