from flask import Blueprint, request, jsonify
from database.models import User
from database.models import db

user_bp = Blueprint("user_bp", __name__)

# Create a new user
@user_bp.route("/users", methods=["POST"])
def create_user():
    data = request.json
    new_user = User(username=data["username"], mail=data["mail"], password=data["password"])
    print(new_user)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully!"}), 201

# Get all users
@user_bp.route("/users", methods=["GET"])
def get_users():
    users = User.query.all()
    return jsonify([{"userID": u.userID, "username": u.username, "mail": u.mail} for u in users])
