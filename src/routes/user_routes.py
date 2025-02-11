from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from database.models import User
from database.models import db
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies, JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

user_bp = Blueprint("user_bp", __name__)


# @user_bp.route("/users", methods=["POST"])
# def create_user():
#     data = request.json
#     new_user = User(username=data["username"], mail=data["mail"], password=data["password"])
#     print(new_user)
#     db.session.add(new_user)
#     db.session.commit()
#     return jsonify({"message": "User created successfully!"}), 201

# @user_bp.route("/users", methods=["GET"])
# def get_users():
#     users = User.query.all()
#     return jsonify([{"userID": u.userID, "username": u.username, "mail": u.mail} for u in users])


# @user_bp.route("/get-jwt", methods=["GET"])
# def get_jwt():
#     access_token = create_access_token(identity="test")
#     return jsonify(access_token), 200


@user_bp.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        passWord = request.form["password"]

        user = User.query.filter_by(mail=email).first()
        if user is not None:
            if check_password_hash(user.password, passWord):
                accessToken = create_access_token(identity={'email': email}, expires_delta=datetime.timedelta(minutes=120))
                resp = redirect(url_for('home'))
                set_access_cookies(resp, accessToken)
                return resp

        flash("Bad username or password", 'danger')
        return redirect(url_for('api_bp.user_bp.login'))
    
    return render_template("login.html")  

@user_bp.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match!", 'danger')
            return redirect(url_for('api_bp.user_bp.register')) 

        user = User.query.filter_by(mail=email).first()
        if user:
            flash("Email already registered!", 'danger')
            return redirect(url_for('api_bp.user_bp.register'))

        hashed_password = generate_password_hash(password)

        new_user = User(mail=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful!", 'success')
        return redirect(url_for('api_bp.user_bp.login')) 

    return render_template("register.html")