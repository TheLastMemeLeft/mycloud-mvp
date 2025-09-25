# src/routes/auth.py
"""Authentication routes for user registration and login."""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from src.models import db, User
from typing import Tuple, Dict

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register() -> Tuple[Dict, int]:
    """Register a new user."""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 400
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@auth_bp.route("/login", methods=["POST"])
def login() -> Tuple[Dict, int]:
    """Authenticate user and issue JWT token."""
    data = request.get_json()
    user = User.query.filter_by(username=data.get("username")).first()
    if not user or not user.check_password(data.get("password")):
        return jsonify({"message": "Invalid credentials"}), 401
    token = create_access_token(identity=user.id)
    return jsonify({"token": token}), 200