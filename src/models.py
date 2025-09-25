# src/models.py
"""Database models for users, files, and share links."""
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication."""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    files = db.relationship("File", backref="owner", lazy=True)
    share_links = db.relationship("ShareLink", backref="owner", lazy=True)

    def set_password(self, password: str) -> None:
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify the user's password."""
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    """File model storing metadata and encryption key."""
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)  # Server-stored name
    original_filename = db.Column(db.String(100), nullable=False)  # User-provided name
    hash_value = db.Column(db.String(64), nullable=False)  # SHA-256 hash
    encryption_key = db.Column(db.LargeBinary(32), nullable=False)  # AES-256 key
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    share_links = db.relationship("ShareLink", backref="file", lazy=True)

class ShareLink(db.Model):
    """Model for shareable file links."""
    __tablename__ = "share_links"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False)  # UUID for link
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow() + timedelta(days=7))