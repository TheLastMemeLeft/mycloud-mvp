# src/config.py
"""Configuration for the file storage application."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

class Config:
    """Base configuration class."""
    BASE_DIR = Path(__file__).resolve().parent.parent
    SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")  # Fallback for dev only
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default-jwt-secret")  # Fallback for dev
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR}/instance/site.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    LOG_FOLDER = str(BASE_DIR / "logs")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size