# src/app.py
"""Main application entry point for the file storage system."""
import os
import logging
from flask import Flask
from flask_jwt_extended import JWTManager
from src.config import Config
from src.models import db
from src.routes.auth import auth_bp
from src.routes.files import files_bp

def create_app() -> Flask:
    """Initialize and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    JWTManager(app)

    # Create directories
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["LOG_FOLDER"], exist_ok=True)

    # Set up logging
    logging.basicConfig(
        filename=os.path.join(app.config["LOG_FOLDER"], "app.log"),
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.info("Application started")

    # Create database tables
    with app.app_context():
        db.create_all()

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(files_bp, url_prefix="/files")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)