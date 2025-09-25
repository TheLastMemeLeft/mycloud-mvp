# src/routes/files.py
"""Routes for file operations: upload, download, verify, and share."""
import os
import uuid
import logging
from flask import Blueprint, request, jsonify, send_from_directory
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models import db, File, ShareLink
from src.utils.encryption import generate_key, encrypt_file, decrypt_file
from src.utils.hashing import compute_hash
from src.config import Config
from datetime import datetime
from typing import Tuple, Dict

# Set up logging
logging.basicConfig(
    filename=os.path.join(Config.LOG_FOLDER, "app.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

files_bp = Blueprint("files", __name__)

@files_bp.route("/upload", methods=["POST"])
@jwt_required()
def upload() -> Tuple[Dict, int]:
    """Upload and encrypt a file."""
    user_id = get_jwt_identity()
    if "file" not in request.files:
        logging.error("Upload attempt without file")
        return jsonify({"message": "No file provided"}), 400
    file = request.files["file"]
    if file.filename == "":
        logging.error("Upload attempt with empty filename")
        return jsonify({"message": "No file selected"}), 400

    try:
        # Generate unique filename
        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        file_path = os.path.join(Config.UPLOAD_FOLDER, unique_filename)

        # Compute hash and encrypt
        file_data = file.read()
        hash_value = compute_hash(file)
        key = generate_key()
        ciphertext, iv = encrypt_file(file_data, key)

        # Save encrypted file
        with open(file_path, "wb") as f:
            f.write(iv + ciphertext)  # Store IV with ciphertext

        # Store metadata
        new_file = File(
            filename=unique_filename,
            original_filename=file.filename,
            hash_value=hash_value,
            encryption_key=key,
            user_id=user_id
        )
        db.session.add(new_file)
        db.session.commit()
        logging.info(f"User {user_id} uploaded file {file.filename} (ID: {new_file.id})")
        return jsonify({"message": "File uploaded", "file_id": new_file.id, "hash": hash_value}), 201
    except Exception as e:
        logging.error(f"Upload failed: {str(e)}")
        return jsonify({"message": f"Upload failed: {str(e)}"}), 500

@files_bp.route("/files", methods=["GET"])
@jwt_required()
def list_files() -> Tuple[Dict, int]:
    """List all files for the authenticated user."""
    user_id = get_jwt_identity()
    files = File.query.filter_by(user_id=user_id).all()
    return jsonify([{
        "id": f.id,
        "original_filename": f.original_filename,
        "upload_date": f.upload_date.isoformat(),
        "hash": f.hash_value
    } for f in files]), 200

@files_bp.route("/download/<int:file_id>", methods=["GET"])
@jwt_required()
def download(file_id: int) -> Tuple:
    """Download and decrypt a file."""
    user_id = get_jwt_identity()
    file = File.query.get_or_404(file_id)
    if file.user_id != user_id:
        logging.warning(f"Unauthorized download attempt by user {user_id} for file {file_id}")
        return jsonify({"message": "Unauthorized"}), 403

    file_path = os.path.join(Config.UPLOAD_FOLDER, file.filename)
    if not os.path.exists(file_path):
        logging.error(f"File {file.filename} not found")
        return jsonify({"message": "File missing"}), 404

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        iv, ciphertext = data[:16], data[16:]  # Extract IV
        decrypted_data = decrypt_file(ciphertext, file.encryption_key, iv)
        logging.info(f"User {user_id} downloaded file {file_id}")
        return send_from_directory(
            Config.UPLOAD_FOLDER,
            file.filename,
            as_attachment=True,
            download_name=file.original_filename,
            data=decrypted_data
        )
    except Exception as e:
        logging.error(f"Download failed for file {file_id}: {str(e)}")
        return jsonify({"message": f"Download failed: {str(e)}"}), 500

@files_bp.route("/verify/<int:file_id>", methods=["GET"])
@jwt_required()
def verify(file_id: int) -> Tuple[Dict, int]:
    """Verify file integrity by recomputing hash."""
    user_id = get_jwt_identity()
    file = File.query.get_or_404(file_id)
    if file.user_id != user_id:
        logging.warning(f"Unauthorized verify attempt by user {user_id} for file {file_id}")
        return jsonify({"message": "Unauthorized"}), 403

    file_path = os.path.join(Config.UPLOAD_FOLDER, file.filename)
    if not os.path.exists(file_path):
        logging.error(f"File {file.filename} not found")
        return jsonify({"message": "File missing"}), 404

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        iv, ciphertext = data[:16], data[16:]
        decrypted_data = decrypt_file(ciphertext, file.encryption_key, iv)
        current_hash = hashlib.sha256(decrypted_data).hexdigest()
        is_valid = current_hash == file.hash_value
        logging.info(f"User {user_id} verified file {file_id}: {'valid' if is_valid else 'invalid'}")
        return jsonify({
            "original_hash": file.hash_value,
            "current_hash": current_hash,
            "is_valid": is_valid
        }), 200
    except Exception as e:
        logging.error(f"Verification failed for file {file_id}: {str(e)}")
        return jsonify({"message": f"Verification failed: {str(e)}"}), 500

@files_bp.route("/share/<int:file_id>", methods=["POST"])
@jwt_required()
def create_share_link(file_id: int) -> Tuple[Dict, int]:
    """Generate a time-limited share link for a file."""
    user_id = get_jwt_identity()
    file = File.query.get_or_404(file_id)
    if file.user_id != user_id:
        logging.warning(f"Unauthorized share attempt by user {user_id} for file {file_id}")
        return jsonify({"message": "Unauthorized"}), 403

    try:
        token = str(uuid.uuid4())
        share_link = ShareLink(token=token, file_id=file_id, user_id=user_id)
        db.session.add(share_link)
        db.session.commit()
        share_url = f"{request.host_url}share/access/{token}"
        logging.info(f"User {user_id} created share link for file {file_id}")
        return jsonify({"message": "Share link created", "share_url": share_url}), 201
    except Exception as e:
        logging.error(f"Share link creation failed for file {file_id}: {str(e)}")
        return jsonify({"message": f"Share link creation failed: {str(e)}"}), 500

@files_bp.route("/share/access/<string:token>", methods=["GET"])
def access_shared_file(token: str) -> Tuple:
    """Access a file via a share link."""
    share_link = ShareLink.query.filter_by(token=token).first_or_404()
    if share_link.expires_at < datetime.utcnow():
        logging.warning(f"Access attempt with expired share link {token}")
        return jsonify({"message": "Share link expired"}), 410

    file = share_link.file
    file_path = os.path.join(Config.UPLOAD_FOLDER, file.filename)
    if not os.path.exists(file_path):
        logging.error(f"Shared file {file.filename} not found")
        return jsonify({"message": "File missing"}), 404

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        iv, ciphertext = data[:16], data[16:]
        decrypted_data = decrypt_file(ciphertext, file.encryption_key, iv)
        logging.info(f"Shared file {file.id} accessed via token {token}")
        return send_from_directory(
            Config.UPLOAD_FOLDER,
            file.filename,
            as_attachment=True,
            download_name=file.original_filename,
            data=decrypted_data
        )
    except Exception as e:
        logging.error(f"Shared file access failed for token {token}: {str(e)}")
        return jsonify({"message": f"Access failed: {str(e)}"}), 500