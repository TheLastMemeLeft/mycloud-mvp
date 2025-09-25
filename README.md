# mycloud---mvp

# Secure File Storage

A self-hosted file storage system with encryption, hashing, and sharing, built with Flask.

## Features
- User authentication (register/login) with JWT.
- File upload with AES-256 encryption and SHA-256 hashing for integrity.
- File download and verification.
- Time-limited file sharing via unique links.
- SQLite database for metadata storage.

## Setup
1. Clone the repository: `git clone <repo-url>`
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file with `SECRET_KEY` and `JWT_SECRET_KEY` (random 32-char strings).
4. Create `uploads/` and `logs/` directories: `mkdir uploads logs`
5. Run the app: `python src/app.py`

## Usage
- **Register**: `POST /auth/register` with JSON `{"username": "user", "password": "pass"}`
- **Login**: `POST /auth/login` to get a JWT token.
- **Upload**: `POST /files/upload` with file and Bearer token.
- **List Files**: `GET /files/files` with token.
- **Download**: `GET /files/download/<file_id>` with token.
- **Verify**: `GET /files/verify/<file_id>` with token.
- **Share**: `POST /files/share/<file_id>` with token to get a share URL.
- **Access Shared File**: `GET /files/share/access/<token>`

## Security Notes
- Use HTTPS in production.
- Store `.env` securely and never commit it.
- Consider adding rate limiting and quotas for production.

## Future Enhancements
- WebDAV for syncing.
- File versioning.
- Frontend UI with React.