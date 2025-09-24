# MyCloud
MyCloud is a secure, self-hosted file storage system built from scratch as a lightweight alternative to OwnCloud. It features AES-256 encryption, SHA-256 hashing for file integrity, and time-limited file sharing, all powered by Python and Flask. Below is an example of interacting with the API to upload a file, compute its hash, and share it securely:Example API Usage (via cURL)  bash

# Register a user
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "securepass"}'

# Login to get JWT token
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "securepass"}'

# Upload a file (replace <token> with JWT from login)
curl -X POST http://localhost:5000/files/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@/path/to/document.txt"

# Share the file (file_id from upload response)
curl -X POST http://localhost:5000/files/share/1 \
  -H "Authorization: Bearer <token>"

# Access shared file (replace <share_token> with token from share response)
curl http://localhost:5000/files/share/access/<share_token>

Installation : Clone the repository:bash

git clone https://github.com/TheLastMemeLeft/mycloud.git
cd mycloud

Install dependencies:bash

pip install -r requirements.txt

Create a .env file with secure keys:bash

echo "SECRET_KEY=$(openssl rand -hex 16)" > .env
echo "JWT_SECRET_KEY=$(openssl rand -hex 16)" >> .env

Create directories for uploads and logs:bash

mkdir uploads logs

Run the application:bash

python src/app.py

# Usage
MyCloud provides a RESTful API for secure file management. Use an API client like Postman or cURL to interact with the following endpoints:Register: POST /auth/register with {"username": "user", "password": "pass"}
Login: POST /auth/login to obtain a JWT token
Upload File: POST /files/upload with file and Bearer token
List Files: GET /files/files with token
Download File: GET /files/download/<file_id> with token
Verify Integrity: GET /files/verify/<file_id> with token
Share File: POST /files/share/<file_id> with token to get a share URL
Access Shared File: GET /files/share/access/<token> (no auth required)

See the API documentation (docs/api.md) for detailed request/response formats.How does MyCloud work?MyCloud is a Flask-based web application designed for secure file storage and sharing. Key components include:Authentication: Uses JWT for secure user sessions, with passwords hashed via PBKDF2.
File Storage: Files are encrypted with AES-256-CBC, stored in the uploads/ directory, and tracked in a SQLite database with metadata (filename, hash, encryption key).
Integrity Verification: SHA-256 hashes are computed on upload and stored, allowing verification via the /files/verify endpoint to detect tampering.
File Sharing: Time-limited (7-day) share links are generated with UUID tokens, enabling secure access without login.
Modular Design: Organized with Flask Blueprints (auth, files), utility modules (encryption, hashing), and comprehensive logging to logs/app.log.

# Next Steps
The immediate next steps include developing a React-based frontend for a user-friendly interface, integrating WebDAV support using the wsgidav library for cross-device file syncing, and implementing file versioning to allow rollback of changes. Additionally, transitioning file storage to AWS S3 will enhance scalability, while adding multi-factor authentication and rate limiting with flask-limiter will bolster security.



...
