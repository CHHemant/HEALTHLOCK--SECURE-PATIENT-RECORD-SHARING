# HEALTHLOCK - Secure Patient Record Sharing (Simple Python)

A minimal Flask app that stores patient records encrypted at rest (Fernet) and lets you share read-only links that expire.

## Features
- End-to-end: create, list, view patient records
- Records are encrypted with Fernet (AES-128 in GCM via libsodium-equivalent scheme implemented by cryptography's Fernet)
- Time-limited share links (via itsdangerous), no account required to open
- Simple login with default admin user (change password after first run)
- SQLite storage for simplicity

## Requirements
- Python 3.10+
- Windows/macOS/Linux

## Quickstart
```bash
python -m venv .venv
. .venv/Scripts/activate  # On Windows PowerShell
# OR: source .venv/bin/activate  # On macOS/Linux
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000/` and login:
- Username: `admin`
- Password: `admin`

## How it works
- A local `fernet.key` file is created on first run and used to encrypt/decrypt record contents.
- App `SECRET_KEY` is used for sessions and to sign share tokens. A development default is used if not set. For production, set `SECRET_KEY` via environment or `.env`.
- Share links are signed tokens embedding the record id and expire after a short time (default 1 hour).

## Configuration
Create a `.env` file (optional) to override defaults:
```
SECRET_KEY=replace-with-strong-random-string
SHARE_TOKEN_MAX_AGE_SECONDS=3600
DATABASE_URL=sqlite:///healthlock.db
```

## Security notes
- Default credentials are for demo only. Change them immediately in the UI (User menu) or update in code.
- Keep `fernet.key` safe and out of version control. Anyone with it can decrypt stored records.
- This demo uses a single-user model and simple sessions. For real deployments, add multi-user auth, audit logs, and stricter access control.

## License
MIT
