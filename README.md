# HealthLock

Secure patient record sharing for small clinics and independent practitioners. Built around one principle: encryption should be the default, not an afterthought.

Most open-source EHR tools either skip encryption entirely or bolt it on as an optional feature. HealthLock treats it as a first-class architectural concern — every record is encrypted before it touches the database, every share link carries a cryptographic expiry, and every authentication event is logged.

The entire system is approximately 900 lines of Python. No proprietary cloud dependency. Deployable by a single developer on commodity infrastructure.

---

## Research

This project is the subject of a preprint paper submitted to arXiv cs.CR:

**HealthLock: A Lightweight, Encryption-First Framework for Secure Patient Record Sharing**  
Hemant Chilkuri — GH Raisoni University, Nagpur — 2025

The paper covers the full system architecture, a formal threat model mapped to OWASP Top 10 (2021), and a comparative evaluation against three existing systems (MedVault, OpenMRS, BaseVault).

[Read the paper](https://github.com/CHHemant/HEALTHLOCK--SECURE-PATIENT-RECORD-SHARING/blob/main/HealthLock-%20Research-Paper.pdf)

---

## What it does

- Patient records stored encrypted at rest using Fernet (AES-128-CBC with HMAC-SHA256). Plaintext never touches the database.
- Time-limited share links signed with `itsdangerous`. Links expire — a clinician can share a record with a specialist without creating a permanent access grant.
- QR code delivery for physical handoffs in clinical settings.
- Progressive account lockout after five failed attempts, with emergency SMTP-based recovery.
- Comprehensive audit log. Every record access, share link generation, and authentication event is recorded.
- CSRF protection on all state-changing routes via Flask-WTF.
- PDF inline viewer with CSP sandbox and `Cache-Control: no-store` — records viewed in the browser, not downloaded.

---

## Stack

```
Web framework     Flask 3.x (Python 3.10+)
ORM               SQLAlchemy + SQLite (dev) / PostgreSQL (prod)
Encryption        cryptography.fernet — AES-128-CBC + HMAC-SHA256
Token signing     itsdangerous URLSafeTimedSerializer
Password hashing  Werkzeug PBKDF2-SHA256
CSRF              Flask-WTF
QR generation     qrcode + Pillow
PDF generation    reportlab
Sessions          HttpOnly + Secure + SameSite=Lax; 60-min TTL
```

---

## Quickstart

```bash
git clone https://github.com/CHHemant/HEALTHLOCK--SECURE-PATIENT-RECORD-SHARING
cd HEALTHLOCK--SECURE-PATIENT-RECORD-SHARING

python -m venv .venv
source .venv/bin/activate       # macOS / Linux
# .venv\Scripts\activate        # Windows

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` and log in with `admin` / `admin`.

Change the default password immediately after first login.

---

## Configuration

Create a `.env` file in the project root:

```
SECRET_KEY=replace-with-a-strong-random-string
SHARE_TOKEN_MAX_AGE_SECONDS=3600
DATABASE_URL=sqlite:///healthlock.db
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

`fernet.key` is generated automatically on first run. Keep it out of version control — it is already in `.gitignore`. Without it, stored records cannot be decrypted.

---

## Security design

The threat model targets five attack classes: credential-based attacks, direct database access, session-based attacks, abuse of sharing functionality, and cross-site attacks. Nation-state adversaries, hardware-level attacks, and server-side root compromise are out of scope for this prototype.

| Threat | Mitigation | OWASP 2021 |
|---|---|---|
| Credential stuffing | Lockout after 5 attempts, 300s cooldown, SMTP recovery code | A07 |
| Session hijacking | HttpOnly + Secure + SameSite=Lax cookies, 60-min TTL | A02 |
| Data breach at rest | Fernet AES-128-CBC + HMAC-SHA256 on all record content | A02 |
| CSRF | Flask-WTF tokens on all state-changing routes | A01 |
| Share link replay | itsdangerous time-limited signed token, configurable TTL | A01 |
| XSS | Jinja2 auto-escape + Content-Security-Policy | A03 |
| Clickjacking | X-Frame-Options: DENY on all responses | A05 |
| Privilege escalation | Owner-only enforcement on every edit and delete route | A01 |

All responses include: `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and a Content-Security-Policy restricting script sources and disabling object embeds.

---

## Comparison with existing systems

|  | HealthLock | MedVault | OpenMRS | BaseVault |
|---|---|---|---|---|
| Encryption at rest | Fernet AES-128 | AES-256 | None | AES-256 |
| Time-limited share links | Signed token | None | None | None |
| QR code delivery | Yes | None | None | None |
| Account lockout | 5 attempts | Yes | None | Yes |
| Emergency recovery | SMTP code | None | None | None |
| Audit logging | Yes | Yes | Yes | None |
| CSRF protection | Flask-WTF | Yes | Yes | None |
| Open source | MIT | No | GPL | MIT |

HealthLock is the only evaluated system that combines time-limited cryptographic share links, QR delivery, emergency account recovery, and audit logging in a single-developer-deployable open-source codebase.

---

## Limitations

These are documented in full in Section 6 of the paper.

**Single-key encryption.** All records share one Fernet key. A key compromise decrypts all records. Per-record HKDF derivation would limit the blast radius and is the most important near-term improvement.

**No multi-role RBAC.** The current model has one user type. HIPAA minimum-necessary compliance requires role differentiation between clinicians, administrators, and patients.

**SQLite default.** Lacks row-level locking for concurrent clinical use. PostgreSQL is supported via `DATABASE_URL` but Alembic migrations are not included.

**No HIPAA certification.** HealthLock is a research prototype. HIPAA compliance requires administrative, physical, and technical safeguards that extend well beyond the software layer.

---

## Planned work

- Per-patient HKDF key derivation to limit key compromise blast radius
- Privacy-preserving RAG pipeline for semantic search over encrypted records without plaintext decryption at query time
- Multi-role RBAC with Flask-Principal
- Client-side end-to-end encryption for share links via the Web Crypto API
- FHIR HL7 R4 API endpoint for clinical interoperability
- Formal penetration testing against the OWASP Web Security Testing Guide

---

## Citation

```bibtex
@misc{chilkuri2025healthlock,
  title  = {HealthLock: A Lightweight, Encryption-First Framework for Secure Patient Record Sharing},
  author = {Chilkuri, Hemant},
  year   = {2025},
  note   = {Preprint. arXiv cs.CR},
  url    = {https://github.com/CHHemant/HEALTHLOCK--SECURE-PATIENT-RECORD-SHARING}
}
```

---

## License

MIT. See LICENSE for details.
