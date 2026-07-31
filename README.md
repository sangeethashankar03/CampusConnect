# CampusConnect

##Project Overview

CampusConnect allows university students to register, connect, send end-to-end encrypted messages, create study groups, and share encrypted files. Every encryption operation happens inside the user's own browser using the Web Crypto API.

## Live Deployment

Render: https://campusconnect-aoi5.onrender.com

---

## Security Features

### 1. Real Email Verification (SendGrid)
Registration requires proving ownership of a real Google Gmail account. A random 6-digit code is generated server-side, saved temporarily in the pending_verifications table with a 10-minute expiry, and delivered via SendGrid over HTTPS. Only after the correct code is submitted does a real account get created. The temporary record is deleted immediately after.

### 2. Password Hashing (bcrypt)
Passwords are never stored in plaintext. Every password is run through bcrypt with a cost factor of 12, producing a salted, one-way hash in $2b$12$ format. Even with full database access, the original password cannot be recovered. Verified directly by querying the users table on the live database.

### 3. Brute-Force Login Protection
Five consecutive failed login attempts locks the account for 5 minutes. The failed_login_count and locked_until columns are updated server-side on every failed attempt. The lockout cannot be bypassed by the client since the check happens before any password comparison.

### 4. RSA Keypair Generation (Client-Side Only)
The first time a user logs in, their browser generates two RSA keypairs using window.crypto.subtle — not the server. Two keypairs are created:
- RSA-OAEP (2048-bit) for encrypting and decrypting message content
- RSA-PSS (2048-bit) for signing and verifying messages

The server is never involved in key generation and never sees a private key in usable form.

### 5. Private Key Protection (PBKDF2 + AES-GCM)
Before private keys leave the browser, they are encrypted using a key-encryption-key (KEK) derived from the user's own password via PBKDF2 with a random salt and 210,000 iterations. The server stores only the encrypted private key blobs and the salt. Verified directly: no BEGIN PRIVATE KEY header exists anywhere in the enc_private_key_blob column on the live database.

### 6. Hybrid Encryption for Messages (AES-256-GCM + RSA-OAEP)
Every message uses hybrid encryption entirely client-side:
- A brand-new one-time AES-256-GCM key is generated per message
- The message content is encrypted with that AES key
- The AES key is RSA-OAEP wrapped twice: once with the recipient's public key, once with the sender's own public key so they can reread their own sent messages
- The ciphertext is signed with the sender's RSA-PSS private key
- The server stores only ciphertext, nonce, both wrapped keys, and the signature

Verified directly: the ciphertext column in the messages table contains only unreadable data on the live database.

### 7. Digital Signatures (RSA-PSS)
Every message and file is signed by the sender before transmission. The recipient verifies the signature using the sender's public key before decrypting. This confirms the message genuinely came from that person and was not altered in transit.

### 8. Connection Request and Accept Flow
Two users must go through a request and accept flow before messaging is allowed. The server checks the accepted status on every single message send, not just once at the start. Even a direct API call bypassing the UI is rejected if no accepted connection exists.

### 9. Group Invite and Accept Flow
Groups are invite-only. Only the group owner can invite members by username. The invited person must explicitly accept before a group_memberships row is ever created. Declining or ignoring an invite means zero membership and zero access to any group content.

### 10. Group Envelope Encryption
Group messages and files use envelope encryption. One AES-256-GCM key is generated per item, then wrapped separately once per current group member using each member's RSA public key. The server stores one ciphertext plus N individually wrapped keys. No shared secret exists anywhere. A member who joins after a message was sent has no wrapped key for it and genuinely cannot decrypt it.

Verified directly: the group_message_keys and file_keys tables show the same message or file ID with completely different wrapped_key values per user on the live database.

### 11. Role-Based Access Control (RBAC)
Every account has a role column defaulting to student. Admin-only routes are protected by the role_required decorator which checks the actual database role on every request. Verified by testing both the denied case (student account) and the granted case (admin account) against the live API.

### 12. Safety Number Verification
Both participants in a conversation can independently compute a short numeric code by hashing their combined public keys client-side. If both codes match when compared out-of-band, it proves the server never substituted either public key during distribution.

### 13. Security Headers
Every response includes:X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and Referrer

## Technologies

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript, Web Crypto API |
| Backend | Python 3, Flask, Flask-SQLAlchemy, Flask-JWT-Extended, Flask-Bcrypt, Flask-Migrate |
| Database | PostgreSQL 18 |
| Email Delivery | SendGrid (HTTPS API, not SMTP) |
| Deployment | Render (Web Service + Managed PostgreSQL) |
| Encryption Algorithms | RSA-OAEP 2048-bit, RSA-PSS 2048-bit, AES-256-GCM, PBKDF2-SHA256 |

System architecture
```
frontend/         Static HTML/CSS/vanilla JS — no build step, no framework
backend/
  app/
    auth/          Gmail-verified registration, login, brute-force lockout
    crypto/        Public key storage + encrypted private-key backup
    messaging/      1:1 connection requests + encrypted direct messages
    groups/        Study groups, invite-based membership, encrypted group chat
    files/         Envelope-encrypted group file sharing
    admin/         Role-gated admin endpoints
    models/        SQLAlchemy models
  migrations/      Alembic/Flask-Migrate schema history

```

Client tier (Browser)
- RSA keypair generation using window.crypto.subtle — entirely client-side
- AES-256-GCM message and file encryption before any network transmission
- Private keys held in sessionStorage for the active session only — cleared on tab close

Application tier (Render Web Service)
- Flask REST API — JWT validation, access control, ciphertext routing
- Never decrypts any content — no decryption capability exists server-side

Data tier (Render PostgreSQL 18)
- Stores bcrypt hashes, encrypted private key blobs, message ciphertext, wrapped AES keys
- Zero readable secrets stored at any point

Email tier (SendGrid)
- OTP delivery via HTTPS API — no SMTP, works on all cloud platforms without port restrictions


### Prerequisites

- Python 3.10 or higher
- PostgreSQL running locally
- A Gmail account
- A SendGrid account with a verified sender identity and API key

### Setup

**1. Clone the repository:**
```
git clone https://github.com/sangeethashankar03/CampusConnect.git
cd CampusConnect/backend
```

**2. Install dependencies:**
```
pip install -r requirements.txt
```

**3. Create a `.env` file in the `backend/` folder:**
```
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
DATABASE_URL=postgresql://username:password@localhost:5432/campusconnect
MAIL_USERNAME=your-gmail@gmail.com
MAIL_PASSWORD=your-16-char-gmail-app-password
SENDGRID_API_KEY=your-sendgrid-api-key
UPLOAD_FOLDER=uploads
```

**4. Run database migrations:**
```
python -m flask db upgrade
```

**5. Start the server:**
```
python run.py
```

**6. Open your browser at:** `http://127.0.0.1:5000`

---

## Database Schema

| Table | Purpose |
|---|---|
| `users` | Email, username, bcrypt hash, role, lockout fields |
| `pending_verifications` | Temporary email and code during registration, deleted after use |
| `public_keys` | Public keys in plain text, encrypted private key blobs, KDF salt |
| `conversations` | Connection request status between two users |
| `messages` | Ciphertext, nonce, two wrapped AES keys, RSA-PSS signature |
| `groups` | Group name, module code, creator |
| `group_memberships` | Which users belong to which groups and their role |
| `group_invites` | Pending invites with status |
| `group_messages` | Group chat ciphertext, nonce, signature |
| `group_message_keys` | Per-member wrapped AES key for each group message |
| `shared_files` | Encrypted file blob location and nonce |
| `file_keys` | Per-member wrapped AES key for each shared file |

---

## Deployment on Render

The application is deployed as a single web service on Render serving both the Flask API and the static frontend files. The database is a managed PostgreSQL 18 instance on Render in the Frankfurt region. Email delivery uses SendGrid's HTTPS API to avoid SMTP port restrictions on cloud hosting.

**Environment variables required on Render:**

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Internal Database URL from Render PostgreSQL |
| `SECRET_KEY` | Flask secret key |
| `JWT_SECRET_KEY` | JWT signing key |
| `MAIL_USERNAME` | Gmail address used as sender identity |
| `MAIL_PASSWORD` | Gmail app password |
| `SENDGRID_API_KEY` | SendGrid API key for email delivery |
| `UPLOAD_FOLDER` | `uploads` |

---

AI Assistance

This project was developed with the assistance of Claude (Anthropic) as an AI pair programming tool. AI was used throughout the development process for architecture decisions, security implementation guidance, code generation and debugging. All AI interaction logs and prompts are documented 

