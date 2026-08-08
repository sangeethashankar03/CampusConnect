# CampusConnect

##Project Idea
For this project, we are planning to build a secure communication and collaboration platform called CampusConnect. The main idea is to provide a platform where university students can communicate with each other, create study groups, and share academic resources in a secure environment.

Students will be able to register, log in, send messages, create group chats, and share files related to their studies and projects. We plan to implement secure user authentication, end-to-end encrypted communication, password hashing, and access control so that only authorised users can access protected content.

##Features
- Identity and access control
Gmail-verified registration: a 6-digit one-time code is emailed before an account can be created (real Gmail SMTP)
bcrypt password hashing; 10+ character passwords with upper/lower/digit/symbol enforced client- and server-side
Brute-force protection: account locks for 5 minutes after 5 failed login attempts
JWT-based session auth (1-hour expiry) validated on every protected endpoint
Role-based access: an `admin` role gates a user-roster endpoint, enforced server-side (not just hidden in the UI)
Encrypted direct messaging
RSA-2048-OAEP key wrapping + AES-256-GCM content encryption, generated fresh per message
RSA-PSS signatures on every message; verified against the sender's public signing key
Messages only sendable between users with a mutually accepted connection request — enforced server-side
Safety-number verification: both parties can compare a code derived from each other's public keys out-of-band to detect a server-side key-substitution (MITM) attempt
Study groups
Invite-only membership: only the group owner can invite (by username), and the invitee must explicitly accept — no open self-join by guessable group ID
Owner/member roles per group
Encrypted group chat and file sharing
Envelope encryption: one fresh AES-256-GCM key per message/file, RSA-OAEP-wrapped once for every current member's public key
A member who joins later cannot decrypt anything sent before they joined; a member who leaves cannot decrypt anything sent after — both are the correct, intended behaviour, not bugs
Files are encrypted entirely client-side before upload; the server stores only ciphertext blobs and per-member wrapped keys, never a usable key or plaintext
Key persistence and recovery
Private keys are generated once per account, encrypted client-side (PBKDF2-derived key from the user's password + AES-256-GCM), and backed up server-side as ciphertext the server itself cannot open
On every subsequent login, the browser fetches that encrypted backup and decrypts it locally with the freshly-entered password — the same keypair is recovered rather than a new one generated, so historical messages stay decryptable
---
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
 ##plaintext must never reach the backend or the database. All cryptography — key generation, encryption, decryption, signing, signature and safety-number verification — happens in the browser via the Web Crypto API (`frontend/js/crypto.js`).
Component responsibilities
Tier	Responsibility
Client	Static pages served by Flask; all key generation and encrypt/decrypt via Web Crypto API; polls the REST API for new messages (no WebSocket layer)
Application	Flask REST API — JWT auth, connection/invite/membership enforcement, ciphertext relay and storage. Never decrypts anything.
Data	PostgreSQL — users, connections, groups/memberships/invites, messages (ciphertext + wrapped keys only), encrypted private-key backups
This is currently a local/self-hosted setup — there is no live deployed URL yet. See §Setup below to run it locally, or your own report/submission for wherever you deploy it (the brief requires a deployment link).
---
Cryptographic workflow
Registration — user submits a Gmail address → server emails a 6-digit code → user enters it → server marks that email verified → user sets a password → account is created.
First login — browser generates an RSA-2048 keypair for encryption and a separate one for signing. A key-encryption-key (KEK) is derived from the user's password via PBKDF2. Both private keys are encrypted with that KEK (AES-256-GCM) and sent to the server as ciphertext, along with the two public keys in plaintext.
Later logins — browser fetches the encrypted private-key backup, re-derives the same KEK from the password just entered, and decrypts locally. No new keypair is generated; the server never sees a usable private key at any point.
Sending a direct message — sender generates a one-off AES-256-GCM key, encrypts the plaintext, wraps that AES key with RSA-OAEP twice (once for the recipient's public key, once for the sender's own, so the sender can re-read their own sent messages), and signs the plaintext with RSA-PSS before encrypting.
Sending to a group — sender fetches the public keys of every current group member, generates one AES key for the message/file, and wraps it once per member. The server stores N wrapped copies of a key it can never itself unwrap.
Receiving — recipient unwraps the AES key with their own RSA private key, decrypts the content, and verifies the signature against the sender's public signing key.
Out-of-band verification — for direct conversations, both users can compute and compare a safety number derived from each other's public keys, to detect a server-side key-substitution attack.
---
Security
CampusConnect is designed under the assumption that the server and database could be read by an attacker (or a curious operator). The objective is damage limitation: a compromised server must not expose readable message or file content.
Implemented controls
End-to-end RSA-OAEP + AES-256-GCM encryption for direct messages, group chat, and group files
RSA-PSS signatures on every message, verified client-side
Gmail one-time-code identity verification before account creation
bcrypt password hashing + brute-force lockout (5 attempts / 5-minute lock)
Server-enforced connection requirement before two users can message each other
Invite-and-accept group membership (not open self-join)
Envelope encryption scoped to current group members only — no access to messages/files sent outside a user's membership window
Encrypted-at-rest private key backup — server never holds a usable private key
Role-based server-side access control for admin functionality
Basic security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`)
Base64/schema validation on encrypted payloads before they're persisted
Residual risk after a full server/database compromise
An attacker with complete read access to the backend and database still cannot:
Read any direct message, group message, or file content (never stored in plaintext)
Derive any user's private keys (only PBKDF2/AES-GCM-encrypted blobs are stored; the KEK depends on a password the server never has)
Decrypt historical content without also compromising the relevant user's password
They can:
See who is connected to whom, who is in which group, and message/file metadata (timing, size, sender/recipient) — this is a metadata-visible system, not a metadata-hiding one
Deny service (drop, delay, or refuse to relay) — confidentiality and integrity are protected, availability is not
Explicitly out of scope / known limitations — worth stating plainly for the report and for whichever group does your vulnerability analysis:
No forward secrecy. RSA keys are long-lived; a leaked private key compromises every past message ever sent to that key, not just future ones. A per-session ephemeral exchange (X3DH/Double Ratchet-style) is the standard mitigation and is not implemented here.
No epoch/key-rotation on membership change for groups — a design alternative some teams use (see rotation-on-leave in other groups' systems) that this system does not implement. Once a member leaves a group, they simply have no wrapped key for anything sent afterward; existing content already wrapped for them during membership remains something only they can decrypt if they kept a local copy.
Registration only checks the email domain is `gmail.com`/`googlemail.com`, not that it belongs to an actual DBS student — see §Identity for the implication.
No rate limiting on connection requests or group invites (spammable).
Real-time delivery is via polling, not a WebSocket relay — functionally fine for this scope, but adds latency and unnecessary request volume compared to a push-based design.
`frontend/verify.html` is dead code left over from an earlier link-based verification design and calls a `/api/auth/verify` endpoint that no longer exists — safe to delete, not currently linked anywhere.
---
Local development
Prerequisites: Python 3.11+, PostgreSQL, a Gmail account with an App Password (Google blocks plain-password SMTP entirely).
```bash
cd backend
python -m venv venv
source venv/bin/activate        # venv\Scripts\activate on Windows
pip install -r requirements.txt

cp .env.example .env
# edit .env:
#   SECRET_KEY=<random string>
#   JWT_SECRET_KEY=<random string>
#   DATABASE_URL=postgresql://<user>:<password>@localhost:5432/campusconnect
#   MAIL_USERNAME=<your gmail address>
#   MAIL_PASSWORD=<16-character Gmail App Password>

createdb campusconnect
flask db upgrade

python run.py
```
Flask serves `frontend/` as static files directly — once `run.py` is running, open http://localhost:5000/. No separate frontend server needed.
Without valid SMTP credentials set, `POST /api/auth/request-code` will return an error rather than silently succeeding — the app does not fall back to a fake/logged code path in production code.
Environment variables
Variable	Purpose
`SECRET_KEY`	Flask session/signing secret
`JWT_SECRET_KEY`	Signs access tokens (1-hour expiry)
`DATABASE_URL`	PostgreSQL connection string
`MAIL_USERNAME` / `MAIL_PASSWORD`	Gmail SMTP account used to send verification codes
`UPLOAD_FOLDER`	Where encrypted file blobs are stored on disk (default `uploads/`)
Multi-user testing: open two browsers (or one normal + one private/incognito window) with two different Gmail accounts, send a connection request from one to the other, accept it, and message back and forth. For groups: create a group as one user, invite the second by username, accept the invite from the second browser, then use the group's Chat and Files tabs from both sides.
---
Testing
```bash
cd backend
pytest
```
There is currently no CI pipeline configured for this repository — tests are run manually. Adding a GitHub Actions workflow to run `pytest` on push is a reasonable improvement if time allows before submission.
---
Verifying the encryption yourself
Register and log in as two different users (see multi-user testing above).
Connect the two accounts, open the conversation, send a message.
Open the Postgres `messages` table directly (`psql`, pgAdmin, or similar) and inspect the row — `ciphertext`, `nonce`, `enc_aes_key` should all be unreadable base64, never plaintext.
In the browser DevTools Network tab, inspect the `POST /api/messages/` request body — same result, ciphertext only.
Confirm the OpenAPI/Flask routes never expose a "decrypt on the server" endpoint — decryption only ever happens in `frontend/js/crypto.js`, client-side.
Repeat for a group message and a group file upload to confirm the same holds for envelope-encrypted content.
---
API reference
All routes are prefixed `/api` and (except registration/login) require `Authorization: Bearer <token>`.
Auth (`/api/auth`)
Method	Route	Purpose
POST	`/request-code`	Step 1 of registration — sends a 6-digit code to a Gmail address
POST	`/verify-code`	Step 2 — confirms the code
POST	`/complete-registration`	Step 3 — sets password, creates the account
POST	`/login`	Returns a JWT access token
GET	`/me`	Current user's profile
GET	`/search?q=`	Search users by username
Keys (`/api/keys`)
Method	Route	Purpose
POST	`/register`	Store public keys + encrypted private-key backup (first login)
GET	`/backup`	Fetch your own encrypted private-key backup (later logins)
GET	`/<user_id>`	Fetch another user's public keys
Messaging (`/api/messages`)
Method	Route	Purpose
POST	`/conversations/request`	Send a connection request
GET	`/conversations/pending`	Requests awaiting your response
GET	`/conversations/sent`	Requests you sent, with status
GET	`/conversations/accepted`	All accepted conversations (server-side source of truth)
POST	`/conversations/<id>/accept` | `/reject`	Respond to a request
POST	`/`	Send an encrypted direct message (rejected if not connected)
GET	`/<peer_id>`	Fetch message history with a peer (rejected if not connected)
Groups (`/api/groups`)
Method	Route	Purpose
GET	`/`	Your groups
POST	`/`	Create a group (creator becomes owner)
POST	`/<id>/invite`	Owner invites a user by username
GET	`/invites/pending`	Invites waiting for you
POST	`/invites/<id>/accept` | `/reject`	Respond to an invite
POST	`/<id>/leave`	Leave a group
GET	`/<id>/members`	Members + their public keys
POST	`/<id>/messages`	Send an encrypted group message
GET	`/<id>/messages`	Fetch group message history
Files (`/api/files`)
Method	Route	Purpose
POST	`/<group_id>/upload`	Upload an already-encrypted file + wrapped keys
GET	`/<group_id>/<file_id>/download`	Fetch ciphertext + your wrapped key
GET	`/<group_id>`	List files in a group
Admin (`/api/admin`)
Method	Route	Purpose
GET	`/users`	Full user roster — requires `role = admin` (promote manually via SQL)
---
Frontend pages
Page	Purpose
`login.html` / `register.html`	Auth + the 3-step Gmail verification flow
`messages.html`	Search users, manage connection requests, encrypted 1:1 chat, safety numbers
`groups.html`	Create groups, send/respond to invites, lists "your groups" as cards, each with an Open group link
`files.html`	The group detail page (`?group_id=<id>&group_name=<name>`), with Chat and Files tabs — encrypted group messaging and drag-and-drop encrypted file upload/download
`admin.html`	User roster, shown in the nav only to `role = admin` accounts; access enforced server-side regardless
`verify.html`	Dead code — see Known limitations. Not linked anywhere; safe to delete.
---
Contribution & AI-assistance log
Per the CA1 brief's Generative AI Assessment Scale, this project used AI (ChatGPT and Claude) at levels 3–4 — AI-assisted editing and AI task completion with human evaluation — not full AI generation.
AI-assisted: initial project scaffolding (Flask blueprint structure, SQLAlchemy models), debugging of the connection-request/messaging flow, the redesign of private-key handling (PBKDF2 + AES-GCM key backup, replacing an earlier design that regenerated RSA keys on every login), the Gmail-verified registration flow, group-invite and envelope-encryption logic for group chat/files, and this README.
Reviewed and integrated by us: every AI-suggested change was read, tested against the running app, and adjusted before being committed — AI output was not committed unread. Where AI review found a genuine bug (e.g. a signature-verification bug that broke a sender's ability to decrypt their own sent messages) or a genuine gap (e.g. group-join UI never actually wired to the join/invite endpoints), that's noted in code comments and above.
Our own work: overall system design and security requirements, the specific choices of what to build vs. cut given the CA1 time budget, testing, and the vulnerability analysis/mitigation sections of the accompanying report.
Logs retained: full prompt/response transcripts for both AI tools are kept separately and available on request, per the brief's requirement.
---

