# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

**Student:** Zohaib Khan  
**Roll Number:** 22i-0946  
**GitHub:** [https://github.com/zohaibkhan946](https://github.com/zohaibkhan946)

This repository implements a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🧩 Overview

This implementation provides a complete secure chat system with:
- **PKI Setup**: Root CA generation and certificate issuance
- **Mutual Authentication**: Certificate exchange and validation
- **Encrypted Credentials**: AES-128 encryption for registration/login
- **Session Key Establishment**: Diffie-Hellman key exchange
- **Encrypted Messaging**: AES-128 encryption with RSA signatures
- **Non-Repudiation**: Signed session transcripts and receipts

## 🏗️ Folder Structure

```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/                    # Local certs/keys (gitignored)
├─ transcripts/              # Session logs (gitignored)
├─ env.example               # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
└─ requirements.txt          # Minimal dependencies
```

## ⚙️ Setup Instructions

### 1. Clone/Fork Repository

Fork this repository to your own GitHub account and clone it:
```bash
git clone https://github.com/zohaibkhan946/securechat-skeleton.git
cd securechat-skeleton
```

### 2. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
# Copy example environment file
copy env.example .env  # Windows
cp env.example .env    # Linux/Mac

# Edit .env file with your configuration
```

**Configuration Options:**
- `DB_HOST`: MySQL host (default: localhost)
- `DB_PORT`: MySQL port (default: 3306)
- `DB_USER`: MySQL user (default: scuser)
- `DB_PASSWORD`: MySQL password (default: scpass)
- `DB_NAME`: Database name (default: securechat)
- `CA_CERT_PATH`: Path to CA certificate (default: certs/ca_cert.pem)
- `SERVER_CERT_PATH`: Path to server certificate (default: certs/server_cert.pem)
- `SERVER_KEY_PATH`: Path to server private key (default: certs/server_key.pem)
- `CLIENT_CERT_PATH`: Path to client certificate (default: certs/client_cert.pem)
- `CLIENT_KEY_PATH`: Path to client private key (default: certs/client_key.pem)
- `SERVER_HOST`: Server hostname (default: localhost)
- `SERVER_PORT`: Server port (default: 8888)

### 4. Initialize MySQL Database

**Option A: Using Docker (Recommended)**
```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

**Option B: Manual MySQL Setup**
1. Create database:
   ```sql
   CREATE DATABASE securechat;
   CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
   GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
   FLUSH PRIVILEGES;
   ```

2. Initialize schema:
   ```bash
   python -m app.storage.db --init
   ```

### 5. Generate Certificates

```bash
# Generate Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out server

# Generate client certificate
python scripts/gen_cert.py --cn client.local --out client
```

**Certificate Generation Options:**
- `--name`: CA Common Name (for gen_ca.py)
- `--cn`: Certificate Common Name / hostname (for gen_cert.py)
- `--out`: Output file prefix (default: CN with dots replaced)
- `--ca-dir`: CA directory (default: certs)
- `--valid-days`: Validity period in days (default: 365)

### 6. Verify Certificate Generation

```bash
# Inspect CA certificate
openssl x509 -in certs/ca_cert.pem -text -noout

# Inspect server certificate
openssl x509 -in certs/server_cert.pem -text -noout

# Inspect client certificate
openssl x509 -in certs/client_cert.pem -text -noout
```

## 🚀 Execution Steps

### Starting the Server

```bash
# Make sure MySQL is running
python -m app.server
```

**Expected Output:**
```
[*] Secure Chat Server listening on localhost:8888
[*] Waiting for connections...
```

### Starting the Client

In a **separate terminal**:

```bash
python -m app.client
```

**Expected Output:**
```
[*] Connected to localhost:8888
✓ Server certificate verified: server.local
[1] Register
[2] Login
Choose (1/2):
```

### Usage Flow

1. **Connect**: Client connects to server
2. **Certificate Exchange**: Mutual certificate verification
3. **Authentication**: Register new user or login
   - **Registration**: Provide email, username, password
   - **Login**: Provide email, password
4. **Session Key Establishment**: Diffie-Hellman key exchange
5. **Chat**: Exchange encrypted, signed messages
   - Type messages and press Enter
   - Messages are encrypted with AES-128 and signed with RSA
6. **Session Closure**: Type 'quit' to end session
7. **Receipt Exchange**: Session receipts exchanged for non-repudiation

## 📝 Sample Input/Output Formats

### Registration Example

**Client Input:**
```
[1] Register
[2] Login
Choose (1/2): 1
Email: zohaib@example.com
Username: zohaibkhan
Password: ********
```

**Expected Output:**
```
✓ Server certificate verified: server.local
✓ Registration successful!
✓ Session key established

✓ Secure chat session established. Type messages (or 'quit' to end):

You:
```

### Login Example

**Client Input:**
```
[1] Register
[2] Login
Choose (1/2): 2
Email: zohaib@example.com
Password: ********
```

**Expected Output:**
```
✓ Server certificate verified: server.local
✓ Login successful!
✓ Session key established

✓ Secure chat session established. Type messages (or 'quit' to end):

You:
```

### Chat Example

**Client:**
```
You: Hello, server!
Server: Hello, client!

You: How are you?
Server: I'm doing well, thanks!

You: quit
```

**Server Console:**
```
[*] Client connected from ('127.0.0.1', 54321)
✓ Client certificate verified: client.local
✓ User authenticated: zohaibkhan (zohaib@example.com)
✓ Session key established

✓ Secure chat session established. Type messages (or 'quit' to end):
Client: Hello, server!
You: Hello, client!
Client: How are you?
You: I'm doing well, thanks!
```

### Error Messages

- `BAD_CERT`: Certificate validation failed (self-signed, expired, or untrusted)
- `REGISTER_FAILED: User already exists`: Username or email already registered
- `LOGIN_FAILED: Invalid credentials`: Email or password incorrect
- `SIG_FAIL`: Message signature verification failed
- `REPLAY`: Sequence number check failed (replay detected)
- `STALE`: Message timestamp too old (>5 minutes)

## 🧪 Testing & Evidence

### 1. Wireshark Capture

**Setup:**
1. Start Wireshark and capture on `lo0` (loopback) or appropriate interface
2. Start server and client
3. Exchange messages
4. Stop capture

**Expected Results:**
- All application data should be encrypted (no plaintext passwords or messages visible)
- Only encrypted ciphertext, base64-encoded data, and JSON structure visible

**Wireshark Filter:**
```
tcp.port == 8888
```

### 2. Invalid Certificate Test

**Test Self-Signed Certificate:**
```bash
# Generate self-signed certificate (not signed by CA)
openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem -days 365 -nodes -subj "/CN=test.local"

# Use test certificate with client
# Expected: BAD_CERT error
```

**Test Expired Certificate:**
```bash
# Generate expired certificate
python scripts/gen_cert.py --cn test.local --valid-days -1 --out test

# Expected: BAD_CERT error (certificate expired)
```

### 3. Tampering Test

Modify a message in transit using packet manipulation:
- Expected: `SIG_FAIL` error when signature verification fails

### 4. Replay Test

Resend an old message with the same sequence number:
- Expected: `REPLAY` error when sequence number check fails

### 5. Non-Repudiation Verification

**Transcript Files:**
- Location: `transcripts/session_<uuid>.txt`
- Format: `seqno|timestamp|ciphertext|signature|peer-cert-fingerprint`

**Session Receipt:**
- Contains signed transcript hash
- Can be verified offline using participant's certificate

**Verification Script:**
```python
# Verify session receipt
from app.crypto.sign import get_public_key_from_cert, verify_message_hash
from app.storage.transcript import TranscriptLogger

# Load receipt
receipt = {...}  # Receipt JSON

# Compute transcript hash
transcript = TranscriptLogger(session_id)
transcript_hash = transcript.compute_transcript_hash()

# Verify signature
public_key = get_public_key_from_cert(peer_cert_pem)
hash_bytes = bytes.fromhex(receipt['transcript_sha256'])
signature = b64d(receipt['sig'])
is_valid = verify_message_hash(hash_bytes, signature, public_key)
```

## 🔒 Security Features

### Confidentiality
- AES-128 encryption for all messages
- Encrypted credential transmission
- Session keys derived from Diffie-Hellman

### Integrity
- SHA-256 hashing of message metadata
- RSA signatures over message hashes
- Sequence number and timestamp validation

### Authenticity
- X.509 certificate mutual authentication
- RSA signature verification
- Certificate chain validation

### Non-Repudiation
- Signed per-message signatures
- Signed session transcripts
- Signed session receipts
- Offline verifiability

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations occur **explicitly** at the application layer.

- **Do not commit secrets** (certs, private keys, salts, `.env` values).
- All secrets are gitignored via `.gitignore`.

## 📊 Database Schema

```sql
CREATE TABLE users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (username),
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Password Storage:**
- Salt: 16-byte random salt per user
- Hash: `SHA256(salt || password)` stored as hex string (64 chars)

## 🧾 Deliverables Checklist

- [x] Complete implementation with all features
- [x] GitHub repository with meaningful commits
- [x] README.md with complete documentation
- [ ] MySQL schema dump (export after testing)
- [ ] Sample records (export after testing)
- [ ] Wireshark PCAP files
- [ ] Test evidence screenshots
- [ ] Report: `22i-0946-ZohaibKhan-Report-A02.docx`
- [ ] Test Report: `22i-0946-ZohaibKhan-TestReport-A02.docx`

## 📚 References

- Assignment Specification: See `IS_Assignment_2.pdf`
- SEED Security Lab: [Crypto PKI Seedslab](https://seedsecuritylabs.org/)
- Cryptography Library: [cryptography.io](https://cryptography.io/)

## 👤 Author

**Zohaib Khan**  
**Roll Number:** 22i-0946  
**Semester:** Fall 2025  
**Course:** CS-3002 Information Security  
**Institution:** FAST-NUCES

## 📄 License

This project is part of an academic assignment and is for educational purposes only.

---

**GitHub Repository:** [https://github.com/zohaibkhan946/securechat-skeleton](https://github.com/zohaibkhan946/securechat-skeleton)