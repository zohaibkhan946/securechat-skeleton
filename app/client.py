"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import secrets
import hashlib
import uuid
import getpass
from pathlib import Path
from dotenv import load_dotenv

from app.common.protocol import (
    HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
    DHClientMessage, DHServerMessage, Message, ReceiptMessage
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.pki import verify_certificate, get_certificate_fingerprint, PKIValidationError
from app.crypto.dh import generate_dh_params, generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key
from app.crypto.aes import encrypt_aes128_ecb, decrypt_aes128_ecb
from app.crypto.sign import get_public_key_from_cert, verify_message_hash, load_private_key
from app.storage.transcript import TranscriptLogger
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

load_dotenv()


class SecureChatClient:
    """Secure chat client implementing full CIANR protocol."""
    
    def __init__(self, host: str = "localhost", port: int = 8888):
        """Initialize client.
        
        Args:
            host: Server host
            port: Server port
        """
        self.host = host
        self.port = port
        self.cert_path = os.getenv("CLIENT_CERT_PATH", "certs/client_cert.pem")
        self.key_path = os.getenv("CLIENT_KEY_PATH", "certs/client_key.pem")
        self.ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
        
        # Load client certificate and key
        self.client_cert_pem = self._load_certificate(self.cert_path)
        self.client_private_key = load_private_key(self.key_path)
        self.client_cert_fingerprint = get_certificate_fingerprint(
            verify_certificate(self.client_cert_pem, self.ca_cert_path)[0]
        )
        
        self.sock = None
        self.server_cert_pem = None
        self.server_cert = None
    
    def _load_certificate(self, cert_path: str) -> str:
        """Load certificate from file.
        
        Args:
            cert_path: Path to certificate file
            
        Returns:
            PEM encoded certificate string
        """
        with open(cert_path, "r") as f:
            return f.read()
    
    def _send_message(self, message: dict):
        """Send JSON message to server.
        
        Args:
            message: Message dictionary
        """
        data = json.dumps(message).encode('utf-8')
        self.sock.sendall(data + b'\n')
    
    def _receive_message(self) -> dict:
        """Receive JSON message from server.
        
        Returns:
            Message dictionary
        """
        data = b''
        while b'\n' not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        line = data.split(b'\n', 1)[0]
        return json.loads(line.decode('utf-8'))
    
    def _handle_control_plane(self) -> bytes:
        """Handle control plane: certificate exchange and temporary DH.
        
        Returns:
            Temporary AES key for control messages
        """
        # Generate client nonce
        client_nonce = secrets.token_bytes(16)
        
        # Send client hello
        hello = HelloMessage(
            client_cert=self.client_cert_pem,
            nonce=b64e(client_nonce)
        )
        self._send_message(hello.model_dump())
        
        # Receive server hello
        msg = self._receive_message()
        server_hello = ServerHelloMessage(**msg)
        self.server_cert_pem = server_hello.server_cert
        
        # Verify server certificate
        try:
            self.server_cert, server_cn = verify_certificate(self.server_cert_pem, self.ca_cert_path)
            print(f"✓ Server certificate verified: {server_cn}")
        except PKIValidationError as e:
            print(f"✗ BAD_CERT: {str(e)}")
            raise
        
        # Perform temporary DH exchange
        p, g = generate_dh_params()
        client_dh_private = generate_private_key(p)
        client_dh_public = compute_public_value(g, client_dh_private, p)
        
        # Send client DH params
        dh_client = DHClientMessage(g=g, p=p, A=client_dh_public)
        self._send_message(dh_client.model_dump())
        
        # Receive server DH response
        msg = self._receive_message()
        dh_server = DHServerMessage(**msg)
        
        # Compute shared secret and derive AES key
        shared_secret = compute_shared_secret(dh_server.B, client_dh_private, p)
        control_key = derive_aes_key(shared_secret)
        
        return control_key
    
    def register(self, email: str, username: str, password: str, control_key: bytes) -> bool:
        """Register a new user.
        
        Args:
            email: User email
            username: Username
            password: Plaintext password
            control_key: AES key for encryption
            
        Returns:
            True if registration successful
        """
        # Create registration message
        register_data = {
            "type": "register",
            "email": email,
            "username": username,
            "password": password  # Plaintext, will be encrypted
        }
        
        # Encrypt registration data
        register_json = json.dumps(register_data).encode('utf-8')
        encrypted_data = encrypt_aes128_ecb(register_json, control_key)
        
        # Send encrypted registration
        self._send_message({"data": b64e(encrypted_data)})
        
        # Receive response
        msg = self._receive_message()
        
        if msg.get("type") == "register_success":
            print("✓ Registration successful!")
            return True
        elif msg.get("type") == "error":
            print(f"✗ Registration failed: {msg.get('message', 'Unknown error')}")
            return False
        else:
            print(f"✗ Unexpected response: {msg}")
            return False
    
    def login(self, email: str, password: str, control_key: bytes) -> bool:
        """Login with existing credentials.
        
        Args:
            email: User email
            password: Plaintext password
            control_key: AES key for encryption
            
        Returns:
            True if login successful
        """
        # Create login message
        login_data = {
            "type": "login",
            "email": email,
            "password": password  # Plaintext, will be encrypted
        }
        
        # Encrypt login data
        login_json = json.dumps(login_data).encode('utf-8')
        encrypted_data = encrypt_aes128_ecb(login_json, control_key)
        
        # Send encrypted login
        self._send_message({"data": b64e(encrypted_data)})
        
        # Receive response
        msg = self._receive_message()
        
        if msg.get("type") == "login_success":
            print("✓ Login successful!")
            return True
        elif msg.get("type") == "error":
            print(f"✗ Login failed: {msg.get('message', 'Unknown error')}")
            return False
        else:
            print(f"✗ Unexpected response: {msg}")
            return False
    
    def _establish_session_key(self) -> bytes:
        """Establish session key using Diffie-Hellman.
        
        Returns:
            Session AES key (16 bytes)
        """
        # Generate DH parameters
        p, g = generate_dh_params()
        client_dh_private = generate_private_key(p)
        client_dh_public = compute_public_value(g, client_dh_private, p)
        
        # Send client DH parameters
        dh_client = DHClientMessage(g=g, p=p, A=client_dh_public)
        self._send_message(dh_client.model_dump())
        
        # Receive server DH response
        msg = self._receive_message()
        dh_server = DHServerMessage(**msg)
        
        # Compute shared secret and derive AES key
        shared_secret = compute_shared_secret(dh_server.B, client_dh_private, p)
        session_key = derive_aes_key(shared_secret)
        
        return session_key
    
    def _handle_chat_messages(self, session_key: bytes, transcript: TranscriptLogger):
        """Handle encrypted chat messages.
        
        Args:
            session_key: AES session key
            transcript: Transcript logger
        """
        server_public_key = get_public_key_from_cert(self.server_cert_pem)
        server_cert_fingerprint = get_certificate_fingerprint(self.server_cert)
        expected_seqno = 0
        
        print("\n✓ Secure chat session established. Type messages (or 'quit' to end):\n")
        
        while True:
            try:
                # Get user input
                user_input = input("You: ")
                if user_input.lower() == 'quit':
                    # Send quit message
                    self._send_message({"type": "quit"})
                    break
                
                # Prepare message
                seqno = expected_seqno + 1
                ts = now_ms()
                plaintext = user_input.encode('utf-8')
                
                # Encrypt
                ciphertext = encrypt_aes128_ecb(plaintext, session_key)
                ct_base64 = b64e(ciphertext)
                
                # Compute hash: SHA256(seqno || ts || ct)
                hash_input = f"{seqno}{ts}{ct_base64}".encode('utf-8')
                message_hash = hashlib.sha256(hash_input).digest()
                
                # Sign hash
                signature = self.client_private_key.sign(
                    message_hash,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                sig_base64 = b64e(signature)
                
                # Create message
                msg = Message(
                    type="msg",
                    seqno=seqno,
                    ts=ts,
                    ct=ct_base64,
                    sig=sig_base64
                )
                
                # Send message
                self._send_message(msg.model_dump())
                
                # Log to transcript
                transcript.append(
                    seqno, ts, ct_base64, sig_base64, server_cert_fingerprint
                )
                
                expected_seqno = seqno
                
                # Receive server message
                msg_dict = self._receive_message()
                
                if msg_dict.get("type") == "quit" or msg_dict.get("type") == "error":
                    if msg_dict.get("type") == "error":
                        print(f"✗ Error: {msg_dict.get('message', 'Unknown error')}")
                    break
                
                msg = Message(**msg_dict)
                
                # Verify sequence number
                if msg.seqno <= expected_seqno:
                    print(f"✗ REPLAY: Invalid sequence number {msg.seqno}")
                    continue
                expected_seqno = msg.seqno
                
                # Verify timestamp
                current_time = now_ms()
                if abs(current_time - msg.ts) > 300000:  # 5 minutes
                    print(f"✗ STALE: Message too old")
                    continue
                
                # Recompute hash
                hash_input = f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')
                message_hash = hashlib.sha256(hash_input).digest()
                
                # Verify signature
                signature = b64d(msg.sig)
                if not verify_message_hash(message_hash, signature, server_public_key):
                    print(f"✗ SIG_FAIL: Signature verification failed")
                    continue
                
                # Decrypt message
                ciphertext = b64d(msg.ct)
                try:
                    plaintext = decrypt_aes128_ecb(ciphertext, session_key)
                    print(f"Server: {plaintext.decode('utf-8')}\n")
                except Exception as e:
                    print(f"✗ DECRYPT_ERROR: {str(e)}")
                    continue
                
                # Log to transcript
                transcript.append(
                    msg.seqno, msg.ts, msg.ct, msg.sig, server_cert_fingerprint
                )
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                break
    
    def _generate_session_receipt(self, transcript: TranscriptLogger) -> ReceiptMessage:
        """Generate session receipt for non-repudiation.
        
        Args:
            transcript: Transcript logger
            
        Returns:
            Receipt message
        """
        transcript_hash = transcript.compute_transcript_hash()
        first_seq = transcript.get_first_seqno() or 0
        last_seq = transcript.get_last_seqno() or 0
        
        # Sign transcript hash
        hash_bytes = bytes.fromhex(transcript_hash)
        signature = self.client_private_key.sign(
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        receipt = ReceiptMessage(
            type="receipt",
            peer="client",
            first_seq=first_seq,
            last_seq=last_seq,
            transcript_sha256=transcript_hash,
            sig=b64e(signature)
        )
        
        return receipt
    
    def connect(self):
        """Connect to server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[*] Connected to {self.host}:{self.port}")
    
    def run(self):
        """Run client."""
        # Connect to server
        self.connect()
        
        session_id = str(uuid.uuid4())
        transcript = TranscriptLogger(session_id)
        
        try:
            # Control plane: certificate exchange and authentication
            control_key = self._handle_control_plane()
            
            # Authentication: register or login
            print("\n[1] Register")
            print("[2] Login")
            choice = input("Choose (1/2): ").strip()
            
            if choice == "1":
                # Registration
                email = input("Email: ").strip()
                username = input("Username: ").strip()
                password = getpass.getpass("Password: ")
                
                if not self.register(email, username, password, control_key):
                    return
            else:
                # Login
                email = input("Email: ").strip()
                password = getpass.getpass("Password: ")
                
                if not self.login(email, password, control_key):
                    return
            
            # Session key exchange
            session_key = self._establish_session_key()
            print(f"✓ Session key established")
            
            # Chat messages
            self._handle_chat_messages(session_key, transcript)
            
            # Generate and exchange receipts
            receipt = self._generate_session_receipt(transcript)
            self._send_message(receipt.model_dump())
            
            # Receive server receipt
            try:
                msg = self._receive_message()
                if msg.get("type") == "receipt":
                    print(f"\n✓ Received server receipt")
            except:
                pass
            
            print(f"\n✓ Session completed. Transcript saved: {transcript.get_transcript_file_path()}")
            
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            transcript.close()
            if self.sock:
                self.sock.close()


def main():
    client = SecureChatClient()
    client.run()


if __name__ == "__main__":
    main()