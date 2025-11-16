#!/usr/bin/env python3
"""Client that tampers with messages to test SIG_FAIL detection."""

import socket
import json
import base64
import secrets
import hashlib
import os
import sys
import time
from dotenv import load_dotenv
from app.common.utils import now_ms, b64e, b64d
from app.crypto.dh import generate_dh_params, generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key
from app.crypto.aes import encrypt_aes128_ecb
from app.crypto.sign import load_private_key
from app.crypto.pki import verify_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

load_dotenv()


def load_certificate(cert_path):
    """Load certificate from file."""
    with open(cert_path, "r") as f:
        return f.read()


def tamper_with_ciphertext(ciphertext):
    """Tamper with ciphertext by flipping a bit."""
    # Convert to bytearray to modify
    tampered = bytearray(ciphertext)
    # Flip first bit
    tampered[0] ^= 1
    return bytes(tampered)


def main():
    host = "localhost"
    port = 8888
    
    print("=" * 60)
    print("Tampering Test Client")
    print("=" * 60)
    print("\nThis client will send a tampered message to test SIG_FAIL detection.\n")
    
    try:
        # Load client certificate and key
        client_cert_path = os.getenv("CLIENT_CERT_PATH", "certs/client_cert.pem")
        client_key_path = os.getenv("CLIENT_KEY_PATH", "certs/client_key.pem")
        ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
        
        client_cert = load_certificate(client_cert_path)
        client_key = load_private_key(client_key_path)
        
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f"✓ Connected to {host}:{port}")
        
        # Send hello
        client_nonce = secrets.token_bytes(16)
        hello = {
            "type": "hello",
            "client_cert": client_cert,
            "nonce": b64e(client_nonce)
        }
        sock.sendall((json.dumps(hello) + "\n").encode('utf-8'))
        
        # Receive server hello
        response = b''
        while b'\n' not in response:
            response += sock.recv(4096)
        server_hello = json.loads(response.decode('utf-8'))
        
        # Verify server certificate
        try:
            verify_certificate(server_hello["server_cert"], ca_cert_path)
            print("✓ Server certificate verified")
        except Exception as e:
            print(f"✗ Server certificate error: {e}")
            return
        
        # Perform DH exchange for control plane
        p, g = generate_dh_params()
        client_dh_private = generate_private_key(p)
        client_dh_public = compute_public_value(g, client_dh_private, p)
        
        dh_client = {
            "type": "dh_client",
            "g": g,
            "p": p,
            "A": client_dh_public
        }
        sock.sendall((json.dumps(dh_client) + "\n").encode('utf-8'))
        
        response = b''
        while b'\n' not in response:
            response += sock.recv(4096)
        dh_server = json.loads(response.decode('utf-8'))
        
        # Derive control key
        shared_secret = compute_shared_secret(dh_server["B"], client_dh_private, p)
        control_key = derive_aes_key(shared_secret)
        print("✓ Control key established")
        
        # Authenticate (register a test user)
        print("\nAuthenticating...")
        import time
        unique_id = int(time.time() * 1000) % 100000
        register_data = {
            "type": "register",
            "email": f"tamper{unique_id}@test.com",
            "username": f"tamperuser{unique_id}",
            "password": "testpass123"
        }
        register_json = json.dumps(register_data).encode('utf-8')
        encrypted_data = encrypt_aes128_ecb(register_json, control_key)
        sock.sendall((json.dumps({"data": b64e(encrypted_data)}) + "\n").encode('utf-8'))
        
        response = b''
        while b'\n' not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        
        if not response:
            print("✗ Connection closed by server")
            sock.close()
            return
        
        auth_response = json.loads(response.decode('utf-8'))
        
        if auth_response.get("type") != "register_success":
            print(f"⚠ Registration failed (user may exist), trying login...")
            # Try login instead
            login_data = {
                "type": "login",
                "email": f"tamper{unique_id}@test.com",
                "password": "testpass123"
            }
            login_json = json.dumps(login_data).encode('utf-8')
            encrypted_data = encrypt_aes128_ecb(login_json, control_key)
            sock.sendall((json.dumps({"data": b64e(encrypted_data)}) + "\n").encode('utf-8'))
            
            response = b''
            while b'\n' not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            if not response:
                print("✗ Connection closed by server during login")
                sock.close()
                return
            
            auth_response = json.loads(response.decode('utf-8'))
            
            if auth_response.get("type") != "login_success":
                print(f"✗ Login also failed: {auth_response}")
                sock.close()
                return
        
        print("✓ Authentication complete")
        
        # Session key exchange
        p2, g2 = generate_dh_params()
        client_dh_private2 = generate_private_key(p2)
        client_dh_public2 = compute_public_value(g2, client_dh_private2, p2)
        
        dh_client2 = {
            "type": "dh_client",
            "g": g2,
            "p": p2,
            "A": client_dh_public2
        }
        sock.sendall((json.dumps(dh_client2) + "\n").encode('utf-8'))
        
        response = b''
        while b'\n' not in response:
            response += sock.recv(4096)
        dh_server2 = json.loads(response.decode('utf-8'))
        
        if "B" not in dh_server2:
            print(f"✗ Unexpected response: {dh_server2}")
            sock.close()
            return
        
        # Derive session key
        shared_secret2 = compute_shared_secret(dh_server2["B"], client_dh_private2, p2)
        session_key = derive_aes_key(shared_secret2)
        print("✓ Session key established")
        
        # Send a normal message first
        print("\nSending normal message...")
        seqno = 1
        ts = now_ms()
        plaintext = "Hello, this is a normal message".encode('utf-8')
        ciphertext = encrypt_aes128_ecb(plaintext, session_key)
        ct_base64 = b64e(ciphertext)
        
        # Compute hash and sign
        hash_input = f"{seqno}{ts}{ct_base64}".encode('utf-8')
        message_hash = hashlib.sha256(hash_input).digest()
        signature = client_key.sign(message_hash, padding.PKCS1v15(), hashes.SHA256())
        sig_base64 = b64e(signature)
        
        msg = {
            "type": "msg",
            "seqno": seqno,
            "ts": ts,
            "ct": ct_base64,
            "sig": sig_base64
        }
        sock.sendall((json.dumps(msg) + "\n").encode('utf-8'))
        print("✓ Normal message sent")
        
        # Wait a bit for server to process
        time.sleep(0.5)
        
        # Read server's response to first message (discard it)
        try:
            sock.settimeout(1.0)
            response = b''
            while b'\n' not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            if response:
                server_msg = json.loads(response.decode('utf-8'))
                print(f"  (Server responded to normal message)")
        except:
            pass  # Ignore if no response
        sock.settimeout(None)
        
        # Now send a TAMPERED message
        print("\nSending TAMPERED message (ciphertext modified)...")
        seqno = 2
        ts = now_ms()
        plaintext2 = "This message will be tampered".encode('utf-8')
        ciphertext2 = encrypt_aes128_ecb(plaintext2, session_key)
        ct_base64_original = b64e(ciphertext2)
        
        # TAMPER: Modify ciphertext
        tampered_ciphertext = tamper_with_ciphertext(ciphertext2)
        ct_base64_tampered = b64e(tampered_ciphertext)
        
        # Compute hash for ORIGINAL ciphertext and sign it
        hash_input_original = f"{seqno}{ts}{ct_base64_original}".encode('utf-8')
        message_hash_original = hashlib.sha256(hash_input_original).digest()
        signature_original = client_key.sign(message_hash_original, padding.PKCS1v15(), hashes.SHA256())
        sig_base64_original = b64e(signature_original)
        
        # Send TAMPERED ciphertext but with signature for ORIGINAL
        # This creates a mismatch - server will compute hash of tampered ciphertext
        # but signature is for original, so verification will fail
        msg_tampered = {
            "type": "msg",
            "seqno": seqno,
            "ts": ts,
            "ct": ct_base64_tampered,  # Tampered ciphertext
            "sig": sig_base64_original  # Signature for original (mismatch!)
        }
        
        # Verify the mismatch: compute hash of tampered ciphertext
        hash_input_tampered = f"{seqno}{ts}{ct_base64_tampered}".encode('utf-8')
        message_hash_tampered = hashlib.sha256(hash_input_tampered).digest()
        print(f"  Original hash: {message_hash_original.hex()[:16]}...")
        print(f"  Tampered hash: {message_hash_tampered.hex()[:16]}...")
        print(f"  Hashes match: {message_hash_original == message_hash_tampered}")
        print(f"  (They should NOT match for tampering test)")
        
        sock.sendall((json.dumps(msg_tampered) + "\n").encode('utf-8'))
        print("✓ Tampered message sent (ciphertext tampered, signature for original)")
        
        # Wait for response with timeout
        print("\nWaiting for server response...")
        sock.settimeout(5.0)  # 5 second timeout
        try:
            response = b''
            while b'\n' not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            if response:
                server_response = json.loads(response.decode('utf-8'))
                print(f"\nServer response: {server_response}")
                
                if server_response.get("type") == "error" and "SIG_FAIL" in server_response.get("message", ""):
                    print("\n" + "=" * 60)
                    print("✓ SUCCESS: Server detected tampering!")
                    print(f"Error: {server_response.get('message')}")
                    print("=" * 60)
                    print("\n📸 TAKE SCREENSHOT NOW - Save as: tampering_test.png")
                else:
                    print("\n✗ Unexpected response - tampering not detected")
                    print(f"   Expected: error with SIG_FAIL")
                    print(f"   Got: {server_response}")
            else:
                print("\n✗ No response received from server")
        except socket.timeout:
            print("\n✗ Timeout waiting for server response")
        except Exception as e:
            print(f"\n✗ Error receiving response: {e}")
        
        sock.close()
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
