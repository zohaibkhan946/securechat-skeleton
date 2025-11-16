#!/usr/bin/env python3
"""Test invalid certificate rejection."""

import socket
import json
import base64
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


def create_self_signed_cert():
    """Create a self-signed certificate (not signed by CA)."""
    print("Creating self-signed certificate for testing...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sindh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Karachi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "invalid.local"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer  # Self-signed (issuer == subject)
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    # Save certificate
    cert_path = Path("certs/invalid_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Save private key
    key_path = Path("certs/invalid_key.pem")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"✓ Created invalid certificate: {cert_path}")
    return str(cert_path)


def test_invalid_cert(host="localhost", port=8888):
    """Test connection with invalid certificate."""
    print(f"\nTesting connection to {host}:{port} with invalid certificate...")
    
    # Load invalid certificate
    cert_path = create_self_signed_cert()
    with open(cert_path, "r") as f:
        invalid_cert = f.read()
    
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print("✓ Connected to server")
        
        # Send hello with invalid certificate
        hello_msg = {
            "type": "hello",
            "client_cert": invalid_cert,
            "nonce": base64.b64encode(b"test_nonce").decode('utf-8')
        }
        
        data = json.dumps(hello_msg).encode('utf-8')
        sock.sendall(data + b'\n')
        print("✓ Sent hello with invalid certificate")
        
        # Receive response
        response_data = b''
        while b'\n' not in response_data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
        
        response = json.loads(response_data.decode('utf-8'))
        print(f"\nServer response: {response}")
        
        if response.get("type") == "error" and "BAD_CERT" in response.get("message", ""):
            print("\n✓ SUCCESS: Invalid certificate correctly rejected!")
            print(f"  Error message: {response.get('message')}")
            return True
        else:
            print("\n✗ FAIL: Server did not reject invalid certificate!")
            print(f"  Response: {response}")
            return False
            
    except ConnectionRefusedError:
        print(f"✗ Connection refused. Make sure server is running on {host}:{port}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sock.close()


if __name__ == "__main__":
    print("=" * 60)
    print("Invalid Certificate Test")
    print("=" * 60)
    print("\nThis test verifies that the server rejects self-signed certificates.")
    print("Expected result: BAD_CERT error\n")
    
    success = test_invalid_cert()
    
    print("\n" + "=" * 60)
    if success:
        print("✓ Test PASSED")
        print("\nNext steps:")
        print("1. Take a screenshot of this output")
        print("2. Save as 'invalid_cert_test.png'")
        print("3. Include in your test report")
    else:
        print("✗ Test FAILED")
        print("\nPlease check:")
        print("1. Server is running")
        print("2. Server correctly validates certificates")
        print("=" * 60)
