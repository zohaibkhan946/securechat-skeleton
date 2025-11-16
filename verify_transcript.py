#!/usr/bin/env python3
"""Verify session transcript and receipt for non-repudiation."""

import sys
import hashlib
import base64
from pathlib import Path
from app.common.utils import b64d
from app.crypto.sign import get_public_key_from_cert, verify_message_hash
from app.crypto.pki import get_certificate_fingerprint
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def verify_transcript(transcript_path: str, receipt_dict: dict, peer_cert_path: str):
    """Verify transcript and receipt for non-repudiation.
    
    Args:
        transcript_path: Path to transcript file
        receipt_dict: Receipt dictionary (from JSON)
        peer_cert_path: Path to peer's certificate file
    """
    print(f"Verifying transcript: {transcript_path}")
    print(f"Receipt: {receipt_dict}")
    print(f"Peer certificate: {peer_cert_path}\n")
    
    # Load peer certificate
    with open(peer_cert_path, "rb") as f:
        cert_pem = f.read()
    
    peer_cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    peer_public_key = get_public_key_from_cert(cert_pem.decode('utf-8'))
    
    # Read transcript
    with open(transcript_path, "r") as f:
        lines = [line.rstrip('\n') for line in f.readlines() if not line.startswith('#') and line.strip()]
    
    print(f"Transcript has {len(lines)} messages\n")
    
    # Compute transcript hash
    transcript_content = '\n'.join(lines)
    transcript_hash = hashlib.sha256(transcript_content.encode('utf-8')).hexdigest()
    
    print(f"Computed transcript hash: {transcript_hash}")
    print(f"Receipt transcript hash:  {receipt_dict.get('transcript_sha256', 'N/A')}\n")
    
    # Verify transcript hash matches receipt
    if transcript_hash.lower() != receipt_dict.get('transcript_sha256', '').lower():
        print("✗ FAIL: Transcript hash does not match receipt!")
        return False
    
    print("✓ Transcript hash matches receipt")
    
    # Verify receipt signature
    receipt_hash = bytes.fromhex(receipt_dict['transcript_sha256'])
    receipt_sig = b64d(receipt_dict['sig'])
    
    if verify_message_hash(receipt_hash, receipt_sig, peer_public_key):
        print("✓ Receipt signature verified successfully!")
        print("\n✓ Non-repudiation verified: Transcript is authentic and signed")
        return True
    else:
        print("✗ FAIL: Receipt signature verification failed!")
        return False


def verify_message_signature(seqno: int, timestamp: int, ciphertext: str, signature: str, sender_cert_path: str):
    """Verify individual message signature.
    
    Args:
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: Base64 encoded ciphertext
        signature: Base64 encoded signature
        sender_cert_path: Path to sender's certificate
    """
    # Load sender certificate
    with open(sender_cert_path, "rb") as f:
        cert_pem = f.read()
    
    sender_public_key = get_public_key_from_cert(cert_pem.decode('utf-8'))
    
    # Recompute hash
    hash_input = f"{seqno}{timestamp}{ciphertext}".encode('utf-8')
    message_hash = hashlib.sha256(hash_input).digest()
    
    # Verify signature
    sig_bytes = b64d(signature)
    if verify_message_hash(message_hash, sig_bytes, sender_public_key):
        print(f"✓ Message {seqno} signature verified")
        return True
    else:
        print(f"✗ Message {seqno} signature verification failed")
        return False


def main():
    if len(sys.argv) < 4:
        print("Usage:")
        print("  python verify_transcript.py <transcript_file> <receipt_json> <peer_cert>")
        print("\nExample:")
        print("  python verify_transcript.py transcripts/session_abc.txt receipt.json certs/client_cert.pem")
        return
    
    transcript_path = sys.argv[1]
    receipt_path = sys.argv[2]
    peer_cert_path = sys.argv[3]
    
    # Load receipt
    import json
    with open(receipt_path, "r") as f:
        receipt_dict = json.load(f)
    
    print("=" * 60)
    print("Non-Repudiation Verification")
    print("=" * 60)
    print()
    
    success = verify_transcript(transcript_path, receipt_dict, peer_cert_path)
    
    print("\n" + "=" * 60)
    if success:
        print("✓ Verification PASSED")
        print("\nThis proves:")
        print("1. Transcript integrity (hash matches)")
        print("2. Receipt authenticity (signature verified)")
        print("3. Non-repudiation (signed by peer)")
    else:
        print("✗ Verification FAILED")
    print("=" * 60)


if __name__ == "__main__":
    main()
