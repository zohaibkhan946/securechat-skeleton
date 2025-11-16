"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def load_private_key(key_path: str) -> rsa.RSAPrivateKey:
    """Load RSA private key from PEM file.
    
    Args:
        key_path: Path to private key file
        
    Returns:
        RSA private key object
    """
    key_file = Path(key_path)
    with open(key_file, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )


def load_public_key_from_cert(cert_path: str) -> rsa.RSAPublicKey:
    """Load RSA public key from certificate file.
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        RSA public key object
    """
    from cryptography import x509
    
    cert_file = Path(cert_path)
    with open(cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(
            f.read(),
            default_backend()
        )
    
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Certificate does not contain an RSA public key")
    
    return public_key


def get_public_key_from_cert(cert_pem: str) -> rsa.RSAPublicKey:
    """Extract RSA public key from PEM certificate string.
    
    Args:
        cert_pem: PEM encoded certificate string
        
    Returns:
        RSA public key object
    """
    from cryptography import x509
    
    cert = x509.load_pem_x509_certificate(
        cert_pem.encode('utf-8'),
        default_backend()
    )
    
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Certificate does not contain an RSA public key")
    
    return public_key


def sign_sha256(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign data using RSA with SHA-256 (PKCS#1 v1.5).
    
    Args:
        data: Data to sign
        private_key: RSA private key
        
    Returns:
        Digital signature bytes
    """
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def verify_sha256(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Verify RSA signature with SHA-256 (PKCS#1 v1.5).
    
    Args:
        data: Original data
        signature: Signature bytes to verify
        public_key: RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def sign_message_hash(message_hash: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign a pre-computed SHA-256 hash.
    
    This is used when the hash is already computed separately.
    
    Args:
        message_hash: SHA-256 hash of the message (32 bytes)
        private_key: RSA private key
        
    Returns:
        Digital signature bytes
    """
    # Note: PKCS#1 v1.5 padding with SHA-256 uses ASN.1 DER encoding
    # The cryptography library handles this automatically
    return private_key.sign(
        message_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def verify_message_hash(message_hash: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Verify signature of a pre-computed SHA-256 hash.
    
    Args:
        message_hash: SHA-256 hash of the message (32 bytes)
        signature: Signature bytes to verify
        public_key: RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            message_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False