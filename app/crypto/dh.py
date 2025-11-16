"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import secrets
import hashlib


# Standard Diffie-Hellman parameters (RFC 5114, Group 14)
# These are well-known safe primes for DH
STANDARD_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF

STANDARD_G = 2


def generate_dh_params(p: int = None, g: int = None) -> tuple[int, int]:
    """Generate or return standard Diffie-Hellman parameters.
    
    Args:
        p: Prime modulus (default: standard 2048-bit prime)
        g: Generator (default: 2)
        
    Returns:
        Tuple of (p, g)
    """
    if p is None:
        p = STANDARD_P
    if g is None:
        g = STANDARD_G
    return p, g


def generate_private_key(p: int) -> int:
    """Generate a random private key for Diffie-Hellman.
    
    Args:
        p: Prime modulus
        
    Returns:
        Random private key in range [1, p-1]
    """
    # Generate a random integer in range [1, p-1]
    # Using secrets module for cryptographically secure randomness
    return secrets.randbelow(p - 1) + 1


def compute_public_value(g: int, private_key: int, p: int) -> int:
    """Compute public value: g^private_key mod p.
    
    Args:
        g: Generator
        private_key: Private key
        p: Prime modulus
        
    Returns:
        Public value: g^private_key mod p
    """
    return pow(g, private_key, p)


def compute_shared_secret(peer_public_value: int, private_key: int, p: int) -> int:
    """Compute shared secret: peer_public_value^private_key mod p.
    
    Args:
        peer_public_value: Peer's public value
        private_key: Our private key
        p: Prime modulus
        
    Returns:
        Shared secret: peer_public_value^private_key mod p
    """
    return pow(peer_public_value, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """Derive AES-128 key from shared secret.
    
    K = Trunc16(SHA256(big-endian(Ks)))
    
    Args:
        shared_secret: Shared secret Ks from DH exchange
        
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    # Determine number of bytes needed
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8,
        byteorder='big'
    )
    
    # Compute SHA-256 hash
    hash_bytes = hashlib.sha256(secret_bytes).digest()
    
    # Truncate to 16 bytes (128 bits) for AES-128
    return hash_bytes[:16]