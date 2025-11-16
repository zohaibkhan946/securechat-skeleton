"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Pad data using PKCS#7 padding.
    
    Args:
        data: Data to pad
        block_size: Block size in bytes (default: 16 for AES)
        
    Returns:
        Padded data
    """
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data


def unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS#7 padding from data.
    
    Args:
        data: Padded data
        block_size: Block size in bytes (default: 16 for AES)
        
    Returns:
        Unpadded data
        
    Raises:
        ValueError if padding is invalid
    """
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    unpadded_data = unpadder.update(data)
    unpadded_data += unpadder.finalize()
    return unpadded_data


def encrypt_aes128_ecb(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: Plaintext to encrypt
        key: 16-byte AES key
        
    Returns:
        Ciphertext
        
    Raises:
        ValueError if key length is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Pad the plaintext
    padded_plaintext = pad_pkcs7(plaintext, block_size=16)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),  # Electronic Codebook mode
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext


def decrypt_aes128_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext using AES-128 in ECB mode with PKCS#7 padding removal.
    
    Args:
        ciphertext: Ciphertext to decrypt
        key: 16-byte AES key
        
    Returns:
        Plaintext (unpadded)
        
    Raises:
        ValueError if key length is not 16 bytes or if padding is invalid
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),  # Electronic Codebook mode
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = unpad_pkcs7(padded_plaintext, block_size=16)
    
    return plaintext