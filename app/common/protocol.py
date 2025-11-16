"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from typing import Optional
from pydantic import BaseModel


class HelloMessage(BaseModel):
    """Client hello with certificate and nonce."""
    type: str = "hello"
    client_cert: str  # PEM encoded certificate
    nonce: str  # Base64 encoded nonce


class ServerHelloMessage(BaseModel):
    """Server hello with certificate and nonce."""
    type: str = "server_hello"
    server_cert: str  # PEM encoded certificate
    nonce: str  # Base64 encoded nonce


class RegisterMessage(BaseModel):
    """Registration message with encrypted credentials."""
    type: str = "register"
    email: str
    username: str
    pwd: str  # Base64(sha256(salt||pwd))
    salt: str  # Base64 encoded salt


class LoginMessage(BaseModel):
    """Login message with encrypted credentials."""
    type: str = "login"
    email: str
    pwd: str  # Base64(sha256(salt||pwd))
    nonce: str  # Base64 encoded nonce


class DHClientMessage(BaseModel):
    """Diffie-Hellman client parameters."""
    type: str = "dh_client"
    g: int  # Generator
    p: int  # Prime modulus
    A: int  # Public value: g^a mod p


class DHServerMessage(BaseModel):
    """Diffie-Hellman server response."""
    type: str = "dh_server"
    B: int  # Public value: g^b mod p


class Message(BaseModel):
    """Encrypted chat message with signature."""
    type: str = "msg"
    seqno: int  # Sequence number
    ts: int  # Unix timestamp in milliseconds
    ct: str  # Base64 encoded ciphertext
    sig: str  # Base64 encoded RSA signature


class ReceiptMessage(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int  # First sequence number
    last_seq: int  # Last sequence number
    transcript_sha256: str  # Hex encoded SHA-256 of transcript
    sig: str  # Base64 encoded RSA signature