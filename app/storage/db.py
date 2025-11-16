"""MySQL users table + salted hashing (no chat storage)."""

import argparse
import os
import secrets
import hashlib
import pymysql
from typing import Optional, Tuple
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    """Get MySQL database connection.
    
    Returns:
        Database connection object
    """
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER", "scuser"),
        password=os.getenv("DB_PASSWORD", "scpass"),
        database=os.getenv("DB_NAME", "securechat"),
        cursorclass=pymysql.cursors.DictCursor
    )


def init_database():
    """Initialize database schema (create users table if not exists)."""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (username),
                    INDEX idx_email (email)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
        connection.commit()
        print("✓ Database initialized successfully")
    finally:
        connection.close()


def generate_salt() -> bytes:
    """Generate a random 16-byte salt.
    
    Returns:
        16-byte random salt
    """
    return secrets.token_bytes(16)


def hash_password(password: str, salt: bytes) -> str:
    """Compute salted password hash.
    
    pwd_hash = hex(SHA256(salt || password))
    
    Args:
        password: Plaintext password
        salt: 16-byte salt
        
    Returns:
        Hex-encoded SHA-256 hash (64 characters)
    """
    # Concatenate salt and password
    salted_password = salt + password.encode('utf-8')
    
    # Compute SHA-256 hash
    hash_bytes = hashlib.sha256(salted_password).digest()
    
    # Return hex string
    return hash_bytes.hex()


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode('utf-8'), b.encode('utf-8')):
        result |= x ^ y
    return result == 0


def register_user(email: str, username: str, password: str) -> bool:
    """Register a new user with salted password hash.
    
    Args:
        email: User email
        username: Username (must be unique)
        password: Plaintext password
        
    Returns:
        True if registration successful, False if user already exists
        
    Raises:
        Exception on database errors
    """
    connection = get_db_connection()
    try:
        # Check if username or email already exists
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT username, email FROM users WHERE username = %s OR email = %s",
                (username, email)
            )
            existing = cursor.fetchone()
            if existing:
                return False
        
        # Generate salt and hash password
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)
        
        # Insert user
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
        connection.commit()
        return True
    except pymysql.err.IntegrityError:
        # Duplicate entry
        return False
    finally:
        connection.close()


def verify_user(email: str, password: str) -> Optional[Tuple[str, str]]:
    """Verify user credentials.
    
    Args:
        email: User email
        password: Plaintext password
        
    Returns:
        Tuple of (username, email) if credentials are valid, None otherwise
    """
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
            if not user:
                return None
            
            # Compute expected hash
            salt = user['salt']
            expected_hash = hash_password(password, salt)
            
            # Constant-time comparison
            if constant_time_compare(expected_hash, user['pwd_hash']):
                return (user['username'], email)
            return None
    finally:
        connection.close()


def get_user_salt(email: str) -> Optional[bytes]:
    """Get user's salt for password hashing (used during login).
    
    Args:
        email: User email
        
    Returns:
        Salt bytes if user exists, None otherwise
    """
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT salt FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
            if user:
                return user['salt']
            return None
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description="Database management")
    parser.add_argument("--init", action="store_true", help="Initialize database schema")
    
    args = parser.parse_args()
    
    if args.init:
        init_database()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()