#!/usr/bin/env python3
"""Verify that the securechat setup is correct."""

import sys
import os
from pathlib import Path


def check_file(path, description):
    """Check if a file exists."""
    if Path(path).exists():
        print(f"✓ {description}: {path}")
        return True
    else:
        print(f"✗ {description} missing: {path}")
        return False


def check_directory(path, description):
    """Check if a directory exists."""
    if Path(path).is_dir():
        print(f"✓ {description}: {path}")
        return True
    else:
        print(f"✗ {description} missing: {path}")
        return False


def main():
    """Verify setup."""
    print("SecureChat Setup Verification\n")
    print("=" * 50)
    
    errors = []
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("✗ Python 3.7+ required")
        errors.append("Python version")
    else:
        print(f"✓ Python version: {sys.version_info.major}.{sys.version_info.minor}")
    
    # Check required files
    print("\nChecking files...")
    files_to_check = [
        ("requirements.txt", "Requirements file"),
        ("README.md", "README file"),
        ("env.example", "Environment example file"),
        ("app/client.py", "Client implementation"),
        ("app/server.py", "Server implementation"),
        ("scripts/gen_ca.py", "CA generation script"),
        ("scripts/gen_cert.py", "Certificate generation script"),
    ]
    
    for file_path, description in files_to_check:
        if not check_file(file_path, description):
            errors.append(f"{description} ({file_path})")
    
    # Check directories
    print("\nChecking directories...")
    dirs_to_check = [
        ("app", "Application directory"),
        ("app/crypto", "Crypto module"),
        ("app/common", "Common module"),
        ("app/storage", "Storage module"),
        ("scripts", "Scripts directory"),
        ("certs", "Certificates directory"),
        ("transcripts", "Transcripts directory"),
    ]
    
    for dir_path, description in dirs_to_check:
        if not check_directory(dir_path, description):
            errors.append(f"{description} ({dir_path})")
    
    # Check .env file
    print("\nChecking configuration...")
    if Path(".env").exists():
        print("✓ .env file exists")
    else:
        print("✗ .env file missing (copy env.example to .env)")
        errors.append(".env file")
    
    # Check certificates
    print("\nChecking certificates...")
    cert_files = [
        ("certs/ca_cert.pem", "CA certificate"),
        ("certs/ca_key.pem", "CA private key"),
        ("certs/server_cert.pem", "Server certificate"),
        ("certs/server_key.pem", "Server private key"),
        ("certs/client_cert.pem", "Client certificate"),
        ("certs/client_key.pem", "Client private key"),
    ]
    
    certs_missing = False
    for cert_path, description in cert_files:
        if not check_file(cert_path, description):
            certs_missing = True
    
    if certs_missing:
        print("\n⚠ Certificates missing. Run:")
        print("  python scripts/gen_ca.py --name 'FAST-NU Root CA'")
        print("  python scripts/gen_cert.py --cn server.local --out server")
        print("  python scripts/gen_cert.py --cn client.local --out client")
    
    # Check imports
    print("\nChecking Python imports...")
    try:
        import cryptography
        print("✓ cryptography library")
    except ImportError:
        print("✗ cryptography library not installed")
        errors.append("cryptography library")
    
    try:
        import pymysql
        print("✓ PyMySQL library")
    except ImportError:
        print("✗ PyMySQL library not installed")
        errors.append("PyMySQL library")
    
    try:
        import pydantic
        print("✓ pydantic library")
    except ImportError:
        print("✗ pydantic library not installed")
        errors.append("pydantic library")
    
    try:
        import dotenv
        print("✓ python-dotenv library")
    except ImportError:
        print("✗ python-dotenv library not installed")
        errors.append("python-dotenv library")
    
    # Summary
    print("\n" + "=" * 50)
    if errors:
        print(f"\n⚠ Found {len(errors)} issue(s):")
        for error in errors:
            print(f"  - {error}")
        print("\nPlease fix the issues above before running the application.")
        return 1
    elif certs_missing:
        print("\n✓ Setup looks good, but certificates need to be generated.")
        return 0
    else:
        print("\n✓ Setup verification complete! Everything looks good.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
