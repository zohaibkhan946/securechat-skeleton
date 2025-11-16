"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
import os
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta


def create_root_ca(name: str, output_dir: str = "certs"):
    """Create a root Certificate Authority (CA).
    
    Args:
        name: Common Name (CN) for the CA
        output_dir: Directory to store CA certificate and key
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Generate RSA private key (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sindh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Karachi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    # Certificate valid for 10 years
    now = datetime.utcnow()
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # Save private key
    key_path = output_path / "ca_key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)  # Read-only for owner
    
    # Save certificate
    cert_path = output_path / "ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"✓ Root CA created successfully!")
    print(f"  Private key: {key_path}")
    print(f"  Certificate: {cert_path}")
    print(f"  CN: {name}")
    print(f"  Valid until: {cert.not_valid_after}")


def main():
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", default="FAST-NU Root CA", help="CA Common Name")
    parser.add_argument("--out", default="certs", help="Output directory")
    
    args = parser.parse_args()
    create_root_ca(args.name, args.out)


if __name__ == "__main__":
    main()