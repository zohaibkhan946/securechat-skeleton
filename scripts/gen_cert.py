"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta


def load_ca_key_and_cert(ca_dir: str = "certs"):
    """Load CA private key and certificate.
    
    Returns:
        Tuple of (private_key, certificate)
    """
    ca_path = Path(ca_dir)
    
    # Load CA private key
    key_path = ca_path / "ca_key.pem"
    with open(key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    cert_path = ca_path / "ca_cert.pem"
    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_private_key, ca_cert


def issue_certificate(cn: str, ca_dir: str = "certs", output_prefix: str = None, valid_days: int = 365):
    """Issue a certificate signed by the root CA.
    
    Args:
        cn: Common Name (hostname) for the certificate
        ca_dir: Directory containing CA key and cert
        output_prefix: Prefix for output files (e.g., "server" -> server_key.pem, server_cert.pem)
        valid_days: Validity period in days
    """
    if output_prefix is None:
        output_prefix = cn.replace(".", "_")
    
    output_path = Path(ca_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Load CA key and cert
    ca_private_key, ca_cert = load_ca_key_and_cert(ca_dir)
    
    # Generate RSA private key (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sindh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Karachi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Certificate valid for specified days
    now = datetime.utcnow()
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # Issued by CA
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + timedelta(days=valid_days)
    )
    
    # Add Subject Alternative Name (SAN) with DNS name
    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),
        ]),
        critical=False,
    )
    
    # Sign with CA private key
    cert = cert_builder.sign(ca_private_key, hashes.SHA256())
    
    # Save private key
    key_path = output_path / f"{output_prefix}_key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)  # Read-only for owner
    
    # Save certificate
    cert_path = output_path / f"{output_prefix}_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"✓ Certificate issued successfully!")
    print(f"  Private key: {key_path}")
    print(f"  Certificate: {cert_path}")
    print(f"  CN: {cn}")
    print(f"  Valid until: {cert.not_valid_after}")
    print(f"  Signed by: {ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")


def main():
    parser = argparse.ArgumentParser(description="Issue certificate signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name (hostname)")
    parser.add_argument("--out", help="Output file prefix (default: CN)")
    parser.add_argument("--ca-dir", default="certs", help="CA directory")
    parser.add_argument("--valid-days", type=int, default=365, help="Validity period in days")
    
    args = parser.parse_args()
    issue_certificate(args.cn, args.ca_dir, args.out, args.valid_days)


if __name__ == "__main__":
    main()