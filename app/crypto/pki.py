"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime


class PKIValidationError(Exception):
    """Exception raised when certificate validation fails."""
    pass


def load_certificate_from_pem(pem_data: str) -> x509.Certificate:
    """Load X.509 certificate from PEM string.
    
    Args:
        pem_data: PEM encoded certificate string
        
    Returns:
        X.509 certificate object
    """
    try:
        return x509.load_pem_x509_certificate(
            pem_data.encode('utf-8'),
            default_backend()
        )
    except Exception as e:
        raise PKIValidationError(f"Failed to parse certificate: {e}")


def load_ca_certificate(ca_path: str = "certs/ca_cert.pem") -> x509.Certificate:
    """Load CA certificate from file.
    
    Args:
        ca_path: Path to CA certificate file
        
    Returns:
        CA certificate object
    """
    try:
        cert_path = Path(ca_path)
        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                default_backend()
            )
    except Exception as e:
        raise PKIValidationError(f"Failed to load CA certificate: {e}")


def verify_certificate_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Verify that certificate is signed by the CA.
    
    Args:
        cert: Certificate to verify
        ca_cert: CA certificate (issuer)
        
    Returns:
        True if valid, raises PKIValidationError otherwise
    """
    try:
        # Get CA's public key
        ca_public_key = ca_cert.public_key()
        
        # Get signature algorithm from certificate
        sig_algorithm = cert.signature_algorithm_oid
        
        # Determine hash algorithm from signature algorithm OID
        from cryptography.x509.oid import SignatureAlgorithmOID
        if sig_algorithm == SignatureAlgorithmOID.RSA_WITH_MD5:
            hash_alg = hashes.MD5()
        elif sig_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA1:
            hash_alg = hashes.SHA1()
        elif sig_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA256:
            hash_alg = hashes.SHA256()
        elif sig_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA384:
            hash_alg = hashes.SHA384()
        elif sig_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA512:
            hash_alg = hashes.SHA512()
        else:
            # Default to SHA256
            hash_alg = hashes.SHA256()
        
        # Verify signature using PKCS1v15 padding
        from cryptography.hazmat.primitives.asymmetric import padding
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_alg
        )
        
        # Verify issuer matches CA subject
        if cert.issuer != ca_cert.subject:
            raise PKIValidationError("Certificate issuer does not match CA subject")
        
        return True
    except Exception as e:
        if isinstance(e, PKIValidationError):
            raise
        raise PKIValidationError(f"Certificate signature verification failed: {e}")


def check_certificate_validity(cert: x509.Certificate) -> bool:
    """Check if certificate is within validity period.
    
    Args:
        cert: Certificate to check
        
    Returns:
        True if valid, raises PKIValidationError otherwise
    """
    now = datetime.utcnow()
    
    if cert.not_valid_before > now:
        raise PKIValidationError(f"Certificate not yet valid (valid from {cert.not_valid_before})")
    
    if cert.not_valid_after < now:
        raise PKIValidationError(f"Certificate expired (expired on {cert.not_valid_after})")
    
    return True


def check_common_name(cert: x509.Certificate, expected_cn: str = None) -> str:
    """Extract and optionally verify Common Name from certificate.
    
    Args:
        cert: Certificate to check
        expected_cn: Optional expected CN to verify against
        
    Returns:
        Common Name string
        
    Raises:
        PKIValidationError if CN doesn't match or is missing
    """
    # Extract CN from subject
    cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attributes:
        raise PKIValidationError("Certificate missing Common Name")
    
    cn = cn_attributes[0].value
    
    # Check SAN extension for DNS names (more specific)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        if dns_names:
            # Use first DNS name from SAN if available
            cn = dns_names[0]
    except x509.ExtensionNotFound:
        pass  # SAN not present, use CN from subject
    
    # Verify against expected CN if provided
    if expected_cn is not None and cn != expected_cn:
        raise PKIValidationError(f"Certificate CN mismatch: expected '{expected_cn}', got '{cn}'")
    
    return cn


def verify_certificate(
    cert_pem: str,
    ca_cert_path: str = "certs/ca_cert.pem",
    expected_cn: str = None
) -> tuple[x509.Certificate, str]:
    """Comprehensive certificate verification.
    
    Performs the following checks:
    1. Parse certificate
    2. Verify certificate chain (signed by CA)
    3. Check validity period
    4. Extract/verify Common Name
    
    Args:
        cert_pem: PEM encoded certificate string
        ca_cert_path: Path to CA certificate file
        expected_cn: Optional expected Common Name to verify
        
    Returns:
        Tuple of (certificate object, Common Name)
        
    Raises:
        PKIValidationError if any check fails
    """
    # Load and parse certificate
    cert = load_certificate_from_pem(cert_pem)
    
    # Reject self-signed certificates (issuer == subject)
    if cert.issuer == cert.subject:
        raise PKIValidationError("BAD_CERT: Self-signed certificate rejected")
    
    # Load CA certificate
    ca_cert = load_ca_certificate(ca_cert_path)
    
    # Verify certificate chain
    verify_certificate_chain(cert, ca_cert)
    
    # Check validity period
    check_certificate_validity(cert)
    
    # Extract/verify CN
    cn = check_common_name(cert, expected_cn)
    
    return cert, cn


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA-256 fingerprint of certificate.
    
    Args:
        cert: Certificate object
        
    Returns:
        Hex-encoded SHA-256 fingerprint
    """
    return cert.fingerprint(hashes.SHA256()).hex()