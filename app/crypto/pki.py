"""
PKI helpers for SecureChat.

- Load X.509 certificates from PEM (files or strings)
- Verify that a certificate is:
    * Currently valid (time window)
    * Signed by our trusted Root CA
    * Has an expected Common Name (CN)

We do NOT use TLS/SSL sockets here. All crypto is at the application layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID


# ----- Custom error type -----------------------------------------------------


@dataclass
class CertificateError(Exception):
    """Raised when a peer certificate fails validation."""

    message: str

    def __str__(self) -> str:
        return f"CertificateError: {self.message}"


# ----- Basic loading helpers -------------------------------------------------


def load_cert_from_pem(pem_data: bytes) -> x509.Certificate:
    """
    Load an X.509 certificate from PEM-encoded bytes.
    """
    try:
        return x509.load_pem_x509_certificate(pem_data)
    except Exception as exc:  # noqa: BLE001
        raise CertificateError(f"Failed to parse PEM certificate: {exc}") from exc


def load_cert_from_file(path: Path) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.
    """
    if not path.exists():
        raise CertificateError(f"Certificate file not found: {path}")

    with path.open("rb") as f:
        pem_data = f.read()
    return load_cert_from_pem(pem_data)


def get_common_name(cert: x509.Certificate) -> Optional[str]:
    """
    Extract the Common Name (CN) from the certificate subject.
    Returns None if there is no CN attribute.
    """
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    except Exception:
        return None

    if not attrs:
        return None
    return attrs[0].value


# ----- Individual checks -----------------------------------------------------


def check_time_validity(
    cert: x509.Certificate,
    now: Optional[datetime] = None,
) -> None:
    """
    Ensure the certificate is valid at the given time.

    Raises CertificateError if:
      - current time is before not_valid_before, or
      - current time is after not_valid_after.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if now < not_before or now > not_after:
        raise CertificateError(
            f"Certificate expired or not yet valid: "
            f"{not_before.isoformat()} .. {not_after.isoformat()}"
        )


def verify_signed_by(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
) -> None:
    """
    Verify that `cert` is signed by `issuer_cert`.

    Checks:
      - issuer DN matches issuer_cert.subject
      - signature over tbs_certificate_bytes verifies with issuer_cert.public_key()

    Raises CertificateError on failure.
    """
    if cert.issuer != issuer_cert.subject:
        raise CertificateError(
            "Issuer mismatch: certificate is not issued by the given CA"
        )

    public_key = issuer_cert.public_key()
    try:
        public_key.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )
    except Exception as exc:  # noqa: BLE001
        raise CertificateError(f"Certificate signature invalid: {exc}") from exc


def check_common_name(
    cert: x509.Certificate,
    expected_cn: str,
) -> None:
    """
    Check that the certificate's Common Name equals the expected value.

    Raises CertificateError on mismatch.
    """
    cn = get_common_name(cert)
    if cn is None:
        raise CertificateError(
            f"Certificate has no Common Name (CN); expected {expected_cn!r}"
        )
    if cn != expected_cn:
        raise CertificateError(
            f"CN mismatch: expected {expected_cn!r}, got {cn!r}"
        )


# ----- High-level validation entrypoint --------------------------------------


def validate_peer_cert(
    peer_pem_str: str,
    ca_cert: x509.Certificate,
    expected_cn: str,
) -> x509.Certificate:
    """
    Validate a peer certificate against our trusted CA and expected CN.

    Steps:
      1. Parse peer cert from PEM string.
      2. Check validity window (notBefore / notAfter).
      3. Verify signature using CA certificate.
      4. Check Common Name == expected_cn.

    Returns the parsed certificate object on success.
    Raises CertificateError on any failure.
    """
    # 1. Parse PEM
    peer_cert = load_cert_from_pem(peer_pem_str.encode("utf-8"))

    # 2. Time validity
    check_time_validity(peer_cert)

    # 3. Signature chain
    verify_signed_by(peer_cert, ca_cert)

    # 4. CN / hostname match
    check_common_name(peer_cert, expected_cn)

    return peer_cert


# ----- Optional CLI for manual testing ---------------------------------------


def _cli() -> None:
    """
    Simple CLI helper:

    python -m app.crypto.pki --cert path/to/cert.pem --ca certs/ca/ca_cert.pem --cn server.local
    """
    import argparse  # local import to keep top-level clean

    parser = argparse.ArgumentParser(
        description="Manual peer-certificate validation helper."
    )
    parser.add_argument(
        "--cert",
        type=Path,
        required=True,
        help="Path to peer certificate (PEM).",
    )
    parser.add_argument(
        "--ca",
        type=Path,
        required=True,
        help="Path to CA certificate (PEM).",
    )
    parser.add_argument(
        "--cn",
        required=True,
        help="Expected Common Name for the peer certificate.",
    )
    args = parser.parse_args()

    ca_cert = load_cert_from_file(args.ca)
    peer_cert = load_cert_from_file(args.cert)

    # Reuse checks individually for CLI
    try:
        check_time_validity(peer_cert)
        verify_signed_by(peer_cert, ca_cert)
        check_common_name(peer_cert, args.cn)
    except CertificateError as e:
        print(f"[BAD_CERT] {e}")
        raise SystemExit(1)
    else:
        print("[OK] Peer certificate is valid and trusted.")


if __name__ == "__main__":
    _cli()
