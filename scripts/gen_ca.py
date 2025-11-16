#!/usr/bin/env python3
"""
Generate a Root CA (RSA keypair + self-signed X.509 certificate) for SecureChat.

Usage:
    python scripts/gen_ca.py --name "FAST-NU Root CA"

This will create:
    certs/ca/ca_key.pem   - CA private key (PEM, unencrypted; DO NOT COMMIT)
    certs/ca/ca_cert.pem  - CA self-signed certificate (PEM)
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Project root = two levels up from this file: scripts/ -> project root
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CERTS_DIR = PROJECT_ROOT / "certs" / "ca"


def generate_root_ca(common_name: str, out_dir: Path, key_size: int = 2048, days_valid: int = 3650) -> None:
    """
    Generate an RSA keypair and a self-signed X.509 certificate usable as a Root CA.

    :param common_name: CN of the CA (e.g., "FAST-NU Root CA").
    :param out_dir: Directory where ca_key.pem and ca_cert.pem will be written.
    :param key_size: RSA key size in bits (>=2048 recommended).
    :param days_valid: Certificate validity period in days.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate CA private key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # 2. Build subject/issuer name (same for self-signed CA)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    # 3. Certificate metadata
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        # Mark as a CA certificate
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    ca_cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )

    # 4. Write private key and certificate to disk
    key_path = out_dir / "ca_key.pem"
    cert_path = out_dir / "ca_cert.pem"

    with key_path.open("wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),  # keep key unencrypted for this lab
            )
        )

    with cert_path.open("wb") as f:
        f.write(
            ca_cert.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
        )

    print(f"[+] Wrote CA private key to: {key_path}")
    print(f"[+] Wrote CA certificate to: {cert_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a Root CA for SecureChat.")
    parser.add_argument(
        "--name",
        required=True,
        help="Common Name (CN) for the Root CA (e.g., 'FAST-NU Root CA').",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_CERTS_DIR,
        help="Output directory for CA key/cert (default: certs/ca/).",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=2048,
        help="RSA key size in bits (default: 2048).",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=3650,
        help="Certificate validity in days (default: ~10 years).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    generate_root_ca(
        common_name=args.name,
        out_dir=args.out,
        key_size=args.key_size,
        days_valid=args.days,
    )


if __name__ == "__main__":
    main()
