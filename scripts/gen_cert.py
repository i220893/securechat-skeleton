#!/usr/bin/env python3
"""
Issue an RSA X.509 certificate for server/client, signed by the Root CA.

Usage examples (after gen_ca.py has been run):

    python scripts/gen_ca.py --name "FAST-NU Root CA"

    python scripts/gen_cert.py --cn server.local --out certs/server
    python scripts/gen_cert.py --cn client.local --out certs/client

This will create:

    certs/server/key.pem   - server private key   (DO NOT COMMIT)
    certs/server/cert.pem  - server certificate   (PEM)

    certs/client/key.pem   - client private key   (DO NOT COMMIT)
    certs/client/cert.pem  - client certificate   (PEM)
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_CA_DIR = PROJECT_ROOT / "certs" / "ca"
DEFAULT_CA_KEY = DEFAULT_CA_DIR / "ca_key.pem"
DEFAULT_CA_CERT = DEFAULT_CA_DIR / "ca_cert.pem"

DEFAULT_OUT_DIR = PROJECT_ROOT / "certs" / "server"


def load_ca(ca_key_path: Path, ca_cert_path: Path):
    """Load CA private key and certificate from PEM files."""
    if not ca_key_path.exists():
        raise FileNotFoundError(f"CA private key not found: {ca_key_path}")
    if not ca_cert_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")

    with ca_key_path.open("rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    with ca_cert_path.open("rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert


def issue_cert(
    common_name: str,
    out_dir: Path,
    ca_key,
    ca_cert,
    key_size: int = 2048,
    days_valid: int = 365,
) -> None:
    """
    Issue a non-CA X.509 certificate for a given CN, signed by the provided Root CA.

    :param common_name: CN for the end-entity cert (e.g., "server.local").
    :param out_dir: Directory where key.pem and cert.pem will be written.
    :param ca_key: CA private key object.
    :param ca_cert: CA certificate object.
    :param key_size: RSA key size in bits.
    :param days_valid: Certificate validity period in days.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate end-entity private key
    ee_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # 2. Build subject name
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    # 3. Certificate metadata
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)  # issued by our Root CA
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        # Mark as end-entity (not a CA)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(common_name)]
            ),
            critical=False,
        )
    )

    ee_cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )

    key_path = out_dir / "key.pem"
    cert_path = out_dir / "cert.pem"

    # 4. Write private key and certificate
    with key_path.open("wb") as f:
        f.write(
            ee_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),  # for this lab
            )
        )

    with cert_path.open("wb") as f:
        f.write(
            ee_cert.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
        )

    print(f"[+] Wrote entity private key to: {key_path}")
    print(f"[+] Wrote entity certificate to:  {cert_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Issue a client/server X.509 certificate signed by the Root CA."
    )
    parser.add_argument(
        "--cn",
        required=True,
        help="Common Name (CN) for the certificate (e.g., 'server.local', 'client.local').",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help="Output directory for key.pem and cert.pem (default: certs/server/).",
    )
    parser.add_argument(
        "--ca-key",
        type=Path,
        default=DEFAULT_CA_KEY,
        help="Path to CA private key PEM (default: certs/ca/ca_key.pem).",
    )
    parser.add_argument(
        "--ca-cert",
        type=Path,
        default=DEFAULT_CA_CERT,
        help="Path to CA certificate PEM (default: certs/ca/ca_cert.pem).",
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
        default=365,
        help="Certificate validity in days (default: 365).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ca_key, ca_cert = load_ca(args.ca_key, args.ca_cert)
    issue_cert(
        common_name=args.cn,
        out_dir=args.out,
        ca_key=ca_key,
        ca_cert=ca_cert,
        key_size=args.key_size,
        days_valid=args.days,
    )


if __name__ == "__main__":
    main()
