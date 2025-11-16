"""
RSA SHA-256 signing / verification helpers for SecureChat.

- Uses RSASSA-PKCS1v1_5 with SHA-256, via cryptography library.
- Works with private keys loaded from PEM.
- Verification can use either a public key or an X.509 certificate's public key.

We do NOT use TLS/SSL sockets; this is all application-layer crypto.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


@dataclass
class SignError(Exception):
    """Generic error for signing / verification."""

    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"SignError: {self.message}"


PublicKeyLike = Union[rsa.RSAPublicKey, x509.Certificate]


# ---------------------------------------------------------------------------
# Loading keys and certs
# ---------------------------------------------------------------------------


def load_private_key_from_file(path: Path, password: bytes | None = None) -> rsa.RSAPrivateKey:
    """
    Load an RSA private key from a PEM file.

    :param path: path to PEM-encoded private key
    :param password: password for encrypted private keys (None for unencrypted)
    :return: RSAPrivateKey object
    :raises SignError: on parsing/format errors
    """
    if not path.exists():
        raise SignError(f"Private key file not found: {path}")

    try:
        with path.open("rb") as f:
            key_data = f.read()
        key = serialization.load_pem_private_key(key_data, password=password)
    except Exception as exc:  # noqa: BLE001
        raise SignError(f"Failed to load private key: {exc}") from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise SignError("Loaded key is not an RSA private key")

    return key


def load_cert_from_file(path: Path) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.

    :param path: path to PEM-encoded certificate
    :return: x509.Certificate object
    :raises SignError: on parsing errors
    """
    if not path.exists():
        raise SignError(f"Certificate file not found: {path}")

    try:
        with path.open("rb") as f:
            pem = f.read()
        cert = x509.load_pem_x509_certificate(pem)
    except Exception as exc:  # noqa: BLE001
        raise SignError(f"Failed to load certificate: {exc}") from exc

    return cert


# ---------------------------------------------------------------------------
# Core sign / verify operations
# ---------------------------------------------------------------------------


def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign the given data using RSA + SHA-256 (PKCS#1 v1.5).

    NOTE:
        - `data` should be the exact byte string you want covered by the signature.
        - The hash is computed internally as SHA-256(data).

    :param private_key: RSAPrivateKey
    :param data: bytes to sign
    :return: signature bytes
    :raises SignError: on failure
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SignError("Data to sign must be bytes")

    try:
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as exc:  # noqa: BLE001
        raise SignError(f"Failed to create signature: {exc}") from exc

    return signature


def _get_public_key(pub: PublicKeyLike) -> rsa.RSAPublicKey:
    """
    Normalize input into an RSAPublicKey.

    Accepts either:
      - RSAPublicKey directly
      - x509.Certificate (uses its public key)
    """
    if isinstance(pub, rsa.RSAPublicKey):
        return pub

    if isinstance(pub, x509.Certificate):
        pk = pub.public_key()
        if not isinstance(pk, rsa.RSAPublicKey):
            raise SignError("Certificate does not contain an RSA public key")
        return pk

    raise SignError(f"Unsupported public key type: {type(pub)!r}")


def rsa_verify(pub: PublicKeyLike, data: bytes, signature: bytes) -> bool:
    """
    Verify an RSA + SHA-256 (PKCS#1 v1.5) signature.

    :param pub: RSAPublicKey or x509.Certificate
    :param data: original data that was signed
    :param signature: signature bytes
    :return: True if valid, False otherwise
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SignError("Data to verify must be bytes")

    public_key = _get_public_key(pub)
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# Optional CLI helper
# ---------------------------------------------------------------------------


def _cli() -> None:
    """
    Simple CLI usage:

        # Sign a message:
        python -m app.crypto.sign --key certs/server/key.pem --sign "hello"

        # Verify a signature (hex) against a cert:
        python -m app.crypto.sign --cert certs/server/cert.pem --verify "hello" --sig <hex>
    """
    import argparse
    import binascii
    import sys

    parser = argparse.ArgumentParser(description="RSA SHA-256 sign/verify helper")
    parser.add_argument("--key", type=Path, help="Path to RSA private key (PEM).")
    parser.add_argument("--cert", type=Path, help="Path to certificate (PEM) for verification.")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sign", help="String to sign with the given private key.")
    group.add_argument("--verify", help="String whose signature should be verified.")

    parser.add_argument(
        "--sig",
        help="Signature as hex string (required when using --verify).",
    )

    args = parser.parse_args()

    if args.sign:
        if not args.key:
            print("[ERR] --key is required for signing")
            sys.exit(1)

        priv = load_private_key_from_file(args.key)
        data = args.sign.encode("utf-8")
        sig = rsa_sign(priv, data)
        print(binascii.hexlify(sig).decode("ascii"))
        return

    # verify mode
    if not args.cert or not args.sig:
        print("[ERR] --cert and --sig are required for verification")
        sys.exit(1)

    cert = load_cert_from_file(args.cert)
    data = args.verify.encode("utf-8")
    try:
        sig_bytes = binascii.unhexlify(args.sig)
    except Exception as exc:  # noqa: BLE001
        print(f"[ERR] Invalid signature hex: {exc}")
        sys.exit(1)

    ok = rsa_verify(cert, data, sig_bytes)
    if ok:
        print("[OK] Signature is valid.")
    else:
        print("[BAD] Signature is INVALID.")
        sys.exit(1)


if __name__ == "__main__":
    _cli()
