"""
AES-128 (ECB) + PKCS#7 padding helpers for SecureChat.

- Uses a 16-byte key (AES-128 only).
- Uses ECB mode (block cipher only, as specified in the assignment).
- Applies PKCS#7 padding for arbitrary-length plaintexts.

This module does NOT deal with sockets or TLS; it's purely application-layer crypto.
"""

from __future__ import annotations

from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


BLOCK_SIZE_BYTES = 16  # AES block size = 128 bits


class AesError(Exception):
    """Generic AES-related error (bad key, padding failure, etc.)."""


# ----- PKCS#7 padding helpers -------------------------------------------------


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    """
    Apply PKCS#7 padding to arbitrary-length data.

    :param data: plaintext bytes
    :param block_size: block size in bytes (16 for AES)
    :return: padded bytes whose length is a multiple of block_size
    """
    padder = sym_padding.PKCS7(block_size * 8).padder()  # block_size in bits
    padded = padder.update(data) + padder.finalize()
    return padded


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    """
    Remove PKCS#7 padding.

    :param padded: padded bytes
    :param block_size: block size in bytes
    :return: original unpadded bytes
    :raises AesError: if padding is invalid
    """
    unpadder = sym_padding.PKCS7(block_size * 8).unpadder()
    try:
        data = unpadder.update(padded) + unpadder.finalize()
    except Exception as exc:  # noqa: BLE001
        raise AesError(f"Invalid PKCS#7 padding: {exc}") from exc
    return data


# ----- AES-128 ECB helpers ----------------------------------------------------


def _build_cipher(key: bytes) -> Cipher:
    """
    Internal helper to create a Cipher object for AES-128 ECB.

    :param key: 16-byte AES key
    :return: Cipher instance
    :raises AesError: if key length is not 16 bytes
    """
    if not isinstance(key, (bytes, bytearray)):
        raise AesError("AES key must be bytes")
    if len(key) != BLOCK_SIZE_BYTES:
        raise AesError(f"AES-128 key must be {BLOCK_SIZE_BYTES} bytes, got {len(key)}")

    algorithm = algorithms.AES(bytes(key))
    mode = modes.ECB()
    return Cipher(algorithm, mode)


def aes_encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-128 in ECB mode using PKCS#7 padding.

    :param key: 16-byte AES key
    :param plaintext: arbitrary-length plaintext bytes
    :return: ciphertext bytes
    """
    cipher = _build_cipher(key)
    encryptor = cipher.encryptor()

    padded = pkcs7_pad(plaintext, BLOCK_SIZE_BYTES)
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct


def aes_decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext with AES-128 in ECB mode and remove PKCS#7 padding.

    :param key: 16-byte AES key
    :param ciphertext: ciphertext bytes (multiple of block size)
    :return: decrypted plaintext bytes
    :raises AesError: on invalid key or padding
    """
    cipher = _build_cipher(key)
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = pkcs7_unpad(padded, BLOCK_SIZE_BYTES)
    return plaintext


# ----- Optional CLI for quick manual testing ----------------------------------


def _cli() -> None:
    """
    Simple CLI:

        python -m app.crypto.aes --key 00112233445566778899aabbccddeeff --enc "hello"
        python -m app.crypto.aes --key 00112233445566778899aabbccddeeff --dec <hex_ct>

    Key must be 32 hex chars (16 bytes).
    """
    import argparse
    import binascii
    import sys

    parser = argparse.ArgumentParser(description="AES-128-ECB + PKCS#7 test helper")
    parser.add_argument(
        "--key",
        required=True,
        help="AES-128 key as 32 hex characters (16 bytes).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--enc", help="Plaintext string to encrypt.")
    group.add_argument("--dec", help="Ciphertext as hex string to decrypt.")
    args = parser.parse_args()

    try:
        key = binascii.unhexlify(args.key)
    except Exception as exc:  # noqa: BLE001
        print(f"[ERR] Invalid key hex: {exc}")
        sys.exit(1)

    if len(key) != BLOCK_SIZE_BYTES:
        print(f"[ERR] Key must be {BLOCK_SIZE_BYTES} bytes, got {len(key)}")
        sys.exit(1)

    if args.enc is not None:
        pt = args.enc.encode("utf-8")
        ct = aes_encrypt_ecb(key, pt)
        print(binascii.hexlify(ct).decode("ascii"))
    else:
        try:
            ct = binascii.unhexlify(args.dec)
        except Exception as exc:  # noqa: BLE001
            print(f"[ERR] Invalid ciphertext hex: {exc}")
            sys.exit(1)

        try:
            pt = aes_decrypt_ecb(key, ct)
        except AesError as exc:
            print(f"[ERR] {exc}")
            sys.exit(1)
        print(pt.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    _cli()
