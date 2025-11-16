"""
Diffie–Hellman helpers for SecureChat.

We use classic (finite-field) DH via the `cryptography` library:

- One side generates parameters (p, g) and its own private/public key.
- It sends (p, g, public_y) to the peer.
- The peer uses (p, g) to generate its own private/public key.
- Both sides compute the same shared_secret via DH.
- We derive a 16-byte AES-128 key as: Trunc16(SHA256(shared_secret_bytes)).

All of this is at the application layer; no TLS/SSL is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh


class DHError(Exception):
    """Generic Diffie–Hellman related error."""


@dataclass
class DHKeyPair:
    """
    Holds DH private key + public parameters.

    - p, g: the group parameters (integers)
    - y:    the public value g^x mod p
    - private_key: cryptography DHPrivateKey object (kept local)
    """

    p: int
    g: int
    y: int
    private_key: dh.DHPrivateKey


# ---------------------------------------------------------------------------
# Keypair generation
# ---------------------------------------------------------------------------


def generate_dh_keypair(key_size: int = 2048) -> DHKeyPair:
    """
    Generate fresh DH parameters (p, g) and a DH keypair.

    This is typically used by the side that *starts* the exchange
    (e.g., the client for the login/session key exchange).

    :param key_size: size of the prime modulus in bits (default: 2048).
    :return: DHKeyPair containing p, g, public_y, and private_key.
    """
    parameters = dh.generate_parameters(generator=2, key_size=key_size)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    param_numbers = parameters.parameter_numbers()
    public_numbers = public_key.public_numbers()

    return DHKeyPair(
        p=param_numbers.p,
        g=param_numbers.g,
        y=public_numbers.y,
        private_key=private_key,
    )


def generate_dh_keypair_from_params(p: int, g: int) -> DHKeyPair:
    """
    Generate a DH keypair using existing parameters (p, g).

    This is used by the *responder* (e.g., server) after it receives p, g
    from the peer.

    :param p: prime modulus
    :param g: generator
    :return: DHKeyPair with same p, g and a new public_y/private_key.
    """
    param_numbers = dh.DHParameterNumbers(p, g)
    parameters = param_numbers.parameters()
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    return DHKeyPair(
        p=p,
        g=g,
        y=public_numbers.y,
        private_key=private_key,
    )


# ---------------------------------------------------------------------------
# Shared secret + key derivation
# ---------------------------------------------------------------------------


def compute_shared_secret(
    my_keypair: DHKeyPair,
    peer_y: int,
) -> bytes:
    """
    Compute the raw DH shared secret from our private key and peer's public y.

    :param my_keypair: DHKeyPair with our private_key, p, g.
    :param peer_y: peer's public value g^x mod p.
    :return: raw shared secret bytes from DH exchange.
    """
    param_numbers = dh.DHParameterNumbers(my_keypair.p, my_keypair.g)
    peer_public_numbers = dh.DHPublicNumbers(peer_y, param_numbers)
    peer_public_key = peer_public_numbers.public_key()

    try:
        shared_secret = my_keypair.private_key.exchange(peer_public_key)
    except Exception as exc:  # noqa: BLE001
        raise DHError(f"Failed to compute shared secret: {exc}") from exc

    # `shared_secret` is already a byte string as returned by cryptography.
    return shared_secret


def derive_aes_key_from_shared_secret(
    shared_secret: bytes,
    key_len: int = 16,
) -> bytes:
    """
    Derive an AES key from the raw DH shared secret.

    According to the assignment, we use:
        K = Trunc16(SHA256(shared_secret_bytes))

    :param shared_secret: raw DH shared secret (bytes).
    :param key_len: desired key length in bytes (default: 16 for AES-128).
    :return: derived key of length key_len.
    """
    if key_len <= 0:
        raise DHError("key_len must be positive")
    if not isinstance(shared_secret, (bytes, bytearray)):
        raise DHError("shared_secret must be bytes")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    full_hash = digest.finalize()
    if len(full_hash) < key_len:
        raise DHError("Derived hash shorter than requested key_len")

    return full_hash[:key_len]


def derive_aes_key(
    my_keypair: DHKeyPair,
    peer_y: int,
    key_len: int = 16,
) -> Tuple[bytes, bytes]:
    """
    Convenience function: compute shared_secret and derive an AES key.

    :param my_keypair: our DHKeyPair
    :param peer_y: peer's public y
    :param key_len: desired AES key length (16 bytes for AES-128)
    :return: (shared_secret_bytes, aes_key_bytes)
    """
    shared_secret = compute_shared_secret(my_keypair, peer_y)
    aes_key = derive_aes_key_from_shared_secret(shared_secret, key_len=key_len)
    return shared_secret, aes_key


# ---------------------------------------------------------------------------
# Optional demo CLI
# ---------------------------------------------------------------------------


def _cli_demo() -> None:
    """
    Small demo:

        python -m app.crypto.dh --demo

    Shows that both sides derive the same AES-128 key.
    """
    import argparse
    import binascii

    parser = argparse.ArgumentParser(description="DH + AES-key derivation demo")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a local DH exchange and print both sides' keys.",
    )
    args = parser.parse_args()

    if not args.demo:
        parser.print_help()
        return

    # Simulate "client" creating fresh parameters and keypair
    client_kp = generate_dh_keypair(key_size=2048)

    # Simulate "server" using same (p, g) from client
    server_kp = generate_dh_keypair_from_params(client_kp.p, client_kp.g)

    # Each side computes shared secret & AES key
    client_shared, client_aes = derive_aes_key(client_kp, server_kp.y)
    server_shared, server_aes = derive_aes_key(server_kp, client_kp.y)

    print(f"client p  = {client_kp.p}")
    print(f"client g  = {client_kp.g}")
    print(f"client yC = {client_kp.y}")
    print(f"server yS = {server_kp.y}")
    print()
    print(f"client shared = {binascii.hexlify(client_shared).decode()}")
    print(f"server shared = {binascii.hexlify(server_shared).decode()}")
    print()
    print(f"client AES-128 key = {binascii.hexlify(client_aes).decode()}")
    print(f"server AES-128 key = {binascii.hexlify(server_aes).decode()}")
    print()
    print("Keys equal? ", client_aes == server_aes)


if __name__ == "__main__":
    _cli_demo()
