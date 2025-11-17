"""
SecureChat client (practice skeleton, spec-aligned up to login).

Phases:

1) Connect to server over plain TCP.
2) Control plane:
   - Send:   {"type":"hello", "client cert":"...PEM...", "nonce": base64}
   - Receive{"type":"server hello", "server cert":"...PEM...", "nonce": base64}
   - Validate server cert (CA, validity, CN="server.local")
3) DH #1: temporary K_cred for protecting credentials.
   - Client -> Server: {"type":"dh client", "g":int, "p":int, "A":int}
   - Server -> Client: {"type":"dh server", "B":int}
4) Encrypted register OR login over K_cred.
   - Register:
       {"type":"register", "ct": base64(AES(JSON{email,username,password}))}
   - Login:
       {"type":"login",    "ct": base64(AES(JSON{email,password}))}
5) DH #2: session key K_session for future chat (not used in this skeleton).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
from getpass import getpass
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv

from app.common.protocol import (
    Hello,
    ServerHello,
    DhClient,
    DhServer,
    parse_message,
)
from app.common.utils import b64e, b64d
from app.crypto import pki
from app.crypto.dh import generate_dh_keypair, derive_aes_key
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))

CA_CERT_PATH = Path(os.getenv("CA_CERT_PATH", "certs/ca/ca_cert.pem"))

CLIENT_CERT_PATH = Path(os.getenv("CLIENT_CERT_PATH", "certs/client/cert.pem"))
EXPECTED_SERVER_CN = os.getenv("SERVER_CN", "server.local")


# ---------------------------------------------------------------------------
# Line-based JSON helpers (same framing as server)
# ---------------------------------------------------------------------------


def send_json(sock: socket.socket, obj: Any) -> None:
    """
    Send a JSON object followed by a newline.

    If `obj` is a Pydantic model, we serialize with aliases so that JSON keys
    like "client cert" / "server cert" match the spec exactly.
    """
    if hasattr(obj, "dict"):
        payload = obj.dict(by_alias=True)
    else:
        payload = obj
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    sock.sendall(data)


def recv_json(sock: socket.socket) -> Dict[str, Any]:
    """
    Receive one newline-terminated JSON object from the socket
    and return it as a dict.
    """
    chunks: list[bytes] = []
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("server closed connection")
        if ch == b"\n":
            break
        chunks.append(ch)
    raw = b"".join(chunks)
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# Phase 1: hello / server hello + PKI validation
# ---------------------------------------------------------------------------


def do_cert_handshake(sock: socket.socket) -> ServerHello:
    """
    Client side of hello / server hello:

    Client -> Server:
      {"type":"hello", "client cert":"...PEM...", "nonce": base64}

    Server -> Client:
      {"type":"server hello", "server cert":"...PEM...", "nonce": base64}

    Returns the parsed ServerHello model so caller can inspect if needed.
    """
    # Load client's own cert to send
    client_cert_pem = CLIENT_CERT_PATH.read_text(encoding="utf-8")
    client_nonce = os.urandom(16)

    hello = Hello(
        client_cert=client_cert_pem,
        nonce=b64e(client_nonce),
    )
    send_json(sock, hello)
    print("[HELLO] Sent client certificate.")

    # Receive server_hello
    raw = recv_json(sock)
    msg = parse_message(raw)
    if not isinstance(msg, ServerHello):
        raise ValueError(f"Expected 'server hello', got: {raw.get('type')}")

    server_cert_pem = msg.server_cert

    # Validate server certificate
    ca_cert = pki.load_cert_from_file(CA_CERT_PATH)
    pki.validate_peer_cert(
        peer_pem_str=server_cert_pem,
        ca_cert=ca_cert,
        expected_cn=EXPECTED_SERVER_CN,
    )
    print("[PKI] Server certificate validated OK.")

    return msg


# ---------------------------------------------------------------------------
# Phase 2: DH handshake -> AES key (client side)
# ---------------------------------------------------------------------------


def dh_handshake_client(sock: socket.socket) -> bytes:
    """
    Classical DH from client perspective.

    Client -> Server:
        {"type":"dh client", "g": int, "p": int, "A": int}

    Server -> Client:
        {"type":"dh server", "B": int}

    Returns:
        16-byte AES key derived from shared secret.
    """
    # Generate parameters + client keypair
    client_kp = generate_dh_keypair()

    # Send dh_client
    dh_client = DhClient(
        g=client_kp.g,
        p=client_kp.p,
        A=client_kp.y,
    )
    send_json(sock, dh_client)
    print("[DH] Sent dh_client with (p,g,A).")

    # Receive dh_server
    raw = recv_json(sock)
    msg = parse_message(raw)
    if not isinstance(msg, DhServer):
        raise ValueError(f"Expected 'dh server', got: {raw.get('type')}")

    # Compute shared secret and derive AES-128 key
    shared_secret, aes_key = derive_aes_key(client_kp, peer_y=msg.B, key_len=16)
    print("[DH] Shared secret established, AES-128 key derived.")
    return aes_key


# ---------------------------------------------------------------------------
# Phase 3: encrypted register/login using K_cred
# ---------------------------------------------------------------------------


def encrypt_inner_json(aes_key: bytes, inner: Dict[str, Any]) -> str:
    """
    AES-128-ECB encrypt JSON(inner) and return base64 ciphertext string.
    """
    pt = json.dumps(inner, separators=(",", ":")).encode("utf-8")
    ct = aes_encrypt_ecb(aes_key, pt)
    return b64e(ct)


def do_register(sock: socket.socket, k_cred: bytes, email: str, username: str, password: str) -> None:
    """
    Send encrypted register message and print server result.
    """
    inner = {
        "email": email,
        "username": username,
        "password": password,
    }
    ct_b64 = encrypt_inner_json(k_cred, inner)

    outer = {
        "type": "register",
        "ct": ct_b64,
    }
    send_json(sock, outer)
    print("[AUTH] Sent encrypted register payload.")

    resp = recv_json(sock)
    if resp.get("type") != "register_result":
        print(f"[AUTH] Unexpected response to register: {resp}")
        return

    if resp.get("ok"):
        print("[AUTH] Registration succeeded.")
    else:
        print(f"[AUTH] Registration failed: {resp.get('error')}")


def do_login(sock: socket.socket, k_cred: bytes, email: str, password: str) -> bool:
    """
    Send encrypted login message and print server result.

    Returns True if login OK, False otherwise.
    """
    inner = {
        "email": email,
        "password": password,
    }
    ct_b64 = encrypt_inner_json(k_cred, inner)

    outer = {
        "type": "login",
        "ct": ct_b64,
    }
    send_json(sock, outer)
    print("[AUTH] Sent encrypted login payload.")

    resp = recv_json(sock)
    if resp.get("type") != "login_result":
        print(f"[AUTH] Unexpected response to login: {resp}")
        return False

    if resp.get("ok"):
        print("[AUTH] Login succeeded.")
        return True

    print(f"[AUTH] Login failed: {resp.get('error')}")
    return False


# ---------------------------------------------------------------------------
# Main client workflow
# ---------------------------------------------------------------------------


def run_client(
    mode: str,
    email: str | None,
    username: str | None,
    host: str,
    port: int,
) -> None:
    """
    mode: "register" or "login"
    """
    # Prompt for missing pieces
    if email is None:
        email = input("Email: ").strip()
    if mode == "register" and username is None:
        username = input("Username: ").strip()

    password = getpass("Password: ")

    addr = (host, port)
    print(f"[*] Connecting to {addr[0]}:{addr[1]} ...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(addr)
        print("[*] Connected.")

        # Phase 1: certs + PKI
        do_cert_handshake(sock)

        # Phase 2: DH #1 -> K_cred
        print("[PHASE] DH #1 (credentials)...")
        k_cred = dh_handshake_client(sock)

        # Phase 3: encrypted register/login
        if mode == "register":
            assert username is not None
            do_register(sock, k_cred, email, username, password)
            print("[DONE] Registration flow finished.")
            return

        if mode == "login":
            ok = do_login(sock, k_cred, email, password)
            if not ok:
                print("[DONE] Login failed; closing.")
                return

            # If login succeeded, perform DH #2 for chat session key
            print("[PHASE] DH #2 (chat session)...")
            k_session = dh_handshake_client(sock)
            print("[INFO] Session AES key established (not used further in this skeleton).")
            # Here you would enter a chat loop using k_session.
            print("[DONE] Login + session key handshake complete.")
            return

        print(f"[ERR] Unknown mode: {mode!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureChat Client (practice skeleton)")
    parser.add_argument("--host", default=SERVER_HOST, help="Server host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="Server port (default 5000)")
    parser.add_argument(
        "--mode",
        choices=["register", "login"],
        required=True,
        help="Client mode: register a new user or login.",
    )
    parser.add_argument("--email", help="User email (if omitted, prompt)")
    parser.add_argument("--username", help="Username (register mode only)")

    args = parser.parse_args()

    run_client(
        mode=args.mode,
        email=args.email,
        username=args.username,
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    main()
