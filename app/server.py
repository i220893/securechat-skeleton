"""
SecureChat server (practice skeleton, spec-aligned up to login).

Phases implemented:

1) Plain TCP listen/accept
2) Control plane:
   - Client sends:  {"type":"hello", "client cert":"...PEM...", "nonce": base64}
   - Server replies:{"type":"server hello", "server cert":"...PEM...", "nonce": base64}
   - Server validates client cert (CA, validity, CN)
3) DH #1: temporary K_cred for protecting credentials
   - Client -> Server: {"type":"dh client", "g":int, "p":int, "A":int}
   - Server -> Client: {"type":"dh server", "B":int}
   - Both derive AES-128 key K_cred = Trunc16(SHA256(shared_secret))
4) Encrypted register OR login (credentials protected by K_cred)
   - For simplicity, wire format:
       {"type":"register", "ct": base64(AES-128(JSON{email,username,password}))}
       {"type":"login",    "ct": base64(AES-128(JSON{email,password}))}
   - Server decrypts, calls db.create_user / db.verify_user
5) DH #2: session key K_session (not used further in this skeleton)
"""

from __future__ import annotations

import argparse
import json
import os
import socket
from pathlib import Path
from typing import Any, Dict, Tuple

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
from app.crypto.dh import (
    generate_dh_keypair_from_params,
    derive_aes_key,
)
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.storage import db

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))

CA_CERT_PATH = Path(os.getenv("CA_CERT_PATH", "certs/ca/ca_cert.pem"))
SERVER_CERT_PATH = Path(os.getenv("SERVER_CERT_PATH", "certs/server/cert.pem"))
EXPECTED_CLIENT_CN = os.getenv("CLIENT_CN", "client.local")


# ---------------------------------------------------------------------------
# Line-based JSON helpers
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
            raise ConnectionError("peer closed connection")
        if ch == b"\n":
            break
        chunks.append(ch)
    raw = b"".join(chunks)
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# Phase 1: hello / server hello + PKI validation
# ---------------------------------------------------------------------------


def do_cert_handshake(sock: socket.socket) -> Hello:
    """
    Server side of hello / server hello:

    Client -> Server:
      {"type":"hello", "client cert":"...PEM...", "nonce": base64}

    Server -> Client:
      {"type":"server hello", "server cert":"...PEM...", "nonce": base64}

    Returns the parsed Hello model so caller can inspect if needed.
    """
    # 1) Receive hello
    raw = recv_json(sock)
    msg = parse_message(raw)
    if not isinstance(msg, Hello):
        raise ValueError(f"Expected 'hello', got: {raw.get('type')}")

    client_cert_pem = msg.client_cert

    # 2) Validate client certificate against our CA
    ca_cert = pki.load_cert_from_file(CA_CERT_PATH)
    pki.validate_peer_cert(
        peer_pem_str=client_cert_pem,
        ca_cert=ca_cert,
        expected_cn=EXPECTED_CLIENT_CN,
    )
    print("[PKI] Client certificate validated OK.")

    # 3) Send server_hello
    server_cert_pem = SERVER_CERT_PATH.read_text(encoding="utf-8")
    server_nonce = os.urandom(16)

    server_hello = ServerHello(
        server_cert=server_cert_pem,
        nonce=b64e(server_nonce),
    )
    send_json(sock, server_hello)

    return msg


# ---------------------------------------------------------------------------
# Phase 2: DH handshake -> AES key
# ---------------------------------------------------------------------------


def dh_handshake_server(sock: socket.socket) -> bytes:
    """
    Classical DH from server perspective.

    Client -> Server:
        {"type":"dh client", "g": int, "p": int, "A": int}

    Server -> Client:
        {"type":"dh server", "B": int}

    Returns:
        16-byte AES key derived from shared secret.
    """
    raw = recv_json(sock)
    msg = parse_message(raw)
    if not isinstance(msg, DhClient):
        raise ValueError(f"Expected 'dh client', got: {raw.get('type')}")

    # Build server keypair using client's (p, g)
    server_kp = generate_dh_keypair_from_params(msg.p, msg.g)

    # Compute shared secret and derive AES-128 key
    shared_secret, aes_key = derive_aes_key(server_kp, peer_y=msg.A, key_len=16)
    print("[DH] Shared secret established, AES-128 key derived.")

    # Reply with our public B
    dh_server = DhServer(B=server_kp.y)
    send_json(sock, dh_server)

    return aes_key


# ---------------------------------------------------------------------------
# Phase 3: encrypted register/login over K_cred
# ---------------------------------------------------------------------------


def decrypt_inner_json(aes_key: bytes, ct_b64: str) -> Dict[str, Any]:
    """
    AES-128-ECB decrypt base64 ciphertext to a JSON dict.
    """
    ct = b64d(ct_b64)
    pt = aes_decrypt_ecb(aes_key, ct)  # bytes
    return json.loads(pt.decode("utf-8"))


def handle_register_message(
    sock: socket.socket,
    aes_key: bytes,
    wrapper: Dict[str, Any],
) -> None:
    """
    Handle encrypted register message.

    Wire format (outer):
        {"type":"register", "ct": base64(AES(JSON{email,username,password}))}
    """
    if "ct" not in wrapper:
        raise ValueError("register message missing 'ct'")

    inner = decrypt_inner_json(aes_key, wrapper["ct"])
    email = inner["email"]
    username = inner["username"]
    password = inner["password"]

    ok = db.create_user(email=email, username=username, password=password)
    if not ok:
        send_json(sock, {"type": "register_result", "ok": False, "error": "USER_EXISTS"})
        print(f"[AUTH] Registration failed (user exists): {email}")
        return

    send_json(sock, {"type": "register_result", "ok": True})
    print(f"[AUTH] Registered new user: {email} ({username})")


def handle_login_message(
    sock: socket.socket,
    aes_key: bytes,
    wrapper: Dict[str, Any],
) -> bool:
    """
    Handle encrypted login message.

    Wire format (outer):
        {"type":"login", "ct": base64(AES(JSON{email,password}))}

    Returns:
        True if login successful, False otherwise.
    """
    if "ct" not in wrapper:
        raise ValueError("login message missing 'ct'")

    inner = decrypt_inner_json(aes_key, wrapper["ct"])
    email = inner["email"]
    password = inner["password"]

    ok = db.verify_user(email=email, password=password)
    if not ok:
        send_json(sock, {"type": "login_result", "ok": False, "error": "BAD_CREDENTIALS"})
        print(f"[AUTH] Login failed for {email}")
        return False

    send_json(sock, {"type": "login_result", "ok": True})
    print(f"[AUTH] Login OK for {email}")
    return True


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------


def handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    """
    Handle a single client connection up to the point where:

      - Certificates have been exchanged and validated.
      - Credentials have been protected with DH #1 + AES-128.
      - Optional: user has either registered or logged in.
      - A second DH for chat session key has completed.

    Then we close the connection (no data-plane chat in this skeleton).
    """
    print(f"[*] New connection from {addr}")

    try:
        # Phase 1: cert exchange + validation
        do_cert_handshake(conn)

        # Phase 2: DH #1 -> K_cred (for credentials)
        k_cred = dh_handshake_server(conn)

        # Phase 3: encrypted register OR login over K_cred
        first = recv_json(conn)
        msg_type = first.get("type")

        if msg_type == "register":
            handle_register_message(conn, k_cred, first)
            # For this skeleton, we close after registration.
            return

        if msg_type == "login":
            ok = handle_login_message(conn, k_cred, first)
            if not ok:
                return  # close connection on failed login

            # If login succeeded, we now perform a second DH for chat session.
            print("[DH] Starting DH #2 for chat session key...")
            k_session = dh_handshake_server(conn)
            print("[DH] Session AES key established. (Skeleton ends here.)")
            # In a full implementation, you'd now enter a chat loop using k_session.
            return

        # Unexpected type
        send_json(conn, {"type": "error", "error": "EXPECTED_REGISTER_OR_LOGIN"})
        print(f"[WARN] Unexpected first credential message: {msg_type!r}")

    except Exception as exc:
        print(f"[ERR] Exception in handle_client: {exc}")
    finally:
        conn.close()
        print(f"[*] Connection {addr} closed.")


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureChat Server (practice skeleton)")
    parser.add_argument("--host", default=SERVER_HOST, help="Bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="Bind port (default 5000)")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port))
        s.listen(5)
        print(f"[*] Server listening on {args.host}:{args.port}")

        while True:
            conn, addr = s.accept()
            # For simplicity: one client at a time, no threads.
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
