"""
SecureChat client (practice skeleton, spec-aligned with chat send).

Phases:

1) Connect to server over plain TCP.
2) Control plane:
   - Send:   {"type":"hello", "client cert":"...PEM...", "nonce": base64}
   - Receive{"type":"server hello", "server cert":"...PEM...", "nonce": base64}
   - Validate server cert (CA, validity, CN="server.local")
3) DH #1: temporary K_cred for protecting credentials.
4) Encrypted register OR login over K_cred.
5) DH #2: session key K_session for chat.
6) Chat: client SENDS encrypted+signed messages to server.
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
    Msg,
    parse_message,
)
from app.common.utils import b64e, b64d, now_ms
from app.crypto import pki
from app.crypto.dh import generate_dh_keypair, derive_aes_key
from app.crypto.aes import aes_encrypt_ecb
from app.crypto.sign import load_private_key_from_file, rsa_sign
from app.storage.transcript import Transcript

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))

CA_CERT_PATH = Path(os.getenv("CA_CERT_PATH", "certs/ca/ca_cert.pem"))

CLIENT_CERT_PATH = Path(os.getenv("CLIENT_CERT_PATH", "certs/client/cert.pem"))
CLIENT_KEY_PATH = Path(os.getenv("CLIENT_KEY_PATH", "certs/client/key.pem"))
EXPECTED_SERVER_CN = os.getenv("SERVER_CN", "server.local")


# ---------------------------------------------------------------------------
# Line-based JSON helpers (same framing as server)
# ---------------------------------------------------------------------------


def send_json(sock: socket.socket, obj: Any) -> None:
    """
    Send a JSON object followed by a newline.

    If `obj` is a Pydantic model, we serialize with aliases so that JSON keys
    match the protocol spec exactly where aliases are defined.
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
# Helper: build canonical bytes to sign for Msg
# ---------------------------------------------------------------------------


def build_msg_bytes(seqno: int, ts: int, ct_b64: str) -> bytes:
    """
    Build canonical byte string for signing a Msg:

        data = seqno(8B big-endian) || ts(8B big-endian) || ciphertext_bytes
    """
    ct = b64d(ct_b64)
    seq_bytes = seqno.to_bytes(8, "big", signed=False)
    ts_bytes = ts.to_bytes(8, "big", signed=False)
    return seq_bytes + ts_bytes + ct


# ---------------------------------------------------------------------------
# Phase 1: hello / server hello + PKI validation
# ---------------------------------------------------------------------------


def do_cert_handshake(sock: socket.socket) -> ServerHello:
    """
    Client side of hello / server hello.

    Returns the parsed ServerHello model.
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
    _, aes_key = derive_aes_key(client_kp, peer_y=msg.B, key_len=16)
    print("[DH] Shared secret established, AES-128 key derived (client).")
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
# Phase 4: chat loop (client-side send only)
# ---------------------------------------------------------------------------


def chat_loop_client(
    sock: socket.socket,
    session_key: bytes,
    client_priv_key,
) -> None:
    """
    Client chat loop:

    - Reads lines from stdin
    - Encrypts them with AES-128 + PKCS#7 using session_key
    - Builds Msg with seqno, ts, ct, sig
    - Signs canonical bytes with RSA+SHA256
    - Sends to server and logs to transcript

    Command:
      /quit   -> send a simple {"type":"bye"} and exit.
    """
    transcript = Transcript.new(role="client")
    seqno = 1

    print("[CHAT] You can now type messages. Use /quit to end.")

    while True:
        try:
            text = input("you> ").strip()
        except EOFError:
            text = "/quit"

        if not text:
            continue

        if text.lower() in ("/quit", "/exit"):
            send_json(sock, {"type": "bye"})
            print("[CHAT] Session ended by client.")
            break

        ts = now_ms()
        pt = text.encode("utf-8")
        ct = aes_encrypt_ecb(session_key, pt)
        ct_b64 = b64e(ct)

        data_bytes = build_msg_bytes(seqno, ts, ct_b64)
        sig_bytes = rsa_sign(client_priv_key, data_bytes)
        sig_b64 = b64e(sig_bytes)

        msg = Msg(
            seqno=seqno,
            ts=ts,
            ct=ct_b64,
            sig=sig_b64,
        )

        send_json(sock, msg)
        transcript.append("out", msg.dict(by_alias=True))
        seqno += 1


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

    # Load client private key for signing chat messages
    client_priv_key = load_private_key_from_file(CLIENT_KEY_PATH)

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
            print("[INFO] Session AES key established. Entering chat...")
            chat_loop_client(sock, k_session, client_priv_key)
            print("[DONE] Login + chat session complete.")
            return

        print(f"[ERR] Unknown mode: {mode!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureChat Client (practice, with chat send)")
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
