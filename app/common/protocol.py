"""Pydantic models for all SecureChat protocol messages.

Messages (JSON-on-the-wire formats, from assignment spec):

Control Plane:
    { "type":"hello", "client cert":"...PEM...", "nonce": base64 }
    { "type":"server hello", "server cert":"...PEM...", "nonce": base64 }
    { "type":"register", "email":"", "username":"", "pwd": base64, "salt": base64 }
    { "type":"login", "email":"", "pwd": base64, "nonce": base64 }

Key Agreement:
    { "type":"dh client", "g": int, "p": int, "A": int }
    { "type":"dh server", "B": int }

Data Plane:
    { "type":"msg", "seqno": n, "ts": unix_ms, "ct": base64, "sig": base64 }

Non-Repudiation:
    { "type":"receipt", "peer":"client|server",
      "first seq": ..., "last seq": ..., "transcript sha256": hex, "sig": base64 }
"""

from __future__ import annotations

from typing import Literal, Union

from pydantic import BaseModel, Field


class MessageBase(BaseModel):
    """Common config for all protocol messages."""

    class Config:
        # v1/v2 friendly: allow using both field names and aliases
        populate_by_name = True
        allow_population_by_field_name = True  # kept for pydantic<2 compatibility
        extra = "forbid"  # reject unknown fields (helps catch bugs)


# -----------------------
# Control-plane messages
# -----------------------


class Hello(MessageBase):
    type: Literal["hello"] = "hello"
    client_cert: str = Field(alias="client cert")
    nonce: str


class ServerHello(MessageBase):
    type: Literal["server hello"] = "server hello"
    server_cert: str = Field(alias="server cert")
    nonce: str


class Register(MessageBase):
    type: Literal["register"] = "register"
    email: str
    username: str
    # base64(sha256(salt||pwd)) according to the spec
    pwd: str
    salt: str  # base64-encoded salt


class Login(MessageBase):
    type: Literal["login"] = "login"
    email: str
    # base64(sha256(salt||pwd)) according to the spec
    pwd: str
    nonce: str  # base64-encoded nonce


# -----------------------
# Key-agreement messages
# -----------------------


class DhClient(MessageBase):
    type: Literal["dh client"] = "dh client"
    g: int
    p: int
    A: int  # g^a mod p


class DhServer(MessageBase):
    type: Literal["dh server"] = "dh server"
    B: int  # g^b mod p


# -----------------------
# Data-plane message
# -----------------------


class Msg(MessageBase):
    type: Literal["msg"] = "msg"
    seqno: int
    ts: int  # unix ms
    ct: str  # base64 ciphertext
    sig: str  # base64 RSA signature over SHA256(seqno||ts||ct)


# -----------------------
# Session receipt
# -----------------------


class Receipt(MessageBase):
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    first_seq: int = Field(alias="first seq")
    last_seq: int = Field(alias="last seq")
    transcript_sha256: str = Field(alias="transcript sha256")
    sig: str  # base64 RSA signature over transcript_sha256


# -----------------------
# Helper union & parser
# -----------------------

AnyMessage = Union[
    Hello,
    ServerHello,
    Register,
    Login,
    DhClient,
    DhServer,
    Msg,
    Receipt,
]


_TYPE_MAP = {
    "hello": Hello,
    "server hello": ServerHello,
    "register": Register,
    "login": Login,
    "dh client": DhClient,
    "dh server": DhServer,
    "msg": Msg,
    "receipt": Receipt,
}


def parse_message(data: dict) -> AnyMessage:
    """
    Given a decoded JSON dict, return the appropriate Pydantic model instance.

    Example:
        data = json.loads(raw_json)
        msg = parse_message(data)
        if isinstance(msg, Msg):
            ...
    """
    msg_type = data.get("type")
    model_cls = _TYPE_MAP.get(msg_type)
    if model_cls is None:
        raise ValueError(f"Unknown message type: {msg_type!r}")
    # We parse using the raw dict, including keys with spaces (aliases).
    return model_cls.parse_obj(data)
