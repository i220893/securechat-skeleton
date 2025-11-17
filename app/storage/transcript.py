"""
Append-only transcript storage and transcript-hash helpers.

- Each chat session gets a transcript file under `transcripts/`.
- Every message is appended as a single JSON line (direction + message fields).
- At the end of a session, we compute a SHA-256 hash over the entire file
  and use that as the `transcript sha256` in the SessionReceipt.

This module does *not* talk to the network or the database. It is purely
for local, append-only logging and hashing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

from app.common.utils import sha256_hex


TRANSCRIPTS_DIR = Path("transcripts")


@dataclass
class Transcript:
    """
    Represents a single append-only transcript file for one chat session.

    Typical usage:

        t = Transcript.new(role="client")
        t.append("out", msg_dict)   # message we sent
        t.append("in",  msg_dict)   # message we received
        digest = t.compute_hash()   # hex string for SessionReceipt
    """

    path: Path

    # ------------------------------
    # Construction helpers
    # ------------------------------

    @classmethod
    def new(cls, role: Literal["client", "server"], session_id: Optional[str] = None) -> "Transcript":
        """
        Create a new transcript under `transcripts/`.

        :param role: "client" or "server" (for naming)
        :param session_id: optional custom identifier; if None, timestamp-based.
        :return: Transcript instance
        """
        TRANSCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

        if session_id is None:
            # Simple timestamp-based session id
            ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            session_id = ts

        filename = f"{role}-{session_id}.log"
        path = TRANSCRIPTS_DIR / filename

        # Ensure file exists (append-only)
        path.touch(exist_ok=True)

        return cls(path=path)

    # ------------------------------
    # Append-only logging
    # ------------------------------

    def append(self, direction: Literal["in", "out"], msg: dict) -> None:
        """
        Append a single JSON line to the transcript.

        :param direction: "in" (received) or "out" (sent)
        :param msg: a dict representation of the protocol message
                    (e.g. result of `Msg.dict(by_alias=True)`).
        """
        # We enrich the record with direction + timestamp.
        record = {
            "direction": direction,
            "logged_at": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "msg": msg,
        }

        line = json.dumps(record, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    # ------------------------------
    # Transcript hash
    # ------------------------------

    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash (hex) of the entire transcript file.

        This value goes into the `transcript sha256` field of the SessionReceipt.
        """
        with self.path.open("rb") as f:
            data = f.read()
        return sha256_hex(data)

    @staticmethod
    def compute_hash_for_path(path: Path) -> str:
        """
        Convenience helper: compute hash of an arbitrary transcript file path.
        """
        with path.open("rb") as f:
            data = f.read()
        return sha256_hex(data)
