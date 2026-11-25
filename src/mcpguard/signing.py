"""Ed25519 signatures for audit records and checkpoints (optional: needs `pip install mcpguard[signing]`).

Why: the hash chain in `audit.py` detects edits, deletions and reordering, but someone who can write
the log file can also rebuild the whole chain from the first line. A signature made with a key the
attacker does not hold cannot be rebuilt. Two mechanisms are offered:

- per-record signatures (`sig`, `kid` fields), made by the gateway as it writes;
- signed checkpoints (`count` + head hash), exported to storage the gateway host cannot change.

The key on the gateway host protects against tampering by anyone who can edit the log but not read
the key. A checkpoint stored elsewhere protects everything up to that checkpoint even if the host and
its key are later compromised. Neither prevents a compromised host from writing false records from
then on. See docs/adr/0002-signed-audit-records-and-checkpoints.md.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # optional dependency
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised only without the extra installed
    HAVE_CRYPTO = False


class SigningUnavailable(RuntimeError):
    pass


def _require() -> None:
    if not HAVE_CRYPTO:
        raise SigningUnavailable("audit signing needs the 'cryptography' package: pip install 'mcpguard[signing]'")


def _raw_public(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(pub: Ed25519PublicKey) -> str:
    """Short, stable identifier of a public key (first 16 hex chars of SHA-256 of the raw key)."""
    return hashlib.sha256(_raw_public(pub)).hexdigest()[:16]


def generate_keypair(out_dir: str | Path) -> tuple[Path, Path]:
    """Write `audit-signing.key` (PKCS#8 PEM, mode 0600) and `audit-signing.pub` (SPKI PEM)."""
    _require()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    key_path, pub_path = out / "audit-signing.key", out / "audit-signing.pub"
    if key_path.exists():
        raise FileExistsError(f"{key_path} already exists; refusing to overwrite a signing key")
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    key_path.touch(mode=0o600)
    key_path.write_bytes(pem)
    pub_path.write_bytes(
        priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return key_path, pub_path


@dataclass
class Signer:
    private_key: Any

    @classmethod
    def from_file(cls, path: str | Path) -> Signer:
        _require()
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("audit signing key must be an Ed25519 private key")
        return cls(key)

    @classmethod
    def generate(cls) -> Signer:
        _require()
        return cls(Ed25519PrivateKey.generate())

    @property
    def kid(self) -> str:
        return key_id(self.private_key.public_key())

    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, message: str) -> str:
        return base64.b64encode(self.private_key.sign(message.encode())).decode()


@dataclass
class Verifier:
    public_key: Any

    @classmethod
    def from_file(cls, path: str | Path) -> Verifier:
        _require()
        key = serialization.load_pem_public_key(Path(path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("audit verification key must be an Ed25519 public key")
        return cls(key)

    @classmethod
    def from_pem(cls, pem: bytes) -> Verifier:
        _require()
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("audit verification key must be an Ed25519 public key")
        return cls(key)

    @property
    def kid(self) -> str:
        return key_id(self.public_key)

    def verify(self, message: str, signature_b64: str) -> bool:
        try:
            self.public_key.verify(base64.b64decode(signature_b64, validate=True), message.encode())
            return True
        except (InvalidSignature, ValueError):
            return False


# --- checkpoints ----------------------------------------------------------------------------


def _checkpoint_message(cp: dict[str, Any]) -> str:
    body = {k: cp[k] for k in ("log", "count", "head", "ts", "kid")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def make_checkpoint(signer: Signer, log_name: str, count: int, head: str, ts: str) -> dict[str, Any]:
    cp = {"log": log_name, "count": count, "head": head, "ts": ts, "kid": signer.kid}
    cp["sig"] = signer.sign(_checkpoint_message(cp))
    return cp


def checkpoint_signature_ok(verifier: Verifier, cp: dict[str, Any]) -> bool:
    try:
        return cp.get("kid") == verifier.kid and verifier.verify(_checkpoint_message(cp), cp["sig"])
    except KeyError:
        return False
