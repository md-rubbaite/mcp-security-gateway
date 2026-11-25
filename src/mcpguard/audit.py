"""Tamper-evident audit log: JSON Lines where every record carries the hash of the previous one.

Deleting, editing or reordering any line breaks the chain, and `verify` reports the first bad line.
Arguments are never logged in clear: only their SHA-256, so the log itself cannot leak secrets.

Optionally (v1.1) every record is also signed with Ed25519 (`sig`, `kid`), and signed checkpoints
can be exported to other storage. See `signing.py` for what each mechanism does and does not protect.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .signing import Signer, Verifier

GENESIS = "0" * 64
_NOT_HASHED = ("hash", "sig")


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in _NOT_HASHED}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def hash_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(
        self,
        path: str | Path | None,
        clock: Callable[[], datetime] | None = None,
        signer: Signer | None = None,
    ):
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._count = 0
        self.signer = signer
        if self.path and self.path.exists():
            lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                self._prev = json.loads(lines[-1])["hash"]
                self._count = len(lines)

    @property
    def head(self) -> str:
        return self._prev

    @property
    def count(self) -> int:
        return self._count

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            rec = {"ts": self._clock().isoformat(), "event": event, **fields, "prev": self._prev}
            if self.signer is not None:
                rec["kid"] = self.signer.kid  # hashed, so the key id cannot be swapped silently
            rec["hash"] = _digest(rec)
            if self.signer is not None:
                rec["sig"] = self.signer.sign(rec["hash"])
            self._prev = rec["hash"]
            self._count += 1
            self.records.append(rec)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, sort_keys=True) + "\n")
            return rec


@dataclass
class VerifyResult:
    ok: bool
    records: int
    message: str
    head: str = GENESIS
    signed: int = 0


def verify_records(
    lines: list[str],
    verifier: Verifier | None = None,
    require_signatures: bool = False,
) -> VerifyResult:
    prev = GENESIS
    n = signed = 0
    for n, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return VerifyResult(False, n, f"line {n}: not valid JSON", prev, signed)
        if rec.get("prev") != prev:
            return VerifyResult(
                False, n, f"line {n}: chain broken (prev hash does not match line {n - 1})", prev, signed
            )
        if rec.get("hash") != _digest(rec):
            return VerifyResult(False, n, f"line {n}: record was modified", prev, signed)
        if verifier is not None:
            if "sig" in rec:
                if rec.get("kid") != verifier.kid:
                    return VerifyResult(
                        False, n, f"line {n}: signed with a different key ({rec.get('kid')})", prev, signed
                    )
                if not verifier.verify(rec["hash"], rec["sig"]):
                    return VerifyResult(False, n, f"line {n}: signature is not valid", prev, signed)
                signed += 1
            elif require_signatures:
                return VerifyResult(False, n, f"line {n}: record is not signed", prev, signed)
        prev = rec["hash"]
    msg = f"{n} records verified"
    if verifier is not None:
        msg += f", {signed} signatures valid"
    return VerifyResult(True, n, msg, prev, signed)


def verify(path: str | Path) -> tuple[bool, int, str]:
    """Hash-chain check only. Return (ok, records_checked, message). Kept for v1.0 compatibility."""
    r = verify_records(Path(path).read_text(encoding="utf-8").splitlines())
    return r.ok, r.records, r.message


def verify_with_checkpoint(lines: list[str], checkpoint: dict[str, Any]) -> tuple[bool, str]:
    """The log must still contain the checkpointed prefix unchanged: same record count reached, same head."""
    want = int(checkpoint["count"])
    body = [ln for ln in lines if ln.strip()]
    if len(body) < want:
        return False, f"log has {len(body)} records but the checkpoint covers {want} (records were removed)"
    prefix = verify_records(body[:want])
    if not prefix.ok:
        return False, "checkpointed part of the log fails verification: " + prefix.message
    if prefix.head != checkpoint["head"]:
        return False, f"record {want} hash differs from the checkpoint (the log was rewritten)"
    return True, f"first {want} records match the checkpoint"
