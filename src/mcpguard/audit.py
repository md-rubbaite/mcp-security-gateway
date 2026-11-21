"""Tamper-evident audit log: JSON Lines where every record carries the hash of the previous one.

Deleting, editing or reordering any line breaks the chain, and `verify` reports the first bad line.
Arguments are never logged in clear: only their SHA-256, so the log itself cannot leak secrets.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def hash_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None, clock: Callable[[], datetime] | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._prev = GENESIS
        if self.path and self.path.exists():
            lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                self._prev = json.loads(lines[-1])["hash"]

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            rec = {"ts": self._clock().isoformat(), "event": event, **fields, "prev": self._prev}
            rec["hash"] = _digest(rec)
            self._prev = rec["hash"]
            self.records.append(rec)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, sort_keys=True) + "\n")
            return rec


def verify(path: str | Path) -> tuple[bool, int, str]:
    """Return (ok, records_checked, message)."""
    prev = GENESIS
    n = 0
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return False, n, f"line {n}: not valid JSON"
        if rec.get("prev") != prev:
            return False, n, f"line {n}: chain broken (prev hash does not match line {n - 1})"
        if rec.get("hash") != _digest(rec):
            return False, n, f"line {n}: record was modified"
        prev = rec["hash"]
    return True, n, f"{n} records verified"
