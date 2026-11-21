"""Content detectors: secrets, personal data, prompt-injection phrases and hidden characters.

All detectors are deterministic, dependency-free and cheap enough to run on every message.
They are deliberately conservative: a gateway should block obvious abuse, not pretend to be
a complete DLP product.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    kind: str  # "secret" | "pii" | "injection" | "hidden-text"
    rule: str
    excerpt: str


# --- secrets -------------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws-access-key-id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "openai-style-key": re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}\b"),
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "connection-string-password": re.compile(r"(?i)\b(?:password|pwd)\s*=\s*[^;\s]{4,}"),
}

# --- personal data -------------------------------------------------------------------------

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _cards(text: str) -> list[str]:
    hits = []
    for m in CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            hits.append(m.group())
    return hits


# --- prompt injection ----------------------------------------------------------------------

INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "override-instructions": re.compile(
        r"(?i)\b(?:ignore|disregard|forget)\b.{0,30}\b(?:previous|prior|above|all|earlier)\b.{0,20}"
        r"\b(?:instructions?|rules?|prompts?|guidelines?)\b"
    ),
    "role-hijack": re.compile(r"(?i)\byou are now\b|\bnew system prompt\b|\bact as (?:the )?system\b"),
    "concealment": re.compile(
        r"(?i)\b(?:do not|don't|never)\b.{0,20}\b(?:tell|inform|mention|reveal|show)\b.{0,20}\b(?:the )?user\b"
    ),
    "hidden-directive-tag": re.compile(r"(?i)<\s*(?:important|system|instructions?|secret)\s*>"),
    "sensitive-path-reference": re.compile(
        r"(?i)(?:~|\$HOME|/home/[^/\s]+|/root)/\.(?:ssh|aws|kube|gnupg|config/gcloud)\b|\bid_rsa\b|\.env\b"
    ),
    "exfiltration-instruction": re.compile(
        r"(?i)\b(?:send|post|upload|forward|exfiltrate)\b.{0,40}\b(?:to|via)\b.{0,15}(?:https?://|webhook|email)"
    ),
    "tool-shadowing": re.compile(
        r"(?i)\b(?:instead of|before (?:using|calling)|whenever you (?:use|call))\b.{0,40}\btool\b"
    ),
}

# Zero-width, bidi-control and tag characters are invisible to a human reviewer but visible to a model.
_HIDDEN_RANGES = [
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x2069),
    (0xFEFF, 0xFEFF),
    (0xE0000, 0xE007F),
]


def _is_hidden(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _HIDDEN_RANGES)


def _excerpt(s: str, limit: int = 40) -> str:
    s = s.replace("\n", " ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def find_secrets(text: str) -> list[Finding]:
    return [
        Finding("secret", name, _excerpt(m.group()[:8] + "***"))
        for name, rx in SECRET_PATTERNS.items()
        for m in rx.finditer(text)
    ]


def find_pii(text: str) -> list[Finding]:
    out = [Finding("pii", "email", _excerpt(m.group())) for m in EMAIL.finditer(text)]
    out += [Finding("pii", "payment-card", "****" + re.sub(r"\D", "", c)[-4:]) for c in _cards(text)]
    out += [Finding("pii", "iban", m.group()[:4] + "****") for m in IBAN.finditer(text)]
    return out


def find_injection(text: str) -> list[Finding]:
    normalised = unicodedata.normalize("NFKC", "".join(ch for ch in text if not _is_hidden(ch)))
    return [
        Finding("injection", name, _excerpt(m.group()))
        for name, rx in INJECTION_PATTERNS.items()
        for m in rx.finditer(normalised)
    ]


def find_hidden_text(text: str) -> list[Finding]:
    hidden = [ch for ch in text if _is_hidden(ch)]
    if not hidden:
        return []
    codes = sorted({f"U+{ord(c):04X}" for c in hidden})
    return [Finding("hidden-text", "invisible-characters", f"{len(hidden)} chars: {', '.join(codes[:5])}")]


def redact(text: str, *, secrets: bool = True, pii: bool = True) -> tuple[str, int]:
    """Replace secrets and personal data with typed placeholders. Returns (text, count)."""
    count = 0

    def sub(rx: re.Pattern[str], label: str, s: str) -> str:
        nonlocal count
        s2, n = rx.subn(f"[REDACTED:{label}]", s)
        count += n
        return s2

    if secrets:
        for name, rx in SECRET_PATTERNS.items():
            text = sub(rx, name, text)
    if pii:
        text = sub(EMAIL, "email", text)
        for card in _cards(text):
            text = text.replace(card, "[REDACTED:payment-card]")
            count += 1
        text = sub(IBAN, "iban", text)
    return text, count


def iter_strings(value: object) -> list[str]:
    """Flatten every string inside a JSON-like value (keys included)."""
    out: list[str] = []
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for k, item in v.items():
                out.append(str(k))
                stack.append(item)
        elif isinstance(v, list):
            stack.extend(v)
    return out
