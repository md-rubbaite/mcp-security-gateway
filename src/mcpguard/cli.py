"""Command line: proxy | lock | scan-tools | verify-audit | keygen | checkpoint | attack-sim."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import AuditLog, verify_records, verify_with_checkpoint
from .gateway import Gateway
from .pinning import load_lock, review_tools, write_lock
from .policy import PolicyError, load_policy
from .proxy import run_stdio_proxy
from .signing import SigningUnavailable


def _load_tools(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("result", data).get("tools", [])
    return data


def cmd_scan(a: argparse.Namespace) -> int:
    reviews = review_tools(_load_tools(a.tools), load_lock(a.lock))
    worst = 0
    for r in reviews:
        flags = ", ".join(sorted({f.rule for f in r.findings})) or "-"
        print(f"{r.name:<28} {r.status:<8} {flags}")
        if r.poisoned:
            worst = 1
        elif r.status != "pinned" and a.lock:
            worst = max(worst, 1)
    print(f"\n{len(reviews)} tools, {sum(r.poisoned for r in reviews)} suspicious")
    return worst


def cmd_lock(a: argparse.Namespace) -> int:
    tools = _load_tools(a.tools)
    poisoned = [r.name for r in review_tools(tools, {}) if r.poisoned]
    if poisoned and not a.force:
        print(f"refusing to pin suspicious tools: {poisoned} (review them, or pass --force)", file=sys.stderr)
        return 1
    pins = write_lock(a.out, tools, a.server)
    print(f"pinned {len(pins)} tools to {a.out}")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    lines = Path(a.log).read_text(encoding="utf-8").splitlines()
    verifier = None
    if a.pubkey:
        from .signing import Verifier

        verifier = Verifier.from_file(a.pubkey)
    elif a.require_signatures:
        print("error: --require-signatures needs --pubkey", file=sys.stderr)
        return 2
    r = verify_records(lines, verifier, require_signatures=a.require_signatures)
    print(r.message)
    if not r.ok:
        return 1
    if a.checkpoint:
        from .signing import checkpoint_signature_ok

        cp = json.loads(Path(a.checkpoint).read_text(encoding="utf-8"))
        if verifier is None:
            print("error: --checkpoint needs --pubkey", file=sys.stderr)
            return 2
        if not checkpoint_signature_ok(verifier, cp):
            print("checkpoint signature is not valid")
            return 1
        ok, message = verify_with_checkpoint(lines, cp)
        print(message)
        return 0 if ok else 1
    return 0


def cmd_keygen(a: argparse.Namespace) -> int:
    from .signing import generate_keypair

    key, pub = generate_keypair(a.out_dir)
    print(f"private key: {key} (keep it on the gateway host, readable only by the gateway user)")
    print(f"public key:  {pub} (give it to whoever verifies the audit log)")
    return 0


def cmd_checkpoint(a: argparse.Namespace) -> int:
    from datetime import UTC, datetime

    from .signing import Signer, make_checkpoint

    lines = Path(a.log).read_text(encoding="utf-8").splitlines()
    r = verify_records(lines)
    if not r.ok:
        print(f"refusing to checkpoint a broken log: {r.message}", file=sys.stderr)
        return 1
    cp = make_checkpoint(Signer.from_file(a.key), Path(a.log).name, r.records, r.head, datetime.now(UTC).isoformat())
    text = json.dumps(cp, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"checkpoint of {r.records} records written to {a.out}; store it where the gateway host cannot write")
    else:
        sys.stdout.write(text)
    return 0


def cmd_attack_sim(a: argparse.Namespace) -> int:
    from .attacksim import run

    report = run(a.corpus, a.policy, a.lock, a.tools)
    if a.json:
        Path(a.json).write_text(json.dumps(report.to_json(), indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(report.to_markdown())
    return 0 if report.gate_ok else 1


def cmd_proxy(a: argparse.Namespace) -> int:
    if not a.command:
        print("usage: mcpguard proxy --policy P [--lock L] -- <server command>", file=sys.stderr)
        return 2
    policy = load_policy(a.policy)
    signer = None
    if a.sign_key:
        from .signing import Signer

        signer = Signer.from_file(a.sign_key)
    gw = Gateway(policy, lock=load_lock(a.lock), audit=AuditLog(a.audit, signer=signer))
    return run_stdio_proxy(gw, a.command)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcpguard", description="Security gateway for MCP servers")
    p.add_argument("--version", action="version", version=f"mcpguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan-tools", help="review a tools/list response for poisoning and drift")
    s.add_argument("tools")
    s.add_argument("--lock")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("lock", help="pin approved tool definitions")
    s.add_argument("tools")
    s.add_argument("--out", default="mcpguard.lock.json")
    s.add_argument("--server", default="default")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_lock)

    s = sub.add_parser("verify-audit", help="check the audit log hash chain, signatures and a checkpoint")
    s.add_argument("log")
    s.add_argument("--pubkey", help="Ed25519 public key (PEM) to verify record signatures")
    s.add_argument("--require-signatures", action="store_true", help="fail on any unsigned record")
    s.add_argument("--checkpoint", help="signed checkpoint JSON; the log must still contain that prefix")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("keygen", help="create an Ed25519 key pair for audit signing")
    s.add_argument("--out-dir", default="keys")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("checkpoint", help="sign the current head of an audit log")
    s.add_argument("log")
    s.add_argument("--key", required=True)
    s.add_argument("--out")
    s.set_defaults(fn=cmd_checkpoint)

    s = sub.add_parser("attack-sim", help="replay the attack corpus through the gateway and report")
    s.add_argument("--corpus", default="examples/attack-corpus.json")
    s.add_argument("--policy", default="examples/policy.toml")
    s.add_argument("--lock", default="examples/mcpguard.lock.json")
    s.add_argument("--tools", default="examples/tools.json")
    s.add_argument("--json", help="also write the full report as JSON")
    s.set_defaults(fn=cmd_attack_sim)

    s = sub.add_parser("proxy", help="run an MCP server behind the gateway (stdio)")
    s.add_argument("--policy", required=True)
    s.add_argument("--lock")
    s.add_argument("--audit", default="audit/mcpguard.jsonl")
    s.add_argument("--sign-key", help="Ed25519 private key (PEM) to sign every audit record")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_proxy)

    a = p.parse_args(argv)
    if getattr(a, "command", None) and a.command[:1] == ["--"]:
        a.command = a.command[1:]
    try:
        return a.fn(a)
    except (PolicyError, FileNotFoundError, FileExistsError, json.JSONDecodeError, ValueError, SigningUnavailable) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
