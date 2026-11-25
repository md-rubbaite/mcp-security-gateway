"""Tests for v1.1: signed audit records and checkpoints, OPA decision point, telemetry, attack simulation."""

from __future__ import annotations

import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from mcpguard.attacksim import load_corpus, run
from mcpguard.audit import AuditLog, _digest, verify, verify_records, verify_with_checkpoint
from mcpguard.cli import main
from mcpguard.gateway import Gateway
from mcpguard.opa import OpaClient, OpaConfig
from mcpguard.policy import PolicyError, parse_policy
from mcpguard.signing import (
    HAVE_CRYPTO,
    Signer,
    Verifier,
    checkpoint_signature_ok,
    generate_keypair,
    make_checkpoint,
)

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "examples"
needs_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="needs the [signing] extra")

# ------------------------------------------------------------------ signed audit


def _signed_log(tmp_path: Path, n: int = 4) -> tuple[Path, Signer]:
    signer = Signer.generate()
    log = AuditLog(tmp_path / "a.jsonl", signer=signer)
    for i in range(n):
        log.write("call.allowed", tool="read_file", id=i)
    return tmp_path / "a.jsonl", signer


def _lines(p: Path) -> list[str]:
    return p.read_text(encoding="utf-8").splitlines()


@needs_crypto
def test_signed_records_verify_and_carry_key_id(tmp_path):
    path, signer = _signed_log(tmp_path)
    recs = [json.loads(x) for x in _lines(path)]
    assert all(r["kid"] == signer.kid and "sig" in r for r in recs)
    r = verify_records(_lines(path), Verifier.from_pem(signer.public_pem()), require_signatures=True)
    assert r.ok and r.signed == 4


@needs_crypto
def test_chain_only_verification_still_works_on_signed_logs(tmp_path):
    path, _ = _signed_log(tmp_path)
    assert verify(path)[0]


@needs_crypto
def test_rebuilt_chain_without_the_key_is_rejected(tmp_path):
    """An attacker edits a record and recomputes every hash: the chain check passes, the signature check does not."""
    path, signer = _signed_log(tmp_path)
    recs = [json.loads(x) for x in _lines(path)]
    recs[1]["tool"] = "send_email"
    prev = recs[0]["hash"]
    for r in recs[1:]:
        r["prev"] = prev
        r["hash"] = _digest(r)
        prev = r["hash"]
    forged = [json.dumps(r, sort_keys=True) for r in recs]
    assert verify_records(forged).ok  # hash chain alone is fooled
    r = verify_records(forged, Verifier.from_pem(signer.public_pem()))
    assert not r.ok and "line 2: signature is not valid" in r.message


@needs_crypto
def test_record_signed_with_another_key_is_rejected(tmp_path):
    path, _ = _signed_log(tmp_path)
    other = Signer.generate()
    r = verify_records(_lines(path), Verifier.from_pem(other.public_pem()))
    assert not r.ok and "different key" in r.message


@needs_crypto
def test_unsigned_records_fail_only_when_signatures_are_required(tmp_path):
    log = AuditLog(tmp_path / "u.jsonl")
    log.write("tools.listed", offered=1, visible=1)
    v = Verifier.from_pem(Signer.generate().public_pem())
    assert verify_records(_lines(tmp_path / "u.jsonl"), v).ok
    r = verify_records(_lines(tmp_path / "u.jsonl"), v, require_signatures=True)
    assert not r.ok and "not signed" in r.message


@needs_crypto
def test_signature_field_is_not_part_of_the_hash(tmp_path):
    path, _ = _signed_log(tmp_path, 1)
    rec = json.loads(_lines(path)[0])
    no_sig = {k: v for k, v in rec.items() if k != "sig"}
    assert _digest(no_sig) == rec["hash"]


@needs_crypto
def test_reopening_a_log_continues_count_and_chain(tmp_path):
    path, signer = _signed_log(tmp_path, 3)
    again = AuditLog(path, signer=signer)
    assert again.count == 3
    again.write("tools.listed", offered=0, visible=0)
    assert verify_records(_lines(path), Verifier.from_pem(signer.public_pem()), require_signatures=True).ok


# ------------------------------------------------------------------ checkpoints


def _checkpoint(path: Path, signer: Signer) -> dict:
    r = verify_records(_lines(path))
    return make_checkpoint(signer, path.name, r.records, r.head, "2026-11-25T00:00:00+00:00")


@needs_crypto
def test_checkpoint_accepts_appended_records(tmp_path):
    path, signer = _signed_log(tmp_path, 3)
    cp = _checkpoint(path, signer)
    AuditLog(path, signer=signer).write("call.allowed", tool="x", id=9)
    assert checkpoint_signature_ok(Verifier.from_pem(signer.public_pem()), cp)
    ok, msg = verify_with_checkpoint(_lines(path), cp)
    assert ok, msg


@needs_crypto
def test_checkpoint_detects_truncation(tmp_path):
    path, signer = _signed_log(tmp_path, 4)
    cp = _checkpoint(path, signer)
    path.write_text("\n".join(_lines(path)[:2]) + "\n", encoding="utf-8")
    assert verify_records(_lines(path)).ok  # a truncated chain is still a valid chain
    ok, msg = verify_with_checkpoint(_lines(path), cp)
    assert not ok and "removed" in msg


@needs_crypto
def test_checkpoint_detects_a_full_rewrite(tmp_path):
    """Even a key holder who rewrites history after the checkpoint was exported is caught."""
    path, signer = _signed_log(tmp_path, 3)
    cp = _checkpoint(path, signer)
    path.unlink()
    log = AuditLog(path, signer=signer)
    for i in range(3):
        log.write("call.allowed", tool="other_tool", id=i)
    assert verify_records(_lines(path), Verifier.from_pem(signer.public_pem()), require_signatures=True).ok
    ok, msg = verify_with_checkpoint(_lines(path), cp)
    assert not ok and "rewritten" in msg


@needs_crypto
def test_forged_checkpoint_is_rejected(tmp_path):
    path, signer = _signed_log(tmp_path, 2)
    cp = _checkpoint(path, signer)
    cp["count"] = 1
    assert not checkpoint_signature_ok(Verifier.from_pem(signer.public_pem()), cp)
    assert not checkpoint_signature_ok(Verifier.from_pem(Signer.generate().public_pem()), _checkpoint(path, signer))


@needs_crypto
def test_keygen_writes_private_key_0600_and_refuses_to_overwrite(tmp_path):
    key, pub = generate_keypair(tmp_path / "k")
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    assert Signer.from_file(key).kid == Verifier.from_file(pub).kid
    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path / "k")


@needs_crypto
def test_cli_sign_checkpoint_and_verify_end_to_end(tmp_path, capsys):
    assert main(["keygen", "--out-dir", str(tmp_path / "keys")]) == 0
    key, pub = tmp_path / "keys/audit-signing.key", tmp_path / "keys/audit-signing.pub"
    log = AuditLog(tmp_path / "a.jsonl", signer=Signer.from_file(key))
    for i in range(3):
        log.write("call.allowed", tool="read_file", id=i)
    assert main(["checkpoint", str(tmp_path / "a.jsonl"), "--key", str(key), "--out", str(tmp_path / "cp.json")]) == 0
    args = ["verify-audit", str(tmp_path / "a.jsonl"), "--pubkey", str(pub), "--require-signatures"]
    assert main([*args, "--checkpoint", str(tmp_path / "cp.json")]) == 0
    assert "first 3 records match the checkpoint" in capsys.readouterr().out
    lines = _lines(tmp_path / "a.jsonl")
    (tmp_path / "a.jsonl").write_text(lines[0] + "\n", encoding="utf-8")
    assert main([*args, "--checkpoint", str(tmp_path / "cp.json")]) == 1


@needs_crypto
def test_cli_checkpoint_refuses_a_broken_log(tmp_path):
    key, _ = generate_keypair(tmp_path / "k")
    log = AuditLog(tmp_path / "a.jsonl")
    log.write("x")
    log.write("y")
    lines = _lines(tmp_path / "a.jsonl")
    (tmp_path / "a.jsonl").write_text(lines[1] + "\n", encoding="utf-8")
    assert main(["checkpoint", str(tmp_path / "a.jsonl"), "--key", str(key)]) == 1


@needs_crypto
def test_cli_require_signatures_needs_a_key(tmp_path):
    AuditLog(tmp_path / "a.jsonl").write("x")
    assert main(["verify-audit", str(tmp_path / "a.jsonl"), "--require-signatures"]) == 2


# ------------------------------------------------------------------ OPA


class _FakeOpa:
    """A tiny HTTP server answering like OPA's Data API, recording what it received."""

    def __init__(self, reply):
        self.reply = reply
        self.requests: list[tuple[str, dict]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((self.path, body))
                payload = outer.reply(body["input"]) if callable(outer.reply) else outer.reply
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake_opa():
    servers = []

    def make(reply):
        s = _FakeOpa(reply)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def _policy(opa_url: str | None = None, **opa) -> dict:
    doc = {
        "gateway": {"server_name": "demo"},
        "tool": [
            {"name": "read_file", "args": {"path": {"path_prefixes": ["/workspace"]}}},
            {"name": "send_email", "requires_approval": True},
        ],
    }
    if opa_url:
        doc["gateway"]["opa"] = {"url": opa_url, **opa}
    return doc


def _gw(policy_doc: dict, approve: bool = False) -> Gateway:
    gw = Gateway(parse_policy(policy_doc), approver=lambda _n, _a: approve)
    gw.policy.block_unpinned_tools = False
    gw.from_client({"jsonrpc": "2.0", "id": "l", "method": "tools/list"})
    gw.from_server({"jsonrpc": "2.0", "id": "l", "result": {"tools": [{"name": "read_file"}, {"name": "send_email"}]}})
    return gw


def _call(gw: Gateway, name: str, args: dict, i: int = 1):
    return gw.from_client(
        {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}
    )


def test_opa_allow_forwards_and_receives_the_documented_input(fake_opa):
    opa = fake_opa({"result": {"allow": True, "reasons": []}})
    gw = _gw(_policy(opa.url))
    out = _call(gw, "read_file", {"path": "/workspace/a.txt"})
    assert out.decision == "forward"
    path, body = opa.requests[0]
    assert path == "/v1/data/mcpguard/decision"
    assert body["input"] == {
        "server": "demo",
        "tool": "read_file",
        "arguments": {"path": "/workspace/a.txt"},
        "requires_approval": False,
        "approved": None,
    }


def test_opa_deny_blocks_with_its_reasons_and_is_audited(fake_opa):
    opa = fake_opa({"result": {"allow": False, "reasons": ["reading files under /workspace/secrets/ is not allowed"]}})
    gw = _gw(_policy(opa.url))
    out = _call(gw, "read_file", {"path": "/workspace/secrets/x"})
    assert out.decision == "block"
    assert out.reasons == ["reading files under /workspace/secrets/ is not allowed"]
    assert gw.audit.records[-1]["event"] == "call.blocked"


def test_opa_is_not_asked_when_the_local_policy_already_blocks(fake_opa):
    opa = fake_opa({"result": {"allow": True}})
    gw = _gw(_policy(opa.url))
    assert _call(gw, "read_file", {"path": "/etc/passwd"}).decision == "block"
    assert _call(gw, "send_email", {"to": "a"}, 2).decision == "block"  # approval missing
    assert opa.requests == []


def test_opa_cannot_allow_what_the_local_policy_denies(fake_opa):
    opa = fake_opa({"result": {"allow": True}})
    gw = _gw(_policy(opa.url))
    assert _call(gw, "delete_everything", {}).decision == "block"


def test_opa_sees_the_approval_outcome(fake_opa):
    opa = fake_opa(lambda inp: {"result": {"allow": inp["approved"] is True, "reasons": ["needs approval"]}})
    gw = _gw(_policy(opa.url), approve=True)
    assert _call(gw, "send_email", {"to": "a"}).decision == "forward"
    assert opa.requests[0][1]["input"]["requires_approval"] is True


@pytest.mark.parametrize(
    "reply,fragment",
    [
        ({}, "undefined"),
        ({"result": {"allow": "yes"}}, "boolean 'allow'"),
        ({"result": {"allow": False, "reasons": "nope"}}, "list of strings"),
        (b"not json", "invalid reply"),
    ],
)
def test_opa_bad_answers_fail_closed(fake_opa, reply, fragment):
    opa = fake_opa(reply)
    gw = _gw(_policy(opa.url))
    out = _call(gw, "read_file", {"path": "/workspace/a"})
    assert out.decision == "block"
    assert "policy decision point unavailable" in out.reasons[0] and fragment in out.reasons[0]
    assert any(r["event"] == "opa.error" for r in gw.audit.records)


def test_opa_unreachable_fails_closed_by_default():
    gw = _gw(_policy("http://127.0.0.1:9", timeout_ms=200))
    out = _call(gw, "read_file", {"path": "/workspace/a"})
    assert out.decision == "block" and "unavailable" in out.reasons[0]


def test_opa_fail_open_allows_but_logs_every_use():
    gw = _gw(_policy("http://127.0.0.1:9", timeout_ms=200, fail_open=True))
    assert _call(gw, "read_file", {"path": "/workspace/a"}).decision == "forward"
    err = [r for r in gw.audit.records if r["event"] == "opa.error"]
    assert err and "fail_open=true" in err[0]["error"]


def test_opa_timeout_is_enforced():
    calls = []

    def slow_opener(req, timeout):
        calls.append(timeout)
        raise TimeoutError

    client = OpaClient(OpaConfig(url="http://127.0.0.1:8181", timeout_ms=250), opener=slow_opener)
    d = client.decide({"tool": "x"})
    assert calls == [0.25] and not d.allow


@pytest.mark.parametrize(
    "opa,message",
    [
        ({"url": "http://opa.internal:8181"}, "https unless"),
        ({"url": "ftp://127.0.0.1"}, "http(s) URL"),
        ({}, "url is required"),
        ({"url": "https://opa.example", "timeout_ms": 0}, "between 10 and 10000"),
        ({"url": "https://opa.example", "decision": "/"}, "data path"),
        ({"url": "https://opa.example", "colour": "red"}, "unknown keys"),
    ],
)
def test_opa_config_is_validated(opa, message):
    with pytest.raises(PolicyError, match=message.replace("(", r"\(").replace(")", r"\)")):
        parse_policy({"gateway": {"opa": opa}})


def test_policy_without_opa_section_does_not_create_a_client():
    assert _gw(_policy()).opa is None


# ------------------------------------------------------------------ telemetry


def test_spans_describe_decisions_without_argument_values():
    sdk = pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = trace.get_tracer_provider()
    if not isinstance(provider, sdk.TracerProvider):
        provider = sdk.TracerProvider()
        trace.set_tracer_provider(provider)
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    gw = _gw(_policy())
    _call(gw, "read_file", {"path": "/etc/shadow"})
    spans = [s for s in exporter.get_finished_spans() if s.name == "mcpguard tools/call"]
    assert spans, [s.name for s in exporter.get_finished_spans()]
    attrs = dict(spans[-1].attributes)
    assert attrs["gen_ai.tool.name"] == "read_file"
    assert attrs["mcpguard.decision"] == "block"
    assert attrs["mcpguard.reason_count"] >= 1
    assert "/etc/shadow" not in json.dumps(attrs)


# ------------------------------------------------------------------ attack simulation


def _sim():
    return run(EX / "attack-corpus.json", EX / "policy.toml", EX / "mcpguard.lock.json", EX / "tools.json")


def test_attack_corpus_passes_the_regression_gate():
    report = _sim()
    assert report.gate_ok, [(r.id, r.decision, r.reasons) for r in report.unexpected]
    detected, attacks = report.detection
    flagged, benign = report.false_positives
    assert attacks >= 30 and benign >= 10
    assert detected == attacks - sum(r.known_gap for r in report.results if r.expect == "detect")
    assert flagged == sum(r.known_false_positive for r in report.results if r.expect == "pass")


def test_every_known_gap_is_still_a_gap():
    """If a known gap starts being detected, the corpus should be updated so the report stays truthful."""
    for r in _sim().results:
        if r.known_gap:
            assert not r.detected, f"{r.id} is now detected: remove known_gap"
        if r.known_false_positive:
            assert r.detected, f"{r.id} is no longer flagged: remove known_false_positive"


def test_weakening_a_control_fails_the_gate(tmp_path):
    weak = (
        (EX / "policy.toml")
        .read_text(encoding="utf-8")
        .replace('url_domains = ["docs.python.org", "learn.microsoft.com", "modelcontextprotocol.io"]', "")
    )
    (tmp_path / "policy.toml").write_text(weak, encoding="utf-8")
    report = run(EX / "attack-corpus.json", tmp_path / "policy.toml", EX / "mcpguard.lock.json", EX / "tools.json")
    assert not report.gate_ok
    assert {r.id for r in report.unexpected} >= {"ex-unlisted-domain", "ex-lookalike-domain"}


def test_corpus_validation(tmp_path):
    bad = {"scenarios": [{"id": "a", "category": "c", "kind": "call", "expect": "detect"}] * 2}
    (tmp_path / "c.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_corpus(tmp_path / "c.json")
    (tmp_path / "c.json").write_text(json.dumps([{"id": "a", "category": "c", "kind": "x", "expect": "detect"}]))
    with pytest.raises(ValueError, match="unknown kind"):
        load_corpus(tmp_path / "c.json")


def test_cli_attack_sim_writes_reports(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(ROOT)
    assert main(["attack-sim", "--json", str(tmp_path / "r.json")]) == 0
    out = capsys.readouterr().out
    assert "Regression gate: **PASS**" in out
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["gate_ok"] is True and len(data["scenarios"]) == len(load_corpus(EX / "attack-corpus.json"))
