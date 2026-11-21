"""stdio proxy: run the real MCP server as a subprocess and filter traffic in both directions.

MCP's stdio transport sends one JSON-RPC message per line. The host launches `mcpguard proxy`
instead of the server, so no change is needed on either side.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import IO

from .gateway import Gateway


def _write(stream: IO[str], msg: dict, lock: threading.Lock) -> None:
    with lock:
        stream.write(json.dumps(msg, separators=(",", ":")) + "\n")
        stream.flush()


def run_stdio_proxy(
    gateway: Gateway, server_cmd: list[str], stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout
) -> int:
    proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    assert proc.stdin and proc.stdout
    to_client, to_server = threading.Lock(), threading.Lock()

    def pump_server() -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                gateway.audit.write("protocol.invalid_json", direction="server")
                continue
            out = gateway.from_server(msg)
            if out.forward is not None:
                _write(stdout, out.forward, to_client)

    t = threading.Thread(target=pump_server, daemon=True)
    t.start()
    try:
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                gateway.audit.write("protocol.invalid_json", direction="client")
                continue
            out = gateway.from_client(msg)
            if out.reply is not None:
                _write(stdout, out.reply, to_client)
            if out.forward is not None:
                _write(proc.stdin, out.forward, to_server)
    finally:
        proc.stdin.close()
        t.join(timeout=5)
        proc.terminate()
    return proc.wait(timeout=5) or 0
