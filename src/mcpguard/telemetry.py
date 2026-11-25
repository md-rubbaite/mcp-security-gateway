"""Optional OpenTelemetry tracing (needs `pip install mcpguard[otel]` plus an SDK/exporter of your choice).

Without the `opentelemetry-api` package every function here is a no-op, so the core stays
dependency-free. With it, each gateway decision becomes a span named `mcpguard <operation>` with
attributes that never contain argument values or tool output (only names, counts and outcomes):

- `gen_ai.tool.name`           tool being listed or called (OpenTelemetry GenAI semantic convention)
- `mcp.method.name`            MCP JSON-RPC method
- `mcpguard.decision`          forward | block | filtered | sanitised
- `mcpguard.reason_count`      number of reasons behind the decision
- `mcpguard.server`            server name from the policy
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

try:
    from opentelemetry import trace as _trace

    _tracer = _trace.get_tracer("mcpguard")
    HAVE_OTEL = True
except ImportError:  # pragma: no cover - exercised only without the extra installed
    _tracer = None
    HAVE_OTEL = False


class _NoSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass


@contextmanager
def span(operation: str, **attributes: Any) -> Iterator[Any]:
    if _tracer is None:
        yield _NoSpan()
        return
    with _tracer.start_as_current_span(f"mcpguard {operation}") as s:
        for k, v in attributes.items():
            if v is not None:
                s.set_attribute(k, v)
        yield s


def record_outcome(s: Any, decision: str, reasons: list[str]) -> None:
    s.set_attribute("mcpguard.decision", decision)
    s.set_attribute("mcpguard.reason_count", len(reasons))
