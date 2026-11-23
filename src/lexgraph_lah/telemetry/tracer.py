import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from pydantic import BaseModel, Field

from lexgraph_lah.schemas.domain import TelemetrySummary


class ComplianceSpanRecord(BaseModel):
    """Structured OpenTelemetry / FinOps span record for observability and UI rendering."""

    span_id: str
    document_id: str
    reference_date: str | None = None
    active_statute_count: int = 0
    model_tier: str | None = None
    model_routing_reason: str | None = None
    cache_hit: bool | None = None
    tenant_id: str | None = None
    extra_attributes: dict[str, Any] = Field(default_factory=dict)
    telemetry: TelemetrySummary
    timestamp_epoch: float


def emit_otel_attributes(attrs: dict[str, Any]) -> None:
    """Forwards `lexgraph.*` attributes to the active OpenTelemetry span when recording."""
    if not attrs:
        return
    try:
        from opentelemetry import trace as otel_trace

        span = otel_trace.get_current_span()
        if span is not None and span.is_recording():
            for key, val in attrs.items():
                if val is None:
                    continue
                otel_key = key if key.startswith("lexgraph.") else f"lexgraph.{key}"
                span.set_attribute(otel_key, val)
    except (ImportError, RuntimeError, AttributeError):
        pass


class TelemetryRegistry:
    """
    In-memory ring buffer of recent compliance trace spans paired with optional
    Arize Phoenix OpenTelemetry instrumentation.
    """

    def __init__(self, maxlen: int = 200) -> None:
        self._records: deque[ComplianceSpanRecord] = deque(maxlen=maxlen)
        self._otel_initialized: bool = False

    def init_otel(self, endpoint: str | None = None) -> bool:
        """
        Initializes Arize Phoenix OpenTelemetry collector and LangChain auto-instrumentation
        if running in a live environment. Safe no-op in unit tests.
        """
        if self._otel_initialized:
            return True
        try:
            from openinference.instrumentation.langchain import LangChainInstrumentor
            from phoenix.otel import register

            tracer_provider = register(endpoint=endpoint, project_name="lexgraph-lah")
            LangChainInstrumentor().instrument(tracer_provider=tracer_provider)
            self._otel_initialized = True
            return True
        except (ImportError, RuntimeError, ValueError, OSError):
            return False

    def record_span(self, record: ComplianceSpanRecord) -> None:
        self._records.append(record)
        attrs: dict[str, Any] = {
            "span_id": record.span_id,
            "document_id": record.document_id,
            "total_tokens": record.telemetry.total_tokens,
            "estimated_cost_usd": record.telemetry.estimated_cost_usd,
            "estimated_cost_myr": record.telemetry.estimated_cost_myr,
        }
        model_tier = record.model_tier or record.telemetry.model_name
        if model_tier:
            attrs["model_tier"] = model_tier
        if record.model_routing_reason:
            attrs["model_routing_reason"] = record.model_routing_reason
        if record.cache_hit is not None:
            attrs["cache_hit"] = record.cache_hit
        elif record.telemetry.cache_hit:
            attrs["cache_hit"] = True
        if record.tenant_id:
            attrs["tenant_id"] = record.tenant_id
        for k, v in record.extra_attributes.items():
            attrs[k] = v
        emit_otel_attributes(attrs)

    def list_spans(self) -> list[ComplianceSpanRecord]:
        return list(self._records)

    def clear(self) -> None:
        self._records.clear()


telemetry_registry = TelemetryRegistry()


@contextmanager
def measure_latency_ms() -> Iterator[list[float]]:
    """Context manager yielding a single-element list populated with elapsed ms on exit."""
    holder = [0.0]
    start = time.perf_counter()
    try:
        yield holder
    finally:
        holder[0] = (time.perf_counter() - start) * 1000.0
