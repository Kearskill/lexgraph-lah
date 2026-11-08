import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager

from pydantic import BaseModel

from lexgraph_lah.schemas.domain import TelemetrySummary


class ComplianceSpanRecord(BaseModel):
    """Structured OpenTelemetry / FinOps span record for observability and UI rendering."""

    span_id: str
    document_id: str
    reference_date: str | None = None
    active_statute_count: int = 0
    telemetry: TelemetrySummary
    timestamp_epoch: float


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
