"""A tracer that keeps its spans in memory, so a test can read what a call emitted."""

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from keystone.telemetry.tracing import OTelTracer


def traced() -> tuple[OTelTracer, InMemorySpanExporter]:
    """A tracer and the exporter its spans land in as soon as they end."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": "keystone"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return OTelTracer(provider), exporter


def named(spans: tuple[ReadableSpan, ...], name: str) -> list[ReadableSpan]:
    return [span for span in spans if span.name == name]


def dump(spans: tuple[ReadableSpan, ...]) -> str:
    """Everything the spans hold, as one string to search: names, attributes, events, status."""
    return "\n".join(span.to_json() for span in spans)
