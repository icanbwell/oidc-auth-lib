import logging
from typing import Optional, Set, Sequence
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

logger = logging.getLogger(__name__)


class FilteringSpanExporter(SpanExporter):
    """
    A SpanExporter that wraps another exporter and filters out unwanted spans.

    This is simpler than a SpanProcessor because it works at the export level
    and can be easily added to the tracer provider.
    """

    def __init__(
            self,
            wrapped_exporter: SpanExporter,
            excluded_span_names: Optional[Set[str]] = None,
            excluded_span_prefixes: Optional[Set[str]] = None,
            min_duration_ms: Optional[float] = None,
            exclude_root_spans_from_duration_filter: bool = True,
    ):
        """
        Initialize the filtering span exporter.

        Args:
            wrapped_exporter: The span exporter to wrap
            excluded_span_names: Set of exact span names to exclude
            excluded_span_prefixes: Set of span name prefixes to exclude
            min_duration_ms: Minimum duration in milliseconds. Spans shorter than this
                           will be filtered out. Set to None to disable duration filtering.
            exclude_root_spans_from_duration_filter: If True, root spans (spans without parents)
                                                     will not be filtered by duration.
        """
        self.wrapped_exporter = wrapped_exporter
        self.excluded_span_names = excluded_span_names or {
            "saslStart",
            "saslContinue",
            "isMaster",
            "ping",
        }
        self.excluded_span_prefixes = excluded_span_prefixes or set()
        self.min_duration_ms = min_duration_ms
        self.exclude_root_spans_from_duration_filter = exclude_root_spans_from_duration_filter

        logger.info(
            "FilteringSpanExporter initialized. "
            "Excluding span names: %s, prefixes: %s, min_duration_ms: %s, "
            "exclude_root_spans_from_duration_filter: %s",
            self.excluded_span_names,
            self.excluded_span_prefixes,
            self.min_duration_ms,
            self.exclude_root_spans_from_duration_filter,
        )

    def _is_root_span(self, span: ReadableSpan) -> bool:
        """Check if a span is a root span (has no parent)."""
        parent_span_context = span.parent
        return parent_span_context is None or not parent_span_context.is_valid

    def _get_span_duration_ms(self, span: ReadableSpan) -> Optional[float]:
        """
        Calculate span duration in milliseconds.

        Returns:
            Duration in milliseconds, or None if times are not available
        """
        if span.start_time is None or span.end_time is None:
            return None

        # Times are in nanoseconds
        duration_ns = span.end_time - span.start_time
        duration_ms = duration_ns / 1_000_000.0
        return duration_ms

    def _should_export_span(self, span: ReadableSpan) -> bool:
        """
        Determine if a span should be exported.

        Returns:
            True if the span should be exported, False if it should be filtered out
        """
        span_name = span.name

        # Filter 1: Check exact name match
        if span_name in self.excluded_span_names:
            logger.debug("Filtered out span (exact match): %s", span_name)
            return False

        # Filter 2: Check prefix match
        for prefix in self.excluded_span_prefixes:
            if span_name.startswith(prefix):
                logger.debug("Filtered out span (prefix match): %s", span_name)
                return False

        # Filter 3: Check duration (if configured)
        if self.min_duration_ms is not None:
            # Check if we should skip duration filtering for root spans
            is_root = self._is_root_span(span)
            if is_root and self.exclude_root_spans_from_duration_filter:
                logger.debug(
                    "Skipping duration filter for root span: %s",
                    span_name
                )
            else:
                duration_ms = self._get_span_duration_ms(span)
                if duration_ms is not None and duration_ms < self.min_duration_ms:
                    logger.debug(
                        "Filtered out span (duration %.2fms < %.2fms): %s",
                        duration_ms,
                        self.min_duration_ms,
                        span_name
                    )
                    return False

        return True

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        """
        Export spans, filtering out unwanted ones.

        Args:
            spans: The spans to export

        Returns:
            The result of exporting the filtered spans
        """
        # Filter spans
        filtered_spans = [span for span in spans if self._should_export_span(span)]

        if len(filtered_spans) < len(spans):
            logger.debug(
                "Filtered %d out of %d spans",
                len(spans) - len(filtered_spans),
                len(spans)
            )

        # Export filtered spans
        if filtered_spans:
            return self.wrapped_exporter.export(filtered_spans)
        else:
            return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        """Shutdown the wrapped exporter."""
        self.wrapped_exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Force flush the wrapped exporter."""
        return self.wrapped_exporter.force_flush(timeout_millis)
