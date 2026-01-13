import logging
from typing import Optional, Set, override

from opentelemetry.context import Context
from opentelemetry.sdk.trace import (
    ReadableSpan,
    SpanProcessor,
    Span,
)

from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["OPEN_TELEMETRY"])


class FilteringSpanProcessor(SpanProcessor):
    """
    A SpanProcessor that filters out unwanted spans based on:
    - Exact span name matches
    - Span name prefix matches
    - Span duration (optional minimum duration threshold)

    This works with auto-instrumentation and doesn't require modifying the
    instrumentation configuration.
    """

    def __init__(
        self,
        wrapped_processor: SpanProcessor,
        excluded_span_names: Optional[Set[str]] = None,
        excluded_span_prefixes: Optional[Set[str]] = None,
        min_duration_ms: Optional[float] = None,
        exclude_root_spans_from_duration_filter: bool = True,
    ):
        """
        Initialize the filtering span processor.

        Args:
            wrapped_processor: The span processor to wrap
            excluded_span_names: Set of exact span names to exclude
            excluded_span_prefixes: Set of span name prefixes to exclude
            min_duration_ms: Minimum duration in milliseconds. Spans shorter than this
                           will be filtered out. Set to None to disable duration filtering.
            exclude_root_spans_from_duration_filter: If True, root spans (spans without parents)
                                                     will not be filtered by duration. This is
                                                     useful to keep top-level traces visible even
                                                     if they're fast.
        """
        self.wrapped_processor = wrapped_processor
        self.excluded_span_names = excluded_span_names or {
            "saslStart",
            "saslContinue",
            "isMaster",
            "ping",
        }
        self.excluded_span_prefixes = excluded_span_prefixes or set()
        self.min_duration_ms = min_duration_ms
        self.exclude_root_spans_from_duration_filter = (
            exclude_root_spans_from_duration_filter
        )

        logger.info(
            "FilteringSpanProcessor initialized. "
            "Excluding span names: %s, prefixes: %s, min_duration_ms: %s, "
            "exclude_root_spans_from_duration_filter: %s",
            self.excluded_span_names,
            self.excluded_span_prefixes,
            self.min_duration_ms,
            self.exclude_root_spans_from_duration_filter,
        )

    @override
    def on_start(self, span: Span, parent_context: Optional[Context] = None) -> None:
        """Called when a span is started."""
        self.wrapped_processor.on_start(span, parent_context)

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

    @override
    def on_end(self, span: ReadableSpan) -> None:
        """
        Called when a span is ended.
        Only forward spans that pass all filters.
        """
        span_name = span.name

        # Filter 1: Check exact name match
        if span_name in self.excluded_span_names:
            logger.debug("Filtered out span (exact match): %s", span_name)
            return

        # Filter 2: Check prefix match
        for prefix in self.excluded_span_prefixes:
            if span_name.startswith(prefix):
                logger.debug("Filtered out span (prefix match): %s", span_name)
                return

        # Filter 3: Check duration (if configured)
        if self.min_duration_ms is not None:
            # Check if we should skip duration filtering for root spans
            is_root = self._is_root_span(span)
            if is_root and self.exclude_root_spans_from_duration_filter:
                logger.debug("Skipping duration filter for root span: %s", span_name)
            else:
                duration_ms = self._get_span_duration_ms(span)
                if duration_ms is not None and duration_ms < self.min_duration_ms:
                    logger.debug(
                        "Filtered out span (duration %.2fms < %.2fms): %s",
                        duration_ms,
                        self.min_duration_ms,
                        span_name,
                    )
                    return

        # Span passed all filters, forward it
        self.wrapped_processor.on_end(span)

    @override
    def shutdown(self) -> None:
        """Shutdown the wrapped processor."""
        return self.wrapped_processor.shutdown()

    @override
    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Force flush the wrapped processor."""
        return self.wrapped_processor.force_flush(timeout_millis)

    # Support for MultiSpanProcessor interface
    def add_span_processor(self, span_processor: SpanProcessor) -> None:
        """
        Add a span processor to the wrapped processor if it supports it.
        This allows FilteringSpanProcessor to work with MultiSpanProcessor.
        """
        if hasattr(self.wrapped_processor, "add_span_processor"):
            self.wrapped_processor.add_span_processor(span_processor)
        else:
            logger.warning(
                "Wrapped processor %s does not support add_span_processor",
                type(self.wrapped_processor).__name__,
            )
