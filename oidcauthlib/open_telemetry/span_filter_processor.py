"""OpenTelemetry SpanProcessor with configurable filtering.

This module provides:
- PatternMatchingStrategy: Filters spans based on pattern matching
- SpanFilterMetrics: Thread-safe metrics tracking
- SpanFilterProcessor: SpanProcessor that filters spans based on strategy
"""

import logging
from collections import defaultdict
from logging import Logger
from threading import Lock
from typing import Optional

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor
from typing_extensions import override

from oidcauthlib.open_telemetry.protocols import SpanFilterStrategy
from oidcauthlib.open_telemetry.span_filter_config import SpanFilterConfig

# Default timeout for force_flush in milliseconds (30 seconds)
DEFAULT_FLUSH_TIMEOUT_MS: int = 30000


class PatternMatchingStrategy:
    """
    Filters spans based on pattern matching against span names.

    Implicitly implements the SpanFilterStrategy protocol through
    structural subtyping.
    """

    def __init__(self, config: SpanFilterConfig) -> None:
        """
        Initialize the strategy with configuration.

        Args:
            config: Configuration providing filter patterns
        """
        self._config = config

    def should_filter(self, span: ReadableSpan) -> bool:
        """
        Determine if span matches any configured patterns.

        Args:
            span: The span to evaluate

        Returns:
            True if span name contains any configured pattern
        """
        if not self._config.enabled:
            return False

        span_name = span.name
        for pattern in self._config.patterns:
            if pattern in span_name:
                return True

        return False


class SpanFilterMetrics:
    """
    Thread-safe metrics tracking for filtered spans.
    """

    def __init__(self) -> None:
        """Initialize metrics with thread-safe counters."""
        self._filtered_count: int = 0
        self._filtered_by_pattern: dict[str, int] = defaultdict(int)
        self._lock = Lock()

    def increment_filtered(self, span_name: str) -> None:
        """
        Record that a span was filtered.

        Args:
            span_name: Name of the filtered span (for pattern tracking)
        """
        with self._lock:
            self._filtered_count += 1
            # Track by pattern (simplified - just use span name)
            self._filtered_by_pattern[span_name] += 1

    def get_filtered_count(self) -> int:
        """
        Get total number of filtered spans.

        Returns:
            Total count of filtered spans (thread-safe)
        """
        with self._lock:
            return self._filtered_count

    def get_filtered_by_pattern(self) -> dict[str, int]:
        """
        Get count of filtered spans grouped by pattern.

        Returns:
            Dictionary mapping span names to filter counts (copy)
        """
        with self._lock:
            return dict(self._filtered_by_pattern)


class SpanFilterProcessor(SpanProcessor):
    """
    SpanProcessor that filters spans based on configurable strategy.

    Follows the Decorator pattern to wrap another SpanProcessor and
    selectively pass through spans that don't match filter criteria.
    Uses Strategy pattern for filtering logic via SpanFilterStrategy protocol.
    """

    def __init__(
        self,
        wrapped_processor: SpanProcessor,
        strategy: SpanFilterStrategy,
        config: SpanFilterConfig,
        metrics: SpanFilterMetrics,
        logger: Optional[Logger] = None,
    ) -> None:
        """
        Initialize the span filter processor.

        Args:
            wrapped_processor: The actual processor to delegate to
            strategy: Strategy for determining if spans should be filtered
            config: Filter configuration (for debug logging)
            metrics: Metrics tracker
            logger: Optional logger (creates one if not provided)
        """
        self._wrapped = wrapped_processor
        self._strategy = strategy
        self._config = config
        self._metrics = metrics
        self._logger = logger or logging.getLogger(__name__)

    @override
    def on_start(self, span: Span, parent_context: Optional[Context] = None) -> None:
        """
        Called when span starts - always delegate.

        Args:
            span: The span that started
            parent_context: Optional parent context
        """
        self._wrapped.on_start(span, parent_context)

    @override
    def on_end(self, span: ReadableSpan) -> None:
        """
        Called when span ends - filter or delegate.

        Applies filtering logic based on configured strategy.

        Args:
            span: The span that ended
        """
        try:
            if self._strategy.should_filter(span):
                self._handle_filtered_span(span)
                return

            # Not filtered, delegate to wrapped processor
            self._wrapped.on_end(span)

        except Exception:
            # Fail-safe: if filtering fails, pass through the span
            self._logger.exception(
                f"Error in span filtering for {span.name}. "
                f"Passing through span to prevent data loss."
            )
            self._wrapped.on_end(span)

    def _handle_filtered_span(self, span: ReadableSpan) -> None:
        """
        Handle a span that was filtered out.

        Args:
            span: The filtered span
        """
        self._metrics.increment_filtered(span.name)

        if self._config.debug_logging:
            self._logger.debug(
                f"Filtered span: {span.name} "
                f"(total filtered: {self._metrics.get_filtered_count()})"
            )

    @override
    def shutdown(self) -> None:
        """Shutdown the wrapped processor and log final metrics."""
        try:
            filtered_count = self._metrics.get_filtered_count()

            if self._config.debug_logging and filtered_count > 0:
                filtered_by_pattern = self._metrics.get_filtered_by_pattern()
                self._logger.info(
                    f"SpanFilterProcessor shutdown: "
                    f"filtered {filtered_count} spans. "
                    f"Breakdown: {filtered_by_pattern}"
                )

        except Exception:
            self._logger.exception("Error logging shutdown metrics")

        finally:
            # Always shutdown wrapped processor
            self._wrapped.shutdown()

    @override
    def force_flush(self, timeout_millis: int = DEFAULT_FLUSH_TIMEOUT_MS) -> bool:
        """
        Flush the wrapped processor.

        Args:
            timeout_millis: Timeout in milliseconds (default: 30 seconds)

        Returns:
            True if flush succeeded
        """
        return self._wrapped.force_flush(timeout_millis)