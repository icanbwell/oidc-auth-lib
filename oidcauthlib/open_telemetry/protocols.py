"""Protocol definitions for OpenTelemetry span filtering components.

This module defines the strategy protocol for span filtering,
allowing pluggable filtering implementations.
"""

from typing import Protocol, runtime_checkable

from opentelemetry.sdk.trace import ReadableSpan


@runtime_checkable
class SpanFilterStrategy(Protocol):
    """
    Protocol for span filtering strategies.

    Implementations determine whether a span should be filtered based
    on custom logic (pattern matching, attributes, duration, etc.).

    This is the only protocol in the filtering system, as it represents
    the primary extension point for custom filtering behavior.
    """

    def should_filter(self, span: ReadableSpan) -> bool:
        """
        Determine if a span should be filtered.

        Args:
            span: The span to evaluate

        Returns:
            True if the span should be filtered (not exported)
        """
        ...