import logging
from typing import Optional, Set, Sequence

from opentelemetry.context import Context
from opentelemetry.sdk.trace.sampling import (
    Sampler,
    SamplingResult,
    Decision,
    ALWAYS_ON,
)
from opentelemetry.trace import Link, SpanKind, TraceState
from opentelemetry.util.types import Attributes

logger = logging.getLogger(__name__)


class FilteringSampler(Sampler):
    """
    A sampler that filters out spans based on name patterns.

    This is more reliable than a SpanProcessor because it prevents
    spans from being created in the first place, rather than trying
    to filter them after creation.
    """

    def __init__(
            self,
            parent_sampler: Optional[Sampler] = None,
            excluded_span_names: Optional[Set[str]] = None,
            excluded_span_prefixes: Optional[Set[str]] = None,
    ):
        """
        Initialize the filtering sampler.

        Args:
            parent_sampler: The sampler to delegate to for non-filtered spans
            excluded_span_names: Set of exact span names to exclude
            excluded_span_prefixes: Set of span name prefixes to exclude
        """
        self.parent_sampler = parent_sampler or ALWAYS_ON
        self.excluded_span_names = excluded_span_names or {
            "saslStart",
            "saslContinue",
            "isMaster",
            "ping",
        }
        self.excluded_span_prefixes = excluded_span_prefixes or set()

        logger.info(
            "FilteringSampler initialized. Excluding span names: %s, prefixes: %s",
            self.excluded_span_names,
            self.excluded_span_prefixes,
        )

    def should_sample(
            self,
            parent_context: Optional["Context"],
            trace_id: int,
            name: str,
            kind: Optional[SpanKind] = None,
            attributes: Optional[Attributes] = None,
            links: Optional[Sequence[Link]] = None,
            trace_state: Optional["TraceState"] = None,
    ) -> SamplingResult:
        """
        Determine if a span should be sampled.

        Returns DROP for filtered spans, otherwise delegates to parent sampler.
        """
        # Check exact match
        if name in self.excluded_span_names:
            logger.debug("Filtering span (exact match): %s", name)
            return SamplingResult(Decision.DROP)

        # Check prefix match
        for prefix in self.excluded_span_prefixes:
            if name.startswith(prefix):
                logger.debug("Filtering span (prefix match): %s", name)
                return SamplingResult(Decision.DROP)

        logger.debug(f"FilteringSampler: Not filtering span: {name}")

        # Delegate to parent sampler
        return self.parent_sampler.should_sample(
            parent_context, trace_id, name, kind, attributes, links, trace_state
        )

    def get_description(self) -> str:
        """Get a description of this sampler."""
        return f"FilteringSampler(parent={self.parent_sampler.get_description()})"