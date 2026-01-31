"""OpenTelemetry initialization with span filtering.

This module provides the OtelInitializer class that orchestrates
OpenTelemetry provider initialization and integrates span filtering
with existing auto-instrumentation.
"""

import logging
from logging import Logger
from threading import Lock
from typing import Optional

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from oidcauthlib.open_telemetry.span_filter_config import SpanFilterConfig
from oidcauthlib.open_telemetry.span_filter_processor import (
    PatternMatchingStrategy,
    SpanFilterMetrics,
    SpanFilterProcessor,
)


class OtelInitializer:
    """
    Initializes OpenTelemetry providers with custom processors.

    Integrates with opentelemetry-instrument auto-instrumentation
    by augmenting the existing global TracerProvider.

    Thread-safe singleton pattern for initialization.
    """

    _initialized: bool = False
    _lock: Lock = Lock()
    _logger: Logger = logging.getLogger(__name__)

    @classmethod
    def initialize(cls, config: Optional[SpanFilterConfig] = None) -> None:
        """
        Initialize OpenTelemetry with span filtering.

        Args:
            config: Optional configuration override. If None, loads from environment.

        This method is idempotent and thread-safe - safe to call multiple times.

        Raises:
            No exceptions raised - failures are logged and initialization continues
        """
        with cls._lock:
            if cls._initialized:
                cls._logger.debug("OtelInitializer already initialized")
                return

            try:
                # Load configuration
                config = config or SpanFilterConfig.from_environment()

                # Validate configuration
                validation_errors = config.validate()
                if validation_errors:
                    cls._logger.warning(
                        f"Span filter configuration has validation errors: "
                        f"{validation_errors}. Disabling span filtering."
                    )
                    cls._initialized = True
                    return

                if not config.enabled:
                    cls._logger.info("Span filtering disabled via configuration")
                    cls._initialized = True
                    return

                # Get the current tracer provider (set by opentelemetry-instrument)
                tracer_provider = trace.get_tracer_provider()

                if not isinstance(tracer_provider, TracerProvider):
                    cls._logger.warning(
                        "No TracerProvider found. "
                        "Span filtering requires opentelemetry-instrument. "
                        "Skipping initialization."
                    )
                    cls._initialized = True
                    return

                # Wrap existing span processors with filter
                cls._wrap_existing_processors(tracer_provider, config)

                cls._logger.info(
                    f"Span filtering initialized successfully. "
                    f"Patterns: {config.patterns}"
                )
                cls._initialized = True

            except Exception:
                cls._logger.exception(
                    "Failed to initialize span filtering. "
                    "Continuing without filtering to prevent app failure."
                )
                cls._initialized = True  # Mark as initialized to prevent retries

    @classmethod
    def _wrap_existing_processors(
        cls, tracer_provider: TracerProvider, config: SpanFilterConfig
    ) -> None:
        """
        Wrap existing span processors with SpanFilterProcessor.

        Uses reflection to access the internal _active_span_processor
        and wrap it with our filtering logic.

        Args:
            tracer_provider: The tracer provider to modify
            config: Filter configuration

        Raises:
            Logs warnings but does not raise exceptions
        """
        # Access internal span processor (implementation detail)
        if not hasattr(tracer_provider, "_active_span_processor"):
            cls._logger.warning(
                "TracerProvider missing _active_span_processor attribute. "
                "Span filtering may not work with this OTEL version."
            )
            return

        current_processor = tracer_provider._active_span_processor

        if current_processor is None:
            cls._logger.warning(
                "TracerProvider has no active span processor. Cannot apply filtering."
            )
            return

        # Create strategy and metrics
        strategy = PatternMatchingStrategy(config=config)
        metrics = SpanFilterMetrics()

        # Wrap with filter
        filtered_processor = SpanFilterProcessor(
            wrapped_processor=current_processor,
            strategy=strategy,
            config=config,
            metrics=metrics,
            logger=cls._logger,
        )

        # Replace the active processor
        # Type ignore: We're intentionally wrapping the processor with our filter
        tracer_provider._active_span_processor = filtered_processor  # type: ignore[assignment]

        cls._logger.debug(
            f"Wrapped existing processor {type(current_processor).__name__} "
            f"with SpanFilterProcessor"
        )

    @classmethod
    def reset(cls) -> None:
        """
        Reset initialization state.

        FOR TESTING ONLY - allows re-initialization in test scenarios.
        """
        with cls._lock:
            cls._initialized = False