import logging
import os
from typing import Set, Optional
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from oidcauthlib.open_telemetry.filtering_span_processor import FilteringSpanProcessor

logger = logging.getLogger(__name__)


def get_excluded_span_names() -> Set[str]:
    """
    Get excluded span names from environment or use defaults.

    Environment variable: OTEL_EXCLUDED_SPAN_NAMES
    Format: Comma-separated list of span names to exclude
    Example: OTEL_EXCLUDED_SPAN_NAMES="saslStart,saslContinue,isMaster,ping"
    """
    default_excluded = {"saslStart", "saslContinue", "isMaster", "ping"}

    env_excluded = os.environ.get("OTEL_EXCLUDED_SPAN_NAMES", "")
    if env_excluded:
        # Comma-separated list
        custom_excluded = {
            name.strip() for name in env_excluded.split(",") if name.strip()
        }
        logger.info(
            "Using custom excluded span names from environment: %s", custom_excluded
        )
        return custom_excluded

    return default_excluded


def get_min_duration_ms() -> Optional[float]:
    """
    Get minimum span duration from environment.

    Environment variable: OTEL_MIN_SPAN_DURATION_MS
    Format: Float value in milliseconds
    Example: OTEL_MIN_SPAN_DURATION_MS="1000" (1 second)

    Returns:
        Minimum duration in milliseconds, or None if not configured
    """
    env_value = os.environ.get("OTEL_MIN_SPAN_DURATION_MS", "")
    if env_value:
        try:
            min_duration = float(env_value)
            logger.info(
                "Using minimum span duration from environment: %.2fms", min_duration
            )
            return min_duration
        except ValueError:
            logger.warning(
                "Invalid OTEL_MIN_SPAN_DURATION_MS value: %s. Duration filtering disabled.",
                env_value,
            )
    return None


def get_exclude_root_spans_from_duration_filter() -> bool:
    """
    Get whether to exclude root spans from duration filtering.

    Environment variable: OTEL_EXCLUDE_ROOT_SPANS_FROM_DURATION_FILTER
    Format: "true" or "false" (case insensitive)
    Default: "true"

    Returns:
        True if root spans should be excluded from duration filtering
    """
    env_value = os.environ.get("OTEL_EXCLUDE_ROOT_SPANS_FROM_DURATION_FILTER", "true")
    return env_value.lower() in ("true", "1", "yes", "on")


def apply_span_filtering(
    excluded_span_names: Optional[Set[str]] = None,
    excluded_span_prefixes: Optional[Set[str]] = None,
    min_duration_ms: Optional[float] = None,
    exclude_root_spans_from_duration_filter: Optional[bool] = None,
) -> bool:
    """
    Apply span filtering to the existing tracer provider.

    This should be called after auto-instrumentation has been set up,
    typically in the application startup lifespan.

    Args:
        excluded_span_names: Set of exact span names to exclude.
                           If None, uses environment variable or defaults.
        excluded_span_prefixes: Set of span name prefixes to exclude
        min_duration_ms: Minimum span duration in milliseconds. Spans shorter than
                        this will be filtered out. If None, uses environment variable.
        exclude_root_spans_from_duration_filter: If True, root spans won't be filtered
                                                by duration. If None, uses environment variable.

    Returns:
        True if filtering was successfully applied, False otherwise
    """
    try:
        tracer_provider = trace.get_tracer_provider()

        if not isinstance(tracer_provider, TracerProvider):
            logger.warning(
                "TracerProvider is not SDK TracerProvider (type: %s), cannot apply filtering. "
                "This is expected if OpenTelemetry is not configured.",
                type(tracer_provider).__name__,
            )
            return False

        # Access the internal span processor
        if not hasattr(tracer_provider, "_active_span_processor"):
            logger.warning("Could not find _active_span_processor on TracerProvider")
            return False

        existing_processor = tracer_provider._active_span_processor

        # Use provided values or get from environment
        if excluded_span_names is None:
            excluded_span_names = get_excluded_span_names()

        if min_duration_ms is None:
            min_duration_ms = get_min_duration_ms()

        if exclude_root_spans_from_duration_filter is None:
            exclude_root_spans_from_duration_filter = (
                get_exclude_root_spans_from_duration_filter()
            )

        # Wrap it with filtering
        filtering_processor = FilteringSpanProcessor(
            wrapped_processor=existing_processor,
            excluded_span_names=excluded_span_names,
            excluded_span_prefixes=excluded_span_prefixes or set(),
            min_duration_ms=min_duration_ms,
            exclude_root_spans_from_duration_filter=exclude_root_spans_from_duration_filter,
        )

        # Replace the processor
        tracer_provider._active_span_processor = filtering_processor  # type: ignore[assignment]

        filter_info = [f"Excluding span names: {excluded_span_names}"]
        if min_duration_ms is not None:
            filter_info.append(f"min_duration: {min_duration_ms}ms")
            if exclude_root_spans_from_duration_filter:
                filter_info.append("(root spans exempt from duration filter)")

        logger.info(
            "✓ Applied span filtering to TracerProvider. %s", ", ".join(filter_info)
        )
        return True

    except Exception as e:
        logger.exception("Failed to apply span filtering", exc_info=e)
        return False
