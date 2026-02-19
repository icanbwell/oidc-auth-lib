import logging
import os
from typing import Set, Optional
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased
from oidcauthlib.open_telemetry.filtering_span_processor import FilteringSpanProcessor
from oidcauthlib.open_telemetry.filtering_sampler import FilteringSampler
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["OPEN_TELEMETRY"])


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


def get_excluded_span_prefixes() -> Set[str]:
    """
    Get excluded span name prefixes from environment.

    Environment variable: OTEL_EXCLUDED_SPAN_PREFIXES
    Format: Comma-separated list of span name prefixes to exclude
    Example: OTEL_EXCLUDED_SPAN_PREFIXES="mongo.,redis."
    """
    env_excluded = os.environ.get("OTEL_EXCLUDED_SPAN_PREFIXES", "")
    if env_excluded:
        custom_excluded = {
            prefix.strip() for prefix in env_excluded.split(",") if prefix.strip()
        }
        logger.info(
            "Using custom excluded span prefixes from environment: %s", custom_excluded
        )
        return custom_excluded

    return set()


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


def apply_sampler_filtering(
        excluded_span_names: Optional[Set[str]] = None,
        excluded_span_prefixes: Optional[Set[str]] = None,
) -> bool:
    """
    Apply sampler-based filtering to prevent spans from being created.

    This is the most effective way to filter spans as it prevents them
    from being created in the first place.

    Args:
        excluded_span_names: Set of exact span names to exclude
        excluded_span_prefixes: Set of span name prefixes to exclude

    Returns:
        True if filtering was successfully applied, False otherwise
    """
    try:
        tracer_provider = trace.get_tracer_provider()

        if not isinstance(tracer_provider, TracerProvider):
            logger.warning(
                "TracerProvider is not SDK TracerProvider (type: %s), cannot apply sampler filtering.",
                type(tracer_provider).__name__,
            )
            return False

        # Get current sampler
        current_sampler = getattr(tracer_provider, "sampler", None)
        if current_sampler is None:
            logger.warning("Could not get current sampler from TracerProvider")
            return False

        # Use provided values or get from environment
        if excluded_span_names is None:
            excluded_span_names = get_excluded_span_names()

        if excluded_span_prefixes is None:
            excluded_span_prefixes = get_excluded_span_prefixes()

        # Create filtering sampler that wraps the current sampler
        filtering_sampler = FilteringSampler(
            parent_sampler=current_sampler,
            excluded_span_names=excluded_span_names,
            excluded_span_prefixes=excluded_span_prefixes,
        )

        # Wrap it in ParentBased to respect parent sampling decisions
        parent_based_filtering_sampler = ParentBased(root=filtering_sampler)

        # Replace the sampler using __dict__ to avoid property issues
        tracer_provider.__dict__["sampler"] = parent_based_filtering_sampler

        logger.info(
            "✓ Applied sampler-based span filtering. Excluding span names: %s, prefixes: %s",
            excluded_span_names,
            excluded_span_prefixes,
        )
        return True

    except Exception as e:
        logger.exception("Failed to apply sampler filtering", exc_info=e)
        return False


def apply_processor_filtering(
        excluded_span_names: Optional[Set[str]] = None,
        excluded_span_prefixes: Optional[Set[str]] = None,
        min_duration_ms: Optional[float] = None,
        exclude_root_spans_from_duration_filter: Optional[bool] = None,
) -> bool:
    """
    Apply processor-based filtering to filter spans after creation.

    This is used for duration-based filtering which can only be done
    after a span completes.

    Args:
        excluded_span_names: Set of exact span names to exclude
        excluded_span_prefixes: Set of span name prefixes to exclude
        min_duration_ms: Minimum span duration in milliseconds
        exclude_root_spans_from_duration_filter: If True, root spans won't be filtered by duration

    Returns:
        True if filtering was successfully applied, False otherwise
    """
    try:
        tracer_provider = trace.get_tracer_provider()

        if not isinstance(tracer_provider, TracerProvider):
            logger.warning(
                "TracerProvider is not SDK TracerProvider (type: %s), cannot apply processor filtering.",
                type(tracer_provider).__name__,
            )
            return False

        # Use provided values or get from environment
        if excluded_span_names is None:
            excluded_span_names = get_excluded_span_names()

        if excluded_span_prefixes is None:
            excluded_span_prefixes = get_excluded_span_prefixes()

        if min_duration_ms is None:
            min_duration_ms = get_min_duration_ms()

        if exclude_root_spans_from_duration_filter is None:
            exclude_root_spans_from_duration_filter = (
                get_exclude_root_spans_from_duration_filter()
            )

        # Access the internal span processor using __dict__
        if "_active_span_processor" not in tracer_provider.__dict__:
            logger.warning("Could not find _active_span_processor on TracerProvider")
            return False

        existing_processor = tracer_provider.__dict__["_active_span_processor"]

        # Verify it's a SpanProcessor
        if not isinstance(existing_processor, SpanProcessor):
            logger.warning(
                "Existing processor is not a SpanProcessor (type: %s)",
                type(existing_processor).__name__,
            )
            return False

        # Wrap it with filtering
        filtering_processor = FilteringSpanProcessor(
            wrapped_processor=existing_processor,
            excluded_span_names=excluded_span_names,
            excluded_span_prefixes=excluded_span_prefixes,
            min_duration_ms=min_duration_ms,
            exclude_root_spans_from_duration_filter=exclude_root_spans_from_duration_filter,
        )

        # Replace the processor using __dict__
        tracer_provider.__dict__["_active_span_processor"] = filtering_processor

        filter_info = [f"Excluding span names: {excluded_span_names}"]
        if excluded_span_prefixes:
            filter_info.append(f"prefixes: {excluded_span_prefixes}")
        if min_duration_ms is not None:
            filter_info.append(f"min_duration: {min_duration_ms}ms")
            if exclude_root_spans_from_duration_filter:
                filter_info.append("(root spans exempt from duration filter)")

        logger.info(
            "✓ Applied processor-based span filtering. %s",
            ", ".join(filter_info),
        )
        return True

    except Exception as e:
        logger.exception("Failed to apply processor filtering", exc_info=e)
        return False


def apply_span_filtering(
        excluded_span_names: Optional[Set[str]] = None,
        excluded_span_prefixes: Optional[Set[str]] = None,
        min_duration_ms: Optional[float] = None,
        exclude_root_spans_from_duration_filter: Optional[bool] = None,
) -> bool:
    """
    Apply comprehensive span filtering using both sampler and processor approaches.

    The sampler filters spans by name at creation time (most effective).
    The processor filters spans by duration after completion (only way to do duration filtering).

    Args:
        excluded_span_names: Set of exact span names to exclude
        excluded_span_prefixes: Set of span name prefixes to exclude
        min_duration_ms: Minimum span duration in milliseconds
        exclude_root_spans_from_duration_filter: If True, root spans won't be filtered by duration

    Returns:
        True if at least one filtering method was successfully applied
    """
    sampler_applied = False
    processor_applied = False

    # Apply sampler-based filtering (filters by name at creation)
    logger.info("Applying sampler-based span filtering...")
    sampler_applied = apply_sampler_filtering(
        excluded_span_names=excluded_span_names,
        excluded_span_prefixes=excluded_span_prefixes,
    )

    # Apply processor-based filtering (filters by duration and name after completion)
    logger.info("Applying processor-based span filtering...")
    processor_applied = apply_processor_filtering(
        excluded_span_names=excluded_span_names,
        excluded_span_prefixes=excluded_span_prefixes,
        min_duration_ms=min_duration_ms,
        exclude_root_spans_from_duration_filter=exclude_root_spans_from_duration_filter,
    )

    if sampler_applied or processor_applied:
        logger.info("✓ Span filtering applied successfully")
        return True
    else:
        logger.warning("Span filtering could not be applied")
        return False