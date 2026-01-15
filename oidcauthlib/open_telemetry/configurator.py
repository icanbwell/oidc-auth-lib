import logging
import os
from typing import Set
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.sampling import ParentBased
from oidcauthlib.open_telemetry.filtering_sampler import FilteringSampler

logger = logging.getLogger(__name__)


def get_excluded_span_names() -> Set[str]:
    """Get excluded span names from environment or use defaults."""
    default_excluded = {"saslStart", "saslContinue", "isMaster", "ping"}

    env_excluded = os.environ.get("OTEL_EXCLUDED_SPAN_NAMES", "")
    if env_excluded:
        custom_excluded = {
            name.strip() for name in env_excluded.split(",") if name.strip()
        }
        logger.info("Using custom excluded span names: %s", custom_excluded)
        return custom_excluded

    return default_excluded


def get_excluded_span_prefixes() -> Set[str]:
    """Get excluded span name prefixes from environment."""
    env_excluded = os.environ.get("OTEL_EXCLUDED_SPAN_PREFIXES", "")
    if env_excluded:
        custom_excluded = {
            prefix.strip() for prefix in env_excluded.split(",") if prefix.strip()
        }
        logger.info("Using custom excluded span prefixes: %s", custom_excluded)
        return custom_excluded

    return set()


def configure_opentelemetry(tracer_provider: TracerProvider) -> None:
    """
    Configure OpenTelemetry with span filtering.

    This is called by the auto-instrumentation configurator hook.
    """
    logger.info("Configuring OpenTelemetry with span filtering...")

    try:
        # Get current sampler
        current_sampler = getattr(tracer_provider, "sampler", None)
        if current_sampler is None:
            logger.warning("Could not get current sampler from TracerProvider")
            return

        # Get filtering configuration
        excluded_span_names = get_excluded_span_names()
        excluded_span_prefixes = get_excluded_span_prefixes()

        # Create filtering sampler that wraps the current sampler
        filtering_sampler = FilteringSampler(
            parent_sampler=current_sampler,
            excluded_span_names=excluded_span_names,
            excluded_span_prefixes=excluded_span_prefixes,
        )

        # Wrap it in ParentBased to respect parent sampling decisions
        parent_based_filtering_sampler = ParentBased(root=filtering_sampler)

        # Replace the sampler
        tracer_provider.__dict__["sampler"] = parent_based_filtering_sampler

        logger.info(
            "✓ Configured OpenTelemetry with span filtering. "
            "Excluding span names: %s, prefixes: %s",
            excluded_span_names,
            excluded_span_prefixes,
        )

    except Exception as e:
        logger.exception("Failed to configure OpenTelemetry span filtering", exc_info=e)