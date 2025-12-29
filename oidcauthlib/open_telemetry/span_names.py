from __future__ import annotations


class OidcOpenTelemetrySpanNames:
    """
    Centralized span and event names for OpenTelemetry traces.

    Use dot-delimited, low-cardinality names. Dynamic values belong in attributes,
    not in the span/event name. For tool spans that inherently include a dynamic
    tool name, use the helper to construct the name consistently.
    """

    POPULATE_WELL_KNOWN_CONFIG_CACHE: str = "auth.oidc.well_known_config_cache.populate"

    READ_WELL_KNOWN_CONFIGURATION: str = "auth.oidc.well_known_config.read"
