"""Configuration model for OpenTelemetry span filtering.

This module provides immutable configuration for span filtering behavior,
loaded from environment variables with validation.
"""

import os
from dataclasses import dataclass
from typing import ClassVar

# Environment variable names
ENV_VAR_ENABLED: str = "OTEL_SPAN_FILTER_ENABLED"
ENV_VAR_PATTERNS: str = "OTEL_SPAN_FILTER_PATTERNS"
ENV_VAR_DEBUG: str = "OTEL_SPAN_FILTER_DEBUG"

# Boolean parsing
_TRUTHY_VALUES: frozenset[str] = frozenset(("true", "1", "yes", "on"))


def _parse_bool(value: str) -> bool:
    """
    Parse boolean value from string.

    Args:
        value: String value to parse

    Returns:
        True if value is in truthy set (case-insensitive), False otherwise
    """
    return value.lower() in _TRUTHY_VALUES


@dataclass(frozen=True)
class SpanFilterConfig:
    """
    Immutable configuration for span filtering behavior.

    Loaded from environment variables with sensible defaults.
    """

    enabled: bool
    patterns: list[str]
    debug_logging: bool

    # Default values
    DEFAULT_ENABLED: ClassVar[bool] = True
    DEFAULT_PATTERNS: ClassVar[list[str]] = ["saslStart", "saslContinue"]
    DEFAULT_DEBUG_LOGGING: ClassVar[bool] = False

    @classmethod
    def from_environment(cls) -> "SpanFilterConfig":
        """
        Load configuration from environment variables.

        Returns:
            Immutable configuration instance

        Environment Variables:
            OTEL_SPAN_FILTER_ENABLED: Enable/disable filtering
            OTEL_SPAN_FILTER_PATTERNS: Comma-separated patterns
            OTEL_SPAN_FILTER_DEBUG: Enable debug logging
        """
        # Parse enabled flag
        enabled_str = os.environ.get(ENV_VAR_ENABLED, str(cls.DEFAULT_ENABLED))
        enabled = _parse_bool(enabled_str)

        # Parse patterns
        patterns_str = os.environ.get(ENV_VAR_PATTERNS, ",".join(cls.DEFAULT_PATTERNS))
        patterns = [p.strip() for p in patterns_str.split(",") if p.strip()]

        # Parse debug logging
        debug_str = os.environ.get(ENV_VAR_DEBUG, str(cls.DEFAULT_DEBUG_LOGGING))
        debug_logging = _parse_bool(debug_str)

        return cls(
            enabled=enabled,
            patterns=patterns,
            debug_logging=debug_logging,
        )

    def validate(self) -> list[str]:
        """
        Validate configuration and return list of validation errors.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors: list[str] = []

        if self.enabled and not self.patterns:
            errors.append(f"{ENV_VAR_ENABLED} is true but {ENV_VAR_PATTERNS} is empty")

        return errors