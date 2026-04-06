from dataclasses import dataclass


@dataclass(frozen=True)
class AuthServerMetadata:
    """Parsed OAuth 2.0 Authorization Server Metadata (RFC 8414) or
    OpenID Connect Discovery metadata.

    Contains the subset of fields needed to configure an OAuth client:
    authorization and token endpoints (required), plus optional registration
    endpoint, issuer, and supported scopes.
    """

    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None = None
    issuer: str | None = None
    scopes_supported: list[str] | None = None
