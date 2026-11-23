# oidcauthlib

## OIDC userinfo scopes (`OidcUserInfoManager`)

Some providers (e.g. Okta employee access tokens) only carry `openid profile email groups` in the JWT;
the scopes that authorize a caller appear only on the OIDC userinfo response.
`oidcauthlib.auth.userinfo.oidc_userinfo_manager.OidcUserInfoManager` resolves a token's effective
scopes from the token's own claims plus the userinfo endpoint, and caches the userinfo-derived scopes in
a key-value store.

```python
manager = OidcUserInfoManager(
    auth_config_reader=auth_config_reader,
    well_known_configuration_manager=well_known_configuration_manager,
    store=store,                      # py-key-value-aio store; yours, not shared with other services
    cache_collection="oidc-user-info-cache",
    cache_ttl_seconds=86400,
    fetch_timeout_seconds=30,
    scope_claims=["custom:scope"],    # optional extra claims holding scopes
    group_claims=["groups"],          # optional claims holding group names, used whole as scopes
    scope_remove_prefixes=["fhir/prod/"],
)
scopes = await manager.get_scopes_from_user_info_async(access_token=token)
```

- **Scope derivation** follows fhir-server-ui's `jwtParser`: the `scope` claim (plus `scp`), then
  `scope_claims`, then `group_claims` (each value taken whole). Commas separate like spaces, results are
  de-duplicated, and `scope_remove_prefixes` are stripped (first match wins). Nothing beyond `scope`/`scp`
  is read unless configured.
- **Provider** is matched to the token's `iss`: an exact `issuer`, else a `well_known_uri` on the same scheme,
  host and port whose path segments start with the issuer's. Only a token with no `iss` at all is matched by
  its client id. A token matching no provider raises `ValueError`; it is never sent to another provider.
- **Subject check:** for a token that has a `sub`, the userinfo response must carry the same `sub`
  (OIDC Core 5.3.2); a missing or different one raises `ValueError` and nothing is cached.
- **Cache** key is `oidc-userinfo-scopes:<issuer>:<client_id>:<sub>|v1` with each segment percent-encoded
  (so values containing `:` cannot collide, and two providers never share an entry); only the
  userinfo-derived scopes are stored, never the userinfo response. The token's own scopes are re-derived on every call. A token without
  `sub` or without an issuer, or an empty scope list, is not cached. Changes to a user's entitlements are visible after at most
  `cache_ttl_seconds`.
- **Failures:** the cache never fails a lookup. A write failure is logged and swallowed; a read failure or a
  malformed entry is logged and treated as a miss, and the refetched scopes overwrite the bad entry. A
  userinfo HTTP error, a missing provider or a mismatched subject is raised, so each service decides whether
  to fail closed or degrade.

## Administrator and tenant-reader tiers (`oidcauthlib.authorization`)

Pure helpers that turn a caller's merged scopes (for example the result of `OidcUserInfoManager`) into a
tier: `admin` (unrestricted), `reader` (limited to the client keys its `access/<slug>.*` scopes select), or
denied. The subpackage reads no environment variable, does no file or network I/O (its only side effect is a standard `logging` warning with a slug or a count) and imports nothing else from
`oidcauthlib`; the caller verifies the token, looks up the user and passes the configuration in. The
`access/<slug>.*` and `patient/` scope convention is the FHIR server's, described in its
[security guide](https://github.com/icanbwell/fhir-server/blob/main/readme/security.md) (section 5); the tier
model is recorded in [ADR 0001](adrs/0001-authorization-tiers-from-scopes.md).

```python
from oidcauthlib.authorization import (
    ClientSlugResolver,
    parse_client_keys_lenient,
    resolve_admin_access,
    validate_reader_configuration,
)

RAW_CLIENTS = "One=key-1,Two=key-2"  # the setting that holds the client-key mapping

# At startup: refuse an unsafe configuration (a no-op when no reader scopes are set).
validate_reader_configuration(
    reader_scopes=["example/reader"],
    admin_scopes=["example/admin"],
    client_keys_raw=RAW_CLIENTS,
)

clients = ClientSlugResolver.from_client_keys(clients=parse_client_keys_lenient(raw=RAW_CLIENTS))
access = resolve_admin_access(
    scopes=["example/reader", "access/one.*"],
    admin_scopes=["example/admin"],
    reader_scopes=["example/reader"],
    clients=clients,
    allow_all_tenants=False,
)
# access.tier is AdminTier.READER and access.allowed_client_keys == frozenset({"key-1"})
```

- **Order:** any `patient/` scope (trimmed, case-insensitive) denies first; then holding every admin scope
  gives `admin`; then every reader scope plus at least one `access/<slug>.*` that selects a client gives
  `reader`; anything else is denied with a `DenialReason`. An empty admin or reader requirement admits nobody.
- **Slugs:** `access/<slug>.*` selects the client whose name, stripped and with ASCII letters lowercased,
  equals the slug treated the same way; other characters are never folded. Two names that lowercase alike
  make the slug ambiguous and it selects nothing. The `access/` prefix and the `.*` suffix match exactly and
  case-sensitively, like the FHIR server's own check, so `Access/Tenant.*` selects nothing. The `patient/` deny
  is case-insensitive because it can only deny.
  `access/*.*` selects every client only when `allow_all_tenants=True`, including a client whose own slug is
  ambiguous. An ambiguous slug is logged by slug only, through the standard `logging` module (the package
  configures no logger of its own).
- **Blank scopes:** an admin or reader scope list that is empty, or has a blank entry, admits nobody, and
  `validate_reader_configuration` refuses a blank or padded entry in either list.
- **Auditing:** the all-tenants grant logs one info line with the client count, never a slug or key. The package
  records no tier or other decision; consuming services record the tier and `allow_all_tenants` for each decision.
- **No default for "all tenants":** `allowed_client_keys` is `None` only for `admin`. A reader always has a
  non-empty set and a denied caller always has `frozenset()`, so a denial can never be read as unrestricted.
  `AdminAccess` enforces this when it is constructed.
- **Client-key mapping:** a `name -> key` map given as a JSON object or `One=key-1,Two=key-2`.
  `parse_client_keys_lenient` keeps the permissive behavior (a malformed JSON object falls back to comma
  parsing, an entry without `=` is dropped); `parse_client_keys_strict` refuses both, and refuses blank or
  repeated names (two names may share one key, an alias). The lenient parser logs the JSON fallback and the number of dropped entries once each. Error messages name the rule, never a name or key.
- **Eligibility:** `from_client_keys(..., is_eligible=...)` takes a `(name, key) -> bool` strategy for
  callers that exclude some clients; an excluded client is in no view and takes no part in ambiguity.
