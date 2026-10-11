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
- **Subject check:** the userinfo response's `sub` must equal the token's `sub` (OIDC Core 5.3.2); otherwise
  the lookup raises `ValueError` and nothing is cached.
- **Cache** key is `oidc-userinfo-scopes:<issuer>:<client_id>:<sub>|v1` with each segment percent-encoded
  (so values containing `:` cannot collide, and two providers never share an entry); only the
  userinfo-derived scopes are stored, never the userinfo response. The token's own scopes are re-derived on every call. A token without
  `sub` or without an issuer, or an empty scope list, is not cached. Changes to a user's entitlements are visible after at most
  `cache_ttl_seconds`.
- **Failures:** the cache never fails a lookup. A write failure is logged and swallowed; a read failure or a
  malformed entry is logged and treated as a miss, and the refetched scopes overwrite the bad entry. A
  userinfo HTTP error, a missing provider or a mismatched subject is raised, so each service decides whether
  to fail closed or degrade.
