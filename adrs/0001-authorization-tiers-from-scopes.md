# 0001. Administrator and tenant-reader tiers from OAuth scopes

- Status: proposed. The Tech Design Review is waived by Imran Qureshi because this package moves existing code into one shared place; no EA review was held. The scope convention it builds on is documented in the [FHIR server security guide](https://github.com/icanbwell/fhir-server/blob/main/readme/security.md), section 5.
- Ticket: BAI-1945

## Context and problem statement

Services that verify tokens with this library each carry their own copy of the logic that turns a caller's
merged scopes into an authorization tier. The copies drift, and the failure that matters is a denial that is
read as "all tenants". The scope convention itself (`access/<access code>.*` selects the tenants a caller may
see, a `patient/` scope marks a patient token, an administrator scope marks an operator) already exists in the
FHIR server and is documented in its security guide. What is missing is one tested implementation of the
decision.

## Decision drivers

- A denial must never be representable as unrestricted access.
- Misconfiguration (an unset or blank scope setting, a malformed client-key mapping) must fail at startup, not
  silently widen or narrow access in production.
- The library must keep control of token verification, user lookup and configuration out of this package, so
  the package stays reusable and testable.

## Considered options

1. Leave each service with its own copy.
2. A pure subpackage, `oidcauthlib.authorization`, with explicit inputs, no file or network I/O, no environment
   reads and no logging configuration of its own (it only calls the standard `logging` module) (chosen).
3. A class that reads settings from the environment and verifies tokens itself.

## Decision outcome

Option 2. `resolve_admin_access` takes scopes, the all-of administrator and reader scope requirements, a
`ClientSlugResolver` and `allow_all_tenants`, and returns an `AdminAccess` of `admin`, `reader` or denied.

- Order: a `patient/` scope denies first; then every administrator scope gives `admin`; then every reader scope
  plus an `access/<slug>.*` that selects a client gives `reader`; anything else is denied with a `DenialReason`.
- `allowed_client_keys` is `None` only for `admin`; a denied caller carries `frozenset()`. `AdminAccess` enforces
  this on construction.
- An empty requirement list, or one with a blank entry, admits nobody.
- `access/*.*` selects every client only when the caller sets `allow_all_tenants`.
- The `access/` prefix and `.*` suffix match exactly and case-sensitively, as the FHIR server's `access/` check does,
  so this package never grants more than the server would. Only the `patient/` deny is case-insensitive, because it
  can only deny. A slug matches a client name with ASCII letters lowercased and no other folding.
- Two client names that lowercase alike make their slug ambiguous: the slug selects nothing. The wildcard still
  covers those clients, because it means every client in the mapping.
- Two parsers read the client-key mapping. The lenient one keeps the behavior existing services rely on; the
  strict one is for `validate_reader_configuration`, which a service calls once at startup.

### Consequences

- Good: one implementation, with the tenant-isolation rules in tests.
- Good: the package imports nothing from the rest of `oidcauthlib` and performs no file or network I/O (tests enforce both; its only side effect is a standard `logging` warning with a slug or a count).
- Bad: safety depends on the service calling `validate_reader_configuration` at startup and building the
  resolver from the same raw setting. The package cannot enforce that.
- Bad: the lenient parser can still repair or drop malformed input for services that skip validation.
