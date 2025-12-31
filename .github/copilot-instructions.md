# OIDC Auth Lib – Copilot Code Review Instructions

## Objectives
- Ensure changes align with this project's architecture for a reusable OAuth/OIDC authentication library and FastAPI middleware/components.
- Maintain strict type safety (mypy, full annotations), absolute imports, and pre-commit compliance (Ruff, formatting, security checks).
- Protect OAuth/OIDC flows and tokens; avoid secrets leakage and insecure handling.
- Keep Docker Compose-based dev/test/run workflows intact and documented.
- Provide clear, actionable, and prioritized feedback for contributors.

## Repository Context Summary
- Stack: Python 3.12, FastAPI integrations, Docker, Keycloak (OIDC), MongoDB.
- App structure (top-level packages under `oidcauthlib/`):
  - Auth system: `oidcauthlib/auth/` (multi-provider OIDC helpers, PKCE, managers, middleware, routers)
  - DI/IoC: `oidcauthlib/container/` (container, registration, injectors)
  - OpenTelemetry: `oidcauthlib/open_telemetry/` (span and attribute enums)
  - Storage: `oidcauthlib/storage/` (Mongo GridFS and storage factories; cache mapping)
  - Utilities: `oidcauthlib/utilities/` (cached helpers, environment, logger)
- Tests and fixtures: `tests/` with unit/integration suites.
- Docker Compose orchestrates local Keycloak and MongoDB for auth and storage.

## Code Style and Quality Rules
- Use absolute imports only:
  - Good: `from oidcauthlib.auth.auth_manager import AuthManager`
  - Bad: `from .auth_manager import AuthManager`
- Full type annotations for functions, variables, and class attributes; avoid `Any`.
- Comply with mypy (strict where applicable) and Ruff; run `make run-pre-commit` after changes.
- Follow DI pattern via `oidcauthlib/container`:
  - Use the container to resolve services (e.g., `container.resolve(ServiceClass)`).
  - Register services with correct lifecycle (`.singleton()` or `.transient()`).
- Logging follows `oidcauthlib/utilities/logger/` and `LOG_LEVEL` env configuration.
- OpenTelemetry conventions (blocking if violated):
  - Span names must use enums from `oidcauthlib/open_telemetry/span_names.py` (do not hardcode strings).
  - Attribute names must use enums from `oidcauthlib/open_telemetry/attribute_names.py` (do not hardcode strings).
  - Do not include tokens or other sensitive/PII in span attributes.

## Review Focus Areas
1. Security and Privacy (blocking if violated)
   - OAuth/OIDC correctness: well-known metadata, issuer/audience validation, scopes, caches.
   - No secrets in code (except permitted test creds with explicit allowlist pragmas where necessary).
   - Safe handling of tokens; no PII leaks in logs or error messages.
   - External network calls use HTTPS and appropriate certificate handling.
2. Architectural Consistency (blocking if violated)
   - Follows library layering and DI patterns; resolves services via container.
   - FastAPI middleware/routers use provided auth helpers and managers correctly.
   - Storage access goes through the storage factories and configured cache mechanisms.
3. Type Safety and Linting (blocking if violated)
   - Complete type hints; mypy strict passes.
   - Ruff/formatting/security pre-commit hooks pass.
4. Test Coverage and Reliability (blocking if violated)
   - Tests runnable via Docker Compose (`make tests`).
   - Adds/updates unit/integration tests for new behavior.
   - Avoids monkey patching; uses respx/aioresponses and IoC for mocking.
5. Performance and Resource Use (non-blocking unless severe)
   - Efficient token/storage handling; avoid unnecessary I/O.
   - Caching respects `OAUTH_CACHE` settings and avoids staleness.
6. Documentation and Developer Experience (non-blocking but recommended)
   - README/Docs updated for new workflows or env vars.
   - Clear usage instructions and examples for library consumers.

## Blocking Issues (Must Fix Before Merge)
- Missing or incorrect absolute imports.
- Incomplete type annotations; mypy errors; Ruff/lint/security failures.
- Bypassing DI container or improper service lifecycles.
- Auth flows deviating from env-driven multi-provider configuration.
- Tests not runnable via Docker Compose or missing for new public behavior.
- Secrets committed (tokens, passwords) or insecure token storage/usage.
- OpenTelemetry spans or attributes using hardcoded string names (must use enums).

## Non-Blocking Suggestions (Nice to Have)
- Refactor for clarity and maintainability without changing behavior.
- Improve logging granularity using project log levels where helpful.
- Add smoke tests or additional fixtures for edge cases.
- Performance tuning for storage and caching interactions.
- Small docs improvements and examples.

## Security and Privacy Guidelines
- Do not print tokens, PII, or sensitive payloads in logs.
- Validate JWTs and OIDC metadata from `AUTH_WELL_KNOWN_URI_<PROVIDER>`; enforce issuer/audience.
- Use HTTPS endpoints for external calls; manage certs via project scripts/Make targets.
- Respect `OAUTH_CACHE` selection (MongoDB vs memory) and expiry semantics.
- Service accounts should use appropriate manager APIs (e.g., `AuthManager.get_service_account_token_async()`) and correct scopes.

## Performance Guidelines
- Avoid oversized payloads and unnecessary network calls.
- Optimize storage access; fetch only required data.
- Cache appropriately while avoiding staleness and auth scope violations.

## Testing Guidelines
- Always run tests through Docker Compose:
  - `make tests` for full suite.
  - Use documented compose commands for targeted test files.
- Add tests for new auth flows, storage behavior, and DI wiring.
- Use respx/aioresponses for HTTP mocking; inject via IoC; avoid monkey patching.

## Dependencies and Build
- Keep `Pipfile`/`Pipfile.lock` consistent; use `make update` when changing Python deps.
- Build and run via Docker and Make targets.

## Documentation and Examples
- Update `README.md` and `docs/` when changing data flow, auth, or storage.
- Include short usage examples for new public APIs in docstrings and docs.
- Clarify environment variables in `docker-compose.yml` and docs.

## Tone and Feedback Style
- Be direct, constructive, and specific.
- Separate blocking issues from suggestions.
- Provide minimal, concrete examples of fixes (paths, functions, commands) without large code dumps.

## Decision Authority and Constraints
- Absolute imports, strict typing, DI usage, and Docker-based testing are non-negotiable.
- Healthcare/identity data protection is paramount; err on the side of caution.
- If unsure, prefer small, well-tested changes and add tests.

## Quick Start and Common Commands
- Initial setup:
  - Create `docker.env` from `docker.env.example`.
  - Configure local OIDC provider (e.g., Keycloak) and MongoDB via Docker Compose.
  - Run `make devsetup` if provided, otherwise follow README setup steps.
- Running:
  - `make up` to start local stack (if applicable).
  - Verify auth flows using provided FastAPI routes/middleware examples.
- Maintenance:
  - `make build`, `make clean`, `make shell`, `make update`.
- Troubleshooting:
  - Cert issues → use project scripts/targets; check container health/logs; ensure DNS entries.

## Integration Points
- FastAPI integration via middleware, routers, and `AuthManager` for OAuth/OIDC flows.
- Service accounts via `AuthManager.get_service_account_token_async()`.

## Enforcement Checklist for Reviewers
- Imports: absolute only.
- Types: complete annotations; mypy strict green.
- Lint: Ruff + formatting + security pre-commit pass.
- DI: container used correctly; services registered as intended.
- Auth: env-driven multi-provider config; no token/PII leaks.
- Tests: Docker Compose runs; new features have coverage.
- Docs: updated for behavior changes.
- OpenTelemetry: spans and attributes use enum names; no hardcoded strings.
