# MCP FHIR Agent – Copilot Code Review Instructions

## Objectives
- Ensure all changes align with this project’s architecture and workflows for a Model Context Protocol (MCP) FastAPI agent exposing FHIR data via FastMCP tools.
- Maintain strict type safety (mypy --strict), absolute imports, and pre-commit compliance (Ruff, formatting, security checks).
- Protect OAuth/OIDC flows, tokens, and healthcare data. Avoid secrets leakage and insecure handling.
- Keep Docker Compose-based dev/test/run workflows intact and documented.
- Provide clear, actionable, and prioritized feedback for contributors.

## Repository Context Summary
- Stack: Python 3.12, FastAPI, FastMCP, Docker, Keycloak (OIDC), MongoDB, PostgreSQL.
- App structure:
  - FastAPI wrapper: `mcpfhiragent/api.py`, `api_creator.py` (auth middleware, HTTP entry)
  - FastMCP server: `mcpfhiragent/mcp_servers/fhir_server/fhir_server.py` mounted as sub-app
  - Auth system: `mcpfhiragent/auth/` (multi-provider OIDC, PKCE, dynamic client registration)
  - DI: `mcpfhiragent/container/simple_container.py` (IoC pattern; use `api_container.get_container()`)
- FHIR data via GraphQL queries: `mcpfhiragent/fhir/query.gql`
- Responses formatted for LLMs using `fhir_to_llm` (private GitHub dependency)
- Tests and fixtures: `tests/`, `tests_integration/`, `load_data/fixtures/`
- Docker Compose orchestrates local Keycloak, FHIR server, MCP agent.

## Code Style and Quality Rules
- Use absolute imports only (mandatory across repo):
  - Good: `from mcpfhiragent.fhir.unstructured.fhir_attachment import FhirAttachment`
  - Bad: `from .fhir_attachment import FhirAttachment`
- Full type annotations for all functions, variables, class attributes; avoid `Any`.
- Comply with mypy strict and Ruff; run `make run-pre-commit` after changes.
- Follow DI pattern via `mcpfhiragent/api_container.py`:
  - Use `get_container()` and `container.resolve(ServiceClass)`
  - Register services as `.singleton()` or `.transient()` appropriately.
- FastMCP tool definition pattern in `mcpfhiragent/mcp_servers/fhir_server/mcp_server.py`:
  - Use `@mcp.tool()` with `Context`, `Depends(get_access_token)`, and clear `Field` descriptions.
  - Provide comprehensive docstrings that explain purpose, usage, and outputs.
- Logging: configure via `mcpfhiragent/utilities/logger/log_levels.py` and `LOG_LEVEL` env.
- OpenTelemetry conventions (blocking if violated):
  - Span names must use the `OpenTelemetrySpanNames` enum; do not hardcode string literals for span names.
  - Attribute names on spans must use the `OpenTelemetryAttributeNames` enum; do not hardcode string literals for attributes.
  - Keep consistent absolute imports when referencing these enums (e.g., `from mcpfhiragent.utilities.opentelemetry.span_names import OpenTelemetrySpanNames`).
  - Ensure spans and attributes avoid PII; never include tokens or sensitive data in span attributes.

## Review Focus Areas
When reviewing PRs, prioritize the following in order:
1. Security and Privacy (blocking if violated)
   - OAuth/OIDC correctness, token handling, scopes, caches.
   - No secrets in code (except permitted test creds marked with pragma allowlist when necessary).
   - Safe handling of healthcare data; no PII leaks in logs or errors.
   - Network calls: verify TLS/HTTPS endpoints and certificate usage where required.
2. Architectural Consistency (blocking if violated)
   - Follows FastAPI + FastMCP layering and DI patterns.
   - Tools are defined in the correct MCP server module and use token dependency.
   - FHIR access goes through `FhirDataLoader` and GraphQL queries in `query.gql`.
3. Type Safety and Linting (blocking if violated)
   - Complete type hints, no `Any`, strict mypy passes.
   - Ruff/formatting/security pre-commit hooks pass.
4. Test Coverage and Reliability (blocking if violated)
   - Uses Docker Compose test harness (`make tests`).
   - Adds or updates unit/integration tests for new behavior.
   - Avoids monkey patching; uses respx/aioresponses and IoC for mocking.
5. Performance and Resource Use (non-blocking unless severe)
   - Token budget awareness with `fhir_to_llm`.
   - Efficient GraphQL queries; avoid N+1 or over-fetching.
   - Caching respects `OAUTH_CACHE` and avoids stale/incorrect tokens.
6. Documentation and Developer Experience (non-blocking but recommended)
   - README/Docs updated for new workflows or env vars.
   - Clear usage instructions and examples.

## Blocking Issues (Must Fix Before Merge)
- Missing or incorrect absolute imports.
- Incomplete type annotations; mypy errors; Ruff/lint/security failures.
- Bypassing DI container for service resolution or improper service lifecycles.
- MCP tools lacking docstrings or missing `Depends(get_access_token)`.
- Auth flows deviating from configured multi-provider environment variable scheme.
- Tests not runnable via Docker Compose or missing for new public behavior.
- Secrets committed (tokens, passwords) or insecure token storage/usage.
- OpenTelemetry spans or attributes using hardcoded string names (must use enums).

## Non-Blocking Suggestions (Nice to Have)
- Refactor for clarity and maintainability without changing behavior.
- Improve logging granularity using `SRC_LOG_LEVELS` where helpful.
- Add smoke tests or additional fixtures for edge cases.
- Performance tuning of GraphQL queries and response shaping.
- Small docs improvements and examples.

## Security and Privacy Guidelines
- Do not print tokens, PII, or sensitive payloads in logs.
- Validate JWTs and OIDC metadata from `AUTH_WELL_KNOWN_URI_<PROVIDER>`; enforce issuer/audience.
- Use HTTPS endpoints for external calls; manage certs via `make create-certs` when needed.
- Respect `OAUTH_CACHE` selection (MongoDB vs memory) and expiry semantics.
- Service accounts should use `AuthManager.get_service_account_token_async()` and correct scopes.

## Performance Guidelines
- Use `fhir_to_llm` with token budget awareness; avoid oversized responses.
- Optimize GraphQL queries in `query.gql`; fetch only required fields.
- Cache appropriately while avoiding staleness and auth scope violations.

## Testing Guidelines
- Always run tests through Docker Compose:
  - `make tests` for full suite.
  - Use the documented compose command for targeted test files.
- Add tests for new MCP tools, auth flows, and FHIR queries.
- Use `tests/utilities/mcp_test_client.py` for MCP protocol testing.
- Use respx/aioresponses for HTTP mocking; inject via IoC; avoid monkey patching.

## Dependencies and Build
- Private package `fhir_to_llm` requires GitHub CLI auth: `gh auth login` and unset stale `GITHUB_TOKEN`.
- Build via Docker and make targets; ECR login required for related images.
- Keep `Pipfile`/`Pipfile.lock` consistent; use `make update` when changing Python deps.

## Documentation and Examples
- Update `docs/` when changing data flow, auth, or MCP tooling.
- Include short usage examples for new tools in docstrings and docs.
- Clarify environment variables in `docker-compose.yml` and docs.

## Tone and Feedback Style
- Be direct, constructive, and specific.
- Separate blocking issues from suggestions.
- Provide minimal, concrete examples of fixes (paths, functions, commands) without large code dumps.

## Decision Authority and Constraints
- Absolute imports, strict typing, DI usage, and Docker-based testing are non-negotiable.
- Healthcare data protection is paramount; err on the side of caution.
- If unsure, prefer small, well-tested changes and add tests.

## Quick Start and Common Commands
- Initial setup:
  - Authenticate GitHub CLI and unset stale `GITHUB_TOKEN`.
  - Create `docker.env` from `docker.env.example`.
  - Login to ECR and run `make devsetup`.
- Running:
  - `make up` for standard dev stack; visit `https://mcpfhiragent.localhost/test_auth`.
  - For OpenWebUI auth flow, add `/etc/hosts` entry for `keycloak` and use `make up-open-webui-auth`.
- Maintenance:
  - `make build`, `make clean`, `make shell`, `make update`, `make load-data`.
- Troubleshooting:
  - Cert issues → `make create-certs`; check container health/logs; ensure DNS entries.

## Integration Points
- MCP client integration:
  - OpenAI Responses API via `server_url` and `authorization` header.
  - Anthropic via `beta.tools.messages.create()` with `type: "url"`.
  - Plain HTTP: `GET /tools` to list; `POST /<ResourceType>` to execute.
- OAuth flows:
  - Browser via `/auth_test/login` (PKCE).
  - Service accounts via `AuthManager.get_service_account_token_async()`.

## Enforcement Checklist for Reviewers
- Imports: absolute only.
- Types: complete annotations; mypy strict green.
- Lint: Ruff + formatting + security pre-commit pass.
- DI: container used correctly; services registered as intended.
- MCP tools: proper decorators, dependencies, docstrings.
- Auth: env-driven multi-provider config; no token/PII leaks.
- Tests: Docker Compose runs; new features have coverage.
- Docs: updated for behavior changes.
- OpenTelemetry: spans and attributes use enum names; no hardcoded strings.
