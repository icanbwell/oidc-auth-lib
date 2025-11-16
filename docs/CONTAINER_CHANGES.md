# Container Updates - Request-Scoped Dependency Injection

## Summary of Changes

Added request-scoped dependency injection support for FastAPI applications. Services can now have three distinct lifetimes:

### Service Lifetimes

| Method | Lifetime | Behavior | Use Case |
|--------|----------|----------|----------|
| `.singleton()` | Application | One instance for entire app | Config, caches, shared state |
| `.scoped()` | Request | One instance per HTTP request | DB sessions, request context |
| `.transient()` | Call | New instance every time | Factories, commands |

## Key Changes

### 1. SimpleContainer
- Added `scoped()` method for request-scoped services
- Added `create_scope()` method to create child containers
- Added parent container support for inheritance
- Services now check: singleton cache → scoped cache → create new

### 2. ContainerRegistry
- Now uses `contextvars` for async-safe request isolation
- Added `set_scoped()` and `clear_scoped()` methods
- `get_current()` returns request container if available, otherwise default

### 3. New Middleware
- `ContainerScopeMiddleware` - FastAPI middleware that creates a scoped container per request
- Automatically sets up and tears down request containers

### 4. Updated Factory
- Changed `register()` calls to `scoped()` for:
  - `TokenReader`
  - `FastAPIAuthManager`
  - `AuthManager`
- These services are now properly request-scoped

## Usage

### Setup in FastAPI

```python
from fastapi import FastAPI
from oidcauthlib.container import (
    SimpleContainer,
    ContainerRegistry,
    ContainerScopeMiddleware,
)

# Create container and register services
container = SimpleContainer()
container.singleton(ConfigService, ...)
container.scoped(DatabaseSession, ...)
ContainerRegistry.set_default(container)

# Create app and add middleware
app = FastAPI()
app.add_middleware(ContainerScopeMiddleware)
```

### Use in Endpoints

```python
from fastapi import Depends
from oidcauthlib.container import Inject

@app.get("/users/{user_id}")
async def get_user(
    user_id: int,
    user_service: UserService = Depends(Inject(UserService)),
):
    # UserService is scoped - same instance throughout this request
    return await user_service.get_user(user_id)
```

## Implementation Details

### Scoped Container Hierarchy

```
DefaultContainer (singletons + registrations)
    ↓ create_scope()
RequestContainer1 (inherits registrations, own scoped instances)
    ↓ create_scope()
RequestContainer2 (inherits registrations, own scoped instances)
```

### Resolution Algorithm

1. Check global singleton cache → return if found
2. Check local scoped cache → return if found
3. Get factory (from this container or parent)
4. If singleton type → create, cache globally, return
5. If scoped type → create, cache locally, return
6. If transient → create and return (no caching)

### Thread Safety

- **Singletons**: Protected by `threading.Lock` with double-checked locking
- **Scoped**: Isolated per context using `contextvars.ContextVar`
- **Transient**: No synchronization needed

### Middleware Flow

```
Request arrives
  ↓
ContainerScopeMiddleware.dispatch()
  ↓
scoped_container = default.create_scope()
  ↓
ContainerRegistry.set_scoped(scoped_container)
  ↓
Handle request (all Inject() uses scoped_container)
  ↓
ContainerRegistry.clear_scoped()
  ↓
Response sent
```

## Breaking Changes

**None** - This is backward compatible:
- Existing `.singleton()` and `.transient()` work as before
- Existing `.register()` still works (now an alias for `.scoped()`)
- Without middleware, scoped services behave like singletons (existing behavior)

## Testing

New tests added:
- `test_scoped_same_container()` - Scoped services reuse within container
- `test_scoped_different_containers()` - Scoped services differ between containers
- `test_scoped_inherits_from_parent()` - Child containers inherit registrations
- `test_singleton_shared_across_scopes()` - Singletons shared everywhere
- `test_mixed_lifetimes()` - All three lifetimes work together
- Container registry tests with contextvars

## Files Changed

### Modified
- `oidcauthlib/container/simple_container.py` - Added scoped support
- `oidcauthlib/container/interfaces.py` - Added scoped methods to protocol
- `oidcauthlib/container/container_registry.py` - Added contextvar support
- `oidcauthlib/container/oidc_authlib_container_factory.py` - Changed to scoped
- `tests/container/test_simple_container.py` - Added scoped tests

### Created
- `oidcauthlib/container/fastapi_container_middleware.py` - New middleware
- `oidcauthlib/container/__init__.py` - Package exports
- `tests/container/test_container_registry.py` - Registry tests
- `docs/REQUEST_SCOPED_DI.md` - Comprehensive documentation

## Migration Guide

### Before
```python
# This created one instance and reused it everywhere
container.register(UserService, ...)
```

### After
```python
# Option 1: Explicit scoped (recommended)
container.scoped(UserService, ...)
app.add_middleware(ContainerScopeMiddleware)  # Required!

# Option 2: Keep using register (works with middleware)
container.register(UserService, ...)
app.add_middleware(ContainerScopeMiddleware)  # Required!
```

## Benefits

1. **Proper Request Isolation**: Each request gets its own instances
2. **Shared Request Context**: Dependencies within a request share instances
3. **Better Resource Management**: Request-scoped resources cleaned up automatically
4. **Framework Pattern**: Follows ASP.NET Core, Spring, NestJS patterns
5. **Thread Safe**: Uses contextvars for async safety
6. **Backward Compatible**: Existing code continues to work

## Performance

- **Singleton**: Same performance (cached lookup)
- **Scoped**: Small overhead per request (one container creation)
- **Transient**: Same performance (factory call)

The scoped container creation per request is negligible (~microseconds).

## Future Enhancements

Possible future additions:
- Async context manager support for cleanup
- Disposable service pattern
- Named scopes
- Scope validation (prevent singleton → scoped injection)

