# Quick Reference: Request-Scoped DI

## Setup (One Time)

```python
from fastapi import FastAPI
from oidcauthlib.container import (
    SimpleContainer,
    ContainerRegistry,
    ContainerScopeMiddleware,
)

# 1. Create container
container = SimpleContainer()

# 2. Register services
container.singleton(ConfigService, lambda c: ConfigService())
container.scoped(DatabaseSession, lambda c: DatabaseSession())
container.transient(Logger, lambda c: Logger())

# 3. Set default
ContainerRegistry.set_default(container)

# 4. Add middleware to FastAPI
app = FastAPI()
app.add_middleware(ContainerScopeMiddleware)  # ⚠️ REQUIRED!
```

## Usage in Endpoints

```python
from fastapi import Depends
from oidcauthlib.container import Inject

@app.get("/users/{user_id}")
async def get_user(
    user_id: int,
    db: DatabaseSession = Depends(Inject(DatabaseSession)),
):
    # db is scoped - same instance throughout this request
    return db.get_user(user_id)
```

## Service Lifetimes

| Method | When Created | When Reused | Use For |
|--------|-------------|-------------|---------|
| `.singleton()` | Once (first use) | All requests | Config, caches |
| `.scoped()` | Once per request | Within request | DB sessions |
| `.transient()` | Every resolve | Never | Factories |

## Cheat Sheet

```python
# Application-wide (shared everywhere)
container.singleton(ConfigService, lambda c: ConfigService())

# Per-request (shared within request)
container.scoped(DatabaseSession, lambda c: DatabaseSession())

# Always new (never cached)
container.transient(Logger, lambda c: Logger())
```

## Migration

```python
# OLD (without middleware - all services behaved like singletons)
container.register(MyService, ...)

# NEW (with middleware - services are request-scoped)
container.scoped(MyService, ...)  # or keep using .register()
app.add_middleware(ContainerScopeMiddleware)  # Add this!
```

## Common Patterns

### Database Session
```python
container.scoped(
    AsyncSession,
    lambda c: AsyncSession(c.resolve(Database).engine)
)
```

### Repository
```python
container.scoped(
    UserRepository,
    lambda c: UserRepository(session=c.resolve(AsyncSession))
)
```

### Service Layer
```python
container.scoped(
    UserService,
    lambda c: UserService(repo=c.resolve(UserRepository))
)
```

### Configuration (Singleton)
```python
container.singleton(
    Settings,
    lambda c: Settings()
)
```

## Troubleshooting

### Problem: Services not scoped per request
```python
# ❌ Missing middleware
container.scoped(MyService, ...)
# Services behave like singletons

# ✅ Add middleware
app.add_middleware(ContainerScopeMiddleware)
```

### Problem: Different instance in same request
```python
# ❌ Registered as transient
container.transient(MyService, ...)
# New instance every time

# ✅ Use scoped
container.scoped(MyService, ...)
```

### Problem: Same instance across requests
```python
# ❌ Registered as singleton
container.singleton(MyService, ...)
# Shared across all requests

# ✅ Use scoped (and add middleware)
container.scoped(MyService, ...)
app.add_middleware(ContainerScopeMiddleware)
```

## Testing

```python
import pytest

@pytest.fixture
def container():
    c = SimpleContainer()
    SimpleContainer.clear_singletons()
    c.scoped(MyService, lambda c: MyService())
    return c

def test_scoped_service(container):
    # Simulate two requests
    request1 = container.create_scope()
    request2 = container.create_scope()
    
    s1 = request1.resolve(MyService)
    s2 = request2.resolve(MyService)
    
    assert s1 is not s2  # Different per request
```

## Files to Read

- **Usage Guide**: `docs/REQUEST_SCOPED_DI.md`
- **Technical Details**: `docs/CONTAINER_CHANGES.md`
- **Example App**: `examples/fastapi_scoped_di_example.py`

## That's It!

Just add the middleware and you're done:
```python
app.add_middleware(ContainerScopeMiddleware)
```

