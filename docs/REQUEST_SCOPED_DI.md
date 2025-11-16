# Request-Scoped Dependency Injection for FastAPI

This library now supports request-scoped dependency injection, perfect for FastAPI applications where you want:
- **Singletons**: Shared across the entire application (e.g., config, caches)
- **Scoped/Request-level**: One instance per HTTP request (e.g., database sessions, request context)
- **Transient**: New instance every time (e.g., factories, commands)

## Quick Start

### 1. Setup Your Container

```python
from fastapi import FastAPI, Depends
from oidcauthlib.container import (
    SimpleContainer,
    ContainerRegistry,
    Inject,
    ContainerScopeMiddleware,
)

# Create and configure your container
container = SimpleContainer()

# Register singletons (shared across entire app)
container.singleton(DatabaseConfig, lambda c: DatabaseConfig())
container.singleton(CacheService, lambda c: CacheService())

# Register scoped services (one per request)
container.scoped(DatabaseSession, lambda c: DatabaseSession(
    config=c.resolve(DatabaseConfig)
))
container.scoped(UserService, lambda c: UserService(
    db=c.resolve(DatabaseSession)
))

# Register transient services (new instance every time)
container.transient(RequestLogger, lambda c: RequestLogger())

# Set as default container
ContainerRegistry.set_default(container)

# Create FastAPI app
app = FastAPI()

# Add middleware to create scoped container per request
app.add_middleware(ContainerScopeMiddleware)
```

### 2. Use in Your Endpoints

```python
from fastapi import Depends

@app.get("/users/{user_id}")
async def get_user(
    user_id: int,
    user_service: UserService = Depends(Inject(UserService)),
):
    """
    UserService is scoped - the same instance will be used throughout
    this entire request, even if resolved multiple times.
    """
    user = await user_service.get_user(user_id)
    return user


@app.get("/data")
async def get_data(
    user_service: UserService = Depends(Inject(UserService)),
    cache: CacheService = Depends(Inject(CacheService)),
):
    """
    - cache is a singleton (same instance for all requests)
    - user_service is scoped (same instance within this request only)
    """
    if cached_data := cache.get("data"):
        return cached_data
    
    data = await user_service.fetch_data()
    cache.set("data", data)
    return data
```

## Service Lifetimes Explained

### Singleton (`.singleton()`)
```python
container.singleton(CacheService, lambda c: CacheService())
```
- **One instance for the entire application**
- Created once on first use
- Shared across all requests and all threads
- Thread-safe initialization with double-checked locking
- Use for: Configuration, caches, connection pools

### Scoped (`.scoped()`)
```python
container.scoped(DatabaseSession, lambda c: DatabaseSession())
```
- **One instance per container scope (typically per HTTP request)**
- Created once per request on first use
- Shared within the same request (even across multiple dependencies)
- Different instance for each request
- Use for: Database sessions, request context, user-specific data

### Transient (`.transient()`)
```python
container.transient(RequestLogger, lambda c: RequestLogger())
```
- **New instance every time it's resolved**
- Never cached
- Use for: Stateless services, factories, commands

### Register (`.register()`) - Alias for Scoped
```python
container.register(MyService, lambda c: MyService())
```
- **Alias for `.scoped()` - deprecated in favor of explicit `.scoped()`**
- Behaves exactly like scoped services

## How It Works

### Without Middleware (No Request Scope)
```python
# All services resolve from the default container
container = SimpleContainer()
container.singleton(ConfigService, ...)
container.scoped(UserService, ...)  # ⚠️ Behaves like singleton without middleware!
ContainerRegistry.set_default(container)

# UserService will be shared across ALL requests (not what you want!)
```

### With Middleware (Request Scoped)
```python
app.add_middleware(ContainerScopeMiddleware)  # ✅ Add this!

# For each request:
# 1. Middleware creates: scoped_container = default_container.create_scope()
# 2. Middleware sets: ContainerRegistry.set_scoped(scoped_container)
# 3. Your handlers use: Inject(UserService) → gets from scoped container
# 4. After response: ContainerRegistry.clear_scoped()
```

### Resolution Flow
```
Inject(UserService)
  ↓
ContainerRegistry.get_current()
  ↓
Is request container set? 
  ↓ YES                           ↓ NO
Request container               Default container
  ↓                                ↓
Is UserService a singleton? → YES → Return global singleton
  ↓ NO
Is UserService scoped?
  ↓ YES                           ↓ NO (transient)
Already in scope cache?         Create new instance
  ↓ YES        ↓ NO
Return cached  Create & cache → Return instance
```

## Real-World Example

```python
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from fastapi import FastAPI, Depends

# Models
class DatabaseConfig:
    def __init__(self):
        self.url = "postgresql+asyncpg://user:pass@localhost/db"

class Database:
    def __init__(self, config: DatabaseConfig):
        self.engine = create_async_engine(config.url)
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with AsyncSession(self.engine) as session:
            yield session

class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def get_user(self, user_id: int):
        # ... database query
        pass

class UserService:
    def __init__(self, repo: UserRepository):
        self.repo = repo
    
    async def get_user_profile(self, user_id: int):
        user = await self.repo.get_user(user_id)
        # ... business logic
        return user

# Setup
container = SimpleContainer()

# Singleton: Database config and engine (expensive to create)
container.singleton(DatabaseConfig, lambda c: DatabaseConfig())
container.singleton(Database, lambda c: Database(c.resolve(DatabaseConfig)))

# Scoped: Session and repositories (per-request)
async def create_session(c):
    db = c.resolve(Database)
    async with AsyncSession(db.engine) as session:
        return session

container.scoped(AsyncSession, create_session)
container.scoped(UserRepository, lambda c: UserRepository(c.resolve(AsyncSession)))
container.scoped(UserService, lambda c: UserService(c.resolve(UserRepository)))

ContainerRegistry.set_default(container)

app = FastAPI()
app.add_middleware(ContainerScopeMiddleware)

# Usage
@app.get("/users/{user_id}")
async def get_user(
    user_id: int,
    user_service: UserService = Depends(Inject(UserService)),
):
    """
    All dependencies in this request share the same AsyncSession:
    - UserService → UserRepository → AsyncSession (same instance)
    - No need to pass session around manually
    - Automatically cleaned up after request
    """
    return await user_service.get_user_profile(user_id)
```

## Testing

### Test with Isolated Scopes
```python
import pytest
from oidcauthlib.container import SimpleContainer

@pytest.fixture
def container():
    c = SimpleContainer()
    SimpleContainer.clear_singletons()
    # Register your services
    return c

def test_scoped_service_per_request(container):
    container.scoped(MyService, lambda c: MyService())
    
    # Simulate two requests
    request1_scope = container.create_scope()
    request2_scope = container.create_scope()
    
    service1 = request1_scope.resolve(MyService)
    service2 = request2_scope.resolve(MyService)
    
    assert service1 is not service2  # Different instances per request
```

## Migration Guide

If you were using `.register()` and expecting per-request instances:

### Before (Incorrect)
```python
container.register(UserService, ...)  # ❌ No middleware = singleton behavior
```

### After (Correct)
```python
# Option 1: Use .scoped() explicitly
container.scoped(UserService, ...)  # ✅ Clear intent

# Option 2: Use .register() with middleware
container.register(UserService, ...)  # ✅ Works if you add middleware
app.add_middleware(ContainerScopeMiddleware)  # ✅ Required!
```

## Best Practices

1. **Add Middleware Early**: Add `ContainerScopeMiddleware` before other middleware
2. **Use Appropriate Lifetimes**:
   - Singleton: Stateless services, configs, caches
   - Scoped: Database sessions, request context
   - Transient: Factories, commands, stateless operations
3. **Avoid Scope Issues**: Don't inject scoped services into singletons
4. **Test with Scopes**: Create test scopes with `container.create_scope()`

## Advanced: Custom Scopes

You can create custom scopes for non-HTTP scenarios:

```python
# Background job processing
def process_job(job_id: int):
    job_scope = default_container.create_scope()
    ContainerRegistry.set_scoped(job_scope)
    
    try:
        # Process job with scoped services
        service = job_scope.resolve(JobService)
        service.process(job_id)
    finally:
        ContainerRegistry.clear_scoped()
```

## Thread Safety

- **Singletons**: Thread-safe with double-checked locking
- **Scoped**: Thread-safe via `contextvars` (async-safe)
- **Transient**: No locking needed (always creates new)

The middleware uses Python's `contextvars` which is thread-safe and works correctly with async/await.

