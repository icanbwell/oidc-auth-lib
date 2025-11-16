# Visual Guide: Before vs After

## The Problem (Before)

Without request-scoped containers, all services registered with `.register()` behaved like singletons:

```
┌─────────────────────────────────────────────────────────┐
│                   Default Container                      │
│  - TokenReader: Instance A (created once)               │
│  - FastAPIAuthManager: Instance X (created once)        │
│  - AuthManager: Instance Z (created once)               │
└─────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   Request 1            Request 2           Request 3
   Uses: A, X, Z        Uses: A, X, Z       Uses: A, X, Z
   
❌ PROBLEM: All requests share the same instances!
```

## The Solution (After)

With `ContainerScopeMiddleware`, each request gets its own scoped container:

```
┌─────────────────────────────────────────────────────────┐
│              Default Container (Parent)                  │
│  Singletons (shared):                                   │
│  - EnvironmentVariables                                 │
│  - AuthConfigReader                                     │
│  - WellKnownConfigurationCache                          │
│                                                         │
│  Templates (scoped):                                    │
│  - TokenReader ← factory                                │
│  - FastAPIAuthManager ← factory                         │
│  - AuthManager ← factory                                │
└─────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Request 1   │    │  Request 2   │    │  Request 3   │
│  Scope 1     │    │  Scope 2     │    │  Scope 3     │
├──────────────┤    ├──────────────┤    ├──────────────┤
│ TokenReader  │    │ TokenReader  │    │ TokenReader  │
│ Instance A   │    │ Instance B   │    │ Instance C   │
│              │    │              │    │              │
│ AuthManager  │    │ AuthManager  │    │ AuthManager  │
│ Instance X   │    │ Instance Y   │    │ Instance Z   │
└──────────────┘    └──────────────┘    └──────────────┘

✅ SOLUTION: Each request has its own instances!
```

## Within a Single Request

Services are cached within the same request scope:

```
Request 1 - Scope 1
│
├─ Endpoint handler
│   └─ Inject(TokenReader) → Creates Instance A
│
├─ Dependency 1
│   └─ Inject(TokenReader) → Returns Instance A (cached)
│
├─ Dependency 2
│   └─ Inject(FastAPIAuthManager) → Creates Instance X
│       └─ Inject(TokenReader) → Returns Instance A (cached)
│
└─ Dependency 3
    └─ Inject(TokenReader) → Returns Instance A (cached)

✅ Efficient: Same instance reused within request
```

## Middleware Flow

```
HTTP Request arrives
        │
        ▼
┌─────────────────────────────────────┐
│  ContainerScopeMiddleware           │
│                                     │
│  1. Get default container           │
│  2. Create child scope:             │
│     scoped = default.create_scope() │
│  3. Set in registry:                │
│     ContainerRegistry.set_scoped()  │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│  Your Endpoint Handler              │
│                                     │
│  auth = Inject(FastAPIAuthManager)  │
│    ↓                                │
│  ContainerRegistry.get_current()    │
│    ↓                                │
│  Returns scoped container           │
│    ↓                                │
│  Resolves from scoped container     │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│  Response Sent                      │
│                                     │
│  Cleanup:                           │
│  ContainerRegistry.clear_scoped()   │
│                                     │
│  Scoped container disposed          │
└─────────────────────────────────────┘
```

## Resolution Logic

```
When you call: Inject(TokenReader)
                      │
                      ▼
        ContainerRegistry.get_current()
                      │
          ┌───────────┴───────────┐
          │                       │
    Scoped container set?    No scoped container
          │                       │
         YES                      ▼
          │              Return default container
          ▼
    Return scoped container
          │
          ▼
    scoped_container.resolve(TokenReader)
          │
          ▼
    Is TokenReader a singleton?
          │
         NO (it's scoped)
          │
          ▼
    Already in scoped cache?
          │
     ┌────┴────┐
    YES       NO
     │         │
     │         ▼
     │    Create new instance
     │    Cache in scoped container
     │         │
     └────┬────┘
          │
          ▼
    Return instance
```

## Service Lifetime Comparison

```
┌──────────────────────────────────────────────────────────┐
│                    SINGLETON                             │
├──────────────────────────────────────────────────────────┤
│  Container.singleton(ConfigService, ...)                 │
│                                                          │
│  Request 1 ──┐                                          │
│  Request 2 ──┼──→ [Instance A] ← Created once           │
│  Request 3 ──┘                                          │
│                                                          │
│  ✓ Shared across ALL requests                           │
│  ✓ Created once on first use                            │
│  ✓ Thread-safe initialization                           │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│                      SCOPED                              │
├──────────────────────────────────────────────────────────┤
│  Container.scoped(DatabaseSession, ...)                  │
│                                                          │
│  Request 1 ──→ [Instance A] ← Created for request 1     │
│  Request 2 ──→ [Instance B] ← Created for request 2     │
│  Request 3 ──→ [Instance C] ← Created for request 3     │
│                                                          │
│  ✓ One instance PER REQUEST                             │
│  ✓ Shared WITHIN request                                │
│  ✓ Cleaned up after request                             │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│                    TRANSIENT                             │
├──────────────────────────────────────────────────────────┤
│  Container.transient(Logger, ...)                        │
│                                                          │
│  Call 1 ──→ [Instance A]                                │
│  Call 2 ──→ [Instance B]                                │
│  Call 3 ──→ [Instance C]                                │
│                                                          │
│  ✓ New instance EVERY TIME                              │
│  ✓ Never cached                                         │
│  ✓ No sharing                                           │
└──────────────────────────────────────────────────────────┘
```

## Code Example: The Difference

### Without Middleware (Broken)
```python
app = FastAPI()
# ❌ Missing middleware!

container = SimpleContainer()
container.scoped(TokenReader, ...)
ContainerRegistry.set_default(container)

@app.get("/endpoint1")
def endpoint1(token: TokenReader = Depends(Inject(TokenReader))):
    print(id(token))  # 140234567890

@app.get("/endpoint2")
def endpoint2(token: TokenReader = Depends(Inject(TokenReader))):
    print(id(token))  # 140234567890 ← SAME ID!
    
# ❌ Both requests use the same instance!
```

### With Middleware (Fixed)
```python
app = FastAPI()
app.add_middleware(ContainerScopeMiddleware)  # ✅ Added!

container = SimpleContainer()
container.scoped(TokenReader, ...)
ContainerRegistry.set_default(container)

@app.get("/endpoint1")
def endpoint1(token: TokenReader = Depends(Inject(TokenReader))):
    print(id(token))  # 140234567890

@app.get("/endpoint2")
def endpoint2(token: TokenReader = Depends(Inject(TokenReader))):
    print(id(token))  # 140298765432 ← DIFFERENT ID!
    
# ✅ Each request gets its own instance!
```

## Memory and Lifecycle

```
Application Startup
    │
    ▼
┌──────────────────────────────────────┐
│  Default Container Created           │
│  • Registers all services            │
│  • No instances created yet          │
└──────────────────────────────────────┘
    │
    ▼
Request 1 arrives
    │
    ▼
┌──────────────────────────────────────┐
│  Scoped Container 1 Created          │
│  • Inherits registrations            │
│  • Creates TokenReader A             │
│  • Creates AuthManager X             │
│  • Caches in scope                   │
└──────────────────────────────────────┘
    │
    ▼
Request 1 completes
    │
    ▼
┌──────────────────────────────────────┐
│  Scoped Container 1 Disposed         │
│  • Instances A, X eligible for GC    │
│  • Memory reclaimed                  │
└──────────────────────────────────────┘
    │
    ▼
Request 2 arrives (same pattern repeats)
```

## Summary

```
┌─────────────────────────────────────────────────────┐
│  ADD THIS ONE LINE:                                 │
│                                                     │
│  app.add_middleware(ContainerScopeMiddleware)       │
│                                                     │
│  AND YOUR SERVICES WILL BE REQUEST-SCOPED! ✅       │
└─────────────────────────────────────────────────────┘
```

