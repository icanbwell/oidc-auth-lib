"""
Example: Request-Scoped Dependency Injection with FastAPI

This example demonstrates how to use request-scoped services in a FastAPI application.

Note: This is a standalone example that imports from the installed package.
Install dependencies: pip install fastapi uvicorn
Run: python examples/fastapi_scoped_di_example.py
"""

from fastapi import FastAPI, Depends

# Import from the package (these will be available after installing)
try:
    from oidcauthlib.container import (
        SimpleContainer,
        ContainerRegistry,
        Inject,
        ContainerScopeMiddleware,
    )
except ImportError:
    print("Error: oidcauthlib package not installed.")
    print("Install with: pip install -e .")
    import sys
    sys.exit(1)


# Example services
class DatabaseConfig:
    """Application-wide configuration (singleton)"""

    def __init__(self):
        self.connection_string = "postgresql://localhost/mydb"
        print(f"✓ DatabaseConfig created (id: {id(self)})")


class DatabaseSession:
    """Database session - one per request (scoped)"""

    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.session_id = id(self)
        print(f"✓ DatabaseSession created (id: {self.session_id})")

    def query(self, sql: str) -> str:
        return f"Results from session {self.session_id}"


class UserRepository:
    """Repository using database session (scoped)"""

    def __init__(self, db: DatabaseSession):
        self.db = db
        print(f"✓ UserRepository created using session {db.session_id}")

    def get_user(self, user_id: int) -> dict:
        result = self.db.query(f"SELECT * FROM users WHERE id={user_id}")
        return {"id": user_id, "name": f"User {user_id}", "query": result}


class RequestLogger:
    """Logger - new instance every time (transient)"""

    def __init__(self):
        self.logger_id = id(self)
        print(f"✓ RequestLogger created (id: {self.logger_id})")

    def log(self, message: str):
        print(f"[Logger {self.logger_id}] {message}")


# Setup container
def setup_container() -> SimpleContainer:
    container = SimpleContainer()

    # Singleton: shared across all requests
    container.singleton(
        DatabaseConfig,
        lambda c: DatabaseConfig()
    )

    # Scoped: one per request
    container.scoped(
        DatabaseSession,
        lambda c: DatabaseSession(config=c.resolve(DatabaseConfig))
    )

    container.scoped(
        UserRepository,
        lambda c: UserRepository(db=c.resolve(DatabaseSession))
    )

    # Transient: new instance every time
    container.transient(
        RequestLogger,
        lambda c: RequestLogger()
    )

    return container


# Create FastAPI app
app = FastAPI(title="Request-Scoped DI Example")

# Initialize container
container = setup_container()
ContainerRegistry.set_default(container)

# Add middleware for request scoping
app.add_middleware(ContainerScopeMiddleware)


@app.get("/")
async def root():
    return {
        "message": "Request-Scoped DI Example",
        "endpoints": {
            "GET /users/{user_id}": "Get user by ID",
            "GET /demo": "Demonstrate service lifetimes",
        }
    }


@app.get("/users/{user_id}")
async def get_user(
    user_id: int,
    repo: UserRepository = Depends(Inject(UserRepository)),
):
    """
    The UserRepository and its DatabaseSession are scoped.
    The same instances are reused throughout this request.
    """
    print(f"\n=== Request: GET /users/{user_id} ===")
    user = repo.get_user(user_id)
    return user


@app.get("/demo")
async def demo_lifetimes(
    repo1: UserRepository = Depends(Inject(UserRepository)),
    repo2: UserRepository = Depends(Inject(UserRepository)),
    logger1: RequestLogger = Depends(Inject(RequestLogger)),
    logger2: RequestLogger = Depends(Inject(RequestLogger)),
    config: DatabaseConfig = Depends(Inject(DatabaseConfig)),
):
    """
    Demonstrates different lifetimes:
    - repo1 and repo2 share the same DatabaseSession (scoped)
    - logger1 and logger2 are different instances (transient)
    - config is the same instance across all requests (singleton)
    """
    print(f"\n=== Request: GET /demo ===")

    logger1.log("First logger")
    logger2.log("Second logger")

    user1 = repo1.get_user(1)
    user2 = repo2.get_user(2)

    return {
        "singleton": {
            "config_id": id(config),
            "message": "Same instance for all requests"
        },
        "scoped": {
            "repo1_id": id(repo1),
            "repo2_id": id(repo2),
            "same_instance": id(repo1) == id(repo2),
            "db_session_id": repo1.db.session_id,
            "message": "Same instance within this request only"
        },
        "transient": {
            "logger1_id": logger1.logger_id,
            "logger2_id": logger2.logger_id,
            "different_instances": logger1.logger_id != logger2.logger_id,
            "message": "New instance every time"
        },
        "users": [user1, user2]
    }


if __name__ == "__main__":
    import uvicorn

    print("""
╔══════════════════════════════════════════════════════════════╗
║  Request-Scoped Dependency Injection Example                 ║
╚══════════════════════════════════════════════════════════════╝

Starting server...

Try these requests:
  curl http://localhost:8000/
  curl http://localhost:8000/users/123
  curl http://localhost:8000/demo

Watch the console output to see service creation patterns:
  ✓ Singleton:  Created once (first request only)
  ✓ Scoped:     Created once per request
  ✓ Transient:  Created every time resolved

Press Ctrl+C to stop.
""")

    uvicorn.run(app, host="0.0.0.0", port=8000)

