"""
simple_container.py - Your container with request scope support added
"""

import logging
import threading
from contextvars import ContextVar
from typing import Any, Dict, cast, override
from uuid import uuid4

from oidcauthlib.container.interfaces import IContainer, ServiceFactory
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["INITIALIZATION"])


def _safe_type_name(t: Any) -> str:
    """Return a readable name for a type or object."""
    return getattr(t, "__name__", repr(t))


class ContainerError(Exception):
    """Base exception for container errors"""


class ServiceNotFoundError(ContainerError):
    """Raised when a service is not found"""


# ============================================================================
# REQUEST SCOPE STORAGE (NEW)
# ============================================================================

# Store a mapping of request_id -> instances
_request_scope_storage: ContextVar[Dict[str, Dict[type[Any], Any]] | None] = ContextVar(
    "request_scope_storage"
)

# Store current request ID
_current_request_id: ContextVar[str | None] = ContextVar("current_request_id")


class SimpleContainer(IContainer):
    """
    Generic IoC Container with three scopes:

    1. Singleton: Created once, shared across all requests (thread-safe)
    2. Transient: Created every time it's resolved
    3. Request: Created once per request, shared within that request (NEW!)

    Uses a reentrant lock (RLock) for singleton instantiation so that nested resolution
    of other singleton services during factory execution does not deadlock.
    """

    _singletons: Dict[type[Any], Any] = {}  # Shared across all instances
    # Reentrant lock prevents deadlock when singleton factories resolve other singletons
    _singleton_lock: threading.RLock = threading.RLock()

    def __init__(self) -> None:
        self._factories: Dict[type[Any], ServiceFactory[Any]] = {}
        self._singleton_types: set[type[Any]] = set()
        self._request_scoped_types: set[type[Any]] = set()  # NEW
        logger.debug("SimpleContainer initialized (thread=%s)", threading.get_ident())

    @override
    def register[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """
        Register a service factory

        Args:
            service_type: The type of service to register
            factory: Factory function that creates the service
        """
        if not callable(factory):
            raise ValueError(f"Factory for {service_type} must be callable")

        self._factories[service_type] = factory
        logger.debug(
            "Registered factory for service '%s' (singleton=%s, request_scoped=%s)",
            _safe_type_name(service_type),
            service_type in self._singleton_types,
            service_type in self._request_scoped_types,  # NEW
        )
        return self

    @override
    def resolve[T](self, service_type: type[T]) -> T:
        """
        Resolve a service instance

        Automatically detects scope and returns appropriate instance:
        - Singleton: Returns cached instance (thread-safe, double-checked locking)
        - Request: Returns cached instance for current request
        - Transient: Creates new instance

        Args:
            service_type: The type of service to resolve

        Returns:
            An instance of the requested service
        """
        service_name = _safe_type_name(service_type)
        logger.debug(
            "Resolving service '%s' (thread=%s)", service_name, threading.get_ident()
        )

        # Fast path: check if it's a singleton and already instantiated (without lock)
        if service_type in SimpleContainer._singletons:
            logger.debug("Returning cached singleton for '%s'", service_name)
            return cast(T, SimpleContainer._singletons[service_type])

        if service_type not in self._factories:
            logger.error("Service '%s' not found during resolve", service_name)
            raise ServiceNotFoundError(f"No factory registered for {service_type}")

        # Check if this is a singleton type
        if service_type in self._singleton_types:
            logger.debug("Attempting singleton instantiation for '%s'", service_name)
            with SimpleContainer._singleton_lock:
                # Double-check: another thread may have instantiated while we waited for the lock
                if service_type in SimpleContainer._singletons:
                    logger.debug(
                        "Returning cached singleton for '%s' after lock", service_name
                    )
                    return cast(T, SimpleContainer._singletons[service_type])

                # Create and cache the singleton instance
                logger.info(
                    "Instantiating singleton '%s' (thread=%s)",
                    service_name,
                    threading.get_ident(),
                )
                factory = self._factories[service_type]
                service: T = factory(self)
                SimpleContainer._singletons[service_type] = service
                logger.debug("Singleton '%s' instantiated and cached", service_name)
                return service

        # NEW: Check if this is a request-scoped type
        if service_type in self._request_scoped_types:
            return self._resolve_request_scoped(service_type, service_name)

        # Transient service: create new instance without locking
        logger.info(
            "Creating transient instance for '%s' (thread=%s)",
            service_name,
            threading.get_ident(),
        )
        factory = self._factories[service_type]
        return cast(T, factory(self))

    # NEW METHOD
    def _resolve_request_scoped[T](self, service_type: type[T], service_name: str) -> T:
        """
        Resolve request-scoped service with proper per-request isolation.

        Args:
            service_type: The type of service to resolve
            service_name: Human-readable name for logging

        Returns:
            An instance of the requested service for the current request

        Raises:
            ContainerError: If no request scope is active
        """
        # Get current request ID
        request_id = _current_request_id.get(None)
        if request_id is None:
            raise ContainerError(
                f"Cannot resolve request-scoped service '{service_name}' "
                f"outside of a request context. "
                f"Ensure RequestScopeMiddleware is installed or call begin_request_scope()."
            )

        # Get storage for all requests
        all_storage = _request_scope_storage.get(None)
        if all_storage is None:
            raise ContainerError(
                f"Request scope storage not initialized for '{service_name}'. "
                f"This should not happen if begin_request_scope() was called."
            )

        # Get storage for THIS specific request
        if request_id not in all_storage:
            all_storage[request_id] = {}

        request_storage = all_storage[request_id]

        # Check if already created for this request
        if service_type in request_storage:
            logger.debug(
                "Returning cached request-scoped instance for '%s' (request=%s)",
                service_name,
                request_id[:8],  # Log first 8 chars of request ID
            )
            return cast(T, request_storage[service_type])

        # Create new instance for this request
        logger.info(
            "Instantiating request-scoped '%s' (request=%s, thread=%s)",
            service_name,
            request_id[:8],
            threading.get_ident(),
        )
        factory = self._factories[service_type]
        service: T = factory(self)
        request_storage[service_type] = service
        logger.debug(
            "Request-scoped '%s' instantiated and cached for request %s",
            service_name,
            request_id[:8],
        )
        return service

    @override
    def singleton[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """
        Register a singleton instance (application scope).

        Created once and shared across all requests.
        Thread-safe instantiation with double-checked locking.
        """
        self._factories[service_type] = factory
        self._singleton_types.add(service_type)
        logger.debug("Registered singleton service '%s'", _safe_type_name(service_type))
        return self

    @override
    def transient[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """
        Register a transient service.

        Creates a new instance every time it's resolved.
        """

        def create_new(container: IContainer) -> T:
            return factory(container)

        self.register(service_type, create_new)
        logger.debug("Registered transient service '%s'", _safe_type_name(service_type))
        return self

    # NEW METHOD
    def request_scoped[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """
        Register a request-scoped service (NEW!).

        Created once per request, shared within that request.
        Isolated between different requests.
        Requires RequestScopeMiddleware to be installed.

        Args:
            service_type: The type of service to register
            factory: Factory function that creates the service

        Returns:
            Self for method chaining

        Example:
            container.request_scoped(
                TokenReader,
                lambda c: TokenReader(
                    auth_config_reader=c.resolve(AuthConfigReader),
                    well_known_config_manager=c.resolve(WellKnownConfigurationManager),
                ),
            )
        """
        self._factories[service_type] = factory
        self._request_scoped_types.add(service_type)
        logger.debug(
            "Registered request-scoped service '%s'", _safe_type_name(service_type)
        )
        return self

    # NEW STATIC METHODS

    @staticmethod
    def begin_request_scope(request_id: str | None = None) -> str:
        """
        Begin a new request scope with explicit request ID.

        This should be called at the start of each request (typically by middleware).

        Args:
            request_id: Optional request ID. If None, generates a new UUID.

        Returns:
            The request ID for this scope

        Example:
            # In middleware
            request_id = SimpleContainer.begin_request_scope(str(id(request)))
            try:
                # Handle request
                pass
            finally:
                SimpleContainer.end_request_scope()
        """
        if request_id is None:
            request_id = str(uuid4())

        # Initialize storage if needed
        all_storage = _request_scope_storage.get(None)
        if all_storage is None:
            all_storage = {}
            _request_scope_storage.set(all_storage)

        # Set current request ID
        _current_request_id.set(request_id)

        # Initialize storage for this request
        all_storage[request_id] = {}

        logger.debug(
            "Started request scope (request_id=%s..., thread=%s)",
            request_id[:8],
            threading.get_ident(),
        )
        return request_id

    @staticmethod
    def end_request_scope() -> None:
        """
        End the current request scope and clean up.

        This should be called at the end of each request (typically by middleware).
        Cleans up all request-scoped instances for the current request.

        Example:
            # In middleware
            try:
                # Handle request
                pass
            finally:
                SimpleContainer.end_request_scope()
        """
        request_id = _current_request_id.get(None)
        if request_id is None:
            logger.warning("No active request scope to end")
            return

        # Clean up storage for this request
        all_storage = _request_scope_storage.get(None)
        if all_storage and request_id in all_storage:
            instance_count = len(all_storage[request_id])
            del all_storage[request_id]
            logger.debug(
                "Ended request scope (request_id=%s..., thread=%s), "
                "cleaned up %d instances, remaining requests: %d",
                request_id[:8],
                threading.get_ident(),
                instance_count,
                len(all_storage),
            )

        # Clear current request ID
        _current_request_id.set(None)

    @staticmethod
    def get_current_request_id() -> str | None:
        """
        Get the current request ID.

        Returns:
            The current request ID, or None if no request scope is active
        """
        return _current_request_id.get(None)

    @staticmethod
    def is_request_scope_active() -> bool:
        """
        Check if a request scope is currently active.

        Returns:
            True if within a request scope, False otherwise
        """
        return _current_request_id.get(None) is not None

    @classmethod
    def clear_singletons(cls) -> None:
        """
        Clear all singleton instances from the container.

        This does NOT clear request-scoped instances.
        Use end_request_scope() to clean up request-scoped instances.
        """
        count = len(SimpleContainer._singletons)
        logger.debug("Clearing %d singleton instances", count)
        SimpleContainer._singletons.clear()
