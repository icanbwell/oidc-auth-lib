import logging
import threading
from typing import Any, Dict, cast, override

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


class SimpleContainer(IContainer):
    """Generic IoC Container

    Uses a reentrant lock (RLock) for singleton instantiation so that nested resolution
    of other singleton services during factory execution does not deadlock.
    """

    _singletons: Dict[type[Any], Any] = {}  # Shared across all instances
    # Reentrant lock prevents deadlock when singleton factories resolve other singletons
    _singleton_lock: threading.RLock = threading.RLock()

    def __init__(self) -> None:
        # Remove instance-level _singletons
        self._factories: Dict[type[Any], ServiceFactory[Any]] = {}
        self._singleton_types: set[type[Any]] = set()
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
            "Registered factory for service '%s' (singleton=%s)",
            _safe_type_name(service_type),
            service_type in self._singleton_types,
        )
        return self

    @override
    def resolve[T](self, service_type: type[T]) -> T:
        """
        Resolve a service instance

        Uses double-checked locking pattern for singleton instantiation to prevent
        race conditions in multithreaded/concurrent environments.

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
        else:
            # Transient service: create new instance without locking
            logger.info(
                "Creating transient instance for '%s' (thread=%s)",
                service_name,
                threading.get_ident(),
            )
            factory = self._factories[service_type]
            return cast(T, factory(self))

    @override
    def singleton[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """Register a singleton instance"""
        self._factories[service_type] = factory
        self._singleton_types.add(service_type)
        logger.debug("Registered singleton service '%s'", _safe_type_name(service_type))
        return self

    @override
    def transient[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """Register a transient service"""

        def create_new(container: IContainer) -> T:
            return factory(container)

        self.register(service_type, create_new)
        logger.debug("Registered transient service '%s'", _safe_type_name(service_type))
        return self

    @classmethod
    def clear_singletons(cls) -> None:
        """Clear all singleton instances from the container"""
        count = len(SimpleContainer._singletons)
        logger.debug("Clearing %d singleton instances", count)
        SimpleContainer._singletons.clear()
