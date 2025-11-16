import threading
from typing import Any, Dict, cast, override

from oidcauthlib.container.interfaces import IContainer, ServiceFactory


class ContainerError(Exception):
    """Base exception for container errors"""


class ServiceNotFoundError(ContainerError):
    """Raised when a service is not found"""


class SimpleContainer(IContainer):
    """Generic IoC Container"""

    _singletons: Dict[type[Any], Any] = {}  # Shared across all instances
    _singleton_lock: threading.Lock = (
        threading.Lock()
    )  # Protects singleton instantiation

    def __init__(self) -> None:
        # Remove instance-level _singletons
        self._factories: Dict[type[Any], ServiceFactory[Any]] = {}
        self._singleton_types: set[type[Any]] = set()

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
        return self

    @override
    def resolve[T](self, service_type: type[T]) -> T:
        """
        Resolve a service instance

        Uses double-checked locking pattern for singleton instantiation to prevent
        race conditions in multi-threaded/concurrent environments.

        Args:
            service_type: The type of service to resolve

        Returns:
            An instance of the requested service
        """
        # Fast path: check if it's a singleton and already instantiated (without lock)
        if service_type in SimpleContainer._singletons:
            return cast(T, SimpleContainer._singletons[service_type])

        if service_type not in self._factories:
            raise ServiceNotFoundError(f"No factory registered for {service_type}")

        # Check if this is a singleton type
        if service_type in self._singleton_types:
            # Acquire lock for singleton instantiation
            with SimpleContainer._singleton_lock:
                # Double-check: another thread may have instantiated while we waited for the lock
                if service_type in SimpleContainer._singletons:
                    return cast(T, SimpleContainer._singletons[service_type])

                # Create and cache the singleton instance
                factory = self._factories[service_type]
                service: T = factory(self)
                SimpleContainer._singletons[service_type] = service
                return service
        else:
            # Transient service: create new instance without locking
            factory = self._factories[service_type]
            return cast(T, factory(self))

    @override
    def singleton[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """Register a singleton instance"""
        self._factories[service_type] = factory
        self._singleton_types.add(service_type)
        return self

    @override
    def transient[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """Register a transient service (new instance every time)"""
        self._factories[service_type] = factory
        # Explicitly ensure it's not in singleton or scoped types
        self._singleton_types.discard(service_type)
        self._scoped_types.discard(service_type)
        return self

    def scoped[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> "SimpleContainer":
        """Register a scoped service (one instance per container/request)"""
        self._factories[service_type] = factory
        self._scoped_types.add(service_type)
        self._singleton_types.discard(service_type)  # Ensure not in singleton
        return self

    def create_scope(self) -> "SimpleContainer":
        """
        Create a child container that inherits all registrations but has its own scope.
        Useful for request-scoped services in web applications.
        """
        return SimpleContainer(parent=self)

    @classmethod
    def clear_singletons(cls) -> None:
        """Clear all singleton instances from the container"""
        SimpleContainer._singletons.clear()
