from typing import Protocol, Any, Self, Callable

# Type for factory functions
type ServiceFactory[T] = Callable[["IContainer"], T]


class IResolvable(Protocol):
    """
    Minimal protocol for dependency resolution.
    Only includes what Inject actually needs.
    """

    def resolve[T](self, service_type: type[T]) -> T:
        """Resolve a service instance."""
        ...


class IContainer(IResolvable, Protocol):
    """
    Complete protocol defining the SimpleContainer interface.
    Matches all public methods of SimpleContainer.
    """

    _factories: dict[type[Any], Any]
    _singleton_types: set[type[Any]]

    def singleton[T](self, service_type: type[T], factory: "ServiceFactory[T]") -> Self:
        """Register a singleton instance.  Created once, cached, shared across all requests."""
        ...

    def factory[T](self, service_type: type[T], factory: "ServiceFactory[T]") -> Self:
        """Register a factory service. Created every time, never cached"""
        ...

    def request_scoped[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> Self:
        """Register a request-scoped service. Created once per request, cached within request"""
        ...

    @property
    def container_source(self) -> str:
        """Get the underlying container source."""
        ...

    def clear_singletons(self) -> None:
        """Clear all singleton instances from the container."""
        ...
