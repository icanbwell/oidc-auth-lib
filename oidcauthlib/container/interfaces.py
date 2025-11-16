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

    def register[T](self, service_type: type[T], factory: "ServiceFactory[T]") -> Self:
        """Register a service factory."""
        ...

    def singleton[T](self, service_type: type[T], factory: "ServiceFactory[T]") -> Self:
        """Register a singleton instance."""
        ...

    def transient[T](self, service_type: type[T], factory: "ServiceFactory[T]") -> Self:
        """Register a transient service."""
        ...

    def scoped[T](self, service_type: type[T], factory: "ServiceFactory[T]") -> Self:
        """Register a scoped service (one instance per container/request)."""
        ...

    def create_scope(self) -> Self:
        """Create a child container for scoped services."""
        ...

