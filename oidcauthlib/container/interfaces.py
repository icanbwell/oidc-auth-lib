from typing import Protocol, Any, Self, Callable, overload

# Type for factory functions
type ServiceFactory[T] = Callable[["IContainer"], T]


class IResolvable(Protocol):
    """
    Minimal protocol for dependency resolution.
    Only includes what Inject actually needs.
    """

    # Define overloads so mypy allows abstract classes to be resolved
    @overload
    def resolve[T](self, service_type: type[T]) -> T: ...

    @overload
    def resolve[T](self, service_type: type[T] | type[Any]) -> T: ...

    def resolve[T](self, service_type: type[T] | type[Any]) -> T:
        """Resolve a service instance."""
        ...


class IContainer(IResolvable, Protocol):
    """
    Complete protocol defining the SimpleContainer interface.
    Matches all public methods of SimpleContainer.
    """

    _factories: dict[type[Any], Any]
    _singleton_types: set[type[Any]]

    # Define overloads so mypy allows abstract classes to be passed into singleton
    @overload
    def singleton[T](
        self, service_type: type[T], factory: "ServiceFactory[T]"
    ) -> Self: ...

    @overload
    def singleton[T](
        self, service_type: type[T] | type[Any], factory: "ServiceFactory[T]"
    ) -> Self: ...

    def singleton[T](
        self, service_type: type[T] | type[Any], factory: "ServiceFactory[T]"
    ) -> Self:
        """Register a singleton instance.  Created once, cached, shared across all requests."""
        ...

    # Define overloads so mypy allows abstract classes to be passed into factory
    @overload
    def factory[T](
        self, service_type: type[T], factory: "ServiceFactory[T]"
    ) -> Self: ...

    @overload
    def factory[T](
        self, service_type: type[T] | type[Any], factory: "ServiceFactory[T]"
    ) -> Self: ...

    def factory[T](
        self, service_type: type[T] | type[Any], factory: "ServiceFactory[T]"
    ) -> Self:
        """Register a factory service. Created every time, never cached"""
        ...

    # Define overloads so mypy allows abstract classes to be passed into request_scoped
    @overload
    def request_scoped[T](
        self, service_type: type[T], factory: ServiceFactory[T]
    ) -> Self: ...

    @overload
    def request_scoped[T](
        self, service_type: type[T] | type[Any], factory: ServiceFactory[T]
    ) -> Self: ...

    def request_scoped[T](
        self, service_type: type[T] | type[Any], factory: ServiceFactory[T]
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
