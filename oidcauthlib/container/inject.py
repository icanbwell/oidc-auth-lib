from typing import override

from fastapi import HTTPException

from oidcauthlib.container.container_registry import ContainerRegistry
from oidcauthlib.container.interfaces import IResolvable
from oidcauthlib.container.simple_container import ServiceNotFoundError, ContainerError


class Inject[T]:
    """
    Type-safe dependency injection using complete protocol.
    """

    def __init__(self, service_type: type[T]) -> None:
        self.service_type: type[T] = service_type

    def __call__(self) -> T:
        """Called by FastAPI's Depends() system."""
        try:
            container: IResolvable = ContainerRegistry.get_current()
            return container.resolve(self.service_type)
        except ServiceNotFoundError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Service {self.service_type.__name__} not registered: {str(e)}",
            )
        except ContainerError as e:
            raise HTTPException(status_code=500, detail=f"Container error: {str(e)}")

    @override
    def __repr__(self) -> str:
        return f"Inject({self.service_type.__name__})"
