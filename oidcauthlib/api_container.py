import logging
from typing import Annotated

from fastapi import Depends

from oidcauthlib.auth.fastapi_auth_manager import FastAPIAuthManager
from oidcauthlib.container.container_factory import ContainerFactory
from oidcauthlib.container.simple_container import SimpleContainer
from oidcauthlib.auth.config.auth_config_reader import (
    AuthConfigReader,
)
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.utilities.cached import cached
from oidcauthlib.utilities.environment.environment_variables import (
    EnvironmentVariables,
)

logger = logging.getLogger(__name__)


def get_container() -> SimpleContainer:
    """Create the container"""
    return ContainerFactory().create_container()


@cached  # makes it singleton-like
async def get_container_async() -> SimpleContainer:
    """Create the container"""
    return ContainerFactory().create_container()


def get_auth_manager(
    container: Annotated[SimpleContainer, Depends(get_container_async)],
) -> FastAPIAuthManager:
    """helper function to get the auth manager"""
    if not isinstance(container, SimpleContainer):
        raise TypeError(f"container must be SimpleContainer, got {type(container)}")
    return container.resolve(FastAPIAuthManager)


def get_token_reader(
    container: Annotated[SimpleContainer, Depends(get_container_async)],
) -> TokenReader:
    """helper function to get the token reader"""
    if not isinstance(container, SimpleContainer):
        raise TypeError(f"container must be SimpleContainer, got {type(container)}")
    return container.resolve(TokenReader)


def get_environment_variables(
    container: Annotated[SimpleContainer, Depends(get_container_async)],
) -> EnvironmentVariables:
    """helper function to get the environment variables"""
    if not isinstance(container, SimpleContainer):
        raise TypeError(f"container must be SimpleContainer, got {type(container)}")
    return container.resolve(EnvironmentVariables)


def get_auth_config_reader(
    container: Annotated[SimpleContainer, Depends(get_container_async)],
) -> AuthConfigReader:
    """helper function to get the auth config reader"""
    if not isinstance(container, SimpleContainer):
        raise TypeError(f"container must be SimpleContainer, got {type(container)}")
    return container.resolve(AuthConfigReader)
