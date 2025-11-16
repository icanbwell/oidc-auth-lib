import pytest

from oidcauthlib.container.interfaces import IContainer
from oidcauthlib.container.simple_container import SimpleContainer, ServiceNotFoundError


class Foo:
    def __init__(self, value: int) -> None:
        self.value: int = value


def foo_factory(container: IContainer) -> Foo:
    return Foo(42)


def test_register_and_resolve() -> None:
    c: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    c.factory(Foo, foo_factory)
    foo: Foo = c.resolve(Foo)
    assert isinstance(foo, Foo)
    assert foo.value == 42


def test_singleton() -> None:
    c: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    c.singleton(Foo, foo_factory)
    foo1: Foo = c.resolve(Foo)
    foo2: Foo = c.resolve(Foo)
    assert foo1 is foo2


def test_service_not_found() -> None:
    c: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    with pytest.raises(ServiceNotFoundError):
        c.resolve(Foo)
