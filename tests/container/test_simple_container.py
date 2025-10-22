import pytest
from oidcauthlib.container.simple_container import SimpleContainer, ServiceNotFoundError


class Foo:
    def __init__(self, value: int) -> None:
        self.value: int = value


def foo_factory(container: SimpleContainer) -> Foo:
    return Foo(42)


def test_register_and_resolve() -> None:
    c: SimpleContainer = SimpleContainer()
    c.register(Foo, foo_factory)
    foo: Foo = c.resolve(Foo)
    assert isinstance(foo, Foo)
    assert foo.value == 42


def test_singleton() -> None:
    c: SimpleContainer = SimpleContainer()
    c.singleton(Foo, foo_factory)
    foo1: Foo = c.resolve(Foo)
    foo2: Foo = c.resolve(Foo)
    assert foo1 is foo2


def test_transient() -> None:
    c: SimpleContainer = SimpleContainer()
    c.transient(Foo, foo_factory)
    foo1: Foo = c.resolve(Foo)
    foo2: Foo = c.resolve(Foo)
    assert foo1 is not foo2
    assert foo1.value == 42 and foo2.value == 42


def test_service_not_found() -> None:
    c: SimpleContainer = SimpleContainer()
    with pytest.raises(ServiceNotFoundError):
        c.resolve(Foo)
