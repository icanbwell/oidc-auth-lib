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
    c.register(Foo, foo_factory)
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


def test_transient() -> None:
    c: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    c.transient(Foo, foo_factory)
    foo1: Foo = c.resolve(Foo)
    foo2: Foo = c.resolve(Foo)
    assert foo1 is not foo2
    assert foo1.value == 42 and foo2.value == 42


def test_service_not_found() -> None:
    c: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    with pytest.raises(ServiceNotFoundError):
        c.resolve(Foo)


def test_scoped_same_container() -> None:
    """Test that scoped services return the same instance within the same container."""
    c: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    c.scoped(Foo, foo_factory)
    foo1: Foo = c.resolve(Foo)
    foo2: Foo = c.resolve(Foo)
    assert foo1 is foo2  # Same instance in same container


def test_scoped_different_containers() -> None:
    """Test that scoped services return different instances in different containers."""
    parent: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    parent.scoped(Foo, foo_factory)

    # Create two child scopes
    scope1: SimpleContainer = parent.create_scope()
    scope2: SimpleContainer = parent.create_scope()

    foo1: Foo = scope1.resolve(Foo)
    foo2: Foo = scope2.resolve(Foo)

    assert foo1 is not foo2  # Different instances in different scopes
    assert foo1.value == 42 and foo2.value == 42


def test_scoped_inherits_from_parent() -> None:
    """Test that child scopes inherit registrations from parent."""
    parent: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    parent.scoped(Foo, foo_factory)

    child: SimpleContainer = parent.create_scope()
    foo: Foo = child.resolve(Foo)

    assert isinstance(foo, Foo)
    assert foo.value == 42


def test_singleton_shared_across_scopes() -> None:
    """Test that singletons are shared across all scopes."""
    parent: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    parent.singleton(Foo, foo_factory)

    scope1: SimpleContainer = parent.create_scope()
    scope2: SimpleContainer = parent.create_scope()

    foo1: Foo = scope1.resolve(Foo)
    foo2: Foo = scope2.resolve(Foo)
    parent_foo: Foo = parent.resolve(Foo)

    assert foo1 is foo2
    assert foo1 is parent_foo  # All should be the same singleton instance


def test_transient_creates_new_instances_in_scope() -> None:
    """Test that transient services create new instances even within a scope."""
    parent: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()
    parent.transient(Foo, foo_factory)

    scope: SimpleContainer = parent.create_scope()
    foo1: Foo = scope.resolve(Foo)
    foo2: Foo = scope.resolve(Foo)

    assert foo1 is not foo2  # Different instances


def test_mixed_lifetimes() -> None:
    """Test that different lifetime registrations work together correctly."""

    class Service1:
        pass

    class Service2:
        pass

    class Service3:
        pass

    parent: SimpleContainer = SimpleContainer()
    SimpleContainer.clear_singletons()

    parent.singleton(Service1, lambda c: Service1())
    parent.scoped(Service2, lambda c: Service2())
    parent.transient(Service3, lambda c: Service3())

    scope1: SimpleContainer = parent.create_scope()
    scope2: SimpleContainer = parent.create_scope()

    # Singleton: same across all scopes
    s1_scope1 = scope1.resolve(Service1)
    s1_scope2 = scope2.resolve(Service1)
    assert s1_scope1 is s1_scope2

    # Scoped: same within scope, different across scopes
    s2_scope1_a = scope1.resolve(Service2)
    s2_scope1_b = scope1.resolve(Service2)
    s2_scope2 = scope2.resolve(Service2)
    assert s2_scope1_a is s2_scope1_b  # Same within scope1
    assert s2_scope1_a is not s2_scope2  # Different from scope2

    # Transient: always different
    s3_a = scope1.resolve(Service3)
    s3_b = scope1.resolve(Service3)
    assert s3_a is not s3_b
