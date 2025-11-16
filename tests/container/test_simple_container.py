import pytest
from _pytest.logging import LogCaptureFixture

from oidcauthlib.container.interfaces import IContainer
from oidcauthlib.container.simple_container import (
    SimpleContainer,
    ServiceNotFoundError,
    RequestScopeNotActiveError,
)


class Foo:
    def __init__(self, value: int) -> None:
        self.value: int = value


class Bar:
    def __init__(self) -> None:
        # unique identity marker to differentiate instances
        import uuid

        self.marker = uuid.uuid4().hex


def foo_factory(container: IContainer) -> Foo:
    return Foo(42)


def bar_factory(container: IContainer) -> Bar:
    return Bar()


def test_register_and_resolve() -> None:
    c: SimpleContainer = SimpleContainer(source=__name__)
    c.clear_singletons()
    c.factory(Foo, foo_factory)
    foo: Foo = c.resolve(Foo)
    assert isinstance(foo, Foo)
    assert foo.value == 42


def test_singleton() -> None:
    c: SimpleContainer = SimpleContainer(source=__name__)
    c.clear_singletons()
    c.singleton(Foo, foo_factory)
    foo1: Foo = c.resolve(Foo)
    foo2: Foo = c.resolve(Foo)
    assert foo1 is foo2


def test_service_not_found() -> None:
    c: SimpleContainer = SimpleContainer(source=__name__)
    c.clear_singletons()
    with pytest.raises(ServiceNotFoundError):
        c.resolve(Foo)


# ------------------------- Request Scope Tests -------------------------


def test_request_scoped_resolution_same_request() -> None:
    c = SimpleContainer(source=__name__)
    c.request_scoped(Bar, bar_factory)
    request_id = SimpleContainer.begin_request_scope("req-1")
    try:
        b1 = c.resolve(Bar)
        b2 = c.resolve(Bar)
        assert b1 is b2, (
            "Request-scoped service should return same instance within a request"
        )
        assert SimpleContainer.get_current_request_id() == request_id
    finally:
        SimpleContainer.end_request_scope()
    assert SimpleContainer.get_current_request_id() is None


def test_request_scoped_resolution_different_requests() -> None:
    c = SimpleContainer(source=__name__)
    c.request_scoped(Bar, bar_factory)
    SimpleContainer.begin_request_scope("req-A")
    try:
        b_a = c.resolve(Bar)
    finally:
        SimpleContainer.end_request_scope()

    SimpleContainer.begin_request_scope("req-B")
    try:
        b_b = c.resolve(Bar)
    finally:
        SimpleContainer.end_request_scope()

    assert b_a is not b_b, "Different requests must get different instances"


def test_request_scoped_resolution_without_scope() -> None:
    c = SimpleContainer(source=__name__)
    c.request_scoped(Bar, bar_factory)
    with pytest.raises(RequestScopeNotActiveError):
        c.resolve(Bar)


def test_request_scope_lifecycle_helpers() -> None:
    c = SimpleContainer(source=__name__)
    c.request_scoped(Bar, bar_factory)
    assert not SimpleContainer.is_request_scope_active()
    rid = SimpleContainer.begin_request_scope("life-1")
    try:
        assert SimpleContainer.is_request_scope_active()
        assert SimpleContainer.get_current_request_id() == rid
        instance = c.resolve(Bar)
        # clear singletons should not affect request scoped instance
        c.clear_singletons()
        instance2 = c.resolve(Bar)
        assert instance is instance2
    finally:
        SimpleContainer.end_request_scope()
    assert not SimpleContainer.is_request_scope_active()


def test_end_request_scope_without_begin(caplog: LogCaptureFixture) -> None:
    # Ensure no exception when ending scope without begin
    caplog.set_level("WARNING")
    SimpleContainer.end_request_scope()  # should warn and not raise
    assert any("no request scope is active" in msg for msg in caplog.messages)


def test_nested_request_scope_warning(caplog: LogCaptureFixture) -> None:
    c = SimpleContainer(source=__name__)
    c.request_scoped(Bar, bar_factory)
    caplog.set_level("WARNING")
    SimpleContainer.begin_request_scope("outer")
    try:
        SimpleContainer.begin_request_scope("inner")
        try:
            # resolution should work for inner scope
            inner_instance = c.resolve(Bar)
            assert inner_instance is c.resolve(Bar)
        finally:
            SimpleContainer.end_request_scope()  # end inner
        # After ending inner, no active scope (since implementation clears current ID)
        assert not SimpleContainer.is_request_scope_active()
    finally:
        # Ending outer now will just warn because scope is inactive
        SimpleContainer.end_request_scope()
    assert any(
        "another request scope is already active" in msg for msg in caplog.messages
    )
