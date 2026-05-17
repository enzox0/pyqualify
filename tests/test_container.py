"""Tests for qaai.container dependency injection container."""

from typing import Protocol, runtime_checkable

import pytest

from pyqualify.container import Container, DependencyNotRegisteredError


# --- Test protocols and implementations ---


@runtime_checkable
class GreeterProtocol(Protocol):
    """A simple protocol for testing."""

    def greet(self, name: str) -> str: ...


class FriendlyGreeter:
    """Implementation of GreeterProtocol."""

    def greet(self, name: str) -> str:
        return f"Hello, {name}!"


class FormalGreeter:
    """Another implementation of GreeterProtocol."""

    def greet(self, name: str) -> str:
        return f"Good day, {name}."


@runtime_checkable
class CounterProtocol(Protocol):
    """Protocol with mutable state for singleton testing."""

    def increment(self) -> int: ...


class Counter:
    """Stateful implementation for singleton testing."""

    def __init__(self) -> None:
        self._count = 0

    def increment(self) -> int:
        self._count += 1
        return self._count


# --- Tests ---


class TestContainerRegister:
    """Tests for transient (factory) registration."""

    def test_register_and_resolve(self):
        container = Container()
        container.register(GreeterProtocol, lambda: FriendlyGreeter())
        instance = container.resolve(GreeterProtocol)
        assert instance.greet("World") == "Hello, World!"

    def test_register_creates_new_instance_each_time(self):
        container = Container()
        container.register(GreeterProtocol, lambda: FriendlyGreeter())
        instance1 = container.resolve(GreeterProtocol)
        instance2 = container.resolve(GreeterProtocol)
        assert instance1 is not instance2

    def test_register_overwrites_previous_registration(self):
        container = Container()
        container.register(GreeterProtocol, lambda: FriendlyGreeter())
        container.register(GreeterProtocol, lambda: FormalGreeter())
        instance = container.resolve(GreeterProtocol)
        assert instance.greet("World") == "Good day, World."

    def test_register_overwrites_singleton_registration(self):
        container = Container()
        container.register_singleton(GreeterProtocol, lambda: FriendlyGreeter())
        # Overwrite with transient
        container.register(GreeterProtocol, lambda: FormalGreeter())
        instance = container.resolve(GreeterProtocol)
        assert instance.greet("World") == "Good day, World."


class TestContainerRegisterSingleton:
    """Tests for singleton registration."""

    def test_register_singleton_and_resolve(self):
        container = Container()
        container.register_singleton(GreeterProtocol, lambda: FriendlyGreeter())
        instance = container.resolve(GreeterProtocol)
        assert instance.greet("World") == "Hello, World!"

    def test_singleton_returns_same_instance(self):
        container = Container()
        container.register_singleton(GreeterProtocol, lambda: FriendlyGreeter())
        instance1 = container.resolve(GreeterProtocol)
        instance2 = container.resolve(GreeterProtocol)
        assert instance1 is instance2

    def test_singleton_factory_called_once(self):
        call_count = 0

        def factory():
            nonlocal call_count
            call_count += 1
            return FriendlyGreeter()

        container = Container()
        container.register_singleton(GreeterProtocol, factory)
        container.resolve(GreeterProtocol)
        container.resolve(GreeterProtocol)
        container.resolve(GreeterProtocol)
        assert call_count == 1

    def test_singleton_preserves_state(self):
        container = Container()
        container.register_singleton(CounterProtocol, lambda: Counter())
        counter = container.resolve(CounterProtocol)
        assert counter.increment() == 1
        assert counter.increment() == 2
        # Resolve again --- same instance
        counter2 = container.resolve(CounterProtocol)
        assert counter2.increment() == 3

    def test_register_singleton_overwrites_transient(self):
        container = Container()
        container.register(GreeterProtocol, lambda: FriendlyGreeter())
        container.register_singleton(GreeterProtocol, lambda: FormalGreeter())
        instance1 = container.resolve(GreeterProtocol)
        instance2 = container.resolve(GreeterProtocol)
        assert instance1 is instance2
        assert instance1.greet("World") == "Good day, World."

    def test_re_register_singleton_clears_cached_instance(self):
        container = Container()
        container.register_singleton(CounterProtocol, lambda: Counter())
        counter1 = container.resolve(CounterProtocol)
        counter1.increment()
        # Re-register --- should create a fresh instance
        container.register_singleton(CounterProtocol, lambda: Counter())
        counter2 = container.resolve(CounterProtocol)
        assert counter2.increment() == 1  # Fresh counter


class TestContainerResolve:
    """Tests for resolve behavior and error handling."""

    def test_resolve_unregistered_raises_error(self):
        container = Container()
        with pytest.raises(DependencyNotRegisteredError) as exc_info:
            container.resolve(GreeterProtocol)
        assert "GreeterProtocol" in str(exc_info.value)

    def test_error_message_includes_interface_name(self):
        container = Container()
        with pytest.raises(DependencyNotRegisteredError) as exc_info:
            container.resolve(CounterProtocol)
        assert "CounterProtocol" in str(exc_info.value)
        assert "register" in str(exc_info.value).lower()

    def test_multiple_interfaces_independent(self):
        container = Container()
        container.register(GreeterProtocol, lambda: FriendlyGreeter())
        container.register_singleton(CounterProtocol, lambda: Counter())

        greeter = container.resolve(GreeterProtocol)
        counter = container.resolve(CounterProtocol)

        assert greeter.greet("Test") == "Hello, Test!"
        assert counter.increment() == 1

    def test_resolve_with_class_as_interface(self):
        """Container works with concrete classes as keys, not just protocols."""
        container = Container()
        container.register(FriendlyGreeter, lambda: FriendlyGreeter())
        instance = container.resolve(FriendlyGreeter)
        assert isinstance(instance, FriendlyGreeter)

