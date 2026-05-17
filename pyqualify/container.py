"""Lightweight dependency injection container for PyQualify."""

from typing import Any, Callable, TypeVar

T = TypeVar("T")


class DependencyNotRegisteredError(Exception):
    """Raised when attempting to resolve an unregistered interface."""

    def __init__(self, interface: type) -> None:
        self.interface = interface
        super().__init__(
            f"No registration found for '{interface.__qualname__}'. "
            f"Did you forget to call container.register() or container.register_singleton()?"
        )


class Container:
    """Lightweight dependency injection container.

    Supports protocol-based registration, transient factories,
    and singleton (cached) instances.

    Usage:
        container = Container()
        container.register(MyProtocol, lambda: MyImplementation())
        container.register_singleton(LoggerProtocol, lambda: Logger())
        instance = container.resolve(MyProtocol)
    """

    def __init__(self) -> None:
        self._factories: dict[type, Callable[[], Any]] = {}
        self._singletons: dict[type, Callable[[], Any]] = {}
        self._singleton_instances: dict[type, Any] = {}

    def register(self, interface: type[T], factory: Callable[[], T]) -> None:
        """Register a factory that creates a new instance each time resolve() is called.

        Args:
            interface: The protocol or interface type to register.
            factory: A callable that returns a new instance of the implementation.
        """
        # Remove from singletons if previously registered there
        self._singletons.pop(interface, None)
        self._singleton_instances.pop(interface, None)
        self._factories[interface] = factory

    def register_singleton(self, interface: type[T], factory: Callable[[], T]) -> None:
        """Register a factory that is called once; subsequent resolves return the cached instance.

        Args:
            interface: The protocol or interface type to register.
            factory: A callable that returns the singleton instance (called at most once).
        """
        # Remove from transient factories if previously registered there
        self._factories.pop(interface, None)
        # Clear any previously cached instance
        self._singleton_instances.pop(interface, None)
        self._singletons[interface] = factory

    def resolve(self, interface: type[T]) -> T:
        """Resolve an instance for the given interface.

        For transient registrations, a new instance is created each time.
        For singleton registrations, the instance is created on first resolve
        and cached for subsequent calls.

        Args:
            interface: The protocol or interface type to resolve.

        Returns:
            An instance of the registered implementation.

        Raises:
            DependencyNotRegisteredError: If the interface has not been registered.
        """
        # Check transient factories first
        if interface in self._factories:
            return self._factories[interface]()

        # Check singleton registrations
        if interface in self._singletons:
            if interface not in self._singleton_instances:
                self._singleton_instances[interface] = self._singletons[interface]()
            return self._singleton_instances[interface]

        raise DependencyNotRegisteredError(interface)
