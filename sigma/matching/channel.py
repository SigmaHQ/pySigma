from __future__ import annotations

import queue
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

T = TypeVar("T")


class MessageChannel(ABC, Generic[T]):
    """Abstract message channel for passing typed messages between components."""

    @abstractmethod
    def send(self, message: T) -> None: ...

    @abstractmethod
    def receive(self, timeout: float | None = None) -> T | None: ...

    def close(self) -> None:
        pass


class InProcessChannel(MessageChannel[T]):
    """Queue-based in-process channel."""

    def __init__(self) -> None:
        self._queue: queue.Queue[T] = queue.Queue()

    def send(self, message: T) -> None:
        self._queue.put(message)

    def receive(self, timeout: float | None = None) -> T | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self) -> None:
        pass
