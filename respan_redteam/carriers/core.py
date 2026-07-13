"""Carrier contract and registration."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

COMPREHENSION = "comprehension"
ENCODING = "encoding"


class Carrier(ABC):
    name: str = ""
    kind: str = COMPREHENSION
    bypass_priority: int = 100
    bypass_enabled: bool = True
    frame_compatible: bool = False

    @abstractmethod
    def apply(self, text: str) -> str:
        """Transform a payload while preserving its meaning for the target."""


class FunctionalCarrier(Carrier):
    """Concrete carrier configured with metadata and a transformation function."""

    def __init__(self, name: str, transform: Callable[[str], str], *,
                 kind: str = COMPREHENSION, bypass_priority: int = 100,
                 bypass_enabled: bool = True, frame_compatible: bool = False):
        self.name = name
        self.kind = kind
        self.bypass_priority = bypass_priority
        self.bypass_enabled = bypass_enabled
        self.frame_compatible = frame_compatible
        self._transform = transform

    def apply(self, text: str) -> str:
        return self._transform(text)


_REGISTERED: list[Carrier] = []


def register_carrier(carrier: Carrier) -> Carrier:
    global _REGISTERED
    _REGISTERED = [item for item in _REGISTERED if item.name != carrier.name]
    _REGISTERED.append(carrier)
    return carrier


def registered_carriers() -> list[Carrier]:
    return list(_REGISTERED)


def carrier_by_name(name: str) -> Carrier:
    for carrier in _REGISTERED:
        if carrier.name == name:
            return carrier
    raise KeyError(name)


all_carriers = registered_carriers
