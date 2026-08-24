"""Adapter contract and normalization errors."""
from abc import ABC, abstractmethod

from app.services.normalization.models import NormalizedAlert


class NormalizationError(Exception):
    """Base error for the normalization engine."""


class UnknownSourceError(NormalizationError):
    """No adapter is registered for the requested source."""


class AdapterNotImplementedError(NormalizationError):
    """An adapter exists but is still a placeholder (e.g. Wazuh in Phase 1)."""


class MalformedRawEventError(NormalizationError):
    """The raw event cannot be parsed by the adapter."""


class BaseAdapter(ABC):
    """Contract every source adapter must implement.

    An adapter only knows about its own raw format and produces the unified
    NormalizedAlert model. It never touches the database.
    """

    #: identifier used in POST /api/v1/normalize {"source": ...}
    source: str = "unknown"

    @abstractmethod
    def normalize(self, raw_data: dict) -> NormalizedAlert:
        """Convert one raw source event into a NormalizedAlert.

        Must raise MalformedRawEventError when the payload is not parseable.
        """
        raise NotImplementedError
