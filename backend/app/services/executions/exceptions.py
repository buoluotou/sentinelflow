"""Executor exception family (Phase 3.1.5, mirrors the AI layer lineage).

Three concerns, three families:

- ``ExecutorConfigError`` — registry misconfiguration (unknown adapter,
  reserved-but-unimplemented adapter). Nothing was dispatched.
- ``ExecutorOutcomeViolation`` — the PLATFORM judged an adapter result
  structurally invalid: classification ``protocol_violation`` (D9).
  Adapters have no right to self-declare this word.
"""


class ExecutorError(Exception):
    """Base class of all executor-layer errors (never silent failures)."""


class ExecutorConfigError(ExecutorError):
    """EXECUTION_ADAPTER is unknown or reserved-but-unimplemented. The
    registry refuses to fake support (design §8 registry contract)."""


class ExecutorOutcomeViolation(ExecutorError):
    """Platform parse rejected an adapter result (extra fields, unknown
    status like `dispatched`, missing fields, or an adapter
    self-declaring protocol_violation). The 3.1.6 Execute Service maps
    this to a ``failed`` row with classification ``protocol_violation``
    — never a fake success (D9)."""

    def __init__(self, message: str, classification: str = "protocol_violation"):
        super().__init__(message)
        self.classification = classification
