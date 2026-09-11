"""Executor exception family (mirrors the AI layer lineage).

Two leaf families:

- ``ExecutorConfigError`` — registry misconfiguration (unknown adapter,
reserved-but-unimplemented adapter). Nothing was dispatched.
- ``ExecutorOutcomeViolation`` — the platform judged an adapter result
structurally invalid: classification ``protocol_violation``.
Adapters have no right to self-declare this word.
"""


class ExecutorError(Exception):
    """Base class of all executor-layer errors (never silent failures)."""


class ExecutorConfigError(ExecutorError):
    """EXECUTION_ADAPTER is unknown or reserved-but-unimplemented. The
registry raises rather than faking support for the adapter."""


class ExecutorOutcomeViolation(ExecutorError):
    """Platform parse rejected an adapter result (extra fields, unknown
status like `dispatched`, missing fields, or an adapter
self-declaring protocol_violation). The Execute Service maps this to
a ``failed`` row with classification ``protocol_violation`` — the run
is never recorded as a success."""

    def __init__(self, message: str, classification: str = "protocol_violation"):
        super().__init__(message)
        self.classification = classification
