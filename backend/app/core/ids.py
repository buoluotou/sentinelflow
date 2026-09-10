"""Time-ordered UUIDv7 identifiers (RC2 / H-2 — audit ordering).

WHY. The frozen derived-state rule orders an execution chain by
``created_at DESC, id DESC``. RC2 / H-2 moved ``created_at`` to the DATABASE
(SQLite: ``CURRENT_TIMESTAMP``; PostgreSQL production: ``clock_timestamp()``,
migration 0014) and removed the pre-RC2 process-global high-water mark — which
was neither thread-safe nor multi-worker correct. The sanctioned tie-break
``(created_at, id)`` is only deterministic if ``id`` is INSERTION-ORDERED;
the legacy ``uuid4`` made it a random lottery on ties (ubiquitous on SQLite's
second-precision timestamps).

WHAT. :func:`uuid7` implements the RFC 9562 UUIDv7 layout: a 48-bit Unix
millisecond timestamp, a 12-bit monotonic counter ("rand_a"), the version and
variant bits, then random bits. Within one process it is STRICTLY increasing:
a same-millisecond burst increments the counter (overflow carries into the
millisecond), and a wall-clock regression is clamped to a forward-only
sequence — so the value is a true insertion order, never a clock artifact.

WHY A PROCESS COUNTER IS SAFE HERE. One execution chain is written by exactly
ONE process (one request owns the one ``execution_id`` transaction; duplicates
are refused by the frozen unique indexes), so per-chain ordering NEVER depends
on cross-process coordination. Across processes, the embedded millisecond
timestamp keeps the values globally roughly time-ordered, and cross-chain ties
have no correctness surface (the derived state is per ``execution_id``).
"""
import os
import threading
import time
import uuid

#: The RFC 9562 version / variant of every id this module mints.
UUID7_VERSION = 7
_VARIANT_BITS = 0b10  # RFC 4122/9562 variant ("10xx")

_COUNTER_BITS = 12
_COUNTER_MAX = (1 << _COUNTER_BITS) - 1

_LOCK = threading.Lock()
_LAST_MS = 0
_COUNTER = 0


def uuid7() -> uuid.UUID:
    """A time-ordered, process-monotonic UUIDv7 (insertion-order tie-break).

    Strictly increasing within this process even for a same-millisecond burst
    (counter) and under a backward wall-clock step (clamped) — see the module
    docstring for why per-chain correctness never needs cross-process state.
    """
    global _LAST_MS, _COUNTER
    with _LOCK:
        ms = time.time_ns() // 1_000_000
        if ms > _LAST_MS:
            _LAST_MS = ms
            _COUNTER = 0
        else:
            _COUNTER += 1
            if _COUNTER > _COUNTER_MAX:  # >4096 ids in one ms: carry forward
                _LAST_MS += 1
                _COUNTER = 0
        random_bits = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
        value = (
            (_LAST_MS << 80)
            | (UUID7_VERSION << 76)
            | (_COUNTER << 64)
            | (_VARIANT_BITS << 62)
            | random_bits
        )
        return uuid.UUID(int=value)
