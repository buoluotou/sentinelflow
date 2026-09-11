"""Webhook Gate 4 — Semantic Mapping Integration.

The four-gate webhook inbound pipeline (design doc
``docs/design/phase3.4-reconciliation-contract.md``; 3.4.4 spec):

HTTP JSON body
-> Gate 1 Authentication    (3.4.4-A, sealed f35852b)
-> Gate 2 Schema            (3.4.4-B, sealed 716a152)
-> Gate 3 Correlation       (3.4.4-C, sealed b3753b5)
-> Gate 4 Semantic Mapping  (THIS MODULE, 3.4.4-D)
-> Outcome Fact Append      (3.4.4-E)

Gate 3 proved the execution chain EXISTS; it proved NOTHING about the
external effect. This gate is the ONLY place an external state word becomes
an outcome word, and it does so by DELEGATION — never by reimplementation:

validated observation -> normalize_external_state(adapter, external_state)
-> StateMapping (3.4.3-B, sealed 8b89fe7)

``map_external_state`` is a THIN orchestration wrapper. Every
vocabulary decision — which words mean ``confirmed_success`` / ``pending`` /
``unknown``, which are refused — lives in 3.4.3-B's ``normalize_external_state``
and its ``ADAPTER_STATE_VOCABULARIES``. This module adds NO mapping table, NO
``if/elif`` chain, NO copied vocabulary, NO second mapping DTO. It only routes the two trusted inputs the mapper needs.

THE TWO INPUTS:
- ``observation.adapter`` — the TRUSTED callback identity established by
Gate 1 and carried, unclient-controlled, through Gate 2 and 3.4.3-A. A
client-supplied ``body.adapter`` can never reach here: the mapper reads the
adapter from the validated observation ONLY.
- ``observation.external_state`` — the RAW state, passed through UNMODIFIED.
No strip / lower / upper / whitespace-normalize / Mapping-key rewrite
happens here; 3.4.3-B applies the only normalizations an adapter's own code
evidences. D assumes ``validate_observation`` already ran and re-validates NOTHING.

THE SEMANTIC FIREWALLS this gate exists to keep (all enforced in 3.4.3-B and
pinned by tests/test_mapping.py):
- DISPATCH ≠ OUTCOME: the dispatch words ``succeeded`` / ``failed``
are NOT external states. ``succeeded`` never becomes ``confirmed_success``
and ``failed`` never becomes ``confirmed_failure`` just because the names
look alike — Wazuh's evidenced success word is ``success``, never the
dispatch word ``succeeded``.
- NO reconciliation_failed: that word is the READ-FAILURE verdict
(3.4.5), never a state-mapping product. ``StateMapping.__post_init__``
refuses it STRUCTURALLY, so this gate cannot emit it.
- unknown ≠ unrecognized: ``unknown`` is a RECOGNIZED-but-ambiguous
legitimate state (Wazuh ``unknown``). An UNREGISTERED state is refused with
``UnrecognizedExternalState`` — NEVER downgraded to ``unknown`` and NEVER to
``reconciliation_failed``.
- FAIL-CLOSED ANTI-FABRICATION: only Wazuh has a code-evidenced
vocabulary today. Shuffle (trigger-only, no read path), TheHive (case created
≠ resolved, no read path) and Mock (no external system by design) have NO
evidenced external-state vocabulary, so EVERY state they report — including
a plausible-looking ``success`` / ``resolved`` — is REFUSED. This module
never widens a vocabulary to make a demo pass; that requires 3.4.5 read-path
evidence, not a guess.

PURE DOMAIN: no database, no Session, no ORM, no
repository, no commit / flush, no executor, no execution service, no adapter
client, no external transport, no FastAPI. On a refused state it raises
``UnrecognizedExternalState`` (a ``ContractValidationFailure``) and lets it
propagate untouched — the domain layer never converts it to an ``HTTPException``;
HTTP status is decided at final webhook-router wiring (3.4.4-E).
"""

from app.services.outcomes.reconciliation import (
    NormalizedObservation,
    StateMapping,
    normalize_external_state,
)


def map_external_state(observation: NormalizedObservation) -> StateMapping:
    """Map a validated observation's external_state onto the outcome vocabulary.

The Gate 4 integration point: hand the ALREADY-VALIDATED
observation (3.4.3-A ``validate_observation`` ran upstream) to 3.4.3-B's
``normalize_external_state`` and return its immutable ``StateMapping``.

PURE delegation — this function owns NO vocabulary of its own:

- the adapter is ``observation.adapter`` — the TRUSTED Gate-1 identity,
never a client-supplied value;
- the state is ``observation.external_state`` — passed RAW and UNMODIFIED;
- the outcome word, the raw/normalized state echo and the audit reason are
all produced by 3.4.3-B, and the result is the ``StateMapping``.

Returns a ``StateMapping`` whose ``outcome_status`` is one of the four
mappable words (``confirmed_success`` / ``pending`` / ``unknown`` /
``confirmed_failure`` — the last only where an adapter evidences a failure
vocabulary, which none does today). Raises ``UnrecognizedExternalState``
(propagated from 3.4.3-B, never converted) when the state is outside the
adapter's evidenced vocabulary — NO Outcome Fact, NEVER guessed to
``unknown``, NEVER ``reconciliation_failed``.

No database, no session, no executor, no adapter I/O, no FastAPI.
"""
    return normalize_external_state(observation.adapter, observation.external_state)
