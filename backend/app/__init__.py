"""SentinelFlow backend package.

``__version__`` is the single source of the release identity: the FastAPI app
reads it for the OpenAPI ``version`` field, and ``tests/test_app_version.py``
pins the two together so they cannot drift apart. Bump this constant as part of
the release step, together with the matching doc headers and the CHANGELOG entry.
"""

# Current release identity. Kept in sync with the released git tag: the OpenAPI
# version, this constant and the release tag must agree. Bump this one line as
# part of the release step.
__version__ = "1.4.0-rc2"

__all__ = ["__version__"]
