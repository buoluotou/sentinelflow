"""SentinelFlow backend package.

``__version__`` is the SINGLE source of the release identity: the FastAPI app
reads it for the OpenAPI ``version`` field, and ``tests/test_app_version.py``
pins the two together so they cannot drift apart again (the OpenAPI version once
lagged a whole release behind the tag). Bump this ONE constant as part of the
release step, together with the matching doc headers and the CHANGELOG entry.
"""

#: Current release identity. The shipped line's HEAD is the annotated tag
#: ``v1.4.0-rc1``; bump to the next release BEFORE tagging it.
__version__ = "1.4.0-rc1"

__all__ = ["__version__"]
