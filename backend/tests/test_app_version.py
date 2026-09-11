"""Release identity — ONE source of truth for the version string.

The FastAPI OpenAPI ``version`` drifted from the shipped release: it still read
``1.3.0`` while HEAD was already tagged ``v1.4.0-rc1``. ``app.main`` now reads
``app.__version__``, and these tests pin the two together so they cannot
disagree again — a release bump is a ONE-line change in ``backend/app/__init__.py``.
"""
import re

from app import __version__
from app.main import app


class TestReleaseIdentity:
    def test_fastapi_version_comes_from_the_package_constant(self):
        assert app.version == __version__

    def test_openapi_document_reports_the_same_version(self):
        # The value clients actually see on GET /openapi.json.
        assert app.openapi()["info"]["version"] == __version__

    def test_version_is_a_release_identity_not_a_stale_label(self):
        # "1.4.0-rc1" / "1.3.0" — never empty, never a commit hash, and never
        # the pre-RC string the OpenAPI field was stuck on.
        assert re.fullmatch(r"\d+\.\d+\.\d+(?:-rc\d+)?", __version__), __version__
        assert __version__ != "1.3.0"
