import pytest
from pydantic import ValidationError

from aegentra.intake import ArtifactPart, IntakeManifest

DIGEST = "a" * 64


def part(path: str = "src/app.js", size: int = 100) -> dict:
    return {"path": path, "byte_length": size, "sha256": DIGEST}


def test_valid_metadata_has_stable_shadow_fingerprint() -> None:
    first = IntakeManifest.model_validate({"parts": [part("z.js"), part("a.js")]})
    second = IntakeManifest.model_validate({"parts": [part("a.js"), part("z.js")]})
    assert first.shadow_fingerprint() == second.shadow_fingerprint()
    assert first.total_bytes == 200


@pytest.mark.parametrize(
    "path",
    ["../secrets", "src/../secrets", "/absolute.js", "a\\b.js", "a//b.js", "a%2fb.js", "src/./a.js", "🧪.js"],
)
def test_reject_ambiguous_or_unsafe_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        ArtifactPart.model_validate(part(path))


def test_reject_duplicate_paths_and_case_aliases() -> None:
    with pytest.raises(ValidationError):
        IntakeManifest.model_validate({"parts": [part("A.js"), part("a.js")]})


def test_reject_excess_total_size() -> None:
    with pytest.raises(ValidationError):
        IntakeManifest.model_validate({"parts": [part("a.js", 10 * 1024 * 1024), part("b.js", 10 * 1024 * 1024), part("c.js", 10 * 1024 * 1024)]})


@pytest.mark.parametrize("invalid", ["A" * 64, "x" * 64, "a" * 63])
def test_digest_must_be_lowercase_sha256(invalid: str) -> None:
    with pytest.raises(ValidationError):
        ArtifactPart.model_validate({"path": "x.js", "byte_length": 1, "sha256": invalid})


def test_reject_unknown_fields_and_coercions() -> None:
    with pytest.raises(ValidationError):
        ArtifactPart.model_validate({**part(), "approved": True})
    with pytest.raises(ValidationError):
        ArtifactPart.model_validate({"path": "x.js", "byte_length": "1", "sha256": DIGEST})
