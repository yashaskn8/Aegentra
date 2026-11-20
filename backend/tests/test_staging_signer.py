from uuid import uuid4

import pytest

from aegentra.staging_signer import StagingSigner


class FakeS3:
    def __init__(self) -> None:
        self.args = None

    def generate_presigned_url(self, *args, **kwargs) -> str:
        self.args = (args, kwargs)
        return "https://staging.example.test/signed-fixture"


def test_presigner_binds_object_key_length_mime_and_checksum() -> None:
    fake = FakeS3()
    signer = StagingSigner(client=fake, bucket="fixed-staging-bucket")
    issued = signer.issue(
        key=f"staging/{uuid4().hex}/{uuid4().hex}/part-00",
        sha256="a" * 64, byte_length=100,
        media_type="application/javascript",
    )
    assert issued.url.startswith("https://")
    assert issued.expires_seconds == 300
    assert issued.headers["Content-Length"] == "100"
    args, call = fake.args
    assert args == ("put_object",)
    assert call["HttpMethod"] == "PUT"
    assert call["Params"]["Bucket"] == "fixed-staging-bucket"
    assert call["Params"]["ChecksumSHA256"] == issued.headers["x-amz-checksum-sha256"]


@pytest.mark.parametrize("key,length", [
    ("other/file", 1), ("staging/thing", 0), ("staging/thing", 20 * 1024 * 1024),
])
def test_signer_denies_invalid_request(key: str, length: int) -> None:
    signer = StagingSigner(client=FakeS3(), bucket="fixed-staging-bucket")
    with pytest.raises(ValueError):
        signer.issue(
            key=key, sha256="a" * 64, media_type="application/javascript",
            byte_length=length,
        )
