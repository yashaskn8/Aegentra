"""Bridge output is bounded even when the raw device has stale tail bytes."""
import io
import struct
import hashlib
from uuid import uuid4

import pytest

from aegentra.bridge_io import read_raw_output
from aegentra.guest_protocol import FrameError, GuestRequest, encode_input
from aegentra.offline_guest import analyze_frame


def fixture() -> bytes:
    src = b"const x = 1;"
    req = GuestRequest(
        kind="aegentra.guest.input.v1",
        org_id=uuid4(), job_id=uuid4(), generation=2,
        nonce="a" * 43, source_sha256=hashlib.sha256(src).hexdigest(),
        toolchain_sha256="f" * 64, byte_length=len(src),
    )
    return analyze_frame(encode_input(req, src))


def test_read_one_bounded_output_without_raw_device_tail() -> None:
    result = fixture()
    stream = io.BytesIO(result + bytes(4096))
    raw, parsed = read_raw_output(stream)
    assert raw == result
    assert stream.tell() == len(result)
    assert parsed.coverage == "VERIFIED"


@pytest.mark.parametrize("kind", ["missing", "truncated", "oversized", "wrong_magic"])
def test_bad_raw_output_rejected_before_trust(kind: str) -> None:
    sample = fixture()
    if kind == "missing":
        sample = b""
    elif kind == "truncated":
        sample = sample[:-1]
    elif kind == "oversized":
        sample = sample[:4] + struct.pack(">I", 1024 * 1024 + 1) + sample[8:]
    else:
        sample = b"NOPE" + sample[4:]
    with pytest.raises(FrameError):
        read_raw_output(io.BytesIO(sample))
