"""No block devices needed: fixed inert byte streams exercise raw protocol."""
import io
import struct
from uuid import uuid4
import hashlib

import pytest

from aegentra.guest_io import run_once
from aegentra.guest_protocol import (
    FrameError, GuestRequest, decode_output, encode_input,
)


def fixture() -> bytes:
    source = b"const answer = 1;"
    request = GuestRequest(
        kind="aegentra.guest.input.v1",
        org_id=uuid4(), job_id=uuid4(), generation=1,
        nonce="n" * 43, source_sha256=hashlib.sha256(source).hexdigest(),
        toolchain_sha256="c" * 64, byte_length=len(source),
    )
    return encode_input(request, source)


def test_raw_input_consumes_only_declared_length_and_writes_bounded_output() -> None:
    frame = fixture()
    reader = io.BytesIO(frame + bytes(2048))  # raw device padding
    writer = io.BytesIO()
    count = run_once(reader, writer)
    assert count == len(writer.getvalue())
    assert reader.tell() == len(frame)
    assert decode_output(writer.getvalue()).coverage == "VERIFIED"


@pytest.mark.parametrize("tamper", ["wrong_magic", "short", "oversized_header"])
def test_device_frame_errors_never_write_result(tamper: str) -> None:
    raw = fixture()
    if tamper == "wrong_magic":
        raw = b"XXXX" + raw[4:]
    elif tamper == "short":
        raw = raw[:-4]
    else:
        raw = raw[:4] + struct.pack(">I", 10_000) + raw[8:]
    out = io.BytesIO()
    with pytest.raises(FrameError):
        run_once(io.BytesIO(raw), out)
    assert out.getvalue() == b""


def test_output_short_write_is_detected() -> None:
    class ShortWriter(io.BytesIO):
        def write(self, data):
            super().write(data[:2])
            return 2

    with pytest.raises(FrameError, match="short output"):
        run_once(io.BytesIO(fixture()), ShortWriter())
