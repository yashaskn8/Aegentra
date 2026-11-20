"""One-shot bounded raw block I/O inside a native isolated EC2 analysis guest.

A trusted bridge prewrites the input and separately allocates a blank output
device. Neither is mounted. A supervising systemd unit must impose a deadline
and memory, device and syscall limits. The guest has no AWS identity.
"""
from __future__ import annotations

import argparse
import os
import stat
import struct
from typing import BinaryIO

from aegentra.guest_protocol import (
    FrameError, GuestRequest, INPUT_MAGIC, MAX_HEADER, MAX_JS_BYTES,
    decode_input,
)
from aegentra.offline_guest import analyze_frame
from aegentra.content_manifest import strict_json


def _exact(stream: BinaryIO, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        part = stream.read(size - len(buffer))
        if not part:
            raise FrameError("truncated raw device frame")
        buffer.extend(part)
    return bytes(buffer)


def run_once(input_stream: BinaryIO, output_stream: BinaryIO) -> int:
    """Read one bounded raw input and write one bounded raw result.

    Raw EBS devices contain padding after the frame. Only the declared byte
    count is read and the bridge must independently authenticate the result.
    """
    prefix = _exact(input_stream, 8)
    if prefix[:4] != INPUT_MAGIC:
        raise FrameError("invalid raw input domain")
    length = struct.unpack(">I", prefix[4:])[0]
    if not 0 < length <= MAX_HEADER:
        raise FrameError("oversized or empty raw header")
    encoded_header = _exact(input_stream, length)
    try:
        header = GuestRequest.model_validate(strict_json(encoded_header, max_bytes=MAX_HEADER))
    except ValueError as exc:
        raise FrameError("invalid guest request header") from exc
    if not 1 <= header.byte_length <= MAX_JS_BYTES:
        raise FrameError("invalid guest payload budget")
    frame = prefix + encoded_header + _exact(input_stream, header.byte_length)
    # Strict validation (including canonical framing and checksum) is repeated
    # by analyze_frame before the static parser sees any bytes.
    decode_input(frame)
    output = analyze_frame(frame)
    written = output_stream.write(output)
    if written != len(output):
        raise FrameError("short output device write")
    output_stream.flush()
    return len(output)


def _open_device(path: str, *, writable: bool) -> BinaryIO:
    # Never follow symlinks or accept a regular file in production. The bridge
    # identifies the NVMe-to-EBS mapping during independent AMI qualification.
    flags = (os.O_WRONLY if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    if not stat.S_ISBLK(os.fstat(fd).st_mode):
        os.close(fd)
        raise FrameError("guest I/O path is not a raw block device")
    return os.fdopen(fd, "wb" if writable else "rb", buffering=0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline single-attempt guest")
    parser.add_argument("--input-device", required=True)
    parser.add_argument("--output-device", required=True)
    args = parser.parse_args()
    if args.input_device == args.output_device:
        raise SystemExit("input and output devices must differ")
    with _open_device(args.input_device, writable=False) as source:
        with _open_device(args.output_device, writable=True) as output:
            run_once(source, output)


if __name__ == "__main__":
    main()
