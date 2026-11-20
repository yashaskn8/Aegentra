"""Trusted bridge read of one bounded raw output frame after verified detach.

The bridge never mounts guest-produced storage or follows filesystem links.
Actual device identity must be independently bound to the recorded EBS volume.
"""
from __future__ import annotations

import os
import stat
import struct
from typing import BinaryIO

from aegentra.guest_protocol import (
    FrameError, OUTPUT_MAGIC, MAX_RESULT, GuestResponse, decode_output,
)


def _exact(source: BinaryIO, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = source.read(size - len(result))
        if not chunk:
            raise FrameError("raw output is truncated")
        result.extend(chunk)
    return bytes(result)


def read_raw_output(source: BinaryIO) -> tuple[bytes, GuestResponse]:
    """Do not read arbitrary device tail or trust a guest-declared size."""
    prefix = _exact(source, 8)
    if prefix[:4] != OUTPUT_MAGIC:
        raise FrameError("unexpected raw output domain")
    length = struct.unpack(">I", prefix[4:])[0]
    if not 0 < length <= MAX_RESULT:
        raise FrameError("raw output exceeds 1 MiB budget")
    raw = prefix + _exact(source, length)
    return raw, decode_output(raw)


def read_detached_block_device(path: str) -> tuple[bytes, GuestResponse]:
    """Caller first checks pinned EBS identity and two-pass detached custody."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    if not stat.S_ISBLK(os.fstat(fd).st_mode):
        os.close(fd)
        raise FrameError("bridge output is not a raw block device")
    with os.fdopen(fd, "rb", buffering=0) as stream:
        return read_raw_output(stream)
