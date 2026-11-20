"""Canonical S3 object-prefix authorization for protected publication."""
from __future__ import annotations


def valid_origin_prefix(prefix: str) -> bool:
    """Only a non-root, directory-delimited published S3 prefix is enrolled."""
    return (
        isinstance(prefix, str)
        and prefix.startswith("published/")
        and len(prefix) > len("published/")
        and prefix.endswith("/")
        and len(prefix) < 256
        and "\\" not in prefix
        and "\x00" not in prefix
        and all(part not in ("", ".", "..") for part in prefix.split("/")[:-1])
    )


def origin_key_in_scope(prefix: str, key: str) -> bool:
    """S3 keys are opaque; require exact prefix segment boundaries, not near-matches."""
    return (
        valid_origin_prefix(prefix)
        and isinstance(key, str)
        and len(prefix) < len(key) <= 256
        and key.startswith(prefix)
        and "\\" not in key
        and "\x00" not in key
        and all(part not in ("", ".", "..") for part in key.split("/"))
    )
