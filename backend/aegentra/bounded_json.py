"""Bounded JSON parsing of inert evidence before schema validation."""
from __future__ import annotations

import json
import math

from aegentra.intake import MAX_TOTAL_BYTES


class ManifestError(ValueError):
    pass


def _reject_duplicate_keys(items: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in items:
        if key in result:
            raise ManifestError("duplicate JSON property")
        result[key] = value
    return result


def strict_json(data: bytes, *, max_bytes: int = MAX_TOTAL_BYTES) -> object:
    """Require strict UTF-8, bounded nesting and unambiguous JSON values."""
    if len(data) > max_bytes:
        raise ManifestError("JSON exceeds size limit")
    _check_json_depth(data)
    try:
        # Passing bytes directly lets json.loads auto-detect UTF-16/32 and
        # strip a BOM. SA-1.1 requires one UTF-8 wire representation.
        return json.loads(
            data.decode("utf-8", errors="strict"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ManifestError("nonstandard JSON constant")
            ),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_finite_float,
        )
    except ManifestError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ManifestError("invalid JSON") from exc


def _finite_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ManifestError("non-finite JSON number")
    return value


def _check_json_depth(data: bytes, *, max_depth: int = 128) -> None:
    """Bound container nesting before Python's JSON decoder allocates objects."""
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:  # Backslash may escape the following quote.
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):  # [ {
            depth += 1
            if depth > max_depth:
                raise ManifestError("JSON exceeds nesting depth")
        elif byte in (93, 125):  # ] }
            depth -= 1
