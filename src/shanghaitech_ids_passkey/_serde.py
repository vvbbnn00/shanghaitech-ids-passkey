"""Default binary serialization helpers for keystores."""

import json
import zlib
from typing import Any, Mapping

from .errors import KeystoreError


_MAGIC = b"SHTUIDSPASSKEY\x01"


def default_serialize(data: Mapping[str, Any]) -> bytes:
    try:
        payload = json.dumps(
            dict(data),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except Exception as exc:
        raise KeystoreError(f"Failed to encode keystore payload: {exc}") from exc
    return _MAGIC + zlib.compress(payload)


def default_unserialize(blob: bytes) -> Mapping[str, Any]:
    if not isinstance(blob, (bytes, bytearray)):
        raise KeystoreError("Serialized keystore must be bytes")
    raw = bytes(blob)
    if not raw.startswith(_MAGIC):
        raise KeystoreError("Unsupported keystore format")
    try:
        payload = zlib.decompress(raw[len(_MAGIC) :])
        data = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise KeystoreError(f"Failed to decode keystore payload: {exc}") from exc
    if not isinstance(data, dict):
        raise KeystoreError("Decoded keystore payload must be an object")
    return data
