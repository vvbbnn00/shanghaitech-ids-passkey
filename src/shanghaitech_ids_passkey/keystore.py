"""Single-passkey keystore model and serialization helpers."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Union

from ._serde import default_serialize, default_unserialize
from ._utils import utc_now_isoformat
from .errors import KeystoreError


Serializer = Callable[[Dict[str, Any]], bytes]
Unserializer = Callable[[bytes], Mapping[str, Any]]
PathLike = Union[str, Path]


@dataclass
class PasskeyKeystore:
    """A single ShanghaiTech IDS passkey and its related login metadata."""

    username: str
    anon_biometrics_id: str
    device_name: str
    base_url: str
    credential_id: str
    rp_id: str
    user_id: str
    alg: int
    private_key_pem: str = field(repr=False)
    sign_count: int = 0
    created_at: str = ""

    def __post_init__(self) -> None:
        self.username = _require_str(self.username, "username")
        self.anon_biometrics_id = _require_str(
            self.anon_biometrics_id,
            "anon_biometrics_id",
        )
        self.device_name = _require_str(self.device_name, "device_name")
        self.base_url = _require_str(self.base_url, "base_url").rstrip("/")
        self.credential_id = _require_str(self.credential_id, "credential_id")
        self.rp_id = _require_str(self.rp_id, "rp_id")
        self.user_id = _require_str(self.user_id, "user_id")
        self.private_key_pem = _require_str(self.private_key_pem, "private_key_pem")
        try:
            self.alg = int(self.alg)
            self.sign_count = int(self.sign_count)
        except (TypeError, ValueError) as exc:
            raise KeystoreError("alg and sign_count must be integers") from exc
        if self.sign_count < 0:
            raise KeystoreError("sign_count must be non-negative")
        if not self.created_at:
            self.created_at = utc_now_isoformat()

    def to_dict(self, redact_private_key: bool = False) -> Dict[str, Any]:
        private_key_pem = "<redacted>" if redact_private_key else self.private_key_pem
        return {
            "username": self.username,
            "anon_biometrics_id": self.anon_biometrics_id,
            "device_name": self.device_name,
            "base_url": self.base_url,
            "credential_id": self.credential_id,
            "rp_id": self.rp_id,
            "user_id": self.user_id,
            "alg": self.alg,
            "private_key_pem": private_key_pem,
            "sign_count": self.sign_count,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PasskeyKeystore":
        if not isinstance(data, Mapping):
            raise KeystoreError("Keystore data must be a mapping")
        return cls(
            username=_require_str(data.get("username"), "username"),
            anon_biometrics_id=_require_str(
                data.get("anon_biometrics_id"),
                "anon_biometrics_id",
            ),
            device_name=_require_str(data.get("device_name"), "device_name"),
            base_url=_require_str(data.get("base_url"), "base_url"),
            credential_id=_require_str(data.get("credential_id"), "credential_id"),
            rp_id=_require_str(data.get("rp_id"), "rp_id"),
            user_id=_require_str(data.get("user_id"), "user_id"),
            alg=_require_int(data.get("alg"), "alg"),
            private_key_pem=_require_str(data.get("private_key_pem"), "private_key_pem"),
            sign_count=_require_int(data.get("sign_count", 0), "sign_count"),
            created_at=_require_str(data.get("created_at"), "created_at"),
        )

    def serialize(self, serializer: Optional[Serializer] = None) -> bytes:
        serializer_fn = serializer or default_serialize
        try:
            payload = serializer_fn(self.to_dict(redact_private_key=False))
        except KeystoreError:
            raise
        except Exception as exc:
            raise KeystoreError(f"Custom serializer failed: {exc}") from exc
        if not isinstance(payload, (bytes, bytearray)):
            raise KeystoreError("Serializer must return bytes")
        return bytes(payload)

    @classmethod
    def unserialize(
        cls,
        data: bytes,
        unserializer: Optional[Unserializer] = None,
    ) -> "PasskeyKeystore":
        unserializer_fn = unserializer or default_unserialize
        try:
            payload = unserializer_fn(data)
        except KeystoreError:
            raise
        except Exception as exc:
            raise KeystoreError(f"Custom unserializer failed: {exc}") from exc
        return cls.from_dict(payload)

    def dump(self, path: PathLike, serializer: Optional[Serializer] = None) -> None:
        target = Path(path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self.serialize(serializer=serializer))
        except OSError as exc:
            raise KeystoreError(f"Failed to write keystore file: {exc}") from exc

    @classmethod
    def load(
        cls,
        path: PathLike,
        unserializer: Optional[Unserializer] = None,
    ) -> "PasskeyKeystore":
        source = Path(path)
        try:
            payload = source.read_bytes()
        except FileNotFoundError as exc:
            raise KeystoreError(f"Keystore file not found: {source}") from exc
        except OSError as exc:
            raise KeystoreError(f"Failed to read keystore file: {exc}") from exc
        return cls.unserialize(payload, unserializer=unserializer)


def _require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise KeystoreError(f"{field_name} must be a non-empty string")
    return value


def _require_int(value: Any, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise KeystoreError(f"{field_name} must be an integer") from exc
