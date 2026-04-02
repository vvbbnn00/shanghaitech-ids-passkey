"""Configuration helpers for ShanghaiTech IDS interactions."""

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


DEFAULT_BASE_URL = "https://ids.shanghaitech.edu.cn"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
)


@dataclass(frozen=True)
class IDSConfig:
    """Runtime configuration for ShanghaiTech IDS requests."""

    base_url: str = DEFAULT_BASE_URL
    origin: Optional[str] = None
    user_agent: str = DEFAULT_USER_AGENT
    timeout: float = 30.0
    verify_tls: bool = True

    def __post_init__(self) -> None:
        base_url = self._normalize_url(self.base_url, "base_url")
        origin = self._normalize_url(self.origin or base_url, "origin")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        object.__setattr__(self, "base_url", base_url)
        object.__setattr__(self, "origin", origin)

    @staticmethod
    def _normalize_url(value: str, field_name: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"{field_name} must be an absolute http(s) URL")
        return value.rstrip("/")
