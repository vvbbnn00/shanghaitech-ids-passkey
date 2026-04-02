"""Public package interface for ShanghaiTech IDS passkey support."""

from .client import IDSClient
from .config import IDSConfig
from .errors import (
    IDSRequestError,
    KeystoreError,
    SeleniumBindingError,
    ShanghaiTechIDsPasskeyError,
)
from .keystore import PasskeyKeystore
from .selenium_bind import SeleniumBinder

__all__ = [
    "IDSClient",
    "IDSConfig",
    "IDSRequestError",
    "KeystoreError",
    "PasskeyKeystore",
    "SeleniumBinder",
    "SeleniumBindingError",
    "ShanghaiTechIDsPasskeyError",
]

__version__ = "0.1.0"
