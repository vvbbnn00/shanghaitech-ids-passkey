"""Public exception types."""


class ShanghaiTechIDsPasskeyError(Exception):
    """Base exception for the package."""


class KeystoreError(ShanghaiTechIDsPasskeyError):
    """Raised when keystore serialization or validation fails."""


class IDSRequestError(ShanghaiTechIDsPasskeyError):
    """Raised when ShanghaiTech IDS requests or protocol handling fails."""


class SeleniumBindingError(ShanghaiTechIDsPasskeyError):
    """Raised when Selenium-based binding or smoke tests fail."""
