from shanghaitech_ids_passkey import (
    IDSClient,
    IDSConfig,
    IDSRequestError,
    KeystoreError,
    PasskeyKeystore,
    SeleniumBinder,
    SeleniumBindingError,
    ShanghaiTechIDsPasskeyError,
)


def test_public_imports() -> None:
    assert IDSClient is not None
    assert IDSConfig is not None
    assert IDSRequestError is not None
    assert KeystoreError is not None
    assert PasskeyKeystore is not None
    assert SeleniumBinder is not None
    assert SeleniumBindingError is not None
    assert ShanghaiTechIDsPasskeyError is not None
