import json

from shanghaitech_ids_passkey import PasskeyKeystore

from .helpers import make_sample_keystore


def test_binary_round_trip(tmp_path) -> None:
    keystore = make_sample_keystore()
    path = tmp_path / "sample.keystore"

    keystore.dump(path)
    restored = PasskeyKeystore.load(path)

    assert restored.to_dict() == keystore.to_dict()


def test_custom_serializer_round_trip(tmp_path) -> None:
    keystore = make_sample_keystore()
    path = tmp_path / "sample.json"

    keystore.dump(
        path,
        serializer=lambda payload: json.dumps(payload, sort_keys=True).encode("utf-8"),
    )
    restored = PasskeyKeystore.load(
        path,
        unserializer=lambda blob: json.loads(blob.decode("utf-8")),
    )

    assert restored.username == keystore.username
    assert restored.private_key_pem == keystore.private_key_pem


def test_redacted_dict_hides_private_key() -> None:
    keystore = make_sample_keystore()

    redacted = keystore.to_dict(redact_private_key=True)

    assert redacted["private_key_pem"] == "<redacted>"
    assert redacted["credential_id"] == keystore.credential_id
