"""Shared test helpers."""

from typing import Any, Dict

from shanghaitech_ids_passkey import PasskeyKeystore
from shanghaitech_ids_passkey.config import DEFAULT_BASE_URL
from shanghaitech_ids_passkey._webauthn import create_registration_response


def sample_creation_options() -> Dict[str, Any]:
    return {
        "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "rp": {"id": "ids.shanghaitech.edu.cn", "name": "ShanghaiTech IDS"},
        "user": {
            "id": "VDRkb2tvcm9Lb2pp",
            "name": "2025114514",
            "displayName": "2025114514",
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -8},
        ],
        "excludeCredentials": [],
    }


def sample_request_options(credential_id: str) -> Dict[str, Any]:
    return {
        "challenge": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "rpId": "ids.shanghaitech.edu.cn",
        "allowCredentials": [{"type": "public-key", "id": credential_id}],
    }


def make_sample_keystore() -> PasskeyKeystore:
    _, metadata = create_registration_response(
        sample_creation_options(),
        origin=DEFAULT_BASE_URL,
    )
    return PasskeyKeystore(
        username="2025114514",
        anon_biometrics_id="0123456789abcdef0123456789abcdef",
        device_name="TEST-DEVICE",
        base_url=DEFAULT_BASE_URL,
        credential_id=metadata["credential_id"],
        rp_id=metadata["rp_id"],
        user_id=metadata["user_id"],
        alg=metadata["alg"],
        private_key_pem=metadata["private_key_pem"],
        sign_count=metadata["sign_count"],
        created_at=metadata["created_at"],
    )
