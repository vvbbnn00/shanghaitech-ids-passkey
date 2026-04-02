"""Internal WebAuthn helpers used by ShanghaiTech IDS flows."""

import os
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from ._utils import b64url_encode, json_dumps_canonical, utc_now_isoformat
from .errors import IDSRequestError


AAGUID_ZERO = b"\x00" * 16


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def serialize_private_key_pem(private_key: Any) -> str:
    try:
        payload = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except Exception as exc:
        raise IDSRequestError(f"Failed to serialize private key: {exc}") from exc
    return payload.decode("ascii")


def load_private_key_pem(pem_text: str) -> Any:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        return load_pem_private_key(pem_text.encode("ascii"), password=None)
    except Exception as exc:
        raise IDSRequestError(f"Failed to load private key: {exc}") from exc


def create_registration_response(
    creation_options: Mapping[str, Any],
    origin: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    rp = _expect_mapping(creation_options.get("rp"), "creation_options.rp")
    user = _expect_mapping(creation_options.get("user"), "creation_options.user")
    rp_id = _expect_string(rp.get("id"), "creation_options.rp.id")
    user_id = _expect_string(user.get("id"), "creation_options.user.id")
    challenge = _expect_string(
        creation_options.get("challenge"),
        "creation_options.challenge",
    )
    if not _rp_id_matches_origin(rp_id, origin):
        raise IDSRequestError("origin does not match rpId for registration")
    pub_key_params = creation_options.get("pubKeyCredParams")
    if not isinstance(pub_key_params, list) or not pub_key_params:
        raise IDSRequestError("creation_options.pubKeyCredParams is required")

    alg = _pick_alg(pub_key_params)
    excluded = _excluded_credential_ids(creation_options.get("excludeCredentials") or [])
    credential_id = _generate_credential_id(excluded)
    private_key = _generate_keypair(alg)
    cose_public_key = _cose_key_from_private_key(private_key, alg)
    auth_data = _build_authenticator_data_for_create(
        rp_id,
        sign_count=0,
        credential_id=credential_id,
        cose_public_key=cose_public_key,
    )
    client_data = _build_client_data_json(
        typ="webauthn.create",
        challenge_b64url=challenge,
        origin=origin,
    )
    attestation_object = _cbor_dumps(
        {
            "fmt": "none",
            "authData": auth_data,
            "attStmt": {},
        },
    )
    credential_id_b64 = b64url_encode(credential_id)
    return (
        {
            "type": "public-key",
            "id": credential_id_b64,
            "response": {
                "attestationObject": b64url_encode(attestation_object),
                "clientDataJSON": b64url_encode(client_data),
            },
            "clientExtensionResults": {},
        },
        {
            "credential_id": credential_id_b64,
            "rp_id": rp_id,
            "user_id": user_id,
            "alg": alg,
            "private_key_pem": serialize_private_key_pem(private_key),
            "sign_count": 0,
            "created_at": utc_now_isoformat(),
        },
    )


def create_authentication_response(
    request_options: Mapping[str, Any],
    origin: str,
    credential_id_b64: str,
    alg: int,
    private_key_pem: str,
    sign_count: int,
    user_handle_b64: Optional[str],
) -> Tuple[Dict[str, Any], int]:
    rp_id = _expect_string(request_options.get("rpId"), "request_options.rpId")
    challenge = _expect_string(
        request_options.get("challenge"),
        "request_options.challenge",
    )
    if not _rp_id_matches_origin(rp_id, origin):
        raise IDSRequestError("origin does not match rpId for authentication")

    allow_credentials = request_options.get("allowCredentials")
    if isinstance(allow_credentials, list) and allow_credentials:
        allow_ids = [
            item.get("id")
            for item in allow_credentials
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        ]
        if credential_id_b64 not in allow_ids:
            raise IDSRequestError("Stored credential is not in allowCredentials")

    new_sign_count = int(sign_count) + 1
    auth_data = _build_authenticator_data_for_get(
        rp_id,
        sign_count=new_sign_count,
        user_verification=False,
    )
    client_data = _build_client_data_json(
        typ="webauthn.get",
        challenge_b64url=challenge,
        origin=origin,
    )
    to_sign = auth_data + _sha256(client_data)
    signature = _sign_assertion(
        load_private_key_pem(private_key_pem),
        alg,
        to_sign,
    )
    assertion = {
        "type": "public-key",
        "id": credential_id_b64,
        "response": {
            "authenticatorData": b64url_encode(auth_data),
            "clientDataJSON": b64url_encode(client_data),
            "signature": b64url_encode(signature),
        },
        "clientExtensionResults": {},
    }
    if user_handle_b64:
        assertion["response"]["userHandle"] = user_handle_b64
    return assertion, new_sign_count


def _expect_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise IDSRequestError(f"{field_name} must be a non-empty string")
    return value


def _expect_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IDSRequestError(f"{field_name} must be an object")
    return value


def _parse_origin_host(origin: str) -> str:
    parsed = urlparse(origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise IDSRequestError(f"Invalid origin: {origin}")
    return parsed.hostname or ""


def _rp_id_matches_origin(rp_id: str, origin: str) -> bool:
    host = _parse_origin_host(origin)
    return host == rp_id or host.endswith("." + rp_id)


def _build_client_data_json(
    typ: str,
    challenge_b64url: str,
    origin: str,
) -> bytes:
    return json_dumps_canonical(
        {
            "type": typ,
            "challenge": challenge_b64url,
            "origin": origin,
            "crossOrigin": False,
        },
    )


def _excluded_credential_ids(excluded_credentials: Iterable[Any]) -> List[str]:
    excluded = []
    for item in excluded_credentials:
        if isinstance(item, Mapping) and isinstance(item.get("id"), str):
            excluded.append(item["id"])
    return excluded


def _generate_credential_id(excluded_ids: Iterable[str]) -> bytes:
    excluded = set(excluded_ids)
    for _ in range(20):
        candidate = os.urandom(32)
        candidate_b64 = b64url_encode(candidate)
        if candidate_b64 not in excluded:
            return candidate
    raise IDSRequestError("Failed to generate a credential ID")


def _generate_keypair(alg: int) -> Any:
    if alg == -7:
        return ec.generate_private_key(ec.SECP256R1())
    if alg == -8:
        return ed25519.Ed25519PrivateKey.generate()
    if alg == -257:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise IDSRequestError(f"Unsupported COSE alg: {alg}")


def _cose_key_from_private_key(private_key: Any, alg: int) -> Dict[int, Any]:
    public_key = private_key.public_key()
    if alg == -7:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise IDSRequestError("Unexpected public key type for ES256")
        public_numbers = public_key.public_numbers()
        return {
            1: 2,
            3: -7,
            -1: 1,
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
    if alg == -8:
        return {
            1: 1,
            3: -8,
            -1: 6,
            -2: public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        }
    if alg == -257:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise IDSRequestError("Unexpected public key type for RS256")
        public_numbers = public_key.public_numbers()
        return {
            1: 3,
            3: -257,
            -1: _int_to_bytes(public_numbers.n),
            -2: _int_to_bytes(public_numbers.e),
        }
    raise IDSRequestError(f"Unsupported COSE alg: {alg}")


def _pick_alg(pub_key_cred_params: List[Dict[str, Any]]) -> int:
    offered = []
    for item in pub_key_cred_params:
        try:
            offered.append(int(item.get("alg")))
        except Exception:
            continue
    for alg in (-7, -8, -257):
        if alg in offered:
            return alg
    raise IDSRequestError("No supported COSE algorithm was offered")


def _build_authenticator_data_for_create(
    rp_id: str,
    sign_count: int,
    credential_id: bytes,
    cose_public_key: Dict[int, Any],
) -> bytes:
    flags = 0x01 | 0x40
    payload = bytearray()
    payload += _sha256(rp_id.encode("utf-8"))
    payload += bytes([flags])
    payload += sign_count.to_bytes(4, "big")
    payload += AAGUID_ZERO
    payload += len(credential_id).to_bytes(2, "big")
    payload += credential_id
    payload += _cbor_dumps(cose_public_key)
    return bytes(payload)


def _build_authenticator_data_for_get(
    rp_id: str,
    sign_count: int,
    user_verification: bool,
) -> bytes:
    flags = 0x01
    if user_verification:
        flags |= 0x04
    return _sha256(rp_id.encode("utf-8")) + bytes([flags]) + sign_count.to_bytes(4, "big")


def _sign_assertion(private_key: Any, alg: int, payload: bytes) -> bytes:
    try:
        if alg == -7:
            return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        if alg == -8:
            return private_key.sign(payload)
        if alg == -257:
            return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        raise IDSRequestError(f"Failed to sign WebAuthn assertion: {exc}") from exc
    raise IDSRequestError(f"Unsupported COSE alg: {alg}")


def _int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _cbor_dumps(obj: Any) -> bytes:
    return _cbor_encode(obj)


def _cbor_encode(obj: Any) -> bytes:
    if obj is None:
        return b"\xf6"
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if isinstance(obj, int):
        if obj >= 0:
            return _cbor_encode_type_and_length(0, obj)
        return _cbor_encode_type_and_length(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_encode_type_and_length(2, len(obj)) + obj
    if isinstance(obj, str):
        encoded = obj.encode("utf-8")
        return _cbor_encode_type_and_length(3, len(encoded)) + encoded
    if isinstance(obj, (list, tuple)):
        payload = bytearray()
        payload += _cbor_encode_type_and_length(4, len(obj))
        for item in obj:
            payload += _cbor_encode(item)
        return bytes(payload)
    if isinstance(obj, dict):
        payload = bytearray()
        payload += _cbor_encode_type_and_length(5, len(obj))
        items = list(obj.items())
        items.sort(key=lambda item: (_cbor_key_group(item[0]), _cbor_encode(item[0])))
        for key, value in items:
            payload += _cbor_encode(key)
            payload += _cbor_encode(value)
        return bytes(payload)
    raise TypeError(f"Unsupported CBOR type: {type(obj)!r}")


def _cbor_encode_type_and_length(major_type: int, length: int) -> bytes:
    if length <= 23:
        return bytes([(major_type << 5) | length])
    if length <= 0xFF:
        return bytes([(major_type << 5) | 24, length])
    if length <= 0xFFFF:
        return bytes([(major_type << 5) | 25]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFFFF:
        return bytes([(major_type << 5) | 26]) + length.to_bytes(4, "big")
    return bytes([(major_type << 5) | 27]) + length.to_bytes(8, "big")


def _cbor_key_group(value: Any) -> int:
    if isinstance(value, int):
        return 0
    if isinstance(value, str):
        return 1
    if isinstance(value, bytes):
        return 2
    return 3
