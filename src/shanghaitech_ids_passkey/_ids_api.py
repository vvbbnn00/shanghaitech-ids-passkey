"""Internal helpers for ShanghaiTech IDS endpoints and payloads."""

import base64
import re
import secrets
import time
from typing import Any, Dict

from .config import IDSConfig
from .errors import IDSRequestError


def login_url(config: IDSConfig) -> str:
    return config.base_url + "/authserver/login"


def logout_url(config: IDSConfig) -> str:
    return config.base_url + "/authserver/logout"


def start_assertion_url(config: IDSConfig) -> str:
    return config.base_url + "/authserver/startAssertion"


def check_login_url(config: IDSConfig) -> str:
    return config.base_url + "/personalInfo/common/tenant/info?t={0}".format(
        int(time.time()),
    )


def person_center_url(config: IDSConfig) -> str:
    return config.base_url + "/personalInfo/personCenter/index.html"


def is_user_recheck_necessary_url(config: IDSConfig) -> str:
    return (
        config.base_url
        + "/personalInfo/common/isUserRecheckNecessary?t={0}".format(int(time.time()))
    )


def start_register_url(config: IDSConfig) -> str:
    return config.base_url + "/personalInfo/accountSecurity/startRegister"


def finish_register_url(config: IDSConfig) -> str:
    return config.base_url + "/personalInfo/accountSecurity/finishRegister"


def build_nonce() -> str:
    return "0." + str(secrets.randbits(30))


def build_anon_biometrics_id() -> str:
    return secrets.token_hex(16)


def build_device_name() -> str:
    return "SHTU-PASSKEY-{0}".format(int(time.time()))


def encode_username(username: str) -> str:
    return base64.b64encode(username.encode("utf-8")).decode("ascii")


def extract_execution_value(html: str) -> str:
    match = re.search(r'name="execution" value="([^"]+)"', html)
    if not match:
        raise IDSRequestError("Failed to extract execution value from IDS login page")
    return match.group(1)


def expect_mapping(value: Any, field_name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise IDSRequestError("Expected an object for {0}".format(field_name))
    return value
