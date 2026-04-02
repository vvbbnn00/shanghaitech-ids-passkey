"""HTTP client for ShanghaiTech IDS passkey login flows."""

import json
from typing import Any, Dict, Optional

import requests

from ._ids_api import (
    check_login_url,
    encode_username,
    extract_execution_value,
    expect_mapping,
    login_url,
    logout_url,
    start_assertion_url,
)
from ._webauthn import create_authentication_response
from .config import IDSConfig
from .errors import IDSRequestError
from .keystore import PasskeyKeystore


class IDSClient:
    """A high-level requests-based client for ShanghaiTech IDS."""

    def __init__(
        self,
        keystore: PasskeyKeystore,
        config: Optional[IDSConfig] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.keystore = keystore
        self.config = config or IDSConfig(base_url=keystore.base_url)
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", self.config.user_agent)

    def is_logged_in(self) -> bool:
        response = self._request(
            "GET",
            check_login_url(self.config),
            allow_redirects=False,
        )
        return response.status_code == 200

    def login(self) -> None:
        execution = self._get_execution_value()
        assertion = self._build_assertion_payload()
        response = self._request(
            "POST",
            login_url(self.config),
            data={
                "_eventId": "submit",
                "responseJson": json.dumps(assertion, ensure_ascii=False),
                "username": encode_username(self.keystore.username),
                "cllt": "fidoLogin",
                "dllt": "generalLogin",
                "lt": "",
                "execution": execution,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
        )
        self._raise_for_status(response, "IDS login")
        if not self.is_logged_in():
            raise IDSRequestError("IDS login failed")

    def logout(self) -> None:
        response = self._request("GET", logout_url(self.config))
        self._raise_for_status(response, "IDS logout")

    def ensure_logged_in(self) -> None:
        if not self.is_logged_in():
            self.login()

    def get_service(
        self,
        service_url: str,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        self.ensure_logged_in()
        response = self._request(
            "GET",
            service_url,
            allow_redirects=allow_redirects,
            **kwargs,
        )
        self._raise_for_status(response, "service GET")
        return response

    def _build_assertion_payload(self) -> Dict[str, Any]:
        response = self._request(
            "POST",
            start_assertion_url(self.config),
            json={
                "userId": encode_username(self.keystore.username),
                "id": self.keystore.anon_biometrics_id,
            },
        )
        self._raise_for_status(response, "start assertion")
        data = self._response_json(response, "start assertion")
        result = expect_mapping(data.get("result"), "start assertion result")
        request = expect_mapping(result.get("request"), "start assertion request")
        request_options = expect_mapping(
            request.get("publicKeyCredentialRequestOptions"),
            "publicKeyCredentialRequestOptions",
        )
        assertion, new_sign_count = create_authentication_response(
            request_options=request_options,
            origin=self.config.origin or self.config.base_url,
            credential_id_b64=self.keystore.credential_id,
            alg=self.keystore.alg,
            private_key_pem=self.keystore.private_key_pem,
            sign_count=self.keystore.sign_count,
            user_handle_b64=self.keystore.user_id,
        )
        self.keystore.sign_count = new_sign_count
        return {
            "requestId": request.get("requestId"),
            "credential": assertion,
            "sessionToken": None,
        }

    def _get_execution_value(self) -> str:
        response = self._request("GET", login_url(self.config))
        self._raise_for_status(response, "fetch login page")
        return extract_execution_value(response.text)

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_tls)
        try:
            return self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            raise IDSRequestError(f"{method} {url} failed: {exc}") from exc

    @staticmethod
    def _raise_for_status(response: requests.Response, action: str) -> None:
        try:
            response.raise_for_status()
        except requests.RequestException as exc:
            raise IDSRequestError(
                "{0} failed with HTTP {1}".format(action, response.status_code),
            ) from exc

    @staticmethod
    def _response_json(response: requests.Response, action: str) -> Dict[str, Any]:
        try:
            data = response.json()
        except ValueError as exc:
            raise IDSRequestError(f"{action} did not return valid JSON") from exc
        if not isinstance(data, dict):
            raise IDSRequestError(f"{action} did not return a JSON object")
        return data
