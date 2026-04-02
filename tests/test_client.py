import json

import requests

from shanghaitech_ids_passkey import IDSClient
from shanghaitech_ids_passkey.config import IDSConfig

from .helpers import make_sample_keystore, sample_request_options


class FakeResponse:
    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self.text = text
        self._json_data = json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)

    def json(self):
        return self._json_data


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.cookies = requests.cookies.RequestsCookieJar()

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return self.responses.pop(0)


def test_login_updates_sign_count_and_posts_expected_payload() -> None:
    keystore = make_sample_keystore()
    session = FakeSession(
        [
            FakeResponse(text='<input name="execution" value="e1" />'),
            FakeResponse(
                json_data={
                    "result": {
                        "request": {
                            "requestId": "req-1",
                            "publicKeyCredentialRequestOptions": sample_request_options(
                                keystore.credential_id,
                            ),
                        },
                    },
                },
            ),
            FakeResponse(text="ok"),
            FakeResponse(status_code=200, json_data={}),
        ],
    )

    client = IDSClient(keystore, config=IDSConfig(), session=session)
    client.login()

    assert keystore.sign_count == 1
    assert session.calls[1]["kwargs"]["json"]["id"] == keystore.anon_biometrics_id
    response_json = json.loads(session.calls[2]["kwargs"]["data"]["responseJson"])
    assert response_json["credential"]["id"] == keystore.credential_id


def test_get_service_reuses_login_flow() -> None:
    keystore = make_sample_keystore()
    session = FakeSession(
        [
            FakeResponse(status_code=302, json_data={}),
            FakeResponse(text='<input name="execution" value="e2" />'),
            FakeResponse(
                json_data={
                    "result": {
                        "request": {
                            "requestId": "req-2",
                            "publicKeyCredentialRequestOptions": sample_request_options(
                                keystore.credential_id,
                            ),
                        },
                    },
                },
            ),
            FakeResponse(text="ok"),
            FakeResponse(status_code=200, json_data={}),
            FakeResponse(status_code=200, text="service-ok"),
        ],
    )

    client = IDSClient(keystore, config=IDSConfig(), session=session)
    response = client.get_service("https://service.example/path")

    assert response.text == "service-ok"
    assert session.calls[-1]["url"] == "https://service.example/path"
    assert session.calls[-1]["kwargs"]["allow_redirects"] is True
