import requests

from shanghaitech_ids_passkey import IDSConfig, SeleniumBinder
from shanghaitech_ids_passkey import selenium_bind as selenium_bind_module

from .helpers import sample_creation_options


class FakeResponse:
    def __init__(self, json_data):
        self.status_code = 200
        self._json_data = json_data

    def raise_for_status(self):
        return None

    def json(self):
        return self._json_data


class FakeHTTPSession:
    def __init__(self):
        self.headers = {}
        self.cookies = requests.cookies.RequestsCookieJar()
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if "isUserRecheckNecessary" in url:
            return FakeResponse({"code": "0"})
        if "startRegister" in url:
            return FakeResponse(
                {
                    "datas": {
                        "request": {
                            "requestId": "req-1",
                            "username": "2025114514",
                            "publicKeyCredentialCreationOptions": sample_creation_options(),
                        },
                    },
                },
            )
        if "finishRegister" in url:
            return FakeResponse({"code": "0"})
        raise AssertionError("Unexpected HTTP call: {0} {1}".format(method, url))


class FakeElement:
    def __init__(self):
        self.clicked = False

    def click(self):
        self.clicked = True


class FakeDriver:
    def __init__(self):
        self.cookies = [{"name": "CASTGC", "value": "cookie-value"}]
        self.urls = []
        self.closed = False
        self.account_tab = FakeElement()
        self.bind_button = FakeElement()

    def get(self, url):
        self.urls.append(url)

    def get_cookies(self):
        return list(self.cookies)

    def quit(self):
        self.closed = True

    def lookup(self, locator):
        value = locator[1]
        if value == selenium_bind_module._SIDEBAR_ACCOUNT_SECURITY_XPATH:
            return self.account_tab
        if value == selenium_bind_module._BIND_BUTTON_XPATH:
            return self.bind_button
        return object()


class FakeWait:
    def __init__(self, driver, timeout, poll_frequency=0.2, ignored_exceptions=None):
        self.driver = driver

    def until(self, condition):
        return condition(self.driver)


class FakeExpectedConditions:
    @staticmethod
    def visibility_of_element_located(locator):
        return lambda driver: driver.lookup(locator)

    @staticmethod
    def presence_of_element_located(locator):
        return lambda driver: driver.lookup(locator)


class FakeBy:
    XPATH = "xpath"
    TAG_NAME = "tag_name"


def test_selenium_binder_returns_single_keystore(monkeypatch) -> None:
    fake_driver = FakeDriver()
    fake_session = FakeHTTPSession()

    monkeypatch.setattr(selenium_bind_module, "_load_selenium", lambda: {
        "NoSuchElementException": Exception,
        "ElementNotInteractableException": Exception,
        "WebDriverWait": FakeWait,
        "EC": FakeExpectedConditions,
        "By": FakeBy,
    })
    monkeypatch.setattr(selenium_bind_module.requests, "Session", lambda: fake_session)

    binder = SeleniumBinder(
        config=IDSConfig(),
        driver_factory=lambda: fake_driver,
        timeout=1,
    )
    keystore = binder.bind(device_name="TEST-BIND")

    assert keystore.username == "2025114514"
    assert keystore.device_name == "TEST-BIND"
    assert keystore.rp_id == "ids.shanghaitech.edu.cn"
    assert fake_driver.account_tab.clicked is True
    assert fake_driver.bind_button.clicked is True
    assert fake_driver.closed is True


def test_create_driver_ignores_stale_driver_in_path(monkeypatch, tmp_path) -> None:
    stale_driver_dir = tmp_path / "stale-driver"
    safe_dir = tmp_path / "safe-bin"
    stale_driver_dir.mkdir()
    safe_dir.mkdir()
    (stale_driver_dir / "chromedriver").write_text("", encoding="utf-8")

    observed_path = {}

    class FakeWebDriver:
        @staticmethod
        def Chrome():
            observed_path["value"] = selenium_bind_module.os.environ.get("PATH", "")
            return object()

    monkeypatch.setattr(
        selenium_bind_module.os,
        "environ",
        {
            "PATH": selenium_bind_module.os.pathsep.join(
                [str(stale_driver_dir), str(safe_dir)],
            ),
        },
    )

    driver = selenium_bind_module._create_driver(
        {"webdriver": FakeWebDriver},
        "chrome",
    )

    assert driver is not None
    assert str(stale_driver_dir) not in observed_path["value"]
    assert str(safe_dir) in observed_path["value"]
