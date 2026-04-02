"""Selenium-assisted passkey binding helpers."""

import contextlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, TYPE_CHECKING

import requests

from ._ids_api import (
    build_anon_biometrics_id,
    build_device_name,
    build_nonce,
    expect_mapping,
    finish_register_url,
    is_user_recheck_necessary_url,
    person_center_url,
    start_register_url,
)
from ._webauthn import create_registration_response
from .config import IDSConfig
from .errors import IDSRequestError, SeleniumBindingError
from .keystore import PasskeyKeystore


if TYPE_CHECKING:
    from selenium.webdriver.remote.webdriver import WebDriver


LOGGER = logging.getLogger(__name__)

_SIDEBAR_ACCOUNT_SECURITY_XPATH = '//*[@id="app"]/div/div[2]/div/div/div[1]/ul/li[4]'
_BIND_BUTTON_XPATH = (
    '//*[@id="app"]/div/div[2]/div/div/div[2]/div/div/div/div[5]/div/div[6]/div[1]/button'
)


class SeleniumBinder:
    """Bind a ShanghaiTech IDS passkey through a real browser session."""

    def __init__(
        self,
        config: Optional[IDSConfig] = None,
        browser: str = "chrome",
        timeout: float = 600,
        driver_factory: Optional[Callable[[], "WebDriver"]] = None,
    ) -> None:
        self.config = config or IDSConfig()
        self.browser = browser.lower()
        self.timeout = timeout
        self.driver_factory = driver_factory

    def bind(self, device_name: Optional[str] = None) -> PasskeyKeystore:
        selenium = _load_selenium()
        driver = self.driver_factory() if self.driver_factory else _create_driver(
            selenium,
            self.browser,
        )
        session = requests.Session()
        session.headers.update({"User-Agent": self.config.user_agent})
        try:
            LOGGER.info("Opening ShanghaiTech IDS personal center in the browser.")
            driver.get(person_center_url(self.config))

            errors = [
                selenium["NoSuchElementException"],
                selenium["ElementNotInteractableException"],
            ]
            wait = selenium["WebDriverWait"](
                driver,
                timeout=self.timeout,
                poll_frequency=0.2,
                ignored_exceptions=errors,
            )
            account_security_tab = wait.until(
                selenium["EC"].visibility_of_element_located(
                    (selenium["By"].XPATH, _SIDEBAR_ACCOUNT_SECURITY_XPATH),
                ),
            )
            _sync_cookies_to_session(driver, session)
            recheck_status = _get_json(
                session,
                "GET",
                is_user_recheck_necessary_url(self.config),
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
            account_security_tab.click()

            bind_button = selenium["WebDriverWait"](
                driver,
                timeout=5,
                poll_frequency=0.2,
                ignored_exceptions=errors,
            ).until(
                selenium["EC"].visibility_of_element_located(
                    (selenium["By"].XPATH, _BIND_BUTTON_XPATH),
                ),
            )
            bind_button.click()

            if recheck_status.get("code", "9999") != "0":
                LOGGER.info(
                    "IDS requires an additional identity check. Complete it in the browser.",
                )
                while recheck_status.get("code", "9999") != "0":
                    time.sleep(1)
                    _sync_cookies_to_session(driver, session)
                    recheck_status = _get_json(
                        session,
                        "GET",
                        is_user_recheck_necessary_url(self.config),
                        timeout=self.config.timeout,
                        verify=self.config.verify_tls,
                    )

            _sync_cookies_to_session(driver, session)
            request_json = _get_json(
                session,
                "POST",
                start_register_url(self.config),
                json={"n": build_nonce()},
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
            data = expect_mapping(request_json.get("datas"), "start register datas")
            request = expect_mapping(data.get("request"), "start register request")
            creation_options = expect_mapping(
                request.get("publicKeyCredentialCreationOptions"),
                "publicKeyCredentialCreationOptions",
            )
            credential, metadata = create_registration_response(
                creation_options,
                origin=self.config.origin or self.config.base_url,
            )
            chosen_device_name = device_name or build_device_name()
            anon_biometrics_id = build_anon_biometrics_id()
            response = _get_json(
                session,
                "POST",
                finish_register_url(self.config),
                json={
                    "deviceName": chosen_device_name,
                    "anonbiometricsd": anon_biometrics_id,
                    "response": json.dumps(
                        {
                            "requestId": request.get("requestId"),
                            "credential": credential,
                            "sessionToken": None,
                        },
                        ensure_ascii=False,
                    ),
                    "n": build_nonce(),
                },
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
            if response.get("code", "9999") != "0":
                raise SeleniumBindingError(
                    "IDS registration failed: {0}".format(response),
                )

            username = (
                request.get("username")
                or creation_options.get("user", {}).get("name")
                or creation_options.get("user", {}).get("displayName")
            )
            if not isinstance(username, str) or not username:
                raise SeleniumBindingError("Failed to determine IDS username")

            return PasskeyKeystore(
                username=username,
                anon_biometrics_id=anon_biometrics_id,
                device_name=chosen_device_name,
                base_url=self.config.base_url,
                credential_id=metadata["credential_id"],
                rp_id=metadata["rp_id"],
                user_id=metadata["user_id"],
                alg=metadata["alg"],
                private_key_pem=metadata["private_key_pem"],
                sign_count=metadata["sign_count"],
                created_at=metadata["created_at"],
            )
        except IDSRequestError as exc:
            raise SeleniumBindingError(str(exc)) from exc
        except SeleniumBindingError:
            raise
        except Exception as exc:
            raise SeleniumBindingError(f"Unexpected Selenium binding failure: {exc}") from exc
        finally:
            try:
                driver.quit()
            except Exception:
                LOGGER.debug("Failed to close browser cleanly.", exc_info=True)


def open_logged_in_browser(
    session: requests.Session,
    config: IDSConfig,
    browser: str = "chrome",
    timeout: float = 30,
) -> "WebDriver":
    """Open a browser window and inject IDS cookies for smoke validation."""

    selenium = _load_selenium()
    driver = _create_driver(selenium, browser.lower())
    driver.get(config.base_url)
    for cookie in session.cookies:
        payload = {
            "name": cookie.name,
            "value": cookie.value,
            "path": cookie.path or "/",
            "secure": cookie.secure,
        }
        if cookie.domain:
            payload["domain"] = cookie.domain.lstrip(".")
        if cookie.expires:
            payload["expiry"] = int(cookie.expires)
        driver.add_cookie(payload)
    driver.get(person_center_url(config))
    selenium["WebDriverWait"](driver, timeout=timeout).until(
        selenium["EC"].presence_of_element_located((selenium["By"].TAG_NAME, "body")),
    )
    return driver


def _load_selenium() -> Dict[str, Any]:
    try:
        from selenium import webdriver
        from selenium.common import (
            ElementNotInteractableException,
            NoSuchElementException,
        )
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.wait import WebDriverWait
    except ImportError as exc:
        raise SeleniumBindingError(
            "Selenium support is not installed. Install with "
            "`pip install 'shanghaitech-ids-passkey[selenium]'`.",
        ) from exc
    return {
        "webdriver": webdriver,
        "NoSuchElementException": NoSuchElementException,
        "ElementNotInteractableException": ElementNotInteractableException,
        "By": By,
        "EC": EC,
        "WebDriverWait": WebDriverWait,
    }


def _create_driver(selenium: Dict[str, Any], browser: str) -> "WebDriver":
    webdriver = selenium["webdriver"]
    if browser == "chrome":
        return _create_managed_driver(
            browser,
            constructor=lambda: webdriver.Chrome(),
        )
    if browser == "edge":
        return _create_managed_driver(
            browser,
            constructor=lambda: webdriver.Edge(),
        )
    if browser == "firefox":
        return _create_managed_driver(
            browser,
            constructor=lambda: webdriver.Firefox(),
        )
    raise SeleniumBindingError(
        "Unsupported browser '{0}'. Expected chrome, edge or firefox.".format(
            browser,
        ),
    )


def _create_managed_driver(
    browser: str,
    constructor: Callable[[], "WebDriver"],
) -> "WebDriver":
    sanitized_path, ignored_dirs = _build_sanitized_path(browser)
    if ignored_dirs:
        LOGGER.info(
            "Ignoring driver binaries in PATH so Selenium Manager can select "
            "a compatible %s driver: %s",
            browser,
            ", ".join(ignored_dirs),
        )

    try:
        with _temporary_path(sanitized_path):
            return constructor()
    except Exception as exc:
        raise SeleniumBindingError(
            "Failed to start the {0} browser driver automatically. "
            "If you use a custom driver, pass a custom driver_factory; "
            "otherwise remove stale driver binaries from PATH and retry. "
            "Original error: {1}".format(browser, exc),
        ) from exc


def _build_sanitized_path(browser: str, path_value: Optional[str] = None) -> tuple[str, list[str]]:
    raw_path = path_value if path_value is not None else os.environ.get("PATH", "")
    parts = raw_path.split(os.pathsep) if raw_path else []
    driver_names = _driver_binary_names(browser)
    ignored_dirs = []
    kept_dirs = []

    for part in parts:
        if not part:
            continue
        directory = Path(part)
        if any((directory / name).is_file() for name in driver_names):
            ignored_dirs.append(part)
            continue
        kept_dirs.append(part)

    return os.pathsep.join(kept_dirs), ignored_dirs


def _driver_binary_names(browser: str) -> tuple[str, ...]:
    if browser == "chrome":
        return ("chromedriver", "chromedriver.exe")
    if browser == "edge":
        return ("msedgedriver", "msedgedriver.exe")
    if browser == "firefox":
        return ("geckodriver", "geckodriver.exe")
    return tuple()


@contextlib.contextmanager
def _temporary_path(path_value: str):
    original = os.environ.get("PATH")
    os.environ["PATH"] = path_value
    try:
        yield
    finally:
        if original is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = original


def _sync_cookies_to_session(driver: "WebDriver", session: requests.Session) -> None:
    session.cookies.clear()
    for cookie in driver.get_cookies():
        session.cookies.set(cookie["name"], cookie["value"])


def _get_json(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    try:
        response = session.request(method, url, **kwargs)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise IDSRequestError(f"{method} {url} failed: {exc}") from exc
    except ValueError as exc:
        raise IDSRequestError(f"{method} {url} did not return valid JSON") from exc
    if not isinstance(data, dict):
        raise IDSRequestError(f"{method} {url} did not return a JSON object")
    return data
