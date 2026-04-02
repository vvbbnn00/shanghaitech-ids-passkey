from shanghaitech_ids_passkey import KeystoreError, PasskeyKeystore, SeleniumBindingError
from shanghaitech_ids_passkey._cli import main

from .helpers import make_sample_keystore


def test_cli_inspect_json(capsys, tmp_path) -> None:
    keystore = make_sample_keystore()
    path = tmp_path / "ids.keystore"
    keystore.dump(path)

    exit_code = main(["inspect", "--keystore", str(path), "--format", "json"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "<redacted>" in output
    assert keystore.credential_id in output


def test_cli_bind_writes_keystore(monkeypatch, tmp_path) -> None:
    generated = make_sample_keystore()
    target = tmp_path / "bound.keystore"

    class FakeBinder:
        def __init__(self, config=None, browser="chrome", timeout=600, driver_factory=None):
            self.config = config

        def bind(self, device_name=None):
            if device_name:
                generated.device_name = device_name
            return generated

    monkeypatch.setattr("shanghaitech_ids_passkey._cli.SeleniumBinder", FakeBinder)

    exit_code = main(
        [
            "bind",
            "--keystore",
            str(target),
            "--device-name",
            "CLI-DEVICE",
        ],
    )

    assert exit_code == 0
    restored = PasskeyKeystore.load(target)
    assert restored.device_name == "CLI-DEVICE"


def test_cli_login_updates_keystore_and_smoke_opens_browser(monkeypatch, tmp_path) -> None:
    keystore = make_sample_keystore()
    target = tmp_path / "login.keystore"
    keystore.dump(target)

    class FakeDriver:
        def __init__(self):
            self.closed = False

        def quit(self):
            self.closed = True

    driver = FakeDriver()

    class FakeClient:
        def __init__(self, keystore, config=None):
            self.keystore = keystore
            self.config = config
            self.session = object()

        def login(self):
            self.keystore.sign_count += 1

    monkeypatch.setattr("shanghaitech_ids_passkey._cli.IDSClient", FakeClient)
    monkeypatch.setattr(
        "shanghaitech_ids_passkey._cli.open_logged_in_browser",
        lambda session, config, browser="chrome", timeout=30: driver,
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "")

    exit_code = main(
        [
            "login",
            "--keystore",
            str(target),
            "--mode",
            "selenium",
        ],
    )

    assert exit_code == 0
    restored = PasskeyKeystore.load(target)
    assert restored.sign_count == keystore.sign_count + 1
    assert driver.closed is True


def test_cli_bind_reports_package_errors(monkeypatch, tmp_path, caplog) -> None:
    class BrokenBinder:
        def __init__(self, config=None, browser="chrome", timeout=600, driver_factory=None):
            pass

        def bind(self, device_name=None):
            raise SeleniumBindingError("selenium missing")

    monkeypatch.setattr("shanghaitech_ids_passkey._cli.SeleniumBinder", BrokenBinder)

    exit_code = main(["bind", "--keystore", str(tmp_path / "broken.keystore")])

    assert exit_code == 1
