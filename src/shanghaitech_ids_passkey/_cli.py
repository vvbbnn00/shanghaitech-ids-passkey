"""命令行接口。"""

import argparse
import json
import logging
from pathlib import Path
from typing import Iterable, Optional

from .client import IDSClient
from .config import IDSConfig
from .errors import ShanghaiTechIDsPasskeyError
from .keystore import PasskeyKeystore
from .selenium_bind import SeleniumBinder, open_logged_in_browser


LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shanghaitech-ids-passkey",
        description="上海科技大学 IDS 单 passkey 工具。",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    bind_parser = subparsers.add_parser("bind", help="通过 Selenium 绑定 passkey。")
    bind_parser.add_argument("--keystore", required=True, help="keystore 文件路径。")
    bind_parser.add_argument("--device-name", help="自定义 IDS 设备名称。")
    bind_parser.add_argument(
        "--browser",
        default="chrome",
        choices=("chrome", "edge", "firefox"),
        help="Selenium 使用的浏览器。",
    )
    bind_parser.add_argument(
        "--timeout",
        default=600.0,
        type=float,
        help="Selenium 等待超时时间，单位秒。",
    )
    bind_parser.add_argument(
        "--base-url",
        default=None,
        help="覆盖默认 IDS 基础地址。",
    )

    login_parser = subparsers.add_parser("login", help="尝试用 passkey 登录 IDS。")
    login_parser.add_argument("--keystore", required=True, help="keystore 文件路径。")
    login_parser.add_argument(
        "--mode",
        default="http",
        choices=("http", "selenium"),
        help="仅使用 HTTP 登录，或在登录后打开浏览器做验证。",
    )
    login_parser.add_argument(
        "--browser",
        default="chrome",
        choices=("chrome", "edge", "firefox"),
        help="Selenium 冒烟验证使用的浏览器。",
    )
    login_parser.add_argument(
        "--timeout",
        default=30.0,
        type=float,
        help="HTTP 请求超时时间，单位秒。",
    )
    login_parser.add_argument(
        "--base-url",
        default=None,
        help="覆盖默认 IDS 基础地址。",
    )

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="查看 keystore 摘要，不暴露私钥内容。",
    )
    inspect_parser.add_argument("--keystore", required=True, help="keystore 文件路径。")
    inspect_parser.add_argument(
        "--format",
        default="text",
        choices=("text", "json"),
        help="输出格式。",
    )

    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.command == "bind":
            return _command_bind(args)
        if args.command == "login":
            return _command_login(args)
        if args.command == "inspect":
            return _command_inspect(args)
    except ShanghaiTechIDsPasskeyError as exc:
        LOGGER.error("%s", exc)
        return 1
    return 1


def _command_bind(args: argparse.Namespace) -> int:
    config = IDSConfig(base_url=args.base_url or IDSConfig().base_url, timeout=args.timeout)
    binder = SeleniumBinder(
        config=config,
        browser=args.browser,
        timeout=args.timeout,
    )
    keystore = binder.bind(device_name=args.device_name)
    keystore.dump(args.keystore)
    _print_text_summary(keystore)
    return 0


def _command_login(args: argparse.Namespace) -> int:
    keystore_path = Path(args.keystore)
    keystore = PasskeyKeystore.load(keystore_path)
    config = IDSConfig(
        base_url=args.base_url or keystore.base_url,
        timeout=args.timeout,
    )
    client = IDSClient(keystore, config=config)
    initial_sign_count = keystore.sign_count
    driver = None
    try:
        client.login()
        LOGGER.info("IDS 登录成功：%s", keystore.username)
        if args.mode == "selenium":
            driver = open_logged_in_browser(
                client.session,
                config,
                browser=args.browser,
                timeout=args.timeout,
            )
            input("已打开带登录态的浏览器窗口。按回车关闭...")
    finally:
        if keystore.sign_count != initial_sign_count:
            keystore.dump(keystore_path)
        if driver is not None:
            driver.quit()
    return 0


def _command_inspect(args: argparse.Namespace) -> int:
    keystore = PasskeyKeystore.load(args.keystore)
    if args.format == "json":
        print(json.dumps(keystore.to_dict(redact_private_key=True), ensure_ascii=False, indent=2))
    else:
        _print_text_summary(keystore)
    return 0


def _print_text_summary(keystore: PasskeyKeystore) -> None:
    redacted = keystore.to_dict(redact_private_key=True)
    for key in (
        "username",
        "anon_biometrics_id",
        "device_name",
        "base_url",
        "credential_id",
        "rp_id",
        "user_id",
        "alg",
        "sign_count",
        "created_at",
        "private_key_pem",
    ):
        print("{0}: {1}".format(key, redacted[key]))
