"""最小示例：加载 keystore 并执行一次 IDS 登录。"""

import argparse

from shanghaitech_ids_passkey import IDSClient, PasskeyKeystore


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keystore", required=True, help="passkey keystore 文件路径。")
    args = parser.parse_args()

    keystore = PasskeyKeystore.load(args.keystore)
    client = IDSClient(keystore)
    client.login()
    keystore.dump(args.keystore)
    print("IDS 登录成功：{0}".format(keystore.username))


if __name__ == "__main__":
    main()
