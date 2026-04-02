"""示例：在包外对序列化后的 keystore 进行加密。"""

import argparse
from pathlib import Path

from cryptography.fernet import Fernet

from shanghaitech_ids_passkey import PasskeyKeystore


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keystore", required=True, help="明文 keystore 文件路径。")
    parser.add_argument("--encrypted", required=True, help="加密后输出文件路径。")
    parser.add_argument(
        "--fernet-key",
        help="可选的 Fernet key；如果不提供会自动生成。",
    )
    args = parser.parse_args()

    key = args.fernet_key.encode("ascii") if args.fernet_key else Fernet.generate_key()
    fernet = Fernet(key)

    keystore = PasskeyKeystore.load(args.keystore)
    ciphertext = fernet.encrypt(keystore.serialize())
    Path(args.encrypted).write_bytes(ciphertext)

    restored = PasskeyKeystore.unserialize(fernet.decrypt(ciphertext))
    print("Fernet key:", key.decode("ascii"))
    print("恢复后的 keystore 摘要：", restored.to_dict(redact_private_key=True))


if __name__ == "__main__":
    main()
