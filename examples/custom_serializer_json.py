"""示例：给 keystore 使用自定义 JSON serializer。"""

import argparse
import json

from shanghaitech_ids_passkey import PasskeyKeystore


def json_serializer(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def json_deserializer(blob: bytes) -> dict:
    return json.loads(blob.decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, help="现有二进制 keystore 文件路径。")
    parser.add_argument("--target", required=True, help="输出 JSON keystore 文件路径。")
    args = parser.parse_args()

    keystore = PasskeyKeystore.load(args.source)
    keystore.dump(args.target, serializer=json_serializer)

    restored = PasskeyKeystore.load(args.target, unserializer=json_deserializer)
    print(json.dumps(restored.to_dict(redact_private_key=True), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
