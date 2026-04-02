# shanghaitech-ids-passkey

> ⚠️ 本Python包并非官方实现，请谨慎使用，确保遵守相关政策和法律法规。


使用 **Passkey (WebAuthn)** 代替用户名密码，实现对 [统一身份认证 (IDS)](https://ids.shanghaitech.edu.cn) 的**持久化免密登录
**。

适用于需要长期、自动化登录 ShanghaiTech 各平台的脚本场景，无需每次输入密码或处理验证码。

## 特性

- 🔑 **Passkey 认证** — 基于 WebAuthn 标准，在本地生成密钥对并绑定到 IDS，后续登录使用私钥签名，无需密码
- 💾 **Keystore 持久化** — 凭据以二进制格式存储于本地文件，支持自定义序列化 / 加密
- 🖥️ **CLI 工具** — 提供 `bind`、`login`、`inspect` 子命令，开箱即用
- 📦 **Python 库** — 提供 `IDSClient`、`PasskeyKeystore` 等 API，方便集成到你的脚本中
- 🌐 **Selenium 集成** — 可选依赖，用于浏览器内绑定 Passkey 或注入登录态打开浏览器
- 🔒 **无密码存储** — 不保存任何用户名密码，仅保存 Passkey 私钥

## 工作原理

```
┌──────────┐  1. Selenium opens browser    ┌─────────┐
│  Local   │ ──── User logs into IDS ────▶ │   IDS   │
│ Machine  │  2. Auto-register Passkey     │ Service │
│          │ ◀──── Return key pair ──────  │         │
└──────────┘                               └─────────┘
     │
     │  Save keystore file (private key + metadata)
     ▼
┌──────────┐  3. Subsequent auto-login     ┌─────────┐
│   Your   │ ──── Passkey signature ─────▶ │   IDS   │
│  Script  │ ◀──── Return login cookies ─  │ Service │
└──────────┘                               └─────────┘
```

## 安装

目前仅支持通过源码安装。

### 从源码安装

```bash
git clone https://github.com/vvbbnn00/shanghaitech-ids-passkey.git
cd shanghaitech-ids-passkey
pip install -e '.[selenium,dev]'
```

## 快速开始

### 第一步：绑定 Passkey

首次使用需要通过浏览器完成 Passkey 绑定。该命令会打开浏览器，**你需要手动登录 IDS**，程序会自动完成后续的 Passkey 注册流程：

```bash
shanghaitech-ids-passkey bind --keystore my.keystore
```

绑定成功后，凭据信息将保存到 `my.keystore` 文件中。

> ⚠️ **keystore 文件包含你的 Passkey 私钥，请妥善保管，不要泄露或上传到公开仓库。**

### 第二步：使用 Passkey 登录

```bash
# 纯 HTTP 登录验证
shanghaitech-ids-passkey login --keystore my.keystore

# 登录后打开浏览器窗口（带登录态）
shanghaitech-ids-passkey login --keystore my.keystore --mode selenium
```

### 查看 Keystore 信息

```bash
# 文本格式
shanghaitech-ids-passkey inspect --keystore my.keystore

# JSON 格式
shanghaitech-ids-passkey inspect --keystore my.keystore --format json
```

## CLI 参考

```
shanghaitech-ids-passkey <command> [options]
```

| 子命令       | 说明                                    |
|-----------|---------------------------------------|
| `bind`    | 通过 Selenium 绑定 Passkey，生成 keystore 文件 |
| `login`   | 使用已有 keystore 登录 IDS                  |
| `inspect` | 查看 keystore 摘要信息（不暴露私钥）               |

### `bind`

| 参数              | 默认值      | 说明                                     |
|-----------------|----------|----------------------------------------|
| `--keystore`    | *(必填)*   | keystore 输出文件路径                        |
| `--browser`     | `chrome` | 使用的浏览器 (`chrome` / `edge` / `firefox`) |
| `--device-name` | 自动生成     | 注册到 IDS 的设备名称                          |
| `--timeout`     | `600`    | Selenium 等待超时（秒）                       |
| `--base-url`    | IDS 默认地址 | 覆盖 IDS 基础 URL                          |

### `login`

| 参数           | 默认值           | 说明                         |
|--------------|---------------|----------------------------|
| `--keystore` | *(必填)*        | keystore 文件路径              |
| `--mode`     | `http`        | 登录模式 (`http` / `selenium`) |
| `--browser`  | `chrome`      | Selenium 模式下使用的浏览器         |
| `--timeout`  | `30`          | HTTP 请求超时（秒）               |
| `--base-url` | keystore 中的地址 | 覆盖 IDS 基础 URL              |

### `inspect`

| 参数           | 默认值    | 说明                     |
|--------------|--------|------------------------|
| `--keystore` | *(必填)* | keystore 文件路径          |
| `--format`   | `text` | 输出格式 (`text` / `json`) |

也可以通过模块入口调用：

```bash
python -m shanghaitech_ids_passkey <command> [options]
```

## 作为库使用

### 基本登录

```python
from shanghaitech_ids_passkey import IDSClient, PasskeyKeystore

keystore = PasskeyKeystore.load("my.keystore")
client = IDSClient(keystore)

# 登录 IDS
client.login()

# 登录成功后可以使用 client.session 访问需要 IDS 认证的服务
response = client.get_service("https://ids.shanghaitech.edu.cn/authserver/login?service=...")

# 登录后记得保存 keystore（sign_count 会递增）
keystore.dump("my.keystore")
```

### 智能登录（仅在未登录时触发）

```python
client.ensure_logged_in()  # 已登录则跳过，未登录自动执行 login()
```

### 自定义配置

```python
from shanghaitech_ids_passkey import IDSClient, IDSConfig, PasskeyKeystore

keystore = PasskeyKeystore.load("my.keystore")
config = IDSConfig(
    base_url="https://ids.shanghaitech.edu.cn",  # IDS 地址
    timeout=60.0,  # 请求超时
    verify_tls=True,  # TLS 证书校验
)
client = IDSClient(keystore, config=config)
```

### 使用自定义 requests.Session

```python
import requests
from shanghaitech_ids_passkey import IDSClient, PasskeyKeystore

session = requests.Session()
session.headers.update({"Accept-Language": "zh-CN"})

keystore = PasskeyKeystore.load("my.keystore")
client = IDSClient(keystore, session=session)
client.login()

# client.session 就是你传入的 session，登录后带有 IDS cookies
```

### 自定义 Keystore 序列化

默认使用二进制格式（zlib 压缩的 JSON）。你可以自定义序列化方式：

```python
import json
from shanghaitech_ids_passkey import PasskeyKeystore


# 使用明文 JSON 存储
def json_serializer(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def json_deserializer(blob: bytes) -> dict:
    return json.loads(blob.decode("utf-8"))


keystore = PasskeyKeystore.load("my.keystore")
keystore.dump("my.json", serializer=json_serializer)

restored = PasskeyKeystore.load("my.json", unserializer=json_deserializer)
```

### 外部加密 Keystore

```python
from cryptography.fernet import Fernet
from shanghaitech_ids_passkey import PasskeyKeystore

key = Fernet.generate_key()
fernet = Fernet(key)

keystore = PasskeyKeystore.load("my.keystore")
ciphertext = fernet.encrypt(keystore.serialize())

# 保存加密数据 & 解密恢复
restored = PasskeyKeystore.unserialize(fernet.decrypt(ciphertext))
```

## API 概览

| 类 / 函数                        | 说明                                         |
|-------------------------------|--------------------------------------------|
| `IDSClient`                   | 基于 `requests` 的 IDS 登录客户端                  |
| `PasskeyKeystore`             | Passkey 凭据的数据模型，支持 load / dump / serialize |
| `IDSConfig`                   | IDS 请求的配置项（base_url、timeout 等）             |
| `SeleniumBinder`              | 通过 Selenium 在浏览器中完成 Passkey 绑定             |
| `ShanghaiTechIDsPasskeyError` | 包的基础异常类                                    |
| `IDSRequestError`             | IDS 请求 / 协议相关的异常                           |
| `KeystoreError`               | Keystore 序列化 / 校验相关的异常                     |
| `SeleniumBindingError`        | Selenium 绑定相关的异常                           |

## 依赖

| 包                    | 用途                           |
|----------------------|------------------------------|
| `cryptography >= 41` | WebAuthn 密钥生成与签名             |
| `requests >= 2.31`   | HTTP 请求                      |
| `selenium >= 4.0`    | *(可选)* 浏览器自动化，绑定 Passkey 时需要 |

## 要求

- Python >= 3.9
- 绑定 Passkey 时需要 Chrome / Edge / Firefox 浏览器

