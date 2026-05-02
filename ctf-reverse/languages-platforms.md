# CTF Reverse - 平台与框架特定技术

## Table of Contents
- [Roblox Place File Analysis](#roblox-place-file-analysis)
- [Godot Game Asset Extraction](#godot-game-asset-extraction)
- [Rust serde_json Schema Recovery](#rust-serde_json-schema-recovery)
- [Android JNI RegisterNatives Obfuscation (HTB WonderSMS)](#android-jni-registernatives-obfuscation-htb-wondersms)
- [Android DEX Runtime Bytecode Patching via /proc/self/maps (Google CTF 2017)](#android-dex-runtime-bytecode-patching-via-procselfmaps-google-ctf-2017)
- [Android Native .so Loading Bypass in New Project (Codegate CTF 2018)](#android-native-so-loading-bypass-in-new-project-codegate-ctf-2018)
- [Frida Firebase Cloud Functions Bypass (BSidesSF 2026)](#frida-firebase-cloud-functions-bypass-bsidessf-2026)
- [Verilog/Hardware Reverse Engineering (srdnlenCTF 2026)](#veriloghardware-reverse-engineering-srdnlenctf-2026)
- [Prefix-by-Prefix Hash Reversal (Nullcon 2026)](#prefix-by-prefix-hash-reversal-nullcon-2026)
- [Ruby/Perl Polyglot Constraint Satisfaction (BearCatCTF 2026)](#rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026)
- [Electron App + Native Binary Reversing (RootAccess2026)](#electron-app--native-binary-reversing-rootaccess2026)
- [Node.js npm Package Runtime Introspection (RootAccess2026)](#nodejs-npm-package-runtime-introspection-rootaccess2026)
- [Frida Android Certificate Pinning Bypass (h1702ctf 2017)](#frida-android-certificate-pinning-bypass-h1702ctf-2017)
- [Android Anti-Debug: TracerPid, su Binary, System Properties (h1702ctf 2017)](#android-anti-debug-tracerpid-su-binary-system-properties-h1702ctf-2017)
- [Android Log-Based Key Extraction (HackIT 2017)](#android-log-based-key-extraction-hackit-2017)
- [Native JNI Key Extraction via Memory Dump and Smali Patching (HackIT 2017)](#native-jni-key-extraction-via-memory-dump-and-smali-patching-hackit-2017)
- [IBM AS/400 SAVF File EBCDIC Decoding (EKOPARTY 2017)](#ibm-as400-savf-file-ebcdic-decoding-ekoparty-2017)
- [Intel SGX Enclave Reverse Engineering (Pwn2Win 2017)](#intel-sgx-enclave-reverse-engineering-pwn2win-2017)
- [Glulx Interactive Fiction Bytecode Matrix Validation (PlaidCTF 2018)](#glulx-interactive-fiction-bytecode-matrix-validation-plaidctf-2018)
- [Android Smali Injection to Defeat LocalBroadcastManager (TAMUctf 2019)](#android-smali-injection-to-defeat-localbroadcastmanager-tamuctf-2019)

语言核心逆向（Python、BF/esolang、DOS、Unity、OPAL）见 [languages.md](languages.md)。
Go 与 Rust 二进制逆向见 [languages-compiled.md](languages-compiled.md)。

---

## Roblox Place File Analysis

**模式（MazeRunna, 0xFun 2026）：** Roblox 游戏的最新版本是诱饵，真实 flag 藏在旧版本。

**通过 Asset Delivery API 查看历史版本：**
```bash
# Extract placeId and universeId from game page HTML
# Query each version (requires .ROBLOSECURITY cookie):
curl -H "Cookie: .ROBLOSECURITY=..." \
  "https://assetdelivery.roblox.com/v2/assetId/{placeId}/version/1"
# Download location URL → place_v1.rbxlbin
```

**二进制格式解析：** `.rbxlbin` 包含多个 chunk：
- **INST**：类桶与 referent ID
- **PROP**：实例字段（包含 `Script.Source`）
- **PRNT**：父子关系（对象树）

解码 chunk 后，遍历 `PROP` 中的 `Source` 字段，导出各版本 `Script.Source` / `LocalScript.Source`，再做 diff。

**关键经验：** 一定要看版本历史。最新版本可能故意放假 flag，真正逻辑在旧版脚本里。

---

## Godot Game Asset Extraction

**模式（Steal the Xmas）：** 加密的 Godot `.pck` 资源包。

**工具：**
- [gdsdecomp](https://github.com/GDRETools/gdsdecomp) - 提取 Godot 包
- [KeyDot](https://github.com/Titoot/KeyDot) - 从 Godot 可执行文件中提取加密 key

**流程：**
1. 用 KeyDot 分析游戏可执行文件，提取加密 key
2. 将 key 交给 gdsdecomp
3. 解包并在 Godot 编辑器中打开项目
4. 在脚本/资源中搜索 flag

---

## Rust serde_json Schema Recovery

**模式（Curly Crab, PascalCTF 2026）：** Rust 二进制从 stdin 读取 JSON，经 `serde_json` 反序列化后输出成功/失败 emoji。

**思路：**
1. 反汇编 serde 生成的 `Visitor` 实现
2. 每个 visitor 的 `visit_map` / `visit_seq` 会暴露期望的 key 和类型
3. 在反序列化代码中搜索字符串字面量（例如 `"pascal"`、`"CTF"`）
4. 根据 visitor 调用层级重建嵌套 JSON schema
5. 从 visitor 方法名推断类型：`visit_str` = 字符串，`visit_u64` = 数字，`visit_bool` = 布尔，`visit_seq` = 数组

```json
{"pascal":"CTF","CTF":2026,"crab":{"I_":true,"cr4bs":1337,"crabby":{"l0v3_":["rust"],"r3vv1ng_":42}}}
```

**关键点：** flag 往往就是 schema 中 JSON key 按顺序拼接的结果。按字段出现顺序读出来即可。

---

## Android JNI RegisterNatives Obfuscation (HTB WonderSMS)

**模式：** Android 应用通过 `System.loadLibrary()` 加载原生库，但 native 方法不是按标准 JNI 命名（`Java_com_pkg_Class_method`），而是在 `JNI_OnLoad` 中通过 `RegisterNatives` 动态注册。这样会隐藏真正的 C/C++ 处理函数。

**识别：**
```java
// In decompiled Java (jadx):
static { System.loadLibrary("audio"); }
private final native ProcessedMessage processMessage(SmsMessage msg);
```
按标准 JNI，`.so` 里应有 `Java_com_rloura_wondersms_SmsReceiver_processMessage`。若找不到，多半就是 `RegisterNatives`。

**在 Ghidra 中找真实处理函数：**
1. 定位 `JNI_OnLoad`（导出符号，一定存在）
2. 跟到 `RegisterNatives(env, clazz, methods, count)` 调用
3. `methods` 数组内是 `{name, signature, fnPtr}` 结构
4. 顺着 `fnPtr` 找到真正的 native 函数

```c
// JNI_OnLoad registers functions manually:
static JNINativeMethod methods[] = {
    {"processMessage", "(Landroid/telephony/SmsMessage;)LProcessedMessage;", (void*)real_handler}
};
(*env)->RegisterNatives(env, clazz, methods, 1);
```

**静态分析架构选择：**
```bash
# x86_64 gives best Ghidra decompilation (most similar to desktop code)
# Extract from APK:
unzip WonderSMS.apk -d extracted/
ls extracted/lib/x86_64/  # Prefer this over arm64-v8a for static analysis
```

**关键点：** `RegisterNatives` 是常见混淆手法，它切断了 Java 方法名与 native 符号名的直接关联。逆 Android 原生库时，如果符号被 strip，又找不到标准 JNI 命名，优先检查 `JNI_OnLoad`。

**识别特征：** Java 中声明了 native 方法、`.so` 中没有对应 JNI 符号、同时存在 `JNI_OnLoad`。

---

## Android DEX Runtime Bytecode Patching via /proc/self/maps (Google CTF 2017)

原生 JNI 库会在运行时修改内存中的 Dalvik 字节码：读取 `/proc/self/maps` 找到已加载 DEX，用 `mprotect` 改成可写，再对指定偏移做 XOR patch。

```python
# Reconstruct the patched DEX offline:
# 1. Extract the embedded DEX from the APK
# 2. Find the XOR key and patch offsets in the native .so (IDA/Ghidra)
# 3. Apply the same patches to the static DEX
import struct

with open('classes.dex', 'rb') as f:
    dex = bytearray(f.read())

# Patch 144 bytes starting at offset found in .so
xor_key = 0x5A
for i in range(patch_offset, patch_offset + 144):
    dex[i] ^= xor_key

# 4. Recompute DEX checksum and SHA-1 hash
# 5. Decompile with jadx or baksmali
```

**关键点：** 仅静态分析 APK 不够，因为真正执行的是被原生库在内存里改过的 DEX。必须先从 `.so` 提取 XOR key 和 patch 偏移，再离线重建运行时版本。该技巧只适用于 Dalvik（API < 21），不适用于 ART。

---

### Android Native .so Loading Bypass in New Project (Codegate CTF 2018)

**模式：** 与其硬逆复杂 JNI 校验逻辑，不如新建一个 Android Studio 工程，复用原包名、类名和 native 方法签名，直接加载原始 `.so` 并调用 native 函数，绕过所有 Java 层校验。

```java
// Create new project with same package: com.example.puing.a2018codegate
package com.example.puing.a2018codegate;
public class Main4Activity extends AppCompatActivity {
    static { System.loadLibrary("hello-libs"); }
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String flag = stringFromJNI();  // call native directly, skip all Java validation
        Log.d("FLAG", flag);
    }
    public native String stringFromJNI();
}
```

**关键点：** JNI 函数名编码了包路径和类名。只要新项目的包名、类名和方法签名匹配，就能直接调用原始 native 逻辑，完全跳过 Java 层的随机数检查、PIN、root 检测等前置限制。

**识别特征：** APK 中的 flag 或 secret 在 native 代码里生成并返回给 Java，而 Java 层在调用前叠了多层校验。

**参考：** Codegate CTF 2018

---

## Frida Firebase Cloud Functions Bypass (BSidesSF 2026)

**模式（vinyl-drop, doremi）：** Android 应用通过 Firebase Cloud Functions 校验 QR、购买等操作。合法 payload 一般包含 Firebase UID、某个值和时间戳。登录后用 Frida hook 应用，构造合法 payload，直接调用 Cloud Function。

```javascript
// Frida hook to bypass QR validation
Java.perform(function() {
    var FirebaseFunctions = Java.use('com.google.firebase.functions.FirebaseFunctions');
    var FirebaseAuth = Java.use('com.google.firebase.auth.FirebaseAuth');

    // Get current user UID after login
    var auth = FirebaseAuth.getInstance();
    var uid = auth.getCurrentUser().getUid();

    // Construct valid payload: uid + amount + timestamp
    var unixMs = Java.use('java.lang.System').currentTimeMillis();
    var payload = uid + "+100+" + unixMs;

    // Call the Cloud Function directly
    var functions = FirebaseFunctions.getInstance();
    var data = Java.use('java.util.HashMap').$new();
    data.put("payload", payload);
    functions.getHttpsCallable("validateScanPayload").call(data);
});
```

**关键点：** Firebase AppCheck 和 Cloud Functions 很多时候只依赖客户端生成合法请求。登录后用 Frida 可直接调用任意函数并传入自定义参数，从而绕过 QR 扫描、支付等客户端校验。

**识别时机：** APK 含 `google-services.json`、`build.gradle` 依赖 Firebase，或反编译代码里出现 Cloud Function 调用。

**参考：** BSidesSF 2026 "vinyl-drop"

---

## Verilog/Hardware Reverse Engineering (srdnlenCTF 2026)

**模式（Rev Juice）：** Verilog HDL 描述了一台自动售货机，只有按特定投币与选择序列才能解锁隐藏商品。

**思路：**
1. 阅读 Verilog 模块，理解状态机和历史寄存器
2. 找隐藏条件（例如只有 `COINS_HISTORY` 某些 tap 位命中特定值时才开放 product 8）
3. 为每类动作建立时序模型（每个动作占多少时钟周期）
4. 从目标 history 条件反推输入序列

**构造时序模型：**
```python
# Map each action to its cycle count (determined from Verilog state machines)
TIMING = {
    "insert_coin": 3,       # 3 cycles per coin insertion
    "select_success": 7,    # 7 cycles for successful product selection
    "select_fail": 5,       # 5 cycles for failed selection attempt
    "cancel_with_coins": 4, # 4 cycles for cancel when coins > 0
    "cancel_at_zero": 2,    # 2 cycles for cancel when coins = 0
}

# COINS_HISTORY is a shift register updated each cycle
# History tap requirements (from Verilog conditions):
# H[0]=1, H[7]=4, H[28]=H[33]=H[38]=6
# H[63]=H[73]=2, H[80]=9
# (H[19]+H[21]+H[56]+H[69]) mod 32 = 0
```

**关键点：** 硬件题核心不是“功能逻辑”，而是“精确时序”。每个动作持续多少拍、history 在哪一拍采样，决定了最终约束。

**识别特征：** 存在 `.v`/`.sv` 文件、`always @(posedge clk)`、移位寄存器和带隐藏条件的 `case` 状态机。

---

## Prefix-by-Prefix Hash Reversal (Nullcon 2026)

完整方法见 [patterns-ctf-2.md](patterns-ctf-2.md#prefix-hash-brute-force-nullcon-2026)。这里补充语言层注意事项：

**语言相关备注：**
- 哈希算法可能很冷门（MD2、自定义），但不一定需要识别，只要能跑样本并比对输出
- 用 `subprocess.run()` 并加 `timeout=2`，避免错误输入让程序卡死
- 对 strip 后二进制，可用 `ltrace` 看是否泄露哈希函数名（如 `MD2_Update`）

---

## Ruby/Perl Polyglot Constraint Satisfaction (BearCatCTF 2026)

**模式（Polly's Key）：** 单个文件同时是合法的 Ruby 和 Perl。两种语言分别施加不同的 key 约束，必须同时满足才能解出 flag。

**Polyglot 结构利用点：**
- Ruby：`=begin`...`=end` 是块注释
- Perl：`=begin`...`=cut` 是 POD，`=end` 会被忽略
- 通过注释边界差异，使两种语言执行不同代码

**典型约束：**
- **Ruby：** 字符集需满足某种数学性质
- **Perl：** 通过插入排序逆序数等约束确定字符排列

**解法：**
1. 先确定合法字符集（来自其中一种语言）
2. 再利用另一种语言的顺序约束确定排列
3. 计算 key 哈希并解密

```python
# Determine character ordering from inversion counts
def reconstruct_from_inversions(chars, inv_counts):
    result = []
    remaining = sorted(chars)
    for i in range(len(chars) - 1, -1, -1):
        # inv_counts[i] = number of elements to the left that are greater
        idx = inv_counts[i]
        result.insert(idx, remaining.pop(i))
    return result
```

**关键点：** Polyglot 题的核心是先分清“哪段代码被哪种解释器执行”，再把两边约束联立求解。

**识别特征：** 文件可被多个解释器运行（如 `ruby file && perl file`），或题面明确提到 polyglot。

---

## Electron App + Native Binary Reversing (RootAccess2026)

**模式（Rootium Browser）：** Electron 桌面应用把敏感逻辑（vault、crypto、auth）放在原生 ELF/DLL 中；Electron 层只是壳，真正 flag 逻辑在 native binary。

**提取流程：**
1. **解开 Electron 的 ASAR：**
```bash
# Install ASAR tool
npm install -g @electron/asar

# Extract the app.asar archive
asar extract resources/app.asar app_extracted/
ls app_extracted/
```

2. **定位 native binary：**
```bash
# Find native binaries
find app_extracted/ -name "*.node" -o -name "*.so" -o -name "*vault*" -o -name "*auth*"

# Check JS for child_process.spawn or ffi-napi calls
grep -r "spawn\|execFile\|ffi\|require.*native" app_extracted/
```

3. **逆 native binary**（例如 XOR + rotate 密码学小逻辑）：
```python
def decrypt_password(encrypted_bytes, key):
    """Common pattern: XOR with constant + bit rotation + key XOR."""
    result = []
    for i, byte in enumerate(encrypted_bytes):
        decrypted = ((byte ^ 0x42) >> 3) ^ key[i % len(key)]
        result.append(chr(decrypted))
    return ''.join(result)

def decrypt_flag(encrypted_flag, password):
    """Flag uses password as key with position-dependent rotation."""
    result = []
    for i, byte in enumerate(encrypted_flag):
        key_byte = ord(password[i % len(password)])
        decrypted = ((byte ^ 0x7E) >> (i % 8)) ^ key_byte
        result.append(chr(decrypted))
    return ''.join(result)
```

**关键点：** Electron 题通常是“JS 包装 native”。先 `asar` 解包，再顺着 JS 调用链找到真正的本地模块；JS 层往往明文保留了调用顺序或验证流程，能帮助理解 native 逻辑。

**识别特征：** `resources/` 下有 `.asar`，存在 Electron framework，`package.json` 依赖 electron。

---

## Node.js npm Package Runtime Introspection (RootAccess2026)

**模式（RootAccess CLI）：** npm 包做了 RC4 字符串编码、控制流平坦化、flag 分片等混淆，静态分析代价太高，适合直接做运行时探查。

**动态分析方案：**
```javascript
#!/usr/bin/env node

// 1. Load obfuscated modules
const cryptoMod = require('target-package/dist/lib/crypto.js');
const vaultMod = require('target-package/dist/lib/vault.js');

// 2. Enumerate all exported properties
for (const mod of [cryptoMod, vaultMod]) {
    for (const key of Object.keys(mod)) {
        const obj = mod[key];
        console.log(`Export: ${key}`);
        // List all methods including hidden ones
        const props = Object.getOwnPropertyNames(obj);
        const proto = Object.getOwnPropertyNames(obj.prototype || {});
        console.log('  Own:', props);
        console.log('  Proto:', proto);
    }
}

// 3. Extract flag fragments
const Engine = cryptoMod.CryptoEngine;
const total = Engine.getTotalFragments();
let flag = '';
for (let i = 1; i <= total; i++) {
    flag += Engine.getFragment(i);
}
console.log('Flag:', flag);

// 4. Check for hidden methods (common: __getFullFlag__, _debug, _raw)
const hidden = Object.getOwnPropertyNames(Engine)
    .filter(p => p.startsWith('__') || p.startsWith('_'));
console.log('Hidden methods:', hidden);
```

**关键点：** 高度混淆的 JS 常常不值得硬静态。模块一旦 `require`，其内部字符串解密和初始化逻辑通常已自动完成。直接用 `Object.getOwnPropertyNames()` 枚举导出内容，常常比反混淆更快。

**识别特征：** npm 包中的 `dist/` 目录高度压缩/混淆，题面要求逆 CLI 工具，`package.json` 中有自定义命令。

---

## Frida Android Certificate Pinning Bypass (h1702ctf 2017)

APK 使用 OkHttp `CertificatePinner` 做证书绑定。与其搭 MITM 或改 APK，不如用 Frida 直接调用已加载类上的 native JNI 方法。

```javascript
Java.perform(function() {
    var Requestor = Java.use("com.h1702ctf.ctfone.Requestor");
    console.log("hName: " + Requestor.hName());
    console.log("hVal: " + Requestor.hVal());
});
```

直接调用 `hName()` 和 `hVal()` 就能拿到绕过服务端校验所需的 HTTP 头名和值，因此根本不需要真正绕过 pinning。

**关键点：** Frida 不只用于 hook，也可以直接调用类方法。若关键秘密已经在类方法中，就没必要在网络层纠缠证书绑定。

**参考：** h1702ctf 2017

---

## Android Anti-Debug: TracerPid, su Binary, System Properties (h1702ctf 2017)

原生 ARM 代码串联了三道反分析检查：
1. 读取 `/proc/self/status` 检查 `TracerPid` 是否非零
2. 检查 `su` 二进制是否存在
3. 通过 `__system_property_get` 读取自定义系统属性

这些检查控制某个关键寄存器值的计算。可通过静态分析绕过：在 IDA 图视图里顺着控制流找到“正常路径”，再反推出各分支所需寄存器值。

**关键点：** 这类 Android 原生反调试不一定需要动态绕过。很多时候静态走图就能恢复满足所有检查的寄存器条件。

**参考：** h1702ctf 2017

---

## Android Log-Based Key Extraction (HackIT 2017)

一个安全聊天应用把密码学材料用 Android `Log.d()` 打到了日志里：
- Curve25519 base agreement 值
- 每条消息的 ephemeral shared key
- message ID 和 shift counter

AES-CBC 的 IV 由日志中的 ephemeral/shared 值派生，key 则由 base agreement 和累计 shift counter 派生。收集 `adb logcat` 后即可重建 AES-CBC 参数并解密消息。

```bash
adb logcat | grep -E "(agreement|ephemeral|shared|key)" > crypto_log.txt
# Parse log entries to reconstruct: key = f(base_agreement, shift_counter)
#                                   iv  = f(ephemeral_shared)
```

**关键点：** 安全相关应用一旦日志过度详细，就可能直接泄露足够的状态来重建加密参数，无需私钥。

**参考：** HackIT CTF 2017

---

## Native JNI Key Extraction via Memory Dump and Smali Patching (HackIT 2017)

JNI 原生库用 `.data` 中的 XOR 混淆密钥对请求做签名，密钥在运行时才解混淆。

**流程：**
1. 在 root 设备上用 GDB stub 把库载入 IDA
2. 在 XOR 解密后下断点
3. dump 已解密 key 所在内存区域
4. 用 `baksmali` 反汇编 APK 的 DEX，找到构造签名 POST 请求的 smali
5. 修改 smali，使程序去签名你想要的参数，再用 `apktool` 重打包安装

```bash
# Decompile APK
apktool d target.apk -o target_decompiled/
# Edit smali: change signed parameter from original to desired value
# Rebuild
apktool b target_decompiled/ -o target_patched.apk
# Sign and install
```

**关键点：** 对 JNI 签名题，不一定要完整逆算法。很多时候把运行时已解密 key dump 出来，再 patch smali 改签名对象，就足够完成利用。

**参考：** HackIT CTF 2017

---

## IBM AS/400 SAVF File EBCDIC Decoding (EKOPARTY 2017)

IBM AS/400 的 SAVF 二进制文件使用 EBCDIC 编码而不是 ASCII。flag 与干扰文本按“取 2 跳 2”模式交织。

```python
import codecs

with open('savefile.savf', 'rb') as f:
    data = f.read()

# Convert EBCDIC to ASCII
ascii_data = data.decode('cp500')  # cp500 is IBM EBCDIC International

# Filter: keep uppercase letters and underscores (flag charset)
flag_chars = [c for c in ascii_data if c.isupper() or c == '_']
# Or apply take-2-skip-2 pattern after decoding
flag = ''.join(ascii_data[i] for i in range(0, len(ascii_data), 4)
               if ascii_data[i].isupper() or ascii_data[i] == '_')
```

**关键点：** EBCDIC 是 IBM 主机原生编码。先做正确解码，再观察字符分布和交织模式，通常很快就能定位 flag 结构。

**参考：** EKOPARTY CTF 2017

---

## Intel SGX Enclave Reverse Engineering (Pwn2Win 2017)

Intel SGX enclave `.so` 暴露 ECALL 分发表。enclave 逻辑本质仍是标准 x86-64，可直接用 IDA 逆。

**流程：**
1. 在 `.so` 中找到 ECALL table，即按 ECALL 编号索引的函数指针数组
2. 用 IDA 反编译各 ECALL，识别远程认证协议
3. 用 Python 和 `sgx_crypto_wrapper` 手工实现认证流程
4. 密钥派生：P-256 ECDH 后接 CMAC-AES-128 得到 session key（SK）
5. 用 SK 解密 AES-128-GCM 的 flag blob

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import cmac, ciphers

# ECDH: derive shared secret from server's P-256 public key
private_key = ec.generate_private_key(ec.SECP256R1())
shared_secret = private_key.exchange(ec.ECDH(), server_pub_key)

# CMAC-AES-128 key derivation (per SGX attestation spec)
c = cmac.CMAC(ciphers.algorithms.AES(b'\x00' * 16))
c.update(shared_secret[:16])
sk = c.finalize()

# Decrypt flag with AES-128-GCM using derived SK
```

**关键点：** SGX 远程认证的密钥派生是确定性的。只要协议和材料都能复现，就能在 enclave 外算出同样的 session key。

**参考：** Pwn2Win CTF 2017

---

## Glulx Interactive Fiction Bytecode Matrix Validation (PlaidCTF 2018)

**模式：** 题目是一个 Glulx 互动小说（`.ulx`/`.blorb`），玩家输入会在 VM 内经过矩阵乘法变换，再与硬编码向量比较。隐藏的 `xyzzy` 类指令可进入调试房间，从侧门拿到目标向量和常量矩阵。

**流程：**
1. 用 `glulxd` 反汇编，或在 `glulxe`/`git` 解释器下运行并在每条 VM 指令处 dump 内存
2. 定位矩阵常量和比较目标向量
3. 输入隐藏指令触发调试房间，常见词为 `xyzzy`、`plugh`、其他开发者命令
4. 在 Python/Sage 中对线性变换求逆：`input_vec = target_vec * matrix.inverse()` over `Z_{2^32}`

```python
from sage.all import matrix, Zmod

M = matrix(Zmod(2**32), rows)       # rows[i] = extracted matrix row
target = vector(Zmod(2**32), output)
answer = M.solve_right(target)      # required player input as 32-bit words
print(bytes(answer.list()).decode())
```

**关键点：** 互动小说 VM 通常会把开发者指令保留在字典表和对象表中。先 grep `xyzzy`、`debug`、`god`、`plugh` 这类词，再去逆具体验证逻辑，通常更快。

**参考：** PlaidCTF 2018 — writeup 10019

---

## Android Smali Injection to Defeat LocalBroadcastManager (TAMUctf 2019)

**模式（Local News）：** APK 用 `LocalBroadcastManager.getInstance(this).registerReceiver(...)` 注册 `BroadcastReceiver`，只有应用自身触发时才会解码 flag。外部 `adb shell am broadcast` 无效，因为 local broadcast 不出进程：

```bash
$ adb shell cmd package query-receivers --brief -a com.tamu.ctf.START
# No receivers found
```

如果强行改成 `Context.registerReceiver` 会崩。更稳的方法是把 `onReceive` 的主体复制到 `onCreate`，让解混淆逻辑在启动时自动执行并把结果打到 `logcat`。

```smali
# Inside MainActivity.smali, inserted before the final return of onCreate():
const/4 v1, 0x0
invoke-static {v1}, Lio/michaelrocks/paranoid/Deobfuscator$app$Debug;->getString(I)Ljava/lang/String;
move-result-object v1
invoke-static {v1, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
```

```bash
apktool d app.apk -o app
# patch MainActivity.smali ...
apktool b app -o app/dist/app.apk
jarsigner -keystore ~/.android/debug.keystore -storepass android \
  app/dist/app.apk androiddebugkey
adb install -r app/dist/app.apk
adb logcat | grep -i flag
```

**关键点：** `LocalBroadcastManager` 注册的接收器无法从 `adb` 触发，所以“自己发 intent”这条路行不通。最直接的办法是 patch smali，把解混淆调用移动到必经路径并输出到日志。

**参考：** TAMUctf 2019 — Local News, writeup 13565
