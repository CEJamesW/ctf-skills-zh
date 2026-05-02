# CTF Reverse - 编译型语言逆向（Go、Rust）

## Table of Contents
- [Go Binary Reversing](#go-binary-reversing)
  - [Recognition](#recognition)
  - [Symbol Recovery](#symbol-recovery)
  - [Go Memory Layout](#go-memory-layout)
  - [Goroutine and Concurrency Analysis](#goroutine-and-concurrency-analysis)
  - [Common Go Patterns in Decompilation](#common-go-patterns-in-decompilation)
  - [Go Binary Reversing Workflow](#go-binary-reversing-workflow)
  - [Go Binary UUID Patching for C2 Client Enumeration (BSidesSF 2026)](#go-binary-uuid-patching-for-c2-client-enumeration-bsidessf-2026)
- [Rust Binary Reversing](#rust-binary-reversing)
  - [Rust Recognition](#rust-recognition)
  - [Symbol Demangling](#symbol-demangling)
  - [Common Rust Patterns in Decompilation](#common-rust-patterns-in-decompilation)
  - [Rust-Specific Analysis Tools](#rust-specific-analysis-tools)
  - [Rust Lifetime Escape via Compiler Bug #25860 (Hack.lu 2018)](#rust-lifetime-escape-via-compiler-bug-25860-hacklu-2018)
  - [Rust #[no_mangle] libc Override for seccomp Bypass (Hack.lu 2018)](#rust-no_mangle-libc-override-for-seccomp-bypass-hacklu-2018)
  - [Rust xmmword Constant Extraction via IDAPython (Insomnihack 2019)](#rust-xmmword-constant-extraction-via-idapython-insomnihack-2019)
- [Nuitka-Compiled Python — Module Stub Injection (X-MAS CTF 2018)](#nuitka-compiled-python--module-stub-injection-x-mas-ctf-2018)
- [Swift Binary Reversing](#swift-binary-reversing)
- [Kotlin / JVM Binary Reversing](#kotlin--jvm-binary-reversing)
  - [JVM Bytecode (Android/Server)](#jvm-bytecode-androidserver)
  - [Kotlin/Native](#kotlinnative)
- [D Language Binary Reversing (CSAW CTF 2016)](#d-language-binary-reversing-csaw-ctf-2016)
- [Haskell Binary Reversing via STG Closures and hsdecomp (hxp CTF 2017, Codegate 2018)](#haskell-binary-reversing-via-stg-closures-and-hsdecomp-hxp-ctf-2017-codegate-2018)
- [Haskell Binary RE via GHC CMM Intermediate Language (N1CTF 2018)](#haskell-binary-re-via-ghc-cmm-intermediate-language-n1ctf-2018)
- [C++ Binary Reversing (Quick Reference)](#c-binary-reversing-quick-reference)
  - [vtable Reconstruction](#vtable-reconstruction)
  - [RTTI (Run-Time Type Information)](#rtti-run-time-type-information)
  - [Standard Library Patterns](#standard-library-patterns)

---

## Go Binary Reversing

由于 Go 常用于 CLI 工具、网络服务和恶意软件，CTF 中的 Go 二进制越来越常见。

### Recognition

```bash
# Detect Go binary
file binary | grep -i "go"
strings binary | grep "go.buildid"
strings binary | grep "runtime.gopanic"

# Go version embedded in binary
strings binary | grep "^go1\."
```

**关键特征：**
- 静态链接体积很大（即使 hello world 也常有约 2MB）
- 内嵌 `go.buildid`
- `runtime.*` 符号（即使 strip 后也常残留）
- 入口通常是 `main.main` 而不是 `main`
- 常见字符串：`GOROOT`、`GOPATH`、`/usr/local/go/src/`

### Symbol Recovery

Go 即使在 strip 后也会保留相当丰富的类型和函数信息：

```bash
# GoReSym - recovers function names, types, interfaces from Go binaries
# https://github.com/mandiant/GoReSym
./GoReSym -d binary > symbols.json

# Parse output
python3 -c "
import json
with open('symbols.json') as f:
    data = json.load(f)
for fn in data.get('UserFunctions', []):
    print(f\"{fn['Start']:#x}  {fn['FullName']}\")
"
```

**Ghidra with golang-loader：**
```bash
# Install: Ghidra → Window → Script Manager → search "golang"
# Or use: https://github.com/getCUJO/ThreatFox/tree/main/ghidra-golang
# Recovers function names, string references, interface tables
```

**redress（Go 二进制分析）：**
```bash
# https://github.com/goretk/redress
redress -src binary         # Reconstruct source tree
redress -pkg binary         # List packages
redress -type binary        # List types and methods
redress -interface binary   # List interfaces
```

### Go Memory Layout

理解 Go 的数据结构有助于读伪代码：

```c
# String: {pointer, length} (16 bytes on 64-bit)
# NOT null-terminated! Length field is critical.
struct GoString {
    char *ptr;    // pointer to UTF-8 data
    int64 len;    // byte length
};

# Slice: {pointer, length, capacity} (24 bytes on 64-bit)
struct GoSlice {
    void *ptr;    // pointer to backing array
    int64 len;    // current length
    int64 cap;    // allocated capacity
};

# Interface: {type_descriptor, data_pointer} (16 bytes)
struct GoInterface {
    void *type;   // points to type metadata (itab for non-empty interface)
    void *data;   // points to actual value
};

# Map: pointer to runtime.hmap struct
# Channel: pointer to runtime.hchan struct
```

**在 Ghidra/IDA 中：** 若函数参数形如 `(ptr, int64)`，通常是 Go string；三元 `(ptr, int64, int64)` 通常是 slice。

### Goroutine and Concurrency Analysis

```bash
# Identify goroutine spawns in disassembly
strings binary | grep "runtime.newproc"
# newproc1 is the internal goroutine creation function

# In GDB with Go support:
gdb ./binary
(gdb) source /usr/local/go/src/runtime/runtime-gdb.py
(gdb) info goroutines          # List all goroutines
(gdb) goroutine 1 bt          # Backtrace for goroutine 1
```

**反汇编中的 channel 操作：**
- `runtime.chansend1` → `ch <- value`
- `runtime.chanrecv1` → `value = <-ch`
- `runtime.selectgo` → `select { case ... }`
- `runtime.closechan` → `close(ch)`

### Common Go Patterns in Decompilation

**defer 机制：**
- `runtime.deferproc` → 注册 defer 函数
- `runtime.deferreturn` → 在函数退出时执行 defer
- defer 按 LIFO 顺序执行，和清理/密钥擦除等逻辑有关

**错误处理（`if err != nil`）：**
```text
# In disassembly, this appears as:
# call some_function        → returns (result, error) as two values
# test rax, rax             → check if error (second return value) is nil
# jne error_handler
```

**字符串拼接：**
- `runtime.concatstrings` → `s1 + s2 + s3`
- `fmt.Sprintf` → 格式化构造
- 在 `.rodata` 中关注格式串：`"%s%d"`、`"%x"`

**CTF 常见 stdlib 痕迹：**
```go
// Crypto operations → look for these in strings/imports:
// "crypto/aes", "crypto/cipher", "crypto/sha256", "encoding/hex", "encoding/base64"

// Network operations:
// "net/http", "net.Dial", "bufio.NewReader"

// File operations:
// "os.Open", "io.ReadAll", "os.ReadFile"
```

### Go Binary Reversing Workflow

```bash
1. file binary                          # Confirm Go, get arch
2. GoReSym -d binary > syms.json       # Recover symbols
3. strings binary | grep -i flag        # Quick win check
4. Load in Ghidra with golang-loader    # Apply recovered symbols
5. Find main.main                       # Entry point
6. Identify string comparisons          # GoString {ptr, len} pairs
7. Trace crypto operations              # crypto/* package usage
8. Check for embedded resources         # embed.FS in Go 1.16+
```

**Go embed.FS（Go 1.16+）：**
```bash
# Look for embedded file data
strings binary | grep "embed"
# Embedded files appear as raw data in the binary
# Search for known file signatures (PK for zip, PNG header, etc.)
```

**关键点：** Go 运行时即使在 strip 后也携带大量元数据。手工分析前先跑 GoReSym，常能恢复绝大部分函数名。另一个常见坑是 Go 字符串是 `{ptr, len}` 而非 null-terminated；若没有 golang-loader，Ghidra 默认字符串分析很容易漏掉。

**识别特征：** 大型静态二进制（简单程序也常 2MB+）、`go.buildid`、`runtime.gopanic`、`/home/user/go/src/` 等源码路径。

### Go Binary UUID Patching for C2 Client Enumeration (BSidesSF 2026)

**模式（see-two）：** 一个 Go 编译的 C2 客户端通过 `-ldflags -X` 嵌入 UUID。C2 服务端用 mTLS 认证。通过修改 UUID 并重新注册客户端，可枚举其他客户端及其上传文件。

**做法：**
1. 从 Go build metadata 提取 UUID：`go version -m client_binary`
2. 直接补丁 UUID（简单字节替换，前提是长度一致）
3. 用补丁后的客户端向 C2 注册（mTLS 证书通常内嵌或在发行包中）
4. 通过 API 枚举客户端：`GET /api/clients`
5. 列出并下载各客户端的 GCS bucket 或文件存储内容
6. 在下载结果中 grep flag

```bash
# Extract Go build info
go version -m ./client_binary | grep ldflags
# Output shows: -X main.clientUUID=<uuid>

# Patch UUID in binary (replace old UUID bytes with new UUID)
python3 -c "
import sys
data = open('client_binary', 'rb').read()
old_uuid = b'original-uuid-value-here'
new_uuid = b'attacker-uuid-value-here'
patched = data.replace(old_uuid, new_uuid)
open('client_patched', 'wb').write(patched)
"
chmod +x client_patched
./client_patched --register
```

**关键点：** `-ldflags -X` 写入的 Go 字符串值会直接落在二进制数据段中。只要新旧 UUID 等长，替换底层字节数组即可得到可运行的新样本。mTLS 负责认证客户端，但不一定与 UUID 绑定。

**参考：** BSidesSF 2026 "see-two"

---

## Rust Binary Reversing

Rust 二进制在现代 CTF 中也很常见，尤其是加密、系统和安全工具题。

### Rust Recognition

```bash
# Detect Rust binary
strings binary | grep -c "rust"
strings binary | grep "rustc"             # Compiler version
strings binary | grep "/rustc/"           # Source paths
strings binary | grep "core::panicking"   # Panic infrastructure
```

**关键特征：**
- 字符串中有 `core::panicking::panic`
- 以 `_ZN` 开头的 Itanium ABI 混淆符号，如 `_ZN4main4main17h...`
- ELF 中可能有 `.rustc` section
- 引用 `/rustc/<commit_hash>/library/`
- 体积偏大（Rust 默认静态链接）

### Symbol Demangling

```bash
# Rust uses Itanium ABI mangling (same as C++)
# rustfilt demangles Rust-specific symbols
cargo install rustfilt
nm binary | rustfilt | grep "main"

# Or use c++filt (works for most Rust symbols)
nm binary | c++filt | grep "main"

# In Ghidra: Window → Script Manager → search "Demangler"
# Enable "DemangleAllScript" for automatic demangling
```

### Common Rust Patterns in Decompilation

**Option/Result 枚举：**
```text
# Option<T> in memory: {discriminant (0=None, 1=Some), value}
# Result<T, E>: {discriminant (0=Ok, 1=Err), union{ok_val, err_val}}

# In disassembly:
# cmp byte [rbp-0x10], 0    → check if None/Err
# je handle_none_case
```

**Vec<T>（类似 Go slice）：**
```c
struct RustVec {
    void *ptr;      // heap pointer
    uint64 cap;     // capacity
    uint64 len;     // length
};
```

**String / &str：**
```text
# String (owned): {ptr, capacity, length} — 24 bytes, heap-allocated
# &str (borrowed): {ptr, length} — 16 bytes, can point anywhere

# In decompilation, look for:
# alloc::string::String::from    → String creation
# core::str::from_utf8           → byte slice to str
```

**迭代器链：**
```text
# .iter().map().filter().collect() compiles to loop fusion
# In disassembly: tight loop with inlined closures
# Look for: core::iter::adapters::map, filter, etc.
```

**panic 展开：**
```bash
# Panic strings reveal source locations and error messages
strings binary | grep "panicked at"
strings binary | grep "called .unwrap().. on"
# These often contain file paths, line numbers, and variable names
```

### Rust-Specific Analysis Tools

```bash
# cargo-bloat: analyze binary size by function
cargo install cargo-bloat
cargo bloat --release -n 50

# Ghidra Rust helper scripts
# https://github.com/AmateursCTF/ghidra-rust (community scripts for Rust RE)
```

**关键点：** Rust 的 panic 字符串价值很高，常包含源文件路径、行号和语义明确的报错文本，即使 release 构建里也经常保留。应先执行 `strings binary | grep "panicked"`。同时，单态化会导致泛型函数按类型展开复制，因此会看到大量相似函数。

**识别特征：** `core::panicking`、`.rustc`、`/rustc/` 路径、带 Rust 风格模块名的 `_ZN` 符号。

---

## Swift Binary Reversing

完整 Swift 指南见 [platforms.md](platforms.md#swift-binary-reversing)。这里仅保留速查：

```bash
# Detect Swift binary
strings binary | grep "swift"
otool -l binary | grep "swift"

# Demangle Swift symbols
swift demangle 's14MyApp0A8ClassC10checkInput6resultSbSS_tF'
# → MyApp.MyAppClass.checkInput(result: String) -> Bool

# Key runtime functions: swift_allocObject, swift_release, swift_once
# String: small (≤15 bytes inline) or large (heap pointer + length)
# Protocol witness tables = dynamic dispatch (like vtables)
```

**识别特征：** Mach-O 中有 `__swift5_*` section、`swift_` 运行时符号，以及 mangled name 的 `s` 前缀。

---

## Kotlin / JVM Binary Reversing

Kotlin 可编译到 JVM 字节码或原生平台（Kotlin/Native），在 Android 和服务端题里都很常见。

### JVM Bytecode (Android/Server)

```bash
# Detect Kotlin
strings classes.dex | grep "kotlin"
# Look for: kotlin.Metadata annotation, kotlin/jvm/internal/*

# Decompile
jadx classes.dex                     # Best for Kotlin bytecode
cfr classes.jar --kotlin             # CFR with Kotlin mode
fernflower classes.jar output/       # IntelliJ's decompiler

# Kotlin-specific patterns in decompiled output:
# - Companion objects: ClassName$Companion
# - Data classes: copy(), component1(), component2(), toString()
# - Coroutines: ContinuationImpl, invokeSuspend, state machine
# - Null checks: Intrinsics.checkNotNull() everywhere
# - When expression: compiled as tableswitch/lookupswitch
# - Sealed classes: instanceof checks in chain
```

**反汇编中的协程：**
```text
# Coroutines compile to state machines:
# invokeSuspend(result) {
#     switch (this.label) {
#         case 0: this.label = 1; return suspendFunction();
#         case 1: processResult(result); return Unit;
#     }
# }
# Each suspend point becomes a state in the switch.
# Follow the state machine to understand async flow.
```

### Kotlin/Native

```bash
# Kotlin/Native produces platform binaries (no JVM)
# Recognize by: konan, kotlin.native strings
strings binary | grep "konan"

# Much harder to reverse — no reflection metadata
# Uses LLVM backend, looks similar to C/C++ in disassembly
# Key functions: InitRuntime, DeinitRuntime, CreateStablePointer
# Memory management: automatic reference counting (not GC)
```

**识别特征：** JVM 版本可见 `kotlin.Metadata` 注解；Native 版本常见 `konan` 字符串与 `kotlin/` 包路径。

---

## D Language Binary Reversing (CSAW CTF 2016)

D 语言的符号混淆与 C++ 不同，且编译期模板展开会生成大量函数变体。

```bash
# Recognition: D binaries use different mangling than C++
# Symbols contain "_D" prefix and numeric length-prefixed names
# Example: _D4mainQaFNaNbNfZv

# Symbol demangling:
# GDB: set language d
# Radare2: export names show demangled D symbols
# Online: dlang.org/phobos/core_demangle.html

# Common D binary patterns:
# - Templates instantiated at compile-time: enc!("111"), enc!("222"), ...
# - Garbage collector references (GC.malloc, GC.free)
# - Phobos standard library functions (_D3std...)
# - String processing: std.string, std.conv.to

# Reversing a D cipher (XOR with cycling key):
def reverse_d_cipher(encrypted, num_functions=500):
    """D binaries may chain multiple transformation functions.
    Each function XORs with key character, then XORs with key length.
    Process in reverse order."""
    result = encrypted[:]
    for i in range(num_functions - 1, -1, -1):
        key = str(i) * 3  # e.g., "499499499" for function enc!("499")
        key_len = len(key)
        for j in range(len(result)):
            result[j] ^= key_len
            result[j] ^= ord(key[j % key_len])
    return bytes(result)
```

**关键点：** D 在 CTF 中不常见，但 `_D` 符号前缀和 Phobos 库引用很有辨识度。模板系统会把同一逻辑按不同参数展开上百次，应优先寻找如 `enc!("N")` 这类参数化模式。

---

### Haskell Binary Reversing via STG Closures and hsdecomp (hxp CTF 2017, Codegate 2018)

GHC 编译的 Haskell 程序使用 STG（Spineless Tagless G-machine）执行模型，由于惰性求值、closure 和 thunk，通常非常难逆。STG 机器会把大量逻辑转换成 closure 调用，而不是普通函数调用。

**识别：**
- 共享库：`libHSbase-*`、`libHSrts-*`
- 入口符号：`hs_main`
- 符号采用 Z-encoding：`z` 为前缀，`Z` 表示大写，`zd` 表示 `.`，`zi` 表示 `$`
- GHC 调用约定：`rbx` = R1，`r14` = R2

**Closure 结构：**
closure 本质是一个结构体，首个 qword 指向 info table / code。info table 位于代码前方，保存 closure 类型、布局和 SRT 等元数据。

```bash
# Identify Haskell binary
ldd ./binary | grep libHS
readelf -s ./binary | grep hs_main

# Decompile with hsdecomp (github.com/gereeter/hsdecomp)
# Recovers closure structure and pattern matching into pseudo-Haskell
python2 hsdecomp ./binary

# Compile reference for monkey-patching
ghc -O0 reference.hs -o reference
objcopy --dump-section .text=main_code reference
```

**Monkey-patching 技巧：**
若反编译失败或 closure 太黑盒，可用同版本 GHC 编译一个最小 Haskell 程序，提取其 `Main_main_info` 代码，再 patch 到题目二进制中，强制求值隐藏 closure 并打印结果。

```haskell
-- reference.hs: minimal program that evaluates and prints the target closure
module Main where
main :: IO ()
main = print targetClosure  -- replace with the closure you want to evaluate
```

**关键点：** Haskell 的核心障碍是惰性求值和 closure 语义。`hsdecomp` 可恢复 closure 结构和模式匹配；若失败，可通过 monkey-patching 已知 `Main_main_info` 强制执行目标 closure。

**识别特征：** `libHSbase-*`、`hs_main`、Z-encoding 符号（如 `MainZCmain`）、GHC 版本字符串。

**参考：** hxp CTF 2017, Codegate 2018

---

### Haskell Binary RE via GHC CMM Intermediate Language (N1CTF 2018)

GHC 编译的 Haskell 在 IDA 中几乎无法直接反编译；若题目提供或可恢复 `.cmm`（C-- 中间表示），应优先阅读它来理解 thunk、closure 与惰性求值。对于指数增长的递归结构，不要展开完整字符串，而应先记忆化计算每层长度，再二分定位目标字符。

**模式：** 程序构造递归字符串：`f(n) = s1 + f(n-1) + s2 + f(n-1) + s3`。直接求值的时间和空间都是 `O(2^n)`。正确做法是先记忆化每层大小，再沿边界递归定位目标下标。

```python
# Haskell recursive string: f(n) = s1 + f(n-1) + s2 + f(n-1) + s3
# Direct evaluation is O(2^n) -- use size memoization:
from functools import lru_cache

@lru_cache(maxsize=None)
def fsize(n):
    if n == 0: return len(s0)
    return len(s1) + fsize(n-1) + len(s2) + fsize(n-1) + len(s3)

def char_at(n, offset):
    if n == 0: return s0[offset]
    if offset < len(s1): return s1[offset]
    offset -= len(s1)
    if offset < fsize(n-1): return char_at(n-1, offset)
    offset -= fsize(n-1)
    if offset < len(s2): return s2[offset]
    offset -= len(s2)
    return char_at(n-1, offset)
```

**关键点：** GHC 的 CMM 足以保留算法骨架。遇到每层翻倍增长的递归字符串，先算区段大小，再二分/递归取字符，远比物化整个结果高效。

**识别特征：** Haskell 二进制（见上）且题目发行包中附带 `.cmm` 文件。

**参考：** N1CTF 2018

---

## C++ Binary Reversing (Quick Reference)

虽然 C++ 逆向已有大量通用资料，但下面这些模式在 CTF 中尤其常见：

### vtable Reconstruction

```text
# Virtual function tables (vtables):
# First 8 bytes of object → pointer to vtable
# vtable entries: [typeinfo_ptr, destructor, method1, method2, ...]
# In Ghidra: Data → Create Pointer at vtable address

# Identify polymorphic dispatch:
# mov rax, [rdi]           # Load vtable from this pointer
# call [rax + 0x18]        # Call 4th virtual method (0x18/8 = 3rd after typeinfo+dtor)
```

### RTTI (Run-Time Type Information)

```bash
# If not stripped, RTTI reveals class hierarchy
strings binary | grep -E "^[0-9]+[A-Z]"   # Mangled type names
c++filt _ZTI7MyClass                        # → typeinfo for MyClass

# In Ghidra: search for vtable references, follow typeinfo pointer
# typeinfo struct: {vtable_for_typeinfo, name_string, base_class_ptr}
```

### Standard Library Patterns

```text
std::string (libstdc++):
  SSO (Small String Optimization): inline buffer for ≤15 chars
  Layout: {char* ptr, size_t size, union{size_t cap, char buf[16]}}

std::vector<T>:
  {T* begin, T* end, T* capacity_end}

std::map<K,V>:
  Red-black tree: each node has {left, right, parent, color, key, value}

std::unordered_map<K,V>:
  Hash table: {bucket_array, size, load_factor_max, ...}
```

---

### Rust Lifetime Escape via Compiler Bug #25860 (Hack.lu 2018)

**模式：** Rust 编译器漏洞 rust-lang/rust#25860 会错误检查 higher-ranked lifetime variance，使 closure 可通过“重新借用”把引用不安全地延长到 `'static`。在只允许 safe Rust 的沙箱中，这会产生 UAF 原语：可把 `Vec<u8>` 的堆缓冲区别名成 `(usize, usize, usize)` 头部并越界读写。

```rust
// Triggering pattern — safe Rust only
fn extend<'a, 'b, T>(_: &'a &'b (), v: &'b T) -> &'a T { v }

fn bad<T>(v: T) -> &'static T {
    // Closure infers 'a = 'static because of the variance bug
    let f: fn(&'_ &'_ (), &'_ T) -> &'_ T = extend;
    f(&&(), &v) // returned ref now outlives v
}

fn main() {
    let aliased: &'static Vec<u8> = bad(vec![1u8, 2, 3]);
    // Reinterpret the Vec as its raw header: (ptr, len, cap)
    let header: &(usize, usize, usize) =
        unsafe { std::mem::transmute(aliased) };
    println!("ptr={:#x} len={} cap={}", header.0, header.1, header.2);
}
```

**关键点：** 借用检查器中的单个 soundness bug 就足以把安全 Rust 沙箱变成任意读写原语。当题目禁用 `unsafe` 且固定了编译器版本时，应去查该版本之后修复的 `soundness` issue。

**参考：** Hack.lu CTF 2018 — Rusty CodePad, writeup 11859

---

### Rust #[no_mangle] libc Override for seccomp Bypass (Hack.lu 2018)

**模式：** 沙箱化 Rust 二进制在 `main` 早期调用 `prctl(PR_SET_SECCOMP, ...)`，然后转入用户代码。由于题目 crate 与 libc 静态链接，只要定义一个名为 `prctl` 的 `extern "C"` 函数并加上 `#[no_mangle]`，就能在链接期覆盖 libc 符号。返回 `0` 即可假装 seccomp 安装成功，实际不启用过滤。

```rust
// User-supplied code — linked into the same binary as the sandbox harness
#[no_mangle]
pub extern "C" fn prctl(_a: i64, _b: i64) -> i64 {
    0 // pretend success, do not install any filter
}

// When main() calls prctl(PR_SET_SECCOMP, ...) it hits our override
fn main() {
    // The real program runs without seccomp filtering
}
```

**关键点：** Rust 默认静态链接下，`extern "C"` + `#[no_mangle]` 基本等价于编译期 hook。只要沙箱框架调用了某个 libc 符号，攻击者就有机会用同名实现覆盖它。

**参考：** Hack.lu CTF 2018 — Rusty CodePad seccomp variant, writeup 11864

### Rust xmmword Constant Extraction via IDAPython (Insomnihack 2019)

**模式：** Rust 会把字节常量（如 flag 期望值、XOR 表）以 16 字节 xmmword 形式放进 `.rodata`。IDA 通常会显示为 `xmmword_xxxx`。可用 IDAPython 遍历 `.rodata`，读出这些常量，再逆掉简单混淆。

```python
import idc, idaapi
start, end = 0x4A1000, 0x4A1100
for ea in range(start, end, 4):
    d = idc.get_wide_dword(ea)
    print(chr((d >> 2) ^ 0xA), end='')
```

**关键点：** Rust 很难反编译，但字面常量通常很好找。凡是 `input == const_buf` 一类校验，目标值基本都会完整保留在 `.rodata` 中。

**参考：** Insomnihack teaser 2019 — beginner_reverse, writeup 12910

---

## Nuitka-Compiled Python — Module Stub Injection (X-MAS CTF 2018)

**模式：** Nuitka 会把 Python 打包成单体原生二进制，但运行时仍沿用标准 import 机制。只要在当前目录预放一个假的 `base64.py` / `midi.py` / 其他模块同名文件，模块系统就会优先加载你的 stub 而不是内嵌实现。通过记录属性访问和调用参数，可逐步拼出样本使用的 API。

```python
# base64.py next to the binary
class _Trace:
    def __getattr__(self, name):
        def f(*a, **k):
            print(f'base64.{name}({a!r}, {k!r})')
            return b''
        return f
import sys; sys.modules[__name__] = _Trace()
```

运行 `./target_bin`，打印出来的调用轨迹就能直接暴露算法，而不必硬啃 Nuitka 产物。

**关键点：** 只要运行时仍通过 `sys.path` 解析模块名（Nuitka、某些 PyInstaller、Py2Exe、frozen CPython），就可以用当前目录 stub 劫持导入流程。先从 `strings` 里找模块名，再选择合适的 hook 点。

**参考：** X-MAS CTF 2018 — A Christmas Carol, writeup 12667
