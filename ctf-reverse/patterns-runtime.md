# CTF Reverse - Runtime Patching and Oracle Techniques

依赖运行时状态而非静态模式匹配的技术：恶意样本脱壳、多阶段 shellcode、时间/信号侧信道，以及 CTF 特定 oracle 攻击。

静态逆向模式（自定义 VM、反调试、自修改代码、LLVM 混淆、S-box 生成、SECCOMP/BPF、内存转储、x86-64 坑点、逐字节变换）见 [patterns.md](patterns.md)。

## Table of Contents
- [Malware Anti-Analysis Bypass via Patching](#malware-anti-analysis-bypass-via-patching)
- [Multi-Stage Shellcode Loaders](#multi-stage-shellcode-loaders)
- [Timing Side-Channel Attack](#timing-side-channel-attack)
- [Multi-Thread Anti-Debug with Decoy + Signal Handler Mixed Boolean-Arithmetic (ApoorvCTF 2026)](#multi-thread-anti-debug-with-decoy--signal-handler-mixed-boolean-arithmetic-apoorvctf-2026)
- [INT3 Patch + Coredump Brute-Force Oracle (Pwn2Win 2016)](#int3-patch--coredump-brute-force-oracle-pwn2win-2016)
- [Signal Handler Chain + LD_PRELOAD Oracle (Nuit du Hack 2016)](#signal-handler-chain--ld_preload-oracle-nuit-du-hack-2016)
- [printf Format String VM Decompilation to Z3 (SECCON 2017)](#printf-format-string-vm-decompilation-to-z3-seccon-2017)
- [Quadtree Recursive Image Format Parser (Google CTF Quals 2018)](#quadtree-recursive-image-format-parser-google-ctf-quals-2018)

---

## Malware Anti-Analysis Bypass via Patching

**模式（Carrot）：** 恶意样本在执行 payload 前做多层环境检查。

**常见可 patch 检查：**
| Check | Technique | Patch |
|-------|-----------|-------|
| `ptrace(PTRACE_TRACEME)` | 反调试 | 把 `cmp -1` 改为 `cmp 0` |
| `sleep(150)` | 反 sandbox 计时 | 把 sleep 值改成 1 |
| `/proc/cpuinfo` 中的 `"hypervisor"` | 反 VM | `JNZ` 改 `JZ` |
| `"VMware"` / `"VirtualBox"` 字符串 | 反 VM | `JNZ` 改 `JZ` |
| `getpwuid` 用户名检查 | 环境校验 | 翻转比较 |
| `LD_PRELOAD` 检查 | 反 hook | 跳过检查 |
| 风扇数量 / 硬件检查 | 反 VM | `JLE` 改 `JGE` |
| 主机名检查 | 环境校验 | `JNZ` 改 `JZ` |

**Ghidra patch 流程：**
1. 找到检查函数，定位条件跳转
2. 点选指令 → `Ctrl+Shift+G` → 修改 opcode
3. `JNZ`（0x75）改 `JZ`（0x74），或反之
4. 对立即数，直接改操作数字节
5. 导出：按 `O` → 选 “Original File” 格式
6. 对补丁后二进制执行 `chmod +x`

**绕过服务端校验：**
- 如果 patch 后的二进制会把系统信息发到远端，连数据也要一起 patch
- 直接修改采集函数中的字符串地址
- 改 format string，把正确值硬编码进去

---

## Multi-Stage Shellcode Loaders

**模式（I Heard You Liked Loaders）：** 多层嵌套 shellcode，带 XOR 解码循环和反调试。

**调试流程：**
1. 在 launcher 的 `call rax` 处下断，单步进入 shellcode
2. 绕过 ptrace 反调试：走到 syscall 处后 `set $rax=0`
3. 单步穿过 XOR 解码循环（若藏了 `int3`，也可直接在那下断）
4. 对每一层重复，直到最终 payload

**从 `mov` 指令提取 flag：**
```python
# Final stage loads flag 4 bytes at a time via mov ebx, value
# Extract little-endian 4-byte chunks
values = [0x6174654d, 0x7b465443, ...]  # From disassembly
flag = b''.join(v.to_bytes(4, 'little') for v in values)
```

---

## Timing Side-Channel Attack

**模式（Clock Out）：** 每个正确字符都会让校验时间变长（匹配时 sleep 更久）。

**利用：**
```python
import time
from pwn import *

flag = ""
for pos in range(flag_length):
    best_char, best_time = '', 0
    for c in string.printable:
        io = remote(host, port)
        start = time.time()
        io.sendline((flag + c).ljust(total_len, 'X'))
        io.recvall()
        elapsed = time.time() - start
        if elapsed > best_time:
            best_time = elapsed
            best_char = c
        io.close()
    flag += best_char
```

---

## Multi-Thread Anti-Debug with Decoy + Signal Handler Mixed Boolean-Arithmetic (ApoorvCTF 2026)

**模式（A Golden Experience Requiem）：** 多线程二进制叠加多层反分析：线程 1 做诱饵操作（伪 AES + `ud2` 崩溃），线程 2 在 SIGSEGV signal handler 中用 Mixed Boolean Arithmetic（MBA）计算真实 flag，线程 3 擦除内存以阻止事后分析。

**线程布局：**
| Thread | Purpose | Trap |
|--------|---------|------|
| Thread 1 | 诱饵：类 AES 操作 → `ud2` 崩溃 | 误导分析者去逆假密码 |
| Thread 2 | 真实 flag：SIGSEGV handler 中的 MBA 变换 | 隐藏在 signal handler，而非主路径 |
| Thread 3 | 内存擦除：计算完成后清零 flag 数据 | 阻止内存 dump |
| Main | 基于 `rdtsc` 的反调试计时检查 | 调试器附加时污染执行 |

**求解方法：直接用 Python 仿真 MBA 逻辑：**
```python
# MBA helpers (extracted from assembly)
def mba_add(a, b): return (a + b) & 0xff
def mba_xor(a, b): return (a ^ b) & 0xff

def mba_transform(i):
    """Position-dependent transform from signal handler."""
    val = (i * 7 + 0x3f) & 0xff
    rotated = ((i << 3) | (i >> 5)) & 0xff
    return mba_xor(val, rotated)

# S-box (SHA-256 initial hash values repurposed)
SBOX = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def sbox_lookup(i):
    idx = i & 7
    shift = ((i >> 3) & 3) * 8
    return (SBOX[idx] >> shift) & 0xff

# Two interleaved rodata arrays (even indices → array1, odd → array2)
rodata1 = bytes.fromhex("39407691b717c97879013adf3a2adea11c2b04e0")
rodata2 = bytes.fromhex("bb19b025e37eaa786c4116e7aeea00c9c623940d")

flag = []
for i in range(40):  # flag length
    t = mba_transform(i)
    s = sbox_lookup(i)
    mem = rodata1[i // 2] if i % 2 == 0 else rodata2[i // 2]
    flag.append(chr(t ^ s ^ mem))

print(''.join(flag))
```

**关键点：** 真正的 flag 逻辑在 signal handler（SIGSEGV/SIGILL）里，不在主线程。线程 1 的类 AES 代码与 `ud2` 崩溃是刻意误导。`rdtsc` 计时检查会探测调试器并污染输出。正确做法是从汇编中提取 MBA 逻辑并用 Python 重写，避免在调试器下运行原程序。

**检测指标：**
- 多个 `pthread_create`，分别传入不同 handler 函数
- `signal(SIGSEGV, handler)` 或 `sigaction` 初始化
- `ud2` 指令（故意非法指令）
- 用于计时检查的 `rdtsc`
- SHA-256 常量（0x6a09e667...）被拿来当查找表，而非哈希

---

## INT3 Patch + Coredump Brute-Force Oracle (Pwn2Win 2016)

与其逆复杂变换逻辑，不如在变换完成后 patch 一个字节为 `0xCC`（INT3），开启 core dump，对每个字符暴力运行程序，再通过 `strings` 从 coredump 提取变换结果。

```bash
# Patch byte at transform output point to 0xCC
printf '\xcc' | dd of=binary bs=1 seek=$((0x400ebb)) conv=notrunc
ulimit -c unlimited
# Brute-force each position:
for c in $(seq 32 126); do
    echo -ne "$(printf '\\x%02x' $c)$known_suffix" | ./binary 2>/dev/null
    strings core | grep -q "$expected" && echo "Found: $c"
done
```

**关键点：** 把 INT3/SIGTRAP 当作断点 oracle，用 coredump 捕获崩溃点上的计算状态，从而避免完整逆向整个变换。

---

## Signal Handler Chain + LD_PRELOAD Oracle (Nuit du Hack 2016)

二进制用 Unix signal 做流程控制：`main()` 给自己发 1024 次 SIGINT，每个 handler 检查一个密码字符，然后调用 `signal()` 安装下一个 handler。绕过方法：用 LD_PRELOAD 注入自定义 `signal()`，只要被调用就记录日志，借此判断当前字符正确。

```c
// LD_PRELOAD library:
#include <signal.h>
sighandler_t signal(int sig, sighandler_t handler) {
    write(2, "CORRECT\n", 8);  // signal() called = char was correct
    return SIG_DFL;
}
```

**关键点：** 基于 signal-handler 链的反逆向，可以直接通过 LD_PRELOAD hook `signal()` 破解。调用 `signal()` 去安装下一个 handler 这一动作本身，就是当前字符正确的侧信道。

---

### printf Format String VM Decompilation to Z3 (SECCON 2017)

所谓 “虚拟机” 实际上完全由 `%hhn` format string 实现。`%hhn` 会把已输出字符数（mod 256）写到目标字节。连续的 `%Nc%hhn` 指令就能实现任意的按字节写内存，本质上形成一个字节码 VM。

**步骤 1：识别指令类型。**
统计唯一 format pattern，推断指令集：
```bash
# Normalize numbers and count unique patterns
sed -e 's/[[:digit:]]\+/1/g' program.fs | sort | uniq -c | sort -nr
```

**步骤 2：写一个反编译器。**
把 format pattern 转成类 C 伪代码。每个 `%N...%hhn` 对应一次内存写：提取写地址（参数指针）和值（输出字符数）。

**步骤 3：识别算法。**
伪代码通常会还原出一个字节级线性方程组。将内存地址映射到符号变量。

**步骤 4：生成 Z3 约束并求解。**
```python
from z3 import *

flag_len = 32  # adjust based on decompiled output
flag = [BitVec(f'f{i}', 8) for i in range(flag_len)]
s = Solver()

# Constrain to printable ASCII
for f in flag:
    s.add(f >= 0x20, f <= 0x7e)

# Add constraints from decompiled format string operations
# e.g., flag[3] + flag[7] == 0xAB (mod 256)
# These come from the write sequences: each %hhn accumulates
# character counts and writes the result to a target byte
s.add((flag[0] + flag[1]) & 0xFF == 0x9A)  # example constraint
s.add((flag[2] ^ flag[3]) & 0xFF == 0x3F)  # example constraint
# ... (add all constraints from decompilation)

if s.check() == sat:
    m = s.model()
    print(bytes([m[f].as_long() for f in flag]))
```

**详细反编译流程：**
1. 从每个 `%N...%hhn` 对中提取写地址与写值
2. 把内存地址映射到符号变量（flag 字节）
3. 根据写序列建立方程系统
4. 用 Z3 求解

**关键点：** `%hhn` 写入的是已打印字符数（mod 256），一串 `%Nc%hhn` 可以实现任意按字节写，等价于一个字节码 VM。反编译思路是：1. 提取每次写的地址和值，2. 地址映射到符号变量，3. 从写序列构造方程组，4. 交给 Z3 解。

**References:** SECCON 2017

---

## Quadtree Recursive Image Format Parser (Google CTF Quals 2018)

**模式：** 题目给出一种私有图像格式。逆向后发现本质是四叉树：先取包住整个画布的最大 2 次幂正方形，再递归分成四个象限，用 1 字节命令指示四个象限中哪些继续细分。标为 “leaf” 的象限后跟 3 字节 RGB 颜色，其余则继续递归。

```python
# Command byte: bits 3..0 = {top-left, top-right, bottom-left, bottom-right}
# Bit set ⇒ subdivide; bit clear ⇒ leaf (next 3 bytes = RGB)

def parse(stream, x, y, size):
    cmd = stream.read(1)[0]
    half = size // 2
    children = [
        (x,        y       ),
        (x + half, y       ),
        (x,        y + half),
        (x + half, y + half),
    ]
    for i, (cx, cy) in enumerate(children):
        if cmd & (1 << (3 - i)):
            parse(stream, cx, cy, half)
        else:
            rgb = stream.read(3)
            fill_rect(cx, cy, half, half, rgb)
```

持续递归直到 `half == 1`（或遇到 “leaf” 位），按格式推进的字节流把画布填出来。只要象限 bit 顺序匹配正确，flag 图像就会正常还原。

**关键点：** CTF 中的私有图像/压缩格式，绝大多数都是 quadtree、LZ77 变体或 Huffman 流。看到短命令字节后跟递归结构或定长叶子数据时，应优先怀疑这一类。实现原型时先打印每次递归的深度与偏移；如果深度不对，第一怀疑应是 bit 顺序或 leaf 尺寸弄错了。

**References:** Google CTF Quals 2018 — writeup 10335
