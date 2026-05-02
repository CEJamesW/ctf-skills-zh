# CTF Reverse - 比赛特定模式（Part 2）

## Table of Contents
- [Multi-Layer Self-Decrypting Binary (DiceCTF 2026)](#multi-layer-self-decrypting-binary-dicectf-2026)
- [Embedded ZIP + XOR License Decryption (MetaCTF 2026)](#embedded-zip--xor-license-decryption-metactf-2026)
- [Stack String Deobfuscation from .rodata XOR Blob (Nullcon 2026)](#stack-string-deobfuscation-from-rodata-xor-blob-nullcon-2026)
- [Prefix Hash Brute-Force (Nullcon 2026)](#prefix-hash-brute-force-nullcon-2026)
- [CVP/LLL Lattice for Constrained Integer Validation (HTB ShadowLabyrinth)](#cvplll-lattice-for-constrained-integer-validation-htb-shadowlabyrinth)
- [Decision Tree Function Obfuscation (HTB WonderSMS)](#decision-tree-function-obfuscation-htb-wondersms)
- [GF(2^8) Gaussian Elimination for Flag Recovery (ApoorvCTF 2026)](#gf28-gaussian-elimination-for-flag-recovery-apoorvctf-2026)
- [ROP Chain Obfuscation in Modified Binary (PlaidCTF 2016)](#rop-chain-obfuscation-in-modified-binary-plaidctf-2016)

---

## Multi-Layer Self-Decrypting Binary (DiceCTF 2026)

**模式（another-onion）：** 二进制包含 N 层（例如 256 层），每层读取 2 个 key 字节，用 SHA-256 NI 指令派生 keystream，XOR 解密下一层后跳转过去。题目通常有时间限制（如 30 分钟）。

**正确 key 的 oracle：** 错误 key 会产生垃圾代码；正确 key 解出的下一层代码中恰好有 2 条 `call read@plt`。可据此对每层枚举全部 65536 个候选。

**JIT 执行方案（最快）：**
```c
// Map binary's memory at original virtual addresses into solver process
// Compile solver at non-overlapping address: -Wl,-Ttext-segment=0x10000000
void *text = mmap((void*)0x400000, text_size, PROT_RWX, MAP_FIXED|MAP_PRIVATE, fd, 0);
void *bss = mmap((void*)bss_addr, bss_size, PROT_RW, MAP_FIXED|MAP_SHARED, shm_fd, 0);

// Patch read@plt to inject candidate bytes instead of reading stdin
// Patch tail jmp/call to next layer with ret/NOP to return from layer

// Fork-per-candidate: COW gives isolated memory without memcpy
for (int candidate = 0; candidate < 65536; candidate++) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: remap BSS as MAP_PRIVATE (COW from shared file)
        mmap(bss_addr, bss_size, PROT_RW, MAP_FIXED|MAP_PRIVATE, shm_fd, 0);
        inject_key(candidate >> 8, candidate & 0xff);
        ((void(*)())layer_addr)();  // Execute layer as function call
        // Check: does decrypted code contain exactly 2 call read@plt?
        if (count_read_calls(next_layer_addr) == 2) signal_found(candidate);
        _exit(0);
    }
}
```

**性能分层：**
| Approach | Speed | 256-layer estimate |
|----------|-------|--------------------|
| Python subprocess | ~2/s | days |
| Ptrace fork injection | ~119/s | 6+ hours |
| JIT + fork-per-candidate | ~1000/s | 140 min |
| JIT + shared BSS + 32 workers | ~3500/s | **~17 min** |

**共享 BSS 优化：** 将 16MB+ 的 BSS 存进 `/dev/shm`，父进程用 `MAP_SHARED` 映射，子进程再以 `MAP_PRIVATE` 方式重映射，利用 COW 降低 fork 开销，从 16MB 级页表准备降到约 4KB。

**关键点：** 多层解密题本质是构建高性能暴力引擎。JIT 执行（把二进制内存映射进求解器，直接以函数方式调用）比 ptrace 快一个数量级以上。基于 fork 的 COW 又能免费提供每个候选的内存隔离。

**坑点：**
- 真正的二进制可能用 `call`（`0xe8`）而不是 `jmp`（`0xe9`）跨层跳转，需要调整尾部 patch
- BSS 可能超出 ELF 的 MemSiz，由内核 brk 补齐，需额外映射
- SHA-NI 指令有时即使 `/proc/cpuinfo` 未声明也能执行

---

## Embedded ZIP + XOR License Decryption (MetaCTF 2026)

**模式（License To Rev）：** 二进制要求传入一个 license 文件参数；程序内部还嵌了包含正确 license 的 ZIP，以及一段 XOR 加密的 flag。

**识别特征：**
- `strings` 能看到 `EMBEDDED_ZIP`、`ENCRYPTED_MESSAGE`
- 程序未 strip，`nm` 或 `readelf -s` 可直接看到 `.rodata` 中的数据符号
- `file` 显示是 PIE，可执行源码名如 `licensed.c`

**分析流程：**
1. **定位数据符号：**
```bash
readelf -s binary | grep -E "EMBEDDED|ENCRYPTED|LICENSE"
# EMBEDDED_ZIP at offset 0x2220, 384 bytes
# ENCRYPTED_MESSAGE at offset 0x21e0, 35 bytes
```

2. **提取内嵌 ZIP：**
```python
import struct
with open('binary', 'rb') as f:
    data = f.read()
# Find PK\x03\x04 magic in .rodata
zip_start = data.find(b'PK\x03\x04')
# Extract ZIP (size from symbol table or until next symbol)
open('embedded.zip', 'wb').write(data[zip_start:zip_start+384])
```

3. **从 ZIP 中取出 license：**
```bash
unzip embedded.zip  # Contains license.txt
```

4. **XOR 解密 flag：**
```python
license = open('license.txt', 'rb').read()
enc_msg = open('encrypted_msg.bin', 'rb').read()  # Extract from .rodata
flag = bytes(a ^ b for a, b in zip(enc_msg, license))
print(flag.decode())
```

**关键点：** 不需要运行二进制，也不需要绕过过期时间检查。内嵌 ZIP 和加密消息都在 `.rodata`，直接离线提取并 XOR 即可。

**反汇编确认：**
- `memcmp(user_license, decompressed_embedded_zip, size)` 用于校验 license
- 用 `sscanf("%d-%d-%d")` 解析 `EXPIRY_DATE=`
- XOR 循环：`ENCRYPTED_MESSAGE[i] ^ license[i]`，再 `putc()`

**经验：** 当二进制保留了 `EMBEDDED_*`、`ENCRYPTED_*` 这类命名符号时，优先直接提数据，不要先执行程序。

---

## Stack String Deobfuscation from .rodata XOR Blob (Nullcon 2026)

**模式（stack_strings_1/2）：** 二进制从 `.rodata` 映射一个 blob，先 XOR 去混淆，再用该 blob 校验输入。flag 需通过重写校验逻辑恢复。

**识别特征：**
- `mmap()` 后紧跟对 `.rodata` 数据的 XOR 循环
- 校验循环维护运行状态（`eax`、`ebx`、`r9`），并使用 `0x9E3779B9`、`0x85EBCA6B`、`0xA97288ED` 等常量
- 有 `rol32()`，位移与位置相关
- 期望字节存于去混淆后的缓冲区

**做法：**
1. 用 pyelftools 提取 `.rodata` blob：
   ```python
   from elftools.elf.elffile import ELFFile
   with open(binary, "rb") as f:
       elf = ELFFile(f)
       ro = elf.get_section_by_name(".rodata")
       blob = ro.data()[offset:offset+size]
   ```
2. 根据反汇编中的已知 key，通过 XOR 恢复嵌入常量（长度、magic 等）
3. 重写逐字节校验循环：
   - 每轮根据运行状态算出两个类哈希值
   - 将二者以及期望字节异或，恢复当前输入字节
   - 用固定增量更新运行状态

**变体（stack_strings_2）：** 增加了位置置换和对前一字符的状态依赖：
- 位置置换：第 `i` 个字节可能被写到输出的 `pos[i]`
- 状态依赖：`need = (expected - rol8(prev_char, 1)) & 0xFF`
- 每轮必须跟踪更新到当前字符的 `state`

**应重点识别的常量：**
- `0x9E3779B9`（黄金比例分数，常见哈希常量）
- `0x85EBCA6B`（MurmurHash3 finalizer 常量）
- `0xA97288ED`（相关哈希常量）
- 位移量为 `i & 7` 的 `rol32()`

---

## Prefix Hash Brute-Force (Nullcon 2026)

**模式（Hashinator）：** 程序对输入的每个前缀分别计算哈希，并输出一行 digest。若给出 N 个输出 digest，则 flag 长度为 N-1。

**攻击方式：** 逐字符恢复输入：
```python
for pos in range(1, len(target_hashes)):
    for ch in charset:
        candidate = known_prefix + ch + padding
        hashes = run_binary(candidate)
        if hashes[pos] == target_hashes[pos]:
            known_prefix += ch
            break
```

**关键点：** 如果每个前缀哈希彼此独立，没有 chaining/HMAC，那么问题会分解为 `N × |charset|` 次程序运行。这本质上就是哈希版的 byte-at-a-time 攻击。

**识别方式：** 程序会输出多行 hash。只改最后一个字符，只影响最后一行。不同输入长度会导致输出行数不同。

---

## CVP/LLL Lattice for Constrained Integer Validation (HTB ShadowLabyrinth)

**模式：** 二进制用矩阵乘法校验 flag，把字符分组后与系数矩阵相乘，再与预期的 64 位结果比较。普通代数求解无效，因为解必须落在可打印 ASCII 范围（32-126）。这类题可用基于 LLL 的 CVP（Closest Vector Problem）高效求解。

**识别方式：**
1. 二进制按组处理输入字符（例如每组 4 个）
2. 每组与一个系数矩阵相乘
3. 输出与硬编码 64 位常量比较
4. 需要满足小范围整数约束（可打印 ASCII）

**SageMath 的 CVP 解法：**
```python
from sage.all import *

def solve_constrained_matrix(coefficients, targets, char_range=(32, 126)):
    """
    coefficients: list of coefficient rows (e.g., 4 values per group)
    targets: expected output values
    char_range: valid character range (printable ASCII)
    """
    n = len(coefficients[0])  # characters per group
    mid = (char_range[0] + char_range[1]) // 2

    # Build lattice: [coeff_matrix | I*scale]
    # The target vector includes adjusted targets
    M = matrix(ZZ, n + len(targets), n + len(targets))
    scale = 1000  # Weight to constrain character range

    for i, row in enumerate(coefficients):
        for j, c in enumerate(row):
            M[j, i] = c
        M[n + i, i] = 1  # padding

    for j in range(n):
        M[j, len(targets) + j] = scale

    target_vec = vector(ZZ, [t - sum(c * mid for c in row)
                              for row, t in zip(coefficients, targets)]
                        + [0] * n)

    # LLL + CVP
    L = M.LLL()
    closest = L * L.solve_left(target_vec)  # or use Babai
    solution = [closest[len(targets) + j] // scale + mid for j in range(n)]
    return bytes(solution)
```

**两阶段校验常见结构：**
1. **第一阶段（矩阵数学）：** 用 CVP/LLL 求出前 N 个字符
2. 前 N 字符作为 AES key，解密 `file.bin`（末尾 16 字节 XOR + AES-256-CBC + zlib 解压）
3. **第二阶段（自定义 VM）：** 解密得到的字节码在自定义 VM 中校验剩余字符，本质是另一个模 `2^32` 的线性系统

**求解模线性系统（第二阶段）：**
```python
import numpy as np
from sympy import Matrix

# M * x = v (mod 2^32)
M_mod = Matrix(coefficients) % (2**32)
v_mod = Matrix(targets) % (2**32)
# Gaussian elimination in Z/(2^32)
solution = M_mod.solve(v_mod)  # Returns flag characters
```

**关键点：** 当程序通过大系数线性组合校验输入，并且解必须落在一个很小的整数区间时，这通常是伪装成逆向题的 lattice 问题。LLL + CVP 能恢复最接近的格点。交叉参考：若需要 LLL/CVP 基础，可转看 `/ctf-crypto` 中的相关材料。

**检测：** 程序对分组输入做矩阵式运算，与 64 位常量比较，而暴力空间极大（如每组 `256^4`，共 12 组）。

---

## Decision Tree Function Obfuscation (HTB WonderSMS)

**模式：** 二进制将输入送入约 200+ 个自动生成函数。每个函数从若干输入位置构造一个多项式表达式，与常量比较，再向左/右分支。若不脚本化提取，纯手工静态分析几乎不可行。

**识别特征：**
1. 大量结构相似、名字随机的函数（如 `f315732804`）
2. 每个函数都基于若干固定输入位置做算术
3. 函数再调用其他树节点函数或最终校验函数
4. 反编译结果形如：`if (expr cmp constant) call_left() else call_right()`

**Ghidra 无头脚本批量提取：**
```python
# Extract comparison constants from all tree functions
# Run via: analyzeHeadless project/ tmp -import binary -postScript extract_tree.py
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *

fm = currentProgram.getFunctionManager()
results = []
for func in fm.getFunctions(True):
    name = func.getName()
    if name.startswith('f') and name[1:].isdigit():
        # Find CMP instruction and extract immediate constant
        inst_iter = currentProgram.getListing().getInstructions(func.getBody(), True)
        for inst in inst_iter:
            if inst.getMnemonicString() == 'CMP':
                operand = inst.getOpObjects(1)
                if operand:
                    results.append((name, int(operand[0].getValue())))
```

**借助已知输出格式做约束传播：**
1. 从已知输出字节入手（如 `http://HTB{...}`），先固定若干输入位置
2. 已固定位置会在算术约束中级联，逐步确定更多位置
3. 根节点方程约束住剩余自由变量
4. 结合局部英文单词或 flag 格式消解多解

**关键点：** 自动生成决策树看似吓人，但结构高度重复。正确方式是脚本提取（Ghidra、Binary Ninja、radare2），而不是手工挨个逆。树只是调度器，真正逻辑在叶子和对应约束中。

**检测：** 二进制含数百个类似函数，每个引用 3-5 个输入位置，并分支到另两个函数或公共叶节点。

---

## GF(2^8) Gaussian Elimination for Flag Recovery (ApoorvCTF 2026)

**模式（Forge）：** stripped 二进制在 GF(2^8)（使用 AES 多项式）上做高斯消元。矩阵和增广向量嵌在 `.rodata` 中。解向量就是 flag。

**GF(2^8) 运算，使用 AES 多项式（x^8+x^4+x^3+x+1 = 0x11b）：**
```python
def gf_mul(a, b):
    """Multiply in GF(2^8) with AES reduction polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b  # Reduction: x^8 = x^4+x^3+x+1
        b >>= 1
    return p

def gf_inv(a):
    """Brute-force multiplicative inverse (fine for 256 elements)."""
    if a == 0: return 0
    for x in range(1, 256):
        if gf_mul(a, x) == 1:
            return x
    return 0
```

**求解线性系统：**
```python
# Extract N×N matrix + N-byte augmentation from binary .rodata
N = 56  # Flag length
# Build augmented matrix: N rows × (N+1) cols

for col in range(N):
    # Find non-zero pivot
    pivot = next((r for r in range(col, N) if aug[r][col] != 0), -1)
    if pivot != col:
        aug[col], aug[pivot] = aug[pivot], aug[col]
    # Scale pivot row by inverse
    inv = gf_inv(aug[col][col])
    aug[col] = [gf_mul(v, inv) for v in aug[col]]
    # Eliminate column in all other rows
    for row in range(N):
        if row == col: continue
        factor = aug[row][col]
        if factor == 0: continue
        aug[row] = [v ^ gf_mul(factor, aug[col][j]) for j, v in enumerate(aug[row])]

flag = bytes(aug[i][N] for i in range(N))
```

**关键点：** GF(2^8) 不是普通整数运算。加法是 XOR，乘法需要多项式约减。AES 多项式（0x11b）最常见，在汇编里常表现为 `0x1b`。有些题后面还会对结果再做 AES-GCM，但高斯消元求出的原始解向量本身就是 flag。

**检测：** `.rodata` 中有大型矩阵（`N²` 字节）、行变换以 XOR 为主，并出现 `0x1b`/`0x11b` 常量。flag 长度通常与矩阵边长匹配。

---

## ROP Chain Obfuscation in Modified Binary (PlaidCTF 2016)

**模式（quite quixotic quest）：** 修改版 `curl` 提供自定义 `--pctfkey KEY` 参数。key 校验会把 `esp` 替换为一块缓冲区地址，并 `ret` 进一个保存在 `magic_buf` 符号中的约 250KB ROP 链。该链通过 XOR、MD5 和常量比较来校验 key。

**分析方法：**

1. **识别 ROP 分发：** 查找 `mov esp, eax; ret` 之类的 stack pivot，说明控制流被重定向到 ROP 链
2. **转储 ROP 链：** 用 GDB 脚本遍历链中每个返回地址，并反汇编 gadget：
```python
# GDB script to trace ROP gadgets
import gdb

magic_buf = 0x080b0000  # symbol address
buf_size = 0x40000       # quarter megabyte
offset = 0

while offset < buf_size:
    addr = int.from_bytes(gdb.selected_inferior().read_memory(magic_buf + offset, 4), 'little')
    gdb.execute(f'x/3i {addr}')
    # Advance past the gadget (typically 4 bytes per return address)
    offset += 4
```

3. **识别链中的模式：** 关注展开循环、`pop` 跳过数据、`ret imm16` 跨大块区域等
4. **重建算法：** 链通常包含：
   - key 长度检查
   - 字符级操作（ASCII 求和、与常量 XOR）
   - 哈希计算（对派生值取 MD5）
   - 哈希前缀比较
   - 用哈希作为 keystream 对输入做 XOR
   - 与嵌入常量比较

5. **提取并求解：** 导出链中的常量，暴力任何中间值（如字符和对应的 MD5 前缀），再 XOR 还原 key：
```python
import hashlib

# Brute-force the sum that produces correct MD5 prefix
target_prefix = 0xc0050bdd  # extracted from ROP chain
for s in range(128 * 0x35):  # max sum of printable chars * key_length
    h = hashlib.md5(str(s ^ xor_constant).encode()).hexdigest()
    if int(h[:8], 16) == target_prefix:
        md5_key = bytes.fromhex(h)
        break

# XOR embedded values with MD5 keystream to get flag
flag = bytes(v ^ md5_key[i % 16] for i, v in enumerate(embedded_values))
```

**关键点：** ROP 链混淆（ROPfuscation）把算法藏在一连串返回导向 gadget 中。原始地址流看起来像噪声，但只要做到三件事，它就能被正常分析：(a) 导出每个 gadget 的反汇编，(b) 过滤重复与跳过区块，(c) 注释寄存器效果。ROP 链在功能上等价于普通代码，只是把顺序执行换成了 `ret` 驱动。超大链（10 万级 gadget）往往只是被展开后的循环，最后能压缩成约千行伪代码。

另见：[patterns-ctf.md](patterns-ctf.md) 的 Part 1（隐藏模拟器 opcode、SPN 静态提取、图像 XOR 平滑恢复、逐字节分组密码攻击、数学收敛位图、Windows PE XOR 位图 OCR、两阶段 RC4+VM 加载器、GBA ROM meet-in-the-middle、Sprague-Grundy 博弈、内核模块迷宫、多线程 VM channel）。[patterns-ctf-3.md](patterns-ctf-3.md) 的 Part 3（Z3 单行 Python 电路、滑动窗口 popcount、键盘 LED 摩斯码、C++ 析构函数隐藏校验、syscall 副作用内存破坏、MFC 对话框事件处理、VM 顺序 key-chain 爆破、Burrows-Wheeler 逆变换、OpenType 字体连字利用、带自修改代码的 GLSL shader VM、指令计数器作为密码状态）。
