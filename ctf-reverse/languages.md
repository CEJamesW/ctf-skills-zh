# CTF Reverse - 语言特定技术

## Table of Contents
- [Python Bytecode Reversing (dis.dis output)](#python-bytecode-reversing-disdis-output)
  - [Common Pattern: XOR Validation with Split Indices](#common-pattern-xor-validation-with-split-indices)
  - [Bytecode Analysis Tips](#bytecode-analysis-tips)
- [Python Opcode Remapping](#python-opcode-remapping)
  - [Identification](#identification)
  - [Recovery](#recovery)
- [Pyarmor 8/9 Static Unpack (1shot)](#pyarmor-89-static-unpack-1shot)
- [DOS Stub Analysis](#dos-stub-analysis)
- [Unity IL2CPP Games](#unity-il2cpp-games)
- [HarmonyOS HAP/ABC Reverse (abc-decompiler)](#harmonyos-hapabc-reverse-abc-decompiler)
- [Brainfuck/Esolangs](#brainfuckesolangs)
  - [Brainfuck Character-by-Character Static Analysis (BSidesSF 2026)](#brainfuck-character-by-character-static-analysis-bsidessf-2026)
  - [Brainfuck Side-Channel via Read Count Oracle (BSidesSF 2026)](#brainfuck-side-channel-via-read-count-oracle-bsidessf-2026)
  - [Brainfuck Comparison Idiom Detection (BSidesSF 2026)](#brainfuck-comparison-idiom-detection-bsidessf-2026)
- [UEFI Binary Analysis](#uefi-binary-analysis)
- [Transpilation to C](#transpilation-to-c)
- [Code Coverage Side-Channel Attack](#code-coverage-side-channel-attack)
- [Functional Language Reversing (OPAL)](#functional-language-reversing-opal)
- [Python Version-Specific Bytecode (VuwCTF 2025)](#python-version-specific-bytecode-vuwctf-2025)
- [Non-Bijective Substitution Cipher Reversing](#non-bijective-substitution-cipher-reversing)
- [FRACTRAN Program Inversion (Boston Key Party 2016)](#fractran-program-inversion-boston-key-party-2016)
- [GNU Make Turing Machine Simulator (Hack.lu 2018)](#gnu-make-turing-machine-simulator-hacklu-2018)

平台或框架相关技术（Android、Roblox、Godot、Electron、Node.js、Verilog、Ruby/Perl polyglot 等）见 [languages-platforms.md](languages-platforms.md)。
Go 与 Rust 二进制逆向见 [languages-compiled.md](languages-compiled.md)。

---

## Python Bytecode Reversing (dis.dis output)

### Common Pattern: XOR Validation with Split Indices

题目直接给出 CPython 字节码（`dis.dis` 反汇编）。常见模式：
1. 检查 flag 长度
2. 偶数下标字符与 `key1` 异或，并与列表 `p1` 比较
3. 奇数下标字符与 `key2` 异或，并与列表 `p2` 比较

**逆向：**
```python
# Given: p1, p2 (expected values), key1, key2 (XOR keys)
flag = [''] * flag_length
for i in range(len(p1)):
    flag[2*i] = chr(p1[i] ^ key1)      # Even indices
    flag[2*i+1] = chr(p2[i] ^ key2)    # Odd indices
print(''.join(flag))
```

### Bytecode Analysis Tips
- `LOAD_CONST` 后接 `COMPARE_OP`，通常表示期望值
- `BINARY_XOR` 表示使用了异或变换
- `BUILD_TUPLE`/`BUILD_LIST` 配合常量，通常是目标输出数组
- 循环结构里 `FOR_ITER` + `BINARY_SUBSCR` 表示遍历 flag 字符
- 对 `ord` 的 `CALL_FUNCTION` 表示字符转整数

**关键点：** Python 字节码题会把算法以显式栈操作展开。优先关注 `LOAD_CONST`（期望输出）、`BINARY_XOR`/`BINARY_ADD`（变换方式）和 `BUILD_TUPLE`（目标数组），通常无需实际执行字节码就能还原校验逻辑。

---

## Python Opcode Remapping

### Identification
反编译器报 opcode 错误。

### Recovery
1. 在 PyInstaller 包中找到被修改过的 `opcode.pyc`
2. 与原始 Python opcode 表比较
3. 建立映射：`{new_opcode: original_opcode}`
4. 修补目标 `.pyc`
5. 正常反编译

**快捷路径（Hack.lu CTF 2013）：** 如果题目自带修改过的 Python 解释器（例如自定义 `./py`），可直接在该解释器环境中安装 `uncompyle2`/`uncompyle6`，然后用题目自带运行时反编译。修改后的解释器天然理解自己的 opcode 映射，不必手工恢复。

**按 Python 版本选工具：** `uncompyle6` 支持 Python 2.x 到 3.8。Python 3.9+ 字节码建议使用 [`pycdc`](https://github.com/zrax/pycdc)（源码编译：`git clone && cmake . && make`）。

**关键点：** opcode 重映射会让所有标准反编译器失效。最快的方法通常是在 PyInstaller 包里找到修改后的 `opcode.pyc`，与原版做 diff，再把目标 `.pyc` 补回标准 opcode 后反编译。

---

## Pyarmor 8/9 Static Unpack (1shot)

- 工具：`Lil-House/Pyarmor-Static-Unpack-1shot`
- 适用于 Pyarmor 8.x/9.x 加固脚本，无需执行样本
- 快速特征：payload 一般以 `PY` + 6 位数字开头（不支持 Pyarmor 7 及更早的 `PYARMOR` 格式）

流程：
1. 确认目标目录同时包含加固脚本和匹配的 `pyarmor_runtime` 库。
2. 运行 one-shot unpack，生成 `.1shot.` 输出（反汇编 + 实验性反编译）。
3. 以反汇编为准；若反编译源码与字节码不一致，以字节码结果为准。

```bash
python /path/to/oneshot/shot.py /path/to/scripts
```

可选参数：
```bash
# 显式指定 runtime
python /path/to/oneshot/shot.py /path/to/scripts -r /path/to/pyarmor_runtime.so

# 输出到其他目录
python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output
```

说明：
- 运行 `shot.py` 前必须先有 `oneshot/pyarmor-1shot` 可执行文件。
- 如果是 PyInstaller bundle 或归档，先解包，再交给 1shot 处理。

**关键点：** Pyarmor 8/9 通过运行时解密包装脚本。1shot 可直接处理加固字节码与 `pyarmor_runtime` 库，静态完成解包，不需要执行目标。实验性反编译结果不稳定时，以反汇编为准。

---

## DOS Stub Analysis

PE 文件可以把代码藏在 DOS stub 中：
1. 在 Ghidra/IDA 中检查 DOS stub 是否异常大
2. 用 DOSBox 运行
3. 以 16 位 DOS 程序方式载入 IDA
4. 留意 `int 16h`（键盘输入）

**关键点：** PE 文件在 PE 头之前可以嵌入完整的 16 位 DOS 程序。如果 stub 明显偏大，题目逻辑可能完全藏在其中。

---

## Unity IL2CPP Games

- 用 Il2CppDumper 导出符号
- 若 Il2CppDumper 失败，考虑 `global-metadata.dat` 可能被加密；应在主二进制中搜索字符串/xref，跟踪 metadata 加载路径，先找自定义解密逻辑
- 关注 `Start()` 函数
- 常见密钥派生：`key = SHA256(companyName + "\n" + productName)`
- 使用派生密钥解密服务端响应

需要注意，PC 平台的可执行文件通常是 `GameAssembly.dll` 或 `*Assembly.dll`，Android 平台通常是 `libil2cpp.so`。

**关键点：** IL2CPP 会把 C# 编译为本地代码，但 Il2CppDumper 仍可恢复方法名和偏移。如果 dumper 失败，通常是 `global-metadata.dat` 被加密，应先在原生二进制里追踪 metadata 解密流程。

---

## HarmonyOS HAP/ABC Reverse (abc-decompiler)

- 目标文件：`.hap` 包及其中的 `.abc` 字节码
- 工具：`https://github.com/ohos-decompiler/abc-decompiler`
- 从 releases 下载 `jadx-dev-all.jar`

启动时的关键点：
- `java -jar` 可能会进入 GUI 模式
- 命令行模式务必使用：

```bash
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI [options] <input>
```

最常用命令：
```bash
# 基本反编译到目录
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -d "out" ".abc"

# 反编译 .abc（此场景推荐）
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple -d "out_hap" "modules.abc"
```

本题推荐参数：
- `-m simple`：降低高级重建程度，减少 SSA/PHI 导致的失败
- `--log-level ERROR`：只保留关键错误
- 完整推荐命令：

```bash
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple --log-level ERROR -d "out_abc_simple" "modules.abc"
```

参数速查：
- `-d` 输出目录
- `--help` 帮助

说明：
- `.hap` 本质是压缩包，先解压，再定位和分析 `.abc`
- 路径中有空格或非 ASCII 字符时要加引号
- 每次运行使用新的输出目录，避免旧结果残留
- 报错不等于完全失败，优先查看 `out_xxx/sources/`
- `auto` 失败时先切到 `-m simple`

标准流程：
1. 先用 `-m simple --log-level ERROR`
2. 检查输出中的关键业务文件（例如 `pages/Index.java`）
3. 若需要更干净的输出，再尝试 `-m auto` 或 `-m restructure`
4. 若部分方法仍失败，保留 `simple` 输出，继续从其他路径分析逻辑

**关键点：** HarmonyOS 的 `.hap` 是 ZIP 包，内部包含 `.abc` 字节码。最稳妥的做法是使用 abc-decompiler 的 CLI 模式并加 `-m simple`；否则可能只弹出 GUI 而不处理文件。

---

## Brainfuck/Esolangs

- 检查是否由已知工具编译（如 BF-it）
- 理解 tape/内存模型
- 对 cell 操作做静态分析

### Brainfuck Character-by-Character Static Analysis (BSidesSF 2026)

**模式（i-love-my-bf-part1）：** 按字符校验输入的 BF 程序通常具有固定结构：先 `,` 读取字符，然后一串 `+`，其数量就是该字符的期望 ASCII 值。

**提取方法：**
```python
import re

bf_code = open('challenge.bf', 'r').read()

# Split on comma (input read) — each segment handles one character
segments = bf_code.split(',')
expected = []

for seg in segments[1:]:  # Skip preamble before first comma
    # Count consecutive '+' operations before any branch/output
    plus_count = 0
    for ch in seg:
        if ch == '+':
            plus_count += 1
        elif ch in '-.[]><':
            break  # Stop at first non-increment operation
    if plus_count > 0:
        expected.append(chr(plus_count % 256))

flag = ''.join(expected)
print(f"Flag: {flag}")
```

**变体：**
- 使用 `-`：字符值为 `256 - minus_count`
- 混合 `+`/`-`：取净增量
- 字符间有 cell reset（`[-]`）：各段彼此独立
- 基于循环的乘法：如 `[->>+++<<]` 表示乘 3，需要统计循环体内部操作

**识别特征：** BF 文件很大，并反复出现 `,` 后跟大量 `+`/`-`，后面再接比较结构（例如 `[-]` 或 `[->+<]`）。

**关键点：** BF 输入校验通常结构很简单，每个输入字节都与一个通过增量构造出的常量比较。提取这些增量次数即可恢复期望输入，无需运行程序。

**参考：** BSidesSF 2026 "i-love-my-bf-part1"

### Brainfuck Side-Channel via Read Count Oracle (BSidesSF 2026)

**模式（i-love-my-bf-part2）：** 若 BF 程序逐字符校验输入，则正确字符会让程序继续读取更多输入。统计每个候选输入触发了多少次 `,`（读操作），读得更多的候选就是正确字符。

```python
import itertools

def bytes_read_running_bf(bf_code, input_iter, braces):
    """Run BF and count how many input bytes were consumed."""
    tape = [0] * 30000
    ptr = ip = reads = 0
    input_list = list(input_iter)
    input_idx = 0
    while ip < len(bf_code):
        c = bf_code[ip]
        if c == ',':
            if input_idx < len(input_list):
                tape[ptr] = input_list[input_idx]
                input_idx += 1
                reads += 1
            else:
                return reads
        elif c == '.': pass
        elif c == '+': tape[ptr] = (tape[ptr] + 1) % 256
        elif c == '-': tape[ptr] = (tape[ptr] - 1) % 256
        elif c == '>': ptr += 1
        elif c == '<': ptr -= 1
        elif c == '[' and tape[ptr] == 0: ip = braces[ip]
        elif c == ']' and tape[ptr] != 0: ip = braces[ip]
        ip += 1
    return reads

# Recover flag character by character
PRINTABLE = list(range(32, 127))
flag = []
for pos in range(50):  # max flag length
    best_byte = None
    max_reads = 0
    baseline = bytes_read_running_bf(bf, flag + [PRINTABLE[0]], braces)
    for b in PRINTABLE[1:]:
        reads = bytes_read_running_bf(bf, flag + [b], braces)
        if reads > baseline:
            best_byte = b
            break
    if best_byte is None:
        break
    flag.append(best_byte)
print(bytes(flag).decode())
```

**关键点：** BF 校验程序通常是顺序推进的：读一个字符，检查，通过后才继续读下一个。哪个候选导致更多读操作，哪个就是正确字符。

**参考：** BSidesSF 2026 "i-love-my-bf-part2"

### Brainfuck Comparison Idiom Detection (BSidesSF 2026)

**模式（i-love-my-bf-part3）：** 从高级语言编译得到的 BF 程序会复用固定的比较惯用法。比如 `<[-<->] +<[>-<[-]]>[-<+>]` 就是相邻两个 cell 的相等比较。只要在 BF 解释器执行时检测该模式，就能直接从 tape 中提取比较两侧的值。

```python
EQ_PATTERN = "<[-<->] +<[>-<[-]]>[-<+>]"

def instrumented_bf_run(bf_code, dummy_input):
    """Run BF, detect equality comparisons, extract operands."""
    tape = [0] * 30000
    ptr = ip = 0
    comparisons = []

    while ip < len(bf_code):
        # Check if current position starts the eq pattern
        if bf_code[ip:ip+len(EQ_PATTERN)] == EQ_PATTERN:
            # The two cells being compared are at ptr-2 and ptr-1
            lhs = tape[ptr - 2]  # User input byte
            rhs = tape[ptr - 1]  # Expected byte
            comparisons.append((chr(lhs), chr(rhs)))
        # ... normal BF execution ...
        ip += 1

    return comparisons

# Expected bytes from comparisons reveal the flag
```

**关键点：** 编译后的 BF 会反复使用固定模板实现相等判断、条件分支和循环。对这些模板做模式匹配，往往无需完整理解程序逻辑，就能直接提取常量。

**常见 BF 惯用法：**
- `[-]`：清零 cell
- `[->+<]`：把 cell 移到右侧
- `<[-<->] +<[>-<[-]]>[-<+>]`：两个 cell 的相等比较

**参考：** BSidesSF 2026 "i-love-my-bf-part3"

---

## UEFI Binary Analysis

```bash
7z x firmware.bin -oextracted/
file extracted/* | grep "PE32+"
```

- bootkit 会替换 boot loader
- 自定义 VM 可能保护了解密逻辑
- 可把 VM 字节码提升为 C

**关键点：** UEFI 二进制本质上是 PE32+ 可执行文件。先用 `7z` 解固件，再用 `file` 找出 PE 文件并放进 Ghidra/IDA。若是 bootkit 题，重点看 DXE 驱动和 boot services protocol。

---

## Transpilation to C

对重度混淆代码：
```python
for opcode, args in instructions:
    if opcode == 'XOR':
        print(f"r{args[0]} ^= r{args[1]};")
    elif opcode == 'ADD':
        print(f"r{args[0]} += r{args[1]};")
```

编译时加 `-O3`，让编译器做常量折叠。

**关键点：** 把混淆 VM 字节码转成 C，再用 `-O3` 编译，往往能让编译器自动完成常量折叠和死代码消除，比手工去混淆更快。

---

## Code Coverage Side-Channel Attack

**模式（Coverup, Nullcon 2026）：** PHP 题同时提供 XDebug code coverage 数据和加密输出。

**原理：**
- PHP 代码调用 `xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK)`
- 加密逻辑存在数据相关分支：`if ($xored == chr(0)) ... if ($xored == chr(1)) ...`
- coverage JSON 会泄露哪些分支被执行
- 因而可推出哪些 XOR 中间值出现过

**利用：**
```python
import json

# Load coverage data
with open('coverage.json') as f:
    cov = json.load(f)

# Extract executed XOR values from branch coverage
executed_xored = set()
for line_no, hit_count in cov['encrypt.php']['lines'].items():
    if hit_count > 0:
        # Map line numbers to the chr(N) value in the if-statement
        executed_xored.add(extract_value_from_line(line_no))

# For each position, filter candidates
for pos in range(len(ciphertext)):
    candidates = []
    for key_byte in range(256):
        xored = plaintext_byte ^ key_byte  # or reverse S-box lookup
        if xored in executed_xored:
            candidates.append(key_byte)
    # Combined with known plaintext prefix, this uniquely determines key
```

**关键点：** 代码覆盖率本身就是强侧信道，它直接告诉你走过哪些条件分支。任何带数据相关分支的加密实现，都可能通过 coverage 泄露信息。

**缓解识别：** 如果实现是无分支/常数时间 crypto，则该攻击失效。

---

## Functional Language Reversing (OPAL)

**模式（Opalist, Nullcon 2026）：** 二进制由 OPAL（Optimized Applicative Language）纯函数式语言编译得到。

**识别特征：**
- `.impl`（implementation）和 `.sign`（signature）源码文件
- `IMPLEMENTATION` / `SIGNATURE` 关键字
- 大量嵌套 `IF..THEN..ELSE..FI`
- 函数名形如 `f1`, `f2`, ... `fN`
- 大量使用 `seq[nat]`、`string`、`denotation` 类型

**逆向思路：**
1. 纯函数通常可数学逆推，逐步还原整个 pipeline
2. 识别变换链：`f_final(f_n(...f_2(f_1(input))...))`
3. 对每个函数构造逆函数

**针对 scramble 函数的聚合爆破：**
当某一步会累积依赖原始值的状态时：
```python
# Example: f8 adds cumulative offset based on parity of original bytes
# offset contribution per element depends on whether pre-scramble value is even/odd
# Total offset S = sum of contributions, but S mod 256 has only 256 possibilities

decoded = base64_decode(target)
for total_offset_S in range(256):
    candidate = [(b - total_offset_S) % 256 for b in decoded]
    # Verify: recompute S from candidate values
    recomputed_S = sum(contribution(i, candidate[i]) for i in range(len(candidate))) % 256
    if recomputed_S == total_offset_S:
        # Apply remaining inverse steps
        result = apply_inverse_substitution(candidate)
        if all(32 <= c < 127 for c in result):
            print(bytes(result))
```

**关键经验：** 如果某个 scramble 函数存在“结果依赖原值、原值又未知”的鸡生蛋问题，不要暴力枚举所有状态；优先爆破聚合效应（通常模 256 只有 256 种）。

---

## Python Version-Specific Bytecode (VuwCTF 2025)

**模式（A New Machine）：** 题目要求特定 Python 版本（例如 3.14.0 alpha）。

**关键要求：** 必须编译出完全相同的 Python 版本再去反汇编，因为 alpha/beta 的 opcode 与稳定版不同。

```bash
# Build specific Python version
wget https://www.python.org/ftp/python/3.14.0/Python-3.14.0a4.tar.xz
tar xf Python-3.14.0a4.tar.xz
cd Python-3.14.0a4 && ./configure && make -j$(nproc)
./python -c "import dis, marshal; dis.dis(marshal.loads(open('challenge.pyc','rb').read()[16:]))"
```

**常见校验：** flag 与 ASCII 平方值元组比较：
```python
# Reverse: flag[i] = sqrt(expected_tuple[i])
import math
flag = ''.join(chr(int(math.isqrt(v))) for v in expected_values)
```

---

## Non-Bijective Substitution Cipher Reversing

**模式（Coverup, Nullcon 2026）：** S-box/替代表存在碰撞，多个输入映射到同一输出。

**检测：**
```python
sbox = [...]  # substitution table
if len(set(sbox)) < len(sbox):
    print("Non-bijective! Collisions exist.")
```

**构造反向查表：**
```python
from collections import defaultdict
rev_sub = defaultdict(list)
for i, v in enumerate(sbox):
    rev_sub[v].append(i)
# rev_sub[output] = [list of possible inputs]
```

**消歧方法：**
1. 已知明文格式（如 `ENO{`、`flag{`）可固定部分 key byte
2. 侧信道数据（coverage、时间）可排除错误候选
3. 可打印 ASCII 限制（32-126）可收缩搜索空间
4. 对候选重新加密并与已知密文校验

---

## FRACTRAN Program Inversion (Boston Key Party 2016)

FRACTRAN 是一种深奥语言，计算过程是对分数表反复做乘法。输入通过质因数分解编码（顺序质数的指数对应 ASCII）。逆向时，可把每个分数的分子和分母交换，再把“成功输出”倒着跑回去。

```python
# Original: for each step, find first fraction where n*frac is integer
def fractran_step(n, fractions):
    for num, den in fractions:
        if (n * num) % den == 0:
            return (n * num) // den
    return None  # Halt

# Inversion: swap num/denom in fraction table
inverted = [(d, n) for n, d in fraction_table]
# Run target output through inverted program to recover input
```

**关键点：** FRACTRAN 程序常可通过交换分子/分母实现逆向。真正的输入输出语义藏在质因数编码里，必须先分解结果并把连续质数指数映射回 ASCII。

**识别特征：** 题目提到 fractions、prime factorization，或直接给出一串有理数。

---

## GNU Make Turing Machine Simulator (Hack.lu 2018)

**模式：** 一个 `Makefile` 只靠 Make 宏实现图灵机。纸带用一元编码 `+++-` 表示（`+` 是 1，`-` 是 0），状态转移表由 14 个以空格分隔的 9 bit 单词组成，递归 `$(eval)` 驱动状态机直到停机。逆向时可直接解码状态表并与 [bbchallenge.org](https://bbchallenge.org) 的 busy-beaver 数据库比对，或自行用 Python 重写解释器。

```make
# Example sink — 14 words of 9 bits each form the transition table
PROGRAM := 0 1A 1R 1 1B 1L 1 1C 1R 0 1D 1L 0 1A 1L 1 1E 1R 1 1A 1L \
           1 1A 1L 0 1E 1R 0 1F 1R 0 1F 1L 1 1E 1L 1 1H 1R 0 1C 1R
```

```python
# Python decoder for the table
def decode_transition(word):
    bits = int(word, 2)
    write = bits >> 7 & 1
    move  = "LR"[bits >> 6 & 1]
    state = chr(ord("A") + (bits & 0x3F))
    return write, move, state

# Simulate until HALT
tape = [0] * 4096
head = 2048
state = "A"
while state != "H":
    symbol = tape[head]
    idx = (ord(state) - ord("A")) * 2 + symbol
    write, move, state = decode_transition(PROGRAM[idx])
    tape[head] = write
    head += 1 if move == "R" else -1
print(sum(tape))   # Busy-beaver score → hashed for the flag
```

**关键点：** `Makefile` 通过递归 `$(eval)` 和字符串替换可达到图灵完备，因此“只有一个 Makefile”的题也可能隐藏完整解释器。最快的方法是把转移表直接提出来，逐项解码，再本地模拟或检索公开 busy-beaver 数据库。可用 `make -n` 看展开命令而不执行，用 `make -d` 观察递归求值图。

**参考：** Hackover CTF 2018 — Flagmaker, writeup 11503
