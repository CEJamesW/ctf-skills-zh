# CTF Reverse - 仿真与侧信道工具

针对存在反调试、自修改代码或跨架构目标，使得普通 GDB/Frida 不实用的 CTF 题目，介绍仿真框架（Qiling、Triton）和侧信道测量工具（Intel Pin、LD_PRELOAD 钩子）。

核心动态分析工具（Frida、angr、lldb、x64dbg）请参见 [tools-dynamic.md](tools-dynamic.md)。

## 目录
- [Qiling 框架（跨平台仿真）](#qiling-framework-cross-platform-emulation)
  - [Qiling 安装](#qiling-installation)
  - [基本用法](#basic-usage)
  - [通过仿真绕过反调试](#anti-debug-bypass-via-emulation)
  - [使用 Qiling 进行输入模糊测试](#input-fuzzing-with-qiling)
- [Triton（动态符号执行）](#triton-dynamic-symbolic-execution)
- [Intel Pin 指令计数侧信道（Hackover CTF 2015）](#intel-pin-instruction-counting-side-channel-hackover-ctf-2015)
  - [结合遗传算法的 Intel Pin 指令计数（hxp CTF 2017）](#intel-pin-instruction-counting-with-genetic-algorithm-hxp-ctf-2017)
- [仅基于 Opcode 的执行轨迹重构（0CTF 2016）](#opcode-only-trace-reconstruction-0ctf-2016)
- [LD_PRELOAD time() 冻结实现确定性分析（EKOPARTY 2017）](#ld_preload-time-freeze-for-deterministic-analysis-ekoparty-2017)
  - [LD_PRELOAD memcmp 侧信道实现逐字节暴力破解（Blaze CTF 2018）](#ld_preload-memcmp-side-channel-for-byte-by-byte-bruteforce-blaze-ctf-2018)

---

## Qiling 框架（跨平台仿真）

Qiling 支持带有操作系统层（系统调用、文件系统、注册表）支持的二进制仿真。基于 Unicorn，但补充了 Unicorn 缺失的操作系统层。

### Qiling 安装

```bash
pip install qiling
# 下载目标操作系统的 rootfs：
git clone https://github.com/qilingframework/rootfs
```

### 基本用法

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Linux ELF 仿真
ql = Qiling(["./binary", "arg1"], "rootfs/x8664_linux",
            verbose=QL_VERBOSE.DEFAULT)
ql.run()

# Windows PE 仿真（无需 Windows 系统！）
ql = Qiling(["rootfs/x86_windows/bin/binary.exe"], "rootfs/x86_windows")
ql.run()

# ARM/MIPS 仿真（物联网固件）
ql = Qiling(["rootfs/arm_linux/bin/binary"], "rootfs/arm_linux")
ql.run()
```

### 通过仿真绕过反调试

```python
from qiling import Qiling

ql = Qiling(["./binary"], "rootfs/x8664_linux")

# 钩取 ptrace 系统调用 — 返回 0（成功）
def hook_ptrace(ql, ptrace_request, pid, addr, data):
    ql.log.info("ptrace 绕过成功")
    return 0

ql.os.set_syscall("ptrace", hook_ptrace)

# 钩取特定地址（例如反虚拟机检测）
def skip_check(ql):
    ql.arch.regs.rax = 0  # 强制成功
    ql.log.info(f"跳过了 {ql.arch.regs.rip:#x} 处的检测")

ql.hook_address(skip_check, 0x401234)

ql.run()
```

### 使用 Qiling 进行输入模糊测试

```python
# 用不同输入仿真二进制以寻找 flag
import string
from qiling import Qiling

def test_input(candidate):
    ql = Qiling(["./binary"], "rootfs/x8664_linux",
                verbose=QL_VERBOSE.DISABLED, stdin=candidate.encode())
    ql.run()
    return ql.os.stdout.read()

for ch in string.printable:
    output = test_input("flag{" + ch)
    if b"Correct" in output:
        print(f"找到：{ch}")
```

**相较于 GDB/Frida 的优势：**
- 无调试器痕迹（默认绕过所有反调试）
- 跨平台且无需硬件（x86 主机上支持 ARM、MIPS、RISC-V）
- 可用 Python 脚本控制（迭代速度快于 GDB）
- 支持快照/恢复，便于暴力破解

**关键洞察：** Qiling 仿真整个操作系统层（系统调用、文件系统、注册表），而不仅仅是 CPU。这意味着反调试检测如 `ptrace(TRACEME)` 自然返回成功，无需补丁；且可在 x86 主机上分析 ARM/MIPS 二进制，无需 QEMU 或真实硬件。

**适用场景：** 外架构二进制、物联网固件、重度反调试、自动化多输入测试。

---
## Triton（动态符号执行）

完整的 Triton 参考请见 [tools-advanced.md](tools-advanced.md#triton-dynamic-symbolic-execution)。快速用法：

```python
from triton import *

ctx = TritonContext(ARCH.X86_64)

# 符号化输入缓冲区
for i in range(32):
    ctx.symbolizeMemory(MemoryAccess(0x600000 + i, CPUSIZE.BYTE), f"flag_{i}")

# 处理指令并收集约束
# 在比较点，求解 flag
model = ctx.getModel(ctx.getPathConstraintsAst())
flag = ''.join(chr(v.getValue()) for _, v in sorted(model.items()))
```

**关键洞察：** Triton 擅长单路径 DSE（动态符号执行），而 angr 在路径爆炸时表现不佳。给它一个具体的执行轨迹，符号化特定输入，并在比较点求解约束。对于已知执行流程的线性代码路径，速度比 angr 快。

**适用场景：** 单路径符号执行、去混淆、污点分析。对于线性代码路径，速度优于 angr。

---

## Intel Pin 指令计数侧信道（Hackover CTF 2015）

**模式：** 使用 Intel Pin 的 `inscount0` 工具对二进制逐字符暴力破解。每个正确字符会导致比较逻辑中执行更深（更多指令）。

```python
import string
from subprocess import Popen, PIPE

pin = './pin'
tool = './source/tools/ManualExamples/obj-ia32/inscount0.so'
binary = './target'

key = ''
while True:
    best_count, best_char = 0, ''
    for c in string.printable:
        cmd = [pin, '-injection', 'child', '-t', tool, '--', binary]
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        p.communicate((key + c + '\n').encode())
        with open('inscount.out') as f:
            count = int(f.read().split()[-1])
        if count > best_count:
            best_count, best_char = count, c
    key += best_char
    print(f"Found: {key}")
```

**关键洞察：** Movfuscated 二进制（用 `movfuscator` 编译）将每条指令展开为一系列 `mov` 操作，静态分析几乎不可能。但逐字符比较仍会产生可测量的指令计数差异。Pin 的 `inscount0.so` 统计执行的总指令数——每个位置的正确字符会导致约 1000 条以上的额外指令（在比较中执行更远）。同样适用于带有顺序输入检查的混淆二进制。

---

### Intel Pin 指令计数结合遗传算法（hxp CTF 2017）

对于自修改代码，只有在每个字符检查通过后才解密下一块，标准的逐字符 Pin 计数失败，因为搜索空间太大且字符间可能相互影响。改用遗传算法更高效地探索输入空间。

```python
import subprocess
import random
import string

PIN_PATH = '/tmp/pin-3.5/pin'
TOOL_PATH = 'source/tools/ManualExamples/obj-intel64/inscount0.so'

def fitness(candidate):
    """在 Pin 下运行二进制，返回指令计数作为适应度。"""
    proc = subprocess.Popen(
        [PIN_PATH, '-t', TOOL_PATH, '--', './binary'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(candidate.encode())
    # inscount0 将计数写入 stderr 或 inscount.out
    try:
        with open('inscount.out') as f:
            return int(f.read().split()[-1])
    except:
        return 0

def mutate(individual, rate=0.1):
    """随机变异个体中的字符。"""
    result = list(individual)
    for i in range(len(result)):
        if random.random() < rate:
            result[i] = random.choice(string.printable[:62])
    return result

# 遗传算法参数
FLAG_LEN = 40
POP_SIZE = 100
SURVIVORS = 20

# 初始化随机种群
population = [random.choices(string.printable[:62], k=FLAG_LEN) for _ in range(POP_SIZE)]

for generation in range(10000):
    # 按指令计数评分个体
    scored = [(fitness(''.join(p)), p) for p in population]
    scored.sort(reverse=True)
    best_score, best_individual = scored[0]
    print(f"Gen {generation}: {best_score} {''.join(best_individual)}")

    # 保留顶级幸存者，变异补充种群
    survivors = [s[1] for s in scored[:SURVIVORS]]
    population = survivors + [mutate(random.choice(survivors)) for _ in range(POP_SIZE - SURVIVORS)]
```

**针对 Go 二进制（表查找式 flag 检查）的修改 Pin：**
当标准 `inscount` 失败（计数增量与正确性无关，如表查找比较），修改 Pin 的 icount 工具只统计成功分支地址的执行次数。用此定向计数器逐字符暴力破解：
```cpp
// 修改后的 inscount0.cpp — 仅统计特定地址的执行次数
static ADDRINT target_addr = 0x401234;  // 成功分支地址
static UINT64 target_count = 0;

VOID CountAtTarget(ADDRINT ip) {
    if (ip == target_addr) target_count++;
}

VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CountAtTarget,
                   IARG_INST_PTR, IARG_END);
}
```

**关键洞察：** 当每个正确字符解锁新的代码段（自修改或多阶段解密）时，指令计数随正确性单调增加。遗传算法比逐字符暴力更高效地探索输入空间，因为它能同时发现多个正确字符。40 字符 flag 约 30 分钟收敛。对于总指令计数不相关的表查找比较，改为针对特定分支地址计数。

**参考：** hxp CTF 2017

---
## 仅操作码追踪重构（Opcode-Only Trace Reconstruction，0CTF 2016）

给定仅包含操作码（无寄存器/内存值）的执行追踪，重构程序：按地址排序/去重追踪，拆分成基本块，标注函数。排序算法尤其脆弱——分支决策泄露元素排序信息。

**方法：**
1. 按地址排序追踪条目，去重以恢复代码布局
2. 识别基本块边界（跳转、调用、返回）
3. 从追踪顺序映射分支是否被采取的决策
4. 对排序算法，分区比较揭示所有输入元素的相对顺序

**关键洞察：** 执行追踪即使无数据值，仍通过分支决策泄露信息。快速排序的分区比较揭示每步哪个元素更大/更小，仅凭分支方向即可完全恢复排序后的输入。

---

## 通过 LD_PRELOAD 劫持 time() 实现确定性分析（EKOPARTY 2017）

通过 LD_PRELOAD 覆盖 `time()` 返回常量值，冻结任何基于时间戳的伪随机数生成器。一旦二进制的加密变为确定性，即可无需理解 VM 或加密细节，逐字节暴力破解输出。

```c
// freeze_time.c — 编译：gcc -shared -fPIC -o freeze.so freeze_time.c
#include <time.h>

time_t time(time_t *t) {
    if (t) *t = 1234567890;
    return 1234567890;
}
```

```bash
# 编译并使用：
gcc -shared -fPIC -o freeze.so freeze_time.c
LD_PRELOAD=./freeze.so ./binary

# 逐字节 oracle：在冻结时间下运行，尝试每个候选字节，
# 观察输出——正确字节产生预期输出字符。
for byte in $(seq 0 255); do
    output=$(echo -n "$(printf '\x%02x' $byte)" | LD_PRELOAD=./freeze.so ./binary)
    # 检查输出是否符合已知/预期
done
```

如果程序还使用了 `srand()` 或 `rand()`，也覆盖 `rand()`：
```c
int rand(void) { return 42; }
```

**关键洞察：** 通过 LD_PRELOAD 劫持函数冻结非确定性源（时间、随机数）。一旦变为确定性，复杂 VM 也能成为逐字节 oracle。

**参考：** EKOPARTY CTF 2017

---

### 通过 LD_PRELOAD 劫持 memcmp 实现逐字节旁路暴力破解（Blaze CTF 2018）

**模式：** 用 LD_PRELOAD 库替换 `memcmp`，返回匹配字节数而非标准的 -1/0/1 结果。将任何基于 memcmp 的验证转为逐字节 oracle。结合 GDB Python 脚本自动暴力破解每个字符位置。

```c
// memcmp_hook.c - 编译：gcc -shared -fPIC -o hook.so memcmp_hook.c
int memcmp(const char *s1, const char *s2, int n) {
    int cnt = 0;
    for (int i = 0; i < n; ++i) {
        if (s1[i] == s2[i]) cnt++;
        else break;
    }
    return cnt;
}
```

```bash
# 使用方法：LD_PRELOAD=./hook.so gdb ./binary
# 在 memcmp 调用后设置断点，读取返回值以计数匹配字节数
# 逐个字符尝试，找到能增加匹配计数的字符
```

**关键洞察：** 通过 LD_PRELOAD 替换 memcmp 返回匹配长度，将任何比较验证转为逐字节 oracle。结合 GDB 脚本，自动暴力破解密码/flag，无需逆向验证算法。

**检测方式：** 二进制使用 `memcmp` 或 `strcmp` 进行 flag 验证（可通过 `ltrace` 输出或导入表观察）。比较函数以用户输入和计算/存储的期望值作为参数。

**参考：** Blaze CTF 2018
