# CTF Reverse - 模式与技巧

## Table of Contents
- [Custom VM Reversing](#custom-vm-reversing)
  - [Analysis Steps](#analysis-steps)
  - [Common VM Patterns](#common-vm-patterns)
  - [RVA-Based Opcode Dispatching](#rva-based-opcode-dispatching)
  - [State Machine VMs (90K+ states)](#state-machine-vms-90k-states)
  - [Custom VM Reverse Engineering via Fuzzing and Instruction Set Discovery (hxp CTF 2017)](#custom-vm-reverse-engineering-via-fuzzing-and-instruction-set-discovery-hxp-ctf-2017)
- [Anti-Debugging Techniques](#anti-debugging-techniques)
  - [Common Checks](#common-checks)
  - [Bypass Technique](#bypass-technique)
  - [LD_PRELOAD Hook](#ld_preload-hook)
  - [pwntools Binary Patching (Crypto-Cat)](#pwntools-binary-patching-crypto-cat)
- [Nanomites](#nanomites)
  - [Linux (Signal-Based)](#linux-signal-based)
  - [Windows (Debug Events)](#windows-debug-events)
  - [Analysis](#analysis)
- [Self-Modifying Code](#self-modifying-code)
  - [Pattern: XOR Decryption](#pattern-xor-decryption)
- [Known-Plaintext XOR (Flag Prefix)](#known-plaintext-xor-flag-prefix)
  - [Variant: XOR with Position Index](#variant-xor-with-position-index)
- [Mixed-Mode (x86-64 / x86) Stagers](#mixed-mode-x86-64--x86-stagers)
- [LLVM (Low Level Virtual Machine) Obfuscation (Control Flow Flattening)](#llvm-low-level-virtual-machine-obfuscation-control-flow-flattening)
  - [Pattern](#pattern)
  - [De-obfuscation](#de-obfuscation)
- [S-Box / Keystream Generation](#s-box--keystream-generation)
  - [Fisher-Yates Shuffle (Xorshift32)](#fisher-yates-shuffle-xorshift32)
  - [Xorshift64* Keystream](#xorshift64-keystream)
  - [Identifying Patterns](#identifying-patterns)
- [SECCOMP/BPF Filter Analysis](#seccompbpf-filter-analysis)
  - [BPF Analysis](#bpf-analysis)
- [Exception Handler Obfuscation](#exception-handler-obfuscation)
  - [RtlInstallFunctionTableCallback](#rtlinstallfunctiontablecallback)
  - [Vectored Exception Handlers (VEH)](#vectored-exception-handlers-veh)
- [Memory Dump Analysis](#memory-dump-analysis)
  - [When Binary Dumps Memory](#when-binary-dumps-memory)
  - [Known Plaintext Attack](#known-plaintext-attack)
- [Byte-Wise Uniform Transforms](#byte-wise-uniform-transforms)
- [x86-64 Gotchas](#x86-64-gotchas)
  - [Sign Extension](#sign-extension)
  - [Loop Boundary State Updates](#loop-boundary-state-updates)
- [Custom Mangle Function Reversing](#custom-mangle-function-reversing)
- [Position-Based Transformation Reversing](#position-based-transformation-reversing)
- [Hex-Encoded String Comparison](#hex-encoded-string-comparison)
- [Signal-Based Binary Exploration](#signal-based-binary-exploration)

关于恶意软件补丁、多阶段 shellcode 加载器、基于时间/信号的 oracle，以及 CTF 专用运行时攻击（INT3 coredump oracle、signal handler chain、printf format string VM、quadtree image format），见 [patterns-runtime.md](patterns-runtime.md)。

---

## Custom VM Reversing

### Analysis Steps
1. 识别 VM 结构：寄存器、内存、指令指针
2. 逆向 `executeIns`/`runvm` 函数，确定 opcode 语义
3. 编写反汇编器解析字节码
4. 反编译反汇编结果以理解算法

### Common VM Patterns
```c
switch (opcode) {
    case 1: *R[op1] *= op2; break;      // MUL
    case 2: *R[op1] -= op2; break;      // SUB
    case 3: *R[op1] = ~*R[op1]; break;  // NOT
    case 4: *R[op1] ^= mem[op2]; break; // XOR
    case 5: *R[op1] = *R[op2]; break;   // MOV
    case 7: if (R0) IP += op1; break;   // JNZ
    case 8: putc(R0); break;            // PRINT
    case 10: R0 = getc(); break;        // INPUT
}
```

### RVA-Based Opcode Dispatching
- Opcode 本身是指向 handler 函数的 RVA
- Handler 执行操作、读取下一个 RVA、再跳转
- 顺着 RVA 链枚举并映射全部 handler

### State Machine VMs (90K+ states)
```java
// BFS for valid path
var agenda = new ArrayDeque<State>();
agenda.add(new State(0, ""));
while (!agenda.isEmpty()) {
    var current = agenda.remove();
    if (current.path.length() == TARGET_LENGTH) {
        println(current.path);
        continue;
    }
    for (var transition : machine.get(current.state).entrySet()) {
        agenda.add(new State(transition.getValue(),
                            current.path + (char)transition.getKey()));
    }
}
```

**关键点：** 当题目把一段字节码 blob 和一个 dispatcher loop 打包在一起时，通常就是自定义 VM。先还原 opcode switch 表，再写反汇编器把字节码提升出来，最后再理解算法。

### Custom VM Reverse Engineering via Fuzzing and Instruction Set Discovery (hxp CTF 2017)

当静态分析 dispatcher loop 过于复杂时，可采用系统化黑盒方法逆向未知 VM 字节码：

**Step 1: Determine instruction alignment.**
把字节码按不同宽度（6-11 bit）导出为 bit 串，寻找指令对齐方式。重点看是否存在可指示 opcode 边界的重复模式。

**Step 2: Fuzz with random bytes.**
发送单条指令，观察寄存器/内存变化，以建立 opcode 映射。将程序缩减到最小：找出能触发每种可观测效果的最短输入。

**Step 3: Build the instruction set.**
示例：发现的 ISA（变长 6-11 bit）：
```text
000 xxxxxxxx  jmpz    001 xxxxxxxx  jmp     010 xxxxxxxx  call
011 xxxxxxxx  label   1000 xxxxxxx  loadram  1001 xxxxxxx  saveram
110 xxxxxxxx  loadi   11100 xxxxxx  shl      11101 xxxxxx  shr
111100 not    111101 and    111110 or    111111 setif
```

**Step 4: Build assembler/disassembler.**
编写汇编器/反汇编器，对已发现的 ISA 进行组装与反汇编，再对题目字节码反汇编以理解算法。

**Step 5: Implement missing primitives.**
如果 ISA 缺少预期操作，就用现有指令合成。例如仅有 AND/OR/NOT，没有原生 XOR 或 ADD，也能实现 XTEA 解密：
```python
# XOR from AND/OR/NOT:  XOR(a, b) = (a OR b) AND NOT(a AND b)
# ADD via full-adder chains using AND/OR/NOT for carry propagation
def xor_from_primitives(a, b):
    return (a | b) & ~(a & b)

def add_from_primitives(a, b, bits=32):
    carry = 0
    result = 0
    for i in range(bits):
        ai = (a >> i) & 1
        bi = (b >> i) & 1
        sum_bit = xor_from_primitives(xor_from_primitives(ai, bi), carry)
        carry = (ai & bi) | (carry & xor_from_primitives(ai, bi))
        result |= (sum_bit << i)
    return result
```

**关键点：** 如果静态分析 VM 的 dispatch loop 太难，黑盒 fuzzing 往往更快。发单条指令并观察状态变化即可映射 ISA。变长指令集需要测试多个 bit 宽度。ISA 一旦确定，即使原语很少（如只有 AND/OR/NOT），复杂算法（如 XTEA）也依然可实现。

**参考：** hxp CTF 2017

---

## Anti-Debugging Techniques

### Common Checks
- `IsDebuggerPresent()`（Windows）
- `ptrace(PTRACE_TRACEME)`（Linux）
- `/proc/self/status` 中的 TracerPid
- 定时检查（`rdtsc`、`time()`）
- 注册表检查（Windows）

### Bypass Technique
1. 找到调试检查后的 `test` 指令
2. 在该 `test` 处下断点
3. 修改寄存器，绕过条件分支

```bash
# In radare2
db 0x401234          # Break at test
dc                   # Run
dr eax=0             # Clear flag
dc                   # Continue
```

### LD_PRELOAD Hook
```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ptrace.h>

long int ptrace(enum __ptrace_request req, ...) {
    long int (*orig)(enum __ptrace_request, pid_t, void*, void*);
    orig = dlsym(RTLD_NEXT, "ptrace");
    // Log or modify behavior
    return orig(req, pid, addr, data);
}
```

编译：`gcc -shared -fPIC -ldl hook.c -o hook.so`
运行：`LD_PRELOAD=./hook.so ./binary`

**关键点：** 反调试通常是逆向题遇到的第一道障碍。优先在 `main()` 前段查找 `ptrace`、`IsDebuggerPresent` 或 timing check，并先 patch 或 hook 掉，再继续更深入分析。

### pwntools Binary Patching (Crypto-Cat)
直接用 pwntools patch 掉反调试调用，用 `ret` 替换函数体：
```python
from pwn import *

elf = ELF('./challenge', checksec=False)
elf.asm(elf.symbols.ptrace, 'ret')   # Replace ptrace() with immediate return
elf.save('patched')                   # Save patched binary
```

其他常见 patch：
```python
elf.asm(addr, 'nop')                  # NOP out an instruction
elf.asm(addr, 'xor eax, eax; ret')    # Return 0 (bypass checks)
elf.asm(addr, 'mov eax, 1; ret')      # Return 1 (force success)
```

---

## Nanomites

### Linux (Signal-Based)
- `SIGTRAP`（`int 3`）→ 自定义操作
- `SIGILL`（`ud2`）→ 自定义操作
- `SIGFPE`（`idiv 0`）→ 自定义操作
- `SIGSEGV`（空指针解引用）→ 自定义操作

### Windows (Debug Events)
- `EXCEPTION_DEBUG_EVENT` → 主处理器
- 父进程通过 `PTRACE_POKETEXT` 修改子进程
- 魔数标记：`0x1337BABE`、`0xDEADC0DE`

### Analysis
1. 检查是否存在 `fork()` + `ptrace(PTRACE_TRACEME)`
2. 找 `WaitForDebugEvent` 循环
3. 将 EAX 值映射到具体操作
4. 记录操作日志以重建算法

**关键点：** Nanomites 把真实计算藏在仅在调试父进程存在时才会触发的 signal/exception handler 中。如果二进制会 fork，且子进程调用 `ptrace(TRACEME)`，那么父进程才是真正的 CPU。记录它的 POKE 操作即可重建算法。

---

## Self-Modifying Code

### Pattern: XOR Decryption
```asm
lea     rax, next_block
mov     dl, [rcx]        ; Input char
xor_loop:
    xor     [rax+rbx], dl
    inc     rbx
    cmp     rbx, BLOCK_SIZE
    jnz     xor_loop
jmp     rax              ; Execute decrypted
```

**解法：** 若代码块起始有已知 opcode，则可由其推回 XOR key（即 flag 字符）。

**关键点：** 自修改代码通常使用每个输入字符作为密钥解密下一块代码。若每个解密块开头存在已知正确 opcode（如函数序言），就能推出正确 key byte，从而逐字符恢复 flag。

---

## Known-Plaintext XOR (Flag Prefix)

**模式：** 给出加密字节，同时已知 flag 格式（如 `0xL4ugh{`）。

**做法：**
1. 假设 XOR key 为循环重复
2. 用已知前缀（以及提示语）恢复 key 字节
3. 尝试较小 key 长度，并验证输出是否可打印

```python
enc = bytes.fromhex("...")  # ciphertext
known = b"0xL4ugh{say_yes_to_me"
for klen in range(2, 33):
    key = bytearray(klen)
    ok = True
    for i, b in enumerate(known):
        if i >= len(enc):
            break
        ki = i % klen
        v = enc[i] ^ b
        if key[ki] != 0 and key[ki] != v:
            ok = False
            break
        key[ki] = v
    if not ok:
        continue
    pt = bytes(enc[i] ^ key[i % klen] for i in range(len(enc)))
    if all(32 <= c < 127 for c in pt):
        print(klen, key, pt)
```

**注意：** 题目提示经常会原样出现在 flag 主体中（例如 `"say_yes_to_me"`）。

### Variant: XOR with Position Index
**模式：** `cipher[i] = plain[i] ^ key[i % k] ^ i`（或 `^ (i & 0xff)`）。

**症状：**
- 循环 XOR 几乎能拟合已知前缀，但在后面位置失效
- 用已知前缀异或得到的“key”会随索引每次 +1 变化

**修正：** 先去掉索引项，再用已知前缀恢复 key。
```python
enc = bytes.fromhex("...")
known = b"0xL4ugh{say_yes_to_me"
for klen in range(2, 33):
    key = bytearray(klen)
    ok = True
    for i, b in enumerate(known):
        if i >= len(enc):
            break
        ki = i % klen
        v = (enc[i] ^ i) ^ b  # strip index XOR
        if key[ki] != 0 and key[ki] != v:
            ok = False
            break
        key[ki] = v
    if not ok:
        continue
    pt = bytes((enc[i] ^ i) ^ key[i % klen] for i in range(len(enc)))
    if all(32 <= c < 127 for c in pt):
        print(klen, key, pt)
```

---

## Mixed-Mode (x86-64 / x86) Stagers

**模式：** 64 位 ELF 通过 far return（`retf`/`retfq`）跳入 32 位代码块，常出现在反调试之后。

**识别方式：**
- 字节 `0xCB`（retf）或 `0xCA`（retf imm16），有时前面会有 `0x48`（retfq）
- 32 位反汇编中可见紧凑循环里的 SSE 指令（`psubb`、`pxor`、`paddb`）
- 存在跳入 32 位区域的计算跳转

**坑点：**
- `retf` 会弹出 **6 字节**：4 字节 EIP + 2 字节 CS，而不是 8 字节
- 32 位代码块可能依赖继承的 **XMM 状态** 和 **EFLAGS**
- 在不同模拟器间切换时若未传递 XMM/flags，会得到错误结果

**绕过/模拟建议：**
1. 创建 `UC_MODE_32` 模拟器，复制内存、GPR、**EFLAGS** 与 **XMM 寄存器**
2. 执行 32 位代码块后，把内存和寄存器再拷回 64 位环境
3. 若反调试用了 `fork/ptrace` + patch，可模拟父进程记录 POKE，再应用到子进程

---

## LLVM (Low Level Virtual Machine) Obfuscation (Control Flow Flattening)

### Pattern
```c
while (1) {
    if (i == 0xA57D3848) { /* block */ }
    if (i != 0xA5AA2438) break;
    i = 0x39ABA8E6;  // Next state
}
```

### De-obfuscation
1. 编写 GDB 脚本，在 `je` 指令处断下
2. 记录状态变量值
3. 建立状态迁移图
4. 重建真实控制流

**关键点：** 控制流平坦化会把 if/else/loop 统一替换成一个 dispatcher switch。状态变量就是钥匙。运行时跟踪其取值，往往比静态硬啃混淆 CFG 更有效。

---

## S-Box / Keystream Generation

### Fisher-Yates Shuffle (Xorshift32)
```python
def gen_sbox():
    sbox = list(range(256))
    state = SEED
    for i in range(255, -1, -1):
        state = ((state << 13) ^ state) & 0xffffffff
        state = ((state >> 17) ^ state) & 0xffffffff
        state = ((state << 5) ^ state) & 0xffffffff
        j = state % (i + 1) if i > 0 else 0
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox
```

### Xorshift64* Keystream
```python
def gen_keystream():
    ks = []
    state = SEED_64
    mul = 0x2545f4914f6cdd1d
    for _ in range(256):
        state ^= (state >> 12)
        state ^= (state << 25)
        state ^= (state >> 27)
        state = (state * mul) & 0xffffffffffffffff
        ks.append((state >> 56) & 0xff)
    return ks
```

### Identifying Patterns
- Xorshift32：位移 13、17、5（无乘法常量）
- Xorshift64*：位移 12、25、27，然后乘 `0x2545f4914f6cdd1d`
- 另一常见常量：`0x9e3779b97f4a7c15`（黄金比例）

**关键点：** 识别 S-box 生成时，看 Fisher-Yates shuffle 模式（循环从 255 递减、与 PRNG 选中的下标交换）；识别 keystream 生成时，看 xorshift 常量。只要判定出 PRNG 家族，算法就只剩 seed 未知。

---

## SECCOMP/BPF Filter Analysis

```bash
seccomp-tools dump ./binary
```

### BPF Analysis
- `A = sys_number` 后接比较
- `mem[N] = A`、`A = mem[N]` 表示内存操作
- 将其转成约束方程，再用 z3 求解

```python
from z3 import *
flag = [BitVec(f'c{i}', 32) for i in range(14)]
s = Solver()
s.add(flag[0] >= 0x20, flag[0] < 0x7f)
# Add constraints from filter
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[c].as_long()) for c in flag))
```

**关键点：** SECCOMP（Secure Computing Mode）filter 常把 flag 校验编码成对 syscall 参数操作的 BPF 字节码。用 `seccomp-tools` 导出 filter，把比较和内存操作翻译成 z3 约束，即可在不运行二进制的情况下求出 flag。

---

## Exception Handler Obfuscation

### RtlInstallFunctionTableCallback
- 动态注册异常处理器
- Handler 安装新的 handler，并修改代码
- 在 x64dbg 中对异常处理器下断

### Vectored Exception Handlers (VEH)
- `AddVectoredExceptionHandler` 安装 handler
- Handler 在异常地址解密代码
- 单步跟踪并转储解密后的代码

**关键点：** 基于异常处理器的混淆把真实控制流藏进 SEH/VEH handler，并依赖刻意制造的 fault 触发。应在异常处理器内部下断，而不是只盯着触发 fault 的指令。

---

## Memory Dump Analysis

### When Binary Dumps Memory
- 检查是否读取 `/proc/self/maps`
- 检查是否读取 `/proc/self/mem`
- 堆数据常会附加在 dump 后

### Known Plaintext Attack
```python
prologue = bytes([0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5])
encrypted = data[func_offset:func_offset+8]
partial_key = bytes(a ^ b for a, b in zip(encrypted, prologue))
```

**关键点：** 如果二进制读取 `/proc/self/mem` 或 `/proc/self/maps`，它通常是在转储自身内存，可能还是加密后的。可以用已知函数序言（如 `endbr64; push rbp; mov rbp, rsp`）作为已知明文，从加密 dump 中恢复 XOR key。

---

## Byte-Wise Uniform Transforms

**模式：** 输出缓冲区中每个字节只独立依赖对应输入字节，不存在跨字节耦合。

**检测方式：**
- 修改一个输入位置，只会导致一个输出位置变化
- 把输入全部填成同一个字节，输出也变成常量缓冲区

**解法：**
1. 对每个字节值 0..255，运行程序并用该值重复填充输入
2. 记录输出字节，建立映射及其逆映射
3. 将逆映射作用到静态目标字节，恢复 flag

---

## x86-64 Gotchas

### Sign Extension
```python
esi = 0xffffffc7  # NOT -57

# For XOR: low byte only
esi_xor = esi & 0xff  # 0xc7

# For addition: full 32-bit with overflow
r12 = (r13 + esi) & 0xffffffff
```

### Loop Boundary State Updates
汇编经常把状态更新拆散到循环边界两侧：
```asm
    jmp loop_middle        ; First iteration in middle!

loop_top:                   ; State for iterations 2+
    mov  r13, sbox[a & 0xf]
    ; Uses OLD 'a', not new!

loop_middle:
    ; Main computation
    inc  a
    jne  loop_top
```

**关键点：** 反编译器经常会误解 x86-64 的符号扩展和循环边界状态更新。凡涉及 `movsx`/`cdqe` 的运算，都要对照原始汇编检查；同时确认循环变量是在本轮使用前还是使用后更新。

---

## Custom Mangle Function Reversing

**模式（Flag Appraisal）：** 二进制按每次 2 字节并带中间状态混淆输入，再与静态目标比较。

**做法：**
1. 从 `.rodata` 提取静态目标字节
2. 理解 mangle 逻辑：按字节对处理，并维护滚动状态值
3. 编写逆函数（逆序处理，逐步撤销每个操作）
4. 将目标字节送入逆函数，恢复 flag

**关键点：** 如果二进制按 2 字节一组、带运行时状态地混淆输入并与静态目标比较，直接从 `.rodata` 提取目标并编写逆函数即可。对目标字节逆序处理，逐步撤销每一步操作，就能恢复原输入。

---

## Position-Based Transformation Reversing

**模式（PascalCTF 2026）：** 二进制按位置索引对输入做加减变换。

**逆向：**
```python
expected = [...]  # Extract from .rodata
flag = ''
for i, b in enumerate(expected):
    if i % 2 == 0:
        flag += chr(b - i)   # Even: input = output - i
    else:
        flag += chr(b + i)   # Odd: input = output + i
```

---

## Hex-Encoded String Comparison

**模式（Spider's Curse）：** 输入先转为 hex，再与一个 hex 常量比较。

**快速解：** 从 strings/Ghidra 提取 hex 常量，再解码：
```bash
echo "4d65746143..." | xxd -r -p
```

---

## Signal-Based Binary Exploration

**模式（Signal Signal Little Star）：** 二进制使用 UNIX signal 作为二叉树导航机制。

**识别方式：**
- 多次 `sigaction()` 调用，且带 `SA_SIGINFO`
- 设置了 `sigaltstack()`（备用 signal 栈）
- Handler 解码嵌入式 payload，并安装下一对 signal
- 存在两类节点：Node（安装子节点）与 Leaf（打印消息并退出）

**求解思路：**
1. 通过 `LD_PRELOAD` hook `sigaction`，记录 signal 安装
2. 通过发送 signal 对二叉树做 DFS
3. 每一阶段观察安装了哪 2 个 signal
4. 发送其中一个，判断程序是退出（leaf）还是继续安装 2 个（node）
5. 若命中错误 leaf，则回溯并尝试兄弟分支

```c
// LD_PRELOAD interposer to log sigaction calls
int sigaction(int signum, const struct sigaction *act, ...) {
    if (act && (act->sa_flags & SA_SIGINFO))
        log("SET %d SA_SIGINFO=1\n", signum);
    return real_sigaction(signum, act, oldact);
}
```

关于恶意软件补丁、多阶段 shellcode、时间/信号 oracle 以及 CTF writeup 技巧，见 [patterns-runtime.md](patterns-runtime.md)。
