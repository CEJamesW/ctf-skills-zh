# CTF Reverse - Advanced Tools & Deobfuscation

面向商业壳/保护器、二进制 diff、反混淆、仿真与 angr 之外符号执行的高级工具。

高级 GDB 脚本、Ghidra 自动化、patch 框架以及基于 GDB 的 CTF 技巧见 [tools-advanced-2.md](tools-advanced-2.md)。

## Table of Contents
- [VMProtect Analysis](#vmprotect-analysis)
  - [Recognition](#recognition)
  - [Approach](#approach)
  - [Tools](#tools)
  - [CTF Strategy](#ctf-strategy)
- [Themida / WinLicense Analysis](#themida--winlicense-analysis)
  - [Themida Recognition](#themida-recognition)
  - [Approach for CTF](#approach-for-ctf)
- [Binary Diffing](#binary-diffing)
  - [BinDiff](#bindiff)
  - [Diaphora](#diaphora)
- [Deobfuscation Frameworks](#deobfuscation-frameworks)
  - [D-810 (IDA)](#d-810-ida)
  - [GOOMBA (Ghidra)](#goomba-ghidra)
  - [Miasm](#miasm)
- [Qiling Framework (Emulation)](#qiling-framework-emulation)
- [Triton (Dynamic Symbolic Execution)](#triton-dynamic-symbolic-execution)
- [Manticore (Symbolic Execution)](#manticore-symbolic-execution)
- [Rizin / Cutter](#rizin--cutter)
- [RetDec (Retargetable Decompiler)](#retdec-retargetable-decompiler)
- [Custom VM Bytecode Lifting to LLVM IR (Google CTF 2017)](#custom-vm-bytecode-lifting-to-llvm-ir-google-ctf-2017)

---

## VMProtect Analysis

VMProtect 会把 x86/x64 代码虚拟化为由生成式 VM 解释执行的自定义字节码。在 CTF 里属于最难的保护器之一。

### Recognition

```bash
# VMProtect signatures
strings binary | grep -i "vmp\|vmprotect"
# PE sections: .vmp0, .vmp1 (VMProtect adds its own sections)
readelf -S binary | grep ".vmp"
# Large binary with entropy > 7.5 in certain sections
```

**关键特征：**
- 大量 `push` / `pop` 前导（VM 入口把全部寄存器压栈）
- 大型 switch-case 分发表（VM handler 主循环）
- VM handler 内嵌反调试
- 变异引擎：同一 opcode 在不同构建中的 handler 不同

### Approach

```text
1. Identify VM entry points — look for pushad/pushaq-like sequences
2. Find the handler table — large indirect jump (jmp [reg + offset])
3. Trace handler execution — each handler ends with jump to next
4. Identify handlers:
   - vAdd, vSub, vMul, vXor, vNot (arithmetic)
   - vPush, vPop (stack operations)
   - vLoad, vStore (memory access)
   - vJmp, vJcc (control flow)
   - vRet (VM exit — restores real registers)
5. Build disassembler for VM bytecode
6. Simplify / deobfuscate the lifted IL
```

### Tools

- **VMPAttack**（IDA 插件）：自动识别 VM handler
- **NoVmp**：基于 VTIL 的反虚拟化工具（开源）
- **VMProtect devirtualizer scripts**：社区版 IDA/Binary Ninja 脚本
- **CTF 策略：** 与其完整反虚拟化，通常更值得追踪特定操作（密码、比较）

### CTF Strategy

```python
# Trace VM execution dynamically to extract operations on flag
# Hook VM handler dispatch to log opcode + operands

import frida

script = """
var vm_dispatch = ptr('0x...');  // Address of handler table jump
Interceptor.attach(vm_dispatch, {
    onEnter(args) {
        // Log handler index and stack state
        var handler_idx = this.context.rax;  // or whichever register
        console.log('Handler:', handler_idx, 'RSP:', this.context.rsp);
    }
});
"""
```

**关键点：** 在 CTF 中很少需要完整反虚拟化。重点是追踪输入上到底做了什么运算，优先 hook VM 内部调用到的比较函数或密码函数。

---

## Themida / WinLicense Analysis

与 VMProtect 类似，但额外叠加了更重的反调试层。

### Themida Recognition
- 节区：`.themida`、`.winlice`
- 极重的反调试（包括内核级检查、驱动安装）
- 同时结合代码变异、虚拟化和加壳

### Approach for CTF
1. **Dump 解包后的代码：** 让程序跑起来，解包后 dump 进程内存
2. **绕过反调试：** 在 x64dbg 中用 Themida 预设的 ScyllaHide
3. **修复导入：** 用 Scylla 插件重建 IAT
4. **聚焦 dump 后的代码：** 一旦脱壳，后续就按普通二进制分析

```bash
# x64dbg workflow for Themida:
1. Load binary
2. Enable ScyllaHide → Profile: Themida
3. Run to OEP (Original Entry Point) — may need several attempts
4. Dump with Scylla: OEP → IAT Autosearch → Get Imports → Dump
5. Fix dump: Scylla → Fix Dump
6. Analyze fixed dump in Ghidra/IDA
```

---

## Binary Diffing

对 patch 分析、1-day exploit 开发，以及同时提供两个版本二进制的 CTF 题非常关键。

### BinDiff

```bash
# Export from IDA/Ghidra first, then diff
# IDA: File → BinExport → Export as BinExport2
# Ghidra: Use BinExport plugin

# Command line diffing
bindiff primary.BinExport secondary.BinExport
# Opens in BinDiff GUI — shows matched/unmatched functions
```

**关键指标：**
- 每个函数对的相似度分数（0.0-1.0）
- 高亮改动指令
- 未匹配函数 = 新增或删除代码

### Diaphora

BinDiff 的免费开源替代品，以 IDA 插件形式运行。

```bash
# In IDA:
# File → Script file → diaphora.py
# Export first binary, then open second and diff

# Ghidra version: diaphora_ghidra.py
```

**CTF 用法：** 如果题目同时给了 “patched” 和 “original” 二进制，diff 往往能直接指出漏洞或隐藏逻辑。

---

## Deobfuscation Frameworks

### D-810 (IDA)

基于模式的 IDA Pro 反混淆插件，对 OLLVM 混淆效果很好。

```text
Capabilities:
- MBA simplification: (a ^ b) + 2*(a & b) → a + b
- Dead code elimination
- Opaque predicate removal
- Constant folding
- Control flow unflattening (partial)

Installation: Copy to IDA plugins directory
Usage: Edit → Plugins → D-810 → Select rules → Apply
```

### GOOMBA (Ghidra)

```text
GOOMBA (Ghidra-based Obfuscated Object Matching and Bytes Analysis):
- Integrates with Ghidra's P-Code
- Simplifies MBA expressions
- Pattern matching for known obfuscation

Installation: Copy .jar to Ghidra extensions
Usage: Code Browser → Analysis → GOOMBA
```

### Miasm

强大的逆向框架，支持符号执行与 IR lifting。

```python
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.expression import *

# Load binary and lift to Miasm IR
cont = Container.from_stream(open("binary", "rb"))
machine = Machine(cont.arch)
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)

# Disassemble function
asmcfg = mdis.dis_multiblock(entry_addr)

# Lift to IR
lifter = machine.lifter_model_call(loc_db=cont.loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

# Symbolic execution
from miasm.ir.symbexec import SymbolicExecutionEngine
sb = SymbolicExecutionEngine(lifter)
# Execute symbolically, then simplify expressions
```

**用途：** 对表达式树做反混淆，化简复杂算术，追踪混淆代码中的数据流。

---

## Qiling Framework (Emulation)

构建于 Unicorn 之上的跨平台仿真框架，具备 OS 级支持（syscall、文件系统、注册表）。

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Emulate Linux ELF
ql = Qiling(["./binary"], "rootfs/x8664_linux",
            verbose=QL_VERBOSE.DEBUG)

# Hook specific address
@ql.hook_address
def hook_check(ql, address, size):
    if address == 0x401234:
        ql.arch.regs.rax = 0  # Bypass check
        ql.log.info("Anti-debug bypassed")

# Hook syscall
@ql.hook_syscall(name="ptrace")
def hook_ptrace(ql, request, pid, addr, data):
    return 0  # Always succeed

# Hook API (Windows)
@ql.set_api("IsDebuggerPresent", target=ql.os.user_defined_api)
def hook_isdebug(ql, address, params):
    return 0

ql.run()
```

**相对 Unicorn 的优势：**
- OS 仿真（文件 I/O、网络、注册表）
- 多平台（Linux、Windows、macOS、Android、UEFI）
- 内置调试接口
- 支持 rootfs 加载动态库

**CTF 用途：**
- 仿真外架构二进制（ARM、MIPS、RISC-V）
- 一次性绕过所有反调试（无调试器痕迹）
- 无硬件地 fuzz 嵌入式/IoT 固件
- 不修改代码即可跟踪执行

---

## Triton (Dynamic Symbolic Execution)

基于 Pin 的动态二进制分析框架，支持符号执行、污点分析与 AST 化简。

```python
from triton import *

ctx = TritonContext(ARCH.X86_64)

# Load binary sections
with open("binary", "rb") as f:
    binary = f.read()
ctx.setConcreteMemoryAreaValue(0x400000, binary)

# Symbolize input
for i in range(32):
    ctx.symbolizeMemory(MemoryAccess(INPUT_ADDR + i, CPUSIZE.BYTE), f"input_{i}")

# Emulate instructions
pc = ENTRY_POINT
while pc:
    inst = Instruction(pc, ctx.getConcreteMemoryAreaValue(pc, 16))
    ctx.processing(inst)

    # At comparison point, extract path constraint
    if pc == CMP_ADDR:
        ast = ctx.getPathConstraintsAst()
        model = ctx.getModel(ast)
        for k, v in sorted(model.items()):
            print(f"input[{k}] = {chr(v.getValue())}", end="")
        break

    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
```

**Triton vs angr：**
| Feature | Triton | angr |
|---|---|---|
| Execution | Concrete + symbolic (DSE) | Fully symbolic |
| Speed | 更快（由具体执行驱动） | 更慢（探索全部路径） |
| Path explosion | 不易爆炸（只跟一条路径） | 爆炸严重 |
| API | C++ / Python | Python |
| Best for | 单路径反混淆、污点跟踪 | 多路径探索 |

**核心用途：** Triton 特别适合反混淆。让程序具体执行，同时跟踪符号状态，再化简收集到的约束。

---

## Manticore (Symbolic Execution)

Trail of Bits 的符号执行工具，和 angr 类似，但原生支持 EVM（以太坊）。

```python
from manticore.native import Manticore

m = Manticore("./binary")

# Hook success/failure
@m.hook(0x401234)
def success(state):
    buf = state.solve_one_n_batched(state.input_symbols, 32)
    print("Flag:", bytes(buf))
    m.kill()

@m.hook(0x401256)
def fail(state):
    state.abandon()

m.run()
```

**更适合：** EVM/智能合约分析，或较简单的 Linux 二进制。对复杂 RE 场景，angr 通常更成熟。

---

## Rizin / Cutter

Rizin 是 radare2 的维护分支，Cutter 是其 Qt GUI。

```bash
# Rizin CLI (r2-compatible commands)
rizin -d ./binary
> aaa                    # Analyze all
> afl                    # List functions
> pdf @ main             # Print disassembly
> VV                     # Visual graph mode

# Cutter GUI
cutter binary           # Open in GUI with decompiler
```

**Cutter 优势：**
- 内置 Ghidra 反编译器（通过 r2ghidra 插件）
- 图视图、十六进制编辑器、调试面板整合在一个 GUI
- 集成 Python/JavaScript 脚本控制台
- 免费开源

---

## RetDec (Retargetable Decompiler)

基于 LLVM 的反编译器，支持多种架构，免费开源。

```bash
# Install
pip install retdec-decompiler
# Or use web: https://retdec.com/decompilation/

# CLI
retdec-decompiler binary
# Outputs: binary.c (decompiled C), binary.dsm (disassembly)

# Specific function
retdec-decompiler --select-ranges 0x401000-0x401100 binary
```

**优势：** 多架构支持（x86、ARM、MIPS、PowerPC、PIC32），免费，可生成可编译 C。对 Ghidra 支持较弱的架构尤其有用。

---

## Custom VM Bytecode Lifting to LLVM IR (Google CTF 2017)

面对复杂自定义 VM，可把 VM 字节码转译到 LLVM IR，利用 LLVM 优化 pass 化简，再对优化后的 IR 做反编译。

```python
# Pipeline: VM bytecode → custom disassembler → LLVM IR → optimize → decompile
# 1. Write disassembler for the custom VM opcodes
# 2. Emit LLVM IR for each opcode:
#    INC reg  → %reg = add i32 %reg, 1
#    CDEC reg → conditional decrement
#    CALL fn  → call void @fn()
# 3. Use MCJIT or llc to optimize:
#    opt -O3 -S vm_lifted.ll -o vm_optimized.ll
# 4. Load optimized IR in IDA or decompile with RetDec
# Result: 1300 lines → 150 lines after inlining + constant folding
```

**关键点：** LLVM 的优化 pass（内联、常量折叠、死代码消除）对提升后的 VM 字节码化简效果非常显著。一个只有 26 个寄存器、3 个 opcode 的自定义 VM，生成 1300 行 IL，经 `-O3` 后可缩到约 150 行，从而直接暴露底层算法（例如 Collatz 序列计算）。
