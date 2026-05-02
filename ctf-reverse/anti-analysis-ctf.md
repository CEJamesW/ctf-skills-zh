# CTF Reverse - Anti-Analysis CTF Writeups

CTF 特定反分析技巧：signal handler 技巧、指令轨迹逆推、无 call 函数链、父进程修补子进程二进制转储。核心反分析分类（Linux/Windows 反调试、反 VM、反 DBI、代码完整性、反反汇编）见 [anti-analysis.md](anti-analysis.md)。

## Table of Contents
- [SIGILL Handler for Execution Mode Switching (Hack.lu 2015)](#sigill-handler-for-execution-mode-switching-hacklu-2015)
- [SIGFPE Signal Handler Side-Channel via strace Counting (PlaidCTF 2017)](#sigfpe-signal-handler-side-channel-via-strace-counting-plaidctf-2017)
- [Instruction Trace Inversion with Keystone and Unicorn (MeePwn CTF 2017)](#instruction-trace-inversion-with-keystone-and-unicorn-meepwn-ctf-2017)
  - [Call-less Function Chaining via Stack Frame Manipulation (THC CTF 2018)](#call-less-function-chaining-via-stack-frame-manipulation-thc-ctf-2018)
  - [Parent-Patched Child Binary Dump via strace process_vm_writev (Google CTF Quals 2018)](#parent-patched-child-binary-dump-via-strace-process_vm_writev-google-ctf-quals-2018)
- [ConfuserEx Dynamic Module Dump via Constructor Breakpoint (Kaspersky 2018)](#confuserex-dynamic-module-dump-via-constructor-breakpoint-kaspersky-2018)

---

## SIGILL Handler for Execution Mode Switching (Hack.lu 2015)

二进制可能注册 SIGILL（非法指令）处理器，用于在 x86 与 x86-64 执行模式之间切换，或实现自定义 opcode 分发：

1. **注册信号：** `signal(SIGILL, handler)` 为非法指令异常安装回调
2. **模式切换：** handler 修改保存的指令指针或段寄存器，在 32 位与 64 位代码间切换
3. **自定义 opcode：** 非法 x86 指令触发 handler，由其把操作数字节解释为自定义 VM opcode

```c
// Signal handler decodes "illegal" instructions as custom opcodes
void sigill_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *ctx = (ucontext_t *)ucontext;
    unsigned char *pc = (unsigned char *)ctx->uc_mcontext.gregs[REG_RIP];
    // Decode custom opcode from bytes at PC
    // Advance PC past the custom instruction
    ctx->uc_mcontext.gregs[REG_RIP] += opcode_length;
}
```

**关键点：** 如果二进制在早期执行阶段就注册了 SIGILL/SIGSEGV/SIGTRAP handler，应怀疑有自定义指令分发。可用 `strace -e signal` 跟踪信号递送，或在 GDB 中让其不要拦截：`handle SIGILL nostop pass`。

---

## SIGFPE Signal Handler Side-Channel via strace Counting (PlaidCTF 2017)

二进制使用 SIGFPE signal handler 驱动控制流，导致静态分析不可靠。可通过 `strace` 统计 SIGFPE 次数来爆破，正确字符会触发更多信号。

```bash
# Count SIGFPE signals per input character guess
for c in {a..z} {A..Z} {0..9}; do
    count=$(echo -n "${c}AAAAAAA" | strace -e signal=SIGFPE ./binary 2>&1 | grep -c SIGFPE)
    echo "$c: $count"
done
# Character producing the most SIGFPEs is correct
# Repeat for each position, extending the known prefix
```

**关键点：** signal handler（SIGFPE、SIGSEGV、SIGILL）会引入静态分析不可见的隐式控制流。触发信号的次数与校验推进程度相关。通过 `strace -e signal=SIGFPE` 计数，可以把不透明的信号式校验转成逐字符可测的侧信道。

---

## Instruction Trace Inversion with Keystone and Unicorn (MeePwn CTF 2017)

UPX 加壳二进制对 flag 应用一串纯算术变换（sub、add、xor、rol、ror）。没有内存副作用，只有寄存器算术。用 IDAPython 跟踪非跳转指令，再将序列逆置即可恢复 flag。

**逆推规则：**
- 反转指令序列顺序（最后一条先执行）
- 交换逆运算对：`add ↔ sub`、`rol ↔ ror`，`xor` 自反

```python
# IDAPython: collect non-jump instructions in the obfuscated routine
import idaapi, idc

def trace_transforms(start_ea, end_ea):
    instructions = []
    ea = start_ea
    while ea < end_ea:
        mnem = idc.print_insn_mnem(ea)
        if mnem not in ('jmp', 'je', 'jne', 'call', 'ret'):
            instructions.append((ea, mnem, idc.print_operands(ea)))
        ea = idc.next_head(ea)
    return instructions

transforms = trace_transforms(0x401000, 0x401200)

# Invert: reverse order, swap add/sub and rol/ror
inverse_map = {'add': 'sub', 'sub': 'add', 'rol': 'ror', 'ror': 'rol', 'xor': 'xor'}
inverted = [(mnem, op) for (_, mnem, op) in reversed(transforms)]
inverted = [(inverse_map.get(m, m), op) for m, op in inverted]
```

```python
# Assemble inverted instructions with Keystone, emulate with Unicorn
from keystone import *
from unicorn import *
from unicorn.x86_const import *

ks = Ks(KS_ARCH_X86, KS_MODE_64)
uc = Uc(UC_ARCH_X86, UC_MODE_64)

asm_src = '\n'.join(f'{mnem} {op}' for mnem, op in inverted)
encoding, _ = ks.asm(asm_src)

CODE_BASE = 0x400000
uc.mem_map(CODE_BASE, 0x10000)
uc.mem_write(CODE_BASE, bytes(encoding))

# Set initial register state to the observed output value
uc.reg_write(UC_X86_REG_RAX, known_output)
uc.emu_start(CODE_BASE, CODE_BASE + len(encoding))
flag_bytes = uc.reg_read(UC_X86_REG_RAX).to_bytes(8, 'little')
```

**PEB anti-debug note:** 如果二进制读取 `PEB.BeingDebugged` 并据此在两个比较目标中二选一，那么 IDAPython 跟踪到的指令可能走的是调试分支。跟踪前先把 `BeingDebugged` 改成 0，或同时识别两个分支并选取非调试目标值。

**关键点：** 纯算术混淆（无内存写）可以通过跟踪、逆序指令、再交换逆操作完全还原。PEB 反调试会静默改变比较目标，必须确认实际走的是哪一支。

**References:** MeePwn CTF 2017

---

### Call-less Function Chaining via Stack Frame Manipulation (THC CTF 2018)

**模式：** 二进制把函数指针链表构造在栈上，并通过修改保存的 RBP 与返回地址，使 `leave; ret` 在没有任何显式 `CALL` 指令的情况下沿链跳转。由于 push/pop 不平衡、函数边界无法确定，IDA 无法正常反编译。

链上的每个函数都会：
1. 把操作数和下一个函数地址压栈
2. 将保存的 RBP 设为下一栈帧地址
3. 将返回地址设为下一个函数
4. `leave` 从 RBP 恢复 RSP（移动到下一帧），`ret` 跳到下一个函数

```python
# Reversed processing chain (each function applied via leave/ret):
def reverse_processing(byte):
    res = byte | 0x80       # OR 0x80
    res = res ^ 0xCA        # XOR 0xCA
    res = (res + 66) & 0xFF # ADD 66
    res = res ^ 0xCA        # XOR 0xCA (repeated)
    res = (res + 66) & 0xFF
    res = res ^ 0xCA
    res = (res + 66) & 0xFF
    res = res ^ 0xFE        # XOR 0xFE (final)
    return res
# Apply in reverse order, then reverse the character sequence
```

**关键点：** 通过把保存的 RBP 指向下一栈帧、把保存的 RIP 改为下一个函数，`leave; ret` 就能在没有 `call` 的情况下串联函数。依赖 call/ret 平衡的反汇编器无法识别这种函数边界。可逐个 patch 函数体，让 IDA 单独处理。

**检测特征：** 大量小代码块以 `leave; ret` 结尾，却没有对应 `call`。栈上交织出现函数指针与数据。IDA 提示 “stack frame is too big” 或根本建不出函数。

**References:** THC CTF 2018

---

### Parent-Patched Child Binary Dump via strace process_vm_writev (Google CTF Quals 2018)

**模式（Keygenme）：** 二进制先 fork。子进程是充满 `int3`（`0xcc`）陷阱的 stub。父进程用 `ptrace` + `process_vm_writev` 在每次陷阱触发前把真实指令写进子进程，然后继续单步。静态分析子进程只能看到垃圾；单进程调试也看不到父进程写入。

**绕过方式：让 strace 替你做转储：**
```bash
# Record every process_vm_writev the parent performs, including full iov contents.
strace -f -e trace=process_vm_writev -e write=all -o trace.log ./keygenme

# Each entry looks like:
#   process_vm_writev(child_pid, [{iov_base="\x48\x89\xe5...", iov_len=12}], 1,
#                     [{iov_base=0x400c80, iov_len=12}], 1, 0) = 12
```

解析日志，提取 `(remote_addr, bytes)` 对，并生成 IDA `patch_bytes` 脚本：
```python
import re, pathlib
patches = []
pattern = re.compile(
    r'process_vm_writev\(\d+, \[{iov_base="([^"]+)", iov_len=(\d+)}\].*?\[{iov_base=(0x[0-9a-f]+)',
)
for m in pattern.finditer(pathlib.Path('trace.log').read_text()):
    data = m.group(1).encode('latin1').decode('unicode_escape').encode('latin1')
    addr = int(m.group(3), 16)
    patches.append((addr, data))

with open('patch.py', 'w') as fh:
    for addr, data in patches:
        for i, b in enumerate(data):
            fh.write(f'patch_byte({addr + i:#x}, {b:#x})\n')
```

把 `patch.py` 载入 IDA（File → Script file），应用所有父进程写入的指令，就能把原本布满陷阱的子进程还原成可读二进制。补丁后，密码逻辑只是普通循环，可把不可逆部分当黑盒，然后把最终 `strcmp` 改成泄露期望值。

**关键点：** 任何通过 ptracer 改写 tracee `.text` 的反分析方案，对父进程跑 `strace` 都是透明的。`process_vm_writev` 同时包含目标地址和字节内容，因此一次 `strace` 就足够 dump 真正代码。同样思路也适用于使用 `ptrace(PTRACE_POKEDATA)` 或向 `/proc/<pid>/mem` 写入的自修改壳。

**References:** Google CTF Quals 2018 — writeup 10330

---

## ConfuserEx Dynamic Module Dump via Constructor Breakpoint (Kaspersky 2018)

**模式：** ConfuserEx（.NET 保护器）会加密方法体，并在 `<Module>` 构造函数中于运行时解密。可在 dnSpy 中对构造函数下断，单步到动态模块在内存中完全构建后，右键 → **Save Module** 导出已解密、token 保持完好的程序集。然后用 `de4dot` 清理混淆符号。

```text
dnSpy:
  File → Open → target.exe
  Assembly Explorer → <Module> .cctor → F9 (breakpoint)
  F5 to run; wait until loaded
  Right-click assembly → Save Module → out.exe
$ de4dot out.exe        # symbol cleanup
```

**关键点：** ConfuserEx 保护的是磁盘上的代码，而不是运行时表示。只要 .NET 保护器通过构造函数执行解密，构造函数完成后的模块转储就是明文二进制。再配合 de4dot 处理后续的符号混淆即可。

**References:** Kaspersky Industrial CTF 2018 — glardomos, writeup 12325
