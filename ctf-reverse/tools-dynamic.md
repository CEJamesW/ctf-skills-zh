# CTF Reverse - 动态分析工具

## 目录
- [Frida（动态插桩）](#frida-dynamic-instrumentation)
  - [安装](#installation)
  - [基本函数钩取](#basic-function-hooking)
  - [反调试绕过](#anti-debug-bypass)
  - [内存扫描与补丁](#memory-scanning-and-patching)
  - [函数替换](#function-replacement)
  - [跟踪与Stalker](#tracing-and-stalker)
  - [r2frida（Radare2 + Frida 集成）](#r2frida-radare2--frida-integration)
  - [Android/iOS上的Frida](#frida-for-androidios)
  - [Frida 递归函数加速记忆化（hxp CTF 2017）](#frida-memoization-for-recursive-function-speedup-hxp-ctf-2017)
- [angr（符号执行）](#angr-symbolic-execution)
  - [angr 安装](#angr-installation)
  - [基本路径探索](#basic-path-exploration)
  - [带约束的符号输入](#symbolic-input-with-constraints)
  - [钩取函数简化分析](#hook-functions-to-simplify-analysis)
  - [从特定地址开始探索](#exploring-from-specific-address)
  - [常见模式与技巧](#common-patterns-and-tips)
  - [处理路径爆炸](#dealing-with-path-explosion)
  - [angr CFG 恢复](#angr-cfg-recovery)
- [lldb（LLVM 调试器）](#lldb-llvm-debugger)
  - [基本命令](#basic-commands)
  - [脚本编写（Python）](#scripting-python)
- [x64dbg（Windows 调试器）](#x64dbg-windows-debugger)
  - [主要功能](#key-features)
  - [脚本编写](#scripting)
  - [常见 CTF 工作流程](#common-ctf-workflow)
- [putchar() 上的 GDB 寄存器侧信道（picoCTF 2018）](#gdb-register-side-channel-on-putchar-picoctf-2018)
- [radare2 自定义虚拟机跟踪可视面板（OTW Advent 2018）](#radare2-visual-panels-for-custom-vm-tracing-otw-advent-2018)
- [libSegFault.so 崩溃时寄存器转储（OTW Advent 2018）](#libsegfaultso-register-dump-at-crash-otw-advent-2018)
- [r2pipe 二进制遍历 + DP 约束求解器（OTW Advent 2018）](#r2pipe-binary-walking--dp-constraint-solver-otw-advent-2018)
- [strcmp 处的 GDB 命令恢复动态 XOR 密钥（TAMUctf 2019）](#gdb-commands-at-strcmp-to-recover-dynamic-xor-key-tamuctf-2019)

关于 Qiling/Triton 仿真和 Intel Pin / LD_PRELOAD 侧信道技术，请参见 [tools-emulation.md](tools-emulation.md)。

---

## Frida（动态插桩）

Frida 向运行中的进程注入 JavaScript，实现实时钩取、跟踪和修改。对于反调试绕过、运行时检查和移动端逆向非常关键。

### 安装

```bash
pip install frida-tools frida
# 验证
frida --version
```

### 基本函数钩取

```javascript
// hook.js — 拦截函数并打印参数/返回值
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        this.arg0 = Memory.readUtf8String(args[0]);
        this.arg1 = Memory.readUtf8String(args[1]);
        console.log(`strcmp("${this.arg0}", "${this.arg1}")`);
    },
    onLeave: function(retval) {
        console.log(`  → ${retval}`);
    }
});
```

```bash
# 附加到运行中的进程
frida -p $(pidof binary) -l hook.js

# 从启动时注入并插桩
frida -f ./binary -l hook.js --no-pause

# 一行命令：钩取 strcmp 并打印比较内容
frida -f ./binary --no-pause -e '
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        console.log("strcmp:", Memory.readUtf8String(args[0]), Memory.readUtf8String(args[1]));
    }
});
'
```

### 反调试绕过

```javascript
// 绕过 ptrace(PTRACE_TRACEME) — 返回 0（成功）而不调用原函数
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.request === 0) { // PTRACE_TRACEME
            retval.replace(ptr(0));
            console.log("[*] ptrace(TRACEME) 绕过成功");
        }
    }
});

// 绕过 IsDebuggerPresent（Windows）
var isDbg = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
Interceptor.attach(isDbg, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

// 绕过时间检测 — 钩取 clock_gettime 返回固定值
Interceptor.attach(Module.findExportByName(null, "clock_gettime"), {
    onLeave: function(retval) {
        // 强制返回固定时间戳以击败时间检测
        var ts = this.context.rsi || this.context.x1; // x86 或 ARM
        Memory.writeU64(ts, 0);        // tv_sec
        Memory.writeU64(ts.add(8), 0); // tv_nsec
    }
});
```
### 内存扫描与补丁

```javascript
// 在内存中扫描 flag 模式
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, "66 6c 61 67 7b", { // "flag{"
        onMatch: function(address, size) {
            console.log("[FLAG] 发现于:", address, Memory.readUtf8String(address, 64));
        },
        onComplete: function() {}
    });
});

// 修补指令（用 NOP 指令跳过检查）
var addr = Module.findBaseAddress("binary").add(0x1234);
Memory.patchCode(addr, 2, function(code) {
    var writer = new X86Writer(code, { pc: addr });
    writer.putNop();
    writer.putNop();
    writer.flush();
});
```

### 函数替换

```javascript
// 替换验证函数，使其总是返回 true
var checkFlag = Module.findExportByName(null, "check_flag");
Interceptor.replace(checkFlag, new NativeCallback(function(input) {
    console.log("[*] check_flag 被调用，参数为:", Memory.readUtf8String(input));
    return 1; // 始终有效
}, 'int', ['pointer']));
```

### 跟踪与 Stalker

```javascript
// 跟踪函数中的所有调用（Stalker — 指令级跟踪）
var targetAddr = Module.findExportByName(null, "main");
Stalker.follow(Process.getCurrentThreadId(), {
    transform: function(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            if (instruction.mnemonic === "call") {
                iterator.putCallout(function(context) {
                    console.log("CALL 于", context.pc, "→", ptr(context.pc).readPointer());
                });
            }
            iterator.keep();
        }
    }
});
```

### r2frida（Radare2 + Frida 集成）

```bash
# 通过 Frida 附加 radare2 到进程
r2 frida://spawn/./binary

# r2frida 命令
\ii                    # 列出导入
\il                    # 列出加载的模块
\dt strcmp             # 跟踪 strcmp 调用
\dc                    # 继续执行
\dm                    # 列出内存映射
```

### Frida 用于 Android/iOS

```bash
# Android（需要 root 设备或 Frida 服务器）
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# Hook Android Java 方法
frida -U -f com.example.app -l hook_android.js --no-pause
```

```javascript
// hook_android.js — hook Java 方法
Java.perform(function() {
    var MainActivity = Java.use("com.example.app.MainActivity");
    MainActivity.checkPassword.implementation = function(input) {
        console.log("[*] checkPassword 被调用，参数为:", input);
        var result = this.checkPassword(input);
        console.log("[*] 结果:", result);
        return result;
    };
});
```

**关键洞察：** Frida 擅长静态分析难以处理的场景——混淆代码、加壳二进制和运行时生成的数据。Hook 比较函数（`strcmp`、`memcmp`、自定义验证器）以提取预期值，无需逆向算法。使用 `Interceptor.attach` 进行观察，`Interceptor.replace` 进行修改。

**适用场景：** 绕过反调试、提取运行时计算的密钥、Hook 加密函数导出明文、移动应用分析、加壳二进制检测。

### Frida 递归函数加速的记忆化（hxp CTF 2017）

用 Frida hook 递归函数，记忆化结果，重放缓存值以跳过重复计算。类似 Fibonacci 的指数复杂度递归题目通过记忆化瞬间变快。

```javascript
// memo_hook.js — 记忆化递归函数，跳过冗余调用
var memo = {};
var funcAddr = ptr("0x400abc");    // 递归函数地址
var retAddr = ptr("0x400def");     // 函数 ret 指令地址

Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        this.key = args[0].toInt32();
        if (memo[this.key] !== undefined) {
            // 完全跳过计算：设置返回值并跳转到 ret
            this.context.rax = memo[this.key];
            this.context.rip = retAddr;
        }
    },
    onLeave: function(retval) {
        // 缓存结果以供未来相同参数调用
        memo[this.key] = retval.toInt32();
    }
});
```

```bash
# 使用方法
frida -f ./binary -l memo_hook.js --no-pause
```

多参数函数构建复合键：
```javascript
Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        this.key = args[0].toInt32() + "," + args[1].toInt32();
        if (memo[this.key] !== undefined) {
            this.context.rax = memo[this.key];
            this.context.rip = retAddr;
        }
    },
    onLeave: function(retval) {
        memo[this.key] = retval.toInt32();
    }
});
```

**关键洞察：** Frida 的 `Interceptor` 能读写寄存器状态，允许通过设置 `rax`（返回值）和 `rip`（跳转到 ret 指令）来完全跳过函数执行。适用于相同参数产生相同结果的递归函数。指数时间递归计算（Fibonacci、Ackermann、树遍历）通过记忆化变为线性时间。

**参考资料：** hxp CTF 2017

---
## angr（符号执行）

angr 会自动探索程序路径以找到满足约束的输入。它能在几分钟内解决许多需要手动耗费数小时的 flag 校验二进制。

### angr 安装

```bash
pip install angr
```

### 基本路径探索

```python
import angr
import claripy

# 加载二进制
proj = angr.Project('./binary', auto_load_libs=False)

# 查找打印 "Correct!" 的地址，避免打印 "Wrong!" 的地址
# 这些地址可从反汇编（objdump -d 或 Ghidra）中获得
FIND_ADDR = 0x401234    # 成功路径地址
AVOID_ADDR = 0x401256   # 失败路径地址

# 创建仿真管理器并进行探索
simgr = proj.factory.simgr()
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    found = simgr.found[0]
    # 获取达到目标的 stdin 输入
    print("Flag:", found.posix.dumps(0))  # fd 0 = stdin
```

### 带约束的符号输入

```python
import angr
import claripy

proj = angr.Project('./binary', auto_load_libs=False)

# 创建符号输入（例如 32 字节的 flag）
flag_len = 32
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# 限制为可打印 ASCII
state = proj.factory.entry_state(stdin=flag)
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# 限制已知前缀："flag{"
state.solver.add(flag_chars[0] == ord('f'))
state.solver.add(flag_chars[1] == ord('l'))
state.solver.add(flag_chars[2] == ord('a'))
state.solver.add(flag_chars[3] == ord('g'))
state.solver.add(flag_chars[4] == ord('{'))
state.solver.add(flag_chars[flag_len-1] == ord('}'))

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401256)

if simgr.found:
    found = simgr.found[0]
    result = found.solver.eval(flag, cast_to=bytes)
    print("Flag:", result.decode())
```

### Hook 函数以简化分析

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)

# Hook printf 以避免 I/O 路径爆炸
@proj.hook(0x401100, length=5)  # printf 调用地址
def skip_printf(state):
    pass  # 什么也不做，直接跳过

# Hook sleep/反调试函数
@proj.hook(0x401050, length=5)  # sleep 调用地址
def skip_sleep(state):
    pass

# 用摘要替换函数
class AlwaysSucceed(angr.SimProcedure):
    def run(self):
        return 1

proj.hook_symbol('check_license', AlwaysSucceed())
```

### 从特定地址开始探索

```python
# 从函数中间开始（跳过初始化）
state = proj.factory.blank_state(addr=0x401200)

# 手动设置寄存器/内存
state.regs.rdi = 0x600000  # 输入缓冲区指针
state.memory.store(0x600000, b"AAAA" + b"\x00" * 28)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401300, avoid=0x401350)
```

### 常见模式和技巧

```python
# 模式 1：基于 argv 的输入
state = proj.factory.entry_state(args=['./binary', flag_sym])

# 模式 2：多个 find/avoid 地址
simgr.explore(
    find=[0x401234, 0x401300],     # 任一成功路径
    avoid=[0x401256, 0x401400]     # 所有失败路径
)

# 模式 3：通过输出字符串查找（无需地址）
def is_successful(state):
    stdout = state.posix.dumps(1)  # fd 1 = stdout
    return b"Correct" in stdout

def should_avoid(state):
    stdout = state.posix.dumps(1)
    return b"Wrong" in stdout

simgr.explore(find=is_successful, avoid=should_avoid)

# 模式 4：超时保护
simgr.explore(find=0x401234, avoid=0x401256, num_find=1)
# 或使用探索技术：
simgr.use_technique(angr.exploration_techniques.DFS())  # 深度优先
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=500))
```
### 处理路径爆炸

```python
# 对于 flag 检查器，使用 DFS 替代默认的 BFS
simgr.use_technique(angr.exploration_techniques.DFS())

# 限制符号内存操作
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# Hook 代价高的函数（加密、哈希）以避免爆炸
import hashlib
class SHA256Hook(angr.SimProcedure):
    def run(self, data, length, output):
        # 具体化输入并计算哈希
        concrete_data = self.state.solver.eval(
            self.state.memory.load(data, self.state.solver.eval(length)),
            cast_to=bytes
        )
        h = hashlib.sha256(concrete_data).digest()
        self.state.memory.store(output, h)

proj.hook_symbol('SHA256', SHA256Hook())
```

### angr CFG 恢复

```python
# 控制流图用于理解程序结构
cfg = proj.analyses.CFGFast()
print(f"发现函数数量: {len(cfg.functions)}")

# 查找 main 函数
for addr, func in cfg.functions.items():
    if func.name == 'main':
        print(f"main 位于 {addr:#x}")
        break

# 交叉引用
node = cfg.model.get_any_node(0x401234)
print("前驱节点:", [hex(p.addr) for p in cfg.model.get_predecessors(node)])
```

**关键见解：** angr 在具有明确成功/失败路径的 flag 检查器二进制上效果最佳。对于复杂二进制，hook 代价高的函数（加密、I/O）并使用 DFS 探索。先从最简单的方法开始（仅查找/避免地址）再添加约束。如果 angr 运行缓慢，限制输入为可打印 ASCII 并添加已知前缀。

**适用场景：** 带分支逻辑的 flag 验证器、迷宫/路径查找二进制、约束密集的检查、自动化二进制分析。效果较差的场景：重度加密、浮点运算、复杂堆操作。

---

## lldb (LLVM 调试器)

macOS/iOS 的主要调试器，也支持 Linux。Swift/Objective-C 及苹果平台二进制的首选。

### 基本命令

```bash
lldb ./binary
(lldb) run                          # 运行程序
(lldb) b main                       # 在 main 处设置断点
(lldb) b 0x401234                   # 在指定地址设置断点
(lldb) breakpoint set -r "check.*"  # 正则断点
(lldb) c                            # 继续执行
(lldb) si                           # 单步指令
(lldb) ni                           # 下一条指令
(lldb) register read                # 显示所有寄存器
(lldb) register write rax 0         # 修改寄存器
(lldb) memory read 0x401000 -c 32   # 读取 32 字节内存
(lldb) x/s $rsi                     # 查看字符串（GDB 风格）
(lldb) dis -n main                  # 反汇编函数
(lldb) image list                   # 已加载模块及基址
```

### 脚本（Python）

```python
# lldb Python 脚本
import lldb

def hook_strcmp(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    arg0 = frame.FindRegister("rdi").GetValueAsUnsigned()
    arg1 = frame.FindRegister("rsi").GetValueAsUnsigned()
    s0 = process.ReadCStringFromMemory(arg0, 256, lldb.SBError())
    s1 = process.ReadCStringFromMemory(arg1, 256, lldb.SBError())
    print(f'strcmp("{s0}", "{s1}")')

# 在 lldb 中注册：command script add -f script.hook_strcmp hook_strcmp
```

**关键见解：** macOS 二进制（Mach-O）、iOS 应用及无 GDB 环境时使用 lldb。`image list` 可查看 PIE 二进制的 ASLR 偏移。脚本 API 比 GDB 更结构化。

---
## x64dbg (Windows 调试器)

开源的 Windows 调试器，具有现代化的用户界面。是 Windows 逆向工程挑战中 OllyDbg/WinDbg 的替代方案。

### 主要功能

```bash
# 启动
x64dbg.exe binary.exe         # 64 位
x32dbg.exe binary.exe         # 32 位

# 常用快捷键
F2      → 切换断点
F7      → 单步进入
F8      → 单步跳过
F9      → 运行
Ctrl+G  → 跳转到地址
Ctrl+F  → 在内存中查找模式
```

### 脚本支持

```bash
# x64dbg 命令行
bp 0x401234                    # 设置断点
SetBPX 0x401234, 0, "log {s:utf8@[esp+4]}"  # 命中时记录字符串参数
run                            # 继续执行
StepOver                       # 单步跳过
```

### 常见 CTF 工作流程

1. 在 GUI 破解中对 `GetWindowTextA`/`MessageBoxA` 设置断点
2. 从成功/失败消息回溯
3. 对加壳二进制使用 **Scylla** 插件进行 IAT 重建
4. 使用 **Snowman** 反编译插件快速生成伪 C 代码

**关键点：** x64dbg 内置模式扫描、硬件断点和条件日志功能。对于 Windows CTF 二进制，动态分析速度通常快于 IDA/Ghidra。使用 **xAnalyzer** 插件实现自动函数参数注释。

---

## GDB 在 putchar() 上的寄存器侧信道（picoCTF 2018）

**模式：** 二进制逐字符解密 flag，并在打印字符间调用 `usleep()`。无需等待睡眠结束，只需在 `putchar@plt` 设置断点，每次命中时记录 `$rdi`（glibc x86-64 中字符存放寄存器）。GDB 日志循环可在毫秒内导出完整 flag，忽略人为延迟。

```gdb
# 本挑战的 ~/.gdbinit
set pagination off
set logging file flag.log
set logging overwrite on
set logging on

break putchar
commands
  silent
  printf "%c", $rdi
  continue
end

run
```

```bash
gdb -batch -x script.gdb ./crackme
cat flag.log
```

**关键点：** 任何程序用 `usleep`、`nanosleep` 或忙等待延迟输出时，待打印字符已存寄存器。断点输出函数（`putchar`、`fputc`、`write` 且 `fd=1`），打印第一个参数寄存器（x86-64 为 `$rdi`，ARM 为 `$r0`，RISC-V/MIPS 为 `$a0`），用 GDB 脚本批量提取数据。硬件断点可绕过反调试。

**参考：** picoCTF 2018 — learn gdb，writeup 11784

---

## radare2 自定义虚拟机追踪可视面板（OTW Advent 2018）

**模式：** 自定义虚拟机二进制不透明，直到你能同时看到程序计数器、下一条指令、栈和堆。radare2 的面板模式（`V!`）允许你在一屏固定这四个视图，单步执行宿主指令时观察虚拟机状态变化。

```text
f sp @ rbp-0x160       # flag 虚拟机栈指针
f ip @ rbp-0x158       # flag 虚拟机指令指针
f stack @ rbp-0x150
f heap @ rbp-0x148

V!                       # 进入面板模式
# 面板 1: ?v [ip]; pd 1 @ [ip]    (下一条虚拟机指令)
# 面板 2: pxQ 0x60 @ sp             (栈)
# 面板 3: pxQ 0x60 @ heap           (堆)
# 面板 4: afvd                      (局部变量 / 寄存器)
```

在对应虚拟机指令分发的宿主分支上设置条件断点，使用 `ds` 单步。结合 `e io.cache=true` 实现分析时对虚拟机指令的非破坏性补丁。

**关键点：** 观察虚拟机状态实时变化，几分钟内即可逆向自定义虚拟机。面板模式优于静态反编译，因为宿主二进制通常缺乏反编译友好结构；实时观察每个寄存器变化让虚拟机逻辑自明。

**参考：** OverTheWire Advent 2018 — Jackinthebox，writeup 12789

---
## libSegFault.so 崩溃时的寄存器转储（OTW Advent 2018）

**场景：** 你需要在 shellcode 入口处获取精确的寄存器状态，但 gdb 不可用或被 hook。预加载 `libSegFault.so`（glibc 自带）并使程序崩溃：它会将完整的寄存器转储、回溯和内存映射打印到 stderr。

```bash
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libSegFault.so ./target
# 或 32 位：
LD_PRELOAD=/lib32/libSegFault.so ./target

# 强制崩溃：
# segfault_handler 会转储：RIP、RSP、RAX..R15、栈回溯
```

读取打印的寄存器，找出哪些已经指向你的 shellcode（常见：`RAX` → 缓冲区，`RDI` → 零），然后设计最小的 shellcode。

**关键洞察：** libSegFault 是每个 glibc 系统中作为标准调试基础设施安装的。它能将任何段错误转化为免费的寄存器快照，即使在没有 `strace`/`gdb` 权限的加固环境中也有效。

**参考：** OverTheWire Advent Bonanza 2018 — 第22天，writeup 12757

---

## r2pipe 二进制遍历 + DP 约束求解器（OTW Advent 2018）

**场景：** 一个 12 MB 的二进制文件包含 30 万+ 基本块，对 `argv[1]` 进行链式哈希校验。通过 `r2pipe` 遍历每个基本块，将每条指令分类为 hash/cmp/jmp/print，构建约束图，然后用动态规划 + 回溯在输入位置上求解。

```python
import r2pipe
r = r2pipe.open('./huge_binary')
r.cmd('aaa')
for fn in r.cmdj('aflj'):
    for block in r.cmdj(f"pdfj @ {fn['offset']}")['ops']:
        op = block['type']
        if op == 'cmp':  constraints.append(parse_cmp(block))
        if op == 'call': targets.append(block['jump'])
# DP: 记忆化 (position, accepted_set) -> char
```

**关键洞察：** 大型二进制带有哈希链时，如果将每个分支视为输入字节上的不等式，则可解。r2pipe 的 JSON 输出可机器读取；基于位置/值元组的 DP 在执行前剪枝大部分分支。

**参考：** OverTheWire Advent Bonanza 2018 — 第8天，writeup 12771

---

## GDB 在 strcmp 处恢复动态 XOR 密钥的命令（TAMUctf 2019）

**场景（Obfuscaxor）：** 二进制使用 [obfy](https://github.com/fritzone/obfy) C++ 模板混淆器，将简单的 `enc(input)` XOR 循环隐藏在成千上万的模糊谓词下。终极校验仍是 `strcmp(expected_ciphertext, enc(input))` —— 因此不必解开 obfy，直接在 `strcmp` 调用处断点并转储两个操作数：

```
disassemble verify_key
# ... 0x5555555560b9 <+96>: call   strcmp@plt
break *verify_key+96
commands
  silent
  printf "RDI (expected): "
  x/4xg $rdi
  printf "RSI (computed): "
  x/4xg $rsi
  continue
end
run
```

输入已知明文（`AAAAAAAAA`）并记录 `computed_A[i]`。因为 `enc` 是逐字节 XOR 密钥流，密钥字节可直接从与目标的差值恢复：

```python
# input_char ^ key = computed_char，且我们想要：target_char ^ key = target_input
def to_ans(got_A, expected):
    return chr(got_A ^ ord('A') ^ expected)

# 校验：只翻转输入的一个字节，确认只有一个计算字节变化。
```

对整个 16 字节目标串进行逐字节恢复，重构正确密钥（本挑战为 `p3Asujmn9CEeCB3A`）。

**关键洞察：** 当 `strcmp` 是最后一道关卡时，混淆器无关紧要 —— 它的输出仍必须在已知调用点等于固定字符串。GDB 的 `commands` 块将断点变成自动 oracle：一次运行 `AAAA...` 泄露密钥流，第二次用任意目标串即可得到有效输入。适用于任何在固定密钥下实质为输入排列的键控变换。

**参考：** TAMUctf 2019 — Obfuscaxor，writeup 13574
