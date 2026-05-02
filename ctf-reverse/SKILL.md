---
name: ctf-reverse
description: 提供用于 CTF 挑战的逆向工程技术。适用于在利用或求解之前，主要任务是理解已编译、混淆、加壳或虚拟化目标如何工作的场景，包括二进制、APK、WASM、固件、自定义 VM、字节码、游戏客户端、类恶意加载器，以及反调试或反分析逻辑。若漏洞机理已明确、剩余任务是利用，应改用 pwn。纯 Web 流程、日志或磁盘取证、以及纯密码题不应使用，除非真正的阻塞点是逆向其实现。
license: MIT
compatibility: 需要基于文件系统的 agent（Claude Code 或同类）以及 bash、Python 3、用于安装工具的网络访问。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Reverse Engineering

RE 题目的速查参考。详细技术见配套文档。

## Prerequisites

**Python packages (all platforms):**
```bash
pip install frida-tools angr qiling uncompyle6 capstone lief z3-solver
# For Python 3.9+ bytecode: build pycdc from source
git clone https://github.com/zrax/pycdc && cd pycdc && cmake . && make
```

**Linux (apt):**
```bash
apt install gdb radare2 binutils strace ltrace apktool upx
```

**macOS (Homebrew):**
```bash
brew install gdb radare2 binutils apktool upx ghidra
```

**radare2 plugins:**
```bash
r2pm -ci r2ghidra   # radare2 原生 Ghidra 反编译器
```

**Manual install:**
- pwndbg — Linux: [GitHub](https://github.com/pwndbg/pwndbg), macOS: `brew install pwndbg/tap/pwndbg-gdb`

## Additional Resources

- [tools.md](tools.md) - 静态分析工具（GDB、Ghidra、radare2、IDA、Binary Ninja、dogbolt.org、Capstone 配合 RISC-V、Unicorn 仿真、Python 字节码、WASM、Android APK、.NET、加壳二进制）
- [tools-dynamic.md](tools-dynamic.md) - 动态分析工具：Frida（hook、反调试绕过、内存扫描、Android/iOS）、angr 符号执行（路径探索、约束、CFG）、lldb（macOS/LLVM 调试器）、x64dbg（Windows）
- [tools-emulation.md](tools-emulation.md) - 仿真框架与侧信道工具：Qiling（跨平台 OS 级仿真）、Triton（DSE）、Intel Pin 指令计数 + 遗传算法侧信道、仅 opcode 的 trace 重建、LD_PRELOAD 冻结时间与 memcmp 侧信道逐字节爆破
- [tools-advanced.md](tools-advanced.md) - 高级工具（Part 1）：VMProtect/Themida 分析、二进制 diff（BinDiff、Diaphora）、反混淆框架（D-810、GOOMBA、Miasm）、Qiling、Triton DSE、Manticore、Rizin/Cutter、RetDec、自定义 VM 字节码提升到 LLVM IR
- [tools-advanced-2.md](tools-advanced-2.md) - 高级工具（Part 2）：高级 GDB（Python 脚本、爆破、条件断点、观察点、rr 逆向调试、pwndbg/GEF）、高级 Ghidra 脚本、补丁（Binary Ninja API、LIEF）、GDB 约束提取 + ILP 求解器（BackdoorCTF 2017）、GDB 位置编码输入零标志监控（EKOPARTY 2017）、LD_PRELOAD 导出 execute-only 二进制（BackdoorCTF 2017）、PEDA current_inst 逐位抓 flag（CONFidence CTF 2019 Teaser）
- [anti-analysis.md](anti-analysis.md) - 反分析分类：Linux 反调试（ptrace、/proc、计时、信号、直接 syscall）、Windows 反调试（PEB、NtQueryInformationProcess、heap flags、TLS callbacks、HW/SW breakpoint 检测、异常式、线程隐藏）、反 VM/sandbox（CPUID、MAC、计时、环境痕迹、资源）、反 DBI（Frida 检测/绕过）、代码完整性/自哈希、反反汇编（opaque predicates、junk bytes）、MBA 识别/化简、综合绕过策略
- [anti-analysis-ctf.md](anti-analysis-ctf.md) - CTF writeup 技巧：利用 SIGILL handler 切换执行模式（Hack.lu 2015）、通过 strace 计数做 SIGFPE signal handler 侧信道（PlaidCTF 2017）、Keystone + Unicorn 指令轨迹逆推（MeePwn 2017）、通过栈帧操纵实现无 call 函数链（THC 2018）、利用 `process_vm_writev` 导出父进程修补后的子进程二进制（Google CTF Quals 2018）
- [patterns.md](patterns.md) - 基础二进制模式：自定义 VM、反调试、nanomites、自修改代码、XOR 密码、混合模式 stager、LLVM 混淆、S-box/keystream、SECCOMP/BPF、异常处理器、内存转储、逐字节变换、x86-64 坑点、自定义 mangle 逆向、位置相关变换、十六进制字符串比较、基于信号的二进制探索
- [patterns-runtime.md](patterns-runtime.md) - 运行时补丁与 oracle 技术：恶意样本反分析绕过、多阶段 shellcode loader、时间侧信道攻击、多线程反调试 + 诱饵 + signal handler MBA（ApoorvCTF 2026）、INT3 补丁 + coredump 爆破 oracle（Pwn2Win 2016）、signal handler 链 + LD_PRELOAD oracle（Nuit du Hack 2016）、printf format string VM 反编译到 Z3（SECCON 2017）、四叉树递归图像格式解析器（Google CTF Quals 2018）
- [patterns-ctf.md](patterns-ctf.md) - 比赛特定模式（Part 1）：隐藏模拟器 opcode、LD_PRELOAD 提 key、SPN 静态提取、图像 XOR 平滑性、逐字节密码、数学收敛位图、Windows PE XOR 位图 OCR、双阶段 RC4+VM loader、GBA ROM meet-in-the-middle、Sprague-Grundy 博弈论、内核模块迷宫求解、多线程 VM 通道、基于字符串 diff 的后门共享库检测、带 RC4 flat binaries 的自定义 binfmt 内核模块、哈希解析导入 / 无导入勒索软件、破坏 ELF section header 的反分析
- [patterns-ctf-2.md](patterns-ctf-2.md) - 比赛特定模式（Part 2）：多层自解密爆破、嵌入式 ZIP+XOR 许可证、栈字符串反混淆、前缀哈希爆破、用于整数校验的 CVP/LLL 格、决策树函数混淆、GF(2^8) 高斯消元、ROP 链混淆分析（ROPfuscation）
- [patterns-ctf-3.md](patterns-ctf-3.md) - 比赛特定模式（Part 3）：Z3 单行 Python 电路、滑动窗口 popcount、通过 ioctl 的键盘 LED 摩尔斯码、隐藏在 C++ 析构函数中的校验、syscall 副作用内存破坏、MFC 对话框事件处理器、VM 顺序 key-chain 爆破、Burrows-Wheeler transform 逆变换、OpenType 字体连字利用、带自修改代码的 GLSL shader VM、把指令计数器当密码状态、基于 objdump 的批量 crackme 自动化、fork+pipe+dead branch 反分析、通过 sigmoid 层逆变换做 TensorFlow DNN 反演、通过内核 JIT 到 x64 汇编分析 BPF 过滤器
- [languages.md](languages.md) - 语言相关：Python 字节码与 opcode 重映射、Python 版本差异字节码、Pyarmor 静态脱壳、DOS stub、Unity IL2CPP、HarmonyOS HAP/ABC、Brainfuck/esolang（含 BF 按字符静态分析、BF 侧信道读计数 oracle、BF 比较习语识别）、UEFI、转译到 C、代码覆盖侧信道、OPAL 函数式逆向、非双射替换、FRACTRAN 程序逆推
- [languages-platforms.md](languages-platforms.md) - 平台/框架相关：Roblox place 文件分析、Godot 游戏资源提取、Rust serde_json schema 恢复、Android JNI RegisterNatives 混淆、通过 /proc/self/maps 做 Android DEX 运行时字节码补丁、通过新工程绕过 Android native .so 加载、Frida 绕过 Firebase Cloud Functions、Verilog/硬件逆向、逐前缀哈希逆推、Ruby/Perl polyglot 约束求解、Electron ASAR 提取 + 原生二进制分析、Node.js npm 运行时内省
- [languages-compiled.md](languages-compiled.md) - Go 二进制逆向（GoReSym、goroutine、内存布局、channel 操作、embed.FS、用于 C2 枚举的 Go 二进制 UUID 补丁）、Rust 二进制逆向（demangling、Option/Result、Vec、panic 字符串）、Swift 二进制逆向（demangling、protocol witness table）、Kotlin/JVM（协程状态机）、Haskell GHC CMM 中间语言做递归结构分析、C++（vtable 重建、RTTI、STL 模式）
- [platforms.md](platforms.md) - 平台特定逆向：macOS/iOS（Mach-O、代码签名、Objective-C runtime、Swift、dyld、越狱绕过）、嵌入式/IoT 固件（binwalk、UART/JTAG/SPI 提取、ARM/MIPS、RTOS）、内核驱动（Linux .ko、eBPF、Windows .sys）、游戏引擎（Unreal Engine、Unity、反作弊、Lua）、车载 CAN 总线
- [platforms-hardware.md](platforms-hardware.md) - 硬件与高级架构逆向：HD44780 LCD 控制器 GPIO 重建、高级 RISC-V（自定义扩展、特权模式、调试）、ARM64/AArch64 逆向与利用（调用约定、ROP gadget、qemu-aarch64-static 仿真）
- [field-notes.md](field-notes.md) - 速查笔记：二进制类型、反调试绕过、专项模式、CTF 案例备注

---

## When to Pivot

- 如果你已经理解二进制，接下来需要做 heap、ROP 或内核利用，切换到 `/ctf-pwn`。
- 如果题目本质是恢复删除文件、PCAP 数据或磁盘痕迹，切换到 `/ctf-forensics`。
- 如果目标是 Web 应用，而你只是在逆一个很小的客户端辅助脚本，切换到 `/ctf-web`。
- 如果二进制实现的是机器学习模型，而题目是模型攻击或对抗输入，切换到 `/ctf-ai-ml`。
- 如果逆出的核心逻辑是密码算法或数学问题，切换到 `/ctf-crypto`。
- 如果样本是真实恶意软件，带 C2、加壳或规避行为，切换到 `/ctf-malware`。
- 如果题目其实是玩具 VM、编码题或 pyjail，而不是真正的二进制，切换到 `/ctf-misc`。

## Problem-Solving Workflow

1. **先提 strings** - 很多简单题直接有明文 flag
2. **试 ltrace/strace** - 动态分析常常无需逆向就能看到 flag
3. **试 Frida hook** - hook strcmp/memcmp，不逆向也能拿到预期值
4. **试 angr** - 很多 flag checker 可以自动符号执行求解
5. **试 Qiling** - 仿真外架构二进制，或无痕绕过重型反调试
6. **先画控制流**，再改执行路径
7. **把手工流程脚本化**（r2pipe、Frida、angr、Python）
8. **交叉验证假设**，对比多个反编译输出（dogbolt.org 并排看）

## Quick Wins (Try First!)

```bash
# 明文 flag 提取
strings binary | grep -E "flag\{|CTF\{|pico"
strings binary | grep -iE "flag|secret|password"
rabin2 -z binary | grep -i "flag"

# 动态分析，常常能直接截到 flag
ltrace ./binary
strace -f -s 500 ./binary

# 十六进制转储搜索
xxd binary | grep -i flag

# 用测试输入运行
./binary AAAA
echo "test" | ./binary
```

## Initial Analysis

```bash
file binary            # 类型、架构
checksec --file=binary # 安全特性（用于 pwn）
chmod +x binary        # 赋执行权限
```

## Memory Dumping Strategy

**关键思路：** 让程序自己把答案算出来，再 dump。断在最终比较处（`b *main+OFFSET`），输入任意一个长度正确的字符串，然后 `x/s $rsi` 导出程序算出的 flag。

## Decoy Flag Detection

**模式：** 真实检查前有多个假目标。注意是否有多个顺序比较目标和不同的成功提示。断在**最后一次**比较，不要断在前面的诱饵上。

## GDB PIE Debugging

PIE 二进制会随机化基址。用相对断点：
```bash
gdb ./binary
start                    # 强制解析 PIE 基址
b *main+0xca             # 相对 main
run
```

## Comparison Direction (Critical!)

两种模式：1. `transform(flag) == stored_target`，要逆变换。2. `transform(stored_target) == flag`，flag 就是变换后的数据，直接对 stored target 做该变换即可。

## Common Encryption Patterns

- 单字节 XOR - 枚举 256 个值
- 利用已知明文 XOR（`flag{`、`CTF{`）
- 硬编码 key 的 RC4
- 自定义置换 + XOR
- 位置索引 XOR（`^ i` 或 `^ (i & 0xff)`）叠加重复 key

## Quick Tool Reference

```bash
# Radare2
r2 -d ./binary     # 调试模式
aaa                # 分析
afl                # 列函数
pdf @ main         # 反汇编 main

# Ghidra (headless)
analyzeHeadless project/ tmp -import binary -postScript script.py

# IDA
ida64 binary       # 用 IDA64 打开
```

## Deep-Dive Notes

完成第一轮 triage、明确目标类型后，继续看 [field-notes.md](field-notes.md)。

- 目标格式：Python 字节码、WASM、Android、Flutter、.NET、UPX、Tauri
- 技术备注：反调试绕过、VM 分析、x86-64 坑点、迭代求解器、Unicorn、时间侧信道
- 平台备注：Godot、Roblox、macOS/iOS、嵌入式固件、内核驱动、游戏引擎、Swift、Kotlin、Go、Rust、D
- 案例备注：现代 CTF 专用逆向模式与较早的经典题型模式
