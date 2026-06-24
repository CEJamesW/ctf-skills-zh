# 逆向工程现场笔记

支持 [`SKILL.md`](SKILL.md) 的详细快速笔记。请在初步分析后阅读此文件，而非之前。

## 目录

- [二进制类型](#binary-types)
  - [Python .pyc](#python-pyc)
  - [WASM](#wasm)
  - [Android APK](#android-apk)
  - [Flutter APK (Dart AOT)](#flutter-apk-dart-aot)
  - [.NET](#net)
  - [压缩包 (UPX)](#packed-upx)
  - [Tauri 压缩桌面应用](#tauri-packed-desktop-apps)
- [反调试绕过](#anti-debugging-bypass)
- [专用模式](#specialized-patterns)
  - [S-Box / 密钥流模式](#s-box--keystream-patterns)
  - [自定义虚拟机分析](#custom-vm-analysis)
  - [Python 字节码逆向](#python-bytecode-reversing)
  - [基于信号的二进制探索](#signal-based-binary-exploration)
  - [通过补丁绕过恶意软件反分析](#malware-anti-analysis-bypass-via-patching)
  - [预期值表](#expected-values-tables)
  - [x86-64 陷阱](#x86-64-gotchas)
  - [迭代求解器模式](#iterative-solver-pattern)
  - [Unicorn 仿真（复杂状态）](#unicorn-emulation-complex-state)
  - [多阶段 shellcode 加载器](#multi-stage-shellcode-loaders)
  - [定时侧信道攻击](#timing-side-channel-attack)
  - [Godot 游戏资源提取](#godot-game-asset-extraction)
  - [Roblox Place 文件分析](#roblox-place-file-analysis)
  - [未剥离二进制信息泄露](#unstripped-binary-information-leaks)
  - [自定义混淆函数逆向](#custom-mangle-function-reversing)
  - [Rust serde_json 模式恢复](#rust-serde_json-schema-recovery)
  - [基于位置的变换逆向](#position-based-transformation-reversing)
  - [十六进制编码字符串比较](#hex-encoded-string-comparison)
- [CTF 案例笔记](#ctf-case-notes)
  - [嵌入式 ZIP + XOR 许可解密](#embedded-zip--xor-license-decryption)
  - [栈字符串去混淆（.rodata XOR Blob）](#stack-string-deobfuscation-rodata-xor-blob)
  - [前缀哈希暴力破解](#prefix-hash-brute-force)
  - [数学收敛位图](#mathematical-convergence-bitmap)
  - [RISC-V 二进制分析](#risc-v-binary-analysis)
  - [Sprague-Grundy 博弈论二进制](#sprague-grundy-game-theory-binary)
  - [内核模块迷宫求解](#kernel-module-maze-solving)
  - [带通道的多线程虚拟机](#multi-threaded-vm-with-channels)
  - [CVP/LLL 格点用于约束整数验证](#cvplll-lattice-for-constrained-integer-validation)
  - [决策树函数混淆](#decision-tree-function-obfuscation)
  - [Android JNI RegisterNatives 混淆](#android-jni-registernatives-obfuscation)
  - [多层自解密二进制](#multi-layer-self-decrypting-binary)
  - [带自修改代码的 GLSL 着色器虚拟机](#glsl-shader-vm-with-self-modifying-code)
  - [GF(2^8) 高斯消元用于 flag 恢复](#gf28-gaussian-elimination-for-flag-recovery)
  - [Z3 用于单行 Python 布尔电路](#z3-for-single-line-python-boolean-circuit)
  - [滑动窗口 Popcount 差分传播](#sliding-window-popcount-differential-propagation)
  - [Ruby/Perl 多语言约束满足](#rubyperl-polyglot-constraint-satisfaction)
  - [Verilog/硬件逆向](#veriloghardware-re)
  - [带 RC4 扁平二进制的自定义 binfmt 内核模块](#custom-binfmt-kernel-module-with-rc4-flat-binaries)
  - [哈希解析导入 / 无导入勒索软件](#hash-resolved-imports--no-import-ransomware)
  - [ELF 节头破坏用于反分析](#elf-section-header-corruption-for-anti-analysis)
  - [Brainfuck 字符逐个静态分析](#brainfuck-character-by-character-static-analysis)
  - [Brainfuck 通过读取计数 oracle 的侧信道](#brainfuck-side-channel-via-read-count-oracle)
  - [Brainfuck 比较习语检测](#brainfuck-comparison-idiom-detection)
  - [后门共享库检测](#backdoored-shared-library-detection)
  - [Go 二进制逆向](#go-binary-reversing)
  - [Go 二进制 UUID 补丁用于 C2 枚举](#go-binary-uuid-patching-for-c2-enumeration)
  - [D 语言二进制逆向](#d-language-binary-reversing)
  - [Rust 二进制逆向](#rust-binary-reversing)
  - [Frida 动态插桩](#frida-dynamic-instrumentation)
  - [Frida Firebase 云函数绕过](#frida-firebase-cloud-functions-bypass)
  - [angr 符号执行](#angr-symbolic-execution)
  - [Qiling 仿真](#qiling-emulation)
  - [VMProtect / Themida 分析](#vmprotect--themida-analysis)
  - [二进制差异分析](#binary-diffing)
  - [高级 GDB (pwndbg, rr)](#advanced-gdb-pwndbg-rr)
  - [macOS / iOS 逆向](#macos--ios-reversing)
  - [嵌入式 / 物联网固件逆向](#embedded--iot-firmware-re)
  - [内核驱动逆向](#kernel-driver-reversing)
  - [游戏引擎逆向](#game-engine-reversing)
  - [Swift / Kotlin 二进制逆向](#swift--kotlin-binary-reversing)
  - [INT3 补丁 + 核心转储暴力破解 oracle](#int3-patch--coredump-brute-force-oracle)
  - [信号处理链 + LD_PRELOAD oracle](#signal-handler-chain--ld_preload-oracle)
  - [字体连字利用](#font-ligature-exploitation)
  - [指令计数器作为加密状态](#instruction-counter-as-cryptographic-state)
  - [Burrows-Wheeler 变换逆转](#burrows-wheeler-transform-inversion)
  - [FRACTRAN 程序逆转](#fractran-program-inversion)
  - [仅操作码追踪重构](#opcode-only-trace-reconstruction)
  - [线程竞态有符号整数溢出](#thread-race-signed-integer-overflow)
  - [ESP32/Xtensa 固件逆向](#esp32xtensa-firmware-reversing)
  - [自定义虚拟机字节码提升到 LLVM IR](#custom-vm-bytecode-lifting-to-llvm-ir)
  - [SIGFPE 信号处理器侧信道](#sigfpe-signal-handler-side-channel)
  - [通过 objdump 批量 Crackme 自动化](#batch-crackme-automation-via-objdump)
  - [Android DEX 运行时字节码补丁](#android-dex-runtime-bytecode-patching)
  - [Fork + Pipe + 死分支反分析](#fork--pipe--dead-branch-anti-analysis)
## Binary Types

### Python .pyc
使用 `marshal.load()` + `dis.dis()` 反汇编。头部：8 字节（2.x），12 字节（3.0-3.6），16 字节（3.7+）。详见 [languages.md](languages.md#python-bytecode-reversing-disdis-output)。

### WASM
```bash
wasm2c checker.wasm -o checker.c
gcc -O3 checker.c wasm-rt-impl.c -o checker

# WASM 补丁（游戏挑战）：
wasm2wat main.wasm -o main.wat    # 二进制 → 文本
# 编辑 WAT：翻转比较操作，修改常量
wat2wasm main.wat -o patched.wasm # 文本 → 二进制
```

**WASM 游戏补丁（Tac Tic Toe，Pragyan 2026）：** 如果证明生成与走法质量无关，则补丁 minimax（翻转 `i64.lt_s` → `i64.gt_s`，改变 bestScore 符号）使 AI 表现差但证明仍有效。完整游戏补丁模式见 `/ctf-misc`（games-and-vms）。

### Android APK
使用 `apktool d app.apk -o decoded/` 提取资源；使用 `jadx app.apk` 反编译 Java。检查 `decoded/res/values/strings.xml` 查找 flag。详见 [tools.md](tools.md#android-apk)。

### Flutter APK (Dart AOT)
如果存在 `lib/arm64-v8a/libapp.so` + `libflutter.so`，使用 [Blutter](https://github.com/worawit/blutter)：`python3 blutter.py path/to/app/lib/arm64-v8a out_dir`。输出重构的 Dart 符号和 Frida 脚本。详见 [tools.md](tools.md#flutter-apk-blutter)。

### .NET
- dnSpy - 调试 + 反编译
- ILSpy - 反编译器

### Packed (UPX)
```bash
upx -d packed -o unpacked
```
如果解包失败，先检查 UPX 元数据：确认 UPX 节名称、头字段和版本标记是否完整。如果元数据看起来被篡改或不确定，查看 GitHub 上的 UPX 源码以识别可能的修改点。

### Tauri Packed Desktop Apps
Tauri 在可执行文件中嵌入 Brotli 压缩的前端资源。查找 `index.html` 的交叉引用定位资源索引表，导出数据块，进行 Brotli 解压。参考：`tauri-codegen/src/embedded_assets.rs`。

## Anti-Debugging Bypass

常见检测：
- `IsDebuggerPresent()` / PEB.BeingDebugged / NtQueryInformationProcess（Windows）
- `ptrace(PTRACE_TRACEME)` / `/proc/self/status` 中的 TracerPid（Linux）
- TLS 回调（在 main 之前运行 — 检查 PE TLS 目录）
- 时间检测（`rdtsc`，`clock_gettime`，`GetTickCount`）
- 硬件断点检测（通过 GetThreadContext 读取 DR0-DR3）
- INT3 扫描 / 代码自哈希（对 .text 段 CRC）
- 信号相关：SIGTRAP 处理，SIGALRM 超时，SIGSEGV 用于真实逻辑
- Frida/DBI 检测：扫描 `/proc/self/maps`，端口 27042，内联钩子检测

绕过方法：在检测处设置断点，修改寄存器绕过条件。pwntools 补丁示例：`elf.asm(elf.symbols.ptrace, 'ret')` 用立即返回替换函数。详见 [patterns.md](patterns.md#pwntools-binary-patching-crypto-cat)。

更多全面的反分析技术和绕过方法（30+ 种含代码）见 [anti-analysis.md](anti-analysis.md)。

## Specialized Patterns

### S-Box / Keystream Patterns
**Xorshift32：** 移位 13、17、5  
**Xorshift64：** 移位 12、25、27  
**魔数常量：** `0x2545f4914f6cdd1d`，`0x9e3779b97f4a7c15`

### Custom VM Analysis
1. 确认结构：寄存器、内存、指令指针（IP）
2. 逆向 `executeIns` 理解操作码含义
3. 编写反汇编器，将操作码映射到助记符
4. 通常暴力破解比完全逆向更简单
5. 查找通过命令行参数加载的字节码文件

详见 [patterns.md](patterns.md#custom-vm-reversing) 的 VM 工作流程、操作码表和状态机 BFS。

**顺序密钥链暴力破解：** 当 VM 以小块（如 3 字节 = 2^24 候选）验证输入，每块输出密钥作为下一块输入时，使用 OpenMP 并行顺序暴力破解每块。用 `gcc -O3 -march=native -fopenmp` 编译求解器。详见 [patterns-ctf-3.md](patterns-ctf-3.md#vm-sequential-key-chain-brute-force-midnight-flag-2026)。
### Python 字节码逆向
带有交错偶数/奇数表的 XOR flag 校验器很常见。有关字节码分析技巧和逆向模式，请参见 [languages.md](languages.md#python-bytecode-reversing-disdis-output)。

### 基于信号的二进制探索
二进制使用 UNIX 信号作为二叉树导航；通过 `LD_PRELOAD` hook `sigaction`，通过发送信号进行深度优先搜索。详见 [patterns.md](patterns.md#signal-based-binary-exploration)。

### 通过补丁绕过恶意软件反分析
翻转 `JNZ`/`JZ`（0x75/0x74），修改 sleep 值，在 Ghidra 中补丁环境检查（`Ctrl+Shift+G`）。详见 [patterns-runtime.md](patterns-runtime.md#malware-anti-analysis-bypass-via-patching)。

### 期望值表
使用 `objdump -s -j .rodata binary | less` 定位 —— 查找比较指令附近，大小与 flag 长度匹配。

### x86-64 陷阱
符号扩展和 32 位截断的坑。详见 [patterns.md](patterns.md#x86-64-gotchas) 了解细节和代码示例。

### 迭代求解器模式
对每个位置尝试每个字节（0-255），与期望输出匹配。**统一变换捷径：** 如果一个输入字节只改变一个输出字节，构建 0..255 映射后再反转。完整实现见 [patterns.md](patterns.md)。

### Unicorn 仿真（复杂状态）
`from unicorn import *` —— 映射段，设置栈，hook 追踪。**混合模式陷阱：** 64 位 stub 通过 `retf` 跳转到 32 位，需要切换到 UC_MODE_32 并复制 GPR、EFLAGS 和 XMM 寄存器。详见 [tools.md](tools.md#unicorn-模拟)。

### 多阶段 Shellcode 加载器
嵌套 shellcode 带 XOR 解码循环；在 `call rax` 处断点，使用 `set $rax=0` 绕过 ptrace，从 `mov` 指令中提取 flag。详见 [patterns-runtime.md](patterns-runtime.md#multi-stage-shellcode-loaders)。

### 定时侧信道攻击
验证时间因正确字符而异；测量每个候选的耗时，逐字节恢复 flag。详见 [patterns-runtime.md](patterns-runtime.md#timing-side-channel-attack)。

### Godot 游戏资源提取
使用 KeyDot 从可执行文件中提取加密密钥，然后用 gdsdecomp 解包 .pck 包。详见 [languages-platforms.md](languages-platforms.md#godot-game-asset-extraction)。

### Roblox Place 文件分析
查询 Asset Delivery API 获取版本历史；解析 `.rbxlbin` 块（INST/PROP/PRNT）以对比不同版本的脚本源代码。详见 [languages-platforms.md](languages-platforms.md#roblox-place-file-analysis)。

### 未剥离二进制信息泄露
**模式：** 调试信息和文件路径泄露作者身份。快速检查：`strings binary | grep "/home/"`（家目录），`file binary`（是否剥离？），`readelf -S binary | grep debug`（调试节）。

### 自定义混淆函数逆向
二进制每次混淆输入 2 字节并带有运行状态；从 `.rodata` 提取目标，编写逆函数。详见 [patterns.md](patterns.md#custom-mangle-function-reversing)。

### Rust serde_json Schema 恢复
反汇编 serde `Visitor` 实现以恢复预期 JSON schema；字段名顺序揭示 flag。详见 [languages-platforms.md](languages-platforms.md#rust-serde_json-schema-recovery)。

### 基于位置的变换逆向
二进制对位置索引进行加减；通过撤销每个索引偏移进行逆向。详见 [patterns.md](patterns.md#position-based-transformation-reversing)。

### 十六进制编码字符串比较
输入转换为十六进制，与常量比较。用 `xxd -r -p` 解码。详见 [patterns.md](patterns.md#hex-encoded-string-comparison)。

## CTF 案例笔记

### 嵌入式 ZIP + XOR 许可证解密
二进制在 `.rodata` 中带有命名符号（`EMBEDDED_ZIP`、`ENCRYPTED_MESSAGE`）→ 提取包含许可证的 ZIP，使用许可证字节 XOR 加密消息以恢复 flag。无需执行。详见 [patterns-ctf-2.md](patterns-ctf-2.md#embedded-zip--xor-license-decryption-metactf-2026)。
### Stack String 反混淆（.rodata XOR Blob）
二进制映射 `.rodata` blob，进行 XOR 反混淆，使用它来验证输入。用 pyelftools 重新实现验证循环以提取 blob。寻找 `0x9E3779B9`、`0x85EBCA6B` 常量和 `rol32()`。参见 [patterns-ctf-2.md](patterns-ctf-2.md#stack-string-deobfuscation-from-rodata-xor-blob-nullcon-2026)。

### 前缀哈希暴力破解
二进制对每个前缀独立哈希。通过匹配前缀哈希逐字符恢复。参见 [patterns-ctf-2.md](patterns-ctf-2.md#prefix-hash-brute-force-nullcon-2026)。

### 数学收敛位图
**模式：** 二进制通过牛顿法收敛性（例如，z^3-1=0）对坐标对进行分类。通过通过/失败结果的网格渲染 ASCII 艺术旗帜。关键：二进制是分类器，不是检查器——反转数学并进行可视化。参见 [patterns-ctf.md](patterns-ctf.md#mathematical-convergence-bitmap-ehax-2026)。

### RISC-V 二进制分析
静态链接、剥离的 RISC-V ELF。使用 Capstone 的 `CS_MODE_RISCVC | CS_MODE_RISCV64` 支持混合压缩指令。用 `qemu-riscv64` 模拟。注意伪造的 flag 和带增量密钥的 XOR 解密。参见 [tools.md](tools.md#risc-v-二进制分析-ehax-2026)。

### Sprague-Grundy 博弈论二进制
游戏二进制玩有限 Nim，使用伪随机数生成器（PRNG）选择失败位置的移动。识别游戏框架（Grundy 值 = 堆 % (k+1)，XOR 决定位置），通过用户输入反馈跟踪 PRNG 状态演变。参见 [patterns-ctf.md](patterns-ctf.md#sprague-grundy-game-theory-binary-dicectf-2026)。

### 内核模块迷宫求解
Rust 内核模块通过设备 ioctl 实现迷宫。动态枚举命令，构建带诱饵规避的深度优先搜索（DFS）求解器，部署为最小静态二进制（原始系统调用，无 libc）。参见 [patterns-ctf.md](patterns-ctf.md#kernel-module-maze-solving-dicectf-2026)。

### 带通道的多线程虚拟机
自定义虚拟机，16+ 线程通过 futex 通道通信。追踪跨线程边界的数据流，从 GDB 提取常量，注意反转的有效性逻辑，通过广度优先搜索（BFS）状态空间搜索求解。参见 [patterns-ctf.md](patterns-ctf.md#multi-threaded-vm-with-channel-synchronization-dicectf-2026)。

### CVP/LLL 格点用于受限整数验证
二进制通过带 64 位系数的矩阵乘法验证 flag；解必须是可打印 ASCII。使用 SageMath 中的 LLL 约简 + 最近向量问题（CVP）找到受限范围内的最近格点。两阶段模式：阶段 1 恢复 AES 密钥，阶段 2 用另一个线性系统（模 2^32）解密自定义虚拟机字节码。参见 [patterns-ctf-2.md](patterns-ctf-2.md#cvplll-lattice-for-constrained-integer-validation-htb-shadowlabyrinth)。

### 决策树函数混淆
约 200+ 个自动生成函数通过多项式比较路由输入。通过 Ghidra 无头模式脚本提取，而非手动逆向每个函数。已知输出格式的约束传播通过算术约束级联。参见 [patterns-ctf-2.md](patterns-ctf-2.md#decision-tree-function-obfuscation-htb-wondersms)。

### Android JNI RegisterNatives 混淆
`JNI_OnLoad` 中的 `RegisterNatives` 隐藏了哪个 C++ 函数处理每个 Java 本地方法（无标准 `Java_com_pkg_Class_method` 符号）。通过追踪 `JNI_OnLoad` → `RegisterNatives` → `fnPtr` 找到真实处理函数。使用 APK 中的 x86_64 `.so` 以获得最佳 Ghidra 反编译效果。参见 [languages-platforms.md](languages-platforms.md#android-jni-registernatives-obfuscation-htb-wondersms)。

### 多层自解密二进制
N 层二进制，每层使用用户提供的密钥字节 + SHA-NI 解密下一层。使用 oracle（正确密钥 → 有效代码且符合预期模式）。通过每候选分叉的写时复制（COW）隔离实现 JIT 执行以提升速度。参见 [patterns-ctf-2.md](patterns-ctf-2.md#multi-layer-self-decrypting-binary-dicectf-2026)。
### GLSL Shader VM 带自修改代码
**模式：** WebGL2 片段着色器在 256x256 RGBA 纹理（程序内存 + VRAM）上实现图灵完备的虚拟机。自修改代码（STORE 操作码）修补绘制指令。GPU 并行导致写冲突——用 Python 顺序模拟以恢复完整输出。详见 [patterns-ctf-3.md](patterns-ctf-3.md#glsl-shader-vm-with-self-modifying-code-apoorvctf-2026)。

### GF(2^8) 高斯消元用于恢复 Flag
**模式：** 二进制在 GF(2^8) 上使用 AES 多项式（0x11b）进行高斯消元。矩阵和增广向量存放在 `.rodata` 中；解向量即为 flag。反汇编中查找常数 `0x1b`。加法为 XOR，乘法使用多项式约简。详见 [patterns-ctf-2.md](patterns-ctf-2.md#gf28-gaussian-elimination-for-flag-recovery-apoorvctf-2026)。

### 使用 Z3 解析单行 Python 布尔电路
**模式：** 单行 Python（2000+ 分号）使用海象运算符链验证 flag 作为大端整数的布尔电路。混淆的 XOR 表达式 `(a | b) & ~(a & b)`。按分号拆分，符号化转换为 Z3，秒级求解。详见 [patterns-ctf-3.md](patterns-ctf-3.md#z3-for-single-line-python-boolean-circuit-bearcatctf-2026)。

### 滑动窗口 Popcount 差分传播
**模式：** 二进制通过 16 位滑动窗口每个位置的预期 popcount 验证输入。popcount 差分形成递推关系：`bit[i+16] = bit[i] + (data[i+1] - data[i])`。暴力枚举约 4000-8000 个有效初始 16 位窗口，每个确定整个位序列。详见 [patterns-ctf-3.md](patterns-ctf-3.md#sliding-window-popcount-differential-propagation-bearcatctf-2026)。

### Ruby/Perl 多语言混合约束满足
**模式：** 单文件同时有效于 Ruby 和 Perl，两者对密钥施加不同约束。利用 Ruby 的 `=begin`/`=end`（块注释）与 Perl 的 `=begin`/`=cut`（POD）运行不同解释器代码。交集两语言约束恢复唯一密钥。详见 [languages-platforms.md](languages-platforms.md#rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026)。

### Verilog/硬件逆向
**模式：** Verilog HDL 状态机源码，隐藏条件基于移位寄存器历史。分析 `always @(posedge clk)` 块和 `case` 语句找到正确输入序列。详见 [languages-platforms.md](languages-platforms.md#veriloghardware-reverse-engineering-srdnlenctf-2026)。

### 自定义 binfmt 内核模块与 RC4 扁平二进制
**模式：** 内核模块注册 binfmt 处理器用于加密扁平二进制。逆向 `.ko` 找到 RC4 密钥（`movabs` 立即数中），解密扁平二进制，按模块 `vm_mmap` 调用的固定虚拟地址导入。详见 [patterns-ctf.md](patterns-ctf.md#custom-binfmt-kernel-module-with-rc4-flat-binaries-bsidessf-2026)。

### 哈希解析导入 / 无导入勒索软件
**模式：** 二进制无可见导入，运行时通过符号名哈希解析 API。跳过哈希逆向——在 Docker 中用 `LD_PRELOAD` 钩住 OpenSSL 函数直接捕获 AES 密钥。详见 [patterns-ctf.md](patterns-ctf.md#hash-resolved-imports--no-import-ransomware-bsidessf-2026)。

### ELF 节区头损坏防分析
**模式：** 损坏的节区头导致分析工具崩溃，但程序头完整，二进制正常运行。将 `e_shoff` 置零或用 `readelf -l`（仅程序头）查看。flag 隐藏在损坏节区后，带魔数标记 + XOR。详见 [patterns-ctf.md](patterns-ctf.md#elf-section-header-corruption-for-anti-analysis-bsidessf-2026)。
### Brainfuck 字符逐个静态分析
**模式：** BF 程序验证输入时，使用 `,`（读取字符）后跟若干 `+` 操作，`+` 的次数等于预期的 ASCII 值。提取每个输入位置的增量计数，无需执行即可恢复预期输入。详见 [languages.md](languages.md#brainfuck-character-by-character-static-analysis-bsidessf-2026)。

### Brainfuck 通过读取计数 Oracle 的侧信道
**模式：** BF 输入验证器在字符正确时读取更多字节。统计每个候选的 `,` 操作次数——读取次数最高的字节即为正确字节。逐字符恢复。详见 [languages.md](languages.md#brainfuck-side-channel-via-read-count-oracle-bsidessf-2026)。

### Brainfuck 比较习语检测
**模式：** 编译后的 BF 使用固定习语进行相等检查（`<[-<->] +<[>-<[-]]>[-<+>]`）。对解释器进行插桩以检测模式并提取比较操作数（预期的 flag 字节）。详见 [languages.md](languages.md#brainfuck-comparison-idiom-detection-bsidessf-2026)。

### 带后门的共享库检测
二进制在 GDB 中正常工作但正常运行时失败（suid）？检查 `ldd` 是否有非标准 libc 路径，然后用 `strings | diff` 比较可疑库与系统库，查找注入的代码/密码。详见 [patterns-ctf.md](patterns-ctf.md#backdoored-shared-library-detection-via-string-diffing-hacklu-ctf-2012)。

### Go 二进制逆向
大型静态二进制带有 `go.buildid`？使用 GoReSym 恢复函数名（即使是剥离符号的二进制也有效）。Go 字符串是 `{ptr, len}` 对，不是以 null 结尾。查找 `main.main`、`runtime.gopanic`、通道操作（`runtime.chansend1`/`chanrecv1`）。使用 Ghidra golang-loader 插件效果最佳。详见 [languages-compiled.md](languages-compiled.md#go-binary-reversing)。

### Go 二进制 UUID 补丁用于 C2 枚举
**模式：** Go C2 客户端通过 `-ldflags -X` 注入 UUID。对二进制中的 UUID 字节（长度相同）进行补丁，注册到 C2，通过 API 枚举客户端/文件。详见 [languages-compiled.md](languages-compiled.md#go-binary-uuid-patching-for-c2-client-enumeration-bsidessf-2026)。

### D 语言二进制逆向
D 语言二进制具有独特的符号混淆（非 C++ 风格）。模板密集，函数变体多。查找符号中的 `_D` 前缀。详见 [languages-compiled.md](languages-compiled.md#d-language-binary-reversing-csaw-ctf-2016)。

### Rust 二进制逆向
带有 `core::panicking` 字符串和 `_ZN` 混淆符号的二进制？使用 `rustfilt` 进行符号解混淆。Panic 消息包含源代码路径和行号——最快方法是 `strings binary | grep "panicked"`。Option/Result 枚举使用判别字节（0=无/错误，1=有/成功）。详见 [languages-compiled.md](languages-compiled.md#rust-binary-reversing)。

### Frida 动态插桩
无需修改二进制即可 Hook 运行时函数。使用 `frida -f ./binary -l hook.js` 启动并插桩。Hook `strcmp`/`memcmp` 捕获预期值，通过替换 `ptrace` 返回值绕过反调试，扫描内存查找 flag 模式，替换验证函数。详见 [tools-dynamic.md](tools-dynamic.md#frida动态插桩)。

### Frida Firebase 云函数绕过
**模式：** Android 应用通过 Firebase 云函数验证。登录后使用 Frida hook 构造有效负载（UID + 值 + 时间戳）并直接调用云函数，绕过二维码/支付验证。详见 [languages-platforms.md](languages-platforms.md#frida-firebase-cloud-functions-bypass-bsidessf-2026)。

### angr 符号执行
自动路径探索以找到满足约束的输入。用 `angr.Project` 加载二进制，设置查找/避免地址，调用 `simgr.explore()`。限制输入为可打印 ASCII 和已知前缀以加速求解。Hook 代价高的函数（加密、I/O）防止路径爆炸。详见 [tools-dynamic.md](tools-dynamic.md#angr符号执行)。
### Qiling Emulation
跨平台二进制仿真，支持操作系统级别（系统调用、文件系统）。可在任意主机上仿真 Linux/Windows/ARM/MIPS 二进制。无调试器痕迹——默认绕过所有反调试。通过 Python API 钩取系统调用和地址。详见 [tools-dynamic.md](tools-emulation.md#qiling-框架跨平台仿真)。

### VMProtect / Themida 分析
VMProtect 将代码虚拟化为自定义字节码。识别虚拟机入口（类似 pushad），找到处理器表（大型间接跳转），动态追踪处理器。CTF 中重点追踪输入上的操作，而非完全反虚拟化。Themida：使用 ScyllaHide + Scylla 在 OEP 处导出。详见 [tools-advanced.md](tools-advanced.md#vmprotect-analysis)。

### 二进制差异分析
BinDiff 和 Diaphora 比较两个二进制文件以突出差异。挑战提供补丁版/原版时必备。导出自 IDA/Ghidra，差异分析以发现漏洞或隐藏功能。详见 [tools-advanced.md](tools-advanced.md#binary-diffing)。

### 高级 GDB（pwndbg，rr）
pwndbg：`context`，`vmmap`，`search -s "flag{"`，`telescope $rsp`。GEF 的替代方案。使用 `rr record`/`rr replay` 进行逆向调试——可向后单步执行。Python 脚本支持暴力破解和自动追踪。详见 [tools-advanced-2.md](tools-advanced-2.md#advanced-gdb-techniques)。

### macOS / iOS 逆向
Mach-O 二进制：`otool -l` 查看加载命令，`class-dump` 获取 Objective-C 头文件。Swift：`swift demangle` 还原符号。iOS 应用：用 frida-ios-dump 解密 FairPlay DRM，利用 Frida 钩子绕过越狱检测。补丁二进制重新签名使用 `codesign -f -s -`。详见 [platforms.md](platforms.md#macos--ios-reversing)。

### 嵌入式 / 物联网固件逆向
`binwalk -Me firmware.bin` 递归提取。硬件：UART/JTAG/SPI flash 用于固件转储。文件系统：SquashFS（`unsquashfs`）、JFFS2、UBI。用 QEMU 仿真：`qemu-arm -L /usr/arm-linux-gnueabihf/ ./binary`。详见 [platforms.md](platforms.md#embedded--iot-firmware-re)。

### 内核驱动逆向
Linux `.ko`：通过 `file_operations` 结构找到 ioctl 处理函数，追踪 `copy_from_user`/`copy_to_user`。用 QEMU+GDB 调试（`-s -S`）。eBPF：`bpftool prog dump xlated`。Windows `.sys`：找到 `DriverEntry` → `IoCreateDevice` → IRP 处理函数。详见 [platforms.md](platforms.md#kernel-driver-reversing)。

### 游戏引擎逆向
Unreal：用 UnrealPakTool 解包 .pak，使用 FModel 逆向 Blueprint 字节码。Unity Mono：用 dnSpy 反编译 Assembly-CSharp.dll。反作弊（EAC、BattlEye、VAC）：识别系统，绕过特定检测。Lua 游戏：用 `luadec`/`unluac` 反编译字节码。详见 [platforms.md](platforms.md#game-engine-reversing)。

### Swift / Kotlin 二进制逆向
Swift：`swift demangle` 还原符号，协议见证表用于分发，`__swift5_*` 段。Kotlin/JVM：协程编译为状态机在 `invokeSuspend`，用带 Kotlin 模式的 `jadx` 反编译效果最佳。Kotlin/Native：LLVM 后端，反汇编看起来像 C++。详见 [languages-compiled.md](languages-compiled.md#swift-binary-reversing)。

### INT3 Patch + Coredump 暴力破解 Oracle
在变换输出后打补丁 `0xCC`（INT3），启用核心转储，通过 `strings` 从 coredump 中提取计算状态，暴力破解每个输入字符。避免完全逆向变换。详见 [patterns.md](patterns-runtime.md#int3-patch--coredump-brute-force-oracle-pwn2win-2016)。

### 信号处理链 + LD_PRELOAD Oracle
二进制使用信号处理链进行逐字符密码验证。通过 LD_PRELOAD 钩取 `signal()` —— 安装下一个处理器的调用确认当前字符正确。详见 [patterns.md](patterns-runtime.md#signal-handler-chain--ld_preload-oracle-nuit-du-hack-2016)。
### 字体连字利用
自定义 OpenType 字体将多字符连字序列映射为单个字形；反转 GSUB 表以解码隐藏信息。详见 [patterns-ctf-3.md](patterns-ctf-3.md#opentype-font-ligature-exploitation-for-hidden-messages-hack-the-vote-2016)。

### 将指令计数器作为加密状态
**模式：** 手写汇编使用专用寄存器（如 `r12`）作为指令计数器，几乎每条指令后递增。计数器用于对输入字节进行 XOR/ROL/乘法变换，使变换路径相关。通过 Unicorn 仿真逐字节暴力破解恢复 flag。详见 [patterns-ctf-3.md](patterns-ctf-3.md#instruction-counter-as-cryptographic-state-metactf-flash-2026)。

### Burrows-Wheeler 变换逆转
在无终止符的情况下，通过尝试所有可能的行索引来逆转 BWT。使用标准 `bwtool` 或手动列排序重构。详见 [patterns-ctf-3.md](patterns-ctf-3.md#burrows-wheeler-transform-inversion-without-terminator-asis-ctf-finals-2016)。

### FRACTRAN 程序逆转
一种使用迭代分数乘法的晦涩语言。通过交换分数表中的分子和分母，反向运行输出进行逆转。输入输出编码为质因数分解的指数。详见 [languages.md](languages.md#fractran-program-inversion-boston-key-party-2016)。

### 仅含 Opcode 的执行轨迹重构
仅含操作码（无数据）的执行轨迹仍通过分支决策泄露信息。排序算法的比较揭示元素顺序。通过去重轨迹并拆分为基本块进行重构。详见 [tools-dynamic.md](tools-emulation.md#仅操作码追踪重构opcode-only-trace-reconstruction0ctf-2016)。

### 线程竞态带符号整数溢出
游戏二进制存在线程不安全的技能锁。技能选择与伤害计算竞态；`cdqe` 指令将 0xFFFFFFFF 符号扩展为 -1，导致减法时 HP 溢出。详见 [patterns-ctf-3.md](patterns-ctf-3.md#thread-race-condition-with-signed-integer-overflow-codegate-2017)。

### ESP32/Xtensa 固件逆向
IDA 不支持——使用 radare2 + ESP-IDF ROM 链接脚本（`esp32.rom.ld`）进行符号解析。结合公开 ESP-IDF HTTP 服务器示例定位应用逻辑。详见 [patterns-ctf-3.md](patterns-ctf-3.md#esp32xtensa-firmware-reversing-with-rom-symbol-map-insomnihack-2017)。

### 自定义 VM 字节码提升至 LLVM IR
将自定义 VM 字节码转译为 LLVM IR，再用 `opt -O3` 简化（内联、常量折叠、死代码消除）。将 1300 行代码缩减至约 150 行，揭示底层算法。详见 [tools-advanced.md](tools-advanced.md#custom-vm-bytecode-lifting-to-llvm-ir-google-ctf-2017)。

### SIGFPE 信号处理器侧信道
SIGFPE 信号处理器创建静态分析不可见的隐式控制流。通过 `strace -e signal=SIGFPE` 统计每个候选字符的 SIGFPE 信号数——正确字符产生更多信号。详见 [anti-analysis.md](anti-analysis-ctf.md#sigfpe-signal-handler-side-channel-via-strace-counting-plaidctf-2017)。

### 通过 objdump 批量 Crackme 自动化
大量结构相同的 crackme 挑战（数百个二进制）：脚本使用 `objdump` 提取 CMP 立即数和加减算术序列，然后代数逆推密钥，无需执行。详见 [patterns-ctf-3.md](patterns-ctf-3.md#batch-crackme-automation-via-objdump-pattern-extraction-def-con-2017)。

### Android DEX 运行时字节码补丁
本地 JNI 库通过 `/proc/self/maps` + `mprotect` + XOR 在内存中补丁 Dalvik 字节码。仅静态 APK 分析不足——需从本地 `.so` 提取 XOR 密钥和偏移，重构运行时 DEX。详见 [languages-platforms.md](languages-platforms.md#android-dex-runtime-bytecode-patching-via-procselfmaps-google-ctf-2017)。
### Fork + Pipe + 死分支反分析
Fork/pipe 进程间通信，父进程写入数据后退出，子进程读取并继续执行。真正的验证隐藏在一个死分支（始终为假的比较）中。使用 `strace` 可以发现 fork/pipe 模式；修改比较常量以进入隐藏代码。详见 [patterns-ctf-3.md](patterns-ctf-3.md#fork--pipe--dead-branch-anti-analysis-rctf-2017)。
