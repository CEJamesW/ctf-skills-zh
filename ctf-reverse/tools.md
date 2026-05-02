# CTF Reverse - 工具参考

## 目录
- [GDB](#gdb)
  - [基本命令](#basic-commands)
  - [PIE 二进制调试](#pie-binary-debugging)
  - [一行自动化](#one-liner-automation)
  - [内存查看](#memory-examination)
- [Radare2](#radare2)
  - [基本会话](#basic-session)
  - [r2pipe 自动化](#r2pipe-automation)
- [Ghidra](#ghidra)
  - [无头分析](#headless-analysis)
  - [解密模拟器](#emulator-for-decryption)
  - [MCP 命令](#mcp-commands)
- [Unicorn 模拟](#unicorn-emulation)
  - [基本设置](#basic-setup)
  - [混合模式（64 到 32）切换](#mixed-mode-64-to-32-switch)
  - [寄存器跟踪钩子](#register-tracing-hook)
  - [跟踪寄存器变化](#track-register-changes)
- [Python 字节码](#python-bytecode)
  - [反汇编](#disassembly)
  - [提取常量](#extract-constants)
  - [Pyarmor 静态解包（一键）](#pyarmor-static-unpack-1shot)
- [WASM 分析](#wasm-analysis)
  - [反编译为 C](#decompile-to-c)
  - [常见模式](#common-patterns)
- [Android APK](#android-apk)
  - [提取](#extraction)
  - [关键位置](#key-locations)
  - [搜索](#search)
  - [Flutter APK (Blutter)](#flutter-apk-blutter)
  - [HarmonyOS HAP/ABC (abc-decompiler)](#harmonyos-hapabc-abc-decompiler)
- [.NET 分析](#net-analysis)
  - [工具](#tools)
  - [两阶段 XOR + AES-CBC 解码模式 (Codegate 2013)](#two-stage-xor--aes-cbc-decode-pattern-codegate-2013)
  - [NativeAOT](#nativeaot)
- [加壳二进制](#packed-binaries)
  - [UPX](#upx)
  - [自定义加壳](#custom-packers)
  - [PyInstaller](#pyinstaller)
- [LLVM IR](#llvm-ir)
  - [转换为汇编](#convert-to-assembly)
- [RISC-V 二进制分析 (EHAX 2026)](#risc-v-binary-analysis-ehax-2026)
- [Binary Ninja](#binary-ninja)
- [与 dogbolt.org 的反编译器对比](#decompiler-comparison-with-dogboltorg)
- [实用命令](#useful-commands)
- [boolector SMT2 用于自定义哈希逆向 (OTW Advent 2018)](#boolector-smt2-for-custom-hash-reversal-otw-advent-2018)

关于动态插桩工具（Frida、angr、lldb、x64dbg），请参见 [tools-dynamic.md](tools-dynamic.md)。

---

## GDB

### 基本命令
```bash
gdb ./binary
run                      # 运行程序
start                    # 运行到 main
b *0x401234              # 在地址设置断点
b *main+0x100            # 相对 main 的断点
c                        # 继续执行
si                       # 单步指令
ni                       # 下一条指令（跳过调用）
x/s $rsi                 # 查看字符串
x/20x $rsp               # 查看栈
info registers           # 显示寄存器
set $eax=0               # 修改寄存器
```

### PIE 二进制调试
```bash
gdb ./binary
start                    # 强制解析 PIE 基址
b *main+0xca             # 相对 main 设置断点
b *main+0x198
run
```

### 一行自动化
```bash
gdb -ex 'start' -ex 'b *main+0x198' -ex 'run' ./binary
```

### 内存查看
```bash
x/s $rsi                 # 查看 RSI 处字符串
x/38c $rsi               # 38 个字符
x/20x $rsp               # 栈上 20 个十六进制字
x/10i $rip               # RIP 处 10 条指令
```

---

## Radare2

### 基本会话
```bash
r2 -d ./binary           # 以调试模式打开
aaa                      # 全部分析
afl                      # 列出函数
pdf @ main               # 反汇编 main
db 0x401234              # 设置断点
dc                       # 继续执行
ood                      # 重新开始调试
dr                       # 显示寄存器
dr eax=0                 # 修改寄存器
```
### r2pipe 自动化
```python
import r2pipe
r2 = r2pipe.open('./binary', flags=['-d'])
r2.cmd('aaa')
r2.cmd('db 0x401234')

for char in range(256):
    r2.cmd('ood')        # 重启
    r2.cmd(f'dr eax={char}')
    output = r2.cmd('dc')
    if 'correct' in output:
        print(f"Found: {chr(char)}")
```

---

## Ghidra

### 无头分析
```bash
analyzeHeadless /path/to/project tmp -import binary -postScript script.py
```

### 用于解密的模拟器
```java
EmulatorHelper emu = new EmulatorHelper(currentProgram);
emu.writeRegister("RSP", 0x2fff0000);
emu.writeRegister("RBP", 0x2fff0000);

// 写入加密数据
emu.writeMemory(dataAddress, encryptedBytes);

// 设置函数参数
emu.writeRegister("RDI", arg1);

// 运行直到返回
emu.setBreakpoint(returnAddress);
emu.run(functionEntryAddress);

// 读取结果
byte[] decrypted = emu.readMemory(outputAddress, length);
```

### MCP 命令
- 侦察: `list_functions`, `list_imports`, `list_strings`
- 分析: `decompile_function`, `get_xrefs_to`
- 注释: `rename_function`, `rename_variable`

---

## Unicorn 模拟

### 基础设置
```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# 映射代码段
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, code_bytes)

# 映射栈
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)

# 运行
mu.emu_start(start_addr, end_addr)
```

### 混合模式（64位切换到32位）
```python
# 当64位stub通过retf/retfq跳转到32位代码时：
# - retf 弹出4字节EIP + 2字节CS（共6字节）
# - retfq 弹出8字节RIP + 8字节CS（共16字节）

uc32 = Uc(UC_ARCH_X86, UC_MODE_32)
# 复制内存区域，然后复制通用寄存器
reg_map = {
    UC_X86_REG_EAX: UC_X86_REG_RAX,
    UC_X86_REG_EBX: UC_X86_REG_RBX,
    UC_X86_REG_ECX: UC_X86_REG_RCX,
    UC_X86_REG_EDX: UC_X86_REG_RDX,
    UC_X86_REG_ESI: UC_X86_REG_RSI,
    UC_X86_REG_EDI: UC_X86_REG_RDI,
    UC_X86_REG_EBP: UC_X86_REG_RBP,
}
for e, r in reg_map.items():
    uc32.reg_write(e, mu.reg_read(r) & 0xffffffff)  # mu = 上面定义的64位模拟器
uc32.reg_write(UC_X86_REG_EFLAGS, mu.reg_read(UC_X86_REG_RFLAGS) & 0xffffffff)

# SSE密集型代码需要复制XMM寄存器
for xr in [UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
           UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7]:
    uc32.reg_write(xr, mu.reg_read(xr))

# 运行32位代码，然后将寄存器/内存复制回64位
```

**提示：** 设置 `UC_IGNORE_REG_BREAK=1` 可屏蔽未实现寄存器的警告。

### 寄存器跟踪钩子
```python
def hook_code(uc, address, size, user_data):
    if address == TARGET_ADDR:
        rsi = uc.reg_read(UC_X86_REG_RSI)
        print(f"0x{address:x}: rsi=0x{rsi:016x}")

mu.hook_add(UC_HOOK_CODE, hook_code)
```

### 跟踪寄存器变化
```python
prev_rsi = [None]
def hook_rsi_changes(uc, address, size, user_data):
    rsi = uc.reg_read(UC_X86_REG_RSI)
    if rsi != prev_rsi[0]:
        print(f"0x{address:x}: RSI changed to 0x{rsi:016x}")
        prev_rsi[0] = rsi

mu.hook_add(UC_HOOK_CODE, hook_rsi_changes)
```

---

## Python 字节码

### 反汇编
```python
import marshal, dis

with open('file.pyc', 'rb') as f:
    f.read(16)  # 跳过头部（根据Python版本不同而异）
    code = marshal.load(f)
    dis.dis(code)
```

### 提取常量
```python
for ins in dis.get_instructions(code):
    if ins.opname == 'LOAD_CONST':
        print(ins.argval)
```

### Pyarmor 静态解包（一次性）

仓库地址：`https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot`

```bash
# 基本用法（递归处理）
python /path/to/oneshot/shot.py /path/to/scripts

# 显式指定pyarmor运行时库
python /path/to/oneshot/shot.py /path/to/scripts -r /path/to/pyarmor_runtime.so

# 将输出保存到另一个目录
python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output
```

注意事项：
- 运行 `shot.py` 前必须存在 `oneshot/pyarmor-1shot` 目录。
- 支持范围：Pyarmor 8.x-9.x（`PY` + 六位数字头部格式）。
- Pyarmor 7及更早版本（`PYARMOR` 头部）不在支持范围内。
- 反汇编输出通常可靠；反编译源码仍属实验性质。

---
## WASM 分析

### 反编译为 C
```bash
wasm2c checker.wasm -o checker.c
gcc -O3 checker.c wasm-rt-impl.c -o checker
```

### 常见模式
- `w2c_memory` - 线性内存数组
- `wasm_rt_trap(N)` - 运行时错误
- 函数导出：`flagChecker`，`validate`

---

## Android APK

### 提取
```bash
apktool d app.apk -o decoded/   # 最佳 - 解码 XML
jadx app.apk                     # 反编译为 Java
unzip app.apk -d extracted/      # 简单提取
```

### 关键位置
- `res/values/strings.xml` - 字符串资源
- `AndroidManifest.xml` - 应用元数据
- `classes.dex` - Dalvik 字节码
- `assets/`，`res/raw/` - 资源文件

### 搜索
```bash
grep -r "flag\|CTF" decoded/
strings decoded/classes*.dex | grep -i flag
```

### Flutter APK (Blutter)

```bash
# 在 arm64 构建上运行 Blutter
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

### HarmonyOS HAP/ABC (abc-decompiler)

仓库地址：`https://github.com/ohos-decompiler/abc-decompiler`

```bash
# 先解压 .hap 以获取 .abc 文件
unzip app.hap -d hap_extracted/
```

关键启动模式：
```bash
# 使用 CLI 入口（避免 java -jar GUI 模式）
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI [options] <input>
```

```bash
# 基础反编译
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -d "out" ".abc"

# 推荐用于 .abc
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple --log-level ERROR -d "out_abc_simple" ".abc"
```

注意事项：
- 从 `-m simple --log-level ERROR` 开始。
- 如果 `auto` 失败，先尝试 `-m simple`。
- 错误不一定意味着完全失败；检查 `out_xxx/sources/`。
- 每次运行使用新的输出目录。

---

## .NET 分析

### 工具
- **dnSpy** - 调试 + 反编译（最佳）
- **ILSpy** - 反编译器
- **dotPeek** - JetBrains 反编译器

### NativeAOT
- 查找 `System.Private.CoreLib` 字符串
- 存在类型元数据但结构重组
- 搜索长度前缀的 UTF-16 模式

### 两阶段 XOR + AES-CBC 解码模式（Codegate 2013）

**模式：** .NET 二进制存储一个加密字节数组，先经过 XOR 解码，再进行 AES-256-CBC 解密。相同的密钥值同时用作 AES 的 Key 和 IV。

**步骤：**
1. 从二进制中提取硬编码字节数组和密钥字符串（dnSpy/ILSpy）
2. 对每个字节进行 XOR（可能多次，例如先 `0x25` 再 `0x58`，等同于单次 `0x7D`）
3. 对 XOR 结果进行 Base64 解码
4. 使用提取的密钥作为 Key 和 IV，通过 `RijndaelManaged` 进行 AES-256-CBC 解密

```python
from Crypto.Cipher import AES
from base64 import b64decode

# 第一步：XOR 解码
data = bytearray(encrypted_bytes)
for i in range(len(data)):
    data[i] ^= 0x7D  # 组合 XOR 密钥 (0x25 ^ 0x58)

# 第二步：Base64 解码
ct = b64decode(bytes(data))

# 第三步：AES-256-CBC 解密（Key 和 IV 相同）
key = b"9e2ea73295c7201c5ccd044477228527"  # 填充至 32 字节
cipher = AES.new(key, AES.MODE_CBC, iv=key)
plaintext = cipher.decrypt(ct)
```

**关键洞察：** 当 .NET 反编译中出现 `RijndaelManaged`，检查 Key 和 IV 是否相同——这是常见的 CTF 模式。XOR 阶段通常作为真正加密前的简单混淆层。

---

## 压缩二进制文件

### UPX
```bash
upx -d packed -o unpacked
strings binary | grep UPX     # 检查 UPX 签名
```

### 自定义打包器
1. 在解包 stub 后设置断点
2. 转储内存
3. 修复 PE/ELF 头部

### PyInstaller
```bash
python pyinstxtractor.py binary.exe
# 查看目录：binary.exe_extracted/
```

---

## LLVM IR

### 转换为汇编
```bash
llc task.ll --x86-asm-syntax=intel
gcc -c task.s -o file.o
```

---
## RISC-V 二进制分析 (EHAX 2026)

**作者 (iguessbro)：** 静态链接、剥离符号的 RISC-V ELF 二进制文件。无法在 x86 上原生运行。

**使用 Capstone 反汇编：**
```python
from capstone import *

with open('binary', 'rb') as f:
    code = f.read()

# 支持压缩指令的 RISC-V 64 位
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC | CS_MODE_RISCV64)
md.detail = True

# 从入口点反汇编（查看 ELF 头的 e_entry）
TEXT_OFFSET = 0x10000  # 静态 RISC-V 的典型偏移
for insn in md.disasm(code[TEXT_OFFSET:], TEXT_OFFSET):
    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
```

**常见的 RISC-V 模式：**
- `li a0, N` → 加载立即数（参数设置）
- `mv a0, s0` → 寄存器移动
- `call offset` → 函数调用（auipc + jalr 组合）
- `beq/bne a0, zero, label` → 条件跳转
- `sd/ld` → 64 位存储/加载
- `addiw` → 32 位加法（W 后缀表示字操作）

**与 x86 的主要区别：**
- 无标志寄存器 — 比较操作内联于跳转指令中
- 参数传递在 a0-a7 寄存器（非 rdi/rsi/rdx）
- 返回值在 a0
- 保存寄存器 s0-s11（被调用者保存）
- 压缩指令（2 字节）与标准指令（4 字节）混合 — 使用 `CS_MODE_RISCVC`

**RISC-V 中的反逆向技巧：**
- 伪造标志作为字符串常量（检查 `"n0t_th3_r34l"` 模式）
- 防暴力破解的时间检测（rdtime 指令）
- 递增密钥的 XOR 解密：`decrypted[i] = enc[i] ^ (key & 0xFF) ^ 0xA5; key += 7`

**仿真：** `qemu-riscv64 -L /usr/riscv64-linux-gnu/ ./binary`（需要交叉工具链 sysroot）

---

## Binary Ninja

交互式反汇编/反编译器，社区快速增长。

**反编译输出：** 高级中间语言（HLIL）、伪 C、伪 Rust、伪 Python。

```bash
# 打开二进制文件
binaryninja binary
```

```python
# 无头分析（Python API）
import binaryninja
bv = binaryninja.open_view("binary")
for func in bv.functions:
    print(func.name, hex(func.start))
    print(func.hlil)  # 高级中间语言
```

**社区插件：** 通过插件管理器获取（Ctrl+Shift+P → “Plugin Manager”）。

**免费版本：** https://binary.ninja/free/ （基于云，功能有限）。

**相较 Ghidra 的优势：** 启动更快，中间语言更简洁，Python 脚本 API 更好。

---

## dogbolt.org 反编译器对比

**dogbolt.org** 同时运行多个反编译器对同一二进制进行反编译，并并排显示结果。

**支持的反编译器：** Hex-Rays (IDA)、Ghidra、Binary Ninja、angr、RetDec、Snowman、dewolf、Reko、Relyze。

**使用场景：**
- 反编译输出难以理解时 — 通过对比其他反编译器获得清晰度
- 某个反编译器处理某结构错误 — 另一个可能正确
- 快速筛查，无需本地安装所有工具
- 通过交叉验证确认反编译正确性

```bash
# 通过网页上传：https://dogbolt.org/
# 或使用 API：
curl -F "file=@binary" https://dogbolt.org/api/binaries/
```

**关键见解：** 不同反编译器擅长不同结构。当一个输出难读时，另一个通常能生成更清晰的伪代码。交叉验证能发现反编译器的缺陷。

---

## 常用命令

```bash
# 文件信息
file binary
checksec --file=binary
rabin2 -I binary

# 字符串提取
strings binary | grep -iE "flag|secret"
rabin2 -z binary

# 节区信息
readelf -S binary
objdump -h binary

# 符号信息
nm binary
readelf -s binary

# 反汇编
objdump -d binary
objdump -M intel -d binary
```

---

## 使用 boolector SMT2 进行自定义哈希逆向 (OTW Advent 2018)

**模式：** 由位操作构建的自定义哈希函数可用 SMT 求解器破解。boolector 的 QF_BV（位向量）逻辑在此类问题上明显比 Z3 快。将哈希函数直接转为 SMT2，断言输出，求解输入。

```smt
(set-logic QF_BV)
(declare-fun input () (_ BitVec 64))
(assert (bvuge input #x0000000020202020))   ; 可打印字符下界
(assert (bvule input #x000000007e7e7e7e))   ; 可打印字符上界

; 以 bvxor/bvrol/bvadd 链条形式表达哈希函数
(define-fun hash ((x (_ BitVec 64))) (_ BitVec 64) ...)
(assert (= (hash input) #xdeadbeefcafef00d))
(check-sat) (get-model)
```

```bash
boolector -m --output-format=smt2 hash.smt2
```

**关键见解：** Z3 是默认选择，但对于位级哈希难题，boolector 通常快 10-100 倍。通过 IDA/r2 将每个基本块提升为 `bvxor`/`bvrol`/`bvadd`，生成 SMT2，让求解器寻找原像。

**参考资料：** OverTheWire Advent 2018 — Jackinthebox，writeup 12789
