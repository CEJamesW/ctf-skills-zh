# CTF Reverse - 硬件与高级架构逆向

HD44780 LCD GPIO 重建、RISC-V 高级扩展与调试、ARM64/AArch64 逆向与利用。

## Table of Contents
- [HD44780 LCD Controller GPIO Reconstruction (32C3 2015)](#hd44780-lcd-controller-gpio-reconstruction-32c3-2015)
- [RISC-V (Advanced)](#risc-v-advanced)
  - [Custom Extensions](#custom-extensions)
  - [Privileged Modes](#privileged-modes)
  - [RISC-V Debugging](#risc-v-debugging)
- [ARM64/AArch64 Reversing and Exploitation](#arm64aarch64-reversing-and-exploitation)
- [MIPS64 Cavium OCTEON Coprocessor 2 Crypto (SEC-T CTF 2017)](#mips64-cavium-octeon-coprocessor-2-crypto-sec-t-ctf-2017)
- [EFM32 ARM Microcontroller MMIO AES (SEC-T CTF 2017)](#efm32-arm-microcontroller-mmio-aes-sec-t-ctf-2017)
- [MBR/Bootloader Reversing with QEMU + GDB (Square CTF 2017)](#mbrbootloader-reversing-with-qemu--gdb-square-ctf-2017)
- [Game Boy ROM Z80 Analysis in bgb Debugger (Square CTF 2017)](#game-boy-rom-z80-analysis-in-bgb-debugger-square-ctf-2017)
- [KVM Guest Analysis via ioctl + KVM_EXIT_HLT Block Chaining (CSAW 2018)](#kvm-guest-analysis-via-ioctl--kvm_exit_hlt-block-chaining-csaw-2018)
- [Coreboot ROM XOR-Pair Bit-Flip Address Discovery (Hack.lu 2018)](#coreboot-rom-xor-pair-bit-flip-address-discovery-hacklu-2018)

---

## HD44780 LCD Controller GPIO Reconstruction (32C3 2015)

从 Raspberry Pi 的原始 GPIO 采样中恢复 HD44780 LCD 上显示的文本：

1. **识别信号线：** 将 GPIO 引脚映射到 HD44780 信号（RS、CLK、D4-D7，4-bit 模式）
2. **时钟边沿检测：** 在时钟下降沿（1->0）采样数据线
3. **拼接半字节：** 每两个 4-bit 样本合成为一个 8-bit 命令/数据字节
4. **DRAM 地址映射：** HD44780 多行显示使用非连续地址：
   - Line 0: 0x00-0x27
   - Line 1: 0x40-0x67
   - Line 2: 0x14-0x3B
   - Line 3: 0x54-0x7B

```python
display = [' '] * 80  # 4 lines x 20 chars
cursor = 0

for timestamp, gpio_state in sorted(gpio_log):
    if falling_edge(gpio_state, CLK_PIN):
        nibble = extract_data_bits(gpio_state)
        byte = assemble_nibble(nibble)  # Two nibbles per byte
        if rs_high(gpio_state):  # RS=1: data write
            display[dram_to_position(cursor)] = chr(byte)
            cursor += 1
        else:  # RS=0: command (set cursor, clear, etc.)
            cursor = parse_command(byte)
```

**关键点：** GPIO 与 LCD 信号的映射通常不会直接给出。一般可通过“跳变最多的引脚”猜时钟，再根据命令/数据交替模式识别 RS。

---

## RISC-V (Advanced)

超出基础反汇编的内容见 [tools.md](tools.md#risc-v-二进制分析-ehax-2026)。这里补充高级部分：

### Custom Extensions

```text
Bitmanip extensions (Zbb, Zbc, Zbs):
  clz, ctz, cpop         -> count leading/trailing zeros, popcount
  orc.b, rev8            -> byte-level bit manipulation
  andn, orn, xnor        -> negated logic operations
  clmul, clmulh, clmulr  -> carry-less multiplication (crypto)
  bset, bclr, binv, bext -> single-bit operations

Crypto extensions (Zk*):
  aes32esi, aes32dsmi     -> AES round operations
  sha256sig0, sha512sum0  -> SHA hash acceleration
  sm3p0, sm4ed            -> Chinese crypto standards
```

### Privileged Modes

```text
Machine mode (M):  最高权限，固件/bootloader
Supervisor mode (S): OS kernel
User mode (U):      应用程序

CSR registers to watch:
  mstatus/sstatus    -> privilege level, interrupt enable
  mtvec/stvec       -> trap handler address
  mepc/sepc         -> exception return address
  mcause/scause     -> trap cause
  satp              -> page table root (virtual memory)
```

### RISC-V Debugging

```bash
# OpenOCD + GDB for hardware debugging
openocd -f interface/jlink.cfg -f target/riscv.cfg

# GDB for RISC-V
riscv64-unknown-elf-gdb binary
(gdb) target remote :3333

# QEMU with GDB server
qemu-riscv64 -g 1234 -L /usr/riscv64-linux-gnu/ ./binary
riscv64-linux-gnu-gdb -ex 'target remote :1234' ./binary
```

---

## ARM64/AArch64 Reversing and Exploitation

AArch64 常见于移动应用、云服务器、Apple Silicon 和 CTF。其 calling convention 与利用方式和 x86-64 有明显差异。

**环境与仿真：**

```bash
# Install cross-toolchain and emulator
apt install gcc-aarch64-linux-gnu gdb-multiarch qemu-user-static

# Run AArch64 binary on x86 host
qemu-aarch64-static -L /usr/aarch64-linux-gnu/ ./arm64_binary

# Debug with GDB
qemu-aarch64-static -g 12345 -L /usr/aarch64-linux-gnu/ ./arm64_binary &
gdb-multiarch -ex 'set arch aarch64' -ex 'target remote :1234' ./arm64_binary

# With library preloading (for challenges that ship libc)
qemu-aarch64-static -g 12345 -E LD_PRELOAD=./libc.so.6 -L ./lib ./arm64_binary
```

**AArch64 调用约定：**

```text
Registers:
  x0-x7    -- function arguments AND return values (x0 = first arg / return)
  x8       -- indirect result location (struct returns)
  x9-x15   -- caller-saved temporaries
  x19-x28  -- callee-saved (preserved across calls)
  x29 (fp) -- frame pointer
  x30 (lr) -- link register (return address, NOT on stack by default)
  sp       -- stack pointer (must be 16-byte aligned)
  xzr      -- zero register (reads as 0, writes discarded)

Key exploitation differences:
  - Return address in LR (x30), not on stack -- pushed only if function calls others
  - No RIP-relative addressing like x86 -- uses ADRP+ADD pairs for PC-relative loads
  - Fixed 4-byte instruction width -- no variable-length gadget tricks
  - NOP = 0xD503201F (not 0x90)
  - BLR x8 / BR x30 -- indirect calls/jumps use register operands
```

**Ghidra/IDA 中常见模式：**

```text
# PC-relative address loading (equivalent to x86 LEA):
ADRP  x0, #0x411000      ; Load page address (4KB aligned)
ADD   x0, x0, #0x8       ; Add page offset -> x0 = 0x411008

# Function prologue:
STP   x29, x30, [sp, #-0x30]!  ; Push fp + lr, decrement sp
MOV   x29, sp                   ; Set frame pointer

# Function epilogue:
LDP   x29, x30, [sp], #0x30    ; Pop fp + lr, increment sp
RET                              ; Branch to x30 (lr)

# Switch/jump table:
ADR   x1, jump_table
LDRB  w2, [x1, x0]       ; Load offset byte
ADD   x1, x1, w2, SXTB   ; Sign-extend and add
BR    x1                   ; Indirect branch
```

**AArch64 ROP：**

```python
from pwn import *

# AArch64 gadgets differ from x86:
# - "pop {x0}; ret" equivalent: LDP x0, x1, [sp], #0x10; RET
# - Prologue gadgets: LDP x29, x30, [sp, #0x20]; ... RET
# - system() call: x0 = pointer to "/bin/sh", BLR to system

context.arch = 'aarch64'
elf = ELF('./arm64_binary')

# Common gadget pattern in AArch64 libc:
# LDP X19, X20, [SP,#var_s10]
# LDP X29, X30, [SP+var_s0],#0x20
# RET
# Controls x19, x20, x29, x30 and advances sp by 0x20
```

**关键点：** AArch64 指令宽度固定，返回地址保存在 `lr/x30`，因此 gadget 明显比 x86 更受限。实际可用 gadget 主要来自函数序言/尾声中的 `STP`/`LDP` 配对。

**识别时机：** `file` 显示 `ELF 64-bit LSB ... ARM aarch64`。在 x86 主机上可优先用 `qemu-aarch64-static` 跑。

**工具：** radare2（`r2 -AA -a arm -b 64`）、Ghidra、`aarch64-linux-gnu-objdump -d`、Unicorn Engine（`UC_ARCH_ARM64`）

**参考：** Google CTF 2016 "Forced Puns", Insomni'hack 2018 "onecall"

---

## MIPS64 Cavium OCTEON Coprocessor 2 Crypto (SEC-T CTF 2017)

Cavium OCTEON 网络处理器通过 MIPS Coprocessor 2（CP2）实现硬件 AES 和 SHA256，使用 `dmtc2`/`dmfc2` 指令与硬件引擎交互。反汇编里它们看上去像普通寄存器移动，但实际是在驱动 crypto 外设。

**OCTEON 的关键 CP2 寄存器布局：**
```text
AES key registers:
  0x0104 – AES key quadword 0
  0x0105 – AES key quadword 1
  0x0106 – AES key quadword 2
  0x0107 – AES key quadword 3

SHA256 hash registers:
  0x400E–0x4012 – SHA256 intermediate hash words
  0x404F        – SHA256 control/result

dmtc2  rN, 0x0104   ; load 64 bits of AES key into CP2 register 0x104
dmtc2  rN, 0x0105   ; ...next quadword
```

**思路：**
1. 在 IDA/Ghidra 中识别 `dmtc2`/`dmfc2`，若 selector 落在 `0x100-0x40FF` 范围，往往就是 OCTEON CP2
2. 对照 Cavium OCTEON 硬件手册理解寄存器语义
3. 跟踪 key 装载序列，恢复 AES 或 HMAC 材料

**关键点：** MIPS 上的硬件加密器通常伪装成协处理器寄存器写入。只要识别出寄存器地址区间，就能转向厂商文档辅助分析。

**参考：** SEC-T CTF 2017

---

## EFM32 ARM Microcontroller MMIO AES (SEC-T CTF 2017)

Silicon Labs EFM32 Cortex-M 平台的平坦二进制，加载地址为 `0x1000`，运行于 Thumb 模式。

**IDA 设置：**
```text
Processor: ARM Little-endian (ARMv7-M)
Load address: 0x1000
Set T register = 1 (force Thumb mode decoding)
```

**AES 外设 MMIO 布局（EFM32 AES base `0x400E0000`）：**
```text
0x400E0000 + 0x000  CTRL   – enable, decrypt mode
0x400E0000 + 0x004  CMD    – start/stop
0x400E0000 + 0x010  KEYLA  – key low word 0
0x400E0000 + 0x014  KEYLB  – key low word 1
0x400E0000 + 0x018  KEYLC  – key low word 2
0x400E0000 + 0x01C  KEYLD  – key low word 3
```

程序会取两份值异或后写入 AES key 寄存器，再用该 key 以 ECB 模式解密嵌入密文。

```python
from Crypto.Cipher import AES

key_part_a = bytes.fromhex("...")  # extracted from IDA .data section
key_part_b = bytes.fromhex("...")  # second value
key = bytes(a ^ b for a, b in zip(key_part_a, key_part_b))

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
```

**关键点：** 微控制器上的硬件 AES 通常表现为对固定 MMIO 基址的一串写入。识别外设地址后，应立刻查对应芯片参考手册。

**参考：** SEC-T CTF 2017

---

## MBR/Bootloader Reversing with QEMU + GDB (Square CTF 2017)

用 QEMU 启动软盘/磁盘镜像并开启 GDB stub，再附加 GDB，完整调试 16 位实模式或 32 位保护模式 bootloader。

```bash
# Boot with GDB stub on port 1234; -S pauses execution at start
qemu-system-x86_64 -fda disk.img -s -S

# In another terminal, attach GDB
gdb -ex "set architecture i8086" \
    -ex "target remote :1234" \
    -ex "break *0x7c00" \
    -ex "continue"

# Common MBR entry point is 0x7c00 (BIOS loads MBR here)
# Step through bootloader, inspect registers and memory:
(gdb) x/20i $pc
(gdb) info registers
(gdb) x/16xb 0x7c00
```

若要绕过密码校验，可找到比较后的条件跳转，在镜像文件中把它 NOP 掉，或改成恒成立。

```bash
# Find the comparison offset in the image and patch it
python3 -c "
data = open('disk.img', 'rb').read()
# Replace JNZ (0x75) with JMP-short-always or NOP
data = data[:offset] + b'\x90\x90' + data[offset+2:]
open('disk_patched.img', 'wb').write(data)
"
```

**关键点：** QEMU 的 `-s -S` 让 bootloader 调试流程几乎和用户态程序一样，MBR/引导扇区题优先用这条路。

**参考：** Square CTF 2017

---

## Game Boy ROM Z80 Analysis in bgb Debugger (Square CTF 2017)

Game Boy ROM 使用 Sharp SM83（Z80/8080 混合架构）。`bgb` 模拟器自带类似 GDB 的调试功能：断点、内存查看、寄存器显示。

**常见比较指令：**
```asm
LD   A, [HL]    ; load byte from memory pointed to by HL into A
AND  [HL]       ; A = A & *HL  — compares player byte against memory value
CP   N          ; compare A with immediate N (sets Z flag if equal)
```

当输入校验过程中触发 `and (hl)` 或 `cp (hl)` 时，期望字节就直接存放在 `(hl)` 所指地址，可在内存窗口中直接看到。

**bgb 工作流：**
1. 打开 ROM：File → Open ROM
2. 在反汇编窗口右键 “Run to cursor” 或按 F2 下断点
3. 命中比较时，查看 Registers 面板中的 HL 和 Memory 面板中的 `*HL`
4. 记录期望值后继续到下一个位置

**关键点：** Game Boy 题常见的比较会通过 `(hl)` 间接访问期望字节，因此动态单步时能直接读出目标值。

**参考：** Square CTF 2017

---

## KVM Guest Analysis via ioctl + KVM_EXIT_HLT Block Chaining (CSAW 2018)

**模式：** 一个用户态进程托管 KVM VM，guest“程序”由一堆以 `HLT` 结尾的代码块组成。宿主在 `KVM_EXIT_HLT` 时读取 guest 寄存器，并根据 `rax` 在 `0x2020A0` 的跳转表中分派下一个代码块。逆向时应从宿主的 `ioctl` 轨迹入手，而不是只盯 guest 代码。

```bash
# 1. Observe KVM ioctls + register snapshots
strace -v -e ioctl ./challenge 2>&1 | grep -E "KVM_RUN|KVM_(GET|SET)_REGS"

# 2. Dump guest code memory (offset + size from KVM_SET_USER_MEMORY_REGION ioctl)
gdb -batch -ex "attach $(pgrep challenge)" \
    -ex "dump binary memory guest.bin 0x400000 0x410000" \
    -ex "detach"

# 3. Disassemble each HLT-terminated block
objdump -D -b binary -m i386:x86-64 guest.bin | less
```

```python
# Rebuild the dispatch graph
import struct
with open("challenge", "rb") as f:
    data = f.read()
# Host table at 0x2020A0 maps rax → next block offset
table = struct.unpack_from("<128Q", data, 0x2020A0)
for rax, ptr in enumerate(table):
    if ptr:
        print(f"rax={rax:02x} → block {ptr:#x}")
```

**关键点：** KVM 题往往把真正控制流藏在宿主进程里，而 guest 只是若干黑盒代码块。`strace` 观察 KVM ioctl 往往比在 guest 内下断更高效。

**参考：** CSAW CTF Qualification Round 2018 — kvm, writeup 11206

---

## Coreboot ROM XOR-Pair Bit-Flip Address Discovery (Hack.lu 2018)

**模式：** 固件启动时将 ROM 中两个常量异或得到 flag 地址。题目服务允许攻击者翻转 ROM 中任意一位，并观察新的 flag 地址。先计算理论地址 `X = C1 ^ C2`，再与实际地址比较，差异位就指向控制重定向的 ROM 位点。

```python
# Two constants in ROM
C1 = 0xEF56BF92
C2 = 0xEF5A3F92
intended = C1 ^ C2          # 0xC8000 per the source
actual   = 0xC0000          # where the flag really lives in memory

diff = intended ^ actual    # 0x08000 → bit 15
# Find the ROM offset that, when a single bit is flipped, produces `actual`.
# The flip must land in either C1 or C2 so the XOR result has bit 15 cleared.
```

**关键点：** XOR 对单比特翻转是线性的：某一位在任一操作数中被翻转，结果中的对应位也会翻转。比较理论地址与实际地址的差分，通常就能把候选补丁点缩到极小范围。

**参考：** Hack.lu CTF 2018 — 1-bit-missile, writeups 11862, 11865
