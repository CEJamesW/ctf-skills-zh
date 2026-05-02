# CTF Reverse - 比赛特定模式（Part 3）

## Table of Contents
- [Z3 for Single-Line Python Boolean Circuit (BearCatCTF 2026)](#z3-for-single-line-python-boolean-circuit-bearcatctf-2026)
- [Sliding Window Popcount Differential Propagation (BearCatCTF 2026)](#sliding-window-popcount-differential-propagation-bearcatctf-2026)
- [Morse Code from Keyboard LEDs via ioctl (PlaidCTF 2013)](#morse-code-from-keyboard-leds-via-ioctl-plaidctf-2013)
- [C++ Destructor-Hidden Validation (Defcamp 2015)](#c-destructor-hidden-validation-defcamp-2015)
- [Syscall Side-Effect Memory Corruption (Hack.lu 2015)](#syscall-side-effect-memory-corruption-hacklu-2015)
- [MFC Dialog Event Handler Location (WhiteHat 2015)](#mfc-dialog-event-handler-location-whitehat-2015)
- [VM Sequential Key-Chain Brute-Force (Midnight Flag 2026)](#vm-sequential-key-chain-brute-force-midnight-flag-2026)
- [Burrows-Wheeler Transform Inversion without Terminator (ASIS CTF Finals 2016)](#burrows-wheeler-transform-inversion-without-terminator-asis-ctf-finals-2016)
- [OpenType Font Ligature Exploitation for Hidden Messages (Hack The Vote 2016)](#opentype-font-ligature-exploitation-for-hidden-messages-hack-the-vote-2016)
- [GLSL Shader VM with Self-Modifying Code (ApoorvCTF 2026)](#glsl-shader-vm-with-self-modifying-code-apoorvctf-2026)
- [Instruction Counter as Cryptographic State (MetaCTF Flash 2026)](#instruction-counter-as-cryptographic-state-metactf-flash-2026)
- [Thread Race Condition with Signed Integer Overflow (Codegate 2017)](#thread-race-condition-with-signed-integer-overflow-codegate-2017)
- [ESP32/Xtensa Firmware Reversing with ROM Symbol Map (Insomni'hack 2017)](#esp32xtensa-firmware-reversing-with-rom-symbol-map-insomnihack-2017)
- [Batch Crackme Automation via objdump Pattern Extraction (DEF CON 2017)](#batch-crackme-automation-via-objdump-pattern-extraction-def-con-2017)
- [Fork + Pipe + Dead Branch Anti-Analysis (RCTF 2017)](#fork--pipe--dead-branch-anti-analysis-rctf-2017)
- [Time-Locked Binary with Date-Based Key (Hack.lu 2017)](#time-locked-binary-with-date-based-key-hacklu-2017)
- [ARM Code in Image Pixels via UnicornJS (Hack.lu 2017)](#arm-code-in-image-pixels-via-unicornjs-hacklu-2017)
- [x86 16-bit MBR psadbw Constraint Solving (CSAW 2017)](#x86-16-bit-mbr-psadbw-constraint-solving-csaw-2017)
- [TensorFlow DNN Inversion by Inverting Sigmoid Layers (N1CTF 2018)](#tensorflow-dnn-inversion-by-inverting-sigmoid-layers-n1ctf-2018)
- [BPF Filter Analysis via JIT Compilation to x64 Assembly (Midnight Sun CTF 2018)](#bpf-filter-analysis-via-jit-compilation-to-x64-assembly-midnight-sun-ctf-2018)
- [Single-Byte XOR ROM Deobfuscation Sweep (X-MAS CTF 2018)](#single-byte-xor-rom-deobfuscation-sweep-x-mas-ctf-2018)
- [WebKit Array.slice OOB CVE-2016-4622 (Codegate 2019)](#webkit-arrayslice-oob-cve-2016-4622-codegate-2019)
- [Multi-Modulus CRT Keygen with Matrix Lookup Password (Pragyan CTF 2019)](#multi-modulus-crt-keygen-with-matrix-lookup-password-pragyan-ctf-2019)

---

## Z3 for Single-Line Python Boolean Circuit (BearCatCTF 2026)

**模式（Captain Morgan）：** 单行 Python（2000+ 个分号）通过 walrus operator 链把输入拆成大端整数，再用位运算构造布尔电路校验 flag。

**识别特征：**
- 单行 Python，语句由分号分隔
- walrus operator `:=` 链：`(x := expr)`
- 混淆版 XOR：`(x | i) & ~(x & i)`，而不是 `x ^ i`
- 输入被当成一个大整数，再通过位移拆分

**Z3 解法：**
```python
from z3 import *

n_bytes = 29  # Flag length
ari = BitVec('ari', n_bytes * 8)

# Parse semicolon-separated statements
# Model walrus chains as LShR(ari, shift_amount)
# Evaluate boolean expressions symbolically
# Final assertion: result_var == 0

s = Solver()
s.add(bfu == 0)  # Final validation variable
if s.check() == sat:
    m = s.model()
    val = m[ari].as_long()
    flag = val.to_bytes(n_bytes, 'big').decode('ascii')
```

**关键点：** 单行 Python 混淆本质是对输入位的布尔电路。walrus 链只是赋值语句，先按分号切开，再逐条翻译成 Z3。`(a | b) & ~(a & b)` 就是 `a ^ b`。这类电路通常能在一秒内解出。

**识别：** 单行 Python 带 1000+ 个分号、walrus 运算符、位运算，以及最终与 0 或 True 比较。

---

## Sliding Window Popcount Differential Propagation (BearCatCTF 2026)

**模式（Treasure Hunt 4）：** 二进制对输入 bit 流上的每个 16-bit 滑动窗口计算 popcount，并与期望值比较。

**差分传播：**
窗口右移 1 bit 时：
```text
popcount(window[i+1]) - popcount(window[i]) = bit[i+16] - bit[i]
```
因此：
`bit[i+16] = bit[i] + (data[i+1] - data[i])`

```python
expected = [...]  # 337 expected popcount values
total_bits = 337 + 15  # = 352

# Brute-force the initial 16-bit window (must have popcount = expected[0])
for start_val in range(0x10000):
    if bin(start_val).count('1') != expected[0]:
        continue

    bits = [0] * total_bits
    for j in range(16):
        bits[j] = (start_val >> (15 - j)) & 1

    valid = True
    for i in range(len(expected) - 1):
        new_bit = bits[i] + (expected[i + 1] - expected[i])
        if new_bit not in (0, 1):
            valid = False
            break
        bits[i + 16] = new_bit

    if valid:
        # Convert bits to bytes
        flag_bytes = bytes(int(''.join(map(str, bits[i:i+8])), 2)
                          for i in range(0, total_bits, 8))
        if b'BCCTF' in flag_bytes or flag_bytes[:5].isascii():
            print(flag_bytes.decode(errors='replace'))
            break
```

**关键点：** 滑动窗口 popcount 的差分会形成递推关系。除最初 16 位外，其余所有 bit 都被唯一确定。只需暴力初始 16 位窗口中满足首个 popcount 的候选即可，整体复杂度很低。

**识别：** 程序对固定窗口做 popcount/hamming weight。期望数组长度约为 `input_bits - window_size + 1`，数值落在 0 到窗口大小之间。

---

---

## Morse Code from Keyboard LEDs via ioctl (PlaidCTF 2013)

**模式：** 二进制通过 `ioctl(fd, KDSETLED, value)` 控制键盘 LED（Num/Caps/Scroll Lock）闪烁，时序编码为摩斯码。

```bash
# Step 1: Bypass ptrace anti-debug
# Patch ptrace call at offset with NOP (0x90)
python3 -c "
data = open('binary','rb').read()
data = data[:0x72b] + b'\x90'*5 + data[:0x730]  # NOP the ptrace call
open('patched','wb').write(data)
"

# Step 2: Run under strace, capture ioctl calls
strace -e ioctl ./patched 2>&1 | grep KDSETLED > leds.txt

# Step 3: Decode timing patterns
# Short blink (250ms) = dit (.), long blink (750ms) = dah (-)
# Inter-character pause = 3x, inter-word pause = 7x
```

```python
# Parse strace output to extract Morse
import re
morse_map = {'.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
             '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
             '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
             '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
             '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
             '--..':'Z', '-----':'0', '.----':'1'}
# Map LED on-durations to dots/dashes, group by pauses
```

**关键点：** `KDSETLED` 会控制 Linux 物理键盘灯。无需肉眼观察，只要用 `strace -e ioctl` 捕获 LED 状态变化，再按时间间隔解码点划即可。

---

## C++ Destructor-Hidden Validation (Defcamp 2015)

真实校验逻辑可能藏在 `main()` 退出后才执行的 C++ 析构函数中。`__cxa_atexit` 机制会注册这些析构回调：

1. **定位析构函数：** 搜索 `.init_array`/构造区中的 `__cxa_atexit` 调用
2. **静态分析：** 找到其全局对象，并分析析构函数是否执行 flag 校验
3. **动态验证：** 在 `__cxa_finalize` 下断，追踪 `main()` 之后的执行流

```asm
# In IDA/Ghidra: look for atexit registrations
__cxa_atexit(destructor_func, object_ptr, dso_handle);

# Destructor contains actual validation:
# - Regex pattern matching on 4-byte blocks (8 sequential checks)
# - Arithmetic: v2 += -3 * s[i] + 36 + (s[i] ^ 0x2FCFBA)
# - Modular verification of accumulated sum
```

**关键点：** 如果 `main()` 看起来很空或不完整，就去查全局/静态 C++ 对象的析构函数。`.fini_array` 与 `__cxa_atexit` 注册表往往会暴露隐藏的后置逻辑。

---

## Syscall Side-Effect Memory Corruption (Hack.lu 2015)

`rt_sigprocmask` syscall 会把一个 `sigset_t` 写到输出指针。当输入解析把这个指针构造到安全关键变量附近时，就可能发生意外内存破坏：

1. 某些输入字符（如 `:` 到 `@` 范围，`0x3A-0x40`）会触发 `rt_sigprocmask`
2. syscall 会把输出地址处的字节清零，可能覆盖相邻变量
3. 在小端布局中，若被清零的是相邻整数字段的高字节，就可能把它变成一个小值

```c
// Memory layout (no ASLR):
// 0x603390: input_buffer[4]
// 0x603394: security_check_var

// Input ':' triggers: rt_sigprocmask(SIG_BLOCK, NULL, (sigset_t*)0x603397, ...)
// This zeros bytes at 0x603397+, corrupting security_check_var's high bytes
```

**关键点：** 审计输入解析与 syscall 的交互。某些字符到 syscall 的映射在十六进制处理逻辑中很隐蔽，但最终会通过内核写输出缓冲区，形成意外内存改写。

---

## MFC Dialog Event Handler Location (WhiteHat 2015)

查找 MFC（Microsoft Foundation Class）应用中的事件处理函数，可按以下路径：

1. **断在 SendMessageW：** 对 `user32!SendMessageW` 下断，拦截对话框消息
2. **筛 WM_COMMAND：** 消息 ID `0x111` 代表按钮点击与控件事件
3. **跟踪消息映射：** 沿 `CWnd::OnWndMsg` → `CCmdTarget::OnCmdMsg` → 处理函数追踪
4. **关注 OnInitDialog：** 常在 `WM_INITDIALOG`（`0x110`）中完成解密或校验初始化

```asm
# WinDbg/x64dbg:
bp user32!SendMessageW ".if (poi(@esp+8)==0x111) {} .else {gc}"
# Or in IDA: find cross-references to AFX_MSGMAP_ENTRY structures
```

**关键点：** MFC 程序通过消息映射表派发事件。想快速枚举所有事件处理逻辑，可直接定位 `AFX_MSGMAP` 结构，而不是纯靠运行时点点点。

---

## VM Sequential Key-Chain Brute-Force (Midnight Flag 2026)

**模式（67）：** 自定义 VM 按 N 字节分块校验输入。每块输出的 key 会作为下一块输入的一部分，因此无法并行整题求解。但单块搜索空间足够小，可直接暴力（如 3 字节块对应 `2^24`）。

**识别特征：**
- 字节码 opcode 被常量 XOR 过，解开后看起来接近 ASCII
- 存在大量迭代变换（xorshift + multiply，重复 1000+ 次），使代数逆向不现实
- `CHECK` opcode 把累积状态与嵌入常量比较
- `.data` 区很大，且字节码模式重复

**求解流程：**
1. 解析字节码，提取每个块对应的 `CHECK` 值
2. 逐块暴力搜索产生该期望 key 的输入字节
3. 用当前块的 `CHECK` 结果作为下一块的 key

```c
// OpenMP-parallelized per-block brute-force
uint32_t process(uint32_t val) {
    for (int i = 0; i < 1000; i++) {
        val ^= (val << 13);
        val ^= (val >> 17);
        val ^= (val << 5);
        val *= 0x2545f491;
    }
    return val;
}

int solve_block(uint32_t old_key, uint32_t expected_key, unsigned char *out) {
    int found = 0;
    #pragma omp parallel for shared(found)
    for (int v = 0; v < 0x1000000; v++) {
        if (found) continue;
        uint32_t input_val = ((v >> 16) << 16) | (v & 0xFF) | ((v >> 8 & 0xFF) << 8);
        uint32_t saved = input_val ^ old_key;
        uint32_t final_val = process(saved);
        if ((final_val ^ saved) == expected_key) {
            #pragma omp critical
            { if (!found) { out[0]=v>>16; out[1]=(v>>8)&0xFF; out[2]=v&0xFF; found=1; } }
        }
    }
    return found;
}
// Compile: gcc -O3 -march=native -fopenmp -o solve solve.c
```

**关键点：** 当变换故意设计成难以解析逆向的迭代哈希样式函数时，暴力往往就是正解。OpenMP 并行非常关键。虽然块与块之间有顺序依赖，但每一块内部的搜索都高度可并行。

---

## Burrows-Wheeler Transform Inversion without Terminator (ASIS CTF Finals 2016)

对二进制表示执行 BWT，但没有标准终止符，因此无法直接按常规方法逆变换。

```python
def bwt_inverse_bruteforce(bwt_string):
    """Invert BWT when no terminating character is present.
    Standard BWT inverse needs the terminator position.
    Without it, try all n possible rotations."""
    n = len(bwt_string)

    # Standard BWT inverse produces a table
    table = [''] * n
    for _ in range(n):
        table = sorted([bwt_string[i] + table[i] for i in range(n)])

    # Without terminator, all n rows are valid candidates
    # Filter by known constraints (e.g., starts with '1' for binary, matches XOR pattern)
    candidates = []
    for row in table:
        # Apply challenge-specific validation
        if is_valid_plaintext(row):
            candidates.append(row)

    return candidates

def bwt_with_xor_rounds(encrypted_hex, num_rounds):
    """Multi-round BWT with XOR key derived from round index"""
    data = bytes.fromhex(encrypted_hex)
    for round_idx in range(num_rounds - 1, -1, -1):
        # Each round: BWT on binary representation, then XOR with round-based key
        binary_str = ''.join(format(b, '08b') for b in data)
        candidates = bwt_inverse_bruteforce(binary_str)
        # Select candidate matching constraints (leading '1', trailing bit rule)
        data = select_valid_candidate(candidates, round_idx)
    return data
```

**关键点：** 标准 BWT 依赖终止符（如 `$`）来指示原串位置。没有终止符时，逆变换会产出 `n` 个候选旋转。必须借助题目约束（如二进制格式、XOR 轮结构、flag 前缀）筛出正确候选。

---

## OpenType Font Ligature Exploitation for Hidden Messages (Hack The Vote 2016)

字体文件可通过 OpenType ligature 把可见字符序列映射为隐藏 glyph。其映射定义在 GSUB（Glyph Substitution）表中。

```python
from fontTools.ttLib import TTFont

def decode_font_ligatures(font_path, encoded_text):
    """Extract ligature substitution table and decode message"""
    font = TTFont(font_path)

    # Extract GSUB table for ligature substitutions
    gsub = font['GSUB']

    # Navigate to ligature lookup
    ligature_map = {}
    for lookup in gsub.table.LookupList.Lookup:
        for subtable in lookup.SubTable:
            if hasattr(subtable, 'ligatures'):
                for glyph_name, ligatures in subtable.ligatures.items():
                    for lig in ligatures:
                        # Map: input sequence -> output glyph
                        input_seq = [glyph_name] + lig.Component
                        output = lig.LigGlyph
                        ligature_map[tuple(input_seq)] = output

    print("Ligature mappings found:")
    for inp, out in ligature_map.items():
        print(f"  {inp} -> {out}")

    # Alternative: convert TTF to XML for manual analysis
    # font.saveXML('font_dump.xml')
    # Search for <LigatureSubst> entries

# Command-line approach:
# pip install fonttools
# ttx font.otf  # converts to XML
# grep -A5 'LigatureSubst' font.ttx
```

**关键点：** 自定义字体的 GSUB ligature 表可以形成一种“显示字符”和“实际 glyph”不同的替换密码。用 `fonttools` 的 `ttx` 把字体转成 XML 后，ligature 映射关系会变得非常直观。

---

## GLSL Shader VM with Self-Modifying Code (ApoorvCTF 2026)

**模式（Draw Me）：** 一个 WebGL2 fragment shader 在 256x256 RGBA 纹理上实现了图灵完备 VM。该纹理同时充当程序内存和显示输出。

**纹理布局：**
- **第 0 行：** 寄存器（像素 0 为指令指针，像素 1-32 为通用寄存器）
- **第 1-127 行：** 程序内存（RGBA = opcode, arg1, arg2, arg3）
- **第 128-255 行：** VRAM（显示输出）

**Opcodes：** NOP(0)、SET(1)、ADD(2)、SUB(3)、XOR(4)、JMP(5)、JNZ(6)、VRAM-write(7)、STORE(8)、LOAD(9)。每帧执行 16 步。

**自修改代码：** 第一阶段（解密）通过 STORE opcode 对程序内存做 XOR patch，第二阶段（绘制）再执行被修正后的代码。解密过程会把某些 SET 指令覆盖成正确像素颜色值。

**为什么 GPU 渲染会失败：** GPU 按像素并行执行，但每个像素每帧只能保留一个写目标。若同一帧存在多次 VRAM 写，通常只保留最后一次，导致 75% 以上像素丢失。STORE 补丁在并行执行下同样会互相覆盖。

**正确方法：顺序模拟**
```python
from PIL import Image
import numpy as np

img = Image.open('program.png').convert('RGBA')
state = np.array(img, dtype=np.int32).copy()
regs = [0] * 33

# Phase 1: Trace decryption — apply all STORE patches sequentially
x, y = start_x, start_y
while True:
    r, g, b, a = state[y][x]
    opcode = int(r)
    if opcode == 1: regs[g] = b & 255           # SET
    elif opcode == 4: regs[g] = regs[b] ^ regs[a]  # XOR
    elif opcode == 8:                              # STORE — patches program memory
        tx, ty = regs[g], regs[b]
        state[ty][tx] = [regs[a], regs[a+1], regs[a+2], regs[a+3]]
    elif opcode == 5: break                        # JMP to drawing phase
    x += 1
    if x > 255: x, y = 0, y + 1

# Phase 2: Execute drawing code — all VRAM writes preserved
vram = np.zeros((128, 256), dtype=np.uint8)
# ... trace with opcode 7 writing to vram[ty][tx] = color
Image.fromarray(vram, mode='L').save('output.png')
```

**关键点：** GLSL shader 虽然图灵完备，但 GPU 并行执行会带来写冲突。自修改代码会进一步放大这个问题。顺序模拟才能完整恢复补丁和最终输出。`program.png` 本身就是字节码。

**识别：** WebGL/shader 题附带一个 PNG“程序”文件，题面常提示“渲染不出来”或“输出是乱的”。GLSL 源里通常还能看到自定义 opcode 表。

---

## Instruction Counter as Cryptographic State (MetaCTF Flash 2026)

**模式（Who's Counting?）：** 手写汇编程序使用专门寄存器（如 `r12`）充当“指令计数器”，几乎每执行一条指令就递增一次。该计数器会参与对每个输入字节的 XOR、ROL 和乘法变换，因此整个变换路径取决于此前执行过多少条指令。

**识别特征：**
- 手写汇编，缺乏明显编译器模板
- 某个寄存器只增不减（`inc r12` 或 `add r12, 1`）
- 变换逻辑会引用该计数器（如 `xor rax, r12`、`rol al, cl` 且 `cl` 由计数器导出）
- 按字节顺序处理输入，并携带状态前进

**求解方式：**
```python
# Byte-by-byte brute force with emulation
# Since each byte's transformation depends on the counter (which depends
# on all prior instructions), state is path-dependent.

from unicorn import *
from unicorn.x86_const import *

def try_byte(known_prefix, candidate_byte):
    """Emulate binary with known prefix + candidate, check output."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # Map code, stack, data segments
    uc.mem_map(CODE_BASE, 0x10000)
    uc.mem_write(CODE_BASE, binary_code)
    uc.mem_map(STACK_BASE, 0x10000)
    uc.mem_map(DATA_BASE, 0x10000)

    # Write input: known_prefix + candidate
    test_input = known_prefix + bytes([candidate_byte])
    uc.mem_write(DATA_BASE, test_input + b'\x00' * (64 - len(test_input)))

    # Set up registers (rsp, rdi pointing to input, r12 = 0)
    uc.reg_write(UC_X86_REG_RSP, STACK_BASE + 0x8000)
    uc.reg_write(UC_X86_REG_R12, 0)  # instruction counter starts at 0

    try:
        uc.emu_start(CODE_BASE + ENTRY_OFFSET, CODE_BASE + EXIT_OFFSET)
        # Read transformed output, compare against expected
        output = uc.mem_read(OUTPUT_ADDR, len(test_input))
        return output[:len(test_input)] == expected[:len(test_input)]
    except:
        return False

# Recover flag byte by byte
flag = b''
for pos in range(FLAG_LEN):
    for b in range(256):
        if try_byte(flag, b):
            flag += bytes([b])
            print(f"Position {pos}: {chr(b)} -> {flag}")
            break
```

**关键点：** 当某个寄存器既充当指令计数器又参与字节变换时，第 N 个字节的输出依赖于前面所有字节导致的执行路径。理论逆向会非常脆弱，逐字节暴力 + 全模拟（Unicorn 或 GDB 脚本）通常是最稳妥的方案。

**识别：** 程序没有标准库调用、某些寄存器使用方式异常稳定、且存在只递增的寄存器。题名常暗示“counting”“instructions”等。

**替代方式：**
- GDB 脚本：在每个字节处理后下断，比较输出
- 静态分析：手工数指令推导计数器值，再代数求逆，但很容易出错

**参考：** MetaCTF Flash CTF 2026 "Who's Counting?"

---

## Thread Race Condition with Signed Integer Overflow (Codegate 2017)

**模式（Hunting）：** 游戏程序在线程不安全的技能选择逻辑中存在竞态。攻击线程先用有符号比较检查 `skill_id <= 4`，然后短暂休眠；此时切换到另一个技能。火球技能路径使用 `cdqe`（将 EAX 符号扩展到 RAX），会把 `0xFFFFFFFF`（icesword damage）变成有符号的 `-1`。对 boss HP（`0x7FFFFFFFFFFFFFFF`）执行 `boss_hp -= (-1)` 会发生有符号溢出，变为负数，从而直接击杀。

```python
# Race condition exploit:
# Thread A: select fireball (skill_id=2, passes <= 4 check)
# Thread A: sleeps for animation
# Main: switch to icesword (skill_id=5, damage=0xFFFFFFFF)
# Thread A: wakes, reads damage from icesword slot
# cdqe: 0xFFFFFFFF -> 0xFFFFFFFFFFFFFFFF (-1 signed)
# boss_hp -= (-1) -> boss_hp = 0x7FFFFFFFFFFFFFFF + 1 = negative -> dead

import time, threading
def race():
    select_skill(2)  # fireball - passes bounds check
    time.sleep(0.001)
    select_skill(5)  # icesword - race into damage calculation
```

**关键点：** `cdqe` 会把 32 位 EAX 有符号扩展到 64 位 RAX，因此 `0xFFFFFFFF` 会变成 `-1`。再配合竞态把本不该取到的伤害值引入计算路径，就能通过整数溢出直接击杀目标。

---

## ESP32/Xtensa Firmware Reversing with ROM Symbol Map (Insomni'hack 2017)

**模式（Internet of Fail）：** ESP32 固件（Xtensa 架构）在主流逆向工具中支持较差。可借助 ESP32 ROM linker script（`esp32.rom.ld`）把 ROM 函数地址映射为符号名，再配合公开 ESP32 HTTP 服务器源码快速定位逻辑。

```bash
# Load ESP32 firmware in radare2
r2 -a xtensa -b 32 firmware.bin

# Apply ROM symbol map from ESP-IDF
# esp32.rom.ld maps addresses like:
# 0x40000000 = ets_printf
# 0x400013A0 = cache_Read_Enable
# Load as flags: . esp32.rom.ld.r2

# Identify HTTP request handler by cross-referencing
# with esp-idf/examples/protocols/http_server
# Look for URI handler registration patterns
```

**关键点：** Xtensa 在主流 RE 工具中支持薄弱，但 ESP-IDF 自带的 ROM linker script 能直接恢复数百个 ROM 函数名。把它们导入 radare2 后，再对照 ESP-IDF 示例代码，往往能迅速识别 HTTP handler、WiFi callback 等应用层模式。

---

## Batch Crackme Automation via objdump Pattern Extraction (DEF CON 2017)

面对数百个结构一致的 crackme，可直接脚本化 `objdump` 输出，提取比较值和算术操作，无需真正执行样本。

```bash
# Simple variant: extract CMP immediates directly
objdump -M intel -d $binary | grep -P "cmp\s+rdi" | \
    grep -oP "0x\w{1,2}" | xxd -r -p

# Complex variant: parse add/sub/cmp chains and reverse-compute
# Each binary: series of add/sub rdi,N then cmp rdi,target
# Reverse: start from target, undo operations in reverse order
python3 <<'EOF'
import subprocess, re, glob
for binary in sorted(glob.glob("crackmes/*")):
    asm = subprocess.check_output(["objdump", "-M", "intel", "-d", binary]).decode()
    ops = re.findall(r'(add|sub)\s+rdi,(0x\w+)', asm)
    target = int(re.search(r'cmp\s+rdi,(0x\w+)', asm).group(1), 16)
    # Reverse operations
    for op, val in reversed(ops):
        val = int(val, 16)
        target = (target - val) if op == 'add' else (target + val)
    print(chr(target & 0xff), end='')
EOF
```

**关键点：** 批量 crackme 题通常共享同一模板，只有常量不同。直接脚本解析反汇编，提取立即数和算术链，再逆向回推 key，效率远高于逐个运行。

---

## Fork + Pipe + Dead Branch Anti-Analysis (RCTF 2017)

程序使用 fork/pipe IPC：父进程写数据后退出，子进程从管道读取并继续执行。真正的 key 校验逻辑藏在一个恒假的 dead branch 中，需要 patch 才能进入。

```bash
# Detection: fork() + pipe() + read()/write() in main
# The child process reads from pipe, needs to know its own PID

# Dead branch pattern:
# cmp DWORD PTR [ebp-0xc], 0x1  ; compares 0 with 1, always false
# je  real_flag_computation      ; never taken

# Patch: change comparison value from 0x1 to 0x0
# Find: 83 7d f4 01 → change to: 83 7d f4 00
python3 -c "
data = open('binary','rb').read()
data = data.replace(b'\x83\x7d\xf4\x01', b'\x83\x7d\xf4\x00')
open('binary_patched','wb').write(data)
"
```

**关键点：** `fork+pipe` 通常意味着父进程负责准备数据，子进程执行真正逻辑；而 dead branch 则用一个恒假条件把核心代码藏起来。`strace` 很适合先确认 fork/pipe/read 模式，再通过简单 patch 打开隐藏路径。

---

---

## Time-Locked Binary with Date-Based Key (Hack.lu 2017)

程序会读取系统日期，并且只在特定日期（例如 2012 年 12 月 21 日）上正常执行。日期常量通常以 Unix 时间戳或结构化日期比较形式出现在二进制中。

**识别：** 查找落在可疑日期范围内的大整数比较。Unix 时间戳中，2012 年约为 `1.35B`，2017 年约为 `1.5B`。文化意义日期（世界末日、比赛日期、历史事件）尤其值得优先尝试。

```bash
# Set system clock to the required date
sudo date -s "2012-12-21 00:00:00"
./binary

# Or use faketime to avoid system-wide change
LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="2012-12-21 00:00:00" ./binary

# Restore system time afterward
sudo ntpdate pool.ntp.org
```

**在 IDA/Ghidra 中：** 搜索 `time()` 或 `localtime()` 调用。重点关注 `struct tm` 中的 `tm_year`（自 1900 年起）、`tm_mon`（从 0 开始）、`tm_mday`。

**关键点：** 时间锁定题通常使用有文化意义的日期。发现日期比较后，先试修改系统时间或用 `faketime`，往往比继续深挖更省时间。

**参考：** Hack.lu CTF 2017

---

## ARM Code in Image Pixels via UnicornJS (Hack.lu 2017)

JavaScript 题将 ARM 字节码嵌入图像像素中。图像以 base64 存在于 HTML/JS 源里。像素 RGBA 值按顺序拼接即为 ARM 指令流。页面还引入 UnicornJS 库，在运行时提取并执行该字节码。

**识别流程：**
1. 在 JS 中找到 base64 blob，解码出 PNG/BMP
2. 识别 UnicornJS 导入（如 `unicorn.js`、`uc.js`），确定题目使用 ARM 模拟
3. 找到像素提取循环：RGBA 按光栅顺序拼成指令流
4. 将提取出的字节喂给 ARM 反汇编器

```python
from PIL import Image
import capstone

img = Image.open('decoded.png').convert('RGBA')
pixels = list(img.getdata())

# Extract ARM bytecode from pixel data (4 bytes per pixel: R, G, B, A)
arm_code = bytes([channel for pixel in pixels for channel in pixel])

# Disassemble as ARM Thumb or ARM32
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
for insn in md.disasm(arm_code, 0x0):
    print(f"0x{insn.address:04x}: {insn.mnemonic} {insn.op_str}")
```

**关键点：** 这是多层混淆：ARM 代码藏在图像像素中，图像再用 base64 包装，最后通过 UnicornJS 执行。优先识别模拟器库，才能快速确定应逆向哪种 ISA。

**参考：** Hack.lu CTF 2017

---

## x86 16-bit MBR psadbw Constraint Solving (CSAW 2017)

可启动 MBR 使用 SSE2 的 `psadbw` 指令在 xmm 寄存器上校验 flag。每轮会取 2 个输入字节，与常量做 `psadbw`，再比较结果和期望值。

**`psadbw` 语义：**
```asm
psadbw xmm0, xmm1
; For each of 8 byte pairs: sum += |xmm0[i] - xmm1[i]|
; Result stored as 16-bit integer in low qword of xmm0
```

这会产生绝对值和方程：
```text
|a[0] - k[0]| + |a[1] - k[1]| + ... + |a[7] - k[7]| = C
```

**求解方法：**
```python
import numpy as np
from itertools import product

# For each 2-byte masked group, extract the constants and expected sum
# Equations are not purely linear (absolute value), but printable ASCII
# constrains each byte to [0x20, 0x7e], limiting brute-force space

def solve_psadbw_group(known_constants, expected_sum, printable_range=(0x20, 0x7e)):
    """Brute-force 2 unknown bytes given sum-of-abs-diff constraint."""
    solutions = []
    for a, b in product(range(*printable_range), repeat=2):
        pair = [a, b]
        sad = sum(abs(pair[i] - known_constants[i]) for i in range(len(pair)))
        if sad == expected_sum:
            solutions.append(bytes([a, b]))
    return solutions

# For ambiguous cases with multiple solutions: apply additional constraints
# (flag format prefix, character frequency, subsequent iterations)
```

**关键点：** `psadbw` 生成的是绝对差之和约束，不是普通线性方程。但由于每组未知字节数量小、字符范围受限于可打印 ASCII，因此可以对每个独立小组直接暴力。

**参考：** CSAW CTF 2017

---

## TensorFlow DNN Inversion by Inverting Sigmoid Layers (N1CTF 2018)

**模式：** 二进制实现了一个 5 层深度神经网络，激活函数为 sigmoid。输入（flag 字符）先被变换为 `1.0/char_value` 再送入网络。提取权重和偏置后，可以逐层逆推：逆 sigmoid、减去偏置、乘以权重矩阵逆。

```python
import numpy as np

def sigmoid_inv(x):
    return -np.log(1.0/x - 1.0)

# Invert layer by layer from output to input
v = target_output
for i in range(num_layers - 1, -1, -1):
    v = np.dot(sigmoid_inv(v) - biases[i], np.linalg.inv(weights[i]))

# Input was 1.0/char, so flag chars are the multiplicative inverse
flag = ''.join(chr(int(round(1.0 / v[j]))) for j in range(len(v)))
```

**关键点：** 若神经网络的激活函数可逆（sigmoid、tanh），且权重矩阵是方阵，则整个网络也可逐层逆向。注意还要把输入预处理（这里是 `1/x`）一并逆回来。

**识别：** 程序内含 TensorFlow 或自实现 DNN，存在 sigmoid/tanh、矩阵乘法，以及 `.rodata` 中大量浮点数组（权重/偏置）。若矩阵维度为方阵，通常说明可逆。

**参考：** N1CTF 2018

---

## BPF Filter Analysis via JIT Compilation to x64 Assembly (Midnight Sun CTF 2018)

**模式：** 程序创建原始套接字并附加 BPF filter。若标准 BPF 反汇编器难以读懂，可启用内核 BPF JIT，把 BPF 字节码编译成原生 x64 汇编，再从 dmesg 中读取。

```bash
# Enable BPF JIT compilation
echo 1 > /proc/sys/net/core/bpf_jit_enable

# Run the binary, then read JIT-compiled BPF from kernel log
dmesg | grep -A 100 "flen="

# Analysis revealed: expects DNS TXT query on UDP port 3333
dig @target -p 3333 'M4d!bKn3~l' TXT
```

**关键点：** 当 BPF 字节码难以静态阅读时，直接看内核 JIT 生成的原生汇编通常更直观。凡涉及 `SO_ATTACH_FILTER`、原始 socket、`struct sock_fprog` 的题，都应想到这个技巧。

**识别：** 程序用 `setsockopt(... SO_ATTACH_FILTER ...)`、`socket(AF_PACKET, ...)`，或内嵌 `struct sock_filter` 数组（每项 8 字节：opcode、jt、jf、k）。

**参考：** Midnight Sun CTF 2018

---

## Single-Byte XOR ROM Deobfuscation Sweep (X-MAS CTF 2018)

**模式：** 大型 blob（GBA ROM、固件、游戏二进制）无法被 `binwalk`/`file` 识别。对全部 256 个单字节 XOR key 进行扫掠，再对输出重新执行 `file` 和 `strings`；正确 key 往往会露出可识别 magic。

```bash
for i in $(seq 0 255); do
  python3 -c "
import sys
k = $i
d = open('blob.bin','rb').read()
open(f'xor_{k}','wb').write(bytes(b^k for b in d))" 
  file "xor_$i" | grep -v data
done
strings "xor_0x42" | grep -i "POKEMON\|ELF\|MZ"
```

**关键点：** 256 个单字节 XOR key 的代价只有秒级，是遇到未知 blob 时的默认动作之一。优先寻找格式 magic（`ELF`、`PK`、`MZ`、`PDF-`）和 ROM 名称字符串。

**参考：** X-MAS CTF 2018 — Unown Gift, writeup 12665

---

## WebKit Array.slice OOB CVE-2016-4622 (Codegate 2019)

**模式：** 题目提供的 WebKit 源码中，`ArrayPrototype.cpp` 里 `Array.prototype.slice` 的边界检查 `isJSArray(thisObj) && length == toLength(...)` 被注释掉，导致越界读取相邻 JS 对象。再链上 Saelo 的 `addrof` / `fakeobj` 原语，可构造任意读写并进一步转入原生代码执行。

```javascript
let oob = new Array(8);
let victim = {a: 1};
let leak = oob.slice(-1, oob.length + 16)[0];  // reads past backing store
```

**关键点：** 任何浏览器/JIT 引擎题如果明显 patch 掉了安全检查，基本就是经典 CVE 原语。直接 diff 题目源码和上游的 `ArrayPrototype.cpp`、`JSArray.cpp`、`JITOperations.cpp`，优先找被删掉的 `if` 或 `assert`。

**参考：** Codegate CTF 2019 — Butterfree, writeup 12902

---

## Multi-Modulus CRT Keygen with Matrix Lookup Password (Pragyan CTF 2019)

**模式（Super Secure Vault）：** `main` 要求输入一个不超过 30 位的数字 `key`，并检查它是否满足由一个大数 `N = "27644437104591489104652716127"` 拆分出的五组模方程：

```
key mod 27644437 == 213
key mod 10459    == 229
key mod 1489     == 25
key mod 1046527  == 83
key mod 16127    == 135
```

这五个模数两两互素，因此可用中国剩余定理求出最小合法 `key = 3087629750608333480917556`。之后 `func2(password, key, N)` 会把 `key + N + "80"` 拼成 `v12`，再通过一个 10000 字节查表矩阵逐字节验证密码：

```python
# Round 1: index = 100*(10*d0 + d1) + 10*d_mid + d_mid+1
# Round 2: index = 100*((10*d0+d1)**2 % 97) + ((10*d_mid+d_mid+1)**2 % 97)
password = b""
v8, v10 = 0, len(v12) // 2
while v8 < len(v12) // 2:
    idx = 100 * (10*v12[v8] + v12[v8+1]) + 10*v12[v10] + v12[v10+1]
    password += bytes([matrix[idx]]); v8 += 2; v10 += 2
v9, v11 = 0, len(v12) // 2
while v9 < len(v12) // 2:
    a = 10*v12[v9] + v12[v9+1]; b = 10*v12[v11] + v12[v11+1]
    password += bytes([matrix[100*(a*a % 97) + b*b % 97]])
    v9 += 2; v11 += 2
```

使用 CRT（可借助 `sympy.ntheory.modular.crt` 或手写 `mul_inv`）和从二进制中导出的 `matrix`，即可恢复 flag `pctf{R3v3rS1Ng_#s_h311_L0t_Of_Fun}`。

**关键点：** 五个两两互素模数会把 key 唯一固定在模它们乘积的意义下，该乘积约 `4.7e19`，完全落在 30 位输入范围内。因此应直接取最小解，而不是做无意义的大范围枚举。第二阶段看似复杂，其实只是两套固定索引生成器访问静态表，表导出后就变成直接查表。

**参考：** Pragyan CTF 2019 — Super Secure Vault, writeup 13760

---

另见：[patterns-ctf.md](patterns-ctf.md) 的 Part 1，以及 [patterns-ctf-2.md](patterns-ctf-2.md) 的 Part 2（多层自解密二进制、内嵌 ZIP+XOR license、stack string 去混淆、prefix hash 爆破、CVP/LLL lattice、decision tree obfuscation、GF(2^8) Gaussian elimination）。
