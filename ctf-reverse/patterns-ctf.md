# CTF Reverse - 比赛特定模式（Part 1）

## Table of Contents
- [Hidden Emulator Opcodes + LD_PRELOAD Key Extraction (0xFun 2026)](#hidden-emulator-opcodes--ld_preload-key-extraction-0xfun-2026)
- [Spectre-RSB SPN Cipher — Static Parameter Extraction (0xFun 2026)](#spectre-rsb-spn-cipher--static-parameter-extraction-0xfun-2026)
- [Image XOR Mask Recovery via Smoothness (VuwCTF 2025)](#image-xor-mask-recovery-via-smoothness-vuwctf-2025)
- [Shellcode in Data Section via mmap RWX (VuwCTF 2025)](#shellcode-in-data-section-via-mmap-rwx-vuwctf-2025)
- [Recursive execve Subtraction (VuwCTF 2025)](#recursive-execve-subtraction-vuwctf-2025)
- [Byte-at-a-Time Block Cipher Attack (UTCTF 2024)](#byte-at-a-time-block-cipher-attack-utctf-2024)
- [Mathematical Convergence Bitmap (EHAX 2026)](#mathematical-convergence-bitmap-ehax-2026)
- [Windows PE XOR Bitmap Extraction + OCR (srdnlenCTF 2026)](#windows-pe-xor-bitmap-extraction--ocr-srdnlenctf-2026)
- [Two-Stage Loader: RC4 Gate + VM Constraints (srdnlenCTF 2026)](#two-stage-loader-rc4-gate--vm-constraints-srdnlenctf-2026)
- [GBA ROM VM Hash Inversion via Meet-in-the-Middle (srdnlenCTF 2026)](#gba-rom-vm-hash-inversion-via-meet-in-the-middle-srdnlenctf-2026)
- [Sprague-Grundy Game Theory Binary (DiceCTF 2026)](#sprague-grundy-game-theory-binary-dicectf-2026)
- [Kernel Module Maze Solving (DiceCTF 2026)](#kernel-module-maze-solving-dicectf-2026)
- [Multi-Threaded VM with Channel Synchronization (DiceCTF 2026)](#multi-threaded-vm-with-channel-synchronization-dicectf-2026)
- [Backdoored Shared Library Detection via String Diffing (Hack.lu CTF 2012)](#backdoored-shared-library-detection-via-string-diffing-hacklu-ctf-2012)
- [Custom binfmt Kernel Module with RC4 Flat Binaries (BSidesSF 2026)](#custom-binfmt-kernel-module-with-rc4-flat-binaries-bsidessf-2026)
- [Hash-Resolved Imports / No-Import Ransomware (BSidesSF 2026)](#hash-resolved-imports--no-import-ransomware-bsidessf-2026)
- [ELF Section Header Corruption for Anti-Analysis (BSidesSF 2026)](#elf-section-header-corruption-for-anti-analysis-bsidessf-2026)
- [VM Trace Diffing Instead of Full Disassembly (CONFidence CTF 2019 Teaser)](#vm-trace-diffing-instead-of-full-disassembly-confidence-ctf-2019-teaser)

---

## Hidden Emulator Opcodes + LD_PRELOAD Key Extraction (0xFun 2026)

**模式（CHIP-8）：** 非标准 opcode `FxFF` 会触发隐藏的 `superChipRendrer()`，进而执行 AES-256-CBC 解密。密钥由二进制中的常量导出。

**技巧：**
1. 检查所有指令分发分支，寻找非标准 opcode
2. 隐藏 opcode 可能会触发密码学函数（OpenSSL）
3. 用 `LD_PRELOAD` hook `EVP_DecryptInit_ex`，在运行时捕获 AES key：

```c
#include <openssl/evp.h>
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv) {
    // Log key
    for (int i = 0; i < 32; i++) printf("%02x", key[i]);
    printf("\n");
    // Call original
    return ((typeof(EVP_DecryptInit_ex)*)dlsym(RTLD_NEXT, "EVP_DecryptInit_ex"))
           (ctx, type, impl, key, iv);
}
```

```bash
gcc -shared -fPIC -ldl -lssl hook.c -o hook.so
LD_PRELOAD=./hook.so ./emulator rom.ch8
```

---

## Spectre-RSB SPN Cipher — Static Parameter Extraction (0xFun 2026)

**模式：** 二进制利用 cache side channel 实现 S-box，但所有密码参数（轮密钥、S-box 表、置换）都直接放在数据段里。

**关键点：** 不要试图在特殊硬件上运行。直接静态提取参数：
- 8 个 S-box，每个 8 个输出 bit，每个 256 项
- 值 `0x340` 表示 bit 1，`0x100` 表示 bit 0
- 64 字节置换表、8 个轮密钥

```python
# Extract from binary data section
import struct
sbox = [[0]*256 for _ in range(8)]
for i in range(8):
    for j in range(256):
        val = struct.unpack('<I', data[sbox_offset + (i*256+j)*4 : ...])[0]
        sbox[i][j] = 1 if val == 0x340 else 0
```

**结论：** 侧信道实现通常仍会把查找表嵌入内存，直接静态提取即可。

---

## Image XOR Mask Recovery via Smoothness (VuwCTF 2025)

**模式（Trianglification）：** 图像被划分成三角区域，每个区域分别用 `key = (mask * x - y) & 0xFF` 做 XOR 加密，其中 mask 未知（0-255）。

**恢复方法：** 自然图像通常具有平滑梯度。对每个区域暴力枚举 mask（每区 256 个值），用相邻像素差评分：

```python
import numpy as np
from PIL import Image

img = np.array(Image.open('encrypted.png'))

def score_smoothness(region_pixels, mask, positions):
    decrypted = []
    for (x, y), pixel in zip(positions, region_pixels):
        key = (mask * x - y) & 0xFF
        decrypted.append(pixel ^ key)
    # Score: sum of absolute differences between adjacent pixels
    return -sum(abs(decrypted[i] - decrypted[i+1]) for i in range(len(decrypted)-1))

for region in regions:
    best_mask = max(range(256), key=lambda m: score_smoothness(region, m, positions))
```

**搜索空间：** 256 个候选 × N 个区域，复杂度很低。对自然图像，平滑度是可靠评分指标。

---

## Shellcode in Data Section via mmap RWX (VuwCTF 2025)

**模式（Missing Function）：** 二进制把数据段搬运到 RWX 内存（`mmap` 使用 `PROT_READ|PROT_WRITE|PROT_EXEC`），然后跳转过去执行。

**检测：** 查找带 `PROT_EXEC` 标志的 `mmap`。嵌入式 shellcode 常见是用循环 key 做 XOR。

**分析：** 提取数据段，尝试 XOR key（可先试 3 字节循环），再对结果反汇编。

---

## Recursive execve Subtraction (VuwCTF 2025)

**模式（String Inspector）：** 二进制通过 `execve` 递归调用自身，每次减去若干常量。

**解法：** 找到递归终止条件并倒推。常会出现形如 `N * M + remainder` 的数学关系。

---

## Byte-at-a-Time Block Cipher Attack (UTCTF 2024)

**模式（PES-128）：** 第一字节输出只取决于第一字节输入，不存在扩散。

**攻击：** 对每个位置，枚举全部 256 个字节值，将该位置输出字节与目标密文对应字节比较。每个位置只有一个匹配值，因此无需密钥即可逐字节恢复明文。

**识别：** 改变一个输入字节，只影响对应输出字节。这说明没有跨字节扩散，算法可被直接拆解。

---

## Mathematical Convergence Bitmap (EHAX 2026)

**模式（Compute It）：** 二进制用牛顿法判断复平面坐标是否收敛，分类结果按网格排布后形成 ASCII 艺术字 flag。

**识别特征：**
- 输入文件包含坐标对 `(x, y)`
- 二进制迭代某个数学函数（如 `z^3 - 1 = 0`），输出通过/失败
- 点数暗示网格尺寸（例如 2600 = 130×20）
- CTF 常见 5 像素高 ASCII 艺术字

**用于 `z^3 - 1` 的牛顿法：**
```python
def newton_converges_to_one(px, py, max_iter=50, target_count=12):
    """Returns True if Newton's method converges to z=1 in exactly target_count steps."""
    x, y = px, py
    count = 0
    for _ in range(max_iter):
        f_real = x**3 - 3*x*y**2 - 1.0
        f_imag = 3*x**2*y - y**3
        J_rr = 3.0 * (x**2 - y**2)
        J_ri = 6.0 * x * y
        det = J_rr**2 + J_ri**2
        if det < 1e-9:
            break
        x -= (f_real * J_rr + f_imag * J_ri) / det
        y -= (f_imag * J_rr - f_real * J_ri) / det
        count += 1
        if abs(x - 1.0) < 1e-6 and abs(y) < 1e-6:
            break
    return count == target_count

# Read coordinates and render bitmap
points = [(float(x), float(y)) for x, y in ...]
bits = [1 if newton_converges_to_one(px, py) else 0 for px, py in points]
WIDTH = 130  # 2600 / 20 rows
for r in range(len(bits) // WIDTH):
    print(''.join('#' if bits[r*WIDTH+c] else '.' for c in range(WIDTH)))
```

**关键点：** 这类二进制不是 flag checker，而是数学分类器。flag 藏在分类结果形成的图案中，而不是程序直接输出里。逆出数学模型，对所有坐标跑一遍并可视化即可。

---

## Windows PE XOR Bitmap Extraction + OCR (srdnlenCTF 2026)

**模式（Artistic Warmup）：** 程序把输入文本渲染成位图，并与 `.rdata` 中按常量 XOR 存储的期望像素比较。无需理解渲染逻辑，直接提取期望像素即可。

**攻击步骤：**
1. 逆向核心校验函数，确定渲染与比较逻辑
2. 在 `.rdata` 中定位期望像素 blob（通常是比较附近引用的大块数据）
3. 与常量（如 `0xAA`）XOR，恢复目标 DIB
4. 保存成图像并用 OCR 还原 flag 文本

```python
import numpy as np
from PIL import Image

with open("binary.exe", "rb") as f:
    data = f.read()

# Extract from .rdata section (offsets from reversing)
blob_offset = 0xC3620  # .rdata offset to XOR'd blob
blob_size = 0x15F90     # 450 * 50 * 4 (BGRA)
blob = np.frombuffer(data[blob_offset:blob_offset + blob_size], dtype=np.uint8)
expected = blob ^ 0xAA  # XOR with constant key

# Reshape as BGRA image (dimensions from reversing)
img = expected.reshape(50, 450, 4)
channel = img[:, :, 0]  # Take one channel (grayscale text)
Image.fromarray(channel, "L").save("target.png")

# OCR with charset whitelist
import subprocess
result = subprocess.run(
    ["tesseract", "target.png", "stdout", "-c",
     "tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"],
    capture_output=True, text=True)
print(result.stdout)
```

**关键点：** 当二进制把文本渲染后做像素比对时，期望像素本身就是以图像形式存在的 flag。直接从数据段提取，不必深挖渲染细节。使用字符白名单可提升 OCR 对 CTF flag 字符的识别率。

---

## Two-Stage Loader: RC4 Gate + VM Constraints (srdnlenCTF 2026)

**模式（Cornflake v3.5）：** 两阶段恶意加载器。第一阶段用 RC4 校验用户名，第二阶段从 C2 下载并通过 VM 校验密码。

**Stage 1 — RC4 username recovery:**
```python
def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

# Key from binary strings, ciphertext from stored hex
username = rc4(b"s3cr3t_k3y_v1", bytes.fromhex("46f5289437bc009c17817e997ae82bfbd065545d"))
```

**Stage 2 — VM constraint extraction:**
1. 从 C2 端点下载第二阶段（如 `/updates/check.php`）
2. 逆向 VM 字节码解释器（通常 15-20 个 opcode）
3. 提取关于 flag 字符的线性等式约束
4. 解该约束系统（Z3 或手算）

**关键点：** 多阶段加载器常见结构是：第一关用简单密码学（RC4），第二关用更复杂的自定义 VM。若 VM 内存未初始化且始终为 0，很多依赖内存的运算会退化成常量，约束提取将大幅简化。

---

## GBA ROM VM Hash Inversion via Meet-in-the-Middle (srdnlenCTF 2026)

**模式（Dante's Trial）：** GBA ROM 实现自定义 VM。哈希函数是 FNV-1a 变体，且未初始化内存始终为 0。使用 meet-in-the-middle 可拆分搜索空间。

**哈希结构：**
```python
# FNV-1a variant with XOR/multiply
P = 0x100000001b3        # FNV prime
CUP = 0x9e3779b185ebca87  # Golden ratio constant
MASK64 = (1 << 64) - 1

def fmix64(h):
    """Finalization mixer."""
    h ^= h >> 33; h = (h * 0xff51afd7ed558ccd) & MASK64
    h ^= h >> 33; h = (h * 0xc4ceb9fe1a85ec53) & MASK64
    h ^= h >> 33
    return h

def hash_input(chars, seed_lo=0x84222325, seed_hi=0xcbf29ce4):
    hlo, hhi, ptr = seed_lo, seed_hi, 0
    for c in chars:
        # tri_mix(c, mem[ptr]) — mem is always 0
        delta = ((ord(c) * CUP) ^ (0 * P)) & MASK64
        hlo = ((hlo ^ (delta & 0xFFFFFFFF)) * (P & 0xFFFFFFFF)) & 0xFFFFFFFF
        hhi = ((hhi ^ (delta >> 32)) * (P >> 32)) & 0xFFFFFFFF
        ptr = (ptr + 1) & 0xFF
    combined = ((hhi << 32) | (hlo ^ ptr)) & MASK64
    return fmix64((combined * P) & MASK64)
```

**Meet-in-the-middle attack:**
```python
import string

TARGET = 0x73f3ebcbd9b4cd93
LENGTH = 6
SPLIT = 3
charset = [c for c in string.printable if 32 <= ord(c) < 127]

# Forward pass: enumerate first 3 characters from seed state
forward = {}
for c1 in charset:
    for c2 in charset:
        for c3 in charset:
            state = hash_forward(seed, [c1, c2, c3])
            forward[state] = c1 + c2 + c3

# Backward pass: invert fmix64 and final multiply, enumerate last 3 chars
inv_target = invert_fmix64(TARGET)
for c4 in charset:
    for c5 in charset:
        for c6 in charset:
            state = hash_backward(inv_target, [c4, c5, c6])
            if state in forward:
                print(f"Found: {forward[state]}{c4}{c5}{c6}")
```

**关键点：** meet-in-the-middle 能把搜索量从 `95^6 ≈ 7.4×10^11` 降到 `2×95^3 ≈ 1.7×10^6`，速度提升约 43 万倍。前提是哈希从输出侧可逆（`fmix64` 和最终乘法都能逆）。另外，始终为 0 的未初始化 VM 内存会去掉一个变量，使哈希更容易逆。

---

## Sprague-Grundy Game Theory Binary (DiceCTF 2026)

**模式（Bedtime）：** 去符号 Rust 二进制执行 N 轮有界 Nim。每轮包含若干堆和最大取子数 `k`。若当前局面为必败态，程序使用 PRNG 行动；玩家需最优回应，使 PRNG 最终生成非法动作并返回 1。所有轮次返回值之和需等于目标。

**博弈识别：**
- 有界 Nim：每回合从任意一堆取 1 到 `k` 个
- 每堆 **Grundy 值**：`pile_value % (k+1)`
- 全部 Grundy 值 **异或**：非零为必胜态（N-position），零为必败态（P-position）
- N-position：电脑必胜，返回 0
- P-position：电脑使用 PRNG，可能生成非法动作，返回 1

**通过用户反馈追踪 PRNG 状态：**
```python
MASK64 = (1 << 64) - 1

def prng_step(state, pile_count, k):
    """Computer's PRNG move. Returns (pile_idx, amount, new_state)."""
    r12 = state[2] ^ 0x28027f28b04ccfa7
    rax = (state[1] + r12) & MASK64
    s0_new = ROL64((state[0] ** 2 + rax) & MASK64, 32)
    r12_upd = (r12 + rax) & MASK64
    s0_final = ROL64((s0_new ** 2 + r12_upd) & MASK64, 32)

    pile_idx = rax % pile_count
    amount = (r12_upd % k) + 1
    return pile_idx, amount, [s0_final, r12_upd, state[2]]

# Critical: state[2] updated ONLY by user moves (XOR of pile_idx, amount, new_value)
# PRNG moves do NOT affect state[2] — creates feedback loop
```

**求解流程：**
1. 用 GDB 导出游戏数据（所有堆值与参数）
2. 分类统计：P-position（返回 1）与 N-position（返回 0）
3. 模拟每个 P-position：PRNG 动作 → 用户最优回应 → 追踪 `state[2]`
4. 按程序输入格式编码用户动作（如倒序 4 位十进制对）

**关键点：** 当博弈题中的 PRNG 状态依赖用户输入时，必须模拟完整反馈回路，而不是只做博弈论求解。用 GDB 硬件监视点识别哪些状态变量由用户动作更新、哪些由电脑动作更新。

---

## Kernel Module Maze Solving (DiceCTF 2026)

**模式（Explorer）：** Rust 内核模块通过 `/dev/challenge` 的 ioctl 实现三维迷宫。需导航迷宫、避开假出口（status=2）、找到真出口（status=1），再读取 flag。

**Ioctl 枚举：**
| Command | Description |
|---------|-------------|
| `0x80046481-83` | 获取迷宫三轴尺寸（每轴 8-16） |
| `0x80046485` | 获取状态：0=进行中，1=胜利，2=假出口 |
| `0x80046486` | 获取墙体 bitfield（6 个方向） |
| `0x80406487` | 获取 flag（64 字节，仅 status=1 时可读） |
| `0x40046488` | 朝某方向移动（0-5） |
| `0x6489` | 重置位置 |

**带假出口规避的 DFS 求解器：**
```c
// Minimal static binary using raw syscalls (no libc) for small upload size
// gcc -nostdlib -static -Os -fno-builtin -o solve solve.c -Wl,--gc-sections && strip solve

int visited[16][16][16];
int bad[16][16][16];   // decoy positions across resets

void dfs(int fd, int x, int y, int z) {
    if (visited[x][y][z] || bad[x][y][z]) return;
    visited[x][y][z] = 1;

    int status = ioctl_get_status(fd);
    if (status == 1) { read_flag(fd); exit(0); }
    if (status == 2) { bad[x][y][z] = 1; return; }  // decoy — mark bad

    int walls = ioctl_get_walls(fd);
    int dx[] = {1,-1,0,0,0,0}, dy[] = {0,0,1,-1,0,0}, dz[] = {0,0,0,0,1,-1};
    int opp[] = {2,3,0,1,5,4};  // opposite directions for backtracking

    for (int dir = 0; dir < 6; dir++) {
        if (!(walls & (1 << dir))) continue;  // wall present
        ioctl_move(fd, dir);
        dfs(fd, x+dx[dir], y+dy[dir], z+dz[dir]);
        ioctl_move(fd, opp[dir]);  // backtrack
    }
}
// After decoy hit: reset via ioctl 0x6489, clear visited, re-run DFS
```

**远程部署：** 通过 netcat shell 分段上传 base64 编码二进制，解码后执行。

**关键点：** 内核模块题里，把测试二进制注入 initramfs 并动态探测 ioctl，通常比静态逆向 stripped 内核模块更快。求解器尽量做小（原始 syscall、无 libc），方便上传。

---

## Multi-Threaded VM with Channel Synchronization (DiceCTF 2026)

**模式（locked-in）：** 自定义栈 VM 启动 16 个并发线程校验 30 字符 flag。线程之间通过基于 futex 的 channel 通信。整体流程为：输入 → XOR scramble → 变换 → 四进制状态机 → 最终校验。

**分析思路：**
1. 通过 GDB 追踪 channel 读写模式，识别**线程角色**
2. 通过在特定 opcode 上断点，提取常量（XOR scramble 值、查表）
3. 警惕**逻辑取反**：有效时返回 0，无效时非零
4. 关注 futex 副作用：对未持有的 mutex 执行 `unlock_pi` 会返回 `EPERM=1`，可能参与计算

**受限状态机的 BFS 搜索：**
```python
from collections import deque

def solve_flag(scramble_vals, lookup_table, initial_state, target_state):
    """BFS through state machine to find valid flag bytes."""
    flag = [None] * 30
    # Known prefix/suffix from flag format
    flag[0:5] = list(b'dice{')
    flag[29] = ord('}')

    # For each unknown position, try all printable ASCII
    states = {initial_state}
    for pos in range(28, 4, -1):  # processed in reverse
        next_states = {}
        for state in states:
            for ch in range(32, 127):
                transformed = transform(ch, scramble_vals[pos])
                digits = to_base4(transformed)
                new_state = apply_digits(state, digits, lookup_table)
                if new_state is not None:  # valid path exists
                    next_states.setdefault(new_state, []).append((state, ch))
        states = set(next_states.keys())

    # Trace back from target_state to recover flag
```

**关键点：** 多线程 VM 的关键不是单线程逻辑，而是跨线程数据流。channel 通信天然形成 pipeline，应先识别每个线程的职责（输入、变换、校验、输出）。影响计算的常量也可能来自意料之外的位置，如 futex 返回值、线程 ID 等。

---

## Backdoored Shared Library Detection via String Diffing (Hack.lu CTF 2012)

**模式（Zombie Lockbox）：** 一个 setuid 程序使用 `strcmp` 校验密码。预期密码可通过 `strings` 看到，在 GDB 下也能通过，但正常运行时失败。原因是它链接了一个非标准 libc，会依据 suid 状态篡改函数行为。

**检测步骤：**
1. 用 `ldd` 检查是否存在异常库路径：
```bash
ldd ./binary
# Suspicious: libc.so.6 => /lib/libc/libc.so.6  (non-standard path)
# Normal:    libc.so.6 => /lib32/libc.so.6
```

2. 比较可疑 libc 与系统 libc 的字符串：
```bash
strings /lib/libc/libc.so.6 > suspicious_strings
strings /lib32/libc-2.15.so > normal_strings
diff suspicious_strings normal_strings
```

3. 反汇编被 patch 的函数（如 `puts`），定位注入逻辑：
```bash
gdb /lib/libc/libc.so.6
(gdb) disas puts
# Look for unexpected calls or branches
# Injected code may check suid status (getuid/geteuid syscalls)
# and swap the expected password at runtime
```

**关键点：** 当程序在 GDB 下和正常运行时行为不同，应先查 `ldd` 是否使用了非标准库路径。suid 程序在调试器下会降权，因此被植入后门的 libc 可以通过 `getuid`/`geteuid` 检测并改变行为。`strings | diff` 往往能快速暴露注入数据。

---

---

## Custom binfmt Kernel Module with RC4 Flat Binaries (BSidesSF 2026)

**模式（Private Binary）：** 自定义 Linux 内核模块（`.ko`）注册了一个 `binfmt` 处理器。执行带特定 magic 的文件时，内核模块会拦截、在内存中解密文件内容，再跳到入口点。

**逆向方法：**
1. **分析 `.ko`：** 查找 `register_binfmt()` 调用，它会注册一个带 `load_binary` 回调的 `struct linux_binfmt`
2. **找 magic number：** `load_binary` 会检查文件头几个字节
3. **提取加密 key：** 重点找 `movabs` 加载的 8 字节常量，常作为 RC4 key 字节
4. **识别加密方案：** 常见为 RC4、XOR、AES-ECB。RC4 可由 S-box 初始化循环识别（256 字节数组 + swap 模式）
5. **解密 flat binary：** 对去掉头部后的加密内容应用恢复出的 key

```python
from Crypto.Cipher import ARC4

# Extract RC4 key from kernel module (found via movabs instructions)
key = bytes([0x41, 0x42, 0x43, ...])  # Key bytes from .ko disassembly

with open('encrypted.bin', 'rb') as f:
    header = f.read(HEADER_SIZE)  # Skip binfmt header
    encrypted = f.read()

cipher = ARC4.new(key)
decrypted = cipher.decrypt(encrypted)

# The decrypted output is a flat binary (no ELF headers)
# Load at the fixed virtual address specified in the kernel module
# Disassemble with: objdump -b binary -m i386:x86-64 -D decrypted.bin
# Or in Ghidra: import as "Raw Binary", set base address from .ko
```

**内核模块中的识别点：**
- `register_binfmt` / `unregister_binfmt`
- 用 `vm_mmap()` 或 `vm_brk()` 在固定地址分配内存
- 直接跳到映射内存执行
- RC4 的 S-box 初始化模式：0-255 循环、交换 `S[i]` 与 `S[j]`

**关键点：** flat binary 没有 ELF 头，常规工具不会识别。必须从内核模块中提取装载地址（通常在 `vm_mmap` 调用参数里），再按该基址导入解密后的 blob。RC4 key 常以内联立即数形式出现在 `mov`/`movabs` 指令中，而不在数据段里。

**参考：** BSidesSF 2026 "Private Binary"

---

## Hash-Resolved Imports / No-Import Ransomware (BSidesSF 2026)

**模式（Ran Somewhere）：** 恶意样本几乎没有可见导入，所有 API 都在运行时通过符号名哈希解析。程序用 `dlopen` + 自定义哈希表解析 libc 和 libcrypto 函数。

**识别特征：**
- `readelf -d` 看不到动态符号，或只剩少量（如 `dlopen`/`dlsym`）
- strings 中没有标准 API 名
- 反汇编可见哈希循环后接间接调用
- 存在 RC4 加密的内嵌字符串（RSA 公钥、路径、口令等）

**分析捷径：用 LD_PRELOAD 提取密钥**

与其逆完整个哈希解析和密钥导出，不如直接 hook 最终调用到的密码学函数：

```c
// hook_crypto.c — captures AES key used by the ransomware
#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/evp.h>
#include <stdio.h>

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv) {
    if (key) {
        FILE *f = fopen("/tmp/aes_key.bin", "wb");
        fwrite(key, 1, 32, f);  // AES-256
        fclose(f);
        fprintf(stderr, "[HOOK] AES key captured\n");
    }
    typedef int (*orig_t)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*,
                          const unsigned char*, const unsigned char*);
    orig_t orig = (orig_t)dlsym(RTLD_NEXT, "EVP_CipherInit_ex");
    return orig(ctx, type, impl, key, iv);
}
```

```bash
# Compile and run
gcc -shared -fPIC -o hook.so hook_crypto.c -ldl
# Run in Docker container (ransomware may be destructive!)
docker run --rm -v $(pwd):/work -w /work ubuntu:22.04 \
  bash -c "LD_PRELOAD=./hook.so ./ransomware; xxd /tmp/aes_key.bin"
```

**哈希解析常见模式：**
- **SipHash 变体：** 两个 64 位 seed，按符号名字节迭代混合
- **DJB2/FNV 变体：** 常量特征明显，如 `5381`、`0xcbf29ce484222325`
- **ROR13：** Windows 恶意样本常见，`hash = (hash >> 13) | (hash << 19); hash += c`

**捕获密钥后的解密：**
```python
from Crypto.Cipher import AES

key = open('/tmp/aes_key.bin', 'rb').read()
iv = open('/tmp/aes_iv.bin', 'rb').read()  # Also hookable
cipher = AES.new(key, AES.MODE_CBC, iv)

with open('flag.txt.enc', 'rb') as f:
    ct = f.read()
pt = cipher.decrypt(ct)
# Remove PKCS7 padding
pt = pt[:-pt[-1]]
print(pt.decode())
```

**关键点：** 当样本用哈希解析全部导入时，没必要浪费时间去还原哈希函数和构造 rainbow table。直接在沙箱环境中运行，让它自己解析，再用 `LD_PRELOAD` hook 你关心的函数（OpenSSL、文件 I/O、网络调用）。若 AES key 在一次运行中有效，通常之后也始终有效。

**安全：** 疑似勒索软件必须在 Docker 或虚拟机中运行。只挂载加密文件副本，不要挂原件。

**参考：** BSidesSF 2026 "Ran Somewhere"

---

## ELF Section Header Corruption for Anti-Analysis (BSidesSF 2026)

**模式（stubborn-elf）：** ELF 的 section header table 被故意破坏，导致 `readelf`、`objdump`、IDA、Ghidra 等分析工具崩溃或报错。但操作系统实际使用的 **program header** 仍然正常，因此程序可以正常执行。flag 被附加在损坏 section 之后，并带有 magic 标记。

```python
import sys

# Standard tools fail on corrupted section headers
# Manual parsing bypasses section headers entirely

with open("stubborn_elf", "rb") as f:
    data = f.read()

# Search for magic marker appended after ELF sections
magic = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
idx = data.find(magic)
if idx >= 0:
    # Data after magic is XOR-encrypted
    encrypted = data[idx + len(magic):]
    decrypted = bytes(b ^ 0x42 for b in encrypted)
    print(decrypted.decode(errors='ignore'))
```

**关键点：** ELF 运行时真正需要的是 **program header**（PT_LOAD 段），而不是 section header。section header 只是给调试器和分析工具用的元数据。破坏 `e_shoff`、`e_shnum`、`e_shstrndx` 会搞崩工具，但不影响执行。遇到这种情况，应手动解析文件，或先 patch ELF header 把 section table 引用清零，再导入反汇编器。

**恢复方式：**
```bash
# Patch section header offset to 0 (removes section table)
printf '\x00\x00\x00\x00\x00\x00\x00\x00' | dd of=binary bs=1 seek=40 conv=notrunc
# Now Ghidra/IDA can load it using program headers only

# Or use readelf -l (program headers only, ignores sections)
readelf -l stubborn_elf
```

**识别时机：** `readelf -S` 崩溃或输出垃圾，但 `file` 仍识别为 ELF，`readelf -l` 却能正常工作，且程序能运行。

**参考：** BSidesSF 2026 "stubborn-elf"

---

## VM Trace Diffing Instead of Full Disassembly (CONFidence CTF 2019 Teaser)

**模式（Go Machine）：** Go 二进制运行一个 15-handler 栈 VM（dispatch 字符串为 `0123456789OEQLCI`），其 opcode 语义会在每个 tick 后由 LCG 驱动的 `shuffle` handler 重新排列。完整复现解释器很痛苦，但 VM 实际上只是对每组 4 字符输入计算一个简单的 32 位哈希。

更好的方式是：对 dispatch 例程挂调试器驱动的 tracer，每步导出 `(opcode, stack)`，然后比较两个几乎相同输入的 trace：

```python
# Pseudo-code for an IDAPython / gdb conditional-breakpoint tracer
def on_dispatch():
    op  = read_byte(bytecode + pc)
    top = stack[:sp+1]
    print(f"{decode(op)}\t({'|'.join(hex(x) for x in top)})")

# Replay the dumped trace in plain Python; no bytecode parsing, no shuffle logic:
elif line.startswith('save at (0x51)'):
    return stack[top] == expected_hash   # calculated hash lands at mem[0x51]

# Diff trace("abcd") vs trace("dcba") -> the same mul/mod sequence shows up,
# revealing the real algorithm:
def calc_hash(x, mod):
    for _ in range(8):
        x = x * x % mod
    return x * x_original % mod
```

从 trace 中导出每组对应的模数（`[0x88ca6b51, 0x8405b751, 0xbfa08c87, 0x82013f23, 0x4666751b, 0x5271083f]`）以及期望哈希，再对 `string.printable` 的 4 字符排列做暴力匹配 `calc_hash`。

**关键点：** 具有自修改分发逻辑的 VM（shuffle、rotor、LCG 驱动 opcode 表）本质上是在惩罚朴素重实现。直接记录实际执行到的指令流，可以彻底绕过这类技巧。对于给定输入，trace 是确定性的；只改动一位输入并比较两条 trace，就能定位 VM 外壳下真正的算法。

**参考：** CONFidence CTF 2019 Teaser — Go Machine, writeup 13947

---

另见：[patterns-ctf-2.md](patterns-ctf-2.md) 的 Part 2（多层自解密二进制、内嵌 ZIP+XOR license、stack string 去混淆、prefix hash 爆破、CVP/LLL lattice、decision tree obfuscation、GF(2^8) Gaussian elimination），以及 [patterns-ctf-3.md](patterns-ctf-3.md) 的 Part 3（Z3 布尔电路、滑动窗口 popcount、键盘 LED 摩斯码、C++ 析构函数隐藏校验、VM 顺序 key-chain 爆破、BWT 逆变换、OpenType 字体连字利用、带自修改代码的 GLSL shader VM）。
