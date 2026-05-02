# CTF Crypto - PRNG 与密钥恢复

PRNG 状态 / 种子恢复的基础技巧。关于更偏 CTF 实战的高级攻击（MT19937 约束传播、Rule 86 元胞自动机、Java LCG MITM、LFSR bit-fold、Z3 计时预言机、randcrack DSA、NTP 污染 UUID），见 [prng-attacks.md](prng-attacks.md)。

## Table of Contents
- [Mersenne Twister（MT19937）状态恢复](#mersenne-twister-mt19937-state-recovery)
- [通过 GF(2) 矩阵从 random.random() 浮点恢复 MT 状态（PHD CTF Quals 2012）](#mt-state-recovery-from-randomrandom-floats-via-gf2-matrix-phd-ctf-quals-2012)
- [基于时间的种子攻击](#time-based-seed-attacks)
- [通过 Python ctypes 同步 C 的 srand/rand](#c-srandrand-synchronization-via-python-ctypes)
- [分层加密恢复](#layered-encryption-recovery)
- [LCG 参数恢复攻击](#lcg-parameter-recovery-attack)
- [ChaCha20 密钥恢复](#chacha20-key-recovery)
- [GF(2) 矩阵 PRNG 种子恢复（0xFun 2026）](#gf2-matrix-prng-seed-recovery-0xfun-2026)
- [中平方 PRNG 暴力（UTCTF 2024）](#middle-square-prng-brute-force-utctf-2024)
- [由 flag 字节驱动的确定性 RNG + 爬山（VuwCTF 2025）](#deterministic-rng-from-flag-bytes--hill-climbing-vuwctf-2025)
- [按字节预言机 + 随机模式匹配（VuwCTF 2025）](#byte-by-byte-oracle-with-random-mode-matching-vuwctf-2025)
- [RSA 密钥复用 / 重放（UTCTF 2024）](#rsa-key-reuse--replay-utctf-2024)
- [密码破解策略](#password-cracking-strategy)
- [Logistic Map / 混沌 PRNG 种子恢复（BYPASS CTF 2025）](#logistic-map--chaotic-prng-seed-recovery-bypass-ctf-2025)
- [V8 XorShift128+ 状态恢复（Math.random 预测）](#v8-xorshift128-state-recovery-mathrandom-prediction)

CTF 时代的高级 PRNG 技术（2017+）见 [prng-attacks.md](prng-attacks.md)。

---

## Mersenne Twister (MT19937) State Recovery

Python 的 `random` 模块使用 Mersenne Twister。只要能观察到输出，就能恢复其内部状态并预测后续结果。

**关键性质：**
- 内部状态为 624 个 32-bit 数
- 每个输出都由状态经过 tempering 得到
- 每产出 624 次后，会执行一次 twist（重新生成状态）

**基础 untemper（逆单个输出）：**
```python
def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xefc60000
    for _ in range(7):
        y ^= (y << 7) & 0x9d2c5680
    y ^= y >> 11
    y ^= y >> 22
    return y

# 已知连续 624 个输出时，恢复状态
state = [untemper(output) for output in outputs]
```

**Python 在 64 位平台上的 `randrange(maxsize)`：**
- `maxsize = 2^63 - 1`，因此会调用 `getrandbits(63)`
- 每个 63-bit 输出会消耗 2 个 MT 输出：`(mt1 << 31) | (mt2 >> 1)`
- 每次丢掉 1 bit，因此通常需要符号求解

**用 z3 做符号恢复：**
```python
from z3 import *

def symbolic_temper(y):
    y = y ^ (LShR(y, 11))
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ (LShR(y, 18))
    return y

# 构造符号化的 MT 状态
mt = [BitVec(f'mt_{i}', 32) for i in range(624)]
solver = Solver()

# 对每个观测到的 63-bit 输出建立约束
for i, out63 in enumerate(outputs):
    if 2*i + 1 >= 624: break
    y1 = symbolic_temper(mt[2*i])
    y2 = symbolic_temper(mt[2*i + 1])
    combined = Concat(Extract(31, 0, y1), Extract(31, 1, y2))
    solver.add(combined == out63)

if solver.check() == sat:
    state = [solver.model()[mt[i]].as_long() for i in range(624)]
```

**典型用途：**
- 预测 MIME boundary（邮件库）
- 预测 session token
- 绕过 CAPTCHA（可预测验证码）
- 游戏 RNG 利用

## MT State Recovery from random.random() Floats via GF(2) Matrix (PHD CTF Quals 2012)

**模式：** 服务端暴露 `random.random()` 的浮点输出（比如某个 API）。标准 MT untemper 需要 624 个 32-bit 整数，但 `random.random()` 只给出 53-bit 浮点，而且通常每次只能取到约 8 个有效 bit。预计算好的 GF(2) 魔法矩阵可以把这些观测值映射回 624 词 MT 状态。

**关键点：** `random.random()` 实际返回 `(a*2^27+b)/2^53`，其中 `a` 来自一个 MT 输出的 27 bit，`b` 来自下一个输出的 26 bit。若仅拿 `int(float * 256)`，每次只得到 8 个 bit，因此需要约 3360 个观测，而不是 624 个。`not_random` 库已经预计算好了观测 bit 与 MT 状态 bit 的 GF(2) 关系。

```python
import random, gzip, hashlib

# 加载预计算好的 GF(2) 魔法矩阵（来自 github.com/fx5/not_random）
f = gzip.GzipFile("magic_data", "r")
magic = eval(f.read())
f.close()

def rebuild_from_floats(floats):
    """把浮点观测转换成字节值，再恢复 MT 状态。"""
    vals = [int(f * 256) for f in floats]  # 截断到 8 bit
    return rebuild_random(vals)

def rebuild_random(vals):
    """使用 GF(2) 矩阵从 3360+ 个字节观测中恢复 MT19937 状态。"""
    def getbit(bit):
        assert bit >= 0
        return (vals[bit // 8] >> (7 - bit % 8)) & 1
    state = []
    for i in range(624):
        val = 0
        data = magic[i % 2]
        for bit in data:
            val <<= 1
            for b in bit:
                val ^= getbit(b + (i // 2) * 8 - 8)
        state.append(val)
    state.append(0)
    ran = random.Random()
    ran.setstate((3, tuple(state), None))
    # 向前跳过已消费的输出
    for i in range(len(vals) - 3201 + 394):
        ran.randint(0, 255)
    return ran

# 从目标收集 3360+ 个 random.random() 浮点
floats = [...]  # 从服务端 API 观察到的值

# 恢复状态并预测未来输出
my_random = rebuild_from_floats(floats[:3360])

# 验证预测是否匹配后续观测
for observed, predicted in zip(floats[3360:], [my_random.random() for _ in range(40)]):
    assert '%.16f' % observed == '%.16f' % predicted

# 伪造密码重置 token（与服务端计算方式一致）
token = hashlib.md5(('%.16f' % my_random.random()).encode()).hexdigest()
reset_url = f'http://target/reset/{user_id}-{token}/'
```

**攻击流程（预测密码重置 token）：**
1. 从暴露随机数的 API 拉取 3360+ 个浮点值（如 `/?count=3360`）
2. 同时触发一次密码重置（token 的生成方式是 `md5(random.random())`）
3. 通过这些浮点观测恢复 MT 状态
4. 预测服务端下一次 `random.random()` 调用，即重置 token 所用值
5. 拼出携带预测 token 的 reset URL

**何时使用：** 当服务端把 Python `random.random()` 用于安全敏感 token（session ID、密码重置、CSRF token），同时又从另一个接口暴露了随机值。`not_random` 已经处理了底层 bit 级数学，重点是收集足够多浮点观测，并与目标操作做时间同步。

---

## Time-Based Seed Attacks

当加密使用基于时间的 PRNG 种子时：
```python
seed = f"{username}_{timestamp}_{random_bits}"
```

**攻击思路：**
1. **用户名：** 从元数据、邮件头或题目上下文提取
2. **时间戳：** 从文件元数据中获取（ZIP、exiftool）
3. **随机比特：** 查看二进制里是否硬编码；若范围很小则直接暴力

**提取时间戳：**
```bash
# 把时区设成和目标一致
TZ=Pacific/Galapagos exiftool file.enc
# 查找 File Modification Date/Time
```

**暴力毫秒：**
```python
from datetime import datetime
import random

for ms in range(1000):
    ts = f"2021-02-09!07:23:54.{ms:03d}"
    seed = f"{username}_{ts}_{rdata}"
    rng = random.Random()
    rng.seed(seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))
    if try_decrypt(ciphertext, key):
        print(f"Found seed: {seed}")
        break
```

## C srand/rand Synchronization via Python ctypes

**模式：** 二进制启动时调用 `srand(time(NULL))`，再使用 C 的 `rand()` 生成加密密钥、随机挑战或 XOR mask。Python 自带的 `random` 使用的是 Mersenne Twister，不兼容。要想精确复现 C 程序的序列，必须用 `ctypes` 加载同一份 libc，并直接调用它的 `srand()` / `rand()`。

**基础同步（L3akCTF 2024, MireaCTF）：**
```python
from ctypes import CDLL
from time import time

# 加载与目标二进制相同的 libc
libc = CDLL('./libc.so.6')  # 或系统 libc：CDLL('libc.so.6')

# 在与目标同一秒内播种
libc.srand(int(time()))

# 生成与目标 rand() 完全相同的序列
for i in range(16):
    value = libc.rand() & 0xff  # 与目标的截断方式保持一致（例如只取低 8 bit）
    print(value)
```

**解密 XOR 数据（L3akCTF 2024 chonccfile）：**
```python
from ctypes import CDLL
from time import time
from pwn import u32, p32

libc_imp = CDLL('./libc.so.6')
libc_imp.srand(int(time()))

# 二进制对每个 4 字节分组用 rand() 输出做 XOR
encrypted_data = b'...'  # 从堆或内存中读出
result = b''
for i in range(0, len(encrypted_data), 4):
    block = u32(encrypted_data[i:i+4])
    libc_imp.rand()       # 若目标在中间多调了一次 rand()，这里要对齐跳过
    key = libc_imp.rand()
    block ^= key
    result += p32(block)
```

**计时注意事项：**
- `time(NULL)` 只有 1 秒粒度，因此 exploit 要尽量与目标在同一秒启动
- 远程服务可能有启动延迟，常要尝试 `+1` 或 `+2` 秒偏移
- 要考虑 `srand()` 与目标用途之间是否还有额外 `rand()` 调用（例如随机延迟）
- 第一次未必成功，必要时用相邻种子反复重试

**关键点：** Python 的 `random` 和 C 的 `rand()` 完全不是一回事。只要题目里的 C 程序用了 `srand(time(NULL))`，从 Python 复现序列的正确方式就只有 `ctypes.CDLL` + 同一份 libc 的 `srand`/`rand`。优先加载题目给的 `libc.so.6`，保证完全兼容。这类技巧适用于所有 C PRNG 预测：XOR 密钥、挑战值、token 乃至堆上的加密数据。

**替代方式：自定义共享库（MireaCTF）：**
```c
// random_lib.c —— 编译：gcc -shared -o random_lib.so random_lib.c
#include <stdlib.h>
void setseed(int seed) { srand(seed); }
int generate() { return rand() & 0xff; }
```
```python
from ctypes import CDLL
lib = CDLL('./random_lib.so')
lib.setseed(int(time()) + 1)  # +1 对齐远程延迟
numbers = [lib.generate() for _ in range(16)]
```

---

## Layered Encryption Recovery

当二进制使用多层加密时：
1. 先确认加密顺序（例如 Serpent -> TEA）
2. 找出种子推导方式（例如 flag 字符之和）
3. 密钥常由 `srand()` 序列派生
4. 优先暴力有限种子范围（例如可打印 ASCII 之和范围很小）

## LCG Parameter Recovery Attack

线性同余生成器（LCG）是弱 PRNG。只要拿到连续输出，就能恢复参数：

**LCG 公式：** `x_{n+1} = (a * x_n + c) mod m`

**从输出序列恢复参数（SageMath）：**
```python
# 给定序列：[s0, s1, s2, s3, ...]
# crypto-attacks 库：github.com/jvdsn/crypto-attacks
from attacks.lcg import parameter_recovery

sequence = [
    72967016216206426977511399018380411256993151454761051136963936354667101207529,
    49670218548812619526153633222605091541916798863041459174610474909967699929824,
    # ... 更多输出
]

m, a, c = parameter_recovery.attack(sequence)
print(f"Modulus m: {m}")
print(f"Multiplier a: {a}")
print(f"Increment c: {c}")
```

**当 RSA 素数来自 LCG 时：**
- 先恢复 LCG 参数
- 用已知明文 XOR 密文提取 LCG 输出
- 重新生成同样的素数序列来分解 N

```python
# 恢复 XOR 密钥（也就是 LCG 输出）
def recover_lcg_output(plaintext, ciphertext, timestamp):
    pt_bytes = plaintext.encode('utf-8').ljust(32, b'\0')
    ct_int = int.from_bytes(bytes.fromhex(ciphertext), 'big')
    return timestamp ^ int.from_bytes(pt_bytes, 'big') ^ ct_int

# 恢复参数后，重新生成 RSA 素数
lcg = LCG(a, c, m, seed)
primes = []
while len(primes) < 8:
    candidate = lcg.next()
    if is_prime(candidate) and candidate.bit_length() == 256:
        primes.append(candidate)

n = prod(primes)
phi = prod(p - 1 for p in primes)
d = pow(65537, -1, phi)
```

## ChaCha20 Key Recovery

当 ChaCha20 密钥是从可恢复数据派生时：

```python
from Crypto.Cipher import ChaCha20

# 若密钥由可预测来源派生（时间戳、PID 等）
for candidate_key in generate_candidates():
    cipher = ChaCha20.new(key=candidate_key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    if is_valid(plaintext):  # 检查是否符合预期格式
        print(f"Key found: {candidate_key.hex()}")
        break
```

**Ghidra 仿真提取密钥：**
当密钥由复杂函数计算得出时，优先仿真该函数，而不是手工重写。

## GF(2) Matrix PRNG Seed Recovery (0xFun 2026)

**模式（BitStorm）：** 只使用 XOR、移位和轮转的 PRNG，本质上在 GF(2) 上是线性的。

**关键点：** 把整个 PRNG 表示成矩阵乘法：`output_bits = M * seed_bits (mod 2)`。只要输出足够多，用高斯消元就能恢复 seed。

```python
import numpy as np

def build_prng_matrix(prng_func, seed_bits=2048, output_bits=2048):
    """对单位向量运行 PRNG，构造 GF(2) 矩阵。"""
    M = np.zeros((output_bits, seed_bits), dtype=np.uint8)
    for i in range(seed_bits):
        # 设种子的第 i 位为 1
        seed = 1 << (seed_bits - 1 - i)
        output = prng_func(seed)
        for j in range(output_bits):
            M[j, i] = (output >> (output_bits - 1 - j)) & 1
    return M

# 已知 output 后，解方程：M * seed = output (mod 2)
# 使用 GF(2) 高斯消元（参见 modern-ciphers.md 里的 solve_gf2）
seed = solve_gf2(M, output_bits_array)
```

**识别方法：** PRNG 只包含 `^`、`<<`、`>>`、rotate 等位运算时，不要先想着迭代恢复状态，直接把它视为 GF(2) 线性系统。

---

## Middle-Square PRNG Brute Force (UTCTF 2024)

**模式（numbers go brrr）：** 使用中平方方法，且种子空间很小。

```python
# PRNG: seed = int(str(seed * seed).zfill(12)[3:9])  —— 6 位种子
# 种子来源：int(time.time() * 1000) % (10**6) —— 只有 100 万种可能
# AES 密钥：PRNG 跑 8 轮，每轮取 seed % 2^16 作为 2 字节片段

def middle_square_keygen(seed):
    key = b''
    for _ in range(8):
        seed = int(str(seed * seed).zfill(12)[3:9])
        key += (seed % (2**16)).to_bytes(2, 'big')
    return key

# 暴力：对照已知明文加密 / 解密结果
for seed in range(10**6):
    key = middle_square_keygen(seed)
    if try_decrypt(ciphertext, key):
        print(f"Seed: {seed}")
        break
```

**即便交互次数有限：** 只要有一组已知明文，就足以离线暴力。

---

## Deterministic RNG from Flag Bytes + Hill Climbing (VuwCTF 2025)

**模式（Totally Random Art）：** flag 字节本身被拿来作为 Python `random.Random()` 的 seed。flag 的前缀格式已知，后续未知字节会决定最终渲染图案。

**攻击：** 当 PRNG seed 可由 flag 格式部分确定时，就可以对未知字符做爬山搜索：
```python
import random

def render(flag_bytes):
    rng = random.Random()
    rng.seed(flag_bytes)
    grid = [[0]*10 for _ in range(5)]
    for b in flag_bytes:
        steps, stroke = divmod(b, 16)
        x, y = 0, 0
        for _ in range(steps):
            dx, dy = rng.choice([(0,1),(0,-1),(1,0),(-1,0)])
            x = (x + dx) % 10
            y = (y + dy) % 5
        grid[y][x] = (grid[y][x] + stroke) % 16
    return grid

# 爬山：逐位尝试所有字符，保留让画面匹配度最高的那个
target = parse_target_art()
flag = list(b'VuwCTF{')
for pos in range(7, 17):
    best_score, best_char = -1, 0
    for c in range(32, 127):
        candidate = bytes(flag + [c])
        score = sum(1 for y in range(5) for x in range(10)
                    if render(candidate)[y][x] == target[y][x])
        if score > best_score:
            best_score, best_char = score, c
    flag.append(best_char)
```

---

## Byte-by-Byte Oracle with Random Mode Matching (VuwCTF 2025)

**模式（Unorthodox IV）：** 服务端每次加密都会随机选择 N 个 mode / IV 之一，而且你可以提交自定义明文。

**攻击策略：**
1. 连接后先拿到加密后的 flag
2. 用已知前缀做探测，检查当前连接是否“碰到”与 flag 相同的 mode（相同 mode 会给出相同的密文前缀）。若大约 50 次探测都没匹配，就断开重连。
3. 一旦 mode 可达，就按字节测试候选字符。若 mode 匹配且下一字节也匹配，字符正确；若 mode 匹配但下一字节不匹配，则该字符可永久排除。
4. 排除信息跨重连仍然有效。

**关键点：** 先探测 mode 是否可达，再做字符测试，能显著减少浪费。对于 mode 随机化的系统，基于“排除”的搜索往往比基于“确认”的搜索更高效。

---

## RSA Key Reuse / Replay (UTCTF 2024)

**模式（simple signature）：** RSA 密钥在不同轮次之间复用，而且输入交替重复。

**攻击：** 把前面抓到的加密输出原样回放给服务端。如果多次交互使用同一套静态密钥，重放攻击往往是最直接的解法。只要看到多轮协议，第一件事就是确认密钥是否真的在变化。

---

## Logistic Map / Chaotic PRNG Seed Recovery (BYPASS CTF 2025)

**模式（Chaotic Trust）：** 使用 logistic map `x_{n+1} = r * x * (1 - x)` 作为 PRNG 的流密码。密钥流通过把每次迭代得到的浮点打包成字节生成。

**关键点：** Logistic map 虽然“混沌”，但仍然是确定性的。只要恢复初始种子 `x`，就能完整重建密钥流。种子通常是 0 到 1 之间的小数，例如 `0.123456789`。

```python
import struct

def logistic_map(x, r=3.99):
    return r * x * (1 - x)

def decrypt_logistic(cipher_hex, seed):
    cipher = bytes.fromhex(cipher_hex)
    x = seed
    stream = b""

    while len(stream) < len(cipher):
        x = logistic_map(x)
        # 把浮点打包为字节，生成密钥流（注意字节序）
        stream += struct.pack("<f", x)[-2:]  # 也可能用完整 4 字节

    stream = stream[:len(cipher)]
    return bytes(a ^ b for a, b in zip(cipher, stream))

# 暴力种子精度
for precision in range(6, 12):
    for base in [123456, 234567, 314159, 271828]:
        seed = base / (10 ** precision)
        result = decrypt_logistic(cipher_hex, seed)
        if b"FLAG" in result or b"CTF" in result:
            print(f"Seed: {seed}, Flag: {result}")
```

**常见变体：**
- **r 参数：** 通常是 `r = 3.99` 或 `r = 4.0`（完全混沌区）
- **打包方式：** `struct.pack("<f", x)`（4 字节）、`struct.pack("<d", x)`（8 字节），或取 `[-2:]` 作为 2 字节片段
- **种子范围：** 往往是带明显模式的小数，例如 `0.123456789`，或者由题目提示导出

**识别方法：** 题目出现 “chaos”“logistic”“butterfly effect” 等描述，或者源码中直接出现 `x = r * x * (1 - x)` 迭代。

---

## V8 XorShift128+ State Recovery (Math.random Prediction)

**模式：** Web 题用 `Math.floor(CONST * Math.random())` 生成 token、验证码或游戏数值。V8 的 `Math.random()` 使用 XorShift128+（xs128p）PRNG。给定若干连续的 floor 输出，可用 Z3 恢复内部状态（state0, state1），然后预测后续值。

**V8 内部机制：**
1. xs128p 产生 64-bit 状态；V8 用 `state0 >> 12 | 0x3FF0000000000000` 组装出 `[1.0, 2.0)` 区间的双精度，再减 1.0
2. `Math.random()` 读取的是一个**64 项 LIFO 缓存**。缓存空时 `RefillCache()` 一次生成 64 个值，之后按逆序消费
3. 最终输出只依赖 `state0`，不直接使用 `state1`

**xs128p 算法：**
```python
def xs128p(state0, state1):
    s1 = state0 & 0xFFFFFFFFFFFFFFFF
    s0 = state1 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 >> 17) & 0xFFFFFFFFFFFFFFFF
    s1 ^= s0 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s0 >> 26) & 0xFFFFFFFFFFFFFFFF
    state0 = state1 & 0xFFFFFFFFFFFFFFFF
    state1 = s1 & 0xFFFFFFFFFFFFFFFF
    return state0, state1, state0  # 输出是新的 state0
```

**用于 `Math.floor(CONST * Math.random())` 的 Z3 求解器：**
```python
from z3 import *
from decimal import Decimal
import struct

def to_double(value):
    double_bits = (value >> 12) | 0x3FF0000000000000
    return struct.unpack('d', struct.pack('<Q', double_bits))[0] - 1

def from_double(dbl):
    return struct.unpack('<Q', struct.pack('d', dbl + 1))[0] & 0x7FFFFFFFFFFFFFFF

def sym_xs128p(s0, s1):
    s1_ = s0
    s0_ = s1
    s1_ ^= (s1_ << 23)
    s1_ ^= LShR(s1_, 17)
    s1_ ^= s0_
    s1_ ^= LShR(s0_, 26)
    return s1, s1_  # 新的 state0, state1

def solve_v8_random(observed_values, multiple):
    """从连续的 Math.floor(multiple * Math.random()) 输出恢复 xs128p 状态。
    observed_values 必须按 REVERSE 顺序给出（经 tac 处理后，最早的在前）。"""
    ostate0, ostate1 = BitVecs('ostate0 ostate1', 64)
    sym_s0, sym_s1 = ostate0, ostate1
    slvr = SolverFor("QF_BV")

    for val in observed_values:
        sym_s0, sym_s1 = sym_xs128p(sym_s0, sym_s1)
        calc = LShR(sym_s0, 12)  # V8 ToDouble 的 mantissa bit
        # 约束：floor(multiple * to_double(state0)) == val
        lower = from_double(Decimal(val) / Decimal(multiple))
        upper = from_double(Decimal(val + 1) / Decimal(multiple))
        lower_m = lower & 0x000FFFFFFFFFFFFF
        upper_m = upper & 0x000FFFFFFFFFFFFF
        upper_e = (upper >> 52) & 0x7FF
        slvr.add(And(lower_m <= calc, Or(upper_m >= calc, upper_e == 1024)))

    if slvr.check() == sat:
        m = slvr.model()
        return m[ostate0].as_long(), m[ostate1].as_long()
    return None, None

# 状态恢复后预测后续输出
def predict_next(state0, state1, multiple, count):
    results = []
    for _ in range(count):
        state0, state1, output = xs128p(state0, state1)
        import math
        results.append(math.floor(multiple * to_double(output)))
    return results
```

**用法（工具：d0nutptr/v8_rand_buster）：**
```bash
# 收集观测值，按缓存顺序反转后送入求解器
cat observed_codes.txt | tac | python3 xs128p.py --multiple 100000

# 根据恢复状态继续生成预测
python3 xs128p.py --multiple 100000 --gen <state0>,<state1>,<count>
```

**关键点：** 由于缓存是 LIFO 的，观测顺序必须先反转，再输入求解器。Z3 的 `QF_BV`（无量词位向量）理论非常适合处理这种位运算。通常 5-10 个连续输出就足以唯一确定状态。

**常见坑：**
- 忘记把观测顺序反转（缓存是 LIFO）
- 多个浏览器标签页或 web worker 可能各自维护 PRNG 状态
- 跨过 64 次调用的缓存边界时，如果观测跨越 refill，会出现不连续

**反向 xorshift128+（逆向预测）：** 状态恢复后，还可以把 PRNG 往回推，预测**早于**观测序列生成的值。当目标值比观测值更早产生时（例如预测其他用户稍早生成的 2FA code），这一点至关重要。（Midnight Flag 2026）

```python
def undo_rshift_xor(val, shift):
    """逆运算：val ^= (val >> shift)"""
    result = val
    for _ in range(3):  # 对 64 位数，3 次迭代足够
        result = val ^ (result >> shift)
    return result & 0xFFFFFFFFFFFFFFFF

def undo_lshift_xor(val, shift):
    """逆运算：val ^= (val << shift)"""
    result = val
    for _ in range(3):
        result = val ^ ((result << shift) & 0xFFFFFFFFFFFFFFFF)
    return result & 0xFFFFFFFFFFFFFFFF

def reverse_step(s0, s1):
    """把 xs128p 反向运行一步：(s0, s1) → (old_s0, old_s1)"""
    old_s1 = s0
    known = (s1 ^ s0 ^ ((s0 >> 26) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    x = undo_rshift_xor(known, 17)
    old_s0 = undo_lshift_xor(x, 23)
    return old_s0, old_s1

# 用法：从恢复出的状态反向回退 N 步
for _ in range(N):
    state0, state1 = reverse_step(state0, state1)
    predicted = math.floor(CONST * to_double(state0))
```

**何时使用：** Web 题中若 JavaScript 或 Node.js 代码用 `Math.random()` 生成验证码、token、游戏投骰等看似随机的值，就该考虑这类攻击。尤其要留意 `Math.floor(N * Math.random())` 或 `Math.random().toString(36).substr(2)` 之类模式。

---

## Password Cracking Strategy

**未知密码时的攻击顺序：**
1. 通用词典：`rockyou.txt`、`10k-common.txt`
2. 基于题目主题定制词典（用户名、题目关键词）
3. 规则攻击：词典 + `best66.rule`、`dive.rule`
4. 混合攻击：`word + ?d?d?d?d`（单词 + 4 位数字）
5. 暴力：从 4 字符开始，逐步增加长度

**带十六进制盐的 SHA256（VuwCTF 2025, Delicious Cooking）：** 格式通常是 `hash$hex_salt`。盐需要先十六进制解码，再计算 `SHA256(password + salt_bytes)`。口令往往可以从安全问题中推导出来（如 “最喜欢的电影 + PIN” -> `ratatouille0000` 到 `ratatouille9999`）。

**CTF 里的常见密码模式：**
```text
base_password + year     → actnowonclimatechange2026
username + digits        → nemo123, admin2026
theme + numbers          → flag2026, ctf2025
leet speak               → p@ssw0rd, s3cr3t
```

**Hashcat 模式速查：**
```bash
# 常见 hash 模式
-m 0      # MD5
-m 1000   # NTLM
-m 5600   # NTLMv2
-m 13600  # WinZip AES
-m 13000  # RAR5
-m 11600  # 7-Zip

# 攻击模式
-a 0      # 字典
-a 3      # 掩码暴力
-a 6      # 混合（词典 + 掩码）
-a 7      # 混合（掩码 + 词典）
```

**当密码和题目里另一个密码相关时：**
- 试各种变体：`password + year`、`password + 123`
- 尝试反转：`drowssap`
- 尝试常见后缀：`!`、`@`、`#`、`1`、`123`
- 如果 SMB/FTP 密码已知，ZIP 密码通常与之相关

---

CTF 时代的高级 PRNG 技术（2017+）见 [prng-attacks.md](prng-attacks.md)。
