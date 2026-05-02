# CTF Crypto - 流密码攻击

LFSR、RC4 和基于 XOR 的流密码攻击。分组密码攻击（AES、填充预言机、MAC 伪造）见 [modern-ciphers.md](modern-ciphers.md)。

## Table of Contents
- [LFSR 流密码攻击](#lfsr-stream-cipher-attacks)
  - [Berlekamp-Massey 算法](#berlekamp-massey-algorithm)
  - [相关攻击](#correlation-attack)
  - [针对 LFSR 密钥流的已知明文攻击](#known-plaintext-on-lfsr-keystream)
  - [Galois 与 Fibonacci LFSR](#galois-vs-fibonacci-lfsr)
  - [常见 LFSR 长度与多项式](#common-lfsr-lengths-and-polynomials)
  - [通过自相关恢复 Galois LFSR tap（BSidesSF 2026）](#galois-lfsr-tap-recovery-via-autocorrelation-bsidessf-2026)
- [RC4 第二字节偏差区分器（Hackover CTF 2015）](#rc4-second-byte-bias-distinguisher-hackover-ctf-2015)
- [相邻字节 XOR 相关攻击（Defcamp 2015）](#xor-consecutive-byte-correlation-attack-defcamp-2015)
- [Fibonacci 流密码位置移位预言机（EKOPARTY 2017）](#fibonacci-stream-cipher-position-shifting-oracle-ekoparty-2017)
- [用于自定义流密码的 Z3 约束求解（Tokyo Westerns 2017）](#z3-constraint-solving-for-custom-stream-ciphers-tokyo-westerns-2017)
- [通过游程编码碰撞恢复密钥流（Google CTF Quals 2018）](#keystream-recovery-via-run-length-encoding-collisions-google-ctf-quals-2018)
- [LFSR Filter Linear Annihilator Attack（Hack.lu 2018）](#lfsr-filter-linear-annihilator-attack-hacklu-2018)
- [DNS 抓包泄露“主机名即 XOR 密钥”（SECCON 2018）](#hostname-as-xor-key-leaked-via-dns-capture-seccon-2018)

---

## LFSR Stream Cipher Attacks

线性反馈移位寄存器（LFSR）通过初始状态和反馈多项式生成密钥流，在 CTF 密码题和轻量 / 自定义密码中非常常见。

**识别方法：** 题目中出现位级操作（XOR、shift、与 tap mask 相与）、较短的循环密钥流，或描述里明确提到 “stream cipher”“LFSR”“shift register”“linear recurrence” 等关键词。

### Berlekamp-Massey Algorithm

**模式：** 已知一段密钥流（通常由已知明文 XOR 密文得到），要求恢复生成它的最短 LFSR。得到反馈多项式和状态后，就可以预测未来乃至过去的所有输出。

**关键点：** Berlekamp-Massey 能在 `O(n^2)` 时间内找出生成给定序列的最短 LFSR。只要你拿到连续 `2L` 个密钥流 bit（L 为 LFSR 长度），就能完整恢复该 LFSR。

```python
from sage.all import *

# 已知密钥流 bit（由已知明文 XOR 密文得到）
keystream = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1]

# 在 SageMath 中运行 Berlekamp-Massey
F = GF(2)
seq = [F(b) for b in keystream]
R = berlekamp_massey(seq)  # 返回反馈多项式
print(f"LFSR polynomial: {R}")
print(f"LFSR length: {R.degree()}")

# 用前 L 个 bit 恢复初始状态
L = R.degree()
state = keystream[:L]

# 生成后续密钥流
def lfsr_next(state, taps):
    """taps = 由多项式导出的 tap 位置列表"""
    new_bit = 0
    for t in taps:
        new_bit ^= state[t]
    return state[1:] + [new_bit]
```

### Correlation Attack

**模式：** 多个 LFSR 通过非线性组合函数合成为一个输出。如果该组合函数对某一个 LFSR 输出存在相关偏差，就可以把这个 LFSR 单独攻击掉。

**关键点：** 如果 `P(output = LFSR_i output) > 0.5`，就可以只暴力 `LFSR_i` 的初始状态（长度为 L 的 LFSR 只需 `2^L` 个候选），并与已知密钥流做相关性比对。这比暴力整个组合状态快得多。

```python
# 针对单个有偏 LFSR 的相关攻击
def correlation_attack(keystream_bits, lfsr_length, taps, threshold=0.6):
    """尝试所有 2^L 个初始状态，保留相关性最高的候选"""
    best_corr, best_state = 0, None
    for seed in range(2**lfsr_length):
        state = [(seed >> i) & 1 for i in range(lfsr_length)]
        matches = 0
        s = state[:]
        for i, bit in enumerate(keystream_bits):
            if s[0] == bit:
                matches += 1
            s = lfsr_next(s, taps)
        corr = matches / len(keystream_bits)
        if corr > best_corr:
            best_corr, best_state = corr, seed
    return best_state, best_corr
```

### Known-Plaintext on LFSR Keystream

**模式：** 用已知明文和密文 XOR 得到密钥流。只要有至少 `2L` 个密钥流 bit，就可以直接解线性系统。

```python
import numpy as np

# 已知 2L 个密钥流 bit，求解 L 位状态 + L 个反馈 tap
# 密钥流关系：k[i+L] = c[0]*k[i] + c[1]*k[i+1] + ... + c[L-1]*k[i+L-1] (mod 2)
def solve_lfsr(keystream, L):
    """在 GF(2) 上用 2L 个密钥流 bit 求 LFSR 反馈系数"""
    # 构造矩阵：每一行是 [k[i], k[i+1], ..., k[i+L-1]] = k[i+L]
    A = []
    b = []
    for i in range(L):
        A.append(keystream[i:i+L])
        b.append(keystream[i+L])
    # 用 SageMath 在 GF(2) 上求解
    from sage.all import matrix, vector, GF
    M = matrix(GF(2), A)
    v = vector(GF(2), b)
    coeffs = M.solve_right(v)
    return list(coeffs)
```

### Galois vs Fibonacci LFSR

这是两种等价表示，产生相同的密钥流，但“接线方式”不同：
- **Fibonacci：** 多个 tap XOR 后反馈到最后一位（CTF 中最常见）
- **Galois：** 反馈分散到寄存器内部（更适合硬件实现）

两者转换关系：Galois 多项式是 Fibonacci 多项式的倒数。大多数 CTF 工具默认使用 Fibonacci 形式。

### Common LFSR Lengths and Polynomials

| 位数 | 常见原始多项式 | 周期 |
|------|----------------|--------|
| 16 | x^16 + x^14 + x^13 + x^11 + 1 | 65535 |
| 32 | x^32 + x^22 + x^2 + x + 1 | 2^32 - 1 |
| 64 | x^64 + x^4 + x^3 + x + 1 | 2^64 - 1 |

**最大长度 LFSR：** 若反馈多项式是 primitive polynomial，则周期为 `2^L - 1`（遍历所有非零状态）。

### Galois LFSR Tap Recovery via Autocorrelation (BSidesSF 2026)

**模式（lfstream）：** 某个 PNG 文件被按 N 位分组，与一个 Galois LFSR 的当前状态逐块 XOR 加密（右移模型）。LFSR 长度、seed 和 tap mask 都未知。要求只靠已知的 16 字节 PNG 文件头恢复这三者。

**第 1 步：通过已知明文恢复密钥流：**

```bash
# PNG 文件头固定为：89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
# 用它与加密文件前 16 字节 XOR，得到 128 个密钥流 bit
```

**第 2 步：用自相关滑动找出 LFSR 长度：**

把 128 bit 密钥流与自身按不同偏移错开对齐。对齐最多的位置，对应的偏移通常就是 LFSR 周期。对于右移式 Galois LFSR，密钥流每走一步就相当于状态右移 1 bit，因此自相关峰通常出现在 `offset = LFSR length + 1`。

```python
def find_lfsr_length(bits, min_len=8, max_len=64, step=8):
    """通过把密钥流与自身滑动对齐，寻找 LFSR 周期。"""
    best = None
    for n in range(min_len, max_len + 1, step):
        # 按 n bit 切成状态窗口
        states = [int(bits[i*n:(i+1)*n], 2) for i in range(len(bits) // n)]
        if len(states) < 2:
            continue

        # 对每个相邻状态转移，检查是否满足 Galois 右移模型
        mask_votes = {}
        mismatches = 0
        for i in range(len(states) - 1):
            s, nxt = states[i], states[i + 1]
            base = s >> 1  # 不考虑反馈时的纯右移
            if s & 1:      # 若最低位为 1，则应用反馈
                derived_mask = base ^ nxt
                mask_votes[derived_mask] = mask_votes.get(derived_mask, 0) + 1
            else:           # 若最低位为 0，则 next 应等于 base
                if nxt != base:
                    mismatches += 1

        if mask_votes:
            best_mask, support = max(mask_votes.items(), key=lambda kv: kv[1])
            if mismatches == 0:
                print(f"Length {n}: tap_mask=0x{best_mask:0{n//4}x}, "
                      f"support={support}, mismatches=0 ← MATCH")
```

**第 3 步：用恢复出的参数解密：**

```python
def galois_lfsr_step(state, tap_mask, bits):
    """右移式 Galois LFSR 的单步更新。"""
    out = state & 1
    state >>= 1
    if out:
        state ^= tap_mask
    return state & ((1 << bits) - 1)

# Seed = 第一块密钥流（第一次更新前的 LFSR 状态）
seed = int(keystream_bits[:lfsr_bits], 2)
state = seed

with open("flag.png.enc_lfsr", "rb") as f_in, open("flag.png", "wb") as f_out:
    block_size = lfsr_bits // 8
    while True:
        chunk = f_in.read(block_size)
        if not chunk:
            break
        key = state.to_bytes(block_size, "big")
        f_out.write(bytes(b ^ k for b, k in zip(chunk, key)))
        state = galois_lfsr_step(state, tap_mask, lfsr_bits)
```

**关键点：** 对于右移式 Galois LFSR（`state >>= 1; if lsb: state ^= tap_mask`），只要拿到任何一对相邻状态且前一状态的 LSB 为 1，就能直接算出 `tap_mask = (state >> 1) XOR next_state`。这比 Berlekamp-Massey（默认假设 Fibonacci 形式）更直接，也不依赖代数库。自相关寻找长度之所以有效，是因为只有正确长度切分出的状态窗口，才能给出一致的 tap mask 且无矛盾。

**识别时机：** 题目把带已知文件头的文件（PNG、PDF、ZIP、ELF）用某种未知“stream cipher”或“PRNG”做 XOR 加密；文件名或描述里出现 “LFSR”“shift register”“stream”；加密后文件长度完全不变（没有填充），说明是流密码。对右移实现，优先尝试 Galois tap 恢复，它通常比 Berlekamp-Massey 更快更直接。

**常见文件头（用于恢复密钥流）：**

| 格式 | 头部字节 | 可用 bit 数 |
|--------|-------------|-------------|
| PNG | `89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52` | 128 |
| PDF | `25 50 44 46 2d` (`%PDF-`) | 40 |
| ZIP | `50 4b 03 04` | 32 |
| ELF | `7f 45 4c 46` | 32 |
| JFIF | `ff d8 ff e0` | 32 |

---

## RC4 Second-Byte Bias Distinguisher (Hackover CTF 2015)

**模式：** 利用 RC4 的第二字节偏差，把 RC4 输出与真正随机数据区分开。RC4 的第二个输出字节偏向 `0x00`，概率为 `1/128`，而随机应为 `1/256`。

```python
count_zero = 0
for sample in all_samples:
    if sample[1] == 0x00:  # 第二个字节
        count_zero += 1

# 期望值：随机 = N/256，RC4 = N/128（零字节多一倍）
if count_zero > threshold:
    print("RC4")
else:
    print("Random")
```

**关键点：** RC4 的密钥调度会带来一个著名偏差：`P(second_byte == 0) = 1/128`，而不是 `1/256`。大约 2048 个样本时，RC4 通常会出现约 16 个第二字节为 0 的样本，而随机数据只有约 8 个。RC4 还存在其他偏差，如第 3-255 字节的弱偏差，以及每 256 个位置的长期偏差。

---

## XOR Consecutive Byte Correlation Attack (Defcamp 2015)

当一种密码对相邻密文字节做 XOR 时，两条密文之间的关系会直接暴露明文差异，而无需知道密钥：

```python
# 观察：xorct[i] = ct[i] ^ ct[i+1]
# 对两组密文/明文：
# plain2[i] ^ plain1[i] == xorct1[i] ^ xorct2[i]

# 若已知其中一条明文，就能解出另一条：
for i in range(len(ct2)):
    xorct1 = ct1[i] ^ ct1[i+1]
    xorct2 = ct2[i] ^ ct2[i+1]
    plain2_char = xorct1 ^ xorct2 ^ plain1[i]
```

**关键点：** 相邻字节 XOR 会消掉密钥部分，只留下由明文差异决定的量。一条已知明文就足以破解其他消息。

---

## Fibonacci Stream Cipher Position-Shifting Oracle (EKOPARTY 2017)

**模式：** 某个自定义流密码把位置 `k` 的字节加密为 `Fib(seed + k) + plaintext_byte`。每次查询的第一个字节编码 seed。把第一个字节增加 N，就等于把 Fibonacci 起始位置向后平移 1，于是服务端等价于提供了一个“任意位置 Fibonacci 值 XOR 指定明文字节”的预言机。

**攻击方法（通过预言机恢复 flag）：**
1. 发送形如 `[seed_offset][target_byte_position]` 的查询，以请求目标密文的指定位置。
2. 对每个位置暴力 256 个明文字节候选：`candidate_byte + Fib(adjusted_seed + pos)` 应与服务端输出匹配。
3. 把结果与目标密文字节比较，筛出正确明文字节。

```python
# 预言机：server 返回 Fib(seed + k) XOR plaintext[k]
# 每把 seed 偏移 1，就能把目标位置平移到前面
for pos in range(flag_length):
    for candidate in range(256):
        # 通过调 seed，把想要的位置移到 position=0
        oracle_output = query(seed_offset=pos, position=0)
        fib_val = oracle_output ^ candidate
        if matches_target_ciphertext(fib_val, pos):
            flag_bytes.append(candidate)
            break
```

**关键点：** 当密钥流依赖于位置，且该起始位置又可控时，服务端就退化成了解密预言机。查询复杂度是 `O(n * 256)`，对长度为 n 的目标基本线性。

**参考：** EKOPARTY CTF 2017

---

## Z3 Constraint Solving for Custom Stream Ciphers (Tokyo Westerns 2017)

**模式：** 某个自定义流密码采用代数混合：`encrypted[i] = (message[i] + key[i%13] + encrypted[i-1]) % 128`。已知明文前缀（如 `TWCTF{`）能锚定前几个约束。把整个过程编码成 Z3 的整数约束后，可以一次性恢复密钥和剩余 flag。

```python
from z3 import *

key_len = 13
flag_len = len(encrypted)

key = [Int(f'k{i}') for i in range(key_len)]
flag = [Int(f'f{i}') for i in range(flag_len)]

s = Solver()

# 密码递推：enc[i] = (flag[i] + key[i%13] + enc[i-1]) % 128
for i in range(flag_len):
    prev = encrypted[i-1] if i > 0 else 0
    s.add(encrypted[i] == (flag[i] + key[i % key_len] + prev) % 128)

# 密钥和 flag 必须是可打印 ASCII
for k in key:
    s.add(k >= 32, k <= 126)
for f in flag:
    s.add(f >= 32, f <= 126)

# 用已知前缀锚定
for i, c in enumerate(b'TWCTF{'):
    s.add(flag[i] == c)

if s.check() == sat:
    m = s.model()
    recovered = bytes([m[flag[i]].as_long() for i in range(flag_len)])
    print(recovered)
```

**关键点：** 只要流密码的混合方式是代数型的（尤其是带加法的递推），就很适合直接丢给 Z3。把每一步写成约束，再加上已知前缀，求解器就能同时恢复密钥和明文，省去手工逆向公式。

**参考：** Tokyo Westerns CTF 2017

---

## Keystream Recovery via Run-Length Encoding Collisions (Google CTF Quals 2018)

**模式（DogeStore）：** 服务端计算 `sha3(rle_decode(decrypt(xor(input, keystream))))`。由于 RLE 对同一段字符重复有多种合法编码（例如 `a\x02` 和 `a\x01a\x00` 都会解码成 `aa`），两个不同输入可能得到相同的解码结果。不同密文若得到相同哈希，就会泄露某些密钥流字节之间的 XOR 关系。

**利用思路：** 对于每个候选位置对 `(i, i+2)` 和字节值 `x`，构造两条只在这些位置不同的密文。如果两者经服务器处理后 SHA3 相同，就说明 `keystream[i] XOR keystream[i+2] == x`。

```python
def probe(i, x):
    # 构造两条密文，使它们只在 i 和 i+2 的差异为 x
    c1 = baseline_cipher(i, 0, 0)
    c2 = baseline_cipher(i + 2, x, x)
    return sha3(server_decode(c1)) == sha3(server_decode(c2))

diffs = {}
for i in range(keystream_len - 2):
    for x in range(256):
        if probe(i, x):
            diffs[i] = x  # k[i] ^ k[i+2] = x
            break
```

一旦已知任意一个密钥流字节（或可由 flag 前缀约束住），就能把这些差分关系串起来恢复整段密钥流。

**关键点：** 只要协议在解密之后又对明文做了一个“多对一”的后处理（RLE、归一化、转小写等），那么基于该后处理结果的哈希预言机就会泄露明文之间的相等关系，进而泄露密钥流字节之间的关系，甚至不需要直接拿到解密结果。

**参考：** Google CTF Quals 2018，writeup 10370

---

## LFSR Filter Linear Annihilator Attack (Hack.lu 2018)

**模式：** 密钥流不是直接由 LFSR 状态输出，而是经过一个非线性滤波函数 `f`。如果 `f` 存在低阶线性湮灭子 `g`（即在 GF(2) 上满足 `g(f(x)) = 0`），那么每个密文字节都会给出关于初始 LFSR 状态的一个线性方程。累积足够多字节后，即可在 GF(2) 上求解整个系统，恢复初始状态。

```python
from sage.all import *
R = PolynomialRing(GF(2), 'x')
F = GF(2)
# 1. 构造矩阵 A：每一行都是 g(f(state_at_t)) 对 state_0 各 bit 的线性表达
# 2. 解 A * state_0 = 0（核空间给出候选 seed）
# 3. 用“解出来的明文是否可打印”筛选候选
for cand in A.right_kernel():
    pt = decrypt(cipher, cand)
    if all(0x20 <= b < 0x7f for b in pt): print(pt)
```

**关键点：** LFSR + 非线性滤波的安全性取决于滤波函数的代数免疫性。如果 `f` 存在低阶 annihilator，那么整个密钥流实际上仍是线性的，高斯消元就足以恢复状态。拿到滤波函数后，先查 BoolFunction 数据库，再决定是否真要暴力。

**参考：** Hack.lu CTF 2018，LFSR StreamCipher，writeup 12084

---

## Hostname-as-XOR-Key Leaked via DNS Capture (SECCON 2018)

**模式：** 二进制对自身 IP 调用 `gethostbyaddr()`，拿到反查得到的主机名后反转，并把它当作 `/flag.txt.encrypted` 的 XOR 密钥。这个主机名虽然很长很怪（如 `cur10us4ndl0ngh0stn4m3`），但会**明文出现在**反向 DNS 查询流量里。

```python
hostname = b"cur10us4ndl0ngh0stn4m3"[::-1]  # 从 pcap 中恢复
with open('flag.txt.encrypted','rb') as f: ct = f.read()
flag = bytes(b ^ hostname[i % len(hostname)] for i, b in enumerate(ct))
```

**关键点：** DNS 查询、HTTP `Host` 头、TLS SNI 常常会泄露那些二进制自己以为“秘密”的东西。运行题目二进制时，优先抓包；所谓“密钥”可能根本不在你能检查的内存里，而是直接从网络元数据里漏出来。

**参考：** SECCON 2018，Boguscrypt，writeup 12054
