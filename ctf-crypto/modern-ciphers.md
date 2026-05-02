# CTF Crypto - 现代密码攻击

分组密码攻击、MAC 伪造、填充预言机和认证加密。哈希 / 签名类攻击（长度扩展、PBKDF2、MD5 碰撞、Rabin、ECB 预言机）见 [modern-ciphers-2.md](modern-ciphers-2.md)。流密码攻击（LFSR、RC4、XOR）见 [stream-ciphers.md](stream-ciphers.md)。

## Table of Contents
- [AES-CFB-8 静态 IV 状态伪造](#aes-cfb-8-static-iv-state-forging)
- [图像上的 ECB 模式泄露](#ecb-pattern-leakage-on-images)
- [填充预言机攻击](#padding-oracle-attack)
- [CBC-MAC 与 OFB-MAC 的脆弱性差异](#cbc-mac-vs-ofb-mac-vulnerability)
- [非置换 S 盒碰撞攻击](#non-permutation-s-box-collision-attack)
- [LCG 部分输出恢复（0xFun 2026）](#lcg-partial-output-recovery-0xfun-2026)
- [弱哈希函数 / GF(2) 高斯消元](#weak-hash-functions--gf2-gaussian-elimination)
- [复合模下的仿射密码（Nullcon 2026）](#affine-cipher-over-composite-modulus-nullcon-2026)
- [带派生密钥的 AES-GCM（EHAX 2026）](#aes-gcm-with-derived-keys-ehax-2026)
- [AES-GCM Nonce 复用 / Forbidden Attack](#aes-gcm-nonce-reuse--forbidden-attack)
- [类 Ascon 约减轮差分分析（srdnlenCTF 2026）](#ascon-like-reduced-round-differential-cryptanalysis-srdnlenctf-2026)
- [自定义线性 MAC 伪造（Nullcon 2026）](#custom-linear-mac-forgery-nullcon-2026)
- [CBC 填充预言机攻击](#cbc-padding-oracle-attack)
- [Bleichenbacher / PKCS#1 v1.5 RSA 填充预言机](#bleichenbacher--pkcs1-v15-rsa-padding-oracle)
- [生日攻击 / 中间相遇](#birthday-attack--meet-in-the-middle)
- [基于 CRC32 碰撞的签名伪造（iCTF 2013）](#crc32-collision-based-signature-forgery-ictf-2013)
- [逐字节清零预言机恢复 AES 密钥（CONFidence CTF 2017）](#aes-key-recovery-via-byte-by-byte-zeroing-oracle-confidence-ctf-2017)
- [AES-CTR 固定计数器 / 重复密钥流（SHA2017）](#aes-ctr-constant-counter--repeating-keystream-sha2017)
- [自定义 SPN 的按列 XOR 暴力（Hack Dat Kiwi 2017）](#custom-spn-column-wise-xor-brute-force-hack-dat-kiwi-2017)
- [AES-CTR Bitflip + CRC 线性签名伪造（hxp CTF 2017）](#aes-ctr-bitflip--crc-linearity-signature-forgery-hxp-ctf-2017)
- [通过错误信息解密预言机伪造 AES-CBC 密文（Nuit du Hack CTF 2018）](#aes-cbc-ciphertext-forging-via-error-message-decryption-oracle-nuit-du-hack-ctf-2018)
- [用于 PDF 签名伪造的 SHA-1 选择前缀碰撞（DEF CON Quals 2018）](#sha-1-chosen-prefix-collision-for-pdf-signature-forgery-def-con-quals-2018)
- [哈希链原像认证绕过（picoCTF 2017）](#hash-chain-preimage-authentication-bypass-picoctf-2017)
- [通过块边界对齐去除 AES-CBC Nonce（Trend Micro 2018）](#aes-cbc-nonce-strip-via-block-boundary-alignment-trend-micro-2018)

另见 [modern-ciphers-2.md](modern-ciphers-2.md)，其中包含 CRC32 伪造、Blum-Goldwasser、哈希长度扩展、压缩预言机、哈希时间反演、可逆 RNG 的 OFB、弱密钥派生、HMAC-CRC、DES 弱密钥、SRP 绕过、修改版 AES S 盒、square attack、AES-ECB 逐字节攻击、AES-ECB 剪贴拼接、AES-CBC IV bit-flip、Rabin LSB 奇偶预言机、PBKDF2 预哈希绕过、MD5 多重碰撞、自定义哈希状态反演和 CRC32 暴力。

---

## AES-CFB-8 Static IV State Forging

**模式（Cleverly Forging Breaks）：** 使用 8-bit feedback 且复用 IV 的 AES-CFB 允许重建内部状态。

**关键点：** 只要加密过 16 个已知字节，AES 内部移位寄存器状态就完全由这些密文字节确定。此后可以从该已知状态继续“加密”，伪造新的密文。

---

## ECB Pattern Leakage on Images

**模式（Electronic Christmas Book）：** 把 AES-ECB 直接用在 BMP / 图像数据上，会保留视觉模式。

**利用方式：** 相同的明文分组会产生相同的密文分组，因此即便内容被加密，图像结构仍会显形。可以直接肉眼观察，或重排、标记相同分组模式。

---

## Padding Oracle Attack

**模式（The Seer）：** 服务端会泄露“解密后的填充是否合法”。

**逐字节解密：**
```python
def decrypt_byte(block, prev_block, position, oracle, known):
    """known = bytearray(16)，用于记录当前块已恢复出的 intermediate 字节。"""
    for guess in range(256):
        modified = bytearray(prev_block)
        # 设置已知字节，使其形成合法填充
        pad_value = 16 - position
        for j in range(position + 1, 16):
            modified[j] = known[j] ^ pad_value
        modified[position] = guess
        if oracle(bytes(modified) + block):
            return guess ^ pad_value
```

---

## CBC-MAC vs OFB-MAC Vulnerability

OFB 模式会生成一个与明文无关的密钥流，因此可以被 XOR 出来用于伪造签名。

**攻击方式：** 如果已知明文 `P1` 的签名，可为 `P2` 伪造签名：
```text
new_sig = known_sig XOR block2_of_P1 XOR block2_of_P2
```

**重要：** 计算时不要忘记 PKCS#7 填充。如果未知空间很小，直接暴力即可（例如 2 个未知数字时只需试 100 种组合）。

**关键点：** OFB-MAC 的密钥流与明文无关，因此只要拿到一组 `(message, MAC)`，就能把原消息的分组 XOR 掉，再 XOR 进新消息分组，从而伪造任意 MAC。CBC-MAC 则没有这个问题，因为每一块的加密都依赖前一块密文。

---

## Non-Permutation S-box Collision Attack

**模式（Tetraes, Nullcon 2026）：** 某个类 AES 自定义密码使用了存在碰撞的 S 盒。

**检测方法：** 如果 `len(set(sbox)) < 256`，就说明 S 盒不是置换，存在碰撞。先找出碰撞对及其 XOR 差值。

**攻击思路：** 对每个密钥字节，尝试 256 个相差 `delta` 的明文。当 `ct1 == ct2` 时，说明 S 盒输入落在碰撞集合里。每字节只剩 2 路歧义，整体可用 `2^16` 暴力，总查询数约 4,097 次。

完整的 S 盒碰撞分析代码见 [advanced-math.md](advanced-math.md)。

---

## LCG Partial Output Recovery (0xFun 2026)

**已知参数时：** 如果 LCG 的参数 `(M, A, C)` 已知，而输出是 `state mod N`，就按 N 的步长在模空间内枚举状态候选：
```python
# output = state % N, state = (A * prev + C) % M
for candidate in range(output, M, N):
    # 检查 candidate 是否与下一次输出一致
    next_state = (A * candidate + C) % M
    if next_state % N == next_output:
        print(f"State: {candidate}")
```

**只泄露高位时（例如 64 bit 状态的高 32 bit）：**
```python
for low in range(2**32):
    state = (observed_upper << 32) | low
    next_state = (A * state + C) % M
    if (next_state >> 32) == next_observed_upper:
        print(f"Full state: {state}")
```

**关键点：** LCG 的输出截断（只取模、只取高位）只是隐藏了部分状态，但连续输出会把这部分信息重新约束起来。若输出是 `state mod N`，就按 N 遍历整个模数空间；若只看见高位，就暴力低位并用下一个输出来验证。

---

## Weak Hash Functions / GF(2) Gaussian Elimination

只由 XOR 和轮转构成的线性置换，可直接转化为 GF(2) 线性代数问题。把变换写成矩阵，再在 GF(2) 上求逆即可。

```python
import numpy as np

def solve_gf2(A, b):
    """在 GF(2) 上求解 Ax = b。"""
    m, n = A.shape
    Aug = np.hstack([A, b.reshape(-1, 1)]) % 2
    pivot_cols, row = [], 0
    for col in range(n):
        pivot = next((r for r in range(row, m) if Aug[r, col]), None)
        if pivot is None: continue
        Aug[[row, pivot]] = Aug[[pivot, row]]
        for r in range(m):
            if r != row and Aug[r, col]: Aug[r] = (Aug[r] + Aug[row]) % 2
        pivot_cols.append((row, col)); row += 1
    if any(Aug[r, -1] for r in range(row, m)): return None
    x = np.zeros(n, dtype=np.uint8)
    for r, c in reversed(pivot_cols):
        x[c] = Aug[r, -1] ^ sum(Aug[r, c2] * x[c2] for c2 in range(c+1, n)) % 2
    return x
```

**关键点：** 若一个哈希函数只使用 XOR 和轮转（没有 S 盒、没有模加），那它在 GF(2) 上就是线性的。把整个变换表示成二进制矩阵，再做高斯消元，就能直接求原像。这类“避免非线性运算的自定义哈希”通常一碰就碎。

---

## Affine Cipher over Composite Modulus (Nullcon 2026)

仿射加密 `c = A*x + b (mod M)` 当 M 为复合数时，可以拆到各个素因子域里分别求逆，再用 CRT 合并。完整的选择明文恢复与实现见 [advanced-math.md](advanced-math.md#affine-cipher-over-non-prime-modulus-nullcon-2026)。

---

## AES-GCM with Derived Keys (EHAX 2026)

**模式：** 在前面的密码挑战中先恢复出某个 secret（如 LWE 或密钥交换产物），然后通过 SHA-256 从这个 secret 再派生 session nonce 和 AES 密钥，最后做 AES-GCM 解密。

```python
import hashlib
from Cryptodome.Cipher import AES

# 常见的密钥派生链：
# 1. 从上游密码题中恢复出 secret bytes（s_bytes）
# 2. 解开 session nonce：nonce = wrapped_nonce XOR SHA256(s_bytes)[:nonce_len]
# 3. 派生 AES key：key = SHA256(s_bytes + session_nonce)
# 4. 解密 AES-GCM

def decrypt_with_derived_key(s_bytes, wrapped_nonce, ciphertext, aes_nonce, tag, nonce_len=16):
    secret_hash = hashlib.sha256(s_bytes).digest()
    session_nonce = bytes(a ^ b for a, b in zip(wrapped_nonce, secret_hash[:nonce_len]))
    aes_key = hashlib.sha256(s_bytes + session_nonce).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

**关键点：** 如果 AES-GCM 报 `ValueError: MAC check failed`，通常不是 GCM 本身的问题，而是上游恢复的 secret 有误，或者字节序搞反了。

---

## AES-GCM Nonce Reuse / Forbidden Attack

AES-GCM（Galois/Counter Mode）把 AES-CTR 加密和 GHASH 多项式认证拼在一起。同一把 key 下复用 nonce 是灾难性的，会同时破坏机密性和完整性。

**CTR 密钥流复用：** 相同 nonce 会得到相同密钥流，因此 `C1 XOR C2 = P1 XOR P2`。只要一条消息有已知明文，另一条就能直接恢复。

**GHASH 认证密钥恢复：** 认证 tag 是在 GF(2^128) 上对消息做多项式求值。两条使用相同 nonce 的消息会给出关于同一个认证密钥 `H` 的两条方程。把两条 tag 多项式相减，再在 GF(2^128) 上因式分解，就能恢复 `H`。拿到 `H` 后即可伪造任意消息的合法 tag。

```python
from Crypto.Cipher import AES
from sage.all import GF, PolynomialRing

# 已知：两组 (ciphertext, tag, nonce) 使用了同一 nonce
# 第 1 步：利用 CTR 密钥流复用恢复明文
keystream = xor(known_plaintext, ciphertext1)
plaintext2 = xor(keystream, ciphertext2)

# 第 2 步：恢复 GHASH 认证密钥 H
# 在 GF(2^128) 上构造 tag 差分多项式
F = GF(2**128, 'x', modulus=...)  # GCM 多项式
# T1 XOR T2 = P(H)，其中 P 来自密文差异
# 分解 P(H) = 0，得到 H 候选
# 再用已知 tag 验证候选

# 第 3 步：为任意消息伪造 tag
# 用恢复出的 H 计算 GHASH(H, aad, ciphertext)
```

**工具：** [nonce-disrespect](https://github.com/nonce-disrespect/nonce-disrespect) 能自动完成 GHASH 密钥恢复和 tag 伪造。

**短 nonce 暴力：** 如果 GCM 使用极短 nonce（1-4 字节），且 key 已知，那么 nonce 空间本身也可以直接暴力。1 字节 nonce 只有 256 种可能。

**关键点：** AES-GCM 是“nonce 一次一用”方案。只要出现一次 nonce 复用，CTR 会失去保密性，GHASH 会失去认证性。分析题目流量时，一定先检查是否有重复 nonce。

---

## Ascon-like Reduced-Round Differential Cryptanalysis (srdnlenCTF 2026)

**模式（Lightweight）：** 某个类 Ascon 的 4 轮置换，扩散不足。输出 bit 差分上存在与密钥相关的偏置，可通过选择输入差分恢复密钥位。

**攻击流程：**
1. 精确复现置换实现（尤其注意 S-box 后 `x4` 的赋值顺序）
2. 用预计算好的 64×64 GF(2) 逆矩阵，反转 `x0` 的线性层
3. 对每个 bit 位置 `i`，使用差分 `diff = (1<<i, 1<<i)` 做多次查询
4. 测量输出位 `j1 = (i+1) mod 64` 和 `j2 = (i+14) mod 64` 的经验偏置
5. 用带符号掩码的质心聚类，把 `(k0[i], k1[i])` 分类出来
6. 在同一会话里验证候选 key；对边缘样本位补充更多查询

**GF(2) 线性层求逆：**
```python
def build_inverse(shifts=(19, 28)):
    """为类 Ascon 线性层构造 GF(2) 逆矩阵：x ^= rot(x,19) ^ rot(x,28)。"""
    # 构造 GF(2) 上的 64x64 矩阵
    M = [[0]*64 for _ in range(64)]
    for out_bit in range(64):
        M[out_bit][out_bit] = 1
        for shift in shifts:
            M[out_bit][(out_bit + shift) % 64] ^= 1
    # 高斯消元求逆
    aug = [row + [1 if i == j else 0 for j in range(64)] for i, row in enumerate(M)]
    for col in range(64):
        pivot = next(r for r in range(col, 64) if aug[r][col])
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(64):
            if r != col and aug[r][col]:
                aug[r] = [a ^ b for a, b in zip(aug[r], aug[col])]
    return [row[64:] for row in aug]
```

**用质心聚类分类 key bit：**
```python
# 对每个位位置，测量两个输出位置上的偏置
# (k0[i], k1[i]) 有 4 种可能，对应 4 个质心
# 使用符号模式掩码 CMASK=0x73 处理不同 bit 位置的行为差异
# 在二维偏置空间中按欧氏距离最近分类
CMASK = 0x73
for i in range(64):
    bias_j1, bias_j2 = measure_biases(i, samples)
    mask_bit = (CMASK >> (i % 8)) & 1
    centroids = centroid_table[mask_bit]  # 每种位置预计算的质心
    k0_bit, k1_bit = min(range(4), key=lambda c: euclidean_dist(
        (bias_j1, bias_j2), centroids[c]))
```

**关键点：** 约减轮的轻量密码（Ascon、GIFT 等）在轮数不够时，扩散不完全，差分偏置会落到单个密钥位上。线性层可代数反演，差分偏置可通过选择明文查询统计出来，即便样本有噪声也能在足够多观测下恢复。

---

## Custom Linear MAC Forgery (Nullcon 2026)

**模式（Pasty）：** 服务端对 paste ID 使用一个自定义的 SHA-256 派生构造签名。签名对由 key 派生出的三个 8-byte secret block 是线性的。

**结构：** 对每个 8-byte 输出块 `i`：
- `selector = SHA256(id)[i*8] % 3`，决定使用哪个 secret block
- `out[i] = hash_block[i] XOR secret[selector] XOR chain[i-1]`

**恢复：** 生成约 10 个 paste，收集 `(id, sig)` 对。每对会暴露出 4 个 selector 对应的 `secret[selector]`。通常 4-5 对就足以恢复全部 3 个 secret block，之后即可为目标 ID 伪造签名。

**关键点：** 任何基于 XOR 的“自定义签名 / MAC”一旦对 secret block 线性，就几乎等于没保护。先判断是否满足“已知秘密分量后可为任意输入重算签名”这一属性。

---

## CBC Padding Oracle Attack

**模式：** 服务端通过错误信息、计时或状态码泄露 CBC 密文的 PKCS#7 填充是否合法，从而可在不知道密钥的情况下逐块解密任意密文。

```python
from pwn import *

def padding_oracle(iv, ct):
    """若服务端接受填充则返回 True。"""
    resp = requests.post(URL, data={'iv': iv.hex(), 'ct': ct.hex()})
    return 'padding' not in resp.text.lower()  # 或检查状态码

def decrypt_block(prev_block, target_block):
    """使用填充预言机解密一个 16 字节块。"""
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    for byte_pos in range(15, -1, -1):
        pad_val = 16 - byte_pos
        # 设置已知字节，构造合法填充
        crafted = bytearray(16)
        for k in range(byte_pos + 1, 16):
            crafted[k] = intermediate[k] ^ pad_val

        for guess in range(256):
            crafted[byte_pos] = guess
            if padding_oracle(bytes(crafted), target_block):
                intermediate[byte_pos] = guess ^ pad_val
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                break

    return bytes(plaintext)
```

**工具：**
```bash
# PadBuster —— 自动化利用填充预言机
padbuster http://target/decrypt.php ENCRYPTED_B64 16 \
  -encoding 0 -error "Invalid padding"

# Python: pip install padding-oracle
from padding_oracle import PaddingOracle
oracle = PaddingOracle(block_size=16, oracle_fn=check_padding)
plaintext = oracle.decrypt(ciphertext, iv=iv)
```

**关键点：** 预言机只需区分“合法填充”与“非法填充”即可。它可以是不同 HTTP 状态码、报错内容、响应时间，甚至只是后续流程是否继续执行。每次查询只泄露 1 bit，也足以完成解密。每个 16 字节块最多约需 `256 x 16 = 4096` 次查询。

**识别方式：** 只要是 CBC 加密，并且填充出错时存在任何可区分的行为差异，就值得优先怀疑。常见于 cookie、token 和加密 API 参数。

---

## Bleichenbacher / PKCS#1 v1.5 RSA Padding Oracle

**模式：** 使用 PKCS#1 v1.5 填充的 RSA 加密，服务端会泄露解密结果是否具有合法的 `0x00 0x02` 前缀。于是可做自适应选择密文攻击恢复明文。

```python
import gmpy2

def bleichenbacher_oracle(c, n, e):
    """如果 RSA 解密后的 PKCS#1 v1.5 填充合法（0x00 0x02 前缀），则返回 True。"""
    resp = send_to_server(c)
    return resp.status_code != 400  # 填充错误时服务端返回 400

def bleichenbacher_attack(c0, n, e, oracle, k):
    """
    c0: 目标密文（整数）
    k: 模数的字节长度（例如 RSA-2048 时为 256）
    """
    B = pow(2, 8 * (k - 2))

    # 第 1 步：从 s1 = ceil(n / 3B) 开始
    s = (n + 3 * B - 1) // (3 * B)

    # 第 2 步：寻找使 oracle(c0 * s^e mod n) 为 True 的 s
    while True:
        c_prime = (c0 * pow(s, e, n)) % n
        if oracle(c_prime, n, e):
            break
        s += 1

    # 第 3 步：利用 s 缩小区间 [a, b]
    # 不断寻找新的 s，持续收缩区间，直到 a == b
    # 当区间塌缩时，plaintext = a * modinv(s, n) % n
    # （完整实现需要维护区间集合，建议直接用现成工具）
```

**工具：**
```bash
# ROBOT 攻击扫描器（Bleichenbacher 的现代变种）
python3 robot-detect.py -H target.com

# TLS-Attacker 框架
java -jar TLS-Attacker.jar -connect target:443 -workflow_type BLEICHENBACHER
```

**关键点：** 这是一个自适应攻击，每次预言机响应都会缩小候选明文区间。对 RSA-2048 通常需要约 10,000 次查询。ROBOT（Return Of Bleichenbacher's Oracle Threat）证明，即便是现代 TLS 实现，也会因细微计时差异重新暴露这一漏洞。只要服务端能区分“坏填充”和“坏内容”，就有风险。

---

## Birthday Attack / Meet-in-the-Middle

**模式：** 利用生日悖论，为哈希或 MAC 寻找碰撞。n 位哈希通常在约 `2^(n/2)` 次随机尝试后就会出现碰撞。

```python
import hashlib, os

def birthday_collision(hash_fn, output_bits, prefix=b''):
    """找到两个输入，使其截断哈希相同。"""
    target_bytes = output_bits // 8
    seen = {}

    while True:
        msg = prefix + os.urandom(16)
        h = hash_fn(msg).digest()[:target_bytes]
        if h in seen:
            return seen[h], msg  # 找到碰撞
        seen[h] = msg

# 例子：在 SHA-256 前 4 个字节上找碰撞（约 65536 次尝试）
msg1, msg2 = birthday_collision(hashlib.sha256, 32)
```

**中间相遇（2DES、双重加密）：**
```python
def meet_in_the_middle(encrypt_fn, decrypt_fn, plaintext, ciphertext, keyspace):
    """破解双重加密 E(k2, E(k1, pt)) = ct。"""
    # 正向：用所有可能的 k1 加密明文
    forward = {}
    for k1 in keyspace:
        intermediate = encrypt_fn(k1, plaintext)
        forward[intermediate] = k1

    # 反向：用所有可能的 k2 解密密文
    for k2 in keyspace:
        intermediate = decrypt_fn(k2, ciphertext)
        if intermediate in forward:
            return forward[intermediate], k2  # 找到 k1, k2
```

**关键点：** 生日攻击中，n 位哈希达到 50% 碰撞概率约需 `2^(n/2)` 次尝试。中间相遇则把双重加密从 `O(2^(2k))` 降到 `O(2^k)` 时间和 `O(2^k)` 空间，这也是为什么 2DES 的安全性并没有翻倍。

---

## CRC32 Collision-Based Signature Forgery (iCTF 2013)

**模式：** CRC32 是线性的。向任意消息追加 4 个精心构造的字节，就能把 CRC32 调整到目标值，从而伪造签名，而无需知道 secret。

**关键点：** `CRC32(msg || secret)` 根本不是 MAC。只要拿到一组有效 `(msg, sig)`，就能计算出 4 个后缀字节，使 `CRC32(forged_msg || suffix || secret) == target_sig`。由于 CRC32 在线性空间里可预测，这个后缀是确定且可快速求出的。

```python
import struct, binascii

def crc32_forge(data, target_crc):
    """在 data 后追加 4 个字节，使 CRC32(data + suffix) == target_crc"""
    current = binascii.crc32(data) & 0xFFFFFFFF
    # 通过 CRC32 多项式查表或多项式除法找到修正后缀
    suffix = b''
    crc = target_crc ^ 0xFFFFFFFF
    for _ in range(4):
        byte = (crc & 0xFF)
        crc = (crc >> 8)
        suffix = bytes([byte]) + suffix
    return data + suffix  # 这里是简化版；完整实现要做多项式除法
```

**适用场景：** 任何把 CRC32 当作消息认证码的协议。CRC32 只是校验和，不是密码学哈希，对对抗性篡改没有任何完整性保证。

---

## AES Key Recovery via Byte-by-Byte Zeroing Oracle (CONFidence CTF 2017)

**模式：** 当服务允许“选择性把密钥某些字节清零”（例如 key slot 索引计算中的整数溢出）时，可以逐字节恢复完整 AES key。

```python
# 服务维护 key slots，并提供一个带整数溢出的“regenerate”功能
# offset = index * ENTRY_SIZE 发生回绕，从而可把任意位置清零

# 思路：逐步把除一个字节外的所有字节清零，然后暴力该未知字节
for byte_pos in range(16):
    # 通过索引回绕清零除 byte_pos 之外的所有字节
    zero_index = (target_offset * modinv(ENTRY_SIZE, 2**32)) % 2**32
    regenerate(zero_index)

    # 这时密钥形如：[0,0,...,key[byte_pos],...,0,0]
    # 只需暴力一个字节（256 种）
    known_ct = encrypt(known_pt)
    for guess in range(256):
        test_key = bytes([0]*byte_pos + [guess] + [0]*(15-byte_pos))
        if AES.new(test_key, AES.MODE_ECB).encrypt(known_pt) == known_ct:
            recovered_key[byte_pos] = guess
            break
```

**关键点：** `index * ENTRY_SIZE` 的整数溢出常可让攻击者跨越边界写到任意偏移。通过“把除一个字节外的所有 key 字节都清零”，完整 128 bit 搜索就变成 16 次单字节暴力，总共 4096 次测试。

**参考：** CONFidence CTF 2017

---

## AES-CTR Constant Counter / Repeating Keystream (SHA2017)

**模式：** 某 AES-CTR 实现把 `counter=lambda: secret` 写成常量函数，导致计数器永远不递增。此时每次都会使用同一个 16-byte keystream block，本质上退化为 16 字节循环密钥的维吉尼亚 / XOR 密码。

```python
# 固定计数器使 CTR 等价于重复密钥 XOR
key_byte = ciphertext_byte ^ known_plaintext_byte
# 将恢复出的密钥流字节应用到所有按 16 字节对齐的位置
for i, ct_byte in enumerate(ciphertext):
    plaintext_byte = ct_byte ^ keystream[i % 16]
```

**结合文件头利用：**
1. 根据上下文识别文件格式（如 PDF 的 `%PDF-1.`）
2. 用已知文件头与密文 XOR，恢复 `keystream[0:len(header)]`
3. 递推扩展：用已经恢复出的明文去猜下一个结构关键字（如 `endobj`、`/Page`、`stream`），若 XOR 后仍是合理 ASCII，则继续扩展密钥流
4. 工具：`otp_pwn` 支持这种按块对齐的交互式 crib-dragging

**关键点：** 固定 counter 的 AES-CTR 就是重复 16 字节密钥的流密码。任何已知的块对齐明文都会直接泄露对应位置的 keystream。

**参考：** SHA2017

---

## Custom SPN Column-Wise XOR Brute-Force (Hack Dat Kiwi 2017)

**模式：** 某个 SPN（Substitution-Permutation Network）密码使用基于 seed 的 sbox / pbox，并在最后叠加一层逐列 XOR key。如果每个 key 字节只影响一个列位置，就可以把每个 key byte 独立暴力，并用“解密后是否可打印”作预言机。

**攻击步骤：**
1. 收集多组密文块（同一把 key，不同明文）
2. 对每个列位置 `c`（0-15），枚举所有 256 个候选 key byte `k`
3. 应用逆 pbox 和逆 sbox，回退 SPN 轮，然后与候选 `k` XOR
4. 保留那些使**所有**块在位置 `c` 上都落入可打印 ASCII 的候选
5. 把多个块上的有效候选取交集，恢复该列字节

**多轮变体：** 先恢复最外层 XOR key，再利用已知 key 回退一轮 pbox / sbox，然后继续往内层剥。

**seed 驱动置换的依赖性：** 如果 sbox 和 pbox 来自同一个 seed，那么恢复一部分 key 字节后，就会对 seed 以及其余置换项形成额外约束，可把跨列信息传播开来。

**关键点：** 只要 XOR 层按列独立，SPN 就能被拆成多个单字节搜索。若置换还是 seed 生成的，部分解会进一步约束其它列。

**参考：** Hack Dat Kiwi 2017

---

## AES-CTR Bitflip + CRC Linearity Signature Forgery (hxp CTF 2017)

**模式：** AES-CTR 允许对明文做定向 XOR 修改，而 CRC 对 XOR 是线性的：`CRC(A ^ B) = CRC(A) ^ CRC(B) ^ CRC(zeros)`。因此可以把 `{admin: 0}` 翻成 `{admin: 1}`，同时修复对应的加密 CRC。

```python
import binascii
# X = desired_plaintext XOR original_plaintext（即想要翻转的 bit）
X = b'\x00' * offset + b'\x01' + b'\x00' * remaining
crc_diff = binascii.crc32(X) ^ binascii.crc32(b'\x00' * len(X))
# 新密文 = 旧密文 XOR X（数据部分）
# 新 CRC 密文 = 旧 CRC 密文 XOR pack(crc_diff)
```

**关键点：** CRC 在 GF(2) 上是线性的，因此对明文做 XOR 修改时，CRC 的变化量也是可预测的。只要系统把 AES-CTR 当保密层、把 CRC 当完整性层，而不是使用真正的 MAC / AEAD，就能同时翻内容和修校验。

**参考：** hxp CTF 2017

---

### AES-CBC Ciphertext Forging via Error-Message Decryption Oracle (Nuit du Hack CTF 2018)

**模式：** 服务端会解密 AES-CBC cookie，并把解密结果打印进错误信息。向它发送全零块，从报错里读取中间值，再与目标明文 XOR，即可逐块伪造任意密文。这里常被用来通过加密 cookie 递送 blind SQLi 载荷。（Nuit du Hack CTF 2018）

```python
# 为任意明文伪造密文
for i in range(blocks):
    payload = b'\x00' * 16 * (blocks - 1) + last_forged_block
    response = send_payload(payload)
    decrypted = parse_error_message(response)  # 服务端泄露解密字节
    intermediate = decrypted[-16:]
    new_block = xor(target_plaintext_block, intermediate)
    forged_blocks.append(new_block)
```

**关键点：** 只要错误信息里泄露了解密值，就能在不知道 key 的情况下伪造任意明文。思路是：发零块得到 intermediate state，再与目标明文 XOR，最后从后往前逐块构造。

---

## SHA-1 Chosen-Prefix Collision for PDF Signature Forgery (DEF CON Quals 2018)

**模式（EmojiVote）：** 服务端先对上传的 PDF 做 OCR，从中提取命令，然后签名 `sha1(data)`。可以使用 shattered 风格的 SHA-1 选择前缀碰撞，构造两个 OCR 结果不同但 SHA-1 相同的 PDF。

**利用流程：**
1. 构造 PDF A，其 OCR 结果是良性命令（不含 `EXECUTE`）
2. 构造 PDF B，其 OCR 结果是 `EXECUTE <attacker command>`
3. 用 chosen-prefix collision 工具给两者补上碰撞后缀，使 `sha1(A) == sha1(B)`
4. 提交 A，拿到合法签名
5. 把该签名回放到 B 上，服务器只会验摘要，于是执行攻击者命令

```bash
# 生成一对碰撞 PDF（cpc = chosen-prefix collision 工具）
./cpc prefix_A prefix_B collision_A.pdf collision_B.pdf
sha1sum collision_A.pdf collision_B.pdf  # 相同
# 上传 A 取签名，再拿签名去提交 B
```

**关键点：** 只要协议签的是 `sign(sha1(M))` 而不是带强绑定的更安全构造，那么任何 SHA-1 碰撞都会变成签名伪造。选择前缀碰撞已经是实用攻击。

**参考：** DEF CON CTF Qualifier 2018，writeup 10075

---

## Hash Chain Preimage Authentication Bypass (picoCTF 2017)

**模式（hash_chain）：** 服务端在第 N 轮要求你给出 `hash^(N-1)(seed)`，前提是它已知 `hash^N(seed)`。而 seed 又可由公开信息（如 `md5(username)`）导出，因此攻击者可以从头预计算整条链并回答任意轮次。

**利用：**
```python
import hashlib

def H(x): return hashlib.md5(x).digest()

seed = H(username.encode())        # 公开可导出的 seed
chain = [seed]
for _ in range(TARGET_N + 1):
    chain.append(H(chain[-1]))

# 服务端发来 chain[N]，你的回答应该是 chain[N-1]
```

**关键点：** 哈希链只有在 seed 保密时才具备单向性。一旦 seed 可以由公开输入重建（用户名、挑战 ID、时间戳等），整条链就能被正向预计算，“给我前一个哈希”这种认证瞬间失效。

**参考：** picoCTF 2017，writeup 10031

---

## AES-CBC Nonce Strip via Block Boundary Alignment (Trend Micro 2018)

**模式：** 服务端加密 `nonce | padding | identity | timestamp` 并返回 `(iv, ciphertext)`。如果攻击者能控制填充，使得前**恰好一个** 16 字节分组只包含 nonce，那么把 `ciphertext[:16]` 提升为新的 IV，并把 `ciphertext[16:]` 当作新的密文，就会得到一个合法加密，内容只剩 `identity | timestamp`。不需要 key，因为 CBC 第 2 块的解密是 `AES⁻¹(c[16:32]) XOR c[0:16]`，而这正好等于去掉 nonce 后的目标明文。

```python
from Crypto.Cipher import AES
import os

key = os.urandom(16)

# 服务端构造明文并加密
def encrypt_with_nonce(identity, timestamp):
    nonce = os.urandom(8)
    padding = b"\x00" * 8          # 使 nonce + padding 正好凑成 16 字节
    plaintext = nonce + padding + identity + timestamp
    iv = os.urandom(16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
    return iv, ct

iv, ct = encrypt_with_nonce(b"admin___________", b"2018-11-01T00:00")

# 攻击者重写 (iv', ct')，移除 nonce 块
new_iv = ct[:16]
new_ct = ct[16:]
recovered = AES.new(key, AES.MODE_CBC, new_iv).decrypt(new_ct)
assert recovered.startswith(b"admin")
```

**关键点：** CBC 只在第一块使用显式 IV，后续每一块都把前一块密文当作“隐式 IV”。所以任何连续的 CBC 密文切片，只要把它前一块提升成新的 IV，就是一个合法的新 CBC 密文。若固定长度头（nonce、magic、counter）刚好占一个块，就可以被这样“剥掉”。防御方式是把这些头字段纳入 AEAD / HMAC 的认证范围。

**参考：** Trend Micro CTF 2018，Offensive-Analysis 400，writeup 11130
