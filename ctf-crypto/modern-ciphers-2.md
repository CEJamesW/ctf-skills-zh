# CTF Crypto - 现代密码攻击（续）

哈希类攻击、协议层利用、ECB 预言机、Rabin / RSA 奇偶预言机，以及一些特殊密码弱点。核心的 AES / CBC / 填充预言机技巧见 [modern-ciphers.md](modern-ciphers.md)。流密码攻击见 [stream-ciphers.md](stream-ciphers.md)。

## Table of Contents
- [Blum-Goldwasser 比特扩展预言机（PlaidCTF 2013）](#blum-goldwasser-bit-extension-oracle-plaidctf-2013)
- [哈希长度扩展攻击（PlaidCTF 2014）](#hash-length-extension-attack-plaidctf-2014)
- [压缩预言机 / CRIME 风格攻击（BCTF 2015）](#compression-oracle--crime-style-attack-bctf-2015)
- [通过环检测反转哈希时间演化（BSidesSF 2025）](#hash-function-time-reversal-via-cycle-detection-bsidessf-2025)
- [可逆 RNG 的 OFB 逆向解密（BSidesSF 2026）](#ofb-mode-with-invertible-rng-backward-decryption-bsidessf-2026)
- [通过公钥哈希 XOR 的弱密钥派生（BSidesSF 2026）](#weak-key-derivation-via-public-key-hash-xor-bsidessf-2026)
- [HMAC-CRC 线性攻击（Boston Key Party 2016）](#hmac-crc-linearity-attack-boston-key-party-2016)
- [OFB 模式中的 DES 弱密钥（Boston Key Party 2016）](#des-weak-keys-in-ofb-mode-boston-key-party-2016)
- [利用模运算绕过 SRP（ASIS CTF Finals 2016）](#srp-secure-remote-password-protocol-bypass-via-modular-arithmetic-asis-ctf-finals-2016)
- [修改版 AES S 盒暴力恢复（H4ckIT CTF 2016）](#modified-aes-s-box-brute-force-recovery-h4ckit-ctf-2016)
- [约减轮 AES 的 Square Attack（0CTF 2016）](#square-attack-on-reduced-round-aes-0ctf-2016)
- [AES-ECB 逐字节选择明文攻击（ABCTF 2016）](#aes-ecb-byte-at-a-time-chosen-plaintext-abctf-2016)
- [AES-ECB 剪贴拼接分组操纵（NDH Quals 2016）](#aes-ecb-cut-and-paste-block-manipulation-ndh-quals-2016)
- [AES-CBC IV Bit-Flip 认证绕过（Google CTF 2016）](#aes-cbc-iv-bit-flip-authentication-bypass-google-ctf-2016)
- [Rabin 密码体制 LSB 奇偶预言机（PlaidCTF 2016）](#rabin-cryptosystem-lsb-parity-oracle-plaidctf-2016)
- [针对长口令的 PBKDF2 预哈希绕过（BackdoorCTF 2016）](#pbkdf2-pre-hash-bypass-for-long-passwords-backdoorctf-2016)
- [利用 Fastcol 的 MD5 多重碰撞（BackdoorCTF 2016）](#md5-multi-collision-via-fastcol-backdoorctf-2016)
- [素数模上的 GHASH 密钥恢复（nullcon HackIM 2019）](#ghash-key-recovery-over-prime-modulus-nullcon-hackim-2019)
- [SHA-1 长度扩展 + AES-CBC Cookie 伪造（BSidesSF 2019）](#sha-1-length-extension-plus-aes-cbc-cookie-forgery-bsidessf-2019)

更偏后期的自定义哈希反演、CRC32 暴力、带噪声的 RSA 预言机、海绵碰撞、CBC IV 伪造、padding oracle + bit-flip、SPN S 盒交集、AES-CFB IV 恢复、three-round XOR、Unicode 侧信道、SHA-256 basis attack、HMAC 密钥恢复等见 [modern-ciphers-3.md](modern-ciphers-3.md)。

---

## Blum-Goldwasser Bit-Extension Oracle (PlaidCTF 2013)

**模式：** 利用 Blum-Goldwasser 风格加密的解密预言机，通过每次把密文长度扩展 1 bit 来泄露明文奇偶。

**关键点：** 把密文长度从 L 扩到 L+1，做左移 `c << 1`，并提交一个修改后的 `y`。预言机会泄露解密结果每段的最低位。通过控制平方序列 `y = pow(y, 2, N)`，可以不断制造服务端没见过的“合法扩展密文”。

```python
# 通过 bit-extension 迭代恢复明文
for i in range(msg_length):
    extended_c = original_c << 1        # 密文左移 1 bit
    new_y = pow(original_y, 2, N)       # 推进平方序列
    response = oracle(extended_c, new_y, msg_length + 1)
    leaked_bit = response & 1           # LSB 泄露一个明文 bit
    plaintext_bits.append(leaked_bit)
    original_y = new_y
```

**适用场景：** Blum-Goldwasser 或基于 BBS（Blum Blum Shub）的加密题，只要解密预言机接受可变长度密文并返回奇偶信息，就可以这样逐 bit 累积恢复。

---

## Hash Length Extension Attack (PlaidCTF 2014)

**模式：** 服务端使用 MD5、SHA-1 或 SHA-256（Merkle-Damgard 构造）来计算 `hash(SECRET || user_data)`。给定一组合法 hash 和原始数据，即可在不知道 secret 的情况下追加任意数据，并计算新的合法 hash。

```bash
# 使用 HashPump（安装：apt install hashpump）
hashpump --keylength 8 \
  --signature 'ef16c2bffbcf0b7567217f292f9c2a9a50885e01e002fa34db34c0bb916ed5c3' \
  --data 'original_data' \
  --additional ';admin=true'
# 输出：new_signature 和带 padding 的 new_data
```

```python
# Python: hashpumpy
import hashpumpy
new_hash, new_data = hashpumpy.hashpump(
    original_hash, original_data, append_data, secret_length
)
```

**关键点：** Merkle-Damgard 哈希（MD5、SHA-1、SHA-256）按块处理数据，而哈希输出本身就是内部状态。已知 `H(secret || msg)` 后，就能直接继续计算 `H(secret || msg || padding || extension)`。只有 HMAC 这种双层构造天然免疫。若 secret 长度未知，通常试 1-32 即可。

*另见 [ctf-web/auth-infra.md — Hash Length Extension Attack (ASIS CTF 2017)](../ctf-web/auth-infra.md#hash-length-extension-attack-asis-ctf-2017)，那一节展示了同一原语如何用于 Web 认证令牌绕过。*

---

## Compression Oracle / CRIME-Style Attack (BCTF 2015)

**模式：** 服务端先压缩明文（LZW、zlib 等）再加密。通过发送选择明文并观察密文长度变化，可以逐字节泄露未知明文。

```python
import base64

def oracle(plaintext):
    """发送选择明文，返回密文长度。"""
    resp = send_to_server(plaintext)
    return len(base64.b64decode(resp))

# 基线：空输入
base_len = oracle("")

# 逐字节恢复 secret
known = ""
for pos in range(secret_length):
    for c in string.printable:
        candidate = known + c
        length = oracle(candidate)
        if length <= base_len + len(known):  # 压缩得更短 = 命中匹配
            known += c
            break
```

**关键点：** 压缩算法会把重复序列替换成回溯引用。若 `SALT + user_input` 在加密前被压缩，那么你提交与 salt 一部分相同的输入时，压缩后的输出就会更短。CRIME、BREACH、HEIST 都是这一类思路。预言机就是“密文长度”。

---

## Hash Function Time Reversal via Cycle Detection (BSidesSF 2025)

当系统把迭代哈希当作“时间推进函数”（`state_t = H(state_{t-1})`）时，可以借助有限状态空间必然进入环这一性质来“反转时间”：

1. **检测环：** 用 Floyd 龟兔赛跑或 Brent 算法找出环长 L
2. **计算回退步数：** 若想从时间 T 回到更早的 `T_goal`，只需继续前进 `(L - (T - T_goal)) % L` 步

```python
import hashlib

def hash_step(state):
    return hashlib.md5(state).digest()[:8]  # 截断哈希

def find_cycle(start):
    """Brent 环检测：返回 (cycle_length, start_of_cycle)"""
    power = lam = 1
    tortoise = start
    hare = hash_step(start)
    while tortoise != hare:
        if power == lam:
            tortoise = hare
            power *= 2
            lam = 0
        hare = hash_step(hare)
        lam += 1
    # lam = 环长；接着找环起点
    tortoise = hare = start
    for _ in range(lam):
        hare = hash_step(hare)
    mu = 0
    while tortoise != hare:
        tortoise = hash_step(tortoise)
        hare = hash_step(hare)
        mu += 1
    return lam, mu  # 环长, 入环偏移

# 从 T_known 回到 T_goal
cycle_len, _ = find_cycle(known_state)
forward_steps = (cycle_len - (t_known - t_goal)) % cycle_len
state = known_state
for _ in range(forward_steps):
    state = hash_step(state)
# state 现在就是 t_goal 时刻的值
```

**关键点：** 对截断哈希（如 MD5 截到 64 bit），期望环长约为 `2^32`，已经是现实可做的量级。所谓“往回走 N 步”，等价于“沿环再往前走 `L-N` 步”。前提是目标状态已经进入主环，而不在入环前的尾巴上。

---

## OFB Mode with Invertible RNG Backward Decryption (BSidesSF 2026)

**模式（randcrypt）：** 某个自定义分组密码在 OFB 模式下使用自制 RNG 产生密钥流。最后一块明文是已知的零填充，因此会泄露对应的 RNG 状态。若 RNG 状态转移函数可逆（双射），就能把所有更早的状态向后反推出来，从而从尾到头解密整个密文。

```python
def rng_forward(state):
    """自定义 RNG 的正向状态转移（来自题目）。"""
    # 例如：线性同余，或可逆混合
    return (state * A + B) % M

def rng_inverse(state):
    """RNG 的逆函数 —— 恢复前一状态。"""
    return ((state - B) * pow(A, -1, M)) % M

# 最后一块是零填充 → ciphertext XOR 0 = keystream = RNG state
leaked_state = int.from_bytes(ciphertext_blocks[-2], 'big')

# 逆向解密
state = leaked_state
plaintext_blocks = []
for i in range(len(ciphertext_blocks) - 3, -1, -1):
    state = rng_inverse(state)
    pt = xor_bytes(ciphertext_blocks[i], state.to_bytes(block_size, 'big'))
    plaintext_blocks.insert(0, pt)
```

**关键点：** OFB 使加密过程与明文解耦，密钥流完全由初始状态决定。只要任何一个块的明文可预测（填充、头部、魔数），相应的 RNG 状态就会泄露。若 RNG 可逆，这一个状态就足以推回全部状态。

**识别时机：** 自定义 OFB / CTR 模式 + 非标准 PRNG；满足以下至少几点：
1. 加密本质是 XOR
2. 状态更新函数没有信息丢失，可逆
3. 任意位置存在已知明文（填充、文件头、固定结构）

---

## Weak Key Derivation via Public Key Hash XOR (BSidesSF 2026)

**模式（ran-somewhere）：** 某“混合 RSA+AES”设计把 AES key 写成 `SHA256(DER_encoded_public_key) XOR seed`，其中 seed 是硬编码或可预测的。由于公钥本来就是公开的，所以无需 RSA 私钥也能恢复 AES key。

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from hashlib import sha256

# 公钥可直接拿到
pubkey = RSA.import_key(open("public.pem").read())
der_bytes = pubkey.export_key("DER")

# seed 来自题目（硬编码 / 可预测）
seed = b'BSidesSFCTF2026!'

# 按加密器的方式派生 AES key
key_hash = sha256(der_bytes).digest()
aes_key = bytes(a ^ b for a, b in zip(key_hash, seed.ljust(32, b'\x00')))

# 解密
ct = open("flag.enc", "rb").read()
iv, ct_body = ct[:16], ct[16:]
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ct_body)
```

**关键点：** 只使用公有信息（公钥、本来就公开的常量）派生密钥，不管哈希函数多强，安全性都是 0。RSA 私钥根本没有参与 AES key 的生成，这类“混合加密”只是表面像样。

**识别时机：** 题目同时给出公钥和对称加密文件，却完全不给 RSA 私钥或 RSA 密文；或者派生逻辑中明显把公钥 DER / modulus / exponent 直接喂进哈希，再 XOR 常量。

---

## HMAC-CRC Linearity Attack (Boston Key Party 2016)

**模式：** 把 CRC 当作 HMAC 底层哈希会彻底失效，因为 CRC 在 GF(2) 上是线性的。只需一组消息-MAC 对，就能用 GF(2^64) 上的多项式算术恢复 key。

```python
# CRC 线性：CRC(a XOR b) = CRC(a) XOR CRC(b)
# HMAC-CRC(key, msg) = CRC(key_opad || CRC(key_ipad || msg))
# 可重写为 GF(2) 上关于 K 的多项式：
# K = known_terms * inverse(x^(128+M) + x^128) mod CRC_POLY
```

**关键点：** HMAC 是否安全，首先取决于底层哈希是不是非线性的。CRC 这种线性校验和放进 HMAC 只是形式上像 HMAC，实际没有任何抗伪造能力。

---

## DES Weak Keys in OFB Mode (Boston Key Party 2016)

**模式：** DES 存在 4 个弱密钥，满足 `E(E(P,K),K) = P`（即加密自反）。在 OFB 模式下，这会让密钥流周期退化为 2：偶数块 XOR IV，奇数块 XOR `E(IV,K)`。等价于一个 16 字节循环 XOR。

```python
# DES 弱密钥：0x0000000000000000, 0xFFFFFFFFFFFFFFFF,
#             0xE1E1E1E1F0F0F0F0, 0x1E1E1E1E0F0F0F0F
# OFB + 弱密钥：keystream = [IV, E(IV,K), IV, E(IV,K), ...]
# 破解：先试这 4 个弱密钥；或把它当 16 字节循环 XOR
```

**关键点：** 一旦看见 DES + OFB，先把 4 个弱密钥试掉；命中的话密钥流直接坍缩成周期 2。

---

## Square Attack on Reduced-Round AES (0CTF 2016)

**模式：** 4 轮 AES 容易受到 square（integral）攻击。选择 256 个只在一个字节上不同的明文（lambda set）。经过 3 轮后，任意字节位置的 XOR 和都为 0。猜最后一轮 key byte 并部分逆回去，如果 XOR 和为 0，则猜测正确。

```python
# 对最后一轮 key 的每个字节位置：
for candidate in range(256):
    xor_sum = 0
    for ct in ciphertexts:
        xor_sum ^= inv_sub_bytes(ct[pos] ^ candidate)
    if xor_sum == 0:
        key_byte = candidate  # 正确猜测
# 把 2^128 的搜索降成大约 16 * 256 = 4096 次操作
```

**关键点：** 积分密码分析利用的是“平衡性”（XOR 和为 0）在 AES 轮函数中的传播。对 4 轮非常有效；5 轮及以上通常需要更复杂的变体。

---

## SRP (Secure Remote Password) Protocol Bypass via Modular Arithmetic (ASIS CTF Finals 2016)

某些 SRP 实现只检查 `A != 0` 和 `A != N`，于是发送 `A = 2*N` 就能让服务端算出 0 会话密钥。

```python
from hashlib import sha256
import hmac

# SRP 中服务端根据客户端公钥 A 计算共享秘密
# S = (A * v^u) ^ b mod N
# 若 A = 2*N，则 2*N mod N = 0，因此 S = 0

N = server_modulus
# 发送 A = 2*N，可绕过只检查 A != 0 / A != N 的实现
A_malicious = 2 * N

# 服务端得到 S = 0，因此 session key K = SHA256(0)
K = sha256(b'\x00').digest()

# 现在就能用已知的 K 计算合法 HMAC proof
proof = hmac.new(K, salt, sha256).hexdigest()
```

**关键点：** SRP 必须验证的是 `A % N != 0`，而不是只看 `A != 0` 和 `A != N`。任何形如 `A = k*N` 的值都能把共享秘密强制为 0。

---

## Modified AES S-Box Brute-Force Recovery (H4ckIT CTF 2016)

某个 AES 实现只是在标准 S-Box 基础上交换了 3 个元素。这样搜索空间只有 `C(256,3) * 2 = 5,527,040`，完全可以暴力。

```cpp
// 标准 AES S-Box 中有 3 个元素被交换
// 总排列数：C(256,3) * 2 = 约 550 万（可暴力）
#include <openssl/aes.h>

void bruteforce_sbox(uint8_t ciphertext[], uint8_t key[], int ct_len) {
    uint8_t standard_sbox[256]; // 标准 AES S-Box
    // 枚举所有 3 元素交换
    for (int i = 0; i < 256; i++)
        for (int j = i+1; j < 256; j++)
            for (int k = j+1; k < 256; k++) {
                // 在三元组内部尝试交换对：(i,j), (i,k), (j,k)
                uint8_t sbox[256];
                memcpy(sbox, standard_sbox, 256);
                swap(sbox[i], sbox[j]); // 尝试该三元组中的一次两元素交换
                // 解密并检查是否得到合法明文
                if (try_decrypt_with_sbox(sbox, ciphertext, key, ct_len))
                    return; // 找到了
            }
}
```

**关键点：** “自定义 AES S-Box”如果只是对标准 S-Box 做少量交换，搜索空间通常远比想象中小。3 个元素交换的情况完全可暴力。

---

## AES-ECB Byte-at-a-Time Chosen Plaintext (ABCTF 2016)

**模式（Encryption Service）：** 服务端对 `user_input || secret_suffix` 做 AES-ECB。通过控制输入长度，可以一次恢复 secret suffix 的一个字节。

1. 发送递减长度的输入，把下一个未知字节推到某个分组的末尾
2. 对每个位置，枚举 256 个字节，比较得到的目标分组：

```python
from pwn import *
import cryptanalib as ca  # FeatherDuster 的 cryptanalib

def oracle(pt):
    """发送明文，接收 ECB 加密后的密文。"""
    r = remote('target', 7765)
    r.recvuntil('Send me some hex-encoded data to encrypt:\n')
    r.sendline(pt.hex())
    r.recvuntil('Here you go:')
    ct = bytes.fromhex(r.recvline().strip().decode())
    r.close()
    return ct

# 自动化逐字节恢复
flag = ca.ecb_cpa_decrypt(oracle, block_size=16, verbose=True)
print(flag)
```

**手工版：**
```python
block_size = 16
known = b''

for i in range(len(secret)):
    # 填充，使下一个未知字节位于某个块的末尾
    pad_len = block_size - 1 - (len(known) % block_size)
    pad = b'A' * pad_len

    # 获取目标块
    target_ct = oracle(pad)
    target_block_idx = (pad_len + len(known)) // block_size
    target_block = target_ct[target_block_idx*16:(target_block_idx+1)*16]

    # 枚举 256 个候选字节
    for byte_val in range(256):
        test = pad + known + bytes([byte_val])
        test_ct = oracle(test)
        if test_ct[target_block_idx*16:(target_block_idx+1)*16] == target_block:
            known += bytes([byte_val])
            break
```

**关键点：** ECB 会把完全相同的明文块映射成完全相同的密文块。攻击者通过控制前缀长度，让每个未知字节依次落在“可被 256 候选覆盖”的位置上，最多 256 次查询就能确定 1 个字节。总复杂度约为 `256 * secret_length`。

---

## AES-ECB Cut-and-Paste Block Manipulation (NDH Quals 2016)

**模式（Toil33t）：** 服务端把 JSON 会话数据用 AES-ECB 加密。像 `is_admin: false` 这种字段会以可预测方式落在块边界附近。通过精心构造注册输入，再拼接不同密文块，可以把 `false` 换成 `true`。

1. 检测 ECB：注册重复用户名（如 `'A' * 64`），观察密文中是否出现重复块
2. 通过调用户名长度，观察块数量何时变化，定位边界
3. 分别改变用户名和 email 长度，推断字段顺序
4. 构造一个恰好把 `true` 对齐到块起始的输入，再从密文中抽出该块：

```python
# 用空格把 "true" 对齐到块起始（JSON 忽略额外空格）
# 原始：  {"username": "AA", "is_admin": false, "email": ""}
# 目标：  {"username": "AA", "is_admin":            true, "email": ""}
#                                              ^-- 16-byte block boundary

# 用下面输入制造出 "            true" 所在的块
username = "AAA" + " " * 12 + "true"
# 从其密文中抽出对应块

# 再从短用户名拿前缀块
# 从另一份构造里拿后缀块
# 最后拼成：prefix_blocks + true_block + suffix_block
```

**关键点：** ECB 对每个 16 字节块独立加密，没有链式依赖。相同明文块 -> 相同密文块，因此可以直接做块级剪贴拼接。JSON 对额外空白宽容，使块对齐更容易。

---

## AES-CBC IV Bit-Flip Authentication Bypass (Google CTF 2016)

**模式（Eucalypt Forest）：** 服务端把 JSON 会话 blob 用 AES-CBC 加密，并把 IV 和密文一起放进 cookie，但完全没有做完整性校验（无 MAC / HMAC）。翻转 IV 的某些位，就能只修改第一块明文。

1. 注册一个与目标值只差 1 bit 的用户名（例如用 `` `dmin `` 代替 `admin`）
2. 找到这个字符在第一块中的位置
3. 在 IV 中翻同一位，该 bit 会直接传播到解密后的第一块明文：

```python
import binascii
cookie = binascii.unhexlify(auth_cookie)
iv = bytearray(cookie[:16])
ciphertext = cookie[16:]

# 翻转对应字节的最低位，把 '`' 变成 'a'
# 具体位置取决于 JSON 结构：{"username":"`dmin"}
# 'a' (0x61) 与 '`' (0x60) 只差 bit 0
target_pos = 13  # 用户名首字符在第一块中的位置
iv[target_pos] ^= 0x01

forged = binascii.hexlify(bytes(iv) + ciphertext)
```

**关键点：** CBC 解密会把 `AES_dec(C0)` 与 IV XOR，因此翻 IV 中的某一位，只会翻第一块明文中对应位，不影响其他块。前提是服务端完全没有做认证。

---

## Rabin Cryptosystem LSB Parity Oracle (PlaidCTF 2016)

**模式（rabit）：** 服务端用 Rabin 密码体制（`c = m^2 mod n`）加密 flag，并提供 LSB 预言机。对任意密文，它会返回解密明文的最低位。通过二分搜索，可以在 `log2(n)` 次查询中恢复完整明文。

```python
from Crypto.Util.number import long_to_bytes

def lsb_oracle_attack(enc_flag, N, oracle_fn):
    """利用 Rabin / RSA LSB 预言机，通过二分恢复明文。"""
    lower = 0
    upper = N
    C = enc_flag
    # Rabin: encrypt(2,N) = 4；乘上 4 相当于明文翻倍
    e2 = pow(2, 2, N)  # Rabin 用 2^2；RSA 则是 pow(2, e, N)

    for i in range(N.bit_length()):
        C = (e2 * C) % N  # 使明文翻倍
        lsb = oracle_fn(C)
        if lsb == 1:
            # 2*m > N（模回绕后成奇数余数），提高下界
            lower = (upper + lower) // 2
        else:
            # 2*m < N（未回绕，偶数），降低上界
            upper = (upper + lower) // 2
        # 可观察到逐步逼近的解密结果
        print(long_to_bytes(upper))
    return upper
```

**关键点：** Rabin 和 textbook RSA 都是乘法同态的。把密文乘上 `2^e mod N`，就会让明文翻倍。由于 N 是奇数，翻倍时是否跨过 N/2 会改变最低位，于是形成标准二分搜索。

---

## PBKDF2 Pre-Hash Bypass for Long Passwords (BackdoorCTF 2016)

**模式（Mindblown）：** PBKDF2（以及更底层的 HMAC）会对长度超过哈希块大小（SHA-1 / SHA-256 都是 64 字节）的密码先做预哈希。因此若目标密码超过 64 字节，就有 `PBKDF2(password) == PBKDF2(SHA1(password))`，可以直接用哈希值替代原密码登录。

```python
import hashlib

original_password = "complexPasswordWhichContainsManyCharactersWithRandomSuffixeghjrjg"
# 长度 > 64，因此 HMAC 会先对它做哈希
equivalent = hashlib.sha1(original_password.encode()).digest()
# 用 equivalent 登录，PBKDF2 将得到同样的导出密钥
```

**关键点：** HMAC 的内部结构是 `H((K XOR ipad) || message)`。当 K 太长时，HMAC 先把它化成 `H(K)`。因此 `HMAC(long_password, ...) == HMAC(H(long_password), ...)`。这不是实现 bug，而是 HMAC 规范本身的行为。

---

## MD5 Multi-Collision via Fastcol (BackdoorCTF 2016)

**模式（Forge）：** 使用 Marc Stevens 的 `fastcol`，可以批量生成 `2^k` 个 MD5 相同的文件。每次运行得到一对后缀（A/B），把多轮结果串起来，就能得到指数级数量的碰撞样本。

```text
[prefix][suffix1A][suffix2A][suffix3A]  \
[prefix][suffix1A][suffix2A][suffix3B]   |
[prefix][suffix1A][suffix2B][suffix3A]   |-- 这些文件 MD5 全相同
[prefix][suffix1A][suffix2B][suffix3B]   |
[prefix][suffix1B][suffix2A][suffix3A]   |
[prefix][suffix1B][suffix2B][suffix3B]  /
```

```bash
# 安装：git clone https://github.com/cr-marcstevens/hashclash
# 生成一对碰撞（现代 CPU 上约数分钟）
./fastcol -o suffix1A.bin suffix1B.bin < prefix.bin
# 串联：把 suffix1A 接到 prefix 后，再跑 fastcol 得到 suffix2A/2B，依此类推
```

**关键点：** MD5 碰撞已经是实用攻击。因为 MD5 是 Merkle-Damgard 构造，一组碰撞可以继续传播到任意共同后缀上。链 k 次就得到 `2^k` 个相同 MD5 的文件。

---

## GHASH Key Recovery over Prime Modulus (nullcon HackIM 2019)

**模式（GenuineCounterMode）：** 一个自定义 GCM-like 方案把 tag 算成 `tag = c + sum(b_i * H^(i+1)) mod n`，其中 `n` 不是 `GF(2^128)` 多项式域，而是普通 128-bit 素数。nonce 12 字节里有 10 字节固定于 session ID，只剩 2 字节随机，因此大约 256 次查询就会出现 nonce 碰撞。两次碰撞后，`c = E_K(nonce || counter)` 可以相消，剩下关于 `H` 的线性方程，只需一次模逆就能解出。

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

n = 327989969870981036659934487747327553919  # 素数模（不是 GF(2^128)）

# 1. 反复请求单块消息加密，直到出现两条共享 nonce 的密文
# 2. 对碰撞对 (nonce, ct1, tag1) 和 (nonce, ct2, tag2)：
m1 = bytes_to_long(ct1)  # 单个 16-byte 分组
m2 = bytes_to_long(ct2)
t1 = bytes_to_long(tag1)
t2 = bytes_to_long(tag2)
H = ((t1 - t2) * inverse(m1 - m2, n)) % n

# 3. 伪造：先加密 "may i please have the galf"，再通过 CTR 翻位变成 "flag"
#    然后用恢复出的 H 和 c 重算 tag
c0 = (t1 - sum(bytes_to_long(b) * pow(H, i + 1, n) for i, b in enumerate(blocks1))) % n
forged_tag = (c0 + sum(bytes_to_long(b) * pow(H, i + 1, n) for i, b in enumerate(forged_blocks))) % n
```

**关键点：** 真正的 GCM 把 GHASH 放在 `GF(2^128)` 上，攻击复杂得多；若设计者偷懒改成普通素数模，认证部分就退化成线性代数。再叠加 2 字节 nonce 的生日碰撞，整个系统几乎等于明牌。

---

## SHA-1 Length Extension Plus AES-CBC Cookie Forgery (BSidesSF 2019)

**模式（decrypto）：** Cookie 中包含 `user = iv || AES-CBC(key, plaintext)`，另有单独的 `signature = SHA1(secret || decrypt(ct))`。而 session cookie 又泄露了 AES key（例如 base64 session blob 的末尾 32 字节）。于是可以把两个原语串起来：先对 `signature` 做长度扩展，给明文追加 `\nUID 0\n`，再用已知 AES key 把扩展后的明文重新加密，提交更新后的 `user` 与 `signature`。

```python
import hashpumpy, binascii, base64, urllib
from Crypto.Cipher import AES

# 从泄露的 rack.session cookie 中取出 AES key
key = base64.b64decode(urllib.unquote(cookies['rack.session'].split('--')[0]))[-32:]
user = binascii.unhexlify(cookies['user'])
iv, ct = user[:16], user[16:]

def decrypt(c): return AES.new(key, AES.MODE_CBC, iv).decrypt(c).rstrip(b'\x10\x0f\x0e...')
def encrypt(p): pad = 16 - len(p) % 16; return AES.new(key, AES.MODE_CBC, iv).encrypt(p + bytes([pad])*pad)

# 对签名做长度扩展（猜测 secret 长度 = 8）
new_sig, new_plain = hashpumpy.hashpump(cookies['signature'], decrypt(ct), b'\nUID 0\n', 8)
cookies['signature'] = new_sig
cookies['user']      = binascii.hexlify(iv + encrypt(new_plain))
```

**关键点：** 只要 MAC 是 `H(secret || data)`，就能做长度扩展；而如果承载同一份 `data` 的对称加密 key 又意外泄露，就可以把 hashpumpy 产出的“扩展后明文 + 新 tag”直接重新打包进密文。再配合“后出现字段覆盖前字段”一类解析细节，追加的 `UID 0` 就会生效。

---

详见 [modern-ciphers-3.md](modern-ciphers-3.md)，其中包含自定义哈希反演、CRC32 暴力、带噪声的 RSA LSB 预言机、海绵碰撞、CBC IV 伪造 + 截断、padding oracle + bit-flip 命令注入、SPN S 盒交集、AES-CFB IV 恢复、three-round XOR、Unicode 解码侧信道、SHA-256 basis attack、利用 XOR 抵消的 MAC 伪造，以及逐 bit 恢复 HMAC 密钥。
