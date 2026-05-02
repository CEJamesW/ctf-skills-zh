# CTF Crypto - RSA 攻击（第二部分：专项技巧）

## Table of Contents
- [RSA p=q 校验绕过（BearCatCTF 2026）](#rsa-pq-validation-bypass-bearcatctf-2026)
- [gcd(e, phi) > 1 时的 RSA 立方根 CRT（BearCatCTF 2026）](#rsa-cube-root-crt-when-gcde-phi--1-bearcatctf-2026)
- [从 phi(n) 的倍数中分解 n（BearCatCTF 2026）](#factoring-n-from-multiple-of-phin-bearcatctf-2026)
- [利用乘法同态伪造 RSA 签名（MMA CTF 2015）](#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015)
- [基表示导致的弱 RSA 密钥生成（Sharif CTF 2016）](#weak-rsa-key-generation-via-base-representation-sharif-ctf-2016)
- [gcd(e, phi(n)) > 1 的 RSA（CSAW 2015）](#rsa-with-gcde-phin--1-csaw-2015)
- [共素因子的批量 GCD 分解（BSidesSF 2025）](#batch-gcd-for-shared-prime-factoring-bsidessf-2025)
- [从 dp dq qinv 恢复 RSA 部分私钥（0CTF 2016）](#rsa-partial-key-recovery-from-dp-dq-qinv-0ctf-2016)
- [RSA-CRT 故障攻击 / 比特翻转恢复（CSAW CTF 2016）](#rsa-crt-fault-attack--bit-flip-recovery-csaw-ctf-2016)
- [RSA 同态解密预言机绕过（ECTF 2016）](#rsa-homomorphic-decryption-oracle-bypass-ectf-2016)
- [含小素因子的 RSA 与 CRT 分解（Hack The Vote 2016）](#rsa-with-small-prime-factors-and-crt-decomposition-hack-the-vote-2016)
- [Montgomery 约减上的 RSA 计时攻击（DEF CON 2017）](#rsa-timing-attack-on-montgomery-reduction-def-con-2017)
- [Bleichenbacher 低指数 RSA 签名伪造（Google CTF 2017）](#bleichenbacher-low-exponent-rsa-signature-forgery-google-ctf-2017)
- [线性相关素数上的 Coppersmith 小根（Tokyo Westerns 2017）](#coppersmith-small-roots-for-linearly-related-primes-tokyo-westerns-2017)
- [ROCA 攻击：RSA CVE-2017-15361（EasyCTF IV）](#roca-attack-on-rsa-cve-2017-15361-easyctf-iv)
- [e=1 + 伪造模数的 RSA 签名绕过（BackdoorCTF 2018）](#rsa-signature-bypass-with-e1-and-crafted-modulus-backdoorctf-2018)
- [依赖素数 RSA：q = e^-1 mod p（TokyoWesterns CTF 4th 2018）](#dependent-prime-rsa-q--e-1-mod-p-tokyowesterns-ctf-4th-2018)
- [三把 RSA key 的成对 GCD 三角关系（Trend Micro 2018）](#rsa-three-key-pairwise-gcd-triangle-trend-micro-2018)
- [n = p^2*q 的 Schmidt-Samoa 变体（ASIS Finals 2018）](#rsa-n--p2q-schmidt-samoa-variant-asis-finals-2018)
- [通过加密残差 GCD 恢复模数（X-MAS CTF 2018）](#modulus-recovery-via-gcd-of-encryption-residuals-x-mas-ctf-2018)
- [利用 encrypt(-1) 做 textbook RSA 取反（X-MAS CTF 2018）](#textbook-rsa-negation-via-encrypt-1-x-mas-ctf-2018)
- [Poly-Exponent RSA：对 p^p 组合求 GCD（ASIS Finals 2018）](#poly-exponent-rsa-gcd-of-pp-combinations-asis-finals-2018)
- [带偏差的 LSB 预言机与众数恢复（CSAW CTF 2018）](#biased-lsb-oracle-with-mode-of-runs-recovery-csaw-ctf-2018)
- [借助 AES-CTR 长度提示处理立方根回绕（hxp 2018）](#cube-root-wraparound-via-aes-ctr-length-hint-hxp-2018)
- [p = next_prime(2^k + small) 的共素因子批量 GCD（ASIS Finals 2018）](#rsa-p--next_prime2k--small-shared-prime-batch-gcd-asis-finals-2018)
- [只影响 512-bit key 长度范围的 PNG 加密 -> 直接替换尾部（ASIS Finals 2018）](#png-encryption-bounded-by-512-bit-key--trailer-replacement-asis-finals-2018)
- [利用明文可塑性恢复模数（X-MAS 2018）](#modulus-recovery-via-plaintext-malleability-x-mas-2018)
- [RSA CRT d_p 空字节溢出泄露素数（P.W.N. CTF 2018）](#rsa-crt-d_p-null-byte-overflow-primes-leak-pwn-ctf-2018)
- [通过消息分解绕过 textbook RSA 签名黑名单（P.W.N. CTF 2018）](#textbook-rsa-signature-blinding-via-message-factoring-pwn-ctf-2018)
- [strlen-1 触发的末字节模数覆写（OTW Advent 2018）](#last-byte-modulus-overwrite-via-strlen-1-null-truncation-otw-advent-2018)
- [CRC32 碰撞预言机 + RSA 同态签名伪造（BSidesSF 2019）](#crc32-collision-oracle--rsa-homomorphic-signature-forgery-bsidessf-2019)

另见 [rsa-attacks.md](rsa-attacks.md)，其中包含基础 RSA 攻击：small e、Wiener、Fermat、Pollard、Hastad、common modulus、Manger 预言机、Coppersmith 等。

---

## RSA p=q Validation Bypass (BearCatCTF 2026)

**模式（Pickme）：** 服务端会校验用户提交的 RSA key（检查 `n`、`e`、`d`、`p*q=n`、`e*d ≡ 1 mod phi`），然后用这把 key 加密 flag，并尝试做一次测试解密。若测试解密失败，就在错误消息里泄露密文。

**利用：** 令 `p = q`。服务端仍按普通 RSA 计算 `phi = (p-1)*(q-1) = (p-1)^2`，但对 `n = p^2` 来说这其实是错的；真正的欧拉函数是 `phi(p^2) = p*(p-1)`。于是所有校验都会通过，但服务端算出来的 `d` 是错的，测试解密会失败，从而走到泄露密文的分支。

```python
from Crypto.Util.number import getPrime, inverse

p = getPrime(512)
q = p  # p = q！
n = p * q  # = p^2
e = 65537
wrong_phi = (p - 1) * (q - 1)  # = (p-1)^2
d = inverse(e, wrong_phi)  # 通过服务端校验

# 服务端用我们的 key 加密 flag，测试解密失败 -> 泄露密文 c
# 用正确的 totient 解密：
real_phi = p * (p - 1)
real_d = inverse(e, real_phi)
flag = pow(c, real_d, n)
```

**关键点：** `phi(p^2) = p*(p-1)`，不是 `(p-1)^2`。任何没检查 `p != q` 却照抄普通公式的实现，都能被这个技巧击穿。

---

## RSA Cube Root CRT when gcd(e, phi) > 1 (BearCatCTF 2026)

**模式（Kidd's Crypto）：** 使用 `e=3`，且模数由许多都满足 `p ≡ 1 mod 3` 的小素数组成。因此每个 `p-1` 都能被 3 整除，导致 `gcd(e, phi(n)) = 3^k`，标准逆元 `d = e^-1 mod phi` 不存在。

**解法：** 先在每个素数模下求立方根，再用 CRT 组合：
```python
from sympy.ntheory.residues import nthroot_mod
from sympy.ntheory.modular import crt

primes = [p1, p2, ..., p13]  # 全都满足 p ≡ 1 mod 3

# 对每个素数，求 c mod p 的全部 3 个立方根
roots_per_prime = []
for p in primes:
    roots = nthroot_mod(c % p, 3, p, all_roots=True)
    roots_per_prime.append(roots)

# 枚举全部 3^13 = 1,594,323 种 CRT 组合
from itertools import product
for combo in product(*roots_per_prime):
    result, mod = crt(primes, list(combo))
    try:
        text = long_to_bytes(result).decode('ascii')
        if text.isprintable():
            print(f"Flag: {text}")
            break
    except:
        continue
```

**关键点：** 当 `gcd(e, phi(n)) > 1` 时，标准 RSA 解密失效，但每个素数模下仍可求 e 次根。若素数数量不多，枚举所有 CRT 组合仍然可行。

---

## Factoring n from Multiple of phi(n) (BearCatCTF 2026)

**模式（Twisted Pair）：** 给出 RSA 模数 `n`，以及一组泄露值 `(re, rd)`，满足 `re * rd ≡ 1 (mod k*phi(n))`。于是 `re*rd - 1` 就是 `phi(n)` 的某个倍数，可以用来做概率分解。

```python
import random
from math import gcd

def factor_from_phi_multiple(n, phi_multiple):
    """给定 phi(n) 的任意倍数，用 Miller-Rabin 变体分解 n。"""
    # 写成 phi_multiple = 2^s * d，其中 d 为奇数
    s, d = 0, phi_multiple
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(100):  # 100 次尝试
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            prev = x
            x = pow(x, 2, n)
            if x == n - 1:
                break
            if x == 1:
                # prev 是 1 的非平凡平方根
                p = gcd(prev - 1, n)
                if 1 < p < n:
                    return p, n // p
        if x != n - 1:
            p = gcd(x - 1, n)
            if 1 < p < n:
                return p, n // p
    return None

phi_mult = re * rd - 1
p, q = factor_from_phi_multiple(n, phi_mult)
```

**关键点：** 不需要拿到完整 `phi(n)`；任何它的倍数都足以驱动基于非平凡平方根的分解算法。

---

## RSA Signature Forgery via Multiplicative Homomorphism (MMA CTF 2015)

**模式：** 签名预言机拒绝对目标消息 `m` 签名，但愿意签其他值。无填充 RSA 具有乘法同态：`S(a) * S(b) mod n == S(a * b) mod n`。

```python
# 分解目标消息，对每个因子分别求签名
divisor = 2
assert target_msg % divisor == 0
sig_a = sign_oracle(target_msg // divisor)
sig_b = sign_oracle(divisor)
forged_sig = (sig_a * sig_b) % n
```

**关键点：** textbook RSA 签名天然保留乘法结构。只要能把目标消息写成若干“允许签名”的因子的乘积，就能拼出目标签名。

---

## Weak RSA Key Generation via Base Representation (Sharif CTF 2016)

当 RSA 素数按 `p = kp * B + tp` 这种结构生成，其中 `B = 小素数乘积 * 2^400`，且 `kp` 很小（< `2^12`）时：

1. **看 `n mod B^2`：** 因为 `n = p*q = kp*kq*B^2 + (kp*tq + kq*tp)*B + tp*tq`
2. **恢复 `kp*kq`：** 暴力枚举 `kp, kq`（共约 `2^24`）
3. **解二次关系：** 结合中间系数恢复 `tp, tq`

```python
B = product_of_first_443_primes * (2**400)
B2 = B * B

# n = A*B^2 + C*B + D，其中 A=kp*kq，D=tp*tq
A = n // B2
D = n % B

# 暴力 kp, kq，使 kp*kq == A
for kp in range(1, 2**12):
    if A % kp == 0:
        kq = A // kp
        # 再利用剩余关系解 tp, tq
```

**关键点：** 这种结构化素数生成会在 `n` 中留下明显的混合进制痕迹，搜索空间从指数级骤降到多项式级。

---

## RSA with gcd(e, phi(n)) > 1 (CSAW 2015)

当 `gcd(e, phi(n)) = g > 1` 时，标准 RSA 解密失效，因为 `d = e^(-1) mod phi(n)` 不存在。可改用：

1. `e' = e / g`
2. `d' = e'^(-1) mod phi(n)`（现在可逆）
3. `m^g = pow(c, d', n)`（部分解密）
4. 再求 g 次根：尝试满足 `pow(m, g, n) == m^g` 的候选

```python
from sympy import factorint, mod_inverse
from gmpy2 import iroot

g = gcd(e, phi_n)
e_prime = e // g
d_prime = mod_inverse(e_prime, phi_n)
m_g = pow(c, d_prime, n)

# g 不大时，先试整数根
m, is_exact = iroot(m_g, g)
if is_exact:
    plaintext = int(m)
else:
    # 也可能是 m_g + k*n 的整数根
    for k in range(10000):
        m, exact = iroot(m_g + k * n, g)
        if exact:
            plaintext = int(m)
            break
```

**关键点：** 先把指数按 GCD 约化，拿到 `m^g`，再做开根。对小 `g` 非常实用。

---

## Batch GCD for Shared Prime Factoring (BSidesSF 2025)

当多把 RSA 公钥因硬件 RNG、智能卡 bug 或弱种子而共享素因子时：

```python
from math import gcd
from functools import reduce

def batch_gcd(moduli):
    """在一组 RSA 模数中查找共享素因子。"""
    # Product tree 的简化写法
    product = reduce(lambda a, b: a * b, moduli)

    factors = {}
    for n in moduli:
        g = gcd(n, product // n)
        if g != 1 and g != n:
            p = g
            q = n // p
            factors[n] = (p, q)
    return factors

# 使用：输入一批 smartcard / device 的公钥
moduli = [key.n for key in public_keys]
shared = batch_gcd(moduli)
for n, (p, q) in shared.items():
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
```

若素数还带有固定比特模式等结构，可在 GCD 之后继续结合 Coppersmith 恢复剩余位。相关内容见 [advanced-math.md](advanced-math.md)。

**关键点：** 一旦两把 key 共享一个 prime，两把都完了。对成百上千把 key，批量 GCD 的复杂度仍然可控。

---

## RSA Partial Key Recovery from dp dq qinv (0CTF 2016)

**模式：** 只泄露了私钥 PEM 的 CRT 部分（`dp, dq, qinv`），例如私钥文件底部残留。由于 `dp = d mod (p-1)`，可以直接枚举 `k`，检查 `p = (dp * e - 1) / k + 1` 是否为素数。

```python
import gmpy2
# dp, dq, qinv 来自部分 PEM 泄露；e 已知（通常 65537）
for k in range(3, e):
    p_candidate = (dp * e - 1) // k + 1
    if gmpy2.is_prime(p_candidate):
        p = p_candidate
        break
# 同理可用 dq 恢复 q，再验证 qinv * q % p == 1
```

**关键点：** 即使只泄露 CRT 指数，也足以在 `O(e)` 时间里恢复完整私钥。

---

## RSA-CRT Fault Attack / Bit-Flip Recovery (CSAW CTF 2016)

RSA 签名服务在 CRT 计算中偶发单 bit 错误。收集正确签名与故障签名后，可以进一步定位哪一位被翻转。

```python
from Crypto.Util.number import inverse

def recover_d_bits(n, e, valid_sig, faulty_sigs, msg):
    """根据 CRT 故障签名逐 bit 恢复 d。"""
    d_bits = [0] * 1024
    m = pow(msg, 1, n)
    s_good = valid_sig
    for s_bad in faulty_sigs:
        # ratio 暴露被翻转的是哪一位
        ratio = (s_bad * inverse(s_good, n)) % n
        for k in range(1024):
            if ratio == pow(2, pow(2, k, n), n) or ratio == pow(inverse(2, n), pow(2, k, n), n):
                d_bits[k] = 1
                break
    return d_bits
```

**关键点：** 如果 RSA-CRT 在私钥指数 `d` 的某一位上出现单 bit 故障，那么 `faulty_sig * valid_sig^(-1) mod n` 会变成一个非常有结构的值，可用于逐位恢复私钥。

---

## RSA Homomorphic Decryption Oracle Bypass (ECTF 2016)

服务端拒绝直接解密目标密文，但允许解密其他密文。可利用 RSA 的乘法同态：`Dec(a * b mod n) = Dec(a) * Dec(b) mod n`。

```python
from Crypto.Util.number import long_to_bytes, inverse

# 服务端拒绝解 enc_flag
# 但 RSA 同态满足：Dec(A*B) = Dec(A) * Dec(B) mod n
enc_2 = pow(2, e, n)  # 对数字 2 加密
enc_flag_times_2 = (enc_flag * enc_2) % n  # = Enc(flag * 2)

dec_flag_times_2 = oracle_decrypt(enc_flag_times_2)  # 服务端愿意解
dec_2 = oracle_decrypt(enc_2)                         # 服务端也愿意解

# 恢复 flag: (flag * 2) * inverse(2) mod n = flag
flag = (dec_flag_times_2 * inverse(dec_2, n)) % n
print(long_to_bytes(flag))
```

**关键点：** 无填充 RSA 只要允许解任意“邻近密文”，就几乎等于允许解目标密文。

---

## RSA with Small Prime Factors and CRT Decomposition (Hack The Vote 2016)

当模数由许多小素数构成（如都小于 251，且每个出现很多次）时：

```python
from sympy import factorint
from sympy.ntheory.residues import primitive_root
from functools import reduce

n = ...  # 含大量小素因子的模数
e = 65537
c = ...  # 密文

factors = factorint(n)  # {p1: k1, p2: k2, ...}

# 先对每个素数幂模下解密，再用 CRT 合并
from sympy.ntheory.modular import crt as chinese_remainder_theorem

remainders = []
moduli = []
for p, k in factors.items():
    pk = p ** k
    phi_pk = (p - 1) * p ** (k - 1)
    d_pk = pow(e, -1, phi_pk)
    m_pk = pow(c, d_pk, pk)
    remainders.append(m_pk)
    moduli.append(pk)

m = chinese_remainder_theorem(moduli, remainders)[0]
```

**关键点：** 多素数 + 小素数幂意味着把整体解密拆成许多个小模解密，再 CRT 合并即可，远比直接在整个 `phi(n)` 上做事情简单。

---

## RSA Timing Attack on Montgomery Reduction (DEF CON 2017)

**模式：** Montgomery reduction 中“额外减法”的次数会通过时间泄露出来，于是可按 Kocher 思路恢复 RSA 私钥 bit。

```python
# Montgomery 乘法：当中间结果 >= modulus 时会多做一次减法
# 泄露量：每次签名过程中的额外减法次数
# 攻击：对每个私钥 bit 假设 0 / 1，预测减法次数并与观测计时做相关性比较

# 对每个位位置 i（从高位到低位）：
#   假设 bit = 0：只考虑 square
#   假设 bit = 1：考虑 square + multiply
#   比较预测值和观测值的统计相关性

# 恢复 768-bit key 大约需要 20 万次签名
import numpy as np
for bit_pos in range(key_bits):
    for guess in [0, 1]:
        predicted = predict_reductions(known_bits + [guess], messages)
        correlation = np.corrcoef(predicted, observed)[0, 1]
    known_bits.append(0 if corr_0 > corr_1 else 1)
```

**关键点：** Montgomery 乘法中的条件减法本身就是侧信道信号。只要它能通过计时、功耗甚至直接计数暴露，就能逐位恢复私钥。

---

## Bleichenbacher Low-Exponent RSA Signature Forgery (Google CTF 2017)

**模式：** 当 `e=3` 且验签实现只检查 PKCS#1 v1.5 前缀是否正确时，可以构造一个带合法前缀的值，再对它开立方根，从而伪造签名。

```python
# PKCS#1 v1.5 签名块格式：
# 00 01 FF FF ... FF 00 [DigestInfo] [Hash]
# 对 e=3，构造一个值，使其立方根的 3 次方拥有正确前缀

import gmpy2
prefix = b'\x00\x01' + b'\xff' * padding_len + b'\x00' + digest_info + hash_value
# 转成整数，尾部补零作为“垃圾字节”缓冲误差
target = int.from_bytes(prefix + b'\x00' * garbage_len, 'big')
# 开立方根（向上取整）
forged_sig = gmpy2.iroot(target, 3)[0] + 1
# 验证：forged_sig^3 应以前缀 00 01 FF... 开头
```

**关键点：** 只要验签没有检查填充是否一直延续到块尾，低指数下就能靠“合法前缀 + 尾部垃圾”伪造。

---

## Coppersmith Small Roots for Linearly Related Primes (Tokyo Westerns 2017)

**模式：** `q = k*p + delta`，其中 `k` 已知，`delta` 很小。因为 `p ≈ sqrt(N/k)`，可先近似 `q_approx = k * isqrt(N // k) + 2^512`，再把 `delta` 当作小根用 Coppersmith 求出来。

```python
from sage.all import *

N, e, c = ...  # RSA 参数
k = 19  # 已知关系：q = k*p + delta

# 从 sqrt(N/k) 近似 q
q_approx = k * isqrt(N // k) + 2**512

R.<x> = PolynomialRing(Zmod(N))
f = q_approx - x  # 根即 delta = q_approx - q

roots = f.small_roots(X=2**512, beta=0.5)
if roots:
    q = int(q_approx - roots[0])
    p = N // q
    assert p * q == N
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    flag = long_to_bytes(pow(c, d, N))
```

**关键点：** 已知素数之间的线性关系时，大约一半比特信息已经由 `sqrt(N/k)` 给出，剩余误差若足够小，就能被 Coppersmith 捕获。

---

## ROCA Attack on RSA CVE-2017-15361 (EasyCTF IV)

**模式：** Infineon RSA 库生成的 key 带有结构化素数，可通过指纹识别；对 512-bit key 通常可在数分钟内分解。

```bash
# 检测是否存在 ROCA 漏洞
pip install roca-detect
roca-detect rsa_key.pub
# 用 neca 工具分解
git clone https://gitlab.com/jix/neca.git
cd neca && cargo build --release
./target/release/neca <N_decimal>
# 或使用原始研究工具：https://github.com/crocs-muni/roca
```

**关键点：** CVE-2017-15361 影响过 TPM、智能卡和 YubiKey 4。若 `roca-detect` 给出阳性，优先用现成工具分解，不必自己重写。

---

### RSA Signature Bypass with e=1 and Crafted Modulus (BackdoorCTF 2018)

**模式：** 服务端先生成 RSA 签名，再要求用户提供 `(n, e)` 来验证。若设 `e=1`，则 `pow(s, 1, n) = s mod n`。于是直接令 `n = signature - PKCS1_pad(message)`，验证就会通过。（BackdoorCTF 2018）

```python
e = 1
n = signature ** e - PKCS1_pad(h.hexdigest())
# 现在 pow(signature, 1, n) == PKCS1_pad(message)
```

**关键点：** 只要验证端允许用户自定义公钥参数，且没有限制 `e`，`e=1` 就是必试项。

---

## Dependent-Prime RSA: q = e^-1 mod p (TokyoWesterns CTF 4th 2018)

**模式：** 先生成素数 `p`，然后令 `q = e^(-1) mod p`，若 `q` 也是素数就接受。这意味着 `e*q ≡ 1 (mod p)`，也就是 `e*q = k*p + 1`。结合 `n = p*q` 可写成关于 `p` 的二次方程，枚举少量 `k` 即可求根。

```python
from sage.all import PolynomialRing, ZZ

def factor_dependent_n(n, e, max_k=100000):
    P = PolynomialRing(ZZ, 'p'); p = P.gen()
    for k in range(2, max_k, 2):
        # e*q = k*p + 1，且 n = p*q  =>  e*n = p*(k*p + 1)
        poly = k * p * p + p - e * n
        roots = poly.roots()
        for root, _ in roots:
            if root > 1 and n % root == 0:
                return int(root), n // int(root)
    return None
```

**关键点：** 只要 `q` 是由 `p` 通过公开算术关系导出的，RSA 就退化成一个小参数搜索问题。

**参考：** TokyoWesterns CTF 4th 2018，writeup 10862

---

## RSA Three-Key Pairwise GCD Triangle (Trend Micro 2018)

**模式：** 三个模数满足 `N1 = p1*p2`、`N2 = p1*p3`、`N3 = p2*p3`，每一对模数恰好共享一个素因子。只需三次 `gcd`，就能把三把 key 全部分解。

```python
from math import gcd

def factor_triangle(n1, n2, n3):
    p1 = gcd(n1, n2)        # N1 与 N2 的共享素因子
    p2 = gcd(n1, n3)        # N1 与 N3 的共享素因子
    p3 = gcd(n2, n3)        # N2 与 N3 的共享素因子
    assert n1 == p1 * p2 and n2 == p1 * p3 and n3 == p2 * p3
    return p1, p2, p3
```

**关键点：** 这是批量 GCD 的一个封闭特例。只要题目恰好给 3 把模长相近的 RSA 公钥，就应该先试 pairwise GCD。

---

## RSA n = p^2*q Schmidt-Samoa Variant (ASIS Finals 2018)

**模式：** 模数生成方式是 `n = p*p*q`，不是普通的 `p*q`。因此朴素地套 `phi = (p-1)*(q-1)` 会出错；真正的欧拉函数是 `phi = p*(p-1)*(q-1)`。若进一步有 `gcd(e, phi) != 1`，则要先把密文降到较小域 `q` 上再反演。

```python
phi = p*(p-1)*(q-1)
# 用 inverse_mod(q, phi) 把密文降到 mod q
qinv = inverse_mod(q, phi)
enc = pow(enc, qinv, n) % q
# 现在 m < q；再在 phi(q)=q-1 上反演 e*p^2
pinv = inverse_mod(p*p, q-1)
m = pow(enc, pinv, q)
```

**关键点：** 一旦看见 `p^2*q` 一类非标准模数结构，就要立刻改 totient 公式，必要时改到较小域里做逆运算。

---

## Modulus Recovery via GCD of Encryption Residuals (X-MAS CTF 2018)

**模式：** Oracle 允许你加密任意明文，但不公开模数 `n`。对两个消息 `m1, m2` 分别计算 `m^e - enc(m)`，这两个差都一定是 `n` 的倍数，因此它们的 GCD 就是 `n`（或 `n` 的小倍数）。

```python
e = 65537
r1 = bytes_to_long(b'a')**e - encrypt(b'a')
r2 = bytes_to_long(b'b')**e - encrypt(b'b')
n = gcd(r1, r2)
```

**关键点：** 这是黑盒 RSA 的经典探针。拿到 GCD 后若还夹杂小因子，再手动剥掉即可。

---

## Textbook RSA Negation via encrypt(-1) (X-MAS CTF 2018)

**模式：** 解密预言机拒绝直接解目标密文，但允许你先乘别的密文。由于对任意奇数 `e` 有 `(-1)^e ≡ -1 (mod n)`，所以乘上 `pow(-1, e, n)` 相当于把明文取负。

```python
ct_mutated = (ct_flag * pow(-1, e, n)) % n
plaintext = (-decrypt(ct_mutated)) % n
```

**关键点：** 任意奇数指数下，`encrypt(-1) = -1 mod n`。如果解密服务只屏蔽目标密文本身，这种取负就能绕过去。

---

## Poly-Exponent RSA: GCD of p^p Combinations (ASIS Finals 2018)

**模式：** 题目给出若干关于 `p` 和 `q` 的线性 / 多项式组合，例如 `c1 = p^p mod q`、`c2 = (p+q)^(p+q) mod n`。通过把两个都含目标素因子的式子组合起来，再做 GCD，可直接恢复该素因子。

```python
p = gcd(c2*c4 - c3, pow(c4, c4, c2*c4 - c3) - c3)
q = gcd(c1*c4 - c3, pow(c4, c4, c1*c4 - c3) - c3)
for x in small_primes:
    while p % x == 0: p //= x
```

**关键点：** 只要能构造两个共享秘密因子的量，`gcd(a, b)` 就是最便宜的分解器。小余因子再试除掉即可。

---

## Biased LSB Oracle with Mode-of-Runs Recovery (CSAW CTF 2018)

**模式：** LSB 预言机会以小概率给错答案，导致单次二分搜索无法稳定收敛。解决办法不是死磕某一次，而是把完整恢复过程跑很多遍，然后对每个字节取众数。正确字节即便无法在单次中全部收敛，也会在统计上最常出现。

```python
def recover():
    beg, end = 0, n - 1
    for bit in bits:
        mid = (beg + end) // 2
        if bit: beg = mid
        else:   end = mid
    return long_to_bytes(end)

byte_counts = [Counter() for _ in range(flag_len)]
for _ in range(N):
    flag = recover()
    for i, b in enumerate(flag):
        byte_counts[i][b] += 1
flag = bytes(c.most_common(1)[0][0] for c in byte_counts)
```

**关键点：** 有噪声的侧信道更适合做多数投票，而不是追求单次完美。

---

## Cube-Root Wraparound via AES-CTR Length Hint (hxp 2018)

**模式：** 低指数 RSA（`e = 3`）配合某种填充，使 `m^3 > n`，因此简单开立方失败。与此同时，AES-CTR 密文会泄露明文长度（CTR 不改长度），这能帮助你准确知道应当给密文加多少个 `n`，再去找整数立方根。

```python
inv = pow(inverse(2, n), 2040, n)
c = c * inv % n
for k in range(1000):
    m, ok = gmpy2.iroot(c + k*n, 3)
    if ok: flag = long_to_bytes(int(m)); break
```

**关键点：** 当真正的立方根落在 `c + k*n` 上时，长度提示能帮你把 `k` 的搜索压到很小。

---

## RSA p = next_prime(2^k + small) Shared-Prime Batch GCD (ASIS Finals 2018)

**模式：** Keygen 采用 `p = next_prime(2^k + random_small_delta)`。当两个不同 key 的 `delta` 落在同一素数间隔里时，会被 `next_prime` 收敛到同一个 `p`，从而在不同模数之间产生共享素因子。

```python
from math import gcd
for n_a in collected:
    for n_b in collected:
        if n_a == n_b: continue
        p = gcd(n_a, n_b)
        if 1 < p < n_a:
            q = n_a // p
            d = pow(e + 2, -1, (p-1)*(q-1))  # NMC 风格参数
            break
```

**关键点：** 任何把 prime 限制在“常量附近的小范围扰动”里的 keygen，都很容易通过 pairwise GCD 被一锅端。

---

## PNG Encryption Bounded by 512-bit Key → Trailer Replacement (ASIS Finals 2018)

**模式：** 某自定义“多项式 bit sum”密码把 PNG 字节加密成 `C = sum(bit_i * (exp^i + (-1)^i))`。由于 key 长度最多 512 bit，受影响的明文字节最多 64 字节。既然 PNG 的尾部 IDAT + IEND 可以从任意参考图像恢复，不如直接拼回标准尾部。

```python
# 只有前 64 字节受 key 影响，后面与明文逐字节相同
first64 = decrypt_affected_prefix(ct)
rest    = original_png[64:]                # 从参考 PNG 直接拷贝
open('recovered.png', 'wb').write(first64 + rest)
```

**关键点：** 如果密钥长度本身就限制了“最多影响多少字节”，那比起深挖密码学，更应优先考虑文件格式修复。

---

## Modulus Recovery via Plaintext Malleability (X-MAS 2018)

**模式：** Oracle 会返回解密明文，但故意隐藏模数 `N`。发送相关密文 `c` 和 `c * 2^e`，它们对应的明文分别是 `m` 和 `(2m) mod N`。若发生模回绕，则差值 `2m - (2m mod N)` 正好等于 `N`。

```python
m1 = decrypt(ct)                       # m
m2 = decrypt((ct * pow(2, e, m1)) % m1)  # 2m mod N
N = 2*m1 - m2 if 2*m1 != m2 else None
```

**关键点：** 这是利用 RSA 同态和模回绕来“量出”模数本身。

---

## RSA CRT d_p NULL-Byte Overflow Primes Leak (P.W.N. CTF 2018)

**模式：** 服务端用 `fgets()` 读 `d_p` 时没有边界检查。发送 33+ 个空字节会把 `d_p_str` 截断成 0，导致 CRT 路径中 `m_2 = 0^0 = 1`。最终签名落到 `m - 1` 上，于是通过 GCD 就能恢复 `p`。

```python
io.send(b'\x00' * 40)                 # 覆盖 d_p buffer
sig = io.recvline()
p = gcd(sig - 1, N)                   # 直接分解！
```

**关键点：** 任何从网络输入解析 CRT 参数的实现，都要警惕“把 `d_p` 搞成 0”这类攻击。

---

## Textbook RSA Signature Blinding via Message Factoring (P.W.N. CTF 2018)

**模式：** 无填充 RSA 签名拒绝对某些消息签名（黑名单），但乘法同态允许你把目标消息 `m` 分解成两个可签因子 `x, y`，请求各自签名，再相乘得到 `sig(m)`。

```python
for x in range(2, 10000):
    if (m * pow(x, -1, N)) % N == allowed_y:
        y = allowed_y
        sig = (sign(x) * sign(y)) % N
        break
```

**关键点：** 本质上和前面的乘法同态签名伪造是一回事，只不过这里用“因子分解 + 黑名单绕过”的角度呈现。

---

## Last-Byte Modulus Overwrite via strlen-1 Null Truncation (OTW Advent 2018)

**模式：** 服务端用 `username[strlen(username)-1] = 0` 去掉换行。若传入空用户名，`strlen == 0`，这个写入就会回退 1 字节，把 username 缓冲区前面的数据覆盖成 0，而那里碰巧是模数 `N` 的最后一个字节。被改过的 `N` 与真实值只差不超过 255，因此通常能快速被分解。

```python
io.sendline(b'')                       # 空用户名，覆写 N[-1]
N_corrupt = recv_N()
for delta in range(256):
    if is_factorable(N_corrupt + delta - 255):
        N_real = N_corrupt + delta - 255; break
```

**关键点：** `buf[strlen(buf)-1] = 0` 是典型 off-by-one 写法；当 `strlen == 0` 时，会往缓冲区前一个字节写 0。若前面正好放着密码学常量，往往就是直接入口。

---

## CRC32 Collision Oracle + RSA Homomorphic Signature Forgery (BSidesSF 2019)

**模式（rsaos）：** Shell 暴露的是 `RSA(foldhash(cmd))` 这种“签名”，其中 `foldhash` 是由 CRC 风格结构构成的 10-byte 摘要，可分解。特权命令虽然被屏蔽，但服务端愿意为任意普通字符串签名。若能找到一个特权命令，使其 fold 值完全分解成 `< 2^32` 的小因子，那么就能为每个因子各构造一条 CRC32 精确碰撞的普通命令，拿到它们的签名后直接相乘，得到目标命令的签名。

```python
from primefac import primefac
import subprocess, random

def find_cmd_crc(target_crc):
    while True:
        open('/tmp/cmd', 'w').write(f'echo {random.randint(0, 10000)}')
        cmd = subprocess.check_output(['./crchack/crchack', '/tmp/cmd', hex(target_crc)])
        if b'\n' not in cmd:
            return cmd

def find_cmd_fac(priv):
    while True:
        c = f'{priv} {random.randint(0, 10000)}'.encode()
        fs = list(primefac(foldhash(c)))
        if all(f < 2**32 for f in fs):
            return c, fs

priv_cmd, factors = find_cmd_fac('get-flag')
t = 1
for f in factors:
    cmd = find_cmd_crc(f)
    _, sig = get_sig(cmd)
    t = (t * sig) % N
send_priv(priv_cmd, sig=hex(t % N))
```

**关键点：** 如果“哈希”既可分解，又能通过碰撞工具（如 `crchack`）精确实现目标值，而签名方案又是 textbook RSA，那么这三者一拼就是完整的签名伪造链。
