# CTF Crypto - 异构代数结构（第二部分）

收录 2017 年之后常见的异构密码攻击：BB-84、ElGamal 变体、Paillier 预言机、差分隐私、同态取位、Jordan 标准形、OSS 伪造、Cayley-Purser、BIP39、Asmuth-Bloom、Rabin 多项式素数、LCG 周期、Vandermonde 恢复等。基础篇见 [exotic-crypto.md](exotic-crypto.md)。

## Table of Contents
- [BB-84 量子密钥分发 MITM（PlaidCTF 2017）](#bb-84-quantum-key-distribution-mitm-attack-plaidctf-2017)
- [当 B = p-1 时 ElGamal 的平凡 DLP（Hack.lu 2017）](#elgamal-trivial-dlp-when-b--p-1-hacklu-2017)
- [通过同态翻倍实现 Paillier LSB 预言机（CODE BLUE 2017）](#paillier-lsb-oracle-via-homomorphic-doubling-code-blue-2017)
- [差分隐私 Laplace 噪声抵消（Pwn2Win 2017）](#differential-privacy-laplace-noise-cancellation-pwn2win-2017)
- [同态加密预言机的 bit 提取（Tokyo Westerns 2017）](#homomorphic-encryption-oracle-bit-extraction-tokyo-westerns-2017)
- [通过 Jordan 标准形破解矩阵上的 ElGamal（SharifCTF 8）](#elgamal-over-matrices-via-jordan-normal-form-sharifctf-8)
- [利用 Pollard 组合公式伪造 OSS 签名（SharifCTF 8）](#oss-ong-schnorr-shamir-signature-forgery-via-pollards-method-sharifctf-8)
- [无需私钥的 Cayley-Purser 解密（TJCTF 2018）](#cayley-purser-decryption-without-private-key-tjctf-2018)
- [通过校验和暴力 BIP39 缺失助记词（SECCON 2018）](#bip39-partial-mnemonic-brute-force-via-checksum-seccon-2018)
- [通过 CRT 恢复 Asmuth-Bloom 门限秘密（X-MAS 2018）](#asmuth-bloom-threshold-secret-sharing-via-crt-x-mas-2018)
- [使用多项式素数的 Rabin 密码体制（X-MAS 2018）](#rabin-cryptosystem-with-polynomial-primes-x-mas-2018)
- [利用 LCG 周期实现无限输出预测（X-MAS 2018）](#lcg-period-detection-for-unlimited-output-prediction-x-mas-2018)
- [通过 Vandermonde 线性系统恢复多项式系数（X-MAS 2018）](#polynomial-coefficient-recovery-via-vandermonde-linear-system-x-mas-2018)
- [通过四根 CRT 组合完成 Rabin 解密（Pragyan CTF 2019）](#rabin-decryption-via-four-roots-crt-combination-pragyan-ctf-2019)

---

## BB-84 Quantum Key Distribution MITM Attack (PlaidCTF 2017)

**模式：** 在没有认证的模拟版 BB-84 中，完全可以对 Alice 和 Bob 分别做中间人协商。

```python
# 策略：总是用 Z 基测量，并总是向 Bob 发送值 1
# Alice 侧：随机基测量并记录结果
# Bob 侧：永远收到 Z 基下的 1
# Bob 的 key = 全 1（攻击者已知）
# Alice 的 key = 攻击者测得的 qubit 值

for qbit in alice_qbits:
    my_basis = 'Z'
    my_value = measure(qbit, my_basis)
    send_to_bob(basis='Z', value=1)
```

**关键点：** BB-84 只有在经典信道已认证时才安全。若经典信道未认证，攻击者完全可以分别与双方协商出两把不同的 key。

**参考：** PlaidCTF 2017

---

## ElGamal Trivial DLP When B = p-1 (Hack.lu 2017)

**模式：** ElGamal 公钥满足 `B = g^key mod p`。若碰巧 `B + 1 == p`，也就是 `B = -1 mod p`，则根据欧拉判别法，任何 primitive root `g` 都有 `g^((p-1)/2) ≡ -1 (mod p)`。因此私钥直接就是 `(p-1)/2`。

```python
if (B + 1) == p:
    key = (p - 1) // 2
    assert pow(g, key, p) == B
```

**关键点：** 在尝试任何通用 DLP 算法前，先检查 `B == p-1` 和 `B == 1` 这两个平凡边界值。

**参考：** Hack.lu CTF 2017

---

## Paillier LSB Oracle via Homomorphic Doubling (CODE BLUE 2017)

**模式：** Paillier 具备加法同态，因此 `ct^2 mod n^2` 等价于“把明文翻倍”。不断翻倍并观察最低位何时变化，就能像 RSA LSB 预言机一样一位一位恢复明文。

```python
def paillier_double(ct, n):
    """同态地把明文翻倍。"""
    return pow(ct, 2, n * n)

def recover_plaintext(ct, oracle_lsb, n):
    """oracle 返回解密后明文的 LSB。"""
    lower, upper = 0, n
    current_ct = ct
    for _ in range(n.bit_length()):
        current_ct = paillier_double(current_ct)
        lsb = oracle_lsb(current_ct)
        mid = (lower + upper) // 2
        if lsb == 1:
            lower = mid
        else:
            upper = mid
    return lower
```

**关键点：** Paillier 的加法同态足以支持与 RSA LSB 预言机完全同构的二分搜索。

**参考：** CODE BLUE CTF 2017

---

## Differential Privacy Laplace Noise Cancellation (Pwn2Win 2017)

**模式：** 服务端用 Laplace 噪声给字符 ordinal 做差分隐私保护。由于 Laplace 噪声均值为 0，只要对同一位置重复查询并求平均，噪声就会被大数定律抵消。

```python
import requests
import statistics

def recover_char(position, num_queries=1000):
    samples = []
    for _ in range(num_queries):
        noisy_val = query_server(position)
        samples.append(noisy_val)
    true_val = round(statistics.mean(samples))
    return chr(true_val)

flag = ''.join(recover_char(i) for i in range(flag_length))
```

**关键点：** 任何零均值加性噪声，如果查询次数不受限，本质上都能被平均掉。这里不是“破解 Laplace”，而是“攻击无限查询预算”。

**参考：** Pwn2Win CTF 2017

---

## Homomorphic Encryption Oracle Bit-Extraction (Tokyo Westerns 2017)

**模式：** 某同态加密 oracle 允许你对密文做某种操作，相当于对明文“加 1”。通过观察明文何时跨过 `2^k` 边界，可以逐 bit 恢复未知明文。

**提取低位（观察溢出）：**
```python
ct = target_ciphertext
for bit_pos in range(num_bits):
    threshold = 2 ** bit_pos
    increments = 0
    prev_ct = ct
    while True:
        ct = homomorphic_add_one(ct)
        increments += 1
        if bit_has_flipped(ct, prev_ct, bit_pos):
            low_bits = (threshold - increments) % threshold
            break
```

**提取高位（反复除以 2）：**
```python
even_ct = homomorphic_subtract(target_ct, low_bits)
for i in range(high_bit_count):
    even_ct = homomorphic_halve(even_ct)
    high_bits = (high_bits << 1) | observe_lsb(even_ct)
```

**关键点：** 只要加密方案支持“对明文做可控线性操作”，再配上某种可观察性，就可以逐 bit 榨出明文。

**参考：** Tokyo Westerns CTF 2017

---

## ElGamal over Matrices via Jordan Normal Form (SharifCTF 8)

**模式：** 在矩阵群上做离散对数。先把 generator `G` 化到 Jordan 标准形，再从上三角超对角元素里读出指数。

```sage
G = Matrix(GF(p), [[...]])
H = Matrix(GF(p), [[...]])
J, P = G.jordan_form(transformation=True)
H_prime = ~P * H * P
# 对 Jordan block，有 J^alpha 的超对角项 = alpha * lambda^(alpha-1)
alpha = int(J[3][3] * H_prime[3][4] / H_prime[4][4])
```

**关键点：** 矩阵 DLP 并不一定比普通 DLP 难。若矩阵可对角化，就会分解成多个标量 DLP；若存在 Jordan block，超对角项常直接泄露指数。

**参考：** SharifCTF 8（2018）

---

## OSS (Ong-Schnorr-Shamir) Signature Forgery via Pollard's Method (SharifCTF 8)

**模式：** 已知两个合法 OSS 签名，利用 Pollard 组合公式，直接伪造它们消息乘积的签名。

```python
def forge_product(x1, y1, x2, y2, k, n):
    X = (x1*x2 + k*y1*y2) % n
    Y = (x1*y2 - x2*y1) % n
    return X, Y
```

OSS 的判定式是 `x^2 + k*y^2 = m (mod n)`，而这种二次型在代数上是可组合的。

**关键点：** 这是协议本身的代数破绽，不是实现 bug。给定若干签名，就能通过乘法结构拼出新的签名。

**参考：** SharifCTF 8（2018）

---

## Cayley-Purser Decryption Without Private Key (TJCTF 2018)

**模式：** Cayley-Purser 是一种 2×2 矩阵公钥系统。公开参数为 `(alpha, beta, gamma)`，私钥是某个指数 `r`。但解密其实只需要一个与 `gamma` 对易的矩阵 `H`，而这个 `H` 可以完全由公开信息构造出来。

```python
from sage.all import matrix, identity_matrix

invalpha = alpha.inverse()
h_elems = (invalpha * gamma - gamma * beta)
h_denom = (beta - invalpha)
h = matrix([[h_elems[i][j] / h_denom[i][j] for j in range(2)] for i in range(2)])

H = h[0][0] * identity_matrix(2) + gamma
plaintext = (H.inverse() * epsilon * H) * mu * (H.inverse() * epsilon * H)
```

**关键点：** 任何与 `gamma` 对易的矩阵都能充当“解密 key”。而 Cayley-Hamilton 保证这种矩阵可写成 `c1*I + c2*gamma` 的形式，因此根本不需要恢复私钥指数。

**参考：** TJCTF 2018，writeup 10680

---

## BIP39 Partial-Mnemonic Brute Force via Checksum (SECCON 2018)

**模式：** 题目给了 24 个 BIP39 助记词中的 23 个，剩下一个未知。每个词只有 11 bit，因此未知空间只有 2048 种。对每个候选词跑一次 BIP39 校验和，正确答案会自动通过。

```python
from mnemonic import Mnemonic
lg = Mnemonic("japanese")
known = ["...23 words..."]
for w in lg.wordlist:
    try:
        if lg.check(" ".join(known + [w])):
            entropy = lg.to_entropy(" ".join(known + [w]))
            print(md5(entropy).hexdigest())
    except Exception:
        pass
```

**关键点：** BIP39 自带 checksum，因此部分助记词天然可自验证。Electrum seed 等也有类似结构。

**参考：** SECCON 2018，mnemonic，writeup 12053

---

## Asmuth-Bloom Threshold Secret Sharing via CRT (X-MAS 2018)

**模式：** 不是 Shamir 多项式，而是 Asmuth-Bloom：share 的形式是 `(s_i, p_i)`，其中 `s_i = S mod p_i`，而 `p_i` 两两互素。给出足够多的 share 后，直接 CRT 即可恢复 secret。

```python
from sympy.ntheory.modular import crt

residues = [s for s, _ in shares]
moduli   = [p for _, p in shares]
S, M = crt(moduli, residues)
flag = long_to_bytes(int(S))
```

**关键点：** Asmuth-Bloom 的 share 格式包含模数；Shamir 则只给 `(x, y)` 点值。看到 `(residue, modulus)` 就要立刻想到 CRT。

**参考：** X-MAS CTF 2018，writeup 12660

---

## Rabin Cryptosystem with Polynomial Primes (X-MAS 2018)

**模式：** Rabin 的素数并不是随机生成，而是来自某个低维多项式变量 `r`，如 `p = r^2 + 3`、`q = r^2 + 7`。于是 `N = p*q` 也变成关于 `r` 的多项式，可直接用整数根恢复。

```python
from gmpy2 import iroot

# N = (r^2+3)(r^2+7) = r^4 + 10r^2 + 21
r, _ = iroot(N - 21, 4)
p, q = r*r + 3, r*r + 7
x_p = pow(ct, (p+1)//4, p)
x_q = pow(ct, (q+1)//4, q)
# 再用 CRT 合并四个根，挑有已知结构的那个
```

**关键点：** 只要 prime 来源于某个小变量的多项式，密钥生成就不再随机，常可直接退化成整数开方。

**参考：** X-MAS CTF 2018，writeups 12657, 12724

---

## LCG Period Detection for Unlimited Output Prediction (X-MAS 2018)

**模式：** 服务端使用短周期 LCG。只要不断请求，直到看到一个重复输出，就等于找到了周期。此后全部未来值都能预测。

```python
seen = {}
for i in itertools.count():
    v = fetch_next()
    if v in seen:
        period = i - seen[v]
        break
    seen[v] = i
# 之后 future[i] == history[(i - period_start) % period]
```

**关键点：** LCG 天生周期有限，只要交互预算足够、输出空间不大，就有机会直接靠周期检测获胜。

**参考：** X-MAS CTF 2018，writeups 12668, 12669

---

## Polynomial Coefficient Recovery via Vandermonde Linear System (X-MAS 2018)

**模式：** Oracle 会对一个隐藏的 `degree-n` 多项式做求值。拿到 `n+1` 个点后，构造 Vandermonde 矩阵即可恢复所有系数。

```python
from sage.all import matrix, vector, GF
pts = [(x_i, f(x_i)) for x_i in range(degree+1)]
A = matrix([[xi**k for k in range(degree+1)] for xi, _ in pts])
b = vector([yi for _, yi in pts])
coeffs = A.solve_right(b)
```

**关键点：** 任何“神秘多项式”“曲线插值”类 oracle，只要次数不高且点数足够，本质上都是线性代数。

**参考：** X-MAS CTF 2018，writeup 12722

---

## Rabin Decryption via Four-Roots CRT Combination (Pragyan CTF 2019)

**模式（Help Rabin）：** Rabin 加密 `c = m^2 mod n`，其中 `n = p*q`，且 `p, q ≡ 3 mod 4`。一旦恢复 `p, q`（这里是通过 Fermat 风格的相邻素数结构），就可以对每个素数模分别开平方，再 CRT 合并得到四个候选根，只有一个是合法明文。

```python
from Crypto.Util.number import inverse

def ext_gcd(a, b):
    c0, c1, a0, a1, b0, b1 = a, b, 1, 0, 0, 1
    while c1:
        q, r = divmod(c0, c1)
        c0, c1 = c1, r
        a0, a1 = a1, a0 - q * a1
        b0, b1 = b1, b0 - q * b1
    return a0, b0, c0

pe, qe = (p + 1) // 4, (q + 1) // 4
mp, mq = pow(c, pe, p), pow(c, qe, q)
yp, yq, _ = ext_gcd(p, q)

r1 = (yp * p * mq + yq * q * mp) % n
r2 = n - r1
s1 = (yp * p * mq - yq * q * mp) % n
s2 = n - s1

for cand in (r1, r2, s1, s2):
    try:
        pt = bytes.fromhex(hex(cand)[2:])
        if pt.isascii():
            print(pt)
    except Exception:
        pass
```

**关键点：** Rabin 解密天然会产生四个候选，因为 `x^2 ≡ c mod pq` 总有四个根。`p, q ≡ 3 mod 4` 时，单素数模上的平方根是闭式可算的；再配合已知前缀、ASCII 或魔数挑出正确解即可。
