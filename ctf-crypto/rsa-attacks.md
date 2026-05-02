# CTF Crypto - RSA 攻击

## Table of Contents
- [小公钥指数（开立方根）](#small-public-exponent-cube-root)
- [共模攻击](#common-modulus-attack)
- [Wiener 攻击（小私钥指数）](#wieners-attack-small-private-exponent)
- [Pollard's p-1 分解](#pollards-p-1-factorization)
- [Hastad 广播攻击](#hastads-broadcast-attack)
- [连续素数 RSA（Fermat 分解）](#rsa-with-consecutive-primes-fermat-factorization)
- [多素数 RSA](#multi-prime-rsa)
- [受限数字素数的 RSA（LACTF 2026）](#rsa-with-restricted-digit-primes-lactf-2026)
- [结构化 RSA 素数上的 Coppersmith（LACTF 2026）](#coppersmith-for-structured-rsa-primes-lactf-2026)
- [Manger RSA 填充预言机攻击（Nullcon 2026）](#mangers-rsa-padding-oracle-attack-nullcon-2026)
- [通过计时预言机对 RSA-OAEP 进行 Manger 攻击（HTB Early Bird）](#mangers-attack-on-rsa-oaep-via-timing-oracle-htb-early-bird)
- [带平凡根的多项式哈希（Pragyan 2026）](#polynomial-hash-with-trivial-root-pragyan-2026)
- [GF(2)[x] 上的多项式 CRT（Nullcon 2026）](#polynomial-crt-in-gf2x-nullcon-2026)
- [非素数模上的仿射密码（Nullcon 2026）](#affine-cipher-over-non-prime-modulus-nullcon-2026)
- [带线性填充的 Hastad 广播攻击 -- Coppersmith（PlaidCTF 2017）](#hastad-broadcast-attack-with-linear-padding----coppersmith-plaidctf-2017)
- [Franklin-Reiter 相关消息攻击（RSA e=3，N1CTF 2018）](#franklin-reiter-related-message-attack-on-rsa-e3-n1ctf-2018)
- [线性相关素数上的 Coppersmith 攻击（ASIS CTF 2018）](#coppersmith-attack-on-linearly-related-rsa-primes-asis-ctf-2018)
- [rsa-attacks-2.md: RSA p=q 校验绕过（BearCatCTF 2026）](rsa-attacks-2.md#rsa-pq-validation-bypass-bearcatctf-2026)
- [rsa-attacks-2.md: gcd(e, phi) > 1 时的 RSA 立方根 CRT（BearCatCTF 2026）](rsa-attacks-2.md#rsa-cube-root-crt-when-gcde-phi--1-bearcatctf-2026)
- [rsa-attacks-2.md: 从 phi(n) 的倍数中分解 n（BearCatCTF 2026）](rsa-attacks-2.md#factoring-n-from-multiple-of-phin-bearcatctf-2026)
- [rsa-attacks-2.md: 利用乘法同态伪造 RSA 签名（MMA CTF 2015）](rsa-attacks-2.md#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015)
- [rsa-attacks-2.md: 基表示导致的弱 RSA 密钥生成（Sharif CTF 2016）](rsa-attacks-2.md#weak-rsa-key-generation-via-base-representation-sharif-ctf-2016)
- [rsa-attacks-2.md: gcd(e, phi(n)) > 1 的 RSA（CSAW 2015）](rsa-attacks-2.md#rsa-with-gcde-phin--1-csaw-2015)
- [rsa-attacks-2.md: 共素因子的批量 GCD 分解（BSidesSF 2025）](rsa-attacks-2.md#batch-gcd-for-shared-prime-factoring-bsidessf-2025)
- [rsa-attacks-2.md: 从 dp dq qinv 恢复 RSA 部分私钥（0CTF 2016）](rsa-attacks-2.md#rsa-partial-key-recovery-from-dp-dq-qinv-0ctf-2016)
- [rsa-attacks-2.md: RSA-CRT 故障攻击 / 比特翻转恢复（CSAW CTF 2016）](rsa-attacks-2.md#rsa-crt-fault-attack--bit-flip-recovery-csaw-ctf-2016)
- [rsa-attacks-2.md: RSA 同态解密预言机绕过（ECTF 2016）](rsa-attacks-2.md#rsa-homomorphic-decryption-oracle-bypass-ectf-2016)
- [rsa-attacks-2.md: 含小素因子的 RSA 与 CRT 分解（Hack The Vote 2016）](rsa-attacks-2.md#rsa-with-small-prime-factors-and-crt-decomposition-hack-the-vote-2016)

---

## Small Public Exponent (Cube Root)

**模式：** 公钥指数很小（通常是 3），且明文也足够小。当 `m^e < n` 时，密文实际上就是整数意义下的 `m^e`，没有发生模回绕，所以直接开 e 次方根即可。

```python
import gmpy2

def small_e_attack(c, e):
    """当 m^e < n（没有模回绕）时恢复明文。"""
    m, exact = gmpy2.iroot(c, e)
    if exact:
        return int(m)
    return None

# 使用示例
m = small_e_attack(c, e=3)
print(bytes.fromhex(hex(m)[2:]))
```

**何时失败：** 如果 `m^e > n`（例如消息较长或做了填充），模约减就会破坏这个简单结构。此时应改试 Hastad 广播攻击或 Coppersmith。

---

## Common Modulus Attack

**模式：** 同一条消息在相同模数 `n` 下，用两个不同公钥指数 `e1`、`e2` 加密，且 `gcd(e1, e2) = 1`。无需分解 `n` 即可恢复明文。

```python
from math import gcd

def common_modulus_attack(c1, c2, e1, e2, n):
    """当两次加密共享同一 n，且 e1/e2 互素时恢复明文。"""
    # 扩展 GCD：求 a, b，使 a*e1 + b*e2 = 1
    def extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    g, a, b = extended_gcd(e1, e2)
    assert g == 1, "e1 and e2 must be coprime"

    # m = c1^a * c2^b mod n
    # 若指数为负，则改用模逆
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

**关键点：** 共享模数 + 同一消息 + 互素指数，会因 Bezout 恒等式直接泄露明文，完全不需要分解 `n`。

---

## Wiener's Attack (Small Private Exponent)

**模式：** 私钥指数 `d` 很小（`d < N^0.25`）。`e/n` 的连分数展开会把 `d` 暴露出来。

```python
def wiener_attack(e, n):
    """当 d < N^0.25 时，通过 e/n 的连分数恢复 d。"""
    def continued_fraction(num, den):
        cf = []
        while den:
            q, r = divmod(num, den)
            cf.append(q)
            num, den = den, r
        return cf

    def convergents(cf):
        convs = []
        h0, h1 = 0, 1
        k0, k1 = 1, 0
        for a in cf:
            h0, h1 = h1, a * h1 + h0
            k0, k1 = k1, a * k1 + k0
            convs.append((h1, k1))
        return convs

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        # 若 d 合法，则 phi = (e*d - 1) / k 应为整数
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # phi = (p-1)(q-1) = n - p - q + 1，所以 p+q = n - phi + 1
        s = n - phi + 1
        # p、q 是 x^2 - s*x + n = 0 的根
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        from math import isqrt
        t = isqrt(discriminant)
        if t * t == discriminant:
            return d
    return None

# 使用示例
d = wiener_attack(e, n)
m = pow(c, d, n)
```

**何时使用：** 若 `e` 特别大、接近 `n`，往往意味着 `d` 很小。也可以直接试 `owiener`：`pip install owiener`。

---

## Pollard's p-1 Factorization

**模式：** `n` 的某个素因子 `p` 满足 `p-1` 很 smooth（它的所有素因子都较小）。计算 `a^(B!) mod n` 后再与 `n` 求 GCD，即可把 `p` 拉出来。

```python
from math import gcd

def pollard_p1(n, B=100000):
    """当某个素因子 p 的 p-1 在 B 范围内足够 smooth 时分解 n。"""
    a = 2
    for j in range(2, B + 1):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
    return None

# 使用
result = pollard_p1(n)
if result:
    p, q = result
```

**关键点：** 根据费马小定理，如果 `p-1` 整除 `B!`，则 `a^(B!) ≡ 1 (mod p)`，于是 `gcd(a^(B!) - 1, n)` 就会给出 `p`。对更大的 smooth bound 逐渐增大 `B` 即可。

---

## Hastad's Broadcast Attack

**模式：** 相同明文 `m` 用相同的公钥指数 `e`（通常是 3）在 `e` 个不同模数下分别加密。利用 CRT 重建 `m^e`，再开 e 次方根。

```python
from functools import reduce

def hastad_broadcast(ciphertexts, moduli, e):
    """从 e 个相同指数的加密中恢复 m。"""
    assert len(ciphertexts) >= e and len(moduli) >= e

    # 中国剩余定理
    def crt(remainders, moduli):
        N = reduce(lambda a, b: a * b, moduli)
        result = 0
        for r, m in zip(remainders, moduli):
            Ni = N // m
            Mi = pow(Ni, -1, m)
            result += r * Ni * Mi
        return result % N

    # CRT 重建出 m^e（模 N1*N2*...*Ne）
    # 因为 m < 每个 Ni，所以 m^e < N1*N2*...*Ne，没有模回绕
    me = crt(ciphertexts[:e], moduli[:e])

    import gmpy2
    m, exact = gmpy2.iroot(me, e)
    if exact:
        return int(m)
    return None

# 示例（e=3，三个密文）
m = hastad_broadcast([c1, c2, c3], [n1, n2, n3], e=3)
print(bytes.fromhex(hex(m)[2:]))
```

**关键点：** CRT 把多个同余方程合并后，得到的是整数意义下的 `m^e`，因为没有发生模回绕。再开根即可。

---

## Hastad Broadcast Attack with Linear Padding -- Coppersmith (PlaidCTF 2017)

**模式：** Hastad 的推广版。每个接收者并非直接加密相同的 `m`，而是加密 `a_i*m + b_i`，即 `c_i = (a_i * m + b_i)^e mod n_i`。

```python
# 标准 Hastad 要求相同明文
# 加上线性填充后：每个密文实际在加密 a_i*m + b_i
# 使用 CRT 合并，再对合成多项式跑 Coppersmith small_roots

from sage.all import *
# 先用 CRT 合并
N = prod(n_values)
T = [crt_coefficient(i, n_values) for i in range(e)]

P = PolynomialRing(Zmod(N), 'x')
x = P.gen()
poly = sum(T[i] * ((a[i]*x + b[i])**e - c[i]) for i in range(e))
poly = poly.monic()

# Coppersmith 找小根
roots = poly.small_roots(epsilon=1/30)
flag = int(roots[0])
```

**关键点：** 即便每个接收者先对消息做了已知仿射变换，CRT 仍能把它们合成一条关于 `m` 的 e 次多项式方程。只要 `m` 足够小，Coppersmith 就能把它作为小根挖出来。

**参考：** PlaidCTF 2017

---

### Franklin-Reiter Related Message Attack on RSA e=3 (N1CTF 2018)

**模式：** 服务器加密的是 `m + padding`，其中 `padding = sha256(user_input)`，且 `e = 3`。若你拿到两条已知填充差值的密文，就能在 `Zmod(n)` 上对多项式做 GCD，直接恢复 `m`。（N1CTF 2018）

```python
# SageMath
def franklin_reiter(n, pad1, pad2, c1, c2):
    R.<X> = PolynomialRing(Zmod(n))
    f1 = (X + pad1)^3 - c1
    f2 = (X + pad2)^3 - c2
    return -gcd(f1, f2).coefficients()[0]
```

**关键点：** 对于 `e=3`，若同一消息以两个已知仿射变换形式被加密，那么对应多项式共享一个公共根，这个根就是原始消息。

---

### Coppersmith Attack on Linearly-Related RSA Primes (ASIS CTF 2018)

**模式：** 当 RSA 素数满足近似线性关系 `q ~ 4p` 时，可以先由 `sqrt(4*n)` 近似 `q`，再用 Coppersmith 的 `small_roots` 找出误差项。（ASIS CTF 2018）

```python
# SageMath
qbar = isqrt(4 * n)
R.<x> = PolynomialRing(Zmod(n))
f = x + qbar
roots = f.small_roots(X=2^200, beta=0.5)  # 找小误差项
q = qbar + int(roots[0])
p = n // q
```

**关键点：** 当 `q ~ k*p` 且 `k` 已知时，就有 `q ~ sqrt(k*n)`。如果真实值与近似值的差足够小，就可用 Coppersmith 求出误差，从而分解 `n`。

---

## RSA with Consecutive Primes (Fermat Factorization)

**模式（Loopy Primes）：** `q = next_prime(p)`，于是 `p ~ q ~ sqrt(N)`。这本质上就是 Fermat 分解的适用条件：`|p-q|` 很小。

**分解方法：** 从 `sqrt(N)` 附近往下找第一个素因子：
```python
from sympy import nextprime, prevprime, isqrt

root = isqrt(n)
p = prevprime(root + 1)
while n % p != 0:
    p = prevprime(p)
q = n // p
```

**多层变体：** 也会遇到 1024 层嵌套 RSA，每层都使用连续素数。此时只要按相反顺序逐层解密即可。

---

## Multi-Prime RSA

当 `N` 是许多小素数的乘积，而不是普通的 `p*q`：
```python
# 先分解 N（通常更容易）
from sympy import factorint
factors = factorint(n)  # 返回 {p1: e1, p2: e2, ...}

# 用所有因子计算 phi
phi = 1
for p, e in factors.items():
    phi *= (p - 1) * (p ** (e - 1))

d = pow(e, -1, phi)
plaintext = pow(ciphertext, d, n)
```

---

## RSA with Restricted-Digit Primes (LACTF 2026)

**模式（six-seven）：** RSA 的两个素数 `p, q` 只由数字集合 `{6, 7}` 构成，且末位是 7。

**从低位逐位分解：**
```python
# 每一轮已知 p mod 10^k -> 可算 q mod 10^k = n * p^{-1} mod 10^k
# 剪枝：仅保留第 k 位仍属于 {6,7} 的 p 和 q 候选
candidates = [(6,), (7,)]  # p 最低位只能是 6 或 7
for k in range(1, num_digits):
    new_candidates = []
    for p_digits in candidates:
        for d in [6, 7]:
            p_val = sum(p_digits[i] * 10**i for i in range(len(p_digits))) + d * 10**k
            q_val = (n * pow(p_val, -1, 10**(k+1))) % 10**(k+1)
            q_digit_k = (q_val // 10**k) % 10
            if q_digit_k in {6, 7}:
                new_candidates.append(p_digits + (d,))
    candidates = new_candidates
```

**一般规律：** 只要素数的十进制 / 某进制数字来自很小的字符集，就可以从低位开始用模运算做逐位恢复，并在每一位都做强剪枝。

---

## Coppersmith for Structured RSA Primes (LACTF 2026)

**模式（six-seven-again）：** `p = base + 10^k * x`，其中 `base` 已知，`x` 很小（`x < N^0.25`）。

**用 SageMath 攻击：**
```python
# 构造 f(x)，满足 f(x_secret) = 0 (mod p)，因而也为 0 (mod N)
# p = base + 10^k * x -> x + base * (10^k)^{-1} = 0 (mod p)
R.<x> = PolynomialRing(Zmod(N))
f = x + (base * inverse_mod(10**k, N)) % N
roots = f.small_roots(X=2**70, beta=0.5)  # x < N^0.25
```

**何时使用：** 只要某个素数有一部分已知，且未知部分足够小以满足 Coppersmith 界，这就是优先路线。

---

## Manger's RSA Padding Oracle Attack (Nullcon 2026)

**模式（TLS, Nullcon 2026）：** 对 RSA 加密的 key 提供阈值预言机。第一阶段不断倍增 `f`，直到 `k*f >= threshold`；第二阶段做二分。对 64-bit key 约需 128 次查询。

完整实现见 [advanced-math.md](advanced-math.md)。

---

## Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)

**模式：** Flask 应用实现了带自定义哈希（PBKDF2，200 万轮）的 RSA-OAEP。Python 的 `or` 短路会造成计时预言机：若首字节 `Y != 0`，后面的昂贵 PBKDF2 根本不会执行（约 0.6s）；若 `Y == 0`，PBKDF2 会跑完（约 2s）。

**脆弱代码模式：**
```python
if Y != 0 or not self.H_verify(self.L, DB[:self.hLen]) or self.os2ip(PS) != 0:
    return {"ok": False, "error": "decryption error"}
```

**预言机映射：** 响应快 -> `Y != 0`（解密消息 `>= B`）。响应慢 -> `Y == 0`（解密消息 `< B = 2^(8*(k-1))`）。

**如何校准网络环境：**
```python
def calibrate(n, e, k):
    B = pow(2, 8 * (k - 1))
    slow_times, fast_times = [], []
    for i in range(5):
        # 已知慢：加密结果 < B
        enc = pow(B - 1 - i*100, e, n).to_bytes(k, 'big')
        slow_times.append(measure(enc))
        # 已知快：加密结果 > B
        enc = pow(B + 1 + i*100, e, n).to_bytes(k, 'big')
        fast_times.append(measure(enc))
    FAST_UPPER = max(fast_times) * 1.5
    SLOW_LOWER = min(slow_times) * 0.9
```

**对模糊结果重试：**
```python
def padding_oracle(c_int):
    while True:
        total = measure_response_time(c_int)
        if SLOW_LOWER < total < SLOW_UPPER:
            return True   # Y == 0（小于 B）
        elif total < FAST_UPPER:
            return False  # Y != 0（大于 B）
        # 模棱两可：重试
```

**完整 3 步 Manger 攻击（1024-bit RSA 约 1024 轮）：**
```python
# 第 1 步：找 f1，使 f1 * m >= B
f1 = 2
while oracle((pow(f1, e, n) * c) % n):
    f1 *= 2

# 第 2 步：找 f2，使 n <= f2 * m < n + B
f2 = (n + B) // B * f1 // 2
while not oracle((pow(f2, e, n) * c) % n):
    f2 += f1 // 2

# 第 3 步：二分逼近 m
mmin, mmax = ceil_div(n, f2), floor_div(n + B, f2)
while mmin < mmax:
    f = floor_div(2 * B, mmax - mmin)
    i = floor_div(f * mmin, n)
    f3 = ceil_div(i * n, mmin)
    if oracle((pow(f3, e, n) * c) % n):
        mmax = floor_div(i * n + B, f3)
    else:
        mmin = ceil_div(i * n + B, f3)
m = mmin
```

**恢复后再做 OAEP 解码：**
```python
from Crypto.Signature.pss import MGF1
maskedSeed = EM[1:hLen+1]
maskedDB = EM[hLen+1:]
seed = bytes(a ^ b for a, b in zip(maskedSeed, MGF1(maskedDB, hLen, HF)))
DB = bytes(a ^ b for a, b in zip(maskedDB, MGF1(seed, k - hLen - 1, HF)))
# DB[:hLen] 应与 lHash 相等；其后是 0x00...0x01 || message
```

**关键点：** Python 的 `or` 会从左到右短路，一旦前一个条件成立，后面的高代价操作就不执行了。这本质上就是计时预言机。RFC 8017 明确要求不能让攻击者区分不同错误路径。

---

## Polynomial Hash with Trivial Root (Pragyan 2026)

**模式（!!Cand1esaNdCrypt0!!）：** 某 RSA 签名方案采用多项式哈希 `g(x,a,b) = x(x^2 + ax + b) mod P`。

**漏洞：** 对任何参数 `a, b` 都有 `g(0) = 0`。而 RSA 对 0 的签名永远是 0（`0^d mod n = 0`）。

**利用：** 构造一个消息后缀，使 `bytes_to_long(prefix || suffix) = 0 (mod P)`：
```python
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61  # 128-bit 素数
# 计算所需后缀值（模 P）
req = (-prefix_val * pow(256, suffix_len, P)) % P
# 暴力部分字节，直到所有后缀字符都可打印
while True:
    high = os.urandom(32).translate(printable_table)
    low_val = (req - int.from_bytes(high, 'big') * shift) % P
    low = low_val.to_bytes(16, 'big')
    if all(32 <= b <= 126 for b in low):
        suffix = high + low
        break
# 签名直接取 0
```

**一般经验：** 先检查哈希函数在 0、1、-1 等点上是否有平凡根，这类错误在比赛题中很常见。

---

## Polynomial CRT in GF(2)[x] (Nullcon 2026)

**模式（Going in Circles, Nullcon 2026）：** 给出 `r = flag mod f`，其中 `f` 是随机 GF(2) 多项式。收集约 20 组 `(f, r)`，筛掉不互素的后做 CRT 合并。

GF(2)[x] 上的多项式运算与 CRT 实现见 [advanced-math.md](advanced-math.md)。

---

## Affine Cipher over Non-Prime Modulus (Nullcon 2026)

**模式（Matrixfun, Nullcon 2026）：** `c = A @ p + b (mod m)`，其中 `m` 是复合数。做选择明文差分攻击后，再把问题拆到每个素因子域里分别求解。

CRT 方案与 Gauss-Jordan 实现见 [advanced-math.md](advanced-math.md)。

另见 [rsa-attacks-2.md](rsa-attacks-2.md)，其中收录了更偏专项的 RSA 技巧：`p=q` 绕过、立方根 CRT、`phi(n)` 倍数分解、签名伪造、弱密钥生成、批量 GCD、部分私钥恢复、CRT 故障攻击、同态绕过等。
