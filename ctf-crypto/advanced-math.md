# CTF Crypto - 高等数学攻击

## Table of Contents
- [椭圆曲线同源](#elliptic-curve-isogenies)
- [Pohlig-Hellman 攻击（弱 ECC）](#pohlig-hellman-attack-weak-ecc)
- [通用 DLP 的 Baby-Step Giant-Step](#baby-step-giant-step-for-general-dlp)
- [近似 GCD 的 LLL 算法](#lll-algorithm-for-approximate-gcd)
- [利用 LLL 破解 Merkle-Hellman 背包（ASIS 2014）](#merkle-hellman-knapsack-cryptosystem-via-lll-asis-2014)
- [Coppersmith 方法（私钥接近）](#coppersmiths-method-close-private-keys)
- [Coppersmith 方法（结构化素数，LACTF 2026）](#coppersmiths-method-structured-primes-lactf-2026)
- [Clock Group（x^2+y^2=1 mod p）DLP（LACTF 2026）](#clock-group-x2y21-mod-p-dlp-lactf-2026)
- [四元数 RSA](#quaternion-rsa)
- [GF(2)[x] 上的多项式运算](#polynomial-arithmetic-in-gf2x)
- [RSA 签名实现错误](#rsa-signing-bug)
- [非置换 S 盒碰撞攻击（Nullcon 2026）](#non-permutation-s-box-collision-attack-nullcon-2026)
- [GF(2)[x] 上的多项式 CRT（Nullcon 2026）](#polynomial-crt-in-gf2x-nullcon-2026)
- [Manger RSA 填充预言机攻击（Nullcon 2026）](#mangers-rsa-padding-oracle-attack-nullcon-2026)
- [通过 CVP 的 LWE 格攻击（EHAX 2026）](#lwe-lattice-attack-via-cvp-ehax-2026)
- [非素数模上的仿射密码（Nullcon 2026）](#affine-cipher-over-non-prime-modulus-nullcon-2026)
- [GF(2) 线性代数下的自指 CRC（Google CTF 2017）](#introspective-crc-via-gf2-linear-algebra-google-ctf-2017)
- [针对稀疏 / 低汉明重量指数的 BSGS（SEC-T CTF 2017）](#baby-step-giant-step-for-sparselow-hamming-weight-exponents-sec-t-ctf-2017)
- [Hensel 引理：mod p^k 上的多项式根提升（CONFidence CTF 2019 Teaser）](#hensels-lemma-polynomial-root-lifting-mod-pk-confidence-ctf-2019-teaser)

---

## Elliptic Curve Isogenies

同源密码题通常本质上是**图遍历问题**：

**核心概念：**
- `j`-invariant 唯一确定曲线的同构类
- 通过同源相连的曲线构成一张图（常常近似树状）
- 对 2-同源而言，每个节点通常约有 3 个邻居（2 个子节点 + 1 个父节点）

**模块多项式思路：**
- 两个由同源相连的 `j` 值满足 `Φ₂(j₁, j₂) = 0`
- 在有限域中求 `Φ₂(j, Y)` 的根即可找到邻居
- 这通常比直接计算同源映射要快得多

**在同源图中找路径：**
```python
# 通过随机游走到叶子来估计高度
def estimate_height(j, neighbors_func, trials=100):
    min_depth = float('inf')
    for _ in range(trials):
        depth, curr = 0, j
        while True:
            nbrs = neighbors_func(curr)
            if len(nbrs) <= 1:  # 叶子节点
                break
            curr = random.choice(nbrs)
            depth += 1
        min_depth = min(min_depth, depth)
    return min_depth

# 通过 LCA 找两点间路径
def find_path(start, end):
    # 从两个点同时向上爬并记录高度
    # 找最近公共祖先
    # 再拼成：path_up(start) + reversed(path_up(end))
```

**复乘（CM）曲线：**
- 判别式 `D = f² · D_K`，其中 `D_K` 是基本判别式
- conductor `f` 决定树深
- 注意特殊判别式：-163、-67、-43 等（类数为 1）

---

## Pohlig-Hellman Attack (Weak ECC)

当椭圆曲线阶很 smooth（含许多小素因子）时：

```python
from sage.all import *

# 先分解曲线阶
E = EllipticCurve(GF(p), [a, b])
n = E.order()
factors = factor(n)

# 在每个小子群里分别解 DLP
partial_logs = []
for (prime, exp) in factors:
    cofactor = n // (prime ** exp)
    G_sub = cofactor * G
    P_sub = cofactor * P

    d_sub = discrete_log(P_sub, G_sub, ord=prime**exp)
    partial_logs.append((d_sub, prime**exp))

# 再用 CRT 合并
from sympy.ntheory.modular import crt
moduli = [m for (_, m) in partial_logs]
residues = [r for (r, _) in partial_logs]
private_key, _ = crt(moduli, residues)
```

---

## Baby-Step Giant-Step for General DLP

**模式：** 求解 `g^x = h (mod p)` 里的离散对数 `x`。时间和空间复杂度都是 `O(sqrt(n))`，其中 `n` 是群阶。可用于乘法群、椭圆曲线乃至任意循环群。若群阶 smooth，再与 Pohlig-Hellman 组合。

**BSGS 算法：**

```python
from math import isqrt

def bsgs(g, h, p, order=None):
    """Baby-step giant-step: 求 x，使得 g^x = h (mod p)。

    时间/空间: O(sqrt(order))。对子群请传入子群阶。
    """
    if order is None:
        order = p - 1
    m = isqrt(order) + 1

    # Baby step: 建表 g^j
    table = {}
    power = 1
    for j in range(m):
        table[power] = j
        power = (power * g) % p

    # Giant step: 计算 g^(-m)，再枚举 h * (g^(-m))^i
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * factor) % p
    return None

# 例子：平滑 p-1 的 ElGamal（MMA CTF 2015 "Alicegame"）
```

**完整的 Pohlig-Hellman + BSGS 流水线：**

```python
from sympy.ntheory import factorint
from sympy.ntheory.modular import crt

def pohlig_hellman(g, h, p):
    """当 p-1 很 smooth 时，求解 g^x = h (mod p)。"""
    order = p - 1
    factors = factorint(order)

    residues = []
    moduli = []
    for prime, exp in factors.items():
        pe = prime ** exp
        cofactor = order // pe
        gi = pow(g, cofactor, p)
        hi = pow(h, cofactor, p)

        xi = bsgs(gi, hi, p, order=pe)
        if xi is None:
            return None
        residues.append(xi)
        moduli.append(pe)

    x, _ = crt(moduli, residues)
    assert pow(g, x, p) == h % p
    return x
```

**关键点：** BSGS 对阶为 `q` 的子群复杂度为 `O(sqrt(q))`。Pohlig-Hellman 则把大问题拆成多个小子群问题。只要所有因子都不大，1024-bit 的 DLP 也能在几秒内解决。

**识别时机：**
- ElGamal、DSA、DH：先看 `factor(p-1)`
- ECC：同理先分解曲线阶
- 每次连接都重生成参数：可以反复连接，直到拿到平滑参数
- 题面提到 “weak parameters” 或使用可疑的小素数

**Sage 一行：** `discrete_log(Mod(h, p), Mod(g, p))`

**参考：** MMA CTF 2015 "Alicegame", SEC-T CTF "Madlog", Crypto CTF 2021 "RoHaLd"

---

## LLL Algorithm for Approximate GCD

**模式（Grinch's Cryptological Defense）：** 服务端给出若干提示 `h_i = f * p_i + n_i`，其中 `f` 是 flag，`p_i` 是小素数，`n_i` 是小噪声。

**格构造：**
```python
from sage.all import *

# 从服务端拿 3 个 hint
# h_i = f * p_i + n_i（噪声很小）
# 构造格，短向量里会露出这些素数

M = matrix(ZZ, [
    [1, 0, 0, h1],
    [0, 1, 0, h2],
    [0, 0, 1, h3],
    [0, 0, 0, -1]  # 缩放项
])

reduced = M.LLL()
# 短向量里含有 p1, p2, p3
# 再由 f = (h1 - n1) / p1 恢复 flag
```

---

## Merkle-Hellman Knapsack Cryptosystem via LLL (ASIS 2014)

Merkle-Hellman 背包是一种已经失效的公钥方案。给定公钥 `P = [p0, ..., pn-1]` 与密文和 `C`，目标是恢复二进制明文向量：

```python
# Sage
nbit = len(pubKey)
A = Matrix(ZZ, nbit + 1, nbit + 1)

# 左上放单位阵，跟踪选择了哪些元素
for i in range(nbit):
    A[i, i] = 1
    A[i, nbit] = pubKey[i]

# 右下角放目标和
A[nbit, nbit] = -int(encoded)

# LLL 约减后，会出现最后一列为 0 的目标向量
res = A.LLL()

for row in res:
    if row[-1] == 0 and all(b in (0, 1) for b in row[:-1]):
        plaintext_bits = list(row[:-1])
        break
```

**关键点：** 背包问题在合适的格嵌入下会变成短向量问题；LLL 约减后的某一行通常就是目标二进制选择向量。

---

## Coppersmith's Method (Close Private Keys)

**模式（Duality of Key）：** 两组 RSA key pair 的私钥 `d1 ≈ d2`，差值很小。

**攻击：**
```python
# 由 e1*d1 ≡ 1 mod φ 和 e2*d2 ≡ 1 mod φ：
# d2 - d1 ≡ (e1*e2)^(-1) * (e1 - e2) mod p

# 构造多项式 f(x) = (r - x) mod p，其中 x = d2-d1
# 用 Coppersmith small_roots() 找 x

R.<x> = PolynomialRing(Zmod(N))
r = inverse_mod(e1*e2, N) * (e1 - e2) % N
f = r - x
roots = f.small_roots(X=2^128, beta=0.5)
# x = d2 - d1，再由 gcd(f(x), N) 恢复 p
```

---

## Coppersmith's Method (Structured Primes, LACTF 2026)

**模式（six-seven-again）：** `p = base + 10^k · x`，其中 `base` 完全已知，而 `x` 很小。

**条件：** 对 e 次多项式，需要 `x < N^{1/e}`；线性多项式下大致是 `N^0.25`。

**攻击：**
```python
# p = base + 10^k * x，因此有 x ≡ -base * (10^k)^(-1) (mod p)
# 又因为 p | N，所以可在 mod N 上构造拥有根 x 的多项式
R.<x> = PolynomialRing(Zmod(N))
inv_10k = inverse_mod(10^k, N)
f = x + (base * inv_10k) % N  # 必须是 monic
roots = f.small_roots(X=2^70, beta=0.5)
if roots:
    x_val = int(roots[0])
    p = base + 10^k * x_val
    q = N // p
```

**要点：**
- 多项式必须是 monic
- `beta=0.5` 表示寻找一个不小于 `N^0.5` 的因子
- `X` 是根大小的上界
- 这适用于任何“部分已知素数”模式

---

## Clock Group (x^2+y^2=1 mod p) DLP (LACTF 2026)

**模式（the-clock）：** 在单位圆群上做 Diffie-Hellman。

**群结构：**

```python
# 群运算：(x1,y1) * (x2,y2) = (x1*y2 + y1*x2, y1*y2 - x1*x2)
# 单位元：(0, 1)
# 逆元：(x, y)^(-1) = (-x, y)
# 群阶：p + 1（不是 p - 1）

def clock_mul(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def clock_pow(P, n, p):
    result = (0, 1)
    base = P
    while n > 0:
        if n & 1:
            result = clock_mul(result, base, p)
        base = clock_mul(base, base, p)
        n >>= 1
    return result
```

**恢复隐藏素数 `p`：**
```python
# 给定曲线上的点，p 一定整除 (x^2 + y^2 - 1)
from math import gcd
vals = [x**2 + y**2 - 1 for x, y in known_points]
p = reduce(gcd, vals)
```

**若 `p+1` 很 smooth，就用 Pohlig-Hellman：**
```python
order = p + 1
factors = factor(order)
# 在 clock group 中按标准 Pohlig-Hellman 处理
```

**关键提醒：** 这个群同构于 `GF(p²)^*` 中范数为 1 的元素群，阶是 `p+1`。不要误当作乘法群 `p-1` 或普通 ECC。

---

## Quaternion RSA

**模式：** 在 Hamilton 四元数代数 `Z/nZ` 上做“RSA 加密”。明文嵌入到四元数的四个分量中，这些分量又是 `m, p, q` 的线性组合，随后把对应的 4×4 矩阵提升到幂 `e mod n`。

**关键结构：**
```python
# 四元数 q = a0 + a1*i + a2*j + a3*k
# 各分量都线性依赖于 m, p, q：
a0 = m
a1 = m + α1*p + β1*q
a2 = m + α2*p + β2*q
a3 = m + α3*p + β3*q

# 4x4 矩阵表示：
# Row 0: [a0, -a1, -a2, -a3]
# Row 1: [a1,  a0, -a3,  a2]
# Row 2: [a2,  a3,  a0, -a1]
# Row 3: [a3, -a2,  a1,  a0]
```

**关键性质：** 对四元数 `q = s + v`（标量 + 向量）有 `q^k = s_k + t_k*v`。也就是说，向量部分在幂运算下只会整体按比例缩放，方向不变。因此虚部分量的比例保持：

`c1 : c2 : c3 = a1 : a2 : a3 (mod n)`

**分解 `n` 的方法：**
```python
import math

# 从密文首行 [ct0, ct1, ct2, ct3] 中取分量
# Row 0 = [c0, -c1, -c2, -c3]
c0, c1, c2, c3 = ct[0], (-ct[1]) % n, (-ct[2]) % n, (-ct[3]) % n

# 利用比例保持：c1*a2 = c2*a1 (mod n), c1*a3 = c3*a1 (mod n)
# 消去 m 后得到：A*p + B*q ≡ 0 (mod n = pq)，因此 q|A, p|B

A = (-(11*c1-3*c2)*(c1-c3) + (17*c1-3*c3)*(c1-c2)) % n
B = (-(13*c1-7*c2)*(c1-c3) + (19*c1-7*c3)*(c1-c2)) % n

q_factor = math.gcd(A, n)
p_factor = math.gcd(B, n)
```

**分解后解密：**

在 `F_p` 上，四元数代数 `H_p ≅ M_2(F_p)`，其乘法群阶整除 `p²-1`。因此可分别在 mod `p` 与 mod `q` 上解密，再 CRT 合并：

```python
d_p = pow(e, -1, p**2 - 1)
d_q = pow(e, -1, q**2 - 1)

enc_mod_p = [[x % p for x in row] for row in enc_matrix]
enc_mod_q = [[x % q for x in row] for row in enc_matrix]
dec_p = matrix_pow(enc_mod_p, d_p, p)
dec_q = matrix_pow(enc_mod_q, d_q, q)

m = CRT(dec_p[0][0], dec_q[0][0], p, q)
flag = long_to_bytes(m)
```

**为什么成立：** 四维四元数幂运算实际上退化成“标量 + 向量模长”的二维递推，向量方向保持不变。这直接把 `a1:a2:a3` 泄露到密文里，进而可分解 `n`。

**参考：** SECCON CTF 2023 "RSA 4.0", 0xL4ugh CTF "Reduced Dimension"

---

## Polynomial Arithmetic in GF(2)[x]

**CTF 里最常用的 GF(2)[x] 运算：**
```python
def poly_add(a, b):
    """GF(2)[x] 中的加法就是系数整数的 XOR。"""
    return a ^ b

def poly_mul(a, b):
    """GF(2)[x] 中的无进位乘法。"""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return result

def poly_divmod(a, b):
    """GF(2)[x] 中带余除法。"""
    if b == 0:
        raise ZeroDivisionError
    deg_a, deg_b = a.bit_length() - 1, b.bit_length() - 1
    q = 0
    while deg_a >= deg_b and a:
        shift = deg_a - deg_b
        q ^= (1 << shift)
        a ^= (b << shift)
        deg_a = a.bit_length() - 1
    return q, a
```

**用途：** GF(2)[x] 上的 CRT、基于多项式余数恢复 secret、类 Reed-Solomon 纠错等。

---

## RSA Signing Bug

**漏洞：** 签名时误用了公钥指数
- 正确：`sign = m^d mod n`
- 错误：`sign = m^e mod n`

**利用：**
```python
from sympy import integer_nthroot

# 若签名其实是 m^e mod n，则对小 e（如 3）可以直接开 e 次方根伪造
forged_sig, exact = integer_nthroot(message, e)
if exact:
    print(f"Forged signature: {forged_sig}")
```

---

## Non-Permutation S-box Collision Attack (Nullcon 2026)

**检测方式：** 先检查 S 盒是不是置换：
```python
sbox = [...]
if len(set(sbox)) < 256:
    from collections import Counter
    counts = Counter(sbox)
    for val, cnt in counts.items():
        if cnt > 1:
            colliders = [i for i in range(256) if sbox[i] == val]
            delta = colliders[0] ^ colliders[1]
            print(f"S[{hex(colliders[0])}] = S[{hex(colliders[1])}] = {hex(val)}, delta = {hex(delta)}")
```

**攻击：**
1. 对每个 key byte 位置 k（0-15）枚举所有 256 个输入值 `v`
2. 加密两条只在该位置相差 `delta` 的明文
3. 若 `ct1 == ct2`，说明 S 盒输入落在碰撞对 `{c0, c1}` 中
4. 推出 `key[k] = v ^ round_const` 或 `key[k] = v ^ round_const ^ delta`
5. 每字节只剩 2 路歧义，最终 `2^16` 本地暴力

**总查询数：** `16 x 256 + 1 = 4097`

**经验：**
- 符号执行 / SAT / SMT 往往会在 15+ 轮时超时
- non-permutation S-box 会破坏 integral / square attack 所需的平衡性
- 所以第一步一定是检查 S 盒是否为置换

---

## Polynomial CRT in GF(2)[x] (Nullcon 2026)

**模式：** 服务端返回 `r = flag mod f`，其中 `f` 是 GF(2) 上的随机多项式。

**攻击：** 对多项式环 GF(2)[x] 做 CRT：
1. 从服务端收集约 20 组 `(r_i, f_i)`
2. 用多项式 GCD 筛掉不互素的 `f_i`
3. 通过 CRT 合并约束 `flag ≡ r_i (mod f_i)`
4. 当模积总位数超过 flag 长度后，解就是唯一的

```python
def poly_crt(remainders, moduli):
    """GF(2)[x] 上的 CRT：合并 (r_i, f_i)。"""
    result, mod = remainders[0], moduli[0]
    for i in range(1, len(remainders)):
        g, s, t = poly_xgcd(mod, moduli[i])
        combined_mod = poly_mul(mod, moduli[i])
        result = poly_add(poly_mul(poly_mul(remainders[i], s), mod),
                         poly_mul(poly_mul(result, t), moduli[i]))
        result = poly_mod(result, combined_mod)
        mod = combined_mod
    return result, mod
```

---

## Manger's RSA Padding Oracle Attack (Nullcon 2026)

**设定：**
- 待恢复 key `k < 2^64`
- RSA 模数 `n` 很大（1337+ bit）
- 预言机：若 `decrypt < threshold` 返回一种错误，反之返回另一种
- 因为 `k` 很小，不会发生模回绕

**攻击（简化版 Manger）：**
```python
# 第 1 阶段：找 f1，使 k * f1 >= threshold
f1 = 1
while oracle(encrypt(f1)) == "below":
    f1 *= 2

# 第 2 阶段：二分搜索精确 key
lo, hi = 0, threshold
while lo < hi:
    mid = (lo + hi) // 2
    f_test = ceil(threshold, mid + 1)
    if oracle(encrypt(f_test)) == "above":
        hi = mid
    else:
        lo = mid + 1
key = lo
```

**总查询数：** 大约 128 次（64 次找区间 + 64 次二分）

---

## LWE Lattice Attack via CVP (EHAX 2026)

**模式（Dream Labyrinth）：** 多层挑战的最后一层是 LWE。给出 `b = A*s + e (mod q)`，其中 secret `s ∈ {-1,0,1}^n`，误差 `e` 很小。

**用 fpylll 做 CVP / Babai：**
```python
from fpylll import IntegerMatrix, LLL, CVP
import numpy as np

q = 3329
n = 256
m = 512

def solve_lwe_cvp(A, b, q, n, m):
    dim = m + n
    B = IntegerMatrix(dim, dim)

    # 上半部分：q*I_m
    for i in range(m):
        B[i, i] = q

    # 下半部分：[A^T | I_n]
    for j in range(n):
        for i in range(m):
            B[m + j, i] = int(A[i][j])
        B[m + j, m + j] = 1

    LLL.reduction(B)

    target = [int(b[i]) for i in range(m)] + [0] * n
    closest = CVP.babai(B, target)

    s_candidate = [closest[m + j] for j in range(n)]

    # 投影回 {-1, 0, 1}
    s = []
    for val in s_candidate:
        val_mod = val % q
        if val_mod == 0:
            s.append(0)
        elif val_mod == 1:
            s.append(1)
        elif val_mod == q - 1:
            s.append(-1)
        else:
            s.append(min([-1, 0, 1], key=lambda t: abs((val_mod - t) % q)))
    return s

s = solve_lwe_cvp(A, b, q, n, m)
```

**极其重要：字节序坑。** 服务端可能自称 big-endian，实际却用 little-endian。若 CVP 输出全是垃圾，优先交换 secret 的字节序解释：
```python
s_bytes_le = bytes([(v % 256) for v in s])
s_bytes_be = s_bytes_le[::-1]
```

**LWE 解出来后的常见密钥派生链：**
```python
import hashlib
from Cryptodome.Cipher import AES

s_bytes = bytes([(v % 256) for v in s])

session_nonce = bytes(a ^ b for a, b in
    zip(wrapped_nonce, hashlib.sha256(s_bytes).digest()[:16]))

aes_key = hashlib.sha256(s_bytes + session_nonce).digest()

cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
```

**多层密码题的常见结构：**
- **Layer 1（几何）：** 从带噪距离恢复点位置，常用最小二乘 / 三边定位
- **Layer 2（子空间）：** 在高维数据里识别隐藏低维子空间
- **Layer 3（LWE）：** 用格恢复 secret，再派生 AES key

**参考：** EHAX CTF 2026 "Dream Labyrinth"

---

## Affine Cipher over Non-Prime Modulus (Nullcon 2026)

**模式：** `c = A @ p + b (mod m)`，其中 `A` 是 n×n 矩阵，而 `m` 可能是复合数（如 65）。

**选择明文攻击：**
1. 发送 `n+1` 组精心构造的输入
2. 做差得到 `c_i - c_0 = A @ (p_i - p_0) (mod m)`
3. 构造明文差分矩阵 D 与密文差分矩阵 E
4. 用高斯-约旦求 `A = E @ D^{-1} (mod m)`
5. 再由 `b = c_0 - A @ p_0 (mod m)` 恢复偏移项

**对复合模数的 CRT 方案（推荐）：**
```python
def crt2(r1, m1, r2, m2):
    """CRT: x = r1 (mod m1), x = r2 (mod m2)"""
    m1_inv = pow(m1, m2 - 2, m2)
    t = ((r2 - r1) * m1_inv) % m2
    return (r1 + m1 * t) % (m1 * m2)

def gauss_elim(A, b, mod):
    """在 Z/modZ 上做高斯消元。"""
    n = len(b)
    M = [list(A[i]) + [b[i]] for i in range(n)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if M[r][col] % mod), None)
        if pivot is None: continue
        M[col], M[pivot] = M[pivot], M[col]
        inv = pow(M[col][col], -1, mod)
        M[col] = [x * inv % mod for x in M[col]]
        for r in range(n):
            if r != col and M[r][col] % mod:
                f = M[r][col]
                M[r] = [(M[r][j] - f * M[col][j]) % mod for j in range(n + 1)]
    return [M[i][n] % mod for i in range(n)]

# 对 m=65=5*13 分别在 GF(5)、GF(13) 上求解，再 CRT 合并
A5, b5 = A % 5, rhs % 5
A13, b13 = A % 13, rhs % 13
x5 = gauss_elim(A5, b5, mod=5)
x13 = gauss_elim(A13, b13, mod=13)
x = [crt2(x5[i], 5, x13[i], 13) for i in range(len(x5))]
```

---

## Introspective CRC via GF(2) Linear Algebra (Google CTF 2017)

**模式：** 寻找一个 ASCII 字符串，使其 CRC-N 值恰好等于该字符串本身（自指 CRC）。把 CRC 看成 GF(2) 上的线性映射即可。

```python
# CRC 在 GF(2) 上是线性的：CRC(a XOR b) = CRC(a) XOR CRC(b)
# 目标：找 x，使得 CRC(x) = x
# 1. 先算全零输入的 CRC 基线
# 2. 对每个 bit 翻转，记录 CRC 差分
# 3. 建立线性系统：CRC(x) XOR x = 0
# 4. 在 GF(2) 上高斯消元
from sage.all import *
F = GF(2)
M = Matrix(F, n_bits, n_bits)
# ... 用 CRC 余数填矩阵 ...
solution = M.solve_right(target_vector)
```

**关键点：** CRC 是线性的，因此“CRC(x)=x”不是魔法题，而是线性代数题。难点仅在于选择自由变量，保证最终字节仍落在可打印 ASCII 范围。

**参考：** Google CTF 2017

---

## Baby-Step Giant-Step for Sparse/Low Hamming Weight Exponents (SEC-T CTF 2017)

**模式：** DLP 中的指数已知汉明重量很低，例如 128 bit 的指数至多只有 11 个 bit 为 1。把指数拆成两半 `e = e1 * 2^64 + e2`，分别只枚举 5 个 / 6 个置位的组合，做 meet-in-the-middle。

**复杂度：** `C(128, 5) ≈ 10^8` 个 baby step，`C(128, 6) ≈ 10^9` 个 giant step，远低于暴力 `2^128` 或普通 BSGS 的 `2^64`。

```python
from itertools import combinations
from math import comb

half = 64
k_low, k_high = 5, 6

# Baby step: 预计算所有低半部分组合
baby = {}
for bit_positions in combinations(range(half), k_low):
    x1 = sum(1 << b for b in bit_positions)
    val = pow(g, x1 * (2**half), p)
    baby[val] = x1

# Giant step: 查找 a * g^(-x2) 是否在表中
g_inv = pow(g, -1, p)
for bit_positions in combinations(range(half), k_high):
    x2 = sum(1 << b for b in bit_positions)
    candidate = (a * pow(g_inv, x2, p)) % p
    if candidate in baby:
        x1 = baby[candidate]
        x = x1 * (2**half) + x2
        assert pow(g, x, p) == a
        print(f"Found exponent: {x}")
        break
```

**验证：**
```python
assert bin(x).count('1') <= 11
```

**关键点：** 当题目对指数的汉明重量做了强约束时，最优解往往不是普通 DLP，而是“稀疏指数 meet-in-the-middle”。

**参考：** SEC-T CTF 2017

---

## Hensel's Lemma: Polynomial Root Lifting mod p^k (CONFidence CTF 2019 Teaser)

**模式（Bro, do you even lift?）：** 题目给出一个多项式 `P(x)`，其唯一根就是 `N = p^k` 意义下的 flag；`p` 很小但 `k` 很大。直接在 `p^k` 上暴力不可能，但 Hensel 引理允许把 mod `p` 上的简单根逐步提升到 mod `p^k`。

```python
# sage
R.<x> = PolynomialRing(ZZ)
pol   = ...
p     = 35671
k     = 100

# 第 1 步：先枚举 mod p 的根
roots_p = [r for r in range(p) if pol(r) % p == 0]

# 第 2 步：从 p, p^2, ..., p^k 逐层提升
def hensel_lift(pol, root, p, k):
    dpol = pol.derivative()
    r = root
    mod = p
    for i in range(1, k):
        mod_next = mod * p
        inv = inverse_mod(int(dpol(r)) % p, p)
        r = (r - int(pol(r)) * inv) % mod_next
        mod = mod_next
    return r

flag_int = hensel_lift(pol, roots_p[0], p, k)
```

**关键点：** 对 `P(x) ≡ 0 mod p^k`，只要 `P'(root)` 不被 `p` 整除，解就能像牛顿迭代一样层层提升。每一轮都必须把中间量及时模掉，否则整数会爆炸到不可计算。
