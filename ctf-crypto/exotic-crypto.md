# CTF Crypto - 异构代数结构

## Table of Contents
- [Braid Group DH — Alexander Polynomial 的乘法性（DiceCTF 2026）](#braid-group-dh--alexander-polynomial-multiplicativity-dicectf-2026)
- [部分输出下的单调函数求逆](#monotone-function-inversion-with-partial-output)
- [Tropical Semiring Residuation Attack（BearCatCTF 2026）](#tropical-semiring-residuation-attack-bearcatctf-2026)
- [Paillier 密码体制攻击（SECCON 2015）](#paillier-cryptosystem-attack-seccon-2015)
- [带螺旋交织的海明码纠错（Sharif CTF 2016）](#hamming-code-error-correction-with-helical-interleaving-sharif-ctf-2016)
- [ElGamal 通用重加密（Sharif CTF 2016）](#elgamal-universal-re-encryption-sharif-ctf-2016)
- [通过密文分解绕过 Paillier 预言机尺寸限制（BSidesSF 2025）](#paillier-oracle-size-bypass-via-ciphertext-factoring-bsidessf-2025)
- [格式保持加密 Feistel 暴力（BSidesSF 2026）](#format-preserving-encryption-feistel-brute-force-bsidessf-2026)
- [二十面体对称群密码（BSidesSF 2026）](#icosahedral-symmetry-group-cipher-bsidessf-2026)
- [Goldwasser-Micali 密文复制预言机（BSidesSF 2026）](#goldwasser-micali-ciphertext-replication-oracle-bsidessf-2026)

---

## Braid Group DH — Alexander Polynomial Multiplicativity (DiceCTF 2026)

**模式（Plane or Exchange）：** 一个建立在 braid 上的 Diffie-Hellman。公钥通过把私有 braid 与公开信息连接，再做一堆 Reidemeister 风格打乱得到。共享秘密为 `sha256(normalize(calculate(connect(my_priv, their_pub))))`，其中 `calculate()` 计算的是 braid 的 Alexander polynomial。

**协议结构：**
```python
import sympy as sp
import hashlib

t = sp.Symbol('t')

def compose(p1, p2):
    return [p1[p2[i]] for i in range(len(p1))]

def inverse(p):
    inv = [0] * len(p)
    for i, j in enumerate(p):
        inv[j] = i
    return inv

def connect(g1, g2):
    """在连接处做一次交换，把两条 braid 拼起来。"""
    x1, o1 = g1
    x2, o2 = g2
    l = len(x1)
    new_x = list(x1) + [v + l for v in x2]
    new_o = list(o1) + [v + l for v in o2]
    new_x[l-1], new_x[l] = new_x[l], new_x[l-1]
    return (new_x, new_o)

def sweep(ap):
    """从 arc presentation 计算绕数矩阵。"""
    l = len(ap)
    current_row = [0] * l
    matrix = []
    for pair in ap:
        c1, c2 = sorted(pair)
        diff = pair[1] - pair[0]
        s = 1 if diff > 0 else (-1 if diff < 0 else 0)
        for c in range(c1, c2):
            current_row[c] += s
        matrix.append(list(current_row))
    return matrix

def mine(point):
    x, o = point
    return sweep([*zip(x, o)])

def calculate(point):
    """计算 braid 的 Alexander polynomial。"""
    mat = sp.Matrix([[t**(-x) for x in y] for y in mine(point)])
    return mat.det(method='bareiss') * (1 - t)**(1 - len(point[0]))

def normalize(calculation):
    """把 Laurent 多项式归一化。"""
    poly = sp.expand(sp.simplify(calculation))
    all_exp = [term.as_coeff_exponent(t)[1] for term in poly.as_ordered_terms()]
    min_exp = min(all_exp)
    poly = sp.expand(sp.simplify(poly * t**(-min_exp)))
    if poly.coeff(t, 0) < 0:
        poly *= -1
    return poly
```

**致命漏洞：Alexander polynomial 的乘法性**

Alexander polynomial 满足 `Δ(β₁·β₂) = Δ(β₁) × Δ(β₂)`。于是整个 DH 变成了交换群问题：

```python
# Eve 只凭公开值就能算共享秘密
calc_pub = normalize(calculate(pub_info))
calc_alice = normalize(calculate(alice_pub))
calc_bob = normalize(calculate(bob_pub))

# 恢复 Alice 私有部分对应的多项式
calc_alice_priv = sp.cancel(calc_alice / calc_pub)

# 共享秘密 = calc(alice_priv) * calc(bob_pub)
shared_poly = normalize(sp.expand(calc_alice_priv * calc_bob))
shared_hex = hashlib.sha256(str(shared_poly).encode()).hexdigest()

# 再去解 XOR 流密码
key = bytes.fromhex(shared_hex)
while len(key) < len(ciphertext):
    key += hashlib.sha256(key).digest()
plaintext = bytes(a ^ b for a, b in zip(ciphertext, key))
```

**大矩阵计算技巧：**

对有理函数矩阵直接做 Bareiss 会极慢。先把分母清掉：

```python
k = max(abs(w) for row in winding_matrix for w in row)
n = len(winding_matrix)

# 原来 M[i][j] = t^(-w[i][j])
# 改成 M'[i][j] = t^(k - w[i][j])，所有指数都非负
mat_poly = sp.Matrix([[t**(k - w) for w in row] for row in winding_matrix])
det_scaled = mat_poly.det(method='bareiss')

# 再除回去
det_true = sp.cancel(det_scaled / t**(k * n))
result = sp.cancel(det_true * (1 - t)**(1 - n))
```

**验证方式：回文性**
合法的 Alexander polynomial 系数应当前后对称：
```python
def is_palindromic(poly, var=t):
    coeffs = sp.Poly(poly, var).all_coeffs()
    return coeffs == coeffs[::-1]
```

**识别时机：** 题目提到 braid、knot、permutation pair、winding number、Reidemeister move、topological key exchange 等。关键在于：Alexander polynomial 虽然是强不变量，但它是乘法性的，不适合拿来做 DH。

**参考：** DiceCTF 2026 "Plane or Exchange"

---

## Monotone Function Inversion with Partial Output

**模式：** flag 被转成一个实数，送进某个可逆 / 单调函数（如迭代映射、螺旋变换），输出的若干位数字被遮住或抹掉。目标是恢复这些缺失数字，再做逆变换拿回 flag。

**识别特征：**
- 输出是高精度小数，夹杂若干 `?`
- 变换平滑 / 单调，可通过 root-finding 反解
- flag 格式把输入压在一个很小的区间内
- 题目提示如 “brute won't cut it” 或 “binary search”

**关键点：** 对单调函数 `f`，flag 格式（如 `0xL4ugh{...}`）往往把输出约束进极窄范围。很多“未知位”在所有合法输入上其实是固定的，可先直接确定。

**分层恢复数字：**

1. **找固定数字：** 计算 `f(flag_min)` 和 `f(flag_max)`，比较所有位；两边相同的位就是固定值
2. **顺序细化：** 对剩余未知位逐个尝试 0-9，并做逆变换；正确值会解出合法 ASCII flag
3. **验证：** 正确数字会给出正常 flag，错误数字会产出乱码

```python
import mpmath

# 与 SageMath RealField(N) 精度完全对齐
mpmath.mp.prec = 256

phi = (mpmath.mpf(1) + mpmath.sqrt(mpmath.mpf(5))) / 2

def forward(x0):
    x = x0
    for i in range(iterations):
        r = mpmath.mpf(i) / mpmath.mpf(iterations)
        x = r * mpmath.sqrt(x*x + 1) + (1 - r) * (x + phi)
    return x

def invert(y_target, x_guess):
    def f(x0):
        return forward(x0) - y_target
    return mpmath.findroot(f, x_guess, tol=mpmath.mpf(10)**(-200))

masked = "?7086013?3756162?51694057..."
unknown_positions = [0, 8, 16, 25, 33, ...]

for pos in remaining_unknowns:
    for digit in range(10):
        output_val = construct_number(known_digits | {pos: digit})
        x_inv = invert(output_val, x_guess=0.335)
        flag_int = int(x_inv * mpmath.power(10, flag_digits))
        flag_bytes = flag_int.to_bytes(30, 'big')
        if is_valid_flag(flag_bytes):
            known_digits[pos] = digit
            break
```

**为什么有效：** 每一位未知数字影响输出的小数位尺度不同。先恢复高位数字，会大幅缩小逆变换后的可能范围，从而让后续位越来越容易确定。整体复杂度通常是 `10 * 未知位数`，而不是指数爆炸。

**精度对齐：** Sage 的 `RealField(N)` 用的是 N-bit MPFR mantissa。在 mpmath 里要设 `mp.prec = N`，不是 `mp.dps`。最后几位通常非常精度敏感。

**参考：** 0xL4ugh CTF "SpiralFloats"

---

## Tropical Semiring Residuation Attack (BearCatCTF 2026)

**模式（Tropped）：** 在 tropical matrix（min-plus 代数）上做 Diffie-Hellman，共享秘密逐字符 XOR 到密文上。

**Tropical 代数：**
- 加法 = `min(a, b)`
- 乘法 = `a + b`
- 矩阵乘法：`(A*B)[i,j] = min_k(A[i,k] + B[k,j])`

**通过 residuation 从公开矩阵恢复共享秘密：**
```python
def tropical_residuate(M, Mb, aM, n):
    """从公开矩阵中恢复共享秘密。"""
    # 右 residual: b*[j] = max_i(Mb[i] - M[i][j])
    b_star = [max(Mb[i] - M[i][j] for i in range(n)) for j in range(n)]
    # 共享秘密: aMb = min_j(aM[j] + b*[j])
    aMb = min(aM[j] + b_star[j] for j in range(n))
    return aMb

for i, enc_char in enumerate(encrypted):
    key = shared_secret % 32
    plaintext_char = chr(key ^ ord(enc_char))
```

**关键点：** tropical DH 之所以不安全，是因为 min-plus 半环没有标准 DH 需要的“难逆”结构。给出 `M` 与 `M*b` 后，可以直接通过 residuation 算出足够多的 `b` 信息，进一步恢复共享秘密。

---

## Paillier Cryptosystem Attack (SECCON 2015)

Paillier 的加密形式是 `c = g^m * r^n mod n^2`，具备加法同态。若题目给出一堆 oracle 方程 `(c, o, h)`：

1. **先估计 `n`：** 用 `sqrt(max(c, o, h))` 做下界，再在附近暴力
2. **验证 `n`：** 检查诸如 `h = (c * o) % (n^2)` 的关系
3. **分解 `n`：** 用常规方式得到 `p, q`
4. **解密：**

```python
from sympy import lcm, mod_inverse

lam = lcm(p - 1, q - 1)
n2 = n * n

def L(x):
    return (x - 1) // n

g_lam = pow(g, lam, n2)
mu = mod_inverse(L(g_lam), n)

c_lam = pow(c, lam, n2)
m = (L(c_lam) * mu) % n
```

**关键点：** Paillier 在 `n^2` 模下工作，因此密文比普通 RSA 大得多。加法同态 `E(m1) * E(m2) = E(m1 + m2)` 常常会把明文关系直接暴露出来。

---

## Hamming Code Error Correction with Helical Interleaving (Sharif CTF 2016)

当数据使用 Hamming(31,26) 并结合螺旋扫描交织时：

1. **先爆宽高：** 在 30×30 范围内暴力矩阵尺寸，看哪些尺寸能导出合法海明码流
2. **按螺旋 / 对角模式读比特**
3. **跑海明综合校验**，定位并纠正错误

```python
import numpy as np

def check_hamming(codeword, H):
    """syndrome = H * c^T；若为 0，则码字合法"""
    syndrome = np.dot(H, codeword) % 2
    return np.all(syndrome == 0)

for w in range(1, 31):
    for h in range(1, 31):
        matrix = data[:w*h].reshape(h, w)
        bits = read_helical(matrix)
        if validate_hamming_stream(bits, H):
            print(f"Dimensions: {w}x{h}")
```

**关键点：** 起始 bit 对齐不明时，通常还要额外尝试 8 种偏移。合法海明码字在校验矩阵下的 syndrome 必须为 0。

---

## ElGamal Universal Re-encryption (Sharif CTF 2016)

给定 ElGamal 风格密文 `(a, b, c, d) = (g^r, h^r, g^s, m*h^s)`，无需私钥也能把它重随机化成另一条解密同样消息的合法密文。把指数从 `r -> 2r`，`s -> r+s`：

```python
def reencrypt(a, b, c, d, p):
    return [
        (a * a) % p,    # g^(2r)
        (b * b) % p,    # h^(2r)
        (a * c) % p,    # g^(r+s)
        (d * b) % p     # m*h^(r+s)
    ]
```

**关键点：** ElGamal 的同态使你可以对密文重新随机化，只要保持指数关系一致即可。

---

## Paillier Oracle Size Bypass via Ciphertext Factoring (BSidesSF 2025)

当 Paillier 解密预言机拒绝超过某大小限制的明文时，可利用同态把目标密文拆成更小的区间并逐步二分。

1. **Paillier 加法同态：** `E(m1) * E(m2) mod n^2 = E(m1 + m2 mod n)`
2. **标量乘法：** `E(m)^k mod n^2 = E(k*m mod n)`
3. **构造 `E(flag - offset)`：** 通过结果是否“太大 / wraparound”来判断 flag 落在 offset 的哪一侧
4. **二分搜索：** 用 `O(log n)` 查询恢复 flag

```python
from Crypto.Util.number import inverse

def paillier_sub(c, plaintext_sub, n):
    """由 E(m) 计算 E(m - plaintext_sub)。"""
    n2 = n * n
    neg_enc = pow(n + 1, n - plaintext_sub, n2)
    return (c * neg_enc) % n2

def recover_flag(enc_flag, n, oracle_decrypt):
    low, high = 0, n
    while high - low > 1:
        mid = (low + high) // 2
        test_ct = paillier_sub(enc_flag, mid, n)
        result = oracle_decrypt(test_ct)
        if result < n // 2:
            low = mid
        else:
            high = mid
    return low
```

**关键点：** 只要 oracle 能泄露“解密结果偏大还是偏小”，Paillier 的加法同态就足以支持二分。

---

## Format-Preserving Encryption Feistel Brute-Force (BSidesSF 2026)

**模式（tokencrypt）：** 一个 FPE（格式保持加密）Feistel 网络，96-bit key 被拆成三个功能完全不同的部分：其中真正控制轮函数的只有 16 bit，剩余部分只是 GF(2) 仿射混合与偏移。

**key 结构：**
- `s`（16 bit）：Feistel 轮子密钥，可直接暴力
- `seed56`（56 bit）：生成可逆 GF(2) 仿射矩阵 `M`（24×24）
- `b24`（24 bit）：仿射偏移

**攻击：**
1. 收集多组 `(plaintext, ciphertext)`
2. 暴力 `s` 的 65536 种候选，跑 Feistel core
3. 若 `s` 正确，剩余变换 `ciphertext = M * feistel_output XOR b24` 在线性代数上是可解的
4. 收集 24+ 组样本，在 GF(2) 上求出 `M` 和 `b24`

```python
import numpy as np

def feistel_encrypt(pt_24bit, s, rounds=3):
    """24-bit Feistel，轮密钥为 16-bit 的 s。"""
    L, R = pt_24bit >> 12, pt_24bit & 0xFFF
    for r in range(rounds):
        f = (R * s + r) & 0xFFF
        L, R = R, L ^ f
    return (L << 12) | R

for s_candidate in range(1 << 16):
    feistel_outputs = [feistel_encrypt(pt, s_candidate) for pt in known_pts]
    # 检查 feistel_outputs -> known_cts 是否是 GF(2) 上的仿射关系
```

**关键点：** 不要被“总 key 长度 96 bit”迷惑。真正保护 Feistel core 的只有 16 bit。

**参考：** BSidesSF 2026 "tokencrypt"

---

## Icosahedral Symmetry Group Cipher (BSidesSF 2026)

**模式（dodecacrypt）：** 把消息字节映射为十二面体面置换。二十面体旋转群的阶是 120，因此每个 base-120 “数字”都对应 12 个面标签的一种排列。

**工作方式：**
1. 把消息转成一个大整数，再写成 base 120
2. 每个 base-120 数字选择 120 个置换之一
3. 从固定视角渲染十二面体，只能看到 12 个面中的 6 个
4. 尽管可见信息不完整，但 120 种置换之间的冲突仍极少，足够做查表恢复

**攻击：**
1. **建查表：** 枚举 0-119 的单个数字输入，请求渲染结果，记录可见 6 个面的排列
2. **匹配密文：** 对每个密文符号，比对可见面模式，恢复对应的 base-120 数字
3. **重建消息：** 把 base-120 数字序列转回整数，再转 bytes

```python
import itertools

lookup = {}
for digit in range(120):
    visible = get_visible_faces(encrypt_single(digit))
    lookup[tuple(visible)] = digit

base120_digits = []
for symbol in ciphertext_symbols:
    visible = get_visible_faces(symbol)
    base120_digits.append(lookup[tuple(visible)])

value = sum(d * 120**i for i, d in enumerate(reversed(base120_digits)))
plaintext = value.to_bytes((value.bit_length() + 7) // 8, 'big')
```

**关键点：** icosahedral rotation group 的阶只有 120，小到可以整表枚举。即便只看到一半面，查表在实战中也足够稳定。

**参考：** BSidesSF 2026 "dodecacrypt"

---

## Goldwasser-Micali Ciphertext Replication Oracle (BSidesSF 2026)

**模式（kproof）：** 某“knowledge proof”协议把用户选择的 AES key 用 Goldwasser-Micali（GM）逐 bit 加密。服务端会解出这些 GM bit，重组 AES key，再用它解密并哈希一个 probe payload。漏洞在于：单个 GM 密文值可以被重复提交。如果把同一个 GM bit 复制 128 次，就会得到全 0 或全 1 的 128-bit AES key。

**GM 基础：**
- 每个密文值只编码 1 个 bit
- bit 0 -> 二次剩余
- bit 1 -> 非剩余
- 解密只是在检验该值是否为二次剩余

**漏洞本质：**
服务端接受 128 行 GM 密文作为 AES key。如果把同一行重复 128 次，得到的 AES key 只可能是：
- `00...00`（若该 bit 为 0）
- `FF...FF`（若该 bit 为 1）

攻击者自己控制 probe 明文和 IV，因此可以预先算出两种 key 下的哈希，再和服务端返回值比较。

**攻击（128 次查询恢复整把 key）：**

```python
from Crypto.Cipher import AES
import hashlib

def recover_bit(gm_ciphertext_line, probe_ct, probe_iv, oracle):
    """判断一个 GM 密文行编码的是 0 还是 1。"""
    key_all_zero = b'\x00' * 16
    key_all_ones = b'\xff' * 16

    hash0 = hashlib.sha256(
        AES.new(key_all_zero, AES.MODE_CBC, probe_iv).decrypt(probe_ct)
    ).hexdigest()
    hash1 = hashlib.sha256(
        AES.new(key_all_ones, AES.MODE_CBC, probe_iv).decrypt(probe_ct)
    ).hexdigest()

    result_hash = oracle.query(gm_ciphertext_line, copies=128)

    if result_hash == hash0:
        return 0
    elif result_hash == hash1:
        return 1

captured_gm_lines = parse_transcript(transcript)
key_bits = [recover_bit(line, probe_ct, probe_iv, oracle)
            for line in captured_gm_lines]

aes_key = bits_to_bytes(key_bits)
plaintext = AES.new(aes_key, AES.MODE_CBC, captured_iv).decrypt(captured_ct)
```

**关键点：** 逐 bit 公钥加密 + 可重复提交 + 对重组后对称 key 的可区分预言机，这三点一旦同时出现，就会把 128-bit key 降成 128 次线性查询。

**更一般的规律：** 任何把 key 按 bit 加密、再对重组后的完整 key 提供某种 oracle 的协议，都很可能能被“逐 bit 复制 + 区分”击穿。

**参考：** BSidesSF 2026 "kproof"


更多 2017+ 的异构密码学攻击见 [exotic-crypto-2.md](exotic-crypto-2.md)。
