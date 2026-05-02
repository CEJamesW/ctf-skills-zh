# CTF Crypto - 椭圆曲线攻击

## Table of Contents
- [小子群攻击](#small-subgroup-attacks)
- [无效曲线攻击](#invalid-curve-attacks)
- [奇异曲线](#singular-curves)
- [Smart 攻击（异常曲线）](#smarts-attack-anomalous-curves)
- [ECC 故障注入](#ecc-fault-injection)
- [通过 Pohlig-Hellman 解 clock group DLP（LACTF 2026）](#clock-group-dlp-via-pohlig-hellman-lactf-2026)
- [ECDSA nonce 复用（BearCatCTF 2026）](#ecdsa-nonce-reuse-bearcatctf-2026)
- [Ed25519 扭点侧信道（BearCatCTF 2026）](#ed25519-torsion-side-channel-bearcatctf-2026)
- [DSA nonce 复用恢复私钥（VolgaCTF 2016）](#dsa-nonce-reuse-for-private-key-recovery-volgactf-2016)
- [DSA 有限 k 值暴力（ASIS CTF Finals 2016）](#dsa-limited-k-value-brute-force-asis-ctf-finals-2016)
- [通过 GCD 找 ECC 共享素因子（ASIS CTF Finals 2016）](#ecc-shared-prime-factor-via-gcd-asis-ctf-finals-2016)
- [利用 k 生成过程中的 MD5 碰撞恢复 DSA 密钥（CONFidence CTF 2017）](#dsa-key-recovery-via-md5-collision-on-k-generation-confidence-ctf-2017)
- [Ed25519 同 nonce 私钥恢复（hxp 2018）](#ed25519-same-nonce-key-recovery-hxp-2018)
- [把奇异曲线 ECDLP 降到加法群 / 乘法群（hxp 2018）](#singular-curve-ecdlp-to-additivemultiplicative-group-hxp-2018)

---

## Small Subgroup Attacks

- 先检查曲线阶是否有小因子
- 用 Pohlig-Hellman 把离散对数分解到多个小子群里，再用 CRT 合并

```python
# SageMath ECC 基础
E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]  # 生成元
order = E.order()
```

**关键点：** 如果曲线阶包含很多小素因子，Pohlig-Hellman 会把整个 ECDLP 拆成许多小问题，极易求解。第一件事永远是分解曲线阶。

---

## Invalid Curve Attacks

若实现没有做点验证，就可以发送位于“其他曲线”上的点，尤其是具有小子群阶的点，从而逐步泄露私钥。

**关键点：** 无效曲线攻击的本质是：服务端以为自己在目标曲线上做标量乘法，实际上却在攻击者构造的弱曲线上计算，结果会把私钥模某个小阶的信息泄露出来。

---

## Singular Curves

如果判别式 `delta = 0`，曲线就是奇异曲线，ECDLP 会退化成域上的加法或乘法离散对数。

**关键点：** 先算 `4a^3 + 27b^2 mod p`。若为 0，则曲线不是正常椭圆曲线，问题会降到 cusp（加法群）或 node（乘法群），都能在多项式时间里解决。

---

## Smart's Attack (Anomalous Curves)

**何时使用：** 曲线阶恰好等于底层域特征 `p`，即异常曲线。此时可用 p-adic lifting 在 `O(1)` 内解决 ECDLP。

**关键点：** 永远先检查 `E.order() == p`。若成立，ECDLP 基本可以视为秒解。Sage 的 `discrete_log` 通常能自动处理；若自动化失败，再自己做 p-adic lift。

**检测：** `E.order() == p`，这是最该先验的条件。

**SageMath 自动版：**
```python
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)
# Sage 的 discrete_log 会自动处理异常曲线
secret = G.discrete_log(Q)
```

**手工 p-adic lift（当自动法失败时）：**
```python
def smart_attack(p, a, b, G, Q):
    E = EllipticCurve(GF(p), [a, b])
    Qp = pAdicField(p, 2)  # 精度为 2 的 p-adic 域
    Ep = EllipticCurve(Qp, [a, b])

    # 把点 lift 到 p-adic 域
    Gp = Ep.lift_x(ZZ(G[0]), all=True)  # 尝试两个 lift
    Qp_point = Ep.lift_x(ZZ(Q[0]), all=True)

    for gp in Gp:
        for qp in Qp_point:
            try:
                # 乘 p，进入 reduction kernel
                pG = p * gp
                pQ = p * qp
                # 取 p-adic 对数
                x_G = ZZ(pG[0] / pG[1]) / p
                x_Q = ZZ(pQ[0] / pQ[1]) / p
                secret = ZZ(x_Q / x_G) % p
                if E(G) * secret == E(Q):
                    return secret
            except (ZeroDivisionError, ValueError):
                continue
    return None
```

**拿到 ECC secret 之后的多层解密：** 很多题会再套一层 AES-CBC 或 DES-CBC，这些都只是体力活。通常从共享秘密再过一层 SHA-256 就能派生密钥。

---

## ECC Fault Injection

**模式（Faulty Curves）：** ECC 计算中发生比特翻转或其他故障，可据此恢复私钥位。

**攻击思路：** 对比正确输出与故障输出，按位判断哪些比特影响了结果：
```python
# 对于每个私钥 bit 位置：
# 如果该位出现故障会改变输出 -> 说明该 bit 参与了运算
# 一个常见判别器是：faulty_output == correct_output -> 该位为 0
```

---

## Clock Group DLP via Pohlig-Hellman (LACTF 2026)

**模式（the-clock）：** 在单位圆群 `x^2 + y^2 = 1 (mod p)` 上做 Diffie-Hellman。

**关键事实：**
- 群运算：`(x1,y1) * (x2,y2) = (x1*y2 + y1*x2, y1*y2 - x1*x2)`
- **群阶是 `p + 1`，不是 `p - 1`**
- 它与 `GF(p^2)^*` 中范数为 1 的元素同构

**群运算实现：**
```python
def clock_mul(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def clock_pow(P, n, p):
    result = (0, 1)  # 单位元
    base = P
    while n > 0:
        if n & 1:
            result = clock_mul(result, base, p)
        base = clock_mul(base, base, p)
        n >>= 1
    return result
```

**如何恢复隐藏的素数 `p`：**
```python
# 已知点都在曲线上，因此 p 整除 (x^2 + y^2 - 1)
from math import gcd
vals = [x**2 + y**2 - 1 for x, y in known_points]
p = reduce(gcd, vals)
# 可能还需要去掉一些小因子
```

**当 `p+1` 足够 smooth 时的攻击：**
```python
# 1. 先由点集恢复 p：对 (x^2 + y^2 - 1) 求 gcd
# 2. 分解 p+1
# 3. 用 Pohlig-Hellman 在各小子群解 DLP，再 CRT 合并
# 4. 算出共享秘密，进一步派生 AES key（例如 MD5）
```

**识别方式：** 题目提到 “clock”“circle”，或给的点满足 `x^2+y^2=1`。一定检查的是 `p+1` 是否 smooth，而不是 `p-1`。

---

## Ed25519 Torsion Side Channel (BearCatCTF 2026)

**模式（Curvy Wurvy）：** 某 Ed25519 签名预言机按 `user_key = MASTER_KEY * uid mod l` 给用户派生私钥，目标是通过查询恢复 `MASTER_KEY`。

**攻击利用了 Ed25519 的 cofactor `h = 8`：**
- 完整曲线阶是 `8*l`，但标量运算通常只在 `l` 上约简
- 当 `MASTER_KEY * 2^t` 对 `l` 发生回绕时，结果会携带可见的 torsion 分量，表现在 y 坐标上

**通过二进制分解提取 key：**
```python
# 对 t = 0..255 查询 sign(uid=3, 2^t)
# S_t = (MASTER_KEY * 2^t mod l) * P3
# 检查：double(S_t) 是否等于 S_{t+1}

bits = []
for t in range(255):
    S_t = query_sign(3, 2**t)
    S_t1 = query_sign(3, 2**(t+1))
    doubled = point_double(S_t)
    # 若 doubled.y != S_{t+1}.y，说明发生了 torsion wrap
    bits.append(0 if doubled.y == S_t1.y else 1)

# 重构：MASTER_KEY ≈ l * (0.bit0 bit1 bit2 ...)_binary
# 再试 8 种 torsion 修正，得到精确值
```

**关键点：** cofactor 会把“对 `l` 的回绕”变成可见的 torsion 位移。通过查询 2 的幂并检查相邻点的 y 坐标一致性，就能逐 bit 泄露 master scalar。

---

## ECDSA Nonce Reuse (BearCatCTF 2026)

**模式（Chatroom）：** secp256k1 上的 ECDSA 签名错误地复用了固定 nonce `k`。只要两条签名的 `r` 相同，就能恢复 nonce 和私钥。

**恢复方法：**
```python
from hashlib import sha256

# 两条签名 (r, s1) 和 (r, s2) 共享相同 r -> 同一个 nonce k
h1 = int(sha256(msg1).hexdigest(), 16)
h2 = int(sha256(msg2).hexdigest(), 16)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 阶

k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n
d = ((s1 * k - h1) * pow(r, -1, n)) % n  # 私钥
```

**关键点：** 只要看到重复的 `r`，就应立刻怀疑 nonce 复用。这和当年 PS3 漏洞是同一类错误。

---

## DSA Nonce Reuse for Private Key Recovery (VolgaCTF 2016)

**模式：** 两条 DSA 签名若共享同一个 nonce `k`（即 `r` 相同），则会泄露私钥。原理与 ECDSA nonce 复用完全一样，只是参数不同。

```python
# 两条签名 (r, s1, H(m1)) 与 (r, s2, H(m2))
k = ((H_m1 - H_m2) * pow(s1 - s2, -1, q)) % q
x = ((s1 * k - H_m1) * pow(r, -1, q)) % q  # 私钥
# 然后即可伪造任意消息签名
```

**关键点：** DSA / ECDSA 的 nonce 复用公式本质相同。看到重复 `r` 就直接套公式。

---

## DSA Limited k-Value Brute Force (ASIS CTF Finals 2016)

某些 DSA 实现把 `k` 限制在很小的空间里（例如只有 1024 种可能）。此时可对多条签名直接暴力 `k` 值并解线性方程组。

```python
from Crypto.Util.number import inverse

def recover_dsa_key(signatures, q, g, p):
    """当 k 只来自很小空间时恢复 DSA 私钥。"""
    (r1, s1, h1), (r2, s2, h2) = signatures[0], signatures[1]

    for k1 in range(1, 1024):
        for k2 in range(1, 1024):
            # DSA: s = k^-1 * (h + x*r) mod q
            # 两条签名可联立解 x
            num = (s2 * k2 * h1 - s1 * k1 * h2) % q
            den = (s1 * k1 * r2 - s2 * k2 * r1) % q
            if den == 0:
                continue
            x = (num * inverse(den, q)) % q
            # 验证：检查 r1 是否确实来自 k1
            if pow(g, k1, p) % q == r1:
                return x
    return None
```

**关键点：** 即使 nonce 不重复，只要来自小空间，暴力它就足够了。

---

## ECC Shared Prime Factor via GCD (ASIS CTF Finals 2016)

多个 ECC 公钥使用了有缺陷的素数生成器，例如额外过滤了 `prime % 3 == 2`，把候选空间压得太小，于是不同 key 之间开始共享素因子。

```python
from math import gcd
from Crypto.Util.number import inverse

# 收集多个 ECC 公钥里用到的模数
moduli = [key.n for key in public_keys]

# 两两做 GCD
for i in range(len(moduli)):
    for j in range(i + 1, len(moduli)):
        g = gcd(moduli[i], moduli[j])
        if 1 < g < moduli[i]:
            p = g
            q = moduli[i] // p
            print(f"Key {i} factored: p={p}, q={q}")
            # 接着就能用分解结果解密
```

**关键点：** 任何对 prime 候选空间的额外模限制，都会显著增加共享因子的概率。拿到一组 key 时先跑 GCD 几乎没有成本。

---

## DSA Key Recovery via MD5 Collision on k-Generation (CONFidence CTF 2017)

**模式：** 若 DSA 的 nonce `k` 来源于 `MD5(prefix + counter)`，就可以用 MD5 prefix collision 强行让两个不同 counter 得到同一个 `k`，再回到标准的 nonce 复用私钥恢复。

```python
# k = int(MD5("K = {n: " + str(counter) + ...))
# 用 fastcoll 在前缀 "K = {n: " 上造碰撞
# 两个不同 counter -> 相同 MD5 -> 相同 k -> nonce 复用

import subprocess
subprocess.run(["fastcoll", "-p", prefix_file, "-o", "col1", "col2"])

# 拿到两条共享 k 的签名（r 相同）
sig1 = sign(msg1, counter1)
sig2 = sign(msg2, counter2)

# 标准 DSA nonce 复用恢复
k = (hash1 - hash2) * modinv(sig1.s - sig2.s, q) % q
private_key = (sig1.s * k - hash1) * modinv(sig1.r, q) % q
```

**关键点：** 如果签名方案把可控内容喂给 MD5 再导出 nonce，那么 `fastcoll` 这样的碰撞工具就能把它打回 nonce 复用问题。

**参考：** CONFidence CTF 2017

---

## Ed25519 Same-Nonce Key Recovery (hxp 2018)

**模式：** 某个 Ed25519 实现虽然使用确定性 nonce，但在切换公钥或故障情况下，把同一个私钥标量 `a` 与不同 `(R, h)` 组合到了一起。若两条签名共享同一 `a`，就有 `a = (S1 - S2) * inverse(h1 - h2) mod L`。

```python
L = 2**252 + 27742317777372353535851937790883648493
a = (S1 - S2) * pow(h1 - h2, -1, L) % L   # 恢复出的私钥标量
```

**关键点：** Ed25519 虽然默认确定性，但一旦实现把 `(r, k)` 与真正的消息 / 公钥哈希错配，就会退化成经典 nonce 复用。

**参考：** hxp CTF 2018，writeup 12561

---

## Singular Curve ECDLP to Additive/Multiplicative Group (hxp 2018)

**模式：** 题目给出的“椭圆曲线”其实是奇异曲线，判别式为 0。先找出多项式 `f(x) = x^3 + ax + b` 的双根，对曲线做平移后，就能把离散对数问题映射到普通加法群或乘法群。

```python
# 找奇异点 r
P.<x> = PolynomialRing(GF(p))
f = x^3 + a*x + b
r = (f.derivative()).roots()[0][0]
# 平移曲线，使奇异点在原点
# 对 nodal 情况，可用 (x, y) -> (x - r) / y 映射到乘法群
```

**关键点：** 判别式 `-16(4a^3 + 27b^2)` 为 0 时，问题就已经不再是标准椭圆曲线密码，而是普通有限域里的简单 DLP。

**参考：** hxp CTF 2018，writeup 12563
