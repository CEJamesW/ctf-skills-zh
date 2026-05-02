# CTF Crypto - ZKP、求解器与高级技巧

## Table of Contents
- [ZKP 攻击](#zkp-attacks)
- [图 3-着色](#graph-3-coloring)
- [Z3 SMT 求解器指南](#z3-smt-solver-guide)
- [混淆电路：恢复 Free XOR 的 Delta（LACTF 2026）](#garbled-circuits-free-xor-delta-recovery-lactf-2026)
- [Bigram/Trigram 替换 -> 约束求解（LACTF 2026）](#bigramtrigram-substitution---constraint-solving-lactf-2026)
- [确定性系数的 Shamir Secret Sharing（LACTF 2026）](#shamir-secret-sharing-with-deterministic-coefficients-lactf-2026)
- [加密保护端点中的竞态条件（LACTF 2026）](#race-condition-in-crypto-protected-endpoints-lactf-2026)
- [混淆电路：利用元数据泄露恢复 AES key（srdnlenCTF 2026）](#garbled-circuits-aes-key-recovery-via-metadata-leakage-srdnlenctf-2026)
- [后量子签名故障注入：MAYO（srdnlenCTF 2026）](#post-quantum-signature-fault-injection-mayo-srdnlenctf-2026)
- [基于格的门限签名攻击：FROST（srdnlenCTF 2026）](#lattice-based-threshold-signature-attack-frost-srdnlenctf-2026)
- [Groth16 Trusted Setup 损坏：delta == gamma（DiceCTF 2026）](#groth16-broken-trusted-setup--delta--gamma-dicectf-2026)
- [Groth16 证明重放：未约束的 Nullifier（DiceCTF 2026）](#groth16-proof-replay--unconstrained-nullifier-dicectf-2026)
- [利用 Verifier Oracle 伪造 DV-SNARG（DiceCTF 2026）](#dv-snarg-forgery-via-verifier-oracle-dicectf-2026)
- [KZG Pairing Oracle 恢复置换（UNbreakable 2026）](#kzg-pairing-oracle-for-permutation-recovery-unbreakable-2026)
- [复用多项式系数的 Shamir Secret Sharing（PoliCTF 2017）](#shamir-secret-sharing-with-reused-polynomial-coefficients-polictf-2017)

---

## ZKP Attacks

- 优先找证明过程中的信息泄露
- 若题目要求你证明**不可能成立**的命题（如 K4 的 3-着色），那就必须想办法作弊
- 利用哈希碰撞实现“先提交一个值，后打开成另一个值”
- 恢复 PRNG 状态：若 salt 来自有种子的 PRNG，就可预测
- 小域暴力：若已知 `commit(i) = sha256(salt(i), color(i))` 且 salt 公开，就可暴力所有颜色

---

## Graph 3-Coloring

```python
import networkx as nx
nx.coloring.greedy_color(G, strategy='saturation_largest_first')
```

---

## Z3 SMT Solver Guide

Z3 用来解约束满足问题。当密码题最终退化为“找出满足一堆条件的值”时，它通常很合适。

**基础用法：**
```python
from z3 import *

# 布尔变量（位级问题）
bits = [Bool(f'b{i}') for i in range(64)]

# 整数 / 位向量变量
x = BitVec('x', 32)  # 32-bit 位向量
y = Int('y')         # 任意精度整数

solver = Solver()
solver.add(x ^ 0xdeadbeef == 0x12345678)
solver.add(y > 100, y < 200)

if solver.check() == sat:
    model = solver.model()
    print(model.eval(x))
```

**BPF / SECCOMP 过滤器求解：**

当题目使用 BPF 字节码做 flag 校验时（如自定义 syscall 过滤器）：

```python
from z3 import *

# 把 flag 建模成若干 4-byte 块（BPF 常这么读）
flag = [BitVec(f'f{i}', 32) for i in range(14)]
s = Solver()

# 约束：可打印 ASCII
for f in flag:
    for byte in range(4):
        b = (f >> (byte * 8)) & 0xff
        s.add(b >= 0x20, b < 0x7f)

# 从 BPF dump（如 seccomp-tools dump ./binary）重建约束
mem = [BitVec(f'm{i}', 32) for i in range(16)]

s.add(mem[0] == flag[0])
s.add(mem[1] == mem[0] ^ flag[1])
s.add(mem[4] == mem[0] + mem[1] + mem[2] + mem[3])
s.add(mem[8] == 4127179254)

if s.check() == sat:
    m = s.model()
    flag_bytes = b''
    for f in flag:
        val = m[f].as_long()
        flag_bytes += val.to_bytes(4, 'little')
    print(flag_bytes.decode())
```

**把 bit 解回 flag：**
```python
from Crypto.Util.number import long_to_bytes

if solver.check() == sat:
    model = solver.model()
    flag_bits = ''.join('1' if model.eval(b) else '0' for b in bits)
    print(long_to_bytes(int(flag_bits, 2)))
```

**什么时候用 Z3：**
- 类型系统约束（OCaml GADT、Haskell type puzzle）
- 带代数结构的自定义 hash / cipher
- 有限域上的方程组
- 把 SAT 编码进题目里的挑战
- 约束传播类谜题

---

## Garbled Circuits: Free XOR Delta Recovery (LACTF 2026)

**模式（sisyphus）：** 使用 free XOR 优化的 Yao garbled circuit。正常求值时只能拿到某一条 wire label，但另一条 label 也是后续所必需的。

**Free XOR 性质：** 同一条 wire 的两个 label 满足 `W_0 XOR W_1 = delta`，其中 `delta` 是全局秘密。

**攻击：** 取四行真值表中的三行密文做 XOR，使 AES 项相互抵消：
```python
# Encrypted rows: E_i = AES(key_a_i XOR key_b_i, G_out_f(a,b))
# 选择三行做 XOR，若 AES 输入之间只差 delta，就会相互抵消
# 于是可直接露出 delta，进而 W_1 = W_0 XOR delta
```

**一般规律：** 在 garbled circuit 里，只要能拿到同一条 wire 的任意两种 label，就等价于恢复全局 `delta`，接着几乎所有 wire label 都能推出。

---

## Bigram/Trigram Substitution -> Constraint Solving (LACTF 2026)

**模式（lazy-bigrams）：** 一个 bigram 替换密码，而明文结构已知（例如 NATO phonetic alphabet）。

**OR-Tools CP-SAT 思路：**
1. 把替换映射建模为单射（每个 bigram 一个 `IntVar`）
2. 用已知 flag 前缀加 crib 约束
3. 加入“明文必须是合法 NATO 单词序列”的正则 / automaton 约束
4. 交给求解器，往往能得到唯一解

**模式（not-so-lazy-trigrams）：** 所谓 trigram substitution，其实按位置 `mod 3` 分解成 3 个独立的单表替换密码。

**分解关键点：** 如果密文使用 `shuffle[pos % n][char]` 这类结构，那么每个余数类 `pos = k (mod n)` 都是独立的 monoalphabetic substitution，可分别做频率分析或已知明文恢复。

---

## Shamir Secret Sharing with Deterministic Coefficients (LACTF 2026)

**模式（spreading-secrets）：** Shamir 多项式的系数 `a_1...a_9` 不是随机的，而是由 secret `s` 通过某个有种子的 RNG 决定。题目还泄露了一个 share `(x_0, y_0)`。

**漏洞：** 已知一条 share 后，方程

`y_0 = s + g(s)*x_0 + g^2(s)*x_0^2 + ... + g^9(s)*x_0^9`

就变成关于 `s` 的**一元方程**。

**通过 Frobenius 找根：**
```python
# 在 GF(p) 中，通过 gcd(h(s), x^p - x) 找 root
# h(s) = s + g(s)*x_0 + ... + g^9(s)*x_0^9 - y_0
R.<x> = PolynomialRing(GF(p))
h = construct_polynomial(x0, y0)
xp = pow(x, p, h)
g = gcd(xp - x, h)
roots = [-g[0]/g[1]] if g.degree() == 1 else g.roots()
```

**一般规律：** 只要 Shamir 的所有系数都由 secret 决定，一条 share 就不再是“随机切片”，而是直接构成一元代数方程。

---

## Race Condition in Crypto-Protected Endpoints (LACTF 2026)

**模式（misdirection）：** 某个端点存在 TOCTOU 竞态：先判断 `if counter < 4`，再自增。只要并发足够高，多个请求就会在自增前一起通过检查。

**利用：**
1. **绕过缓存：** 稍微改动每个请求（如 nonce 前面补零），避免服务端复用验签缓存
2. **同步并发：** 用 barrier 同时发出几十个请求
3. 所有请求在看到 `counter < 4` 时都认为自己合法，最终把计数器一口气冲过限制

```python
from multiprocessing import Process, Barrier
barrier = Barrier(80)

def make_request(barrier, modified_sig):
    barrier.wait()
    requests.post(url, json={"sig": modified_sig})

processes = [Process(target=make_request, args=(barrier, modify_sig(i))) for i in range(80)]
```

**关键点：** 这是典型 `check-then-act` 漏洞。在密码学外层协议里一样适用。

---

## Garbled Circuits: AES Key Recovery via Metadata Leakage (srdnlenCTF 2026)

**模式（FHAES）：** 服务端用 garbled circuits 评估 AES，且每个连接中的 key 固定。攻击点不在 AES 本身，而在 garbling 元数据。

**攻击流程：**
1. 构造一个自定义电路，其中有一个攻击者可控的 AND gate，用来泄露全局 Free-XOR offset `delta`
2. 知道 `delta` 后，作为 evaluator 本地跑 key schedule 相关部分（前 1360 个 AND gate）
3. 对前 16 个 key-schedule S-box 调用，暴力 256 个输入字节，并重建该 S-box 子电路，与观察到的 AND table 对比
4. 从 S-box 输出恢复 key word，结合 AES-128 key schedule 递推式反推出完整 128-bit key

```python
def garble_and(A, B, D, and_idx):
    """按正确奇偶规则重建 garbling。"""
    r = B & 1
    alpha = A & 1
    beta = B & 1
    return gate0, gate1, z

def evaluator_and(A, B, gate0, gate1, and_idx):
    """用基于哈希的方式求值 AND gate。"""
    hashA = h_wire(A, and_idx)
    hashB = h_wire(B, and_idx)
    L = hashA if (A & 1) == 0 else (hashA ^ gate0)
    R = hashB if (B & 1) == 0 else (hashB ^ gate1)
    return L ^ R ^ (A * (B & 1))
```

**关键点：** 固定 key + free XOR + AND truth table 泄露，会让小输入空间的 S-box 变得可暴力。这里是从“恢复 delta”进一步升级到“恢复整把 AES key”。

---

## Post-Quantum Signature Fault Injection: MAYO (srdnlenCTF 2026)

**模式（Faulty Mayo）：** 在 `mayo_sign_signature` 的最后 `s = v + O*x` 之前存在 1 byte 故障注入窗口。通过 64 次带控制的故障签名，可以逐行恢复秘密矩阵 `O`。

**攻击流程：**
1. 逆向二进制，把 fault offset 映射到 `mayo_sign_signature` 的具体指令
2. 对秘密矩阵 `O` 的每一行，利用故障签名提取一组 GF(16) 线性方程
3. 对每行的 17 个变量做 GF(16) 高斯消元
4. 用恢复出的 `O` 和公钥里的 public seed 重建等价 signer
5. 为目标消息伪造合法签名

**GF(16) 高斯消元：**
```python
INV = [0] * 16
MUL = [[0]*16 for _ in range(16)]

def solve_linear_gf16(equations, nvars=17):
    """在 GF(16) 上做高斯消元。"""
    A = [x[:] + [y] for x, y in equations]
    m, row = len(A), 0
    for col in range(nvars):
        piv = next((r for r in range(row, m) if A[r][col] != 0), None)
        if piv is None: continue
        A[row], A[piv] = A[piv], A[row]
        invp = INV[A[row][col]]
        A[row] = [MUL[invp][v] for v in A[row]]
        for r in range(m):
            if r != row and A[r][col] != 0:
                f = A[r][col]
                A[r] = [A[r][c] ^ MUL[f][A[row][c]] for c in range(nvars + 1)]
        row += 1
    return [A[i][nvars] for i in range(nvars)]
```

**关键点：** 这相当于把经典 DFA 的思路搬到后量子签名上，只不过底层代数从 GF(2^8) / 整数换成了 GF(16)。

---

## Lattice-Based Threshold Signature Attack: FROST (srdnlenCTF 2026)

**模式（Threshold）：** 预处理队列容量限制允许收集大量签名样本。由于 challenge 构造可控，每个系数最终变成一维带噪线性方程。

**攻击流程：**
1. 利用“活动队列最多 8 个”的限制，而不是总次数限制，通过交替菜单操作累积样本
2. 每次构造 commitment `w₀`，让聚合 commitment 在取高位前抵消，从而固定 challenge `c`
3. challenge 固定后，每个系数变成 `z = λ·u + noise (mod q)`
4. 选择不同 signer 子集，使目标 signer 的 Lagrange 系数 λ 呈现不同尺度
5. 通过区间求交 + 最大似然恢复 share
6. 恢复 7 个 share 后，再与自己的 share 一起做拉格朗日插值，重建主秘密

**区间求交：**
```python
from math import ceil, floor

def intersect_intervals(intervals, lam, z, q, B):
    """根据一组 (λ, z) 观测与噪声上界 B 收缩候选区间。"""
    out = []
    for lo, hi in intervals:
        if lam > 0:
            kmin = ceil((lam * lo - z - B) / q)
            kmax = floor((lam * hi - z + B) / q)
            for k in range(kmin, kmax + 1):
                a = (z + q * k - B) / lam
                b = (z + q * k + B) / lam
                lo2, hi2 = max(lo, a), min(hi, b)
                if lo2 <= hi2:
                    out.append((lo2, hi2))
    out.sort()
    merged = [out[0]] if out else []
    for lo, hi in out[1:]:
        if lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged
```

**关键点：** 一旦 challenge 可控，门限签名里每个参与方 share 的贡献就能被拆开。通过不同子集改变 Lagrange 系数，相当于对同一个未知量做多尺度投影，区间会不断收缩到唯一值。

---

## Groth16 Broken Trusted Setup — delta == gamma (DiceCTF 2026)

**模式（Housing Crisis）：** Groth16 verifier 中竟然满足 `vk_delta_2 == vk_gamma_2`，这会彻底破坏 soundness，证明可以被平凡伪造。

**伪造：**
```python
from py_ecc.bn128 import G1, G2, multiply, add, neg, pairing
from py_ecc.bn128 import curve_order as q

# 当 delta == gamma 时，配对方程化简：
# e(A, B) = e(alpha, beta) * e(vk_x + C, gamma)
# 令 A = vk_alpha1, B = vk_beta2，则：
# e(alpha, beta) * e(vk_x + C, gamma) = e(alpha, beta)
# -> e(vk_x + C, gamma) = 1 -> C = -vk_x

forged_A = vk_alpha1
forged_B = vk_beta2
forged_C = neg(vk_x)
```

**检测：** 先看 verifier contract 中 `vk_delta_2` 与 `vk_gamma_2` 是否相等。若相等，整个 Groth16 就已经塌了。

**关键点：** 在动任何复杂脑筋之前，先检查 verification key 常量是不是已经明显损坏。

---

## Groth16 Proof Replay — Unconstrained Nullifier (DiceCTF 2026)

**模式（Housing Crisis）：** DAO 没有记录已经使用过的 `proposalNullifierHash`，而电路里这个 nullifier 也没有真正受约束。于是 setup 交易中的一份合法 proof 可以无限次重放。

**攻击：**
1. 找到 DAO 的部署 / setup 交易
2. 提取其中的 Groth16 证明
3. 针对每个 proposal 重放同一份 proof
4. 利用可重复提案来控制 DAO 行为（下注、建市场、结算等）

**关键点：** 对 ZK 系统来说，“nullifier 是否被跟踪”和“电路是否真的约束了公开输入”同样重要。

---

## DV-SNARG Forgery via Verifier Oracle (DiceCTF 2026)

**模式（Dot）：** 一个 adder circuit 上的 DV-SNARG。要求你为**错误答案**伪造 20 份合法 proof。

**关键点：** DV-SNARG 在 prover 能访问 verifier oracle 时，soundness 会显式退化（ePrint 2024/1138）。可通过查询模式逐步学出 verifier 的秘密随机量。

**DPP（Dot Product Proof）结构：**
```text
q[i] = v[i] + b*(tensor[i] - constraint[i])
其中 b 为固定常数（如 162817）
     v[i] 为 [-256, 256] 的随机值
     constraint weights r 为 [-2^40, 2^40] 的随机值
```

**通过 CRS 项抵消来伪造：**
对于一个错误答案，只有输出约束（wire N）被破坏。找两条 CRS 项，它们对某个 gate 的约束贡献恰好可互相抵消：

1. wire N 同时出现在 gate G 与输出约束中
2. gate G 的输入对 `pair(input1, input2)` 只出现在 gate G
3. 对错误 proof 加上 `CRS[wire_N]` 再减去 `CRS[pair]`，即可抵消 `b*r_G`
4. 剩余差额 `b*r_output` 也会同步抵消
5. 再通过 `h2` 上附加 `delta = -v[N] + 2*b*v[input1]*v[input2]` 修正

**通过 oracle 学 `v`：**
```python
# 当 streak=0 时，提交正确答案是“安全”的，不会重置 streak
# 利用未约束的对角项，学习 |v[i]|

for guess in range(257):
    response = oracle_query(guess)
    if response == "hit":
        abs_v_i = guess
        break

# 再利用非对角的未约束 pair 判断符号
```

**性能：** Phase 1 约 364 次查询，20 份 proof 大约总共 400 秒左右。

**关键点：** 对这类 oracle 型 DV-SNARG，策略通常是先学出少量 verifier 随机量，再利用 CRS 代数消项伪造证明。

---

## KZG Pairing Oracle for Permutation Recovery (UNbreakable 2026)

**模式（toxicwaste）：** KZG 承诺公开了一组被打乱顺序的点 `{alpha^i * G1}`。shuffle 只隐藏“哪个点对应哪个指数”。利用配对作为 oracle，可以先恢复指数顺序，再恢复 toxic waste `alpha`。

**distortion map 技巧：** 在超奇异 pairing-friendly 曲线上，失真映射 `psi((x,y)) = (zeta*x, y)`（`zeta^3 = 1`）可把“指数相加”暴露到配对值里：

```python
from sage.all import *

# 对于 P_i = alpha^a_i * G1, P_j = alpha^a_j * G1：
# e(P_i, psi(P_j)) = e(G1, psi(G1))^(alpha^(a_i + a_j))
# 若 e(P_i, psi(P_j)) == e(P_k, psi(G1))，则 a_i + a_j == a_k

g1 = None
base_pairing = None
for P in shuffled_points:
    val = P.weil_pairing(psi(P), order)
    if base_pairing is None:
        base_pairing = val
        g1 = P
    elif val == base_pairing:
        g1 = P
        break

# 再沿着链依次恢复 alpha*G1, alpha^2*G1, ...
# 最后拿到有序点集后，可解多项式得到 alpha
```

**关键点：** 配对把“加法关系”暴露给你，却不要求你真正解离散对数。于是原本看似安全的 shuffle，会退化成一个可排序问题。

---

## Shamir Secret Sharing with Reused Polynomial Coefficients (PoliCTF 2017)

**模式：** 某个 Shamir SSS 实现对 secret 的每个字符都复用了同一组随机多项式系数。于是同一评估点上的两个 share 相减时，高次项会全部抵消。

```python
# 正常 Shamir：每个字符都应使用不同的随机系数
# 错误实现：对所有字符都复用同一组 a_j
# 因此：
# y_1[i] - y_1[0] = f[i] - f[0]
# 若已知 f[0]（例如 flag 前缀里的 'f'）：
flag = ''.join(chr(shares[i] - shares[0] + ord('f')) for i in range(len(shares)))
```

**关键点：** 正确的 Shamir SSS 必须对每个 secret byte 独立采样随机系数。一旦复用系数，share 间相减就会直接露出明文差值。

**参考：** PoliCTF 2017
