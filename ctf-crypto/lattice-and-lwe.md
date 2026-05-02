# CTF Crypto - 格与 LWE 攻击

## Table of Contents
- [快速分诊：这是不是格问题？](#quick-triage-is-this-a-lattice-problem)
- [核心工具：LLL、BKZ、Babai、CVP、SVP](#core-tools-lll-bkz-babai-cvp-svp-asis-ctf-finals-2015-ctfzone-2017)
  - [LLL](#lll)
  - [BKZ](#bkz)
  - [Babai 最近平面](#babai-nearest-plane)
  - [CVP vs SVP](#cvp-vs-svp)
- [隐藏数问题（HNP）：部分 nonce / 偏置 nonce](#hidden-number-problem-hnp-partial-nonce--biased-nonce-nullcon-hackim-2020-ledger-donjon-ctf-2020)
  - [最小化的 ECDSA 部分 nonce 工作流](#minimal-ecdsa-partial-nonce-workflow)
- [把 LCG 与截断输出视为格问题](#lcg-and-truncated-output-as-a-lattice-problem-x-mas-ctf-2018-fwordctf-2020)
  - [最小化的截断 LCG 工作流](#minimal-truncated-lcg-workflow)
- [通过嵌入与 CVP 解 LWE](#lwe-via-embedding-and-cvp-plaidctf-2016-aero-ctf-2020)
  - [嵌入式格构造](#embedding-style-lattice)
  - [针对三元或稀疏秘密](#for-ternary-or-sparse-secrets)
- [Ring-LWE / Module-LWE 识别笔记](#ring-lwe--module-lwe-recognition-notes-plaidctf-2016-dicectf-2022)
  - [把 Ring-LWE 摊平成普通 LWE](#flattening-ring-lwe-to-plain-lwe)
- [正交格：HSSP / AHSSP 风格恢复](#orthogonal-lattices-hssp--ahssp-style-recovery-zer0pts-ctf-2022)
- [通过格约减解 Subset Sum / Knapsack](#subset-sum--knapsack-via-lattice-reduction-hitcon-ctf-2017-backdoorctf-2023)
- [常见失败模式](#common-failure-modes)
- [在投入格之前的快速检查表](#quick-checklist-before-you-commit-to-lattices)

---

## Quick Triage: Is This a Lattice Problem?

遇到以下信息时，优先考虑格工具：

- 大量模方程，并且题目承诺隐藏量很小、很稀疏，或彼此接近
- 某个 secret nonce / seed / state bit 只泄露了一部分
- 线性关系里带有有界误差项
- 在 `Z_q` 上给出向量 / 矩阵，而真正解应该异常地短
- subset-sum / knapsack 结构“看起来过于规整”

常见 CTF 说法：

- “已知 k 的高位”
- “误差很小”
- “秘密系数属于 {-1,0,1}”
- “从截断输出恢复 seed”
- “找一条短向量”
- “解带噪模线性方程”

**先问自己：到底什么是“小”的？**

- secret 本身
- 误差向量
- nonce 差值
- `{0,1}^n` 中的子集指示向量
- 模回绕引入的修正项

这个“小东西”通常就是格真正要暴露出来的对象。

---

## Core Tools: LLL, BKZ, Babai, CVP, SVP (ASIS CTF Finals 2015, CTFZone 2017)

### LLL

默认第一步。快、稳，很多 CTF 参数下已经够用。

适用场景：

- 维度中等
- 隐藏向量真的很短
- 题目明显期待标准 embedding attack
- 你想先看出结构，再追求精确恢复

```python
from sage.all import Matrix, ZZ

M = Matrix(ZZ, basis_rows)
R = M.LLL()
print(R[0])
```

### BKZ

当 LLL 差一点时再上 BKZ。

- 适合更难的 CVP / SVP 实例
- 目标向量与随机格向量间距不明显时更有用
- 在 CTF 中，`BKZ(block_size=20..35)` 往往已经足够

```python
R = M.BKZ(block_size=25)
```

### Babai nearest plane

先把基约减，再用 Babai 做近似 CVP，常见于三元 secret 或小误差 LWE。

```python
from fpylll import IntegerMatrix, CVP

# 构造并约减好基之后：
closest = CVP.babai(B, target)
```

### CVP vs SVP

- **SVP：** 找一条异常短的非零格向量
- **CVP：** 找离某个目标最近的格点

经验法则：

- 若你只知道“某种关系应该很短”，优先想 SVP / embedding
- 若已经有一个目标向量，希望找最近合法点，优先想 CVP / Babai

---

## Hidden Number Problem (HNP): Partial Nonce / Biased Nonce (nullcon HackIM 2020, Ledger Donjon CTF 2020)

**模式：** 签名或 PRNG 方程泄露了隐藏值 `k` 的若干 bit，或者 `k` 本身来自偏置 / 小范围分布。

典型形式：

`a_i * x + b_i ≡ e_i (mod q)`

其中：

- `x` 是私钥
- `e_i` 很小，或部分已知

正是这个“小误差”让问题进入格范畴。

**何时使用：**

- 多条签名泄露了 nonce 的高位 / 低位
- Schnorr / ECDSA 的 nonce 有偏置
- 自定义模方程中每行都只有一小段隐藏修正

**实战流程：**

1. 先把方程全部规整，让同一个 secret key 出现在每一行
2. 把有界误差项单独拿出来
3. 缩放各行，使不同坐标量级尽量接近
4. 跑 `LLL`
5. 回代到原方程中验证 candidate

模板：

```python
from sage.all import Matrix, ZZ

def build_hnp_lattice(q, coeffs, bounds):
    n = len(coeffs)
    rows = []
    for i in range(n):
        row = [0] * (n + 1)
        row[i] = q
        rows.append(row)

    last = [c for c in coeffs] + [bounds]
    rows.append(last)
    return Matrix(ZZ, rows)
```

**关键点：** CTF 里的 HNP 往往不需要“完美建模”。只要真解对应的向量比随机向量短 enough，`LLL` 往往就会把它直接暴露出来，或者至少逼近到只剩几位可暴力。

### Minimal ECDSA partial-nonce workflow

若题目泄露了每个 nonce `k_i` 的高位，可写成：

`k_i = leaked_i * 2^t + delta_i`

其中 `delta_i` 很小。对 ECDSA：

`s_i * k_i - h_i ≡ r_i * d (mod q)`

代入后得到：

`r_i * d - s_i * delta_i ≡ s_i * leaked_i * 2^t - h_i (mod q)`

现在未知量变成：

- 私钥 `d`
- 一组很小的修正项 `delta_i`

这正是格要抓的东西。

最小模板：

```python
from sage.all import Matrix, ZZ

def build_ecdsa_partial_nonce_lattice(q, rs, ss, hs, leaked, t):
    n = len(rs)
    M = Matrix(ZZ, n + 2, n + 2)

    for i in range(n):
        M[i, i] = q

    for i in range(n):
        M[n, i] = ss[i]
        M[n + 1, i] = (hs[i] - ss[i] * leaked[i] * (1 << t)) % q

    M[n, n] = 1
    M[n + 1, n + 1] = q // (1 << t)
    return M
```

接下来：

1. 构造格
2. 跑 `LLL`
3. 在短向量里找可疑的 `d`
4. 用所有签名回验
5. 若只差 1-2 位，补一个很小的暴力收尾

---

## LCG and Truncated Output as a Lattice Problem (X-MAS CTF 2018, FwordCTF 2020)

**模式：** 内部状态满足仿射递推，但你只能看到：

- 高位
- 低位
- 带未知参数的多个状态
- 或连续输出 + 小隐藏修正

常见情形：

- seed 未知，但模数已知
- 模数、`a`、`b` 已知，只泄露高位
- `a`、`b` 未知，但拿到了多个精确或截断输出

技巧是写成：

`state_i = observed_i * 2^t + hidden_i`

其中 `hidden_i` 很小。代回递推式后，就得到关于这些小量的模线性关系。

**何时使用：**

- LCG 状态只泄露高位
- 递推模数很大
- 拿到了若干连续输出
- 直接代数求解显得很乱，但每步只差一点点隐藏余量

**关键点：** 截断 LCG 往往只是换皮版 HNP。只要隐藏部分足够小，格就能把它拉出来。

### Minimal truncated-LCG workflow

假设：

`x_{i+1} = a*x_i + b (mod m)`

但服务端只泄露高位：

`y_i = x_i >> t`

于是：

`x_i = y_i * 2^t + z_i`

其中 `z_i` 是隐藏低位，且很小。代入递推：

`y_{i+1} * 2^t + z_{i+1} ≡ a*(y_i * 2^t + z_i) + b (mod m)`

整理后：

`z_{i+1} - a*z_i ≡ a*y_i*2^t + b - y_{i+1}*2^t (mod m)`

现在未知量就是小的 `z_i`，这是标准格入口。

模板：

```python
from sage.all import Matrix, ZZ

def build_truncated_lcg_lattice(m, a, b, ys, t):
    n = len(ys) - 1
    M = Matrix(ZZ, n + 1, n + 1)

    for i in range(n):
        M[i, i] = m

    for i in range(n):
        rhs = (a * ys[i] * (1 << t) + b - ys[i + 1] * (1 << t)) % m
        M[n, i] = rhs

    M[n, n] = 1 << t
    return M
```

接下来：

1. 使用多组连续输出
2. 跑 `LLL`
3. 恢复候选低位 `z_i`
4. 重建完整状态 `x_i`
5. 精确验证递推关系

---

## LWE via Embedding and CVP (PlaidCTF 2016, Aero CTF 2020)

**模式：** 给定 `A`、`b`、模数 `q`，并承诺：

`b = A*s + e (mod q)`

其中：

- `s` 很小或很稀疏
- `e` 很小

这就是标准 LWE。

**先问几个问题：**

- `s` 是否来自 `{-1,0,1}` 或一个很小的集合？
- 误差是否明显远小于 `q`？
- 行数是否很多、列数相对少？
- 如果把模回绕忽略掉，整数线性代数是否“几乎成立”？

### Embedding-style lattice

```python
from sage.all import Matrix, ZZ, identity_matrix, zero_matrix, block_matrix

def lwe_embedding(A, q):
    m, n = A.nrows(), A.ncols()
    top = block_matrix([[q * identity_matrix(m), zero_matrix(ZZ, m, n)]])
    bottom = block_matrix([[A.transpose(), identity_matrix(n)]])
    return block_matrix([[top], [bottom]])
```

之后：

- 先约减基
- 再用 Babai / nearest-plane 找目标附近格点
- 恢复 secret / error 对

### For ternary or sparse secrets

CVP 输出后：

- 把接近 0 的值映回 `{-1,0,1}`
- 同时测试大小端
- 同时测试行向量 / 列向量约定

**关键点：** 很多 CTF LWE 远低于真实密码学安全阈值。题目的关键通常不是“打破工业级 LWE”，而是发现 secret 或 error 被故意选得太小。

---

## Ring-LWE / Module-LWE Recognition Notes (PlaidCTF 2016, DiceCTF 2022)

以下迹象提示你可能碰到了 Ring-LWE / Module-LWE：

- 对象是多项式，模掉 `x^n ± 1`
- 乘法是循环卷积或负循环卷积
- 样本形如 `(a(x), b(x)=a(x)s(x)+e(x))`
- 系数都在模 `q` 下

但在很多 CTF 里，真正的捷径并不是完整的 Ring-LWE 攻击，而是：

- 系数小到可以直接 lift 回整数
- 环结构能拆成更简单的标量问题
- 服务端泄露足够多评价点，可摊平成普通 LWE
- NTT / 表示转换存在 bug

**实战建议：**

- 先试着把多项式问题摊平成向量
- 在追更深的代数结构前，先测试系数 embedding
- 检查 NTT / inverse NTT 是否写错
- 检查符号、字节序，以及系数是否被正确中心化到 `[-q/2, q/2]`

### Flattening Ring-LWE to plain LWE

```python
from sage.all import Matrix, ZZ, vector

def ring_lwe_to_matrix(a_poly, n, q):
    """把 Z_q[x]/(x^n+1) 中的 a(x) 摊平成负循环旋转矩阵。"""
    coeffs = list(a_poly) + [0] * (n - len(list(a_poly)))
    rows = []
    for i in range(n):
        row = [0] * n
        for j in range(n):
            idx = (i - j) % n
            sign = -1 if (i - j) < 0 and ((i - j) % n) != 0 else 1
            # negacyclic: x^n = -1
            if j <= i:
                row[j] = coeffs[i - j]
            else:
                row[j] = -coeffs[n + i - j]
        rows.append(row)
    return Matrix(ZZ, rows)
# 摊平后按普通 LWE 处理：b_vec = A_mat * s_vec + e_vec (mod q)
```

**关键点：** 多数 Ring-LWE / Module-LWE CTF 题，最终都能先摊平到 plain LWE，再用常规格工具解决。

---

## Orthogonal Lattices: HSSP / AHSSP Style Recovery (zer0pts CTF 2022)

**模式：** 你拿到的不是 secret matrix 本身，而是一批应当与它正交（模 `M` 或模 `p`）的向量。

这种结构常出现在：

- 恢复隐藏的二元矩阵
- 恢复隐藏的低重量子空间
- 从模内积关系中重建未知行

核心流程：

1. 构造一个格，使其短向量代表“正交关系”
2. 约减这个格
3. 得到正交格
4. 求 kernel / 正交补
5. 再次约减，显露真实的二元或短基

```python
from sage.all import Matrix, ZZ, identity_matrix, block_matrix

def orthogonal_lattice_recovery(H, M):
    """从 h = alpha * A (mod M) 恢复隐藏二元基。"""
    k, n = H.nrows(), H.ncols()
    top = block_matrix([[M * identity_matrix(k), Matrix(ZZ, k, n)]])
    bot = block_matrix([[H.change_ring(ZZ).transpose(), identity_matrix(n)]])
    L = block_matrix([[top], [bot]])
    L_reduced = L.LLL()
    return L_reduced
```

**何时使用：**

- 题目给出 `h = αA` 或其仿射变体
- 未知矩阵项来自 `{0,1}` 或其他很小的字母表
- 直接解不动，因为真正结构躲在某个未知子空间里

**关键点：** 最短向量往往不是最终答案，而是“进入答案空间的入口”。先恢复正交空间，再反向重建隐藏基。

---

## Subset Sum / Knapsack via Lattice Reduction (HITCON CTF 2017, BackdoorCTF 2023)

**模式：** 恢复一个二元向量 `x_i ∈ {0,1}`，满足：

`sum(a_i * x_i) = target`

这是经典 subset-sum / knapsack 格模型。

适用场景：

- 实例是刻意设计的 low-density
- 隐藏向量是二元的
- 直接 meet-in-the-middle 仍然太大

模板：

```python
from sage.all import Matrix, ZZ

def knapsack_lattice(weights, target):
    n = len(weights)
    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = 1
        M[i, n] = weights[i]
    M[n, n] = -target
    return M
```

然后：

- 跑 `LLL`
- 找最后一列为 0 的行
- 检查前面坐标是否落在 `{0,1}` 或 `{-1,0,1}`

**关键点：** 格的构造保证了“正确子集”会对应一条异常短、且最后坐标异常小的向量。CTF 简化实例里，这个向量通常会在 LLL 后留下来。

---

## Common Failure Modes

- **缩放错误：** 某个坐标量级过大，把真正短向量淹没了
- **中心化错误：** 应该映射到 `[-q/2, q/2]`，而不是保留在 `[0, q)`
- **方向搞反：** 行 / 列约定写反
- **样本太少：** 格是对的，但约束不足以钉住 secret
- **噪声太大：** LLL 不够，需要 BKZ、更好的缩放或换 embedding
- **题型判断错：** 看起来像 LWE，其实可能是纯线代、CRT 或编码 bug
- **忘了最后的小暴力：** 格常常只能把你带到“几乎正确”

---

## Quick Checklist Before You Commit to Lattices

- 我能否把未知量写成“小 secret”或“小误差”？
- 是否存在一个受界项，使某条向量比随机向量明显更短？
- 我是否试过把系数中心化？
- 我是否试过行 / 列两种约定？
- 我是否先跑过 `LLL`，而不是一上来就堆复杂模型？
- 如果 `LLL` 差一点，我是否试过 `BKZ` 或 Babai？
- 若实例是多项式型，我是否先把它摊平成系数向量？

如果这些问题大多回答为“是”，那这题大概率就该用格。
