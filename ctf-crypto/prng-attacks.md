# CTF Crypto - PRNG 攻击（CTF 时代技巧）

更偏 CTF 实战、2017 年之后常见的 PRNG 攻击。基础 PRNG 恢复（MT19937、LCG 参数恢复、ChaCha20、V8 XorShift128+、密码破解）见 [prng.md](prng.md)。

## Table of Contents
- [从子集和恢复 Mersenne Twister 种子（Tokyo Westerns 2017）](#mersenne-twister-seed-recovery-from-subset-sum-tokyo-westerns-2017)
- [通过约束传播恢复 MT19937 状态（HITCON 2017）](#mt19937-state-recovery-via-constraint-propagation-hitcon-2017)
- [用 Z3 逆 Rule 86 元胞自动机 PRNG（Insomni'hack 2018）](#rule-86-cellular-automaton-prng-reversal-via-z3-insomnihack-2018)
- [利用部分模值对 Java LCG 种子做中间相遇（P.W.N. CTF 2018）](#java-lcg-seed-meet-in-the-middle-via-partial-modulo-pwn-ctf-2018)
- [通过乘法逆元向后回推 LCG（P.W.N. CTF 2018）](#lcg-backward-stepping-via-multiplicative-inverse-pwn-ctf-2018)
- [从 ASCII 奇偶性恢复 LFSR bit-fold（X-MAS CTF 2018）](#lfsr-bit-fold-recovery-from-ascii-parity-x-mas-ctf-2018)
- [利用 Z3 求解时间形成的 PRNG 计时预言机（X-MAS CTF 2018）](#z3-solve-time-timing-oracle-on-prng-x-mas-ctf-2018)
- [用 randcrack 预测 DSA k（CSAW CTF 2018）](#randcrack-fed-dsa-k-prediction-csaw-ctf-2018)
- [通过格式化字符串全局写偏移时间种子 PRNG（FireShell 2019）](#time-seeded-prng-offset-via-format-string-global-write-fireshell-2019)
- [通过 UUID XOR 泄露被 NTP 污染的 PRNG 状态（RuCTFe 2018）](#ntp-poisoned-prng-state-leak-via-uuid-xor-ructfe-2018)

---

## Mersenne Twister Seed Recovery from Subset Sum (Tokyo Westerns 2017)

**模式：** MT19937 用一个 32-bit 种子生成若干子集和问题（例如“从一组数里选若干个，使其和为目标值”）。解出这些小型子集和后，可以恢复特定位置的 MT 输出值。只要恢复出索引 0 和 227 处的两个输出，就足以逆推出 MT 的播种过程。

**MT twist 函数关系：**
```text
mt[i] = mt[i-624] XOR twist(mt[i-624], mt[i-623])
```
在环回处，`mt[624]` 同时依赖 `mt[0]`（新一轮）和 `mt[397]`（旧一轮）。如果能通过子集和解出 `mt[0]` 和 `mt[227]`（它与 `mt[624-227] = mt[397]` 对应），就能得到足够信息来逆 twist。

```python
import random

def crack_seed_from_two_outputs(mt0_val, mt227_val):
    """枚举所有 2^32 种种子，直到 MT 输出匹配恢复值。"""
    for seed in range(2**32):
        r = random.Random()
        r.seed(seed)
        # 生成到索引 0 和 227
        outputs = [r.getrandbits(32) for _ in range(228)]
        if outputs[0] == mt0_val and outputs[227] == mt227_val:
            return seed
    return None

# 一旦恢复种子，未来和过去的输出都可预测
r = random.Random()
r.seed(recovered_seed)
```

**关键点：** 利用 twist 的环回关系，MT19937 只需极少量状态值（如索引 0 和 227）就能恢复播种信息。凡是通过可解数学谜题间接暴露 MT 状态的位置，都应考虑整机状态恢复。

**参考：** Tokyo Westerns CTF 2017

---

## MT19937 State Recovery via Constraint Propagation (HITCON 2017)

**模式：** 服务端每轮问题只泄露 24-120 bit 的 PRNG 输出（例如部分位模式、子集和结果、模约简值）。与其硬等 624 个完整 32-bit 输出，不如把 MT 状态建模成“每个单元都有一组候选值”，再沿着 MT 递推在前后方向做约束传播。

**MT 递推依赖：**
```text
state[i] = state[i-624] XOR twist(state[i-624], state[i-623])
```
这意味着 `state[x]` 同时依赖 `state[x-624]`、`state[x-623]` 和 `state[x-227]`（通过生成步骤）。任意位置的部分信息都可以双向传播。

**约束传播方法：**
```python
# 模型：每个状态字起初都有 2^32 个候选
# 部分观测：缩小对应索引的候选集合
# 传播：对每个被约束的单元，继续收缩相关位置

def propagate_forward(state_candidates, idx):
    """MT: state[idx+624] = f(state[idx], state[idx+1])"""
    for s0 in state_candidates[idx]:
        for s1 in state_candidates[idx + 1]:
            new_val = mt_twist(s0, s1)
            state_candidates[idx + 624].add(new_val)

def propagate_backward(state_candidates, idx):
    """逆 twist，用后面的值反向约束更早的状态。"""
    for val in state_candidates[idx]:
        # 已知 state[idx] 和 state[idx-623]，回推 state[idx-624]
        for s1 in state_candidates[idx - 623]:
            s0 = mt_untwist(val, s1)
            state_candidates[idx - 624].add(s0)

# 只要在不同位置收集到约 20 组 24+ bit 的部分观测：
# 大多数状态字都会收缩到单一候选，从而确定整个状态
```

**关键点：** MT19937 的递推允许双向约束传播。多个位置上的部分信息会不断相互收缩，直到整个 624 词状态收敛。每次观测泄露的 bit 越多，所需样本数越少；通常 20 组左右、每组 24 bit 以上的观测就够了。

**参考：** HITCON CTF 2017

---

## Rule 86 Cellular Automaton PRNG Reversal via Z3 (Insomni'hack 2018)

**模式：** 使用 Wolfram 基本元胞自动机 Rule 86 作为 PRNG。可直接用 Z3 的 Bool 数组把 128 轮反推出来：

```python
from z3 import *

def RULE86(x, y, z):
    return Or(And(Not(x), Not(y), z), And(Not(x), y, Not(z)),
              And(x, Not(y), Not(z)), And(x, y, Not(z)))

s = Solver()
state = [Bool(f'b{i}') for i in range(256)]
# 符号化前推 128 轮
for round in range(128):
    new_state = [RULE86(state[(i-1)%256], state[i], state[(i+1)%256]) for i in range(256)]
    state = new_state
# 约束最终状态等于已知输出
for i, bit in enumerate(known_output):
    s.add(state[i] == (bit == 1))
s.check()
model = s.model()
```

**关键点：** 基本元胞自动机通常**不是单射**，也就是说可能有多个前像。但 Z3 很擅长处理这种布尔搜索。对 Rule 86 而言，其 DNF 一共有 4 项（86 的二进制为 `01010110`，对应 rule table 中的 1、2、4、6 位）。可以配合 `s.push()` / `s.pop()` 分轮回溯。这个思路其实适用于任何“把基本元胞自动机当 PRNG”的题：把规则真值表编码成布尔公式，符号化展开 N 轮，再把最终状态约束为已知输出即可。

**参考：** Insomni'hack CTF 2018

---

## Java LCG Seed Meet-in-the-Middle via Partial Modulo (P.W.N. CTF 2018)

**模式：** Java `Random` 的输出只以模 62 的形式可见（例如某密码只暴露字母数字字符）。完整 48-bit 种子暴力不可行，但部分输出依然泄露最低位（`output mod 2`），而高位也能独立恢复，因为 Java LCG 的核心是 `(seed*a + c) >> 16`。因此可以把搜索拆成 `2^18` 的低位部分和 `2^30` 的高位部分。

```python
# 第 1 阶段：枚举低 18 位，筛出 nextInt(62) 奇偶性与已知字符匹配的候选
for low in range(1 << 18):
    if simulate(low)[: K] == known_prefix: candidates.append(low)

# 第 2 阶段：把每个候选扩展到 48 bit，并比对后续输出
for low in candidates:
    for high in range(1 << 30):
        seed = (high << 18) | low
        if simulate(seed) == full_known: return seed
```

**关键点：** Java 的 LCG 会丢弃最低 16 位，因此低 18 位实际上只影响 `nextInt()` 的最低有效 bit。按照这个边界拆分种子后，原本不可行的 `2^48` 搜索会变成两个可管理的阶段：`2^18 + 2^30`。

**参考：** P.W.N. CTF 2018，PW API，writeup 12065

---

## LCG Backward Stepping via Multiplicative Inverse (P.W.N. CTF 2018)

**模式：** 一旦恢复出任意一个向前的状态，就能利用乘数的模逆元反推前一状态：`prev = a^-1 * (state - c) mod m`。对 Java 而言，`a^-1 = -35320271006875 mod 2^48`。

```python
M = 1 << 48
a_inv = pow(25214903917, -1, M)  # Java 乘子的逆元
prev_state = (a_inv * (state - 11)) % M
```

**关键点：** 对任意模为 2 的幂的 LCG，只要乘子可逆，一旦知道某个状态，就能沿链条双向行走，无需再从种子重新模拟。

**参考：** P.W.N. CTF 2018，PW API，writeup 12065

---

## LFSR Bit-Fold Recovery from ASCII Parity (X-MAS CTF 2018)

**模式：** 某个自定义 PRNG 把 32-bit 状态经过多次移位 XOR 折叠成一个 8-bit 输出字节。由于观测到的字节是 ASCII（最高位必为 0），于是每个观测字节都会泄露内部状态的一个奇偶方程。累积足够多这样的约束后，就能在 GF(2) 上用高斯消元恢复状态，而无需暴力。

```python
# 收集奇偶约束：每个 ASCII 字节都会给出 top_bit == 0
# 每个输出 bit 都是状态 bit 的线性组合
# 把约束堆成矩阵，再在 GF(2) 上求解
import numpy as np
A = np.array(constraint_rows, dtype=np.uint8)
b = np.array(known_bits,      dtype=np.uint8)
state = gf2_solve(A, b)
```

**关键点：** 折叠输出字节并不会“隐藏”状态，只要底层仍然是线性的，每个输出 bit 就还是状态 bit 的线性组合。ASCII 的高位恒为 0，正好把这些输出转化成免费线性方程。

**参考：** X-MAS CTF 2018，Probably Really Nice Goodies from Santa，writeup 12686

---

## Z3 Solve-Time Timing Oracle on PRNG (X-MAS CTF 2018)

**模式：** 无法直接验证 PRNG 猜测是否正确，但 `Solver.check()` 在正确输入上会显著更慢，因为约束图会变成“难以判 UNSAT”的情况，而错误输入则往往迅速返回 trivially SAT / SAT。可以对每个字符候选做紧超时的 Z3 调用，用耗时当作预言机。

```python
from z3 import Solver, sat
for c in string.printable:
    s = Solver()
    s.set('timeout', 500)
    s.add(prng_constraints(flag + c, ciphertext))
    t = time.time()
    if s.check() == sat and (time.time() - t) > 0.4:
        flag += c
        break
```

**关键点：** 很多题目内部其实自己就在跑 solver。错误猜测之所以返回很快，是因为约束过于松散或明显可满足；正确猜测反而会把系统逼到困难分支。把 timeout 设紧一些，然后把“求解明显更慢”的候选提升优先级。

**参考：** X-MAS CTF 2018，Probably Really Nice Goodies from Santa，writeup 12686

---

## randcrack-Fed DSA k Prediction (CSAW CTF 2018)

**模式：** DSA 签名时用 `random.randrange()` 生成 nonce `k`。如果服务端同时还有一个“忘记密码”接口会泄露 Python `random` 的输出，那么只要把 624 个 32-bit 样本喂给 `randcrack`，就能预测下一次 `k`，再用 `x = (s*k - h) * r^-1 mod q` 恢复私钥。

```python
from randcrack import RandCrack
rc = RandCrack()
for _ in range(624 // 2):
    v = getrand64()
    rc.submit(v & 0xffffffff); rc.submit(v >> 32)
k = rc.predict_randrange(2, q)
x = ((s*k - h) * pow(r, -1, q)) % q
```

**关键点：** Python 的 `random` 是全局共享的。任何会泄露 `random` 输出的接口，都会污染同进程里其他所有 RNG 使用点，包括 DSA nonce。

**参考：** CSAW CTF 2018，Disastrous Security Apparatus，writeup 12495

---

## Time-Seeded PRNG Offset via Format-String Global Write (FireShell 2019)

**模式：** 服务端使用 `srand((time(0)/10) + bet)` 播种，其中 `bet` 是一个可写全局变量。若存在格式化字符串漏洞，就能先把 `bet` 改成自己想要的值，再在本地用相同 libc 预测后续 `rand()`。

```python
# 1. 格式化字符串：%Xc%Y$n  把想要的 bet 写到 &bet (0x602020)
# 2. 本地：用 C 标准库复现 rand()
from ctypes import CDLL
libc = CDLL('libc.so.6')
libc.srand((int(time.time())//10) + bet_value)
predicted = [libc.rand() for _ in range(n)]
```

**关键点：** 一旦种子等于“时间 + 攻击者可写常量”，那么所谓时间随机数就变成了完全可预测的确定性 RNG，因为攻击者已经控制了整个种子。

**参考：** FireShell CTF 2019，casino，writeup 12916

---

## NTP-Poisoned PRNG State Leak via UUID XOR (RuCTFe 2018)

**模式：** 服务端按 `uuid = time ^ hash_state` 生成 UUID。若你能让它访问一个由你控制的 NTP 端点，并让该端点返回 `0x00`，那么服务端返回的 UUID 就会直接等于 `hash_state`。之后所有 UUID 都可预测：`target_uuid ^ hash_state = required_timestamp`。

```python
# 1. 把服务端的 NTP 指向攻击者控制的返回 0 的时间源
# 2. 注册一次；拿到的 UUID 就等于内部状态
# 3. 对任意目标 uuid，计算所需时间戳 = uuid ^ state
# 4. 发送这个时间戳，读取对应消息
```

**关键点：** 只要“随机量”通过 XOR 与一个用户可控值混合，那就等于把内部状态直接送给攻击者。时间源尤其要检查是否能被用户影响。

**参考：** RuCTFe 2018，vch，writeup 12146
