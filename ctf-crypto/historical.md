# CTF Crypto - 历史密码

## Table of Contents
- [Lorenz SZ40/42（Tunny）密码](#lorenz-sz4042-tunny-cipher)
- [书本密码暴力（Nullcon 2026）](#book-cipher-brute-force-nullcon-2026)

---

## Lorenz SZ40/42 (Tunny) Cipher

Lorenz 密码机使用 12 个轮子来加密 5-bit 的 ITA2 / Baudot 字符。在已知明文场景下，可以通过结构化攻击恢复全部轮子设置。

**机器结构：**
- 5 个 χ（chi）轮：周期分别为 41、31、29、26、23，每一步都前进
- 5 个 Ψ（psi）轮：周期分别为 43、47、51、53、59，只有在 μ37=1 时才前进
- μ61 轮：周期 61，每一步都前进，并控制 μ37 是否前进
- μ37 轮：周期 37，只有在 μ61=1 时才前进，并控制 Ψ 轮是否前进

**加密公式：** `ciphertext[i] = plaintext[i] XOR chi[i] XOR psi[i]`（按 5-bit 字符）

**核心：Δ（delta）方法是基础中的基础：**

```python
# 第 1 步：通过已知明文恢复密钥流
key_stream = [pt[i] ^ ct[i] for i in range(N)]

# 第 2 步：计算 delta 密钥流（真正的关键）
delta_k = [key_stream[i] ^ key_stream[i+1] for i in range(N-1)]
# delta_k = delta_chi XOR delta_psi
# 因为 psi 只有大约 25% 的时间会移动，所以 delta_k 会明显偏向 delta_chi

# 第 3 步：在每个轮子相位上用多数表决恢复 delta_chi
# 假设轮子从位置 1 开始
for bit in range(5):
    P = chi_periods[bit]  # [41, 31, 29, 26, 23]
    delta_chi = []
    for phase in range(P):
        # 收集该轮相位上出现的所有 delta_k 值
        vals = [delta_k_bit[i] for i in range(phase, len(delta_k_bit), P)]
        delta_chi.append(1 if sum(vals) > len(vals)/2 else 0)

# 第 4 步：对 delta_chi 积分，得到 chi（每个轮子有 2 个候选：初始位是 0 或 1）
chi = [start]  # start = 0 或 1
for i in range(P-1):
    chi.append(chi[-1] ^ delta_chi[i])
# 环形一致性检查：chi[0] ^ chi[-1] 应等于 delta_chi[P-1]

# 第 5 步：用密钥流减去 chi，得到 psi 的贡献
# 识别 psi 何时移动：delta_psi = delta_k XOR delta_chi
# 当 5 个 bit 的 delta_psi 全为 0 时，说明 μ37 关闭了（psi 未移动）
# （统计上看，只要 psi 真移动了，5 个 cam 恰好都不变是极少见的）

# 第 6 步：从移动模式确定 μ61（周期 61）
# 当我们观察到 psi 从停转恢复时，对应的 μ61[pos] = 1

# 第 7 步：再交叉推断 μ37（周期 37）
# μ37 只有在 μ61=1 时才前进

# 第 8 步：在 psi 实际移动的那些位置上，根据 delta_psi 恢复 psi 轮
# 寻找周期为 43、47、51、53、59 的重复模式

# 第 9 步：暴力剩余歧义
# 总候选数：2^5（chi）× 2^5（psi）× 61×37（μ 的位置）= 2,313,472
# 非常容易暴力：解密后检查已知明文是否吻合即可
```

**常见误区：**
- 不要把 psi 错当成“周期为 2 的交替器”之类的简化模型，它本身就是周期 43-59 的真实轮组
- 不要把时间花在给 motor 做统计找周期上，直接用结构化的 Δ 方法
- 不要试图用 LFSR 思路分析 stepping 序列，这些步进来自机械轮，而不是 LFSR
- 所谓“步进率”（约 35%）只是 μ37 和 μ61 各自约 50% 为 1 所造成的结果，psi 实际步进约 25%
- 除非有明确证据，否则始终假设使用标准轮周期
- 总暴力空间非常小（不到 300 万），不用过度优化

**ITA2 / Baudot 编码（5-bit）：**
```python
# Lorenz 题目中常用的标准 ITA2 映射
char_to_code = {
    'A': 24, 'B': 19, 'C': 14, 'D': 18, 'E': 16, 'F': 22, 'G': 11,
    'H': 5,  'I': 12, 'J': 26, 'K': 30, 'L': 9,  'M': 7,  'N': 6,
    'O': 3,  'P': 13, 'Q': 29, 'R': 10, 'S': 20, 'T': 1,  'U': 28,
    'V': 15, 'W': 25, 'X': 23, 'Y': 21, 'Z': 17,
    '9': 4,  '5': 27, '8': 31, '3': 8,  '4': 2,  '/': 0,
}
# Code 27 = FIGS 切换，Code 31 = LTRS 切换
```

---

## Book Cipher Brute Force (Nullcon 2026)

**模式（Booking Key）：** 书本密码把口令编码成参考文本中的“向前步数”列表。

**关键点：** 利用字符集约束，起始位置候选会被大幅削减：
```python
def decode_book_cipher(cipher_distances, book_text, valid_chars):
    """暴力起始位置；通过字符集过滤候选。"""
    candidates = []
    for start_key in range(len(book_text)):
        pos = start_key
        password = []
        valid = True
        for dist in cipher_distances:
            pos = (pos + dist) % len(book_text)
            ch = book_text[pos]
            if ch not in valid_chars:
                valid = False
                break
            password.append(ch)
        if valid:
            candidates.append((start_key, ''.join(password)))
    return candidates  # 通常从约 56k 个位置缩到 3-4 个候选
```
