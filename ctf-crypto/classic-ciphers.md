# CTF Crypto - 古典密码

## Table of Contents
- [维吉尼亚密码](#vigenere-cipher)
- [Atbash 密码](#atbash-cipher)
- [Polybius 方阵密码（Qiwi-Infosec 2016）](#polybius-square-cipher-qiwi-infosec-2016)
- [旋转轮替换密码](#substitution-cipher-with-rotating-wheel)
- [Kasiski 密钥长度检验](#kasiski-examination-for-key-length)
- [XOR 变体](#xor-variants)
  - [通过频率分析恢复多字节 XOR 密钥](#multi-byte-xor-key-recovery-via-frequency-analysis)
  - [级联 XOR（首字节暴力）](#cascade-xor-first-byte-brute-force)
  - [带旋转的 XOR：2 的幂位隔离（Pragyan 2026）](#xor-with-rotation-power-of-2-bit-isolation-pragyan-2026)
  - [弱 XOR 校验暴力（Pragyan 2026）](#weak-xor-verification-brute-force-pragyan-2026)
- [带负载均衡后端的确定性 OTP（Pragyan 2026）](#deterministic-otp-with-load-balanced-backends-pragyan-2026)
- [OTP 密钥复用 / Many-Time Pad XOR（BYPASS CTF 2025）](#otp-key-reuse--many-time-pad-xor-bypass-ctf-2025)
- [书本密码](#book-cipher)
- [变长同音替换（ASIS CTF Finals 2013）](#variable-length-homophonic-substitution-asis-ctf-finals-2013)
- [网格置换密码密钥空间缩减（BSidesSF 2026）](#grid-permutation-cipher-keyspace-reduction-bsidessf-2026)
- [基于图像的凯撒位移密码（BSidesSF 2026）](#image-based-caesar-shift-ciphers-bsidessf-2026)
  - [变体 A：垂直条带位移（caesar1）](#variant-a--vertical-strip-shift-caesar1)
  - [变体 B：用 ASCII 编码的水平位移（caesar2）](#variant-b--horizontal-shift-with-ascii-encoding-caesar2)
- [通过文件格式头恢复 XOR 密钥（MetaCTF Flash 2026）](#xor-key-recovery-via-file-format-headers-metactf-flash-2026)
- [3D Vigenere 回文对称密钥恢复（SECCON 2017）](#3d-vigenere-palindrome-symmetry-key-recovery-seccon-2017)
- [Nihilist 密码双 crib 密钥恢复（Security Fest CTF 2018）](#nihilist-cipher-double-crib-key-recovery-security-fest-ctf-2018)
- [16 字节 XOR 分组密码结构反演（h4ckc0n 2018）](#16-byte-xor-block-cipher-structural-reversal-h4ckc0n-2018)
- [旗语照片解码（DefCamp CTF 2018）](#flag-semaphore-photo-decoding-defcamp-ctf-2018)
- [随机填充下的双字节半字节重组（Trend Micro 2018）](#two-byte-nibble-reassembly-with-random-padding-trend-micro-2018)

---

## Vigenere Cipher

**已知明文攻击（CTF 中最常见）：**
```python
def vigenere_decrypt(ciphertext, key):
    result = []
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(c)
    return ''.join(result)

def derive_key(ciphertext, plaintext):
    """根据已知明文推导密钥（例如 flag 格式 CCOI26{）"""
    key = []
    for c, p in zip(ciphertext, plaintext):
        if c.isalpha() and p.isalpha():
            c_val = ord(c.upper()) - ord('A')
            p_val = ord(p.upper()) - ord('A')
            key.append(chr((c_val - p_val) % 26 + ord('A')))
    return ''.join(key)
```

### Kasiski Examination for Key Length

当没有已知明文时，可以用 Kasiski 检验先确定维吉尼亚密钥长度：找到密文里的重复序列，并计算它们间距的 GCD。

```python
from math import gcd
from functools import reduce
from collections import Counter

def kasiski_examination(ciphertext, min_seq=3):
    """寻找重复序列并计算可能的密钥长度。"""
    ct = ''.join(c.upper() for c in ciphertext if c.isalpha())
    distances = []

    # 寻找重复的三元组及其间距
    for seq_len in range(min_seq, 6):
        seen = {}
        for i in range(len(ct) - seq_len):
            seq = ct[i:i+seq_len]
            if seq in seen:
                for prev_pos in seen[seq]:
                    distances.append(i - prev_pos)
                seen[seq].append(i)
            else:
                seen[seq] = [i]

    # 密钥长度往往是这些间距的 GCD
    if distances:
        key_len = reduce(gcd, distances)
        print(f"Likely key length: {key_len}")
        print(f"All distances: {sorted(set(distances))}")
        return key_len
    return None

def frequency_attack(ciphertext, key_length):
    """按每个密钥位置分组做频率分析来破解维吉尼亚。"""
    ct = [c.upper() for c in ciphertext if c.isalpha()]
    english_freq = [0.082,0.015,0.028,0.043,0.127,0.022,0.020,0.061,0.070,
                   0.002,0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,
                   0.063,0.091,0.028,0.010,0.023,0.002,0.020,0.001]
    key = []

    for i in range(key_length):
        group = [ct[j] for j in range(i, len(ct), key_length)]
        # 尝试每个位移，并按英文字符频率打分
        best_shift, best_score = 0, -1
        for shift in range(26):
            decrypted = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in group]
            freq = Counter(decrypted)
            score = sum(freq.get(chr(j+65), 0) / len(group) * english_freq[j]
                       for j in range(26))
            if score > best_score:
                best_score = score
                best_shift = shift
        key.append(chr(best_shift + ord('A')))

    return ''.join(key)
```

**关键点：** 维吉尼亚密文中重复序列出现的间距通常是密钥长度的倍数。把所有这类间距求 GCD，往往就能得到密钥长度。随后每个位置都退化成一个简单的凯撒密码，可单独用频率分析解决。

**当标准密钥推导不奏效时：**
1. 密钥可能并不循环，而是与消息一样长。
2. 密钥可能取自题目主题（人物名、短语等）。
3. 密钥可能带“填充”，例如 `IICCHHAA` 而不是 `ICHA`。
4. 可以从题目主题猜若干明文字词，进一步导出完整密钥。

---

## Atbash Cipher

简单替换：A<->Z，B<->Y，C<->X，依此类推。

```python
def atbash(text):
    return ''.join(
        chr(ord('Z') - (ord(c.upper()) - ord('A'))) if c.isalpha() else c
        for c in text
    )
```

**识别特征：** 题名中有提示（如 “Abashed” 指向 Atbash）、保留空格和标点、严格 1 对 1 替换。

---

## Polybius Square Cipher (Qiwi-Infosec 2016)

5x5 网格密码，每个字母映射为一对两位数字坐标（行、列）。通常 I/J 共用一个格子。

```python
import string

def polybius_decrypt(ciphertext, key="ABCDEFGHIKLMNOPQRSTUVWXYZ"):
    """解密 Polybius 方阵密码（数字对范围 1-5）"""
    grid = {}
    for i, ch in enumerate(key):
        row, col = i // 5 + 1, i % 5 + 1
        grid[(row, col)] = ch

    digits = [int(d) for d in ciphertext if d.isdigit()]
    plaintext = ""
    for i in range(0, len(digits), 2):
        plaintext += grid.get((digits[i], digits[i+1]), '?')
    return plaintext

# 例子："5211251521531412" -> 配对 (5,2)(1,1)(2,5)(1,5)(2,1)(5,3)(1,4)(1,2)
print(polybius_decrypt("5211251521531412"))
```

**关键点：** Polybius 密文往往只包含 1-5 之间的数字。5x5 网格会把 I/J 合并到同一格。即便用了自定义字母表，双数字坐标结构本身不会变。

---

## Substitution Cipher with Rotating Wheel

**模式（Wheel of Mystery）：** 使用物理密码轮的内外字母表。

**自动化求解：** 一般替换密码可先用 [quipqiup.com](https://quipqiup.com/)；它会用词形模式匹配和语言熵来求解，无需预先知道密钥。

**暴力所有旋转：**
```python
outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ{}"
inner = "QNFUVWLEZYXPTKMR}ABJICOSDHG{"  # 已知

for rotation in range(len(outer)):
    rotated = inner[rotation:] + inner[:rotation]
    mapping = {outer[i]: rotated[i] for i in range(len(outer))}
    decrypted = ''.join(mapping.get(c, c) for c in ciphertext)
    if decrypted.startswith("METACTF{"):
        print(decrypted)
```

---

## XOR Variants

### Multi-Byte XOR Key Recovery via Frequency Analysis

**模式：** 密文与一个重复的多字节密钥做 XOR。密钥长度未知。

**步骤 1，确定密钥长度：** 依次尝试各候选长度，按 `位置 mod 密钥长度` 分组，对每组按英文文本频率评分（空格 `0x20` 最常见）。

**步骤 2，恢复每个密钥字节：** 对每个位置暴力 256 个字节值，选择产生最像英文解密结果的那个。

```python
from collections import Counter

def score_english(data):
    """给字节序列打分，衡量其有多像英文。"""
    freq = Counter(data)
    # 英文中最常见的字符通常是空格
    return freq.get(ord(' '), 0) + sum(freq.get(c, 0) for c in range(ord('a'), ord('z')+1))

def find_key_length(ciphertext, max_len=40):
    """通过对每一列做单字节 XOR 评分来测试密钥长度。"""
    best_len, best_score = 1, 0
    for kl in range(1, max_len + 1):
        total = 0
        for col in range(kl):
            group = ciphertext[col::kl]
            best_col_score = max(
                score_english(bytes(b ^ k for b in group))
                for k in range(256)
            )
            total += best_col_score
        if total > best_score:
            best_score = total
            best_len = kl
    return best_len

def recover_key(ciphertext, key_length):
    """通过频率分析恢复每个密钥字节。"""
    key = []
    for col in range(key_length):
        group = ciphertext[col::key_length]
        best_k = max(range(256), key=lambda k: score_english(bytes(b ^ k for b in group)))
        key.append(best_k)
    return bytes(key)

ct = open('encrypted.bin', 'rb').read()
kl = find_key_length(ct)
key = recover_key(ct, kl)
print(f"Key ({kl} bytes): {key}")
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)))
```

**关键点：** 多字节循环 XOR 会拆成 `key_length` 个相互独立的单字节 XOR 问题。英文频率，尤其是空格 `0x20`，通常足以可靠识别正确的密钥字节。密文长度超过约 100 字节时效果最佳。

### Cascade XOR (First-Byte Brute Force)

**模式（Shifty XOR）：** 每个字节都与前一个密文字节做 XOR。

```python
# c[i] = p[i] ^ c[i-1]（或类似级联关系）
# 只需暴力首字节，后面全部确定
for first_byte in range(256):
    flag = [first_byte]
    for i in range(1, len(ct)):
        flag.append(ct[i] ^ flag[i-1])
    if all(32 <= b < 127 for b in flag):
        print(bytes(flag))
```

### XOR with Rotation: Power-of-2 Bit Isolation (Pragyan 2026)

**模式（R0tnoT13）：** 已知 `S XOR ROTR(S, k)` 在多个旋转偏移 k 下的结果，要求恢复 S。

**关键点：** 当所有旋转偏移都是 2 的幂（2、4、8、16、32、64）时，偶数索引位和奇数索引位在所有帧中永远不会混合。这会把 N 位恢复问题降成只需暴力 2 个 bit。

**算法：**
1. 用 `k=2` 这一帧，把 S 的所有 bit 表达成两个未知量（偶数位的 `s_0` 和奇数位的 `s_1`）。
2. 候选状态只剩 4 个，全部尝试并用其余帧验证。
3. 把合法状态与密文 XOR，得到明文。

### Weak XOR Verification Brute Force (Pragyan 2026)

**模式（Dor4_Null5）：** 校验逻辑把所有比较字节 XOR 进一个字节，而不是逐字节比较。

**漏洞：** 任何固定响应都有 `1/256` 的通过概率。如果交互次数充足（如 4919 次），平均约 256 次就能撞成功。

```python
for attempt in range(3000):
    r.sendlineafter(b"prompt: ", b"00" * 8)  # 固定全零响应
    result = r.recvline()
    if b"successful" in result:
        break
```

---

## Deterministic OTP with Load-Balanced Backends (Pragyan 2026)

**模式（DumCows）：** 服务端为每次连接重置确定性的密钥流来加密数据。其后面挂了多个不同密钥流的后端，由负载均衡器分发。

**攻击步骤：**
1. 发送已知明文（例如 18 个字节的 `'A'`），与对应密文 XOR，恢复密钥流。
2. 用该密钥流与目标密文 XOR，解出 secret。
3. **后端匹配：** 只有连到同一个后端时密钥流才一致；需要反复重连直到模式吻合。

```python
def recover_keystream(known, ciphertext):
    return bytes(k ^ c for k, c in zip(known, ciphertext))

def decrypt(keystream, target_ct):
    return bytes(k ^ c for k, c in zip(keystream, target_ct))
```

**关键点：** 只要每个连接内的加密是确定性的，且没有 nonce/IV，已知明文攻击就是平凡的。真正的难点只是匹配到同一个后端。

---

## OTP Key Reuse / Many-Time Pad XOR (BYPASS CTF 2025)

**模式（Once More Unto the Same Wind）：** 两条密文使用了同一个 OTP 密钥。若已知其中一条消息的明文，就能恢复另一条。

**XOR 性质：** `C1 XOR C2 = P1 XOR P2`（密钥抵消）。当一条明文 `P1` 已知时，另一条可直接求得：`P2 = C1 XOR C2 XOR P1`。

```python
from pwn import xor

c1 = bytes.fromhex("7713283f5e9979...")
c2 = bytes.fromhex("740b393f4c8b67...")

# 若其中一条明文已知或可猜（例如填充的 'A'）
known_plaintext = b"A" * len(c1)
flag = xor(xor(c1, c2), known_plaintext)
print(flag)
```

**当明文未知时，使用 crib dragging：**
```python
def crib_drag(c1, c2, crib, max_pos=None):
    """把一个已知单词在两条密文的 XOR 上滑动测试。"""
    xored = xor(c1[:min(len(c1), len(c2))], c2[:min(len(c1), len(c2))])
    for pos in range(len(xored) - len(crib)):
        candidate = xor(xored[pos:pos+len(crib)], crib)
        if all(32 <= b < 127 for b in candidate):
            print(f"pos {pos}: {candidate}")
```

**关键点：** OTP 只有在密钥真的“一次一用”时才安全。重复使用同一密钥会泄露 `P1 XOR P2`，再配合已知明文或 crib dragging 即可利用。

---

## Book Cipher

**模式（Booking Key, Nullcon 2026）：** “向前跳步”式书本密码。对起始位置做暴力，再加字符集过滤，可把约 56k 个候选压到 3-4 个。

完整实现见 [historical.md](historical.md)。

---

## Variable-Length Homophonic Substitution (ASIS CTF Finals 2013)

**模式（Rookie Agent）：** 密文由字母数字字符构成，按 5 个一组分块。单字符频率分布明显不均。进一步做 n-gram 分析会发现：某些重复的多字符组映射到单个明文字母，而且不同明文字母对应的编码组长度可能不同（1-4 个字符）。

**分析流程：**

1. 去掉空白后，统计 1 到 6 阶 n-gram 频率：
```python
from collections import Counter

ct = "6di16ovhtmnzslsxqcjo8fkdmtyrbn..."  # 清洗后的密文
for n in range(1, 7):
    ngrams = [ct[i:i+n] for i in range(len(ct)-n+1)]
    freq = Counter(ngrams).most_common(20)
    print(f"{n}-grams: {freq[:10]}")
```

2. 找出“频率完全一致”的字符组。如果 `8f`、`fk`、`kd` 各自都出现 36 次，再检查 `8fkd` 是否也正好出现 36 次；若是，则它很可能是一个完整替换单元：
```python
# 迭代地把高频固定分组替换成单个符号
substitutions = {
    '8fkd': 'E', '4bg9': 'I', 'lsxq': 'A', 'fmrk': 'B',
    '9gle': 'C', 'mtyr': 'D', 'cjo': 'F', 'htm': 'G',
    # ... 继续补全其余识别出的分组
}
reduced = ct
for pattern, symbol in sorted(substitutions.items(), key=lambda x: -len(x[0])):
    reduced = reduced.replace(pattern, symbol)
```

3. 经过规约后，文本就变成普通的单表替换密码，可用 [quipqiup.com](https://quipqiup.com/) 或常规统计分析继续求解。

4. 如果解出后仍有少数字符不确定，而 flag 又附带了可验证的哈希，则可离线暴力这些歧义字符的排列：
```python
from itertools import permutations
from hashlib import sha256

partial_flag = '3c6a1c371b381c943065864b95ae5546'
ambiguous_chars = '12456789x'  # 映射仍不确定的字符
known_hash = '9f2a579716af14400c9ba1de8682ca52c17b3ed4235ea17ac12ae78ca24876ef'

for p in permutations(ambiguous_chars):
    mapping = dict(zip(ambiguous_chars, p))
    candidate = ''.join(mapping.get(c, c) for c in partial_flag)
    if sha256(('ASIS_' + candidate).encode()).hexdigest() == known_hash:
        print(f"Flag: ASIS_{candidate}")
        break
```

**关键点：** 变长同音替换通过把高频字母编码成更长的密文组来掩盖字母频率。破解时正好反过来：寻找总是一起出现的 n-gram，把它们缩并成单符号，再把问题降成普通单表替换。若 flag 格式提供了哈希校验，最后剩余的少量歧义字符可以直接离线暴力排列。

---

## Grid Permutation Cipher Keyspace Reduction (BSidesSF 2026)

**模式（ghostcrypt）：** 某种建立在 5x5 网格上的替换密码，密钥分别独立置换行和列。行置换与列置换是可交换的，也就是先做所有行交换、再做所有列交换，与顺序无关。这样密钥空间会从看似很大塌缩到 `5! x 5! = 14,400`，暴力非常轻松。

```python
from itertools import permutations

# 5x5 网格替换密码：暴力行置换 + 列置换
grid_size = 5
ciphertext = "..."  # 密文
wordlist = set(open("/usr/share/dict/words").read().split())

for row_perm in permutations(range(grid_size)):
    for col_perm in permutations(range(grid_size)):
        # 对网格应用逆置换
        decrypted = apply_grid_permutation(ciphertext, row_perm, col_perm)
        words = decrypted.split()
        if sum(1 for w in words if w.lower() in wordlist) > len(words) * 0.5:
            print(f"Key: rows={row_perm}, cols={col_perm}")
            print(decrypted)
            break
```

**关键点：** 网格上的行置换与列置换彼此独立、且可交换。总密钥空间是“行置换数 x 列置换数”，也就是 `n!^2`，而不是所有格子整体排列的阶乘。对于 5x5 网格，就是 `120 x 120 = 14,400`，可在毫秒级暴力。

**识别时机：** 题目使用网格型密码、提到“行/列打乱”，或者给出一个看起来像置换矩阵的替换表。凡是“行和列分别打乱”的网格密码，都有这种 `n!^2` 的密钥空间特性。

---

## Image-Based Caesar Shift Ciphers (BSidesSF 2026)

这是把凯撒位移思想施加到二维图像数据上的两个变体：

### Variant A — Vertical Strip Shift (caesar1)

每个垂直像素条向下平移 `(column / strip_width) * multiplier mod height`。其中 `multiplier` 是一个小整数（1-50），因此可暴力。

```python
from PIL import Image
import sys

img = Image.open("shifted.png")
w, h = img.size
pixels = img.load()
strip_width = 10  # 通过肉眼观察得到

for multiplier in range(1, 51):
    out = Image.new("RGB", (w, h))
    out_px = out.load()
    for x in range(w):
        shift = (x // strip_width) * multiplier % h
        for y in range(h):
            out_px[x, (y - shift) % h] = pixels[x, y]
    out.save(f"attempt_{multiplier}.png")
```

### Variant B — Horizontal Shift with ASCII Encoding (caesar2)

每一行都按不同的偏移量做水平位移，而该偏移值本身直接编码 flag 的一个 ASCII 字符。

```python
from PIL import Image

original = Image.open("original.png")
shifted = Image.open("shifted.png")
w, h = original.size

flag = ""
prev_shift = -1
for y in range(h):
    orig_row = [original.getpixel((x, y)) for x in range(w)]
    shift_row = [shifted.getpixel((x, y)) for x in range(w)]
    # 通过比较两行找出位移量
    for offset in range(128):
        if all(orig_row[(x + offset) % w] == shift_row[x] for x in range(min(20, w))):
            if offset != prev_shift:
                flag += chr(offset)
                prev_shift = offset
            break
print(flag)
```

**关键点：** 图像像素的平移，本质上是视觉版本的凯撒密码。只要拿到原图和位移图，对每一行或每一列求偏移量，偏移值往往就直接承载隐藏数据。

**识别时机：** 题目给出一张或两张图片，能看见明显的水平 / 垂直“剪切”伪影。如果原图和位移后的版本同时给出，优先按行或按列比较位移，再检查这些偏移是否可解码为 ASCII。

---

## XOR Key Recovery via File Format Headers (MetaCTF Flash 2026)

**模式（In The Door）：** 文件声称属于某种已知格式（如 PDF、PNG、ZIP），但 `file` 却识别为 `data`。这意味着它很可能被重复 XOR 密钥加密了。通过把加密字节与预期文件头 XOR，可以恢复密钥前缀；再利用文件末尾的已知结构扩展出完整密钥。

```python
# 第 1 步：用预期文件头与前几个字节 XOR，导出密钥开头
encrypted = open('encrypted.pdf', 'rb').read()

# PDF 文件总以 %PDF-1. 开头
expected_header = b'%PDF-1.'
key_start = bytes(a ^ b for a, b in zip(encrypted[:len(expected_header)], expected_header))
print(f"Key prefix: {key_start}")  # 例如 b'h4ck4ll'

# 第 2 步：利用已知尾部结构扩展密钥
# PDF 文件通常以 %%EOF 结束（后面可能跟换行）
# 尝试文件尾部常见模式
pdf_trailers = [b'%%EOF\n', b'%%EOF\r\n', b'%%EOF']
for trailer in pdf_trailers:
    tail = encrypted[-len(trailer):]
    key_tail = bytes(a ^ b for a, b in zip(tail, trailer))
    print(f"Key tail candidate: {key_tail}")

# 第 3 步：一旦知道密钥长度，就把片段拼起来
# 可用的锚点还包括：'startxref'、'trailer'、'endobj'
key = b'h4ck4llth3cryp70'  # 16 字节循环密钥
key_len = len(key)

# 第 4 步：解密整个文件
decrypted = bytes(encrypted[i] ^ key[i % key_len] for i in range(len(encrypted)))
with open('decrypted.pdf', 'wb') as f:
    f.write(decrypted)

# 验证
import subprocess
result = subprocess.run(['file', 'decrypted.pdf'], capture_output=True, text=True)
print(result.stdout)  # 应显示：PDF document
```

**关键点：** 每种文件格式都有固定位置的已知字节序列：开头的魔数、中间的结构标记、结尾的尾签名。只要 XOR 使用的是循环密钥，而且你知道足够多的固定偏移明文，就能完整恢复密钥。若密钥长度为 N，则需要知道模 N 意义下足够多位置的明文字节；这些字节不必连续，但必须知道它们在文件中的偏移。

**常见文件格式的已知锚点：**

| 格式 | 文件头 | 尾部 / 结束标记 |
|--------|--------|----------------|
| PDF | `%PDF-1.` | `%%EOF` |
| PNG | `\x89PNG\r\n\x1a\n` | `IEND\xaeB\x60\x82` |
| ZIP | `PK\x03\x04` | `PK\x05\x06`（EOCD） |
| JPEG | `\xff\xd8\xff\xe0` | `\xff\xd9` |
| ELF | `\x7fELF` | -- |
| GIF | `GIF89a` 或 `GIF87a` | `\x3b`（trailer） |

**识别时机：** 题目给出一个本应属于已知格式的文件（扩展名或题目描述已经暗示），但 `file` 却报告为 `data` 或错误类型。十六进制开头看不到任何熟悉的魔数。这时先把前几个字节与预期文件头 XOR。如果结果像可读 ASCII 字符串或某种循环模式，那通常就是重复 XOR 密钥。

**如何确定密钥长度：** 如果由文件头推出来的密钥片段本身出现周期，或看起来像可读字符串，可以先尝试常见长度（8、16、32）。另一种做法是把文件与其自身按候选长度错位 XOR，若出现大量空字节或低熵输出，通常说明该错位接近真实密钥长度。

**参考：** MetaCTF Flash CTF 2026 "In The Door"

---

## 3D Vigenere Palindrome Symmetry Key Recovery (SECCON 2017)

**模式：** 在 3D Vigenere 中，如果 `k2 = reverse(k1)`，那么加密只依赖于 `k1[i] + k1[key_len-1-i]` 这种对称和。也就是说，真正需要恢复的独立密钥只有一半。

```python
# 加密：ct[i] = table[k1[i%kl]][k2[i%kl]][pt[i]]
# 若 k2 = reverse(k1)，则 ct[i] 只取决于 k1[i%kl] + k1[(kl-1-i)%kl]
# 已知明文前缀足以恢复 kl/2 个和
# 然后只需暴力一半密钥（另一半被这些和约束住）
for c1 in range(len(s)):
    for c2 in range(len(s)):
        if (c1 + c2) % len(s) == known_sum:
            # 测试这对密钥字符
```

**关键点：** 回文式密钥结构（`k2 = reverse(k1)`）把有效密钥空间减半。每个明文位置只受镜像位置上的两个密钥字符之和影响。长度达到 `key_length/2` 的已知明文就足以约束这些和，从而大幅压缩剩余暴力空间。任何“因密钥对称性减少独立变量”的多表替换密码，都可以沿这个思路处理。

**参考：** SECCON CTF 2017

---

## Nihilist Cipher Double-Crib Key Recovery (Security Fest CTF 2018)

**模式（Mission Impossible）：** Nihilist 密码先用 Polybius 方阵把明文字母变成两位坐标，再把密钥数字流加到这些坐标上，得到密文字串。

**关键点：** flag 格式 `midnight{...}` 里有两个已知位置的 `i`。它们对应的 Polybius 坐标必然相同（例如 `24`），所以两处密文字差值会直接泄露两组密钥数字，足以大幅约束加法密钥。再结合“每个合法 Polybius 坐标都必须在 1-5 范围内”，可以极其激进地剪掉错误候选。

**恢复思路：**
```python
# 对每一对密钥数字 (k1, k2) 枚举 1..9：
#   对每个两位密文分组：
#     plain = ((c1 - k1) % 10, (c2 - k2) % 10)
#     如果 plain[0] 或 plain[1] 不在 1..5：直接淘汰
#   否则再做频率测试（最高频字母通常对应 'e'）并反查 Polybius
```
利用 flag 前缀中两个重复字符的约束先把密钥空间切到极少数候选，再基于剩余密文频率暴力 Polybius 方阵。

**参考：** Security Fest CTF 2018，writeup 10210

---

## 16-Byte XOR Block Cipher Structural Reversal (h4ckc0n 2018)

**模式（自定义 XOR 分组密码）：** 加密按 16 字节分组进行，每组再拆成四条 4 字节 lane。每个输出字节都是同组内多个输入字节的 XOR；其中任意一条 lane 都能由另外三条 lane 的 XOR 重建出来。

**利用方法：** 因为每个密文字节都是本组明文字节的线性组合，所以把三条 lane 异或起来就能还原第四条。不需要恢复密钥，只要识别出线性结构，算法本身就是可逆的。

```python
def decrypt(ciphertext):
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        for j in range(4):
            xorsum = 0
            for k in range(4):
                if k != j:
                    for l in range(i + k*4, i + k*4 + 4):
                        xorsum ^= ciphertext[l]
            for m in range(i + j*4, i + j*4 + 4):
                out.append(ciphertext[m] ^ xorsum)
    return bytes(out)
```

**关键点：** 任何“只由 XOR 组成、且没有真正密钥”的固定分组密码，本质上都是线性系统。如果每个输出 bit 都是输入 bit 的线性组合，直接解这个线性依赖即可，不需要暴力或猜密钥。

**参考：** h4ckc0n 2018，writeup 10806

---

## Flag Semaphore Photo Decoding (DefCamp CTF 2018)

**模式：** 题目给出若干张人举旗的照片，每个姿势都对应标准旗语中的一个字母（8 个方向 x 2 条手臂，约 32 个字符）。其中有两个特殊姿势：`J`（切回“字母模式”）和 `#`（切到“数字模式”），解码时需要维护当前模式。

```python
SEMAPHORE = {
    ('NW','N'): 'A', ('NW','NE'): 'B', ('NW','E'): 'C', ('NW','SE'): 'D',
    # ... 完整表可见 Wikipedia
    ('N','NE'):  'J',  # 字母模式切换
    ('NE','SE'): '#',  # 数字模式切换
}
letters = [SEMAPHORE[pose] for pose in pose_sequence]
```

**关键点：** 旗语题通常会伪装成“跳舞的人”或“艺术装置”照片。只要每一帧里恰好有两条伸展的肢体，这就是非常明显的识别信号。

**参考：** DefCamp CTF 2018，Multiple Flags，writeup 12005

---

## Two-Byte Nibble Reassembly with Random Padding (Trend Micro 2018)

**模式：** 自定义编码把每个输入字节拆成高低两个半字节，各自再用一个随机高半字节补齐，因此每个原字节会编码成两个输出字节。恢复时只要取每个输出字节的低半字节，再重新拼接即可。

```python
def decode(src):
    return bytes(((src[2*i] & 0xf) << 4) | (src[2*i+1] & 0xf)
                 for i in range(len(src)//2))
```

**关键点：** 随机填充出现在**高半字节**时，可以完全忽略，因为只有低半字节携带有效信息。若编码后长度正好是原始长度的 2 倍，且高半字节直方图接近均匀分布，就应优先怀疑这一类编码。

**参考：** Trend Micro CTF 2018，J1，writeup 12874
