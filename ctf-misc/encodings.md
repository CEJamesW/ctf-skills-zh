# CTF Misc - 编码与媒体

## 目录
- [常见编码](#common-encodings)
  - [Base64](#base64)
  - [Base32](#base32)
  - [Hex](#hex)
  - [IEEE 754 浮点编码](#ieee-754-floating-point-encoding)
  - [UTF-16 字节序反转 (LACTF 2026)](#utf-16-endianness-reversal-lactf-2026)
  - [BCD（二进制编码十进制）编码 (VuwCTF 2025)](#bcd-binary-coded-decimal-encoding-vuwctf-2025)
  - [多层编码检测 (0xFun 2026)](#multi-layer-encoding-detection-0xfun-2026)
  - [URL 编码](#url-encoding)
  - [ROT13 / Caesar](#rot13--caesar)
  - [Caesar 暴力破解](#caesar-brute-force)
- [二维码 (QR Codes)](#qr-codes)
  - [基本命令](#basic-commands)
  - [二维码结构](#qr-structure)
  - [修复损坏的二维码](#repairing-damaged-qr)
  - [定位图案模板](#finder-pattern-template)
  - [二维码分块重组 (LACTF 2026)](#qr-code-chunk-reassembly-lactf-2026)
  - [通过索引目录的二维码分块重组 (UTCTF 2026)](#qr-code-chunk-reassembly-via-indexed-directories-utctf-2026)
- [多阶段 URL 编码链 (UTCTF 2026)](#multi-stage-url-encoding-chain-utctf-2026)
- [晦涩语言 (Esoteric Languages)](#esoteric-languages)
  - [Whitespace 语言解析器 (BYPASS CTF 2025)](#whitespace-language-parser-bypass-ctf-2025)
  - [自定义 Brainfuck 变体（主题 Esolangs）](#custom-brainfuck-variants-themed-esolangs)
  - [多层晦涩语言链 (Break In 2016)](#multi-layer-esoteric-language-chains-break-in-2016)
- [base65536 CJK Unicode 二进制编码 (IceCTF 2018)](#base65536-cjk-unicode-binary-encoding-icectf-2018)

另见：[encodings-advanced.md](encodings-advanced.md) - Verilog/HDL，Gray 码，二叉树编码，RTF 自定义标签，SMS PDU 解码，多编码解题器，UTF-9，像素二进制编码，十六进制数独 + QR，TOPKEK，MaxiCode

---

## 常见编码

### Base64
```bash
echo "encoded" | base64 -d
# 字符集: A-Za-z0-9+/=
```

### Base32
```bash
echo "OBUWG32DKRDHWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=" | base32 -d
# 字符集: A-Z2-7= （无小写，无 0,1,8,9）
```

### Hex
```bash
echo "68656c6c6f" | xxd -r -p
```

### IEEE 754 浮点编码

当数字以原始 IEEE 754 字节查看时，编码为 ASCII 文本：

```python
import struct

values = [240600592, 212.2753143310547, 2.7884192016691608e+23]

# 每个 float32 打包为 4 个 ASCII 字节
for v in values:
    packed = struct.pack('>f', v)  # 大端单精度浮点
    print(f"{v} -> {packed}")      # b'Meta', b'CTF{', b'fl04'

# 对于双精度（每个值 8 字节）：
# struct.pack('>d', v)
```

**关键点：** 如果题目给出一串数字（整数、小数、科学计数法混合），尝试将每个数字按 IEEE 754 float32 打包（`struct.pack('>f', v)`）——这 4 个字节常常拼出 ASCII 文本。

### UTF-16 字节序反转 (LACTF 2026)

**模式（字节序）：** 文本“变成日文”——UTF-16 字节序不匹配导致的乱码（mojibake）。

**修复：** 反转编码/解码顺序：
```python
# 如果编码为 UTF-16-LE 但解码为 UTF-16-BE：
fixed = mojibake.encode('utf-16-be').decode('utf-16-le')

# 如果编码为 UTF-16-BE 但解码为 UTF-16-LE：
fixed = mojibake.encode('utf-16-le').decode('utf-16-be')
```

**识别：** 文本显示为 CJK 字符（日本/中文），题目提到“翻译”或“字节序”。

### BCD（二进制编码十进制）编码 (VuwCTF 2025)

**模式：** 题目名称暗示比例（如“1.5x” = 1.5:1 字节比例）。每个半字节编码一个十进制数字。

```python
def bcd_decode(data):
    """解码 BCD：每字节包含 2 个十进制数字。"""
    return ''.join(f'{(b>>4)&0xf}{b&0xf}' for b in data)

# 然后将十进制字符串转换为 ASCII
ascii_text = ''.join(chr(int(decoded[i:i+2])) for i in range(0, len(decoded), 2))
```
### 多层编码检测 (0xFun 2026)

**模式（139 步）：** 递归解码，使用 troll flags 作为诱饵。

**关键规则：** 当数据全部是十六进制字符（0-9，a-f）时，优先解码为 **hex**，而不是 base64（base64 也接受这些字符）。

```python
def auto_decode(data):
    while True:
        data = data.strip()
        if data.startswith('REAL_DATA_FOLLOWS:'):
            data = data.split(':', 1)[1]
        # 当模糊时优先十六进制
        if all(c in '0123456789abcdefABCDEF' for c in data) and len(data) % 2 == 0:
            data = bytes.fromhex(data).decode('ascii', errors='replace')
        elif set(data) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='):
            data = base64.b64decode(data).decode('ascii', errors='replace')
        else:
            break
    return data
```

**忽略 troll flags** — 检查“keep decoding”或“REAL_DATA_FOLLOWS:”标记。

### URL 编码
```python
import urllib.parse
urllib.parse.unquote('hello%20world')
```

### ROT13 / 凯撒密码
```bash
echo "uryyb" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
```

**ROT13 模式：** `gur` = “the”，`synt` = “flag”

### 凯撒密码暴力破解
```python
text = "Khoor Zruog"
for shift in range(26):
    decoded = ''.join(
        chr((ord(c) - 65 - shift) % 26 + 65) if c.isupper()
        else chr((ord(c) - 97 - shift) % 26 + 97) if c.islower()
        else c for c in text)
    print(f"{shift:2d}: {decoded}")
```

---

## QR 码

### 基本命令
```bash
zbarimg qrcode.png           # 解码
zbarimg -S*.enable qr.png    # 所有条码类型
qrencode -o out.png "data"   # 编码
```

### QR 结构

**定位图案（3 个角）：** 左上、右上、左下各 7x7 模块

**版本公式：** 每边 `(version * 4) + 17` 个模块

### 修复损坏的 QR

```python
from PIL import Image
import numpy as np

img = Image.open('damaged_qr.png')
arr = np.array(img)

# 转为二值
gray = np.mean(arr, axis=2)
binary = (gray < 128).astype(int)

# 找 QR 边界
rows = np.any(binary, axis=1)
cols = np.any(binary, axis=0)
rmin, rmax = np.where(rows)[0][[0, -1]]
cmin, cmax = np.where(cols)[0][[0, -1]]

# 检查定位图案
qr = binary[rmin:rmax+1, cmin:cmax+1]
print("左上角:", qr[0:7, 0:7].sum())  # 应该约为 25
```

### 定位图案模板
```python
finder_pattern = [
    [1,1,1,1,1,1,1],
    [1,0,0,0,0,0,1],
    [1,0,1,1,1,0,1],
    [1,0,1,1,1,0,1],
    [1,0,1,1,1,0,1],
    [1,0,0,0,0,0,1],
    [1,1,1,1,1,1,1],
]
```

### QR 码块重组（LACTF 2026）

**模式（纠错）：** QR 码被拆分成网格块（例如 5x5 个 9x9 像素块），并被打乱顺序。

**解决思路：**
1. **固定已知块：** 利用结构模式——定位图案（3 个角）、时序图案、对齐图案——放置约 50% 的块
2. **提取码字约束：** 对每个候选有效载荷长度，使用 QR 规范识别编码中不变的像素
3. **回溯搜索：** 在像素约束下分配剩余块，直到 QR 成功解码

**工具：** `segno`（Python QR 库）、`zbarimg` 用于解码。

### 通过索引目录重组 QR 码（UTCTF 2026）

**模式（QRecreate）：** QR 码拆分成编号块，存储在不同目录中。目录名以 base64 编码块索引（例如 `MDAx` → `001` → 索引 1）。

**解决思路：**
1. 将每个目录名从 base64 解码得到数字索引
2. 按解码索引排序块
3. 按网格排列（例如 100 块 → 10x10），拼接成一张图像
4. 解码重建的 QR 码

```python
import os, base64, math
from PIL import Image

# 1. 解码目录名获取索引
chunks = []
for dirname in os.listdir('chunks/'):
    index = int(base64.b64decode(dirname).decode())
    tile = Image.open(f'chunks/{dirname}/tile.png')
    chunks.append((index, tile))

# 2. 按索引排序并排列成网格
chunks.sort(key=lambda x: x[0])
n = len(chunks)
side = int(math.isqrt(n))
tile_w, tile_h = chunks[0][1].size

canvas = Image.new("RGB", (side * tile_w, side * tile_h), (255, 255, 255))
for i, (_, tile) in enumerate(chunks):
    r, c = divmod(i, side)
    canvas.paste(tile, (c * tile_w, r * tile_h))

canvas.save('reconstructed_qr.png')
# 3. 使用 zbarimg 或 pyzbar 解码
```

**关键洞察：** 与 LACTF 变体（打乱块需结构分析）不同，索引块只需排序。挑战在于识别目录名是 base64 编码的索引。目录名看似随机字符串时，尝试用 `base64 -d` 解码。 

---
## Multi-Stage URL Encoding Chain (UTCTF 2026)

**模式（线索）：** Flag 隐藏在一连串不同编码的 URL 之后。沿着线索追踪外部资源（GitHub Gists、Pastebin 等），每跳解码一次。

**每跳常见编码层：**
1. **Base64** → 指向下一个资源的 URL
2. **Hex** → 指向下一个资源的 URL（例如，`68747470733a2f2f...` = `https://...`）
3. **ROT13** → 最终 flag

**解码流程：**
```python
import base64, codecs

# 第1跳：Base64
hop1 = "aHR0cHM6Ly9naXN0Lmdp..."
url2 = base64.b64decode(hop1).decode()

# 第2跳：Hex 编码的 URL
hop2 = "68747470733a2f2f..."
url3 = bytes.fromhex(hop2).decode()

# 第3跳：ROT13 编码的 flag
hop3 = "hgsynt{...}"
flag = codecs.decode(hop3, 'rot_13')
```

**关键洞察：** 每个资源中包含关于下一步编码的提示（例如，“Three letters follow”暗示3字符编码如 hex）。注意周围文本（诗歌、注释、文件名）中的上下文线索，指示编码类型。

**检测方法：** 题目提及“trail”、“breadcrumbs”、“follow”或“scavenger hunt”。第一个资源包含看似编码数据而非直接 flag。

---

## Esoteric Languages

| 语言 | 模式 |
|----------|---------|
| Brainfuck | `++++++++++[>+++++++>` |
| Whitespace | 仅包含空格、制表符、换行符（或 S/T/L 替代） |
| Ook! | `Ook. Ook? Ook!` |
| Malbolge | 极度混淆 |
| Piet | 基于图像 |

### Whitespace Language Parser (BYPASS CTF 2025)

**模式（诅咒卷轴的低语）：** 文件仅包含 S（空格）、T（制表符）、L（换行符）字符——或可见替代符。基于栈的虚拟机（VM），支持 PUSH、OUTPUT 和 EXIT 指令。

**指令集（IMP = 指令修改参数）：**
| 指令 | 编码 | 操作 |
|-------------|----------|--------|
| PUSH | `S S` + 符号 + 二进制 + `L` | 将数字压入栈（S=0，T=1，L=终止符） |
| OUTPUT CHAR | `T L S S` | 弹出栈顶，作为 ASCII 字符输出 |
| EXIT | `L L L` | 程序终止 |

```python
def solve_whitespace(content):
    # 转换为 S/T/L 令牌（处理原始空白和可见字符）
    if any(c in content for c in 'STL'):
        code = [c for c in content if c in 'STL']
    else:
        code = [{'\\s': 'S', '\\t': 'T', '\\n': 'L'}.get(c, '') for c in content]
        code = [c for c in code if c]

    stack, output, i = [], "", 0

    while i < len(code):
        if code[i:i+2] == ['S', 'S']:  # PUSH
            i += 2
            sign = 1 if code[i] == 'S' else -1
            i += 1
            val = 0
            while i < len(code) and code[i] != 'L':
                val = (val << 1) + (1 if code[i] == 'T' else 0)
                i += 1
            i += 1  # 跳过终止符 L
            stack.append(sign * val)
        elif code[i:i+4] == ['T', 'L', 'S', 'S']:  # OUTPUT CHAR
            i += 4
            if stack:
                output += chr(stack.pop())
        elif code[i:i+3] == ['L', 'L', 'L']:  # EXIT
            break
        else:
            i += 1

    return output
```

**识别方法：** 文件仅含空白字符，或题目提及“invisible code”、“blank page”，或使用 S/T/L 替代。可尝试 [Whitespace 在线解释器](https://vii5ard.github.io/whitespace/) 快速测试。

---

### Custom Brainfuck Variants (Themed Esolangs)

**模式：** 文件包含重复的主题词（如“arch”、“linux”、“btw”）作为 Brainfuck 操作的替代。常见于 Easy/Misc CTF 题目。

**识别：**
- 文件为 ASCII 文本，行很长，重复词多
- 词汇量小（5-8 个唯一词）
- 有一个词作为行终止符（映射为 `.` 输出）
- 两个词用于增减（其中一个在行中重复多次）
- 词通常与某个梗或主题相关（如“I use Arch Linux BTW”）

**标准 Brainfuck 操作映射：**
| 操作 | 含义 | 典型模式 |
|----|---------|-----------------|
| `+` | 增加单元格值 | 最频繁词（定义数值） |
| `-` | 减少单元格值 | 第二频繁词 |
| `>` | 指针右移 | 短词，单独出现或与 `.` 一起 |
| `<` | 指针左移 | 与 `>` 配对词 |
| `[` | 循环开始 | 出现在带有对应 `]` 的行首 |
| `]` | 循环结束 | 出现在与 `[` 同行末尾 |
| `.` | 输出字符 | 行终止词 |

**解题思路：**
```python
from collections import Counter
words = content.split()
freq = Counter(words)
# 最频繁 = 可能是 + 或 -，行终止词 = 可能是 .

# 映射词到 BF 操作，翻译后用标准 BF 解释器执行
mapping = {'arch': '+', 'linux': '-', 'i': '>', 'use': '<',
           'the': '[', 'way': ']', 'btw': '.'}
bf = ''.join(mapping.get(w, '') for w in words)
# 然后用标准 Brainfuck 解释器执行 bf 字符串
```

**真实示例（0xL4ugh CTF - "iUseArchBTW"）：** `.archbtw` 扩展名，主题为“I use Arch Linux BTW”梗。

**提示：** 若输出非 ASCII，尝试交换 `+`/`-` 或 `>`/`<`。确认输出以已知 flag 格式开头。

---
### 多层冷门语言链（2016年破解）

挑战可能会堆叠多个冷门语言，需要顺序解释：

1. **Piet：** 使用彩色像素块的视觉编程语言。将 PNG 图片作为代码执行：
```bash
npiet challenge.png         # npiet 解释器
# 或：java -jar PietDev.jar challenge.png
```

2. **Malbolge：** 极其难懂的冷门语言。解码上一层的输出：
```bash
# Piet 输出 → base64 解码 → Malbolge 源码
echo "piet_output" | base64 -d > program.mal
malbolge program.mal        # 或使用在线解释器
```

常见冷门语言链：Piet → base64 → Malbolge，Brainfuck → Ook → Whitespace，JSFuck → 标准 JS。

**关键洞察：** 当 PNG 文件没有明显的视觉隐写时，尝试将其作为 Piet 代码解释。使用 `file` + 视觉检查识别第一层，然后顺序解码。

---

## base65536 CJK Unicode 二进制编码（IceCTF 2018）

**模式：** 看似一片中文字符（CJK 统一表意文字）的乱码，实际上是 **base65536** 编码：每个字符携带两个字节数据，将 0x0000..0xFFFF 映射到挑选的 65,536 个 Unicode 码点子集。通过 `file` 报告“Unicode text, UTF-8”且大部分为 CJK 码点来检测；用 `base65536` npm 包或 Python 移植版解码。

```bash
# Node.js / npm 路径
npm install -g base65536
echo -n "宝䀈䀋..." | base65536 --decode > out.bin

# Python 移植版
pip install base65536
python3 - <<'PY'
import base65536, sys
sys.stdout.buffer.write(base65536.decode(open("blob.txt").read()))
PY > out.bin

file out.bin
# 常见结果：“Zip archive data” 或 “ELF 64-bit”
```

**关键洞察：** base64 是 3 字节 → 4 字符；base65536 是 2 字节 → 1 个 *Unicode 码点*，且码点以 1–4 个 UTF-8 字节呈现，编码流在磁盘上实际上 *膨胀* 约 2 倍 —— 但视觉上看起来紧凑，这就是 CTF 的技巧。任何缺乏基本多语言平面变异且以 CJK、韩文或藏文为主的 Unicode 墙都是候选。还可检查 base1024（BMP）、base2048、base4096 和 base32768 等相关技巧。

**参考：** IceCTF 2018 — Rabbit Hole，writeup 11421
