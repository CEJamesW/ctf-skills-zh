# CTF Forensics - Steganography

非图像隐写技术（PDF、SVG、终端、文本、压缩、电子表格）以及通用图像隐写模式（PNG 结构、文件叠加、GIF、自立体图、交错）。关于图像特定隐写（JPEG DQT/F5/slack，BMP 位平面，PNG 调色板，像素置换，边缘匹配），请参见 [stego-image.md](stego-image.md)。关于高级技术（FFT、SSTV、音频、视频、JPEG XL），请参见 [stego-advanced.md](stego-advanced.md) 和 [stego-advanced-2.md](stego-advanced-2.md)。

## 目录
- [快速工具](#quick-tools)
- [二进制边框隐写术](#binary-border-steganography)
- [多层 PDF 隐写术（Pragyan 2026）](#multi-layer-pdf-steganography-pragyan-2026)
- [高级 PDF 隐写术（Nullcon 2026 rdctd 系列）](#advanced-pdf-steganography-nullcon-2026-rdctd-series)
- [SVG 动画关键帧隐写术（UTCTF 2024）](#svg-animation-keyframe-steganography-utctf-2024)
- [PNG 块重排序（0xFun 2026）](#png-chunk-reordering-0xfun-2026)
- [文件格式叠加（0xFun 2026）](#file-format-overlays-0xfun-2026)
- [嵌套 PNG 及迭代 XOR 密钥（VuwCTF 2025）](#nested-png-with-iterating-xor-keys-vuwctf-2025)
- [GIF 帧差分 + 摩尔斯码（BaltCTF 2013）](#gif-frame-differential--morse-code-baltctf-2013)
- [GZSteg + Spammimic 文本隐写（VolgaCTF 2013）](#gzsteg--spammimic-text-steganography-volgactf-2013)
- [电子表格频率分析二进制恢复（Sharif CTF 2016）](#spreadsheet-frequency-analysis-binary-recovery-sharif-ctf-2016)
- [Kitty 终端图形协议解码（BSidesSF 2026）](#kitty-terminal-graphics-protocol-decoding-bsidessf-2026)
- [终端艺术中的 ANSI 转义序列隐写（BSidesSF 2026）](#ansi-escape-sequence-steganography-in-terminal-art-bsidessf-2026)
- [自立体图 / 魔眼图解（BSidesSF 2026）](#autostereogram--magic-eye-solving-bsidessf-2026)
- [双层字节+行交错（BSidesSF 2026）](#two-layer-byteline-interleaving-bsidessf-2026)
- [渐进式 PNG 分层 XOR 解密（OpenCTF 2016）](#progressive-png-layered-xor-decryption-openctf-2016)
- [多流视频容器隐写（BSidesSF 2026）](#multi-stream-video-container-steganography-bsidessf-2026)
- [APNG（动画 PNG）帧提取（IceCTF 2016）](#apng-animated-png-frame-extraction-icectf-2016)
- [PNG 高度/CRC 操作隐藏内容（H4ckIT CTF 2016）](#png-heightcrc-manipulation-for-hidden-content-h4ckit-ctf-2016)
- [视频中曲面玻璃反射的二维码重建（PlaidCTF 2018）](#qr-code-reconstruction-from-curved-glass-reflection-in-video-plaidctf-2018)
- [GIF 调色板操作重建二维码（3DSCTF 2017）](#gif-palette-manipulation-for-qr-code-reconstruction-3dsctf-2017)
- [Angecryption：AES-CBC 加密一个有效文件为另一个（34C3 CTF 2017）](#angecryption-aes-cbc-encrypting-one-valid-file-into-another-34c3-ctf-2017)
- [SVG 微坐标隐写（SharifCTF 8）](#svg-micro-coordinate-steganography-sharifctf-8)

---

## 快速工具

```bash
steghide extract -sf image.jpg
zsteg image.png              # PNG/BMP 分析
stegsolve                    # 可视化分析

# Steghide 暴力破解（0xFun 2026）
stegseek image.jpg rockyou.txt  # 比 stegcracker 更快
# 常见弱密码短语："simple", "password", "123456"
```

---

## 二进制边框隐写术

**模式（Framer, PascalCTF 2026）：** 消息编码为图像周围 1 像素边框的黑白像素。

```python
from PIL import Image

img = Image.open('output.jpg')
w, h = img.size
bits = []

# 顺时针读取边框：上 → 右 → 下（反向）→ 左（反向）
for x in range(w): bits.append(0 if sum(img.getpixel((x, 0))[:3]) < 384 else 1)
for y in range(1, h): bits.append(0 if sum(img.getpixel((w-1, y))[:3]) < 384 else 1)
for x in range(w-2, -1, -1): bits.append(0 if sum(img.getpixel((x, h-1))[:3]) < 384 else 1)
for y in range(h-2, 0, -1): bits.append(0 if sum(img.getpixel((0, y))[:3]) < 384 else 1)

# 将比特转换为 ASCII
msg = ''.join(chr(int(''.join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits)-7, 8))
```

---

## 多层 PDF 隐写术（Pragyan 2026）

**模式（epstein 文件）：** 旗标隐藏在 PDF 的多个层中。

**层检查清单：**
1. `strings file.pdf | grep -i hidden` -- PDF 对象中的隐藏注释
2. 提取十六进制字符串，尝试与主题相关关键词进行 XOR
3. 检查 `%%EOF` 标记之后的字节 -- 可能包含 GPG/加密数据
4. 尝试 ROT18（字母 ROT13 + 数字 ROT5）作为最终解码层

```bash
# 提取 EOF 后数据
python3 -c "
data = open('file.pdf','rb').read()
eof = data.rfind(b'%%EOF')
print(data[eof+5:].hex())
"
```

---

## 高级 PDF 隐写术（Nullcon 2026 rdctd 系列）

单个 PDF 中的六种不同隐藏技术：

**1. 隐形文本分隔符：** 下划线渲染为不可见的线段。用 `pdftotext -layout` 提取并将空白归一化为下划线。

**2. 带转义大括号的 URI 注释：** 链接注释中 URI 包含带 `\{` 和 `\}` 转义的旗标：
```python
import pikepdf
pdf = pikepdf.Pdf.open(pdf_path)
for page in pdf.pages:
    for annot in (page.get("/Annots") or []):
        obj = annot.get_object()
        if obj.get("/Subtype") == pikepdf.Name("/Link"):
            uri = str(obj.get("/A").get("/URI")).replace(r"\{", "{").replace(r"\}", "}")
            # 检查旗标模式
```

**3. 模糊/涂黑图像与 Wiener 反卷积：**
```python
from skimage.restoration import wiener
import numpy as np

def gaussian_psf(sigma):
    k = int(sigma * 6 + 1) | 1
    ax = np.arange(-(k//2), k//2 + 1, dtype=np.float32)
    xx, yy = np.meshgrid(ax, ax)
    psf = np.exp(-(xx**2 + yy**2) / (2 * sigma * sigma))
    return psf / psf.sum()

img_arr = np.asarray(img.convert("L")).astype(np.float32) / 255.0
deconv = wiener(img_arr, gaussian_psf(3.0), balance=0.003, clip=False)
```

**4. 矢量矩形二维码：** 数百个微小填充矩形（如 1.718x1.718 单位）组成二维码。解析 PDF 内容流中的 `re` 操作符，提取中心点，渲染为网格，用 `zbarimg` 解码。

**5. 压缩对象流：** 使用 `mutool clean -d -c -m input.pdf output.pdf` 解压所有流，然后用 `strings` 搜索。

**6. 文档元数据：** 检查 Producer、Author、Keywords 字段：`pdfinfo doc.pdf` 或 `exiftool doc.pdf`。

**官方 writeup 细节（Nullcon 2026 rdctd 1-6）：**
- **rdctd 1：** 旗标以明文形式可见（第 3.4 节）
- **rdctd 2：** 旗标在带转义大括号的超链接 URI 中 (`\{`, `\}`)
- **rdctd 3：** 蓝色通道的 LSB 隐写，**第 5 位平面**（非第 0 位！）。用 `zsteg` 检查所有位平面：`zsteg -a extracted.ppm | grep ENO`
- **rdctd 4：** 黑色涂黑框下隐藏二维码。用 Master PDF Editor 移除框，扫描二维码
- **rdctd 5：** 旗标在 FlateDecode 压缩流中（`strings` 不可见）：
  ```python
  import re, zlib
  pdf = open('file.pdf', 'rb').read()
  for s in re.findall(b'stream[\r\n]+(.*?)[\r\n]+endstream', pdf, re.S):
      try:
          dec = zlib.decompress(s)
          if b'ENO{' in dec: print(dec)
      except: pass
  ```
- **rdctd 6：** 旗标在 `/Producer` 元数据字段中

**全面的 PDF 旗标搜索清单：**
1. `strings -a file.pdf | grep -o 'FLAG_FORMAT{[^}]*}'`
2. `exiftool file.pdf`（所有元数据字段）
3. `pdfimages -all file.pdf img` + `zsteg -a img-*.ppm`
4. 用 PDF 编辑器打开，检查覆盖/涂黑框隐藏内容
5. 解压 FlateDecode 流并搜索
6. 解析链接注释中带转义字符的 URI
7. `mutool clean -d file.pdf clean.pdf && strings clean.pdf`

---
## SVG 动画关键帧隐写术 (UTCTF 2024)

**模式（疯狂检测）：** SVG favicon 包含交替填充颜色的动画关键帧。

**编码：** `#FFFF` = 1，`#FFF6` = 0。时间间隔（约0.314秒或3倍0.314秒）编码摩尔斯码的点和划。

**检测：** 查找带有 `<animate>` 标签、`keyTimes`/`values` 属性的 SVG 文件。检查 favicon.svg 和其他矢量资源。两值交替模式编码二进制或摩尔斯码。

---

## APNG（动画 PNG）帧提取 (IceCTF 2016)

APNG 文件在标准 PNG 容器内包含多帧。使用 `tweakpng` 或 `apngdis` 等工具提取单独帧，帧中可能包含隐藏数据。

```bash
# 检查 PNG 是否为 APNG（包含 acTL 块）
python3 -c "
import struct
with open('image.png', 'rb') as f:
    data = f.read()
    if b'acTL' in data:
        print('检测到 APNG！')
        idx = data.index(b'acTL')
        num_frames = struct.unpack('>I', data[idx+4:idx+8])[0]
        print(f'帧数: {num_frames}')
"

# 使用 apngdis 提取帧
apngdis image.apng  # 生成 frame_01.png, frame_02.png, ...

# 备选：使用 PHP 或 Python 库
# pip install apng
python3 -c "
from apng import APNG
im = APNG.open('image.apng')
for i, (png, control) in enumerate(im.frames):
    png.save(f'frame_{i:02d}.png')
"
```

**关键点：** 普通 PNG 查看器只显示 APNG 的第一帧。隐藏数据可能存在于后续任意帧。`acTL` 块标识 APNG 格式；`fcTL`/`fdAT` 块包含额外帧数据。

---

## PNG 高度/CRC 操作隐藏内容 (H4ckIT CTF 2016)

PNG 图像通过错误的 IHDR 尺寸隐藏可视区域下方的内容。通过匹配 IHDR CRC 进行高度暴力破解。

```python
import struct, zlib

def fix_png_height(filename):
    with open(filename, 'rb') as f:
        data = bytearray(f.read())

    # IHDR 块从偏移 8 开始（PNG 签名后8字节）
    # IHDR 布局：宽度(4) 高度(4) 位深(1) 色彩类型(1) ...
    ihdr_start = 8 + 4  # 跳过签名 + 块长度
    ihdr_data = data[ihdr_start:ihdr_start + 17]  # "IHDR" + 13 字节
    stored_crc = struct.unpack('>I', data[ihdr_start + 17:ihdr_start + 21])[0]

    width = struct.unpack('>I', ihdr_data[4:8])[0]

    # 暴力破解正确高度
    for h in range(1, 4096):
        test_ihdr = ihdr_data[:8] + struct.pack('>I', h) + ihdr_data[12:]
        if zlib.crc32(test_ihdr) & 0xffffffff == stored_crc:
            print(f"正确高度: {h} (原高度: {struct.unpack('>I', ihdr_data[8:12])[0]})")
            data[ihdr_start + 8:ihdr_start + 12] = struct.pack('>I', h)
            with open('fixed_' + filename, 'wb') as f:
                f.write(data)
            return h

    # 若无 CRC 匹配，可能需先设置高度再修正 CRC
    # 手动方法：设置更大高度，修正 CRC
    return None
```

**关键点：** PNG 在 IHDR 块中存储图像尺寸及 CRC。若高度被缩小，隐藏数据仍存在 IDAT 块中。通过对比存储的 CRC 暴力破解高度可得正确尺寸。若 CRC 也被修改，尝试增大高度并重新计算 CRC。

---

## PNG 块重排序 (0xFun 2026)

**模式（Spectrum）：** 无效 PNG 文件块顺序混乱。

**修复：** 重新排序为：`签名 + IHDR + （辅助块） + （所有 IDAT 按顺序） + IEND`。

```python
import struct

with open('broken.png', 'rb') as f:
    data = f.read()

sig = data[:8]
chunks = []
pos = 8
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8]
    chunk_data = data[pos+8:pos+8+length]
    crc = data[pos+8+length:pos+12+length]
    chunks.append((chunk_type, length, chunk_data, crc))
    pos += 12 + length

# 排序：IHDR 首，IEND 末，IDAT 保持原序
ihdr = [c for c in chunks if c[0] == b'IHDR']
idat = [c for c in chunks if c[0] == b'IDAT']
iend = [c for c in chunks if c[0] == b'IEND']
other = [c for c in chunks if c[0] not in (b'IHDR', b'IDAT', b'IEND')]

with open('fixed.png', 'wb') as f:
    f.write(sig)
    for typ, length, data, crc in ihdr + other + idat + iend:
        f.write(struct.pack('>I', length) + typ + data + crc)
```

---

## 文件格式叠加 (0xFun 2026)

**模式（Pixel Rehab）：** PNG IEND 后附加归档文件，但魔数字节被覆盖为 PNG 签名。

**检测：** 检查 IEND 后的字节是否有附加数据。对比魔数字节与已知格式。

```python
# 查找 IEND，检查后续内容
data = open('image.png', 'rb').read()
iend_pos = data.find(b'IEND') + 8  # IEND + CRC 后
trailer = data[iend_pos:]
# 若前4字节为 PNG 签名，替换为 7z 魔数
if trailer[:4] == b'\x89PNG':
    trailer = b'\x37\x7a\xbc\xaf\x27\x1c' + trailer[6:]
    open('hidden.7z', 'wb').write(trailer)
```

---

## 迭代 XOR 密钥的嵌套 PNG (VuwCTF 2025)

**模式（Matroiska）：** 每层 PNG 使用递增密钥 XOR 加密（如 "layer2", "layer3" 等）。

**识别：** 通过 Matryoshka/嵌套提示，尝试递增密钥模式递归提取。

---

## GIF 帧差分 + 摩尔斯码 (BaltCTF 2013)

**模式：** 动画 GIF 中隐藏点仅在帧与原始帧对比时可见。点编码摩尔斯码。

```bash
# 提取动画 GIF 帧
convert animated.gif frame_%03d.gif

# 使用 ImageMagick 比较每帧与基准帧
for i in $(seq 1 100); do
    compare -fuzz 10% -compose src stego_$i.gif original_$i.gif diff_$i.gif
done

# 检查差异图像 — 点出现在特定位置
# 将点模式映射为摩尔斯码：小点=点， 大点=划
```

**关键点：** `compare -fuzz 10%` 揭示肉眼难见的单像素改动。差异图显示孤立点，其时序/间隔编码摩尔斯码。解码点→划→字母→flag。

---

## GZSteg + Spammimic 文本隐写 (VolgaCTF 2013)

**模式：** 数据隐藏于 gzip 压缩元数据，通过 spammimic.com 解码。

1. 对 gzip 1.2.4 源码应用 GZSteg 补丁，编译，使用 `gzip --s` 标志提取
2. 提取文本类似垃圾邮件 — 提交至 [spammimic.com](https://www.spammimic.com/) 解码器
3. 解码输出即为 flag

**关键点：** GZSteg 利用 gzip DEFLATE 压缩格式的冗余嵌入隐蔽数据。提取的负载通常使用第二层隐写（spammimic 将数据编码为看似无害的垃圾邮件文本）。注意 `.gz` 文件大小异常。

---
## Spreadsheet Frequency Analysis Binary Recovery (Sharif CTF 2016)

当电子表格单元格包含频率不同的数字时，频率排名可能编码二进制数据：

1. **统计每个唯一值的出现次数**
2. **按频率排序**，创建映射：值 -> 频率排名（0-255）
3. **用频率排名替换每个单元格**，以恢复原始字节

```python
from collections import Counter

# 统计每个值的频率
freq = Counter(all_cell_values)

# 创建映射：值 -> 频率排序列表中的索引
sorted_vals = sorted(freq.keys(), key=lambda x: freq[x])
mapping = {v: i for i, v in enumerate(sorted_vals)}

# 应用映射恢复二进制
binary = bytes(mapping[v] for v in all_cell_values)
# 结果通常是 ELF 二进制或图像
```

**关键洞察：** 256 个唯一值暗示字节级编码。映射输出的频率分布应类似典型二进制文件的统计特征。

---

## Kitty Terminal Graphics Protocol Decoding (BSidesSF 2026)

**模式（kitty）：** 文件包含 Kitty 终端图形协议转义序列（`ESC_G`），嵌入了以 base64 编码分块的 zlib 压缩 RGB 图像数据。

**协议格式：**
```text
\x1b_Ga=T,q=2,f=24,o=z,m=1,s=WIDTH,v=HEIGHT;BASE64DATA\x1b\\
```

**头字段：**
- `a=T` — 动作：传输
- `q=2` — 静默模式（抑制响应）
- `f=24` — 格式：24 位 RGB
- `o=z` — 压缩：zlib
- `m=1` — 后续还有分块；`m=0` — 最后一个分块
- `s=WIDTH,v=HEIGHT` — 图像尺寸（仅出现在第一个分块）

**解码流程：**
```python
import re
import base64
import zlib
from PIL import Image

# 读取原始文件
data = open('kitty_output.bin', 'rb').read()

# 从转义序列中提取所有 base64 负载
# 模式：\x1b_G...;BASE64\x1b\\
chunks = re.findall(rb'\x1b_G([^;]*);([^\x1b]*)\x1b\\\\', data)

# 从第一个分块头部解析尺寸
first_header = chunks[0][0].decode()
width = int(re.search(r's=(\d+)', first_header).group(1))
height = int(re.search(r'v=(\d+)', first_header).group(1))

# 拼接所有 base64 负载
b64_data = b''.join(chunk[1] for chunk in chunks)
compressed = base64.b64decode(b64_data)
raw_rgb = zlib.decompress(compressed)

# 重建图像
img = Image.frombytes('RGB', (width, height), raw_rgb)
img.save('recovered.png')
```

**关键洞察：** Kitty 图形协议是现代终端图像显示机制。数据在非 Kitty 终端查看时不可见，但可从原始转义序列中解码。多分块消息（`m=1` 后续分块）必须在 base64 解码前拼接。

**检测方法：** 二进制文件包含 `\x1b_G` 序列。`strings` 输出显示夹杂转义码的类似 base64 数据。挑战中提及“kitty”、“terminal graphics”或“meow”。

**参考资料：** BSidesSF 2026 “kitty”

---

## ANSI Escape Sequence Steganography in Terminal Art (BSidesSF 2026)

**模式（roar）：** 旗标文本夹杂在 ANSI 颜色转义码和 Unicode 盲文字符中，形成终端艺术。渲染时艺术正常显示，旗标字符不可见（零宽或与背景同色）。但通过剥离所有转义序列和非 ASCII 字符可提取旗标。

**提取方法：**
```python
import re

data = open('art.txt', 'rb').read().decode('utf-8', errors='replace')

# 去除 ANSI 转义序列
clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', data)

# 仅提取可打印 ASCII（旗标字符）
flag_chars = [c for c in clean if 32 <= ord(c) <= 126 and c not in ' \t\n']

# 或：过滤盲文 Unicode 区块（U+2800-U+28FF）和其他非 ASCII
flag_chars = [c for c in clean if ord(c) < 128 and c.isprintable() and c != ' ']

print(''.join(flag_chars))
```

**替代方法 — 与渲染输出做差异对比：**
```bash
# 带 ANSI 码渲染，捕获可见文本
cat art.txt | col -b > rendered.txt
# 比较原始与渲染文件，找出隐藏字符
```

**关键洞察：** ANSI 转义序列控制终端颜色、光标位置和文本属性。夹杂在转义码间的旗标字符技术上存在于文件中，但渲染时不可见，因为它们要么：(a) 与背景同色，(b) 后跟光标回退序列，或 (c) 被后续字符覆盖。直接提取原始字节绕过所有渲染技巧。

**检测方法：** 文件中大量 `\x1b[` 序列（ANSI 码）、Unicode 盲文字符（U+2800-U+28FF），且文件大小远大于可见内容。挑战中提及“terminal”、“art”、“ANSI”或展示 ASCII/Unicode 艺术。

**参考资料：** BSidesSF 2026 “roar”

---

### Autostereogram / Magic Eye Solving (BSidesSF 2026)

**模式（stereotype）：** 挑战图像是自动立体图（Magic Eye）。隐藏的 3D 内容（旗标文本）通过交叉/发散视线观察或程序化层差法揭示。

**程序化解法（GIMP 或 Python）：**
1. 复制图像为第二图层
2. 将顶层混合模式设为“Difference”
3. 将顶层水平滑动重复宽度（约 100 像素）
4. 隐藏的深度图案以亮线形式出现在暗背景上

```python
from PIL import Image
import numpy as np

img = np.array(Image.open('stereogram.png'))
shift = 100  # 重复宽度 — 试试 80-120 之间的值
diff = np.abs(img[:, shift:].astype(int) - img[:, :-shift].astype(int))
Image.fromarray(diff.astype(np.uint8)).save('revealed.png')
```

**寻找偏移值：** 重复宽度是相同垂直条纹之间的水平距离。对单行做自相关：`np.correlate(row, row, mode='full')` — 中心点之后的第一个峰值即为偏移。

**关键洞察：** 自动立体图通过相对于重复图案的水平像素位移编码深度。将图像与其偏移副本相减可抵消重复背景，显示深度变化即旗标文本。

**识别时机：** 图像有重复纹理/图案，挑战提及“eyes”、“seeing”、“3D”、“magic”或“stereogram”。

**参考资料：** BSidesSF 2026 “stereotype”

---
### 双层字节+行交错 (BSidesSF 2026)

**模式 (seeing-double)：** 两个 PNG 文件在字节级别交错合并成一个文件。经过字节级别的解交错后，得到的图像其扫描线仍然交错，需要第二轮行级别的解交错。

**步骤 1 — 字节解交错：**
```python
data = open('interleaved.ppnngg', 'rb').read()
file_a = bytes(data[i] for i in range(0, len(data), 2))  # 偶数字节
file_b = bytes(data[i] for i in range(1, len(data), 2))  # 奇数字节
# file_a 和 file_b 是有效的 PNG 文件
```

**步骤 2 — 行解交错（如有需要）：**
```python
from PIL import Image
import numpy as np

img = np.array(Image.open('file_a.png'))
# 偶数行组成一个子图，奇数行组成另一个子图
sub1 = img[0::2]  # 第0、2、4行，依此类推
sub2 = img[1::2]  # 第1、3、5行，依此类推
Image.fromarray(sub1).save('final_a.png')
Image.fromarray(sub2).save('final_b.png')
```

**关键洞察：** 双层交错（先字节，再扫描线）意味着单层简单解交错会产生乱码。识别多层交错的方法是：(1) 解交错后的文件是有效图像，但内容看起来“条纹状”或有交替行伪影，(2) 文件扩展名提示（如 `.ppnngg` 表示两个 PNG 交错）。

**检测方法：** 文件有双扩展名或不寻常扩展名。`file` 命令可能识别为数据或某种格式。偶数/奇数字节提取后产生有效文件头（例如，两部分都以 PNG 魔数 `89 50 4E 47` 开头）。

**参考资料：** BSidesSF 2026 “seeing-double”

---

### 多流视频容器隐写 (BSidesSF 2026)

**模式 (ads)：** MP4 视频容器包含多个视频流。默认流（stream 0:0）正常播放，但第二个流（0:1）包含 flag。大多数播放器只显示第一个/默认流。第二个流使用 AV1 编码，许多工具支持较差，增加了分析难度。

```bash
# 检测多个流
ffprobe -hide_banner flag.mp4
# 查找 Stream #0:1 — 第二个视频流

# 提取第二个流到单独文件
ffmpeg -i flag.mp4 -map 0:1 -c copy second_stream.mp4

# 或仅提取流1的第一帧
ffmpeg -i flag.mp4 -map 0:1 -frames:v 1 flag.jpg
```

**关键洞察：** MP4/MKV 容器可包含多个视频、音频和字幕轨道。大多数播放器默认播放 stream 0:0。务必使用 `ffprobe` 或 `mediainfo` 枚举所有流。`ffmpeg` 的 `-map 0:N` 参数用于选择特定流。VLC 也可通过菜单 Video → Video Track 切换轨道。

**识别时机：** 挑战提供的视频文件中，画面内容看似无关或误导。`ffprobe` 显示多个 `Stream` 条目。检查元数据字段如 `handler_name` 以获取提示（例如 “CTF Trickery”）。

**检测清单：**
1. `ffprobe -hide_banner file.mp4` — 统计 Stream 行数
2. `mediainfo file.mp4` — 检查轨道数量
3. VLC → Video → Video Track → 尝试所有轨道

**参考资料：** BSidesSF 2026 “ads”

---

## 渐进式 PNG 分层 XOR 解密 (OpenCTF 2016)

**模式 (渐进加密)：** PNG 包含标准的 `IDAT` 块（粗略的第一扫描）和自定义的 `scRT` 块。每个 `scRT` 块用多字节密钥 XOR 加密。解密后会得到另一个 `IDAT` 块和另一个 `scRT`，形成嵌套层。

1. 从 PNG 中提取自定义的 `scRT` 块数据
2. 使用 xortool 猜测 XOR 密钥（预期最频繁字节为 `\xFF`，对应图像数据）：
```bash
# 提取 scRT 块内容
python3 -c "
import struct
with open('image.png', 'rb') as f:
    data = f.read()
# 解析 PNG 块，查找 scRT
pos = 8  # 跳过 PNG 签名
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8]
    if chunk_type == b'scRT':
        with open('layer.bin', 'wb') as out:
            out.write(data[pos+8:pos+8+length])
    pos += 12 + length
"

# 猜测 XOR 密钥
xortool -c ff layer.bin
# 输出：key = 'nacho'
```

3. 解密并拆分：解密数据包含有效的 `IDAT` 块，后跟另一个 `scRT`
4. 对每层重复，直到所有 `scRT` 块解密完成
5. 重组：拼接 PNG 头 + 所有解密的 `IDAT` 块 + `IEND`

**本挑战的层密钥：** `nacho`, `savages`, `president`, `kilobits`, `monkey`, `butler`

**捷径：** 用 GraphBitStreamer 以原始 PNG 字节作为原始图像打开（32 bpp，宽度与原图匹配）。弱 XOR 加密保留视觉模式（类似 ECB 加密图像），使 flag 可读，无需完全解密。

**关键洞察：** 自定义 PNG 块（非标准四字母类型）常用于隐藏数据。PNG 规范允许任意辅助块，解析器忽略未知类型。多层使用不同 XOR 密钥时，需分别用频率分析破解。捷径有效是因为短重复密钥的 XOR 保留了大尺度像素模式，类似 ECB 模式的视觉泄露。

---

### 视频中曲面玻璃反射的二维码重建 (PlaidCTF 2018)

**模式：** 二维码仅作为监控视频中玻璃球的曲面反射出现（约100像素宽）。需手动重建：翻转、去畸变、识别为版本 2（25x25），解码格式字符串获取 ECC 级别，利用已知 flag 前缀逐像素重建数据。

**步骤：**
1. 从视频中提取最佳帧，裁剪反射区域
2. 水平翻转（镜像反射）并去畸变
3. 识别二维码版本（25x25 = 版本 2），解码格式位获取 ECC 级别和掩码模式
4. 开始手动逐像素转录 25x25 网格
5. 初次解码失败时，利用已知明文（flag 前缀 "PCTF{"）修正前几个数据字节
6. 高 ECC 级别（Q = 25% 纠错）修正剩余像素错误

```python
from PIL import Image
import numpy as np

# 步骤 1：提取并翻转反射
frame = Image.open('best_frame.png')
reflection = frame.crop((x1, y1, x2, y2))
flipped = reflection.transpose(Image.FLIP_LEFT_RIGHT)

# 步骤 2：放大以便手动转录
scaled = flipped.resize((500, 500), Image.NEAREST)
scaled.save('reflection_scaled.png')

# 步骤 3：手动转录 25x25 网格（版本 2 QR）
# 手动识别像素后，创建二维码矩阵
qr_matrix = np.zeros((25, 25), dtype=np.uint8)
# 根据视觉检查填充模块...
# qr_matrix[row][col] = 1  # 黑模块
# qr_matrix[row][col] = 0  # 白模块

# 步骤 4：渲染为干净二维码图像以供扫描
cell_size = 20
qr_img = Image.new('L', (25 * cell_size, 25 * cell_size), 255)
for r in range(25):
    for c in range(25):
        if qr_matrix[r][c]:
            for dy in range(cell_size):
                for dx in range(cell_size):
                    qr_img.putpixel((c * cell_size + dx, r * cell_size + dy), 0)
qr_img.save('reconstructed_qr.png')

# 步骤 5：用 zbarimg 扫描或用已知前缀修正错误
# zbarimg reconstructed_qr.png
```

**关键洞察：** 高 ECC 级别（Q 或 H）的二维码能容忍较大重建误差。当二维码部分可见（反射、损坏、低分辨率）时，手动重建可用，利用已知明文修正早期数据模块，剩余由 ECC 自动纠正。

---
### GIF 调色板操作用于 QR 码重构（3DSCTF 2017）

GIF 包含 108,900 帧单像素图像。每帧像素数据相同，但调色板条目不同。将调色板颜色映射为黑/白以重构一个 330x330 的 QR 码：

```python
from PIL import Image
gif = Image.open('challenge.gif')
width = int(gif.n_frames ** 0.5)  # sqrt(108900) = 330
pixels = []
for i in range(gif.n_frames):
    gif.seek(i)
    palette = gif.getpalette()
    # 第一个调色板条目：黄色=(255,255,0) 或绿色=(0,255,0)
    pixels.append(0 if palette[0] > 128 else 255)  # 黑色或白色

out = Image.new('L', (width, width))
out.putdata(pixels)
out.save('qr.png')
# zbarimg qr.png
```

**关键洞察：** GIF 帧具有相同的像素数据但不同的调色板颜色，通过调色板操作编码二进制数据。帧数是一个完全平方数，给出隐藏图像的边长。每帧代表一个像素；调色板的第一个条目决定其颜色。当 GIF 拥有异常大量且数量为完全平方数的帧时，应检查是否存在基于调色板的编码。

---

### Angecryption：AES-CBC 将一个有效文件加密成另一个有效文件（34C3 CTF 2017）

基于 Ange Albertini 的技术：通过精心构造的 AES-CBC 密钥和 IV，可以将一个有效的图像文件加密成另一个有效的图像文件：

```python
from Crypto.Cipher import AES
key = bytes.fromhex('...')  # 提供或恢复的密钥
iv = bytes.fromhex('...')
aes = AES.new(key, AES.MODE_CBC, iv)
encrypted = aes.encrypt(open('flag.png', 'rb').read())
# encrypted 也是一个有效的 PNG（一个遮罩图像）
# 将遮罩叠加在原图上以揭示隐藏内容
```

**关键洞察：** Angecryption 利用文件格式头部具有足够的自由度，使其能在选定的密钥/IV 下通过 AES-CBC 加密后仍保持有效。该技术通过构造 IV，使得解密“遮罩”文件头部时产生一个有效的“flag”文件头部。当你在挑战中发现两个有效图像文件和一个 AES 密钥/IV 时，尝试加密其中一个——结果可能是另一个，通过视觉对比即可发现 flag。

---

### SVG 微坐标隐写（SharifCTF 8）

SVG 包含一个可见图形和第二个 `<g>` 元素，后者具有极小的坐标值（例如 450.xxxxx，835.xxxxx）。应用 SVG 变换进行放大：

```xml
<svg viewBox="448.75 834.69 2 2" width="2000" height="2000">
  <!-- 或应用变换： -->
  <g transform="scale(200, 200) translate(-448.75, -834.69)">
    <!-- 隐藏内容变得可见 -->
  </g>
</svg>
```

**关键洞察：** SVG 坐标的小数位数很多，隐藏了在正常缩放下不可见的微观绘图。检查 `<g>` 元素中坐标值是否聚集在极小范围内。坐标的小数部分定义了隐藏图像。通过放大 100-1000 倍并平移到聚集中心即可揭示。当 SVG 文件大小对于可见内容异常大时，检查 `<path>`、`<line>` 或 `<g>` 元素中的坐标精度。
