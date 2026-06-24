# CTF Forensics - 图像隐写术

针对在图像格式（JPEG、PNG、BMP、GIF）中隐藏数据的特定技术。对于非图像隐写（PDF、音频、终端、文本），请参见 [steganography.md](steganography.md)。对于高级技术（FFT、SSTV、音频、视频、JPEG XL），请参见 [stego-advanced.md](stego-advanced.md) 和 [stego-advanced-2.md](stego-advanced-2.md)。

## 目录
- [JPEG 未使用量化表最低有效位隐写术 (EHAX 2026)](#jpeg-unused-quantization-table-lsb-steganography-ehax-2026)
- [BMP 位平面二维码提取 + Steghide (BYPASS CTF 2025)](#bmp-bitplane-qr-code-extraction--steghide-bypass-ctf-2025)
- [图像拼图通过边缘匹配重组 (BYPASS CTF 2025)](#image-jigsaw-puzzle-reassembly-via-edge-matching-bypass-ctf-2025)
- [F5 JPEG DCT 系数比率检测 (ApoorvCTF 2026)](#f5-jpeg-dct-coefficient-ratio-detection-apoorvctf-2026)
- [PNG 未使用调色板条目隐写术 (ApoorvCTF 2026)](#png-unused-palette-entry-steganography-apoorvctf-2026)
- [二维码瓦片重建 (UTCTF 2026)](#qr-code-tile-reconstruction-utctf-2026)
- [基于种子的像素置换 + 多位平面二维码 (L3m0nCTF 2025)](#seed-based-pixel-permutation--multi-bitplane-qr-l3m0nctf-2025)
- [JPEG 缩略图像素到文本映射 (RuCTF 2013)](#jpeg-thumbnail-pixel-to-text-mapping-ructf-2013)
- [条件 LSB 提取 — 近黑像素过滤 (BaltCTF 2013)](#conditional-lsb-extraction--near-black-pixel-filter-baltctf-2013)
- [JPEG Slack 空间隐写术 (BSidesSF 2025)](#jpeg-slack-space-steganography-bsidessf-2025)
- [最近邻插值隐写术 (BSidesSF 2025)](#nearest-neighbor-interpolation-steganography-bsidessf-2025)
- [RGB 奇偶校验隐写术 (Break In 2016)](#rgb-parity-steganography-break-in-2016)
- [像素坐标链隐写术 (H4ckIT CTF 2016)](#pixel-coordinate-chain-steganography-h4ckit-ctf-2016)
- [AVI 帧差分像素隐写术 (H4ckIT CTF 2016)](#avi-frame-differential-pixel-steganography-h4ckit-ctf-2016)
- [JPEG 单比特翻转暴力破解 + OCR (SECCON 2017)](#jpeg-single-bit-flip-brute-force-with-ocr-seccon-2017)
- [GIF 帧 PLTE 块拼接成 ELF (IceCTF 2018)](#gif-frame-plte-chunk-concatenation-to-elf-icectf-2018)
- [幸存像素上的嵌套缩放二维码叠加 (SECCON 2018)](#nested-resize-qr-overlay-at-survivor-pixels-seccon-2018)
- [ImageMagick +append 拼图拼接 + 缝隙解决 (X-MAS CTF 2018)](#imagemagick-append-puzzle-stitching--gaps-solver-x-mas-ctf-2018)
- [Steghide 密码短语在 JPEG 头部元数据中 (Saudi/Oman CTF 2019)](#steghide-passphrase-in-jpeg-header-metadata-saudioman-ctf-2019)
- [损坏的 PNG 魔数和小写块修复 (Pragyan CTF 2019)](#corrupted-png-magic-and-lowercase-chunk-repair-pragyan-ctf-2019)

---

## JPEG 未使用量化表最低有效位隐写术 (EHAX 2026)

**模式（Jpeg Soul）：** “无关紧要”的提示指向 JPEG 量化表（DQT）中的最低有效位。JPEG 可以嵌入未被帧标记引用的 DQT 表（ID 2、3）——渲染器不可见，但携带隐藏数据。

**检测方法：** JPEG 中的 DQT 表数量多于组件引用的数量。标准 JPEG 使用 2 个表（亮度 + 色度）；额外的 ID 为 2、3 的表则可疑。

```python
from PIL import Image

img = Image.open('challenge.jpg')

# 访问量化表（PIL 以字典形式暴露）
# 标准：表 0（亮度）和 1（色度）
# 隐藏：表 2、3（SOF 标记未引用）
qtables = img.quantization

bits = []
for table_id in sorted(qtables.keys()):
    if table_id >= 2:  # 未使用的表
        table = qtables[table_id]
        for i in range(64):  # 每个 DQT 有 8x8=64 个值
            bits.append(table[i] & 1)  # 提取最低有效位

# 将位转换为 ASCII
flag = ''
for i in range(0, len(bits) - 7, 8):
    byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
    if 32 <= byte <= 126:
        flag += chr(byte)
print(flag)
```

**手动提取 DQT（当 PIL 不暴露所有表时）：**
```python
# 手动解析 JPEG，查找所有 DQT 标记 (0xFFDB)
data = open('challenge.jpg', 'rb').read()
pos = 0
while pos < len(data) - 1:
    if data[pos] == 0xFF and data[pos+1] == 0xDB:
        length = int.from_bytes(data[pos+2:pos+4], 'big')
        dqt_data = data[pos+4:pos+2+length]
        table_id = dqt_data[0] & 0x0F
        precision = (dqt_data[0] >> 4) & 0x0F  # 0=8位，1=16位
        values = list(dqt_data[1:65]) if precision == 0 else []
        print(f"DQT 表 {table_id}: {values[:8]}...")
        pos += 2 + length
    else:
        pos += 1
```

**关键洞察：** JPEG 量化表是元数据——它们能在重新压缩和大多数图像处理后保留。未使用的表 ID（2-15）可以携带任意数据而不影响图像。

---
## BMP 位平面二维码提取 + Steghide（BYPASS CTF 2025）

**模式（黄金挑战）：** BMP 图像在特定位平面中隐藏二维码。提取二维码以获取 steghide 密码。

**技术：** 提取每个 RGB 通道的单个位平面（位 0-2），渲染为图像，扫描二维码。

```python
from PIL import Image
import numpy as np

img = Image.open('challenge.bmp')
pixels = np.array(img)

# 提取单个位平面
for ch_idx, ch_name in enumerate(['R', 'G', 'B']):
    for bit in range(3):  # 检查位 0、1、2
        channel = pixels[:, :, ch_idx]
        bit_plane = ((channel >> bit) & 1) * 255
        Image.fromarray(bit_plane.astype(np.uint8)).save(f'bit_{ch_name}_{bit}.png')

# 所有通道的合并最低有效位
lsb_img = np.zeros_like(pixels)
for ch in range(3):
    lsb_img[:, :, ch] = (pixels[:, :, ch] & 1) * 255
Image.fromarray(lsb_img).save('lsb_all.png')
```

**完整攻击链：**
1. 提取位平面 → 在特定位平面中找到二维码（通常是位 1，而非位 0）
2. 使用 `zbarimg bit_G_1.png` 扫描二维码 → 获取 steghide 密码
3. `steghide extract -sf challenge.bmp -p <password>` → 提取隐藏文件

**关键洞察：** 标准 LSB（最低有效位）工具只检查位 0。隐藏的二维码可能在位 1 或位 2 —— 始终系统性地检查多个位平面。BMP 格式保留了精确的像素值（无压缩伪影）。

---

## 通过边缘匹配重组拼图图像（BYPASS CTF 2025）

**模式（拼图）：** 归档包含多个拼图块图像，需重新组装成原始图像。重组后的图像包含 flag（可能经过 ROT13 编码）。

**技术：** 计算所有拼图块对之间共享边缘的像素强度差异，然后贪心地放置拼块以最小化总边缘差异。

```python
from PIL import Image
import numpy as np
import os

# 加载所有拼块
pieces = {}
for f in sorted(os.listdir('pieces/')):
    pieces[f] = np.array(Image.open(f'pieces/{f}'))

piece_list = list(pieces.keys())
n = len(piece_list)
grid_size = int(n ** 0.5)  # 例如，25 块 → 5x5

# 计算边缘兼容度
def edge_diff(img1, img2, direction):
    if direction == 'right':
        return np.sum(np.abs(img1[:, -1].astype(int) - img2[:, 0].astype(int)))
    elif direction == 'bottom':
        return np.sum(np.abs(img1[-1, :].astype(int) - img2[0, :].astype(int)))

# 构建兼容矩阵
right_compat = np.full((n, n), float('inf'))
bottom_compat = np.full((n, n), float('inf'))
for i in range(n):
    for j in range(n):
        if i != j:
            right_compat[i, j] = edge_diff(pieces[piece_list[i]], pieces[piece_list[j]], 'right')
            bottom_compat[i, j] = edge_diff(pieces[piece_list[i]], pieces[piece_list[j]], 'bottom')

# 贪心放置
grid = [[None] * grid_size for _ in range(grid_size)]
used = set()
for row in range(grid_size):
    for col in range(grid_size):
        best_piece, best_diff = None, float('inf')
        for idx in range(n):
            if idx in used:
                continue
            diff = 0
            if col > 0:
                diff += right_compat[grid[row][col-1], idx]
            if row > 0:
                diff += bottom_compat[grid[row-1][col], idx]
            if diff < best_diff:
                best_diff, best_piece = diff, idx
        grid[row][col] = best_piece
        used.add(best_piece)

# 重组图像
piece_h, piece_w = pieces[piece_list[0]].shape[:2]
final = Image.new('RGB', (grid_size * piece_w, grid_size * piece_h))
for row in range(grid_size):
    for col in range(grid_size):
        final.paste(Image.open(f'pieces/{piece_list[grid[row][col]]}'),
                     (col * piece_w, row * piece_h))
final.save('reassembled.png')
```

**后处理：** 检查重组图像中的文本是否经过 ROT13 编码。使用 `tr 'A-Za-z' 'N-ZA-Mn-za-m'` 解码。

**关键洞察：** 边缘匹配通过最小化共享边界的像素差异实现。贪心方法（将拼块放置到与已放置邻居边缘差异最小的位置）对大多数 CTF 拼图效果良好。对于更难的拼图，可加入回溯。 

---
## F5 JPEG DCT 系数比率检测 (ApoorvCTF 2026)

**模式（Engraver's Fault）：** 通过分析 JPEG 图像的 DCT 系数分布检测 F5 隐写。F5 会将 ±1 的 AC 系数向 0 递减，导致可测量的比率变化。

**检测指标 — ±1/±2 AC 系数比率：**
```python
import numpy as np
from PIL import Image
import jpegio  # 或使用 jpeg_toolbox

def f5_ratio(jpeg_path):
    """比率低于 0.15 表示 F5 修改；高于 0.20 表示干净。"""
    jpg = jpegio.read(jpeg_path)
    coeffs = jpg.coef_arrays[0].flatten()  # 亮度 Y 通道
    coeffs = coeffs[coeffs != 0]  # 去除 DC/零系数
    count_1 = np.sum(np.abs(coeffs) == 1)
    count_2 = np.sum(np.abs(coeffs) == 2)
    return count_1 / max(count_2, 1)
```

**稀疏图像边界情况：** DCT 系数中零系数超过 80% 的图像会导致 ±1/±2 比率误导。使用次级指标：
```python
def f5_sparse_check(jpeg_path):
    """对于稀疏图像，±2/±3 比率低于 2.5 表示修改。"""
    jpg = jpegio.read(jpeg_path)
    coeffs = jpg.coef_arrays[0].flatten()
    count_2 = np.sum(np.abs(coeffs) == 2)
    count_3 = np.sum(np.abs(coeffs) == 3)
    return count_2 / max(count_3, 1)

# 组合分类器：
r12 = f5_ratio(path)
r23 = f5_sparse_check(path)
is_modified = r12 < 0.15 or (r12 < 0.25 and r23 < 2.5)
```

**关键洞察：** F5 隐写将 ±1 系数向 0 移动，降低了 ±1/±2 比率。自然 JPEG 的比率在 0.25-0.45 之间；F5 修改后降至 0.10 以下。稀疏图像（大部分平坦/白色）需要使用次级的 ±2/±3 指标，因为它们的 ±1 计数本身就很低。

---

## PNG 未使用调色板条目隐写 (ApoorvCTF 2026)

**模式（The Gotham Files）：** 带调色板的 PNG（8 位索引色）在未被像素引用的调色板条目中隐藏数据。图像使用索引 0-199，但 PLTE 块有 256 条目 — 索引 200-255 的红色通道值中包含隐藏的 ASCII。

```python
from PIL import Image
import struct

def extract_unused_plte(png_path):
    img = Image.open(png_path)
    palette = img.getpalette()  # 扁平列表: [R0,G0,B0, R1,G1,B1, ...]
    pixels = list(img.getdata())
    used_indices = set(pixels)

    # 从未使用的调色板条目中提取红色通道
    flag = ''
    for i in range(256):
        if i not in used_indices:
            r = palette[i * 3]  # 红色通道
            if 32 <= r <= 126:
                flag += chr(r)
    return flag
```

**关键洞察：** PNG 调色板最多可有 256 条目，但图像通常使用较少。未使用的条目对查看者不可见，但仍保留在文件中。元数据提示如“collector”、“the entries that don't make it to the page”或“red light”指向此技术。务必检查哪些调色板索引被实际引用与分配。

---

## QR Code 瓷砖重组 (UTCTF 2026)

**模式（QRecreate）：** QR 码被拆分成瓷砖/碎片，需要重新组装。瓷砖可能被打乱、旋转或缺少定位图案。

**重组工作流程：**
```python
from PIL import Image
import numpy as np

# 加载打乱的瓷砖
tiles = []
for i in range(N_TILES):
    tile = Image.open(f'tile_{i}.png')
    tiles.append(np.array(tile))

# 策略 1：边缘匹配（类似拼图）
# 每个瓷砖边缘有唯一的位模式 — 匹配相邻边缘
def edge_signature(tile, side):
    if side == 'top': return tuple(tile[0, :].flatten())
    if side == 'bottom': return tuple(tile[-1, :].flatten())
    if side == 'left': return tuple(tile[:, 0].flatten())
    if side == 'right': return tuple(tile[:, -1].flatten())

# 策略 2：QR 结构约束
# - 定位图案（大方块）必须位于 3 个角落
# - 定时图案（交替黑白）连接定位图案
# - 利用这些作为锚点定向剩余瓷砖

# 策略 3：暴力破解小网格
# 对于 3x3 或 4x4 网格，尝试所有排列并用 zbarimg 扫描
from itertools import permutations
import subprocess

grid_size = 3
tile_size = tiles[0].shape[0]
for perm in permutations(range(len(tiles))):
    img = Image.new('L', (grid_size * tile_size, grid_size * tile_size))
    for idx, tile_idx in enumerate(perm):
        row, col = divmod(idx, grid_size)
        img.paste(Image.fromarray(tiles[tile_idx]),
                  (col * tile_size, row * tile_size))
    img.save('/tmp/qr_attempt.png')
    result = subprocess.run(['zbarimg', '/tmp/qr_attempt.png'],
                          capture_output=True, text=True)
    if result.stdout.strip():
        print(f"解码结果: {result.stdout}")
        break
```

**关键洞察：** QR 码具有结构约束（定位图案、定时图案、格式信息），极大地缩小了搜索空间。先利用 QR 结构作为锚点，再暴力破解瓷砖位置。

---
## Seed-Based Pixel Permutation + Multi-Bitplane QR (L3m0nCTF 2025)

**模式（Lost Signal）：** 图像中像素颜色随机化，隐藏了一个二维码。像素按照种子确定的排列顺序访问，数据在亮度（Y）通道的多个比特平面中交错存储。

**提取流程：**
1. 将图像转换为 YCbCr 并提取 Y（亮度）通道
2. 使用已知种子生成像素访问顺序
3. 以交错顺序从多个比特平面提取最低有效位（LSB）位
4. 重构为二值图像并扫描二维码

```python
from PIL import Image
import numpy as np

SEED = 739391  # 给定或暴力破解得到

# 1. 提取 Y 通道
img = Image.open("challenge.png").convert("YCbCr")
Y = np.array(img.split()[0], dtype=np.uint8)
h, w = Y.shape

# 2. 生成确定性像素排列
rng = np.random.RandomState(SEED)
perm = np.arange(h * w)
rng.shuffle(perm)

# 3. 从多个比特平面交错提取位
bitplanes = [0, 1]  # LSB0 和 LSB1
total_bits = h * w
bits = np.zeros(total_bits, dtype=np.uint8)

for i in range(total_bits):
    pix_idx = perm[i // len(bitplanes)]
    bp = bitplanes[i % len(bitplanes)]
    y, x = divmod(pix_idx, w)
    bits[i] = (Y[y, x] >> bp) & 1

# 4. 重构二维码
qr = bits.reshape((h, w))
qr_img = Image.fromarray((255 * (1 - qr)).astype(np.uint8))
qr_img.save("recovered_qr.png")
# zbarimg recovered_qr.png
```

**关键洞察：** 种子定义了确定性的像素访问顺序（通过 `RandomState` 实现 Fisher-Yates 洗牌）。没有正确的种子，输出就是随机噪声。不同比特平面的位交错存储（像素 N 的 bit 0，像素 N 的 bit 1，像素 N+1 的 bit 0，……），使数据密度翻倍。优先尝试 Y（亮度）通道——它对隐藏的二进制数据对比度最高。

**种子恢复：** 如果种子未知，可在 EXIF 元数据、文件名、图像尺寸、挑战描述中的数字，或通过暴力破解小范围内寻找。

**检测：** 图像看似随机彩色噪声，但尺寸异常（完美正方形，2 的幂次）。挑战中提及“seed”、“random”或“signal”。

---

## JPEG Thumbnail Pixel-to-Text Mapping (RuCTF 2013)

**模式：** JPEG 中嵌入的缩略图，暗色像素与主图中可见文本的字符位置一一对应。

```python
from PIL import Image
# 提取缩略图：exiftool -b -ThumbnailImage secret.jpg > thumb.jpg
thumb = Image.open('thumb.jpg')
text_lines = ["line1 of visible text...", "line2..."]  # OCR 或手动录入照片中的文本
result = ''
for y in range(thumb.height):
    for x in range(thumb.width):
        r, g, b = thumb.getpixel((x, y))[:3]
        if r < 100 and g < 100 and b < 100:  # 暗像素 = 选中字符
            result += text_lines[y][x]
```

**关键洞察：** 使用 `exiftool -b -ThumbnailImage` 提取缩略图。暗色像素作为主图文本的选择掩码。用 OCR（ABBYY FineReader、Tesseract）获取文本网格，再将暗色缩略图像素映射到字符位置。

---

## Conditional LSB Extraction — Near-Black Pixel Filter (BaltCTF 2013)

**模式：** 仅 R<=1 且 G<=1 且 B<=1 的像素携带隐写数据。标准 LSB 工具因处理所有像素而漏掉数据。

```python
from PIL import Image
img = Image.open('image.png')
bits = ''
for pixel in img.getdata():
    r, g, b = pixel[0], pixel[1], pixel[2]
    if not (r <= 1 and g <= 1 and b <= 1):
        continue  # 跳过非载体像素
    bits += str(r & 1) + str(g & 1) + str(b & 1)
# 将位转换为字节
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
```

**关键洞察：** 当标准 `zsteg`/`stegsolve` 无法发现数据时，尝试先按像素值范围过滤再提取 LSB。载体像素可能限制在近黑、近白或特定颜色范围内。

---
## JPEG Slack Space Steganography (BSidesSF 2025)

JPEG 压缩会将图像填充到 8x8 像素块边界。隐藏数据存在于超出可见图像尺寸的填充像素中：

1. **确定填充尺寸：** JPEG 会向上取整到最接近的 8 的倍数。一个 253x195 的图像会填充到 256x200
2. **提取 slack 像素：** 使用工具将可见区域扩展到真实的块尺寸

```bash
# 扩展图像以查看 slack 像素
python3 jpeg_uncrop.py input.jpg --width 256 --height 200
# 或使用 ImageMagick 强制完整解码
magick input.jpg -define jpeg:size=256x200 extended.png
```

3. **从 slack 像素解码二进制：** 填充区域中黑色=0，白色=1。常见编码格式：
   - 2 字节：魔数
   - 1 字节：密钥长度
   - N 字节：加密密钥
   - 1 字节：消息长度
   - N 字节：加密消息

**关键洞察：** 大多数图像编辑器和查看器会裁剪到声明的尺寸，隐藏了填充部分。使用 `jpegtran -crop` 或原始 DCT 解码器可以访问完整的块数据。

---

## Nearest-Neighbor Interpolation Steganography (BSidesSF 2025)

隐藏数据以像素网格形式编码，均匀分布在高分辨率图像中。使用最近邻插值下采样只提取隐藏的像素：

```bash
# 在 4096x3072 图像中隐藏像素间隔为 16
# 使用最近邻插值下采样 16 倍，恢复 256x192 的隐藏图像
magick flag.webp -interpolate nearest-neighbor -interpolative-resize 256x192 flag_visible.png
```

**关键洞察：** 最近邻插值选择精确的像素值（无混合），保留了隐藏数据。双线性或双三次插值会对周围像素取平均，破坏消息。挑战名称或描述通常会提示所用的插值方法。

**检测方法：** 在图像查看器中打开并放大，观察规则间隔的重复像素模式。计算图像尺寸与疑似网格间距的最大公约数。

---

## RGB Parity Steganography (Break In 2016)

隐藏图像编码在像素 RGB 和的奇偶性中。计算每个像素的 R+G+B 和——偶数和为白色，奇数和为黑色。渲染出包含隐藏消息的二值位图。

```python
from PIL import Image
img = Image.open('image.png')
out = Image.new('1', img.size)
for x in range(img.width):
    for y in range(img.height):
        r, g, b = img.getpixel((x, y))[:3]
        out.putpixel((x, y), (r + g + b) % 2)
out.save('hidden.png')
```

**关键洞察：** 与 LSB（最低有效位）隐写（单通道、单比特）不同，奇偶性隐写使用所有通道的和。注意挑战中关于“成对”、“配对”或“颜色相加”的提示。

**检测方法：** 图像看起来正常，但像素 RGB 和的奇偶分布非随机。

---

## Pixel Coordinate Chain Steganography (H4ckIT CTF 2016)

每个像素在红色通道编码数据字节，绿色和蓝色通道编码下一个要读取像素的坐标，形成图像中的链表遍历。

```python
from PIL import Image

def extract_coordinate_chain(image_path, start_x=0, start_y=0):
    """跟随坐标链：R=数据，G=下一个 x，B=下一个 y"""
    img = Image.open(image_path)
    flag = ""
    x, y = start_x, start_y
    visited = set()

    while (x, y) not in visited:
        visited.add((x, y))
        r, g, b = img.getpixel((x, y))[:3]

        if r == 0:  # 空字符终止符
            break

        flag += chr(r)
        x, y = g, b  # 绿色和蓝色通道给出下一个像素坐标

    return flag

# 变体：
# - (R,G) = 坐标，B = 数据字节
# - 对于宽度超过 256 像素的图像，坐标存储为 (G*256+B)
# - 起始像素由元数据或已知偏移指示
```

**关键洞察：** 链表像素遍历隐藏了消息和读取顺序。标准的 LSB 分析无法发现，因为只有特定像素携带数据。注意绿色/蓝色通道中结构异常的值（可能是坐标的小数字）。

---
## AVI 帧差分像素隐写术 (H4ckIT CTF 2016)

逐像素比较连续视频帧。像素值恰好增加 1 表示编码“1”位；未变化的像素编码“0”。收集比特形成 Brainfuck 程序或二进制消息。

```python
from PIL import Image
import subprocess

def extract_frame_differential(frame_dir, num_frames):
    """比较连续帧：像素增加 = 1，未变 = 0"""
    bits = ""

    for i in range(num_frames - 1):
        img1 = Image.open(f"{frame_dir}/frame_{i:04d}.png")
        img2 = Image.open(f"{frame_dir}/frame_{i+1:04d}.png")

        pixels1 = list(img1.getdata())
        pixels2 = list(img2.getdata())

        for p1, p2 in zip(pixels1, pixels2):
            if p1 != p2:
                # 像素变化（增加 1）= 位 "1"
                bits += "1"
            else:
                bits += "0"

    # 将比特转换为 ASCII 或解释为 Brainfuck
    message = ""
    for i in range(0, len(bits), 8):
        byte = int(bits[i:i+8], 2)
        if 32 <= byte < 127:
            message += chr(byte)

    return message

# 先从 AVI 中提取帧：
# binwalk video.avi  （提取嵌入的 PNG/BMP 帧）
# 或：ffmpeg -i video.avi frame_%04d.png
```

**关键洞察：** 帧差分隐写术在时间域隐藏数据，而非空间域。标准图像隐写工具只分析单帧，无法检测帧间变化。提取所有帧，然后对连续帧对做差分，寻找单像素值递增。

---

### JPEG 单比特翻转暴力破解与 OCR (SECCON 2017)

损坏的 JPEG 文件含单个比特翻转。生成所有单比特变体并用 OCR 扫描：

```python
data = open('corrupted.jpg', 'rb').read()
for byte_pos in range(len(data)):
    for bit in range(8):
        candidate = data[:byte_pos] + bytes([data[byte_pos] ^ (1 << bit)]) + data[byte_pos+1:]
        with open(f'attempt_{byte_pos}_{bit}.jpg', 'wb') as f:
            f.write(candidate)
```

```bash
# 自动 OCR 扫描 flag
for f in attempt_*.jpg; do
    result=$(tesseract "$f" stdout 2>/dev/null)
    if echo "$result" | grep -qi "flag\|ctf\|SECCON"; then
        echo "在 $f 中找到: $result"
    fi
done
```

**关键洞察：** 对于小文件（< 10KB），单比特翻转的总搜索空间为 `8 * 文件大小`，通常低于 80,000 个候选，易于暴力破解。使用缩略图生成作为快速有效性检查（损坏的 JPEG 无法解码），然后对存活者进行 OCR。JPEG 压缩数据规则：`0xFF` 后总是跟 `0x00`（填充字节）或标记 — 违反此规则的位置即为损坏点。

---

## GIF 帧 PLTE 块拼接成 ELF (IceCTF 2018)

**模式：** GIF 通过分割成索引 PNG 帧隐藏 Linux ELF 二进制。每帧的 `PLTE`（调色板）块存储二进制的下一片段 — 实际像素数据无关紧要。用 Pillow 提取：遍历帧，将每帧转为 PNG，遍历 PNG 块，拼接所有 `PLTE` 块体，结果即为有效 ELF 文件。

```python
from PIL import Image, ImagePalette
import struct

def read_png_plte(png_bytes):
    i = 8  # 跳过 PNG 魔数
    while i < len(png_bytes):
        length = struct.unpack(">I", png_bytes[i:i+4])[0]
        ctype  = png_bytes[i+4:i+8]
        body   = png_bytes[i+8:i+8+length]
        if ctype == b"PLTE":
            return body
        i += 12 + length
    return b""

payload = bytearray()
with Image.open("carrier.gif") as gif:
    for frame in range(gif.n_frames):
        gif.seek(frame)
        png_buf = io.BytesIO()
        gif.save(png_buf, "PNG")
        payload += read_png_plte(png_buf.getvalue())

open("recovered.elf", "wb").write(payload)
```

**关键洞察：** GIF 帧内部各自存有调色板。将每帧重新编码为 PNG 时，调色板以 `PLTE` 块形式保留 — 这是一个被忽略但字节精确的容器。任何使用多帧格式且每帧带元数据的隐写载体（GIF 调色板、APNG 帧数据、PDF 页面流、MKV 轨道）都可将数据嵌入*元数据通道*，而非像素通道，从而绕过大多数 LSB 类检测。当 GIF 看似无害动画但含额外帧或调色板条目时，先逐块导出再处理像素。

**参考：** IceCTF 2018 — ilovebees，writeup 11418

---
## Nested-Resize QR Overlay at Survivor Pixels (SECCON 2018)

**模式：** 挑战 PNG 根据缩小次数（500 → 250 → 100 → 50）使用最近邻插值解码为两个不同的 QR 码。追踪每次缩小后存活的源像素：对于一个 10× 链条，使用 `PIL.Image.resize(size, Image.NEAREST)`，存活像素位于索引 `(10i+7, 10j+7)`。在这些位置叠加第二个 QR，使其仅在链式缩放后显现。

```python
from PIL import Image
big = Image.open('qr1.png')              # 500x500 可见 QR
small = Image.open('qr2.png')            # 50x50 隐藏 QR
px = big.load()
sx = small.load()
for i in range(50):
    for j in range(50):
        px[10*i+7, 10*j+7] = sx[i, j]
big.save('trap.png')
```

**关键洞察：** 最近邻缩放每个源块精确保留一个像素；其偏移取决于舍入（PIL 选择 `floor(original*scale)+0.5`）。每次缩放计算存活索引，然后在这些索引处合成嵌套隐写。只要插值是最近邻，适用于任意数量的级联缩放。

**参考：** SECCON 2018 — QRChecker，writeup 12014

---

## ImageMagick +append Puzzle Stitching + gaps Solver (X-MAS CTF 2018)

**模式：** 磁盘镜像包含 N 个由 `foremost` 或 `scalpel` 切割出的拼图 PNG。用 ImageMagick 的 `convert +append` 将所有碎片水平拼接，然后用已知碎片大小（通常存储在 EXIF）将拼接条传给 `gaps` 拼图求解器（[gaps](https://github.com/nemanja-m/gaps)）自动重组。

```bash
foremost -t png -i disk.img -o pieces
convert +append pieces/*.png strip.png
gaps --image=strip.png --size=273
```

**关键洞察：** CTF 拼图挑战很少需要手动操作。切割碎片，拼接，运行 `gaps` —— 它用遗传算法几分钟内完成重组。用 `exiftool` 读取每个碎片的尺寸提示。

**参考：** X-MAS CTF 2018 — Message from Santa，writeup 12662

---

## Steghide Passphrase in JPEG Header Metadata (Saudi/Oman CTF 2019)

**模式：** JPEG 文件中嵌入了 `steghide` 载荷，其密码以纯 ASCII 形式隐藏在 JPEG 头部/元数据区域。标准工具（`exiftool`、`strings`）可能因字节范围未标记为有效 EXIF/注释标签而漏检，但用 `xxd` 查看前几百字节可发现该字符串。

```bash
# 扫描头部可疑 ASCII
xxd info.jpg | head -20
# 00000010: ffdb 0043 0008 6261 6469 7362 6164 0008  ...C..badisbad..
#                      ^^^^^^^^^^^^^^^^^ 密码位于偏移 0x18

# 用密码确认 steghide 载荷
steghide --info info.jpg       # 提示输入密码
steghide extract -sf info.jpg -p badisbad
```

**关键洞察：** 始终用 `xxd`/`hexdump -C` 扫描 JPEG 前约 256 字节的 ASCII 字符串 —— 作者有时将密码塞入 JFIF/APPn 段的保留区，`exiftool` 不会显示，但十六进制视图中一目了然。结合 `steghide`、`outguess` 或 `stegseek` 词表种子使用。

**参考：** Quals Saudi 和 Oman National Cyber Security CTF 2019 — Hack a nice day，writeup 13232

---

## Corrupted PNG Magic and Lowercase Chunk Repair (Pragyan CTF 2019)

**模式：** PNG 无法读取，因为 8 字节魔数被篡改（如 `89 50 4E 47 2E 0A 2E 0A` 替代正确的 `89 50 4E 47 0D 0A 1A 0A`），且关键块名小写（`idat` 替代 `IDAT`）。PNG 解码器将小写块名视为“辅助”，跳过它们，导致图像看似空白，直到修正大小写。元数据（如 `exiftool` 的 Artist 字段）提供下一步线索。

```bash
# 第一步：修补魔数字节
printf '\x89PNG\r\n\x1a\n' | dd of=broken.png conv=notrunc bs=1 count=8

# 第二步：重新大写关键块名（IHDR, IDAT, IEND, PLTE）
python3 -c "
d = open('broken.png','rb').read()
d = d.replace(b'idat', b'IDAT').replace(b'iend', b'IEND')
open('fixed.png','wb').write(d)
"

# 第三步：提取隐藏元数据
exiftool fixed.png | grep -Ei 'artist|comment|desc'
# Artist : md5_MEf89jf4h9   -> 使用 md5(...) 作为 zip 密码
```

**关键洞察：** PNG 有两个正交的可解析性门槛：8 字节签名和每个块名的大小写（首字母大写为关键块）。修复两者后再判断文件是否为空。`pngcheck -v` 精确指出错误字节/块。可读后，将 EXIF 的 `Artist`、`Description` 和 `tEXt`/`iTXt` 块视为主要隐藏点。

**参考：** Pragyan CTF 2019 — Magic PNGs，writeup 13833
