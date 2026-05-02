# CTF Forensics - 高级隐写术（第2部分）

另见：[stego-advanced.md](stego-advanced.md) 关于音频隐写（FFT 频域、DTMF、SSTV、LSB 音频、音乐音符、元数据编码、波形二进制、频谱二维码）和空白字符/归档编码。

## 目录
- [视频帧累积隐藏图像（ASIS CTF Finals 2013）](#video-frame-accumulation-for-hidden-image-asis-ctf-finals-2013)
- [反转音频隐藏信息（ASIS CTF Finals 2013）](#reversed-audio-hidden-message-asis-ctf-finals-2013)
- [视频帧平均隐藏内容（SECCON 2015）](#video-frame-averaging-for-hidden-content-seccon-2015)
- [JPEG XL TOC 排列隐写（BSidesSF 2026）](#jpeg-xl-toc-permutation-steganography-bsidessf-2026)
- [Arnold 猫映射图像解扰（Nuit du Hack 2017）](#arnolds-cat-map-image-descrambling-nuit-du-hack-2017)
- [高分辨率 SSTV 自定义 FM 解调（PlaidCTF 2017）](#high-resolution-sstv-custom-fm-demodulation-plaidctf-2017)
- [MJPEG FFD9 后额外字节隐写（PoliCTF 2017）](#mjpeg-extra-bytes-after-ffd9-steganography-polictf-2017)
- [EXIF Zlib 数据与非默认 LSB 像素模式（ASIS CTF Finals 2017）](#exif-zlib-data-with-non-default-lsb-pixel-pattern-asis-ctf-finals-2017)
- [PDF 交叉引用表隐蔽通道（SEC-T CTF 2017）](#pdf-cross-reference-table-covert-channel-sec-t-ctf-2017)
- [网络抓包中的 ANSI 转义码隐写（Square CTF 2017）](#ansi-escape-code-steganography-in-network-capture-square-ctf-2017)
- [像素级 ECB 去重图像恢复（BackdoorCTF 2017）](#pixel-wise-ecb-deduplication-for-image-recovery-backdoorctf-2017)
- [多色 QR 码二进制映射暴力破解（STEM CTF 2019）](#multi-color-qr-code-binary-mapping-brute-force-stem-ctf-2019)

---

## 视频帧累积隐藏图像（ASIS CTF Finals 2013）

**模式：** 视频中小图像（图标、形状）在不同屏幕位置短暂闪烁。单帧看似随机，但将所有帧合成后，位置会描绘出隐藏的图案（二维码、文本、图像）。

**提取流程：**

1. 从视频中提取单帧：
```bash
ffmpeg -i challenge.mp4 -vsync 0 frames/frame_%04d.png
```

2. 合成所有帧，取所有像素值的最大值（或并集）：
```python
from PIL import Image
import os

frames_dir = 'frames'
frame_files = sorted(os.listdir(frames_dir))

# 载入第一帧作为基底
base = Image.open(os.path.join(frames_dir, frame_files[0])).convert('L')

# 累积：取所有帧的像素最大值
import numpy as np
accumulated = np.array(base, dtype=np.float64)
for f in frame_files[1:]:
    frame = np.array(Image.open(os.path.join(frames_dir, f)).convert('L'), dtype=np.float64)
    accumulated = np.maximum(accumulated, frame)

result = Image.fromarray(accumulated.astype(np.uint8))
result.save('accumulated.png')
```

3. 备选方案：转换为 GIF，在 GIMP 中删除黑色背景帧，查看所有位置叠加效果。

4. 清理显现的图案（如二维码）——选择前景，扩展/收缩选区，填充，缩放到预期尺寸（如版本1二维码为21x21）：
```bash
# 扫描二维码
zbarimg accumulated.png
```

**关键洞察：** 当视频中物体在看似随机的位置闪烁时，将所有帧合成。位置本身编码隐藏数据——每帧贡献一个像素/单元到更大图像。可转换为 GIF 逐帧检查，或用 PIL/NumPy 取所有帧的像素最大值。

---

## 反转音频隐藏信息（ASIS CTF Finals 2013）

**模式：** 音频轨道（独立或从视频提取）听起来杂乱无章或难以理解。反转播放后出现语音、数字或其他有意义内容。

**提取与反转：**
```bash
# 从视频提取音频
ffmpeg -i challenge.mp4 -vn -acodec pcm_s16le audio.wav

# 反转音频
sox audio.wav reversed.wav reverse
# 或：ffmpeg -i audio.wav -af areverse reversed.wav

# 播放以听隐藏信息
play reversed.wav
```

**备选方案：** 用 Audacity 打开 -> 效果 -> 反转。听是否有语音、数字或编码数据。

**关键洞察：** 反转音频是最简单的音频隐写技术之一。如果音频听起来像杂乱语音但节奏明显，先尝试反转。隐藏内容通常是数字字符串（如 MD5 哈希）或下一步挑战指令。多媒体文件的音频和视频轨道都要分别检查。

---

## 视频帧平均隐藏内容（SECCON 2015）

通过时间平均提取隐藏在多帧视频中的内容：

```python
import numpy as np
from PIL import Image
import glob

frames = sorted(glob.glob('frames/*.png'))
N = len(frames)

# 以浮点数累积帧以保留精度
acc = np.zeros(np.array(Image.open(frames[0])).shape, dtype=np.float64)
for f in frames:
    acc += np.array(Image.open(f), dtype=np.float64) / N

# 转回 uint8
result = Image.fromarray(np.round(acc).astype(np.uint8))
result.save('averaged.png')
```

如果平均图像较暗，可用直方图均衡增强对比度：

```python
from PIL import ImageOps
enhanced = ImageOps.equalize(result.convert('L'))
enhanced.save('enhanced.png')
```

**关键洞察：** 被运动、噪声或快速变化遮蔽的内容，通过平均后变得可见。先用 `ffmpeg -i video.mp4 frames/%04d.png` 提取帧。适用于隐藏二维码、文本和水印。

---

## JPEG XL TOC 排列隐写（BSidesSF 2026）

**模式（image-progress）：** JPEG XL 的目录表（TOC）支持排列字段，重新排序文件中 AC 组（渐进扫描瓦片）的存储顺序。渐进解码时，随着文件截断偏移增加，256x256 瓦片的出现顺序编码了 flag。

**解码方法：**
1. **渐进截断：** 以递增字节偏移截断 JXL 文件（如每1KB）
2. **解码每个截断：** 用 `djxl` 解码每个截断文件
3. **测量瓦片收敛：** 将每个截断解码与完整解码比较，确定哪些 256x256 瓦片已收敛（与最终图像匹配）
4. **读取收敛顺序：** 瓦片达到最终状态的顺序拼出 flag

```python
import subprocess
import numpy as np
from PIL import Image

# 完整解码作为参考
subprocess.run(['djxl', 'flag.jxl', 'full.png'])
full = np.array(Image.open('full.png'))
h, w = full.shape[:2]
tile_size = 256
tiles_x = (w + tile_size - 1) // tile_size
tiles_y = (h + tile_size - 1) // tile_size

# 跟踪每个瓦片收敛时间
converged = {}
jxl_data = open('flag.jxl', 'rb').read()

for offset in range(1000, len(jxl_data), 1000):
    # 写入截断文件
    with open('/tmp/trunc.jxl', 'wb') as f:
        f.write(jxl_data[:offset])

    # 尝试解码（短截断可能失败）
    result = subprocess.run(['djxl', '/tmp/trunc.jxl', '/tmp/trunc.png'],
                          capture_output=True)
    if result.returncode != 0:
        continue

    partial = np.array(Image.open('/tmp/trunc.png'))

    # 检查哪些瓦片与完整解码匹配
    for ty in range(tiles_y):
        for tx in range(tiles_x):
            tile_id = ty * tiles_x + tx
            if tile_id in converged:
                continue
            y0, y1 = ty * tile_size, min((ty+1) * tile_size, h)
            x0, x1 = tx * tile_size, min((tx+1) * tile_size, w)
            if np.array_equal(partial[y0:y1, x0:x1], full[y0:y1, x0:x1]):
                converged[tile_id] = offset

# 按收敛顺序排序瓦片
order = sorted(converged.items(), key=lambda x: x[1])
flag_chars = [chr(tile_id) for tile_id, _ in order]
print('Flag:', ''.join(flag_chars))
```

**备选方案 — 直接提取 TOC：**
```bash
# 修改版 djxl 带调试打印可直接提取 TOC 排列
# 查找 JXL 帧头中的排列数组
# TOC 排列映射：stored_order[i] -> logical_group[i]
# 逆映射为：logical_group -> stored_order（收敛优先级）
```

**JPEG XL 渐进结构：**
- **DC 组：** 低频数据（先收敛，提供模糊预览）
- **AC 组：** 高频细节，按 256x256 瓦片存储
- **TOC 排列：** 重新排序 AC 组存储顺序——控制渐进加载时瓦片细节出现顺序
- **Lehmer 码：** JXL 在 TOC 头中用 Lehmer 码序列编码排列

**关键洞察：** JPEG XL 的 TOC 排列是渐进渲染优化的合法特性（优先重要区域）。作为隐写通道不可见——完全解码图像无差异。隐藏数据仅通过观察渐进收敛顺序显现，需要多点截断文件。

**检测：** JXL 文件渐进渲染时瓦片出现顺序异常（如拼出文本）。挑战提示“progressive”、“convergence”或“order matters”。

**参考：** BSidesSF 2026 “image-progress”

---
## Arnold's Cat Map 图像解扰 (Nuit du Hack 2017)

Arnold's Cat Map 是一种混沌的保持面积变换，具有周期性——迭代足够次数后会恢复原始图像。当图像看起来像被噪声样式扰乱但保持正确的尺寸和颜色直方图时，可以怀疑是 Cat Map 扰乱。

```python
from PIL import Image
import numpy as np

img = np.array(Image.open('scrambled.png'))
N = img.shape[0]  # 必须是正方形

def arnold_cat_map(image, n):
    """应用 Arnold's Cat Map 变换"""
    result = np.zeros_like(image)
    for x in range(n):
        for y in range(n):
            nx = (2*x + y) % n
            ny = (x + y) % n
            result[nx, ny] = image[x, y]
    return result

# 迭代直到恢复原始图像（周期依赖于 N）
current = img.copy()
for i in range(1, N * N):
    current = arnold_cat_map(current, N)
    Image.fromarray(current).save(f'frame_{i:04d}.png')
    # 检查是否已恢复原始图像（或人工视觉检查）
```

**关键洞察：** Arnold's Cat Map 具有周期性，对于大多数图像尺寸，周期是 `3*N` 的因数。迭代正向变换最终会恢复原始图像。对于大图像，建议通过计算矩阵特征值在 `Z/NZ` 中的阶的最小公倍数（lcm）来解析周期，而非暴力迭代所有次数。

**检测方法：** 正方形图像，看起来像均匀扰乱的噪声，但颜色分布合理。挑战中可能提及“cat”、“Arnold”、“chaotic”或“permutation”。

---

## 高分辨率 SSTV 自定义 FM 解调 (PlaidCTF 2017)

当 WAV 文件包含高于标准采样率的 SSTV 信号（例如 96kHz，而标准带宽约为 2.3kHz）时，标准 SSTV 解码器无法正确处理高频内容。此时需要使用自定义 FM 解调。

```python
# 方法1：GNU Radio
# Hilbert 变换 -> 正交解调 -> 低通滤波

# 方法2：手动 arccos + 求导（处理截断信号）
import numpy as np
from scipy.io import wavfile

rate, data = wavfile.read('signal.wav')
# 归一化到 [-1, 1]
data = data / np.max(np.abs(data))
# 限制到有效 arccos 范围
data = np.clip(data, -0.999, 0.999)
# 通过 arccos 求相位，再求导得到瞬时频率
phase = np.arccos(data)
freq = np.diff(phase) * rate / (2 * np.pi)
# 将频率映射到像素强度（1500-2300Hz 是典型 SSTV 频率范围）
pixels = np.clip((freq - 1500) / 800 * 255, 0, 255).astype(np.uint8)
```

**关键洞察：** 标准 SSTV 解码器（QSSTV、MMSSTV）假设带宽约为 2.3kHz。高采样率录音可能包含更宽带信号，标准解码器会截断。通过 `arccos` + 微分的手动 FM 解调（避免 Hilbert 变换在截断信号上的伪影）可以恢复完整频率范围。

**检测方法：** WAV 文件采样率异常高（48kHz、96kHz），标准 SSTV 解码器输出乱码或部分内容。频谱图显示频率调制信号结构。

---

## MJPEG FFD9 之后的额外字节隐写 (PoliCTF 2017)

MJPEG 视频帧在 JPEG 结束标记（FFD9）之后包含额外字节，利用这些填充字节隐藏数据。

```python
# 将 MJPEG 拆分为单独帧
frames = open('video.mjpeg', 'rb').read().split(b'\xff\xd8')

hidden = b""
for frame in frames:
    if not frame: continue
    frame = b'\xff\xd8' + frame
    # 查找 JPEG 结束标记
    eoi = frame.find(b'\xff\xd9')
    if eoi != -1:
        extra = frame[eoi + 2:]  # FFD9 之后的字节
        if extra:
            hidden += extra

print(hidden.decode(errors='ignore'))
```

**关键洞察：** JPEG 解码器在遇到 FFD9（图像结束）标记时停止，忽略后续字节。在 MJPEG 流中，每帧是完整 JPEG，若在每帧 FFD9 后附加额外字节，则形成视频播放器不可见的隐蔽通道。

**检测方法：** MJPEG 文件中单帧大小略大于预期。用 `binwalk` 扫描原始 MJPEG 可能显示重复 JPEG 头。十六进制查看时，FFD9 与下一个 FFD8 之间存在非零数据。

---

## EXIF Zlib 数据与非默认 LSB 像素模式 (ASIS CTF Finals 2017)

JPG 的 EXIF `ImageDescription` 字段包含 zlib 压缩后再 base64 编码的数据。通过 base64 解码后检测 `\x78\x9C` zlib 魔数。解压后提示使用 Stegano Python 库的 `triangular_numbers` 生成器进行非顺序像素选择（位置为 1, 3, 6, 10, ...）。

```bash
# 第一步：提取 EXIF ImageDescription
exiftool -ImageDescription image.jpg
# 或：
python3 -c "
from PIL import Image
img = Image.open('image.jpg')
desc = img._getexif()[270]  # 标签 270 = ImageDescription
print(repr(desc))
"

# 第二步：Base64 解码后 zlib 解压
python3 -c "
import base64, zlib
desc = '<exif_description_value>'
decoded = base64.b64decode(desc)
print(zlib.decompress(decoded).decode())
"

# 第三步：使用 Stegano 和 triangular_numbers 生成器提取隐藏数据
python3 -c "
from stegano import lsb
from stegano.lsb import generators
print(lsb.reveal('image.png', generators.triangular_numbers()))
"
```

**关键洞察：** 标准 LSB 工具（zsteg、stegsolve）无法处理非顺序像素模式。Stegano 库支持自定义生成器；务必检查 EXIF 元数据以获取使用哪种生成器的提示。`\x78\x9C` 是 deflate 压缩的魔数，是 zlib 压缩内容的可靠标志。

---

## PDF 交叉引用表隐蔽通道 (SEC-T CTF 2017)

PDF 的 xref 表条目通常使用生成号 0（活动对象）或 65535（空闲/删除）。非标准生成号用于编码数据：按顺序读取每个非零且非 65535 的生成号，按十六进制转 ASCII 字符（可能需要反转字符串）。

```bash
# 使用 pdf-parser.py 检查原始 xref 条目
python pdf-parser.py --stats suspicious.pdf
python pdf-parser.py --type /XRef suspicious.pdf

# 或直接读取原始 xref 表
python3 -c "
with open('suspicious.pdf', 'rb') as f:
    data = f.read().decode('latin-1')

# 查找 xref 段
xref_idx = data.rfind('xref')
xref_section = data[xref_idx:xref_idx+2000]
gen_numbers = []
for line in xref_section.splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[2] in ('n', 'f'):
        gen = int(parts[1])
        if gen not in (0, 65535):
            gen_numbers.append(gen)

# 将十六进制值转换为 ASCII
flag = bytes.fromhex(''.join(f'{g:02x}' for g in gen_numbers)).decode()
print(flag)
# 也尝试反转输出：print(flag[::-1])
"
```

**关键洞察：** PDF xref 生成号通常不被查看器严格验证，成为低噪声隐写通道。任何非 0（活动）或 65535（删除）的值都值得怀疑。使用 `pdf-parser.py --raw` 可查看未经解析器规范化的原始 xref 条目。

---
## 网络抓包中的 ANSI 转义码隐写术（Square CTF 2017）

网络数据包中包含 ANSI 转义序列（颜色码、光标移动）。使用原始十六进制和字符串工具查看时会显示乱码。将原始字节通过终端分页器（`more`、`less -r`）管道传输以渲染转义码——flag 会以彩色或定位文本形式显现。

```bash
# 提取原始 TCP 流负载
tshark -r capture.pcap -q -z "follow,tcp,raw,0" | \
  tail -n +7 | tr -d '\n' | xxd -r -p > stream.bin

# 渲染 ANSI 转义码（最简单方法）
more stream.bin
# 或者
cat stream.bin | less -r

# 另一种方法：直接提取数据字段
tshark -r capture.pcap -T fields -e data | xxd -r -p | more
```

需要识别的 ANSI 转义模式：
- `\x1b[<n>m` — 颜色/属性码
- `\x1b[<row>;<col>H` — 光标定位
- `\x1b[<n>A/B/C/D` — 光标移动（上/下/右/左）

**关键洞察：** ANSI 转义序列编码的视觉信息只有通过终端渲染才能显现。如果内容看起来像终端输出，务必尝试 `more` 或 `less -r`。光标定位序列可以拼出只有在终端上才正确显示的文本。

---

## 基于像素的 ECB 去重恢复图像（BackdoorCTF 2017）

一张图像通过将每个像素值替换为哈希值进行加密（ECB 模式像素加密）。由于像素值空间较小（灰度为 256，或有限调色板），可以预先计算哈希到像素的查找表，并将每个哈希值映射回原始像素。

```python
from PIL import Image
import hashlib

img = Image.open('encrypted.png').convert('L')  # 灰度图
pixels = list(img.getdata())

# 构建查找表：hash(pixel) -> 像素值
# 加密将每个唯一像素值映射到唯一哈希
# 由于空间小（256个值），枚举所有可能的原始值
lookup = {}
for original_val in range(256):
    # 确定使用的哈希函数（MD5、SHA1 等）
    h = hashlib.md5(bytes([original_val])).hexdigest()
    lookup[h] = original_val

# 重构：加密图像中的每个“像素”实际上是哈希索引
# 对于基于调色板的图像，映射颜色索引 -> 原始像素
unique_colors = list(set(pixels))
color_map = {}
for i, color in enumerate(unique_colors):
    # ECB：相同像素 -> 相同密文值
    # 统计唯一值以确认空间小
    pass

# 更简单：如果加密值是小整数（0-255 重映射）
# 结构被保留——只需找到正确的排列
reconstructed = Image.new('L', img.size)
# 使用查找表映射每个加密值回原始值
```

**关键洞察：** ECB 模式像素加密通过相同明文像素对应相同密文泄露结构。灰度值仅有 256 种可能，预计算完整查找表非常简单。加密图像会显示与原图相同的形状/边缘，结构可识别，确认了 ECB 模式。

---

## 多色 QR 码二进制映射暴力破解（STEM CTF 2019）

**模式：** 一个类似 QR 的图像使用 N 种颜色而非黑白。有效 QR 码只需两种状态（黑=1，白=0），因此每种颜色必须映射到其中之一。对于 N 个非平凡颜色，遍历所有 2^N 种二进制划分并尝试解码每个候选。典型 N=6 产生 64 个候选；其中 3 个通常能解码（QR 码的冗余纠错机制）。

```python
from PIL import Image
from itertools import product
import subprocess, os

img = Image.open('QvR.png').convert('RGB')
px = img.load()
w, h = img.size

# 收集不同的非纯色（忽略黑白，因为它们无歧义）
palette = set()
for y in range(h):
    for x in range(w):
        c = px[x, y]
        if c not in ((0, 0, 0), (255, 255, 255)):
            palette.add(c)
palette = sorted(palette)                       # 确定顺序
print(f'{len(palette)} 个可变颜色 -> {2**len(palette)} 次尝试')

for bits in product([0, 1], repeat=len(palette)):
    mapping = dict(zip(palette, bits))
    out = Image.new('1', (w, h), 1)
    op = out.load()
    for y in range(h):
        for x in range(w):
            c = px[x, y]
            if c == (0, 0, 0):       v = 0
            elif c == (255, 255, 255): v = 1
            else:                     v = mapping[c]
            op[x, y] = v
    fn = f'try_{"".join(map(str, bits))}.png'
    out.save(fn)
    r = subprocess.run(['zbarimg', '-q', fn], capture_output=True, text=True)
    if r.stdout.strip():
        print(fn, '->', r.stdout.strip())
```

**关键洞察：** QR 码严格是二值的——任何“看起来像”QR 的多色图像都隐藏了一个 2^N 的着色映射。由于 QR 码有强大的 Reed-Solomon 纠错，多种划分都能解码（每个划分在同一物理网格中携带不同信息）。务必尝试所有 2^N 种映射；当 N<=8 时暴力破解开销极小，`zbarimg` 会自动筛选有效结果。

**参考资料：** STEM CTF: Cyber Challenge 2019 — QvR Code，writeup 13375
