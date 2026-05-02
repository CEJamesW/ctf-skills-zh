# CTF Forensics - 高级隐写术

另见：[stego-advanced-2.md](stego-advanced-2.md) 涉及视频帧技术、JPEG XL TOC 置换、Arnold 猫映射、SSTV 调频解调、MJPEG 隐写、EXIF/隐写像素模式、PDF xref 隐蔽通道、ANSI 转义码隐写和 ECB 图像恢复。

## 目录
- [FFT 频域隐写术 (Pragyan 2026)](#fft-frequency-domain-steganography-pragyan-2026)
- [SSTV 诱饵 + LSB 音频隐写 (0xFun 2026)](#sstv-red-herring--lsb-audio-stego-0xfun-2026)
- [通过 SSTV 的 DotCode 条码 (0xFun 2026)](#dotcode-barcode-via-sstv-0xfun-2026)
- [DTMF 音频解码](#dtmf-audio-decoding)
- [自定义频率 DTMF / 双音键盘编码 (EHAX 2026)](#custom-frequency-dtmf--dual-tone-keypad-encoding-ehax-2026)
- [多轨音频差分相减 (EHAX 2026)](#multi-track-audio-differential-subtraction-ehax-2026)
- [跨通道多比特 LSB 隐写 (ApoorvCTF 2026)](#cross-channel-multi-bit-lsb-steganography-apoorvctf-2026)
- [音频 FFT 音符识别 (BYPASS CTF 2025)](#audio-fft-musical-note-identification-bypass-ctf-2025)
- [音频元数据八进制编码 (BYPASS CTF 2025)](#audio-metadata-octal-encoding-bypass-ctf-2025)
- [带空白符编码的嵌套 Tar 归档 (UTCTF 2026)](#nested-tar-archive-with-whitespace-encoding-utctf-2026)
- [DeepSound 音频隐写及密码破解 (INShAck 2018)](#deepsound-audio-steganography-with-password-cracking-inshack-2018)
- [音频波形二进制编码 (BackdoorCTF 2013)](#audio-waveform-binary-encoding-backdoorctf-2013)
- [音频频谱隐藏二维码 (BaltCTF 2013)](#audio-spectrogram-hidden-qr-code-baltctf-2013)
- [字节反转 .docx ZIP 双向归档 (Security Fest CTF 2018)](#byte-reversed-docx-zip-bidirectional-archive-security-fest-ctf-2018)
- [MIDI Note-On/Note-Off 音高对编码 (X-MAS CTF 2018)](#midi-note-onnote-off-pitch-pair-encoding-x-mas-ctf-2018)

---

## FFT 频域隐写术 (Pragyan 2026)

**模式 (H@rDl4u6H)：** 图像通过二维 FFT 在频域中编码数据。

**解码流程：**
```python
import numpy as np
from PIL import Image

img = np.array(Image.open("image.png")).astype(float)
F = np.fft.fftshift(np.fft.fft2(img))
mag = np.log(1 + np.abs(F))

# 寻找模式：同心圆环，特定位置的点
# 亮峰 = 0 位，暗（无峰）= 1 位
cy, cx = mag.shape[0]//2, mag.shape[1]//2
radii = [100 + 69*i for i in range(21)]  # 示例间距
angles = [0, 22.5, 45, 67.5, 90, 112.5, 135, 157.5]
THRESHOLD = 13.0

bits = []
for r in radii:
    byte_val = 0
    for a in angles:
        fx = cx + r * np.cos(np.radians(a))
        fy = cy - r * np.sin(np.radians(a))
        bit = 0 if mag[int(round(fy)), int(round(fx))] > THRESHOLD else 1
        byte_val = (byte_val << 1) | bit
    bits.append(byte_val)
```

**识别提示：** 题目提到“变换”，诗中提及“频率”，或图像看起来空白/噪声。优先尝试 FFT 可视化。

---

## SSTV 诱饵 + LSB 音频隐写 (0xFun 2026)

**模式 (Melodie)：** WAV 文件包含 SSTV 信号（Scottie 1），解码为“SEEMS LIKE A DEADEND”。真正的 flag 藏在音频样本的 2 位 LSB 中。

```bash
# 解码 SSTV（诱饵）
qsstv  # 会显示假消息

# 从 LSB 提取真正的 flag
pip install stego-lsb
stegolsb wavsteg -r -i audio.wav -o out.bin -n 2 -b 1000
```

**教训：** 明显信号可能是诱饵。即使发现其他编码，也要检查 LSB。 

---
## DotCode 条形码通过 SSTV (0xFun 2026)

**模式（点阵）：** SSTV 解码产生点阵图像。不是二维码 — 它是 DotCode 格式。

**识别：** 点阵图案不是标准二维码。DotCode 是一种针对高速打印优化的二维条码。

**工具：** Aspose 在线 DotCode 读取器（免费）。

---

## DTMF 音频解码

**模式（电话拨号）：** 音频文件包含电话拨号音，编码数据。

```bash
# 解码 DTMF 音调
sox phonehome.wav -t raw -r 22050 -e signed-integer -b 16 -c 1 - | \
    multimon-ng -t raw -a DTMF -
```

**后处理：** 电话号码可能在分隔符 (#) 后包含八进制编码的 ASCII：
```python
# 将八进制组转换为 ASCII
octal_groups = ["115", "145", "164", "141"]  # M, e, t, a
flag = ''.join(chr(int(g, 8)) for g in octal_groups)
```

---

## 自定义频率 DTMF / 双音键盘编码 (EHAX 2026)

**模式（量子消息）：** 音频包含非标准频率的双音序列，按固定间隔排列（例如每秒一次）。提示中提到“谐振振荡器”或物理学，指向自定义频率设计。

**识别：** 频谱图显示两组不同频率，不符合标准 DTMF（697-1633 Hz）。寻找频率音调均匀排列的行/列。

**解码流程：**
```python
import numpy as np
from scipy.io import wavfile

rate, audio = wavfile.read('challenge.wav')

# 1. 生成频谱图以识别频率网格
# 使用 ffmpeg: ffmpeg -i challenge.wav -lavfi showspectrumpic=s=1920x1080 spec.png

# 2. 将频率映射到键盘（自定义网格，非标准 DTMF）
# 例如：行 = [301, 902, 1503, 2104] Hz，列 = [2705, 3306, 3907] Hz
# 形成 4x3 键盘 -> 数字 0-9 + 符号

# 3. 按时间窗口提取音调对
window_size = rate  # 每符号 1 秒
for i in range(0, len(audio), window_size):
    segment = audio[i:i+window_size]
    freqs = np.fft.rfftfreq(len(segment), 1/rate)
    magnitude = np.abs(np.fft.rfft(segment))
    # 找到两个主峰 -> 映射到行/列 -> 数字

# 4. 将数字序列转换为 ASCII
# 将数字拆分为可变长度组（ASCII 范围 32-126）
# 例如 "72101108108111" -> [72, 101, 108, 108, 111] -> "Hello"
def digits_to_ascii(digits):
    result, i = [], 0
    while i < len(digits):
        for length in [2, 3]:  # ASCII 码为 2-3 位数字
            if i + length <= len(digits):
                val = int(digits[i:i+length])
                if 32 <= val <= 126:
                    result.append(chr(val))
                    i += length
                    break
        else:
            i += 1
    return ''.join(result)
```

**关键点：** 当音调不符合标准 DTMF 频率时，先生成频谱图识别自定义频率网格。映射关系依挑战而异。

---

## 多轨音频差分相减 (EHAX 2026)

**模式（企鹅）：** MKV/视频文件包含两个几乎相同的音轨。隐藏数据作为两轨间微小差异嵌入，单独听任一轨道时不可察觉。

**识别：**
- `ffprobe` 显示多个音频流（例如两个立体声 FLAC 音轨）
- 元数据可能包含诱饵 flag（如注释中）
- 轨道标签可能误导（如立体声标为“5.1 环绕声”）
- `sox --info` / `sox -n stat` 显示两轨 RMS、振幅和频率统计几乎相同

**提取流程：**
```bash
# 1. 提取两个音轨
ffmpeg -i challenge.mkv -map 0:a:0 -c copy track0.flac
ffmpeg -i challenge.mkv -map 0:a:1 -c copy track1.flac

# 2. 转换为 WAV 以便处理
ffmpeg -i track0.flac track0.wav
ffmpeg -i track1.flac track1.wav

# 3. 相减：反相一轨并混合（抵消共有内容）
sox -m track0.wav "|sox track1.wav -p vol -1" diff.wav

# 4. 归一化差分信号
sox diff.wav diff_norm.wav gain -n -3

# 5. 生成频谱图读取 flag
sox diff_norm.wav -n spectrogram -o spectrogram.png -X 2000 -Y 1000 -z 100 -h

# 6. 可选：滤波隔离 flag 频段
sox diff_norm.wav filtered.wav sinc 5000-12000
sox filtered.wav -n spectrogram -o filtered_spec.png -X 2000 -Y 1000 -z 100 -h
```

**关键点：** 当两音轨几乎相同时，反相混合相减可抵消共有内容，隔离隐藏数据。flag 通常以文本形式编码在差分信号的频谱图中，显示在特定频段（如 5-12 kHz）。

**常见陷阱：**
- 元数据/注释中的诱饵 flag — 始终验证
- 错误标注的声道配置（立体声标为 5.1）
- flag 可能只在狭窄时间窗口可见 — 使用高分辨率频谱图（`-X 2000+`）

---
## Cross-Channel Multi-Bit LSB Steganography (ApoorvCTF 2026)

**模式（Beneath the Armor）：** 标准的 LSB 工具（zsteg、stegsolve）失效，因为每个 RGB 通道使用不同的位位置：红色通道位 0，绿色通道位 1，蓝色通道位 2。

```python
from PIL import Image

img = Image.open("challenge.png")
pixels = img.load()
bits = []
for y in range(img.height):
    for x in range(img.width):
        r, g, b = pixels[x, y][:3]
        bits.append((r >> 0) & 1)  # 红色：位 0
        bits.append((g >> 1) & 1)  # 绿色：位 1
        bits.append((b >> 2) & 1)  # 蓝色：位 2

# 每像素打包 3 位成字节
data = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    data.append(byte)
print(data.decode('ascii', errors='ignore'))
```

**关键洞察：** 当标准 LSB 工具无结果时，数据可能在每个通道使用不同的位位置。提示“cycles”或“modular”暗示在通道间循环使用位位置（0→1→2）。总是尝试非标准的位组合：R[0]G[1]B[2]，R[1]G[2]B[0]，R[2]G[0]B[1] 等。

**检测：** 标准的 `zsteg -a` 和 `stegsolve` 在元数据提示含隐藏数据的图像上无结果。

---

## Audio FFT Musical Note Identification (BYPASS CTF 2025)

**模式（Piano）：** 通过 FFT（快速傅里叶变换）识别主导频率，映射到音乐音符（A-G），然后将字母名读作单词。

**技术：** 对音频执行 FFT，识别主导频率，映射到音乐音符。

```python
import numpy as np
from scipy.io import wavfile

rate, audio = wavfile.read('challenge.wav')
if audio.ndim > 1:
    audio = audio[:, 0]  # 单声道

# FFT 找主导频率
freqs = np.fft.rfftfreq(len(audio), 1/rate)
magnitude = np.abs(np.fft.rfft(audio))

# 找前 20 个峰值
peak_indices = np.argsort(magnitude)[-20:]
peak_freqs = sorted(set(round(freqs[i]) for i in peak_indices if freqs[i] > 20))

# 音符频率映射（A4 = 440 Hz）
NOTE_FREQS = {
    'C4': 261.63, 'D4': 293.66, 'E4': 329.63, 'F4': 349.23,
    'G4': 392.00, 'A4': 440.00, 'B4': 493.88,
    'C5': 523.25, 'D5': 587.33, 'E5': 659.25, 'F5': 698.46,
    'G5': 783.99, 'A5': 880.00, 'B5': 987.77,
}

def freq_to_note(freq):
    return min(NOTE_FREQS.items(), key=lambda x: abs(x[1] - freq))[0]

notes = [freq_to_note(f) for f in peak_freqs]
# 提取字母名：B, A, D, F, A, C, E → "BADFACE"
answer = ''.join(n[0] for n in notes)
print(f"Notes: {notes}")
print(f"Answer: {answer}")
```

**提取并检查音频元数据**，使用 `exiftool audio.mp3` 查找注释字段中的编码提示（例如八进制分隔值 → base64 → 解码提示）。

**关键洞察：** 音符名（A-G）可以拼成单词。当挑战涉及音乐/钢琴时，通过 FFT 识别主导频率并将音符字母名读作文本。

---

## Audio Metadata Octal Encoding (BYPASS CTF 2025)

**模式（Piano metadata）：** 音频文件元数据（exiftool 注释字段）包含下划线分隔的数字，表示八进制编码的 ASCII 值（仅包含数字 0-7）。

```python
# 提取并解码八进制元数据
import subprocess, base64

# 获取元数据注释
comment = "103_137_63_157_144_145_144_40_162_145_154_151_143"
octal_values = comment.split('_')
decoded = ''.join(chr(int(v, 8)) for v in octal_values)

# 可能解码为 base64，需要再解一层
result = base64.b64decode(decoded).decode()
print(result)
```

**关键洞察：** 当元数据包含下划线分隔的数字时，尝试八进制（仅数字 0-7）、十进制或十六进制解释。多层编码（八进制 → base64 → 明文）很常见。

---
## 嵌套 Tar 归档与空白字符编码 (UTCTF 2026)

**模式（Silent Archive）：** 深度嵌套的 tar 归档，数据通过文件名或内容中的空白字符（空格、制表符、换行符）进行编码。

**检测方法：** 归档解压后得到另一个归档（tar-in-tar 链）。文件内容看似为空，但包含不可见的空白字符。

**解码流程：**
```python
import tarfile
import os

# 1. 递归解压嵌套的 tar 归档
def extract_all(path, depth=0):
    if depth > 100:  # 防止无限嵌套
        return
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as tf:
            tf.extractall(f'layer_{depth}')
            for member in tf.getmembers():
                extract_all(f'layer_{depth}/{member.name}', depth + 1)

# 2. 从文件名或内容中收集空白字符
whitespace_data = []
for root, dirs, files in os.walk('layer_0'):
    for f in files:
        path = os.path.join(root, f)
        with open(path, 'rb') as fh:
            content = fh.read()
            # 检查是否仅包含空白字符
            if content.strip() == b'':
                for byte in content:
                    if byte == 0x20:  # 空格
                        whitespace_data.append('0')
                    elif byte == 0x09:  # 制表符
                        whitespace_data.append('1')

# 3. 将空白字符转换为二进制
bits = ''.join(whitespace_data)
message = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
print(message.decode(errors='replace'))
```

**空白字符编码变体：**
- 空格 = 0，制表符 = 1（二进制编码）
- 空白隐写术：行尾的空格/制表符
- Unicode 文本中的零宽字符（U+200B、U+200C、U+FEFF）
- 单词间空格数量编码数据

**关键洞察：** “静默”或“不可见”的提示指向空白字符编码。使用 `xxd` 或 `cat -A` 来显示隐藏的空白字符。深度嵌套的归档是误导——数据在空白字符中，而非嵌套深度。

---

## DeepSound 音频隐写与密码破解 (INShAck 2018)

**模式：** 两阶段音频隐写：第一部分在 Audacity 频谱图中可见，第二部分用 DeepSound 工具隐藏（密码保护）。使用 `deepsound2john.py` 提取哈希，用 John 破解密码，然后提取隐藏文件。

```bash
# 阶段 1：检查频谱图中的可见文本
sox audio.wav -n spectrogram -o spec.png

# 阶段 2：提取 DeepSound 密码哈希
python3 deepsound2john.py audio.wav > hash.txt

# 破解密码
john --wordlist=rockyou.txt hash.txt

# 使用 DeepSound GUI 或命令行工具和破解的密码提取隐藏文件
```

**DeepSound 检测：**
```python
# DeepSound 在 WAV 文件中嵌入签名
# 检查音频数据中的 DeepSound 头部模式
with open('audio.wav', 'rb') as f:
    data = f.read()
    # DeepSound 在音频数据部分使用特定字节模式
    # John the Ripper bleeding-jumbo 分支中的 deepsound2john.py
    # 自动处理检测和哈希提取
```

**工具安装：**
```bash
# deepsound2john.py 是 John the Ripper bleeding-jumbo 的一部分
git clone https://github.com/openwall/john.git
# 脚本位置：john/run/deepsound2john.py

# DeepSound GUI（Windows）：http://jpinsoft.net/deepsound/
# Linux 用户可在 Wine 下运行，或使用提取的哈希配合 john 破解
```

**关键洞察：** DeepSound 将文件嵌入 WAV 音频中，支持可选 AES 加密。密码哈希可用 John the Ripper bleeding-jumbo 分支的 `deepsound2john.py` 提取。音频挑战中应同时检查频谱图（视觉隐写）和 DeepSound（数据隐写）。

**检测方法：** WAV 文件看似正常，但 `deepsound2john.py` 能生成哈希。挑战通常有两部分结构，第一部分简单（频谱图），第二部分需用工具破解。挑战描述中可能提到“层”、“隐藏”或“深度”。 

---
## 音频波形二进制编码 (BackdoorCTF 2013)

**模式：** WAV 文件包含两种不同的波形形状，分别代表二进制的 0 和 1。将 8 位分组为字节并解码为 ASCII。

```python
import wave, struct
wf = wave.open('audio.wav', 'rb')
frames = wf.readframes(wf.getnframes())
samples = struct.unpack(f'{len(frames)//2}h', frames)

# 识别两种不同的波形模式（例如，正峰与平坦）
# 将音频分割为固定长度的窗口，分类每个窗口为 0 或 1
bits = ''
window = len(samples) // num_bits
for i in range(num_bits):
    segment = samples[i*window:(i+1)*window]
    bits += '1' if max(segment) > threshold else '0'

# 将二进制解码为 ASCII
flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-7, 8))
```

**关键洞察：** 用 Audacity 打开并放大——两种视觉上明显不同的波形交替出现。每种波形代表一位。统计波形，分组为 8 位字节，解码为 ASCII。

---

## 音频频谱图隐藏二维码 (BaltCTF 2013)

**模式：** 音频文件在频域中隐藏视觉数据，仅在频谱图视图中可见。

```bash
# 生成频谱图图片
sox audio.mp3 -n spectrogram -o spec.png
# 或使用 Sonic Visualiser 进行交互式探索

# 在特定频段（通常 5-12 kHz）寻找视觉模式
# 从频谱图中提取/拼接二维码碎片
# 使用：zbarimg assembled_qr.png 扫描
```

**关键洞察：** 使用 Sonic Visualiser（图层 → 添加频谱图），可调节窗口大小和色彩映射。二维码或文本通常出现在 2-15 kHz 频段。多个频谱图碎片可能需要在图像编辑器中拼接后再扫描。

---

## 字节反转的 .docx ZIP 双向归档 (Security Fest CTF 2018)

**模式（Zion）：** 分发的文件是有效的 `.docx`（ZIP 归档）。正常解压只看到一个诱饵文档。将整个文件字节反转后，结果仍是一个有效的 ZIP 归档——包含第二个 `word/media/*.png`，其内容即为 flag。

**提取：**
```bash
# 验证正向归档
unzip -l doc.docx

# 反转字节流并解压镜像归档
python3 -c "import sys;sys.stdout.buffer.write(open('doc.docx','rb').read()[::-1])" > mirror.zip
unzip -l mirror.zip
unzip mirror.zip 'word/media/*' -d mirror/
```

**为何双向都能成功：** ZIP 的中央目录位于归档末尾，本地文件头仅通过该目录中的偏移量解析。通过在文件开头放置第二组本地文件头，并在反转后末尾放置匹配的中央目录，文件在两种读取顺序下均符合 ZIP 规范。Python 的 `zipfile` 和 `unzip -l` 从尾部读取中央目录，因此无论哪端先出现都能正常打开。

**关键洞察：** 当前向解压仅得诱饵时，务必测试容器文件的字节反转、位反转和字节交错。对正向和反转文件都运行 `binwalk`，以发现任一方向隐藏的嵌入归档。此技巧适用于任何解析器容忍尾部垃圾的格式（ZIP、RAR、PDF、tar）。

**参考：** Security Fest CTF 2018 — writeup 10204

---

## MIDI Note-On/Note-Off 音高对编码 (X-MAS CTF 2018)

**模式：** MIDI 文件播放无明显旋律，但严格交替出现 Note-On/Note-Off。隐藏信息按每对一字节拆分：`ord(char) = note_on_pitch + note_off_pitch`。有时编码为高低半字节：`ord(char) = (on << 4) | off`。

```python
import mido
mid = mido.MidiFile('hidden.mid')
ons, offs = [], []
for ev in mid.tracks[0]:
    if ev.type == 'note_on':   ons.append(ev.note)
    elif ev.type == 'note_off': offs.append(ev.note)
flag = ''.join(chr(o + f) for o, f in zip(ons, offs))
```

**关键洞察：** MIDI 音高值为 7 位（0..127），任何字节都可拆分为两个音符。当 MIDI 听起来“无调”但严格遵守音符对交替时，尝试 `on + off`、`(on<<4)|off`、`off - on` 和异或组合，方可确认是否为音频隐写。

**参考：** X-MAS CTF 2018 — A Christmas Carol，writeup 12667

---
