# CTF Forensics - 信号与硬件

## 目录
- [VGA 信号解码](#vga-信号解码)
- [HDMI TMDS 解码](#hdmi-tmds-解码)
- [DisplayPort 8b/10b + LFSR 解码](#displayport-8b10b--lfsr-解码)
- [Voyager 金唱片音频 (0xFun 2026)](#voyager-金唱片音频-0xfun-2026)
- [侧信道功率分析 (EHAX 2026)](#侧信道功率分析-ehax-2026)
- [Saleae Logic 2 UART 解码 (EHAX 2026)](#saleae-logic-2-uart-解码-ehax-2026)
- [Flipper Zero .sub 文件 (0xFun 2026)](#flipper-zero-sub-文件-0xfun-2026)
- [键盘声学侧信道 (ApoorvCTF 2026)](#键盘声学侧信道-apoorvctf-2026)
- [CD 音频光盘镜像隐写 (BSidesSF 2026)](#cd-音频光盘镜像隐写-bsidessf-2026)
- [大写锁定 LED 摩尔斯码视频提取 (STEM CTF 2018)](#大写锁定-led-摩尔斯码视频提取-stem-ctf-2018)
- [Linux input_event 键盘记录器转储解析 (Pwn2Win 2016)](#linux-input_event-键盘记录器转储解析-pwn2win-2016)
- [I2C 总线协议解码 (EKOPARTY CTF 2016)](#i2c-总线协议解码-ekoparty-ctf-2016)
- [IBM-29 打孔卡 OCR (EKOPARTY CTF 2016)](#ibm-29-打孔卡-ocr-ekoparty-ctf-2016)
- [从 WAV 音频解码串行 UART 数据 (EasyCTF 2017)](#从-wav-音频解码串行-uart-数据-easyctf-2017)
- [USB MIDI Launchpad 流量重构 (Sthack 2017)](#usb-midi-launchpad-流量重构-sthack-2017)
- [Tektronix 逻辑分析仪 CSV 时钟边沿提取 (35C3 2018)](#tektronix-逻辑分析仪-csv-时钟边沿提取-35c3-2018)

---

## VGA 信号解码

**帧结构：** 总计 800x525（640x480 有效区域 + 空白区）。每个采样 = 5 字节：R, G, B, HSync, VSync。颜色为 6 位（0-63）。

```python
import numpy as np
from PIL import Image

data = open('vga.bin', 'rb').read()

TOTAL_W, TOTAL_H = 800, 525
ACTIVE_W, ACTIVE_H = 640, 480
BYTES_PER_SAMPLE = 5  # R, G, B, hsync, vsync

# 解析原始采样
samples = np.frombuffer(data, dtype=np.uint8).reshape(-1, BYTES_PER_SAMPLE)
frame = samples.reshape(TOTAL_H, TOTAL_W, BYTES_PER_SAMPLE)

# 提取有效区域，将 6 位色彩扩展到 8 位
active = frame[:ACTIVE_H, :ACTIVE_W, :3]  # 仅 RGB
img_arr = (active.astype(np.uint16) * 4).clip(0, 255).astype(np.uint8)
Image.fromarray(img_arr).save('vga_output.png')
```

**关键点：** 总帧尺寸大于可见区域 — 始终裁剪空白区。如果颜色看起来较暗，检查是否为 6 位色（乘以 4）。

---

## HDMI TMDS 解码

**结构：** 3 个通道（R、G、B），每个编码为 10 位 TMDS（过渡最小化差分信号）符号。第 9 位为反转标志，第 8 位为 XOR/XNOR 模式。解码从最高有效位开始确定。

```python
def tmds_decode(symbol_10bit):
    """将 10 位 TMDS 符号解码为 8 位像素值。"""
    bits = [(symbol_10bit >> i) & 1 for i in range(10)]
    # bits[9] = 反转标志, bits[8] = XOR/XNOR 模式

    # 第一步：撤销可选反转（第 9 位）
    if bits[9]:
        d = [1 - bits[i] for i in range(8)]
    else:
        d = [bits[i] for i in range(8)]

    # 第二步：撤销 XOR/XNOR 链（第 8 位选择模式）
    q = [d[0]]
    if bits[8]:
        for i in range(1, 8):
            q.append(d[i] ^ q[i-1])        # XOR 模式
    else:
        for i in range(1, 8):
            q.append(d[i] ^ q[i-1] ^ 1)    # XNOR 模式

    return sum(q[i] << i for i in range(8))

# 解析：从二进制读取 10 位符号，分组为 3 个通道
# 帧尺寸为 800x525，总尺寸，裁剪为 640x480 有效区域
```

**识别提示：** 二进制数据具有 10 位对齐结构。题目提及 HDMI、DVI 或 TMDS。

---

## DisplayPort 8b/10b + LFSR 解码

**结构：** 10 位 8b/10b 符号解码为 8 位数据，随后进行 LFSR 解扰。以 64 列传输单元组织（60 列数据 + 4 列开销）。

```python
# 标准 8b/10b 解码表（部分 — 完整表有 256 条目）
# 使用预构建表：映射 10 位符号 -> 8 位数据
# 关键：运行差异跟踪直流平衡

# LFSR 解扰器 (x^16 + x^5 + x^4 + x^3 + 1)
def lfsr_descramble(data):
    """DisplayPort LFSR 解扰器。控制符号（BS/BE）时重置。"""
    lfsr = 0xFFFF  # 初始状态
    result = []
    for byte in data:
        out = byte
        for bit_idx in range(8):
            feedback = (lfsr >> 15) & 1
            out ^= (feedback << bit_idx)
            new_bit = ((lfsr >> 15) ^ (lfsr >> 4) ^ (lfsr >> 3) ^ (lfsr >> 2)) & 1
            lfsr = ((lfsr << 1) | new_bit) & 0xFFFF
        result.append(out & 0xFF)
    return bytes(result)

# 传输单元布局：每个 TU 64 列
# 列 0-59：像素数据（RGB）
# 列 60-63：开销（同步、填充）
# LFSR 在控制字节（BS=0x1C, BE=0xFB）时重置
```

**关键点：** LFSR 加扰器在控制字节时重置 — 识别这些字节以同步解扰。无重置点时输出混乱。

---

## Voyager 金唱片音频 (0xFun 2026)

**模式（11 条接触线）：** 模拟图像编码为音频。同步脉冲（尖锐负脉冲）分隔扫描线。脉冲间幅度表示像素亮度。

```python
import numpy as np
from scipy.io import wavfile
from PIL import Image

rate, audio = wavfile.read('golden_record.wav')
audio = audio.astype(np.float32)

# 查找同步脉冲（低于阈值的尖锐负脉冲）
threshold = np.min(audio) * 0.7
sync_indices = np.where(audio < threshold)[0]

# 将连续同步采样分组为脉冲起点
pulses = [sync_indices[0]]
for i in range(1, len(sync_indices)):
    if sync_indices[i] - sync_indices[i-1] > 100:
        pulses.append(sync_indices[i])

# 提取脉冲间扫描线，重采样为固定宽度
WIDTH = 512
lines = []
for i in range(len(pulses) - 1):
    line = audio[pulses[i]:pulses[i+1]]
    resampled = np.interp(np.linspace(0, len(line)-1, WIDTH), np.arange(len(line)), line)
    lines.append(resampled)

# 归一化并保存为图像
img_arr = np.array(lines)
img_arr = ((img_arr - img_arr.min()) / (img_arr.max() - img_arr.min()) * 255).astype(np.uint8)
Image.fromarray(img_arr).save('voyager_image.png')
```

---
## Side-Channel Power Analysis (EHAX 2026)

**模式（功耗泄露）：** 在加密操作期间记录的功耗轨迹。正确的密钥猜测会在特定采样点导致可测量的功耗差异。

**数据格式：** 通常是多维数组：`[positions × guesses × traces × samples]`。例如，6 个数字位置 × 10 个猜测（0-9）× 20 条轨迹 × 50 个采样点。

**攻击（差分功耗分析）：**
```python
import numpy as np
import hashlib

# 加载功耗轨迹：形状 = (positions, guesses, traces, samples)
data = np.load('power_traces.npy')  # 或从 CSV/JSON 解析
n_positions, n_guesses, n_traces, n_samples = data.shape

# 对每个位置，找到在泄露点功耗最大的猜测
key_digits = []
for pos in range(n_positions):
    # 对每个猜测在所有轨迹上求平均
    avg_power = data[pos].mean(axis=1)  # 形状: (guesses, samples)

    # 找到在猜测间功耗方差最大的采样点
    # 该点为“泄露点”，正确猜测在此处最明显
    variance_per_sample = avg_power.var(axis=0)
    leak_sample = np.argmax(variance_per_sample)

    # 在泄露点功耗最大的猜测即为正确猜测
    best_guess = np.argmax(avg_power[:, leak_sample])
    key_digits.append(best_guess)

key = ''.join(str(d) for d in key_digits)
print(f"Recovered key: {key}")

# Flag 可能是密钥的 SHA256
flag = hashlib.sha256(key.encode()).hexdigest()
```

**识别：** 题目提及“power”、“side-channel”、“leakage”、“traces”或“measurements”。数据为多维数值数组，轴分别对应位置/猜测/轨迹/采样。

**关键洞察：** “泄露点”是正确与错误猜测功耗差异最大的采样索引。先对轨迹求平均以降低噪声，再找猜测间方差最大的采样点。

---

## Saleae Logic 2 UART Decode (EHAX 2026)

**模式（Baby Serial）：** Saleae Logic 2 `.sal` 文件（ZIP 压缩包），包含数字通道采样。数据以 UART 串口编码。

**文件结构：** `.sal` 是包含 `digital-0.bin` 到 `digital-7.bin` 以及 `meta.json` 的 ZIP 文件。通常只有通道 0 有数据。

**二进制格式（digital-*.bin）：**
```text
<SALEAE> 魔数（8 字节）
version: u32 = 2
type: u32 = 100（数字信号）
initial_state: u32（0 或 1）
... 头部字段 ...
增量编码的状态转换（变长整数）
```

**增量编码：** 每个值表示状态转换之间的采样数。信号在每个增量处在高电平和低电平间交替。

**基于增量的 UART 解码：**
```python
import numpy as np

# 从二进制（头部之后）解析增量
# 重建信号时间线
times = np.cumsum(deltas)
states = []
state = initial_state
for d in deltas:
    states.append(state)
    state ^= 1  # 每次转换切换状态

# UART 解码：检测起始位（高→低），在位中心采样 8 个数据位
# 波特率检测：最常见的增量 ≈ 每位采样数
# 1MHz 采样率下：115200 波特率 ≈ 8.7 采样/位

def uart_decode(transitions, sample_rate=1_000_000, baud=115200):
    bit_period = sample_rate / baud
    bytes_out = []
    i = 0
    while i < len(transitions):
        # 找起始位（下降沿）
        if transitions[i] == 0:  # 低电平 = 起始位
            byte_val = 0
            for bit in range(8):
                sample_time = (1.5 + bit) * bit_period  # 每个位中心
                # 在起始位偏移处采样信号
                bit_val = get_signal_at(sample_time)
                byte_val |= (bit_val << bit)  # 低位优先
            bytes_out.append(byte_val)
        i += 1
    return bytes(bytes_out)
```

**常见陷阱：**
- **极性反转：** UART 空闲为高电平（mark）。若 initial_state=1，编码可能反转——两种情况都试试
- **波特率猜测：** 检查常见波特率：9600、19200、38400、57600、115200、230400
- **输出格式：** 解码字节可能是 base64 编码（包含 PNG 图片或文本）
- **Saleae 内部格式 ≠ 导出格式：** `.sal` 内部二进制编码与 CSV/二进制导出不同。直接解析原始增量转换

**快速方法：** 安装 Saleae Logic 2，打开 `.sal` 文件，添加 UART 分析器并自动波特率检测，导出解码数据。

---

## Flipper Zero .sub File (0xFun 2026)

RAW_Data 二进制 -> 过滤噪声字节（0x80-0xFF）-> 展开批量变量引用 -> 与提示文本异或。

**关键洞察：** Flipper Zero `.sub` 文件包含原始射频信号数据。RAW_Data 字段以脉冲时序编码二进制。过滤噪声字节（0x80-0xFF），展开任何批量变量引用，并与题目提示文本异或以恢复 flag。

---

## Keyboard Acoustic Side-Channel (ApoorvCTF 2026)

**模式（Author on the Run）：** 从按键音频录音中恢复输入文本。参考音频提供带标签样本（已知按键），flag 音频包含未知按键需分类。

**步骤 1 — 通过能量峰值检测按键：**
```python
import numpy as np
from scipy.signal import find_peaks
from scipy.io import wavfile

sr, audio = wavfile.read('flag.wav')
if audio.ndim > 1:
    audio = audio.mean(axis=1)

# 滑动窗口能量包络（10ms 窗口）
win = int(0.01 * sr)
energy = np.array([np.sum(audio[i:i+win]**2) for i in range(0, len(audio) - win, win)])

# 寻找峰值，最小间隔 175ms
min_dist = int(0.175 * sr / win)
peaks, _ = find_peaks(energy, height=0.03 * energy.max(), distance=min_dist)
```

**步骤 2 — 提取每次按键的 MFCC 特征：**
```python
import librosa

def extract_features(audio, sr, peak_sample, window_ms=10):
    win = int(window_ms / 1000 * sr)
    start = max(0, peak_sample - win // 2)
    segment = audio[start:start + win]
    mfccs = librosa.feature.mfcc(y=segment.astype(float), sr=sr, n_mfcc=20)
    return np.concatenate([mfccs.mean(axis=1), mfccs.std(axis=1)])  # 40 维
```

**步骤 3 — 使用 KNN 对比带标签参考进行分类：**
```python
from sklearn.neighbors import KNeighborsClassifier

# 从带标签音频构建参考（26 个键 × 50 次按键）
X_ref, y_ref = [], []
for key_idx, key in enumerate('abcdefghijklmnopqrstuvwxyz'):
    for peak in reference_peaks[key_idx * 50:(key_idx + 1) * 50]:
        X_ref.append(extract_features(ref_audio, sr, peak))
        y_ref.append(key)

knn = KNeighborsClassifier(n_neighbors=5)
knn.fit(X_ref, y_ref)

# 对 flag 按键分类
flag = ''.join(knn.predict([extract_features(flag_audio, sr, p) for p in flag_peaks]))
```

**关键洞察：** 窗口大小至关重要——10ms 捕获初始冲击瞬态，是每个按键最具区分性的特征。更大窗口（20-30ms）包含按键释放噪声，降低分类准确率。使用所有单独参考样本而非平均，KNN 对更多数据点的方差处理更好。

**识别：** 提供两个音频文件（参考 + 目标），或题目提及“typing”、“keyboard”、“acoustic”。

---
## CD 音频光盘映像隐写术 (BSidesSF 2026)

**模式 (cdimage)：** 视觉图像编码为 CD 表面的坑/地模式。`.cdda` 文件（原始 CD 数字音频）仅包含两个字节值（例如 `0x0d` 和 `0xa8`），分别代表反射的地和非反射的坑。当以螺旋形渲染到光盘映像上时，二进制模式形成可读的文本或图像——类似于 LightScribe，但使用的是数据层。

**关键组件：**
1. **CIRC 解交织** — CD 音频数据采用交叉交织编码以进行错误校正。编码工具（例如 [arduinocelentano/cdimage](https://github.com/arduinocelentano/cdimage)）预先交织数据以补偿。解码时需先反转 CIRC 交织再进行渲染。
2. **螺旋几何** — 每轨字节数线性增加：`tr(n) = tr0 + n * dtr`，物理半径 `r(n) = r0 + n * dr`。默认参数：`tr0=22951.52`，`dtr=1.387`，`r0=24.5mm`。
3. **极坐标转笛卡尔渲染** — 将字节值累积到极坐标网格 `(radius_pixel, angle_bin)`，然后转换为圆形光盘图像。

**解交织（CIRC 反转）：**

```python
import numpy as np

def deinterleave_cdda(data):
    """反转 cdimage 工具的 CIRC 预交织。"""
    D = 4
    delays = [
        -24*(3),          -24*(1*D+2)+1,    8-24*(2*D+3),    8-24*(3*D+2)+1,
        16-24*(4*D+3),    16-24*(5*D+2)+1,  2-24*(6*D+3),    2-24*(7*D+2)+1,
        10-24*(8*D+3),    10-24*(9*D+2)+1,  18-24*(10*D+3),  18-24*(11*D+2)+1,
        4-24*(16*D+1),    4-24*(17*D)+1,    12-24*(18*D+1),  12-24*(19*D)+1,
        20-24*(20*D+1),   20-24*(21*D)+1,   6-24*(22*D+1),   6-24*(23*D)+1,
        14-24*(24*D+1),   14-24*(25*D)+1,   22-24*(26*D+1),  22-24*(27*D)+1
    ]
    # 构建每个输出索引的偏移：output[g*24+i] 来源于 input[g*24+i + offset[i]]
    offsets = [0] * 24
    for pinf in range(24):
        i = delays[pinf] % 24
        if i < 0:
            i += 24
        dg = (i - delays[pinf]) // 24
        offsets[i] = -(111 - dg) * 24 + (pinf - i)

    total = len(data)
    result = np.zeros(total, dtype=np.uint8)
    for i in range(24):
        out_pos = np.arange(i, total, 24, dtype=np.int64)
        in_pos = out_pos + offsets[i]
        valid = (in_pos >= 0) & (in_pos < total)
        result[in_pos[valid]] = data[out_pos[valid]]
    return result
```

**将解交织数据渲染为光盘图像：**

```python
from PIL import Image

def render_cdda_disc(data, img_size=1024, tr0=22951.52052, dtr=1.3865961805,
                     r0=24.5, rcd=57.5, scale=0.115, n_angle_bins=8192,
                     bright_byte=0x0d):
    """将解交织的 CDDA 数据渲染为圆形光盘图像。"""
    center = img_size // 2
    dr = dtr * r0 / tr0
    polar_sum = np.zeros((img_size, n_angle_bins), dtype=np.float64)
    polar_count = np.zeros((img_size, n_angle_bins), dtype=np.float64)

    tr, r, pos, c_float = tr0, r0, 0, 0.0
    total = len(data)
    while c_float < (800 * 1024 * 1024 - tr) and pos < total:
        itr = int(tr)
        r_px = int(r / scale)
        if 0 <= r_px < img_size:
            end = min(pos + itr, total)
            chunk = data[pos:end]
            n_tb = len(chunk)
            if n_tb > 0:
                angles = (np.arange(n_tb, dtype=np.int64) * n_angle_bins // n_tb) % n_angle_bins
                is_bright = (chunk == bright_byte).astype(np.float64)
                np.add.at(polar_sum[r_px], angles, is_bright)
                np.add.at(polar_count[r_px], angles, 1.0)
        c_float += tr
        ic = pos + itr
        while int(c_float) > ic:
            ic += 1
        pos = ic
        tr += dtr
        r += dr

    density = np.where(polar_count > 0, polar_sum / polar_count, 0)
    ys, xs = np.mgrid[0:img_size, 0:img_size]
    dx, dy = (xs - center).astype(float), (ys - center).astype(float)
    r_arr = np.sqrt(dx * dx + dy * dy).astype(int)
    theta = np.arctan2(-dy, dx)
    theta[theta < 0] += 2 * np.pi
    a_idx = (theta / (2 * np.pi) * n_angle_bins).astype(int) % n_angle_bins
    output = density[np.clip(r_arr, 0, img_size - 1), a_idx]
    output[(r_arr < int(r0 / scale)) | (r_arr > int(rcd / scale))] = 0
    return Image.fromarray((output * 255).astype(np.uint8))

# 完整流程
data = np.fromfile('flag.cdda', dtype=np.uint8)
deinterleaved = deinterleave_cdda(data)
img = render_cdda_disc(deinterleaved)
img.save('disc_output.png')
```

**关键洞察：** 若不进行 CIRC 解交织，径向结构（明暗环）可见，但角度细节（文本）完全混乱。交织将每个字节分散到约 108 组（约 2592 字节），在典型轨道长度（约 3万-5万字节/转）下，角度位置偏移可达 30 度——足以破坏任何可读模式。校准图像通过显示已知文本确认解码正确。

**校准流程：** 挑战提供 `calibrate_img.cdda` 及其已知输出（`calibrate_img.png` 显示 "Calibrate: 0123456789abc..."）。使用此对验证几何参数（tr0、dtr、r0、scale）后再解码 flag 文件。

**检测：** 挑战提及“专辑”、“CD 抓轨”、“CDDA”，或提供仅含两个唯一字节值的大文件（约 800MB）。`file` 命令报告“ISO-8859 文本，带 CR 行终止符”，因为 `0x0d`（CR）是两个值之一。

---

## Caps-Lock LED 摩尔斯码提取（STEM CTF 2018）

**模式：** 通过 OpenCV 帧逐帧分析，追踪键盘上 caps-lock LED 像素，从监控摄像头视频中提取摩尔斯码。

```python
import cv2

vidcap = cv2.VideoCapture('SecurityCamera.mp4')
morse = []
while vidcap.isOpened():
    ret, frame = vidcap.read()
    if not ret: break
    r, g, b = frame[58, 686]  # caps-lock LED 像素坐标
    is_on = r > 200 and g > 200 and b > 200
    morse.append(is_on)

# 将开/关持续时间转换为点、划和空格
# 短亮=点，长亮=划，中等暗=字母间隔，长暗=单词间隔
durations = []
current = morse[0]
count = 0
for state in morse:
    if state == current:
        count += 1
    else:
        durations.append((current, count))
        current = state
        count = 1
durations.append((current, count))

# 根据观察到的持续时间校准阈值
# 典型：点=2-4帧，划=6-10帧，字母间隔=4-6帧，单词间隔=10帧以上
MORSE_MAP = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9', '-----': '0',
}
```

**关键洞察：** 键盘 LED（caps lock、num lock、scroll lock）可被程序控制，且在监控摄像头录像中可见。追踪视频帧中特定像素坐标，开/关持续时间编码摩尔斯码（短=点，长=划）。

**检测：** 监控摄像头拍摄的键盘视频，LED 不规则闪烁。挑战提及“监控摄像头”、“键盘”、“闪烁”或“摩尔斯码”。

---
## Linux input_event Keylogger Dump Parsing (Pwn2Win 2016)

原始二进制转储，包含24字节重复结构，匹配 Linux 的 `struct input_event`（`struct timeval` + `__u16 type` + `__u16 code` + `__s32 value`）。过滤 `type == EV_KEY (1)` 且 `value == 1`（按键按下），通过 Linux 内核的 `input-event-codes.h` 映射按键码。

```python
import struct
with open('dump.bin', 'rb') as f:
    while data := f.read(24):
        tv_sec, tv_usec, type_, code, value = struct.unpack('<QQHHi', data)
        if type_ == 1 and value == 1:  # EV_KEY，按键按下
            print(f"Key code: {code}")  # 通过 input-event-codes.h 映射
```

**关键点：** `/dev/input/event*` 捕获数据格式固定为24字节的 `struct input_event`。过滤 EV_KEY 类型且 value=1 表示按键按下。使用 Linux 内核头文件 `input-event-codes.h` 映射按键码。

**检测方法：** 二进制文件大小是24的倍数。题目提示 keylogger、键盘或输入设备。

---

## I2C Bus Protocol Decoding (EKOPARTY CTF 2016)

逻辑分析仪捕获的 I2C（Inter-Integrated Circuit）总线通信。解码 SDA（数据）和 SCL（时钟）信号以提取传输的字节。

```python
def decode_i2c(sda_signal, scl_signal):
    """从逻辑分析仪捕获中解码 I2C 协议
    通道0 = SDA（数据），通道1 = SCL（时钟）

    I2C 帧结构：
    - START：SDA 在 SCL 高电平时下降
    - STOP：SDA 在 SCL 高电平时上升
    - 数据：在 SCL 上升沿采样 SDA
    - ACK：第9位（低电平 = ACK，高电平 = NACK）
    """
    bytes_out = []
    current_byte = 0
    bit_count = 0
    in_frame = False

    for i in range(len(scl_signal) - 1):
        # 检测 START 条件
        if sda_signal[i] == 1 and sda_signal[i+1] == 0 and scl_signal[i] == 1:
            in_frame = True
            bit_count = 0
            current_byte = 0
            continue

        # 检测 STOP 条件
        if sda_signal[i] == 0 and sda_signal[i+1] == 1 and scl_signal[i] == 1:
            in_frame = False
            continue

        # 在 SCL 上升沿采样数据
        if in_frame and scl_signal[i] == 0 and scl_signal[i+1] == 1:
            if bit_count < 8:
                current_byte = (current_byte << 1) | sda_signal[i+1]
                bit_count += 1
            elif bit_count == 8:
                bytes_out.append(current_byte)
                bit_count = 0
                current_byte = 0

    return bytes_out

# 工具：Saleae Logic 2，sigrok/PulseView，OLS（Open Logic Sniffer）
# 导入：File > Open Logic Sniffer capture
# 解码：Analyzers > I2C > 设置 SDA/SCL 通道
```

**关键点：** I2C 只使用两根线（SDA + SCL）。START/STOP 条件发生在 SDA 变化且 SCL 为高电平时。数据位在 SCL 上升沿采样。每第9位为 ACK。使用逻辑分析仪软件（Saleae、sigrok）可自动解码。

---

## IBM-29 Punched Card OCR (EKOPARTY CTF 2016)

通过检测标准 80 列 x 12 行网格中孔的位置，解码 IBM-29 打孔卡图像。

```python
from PIL import Image

# IBM-29 字符编码：列打孔模式 -> 字符
IBM_029_MAP = {
    (12,): 'A', (12,1): 'A', (12,2): 'B', (12,3): 'C',  # 等等
    (11,): '-', (11,1): 'J', (11,2): 'K',  # 等等
    (0,): '0', (1,): '1', (2,): '2',  # 区域0 + 数字
    # 完整映射见：http://www.columbia.edu/cu/computinghistory/029.html
}

def decode_punched_card(image_path, cols=80, rows=12,
                        x_spacing=7, y_spacing=20, x_offset=10, y_offset=10):
    """检测卡片图像中的打孔并解码为文本"""
    img = Image.open(image_path).convert('L')
    text = ""

    for col in range(cols):
        punches = []
        for row in range(rows):
            x = x_offset + col * x_spacing
            y = y_offset + row * y_spacing
            pixel = img.getpixel((x, y))
            if pixel > 200:  # 白色 = 打孔
                punches.append(row)

        if punches:
            key = tuple(punches)
            text += IBM_029_MAP.get(key, '?')
        else:
            text += ' '

    return text

# 处理多张卡片图像
for i in range(14):
    card_text = decode_punched_card(f'card_{i:02d}.png')
    print(f"Card {i}: {card_text}")
```

**关键点：** IBM 打孔卡使用 12 行 x 80 列网格。每个字符由一列中1-3个孔编码。网格间距因读卡器/扫描仪分辨率不同而异——通过测量已知参考孔间距进行校准。白色/浅色像素表示打孔。

---

## Serial UART Data Decoding from WAV Audio (EasyCTF 2017)

音频文件中可能包含以方波信号编码的串口（UART）数据。通过采样幅度电平和解析比特时序进行解码。

```python
import struct

with open('signal.wav', 'rb') as f:
    f.read(44)  # 跳过 WAV 头
    samples = []
    while True:
        data = f.read(2)
        if not data: break
        samples.append(struct.unpack('<h', data)[0])

# 参数：9600 波特率，1 起始位，8 数据位，无奇偶校验，2 停止位
SAMPLES_PER_BIT = len(samples) // expected_bits  # 9600 波特率 @ 384kHz 约40个采样点
THRESHOLD = 0  # 高于为1，低于为0

# 将采样转换为比特
bits = [1 if s > THRESHOLD else 0 for s in samples]

# 查找帧：起始位（0）+ 8 数据位 + 停止位（1,1）
output = []
i = 0
while i < len(bits) - 11:
    if bits[i] == 0:  # 起始位
        byte_bits = bits[i+1:i+9]  # 低位优先
        byte_val = sum(b << j for j, b in enumerate(byte_bits))
        output.append(byte_val)
        i += 11  # 跳过起始位 + 8 数据位 + 2 停止位
    else:
        i += 1

print(bytes(output))
```

**关键点：** 音频中的 UART 串口数据表现为具有明确比特时序的方波。关键参数包括波特率（每比特采样数）、帧格式（起始/停止位、奇偶校验）和比特顺序（UART 是低位优先）。起始位（低电平）为每个字节帧提供同步。

**检测方法：** WAV 文件中在 Audacity 可见清晰的方波模式。两个明显的幅度电平且时序规律。题目提示“serial”、“UART”、“baud”或“RS-232”。

---
## USB MIDI Launchpad 流量重构（Sthack 2017）

来自 MIDI 控制器设备（例如 Novation Launchpad）的 USB 流量将按键按下编码为 MIDI Note On/Off 消息，可以重构为可视化图案。

```python
from scapy.all import rdpcap

pkts = rdpcap('capture.pcapng')
# 过滤包含 MIDI 数据的 USB 批量传输包
# Launchpad MIDI: 0x90 = Note On，0x80 = Note Off
# 格式: [状态, 键值, 力度]
# 键值编码 (行, 列): key = row*16 + col

characters = []
current_grid = [[0]*8 for _ in range(8)]

for pkt in pkts:
    data = bytes(pkt)
    # 在 USB 负载中查找 MIDI 消息
    if len(data) >= 4:
        status = data[-3]
        key = data[-2]
        velocity = data[-1]

        if status == 0x90 and velocity > 0:  # Note On
            row, col = key // 16, key % 16
            if 0 <= row < 8 and 0 <= col < 8:
                current_grid[row][col] = 1
        elif status == 0x80 or (status == 0x90 and velocity == 0):  # Note Off
            # 全灭序列 = 字符分隔符
            if all(current_grid[r][c] == 0 for r in range(8) for c in range(8)):
                characters.append(current_grid)
                current_grid = [[0]*8 for _ in range(8)]
```

**关键洞察：** MIDI 设备使用标准化的消息格式。Novation Launchpad 将其 8x8 网格映射到 MIDI 音符，其中 `key = row*16 + col`。Note On (0x90) 且力度 > 0 表示按钮点亮，Note Off (0x80) 表示按钮熄灭。连续的全灭消息序列用来分隔网格上显示的字符。

**检测方法：** USB PCAP 中包含批量传输包，负载为 3 字节或 4 字节。USB 设备描述符显示 MIDI 类（音频类，子类 MIDI 流）。挑战中提及 “MIDI”、“Launchpad”、“音乐控制器” 或 “网格”。

---

## Tektronix 逻辑分析仪 CSV 时钟边沿提取（35C3 2018）

**模式：** Tektronix 逻辑分析仪将多通道采集导出为约 10MB 的 CSV 文件，每列对应一个信号（CLK、R、G、B 等）。用 Python 解析文件，检测 CLK 列的上升沿，并在每个边沿采样数据列，以重构传输的图像/流。

```python
import csv
with open('capture.csv') as f:
    reader = csv.reader(f)
    prev_clk = 0
    bits = []
    for row in reader:
        try: clk = int(row[1])
        except ValueError: continue
        if prev_clk == 0 and clk == 1:          # 上升沿
            bits.append((int(row[2]), int(row[3]), int(row[4])))
        prev_clk = clk
# 将 bits 重塑为图像并用 PIL 渲染
```

**关键洞察：** 逻辑分析仪 CSV 始终是边沿采样。通过其 50% 占空比识别时钟列，然后在每个上升沿同步采样数据列。适用于任何同步总线（RGB、SPI、I²C 时钟线）。

**参考资料：** 35C3 CTF 2018 — box of blink，writeup 12907
