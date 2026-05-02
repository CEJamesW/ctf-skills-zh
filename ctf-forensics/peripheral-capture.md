# CTF Forensics - 外设捕获分析

从数据包捕获中重构 USB、HID 和蓝牙外设流量。有关通用网络 PCAP 取证（DNS/TCP/ICMP/SMB/RADIUS/RC4），请参见 [network-advanced.md](network-advanced.md)。有关基础网络取证，请参见 [network.md](network.md)。

## 目录
- [USB HID 鼠标/笔绘图恢复 (EHAX 2026)](#usb-hid-mousepen-drawing-recovery-ehax-2026)
- [USB HID 键盘捕获解码 (EKOPARTY CTF 2016)](#usb-hid-keyboard-capture-decoding-ekoparty-ctf-2016)
- [USB 键盘 LED 摩尔斯码外泄 (BITSCTF 2017)](#usb-keyboard-led-morse-code-exfiltration-bitsctf-2017)
- [USB HID 键盘箭头键导航追踪 (HackIT 2017)](#usb-hid-keyboard-arrow-key-navigation-tracking-hackit-2017)
- [蓝牙 RFCOMM 数据包重组 (HITCON 2018)](#bluetooth-rfcomm-packet-reassembly-hitcon-2018)
- [GBA USB URB_INTERRUPT 帧缓冲提取 (hxp 2018)](#gba-usb-urb_interrupt-framebuffer-extraction-hxp-2018)

---

## USB HID 鼠标/笔绘图恢复 (EHAX 2026)

**模式（画家）：** PCAP 包含来自鼠标/笔设备的 USB HID 中断传输。绘图数据编码为相对移动，带有多种绘图模式。

**数据包格式（7 字节 HID 报告）：**
| 字节 | 字段 | 说明 |
|------|-------|-------|
| 0 | 按钮状态 | 0x01 = 按下（可能是常量） |
| 1 | 模式/垫 | 0=悬停，1=绘图模式1，2=绘图模式2 |
| 2-3 | dx (int16 LE) | 相对 X 移动 |
| 4-5 | dy (int16 LE) | 相对 Y 移动 |
| 6 | 滚轮 | 通常为 0 |

**提取与渲染：**
```python
import struct
from PIL import Image, ImageDraw

# 提取 HID 数据
# tshark -r capture.pcap -Y "usb.transfer_type==1" -T fields -e usb.capdata

packets = []
with open('hid_data.txt') as f:
    for line in f:
        raw = bytes.fromhex(line.strip().replace(':', ''))
        if len(raw) >= 7:
            btn = raw[0]
            mode = raw[1]
            dx = struct.unpack('<h', raw[2:4])[0]
            dy = struct.unpack('<h', raw[4:6])[0]
            packets.append((btn, mode, dx, dy))

# 按模式累积位置
SCALE = 5
positions = {0: [], 1: [], 2: []}
x, y = 0, 0
for btn, mode, dx, dy in packets:
    x += dx
    y += dy
    positions[mode].append((x, y))

# 分别渲染每个模式（不同颜色 = 不同文本层）
for mode in [1, 2]:
    pts = positions[mode]
    if not pts:
        continue
    min_x = min(p[0] for p in pts) - 100
    min_y = min(p[1] for p in pts) - 100
    max_x = max(p[0] for p in pts) + 100
    max_y = max(p[1] for p in pts) + 100
    w = (max_x - min_x) * SCALE
    h = (max_y - min_y) * SCALE
    img = Image.new('RGB', (w, h), 'white')
    draw = ImageDraw.Draw(img)
    for i in range(1, len(pts)):
        x0 = (pts[i-1][0] - min_x) * SCALE
        y0 = (pts[i-1][1] - min_y) * SCALE
        x1 = (pts[i][0] - min_x) * SCALE
        y1 = (pts[i][1] - min_y) * SCALE
        # 跳过长距离跳跃（笔离开）
        if abs(pts[i][0]-pts[i-1][0]) < 50 and abs(pts[i][1]-pts[i-1][1]) < 50:
            draw.line([(x0,y0),(x1,y1)], fill='black', width=3)
    img.save(f'mode_{mode}.png')
```

**关键技术：**
- **分离模式：** 不同按钮/模式值绘制不同文本层 — 分别渲染
- **跳过笔离开：** 大的 dx/dy 跳跃表示笔被抬起，非绘制 — 通过距离阈值过滤
- **高分辨率：** 5-8 倍缩放并留边距，便于识别手写内容
- **时间渐变：** 按时间顺序用彩虹渐变色标记点，追踪笔画方向
- **字符分割：** 通过大 X 轴间隔将连续同模式点分组，分离字符

**替代方案：AWK 提取 + SVG 渲染（更快流程）：**
```bash
# 一次性提取 capdata 并转换为有符号增量
tshark -r pref.pcap -Y "usb.transfer_type==0x01 && usb.endpoint_address==0x81 && usb.capdata" \
  -T fields -e usb.capdata > capdata.txt

awk '
function hexval(c){ return index("0123456789abcdef",tolower(c))-1 }
function hex2dec(h, n,i){ n=0; for(i=1;i<=length(h);i++) n=n*16+hexval(substr(h,i,1)); return n }
function s16(u){ return (u>=32768)?u-65536:u }
{ d=$1; if(length(d)!=14) next
  btn=hex2dec(substr(d,3,2))
  x=s16(hex2dec(substr(d,7,2) substr(d,5,2)))
  y=s16(hex2dec(substr(d,11,2) substr(d,9,2)))
  print btn, x, y }' capdata.txt > deltas.txt
```
然后用 SVG（Python）渲染 — 过滤笔按下状态（button=2），累积增量，翻转 Y 轴，绘制连续笔按下点间的笔画。

**与键盘 HID 的区别：** 鼠标 HID 使用相对移动（累积），键盘使用按键码（直接）。鼠标绘图需要渲染，键盘需要查键码表。

---

## USB HID 键盘捕获解码 (EKOPARTY CTF 2016)

USB 键盘捕获包含映射到按键的 HID 扫描码。解码捕获以重构输入文本。

```python
# USB HID 键盘报告格式：
# 字节 0：修饰键（Shift、Ctrl、Alt）
# 字节 1：保留（0x00）
# 字节 2-7：最多 6 个同时按下的键码

# HID 扫描码到字符映射（部分）
HID_MAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e',
    0x09: 'f', 0x0a: 'g', 0x0b: 'h', 0x0c: 'i', 0x0d: 'j',
    0x0e: 'k', 0x0f: 'l', 0x10: 'm', 0x11: 'n', 0x12: 'o',
    0x13: 'p', 0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
    0x18: 'u', 0x19: 'v', 0x1a: 'w', 0x1b: 'x', 0x1c: 'y',
    0x1d: 'z', 0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4',
    0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9',
    0x27: '0', 0x28: '\n', 0x2c: ' ', 0x2d: '-', 0x2e: '=',
    0x2f: '[', 0x30: ']', 0x33: ';', 0x34: "'", 0x36: ',',
    0x37: '.', 0x38: '/',
}

SHIFT_MAP = {
    'a': 'A', 'b': 'B', '1': '!', '2': '@', '3': '#', '4': '$',
    '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
    '-': '_', '=': '+', '[': '{', ']': '}', ';': ':', "'": '"',
    ',': '<', '.': '>', '/': '?',
}

def decode_hid_keyboard(capture_data):
    """解码 USB HID 键盘捕获为文本"""
    text = ""
    for report in capture_data:
        modifier = report[0]
        keycode = report[2]  # 报告中的第一个按键

        if keycode == 0:
            continue

        char = HID_MAP.get(keycode, '')
        if modifier & 0x22:  # 左或右 Shift
            char = SHIFT_MAP.get(char, char.upper())

        text += char
    return text

# 从 Wireshark 提取：tshark -r capture.pcapng -T fields -e usb.capdata
# 或从文本转储：解析 +XX/-XX 格式（+ = 按键按下，- = 按键释放）
```

**关键点：** USB HID 键盘发送 8 字节报告，字节 0 是修饰键（Shift/Ctrl/Alt），字节 2-7 是活动按键扫描码。在 Wireshark 中，使用过滤器 `usb.transfer_type == 1` 并提取 `usb.capdata`。忽略字节 2 为 0x00（按键释放）的报告。

---
## USB 键盘 LED 摩尔斯码外泄 (BITSCTF 2017)

**模式（Ghost in the Machine）：** 一个 USB 键盘流量的 pcap 包含主机到设备的包，包中交替出现 `0x01`/`0x03` 值来控制大写锁定键的 LED 状态。LED 状态变化的时间差编码了摩尔斯码：持续时间超过 300ms 表示长划线，较短的持续时间表示点。解码摩尔斯序列以恢复 flag。

```python
from scapy.all import rdpcap
import struct

packets = rdpcap('usb_capture.pcap')
signals = []

for p in packets:
    raw = bytes(p)
    # USB HID SET_REPORT 到键盘（主机 -> 设备）
    if len(raw) >= 35 and raw[30] in (0x01, 0x03):
        timestamp = p.time
        led_state = raw[30]  # 0x01 = LED 关闭, 0x03 = LED 打开
        signals.append((timestamp, led_state))

# 将时间转换为摩尔斯码
morse = ''
for i in range(0, len(signals) - 1, 2):
    duration = signals[i+1][0] - signals[i][0]
    if duration > 0.3:
        morse += '-'
    else:
        morse += '.'
    # 信号间的间隔表示字母/单词边界
```

**关键洞察：** 通过键盘 LED 状态变化进行数据外泄，捕获于 USB pcap 中。LED 控制包使用 HID SET_REPORT 类请求。通过开/关转换的时间分析揭示摩尔斯码模式。工具：Wireshark USB 解码器，过滤条件 `usb.transfer_type == 0x02`（中断传输）且方向为主机→设备。

---

## USB HID 键盘箭头键导航追踪 (HackIT 2017)

来自 Apple 键盘的 USB HID 键盘流量需要追踪箭头键导航。使用 USB HID 使用表解码 HID 键码。修饰符字节 `0x02` 表示 Shift（大写）。通过上下箭头按键追踪光标位置，以确定哪一行包含 flag。

```bash
tshark -r capture.pcap -T fields -e usb.capdata | \
  python3 decode_hid.py  # 必须追踪箭头键以确定行位置
```

需要追踪的箭头键 HID 码：
- `0x4F` = 右箭头
- `0x50` = 左箭头
- `0x51` = 下箭头（下一行）
- `0x52` = 上箭头（上一行）

```python
# 框架：在 HID 解码时追踪行位置
line = 0
lines = {0: ""}
for report in hid_reports:
    modifier = report[0]
    keycode = report[2]
    if keycode == 0x51:    # 下箭头
        line += 1; lines.setdefault(line, "")
    elif keycode == 0x52:  # 上箭头
        line -= 1; lines.setdefault(line, "")
    elif keycode in HID_MAP:
        char = HID_MAP[keycode]
        if modifier & 0x22:
            char = char.upper()
        lines[line] += char
# flag 位于通过箭头导航确定的特定行
```

**关键洞察：** USB 键盘捕获必须考虑光标移动键（箭头、退格键）。追踪光标行位置以分别重建每行输入的文本——flag 可能位于非零行，需通过箭头键导航到该行。

---

## 蓝牙 RFCOMM 数据包重组 (HITCON 2018)

**模式：** 一个 Lego EV3 通过蓝牙的捕获包含 RFCOMM 帧，其负载是 EV3 直接命令。数据包长度为 32–34 字节，含 8 字节 RFCOMM 头部，携带一个 `order` 字节和一个 `group_number` 字节，这两个字节共同用于重新排序成连贯的二进制数据。重组步骤为：(1) 在 Wireshark 过滤 `btrfcomm`，(2) 先按 `group_number` 再按 `order` 排序数据包，(3) 拼接头部后的数据字段。

```python
# 使用 pyshark 的 Python 示例
import pyshark
cap = pyshark.FileCapture("capture.pcap", display_filter="btrfcomm")
frames = []
for pkt in cap:
    raw = bytes.fromhex(pkt.btrfcomm.payload.replace(":", ""))
    # RFCOMM 头部大小可变：4（UIH）或 5（带长度扩展）
    hdr_len = 4 if raw[2] & 0x01 == 0 else 5
    body = raw[hdr_len:]
    order, group = body[0], body[1]
    frames.append((group, order, body[2:]))
frames.sort()
binary = b"".join(chunk for _, _, chunk in frames)
open("payload.bin", "wb").write(binary)
```

**关键洞察：** RFCOMM 是基于 L2CAP 的类似 TCP 的串口仿真；当应用负载超过 MTU 时会分片。CTF 题目喜欢将 flag 分散在多个帧中，因为大多数 pcap 解析只停留在 TCP/UDP 层，跳过蓝牙链路层。使用 Wireshark 过滤器 `btrfcomm.channel`、`btl2cap` 或 `btsnoop_hci` 来隔离相关流，然后按可用的 order/group 字节排序后拼接。类似逻辑适用于 USB 批量传输（`usb.transfer_type == 0x03`）和基于 BLE 的 MIDI 流量。

**参考：** HITCON CTF 2018 — EV3 Basic，writeup 11902

---

## GBA USB URB_INTERRUPT 帧缓冲区提取 (hxp 2018)

**模式：** pcap 包含来自 Game Boy Advance 调试适配器的 USB `URB_INTERRUPT` 包。GBA 帧缓冲区为 `240 × 160`，采用 RGB565 格式（2 字节/像素，共 76800 字节）。块类型 6 携带内存转储；将每个包的负载拆分到帧缓冲区网格中，并将 RGB565 转换为 8 位 RGB 元组。

```python
from PIL import Image
from scapy.all import rdpcap
pkts = [p for p in rdpcap('cap.pcap') if p.haslayer('Raw')]
img = Image.new('RGB', (240, 160))
for p in pkts:
    if p.Raw.load[3] == 0x06:        # 类型 6 = 内存转储
        data = p.Raw.load[4:]
        for i in range(76800 // 2):
            rgb = int.from_bytes(data[2*i:2*i+2], 'little')
            r = (rgb & 0xF800) >> 8
            g = (rgb & 0x07E0) >> 3
            b = (rgb & 0x001F) << 3
            img.putpixel((i % 240, i // 240), (r, g, b))
img.save('screen.png')
```

**关键洞察：** 手持游戏机调试协议通常将内存转储封装在带类型的块中。遇到 GBA/NDS/PSP USB 流量时，先 grep 类型 6（帧缓冲区）或类型 7（音频），再解析其余内容。

**参考：** hxp CTF 2018 — cheatquest of hxpschr 2，writeup 12591
