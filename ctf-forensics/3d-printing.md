# CTF Forensics - 3D 打印 / CAD 文件取证

## 目录
- [PrusaSlicer 二进制 G-code (.g / .bgcode)](#prusaslicer-binary-g-code-g--bgcode)
- [QOIF (Quite OK Image Format)](#qoif-quite-ok-image-format)
- [G-code 分析技巧](#g-code-analysis-tips)
- [G-code 侧视图可视化 (0xFun 2026)](#g-code-side-view-visualization-0xfun-2026)
- [不常见的文件魔数](#uncommon-file-magic-bytes)

---

## PrusaSlicer 二进制 G-code (.g / .bgcode)

**文件魔数:** `GCDE` (4 字节)

`.g` 扩展名是 PrusaSlicer 的二进制 G-code 格式（bgcode）。它以块结构存储 G-code，并带有压缩。

**文件结构:**
```text
Header: "GCDE"(4) + version(4) + checksum_type(2)
Blocks: [type(2) + compression(2) + uncompressed_size(4)
         + compressed_size(4) if compressed
         + type-specific fields
         + data + CRC32(4)]
```

**块类型:**
- 0 = FileMetadata（含编码字段，2 字节）
- 1 = GCode（含编码字段，2 字节）
- 2 = SlicerMetadata（含编码字段，2 字节）
- 3 = PrinterMetadata（含编码字段，2 字节）
- 4 = PrintMetadata（含编码字段，2 字节）
- 5 = Thumbnail（含格式(2) + 宽度(2) + 高度(2)）

**压缩类型:** 0=无，1=Deflate，2=Heatshrink(11,4)，3=Heatshrink(12,4)

**缩略图格式:** 0=PNG，1=JPEG，2=QOI (Quite OK Image)

**解析和提取 G-code:**
```python
import struct, zlib
import heatshrink2  # pip install heatshrink2

with open('file.g', 'rb') as f:
    data = f.read()

pos = 10  # 头部之后
while pos < len(data) - 8:
    block_type = struct.unpack('<H', data[pos:pos+2])[0]
    compression = struct.unpack('<H', data[pos+2:pos+4])[0]
    uncompressed_size = struct.unpack('<I', data[pos+4:pos+8])[0]
    pos += 8
    if compression != 0:
        compressed_size = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
    else:
        compressed_size = uncompressed_size
    # 类型特定的额外头字段
    if block_type in [0,1,2,3,4]:
        pos += 2  # 编码字段
    elif block_type == 5:
        pos += 6  # 格式 + 宽度 + 高度
    block_data = data[pos:pos+compressed_size]
    pos += compressed_size + 4  # 数据 + CRC32

    if block_type == 1:  # GCode 块
        if compression == 3:  # Heatshrink 12/4
            gcode = heatshrink2.decompress(block_data, window_sz2=12, lookahead_sz2=4)
        elif compression == 1:  # Deflate (zlib)
            gcode = zlib.decompress(block_data)
        # 在 gcode 中搜索隐藏的注释/flag
```

**常见隐藏位置:**
- G-code 注释（`;=== FLAG_CHAR ... ===`）在特定层高
- 自定义 G-code 段（`;TYPE:Custom`）
- 元数据字段（对象名称，耗材信息）
- 缩略图图像（提取并查看 QOIF/PNG）

## QOIF (Quite OK Image Format)

**魔数:** `qoif` (4 字节) + 宽度(4 大端) + 高度(4 大端) + 通道数(1) + 色彩空间(1)

PrusaSlicer 缩略图中使用的轻量级图像格式。可用 Python struct 解码或使用 `qoi` 库。

## G-code 分析技巧

```bash
# 在解压后的 gcode 中搜索 flag 模式
grep -i "flag\|meta\|ctf\|secret" output.gcode

# 查找层变化处的自定义注释
grep ";.*FLAG\|;.*LAYER_CHANGE" output.gcode

# 提取 XY 坐标用于视觉模式分析
grep "^G1" output.gcode | awk '{print $2, $3}' > coords.txt
```

## G-code 侧视图可视化 (0xFun 2026)

**模式 (PrintedParts):** 绘制 X 对 Z（侧视图），并对 Y 进行过滤。在特定 Y 范围的挤出段形成可读文本。

```bash
# 从 G-code 中提取 XY 坐标
grep "^G1" output.gcode | awk '{print $2, $3}' > coords.txt
# 使用 matplotlib 绘图以发现视觉模式
```

**经验:** G-code 只是坐标列表。侧投影（XZ 或 YZ）能揭示凸起/雕刻的文本。

---

## 不常见的文件魔数

| 魔数   | 格式                  | 扩展名       | 说明                      |
|--------|-----------------------|--------------|---------------------------|
| `GCDE` | PrusaSlicer 二进制 G-code | `.g`, `.bgcode` | 3D 打印，heatshrink 压缩    |
| `qoif` | Quite OK Image Format  | `.qoi`       | 轻量级图像格式，常嵌入       |
| `OggS` | Ogg 容器              | `.ogg`       | 音频/视频                  |
| `RIFF` | RIFF 容器             | `.wav`,`.avi`| 检查子格式                 |
| `%PDF` | PDF                   | `.pdf`       | 检查元数据和嵌入对象        |
