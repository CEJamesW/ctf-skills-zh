# CTF Forensics - 磁盘恢复与提取模式

## 目录
- [从内存转储恢复 LUKS 主密钥 (Hack.lu 2015)](#luks-master-key-recovery-from-memory-dump-hacklu-2015)
- [基于时间戳种子的伪随机数生成器暴力破解以恢复加密密钥 (CSAW 2015)](#prng-timestamp-seed-brute-force-for-encryption-key-recovery-csaw-2015)
- [VBA 宏编码二进制恢复 (Sharif CTF 2016)](#vba-macro-encoded-binary-recovery-sharif-ctf-2016)
- [FemtoZip 共享字典解压缩 (Sharif CTF 2016)](#femtozip-shared-dictionary-decompression-sharif-ctf-2016)
- [从损坏元数据重建 XFS 文件系统 (BSidesSF 2025)](#xfs-filesystem-reconstruction-from-corrupted-metadata-bsidessf-2025)
- [Tar 归档重复条目提取 (BSidesSF 2025)](#tar-archive-duplicate-entry-extraction-bsidessf-2025)
- [嵌套套娃文件系统提取 (BSidesSF 2025)](#nested-matryoshka-filesystem-extraction-bsidessf-2025)
- [通过空字节交错实现反 carving (BSidesSF 2024)](#anti-carving-via-null-byte-interleaving-bsidessf-2024)
- [BTRFS 子卷/快照恢复 (BSidesSF 2026)](#btrfs-subvolumesnapshot-recovery-bsidessf-2026)
- [FAT16 空闲空间数据恢复 (BSidesSF 2026)](#fat16-free-space-data-recovery-bsidessf-2026)
- [通过 Sleuth Kit 恢复 FAT16 删除文件 (MetaCTF Flash 2026)](#fat16-deleted-file-recovery-via-sleuth-kit-metactf-flash-2026)
- [通过 fsck 恢复 Ext2 孤立 inode (BSidesSF 2026)](#ext2-orphaned-inode-recovery-via-fsck-bsidessf-2026)
- [通过头字段操作修复损坏 ZIP (PlaidCTF 2017)](#corrupted-zip-repair-via-header-field-manipulation-plaidctf-2017)
- [从 FAT 镜像恢复已删除的 .git 仓库 (Square CTF 2017)](#recovering-deleted-git-repository-from-fat-image-square-ctf-2017)
- [从 Git 提交历史恢复 DNSSEC 密钥 (Hack.lu 2017)](#dnssec-key-recovery-from-git-commit-history-hacklu-2017)
- [通过 CRC32 重建修复 XZ 流头 (Hackover 2018)](#xz-stream-header-repair-via-crc32-reconstruction-hackover-2018)
- [利用 bkcrack 破解 ZipCrypto 已知明文 (Codegate 2019)](#zipcrypto-known-plaintext-cracking-via-bkcrack-codegate-2019)
- [SQLite 序列类型字节取证 (RITSEC 2018)](#sqlite-serial-type-byte-forensics-ritsec-2018)
- [递归 Binwalk 链 PNG->PDF->DOCX->PNG->Base64 (TAMUctf 2019)](#recursive-binwalk-chain-png-pdf-docx-png-base64-tamuctf-2019)
- [使用 exrex 的正则密码嵌套 Zip 链 (UTCTF 2019)](#regex-password-nested-zip-chain-with-exrex-utctf-2019)
- [另见](#see-also)

---

## 从内存转储恢复 LUKS 主密钥 (Hack.lu 2015)

使用 AES 密钥调度检测从虚拟机内存转储中恢复 LUKS 加密密钥：

1. **提取内存：** 从虚拟机快照获取内存转储（.elf、.vmem、.raw）
2. **查找 AES 密钥：** 使用 `aeskeyfind` 在内存中检测 AES 密钥调度

```bash
aeskeyfind memory.elf
# 输出：候选 AES-256 密钥（每个 64 个十六进制字符）
```

3. **写入密钥文件：** 将十六进制密钥转换为二进制

```bash
echo "deadbeef..." | xxd -r -p > master.key
```

4. **使用主密钥添加新的 LUKS 密码：**

```bash
cryptsetup luksAddKey --master-key-file master.key /dev/mapper/volume
# 按提示输入新密码
cryptsetup luksOpen /dev/mapper/volume decrypted
mount /dev/mapper/decrypted /mnt
```

**关键洞察：** AES 密钥调度具有独特的数学结构，`aeskeyfind` 能检测到它们，无论它们在内存中的位置。适用于 LUKS、dm-crypt、FileVault 和 BitLocker 卷。

配套工具：`rsakeyfind`（RSA 密钥），`aesfix`（损坏密钥恢复）。

---

## 基于时间戳种子的伪随机数生成器暴力破解以恢复加密密钥 (CSAW 2015)

当加密密钥由基于时间戳的伪随机数生成器（PRNG）生成时，暴力破解种子：

1. **识别种子来源：** 查找用作 PRNG 种子的 `Time.now.to_i`、`time(NULL)`、`System.currentTimeMillis()`
2. **确定时间窗口：** 使用文件元数据（创建/修改时间戳）限定搜索范围
3. **暴力破解种子：** 尝试文件时间戳前后 +/-24 小时内的每一秒

```python
import struct
from Crypto.Cipher import AES

# Ruby 兼容的随机实现（或使用 ctypes 调用 C rand）
for seed in range(timestamp - 86400, timestamp + 86400):
    rng = RandomWithSeed(seed)
    key = bytes([rng.rand(256) for _ in range(32)])  # AES-256
    iv = bytes([rng.rand(256) for _ in range(16)])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    # 验证：检查已知文件签名
    if plaintext[:4] == b'\x89PNG' or plaintext[:2] == b'\xff\xd8':
        print(f"找到种子对应的密钥: {seed}")
        break
```

**关键洞察：** 扩大时间窗口，超出明显时间戳范围——时钟偏差、时区差异和文件系统粒度可能导致有效种子偏移数小时。

---

## VBA 宏编码二进制恢复 (Sharif CTF 2016)

Excel/Word 宏可能将二进制数据编码在单元格值中。提取并解码：

1. **提取宏：** 使用 `olevba` 或在 LibreOffice 中打开以检查 VBA 代码
2. **识别编码：** 查找类似 `Cells(i, j).Value` 的单元格迭代模式
3. **反转编码公式：**

```python
# 如果宏编码为：cell_value = byte_value * 3 + 78
# 反转为：byte_value = (cell_value - 78) // 3

import openpyxl
wb = openpyxl.load_workbook('challenge.xlsx')
ws = wb.active

binary_data = bytearray()
for row in ws.iter_rows():
    for cell in row:
        if cell.value is not None:
            binary_data.append((int(cell.value) - 78) // 3)

with open('recovered.elf', 'wb') as f:
    f.write(binary_data)
```

**关键洞察：** 使用 `file` 命令检查恢复的文件——常见输出为 ELF 二进制、PE 可执行文件或包含 flag 的图像。

---

## FemtoZip 共享字典解压缩 (Sharif CTF 2016)

FemtoZip 使用共享字典模型压缩相似文档集合。给定 `.model` 文件和压缩数据时：

```bash
# 安装 femtozip
git clone https://github.com/gtoubassi/femtozip
cd femtozip && make

# 使用提供的模型解压
./fzip --model fashion.model --decompress compressed_dir/ --output decompressed_dir/
```

解压后，搜索可能成千上万个文件：

```bash
# 按元数据字段过滤
grep -r "category.*forensic" decompressed_dir/ | grep "year.*2016"
```

**关键洞察：** FemtoZip 在 CTF 中较为罕见。通过 `.model` 文件和大量共享结构（JSON、XML 模板）的小型压缩文件识别它。

---
## XFS 文件系统从损坏元数据中重建（BSidesSF 2025）

当 XFS 超级块或分配组元数据损坏但 inode 完好时：

1. **直接解析 inode：** XFS inode 包含带有 `[startoff, startblock, blockcount]` 元组的 extent 列表
2. **计算块偏移：** 将 startblock 乘以文件系统块大小（通常为 4K）
3. **提取文件数据：** 直接从原始磁盘镜像复制块

```bash
# 从已知 inode extent 中提取文件
# startblock=104333, blockcount=256, block_size=4096
dd if=disk.img bs=4096 skip=104333 count=256 of=recovered.jpg

# 解析 XFS inode 结构（在已知偏移处）
python3 -c "
import struct
with open('disk.img', 'rb') as f:
    f.seek(inode_offset)
    magic = f.read(2)  # 'IN' = 0x494e
    # 解析 di_core（96 字节）：mode, uid, gid, nlink, size 等
    # 解析 extent 列表：每个 extent = 16 字节
    # startoff (54 位) | startblock (52 位) | blockcount (21 位)
"
```

**关键洞察：** XFS 将 extent 映射内联存储在 inode 中（最多约 4 个 extent）。对于更多 extent 的文件，需跟踪 inode 中的 B+ 树根节点。若可用，使用 `xfs_db`：`xfs_db -r disk.img` → `inode <num>` → `print`。

---

## Tar 归档重复条目提取（BSidesSF 2025）

Tar 格式允许多个相同文件名的条目。标准提取会覆盖早期条目，但可以针对特定出现的条目提取：

```bash
# 列出所有条目（显示重复项）
tar -tvf archive.tar.xz | grep -c '^\.'

# 提取特定出现的条目（从 1 开始计数）
tar -Jxvf archive.tar.xz '.' --occurrence=2 -O > second_entry.bin

# 通过文件切割提取所有出现的条目
binwalk -e archive.tar
# 或编程迭代提取
python3 -c "
import tarfile
with tarfile.open('archive.tar.xz') as tf:
    for i, member in enumerate(tf.getmembers()):
        if member.name == '.':
            data = tf.extractfile(member).read()
            with open(f'entry_{i}.bin', 'wb') as f:
                f.write(data)
"
```

**关键洞察：** GNU tar 的 `--occurrence=N` 标志选择匹配名称的第 N 个条目。若不使用该标志，提取时只保留最后一个条目。挑战中可能将 flag 隐藏在中间条目，普通提取会跳过。

---

## 嵌套套娃文件系统提取（BSidesSF 2025）

磁盘镜像包含嵌套压缩文件系统层（可能深达 10-20+ 层）：

```bash
#!/bin/bash
# 自动化层级提取
IMG="disk.img"
for i in $(seq 1 20); do
    echo "=== Layer $i ==="
    file "$IMG"

    # 检测并解压
    case "$(file -b "$IMG")" in
        *XZ*)     xz -d "$IMG"; IMG="${IMG%.xz}" ;;
        *gzip*)   gunzip "$IMG"; IMG="${IMG%.gz}" ;;
        *ext4*)
            mkdir -p "layer_$i"
            sudo mount -o ro,loop "$IMG" "layer_$i"
            IMG=$(find "layer_$i" -type f -name "*.img" -o -name "*.xz" | head -1)
            ;;
        *ISO*|*HFS*|*XFS*|*AmigaDOS*)
            mkdir -p "layer_$i"
            sudo mount -o ro,loop "$IMG" "layer_$i" 2>/dev/null || \
            sudo mount -t affs -o ro,loop "$IMG" "layer_$i" 2>/dev/null
            IMG=$(find "layer_$i" -type f | head -1)
            ;;
    esac
done
```

遇到的文件系统类型：ext4、XFS、HFS/HFS+、AFFS（AmigaDOS）、FAT。分区镜像使用 `losetup` 的 `--offset` 参数。最终层通常包含带 flag 的镜像或文本文件。

**关键洞察：** 事先安装不常见的文件系统驱动（`hfsplus`、`affs`）。部分层在无分区表时需手动计算扇区偏移。

---

## 通过空字节交错实现反切割（BSidesSF 2024）

文件以每隔一个位置插入空字节的方式存储，能绕过基于魔数的文件切割工具（binwalk、foremost、scalpel）：

1. **识别反切割：** 文件切割找不到文件，但 `xfs_db` 或文件系统级工具显示文件存在且大小正确
2. **提取原始块：** 利用文件系统 extent 信息定位文件数据

```bash
# XFS：查找文件 extent
xfs_db -r disk.img -c 'inode <inum>' -c 'print'
# 提取 extent 数据
dd if=disk.img bs=4096 skip=<startblock> count=<blockcount> of=raw.bin
```

3. **去除交错的空字节：** 只保留偶数（或奇数）位置的字节

```python
with open('raw.bin', 'rb') as f:
    data = f.read()
# 去除奇数位置的空字节
cleaned = bytes(data[i] for i in range(0, len(data), 2))
with open('recovered.png', 'wb') as f:
    f.write(cleaned)
```

```perl
# Perl 单行命令等效
perl -0777 -pe 's/(.)./\1/gs' raw.bin > recovered.png
```

**关键洞察：** 当文件切割失败但文件系统元数据完好时，通过块级访问提取并查找字节级混淆模式。空字节交错会使文件大小翻倍——比较实际大小与预期大小是检测启发式方法。

---

---

## BTRFS 子卷/快照恢复（BSidesSF 2026）

**模式（时光倒流）：** BTRFS 文件系统中删除的文件可能仍存在于快照或备用子卷中。默认挂载只显示活动子卷，但备份快照包含历史文件状态。

**恢复流程：**
```bash
# 1. 设置环回设备
sudo losetup /dev/loop0 challenge.img

# 2. 列出可用子卷
sudo btrfs subvolume list /dev/loop0
# 输出示例：ID 256 gen 7 top level 5 path @
#           ID 257 gen 5 top level 5 path @backup

# 3. 挂载默认子卷（可能显示删除文件缺失）
sudo mount /dev/loop0 /mnt/default
ls /mnt/default/  # flag 文件缺失

# 4. 挂载备份子卷
sudo mount -o subvol=@backup /dev/loop0 /mnt/backup
ls /mnt/backup/   # flag 文件存在！
cat /mnt/backup/flag.txt

# 5. 另一种方式：通过子卷 ID 挂载
sudo mount -o subvolid=257 /dev/loop0 /mnt/backup
```

**BTRFS 取证关键命令：**
```bash
# 显示文件系统信息
btrfs filesystem show /dev/loop0

# 列出所有子卷（包括快照）
btrfs subvolume list -a /mnt

# 显示快照详情
btrfs subvolume show /mnt/@backup

# 查找已删除子卷（孤立）
btrfs-find-root /dev/loop0
```

**BTRFS 快照类型：**
- **可写子卷：** `@`、`@home` — 标准 Ubuntu 布局
- **只读快照：** 由 `btrfs subvolume snapshot -r` 创建 — 不可变副本
- **备份子卷：** `@backup`、`@snap-YYYYMMDD` — 命名因工具（Timeshift、snapper）而异

**关键洞察：** BTRFS 采用写时复制。删除活动子卷中的文件不会擦除数据，只要快照或备用子卷仍引用这些块。务必使用 `btrfs subvolume list` 枚举所有子卷。`-o subvol=` 挂载选项是访问非默认子卷的关键。

**检测：** `file disk.img` 显示 “BTRFS Filesystem”。挑战中提及“快照”、“时光旅行”、“倒带”或“恢复”。

**参考：** BSidesSF 2026 “turn-back-the-clock”

---
## FAT16 空闲空间数据恢复（BSidesSF 2026）

**模式（freeflag）：** 数据隐藏在 FAT16 文件系统的空闲（未分配）簇中。挂载的文件系统没有可疑文件，但空闲簇中包含可恢复的数据。

```python
import struct

with open("disk.img", "rb") as f:
    # 读取 FAT16 引导扇区
    f.seek(0)
    boot = f.read(512)
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    reserved_sectors = struct.unpack_from("<H", boot, 14)[0]
    num_fats = boot[16]
    sectors_per_fat = struct.unpack_from("<H", boot, 22)[0]
    root_entries = struct.unpack_from("<H", boot, 17)[0]

    cluster_size = bytes_per_sector * sectors_per_cluster
    fat_start = reserved_sectors * bytes_per_sector
    root_dir_start = fat_start + (num_fats * sectors_per_fat * bytes_per_sector)
    data_start = root_dir_start + (root_entries * 32)

    # 读取 FAT 表
    f.seek(fat_start)
    fat = f.read(sectors_per_fat * bytes_per_sector)

    # 查找空闲簇（FAT 条目 == 0x0000）
    free_data = b""
    for cluster in range(2, len(fat) // 2):
        entry = struct.unpack_from("<H", fat, cluster * 2)[0]
        if entry == 0x0000:  # 空闲簇
            offset = data_start + (cluster - 2) * cluster_size
            f.seek(offset)
            free_data += f.read(cluster_size)

    # 在空闲空间中搜索 flag
    if b"CTF{" in free_data:
        idx = free_data.index(b"CTF{")
        print(free_data[idx:idx+100])
```

**关键洞察：** FAT16/FAT32 将已删除文件的簇标记为空闲（条目 = 0x0000），但不会清零数据。枚举空闲簇并读取其内容可以恢复已删除或隐藏的数据。可以使用 `foremost`、`scalpel` 或手动解析 FAT 表提取这些数据。检查卷标以获取提示（例如 "FREESPACE"）。

**识别时机：** 挑战提供文件系统镜像。挂载后无有用内容，但 `file` 命令识别为 FAT16/FAT32。卷标或挑战描述提示“空闲空间”、“已删除”或“明文隐藏”。

**参考资料：** BSidesSF 2026 “freeflag”

---

## 通过 Sleuth Kit 恢复 FAT16 已删除文件（MetaCTF Flash 2026）

**模式（rm -rf flag.png）：** 一个文件从 FAT16 文件系统镜像中被删除。文件数据和簇链仍然完整，但目录项的第一个字节被替换为 `0xE5`（FAT 删除标记）。Sleuth Kit 的 `fls` 和 `icat` 可通过 inode 恢复文件。

```bash
# 第一步：识别文件系统
file flash.img
# flash.img: DOS/MBR boot sector, code offset 0x3e+2, ... FAT (16 bit) ...

# 第二步：列出所有文件，包括已删除的（-d = 仅已删除，-r = 递归）
fls -r -d flash.img
# r/r * 4:    _lag.png    (首字符被 FAT 删除标记替换)

# 第三步：通过 inode 号恢复已删除文件
icat flash.img 4 > recovered_flag.png

# 第四步：验证恢复结果
file recovered_flag.png
# recovered_flag.png: PNG image data, 800 x 600, 8-bit/color RGBA
```

**关键洞察：** FAT16/FAT32 删除操作仅将目录项首字节标记为 `0xE5`，并在 FAT 表中将簇标记为空闲，但实际文件数据直到被覆盖前仍保留在磁盘上。文件名看似被破坏（例如 `flag.png` 变成 `_lag.png`），但 `fls -d` 会列出已删除条目，`icat` 通过原簇链提取完整文件。此方法比空闲空间雕刻更精准，因为保留了原文件边界。

**识别时机：** 挑战提供带有已删除文件的 FAT 文件系统镜像。挑战名称或描述提示删除（`rm`、`deleted`、`removed`）。挂载后文件缺失，但 `fls` 显示已删除目录项。

**替代方法：**
- 使用 `foremost` / `scalpel` 进行无文件系统感知的雕刻
- 使用 `fatcat` 进行低级 FAT 操作
- 手动十六进制编辑：搜索目录簇中的 `0xE5` 条目

**参考资料：** MetaCTF Flash CTF 2026 “rm -rf flag.png”

---

## 通过 fsck 恢复 Ext2 孤立 inode（BSidesSF 2026）

**模式（orphan）：** 一个文件从 ext2 文件系统中被删除，留下孤立 inode。该文件不出现在任何目录列表中，但 `fsck` 能检测到未连接的 inode 并将其重新连接到 `/lost+found`。

```bash
# 挂载镜像 — 无 flag 可见
sudo mount -o loop disk.img /mnt
ls /mnt  # 无有用内容

# 运行 fsck 检测孤立 inode
sudo umount /mnt
e2fsck -y disk.img
# 输出: "Unattached inode 13"
# 输出: "Connect to /lost+found? yes"

# 重新挂载并检查 lost+found
sudo mount -o loop disk.img /mnt
ls /mnt/lost+found/
# 找到: #13
file /mnt/lost+found/\#13  # 识别文件类型（例如 PNG）
cp /mnt/lost+found/\#13 recovered_flag.png
```

**关键洞察：** Ext2/ext3/ext4 删除操作移除目录项，但 inode 和数据块可能在被覆盖前仍存在。`e2fsck`（使用 `-y` 自动修复）能检测这些孤立 inode 并将其连接到 `/lost+found`，文件名为数字编号。对于 ext2（无日志）来说，恢复更可靠，因为删除时不会清零数据块。

**识别时机：** 挑战提供 ext2/ext3/ext4 文件系统镜像。正常挂载无内容。挑战提示“删除”、“孤立”、“丢失”或“恢复”。对取证文件系统镜像应始终运行 `fsck`。

**替代工具：**
- `debugfs` — 交互式 ext2 探索：`debugfs disk.img` 后用 `lsdel` 列出已删除 inode
- `extundelete` — 自动化 ext3/ext4 恢复
- `icat`（Sleuth Kit）— 通过 inode 号提取文件：`icat disk.img 13 > recovered`

**参考资料：** BSidesSF 2026 “orphan”

---

## 通过头字段修改修复损坏的 ZIP（PlaidCTF 2017）

ZIP 归档中损坏的文件名长度字段可以通过十六进制编辑本地文件头和中央目录项来修复。

```python
# ZIP 本地文件头格式（从 PK\x03\x04 偏移 0x04 开始）：
# 偏移 26：文件名长度（2 字节，小端序）
# ZIP 中央目录项（在 PK\x01\x02）：
# 偏移 28：文件名长度（2 字节，小端序）

# 修复：将两个文件名长度字段设置为实际文件名大小
import struct
with open('broken.zip', 'rb') as f:
    data = bytearray(f.read())

# 查找并修正本地文件头文件名长度
lfh = data.index(b'PK\x03\x04')
struct.pack_into('<H', data, lfh + 26, 8)  # 设置为 8 字节

# 查找并修正中央目录文件名长度
cde = data.index(b'PK\x01\x02')
struct.pack_into('<H', data, cde + 28, 8)  # 必须匹配

# 写入修正后的文件名字节
data[lfh+30:lfh+38] = b'flag.txt'

with open('fixed.zip', 'wb') as f:
    f.write(data)

# 备选方案：对候选偏移进行 deflate 解压暴力尝试
import zlib
with open('broken.zip', 'rb') as f:
    raw = f.read()
for offset in range(0x1E, 0x100):
    try:
        result = zlib.decompress(raw[offset:], -15)
        print(f"Offset {offset:#x}: {result}")
        break
    except zlib.error:
        continue
```

**关键洞察：** ZIP 文件名长度字段同时出现在本地文件头（偏移 26）和中央目录（偏移 28），两者必须匹配且反映实际文件名长度。当这些字段被破坏为异常值（如 9001）时，归档看起来为空。作为备选，尝试对候选数据偏移进行原始 deflate 解压。

**检测方法：** ZIP 文件使用 `unzip -l` 显示为空或报错无效文件名长度。`hexdump` 显示有效的 `PK\x03\x04` 和 `PK\x01\x02` 签名，但长度字段异常。

---
## 从 FAT 镜像恢复已删除的 .git 仓库（Square CTF 2017）

一个包含已删除 `.git` 目录的 FAT 文件系统镜像。使用 TSK 的 `fls -r` 列出所有文件，包括已删除的（以 `*` 标记）。用 `icat` 提取已删除的 inode。根据提取的文件重建 git 对象目录结构，然后使用 `git fsck` 和 `git log` 恢复提交历史和 flag。

```bash
# 第一步：列出所有文件，包括已删除的（* 前缀 = 已删除）
fls -r disk.img | grep '\*'
# 示例输出：
# r/r * 5:   .git/HEAD
# r/r * 6:   .git/config
# r/r * 7:   .git/objects/ab/cdef1234...

# 第二步：按 inode 号提取已删除文件
icat disk.img 5 > HEAD
icat disk.img 6 > config
# 对所有 git 对象 inode 重复此操作

# 第三步：重建 .git 目录结构
mkdir -p recovered/.git/objects/ab/
# 将每个提取的对象放置到正确路径

# 第四步：恢复提交历史
cd recovered
git fsck --full        # 检查对象完整性，查找悬挂提交
git log --all          # 显示所有提交，包括未引用的
git show <commit_hash> # 查看特定提交以获取 flag
```

**关键洞察：** FAT 通过将目录项的第一个字节改为 `0xE5` 来标记已删除文件，但保持簇数据不变直到被重用。TSK 的 `fls`/`icat` 通过 inode 提取已删除文件，使删除在取证上可逆。Git 对象是内容寻址的——一旦提取，`git fsck` 即使没有有效的 HEAD 引用也能找到所有可达提交。

---

## 从 Git 提交历史恢复 DNSSEC 密钥（Hack.lu 2017）

DNSSEC 私有签名密钥提交到 git 仓库后被删除，但仍永久保留在提交历史中。恢复密钥以搭建本地 BIND 实例并伪造 DNSSEC 签名的 DNS 响应。

```bash
# 第一步：查找删除密钥文件的提交
git log --all --diff-filter=D -- '*.private' '*.key' 'Kexample.*.+*.+*.key'

# 第二步：从删除前的提交恢复已删除的密钥文件
git show <commit_hash>^:<path/to/Kzone.+005+12345.private> > recovered.private
git show <commit_hash>^:<path/to/Kzone.+005+12345.key> > recovered.key

# 备选：搜索所有提交中的密钥材料
git log --all -p -- '*.private' | grep -A 20 'Private-key-format'

# 第三步：验证密钥内容
cat recovered.private
# Private-key-format: v1.3
# Algorithm: 5 (RSASHA1)
# ...

# 第四步：使用恢复的密钥伪造 DNSSEC 签名响应
# 用恢复的签名密钥配置 BIND 并签名区域
dnssec-signzone -K /path/to/keys -o example.com zone.db
```

**关键洞察：** git 历史中的敏感加密密钥材料是永久可恢复的——`git log --diff-filter=D` 查找所有删除文件的提交，`git show <commit>^:<path>` 获取删除前的文件状态。DNSSEC 私钥允许伪造该区域的任意 DNS 记录，从而实现 DNS 缓存投毒或将流量重定向到攻击者控制的服务器。

---

## 通过 CRC32 重建修复 XZ 流头（Hackover 2018）

**模式：** 文件有有效的 XZ 流尾，但流头被覆盖（通常用 `PK\x03\x04` 伪装成 ZIP）。根据格式规范重建 12 字节 XZ 头：魔数 `FD 37 7A 58 5A 00`，两个字节的流标志，以及这两个标志的 4 字节小端 CRC32。将重建的头部加到文件前面，`xz -d` 可正常解压。

```bash
# 1. 确认尾部 — XZ 流尾魔数是文件末尾的 "YZ"
xxd broken.xz | tail -1
# 00002ff0: 00 00 01 59 5A  ...YZ

# 2. 从尾部读取 stream_flags（从文件末尾偏移 -6 处的两个字节）
STREAM_FLAGS=$(xxd -p -s -6 -l 2 broken.xz)
# 例如 00 04  → CHECK_CRC64

# 3. 计算这两个标志字节的 CRC32（小端输出）
CRC=$(python3 -c "import binascii; print(binascii.crc32(bytes.fromhex('$STREAM_FLAGS')).to_bytes(4,'little').hex())")

# 4. 重建头部并替换文件前 12 字节
printf '\xFD7zXZ\x00' > newhdr.bin
printf '%s' "$STREAM_FLAGS" | xxd -r -p >> newhdr.bin
printf '%s' "$CRC"          | xxd -r -p >> newhdr.bin
dd if=newhdr.bin of=broken.xz bs=1 count=12 conv=notrunc

# 5. 解压
xz -d broken.xz
```

**关键洞察：** XZ 流由固定的 12 字节头和 12 字节尾组成，两者都包含相同的 `stream_flags` 字节——当头部损坏时，可以从完好的尾部复制标志并重新计算头部 CRC32。此头部重建技巧适用于任何校验输入足够小以暴力破解或从尾部推导的格式：GZIP（尾部的 `isize`/`crc32`）、ZIP（中央目录在本地文件头之前）、zstd（带跳帧的帧头）。当挑战给你一个魔数属于错误格式的文件时，先检查**最后几个字节**的真实尾部签名，再尝试修复头部。

**参考：** Hackover CTF 2018 — UnbreakMyStart，writeup 11508

---

## 通过 bkcrack 破解 ZipCrypto 已知明文（Codegate 2019）

**模式：** ZipCrypto（传统 PKZIP 流密码，非 AES-256）在拥有至少 12 字节已知明文时易受已知明文攻击。`pkcrack` 是经典工具，但常在现代压缩包上失败；`bkcrack`（[bkcrack](https://github.com/kimci86/bkcrack)）能处理部分头部的边缘情况。

```bash
# 提取任意未加密的邻近文件及其加密版本
unzip secret.zip unencrypted_known.txt
bkcrack -C secret.zip -c target.txt -p unencrypted_known.txt -P known.zip
# 用恢复的内部状态解密整个压缩包
bkcrack -C secret.zip -k <k0> <k1> <k2> -d target_decrypted.bin
```

**关键洞察：** ZIP 头通常包含已知常量（PNG/JPEG 魔数、空的 `README.txt`、`.gitignore`）。任何带有未加密参考文件的加密 ZIP，或你能猜出 12 字节以上头部的，都能立即被 `bkcrack` 破解。当 `pkcrack` 失败时切换使用它。

**参考：** Codegate CTF 2019 — Rich Project，writeup 12907

---

## SQLite Serial-Type 字节取证（RITSEC 2018）

**模式：** 两个几乎相同的 SQLite 文件仅在选定字节不同。SQLite 记录用“serial type”变长整数编码每列，既描述类型又携带长度（类型 ≥13 表示字符串，长度为 `(type - 13) / 2`）。遍历记录，定位版本间变化的 serial-type 字节，读取相邻文本载荷以恢复隐藏字符。

```python
def extract_hidden(path):
    with open(path, 'rb') as f: db = f.read()
    offsets = [0x892, 0xBA5, 0xE13]   # 先对比两个文件
    return bytes(db[off] for off in offsets)
```

**关键洞察：** SQLite 的 varint serial-type 方案将元数据*内联*存储于载荷中，攻击者只需翻转一个 varint 即可改变接下来 N 字节的解释。逐字节对比两个版本，按记录聚类差异，解码每个 varint 定位隐藏文本字段。

**参考：** RITSEC CTF 2018 — Lite Forensics，writeup 12223

---
## 递归 Binwalk 链 PNG->PDF->DOCX->PNG->Base64 (TAMUctf 2019)

**模式：** 一个载体文件隐藏了一连串嵌套文档——PNG 文件后面附加了 PDF，PDF 内嵌了 DOCX（其实是 ZIP），DOCX 内嵌了另一个 PNG，而该 PNG 在 IEND/EOF 后附加了 Base64。每一层都改变容器格式以规避简单的字符串搜索。

```bash
# 第1-2层：从外层 PNG 中提取所有内容（拉出 PDF、ZIP 流等）
binwalk --dd=".*" art.png
cd _art.png.extracted
file *                      # 识别 Microsoft Word 2007+ 数据块

# 第3层：DOCX 是 ZIP 压缩包
unzip 34591D -d docx/        # binwalk 的十六进制偏移作为文件名
ls docx/word/media/          # image1.png 是下一层载体

# 第4层：对内层 PNG 递归 binwalk，提取嵌入的 PDF
binwalk --dd=".*" docx/word/media/image1.png

# 第5层：检查内层 PDF 的 %%EOF 之后是否有附加数据
strings _image1.png.extracted/*.pdf | tail -n 10
# -> ZmxhZ3tQMGxZdEByX0QwX3kwdV9HM3RfSXRfTjB3P30K
echo 'ZmxhZ3tQMGxZdEByX0QwX3kwdV9HM3RfSXRfTjB3P30K' | base64 -d
```

**关键洞察：** 当对最外层文件执行 `grep flag` 失败时，假设每个提取出的文件本身也是一个载体。DOCX/XLSX/PPTX/APK/JAR 都是 ZIP 格式，因此可以直接用 `unzip`。PDF 通常会在最后的 `%%EOF` 之后携带数据，所以总是用 `strings | tail` 或跳过 trailer 来查看。`binwalk --dd=".*"` 会将每个签名命中写入磁盘，方便递归操作且输入命令简洁。

**参考资料：** TAMUctf 2019 — I Heard You Like Files，writeups 13412 和 13587

---

## 带 exrex 的正则密码嵌套 Zip 链 (UTCTF 2019)

**模式：** 外层 zip 包含一个 `hint.txt`（正则表达式）和 `archive.zip`；正则表达式枚举内层 zip 的密码集合。每解压一层 zip 就得到下一层的正则提示。链条很深（1000+ 层），必须脚本化。`exrex.generate(regex)` 可以生成所有匹配正则的字符串，非常适合受限密码空间。

```python
import exrex, zipfile, os

hint = r'^  7  y  RU[A-Z]KKx2 R4\d[a-z]B  N$'
archive = 'RegularZips.zip'

for i in range(10000):
    candidates = list(exrex.generate(hint))
    out_dir = f'layer{i}'
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for pw in candidates:
            try:
                zf.extractall(out_dir, pwd=pw.encode())
                print(f'[{i}] pw={pw}')
                break
            except Exception:
                continue
        else:
            raise RuntimeError(f'no password matched regex at layer {i}')
    with open(os.path.join(out_dir, 'hint.txt')) as f:
        hint = f.read().strip()
    archive = os.path.join(out_dir, 'archive.zip')
    if not os.path.exists(archive):
        print('FLAG IN', out_dir)
        break
```

**关键洞察：** 当 zip 密码由正则表达式描述时，不要盲目暴力 ASCII 枚举——用 `exrex` 只生成匹配的字符串（通常每层只有少数候选）。自动化提取-读取提示-重复循环；1000 层几秒内完成，因为每层的搜索空间极小。

**参考资料：** UTCTF 2019 — Regular Zips，writeups 13951 和 13861

---

## 另见

- [disk-and-memory.md](disk-and-memory.md) - 核心磁盘/内存取证（Volatility，磁盘镜像分析，VM/OVA/VMDK，VMware 快照，coredump，KAPE 甄别，PowerShell 勒索软件，Android/Docker/云取证，BSON 重建，TrueCrypt/VeraCrypt 挂载）
- [disk-advanced.md](disk-advanced.md) - 高级磁盘和内存技术（已删除分区，ZFS 取证，GPT GUID 编码，VMDK 稀疏解析，内存转储字符串提取，勒索软件密钥恢复，WordPerfect 宏 XOR，minidump ISO 9660 恢复，APFS 快照，RAID 5 XOR 恢复）