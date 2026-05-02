# CTF Forensics - 高级磁盘与内存技术

## 目录
- [已删除分区恢复](#deleted-partition-recovery)
- [ZFS 取证（Nullcon 2026）](#zfs-forensics-nullcon-2026)
- [GPT 分区 GUID 数据编码（VuwCTF 2025）](#gpt-partition-guid-data-encoding-vuwctf-2025)
- [Windows Minidump 字符串提取（0xFun 2026）](#windows-minidump-string-carving-0xfun-2026)
- [VMDK 稀疏解析（0xFun 2026）](#vmdk-sparse-parsing-0xfun-2026)
- [内存转储字符串提取（Pragyan 2026）](#memory-dump-string-carving-pragyan-2026)
- [内存转储恶意软件提取 + XOR（VuwCTF 2025）](#memory-dump-malware-extraction--xor-vuwctf-2025)
- [Linux 勒索软件内存密钥恢复（MetaCTF 2026）](#linux-ransomware-memory-key-recovery-metactf-2026)
- [WordPerfect 宏 XOR 提取（srdnlenCTF 2026）](#wordperfect-macro-xor-extraction-srdnlenctf-2026)
- [Minidump ISO 9660 恢复 + XOR 密钥（srdnlenCTF 2026）](#minidump-iso-9660-recovery--xor-key-srdnlenctf-2026)
- [APFS 快照历史文件恢复（srdnlenCTF 2026）](#apfs-snapshot-historical-file-recovery-srdnlenctf-2026)
- [通过 XOR 恢复 RAID 5 磁盘（Crypto-Cat）](#raid-5-disk-recovery-via-xor-crypto-cat)
- [HFS+ 资源分支隐藏二进制恢复（CONFidence CTF 2017）](#hfs-resource-fork-hidden-binary-recovery-confidence-ctf-2017)
- [通过增量键插入进行 Kyoto Cabinet 哈希数据库取证（ASIS CTF 2018）](#kyoto-cabinet-hash-database-forensics-via-incremental-key-insertion-asis-ctf-2018)
- [从差异表重建 SQLite 编辑历史（Google CTF 2017）](#sqlite-edit-history-reconstruction-from-diff-table-google-ctf-2017)
- [另见](#see-also)

---

## 已删除分区恢复

**模式（Till Delete Do Us Part）：** 带有已删除分区表的 USB 镜像。

**恢复流程：**
```bash
# 检查分区
fdisk -l image.img              # 显示无分区

# 恢复分区表
testdisk image.img              # 交互式恢复

# 或使用 kpartx 映射分区
kpartx -av image.img            # 映射为 /dev/mapper/loop0p1

# 挂载恢复的分区
mount /dev/mapper/loop0p1 /mnt/evidence

# 检查隐藏目录
ls -la /mnt/evidence            # 查找 .dotfolders
find /mnt/evidence -name ".*"   # 查找隐藏文件
```

**Flag 隐藏方式：** 路径组件作为 flag 字符（例如 `/.Meta/CTF/{f/l/a/g}`）

---

## ZFS 取证（Nullcon 2026）

**模式：** 损坏的 ZFS 池镜像，包含加密数据集。

**恢复流程：**
1. **标签重建：** 所有 4 个 ZFS 标签可能被清零。使用 `strings` + 偏移搜索在镜像其他位置找到打包的 nvlist 数据。
2. **MOS 对象修复：** 将已知良好的 nvlist 字节复制到块位置，重新计算 Fletcher4 校验和：
```python
def fletcher4(data):
    a = b = c = d = 0
    for i in range(0, len(data), 4):
        a = (a + int.from_bytes(data[i:i+4], 'little')) & 0xffffffff
        b = (b + a) & 0xffffffff
        c = (c + b) & 0xffffffff
        d = (d + c) & 0xffffffff
    return (d << 96) | (c << 64) | (b << 32) | a
```
3. **加密破解：** 从 ZAP 对象中提取 PBKDF2 参数（迭代次数、盐）。使用 PyOpenCL GPU 加速 PBKDF2-HMAC-SHA1，CPU 验证 AES-256-GCM 解包。
4. **密码列表：** rockyou.txt 或类似。GPU 速率约 24k 密码/秒。

---

## GPT 分区 GUID 数据编码（VuwCTF 2025）

**模式（Undercut）：** “仅限 LLMs” + “undercut” → 不是 AI GPT，而是 GUID 分区表。

**关键洞察：** GPT 分区 GUID 是 16 个任意字节——可以编码任何内容。查找 GUID 中的文件魔数头。

```bash
# 解析 GPT 分区表
gdisk -l image.img
# 或用 Python：
python3 -c "
import struct
data = open('image.img','rb').read()
# GPT 头在 LBA 1（偏移 512）
# 分区条目从 LBA 2（偏移 1024）开始
# 每个条目 128 字节，GUID 在偏移 16（16 字节）
for i in range(128):
    entry = data[1024 + i*128 : 1024 + (i+1)*128]
    guid = entry[16:32]
    if guid != b'\x00'*16:
        print(f'Partition {i}: {guid.hex()}')
"
```

**第一个 GUID 以 `BZh11AY&SY` 开头**（bzip2 魔数）→ 拼接 GUID，作为 bzip2 解压，再解码 ASCII85。

---

## Windows Minidump 字符串提取（0xFun 2026）

**模式（kd）：** Go 二进制崩溃转储。flag 作为明文字符串常量在 .data 段中存活于 minidump 内存。

```bash
strings -a minidump.dmp | grep -i "flag\|ctf\|0xFUN"
```

**经验：** Minidump 包含完整内存区域。字符串常量、密钥和秘密均保留。`strings -a` + `grep` 是快速路径。

---

## VMDK 稀疏解析（0xFun 2026）

**模式（VMware）：** 分割稀疏 VMDK 需要遍历 grain 目录和 grain 表。

**关键步骤：**
1. 解析 VMDK 稀疏头（grain 大小，GD 偏移，GT 覆盖）
2. 跟踪 grain 目录 → grain 表 → 数据 grain
3. 计算跨分割文件的绝对磁盘偏移
4. 挂载提取的文件系统（ext4，NTFS）

**经验：** 不要假设 VM 镜像可以直接挂载。需手动解析 VMDK 稀疏格式。

---

## 内存转储字符串提取（Pragyan 2026）

**模式（c47chm31fy0uc4n）：** Linux 内存转储，flag 存在于环境变量或进程数据中。

```bash
strings -a -n 6 memdump.bin | grep -E "SYNC|FLAG|SSH_CLIENT|SESSION_KEY"
# SSH 相关信息揭示源 IP 和临时端口
# 环境变量可能包含密钥/令牌
```

---

## 内存转储恶意软件提取 + XOR（VuwCTF 2025）

**模式（Jellycat）：** 从 Windows 内存转储中提取伪可执行文件。加密方式：先减去 0x32，再用循环密钥 XOR（大型多行字符串，如 ASCII 艺术）。

**关键经验：** 始终从内存中提取并逆向实际二进制，而非信任 `strings` 输出（字符串表可能是误导）。XOR 密钥可达数百字节（ASCII 艺术、Lorem Ipsum）。

```python
# 提取二进制，在数据段找到 XOR 密钥
key = b"..."  # 大型 ASCII 艺术字符串
cipher = open('extracted.bin', 'rb').read()
plaintext = bytes((b - 0x32) ^ key[i % len(key)] for i, b in enumerate(cipher))
```

---

## Linux 勒索软件内存密钥恢复（MetaCTF 2026）

**模式：** Linux 内存转储 + 加密 `.veg` 文件 + `enc_key.bin`；勒索软件使用混合加密（文件用 AES，密钥用 RSA 包装）。Volatility 可能因符号/KASLR（内核地址空间布局随机化）不匹配而无法列举进程。

**快速流程：**
1. **分析前确认归档完整性。**
```bash
unzip -l encrypted_files.zip
# 比较列出的文件/大小与提取树；不符则重新干净提取
unzip -o encrypted_files.zip -d encrypted_full
```

2. **快速逆向勒索软件二进制以识别模式/布局。**
```bash
strings -a ransomware.elf | grep -E "enc_key|EVP_aes|PUBLIC KEY|.veg"
objdump -d ransomware.elf | less
```
- 典型发现：`AES-256-OFB`，IV 前置于每个 `.veg`，全局 32 字节 AES 密钥，硬编码 RSA 公钥。

3. **尝试正常使用 Volatility，若输出为空/不稳定立即转向。**
```bash
vol -f memdump.raw linux.pslist
vol -f memdump.raw linux.proc.Maps
vol -f memdump.raw linux.vmayarascan
```
- 若 Linux 插件返回空或无效输出，尽管 banner/符号正确，执行**原始内存候选扫描**。

4. **通过锚点候选扫描 + 魔数验证恢复 AES 密钥。**
- 利用内存中重复出现的锚点字符串（如 `/home/.../enc_key.bin`，HOME 路径）。
- 推导锚点附近的候选偏移（页对齐窗口）。
- 测试每个 32 字节候选，通过解密多个 `.veg` 文件的前几个块并检查魔数（`%PDF-`，`PK\x03\x04`，`\x89PNG\r\n\x1a\n`）。
- 保留满足多个独立签名的候选。

5. **解密完整数据集并验证输出完整性。**
```bash
# OFB：iv = 前 16 字节，密文从 +16 开始
# 递归解密所有 *.veg，来自干净提取目录
```
- 验证恢复文件数与 zip 列表一致。
- 注意重复镜像树（如 `snap/*/Downloads/...`），逻辑去重。

6. **防范假 flag。**
- 将仅元数据的 flag 视为可疑，除非挑战上下文支持。
- 优先使用主项目工件中的令牌并执行唯一性检查：
```bash
rg -n -a '[A-Za-z]+CTF\\{[^}]+\\}' recovered_full
pdftotext recovered_full/**/*.pdf - 2>/dev/null | rg '[A-Za-z]+CTF\\{'
```

**关键经验：**
- 不要信任部分/过时的提取树；重新干净提取 zip。
- 在 OFB 勒索软件中，魔数验证是快速密钥 oracle。
- 元数据中合理的 `CTF{...}` 可能是诱饵；需全语料库一致性确认。

---
## WordPerfect 宏 XOR 提取 (srdnlenCTF 2026)

**模式（Trilogy of Death Vol I: Corel）：** Corel Linux 磁盘镜像包含带有 XOR 加密字节数组的 WordPerfect 宏文件（fc.wcm）。

**关键洞察：** WordPerfect 宏文件（`.wcm`）可以包含带有嵌入加密数据的可执行宏。XOR 公式 `(bb + kb) - 2*(bb & kb)` 在数学上等价于按位 XOR。

**在字符集约束下暴力破解 4 字节 XOR 密钥：**
```python
import string

docbody = [206, 56, 8, 128, 209, 47, 2, 149, ...]  # 宏中的加密字节
allowed = set(map(ord, string.ascii_lowercase + string.digits + "_{}"))

# 独立为每个 mod 4 位置寻找有效的密钥字节
cands = []
for j in range(4):
    good = []
    for k in range(256):
        if all((docbody[i] ^ k) in allowed for i in range(j, len(docbody), 4)):
            good.append(k)
    cands.append(good)

# 尝试所有组合（通常每个位置候选很少）
for k0 in cands[0]:
    for k1 in cands[1]:
        for k2 in cands[2]:
            for k3 in cands[3]:
                key = [k0, k1, k2, k3]
                pt = ''.join(chr(c ^ key[i % 4]) for i, c in enumerate(docbody))
                if pt.startswith("srd") and pt.endswith("}"):
                    print(pt)
```

**经验教训：** 传统文档格式（WordPerfect、Lotus 1-2-3）可以嵌入带有混淆数据的可执行宏。当你知道 flag 字符集时，通过独立过滤每个密钥字节，暴力破解短 XOR 密钥非常简单。

---

## Minidump ISO 9660 恢复 + XOR 密钥 (srdnlenCTF 2026)

**模式（Trilogy of Death Vol II: The Legendary Armory）：** 两个驻留在易失性内存（minidump）中的遗迹必须进行 XOR；内存碎片中的 ISO 9660 目录项指向隐藏数据。

**技术步骤：**
1. 在 minidump 中搜索 ISO 9660 目录项签名
2. 解析目录项以定位目标文件偏移和大小
3. 使用恢复的 XOR 密钥（例如 8 字节循环密钥）解密文件
4. 将结果数据解析为无中央目录的 ZIP（仅本地头）

**无中央目录的 ZIP 本地头解析：**
```python
import struct, zlib

pos = 0
files = {}
while True:
    off = dec.find(b"PK\x03\x04", pos)
    if off < 0:
        break
    (ver, flag, method, _, _, crc, csize, usize, nlen, xlen) = struct.unpack_from(
        "<HHHHHIIIHH", dec, off + 4)
    name = dec[off + 30:off + 30 + nlen].decode()
    data_off = off + 30 + nlen + xlen
    comp = dec[data_off:data_off + csize]
    if method == 8:  # Deflate
        raw = zlib.decompress(comp, -15)
    else:
        raw = comp
    files[name] = raw
    pos = data_off + csize
```

**关键洞察：** 当 ZIP 中央目录缺失或损坏时，直接遍历本地文件头（`PK\x03\x04`）。每个本地头包含足够的元数据（压缩方法、大小、文件名）以独立提取文件。

---

## APFS 快照历史文件恢复 (srdnlenCTF 2026)

**模式（Trilogy of Death Vol III: The Poisoned Apple）：** APFS 卷维护历史快照；恢复关键文件的早期状态可揭示中毒前的真实值。

**技术步骤：**
1. 从 DMG 中提取 APFS 分区（通过扇区偏移定位）
2. 在所有快照中搜索 APFS 卷超级块（魔数 `APSB`），记录事务 ID（XID）
3. 使用支持 APFS 的 Sleuth Kit 工具 `icat` 读取不同快照 XID 下的特定 inode
4. 比较跨 XID 边界的文件内容，确定中毒发生时间
5. 使用中毒前的值进行解密

**跨快照查找 APFS 卷超级块：**
```python
import struct

with open("apfs_partition.img", "rb") as f:
    mm = f.read()

snaps = []
pos = 0
while True:
    idx = mm.find(b"APSB", pos)
    if idx < 0:
        break
    # XID 位于魔数前 16 字节处（块头）
    hdr_start = idx - 32
    xid = struct.unpack_from("<Q", mm, hdr_start + 16)[0]
    blk = hdr_start // 4096
    snaps.append((xid, blk))
    pos = idx + 1

# 跨快照读取目标 inode
import subprocess
for xid, blk in sorted(set(snaps)):
    try:
        out = subprocess.check_output(
            ["icat", "-f", "apfs", "-P", "apfs", "-B", str(blk),
             "apfs_partition.img", "449414"])  # 目标 inode 号
        print(f"XID {xid}: {out[:64]}...")
    except:
        pass
```

**使用恢复的真实密钥解密：**
```python
import hashlib
from Cryptodome.Cipher import AES

# 中毒前的密钥值（在早期快照中找到）
authentic_key_hex = "39f520679fd68654500f9cd44e8caed2bc897a3227dc297c4520336de2a59dd7"
key = hashlib.pbkdf2_hmac('sha256', bytes.fromhex(authentic_key_hex), salt, iterations)
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(encrypted_flag)
```

**关键洞察：** APFS（以及其他写时复制文件系统如 ZFS/Btrfs）在快照中保留历史文件状态。当挑战涉及“中毒”或“篡改”数据时，务必检查旧快照中是否包含原始值。使用不同块偏移的 `icat` 读取同一 inode 在不同事务 ID 下的内容。

---

## 通过 XOR 恢复 RAID 5 磁盘 (Crypto-Cat)

**模式：** RAID 5 阵列中有一块磁盘损坏或丢失。提供两块正常磁盘，需通过 XOR 奇偶校验重建第三块。

**RAID 5 奇偶校验原理：** 数据分布在 N 块磁盘上，奇偶校验分布式存储。任意条带满足 `Disk1 XOR Disk2 XOR ... XOR DiskN = 0`。若缺失一块磁盘，XOR 剩余磁盘即可恢复。

**恢复脚本：**
```python
# 从 disk1 和 disk3 恢复缺失的 disk2
with open('disk1.img', 'rb') as f:
    disk1 = f.read()
with open('disk3.img', 'rb') as f:
    disk3 = f.read()

# 按字节 XOR 恢复缺失磁盘
disk2 = bytes(a ^ b for a, b in zip(disk1, disk3))

with open('disk2.img', 'wb') as f:
    f.write(disk2)
```

**恢复后操作：**
```bash
# 重新组装 RAID 阵列
mdadm --create /dev/md0 --level=5 --raid-devices=3 \
  disk1.img disk2.img disk3.img

# 或挂载单独恢复的磁盘（如果包含文件系统）
mount -o loop,ro disk2.img /mnt/recovered
```

**关键洞察：** RAID 5 在每个条带中使用所有磁盘的 XOR 奇偶校验。XOR 是自反的：若 `A XOR B XOR C = 0`，则 `B = A XOR C`。对于 N 磁盘 RAID 5，将 N-1 个正常磁盘 XOR 即可恢复缺失磁盘。

**检测方法：** 挑战提供多个大小相同的磁盘镜像，提及“阵列”、“冗余”或“奇偶校验”。`file` 命令可能识别为文件系统镜像或原始数据。

---
## HFS+ 资源分支隐藏二进制恢复（CONFidence CTF 2017）

HFS+ 文件可以有一个资源分支，包含大多数工具看不到的隐藏数据。使用 HFSExplorer 检查目录，使用带有 HFS 模板的 010 Editor 进行提取。

```bash
# 1. 挂载或打开 HFS+ 镜像
# 标准工具无法检测资源分支：
binwalk image.dmg    # 不会找到资源分支内容
strings image.dmg    # 可能显示片段

# 2. 使用 HFSExplorer 浏览目录
# 查找资源分支大小非零的文件
# 可疑：nodeID 1337 或类似的 CTF 典型 ID

# 3. 检查 .fseventsd 日志以获取历史文件操作
pip install FSEventsParser
python FSEventsParser.py -s image.dmg -o events.csv
# 显示卷上文件的创建/删除情况

# 4. 使用 010 Editor 提取资源分支数据：
# - 使用 HFS+ 模板加载磁盘镜像
# - 导航到目录 -> 目标文件 -> 资源分支范围
# - 记录范围记录中的起始块和长度
# - 如果分布在多个范围，提取并拼接：
dd if=image.dmg bs=4096 skip=$BLOCK1 count=$LEN1 of=part1.bin
dd if=image.dmg bs=4096 skip=$BLOCK2 count=$LEN2 of=part2.bin
cat part1.bin part2.bin > recovered_binary
```

**关键洞察：** HFS+ 资源分支是附加到文件的第二数据流，大多数只检查数据分支的取证工具看不到它们。`binwalk`、`foremost` 和 `strings` 都无法检测。HFSExplorer 在目录中显示两个分支；带 HFS 模板的 010 Editor 显示范围记录以便手动提取。`.fseventsd` 日志可以揭示隐藏文件的创建/删除。

**检测：** DMG 或 HFS+ 磁盘镜像，标准 carving 无法找到内容。`file` 命令识别为 "Apple HFS+" 或 "Apple Partition Map"。挑战提及 "Mac"、"Apple" 或 "hidden data"。

---

## 通过增量键插入进行 Kyoto Cabinet 哈希数据库取证（ASIS CTF 2018）

**模式：** 未知二进制文件被识别为 Kyoto Cabinet (KC) 哈希数据库。Flag 字符作为值存储，键被置零。由于数据库使用固定大小哈希表，通过逐个插入顺序键并观察二进制差异中被覆盖的哈希槽，恢复顺序。

```bash
# 识别格式
file unknown.db  # 可能无法识别 KC 格式
strings unknown.db | head  # 查找 "KCPH" 魔数

# 枚举值
kchashmgr list tokyo.kch

# 通过增量插入 + 二进制差异恢复键顺序
for i in $(seq -w 000 088); do
    cp tokyo.kch test.kch
    kchashmgr set test.kch "$i" "probe"
    diff <(xxd tokyo.kch) <(xxd test.kch) | head -5
    # 变化的偏移显示原始条目映射到键 $i
done
```

**完整恢复脚本（Python）：**
```python
import subprocess, shutil

original = 'tokyo.kch'
# 获取数据库中所有值
values = subprocess.check_output(['kchashmgr', 'list', original]).decode().splitlines()

mapping = {}
for i in range(len(values)):
    key = f'{i:03d}'
    shutil.copy(original, 'test.kch')
    subprocess.run(['kchashmgr', 'set', 'test.kch', key, 'probe'], check=True)
    # 二进制差异查找哪个槽被修改
    orig_hex = subprocess.check_output(['xxd', original]).decode()
    test_hex = subprocess.check_output(['xxd', 'test.kch']).decode()
    for orig_line, test_line in zip(orig_hex.splitlines(), test_hex.splitlines()):
        if orig_line != test_line:
            mapping[i] = orig_line  # 记录被覆盖的条目
            break

# 根据顺序值重建 flag
flag = ''.join(values[i] for i in sorted(mapping.keys()))
print(flag)
```

**关键洞察：** 哈希数据库根据键的哈希值存储条目位置。当键被置零或损坏时，存储顺序基于哈希而非插入顺序。逐个插入探针键并对数据库进行二进制差异，找出每个探针覆盖的槽，揭示原始键值映射。

---

## 通过 Diff 表重建 SQLite 编辑历史（Google CTF 2017）

SQLite 数据库存储笔记/文档编辑历史为 diff 条目（操作、位置、文本、diffset），可回放以重建任意时间点的内容。

```python
import sqlite3

db = sqlite3.connect('notes.db')
# 表结构：diffs(id, type, position, text, diffset)
# type: 'insert' 或 'remove'
diffs = db.execute("SELECT type, position, text FROM diffs ORDER BY id").fetchall()

document = ""
for op_type, position, text in diffs:
    if op_type == 'insert':
        document = document[:position] + text + document[position:]
    elif op_type == 'remove':
        document = document[:position] + document[position + len(text):]
    # 每步检查 flag（可能被输入后删除）
    if 'CTF{' in document or 'flag{' in document:
        print(f"Flag found: {document}")
```

**关键洞察：** 协作编辑工具存储增量 diff。顺序回放所有操作可揭示编辑历史中任意时刻存在的内容，包括后来删除的秘密。应在每个中间状态检查 flag，而非仅最终文档。

**检测：** SQLite 数据库，表包含 `type`/`operation`、`position`、`text` 列。挑战提及 "notes"、"editor"、"collaboration" 或 "history"。通过 `.schema` 或 `sqlite3 db.sqlite ".tables"` 查看 diff 风格表结构。

---

## 参见

- [disk-and-memory.md](disk-and-memory.md) - 核心磁盘和内存取证（Volatility 3，磁盘镜像分析，VM/OVA/VMDK 取证，VMware 快照，GIMP 原始内存转储可视化，coredump 分析，Windows KAPE 筛查，PowerShell 勒索软件，Android 取证，Docker 容器取证，云存储取证，BSON 重建，TrueCrypt/VeraCrypt 挂载）
- [disk-recovery.md](disk-recovery.md) - 磁盘恢复和提取模式（LUKS 主密钥恢复，PRNG 时间戳种子暴力破解，VBA 宏二进制恢复，FemtoZip 解压，XFS 重建，tar 重复条目提取，嵌套套娃文件系统提取，零字节交错反 carving）
