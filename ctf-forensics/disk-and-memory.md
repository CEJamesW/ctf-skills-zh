# CTF Forensics - 磁盘与内存分析

## 目录
- [内存取证（Volatility 3）](#memory-forensics-volatility-3)
- [磁盘镜像分析](#disk-image-analysis)
- [虚拟机取证（OVA/VMDK）](#vm-forensics-ovavmdk)
- [VMware 快照取证](#vmware-snapshot-forensics)
- [GIMP 原始内存转储可视化检查（INShAck 2018）](#gimp-raw-memory-dump-visual-inspection-inshack-2018)
- [核心转储分析](#coredump-analysis)
- [Windows KAPE 初筛分析（UTCTF 2026）](#windows-kape-triage-analysis-utctf-2026)
- [PowerShell 勒索软件分析](#powershell-ransomware-analysis)
- [Android 取证](#android-forensics)
- [容器取证（Docker）](#container-forensics-docker)
- [云存储取证（AWS S3 / GCP / Azure）](#cloud-storage-forensics-aws-s3--gcp--azure)
- [BSON（二进制 JSON）格式重构（IceCTF 2016）](#bson-binary-json-format-reconstruction-icectf-2016)
- [TrueCrypt / VeraCrypt 卷挂载（GreHack CTF 2016）](#truecrypt--veracrypt-volume-mounting-grehack-ctf-2016)
- [Volatility mftparser 基于偏移的已删除文件恢复（BSides Delhi 2018）](#volatility-mftparser-offset-based-deleted-file-recovery-bsides-delhi-2018)
- [通过 ASCII 艺术签名检测 Brotli Blob（ASIS Finals 2018）](#brotli-blob-detection-via-ascii-art-signature-asis-finals-2018)
- [corkami/pocs MD5 PDF 碰撞生成（35C3 2018）](#corkamipocs-md5-pdf-collision-generation-35c3-2018)
- [参见](#see-also)

---

## 内存取证（Volatility 3）

```bash
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.netscan
vol3 -f memory.dmp windows.filescan
vol3 -f memory.dmp windows.dumpfiles --physaddr <addr>
vol3 -f memory.dmp windows.mftscan | grep flag
```

**常用插件：**
- `windows.pslist` / `windows.pstree` - 进程列表
- `windows.cmdline` - 命令行参数
- `windows.netscan` - 网络连接
- `windows.filescan` - 内存中的文件对象
- `windows.dumpfiles` - 通过物理地址提取文件
- `windows.mftscan` - 内存中的 MFT 文件对象（时间戳、文件名）。注意：`mftparser` 仅限 Volatility 2，Vol3 使用 `mftscan`

---

## 磁盘镜像分析

```bash
# 只读挂载
sudo mount -o loop,ro image.dd /mnt/evidence

# Autopsy / Sleuth Kit
fls -r image.dd              # 递归列出文件
icat image.dd <inode>        # 通过 inode 提取文件

# 恢复已删除文件
photorec image.dd
foremost -i image.dd
```

---

## 虚拟机取证（OVA/VMDK）

```bash
# OVA = 包含 VMDK + OVF 的 TAR 归档
tar -xvf machine.ova

# 7z 可直接读取 VMDK（无需挂载）
7z l disk.vmdk | head -100
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r
```

**从虚拟机镜像中提取的关键文件：**
- `Windows/System32/config/SAM` - 密码哈希
- `Windows/System32/config/SYSTEM` - 启动密钥
- `Windows/System32/config/SOFTWARE` - 已安装软件
- `Users/*/NTUSER.DAT` - 用户注册表
- `Users/*/AppData/` - 浏览器数据、凭据

---

## VMware 快照取证

**将 VMware 快照转换为内存转储：**
```bash
# .vmss（挂起状态）+ .vmem（内存）→ memory.dmp
vmss2core -W path/to/snapshot.vmss path/to/snapshot.vmem
# 输出：memory.dmp（可用 Volatility/MemprocFS 分析）
```

**快照中的恶意软件狩猎（Armorless）：**
1. 检查 Amcache 中加密时间戳附近执行的二进制文件
2. 查找欺骗性名称（Unicode 近似字符：用 `ṙ` 替代 `r`）
3. 从内存中转储可疑可执行文件
4. 如果是 PyInstaller 打包：用 `pyinstxtractor` → 反编译 `.pyc`
5. 如果是 PyArmor 保护：使用 PyArmor-Unpacker

**通过 MFT 恢复勒索软件密钥：**
- 即使原始文件被删除，MFT 仍保留修改时间戳
- 基于种子的加密：恢复 mtime → 推导密钥
```bash
vol3 -f memory.dmp windows.mftscan | grep flag
# mtime 作为 Unix 纪元 → PRNG 种子 → 推导加密密钥
```

---

## GIMP 原始内存转储可视化检查（INShAck 2018）

**模式：** 当 Volatility 失败或配置文件不匹配时，直接在 GIMP 中以原始图像数据打开内存转储。滚动浏览内存并调整图像宽度，寻找以像素数据渲染的先前显示的图像。

**步骤：**
1. 在 GIMP 中打开 `.dmp` 文件：文件 > 打开，设置图像类型为“原始图像数据”
2. 设置像素格式为 RGB，宽度约为 1920（显示器分辨率）
3. 滚动文件偏移，同时用方向键调整宽度
4. 当宽度匹配原始扫描线时，先前显示的图像（桌面、浏览器内容）变得可见

```bash
# 备选方案：使用 Python + PIL 扫描内存作为像素数据
python3 -c "
from PIL import Image
import numpy as np

with open('memory.dmp', 'rb') as f:
    data = f.read()

# 尝试常见显示宽度：1920, 1366, 1280, 1024
for width in [1920, 1366, 1280, 1024]:
    stride = width * 3  # RGB = 每像素 3 字节
    # 在转储中不同偏移采样
    for offset in range(0, len(data) - stride * 100, stride * 500):
        chunk = data[offset:offset + stride * 100]
        if len(chunk) == stride * 100:
            img = Image.frombytes('RGB', (width, 100), chunk)
            # 检查图像是否有意义内容（非全零/噪声）
            arr = np.array(img)
            if 10 < arr.mean() < 245 and arr.std() > 20:
                img.save(f'frame_{width}_{offset}.png')
                print(f'潜在图像位于偏移 {offset}, 宽度 {width}')
"
```

**关键洞察：** 原始内存转储包含屏幕上显示的帧缓冲数据。GIMP 可以将任意二进制数据渲染为像素。当图像宽度匹配原始显示扫描线时，用户桌面的截图无需任何取证工具、配置文件或解密即可显现。

---

## 核心转储分析

```bash
gdb -c core.dump
(gdb) info registers
(gdb) x/100x $rsp
(gdb) find 0x0, 0xffffffff, "flag"
```

---

## Windows KAPE 初筛分析（UTCTF 2026）

**模式（Landfall、Sherlockk、Cold Workspace）：** KAPE（Kroll Artifact Parser and Extractor）初筛收集的 ZIP 包含 Windows 取证工件。多个挑战引用相同的初筛数据集。

**KAPE 初筛结构：**
```text
Modified_KAPE_Triage_Files/
├── C/
│   ├── Users/<username>/
│   │   ├── AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/
│   │   │   └── ConsoleHost_history.txt    # PowerShell 命令历史
│   │   ├── NTUSER.DAT                     # 用户注册表配置单元
│   │   └── AppData/Roaming/Microsoft/Windows/Recent/  # 最近文件
│   ├── Windows/
│   │   ├── System32/config/
│   │   │   ├── SAM          # 密码哈希
│   │   │   ├── SYSTEM       # 系统配置 + 启动密钥
│   │   │   └── SOFTWARE     # 已安装软件
│   │   └── appcompat/Programs/
│   │       └── Amcache.hve  # 执行历史及 SHA-1 哈希
│   └── $MFT                 # 主文件表
└── ...
```

**高价值工件：**

1. **PowerShell 历史** — 揭示攻击者命令：
```bash
cat "C/Users/*/AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
# 查找：凭据访问、横向移动、数据准备
```

2. **Amcache** — 执行程序及时间戳和哈希：
```bash
# 使用 Eric Zimmerman 的 AmcacheParser 或 regipy 解析
python3 -c "
from regipy.registry import RegistryHive
reg = RegistryHive('C/Windows/appcompat/Programs/Amcache.hve')
for entry in reg.recurse_subkeys(as_json=True):
    print(entry)
" | grep -i "flag\|suspicious\|malware"
```

3. **MFT 常驻数据** — 直接存储在 MFT 记录中的小文件：
```python
# 解析 MFT 中的常驻文件数据（小于约 700 字节的文件内联存储）
# 使用 analyzeMFT 或 python-ntfs
import struct

with open('$MFT', 'rb') as f:
    mft_data = f.read()

# 在原始 MFT 数据中搜索 flag 模式
import re
flags = re.findall(rb'utflag\{[^}]+\}', mft_data)
for flag in flags:
    print(f"发现: {flag.decode()}")
```

4. **内存转储中的环境变量**（Cold Workspace 模式）：
```bash
# 小型 .dmp 文件可能是包含环境变量块的迷你转储
strings -a cold-workspace.dmp | grep -i "flag\|password\|key\|secret"
# 环境变量在进程内存快照中存活
```

**UTCTF 2026 挑战模式：**
- **Landfall：** Flag 隐藏在 PowerShell 历史或 Amcache 执行记录中
- **Sherlockk：** 关联 Amcache 条目与 MFT 时间戳识别恶意活动
- **Cold Workspace：** 从内存转储提取环境变量中的 Flag
- **Checkpoint A/B：** 使用组合工件的多阶段调查

**关键洞察：** KAPE 初筛 ZIP 包含预先收集的取证工件 — 无需完整磁盘镜像。优先从 PowerShell 历史（最快）→ Amcache（执行时间线）→ MFT（小文件常驻数据）→ 注册表配置单元（持久性、凭据）开始分析。

---
## PowerShell 勒索软件分析

**模式（来自 Krampus 的邮件）：** PowerShell 内存转储 + 网络抓包。

**分析流程：**
1. 从 minidump 中提取脚本块：
```bash
python power_dump.py powershell.DMP
# 或者：strings powershell.DMP | grep -A5 "function\|Invoke-"
```

2. 识别加密方式（通常是 AES-CBC，使用 SHA-256 派生密钥）

3. 从 PCAP 中提取加密附件：
```bash
# 在 Wireshark 中过滤 SMTP 流量
# 导出附件，进行 base64 解码
```

4. 在内存转储中查找加密密钥：
```bash
# 密钥通常用 Get-Random 生成，正则搜索：
strings powershell.DMP | grep -E '^[A-Za-z0-9]{24}$' | sort | head
```

5. 类似地查找归档密码，解密各层

---

## Android 取证

```bash
# 从设备提取 APK
adb pull /data/app/com.target.app/base.apk

# 分析 APK 内容
apktool d base.apk -o decompiled/
# 检查：AndroidManifest.xml，res/values/strings.xml，shared_prefs/

# 从 Android 备份中提取数据
adb backup -apk -shared -all -f backup.ab
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar

# SQLite 数据库（联系人、短信、浏览器历史）
sqlite3 /data/data/com.android.providers.contacts/databases/contacts2.db ".tables"
sqlite3 /data/data/com.android.providers.telephony/databases/mmssms.db "SELECT * FROM sms"

# 解析 Android 文件系统镜像
mkdir android_mount && mount -o ro android_image.img android_mount/
# 关键位置：
# /data/data/<app>/databases/     — 应用 SQLite 数据库
# /data/data/<app>/shared_prefs/  — 应用偏好设置（XML）
# /data/system/packages.xml       — 已安装包信息
# /data/misc/wifi/wpa_supplicant.conf — 保存的 WiFi 密码
```

**关键洞察：** Android 将应用数据存储在 `/data/data/<package>/` 目录下，包含 SQLite 数据库和 XML 格式的共享偏好。`adb backup` 可捕获完整应用状态。CTF 中应检查 `shared_prefs/` 以寻找硬编码的秘密，`databases/` 中查找 flag。

---

## 容器取证（Docker）

```bash
# 导出 Docker 镜像层
docker save IMAGE:TAG -o image.tar
tar xf image.tar
# 每个层是一个目录，包含 layer.tar，记录文件系统变更
# 检查：layer.tar 文件中新增/修改的文件，删除的文件（.wh.* 白化文件）

# 查看镜像历史构建命令（可能包含秘密）
docker history IMAGE:TAG --no-trunc
# 显示所有 Dockerfile 指令，包括 ARG 和 ENV 值

# 不运行容器提取文件系统
docker create --name extract IMAGE:TAG
docker export extract -o container_fs.tar
docker rm extract

# 使用 dive 分析（分层差异查看器）
dive IMAGE:TAG

# 容器镜像中常见的取证目标：
# /app/.env, /app/config/* — 应用秘密
# /root/.bash_history     — 构建时命令历史
# /etc/shadow             — 泄露的凭据
# 删除的文件即使在后续层被移除，仍可在早期层中看到
```

**关键洞察：** Docker 镜像是分层的——后层删除的文件仍存在于前层的 tar 中。使用 `docker history --no-trunc` 可查看完整 Dockerfile 命令，包括通过 `ARG` 或 `ENV` 传递的秘密。`dive` 工具可交互式可视化层差异。

---

## 云存储取证（AWS S3 / GCP / Azure）

```bash
# 枚举公共 S3 桶
aws s3 ls s3://target-bucket/ --no-sign-request
aws s3 cp s3://target-bucket/flag.txt . --no-sign-request

# 检查桶版本控制（之前版本可能包含已删除的 flag）
aws s3api list-object-versions --bucket target-bucket --no-sign-request
aws s3api get-object --bucket target-bucket --key secret.txt --version-id VERSION_ID out.txt

# GCP 云存储
gsutil ls gs://target-bucket/
gsutil cp gs://target-bucket/flag.txt .

# Azure Blob 存储
az storage blob list --container-name target --account-name storageaccount
az storage blob download --container-name target --name flag.txt --account-name storageaccount
```

**关键洞察：** 云存储的版本控制会保留已删除对象。即使 flag 文件从桶中删除，之前的版本仍可通过 `list-object-versions` 访问。务必检查是否启用了版本控制的桶。

---

## BSON（二进制 JSON）格式重构（IceCTF 2016）

BSON 是 MongoDB 的二进制序列化格式。损坏的 BSON 文件需要修复头部后才能解析，且可能包含 base64 编码的文件片段。

```python
import bson

# BSON 头部：前 4 字节为小端文档大小
# 修复损坏的头部，设置正确大小
with open('data.bson', 'rb') as f:
    data = bytearray(f.read())

# 如果头部损坏（例如缺失前三字节），修复大小头
import struct
correct_size = len(data) + 3  # 补偿缺失字节
data = struct.pack('<I', correct_size)[1:] + data  # 补充缺失字节

# 解析 BSON 文档
docs = bson.decode_all(bytes(data))
for doc in docs:
    print(doc)

# 从 BSON 块重构文件（常见模式）：
# 每个文档包含：{index: N, data: "base64_chunk"}
import base64
chunks = sorted(docs, key=lambda d: d.get('index', d.get('i', 0)))
reconstructed = b''
for chunk in chunks:
    b64_data = chunk.get('data', chunk.get('d', ''))
    reconstructed += base64.b64decode(b64_data)

with open('reconstructed.png', 'wb') as f:
    f.write(reconstructed)
```

**关键洞察：** BSON 以 4 字节小端大小字段开头。若文件损坏，检查是否缺失或错误。使用 `bson.decode_all()`（pymongo 提供）解析，按索引排序块，拼接 base64 解码数据以重构嵌入文件。

---

## TrueCrypt / VeraCrypt 卷挂载（GreHack CTF 2016）

CTF 挑战中的加密卷可能使用 TrueCrypt 或 VeraCrypt。通过标志/品牌线索识别，然后用恢复的密钥文件或密码挂载。

```bash
# 识别 TrueCrypt 卷：
# - 无文件签名/魔数（设计如此）
# - 精确大小为 512 字节的倍数
# - 全文件高熵
# - 上下文线索：相关图片中有 TrueCrypt 标志

# 使用密码挂载：
truecrypt -t -p "password123" volume.tc /mnt/tc
veracrypt -t -p "password123" volume.tc /mnt/vc

# 使用密钥文件挂载（无密码）：
truecrypt -t -p "" -k keyfile.png volume.tc /mnt/tc
veracrypt -t -p "" -k keyfile.png volume.tc /mnt/vc

# 挂载隐藏卷（不同密码）：
truecrypt -t -p "hidden_password" volume.tc /mnt/tc

# CTF 中常见密钥文件位置：
# - 从其他挑战步骤提取的图片
# - Git 仓库中找到的 GPG 加密文件密钥
# - 嵌入其他取证工件的文件

# 如果 TrueCrypt 不可用（已停用）：
# 使用 VeraCrypt（向后兼容 TrueCrypt 卷）
# 对旧 TC 卷添加 --truecrypt 标志：
veracrypt -t --truecrypt -p "password" volume.tc /mnt/vc
```

**关键洞察：** TrueCrypt 卷无魔数或可识别头部，看起来像随机数据。通过上下文线索识别（相关图片含 TrueCrypt 标志，文件大小为 512 字节倍数，或挑战描述提及加密）。VeraCrypt 的 `--truecrypt` 标志支持旧版 TC 卷。

---
## Volatility mftparser 基于偏移的已删除文件恢复（BSides Delhi 2018）

**模式：** 标准的 `dumpfiles` 或 `filescan` + `dumpfiles --physaddr` 无法恢复已删除文件，因为其目录项已被标记为空闲。仍然保存文件 `$DATA` 属性的 MFT 记录会一直存在，直到该记录被重用。Volatility 2 的 `mftparser` 在给定通过 `filescan` 找到的 MFT 记录的精确 `--offset` 时，可以直接导出常驻的 `$DATA`。

```bash
# 1. 定位 MFT 记录偏移（Volatility 2 示例；Vol3 使用 windows.mftscan）
vol.py -f Challenge.raw --profile=Win7SP1x86 mftparser \
    | grep -A2 "target_filename"

# 2. 导出匹配的 MFT 条目的所有属性，包括 $DATA
vol.py -f Challenge.raw --profile=Win7SP1x86 mftparser \
    --offset=0x7ca3c00 --dump-dir=./out/

ls ./out/
# file.data.$DATA 包含恢复的内容
```

**关键洞察：** NTFS 通过翻转 MFT 记录头部的一个位（`0x16` 字节：`0x01 == 使用中`）来标记文件为“已删除”。在记录被重新分配之前，整个 `$DATA` 属性仍然完整，仅是延迟释放。对于常驻文件（小于约700字节，存储在 MFT 内联），使用 `mftparser --offset=<record>`；对于较大文件，使用 `dd`/`icat` 结合簇运行。放弃前务必在 `windows.mftscan` 输出中 grep 文件名：内存中常驻的 MFT 碎片在磁盘删除后仍可找到。

**参考：** BSides Delhi CTF 2018 — Never Too Late Mister，writeups 11963, 11970

---

## 通过 ASCII 艺术签名检测 Brotli Blob（ASIS Finals 2018）

**模式：** Binwalk 和 `file` 无法识别 Brotli 压缩数据，因为该格式没有固定的魔数。用 `brotli.decompress()` 解压候选 blob；Brotli 参考实现会嵌入自己的 ASCII 艺术 logo `Brrroootttllliii` 作为完整性校验输出。如果解压后的字节包含该字符串或其他 Brotli 特有的遥测字符串，则原始 blob 是 Brotli 压缩的。

```python
import brotli
try:
    out = brotli.decompress(blob)
    if b'rrrooottl' in out or b'Brotli' in out:
        print('Brotli-compressed')
except Exception: pass
```

**关键洞察：** 任何没有魔数字节的压缩器都可以通过试探性解压来识别。对于 Brotli、`zstd`、`snappy`、`lzma-alone`，依次尝试各库，直到某个成功且不抛异常。

**参考：** ASIS CTF Finals 2018 — Green Cabbage，writeup 12419

---

## corkami/pocs MD5 PDF 碰撞生成（35C3 2018）

**模式：** 挑战要求两个有效 PDF 具有相同 MD5 但内容不同。使用 corkami/pocs 的 `pdf.py` 结合 `enscript | ps2pdf` 生成带有碰撞友好填充的 PDF 头部，然后用 `fastcoll`（或用于 chosen-prefix 的 `hashclash`）驱动碰撞。之所以可行，是因为 PDF 格式允许 `%PDF` 尾部区域有垃圾数据，MD5 碰撞块可以覆盖该区域。

```bash
enscript -p out.ps content.txt
ps2pdf out.ps base.pdf
python pdf.py base.pdf target1.pdf target2.pdf
fastcoll -p base.pdf -o target1.pdf target2.pdf
md5sum target1.pdf target2.pdf    # 相同
```

**关键洞察：** PDF 碰撞是用合适工具链一条命令流水线完成的。更难的是 chosen-prefix MD5（不同可见内容），需要 `hashclash` 和 10-20 CPU 小时。查看 `pocs/collisions/` 目录，内含各种文件格式的预构建脚手架。

**参考：** 35C3 CTF 2018 — collider，writeup 12836

---

## 另见

- [disk-advanced.md](disk-advanced.md) - 高级磁盘和内存技术（已删除分区恢复、ZFS 取证、GPT GUID 编码、VMDK 稀疏解析、内存转储字符串雕刻、勒索软件密钥恢复、WordPerfect 宏 XOR、minidump ISO 9660 恢复、APFS 快照恢复、RAID 5 XOR 恢复、Kyoto Cabinet 哈希数据库取证）
- [disk-recovery.md](disk-recovery.md) - 磁盘恢复和提取模式（LUKS 主密钥恢复、伪随机数生成器时间戳种子暴力破解、VBA 宏二进制恢复、FemtoZip 解压、XFS 重建、tar 重复条目提取、嵌套套娃文件系统提取、通过空字节交错实现反雕刻）
