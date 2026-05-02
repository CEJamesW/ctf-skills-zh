# CTF Forensics - Windows

## 目录
- [Windows 事件日志 (.evtx)](#windows-event-logs-evtx)
- [注册表分析](#registry-analysis)
  - [OEMInformation 后门检测](#oeminformation-backdoor-detection)
- [SAM 数据库分析](#sam-database-analysis)
- [回收站取证](#recycle-bin-forensics)
- [浏览器历史](#browser-history)
- [Windows 远程遥测 (imprbeacons.dat)](#windows-telemetry-imprbeaconsdat)
- [Hosts 文件隐藏数据](#hosts-file-hidden-data)
- [联系人文件 (.contact)](#contact-files-contact)
- [WinZip AES 加密归档](#winzip-aes-encrypted-archives)
- [NTFS 备用数据流](#ntfs-alternate-data-streams)
- [NTFS MFT 分析](#ntfs-mft-analysis)
- [USN 日志 ($J) 分析](#usn-journal-j-analysis)
- [SAM 账户创建时间](#sam-account-creation-timing)
- [Impacket wmiexec.py 产物](#impacket-wmiexecpy-artifacts)
- [PowerShell 历史作为时间线](#powershell-history-as-timeline)
- [用户配置文件创建作为首次登录指示](#user-profile-creation-as-first-login-indicator)
- [RDP 会话事件 ID](#rdp-session-event-ids)
- [Windows Defender MPLog 分析](#windows-defender-mplog-analysis)
- [反取证检测清单](#anti-forensics-detection-checklist)
- [Windows 内存取证：certutil Base64 ZIP 恢复 (SEC-T CTF 2017)](#windows-memory-forensics-certutil-base64-zip-recovery-sec-t-ctf-2017)
- [NTFS EFSTMPWP 文件夹作为 cipher.exe 擦除痕迹 (Security Fest CTF 2018)](#ntfs-efstmpwp-folder-as-cipherexe-wipe-artifact-security-fest-ctf-2018)
- [Volatility clipboard 插件用于复制粘贴秘密恢复 (OtterCTF 2018)](#volatility-clipboard-plugin-for-copy-paste-secret-recovery-otterctf-2018)
- [Volatility 凭证恢复工具包 (OtterCTF 2018)](#volatility-credential-recovery-toolkit-otterctf-2018)

---

## Windows 事件日志 (.evtx)

**关键事件 ID：**

| 事件 ID | 描述 |
|----------|-------------|
| 1001 | Bugcheck/重启 |
| 41 | 非正常关机 |
| 4720 | 用户账户创建 |
| 4722 | 用户账户启用 |
| 4724 | 尝试重置密码 |
| 4726 | 用户账户删除 |
| 4738 | 用户账户更改 |
| 4781 | 账户名更改（重命名） |

**使用 python-evtx 解析：**
```python
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml_str = record.xml()
        root = ET.fromstring(xml_str)
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        event_id = root.find('.//ns:EventID', ns).text
        if event_id == '4720':
            data = {}
            for d in root.findall('.//ns:Data', ns):
                data[d.get('Name')] = d.text
            print(f"用户创建: {data.get('TargetUserName')}")
```

---

## 注册表分析

```bash
# RegRipper
rip.pl -r NTUSER.DAT -p all

# 关键注册表蜂巢
NTUSER.DAT   # 用户设置
SAM          # 用户账户
SYSTEM       # 系统配置
SOFTWARE     # 已安装软件
```

### OEMInformation 后门检测

**位置：** `SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation`

```python
from Registry import Registry

reg = Registry.Registry("SOFTWARE")
key = reg.open("Microsoft\\Windows\\CurrentVersion\\OEMInformation")
for val in key.values():
    print(f"{val.name()}: {val.value()}")
```

**恶意软件指示：** 修改的 `SupportURL` 指向 C2。

---

## SAM 数据库分析

**所需文件：**
- `Windows/System32/config/SAM` - 密码哈希
- `Windows/System32/config/SYSTEM` - 启动密钥

**使用 impacket 提取哈希：**
```python
from impacket.examples.secretsdump import LocalOperations, SAMHashes

localOps = LocalOperations('SYSTEM')
bootKey = localOps.getBootKey()
sam = SAMHashes('SAM', bootKey)
sam.dump()  # username:RID:LM:NTLM:::
```

**验证/破解 NTLM：**
```python
from Crypto.Hash import MD4

def ntlm_hash(password):
    h = MD4.new()
    h.update(password.encode('utf-16-le'))
    return h.hexdigest()

# 使用 hashcat 破解
# hashcat -m 1000 hashes.txt wordlist.txt
```

**常见 RID：**
- 500 = Administrator
- 501 = Guest
- 1000+ = 用户账户

---
## Recycle Bin Forensics

**位置：** `$Recycle.Bin\<SID>\`

**文件结构：**
- `$R<random>.<ext>` - 实际删除的内容
- `$I<random>.<ext>` - 元数据（原始路径，时间戳）

**解析 $I 元数据：**
```python
# strings 显示原始路径
# C.:.\.U.s.e.r.s.\.U.s.e.r.4.\.D.o.c.u.m.e.n.t.s.\.file.docx
```

**十六进制编码的 flag 片段：**
```bash
cat '$R_InternSecret.txt'
# 输出: 4B4354467B72656330...
echo "4B4354467B72656330..." | xxd -r -p
```

---

## Browser History

**Edge/Chrome (SQLite)：**
```python
import sqlite3

history = "Users/<user>/AppData/Local/Microsoft/Edge/User Data/Default/History"
conn = sqlite3.connect(history)
cur = conn.cursor()
cur.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC")
for url, title in cur.fetchall():
    print(f"{title}: {url}")
```

---

## Windows Telemetry (imprbeacons.dat)

**位置：** `Users/<user>/AppData/Local/Packages/Microsoft.Windows.ContentDeliveryManager_*/LocalState/`

```bash
strings imprbeacons.dat | tr '&' '\n' | grep -E "CIP|geo_|COUNTRY"
```

**关键字段：** `CIP`（客户端 IP）、`geo_lat/long`、`COUNTRY`、`SMBIOSDM`

---

## Hosts File Hidden Data

**位置：** `Windows/System32/drivers/etc/hosts`

攻击者通过过多的空白字符隐藏数据：
```bash
# 检测隐藏内容
xxd hosts | tail -20
```

---

## Contact Files (.contact)

**位置：** `Users/<user>/Contacts/*.contact`

**Notes 中的隐藏数据：**
```xml
<c:Notes>h1dden_c0ntr4ct5</c:Notes>
```

---

## WinZip AES Encrypted Archives

```bash
# 提取哈希
zip2john encrypted.zip > zip_hash.txt

# 使用 hashcat 破解（模式 13600）
hashcat -m 13600 zip_hash.txt wordlist.txt

# 混合模式：单词 + 4 位数字
hashcat -m 13600 zip_hash.txt wordlist.txt -a 6 '?d?d?d?d'
```

---

## NTFS Alternate Data Streams

**模式说明：** NTFS 支持每个文件多个数据流。默认数据流存储正常文件内容，额外的命名数据流（Alternate Data Streams / ADS）可以隐蔽地隐藏任意数据。`dir`、资源管理器和大多数工具只显示默认数据流。

**检测和枚举：**

```bash
# 在挂载的 NTFS 卷上（Linux）：
getfattr -R -n ntfs.streams.list /mnt/ntfs/     # 列出所有文件的所有数据流

# 使用 Sleuth Kit 处理原始 NTFS 镜像（法证最佳）：
fls -r ntfs_image.dd                              # 递归列出文件
fls -r ntfs_image.dd | grep -i ":"                # ADS 条目包含 ":"
# 输出示例：r/r 66-128-4: Documents/credentials.txt:hidden_flag.jpg

# 通过 inode 提取 ADS — 先查找 inode：
istat ntfs_image.dd 66                            # 显示 inode 66 的所有属性
# 查找带名称的 $DATA 属性（例如 $DATA "hidden_flag.jpg"）

icat ntfs_image.dd 66-128-4 > hidden_flag.jpg    # 通过完整地址提取 ADS

# 使用 ntfsstreams（ntfs-3g 的一部分）：
ntfs_streams_list /dev/sda1
```

**Windows（实时分析）：**

```powershell
# 列出文件的 ADS
Get-Item -Path C:\file.txt -Stream *

# 读取 ADS 内容
Get-Content -Path C:\file.txt -Stream hidden_data

# dir /r 显示 ADS（Windows Vista 及以上）
dir /r C:\Users\suspect\Documents\

# 常见 ADS 名称检查：
# Zone.Identifier — 标记从互联网下载的文件
# （包含 ZoneId、ReferrerUrl、HostUrl）
Get-Content -Path C:\file.exe -Stream Zone.Identifier
```

**从原始 NTFS 镜像用 Python 提取：**

```python
# 使用 pytsk3（Sleuth Kit 的 Python 绑定）
import pytsk3

img = pytsk3.Img_Info("ntfs_image.dd")
fs = pytsk3.FS_Info(img)

# 遍历所有文件并检查 ADS
for entry in fs.open_dir("/"):
    for attr in entry:
        if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA:
            name = attr.info.name or "(default)"
            if name != "(default)":
                print(f"发现 ADS: {entry.info.name.name}/{name} "
                      f"(大小: {attr.info.size})")
                # 读取 ADS 内容
                data = entry.read_random(0, attr.info.size, attr.info.type, attr.info.id)
```

**关键洞察：** ADS 对 `dir`（无 `/r` 参数）、资源管理器和大多数只检查默认数据流的法证工具是不可见的。Sleuth Kit 的 `fls` 使用冒号标记（`inode-type-id`）是枚举和提取镜像中 ADS 最可靠的方法。恶意软件利用 ADS 隐藏 payload，CTF 挑战用它们隐藏 flag。`Zone.Identifier` 流是最常见的 ADS——浏览器和邮件客户端自动添加到下载文件中。

**识别时机：** 挑战提供 NTFS 镜像，提及“隐藏数据”、“明处隐藏”或“alternate streams”。凭证文件或看似简单的文档可能附带 ADS。任何 NTFS 法证挑战都应运行 `fls -r image.dd | grep ":"`。

**参考：** Google CTF 2019 “Home Computer”，TCP1P CTF 2023 “hide and split”，De1CTF 2019 “DeeplnReal”

---
## NTFS MFT 分析

**位置：** `C:\$MFT`（主文件表）

**关键技术：**
- 文件名以 UTF-16LE 格式存储在 MFT 中
- 每个文件有两组时间戳：`$STANDARD_INFORMATION`（用户可修改）和 `$FILE_NAME`（系统控制）
- 时间戳篡改检测：比较 SI 和 FN 时间戳；如果 SI 日期远早于 FN 日期，则文件被时间戳篡改

```python
# 在 MFT 中搜索文件名（二进制文件，使用 strings）
# ASCII:
# strings $MFT | grep -i "suspicious"
# UTF-16LE:
# strings -el $MFT | grep -i "suspicious"

# MFT 记录结构（每条 1024 字节，从偏移 0 开始）：
# - 偏移 0x00: "FILE" 签名
# - 属性 0x30 ($FILE_NAME)：包含 FN 时间戳（可靠）
# - 属性 0x10 ($STANDARD_INFORMATION)：包含 SI 时间戳（可修改）
```

---

## USN 日志 ($J) 分析

**位置：** `C:\$Extend\$J`（更新序列号日志）

跟踪所有文件系统更改。事件日志被清除时尤为关键。

```python
import struct, datetime

def parse_usn_record(data, offset):
    """解析给定偏移处的 USN_RECORD_V2"""
    rec_len = struct.unpack_from('<I', data, offset)[0]
    major = struct.unpack_from('<H', data, offset + 4)[0]  # 必须是 2
    file_ref = struct.unpack_from('<Q', data, offset + 8)[0] & 0xFFFFFFFFFFFF
    parent_ref = struct.unpack_from('<Q', data, offset + 16)[0] & 0xFFFFFFFFFFFF
    timestamp = struct.unpack_from('<Q', data, offset + 32)[0]
    reason = struct.unpack_from('<I', data, offset + 40)[0]
    file_attr = struct.unpack_from('<I', data, offset + 52)[0]
    fn_len = struct.unpack_from('<H', data, offset + 56)[0]
    fn_off = struct.unpack_from('<H', data, offset + 58)[0]  # 通常为 60
    filename = data[offset + fn_off:offset + fn_off + fn_len].decode('utf-16-le')
    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp // 10)
    return dt, filename, reason, file_attr, parent_ref

# USN Reason 标志：
# 0x1=数据覆盖, 0x2=数据扩展, 0x4=数据截断
# 0x100=文件创建, 0x200=文件删除, 0x1000=命名数据覆盖
# 0x80000000=关闭
```

**关键取证用途：**
- 即使日志被清除，也能找到文件创建/删除时间
- 跟踪 wmiexec.py 输出文件（`__<timestamp>.<random>`）
- 确定 PowerShell 历史写入时间（命令时间线）
- 检测用户配置文件创建（首次交互登录时间）

---

## SAM 账户创建时间

当安全事件日志（EventID 4720）被清除时，可从 SAM 注册表确定账户创建时间：

```python
from regipy.registry import RegistryHive

sam = RegistryHive('SAM')
# 跳转到：SAM\Domains\Account\Users\Names\<username>
# 该键的 last_modified 时间戳 = 账户创建时间
names_key = sam.get_key('SAM\\Domains\\Account\\Users\\Names')
for subkey in names_key.iter_subkeys():
    print(f"{subkey.name}: created {subkey.header.last_modified}")
```

---

## Impacket wmiexec.py 产物

**wmiexec.py** 是一个流行的远程命令执行工具，基于 WMI。关键产物：

1. **输出文件：** 在 `C:\Windows\`（ADMIN$ 共享）创建 `__<unix_timestamp>.<random>` 文件
   - 文件被创建，写入命令输出，读取后删除
   - 每次命令执行都会创建一个新周期
   - USN 日志保留创建/删除时间戳，即使文件已删除

2. **WMI 提供程序主机：** `WMIPRVSE.EXE` 预取文件确认 WMI 使用

3. **时间线重建：** 统计输出文件的 USN 创建-删除周期，确定执行命令次数

```python
# 在 MFT 中搜索 wmiexec 输出文件
# strings -el $MFT | grep -E '^__[0-9]{10}'
# 文件名中的 unix 时间戳 = 近似执行开始时间
```

---
## PowerShell 历史作为时间线

**位置：** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

PSReadLine 以增量方式写入命令。**该文件上的 USN 日志 DATA_EXTEND 事件对应单个命令的执行：**

```text
08:05:19 - FILE_CREATE + DATA_EXTEND → 输入的第一个命令
08:05:50 - DATA_EXTEND → 输入的第二个命令
08:09:57 - DATA_EXTEND → 输入的第三个命令
```

这为每条命令提供了精确的执行时间戳，即使 PowerShell 日志被清除。

---

## 用户配置文件创建作为首次登录指示器

当事件日志被清除时，USN 日志中用户配置文件目录的创建揭示了首次交互式登录：

```python
# 在 USN 日志中搜索用户名目录创建
# 原因标志 0x100 (FILE_CREATE)，父引用匹配 C:\Users (MFT 引用 512)
# 示例：ithelper 目录 FILE_CREATE 父=512 时间 08:03:51
# → 首次登录（RDP/控制台）大约在 08:03
```

**关键洞察：** 用户配置文件仅在首次交互式登录（RDP 或控制台）时创建，不通过 WMI/wmiexec 远程执行。

---

## RDP 会话事件 ID

**TerminalServices-LocalSessionManager\Operational：**

| 事件 ID | 描述 |
|----------|-------------|
| 21 | 会话登录成功 |
| 22 | 收到 Shell 启动通知 |
| 23 | 会话注销成功 |
| 24 | 会话断开连接 |
| 25 | 会话重新连接成功 |
| 40 | 会话创建 |
| 41 | 会话开始（用户通知） |
| 42 | Shell 启动（用户通知） |

**TerminalServices-RemoteConnectionManager\Operational：**

| 事件 ID | 描述 |
|----------|-------------|
| 261 | 监听器接收连接 |
| 1149 | RDP 用户认证成功（包含源 IP） |

**RemoteDesktopServices-RdpCoreTS\Operational：**

| 事件 ID | 描述 |
|----------|-------------|
| 131 | 连接接受（TCP，包含 ClientIP:端口） |
| 102 | 来自客户端的连接 |
| 103 | 断开连接（检查 ReasonCode） |

---

## Windows Defender MPLog 分析

**位置：** `C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log`

丰富的威胁检测时间线来源，即使其他日志被清除：

```bash
# 查找威胁检测
grep -i "DETECTION\|THREAT\|QUARANTINE" MPLog*.log

# 查找 ASR（攻击面减少）规则活动
grep -i "ASR\|Process.*Block" MPLog*.log

# 关键 ASR 规则（攻击尝试指示器）：
# - “阻止来自 PSExec 和 WMI 命令的进程创建”
# - “阻止从 lsass.exe 窃取凭据”
```

**检测历史文件：** `C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\`
- 包含 SHA256、文件路径和检测名称的二进制文件
- 使用 `strings` 解析以提取 IOC

---

## 反取证检测清单

当事件日志被清除（攻击者使用 `wevtutil cl` 或 `Clear-EventLog`）时：

1. **USN 日志** - 日志清除后仍存活；显示文件操作时间线
2. **SAM 注册表** - 保留账户创建时间戳
3. **PowerShell 历史** - ConsoleHost_history.txt 通常未被清除
4. **预取文件** - 显示执行的程序（C:\Windows\Prefetch\）
5. **MFT** - 即使文件被删除，文件元数据仍被保留
6. **Defender MPLog** - 独立于 Windows 事件日志，通常未被清除
7. **RDP 事件日志** - TerminalServices 日志独立于 Security.evtx
8. **WMI 存储库** - C:\Windows\System32\wbem\Repository\OBJECTS.DATA
9. **浏览器历史** - 用户 AppData 中的 SQLite 数据库
10. **注册表时间戳** - 键的最后修改时间揭示活动

**Security.evtx 事件 ID 1102** = “审核日志已被清除”（具有讽刺意味的是，即使在清除时也会记录）

---
## Windows Memory Forensics: certutil Base64 ZIP Recovery (SEC-T CTF 2017)

使用 Volatility 对内存转储进行分析，其中 `psxview` 可揭示隐藏的 cmd/powershell 进程。恶意批处理脚本使用 `bitsadmin` 下载并用 `certutil -decode` 对 payload 进行 base64 解码。搜索内存中的 `UEsD`（ZIP 魔数 `PK\x03` 的 base64 编码）以找到传输中的 base64 归档文件，然后解码以恢复包括注册表项在内的 ZIP 内容。

```bash
# 第1步：查找隐藏进程（psxview 比较多个进程列表）
vol.py -f dump.raw --profile=Win7SP1x64 psxview

# 第2步：导出可疑进程内存
vol.py -f dump.raw --profile=Win7SP1x64 procdump -p <PID> -D ./dumps/

# 第3步：扫描原始内存中的 base64 编码 ZIP 归档
# UEsD = base64("PK\x03") — ZIP 魔数字节的 base64 编码
strings dump.raw | grep -o 'UEsD[A-Za-z0-9+/=]*' > candidates.txt

# 第4步：解码每个候选项
python3 -c "
import base64, sys
with open('candidates.txt') as f:
    for line in f:
        line = line.strip()
        # 补齐为有效的 base64 长度
        padded = line + '=' * (-len(line) % 4)
        try:
            data = base64.b64decode(padded)
            if data[:4] == b'PK\x03\x04':
                with open('recovered.zip', 'wb') as out:
                    out.write(data)
                print('ZIP recovered')
                break
        except Exception:
            pass
"

# 第5步：解压 ZIP 内容
unzip recovered.zip
```

**恶意软件指示器：**
- `bitsadmin /transfer` — 无需浏览器的后台下载
- `certutil -decode input.b64 output.exe` — base64 解码滥用
- 异常位置的批处理文件（`.bat`、`.cmd`）（如 `%TEMP%`、`%APPDATA%`）
- ZIP payload 中的注册表导出文件（`.reg`）

**关键洞察：** `certutil` 常被恶意软件滥用作为 living-off-the-land 技术进行 base64 解码。`UEsD` 是 ZIP 魔数字节 `PK\x03` 的 base64 编码——将其用作内存扫描签名，以在 ZIP 归档写入磁盘之前或删除之后找到传输中的 ZIP 文件。

---

## NTFS EFSTMPWP 文件夹作为 cipher.exe 擦除痕迹 (Security Fest CTF 2018)

**模式（Mr.reagan）：** 一个 NTFS 镜像包含 `$RECYCLE.BIN`，同时还有一个稀疏使用的隐藏目录 `EFSTMPWP`。该目录由 `cipher.exe /w` 创建——Windows 内置的多遍覆盖卷空闲空间的工具——用于存放多遍擦除时的临时文件。该目录的存在意味着嫌疑人执行了安全擦除命令，因此恢复已删除数据的可能性很小。

**检测方法：**
```bash
# 以只读方式挂载 NTFS 镜像
sudo mount -o ro,loop,show_sys_files image.dd /mnt/ntfs

# 查找擦除痕迹
find /mnt/ntfs -maxdepth 2 -iname 'EFSTMPWP' -o -iname '$Recycle.Bin'

# MFT 条目也记录了该目录，创建进程为 cipher.exe
mft_parser -i image.dd -o mft.csv
grep -i 'EFSTMPWP' mft.csv
```

**影响：**
- 不要浪费时间在空闲空间中雕刻已删除的用户数据；它已被覆盖。
- 将重点转向其他持久化路径：`$Recycle.Bin` 内容、NTFS 日志（$LogFile / $UsnJrnl）、卷影副本和 MFT 常驻数据。
- 检查事件日志（`Security.evtx`、`Microsoft-Windows-Application-Experience%4Program-Inventory.evtx`）中的 `cipher.exe` 执行时间戳——它们是反取证时间线的锚点。

**关键洞察：** 安全擦除工具会留下自己的文件系统指纹。`cipher.exe /w` 创建 `EFSTMPWP`；`sdelete` 创建以被擦除目标命名并带有 `.ZZZ` 风格扩展名的文件；BleachBit 留下 `~BleachBit*.tmp`。在启动任何恢复工作前，先 grep 这些痕迹文件名——它们告诉你恢复是否值得尝试。

**参考资料：** Security Fest CTF 2018 — writeup 10206

---
## Volatility clipboard 插件用于复制粘贴秘密恢复（OtterCTF 2018）

**模式：** 用户将密码 / 密钥 / flag 复制到剪贴板。Windows 即使在源应用关闭后，也会在内存中保持剪贴板数据的活跃状态。Volatility 的 `clipboard` 插件枚举 `CF_UNICODETEXT` / `CF_TEXT` 缓冲区，并逐字打印最近的复制粘贴内容。

```bash
vol.py -f memory.vmem --profile=Win7SP1x64 clipboard
# Volatility 3:
vol -f memory.vmem windows.clipboard
```

**关键洞察：** 在花费数小时对 LSASS 进行雕刻或遍历进程堆之前，先运行 `clipboard` —— 关于“傻 Rick 复制了他的密码”的 CTF 挑战总是在这里出现。结合 `cmdline`、`consoles` 和 `filescan` 可实现完整的用户活动重建。

**参考资料：** OtterCTF 2018 — Silly Rick，writeup 12596

---

## Volatility 凭证恢复工具包（OtterCTF 2018）

**模式：** 一份内存转储，按顺序尝试以下 Volatility 插件清单：

```bash
# 1. 最近复制粘贴的密码
vol.py -f dump.vmem --profile=Win7SP1x64 clipboard

# 2. 加载插件：mimikatz（第三方）——明文 wdigest 凭证
vol.py --plugins=./plugin/ -f dump.vmem --profile=Win7SP1x64 mimikatz

# 3. 来自 SAM 配置单元的 NTLM / LM 哈希
vol.py -f dump.vmem --profile=Win7SP1x64 hivelist          # 查找 SAM 偏移
vol.py -f dump.vmem --profile=Win7SP1x64 hashdump -y SYSTEM_off -s SAM_off

# 4. 注册表值（计算机名、策略）
vol.py -f dump.vmem --profile=Win7SP1x64 printkey \
    -K 'ControlSet001\Control\ComputerName\ComputerName'

# 5. 进程内存雕刻：转储并 grep 查找模式
vol.py -f dump.vmem --profile=Win7SP1x64 memdump -p 3720 -D out/
strings out/3720.dmp | grep -iE 'pass|flag'

# 6. 网络连接痕迹
vol.py -f dump.vmem --profile=Win7SP1x64 netscan

# 7. 进程树和加载的 DLL 用于恶意软件分类
vol.py -f dump.vmem --profile=Win7SP1x64 pstree
vol.py -f dump.vmem --profile=Win7SP1x64 dlllist -p PID
```

**关键洞察：** 不要只用 `strings` 狩猎。Volatility 插件套件针对每种痕迹都有插件：clipboard、mimikatz（明文）、hashdump（哈希）、printkey（注册表）、memdump（每进程内存）、netscan（套接字）、pstree（进程层级）、dlllist（加载模块）。按从最便宜到最昂贵的顺序运行它们。

**参考资料：** OtterCTF 2018 — 多个挑战，writeups 12569–12572, 12596
