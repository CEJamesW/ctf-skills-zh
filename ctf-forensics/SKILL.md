---
name: ctf-forensics
description: 提供用于CTF挑战的数字取证和信号分析技术。适用于分析磁盘镜像、内存转储、事件日志、网络抓包、加密货币交易、隐写术、PDF分析、Windows注册表、Volatility、PCAP、Docker镜像、coredump、侧信道功率轨迹、DTMF音频频谱图、数据包时序分析、CD音频光盘镜像，或恢复已删除文件和凭据。
license: MIT
compatibility: 需要基于文件系统的代理（Claude Code或类似工具），支持bash、Python 3，并具备工具安装的网络访问权限。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Forensics & Blockchain

CTF取证挑战快速参考。每种技术这里都有一行命令；完整细节请参见支持文件。

## 先决条件

**Python包（所有平台）：**
```bash
pip install volatility3 Pillow numpy matplotlib
```

**Linux（apt）：**
```bash
apt install binwalk foremost libimage-exiftool-perl tshark sleuthkit \
  ffmpeg steghide testdisk john pcapfix
```

**macOS（Homebrew）：**
```bash
brew install binwalk exiftool wireshark sleuthkit ffmpeg \
  testdisk john-jumbo
```

**Ruby gems（所有平台）：**
```bash
gem install zsteg
```

## 额外资源

- [3d-printing.md](3d-printing.md) - 3D打印取证（PrusaSlicer二进制G-code，QOIF，热缩管）
- [windows.md](windows.md) - Windows取证（注册表、SAM、事件日志、回收站、NTFS备用数据流、USN日志、PowerShell历史、Defender MPLog、WMI持久化、Amcache）
- [network.md](network.md) - 网络取证基础（tcpdump，TLS/SSL密钥日志解密，coredump中TLS主密钥提取，Wireshark，PCAP，端口扫描，SMB3解密，5G/NR协议，WordPress侦察，凭据，USB HID速记，BCD编码，HTTP文件上传外泄，基于时间戳排序的分卷归档重组）
- [network-advanced.md](network-advanced.md) - 高级网络取证（数据包间隔时序编码，NTLMv2哈希破解，TCP标志隐蔽信道，DNS末字节隐写，DNS尾字节二进制编码，多层PCAP与XOR+ZIP及mDNS密钥，Brotli解压炸弹缝隙分析，SMB RID回收通过LSARPC，Timeroasting MS-SNTP哈希提取，dnscat2重组，RADIUS共享密钥破解，RC4流识别，ICMP负载字节旋转，ICMP ping时延隐蔽信道）
- [peripheral-capture.md](peripheral-capture.md) - USB/HID/蓝牙外设流量重构（USB HID鼠标/笔绘图恢复，USB HID键盘捕获解码，USB键盘LED摩尔斯码外泄，USB HID键盘箭头键导航追踪，蓝牙RFCOMM数据包重组）
- [disk-and-memory.md](disk-and-memory.md) - 核心磁盘/内存取证（Volatility，磁盘挂载/雕刻，VM/OVA/VMDK，VMware快照，GIMP原始内存转储可视化检查，coredump，Windows KAPE分诊，PowerShell勒索软件，Android取证，Docker容器取证，云存储取证，BSON重构，TrueCrypt/VeraCrypt挂载）
- [disk-advanced.md](disk-advanced.md) - 高级磁盘和内存技术（已删除分区，ZFS取证，GPT GUID编码，VMDK稀疏解析，内存转储字符串雕刻，勒索软件密钥恢复，WordPerfect宏XOR，minidump ISO 9660恢复，APFS快照恢复，RAID 5 XOR恢复，HFS+资源分支恢复，Kyoto Cabinet哈希数据库取证，SQLite编辑历史重构）
- [disk-recovery.md](disk-recovery.md) - 磁盘恢复和提取模式（LUKS主密钥恢复，伪随机数生成器时间戳种子暴力破解，VBA宏二进制恢复，FemtoZip解压，XFS文件系统重构，tar重复条目提取，嵌套套娃文件系统提取，反雕刻通过空字节交错，BTRFS子卷/快照恢复，FAT16空闲空间数据恢复，FAT16已删除文件通过Sleuth Kit fls/icat恢复，ext2孤立inode通过fsck恢复，损坏ZIP头修复）
- [steganography.md](steganography.md) - 通用隐写术（二进制边界隐写，PDF多层隐写，SVG关键帧，PNG重排，文件叠加，GIF帧差摩尔斯码，GZSteg + spammimic，电子表格频率恢复，Kitty终端图形协议解码，ANSI转义序列隐写，自立体图解法，双层字节+行交错，多流视频容器隐写，渐进式PNG分层XOR解密，曲面反射QR码重构）
- [stego-image.md](stego-image.md) - 图像专用隐写术（JPEG未用DQT表LSB，BMP位平面QR提取，图像拼图重组，F5 JPEG DCT比率检测，PNG未用调色板条目隐写，QR码瓦片重构，基于种子的像素置换+多位平面QR，JPEG缩略图像素到文本映射，条件LSB与像素过滤，JPEG空闲空间，最近邻插值隐写，RGB奇偶校验隐写）
- [stego-advanced.md](stego-advanced.md) - 高级隐写术第1部分：音频和信号技术（FFT频域，DTMF音频，SSTV+LSB，DotCode条码，自定义频率双音键盘，多轨音频差分减法，跨通道多位LSB，音频FFT音乐音符，音频元数据八进制编码，嵌套tar空白符编码，DeepSound音频隐写及密码破解，音频波形二进制编码，音频频谱隐藏QR）
- [stego-advanced-2.md](stego-advanced-2.md) - 高级隐写术第2部分：视频、图像变换及格式专用技术（视频帧累积，反向音频，视频帧平均，JPEG XL TOC置换隐写，Arnold猫映射解扰，高分辨率SSTV自定义FM解调，MJPEG FFD9尾字节隐写，EXIF zlib + Stegano像素模式，PDF xref隐蔽信道，ANSI转义码隐写，像素级ECB去重）
- [linux-forensics.md](linux-forensics.md) - Linux/应用取证（日志分析，Docker镜像取证，攻击链，浏览器凭据，Firefox历史，TFTP，TLS弱RSA，USB音频，Git目录恢复，KeePass v4破解，Git reflog/fsck合并恢复，浏览器痕迹分析（Chrome/Chromium/Firefox历史、Cookies、下载、本地存储、会话恢复），损坏git blob字节暴力修复，VBA宏Excel单元格数据到ELF二进制提取，Python内存中源代码恢复通过pyrasite）
- [signals-and-hardware.md](signals-and-hardware.md) - 硬件信号解码与解码代码（VGA帧解析，HDMI TMDS符号解码，DisplayPort 8b/10b + LFSR解扰器），Voyager金唱片音频，Saleae Logic 2 UART解码，Flipper Zero .sub文件，侧信道功率分析（DPA），键盘声学侧信道，CD音频光盘隐写（CIRC去交错+螺旋渲染），大写锁定LED摩尔斯码视频提取，Linux input_event键盘记录转储解析，WAV音频串口UART，USB MIDI Launchpad网格重构

---
## 何时切换方向

- 如果你恢复了一个加密数据块，而难点变成了 RSA、AES 或格密码学，切换到 `/ctf-crypto`。
- 如果证据确实指向恶意软件的预备阶段、信标配置提取或打包样本，切换到 `/ctf-malware`。
- 如果工件是一个 Web 应用备份或 API 转储，剩下的问题是应用逻辑，切换到 `/ctf-web`。
- 如果取证证据实际上是编码谜题、隐写术技巧或晦涩格式，而非真正的取证，切换到 `/ctf-misc`。
- 如果你需要追踪基础设施、归因攻击者或从取证发现中调查公共记录，切换到 `/ctf-osint`。
- 如果恢复的工件是需要反汇编和分析的编译二进制文件或固件，切换到 `/ctf-reverse`。

## 快速启动命令

```bash
# 文件分析
file suspicious_file
exiftool suspicious_file     # 元数据
binwalk suspicious_file      # 嵌入文件
strings -n 8 suspicious_file
hexdump -C suspicious_file | head  # 检查魔数

# 磁盘取证
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd              # 列出文件
photorec image.dd            # 恢复已删除文件

# 内存取证（Volatility 3）
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.filescan
```

完整的 Volatility 插件参考、虚拟机取证和核心转储分析见 [disk-and-memory.md](disk-and-memory.md)。

## 日志分析

```bash
grep -iE "(flag|part|piece|fragment)" server.log     # Flag 片段
grep "FLAGPART" server.log | sed 's/.*FLAGPART: //' | uniq | tr -d '\n'  # 重组
sort logfile.log | uniq -c | sort -rn | head         # 查找异常
```

Linux 攻击链分析和 Docker 镜像取证见 [linux-forensics.md](linux-forensics.md)。

## Windows 事件日志 (.evtx)

**关键事件 ID：**
- 1001 - Bugcheck/重启
- 1102 - 审计日志被清除
- 4720 - 用户账户创建
- 4781 - 账户重命名

**RDP 会话 ID（TerminalServices-LocalSessionManager）：**
- 21 - 会话登录成功
- 24 - 会话断开
- 1149 - RDP 认证成功（RemoteConnectionManager，含源 IP）

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        print(record.xml())
```

完整事件 ID 表、注册表分析、SAM 解析、USN 日志和反取证检测见 [windows.md](windows.md)。

- **NTFS 备用数据流 (ADS)：** 通过命名的 NTFS 流附加到文件的隐藏数据。`dir`/资源管理器不可见。用 `fls -r image.dd | grep ":"` 检测，用 `icat` 提取。详见 [windows.md](windows.md#ntfs-alternate-data-streams)。

## 日志被清除时

如果攻击者清除了事件日志，使用以下替代来源：
1. **USN 日志 ($J)** - 文件操作时间线（MFT 引用、时间戳、原因）
2. **SAM 注册表** - 通过关键的 last_modified 时间戳推断账户创建
3. **PowerShell 历史** - ConsoleHost_history.txt（USN DATA_EXTEND = 命令时间）
4. **Defender MPLog** - 独立日志，含威胁检测和 ASR 事件
5. **Prefetch** - 程序执行证据
6. **用户配置文件创建** - 首次登录时间（USN 日志中的配置文件目录）

详细解析代码和反取证检测清单见 [windows.md](windows.md)。

## 隐写术

```bash
steghide extract -sf image.jpg
zsteg image.png              # PNG/BMP 分析
stegsolve                    # 可视化分析
```

- **二值边界隐写：** 1 像素边框的黑白像素顺时针编码比特
- **FFT 频域隐写：** 图像数据隐藏在二维 FFT 幅度谱中；尝试 `np.fft.fft2` 可视化
- **DTMF 音频：** 电话音调编码数据；用 `multimon-ng -a DTMF` 解码
- **多层 PDF：** 检查隐藏注释、EOF 后数据、与关键词异或、ROT18 最终层
- **SSTV + LSB：** SSTV 信号可能是干扰；用 `stegolsb` 检查音频样本的 2 位 LSB
- **SVG 关键帧：** 动画的 `keyTimes`/`values` 属性通过填充色交替编码二进制/摩斯码
- **PNG 块重排：** 修正块顺序：IHDR → 辅助块 → IDAT（顺序）→ IEND
- **文件覆盖：** 检查 IEND 后是否有附加的归档文件，可能覆盖魔数
- **APNG 帧提取：** 动画 PNG 有多帧；用 `apngdis` 提取或解析 `fdAT`/`fcTL` 块。详见 [steganography.md](steganography.md#apng动画-png帧提取-icectf-2016)。
- **PNG 高度/CRC 操作：** 修改 IHDR 高度字段，暴力破解直到 CRC 匹配以揭示隐藏行。详见 [steganography.md](steganography.md#png-高度crc-操作隐藏内容-h4ckit-ctf-2016)。
- **像素坐标链隐写：** 链表遍历，R=数据字节，G/B=下一个像素坐标。详见 [stego-image.md](stego-image.md#pixel-coordinate-chain-steganography-h4ckit-ctf-2016)。
- **AVI 帧差分：** 异或连续视频帧，揭示像素差异中的隐藏数据。详见 [stego-image.md](stego-image.md#avi-帧差分像素隐写术-h4ckit-ctf-2016)。

- **自定义频率 DTMF：** 非标准双音频率；先生成频谱图（`ffmpeg -i audio -lavfi showspectrumpic`），映射自定义网格到键盘数字，解码可变长度 ASCII
- **JPEG DQT LSB：** 未使用的量化表（ID 2、3）携带 LSB 编码数据；通过 `Image.open().quantization` 访问并提取每个 64 值的第 0 位
- **多轨音频相减：** MKV/视频中两条几乎相同的音轨；`sox -m a0.wav "|sox a1.wav -p vol -1" diff.wav` 抵消共享内容，差分信号频谱图（5-12 kHz）出现 flag
- **包间隔定时：** 相同包有两种不同间隔（如 10ms/100ms）编码二进制；按接口过滤，计算包间差，阈值转比特

完整代码示例和解码流程见 [steganography.md](steganography.md)、[stego-advanced.md](stego-advanced.md) 和 [stego-advanced-2.md](stego-advanced-2.md)。

## PDF 分析

```bash
exiftool document.pdf        # 元数据（常藏 flag！）
pdftotext document.pdf -     # 提取文本
strings document.pdf | grep -i flag
binwalk document.pdf         # 嵌入文件
```

**高级 PDF 隐写（Nullcon 2026 rdctd）：** 六种技术——不可见文本分隔符、带转义大括号的 URI 注释、模糊图像的 Wiener 反卷积、矢量矩形二维码、压缩对象流（`mutool clean -d`）、文档元数据字段。

完整 PDF 隐写技术和代码见 [steganography.md](steganography.md)。
## 磁盘 / 虚拟机 / 内存取证

```bash
# 磁盘镜像
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd && photorec image.dd

# 虚拟机镜像 (OVA/VMDK)
tar -xvf machine.ova
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r

# 内存 (Volatility 3)
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.netscan
vol3 -f memory.dmp windows.dumpfiles --physaddr <addr>

# 字符串提取
strings -a -n 6 memdump.bin | grep -E "FLAG|SSH_CLIENT|SESSION_KEY"

# Core dump
gdb -c core.dump  # info registers, x/100x $rsp, find "flag"
```

完整的 Volatility 插件参考、虚拟机取证和 VMware 快照请参见 [disk-and-memory.md](disk-and-memory.md)。删除分区恢复、ZFS 取证和勒索软件分析请参见 [disk-advanced.md](disk-advanced.md)。

## Windows 密码哈希

```bash
# 使用 impacket 提取，使用 hashcat -m 1000 破解
python -c "from impacket.examples.secretsdump import *; SAMHashes('SAM', LocalOperations('SYSTEM').getBootKey()).dump()"
```

有关 SAM 详细信息请参见 [windows.md](windows.md)，有关从 PCAP 破解 NTLMv2 请参见 [network-advanced.md](network-advanced.md)。

## 比特币追踪

- 使用 mempool.space API：`https://mempool.space/api/tx/<TXID>`
- **剥离链（Peel chain）：** 始终跟踪较大输出；整数金额通常表示剥离操作

## 不常见的文件魔数

| 魔数 | 格式 | 扩展名 | 说明 |
|-------|--------|-----------|-------|
| `OggS` | Ogg 容器 | `.ogg` | 音频/视频 |
| `RIFF` | RIFF 容器 | `.wav`,`.avi` | 检查子格式 |
| `%PDF` | PDF | `.pdf` | 检查元数据和嵌入对象 |
| `GCDE` | PrusaSlicer 二进制 G-code | `.g`, `.bgcode` | 参见 3d-printing.md |

## 常见的 Flag 位置

- PDF 元数据字段（作者、标题、关键词）
- 图片 EXIF 数据
- 已删除文件（回收站 `$R` 文件）
- 注册表值
- 浏览器历史
- 日志文件碎片
- 内存字符串

## WMI 持久化分析

**模式（Backchimney）：** 恶意软件使用 WMI 事件订阅实现持久化（MITRE T1546.003）。

```bash
python PyWMIPersistenceFinder.py OBJECTS.DATA
```

- 查找带有 CommandLineEventConsumer 的 FilterToConsumerBindings
- 消费者命令中的 Base64 编码 PowerShell
- 事件过滤器触发系统事件（登录、定时器）

WMI 存储库分析详情请参见 [windows.md](windows.md)。

## 网络取证快速参考

- **TFTP netascii：** 二进制传输会损坏；用 `data.replace(b'\r\n', b'\n').replace(b'\r\x00', b'\r')` 修复
- **TLS keylog 解密：** 将 SSLKEYLOGFILE 或 RSA 私钥导入 Wireshark（编辑 → 首选项 → 协议 → TLS）
- **TLS 弱 RSA：** 提取证书，分解模数，使用 `rsatool` 生成私钥，添加到 Wireshark
- **USB 音频：** 使用 `tshark -e usb.iso.data` 提取等时数据，在 Audacity 中导入为原始 PCM
- **PCAP 中的 NTLMv2：** 从 NTLMSSP_AUTH 中提取服务器挑战 + NTProofStr + blob，进行暴力破解
- **WPA/WEP WiFi 解密：** `aircrack-ng -w wordlist capture.pcap` 破解 WPA 握手；WEP 通过足够 IV 破解。详见 [network.md](network.md#wpawep-wifi-decryption-from-pcap-defcamp-ctf-2016)。
- **PCAP 修复：** `pcapfix -d corrupted.pcap` 修复损坏的 PCAP 头/校验和以供 Wireshark 加载。详见 [network.md](network.md#corrupted-pcap-repair-with-pcapfix-csaw-ctf-2016)。
- **USB HID 键盘解码：** 从 USB 捕获中提取 8 字节 HID 报告；字节 2 = 键码，字节 0 = 修饰符（Shift）。详见 [peripheral-capture.md](peripheral-capture.md#usb-hid-键盘捕获解码-ekoparty-ctf-2016)。
- **dnscat2 重组：** 解码十六进制/base32 子域标签，剥离 9 字节 dnscat2 头，去重重传，重组负载。详见 [network-advanced.md](network-advanced.md#dnscat2-traffic-reassembly-from-dns-pcap-bsidessf-2017)。
- **USB 键盘 LED 渗漏：** 主机到设备的 HID SET_REPORT 包切换大写锁定 LED，时序编码摩尔斯码。详见 [peripheral-capture.md](peripheral-capture.md#usb-键盘-led-摩尔斯码外泄-bitsctf-2017)。

SMB3 解密、凭证提取请参见 [network.md](network.md)，完整 TLS/TFTP/USB 工作流请参见 [linux-forensics.md](linux-forensics.md)。

## 浏览器取证

- **Chrome/Edge：** 使用 DPAPI 主密钥解密 `Login Data` SQLite，AES-GCM 加密
- **Firefox：** 查询 `places.sqlite` -- `SELECT url FROM moz_places WHERE url LIKE '%flag%'`

完整浏览器凭证解密代码请参见 [linux-forensics.md](linux-forensics.md)。

## 其他技术快速参考

- **Docker 镜像取证：** 配置 JSON 保留所有 `RUN` 命令，即使清理后仍然存在。`tar xf app.tar` 后检查配置 blob。详见 [linux-forensics.md](linux-forensics.md)。
- **Linux 攻击链：** 检查 `auth.log`、`.bash_history`、最近的二进制文件、PCAP。详见 [linux-forensics.md](linux-forensics.md)。
- **RAID 5 XOR 恢复：** 三盘 RAID 5 中两盘 → 字节异或恢复第三盘：`bytes(a ^ b for a, b in zip(disk1, disk3))`。详见 [disk-advanced.md](disk-advanced.md#通过-xor-恢复-raid-5-磁盘-crypto-cat)。
- **GIMP 原始内存转储可视化检查：** Volatility 失败时，将 `.dmp` 以原始 RGB 数据打开，宽度约为显示器宽度（~1920）；滚动查找用户桌面帧缓冲截图。详见 [disk-and-memory.md](disk-and-memory.md#gimp-原始内存转储可视化检查inshack-2018)。
- **Kyoto Cabinet 哈希数据库取证：** 通过插入顺序探针键并二进制差异比较，恢复零键的键排序，找出每个哈希槽被覆盖的键。详见 [disk-advanced.md](disk-advanced.md#通过增量键插入进行-kyoto-cabinet-哈希数据库取证asis-ctf-2018)。
- **PowerShell 勒索软件：** 从 minidump 提取脚本，找到 AES 密钥，解密 SMTP 附件。详见 [disk-and-memory.md](disk-and-memory.md)。
- **Linux 勒索软件 + 内存转储：** Volatility 不可靠时，通过原始内存候选扫描和魔数验证恢复 AES 密钥；重新干净提取 zip 以避免漏文件/误报。详见 [disk-advanced.md](disk-advanced.md)。
- **已删除分区：** 使用 `testdisk` 或 `kpartx -av`。详见 [disk-advanced.md](disk-advanced.md)。
- **ZFS 取证：** 重建标签、Fletcher4 校验和、PBKDF2 破解。详见 [disk-advanced.md](disk-advanced.md)。
- **BSON 重组：** 从原始字节重组 BSON（二进制 JSON）文档；使用 Python `bson` 库解析。详见 [disk-and-memory.md](disk-and-memory.md#bson二进制-json格式重构icectf-2016)。
- **TrueCrypt 挂载：** 使用已知密码挂载 TrueCrypt/VeraCrypt 卷，命令 `veracrypt --mount` 或 `cryptsetup open --type tcrypt`。详见 [disk-and-memory.md](disk-and-memory.md#truecrypt--veracrypt-卷挂载grehack-ctf-2016)。
- **硬件信号：** VGA/HDMI TMDS/DisplayPort，Voyager 音频，Saleae UART 解码，Flipper Zero。详见 [signals-and-hardware.md](signals-and-hardware.md)。
- **视频中的大写锁定 LED 摩尔斯码：** 使用 OpenCV 跟踪监控摄像头帧中的大写锁定 LED 像素；开/关时长编码摩尔斯码（短点=点，长划=划）。详见 [signals-and-hardware.md](signals-and-hardware.md#caps-lock-led-摩尔斯码提取stem-ctf-2018)。
- **I2C 协议解码：** 解码 I2C 总线捕获（SDA/SCL 线）以提取 EEPROM 或传感器通信数据。详见 [signals-and-hardware.md](signals-and-hardware.md#i2c-bus-protocol-decoding-ekoparty-ctf-2016)。
- **穿孔卡 OCR：** 通过映射孔位到字符，使用标准编码网格解码 IBM-29 穿孔卡图像。详见 [signals-and-hardware.md](signals-and-hardware.md#ibm-29-punched-card-ocr-ekoparty-ctf-2016)。
- **USB HID 鼠标绘图：** 按绘图模式渲染相对 HID 移动为位图；分离模式，跳过笔抬起，缩放 5-8 倍。详见 [peripheral-capture.md](peripheral-capture.md#usb-hid-鼠标笔绘图恢复-ehax-2026)。
- **侧信道功率分析：** 多维功率轨迹（位置 × 猜测 × 轨迹 × 采样）。对轨迹求平均，找最大方差采样点，选择泄漏点最大功率的猜测。详见 [signals-and-hardware.md](signals-and-hardware.md)。
- **包间隔时序：** 二进制数据编码为 PCAP 中包间延迟。两个间隔值对应两个比特值。详见 [network-advanced.md](network-advanced.md)。
- **BMP 位平面二维码：** 使用 NumPy 提取每个 RGB 通道的 0-2 位平面；隐藏二维码通常在位 1（非位 0）。详见 [stego-image.md](stego-image.md#bmp-位平面二维码提取--steghidebypass-ctf-2025)。
- **图像拼图重组：** 通过拼块边缘像素差匹配，贪心放置到网格。详见 [stego-image.md](stego-image.md#通过边缘匹配重组拼图图像bypass-ctf-2025)。
- **DeepSound 音频隐写及密码破解：** 使用 `deepsound2john.py` 提取哈希，用 John 破解，从 WAV 中恢复隐藏文件；始终检查频谱图和 DeepSound。详见 [stego-advanced.md](stego-advanced.md#deepsound-音频隐写与密码破解-inshack-2018)。
- **曲面反射中的二维码重建：** 手动从视频中玻璃球反射重建二维码；翻转、去畸变，使用已知明文前缀修正前几字节，高纠错码修正其余。详见 [steganography.md](steganography.md#视频中曲面玻璃反射的二维码重建-plaidctf-2018)。
- **音频 FFT 笔记：** 主导频率 → 音符名称（A-G）拼写单词。详见 [stego-advanced.md](stego-advanced.md)。
- **音频元数据八进制：** Exiftool 注释中下划线分隔的八进制数字 → 解码为 ASCII/base64。详见 [stego-advanced.md](stego-advanced.md)。
- **G-code 可视化：** 侧投影（XZ/YZ）显示文本。详见 [3d-printing.md](3d-printing.md)。
- **Git 目录恢复：** 使用 `gitdumper.sh` 恢复暴露的 `.git` 目录。详见 [linux-forensics.md](linux-forensics.md)。
- **KeePass v4 破解：** 标准 `keepass2john` 不支持 v4/Argon2；使用 `ivanmrsulja/keepass2john` 分支或 `keepass4brute`。用 `cewl` 生成字典。详见 [linux-forensics.md](linux-forensics.md)。
- **跨通道多比特 LSB：** 不同 RGB 通道的不同位位置（R[0], G[1], B[2]）编码隐藏数据。详见 [stego-advanced.md](stego-advanced.md)。
- **F5 JPEG DCT 检测：** ±1 与 ±2 AC 系数比率从约 3:1 降至约 1:1；稀疏图像需次级 ±2/±3 指标。详见 [stego-image.md](stego-image.md#f5-jpeg-dct-系数比率检测-apoorvctf-2026)。
- **PNG 未使用调色板隐写：** 未被像素引用的 PLTE 条目在红色通道值中携带隐藏数据。详见 [stego-image.md](stego-image.md#png-未使用调色板条目隐写-apoorvctf-2026)。
- **键盘声学侧信道：** 从击键音频提取 MFCC 特征 + KNN 分类对比标记参考。10ms 窗口捕获冲击瞬态。详见 [signals-and-hardware.md](signals-and-hardware.md)。
- **TCP 标志隐蔽通道：** 6 个 TCP 标志位（FIN/SYN/RST/PSH/ACK/URG）= 0-63 值，编码 base64 字符。固定目标端口上的无意义标志组合即隐蔽数据。详见 [network-advanced.md](network-advanced.md)。
- **Brotli 解压炸弹缝隙：** 压缩炸弹有重复块；flag 在缝隙处打破模式。比较相邻块找不连续，只解压该区域。详见 [network-advanced.md](network-advanced.md)。
- **Git reflog/fsck squash 恢复：** `git rebase --squash` 留下孤立对象，可用 `git fsck --unreachable --no-reflogs` 恢复。详见 [linux-forensics.md](linux-forensics.md)。
- **DNS 尾部字节二进制：** DNS 查询结构后附加额外字节（`0x30`/`0x31`）编码二进制位；8 位 MSB 优先块 → ASCII。详见 [network-advanced.md](network-advanced.md)。
- **伪 TLS + mDNS 密钥 + 可打印字符合并：** 伪装成 TLS 的 TCP 流隐藏 ZIP；用 mDNS TXT 记录的 XOR 密钥解密；通过选择可打印字符合并两个解密数组。详见 [network-advanced.md](network-advanced.md)。
- **基于种子的像素置换隐写（Seed-based pixel permutation stego）：** 确定性像素洗牌（使用已知种子的 Fisher-Yates 算法）+ 从 Y 通道多位平面交错的 LSB 提取 → 隐藏的二维码。详见 [stego-image.md](stego-image.md#seed-based-pixel-permutation--multi-bitplane-qr-l3m0nctf-2025)。
- **BTRFS 快照恢复（BTRFS snapshot recovery）：** 被删除的文件在 BTRFS 快照/备用子卷中依然存在。使用 `mount -o subvol=@backup` 访问历史副本。详见 [disk-recovery.md](disk-recovery.md#btrfs-子卷快照恢复bsidessf-2026)。
- **JPEG XL TOC 置换（JPEG XL TOC permutation）：** JXL 的渐进式 TOC 置换控制部分解码时的图块收敛顺序。截断到不同偏移，测量哪些图块先收敛 → 收敛顺序编码 flag。详见 [stego-advanced-2.md](stego-advanced-2.md#jpeg-xl-toc-排列隐写bsidessf-2026)。
- **Kitty 终端图形（Kitty terminal graphics）：** `ESC_G` 协议以 base64 分块嵌入 zlib 压缩的 RGB 图像数据。剥离转义序列，拼接，解压，重建图像。详见 [steganography.md](steganography.md#kitty-terminal-graphics-protocol-decoding-bsidessf-2026)。
- **ANSI 转义序列隐写（ANSI escape sequence stego）：** flag 文本交错在 ANSI 颜色码和盲文字符之间。渲染时不可见；通过剥离转义序列和非 ASCII 字符提取。详见 [steganography.md](steganography.md#ansi-escape-sequence-steganography-in-terminal-art-bsidessf-2026)。
- **自动立体图解法（Autostereogram solving）：** 复制图层，差值混合，水平平移约 100 像素以显示隐藏的 3D 文字。详见 [steganography.md](steganography.md#autostereogram--magic-eye-solving-bsidessf-2026)。
- **双层字节+行交错（Two-layer byte+line interleaving）：** 两个文件先字节交错，再扫描线交错。先反交错偶数/奇数字节（得到有效图像），再反交错偶数/奇数行。详见 [steganography.md](steganography.md#ansi-escape-sequence-steganography-in-terminal-art-bsidessf-2026)。
- **SMB RID 重用（SMB RID recycling）：** 访客认证 + LSARPC 的 `LsaLookupSids` 通过递增 RID 从 PCAP 中枚举 AD 账户。详见 [network-advanced.md](network-advanced.md#通过-lsarpc-的-smb-rid-循环-midnight-2026)。
- **时间烤（Timeroasting，MS-SNTP）：** 使用机器 RID 的 NTP 请求从 DC 提取 HMAC-MD5 哈希；用 hashcat -m 31300 破解。详见 [network-advanced.md](network-advanced.md#timeroasting--ms-sntp-hash-extraction-midnight-2026)。
- **Android 取证（Android forensics）：** 使用 `adb pull` 导出 APK，使用 `apktool` 分析，检查 `/data/data/<package>/` 下的 `shared_prefs/` 和 SQLite 数据库。详见 [disk-and-memory.md](disk-and-memory.md#android-取证)。
- **Docker 容器取证（Docker container forensics）：** `docker save` 导出分层 tar 包；被删除文件仍存在于早期层。`docker history --no-trunc` 显示构建秘密。详见 [disk-and-memory.md](disk-and-memory.md#容器取证docker)。
- **云存储取证（Cloud storage forensics）：** S3/GCP/Azure 版本控制保留已删除对象。使用 `list-object-versions` 恢复已删除 flag。详见 [disk-and-memory.md](disk-and-memory.md#云存储取证aws-s3--gcp--azure)。
- **APFS 快照恢复（APFS snapshot recovery）：** 写时复制文件系统在快照中保留历史文件状态；使用 `icat` 结合不同 XID 块偏移读取跨事务 ID 的 inode。详见 [disk-advanced.md](disk-advanced.md#apfs-快照历史文件恢复-srdnlenctf-2026)。
- **Windows KAPE 初步分析（Windows KAPE triage）：** 预收集的工件 ZIP；从 PowerShell 历史 → Amcache → MFT → 注册表配置单元开始分析。详见 [disk-and-memory.md](disk-and-memory.md#windows-kape-初筛分析utctf-2026)。
- **WordPerfect 宏 XOR（WordPerfect macro XOR）：** `.wcm` 文件包含嵌入加密数据的宏；XOR 公式 `(a+b)-2*(a&b)` 等价于按位异或。详见 [disk-advanced.md](disk-advanced.md#wordperfect-宏-xor-提取-srdnlenctf-2026)。
- **从 coredump 提取 TLS 主密钥（TLS master key from coredump）：** 在 coredump 中搜索会话 ID（来自 Wireshark 握手）；读取其前 48 字节作为主密钥。创建 Wireshark 预主密钥日志文件。详见 [network.md](network.md#从-coredump-中提取-tls-主密钥plaidctf-2014)。
- **损坏的 git blob 修复（Corrupted git blob repair）：** 单字节损坏导致 SHA-1 变化；对每个字节位置暴力尝试（256 × 文件大小），用 `git hash-object` 验证。详见 [linux-forensics.md](linux-forensics.md#通过字节暴力破解修复损坏的-git-blobcsaw-ctf-2015)。
- **从 PCAP 重组分割归档（Split archive reassembly from PCAP）：** 同尺寸 HTTP 传输文件，MD5 哈希命名，是归档碎片；按 Apache 目录列表时间排序，拼接，从 TCP 聊天流提取密码。详见 [network.md](network.md#split-archive-reassembly-from-http-transfers-asis-ctf-finals-2013)。
- **视频帧累积（Video frame accumulation）：** 视频中不同位置闪烁图像；合成所有帧（逐像素取最大值）显示隐藏二维码或图像。详见 [stego-advanced-2.md](stego-advanced-2.md#视频帧累积隐藏图像asis-ctf-finals-2013)。
- **反转音频（Reversed audio）：** 听起来像语音的杂乱音频倒放；使用 `sox audio.wav reversed.wav reverse` 或 Audacity 效果 → 反转揭示隐藏信息。详见 [stego-advanced-2.md](stego-advanced-2.md#反转音频隐藏信息asis-ctf-finals-2013)。
- **多流视频容器隐写（Multi-stream video container stego）：** MP4/MKV 含多视频流；默认流是迷惑，flag 在次要流。用 `ffprobe -hide_banner file.mp4` 枚举，`ffmpeg -i file.mp4 -map 0:1 -frames:v 1 flag.jpg` 提取。详见 [steganography.md](steganography.md#ansi-escape-sequence-steganography-in-terminal-art-bsidessf-2026)。
- **FAT16 空闲空间恢复（FAT16 free space recovery）：** flag 隐藏在 FAT16 文件系统未分配簇中。解析 FAT 表，枚举空闲簇（条目=0x0000），读取数据区。详见 [disk-recovery.md](disk-recovery.md#fat16-空闲空间数据恢复bsidessf-2026)。
- **FAT16 删除文件恢复（fls/icat）（FAT16 deleted file recovery）：** FAT 删除时目录项首字节替换为 `0xE5`，但数据仍在。用 `fls -r -d image.img` 列出删除项，`icat image.img <inode>` 按 inode 恢复。详见 [disk-recovery.md](disk-recovery.md#通过-sleuth-kit-恢复-fat16-已删除文件metactf-flash-2026)。
- **Ext2 孤立 inode 恢复（Ext2 orphaned inode recovery）：** 删除文件留下孤立 inode；用 `e2fsck -y disk.img` 连接到 `/lost+found`。也可用 `debugfs` 的 `lsdel` 或 `icat`。详见 [disk-recovery.md](disk-recovery.md#通过-fsck-恢复-ext2-孤立-inodebsidessf-2026)。
- **Linux input_event 键盘记录解析（Linux input_event keylogger parsing）：** 24 字节 `struct input_event` 二进制转储；过滤 `type==1`（EV_KEY）、`value==1`（按下），通过 `input-event-codes.h` 映射键码。详见 [signals-and-hardware.md](signals-and-hardware.md#linux-input_event-keylogger-dump-parsing-pwn2win-2016)。
- **VBA 宏单元格数据转二进制（VBA macro cell data to binary）：** Excel 单元格含数值；VBA `CByte((val-78)/3)` 转换为 ELF 字节。用 Python 重写，切勿运行宏。详见 [linux-forensics.md](linux-forensics.md#vba-宏取证---excel-单元格数据转-elf-二进制sharif-ctf-2016)。
- **RGB 奇偶隐写（RGB parity steganography）：** 每像素 R+G+B 求和；偶数为白，奇数为黑，渲染隐藏二进制位图。详见 [stego-image.md](stego-image.md#rgb-parity-steganography-break-in-2016)。
- **隐藏 PDF 对象（Hidden PDF objects）：** 未被引用的内容流对象不在 `/Kids` 数组中。添加到 `/Kids`，递增 `/Count`，重新渲染。详见 [network-advanced.md](network-advanced.md#unreferenced-pdf-objects-with-hidden-pages-sharifctf-7-2016)。
- **Arnold 猫映射解扰（Arnold's Cat Map descrambling）：** 方形图像的周期性混沌变换；迭代正向映射直到恢复原图。周期整除 `3*N`。详见 [stego-advanced-2.md](stego-advanced-2.md#arnolds-cat-map-图像解扰-nuit-du-hack-2017)。
- **Python 内存中源码恢复（Python in-memory source recovery）：** 附加 `pyrasite-shell` 到运行中的 Python 进程，使用 `uncompyle6`（Python ≤3.8）或 `pycdc`（Python 3.9+）反编译 `func_code` 对象，导出 `globals()` 查找秘密。详见 [linux-forensics.md](linux-forensics.md#通过-pyrasite-恢复-python-内存中的源代码insomnihack-2017)。
- **HFS+ 资源分支恢复（HFS+ resource fork recovery）：** HFS+ 资源分支中隐藏数据，`binwalk`/`foremost` 无法检测；用 HFSExplorer + 010 Editor HFS 模板提取范围记录。详见 [disk-advanced.md](disk-advanced.md#hfs-资源分支隐藏二进制恢复confidence-ctf-2017)。
- **WAV 音频中的串口 UART（Serial UART from WAV audio）：** 音频中的方波编码 UART 串口数据；确定波特率，解析起始/停止位，解码 LSB 优先的字节帧。详见 [signals-and-hardware.md](signals-and-hardware.md#serial-uart-data-decoding-from-wav-audio-easyctf-2017)。
- **高分辨率 SSTV 解调（High-resolution SSTV demodulation）：** 标准 SSTV 解码器无法处理高采样率录音；用手动 FM 解调结合 `arccos` + 微分实现。详见 [stego-advanced-2.md](stego-advanced-2.md#高分辨率-sstv-自定义-fm-解调-plaidctf-2017)。
- **损坏 ZIP 头修复（Corrupted ZIP header repair）：** 修正本地文件头（偏移 26）和中央目录（偏移 28）中的文件名长度字段；备选方案：在候选偏移暴力尝试原始 deflate 解压。详见 [disk-recovery.md](disk-recovery.md#通过头字段修改修复损坏的-zipplaidctf-2017)。
- **SQLite 编辑历史重建（SQLite edit history reconstruction）：** 重放 SQLite 差异表中的插入/删除差异，重建文档每个中间状态；flag 可能曾被输入后删除。详见 [disk-advanced.md](disk-advanced.md#通过-diff-表重建-sqlite-编辑历史google-ctf-2017)。
- **MJPEG FFD9 尾随字节隐写（MJPEG FFD9 trailing byte stego）：** MJPEG 帧中 JPEG EOI 标记（FFD9）后多余字节形成隐蔽通道；按 FFD8 分割，提取 FFD9 后数据。详见 [stego-advanced-2.md](stego-advanced-2.md#mjpeg-ffd9-之后的额外字节隐写-polictf-2017)。
- **USB MIDI Launchpad 网格重建（USB MIDI Launchpad grid reconstruction）：** USB PCAP 中的 MIDI Note On/Off 映射到 8x8 Launchpad 网格（`key = row*16 + col`）；从按键序列重建视觉图案。详见 [signals-and-hardware.md](signals-and-hardware.md#usb-midi-launchpad-流量重构sthack-2017)。
## 通过 LSARPC 的 SMB RID 重用（Midnight 2026）

通过分析带有连续 RID 的 LSARPC `LsaLookupSids` 调用，从 PCAP 中枚举 AD 账户，前提是经过 Guest 认证。过滤条件：`dcerpc.cn_bind_to_str contains lsarpc`。

完整的 RPC 调用序列和 Wireshark 过滤器请参见 [network-advanced.md](network-advanced.md#通过-lsarpc-的-smb-rid-循环-midnight-2026)。

## Timeroasting / MS-SNTP 哈希提取（Midnight 2026）

通过发送带有机器账户 RID 的 NTP 请求，从 MS-SNTP 响应中提取可破解的 HMAC-MD5 哈希。使用 `hashcat -m 31300` 进行破解。

```bash
# 提取 NTP 负载，转换为 hashcat 格式，进行破解
tshark -r capture.pcapng -Y "ntp && ip.src == <DC_IP>" -T fields -e udp.payload
hashcat -m 31300 -a 0 -O hashes.txt rockyou.txt --username
```

负载解析脚本和完整攻击链请参见 [network-advanced.md](network-advanced.md#timeroasting--ms-sntp-hash-extraction-midnight-2026)。

## PCAP 中的 HTTP 渗漏

**快速路径：** 使用 `tshark --export-objects http,/tmp/objects` 可即时提取上传的文件。检查 multipart POST 上传、不寻常的 User-Agent 字符串以及渗漏的文件（带有 flag 文本的图片）。详见 [network.md](network.md#pcap-中的-http-文件上传外泄metactf-2026)。

## 常见编码

```bash
echo "base64string" | base64 -d
echo "hexstring" | xxd -r -p
# ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**ROT18：** 对字母执行 ROT13，对数字执行 ROT5。多阶段取证中常见的最终编码层。实现方法请参见 [linux-forensics.md](linux-forensics.md)。
