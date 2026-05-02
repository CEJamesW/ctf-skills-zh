# CTF Forensics - 网络

## 目录
- [tcpdump 快速参考](#tcpdump-quick-reference)
- [通过 Keylog 文件进行 TLS/SSL 解密](#tlsssl-decryption-via-keylog-file)
- [Wireshark 基础](#wireshark-basics)
- [端口扫描分析](#port-scan-analysis)
- [通过 MAC OUI 识别网关/设备](#gatewaydevice-via-mac-oui)
- [WordPress 侦察](#wordpress-reconnaissance)
- [后渗透流量](#post-exploitation-traffic)
- [凭证提取](#credential-extraction)
- [SMB3 加密流量](#smb3-encrypted-traffic)
- [5G/NR 协议分析](#5gnr-protocol-analysis)
- [邮件头](#email-headers)
- [USB HID 隐写/Chord PCAP（UTCTF 2024）](#usb-hid-stenographychord-pcap-utctf-2024)
- [UDP 中的 BCD 编码（VuwCTF 2025）](#bcd-encoding-in-udp-vuwctf-2025)
- [PCAP 中的 HTTP 文件上传外泄（MetaCTF 2026）](#http-file-upload-exfiltration-in-pcap-metactf-2026)
- [从 Coredump 中提取 TLS 主密钥（PlaidCTF 2014）](#tls-master-key-extraction-from-coredump-plaidctf-2014)
- [HTTP 传输中的分割归档重组（ASIS CTF Finals 2013）](#split-archive-reassembly-from-http-transfers-asis-ctf-finals-2013)
- [从 PCAP 解密 WPA/WEP WiFi（DefCamp CTF 2016）](#wpawep-wifi-decryption-from-pcap-defcamp-ctf-2016)
- [使用 pcapfix 修复损坏的 PCAP（CSAW CTF 2016）](#corrupted-pcap-repair-with-pcapfix-csaw-ctf-2016)
- [从 PCAP 解密 SAP Dialog 协议（GreHack CTF 2016）](#sap-dialog-protocol-decryption-from-pcap-grehack-ctf-2016)
- [通过二进制响应探测的 DNS 外泄 Oracle（ASIS CTF Finals 2017）](#dns-exfiltration-oracle-via-binary-response-probing-asis-ctf-finals-2017)
- [ICMP Echo 负载长度作为隐蔽信道（TokyoWesterns CTF 4th 2018）](#icmp-echo-payload-length-as-covert-channel-tokyowesterns-ctf-4th-2018)

---

## tcpdump 快速参考

命令行数据包捕获工具，用于快速网络取证初步分析。

```bash
# 在接口上进行基本捕获
sudo tcpdump -i eth0

# 捕获到文件
sudo tcpdump -i eth0 -w capture.pcap

# 按源 IP 过滤
sudo tcpdump -i eth0 src 192.168.1.100

# 按目标端口过滤
sudo tcpdump -i eth0 dst port 80

# 组合过滤并输出到文件
sudo tcpdump -i eth0 -w packets.pcap 'src 172.22.206.250 and port 443'

# 从文件读取并显示详细信息
tcpdump -r capture.pcap -v

# 显示数据包内容的 ASCII
tcpdump -r capture.pcap -A

# 显示十六进制 + ASCII 转储
tcpdump -r capture.pcap -X

# 统计总包数
tcpdump -r capture.pcap -q | wc -l
```

**常用过滤器：**
| 过滤器 | 说明 |
|--------|-------------|
| `host 10.0.0.1` | 与该 IP 的流量 |
| `net 192.168.1.0/24` | 整个子网 |
| `port 80` | HTTP 流量 |
| `tcp` / `udp` / `icmp` | 协议过滤 |
| `src host X and dst port Y` | 组合过滤 |

**关键提示：** 当 Wireshark 不可用时，使用 tcpdump 进行快速命令行初步分析。可通过管道传给 `strings` 或 `grep` 快速搜索 flag：`tcpdump -r capture.pcap -A | grep -i flag`。

---

## 通过 Keylog 文件进行 TLS/SSL 解密

要在 Wireshark 中解密 TLS 流量，需要提供 pre-master secret 或 keylog 文件。

**方法 1 — SSLKEYLOGFILE（客户端密钥日志）：**

如果挑战提供了 keylog 文件（或你可以设置 `SSLKEYLOGFILE`）：
```bash
# 在运行客户端前设置环境变量
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl https://target/secret

# 导入到 Wireshark：
# 编辑 → 首选项 → 协议 → TLS → (Pre)-Master-Secret 日志文件名 → /tmp/sslkeys.log
```

**Keylog 文件格式（NSS Key Log 格式）：**
```text
CLIENT_RANDOM <32字节客户端随机数十六进制> <48字节主密钥十六进制>
```

**方法 2 — RSA 私钥（如果已知服务器密钥）：**

**注意：** 仅适用于 RSA 密钥交换。使用前向保密（ECDHE/DHE 套件）的会话无法用服务器私钥解密 — 应使用方法 1。CTF 中弱 RSA 密钥通常使用 RSA 密钥交换。

```bash
# Wireshark：编辑 → 首选项 → 协议 → TLS → RSA 密钥列表
# IP: 127.0.0.1，端口: 443，协议: http，密钥文件: server.key

# 或通过 tshark：
tshark -r capture.pcap -o "tls.keys_list:127.0.0.1,443,http,server.key" -Y http
```

**方法 3 — 弱 RSA 密钥分解（参见 linux-forensics.md）：**
```bash
# 从 PCAP 中提取证书
tshark -r capture.pcap -Y "tls.handshake.type==11" -T fields -e tls.handshake.certificate | head -1

# 分解弱模数，使用 rsatool 生成私钥
python rsatool.py -p <p> -q <q> -e 65537 -o server.key

# 导入密钥到 Wireshark
```

**解密所需的 SSL 握手组件：**
1. `client_random` — ClientHello 中发送
2. `server_random` — ServerHello 中发送
3. Pre-master secret (PMS) — 在 ClientKeyExchange 中用服务器 RSA 公钥加密

**关键提示：** 查找挑战文件中的 keylog 文件（`.log`、`sslkeys.txt`）。如果挑战给出私钥，直接使用。对于证书中的弱 RSA 密钥，分解模数以推导私钥。

---

## Wireshark 基础

```bash
# 过滤器
http.request.method == "POST"
tcp.stream eq 5
frame contains "flag"

# 导出文件
文件 → 导出对象 → HTTP

# tshark
tshark -r capture.pcap -Y "http" -T fields -e http.file_data
tshark -r capture.pcap --export-objects http,/tmp/http_objects
```

---

## 端口扫描分析

```bash
# IP 会话统计
tshark -r capture.pcap -q -z conv,ip

# 查找开放端口（SYN-ACK 响应）
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==1" \
  -T fields -e ip.src -e tcp.srcport | sort -u
```

---

## 通过 MAC OUI 识别网关/设备

```bash
# 提取 MAC 地址
tshark -r capture.pcap -Y "arp" -T fields \
  -e arp.src.hw_mac -e arp.src.proto_ipv4 | sort -u

# 厂商查询
curl -s "https://macvendors.com/query/88:bd:09"
```

---

## WordPress 侦察

**识别 WPScan：**
```bash
tshark -r capture.pcap -Y "http.user_agent contains \"WPScan\"" | head -1
```

**WordPress 版本：**
```bash
cat /tmp/http_objects/feed* | grep -i generator
```

**插件：**
```bash
tshark -r capture.pcap \
  -Y "http.response.code == 200 && http.request.uri contains \"wp-content/plugins\"" \
  -T fields -e http.request.uri | sort -u
```

**用户名（REST API）：**
```bash
cat /tmp/http_objects/*per_page* | jq '.[].name'
```

---
## 后渗透流量

**步骤 1：TCP 会话**
```bash
tshark -r capture.pcap -q -z conv,tcp
```

**步骤 2：已建立连接（SYN-ACK）**
```bash
tshark -r capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 1" \
  -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport | sort -u
```

**步骤 3：跟踪 TCP 流**
```bash
tshark -r capture.pcap -q -z "follow,tcp,ascii,<stream_number>"
```

**反向 shell 指示器：**
- `bash: cannot set terminal process group`
- `bash: no job control in this shell`
- 类似 `www-data@hostname:/path$` 的 shell 提示符

---

## 凭证提取

**高价值文件：**
| 应用 | 文件 | 格式 |
|-------------|------|--------|
| WordPress | `wp-config.php` | `define('DB_PASSWORD', '...')` |
| Laravel | `.env` | `DB_PASSWORD=` |
| MySQL | `/etc/mysql/debian.cnf` | `password = ` |

```bash
# 在 shell 流中搜索凭证
tshark -r capture.pcap -q -z "follow,tcp,ascii,<stream>" | grep -i "password"
```

---

## SMB3 加密流量

**步骤 1：提取 NTLMv2 哈希**
```bash
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.ntlmv2_response.ntproofstr \
  -e ntlmssp.auth.username
```

**步骤 2：使用 hashcat 破解**
```bash
hashcat -m 5600 ntlmv2_hash.txt wordlist.txt
```

**步骤 3：推导 SMB 3.1.1 会话密钥（Python）**
```python
from Cryptodome.Cipher import AES, ARC4
from Cryptodome.Hash import MD4
import hmac, hashlib

def SP800_108_Counter_KDF(Ki, Label, Context, L):
    n = (L // 256) + 1
    result = b''
    for i in range(1, n + 1):
        data = i.to_bytes(4, 'big') + Label + b'\x00' + Context + L.to_bytes(4, 'big')
        result += hmac.new(Ki, data, hashlib.sha256).digest()
    return result[:L // 8]

# 计算会话密钥
nt_hash = MD4.new(password.encode('utf-16le')).digest()
response_key = hmac.new(nt_hash, (user.upper() + domain.upper()).encode('utf-16le'), hashlib.md5).digest()
key_exchange_key = hmac.new(response_key, ntproofstr, hashlib.md5).digest()
session_key = ARC4.new(key_exchange_key).encrypt(encrypted_session_key)

# 推导加密密钥
c2s_key = SP800_108_Counter_KDF(session_key, b"SMBC2SCipherKey\x00", preauth_hash, 128)
s2c_key = SP800_108_Counter_KDF(session_key, b"SMBS2CCipherKey\x00", preauth_hash, 128)
```

**步骤 4：解密（AES-128-GCM）**
```python
def decrypt_smb311(transform_data, key):
    signature = transform_data[4:20]
    nonce = transform_data[20:32]
    aad = transform_data[20:52]
    encrypted = transform_data[52:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(encrypted, signature)
```

---

## 5G/NR 协议分析

**Wireshark 设置：**
- 启用：NAS-5GS、RLC-NR、PDCP-NR、MAC-NR

**5G 中的 SMS（3GPP TS 23.040）：**

| IEI | 格式 |
|-----|--------|
| 0x0c | iMelody（铃声） |
| 0x0e | 大动画（16×16） |
| 0x18 | WVG（矢量图形） |

**iMelody 转摩斯码：**
- 类似 `c4c4c4r2` 的音符编码点划符号

---

## 邮件头

- 检查路由信息
- 查找编码附件（base64）
- MIME 边界可能隐藏数据

---

## USB HID 速记/和弦 PCAP（UTCTF 2024）

**模式（乱码）：** USB 键盘 PCAP 中同时多键按下 = 速记和弦。

**检测：** 中断传输中出现多个同时按下的 USB HID 键（6 个及以上），非正常打字。

**解码流程：**
1. 从 PCAP 中提取 HID 报告
2. 检测同时按键状态（同一报告中多个键码）
3. 将和弦映射到 Plover 速记词典
4. 安装 Plover，使用其词典进行翻译

```bash
# 提取 USB HID 数据
tshark -r capture.pcap -Y "usb.transfer_type == 1" -T fields -e usb.capdata
```

---

## UDP 中的 BCD 编码（VuwCTF 2025）

**模式（1.5x-engineer）：** “1.5x” 指编码比例。

**BCD（二进制编码十进制）：** 每个半字节（4 位）编码一个十进制数字（0-9）。每字节编码两个数字，相比 ASCII 十进制每字节一个数字，BCD 密度是 ASCII 的 2 倍。“1.5x” 名称指挑战特定的帧结构：3 个 BCD 字节编码 6 个数字，代表 2 个 ASCII 字节（3:2 比例）。

**解码：**
```python
def bcd_decode(data):
    result = ''
    for byte in data:
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        result += f'{high}{low}'
    return result

# UDP 会话通过首字节区分
# 会话 1 = BCD 编码的 ASCII 元数据带 flag
# 会话 2 = 加密的 DOCX
```

**经验：** 挑战名称通常暗示编码比例或技术。

---

## PCAP 中的 HTTP 文件上传外泄（MetaCTF 2026）

**模式（Dead Drop）：** 小型 PCAP，TCP 流中包含 HTTP 流量。外泄数据通过 multipart 表单 POST 上传为文件。

**快速排查：**
```bash
# 统计数据包和协议
tshark -r capture.pcap -q -z io,phs

# 列出 HTTP 请求
tshark -r capture.pcap -Y "http.request" -T fields -e http.request.method -e http.request.uri -e http.host

# 导出所有 HTTP 对象（传输的文件）
tshark -r capture.pcap --export-objects http,/tmp/http_objects
ls -la /tmp/http_objects/

# 跟踪特定 TCP 流
tshark -r capture.pcap -q -z "follow,tcp,ascii,0"
tshark -r capture.pcap -q -z "follow,tcp,ascii,1"
```

**提取流程：**
1. 导出 HTTP 对象 — 上传的文件会自动提取
2. 检查 multipart form-data POST 请求（文件上传）
3. 查找异常 User-Agent 字符串（如 `DeadDropBot/1.0`）指示自动化外泄
4. 提取的文件可能是带有可视化 flag 文本的图片（PNG/JPEG）— 打开检查

**外泄关键指示器：**
- POST 到 `/upload` 端点
- 非标准 User-Agent 字符串
- 数据包数量少但包含文件传输
- “Dead drop” 模式：攻击者上传文件到 Web 服务器供后续检索

**经验：** 总是先用 `--export-objects` 提取传输文件，再做深度包分析。flag 通常就在外泄文件中。

---

## 从 Coredump 中提取 TLS 主密钥（PlaidCTF 2014）

**模式：** 给定包含 HTTPS 流量的 PCAP 和服务器/客户端进程的 coredump，从 OpenSSL 内存中的会话结构提取 TLS 主密钥以解密流量。

**提取流程：**

1. 在 Wireshark 的握手中找到 TLS 会话 ID（ClientHello/ServerHello 明文可见）
2. 在 coredump 中搜索会话 ID 字节：
```bash
# 在 coredump 中搜索会话 ID
grep -c '\x19\xAB\x5E\xDC\x02\xF0\x97\xD5' corefile
hexdump -C corefile | grep --before=5 '19 ab 5e dc'
```

3. 在 OpenSSL 的 `ssl_session_st` 结构中，`master_key[48]` 紧挨着 `session_id[32]` 之前。读取会话 ID 匹配位置前的 48 字节。

4. 创建 Wireshark 预主密钥日志文件：
```text
RSA Session-ID:<hex_session_id> Master-Key:<hex_master_key>
```

5. 在 Wireshark 中加载：编辑 → 首选项 → 协议 → TLS → （预）主密钥日志文件名

**关键点：** OpenSSL 在 `ssl_session_st` 中将 `master_key[48]` 直接存储在 `session_id[32]` 之前。搜索 coredump 中的会话 ID（来自 TLS 握手），然后读取其前 48 字节。此方法适用于 coredump、内存转储和 Volatility 内存提取。

---
## Split Archive Reassembly from HTTP Transfers (ASIS CTF Finals 2013)

**模式：** PCAP 包含多个带有 MD5 哈希文件名的 HTTP 文件传输，文件大小均相同，只有一个较小的文件。文件是拆分归档（例如 7z）的碎片，必须按顺序重新组装。另一个 TCP 流包含带有归档密码的聊天对话。

**识别：**
- 多个通过 HTTP 传输的文件，大小统一（例如 61440 字节），且有一个较小的尾部碎片
- 第一个文件具有归档魔数（例如 `7z` 头部 `37 7A BC AF 27 1C`）
- 使用掩盖流量和多个端口来混淆传输
- PCAP 中的 Apache 目录列表提供文件修改时间戳

**重组工作流程：**

1. 提取所有 HTTP 对象并识别碎片：
```bash
# 导出 HTTP 对象
tshark -r capture.pcap --export-objects http,/tmp/http_objects
ls -la /tmp/http_objects/

# 检查第一个文件的归档魔数
xxd /tmp/http_objects/d33cf9e6230f3b8e5a0c91a0514ab476 | head -1
# 00000000: 377a bcaf 271c ...  → 7z 归档头
```

2. 从 PCAP 中 Apache 目录列表的时间戳确定碎片顺序：
```bash
# 提取目录列表页面
tshark -r capture.pcap -Y "http.response and http.content_type contains html" \
  -T fields -e http.file_data | head -1
# 从 HTML 表格解析修改时间戳，按时间排序
```

3. 按时间戳顺序拼接碎片：
```bash
# 按修改时间戳排序文件（最早的先，最小的文件最后）
cat d33cf9e6230f3b8e5a0c91a0514ab476 \
    57f18f111f47eb9f7b5cdf5bd45144b0 \
    1e13be50f05092e2a4e79b321c8450d4 \
    ... \
    c68cc0718b8b85e62c8a671f7c81e80a > archive.7z
```

4. 从 TCP 会话流中提取密码：
```bash
# 跟踪 TCP 流查找带有密钥交换的聊天
tshark -r capture.pcap -q -z "follow,tcp,ascii,0"
# 查找“secret key” / “part N”消息，拼接所有部分
```

5. 使用恢复的密码解压：
```bash
7z x archive.7z -p"M)m5s6S^[>@#Q3+10PD.KE#cyPsvqH"
```

**关键洞察：** 当 PCAP 包含许多同尺寸文件传输时，怀疑是拆分归档。碎片顺序不是下载顺序——查找 PCAP 中的 Apache/nginx 目录列表页面，其修改时间戳提供正确的重组顺序。最小的文件是尾部碎片。

---

## WPA/WEP WiFi Decryption from PCAP (DefCamp CTF 2016)

捕获的 pcapng 格式 WiFi 流量如果通过暴力破解获得了 WEP/WPA 密钥或已知密钥，则可以解密。

```bash
# 第一步：识别捕获中的加密 WiFi 网络
aircrack-ng capture.pcapng

# 第二步：破解 WEP 密钥（PTW 攻击或暴力破解）
aircrack-ng -a 1 capture.pcapng                    # PTW 攻击（快速）
aircrack-ng -a 1 -w wordlist.txt capture.pcapng     # 字典攻击

# 第三步：破解 WPA/WPA2 密钥
aircrack-ng -a 2 -w rockyou.txt capture.pcapng

# 第四步：使用恢复的密钥解密流量
airdecap-ng -w "recovered_key" capture.pcapng       # WEP
airdecap-ng -p "passphrase" -e "SSID" capture.pcapng # WPA

# 第五步：分析解密后的流量
# 输出：capture-dec.pcapng（解密后的数据包）
wireshark capture-dec.pcapng

# 备选方案：直接在 Wireshark 中解密
# 编辑 > 首选项 > 协议 > IEEE 802.11
# 添加解密密钥（WEP/WPA-PWD/WPA-PSK）

# 查找：HTTP 流量、IPP（打印）、FTP、未加密协议
# 多次密码更改可能需要多次解密
```

**关键洞察：** WiFi CTF 挑战中，捕获文件中常有多次加密密钥更换。解密后在流量中寻找下一个密码提示，再解密下一段。检查 Internet Printing Protocol (IPP) 流中的作业名字段，可能包含 flag。

---

## Corrupted PCAP Repair with pcapfix (CSAW CTF 2016)

损坏的数据包捕获文件可以修复，使其能在 Wireshark 中打开。

```bash
# 安装 pcapfix
# apt install pcapfix  (或 brew install pcapfix)

# 修复损坏的 pcap/pcapng 文件
pcapfix -d corrupted.pcap        # 基础修复，带详细输出
pcapfix -d corrupted.pcapng      # 也支持 pcapng 格式

# 输出：fixed_corrupted.pcap（修复后的文件）

# pcapfix 处理的常见损坏类型：
# - 文件头损坏（魔数）
# - 数据包截断
# - 无效的数据包长度
# - 缺失数据包头
# - 字节序错误
# - 损坏的节头（pcapng）

# 如果 pcapfix 失败，尝试手动修复：
python3 -c "
import struct
with open('corrupted.pcap', 'rb') as f:
    data = bytearray(f.read())

# 修复 pcap 魔数（微秒时间戳 0xa1b2c3d4，纳秒时间戳 0xa1b23c4d）
data[0:4] = struct.pack('<I', 0xa1b2c3d4)

# 修复版本号（2.4）
data[4:6] = struct.pack('<H', 2)
data[6:8] = struct.pack('<H', 4)

with open('fixed.pcap', 'wb') as f:
    f.write(data)
"

# 然后用 Wireshark 打开
wireshark fixed_corrupted.pcap
```

**关键洞察：** 损坏的 PCAP 在取证 CTF 挑战中很常见。优先尝试 `pcapfix`，它能自动处理大多数损坏。手动修复时，pcap 头部为 24 字节：魔数(4) + 版本(4) + 时区(4) + 精度(4) + 捕获长度(4) + 链路类型(4)。

---

## SAP Dialog Protocol Decryption from PCAP (GreHack CTF 2016)

网络捕获中的 SAP Dialog 帧可使用 Windows 下的 Cain and Abel 工具解密。

```bash
# SAP Dialog 协议使用弱混淆（非真正加密）
# 第一步：在 Wireshark 中打开 PCAP 识别 SAP 流量
# 过滤器：sap 或 tcp.port == 3200

# 第二步：使用 Cain and Abel（Windows 工具）解密
# - 在 Cain 的 Sniffer 标签导入 PCAP
# - 选择 SAP Dialog 条目
# - 右键 > 查看以解密帧
# - 用 Ctrl+F 搜索关键字（flag、key、password）

# 备选方案：使用 Wireshark 的 SAP Dissector 插件
# - 安装：apt install wireshark-plugin-sap（如果可用）
# - 或：https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark

# 手动方法使用 pysap：
# pip install pysap
from pysap import SAPDiag
# 解析 PCAP 中的 SAP Dialog 数据包
```

**关键洞察：** SAP Dialog 协议的“加密”是简单的混淆，易于逆转。Cain and Abel（Windows）内置 SAP Dialog 解密。Linux 下可用 pysap 或 Wireshark SAP 解析插件。

---

---
## 通过二进制响应探测的 DNS 外泄 Oracle（ASIS CTF Finals 2017）

对带有二进制字符串前缀的子域名进行 DNS 查询充当一个 oracle：当前缀匹配 flag 位时，服务器返回 NOERROR，否则返回 NXDOMAIN。通过逐步构建二进制字符串——每次添加一位并测试哪个值返回 NOERROR——逐位重建 flag。

```python
import dns.resolver

flag_bits = ""
flag_len = 40  # 根据预期的 flag 字符长度调整

for i in range(flag_len * 8):
    for bit in ['0', '1']:
        try:
            dns.resolver.resolve(f"{flag_bits}{bit}.target.com", 'A')
            flag_bits += bit
            break
        except dns.resolver.NXDOMAIN:
            continue

# 将二进制字符串转换为 ASCII
flag = ''.join(chr(int(flag_bits[i:i+8], 2)) for i in range(0, len(flag_bits), 8))
print(flag)
```

**关键洞察：** DNS 返回的 NOERROR 与 NXDOMAIN 充当二进制 oracle，每次查询泄露一位信息——适用于任何基于 DNS 的隐蔽信道。每次查询测试候选前缀是否正确，实现 O(n) 复杂度的重建，其中 n 是 flag 的位数。

---

## 利用 ICMP Echo 负载长度作为隐蔽信道（TokyoWesterns CTF 4th 2018）

**模式：** 一个 PCAP 文件包含一系列 ICMP echo-request 包。负载字节看似随机，但每个负载的*长度*是一个可打印的 ASCII 字符——发送方使用 `ping -s <len>` 逐字符传输 flag，绕过任何内容级 IDS。内容检查无异常，只有每个包的长度字段携带数据。

**提取：**
```python
from scapy.all import rdpcap, ICMP

pkts = rdpcap('capture.pcap')
flag = ''.join(
    chr(len(p[ICMP].payload))
    for p in pkts
    if ICMP in p and p[ICMP].type == 8   # echo-request
)
print(flag)
```

**关键洞察：** 发送方能控制的任何元数据字段（包长度、TTL、IPID、TCP窗口大小、DNS QNAME 长度、HTTP 请求顺序）都可能成为隐蔽信道。分析负载内容前，先绘制每包元数据分布图——若直方图仅落在可打印 ASCII 范围内即为明显信号。结合 `tshark -T fields -e icmp.data_len` 可快速从大规模 PCAP 中提取。

**参考：** TokyoWesterns CTF 4th 2018 — writeup 10866

另见：[network-advanced.md](network-advanced.md) 了解高级网络取证技术（包间隔时间编码、USB HID 鼠标/笔迹恢复、NTLMv2 哈希破解、TCP flag 隐蔽信道、DNS 隐写、多层 PCAP XOR、Brotli 解压炸弹缝隙分析、SMB RID 重用、Timeroasting MS-SNTP）。
