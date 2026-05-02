# CTF Forensics - Network (Advanced)

对于 USB/HID/蓝牙外设捕获分析（鼠标/笔迹恢复，键盘扫描码，LED 摩尔斯码外泄，RFCOMM 重组），请参见 [peripheral-capture.md](peripheral-capture.md)。基础网络取证请参见 [network.md](network.md)。

## 目录
- [基于数据包间隔时间的编码 (EHAX 2026)](#packet-interval-timing-based-encoding-ehax-2026)
- [从 PCAP 破解 NTLMv2 哈希 (Pragyan 2026)](#ntlmv2-hash-cracking-from-pcap-pragyan-2026)
- [TCP 标志隐蔽信道 (BearCatCTF 2026)](#tcp-flag-covert-channel-bearcatctf-2026)
- [DNS 查询名最后字节隐写 (UTCTF 2026)](#dns-query-name-last-byte-steganography-utctf-2026)
  - [DNS 尾部字节二进制编码 (UTCTF 2026)](#dns-trailing-byte-binary-encoding-utctf-2026)
- [多层 PCAP XOR + ZIP (UTCTF 2026)](#multi-layer-pcap-with-xor--zip-utctf-2026)
- [Brotli 解压炸弹缝隙分析 (BearCatCTF 2026)](#brotli-decompression-bomb-seam-analysis-bearcatctf-2026)
- [通过 LSARPC 回收 SMB RID (Midnight 2026)](#smb-rid-recycling-via-lsarpc-midnight-2026)
- [Timeroasting / MS-SNTP 哈希提取 (Midnight 2026)](#timeroasting--ms-sntp-hash-extraction-midnight-2026)
- [带字节旋转的 ICMP 负载隐写 (HackIM 2016)](#icmp-payload-steganography-with-byte-rotation-hackim-2016)
- [通过校验和验证重组数据包 (Break In 2016)](#packet-reconstruction-via-checksum-validation-break-in-2016)
- [从 DNS PCAP 重组 dnscat2 流量 (BSidesSF 2017)](#dnscat2-traffic-reassembly-from-dns-pcap-bsidessf-2017)
- [未引用的 PDF 对象与隐藏页面 (SharifCTF 7 2016)](#unreferenced-pdf-objects-with-hidden-pages-sharifctf-7-2016)
- [通过提取的 PKCS12 密钥解密 RDP 会话 (HITB 2017)](#rdp-session-decryption-via-extracted-pkcs12-key-hitb-2017)
- [RADIUS 共享密钥破解 (UConn CyberSEED 2017)](#radius-shared-secret-cracking-uconn-cyberseed-2017)
- [Shellcode PCAP 中的 RC4 流识别 (CODE BLUE 2017)](#rc4-stream-identification-in-shellcode-pcap-code-blue-2017)
- [ICMP Ping 时间延迟隐蔽信道 (DefCamp 2018)](#icmp-ping-time-delay-covert-channel-defcamp-2018)

---

## 基于数据包间隔时间的编码 (EHAX 2026)

**模式（Breathing Void）：** 大型 PCAPNG 文件包含数百万数据包，但只有一个接口上的几百个数据包携带数据。信号隐藏在**相同数据包之间的时间间隔**中，而非内容。

**识别方法：** 题目提及“breathing”、“void”、“silence”或时间。PCAP 有多个接口，但只有一个接口有有趣流量。数据包内容相同，但间隔时间有两种不同值。

**解码流程：**
```python
from scapy.all import rdpcap

packets = rdpcap('challenge.pcapng')

# 1. 过滤到正确接口（例如接口 2）
# tshark: tshark -r challenge.pcapng -Y "frame.interface_id == 2" -T fields -e frame.time_epoch

# 2. 计算数据包间隔时间
times = [float(pkt.time) for pkt in packets if pkt.sniffed_on == 'interface_2']
intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

# 3. 识别二进制映射（两种不同间隔值）
# 例如，10ms → 0，100ms → 1（阈值约 50ms）
threshold = 0.05  # 50ms
bits = [0 if dt < threshold else 1 for dt in intervals]

# 4. 可能需要在开头补一个 0 位（第一个间隔无前驱）
bits = [0] + bits

# 5. 按 MSB 优先将比特转换为字节
data = bytes(int(''.join(str(b) for b in bits[i:i+8]), 2)
             for i in range(0, len(bits) - 7, 8))
print(data.decode(errors='replace'))
```

**关键洞察：** 当相同数据包在单一接口上出现且只有两种实际间隔值时，几乎可以确定是通过时间间隔进行的二进制编码。内容是噪声，信号在间隔。先按接口过滤，再统计唯一间隔。

**规模提示：** 大型 PCAP（数百万包）中信号通常只在极小子集。用 `tshark -q -z io,phs` 进行初步筛选，找出数据包最少的接口——很可能是数据载体。

---

## 从 PCAP 破解 NTLMv2 哈希 (Pragyan 2026)

**模式（$whoami）：** PCAP 中的 SMB2 认证。

**提取：** 从 NTLMSSP_AUTH 包中提取：服务器挑战（server challenge）、NTProofStr 和 blob。

**已知密码格式的暴力破解：**
```python
import hashlib, hmac
from Crypto.Hash import MD4

def try_password(password, username, domain, server_challenge, blob, expected_proof):
    nt_hash = MD4.new(password.encode('utf-16-le')).digest()
    identity = (username.upper() + domain).encode('utf-16-le')
    ntlmv2_hash = hmac.new(nt_hash, identity, hashlib.md5).digest()
    proof = hmac.new(ntlmv2_hash, server_challenge + blob, hashlib.md5).digest()
    return proof == expected_proof
```

---

## TCP 标志隐蔽信道 (BearCatCTF 2026)

**模式（pCapsized）：** 可疑 TCP 包带有混乱的标志组合（FIN+SYN，SYN+RST+PSH+URG 等）。6 个 TCP 标志位编码 base64 字符。

**解码：**
```python
from scapy.all import rdpcap, TCP

pkts = rdpcap('capture.pcap')
suspicious = [p for p in pkts if TCP in p and p[TCP].dport == 5748]

# 将 6 位标志值映射到 base64 字母表
b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
encoded = ''.join(b64[p[TCP].flags & 0x3F] for p in suspicious)

import base64
flag = base64.b64decode(encoded).decode()
```

**关键洞察：** TCP 有 6 个标准标志位（FIN、SYN、RST、PSH、ACK、URG），值范围 0-63，正好对应 base64 字母表。正常包中出现异常标志组合表明隐蔽信道。通过目标端口或源 IP 过滤以隔离信道。

**检测：** 标志组合无意义（如同时有 FIN+SYN），目标端口固定，数据包数为 4 的倍数（base64 对齐）。

---

## DNS 查询名最后字节隐写 (UTCTF 2026)

**模式（Last Byte Standing）：** PCAP 中 DNS 查询，数据编码在每个查询名的最后一个字节。

**识别：** 许多 DNS 查询指向异常或连续子域名。有效数据不在查询名本身，而在每个查询名的最后一个字节/字符。

**解码流程：**
```python
from scapy.all import rdpcap, DNS, DNSQR

packets = rdpcap('last-byte-standing.pcap')

data = []
for pkt in packets:
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode(errors='replace').rstrip('.')
        if qname:
            data.append(qname[-1])  # 查询名最后一个字符

# 从最后字节重建消息
message = ''.join(data)
print(message)
# 可能需要额外解码（十六进制、base64 等）
```

**变体：**
- 每个子域标签的最后一个字节（以 `.` 分割）
- 特定字符位置（首字符、第 N 个、最后一个）
- 多个查询中的十六进制编码字节
- 子域标签作为 base32/base64 块（DNS 隧道）
- **DNS 查询结构后的尾部字节**（见下文）

**关键洞察：** DNS 外泄常隐藏数据于查询名。当查询看似随机但有规律时，提取特定字符位置。“最后字节”模式简单有效——每个查询贡献一个字节。

**检测：** 大量 DNS 查询指向单一域名，无合法用途，子域名连续或有模式。
### DNS 尾随字节二进制编码 (UTCTF 2026)

**模式（Last Byte Standing 变体）：** 每个 DNS 查询包在标准 DNS 问题结构之后（null 终止符 + Type A + Class IN 字段之后）附加一个额外字节。该额外字节为 `0x30`（'0'）或 `0x31`（'1'），每个包编码一位。

**解码流程：**
```python
from scapy.all import rdpcap, DNS, DNSQR, Raw

packets = rdpcap('challenge.pcap')

bits = []
for pkt in packets:
    if pkt.haslayer(DNSQR):
        # 获取原始 DNS 负载
        raw = bytes(pkt[DNS])
        # 标准 DNS 问题结束位置：header(12) + qname + null(1) + type(2) + class(2)
        qname = pkt[DNSQR].qname
        expected_len = 12 + len(qname) + 1 + 2 + 2  # +1 为前导长度字节
        if len(raw) > expected_len:
            trailing = raw[expected_len:]
            for b in trailing:
                bits.append(chr(b))  # '0' 或 '1'

# 将比特串转换为 ASCII（MSB 优先，8 位一组）
bitstring = ''.join(bits)
flag = ''.join(chr(int(bitstring[i:i+8], 2)) for i in range(0, len(bitstring) - 7, 8))
print(flag)
```

**关键洞察：** 数据隐藏在 DNS 查询名之外，位于问题记录之后的额外填充字节中。Wireshark 十六进制检查显示非标准包长度。每个尾随字节代表 ASCII '0' 或 '1'，组成二进制流解码出 flag。

**检测方法：** DNS 包大小略大于其查询名所需长度。十六进制转储显示 Class IN 字段（`00 01`）后有 `0x30`/`0x31` 字节。所有包的查询域名一致。

---

## 多层 PCAP 与 XOR + ZIP (UTCTF 2026)

**模式（Half Awake）：** PCAP 包含多协议层隐藏数据。需要协议感知提取、使用内嵌密钥进行 XOR 解密，并合并并行数据流。

**详细流程：**

1. **检查 HTTP 流** 寻找指令或提示（如“mDNS 名称是提示”，“不是每个 TCP 数据块都是它看起来的样子”）
2. **识别伪协议流：** 一个标记为 TLS 的 TCP 流实际上可能包含原始 ZIP 文件（PK 魔数 `50 4b`）。检查可疑流的原始十六进制
3. **从 mDNS 提取 XOR 密钥：** 查找 mDNS TXT 记录（如 `key.version.local`）包含 XOR 密钥
4. **使用 mDNS 密钥进行 XOR 解密** 提取的数据
5. **合并并行数据集**，使用可打印性作为选择器

```python
import string
from scapy.all import rdpcap, Raw, DNS, DNSRR

packets = rdpcap('half-awake.pcap')

# 1. 从 mDNS TXT 记录提取 XOR 密钥
xor_key = None
for pkt in packets:
    if pkt.haslayer(DNSRR):
        rr = pkt[DNSRR]
        if b'key' in rr.rrname.lower():
            xor_key = int(rr.rdata, 16)  # 例如 0xb7

# 2. 提取伪 TLS 流（在原始 TCP 数据中查找 PK 头）
# 使用 Wireshark: tcp.stream eq N → 导出原始字节
# 或用 scapy 过滤正确流提取

# 3. 对 ZIP 内容的两个数据集进行 XOR 解密
def xor_decrypt(data, key):
    return bytes(b ^ key for b in data)

p1 = xor_decrypt(stage1_data, xor_key)
p2 = xor_decrypt(stage2_data, xor_key)

# 4. 使用可打印性合并：每个位置取可打印字符
flag = ''.join(
    chr(p1[i]) if chr(p1[i]) in string.printable and chr(p1[i]).isprintable()
    else chr(p2[i])
    for i in range(len(p1))
)
print(flag)
```

**关键洞察：** 当 PCAP 包含两个 XOR 解码后长度相等的字节数组，单独均无法产生可读文本时，逐字符合并，选择可打印 ASCII 字符。XOR 密钥通常隐藏在内嵌协议如 mDNS TXT 记录中，无需暴力破解。

**指示器：**
- HTTP 流带有元指令（“不是每个 TCP 数据块都是它看起来的样子”）
- TCP 流协议解析不匹配（Wireshark 显示 TLS，但原始字节含 PK/ZIP 头）
- mDNS 查询可疑服务名（如 `key.version.local`）
- 提取归档中两个长度相同的数据文件

---

## Brotli 解压炸弹接缝分析 (BearCatCTF 2026)

**模式（Cursed Map）：** HTTP 下载文件，解压后为数 GB（解压炸弹）。flag 位于压缩数据中两个炸弹半块的接缝处。

**识别方法：** 压缩数据呈现重复块模式（如 105 字节周期）。某块打破模式——flag 位于该不连续处。

```python
import brotli

with open('flag.txt.br', 'rb') as f:
    data = f.read()

# 找出重复块大小
block_size = 105  # 通过比较相邻块确定
for i in range(0, len(data) - block_size, block_size):
    if data[i:i+block_size] != data[i+block_size:i+2*block_size]:
        seam_offset = i + block_size
        break

# 仅解压异常块
dec = brotli.Decompressor()
result = dec.process(data[seam_offset:seam_offset+block_size])
# flag 在解压输出中
```

**关键洞察：** 解压炸弹使用高度重复的压缩数据。flag 打破重复，形成可检测异常。比较相邻固定大小块找出不连续处，再仅解压该区域，无需解压整个多 GB 输出。

**检测方法：** 文件极高压缩比（MB → GB），HTTP Content-Encoding: br，或文件被识别为 Brotli。尝试解压时工具卡死或内存溢出。

---

## 通过 LSARPC 的 SMB RID 循环 (Midnight 2026)

**模式（UntilTime）：** PCAP 包含 SMB2 认证，随后通过 `\pipe\lsarpc` 进行 RPC 调用。攻击者通过迭代 RID（相对标识符）调用 LSARPC 函数枚举 Active Directory 账户。

**识别方法：** SMB2 会话建立伴随多次认证尝试（空会话、Guest、随机用户名），随后 RPC 绑定到 LSARPC 并重复调用带递增 RID 的 `LsaLookupSids`。

**Wireshark 分析：**
```bash
# 过滤攻击者 IP 的 SMB2 认证尝试
tshark -r capture.pcapng -Y "ip.src == 198.51.100.16 && smb2.cmd == 1"

# 查找 LSARPC RPC 调用
tshark -r capture.pcapng -Y "dcerpc.cn_bind_to_str contains lsarpc"
```

**RPC 调用序列：**
1. `LsaOpenPolicy` — 打开目标策略句柄
2. `LsaQueryInformationPolicy` — 提取域 SID（如 `S-1-5-21-...`）
3. `LsaLookupSids` — 通过迭代 RID（1000、1001、1002、...）解析 SID 到账户名

**关键洞察：** Guest 账户认证（通常默认启用）允许通过 LSARPC 枚举域账户。攻击者通过将递增 RID 附加到域 SID 构造 SID，调用 `LsaLookupSids`。有效账户返回名称，无效 RID 返回错误。此技术称为 **RID 循环** 或 **RID 暴力破解**。

**检测指标：**
- 多个带顺序 RID 的 `LsaLookupSids` 请求
- Guest 认证成功后连接 RPC 管道
- 单一来源大量 LSARPC 流量

---
## Timeroasting / MS-SNTP Hash Extraction (Midnight 2026)

**模式（UntilTime）：** 通过 RID 回收枚举有效的机器账户 RID 后，攻击者向这些 RID 发送 NTP 请求，从域控制器的 MS-SNTP 响应中提取 HMAC-MD5 认证材料。

**背景：** Microsoft 的 MS-SNTP 在 Active Directory 环境中扩展了标准 NTP，加入了 Netlogon 认证。客户端在 NTP 的 `Key Identifier` 字段（4 字节，小端序）中放置域 RID。域控制器响应一个基于机器账户 NTLM 哈希派生的 HMAC-MD5 签名——泄露了可破解的认证材料。

**Wireshark 提取：**
```bash
# 过滤来自攻击者的 NTP 流量
tshark -r capture.pcapng -Y "ntp && ip.src == 10.16.13.13" -T fields -e udp.payload
```

**将 Key Identifier 转换为 RID：**
```bash
# NTP Key Identifier 是 4 字节，小端序
echo "<key_id_hex>" | sed 's/\(..\)/\1 /g' | awk '{print "0x"$4$3$2$1}' | xargs printf "%d\n"
```

**NTP 响应负载结构（68 字节）：**

| 偏移 | 长度 | 字段 |
|--------|--------|-------|
| 0-47 | 48 | Salt（NTP 头 + 扩展） |
| 48-51 | 4 | Key Identifier（RID，小端序） |
| 52-67 | 16 | HMAC-MD5 加密校验和 |

**Hashcat 哈希重构（模式 31300）：**
```python
import sys
from struct import unpack

def to_hashcat_form(hex_payload):
    data = bytes.fromhex(hex_payload.strip())
    salt = data[:48]
    rid = unpack('<I', data[-20:-16])[0]
    md5hash = data[-16:]
    return f"{rid}:$sntp-ms${md5hash.hex()}${salt.hex()}"

if len(sys.argv) != 2:
    print("Usage: python sntp_to_hashcat.py <hex_payload>")
    sys.exit(1)

print(to_hashcat_form(sys.argv[1]))
```

**使用 Hashcat 破解：**
```bash
# 模式 31300 = MS-SNTP (Timeroasting)
hashcat -m 31300 -a 0 -O hashes.txt rockyou.txt --username
```

**示例哈希格式：**
```text
1108:$sntp-ms$d7d0422d66705c6189c1d20aed76baa4$1c0111e900000000000a09314c4f434ced4c979d652b89f1e1b8428bffbfcd0aed4ca3bbb1338716ed4ca3bbb133cf3a
```

**关键洞察：** 域控制器的 MS-SNTP 响应泄露了与机器账户 NTLM 哈希相关的 HMAC-MD5 认证材料。与针对服务账户的 Kerberoasting 不同，Timeroasting 针对的是密码通常较弱或可预测（如小写主机名）的**机器账户**。任何有效的 RID 都会触发响应——只需对 DC 的 NTP 服务（UDP 123）有网络访问权限，无需特殊权限。

**完整攻击链：**
1. 以 Guest 身份认证 SMB
2. 通过 LSARPC RID 回收枚举有效 RID
3. 使用发现的 RID 发送 MS-SNTP 请求
4. 从 NTP 响应中提取 HMAC-MD5 哈希
5. 使用 Hashcat 模式 31300 离线破解

---

## ICMP Payload Steganography with Byte Rotation (HackIM 2016)

数据隐藏在 ICMP 回显请求/响应负载中，采用字节级旋转编码：

```python
from scapy.all import rdpcap, ICMP

packets = rdpcap('challenge.pcap')
icmp_data = b''
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # 回显请求
        icmp_data += bytes(pkt[ICMP].payload)

# 应用字节旋转（字节的凯撒密码）
SHIFT = 42
decoded = bytes((b - SHIFT) % 256 for b in icmp_data)

# 结果可能是 base64 编码
import base64
plaintext = base64.b64decode(decoded)
```

**关键洞察：** 分析者通常忽略 ICMP 负载，专注于 TCP/UDP。检查 ICMP 包中非标准负载大小或非零数据。常见编码层次：字节旋转 -> base64 -> shell 命令。

---

## Packet Reconstruction via Checksum Validation (Break In 2016)

通过协议校验和验证重构损坏/不完整的数据包：

1. **从包结构分析中识别缺失字节**（以太网、IP、TCP 头）
2. **暴力破解缺失值**，并验证：
   - IP 头校验和（16 位反码和）
   - TCP 校验和（包含伪头部）
3. **从重构的负载中提取数据**

```python
import struct

def ip_checksum(header_bytes):
    """计算 IP 头校验和"""
    words = struct.unpack('!' + 'H' * (len(header_bytes) // 2), header_bytes)
    s = sum(words)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

# 暴力破解缺失字节以匹配预期校验和
for candidate in range(256):
    header = header_template[:missing_offset] + bytes([candidate]) + header_template[missing_offset+1:]
    if ip_checksum(header) == 0:  # 有效校验和为 0
        print(f"缺失字节: 0x{candidate:02x}")
```

**关键洞察：** 协议校验和限制缺失数据。单字节缺失时暴力破解瞬间完成。多字节缺失时，利用 TCP 序列号和 MAC/IP 头结构缩小搜索空间。

---

## dnscat2 Traffic Reassembly from DNS PCAP (BSidesSF 2017)

**模式（dnscap）：** 从 DNS pcap 中提取通过 dnscat2 隧道传输的数据。解码 DNS 查询中的 base32 子域标签，剥离每个数据块的 9 字节 dnscat2 协议头，通过比较连续查询去重重传包，然后重组负载（如 PNG 图片）。

```python
from scapy.all import rdpcap, DNSQR

packets = rdpcap('capture.pcap')
domain = '.skullseclabs.org.'
prev = None
data = b''

for p in packets:
    if not p.haslayer(DNSQR):
        continue
    qname = p[DNSQR].qname.decode()
    if domain not in qname:
        continue
    # 去除域名，连接十六进制编码标签
    labels = qname.replace(domain, '').split('.')
    chunk = bytes.fromhex(''.join(labels))
    chunk = chunk[9:]  # 去除 9 字节 dnscat2 头
    if chunk == prev:
        continue  # 跳过重传
    prev = chunk
    data += chunk

with open('extracted.png', 'wb') as f:
    f.write(data)
```

**关键洞察：** dnscat2 在 DNS 查询子域标签中编码数据（十六进制或 base32）。每个查询携带 9 字节头（会话 ID、序列号、确认号）。重传常见——通过比较连续负载去重。重组流可能包含可通过魔数识别的文件（PNG、文档）。

---
## Unreferenced PDF Objects with Hidden Pages (SharifCTF 7 2016)

**模式（奇怪的 PDF）：** 一个 PDF 包含未被页面树引用的对象。要揭示隐藏内容：（1）使用 `qpdf --show-xref` 或文本编辑器检查原始 PDF 对象，（2）识别未被引用的内容流对象，（3）修改 Pages 对象中的 `/Kids` 数组以包含隐藏页面引用，（4）增加 `/Count` 值，（5）重新渲染 PDF 以显示之前隐藏的包含 flag 数据的页面。

```bash
# 列出 PDF 中的所有对象
qpdf --show-xref suspicious.pdf

# 查找页面对象和隐藏内容对象
strings suspicious.pdf | grep -E '/Type /Page|/Contents|/Kids'

# 手动修复：编辑 PDF 添加隐藏页面引用
# 修改：/Kids [1 0 R]  ->  /Kids [1 0 R 5 0 R]
# 修改：/Count 1  ->  /Count 2
# 重写 xref 表或使用 qpdf --linearize 修正偏移
qpdf --linearize modified.pdf fixed.pdf
```

**关键洞察：** PDF 查看器只渲染从 `/Pages` 树根可达的页面。未被引用的对象在文件中不可见但仍存在。检查对象交叉引用：任何不在 `/Kids` 中的内容流对象可能包含隐藏数据。`mutool clean -d` 和 `qpdf --show-object N` 有助于检查单个对象。

---

## RDP Session Decryption via Extracted PKCS12 Key (HITB 2017)

PCAP 包含通过 UDP 传输的 PKCS12（.p12/.pfx）文件。从 PKCS12 容器中提取私钥，然后加载到 Wireshark 中以解密 RDP 会话并恢复传输数据。

```bash
# 从 PKCS12 中提取私钥（无证书，无密码保护）
openssl pkcs12 -in cert.p12 -out key.pem -nocerts -nodes

# 在 Wireshark 中：编辑 > 首选项 > 协议 > TLS > RSA 密钥列表
# 添加条目：IP=<rdp_server_ip>, 端口=3389, 协议=tpkt, 密钥文件=key.pem
```

**关键洞察：** 网络抓包中的 PKCS12 文件提供了解密 Wireshark 中加密 RDP 会话所需的私钥。查找 RDP 会话开始前的 .p12/.pfx 文件传输（通常在 UDP 或 FTP 流中）。

---

## RADIUS Shared Secret Cracking (UConn CyberSEED 2017)

使用 `radius2john.pl` 从 PCAP 中提取 RADIUS 认证哈希，使用 john 破解共享密钥，然后在 Wireshark 中输入破解的密钥以解密混淆的密码字段。

```bash
# 提取 john 用的哈希
perl radius2john.pl capture.pcap > radius_hash.txt
john radius_hash.txt --wordlist=rockyou.txt

# Wireshark：编辑 > 首选项 > 协议 > RADIUS > 共享密钥 = <cracked_secret>
# RADIUS Access-Request 包现在将显示解密的 User-Password 字段
```

`radius2john.pl` 是 JohnTheRipper jumbo 包的一部分（`src/radius2john.pl`）。

**关键洞察：** RADIUS 使用 MD5(shared_secret + authenticator + password) 进行密码混淆——通过 john 破解共享密钥可以暴露抓包中的所有凭据。共享密钥通常是一个简短的字典单词。

---

## RC4 Stream Identification in Shellcode PCAP (CODE BLUE 2017)

一个后门发送 32 字节的 `/dev/urandom` 作为 RC4 密钥，然后加密所有后续流量。通过 shellcode 中可见的特征性 256 字节 KSA（密钥调度算法）表初始化模式识别 RC4。从 TCP 流的前 32 字节提取密钥并解密剩余数据。

```python
from scapy.all import rdpcap, TCP

packets = rdpcap('capture.pcap')
stream = b''
for pkt in packets:
    if TCP in pkt and pkt[TCP].payload:
        stream += bytes(pkt[TCP].payload)

# 前 32 字节 = RC4 密钥（来自 /dev/urandom）
key = stream[:32]
ciphertext = stream[32:]

# RC4 解密
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

plaintext = rc4(key, ciphertext)
```

**关键洞察：** shellcode 中的 RC4 可通过 256 字节置换表初始化循环（KSA）识别。密钥通常是连接开始时传输的前 N 字节，随后是加密数据。寻找固定长度的初始数据块，后面跟随加密流量。

---

参见：[network.md](network.md) 了解基础网络取证技术（tcpdump、TLS/SSL 解密、Wireshark、端口扫描、SMB3 解密、凭据提取、5G 协议）。

---

## ICMP Ping Time-Delay Covert Channel (DefCamp 2018)

**模式：** 攻击者通过调制服务器响应时间，在 ICMP 回显应答中外泄数据。延迟小于 200 ms 编码为“忽略”（填充帧），200–1000 ms 编码二进制 `0`，大于 1000 ms 编码二进制 `1`。通过配对每个请求与其回复（匹配 `icmp.ident`/`icmp.seq`）并将时间差转换为比特重构数据。

```python
from scapy.all import rdpcap, ICMP
pkts = rdpcap("broken_tv.pcap")
pairs = {}
for p in pkts:
    if ICMP in p and p[ICMP].type == 8:          # 回显请求
        pairs[p[ICMP].seq] = p.time
bits = []
for p in pkts:
    if ICMP in p and p[ICMP].type == 0:          # 回显应答
        dt = p.time - pairs[p[ICMP].seq]
        if dt < 0.2:                             # <200 ms：填充
            continue
        bits.append("1" if dt > 1.0 else "0")
data = int("".join(bits), 2).to_bytes(len(bits)//8, "big")
print(data)
```

**关键洞察：** ICMP 定时隐蔽信道将连续的延迟分布划分为离散区间。两个阈值比具体数值更重要：任何双峰“快与慢”分布夹杂“填充”区域都允许接收方自同步。通过绘制所有 ICMP 对的 `reply_time - request_time` 直方图检测此信道——正常流量呈单峰高斯分布，隐蔽流量显示明显多峰。

**参考：** DefCamp CTF Qualification 2018 — Broken TV，writeup 11415
