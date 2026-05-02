# Web 与 DNS OSINT

## 目录
- [Google Dorking](#google-dorking)
- [OSINT 中的 Google Docs/Sheets](#google-docssheets-in-osint)
- [DNS 侦察](#dns-reconnaissance)
- [DNS TXT 记录 OSINT](#dns-txt-record-osint)
- [Tor 中继查询](#tor-relay-lookups)
- [GitHub 仓库评论](#github-repository-comments)
- [Telegram 机器人调查](#telegram-bot-investigation)
- [FEC 政治捐款研究](#fec-political-donation-research)
- [Wayback Machine](#wayback-machine)
- [WHOIS 调查](#whois-investigation)
- [Shodan SSH 指纹查询 (EKOPARTY CTF 2016)](#shodan-ssh-fingerprint-lookup-ekoparty-ctf-2016)
- [假服务横幅检测（指纹识别）(MetaCTF Flash 2026)](#fake-service-banner-detection-via-fingerprinting-metactf-flash-2026)
- [Git 提交作者挖掘凭据 (Hackover 2018)](#git-commit-author-mining-for-credentials-hackover-2018)
- [.DS_Store 目录枚举与 Python-dsstore (35C3 2018)](#ds_store-directory-enumeration-with-python-dsstore-35c3-2018)
- [TTF 字形轮廓差异比对破解混淆验证码 (Square CTF 2018)](#ttf-glyph-contour-diffing-for-obfuscated-captcha-square-ctf-2018)
- [跨挑战容器 IP 重用 (RITSEC 2018)](#cross-challenge-container-ip-reuse-ritsec-2018)
- [资源](#resources)

---

## Google Dorking

```text
site:example.com filetype:pdf
intitle:"index of" password
inurl:admin
"confidential" filetype:doc
```

**Google 图片 TBS（To Be Searched）参数：**

在 Google 图片搜索 URL 中附加 `&tbs=` 筛选器以进行精确过滤：

| 筛选器 | 参数 | 示例 |
|--------|-----------|---------|
| 仅人脸 | `itp:face` | 查找头像照片 |
| 剪贴画 | `itp:clipart` | Logo、图标 |
| 动态 GIF | `itp:animated` | 动画图片 |
| 特定颜色 | `ic:specific,isc:green` | 主色调筛选 |
| 透明背景 | `ic:trans` | 带透明度的 PNG |
| 大图 | `isz:l` | 仅高分辨率 |
| 最低分辨率 | `isz:lt,islt:2mp` | 大于 200 万像素 |

**组合示例：** 在 LinkedIn 上搜索某公司实习生的人脸照片：
```text
https://www.google.com/search?q="orange"+"alternant"+site:linkedin.com&tbm=isch&tbs=itp:face
```

**关键洞察：** `itp:face` 筛选器对 OSINT 特别有用——它从结果中过滤掉 logo、横幅和 UI 截图，只留下头像照片。结合 `site:` 和日期范围（`after:YYYY-MM-DD`）进行定向侦察。

## Google Docs/Sheets in OSINT

- 嫌疑人可能在推文或帖子中链接到 Google Sheets/Docs
- 尝试公开访问 URL：
  - `/export?format=csv` — 导出为 CSV
  - `/pub` — 发布版本
  - `/gviz/tq?tqx=out:csv` — Visualization API CSV 导出
  - `/htmlview` — HTML 视图
- 私有表格需要认证；flag 可能就在表格中
- Sheet ID 是稳定的标识符，即使共享设置更改

## DNS Reconnaissance

Flag 通常在子域名的 TXT 记录中，而非根域名：
```bash
dig -t txt subdomain.ctf.domain.com
dig -t any domain.com
dig axfr @ns.domain.com domain.com  # 区域传送
```

## DNS TXT Record OSINT

```bash
dig TXT ctf.domain.org
dig TXT _dmarc.domain.org
dig ANY domain.org
```

**教训：** DNS TXT 记录是公开可查询的。务必检查 CTF 域名和子域名的 TXT、CNAME、MX 记录。

## Tor Relay Lookups

```text
https://metrics.torproject.org/rs.html#simple/<FINGERPRINT>
```
检查中继族群成员，按"首次发现"日期排序以获取有序的 flag。

## GitHub Repository Comments

**模式（Rogue, VuwCTF 2025）：** 隐藏在 GitHub 仓库评论中的信息（issue 评论、PR 审查、提交信息、wiki 编辑）。

**检查：** `gh api repos/OWNER/REPO/issues/comments`、`gh api repos/OWNER/REPO/commits`、wiki 编辑历史。

## Telegram Bot Investigation

**模式：** 取证痕迹（浏览器历史、聊天记录）可能引用需要主动交互的 Telegram 机器人。

**在取证中查找机器人引用：**
```python
# 在浏览器历史中搜索 Telegram URL
import sqlite3
conn = sqlite3.connect("History")  # Edge/Chrome 历史数据库
cur = conn.cursor()
cur.execute("SELECT url FROM urls WHERE url LIKE '%t.me/%'")
# 示例：https://t.me/comrade404_bot
```

**机器人交互工作流：**
1. 访问 `https://t.me/<botname>` -> 在 Telegram 中打开
2. 用 `/start` 或机器人自定义命令开始对话
3. 机器人可能需要验证（CTF 风格的挑战）
4. 答案通常需要取证分析的知识

**验证问题模式：**
- "你使用哪个用户账户进行了 X？" -> 检查浏览器历史、登录记录
- "哪个账户被修改了？" -> 检查 Security.evtx Event 4781（重命名）
- "你访问了什么文件？" -> 检查 MRU、最近文件、Shellbags

**示例机器人流程：**
```text
Bot: "TIER 1: 哪个账户用于在线搜索？"
-> 从 Edge 历史中得出答案，显示 Bing/Google 搜索记录

Bot: "TIER 2: 你更改了哪个账户名？"
-> 从安全事件日志中得出答案（账户重命名事件）

Bot: [授予访问权限] "网站：http://x.x.x.x:5000，用户名：mehacker，密码：flaghere"
```

**关键洞察：** 机器人回复可能揭示：
- 攻击者的真实身份/代号
- 次级系统的凭据
- 直接的 flag 组成部分
- 隐藏 Web 服务的链接

## FEC Political Donation Research

**模式（Shell Game）：** 通过 FEC 备案追踪组织捐款者。

**关键资源：**
- [FEC.gov](https://www.fec.gov/data/) — 委员会收支
- 501(c)(4) 组织可以向超级政治行动委员会（Super PAC）捐款而无需披露原始出资者
- 查找最大的组织捐款者，然后研究该组织领导层（CEO/总裁）

## Wayback Machine

```bash
# 查找某网站的所有存档 URL
curl "http://web.archive.org/cdx/search/cdx?url=example.com*&output=json&fl=timestamp,original,statuscode"
```

- 检查已删除的帖子、旧资料页面、缓存页面
- CDX API 用于编程访问存档索引

## WHOIS Investigation

```bash
# 基本 WHOIS 查询
whois example.com

# 需要提取的关键字段：
# - 注册人名称/邮箱/组织（通常被隐私服务遮蔽）
# - 创建/过期日期（时间线关联）
# - 域名服务器（共享主机识别）
# - 注册商（可指示技术水平）

# 历史 WHOIS（隐私保护启用之前的）
# 使用 SecurityTrails、WhoisXML API 或 DomainTools
curl "https://api.securitytrails.com/v1/domain/example.com/whois" \
  -H "APIKEY: YOUR_KEY"

# 反向 WHOIS——查找同一实体注册的所有域名
# 按注册人邮箱、组织名称或电话号码搜索
curl "https://reverse-whois-api.whoisxmlapi.com/api/v2" \
  -d '{"searchType":"current","mode":"purchase","basicSearchTerms":{"include":["target@email.com"]}}'

# IP WHOIS（查找网络所有者）
whois 1.2.3.4
# 关注：NetName、OrgName、CIDR 范围、滥用联系方式

# ASN 查询
whois -h whois.radb.net AS12345
# 或使用 bgp.tools：https://bgp.tools/as/12345
```

**关键洞察：** WHOIS 数据最适用于时间线关联（域名相对于 CTF 事件何时注册？）、反向查询（哪些其他域名共享同一注册人？）以及识别共享基础设施。通过 SecurityTrails 或 Wayback Machine 的历史 WHOIS 可揭示隐私保护前的注册人详细信息。

---

## Shodan SSH Fingerprint Lookup (EKOPARTY CTF 2016)

通过在 Shodan 上搜索服务的 SSH 指纹来发现 Tor 隐藏服务或 CDN 背后的真实 IP。

```bash
# 步骤 1：从目标获取 SSH 指纹
ssh-keyscan -t rsa target.onion 2>/dev/null | ssh-keygen -lf - -E md5
# 或使用专用扫描器：
# pip install ssh-audit
ssh-audit target.onion

# 步骤 2：提取指纹哈希
# 如 MD5:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90

# 步骤 3：在 Shodan 上搜索匹配的指纹
# 通过 API：
import shodan
api = shodan.Shodan('YOUR_API_KEY')
results = api.search('ssh.fingerprint:"ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90"')
for result in results['matches']:
    print(f"IP: {result['ip_str']}")
    print(f"Port: {result['port']}")
    print(f"Banner: {result['data'][:200]}")

# 通过 Shodan CLI：
shodan search 'ssh.fingerprint:"ab:cd:ef:12:34:56:78:90"'

# 通过 Web：https://www.shodan.io/search?query=ssh.fingerprint:%22...%22

# 同样适用于 TLS 证书指纹：
# shodan search 'ssl.cert.fingerprint:"SHA256_HASH"'
```

**关键洞察：** SSH 主机密钥对每台服务器都是唯一的。如果隐藏服务运行 SSH，其指纹可在 Shodan/Censys 上搜索以找到真实 IP。此技术也适用于去匿名化 CloudFlare 或其他 CDN 背后的服务。同时搜索 SSH 指纹和 TLS 证书指纹。

---

## Fake Service Banner Detection via Fingerprinting (MetaCTF Flash 2026)

**模式（O-Syn-T）：** 端口在标准服务端口（如 22/SSH）上显示为开放，但背后的服务并非声称的那样。基本 SYN 扫描报告端口为开放，但服务版本检测揭示包含 flag 的假横幅或自定义横幅。

```bash
# 步骤 1：基本端口扫描发现端口 22 开放
nmap -sS target.ctf
# PORT   STATE SERVICE
# 22/tcp open  ssh

# 步骤 2：服务版本指纹识别揭示欺骗
nmap -sV -sC target.ctf -p 22
# PORT   STATE SERVICE VERSION
# 22/tcp open  ssh?
# |_banner: MetaCTF{fake_banner_flag_here}

# 步骤 3：或直接用 netcat 连接读取横幅
nc target.ctf 22
# MetaCTF{fake_banner_flag_here}

# 替代方案：对 TLS 包装的横幅使用 curl 或 openssl
echo "" | timeout 3 nc -w 3 target.ctf 22
```

**关键洞察：** 永远不要仅凭端口号判断。SYN 扫描只确认端口是开放的，不能确认运行的是什么服务。始终运行 `nmap -sV`（版本检测）或用 `nc` 连接读取实际横幅。CTF 挑战利用了"端口 22 = SSH、端口 80 = HTTP"等假设。标准端口上的自定义横幅服务是常见的 OSINT/网络侦察技巧。

**何时识别：** 挑战名称暗示网络扫描或侦察（"SYN"、"scan"、"port"）。预期方法是枚举开放端口，但 flag 在服务横幅本身中，而非需要利用漏洞。

---

## Git Commit Author Mining for Credentials (Hackover 2018)

**模式：** 挑战提到一个没有凭据的用户名，期望攻击者转向该用户拥有的公开仓库（GitHub/GitLab/Bitbucket）。`git shortlog -sne` 或 `git log --format="%an <%ae>"` 从提交历史中提取每个作者邮箱——该地址通常是目标服务期望的有效登录用户名，在你尝试密码重置或 SQL 注入流程之前。

```bash
# 克隆目标的公开仓库并列出每个贡献者邮箱
git clone https://github.com/<target-user>/<repo>.git
cd repo
git shortlog -sne
# 23  John Doe <[email protected]>
#  5  John Doe <[email protected]>     ← 通常是真实登录邮箱

# 一次提取所有历史作者：
git log --format="%an <%ae>%n%cn <%ce>" | sort -u
```

```bash
# GitHub 全局枚举——列出用户的每个事件
gh api "users/<target-user>/events/public" --paginate \
   | jq -r '.[] | .payload.commits[]?.author.email' | sort -u
```

**关键洞察：** Git 仓库是每个作者、提交者和联合作者的签名审计日志。即使有人更换了邮箱，历史记录仍保留旧地址。同时挖掘 `author.email` 和 `committer.email`，也查看 `.mailmap`、`CONTRIBUTORS` 和 GPG 签名的提交（`git log --show-signature`）。将每个恢复的邮箱视为目标服务的候选登录——许多 CTF Web 靶机、HR 门户和密码重置流程直接接受来自公开仓库的作者邮箱。

**参考：** Hackover CTF 2018 — who knows john dows?, writeups 11537, 11646

---

## .DS_Store Directory Enumeration with Python-dsstore (35C3 2018)

**模式：** macOS `.DS_Store` 文件会泄露目录列表，即使 Web 服务器通过 `robots.txt` 或混淆路径隐藏了它们。尽可能下载 `.DS_Store`（根目录、`/uploads/`、`/static/`）并解析以枚举原本无法猜测的文件名。

```bash
curl -sO https://target/.DS_Store
python3 -m dsstore .DS_Store
# 打印 Finder 在该目录中曾看到的每个文件
```

**关键洞察：** `.DS_Store` 由 macOS 自动生成，经常被意外推送到生产环境。它暴露的是文件名而非内容，但这足以找到隐藏的管理面板、备份文件和上传的 flag。

**参考：** 35C3 CTF 2018 — McDonald, writeup 12763

---

## TTF Glyph Contour Diffing for Obfuscated CAPTCHA (Square CTF 2018)

**模式：** 验证码通过将字形 ID 重映射到随机 `cmap` 条目来提供混淆字符，因此浏览器仍显示"5"，但底层 Unicode 码点是 `U+E042`。提取 TTF，用 `ttx` 导出每个字形的轮廓，构建已知数字/字母轮廓的参考库，然后将传入字形与参考库进行 `diff` 以恢复真实字符。

```bash
ttx -t glyf -g -d glyph_out font.ttf
# glyph_out/font.glyf/<glyph_name>.ttx 包含轮廓 XML
diff glyph_out/font.glyf/zero.ttx reference/zero.ttx
```

**关键洞察：** 依赖自定义字体的视觉验证码很容易被破解，因为字形*形状*在 cmap 重映射下是不变的。从任何标准字体构建一次参考库，然后在每个挑战变体中重复使用。

**参考：** Square CTF 2018 — C8, writeup 12161

---

## Cross-Challenge Container IP Reuse (RITSEC 2018)

**模式：** 在 Docker 托管的 CTF 基础设施中，同一子网中的所有挑战通常共享内部 IP 范围。从一个挑战中泄露容器的 `REMOTE_ADDR` 或路由表（通常通过命令注入或 SSRF），然后将泄露的 IP 应用到任何其他基于 `REMOTE_ADDR` 哈希、`X-Forwarded-For` 检查或 MD5(IP) 路径的挑战中。

```text
# 挑战 A 泄露 REMOTE_ADDR = 10.0.10.254
# 挑战 B 期望上传到 /uploads/md5(10.0.10.254)/md5(time()).ext
```

**关键洞察：** 多挑战 CTF 通常会跨挑战泄露基础设施细节。始终先映射共享子网，然后将信息从最弱的挑战转用到最受限的挑战。

**参考：** RITSEC CTF 2018 — Lazy Dev → Archivr, writeups 12234-12235

---

## Resources

- **Shodan** — 互联网连接设备搜索
- **Censys** — 证书和主机搜索
- **VirusTotal** — 文件/URL 信誉查询
- **WHOIS** — 域名注册信息
- **Wayback Machine** — 历史快照
