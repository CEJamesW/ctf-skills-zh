---
name: ctf-osint
description: 提供用于 CTF 挑战的开源情报（OSINT）技术。适用于从公共来源、社交媒体、地理定位、DNS 记录、用户名枚举、反向图像搜索、Google Dorking、Wayback Machine、Tor 中继、FEC 备案查询，或识别哈希值和坐标等未知数据。
license: MIT
compatibility: 需要基于文件系统的代理（Claude Code 或类似），以及 bash、Python 3 和互联网访问以进行 OSINT 查询。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF OSINT（开源情报）

CTF OSINT 挑战快速参考。每种技术在此提供一行摘要；完整细节请参阅辅助文件。

## 前置条件

**Python 包（全平台）：**
```bash
pip install shodan Pillow
```

**Linux (apt)：**
```bash
apt install whois dnsutils nmap libimage-exiftool-perl imagemagick curl
```

**macOS (Homebrew)：**
```bash
brew install whois bind nmap exiftool imagemagick curl
```

## 附加资源

- [social-media.md](social-media.md) — Twitter/X（用户 ID、Snowflake 时间戳、Nitter、memory.lol、Wayback CDX）、Tumblr（博客检查、帖子 JSON、头像）、BlueSky 搜索 + API、Unicode 同形字隐写术、Discord API、用户名 OSINT（namechk、whatsmyname、Osint Industries）、用户名元数据挖掘（邮政编码）、平台误报、多平台链条、Strava 健身路线 OSINT
- [geolocation-and-media.md](geolocation-and-media.md) — 图像分析、反向图像搜索（含百度用于中国定位）、Google Lens 裁剪区域搜索、反射/镜像文字阅读、地理定位技术（铁路标志、基础设施地图、MGRS）、Google Plus Codes、EXIF/元数据、硬件识别、报纸档案、IP 地理定位、Google Street View 全景匹配、What3Words 微地标匹配、Google Maps 众包照片验证、Overpass Turbo 空间查询、音乐主题地标地理定位与琴键编码
- [web-and-dns.md](web-and-dns.md) — Google Dorking（含 TBS 图片筛选器）、Google Docs/Sheets 枚举、DNS 侦察（TXT、区域传送）、Wayback Machine、FEC 研究、Tor 中继查询、GitHub 仓库分析、Telegram 机器人调查、WHOIS 调查（反向 WHOIS、历史 WHOIS、IP/ASN 查询）、假服务横幅检测（nmap 指纹识别）

---

## 何时切换

- 如果你已在本地拥有文件或数据包，需要提取或雕刻数据，请切换到 `/ctf-forensics`。
- 如果任务变为对实时 HTTP 服务的主动利用，请切换到 `/ctf-web`。
- 如果在溯源过程中发现恶意软件样本、信标或可疑二进制文件，请切换到 `/ctf-malware`。

## 快速入门命令

```bash
# DNS 侦察
dig -t any target.com
dig -t txt target.com
dig axfr @ns.target.com target.com
whois target.com

# 图像元数据
exiftool image.jpg
identify -verbose image.jpg | head -30

# Web 存档
curl "https://web.archive.org/web/20230101*/target.com"

# 用户名查询
curl -s "https://whatsmyname.app/api/lookup?username=<user>"

# Shodan
shodan search "hostname:target.com"
shodan host <ip>
```

## 字符串识别

- 40 位十六进制字符 -> SHA-1（Tor 指纹）
- 64 位十六进制字符 -> SHA-256
- 32 位十六进制字符 -> MD5

## Twitter/X 账户追踪

- 持久数字用户 ID：`https://x.com/i/user/<id>` 即使改名后仍有效。
- Snowflake 时间戳：`(id >> 22) + 1288834974657` = Unix 毫秒。
- 使用 Wayback CDX、Nitter、memory.lol 获取历史数据。参见 [social-media.md](social-media.md)。

## Tumblr 调查

- 博客检查：`curl -sI` 查看 `x-tumblr-user` 头。头像地址：`/avatar/512`。参见 [social-media.md](social-media.md)。

## 用户名 OSINT

- [whatsmyname.app](https://whatsmyname.app)（741+ 个站点）、[namechk.com](https://namechk.com)。注意平台误报。参见 [social-media.md](social-media.md)。

## 图像分析与反向图像搜索

- Google Lens（裁剪至感兴趣区域，最适合识别地标/店铺/标志）、Google Images、TinEye、Yandex（人脸）。检查图片角落是否有视觉隐写。Twitter 会剥离 EXIF。参见 [geolocation-and-media.md](geolocation-and-media.md)。
- **裁剪区域搜索：** 隔离独特元素（店铺标志、建筑立面），通过 Google Lens 搜索比全场景搜索效果更好。参见 [geolocation-and-media.md](geolocation-and-media.md)。
- **反射文字：** 将镜像/反射文字（水面、玻璃）水平翻转；使用引号搜索部分文本。参见 [geolocation-and-media.md](geolocation-and-media.md)。

## 地理定位

- 铁路道口标志、基础设施地图（OpenRailwayMap、OpenInfraMap）、排除法。参见 [geolocation-and-media.md](geolocation-and-media.md)。
- **Street View 全景匹配：** 特征提取 + 多指标图像相似度排序，与候选全景对比。当挑战图像是 Street View 照片的裁剪时非常有用。参见 [geolocation-and-media.md](geolocation-and-media.md)。
- **路标 OCR：** 从方向标志中提取文本（城镇名称、路线编号）以精确定位道路走廊。行车方向 + 标志样式 + 文字体系可识别国家。参见 [geolocation-and-media.md](geolocation-and-media.md)。
- **建筑 + 品牌识别：** 后苏联式混凝土建筑 = 俄罗斯/独联体；有名称的商家 → 搜索地点/分店 → 与海岸线/地形交叉验证。参见 [geolocation-and-media.md](geolocation-and-media.md)。
- **音乐主题地标地理定位：** 全球多个音乐相关地标图片；每个地标产生一个钢琴键编号，编码一个 flag 字符。先识别所有地点，再解码键序列。参见 [geolocation-and-media.md](geolocation-and-media.md)。

## MGRS 坐标

- 网格格式 "4V FH 246 677" -> 在线转换器 -> 经纬度 -> Google Maps。参见 [geolocation-and-media.md](geolocation-and-media.md)。

## Google Plus Codes

- 格式 `XXXX+XXX`（字符集：`23456789CFGHJMPQRVWX`）。在 Google Maps 上放置图钉 → Plus Code 出现在详情中。免费，无需 API 密钥。参见 [geolocation-and-media.md](geolocation-and-media.md)。

## 元数据提取

```bash
exiftool image.jpg           # EXIF 数据
pdfinfo document.pdf         # PDF 元数据
mediainfo video.mp4          # 视频元数据
```

## Google Dorking

```text
site:example.com filetype:pdf
intitle:"index of" password
```

**图片 TBS 筛选器：** 在 Google 图片搜索 URL 中附加 `&tbs=itp:face` 可筛选仅显示人脸（过滤掉 logo/横幅）。参见 [web-and-dns.md](web-and-dns.md)。

## Google Docs/Sheets

- 尝试 `/export?format=csv`、`/pub`、`/gviz/tq?tqx=out:csv`、`/htmlview`。参见 [web-and-dns.md](web-and-dns.md)。

## DNS 侦察

```bash
dig -t txt subdomain.ctf.domain.com
dig axfr @ns.domain.com domain.com  # 区域传送
```

务必检查 CTF 域名的 TXT、CNAME、MX 记录。参见 [web-and-dns.md](web-and-dns.md)。

## Tor 中继查询

- `https://metrics.torproject.org/rs.html#simple/<FINGERPRINT>` — 检查中继族群，按"首次发现"排序。参见 [web-and-dns.md](web-and-dns.md)。

## GitHub 仓库分析

- 检查 issue 评论、PR 审查、提交信息、wiki 编辑，使用 `gh api`。参见 [web-and-dns.md](web-and-dns.md)。

## Telegram 机器人调查

- 在浏览器历史中查找机器人引用，通过 `/start` 交互，回答验证问题。参见 [web-and-dns.md](web-and-dns.md)。

## FEC 政治捐款研究

- FEC.gov 查询委员会收支；501(c)(4) 组织会隐藏原始出资者。参见 [web-and-dns.md](web-and-dns.md)。

## IP 地理定位

```bash
curl "http://ip-api.com/json/103.150.68.150"
```

参见 [geolocation-and-media.md](geolocation-and-media.md)。

## Unicode 同形字隐写术

**模式：** 来自不同 Unicode 区块（西里尔文、希腊文、数学字体）的视觉上相同的 Unicode 字符在社交媒体帖子中编码二进制数据。ASCII = 0，同形字 = 1。按位分组为字节即可得到 flag。参见 [social-media.md](social-media.md#unicode-homoglyph-steganography-on-bluesky-metactf-2026)。

## BlueSky 公共 API

无需认证。端点：`public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=...`、`app.bsky.actor.searchActors`、`app.bsky.feed.getAuthorFeed`。检查官方帖子的所有回复。参见 [social-media.md](social-media.md#unicode-homoglyph-steganography-on-bluesky-metactf-2026)。

## 假服务横幅检测

**模式：** 端口在标准服务端口（22/SSH、80/HTTP）上显示为开放，但运行的是假服务。`nmap -sV` 或 `nc host port` 可在横幅中发现 flag。永远不要仅凭端口号判断——必须指纹识别服务。参见 [web-and-dns.md](web-and-dns.md#fake-service-banner-detection-via-fingerprinting-metactf-flash-2026)。

## Shodan SSH 指纹查询

通过 SSH 主机密钥指纹在 Shodan 上搜索以识别服务器：`shodan search "fingerprint:AA:BB:CC:..."`。参见 [web-and-dns.md](web-and-dns.md#shodan-ssh-fingerprint-lookup-ekoparty-ctf-2016)。

## 游戏平台 OSINT

在游戏平台（Steam、Xbox、PSN、MMO）上查找用户名，获取角色档案、活动记录和关联账户。参见 [social-media.md](social-media.md#gaming-platform-osint--mmo-character-lookup-csaw-ctf-2016)。

## 资源

- **Shodan** — 互联网连接设备搜索
- **Censys** — 证书和主机搜索
- **VirusTotal** — 文件/URL 信誉查询
- **WHOIS** — 域名注册信息
- **Wayback Machine** — 历史快照
