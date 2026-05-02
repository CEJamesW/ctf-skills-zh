# 社交媒体 OSINT

## 目录
- [社交媒体 OSINT](#社交媒体-osint)
  - [目录](#目录)
  - [Twitter/X Account Tracking](#twitterx-account-tracking)
  - [Tumblr Investigation](#tumblr-investigation)
  - [BlueSky Advanced Search](#bluesky-advanced-search)
  - [Username OSINT](#username-osint)
  - [Platform False Positives](#platform-false-positives)
  - [Social Media General Tips](#social-media-general-tips)
  - [Multi-Platform OSINT Chain](#multi-platform-osint-chain)
  - [Gaming Platform OSINT / MMO Character Lookup (CSAW CTF 2016)](#gaming-platform-osint--mmo-character-lookup-csaw-ctf-2016)
  - [MetaCTF OSINT Challenge Patterns](#metactf-osint-challenge-patterns)
  - [Unicode Homoglyph Steganography on BlueSky (MetaCTF 2026)](#unicode-homoglyph-steganography-on-bluesky-metactf-2026)
  - [Strava Fitness Route OSINT (MidnightCTF 2026)](#strava-fitness-route-osint-midnightctf-2026)
  - [Discord API Enumeration](#discord-api-enumeration)

---

## Twitter/X Account Tracking

**持久数字用户 ID（关键技术）：**
- 每个 Twitter/X 账户都有一个永远不变的永久数字 ID
- 通过 ID 访问任何账户：`https://x.com/i/user/<numeric_id>` — 即使改名后仍有效
- 从存档页面查找用户 ID（JSON-LD `"author":{"identifier":"..."}`）
- 当用户名已被删除/更改但你从取证痕迹中获得了 ID 时非常有用

**用户名更名检测：**
- Twitter 用户 ID 在更名后保持不变；t.co 短链接指向旧用户名
- Wayback CDX API 查找存档的个人资料：`http://web.archive.org/cdx/search/cdx?url=twitter.com/USERNAME*&output=json`
- 存档页面包含带用户 ID、创建日期、关注/粉丝数的 JSON-LD
- 存档推文中的 t.co 链接揭示之前的用户名（重定向 URL 包含发帖时的用户名）
- 同一推文 ID 可在不同用户名下访问 = 确认已更名

**Twitter 替代数据源：**
- Nitter 实例（如 `nitter.poast.org/USERNAME`）无需登录即可查看推文
- Syndication API：`https://syndication.twitter.com/srv/timeline-profile/screen-name/USERNAME`
- Twitter Snowflake ID 编码时间戳：`(id >> 22) + 1288834974657` = Unix 毫秒
- memory.lol 和 twitter.lolarchiver.com 追踪用户名历史

**用于 Twitter 的 Wayback Machine：**
```bash
# 查找某用户名的所有存档 URL
curl "http://web.archive.org/cdx/search/cdx?url=twitter.com/USERNAME*&output=json&fl=timestamp,original,statuscode"

# 同时检查头像图片
curl "http://web.archive.org/cdx/search/cdx?url=pbs.twimg.com/profile_images/*&output=json"

# 检查 t.co 短链接
curl "http://web.archive.org/cdx/search/cdx?url=t.co/SHORTCODE&output=json"
```

## Tumblr Investigation

**博客存在性检查：**
- `curl -sI "https://USERNAME.tumblr.com"` -> 查找 `x-tumblr-user` 头（确认博客存在，即使 API 返回 401）
- Tumblr API 可能返回 401（未授权），但博客仍可通过浏览器公开查看

**从 Tumblr HTML 提取帖子内容：**
- Tumblr 将帖子数据以 JSON 嵌入页面 HTML 中
- 搜索 `"content":[` 以找到帖子正文数据
- 帖子包含 `type: "text"` 带 `text` 字段，以及 `type: "image"` 带媒体 URL
- 头像 URL 模式：`https://64.media.tumblr.com/HASH/HASH-XX/s512x512u_c1/FILENAME.jpg`

**头像作为 flag 容器：**
- 直接头像端点：`https://api.tumblr.com/v2/blog/USERNAME.tumblr.com/avatar/512`
- 或简写：`https://USERNAME.tumblr.com/avatar/512`（重定向到 CDN URL）
- 可用尺寸：16、24、30、40、48、64、96、128、512
- Flag 可能以小文字隐藏在头像图片中（视觉隐写，非二进制隐写）
- 始终下载最高分辨率（512）并放大检查所有区域

## BlueSky Advanced Search

**模式（Ms Blue Sky）：** 在 BlueSky 社交媒体上查找目标的帖子。

**搜索筛选器：**
```text
from:username        # 来自特定用户的帖子
since:2025-01-01     # 日期范围
has:images           # 包含图片的帖子
```

**参考：** https://bsky.social/about/blog/05-31-2024-search

## Username OSINT

- [namechk.com](https://namechk.com) — 跨平台检查用户名
- [whatsmyname.app](https://whatsmyname.app) — 用户名枚举（741+ 个站点）
- [Osint Industries](https://osint.industries) — 跨平台人员搜索（付费，覆盖健身/小众平台）
- 在主要平台上用引号搜索 `"username"`

**用户名元数据挖掘：**
用户名通常在其结构中嵌入地理或时间信号。提取并研究数字后缀、前缀或嵌入的模式：

| 模式 | 示例 | 信号 |
|---------|---------|--------|
| 末尾数字 = 邮政编码 | `LinXiayu35170` | 35170 = 法国 Bruz |
| 出生年份后缀 | `jsmith1998` | 1998 年出生 |
| 区号 | `user212nyc` | 212 = 曼哈顿 |
| 国家代码 | `player44uk` | +44 = 英国 |

将提取的代码与邮政编码数据库、电话号码注册表或地理地名录交叉验证，以缩小目标位置范围。（MidnightCTF 2026）

**用户名链条追踪（账户更名）：**
1. 从已知用户名开始 -> 查找 Wayback 存档
2. 在存档页面中查找 t.co 链接或指向其他用户名的交叉引用
3. 发现新用户名 -> 在所有平台上再次枚举
4. 重复直到找到包含 flag 的平台

**CTF 用户名枚举优先平台：**
- Twitter/X、Tumblr、GitHub、Reddit、Bluesky、Mastodon
- Spotify、SoundCloud、Steam、Keybase
- Strava、Garmin Connect、MapMyRun（健身/GPS——泄露物理位置）
- Pastebin、LinkedIn、YouTube、TikTok
- 个人链接服务（linktr.ee、bio.link、about.me）

## Platform False Positives

返回 200 但无真实资料的平台：
- Telegram（`t.me/USER`）：始终返回 200 并显示 "Contact @USER" 页面；检查标题中是 "View" 还是 "Contact"
- TikTok：返回 200 并在正文中显示 "Couldn't find this account"
- Smule：返回 200 并在页面内容中显示 "Not Found"
- linkin.bio：未声明的名称重定向到 Later.com 产品页面
- Instagram：返回 200 但显示登录墙（可能存在也可能不存在）

## Social Media General Tips

- 在 Wayback Machine 上检查 Bluesky、Twitter 等平台上已删除的帖子
- 未列出的 YouTube 视频可能链接在已删除的帖子中
- 简介链接可能指向 itch.io、个人网站等更多信息
- 在平台特定搜索中用引号搜索 `"username"`
- 挑战标题通常是提示（如 "Linked Traces" -> LinkedIn / 关联账户）
- **Twitter 会剥离 EXIF**——不要在 Twitter 提供的图片上浪费时间做隐写分析
- **Tumblr 头像保留更多元数据**，比帖子图片保留的更多

## Multi-Platform OSINT Chain

**模式（Massive-Equipment393）：** Reddit 用户名 -> Spotify 社交链接 -> Base58 编码字符串 -> Spotify 播放列表描述（base64）-> 歌曲标题首字母离合字。

**关键技术：**
- Base58 解码用于非标准编码
- Spotify 播放列表在描述和歌曲标题首字母中编码数据
- 平台链式跳转：每个平台链接到下一个

## Gaming Platform OSINT / MMO Character Lookup (CSAW CTF 2016)

CTF OSINT 挑战可能需要在 MMO 平台上查找游戏角色、公会或个人资料。

```text
# 魔兽世界角色/公会查询：
# - Blizzard API: https://develop.battle.net/documentation/world-of-warcraft
# - WoW Progress: https://www.wowprogress.com
# - Raider.IO: https://raider.io
# 搜索：公会名 + 服务器名（如 "Blackfathom Deep Dish" on US-Turalyon）

# Steam 个人资料搜索：
# - steamcommunity.com/id/[username]
# - steamid.io 用于 SteamID 查询

# Minecraft 玩家查询：
# - NameMC: https://namemc.com
# - 显示皮肤、改名历史、服务器

# Discord 用户查询：
# - discord.id 用于用户/服务器查询
# - 机器人：UserInfo 用于详细资料

# 游戏 OSINT 链条模式：
# 1. 博客/Twitter 提到公会或游戏名
# 2. 在游戏专用追踪网站上查找公会
# 3. 从公会花名册找到角色名
# 4. 角色名可能在其他平台上使用
# 5. 与其他 OSINT 发现交叉验证
```

**关键洞察：** 游戏资料在 OSINT 中常被忽视，但包含丰富的元数据（游戏时间、真实姓名、关联账户、服务器地区）。公会/战队追踪器索引公开的游戏 API 并缓存历史数据。角色名经常在多个平台上重复使用。

---

## MetaCTF OSINT Challenge Patterns

**常见流程：**
1. 起始图像中隐藏 EXIF/元数据 -> 提取用户名
2. 用户名枚举（Sherlock/WhatsMyName）跨平台搜索
3. 在平台 X 上找到指向平台 Y 线索的个人资料
4. Flag 隐藏在最终平台上（Spotify 简介、BlueSky 帖子、Tumblr 头像等）

**平台特定的 flag 位置：**
- Spotify：播放列表名称、艺术家简介
- BlueSky：帖子内容
- Tumblr：头像图片、帖子文字
- Reddit：帖子/评论内容
- Smule：歌曲录制或简介
- SoundCloud：音轨描述

**关键技术：**
- 通过 Wayback + t.co 链接追踪账户更名
- 跨平台用户名关联
- 以最大分辨率视觉检查所有个人资料图片
- 歌词识别 -> 艺术家/歌曲作为 flag 组成部分

## Unicode Homoglyph Steganography on BlueSky (MetaCTF 2026)

**模式（Skybound Secrets）：** Flag 使用 Unicode 同形字隐写术隐藏在 Bluesky 帖子中——来自不同 Unicode 区块的视觉上相同的字符编码二进制数据。

**检测：**
- 帖子文本看起来正常，但逐字符分析揭示非 ASCII 码点
- 来自西里尔文（`а` U+0430 vs `a` U+0061）、希腊文、亚美尼亚文、数学等宽字体等区块的字符
- 每个字符编码 1 位：ASCII = 0，同形字 = 1

**Bluesky API 搜索工作流：**
```bash
# 搜索关于 CTF 的帖子
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=metactf+flash+ctf&sort=latest" | jq '.posts[].record.text'

# 搜索特定账户
curl -s "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?q=metactf" | jq '.actors[].handle'

# 获取个人资料
curl -s "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=metactf.bsky.social" | jq

# 获取作者动态（所有帖子）
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=metactf.bsky.social&limit=50" | jq '.feed[].post.record.text'

# 获取帖子线程（含回复）
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=at://did:plc:.../app.bsky.feed.post/..." | jq
```

**解码同形字隐写术：**
```python
def decode_homoglyph_stego(text):
    bits = []
    for ch in text:
        if ch in ('\u2019',):  # 平台自动插入的右单引号
            continue  # 跳过，非故意的同形字
        if ord(ch) < 128:
            bits.append(0)  # 标准 ASCII
        else:
            bits.append(1)  # Unicode 同形字 = 1 位

    # 按字节分组（高位优先）
    flag = ''
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bits[i + j]
        flag += chr(byte_val)
    return flag
```

**常见同形字对：**
| ASCII | 同形字 | Unicode 区块 |
|-------|-----------|---------------|
| `a` (U+0061) | `а` (U+0430) | 西里尔文 |
| `o` (U+006F) | `о` (U+043E) | 西里尔文 |
| `e` (U+0065) | `е` (U+0435) | 西里尔文 |
| `s` (U+0073) | `ѕ` (U+0455) | 西里尔文 DZE |
| `t` (U+0074) | `𝚝` (U+1D69D) | 数学等宽字体 |
| `p` (U+0070) | `р` (U+0440) | 西里尔文 |

**关键教训：**
- 检查官方 CTF 帖子的所有回复，不仅仅是主帖
- 平台自动格式化（智能引号 `'` → `'`）必须从位编码中排除
- "hype comes with its own secrets" 之类的提示暗示社交媒体帖子本身中存在隐写术
- Bluesky 公共 API 无需认证——使用 `public.api.bsky.app`

---

## Strava Fitness Route OSINT (MidnightCTF 2026)

**模式（Where was Chine）：** 通过健身追踪数据识别目标的物理位置。在 Twitter 上发现用户名 → 在 GitHub 代码中找到别名 → 在 Strava 上搜索别名 → 跑步路线终点揭示位置。

**Strava 公开数据暴露：**
- 公开运动员资料：`https://www.strava.com/athletes/<id>`
- 活动地图显示带起点/终点的 GPS 路线
- 即使"隐私区域"也可通过分析区域外的路线形状来绕过
- 赛段排行榜无需关注即可揭示运动员位置

**位置提取工作流：**
1. 通过用户名枚举（Whatsmyname、Osint Industries）找到目标的 Strava 资料
2. 检查公开活动中的 GPS 路线地图
3. 识别路线起点/终点或常去位置
4. 在 Google Maps 上搜索终点位置
5. 使用 Google Maps 用户提交照片验证（参见 [geolocation-and-media.md](geolocation-and-media.md#google-maps-crowd-sourced-photo-verification-midnightctf-2026)）

**关键洞察：** 健身应用是高价值 OSINT 目标，因为用户很少限制活动可见性。单次公开跑步即可揭示家/工作地点附近区域。将 GPS 终点与 Google Maps 交叉验证以识别特定公园、建筑或地标。

**检测：** 挑战提到运动、跑步、骑行、健身、GPS 或健康追踪。目标人物有活跃/运动型的个人设定。

---

## Discord API Enumeration

**模式（Insanity 1 & 2, 0xFun 2026）：** Flag 隐藏在普通 UI 中不可见的 Discord 服务器元数据中。

**隐藏位置：**
- 身份组名称
- 动态 GIF 表情（flag 在第 2 帧，持续时间极短）
- 消息嵌入（embed）
- 服务器描述、贴纸、活动

```bash
# 使用用户 token 枚举
TOKEN="your_token"
# 列出身份组
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/roles"
# 列出表情
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/emojis"
# 搜索消息
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/messages/search?content=flag"
```

**动态表情：** 下载 GIF，提取帧——隐藏数据可能位于正常速度下不可见的短暂帧中。
