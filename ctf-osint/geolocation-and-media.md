# 																																	地理定位与媒体分析

## 目录

- [图像分析](#image-analysis)
- [反向图像搜索](#reverse-image-search)
- [地理定位技术](#geolocation-techniques)
- [MGRS（军事网格参考系统）](#mgrs-military-grid-reference-system)
- [Google Plus Codes / 开放位置码 (MidnightCTF 2026)](#google-plus-codes--open-location-codes-midnightctf-2026)
- [元数据提取](#metadata-extraction)
- [硬件/产品识别](#hardwareproduct-identification)
- [报纸档案与历史研究](#newspaper-archives-and-historical-research)
- [Google Street View 全景匹配 (EHAX 2026)](#google-street-view-panorama-matching-ehax-2026)
- [路标语言与行车方向分析 (EHAX 2026)](#road-sign-language-and-driving-side-analysis-ehax-2026)
- [后苏联建筑与品牌识别 (EHAX 2026)](#post-soviet-architecture-and-brand-identification-ehax-2026)
- [IP 地理定位与溯源](#ip-geolocation-and-attribution)
- [Google Lens 裁剪区域搜索 (UTCTF 2026)](#google-lens-cropped-region-search-utctf-2026)
- [反射与镜像文字阅读 (UTCTF 2026)](#reflected-and-mirrored-text-reading-utctf-2026)
- [What3Words (W3W) 地理定位 (UTCTF 2026)](#what3words-w3w-geolocation-utctf-2026)
- [纪念性大字 / Letreiro 识别 (UTCTF 2026)](#monumental-letters--letreiro-identification-utctf-2026)
- [Google Maps 众包照片验证 (MidnightCTF 2026)](#google-maps-crowd-sourced-photo-verification-midnightctf-2026)
- [Overpass Turbo 空间查询 (LAB'OSINT 2025)](#overpass-turbo-spatial-queries-labosint-2025)
- [音乐主题地标地理定位与琴键编码 (BSidesSF 2026)](#music-themed-landmark-geolocation-with-key-encoding-bsidessf-2026)

---

## Image Analysis

- Discord 头像：截图并进行反向图像搜索
- 识别图像中的物体（武器、装备）-> 查找角色/阵营
- 没有 EXIF？使用视觉特征（建筑、标志、地标）
- **视觉隐写术**：flag 以微小/低对比度文字隐藏在图像中（非二进制隐写）
  - 务必以全分辨率查看图像并检查所有角落/边缘
  - 黑底深色或白底浅色文字，逐渐变小的字体
  - 头像/个人资料图片是常见的隐藏位置
- **Twitter 会剥离 EXIF**——不要在 Twitter 提供的图片上浪费时间做隐写分析
- **Tumblr 头像保留更多元数据**，比帖子图片保留的更多

## Reverse Image Search

- Google Lens（裁剪至特定区域，最适合识别地标/店铺/标志）
- Google Images（最全面）
- TinEye（精确匹配）
- Yandex（擅长人脸识别，东欧地区）
- 百度图片 / `graph.baidu.com`（最适合中国地点——当视觉线索提示中国时使用：蓝色车牌、简体中文、门楼建筑）
- Bing Visual Search

## Geolocation Techniques

- 铁路道口标志：带红色边框的白色 X = 加拿大
- 使用基础设施地图：
  - [Open Infrastructure Map](https://openinframap.org) — 电力线路
  - [OpenRailwayMap](https://www.openrailwaymap.org/) — 铁路轨道
  - 高压输电线路地图
- 排除法：先缩小到国家，再到地区
- 交叉验证多个特征（铁路 + 电力线 + 山脉）
- MGRS 坐标：基于网格的军用系统（如 "4V FH 246 677"）-> 在线转换

## MGRS (Military Grid Reference System)

**模式（On The Grid）：** 编码坐标如 "4V FH 246 677"。

**识别：** 题目标题提到"网格"，代码格式匹配 MGRS 模式。

**转换：** 使用在线 MGRS 转换器 -> 经纬度 -> Google Maps 获取地名。

## Google Plus Codes / Open Location Codes (MidnightCTF 2026)

**模式（Chine Zhao）：** flag 格式要求 Google Plus Code（如 `H9G2+47X`），而非坐标或 W3W。Plus Codes 是 Google 开源的街道地址替代方案。

**格式：** `XXXX+XX`（短码/本地）或 `8FVC9G8F+6W`（完整/全球）。字符集为 `23456789CFGHJMPQRVWX`。`+` 分隔符始终存在。

**生成 Plus Code：**
1. 在 Google Maps 上找到精确位置
2. 点击地图在精确位置放置图钉
3. Plus Code 出现在位置详情面板中（如 `H9G2+47X 河北省邯郸市`）
4. 或在 Google Maps 搜索栏输入坐标——Plus Code 显示在结果中

**精度：** 标准 Plus Codes 分辨率约为 14m x 14m（对比 W3W 的 3m x 3m）。添加额外字符可提高精度。米级位置变化可能改变编码。

**关键洞察：** 与 W3W（专有，需要 API 密钥）不同，Plus Codes 是免费的，内置于 Google Maps。当 flag 格式显示 `{XXXX+XXX}` 时，将其识别为 Plus Code。将 Street View 相机定位到精确拍摄位置，然后从地图图钉读取 Plus Code。

**参考：** https://maps.google.com/pluscodes/

---

## Metadata Extraction

```bash
exiftool image.jpg           # EXIF 数据
pdfinfo document.pdf         # PDF 元数据
mediainfo video.mp4          # 视频元数据
```

## Hardware/Product Identification

**模式（Computneter, VuwCTF 2025）：** 电池规格 -> 制造商识别。将规格（电压、容量、外形）与制造商数据库交叉验证。

## Newspaper Archives and Historical Research

- Scout Life 杂志档案：https://scoutlife.org/wayback/
- 美国国会图书馆：https://www.loc.gov/（报纸搜索）
- 使用带日期范围的高级搜索

**模式（It's News, VuwCTF 2025）：** 结合报纸档案日期搜索与 EXIF GPS 坐标进行特定地点识别。

**工具：** 美国国会图书馆报纸档案、Google Maps 用于 GPS 坐标查找。

## Google Street View Panorama Matching (EHAX 2026)

**模式（amnothappyanymore）：** 挑战图像是 Google Street View 全景的裁剪部分。必须识别精确的全景 ID 和坐标。

**方法：**
1. **提取视觉特征：** 识别独特地标（道路类型、车辆、集装箱、山体形状、建筑风格、植被）
2. **缩小区域：** 使用视觉线索识别国家/地区（如格陵兰景观、特定道路基础设施）
3. **编译候选全景：** 使用 Google Street View 覆盖地图在已识别区域查找全景
4. **特征匹配：** 将挑战图像特征与候选全景进行对比：
   ```python
   import cv2
   import numpy as np
   
   # 加载挑战图像和候选全景
   challenge = cv2.imread('challenge.jpg')
   candidate = cv2.imread('panorama.jpg')
   
   # ORB 特征检测与匹配
   orb = cv2.ORB_create(nfeatures=5000)
   kp1, des1 = orb.detectAndCompute(challenge, None)
   kp2, des2 = orb.detectAndCompute(candidate, None)
   
   bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
   matches = bf.match(des1, des2)
   score = sum(1 for m in matches if m.distance < 50)
   ```
5. **排序系统：** 使用多种评分方法（全局特征匹配、局部块对比、颜色直方图分析）并组合排名
6. **API 提交：** 以所需格式提交全景 ID 和坐标（如 `lat/lng/sessionId/nonce`）

**Google Street View API 模式：**
```python
# Street View 元数据 API（检查是否有覆盖）
# GET https://maps.googleapis.com/maps/api/streetview/metadata?location=LAT,LNG&key=KEY

# Street View 图像 API
# GET https://maps.googleapis.com/maps/api/streetview?size=640x480&location=LAT,LNG&heading=90&key=KEY

# 从页面源码解析全景 ID（从 JavaScript 中提取）：
# 在页面数据结构中查找 panoId
```

**关键洞察：**
- 挑战图像通常是全景的裁剪——裁剪区域可能不包含地平线或天空，使地理定位更困难
- 独特元素：路面类型、车辆品牌、标牌语言、电线杆、集装箱颜色
- 格陵兰、冰岛、法罗群岛的 Street View 覆盖有限——枚举该区域所有全景
- 使用多种指标（特征匹配 + 颜色分析 + 块对比）进行图像相似度排序比任何单一方法更稳健

---

## Road Sign Language and Driving Side Analysis (EHAX 2026)

**模式（date_spot）：** 海岸位置的街景图像。从道路基础设施识别精确坐标。

**系统化方法：**
1. **行车方向：** 左侧通行 → 右舵驾驶国家（日本、英国、澳大利亚等）
2. **标志语言/文字体系：** 汉字 → 日本；西里尔字母 → 俄罗斯/独联体；阿拉伯文 → 中东/北非
3. **路标样式：** 白色文字的蓝色方向标志 + 路线编号 → 日本高速公路
4. **标志 OCR：** 从方向标志中提取文本以识别城镇/城市名称和路线编号
5. **路线追踪：** 搜索已识别的路线编号 + 城镇名称以找到道路走廊
6. **地形匹配：** 将海岸线、港口、灯塔、桥梁与卫星视图匹配

**日本基础设施线索：**
- 带白色汉字 + 路线编号的蓝色高速公路标志（如 E59）
- 独特的护栏样式（镀锌钢材，波浪形轮廓）
- 海岸公路上的混凝土海堤
- 带白色灯塔建筑的小型渔港

**通用国家识别捷径：**
| 特征 | 国家/地区 |
|---------|---------------|
| 汉字 + 蓝色高速公路标志 | 日本 |
| 西里尔字母 + 宽阔大道 | 俄罗斯/独联体 |
| 白色 X 形道口标志 | 加拿大 |
| 黄色菱形警告标志 | 美国/加拿大 |
| 绿色高速公路标志 | 德国 |
| 棕色旅游标志 | 法国 |
| 带红色反光片的路桩 | 荷兰 |

---

## Post-Soviet Architecture and Brand Identification (EHAX 2026)

**模式（idinahui）：** 海岸停车场图像。从建筑风格、车辆类型、标牌和当地品牌识别位置。

**识别链条：**
1. **建筑：** 粗野主义混凝土建筑 → 后苏联地区
2. **车辆：** 反向图像搜索车型，缩小到俄罗斯/独联体市场车辆
3. **文字：** 西里尔文标牌确认俄语区
4. **旗帜：** 地区政府旗帜与国旗三色旗并列 → 识别特定联邦主体
5. **品牌：** 有名称的餐厅/连锁店（如 "Mimino"——格鲁吉亚主题连锁，遍布俄罗斯）→ 搜索地理分布
6. **海岸特征：** 里海海岸线 + 北高加索建筑 → 达吉斯坦/马哈奇卡拉

**关键技术——餐厅/品牌地理定位：**
- 识别任何可读的商家名称或品牌 logo
- 搜索该商家 + "门店" 或 "分店"
- 与其他视觉线索（海岸线、地形）交叉验证以精确定位
- Google Maps 商家搜索对有名称的商户非常有效

**后苏联视觉标志：**
- 板式公寓楼（赫鲁晓夫楼/勃列日涅夫楼）
- 带中央隔离带的宽阔大道
- 混凝土公交站
- 独特的电线杆设计
- 苏联时代纪念碑和马赛克

---

## IP Geolocation and Attribution

**免费地理定位服务：**
```bash
# IP-API（无需密钥）
curl "http://ip-api.com/json/103.150.68.150"

# ipinfo.io
curl "https://ipinfo.io/103.150.68.150/json"
```

**孟加拉国 IP 范围（KCTF 中常见）：**
- `103.150.x.x` — 孟加拉国 ISP
- 手机号前缀：+880 13/14/15/16/17/18/19

**将位置与证据关联：**
- Windows 遥测数据（imprbeacons.dat）包含 `CIP` 字段
- 登录历史 API 可能显示 IP + 操作系统关联
- 通过 ASN 查询检测 VPN/代理

---

## Google Lens Cropped Region Search (UTCTF 2026)

**模式（W3W1/W3W2）：** 挑战图像包含多个元素，但只有一个对识别有用。搜索前裁剪至相关部分。

**技术：**
1. 识别图像中最独特的元素（店铺标志、建筑立面、地标）
2. 裁剪图像以隔离该元素——去除增加噪音的周围环境
3. 使用 Google Lens（`lens.google.com` 或在 Chrome 中右键 → "使用 Google Lens 搜索图片"）搜索裁剪区域
4. 查看视觉相似结果以识别具体位置或商家

**何时裁剪：**
- 店面：仅裁剪店面和标牌
- 地标：裁剪独特的建筑特征
- 标志：仅裁剪标志文字
- 教堂/建筑：裁剪独特的外立面

**关键洞察：** Google Lens 对裁剪区域的效果明显优于全场景图像。全场景可能返回通用景观结果，而裁剪的店铺标志可以返回确切的商家及其地址。

**示例工作流（W3W2）：**
1. 挑战图像显示一条街景中有一家商店
2. 仅裁剪商店部分
3. Google Lens 识别出商店及其位置
4. 在 Google Maps Street View 上验证
5. 将坐标转换为 What3Words

---

## Reflected and Mirrored Text Reading (UTCTF 2026)

**模式（W3W3）：** 图像中可见的文字是反射/镜像的（如水面或玻璃中的标志反射）。必须反向阅读文字以识别位置。

**技术：**
1. 识别图像中的反射文字（常见于水面反射、玻璃表面、镜子）
2. 水平翻转图像以正常阅读文字
3. 如果文字部分被遮挡，搜索可读部分作为前缀/后缀：
   - "Aguas de Lind..." → 搜索 `"Aguas de Lind"` → 找到 "Aguas de Lindoia"
4. 使用识别出的文字在 Google Maps 上定位

**部分文字搜索策略：**
```text
# 使用通配符/部分词搜索
"Aguas de Lind"           # 带引号的部分匹配
"Aguas de Lind" city      # 添加上下文关键词
"Aguas de Lind*" brazil   # 如果可从图像识别国家则添加
```

**反射文字的图像翻转：**
```bash
# 使用 ImageMagick 水平翻转图像
convert input.jpg -flop flipped.jpg

# 或使用 Python/PIL
python3 -c "
from PIL import Image
img = Image.open('input.jpg')
img.transpose(Image.FLIP_LEFT_RIGHT).save('flipped.jpg')
"
```

**关键洞察：** 当反射文字中某个字母模糊不清（如 "T" 还是 "I"）时，尝试两种变体分别搜索。带引号的部分文字搜索即使只有 60-70% 的文字可读，也能有效识别地名。

---

## What3Words (W3W) Geolocation (UTCTF 2026)

**模式（W3W1/W3W2/W3W3）：** 某位置的照片。找到精确的 What3Words 地址（3 米精度网格）。Flag 格式：`utflag{word1.word2.word3}`。

**What3Words 基础：**
- 将整个世界划分为 3m x 3m 的方格，每个方格有唯一的三词地址
- 单词使用特定语言（默认英语）
- 相邻方格的地址完全不同（无空间关联性）
- 网站：https://what3words.com/

**工作流：**
1. **识别位置**——使用标准地理定位技术（反向图像搜索、地标、标志、建筑）
2. **获取精确 GPS 坐标**——从 Google Maps 卫星视图
3. **将坐标转换为 W3W**——使用网站（在搜索栏输入坐标）
4. **微调：** 精确的 3m 方格很重要——小幅移动坐标检查相邻方格

**坐标到 W3W 转换：**
```text
# 导航到 what3words.com 并输入坐标：
# 格式：纬度, 经度（如 30.2870, -97.7415）
# 或在地图上点击精确位置

# W3W API 需要 API 密钥（CTF 中不一定可用）：
# GET https://api.what3words.com/v3/convert-to-3wa?coordinates=30.2870,-97.7415&key=API_KEY
```

**常见陷阱：**
- **3m 精度很关键：** 建筑入口和停车场可能有不同的 W3W 地址。匹配照片的精确视角。
- **相机位置 vs 被摄主体：** W3W 地址可能指的是相机所在位置，而非指向的目标。
- **卫星 vs 街景：** Google Maps 图钉可能与实际 W3W 网格不完全对齐。
- **附近多栋建筑：** 教堂、商店和地标可能有多个候选方格。

**精确定位技巧：**
- 使用 Google Street View 匹配精确的相机角度
- 与 OpenStreetMap (OSM) 交叉参考以获取精确建筑轮廓
- 在最佳猜测周围尝试 5-10 个相邻 W3W 地址
- 挑战图像通常显示特定特征（入口、标志、地标）——找到那个精确位置
- **微地标匹配：** 识别挑战图像中的小型独特特征（电线杆、小径石头、路桩、花盆）并在 Street View 中定位相同特征，以精确到 3m 方格
- **背景建筑三角定位：** 匹配挑战图像角度中可见的背景建筑。在 Street View 中找到相同建筑，然后确定相机必须在哪个位置才能产生相同透视效果
- **地理特征缩小：** 当你知道城市但不知道确切位置时，使用图像中可见的独特地理特征（湖泊、河流、海岸线）缩小搜索范围，然后再切换到 Street View

---

## Monumental Letters / Letreiro Identification (UTCTF 2026)

**模式（W3W3）：** 拼写城市/地点名称的大型 3D 字母照片，常反射在水池中。在拉丁美洲城市中常见作为旅游地标。

**识别线索：**
- 大型彩色 3D 块状字母
- 通常位于中央广场（praça）或旅游区
- 可能包含当地语言的城市名称
- 装饰性水池中的倒影是常见设计

**搜索策略：**
- Google：`"letras monumentales" [城市名]` 或 `"letreiro turístico" [城市名]`
- OpenStreetMap：搜索城市中心附近标记为 `tourism=attraction` 的节点
- Google Maps：搜索 `[城市名] sign` 或 `[城市名] letters` 并查看照片

**关键洞察：** 这些纪念性字母装置（西班牙语 "letras monumentales"，葡萄牙语 "letreiro turístico"）在拉丁美洲城市极为常见。安装的精确 GPS 坐标可在 OpenStreetMap 或 Google Maps 照片图钉上找到。

---

## Google Maps Crowd-Sourced Photo Verification (MidnightCTF 2026)

**模式（Where was Chine）：** 通过将挑战图像与该地点的 Google Maps 用户提交照片进行匹配来验证候选位置。

**工作流：**
1. 从其他 OSINT 线索（Strava GPS 路线、地址研究、社交媒体帖子）识别候选位置名称
2. 在 Google Maps 上搜索该位置名称
3. 点击位置图钉并浏览 **照片** 标签（用户提交的图片）
4. 将场景元素（建筑、树木、小径、水景、标牌）与挑战图像进行对比
5. 匹配确认位置——地名通常就是 flag

**何时使用：** 通过非视觉 OSINT（健身路线、地址、社交关系）缩小到候选位置后，使用 Google Maps 照片作为最终视觉确认。对于公园、广场和地标特别有用，因为许多游客会上传照片。

**关键洞察：** Google Maps 聚合了标记到特定位置的众包照片。即使反向图像搜索失败（因为挑战图像是原创的，非爬取的），相同的物理场景也会出现在游客照片中。按地名搜索，而非按图像搜索。

---

## Overpass Turbo Spatial Queries (LAB'OSINT 2025)

**模式（Portrait robot）：** 在已知城市中查找地铁入口附近的特定商家（报刊亭）。Overpass Turbo 查询 OpenStreetMap 数据，按类型在其他 POI 半径范围内定位兴趣点。

**工具：** https://overpass-turbo.eu/

**示例——在巴塞罗那查找地铁入口 10m 范围内的报刊亭：**
```text
[out:json][timeout:25];
{{geocodeArea:Barcelona}}->.searchArea;

(
  node["railway"="subway_entrance"](area.searchArea);
)->.metros;

(
  node(around.metros:10)["shop"~"newsagent|kiosk"];
  way(around.metros:10)["shop"~"newsagent|kiosk"];
);

out body;
>;
out skel qt;
```

**OSINT 常用查询模式：**
```text
# 某城市火车站附近的所有咖啡馆
{{geocodeArea:CityName}}->.a;
node["railway"="station"](area.a)->.stations;
node(around.stations:50)["amenity"="cafe"];

# 某区域内的所有 ATM
node["amenity"="atm"]({{bbox}});

# 特定坐标（经纬度）附近的酒店
node(around:200,48.8566,2.3522)["tourism"="hotel"];
```

**OSINT 挑战中常用的 OSM 标签：**

| 标签 | 值 |
|-----|--------|
| `shop` | `newsagent`、`kiosk`、`bakery`、`supermarket` |
| `amenity` | `cafe`、`restaurant`、`bank`、`atm`、`pharmacy` |
| `tourism` | `hotel`、`attraction`、`museum`、`viewpoint` |
| `railway` | `station`、`subway_entrance`、`halt` |

**关键洞察：** 当挑战图像显示已知城市中公交站附近的商家时，Overpass Turbo 可以通过查询公交节点小半径范围内的商家类型，将候选位置缩小到少数几个。使用 Google Street View 验证每个结果。`around` 操作符（邻近筛选器）是最有用的功能——它取代了数小时的手动地图浏览。

---

## Music-Themed Landmark Geolocation with Key Encoding (BSidesSF 2026)

**模式（strike-a-coord）：** 14 张全球音乐主题地标图片。对于每个位置：
1. 通过视觉线索识别地标（标牌、建筑、旗帜、独特特征）
2. 每个地标都有音乐关联（作曲家出生地、音乐厅、音乐博物馆）
3. 每个位置的视觉元素映射到特定的钢琴键编号
4. 钢琴键编号序列编码 flag

使用的地理定位技术：
- **标牌/文字：** 可读标牌缩小到城市/国家（如 "BTHVN" = 波恩的贝多芬出生地）
- **建筑风格：** 建筑材料、屋顶形状、窗户设计识别地区
- **国旗/国徽：** 可见的旗帜或政府建筑识别国家
- **Google Lens/反向图像搜索：** 匹配独特的建筑立面
- **Street View 确认：** 通过 Google Street View 验证候选位置

```python
# 钢琴键编码：每个地标产生一个键编号（1-88）
# 键编号映射到字符
piano_keys = [35, 67, 42, ...]  # 从每个地标恢复

# 常见编码：直接 ASCII、MIDI 音符号，或自定义映射
flag = ""
for key in piano_keys:
    # 如果键映射到 ASCII：key + 偏移量
    flag += chr(key + 32)  # 示例偏移
print(flag)
```

**关键洞察：** 多地点 OSINT 挑战将传统地理定位（地标识别）与二级编码层结合。每个位置的"钢琴键"或"音符"提取 flag 的一个字符。解题策略：先识别所有位置（较容易的部分），再从每个位置的数据点确定编码方案。

**何时识别：** 挑战提供多张具有音乐或主题线索的图片。每张图片需要单独地理定位。Flag 不在任何单个位置——而是编码在所有位置中。

**参考：** BSidesSF 2026 "strike-a-coord"
