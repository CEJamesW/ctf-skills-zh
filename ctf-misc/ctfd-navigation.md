# CTFd 平台导航（无浏览器）

通过 REST API 对基于 CTFd 的 CTF 平台进行编程交互。消除比赛期间对浏览器的依赖。

## 目录

- [检测 CTFd](#detect-ctfd)
- [认证](#authentication)
- [列出挑战](#list-challenges)
- [挑战详情](#challenge-details)
- [下载挑战文件](#download-challenge-files)
- [提交 flag](#submit-flags)
- [排行榜](#scoreboard)
- [提示与解锁](#hints-and-unlocks)
- [通知](#notifications)
- [用户和团队信息](#user-and-team-info)
- [完整比赛工作流程](#full-competition-workflow)
- [Python CTFd 客户端](#python-ctfd-client)
- [故障排除](#troubleshooting)

---

## 检测 CTFd

HTTP 响应中的 CTFd 指纹：

```bash
# 检查响应头和正文中的 CTFd 签名
curl -sI "$CTF_URL" | grep -i 'ctfd\|powered-by'

# 检查 CTFd API 端点（返回 Swagger UI 或 JSON）
curl -s "$CTF_URL/api/v1/" | head -20

# 检查 CTFd 静态资源
curl -s "$CTF_URL" | grep -oE '(ctfd|CTFd|/themes/core)'

# 检查 CTFd 登录页面结构
curl -s "$CTF_URL/login" | grep -oE 'name="nonce"'
```

**关键指示：**
- `/api/v1/` 返回 Swagger/RESTX 文档
- HTML 包含 `/themes/core/` 资源路径
- 登录表单包含 `nonce` 隐藏字段
- 响应头可能在 `Server` 或 `X-Powered-By` 中包含 `CTFd`

---

## 认证

CTFd 支持两种认证方式：会话 Cookie（登录流程）和 API 令牌（推荐）。

**重要提示：** 检测到 CTFd 后，**请向用户索要他们的 API 令牌**。令牌默认不提供——用户必须先在 CTFd Web UI（设置 > 访问令牌）生成令牌，API 访问才会生效。如果用户还没有令牌，请引导他们：在浏览器中登录 CTFd，进入设置 > 访问令牌，创建令牌，然后粘贴回来。

### 方法一：API 令牌（推荐）

从 CTFd Web UI（设置 > 访问令牌）生成令牌，或者如果已有会话 Cookie：

```bash
# 通过 API 生成令牌（需先进行会话认证）
curl -s -X POST "$CTF_URL/api/v1/tokens" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"expiration": "2026-12-31", "description": "CLI access"}' | jq .
```

使用令牌进行后续所有请求：

```bash
export CTF_URL="https://ctf.example.com"
export CTF_TOKEN="ctfd_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 测试认证
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/users/me" | jq .
```

### 方法二：会话登录（基于 Cookie）

```bash
# 第一步：从登录页面获取 CSRF nonce
NONCE=$(curl -sc cookies.txt "$CTF_URL/login" | grep 'name="nonce"' | grep -oE 'value="[^"]*"' | cut -d'"' -f2)

# 第二步：使用凭据登录
curl -sb cookies.txt -c cookies.txt -X POST "$CTF_URL/login" \
  -d "name=username&password=password&nonce=$NONCE" \
  -L -o /dev/null -w '%{http_code}'

# 第三步：使用 Cookie 调用 API
curl -s -b cookies.txt "$CTF_URL/api/v1/users/me" | jq .
```

**关键点：** nonce 是表单登录所需的 CSRF 令牌。API 令牌认证完全绕过此步骤——有令牌时优先使用令牌。

---

## 列出挑战

```bash
# 所有可见挑战
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges" | jq .

# 按类别过滤
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges?category=web" | jq .

# 简洁列表：id、名称、类别、分值、解题数
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges" | \
  jq -r '.data[] | "\(.id)\t\(.value)pts\t\(.category)\t\(.name)\t(\(.solves) solves)"' | \
  sort -t$'\t' -k3,3 -k2,2rn | column -t -s$'\t'
```

**响应结构：**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "type": "standard",
      "name": "Challenge Name",
      "value": 100,
      "solves": 42,
      "solved_by_me": false,
      "category": "web",
      "tags": [],
      "template": "...",
      "script": "..."
    }
  ]
}
```

---
## Challenge Details

```bash
# 完整的挑战详情（描述、文件、提示、标签）
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CHALL_ID" | jq .

# 仅提取描述（HTML格式）
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CHALL_ID" | \
  jq -r '.data.description'

# 去除HTML标签以获得可读描述
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CHALL_ID" | \
  jq -r '.data.description' | sed 's/<[^>]*>//g'

# 列出附加到挑战的文件
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CHALL_ID" | \
  jq -r '.data.files[]'

# 获取连接信息（如果描述中有）
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CHALL_ID" | \
  jq -r '.data.description' | grep -oE '(nc |ssh |https?://)[^ <"]+' | head -5
```

---

## Download Challenge Files

CTFd 使用带有令牌签名的 URL 提供文件。请从挑战详情中提取并下载：

```bash
# 从挑战中获取文件URL
FILES=$(curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CHALL_ID" | \
  jq -r '.data.files[]')

# 下载所有挑战文件
mkdir -p "chall_$CHALL_ID"
for f in $FILES; do
  # 文件路径是相对路径 — 需加上基础URL前缀
  URL="${CTF_URL}${f}"
  FILENAME=$(basename "$f" | sed 's/?.*//')
  curl -s -H "Authorization: Token $CTF_TOKEN" -o "chall_$CHALL_ID/$FILENAME" "$URL"
  echo "Downloaded: $FILENAME"
done
```

**关键提示：** 文件URL包含一个查询字符串令牌（`?token=...`）用于认证下载。该令牌有时间限制 — 如果下载返回403错误，请重新获取挑战详情。

---

## Submit Flags

```bash
# 提交flag
curl -s -X POST -H "Authorization: Token $CTF_TOKEN" \
  -H "Content-Type: application/json" \
  "$CTF_URL/api/v1/challenges/attempt" \
  -d "{\"challenge_id\": $CHALL_ID, \"submission\": \"flag{example}\"}" | jq .
```

**响应状态：**
| 状态 | 含义 |
|--------|---------|
| `correct` | Flag被接受 |
| `incorrect` | Flag错误 |
| `already_solved` | 你/团队之前已解出 |
| `ratelimited` | 尝试次数过多（默认：每分钟10次） |
| `paused` | CTF已暂停 |

**关键提示：** 每个用户每分钟最多允许10次错误提交。请合理分散暴力破解尝试，否则会被暂时锁定。

---

## Scoreboard

```bash
# 完整排行榜
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/scoreboard" | jq .

# 前10名
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/scoreboard/top/10" | jq .

# 简洁排行榜
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/scoreboard/top/20" | \
  jq -r '.data | to_entries[] | "\(.value.pos)\t\(.value.name)\t\(.value.score)pts"' | \
  column -t -s$'\t'
```

**注意：** 排行榜在服务器端缓存60秒。

---

## Hints and Unlocks

```bash
# 列出挑战提示（从挑战详情）
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CHALL_ID" | \
  jq '.data.hints'

# 获取提示内容（免费或已解锁）
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/hints/$HINT_ID" | jq .

# 解锁付费提示（消耗积分）
curl -s -X POST -H "Authorization: Token $CTF_TOKEN" \
  -H "Content-Type: application/json" \
  "$CTF_URL/api/v1/unlocks" \
  -d "{\"target\": $HINT_ID, \"type\": \"hints\"}" | jq .
```

---

## Notifications

```bash
# 获取所有通知（主办方公告）
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/notifications" | jq .

# 获取通知数量（HEAD请求）
curl -sI -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/notifications" | \
  grep -i 'x-total'

# 轮询获取自上次查看后的新通知
curl -s -H "Authorization: Token $CTF_TOKEN" \
  "$CTF_URL/api/v1/notifications?since_id=$LAST_ID" | jq .
```

---
## 用户和团队信息

```bash
# 当前用户资料
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/users/me" | jq .

# 我的解题记录
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/users/me/solves" | \
  jq -r '.data[] | "\(.challenge.name)\t\(.challenge.value)pts\t\(.date)"'

# 我的失败尝试
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/users/me/fails" | jq .

# 当前团队（团队模式）
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/teams/me" | jq .

# 团队解题记录
TEAM_ID=$(curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/teams/me" | jq '.data.id')
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/teams/$TEAM_ID/solves" | jq .
```

---

## 完整竞赛工作流程

从终端端到端的 CTFd 交互：

```bash
#!/usr/bin/env bash
# CTFd CLI 工作流程 — 设置这两个变量后即可使用
export CTF_URL="https://ctf.example.com"
export CTF_TOKEN="ctfd_your_token_here"
AUTH="-H 'Authorization: Token $CTF_TOKEN'"

# 1. 验证身份
echo "=== 当前登录用户 ==="
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/users/me" | jq -r '.data | "\(.name) (id: \(.id))"'

# 2. 按类别列出所有挑战
echo -e "\n=== 挑战列表 ==="
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges" | \
  jq -r '.data | sort_by(.category, -.value) | .[] |
    "\(.solved_by_me | if . then "✓" else " " end) \(.id)\t\(.value)pts\t\(.category)\t\(.name)"' | \
  column -t -s$'\t'

# 3. 查看指定挑战详情
read -p "挑战 ID: " CID
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CID" | \
  jq -r '.data | "名称: \(.name)\n类别: \(.category)\n分值: \(.value)\n解题数: \(.solves)\n\n描述:\n\(.description)"' | \
  sed 's/<[^>]*>//g'

# 4. 下载文件
mkdir -p "chall_$CID"
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges/$CID" | \
  jq -r '.data.files[]' | while read -r f; do
    curl -s -H "Authorization: Token $CTF_TOKEN" -o "chall_$CID/$(basename "$f" | sed 's/?.*//')" "${CTF_URL}${f}"
  done
echo "文件已下载到 chall_$CID/"

# 5. 提交 flag
read -p "Flag: " FLAG
curl -s -X POST -H "Authorization: Token $CTF_TOKEN" \
  -H "Content-Type: application/json" \
  "$CTF_URL/api/v1/challenges/attempt" \
  -d "{\"challenge_id\": $CID, \"submission\": \"$FLAG\"}" | \
  jq -r '.data | "\(.status): \(.message)"'
```

---

## Python CTFd 客户端

用于脚本化交互的可复用类：

```python
import requests
import os
import re
from pathlib import Path


class CTFdClient:
    """用于竞赛的最简 CTFd API 客户端。"""

    def __init__(self, url, token):
        self.url = url.rstrip('/')
        self.s = requests.Session()
        self.s.headers['Authorization'] = f'Token {token}'

    def _get(self, path, **kwargs):
        r = self.s.get(f'{self.url}/api/v1{path}', **kwargs)
        r.raise_for_status()
        return r.json()

    def _post(self, path, json=None):
        r = self.s.post(f'{self.url}/api/v1{path}', json=json)
        r.raise_for_status()
        return r.json()

    # --- 挑战相关 ---

    def challenges(self, category=None):
        """列出所有可见挑战。"""
        params = {'category': category} if category else {}
        return self._get('/challenges', params=params)['data']

    def challenge(self, cid):
        """获取完整挑战详情。"""
        return self._get(f'/challenges/{cid}')['data']

    def unsolved(self):
        """列出当前用户尚未解出的挑战。"""
        return [c for c in self.challenges() if not c.get('solved_by_me')]

    # --- 文件相关 ---

    def download_files(self, cid, dest='.'):
        """下载指定挑战的所有文件。"""
        info = self.challenge(cid)
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        paths = []
        for f in info.get('files', []):
            url = f'{self.url}{f}' if f.startswith('/') else f
            fname = re.sub(r'\?.*', '', f.split('/')[-1])
            out = dest / fname
            r = self.s.get(url)
            r.raise_for_status()
            out.write_bytes(r.content)
            paths.append(str(out))
        return paths

    # --- Flag 提交 ---

    def submit(self, cid, flag):
        """提交 flag。返回 (状态, 消息)。"""
        resp = self._post('/challenges/attempt',
                          json={'challenge_id': cid, 'submission': flag})
        d = resp['data']
        return d['status'], d['message']

    # --- 排行榜 ---

    def scoreboard(self, top=10):
        """获取前 N 名排行榜条目。"""
        return self._get(f'/scoreboard/top/{top}')['data']

    # --- 用户/团队信息 ---

    def me(self):
        """当前用户信息。"""
        return self._get('/users/me')['data']

    def my_solves(self):
        """当前用户已解出的挑战。"""
        return self._get('/users/me/solves')['data']

    # --- 提示相关 ---

    def hint(self, hint_id):
        """获取提示内容（已解锁或免费）。"""
        return self._get(f'/hints/{hint_id}')['data']

    def unlock_hint(self, hint_id):
        """解锁提示（需花费积分）。"""
        return self._post('/unlocks', json={'target': hint_id, 'type': 'hints'})

    # --- 通知相关 ---

    def notifications(self, since_id=None):
        """获取公告。可选按通知 ID 过滤。"""
        params = {'since_id': since_id} if since_id else {}
        return self._get('/notifications', params=params)['data']


# --- 使用示例 ---

if __name__ == '__main__':
    c = CTFdClient(os.environ['CTF_URL'], os.environ['CTF_TOKEN'])

    # 仪表盘
    print(f"当前登录用户: {c.me()['name']}")
    print(f"\n未解出的挑战:")
    for ch in c.unsolved():
        print(f"  [{ch['id']}] {ch['category']}/{ch['name']} ({ch['value']}pts, {ch['solves']} 解题数)")

    # 下载并提交示例流程
    # files = c.download_files(1, dest='chall_1')
    # status, msg = c.submit(1, 'flag{...}')
    # print(f"{status}: {msg}")
```

---
## 故障排除

| 现象 | 原因 | 解决方法 |
|---------|-------|-----|
| 401 未授权 | Token 过期或无效 | 通过网页 UI 或会话登录重新生成 token |
| 下载文件时 403 | 文件 token 过期 | 重新获取挑战详情以获得新的文件 URL |
| 访问挑战时 403 | CTF 未开始或邮箱未验证 | 检查 `/api/v1/users/me` 中的 `verified` 字段 |
| 429 速率限制 | 错误 flag 提交过多 | 等待 60 秒；默认限制为每分钟 10 次错误提交 |
| 挑战列表为空 | CTF 尚未开始 | 在通知或配置中检查 CTF 开始时间 |
| 缺少 `nonce` | 登录页面变更或反机器人机制 | 尝试使用 API token 认证替代会话登录 |
| API 中无连接信息 | 部分 CTF 使用动态实例 | 检查挑战专用的实例 API 或 Docker 端点 |
