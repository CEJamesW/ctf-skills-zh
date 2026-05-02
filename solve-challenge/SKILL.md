---
name: solve-challenge
description: 通过执行初步分类，识别主导类别，并将执行路由到正确的专用 ctf-* 技能来解决 CTF 挑战。当用户给出挑战包、远程服务、可疑文件或仅有模糊的挑战描述时，必须确定从哪里开始时使用。不要在类别已明确且可以直接调用专用技能时使用；这是调度器和侦察入口点，而非针对特定类别技术的最深参考。
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access. Orchestrates other ctf-* skills.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "true"
  argument-hint: "[category] [challenge-file-or-url]"
---

# CTF Challenge Solver

你是一名熟练的 CTF 选手。你的目标是解决挑战并找到 flag。

## 环境设置

根据你的工作流程，有两种设置策略：

### 预安装（推荐在比赛前）

使用中央安装入口：

```bash
bash scripts/install_ctf_tools.sh all
```

当你只想安装某一工具组时，运行更精简的模式：

```bash
bash scripts/install_ctf_tools.sh python
bash scripts/install_ctf_tools.sh apt
bash scripts/install_ctf_tools.sh brew
bash scripts/install_ctf_tools.sh gems
bash scripts/install_ctf_tools.sh go
bash scripts/install_ctf_tools.sh manual
```

完整的软件包列表现存于 [scripts/install_ctf_tools.sh](../scripts/install_ctf_tools.sh)。

### 按需安装（比赛中）

每个类别技能的 `SKILL.md` 中有一个**先决条件**部分，仅列出该类别所需的工具。按需安装。

## 工作流程

### 第0步：CTFd 平台检测

如果已知 CTF 平台 URL，检查其是否运行 CTFd 并切换到基于 API 的导航：

```bash
# 检测 CTFd（查找 /api/v1/ 和 /themes/core/）
curl -s "$CTF_URL/api/v1/" | head -5
curl -s "$CTF_URL" | grep -oE '/themes/core/'
```

如果检测到 CTFd，**请用户提供他们的 API 令牌**（在 CTFd 设置 > 访问令牌中生成）。令牌默认不提供——用户必须先在 CTFd Web UI 中创建。提供后，设置环境变量并通过 API 继续：

```bash
export CTF_URL="https://ctf.example.com"
export CTF_TOKEN="ctfd_..."  # 向用户索取
```

调用 `/ctf-misc` 并加载其 `ctfd-navigation.md` 以获取完整 API 参考和 Python 客户端类。

### 第1步：侦察

1. **探索文件** —— 列出挑战目录，对所有文件运行 `file *`
2. **分类二进制文件** —— 对二进制文件运行 `strings`、`xxd | head`、`binwalk`、`checksec`
3. **抓取链接** —— 如果挑战提及 URL，优先抓取以获取上下文
4. **连接服务** —— 尝试远程服务（`nc`）以了解其预期
5. **阅读提示** —— 挑战描述、文件名和注释通常包含线索

### 第2步：分类

确定主要类别，然后调用匹配的技能。

**按文件类型：**
- `.pcap`、`.pcapng`、`.evtx`、`.raw`、`.dd`、`.E01` -> forensics
- `.elf`、`.exe`、`.so`、`.dll`、无扩展名的二进制 -> reverse 或 pwn（检查是否提供远程服务——若是，可能是 pwn）
- `.py`、`.sage`、带数字的 `.txt` -> crypto
- `.apk`、`.wasm`、`.pyc` -> reverse
- Web URL 或含 HTML/JS/PHP/模板的源码 -> web
- 无明显内容的图片、音频、PDF -> forensics（隐写术）

**按挑战描述关键词：**
- “buffer overflow”、“ROP”、“shellcode”、“libc”、“heap” -> pwn
- “RSA”、“AES”、“cipher”、“encrypt”、“prime”、“modulus”、“lattice”、“LWE”、“GCM” -> crypto
- “XSS”、“SQL”、“injection”、“cookie”、“JWT”、“SSRF” -> web
- “disk image”、“memory dump”、“packet capture”、“registry”、“power trace”、“side-channel”、“spectrogram”、“audio tracks”、“MKV” -> forensics
- “find”、“locate”、“identify”、“who”、“where” -> osint
- “obfuscated”、“packed”、“C2”、“malware”、“beacon” -> malware
- “jail”、“sandbox”、“escape”、“encoding”、“signal”、“game”、“Nim”、“commitment”、“Gray code” -> misc

**按服务行为：**
- 端口带交互提示，长输入崩溃 -> pwn
- HTTP 服务 -> web
- netcat 带数学/密码学谜题 -> crypto
- netcat 带受限 shell 或 eval -> misc（jail）
### 第3步：调用类别技能

一旦确定类别，**调用匹配的技能**以获取专门的技术：

| 类别 | 调用命令 | 适用场景 |
|----------|--------|-------------|
| Web | `/ctf-web` | XSS、SQLi、SSTI、SSRF、JWT、文件上传、原型污染 |
| Pwn | `/ctf-pwn` | 缓冲区溢出、格式化字符串、堆、ROP、沙箱逃逸 |
| Crypto | `/ctf-crypto` | RSA、AES、ECC、伪随机数生成器、零知识证明、经典密码 |
| Reverse | `/ctf-reverse` | 二进制分析、游戏客户端、虚拟机、混淆代码 |
| Forensics | `/ctf-forensics` | 磁盘镜像、内存转储、事件日志、隐写、网络抓包 |
| OSINT | `/ctf-osint` | 社交媒体、地理定位、DNS、公共记录 |
| Malware | `/ctf-malware` | 混淆脚本、C2流量、PE/.NET分析 |
| Misc | `/ctf-misc` | 沙箱、编码、射频/软件定义无线电、晦涩语言、约束求解 |

你也可以调用 `/ctf-<category>` 来加载完整的技能说明和详细技术。

### 第4步：卡关时转换思路

如果第一种方法无效：

1. **重新审视假设** —— 这真的是你认为的类别吗？“web”题可能需要用 crypto 来伪造 JWT。“forensics” 的 PCAP 可能包含可重放的 pwn 漏洞。
2. **尝试不同的类别技能** —— 许多题目跨多个类别。调用第二个技能以获取交叉技术。
3. **寻找遗漏的线索** —— 隐藏文件、备用端口、响应头、源码注释、图片元数据。
4. **简化问题** —— 如果利用过于复杂，检查是否有更简单的路径（默认凭证、已知 CVE、逻辑漏洞）。
5. **检查边界情况** —— Off-by-one、竞态条件、整数溢出、编码不匹配。

**常见多类别组合模式：**
- Forensics + Crypto：PCAP/磁盘镜像中的加密数据，需要 crypto 解密
- Web + Reverse：Web 题中的 WASM 或混淆 JS
- Web + Crypto：JWT 伪造、自定义 MAC/签名方案
- Reverse + Pwn：先逆向二进制，再利用漏洞
- Forensics + OSINT：从转储恢复数据，再通过公共资源追踪
- Misc + Crypto：沙箱逃逸需要在约束下构建密码原语
- OSINT + Stego：社交媒体帖子中的 Unicode 同形异义隐写（西里尔字母伪装编码比特）
- Web + Forensics：付费墙绕过（curl 显示被 CSS 覆盖隐藏的内容）
- Misc + Crypto + Game Theory：多阶段交互挑战，包含 AES 解密 → HMAC 承诺 → 组合博弈求解（GF(256) Nim）
- Crypto + Geometry + Lattice：多层挑战，从空间重构 → 子空间恢复 → LWE 求解 → AES-GCM 解密
- Forensics + Signal Processing：功率轨迹/侧信道分析，需要对测量数据做统计分析
- Forensics + Network + Encoding：PCAP 中基于时间的编码（包间隔编码二进制数据）

### 第5步：生成 Write-up

解题后，调用 `/ctf-writeup` 生成标准化的提交风格 writeup —— 简洁、可复现，方便竞赛组织者或队友验证。

## Flag 格式

Flag 格式因 CTF 而异。常见格式：
- `flag{...}`、`FLAG{...}`、`CTF{...}`、`TEAM{...}`
- 自定义前缀：查看题目描述或 CTF 规则（如 `ENO{...}`、`HTB{...}`、`picoCTF{...}`）
- 有时仅为无包装的纯文本字符串

**验证规则（重要）：**
- 如果发现多个类似 flag 的字符串，视为候选项，需验证后确定。
- 优先选择与目标工件/流程相关的 token（非随机元数据噪声或明显诱饵）。
- 做全库唯一性检查，报告时附带源文件/路径。

```bash
# 在文件中搜索常见 flag 模式
grep -rniE '(flag|ctf|eno|htb|pico)\{' .
# 在二进制/内存输出中搜索
strings output.bin | grep -iE '\{.*\}'
```
## 快速参考

```bash
# 侦察
file *                                    # 识别文件类型
strings binary | grep -i flag             # 快速字符串搜索
xxd binary | head -20                     # 十六进制转储头部
binwalk -e firmware.bin                   # 提取嵌入文件
checksec --file=binary                    # 检查二进制保护

# 连接
nc host port                              # 连接到挑战
echo -e "answer1\nanswer2" | nc host port # 脚本化输入
curl -v http://host:port/                 # HTTP 侦察

# Python 利用模板
python3 -c "
from pwn import *
r = remote('host', port)
r.interactive()
"
```

## 挑战

$ARGUMENTS
