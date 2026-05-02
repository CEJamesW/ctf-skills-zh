---
name: ctf-web
description: 提供用于 CTF 挑战的 Web 利用技术。适用于目标主要是 HTTP 应用、API、浏览器客户端、模板引擎、身份流或智能合约前后端表面时，包括 XSS、SQLi、SSTI、SSRF、XXE、JWT、认证绕过、文件上传、请求走私、OAuth/OIDC、SAML、原型污染等常见 Web 漏洞。若问题本质上是原生二进制内存破坏、独立可执行文件逆向、磁盘/内存取证，或纯密码分析，则不要使用它，除非 Web 漏洞仍然是拿到 flag 的主路径。
license: MIT
compatibility: 需要基于文件系统的代理（Claude Code 或类似工具），以及 bash、Python 3 和互联网访问以安装工具。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Web Exploitation

把这个 skill 当成 Web 重题的分流与执行指南。首轮摸排要短：先画出应用边界，确认信任边界，再进入具体技巧文档。

## Prerequisites

**Python 包（全平台）：**
```bash
pip install sqlmap flask-unsign requests
```

**Linux (apt)：**
```bash
apt install hashcat jq curl
```

**macOS (Homebrew)：**
```bash
brew install hashcat jq curl
```

**Go 工具（全平台，需要 Go）：**
```bash
go install github.com/ffuf/ffuf/v2@latest
```

**手动安装：**
- ysoserial — [GitHub](https://github.com/frohoff/ysoserial)，需要 Java（Java 反序列化 payload）

## Additional Resources

- [sql-injection.md](sql-injection.md) - SQL 注入技巧：认证绕过、UNION 提取、过滤绕过、二阶 SQLi、截断、竞态辅助泄露、`INSERT ON DUPLICATE KEY UPDATE` 覆盖口令、`innodb_table_stats` WAF 绕过
- [server-side.md](server-side.md) - PHP 类型杂糅、`php://filter` LFI、Python `str.format` 遍历、SSTI（Jinja2、Twig、ERB、Mako、EJS、Vue.js、Smarty）、SSRF（Host 头、DNS rebinding、curl 跳转、未转义点号正则、SNI FTP smuggling、`mod_vhost_alias`）、PHP `hash_hmac` NULL
- [server-side-2.md](server-side-2.md) - XXE（基础、OOB、DOCX 上传）、通过 `X-Forwarded-For` 的 XML 注入、PHP variable variables、PHP `uniqid` 可预测文件名、顺序正则替换绕过、命令注入（换行、黑名单、sendmail CGI、多条码、git CLI）、GraphQL 注入（introspection、batching、插值）
- [server-side-exec.md](server-side-exec.md) - 直接代码执行路径、上传到 RCE、邻接反序列化执行链、LaTeX 注入、Header 与 API 滥用
- [server-side-exec-2.md](server-side-exec-2.md) - 更多执行链：SQLi 碎片化、路径解析技巧、polyglot 上传、wrapper 滥用、文件名注入、带文件名截断的 BMP 像素 webshell
- [server-side-deser.md](server-side-deser.md) - Java / Python / PHP 反序列化与竞态利用手册、PHP `SoapClient` 反序列化触发 CRLF SSRF
- [server-side-advanced.md](server-side-advanced.md) - 高级 SSRF、遍历、归档、解析器、框架与现代应用服务端问题，含 Nginx alias traversal
- [server-side-advanced-2.md](server-side-advanced-2.md) - Docker API SSRF、Castor/XML、Apache expression 读取、解析器差异、Windows 路径技巧、恶意 MySQL 服务器文件读取
- [server-side-advanced-3.md](server-side-advanced-3.md) - 第三部分（CSAW/35C3/ASIS/PlaidCTF 2018）：WAV polyglot 上传、多斜杠 URL `path.startswith` 绕过、Xalan XSLT `math:random()` 种子猜测、`SoapClient _user_agent` CRLF 方法走私、`gopher:///` 无主机 URL scheme 绕过、攻击者指定外连 URL 导致的 SSRF 凭据泄露
- [server-side-advanced-4.md](server-side-advanced-4.md) - 第四部分：WeasyPrint SSRF / 文件读取（CVE-2024-28184）、MongoDB regex / `$where` 盲预言机、Pongo2 Go 模板注入、ZIP PHP webshell、`basename()` 绕过、wget CRLF SSRF -> SMTP、Gopher SSRF 到 MySQL 盲 SQLi、React Server Components Flight RCE（CVE-2025-55182）、通过 `sslsplit+arpspoof` 的 AMQP/TLS 中间人、CairoSVG XXE、Bazaar 仓库重建
- [client-side.md](client-side.md) - XSS、CSRF、缓存投毒、DOM 技巧、admin bot 滥用、请求走私、付费墙绕过
- [client-side-advanced.md](client-side-advanced.md) - CSP 绕过、Unicode 技巧、XSSI、CSS 外带、浏览器归一化怪异行为、`postMessage` 的 null origin 绕过
- [auth-and-access.md](auth-and-access.md) - 认证 / 授权绕过、隐藏端点、IDOR、重定向链、子域接管、AI chatbot 越狱
- [auth-and-access-2.md](auth-and-access-2.md) - 第二部分（2018 风格）：`std::unordered_set` 桶碰撞认证绕过、`nodeprep.prepare` Unicode 同形用户名碰撞、SRP `A=0/A=N` 认证绕过、ArangoDB AQL `MERGE` 提权
- [auth-jwt.md](auth-jwt.md) - JWT / JWE 操纵、弱 secret、Header 注入、key confusion、重放
- [auth-infra.md](auth-infra.md) - OAuth / OIDC、SAML、CORS、CI/CD secrets、IdP 滥用、登录污染
- [node-and-prototype.md](node-and-prototype.md) - 原型污染、JS 沙箱逃逸、Node.js 攻击链
- [web3.md](web3.md) - Solidity 与 Web3 挑战笔记
- [cves.md](cves.md) - 可与 challenge banner、Header、依赖泄露或版本字符串对应的 CVE 导向技巧
- [field-notes.md](field-notes.md) - 长篇利用笔记：SQLi、XSS、LFI、JWT、SSTI、SSRF、命令注入、XXE、反序列化、竞态、认证绕过和多阶段利用链的速查表

## When to Pivot

- 如果目标是原生二进制、自定义 VM 或固件镜像，先切到 `/ctf-reverse`。
- 如果 HTTP 漏洞只给了代码执行，而真正难点变成了内存破坏或 seccomp 逃逸，切到 `/ctf-pwn`。
- 如果所谓 “web” 题的核心其实是 JWT 数学、自定义 MAC 或密码原语，切到 `/ctf-crypto`。
- 如果题目要求分析日志、PCAP 或从 Web 服务器恢复工件，切到 `/ctf-forensics`。
- 如果拿 flag 前必须先从公开网站、DNS 记录或社交媒体收集情报，切到 `/ctf-osint`。

## First-Pass Workflow

1. 先识别真正边界：纯浏览器、纯后端、混合应用，还是身份流。
2. 在 fuzz 之前，先为每个主要功能抓一组正常请求 / 响应。
3. 从 JS bundle、响应头、路由和替代 HTTP 方法里枚举隐藏功能。
4. 判断大致漏洞族：注入、鉴权、解析器不一致、上传、代理信任、状态机，还是客户端执行。
5. 先做最小利用：一个泄露、一次绕过、一个 primitive。完整利用链放后面。

## Quick Start Commands

```bash
# Recon
curl -sI https://target.com
ffuf -u https://target.com/FUZZ -w wordlist.txt
curl -s https://target.com/robots.txt

# SQLi quick test
sqlmap -u "https://target.com/page?id=1" --batch --dbs

# JWT decode (no verification)
echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Cookie decode (Flask)
flask-unsign --decode --cookie '<cookie>'
flask-unsign --unsign --cookie '<cookie>' --wordlist rockyou.txt

# SSTI probes
curl "https://target.com/page?name={{7*7}}"
curl "https://target.com/page?name={{config}}"

# Request inspection
curl -v -X POST https://target.com/api -H "Content-Type: application/json" -d '{}'
```

## First Questions to Answer

- flag 更可能在浏览器里、API 返回值里、本地文件、数据库记录，还是内网服务里？
- 应用是否会把用户可控数据喂进模板、重定向、文件路径、Header、序列化对象或后台任务？
- 是否存在多个解析器互相打架：代理 vs 应用、URL parser vs fetcher、sanitizer vs 浏览器、serializer vs filter？
- 能否先把漏洞缩成更小的 primitive：读一个文件、伪造一个 token、打一条内网接口、触发一次 bot 访问？

## High-Value Recon Checks

- 先看 HTML、内联脚本和打包后的 JS，再猜 API 面。
- 对比 UI 实际提交什么、后端又接受什么；可选 JSON 字段经常会打开隐藏路径。
- 早期就检查元数据和辅助路径：`/robots.txt`、`/sitemap.xml`、`/.well-known/`、`/admin`、`/debug`、`/.git/`、`/.env`。
- 对有价值的路由试不同方法和内容类型：`GET`、`POST`、`PUT`、`PATCH`、`TRACE`、JSON、form、multipart、XML。
- 把文件上传、PDF/export、webhook、OAuth callback 和 admin bot 功能都当成高价值放大器。

## Fast Pattern Map

- SQL 报错、奇怪过滤或与状态相关的 DB 行为：先看 [sql-injection.md](sql-injection.md)。
- 模板、文件读取、SSRF、命令执行、XML 或解析器漏洞：先看 [server-side.md](server-side.md) 和 [server-side-exec.md](server-side-exec.md)。
- XSS、CSP 绕过、admin bot、客户端路由、DOM 问题或无脚本外带：先看 [client-side.md](client-side.md)。
- 会话伪造、隐藏管理路由、JWT、OAuth、SAML 或弱信任边界：先看 [auth-and-access.md](auth-and-access.md)、[auth-jwt.md](auth-jwt.md) 和 [auth-infra.md](auth-infra.md)。
- Node.js 应用、原型污染、VM 沙箱或通往内网的 SSRF：补看 [node-and-prototype.md](node-and-prototype.md)。
- 智能合约前端或区块链集成应用：补看 [web3.md](web3.md)。

## Common Chain Shapes

- Recon -> hidden route -> auth bypass -> internal file read -> token 或 flag
- XSS / HTML 注入 -> admin bot -> 特权操作 -> secret 泄露
- 遍历 / 上传 -> 配置或源码泄露 -> secret 恢复 -> session 伪造
- SSRF -> metadata 或内网 API -> 凭据泄露 -> 代码执行
- SQLi / NoSQL 注入 -> 凭据绕过 -> 二阶段模板或上传滥用

## Deep-Dive Notes

一旦确认题目真的以 Web 为主，再看 [field-notes.md](field-notes.md) 的长篇利用目录：

- Recon、SQLi、XSS、遍历、JWT、SSTI、SSRF、XXE、命令注入速查
- 反序列化、竞态、文件上传到 RCE、多阶段利用链
- Node、OAuth/SAML、CI/CD、Web3、bot abuse、CSP 绕过和现代浏览器技巧
- 以 CVE 为线索的打法，以及现代题里仍然常见的旧套路

## Common Flag Locations

- 文件：`/flag.txt`、`/flag`、`/app/flag.txt`、`/home/*/flag*`
- 环境：`/proc/self/environ`、进程命令行、debug 配置导出
- 数据库：`flag`、`flags`、`secret` 之类表名，或预置 challenge 数据
- HTTP：自定义响应头、历史响应、隐藏路由、管理导出
- 浏览器：隐藏 DOM 节点、`data-*` 属性、内联状态对象、source map
