# CTF Web - Auth & Access Control Attacks (Part 2)

补充 2018 年前后的认证与访问控制技巧：分桶碰撞导致的哈希认证绕过、Unicode 用户名同形碰撞、SRP 的 A=0/A=N 绕过、ArangoDB AQL MERGE 提权。基础认证/授权技巧见 [auth-and-access.md](auth-and-access.md)。JWT 见 [auth-jwt.md](auth-jwt.md)。OAuth/OIDC/SAML/CI-CD 见 [auth-infra.md](auth-infra.md)。

## Table of Contents
- [std::unordered_set Bucket Collision Auth Bypass (Hackover 2018)](#stdunordered_set-bucket-collision-auth-bypass-hackover-2018)
- [nodeprep.prepare Homograph Username Collision (HCTF 2018)](#nodeprepprepare-homograph-username-collision-hctf-2018)
- [SRP A=0, A=N Auth Bypass (OTW Advent 2018)](#srp-a0-an-auth-bypass-otw-advent-2018)
- [ArangoDB AQL MERGE Injection for Privilege Escalation (P.W.N. CTF 2018)](#arangodb-aql-merge-injection-for-privilege-escalation-pwn-ctf-2018)

---

## std::unordered_set Bucket Collision Auth Bypass (Hackover 2018)

**模式：** 某 C++ 后端把凭据哈希存进 `std::unordered_set<std::string>`。集合的 bucket index 仅由 SHA-512 摘要的前几个字节决定（截断后的 `size_t` 哈希），而查找循环又在探测次数达到上限后提前停止（`MAX_LOOKUPS = 1000`）。只要往与 `root` 账号同一个 bucket 里塞入 1000+ 个碰撞项，就能让真正的比较永远轮不到执行，最终在攻击者指定密码时返回“找到该项”。

```cpp
// Vulnerable shape
std::unordered_set<std::string> users;
auto it = users.find(login_key);           // probes at most MAX_LOOKUPS
if (it != users.end()) { /* accepted */ }
```

```python
# Flood registration: every entry collides in root's bucket
import requests
for i in range(1100):
    requests.post("http://target/register",
                  data={"name": f"ro{i:04d}", "password": "ot1"})
# Log in as root with an arbitrary password — loop gives up before compare
requests.post("http://target/login", data={"name": "root", "password": "anything"})
```

**关键点：** 当哈希表只根据被截断的摘要去分桶时，攻击者只需要命中同一个 bucket，而不必构造完整哈希碰撞。若实现里还有限定探测次数的 DoS 防护，向该 bucket 灌入大量碰撞项就会把认证逻辑变成“无条件接受”。凡是 `unordered_map` / `unordered_set` 的键值来自低熵用户输入导出值，都值得警惕，尤其是把长摘要 XOR 折叠成 `size_t` 的写法。

**参考：** Hackover CTF 2018 — secure-hash, writeup 11502

---

## nodeprep.prepare Homograph Username Collision (HCTF 2018)

**模式：** 注册流程调用 `node-xmpp-server` 的 `nodeprep.prepare(username)`，该函数会执行 RFC-3491/Stringprep 规范化。诸如 `ᴬ`（U+1D2C，Modifier Letter Capital A）这类 Unicode 字符会被规范化成 ASCII `A`，导致现有用户查找命中已注册的 `admin`。于是可以用任意密码注册 `ᴬdmin`，并在找回密码流程中把真实管理员密码重置掉。

```text
username: \u1D2Cdmin   # ᴬdmin
nodeprep.prepare("ᴬdmin") == "admin"
```

**关键点：** 任何“查找前做规范化，但存储时保留原始字符串”的用户名流水线都存在风险。正确做法是在写入时就统一规范化，并拒绝一切规范化后与现有用户冲突的注册。常见需要审计的库包括 `nodeprep`、`icu.normalize`、`unicodedata.normalize`、`golang.org/x/text/secure/precis`。

**参考：** HCTF 2018 — admin, writeup 12132

---

## SRP A=0, A=N Auth Bypass (OTW Advent 2018)

**模式：** 某些 SRP（Secure Remote Password）实现没有校验 `A % N != 0`，允许客户端发送 `A = 0`（或 `A = k*N`）。此时服务器计算 `S = (A * v^u)^b mod N = 0`，会话密钥就退化成攻击者已知的 `H(0)`，从而在不知道密码的情况下完成登录。

```text
Client: sends A = 0
Server: computes S = 0
Session key: K = H(0)   # attacker knows this
```

**关键点：** SRP、DH 等基于群的协议都必须显式验证公开值不是平凡值。规范实现会拒绝 `A % N == 0`；错误实现不会。相同思路同样适用于 `A = N, 2N, ...`。

**参考：** OverTheWire Advent Bonanza 2018 — writeup 12750

---

## ArangoDB AQL MERGE Injection for Privilege Escalation (P.W.N. CTF 2018)

**模式：** ArangoDB 的 AQL 支持把用户提供的片段直接拼进 `FILTER` 子句。注入 `' || 1 == 1 LET newitem = MERGE(u, {'role':'admin'}) RETURN newitem //` 后，可把登录检查改造成“在内存中构造 admin 版本的用户对象”，服务端随后返回这份已提权对象，而不会真正改写数据库记录。

```text
username: x' || 1 == 1 LET newitem = MERGE(u, {'role':'admin'}) RETURN newitem //
password: anything
```

**关键点：** 每种 NoSQL 数据库都有自己的注入语法。AQL 中的 `MERGE` 可以基于查询到的记录构造新文档，因此即便持久化层没被改动，也可能绕过仅检查返回对象字段的 ACL。修复方式仍然是使用参数化 bind variables。

**参考：** P.W.N. CTF 2018 — H!pster Startup, writeup 12067
