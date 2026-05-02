# CTF Crypto - 现代密码攻击（第三部分）

自定义哈希反演、CRC 暴力、带噪声的 RSA 预言机、海绵碰撞、CBC / padding oracle 技巧、SPN 恢复、AES-CFB、三轮 XOR、Unicode 侧信道、SHA-256 basis attack、MAC 伪造、HMAC bit 预言机。关于 Blum-Goldwasser、长度扩展、压缩预言机、OFB / HMAC-CRC / DES 弱密钥、SRP、square attack、AES-ECB / CBC 预言机、Rabin、PBKDF2 和 MD5 多重碰撞，见 [modern-ciphers-2.md](modern-ciphers-2.md)。

## Table of Contents
- [通过已知中间状态反演自定义哈希（BackdoorCTF 2016）](#custom-hash-state-reversal-via-known-intermediates-backdoorctf-2016)
- [小载荷 CRC32 暴力（BackdoorCTF 2016）](#crc32-brute-force-for-small-payloads-backdoorctf-2016)
- [带噪声的 RSA LSB 预言机与事后纠错（SharifCTF 7 2016）](#noisy-rsa-lsb-oracle-with-post-hoc-error-correction-sharifctf-7-2016)
- [部分状态上的海绵哈希 MITM 碰撞（BKP 2017）](#sponge-hash-collision-via-meet-in-the-middle-on-partial-state-bkp-2017)
- [CBC IV 伪造 + 截断分组绕过认证（0CTF 2017）](#cbc-iv-forgery--block-truncation-for-authentication-bypass-0ctf-2017)
- [Padding Oracle + CBC Bitflip 命令注入（BSidesSF 2017）](#padding-oracle-to-cbc-bitflip-command-injection-bsidessf-2017)
- [利用 S 盒交集恢复 SPN 部分密钥（SharifCTF 7 2016）](#spn-cipher-partial-key-recovery-via-s-box-intersection-sharifctf-7-2016)
- [从时间戳种子 PRNG 恢复 AES-CFB IV（SHA2017）](#aes-cfb-iv-recovery-from-timestamp-seeded-prng-sha2017)
- [三轮 XOR 协议中的密钥相消（HITB 2017）](#three-round-xor-protocol-key-cancellation-hitb-2017)
- [AES-CBC UnicodeDecodeError 侧信道预言机（Kaspersky 2017）](#aes-cbc-unicodedecodeerror-side-channel-oracle-kaspersky-2017)
- [针对 XOR 聚合哈希的 SHA-256 Basis Attack（34C3 CTF 2017）](#sha-256-basis-attack-for-xor-aggregate-hash-bypass-34c3-ctf-2017)
- [通过 XOR 分组抵消与轮换密钥流伪造 MAC（PlaidCTF 2018）](#custom-mac-forgery-via-xor-block-cancellation-with-key-rotation-plaidctf-2018)
- [通过 XOR + 加法算术逐 bit 恢复 HMAC 密钥（Midnight Sun CTF 2018）](#bit-by-bit-hmac-key-recovery-via-xor-plus-addition-arithmetic-midnight-sun-ctf-2018)
- [从第 2 块已知明文恢复 CBC IV（RITSEC 2018）](#cbc-iv-recovery-from-block-2-known-plaintext-ritsec-2018)
- [基于字符匹配的迭代 SHA-256 计时预言机（35C3 2018）](#iterated-sha-256-timing-oracle-on-character-match-35c3-2018)
- [从 PCAP 矩阵在 GF(p) 上恢复 AES key（35C3 Junior 2018）](#gfp-linear-system-aes-key-recovery-from-pcap-matrix-35c3-junior-2018)
- [带 UTF-8 高位绕过的 SHA-1 长度扩展（OTW Advent 2018）](#sha-1-length-extension-with-utf-8-high-byte-bypass-otw-advent-2018)
- [跨会话利用 CRT 恢复立方根（X-MAS 2018）](#cross-session-cube-root-recovery-via-crt-x-mas-2018)
- [通过翻前一块字节提升 Cookie 权限（picoCTF 2018）](#cbc-previous-block-byte-flipping-for-cookie-privilege-escalation-picoctf-2018)

---

## Custom Hash State Reversal via Known Intermediates (BackdoorCTF 2016)

**模式（Collision Course）：** 某自定义哈希按 4 字节分组处理，用 XOR 和轮转更新状态。如果题目打印了中间状态，就能反推出每个分组的哈希值：`hash(block) = s(i) XOR ROL(s(i+1), 7)`。随后对每个目标哈希值分别暴力 4 字节可打印输入即可。

```python
def reverse_hash_states(states):
    """给定中间哈希状态，恢复各分组的哈希值。"""
    blocks = []
    for i in range(len(states) - 1):
        # state_update: s(i+1) = ROR(s(i) ^ hash(block), 7)
        # 因此：         hash(block) = s(i) ^ ROL(s(i+1), 7)
        h = states[i] ^ rol32(states[i+1], 7)
        blocks.append(h)
    return blocks

def rol32(val, n):
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

# 对每个分组哈希值暴力可打印 4 字节
import itertools, string
for target_hash in block_hashes:
    for chars in itertools.product(string.printable, repeat=4):
        block = bytes(ord(c) for c in chars)
        if custom_hash(block) == target_hash:
            print(f"Found: {block}")
            break
```

**关键点：** 一旦中间状态泄露，原本的整体哈希问题就会拆成多个独立的 4 字节暴力问题。若输入受限于可打印 ASCII，搜索空间会大幅下降。

---

## CRC32 Brute-Force for Small Payloads (BackdoorCTF 2016)

**模式（CRC）：** 加密 ZIP 文件的头部仍然保存了未压缩内容的 CRC32。若文件内容很短（如 5 字节），可以直接暴力所有可打印 5 字节字符串，计算 CRC32 并与头部值比对。可能会有多个候选，但通常能结合上下文去歧义。

```python
import binascii, itertools, string, zipfile

# 不解密也能从 ZIP 头里读出 CRC
with zipfile.ZipFile('encrypted.zip') as z:
    crc = z.infolist()[0].CRC

# 暴力 5 字节可打印内容
for chars in itertools.product(string.printable[:95], repeat=5):
    candidate = ''.join(chars).encode()
    if binascii.crc32(candidate) & 0xFFFFFFFF == crc:
        print(f"Match: {candidate}")
```

**关键点：** ZIP 头里的 CRC32 永远是明文可见的，即使 ZIP 被口令保护。对不超过 6 字节的可打印 ASCII 文件，搜索空间仍在可行范围内。C 实现会比 Python 快很多。

---

## Noisy RSA LSB Oracle with Post-Hoc Error Correction (SharifCTF 7 2016)

**模式：** 标准 RSA LSB 预言机二分搜索的扩展版。预言机会偶尔返回错误结果。先完整跑一遍常规攻击，再检查输出字节。若出现非 ASCII 或不合理字符，通常说明最后若干 bit 中某一步 oracle 结果出错了。尝试翻转附近的单个预言机结果，往往能修正后续全部解密。

```python
def lsb_oracle_attack(ciphertext, e, n, oracle_fn, flips=None):
    """利用 RSA LSB 预言机恢复明文，并支持可选的误差修正。"""
    flips = flips or []
    lower, upper = 0, n
    mult = 1
    for i in range(n.bit_length()):
        ciphertext = (ciphertext * pow(2, e, n)) % n
        result = oracle_fn(ciphertext)
        if i in flips:
            result = not result  # 修正已知错误
        mid = (lower + upper) // 2
        if result == 0:
            upper = mid
        else:
            lower = mid
    return lower
```

**关键点：** 稀疏的 oracle 错误只会在解密结果的局部位置造成污染。若你对输出字符集有预期（如 hex、ASCII），就能反推错误查询大致落在哪个位置，再通过“翻转该次 oracle 结果”完成纠偏。

---

## Sponge Hash Collision via Meet-in-the-Middle on Partial State (BKP 2017)

**模式：** 某自定义海绵哈希以固定 AES key 为置换，每次把 10 字节消息块 XOR 进 16 字节状态。因为每块只能控制 16 字节状态里的 10 字节，直接原像搜索要约 `2^48`。用 MITM 可把它降下来：预计算 `2^24` 个前向 AES 结果并按后 6 字节索引，再做反向搜索。

```python
from Crypto.Cipher import AES
import os

aes = AES.new(b'\x00' * 16, AES.MODE_ECB)
forward = {}

# 前向：计算 AES(random_10_bytes || 0x00*6)，按最后 6 字节索引
for _ in range(2**24):
    block = os.urandom(10) + b'\x00' * 6
    enc = aes.encrypt(block)
    forward[enc[-6:]] = block

# 反向：计算 AES_dec(target XOR random_c)，检查后 6 字节是否匹配
target_state = b'\x77\x40\x56\x0a\x1d\x64'  # 目标哈希
for _ in range(2**40):
    c_block = os.urandom(10) + target_state
    dec = aes.decrypt(c_block)
    if dec[-6:] in forward:
        a_block = forward[dec[-6:]]
        b_block = xor(aes.encrypt(a_block), dec)  # 中间块
        break
```

**关键点：** 当海绵的 rate 小于状态宽度时，那些“不可控字节”反而提供了 MITM 的切口：一边预计算，一边反向搜索，复杂度从 `2^48` 下降为 `2^24` 级空间和时间。

---

## CBC IV Forgery + Block Truncation for Authentication Bypass (0CTF 2017)

**模式：** 服务端把 `MD5(padded_name) || padded_name` 用 AES-CBC 加密，并在登录时检查 MD5 作为完整性标记。可以把两种攻击结合起来：
1. **IV 操纵：** XOR IV，把解密后的第一块从源 MD5 改成目标 MD5
2. **块截断：** 注册 `pad("admin") + 16_junk_bytes` 后，直接去掉尾部多余密文块。CBC 没有长度字段，只要新的最后一块仍是合法 PKCS7 填充，截断后的密文就是合法的

```python
# 伪造 IV：把注册时的 MD5 翻成 "admin" 对应的 MD5
source_md5 = md5(pad("admin") + b"A"*16)
target_md5 = md5(pad("admin"))
new_iv = bytes(a ^ b ^ c for a, b, c in zip(original_iv, source_md5, target_md5))

# 去掉最后 2 块（junk + PKCS padding 块）
forged_token = new_iv + ciphertext[16:-32]
```

**关键点：** AES-CBC 自身并不提供长度完整性。只要新的结尾仍是合法填充，就可以安全裁掉尾部分组。再结合对第 0 块的 IV 伪造，就能伪造任意第一块内容。

---

## Padding Oracle to CBC Bitflip Command Injection (BSidesSF 2017)

**模式：** 某 URL 参数是加密后的命令。错误信息会泄露填充是否合法，因此既可以先用 padding oracle 恢复原命令明文，又可以进一步通过 CBC bitflip 注入 shell 元字符（如 `;$(cmd)`），最终把纯密码学漏洞升级成命令执行。

```python
# 第 1 步：padding oracle 恢复明文
plaintext = padding_oracle_decrypt(ciphertext, oracle_fn)

# 第 2 步：CBC bitflip —— 修改第 N-1 块，使第 N 块解密后变成目标命令
target_block = 5
desired = b';$(cat *.txt)   '  # 16 字节，尾部补空格
original = plaintext[target_block * 16:(target_block + 1) * 16]
ct = bytearray(bytes.fromhex(ciphertext))
for i in range(16):
    ct[(target_block - 1) * 16 + i] ^= original[i] ^ desired[i]
forged = ct.hex()
```

**关键点：** Padding oracle 与 CBC bitflip 本来常被分开讲，但链起来后就是完整攻击链：先靠预言机拿到明文，再用 bitflip 精准注入载荷。

---

## SPN Cipher Partial Key Recovery via S-box Intersection (SharifCTF 7 2016)

**模式：** 一个 3 轮 SPN，块长 36 bit，S 盒宽 6 bit。利用选择明文对，对最后两轮的子密钥对 `(k2, k3)` 做部分逆推，并检查中间 S 盒输入是否满足约束。把约 200 组明密文对上的“合法候选”取交集后，每个 6-bit 子密钥都能唯一确定。

```python
def recover_subkeys(pairs, sbox, perm):
    """通过多组明密文对交集恢复 6-bit 子密钥。"""
    for sbox_pos in range(6):  # 每轮 6 个 S 盒
        candidates = None
        for pt, ct in pairs:
            valid = set()
            for k2 in range(64):  # 第 2 轮 6-bit 子密钥
                for k3 in range(64):  # 第 3 轮 6-bit 子密钥
                    # 对第 3、2 轮做部分逆运算
                    intermediate = inv_sbox[ct_bits[sbox_pos] ^ k3]
                    intermediate = inv_perm(intermediate)
                    if inv_sbox[intermediate ^ k2] == expected_from_pt:
                        valid.add((k2, k3))
            candidates = valid if candidates is None else candidates & valid
        assert len(candidates) == 1  # 唯一子密钥对
```

**关键点：** SPN 结构很适合做分治。每个 S 盒位置都可以单独攻击，多对明密文的交集会迅速把候选压缩到唯一解。

---

## AES-CFB IV Recovery from Timestamp-Seeded PRNG (SHA2017)

**模式：** 某勒索软件用 AES-CFB 加密文件，口令写死在 `bash_history` 里，而 IV 则来自 `random.choice()`，其随机数种子是加密时刻的 `int(time())`。文件系统保留了文件 mtime，而 mtime 恰好就是 seed，从而可以完整恢复 IV 并解密。

```python
import random, os, string, base64
from Crypto.Cipher import AES

password = b'hardcoded_password_from_bash_history'
img = 'encrypted_file.enc'

# 文件 mtime 就是加密时所用的随机种子
random.seed(int(os.stat(img).st_mtime))
iv = ''.join(random.choice(string.letters + string.digits) for _ in range(16))

aes = AES.new(password, AES.MODE_CFB, iv.encode())
with open(img, 'rb') as f:
    ciphertext = base64.b64decode(f.read())
plaintext = aes.decrypt(ciphertext)
```

**关键点：** 如果 PRNG 在加密时以 `time()` 播种，那么文件系统保留的 mtime 往往就是最直接的 seed 泄露。注意 Python 2 和 Python 3 的 `random` 实现不同，同一 seed 可能产出不同序列。复制文件时也要注意 `cp -it` / `mv` 之类操作可能改掉 mtime。

---

## Three-Round XOR Protocol Key Cancellation (HITB 2017)

**模式：** 自定义协议做了一个三轮 XOR 密钥交换：
1. 客户端发 `c1 = msg XOR clientKey`
2. 服务端回 `c2 = c1 XOR serverKey`
3. 客户端再发 `c3 = c2 XOR clientKey`

如果这三条消息都能从抓包里拿到，那么直接做 `c1 XOR c2 XOR c3` 就能得到原始 `msg`，因为所有 key 都抵消了：

```python
# c1 = msg ^ clientKey
# c2 = msg ^ clientKey ^ serverKey
# c3 = msg ^ serverKey
# c1 ^ c2 ^ c3 = msg   （所有 key 全被 XOR 抵消）
plaintext = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, c3))
```

**关键点：** 同一把 key 被 XOR 偶数次时，必然会在代数上消掉。三轮 XOR 协议如果设计成“客户端 key 出现两次”，就等于明着把明文送出来。

---

## AES-CBC UnicodeDecodeError Side-Channel Oracle (Kaspersky 2017)

**模式：** 服务端解密 AES-CBC 后会尝试按 UTF-8 解码。非法 UTF-8 序列会抛出 `UnicodeDecodeError`，而这一错误可与其他错误区分开，于是等价于一个“内容是否合法”的解密预言机。

**攻击：** 套用标准 CBC bit-flip 预言机思路，只不过判定条件从“填充是否合法”变成“UTF-8 是否合法”：
1. 要恢复块 `b` 中位置 `i` 的明文字节，就修改块 `b-1` 中对应字节
2. 枚举 256 个 XOR 值，当该修改让解密结果在 UTF-8 上变得合法时，服务端会返回“非 UnicodeDecodeError”响应
3. 根据通过的 XOR 值和你对 `c[b-1][i]` 的修改量，反推出 `plaintext[b][i]`

```python
# 利用 UTF-8 合法性做 CBC bit-flip 预言机
for guess in range(256):
    modified = bytearray(prev_block)
    modified[pos] = known_intermediate[pos] ^ guess  # 构造目标输出字节
    if not unicode_error(modified_block + target_block):
        plaintext_byte = guess  # 这个位置的 UTF-8 合法
        break
```

**关键点：** 只要某种错误能区分“明文合法 / 非法”，它就能当作解密预言机。不只 PKCS#7 填充，UTF-8、base64、JSON 解析等都可以。

---

## SHA-256 Basis Attack for XOR-Aggregate Hash Bypass (34C3 CTF 2017)

**模式：** 收集 256 个文件，使它们的 SHA-256 哈希在 `Z_2^256` 中构成一组基。之后对任意目标哈希，都能求出该基中哪些文件的 SHA-256 XOR 起来等于目标差值，从而破坏 `XOR(sha256(file_i)) == expected` 这类聚合校验。

```python
# 1. 生成约 300 个随机合法 Python 文件
# 2. 计算它们的 SHA-256，视作 GF(2) 上的 256-bit 向量
# 3. 用高斯消元找出其中 256 个线性无关向量
# 4. 目标：h_new XOR (XOR of sha256(basis_files)) = h_orig
# 5. 解线性系统，得到需要纳入哪些 basis files
from sage.all import GF, matrix
M = matrix(GF(2), [hash_to_bits(sha256(f)) for f in basis_files])
target = hash_to_bits(sha256(malicious_zip)) ^ hash_to_bits(original_hash)
solution = M.solve_left(target)
```

**关键点：** 这里并不是找 SHA-256 碰撞，而是利用“XOR 聚合”本身的线性弱点。随机 256 个哈希几乎必然张满整个 `GF(2)^256`，因此能组合出任意目标差值。

---

### Custom MAC Forgery via XOR Block Cancellation with Key Rotation (PlaidCTF 2018)

**模式：** 某个自定义 MAC 用 AES-ECB 生成内部 key stream，而该 key stream 每 128 块重复一次。构造三次查询，让 2048 字节的填充分组在 XOR 下彼此抵消，最后只剩目标命令的 MAC。（PlaidCTF 2018）

```python
mac1 = fmac("tag " + tag_cmd(cmdline))      # tag AAA...
mac2 = fmac("tag " + expand_cmd(cmdline))    # tag BBB...(2048) + cmd_padded
mac3 = fmac("tag " + expand_cmd(tag_cmd(cmdline)))  # tag BBB...(2048) + tagAAA_padded
forged_mac = mac1 ^ mac2 ^ mac3  # XOR 抵消后等于 fmac(cmdline)
```

**关键点：** 只要 MAC 内部 key stream 周期性重复，就能安排相同块落在同一周期位置，通过多次查询使其互相抵消。三次查询就够伪造任意目标命令的 MAC。

---

### Bit-by-Bit HMAC Key Recovery via XOR Plus Addition Arithmetic (Midnight Sun CTF 2018)

**模式：** 某有缺陷的 HMAC 实现计算 `sha256((key XOR msg) + msg)`，其中 `+` 是逐位加法而非拼接。发送 `msg=0` 时会得到 `sha256(key)`。再对每个 bit 位 `i` 发送 `msg=2^i`：若 key 的第 i 位为 1，则 XOR 清掉后又被加法补回，因此哈希不变；否则哈希改变。（Midnight Sun CTF 2018）

```python
key_hash = get_digest(b'\x00')  # sha256(key + 0) = sha256(key)
key = 0
for i in range(key_bits):
    digest = get_digest(int_to_bytes(2**i))
    if digest == key_hash:
        key |= (1 << i)  # 第 i 位为 1
```

**关键点：** XOR 与加法叠在一起时，会形成逐位可探测的行为：若 key[i]=1，则 `1 XOR 1 = 0`，再 `0 + 1 = 1`，最终恢复原值；若 key[i]=0`，则 `0 XOR 1 = 1`，再加 1 会进位，输出变化。于是形成按位 oracle。

---

### CBC IV Recovery from Block-2 Known Plaintext (RITSEC 2018)

**模式：** 已知完整 AES-CBC 密文、从第 2 块开始的明文，以及部分 key。先利用第 2 块（它不依赖 IV）暴力缺失 key 字节，再用 `AES_decrypt(ct[0], K) XOR plaintext[0]` 反推出 IV。

```python
for tail in itertools.product(string.printable, repeat=2):
    K = base_key + ''.join(tail).encode()
    if AES.new(K, AES.MODE_ECB).decrypt(ct)[16:32] == plaintext[16:32]:
        raw = AES.new(K, AES.MODE_ECB).decrypt(ct[:16])
        IV = bytes(a ^ b for a, b in zip(raw, plaintext[:16]))
        break
```

**关键点：** CBC 第 2 块的解密使用的是上一块密文，而不是显式 IV，所以可以先独立恢复 key；拿到 key 后，再回头 XOR 出第 1 块所需的 IV。

**参考：** RITSEC CTF 2018，Who drew on my program，writeup 12269

---

### Iterated SHA-256 Timing Oracle on Character Match (35C3 2018)

**模式：** 服务端逐字符校验密码，每命中一个正确字符，就额外执行 9999 次 SHA-256。于是每猜对一个字符，响应会慢约 0.66 秒。对每个位置按时间差暴力即可。

```python
for ch in string.printable:
    t = time.time()
    send(prefix + ch)
    dt = time.time() - t
    if dt > baseline + 0.3:
        prefix += ch; break
```

**关键点：** 任何带早停的比较，只要每次命中会触发高代价哈希，就会产生强烈的逐位计时信号。比较时要看“相对基线差”，不要执着于绝对时间。

**参考：** 35C3 CTF 2018，ultra secret，writeup 12820

---

### GF(p) Linear-System AES Key Recovery from PCAP Matrix (35C3 Junior 2018)

**模式：** 服务端在网络中发送了 40 组明文 / 密文对。先用 tshark 从 pcap 中提取样本，再在 `GF(p)` 上构造一个 40×40 线性系统，直接求 AES round-key 字节。

```python
from sage.all import matrix, GF
A = matrix(GF(p), 40, A_rows)
key = A.solve_right(vector(GF(p), b))
```

用 `tshark -r file.pcap -Y 'data.len>0' -T fields -e data` 把有效负载导出来，解析成矩阵行后交给 Sage 即可。

**关键点：** 只要协议暴露了足够多“已知输入经过线性变换后的输出”，剩下就是线性代数。`solve_right` 足够处理这类题。

**参考：** 35C3 Junior CTF 2018，pretty-linear，writeups 12788, 12789

---

### SHA-1 Length Extension with UTF-8 High-Byte Bypass (OTW Advent 2018)

**模式：** 服务端对可做长度扩展的 SHA-1 MAC 做了“追加字节必须 `< 0x80`”的过滤。标准 `hashpumpy` / `hlextend` 产出的 padding 含有 `0x80` 等字节，会被拒绝。解决办法是把这些字节改写成合法 UTF-8 多字节序列（例如 `\xc2\x80` 对应 U+0080），绕过过滤，而 SHA-1 处理的仍是同样的字节流语义。

```python
import hlextend
h = hlextend.new('sha1')
forged = h.extend(b';cat flag', b'A'*msg_len, key_len, old_mac)
# 把 0x80-0xFF 改写成 UTF-8 两字节等价表示
safe = forged.replace(b'\x80', b'\xc2\x80')
```

**关键点：** “只允许 ASCII”的过滤并不能真正阻止长度扩展，只是把 payload 构造变麻烦了。只要编码层与哈希层的字节解释存在缝隙，就可以用 UTF-8 做绕过。

**参考：** OverTheWire Advent Bonanza 2018，Day 16，writeup 12754

---

### Cross-Session Cube-Root Recovery via CRT (X-MAS 2018)

**模式：** 服务端在多个会话中用不同模数 `N_i` 暴露相同小明文的 `m^3 mod N_i`。只要 `m^3 < N_1 * N_2 * N_3`，就可以通过 CRT 重建整数意义下的 `m^3`，再用 `iroot` 开立方恢复 `m`。

```python
from sympy.ntheory.modular import crt
from gmpy2 import iroot
m_cubed, _ = crt([N1, N2, N3], [c1, c2, c3])
m, exact = iroot(int(m_cubed), 3)
assert exact
```

**关键点：** 这就是 Håstad 广播攻击在“同一明文、多个模数”的直接特例。只要积足够大，CRT 就能把模方程还原成整数方程。

**参考：** X-MAS CTF 2018，Santa's list 2.0，writeup 12659

---

## CBC Previous-Block Byte Flipping for Cookie Privilege Escalation (picoCTF 2018)

**模式（Secured Logon）：** 服务端把 `{"username": "...", "admin": 0, ...}` 用 AES-CBC + base64 加密后返回为 cookie，但不做 MAC。若想把 `admin: 0` 改成 `admin: 1`，只要找到字符 `'0'` 在某个明文块 `P_{n+1}` 中的位置，再把**前一块**密文 `C_n` 对应字节 XOR 上 `ord('0') ^ ord('1')` 即可。`C_n` 所对应的前一明文块会变成垃圾，但 `P_{n+1}` 的目标字节会被精准翻转，因为 `P_{n+1} = AES_dec(C_{n+1}) XOR C_n`。

```python
from base64 import b64encode, b64decode

cookie = b64decode(stolen_cookie)              # IV || C1 || C2 || ...（或 C0||...）
buf    = bytearray(cookie)

# 明文块布局示例：
#   block 1: "{'username': '',"      <- 翻转后会变成垃圾
#   block 2: " 'admin': 0, 'pa"      <- 目标字节 10（字符 '0'）
#   block 3: "ssword': ''}"

# 要翻第 2 块明文的第 10 字节，就去改前一块密文的第 10 字节
# 若 cookie 带 IV，则偏移 = 16（IV） + 0*16（C1） + 10 = 26
# 若没有显式 IV，则偏移就是 10
offset = 10
buf[offset] ^= ord('0') ^ ord('1')             # 0x30 ^ 0x31 = 0x01

forged_cookie = b64encode(bytes(buf)).decode()
```

**关键点：** 在 CBC 中，翻 `C_n` 的某一位，只会精准翻到 `P_{n+1}` 的同一位；代价是 `P_n` 变成乱码。只要服务端能容忍前一块乱码（例如 JSON 解析宽松、未知字段被忽略），就能完成权限提升。与 [AES-CBC IV Bit-Flip (Google CTF 2016)](modern-ciphers-2.md#aes-cbc-iv-bit-flip-authentication-bypass-google-ctf-2016) 不同，那一招是改 IV，因此只影响第 0 块。
