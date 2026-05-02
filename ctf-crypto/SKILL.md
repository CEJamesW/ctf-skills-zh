---
name: ctf-crypto
description: 提供用于 CTF 挑战的密码学攻击技术。适用于攻击加密、哈希、签名、ZKP、PRNG，或涉及 RSA、AES、ECC、格、LWE、CVP、数论、Coppersmith、Pollard、Wiener、填充预言机、GCM、密钥派生、流密码/分组密码弱点等数学密码学问题。
license: MIT
compatibility: 需要基于文件系统的代理（Claude Code 或类似工具），以及 bash、Python 3 和互联网访问以安装工具。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF 密码学

Crypto CTF 挑战的快速参考。这里先给出每种技术的一句话摘要；完整细节和代码见对应支撑文件。

## 前置依赖

**Python 包（全平台）：**
```bash
pip install pycryptodome z3-solver sympy gmpy2 hashpumpy fpylll py_ecc
```

**Linux (apt)：**
```bash
apt install hashcat sagemath
```

**macOS (Homebrew)：**
```bash
brew install hashcat
```

**手动安装：**
- SageMath：Linux 用 `apt install sagemath`，macOS 用 `brew install --cask sage`
- RsaCtfTool：`git clone https://github.com/RsaCtfTool/RsaCtfTool`（自动化 RSA 攻击工具）

> **注意：** `gmpy2` 依赖 libgmp。Linux：`apt install libgmp-dev`，macOS：`brew install gmp`。

## 补充资源

- [classic-ciphers.md](classic-ciphers.md) - 古典密码：维吉尼亚（含 Kasiski 检验）、Atbash、替换轮盘、XOR 变体（含多字节频率分析）、确定性 OTP、级联 XOR、书本密码、OTP 密钥复用 / many-time pad、变长同音替换、网格置换密码密钥空间缩减、基于图像的凯撒位移密码、通过文件格式头恢复 XOR 密钥
- [modern-ciphers.md](modern-ciphers.md) - 现代密码攻击：AES（CFB-8、ECB 泄露）、CBC-MAC/OFB-MAC、填充预言机、S 盒碰撞、GF(2) 消元、LCG 部分输出恢复、复合模数下的仿射密码、派生密钥的 AES-GCM、AES-GCM nonce 复用（forbidden attack）、类 Ascon 约减轮差分分析、自定义线性 MAC 伪造、CBC 填充预言机（完整分组解密）、Bleichenbacher RSA PKCS#1 v1.5 填充预言机（ROBOT）、生日攻击 / 中间相遇、CRC32 碰撞签名伪造、逐字节清零预言机恢复 AES 密钥、通过错误信息解密预言机伪造 AES-CBC 密文
- [modern-ciphers-2.md](modern-ciphers-2.md) - 现代密码攻击（第二部分）：Blum-Goldwasser 比特扩展预言机、哈希长度扩展、压缩预言机（CRIME 风格）、通过环检测反转哈希函数时间演化、可逆 RNG 的 OFB 模式逆向解密、通过公钥哈希 XOR 的弱密钥派生、HMAC-CRC 线性攻击、OFB 模式中的 DES 弱密钥、SRP 协议绕过、修改版 AES S 盒暴力、约减轮 AES 的 square attack、AES-ECB 逐字节选择明文、AES-ECB 剪贴拼接分组操纵、AES-CBC IV 位翻转认证绕过、Rabin LSB 奇偶预言机、PBKDF2 预哈希绕过、利用 fastcol 的 MD5 多重碰撞
- [modern-ciphers-3.md](modern-ciphers-3.md) - 现代密码攻击（第三部分）：自定义哈希状态反演、小载荷 CRC32 暴力、带噪声的 RSA LSB 预言机纠错、海绵哈希 MITM 碰撞、CBC IV 伪造 + 截断分组、由填充预言机转 CBC bitflip RCE、SPN S 盒交集攻击、时间戳种子 PRNG 的 AES-CFB IV 恢复、三轮 XOR 协议的密钥相消、AES-CBC UnicodeDecodeError 侧信道预言机、针对 XOR 聚合哈希绕过的 SHA-256 基攻击、通过 XOR 分组抵消伪造自定义 MAC、通过 XOR+加法算术恢复 HMAC 密钥
- [stream-ciphers.md](stream-ciphers.md) - 流密码攻击：LFSR（Berlekamp-Massey、相关攻击、已知明文、Galois vs Fibonacci、通过自相关恢复 Galois tap）、RC4 第二字节偏差、相邻字节 XOR 相关性
- [rsa-attacks.md](rsa-attacks.md) - RSA 攻击：小 e（开立方根）、共模、Wiener、Pollard p-1、Hastad 广播、带线性填充的 Hastad（Coppersmith）、Franklin-Reiter 相关消息（e=3）、Coppersmith 线性相关素数、Fermat / 连续素数、多素数、受限数字素数、结构化素数上的 Coppersmith、Manger 预言机、多项式哈希
- [rsa-attacks-2.md](rsa-attacks-2.md) - RSA 攻击（专项）：RSA `p=q` 校验绕过、`gcd(e,phi)>1` 的立方根 CRT、从 `phi(n)` 的倍数分解、乘法同态签名伪造、基表示导致的弱密钥生成、`gcd(e,phi)>1` 时的指数约化、批量 GCD 共素因子分解、从 `dp/dq/qinv` 恢复部分私钥、RSA-CRT 故障攻击、同态解密预言机绕过、小素数 CRT 分解、Montgomery 约减计时攻击、低指数 Bleichenbacher 签名伪造、`e=1` 且伪造模数时的 RSA 签名绕过
- [ecc-attacks.md](ecc-attacks.md) - ECC 攻击：小子群、无效曲线、Smart 攻击（异常曲线，含 Sage 代码）、故障注入、clock group 离散对数、Pohlig-Hellman、ECDSA nonce 复用、Ed25519 扭点侧信道、DSA nonce 复用、利用 MD5 碰撞影响 k 生成从而恢复 DSA 密钥
- [zkp-and-advanced.md](zkp-and-advanced.md) - ZKP / 图 3-着色、Z3 求解器指南、混淆电路、Shamir SSS、二元组约束求解、竞态条件、Groth16 损坏 setup、DV-SNARG 伪造、KZG pairing 预言机恢复置换、复用多项式系数的 Shamir SSS
- [prng.md](prng.md) - PRNG 攻击（基础）：MT19937、通过 GF(2) 魔法矩阵从 MT 浮点输出恢复以预测 token、LCG、GF(2) 矩阵 PRNG、通过 Z3 恢复 V8 XorShift128+ `Math.random()` 状态、中平方、确定性 RNG 爬山搜索、随机模式预言机、时间种子、通过 ctypes 同步 C 的 `srand/rand`、密码破解、logistic map 混沌 PRNG
- [prng-attacks.md](prng-attacks.md) - PRNG 攻击（CTF 时代，2017+）：MT 子集和种子恢复、MT19937 约束传播、通过 Z3 逆 Rule 86 元胞自动机、Java LCG 对部分模值的中间相遇、利用模逆逆推 LCG、LFSR bit-fold ASCII 奇偶恢复、Z3 求解时间侧信道、利用 randcrack 预测 DSA k、格式化字符串导致的 PRNG 种子偏移、NTP 污染 PRNG 下的 UUID XOR
- [historical.md](historical.md) - 历史密码（Lorenz SZ40/42、书本密码实现）
- [advanced-math.md](advanced-math.md) - 高等数学攻击（同源、Pohlig-Hellman、通用 DLP 的 baby-step giant-step、LLL、利用 LLL 攻击 Merkle-Hellman 背包、Coppersmith、四元数 RSA、GF(2)[x] 上的 CRT、S 盒碰撞代码、LWE 格 CVP 攻击、非素数模上的仿射密码、GF(2) 线性代数下的 introspective CRC）
- [lattice-and-lwe.md](lattice-and-lwe.md) - 格攻击分诊与流程：LLL/BKZ/Babai、部分或偏置 nonce 导出的 HNP、截断 LCG 状态恢复、LWE 嵌入与 CVP、Ring-LWE / Module-LWE 识别、正交格、subset sum / knapsack，以及常见失败模式
- [exotic-crypto.md](exotic-crypto.md) - 异构代数结构（辫群 DH / Alexander 多项式、单调函数求逆、热带半环 residuation、Paillier 密码体制、海明码螺旋交织、ElGamal 通用重加密、FPE Feistel 暴力、二十面体对称群密码、Goldwasser-Micali 复制预言机）
- [exotic-crypto-2.md](exotic-crypto-2.md) - 异构代数结构（第二部分，2017+）：BB-84 QKD 中间人、ElGamal 平凡 DLP（`B=p-1`）、通过同态倍增实现的 Paillier LSB 预言机、差分隐私噪声抵消、同态加密取位、Jordan 标准形下的矩阵 ElGamal、利用 Pollard 的 OSS 签名伪造、无需私钥的 Cayley-Purser 解密、BIP39 部分助记词校验和暴力、Asmuth-Bloom CRT 门限恢复、使用多项式素数的 Rabin、LCG 周期检测、Vandermonde 多项式系数恢复

---

## 何时切换

- 如果真正的瓶颈是理解二进制、混淆客户端或奇怪的 VM，请切换到 `/ctf-reverse`。
- 如果挑战主要是抓包取证、磁盘恢复或隐写提取，尚未进入解密阶段，请切换到 `/ctf-forensics`。
- 如果密码学部分已经解决，剩下只是对脆弱网络服务实现利用，请切换到 `/ctf-pwn` 或 `/ctf-web`。
- 如果密码挑战涉及对抗式 ML、模型提取或神经网络密码，请切换到 `/ctf-ai-ml`。
- 如果题目本质上更像编码谜题、怪异密码或多义技巧，而不是真正的密码分析，请切换到 `/ctf-misc`。

## 快速开始命令

```bash
# 识别密码类型
python3 -c "from Crypto.Util.number import *; n=<N>; print(f'bits={n.bit_length()}')"

# RSA 快速检查
python3 -c "from sympy import factorint; print(factorint(<n>))"  # 有小因子吗？
openssl rsa -pubin -in key.pub -text -noout  # 从 PEM 中提取 n、e

# 快速分解工具
python3 RsaCtfTool.py -n <n> -e <e> --uncipher <c>

# XOR 分析
python3 -c "from pwn import xor; print(xor(bytes.fromhex('<hex>'), b'flag{'))"

# 哈希识别
hashid '<hash>'
hashcat --identify '<hash>'

# SageMath（格 / ECC）
sage -c "print(factor(<n>))"
```

## Classic Ciphers

- **Caesar：** 频率分析或暴力枚举 26 个密钥。
- **Vigenere：** 利用 flag 格式前缀做已知明文攻击；通过 `(ct - pt) mod 26` 导出密钥。未知密钥长度时用 Kasiski 检验（重复序列距离的 GCD）。
- **Atbash：** A<->Z 替换；留意题名中的 “Abashed” 一类提示。
- **Substitution wheel：** 暴力所有内外字母表的相对旋转。
- **Multi-byte XOR：** 按密钥位置拆分密文，对每一列独立做频率分析；按英文字符频率评分（空格 = `0x20`）。
- **Cascade XOR：** 暴力首字节（256 次），其余字节会被确定性推出。
- **XOR rotation (power-of-2)：** 偶数位和奇数位永不混合；只有 4 个候选状态。
- **Weak XOR verification：** 单字节 XOR 校验只有 `1/256` 通过率；交互预算足够时直接暴力。
- **Deterministic OTP：** 通过已知明文 XOR 恢复密钥流；注意匹配负载均衡后的同一后端。
- **OTP key reuse (many-time pad)：** `C1 XOR C2 XOR known_P = unknown_P`；无已知明文时做 crib dragging。
- **Homophonic (variable-length)：** 多字符密文分组映射到单个明文字母。寻找所有子 n-gram 频率完全一致的 n-gram，用单符号替换后按单表替换求解。见 [classic-ciphers.md](classic-ciphers.md#variable-length-homophonic-substitution-asis-ctf-finals-2013)。
- **Grid permutation cipher：** 5x5 网格的行列独立置换将密钥空间压缩为 `5! x 5! = 14,400`；可在毫秒级暴力。见 [classic-ciphers.md](classic-ciphers.md#grid-permutation-cipher-keyspace-reduction-bsidessf-2026)。
- **Image-based Caesar shift：** 像素行/列按条带偏移；对比原图与位移图，从偏移量中提取 ASCII 编码的 flag。见 [classic-ciphers.md](classic-ciphers.md#image-based-caesar-shift-ciphers-bsidessf-2026)。
- **Polybius square cipher：** 5x5 网格把字母对映射为明文；数字 / 坐标编码位置。见 [classic-ciphers.md](classic-ciphers.md#polybius-square-cipher-qiwi-infosec-2016)。
- **XOR key recovery via file format headers：** 文件声称是 PDF/PNG/ZIP，但 `file` 只识别为 `data`。把前几个字节与预期魔数 XOR 得到循环密钥，再利用尾部结构（`%%EOF`、IEND 标记）扩展。见 [classic-ciphers.md](classic-ciphers.md#xor-key-recovery-via-file-format-headers-metactf-flash-2026)。

完整代码示例见 [classic-ciphers.md](classic-ciphers.md)。

## Modern Cipher Attacks

- **AES-ECB：** 分组重排、逐字节选择明文恢复后缀（每字节 256 次查询，工具：FeatherDuster `ecb_cpa_decrypt`）；图像在 ECB 下保留可视模式。ECB 剪贴拼接：拼接密文分组伪造 JSON 字段（如 `is_admin: true`）。见 [modern-ciphers-2.md](modern-ciphers-2.md#aes-ecb-byte-at-a-time-chosen-plaintext-abctf-2016)。
- **AES-CBC：** 通过位翻转改变明文；填充预言机可在无密钥情况下解密。IV bit-flip：翻 IV 的特定位来改写第一块明文（前提是没有 MAC）。见 [modern-ciphers-2.md](modern-ciphers-2.md#aes-cbc-iv-bit-flip-authentication-bypass-google-ctf-2016)。
- **CBC IV forgery + block truncation：** XOR IV 字节修改解密后的第 0 块；截断尾部分组（CBC 无长度完整性保护）。当 MAC 内嵌在密文中时可伪造认证令牌。见 [modern-ciphers-2.md](modern-ciphers-3.md#cbc-iv-forgery--block-truncation-for-authentication-bypass-0ctf-2017)。
- **Padding oracle to CBC bitflip RCE：** 将填充预言机（恢复明文）和 CBC bitflip（注入 shell 元字符）串起来，对加密参数达成命令注入。见 [modern-ciphers-2.md](modern-ciphers-3.md#padding-oracle-to-cbc-bitflip-command-injection-bsidessf-2017)。
- **AES-CFB-8：** 静态 IV + 8 位反馈使得在 16 个已知字节后可以重建状态。
- **CBC-MAC/OFB-MAC：** 通过 XOR 密钥流伪造签名：`new_sig = old_sig XOR block_diff`。
- **S-box collisions：** 非置换 S 盒（`len(set(sbox)) < 256`）允许通过 4,097 次查询恢复密钥。
- **GF(2) elimination：** 线性哈希函数（XOR + 轮转）可在 GF(2) 上高斯消元求解。
- **Padding oracle：** 修改前一块并测试填充有效性，逐字节解密。
- **LFSR stream ciphers：** Berlekamp-Massey 用 2L 个密钥流比特恢复反馈多项式；带偏置组合函数的多个 LFSR 可用相关攻击破解。
- **Galois LFSR tap recovery：** 用已知文件头（PNG/PDF/ZIP）与密文 XOR 得到密钥流；切成 N 位窗口，对 `LSB=1` 的转移计算 `(state >> 1) XOR next_state` 直接恢复 tap mask。用自相关滑动找到正确长度。见 [stream-ciphers.md](stream-ciphers.md#galois-lfsr-tap-recovery-via-autocorrelation-bsidessf-2026)。
- **OFB with invertible RNG：** 任意块中的已知明文会泄露 RNG 状态；若状态转移是双射，就能把 RNG 反推回去解出所有块。见 [modern-ciphers-2.md](modern-ciphers-2.md#ofb-mode-with-invertible-rng-backward-decryption-bsidessf-2026)。
- **Weak key derivation (public key hash XOR)：** 从 `SHA256(public_key) XOR seed` 派生的 AES 密钥无需私钥即可完全恢复；“混合式” RSA+AES 实际没有安全性。见 [modern-ciphers-2.md](modern-ciphers-2.md#weak-key-derivation-via-public-key-hash-xor-bsidessf-2026)。
- **HMAC-CRC linearity：** CRC 在 GF(2) 上是线性的，因此从一组消息-MAC 对就能用多项式算术恢复 HMAC-CRC 的密钥。见 [modern-ciphers-2.md](modern-ciphers-2.md#hmac-crc-linearity-attack-boston-key-party-2016)。
- **DES weak keys in OFB：** 4 个 DES 弱密钥使加密成为自反；OFB 密钥流周期为 2，可退化为 16 字节循环 XOR。见 [modern-ciphers-2.md](modern-ciphers-2.md#des-weak-keys-in-ofb-mode-boston-key-party-2016)。
- **Square attack (reduced-round AES)：** 4 轮 AES 可被积分密码分析破坏：使用 256 明文的 lambda 集合，猜最后一轮字节并用异或和为 0 区分。见 [modern-ciphers-2.md](modern-ciphers-2.md#square-attack-on-reduced-round-aes-0ctf-2016)。
- **AES-GCM nonce reuse (forbidden attack)：** 相同 nonce = CTR 密钥流复用 + 通过 GF(2^128) 多项式分解恢复 GHASH 认证密钥。工具：`nonce-disrespect`。见 [modern-ciphers.md](modern-ciphers.md#aes-gcm-nonce-reuse--forbidden-attack)。
- **SRP protocol bypass：** 发送 `A = 0` 或 `A = n` 可强制共享秘密为 0，完全绕过口令验证。见 [modern-ciphers-2.md](modern-ciphers-2.md#srp-secure-remote-password-protocol-bypass-via-modular-arithmetic-asis-ctf-finals-2016)。
- **Modified AES S-Box brute force：** 自定义 S 盒只有 16 个唯一输出，显著降低密钥熵，可逐轮暴力候选字节。见 [modern-ciphers-2.md](modern-ciphers-2.md#modified-aes-s-box-brute-force-recovery-h4ckit-ctf-2016)。
- **Rabin LSB parity oracle：** Rabin 密文 `c = m^2 mod n` 搭配最低位预言机，可用乘法同态（`c * 4 mod n` 使明文翻倍）在 `log2(n)` 次查询内二分恢复明文。见 [modern-ciphers-2.md](modern-ciphers-2.md#rabin-cryptosystem-lsb-parity-oracle-plaidctf-2016)。
- **Noisy RSA LSB oracle error correction：** 当 LSB 预言机偶发出错时，先跑标准攻击，再检查输出字符集；翻转出错位置的预言机结果即可修正剩余解密。见 [modern-ciphers-2.md](modern-ciphers-3.md#noisy-rsa-lsb-oracle-with-post-hoc-error-correction-sharifctf-7-2016)。
- **PBKDF2 pre-hash bypass：** HMAC 会对长度超过 64 字节的密钥做预哈希（SHA-1/SHA-256 块大小）。原始口令超过 64 字节时，可用 `SHA1(password)` 代替 `password` 登录。见 [modern-ciphers-2.md](modern-ciphers-2.md#pbkdf2-pre-hash-bypass-for-long-passwords-backdoorctf-2016)。
- **MD5 multi-collision (fastcol)：** 链式调用 `fastcol` 生成 `2^k` 个 MD5 相同的文件。Merkle-Damgard 组合下，碰撞会沿附加后缀传播。见 [modern-ciphers-2.md](modern-ciphers-2.md#md5-multi-collision-via-fastcol-backdoorctf-2016)。
- **Custom hash state reversal：** 迭代哈希泄露中间状态时，可通过反推状态更新方程分离各分组的哈希值，然后对每个 4 字节分组独立暴力。见 [modern-ciphers-2.md](modern-ciphers-3.md#custom-hash-state-reversal-via-known-intermediates-backdoorctf-2016)。
- **CRC32 brute-force (small payloads)：** ZIP 的 CRC32 头部未加密；对小文件（≤ 6 字节）可暴力所有可打印字符串，与存储 CRC32 比对恢复内容。见 [modern-ciphers-2.md](modern-ciphers-3.md#crc32-brute-force-for-small-payloads-backdoorctf-2016)。
- **Custom MAC forgery via XOR block cancellation：** 当 MAC 密钥流周期性重复时，构造 3 次查询让填充分组相互 XOR 抵消，从而伪造任意目标命令的 MAC。见 [modern-ciphers-2.md](modern-ciphers-3.md#custom-mac-forgery-via-xor-block-cancellation-with-key-rotation-plaidctf-2018)。
- **HMAC key recovery (XOR + addition arithmetic)：** 有缺陷的 HMAC 采用 `sha256((key XOR msg) + msg)`，会逐位泄露密钥：`msg=0` 给出 `sha256(key)`，`msg=2^i` 只有在密钥第 i 位为 1 时匹配。见 [modern-ciphers-2.md](modern-ciphers-3.md#bit-by-bit-hmac-key-recovery-via-xor-plus-addition-arithmetic-midnight-sun-ctf-2018)。
- **AES-CBC ciphertext forging (error-message oracle)：** 服务器在错误信息中泄露解密字节；发送全零分组可学出中间状态，再与目标明文 XOR，逐块伪造密文。见 [modern-ciphers.md](modern-ciphers.md#aes-cbc-ciphertext-forging-via-error-message-decryption-oracle-nuit-du-hack-ctf-2018)。

完整示例见 [modern-ciphers.md](modern-ciphers.md) 和 [modern-ciphers-2.md](modern-ciphers-2.md)。

## RSA Attacks

- **Small e with small message：** 直接开 e 次方根。
- **Common modulus：** 扩展 GCD 攻击。
- **Wiener's attack：** `d` 很小。
- **Fermat factorization：** `p` 和 `q` 非常接近。
- **Pollard's p-1：** `p-1` 很 smooth。
- **Hastad's broadcast：** 同一消息被多次以 `e=3` 加密。
- **Consecutive primes：** `q = next_prime(p)`；从 `sqrt(N)` 下方的第一个素数开始找。
- **Multi-prime：** 用 sympy 分解 `N`，再由所有因子计算 `phi`。
- **Restricted-digit primes：** 从低位开始逐位分解，并结合模约束剪枝。
- **Coppersmith structured primes：** 素数部分已知；在 SageMath 中用 `f.small_roots()`。
- **Manger oracle (simplified)：** 第一阶段倍增，第二阶段二分；对 64 位密钥约 128 次查询。
- **Manger on RSA-OAEP (timing)：** Python 的 `or` 短路在 `Y != 0` 时跳过昂贵的 PBKDF2，形成快/慢计时预言机。完整 3 步攻击对 1024 位 RSA 约需 1024 轮；用已知快/慢样本校准阈值。
- **Polynomial hash (trivial root)：** 多项式哈希中 `g(0) = 0`；构造后缀使 `msg = 0 (mod P)`，则签名也为 0。
- **Polynomial CRT in GF(2)[x]：** 收集约 20 个余数 `r = flag mod f`，筛掉不互素的后做 CRT 合并。
- **Affine over composite modulus：** 在每个素因子域内分别做 CRT；每个素模上做高斯-约旦消元。
- **RSA p=q validation bypass：** 设置 `p=q` 让服务端错误计算 `phi=(p-1)^2` 而不是 `p*(p-1)`；测试解密失败时会泄露密文。
- **RSA cube root CRT (gcd(e,phi)>1)：** 当所有素数都满足 `p ≡ 1 mod e` 时，可用 `nthroot_mod` 分别求每个素数模下的 e 次根，再枚举 CRT 组合（对小 k，`3^k` 是可行的）。
- **Factoring from phi(n) multiple：** 任何 `phi(n)` 的倍数（如 `e*d-1`）都可用 Miller-Rabin 的平方根技巧分解；每次尝试成功概率至少 `1/2`。
- **Weak keygen via base representation：** 若素数形如 `p = kp*B + tp` 且 `kp` 很小，则 `n` 具有混合进制结构；暴力 `kp*kq`（约 `2^24`）即可分解。
- **RSA with gcd(e,phi)>1 (exponent reduction)：** 令 `e' = e/g`，求 `d' = e'^(-1) mod phi`，部分解密得到 `m^g`，再在整数上开 g 次方根。
- **RSA partial key recovery (dp/dq/qinv)：** 部分 PEM 泄露的 CRT 指数允许 `O(e)` 恢复素数：枚举 `k`，检查 `(dp*e-1)/k+1` 是否为素数。见 [rsa-attacks-2.md](rsa-attacks-2.md#rsa-partial-key-recovery-from-dp-dq-qinv-0ctf-2016)。
- **RSA-CRT fault attack：** 单个故障 CRT 签名可通过 `gcd(s^e - m, n)` 泄露因子（Bellcore 攻击）。见 [rsa-attacks-2.md](rsa-attacks-2.md#rsa-crt-fault-attack--bit-flip-recovery-csaw-ctf-2016)。
- **RSA homomorphic decryption bypass：** 乘法同态使你可以查询 `c * r^e mod n`，再把结果除以 `r`，从而解出原始 `c`。见 [rsa-attacks-2.md](rsa-attacks-2.md#rsa-homomorphic-decryption-oracle-bypass-ectf-2016)。
- **RSA small prime CRT decomposition：** 若 `n` 含有许多小素因子，就试除分解，分别求 `m mod p_i`，再用 CRT 合并。见 [rsa-attacks-2.md](rsa-attacks-2.md#rsa-with-small-prime-factors-and-crt-decomposition-hack-the-vote-2016)。
- **Hastad broadcast with linear padding (Coppersmith)：** 若 e 个接收者在加密前各自应用已知仿射变换 `a_i*m+b_i`，则 CRT + Coppersmith `small_roots` 可恢复 `m`。见 [rsa-attacks.md](rsa-attacks.md#hastad-broadcast-attack-with-linear-padding----coppersmith-plaidctf-2017)。
- **RSA Montgomery reduction timing attack：** Montgomery 乘法中的额外减法次数泄露私钥位，可通过统计相关性按从高位到低位恢复。见 [rsa-attacks-2.md](rsa-attacks-2.md#rsa-timing-attack-on-montgomery-reduction-def-con-2017)。
- **Bleichenbacher low-exponent signature forgery：** 在 `e=3` 时，构造带正确填充前缀的值并开立方根即可伪造 PKCS#1 v1.5 签名；尾部垃圾会吸收剩余误差。见 [rsa-attacks-2.md](rsa-attacks-2.md#bleichenbacher-low-exponent-rsa-signature-forgery-google-ctf-2017)。
- **Franklin-Reiter related message attack (e=3)：** 两个密文分别对应 `m+pad1` 和 `m+pad2`，且已知填充差值；在 `Zmod(n)` 上做多项式 GCD 可直接恢复 `m`。见 [rsa-attacks.md](rsa-attacks.md#franklin-reiter-related-message-attack-on-rsa-e3-n1ctf-2018)。
- **RSA signature bypass (e=1, crafted modulus)：** 验证器允许用户自带 `(n, e)`；设 `e=1` 且 `n = sig - PKCS1_pad(msg)`，即可让 `pow(sig, 1, n)` 等于期望的填充哈希。见 [rsa-attacks-2.md](rsa-attacks-2.md#rsa-signature-bypass-with-e1-and-crafted-modulus-backdoorctf-2018)。
- **Coppersmith on linearly-related primes：** 当 `q ~ k*p` 且已知 `k` 时，取 `q ~ sqrt(k*n)`，再对误差项做 Coppersmith `small_roots`。这是 Fermat 分解对非连续素数情形的推广。见 [rsa-attacks.md](rsa-attacks.md#coppersmith-attack-on-linearly-related-rsa-primes-asis-ctf-2018)。

完整代码示例见 [rsa-attacks.md](rsa-attacks.md) 和 [advanced-math.md](advanced-math.md)。

## Elliptic Curve Attacks

- **Small subgroup：** 检查曲线阶的小因子；Pohlig-Hellman + CRT。
- **Invalid curve：** 若缺少点验证，可发送位于更弱曲线上的点。
- **Singular curves：** 判别式为 0 时，DLP 会退化到加法群或乘法群。
- **Smart's attack：** 异常曲线（`#E = p`）可通过 p-adic lift 在 `O(1)` 内解 DLP。
- **Baby-step giant-step (BSGS)：** 通用 DLP 为 `O(sqrt(n))` 时间/空间。对 smooth 阶群（`p-1` 或曲线阶的所有因子都小）可与 Pohlig-Hellman 结合。Sage：`discrete_log(Mod(h,p), Mod(g,p))`。见 [advanced-math.md](advanced-math.md#baby-step-giant-step-for-general-dlp)。
- **Fault injection：** 对比正确输出和故障输出，逐位恢复密钥。
- **Clock group (`x^2+y^2=1`)：** 群阶是 `p+1`（不是 `p-1`）；当 `p+1` 很 smooth 时用 Pohlig-Hellman。
- **Isogenies：** 通过模多项式做图遍历，再用 LCA 找路径。
- **ECDSA nonce reuse：** 两个签名若 `r` 相同，就能通过模运算恢复 nonce `k` 和私钥 `d`。优先检查是否存在重复 `r`。
- **Braid group DH：** Alexander 多项式在辫子拼接下具有乘法性，因此 Eve 可从公开值直接计算共享秘密。见 [exotic-crypto.md](exotic-crypto.md#braid-group-dh--alexander-polynomial-multiplicativity-dicectf-2026)。
- **Ed25519 torsion side channel：** 当密钥派生为 `key = master * uid mod l` 时，余因子 `h=8` 会泄露秘密标量位；查询 2 的幂并检查 y 坐标一致性。
- **Tropical semiring residuation：** 热带（min-plus）DH 是可破的；残差 `b* = max(Mb[i] - M[i][j])` 可直接从公开矩阵恢复共享秘密。
- **FPE Feistel brute-force：** 轮密钥只有 16 位的格式保持加密可直接暴力；剩余的 GF(2) 仿射混合层可通过高斯消元求解。见 [exotic-crypto.md](exotic-crypto.md#format-preserving-encryption-feistel-brute-force-bsidessf-2026)。
- **Icosahedral symmetry cipher：** 十二面体面置换构成阶为 120 的群；可通过 API 探测建立全部置换查找表，再匹配可见面模式。见 [exotic-crypto.md](exotic-crypto.md#icosahedral-symmetry-group-cipher-bsidessf-2026)。
- **Goldwasser-Micali replication oracle：** GM 每个密文只加密 1 bit；把同一个密文值重复 N 次当成 N 位密钥，会强制得到全 0 或全 1 密钥，再通过哈希预言机区分。128 次查询可恢复完整 AES 密钥。见 [exotic-crypto.md](exotic-crypto.md#goldwasser-micali-ciphertext-replication-oracle-bsidessf-2026)。
- **DSA nonce reuse：** 两个 DSA 签名若 `r` 相同，可用与 ECDSA 相同的公式恢复私钥。见 [ecc-attacks.md](ecc-attacks.md#dsa-nonce-reuse-for-private-key-recovery-volgactf-2016)。
- **DSA limited k brute force：** 当 nonce `k` 很小（如 20 位）时，枚举所有 `k` 并检查哪个产生已知的 `r`。见 [ecc-attacks.md](ecc-attacks.md#dsa-limited-k-value-brute-force-asis-ctf-finals-2016)。
- **ECC shared prime GCD：** 多条 ECC 曲线的模数共享素因子；`gcd(n1, n2)` 直接揭示该素因子。见 [ecc-attacks.md](ecc-attacks.md#ecc-shared-prime-factor-via-gcd-asis-ctf-finals-2016)。
- **DSA key recovery via MD5 collision on k-generation：** 当 `k` 来源于 `MD5(prefix+counter)` 时，可用 `fastcoll` 生成 MD5 前缀碰撞强制 nonce 复用，再做标准私钥恢复。见 [ecc-attacks.md](ecc-attacks.md#dsa-key-recovery-via-md5-collision-on-k-generation-confidence-ctf-2017)。
- **BB-84 QKD MITM：** 模拟版 BB-84 若经典信道未认证，则可被完全中间人；分别与双方协商密钥，并向其中一方强制常量值。见 [exotic-crypto-2.md](exotic-crypto-2.md#bb-84-quantum-key-distribution-mitm-attack-plaidctf-2017)。

完整示例见 [ecc-attacks.md](ecc-attacks.md)、[advanced-math.md](advanced-math.md) 和 [exotic-crypto.md](exotic-crypto.md)。

## Lattice / LWE Attacks

- **Quick triage：** 如果题目给出模线性方程，并承诺隐藏量很小、稀疏、有偏或只有部分泄露，优先把它当成格问题。见 [lattice-and-lwe.md](lattice-and-lwe.md#quick-triage-is-this-a-lattice-problem)。
- **LLL / BKZ / Babai：** 从 LLL 开始；LLL 差一点时升级 BKZ；约减之后用 Babai 解近似 CVP。见 [lattice-and-lwe.md](lattice-and-lwe.md#core-tools-lll-bkz-babai-cvp-svp-asis-ctf-finals-2015-ctfzone-2017)。
- **HNP from partial nonce leakage：** ECDSA / Schnorr 的部分或偏置 nonce 往往可归约成 Hidden Number Problem 格；先规范化方程、隔离有界误差、做约减，最后必要时暴力剩余几位。见 [lattice-and-lwe.md](lattice-and-lwe.md#hidden-number-problem-hnp-partial-nonce--biased-nonce-nullcon-hackim-2020-ledger-donjon-ctf-2020)。
- **Truncated LCG state recovery：** 高位或低位泄露的仿射递推，本质上常是伪装成 HNP；把状态写成 `observed * 2^t + hidden`，再解小的隐藏修正项。见 [lattice-and-lwe.md](lattice-and-lwe.md#lcg-and-truncated-output-as-a-lattice-problem-x-mas-ctf-2018-fwordctf-2020)。
- **LWE via CVP (Babai)：** 从 `[q*I | 0; A^T | I]` 构造格，用 `fpylll` 的 `CVP.babai` 找最近向量，再投影到三元集合 `{-1,0,1}`。注意服务端描述和实际编码之间的字节序差异。
- **Ring-LWE / Module-LWE recognition：** 多项式或负循环结构看上去很吓人，但很多 CTF 会因为系数过小、表示有 bug、或泄露太多，而可以重新摊平成普通 LWE。见 [lattice-and-lwe.md](lattice-and-lwe.md#ring-lwe--module-lwe-recognition-notes-plaidctf-2016-dicectf-2022)。
- **Orthogonal lattices：** 隐藏子集或隐藏子空间问题可能需要先恢复正交格，再从其补空间中重构真实的二元基或短基。见 [lattice-and-lwe.md](lattice-and-lwe.md#orthogonal-lattices-hssp--ahssp-style-recovery-zer0pts-ctf-2022)。
- **LLL for approximate GCD：** 格中的短向量会泄露隐藏因子。
- **Subset sum / knapsack：** 二元背包与低密度 subset-sum 仍是典型格问题；构造标准基后，寻找最后一列为 0 的约减行。见 [lattice-and-lwe.md](lattice-and-lwe.md#subset-sum--knapsack-via-lattice-reduction-hitcon-ctf-2017-backdoorctf-2023)。
- **Multi-layer challenges：** 几何 -> 子空间恢复 -> LWE -> AES-GCM 解密 的多层链路。

LWE 的完整求解代码见 [advanced-math.md](advanced-math.md)，而攻击选择、嵌入方法和失败模式分诊见 [lattice-and-lwe.md](lattice-and-lwe.md)。

## ZKP & Constraint Solving

- **ZKP cheating：** 对不可能问题（如 K4 的 3-着色），要找哈希碰撞或预测 PRNG 盐值。
- **Graph 3-coloring：** `nx.coloring.greedy_color(G, strategy='saturation_largest_first')`
- **Z3 solver：** 位级约束用 BitVec，大整数用 Int；也适合解 BPF / SECCOMP 过滤器。
- **Garbled circuits (free XOR)：** XOR 三条真值表项即可恢复全局 delta。
- **Bigram substitution：** 对已知明文结构，用带 automaton 约束的 OR-Tools CP-SAT。
- **Trigram decomposition：** 对位置模 n 分组后，每组都是独立的单表替换。
- **Shamir SSS (deterministic coefficients)：** 一个 share + 带种子的 RNG，可化成关于 secret 的一元方程。
- **Race condition (TOCTOU)：** 同步并发请求可绕过 `counter < N` 检查。
- **Groth16 broken setup (delta==gamma)：** 可直接伪造：`A=alpha, B=beta, C=-vk_x`。先检查 verifier 常量。
- **Groth16 proof replay：** 若 nullifier 不受约束且不做跟踪，则可从 setup 交易无限重放证明。
- **DV-SNARG forgery：** 有 verifier 预言机时，可从不受约束的 pair 中学出秘密 `v` 值，再通过 CRS 项抵消完成伪造。
- **Shamir SSS reused polynomial coefficients：** 如果每个 secret byte 都复用了同一组随机系数，那么 share 相减会消掉全部随机性，只剩明文差值。见 [zkp-and-advanced.md](zkp-and-advanced.md#shamir-secret-sharing-with-reused-polynomial-coefficients-polictf-2017)。

完整代码示例和求解模式见 [zkp-and-advanced.md](zkp-and-advanced.md)。

## Modern Cipher Attacks (Additional)

- **Affine over composite modulus：** `c = A*x+b (mod M)`，其中 M 为复合数（如 65=5*13）。使用 one-hot 向量做选择明文恢复，再在各素因子上做 CRT 逆运算。见 [modern-ciphers.md](modern-ciphers.md#affine-cipher-over-composite-modulus-nullcon-2026)。
- **Custom linear MAC forgery：** 基于 XOR 的签名对秘密分组是线性的。通过约 5 组已知对恢复 secret，然后为目标消息伪造。见 [modern-ciphers.md](modern-ciphers.md#custom-linear-mac-forgery-nullcon-2026)。
- **Manger oracle (RSA threshold)：** 利用 RSA 乘法性质 + 对 `m*s < 2^128` 的二分搜索；约 128 次查询恢复 AES 密钥。
- **AES key recovery via byte-by-byte zeroing oracle：** 密钥槽索引中的整数溢出允许选择性清零单字节；逐字节暴力（每字节 256 次，共 4096 次）恢复密钥。见 [modern-ciphers.md](modern-ciphers.md#aes-key-recovery-via-byte-by-byte-zeroing-oracle-confidence-ctf-2017)。

## Introspective CRC via GF(2) Linear Algebra

自指 CRC：寻找一个 ASCII 字符串，使它的 CRC 等于它自己。由于 CRC 在 GF(2) 上是线性的，因此该约束可化成可解的线性系统，自由变量再选到可打印 ASCII 范围。见 [advanced-math.md](advanced-math.md#introspective-crc-via-gf2-linear-algebra-google-ctf-2017)。

## CBC Padding Oracle Attack

服务器只要能区分“填充有效 / 无效”，就能在无密钥条件下解密任意 CBC 密文。对每个 16 字节分组大约需要 4096 次查询。工具可用 PadBuster 或 Python 的 `padding-oracle` 库。见 [modern-ciphers.md](modern-ciphers.md#cbc-padding-oracle-attack)。

## Bleichenbacher RSA Padding Oracle (ROBOT)

RSA PKCS#1 v1.5 填充校验预言机可做自适应选择密文恢复明文。对 RSA-2048 大约需 1 万次查询。TLS 实现中也可能通过计时暴露。见 [modern-ciphers.md](modern-ciphers.md#bleichenbacher--pkcs1-v15-rsa-padding-oracle)。

## Birthday Attack / Meet-in-the-Middle

n 位哈希的碰撞约需 `2^(n/2)` 次尝试。中间相遇把双重加密的复杂度从 `O(2^(2k))` 降到 `O(2^k)`。见 [modern-ciphers.md](modern-ciphers.md#birthday-attack--meet-in-the-middle)。

- **Sponge hash MITM collision：** 当海绵的 rate 小于状态大小时，未受控的状态字节允许 MITM：预计算以前向加密为键的表，再反向搜索匹配。可把 `2^48` 降到 `2^24`。见 [modern-ciphers-2.md](modern-ciphers-3.md#sponge-hash-collision-via-meet-in-the-middle-on-partial-state-bkp-2017)。

## CRC32 Collision-Based Signature Forgery (iCTF 2013)

CRC32 是线性的。向消息后追加 4 个可控字节即可强制得到任意目标 CRC32，从而在不知道 secret 的情况下伪造 `CRC32(msg || secret)` 类型的签名。见 [modern-ciphers.md](modern-ciphers.md#crc32-collision-based-signature-forgery-ictf-2013)。

## Blum-Goldwasser Bit-Extension Oracle (PlaidCTF 2013)

每次预言机查询都能把密文向后扩展 1 bit，并通过奇偶性泄露明文。核心是操纵 BBS 平方序列来构造合法的扩展密文。见 [modern-ciphers-2.md](modern-ciphers-2.md#blum-goldwasser-bit-extension-oracle-plaidctf-2013)。

## Hash Length Extension Attack

利用 Merkle-Damgard 哈希（`hash(SECRET || user_data)`）的结构，在不知道 secret 的情况下追加任意数据并计算合法哈希。工具：`hashpump` 或 `hashpumpy`。见 [modern-ciphers-2.md](modern-ciphers-2.md#hash-length-extension-attack-plaidctf-2014)。

## Compression Oracle (CRIME-Style)

先压缩再加密会通过密文长度变化泄露明文。发送选择明文，若 n-gram 命中则压缩更短。这与 CRIME / BREACH 同类。见 [modern-ciphers-2.md](modern-ciphers-2.md#compression-oracle--crime-style-attack-bctf-2015)。

## RC4 Second-Byte Bias

RC4 的第二个输出字节偏向 `0x00`（概率 `1/128`，而随机应为 `1/256`）。用约 2048 个样本即可把 RC4 与真正随机区分开。见 [stream-ciphers.md](stream-ciphers.md#rc4-second-byte-bias-distinguisher-hackover-ctf-2015)。

## RSA Multiplicative Homomorphism Signature Forgery

无填充 RSA 满足 `S(a) * S(b) mod n = S(a*b) mod n`。若预言机屏蔽目标消息，就去签它的因子再相乘。见 [rsa-attacks-2.md](rsa-attacks-2.md#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015)。

## Common Patterns

- **RSA basics：** `phi = (p-1)*(q-1)`，`d = inverse(e, phi)`，`m = pow(c, d, n)`。完整示例见 [rsa-attacks.md](rsa-attacks.md)。
- **XOR：** `from pwn import xor; xor(ct, key)`。XOR 变体见 [classic-ciphers.md](classic-ciphers.md)。

## C srand/rand Prediction via ctypes (L3akCTF 2024, MireaCTF)

**模式：** 二进制使用 `srand(time(NULL))` + `rand()` 生成密钥 / XOR mask。Python 的 `random` 模块使用的是另一种 PRNG。应使用 `ctypes.CDLL('./libc.so.6')` 直接调用 C 的 `srand(int(time()))` 和 `rand()`，才能精确复现序列。XOR 解密示例与计时技巧见 [prng.md](prng.md#c-srandrand-synchronization-via-python-ctypes)。

## V8 XorShift128+ (Math.random) State Recovery

**模式：** V8 JavaScript 引擎的 `Math.random()` 使用 xs128p PRNG。给定 5-10 个连续的 `Math.floor(CONST * Math.random())` 输出，可用 Z3 的 QF_BV 求解器恢复内部状态（state0, state1），并预测后续值。注意输出值必须按 LIFO cache 的顺序反转。工具：`d0nutptr/v8_rand_buster`。见 [prng.md](prng.md#v8-xorshift128-state-recovery-mathrandom-prediction)。

## MT State Recovery from Float Outputs (PHD CTF Quals 2012)

**模式：** 服务端暴露 `random.random()` 浮点值。标准 untemper 需要 624 个 32 位整数，但浮点每次只泄露约 8 个可用 bit。预计算的 GF(2) 魔法矩阵（`not_random` 库）可从 3360+ 个浮点观测中恢复完整 MT 状态，从而预测密码重置 token、会话 ID 或 CSRF token。见 [prng.md](prng.md#mt-state-recovery-from-randomrandom-floats-via-gf2-matrix-phd-ctf-quals-2012)。

## Chaotic PRNG (Logistic Map)

- **Logistic map：** `x = r * x * (1 - x)`，`r ≈ 3.99-4.0`；通过暴力高精度小数恢复种子。
- **Keystream：** 每轮使用 `struct.pack("<f", x)` 作为密钥流，再与密文 XOR。

完整代码见 [prng.md](prng.md#logistic-map--chaotic-prng-seed-recovery-bypass-ctf-2025)。

## SPN S-box Intersection Attack

对 SPN 的分治恢复：独立攻击每个 S 盒位置，再在多组明密文对上取合法子密钥候选的交集。可把指数级密钥空间拆成多个独立子搜索。见 [modern-ciphers-2.md](modern-ciphers-3.md#spn-cipher-partial-key-recovery-via-s-box-intersection-sharifctf-7-2016)。

## Useful Tools

- **Python：** `pip install pycryptodome z3-solver sympy gmpy2`
- **SageMath：** `sage -python script.py`（ECC、Coppersmith、格攻击必备）
- **RsaCtfTool：** `python RsaCtfTool.py -n <n> -e <e> --uncipher <c>`，自动化 RSA 攻击套件（尝试 Wiener、Hastad、Fermat、Pollard 等多种方法）
- **quipqiup.com：** 自动化单表替换密码求解器（频率 + 词形模式分析）
