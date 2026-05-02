# CTF Misc - 游戏、虚拟机与约束求解（第4部分）

从2018年及以后写作中提取的额外CTF时代挑战。早期部分请参见 [games-and-vms.md](games-and-vms.md)、[games-and-vms-2.md](games-and-vms-2.md) 和 [games-and-vms-3.md](games-and-vms-3.md)。

## 目录
- [XSLT 作为二分查找的图灵完备虚拟机 (35C3 2018)](#xslt-as-turing-complete-vm-for-binary-search-35c3-2018)
- [JavaScript MAX_SAFE_INTEGER 后继相等性 (35C3 2018)](#javascript-max_safe_integer-successor-equality-35c3-2018)
- [仅比较DSL中的二分查找Oracle (35C3 2018)](#binary-search-oracle-in-comparison-only-dsl-35c3-2018)
- [通过脚本引擎超时错误实现盲SQL注入 (35C3 2018)](#blind-sqli-via-script-engine-timeout-error-35c3-2018)
- [用于递推谜题的OEIS序列自动查询 (X-MAS CTF 2018)](#oeis-sequence-lookup-automation-for-recurrence-puzzles-x-mas-ctf-2018)
- [基于格式字符串结构约束的二维码重组 (Square CTF 2018)](#qr-code-reassembly-from-format-string-structural-constraints-square-ctf-2018)
- [斐波那契类递推的矩阵快速幂 (Pwn2Win 2018)](#matrix-exponentiation-for-fibonacci-like-recurrence-pwn2win-2018)
- [青蛙跳跃计数的三项递推 (FireShell 2019)](#tribonacci-recurrence-for-frog-jump-counting-fireshell-2019)
- [Selenium + Tesseract 实现动态字体验证码识别 (Square CTF 2018)](#selenium--tesseract-for-dynamic-font-captcha-square-ctf-2018)
- [Brainfuck 解码 Piet 图像URL — 多层多态体 (RITSEC 2018)](#brainfuck-decodes-piet-image-url--multi-layer-polyglot-ritsec-2018)
- [Bytebeat 合成代码识别隐藏音频 (RITSEC 2018)](#bytebeat-synth-code-recognition-for-hidden-audio-ritsec-2018)

---

## XSLT 作为二分查找的图灵完备虚拟机 (35C3 2018)

**模式：** 挑战仅执行 XSLT 模板。`<xsl:choose>`、带递归的 `<xsl:call-template>` 和 `<xsl:variable>` 组成了带栈的完整图灵完备运行时。编码一个二分查找oracle：`<drinks>` 元素保存栈，`<plate>` 元素是指令，`<course>` 块作为标签。

```xml
<xsl:template name="step">
  <xsl:param name="lo"/><xsl:param name="hi"/>
  <xsl:variable name="mid" select="($lo + $hi) div 2"/>
  <xsl:choose>
    <xsl:when test="$target = $mid">...found...</xsl:when>
    <xsl:when test="$target &lt; $mid">
      <xsl:call-template name="step">
        <xsl:with-param name="lo" select="$lo"/>
        <xsl:with-param name="hi" select="$mid"/>
      </xsl:call-template>
    </xsl:when>
    ...
  </xsl:choose>
</xsl:template>
```

**关键洞察：** 任何带有命名递归和条件判断的“纯模板”语言都是一个虚拟机。在尝试逃逸沙箱前，先用其原生构造构建一个原语（二分查找、位提取、状态累加器）。

**参考：** 35C3 CTF 2018 — Juggle，writeup 12803

---

## JavaScript MAX_SAFE_INTEGER 后继相等性 (35C3 2018)

**模式：** 挑战断言 `x !== x + 1`。对于 `x = Number.MAX_SAFE_INTEGER + 1 === 9007199254740992`，IEEE 754 舍入使得 `x + 1 === x` 为真，因此断言成立，检查被绕过。

```js
let x = 9007199254740992; // 2^53
console.log(x === x + 1); // true
```

**关键洞察：** 任何将 `n` 与 `n + 1` 比较的数值不变量在浮点边界处都会失败。当JS检查看似对算术做出假设时，使用 `2^53`、`Infinity`、`NaN` 和 `-0 === 0` 组合进行测试。

**参考：** 35C3 CTF 2018 — Number Error，writeup 12828

---
## Binary Search Oracle in Comparison-Only DSL (35C3 2018)

**模式：** 挑战的 DSL 仅暴露针对秘密值的比较。通过从初始猜测中减去递减的二次幂（`2^30, 2^29, ..., 2^0`），当比较结果为“小于”时加回该值，为“大于”时减去该值，将其转换为完整的 oracle。

```python
guess = 0
for shift in range(30, -1, -1):
    guess += 1 << shift
    if oracle(guess) > 0:     # 猜测过高
        guess -= 1 << shift
```

**关键洞察：** 任何布尔比较器都能让你用 `O(log N)` 次查询实现二分搜索。相同的技巧能将任何基于比较的泄露——正则匹配、时间信道、HTTP 状态码——折叠成完整的值。

**参考资料：** 35C3 CTF 2018 — Juggle，writeup 12803

---

## Blind SQLi via Script-Engine Timeout Error (35C3 2018)

**模式：** 服务器对用户提供的代码片段执行 `eval`，并设置严格的超时。将 payload 包裹在 `if charAt(FLAG, pos) == '?' then pause(10000) end` 中——正确字符会挂起直到超时触发错误；错误字符则立即返回。将超时视为真值位。

```lua
-- Lua eval 沙箱中的盲定时 oracle
for c in printable do
    send(("if charAt(FLAG, %d) == '%s' then pause(10000) end"):format(i, c))
    if response_time > 5 then flag = flag .. c; break end
end
```

**关键洞察：** 带超时的脚本执行服务是有状态的 oracle：任何长时间运行的表达式都会通过超时与即时返回的墙钟差异泄露布尔值。

**参考资料：** 35C3 CTF 2018 — dev/null，writeups 12830, 12871

---

## OEIS Sequence Lookup Automation for Recurrence Puzzles (X-MAS CTF 2018)

**模式：** 服务器要求给出数学序列的下一个项。自动化查询：访问 https://oeis.org/search?q=1,1,2,5,14，使用 pyquery 解析第一个结果，提取 `Next term`，返回给服务器。对受 PoW 保护的服务，结合 MD5 验证码暴力破解。

```python
import requests
from pyquery import PyQuery as pq
r = requests.get('https://oeis.org/search', params={'q': ','.join(map(str, seq))})
doc = pq(r.text)
next_term = doc('pre').eq(1).text().split(',')[len(seq)]
```

**关键洞察：** 任何整数序列谜题都能通过一次 HTTP 请求借助 OEIS 解决。难点在于包装（验证码、PoW、socket 封包）——自动化后数学不再是瓶颈。

**参考资料：** X-MAS CTF 2018 — A Weird List of Sequences，writeup 12683

---

## QR Code Reassembly from Format-String Structural Constraints (Square CTF 2018)

**模式：** 挑战提供被切碎的二维码单像素列。不是暴力尝试 `21!` 种排列，而是基于二维码不变量定位：三个定位图案、它们之间的时序图案、固定的暗模块，以及第 8 列的 15 位格式字符串只有 32 个有效值（纠错等级 × 掩码模式）。先用结构约束过滤切片，再对剩余少数进行排列。

```python
wanted_formats = load_32_valid_qr_formats()
for col in slices:
    if col[:7] in wanted_formats_column_8:
        candidate_cols.append(col)
for perm in itertools.permutations(candidate_cols):
    if decode_qr(np.stack(perm)):
        return perm
```

**关键洞察：** 格式特定约束能大幅缩减排列空间。二维码版本 1 只有 32 种可能的格式字符串；以此为锚点进行剪枝再暴力破解。

**参考资料：** Square CTF 2018 — C3: Shredded，writeup 12331

---

## Matrix Exponentiation for Fibonacci-Like Recurrence (Pwn2Win 2018)

**模式：** 挑战要求计算递推式 `a_{n+1} = f(a_n, a_{n-1})` 的第 `N` 项，`N` 可达 `10^{12}`。朴素迭代不可行。将更新写成 2×2 矩阵乘积 `[a_{n+1}; a_n] = M * [a_n; a_{n-1}]`，用二分幂法在 `O(log N)` 内计算 `M^N`。

```python
MOD = 10**9 + 7
def matmult(a, b):
    return ((a[0]*b[0] + a[1]*b[2]) % MOD, (a[0]*b[1] + a[1]*b[3]) % MOD,
            (a[2]*b[0] + a[3]*b[2]) % MOD, (a[2]*b[1] + a[3]*b[3]) % MOD)
def matpow(M, n):
    R = (1,0,0,1)
    while n:
        if n & 1: R = matmult(R, M)
        M = matmult(M, M); n >>= 1
    return R
```

**关键洞察：** 任何环上的线性递推都可归约为矩阵幂运算。遇到暴露巨大 `N` 的经典序列——斐波那契、三项递推、卢卡斯、线性皮萨诺、随机数计数器——都可用此法。

**参考资料：** Pwn2Win CTF 2018 — Too Slow，writeup 12501

---
## Tribonacci 递推用于青蛙跳跃计数（FireShell 2019）

**模式：** 一个工作量证明握手问题询问青蛙如果能跳 1、2 或 3 步，有多少种方式能到达第 `N` 级台阶。即 `f(N) = f(N-1) + f(N-2) + f(N-3)` —— Tribonacci 数列。预先计算对服务器模数取模；对于较大的 `N`，结合上文的矩阵快速幂方法。

```python
def tribonacci(N, MOD=13371337):
    a, b, c = 0, 0, 1
    for _ in range(N):
        a, b, c = b, c, (a + b + c) % MOD
    return c
```

**关键洞察：** “用步长集合 {1..k} 爬 N 级台阶的方式数”总是线性递推。对服务器最大 `N` 进行记忆化，跨请求缓存，并在题目提到“frog”时牢记 Tribonacci 恒等式。

**参考：** FireShell CTF 2019 — Frogs，writeup 12961

---

## Selenium + Tesseract 处理动态字体 CAPTCHA（Square CTF 2018）

**模式：** CAPTCHA 生成带随机字形字体的数学表达式，每 5 秒重新渲染一次。通过 Selenium 截取全窗口截图，传给 Tesseract OCR；在 `eval()` 前清理 Tesseract 常见混淆（`x`→`*`，`{`→`(`）。

```python
from selenium import webdriver
from PIL import Image
import pytesseract, io
d = webdriver.Chrome()
d.get(URL); d.execute_script("document.body.style.zoom='450%'")
img = Image.open(io.BytesIO(d.get_screenshot_as_png()))
expr = pytesseract.image_to_string(img).replace('x','*').replace('{','(').replace('}',')')
d.execute_script(f"document.getElementsByName('answer')[0].value={eval(expr)}")
d.find_element_by_tag_name('form').submit()
```

**关键洞察：** 动态 CAPTCHA 通常寿命太短不适合手动解答，但用 1 秒的 Selenium + Tesseract 循环轻松搞定。OCR 单独失败时，结合 cmap 字库参考（见 ctf-osint/web-and-dns.md）。

**参考：** Square CTF 2018 — C8，writeups 12160, 12178

---

## Brainfuck 解码 Piet 图片 URL — 多层多语言混合（RITSEC 2018）

**模式：** 识别三种最常见的 esolang 叠加：Brainfuck 源码输出 YouTube URL，视频缩略图边框是 Piet 程序，执行打印 flag。用 `bf` → `yt-dlp` → 去除边框像素 → `npiet` 流水线。

```bash
bf puzzle.bf                          # 打印 youtube.com/watch?v=XXXX
yt-dlp -x --write-thumbnail "$URL"    # 下载 JPG 缩略图
python crop_border.py thumb.jpg > piet.png
npiet piet.png                        # 打印 flag
```

**关键洞察：** 多层 esolang 眼见为实：Brainfuck 是 `+-<>.,[]`，Piet 是彩色方块网格，Whitespace 是不可见字符。题目描述提及多种“奇怪”格式时，按顺序流水线解码器。

**参考：** RITSEC CTF 2018 — writeup 12224

---

## Bytebeat 合成代码识别隐藏音频（RITSEC 2018）

**模式：** 一行简短的类 C 代码是 bytebeat —— 一种生成音乐格式，`t` 是单调采样计数器。粘贴到在线解释器（http://wry.me/bytebeat/）收听；生成的旋律是可识别歌曲，歌曲名即为 flag。

```c
/* Bytebeat 示例：输出字节 = 该表达式的低 8 位 */
(t * ((t >> 12 | t >> 8) & 63 & t >> 4))
```

**关键洞察：** 通过 (a) `t` 变量，(b) 位移混合取模，(c) 输出为 8 位无符号整数识别 bytebeat。`%`、`|`、`&`、`^`、`>>`、`<<` 操作符作用于 `t` 是 bytebeat 标志。无需解码 —— 直接播放即可。

**参考：** RITSEC CTF 2018 — writeups 12261, 12268

---
