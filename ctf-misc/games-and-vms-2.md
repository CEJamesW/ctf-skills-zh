# CTF Misc - 游戏、虚拟机与约束求解（第2部分）

## 目录
- [Cookie Checkpoint 游戏暴力破解（BYPASS CTF 2025）](#cookie-checkpoint-game-brute-forcing-bypass-ctf-2025)
- [Flask Session Cookie 游戏状态泄露（BYPASS CTF 2025）](#flask-session-cookie-game-state-leakage-bypass-ctf-2025)
- [WebSocket 游戏操控 + 神秘提示解码（BYPASS CTF 2025）](#websocket-game-manipulation--cryptic-hint-decoding-bypass-ctf-2025)
- [仅服务器时间验证绕过（BYPASS CTF 2025）](#server-time-only-validation-bypass-bypass-ctf-2025)
- [De Bruijn 序列用于子串覆盖（BearCatCTF 2026）](#de-bruijn-sequence-for-substring-coverage-bearcatctf-2026)
- [Brainfuck 解释器插桩（BearCatCTF 2026）](#brainfuck-interpreter-instrumentation-bearcatctf-2026)
- [WASM 线性内存操控（BearCatCTF 2026）](#wasm-linear-memory-manipulation-bearcatctf-2026)
- [参考文献](#references)

---

## Cookie Checkpoint 游戏暴力破解（BYPASS CTF 2025）

**模式（来自牌组的信号）：** 服务器端游戏，选择瓷砖会增加分数。错误选择会重置游戏。分数通过 session cookie 跟踪。

**技巧：** 在每次猜测前保存 cookie，失败时恢复 cookie 以避免重置进度。

```python
import requests

URL = "https://target.example.com"

def solve():
    s = requests.Session()
    s.post(f"{URL}/api/new")

    while True:
        data = s.get(f"{URL}/api/signal").json()
        if data.get('done'):
            break

        checkpoint = s.cookies.get_dict()

        for tile_id in range(1, 10):
            r = s.post(f"{URL}/api/click", json={'clicked': tile_id})
            res = r.json()

            if res.get('correct'):
                if res.get('done'):
                    print(f"FLAG: {res.get('flag')}")
                    return
                break
            else:
                s.cookies.clear()
                s.cookies.update(checkpoint)
```

**关键洞察：** Session cookie 充当存档状态。失败时保存并恢复 cookie，使得暴力破解可以确定性进行而不会被游戏重置惩罚。

---

## Flask Session Cookie 游戏状态泄露（BYPASS CTF 2025）

**模式（Hungry, Not Stupid）：** Flask 游戏将正确答案存储在签名的 session cookie 中。使用 `flask-unsign -d` 解码 cookie，揭示服务器端游戏状态，无需实际玩游戏。

```bash
# 解码 Flask session cookie（读取无需密钥）
flask-unsign -d -c '<cookie_value>'
```

**示例解码状态：**
```json
{
  "all_food_pos": [{"x": 16, "y": 12}, {"x": 16, "y": 28}, {"x": 9, "y": 24}],
  "correct_food_pos": {"x": 16, "y": 28},
  "level": 0
}
```

**关键洞察：** Flask session cookie 默认是签名而非加密的。`flask-unsign -d` 可在无密钥情况下解码，暴露服务器端游戏状态，包括正确答案。

**检测特征：** Base64 格式的 session cookie，段之间用点号（`.`）分隔。Flask 使用 `itsdangerous` 签名格式。

---

## WebSocket 游戏操控 + 神秘提示解码（BYPASS CTF 2025）

**模式（Maze of the Unseen）：** 浏览器端迷宫游戏，墙壁不可见。检查点通过 WebSocket 由服务器验证。神秘提示编码目标坐标。

**技巧：**
1. 打开浏览器控制台，检查 WebSocket 消息和 `player` 对象
2. 解码神秘提示（例如 "mosquito were not available" → MQTT → 端口 1883）
3. 通过控制台直接传送到目标坐标

```javascript
function teleport(x, y) {
    player.x = x;
    player.y = y;
    verifyProgress(Math.round(player.x), Math.round(player.y));
    console.log(`Teleported to x:${player.x}, y:${player.y}`);
}

// "mosquito" → MQTT（Mosquitto 代理，端口 1883），"not available" → 404
teleport(1883, 404);
```

**常见神秘提示映射：**
- "mosquito" → MQTT（Mosquitto 代理，端口 1883）
- "not found" / "not available" → HTTP 404
- 端口号、协议默认值或 ASCII 值作为坐标

**关键洞察：** 浏览器端游戏状态暴露在 JS 控制台。直接修改 `player.x`/`player.y` 或等效属性，然后调用进度验证函数。

---
## Server Time-Only Validation Bypass (BYPASS CTF 2025)

**模式（Level Devil）：** 横向卷轴游戏，需要穿越地图。服务器验证经过的时间是否足够（map_length / speed），但不验证实际移动。

```python
import requests
import time

TARGET = "https://target.example.com"

s = requests.Session()
r = s.post(f"{TARGET}/api/start")
session_id = r.json().get('session_id')

# 等待所需的穿越时间（例如，4800px / 240px/s = 20秒 + 余量）
time.sleep(25)

s.post(f"{TARGET}/api/collect_flag", json={'session_id': session_id})
r = s.post(f"{TARGET}/api/win", json={'session_id': session_id})
print(r.json().get('flag'))
```

**关键洞察：** 当服务器只验证经过时间（不验证玩家位置、输入或移动）时，启动会话，等待所需时间，然后提交胜利请求。务必检查游戏 API 是否有可直接调用的 start/win 端点。

---

## De Bruijn 序列用于子串覆盖 (BearCatCTF 2026)

**模式（Brown's Revenge）：** 服务器每轮生成随机 n 位二进制码。输入必须包含该码作为子串。在字符限制内用单个固定输入通过 20+ 轮。

```python
def de_bruijn(k, n):
    """生成 de Bruijn 序列 B(k, n)：循环序列，包含所有长度为 n 的 k 进制字符串恰好一次作为子串。"""
    a = [0] * k * n
    sequence = []
    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p+1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return sequence

# 对于 12 位二进制码：B(2, 12) 长度为 4096
seq = ''.join(map(str, de_bruijn(2, 12)))
payload = seq + seq[:11]  # 线性化：4096 + 11 = 4107 字符
# 每个可能的 12 位码都作为子串出现
```

**关键洞察：** De Bruijn 序列 B(k, n) 包含所有 k^n 个可能的长度为 n 的 k 进制字符串作为子串，循环长度为 k^n。线性化（非循环）时，附加前 n-1 个字符。总长度 = k^n + n - 1。每轮发送相同字符串——它包含所有可能的码。

**检测点：** 必须找到任意 n 位模式作为有限长度输入的子串。字符预算与 de Bruijn 长度（k^n + n - 1）匹配。

---

## Brainfuck 解释器插桩 (BearCatCTF 2026)

**模式（Ghost Ship）：** 大型 Brainfuck 程序（10K+ 指令）逐字符验证 flag。完全逆向不可行。

**逐字符暴力破解通过插桩：**
1. 插桩 Brainfuck 解释器以跟踪 tape 单元值
2. 找到“错误计数”单元，每次错误字符时递增
3. 对每个位置，尝试所有可打印 ASCII 字符——选择不会增加错误计数的字符

```python
def run_bf_instrumented(code, input_bytes, max_steps=500000):
    tape = [0] * 30000
    dp, ip, inp_idx = 0, 0, 0
    for _ in range(max_steps):
        if ip >= len(code): break
        c = code[ip]
        if c == '+': tape[dp] = (tape[dp] + 1) % 256
        elif c == '-': tape[dp] = (tape[dp] - 1) % 256
        elif c == '>': dp += 1
        elif c == '<': dp -= 1
        elif c == '.': pass  # 输出
        elif c == ',':
            tape[dp] = input_bytes[inp_idx] if inp_idx < len(input_bytes) else 0
            inp_idx += 1
        elif c == '[' and tape[dp] == 0:
            # 跳过到匹配的 ]
            ...
        elif c == ']' and tape[dp] != 0:
            # 跳回匹配的 [
            ...
        ip += 1
    return tape

# 暴力破解：约 40 个位置 × 95 个字符 = 3800 次运行
flag = []
for pos in range(40):
    for c in range(32, 127):
        candidate = flag + [c] + [ord('A')] * (39 - pos)
        tape = run_bf_instrumented(code, candidate)
        if tape[WRONG_COUNT_CELL] == 0:  # 到此位置无错误
            flag.append(c)
            break
```

**关键洞察：** 逐字符验证输入的 Brainfuck 程序无需理解程序逻辑即可暴力破解。插桩解释器观察 tape 状态，找到跟踪验证进度的单元，优化逐字符搜索。约 3800 次运行几分钟内完成。

---
## WASM 线性内存操作（BearCatCTF 2026）

**题目（Dubious Doubloon）：** 浏览器游戏编译为 WebAssembly，胜利条件依赖运气（例如连续 15 次抛硬币）。WASM 线性内存是平坦且无保护的。

**Node.js 中的直接内存修改：**
```javascript
const { readFileSync } = require('fs');
const wasmBuffer = readFileSync('game.wasm');
const { instance } = await WebAssembly.instantiate(wasmBuffer, imports);
const mem = new DataView(instance.exports.memory.buffer);

// 在已知偏移处修改游戏变量
mem.setInt32(0x102918, 14, true);   // 连胜计数器 = 14（需要 15）
mem.setInt32(0x102898, 100, true);  // 胜率 = 100%

// 再抛一次 → 保证胜利 → 解码 flag
const result = instance.exports.flipCoin();
```

**关键洞察：** 与 WAT 补丁（修改二进制）不同，内存操作是在加载后修改运行时状态。所有 WASM 变量都存放在固定偏移的平坦线性内存中。使用 `wasm-objdump -x game.wasm` 或搜索已知常量来定位变量偏移。无需理解完整游戏逻辑——只需将状态设置为“即将获胜”。

**检测方式：** WASM 游戏要求统计上不可能出现的序列（连胜、满分）。游戏逻辑存在于可在 Node.js 中加载的 `.wasm` 文件中。

---

## 参考
- BYPASS CTF 2025 “Signal from the Deck”：Cookie 检查点游戏暴力破解
- BYPASS CTF 2025 “Hungry, Not Stupid”：Flask Cookie 游戏状态泄露
- BYPASS CTF 2025 “Maze of the Unseen”：WebSocket 传送 + 隐晦提示
- BYPASS CTF 2025 “Level Devil”：仅服务器时间验证绕过
- BearCatCTF 2026 “Brown's Revenge”：De Bruijn 序列子串覆盖
- BearCatCTF 2026 “Ghost Ship”：Brainfuck 仪器化暴力破解
- BearCatCTF 2026 “Dubious Doubloon”：WASM 线性内存状态补丁

---

另见：[games-and-vms.md](games-and-vms.md) 涉及 WASM 补丁、Roblox 逆向、PyInstaller、Z3、K8s RBAC、浮点数利用、自定义汇编沙箱逃逸及多阶段加密游戏。
