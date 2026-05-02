---
name: ctf-pwn
description: 提供面向 CTF 挑战的二进制利用技术。适用于你已经拥有一个存在漏洞的原生目标或服务，并需要把内存破坏或底层原语转化为代码执行或提权的场景，例如缓冲区溢出、格式化字符串、堆漏洞、ROP、ret2libc、shellcode、内核利用、seccomp 绕过、沙箱逃逸，或 Windows/Linux 利用链。当主要阻碍是理解二进制在做什么时不要使用它；应先做逆向。不要用于纯 Web 漏洞、磁盘或数据包取证、或独立的密码/数学挑战。
license: MIT
compatibility: 需要基于文件系统的代理（Claude Code 或类似工具），并具备 bash、Python 3 与可用于安装工具的互联网访问。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Binary Exploitation (Pwn)

二进制利用（pwn）CTF 挑战速查表。这里给出每类技术的一行摘要；完整细节见对应支持文档。

## Prerequisites

**Python 包（所有平台）：**
```bash
pip install pwntools ropper ROPgadget
```

**Linux（apt）：**
```bash
apt install gdb binutils strace ltrace qemu-system-x86
```

**macOS（Homebrew）：**
```bash
brew install gdb binutils qemu
```

**Ruby gems（所有平台）：**
```bash
gem install one_gadget seccomp-tools
```

**手动安装：**
- pwndbg：Linux 见 [GitHub](https://github.com/pwndbg/pwndbg)，macOS 用 `brew install pwndbg/tap/pwndbg-gdb`
- checksec：pwntools 自带

## Additional Resources

- [overflow-basics.md](overflow-basics.md) - 栈/全局缓冲区溢出、ret2win、canary 绕过、forking 服务上的逐字节 canary 爆破、结构体指针覆写、有符号整数绕过、隐藏 gadget、基于步长的 OOB 读泄漏、解析器中未检查 memcpy 长度导致的栈溢出及被调用者保存寄存器恢复
- [rop-and-shellcode.md](rop-and-shellcode.md) - 核心 ROP 链（ret2libc、syscall ROP、rdx 控制、shell 交互）、ret2csu、坏字符 XOR 绕过、非常规 x86 gadget（BEXTR/XLAT/STOSB/PEXT）、`xchg rax,esp` 栈迁移、用 sprintf() gadget 链绕过坏字符、canary XOR 尾声作 RDX 清零 gadget、用 read() 返回值驱动的 stub_execveat syscall 作为 execve 替代
- [rop-advanced.md](rop-advanced.md) - 高级 ROP 技术：通过 `leave;ret` 双重栈迁移到 BSS、带 UTF-8 约束的 SROP（Sigreturn-Oriented Programming）、seccomp 绕过、用 RETF 做架构切换（x64→x32）绕过 seccomp、输入反转下的 shellcode、`.fini_array` 劫持、ret2vdso、pwntools 模板、利用 x32 ABI syscall 别名绕过 seccomp、基于时间的盲 shellcode 外带
- [format-string.md](format-string.md) - 格式化字符串利用（泄漏、GOT 覆写、blind pwn、过滤绕过、canary 泄漏、`__free_hook`、`.rela.plt` 打补丁、覆写保存的 EBP 以迁移到 `.bss`、覆写 `argv[0]` 泄漏栈破坏信息、用 `.fini_array` 循环做多阶段利用、用顺序 `%p` 绕过 `__printf_chk`、单次调用完成泄漏 + GOT 覆写、输入变换下的 ROT13 编码格式串利用）
- [advanced.md](advanced.md) - seccomp 高级技术、UAF、JIT、非常规 GOT、基数转换导致的堆重叠、树形数据结构栈下分配、ret2dlresolve、内核利用（基础）
- [heap-techniques.md](heap-techniques.md) - House of Apple 2（含 setcontext SUID 变种）、House of Einherjar、House of Orange/Spirit/Lore/Force、heap grooming、自定义分配器（nginx、talloc）、经典 unlink、musl libc 堆（meta 指针 + atexit 劫持）、tcache stashing unlink attack、unsafe unlink + top chunk 合并
- [heap-techniques-2.md](heap-techniques-2.md) - CTF writeup 中的堆变体：UAF vtable 指针编码 shell 参数、未初始化 chunk 残留指针泄漏、tcache strcpy 空字节溢出 + 向后合并、相邻结构体函数指针溢出实现 libc 泄漏 + GOT 覆写、隐藏菜单 tcache poisoning、tcache double-free + 伪造 `_IO_FILE` vtable 劫持 stdout、tcache 向 fastbin 提升的跨 bin 攻击、6 位索引 OOB + written_bytes 累加器、在 calloc 得到的 chunk 上翻转 IS_MMAPED 位以做 unsorted bin 泄漏、文件名正则约束下仅改堆指针 LSB 的 fastbin、自定义分配器 unsafe unlink 到 GOT
- [heap-fsop.md](heap-fsop.md) - FILE 结构（`_IO_FILE`）利用：fastbin stdout vtable 双阶段劫持以击破 PIE + Full RELRO、`_IO_buf_base` 空字节 stdin 劫持、glibc 2.24+ `_IO_FILE` vtable 校验绕过、对 stdin `_IO_buf_end` 的 unsorted-bin attack、经由 mp_ 结构进行 unsorted-bin 破坏、`realloc(ptr, 0)` 作为 `free()` UAF、单字节引用计数回绕 UAF
- [advanced-exploits.md](advanced-exploits.md) - 高级利用技术（第 1 部分）：VM 有符号比较、BF JIT shellcode、类型混淆、off-by-one 索引破坏、DNS 溢出、ASAN shadow memory、编码约束下的格式串、自定义 canary 保持、有符号整数绕过、感知 canary 的部分溢出、CSV 注入、MD5 原像 gadget、VM GC UAF slab 复用、路径穿越 sanitizer 绕过、FSOP + 通过 openat/mmap/write 绕过 seccomp
- [advanced-exploits-2.md](advanced-exploits-2.md) - 高级利用技术（第 2 部分）：通过自修改绕过字节码校验器、带 SQE 注入的 io_uring UAF、int32->int16 整数截断、GC 空引用级联破坏、无泄漏 libc 的多次 fgets stdout FILE 覆写、有符号/无符号 char 下溢导致堆溢出、XOR 密钥流暴力写原语、tcache 指针解密堆泄漏、伪造 chunk size 触发 unsorted bin 提升、FSOP stdout TLS 泄漏、通过 `__call_tls_dtors` 劫持 TLS 析构器、自定义 shadow stack 指针溢出绕过、有符号 int 溢出导致负索引 OOB 堆写、XSS 到二进制 pwn 的桥接
- [advanced-exploits-4.md](advanced-exploits-4.md) - 高级利用技术（第 4 部分）：Windows SEH 覆写 + pushad VirtualAlloc ROP、IAT 相对解析、分离进程 shell 稳定性、SeDebugPrivilege 提升到 SYSTEM、ARM 缓冲区溢出配合 Thumb shellcode、Forth 解释器 system word 利用、GF(2) 高斯消元实现多轮 tcache poisoning、单比特翻转利用原语（mprotect + 迭代代码打补丁）、通过静态生命体演化 Game of Life shellcode、基于菜单的 strdup/free 顺序造成 UAF、用 system() 作为合法调用目标绕过 Windows CFG、把神经网络输出作为函数指针索引 OOB、通过计数器溢出绕过 shellcode 唯一字节限制
- [advanced-exploits-3.md](advanced-exploits-3.md) - 高级利用技术（第 3 部分）：栈变量重叠/进位破坏 OOB、8 位循环计数器导致的 1 字节溢出、游戏 AI 算术平均 OOB 读、任意读写 + GOT 覆写拿 shell、通过 `__environ` 和 memcpy 溢出泄漏栈、通过 uint16 跳转截断实现 JIT 沙箱逃逸、多问题 DNS 压缩指针栈溢出 ROP、通过程序头操纵绕过 ELF 代码签名、游戏关卡格式中的有符号/无符号坐标不匹配、缺少 O_CLOEXEC 导致文件描述符继承、元数据解析中的符号扩展整数下溢、只读原语下构造 ROP 链、借助持久寄存器和时间侧信道的 4 字节 shellcode、CRC oracle 作为任意读、UTF-8 大小写转换缓冲区溢出
- [advanced-exploits-5.md](advanced-exploits-5.md) - 高级利用技术（第 5 部分）：数据解释型利用，包括 Chip-8 模拟器 OOB 内存做 ret2libc、双精度浮点 quicksort 重新定位 canary、bloom filter 中 `abs(INT_MIN)` 导致负索引 OOB 写
- [sandbox-escape.md](sandbox-escape.md) - 自定义 VM 利用、FUSE/CUSE 设备、busybox/受限 shell、shell 技巧、process_vm_readv 沙箱绕过、命名管道文件大小绕过、CPU 模拟器 print opcode 上的 Python eval 注入（交叉引用 `ctf-misc/pyjails.md` 中的 Python jail 技巧）
- [kernel.md](kernel.md) - Linux 内核利用基础：环境搭建、QEMU 调试、堆喷结构（tty_struct、poll_list、user_key_payload、seq_operations）、内核栈溢出、canary 泄漏、提权（ret2usr、kernel ROP）、覆写 modprobe_path、覆写 core_pattern、kmalloc 尺寸不匹配导致的堆溢出 + struct file `f_op` 破坏
- [kernel-techniques.md](kernel-techniques.md) - 内核利用技术：tty_struct kROP（伪造 vtable + 栈迁移）、通过 ioctl 寄存器控制实现 AAW、用 userfaultfd 稳定竞争、SLUB 分配器内部机制（freelist hardening/obfuscation）、通过 kernel panic 泄漏、扩展 MADV_DONTNEED 竞争窗口（DiceCTF 2026）、跨 cache 的 CPU-split 攻击（DiceCTF 2026）、PTE overlap file write（DiceCTF 2026）、通过 failed file open 触发 addr_limit 绕过实现内核内存读写
- [kernel-bypass.md](kernel-bypass.md) - 内核防护绕过：KASLR/FGKASLR 绕过（`__ksymtab`）、KPTI 绕过（swapgs trampoline、signal handler、通过 ROP 覆写 modprobe_path/core_pattern）、SMEP/SMAP 绕过、GDB 调试内核模块、initramfs/virtio-9p 工作流、利用模板、利用投递
- [field-notes.md](field-notes.md) - 详细 pwn 笔记：堆利用速查、额外利用备注、常用命令

---

## When to Pivot

- 如果你还不理解二进制在做什么，先切换到 `/ctf-reverse` 再尝试利用。
- 如果服务本质上是受限 shell、编码谜题或沙箱语言题，切换到 `/ctf-misc`。
- 如果利用路径更依赖 Web 端点、会话漏洞或上传原语，而非内存破坏，切换到 `/ctf-web`。
- 如果漏洞利用前必须先打破某个密码学原语，切换到 `/ctf-crypto`。

## Quick Start Commands

```bash
# Binary analysis
checksec --file=binary
file binary
readelf -h binary

# Find gadgets
ROPgadget --binary binary | grep "pop rdi"
ropper -f binary --search "pop rdi"
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# Debug
gdb -q binary -ex 'start' -ex 'checksec'

# Pattern for offset finding
python3 -c "from pwn import *; print(cyclic(200))"
python3 -c "from pwn import *; print(cyclic_find(0x61616168))"

# libc identification
./libc-database/find puts <leaked_addr_last_3_nibbles>
```

## Source Code Red Flags

- Threading/`pthread` -> 竞争条件
- `usleep()`/`sleep()` -> 时间窗口
- 多线程中的全局变量 -> TOCTOU

## Race Condition Exploitation

```bash
bash -c '{ echo "cmd1"; echo "cmd2"; sleep 1; } | nc host port'
```

## Common Vulnerabilities

- 缓冲区溢出：`gets()`、`scanf("%s")`、`strcpy()`
- 格式化字符串：`printf(user_input)`
- 整数溢出、UAF、竞争条件

## Protection Implications for Exploit Strategy

| Protection | Status | Implication |
|-----------|--------|-------------|
| PIE | Disabled | 所有地址（GOT、PLT、函数）固定，可直接覆写 |
| RELRO | Partial | GOT 可写，可做 GOT overwrite |
| RELRO | Full | GOT 只读，需要替代目标（hook、vtable、返回地址） |
| NX | Enabled | 不能在栈/堆上直接执行 shellcode，改用 ROP 或 ret2win |
| Canary | Present | 栈破坏会被检测，需要先泄漏或避免走栈溢出（改打堆） |

**快速决策树：**
- Partial RELRO + No PIE -> GOT overwrite（最简单，地址固定）
- Full RELRO -> 目标选 `__free_hook`、`__malloc_hook`（glibc < 2.34）或返回地址
- 存在栈 canary -> 优先考虑基于堆的攻击，或先泄漏 canary

## Stack Buffer Overflow

1. 找偏移：`cyclic 200` 然后 `cyclic -l <value>`
2. 检查保护：`checksec --file=binary`
3. No PIE + No canary = 直接 ROP
4. 通过格式串或部分覆写泄漏 canary
5. 对 forking 服务器逐字节爆破 canary（最多 7*256 次）

**ret2win with magic value：** 溢出 -> `ret`（对齐）-> `pop rdi; ret` -> magic -> win()。**栈对齐：** 若在 `movaps` 上 SIGSEGV，加一个额外 `ret` gadget。**偏移：** buffer 在 `rbp - N`，返回地址在 `rbp + 8`，总偏移 = N + 8。**输入过滤：** 断言 payload 不包含 `memmem()` 禁止的字符串。**Gadget：** `ROPgadget --binary binary | grep "pop rdi"`，或用 pwntools `ROP()` 挖 CMP immediate 里的隐藏 gadget。完整利用代码见 [overflow-basics.md](overflow-basics.md)。

## Parser Stack Overflow (Unchecked memcpy)

**模式：** 自定义文件解析器（PCAP、图片、归档）分配固定栈缓冲区，但输入记录长度可超出它。`memcpy` 在做长度校验前就复制，覆盖保存寄存器和返回地址。必须恢复被调用者保存寄存器：`rbx` 指向可读内存（BSS），循环计数器设成退出值，然后接 `ret` gadget + win 函数。见 [overflow-basics.md](overflow-basics.md#parser-stack-overflow-via-unchecked-memcpy-length-metactf-flash-2026)。

## Struct Pointer Overwrite (Heap Menu Challenges)

**模式：** 菜单题里 create/modify/delete 结构体，结构体中既有数据缓冲区也有指针。把 name 溢出到指针字段，改成 GOT 地址，再通过 modify 写入 win 地址。完整利用和 GOT 目标选择表见 [overflow-basics.md](overflow-basics.md)。

## Signed Integer Bypass

**模式：** `scanf("%d")` 没有符号检查；负数数量 * 单价 = 负总价，绕过余额校验。见 [overflow-basics.md](overflow-basics.md)。

## Canary-Aware Partial Overflow

**模式：** 溢出 buffer 和 canary 之间的 `valid` 标志位，不碰 canary。用 `./` 作为无副作用路径填充以精确控长。完整链路见 [overflow-basics.md](overflow-basics.md) 与 [advanced.md](advanced.md)。

## Global Buffer Overflow (CSV Injection)

**模式：** 相邻全局变量；通过额外 CSV 分隔符溢出，修改文件名指针。见 [overflow-basics.md](overflow-basics.md) 和 [advanced.md](advanced.md)。

## ROP Chain Building

通过 `puts@PLT(puts@GOT)` 泄漏 libc，返回 vuln，再第二阶段 `system("/bin/sh")`。完整两阶段 ret2libc 模式、泄漏解析和返回目标选择见 [rop-and-shellcode.md](rop-and-shellcode.md)。

**DynELF libc 发现：** `pwntools.DynELF(leak_func, pointer_in_libc)` 能在远程环境中不知 libc 版本时解析符号。见 [rop-and-shellcode.md](rop-and-shellcode.md#dynelf-automated-libc-discovery-rc3-ctf-2016)。

**小缓冲区中的受限 shellcode：** 当缓冲区太小，使用 `< 20 bytes` 的 `read()` stub shellcode 拉取第二阶段完整 shellcode。见 [rop-and-shellcode.md](rop-and-shellcode.md#constrained-shellcode-in-small-buffers-tum-ctf-2016)。

**原始 syscall ROP：** 若 `system()`/`execve()` 因 CET/IBT 崩溃，改用 libc 里的 `pop rax; ret` + `syscall; ret`。见 [rop-and-shellcode.md](rop-and-shellcode.md)。

**ret2csu：** `__libc_csu_init` gadget 可控制 `rdx`、`rsi`、`edi` 并调用任意 GOT 函数，在无 libc gadget 时实现通用三参调用。见 [rop-and-shellcode.md](rop-and-shellcode.md#ret2csu--__libc_csu_init-gadgets-crypto-cat)。

**坏字符 XOR 绕过：** 先用 key 对数据 XOR，再写到 `.data`，然后用 ROP gadget 原地 XOR 回来。可规避空字节、换行等过滤字符。见 [rop-and-shellcode.md](rop-and-shellcode.md#bad-character-bypass-via-xor-encoding-in-rop-crypto-cat)。

**非常规 gadget（BEXTR/XLAT/STOSB/PEXT）：** 当没有标准 `mov` 写 gadget 时，链式利用冷门 x86 指令逐字节写内存。见 [rop-and-shellcode.md](rop-and-shellcode.md#exotic-x86-gadgets--bextrxlatstosbpext-crypto-cat)。

**栈迁移（`xchg rax,esp`）：** 当溢出空间不足以容纳完整 ROP 链时，把栈指针换到可控 heap/buffer。需要先用 `pop rax; ret` 装载迁移地址。见 [rop-and-shellcode.md](rop-and-shellcode.md#stack-pivot-via-xchg-raxesp-crypto-cat)。

**rdx 控制：** `puts()` 之后，rdx 常被破坏成 1。可用 libc 中的 `pop rdx; pop rbx; ret`，或重新进入二进制的 read 设置逻辑再栈迁移。见 [rop-and-shellcode.md](rop-and-shellcode.md)。

**Canary XOR 尾声作 rdx 清零 gadget：** 当没有 `pop rdx; ret` 时，可跳到 canary 检查尾声 `xor rdx, fs:28h`；若 canary 完整，它会把 RDX 清零。见 [rop-and-shellcode.md](rop-and-shellcode.md#stack-canary-xor-epilogue-as-rdx-zeroing-gadget-volgactf-2017)。

**stub_execveat 作为 execve 替代：** 当没有 `pop rax; ret` 时，改用 `stub_execveat`（syscall 322/0x142）代替 `execve`，并精确发送 0x142 字节，让 `read()` 返回值设置 rax。见 [rop-and-shellcode.md](rop-and-shellcode.md#stub_execveat-syscall-as-execve-alternative-asis-ctf-2018)。

**Shell 交互：** `execve` 后先 `sleep(1)`，再 `sendline(b'cat /flag*')`。见 [rop-and-shellcode.md](rop-and-shellcode.md)。

## Format String Through Input Transformation

**ROT13 编码格式串：** 当输入在到达 `printf` 前会被 ROT13/凯撒变换，先用逆变换对格式串 payload 预编码，使其到达时保持原样。见 [format-string.md](format-string.md#format-string-exploit-through-rot13-encoding-sunshinectf-2018)。

## Kernel Exploitation

**通过 failed file open 绕过 addr_limit：** 当某内核模块把 `addr_limit = KERNEL_DS` 设上去，但错误路径没恢复时，制造错误（例如把目标文件换成目录）即可保留用户态对内核内存的 `read()`/`write()` 访问。见 [kernel-techniques.md](kernel-techniques.md#kernel-addr_limit-bypass-via-failed-file-open-midnight-sun-ctf-2018)。

## Sandbox and Emulator Escape

**CPU emulator eval 注入：** 当模拟器的 print opcode 用 `eval('"' + buf + '"')` 处理转义序列时，可通过 ADD opcode 在模拟器内存中构造 `"+__import__("os").system("cmd")#`，逃出字符串并执行 Python。见 [sandbox-escape.md](sandbox-escape.md#cpu-emulator-print-opcode-python-eval-injection-midnight-sun-ctf-2018)。

## Advanced Exploit Primitives

**神经网络函数指针 OOB：** 当程序把神经网络输出当作函数指针数组索引，且没有边界检查时，可重新训练权重/偏置，使其产生越界索引，从偏置数组读取目标地址。见 [advanced-exploits-4.md](advanced-exploits-4.md#neural-network-output-as-function-pointer-index-oob-swampctf-2018)。

**通过计数器溢出绕过 shellcode 唯一字节限制：** 当 shellcode 被限制为最多 N 种唯一字节时，可先喷栈破坏 `seen[256]` 计数器，再重跑 main（跳过 `memset`），利用计数器溢出让第二轮接受任意字节。见 [advanced-exploits-4.md](advanced-exploits-4.md#shellcode-unique-byte-limit-bypass-via-counter-overflow-blaze-ctf-2018)。

## Deep-Dive Notes

确认题目确实以利用为主后，再使用 [field-notes.md](field-notes.md)。

- 堆与分配器笔记：House of Apple、tcache、unsafe unlink、talloc、UAF、FSOP
- 高级利用笔记：seccomp 绕过、ret2vdso、io_uring、整数截断、ASAN、时间预言机
- 沙箱与混合题笔记：pyjail 交叉技巧、busybox 逃逸、自定义 VM、shell 技巧、路径 sanitizer
- 内核与 Windows 笔记：内核利用流程、SEH、CFG 绕过、提权
- 历史案例笔记：老题但仍可复用的 CTF 利用模式
