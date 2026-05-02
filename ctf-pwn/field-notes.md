# Pwn 现场笔记

支持 [`SKILL.md`](SKILL.md) 的详细 pwn 笔记。确认挑战确实需要利用后再阅读此文件。

## 目录

- [Heap Exploitation](#heap-exploitation)
- [Additional Exploit Notes](#additional-exploit-notes)
  - [talloc Pool Header Forgery](#talloc-pool-header-forgery)
  - [JIT Compilation Exploits](#jit-compilation-exploits)
  - [Type Confusion in Interpreters](#type-confusion-in-interpreters)
  - [Off-by-One Index / Size Corruption](#off-by-one-index--size-corruption)
  - [Double win() Call](#double-win-call)
  - [Arbitrary Read/Write to Shell via GOT Overwrite](#arbitrary-readwrite-to-shell-via-got-overwrite)
  - [Stack Leak via __environ and memcpy Overflow](#stack-leak-via-__environ-and-memcpy-overflow)
  - [JIT Sandbox Escape via uint16 Jump Truncation](#jit-sandbox-escape-via-uint16-jump-truncation)
  - [DNS Compression Pointer Stack Overflow](#dns-compression-pointer-stack-overflow)
  - [ELF Code Signing Bypass via Program Headers](#elf-code-signing-bypass-via-program-headers)
  - [Game Level Format Signed/Unsigned Coordinate Mismatch](#game-level-format-signedunsigned-coordinate-mismatch)
  - [File Descriptor Inheritance via Missing O_CLOEXEC](#file-descriptor-inheritance-via-missing-o_cloexec)
  - [Sign Extension Integer Underflow in Metadata Parsing](#sign-extension-integer-underflow-in-metadata-parsing)
  - [ROP Chain Construction with Read-Only Primitive](#rop-chain-construction-with-read-only-primitive)
  - [Esoteric Language GOT Overwrite](#esoteric-language-got-overwrite)
  - [Protocol Stack Bleeding](#protocol-stack-bleeding)
  - [Timing Attack Flag Recovery](#timing-attack-flag-recovery)
  - [DNS Record Buffer Overflow](#dns-record-buffer-overflow)
  - [ASAN Shadow Memory Exploitation](#asan-shadow-memory-exploitation)
  - [Format String .fini_array Loop for Multi-Stage Exploitation](#format-string-fini_array-loop-for-multi-stage-exploitation)
  - [Format String with RWX .fini_array Hijack](#format-string-with-rwx-fini_array-hijack)
  - [Custom Canary Preservation](#custom-canary-preservation)
  - [MD5 Preimage Gadget Construction](#md5-preimage-gadget-construction)
  - [Python Sandbox Escape](#python-sandbox-escape)
  - [VM GC-Triggered UAF (Slab Reuse)](#vm-gc-triggered-uaf-slab-reuse)
  - [GC Null-Reference Cascading Corruption](#gc-null-reference-cascading-corruption)
  - [OOB Read via Stride/Rate Leak](#oob-read-via-striderate-leak)
  - [SROP with UTF-8 Constraints](#srop-with-utf-8-constraints)
  - [VM Exploitation (Custom Bytecode)](#vm-exploitation-custom-bytecode)
  - [FUSE/CUSE Character Device Exploitation](#fusecuse-character-device-exploitation)
  - [Busybox/Restricted Shell Escalation](#busyboxrestricted-shell-escalation)
  - [process_vm_readv Sandbox Bypass](#process_vm_readv-sandbox-bypass)
  - [Named Pipe (mkfifo) File Size Bypass](#named-pipe-mkfifo-file-size-bypass)
  - [Shell Tricks](#shell-tricks)
  - [Double Stack Pivot to BSS via leave;ret](#double-stack-pivot-to-bss-via-leaveret)
  - [RETF Architecture Switch for Seccomp Bypass](#retf-architecture-switch-for-seccomp-bypass)
  - [Leakless Libc via Multi-fgets stdout FILE Overwrite](#leakless-libc-via-multi-fgets-stdout-file-overwrite)
  - [Signed/Unsigned Char Underflow to Heap Overflow](#signedunsigned-char-underflow-to-heap-overflow)
  - [TLS Destructor Hijack via `__call_tls_dtors`](#tls-destructor-hijack-via-__call_tls_dtors)
  - [Signed Int Overflow to Negative OOB Heap Write](#signed-int-overflow-to-negative-oob-heap-write)
  - [Custom Shadow Stack Bypass via Pointer Overflow](#custom-shadow-stack-bypass-via-pointer-overflow)
  - [Windows SEH Overwrite + VirtualAlloc ROP](#windows-seh-overwrite--virtualalloc-rop)
  - [SeDebugPrivilege to SYSTEM](#sedebugprivilege-to-system)
  - [mmap/munmap Size Mismatch UAF](#mmapmunmap-size-mismatch-uaf)
  - [strcspn Indirect Null Byte Injection](#strcspn-indirect-null-byte-injection)
  - [Windows CFG Bypass Using system() as Valid Call Target](#windows-cfg-bypass-using-system-as-valid-call-target)
  - [4-Byte Shellcode with Timing Side-Channel](#4-byte-shellcode-with-timing-side-channel)
  - [CRC Oracle as Arbitrary Read Primitive](#crc-oracle-as-arbitrary-read-primitive)
  - [UTF-8 Case Conversion Buffer Overflow](#utf-8-case-conversion-buffer-overflow)
- [Useful Commands](#useful-commands)
## Heap Exploitation

- tcache 污染（glibc 2.26+）、fastbin dup / double free
- House of Force（旧版 glibc）、unsorted bin 攻击
- **House of Apple 2**（glibc 2.34+）：通过 `_IO_wfile_jumps` 实现 FSOP（File Stream Oriented Programming），当 `__free_hook`/`__malloc_hook` 被移除时。伪造 FILE，设置 `_flags = " sh"`，vtable 链接到 `system(fp)`。针对 SUID 二进制：使用 `setcontext()` 变体进行栈切换 → `setuid(0)` → `system()`（dash 在 uid != euid 时会降权限）。详见 [heap-techniques.md](heap-techniques.md#setcontext-variant-for-suid-binaries-midnight-flag-2026)。
- **Classic unlink**：破坏相邻 chunk 元数据，触发向后合并以实现写任意地址的能力。仅适用于 2.26 之前的 glibc。详见 [heap-techniques.md](heap-techniques.md#classic-heap-unlink-attack-crypto-cat)。
- **House of Force：** 破坏 top chunk 大小为 `0xffffffffffffffff`，下一次 `malloc(target - top - 2*SIZE_SZ)` 返回任意地址。仅适用于 2.29 之前的 glibc。详见 [heap-techniques.md](heap-techniques.md#house-of-force-csaw-ctf-2016)。
- **House of Einherjar**：Off-by-one 置零清除 PREV_INUSE，利用向后合并和自指向 unlink。
- **Safe-linking**（glibc 2.32+）：tcache 的 fd 指针被混淆为 `ptr ^ (chunk_addr >> 12)`。
- 检查 glibc 版本：`strings libc.so.6 | grep GLIBC`
- 已释放的 chunk 包含 libc 指针（fd/bk）→ 可通过错误信息或缺失的 null 终止符泄露
- Heap feng shui：控制分配顺序/大小，制造空洞，使目标 chunk 紧邻溢出源
- **Unsafe unlink + top chunk consolidation**：unlink 后写入自指针到 BSS，伪造跨越 top chunk 的 BSS chunk。`free()` 合并，堆基址迁移到 BSS。后续 malloc 返回 BSS 内存。详见 [heap-techniques.md](heap-techniques.md#unsafe-unlink-to-bss--top-chunk-consolidation-seccon-2016)。

**House of Orange：** 破坏 top chunk 大小 → 大块 malloc 触发 sysmalloc → 旧 top chunk 被释放但未调用 `free()`。结合 FSOP。详见 [heap-techniques.md](heap-techniques.md#house-of-orange)。

**House of Spirit：** 在目标区域伪造假 chunk，`free()` 后重新分配以获得写权限。需要有效大小和下一个 chunk 大小。详见 [heap-techniques.md](heap-techniques.md#house-of-spirit)。

**House of Lore：** 破坏 smallbin 的 `bk` → 链接假 chunk → 第二次 malloc 返回攻击者控制地址。详见 [heap-techniques.md](heap-techniques.md#house-of-lore)。

**ret2dlresolve：** 伪造 Elf64_Sym/Rela 以解析任意 libc 函数，无需泄露。`Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])`。需要 Partial RELRO。详见 [advanced.md](advanced.md#ret2dlresolve)。

**tcache stashing unlink（glibc 2.29+）：** 在 tcache 存储过程中破坏 smallbin chunk 的 `bk` → 任意地址被链接进 tcache → 写原语。详见 [heap-techniques.md](heap-techniques.md#tcache-stashing-unlink-attack)。

**UAF vtable 指针编码 shell 参数：** UAF 后，堆喷射将 `system()` 放置在偏移 +3 处。包含低字节 `0x6873`（"sh"）的对象地址作为命令字符串参数，当通过劫持的 vtable 调用 `system(this)` 时生效。详见 [heap-techniques-2.md](heap-techniques-2.md#uaf-vtable-pointer-encoding-shell-argument-bctf-2017)。

**Fastbin stdout vtable 两阶段劫持（PIE + Full RELRO）：** 利用 libc stdout 区域的 0x7f 字节作为伪 fastbin chunk 大小。两阶段：先将 vtable 重定向到 `gets()`（rdi=stdout），然后 `gets()` 再次覆盖 vtable 指向 `system()` 并传入命令字符串。详见 [heap-techniques.md](heap-fsop.md#fastbin-stdout-vtable-two-stage-hijack-for-pie--full-relro-asis-ctf-2017)。

详见 [heap-techniques.md](heap-techniques.md) 了解 House of Apple 2 FSOP 链（+ setcontext SUID 变体）、House of Orange/Spirit/Lore/Force、tcache stashing unlink、自定义分配器利用（nginx pools、talloc）、classic unlink、musl libc 堆。详见 [advanced.md](advanced.md) 了解 ret2dlresolve、基于基址转换的堆重叠、树形数据结构栈下分配。

**GF(2) 高斯消元用于 tcache 污染：** 当确定性 XOR 密码破坏堆元数据作为副作用时，将破坏建模为 GF(2) 上的线性代数。找到一组密码种子子集，其 XOR 组合将 tcache `fd` 从当前值变换为目标地址。详见 [advanced-exploits-4.md](advanced-exploits-4.md#gf2-gaussian-elimination-for-multi-pass-tcache-poisoning-midnight-flag-2026)。
## 额外利用笔记

### talloc 池头伪造
**模式：** talloc（Samba/CUPS 中的分层分配器）池头伪造。伪造带有可控 `end`/`object_count` 字段的假池头，以重定向下一次 `talloc()` 到任意地址。泄露 libc 的 GOT，写入 `__free_hook` 为 `system()`。详见 [heap-techniques.md](heap-techniques.md#talloc-pool-header-forgery-for-arbitrary-readwrite-boston-key-party-2016)。

### JIT 编译利用
**模式：** 指令编码中的 off-by-one 导致机器码错位。将 shellcode 嵌入减法操作的操作数字节中，使用 2 字节 `jmp` 指令串联。详见 [advanced.md](advanced.md)。

**BF JIT 不平衡括号：** 不平衡的 `]` 从栈中弹出带有读写执行权限的 tape 地址 → 用 `+`/`-` 写 shellcode 到 tape，触发 `]` 跳转执行。详见 [advanced.md](advanced.md)。

### 解释器中的类型混淆
**模式：** 解释器设置了错误的类型标签 → 结构体字段被错误解释。一个变体中未使用的填充字节在另一个变体中变成了活跃的指针/数据。将字节标记为类型值触发 UNKNOWN_DATA 转储。详见 [advanced.md](advanced.md)。

### Off-by-One 索引/大小破坏
**模式：** 数组索引 0 映射到 `entries[-1]`，与结构体元数据（大小字段）重叠。大小被破坏 → OOB 读取泄露 canary/libc，随后 OOB 写入放置 ROP 链。详见 [advanced.md](advanced.md)。

### 双重调用 win()
**模式：** `win()` 检查 `if (attempts++ > 0)` — 需要调用两次。栈上放置两个返回地址：`p64(win) + p64(win)`。详见 [advanced.md](advanced.md)。

### 通过 GOT 覆盖实现任意读写并获得 Shell
**模式：** 二进制提供显式的读写原语。通过 GOT 读取泄露 libc，覆盖 `strtoll@GOT` 为 `system`，下一次调用变为 `system(user_input)`。选择 GOT 目标函数，其第一个参数为用户控制的字符串。详见 [advanced-exploits-3.md](advanced-exploits-3.md#arbitrary-readwrite-to-shell-via-got-overwrite-bsidessf-2026)。

### 通过 __environ 和 memcpy 溢出泄露栈
**模式：** 二进制带只读原语和 `memcpy(stack_buf, user_addr, user_len)`。通过 GOT 泄露 libc，通过 `__environ` 泄露栈，在输入缓冲区植入 ROP 地址，溢出 memcpy 覆盖返回地址，发送 EOF 触发返回。详见 [advanced-exploits-3.md](advanced-exploits-3.md#stack-leak-via-__environ-and-memcpy-overflow-bsidessf-2026)。

### 通过 uint16 跳转截断实现 JIT 沙箱逃逸
**模式：** JIT 编译器将条件跳转偏移截断为 uint16，导致代码超过 64KB 时错位。将 2 字节 shellcode 片段嵌入 `add` 立即数中，使用 `jmp $+3` 串联执行。详见 [advanced-exploits-3.md](advanced-exploits-3.md#jit-sandbox-escape-via-conditional-jump-uint16-truncation-bsidessf-2026)。

### DNS 压缩指针栈溢出
**模式：** 自定义 DNS 服务器未跟踪解压名称长度。压缩指针链重复访问数据，导致栈缓冲区溢出。将 ROP 链拆分到多个 DNS 查询条目中。详见 [advanced-exploits-3.md](advanced-exploits-3.md#dns-compression-pointer-stack-overflow-with-multi-question-rop-bsidessf-2026)。

### 通过程序头绕过 ELF 代码签名
**模式：** 签名方案对节头和内容进行哈希，但不包括程序头。追加 shellcode，修改 LOAD 段的 `p_offset` 指向追加数据 — 签名仍然有效，加载器执行攻击者代码。详见 [advanced-exploits-3.md](advanced-exploits-3.md#elf-code-signing-bypass-via-program-header-manipulation-bsidessf-2026)。
### 游戏关卡格式有符号/无符号坐标不匹配
**模式：** 关卡编辑器解析有符号整数坐标，但通过无符号比较进行边界检查——负坐标通过检查并写入关卡数组之前的块 ID（任意字节），从而实现栈返回地址覆盖。通过隐藏的开发者模式泄露栈地址，将 shellcode 编码为块 ID。详见 [advanced-exploits-3.md](advanced-exploits-3.md#game-level-format-signedunsigned-coordinate-mismatch-bsidessf-2026)。

### 通过缺失 O_CLOEXEC 导致的文件描述符继承
**模式：** 服务将秘密读入未带 `MFD_CLOEXEC` 的 `memfd_create()` 文件描述符，然后调用 `system()` 执行用户命令——子进程继承该文件描述符。通过 shell 引号拆分（用 `p'r'oc` 替代 `proc`）绕过 `strstr()` 关键字过滤，读取 `/proc/self/fd/N`。详见 [advanced-exploits-3.md](advanced-exploits-3.md#file-descriptor-inheritance-via-missing-o_cloexec-bsidessf-2026)。

### 元数据解析中的符号扩展整数下溢
**模式：** 元数据解析器的 `to_int32` 将无符号值 ≥ 0x80000000 转换为负的有符号整数。用作数组索引/偏移时，导致越界内存访问。通过逐字节迭代泄露内存中的 flag。详见 [advanced-exploits-3.md](advanced-exploits-3.md#sign-extension-integer-underflow-in-metadata-parsing-bsidessf-2026)。

### 仅读原语的 ROP 链构造
**模式：** 二进制仅有 `read()` 原语——无写入，无 win 函数。通过 GOT 泄露 libc，然后通过从 libc 偏移读取内容匹配所需 ROP gadget 地址的字节，将任意字节“导入”栈上。读原语兼具写入功能。详见 [advanced-exploits-3.md](advanced-exploits-3.md#rop-chain-construction-with-read-only-primitive-bsidessf-2026)。

### 玄学语言 GOT 覆盖
**模式：** Brainfuck/Pikalang 解释器带无限带，允许相对于缓冲区基址的任意读写。移动指针至 GOT，逐字节覆盖为 `system()`。详见 [advanced.md](advanced.md)。

### 协议栈泄漏
自定义网络协议基于长度字段回显数据，当长度超过实际数据时泄露栈内存（类似 Heartbleed）。详见 [overflow-basics.md](overflow-basics.md#protocol-length-field-stack-bleeding-ekoparty-ctf-2016)。

### 定时攻击恢复 flag
验证时间随正确字符变化；测量每个候选字节的耗时，逐字符恢复 flag。详见 [advanced-exploits.md](advanced-exploits.md#timing-attack-for-character-by-character-flag-recovery-rc3-ctf-2016)。

### DNS 记录缓冲区溢出
**模式：** 许多 AAAA 记录在 DNS 响应解析器中溢出栈缓冲区。设置带有过多记录的 DNS 服务器，覆盖返回地址。详见 [advanced.md](advanced.md)。

### ASAN 影子内存利用
**模式：** 带 AddressSanitizer 的二进制存在格式字符串 + 越界写。ASAN 可能使用“假栈”（50% 概率）。泄露 PIE，区分真栈与假栈，计算越界写偏移覆盖返回地址。详见 [advanced.md](advanced.md)。

### 格式字符串 .fini_array 循环实现多阶段利用
**模式：** `printf()` 后无 GOT 函数调用。覆盖 `.fini_array[0]` 为 `main()` 实现重执行循环。阶段 1：泄露 libc/栈。阶段 2：`printf@GOT` 改为 `system()`，`__stack_chk_fail@GOT` 改为 `main()`。阶段 3：破坏 canary 触发 `__stack_chk_fail` 重入，此时 `printf(input)` 即为 `system(input)`。详见 [format-string.md](format-string.md#format-string-fini_array-loop-for-multi-stage-exploitation-codegate-2016)。
### Format String with RWX .fini_array Hijack
**模式（Encodinator）：** 在 RWX 内存中传递给 `printf()` 的 Base85 编码输入。将 shellcode 写入 RWX 区域，通过格式字符串 `%hn` 写入覆盖 `.fini_array[0]`。使用收敛循环进行 base85 参数编号。详见 [advanced.md](advanced.md)。

### Custom Canary Preservation
**模式：** 缓冲区溢出必须保留已知的 canary 值。在正确偏移处写入精确的 canary 字节：`b'A' * 64 + b'BIRD' + b'X'`。详见 [advanced.md](advanced.md)。

### MD5 Preimage Gadget Construction
**模式（Hashchain）：** 使用带有 `eb 0c` 前缀（jmp +12）跳过中间字节的 MD5 预映像暴力破解；字节 14-15 变成 2 字节的 i386 指令。利用 `31c0`（xor eax）、`cd80`（int 0x80）等 gadget 构建系统调用链。详见 [advanced.md](advanced.md) 中的 C 代码和 v2 技术。

### Python Sandbox Escape
通过 f-string 绕过 AST，使用 `b'flag.txt'`（字节 vs 字符串）绕过审计钩子，基于 MRO 恢复 `__builtins__`。详见 [sandbox-escape.md](sandbox-escape.md)。

### VM GC-Triggered UAF (Slab Reuse)
**模式：** 自定义 VM，带有 NEWBUF/SLICE/GC 操作码。切片创建共享 slab 引用；丢弃并 GC 切片时释放 slab，但父对象仍持有。分配函数对象重用 slab，通过 UAF 读取泄露代码指针，覆盖为 win() 地址。详见 [advanced.md](advanced.md)。

### GC Null-Reference Cascading Corruption
**模式：** 标记-压缩 GC 跟踪到堆地址 0 的空引用，创建伪造对象。压缩过程中，memmove 级联破坏相邻对象头 → OOB 访问 → libc 泄露 → FSOP。详见 [advanced.md](advanced.md)。

### OOB Read via Stride/Rate Leak
**模式：** 字符串处理函数带用户控制的步长，跳过空终止符，逐字节泄露栈 canary 和返回地址。随后利用泄露值溢出。详见 [overflow-basics.md](overflow-basics.md)。

### SROP with UTF-8 Constraints
**模式：** 当 payload 必须是有效 UTF-8（Rust 二进制、JSON 解析器）时，使用 SROP —— 只需 3 个 gadget。跨寄存器字段边界的多字节 UTF-8 序列“修正”高字节。详见 [rop-advanced.md](rop-advanced.md)。

### VM Exploitation (Custom Bytecode)
**模式：** 自定义 VM，syscall 中存在 OOB 读写。通过 XOR 编码的函数指针泄露 PIE，溢出重写指针为 `win() ^ KEY`。详见 [sandbox-escape.md](sandbox-escape.md)。

### FUSE/CUSE Character Device Exploitation
查找 `cuse_lowlevel_main()` / `fuse_main()`，后门写处理函数带命令解析。利用漏洞执行 `chmod /etc/passwd`，然后修改以获得 root 权限。详见 [sandbox-escape.md](sandbox-escape.md)。

### Busybox/Restricted Shell Escalation
通过字符设备寻找可写路径，目标为 `/etc/passwd` 或 `/etc/sudoers`，修改权限后再修改内容。详见 [sandbox-escape.md](sandbox-escape.md)。

### process_vm_readv Sandbox Bypass
**模式：** 沙箱通过 `process_vm_readv()` + `realpath()` 验证文件路径。通过 `mmap(MAP_FIXED)` 在固定地址映射仅 `PROT_READ` 内存 —— 沙箱的 `process_vm_readv` 静默失败，完全绕过路径验证。详见 [sandbox-escape.md](sandbox-escape.md#process_vm_readv-failure-as-sandbox-escape-0ctf-2016)。

### Named Pipe (mkfifo) File Size Bypass
**模式：** 二进制在读取前检查 `stat()` 文件大小。命名管道报告 `st_size = 0`，但通过 `read()` 传递任意数据。执行 `mkfifo /tmp/pipe && cat payload > /tmp/pipe &`，然后将管道传给二进制。结合 `ln -s /flag arena.c` 实现 ROP 中字符串重用。详见 [sandbox-escape.md](sandbox-escape.md#named-pipe-mkfifo-for-file-size-check-bypass-nuit-du-hack-2016)。
### Shell Tricks
`exec<&3;sh>&3` 用于文件描述符重定向，使用 `$0` 替代 `sh`，使用 `ls -la /proc/self/fd` 查找正确的文件描述符。详见 [sandbox-escape.md](sandbox-escape.md)。

### Double Stack Pivot to BSS via leave;ret
**模式：** 小型溢出（仅覆盖 RBP + RIP）。覆盖 RBP → BSS 地址，RIP → `leave; ret` gadget。`leave` 指令将 RSP 设置为 RBP（即 BSS）。第二阶段在 BSS 调用 `fgets(BSS+offset, large_size, stdin)` 以加载完整的 ROP 链。详见 [rop-advanced.md](rop-advanced.md#double-stack-pivot-to-bss-via-leaveret-midnightflag-2026)。

### RETF Architecture Switch for Seccomp Bypass
**模式：** Seccomp 阻止 64 位系统调用（如 `open`、`execve`）。使用 `retf` gadget 加载 CS=0x23（IA-32e 兼容模式）。在 32 位模式下，`int 0x80` 使用不同的系统调用号（open=5，read=3，write=4），不受过滤器限制。需要 `mprotect` 使 BSS 可执行以运行 32 位 shellcode。详见 [rop-advanced.md](rop-advanced.md#retf-architecture-switch-for-seccomp-bypass-midnightflag-2026)。

### Leakless Libc via Multi-fgets stdout FILE Overwrite
**模式：** 无 libc 泄露。通过 ROP 链多次调用 `fgets(addr, 7, stdin)` 构造伪造的 stdout FILE 结构体于 BSS。将 `_IO_write_base` 设置为 GOT 条目，调用 `fflush(stdout)` → 泄露 GOT 内容 → 计算 libc 基址。7 字节写入避免了空字节破坏，因为 libc 指针高位字节已是 `\x00`。详见 [advanced-exploits-2.md](advanced-exploits-2.md#leakless-libc-via-multi-fgets-stdout-file-overwrite-midnightflag-2026)。

### Signed/Unsigned Char Underflow to Heap Overflow
**模式：** 大小字段存储为 `signed char`，使用时转换为 `unsigned char`。`size = -112` → `(unsigned char)(-112) = 144`，导致对 127 字节缓冲区溢出 17 字节。结合 XOR 密钥流暴力破解实现字节精确写入，伪造 chunk 大小以促使 unsorted bin 升级（libc 泄露），利用 FSOP stdout 泄露 TLS，再通过 TLS 析构函数（`__call_tls_dtors`）覆盖实现 RCE。详见 [advanced-exploits-2.md](advanced-exploits-2.md#signedunsigned-char-underflow-to-heap-overflow--tls-destructor-hijack-midnightflag-2026)。

### TLS Destructor Hijack via `__call_tls_dtors`
**模式：** glibc 2.34+ 上 House of Apple 2 的替代方案。伪造 `__tls_dtor_list` 条目，使用指针保护混淆的函数指针：`encoded = rol(target ^ pointer_guard, 0x11)`。需要通过 FSOP stdout 重定向泄露 TLS 段中的 pointer guard。每个节点在退出时调用 `PTR_DEMANGLE(func)(obj)`。详见 [advanced-exploits-2.md](advanced-exploits-2.md#tls-destructor-overwrite-for-rce-via-__call_tls_dtors)。

### Signed Int Overflow to Negative OOB Heap Write
**模式（Canvas of Fear）：** 索引公式 `y * width + x` 在有符号 32 位整数中溢出为负值，绕过边界检查并向后写入堆元数据。利用此破坏相邻 chunk 大小/指针，通过 unsorted bin 泄露 libc，重定向数据指针到 `environ` 泄露栈，再写入 ROP 链覆盖 main 返回地址。当二进制程序位于 Web API 后时，链式利用 XSS → Fetch API → 堆漏洞，并在 API 参数中注入 `\n` 以通过 `sendline()` 实现命令堆叠。完整利用链、XSS 桥接模式及 RGB 像素写入原语详见 [advanced-exploits-2.md](advanced-exploits-2.md#signed-int-overflow-to-negative-oob-heap-write--xss-to-binary-pwn-bridge-midnight-2026)。

### Custom Shadow Stack Bypass via Pointer Overflow
**模式（Revenant）：** 用户态影子栈位于 `.bss`，指针无边界限制。递归推进 `shadow_stack_ptr` 超出数组进入用户控制内存（如 `username` 缓冲区），写入 `win()`，然后溢出硬件栈返回地址使其匹配。两者检查均通过。完整利用及 `.bss` 布局分析详见 [advanced-exploits-2.md](advanced-exploits-2.md#custom-shadow-stack-bypass-via-pointer-overflow-midnight-2026)。
### Windows SEH 覆盖 + VirtualAlloc ROP
格式化字符串泄露绕过 ASLR。通过 SEH（结构化异常处理器）覆盖并使用栈枢轴跳转到 ROP 链。`pushad` 构建 VirtualAlloc 调用帧以绕过 DEP（数据执行保护）。分离进程启动器用于线程型服务器上的 shell 稳定性。详见 [advanced-exploits-4.md](advanced-exploits-4.md#windows-seh-overwrite--pushad-virtualalloc-rop-rainbowtwo-htb)。

### SeDebugPrivilege 提权到 SYSTEM
`SeDebugPrivilege` + Meterpreter `migrate -N winlogon.exe` -> SYSTEM。详见 [advanced-exploits-4.md](advanced-exploits-4.md#sedebugprivilege-to-system-rainbowtwo-htb)。

### mmap/munmap 大小不匹配 UAF
通过 mmap（小）/munmap（大）过度解除映射破坏相邻映射。线程栈填补空隙，旧缓冲区指针变为写入栈。无竞态条件的 UAF 变体。详见 [advanced-exploits-4.md](advanced-exploits-4.md#mmapmunmap-size-mismatch-uaf-for-thread-stack-overlap-0ctf-2017)。

### strcspn 间接空字节注入
`strcspn(buf, "\r\n")` + 空写入在注入换行处截断字符串。绕过 CGI 空字节过滤实现路径遍历。详见 [advanced-exploits-4.md](advanced-exploits-4.md#strcspn-as-indirect-null-byte-injection-bsidessf-2017)。

### 使用 system() 作为有效调用目标绕过 Windows CFG
**模式：** Windows CFG 验证间接调用目标，但 msvcrt 中的 `system()` 通过验证，因为它是合法的 API 入口点。覆盖函数指针为 `system()`，参数中用逗号代替空格以绕过输入过滤。详见 [advanced-exploits-4.md](advanced-exploits-4.md#windows-cfg-bypass-using-system-as-valid-call-target-insomnihack-2017)。

### 4 字节 Shellcode 结合定时侧信道
**模式：** 二进制在 4096 次循环中仅执行用户 shellcode 的 4 字节。被调用保存寄存器（r12-r15）在迭代间保持，允许增量构建状态。4096 次循环放大定时差异，实现可靠侧信道测量。详见 [advanced-exploits-3.md](advanced-exploits-3.md#4-byte-shellcode-with-timing-side-channel-via-persistent-registers-google-ctf-2017)。

### CRC Oracle 作为任意读取原语
**模式：** CRC 在单字节上是双射。溢出指针控制 CRC 输入地址，预计算所有 256 个单字节 CRC，反查任意内存的每个字节。链式读取泄露 GOT、libc、栈和 canary。详见 [advanced-exploits-3.md](advanced-exploits-3.md#crc-oracle-as-arbitrary-read-primitive-asis-ctf-2017)。

### UTF-8 大小写转换缓冲区溢出
**模式：** Unicode 大小写转换可能扩展字符字节长度（例如，2 字节 UTF-8 大写后变为 4 字节）。如果缓冲区按输入长度分配，较长的输出会溢出。影响 GLib 的 `g_utf8_strup()`、ICU 及类似函数。详见 [advanced-exploits-3.md](advanced-exploits-3.md#utf-8-case-conversion-buffer-overflow-hitb-ctf-2017)。

## 有用命令

`checksec`、`one_gadget`、`ropper`、`ROPgadget`、`seccomp-tools dump`、`strings libc | grep GLIBC`。完整命令列表和 pwntools 模板见 [rop-advanced.md](rop-advanced.md)。
